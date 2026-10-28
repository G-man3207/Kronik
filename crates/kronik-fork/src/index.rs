//! The production side of a replay (docs/design/m3-fork.md §3.1-§3.2):
//! main's records up to the end of the window, its root inputs, and its
//! turns by causal key.

use std::collections::BTreeMap;

use kronik_core::causal;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_log::{Committed, LogError, LogReader};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

/// A root input of the window.
#[derive(Debug, Clone)]
pub struct RootInput {
    /// The root turn's `TurnRecord`.
    pub lsn: Lsn,
    /// The first record of its tree: the root turn's `TurnBegin` when it
    /// wrote one (a turn with calls does, and its callees commit before
    /// its own record), else `lsn`; never at or before the fork point.
    pub start_lsn: Lsn,
    pub actor: ActorRef,
    pub causal_key: pb::CausalKey,
    pub input: pb::Input,
    pub logical_time_ms: u64,
    /// `<kind> <input label>`: the sampling stratum and the causes group.
    pub stratum: String,
    pub subject: Option<String>,
}

/// `METHOD /route` for HTTP, `message <name>` or `timer <name>` otherwise.
pub fn input_label(input: Option<&pb::Input>) -> String {
    match input.and_then(|i| i.kind.as_ref()) {
        Some(pb::input::Kind::Http(h)) => {
            // Never the raw path: it can hold user data (ADR 0023).
            let route = if h.route.is_empty() {
                "(no route)"
            } else {
                h.route.as_str()
            };
            format!("{} {route}", h.method)
        }
        Some(pb::input::Kind::Message(m)) => {
            format!("message {}", m.msg.as_ref().map_or("", |m| m.name.as_str()))
        }
        Some(pb::input::Kind::Timer(t)) => {
            format!("timer {}", t.msg.as_ref().map_or("", |m| m.name.as_str()))
        }
        Some(pb::input::Kind::Migrate(m)) => format!("migrate {}", m.to_schema_version),
        None => String::new(),
    }
}

/// A snapshot a replay starts from instead of LSN 1 (m6-storage §3).
#[derive(Debug, Clone)]
pub struct Base {
    pub lsn: Lsn,
    pub dir: std::path::PathBuf,
    /// The snapshot's configuration records (deployments, grants, limits,
    /// foreign actors), in LSN order.
    pub config: Vec<(Lsn, Record)>,
}

impl Base {
    /// Reads the configuration a snapshot's `state.db` holds.
    pub fn open(lsn: Lsn, dir: std::path::PathBuf) -> Result<Base, String> {
        let conn = rusqlite::Connection::open_with_flags(
            dir.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| e.to_string())?;
        let mut config: Vec<(Lsn, Record)> = Vec::new();
        let mut st = conn
            .prepare("SELECT lsn, record FROM deployments ORDER BY epoch")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (l, b) = row.map_err(|e| e.to_string())?;
            let d = <pb::Deployment as prost::Message>::decode(b.as_slice())
                .map_err(|e| e.to_string())?;
            config.push((l as Lsn, Record::Deployment(d)));
        }
        let mut st = conn
            .prepare("SELECT lsn, kind, record FROM config_records ORDER BY lsn")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (l, k, b) = row.map_err(|e| e.to_string())?;
            config.push((
                l as Lsn,
                Record::decode(k as u8, &b).map_err(|e| e.to_string())?,
            ));
        }
        config.sort_by_key(|(l, _)| *l);
        Ok(Base { lsn, dir, config })
    }
}

/// Main's history for one replay.
pub struct ProductionIndex {
    pub fork_lsn: Lsn,
    pub to_lsn: Lsn,
    /// The snapshot the records continue, if any.
    pub base: Option<Base>,
    /// Every record `first_lsn..=to_lsn`, in LSN order (index = lsn -
    /// first_lsn); `first_lsn` is the base snapshot's LSN + 1, else 1.
    pub records: std::sync::Arc<Vec<Committed>>,
    /// Turn records by causal key encoding -> lsn.
    turns: BTreeMap<Vec<u8>, Lsn>,
    /// Turn LSNs by root id, in LSN order.
    trees: BTreeMap<String, Vec<Lsn>>,
    pub roots: Vec<RootInput>,
    /// Opens production's sealed SQL changesets when a cursor applies them
    /// (M8); plain unless the index was revealed for a fork.
    pub sealer: std::sync::Arc<kronik_privacy::sealer::Sealer>,
}

impl ProductionIndex {
    /// Reads main's log up to `to_lsn` and indexes the window
    /// `(fork_lsn, to_lsn]`.
    pub async fn load(
        reader: &LogReader,
        fork_lsn: Lsn,
        to_lsn: Lsn,
    ) -> Result<ProductionIndex, LogError> {
        ProductionIndex::load_from(reader, None, fork_lsn, to_lsn).await
    }

    /// Like `load`, continuing the snapshot `base` (its LSN at most
    /// `fork_lsn`): only records after it are read.
    pub async fn load_from(
        reader: &LogReader,
        base: Option<Base>,
        fork_lsn: Lsn,
        to_lsn: Lsn,
    ) -> Result<ProductionIndex, LogError> {
        let first = base.as_ref().map_or(1, |b| b.lsn + 1);
        let mut records = Vec::with_capacity(to_lsn.saturating_sub(first) as usize + 1);
        if to_lsn >= first {
            reader
                .read(first, to_lsn, |c| {
                    records.push(c);
                    Ok(())
                })
                .await?;
        }
        if let Some(c) = records.first()
            && c.lsn != first
        {
            return Err(LogError::Corrupt(format!(
                "replay needs the log from lsn {first}, but it starts at {}",
                c.lsn
            )));
        }
        let mut index = ProductionIndex::from_records(records, fork_lsn, to_lsn);
        index.base = base;
        Ok(index)
    }

    /// The first LSN of `records`.
    pub fn first_lsn(&self) -> Lsn {
        self.base.as_ref().map_or(1, |b| b.lsn + 1)
    }

    pub fn from_records(records: Vec<Committed>, fork_lsn: Lsn, to_lsn: Lsn) -> ProductionIndex {
        ProductionIndex::from_shared(std::sync::Arc::new(records), fork_lsn, to_lsn)
    }

    fn from_shared(
        records: std::sync::Arc<Vec<Committed>>,
        fork_lsn: Lsn,
        to_lsn: Lsn,
    ) -> ProductionIndex {
        let mut turns = BTreeMap::new();
        let mut trees: BTreeMap<String, Vec<Lsn>> = BTreeMap::new();
        let mut roots = Vec::new();
        let mut begins: BTreeMap<String, Lsn> = BTreeMap::new();
        for c in records.iter().take_while(|c| c.lsn <= to_lsn) {
            if let Record::TurnBegin(b) = &c.record
                && let Some(key) = &b.causal_key
                && key.path.is_empty()
            {
                begins.entry(key.root.clone()).or_insert(c.lsn);
            }
            let Record::TurnRecord(t) = &c.record else {
                continue;
            };
            let Some(key) = &t.causal_key else { continue };
            turns.insert(causal::encode(key), c.lsn);
            trees.entry(key.root.clone()).or_default().push(c.lsn);
            if c.lsn <= fork_lsn || !key.path.is_empty() {
                continue;
            }
            let input = t.input.clone().unwrap_or_default();
            if matches!(input.kind, Some(pb::input::Kind::Migrate(_)) | None) {
                continue;
            }
            let Some(actor) = t.actor.as_ref().map(ActorRef::from_pb) else {
                continue;
            };
            let subject = match &input.kind {
                Some(pb::input::Kind::Message(m)) => m
                    .msg
                    .as_ref()
                    .and_then(|m| m.body.as_ref())
                    .and_then(|b| b.subject.clone()),
                // The gateway's `subject_from` tags the body and every
                // header with the request's subject (M8 §11).
                Some(pb::input::Kind::Http(h)) => {
                    match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                        Some(pb::body::Value::Inline(s)) if s.subject.is_some() => {
                            s.subject.clone()
                        }
                        _ => h
                            .headers
                            .iter()
                            .find_map(|h| h.value.as_ref().and_then(|v| v.subject.clone())),
                    }
                }
                _ => None,
            };
            let start_lsn = begins
                .get(&key.root)
                .map_or(c.lsn, |b| (*b).min(c.lsn))
                .max(fork_lsn + 1);
            roots.push(RootInput {
                lsn: c.lsn,
                start_lsn,
                stratum: format!("{} {}", actor.kind, input_label(Some(&input))),
                actor,
                causal_key: key.clone(),
                logical_time_ms: t.logical_time_ms,
                input,
                subject,
            });
        }
        ProductionIndex {
            fork_lsn,
            to_lsn,
            base: None,
            records,
            turns,
            trees,
            roots,
            sealer: std::sync::Arc::new(kronik_privacy::sealer::Sealer::plain()),
        }
    }

    /// Shows the index's user data as the fork may see it (M8 §5, §9):
    /// root inputs, recorded effects and turn records are revealed in place
    /// (plaintext, or pseudonyms for `--no-pii`); SQL changesets stay as
    /// recorded and are opened by the cursor's store with `privacy.sealer`.
    pub fn reveal(&mut self, privacy: &crate::privacy::ForkPrivacy) {
        self.sealer = privacy.sealer.clone();
        for c in std::sync::Arc::make_mut(&mut self.records) {
            match &mut c.record {
                Record::TurnRecord(t) => {
                    privacy.reveal_turn(t);
                }
                Record::TurnBegin(b) => {
                    if let Some(i) = b.input.as_mut() {
                        privacy.reveal_input(i);
                    }
                }
                Record::EffectResult(e) => {
                    if let Some(e) = e.effect.as_mut() {
                        privacy.reveal_effect(e);
                    }
                }
                _ => {}
            }
        }
        for r in &mut self.roots {
            privacy.reveal_input(&mut r.input);
        }
    }

    pub fn record(&self, lsn: Lsn) -> Option<&Committed> {
        lsn.checked_sub(self.first_lsn())
            .and_then(|i| self.records.get(i as usize))
    }

    /// The production turn with this causal key.
    pub fn turn(&self, key: &pb::CausalKey) -> Option<(Lsn, &pb::TurnRecord)> {
        let lsn = *self.turns.get(&causal::encode(key))?;
        match &self.record(lsn)?.record {
            Record::TurnRecord(t) => Some((lsn, t)),
            _ => None,
        }
    }

    /// The production turns of a root input's causal tree within the window,
    /// in LSN order.
    pub fn tree(&self, root: &RootInput) -> Vec<(Lsn, &pb::TurnRecord)> {
        self.trees
            .get(&root.causal_key.root)
            .into_iter()
            .flatten()
            .filter(|l| **l >= root.start_lsn)
            .filter_map(|l| match &self.record(*l)?.record {
                Record::TurnRecord(t) => Some((*l, t)),
                _ => None,
            })
            .collect()
    }

    /// Every turn LSN of a causal tree, in LSN order.
    pub fn tree_lsns(&self, root: &str) -> Option<&[Lsn]> {
        self.trees.get(root).map(Vec::as_slice)
    }

    /// The root input's own turn (empty causal path), not a consequence.
    pub fn root_turn_lsn(&self, root: &str) -> Option<Lsn> {
        self.trees.get(root)?.iter().copied().find(|&l| {
            let Some(c) = self.record(l) else {
                return false;
            };
            let Record::TurnRecord(t) = &c.record else {
                return false;
            };
            t.causal_key.as_ref().is_some_and(|k| k.path.is_empty())
        })
    }

    /// Configuration records (deployments, grants, limits, foreign actors)
    /// up to `lsn`.
    pub fn config_records(&self, upto: Lsn) -> Vec<Record> {
        let base = self
            .base
            .iter()
            .flat_map(|b| b.config.iter())
            .filter(|(l, _)| *l <= upto)
            .map(|(_, r)| r.clone());
        base.chain(self.records_config(upto)).collect()
    }

    fn records_config(&self, upto: Lsn) -> Vec<Record> {
        self.records
            .iter()
            .filter(|c| c.lsn <= upto)
            .filter(|c| {
                matches!(
                    c.record,
                    Record::Deployment(_)
                        | Record::Grant(_)
                        | Record::Limits(_)
                        | Record::ForeignActor(_)
                )
            })
            .map(|c| c.record.clone())
            .collect()
    }

    /// Each kind's code as of `upto` (the last deployment of each kind).
    pub fn kinds_at(&self, upto: Lsn) -> BTreeMap<String, pb::KindVersion> {
        let mut kinds = BTreeMap::new();
        let base = self
            .base
            .iter()
            .flat_map(|b| b.config.iter())
            .filter(|(l, _)| *l <= upto)
            .map(|(_, r)| r);
        let after = self
            .records
            .iter()
            .filter(|c| c.lsn <= upto)
            .map(|c| &c.record);
        for r in base.chain(after) {
            if let Record::Deployment(d) = r {
                for k in &d.kinds {
                    kinds.insert(k.kind.clone(), k.clone());
                }
            }
        }
        kinds
    }

    /// The first root input whose logical time is at least `due`.
    pub fn first_root_at_or_after(&self, due: u64) -> Option<&RootInput> {
        self.roots.iter().find(|r| r.logical_time_ms >= due)
    }
}
