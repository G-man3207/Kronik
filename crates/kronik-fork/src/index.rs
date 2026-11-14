//! The production side of a replay (docs/design/m3-fork.md §3.1-§3.2):
//! main's records up to the end of the window, its root inputs, and its
//! turns by causal key.

use std::collections::{BTreeMap, BTreeSet};

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

/// `METHOD /route` for HTTP, `message <name>` or `timer <name>`, and
/// `connection <open|frame|close> <WEBSOCKET|SSE> /route` for a connection
/// input (M24): never the connection id or a frame's data.
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
        Some(pb::input::Kind::Connection(c)) => {
            let event = match &c.event {
                Some(pb::connection_input::Event::Open(_)) => "open",
                Some(pb::connection_input::Event::Frame(_)) => "frame",
                Some(pb::connection_input::Event::Close(_)) => "close",
                None => "(no event)",
            };
            let route = if c.route.is_empty() {
                "(no route)"
            } else {
                c.route.as_str()
            };
            format!(
                "connection {event} {} {route}",
                kronik_proto::connection::protocol_method(c.protocol)
            )
        }
        None => String::new(),
    }
}

/// A snapshot a replay starts from instead of LSN 1 (m6-storage §3).
#[derive(Debug, Clone)]
pub struct Base {
    pub lsn: Lsn,
    pub dir: std::path::PathBuf,
    /// The snapshot's configuration records (deployments, grants, limits,
    /// foreign actors, secret links), in LSN order.
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

/// A configuration record as replay sees it: a rebase switch counts as its
/// deployment (M13). A secret link is one, as it is in the store's
/// `config_records` that a base snapshot is read from: a fork sees the links
/// in force at its fork point, whether they were made before its base
/// snapshot or after it.
fn config_view(r: &Record) -> Option<Record> {
    match r {
        Record::Deployment(_)
        | Record::Grant(_)
        | Record::Limits(_)
        | Record::ForeignActor(_)
        | Record::PrivacyMode(_)
        | Record::SimulatorConfig(_)
        | Record::SecretLink(_) => Some(r.clone()),
        _ => r
            .rebase_switch()
            .and_then(|(_, sw)| sw.deployment.clone())
            .map(Record::Deployment),
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
    /// Turn LSNs whose guest read a value whose subject was erased: in its
    /// input, or in an effect's request or response. Identity replay cannot
    /// verify such a turn against its input; it reports it as unverifiable
    /// instead of divergent (S-16, ADR 0109).
    pub erased_turns: BTreeSet<Lsn>,
    /// For a turn whose guest read no erased value but whose own outputs
    /// (state writes, messages, timers, its reply, SQL changes) hold values of
    /// subjects erased since, those subjects. The turn is replayed and
    /// compared like any other, except for those subjects' values, which no
    /// one can read again (ADR 0109 point 9).
    pub erased_outputs: BTreeMap<Lsn, BTreeSet<String>>,
    /// For each turn of [`ProductionIndex::erased_turns`], the ordinals of the
    /// effects whose recorded request was erased. Such a request cannot be
    /// rebuilt from the revealed input, so replay serves the recording.
    pub erased_effects: BTreeMap<Lsn, BTreeSet<u32>>,
    /// (lsn, actor, subject, untagged) of every SQL changeset whose subject
    /// was erased. A store skips it when it applies the record, so the
    /// actor's database lacks rows production had until the subject's
    /// `Erasure` deleted them ([`ProductionIndex::sql_gap`]; ADR 0109).
    /// `untagged`: the engine that recorded it let a subject's turn write a
    /// table without `_subject` ([`crate::taint::subject_rows_may_be_untagged`]),
    /// whose rows the erasure does not delete.
    pub erased_sql: Vec<(Lsn, String, String, bool)>,
    /// (lsn, subject, key version) of the `Erasure` records, in LSN order.
    pub erasures: Vec<(Lsn, String, u32)>,
    /// Opens production's sealed SQL changesets when a cursor applies them
    /// (M8); plain unless the index was revealed for a fork.
    pub sealer: std::sync::Arc<kronik_privacy::sealer::Sealer>,
    /// Set by [`ProductionIndex::reveal`] for a `--no-pii` fork. The cursor
    /// rewrites snapshot rows the same way revealed changesets were.
    pub no_pii: bool,
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
        let mut erasures = Vec::new();
        for c in records.iter().take_while(|c| c.lsn <= to_lsn) {
            if let Record::Erasure(e) = &c.record {
                erasures.push((c.lsn, e.subject.clone(), e.key_version));
            }
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
                // M24 §4.10: the connection's subject, from the recorded
                // input, as the node derives the turn's default subject.
                Some(pb::input::Kind::Connection(c)) => kronik_proto::connection::input_subject(c),
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
            erased_turns: BTreeSet::new(),
            erased_outputs: BTreeMap::new(),
            erased_effects: BTreeMap::new(),
            erased_sql: Vec::new(),
            erasures,
            sealer: std::sync::Arc::new(kronik_privacy::sealer::Sealer::plain()),
            no_pii: false,
        }
    }

    /// Shows the index's user data as the fork may see it (M8 §5, §9):
    /// root inputs, recorded effects and turn records are revealed in place
    /// (plaintext, or pseudonyms for `--no-pii`). Subject-tagged SQL
    /// changesets are unsealed and, for `--no-pii`, pseudonymized before
    /// the cursor's store applies them.
    pub fn reveal(&mut self, privacy: &crate::privacy::ForkPrivacy) {
        self.sealer = privacy.sealer.clone();
        self.no_pii = privacy.no_pii;
        for c in std::sync::Arc::make_mut(&mut self.records) {
            match &mut c.record {
                Record::TurnRecord(t) => {
                    // Before it is replaced by `[erased]`: an erased value
                    // the guest read (its input, an effect's request or
                    // response) means no replay can reproduce what it read,
                    // so the turn is unverifiable (S-16, ADR 0109). Erased
                    // values only among its outputs leave the rest of the
                    // turn comparable (ADR 0109 point 9).
                    let mut read = false;
                    kronik_proto::sealables::input_mut(t.input.as_mut(), &mut |s| {
                        read |= privacy.opens_erased(s);
                    });
                    for e in &mut t.effects {
                        kronik_proto::sealables::effect_mut(e, &mut |s| {
                            read |= privacy.opens_erased(s);
                        });
                    }
                    let mut outputs = BTreeSet::new();
                    kronik_proto::sealables::turn_mut(t, &mut |s| {
                        if let Some(subject) = &s.subject
                            && privacy.opens_erased(s)
                        {
                            outputs.insert(subject.clone());
                        }
                    });
                    if read {
                        self.erased_turns.insert(c.lsn);
                    } else if !outputs.is_empty() {
                        self.erased_outputs.insert(c.lsn, outputs);
                    }
                    let effects: BTreeSet<u32> = t
                        .effects
                        .iter()
                        .filter(|e| {
                            e.request
                                .as_ref()
                                .is_some_and(|request| privacy.opens_erased(request))
                        })
                        .map(|e| e.ordinal)
                        .collect();
                    if !effects.is_empty() {
                        self.erased_effects.insert(c.lsn, effects);
                    }
                    let actor = t
                        .actor
                        .as_ref()
                        .map(|a| format!("{}/{}", a.kind, a.key))
                        .unwrap_or_default();
                    let untagged = crate::taint::subject_rows_may_be_untagged(&t.engine_version);
                    for cs in t.sql_changes.iter().filter_map(|c| c.changeset.as_ref()) {
                        if let Some(subject) = &cs.subject
                            && privacy.opens_erased(cs)
                        {
                            self.erased_sql
                                .push((c.lsn, actor.clone(), subject.clone(), untagged));
                        }
                    }
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

    /// This index continued to `to_lsn`: only the records after its end
    /// are read and revealed (a rebase's last round inside the pause,
    /// m13-rebase §4). `self` must have been revealed with `privacy`.
    pub async fn extended(
        &self,
        reader: &LogReader,
        to_lsn: Lsn,
        privacy: &crate::privacy::ForkPrivacy,
    ) -> Result<ProductionIndex, LogError> {
        let from = self.to_lsn + 1;
        let mut more = Vec::new();
        if to_lsn >= from {
            reader
                .read(from, to_lsn, |c| {
                    more.push(c);
                    Ok(())
                })
                .await?;
        }
        if let Some(c) = more.first()
            && c.lsn != from
        {
            return Err(LogError::Corrupt(format!(
                "replay needs the log from lsn {from}, but it continues at {}",
                c.lsn
            )));
        }
        let mut tail = ProductionIndex::from_records(more, self.fork_lsn, to_lsn);
        tail.reveal(privacy);
        // shortcut: copies the window's records once per extension; chunked
        // records would avoid it if long windows make the last round slow.
        let mut records = (*self.records).clone();
        records.extend(std::sync::Arc::unwrap_or_clone(tail.records));
        let mut index =
            ProductionIndex::from_shared(std::sync::Arc::new(records), self.fork_lsn, to_lsn);
        index.base = self.base.clone();
        index.sealer = privacy.sealer.clone();
        index.no_pii = privacy.no_pii;
        index.erased_turns = self.erased_turns.clone();
        index.erased_turns.extend(tail.erased_turns);
        index.erased_outputs = self.erased_outputs.clone();
        index.erased_outputs.extend(tail.erased_outputs);
        index.erased_effects = self.erased_effects.clone();
        index.erased_effects.extend(tail.erased_effects);
        index.erased_sql = self.erased_sql.clone();
        index.erased_sql.extend(tail.erased_sql);
        Ok(index)
    }

    /// The LSN of the snapshot the records continue (0 without one): a
    /// store's state written at or below it is the snapshot's, the rest the
    /// replay's.
    pub fn base_lsn(&self) -> Lsn {
        self.base.as_ref().map_or(0, |b| b.lsn)
    }

    /// Whether, at production position `at`, the replay's database of
    /// `actor` lacks rows production had: an erased subject's changeset was
    /// skipped before `at`, and that subject's `Erasure`, which deleted the
    /// rows in production too, comes after it (ADR 0109). `untagged`: the
    /// database has a table without `_subject`. Only a changeset an engine
    /// before ADR 0005 §6 option B recorded can hold rows of such a table
    /// (from then on a subject's turn cannot write one), which the erasure
    /// left in production: for it the gap stays. Every other changeset's
    /// gap ends at the erasure, whatever tables the database has.
    pub fn sql_gap(&self, actor: &str, at: Lsn, untagged: bool) -> bool {
        self.erased_sql
            .iter()
            .filter(|(lsn, a, _, _)| a == actor && *lsn < at)
            .any(|(lsn, _, subject, old_engine)| {
                (untagged && *old_engine)
                    || self
                        .erasures
                        .iter()
                        .find(|(e, s, _)| s == subject && e > lsn)
                        .is_none_or(|(e, _, _)| at < *e)
            })
    }

    /// Whether an erased subject's changeset of `actor` was skipped at all.
    pub fn has_erased_sql(&self, actor: &str) -> bool {
        self.erased_sql.iter().any(|(_, a, _, _)| a == actor)
    }

    /// The production turns below `key` in its causal tree (messages,
    /// calls, timers and compensations it caused, and theirs), in LSN order.
    pub fn below(&self, key: &pb::CausalKey) -> Vec<(Lsn, &pb::TurnRecord)> {
        self.trees
            .get(&key.root)
            .into_iter()
            .flatten()
            .filter_map(|l| match &self.record(*l)?.record {
                Record::TurnRecord(t) => Some((*l, t)),
                _ => None,
            })
            .filter(|(_, t)| {
                t.causal_key
                    .as_ref()
                    .is_some_and(|k| k.path.len() > key.path.len() && k.path.starts_with(&key.path))
            })
            .collect()
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

    /// Configuration records (deployments, grants, limits, foreign actors,
    /// secret links) up to `lsn`.
    pub fn config_records(&self, upto: Lsn) -> Vec<Record> {
        let base = self
            .base
            .iter()
            .flat_map(|b| b.config.iter())
            .filter(|(l, _)| *l <= upto)
            .map(|(_, r)| r.clone());
        base.chain(self.records_config(upto)).collect()
    }

    /// Every configuration record with its LSN up to `upto`: the base
    /// snapshot's, then the window's, in LSN order.
    pub fn config_records_upto(&self, upto: Lsn) -> Vec<(Lsn, Record)> {
        let base = self
            .base
            .iter()
            .flat_map(|b| b.config.iter())
            .filter(|(l, _)| *l <= upto)
            .cloned();
        let window = self
            .records
            .iter()
            .filter(|c| c.lsn <= upto)
            .filter_map(|c| config_view(&c.record).map(|r| (c.lsn, r)));
        base.chain(window).collect()
    }

    fn records_config(&self, upto: Lsn) -> Vec<Record> {
        self.records
            .iter()
            .filter(|c| c.lsn <= upto)
            .filter_map(|c| config_view(&c.record))
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
            .filter_map(|c| match c.record.rebase_switch() {
                Some(_) => config_view(&c.record),
                None => matches!(c.record, Record::Deployment(_)).then(|| c.record.clone()),
            });
        let base: Vec<Record> = base.cloned().collect();
        for r in base.iter().cloned().chain(after) {
            if let Record::Deployment(d) = &r {
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
