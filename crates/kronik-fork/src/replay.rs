//! The replay engine (docs/design/m3-fork.md §3): isolated replay over a
//! production cursor with discarded overlays, continuous replay in a fork
//! store, the deterministic scheduler, and the replay effect gate (exact,
//! approximate and synthetic matching; no live effects, I7).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kronik_core::causal;
use kronik_core::env::{BoxFuture, Env};
use kronik_core::ids::{ActorRef, CodeHash, Lsn};
use kronik_effects::Config;
use kronik_effects::http::{fingerprint, parse_url, target_of};
use kronik_log::{Committed, Position};
use kronik_privacy::SecretStore;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, GateError, Program, TurnLimits, TurnRequest,
};
use kronik_sched::effects::{map_call_outcome, outcome_of_call, outcome_of_fetch};
use kronik_sched::host::{SqlHandle, SqlTurn};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool, TurnOpts};
use prost::Message as _;

use crate::index::{ProductionIndex, RootInput};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error(transparent)]
    Store(#[from] kronik_store::StoreError),
    #[error("replay failed: {0}")]
    Host(String),
    /// A recorded input holds a sealed value whose subject key this node's
    /// keystore lacks.
    #[error("replay failed: {0}")]
    KeyMissing(kronik_runtime::RunError),
}

/// One kind's code in the fork.
#[derive(Clone)]
pub struct ForkKind {
    pub hash: CodeHash,
    pub program: Arc<Program>,
    pub schema_version: u32,
}

/// Everything a replay needs besides the stores.
pub struct ReplaySetup {
    pub fork: String,
    pub index: Arc<ProductionIndex>,
    pub kinds: BTreeMap<String, ForkKind>,
    pub config: Arc<Config>,
    pub epoch: u64,
    pub secrets: Option<Arc<SecretStore>>,
    /// Canned answers for effects without a recording (synthetic).
    pub stubs: Vec<crate::stubs::StubRule>,
    /// `[fork] live_allowlist`: hosts whose unrecorded GETs without secret
    /// headers may go out live (I7: nothing else ever leaves a fork).
    pub live: Option<LiveAccess>,
    /// What the fork sees of production's user data (M8).
    pub privacy: crate::privacy::ForkPrivacy,
    /// Production's live `state.db` when its actor and kv rows match a
    /// rebuilt store. `run` uses it instead of replaying the window again.
    pub prod_store: Option<Arc<Store>>,
    /// Counts the root inputs replayed, when someone follows the replay.
    pub progress: Option<Arc<Progress>>,
}

/// Live access from a fork: the allowlisted hosts and the environment
/// whose network and timer carry the request.
#[derive(Clone)]
pub struct LiveAccess {
    pub hosts: Vec<String>,
    pub env: Env,
}

impl ReplaySetup {
    /// A setup without stubs or live access.
    pub fn new(
        fork: String,
        index: Arc<ProductionIndex>,
        kinds: BTreeMap<String, ForkKind>,
        config: Config,
        secrets: Option<Arc<SecretStore>>,
    ) -> ReplaySetup {
        ReplaySetup {
            fork,
            index,
            kinds,
            epoch: config.epoch,
            config: Arc::new(config),
            secrets,
            stubs: Vec::new(),
            live: None,
            privacy: crate::privacy::ForkPrivacy::plain(),
            prod_store: None,
            progress: None,
        }
    }
}

/// How far a replay has come (M10: `kronik proposal status`): root inputs
/// done and to do, per mode. Counters only; they never change a result.
#[derive(Debug, Default)]
pub struct Progress {
    pub isolated_done: std::sync::atomic::AtomicU64,
    pub isolated_total: std::sync::atomic::AtomicU64,
    pub continuous_done: std::sync::atomic::AtomicU64,
    pub continuous_total: std::sync::atomic::AtomicU64,
    /// Test hook: each isolated root input waits for a permit first.
    #[doc(hidden)]
    pub gate: Option<Arc<tokio::sync::Semaphore>>,
}

impl Progress {
    fn add(counter: &std::sync::atomic::AtomicU64, n: u64) {
        counter.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A turn the fork ran.
#[derive(Debug, Clone)]
pub struct ForkTurn {
    /// `<fork>:<lsn>` (continuous) or `<fork>:r<root_lsn>.<n>` (isolated).
    pub id: String,
    pub record: pb::TurnRecord,
    /// The LSN it was applied at in its store (the fork log's LSN in
    /// continuous replay).
    pub lsn: Lsn,
    /// The matched production turn.
    pub prod_lsn: Option<Lsn>,
    /// It read a pseudonym or an erased value, or is [`ForkTurn::sql`]
    /// (`--no-pii` forks): a difference is `pii-masked`, not a divergence
    /// (M8 §9).
    pub masked: bool,
    /// It read a pseudonym or an erased value: it did not run on real
    /// data, so failing where production committed is no introduced error.
    pub pseudonyms: bool,
    /// `--no-pii` forks: it used SQL, called a turn that did, or was sent
    /// by one, so its values may hold real SQL rows (SQL is not
    /// pseudonymized). Implies `masked`; see [`crate::privacy::conceal_turn`].
    pub sql: bool,
}

/// The fork turns of one root input's tree (isolated replay).
pub struct TreeResult {
    pub root_lsn: Lsn,
    pub turns: Vec<ForkTurn>,
}

/// A fresh in-memory store (production cursors and fork stores).
pub fn memory_store() -> Result<Arc<Store>, ReplayError> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| ReplayError::Store(kronik_store::StoreError::Sqlite(e)))?;
    Ok(Store::open(
        conn,
        SqlPool::new(Arc::new(MemOpener), Limits::default(), usize::MAX),
    )?)
}

/// A production cursor at the start of the index: its base snapshot loaded
/// into memory, else an empty store.
pub fn cursor(index: &ProductionIndex) -> Result<Arc<Store>, ReplayError> {
    let store = match &index.base {
        Some(b) => Store::open_snapshot_in_memory(&b.dir)?,
        None => memory_store()?,
    };
    // Production's sealed SQL changesets are opened as they are applied.
    store.set_sealer(index.sealer.clone());
    Ok(store)
}

/// Applies production records up to and including `upto`.
pub fn advance(store: &Store, index: &ProductionIndex, upto: Lsn) -> Result<(), ReplayError> {
    let from = store.applied.get();
    if upto <= from {
        return Ok(());
    }
    let first = index.first_lsn();
    let start = (from + 1).saturating_sub(first) as usize;
    let end = ((upto + 1).saturating_sub(first) as usize).min(index.records.len());
    if start >= end {
        return Ok(());
    }
    let cap = if end - start >= 8_192 { 65_536 } else { 512 };
    for chunk in index.records[start..end].chunks(cap) {
        store.apply(chunk)?;
    }
    Ok(())
}

/// A pending fork turn.
struct Pending {
    actor: ActorRef,
    input: pb::Input,
    key: pb::CausalKey,
    time: u64,
    subject: Option<String>,
    /// Sent by a turn whose values may hold real SQL rows ([`ForkTurn::sql`]).
    sql: bool,
}

struct Runner {
    setup: Arc<ReplaySetup>,
    store: Arc<Store>,
    prefix: String,
    isolated: bool,
    counter: AtomicU64,
    turns: Mutex<Vec<ForkTurn>>,
    queue: Mutex<BTreeMap<Vec<u64>, Pending>>,
    /// Queued fork timers: (actor, id) -> order key.
    timers: Mutex<BTreeMap<(ActorRef, u64), Vec<u64>>>,
    timer_seq: AtomicU64,
    /// Production LSN through which an isolated tree has merged records that
    /// are not its own turns. A matched consequence reads state at its place.
    caught_up: Mutex<Lsn>,
    /// Isolated leaf turns not yet applied to the store, in tree order.
    /// The next turn of the tree may read what they wrote, so it applies
    /// them first ([`Runner::flush_leaves`]); a leaf that ends the tree is
    /// never applied (the overlay is rolled back and the diff is built
    /// from the records).
    leaves: Mutex<Vec<pb::TurnRecord>>,
}

impl Runner {
    fn new(
        setup: Arc<ReplaySetup>,
        store: Arc<Store>,
        prefix: String,
        isolated: bool,
    ) -> Arc<Runner> {
        Arc::new(Runner {
            setup,
            store,
            prefix,
            isolated,
            counter: AtomicU64::new(0),
            turns: Mutex::new(Vec::new()),
            queue: Mutex::new(BTreeMap::new()),
            timers: Mutex::new(BTreeMap::new()),
            timer_seq: AtomicU64::new(0),
            caught_up: Mutex::new(0),
            leaves: Mutex::new(Vec::new()),
        })
    }

    /// Applies the buffered leaf records, in tree order. Runs before the
    /// next turn of the tree (a consequence, a callee, a migration) so it
    /// reads the state they wrote, and before `catch_up` merges production
    /// records that are newer than a leaf.
    fn flush_leaves(&self) -> Result<(), ReplayError> {
        for record in std::mem::take(&mut *lock(&self.leaves)) {
            self.apply(record)?;
        }
        Ok(())
    }

    fn push(&self, order: Vec<u64>, p: Pending) {
        lock(&self.queue).insert(order, p);
    }

    /// The order key of a child turn: its production LSN when matched,
    /// else right after its parent.
    fn child_order(&self, parent: &[u64], key: &pb::CausalKey, ordinal: u32) -> Vec<u64> {
        match self.setup.index.turn(key) {
            Some((lsn, _)) => vec![lsn],
            None => {
                let mut o = parent.to_vec();
                o.push(u64::from(ordinal) + 1);
                o
            }
        }
    }

    /// Before a matched turn that production committed after the root, apply
    /// the records in between that are not this tree. The overlay still
    /// starts at the tree's first record, so a timer (or any later
    /// consequence) would otherwise read state from before later root inputs
    /// and the diff would attribute their writes to this tree. Tree turns are
    /// skipped: the fork runs those. Records are renumbered onto the cursor
    /// so the applier's consecutive-LSN rule holds inside the overlay.
    fn catch_up(&self, p: &Pending) -> Result<(), ReplayError> {
        if !self.isolated || p.key.path.is_empty() {
            return Ok(());
        }
        let Some((prod_lsn, _)) = self.setup.index.turn(&p.key) else {
            return Ok(());
        };
        let Some(root_lsn) = self.setup.index.root_turn_lsn(&p.key.root) else {
            return Ok(());
        };
        // A callee that committed before its caller already belongs to the
        // state the tree started from, or runs as its own fork turn.
        if prod_lsn <= root_lsn {
            return Ok(());
        }
        let mut caught = lock(&self.caught_up);
        let from = (*caught).max(root_lsn).saturating_add(1);
        if from >= prod_lsn {
            return Ok(());
        }
        let skip = self.setup.index.tree_lsns(&p.key.root);
        let mut batch = Vec::new();
        for lsn in from..prod_lsn {
            if skip.is_some_and(|s| s.binary_search(&lsn).is_ok()) {
                continue;
            }
            let Some(c) = self.setup.index.record(lsn) else {
                continue;
            };
            if let Record::TurnBegin(b) = &c.record
                && b.causal_key.as_ref().is_some_and(|k| k.root == p.key.root)
            {
                continue;
            }
            let next = self.store.applied.get() + 1 + batch.len() as u64;
            batch.push(Committed {
                lsn: next,
                pos: c.pos,
                record: c.record.clone(),
            });
        }
        for chunk in batch.chunks(512) {
            self.store.apply(chunk)?;
        }
        *caught = prod_lsn - 1;
        Ok(())
    }

    /// Runs queued turns in order until the queue is empty.
    async fn drain(self: Arc<Self>) -> Result<(), ReplayError> {
        loop {
            let next = lock(&self.queue).pop_first();
            let Some((order, p)) = next else {
                return Ok(());
            };
            self.flush_leaves()?;
            self.catch_up(&p)?;
            let root = p.key.path.is_empty();
            // A timer the fork no longer has pending is skipped: still done.
            let skip = match &p.input.kind {
                Some(pb::input::Kind::Timer(t)) => {
                    lock(&self.timers).remove(&(p.actor.clone(), t.timer_id));
                    !self
                        .store
                        .db()
                        .timer_pending(&p.actor.kind, &p.actor.key, t.timer_id)?
                }
                _ => false,
            };
            if !skip {
                self.clone().run(p, order).await?;
            }
            if root
                && !self.isolated
                && let Some(progress) = &self.setup.progress
            {
                Progress::add(&progress.continuous_done, 1);
            }
        }
    }

    /// Schedules a fork timer. An isolated tree fires only the timers
    /// production fired in the window (the fork set the same timer: its turn
    /// has the production turn's causal key), at the production turn's
    /// place; continuous replay fires every timer that comes due.
    fn schedule_timer(
        &self,
        actor: &ActorRef,
        key: pb::CausalKey,
        op: &pb::TimerOp,
        scheduled_by: &str,
        sql: bool,
    ) {
        let order = match self.setup.index.turn(&key) {
            Some((lsn, _)) => vec![lsn],
            None if self.isolated => return,
            None => match self.setup.index.first_root_at_or_after(op.due_ms) {
                // Right before the first production position at or after
                // the due time.
                Some(r) => vec![
                    r.lsn - 1,
                    u64::MAX,
                    self.timer_seq.fetch_add(1, Ordering::Relaxed),
                ],
                None => return,
            },
        };
        let input = pb::Input {
            kind: Some(pb::input::Kind::Timer(pb::TimerInput {
                timer_id: op.timer_id,
                msg: op.msg.clone(),
                due_ms: op.due_ms,
                scheduled_by: scheduled_by.to_owned(),
            })),
        };
        let subject = op
            .msg
            .as_ref()
            .and_then(|m| m.body.as_ref())
            .and_then(|b| b.subject.clone());
        lock(&self.timers).insert((actor.clone(), op.timer_id), order.clone());
        self.push(
            order,
            Pending {
                actor: actor.clone(),
                input,
                key,
                time: op.due_ms,
                subject,
                sql,
            },
        );
    }

    fn cancel_timer(&self, actor: &ActorRef, id: u64) {
        if let Some(order) = lock(&self.timers).remove(&(actor.clone(), id)) {
            lock(&self.queue).remove(&order);
        }
    }

    fn next_id(&self, lsn: Lsn) -> String {
        if self.isolated {
            format!(
                "{}{}",
                self.prefix,
                self.counter.fetch_add(1, Ordering::Relaxed)
            )
        } else {
            format!("{}{lsn}", self.prefix)
        }
    }

    fn apply(&self, record: pb::TurnRecord) -> Result<Lsn, ReplayError> {
        let lsn = self.store.applied.get() + 1;
        self.store.apply(&[Committed {
            lsn,
            pos: Position {
                segment: 0,
                offset: 0,
            },
            record: Record::TurnRecord(record),
        }])?;
        Ok(lsn)
    }

    fn record_unrun(
        &self,
        p: &Pending,
        hash: Option<CodeHash>,
        code: &str,
        message: String,
    ) -> Result<ForkTurn, ReplayError> {
        let outcome = pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            error_code: code.into(),
            message,
            output: None,
        };
        let record = pb::TurnRecord {
            execution_id: String::new(),
            actor: Some(p.actor.to_pb()),
            code_hash: hash.map(|h| h.0.to_vec()).unwrap_or_default(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(p.key.clone()),
            logical_time_ms: p.time,
            input: Some(p.input.clone()),
            outcome: Some(outcome),
            config_epoch: self.setup.epoch,
            ..Default::default()
        };
        let lsn = self.apply(record.clone())?;
        let sql = p.sql;
        let pseudonyms =
            self.setup.privacy.no_pii && crate::privacy::tagged_input(record.input.as_ref());
        let turn = ForkTurn {
            id: self.next_id(lsn),
            lsn,
            prod_lsn: self.setup.index.turn(&p.key).map(|(l, _)| l),
            record,
            masked: sql || pseudonyms,
            pseudonyms,
            sql,
        };
        lock(&self.turns).push(turn.clone());
        Ok(turn)
    }

    /// Runs one fork turn (with a migrate turn first when needed), applies
    /// it, and queues its children.
    fn run(
        self: Arc<Self>,
        p: Pending,
        order: Vec<u64>,
    ) -> BoxFuture<'static, Result<ForkTurn, ReplayError>> {
        Box::pin(async move {
            self.flush_leaves()?;
            let Some(kind) = self.setup.kinds.get(&p.actor.kind).cloned() else {
                return self.record_unrun(
                    &p,
                    None,
                    "ACTOR_NOT_FOUND",
                    format!("no deployed kind {:?}", p.actor.kind),
                );
            };
            let migrate_input = matches!(p.input.kind, Some(pb::input::Kind::Migrate(_)));
            let actor_version = self
                .store
                .db()
                .actor(&p.actor.kind, &p.actor.key)?
                .map_or(0, |a| a.schema_version);
            let target = kind.schema_version.max(actor_version);
            if !migrate_input && target > actor_version {
                let m = Pending {
                    actor: p.actor.clone(),
                    input: pb::Input {
                        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                            from_schema_version: actor_version,
                            to_schema_version: target,
                        })),
                    },
                    key: causal::migrate(&p.key, &p.actor),
                    time: p.time,
                    subject: None,
                    sql: false,
                };
                let mut morder = order.clone();
                morder.push(0);
                let mt = self.clone().run(m, morder).await?;
                if mt
                    .record
                    .outcome
                    .as_ref()
                    .is_none_or(|o| o.kind != pb::OutcomeKind::Committed as i32)
                {
                    return self.record_unrun(
                        &p,
                        Some(kind.hash),
                        "TURN_FAILED",
                        format!(
                            "migration to schema version {target} failed in turn {}",
                            mt.id
                        ),
                    );
                }
            }
            let version = match &p.input.kind {
                Some(pb::input::Kind::Migrate(m)) => m.to_schema_version,
                _ => target,
            };
            self.run_turn(p, order, kind, version, migrate_input).await
        })
    }

    async fn run_turn(
        self: Arc<Self>,
        p: Pending,
        order: Vec<u64>,
        kind: ForkKind,
        schema_version: u32,
        migrate: bool,
    ) -> Result<ForkTurn, ReplayError> {
        let prod = self.setup.index.turn(&p.key);
        let prod_lsn = prod.map(|(l, _)| l);
        let (time, seed, prod_effects) = match prod {
            Some((_, t)) => (
                t.logical_time_ms,
                t.random_seed.as_slice().try_into().unwrap_or([0u8; 32]),
                t.effects.clone(),
            ),
            None => {
                let mut bytes = b"kronik.fork.seed.v1".to_vec();
                bytes.extend_from_slice(self.setup.fork.as_bytes());
                bytes.extend_from_slice(&causal::encode(&p.key));
                (p.time, *blake3::hash(&bytes).as_bytes(), Vec::new())
            }
        };
        let kl = self.setup.config.limits(&p.actor.kind);
        let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        let limits = TurnLimits {
            fuel: kl.fuel,
            memory_bytes: size(kl.memory_bytes),
            message_bytes: size(kl.message_bytes),
            state_value_bytes: size(kl.state_value_bytes),
        };
        let call_chain = match &p.input.kind {
            Some(pb::input::Kind::Message(m)) => {
                m.call_chain.iter().map(ActorRef::from_pb).collect()
            }
            _ => Vec::new(),
        };
        let gate = Arc::new(ReplayGate {
            runner: self.clone(),
            actor: p.actor.clone(),
            key: p.key.clone(),
            time,
            order: order.clone(),
            prod: prod_effects,
            call_chain,
            state: Mutex::new(GateState::default()),
        });
        let sql = Arc::new(Mutex::new(SqlTurn::new(
            self.store.clone(),
            &p.actor,
            TurnOpts {
                seed,
                time_ms: time as i64,
                default_subject: p.subject.clone(),
                migrate,
                sql_budget: limits.fuel,
                max_bytes: kl.sql_bytes_per_actor,
            },
        )));
        let req = TurnRequest {
            actor: p.actor.clone(),
            causal_key: p.key.clone(),
            logical_time_ms: time,
            seed,
            input: p.input.clone(),
            limits,
            subject: p.subject.clone(),
        };
        let state = Arc::new(crate::privacy::ForkState::new(
            self.store.clone(),
            p.actor.clone(),
            self.setup.privacy.clone(),
        ));
        let run = kind
            .program
            .run(
                req,
                state.clone(),
                Some(Box::new(SqlHandle(sql.clone()))),
                Some(Arc::new(GateHandle(gate.clone()))),
            )
            .await;
        let mut out = match run {
            Ok(o) => o,
            Err(e) => {
                let _ = lock(&sql).end(false, &[]);
                return Err(match e {
                    e @ kronik_runtime::RunError::KeyMissing(_) => ReplayError::KeyMissing(e),
                    e => ReplayError::Host(e.to_string()),
                });
            }
        };
        drop(out.sql.take());
        let mut gs = std::mem::take(&mut *lock(&gate.state));
        let mut sql_changes = Vec::new();
        let mut sql_schema = Vec::new();
        let ended = lock(&sql).end(out.committed(), &gs.secrets);
        let used_sql = !matches!(ended, Ok(None));
        match ended {
            Ok(Some(t)) => {
                sql_schema = t
                    .ddl
                    .into_iter()
                    .map(|statement| pb::SqlSchemaChange { statement })
                    .collect();
                sql_changes = t
                    .changesets
                    .into_iter()
                    .map(|(subject, cs)| pb::SqlChangeset {
                        changeset: Some(pb::Sealable {
                            subject,
                            value: Some(pb::sealable::Value::Plain(cs)),
                        }),
                    })
                    .collect();
            }
            Ok(None) => {}
            Err(msg) => {
                out.outcome = pb::Outcome {
                    kind: pb::OutcomeKind::Failed as i32,
                    error_code: "TURN_FAILED".into(),
                    message: msg,
                    output: None,
                };
                out.writes.clear();
                out.messages.clear();
                out.timers.clear();
            }
        }
        // I8, exactly as production: secret values the turn used are
        // replaced in its outputs, effect records and compensations.
        kronik_sched::scrub::output(&mut out, &gs.secrets);
        for e in &mut gs.records {
            kronik_sched::scrub::effect(e, &gs.secrets);
        }
        for m in &mut gs.compensations {
            kronik_sched::scrub::message(&mut m.msg, &gs.secrets);
        }
        let real_rows = self.setup.privacy.no_pii && (used_sql || gs.sql || p.sql);
        let committed = out.committed();
        // As in production: a turn that did not commit after an effect whose
        // outcome is unknown fails with EFFECT_OUTCOME_UNKNOWN.
        if !committed
            && gs
                .records
                .iter()
                .any(|e| e.status == pb::EffectStatus::OutcomeUnknown as i32)
        {
            out.outcome.kind = pb::OutcomeKind::EffectOutcomeUnknown as i32;
            out.outcome.error_code = "EFFECT_OUTCOME_UNKNOWN".into();
        }
        let leaf = self.isolated
            && out.messages.is_empty()
            && out.timers.is_empty()
            && gs.compensations.is_empty()
            && sql_changes.is_empty()
            && sql_schema.is_empty();
        let record = pb::TurnRecord {
            execution_id: String::new(),
            actor: Some(p.actor.to_pb()),
            code_hash: kind.hash.0.to_vec(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(p.key.clone()),
            logical_time_ms: time,
            random_seed: seed.to_vec(),
            input: Some(p.input.clone()),
            effects: gs.records,
            writes: out.writes,
            messages: out.messages,
            timers: out.timers,
            outcome: Some(out.outcome),
            fuel_used: out.fuel_used,
            sql_changes,
            compensations: if committed {
                Vec::new()
            } else {
                gs.compensations
            },
            sql_schema,
            blob_refs: Vec::new(),
            config_epoch: self.setup.epoch,
            memory_peak_bytes: out.memory_peak_bytes,
            schema_version: if committed { schema_version } else { 0 },
            // A recomputed turn's wall time says nothing about production.
            duration_us: 0,
        };
        // An isolated leaf's row is rolled back with the overlay, so it is
        // only buffered: if a later turn of the tree runs, it applies the
        // buffer first, because that turn may read what the leaf wrote (a
        // compensation reversing the callee's posting, billing-ts's
        // declined charge). A leaf that ends the tree is never applied,
        // which keeps the savepoint write away from most roots.
        let lsn = if leaf {
            lock(&self.leaves).push(record.clone());
            self.store.applied.get() + 1 + self.counter.fetch_add(1, Ordering::Relaxed)
        } else {
            self.apply(record.clone())?
        };
        let id = self.next_id(lsn);
        if committed {
            for m in &record.messages {
                let Some(to) = m.to.as_ref().map(ActorRef::from_pb) else {
                    continue;
                };
                let key = causal::child(&p.key, &p.actor, m.ordinal);
                let order = self.child_order(&order, &key, m.ordinal);
                let subject = m
                    .msg
                    .as_ref()
                    .and_then(|x| x.body.as_ref())
                    .and_then(|b| b.subject.clone());
                self.push(
                    order,
                    Pending {
                        actor: to,
                        input: message_input(pb::MessageSource::Actor, &p.actor, m, time, ""),
                        key,
                        time,
                        subject,
                        sql: real_rows,
                    },
                );
            }
            for t in &record.timers {
                if t.kind == pb::TimerOpKind::Schedule as i32 {
                    let key = causal::child(&p.key, &p.actor, t.ordinal);
                    self.schedule_timer(&p.actor, key, t, &id, real_rows);
                } else {
                    self.cancel_timer(&p.actor, t.timer_id);
                }
            }
        } else {
            for m in &record.compensations {
                let Some(to) = m.to.as_ref().map(ActorRef::from_pb) else {
                    continue;
                };
                let key = causal::compensation(&p.key, &p.actor, m.ordinal, &to);
                let compensates = causal::message_id(&p.key, m.ordinal);
                let order = self.child_order(&order, &key, m.ordinal);
                self.push(
                    order,
                    Pending {
                        actor: to,
                        input: message_input(
                            pb::MessageSource::Compensation,
                            &p.actor,
                            m,
                            time,
                            &compensates,
                        ),
                        key,
                        time,
                        subject: None,
                        sql: real_rows,
                    },
                );
            }
        }
        let pseudonyms = self.setup.privacy.no_pii
            && (state.masked()
                || crate::privacy::tagged_input(record.input.as_ref())
                || record.effects.iter().any(|e| {
                    e.grounding != pb::Grounding::Live as i32
                        && e.response.as_ref().is_some_and(|r| r.subject.is_some())
                }));
        let turn = ForkTurn {
            id,
            record,
            lsn,
            prod_lsn,
            masked: pseudonyms || (self.setup.privacy.no_pii && real_rows),
            pseudonyms,
            sql: real_rows,
        };
        lock(&self.turns).push(turn.clone());
        Ok(turn)
    }
}

fn message_input(
    source: pb::MessageSource,
    sender: &ActorRef,
    m: &pb::OutboundMessage,
    sent: u64,
    compensates: &str,
) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: source as i32,
            sender: Some(sender.to_pb()),
            msg: m.msg.clone(),
            message_id: m.message_id.clone(),
            sent_logical_time_ms: sent,
            compensates: compensates.to_owned(),
            ..Default::default()
        })),
    }
}

#[derive(Default)]
struct GateState {
    records: Vec<pb::EffectRecord>,
    compensations: Vec<pb::OutboundMessage>,
    secrets: Vec<(String, Vec<u8>)>,
    /// A callee's values may hold real SQL rows ([`ForkTurn::sql`]).
    sql: bool,
}

/// The replay effect gate of one fork turn.
struct ReplayGate {
    runner: Arc<Runner>,
    actor: ActorRef,
    key: pb::CausalKey,
    time: u64,
    order: Vec<u64>,
    prod: Vec<pb::EffectRecord>,
    call_chain: Vec<ActorRef>,
    state: Mutex<GateState>,
}

struct GateHandle(Arc<ReplayGate>);

fn plain(bytes: Vec<u8>) -> Option<pb::Sealable> {
    tagged(&None, bytes)
}

/// A recorded value of `subject`, as production records it
/// (kronik-sched's effects): the fork's log seals it, its diff redacts it.
fn tagged(subject: &Option<String>, bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.clone(),
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

/// The guest-visible text of a replay without a recording (FailClosed).
pub const NO_RECORDING: &str = "replay: no recording";

impl ReplayGate {
    fn config(&self) -> &Config {
        &self.runner.setup.config
    }

    fn prod_at(&self, ordinal: u32) -> Option<&pb::EffectRecord> {
        self.prod.iter().find(|e| e.ordinal == ordinal)
    }

    fn push(&self, rec: pb::EffectRecord) {
        lock(&self.state).records.push(rec);
    }

    fn denied(&self, ordinal: u32, kind: &str, target: String, error: String) -> pb::EffectRecord {
        pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target,
            status: pb::EffectStatus::Denied as i32,
            error,
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        }
    }

    fn synthetic(
        &self,
        ordinal: u32,
        kind: &str,
        target: String,
        fp: Vec<u8>,
        request: Option<pb::Sealable>,
    ) -> pb::EffectRecord {
        pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target,
            fingerprint: fp,
            request,
            status: pb::EffectStatus::Denied as i32,
            error: NO_RECORDING.into(),
            grounding: pb::Grounding::Synthetic as i32,
            ..Default::default()
        }
    }

    async fn fetch(&self, ordinal: u32, req: FetchRequest) -> FetchOutcome {
        let t = match parse_url(&req.url) {
            Ok(t) => t,
            Err(e) => {
                self.push(self.denied(ordinal, "http.fetch", String::new(), e.clone()));
                return FetchOutcome::Denied(e);
            }
        };
        // foreign:// is a call to a foreign actor (docs/design/m7-foreign.md
        // §11): matched against recordings like http.fetch, never sent.
        let foreign = t.scheme == "foreign";
        let kind = if foreign {
            "foreign.http"
        } else {
            "http.fetch"
        };
        let cap = if foreign {
            format!("foreign:{}", t.host)
        } else {
            format!("http:{}", t.host)
        };
        let granted = if foreign {
            self.config().grant(&self.actor.kind, &cap).is_some()
        } else {
            self.config()
                .http_grant(&self.actor.kind, &t.host)
                .is_some()
        };
        if !granted {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, kind, cap, e.clone()));
            return FetchOutcome::Denied(e);
        }
        if foreign && self.config().foreign(&t.host).is_none() {
            let e = format!("FOREIGN_NOT_FOUND: no foreign actor {}", t.host);
            self.push(self.denied(ordinal, kind, cap, e.clone()));
            return FetchOutcome::Denied(e);
        }
        let prod = self.prod_at(ordinal).cloned();
        let prod_req = prod.as_ref().filter(|p| p.kind == kind).and_then(|p| {
            pb::HttpEffectRequest::decode(sealable_bytes(p.request.as_ref()).as_slice()).ok()
        });
        let mut headers = Vec::new();
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("idempotency-key") {
                continue;
            }
            let v = match value {
                FetchHeader::Text(text) => pb::http_effect_header::Value::Text(text.clone()),
                FetchHeader::Secret {
                    name: secret,
                    template,
                } => {
                    let scap = format!("secret:{secret}");
                    if self.config().grant(&self.actor.kind, &scap).is_none() {
                        let e = format!("CAPABILITY_NOT_GRANTED: {scap}");
                        self.push(self.denied(ordinal, kind, scap, e.clone()));
                        return FetchOutcome::Denied(e);
                    }
                    let recorded = prod_req.as_ref().and_then(|r| {
                        r.headers.iter().find_map(|h| match &h.value {
                            Some(pb::http_effect_header::Value::Secret(s))
                                if h.name == *name && s.name == *secret =>
                            {
                                Some(s.clone())
                            }
                            _ => None,
                        })
                    });
                    pb::http_effect_header::Value::Secret(recorded.unwrap_or(pb::SecretRef {
                        name: secret.clone(),
                        template: template.clone(),
                        version: 0,
                        version_hash: Vec::new(),
                    }))
                }
            };
            headers.push(pb::HttpEffectHeader {
                name: name.clone(),
                value: Some(v),
            });
        }
        let request = pb::HttpEffectRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers,
            body: req.body.clone(),
        };
        // Keyed for a subject's request, as production records it.
        let sealer = &self.runner.setup.privacy.sealer;
        let plain_fp = fingerprint(&request).unwrap_or_default();
        let fp = sealer.effect_fingerprint(req.subject.as_deref(), plain_fp.clone());
        let encoded = tagged(&req.subject, request.encode_to_vec());
        if let (Some(p), Some(pr)) = (prod, prod_req) {
            if sealer.fingerprint_matches(req.subject.as_deref(), &p.fingerprint, &plain_fp) {
                let mut rec = p;
                rec.grounding = pb::Grounding::Exact as i32;
                let out = outcome_of_fetch(&rec);
                self.push(rec);
                return out;
            }
            if target_of(&pr).is_some() && target_of(&pr) == target_of(&request) {
                let mut rec = p;
                rec.grounding = pb::Grounding::Approximate as i32;
                rec.fingerprint = fp;
                rec.request = encoded;
                let out = outcome_of_fetch(&rec);
                self.push(rec);
                return out;
            }
        }
        let setup = &self.runner.setup;
        // Synthetic: a stub rule if one matches.
        if let Some(rule) = crate::stubs::find(&setup.stubs, &req.method, &req.url) {
            let mut rec = self.synthetic(ordinal, kind, cap, fp, encoded);
            rec.error = String::new();
            rec.status = match rule.error.as_deref() {
                Some("network") => pb::EffectStatus::Network,
                Some("timeout") => pb::EffectStatus::Timeout,
                Some("too-large") => pb::EffectStatus::TooLarge,
                Some(_) => pb::EffectStatus::Denied,
                None => pb::EffectStatus::Ok,
            } as i32;
            if rule.error.is_some() {
                rec.error = format!("stub: {}", rule.error.as_deref().unwrap_or_default());
            } else {
                rec.response = tagged(
                    &req.subject,
                    pb::HttpEffectResponse {
                        status: u32::from(rule.status),
                        headers: rule
                            .headers
                            .iter()
                            .map(|(name, value)| pb::HeaderPair {
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect(),
                        body: rule.body.clone().into_bytes(),
                    }
                    .encode_to_vec(),
                );
            }
            let out = outcome_of_fetch(&rec);
            self.push(rec);
            return out;
        }
        // Live: an allowlisted host, a GET, no secret headers.
        let secretless = req
            .headers
            .iter()
            .all(|(_, v)| matches!(v, FetchHeader::Text(_)));
        if let Some(live) = &setup.live
            && t.scheme != "foreign"
            && req.method.eq_ignore_ascii_case("GET")
            && secretless
            && live.hosts.contains(&t.host)
        {
            let env = live.env.clone();
            return self.fetch_live(ordinal, cap, fp, encoded, req, env).await;
        }
        self.push(self.synthetic(ordinal, kind, cap, fp, encoded));
        FetchOutcome::Denied(NO_RECORDING.into())
    }

    /// A live GET from a fork (`[fork] live_allowlist`), grounding `live`.
    async fn fetch_live(
        &self,
        ordinal: u32,
        cap: String,
        fp: Vec<u8>,
        encoded: Option<pb::Sealable>,
        req: FetchRequest,
        env: Env,
    ) -> FetchOutcome {
        let limits = self.config().limits(&self.actor.kind);
        let headers = req
            .headers
            .iter()
            .filter_map(|(n, v)| match v {
                FetchHeader::Text(t) => Some((n.clone(), t.clone())),
                FetchHeader::Secret { .. } => None,
            })
            .collect();
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: "http.fetch".into(),
            target: cap,
            fingerprint: fp,
            request: encoded,
            delivery: "replay-safe".into(),
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        };
        let call = env.net.http(kronik_core::env::HttpRequest {
            method: req.method,
            url: req.url,
            headers,
            body: req.body.into(),
            max_response_bytes: limits.effect_response_bytes,
        });
        rec.status = match env.timeout(limits.effect_timeout, call).await {
            Err(_) => {
                rec.error = format!(
                    "no response within {} ms",
                    limits.effect_timeout.as_millis()
                );
                pb::EffectStatus::Timeout
            }
            Ok(Err(kronik_core::env::NetError::TooLarge)) => {
                rec.error = format!(
                    "the response exceeds {} bytes",
                    limits.effect_response_bytes
                );
                pb::EffectStatus::TooLarge
            }
            Ok(Err(kronik_core::env::NetError::Connect(e) | kronik_core::env::NetError::Io(e))) => {
                rec.error = e;
                pb::EffectStatus::Network
            }
            Ok(Ok(resp)) => {
                rec.response = tagged(
                    &req.subject,
                    pb::HttpEffectResponse {
                        status: u32::from(resp.status),
                        headers: resp
                            .headers
                            .into_iter()
                            .map(|(name, value)| pb::HeaderPair { name, value })
                            .collect(),
                        body: resp.body.to_vec(),
                    }
                    .encode_to_vec(),
                );
                pb::EffectStatus::Ok
            }
        } as i32;
        let out = outcome_of_fetch(&rec);
        self.push(rec);
        out
    }

    async fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> Result<CallOutcome, GateError> {
        let message_id = causal::message_id(&self.key, ordinal);
        let request = pb::CallEffectRequest {
            to: Some(to.to_pb()),
            msg: Some(msg.clone()),
            compensate: compensate.clone(),
            message_id: message_id.clone(),
        };
        let encoded = request.encode_to_vec();
        // The request holds the message: it is the message's subject's data.
        let msg_subject = msg.body.as_ref().and_then(|b| b.subject.clone());
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: "actor.call".into(),
            target: format!("actor:{to}"),
            fingerprint: self.runner.setup.privacy.sealer.effect_fingerprint(
                msg_subject.as_deref(),
                blake3::hash(&encoded).as_bytes().to_vec(),
            ),
            request: tagged(&msg_subject, encoded),
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        };
        let (outcome, turn_id) = if to == self.actor || self.call_chain.contains(&to) {
            (CallOutcome::Reentrant, String::new())
        } else if !self.runner.setup.kinds.contains_key(&to.kind) {
            (CallOutcome::NotFound, String::new())
        } else {
            let mut chain = self.call_chain.clone();
            chain.push(self.actor.clone());
            let key = causal::child(&self.key, &self.actor, ordinal);
            let order = self.runner.child_order(&self.order, &key, ordinal);
            let subject = msg.body.as_ref().and_then(|b| b.subject.clone());
            let input = pb::Input {
                kind: Some(pb::input::Kind::Message(pb::MessageInput {
                    source: pb::MessageSource::Call as i32,
                    sender: Some(self.actor.to_pb()),
                    msg: Some(msg),
                    message_id,
                    sent_logical_time_ms: self.time,
                    call_chain: chain.iter().map(ActorRef::to_pb).collect(),
                    ..Default::default()
                })),
            };
            let turn = self
                .runner
                .clone()
                .run(
                    Pending {
                        actor: to.clone(),
                        input,
                        key,
                        time: self.time,
                        subject,
                        sql: false,
                    },
                    order,
                )
                .await
                .map_err(|e| GateError::Host(e.to_string()))?;
            let o = turn.record.outcome.clone().unwrap_or_default();
            if turn.sql {
                lock(&self.state).sql = true;
            }
            (map_call_outcome(&o), turn.id)
        };
        rec.status = match &outcome {
            CallOutcome::Ok(reply) => {
                let reply_subject = reply
                    .as_ref()
                    .and_then(|m| m.body.as_ref())
                    .and_then(|b| b.subject.clone());
                rec.response = tagged(
                    &reply_subject,
                    pb::CallEffectResponse {
                        reply: reply.clone(),
                        turn_id,
                    }
                    .encode_to_vec(),
                );
                pb::EffectStatus::Ok
            }
            CallOutcome::NotFound => pb::EffectStatus::NotFound,
            CallOutcome::Rejected(m) => {
                rec.error = m.clone();
                pb::EffectStatus::Rejected
            }
            CallOutcome::Failed(m) => {
                rec.error = m.clone();
                pb::EffectStatus::Failed
            }
            CallOutcome::Reentrant => pb::EffectStatus::Reentrant,
            CallOutcome::Timeout => pb::EffectStatus::Timeout,
        } as i32;
        let out = outcome_of_call(&rec);
        if let (CallOutcome::Ok(_), Some(c)) = (&outcome, compensate) {
            let key = causal::compensation(&self.key, &self.actor, ordinal, &to);
            lock(&self.state).compensations.push(pb::OutboundMessage {
                to: Some(to.to_pb()),
                msg: Some(c),
                ordinal,
                message_id: causal::causal_id(&key),
            });
        }
        self.push(rec);
        Ok(out)
    }

    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> CryptoOutcome {
        let (kind, alg) = match algorithm {
            CryptoAlgorithm::HmacSha256 => ("crypto.hmac-sha256", "hmac-sha256"),
            CryptoAlgorithm::SignEd25519 => ("crypto.sign-ed25519", "sign-ed25519"),
        };
        let cap = format!("secret:{secret}");
        if self.config().grant(&self.actor.kind, &cap).is_none() {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, kind, cap, e.clone()));
            return CryptoOutcome::Denied(e);
        }
        let data_hash = blake3::hash(&data).as_bytes().to_vec();
        let mut h = blake3::Hasher::new();
        h.update(alg.as_bytes());
        h.update(b"\0");
        h.update(secret.as_bytes());
        h.update(b"\0");
        h.update(&data_hash);
        let fp = h.finalize().as_bytes().to_vec();
        if let Some(p) = self
            .prod_at(ordinal)
            .filter(|p| p.kind == kind && p.fingerprint == fp)
            .cloned()
        {
            let mut rec = p;
            rec.grounding = pb::Grounding::Exact as i32;
            let out = if rec.status == pb::EffectStatus::Ok as i32 {
                CryptoOutcome::Ok(sealable_bytes(rec.response.as_ref()))
            } else if rec.status == pb::EffectStatus::Denied as i32 {
                CryptoOutcome::Denied(rec.error.clone())
            } else {
                CryptoOutcome::Unsupported(rec.error.clone())
            };
            self.push(rec);
            return out;
        }
        // Unmatched: computed on the host, the value never leaves it.
        let value = self
            .runner
            .setup
            .secrets
            .as_ref()
            .and_then(|s| s.current(&secret).ok().flatten());
        let Some(v) = value else {
            self.push(self.synthetic(ordinal, kind, cap, fp, None));
            return CryptoOutcome::Denied(NO_RECORDING.into());
        };
        lock(&self.state)
            .secrets
            .push((secret.clone(), v.value.clone()));
        let result = match algorithm {
            CryptoAlgorithm::HmacSha256 => Ok(kronik_effects::crypto::hmac_sha256(&v.value, &data)),
            CryptoAlgorithm::SignEd25519 => kronik_effects::crypto::sign_ed25519(&v.value, &data),
        };
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target: cap,
            fingerprint: fp,
            grounding: pb::Grounding::Exact as i32,
            ..Default::default()
        };
        let out = match result {
            Ok(o) => {
                rec.status = pb::EffectStatus::Ok as i32;
                rec.response = plain(o.clone());
                CryptoOutcome::Ok(o)
            }
            Err(e) => {
                rec.status = pb::EffectStatus::Failed as i32;
                rec.error = e.clone();
                CryptoOutcome::Unsupported(e)
            }
        };
        self.push(rec);
        out
    }

    fn reveal(&self, ordinal: u32, name: String) -> Result<String, String> {
        let kind = "secret.reveal";
        let cap = format!("secret-reveal:{name}");
        if self.config().grant(&self.actor.kind, &cap).is_none() {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, kind, cap, e.clone()));
            return Err(e);
        }
        let fp = blake3::hash(format!("reveal\0{name}").as_bytes())
            .as_bytes()
            .to_vec();
        // A fork never gets a secret's value (brief, effect table): reveal
        // answers the placeholder that production's records hold in place
        // of the value, so requests built from it match the recordings.
        let matched = self
            .prod_at(ordinal)
            .is_some_and(|p| p.kind == kind && p.fingerprint == fp);
        self.push(pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target: cap,
            fingerprint: fp,
            status: pb::EffectStatus::Ok as i32,
            grounding: if matched {
                pb::Grounding::Exact
            } else {
                pb::Grounding::Synthetic
            } as i32,
            ..Default::default()
        });
        Ok(format!("[secret:{name}]"))
    }
}

impl EffectGate for GateHandle {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { Ok(g.fetch(ordinal, req).await) })
    }

    fn call(
        &self,
        ordinal: u32,
        to: ActorRef,
        msg: pb::Message,
        compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { g.call(ordinal, to, msg, compensate).await })
    }

    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { Ok(g.crypto(ordinal, algorithm, secret, data)) })
    }

    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { Ok(g.reveal(ordinal, name)) })
    }
}

fn root_pending(r: &RootInput) -> Pending {
    Pending {
        actor: r.actor.clone(),
        input: r.input.clone(),
        key: r.causal_key.clone(),
        time: r.logical_time_ms,
        subject: r.subject.clone(),
        sql: false,
    }
}

/// Fewest root inputs left in a range that a worker with none splits: a
/// fresh production cursor costs about as much as a few hundred roots.
const MIN_SPLIT: usize = 1_024;

/// Root inputs of an isolated replay, in order of their trees' first
/// records, in contiguous ranges. A worker takes its range from the front;
/// a worker without roots left splits off the back half of the longest
/// range, so a worker done early (or the continuous replay's task, once it
/// is done) takes part of the rest. A root's result depends only on
/// production's state before its first record (§3.3), so where ranges
/// split changes no byte of the diff.
struct Shares {
    roots: Vec<RootInput>,
    /// Per range: the next root and the end. The first `initial` are the
    /// contiguous ranges a worker each starts on; splits add the others.
    ranges: Mutex<Vec<(usize, usize)>>,
    initial: usize,
    min_split: usize,
}

impl Shares {
    fn new(mut roots: Vec<RootInput>, ranges: usize, min_split: usize) -> Arc<Shares> {
        roots.sort_by_key(|r| r.start_lsn);
        let n = roots.len();
        let ranges = ranges.clamp(1, n.max(1));
        let per = n.div_ceil(ranges).max(1);
        let initial = ranges;
        let ranges = (0..ranges)
            .map(|i| ((i * per).min(n), ((i + 1) * per).min(n)))
            .collect();
        Arc::new(Shares {
            roots,
            ranges: Mutex::new(ranges),
            initial,
            min_split: min_split.max(2),
        })
    }

    /// The next root for the worker on `range`, or `None` when none is left
    /// for it. A split moves the worker to the range it split off.
    fn next(&self, range: &mut Option<usize>) -> Option<usize> {
        let mut ranges = lock(&self.ranges);
        if let Some((next, end)) = range.and_then(|r| ranges.get_mut(r))
            && *next < *end
        {
            *next += 1;
            return Some(*next - 1);
        }
        let (r, left) = ranges
            .iter()
            .enumerate()
            .map(|(r, &(next, end))| (r, end - next))
            .max_by_key(|&(r, left)| (left, std::cmp::Reverse(r)))?;
        if left < self.min_split {
            return None;
        }
        let (next, end) = ranges.get_mut(r)?;
        let mid = *next + left / 2;
        let end_old = *end;
        *end = mid;
        ranges.push((mid + 1, end_old));
        *range = Some(ranges.len() - 1);
        Some(mid)
    }

    /// Replays roots until none is left for this worker.
    async fn work(
        self: Arc<Self>,
        setup: Arc<ReplaySetup>,
        mut range: Option<usize>,
    ) -> Result<Vec<TreeResult>, ReplayError> {
        let mut store: Option<Arc<Store>> = None;
        let mut out = Vec::new();
        while let Some(i) = self.next(&mut range) {
            let Some(r) = self.roots.get(i) else { break };
            if let Some(gate) = setup.progress.as_ref().and_then(|p| p.gate.as_ref())
                && let Ok(permit) = gate.acquire().await
            {
                permit.forget();
            }
            // Production state before the tree's first record: a root
            // turn's callees commit before the root's own record.
            let before = r.start_lsn - 1;
            // A cursor only moves forward: a range split off behind it
            // needs a fresh one.
            let store = match &store {
                Some(s) if s.applied.get() <= before => s.clone(),
                _ => {
                    let s = cursor(&setup.index)?;
                    store = Some(s.clone());
                    s
                }
            };
            advance(&store, &setup.index, before)?;
            let applied = store.overlay_begin()?;
            let runner = Runner::new(
                setup.clone(),
                store.clone(),
                format!("{}:r{}.", setup.fork, r.lsn),
                true,
            );
            runner.push(vec![r.lsn], root_pending(r));
            let res = runner.clone().drain().await;
            store.overlay_rollback(applied)?;
            res?;
            let turns = std::mem::take(&mut *lock(&runner.turns));
            out.push(TreeResult {
                root_lsn: r.lsn,
                turns,
            });
            if let Some(progress) = &setup.progress {
                Progress::add(&progress.isolated_done, 1);
            }
        }
        Ok(out)
    }
}

/// Runs one worker per initial range of `shares`; the results come in no
/// particular order.
async fn isolated_on(
    env: &Env,
    setup: Arc<ReplaySetup>,
    shares: Arc<Shares>,
) -> Result<Vec<TreeResult>, ReplayError> {
    let mut handles = Vec::new();
    for r in 0..shares.initial {
        let work = shares.clone().work(setup.clone(), Some(r));
        handles.push(env.spawn("replay-worker", work));
    }
    let mut results = Vec::with_capacity(shares.roots.len());
    for h in handles {
        let part = h
            .await
            .ok_or_else(|| ReplayError::Host("a replay worker was dropped".into()))??;
        results.extend(part);
    }
    Ok(results)
}

/// Isolated replay of `roots` (in LSN order) with `workers` workers; the
/// result does not depend on `workers`.
pub async fn isolated(
    env: &Env,
    setup: Arc<ReplaySetup>,
    roots: Vec<RootInput>,
    workers: usize,
) -> Result<Vec<TreeResult>, ReplayError> {
    let shares = Shares::new(roots, workers, MIN_SPLIT);
    let mut results = isolated_on(env, setup, shares).await?;
    results.sort_by_key(|t| t.root_lsn);
    Ok(results)
}

/// [`isolated`] that starts `ranges` workers on contiguous ranges and
/// `splitters` more that start by splitting the longest range, splitting
/// ranges of at least `min_split` roots. For tests of the split.
#[doc(hidden)]
pub async fn isolated_split(
    env: &Env,
    setup: Arc<ReplaySetup>,
    roots: Vec<RootInput>,
    ranges: usize,
    splitters: usize,
    min_split: usize,
) -> Result<Vec<TreeResult>, ReplayError> {
    let shares = Shares::new(roots, ranges, min_split);
    let mut late = Vec::new();
    for _ in 0..splitters {
        late.push(env.spawn("replay-worker", shares.clone().work(setup.clone(), None)));
    }
    let mut results = isolated_on(env, setup, shares).await?;
    for h in late {
        results.extend(
            h.await
                .ok_or_else(|| ReplayError::Host("a replay worker was dropped".into()))??,
        );
    }
    results.sort_by_key(|t| t.root_lsn);
    Ok(results)
}

/// A continuous replay: the fork's own store evolving over every root
/// input in production order. Kept alive so catch-up can extend it.
pub struct Continuous {
    setup: Arc<ReplaySetup>,
    runner: Arc<Runner>,
    pub store: Arc<Store>,
    pub replayed_to: Lsn,
}

impl Continuous {
    /// State at the fork point plus the fork's own leading records (its
    /// `BranchCreated` and `Deployment`, at `fork_lsn + 1..`), with the
    /// timers pending there queued.
    pub fn start(setup: Arc<ReplaySetup>, head: &[Record]) -> Result<Continuous, ReplayError> {
        let store = cursor(&setup.index)?;
        advance(&store, &setup.index, setup.index.fork_lsn)?;
        for r in head {
            store.apply(&[Committed {
                lsn: store.applied.get() + 1,
                pos: Position {
                    segment: 0,
                    offset: 0,
                },
                record: r.clone(),
            }])?;
        }
        let runner = Runner::new(
            setup.clone(),
            store.clone(),
            format!("{}:", setup.fork),
            false,
        );
        let pending = store.db().timers(None)?;
        for t in pending {
            let op = pb::TimerOp {
                kind: pb::TimerOpKind::Schedule as i32,
                timer_id: t.timer_id,
                due_ms: t.due_ms,
                msg: Some(t.msg),
                ordinal: 0,
            };
            runner.schedule_timer(&t.actor, t.causal_key, &op, "", false);
        }
        let fork_lsn = setup.index.fork_lsn;
        Ok(Continuous {
            setup,
            runner,
            store,
            replayed_to: fork_lsn,
        })
    }

    /// Runs every root input of the index up to its end.
    pub async fn run(&mut self) -> Result<(), ReplayError> {
        self.store.begin_bulk_replay()?;
        let result: Result<(), ReplayError> = async {
            for r in self
                .setup
                .index
                .roots
                .iter()
                .filter(|r| r.lsn > self.replayed_to)
            {
                self.runner.push(vec![r.lsn], root_pending(r));
                if let Some(progress) = &self.setup.progress {
                    Progress::add(&progress.continuous_total, 1);
                }
            }
            self.runner.clone().drain().await?;
            self.replayed_to = self.setup.index.to_lsn;
            Ok(())
        }
        .await;
        // The diff reads actors and kv, not the indexes. Rebuild them so a
        // later catch-up or inspection sees a normal store.
        let end = self.store.end_bulk_replay();
        result?;
        end?;
        Ok(())
    }

    /// Continues over a longer window (catch-up): `setup` must describe the
    /// same fork with an index that extends this one.
    pub async fn extend(&mut self, setup: Arc<ReplaySetup>) -> Result<(), ReplayError> {
        let turns = std::mem::take(&mut *lock(&self.runner.turns));
        let queue = std::mem::take(&mut *lock(&self.runner.queue));
        let timers = std::mem::take(&mut *lock(&self.runner.timers));
        let runner = Runner::new(
            setup.clone(),
            self.store.clone(),
            format!("{}:", setup.fork),
            false,
        );
        *lock(&runner.turns) = turns;
        *lock(&runner.queue) = queue;
        *lock(&runner.timers) = timers;
        self.runner = runner;
        self.setup = setup;
        self.run().await
    }

    pub fn turns(&self) -> Vec<ForkTurn> {
        lock(&self.runner.turns).clone()
    }

    /// Keeps the turns `keep` returns true for; it may change them (a
    /// preview forgets its logged requests, M11).
    pub fn retain_turns(&self, keep: impl FnMut(&mut ForkTurn) -> bool) {
        lock(&self.runner.turns).retain_mut(keep);
    }

    /// How many turns it holds in memory.
    pub fn turn_count(&self) -> usize {
        lock(&self.runner.turns).len()
    }

    /// Whether the fork has code for `kind`.
    pub fn has_kind(&self, kind: &str) -> bool {
        self.setup.kinds.contains_key(kind)
    }

    /// A message into an actor of the fork, as an operator root input with
    /// `root_id`, run under the fork's code after everything replayed so
    /// far; its consequences run too. Returns the root turn.
    pub async fn send(
        &mut self,
        actor: ActorRef,
        msg: pb::Message,
        root_id: String,
        time: u64,
    ) -> Result<ForkTurn, ReplayError> {
        let key = causal::root(root_id);
        let subject = msg.body.as_ref().and_then(|b| b.subject.clone());
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Operator as i32,
                msg: Some(msg),
                message_id: causal::causal_id(&key),
                sent_logical_time_ms: time,
                ..Default::default()
            })),
        };
        self.send_input(actor, input, key, time, subject).await
    }

    /// Any input into an actor of the fork as a new root input with `key`,
    /// run under the fork's code after everything replayed so far; its
    /// consequences run too. Returns the root turn.
    pub async fn send_input(
        &mut self,
        actor: ActorRef,
        input: pb::Input,
        key: pb::CausalKey,
        time: u64,
        subject: Option<String>,
    ) -> Result<ForkTurn, ReplayError> {
        let order = vec![
            u64::MAX,
            self.runner.timer_seq.fetch_add(1, Ordering::Relaxed),
        ];
        let turn = self
            .runner
            .clone()
            .run(
                Pending {
                    actor,
                    input,
                    key,
                    time,
                    subject,
                    sql: false,
                },
                order,
            )
            .await?;
        self.runner.clone().drain().await?;
        Ok(turn)
    }
}

/// Production's state at the end of the window (for the continuous diff).
pub fn production_store(index: &ProductionIndex) -> Result<Arc<Store>, ReplayError> {
    let store = cursor(index)?;
    store.begin_bulk_replay()?;
    advance(&store, index, index.to_lsn)?;
    store.end_bulk_replay()?;
    Ok(store)
}
/// Whether `live` has the same actors and kv rows the continuous diff
/// reads from `rebuilt`. Actor LSN metadata is not compared; the diff
/// uses kind, key, the SQL flag, and kv values.
pub fn same_diff_rows(live: &Store, rebuilt: &Store) -> Result<bool, ReplayError> {
    let mut after: Option<(String, String)> = None;
    loop {
        let page = live.db().actors(
            None,
            after.as_ref().map(|(k, y)| (k.as_str(), y.as_str())),
            1000,
        )?;
        let Some(last) = page.last() else { break };
        after = Some((last.kind.clone(), last.key.clone()));
        for a in &page {
            let other = rebuilt.db().actor(&a.kind, &a.key)?;
            let Some(other) = other else {
                return Ok(false);
            };
            if other.sql != a.sql {
                return Ok(false);
            }
            let lv = live.db().kv_list(&a.kind, &a.key)?;
            let rv = rebuilt.db().kv_list(&a.kind, &a.key)?;
            if lv.len() != rv.len() {
                return Ok(false);
            }
            for (l, r) in lv.iter().zip(&rv) {
                if l.k != r.k || l.value != r.value || l.subject != r.subject {
                    return Ok(false);
                }
            }
        }
    }
    let mut after: Option<(String, String)> = None;
    loop {
        let page = rebuilt.db().actors(
            None,
            after.as_ref().map(|(k, y)| (k.as_str(), y.as_str())),
            1000,
        )?;
        let Some(last) = page.last() else { break };
        after = Some((last.kind.clone(), last.key.clone()));
        for a in &page {
            if live.db().actor(&a.kind, &a.key)?.is_none() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Isolated replay (sampled with `seed`, default the fork name) and
/// continuous replay as `options.mode` says. With both, continuous replay
/// runs on its own task next to the isolated workers, and that task takes
/// a share of the isolated roots left once it is done.
pub async fn both(
    env: &Env,
    setup: Arc<ReplaySetup>,
    options: &crate::diff::DiffOptions,
    workers: usize,
    seed: Option<&str>,
    head: &[Record],
) -> Result<(Option<Vec<TreeResult>>, Option<Continuous>), ReplayError> {
    let mode = format!("{:?}", options.mode).to_ascii_lowercase();
    kronik_metrics::inc("kronik_replay_runs_total", &[("mode", &mode)]);
    let shares = options.mode.isolated().then(|| {
        let roots = crate::sample::sample(
            &setup.index.roots,
            seed.unwrap_or(&setup.fork),
            options.sample,
        );
        let w = if options.mode.continuous() {
            workers.saturating_sub(1).max(1)
        } else {
            workers
        };
        if let Some(progress) = &setup.progress {
            Progress::add(&progress.isolated_total, roots.len() as u64);
        }
        Shares::new(roots, w, MIN_SPLIT)
    });
    let cont = if options.mode.continuous() {
        let setup = setup.clone();
        let head = head.to_vec();
        let shares = shares.clone();
        Some(env.spawn("replay-continuous", async move {
            let mut c = Continuous::start(setup.clone(), &head)?;
            c.run().await?;
            let trees = match shares {
                Some(s) => s.work(setup, None).await?,
                None => Vec::new(),
            };
            Ok::<_, ReplayError>((c, trees))
        }))
    } else {
        None
    };
    let mut trees = match &shares {
        Some(s) => Some(isolated_on(env, setup.clone(), s.clone()).await?),
        None => None,
    };
    let continuous = match cont {
        Some(h) => {
            let (c, more) = h
                .await
                .ok_or_else(|| ReplayError::Host("continuous replay was dropped".into()))??;
            if let Some(t) = &mut trees {
                t.extend(more);
            }
            Some(c)
        }
        None => None,
    };
    if let Some(t) = &mut trees {
        t.sort_by_key(|t| t.root_lsn);
    }
    Ok((trees, continuous))
}
