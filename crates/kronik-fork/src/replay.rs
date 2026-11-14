//! The replay engine (docs/design/m3-fork.md §3): isolated replay over a
//! production cursor with discarded overlays, continuous replay in a fork
//! store, the deterministic scheduler, and the replay effect gate (exact,
//! approximate and synthetic matching; no live effects, I7).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kronik_core::authority::AuthLease;
use kronik_core::causal;
use kronik_core::env::{BoxFuture, Env};
use kronik_core::error::ErrorCode;
use kronik_core::ids::{ActorRef, CodeHash, Lsn};
use kronik_effects::http::{
    CompiledScrubber, fingerprint, fingerprint_v2, parse_request_url, prepared_target,
    prepared_version, target_of, under_rules_of,
};
use kronik_effects::{Config, ConfigHistory};
use kronik_log::{Committed, Position};
use kronik_privacy::SecretStore;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, GateError, Program, SendNowOutcome, SendNowRequest, TurnLimits, TurnRequest,
};
use kronik_sched::effects::{map_call_outcome, outcome_of_fetch, outcome_of_send_now};
use kronik_sched::host::{SqlHandle, SqlTurn};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool, TurnOpts};
use prost::Message as _;

use crate::index::{ProductionIndex, RootInput};
use crate::taint::Taint;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error(transparent)]
    Store(#[from] kronik_store::StoreError),
    #[error("replay failed: {0}")]
    Host(String),
    #[error("replay prerequisite is unavailable: {0:?}")]
    Prerequisite(ErrorCode),
    /// A recorded input holds a sealed value whose subject key this node's
    /// keystore lacks.
    #[error("replay failed: {0}")]
    KeyMissing(kronik_runtime::RunError),
    /// A sealed value of a subject this node's keystore erased reached a
    /// fork turn unopened. Not a missing key: the value is gone for good.
    /// The message does not name the subject (as `Unreadable::Erased`).
    #[error(
        "replay failed: SUBJECT_ERASED: a sealed value of an erased subject reached a fork turn"
    )]
    Erased,
}

/// One kind's code in the fork.
#[derive(Clone)]
pub struct ForkKind {
    pub hash: CodeHash,
    pub program: Arc<Program>,
    pub schema_version: u32,
}

#[derive(Clone)]
enum ReplayDispatch {
    RecordedOnly,
    Authorized(AuthLease),
}

/// Everything a replay needs besides the stores.
pub struct ReplaySetup {
    pub fork: String,
    pub index: Arc<ProductionIndex>,
    pub kinds: BTreeMap<String, ForkKind>,
    pub config: Arc<Config>,
    pub epoch: u64,
    /// Engine checks replay production policy, unlike a fork's fixed overrides.
    pub(crate) upgrade_config: Option<Mutex<ConfigHistory>>,
    pub(crate) upgrade_code: BTreeMap<CodeHash, ForkKind>,
    pub secrets: Option<Arc<SecretStore>>,
    /// The values of linked secrets this process already holds (the node's
    /// secret cache): what an unmatched `crypto.*` of a `compute` grant uses
    /// for a name linked at the fork point. A fork never fetches (I7).
    pub held_secrets: Option<Arc<dyn HeldKeys>>,
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
    /// Main's simulator configuration at the fork point with the request's
    /// overrides (M12, I5, ADR 0014).
    pub simulators: Arc<crate::simulators::Simulators>,
    /// The model simulator, when the server configures one (ADR 0015).
    pub model: Option<crate::simulators::ModelAccess>,
    /// A rollback via replay (M13): its turns become main's state, so it
    /// answers from recordings only and leaves every consequence production
    /// has not run pending for main (m13-rebase §4, §8).
    pub rebase: bool,
    /// A preview fork (M11, ADR 0025). An unmatched fetch is stubbed, denied,
    /// or an allowlisted secret-less GET. The model simulator is a POST to a
    /// configured endpoint, not that GET, so it is not used.
    pub preview: bool,
    /// The fork's copies of `fork_mode = "sandbox"` foreign actors (M14,
    /// ADR 0019), used by continuous replay only.
    pub copies: Option<ForkCopies>,
    /// The budget of one turn's record (`kronik_sched::record_budget`):
    /// production's, so a replay makes the decisions production made.
    pub record_limit: usize,
    dispatch: ReplayDispatch,
}

/// The copies of foreign actors a fork's continuous replay talks to, and
/// the environment whose timer bounds each call.
#[derive(Clone)]
pub struct ForkCopies {
    pub env: Env,
    pub copies: BTreeMap<String, Arc<dyn kronik_effects::foreign::ForeignCopy>>,
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
        original: AuthLease,
    ) -> ReplaySetup {
        Self::with_dispatch(
            fork,
            index,
            kinds,
            config,
            secrets,
            ReplayDispatch::Authorized(original),
        )
    }

    /// Uses actual historical source data without granting ordinary physical I/O.
    pub fn recorded(
        fork: String,
        index: Arc<ProductionIndex>,
        kinds: BTreeMap<String, ForkKind>,
        config: Config,
        secrets: Option<Arc<SecretStore>>,
    ) -> ReplaySetup {
        Self::with_dispatch(
            fork,
            index,
            kinds,
            config,
            secrets,
            ReplayDispatch::RecordedOnly,
        )
    }

    fn with_dispatch(
        fork: String,
        index: Arc<ProductionIndex>,
        kinds: BTreeMap<String, ForkKind>,
        config: Config,
        secrets: Option<Arc<SecretStore>>,
        dispatch: ReplayDispatch,
    ) -> ReplaySetup {
        let simulators = Arc::new(crate::simulators::Simulators::new(&index, &[]));
        ReplaySetup {
            simulators,
            model: None,
            copies: None,
            fork,
            index,
            kinds,
            epoch: config.epoch,
            config: Arc::new(config),
            upgrade_config: None,
            upgrade_code: BTreeMap::new(),
            secrets,
            held_secrets: None,
            stubs: Vec::new(),
            live: None,
            privacy: crate::privacy::ForkPrivacy::plain(),
            prod_store: None,
            progress: None,
            rebase: false,
            preview: false,
            record_limit: kronik_sched::record_budget::turn_limit(kronik_log::MAX_RECORD as usize),
            dispatch,
        }
    }

    fn historical_config(&self, epoch: Option<u64>) -> Option<Arc<Config>> {
        let epoch = epoch?;
        self.upgrade_config
            .as_ref()
            .map(|history| lock(history).at(epoch))
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
    /// It met erased data: its recording holds a value whose subject was
    /// erased, it read an erased state value, or erased data shaped what it
    /// ran on (an input an unverifiable turn sent, state such a turn or a
    /// production turn missing below one left different, an actor database
    /// lacking an erased subject's rows, an unverifiable callee). The
    /// recording, not the guest's input, is the only truth, so a difference
    /// from production is `unverifiable` rather than divergent (S-16, ADR
    /// 0109; [`crate::taint`]).
    pub erased: bool,
    /// `--no-pii` forks: it used SQL, called a turn that did, or was sent
    /// by one. Its reply and record are concealed even though subject-tagged
    /// text and blob cells in the actor database are pseudonyms: a value
    /// copied into a name, key or URL is not tracked. Implies `masked`; see
    /// [`crate::privacy::conceal_turn`].
    pub sql: bool,
    /// Its values may hold personal data, in any fork: its input was tagged
    /// or came from such a turn, it read tagged state, used SQL, recorded a
    /// tagged effect value, used a secret, or called a turn that did. The
    /// model simulator declines for such turns and their consequences
    /// (ADR 0015).
    pub personal: bool,
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
    if index.no_pii {
        // A snapshot already holds the rows. Rewrite them the same way
        // revealed changesets were, before any later UPDATE is applied.
        let actors = store.db().sql_actors()?;
        for name in actors {
            let db = store
                .sql
                .get(&name)
                .map_err(|e| ReplayError::Host(e.to_string()))?;
            let mut actor = db.lock().unwrap_or_else(|e| e.into_inner());
            actor
                .pseudonymize_subject_cells(|subject, value| {
                    crate::privacy::ForkPrivacy::sql_cell(&index.sealer, subject, value)
                })
                .map_err(ReplayError::Host)?;
        }
    }
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
        // A rebase switch in production's history installs its shadow,
        // built from the same records (M13, ADR 0017).
        store.apply_with(chunk, &mut |c| {
            let (id, sw) = c
                .record
                .rebase_switch()
                .ok_or_else(|| kronik_store::StoreError::Corrupt("not a switch".into()))?;
            kronik_store::rebase::shadow_for(
                id,
                sw,
                c.lsn,
                index.base.as_ref().map(|b| (b.lsn, b.dir.as_path())),
                &index.records,
                index.sealer.clone(),
            )
        })?;
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
    /// Sent by a turn that used SQL ([`ForkTurn::sql`]).
    sql: bool,
    /// Sent by a turn whose values may hold personal data
    /// ([`ForkTurn::personal`]).
    personal: bool,
    /// Sent by a turn the replay could not verify ([`ForkTurn::erased`]): a
    /// message whose body erased data shaped is unverifiable too.
    unverified: bool,
}

/// What the scheduler runs next at its order key.
enum Queued {
    Turn(Box<Pending>),
    /// Production's `Erasure` of a subject through a key version, at its
    /// place: continuous replay deletes what production deleted there.
    Erasure(String, u32),
}

struct Runner {
    setup: Arc<ReplaySetup>,
    store: Arc<Store>,
    prefix: String,
    isolated: bool,
    counter: AtomicU64,
    turns: Mutex<Vec<ForkTurn>>,
    queue: Mutex<BTreeMap<Vec<u64>, Queued>>,
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
    /// State the store holds that the replay could not verify after an
    /// erasure (ADR 0109): a turn that reads it is unverifiable too.
    taint: Arc<Mutex<Taint>>,
    /// The production LSN the store held everything through before this
    /// runner's turns: a production turn at or below it is in the store,
    /// not one the fork may leave out.
    base: Lsn,
    /// The production turns the fork has run (their LSNs).
    ran: Mutex<std::collections::BTreeSet<Lsn>>,
    /// Calls served their recorded timeout, by call message id: where
    /// their compensation runs if the callee's turn releases it (#30).
    timed_out: Mutex<HashMap<String, TimedOutCall>>,
    /// Callee turns production closed without running them (a call lost to
    /// a restart, closed at the next start): by causal key, the error code
    /// and message the fork records instead of running the guest.
    unrun: Mutex<HashMap<Vec<u8>, (String, String)>>,
}

/// A call the fork served its recorded timeout (the fork gate's `call`).
/// Its callee's turn runs as a consequence where production ran it, and its
/// compensation, if the caller failed, goes out once that turn committed:
/// the store decides it as production's does (`released_compensation`).
struct TimedOutCall {
    /// The compensation's order key.
    order: Vec<u64>,
    /// The calling turn's taint when it made the call, which the
    /// compensation it carries inherits.
    sql: bool,
    personal: bool,
    unverified: bool,
}

impl Runner {
    fn new(
        setup: Arc<ReplaySetup>,
        store: Arc<Store>,
        prefix: String,
        isolated: bool,
        base: Lsn,
    ) -> Arc<Runner> {
        Arc::new(Runner {
            base,
            ran: Mutex::new(std::collections::BTreeSet::new()),
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
            taint: Arc::new(Mutex::new(Taint::default())),
            timed_out: Mutex::new(HashMap::new()),
            unrun: Mutex::new(HashMap::new()),
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
        lock(&self.queue).insert(order, Queued::Turn(Box::new(p)));
    }

    /// After the callee's turn of a call served its recorded timeout is
    /// applied at `lsn`: the compensation that turn released, if the caller
    /// failed first, runs where production ran it, with the caller's taint
    /// at the call ([`TimedOutCall`]).
    fn release_compensation(&self, input: &pb::Input, lsn: Lsn) -> Result<(), ReplayError> {
        let Some(pb::input::Kind::Message(m)) = input.kind.as_ref() else {
            return Ok(());
        };
        let Some(call) = lock(&self.timed_out).remove(&m.message_id) else {
            return Ok(());
        };
        let Some(row) = self.store.db().released_compensation(&m.message_id, lsn)? else {
            return Ok(());
        };
        if self.deferred(&row.causal_key) {
            return Ok(());
        }
        let time = match row.input.kind.as_ref() {
            Some(pb::input::Kind::Message(sent)) => sent.sent_logical_time_ms,
            _ => 0,
        };
        self.push(
            call.order,
            Pending {
                actor: row.to,
                input: row.input,
                key: row.causal_key,
                time,
                subject: None,
                sql: call.sql,
                personal: call.personal,
                unverified: call.unverified,
            },
        );
        Ok(())
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

    /// A rebase leaves a consequence production has not run (not in the
    /// index: in flight at the pause, or new under the old code) pending in
    /// the fork's store, so main runs it, with real effects, after the
    /// switch (m13-rebase §4). A later round queues it once production ran it.
    fn deferred(&self, key: &pb::CausalKey) -> bool {
        self.setup.rebase && self.setup.index.turn(key).is_none()
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
        let mut taint = lock(&self.taint);
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
            // Production's own record: from here on both sides hold what it
            // wrote, and its erasure deletes on both sides.
            match &c.record {
                Record::TurnRecord(t) => taint.verified_turn(t, lsn),
                Record::Erasure(e) => taint.erasure(&e.subject, lsn),
                _ => {}
            }
            let next = self.store.applied.get() + 1 + batch.len() as u64;
            batch.push(Committed {
                lsn: next,
                pos: c.pos,
                record: c.record.clone(),
            });
        }
        drop(taint);
        for chunk in batch.chunks(512) {
            self.store.apply(chunk)?;
        }
        *caught = prod_lsn - 1;
        Ok(())
    }

    /// Runs queued turns in order until the queue is empty.
    async fn drain(self: Arc<Self>, dispatch: ReplayDispatch) -> Result<(), ReplayError> {
        loop {
            let next = lock(&self.queue).pop_first();
            let Some((order, queued)) = next else {
                return Ok(());
            };
            let p = match queued {
                Queued::Turn(p) => *p,
                Queued::Erasure(subject, key_version) => {
                    self.erase(&subject, key_version, order.first().copied().unwrap_or(0))?;
                    continue;
                }
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
            } || self.resend_not_needed(&p);
            if !skip {
                self.clone().run(p, order, dispatch.clone()).await?;
            }
            if root
                && !self.isolated
                && let Some(progress) = &self.setup.progress
            {
                Progress::add(&progress.continuous_done, 1);
            }
        }
    }

    /// Production's `Erasure` of `subject` at `at`, followed by the
    /// continuous store: it deletes and tombstones what production's did
    /// there, so later turns read what production's read (ADR 0109).
    fn erase(&self, subject: &str, key_version: u32, at: Lsn) -> Result<(), ReplayError> {
        self.flush_leaves()?;
        self.store.erase_again(subject, key_version)?;
        lock(&self.taint).erasure(subject, at);
        Ok(())
    }

    /// A dead-letter resend in the window whose original the fork ran with
    /// success (M8): running it again would apply the message twice.
    fn resend_not_needed(&self, p: &Pending) -> bool {
        let Some(pb::input::Kind::Message(m)) = &p.input.kind else {
            return false;
        };
        if m.source != pb::MessageSource::DeadLetterResend as i32 {
            return false;
        }
        let Some(of) = kronik_core::ids::TurnId::parse(&m.resend_of) else {
            return false;
        };
        lock(&self.turns).iter().any(|t| {
            t.prod_lsn == Some(of.lsn)
                && t.record
                    .outcome
                    .as_ref()
                    .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
        })
    }

    /// Queues what the store holds pending (continuous replay): its timers
    /// not queued yet, and its mailbox in production delivery order (M7).
    /// A message production delivered runs at that turn's place; one it did
    /// not runs first, after `after` (a rebase leaves it for main).
    fn queue_pending(&self, after: Lsn) -> Result<(), ReplayError> {
        for mut t in self.store.db().timers(None)? {
            if lock(&self.timers).contains_key(&(t.actor.clone(), t.timer_id)) {
                continue;
            }
            kronik_proto::sealables::message_mut(Some(&mut t.msg), &mut |s| {
                self.reveal_stored(s, t.lsn)
            });
            let op = pb::TimerOp {
                kind: pb::TimerOpKind::Schedule as i32,
                timer_id: t.timer_id,
                due_ms: t.due_ms,
                msg: Some(t.msg),
                ordinal: 0,
            };
            // A fork turn of an earlier round scheduled it: its id and flags,
            // as when the timer is queued in that turn's round (review
            // M13-1). Production scheduled the others: what that turn read
            // is unknown, so they count as personal (review N12-3).
            let (by, sql, personal, unverified) = lock(&self.turns)
                .iter()
                .find(|f| f.lsn == t.lsn)
                .map_or_else(
                    || (String::new(), false, true, false),
                    |f| (f.id.clone(), f.sql, f.personal, f.erased),
                );
            self.schedule_timer(
                &t.actor,
                t.causal_key,
                &op,
                &by,
                (sql, personal, unverified),
            );
        }
        for (i, mut m) in self.store.db().mailbox()?.into_iter().enumerate() {
            let order = match self.setup.index.turn(&m.causal_key) {
                Some((lsn, _)) => vec![lsn],
                None if self.setup.rebase => continue,
                None => vec![after, i as u64],
            };
            kronik_proto::sealables::input_mut(Some(&mut m.input), &mut |s| {
                self.reveal_stored(s, m.lsn)
            });
            let (subject, time) = match &m.input.kind {
                Some(pb::input::Kind::Message(x)) => (
                    x.msg
                        .as_ref()
                        .and_then(|b| b.body.as_ref())
                        .and_then(|b| b.subject.clone()),
                    x.sent_logical_time_ms,
                ),
                _ => (None, 0),
            };
            let unverified = lock(&self.turns).iter().any(|f| f.lsn == m.lsn && f.erased);
            self.push(
                order,
                Pending {
                    actor: m.to,
                    input: m.input,
                    key: m.causal_key,
                    time,
                    subject,
                    sql: false,
                    // Production sent it (or a turn whose reads are not
                    // known here): counted as personal (review N12-3).
                    personal: true,
                    unverified,
                },
            );
        }
        Ok(())
    }

    /// A value a queued timer or message carries in the store, as the
    /// fork's guest may see it: one the base snapshot holds (`lsn` at or
    /// below it) is production's and revealed like any recorded value, one
    /// the replay wrote is revealed as written; an erased one (a tombstone
    /// the erasure left) reads `[erased]` and its turn's recording is
    /// unverifiable (ADR 0109).
    fn reveal_stored(&self, s: &mut pb::Sealable, lsn: Lsn) {
        if lsn > self.setup.index.base_lsn() {
            self.setup.privacy.reveal_written(s);
        } else {
            self.setup.privacy.reveal(s);
        }
    }

    /// Schedules a fork timer. An isolated tree fires only the timers
    /// production fired in the window (the fork set the same timer: its turn
    /// has the production turn's causal key), at the production turn's
    /// place; continuous replay fires every timer that comes due.
    /// `flags`: the scheduling turn's [`Pending::sql`], [`Pending::personal`]
    /// and [`Pending::unverified`].
    fn schedule_timer(
        &self,
        actor: &ActorRef,
        key: pb::CausalKey,
        op: &pb::TimerOp,
        scheduled_by: &str,
        (sql, personal, unverified): (bool, bool, bool),
    ) {
        let order = match self.setup.index.turn(&key) {
            Some((lsn, _)) => vec![lsn],
            None if self.isolated || self.setup.rebase => return,
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
                personal,
                unverified,
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
        order: &[u64],
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
        let config = self
            .setup
            .historical_config(self.setup.index.turn(&p.key).map(|(_, t)| t.config_epoch));
        let record = pb::TurnRecord {
            execution_id: String::new(),
            actor: Some(p.actor.to_pb()),
            code_hash: hash.map(|h| h.0.to_vec()).unwrap_or_default(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(p.key.clone()),
            logical_time_ms: p.time,
            input: Some(p.input.clone()),
            outcome: Some(outcome),
            config_epoch: config.as_ref().map_or(self.setup.epoch, |c| c.epoch),
            ..Default::default()
        };
        let lsn = self.apply(record.clone())?;
        let sql = p.sql;
        let pseudonyms =
            self.setup.privacy.no_pii && crate::privacy::tagged_input(record.input.as_ref());
        let prod = self.setup.index.turn(&p.key);
        let erased = prod.is_some_and(|(l, _)| self.setup.index.erased_turns.contains(&l))
            || self.shaped(p, prod.map(|(_, t)| t));
        self.settle(&p.key, &record, prod, order, erased);
        let turn = ForkTurn {
            id: self.next_id(lsn),
            lsn,
            prod_lsn: prod.map(|(l, _)| l),
            record,
            masked: sql || pseudonyms || erased,
            pseudonyms,
            sql,
            erased,
            personal: p.personal || p.subject.is_some(),
        };
        lock(&self.turns).push(turn.clone());
        Ok(turn)
    }

    /// Whether, at production position `at`, the actor's SQL database may
    /// hold other rows than production's because of an erasure: an
    /// unverifiable turn left it different ([`Taint`]), or an erased
    /// subject's changeset was skipped and production had not erased the
    /// rows yet ([`ProductionIndex::sql_gap`]).
    fn sql_unverified(&self, actor: &ActorRef, at: Lsn) -> Result<bool, ReplayError> {
        let name = format!("{}/{}", actor.kind, actor.key);
        if !lock(&self.taint).has_sql(&name) && !self.setup.index.has_erased_sql(&name) {
            return Ok(false);
        }
        let untagged = self
            .store
            .sql
            .get(&name)
            .map_err(|e| ReplayError::Host(e.to_string()))?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_table_without_subject()
            .map_err(ReplayError::Host)?;
        Ok(lock(&self.taint).sql(&name, at, untagged)
            || self.setup.index.sql_gap(&name, at, untagged))
    }

    /// Whether erased data shaped `p`'s input: an unverifiable turn sent it
    /// and it differs from what production's counterpart received (or there
    /// is none). Such a turn ran on stand-in data even though its own
    /// recording holds no erased value (ADR 0109).
    fn shaped(&self, p: &Pending, prod: Option<&pb::TurnRecord>) -> bool {
        p.unverified && prod.is_none_or(|t| !same_input(t.input.as_ref(), &p.input))
    }

    /// Updates the store's taint after the turn `record` at `order`: an
    /// unverifiable turn marks where it left the state different from its
    /// production counterpart's, and everything production turns below it
    /// wrote, from their own positions (the fork may never run them); a
    /// verified turn's writes replace what was marked before (ADR 0109).
    fn settle(
        &self,
        key: &pb::CausalKey,
        record: &pb::TurnRecord,
        prod: Option<(Lsn, &pb::TurnRecord)>,
        order: &[u64],
        erased: bool,
    ) {
        let at = order.first().copied().unwrap_or(0);
        if let Some((lsn, _)) = prod {
            lock(&self.ran).insert(lsn);
        }
        if !erased {
            lock(&self.taint).verified_turn(record, at);
            return;
        }
        let ran = lock(&self.ran).clone();
        let mut taint = lock(&self.taint);
        taint.unverified_turn(Some(record), prod.map(|(_, t)| t), at);
        // Below it: what production ran that the store does not hold and the
        // fork has not run (a migration or a callee that committed first is
        // in the store already, or ran in the fork).
        for (lsn, below) in self.setup.index.below(key) {
            if lsn > self.base && !ran.contains(&lsn) {
                taint.missing_turn(below, lsn);
            }
        }
    }

    /// Runs one fork turn (with a migrate turn first when needed), applies
    /// it, and queues its children.
    fn run(
        self: Arc<Self>,
        p: Pending,
        order: Vec<u64>,
        dispatch: ReplayDispatch,
    ) -> BoxFuture<'static, Result<ForkTurn, ReplayError>> {
        Box::pin(async move {
            self.flush_leaves()?;
            // A callee turn production closed without running it (#30) is
            // recorded as production recorded it, without running the guest.
            if let Some((code, message)) = lock(&self.unrun).remove(&causal::encode(&p.key)) {
                let hash = self.setup.kinds.get(&p.actor.kind).map(|k| k.hash);
                return self.record_unrun(&p, &order, hash, &code, message);
            }
            let kind = match self
                .setup
                .upgrade_config
                .as_ref()
                .and_then(|_| self.setup.index.turn(&p.key))
            {
                Some((_, turn)) => CodeHash::from_slice(&turn.code_hash)
                    .and_then(|hash| self.setup.upgrade_code.get(&hash)),
                None => self.setup.kinds.get(&p.actor.kind),
            };
            let Some(kind) = kind.cloned() else {
                return self.record_unrun(
                    &p,
                    &order,
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
                    personal: false,
                    unverified: false,
                };
                let mut morder = order.clone();
                morder.push(0);
                let mt = self.clone().run(m, morder, dispatch.clone()).await?;
                if mt
                    .record
                    .outcome
                    .as_ref()
                    .is_none_or(|o| o.kind != pb::OutcomeKind::Committed as i32)
                {
                    return self.record_unrun(
                        &p,
                        &order,
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
            self.run_turn(p, order, kind, version, migrate_input, dispatch)
                .await
        })
    }

    async fn run_turn(
        self: Arc<Self>,
        p: Pending,
        order: Vec<u64>,
        kind: ForkKind,
        schema_version: u32,
        migrate: bool,
        dispatch: ReplayDispatch,
    ) -> Result<ForkTurn, ReplayError> {
        let prod = self.setup.index.turn(&p.key);
        let prod_lsn = prod.map(|(l, _)| l);
        let erased_turn = prod_lsn.is_some_and(|lsn| self.setup.index.erased_turns.contains(&lsn));
        // What may make the turn unverifiable besides its own recording
        // (ADR 0109): an input erased data shaped, and an actor database that
        // lacks rows production had or holds rows an unverifiable turn wrote.
        let at = order.first().copied().unwrap_or(0);
        let shaped = self.shaped(&p, prod.map(|(_, t)| t));
        let sql_unverified = self.sql_unverified(&p.actor, at)?;
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
        let config = self
            .setup
            .historical_config(prod.map(|(_, t)| t.config_epoch));
        let epoch = config.as_ref().map_or(self.setup.epoch, |c| c.epoch);
        let kl = config
            .as_deref()
            .unwrap_or(&self.setup.config)
            .limits(&p.actor.kind);
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
        let state = Arc::new(
            crate::privacy::ForkState::new(
                self.store.clone(),
                p.actor.clone(),
                self.setup.privacy.clone(),
            )
            .with_base(self.setup.index.base_lsn())
            .with_taint(self.taint.clone(), at),
        );
        let erased_effects = prod_lsn
            .and_then(|lsn| self.setup.index.erased_effects.get(&lsn))
            .cloned()
            .unwrap_or_default();
        // The same record budget as production, started from what the
        // record holds before any effect, so a replay makes the same
        // decisions (kronik_sched::record_budget).
        let input_cost = kronik_sched::record_budget::input_cost(&mut p.input.clone());
        let record_limit = self.setup.record_limit;
        let budget = kronik_sched::record_budget::Budget::new(
            record_limit,
            kronik_sched::record_budget::base_cost(
                &p.actor.to_pb(),
                &kind.hash.0,
                &p.key,
                time,
                &seed,
                input_cost,
                epoch,
            ),
        );
        let gate = Arc::new(ReplayGate {
            dispatch,
            runner: self.clone(),
            config,
            actor: p.actor.clone(),
            key: p.key.clone(),
            time,
            order: order.clone(),
            prod: prod_effects,
            call_chain,
            state: Mutex::new(GateState {
                budget,
                ..GateState::default()
            }),
            erased_effects,
            input_tagged: p.subject.is_some()
                || p.personal
                || crate::privacy::tagged_input(Some(&p.input)),
            fork_state: state.clone(),
            sql: sql.clone(),
            unverified: erased_turn || shaped,
            sql_unverified,
        });
        let req = TurnRequest {
            actor: p.actor.clone(),
            causal_key: p.key.clone(),
            logical_time_ms: time,
            seed,
            input: p.input.clone(),
            limits,
            subject: p.subject.clone(),
        };
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
                let _ = lock(&sql).end(false, &[] as &[(&str, &[u8])]);
                return Err(run_error(e, &self.setup.privacy.sealer));
            }
        };
        drop(out.sql.take());
        let gs = std::mem::take(&mut *lock(&gate.state));
        let matcher =
            match CompiledScrubber::new(&gs.secrets, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES)
            {
                Ok(matcher) => matcher.into_owned(),
                Err(_) => {
                    let _ = lock(&sql).end(false, &[] as &[(&str, &[u8])]);
                    return Err(ReplayError::Prerequisite(ErrorCode::SecretUnavailable));
                }
            };
        // Output larger than one log record holds fails the turn with
        // TURN_TOO_LARGE, as in production.
        let output = kronik_sched::scrub::output(&mut out, &matcher);
        let output_too_large = matches!(output, Err(kronik_effects::http::ScrubError::OutputLimit));
        if output_too_large {
            out.writes.clear();
            out.messages.clear();
            out.timers.clear();
            out.outcome = kronik_sched::record_budget::too_large_outcome(record_limit);
        } else if output.is_err() {
            let _ = lock(&sql).end(false, &[] as &[(&str, &[u8])]);
            return Err(ReplayError::Prerequisite(ErrorCode::SecretUnavailable));
        }
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
            Err(mut msg) => {
                kronik_sched::scrub::text(&mut msg, &matcher, kronik_log::MAX_RECORD as usize)
                    .map_err(|_| ReplayError::Prerequisite(ErrorCode::SecretUnavailable))?;
                out.outcome = pb::Outcome {
                    kind: pb::OutcomeKind::Failed as i32,
                    error_code: "TURN_FAILED".into(),
                    message: msg,
                    output: None,
                };
                out.writes.clear();
                out.messages.clear();
                out.timers.clear();
                out.connection_ops.clear();
            }
        }
        let real_rows = self.setup.privacy.no_pii && (used_sql || gs.sql || p.sql);
        let personal = gate.saw_personal_with(&gs) || used_sql;
        // A turn that met erased data (S-16, ADR 0109): its recording holds
        // an erased value, erased data shaped its input, it read an erased
        // value or state erased data shaped, used an actor database that
        // lacks an erased subject's rows production had, or called a turn
        // that did. Marked whatever the mode, so the diff reports it as
        // unverifiable, not divergent.
        let erased = gate.unverified
            || state.erased()
            || (sql_unverified && used_sql)
            || gs.unverified_callee;
        // As in production: a turn that does not commit after an effect
        // whose outcome is unknown ends with EFFECT_OUTCOME_UNKNOWN, decided by
        // `fit` and `fail` below on the final record.
        let committed = out.committed();
        let compensations = gs.compensations;
        let mut record = pb::TurnRecord {
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
                compensations.clone()
            },
            sql_schema,
            blob_refs: Vec::new(),
            config_epoch: epoch,
            memory_peak_bytes: out.memory_peak_bytes,
            schema_version: if committed { schema_version } else { 0 },
            // M24: the fork's own connections table follows its turns'
            // buffered operations, as production's does (ADR 0116).
            connection_ops: if committed {
                out.connection_ops
            } else {
                Vec::new()
            },
            // A recomputed turn's wall time says nothing about production.
            duration_us: 0,
        };
        // The record budget, decided as production decides it.
        if output_too_large {
            kronik_sched::record_budget::fail(
                &mut record,
                &compensations,
                record_limit,
                input_cost,
            );
        } else {
            kronik_sched::record_budget::fit(&mut record, &compensations, record_limit, input_cost);
        }
        let committed = record
            .outcome
            .as_ref()
            .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32);
        // The callee's turn of a call served its recorded timeout: applying it
        // decides whether the call's compensation goes out (#30).
        let resolves_timed_out = match p.input.kind.as_ref() {
            Some(pb::input::Kind::Message(m)) if m.source == pb::MessageSource::Call as i32 => {
                lock(&self.timed_out).contains_key(&m.message_id)
            }
            _ => false,
        };
        let leaf = self.isolated
            && !resolves_timed_out
            && record.messages.is_empty()
            && record.timers.is_empty()
            && compensations.is_empty()
            && record.sql_changes.is_empty()
            && record.sql_schema.is_empty();
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
        if resolves_timed_out {
            self.release_compensation(&p.input, lsn)?;
        }
        if committed {
            for m in &record.messages {
                let Some(to) = m.to.as_ref().map(ActorRef::from_pb) else {
                    continue;
                };
                let key = causal::child(&p.key, &p.actor, m.ordinal);
                if self.deferred(&key) {
                    continue;
                }
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
                        personal,
                        unverified: erased,
                    },
                );
            }
            for t in &record.timers {
                if t.kind == pb::TimerOpKind::Schedule as i32 {
                    let key = causal::child(&p.key, &p.actor, t.ordinal);
                    self.schedule_timer(&p.actor, key, t, &id, (real_rows, personal, erased));
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
                if self.deferred(&key) {
                    continue;
                }
                let compensates = causal::message_id(&p.key, m.ordinal);
                // A timed-out call's compensation goes out with this record
                // only if its callee's turn committed first; else that turn
                // releases it (`release_compensation`), or drops it (#30).
                if record
                    .effects
                    .iter()
                    .any(|e| e.ordinal == m.ordinal && e.timed_out_call())
                    && self
                        .store
                        .db()
                        .released_compensation(&compensates, lsn)?
                        .is_none()
                {
                    continue;
                }
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
                        personal,
                        unverified: erased,
                    },
                );
            }
        }
        self.settle(&p.key, &record, prod, &order, erased);
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
            masked: pseudonyms || (self.setup.privacy.no_pii && real_rows) || erased,
            pseudonyms,
            sql: real_rows,
            erased,
            personal,
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

/// Whether a turn's effects used a secret (ADR 0015): a `crypto.*` effect or
/// a `secret.reveal`, whatever answered it. A signature computed on the
/// host, one served from production's recording (the guest holds a value
/// made with the key), a denied call (a `recorded` grant, ADR 0112, a
/// missing or linked key, no grant) and a reveal's placeholder all count,
/// so the model simulator declines for the rest of the turn. Every crypto
/// and reveal path of the gate records its effect, so the records are the
/// complete account; the computed keys in `GateState::secrets` are not.
fn used_a_secret(records: &[pb::EffectRecord]) -> bool {
    records
        .iter()
        .any(|r| r.kind.starts_with("crypto.") || r.kind == "secret.reveal")
}

/// A replayed turn's runtime failure. A sealed value that reached the guest
/// unopened is `SUBJECT_ERASED` when the keystore erased its subject (its
/// key is not missing, it is gone on purpose), `KEYSTORE_INCOMPLETE`
/// otherwise.
fn run_error(e: kronik_runtime::RunError, sealer: &kronik_privacy::sealer::Sealer) -> ReplayError {
    match e {
        kronik_runtime::RunError::Prerequisite(code) => ReplayError::Prerequisite(code),
        kronik_runtime::RunError::KeyMissing(subject)
            if sealer
                .erasure_floor(&subject)
                .is_ok_and(|floor| floor.is_some()) =>
        {
            ReplayError::Erased
        }
        e @ kronik_runtime::RunError::KeyMissing(_) => ReplayError::KeyMissing(e),
        e => ReplayError::Host(e.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[test]
fn a_sealed_value_of_an_erased_subject_is_subject_erased_not_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let owner = kronik_privacy::key_source::lock_data(dir.path()).unwrap();
    let (master, _) =
        kronik_privacy::MasterKey::open(&dir.path().join("master.key"), dir.path(), Some([7; 32]))
            .unwrap();
    let sealer = kronik_privacy::sealer::Sealer::new(
        kronik_privacy::keystore::Keystore::open_owned(&owner, &master).unwrap(),
    );
    sealer.set_on(true);
    let mut value = pb::Sealable {
        subject: Some("user:1".into()),
        value: Some(pb::sealable::Value::Plain(b"x".to_vec())),
    };
    sealer
        .seal_value(&mut value, &|b: &mut [u8]| b.fill(3), 1)
        .unwrap();
    sealer.erase("user:1", 2).unwrap();
    let missing = |subject: &str| kronik_runtime::RunError::KeyMissing(subject.into());
    let erased = run_error(missing("user:1"), &sealer);
    assert!(matches!(erased, ReplayError::Erased), "{erased:?}");
    assert!(erased.to_string().contains("SUBJECT_ERASED"), "{erased}");
    assert!(!erased.to_string().contains("user:1"), "{erased}");
    let other = run_error(missing("user:2"), &sealer);
    assert!(matches!(other, ReplayError::KeyMissing(_)), "{other:?}");
    assert!(other.to_string().contains("KEYSTORE_INCOMPLETE"), "{other}");
}

#[cfg(test)]
#[test]
fn every_crypto_or_reveal_record_is_a_secret_use() {
    let record =
        |kind: &str, grounding: pb::Grounding, status: pb::EffectStatus| pb::EffectRecord {
            kind: kind.into(),
            grounding: grounding as i32,
            status: status as i32,
            ..Default::default()
        };
    use pb::EffectStatus as S;
    use pb::Grounding as G;
    for used in [
        // Computed on the host, or served from production's recording.
        record("crypto.hmac-sha256", G::Exact, S::Ok),
        record("crypto.sign-ed25519", G::Exact, S::Ok),
        // Denied: a recorded grant or a missing or linked key, or no grant.
        record("crypto.hmac-sha256", G::Synthetic, S::Denied),
        record("crypto.sign-ed25519", G::Live, S::Denied),
        // A reveal answers a placeholder, matched or not.
        record("secret.reveal", G::Exact, S::Ok),
        record("secret.reveal", G::Synthetic, S::Ok),
    ] {
        let others = [record("http.fetch", G::Exact, S::Ok), used.clone()];
        assert!(used_a_secret(&others), "{used:?}");
    }
    for unused in [
        record("http.fetch", G::Exact, S::Ok),
        record("foreign.http", G::Synthetic, S::Denied),
        record("actor.call", G::Exact, S::Ok),
    ] {
        assert!(!used_a_secret(std::slice::from_ref(&unused)), "{unused:?}");
    }
    assert!(!used_a_secret(&[]));
}

#[derive(Default)]
struct GateState {
    records: Vec<pb::EffectRecord>,
    compensations: Vec<pb::OutboundMessage>,
    /// What the turn's record may still take, charged as in production
    /// (`kronik_sched::record_budget`).
    budget: kronik_sched::record_budget::Budget,
    /// The keys this turn computed with on the host, for scrubbing. Not
    /// every secret use: see [`used_a_secret`].
    secrets: Vec<(String, Vec<u8>)>,
    /// A callee used SQL ([`ForkTurn::sql`]).
    sql: bool,
    /// A callee's values may hold personal data ([`ForkTurn::personal`]).
    personal: bool,
    /// A callee the replay could not verify ([`ForkTurn::erased`]): what it
    /// answered need not be what production's answered.
    unverified_callee: bool,
}

/// The replay effect gate of one fork turn.
struct ReplayGate {
    dispatch: ReplayDispatch,
    runner: Arc<Runner>,
    config: Option<Arc<Config>>,
    actor: ActorRef,
    key: pb::CausalKey,
    time: u64,
    order: Vec<u64>,
    prod: Vec<pb::EffectRecord>,
    call_chain: Vec<ActorRef>,
    state: Mutex<GateState>,
    /// The effect ordinals of this turn whose recorded request was erased
    /// (S-16, ADR 0109): their outcome is served, not re-derived.
    erased_effects: std::collections::BTreeSet<u32>,
    /// What the turn has seen of personal data, for the model simulator
    /// (ADR 0015): its root input's subject, state reads, SQL.
    input_tagged: bool,
    fork_state: Arc<crate::privacy::ForkState>,
    sql: Arc<Mutex<SqlTurn>>,
    /// The turn's recording holds an erased value, or erased data shaped
    /// its input (ADR 0109).
    unverified: bool,
    /// The turn's actor database may differ from production's because of
    /// an erasure; using it makes the turn unverifiable.
    sql_unverified: bool,
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

fn prepared_plain(value: &pb::Sealable) -> Result<&[u8], GateError> {
    match value.value.as_ref() {
        Some(pb::sealable::Value::Plain(bytes)) => Ok(bytes.as_slice()),
        _ => Err(GateError::Prerequisite(ErrorCode::SecretUnavailable)),
    }
}

/// A prepared response may be checked for ambiguity, never rewritten.
pub(crate) fn prepared_outcome_safe(
    outcome: &pb::Outcome,
    matcher: &CompiledScrubber<'_>,
) -> Result<(), GateError> {
    let mut fields = vec![outcome.message.as_bytes()];
    match outcome.output.as_ref() {
        Some(pb::outcome::Output::Reply(message)) => {
            fields.push(message.name.as_bytes());
            fields.push(message.content_type.as_bytes());
            if let Some(body) = &message.body {
                fields.push(prepared_plain(body)?);
            }
        }
        Some(pb::outcome::Output::Http(response)) => {
            for header in &response.headers {
                fields.push(header.name.as_bytes());
                if let Some(value) = &header.value {
                    fields.push(prepared_plain(value)?);
                }
            }
            match response.body.as_ref().and_then(|body| body.value.as_ref()) {
                Some(pb::body::Value::Inline(value)) => fields.push(prepared_plain(value)?),
                Some(pb::body::Value::Blob(_)) => {
                    return Err(GateError::Prerequisite(ErrorCode::Unavailable));
                }
                None => {}
            }
        }
        Some(pb::outcome::Output::Accept(accept)) => {
            for header in &accept.headers {
                fields.push(header.name.as_bytes());
                if let Some(value) = &header.value {
                    fields.push(prepared_plain(value)?);
                }
            }
        }
        None => {}
    }
    kronik_sched::scrub::prepared_fields_safe(None, None, matcher, fields)
        .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))
}

/// A neighbor hit after source-identity disclosure. Decline is not a
/// disclosure: the next simulator may answer. A prerequisite is not a
/// decline: the source answer must not reach the guest or a later external
/// call. Contract fakes and stub rules are synthetic (ADR 0016) and must
/// not be passed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NeighborRecorded {
    pub record: pb::EffectRecord,
    pub outcome: FetchOutcome,
}

/// Decline carries no payload. The recorded arm is boxed so the enum stays
/// small (the source effect is large).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NeighborDisclosure {
    Decline,
    Recorded(Box<NeighborRecorded>),
}

/// Store a neighbor hit as the source effect, or refuse it. The secret-use
/// prefix is the one taken through the source ordinal. Unknown scope is not
/// an empty scope, and a missing body is not an empty inline body.
pub(crate) fn disclose_neighbor(
    hit: &kronik_effects::simulator::NeighborHit<'_>,
    ordinal: u32,
    kind: &str,
    current: Option<&[pb::SecretRef]>,
    matcher: &CompiledScrubber<'_>,
    sealer: &kronik_privacy::sealer::Sealer,
) -> Result<NeighborDisclosure, GateError> {
    if hit.source.kind != kind {
        return Ok(NeighborDisclosure::Decline);
    }
    let request_bytes = match hit
        .source
        .request
        .as_ref()
        .and_then(|value| value.value.as_ref())
    {
        Some(pb::sealable::Value::Plain(bytes)) => bytes.as_slice(),
        _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
    };
    let source_req = pb::HttpEffectRequest::decode(request_bytes)
        .map_err(|_| GateError::Prerequisite(ErrorCode::Unavailable))?;
    if hit.source.status == pb::EffectStatus::Ok as i32 {
        match hit
            .source
            .response
            .as_ref()
            .and_then(|value| value.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(_)) => {}
            // A referenced or unreadable body is not an empty success.
            _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
        }
    }
    let subject = hit
        .source
        .request
        .as_ref()
        .and_then(|value| value.subject.as_deref());
    let verified = match source_req.fingerprint_version {
        0 => {
            let plain_fp = fingerprint(&source_req).map_err(|_| {
                GateError::Host("The legacy neighbor fingerprint is invalid".into())
            })?;
            sealer.fingerprint_matches(subject, &hit.source.fingerprint, &plain_fp)
        }
        2 | 3 => {
            let Some(prefix) = hit.prefix else {
                return Ok(NeighborDisclosure::Decline);
            };
            let target = prepared_target(&source_req)
                .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
            let plain_fp = fingerprint_v2(&source_req, &target)
                .map_err(|_| GateError::Host("The neighbor fingerprint is invalid".into()))?;
            if !sealer.fingerprint_matches(subject, &hit.source.fingerprint, &plain_fp) {
                return Ok(NeighborDisclosure::Decline);
            }
            disclose_prepared_neighbor(&source_req, &target, hit.source, current, prefix, matcher)?;
            true
        }
        _ => return Ok(NeighborDisclosure::Decline),
    };
    if !verified {
        return Ok(NeighborDisclosure::Decline);
    }
    let mut record = hit.source.clone();
    record.ordinal = ordinal;
    record.grounding = pb::Grounding::Synthetic as i32;
    record.simulator = kronik_effects::simulator::label::NEIGHBOR.into();
    let record = if source_req.fingerprint_version == 0 {
        kronik_sched::effects::legacy_http_disclosure(record, &source_req, matcher)?
    } else {
        record
    };
    let outcome = outcome_of_fetch(&record)?;
    Ok(NeighborDisclosure::Recorded(Box::new(NeighborRecorded {
        record,
        outcome,
    })))
}

/// Version-2 neighbor bytes stay unchanged only with a covering source
/// prefix or a no-match proof. `current: None` is unknown, not empty.
fn disclose_prepared_neighbor(
    req: &pb::HttpEffectRequest,
    target: &kronik_effects::http::Target,
    source: &pb::EffectRecord,
    current: Option<&[pb::SecretRef]>,
    prefix: &[pb::SecretRef],
    matcher: &CompiledScrubber<'_>,
) -> Result<(), GateError> {
    let response_bytes = match source
        .response
        .as_ref()
        .and_then(|value| value.value.as_ref())
    {
        Some(pb::sealable::Value::Plain(bytes)) => bytes.as_slice(),
        _ => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
    };
    let response = pb::HttpEffectResponse::decode(response_bytes)
        .map_err(|_| GateError::Prerequisite(ErrorCode::Unavailable))?;
    // Coverage first. A miss still scans the real fields; it does not treat
    // unknown scope as a proved empty set, and it does not replace a
    // referenced body with an empty inline substitute.
    if kronik_sched::scrub::secret_scope_is_subset(current, Some(prefix))
        .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?
    {
        return Ok(());
    }
    if kronik_sched::scrub::http_url_contains(target, &target.host, &|bytes| {
        matcher.is_match(bytes)
    })
    .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?
    {
        return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
    }
    let mut fields = Vec::new();
    if !kronik_sched::scrub::protocol_method(&req.method) {
        fields.push(req.method.as_bytes());
    }
    fields.push(req.body.as_slice());
    for header in &req.headers {
        fields.push(header.name.as_bytes());
        match &header.value {
            Some(pb::http_effect_header::Value::Text(value)) => fields.push(value.as_bytes()),
            Some(pb::http_effect_header::Value::Secret(reference)) => {
                if !reference.template.is_empty() {
                    fields.push(reference.template.as_bytes());
                }
            }
            // A missing header value is not an empty proved-clear field.
            None => return Err(GateError::Prerequisite(ErrorCode::Unavailable)),
        }
    }
    fields.push(response.body.as_slice());
    for header in &response.headers {
        fields.push(header.name.as_bytes());
        fields.push(header.value.as_bytes());
    }
    // Original scope is the source prefix. Unknown current scope does not
    // skip the scan, and is not passed as a proved empty set.
    kronik_sched::scrub::prepared_fields_safe(current, Some(prefix), matcher, fields)
        .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Vec<u8> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.clone(),
        _ => Vec::new(),
    }
}

/// The guest-visible text of a replay without a recording (FailClosed).
pub const NO_RECORDING: &str = "replay: no recording";

/// The error of an unmatched effect of a fork that needs a secret which is
/// linked to an external backend at the fork point, when this process holds
/// no value of it for that link (`SECRET_UNAVAILABLE`).
fn linked_secret_denial(name: &str) -> String {
    format!(
        "SECRET_UNAVAILABLE: {name} is linked to an external secret manager, this node holds \
         no value of it for the fork point's link, and a fork never fetches"
    )
}

/// What an unmatched `crypto.*` of a fork computes with.
enum UnmatchedKey {
    /// The name is linked to an external backend in the configuration of the
    /// fork point, and this process holds no value of it for that link: a
    /// fork never fetches (I7), and the built-in store holds an older value
    /// of the name or none. Nothing is computed.
    Unheld,
    /// The built-in store has no value of the name, or the fork has no store
    /// (a preview: no production key computes for it).
    Missing,
    /// The built-in store's current value of a name that is not linked.
    Value(kronik_privacy::SecretValue),
    /// The value this process holds for the fork point's link of a linked
    /// name. A computation with it is graded synthetic, not exact: it rests
    /// on what this process holds (a later version after a rotation, nothing
    /// after a restart), so a diff grades it the same whether it was held or
    /// not.
    Held(kronik_privacy::SecretValue),
}

/// The built-in store, as an unmatched `crypto.*` of a fork reads it.
trait KeyStore {
    fn current_key(&self, name: &str) -> Option<kronik_privacy::SecretValue>;
}

impl KeyStore for SecretStore {
    fn current_key(&self, name: &str) -> Option<kronik_privacy::SecretValue> {
        self.current(name).ok().flatten()
    }
}

/// The values of linked secrets that this process already holds, as an
/// unmatched `crypto.*` of a fork reads them (m23 §6): never a fetch.
pub trait HeldKeys: Send + Sync {
    /// The value held for `name` under the link of `config` (the fork
    /// point's: its backend, binding, reference and generation), when the
    /// backend is still trusted and the value has not been revoked.
    fn held_key(&self, name: &str, config: &Config) -> Option<kronik_privacy::SecretValue>;
}

impl HeldKeys for kronik_sched::secrets::SecretCache {
    fn held_key(&self, name: &str, config: &Config) -> Option<kronik_privacy::SecretValue> {
        // Read-only: a fork never changes production's stale tracking, its
        // `kronik_secret_stale` gauge or its log.
        self.fork_value(name, config)
    }
}

/// The key for an unmatched `crypto.*` of `name` in a fork whose
/// configuration is `config`. Without a store (a preview), nothing is
/// computed, linked or not. A link at the fork point decides before the
/// store is asked: a linked name is the held value of that link, or none.
fn unmatched_key(
    config: &Config,
    store: Option<&dyn KeyStore>,
    held: Option<&dyn HeldKeys>,
    name: &str,
) -> UnmatchedKey {
    let Some(store) = store else {
        return UnmatchedKey::Missing;
    };
    if config.secret_is_linked(name) {
        return match held.and_then(|held| held.held_key(name, config)) {
            Some(value) => UnmatchedKey::Held(value),
            None => UnmatchedKey::Unheld,
        };
    }
    match store.current_key(name) {
        Some(value) => UnmatchedKey::Value(value),
        None => UnmatchedKey::Missing,
    }
}

fn model_error(error: kronik_core::error::ApiError) -> GateError {
    match error.code {
        ErrorCode::Internal | ErrorCode::StorageCorrupt => GateError::Host(error.message),
        _ => GateError::Prerequisite(error.code),
    }
}

/// Whether a recorded effect with this status may hold a secret reference
/// that never got a version. Production records one only for an effect that
/// did not get its secret: the secret does not exist (`Denied`), the backend
/// could not be had (`Network`), or a re-run ended an effect of an `unsafe`
/// grant as `OutcomeUnknown` without asking. Production's own re-run refuses
/// such a reference on a successful record, and a fork must not replay as
/// exact what production would not.
fn may_lack_its_secret(status: i32) -> bool {
    matches!(
        pb::EffectStatus::try_from(status),
        Ok(pb::EffectStatus::Denied | pb::EffectStatus::Network | pb::EffectStatus::OutcomeUnknown)
    )
}

#[cfg(test)]
#[test]
fn only_an_effect_that_did_not_get_its_secret_may_lack_a_secret_version() {
    use pb::EffectStatus::{Denied, Network, OutcomeUnknown};
    let mut seen = 0;
    for status in 0..32 {
        let Ok(known) = pb::EffectStatus::try_from(status) else {
            // A status this build does not know is not one production recorded
            // for an effect without its secret.
            assert!(!may_lack_its_secret(status), "{status}");
            continue;
        };
        seen += 1;
        assert_eq!(
            may_lack_its_secret(status),
            matches!(known, Denied | Network | OutcomeUnknown),
            "{known:?}"
        );
    }
    assert!(seen >= 12, "{seen} statuses");
}

#[cfg(test)]
#[test]
fn model_failures_keep_host_vs_prerequisite_semantics() {
    for code in [ErrorCode::Internal, ErrorCode::StorageCorrupt] {
        let error = kronik_core::error::ApiError::new(code, "The model response is invalid");
        assert!(matches!(model_error(error), GateError::Host(message)
            if message == "The model response is invalid"));
    }
    let error = kronik_core::error::ApiError::new(
        ErrorCode::Unavailable,
        "The model endpoint is unavailable",
    );
    assert!(matches!(
        model_error(error),
        GateError::Prerequisite(ErrorCode::Unavailable)
    ));
}

impl ReplayGate {
    fn original(&self) -> Result<&AuthLease, GateError> {
        match &self.dispatch {
            ReplayDispatch::Authorized(original) => Ok(original),
            ReplayDispatch::RecordedOnly => Err(GateError::Prerequisite(ErrorCode::Unavailable)),
        }
    }

    fn config(&self) -> &Config {
        self.config.as_deref().unwrap_or(&self.runner.setup.config)
    }

    fn matcher(&self) -> Result<CompiledScrubber<'static>, GateError> {
        self.matcher_with_scope().map(|(matcher, _)| matcher)
    }

    // The replay's scrub plan: matcher plus the references it may mint.
    #[allow(clippy::type_complexity)]
    fn matcher_with_scope(
        &self,
    ) -> Result<(CompiledScrubber<'static>, Option<Arc<[pb::SecretRef]>>), GateError> {
        if let ReplayDispatch::Authorized(original) = &self.dispatch {
            original
                .check()
                .map_err(|error| GateError::Prerequisite(error.code))?;
        }
        let source = self
            .runner
            .setup
            .model
            .as_ref()
            .map(|model| (model.secret_snapshot)())
            .transpose()
            .map_err(|error| GateError::Prerequisite(error.code))?;
        let snapshot = source
            .as_ref()
            .map(crate::simulators::ModelSecretSnapshot::snapshot);
        let state = lock(&self.state);
        let patterns: Vec<_> = snapshot
            .into_iter()
            .flat_map(|snapshot| {
                snapshot
                    .values
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_slice()))
            })
            .chain(
                state
                    .secrets
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_slice())),
            )
            .collect();
        let scope = if state.secrets.is_empty() {
            snapshot.and_then(|snapshot| snapshot.references.clone())
        } else {
            // These older observations have no certified identity in this
            // profile; do not invent an empty complete source scope.
            None
        };
        let matcher =
            CompiledScrubber::new(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES)
                .map(CompiledScrubber::into_owned)
                .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        Ok((matcher, scope))
    }

    fn prepare_http_record(
        &self,
        record: &mut pb::EffectRecord,
        matcher: &CompiledScrubber<'_>,
    ) -> Result<FetchOutcome, GateError> {
        if record.status == pb::EffectStatus::Ok as i32 {
            let payload = record
                .response
                .as_ref()
                .ok_or_else(|| GateError::Host("The HTTP response is missing".into()))?;
            let subject = payload.subject.clone();
            let Some(pb::sealable::Value::Plain(bytes)) = payload.value.as_ref() else {
                return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
            };
            let response = pb::HttpEffectResponse::decode(bytes.as_slice())
                .map_err(|_| GateError::Host("The HTTP response is invalid".into()))?;
            return kronik_sched::effects::prepare_inline_fetch_response(
                record,
                &subject,
                response,
                matcher,
                usize::try_from(self.config().limits(&self.actor.kind).effect_response_bytes)
                    .unwrap_or(usize::MAX)
                    .min(kronik_log::MAX_RECORD as usize),
            );
        }
        kronik_sched::scrub::text(&mut record.error, matcher, kronik_log::MAX_RECORD as usize)
            .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        outcome_of_fetch(record)
    }

    fn prod_at(&self, ordinal: u32) -> Option<&pb::EffectRecord> {
        self.prod.iter().find(|e| e.ordinal == ordinal)
    }

    /// Records an effect of the turn. As in production, a record that does
    /// not fit in what is left of the turn's record traps the turn with
    /// `TURN_TOO_LARGE` (`kronik_sched::record_budget`).
    fn push(&self, mut rec: pb::EffectRecord) -> Result<(), GateError> {
        let cost = kronik_sched::record_budget::effect_cost(&mut rec);
        let mut state = lock(&self.state);
        state.budget.take(cost, rec.ordinal, &rec.kind)?;
        state.records.push(rec);
        Ok(())
    }

    /// Production's response cap for a new fetch whose recorded request is
    /// `encoded`: what is left of the turn's record after the request and a
    /// result without a body, at most the kind's `effect_response_bytes`.
    fn response_cap(&self, encoded: Option<&pb::Sealable>, effect_response_bytes: u64) -> u64 {
        let len = match encoded.and_then(|s| s.value.as_ref()) {
            Some(pb::sealable::Value::Plain(bytes)) => bytes.len(),
            _ => 0,
        };
        let room = lock(&self.state).budget.clone();
        kronik_sched::record_budget::response_room(
            &room,
            kronik_sched::record_budget::fetch_need(len),
            effect_response_bytes,
        )
    }

    /// The error of a response over `cap` ([`ReplayGate::response_cap`]),
    /// worded as production words it.
    fn too_large_error(cap: u64, effect_response_bytes: u64) -> String {
        if cap < effect_response_bytes {
            format!("the response exceeds {cap} bytes, what is left of the turn's record")
        } else {
            format!("the response exceeds {cap} bytes")
        }
    }

    /// As in production: a fetch result that does not fit in what is left of
    /// the turn's record is too large for this turn, and the guest never
    /// sees it. Every answer a fork makes up goes through it too (a stub
    /// rule's, a contract fake's, a neighbor's, the model's): a large
    /// synthetic answer is `too-large` for the guest, as a live one is, and
    /// does not trap the turn when it is recorded.
    fn fit_fetch(
        &self,
        rec: &mut pb::EffectRecord,
        out: Result<FetchOutcome, GateError>,
    ) -> Result<FetchOutcome, GateError> {
        if matches!(out, Ok(FetchOutcome::HostRedactionFailure) | Err(_)) {
            return out;
        }
        let room = lock(&self.state).budget.clone();
        if room.fits(kronik_sched::record_budget::effect_cost(rec)) {
            return out;
        }
        rec.response = None;
        rec.status = pb::EffectStatus::TooLarge as i32;
        rec.error = "the response does not fit in what is left of the turn's record".into();
        Ok(FetchOutcome::TooLarge)
    }

    /// Production's admission of a new effect: its `need` bytes must fit in
    /// what is left of the turn's record, or the turn traps with
    /// `TURN_TOO_LARGE` before the effect happens.
    fn admit(&self, ordinal: u32, kind: &str, need: usize) -> Result<(), GateError> {
        let state = lock(&self.state);
        if state.budget.fits(need) {
            Ok(())
        } else {
            Err(state.budget.refuse(ordinal, kind))
        }
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
            simulator: kronik_effects::simulator::label::FAIL_CLOSED.into(),
            ..Default::default()
        }
    }

    /// Whether the turn has seen personal data or a secret: the model
    /// simulator then declines (docs/design/m12-simulators.md §3.3).
    fn tainted(&self, req: &FetchRequest) -> bool {
        req.subject.is_some() || self.saw_personal()
    }

    /// Whether the turn has met erased data so far ([`ForkTurn::erased`]):
    /// a callee it calls now gets a message that data may have shaped.
    fn unverified_so_far(&self) -> bool {
        self.unverified
            || self.fork_state.erased()
            || (self.sql_unverified && lock(&self.sql).used())
            || lock(&self.state).unverified_callee
    }

    /// Whether the turn has seen personal data or a secret so far.
    fn saw_personal(&self) -> bool {
        lock(&self.sql).used() || self.saw_personal_with(&lock(&self.state))
    }

    /// [`ReplayGate::saw_personal`] with the gate's state at hand (SQL use
    /// aside): its input (tagged, or sent by a turn that saw personal data),
    /// tagged state it read, a callee that saw personal data or SQL rows,
    /// any use of a secret ([`used_a_secret`]), a tagged effect value.
    fn saw_personal_with(&self, state: &GateState) -> bool {
        self.input_tagged
            || self.fork_state.saw_subject()
            || state.personal
            || state.sql
            || !state.secrets.is_empty()
            || used_a_secret(&state.records)
            || state.records.iter().any(|r| {
                r.request.as_ref().is_some_and(|x| x.subject.is_some())
                    || r.response.as_ref().is_some_and(|x| x.subject.is_some())
            })
    }

    async fn fetch(&self, ordinal: u32, req: FetchRequest) -> Result<FetchOutcome, GateError> {
        if let Some(record) = self
            .prod_at(ordinal)
            .filter(|record| {
                matches!(record.kind.as_str(), "http.fetch" | "foreign.http")
                    && record.status == pb::EffectStatus::HostRedactionFailure as i32
            })
            .cloned()
        {
            self.push(record)?;
            return Err(GateError::HostRedactionFailure);
        }
        // The recorded request was erased: its plaintext is gone, so no
        // request the guest can build is comparable with it. The recording is
        // the only outcome there is - serve it, and mark the turn unverifiable
        // (S-16, ADR 0109). Only a fetch-like recording is served this way; an
        // effect of another kind at this ordinal is a real divergence.
        if self.erased_effects.contains(&ordinal)
            && let Some(mut record) = self.prod_at(ordinal).cloned()
            && matches!(record.kind.as_str(), "http.fetch" | "foreign.http")
        {
            record.grounding = pb::Grounding::Exact as i32;
            let out = outcome_of_fetch(&record)?;
            self.push(record)?;
            return Ok(out);
        }
        let (matcher, prepared_scope) = self.matcher_with_scope()?;
        let (t, raw_host) = match parse_request_url(&req.url) {
            Ok(t) => t,
            Err(_) => {
                // The record production writes for an unparseable URL: the
                // rejected target is withheld and the code is the error.
                let error = ErrorCode::BadRequest.as_str().to_owned();
                self.push(self.denied(
                    ordinal,
                    "http.fetch",
                    "http:[withheld]".into(),
                    error.clone(),
                ))?;
                return Ok(FetchOutcome::Denied(error));
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
            // Production withholds a rejected target's host (`http:[withheld]`);
            // the denial's audited error still names the capability.
            let withheld = if foreign {
                "foreign:[withheld]"
            } else {
                "http:[withheld]"
            };
            self.push(self.denied(ordinal, kind, withheld.into(), e.clone()))?;
            return Ok(FetchOutcome::Denied(e));
        }
        if foreign && self.config().foreign(&t.host).is_none() {
            // Production's words exactly: the error is part of the effect's
            // cost in the turn's record, so another text could make the
            // budget decide otherwise.
            let e = ErrorCode::ForeignNotFound.as_str().to_owned();
            self.push(self.denied(ordinal, kind, "foreign:[withheld]".into(), e.clone()))?;
            return Ok(FetchOutcome::Denied(e));
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
                        self.push(self.denied(ordinal, kind, scap, e.clone()))?;
                        return Ok(FetchOutcome::Denied(e));
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
                    // An unresolved reference is how production records an effect
                    // that never got its secret (not found, or unavailable): the
                    // recorded error is replayed below, with the fingerprint of
                    // that very request. Any other record with one is damaged,
                    // as is a reference that claims a version and does not name
                    // one.
                    let never_got_it = prod.as_ref().is_some_and(|p| may_lack_its_secret(p.status));
                    if let Some(reference) = &recorded
                        && !(reference.is_unresolved() && never_got_it)
                        && let Err(error) = reference.resolved_version()
                    {
                        let error = error.to_string();
                        self.push(self.denied(ordinal, kind, scap, error.clone()))?;
                        return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
                    }
                    pb::http_effect_header::Value::Secret(recorded.unwrap_or(pb::SecretRef {
                        name: secret.clone(),
                        template: template.clone(),
                        version: 0,
                        version_hash: Vec::new(),
                        wide_version: 0,
                    }))
                }
            };
            headers.push(pb::HttpEffectHeader {
                name: name.clone(),
                value: Some(v),
            });
        }
        let mut request = pb::HttpEffectRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers,
            body: req.body.clone(),
            fingerprint_version: 2,
            ..Default::default()
        };
        // Keyed for a subject's request, as production records it.
        let sealer = &self.runner.setup.privacy.sealer;
        if let (Some(record), Some(source)) = (&prod, &prod_req) {
            match source.fingerprint_version {
                0 => {
                    let candidate = {
                        let state = lock(&self.state);
                        kronik_sched::scrub::legacy_verification_fingerprint(
                            &mut request,
                            source,
                            &state.secrets,
                        )
                        .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?
                    };
                    let source_fp = fingerprint(source).map_err(GateError::Host)?;
                    let subject = record
                        .request
                        .as_ref()
                        .and_then(|value| value.subject.as_deref());
                    if !sealer.fingerprint_matches(subject, &record.fingerprint, &source_fp) {
                        return Err(GateError::Host(
                            "The legacy HTTP source fingerprint is invalid".into(),
                        ));
                    }
                    if candidate != source_fp {
                        return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
                    }
                    let record = kronik_sched::effects::legacy_http_disclosure(
                        record.clone(),
                        source,
                        &matcher,
                    )?;
                    let outcome = outcome_of_fetch(&record);
                    self.push(record)?;
                    return outcome;
                }
                2 | 3 => {}
                _ => {
                    return Err(GateError::Host(
                        "The HTTP fingerprint policy is invalid".into(),
                    ));
                }
            }
        }
        let recorded_target = kronik_sched::scrub::http_request(
            &mut request,
            &t,
            raw_host,
            &matcher,
            kronik_log::MAX_RECORD as usize,
        )
        .map_err(|_| GateError::Prerequisite(ErrorCode::SecretUnavailable))?;
        // The actor type's fingerprint rules for this turn, recorded in the
        // fork's request as production records its own (ADR 0134).
        self.config()
            .fingerprint_rules(&self.actor.kind)
            .apply(&mut request)
            .map_err(GateError::Host)?;
        let plain_fp = fingerprint_v2(&request, &recorded_target).map_err(GateError::Host)?;
        let fp = sealer.effect_fingerprint(req.subject.as_deref(), plain_fp.clone());
        // A recording is compared under its own rules, never the fork's: the
        // fork's request as that recording's rules fingerprint it.
        let matching_fp = match &prod_req {
            Some(source) if prepared_version(source.fingerprint_version) => {
                fingerprint_v2(&under_rules_of(&request, source), &recorded_target)
                    .map_err(GateError::Host)?
            }
            _ => plain_fp.clone(),
        };
        let original_cap = cap;
        let cap = format!(
            "{}:{}",
            if foreign { "foreign" } else { "http" },
            recorded_target.host
        );
        let encoded = tagged(&req.subject, request.encode_to_vec());
        // Production admits a new fetch with room for its request and a
        // result without a body; the same refusal keeps a replay identical.
        let need = kronik_sched::record_budget::fetch_need(request.encoded_len());
        self.admit(ordinal, kind, need)?;
        // A copy of the foreign actor answers in continuous replay (M14).
        if t.scheme == "foreign"
            && !self.runner.isolated
            && let Some(copies) = self.runner.setup.copies.clone()
            && let Some(copy) = copies.copies.get(&t.host).cloned()
        {
            return self
                .fetch_copy(
                    ordinal,
                    cap,
                    (fp, matching_fp),
                    encoded,
                    req,
                    prod,
                    copy,
                    copies.env,
                    &matcher,
                )
                .await;
        }
        if let (Some(p), Some(pr)) = (prod, prod_req) {
            if sealer.fingerprint_matches(req.subject.as_deref(), &p.fingerprint, &matching_fp) {
                let mut rec = p;
                rec.grounding = pb::Grounding::Exact as i32;
                let out = outcome_of_fetch(&rec);
                self.push(rec)?;
                return out;
            }
            if target_of(&pr).is_some() && target_of(&pr) == target_of(&request) {
                let mut rec = p;
                rec.grounding = pb::Grounding::Approximate as i32;
                rec.fingerprint = fp;
                rec.request = encoded;
                let out = outcome_of_fetch(&rec);
                self.push(rec)?;
                return out;
            }
        }
        let setup = &self.runner.setup;
        let sims = setup.simulators.target(&original_cap);
        // Synthetic: a stub rule of the request, then of the target.
        let rule = crate::stubs::find(&setup.stubs, &req.method, &req.url)
            .or_else(|| sims.and_then(|s| crate::stubs::find(&s.stubs, &req.method, &req.url)));
        if let Some(rule) = rule {
            let mut rec = self.synthetic(ordinal, kind, cap, fp, encoded);
            // ADR 0016: a stub answer is synthetic. It is not a neighbor hit
            // and does not carry a source effect's secret-use prefix.
            rec.simulator = kronik_effects::simulator::label::STUB.into();
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
                let response = pb::HttpEffectResponse {
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
                };
                let out = kronik_sched::effects::prepare_inline_fetch_response(
                    &mut rec,
                    &req.subject,
                    response,
                    &matcher,
                    usize::try_from(self.config().limits(&self.actor.kind).effect_response_bytes)
                        .unwrap_or(usize::MAX)
                        .min(kronik_log::MAX_RECORD as usize),
                );
                // As for a live fetch: an answer that does not fit in what is
                // left of the turn's record is too large for this turn.
                let out = self.fit_fetch(&mut rec, out);
                self.push(rec)?;
                return out;
            }
            let out = self.prepare_http_record(&mut rec, &matcher);
            let out = self.fit_fetch(&mut rec, out);
            self.push(rec)?;
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
            return self
                .fetch_live(ordinal, cap, fp, encoded, req, env, &matcher)
                .await;
        }
        if let Some(s) = sims {
            use kronik_effects::simulator::{EffectRequest, EffectSimulator, ReplayContext};
            let ereq = EffectRequest {
                ordinal,
                kind: kind.into(),
                target: cap.clone(),
                fingerprint: fp.clone(),
                http: Some(request.clone()),
            };
            let ctx = ReplayContext { recorded: &[] };
            let neighbor = s
                .neighbor
                .then(|| setup.simulators.neighbor(&setup.index, &cap));
            // Contract fakes stay synthetic (ADR 0016). They are not neighbor
            // hits and do not take a source secret-use prefix.
            if let Some(answer) = s
                .contract
                .as_ref()
                .and_then(|contract| contract.respond(&ereq, &ctx))
            {
                let mut rec = answer.record;
                rec.request = encoded;
                let out = self.prepare_http_record(&mut rec, &matcher);
                let out = self.fit_fetch(&mut rec, out);
                self.push(rec)?;
                return out;
            }
            if let Some(neighbor) = &neighbor
                && let Some(hit) = neighbor.find(&request)
            {
                match disclose_neighbor(
                    &hit,
                    ordinal,
                    kind,
                    prepared_scope.as_deref(),
                    &matcher,
                    self.runner.setup.privacy.sealer.as_ref(),
                )? {
                    NeighborDisclosure::Decline => {}
                    NeighborDisclosure::Recorded(recorded) => {
                        let NeighborRecorded {
                            mut record,
                            outcome,
                        } = *recorded;
                        let out = self.fit_fetch(&mut record, Ok(outcome));
                        self.push(record)?;
                        return out;
                    }
                }
            }
            // A preview reaches the outside world only through an allowlisted
            // secret-less GET (ADR 0025). The model is a POST, so it is not
            // asked even if a client was attached.
            if !setup.preview
                && s.model
                && let Some(model) = &setup.model
            {
                let cached = model.has_cached_answer(&cap, &fp).map_err(model_error)?;
                if !cached {
                    self.original()?
                        .check()
                        .map_err(|error| GateError::Prerequisite(error.code))?;
                    if self.tainted(&req) {
                        self.push(self.synthetic(ordinal, kind, cap, fp, encoded))?;
                        return Ok(FetchOutcome::Denied(NO_RECORDING.into()));
                    }
                }
                let max = model.config.max_examples;
                let examples = |matcher: &CompiledScrubber<'_>, scope: Option<&[pb::SecretRef]>| {
                    crate::simulators::model_examples(
                        &crate::simulators::Simulators::model_sources(&setup.index, &cap),
                        max,
                        matcher,
                        scope,
                    )
                };
                let answer = match &self.dispatch {
                    ReplayDispatch::RecordedOnly => model
                        .cached_answer(&cap, &fp)
                        .map_err(model_error)?
                        .ok_or(GateError::Prerequisite(ErrorCode::Unavailable))?,
                    ReplayDispatch::Authorized(original) => model
                        .answer(
                            &cap,
                            &fp,
                            &request,
                            &recorded_target,
                            prepared_scope.as_deref(),
                            examples,
                            original,
                        )
                        .await
                        .map_err(model_error)?,
                };
                if let Some(a) = answer {
                    let rec = pb::EffectRecord {
                        ordinal,
                        kind: kind.into(),
                        target: cap,
                        fingerprint: fp,
                        request: encoded,
                        status: pb::EffectStatus::Ok as i32,
                        grounding: pb::Grounding::Synthetic as i32,
                        simulator: kronik_effects::simulator::label::MODEL.into(),
                        response: plain(
                            pb::HttpEffectResponse {
                                status: u32::from(a.status),
                                headers: a
                                    .headers
                                    .into_iter()
                                    .map(|(name, value)| pb::HeaderPair { name, value })
                                    .collect(),
                                body: a.body.into_bytes(),
                            }
                            .encode_to_vec(),
                        ),
                        ..Default::default()
                    };
                    let mut rec = rec;
                    let out = outcome_of_fetch(&rec);
                    let out = self.fit_fetch(&mut rec, out);
                    self.push(rec)?;
                    return out;
                }
            }
        }
        self.push(self.synthetic(ordinal, kind, cap, fp, encoded))?;
        Ok(FetchOutcome::Denied(NO_RECORDING.into()))
    }

    /// A call to a fork's copy of a foreign actor (M14): sent to the copy
    /// in fork order, so its state follows the fork. Production's recorded
    /// answer stays when the request is the same (`exact`); otherwise the
    /// copy's answer is the result (`forked`, ADR 0020).
    #[allow(clippy::too_many_arguments)]
    async fn fetch_copy(
        &self,
        ordinal: u32,
        cap: String,
        (fp, matching_fp): (Vec<u8>, Vec<u8>),
        encoded: Option<pb::Sealable>,
        req: FetchRequest,
        prod: Option<pb::EffectRecord>,
        copy: Arc<dyn kronik_effects::foreign::ForeignCopy>,
        env: Env,
        matcher: &CompiledScrubber<'_>,
    ) -> Result<FetchOutcome, GateError> {
        self.original()?
            .check()
            .map_err(|error| GateError::Prerequisite(error.code))?;
        let limits = self.config().limits(&self.actor.kind);
        let cap_bytes = self.response_cap(encoded.as_ref(), limits.effect_response_bytes);
        let sealer = &self.runner.setup.privacy.sealer;
        let exact = prod.as_ref().is_some_and(|p| {
            sealer.fingerprint_matches(req.subject.as_deref(), &p.fingerprint, &matching_fp)
        });
        let headers = req
            .headers
            .iter()
            .filter_map(|(n, v)| match v {
                FetchHeader::Text(t) => Some((n.clone(), t.clone())),
                FetchHeader::Secret { .. } => None,
            })
            .collect();
        let call = copy.http(kronik_core::env::HttpRequest {
            method: req.method,
            url: req.url,
            headers,
            body: req.body.into(),
            max_response_bytes: cap_bytes,
        });
        let answer = env.timeout(limits.effect_timeout, call).await;
        if let Some(p) = prod.filter(|_| exact) {
            let mut rec = p;
            rec.grounding = pb::Grounding::Exact as i32;
            let out = outcome_of_fetch(&rec);
            self.push(rec)?;
            return out;
        }
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: "foreign.http".into(),
            target: cap,
            fingerprint: fp,
            request: encoded,
            grounding: pb::Grounding::Forked as i32,
            ..Default::default()
        };
        rec.status = match answer {
            Err(_) => {
                rec.error = format!(
                    "no response within {} ms",
                    limits.effect_timeout.as_millis()
                );
                pb::EffectStatus::Timeout
            }
            Ok(Err(kronik_core::env::NetError::TooLarge)) => {
                rec.error = Self::too_large_error(cap_bytes, limits.effect_response_bytes);
                pb::EffectStatus::TooLarge
            }
            Ok(Err(kronik_core::env::NetError::Connect(e) | kronik_core::env::NetError::Io(e))) => {
                rec.error = e;
                pb::EffectStatus::Network
            }
            Ok(Ok(resp)) => {
                let response = pb::HttpEffectResponse {
                    status: u32::from(resp.status),
                    headers: resp
                        .headers
                        .into_iter()
                        .map(|(name, value)| pb::HeaderPair { name, value })
                        .collect(),
                    body: resp.body.to_vec(),
                };
                let out = kronik_sched::effects::prepare_inline_fetch_response(
                    &mut rec,
                    &req.subject,
                    response,
                    matcher,
                    usize::try_from(limits.effect_response_bytes)
                        .unwrap_or(usize::MAX)
                        .min(kronik_log::MAX_RECORD as usize),
                );
                let out = self.fit_fetch(&mut rec, out);
                self.push(rec)?;
                return out;
            }
        } as i32;
        let out = self.prepare_http_record(&mut rec, matcher);
        let out = self.fit_fetch(&mut rec, out);
        self.push(rec)?;
        out
    }

    /// A live GET from a fork (`[fork] live_allowlist`), grounding `live`.
    // One live fetch's admission: ordinal, capability, body and scrubber.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_live(
        &self,
        ordinal: u32,
        cap: String,
        fp: Vec<u8>,
        encoded: Option<pb::Sealable>,
        req: FetchRequest,
        env: Env,
        matcher: &CompiledScrubber<'_>,
    ) -> Result<FetchOutcome, GateError> {
        let limits = self.config().limits(&self.actor.kind);
        let cap_bytes = self.response_cap(encoded.as_ref(), limits.effect_response_bytes);
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
        let call = env.net.http_authorized(
            kronik_core::env::HttpRequest {
                method: req.method,
                url: req.url,
                headers,
                body: req.body.into(),
                max_response_bytes: cap_bytes,
            },
            self.original()?.clone(),
        );
        rec.status = match env.timeout(limits.effect_timeout, call).await {
            Err(_) => {
                rec.error = format!(
                    "no response within {} ms",
                    limits.effect_timeout.as_millis()
                );
                pb::EffectStatus::Timeout
            }
            Ok(Err(kronik_core::env::NetError::TooLarge)) => {
                rec.error = Self::too_large_error(cap_bytes, limits.effect_response_bytes);
                pb::EffectStatus::TooLarge
            }
            Ok(Err(kronik_core::env::NetError::Connect(e) | kronik_core::env::NetError::Io(e))) => {
                rec.error = e;
                pb::EffectStatus::Network
            }
            Ok(Ok(resp)) => {
                let response = pb::HttpEffectResponse {
                    status: u32::from(resp.status),
                    headers: resp
                        .headers
                        .into_iter()
                        .map(|(name, value)| pb::HeaderPair { name, value })
                        .collect(),
                    body: resp.body.to_vec(),
                };
                let out = kronik_sched::effects::prepare_inline_fetch_response(
                    &mut rec,
                    &req.subject,
                    response,
                    matcher,
                    usize::try_from(limits.effect_response_bytes)
                        .unwrap_or(usize::MAX)
                        .min(kronik_log::MAX_RECORD as usize),
                );
                let out = self.fit_fetch(&mut rec, out);
                self.push(rec)?;
                return out;
            }
        } as i32;
        let out = self.prepare_http_record(&mut rec, matcher);
        let out = self.fit_fetch(&mut rec, out);
        self.push(rec)?;
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
        let matcher = self.matcher()?;
        let mut request = pb::CallEffectRequest {
            to: Some(to.to_pb()),
            msg: Some(msg),
            compensate,
            message_id: message_id.clone(),
            fingerprint_version: 2,
        };
        match kronik_sched::scrub::call_request(
            &mut request,
            &matcher,
            kronik_log::MAX_RECORD as usize,
        ) {
            Ok(()) => {}
            Err(
                kronik_sched::scrub::CallRequestError::UnsafeMessage
                | kronik_sched::scrub::CallRequestError::UnsafeCompensation,
            ) => {
                let error = ErrorCode::PolicyDenied.as_str().to_owned();
                self.push(self.denied(
                    ordinal,
                    "actor.call",
                    format!("actor:{to}"),
                    error.clone(),
                ))?;
                return Ok(CallOutcome::Failed(error));
            }
            Err(kronik_sched::scrub::CallRequestError::Redaction(_)) => {
                return Err(GateError::Prerequisite(ErrorCode::SecretUnavailable));
            }
        }
        let encoded = request.encode_to_vec();
        let compensate = request.compensate.take();
        // Production admits a new call with room for its request, its
        // compensation's copy and a result without a body.
        let need =
            kronik_sched::record_budget::call_need(encoded.len(), compensate.as_ref(), &to.to_pb());
        self.admit(ordinal, "actor.call", need)?;
        let msg = request
            .msg
            .take()
            .ok_or_else(|| GateError::Host("The call message is missing".into()))?;
        // The request holds the message: it is the message's subject's data.
        let msg_subject = msg.body.as_ref().and_then(|b| b.subject.clone());
        let plain = blake3::hash(&encoded).as_bytes().to_vec();
        let sealer = &self.runner.setup.privacy.sealer;
        // The same request that timed out in production: the fork's own call
        // never times out, so it serves the recorded outcome instead.
        let recorded_timeout = self
            .prod_at(ordinal)
            .filter(|p| {
                p.timed_out_call()
                    && sealer.fingerprint_matches(msg_subject.as_deref(), &p.fingerprint, &plain)
            })
            .cloned();
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: "actor.call".into(),
            target: format!("actor:{to}"),
            fingerprint: sealer.effect_fingerprint(msg_subject.as_deref(), plain),
            request: tagged(&msg_subject, encoded),
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        };
        let (outcome, turn_id, callee_lsn) = if to == self.actor || self.call_chain.contains(&to) {
            (CallOutcome::Reentrant, String::new(), None)
        } else if !self.runner.setup.kinds.contains_key(&to.kind) {
            (CallOutcome::NotFound, String::new(), None)
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
                    message_id: message_id.clone(),
                    sent_logical_time_ms: self.time,
                    call_chain: chain.iter().map(ActorRef::to_pb).collect(),
                    ..Default::default()
                })),
            };
            if let Some(recorded) = recorded_timeout {
                let callee = Pending {
                    actor: to.clone(),
                    input,
                    key,
                    time: self.time,
                    subject,
                    sql: false,
                    personal: self.saw_personal(),
                    unverified: self.unverified_so_far(),
                };
                return self.served_timeout(recorded, &message_id, callee, order, compensate);
            }
            let mut turn = self
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
                        personal: self.saw_personal(),
                        unverified: self.unverified_so_far(),
                    },
                    order,
                    self.dispatch.clone(),
                )
                .await
                .map_err(|e| GateError::Host(e.to_string()))?;
            let o =
                turn.record.outcome.take().ok_or_else(|| {
                    GateError::Host("The committed callee outcome is missing".into())
                })?;
            {
                let mut state = lock(&self.state);
                state.sql |= turn.sql;
                state.personal |= turn.personal;
                state.unverified_callee |= turn.erased;
            }
            (map_call_outcome(o)?, turn.id, Some(turn.lsn))
        };
        // The callee's turn ran in the fork, so its source is the fork's: its
        // position in the fork's store, in the fork's namespace, as
        // production names the callee's turn in its log. With a source, a
        // reply over what is left of the turn's record is withheld and
        // recorded as HOST_REDACTION_FAILURE with the callee's status, as in
        // production, instead of failing the whole replay as a missing
        // prerequisite.
        rec.callee_source = callee_lsn.map(|lsn| pb::ActorSource {
            shard: None,
            lsn,
            branch: self.runner.setup.fork.clone(),
        });
        // A reply larger than what is left of the turn's record is withheld,
        // as in production.
        let room = lock(&self.state).budget.clone();
        let reply_bytes = kronik_sched::record_budget::response_room(
            &room,
            need,
            self.config()
                .limits(&self.actor.kind)
                .effect_response_bytes
                .min(u64::from(kronik_log::MAX_RECORD)),
        );
        let out = kronik_sched::effects::prepare_call_outcome(
            &mut rec,
            outcome,
            turn_id,
            &matcher,
            usize::try_from(reply_bytes).unwrap_or(usize::MAX),
            None,
            None,
        );
        if out
            .as_ref()
            .is_err_and(|error| !matches!(error, GateError::HostRedactionFailure))
        {
            return out;
        }
        if rec.successful_call()
            && let Some(c) = compensate
        {
            let key = causal::compensation(&self.key, &self.actor, ordinal, &to);
            let mut compensation = pb::OutboundMessage {
                to: Some(to.to_pb()),
                msg: Some(c),
                ordinal,
                message_id: causal::causal_id(&key),
            };
            let cost = kronik_sched::record_budget::message_cost(&mut compensation);
            let mut state = lock(&self.state);
            state.budget.charge(cost);
            state.compensations.push(compensation);
        }
        self.push(rec)?;
        out
    }

    /// A call that timed out in production, met with the same request: the
    /// caller gets the recorded timeout, as a recorded effect is served
    /// (M3), since the fork's own call never times out. The callee's turn
    /// still runs as a consequence where production ran it (`order`), and
    /// only if production ran it: a queued call lost to a restart never ran.
    /// The compensation is recorded as production records it, and goes out
    /// once the callee's turn committed in the fork (#30, `Runner`).
    fn served_timeout(
        &self,
        mut recorded: pb::EffectRecord,
        message_id: &str,
        callee: Pending,
        order: Vec<u64>,
        compensate: Option<pb::Message>,
    ) -> Result<CallOutcome, GateError> {
        let ordinal = recorded.ordinal;
        let to = callee.actor.clone();
        if let Some((_, ran)) = self.runner.setup.index.turn(&callee.key) {
            // A call lost to a restart: the next start closed it as a turn
            // that never ran (no seed; m2-effects §5), and so does the fork.
            let outcome = ran.outcome.clone().unwrap_or_default();
            if ran.random_seed.is_empty() && outcome.kind != pb::OutcomeKind::Committed as i32 {
                lock(&self.runner.unrun).insert(
                    causal::encode(&callee.key),
                    (outcome.error_code, outcome.message),
                );
            }
            let compensation_key = causal::compensation(&self.key, &self.actor, ordinal, &to);
            // One lock at a time: the taint helpers lock the state too.
            let sql = lock(&self.state).sql;
            let personal = self.saw_personal();
            let unverified = self.unverified_so_far();
            let timed_out = TimedOutCall {
                order: self
                    .runner
                    .child_order(&self.order, &compensation_key, ordinal),
                sql,
                personal,
                unverified,
            };
            lock(&self.runner.timed_out).insert(message_id.to_owned(), timed_out);
            self.runner.push(order, callee);
        }
        if let Some(c) = compensate {
            let key = causal::compensation(&self.key, &self.actor, ordinal, &to);
            let mut compensation = pb::OutboundMessage {
                to: Some(to.to_pb()),
                msg: Some(c),
                ordinal,
                message_id: causal::causal_id(&key),
            };
            let cost = kronik_sched::record_budget::message_cost(&mut compensation);
            let mut state = lock(&self.state);
            state.budget.charge(cost);
            state.compensations.push(compensation);
        }
        recorded.grounding = pb::Grounding::Exact as i32;
        self.push(recorded)?;
        Ok(CallOutcome::Timeout)
    }

    fn crypto(
        &self,
        ordinal: u32,
        algorithm: CryptoAlgorithm,
        secret: String,
        data: Vec<u8>,
    ) -> Result<CryptoOutcome, GateError> {
        let (kind, alg) = match algorithm {
            CryptoAlgorithm::HmacSha256 => ("crypto.hmac-sha256", "hmac-sha256"),
            CryptoAlgorithm::SignEd25519 => ("crypto.sign-ed25519", "sign-ed25519"),
        };
        let cap = format!("secret:{secret}");
        let Some(grant) = self.config().grant(&self.actor.kind, &cap) else {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, kind, cap, e.clone()))?;
            return Ok(CryptoOutcome::Denied(e));
        };
        // Production admits a new crypto effect with room for its result.
        self.admit(ordinal, kind, kronik_sched::record_budget::SMALL_NEED)?;
        // Copy the mode: the grant reference does not outlive the match below.
        let in_forks = grant.in_forks;
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
            self.push(rec)?;
            return Ok(out);
        }
        // Unmatched. A recorded grant does not compute. Compute signs on the
        // host with the built-in store's value, or with the value held for
        // the fork point's link of a linked name; the key never leaves it.
        let store = self.runner.setup.secrets.as_deref();
        let held = self.runner.setup.held_secrets.as_deref();
        let (v, grounding) = match unmatched_key(
            self.config(),
            store.map(|s| s as &dyn KeyStore),
            held,
            &secret,
        ) {
            UnmatchedKey::Value(v) => (v, pb::Grounding::Exact),
            UnmatchedKey::Held(v) => (v, pb::Grounding::Synthetic),
            UnmatchedKey::Missing => {
                self.push(self.synthetic(ordinal, kind, cap, fp, None))?;
                return Ok(CryptoOutcome::Denied(NO_RECORDING.into()));
            }
            // Denied in the fork, and marked unverifiable like the other
            // effects it cannot answer: with the cause as the guest's error
            // when the grant would have computed.
            UnmatchedKey::Unheld => {
                let mut record = self.synthetic(ordinal, kind, cap, fp, None);
                if in_forks != kronik_effects::InForks::Recorded {
                    record.error = linked_secret_denial(&secret);
                }
                let denied = CryptoOutcome::Denied(record.error.clone());
                self.push(record)?;
                return Ok(denied);
            }
        };
        // A recorded grant returns a matching recording or denies the call.
        // It does not compute, so the production key is not used.
        if in_forks == kronik_effects::InForks::Recorded {
            drop(v);
            self.push(self.synthetic(ordinal, kind, cap, fp, None))?;
            return Ok(CryptoOutcome::Denied(NO_RECORDING.into()));
        }
        tracing::info!(
            algorithm = alg,
            name = %secret,
            kind = %self.actor.kind,
            "fork computed a crypto effect; the key stayed on the host"
        );
        kronik_metrics::inc(
            "kronik_fork_crypto_computations_total",
            &[("algorithm", alg)],
        );
        let result = match algorithm {
            CryptoAlgorithm::HmacSha256 => Ok(kronik_effects::crypto::hmac_sha256(&v.value, &data)),
            CryptoAlgorithm::SignEd25519 => kronik_effects::crypto::sign_ed25519(&v.value, &data),
        };
        lock(&self.state).secrets.push((secret.clone(), v.value));
        let mut rec = pb::EffectRecord {
            ordinal,
            kind: kind.into(),
            target: cap,
            fingerprint: fp,
            grounding: grounding as i32,
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
        self.push(rec)?;
        Ok(out)
    }

    /// `connections.send-now` in a fork (M24 §7.3): there is no hub, and
    /// nothing is written. A kind without the grant is denied, as in
    /// production. A recording of the same ordinal, kind and connection
    /// answers: exact for the identical frame, approximate for another one.
    /// Otherwise the connection model answers: `ok` on a live connection of
    /// the turn's actor that is not closing in the fork's state, `closed`
    /// otherwise, also for an id without a live connection (synthetic,
    /// simulator `connection`).
    fn send_now(&self, ordinal: u32, req: SendNowRequest) -> Result<SendNowOutcome, GateError> {
        use kronik_proto::connection::{
            SEND_NOW_KIND as KIND, send_now_fingerprint, send_now_request,
        };
        let target = format!("connection:{}", req.connection);
        let sealer = &self.runner.setup.privacy.sealer;
        let plain_fp = send_now_fingerprint(&req.connection, &req.frame);
        let fp = sealer.effect_fingerprint(req.subject.as_deref(), plain_fp.clone());
        let record = |status: pb::EffectStatus, grounding: pb::Grounding| pb::EffectRecord {
            ordinal,
            kind: KIND.into(),
            target: target.clone(),
            fingerprint: fp.clone(),
            status: status as i32,
            request: tagged(
                &req.subject,
                send_now_request(
                    &req.connection,
                    if matches!(
                        status,
                        pb::EffectStatus::Ok | pb::EffectStatus::OutcomeUnknown
                    ) {
                        req.seq
                    } else {
                        0
                    },
                    &req.frame,
                )
                .encode_to_vec(),
            ),
            delivery: "unsafe".into(),
            grounding: grounding as i32,
            ..Default::default()
        };
        let cap = kronik_effects::Capability::SEND_NOW;
        if self.config().grant(&self.actor.kind, cap).is_none() {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, KIND, target.clone(), e.clone()))?;
            return Ok(SendNowOutcome::Denied(e));
        }
        // Production admits a new send-now with room for its request.
        let need = send_now_request(&req.connection, req.seq, &req.frame).encoded_len();
        self.admit(ordinal, KIND, kronik_sched::record_budget::fetch_need(need))?;
        if let Some(p) = self
            .prod_at(ordinal)
            .filter(|p| p.kind == KIND && p.target == target)
            .cloned()
        {
            let outcome = outcome_of_send_now(&p)?;
            let status = pb::EffectStatus::try_from(p.status).unwrap_or(pb::EffectStatus::Closed);
            let exact =
                sealer.fingerprint_matches(req.subject.as_deref(), &p.fingerprint, &plain_fp);
            let mut rec = record(
                status,
                if exact {
                    pb::Grounding::Exact
                } else {
                    pb::Grounding::Approximate
                },
            );
            rec.error = p.error;
            self.push(rec)?;
            return Ok(outcome);
        }
        let (status, outcome) = if !req.live || req.closing {
            (pb::EffectStatus::Closed, SendNowOutcome::Closed)
        } else {
            (pb::EffectStatus::Ok, SendNowOutcome::Ok)
        };
        let mut rec = record(status, pb::Grounding::Synthetic);
        rec.simulator = kronik_effects::simulator::label::CONNECTION.into();
        self.push(rec)?;
        Ok(outcome)
    }

    fn reveal(&self, ordinal: u32, name: String) -> Result<Result<String, String>, GateError> {
        let kind = "secret.reveal";
        let cap = format!("secret-reveal:{name}");
        if self.config().grant(&self.actor.kind, &cap).is_none() {
            let e = format!("CAPABILITY_NOT_GRANTED: {cap}");
            self.push(self.denied(ordinal, kind, cap, e.clone()))?;
            return Ok(Err(e));
        }
        // Production admits a new reveal with room for its result.
        self.admit(ordinal, kind, kronik_sched::record_budget::SMALL_NEED)?;
        let fp = blake3::hash(format!("reveal\0{name}").as_bytes())
            .as_bytes()
            .to_vec();
        // An effect production recorded as failed (no such secret, or the
        // backend could not be reached) fails the same way here.
        if let Some(recorded) = self.prod_at(ordinal).filter(|p| {
            p.kind == kind && p.fingerprint == fp && p.status != pb::EffectStatus::Ok as i32
        }) {
            let mut rec = recorded.clone();
            rec.grounding = pb::Grounding::Exact as i32;
            let error = rec.error.clone();
            self.push(rec)?;
            return Ok(Err(error));
        }
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
            // Every synthetic answer is labeled (M12 criterion 1).
            simulator: if matched {
                String::new()
            } else {
                kronik_effects::simulator::label::PLACEHOLDER.into()
            },
            ..Default::default()
        })?;
        Ok(Ok(format!("[secret:{name}]")))
    }
}

impl EffectGate for GateHandle {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { g.fetch(ordinal, req).await })
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
        Box::pin(async move { g.crypto(ordinal, algorithm, secret, data) })
    }

    fn reveal(
        &self,
        ordinal: u32,
        name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { g.reveal(ordinal, name) })
    }

    fn send_now(
        &self,
        ordinal: u32,
        req: SendNowRequest,
    ) -> BoxFuture<'static, Result<SendNowOutcome, GateError>> {
        let g = self.0.clone();
        Box::pin(async move { g.send_now(ordinal, req) })
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
        personal: false,
        unverified: false,
    }
}

/// Whether a fork turn received the input production's counterpart did. A
/// timer input names the turn that scheduled it, the fork's own turn id in a
/// fork, so that name is not compared.
fn same_input(prod: Option<&pb::Input>, fork: &pb::Input) -> bool {
    let plain = |i: &pb::Input| {
        let mut i = i.clone();
        if let Some(pb::input::Kind::Timer(t)) = i.kind.as_mut() {
            t.scheduled_by.clear();
        }
        i
    };
    prod.is_some_and(|p| plain(p) == plain(fork))
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
                before,
            );
            runner.push(vec![r.lsn], root_pending(r));
            let res = runner.clone().drain(setup.dispatch.clone()).await;
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
    /// The setup the next turns run under (the model cache to save).
    pub fn setup(&self) -> &ReplaySetup {
        &self.setup
    }

    /// State at the fork point plus the fork's own leading records (its
    /// `BranchCreated` and `Deployment`, at `fork_lsn + 1..`), with the
    /// timers and messages pending there queued.
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
            setup.index.fork_lsn,
        );
        runner.queue_pending(setup.index.fork_lsn)?;
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
            // Production's erasures in the window, at their places: the fork
            // store deletes what production's did there (ADR 0109), so a
            // later turn reads what production's read and the final states
            // agree.
            for (lsn, subject, key_version) in self
                .setup
                .index
                .erasures
                .iter()
                .filter(|(l, _, _)| *l > self.replayed_to && *l <= self.setup.index.to_lsn)
            {
                lock(&self.runner.queue)
                    .insert(vec![*lsn], Queued::Erasure(subject.clone(), *key_version));
            }
            self.runner
                .clone()
                .drain(self.setup.dispatch.clone())
                .await?;
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
            self.runner.base,
        );
        *lock(&runner.turns) = turns;
        *lock(&runner.queue) = queue;
        *lock(&runner.timers) = timers;
        *lock(&runner.taint) = std::mem::take(&mut *lock(&self.runner.taint));
        *lock(&runner.ran) = std::mem::take(&mut *lock(&self.runner.ran));
        runner.timer_seq.store(
            self.runner.timer_seq.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        // What the last round left pending: timers not due within it, and
        // a rebase's consequences production has run since.
        runner.queue_pending(self.replayed_to)?;
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
        original: AuthLease,
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
        self.send_input(actor, input, key, time, subject, original)
            .await
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
        original: AuthLease,
    ) -> Result<ForkTurn, ReplayError> {
        let dispatch = ReplayDispatch::Authorized(original);
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
                    personal: false,
                    unverified: false,
                },
                order,
                dispatch.clone(),
            )
            .await?;
        self.runner.clone().drain(dispatch).await?;
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

#[cfg(test)]
mod linked_key_tests {
    use super::*;
    use kronik_proto::Record;
    use std::sync::Mutex;

    fn link(name: &str, backend: &str, epoch: u64) -> Record {
        Record::SecretLink(pb::SecretLink {
            name: name.into(),
            backend: backend.into(),
            r#ref: if backend.is_empty() {
                ""
            } else {
                "secret/a#key"
            }
            .into(),
            epoch,
            generation: epoch,
            ..Default::default()
        })
    }

    /// A built-in store with older values than any backend serves, which
    /// remembers what it was asked.
    struct Keys(Mutex<Vec<String>>);

    impl KeyStore for Keys {
        fn current_key(&self, name: &str) -> Option<kronik_privacy::SecretValue> {
            self.0.lock().unwrap().push(name.to_owned());
            matches!(name, "stripe" | "plain").then(|| kronik_privacy::SecretValue {
                meta: kronik_privacy::SecretMeta {
                    name: name.into(),
                    version: 1,
                    version_hash: vec![0; 16],
                    created_wall_ms: 0,
                },
                value: b"older-built-in-value".to_vec(),
            })
        }
    }

    /// What this process holds for a link: `stripe`'s value, for the link
    /// of generation 1 only, and it remembers what it was asked.
    struct Held(Mutex<Vec<String>>);

    impl HeldKeys for Held {
        fn held_key(&self, name: &str, config: &Config) -> Option<kronik_privacy::SecretValue> {
            self.0.lock().unwrap().push(name.to_owned());
            (name == "stripe" && config.secret_link(name).is_some_and(|l| l.generation == 1)).then(
                || kronik_privacy::SecretValue {
                    meta: kronik_privacy::SecretMeta {
                        name: name.into(),
                        version: 7,
                        version_hash: vec![1; 16],
                        created_wall_ms: 0,
                    },
                    value: b"held-backend-value".to_vec(),
                },
            )
        }
    }

    /// The link in force in the configuration of the fork decides, before the
    /// built-in store is asked: a linked name is the value held for that
    /// link, or none (never the store's older value, and never a fetch); any
    /// other name is the store's; the record that an unlink leaves makes the
    /// name the store's again.
    #[test]
    fn a_linked_name_is_the_held_value_of_its_link_and_never_the_stores() {
        let keys = Keys(Mutex::new(Vec::new()));
        let held = Held(Mutex::new(Vec::new()));
        let store = Some(&keys as &dyn KeyStore);
        let mut config = Config::default();
        assert!(matches!(
            unmatched_key(&config, store, Some(&held), "stripe"),
            UnmatchedKey::Value(v) if v.value == b"older-built-in-value"
        ));
        config.apply(&link("stripe", "bao", 1));
        keys.0.lock().unwrap().clear();
        assert!(matches!(
            unmatched_key(&config, store, Some(&held), "stripe"),
            UnmatchedKey::Held(v) if v.value == b"held-backend-value"
        ));
        // Nothing held (here: no cache, or another generation): denied.
        assert!(matches!(
            unmatched_key(&config, store, None, "stripe"),
            UnmatchedKey::Unheld
        ));
        let mut relinked = config.clone();
        relinked.apply(&link("stripe", "bao", 3));
        assert!(matches!(
            unmatched_key(&relinked, store, Some(&held), "stripe"),
            UnmatchedKey::Unheld
        ));
        assert!(keys.0.lock().unwrap().is_empty(), "the store was asked");
        assert!(matches!(
            unmatched_key(&config, store, Some(&held), "plain"),
            UnmatchedKey::Value(v) if v.value == b"older-built-in-value"
        ));
        assert!(matches!(
            unmatched_key(&config, store, Some(&held), "missing"),
            UnmatchedKey::Missing
        ));
        config.apply(&link("stripe", "", 2));
        assert!(matches!(
            unmatched_key(&config, store, Some(&held), "stripe"),
            UnmatchedKey::Value(v) if v.value == b"older-built-in-value"
        ));
    }

    /// A fork without a store (a preview) computes nothing, as before: also
    /// for a linked name whose value is held.
    #[test]
    fn a_fork_without_a_store_computes_nothing_linked_or_not() {
        let held = Held(Mutex::new(Vec::new()));
        let mut config = Config::default();
        config.apply(&link("stripe", "bao", 1));
        for name in ["stripe", "plain"] {
            assert!(matches!(
                unmatched_key(&config, None, Some(&held), name),
                UnmatchedKey::Missing
            ));
        }
        assert!(held.0.lock().unwrap().is_empty());
    }

    /// What the guest of the fork reads when it is refused: the code and the
    /// name.
    #[test]
    fn the_refusal_names_the_code_and_the_secret() {
        let text = linked_secret_denial("stripe");
        assert!(
            text.starts_with("SECRET_UNAVAILABLE: stripe is linked"),
            "{text}"
        );
    }
}
