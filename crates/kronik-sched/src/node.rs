//! The node: one branch of one daemon.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use kronik_core::causal;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, CodeHash, Lsn, TurnId, random_id};
use kronik_core::time::LogicalClock;
use kronik_effects::rate::RateLimiter;
use kronik_effects::{Capability, Config, ConfigHistory, Delivery, KindLimits, Rate};
use kronik_log::{Committed, Log, LogConfig, LogError, LogReader};
use kronik_privacy::SecretStore;
use kronik_privacy::sealer::Sealer;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{CodeError, CodeStore, LogEvent, Program, TurnLimits, TurnRequest};
use kronik_store::sql::TurnOpts;
use kronik_store::{Store, StoreError};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

use crate::effects::{Gate, TurnFx, TurnSpec};
use crate::host::{KvView, SqlHandle, SqlTurn};
use crate::timers::Wheel;
use crate::{NodeConfig, TurnResult};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, e.to_string())
}

fn store_err(e: StoreError) -> ApiError {
    match e {
        StoreError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
        other => internal(other),
    }
}

/// What the node needs to start.
pub struct NodeParts {
    pub env: Env,
    pub config: NodeConfig,
    pub log: LogConfig,
    pub store: Arc<Store>,
    pub code: Arc<CodeStore>,
    /// The secret store; without it, secret headers, crypto and reveal are
    /// denied with SECRET_NOT_FOUND.
    pub secrets: Option<Arc<SecretStore>>,
    /// Seals values in privacy mode and holds the keystore
    /// (docs/design/m8-privacy.md); `None` runs without a keystore: nothing
    /// is sealed and `privacy status` has no keystore counts.
    pub sealer: Option<Arc<Sealer>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Code(#[from] CodeError),
    #[error("STORAGE_CORRUPT: {0}")]
    Corrupt(String),
    #[error("ENGINE_VERSION_MISMATCH: {0}")]
    EngineMismatch(String),
    /// The master key is missing over existing stores, or is another key
    /// than theirs (`MASTER_KEY_MISSING`, `MASTER_KEY_MISMATCH`).
    #[error(transparent)]
    Key(kronik_privacy::PrivacyError),
    /// An erasure's record could not be committed at start
    /// ([`Node::recover_erasures`]).
    #[error("erasure recovery: {0}")]
    Erasure(String),
}

/// A route served by a deployed kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub kind: String,
    pub method: String,
    pub pattern: String,
}

/// The outcome of `deploy`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeployResult {
    pub dry_run: bool,
    /// The kind already runs this exact code; nothing was written.
    pub unchanged: bool,
    pub epoch: u64,
    pub lsn: Lsn,
    pub code_hash: CodeHash,
    pub manifest: pb::Manifest,
    pub warnings: Vec<String>,
}

/// A code switch written as one `Deployment` (promote, rollback).
#[derive(Debug, Clone)]
pub struct CodeSwitch {
    pub kinds: Vec<pb::KindVersion>,
    /// The code each kind must run on main right now, checked under the
    /// deploy lock (a proposal's skipped components and its changed kinds'
    /// code when the proposal was made); an empty hash means the kind must not exist. Else
    /// `PROPOSAL_STALE`.
    pub pinned: Vec<pb::KindVersion>,
    pub cause: pb::DeploymentCause,
    pub verified_through_lsn: Lsn,
    pub unverified_inputs: u64,
    pub proposal_id: String,
    pub rollback_of_epoch: u64,
}

struct Kind {
    version: pb::KindVersion,
    program: Arc<Program>,
    hash: CodeHash,
}

type Reply = oneshot::Sender<Result<TurnResult, ApiError>>;

struct Job {
    input: pb::Input,
    causal_key: pb::CausalKey,
    parent_time: u64,
    subject: Option<String>,
    reply: Option<Reply>,
    rerun: Option<Rerun>,
}

/// A `TurnBegin` without a turn record, re-run at startup.
struct Rerun {
    begin: pb::TurnBegin,
    recorded: Vec<pb::EffectRecord>,
}

#[derive(Default)]
struct Slot {
    queue: VecDeque<Job>,
    running: bool,
}

/// A turn result several callers can wait for (ingress dedup).
#[derive(Default)]
pub struct Waiter {
    result: Mutex<Option<Result<TurnResult, ApiError>>>,
    notify: Notify,
}

impl Waiter {
    fn complete(&self, r: Result<TurnResult, ApiError>) {
        *lock(&self.result) = Some(r);
        self.notify.notify_waiters();
    }

    pub async fn wait(&self) -> Result<TurnResult, ApiError> {
        loop {
            let notified = self.notify.notified();
            if let Some(r) = lock(&self.result).clone() {
                return r;
            }
            notified.await;
        }
    }
}

/// How an ingress request with an `Idempotency-Key` was admitted.
pub enum Ingress {
    /// A new root input; wait for its turn.
    Started(Arc<Waiter>),
    /// The same request is running; wait for it.
    Joined(Arc<Waiter>),
    /// The request committed before; this is its saved result.
    Done(Box<TurnResult>),
}

struct Inflight {
    request_hash: Vec<u8>,
    waiter: Arc<Waiter>,
}

/// Set once when the log writer or the applier fails; the daemon must exit
/// and recover on restart.
#[derive(Default)]
struct Fatal {
    msg: Mutex<Option<String>>,
    notify: Notify,
}

impl Fatal {
    fn set(&self, msg: String) {
        tracing::error!(error = %msg, "fatal storage failure; the daemon must restart");
        lock(&self.msg).get_or_insert(msg);
        self.notify.notify_waiters();
    }

    fn get(&self) -> Option<String> {
        lock(&self.msg).clone()
    }

    async fn wait(&self) -> String {
        loop {
            let notified = self.notify.notified();
            if let Some(m) = self.get() {
                return m;
            }
            notified.await;
        }
    }
}

/// Simulation hooks: observations the DST invariants need.
#[derive(Default)]
pub struct Probe {
    /// Turns executed (each run of `handle`, including migrations).
    pub turns_run: AtomicU64,
}

pub struct Node {
    pub(crate) env: Env,
    pub(crate) cfg: NodeConfig,
    log: Log,
    reader: LogReader,
    store: Arc<Store>,
    code: Arc<CodeStore>,
    clock: LogicalClock,
    kinds: Mutex<BTreeMap<String, Arc<Kind>>>,
    epoch: AtomicU64,
    actors: Mutex<HashMap<ActorRef, Slot>>,
    permits: Semaphore,
    inflight: Mutex<HashMap<(ActorRef, String), Inflight>>,
    resending: Mutex<HashSet<Lsn>>,
    pub(crate) deploy_lock: Arc<tokio::sync::Mutex<()>>,
    /// Code switches (deploy, promote, rollback) hold it for writing from
    /// their `Deployment`'s commit until every kind and the epoch are
    /// swapped; a turn reads its code and epoch under it for reading, so a
    /// turn either starts before the switch with the old code of every kind
    /// or after its LSN with the new code of every kind (ADR 0013).
    switch_gate: Arc<tokio::sync::RwLock<()>>,
    pub(crate) snapshot_lock: tokio::sync::Mutex<()>,
    group_commit_window: Duration,
    fatal: Arc<Fatal>,
    /// Free bytes on the log's file system, refreshed every second while
    /// `[log] disk_reserve` is set (`u64::MAX` until the first reading).
    disk_free: AtomicU64,
    config: Mutex<ConfigHistory>,
    pub(crate) secrets: Option<Arc<SecretStore>>,
    /// Follows the latest `PrivacyMode` record (set at start and by
    /// `set_privacy_mode`).
    pub(crate) sealer: Arc<Sealer>,
    /// The sandboxes behind `foreign://` (docs/design/m7-foreign.md).
    pub(crate) foreign: Option<Arc<dyn kronik_effects::foreign::ForeignHost>>,
    pub(crate) rates: RateLimiter,
    wheel: Mutex<Wheel>,
    wheel_notify: Arc<Notify>,
    pub probe: Probe,
    me: Weak<Node>,
}

/// Segments in flight: decoding a segment (and preparing its catch-up rows)
/// costs more than applying it, so every core decodes.
fn decode_ahead() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(2, 6)
}

/// One segment, ready to apply.
enum Decoded {
    /// A bulk replay's rows of a segment of simple turns, built where the
    /// segment was decoded, dropping each record right away: a small, warm
    /// heap and no records freed on the apply thread.
    Rows(Box<kronik_store::CatchupRows>),
    Records(Vec<Committed>),
}

/// Applies `(applied, upto]`. A gap of `bulk_replay_min` records or more
/// drops scattered indexes (rebuilding them costs more than maintaining
/// them below it), applies `startup_apply_batch` records per transaction
/// (startup only needs atomicity: the log is the truth), and decodes the
/// next segments while one applies.
async fn replay_unapplied(
    env: &Env,
    reader: &LogReader,
    store: &Store,
    applied: Lsn,
    upto: Lsn,
    config: &NodeConfig,
) -> Result<(), StartError> {
    let bulk = upto.saturating_sub(applied) >= config.bulk_replay_min;
    if bulk {
        store.begin_bulk_replay()?;
    }
    let batch_cap = if bulk {
        config.startup_apply_batch
    } else {
        config.apply_batch
    };
    let result = replay_segments(env, reader, store, applied + 1, upto, bulk, batch_cap).await;
    match result {
        // Journaling was off: the file may hold part of a failed batch. Its
        // marker stays, so the next start rebuilds it.
        Err(e) if bulk => {
            if let Err(abort) = store.abort_bulk_replay() {
                tracing::warn!(error = %abort, "ending the failed bulk replay");
            }
            Err(e)
        }
        Err(e) => Err(e),
        Ok(()) if bulk => Ok(store.end_bulk_replay()?),
        Ok(()) => Ok(()),
    }
}

async fn replay_segments(
    env: &Env,
    reader: &LogReader,
    store: &Store,
    from: Lsn,
    upto: Lsn,
    bulk: bool,
    batch_cap: usize,
) -> Result<(), StartError> {
    let starts = reader.starts().await?;
    let mut segs = Vec::new();
    for (i, &start) in starts.iter().enumerate() {
        if starts.get(i + 1).is_some_and(|n| *n <= from) {
            continue;
        }
        if start > upto {
            break;
        }
        segs.push((start, i + 1 == starts.len()));
    }
    // `state.db` skips what it has; `from` can be lower for an actor
    // database that is behind.
    let applied = store.applied.get();
    let branch = reader.branch().to_owned();
    let width = decode_ahead();
    let mut inflight = VecDeque::new();
    let mut next = 0usize;
    let spawn = |idx: usize| {
        let (start, allow_tail) = segs[idx];
        let reader = reader.clone();
        let branch = branch.clone();
        let env_b = env.clone();
        env.spawn("startup-decode", async move {
            let image = reader.read_image(start).await?;
            env_b
                .blocking(
                    "startup-decode",
                    move || -> Result<(Lsn, Decoded), StartError> {
                        let decode = |image: &[u8]| {
                            kronik_log::decode_segment_image(
                                image, &branch, start, from, upto, allow_tail,
                            )
                        };
                        if !bulk {
                            let segment = decode(&image)?;
                            return Ok((segment.next_lsn, Decoded::Records(segment.records)));
                        }
                        // Each record is dropped as soon as it is added: the
                        // heap stays small and warm.
                        let mut rows = Some(kronik_store::CatchupRows::new(applied));
                        let next_lsn = kronik_log::scan_segment_image(
                            &image,
                            &branch,
                            start,
                            from,
                            upto,
                            allow_tail,
                            |c| {
                                if let Some(r) = &mut rows
                                    && !r.push(&c)?
                                {
                                    rows = None;
                                }
                                Ok::<_, StartError>(())
                            },
                        )?;
                        match rows {
                            Some(rows) => Ok((next_lsn, Decoded::Rows(Box::new(rows)))),
                            // Not all simple turns: the records themselves.
                            None => {
                                let segment = decode(&image)?;
                                Ok((segment.next_lsn, Decoded::Records(segment.records)))
                            }
                        }
                    },
                )
                .await
                .unwrap_or_else(|| Err(LogError::Stopped("segment decode dropped".into()).into()))
        })
    };
    while inflight.len() < width && next < segs.len() {
        inflight.push_back(spawn(next));
        next += 1;
    }
    let mut expected: Option<Lsn> = None;
    let mut done = 0usize;
    while let Some(handle) = inflight.pop_front() {
        if next < segs.len() {
            inflight.push_back(spawn(next));
            next += 1;
        }
        let (start, _) = segs[done];
        done += 1;
        let (next_lsn, decoded) = handle
            .await
            .ok_or_else(|| StartError::Log(LogError::Stopped("segment decode dropped".into())))??;
        if let Some(exp) = expected
            && exp != start
        {
            return Err(StartError::Corrupt(format!(
                "segment {start} starts at lsn {start}, expected {exp}"
            )));
        }
        expected = Some(next_lsn);
        match decoded {
            Decoded::Rows(rows) => store.apply_catchup(*rows)?,
            Decoded::Records(records) => {
                for batch in records.chunks(batch_cap) {
                    store.apply(batch)?;
                }
            }
        }
    }
    Ok(())
}

impl Node {
    /// Opens the log (truncating a torn tail), applies every durable record
    /// the store has not applied, loads the deployed code and re-queues
    /// undelivered messages.
    pub async fn start(parts: NodeParts) -> Result<Arc<Node>, StartError> {
        let NodeParts {
            env,
            config,
            log: log_cfg,
            store,
            code,
            secrets,
            sealer,
        } = parts;
        let sealer = sealer.unwrap_or_else(|| Arc::new(Sealer::plain()));
        // The store opens sealed SQL changesets while it replays the log
        // (docs/design/m8-privacy.md §4).
        store.set_sealer(sealer.clone());
        let (committed_tx, committed_rx) = mpsc::unbounded_channel();
        let (fatal_tx, fatal_rx) = oneshot::channel();
        let log_dir = log_cfg.dir.clone();
        let space_dir = log_dir.clone();
        let group_commit_window = log_cfg.group_commit_window;
        let (log, opened) = Log::open(&env, log_cfg, committed_tx, fatal_tx).await?;
        if opened.truncated_bytes > 0 {
            tracing::warn!(
                bytes = opened.truncated_bytes,
                "truncated a torn tail of the active log segment"
            );
        }
        let reader = LogReader::new(env.clone(), log_dir, config.branch.clone());
        let applied = store.applied.get();
        let last = opened.next_lsn - 1;
        if applied > last {
            return Err(StartError::Corrupt(format!(
                "state.db has applied lsn {applied}, but the log ends at {last}"
            )));
        }
        let from = store.replay_from()?;
        if from < last && from + 1 < opened.first_lsn {
            return Err(StartError::Corrupt(format!(
                "state is at lsn {from}, but the log starts at {} (compacted); install a \
                 snapshot that reaches it or restore one",
                opened.first_lsn
            )));
        }
        if from < last {
            tracing::info!(from = from + 1, to = last, "replaying the log");
            replay_unapplied(&env, &reader, &store, from, last, &config).await?;
        }
        if store.applied.get() != last {
            return Err(StartError::Corrupt(format!(
                "replay ended at lsn {}, the log ends at {last}",
                store.applied.get()
            )));
        }
        // Data written by another engine needs a passing `kronik upgrade
        // check` first (docs/design/m6-storage.md §7).
        let (recorded, epoch_now) = {
            let db = store.db();
            (db.engine_version()?, db.config_epoch()?)
        };
        let upgrade = match &config.storage {
            Some(s) => match crate::upgrade::gate(
                &s.data_dir,
                recorded.as_deref(),
                kronik_runtime::ENGINE_VERSION,
                epoch_now,
                env.clock.wall_ms(),
            ) {
                crate::upgrade::Gate::Same => None,
                crate::upgrade::Gate::Upgrade(u) => Some(u),
                crate::upgrade::Gate::Refuse(m) => return Err(StartError::EngineMismatch(m)),
            },
            None => None,
        };

        let (hwm, epoch, kind_rows, mailbox, config_records, open_turns, timers) = {
            let db = store.db();
            (
                db.time_hwm()?,
                db.config_epoch()?,
                db.kinds()?,
                db.mailbox()?,
                db.config_records()?,
                db.open_turns()?,
                db.timers(None)?,
            )
        };
        let mut history = ConfigHistory::default().with_sql_default(config.sql_bytes_per_actor);
        for r in config_records {
            history.push(r);
        }
        let mut reruns = Vec::new();
        for t in open_turns {
            let c = reader.read_at(t.pos).await?;
            let Record::TurnBegin(begin) = c.record else {
                return Err(StartError::Corrupt(format!(
                    "open turn {} does not point at a TurnBegin",
                    t.execution_id
                )));
            };
            let recorded = store.db().open_effects(&t.execution_id)?;
            reruns.push((t.actor, begin, recorded));
        }
        let mut kinds = BTreeMap::new();
        for row in kind_rows {
            let hash = CodeHash::from_slice(&row.version.code_hash)
                .ok_or_else(|| StartError::Corrupt("kind with a bad code hash".into()))?;
            let program = code.get(&hash)?;
            kinds.insert(
                row.version.kind.clone(),
                Arc::new(Kind {
                    version: row.version,
                    program,
                    hash,
                }),
            );
        }

        // The first reading before any work is admitted; then every second.
        let disk_free = if config.disk_reserve > 0 {
            env.fs
                .available(space_dir.clone())
                .await
                .unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        let fatal = Arc::new(Fatal::default());
        let node = Arc::new_cyclic(|me| Node {
            permits: Semaphore::new(config.concurrency.max(1)),
            clock: LogicalClock::new(hwm),
            env: env.clone(),
            log,
            reader,
            store: store.clone(),
            code,
            kinds: Mutex::new(kinds),
            epoch: AtomicU64::new(epoch),
            actors: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            resending: Mutex::new(HashSet::new()),
            deploy_lock: Arc::new(tokio::sync::Mutex::new(())),
            switch_gate: Arc::new(tokio::sync::RwLock::new(())),
            snapshot_lock: tokio::sync::Mutex::new(()),
            group_commit_window,
            fatal: fatal.clone(),
            disk_free: AtomicU64::new(disk_free),
            config: Mutex::new(history),
            secrets,
            sealer: sealer.clone(),
            rates: RateLimiter::starting_full(env.clock.monotonic()),
            wheel: Mutex::new(Wheel::default()),
            wheel_notify: Arc::new(Notify::new()),
            probe: Probe::default(),
            me: me.clone(),
            foreign: config.foreign.0.clone(),
            cfg: config,
        });
        node.sealer
            .set_on(node.privacy_mode().0 == pb::PrivacyState::On);
        if let Some(storage) = &node.cfg.storage {
            crate::reseal::publish_keystore_retention(
                &storage.data_dir,
                node.cfg.keystore_backup_retention.as_millis() as u64,
            );
        }
        let f = fatal.clone();
        env.spawn("log-fatal", async move {
            if let Ok(msg) = fatal_rx.await {
                f.set(msg);
            }
        });
        env.spawn(
            "applier",
            applier(store, committed_rx, node.cfg.apply_batch, fatal),
        );
        if let Some(u) = upgrade {
            tracing::info!(
                from = %u.from_engine_version,
                to = %u.to_engine_version,
                checked_through_lsn = u.checked_through_lsn,
                "engine upgrade"
            );
            node.commit(Record::EngineUpgrade(u)).await.map_err(|e| {
                StartError::Corrupt(format!("recording the engine upgrade: {}", e.message))
            })?;
        }
        // A subject whose keys were erased by a run that stopped before the
        // Erasure record (docs/design/m8-privacy.md §6.1).
        node.recover_erasures()
            .await
            .map_err(|e| StartError::Erasure(e.message))?;
        // Foreign actors run before open turns are re-run: a re-run may redo
        // a foreign call (docs/design/m7-foreign.md §5).
        node.reconcile_foreign().await;
        // Open turns first: each is the delivery of its input, so its mailbox
        // entry is skipped and its ingress key joins the re-run.
        let mut rerun_messages = HashSet::new();
        let rerun_count = reruns.len();
        for (actor, begin, recorded) in reruns {
            let input = begin.input.clone().unwrap_or_default();
            let mut reply = None;
            let mut subject = None;
            match &input.kind {
                Some(pb::input::Kind::Message(m)) => {
                    rerun_messages.insert(m.message_id.clone());
                    subject = body_subject(m.msg.as_ref());
                }
                Some(pb::input::Kind::Http(h)) if !h.idempotency_key.is_empty() => {
                    let waiter = Arc::new(Waiter::default());
                    let entry = (actor.clone(), h.idempotency_key.clone());
                    lock(&node.inflight).insert(
                        entry.clone(),
                        Inflight {
                            request_hash: h.request_hash.clone(),
                            waiter: waiter.clone(),
                        },
                    );
                    let (tx, rx) = oneshot::channel();
                    reply = Some(tx);
                    node.complete_later(rx, waiter, Some(entry));
                }
                _ => {}
            }
            tracing::info!(actor = %actor, execution_id = %begin.execution_id, "re-running an unfinished turn");
            node.enqueue(
                actor,
                Job {
                    input,
                    causal_key: begin.causal_key.clone().unwrap_or_default(),
                    parent_time: 0,
                    subject,
                    reply,
                    rerun: Some(Rerun { begin, recorded }),
                },
            );
        }
        let pending = mailbox.len();
        for row in mailbox {
            if rerun_messages.contains(&row.message_id) {
                continue;
            }
            let (parent_time, subject, causal_key) = match &row.input.kind {
                Some(pb::input::Kind::Message(m)) => (
                    m.sent_logical_time_ms,
                    body_subject(m.msg.as_ref()),
                    row.causal_key.clone(),
                ),
                _ => (0, None, row.causal_key.clone()),
            };
            node.enqueue(
                row.to,
                Job {
                    input: row.input,
                    causal_key,
                    parent_time,
                    subject,
                    reply: None,
                    rerun: None,
                },
            );
        }
        {
            let mut w = lock(&node.wheel);
            for t in &timers {
                w.add(t.actor.clone(), t.timer_id, t.due_ms);
            }
        }
        let weak = Arc::downgrade(&node);
        env.spawn("timers", timer_loop(weak));
        if node.cfg.disk_reserve > 0 {
            env.spawn(
                "disk-space",
                disk_space_loop(Arc::downgrade(&node), space_dir),
            );
        }
        if let Some(s) = &node.cfg.storage {
            env.spawn(
                "snapshots",
                crate::snapshots::snapshot_loop(Arc::downgrade(&node), s.snapshot_interval),
            );
        }
        tracing::info!(
            applied_lsn = node.store.applied.get(),
            pending_messages = pending,
            reruns = rerun_count,
            timers = timers.len(),
            "node started"
        );
        Ok(node)
    }

    pub fn branch(&self) -> &str {
        &self.cfg.branch
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The log's group-commit window (fork logs use the same).
    pub fn group_commit_window(&self) -> Duration {
        self.group_commit_window
    }

    /// The code store (replay loads the code of past deployments).
    pub fn code(&self) -> &Arc<CodeStore> {
        &self.code
    }

    /// The secret store, when a master key is configured.
    pub fn secrets(&self) -> Option<&Arc<SecretStore>> {
        self.secrets.as_ref()
    }

    pub fn reader(&self) -> &LogReader {
        &self.reader
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    pub fn applied_lsn(&self) -> Lsn {
        self.store.applied.get()
    }

    /// `[sql] max_size_per_actor` for this node (1 GiB unless `serve` set it).
    pub fn sql_bytes_per_actor(&self) -> u64 {
        self.cfg.sql_bytes_per_actor
    }

    /// The fatal storage failure, if one happened.
    pub fn fatal(&self) -> Option<String> {
        self.fatal.get()
    }

    /// Resolves when a fatal storage failure happens.
    pub async fn wait_fatal(&self) -> String {
        self.fatal.wait().await
    }

    pub fn kind_exists(&self, kind: &str) -> bool {
        lock(&self.kinds).contains_key(kind)
    }

    /// The current configuration epoch and every deployed route.
    pub fn routes(&self) -> (u64, Vec<RouteEntry>) {
        let kinds = lock(&self.kinds);
        let mut out = Vec::new();
        for (name, k) in kinds.iter() {
            if let Some(m) = &k.version.manifest {
                for r in &m.routes {
                    out.push(RouteEntry {
                        kind: name.clone(),
                        method: r.method.clone(),
                        pattern: r.pattern.clone(),
                    });
                }
            }
        }
        (self.epoch.load(Ordering::Acquire), out)
    }

    pub(crate) fn me(&self) -> Option<Arc<Node>> {
        self.me.upgrade()
    }

    fn enqueue(&self, actor: ActorRef, job: Job) {
        let Some(me) = self.me() else { return };
        let mut actors = lock(&self.actors);
        let slot = actors.entry(actor.clone()).or_default();
        slot.queue.push_back(job);
        if !slot.running {
            slot.running = true;
            drop(actors);
            self.env
                .spawn("actor", async move { me.worker(actor).await });
        }
    }

    async fn worker(self: Arc<Self>, actor: ActorRef) {
        loop {
            let job = {
                let mut actors = lock(&self.actors);
                match actors.get_mut(&actor).and_then(|s| s.queue.pop_front()) {
                    Some(j) => j,
                    None => {
                        actors.remove(&actor);
                        return;
                    }
                }
            };
            let timer = match &job.input.kind {
                Some(pb::input::Kind::Timer(t)) => Some(t.timer_id),
                _ => None,
            };
            let result = self
                .run_job(
                    &actor,
                    job.input,
                    job.causal_key,
                    job.parent_time,
                    job.subject,
                    job.rerun,
                )
                .await;
            if let Some(id) = timer {
                lock(&self.wheel).done(&actor, id);
            }
            if let Err(e) = &result {
                tracing::warn!(actor = %actor, error = %e, "input not processed");
            }
            if let Some(reply) = job.reply {
                let _ = reply.send(result);
            }
        }
    }

    fn kind(&self, name: &str) -> Option<Arc<Kind>> {
        lock(&self.kinds).get(name).cloned()
    }

    /// Runs an input on its actor: a migrate turn first when the code's
    /// schema version is ahead of the actor's, then the input's own turn.
    /// A re-run repeats its recorded turn exactly.
    async fn run_job(
        &self,
        actor: &ActorRef,
        input: pb::Input,
        key: pb::CausalKey,
        parent_time: u64,
        subject: Option<String>,
        rerun: Option<Rerun>,
    ) -> Result<TurnResult, ApiError> {
        if let Some(f) = self.fatal() {
            return Err(ApiError::new(ErrorCode::Unavailable, f));
        }
        let branch = self.cfg.branch.clone();
        match &input.kind {
            Some(pb::input::Kind::Message(m)) if rerun.is_none() => {
                if m.source == pb::MessageSource::Call as i32
                    && let Some((lsn, mut outcome)) = self
                        .store
                        .db()
                        .call_outcome(&m.message_id)
                        .map_err(store_err)?
                {
                    self.unseal_outcome(&mut outcome);
                    return Ok(TurnResult {
                        turn_id: TurnId { branch, lsn },
                        outcome,
                    });
                }
                if matches!(
                    pb::MessageSource::try_from(m.source),
                    Ok(pb::MessageSource::Actor | pb::MessageSource::Compensation)
                ) && let Some(lsn) =
                    self.store.db().delivery(&m.message_id).map_err(store_err)?
                {
                    return Err(internal(format!(
                        "message {} was already delivered in turn {}",
                        m.message_id,
                        TurnId { branch, lsn }
                    )));
                }
            }
            Some(pb::input::Kind::Timer(t))
                if rerun.is_none()
                    && !self
                        .store
                        .db()
                        .timer_pending(&actor.kind, &actor.key, t.timer_id)
                        .map_err(store_err)? =>
            {
                return Err(internal(format!(
                    "timer {} is no longer pending",
                    t.timer_id
                )));
            }
            _ => {}
        }
        if let Some(hold) = &self.cfg.test_hold_switch {
            hold.arrived.fetch_add(1, Ordering::SeqCst);
        }
        let (kind, mut epoch) = self.start_code(&actor.kind).await;
        let Some(mut kind) = kind else {
            return self
                .record_unrun(
                    actor,
                    None,
                    epoch,
                    input,
                    key,
                    parent_time,
                    ErrorCode::ActorNotFound,
                    format!("no deployed kind {:?}", actor.kind),
                )
                .await;
        };
        // The guest gets plaintext; an input of an erased subject can't run
        // (docs/design/m8-privacy.md §5).
        if let Err(e) = self.check_input(&input) {
            let (code, message) = Node::unreadable_input(&e);
            return self
                .record_unrun(
                    actor,
                    Some(&kind),
                    epoch,
                    input,
                    key,
                    parent_time,
                    code,
                    message,
                )
                .await;
        }
        let actor_version = || -> Result<u32, ApiError> {
            Ok(self
                .store
                .db()
                .actor(&actor.kind, &actor.key)
                .map_err(store_err)?
                .map_or(0, |a| a.schema_version))
        };
        if let Some(r) = rerun {
            let (version, migrate) = match &input.kind {
                Some(pb::input::Kind::Migrate(m)) => (m.to_schema_version, true),
                // The recorded code's schema version, not the current kind's:
                // a switch may have raised it since the turn began.
                _ => (
                    self.schema_of(&r.begin.code_hash)?
                        .unwrap_or(kind.version.schema_version)
                        .max(actor_version()?),
                    false,
                ),
            };
            return self
                .run_turn(
                    actor,
                    &kind,
                    input,
                    key,
                    parent_time,
                    subject,
                    version,
                    migrate,
                    epoch,
                    Some(r),
                )
                .await;
        }
        let mut target = kind.version.schema_version.max(actor_version()?);
        // A migrate turn runs first when the code's schema version is ahead of
        // the actor's. If a switch swapped the code meanwhile, the input's
        // turn takes the new code (and migrates again if it must), so it
        // never starts with code older than the switch.
        loop {
            let from = actor_version()?;
            if target <= from {
                break;
            }
            let migrate = pb::Input {
                kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                    from_schema_version: from,
                    to_schema_version: target,
                })),
            };
            let r = self
                .run_turn(
                    actor,
                    &kind,
                    migrate,
                    causal::migrate(&key, actor),
                    parent_time,
                    None,
                    target,
                    true,
                    epoch,
                    None,
                )
                .await?;
            if !r.committed() {
                return self
                    .record_unrun(
                        actor,
                        Some(&kind),
                        epoch,
                        input,
                        key,
                        parent_time,
                        ErrorCode::TurnFailed,
                        format!(
                            "migration to schema version {target} failed in turn {}",
                            r.turn_id
                        ),
                    )
                    .await;
            }
            let (now, at) = self.start_code(&actor.kind).await;
            epoch = at;
            match now {
                Some(now) if now.hash != kind.hash => {
                    kind = now;
                    target = kind.version.schema_version.max(actor_version()?);
                }
                _ => break,
            }
        }
        self.run_turn(
            actor,
            &kind,
            input,
            key,
            parent_time,
            subject,
            target,
            false,
            epoch,
            None,
        )
        .await
    }

    /// A turn's code and configuration epoch, taken together under the
    /// switch gate (ADR 0013).
    async fn start_code(&self, kind: &str) -> (Option<Arc<Kind>>, u64) {
        let _start = self.switch_gate.read().await;
        (self.kind(kind), self.epoch.load(Ordering::Acquire))
    }

    /// The schema version of the code `hash` in its `Deployment` (a re-run's
    /// recorded code).
    fn schema_of(&self, hash: &[u8]) -> Result<Option<u32>, ApiError> {
        Ok(self
            .store
            .db()
            .deployments()
            .map_err(store_err)?
            .into_iter()
            .flat_map(|(_, d)| d.kinds)
            .find(|k| k.code_hash == hash)
            .map(|k| k.schema_version))
    }

    /// The configuration of `epoch` and the kind's limits under it.
    fn config_at(&self, epoch: u64) -> Arc<Config> {
        lock(&self.config).at(epoch)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_turn(
        &self,
        actor: &ActorRef,
        kind: &Kind,
        input: pb::Input,
        key: pb::CausalKey,
        parent_time: u64,
        subject: Option<String>,
        schema_version: u32,
        migrate: bool,
        epoch: u64,
        rerun: Option<Rerun>,
    ) -> Result<TurnResult, ApiError> {
        let started = self.env.clock.monotonic();
        let clock = self.env.clock.clone();
        let _timer = kronik_metrics::timer(
            "kronik_turn_duration_seconds",
            ("kind", &actor.kind),
            move || clock.monotonic(),
        );
        let Some(me) = self.me() else {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ));
        };
        let (execution_id, seed, time, epoch, program, code_hash, recorded) = match rerun {
            Some(r) => {
                let seed: [u8; 32] = r.begin.random_seed.as_slice().try_into().map_err(|_| {
                    ApiError::new(ErrorCode::StorageCorrupt, "TurnBegin with a bad seed")
                })?;
                let hash = CodeHash::from_slice(&r.begin.code_hash).ok_or_else(|| {
                    ApiError::new(ErrorCode::StorageCorrupt, "TurnBegin with a bad code hash")
                })?;
                if r.begin.engine_version != kronik_runtime::ENGINE_VERSION {
                    tracing::warn!(
                        recorded = %r.begin.engine_version,
                        running = kronik_runtime::ENGINE_VERSION,
                        "re-running a turn recorded by another engine version"
                    );
                }
                let program = self.code.get(&hash).map_err(internal)?;
                (
                    r.begin.execution_id,
                    seed,
                    r.begin.logical_time_ms,
                    r.begin.config_epoch,
                    program,
                    hash,
                    Some({
                        let mut recorded = r.recorded;
                        self.unseal_effects(&mut recorded);
                        recorded
                    }),
                )
            }
            None => (
                random_id(&self.env),
                self.env.random_bytes::<32>(),
                self.clock.next(self.env.clock.as_ref(), parent_time),
                epoch,
                kind.program.clone(),
                kind.hash,
                None,
            ),
        };
        let config = self.config_at(epoch);
        let kind_limits = config.limits(&actor.kind);
        let limits = turn_limits(&kind_limits);
        let call_chain = match &input.kind {
            Some(pb::input::Kind::Message(m)) => {
                m.call_chain.iter().map(ActorRef::from_pb).collect()
            }
            _ => Vec::new(),
        };
        let fx = TurnFx::new(
            me,
            TurnSpec {
                actor: actor.clone(),
                execution_id: execution_id.clone(),
                causal_key: key.clone(),
                time,
                config,
                limits: kind_limits,
                call_chain,
                begin: pb::TurnBegin {
                    execution_id: execution_id.clone(),
                    actor: Some(actor.to_pb()),
                    code_hash: code_hash.0.to_vec(),
                    engine_version: kronik_runtime::ENGINE_VERSION.into(),
                    causal_key: Some(key.clone()),
                    logical_time_ms: time,
                    random_seed: seed.to_vec(),
                    input: Some(input.clone()),
                    config_epoch: epoch,
                },
                recorded,
            },
        );
        let sql = Arc::new(Mutex::new(SqlTurn::new(
            self.store.clone(),
            actor,
            TurnOpts {
                seed,
                time_ms: time as i64,
                default_subject: subject.clone(),
                migrate,
                sql_budget: limits.fuel,
                max_bytes: kind_limits.sql_bytes_per_actor,
            },
        )));
        let req = TurnRequest {
            actor: actor.clone(),
            causal_key: key.clone(),
            logical_time_ms: time,
            seed,
            input: self.guest_input(&input),
            limits,
            subject,
        };
        let state = Arc::new(KvView {
            store: self.store.clone(),
            actor: actor.clone(),
            sealer: self.sealer.clone(),
        });
        let permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        self.probe.turns_run.fetch_add(1, Ordering::Relaxed);
        let run = program
            .run(
                req,
                state,
                Some(Box::new(SqlHandle(sql.clone()))),
                Some(Arc::new(Gate(fx.clone()))),
            )
            .await;
        drop(permit);
        let mut out = match run {
            Ok(out) => out,
            Err(e) => {
                let _ = lock(&sql).end(false, &[]);
                return Err(internal(e));
            }
        };
        drop(out.sql.take());
        let fxs = std::mem::take(&mut *lock(&fx.state));
        let causal_id = causal::causal_id(&key);
        emit_logs(actor, &causal_id, &execution_id, &out.logs, &fxs.secrets);

        let mut sql_changes = Vec::new();
        let mut sql_schema = Vec::new();
        match lock(&sql).end(out.committed(), &fxs.secrets) {
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
                    error_code: ErrorCode::TurnFailed.as_str().into(),
                    message: msg,
                    output: None,
                };
                out.writes.clear();
                out.messages.clear();
                out.timers.clear();
            }
        }
        // I8: structured fields only, never encoded bytes (crate::scrub).
        crate::scrub::output(&mut out, &fxs.secrets);
        let mut fxs = fxs;
        for e in &mut fxs.records {
            crate::scrub::effect(e, &fxs.secrets);
        }
        for m in &mut fxs.compensations {
            crate::scrub::message(&mut m.msg, &fxs.secrets);
        }
        let committed = out.committed();
        if !committed && fxs.outcome_unknown {
            out.outcome.kind = pb::OutcomeKind::EffectOutcomeUnknown as i32;
            out.outcome.error_code = ErrorCode::EffectOutcomeUnknown.as_str().into();
        }
        let messages = if committed {
            out.messages.clone()
        } else {
            Vec::new()
        };
        let timers = if committed {
            out.timers.clone()
        } else {
            Vec::new()
        };
        let outcome = out.outcome.clone();
        let record = pb::TurnRecord {
            execution_id,
            actor: Some(actor.to_pb()),
            code_hash: code_hash.0.to_vec(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(key.clone()),
            logical_time_ms: time,
            random_seed: seed.to_vec(),
            input: Some(input),
            effects: fxs.records,
            writes: out.writes,
            messages: out.messages,
            timers: out.timers,
            outcome: Some(out.outcome),
            fuel_used: out.fuel_used,
            sql_changes,
            compensations: if committed {
                Vec::new()
            } else {
                fxs.compensations.clone()
            },
            sql_schema,
            blob_refs: Vec::new(),
            config_epoch: epoch,
            memory_peak_bytes: out.memory_peak_bytes,
            schema_version: if committed { schema_version } else { 0 },
            duration_us: u64::try_from(
                self.env
                    .clock
                    .monotonic()
                    .saturating_sub(started)
                    .as_micros(),
            )
            .unwrap_or(u64::MAX),
        };
        let lsn = self.commit(Record::TurnRecord(record)).await?;
        for m in messages {
            self.deliver(actor, &key, time, m, pb::MessageSource::Actor, "");
        }
        if !committed {
            for m in fxs.compensations {
                let compensates = causal::message_id(&key, m.ordinal);
                self.deliver(
                    actor,
                    &key,
                    time,
                    m,
                    pb::MessageSource::Compensation,
                    &compensates,
                );
            }
        }
        if !timers.is_empty() {
            let mut w = lock(&self.wheel);
            for t in &timers {
                if t.kind == pb::TimerOpKind::Schedule as i32 {
                    w.add(actor.clone(), t.timer_id, t.due_ms);
                } else {
                    w.remove(actor, t.timer_id);
                }
            }
            drop(w);
            self.wheel_notify.notify_one();
        }
        Ok(TurnResult {
            turn_id: TurnId {
                branch: self.cfg.branch.clone(),
                lsn,
            },
            outcome,
        })
    }

    /// Records a failed turn for an input that could not run (no deployed
    /// kind, failed migration), so messages leave the mailbox and appear in
    /// the dead letters and the history.
    #[allow(clippy::too_many_arguments)]
    async fn record_unrun(
        &self,
        actor: &ActorRef,
        kind: Option<&Kind>,
        epoch: u64,
        input: pb::Input,
        key: pb::CausalKey,
        parent_time: u64,
        code: ErrorCode,
        message: String,
    ) -> Result<TurnResult, ApiError> {
        let time = self.clock.next(self.env.clock.as_ref(), parent_time);
        let outcome = pb::Outcome {
            kind: pb::OutcomeKind::Failed as i32,
            error_code: code.as_str().into(),
            message,
            output: None,
        };
        let record = pb::TurnRecord {
            execution_id: random_id(&self.env),
            actor: Some(actor.to_pb()),
            code_hash: kind.map(|k| k.hash.0.to_vec()).unwrap_or_default(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(key),
            logical_time_ms: time,
            input: Some(input),
            outcome: Some(outcome.clone()),
            config_epoch: epoch,
            ..Default::default()
        };
        let lsn = self.commit(Record::TurnRecord(record)).await?;
        Ok(TurnResult {
            turn_id: TurnId {
                branch: self.cfg.branch.clone(),
                lsn,
            },
            outcome,
        })
    }

    /// Appends a record and waits until it is applied.
    async fn commit(&self, mut record: Record) -> Result<Lsn, ApiError> {
        self.seal(&mut record)?;
        if let Record::TurnRecord(t) = &record {
            let outcome = t
                .outcome
                .as_ref()
                .and_then(|o| pb::OutcomeKind::try_from(o.kind).ok())
                .map(|k| kronik_metrics::enum_label(k.as_str_name(), "OUTCOME_KIND_"))
                .unwrap_or_default();
            let kind = t
                .actor
                .as_ref()
                .map(|a| a.kind.as_str())
                .unwrap_or_default();
            kronik_metrics::inc(
                "kronik_turns_total",
                &[("kind", kind), ("outcome", &outcome)],
            );
        }
        let lsn = match self.log.append(record).await {
            Ok(lsn) => lsn,
            Err(e) => {
                self.fatal.set(e.to_string());
                return Err(ApiError::new(ErrorCode::Unavailable, e.to_string()));
            }
        };
        tokio::select! {
            biased;
            () = self.store.applied.wait(lsn) => Ok(lsn),
            msg = self.fatal.wait() => Err(ApiError::new(ErrorCode::Unavailable, msg)),
        }
    }

    fn deliver(
        &self,
        from: &ActorRef,
        key: &pb::CausalKey,
        time: u64,
        m: pb::OutboundMessage,
        source: pb::MessageSource,
        compensates: &str,
    ) {
        let Some(to) = m.to.as_ref().map(ActorRef::from_pb) else {
            return;
        };
        let subject = body_subject(m.msg.as_ref());
        let causal_key = if source == pb::MessageSource::Compensation {
            causal::compensation(key, from, m.ordinal, &to)
        } else {
            causal::child(key, from, m.ordinal)
        };
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: source as i32,
                sender: Some(from.to_pb()),
                msg: m.msg,
                message_id: m.message_id,
                sent_logical_time_ms: time,
                compensates: compensates.to_owned(),
                ..Default::default()
            })),
        };
        self.enqueue(
            to,
            Job {
                input,
                causal_key,
                parent_time: time,
                subject,
                reply: None,
                rerun: None,
            },
        );
    }

    /// Queues the callee's turn of a `call`.
    pub(crate) fn enqueue_call(
        &self,
        to: ActorRef,
        input: pb::Input,
        key: pb::CausalKey,
        time: u64,
    ) -> oneshot::Receiver<Result<TurnResult, ApiError>> {
        let subject = match &input.kind {
            Some(pb::input::Kind::Message(m)) => body_subject(m.msg.as_ref()),
            _ => None,
        };
        let (tx, rx) = oneshot::channel();
        self.enqueue(
            to,
            Job {
                input,
                causal_key: key,
                parent_time: time,
                subject,
                reply: Some(tx),
                rerun: None,
            },
        );
        rx
    }

    /// Appends a record and resolves after its fsync (not its apply).
    pub(crate) async fn append(&self, mut record: Record) -> Result<Lsn, ApiError> {
        self.seal(&mut record)?;
        self.log.append(record).await.map_err(|e| {
            self.fatal.set(e.to_string());
            ApiError::new(ErrorCode::Unavailable, e.to_string())
        })
    }

    /// Queues a root input and returns the receiver of its result.
    fn start_root(
        &self,
        actor: ActorRef,
        root_id: String,
        input: pb::Input,
        subject: Option<String>,
    ) -> oneshot::Receiver<Result<TurnResult, ApiError>> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(
            actor,
            Job {
                input,
                causal_key: causal::root(root_id),
                parent_time: 0,
                subject,
                reply: Some(tx),
                rerun: None,
            },
        );
        rx
    }

    /// Admits new work: refused when the node has stopped, or when its
    /// log's file system is below `[log] disk_reserve`. Actions that free
    /// space or are needed in an incident (rollback, promote, approvals,
    /// guard records, `foreign remove`, revoke, limits, erasure) use
    /// [`Node::check_alive`].
    pub fn check_running(&self) -> Result<(), ApiError> {
        self.check_alive()?;
        if let Some(free) = self.disk_below_reserve() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                format!(
                    "the log's file system has {} MiB free, less than [log] disk_reserve \
                     ({} MiB): new inputs and changes wait until there is room",
                    free >> 20,
                    self.cfg.disk_reserve >> 20
                ),
            )
            .with_hint(
                "Free disk space on the data directory's file system (foreign actors' data, \
                 old snapshots), or lower [log] disk_reserve. Rollback, promote, \
                 `foreign remove`, revoke, limits and erasure still work.",
            ));
        }
        Ok(())
    }

    /// The free bytes of the log's file system when they are below
    /// `[log] disk_reserve` (`/v1/health`, metrics), else None.
    pub fn disk_below_reserve(&self) -> Option<u64> {
        self.disk_free()
            .filter(|free| *free < self.cfg.disk_reserve)
    }

    /// The free bytes of the log's file system (read every second), when
    /// `[log] disk_reserve` is set and a reading succeeded (`u64::MAX`
    /// stands for no reading yet).
    pub fn disk_free(&self) -> Option<u64> {
        let free = self.disk_free.load(Ordering::Relaxed);
        (self.cfg.disk_reserve > 0 && free != u64::MAX).then_some(free)
    }

    /// How many bytes new work may still write before the log's file
    /// system reaches `[log] disk_reserve` (`foreign add` bounds its image
    /// by it). None without a reserve or a reading.
    pub fn disk_budget(&self) -> Option<u64> {
        self.disk_free()
            .map(|free| free.saturating_sub(self.cfg.disk_reserve))
    }

    /// Refused only when the node has stopped: for the actions that must
    /// work on a full disk too (their records are small).
    pub(crate) fn check_alive(&self) -> Result<(), ApiError> {
        match self.fatal() {
            Some(f) => Err(ApiError::new(ErrorCode::Unavailable, f)),
            None => Ok(()),
        }
    }

    /// Admits an HTTP root input. With an `Idempotency-Key`, the saved
    /// response and the in-flight table are checked under one lock.
    pub fn ingress(
        &self,
        actor: ActorRef,
        mut http: pb::HttpInput,
        subject: Option<String>,
    ) -> Result<Ingress, ApiError> {
        self.check_alive()?;
        // The log requires a body (an empty one for bodiless requests); a
        // record without one could be written but not read back.
        if http.body.is_none() {
            http.body = Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(Vec::new())),
                })),
            });
        }
        let waiter = Arc::new(Waiter::default());
        let input = |http| pb::Input {
            kind: Some(pb::input::Kind::Http(http)),
        };
        if http.idempotency_key.is_empty() {
            self.check_running()?;
            let rx = self.start_root(actor, random_id(&self.env), input(http), subject);
            self.complete_later(rx, waiter.clone(), None);
            return Ok(Ingress::Started(waiter));
        }
        let entry = (actor.clone(), http.idempotency_key.clone());
        let mut inflight = lock(&self.inflight);
        if let Some(e) = inflight.get(&entry) {
            if e.request_hash != http.request_hash {
                return Err(reused(&http.idempotency_key));
            }
            return Ok(Ingress::Joined(e.waiter.clone()));
        }
        let saved = self
            .store
            .db()
            .ingress(&actor.kind, &actor.key, &http.idempotency_key)
            .map_err(store_err)?;
        // A row saved with an older request hash (v1: without the
        // requester; v2: with cookie values) counts as expired, so its
        // response is never replayed to someone else and a key is not
        // refused for a credential that rotated.
        // A v1 hash is 32 bytes without a version byte; its first byte can
        // still be 3.
        if let Some(row) = saved.filter(|r| {
            r.request_hash.len() == 33
                && r.request_hash.first() == Some(&crate::INGRESS_HASH_VERSION)
        }) {
            let ttl = self.cfg.ingress_ttl.as_millis() as u64;
            let now = self.env.clock.wall_ms().max(self.clock.high_water());
            if row.logical_time_ms.saturating_add(ttl) > now {
                if row.request_hash != http.request_hash {
                    return Err(reused(&http.idempotency_key));
                }
                let mut outcome = row.outcome;
                self.unseal_outcome(&mut outcome);
                return Ok(Ingress::Done(Box::new(TurnResult {
                    turn_id: TurnId {
                        branch: self.cfg.branch.clone(),
                        lsn: row.lsn,
                    },
                    outcome,
                })));
            }
        }
        // Joins and saved replies above write nothing: only a new turn
        // needs the disk reserve.
        self.check_running()?;
        inflight.insert(
            entry.clone(),
            Inflight {
                request_hash: http.request_hash.clone(),
                waiter: waiter.clone(),
            },
        );
        drop(inflight);
        let rx = self.start_root(actor, random_id(&self.env), input(http), subject);
        self.complete_later(rx, waiter.clone(), Some(entry));
        Ok(Ingress::Started(waiter))
    }

    fn complete_later(
        &self,
        rx: oneshot::Receiver<Result<TurnResult, ApiError>>,
        waiter: Arc<Waiter>,
        entry: Option<(ActorRef, String)>,
    ) {
        let Some(me) = self.me() else { return };
        self.env.spawn("ingress", async move {
            let r = rx.await.unwrap_or_else(|_| {
                Err(ApiError::new(
                    ErrorCode::Unavailable,
                    "the turn was abandoned",
                ))
            });
            // The ingress row is applied before the result arrives, so
            // removing the in-flight entry leaves no window without either.
            if let Some(entry) = entry {
                lock(&me.inflight).remove(&entry);
            }
            waiter.complete(r);
        });
    }

    fn check_message(&self, kind: &str, msg: &pb::Message) -> Result<(), ApiError> {
        if !self.kind_exists(kind) {
            return Err(ApiError::new(
                ErrorCode::ActorNotFound,
                format!("no deployed kind {kind:?}"),
            ));
        }
        let len = match msg.body.as_ref().and_then(|b| b.value.as_ref()) {
            Some(pb::sealable::Value::Plain(b)) => b.len(),
            _ => 0,
        };
        let limit = self.config_now().limits(kind).message_bytes;
        if len as u64 > limit {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("the message is {len} bytes, the limit is {limit}"),
            ));
        }
        Ok(())
    }

    /// `kronik send`: an operator message as a root input; waits for the turn.
    pub async fn send(
        &self,
        actor: ActorRef,
        mut msg: pb::Message,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<Option<TurnResult>, ApiError> {
        // The log requires a message body (an empty one when absent).
        if msg.body.is_none() {
            msg.body = Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(Vec::new())),
            });
        }
        self.check_running()?;
        self.check_message(&actor.kind, &msg)?;
        if dry_run {
            return Ok(None);
        }
        let root = random_id(&self.env);
        let subject = body_subject(Some(&msg));
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Operator as i32,
                sender: None,
                msg: Some(msg),
                message_id: root.clone(),
                sent_logical_time_ms: 0,
                resend_of: String::new(),
                audit: Some(audit),
                ..Default::default()
            })),
        };
        let rx = self.start_root(actor, root, input, subject);
        rx.await
            .unwrap_or_else(|_| {
                Err(ApiError::new(
                    ErrorCode::Unavailable,
                    "the turn was abandoned",
                ))
            })
            .map(Some)
    }

    /// `kronik dead-letters resend`: the dead letter's message as a new root
    /// input; waits for the turn.
    pub async fn resend(
        &self,
        lsn: Lsn,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<Option<TurnResult>, ApiError> {
        self.check_running()?;
        let id = TurnId {
            branch: self.cfg.branch.clone(),
            lsn,
        };
        let dl = self
            .store
            .db()
            .dead_letter(lsn)
            .map_err(store_err)?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::DeadLetterNotFound,
                    format!("no dead letter {id}"),
                )
            })?;
        if let Some(by) = dl.resent_as {
            return Err(ApiError::new(
                ErrorCode::DeadLetterAlreadyResent,
                format!(
                    "dead letter {id} was resent as {}",
                    TurnId {
                        branch: self.cfg.branch.clone(),
                        lsn: by
                    }
                ),
            ));
        }
        // A resent compensation keeps the call it compensates, so its
        // success resolves the orphan.
        let (sender, msg, compensates) = match dl.input.kind {
            Some(pb::input::Kind::Message(m)) => (m.sender, m.msg, m.compensates),
            Some(pb::input::Kind::Timer(t)) => (None, t.msg, String::new()),
            _ => {
                return Err(internal(format!(
                    "dead letter {id} has neither a message nor a timer"
                )));
            }
        };
        let msg = msg.ok_or_else(|| internal(format!("dead letter {id} has no message")))?;
        self.check_message(&dl.actor.kind, &msg)?;
        if dry_run {
            return Ok(None);
        }
        if !lock(&self.resending).insert(lsn) {
            return Err(ApiError::new(
                ErrorCode::DeadLetterAlreadyResent,
                format!("dead letter {id} is being resent"),
            ));
        }
        let root = random_id(&self.env);
        let subject = body_subject(Some(&msg));
        let input = pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::DeadLetterResend as i32,
                sender,
                msg: Some(msg),
                message_id: root.clone(),
                sent_logical_time_ms: 0,
                resend_of: id.to_string(),
                audit: Some(audit),
                compensates,
                ..Default::default()
            })),
        };
        let rx = self.start_root(dl.actor, root, input, subject);
        let r = rx.await.unwrap_or_else(|_| {
            Err(ApiError::new(
                ErrorCode::Unavailable,
                "the turn was abandoned",
            ))
        });
        lock(&self.resending).remove(&lsn);
        r.map(Some)
    }

    /// `kronik deploy` of a kind without history.
    pub async fn deploy(
        &self,
        bytes: &[u8],
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<DeployResult, ApiError> {
        self.check_running()?;
        let guard = self.deploy_lock.clone().lock_owned().await;
        let (hash, program, manifest) = self.prepare_code(bytes).await?;
        let kind = manifest.kind.clone();
        let current = self.kind(&kind);
        let epoch = self.epoch.load(Ordering::Acquire);
        let config = self.config_now();
        let warnings = manifest
            .capabilities
            .iter()
            // Grants do not need a deployed kind: skip the ones in force.
            .filter(|c| match c.strip_prefix("http:") {
                Some(host) => config.http_grant(&kind, host).is_none(),
                None => config.grant(&kind, c).is_none(),
            })
            .map(|c| {
                format!(
                    "capability {c} is not granted; run: kronik grant {kind} {c} --reason '...'"
                )
            })
            .collect();
        if let Some(c) = &current {
            if c.hash == hash {
                return Ok(DeployResult {
                    dry_run,
                    unchanged: true,
                    epoch,
                    lsn: 0,
                    code_hash: hash,
                    manifest,
                    warnings,
                });
            }
            if self.store.db().kind_has_history(&kind).map_err(store_err)? {
                return Err(ApiError::new(
                    ErrorCode::VerifyRequired,
                    format!(
                        "kind {kind:?} has history; deploying new code over it needs \
                         `kronik propose` and `kronik promote`"
                    ),
                ));
            }
        }
        self.check_routes(&kind, &manifest)?;
        let epoch = epoch + 1;
        if dry_run {
            return Ok(DeployResult {
                dry_run,
                unchanged: false,
                epoch,
                lsn: 0,
                code_hash: hash,
                manifest,
                warnings,
            });
        }
        let version = pb::KindVersion {
            kind: kind.clone(),
            code_hash: hash.0.to_vec(),
            schema_version: manifest.schema_version,
            manifest: Some(manifest.clone()),
            code_size: bytes.len() as u64,
        };
        let record = pb::Deployment {
            epoch,
            kinds: vec![version.clone()],
            effective_lsn: 0,
            verified_through_lsn: 0,
            unverified_inputs: 0,
            cause: pb::DeploymentCause::Deploy as i32,
            proposal_id: String::new(),
            rollback_of_epoch: 0,
            audit: Some(audit),
        };
        let gate = self.switch_gate.clone().write_owned().await;
        let lsn = self
            .finish_switch(guard, gate, record, vec![(version, program, hash)], false)
            .await?;
        tracing::info!(kind = %kind, code = %hash.short(), epoch, lsn, "deployed");
        Ok(DeployResult {
            dry_run,
            unchanged: false,
            epoch,
            lsn,
            code_hash: hash,
            manifest,
            warnings,
        })
    }

    /// Compiles, checks and describes a component without deploying it
    /// (deploy and proposals).
    pub async fn prepare_code(
        &self,
        bytes: &[u8],
    ) -> Result<(CodeHash, Arc<Program>, pb::Manifest), ApiError> {
        let (hash, program) = self.code.add(bytes).map_err(|e| match e {
            CodeError::ImportNotAllowed(bad) => ApiError::new(
                ErrorCode::ImportNotAllowed,
                format!("the component imports {}", bad.join(", ")),
            ),
            CodeError::Invalid(m) => ApiError::new(ErrorCode::BadRequest, m),
            other => internal(other),
        })?;
        let manifest = program
            .describe(TurnLimits::default())
            .await
            .map_err(|m| ApiError::new(ErrorCode::TurnFailed, format!("describe failed: {m}")))?;
        validate_manifest(&manifest)?;
        Ok((hash, program, manifest))
    }

    /// ROUTE_CONFLICT when another kind serves one of the manifest's routes.
    fn check_routes(&self, kind: &str, manifest: &pb::Manifest) -> Result<(), ApiError> {
        self.check_routes_of(&[(kind, manifest)])
    }

    /// ROUTE_CONFLICT when, after `set` replaced its kinds' code, two kinds
    /// would serve one route: a kind of the set against the other deployed
    /// kinds, or two kinds of the set against each other.
    pub fn check_set_routes(&self, set: &[pb::KindVersion]) -> Result<(), ApiError> {
        let set: Vec<(&str, &pb::Manifest)> = set
            .iter()
            .filter_map(|v| Some((v.kind.as_str(), v.manifest.as_ref()?)))
            .collect();
        self.check_routes_of(&set)
    }

    fn check_routes_of(&self, set: &[(&str, &pb::Manifest)]) -> Result<(), ApiError> {
        let (_, mut routes) = self.routes();
        routes.retain(|o| !set.iter().any(|(kind, _)| o.kind == *kind));
        for (kind, manifest) in set {
            for r in &manifest.routes {
                let norm = normalize_pattern(&r.pattern);
                if let Some(other) = routes.iter().find(|o| {
                    o.kind != *kind && o.method == r.method && normalize_pattern(&o.pattern) == norm
                }) {
                    return Err(ApiError::new(
                        ErrorCode::RouteConflict,
                        format!(
                            "{} {} is already served by kind {:?} ({})",
                            r.method, r.pattern, other.kind, other.pattern
                        ),
                    ));
                }
            }
            routes.extend(manifest.routes.iter().map(|r| RouteEntry {
                kind: (*kind).to_owned(),
                method: r.method.clone(),
                pattern: r.pattern.clone(),
            }));
        }
        Ok(())
    }

    /// The code `kind` runs on this branch now.
    pub fn deployed(&self, kind: &str) -> Option<pb::KindVersion> {
        self.kind(kind).map(|k| k.version.clone())
    }

    /// `PROPOSAL_STALE` unless every kind runs its pinned code on main (an
    /// empty hash: the kind must not exist). [`Node::switch_code`] checks
    /// this under the deploy lock; promote also calls it before catch-up, so
    /// a stale proposal fails before it replays.
    pub fn check_pins(&self, pinned: &[pb::KindVersion]) -> Result<(), ApiError> {
        for v in pinned {
            let same = self.kind(&v.kind).map_or(v.code_hash.is_empty(), |k| {
                k.hash.0.as_slice() == v.code_hash.as_slice()
            });
            if same {
                continue;
            }
            // The deployment that last switched the kind, for the message.
            let changed_by = self
                .store()
                .db()
                .deployments()
                .ok()
                .and_then(|ds| {
                    ds.into_iter()
                        .rev()
                        .find(|(_, d)| d.kinds.iter().any(|k| k.kind == v.kind))
                })
                .map_or_else(String::new, |(_, d)| {
                    format!(" (deployment {} changed it)", d.epoch)
                });
            let message = match CodeHash::from_slice(&v.code_hash) {
                Some(h) => format!(
                    "kind {:?} no longer runs {}, the code it ran when the proposal was made{changed_by}",
                    v.kind,
                    h.short()
                ),
                None => format!(
                    "kind {:?} did not exist when the proposal was made and now runs code{changed_by}",
                    v.kind
                ),
            };
            return Err(ApiError::new(ErrorCode::ProposalStale, message).with_hint(
                "See what changed it: kronik deployments list. Propose again: kronik propose <wasm>... --reason \"...\"",
            ));
        }
        Ok(())
    }

    /// Switches a set of kinds to other code with one `Deployment` (promote,
    /// rollback): one epoch and one LSN for the whole set. Turns that start
    /// after it run the new code of every kind in the set, running turns
    /// finish with the old. Returns (epoch, lsn); lsn is 0 for a dry run.
    pub async fn switch_code(
        &self,
        switch: CodeSwitch,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        // Promote and rollback: needed in an incident, also on a full disk.
        self.check_alive()?;
        let guard = self.deploy_lock.clone().lock_owned().await;
        self.check_pins(&switch.pinned)?;
        self.check_set_routes(&switch.kinds)?;
        let mut installs = Vec::with_capacity(switch.kinds.len());
        for v in &switch.kinds {
            let hash = CodeHash::from_slice(&v.code_hash).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("kind {:?}: bad code hash", v.kind),
                )
            })?;
            let program = self.code.get(&hash).map_err(internal)?;
            installs.push((v.clone(), program, hash));
        }
        let epoch = self.epoch.load(Ordering::Acquire) + 1;
        if dry_run {
            return Ok((epoch, 0));
        }
        let record = pb::Deployment {
            epoch,
            kinds: switch.kinds,
            effective_lsn: 0,
            verified_through_lsn: switch.verified_through_lsn,
            unverified_inputs: switch.unverified_inputs,
            cause: switch.cause as i32,
            proposal_id: switch.proposal_id,
            rollback_of_epoch: switch.rollback_of_epoch,
            audit: Some(audit),
        };
        let gate = self.switch_gate.clone().write_owned().await;
        let lsn = self
            .finish_switch(guard, gate, record, installs, true)
            .await?;
        tracing::info!(epoch, lsn, "switched code");
        Ok((epoch, lsn))
    }

    /// Commits a code switch's `Deployment` and installs its kinds and
    /// epoch on a task of its own that holds the deploy lock and the switch
    /// gate (written): a caller that goes away (a client disconnect) never
    /// leaves a switch committed but not installed. `hold`: park on
    /// `test_hold_switch` before the install.
    async fn finish_switch(
        &self,
        guard: tokio::sync::OwnedMutexGuard<()>,
        gate: tokio::sync::OwnedRwLockWriteGuard<()>,
        record: pb::Deployment,
        installs: Vec<(pb::KindVersion, Arc<Program>, CodeHash)>,
        hold: bool,
    ) -> Result<Lsn, ApiError> {
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let epoch = record.epoch;
        let task = self.env.spawn("switch", async move {
            let _guard = guard;
            let _gate = gate;
            let lsn = node.commit(Record::Deployment(record)).await?;
            if hold && let Some(hold) = &node.cfg.test_hold_switch {
                hold.parked.fetch_add(1, Ordering::SeqCst);
                if let Ok(permit) = hold.release.acquire().await {
                    permit.forget();
                }
            }
            let mut kinds = lock(&node.kinds);
            for (version, program, hash) in installs {
                tracing::info!(kind = %version.kind, code = %hash.short(), epoch, lsn, "code installed");
                kinds.insert(
                    version.kind.clone(),
                    Arc::new(Kind {
                        version,
                        program,
                        hash,
                    }),
                );
            }
            node.epoch.store(epoch, Ordering::Release);
            Ok(lsn)
        });
        task.await.unwrap_or_else(|| {
            Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ))
        })
    }

    /// Writes an `Approval` record in this branch's log.
    pub async fn record_approval(&self, approval: pb::Approval) -> Result<Lsn, ApiError> {
        self.check_alive()?;
        self.commit(Record::Approval(approval)).await
    }

    /// Writes a `GuardTriggered` record (`kronik watch`, M11) in this
    /// branch's log. Allowed below `[log] disk_reserve`: it records an
    /// incident (a rollback that already happened, or an alert).
    pub async fn record_guard(&self, guard: pb::GuardTriggered) -> Result<Lsn, ApiError> {
        self.check_alive()?;
        self.commit(Record::GuardTriggered(guard)).await
    }

    /// `kronik policy set`: a `Policy` record at the next epoch (the rules
    /// are validated by the caller). Returns (epoch, lsn); lsn is 0 for a
    /// dry run.
    pub async fn set_policy(
        &self,
        rules_toml: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        self.check_running()?;
        let guard = self.deploy_lock.clone().lock_owned().await;
        let epoch = self.epoch.load(Ordering::Acquire) + 1;
        if dry_run {
            return Ok((epoch, 0));
        }
        let record = Record::Policy(pb::Policy {
            epoch,
            rules_toml: rules_toml.to_owned(),
            rules_hash: blake3::hash(rules_toml.as_bytes()).as_bytes().to_vec(),
            audit: Some(audit),
        });
        let lsn = self.commit_config(guard, epoch, record).await?;
        Ok((epoch, lsn))
    }

    fn fire_timer(&self, actor: ActorRef, id: u64, due_ms: u64) {
        let row = self
            .store
            .db()
            .timers(Some((&actor.kind, &actor.key)))
            .ok()
            .and_then(|rows| rows.into_iter().find(|t| t.timer_id == id));
        let Some(row) = row else {
            lock(&self.wheel).done(&actor, id);
            return;
        };
        let subject = body_subject(Some(&row.msg));
        let input = pb::Input {
            kind: Some(pb::input::Kind::Timer(pb::TimerInput {
                timer_id: id,
                msg: Some(row.msg),
                due_ms,
                scheduled_by: TurnId {
                    branch: self.cfg.branch.clone(),
                    lsn: row.lsn,
                }
                .to_string(),
            })),
        };
        self.enqueue(
            actor,
            Job {
                input,
                causal_key: row.causal_key,
                parent_time: due_ms,
                subject,
                reply: None,
                rerun: None,
            },
        );
    }

    /// The configuration of the current epoch.
    pub fn config_now(&self) -> Arc<Config> {
        let epoch = self.epoch.load(Ordering::Acquire);
        self.config_at(epoch)
    }

    pub(crate) fn hold_after_call(&self) -> bool {
        self.cfg.test_hold_after_call
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Appends a configuration record for the next epoch (deploy lock held).
    ///
    /// The commit and what follows it (the configuration and epoch in
    /// memory, the sealer for a privacy mode, the snapshot after an erasure)
    /// run on a task of their own that holds the deploy lock (`guard`), as a
    /// code switch does: a caller that goes away never leaves a committed
    /// record half applied.
    pub(crate) async fn commit_config(
        &self,
        guard: tokio::sync::OwnedMutexGuard<()>,
        epoch: u64,
        record: Record,
    ) -> Result<Lsn, ApiError> {
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let task = self.env.spawn("config", async move {
            let _guard = guard;
            let erasure = matches!(record, Record::Erasure(_));
            let privacy = matches!(record, Record::PrivacyMode(_));
            let committed = node.commit(record.clone()).await;
            if committed.is_ok() {
                lock(&node.config).push(record);
                node.epoch.store(epoch, Ordering::Release);
            }
            // The sealer follows the configuration, committed or not.
            if privacy {
                node.sealer
                    .set_on(node.privacy_mode().0 == pb::PrivacyState::On);
            }
            let lsn = committed?;
            if erasure {
                node.after_erasure(lsn).await?;
            }
            Ok(lsn)
        });
        task.await.unwrap_or_else(|| {
            Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ))
        })
    }

    /// `kronik grant`: writes a `Grant` record. Returns (epoch, lsn); lsn is 0
    /// for a dry run.
    pub async fn grant(
        &self,
        kind: &str,
        capability: &str,
        delivery: Option<Delivery>,
        rate: Option<Rate>,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        self.check_running()?;
        if !kronik_core::ids::valid_kind(kind) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("{kind:?} is not a valid kind"),
            ));
        }
        let cap = Capability::parse(capability).ok_or_else(|| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "{capability:?} is not a capability (http:<host>, http:*.<domain>, \
                     foreign:<name>, secret:<name>, secret-reveal:<name>)"
                ),
            )
        })?;
        if (delivery.is_some() || rate.is_some())
            && !matches!(cap, Capability::Http(_) | Capability::Foreign(_))
        {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "delivery and rate apply to http: and foreign: capabilities only",
            ));
        }
        let guard = self.deploy_lock.clone().lock_owned().await;
        let epoch = self.epoch() + 1;
        if dry_run {
            return Ok((epoch, 0));
        }
        let record = Record::Grant(pb::Grant {
            epoch,
            op: pb::GrantOp::Grant as i32,
            kind: kind.into(),
            capability: cap.render(),
            delivery: delivery.map(Delivery::to_pb),
            rate: rate.map(|r| r.to_pb()),
            audit: Some(audit),
        });
        let lsn = self.commit_config(guard, epoch, record).await?;
        tracing::info!(kind, capability = %cap.render(), epoch, lsn, "granted");
        Ok((epoch, lsn))
    }

    /// `kronik revoke`.
    pub async fn revoke(
        &self,
        kind: &str,
        capability: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        self.check_alive()?;
        let cap = Capability::parse(capability)
            .map(|c| c.render())
            .unwrap_or_else(|| capability.to_owned());
        let guard = self.deploy_lock.clone().lock_owned().await;
        if self.config_now().grant(kind, &cap).is_none() {
            return Err(ApiError::new(
                ErrorCode::CapabilityNotGranted,
                format!("kind {kind:?} has no grant {cap}"),
            ));
        }
        let epoch = self.epoch() + 1;
        if dry_run {
            return Ok((epoch, 0));
        }
        let record = Record::Grant(pb::Grant {
            epoch,
            op: pb::GrantOp::Revoke as i32,
            kind: kind.into(),
            capability: cap.clone(),
            delivery: None,
            rate: None,
            audit: Some(audit),
        });
        let lsn = self.commit_config(guard, epoch, record).await?;
        tracing::info!(kind, capability = %cap, epoch, lsn, "revoked");
        Ok((epoch, lsn))
    }

    /// Hands the declared foreign actors of the current epoch to the
    /// foreign host, which starts and stops sandboxes to match.
    pub async fn reconcile_foreign(&self) {
        let Some(host) = &self.foreign else {
            return;
        };
        let declared: Vec<pb::ForeignActor> = self.config_now().foreign_actors().cloned().collect();
        host.reconcile(declared, self.secrets.clone()).await;
    }

    /// `kronik foreign add`: writes a `ForeignActor` add record (the caller
    /// has validated and fetched the image), then starts the sandbox.
    /// Returns (epoch, lsn); lsn is 0 for a dry run.
    pub async fn foreign_add(
        &self,
        mut record: pb::ForeignActor,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        self.check_running()?;
        if !kronik_effects::foreign::valid_name(&record.name) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "{:?} is not a foreign actor name (DNS-style labels of a-z, 0-9 and -, \
                     joined by dots, at most 63 characters)",
                    record.name
                ),
            ));
        }
        let (epoch, lsn) = {
            let guard = self.deploy_lock.clone().lock_owned().await;
            if self.config_now().foreign(&record.name).is_some() {
                return Err(ApiError::new(
                    ErrorCode::ForeignExists,
                    format!("foreign actor {} is already declared", record.name),
                ));
            }
            let epoch = self.epoch() + 1;
            if dry_run {
                return Ok((epoch, 0));
            }
            record.epoch = epoch;
            record.op = pb::ForeignOp::Add as i32;
            record.audit = Some(audit);
            let name = record.name.clone();
            let lsn = self
                .commit_config(guard, epoch, Record::ForeignActor(record))
                .await?;
            tracing::info!(name, epoch, lsn, "foreign actor added");
            (epoch, lsn)
        };
        self.reconcile_foreign().await;
        Ok((epoch, lsn))
    }

    /// `kronik foreign remove`: writes a `ForeignActor` remove record, then
    /// stops the sandbox. Returns (epoch, lsn); lsn is 0 for a dry run.
    pub async fn foreign_remove(
        &self,
        name: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn), ApiError> {
        self.check_alive()?;
        let (epoch, lsn) = {
            let guard = self.deploy_lock.clone().lock_owned().await;
            if self.config_now().foreign(name).is_none() {
                return Err(ApiError::new(
                    ErrorCode::ForeignNotFound,
                    format!("no foreign actor {name} is declared"),
                ));
            }
            let epoch = self.epoch() + 1;
            if dry_run {
                return Ok((epoch, 0));
            }
            let record = Record::ForeignActor(pb::ForeignActor {
                epoch,
                op: pb::ForeignOp::Remove as i32,
                name: name.to_owned(),
                audit: Some(audit),
                ..Default::default()
            });
            let lsn = self.commit_config(guard, epoch, record).await?;
            tracing::info!(name, epoch, lsn, "foreign actor removed");
            (epoch, lsn)
        };
        self.reconcile_foreign().await;
        Ok((epoch, lsn))
    }

    /// `kronik limits set`: unset fields keep their value.
    pub async fn set_limits(
        &self,
        mut limits: pb::Limits,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn, KindLimits), ApiError> {
        self.check_alive()?;
        if !kronik_core::ids::valid_kind(&limits.kind) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("{:?} is not a valid kind", limits.kind),
            ));
        }
        let guard = self.deploy_lock.clone().lock_owned().await;
        let epoch = self.epoch() + 1;
        limits.epoch = epoch;
        limits.audit = Some(audit);
        let mut preview = (*self.config_now()).clone();
        let record = Record::Limits(limits.clone());
        preview.apply(&record);
        let effective = preview.limits(&limits.kind);
        if dry_run {
            return Ok((epoch, 0, effective));
        }
        let lsn = self.commit_config(guard, epoch, record).await?;
        Ok((epoch, lsn, effective))
    }

    fn secret_store(&self) -> Result<&Arc<SecretStore>, ApiError> {
        self.secrets.as_ref().ok_or_else(|| {
            ApiError::new(ErrorCode::Unavailable, "the secret store is not configured")
        })
    }

    /// `kronik secret set`.
    pub fn secret_set(
        &self,
        name: &str,
        value: &[u8],
        audit: &pb::Audit,
        dry_run: bool,
    ) -> Result<Option<kronik_privacy::SecretMeta>, ApiError> {
        let store = self.secret_store()?;
        if !kronik_privacy::valid_name(name) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("secret names must match [a-z0-9][a-z0-9_.-]{{0,63}}, got {name:?}"),
            ));
        }
        if dry_run {
            return Ok(None);
        }
        let nonce = self.env.random_bytes::<24>();
        store
            .set(
                name,
                value,
                nonce,
                self.env.clock.wall_ms(),
                &audit.token_id,
                &audit.reason,
            )
            .map(Some)
            .map_err(internal)
    }

    pub fn secret_list(&self) -> Result<Vec<kronik_privacy::SecretMeta>, ApiError> {
        self.secret_store()?.list().map_err(internal)
    }

    /// `kronik secret delete`: returns how many versions were deleted.
    pub fn secret_delete(&self, name: &str, dry_run: bool) -> Result<u32, ApiError> {
        let store = self.secret_store()?;
        let exists = store
            .list()
            .map_err(internal)?
            .iter()
            .any(|m| m.name == name);
        if !exists {
            return Err(ApiError::new(
                ErrorCode::SecretNotFound,
                format!("no secret {name:?}"),
            ));
        }
        if dry_run {
            return Ok(0);
        }
        store
            .delete(name, self.env.clock.wall_ms())
            .map_err(internal)
    }

    /// Values of every live secret, for scrubbing API output.
    pub fn secret_values(&self) -> Vec<(String, Vec<u8>)> {
        self.secrets
            .as_ref()
            .and_then(|s| s.values().ok())
            .unwrap_or_default()
    }

    /// Reads one record of this branch's log.
    pub async fn read_record(&self, lsn: Lsn) -> Result<Option<Committed>, ApiError> {
        let Some(t) = self.store.db().turn(lsn).map_err(store_err)? else {
            return Ok(None);
        };
        self.reader
            .read_at(t.pos)
            .await
            .map(Some)
            .map_err(|e| match e {
                LogError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
                other => internal(other),
            })
    }

    /// Logical time of the latest turn with `lsn <= at_most`. `None` when
    /// no turn has been applied at or before that point (logical time has
    /// not started; only turns advance it).
    pub async fn logical_time_at(&self, at_most: Lsn) -> Result<Option<u64>, ApiError> {
        let pos = {
            let db = self.store.db();
            let turn = db.latest_turn_at(at_most).map_err(store_err)?;
            let open = db.latest_open_turn_at(at_most).map_err(store_err)?;
            match (turn, open) {
                (Some(t), Some(o)) if o.lsn > t.lsn => Some(o),
                (Some(t), _) => Some(t),
                (None, o) => o,
            }
        };
        let Some(t) = pos else {
            return Ok(None);
        };
        let c = self.reader.read_at(t.pos).await.map_err(|e| match e {
            LogError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
            other => internal(other),
        })?;
        Ok(match c.record {
            Record::TurnRecord(r) => Some(r.logical_time_ms),
            Record::TurnBegin(b) => Some(b.logical_time_ms),
            _ => None,
        })
    }

    /// Logical time of the earliest turn with `lsn > after`. `None` when
    /// no later turn has been applied.
    pub async fn logical_time_after(&self, after: Lsn) -> Result<Option<u64>, ApiError> {
        let pos = {
            let db = self.store.db();
            let turn = db.earliest_turn_after(after).map_err(store_err)?;
            let open = db.earliest_open_turn_after(after).map_err(store_err)?;
            match (turn, open) {
                (Some(t), Some(o)) if o.lsn < t.lsn => Some(o),
                (Some(t), _) => Some(t),
                (None, o) => o,
            }
        };
        let Some(t) = pos else {
            return Ok(None);
        };
        let c = self.reader.read_at(t.pos).await.map_err(|e| match e {
            LogError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
            other => internal(other),
        })?;
        Ok(match c.record {
            Record::TurnRecord(r) => Some(r.logical_time_ms),
            Record::TurnBegin(b) => Some(b.logical_time_ms),
            _ => None,
        })
    }
}

fn reused(key: &str) -> ApiError {
    ApiError::new(
        ErrorCode::IdempotencyKeyReused,
        format!("Idempotency-Key {key:?} was used for a different request"),
    )
}

fn body_subject(msg: Option<&pb::Message>) -> Option<String> {
    msg.and_then(|m| m.body.as_ref())
        .and_then(|b| b.subject.clone())
}

fn emit_logs(
    actor: &ActorRef,
    causal_id: &str,
    execution_id: &str,
    logs: &[LogEvent],
    secrets: &[(String, Vec<u8>)],
) {
    use kronik_effects::http::scrub_str;
    for e in logs {
        let fields = scrub_str(
            &e.fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            secrets,
        );
        let message = scrub_str(e.message.trim_end(), secrets);
        macro_rules! ev {
            ($lvl:ident) => {
                tracing::$lvl!(
                    target: "kronik::guest",
                    actor = %actor,
                    causal_id,
                    execution_id,
                    fields = %fields,
                    "{}",
                    message
                )
            };
        }
        match e.level {
            "trace" => ev!(trace),
            "debug" => ev!(debug),
            "warn" => ev!(warn),
            "error" => ev!(error),
            _ => ev!(info),
        }
    }
}

fn turn_limits(l: &KindLimits) -> TurnLimits {
    let size = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
    TurnLimits {
        fuel: l.fuel,
        memory_bytes: size(l.memory_bytes),
        message_bytes: size(l.message_bytes),
        state_value_bytes: size(l.state_value_bytes),
    }
}

/// Reads the free space of the log's file system every second into
/// `Node::disk_free`, and says when it crosses `[log] disk_reserve`.
async fn disk_space_loop(node: Weak<Node>, dir: std::path::PathBuf) {
    let mut low = false;
    loop {
        let Some(n) = node.upgrade() else { return };
        match n.env.fs.available(dir.clone()).await {
            Ok(free) => {
                n.disk_free.store(free, Ordering::Relaxed);
                let now_low = free < n.cfg.disk_reserve;
                if now_low && !low {
                    tracing::error!(
                        free_mib = free >> 20,
                        reserve_mib = n.cfg.disk_reserve >> 20,
                        "the log's file system is below [log] disk_reserve: new inputs and changes are refused"
                    );
                } else if low && !now_low {
                    tracing::info!(
                        free_mib = free >> 20,
                        "free disk space is back above [log] disk_reserve"
                    );
                }
                low = now_low;
            }
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "reading free disk space failed")
            }
        }
        let sleep = n.env.clock.sleep(Duration::from_secs(1));
        drop(n);
        sleep.await;
    }
}

/// Fires due timers: sleeps until the next due time (wall clock) or until a
/// new timer arrives, then queues each due timer's turn.
async fn timer_loop(node: Weak<Node>) {
    loop {
        let Some(n) = node.upgrade() else { return };
        let now = n.env.clock.wall_ms();
        let (due, next) = {
            let mut w = lock(&n.wheel);
            (w.take_due(now), w.next_due())
        };
        for (actor, id, due_ms) in due {
            n.fire_timer(actor, id, due_ms);
        }
        let wait = next
            .map_or(60_000, |d| d.saturating_sub(now))
            .clamp(1, 60_000);
        let sleep = n.env.clock.sleep(Duration::from_millis(wait));
        let notify = n.wheel_notify.clone();
        drop(n);
        let notified = notify.notified();
        tokio::select! {
            biased;
            () = notified => {}
            () = sleep => {}
        }
    }
}

/// The HTTP methods a route may declare (and the gateway accepts).
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// `{name}` segments become `{}` so that patterns differing only in
/// parameter names compare equal.
pub fn normalize_pattern(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|s| if s.starts_with('{') { "{}" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_manifest(m: &pb::Manifest) -> Result<(), ApiError> {
    let bad = |msg: String| Err(ApiError::new(ErrorCode::BadRequest, msg));
    if !kronik_core::ids::valid_kind(&m.kind) {
        return bad(format!(
            "describe returned kind {:?}; kinds must match [a-z][a-z0-9-]{{0,62}}",
            m.kind
        ));
    }
    let mut seen = HashSet::new();
    for r in &m.routes {
        if !METHODS.contains(&r.method.as_str()) {
            return bad(format!("route method {:?} is not supported", r.method));
        }
        if !r.pattern.starts_with('/') {
            return bad(format!("route pattern {:?} must start with '/'", r.pattern));
        }
        let mut names = HashSet::new();
        for seg in r.pattern.split('/').skip(1) {
            if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                let ok = !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                if !ok || !names.insert(name) {
                    return bad(format!(
                        "route pattern {:?} has an invalid or repeated parameter {seg:?}",
                        r.pattern
                    ));
                }
            } else if seg.contains(['{', '}']) || (seg.is_empty() && r.pattern != "/") {
                return bad(format!(
                    "route pattern {:?} has an invalid segment {seg:?}",
                    r.pattern
                ));
            }
        }
        if !seen.insert((r.method.clone(), normalize_pattern(&r.pattern))) {
            return bad(format!("route {} {} is listed twice", r.method, r.pattern));
        }
    }
    Ok(())
}

async fn applier(
    store: Arc<Store>,
    mut rx: mpsc::UnboundedReceiver<Committed>,
    max: usize,
    fatal: Arc<Fatal>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while batch.len() < max {
            match rx.try_recv() {
                Ok(c) => batch.push(c),
                Err(_) => break,
            }
        }
        if let Err(e) = store.apply(&batch) {
            fatal.set(format!("applying lsn {}: {e}", batch[0].lsn));
            return;
        }
    }
}
