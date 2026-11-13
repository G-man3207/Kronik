//! The node: one branch of one daemon.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use kronik_core::authority::AuthLease;
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

mod native;
mod native_installation;
mod native_metadata_audit;
mod native_subject_keys;
mod records;
mod source_gc;
pub use records::{ShardReadPoint, ShardReader, ShardRecordPage};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, e.to_string())
}

pub(crate) fn store_err(e: StoreError) -> ApiError {
    match e {
        StoreError::Corrupt(m) => ApiError::new(ErrorCode::StorageCorrupt, m),
        other => internal(other),
    }
}

/// A record the log refused for its size ([`LogError::is_refusal`]):
/// nothing was written and the writer is healthy, so the node goes on.
pub(crate) fn refused(e: &LogError) -> ApiError {
    ApiError::new(
        ErrorCode::PayloadTooLarge,
        format!("{e}; nothing was written"),
    )
    .with_hint("One log record holds at most 128 MiB: send less data in one request.")
}

/// The answer to a resend whose dead letter the rebased state no longer has
/// (m13-rebase §3), given when the switch drops the held resend and when a
/// resend that was queued after that is about to run.
fn dead_letter_gone(lsn: Lsn) -> ApiError {
    ApiError::new(
        ErrorCode::DeadLetterNotFound,
        format!("dead letter {lsn} is gone: a rollback via replay switched main's state"),
    )
}

/// Fixed host lifecycle producers, never deserialized operator authority.
#[derive(Clone, Copy)]
pub enum SystemAudit {
    ExportConfiguration,
    RetentionGap,
    Restore,
    KeySource,
    FleetRecovery,
}

impl SystemAudit {
    fn identity(self) -> (&'static str, &'static str) {
        match self {
            Self::ExportConfiguration => ("audit.config", "system"),
            Self::RetentionGap => ("audit.gap", "system"),
            Self::Restore => ("restore", "system"),
            Self::KeySource => ("keys.source", "system"),
            Self::FleetRecovery => ("token.revoke", "system:fleet-recovery"),
        }
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
    pub key_source: Option<Arc<kronik_privacy::key_source::KeySource>>,
    pub ownership: Option<kronik_privacy::key_source::DataOwnership>,
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
    #[error(transparent)]
    KeySource(kronik_privacy::key_source::KeySourceError),
    /// An invalid `[secrets]` setting. Like the other `kronik.toml` settings
    /// the daemon refuses, it is a `BAD_REQUEST`: a catalog code that
    /// `kronik explain` resolves.
    #[error("BAD_REQUEST: {0}")]
    SecretConfig(String),
    #[error(transparent)]
    Secret(#[from] ApiError),
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
    origin: OperationOrigin,
}

impl Job {
    /// The callee turn of a `call` whose caller still waits for it: it runs
    /// while the turn gate drains so that the calling turn can finish (ADR
    /// 0018). One whose caller gave up waits for the drain to end.
    fn is_call(&self) -> bool {
        matches!(&self.input.kind, Some(pb::input::Kind::Message(m)) if m.source == pb::MessageSource::Call as i32)
            && self.reply.as_ref().is_some_and(|r| !r.is_closed())
    }

    /// A resend of a dead letter: the dead letter's LSN.
    fn resend_of(&self) -> Option<Lsn> {
        match &self.input.kind {
            Some(pb::input::Kind::Message(m))
                if m.source == pb::MessageSource::DeadLetterResend as i32 =>
            {
                TurnId::parse(&m.resend_of).map(|t| t.lsn)
            }
            _ => None,
        }
    }

    /// A message from the mailbox or a timer: replaced by the rebased
    /// mailbox and timers at a rebase switch.
    fn is_state_job(&self) -> bool {
        self.rerun.is_none()
            && match &self.input.kind {
                Some(pb::input::Kind::Message(m)) => matches!(
                    pb::MessageSource::try_from(m.source),
                    Ok(pb::MessageSource::Actor | pb::MessageSource::Compensation)
                ),
                Some(pb::input::Kind::Timer(_)) => true,
                _ => false,
            }
    }
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
struct Fatal {
    msg: Mutex<Option<String>>,
    notify: Notify,
    publication: Arc<Mutex<()>>,
    lifecycle: Arc<crate::native_execution::Lifecycle>,
}

impl Fatal {
    fn new(
        publication: Arc<Mutex<()>>,
        lifecycle: Arc<crate::native_execution::Lifecycle>,
    ) -> Self {
        Self {
            msg: Mutex::new(None),
            notify: Notify::new(),
            publication,
            lifecycle,
        }
    }

    fn set(&self, msg: String) {
        {
            let _publication = lock(&self.publication);
            self.lifecycle.stop_under_publication();
        }
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

#[derive(Clone)]
pub(crate) enum OperationOrigin {
    Internal,
    Request(AuthLease),
}

impl OperationOrigin {
    fn check(&self) -> Result<(), ApiError> {
        match self {
            Self::Internal => Ok(()),
            Self::Request(authority) => authority.check(),
        }
    }
}

pub struct Node {
    pub(crate) env: Env,
    pub(crate) cfg: NodeConfig,
    log: Log,
    native_execution: Arc<crate::native_execution::NativeExecution>,
    native_recovery: AuthLease,
    reader: LogReader,
    store: Arc<Store>,
    code: Arc<CodeStore>,
    clock: LogicalClock,
    kinds: Mutex<BTreeMap<String, Arc<Kind>>>,
    epoch: Arc<AtomicU64>,
    actors: Mutex<HashMap<ActorRef, Slot>>,
    permits: Semaphore,
    inflight: Mutex<HashMap<(ActorRef, String), Inflight>>,
    resending: Mutex<HashSet<Lsn>>,
    /// Serializes configuration changes; first in the lock order (ADR 0013,
    /// crate::gate). Shared so a rebase switch's drain can hold it.
    pub(crate) deploy_lock: Arc<tokio::sync::Mutex<()>>,
    /// Where turns start: the switch gate and the drain (crate::gate).
    pub(crate) gate: crate::gate::TurnGate,
    pub(crate) snapshot_lock: Arc<tokio::sync::Mutex<()>>,
    group_commit_window: Duration,
    fatal: Arc<Fatal>,
    /// Free bytes on the log's file system, refreshed every second while
    /// `[log] disk_reserve` is set or retention runs, whose audit hold gives
    /// way on it even without a reserve (review M4); `u64::MAX` until the
    /// first reading.
    disk_free: AtomicU64,
    config: Mutex<ConfigHistory>,
    pub(crate) secrets: Option<Arc<SecretStore>>,
    pub(crate) secret_runtime: Option<Arc<crate::secrets::SecretRuntime>>,
    effect_slots: Arc<Semaphore>,
    key_source: Option<Arc<kronik_privacy::key_source::KeySource>>,
    publication: Arc<Mutex<()>>,
    lifecycle: Arc<crate::native_execution::Lifecycle>,
    /// Follows the latest `PrivacyMode` record (set at start and by
    /// `set_privacy_mode`).
    pub(crate) sealer: Arc<Sealer>,
    /// The sandboxes behind `foreign://` (docs/design/m7-foreign.md).
    pub(crate) foreign: Option<Arc<dyn kronik_effects::foreign::ForeignHost>>,
    pub(crate) rates: RateLimiter,
    wheel: Mutex<Wheel>,
    wheel_notify: Arc<Notify>,
    /// The shadow of the rebase being promoted (ADR 0017), shared with the
    /// applier.
    pub(crate) rebase: crate::rebase::RebaseCtx,
    pub probe: Probe,
    /// The audit export's floor under retention (ADR 0084).
    retention_hold: crate::snapshots::RetentionHold,
    /// How often retention compacted the index rows (`db.compact`).
    pub(crate) db_compactions: std::sync::atomic::AtomicU64,
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
    rebase: &crate::rebase::RebaseCtx,
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
    let result = replay_segments(env, rebase, store, applied + 1, upto, bulk, batch_cap).await;
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
    rebase: &crate::rebase::RebaseCtx,
    store: &Store,
    from: Lsn,
    upto: Lsn,
    bulk: bool,
    batch_cap: usize,
) -> Result<(), StartError> {
    let reader = &rebase.reader;
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
                    rebase.apply(store, batch).await?;
                }
            }
        }
    }
    Ok(())
}

struct NativeStartupGuard(Option<Arc<Node>>);

impl Drop for NativeStartupGuard {
    fn drop(&mut self) {
        if let Some(node) = &self.0
            && let Err(error) = node.stop_native_execution()
        {
            tracing::error!(error = %error.message, "stopping unfinished native startup failed");
        }
    }
}

impl Node {
    /// Opens the log (truncating a torn tail), applies every durable record
    /// the store has not applied, loads the deployed code and re-queues
    /// undelivered messages.
    pub async fn start(parts: NodeParts) -> Result<Arc<Node>, StartError> {
        let NodeParts {
            env,
            config,
            log: mut log_cfg,
            store,
            code,
            secrets,
            sealer,
            key_source,
            ownership,
        } = parts;
        let publication = Arc::new(Mutex::new(()));
        let lifecycle = Arc::new(crate::native_execution::Lifecycle::new(ownership));
        let secret_runtime = match &secrets {
            Some(file) => {
                let backends = kronik_privacy::secret_backend::config::Backends::new(
                    &env,
                    &config.secret_settings,
                    key_source.as_ref().map(|source| source.master()),
                )
                .await
                .map_err(StartError::SecretConfig)?;
                Some(
                    crate::secrets::SecretRuntime::new(
                        env.clone(),
                        file.clone(),
                        backends,
                        config.secret_settings.clone(),
                        publication.clone(),
                        &lifecycle,
                    )
                    .map_err(|error| StartError::Corrupt(error.to_string()))?,
                )
            }
            None => {
                config
                    .secret_settings
                    .check()
                    .map_err(StartError::SecretConfig)?;
                if !config.secret_settings.backends.is_empty() {
                    return Err(StartError::SecretConfig(
                        "Secret backends require the loaded encrypted secret store".into(),
                    ));
                }
                None
            }
        };
        let sealer = sealer.unwrap_or_else(|| Arc::new(Sealer::plain()));
        // The store opens sealed SQL changesets while it replays the log
        // (docs/design/m8-privacy.md §4).
        store.set_sealer(sealer.clone());
        let (committed_tx, committed_rx) = mpsc::unbounded_channel();
        let (fatal_tx, fatal_rx) = oneshot::channel();
        let log_dir = log_cfg.dir.clone();
        let space_dir = log_dir.clone();
        let group_commit_window = log_cfg.group_commit_window;
        let native_source_first_lsn = log_cfg.first_lsn;
        // What state.db applied was fsynced and acknowledged: the log must
        // never cut it off as a torn tail (#26).
        log_cfg.acknowledged_through = store.applied.get();
        let (log, opened) = Log::open(&env, log_cfg, committed_tx, fatal_tx).await?;
        let writer = log.bind_native_execution(publication.clone(), lifecycle.ownership())?;
        let native_execution = crate::native_execution::NativeExecution::new(
            publication.clone(),
            lifecycle.clone(),
            writer,
            native_source_first_lsn,
        );
        let native_recovery = native_execution
            .recovery_authority()
            .map_err(|error| StartError::Corrupt(error.to_string()))?;
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
                "state.db has applied lsn {applied}, but the log ends at {last}: the log lost \
                 records that were acknowledged (for example, a release before 0.5 cut a \
                 record over 128 MiB off at its start as if it were a torn tail). Keep the \
                 data directory and do not delete segments; a shipped copy of the log may \
                 still hold them: kronik restore --from <url> into a new data directory"
            )));
        }
        let rebase = crate::rebase::RebaseCtx::new(
            reader.clone(),
            config
                .storage
                .as_ref()
                .map(|s| crate::snapshots::snapshots_dir(&s.data_dir, &config.branch)),
        );
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
            replay_unapplied(&env, &rebase, &store, from, last, &config).await?;
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
            // Retention keeps the segment of an open turn's TurnBegin (#35);
            // a directory an older release compacted may lack it.
            let c = reader.read_at(t.pos).await.map_err(|e| match e {
                LogError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                    StartError::Corrupt(format!(
                        "the open turn {} of {} began at lsn {} in log segment {}, which is \
                         gone (retention of a release before 0.5 deleted it), so it cannot run \
                         again. Keep the data directory; restore a snapshot taken after the turn \
                         ended, or a copy of that segment",
                        t.execution_id, t.actor, t.lsn, t.pos.segment
                    ))
                }
                other => StartError::Log(other),
            })?;
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
        let measure = config.disk_reserve > 0 || config.storage.is_some();
        let disk_free = if measure {
            env.fs
                .available(space_dir.clone())
                .await
                .unwrap_or(u64::MAX)
        } else {
            u64::MAX
        };
        let fatal = Arc::new(Fatal::new(publication.clone(), lifecycle.clone()));
        let node = Arc::new_cyclic(|me| Node {
            permits: Semaphore::new(config.concurrency.max(1)),
            clock: LogicalClock::new(hwm),
            env: env.clone(),
            log,
            native_execution: native_execution.clone(),
            native_recovery,
            reader,
            store: store.clone(),
            code,
            kinds: Mutex::new(kinds),
            epoch: Arc::new(AtomicU64::new(epoch)),
            actors: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            resending: Mutex::new(HashSet::new()),
            deploy_lock: Arc::new(tokio::sync::Mutex::new(())),
            gate: crate::gate::TurnGate::default(),
            snapshot_lock: Arc::new(tokio::sync::Mutex::new(())),
            group_commit_window,
            fatal: fatal.clone(),
            disk_free: AtomicU64::new(disk_free),
            config: Mutex::new(history),
            secrets,
            secret_runtime,
            effect_slots: Arc::new(Semaphore::new(64)),
            key_source,
            publication,
            lifecycle,
            sealer: sealer.clone(),
            rates: RateLimiter::starting_full(env.clock.monotonic()),
            wheel: Mutex::new(Wheel::default()),
            wheel_notify: Arc::new(Notify::new()),
            rebase: rebase.clone(),
            probe: Probe::default(),
            retention_hold: Default::default(),
            db_compactions: Default::default(),
            me: me.clone(),
            foreign: config.foreign.0.clone(),
            cfg: config,
        });
        native_execution
            .bind_node(Arc::downgrade(&node))
            .map_err(|error| StartError::Corrupt(error.to_string()))?;
        let mut startup = NativeStartupGuard(Some(node.clone()));
        if let Some(runtime) = &node.secret_runtime {
            runtime
                .bind_native_current_execution(
                    &native_execution,
                    &node.store,
                    &node.reader,
                    node.epoch(),
                )
                .await
                .map_err(|error| StartError::Corrupt(error.to_string()))?;
            let _publication = lock(&node.publication);
            runtime.publish_native_current_config_under_publication(node.epoch());
        }
        #[cfg(test)]
        native::observe_startup(&node);
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
            applier(
                store,
                node.rebase.clone(),
                committed_rx,
                node.cfg.apply_batch,
                fatal,
                node.secret_runtime.clone(),
            ),
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
        node.initialize_secret_versions(last == 0, node.native_recovery.clone())
            .await?;
        node.start_secret_refresh(node.native_recovery.clone());
        // Physical ACTIVE precedes Foreign recovery; public readiness is still the final Ok(node).
        native_execution
            .activate()
            .map_err(|error| StartError::Corrupt(error.to_string()))?;
        // Foreign actors run before open turns are re-run: a re-run may redo
        // a foreign call (docs/design/m7-foreign.md §5).
        node.reconcile_foreign().await;
        kronik_core::authority::Authority::check(native_execution.as_ref())
            .map_err(|error| StartError::Corrupt(error.to_string()))?;
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
                    origin: OperationOrigin::Internal,
                },
            );
        }
        let pending = mailbox.len();
        for row in mailbox {
            if rerun_messages.contains(&row.message_id) {
                continue;
            }
            node.enqueue_mailbox(row);
        }
        {
            let mut w = lock(&node.wheel);
            for t in &timers {
                w.add(t.actor.clone(), t.timer_id, t.due_ms);
            }
        }
        let weak = Arc::downgrade(&node);
        env.spawn("timers", timer_loop(weak));
        if measure {
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
        startup.0 = None;
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
    /// The already-loaded master key; consumers must not reopen a KMS.
    pub fn key_source(&self) -> Option<&Arc<kronik_privacy::key_source::KeySource>> {
        self.key_source.as_ref()
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

    /// The log writer's fsynced head: every record up to this LSN is
    /// durably committed (the applier may still be catching up).
    pub fn committed_head(&self) -> Lsn {
        self.log.committed_head()
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
        let call = job.is_call();
        slot.queue.push_back(job);
        if call {
            // A drained worker runs callee turns.
            self.gate.changed.notify_waiters();
        }
        if !slot.running {
            slot.running = true;
            drop(actors);
            self.env
                .spawn("actor", async move { me.worker(actor).await });
        }
    }

    async fn worker(self: Arc<Self>, actor: ActorRef) {
        loop {
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let next = {
                let mut actors = lock(&self.actors);
                let mut drain = lock(&self.gate.drain);
                let Some(slot) = actors.get_mut(&actor) else {
                    return;
                };
                // While drained only callee turns start (ADR 0018).
                let pick = if drain.drained {
                    slot.queue.iter().position(Job::is_call)
                } else if slot.queue.is_empty() {
                    None
                } else {
                    Some(0)
                };
                match pick.and_then(|i| slot.queue.remove(i)) {
                    Some(job) => {
                        drain.running += 1;
                        Some(job)
                    }
                    None if slot.queue.is_empty() => {
                        actors.remove(&actor);
                        return;
                    }
                    None => None,
                }
            };
            let Some(job) = next else {
                changed.await;
                continue;
            };
            let resend = job.resend_of();
            let timer = match &job.input.kind {
                Some(pb::input::Kind::Timer(t)) => Some(t.timer_id),
                _ => None,
            };
            let retry_begin = job.rerun.as_ref().map(|rerun| rerun.begin.clone());
            let retry_subject = job.subject.clone();
            let mut result = self
                .run_job(
                    &actor,
                    job.input,
                    job.causal_key,
                    job.parent_time,
                    job.subject,
                    job.rerun,
                    job.origin,
                )
                .await;
            if let Some(begin) = retry_begin {
                let mut delay = crate::secrets::recovery::RETRY_INITIAL;
                let mut stalled = None;
                let mut waits = 0u32;
                let mut transient = 0u32;
                while let Err(error) = &result {
                    if !crate::secrets::recovery::rerun_waits(
                        error.code,
                        transient,
                        self.fatal().is_some(),
                    ) {
                        break;
                    }
                    if error.code == ErrorCode::Unavailable {
                        transient += 1;
                    }
                    stalled.get_or_insert_with(crate::secrets::recovery::Stalled::new);
                    if waits.is_multiple_of(crate::secrets::recovery::RERUN_WARN_EVERY) {
                        tracing::warn!(
                            actor = %actor,
                            execution_id = %begin.execution_id,
                            code = %error.code,
                            waits,
                            "the re-run of an open turn is waiting for what it needs"
                        );
                    }
                    waits = waits.saturating_add(1);
                    self.env.clock.sleep(delay).await;
                    delay = delay
                        .saturating_mul(2)
                        .min(crate::secrets::recovery::RETRY_MAX);
                    let recorded = match self.store.db().open_effects(&begin.execution_id) {
                        Ok(recorded) => recorded,
                        Err(error) => {
                            result = Err(store_err(error));
                            break;
                        }
                    };
                    let (Some(input), Some(key)) = (&begin.input, &begin.causal_key) else {
                        result = Err(ApiError::new(
                            ErrorCode::StorageCorrupt,
                            "An open turn has no canonical input or causal key",
                        ));
                        break;
                    };
                    result = self
                        .run_job(
                            &actor,
                            input.clone(),
                            key.clone(),
                            job.parent_time,
                            retry_subject.clone(),
                            Some(Rerun {
                                begin: begin.clone(),
                                recorded,
                            }),
                            OperationOrigin::Internal,
                        )
                        .await;
                }
            }
            if let Some(lsn) = resend {
                lock(&self.resending).remove(&lsn);
            }
            if let Some(id) = timer {
                lock(&self.wheel).done(&actor, id);
            }
            if let Err(e) = &result {
                tracing::warn!(actor = %actor, error = %e, "input not processed");
            }
            if let Some(reply) = job.reply {
                let _ = reply.send(result);
            }
            self.gate.turn_ended();
        }
    }

    /// Queues a pending message of the mailbox.
    fn enqueue_mailbox(&self, row: kronik_store::db::MailboxRow) {
        let (parent_time, subject) = match &row.input.kind {
            Some(pb::input::Kind::Message(m)) => {
                (m.sent_logical_time_ms, body_subject(m.msg.as_ref()))
            }
            _ => (0, None),
        };
        self.enqueue(
            row.to,
            Job {
                input: row.input,
                causal_key: row.causal_key,
                parent_time,
                subject,
                reply: None,
                rerun: None,
                origin: OperationOrigin::Internal,
            },
        );
    }

    /// After a rebase switch (ADR 0018) has installed its code: the timer
    /// wheel and the queued messages and timers from the rebased state.
    /// Root inputs waiting in the queues stay, but resends of dead letters
    /// the rebased state no longer has (m13-rebase §3).
    pub(crate) fn reload_after_rebase(&self) -> Result<(), ApiError> {
        let resends: Vec<Lsn> = lock(&self.actors)
            .values()
            .flat_map(|s| s.queue.iter().filter_map(Job::resend_of))
            .collect();
        let (timers, mailbox, gone_letters) = {
            let db = self.store.db();
            let mut gone = HashSet::new();
            for lsn in resends {
                if db.dead_letter(lsn).map_err(store_err)?.is_none() {
                    gone.insert(lsn);
                }
            }
            (
                db.timers(None).map_err(store_err)?,
                db.mailbox().map_err(store_err)?,
                gone,
            )
        };
        {
            let mut w = lock(&self.wheel);
            *w = Wheel::default();
            for t in &timers {
                w.add(t.actor.clone(), t.timer_id, t.due_ms);
            }
        }
        self.wheel_notify.notify_one();
        let mut gone = Vec::new();
        for slot in lock(&self.actors).values_mut() {
            for job in std::mem::take(&mut slot.queue) {
                match job.resend_of() {
                    _ if job.is_state_job() => {}
                    Some(lsn) if gone_letters.contains(&lsn) => gone.push((lsn, job)),
                    _ => slot.queue.push_back(job),
                }
            }
        }
        for (lsn, job) in gone {
            lock(&self.resending).remove(&lsn);
            if let Some(reply) = job.reply {
                let _ = reply.send(Err(dead_letter_gone(lsn)));
            }
        }
        for row in mailbox {
            self.enqueue_mailbox(row);
        }
        Ok(())
    }

    /// Commits a switch's record and installs its code on a task of its
    /// own that holds `held` (the deploy lock or the rebase pause) and
    /// `gate`, the switch gate held for writing: a caller that goes away
    /// (a client disconnect) never leaves a switch committed but not
    /// installed. `hold`: park on `test_hold_switch` before the install. A rebase switch then reloads the queues and timers; when
    /// that fails after the commit the node goes fatal.
    // A code switch's admission carries the held locks, gate and deployment
    // state: one call site, no struct worth its own name.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_switch<H: Send + 'static>(
        &self,
        held: H,
        gate: tokio::sync::OwnedRwLockWriteGuard<()>,
        record: Record,
        installs: Vec<(pb::KindVersion, Arc<Program>, CodeHash)>,
        epoch: u64,
        hold: bool,
        origin: OperationOrigin,
    ) -> Result<Lsn, ApiError> {
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let rebase = matches!(record, Record::StateRebase(_));
        let task = self.env.spawn("switch", async move {
            let _held = held;
            let _gate = gate;
            let deployment = match &record {
                Record::Deployment(deployment) => Some(deployment.clone()),
                Record::StateRebase(rebase) => match &rebase.part {
                    Some(pb::state_rebase::Part::Switch(switch)) => switch.deployment.clone(),
                    _ => None,
                },
                _ => None,
            };
            let lsn = node.commit_origin(record, origin).await?;
            if let Some(deployment) = deployment {
                lock(&node.config).push(Record::Deployment(deployment));
            }
            if hold {
                node.hold_switch().await;
            }
            node.install_code(installs, epoch);
            if rebase {
                if let Err(e) = node.reload_after_rebase() {
                    node.fatal.set(format!(
                        "reloading after the rebase switch at lsn {lsn}: {e}"
                    ));
                    return Err(e);
                }
                node.rebase.clear_live();
            }
            drop(_held);
            drop(_gate);
            node.recertify_cached_secret_inventory().await?;
            Ok(lsn)
        });
        task.await.unwrap_or_else(|| {
            Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ))
        })
    }

    /// Installs the code of a switch's kinds and its epoch: the one install
    /// path of deploy, promote, rollback and the rebase switch, called with
    /// the switch gate held for writing after the record is applied.
    pub(crate) fn install_code(
        &self,
        installs: Vec<(pb::KindVersion, Arc<Program>, CodeHash)>,
        epoch: u64,
    ) {
        {
            let mut kinds = lock(&self.kinds);
            for (version, program, hash) in installs {
                tracing::info!(kind = %version.kind, code = %hash.short(), epoch, "code installed");
                kinds.insert(
                    version.kind.clone(),
                    Arc::new(Kind {
                        version,
                        program,
                        hash,
                    }),
                );
            }
        }
        self.publish_secret_config_epoch(|| self.epoch.store(epoch, Ordering::Release));
    }

    /// The test hook `NodeConfig::test_hold_switch`: parks a switch after
    /// its record is applied and before its code is installed.
    pub(crate) async fn hold_switch(&self) {
        if let Some(hold) = &self.cfg.test_hold_switch {
            hold.parked.fetch_add(1, Ordering::SeqCst);
            if let Ok(permit) = hold.release.acquire().await {
                permit.forget();
            }
        }
    }

    /// The test hook `SwitchHold::park_resend`: parks a resend after the
    /// check of its dead letter and before its job is queued.
    async fn hold_resend(&self) {
        if let Some(hold) = &self.cfg.test_hold_switch
            && hold.park_resend.load(Ordering::SeqCst)
        {
            hold.resend_parked.fetch_add(1, Ordering::SeqCst);
            if let Ok(permit) = hold.resend_release.acquire().await {
                permit.forget();
            }
        }
    }

    fn kind(&self, name: &str) -> Option<Arc<Kind>> {
        lock(&self.kinds).get(name).cloned()
    }

    /// Runs an input on its actor: a migrate turn first when the code's
    /// schema version is ahead of the actor's, then the input's own turn.
    /// A re-run repeats its recorded turn exactly.
    // One admitted turn's inputs; grouping them would only move the same
    // names into a struct the caller unpacks again.
    #[allow(clippy::too_many_arguments)]
    async fn run_job(
        &self,
        actor: &ActorRef,
        input: pb::Input,
        key: pb::CausalKey,
        parent_time: u64,
        subject: Option<String>,
        rerun: Option<Rerun>,
        origin: OperationOrigin,
    ) -> Result<TurnResult, ApiError> {
        origin.check()?;
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
                        scrubbed_with: None,
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
                // The switch of a rollback via replay drops the held resends
                // it finds in the queues, but a resend that checked its dead
                // letter before the switch can be queued after it: it runs
                // only if the state it runs on still has the dead letter.
                if m.source == pb::MessageSource::DeadLetterResend as i32
                    && let Some(of) = TurnId::parse(&m.resend_of)
                    && self
                        .store
                        .db()
                        .dead_letter(of.lsn)
                        .map_err(store_err)?
                        .is_none()
                {
                    return Err(dead_letter_gone(of.lsn));
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
        let (kind, mut epoch) = self.start_code(&actor.kind, &origin).await?;
        let Some(mut kind) = kind else {
            let message = format!("no deployed kind {:?}", actor.kind);
            // An open turn is closed under its own execution id, or its
            // open_turns row would outlive the failure and the next start
            // would run it again (and it would keep the log from compaction).
            return match rerun {
                Some(r) => {
                    self.close_open_turn(
                        r.begin,
                        r.recorded,
                        ErrorCode::ActorNotFound,
                        message,
                        true,
                    )
                    .await
                }
                None => {
                    self.record_unrun(
                        actor,
                        None,
                        epoch,
                        input,
                        key,
                        parent_time,
                        ErrorCode::ActorNotFound,
                        message,
                        origin.clone(),
                    )
                    .await
                }
            };
        };
        // The guest gets plaintext; an input of an erased subject can't run
        // (docs/design/m8-privacy.md §5).
        if let Err(e) = self.check_input(&input) {
            let (code, message) = Node::unreadable_input(&e);
            return match rerun {
                Some(r) => {
                    self.close_open_turn(r.begin, r.recorded, code, message, true)
                        .await
                }
                None => {
                    self.record_unrun(
                        actor,
                        Some(&kind),
                        epoch,
                        input,
                        key,
                        parent_time,
                        code,
                        message,
                        origin.clone(),
                    )
                    .await
                }
            };
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
                    origin.clone(),
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
                    origin.clone(),
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
                        origin.clone(),
                    )
                    .await;
            }
            let (now, at) = self.start_code(&actor.kind, &origin).await?;
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
            origin,
        )
        .await
    }

    /// A turn's code and configuration epoch, taken together under the
    /// switch gate (ADR 0013).
    async fn start_code(
        &self,
        kind: &str,
        origin: &OperationOrigin,
    ) -> Result<(Option<Arc<Kind>>, u64), ApiError> {
        let _start = match origin {
            OperationOrigin::Internal => self.gate.start().await,
            OperationOrigin::Request(authority) => tokio::select! {
                biased;
                () = authority.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated, "queued actor request revoked at switch gate")),
                held = self.gate.start() => held,
            },
        };
        Ok((self.kind(kind), self.epoch.load(Ordering::Acquire)))
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
        origin: OperationOrigin,
    ) -> Result<TurnResult, ApiError> {
        origin.check()?;
        let original_execution = match &origin {
            OperationOrigin::Request(authority) => authority.clone(),
            OperationOrigin::Internal => self.native_recovery_authority()?,
        };
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
        let (execution_id, seed, time, epoch, program, code_hash, recorded, recovery_begin) =
            match rerun {
                Some(r) => {
                    let config = self.config_at(r.begin.config_epoch);
                    if let Err(error) = self
                        .prepare_recorded_secrets(
                            &r.begin,
                            &r.recorded,
                            &config,
                            original_execution.clone(),
                        )
                        .await
                    {
                        if error.code == ErrorCode::SecretVersionGone {
                            return self
                                .fail_recorded_secret(r.begin, r.recorded, error.code)
                                .await;
                        }
                        return Err(error);
                    }
                    let seed: [u8; 32] =
                        r.begin.random_seed.as_slice().try_into().map_err(|_| {
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
                        r.begin.execution_id.clone(),
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
                        Some(r.begin),
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
        // One log record holds everything the turn records (#26): the
        // budget starts with what the record holds before any effect.
        let mut guest_input = self.guest_input(&input);
        let input_cost = crate::record_budget::input_cost(&mut guest_input);
        let record_limit = self.turn_record_limit();
        let base = crate::record_budget::base_cost(
            &actor.to_pb(),
            &code_hash.0,
            &key,
            time,
            &seed,
            input_cost,
            epoch,
        );
        if base > record_limit {
            // Not even a failed record could hold this input. Nothing of the
            // turn was written; a root input is refused like a body over
            // the limit.
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "the input of {actor} needs {base} bytes of its turn's record, which holds \
                     at most {record_limit}; the turn did not run"
                ),
            ));
        }
        let fx = TurnFx::new(
            me,
            TurnSpec {
                actor: actor.clone(),
                execution_id: execution_id.clone(),
                causal_key: key.clone(),
                time,
                started: self.env.clock.monotonic(),
                config,
                limits: kind_limits,
                call_chain,
                budget: crate::record_budget::Budget::new(record_limit, base),
                begin: recovery_begin.unwrap_or_else(|| pb::TurnBegin {
                    execution_id: execution_id.clone(),
                    actor: Some(actor.to_pb()),
                    code_hash: code_hash.0.to_vec(),
                    engine_version: kronik_runtime::ENGINE_VERSION.into(),
                    causal_key: Some(key.clone()),
                    logical_time_ms: time,
                    random_seed: seed.to_vec(),
                    input: Some(input.clone()),
                    config_epoch: epoch,
                }),
                recorded,
                origin: origin.clone(),
            },
            original_execution,
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
            input: guest_input,
            limits,
            subject,
        };
        let state = Arc::new(KvView {
            store: self.store.clone(),
            actor: actor.clone(),
            sealer: self.sealer.clone(),
        });
        let permit = tokio::select! {
            biased;
            () = async { match &origin { OperationOrigin::Internal => std::future::pending::<()>().await, OperationOrigin::Request(authority) => authority.cancelled().await } } => {
                return Err(ApiError::new(ErrorCode::Unauthenticated, "queued actor request revoked"));
            }
            permit = self.permits.acquire() => permit.map_err(|_| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?,
        };
        origin.check()?;
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
            Err(kronik_runtime::RunError::Prerequisite(code)) => {
                if let Err(message) = lock(&sql).end(false, &[] as &[(&str, &[u8])]) {
                    self.fatal.set(message.clone());
                    return Err(ApiError::new(ErrorCode::Unavailable, message));
                }
                if matches!(code, ErrorCode::SecretUnavailable | ErrorCode::Unavailable) {
                    return Err(ApiError::new(
                        code,
                        "An immutable recorded effect prerequisite is temporarily unavailable",
                    ));
                }
                let last = lock(&fx.state).last_result_lsn;
                tokio::select! {
                    biased;
                    () = self.store.applied.wait(last) => {},
                    message = self.fatal.wait() => return Err(ApiError::new(ErrorCode::Unavailable, message)),
                }
                let mut canonical = self
                    .store
                    .db()
                    .open_effects(&execution_id)
                    .map_err(store_err)?;
                let state = std::mem::take(&mut *lock(&fx.state));
                for effect in state.records {
                    if !canonical
                        .iter()
                        .any(|record| record.ordinal == effect.ordinal)
                    {
                        canonical.push(effect);
                    }
                }
                canonical.sort_by_key(|effect| effect.ordinal);
                return self
                    .fail_recorded_secret(
                        fx.admitted_begin().clone(),
                        canonical,
                        ErrorCode::SecretVersionGone,
                    )
                    .await;
            }
            Err(e) => {
                let _ = lock(&sql).end(false, &[] as &[(&str, &[u8])]);
                return Err(internal(e));
            }
        };
        drop(out.sql.take());
        let mut fxs = std::mem::take(&mut *lock(&fx.state));
        let causal_id = causal::causal_id(&key);
        let secret_patterns = crate::effects::secret_patterns(&fxs.secrets);
        emit_logs(
            actor,
            &causal_id,
            &execution_id,
            std::mem::take(&mut out.logs),
            &secret_patterns,
        );

        let mut sql_changes = Vec::new();
        let mut sql_schema = Vec::new();
        match lock(&sql).end(out.committed(), &secret_patterns) {
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
        // Only new guest data is prepared here; receipts and cleanup intents
        // already carry their immutable disclosure policy.
        let closed_host_trap = out.outcome.kind == pb::OutcomeKind::Trap as i32
            && out.outcome.error_code == ErrorCode::HostRedactionFailure.as_str()
            && out.outcome.message.is_empty()
            && out.outcome.output.is_none()
            && out.writes.is_empty()
            && out.messages.is_empty()
            && out.timers.is_empty();
        let disclosure = if closed_host_trap {
            // The common runtime trap already discarded all unjournaled data.
            // Do not repeat a failed matcher construction and strand the turn.
            Ok(())
        } else {
            kronik_effects::http::CompiledScrubber::new_output(
                &secret_patterns,
                crate::scrub::MAX_SECRET_PATTERN_BYTES,
            )
            .and_then(|matcher| crate::scrub::output(&mut out, &matcher))
        };
        // Output larger than one log record can hold: the turn fails with
        // TURN_TOO_LARGE below, and none of it (prepared or not) is kept.
        let output_too_large = matches!(
            disclosure,
            Err(kronik_effects::http::ScrubError::OutputLimit)
        );
        if output_too_large {
            out.writes.clear();
            out.messages.clear();
            out.timers.clear();
            out.outcome = crate::record_budget::too_large_outcome(record_limit);
        }
        let strict_preparation = disclosure.is_ok() && !closed_host_trap;
        if let Err(error) = disclosure
            && !output_too_large
        {
            // end_turn captured SQL facts and rolled back its savepoint;
            // none of these local buffers has been appended or applied.
            // A NEW post-runtime failure is not a durable effect 11 or a
            // synthetic terminal trap after the Runtime Store is gone.
            return Err(internal(error));
        }
        drop(secret_patterns);
        // An empty proven scope carries no scrubbed identity: report absence so
        // a live result equals the same turn's idempotent replay (which cannot
        // reconstruct a distinguishably empty scope from its saved outcome).
        let scrubbed_with = if strict_preparation {
            fxs.take_secret_scope().filter(|scope| !scope.is_empty())
        } else {
            None
        };
        let committed = out.committed();
        if !committed && fxs.outcome_unknown && !output_too_large {
            out.outcome.kind = pb::OutcomeKind::EffectOutcomeUnknown as i32;
            out.outcome.error_code = ErrorCode::EffectOutcomeUnknown.as_str().into();
        }
        let mut record = pb::TurnRecord {
            execution_id,
            actor: Some(actor.to_pb()),
            code_hash: code_hash.0.to_vec(),
            engine_version: kronik_runtime::ENGINE_VERSION.into(),
            causal_key: Some(key.clone()),
            logical_time_ms: time,
            random_seed: seed.to_vec(),
            input: Some(input),
            effects: std::mem::take(&mut fxs.records),
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
        // A record over the budget fails with TURN_TOO_LARGE and keeps its
        // input, effects and compensations, which the gate kept within it.
        let fitted = if output_too_large {
            crate::record_budget::fail(&mut record, &fxs.compensations, record_limit, input_cost)
        } else {
            crate::record_budget::fit(&mut record, &fxs.compensations, record_limit, input_cost)
        };
        if fitted != crate::record_budget::Fit::Fits {
            tracing::warn!(
                actor = %actor,
                stripped = fitted == crate::record_budget::Fit::Stripped,
                "the turn's record did not fit in one log record: it fails with TURN_TOO_LARGE"
            );
        }
        let outcome = record.outcome.clone().unwrap_or_default();
        let committed = outcome.kind == pb::OutcomeKind::Committed as i32;
        let messages = if committed {
            record.messages.clone()
        } else {
            Vec::new()
        };
        let timers = if committed {
            record.timers.clone()
        } else {
            Vec::new()
        };
        let authorized = !fxs.begun && matches!(&origin, OperationOrigin::Request(_));
        let completion = if fxs.begun {
            OperationOrigin::Internal
        } else {
            origin
        };
        let lsn = self
            .commit_origin(Record::TurnRecord(record), completion)
            .await?;
        if authorized {
            Self::observe_turn(&actor.kind, Some(&outcome));
        }
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
            scrubbed_with,
        })
    }

    /// Records a failed turn for an input that could not run (no deployed
    /// kind, failed migration), so messages leave the mailbox and appear in
    /// the dead letters and the history. A new input only: an open turn is
    /// closed under its own execution id ([`Node::close_open_turn`]).
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
        origin: OperationOrigin,
    ) -> Result<TurnResult, ApiError> {
        origin.check()?;
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
        let authorized = matches!(&origin, OperationOrigin::Request(_));
        let lsn = self
            .commit_origin(Record::TurnRecord(record), origin)
            .await?;
        if authorized {
            Self::observe_turn(&actor.kind, Some(&outcome));
        }
        Ok(TurnResult {
            turn_id: TurnId {
                branch: self.cfg.branch.clone(),
                lsn,
            },
            outcome,
            scrubbed_with: None,
        })
    }

    /// Appends a record and waits until it is applied.
    fn observe_turn(kind: &str, outcome: Option<&pb::Outcome>) {
        let outcome = outcome
            .and_then(|outcome| pb::OutcomeKind::try_from(outcome.kind).ok())
            .map(|kind| kronik_metrics::enum_label(kind.as_str_name(), "OUTCOME_KIND_"))
            .unwrap_or_default();
        kronik_metrics::inc(
            "kronik_turns_total",
            &[("kind", kind), ("outcome", &outcome)],
        );
    }

    pub(crate) async fn commit(&self, mut record: Record) -> Result<Lsn, ApiError> {
        self.seal(&mut record)?;
        if let Record::TurnRecord(turn) = &record {
            Self::observe_turn(
                turn.actor
                    .as_ref()
                    .map(|actor| actor.kind.as_str())
                    .unwrap_or_default(),
                turn.outcome.as_ref(),
            );
        }
        let lsn = match self.log.append(record).await {
            Ok(lsn) => lsn,
            Err(e) if e.is_refusal() => return Err(refused(&e)),
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

    /// The largest record body this node's log appends: `MAX_RECORD`,
    /// unless a test lowered it.
    pub fn record_limit(&self) -> usize {
        self.log.record_limit()
    }

    /// The budget of one turn's record ([`crate::record_budget`]): the same
    /// for production turns and for their replays.
    pub fn turn_record_limit(&self) -> usize {
        crate::record_budget::turn_limit(self.log.record_limit())
    }

    pub(crate) async fn commit_authorized(
        &self,
        record: Record,
        authority: AuthLease,
    ) -> Result<Lsn, ApiError> {
        let record = self.seal_authorized(record, authority.clone()).await?;
        let lsn = match self.log.append_authorized(record, authority).await {
            Ok(lsn) => lsn,
            Err(kronik_log::AuthorizedAppendError::Authority(error)) => return Err(error),
            Err(kronik_log::AuthorizedAppendError::Storage(error)) if error.is_refusal() => {
                return Err(refused(&error));
            }
            Err(kronik_log::AuthorizedAppendError::Storage(error)) => {
                self.fatal.set(error.to_string());
                return Err(ApiError::new(ErrorCode::Unavailable, error.to_string()));
            }
        };
        tokio::select! {
            biased;
            () = self.store.applied.wait(lsn) => Ok(lsn),
            message = self.fatal.wait() => Err(ApiError::new(ErrorCode::Unavailable, message)),
        }
    }

    async fn seal_authorized(
        &self,
        mut record: Record,
        authority: AuthLease,
    ) -> Result<Record, ApiError> {
        if !self.sealer.is_on() || self.sealer.keystore().is_none() {
            return Ok(record);
        }
        let mut tagged = false;
        kronik_proto::sealables::record_mut(&mut record, &mut |value| {
            tagged |= value.subject.is_some()
                && matches!(value.value, Some(pb::sealable::Value::Plain(_)));
        });
        if !tagged {
            return Ok(record);
        }
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "The node is stopping"))?;
        self.authorized_effect(authority, move || async move {
            node.seal(&mut record)?;
            Ok(record)
        })
        .await
    }

    pub(crate) async fn commit_origin(
        &self,
        record: Record,
        origin: OperationOrigin,
    ) -> Result<Lsn, ApiError> {
        match origin {
            OperationOrigin::Internal => self.commit(record).await,
            OperationOrigin::Request(authority) => self.commit_authorized(record, authority).await,
        }
    }

    pub(crate) async fn append_origin(
        &self,
        record: Record,
        origin: OperationOrigin,
    ) -> Result<Lsn, ApiError> {
        match origin {
            OperationOrigin::Internal => self.append(record).await,
            OperationOrigin::Request(authority) => {
                let record = self.seal_authorized(record, authority.clone()).await?;
                match self.log.append_authorized(record, authority).await {
                    Ok(lsn) => Ok(lsn),
                    Err(kronik_log::AuthorizedAppendError::Authority(error)) => Err(error),
                    Err(kronik_log::AuthorizedAppendError::Storage(error))
                        if error.is_refusal() =>
                    {
                        Err(refused(&error))
                    }
                    Err(kronik_log::AuthorizedAppendError::Storage(error)) => {
                        self.fatal.set(error.to_string());
                        Err(ApiError::new(ErrorCode::Unavailable, error.to_string()))
                    }
                }
            }
        }
    }

    pub(crate) async fn switch_authorized(
        &self,
        authority: &AuthLease,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, ApiError> {
        tokio::select! {
            biased;
            () = authority.cancelled() => Err(ApiError::new(ErrorCode::Unauthenticated, "request revoked while waiting for switch gate")),
            held = self.gate.switch() => Ok(held),
        }
    }

    pub(crate) async fn lock_deploy_authorized(
        &self,
        authority: &AuthLease,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, ApiError> {
        tokio::select! {
            biased;
            () = authority.cancelled() => Err(ApiError::new(ErrorCode::Unauthenticated, "Request revoked while waiting for the configuration lock")),
            held = self.deploy_lock.clone().lock_owned() => Ok(held),
        }
    }

    /// Admission for an exact non-log effect, never for a later unknown log record.
    pub async fn authorized_effect<T, F, Fut>(
        &self,
        authority: AuthLease,
        effect: F,
    ) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, ApiError>> + Send + 'static,
    {
        let slot = tokio::select! {
            biased;
            () = authority.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated, "Request revoked while waiting for side-effect capacity")),
            slot = self.effect_slots.clone().acquire_owned() => slot
                .map_err(|_| ApiError::new(ErrorCode::Unavailable, "Side-effect worker closed"))?,
        };
        let (send, receive) = oneshot::channel::<()>();
        let (done, result) = oneshot::channel();
        let retained = authority.clone();
        self.env.spawn("authorized-effect", async move {
            let _slot = slot;
            let _authority = retained;
            if receive.await.is_ok() {
                let _ = done.send(effect().await);
            }
        });
        let mut pending = Some(send);
        authority.admit(&mut || {
            pending
                .take()
                .ok_or_else(|| internal("Side effect admitted twice"))?
                .send(())
                .map_err(|_| ApiError::new(ErrorCode::Unavailable, "Side-effect worker stopped"))
        })?;
        if pending.is_some() {
            return Err(internal("Authority did not admit the side effect"));
        }
        result
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "Side-effect worker stopped"))?
    }

    pub(crate) fn deliver(
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
                origin: OperationOrigin::Internal,
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
                origin: OperationOrigin::Internal,
            },
        );
        rx
    }

    /// Appends records in order (sealed) and resolves once the last is
    /// applied; its LSN, 0 for none.
    // Unused since the single-record commit path settled; kept for the M23
    // track's batched writes.
    #[allow(dead_code)]
    pub(crate) async fn commit_all(&self, records: Vec<Record>) -> Result<Lsn, ApiError> {
        let mut sealed = Vec::with_capacity(records.len());
        for mut r in records {
            self.seal(&mut r)?;
            sealed.push(r);
        }
        let last = match self.log.append_all(sealed).await {
            Ok(last) => last.unwrap_or(0),
            Err(e) if e.is_refusal() => return Err(refused(&e)),
            Err(e) => {
                self.fatal.set(e.to_string());
                return Err(ApiError::new(ErrorCode::Unavailable, e.to_string()));
            }
        };
        tokio::select! {
            biased;
            () = self.store.applied.wait(last) => Ok(last),
            msg = self.fatal.wait() => Err(ApiError::new(ErrorCode::Unavailable, msg)),
        }
    }

    pub(crate) fn arc(&self) -> Option<Arc<Node>> {
        self.me()
    }

    /// Appends a record and resolves after its fsync (not its apply).
    pub(crate) async fn append(&self, mut record: Record) -> Result<Lsn, ApiError> {
        self.seal(&mut record)?;
        self.log.append(record).await.map_err(|e| {
            if e.is_refusal() {
                return refused(&e);
            }
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
        origin: OperationOrigin,
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
                origin,
            },
        );
        rx
    }

    async fn wait_root(
        &self,
        mut reply: oneshot::Receiver<Result<TurnResult, ApiError>>,
        root: &str,
        authority: AuthLease,
    ) -> Result<TurnResult, ApiError> {
        tokio::select! {
            biased;
            () = authority.cancelled() => {
                let mut removed = false;
                for slot in lock(&self.actors).values_mut() {
                    slot.queue.retain(|job| {
                        let matches = matches!(&job.input.kind, Some(pb::input::Kind::Message(message)) if message.message_id == root);
                        if matches && let Some(lsn) = job.resend_of() { lock(&self.resending).remove(&lsn); }
                        removed |= matches;
                        !matches
                    });
                }
                if removed {
                    return Err(ApiError::new(ErrorCode::Unauthenticated, "queued request revoked"));
                }
                // A worker already owns it; its final append either refuses or completes an admitted operation.
                reply.await.unwrap_or_else(|_| Err(ApiError::new(ErrorCode::Unavailable, "the turn was abandoned")))
            }
            result = &mut reply => result.unwrap_or_else(|_| Err(ApiError::new(ErrorCode::Unavailable, "the turn was abandoned"))),
        }
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

    /// How often retention compacted the index rows (tests, R2-cost).
    #[doc(hidden)]
    pub fn db_compactions(&self) -> u64 {
        self.db_compactions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The audit export's floor under retention, which the exporter sets.
    pub fn retention_hold(&self) -> &crate::snapshots::RetentionHold {
        &self.retention_hold
    }

    /// The free bytes of the log's file system (read every second), when
    /// `[log] disk_reserve` is set and a reading succeeded (`u64::MAX`
    /// stands for no reading yet).
    pub fn disk_free(&self) -> Option<u64> {
        self.measured_disk_free()
            .filter(|_| self.cfg.disk_reserve > 0)
    }

    /// The last reading of free disk, with or without a reserve: the audit
    /// hold's `hold_release` needs it either way.
    pub(crate) fn measured_disk_free(&self) -> Option<u64> {
        let free = self.disk_free.load(Ordering::Relaxed);
        (free != u64::MAX).then_some(free)
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
            let rx = self.start_root(
                actor,
                random_id(&self.env),
                input(http),
                subject,
                OperationOrigin::Internal,
            );
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
                    scrubbed_with: None,
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
        let rx = self.start_root(
            actor,
            random_id(&self.env),
            input(http),
            subject,
            OperationOrigin::Internal,
        );
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
        authority: AuthLease,
    ) -> Result<Option<TurnResult>, ApiError> {
        authority.check()?;
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
        let rx = self.start_root(
            actor,
            root.clone(),
            input,
            subject,
            OperationOrigin::Request(authority.clone()),
        );
        self.wait_root(rx, &root, authority).await.map(Some)
    }

    /// `kronik dead-letters resend`: the dead letter's message as a new root
    /// input; waits for the turn.
    pub async fn resend(
        &self,
        lsn: Lsn,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<Option<TurnResult>, ApiError> {
        authority.check()?;
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
        self.hold_resend().await;
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
        let rx = self.start_root(
            dl.actor,
            root.clone(),
            input,
            subject,
            OperationOrigin::Request(authority.clone()),
        );
        self.wait_root(rx, &root, authority).await.map(Some)
    }

    /// `kronik deploy` of a kind without history.
    pub async fn deploy(
        &self,
        bytes: &[u8],
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<DeployResult, ApiError> {
        authority.check()?;
        self.check_running()?;
        let guard = self.lock_deploy_authorized(&authority).await?;
        let (hash, program, manifest) = self.prepare_code(bytes, authority.clone()).await?;
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
        let gate = self.switch_authorized(&authority).await?;
        let lsn = self
            .finish_switch(
                guard,
                gate,
                Record::Deployment(record),
                vec![(version, program, hash)],
                epoch,
                false,
                OperationOrigin::Request(authority),
            )
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
        authority: AuthLease,
    ) -> Result<(CodeHash, Arc<Program>, pb::Manifest), ApiError> {
        authority.check()?;
        let code = self.code.clone();
        let bytes = bytes.to_vec();
        self.authorized_effect(authority, move || async move {
            let (hash, program) = code.add(&bytes).map_err(|e| match e {
                CodeError::ImportNotAllowed(bad) => ApiError::new(
                    ErrorCode::ImportNotAllowed,
                    format!("the component imports {}", bad.join(", ")),
                ),
                CodeError::Invalid(m) => ApiError::new(ErrorCode::BadRequest, m),
                other => internal(other),
            })?;
            let manifest = program.describe(TurnLimits::default()).await.map_err(|m| {
                ApiError::new(ErrorCode::TurnFailed, format!("describe failed: {m}"))
            })?;
            validate_manifest(&manifest)?;
            Ok((hash, program, manifest))
        })
        .await
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
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
        self.switch_code_impl(switch, audit, dry_run, OperationOrigin::Request(authority))
            .await
    }

    /// Configured Watch rollback only; ordinary requests cannot choose this host origin.
    pub async fn switch_code_from_guard(
        &self,
        mut switch: CodeSwitch,
        mut audit: pb::Audit,
    ) -> Result<(u64, Lsn), ApiError> {
        let reason = audit
            .reason
            .strip_prefix("watch ")
            .and_then(|reason| reason.split_once(": guard `"))
            .and_then(|(watch, rest)| rest.strip_suffix("` fired").map(|guard| (watch, guard)))
            .is_some_and(|(watch, guard)| !watch.is_empty() && !guard.is_empty());
        let exact_pins = switch.kinds.len() == switch.pinned.len()
            && switch.kinds.iter().enumerate().all(|(i, kind)| {
                !switch.kinds[..i]
                    .iter()
                    .any(|previous| previous.kind == kind.kind)
                    && switch
                        .pinned
                        .iter()
                        .filter(|pin| pin.kind == kind.kind)
                        .count()
                        == 1
            });
        if switch.cause != pb::DeploymentCause::Rollback
            || switch.rollback_of_epoch == 0
            || switch.kinds.is_empty()
            || !exact_pins
            || switch
                .pinned
                .iter()
                .any(|pin| CodeHash::from_slice(&pin.code_hash).is_none())
            || !switch.proposal_id.is_empty()
            || switch.verified_through_lsn != 0
            || switch.unverified_inputs != 0
            || !reason
        {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "invalid configured watch rollback",
            ));
        }
        // Audit fields are metadata, never the capability selecting this fixed host path.
        switch.cause = pb::DeploymentCause::Rollback;
        audit.token_id.clear();
        audit.token_id.push_str("kronik");
        self.switch_code_impl(switch, audit, false, OperationOrigin::Internal)
            .await
    }

    async fn switch_code_impl(
        &self,
        switch: CodeSwitch,
        audit: pb::Audit,
        dry_run: bool,
        origin: OperationOrigin,
    ) -> Result<(u64, Lsn), ApiError> {
        origin.check()?;
        // Promote and rollback: needed in an incident, also on a full disk.
        self.check_alive()?;
        let guard = match &origin {
            OperationOrigin::Internal => self.deploy_lock.clone().lock_owned().await,
            OperationOrigin::Request(authority) => self.lock_deploy_authorized(authority).await?,
        };
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
        let gate = match &origin {
            OperationOrigin::Internal => self.gate.switch().await,
            OperationOrigin::Request(authority) => self.switch_authorized(authority).await?,
        };
        let lsn = self
            .finish_switch(
                guard,
                gate,
                Record::Deployment(record),
                installs,
                epoch,
                true,
                origin,
            )
            .await?;
        tracing::info!(epoch, lsn, "switched code");
        Ok((epoch, lsn))
    }

    /// Writes an `Approval` record in this branch's log, its command
    /// scrubbed of stored secret values and tokens (review M5).
    pub async fn record_approval(
        &self,
        mut approval: pb::Approval,
        authority: AuthLease,
    ) -> Result<Lsn, ApiError> {
        authority.check()?;
        self.check_alive()?;
        let owner = approval
            .audit
            .as_ref()
            .map(|a| a.token_id.as_str())
            .unwrap_or_default();
        if !approval.request && owner.starts_with("oidc:") && approval.verified_identity.is_none() {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "OIDC approval requires protected historical identity",
            ));
        }
        if let Some(identity) = &approval.verified_identity {
            kronik_proto::validate_approval(&approval).map_err(|_| {
                ApiError::new(
                    ErrorCode::Unauthenticated,
                    "invalid protected approval identity",
                )
            })?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Identity {
                issuer: String,
                subject: String,
            }
            let opened = self.sealer().open(identity);
            let bytes = opened.bytes().ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unavailable,
                    "protected approval identity cannot be authenticated",
                )
            })?;
            let pair: Identity = serde_json::from_slice(bytes).map_err(|_| {
                ApiError::new(
                    ErrorCode::Unauthenticated,
                    "invalid protected approval identity",
                )
            })?;
            if pair.issuer.is_empty()
                || pair.issuer.len() > 1024
                || pair.issuer.chars().any(char::is_control)
                || pair.subject.is_empty()
                || pair.subject.len() > 255
                || pair.subject.chars().any(char::is_control)
            {
                return Err(ApiError::new(
                    ErrorCode::Unauthenticated,
                    "invalid protected approval identity",
                ));
            }
            let binding = self
                .sealer()
                .keyed_hash(
                    "kronik oidc binding v1",
                    &[pair.issuer.as_bytes(), pair.subject.as_bytes()],
                )
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::Unavailable,
                        "approval identity binding key is unavailable",
                    )
                })?;
            if owner.strip_prefix("oidc:") != Some(kronik_core::ids::hex(&binding).as_str()) {
                return Err(ApiError::new(
                    ErrorCode::Unauthenticated,
                    "protected approval identity does not match its audit principal",
                ));
            }
        }
        let secrets = self.secret_values().ok();
        let patterns = secrets
            .as_ref()
            .map(|values| crate::effects::secret_patterns(values));
        approval.command = crate::scrub::for_log(&approval.command, patterns.as_deref());
        self.commit_authorized(Record::Approval(approval), authority)
            .await
    }

    /// Writes a `GuardTriggered` record (`kronik watch`, M11) in this
    /// branch's log. Allowed below `[log] disk_reserve`: it records an
    /// incident (a rollback that already happened, or an alert).
    pub async fn record_guard(&self, mut guard: pb::GuardTriggered) -> Result<Lsn, ApiError> {
        self.check_alive()?;
        let audit = guard.audit.as_mut().ok_or_else(|| {
            ApiError::new(
                ErrorCode::BadRequest,
                "guard observation has no audit metadata",
            )
        })?;
        audit.token_id.clear();
        audit.token_id.push_str("kronik");
        self.commit(Record::GuardTriggered(guard)).await
    }

    /// Writes a canonically scrubbed `AuditEvent`, including mutation intents
    /// before effects. Allowed below the disk reserve; waits for apply.
    pub async fn record_system_audit_event(
        &self,
        origin: SystemAudit,
        target: &str,
        details: BTreeMap<String, String>,
        mut audit: pb::Audit,
        authority: AuthLease,
    ) -> Result<Lsn, ApiError> {
        authority.check()?;
        let (action, identity) = origin.identity();
        audit.token_id.clear();
        audit.token_id.push_str(identity);
        let record = self.audit_event_record(action, target, details, audit)?;
        self.commit_authorized(record, authority).await
    }

    pub async fn record_audit_event_authorized(
        &self,
        action: &str,
        target: &str,
        details: std::collections::BTreeMap<String, String>,
        audit: pb::Audit,
        authority: AuthLease,
    ) -> Result<Lsn, ApiError> {
        authority.check()?;
        let record = self
            .audit_event_record_waiting(action, target, details, audit)
            .await?;
        self.commit_authorized(record, authority).await
    }

    /// Builds an audit event after a bounded wait for a certified scrub
    /// inventory, scrubbing against the exact inventory it observed. The
    /// documented fail-closed windows close in milliseconds; on expiry the
    /// reason is withheld (never plaintext), which is the safe direction.
    pub(crate) async fn audit_event_record_waiting(
        &self,
        action: &str,
        target: &str,
        details: std::collections::BTreeMap<String, String>,
        audit: pb::Audit,
    ) -> Result<Record, ApiError> {
        if self.secret_runtime.is_none() {
            return self.audit_event_record(action, target, details, audit);
        }
        match self.wait_for_secret_values(false).await {
            Some(values) => {
                let patterns = crate::effects::secret_patterns(&values);
                self.audit_event_record_scrubbed(action, target, details, audit, Some(&patterns))
            }
            None => self.audit_event_record(action, target, details, audit),
        }
    }

    pub(crate) fn audit_event_record(
        &self,
        action: &str,
        target: &str,
        details: std::collections::BTreeMap<String, String>,
        audit: pb::Audit,
    ) -> Result<Record, ApiError> {
        let secrets = self.secret_values().ok();
        let patterns = secrets
            .as_ref()
            .map(|values| crate::effects::secret_patterns(values));
        self.audit_event_record_scrubbed(action, target, details, audit, patterns.as_deref())
    }

    /// Builds an audit event against a proven scrub inventory. Callers that
    /// await the inventory first use this so the reason is scrubbed against
    /// the exact inventory they observed: checking certification and then
    /// re-fetching it would race a retirement in between and withhold a
    /// reason that the inventory was available for.
    pub(crate) fn audit_event_record_scrubbed(
        &self,
        action: &str,
        target: &str,
        mut details: std::collections::BTreeMap<String, String>,
        mut audit: pb::Audit,
        patterns: Option<&crate::scrub::Secrets<'_>>,
    ) -> Result<Record, ApiError> {
        self.check_alive()?;
        if action == "audit.gap" && details.contains_key("namespace") {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "namespaced metadata coverage has a fixed original-execution producer",
            ));
        }
        let positions = crate::scrub::AuditPositions::parse(action, &details)
            .map_err(|message| ApiError::new(ErrorCode::BadRequest, message))?;
        audit.reason = crate::scrub::for_log(&audit.reason, patterns);
        let target = crate::scrub::for_target(target, patterns);
        // Detail keys whose value is operator free text: they carry the same
        // withholding contract as the reason. Every other detail field is
        // operator metadata (codes, names, identifiers, positions) and is
        // scrubbed against the inventory when it is available, left plain
        // when it is not — withholding a failure code would erase the very
        // fact the audit record exists to keep.
        const FREE_TEXT_DETAIL_KEYS: &[&str] = &["note"];
        for (field, value) in &mut details {
            if positions
                .and_then(|positions| positions.value(field))
                .is_none()
            {
                *value = if FREE_TEXT_DETAIL_KEYS.contains(&field.as_str()) {
                    crate::scrub::for_log(value, patterns)
                } else {
                    crate::scrub::for_target(value, patterns)
                };
            }
        }
        let event = pb::AuditEvent {
            action: action.to_owned(),
            target,
            details,
            audit: Some(audit),
            operation: None,
        };
        kronik_proto::control::validate_event(&event)
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        Ok(Record::AuditEvent(event))
    }

    /// Native committed control state; member control uses its actual metadata owner.
    pub fn control_operation(
        &self,
        kind: kronik_proto::control::ControlKind,
    ) -> Result<Option<(kronik_core::ids::SourcePos, pb::audit_event::Operation)>, ApiError> {
        self.local_operator_authority()?;
        self.check_alive()?;
        self.store
            .db()
            .control_state(kind)
            .map(|state| {
                state.map(|(lsn, operation)| {
                    (
                        kronik_core::ids::SourcePos::Actor { shard: None, lsn },
                        operation,
                    )
                })
            })
            .map_err(store_err)
    }

    /// Own this exact ordinary configuration mutation through real fsync and apply.
    pub async fn record_control_operation(
        &self,
        operation: pb::audit_event::Operation,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<Option<kronik_core::ids::SourcePos>, ApiError> {
        self.local_operator_authority()?;
        authority.check()?;
        if operation.kind().is_none() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "this control operation has a dedicated producer",
            ));
        }
        operation
            .validate()
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        if matches!(
            &operation,
            pb::audit_event::Operation::InstallationIdentity(_)
        ) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "installation identity has a fixed startup producer",
            ));
        }
        // The reason is scrubbed under the deploy lock below. A rebuild that
        // has retired the certificate is waited out first, with no lock held.
        self.wait_out_rebuild_window().await;
        let held = self.lock_deploy_authorized(&authority).await?;
        let node = self
            .arc()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let (done, result) = oneshot::channel();
        self.env().spawn("control-operation", async move {
            let _held = held;
            let outcome = async {
                authority.check()?;
                let previous = node.store.db().control_operation(&operation).map_err(store_err)?;
                operation.validate_transition(previous.as_ref())
                    .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()).with_hint("Read the current control configuration before submitting a new transition."))?;
                if dry_run { return Ok(None); }
                let record = node.control_audit_record(operation, audit)?;
                let lsn = node.commit_authorized(record, authority).await?;
                Ok(Some(kronik_core::ids::SourcePos::Actor { shard: None, lsn }))
            }.await;
            let _ = done.send(outcome);
        });
        result.await.map_err(|_| {
            ApiError::new(ErrorCode::Unavailable, "control operation worker stopped")
        })?
    }

    /// Only the original private browser-session capability can derive this tombstone.
    pub async fn record_auth_session_revoked(
        &self,
        audit: pb::Audit,
        dry_run: bool,
        session: kronik_core::authority::SessionLease,
    ) -> Result<Option<kronik_core::ids::SourcePos>, ApiError> {
        self.local_operator_authority()?;
        let revoked = session.revocation().clone();
        let authority: AuthLease = session;
        authority.check()?;
        self.check_alive()?;
        self.wait_out_rebuild_window().await;
        if !matches!(
            revoked.config_source,
            Some(pb::auth_session_revoked::ConfigSource::NativeLsn(_))
        ) {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "session revocation requires its metadata owner",
            ));
        }
        self.store
            .db()
            .validate_auth_session_revoked(&revoked)
            .map_err(store_err)?;
        if revoked.expires_at_ms <= self.env().clock.wall_ms() {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "the original browser session expired",
            ));
        }
        let record = self.control_audit_record(
            pb::audit_event::Operation::AuthSessionRevoked(revoked),
            audit,
        )?;
        if dry_run {
            authority.check()?;
            return Ok(None);
        }
        let lsn = self.commit_authorized(record, authority).await?;
        Ok(Some(kronik_core::ids::SourcePos::Actor {
            shard: None,
            lsn,
        }))
    }

    fn control_audit_record(
        &self,
        operation: pb::audit_event::Operation,
        mut audit: pb::Audit,
    ) -> Result<Record, ApiError> {
        self.check_alive()?;
        let secrets = self.secret_values().ok();
        let patterns = secrets
            .as_ref()
            .map(|values| crate::effects::secret_patterns(values));
        audit.reason = crate::scrub::for_log(&audit.reason, patterns.as_deref());
        let event = pb::AuditEvent {
            action: operation.action().into(),
            target: operation.target().into(),
            details: Default::default(),
            audit: Some(audit),
            operation: Some(operation),
        };
        kronik_proto::control::validate_event(&event)
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        Ok(Record::AuditEvent(event))
    }

    /// `kronik policy set`: a `Policy` record at the next epoch (the rules
    /// are validated by the caller). Returns (epoch, lsn); lsn is 0 for a
    /// dry run.
    pub async fn set_policy(
        &self,
        rules_toml: &str,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
        self.check_running()?;
        let guard = self.lock_deploy_authorized(&authority).await?;
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
        let lsn = self
            .commit_config_authorized(guard, epoch, record, authority)
            .await?;
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
                origin: OperationOrigin::Internal,
            },
        );
    }

    /// The configuration of the current epoch.
    /// The foreign actors' host (forks start copies through it, M14).
    pub fn foreign_host(&self) -> Option<Arc<dyn kronik_effects::foreign::ForeignHost>> {
        self.foreign.clone()
    }

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
        self.commit_config_origin(guard, epoch, record, OperationOrigin::Internal)
            .await
    }

    pub(crate) async fn commit_config_authorized(
        &self,
        guard: tokio::sync::OwnedMutexGuard<()>,
        epoch: u64,
        record: Record,
        authority: AuthLease,
    ) -> Result<Lsn, ApiError> {
        self.commit_config_origin(guard, epoch, record, OperationOrigin::Request(authority))
            .await
    }

    async fn commit_config_origin(
        &self,
        guard: tokio::sync::OwnedMutexGuard<()>,
        epoch: u64,
        record: Record,
        origin: OperationOrigin,
    ) -> Result<Lsn, ApiError> {
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let task = self.env.spawn("config", async move {
            node.commit_config_locked(&guard, epoch, record, origin)
                .await
        });
        task.await.unwrap_or_else(|| {
            Err(ApiError::new(
                ErrorCode::Unavailable,
                "the node is stopping",
            ))
        })
    }

    /// Applies one immutable configuration command while its caller retains
    /// the deploy lock, including an already-admitted reseal continuation.
    pub(crate) async fn commit_config_locked(
        &self,
        _guard: &tokio::sync::OwnedMutexGuard<()>,
        epoch: u64,
        record: Record,
        origin: OperationOrigin,
    ) -> Result<Lsn, ApiError> {
        let erasure = matches!(record, Record::Erasure(_));
        let privacy = matches!(record, Record::PrivacyMode(_));
        let mode_changed = matches!(
            &record,
            Record::PrivacyMode(mode) if mode.mode != self.privacy_mode().0 as i32
        );
        let _privacy_drain = if mode_changed {
            Some(match &origin {
                OperationOrigin::Internal => self.drain(Duration::from_secs(2)).await?,
                OperationOrigin::Request(authority) => tokio::select! {
                    biased;
                    () = authority.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated, "privacy request revoked while draining")),
                    drain = self.drain(Duration::from_secs(2)) => drain?,
                },
            })
        } else {
            None
        };
        let _privacy_gate = if mode_changed {
            Some(match &origin {
                OperationOrigin::Internal => self.gate.switch().await,
                OperationOrigin::Request(authority) => self.switch_authorized(authority).await?,
            })
        } else {
            None
        };
        let committed = self.commit_origin(record.clone(), origin).await;
        if committed.is_ok() {
            lock(&self.config).push(record);
            self.publish_secret_config_epoch(|| self.epoch.store(epoch, Ordering::Release));
        }
        if privacy {
            self.sealer
                .set_on(self.privacy_mode().0 == pb::PrivacyState::On);
        }
        let lsn = committed?;
        if erasure {
            self.after_erasure(lsn).await?;
        }
        drop(_privacy_gate);
        drop(_privacy_drain);
        self.recertify_cached_secret_inventory().await?;
        Ok(lsn)
    }

    /// `kronik grant`: writes a `Grant` record. Returns (epoch, lsn); lsn is 0
    /// for a dry run.
    // The public grant API mirrors the CLI and the wire record.
    #[allow(clippy::too_many_arguments)]
    pub async fn grant(
        &self,
        kind: &str,
        capability: &str,
        delivery: Option<Delivery>,
        rate: Option<Rate>,
        in_forks: kronik_effects::InForks,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
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
        let guard = self.lock_deploy_authorized(&authority).await?;
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
            // Explicit: an empty field is an older record and means compute.
            in_forks: in_forks.to_record(),
        });
        let lsn = self
            .commit_config_authorized(guard, epoch, record, authority)
            .await?;
        tracing::info!(kind, capability = %cap.render(), epoch, lsn, "granted");
        Ok((epoch, lsn))
    }

    /// `kronik stubs set`: writes a `SimulatorConfig` record for one target
    /// (docs/design/m12-simulators.md §2). Returns (epoch, lsn); lsn is 0
    /// for a dry run.
    pub async fn set_simulators(
        &self,
        mut record: pb::SimulatorConfig,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
        self.check_running()?;
        kronik_effects::simulator::check_config(&record)
            .map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let guard = self.lock_deploy_authorized(&authority).await?;
        let epoch = self.epoch() + 1;
        if dry_run {
            return Ok((epoch, 0));
        }
        record.epoch = epoch;
        record.audit = Some(audit);
        let target = record.target.clone();
        let lsn = self
            .commit_config_authorized(guard, epoch, Record::SimulatorConfig(record), authority)
            .await?;
        tracing::info!(target, epoch, lsn, "simulators set");
        Ok((epoch, lsn))
    }

    /// `kronik revoke`.
    pub async fn revoke(
        &self,
        kind: &str,
        capability: &str,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
        self.check_alive()?;
        let cap = Capability::parse(capability)
            .map(|c| c.render())
            .unwrap_or_else(|| capability.to_owned());
        let guard = self.lock_deploy_authorized(&authority).await?;
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
            in_forks: String::new(),
        });
        let lsn = self
            .commit_config_authorized(guard, epoch, record, authority)
            .await?;
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
        let secrets = self
            .native_recovery_authority()
            .ok()
            .and_then(|authority| self.foreign_secret_source(authority));
        host.reconcile(declared, secrets).await;
    }

    /// Where a foreign actor's start and `foreign add` get the value of a
    /// secret: the node's resolver, through the same cache as the effects
    /// of turns, with the configuration of the moment (m23 §6). `original`
    /// is the authority the resolver's provider I/O runs under: the node's
    /// own for the supervisor's starts, the caller's for an add. `None` on a
    /// node without a secret store.
    pub fn foreign_secret_source(
        &self,
        original: AuthLease,
    ) -> Option<kronik_effects::foreign::SecretSource> {
        self.secrets.as_ref()?;
        Some(Arc::new(crate::secrets::ForeignSecretSource {
            node: self.me.clone(),
            original,
        }))
    }

    /// `kronik foreign add`: writes a `ForeignActor` add record (the caller
    /// has validated and fetched the image), then starts the sandbox.
    /// Returns (epoch, lsn); lsn is 0 for a dry run.
    pub async fn foreign_add(
        &self,
        mut record: pb::ForeignActor,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
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
            let guard = self.lock_deploy_authorized(&authority).await?;
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
                .commit_config_authorized(guard, epoch, Record::ForeignActor(record), authority)
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
        authority: AuthLease,
    ) -> Result<(u64, Lsn), ApiError> {
        authority.check()?;
        self.check_alive()?;
        let (epoch, lsn) = {
            let guard = self.lock_deploy_authorized(&authority).await?;
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
            let lsn = self
                .commit_config_authorized(guard, epoch, record, authority)
                .await?;
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
        authority: AuthLease,
    ) -> Result<(u64, Lsn, KindLimits), ApiError> {
        authority.check()?;
        self.check_alive()?;
        if !kronik_core::ids::valid_kind(&limits.kind) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("{:?} is not a valid kind", limits.kind),
            ));
        }
        let guard = self.lock_deploy_authorized(&authority).await?;
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
        let lsn = self
            .commit_config_authorized(guard, epoch, record, authority)
            .await?;
        Ok((epoch, lsn, effective))
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

fn emit_logs<N: AsRef<str>, V: AsRef<[u8]>>(
    actor: &ActorRef,
    causal_id: &str,
    execution_id: &str,
    mut logs: Vec<LogEvent>,
    secrets: &[(N, V)],
) {
    use zeroize::Zeroize as _;
    if crate::scrub::logs(&mut logs, secrets).is_err() {
        for event in &mut logs {
            event.message.zeroize();
            for (name, value) in &mut event.fields {
                name.zeroize();
                value.zeroize();
            }
        }
        logs.clear();
        logs.push(LogEvent {
            level: "warn",
            message: crate::scrub::WITHHELD.into(),
            fields: Vec::new(),
        });
    }
    for event in logs {
        // All free fields are already prepared. Rendering does not rescan
        // generated markers or concatenate raw data before the bound check.
        let size = event
            .fields
            .iter()
            .map(|(name, value)| name.len() + value.len() + 2)
            .sum();
        let mut fields = String::with_capacity(size);
        for (index, (name, value)) in event.fields.iter().enumerate() {
            if index != 0 {
                fields.push(' ');
            }
            fields.push_str(name);
            fields.push('=');
            fields.push_str(value);
        }
        let message = event.message.trim_end();
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
        match event.level {
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
/// `Node::disk_free`, and says when it crosses `[log] disk_reserve`. While
/// the audit hold has given way, it runs retention, at most once a minute.
async fn disk_space_loop(node: Weak<Node>, dir: std::path::PathBuf) {
    const RETAIN_EVERY: Duration = Duration::from_secs(60);
    let mut low = false;
    let mut retained_at: Option<Duration> = None;
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
                let now = n.env.clock.monotonic();
                if retained_at.is_none_or(|t| now.saturating_sub(t) >= RETAIN_EVERY)
                    && n.retain_if_released(free).await
                {
                    retained_at = Some(now);
                }
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
    rebase: crate::rebase::RebaseCtx,
    mut rx: mpsc::UnboundedReceiver<Committed>,
    max: usize,
    fatal: Arc<Fatal>,
    runtime: Option<Arc<crate::secrets::SecretRuntime>>,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while batch.len() < max {
            match rx.try_recv() {
                Ok(c) => batch.push(c),
                Err(_) => break,
            }
        }
        let current = match &runtime {
            Some(runtime) => match runtime
                .begin_native_current_apply(&batch, &store, &rebase.reader)
                .await
            {
                Ok(current) => Some(current),
                // Availability-class publication failures are cache
                // maintenance, not durability: the records still apply, the
                // certified catalogue stays retired (reads stall fail-closed)
                // and the background rebuild retries. Corruption-class
                // failures stay fatal.
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::SecretUnavailable | ErrorCode::Unavailable
                    ) =>
                {
                    tracing::warn!(
                        lsn = batch[0].lsn,
                        error = %error.message,
                        "native-current prepare unavailable; applying without the certified capture and retrying the rebuild"
                    );
                    runtime.schedule_rebuild();
                    None
                }
                Err(error) => {
                    fatal.set(format!(
                        "preparing current secret data at lsn {}: {}",
                        batch[0].lsn, error.message
                    ));
                    return;
                }
            },
            None => None,
        };
        if let Err(e) = rebase.apply(&store, &batch).await {
            fatal.set(format!("applying lsn {}: {e}", batch[0].lsn));
            return;
        }
        // The cache is the applied projection: applied secret rows register
        // into it as they apply (the certification's registry is fed by the
        // applier, not by later store queries racing the applier's lag).
        if let Some(runtime) = &runtime {
            for committed in &batch {
                if let Record::SecretVersion(row) = &committed.record {
                    runtime.register_applied(row.clone());
                }
            }
        }
        let current_cut = current
            .as_ref()
            .and_then(|current| current.as_ref())
            .map_or(0, |current| current.cut());
        if let (Some(runtime), Some(Some(current))) = (&runtime, current)
            && let Err(error) = runtime.finish_native_current_apply(current, &store)
        {
            // Availability-class: as above — degrade to uncertified and let
            // the background rebuild retry; corruption-class stays fatal.
            if matches!(
                error.code,
                ErrorCode::SecretUnavailable | ErrorCode::Unavailable
            ) {
                tracing::warn!(
                    lsn = batch[0].lsn,
                    error = %error.message,
                    "native-current publish unavailable; abandoning the in-flight apply bookkeeping and retrying the rebuild"
                );
                runtime.abandon_in_flight_apply(current_cut);
                runtime.schedule_rebuild();
                continue;
            }
            fatal.set(format!(
                "publishing current secret data at lsn {}: {}",
                batch[0].lsn, error.message
            ));
            return;
        }
    }
}
