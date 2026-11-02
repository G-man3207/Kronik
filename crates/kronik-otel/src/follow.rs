//! Following the committed log for an export stream (m28-otel §3.6, §4.6,
//! ADR 0084): read records after the stream's cursor in batches, hand them
//! to a [`Sink`], and advance and save the cursor only once the sink
//! delivered them. At least once, in LSN order; off the turn path (an
//! `env.spawn` task of `kronik serve` that only reads).

use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use kronik_core::env::{Env, JoinHandle};
use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, ShardReader};

use crate::cursor::{Control, Cursors, Entry, Generation, Rewind};

/// What a sink did with a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Acknowledged: the cursor moves past the batch.
    Delivered,
    /// Refused for good (OTLP 400): the cursor moves past it, counted in
    /// `kronik_export_dropped_total`. `code` is shown in the status.
    Dropped { code: String },
    /// Not delivered: tried again after `after` (`Retry-After`) or the
    /// backoff, counted in `kronik_export_errors_total`.
    Retry {
        code: String,
        after: Option<Duration>,
    },
}

/// Where a stream's records go.
pub trait Sink: Send {
    /// What [`Sink::deliver`] sends, built once per batch and kept across
    /// retries, so `prepare` may move the sink's state forward.
    type Batch: Send + Sync + PartialEq;

    /// Builds the delivery for committed records, in LSN order. Never
    /// called with an empty batch. Failure must leave sink state unchanged;
    /// the follower retries without advancing its cursor.
    fn prepare(
        &mut self,
        records: &[(pb::ActorSource, Committed)],
        generation: Generation,
        reader: &ShardReader,
        snapshot: &CertifiedSecretSnapshot,
        original: AuthLease,
    ) -> impl Future<Output = Result<Self::Batch, String>> + Send;

    /// Sends a prepared batch; called again with the same batch on retry.
    fn deliver(
        &mut self,
        batch: &Self::Batch,
        original: AuthLease,
    ) -> impl Future<Output = Delivery> + Send;

    /// Stages durable resume metadata without publishing its cursor. A retry
    /// must keep the same candidate until publication succeeds.
    fn checkpoint(
        &mut self,
        _lsn: Lsn,
    ) -> impl Future<Output = Result<serde_json::Value, String>> + Send {
        async { Ok(serde_json::Value::Null) }
    }

    /// The manifest now durably selects the staged state and generation.
    fn committed(&mut self, _lsn: Lsn, _generation: Generation, _rewind_pending: bool) {}

    /// Retention deleted `from..=to` before the stream read it. Called
    /// before the next batch; the cursor moves past the gap only once this
    /// returns Ok. Err is a stable code for the status; the follower keeps
    /// the cursor before the gap and calls it again after a backoff.
    fn gap(
        &mut self,
        _from: Lsn,
        _to: Lsn,
        original: AuthLease,
    ) -> impl Future<Output = Result<(), String>> + Send {
        async move {
            original
                .check()
                .map_err(|error| error.code.as_str().to_owned())
        }
    }

    /// The stream has delivered everything applied: called before the
    /// follower waits for more and again when the wait ends, so that what
    /// a sink ages (the audit hold) does not age while nothing lags.
    fn caught_up(&mut self) {}

    /// The cursor moved back (or on) to `to` (`kronik export rewind`):
    /// called before the next batch, so that a sink's state is rebuilt as
    /// it was after `to`.
    fn rewind(
        &mut self,
        _to: Lsn,
        _generation: Generation,
        _reader: &ShardReader,
    ) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }
}

/// A stream's progress, as `kronik export status` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// The last LSN delivered.
    pub cursor: Lsn,
    pub last_success_wall_ms: Option<u64>,
    /// When the follower started: the stall's start before a first success.
    pub started_wall_ms: Option<u64>,
    /// The last failure's code (`http_503`, `connect`, ...), never its text,
    /// which can contain the URL.
    pub last_error: Option<String>,
    /// Ranges retention deleted before the stream read them.
    pub gaps: u64,
}

/// One export stream: its settings for the status, its progress, and the
/// rewind requests the follower picks up.
pub struct Stream {
    /// `traces` or `audit`: the cursor's name and the metrics' label.
    pub name: Arc<str>,
    pub enabled: bool,
    /// The sink's or endpoint's scheme and host only ([`crate::http::scheme_host`]).
    pub sink: String,
    progress: Mutex<Progress>,
    cursors: Arc<Cursors>,
    control: Arc<tokio::sync::Mutex<()>>,
    rewound: tokio::sync::Notify,
    audit: bool,
    stopping: AtomicBool,
    stopped: tokio::sync::Notify,
    tasks: Mutex<Vec<Arc<tokio::sync::Mutex<OwnedTask>>>>,
}

struct OwnedTask {
    handle: Option<JoinHandle<()>>,
    result: Option<Result<(), ApiError>>,
}

impl Stream {
    pub fn new(
        name: impl Into<Arc<str>>,
        enabled: bool,
        sink: String,
        cursor: Lsn,
        cursors: Arc<Cursors>,
    ) -> Arc<Stream> {
        Self::new_kind(name.into(), enabled, sink, cursor, cursors, false)
    }

    /// Audit streams explicitly participate in retention and rewind pinning.
    pub fn new_audit(
        name: impl Into<Arc<str>>,
        enabled: bool,
        sink: String,
        cursor: Lsn,
        cursors: Arc<Cursors>,
    ) -> Arc<Stream> {
        Self::new_kind(name.into(), enabled, sink, cursor, cursors, true)
    }

    fn new_kind(
        name: Arc<str>,
        enabled: bool,
        sink: String,
        cursor: Lsn,
        cursors: Arc<Cursors>,
        audit: bool,
    ) -> Arc<Stream> {
        Arc::new(Stream {
            name,
            enabled,
            sink,
            progress: Mutex::new(Progress {
                cursor,
                ..Progress::default()
            }),
            cursors,
            control: Arc::new(tokio::sync::Mutex::new(())),
            rewound: tokio::sync::Notify::new(),
            audit,
            stopping: AtomicBool::new(false),
            stopped: tokio::sync::Notify::new(),
            tasks: Mutex::new(Vec::new()),
        })
    }

    pub fn progress(&self) -> Progress {
        lock(&self.progress).clone()
    }

    pub fn is_audit(&self) -> bool {
        self.audit
    }

    pub fn is_for_cursors(&self, cursors: &Arc<Cursors>) -> bool {
        Arc::ptr_eq(&self.cursors, cursors)
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    pub async fn stopped(&self) {
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.is_stopping() {
            return;
        }
        stopped.await;
    }

    /// Register the actual worker or supervisor before publishing this stream.
    pub fn own_task(&self, handle: JoinHandle<()>) {
        lock(&self.tasks).push(Arc::new(tokio::sync::Mutex::new(OwnedTask {
            handle: Some(handle),
            result: None,
        })));
    }

    /// Concurrent or cancelled stop callers share the same real task completion.
    pub async fn stop_and_join(&self) -> Result<(), ApiError> {
        self.stopping.store(true, Ordering::Release);
        self.stopped.notify_waiters();
        let mut index = 0;
        let mut failure = None;
        loop {
            let task = lock(&self.tasks).get(index).cloned();
            let Some(task) = task else { break };
            let mut task = task.lock().await;
            if task.result.is_none() {
                let completed = match task.handle.as_mut() {
                    Some(handle) => handle.await.is_some(),
                    None => false,
                };
                let result = if completed {
                    Ok(())
                } else {
                    Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the export worker stopped without completing",
                    ))
                };
                task.handle = None;
                task.result = Some(result);
            }
            if let Some(Err(error)) = &task.result {
                failure.get_or_insert_with(|| error.clone());
            }
            index += 1;
        }
        drop(self.control.lock().await);
        failure.map_or(Ok(()), Err)
    }

    pub async fn control_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.control.lock().await
    }

    /// Pin and enable this before inspecting the corresponding durable control.
    pub fn control_notification(&self) -> tokio::sync::futures::Notified<'_> {
        self.rewound.notified()
    }

    /// Capture the real native cut before this control-only owned initialization.
    pub async fn initialize_native_cursor(
        self: &Arc<Self>,
        node: &Arc<Node>,
        candidate: Entry,
        original: AuthLease,
    ) -> Result<Entry, ApiError> {
        original.check()?;
        if self.is_stopping() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the export stream is stopping",
            ));
        }
        let reader = Arc::new(node.capture_system_export_reader().await?);
        let kronik_core::ids::SourcePos::Actor {
            shard: None,
            lsn: head,
        } = reader.point().source
        else {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "the native initializer captured a different source domain",
            ));
        };
        if candidate.lsn > head {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the initial cursor is ahead of its actual captured native source",
            ));
        }
        let held = tokio::select! {
            biased;
            () = self.stopped() => return Err(ApiError::new(ErrorCode::Unavailable, "the export stream is stopping")),
            () = original.cancelled() => {
                original.check()?;
                return Err(ApiError::new(ErrorCode::Unauthenticated, "initial export authority was revoked"));
            },
            held = self.control.clone().lock_owned() => held,
        };
        reader.check()?;
        let (stream, retained_reader, retained_original) =
            (self.clone(), reader.clone(), original.clone());
        let mut job = Some(async move {
            let (_control, _reader, _original) = (held, retained_reader, retained_original);
            if stream.is_stopping() {
                return Err(ApiError::new(
                    ErrorCode::Unavailable,
                    "the export stream is stopping",
                ));
            }
            // Do not replace a rewind or checkpoint published after the initial absence observation.
            if let Some(existing) = stream.cursors.get(stream.name.as_ref()) {
                return Ok(existing);
            }
            stream
                .cursors
                .save(stream.name.as_ref(), candidate)
                .await
                .map_err(|_| {
                    ApiError::new(
                        ErrorCode::Unavailable,
                        "the initial export cursor could not be made durable",
                    )
                })?;
            stream.cursors.get(stream.name.as_ref()).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Internal,
                    "the durable initial export cursor is missing",
                )
            })
        });
        let mut denial = Some(ApiError::new(
            ErrorCode::Unavailable,
            "the stream or captured source changed before initial cursor admission",
        ));
        let mut accepted = None;
        original.admit(&mut || {
            if self.is_stopping() || !reader.data_is_live_under_publication() {
                return Err(denial.take().unwrap_or_else(|| ApiError {
                    code: ErrorCode::Internal,
                    message: String::new(),
                    hint: None,
                }));
            }
            let job = job.take().ok_or_else(|| ApiError {
                code: ErrorCode::Internal,
                message: String::new(),
                hint: None,
            })?;
            accepted = Some(node.env().spawn("export-initialize", job));
            Ok(())
        })?;
        let saved = accepted
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Internal,
                    "initial cursor authority did not enqueue the operation",
                )
            })?
            .await
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unavailable,
                    "the initial export cursor task did not complete",
                )
            })??;
        self.update(|progress| progress.cursor = saved.lsn);
        Ok(saved)
    }

    /// Only the actual metadata caller supplies these coordinates and its original lease.
    pub async fn rewind_metadata(
        self: &Arc<Self>,
        env: &Env,
        to: u64,
        original: AuthLease,
    ) -> Result<Rewind, ApiError> {
        original.check()?;
        if self.is_stopping() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the export stream is stopping",
            ));
        }
        let held = tokio::select! {
            biased;
            () = self.stopped() => return Err(ApiError::new(ErrorCode::Unavailable, "the export stream is stopping")),
            () = original.cancelled() => {
                original.check()?;
                return Err(ApiError::new(ErrorCode::Unauthenticated, "metadata rewind authority was revoked"));
            },
            held = self.control.clone().lock_owned() => held,
        };
        let current = self.cursors.get(self.name.as_ref()).unwrap_or_default();
        let generation = loop {
            let generation = env.random_bytes();
            if generation != [0; 16]
                && generation != current.generation()
                && current
                    .pending_rewind()
                    .is_none_or(|rewind| rewind.generation != generation)
            {
                break generation;
            }
        };
        let (stream, retained) = (self.clone(), original.clone());
        let mut job = Some(async move {
            let (_control, _original) = (held, retained);
            if stream.is_stopping() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the export stream is stopping",
                ));
            }
            let rewind = stream
                .cursors
                .request_rewind(stream.name.as_ref(), generation, to)
                .await?;
            stream.rewound.notify_one();
            Ok(rewind)
        });
        let mut denial = Some(ApiError::new(
            ErrorCode::Unavailable,
            "the export stream stopped before metadata rewind admission",
        ));
        let mut accepted = None;
        original.admit(&mut || {
            if self.is_stopping() {
                return Err(denial.take().unwrap_or_else(|| ApiError {
                    code: ErrorCode::Internal,
                    message: String::new(),
                    hint: None,
                }));
            }
            let job = job.take().ok_or_else(|| ApiError {
                code: ErrorCode::Internal,
                message: String::new(),
                hint: None,
            })?;
            accepted = Some(env.spawn("export-rewind", job));
            Ok(())
        })?;
        accepted
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Internal,
                    "metadata rewind authority did not enqueue the operation",
                )
            })?
            .await
            .unwrap_or_else(|| Err(io::Error::other("metadata rewind task did not complete")))
            .map_err(|error| {
                if error.kind() == io::ErrorKind::InvalidInput {
                    ApiError::new(
                        ErrorCode::BadRequest,
                        "the rewind no longer matches the durable metadata cursor",
                    )
                } else {
                    ApiError::new(
                        ErrorCode::Unavailable,
                        "the metadata export rewind could not be made durable",
                    )
                }
            })
    }

    /// Durably requests a new replay generation before waking the follower.
    /// The owned task completes even if the operator stops waiting.
    pub async fn rewind(
        self: &Arc<Self>,
        node: &Arc<Node>,
        to: Lsn,
        original: AuthLease,
    ) -> Result<(), ApiError> {
        if self.is_stopping() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the export stream is stopping",
            ));
        }
        let held = tokio::select! {
            biased;
            () = original.cancelled() => {
                original.check()?;
                return Err(ApiError::new(ErrorCode::Unauthenticated, "the original rewind request was revoked"));
            },
            () = self.stopped() => return Err(ApiError::new(ErrorCode::Unavailable, "the export stream is stopping")),
            held = self.control.clone().lock_owned() => held,
        };
        original.check()?;
        let current = self.cursors.get(self.name.as_ref()).unwrap_or_default();
        let generation = loop {
            let generation = node.env().random_bytes();
            if generation != [0; 16]
                && generation != current.generation()
                && current
                    .pending_rewind()
                    .is_none_or(|r| r.generation != generation)
            {
                break generation;
            }
        };
        let (stream, worker) = (self.clone(), node.clone());
        let result = node
            .authorized_effect(original, move || async move {
                let _control = held;
                if stream.is_stopping() {
                    return Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the export stream is stopping",
                    ));
                }
                let audit = stream.is_audit();
                if audit {
                    worker
                        .retention_hold()
                        .rewind(generation, to, worker.env().clock.wall_ms());
                }
                let result = stream
                    .cursors
                    .request_rewind(stream.name.as_ref(), generation, to)
                    .await;
                match &result {
                    Ok(pending) => {
                        if audit {
                            worker.retention_hold().rewind(
                                pending.generation,
                                pending.to,
                                worker.env().clock.wall_ms(),
                            );
                        }
                        stream.rewound.notify_one();
                    }
                    Err(_) if audit => {
                        let saved = stream.cursors.get(stream.name.as_ref()).unwrap_or_default();
                        worker.retention_hold().restore_control(
                            generation,
                            saved.pending_rewind().map(|r| (r.generation, r.to)),
                            saved.lsn,
                            worker.env().clock.wall_ms(),
                        );
                    }
                    Err(_) => {}
                }
                Ok(result)
            })
            .await?;
        // The durable rewind is the admission's whole effect: its pending
        // generation stays in the cursor, so the caller only needs success.
        result.map(|_| ()).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidInput {
                ApiError::new(
                    ErrorCode::BadRequest,
                    "the rewind no longer matches the durable export cursor",
                )
            } else {
                ApiError::new(
                    ErrorCode::Unavailable,
                    "the export rewind could not be made durable",
                )
            }
        })
    }

    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut lock(&self.progress));
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

use kronik_core::{
    authority::{AuthLease, Authority},
    env::BoxFuture,
    error::{ApiError, ErrorCode},
};
use kronik_sched::secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication};

enum Projection {
    Checkpoint,
    Records(
        Arc<ShardReader>,
        Arc<CertifiedSecretSnapshot>,
        SecretSnapshotPublication,
    ),
    Metadata(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication),
    MetadataRecords(
        Arc<Stream>,
        Arc<CertifiedSecretSnapshot>,
        SecretSnapshotPublication,
    ),
}

pub struct RetainedDisclosure {
    original: AuthLease,
    projection: Projection,
    denial: Mutex<Option<ApiError>>,
}
impl RetainedDisclosure {
    /// The snapshot and publication come from ONE native_secret_snapshot_with_publication call.
    pub fn native(
        reader: Arc<ShardReader>,
        snapshot: Arc<CertifiedSecretSnapshot>,
        publication: SecretSnapshotPublication,
        original: AuthLease,
    ) -> AuthLease {
        Arc::new(Self {
            original,
            projection: Projection::Records(reader, snapshot, publication),
            denial: Mutex::new(Some(ApiError::new(
                ErrorCode::Unavailable,
                "the retained native secret snapshot changed before publication",
            ))),
        })
    }

    /// Retain the actual metadata producer's paired certificate, not metadata authority.
    pub fn metadata_response(
        snapshot: Arc<CertifiedSecretSnapshot>,
        publication: SecretSnapshotPublication,
        original: AuthLease,
    ) -> AuthLease {
        Arc::new(Self {
            original,
            projection: Projection::Metadata(snapshot, publication),
            denial: Mutex::new(Some(ApiError::new(
                ErrorCode::Unavailable,
                "the captured metadata response secret snapshot changed before publication",
            ))),
        })
    }

    /// Private configured lifecycle/control publication, not a disclosure escape.
    pub(crate) fn native_checkpoint(original: AuthLease) -> AuthLease {
        Arc::new(Self {
            original,
            projection: Projection::Checkpoint,
            denial: Mutex::new(Some(ApiError::new(
                ErrorCode::Unavailable,
                "the original native checkpoint admission is unavailable",
            ))),
        })
    }
}
/// The configured metadata worker keeps the same stream, paired DATA and original through EOF/cursor publication.
pub fn metadata_records(
    stream: &Arc<Stream>,
    snapshot: Arc<CertifiedSecretSnapshot>,
    publication: SecretSnapshotPublication,
    original: AuthLease,
) -> AuthLease {
    Arc::new(RetainedDisclosure {
        original,
        projection: Projection::MetadataRecords(stream.clone(), snapshot, publication),
        denial: Mutex::new(Some(ApiError::new(
            ErrorCode::Unavailable,
            "the retained metadata stream or secret snapshot changed before publication",
        ))),
    })
}

impl Authority for RetainedDisclosure {
    fn check(&self) -> Result<(), ApiError> {
        self.original.check()?;
        match &self.projection {
            Projection::Checkpoint => Ok(()),
            Projection::Records(reader, _snapshot, publication) => {
                reader.check()?;
                publication.check_current()
            }
            Projection::Metadata(_snapshot, publication) => publication.check_current(),
            Projection::MetadataRecords(stream, _snapshot, publication) => {
                if stream.is_stopping() {
                    return Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the metadata export stream is stopping",
                    ));
                }
                publication.check_current()
            }
        }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        match &self.projection {
            Projection::MetadataRecords(stream, ..) => {
                let stream = stream.clone();
                let original = self.original.clone();
                Box::pin(async move {
                    tokio::select! {
                    biased;
                    () = stream.stopped() => {}, () = original.cancelled() => {} }
                })
            }
            _ => self.original.cancelled(),
        }
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let mut denial = self
            .denial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unavailable,
                    "the retained disclosure admission is already in progress",
                )
            })?;
        let result = self.original.admit(&mut || match &self.projection {
            Projection::Checkpoint => effect(),
            Projection::Records(reader, _snapshot, publication) => {
                if !reader.data_is_live_under_publication() {
                    return Err(ApiError {
                        code: denial.code,
                        message: std::mem::take(&mut denial.message),
                        hint: denial.hint.take(),
                    });
                }
                publication.with_current_publication(&mut denial, &mut *effect)
            }
            Projection::Metadata(_snapshot, publication) => {
                publication.with_current_publication(&mut denial, &mut *effect)
            }
            Projection::MetadataRecords(stream, _snapshot, publication) => {
                let published = publication.with_current_publication(&mut denial, || {
                    if stream.is_stopping() {
                        return Ok(false);
                    }
                    effect()?;
                    Ok(true)
                })?;
                if published {
                    Ok(())
                } else {
                    Err(ApiError {
                        code: denial.code,
                        message: std::mem::take(&mut denial.message),
                        hint: denial.hint.take(),
                    })
                }
            }
        });
        *self
            .denial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(denial);
        result
    }
}

#[cfg(test)]
mod retained_file_tests {
    // The fixtures race real time and spawned tasks around admitted work:
    // the direct calls are the harness, not daemon paths.
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use kronik_core::env::Env;
    use kronik_proto::log::v1 as pb;
    use std::time::Duration;

    /// The node's detached initial secret refresh retires the certificate a
    /// publication taken before it settles fences on; wait until a fresh
    /// publication stays current across an idle window.
    async fn settled(node: &kronik_sched::Node) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok((_, publication)) = node.native_secret_snapshot_with_publication() {
                tokio::time::sleep(Duration::from_millis(5)).await;
                if publication.check_current().is_ok()
                    && publication.data_is_current_under_publication()
                {
                    return;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the initial secret refresh did not settle"
            );
        }
    }

    // Source fixture for the existing Root Node::secret_hmac(..., OriginalLAST)
    // immutable FILE port. No provider echo or general-resolver cache grants.
    #[tokio::test]
    async fn real_file_mac_uses_the_owned_guard_without_cache_reentrancy_or_cache_echo() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, data.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual native FILE MAC".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        };
        let key = b"actual-file-mac-key";
        let stored = node
            .secret_set(
                "m28-file-mac",
                key.to_vec(),
                &audit,
                false,
                original.clone(),
            )
            .await
            .unwrap()
            .unwrap();
        let identity = node
            .secret_identity(node.branch(), "m28-file-mac", stored.version)
            .await
            .unwrap();
        settled(&node).await;
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let held = Arc::downgrade(&snapshot);
        let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
        let guard = RetainedDisclosure::native(reader, snapshot, publication, original.clone());
        let owned = guard.clone();
        drop(guard);
        assert!(held.upgrade().is_some());
        let mac = tokio::time::timeout(
            Duration::from_secs(2),
            node.secret_hmac(node.branch(), &identity, b"message", owned.clone()),
        )
        .await
        .expect("a real FILE fetch and final MAC admission must not relock the held cache")
        .unwrap();
        let expected: [u8; 32] = kronik_effects::crypto::hmac_sha256(key, b"message")
            .try_into()
            .unwrap();
        assert_eq!(mac, expected);

        // Intentionally deny the actual immutable FILE version behind the
        // still-held cached needles. A second MAC must consult that real source,
        // never echo a success from its operational/scrub cache.
        let physical: u64 = identity.source_version.parse().unwrap();
        assert!(
            node.secrets()
                .unwrap()
                .delete("m28-file-mac", physical, node.env().clock.wall_ms())
                .unwrap()
                > 0
        );
        assert!(
            node.secrets()
                .unwrap()
                .version("m28-file-mac", physical)
                .unwrap()
                .is_none()
        );
        assert!(
            node.secrets()
                .unwrap()
                .values()
                .unwrap()
                .iter()
                .any(|(name, bytes)| name == "m28-file-mac" && bytes.as_slice() == key)
        );
        original.check().unwrap();
        // Current production certifies coverage only when every Active ledger
        // version still has its physical value: losing one retires the
        // certificate, and no MAC can be admitted through the stale guard.
        // The held cache is never an operational fallback for that denial.
        assert_eq!(
            owned.check().unwrap_err().code,
            ErrorCode::SecretUnavailable
        );
        assert!(node.native_secret_snapshot().is_err());
        assert!(
            node.refresh_secret_inventory(original.clone())
                .await
                .is_err()
        );
        let denied = tokio::time::timeout(
            Duration::from_secs(2),
            node.secret_hmac(node.branch(), &identity, b"message", owned.clone()),
        )
        .await
        .expect("FILE failure observation must not reenter the retained cache fence");
        assert_eq!(denied.unwrap_err().code, ErrorCode::SecretUnavailable);
        drop(owned);
        assert!(held.upgrade().is_none());
    }

    #[tokio::test]
    async fn metadata_projection_retains_the_same_certificate_without_granting_a_stale_publication()
    {
        // Exercise DATA retention with a genuine producer certificate, not a fabricated metadata source.
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            Env::real(tokio::runtime::Handle::current()),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual certificate data retention".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        };
        node.secret_set(
            "metadata-projection",
            b"first-certificate-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let held = Arc::downgrade(&snapshot);
        let guarded =
            RetainedDisclosure::metadata_response(snapshot, publication, original.clone());
        assert!(held.upgrade().is_some());
        guarded.check().unwrap();
        let mut published = 0;
        guarded
            .admit(&mut || {
                published += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(published, 1);
        node.secret_set(
            "metadata-projection",
            b"second-certificate-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        original.check().unwrap();
        assert!(guarded.check().is_err());
        assert!(
            guarded
                .admit(&mut || {
                    published += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(published, 1);
        assert!(held.upgrade().is_some());
        drop(guarded);
        assert!(held.upgrade().is_none());
    }

    #[tokio::test]
    async fn refreshed_same_facts_require_fresh_preparation_before_a_real_post() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, data.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "native output publication".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        };
        node.secret_set(
            "publication",
            b"wire-publication-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap();
        let render = |snapshot: &CertifiedSecretSnapshot| {
            bytes::Bytes::from(kronik_sched::scrub::for_log(
                "detail: wire-publication-needle",
                Some(&kronik_sched::effects::secret_patterns(&snapshot.values)),
            ))
        };
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let prepared = render(&snapshot);
        let fingerprint = snapshot.fingerprint;
        let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
        let stale = RetainedDisclosure::native(reader, snapshot, publication, original.clone());
        node.refresh_secret_inventory(original.clone())
            .await
            .unwrap();
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        assert_eq!(fingerprint, snapshot.fingerprint);
        // A retired certificate is a secret-source change, not a generic outage.
        assert_eq!(
            stale.check().unwrap_err().code,
            ErrorCode::SecretUnavailable
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/audit", listener.local_addr().unwrap());
        let blocked = tokio::time::timeout(
            Duration::from_secs(2),
            crate::http::post(
                &node,
                url.clone(),
                Vec::new(),
                "text/plain",
                prepared.clone(),
                stale,
            ),
        )
        .await
        .expect("a retired publication must refuse before external I/O");
        assert_eq!(blocked.err(), Some(ErrorCode::Unavailable.as_str()));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );

        let prepared_again = render(&snapshot);
        assert_eq!(prepared_again, prepared);
        let held = Arc::downgrade(&snapshot);
        let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
        let held_reader = Arc::downgrade(&reader);
        let retained = RetainedDisclosure::native(reader, snapshot, publication, original);
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let (headers_sent, headers_seen) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                let mut length = None;
                loop {
                    line.clear();
                    assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let mut received = vec![0; length.unwrap()];
                socket.read_exact(&mut received).await.unwrap();
                socket
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\nconnection: close\r\n\r\n")
                    .await
                    .unwrap();
                headers_sent.send(()).unwrap();
                released.await.unwrap();
                socket.get_mut().write_all(b"x").await.unwrap();
                received
            })
            .await
            .expect("the admitted exact request must finish")
        });
        let client_node = node.clone();
        let body = prepared_again.clone();
        let client = tokio::spawn(async move {
            crate::http::post(&client_node, url, Vec::new(), "text/plain", body, retained).await
        });
        tokio::time::timeout(Duration::from_secs(2), headers_seen)
            .await
            .unwrap()
            .unwrap();
        client.abort();
        let Err(error) = client.await else {
            panic!("the caller task must be cancelled");
        };
        assert!(error.is_cancelled());
        assert!(
            held.upgrade().is_some(),
            "the actual admitted job must own its snapshot through EOF"
        );
        assert!(
            held_reader.upgrade().is_some(),
            "the admitted job also owns the actual held source files through EOF"
        );
        release.send(()).unwrap();
        let received = server.await.unwrap();
        assert_eq!(received, prepared_again);
        assert!(
            !std::str::from_utf8(&received)
                .unwrap()
                .contains("wire-publication-needle")
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while held.upgrade().is_some() || held_reader.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finishing the owned response must release the retained snapshot");
        node.stop_native_execution().unwrap();
    }

    #[tokio::test]
    async fn a_fresh_certificate_cannot_authorize_an_old_readers_configuration_epoch() {
        let data = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            Env::real(tokio::runtime::Handle::current()),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual source configuration change".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        };
        node.secret_set(
            "reader-epoch",
            b"held-reader-epoch-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let stale = Arc::new(node.capture_system_export_reader().await.unwrap());
        let mode = if node.privacy_mode().0 == pb::PrivacyState::On {
            pb::PrivacyState::Off
        } else {
            pb::PrivacyState::On
        };
        assert!(
            node.set_privacy_mode(mode, audit, false, original.clone())
                .await
                .unwrap()
                .changed
        );
        node.refresh_secret_inventory(original.clone())
            .await
            .unwrap();
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        original.check().unwrap();
        publication.check_current().unwrap();
        assert!(!stale.data_is_live_under_publication());
        let guarded = RetainedDisclosure::native(stale, snapshot, publication, original.clone());
        let mut published = false;
        assert!(
            guarded
                .admit(&mut || {
                    published = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!published);
        let fresh = Arc::new(node.capture_system_export_reader().await.unwrap());
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let guarded = RetainedDisclosure::native(fresh, snapshot, publication, original);
        guarded
            .admit(&mut || {
                published = true;
                Ok(())
            })
            .unwrap();
        assert!(published);
    }

    #[tokio::test]
    async fn metadata_worker_guard_retains_exact_pair_and_refuses_post_stop_admission() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(
            env.clone(),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual metadata worker data retention".into(),
            wall_time_ms: env.clock.wall_ms(),
        };
        node.secret_set(
            "metadata-worker",
            b"actual-worker-held-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let held = Arc::downgrade(&snapshot);
        let cursors = Arc::new(Cursors::load(env, data.path()).await.unwrap());
        let stream = Stream::new(
            format!("events-{}:metadata", "actual-worker"),
            true,
            String::new(),
            0,
            cursors,
        );
        let guarded = metadata_records(&stream, snapshot, publication, original.clone());
        assert!(held.upgrade().is_some());
        let mut published = 0;
        guarded
            .admit(&mut || {
                published += 1;
                Ok(())
            })
            .unwrap();
        stream.stop_and_join().await.unwrap();
        original.check().unwrap();
        assert!(guarded.check().is_err());
        assert!(
            guarded
                .admit(&mut || {
                    published += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(published, 1);
        guarded.cancelled().await;
        assert!(held.upgrade().is_some());
        drop(guarded);
        assert!(held.upgrade().is_none());
    }

    #[tokio::test]
    async fn stopping_joins_the_real_owned_http_worker_through_held_response_eof() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(
            env.clone(),
            data.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual stopped worker EOF ownership".into(),
            wall_time_ms: env.clock.wall_ms(),
        };
        node.secret_set(
            "owned-eof",
            b"actual-eof-held-needle".to_vec(),
            &audit,
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
        let held = Arc::downgrade(&snapshot);
        let cursors = Arc::new(Cursors::load(env.clone(), data.path()).await.unwrap());
        let stream = Stream::new(
            format!("events-{}:metadata", "held-response"),
            true,
            String::new(),
            0,
            cursors,
        );
        let guard = metadata_records(&stream, snapshot, publication, original);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received, request_received) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(socket.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(body, b"actual transport data");
            socket
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            received.send(()).unwrap();
            released.await.unwrap();
            socket.get_mut().write_all(b"OK").await.unwrap();
            socket.get_mut().shutdown().await.unwrap();
        });
        let completed = Arc::new(AtomicBool::new(false));
        let done = completed.clone();
        stream.own_task(env.spawn("export-held-response-worker", async move {
            let response = crate::http::post(
                &node,
                format!("http://{address}/actual-transport"),
                Vec::new(),
                "application/octet-stream",
                bytes::Bytes::from_static(b"actual transport data"),
                guard,
            )
            .await
            .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body.as_ref(), b"OK");
            done.store(true, Ordering::SeqCst);
        }));
        request_received.await.unwrap();
        let stopped = stream.stop_and_join();
        tokio::pin!(stopped);
        tokio::select! {
            biased;
            result = stopped.as_mut() => panic!("stop detached an admitted real HTTP response before EOF: {result:?}"),
            () = stream.stopped() => {},
        }
        tokio::select! {
            biased;
            result = stopped.as_mut() => panic!("stop returned while the owned HTTP body was still held: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        assert!(!completed.load(Ordering::SeqCst));
        assert!(held.upgrade().is_some());
        release.send(()).unwrap();
        stopped.await.unwrap();
        server.await.unwrap();
        assert!(completed.load(Ordering::SeqCst));
        assert!(held.upgrade().is_none());
    }
}

/// Batching of a follower.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// At most this many records per batch.
    pub batch: u64,
    /// A smaller batch waits this long for more records.
    pub interval: Duration,
}

pub const FIRST_BACKOFF: Duration = Duration::from_secs(1);
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A `Retry-After` longer than this is cut to it.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);
/// At most this many encoded record bytes per batch (review M3): a
/// backlog of large turn records must not pile up in memory (a record can
/// be 128 MiB). A larger record goes alone.
pub const BATCH_BYTES: usize = 4 << 20;
/// An idle follower wakes at least this far apart.
const MIN_IDLE_TICK: Duration = Duration::from_millis(100);

/// Runs [`follow`] as a task of its own with the sink `make` builds from
/// the stream's saved state, and runs it again after it died (a panic, a
/// bug), after a backoff, from the saved cursor and state: no exporter
/// stays dead until a restart of the daemon (review Low).
///
/// shortcut: only the trace stream runs supervised; a dead audit export
/// keeps its retention hold, which `kronik doctor` shows as a stall, until
/// the daemon restarts. Supervise it too (rebuilding its sink) if one ever
/// dies in production.
pub async fn supervise<S, F, Fut>(
    node: Arc<Node>,
    stream: Arc<Stream>,
    opts: Options,
    mut make: F,
    original: AuthLease,
) where
    S: Sink + 'static,
    F: FnMut(Entry) -> Fut + Send,
    Fut: Future<Output = Result<S, String>> + Send,
{
    let env = node.env().clone();
    let cursors = stream.cursors.clone();
    let mut backoff = FIRST_BACKOFF;
    loop {
        if stream.is_stopping() || original.check().is_err() {
            return;
        }
        let saved = cursors.get(stream.name.as_ref()).unwrap_or_else(|| Entry {
            lsn: stream.progress().cursor,
            ..Entry::default()
        });
        stream.update(|p| p.cursor = saved.lsn);
        let stable = cursors.clone();
        let sink = match node
            .authorized_effect(original.clone(), move || async move {
                Ok(stable.stabilize().await)
            })
            .await
        {
            Ok(Ok(())) => make(saved).await,
            _ => Err("cursor_save".into()),
        };
        if stream.is_stopping() {
            return;
        }
        let sink = match sink {
            Ok(sink) => sink,
            Err(code) => {
                stream.update(|p| p.last_error = Some(code));
                kronik_metrics::inc(
                    "kronik_export_errors_total",
                    &[("stream", stream.name.as_ref())],
                );
                pause(&env, &stream, backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let task = env.spawn(
            "export-follow",
            follow(node.clone(), stream.clone(), opts, sink, original.clone()),
        );
        // Stop or original revocation completes normally; only a lost worker
        // receipt is restarted from the durable cursor.
        if task.await.is_some() {
            return;
        }
        tracing::error!(
            stream = stream.name.as_ref(),
            "export: the exporter task died; restarting it from the saved cursor"
        );
        kronik_metrics::inc(
            "kronik_export_errors_total",
            &[("stream", stream.name.as_ref())],
        );
        stream.update(|p| p.last_error = Some("panic".into()));
        pause(&env, &stream, backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Follows the configured native reader until stop or original revocation.
pub async fn follow<S: Sink + 'static>(
    node: Arc<Node>,
    stream: Arc<Stream>,
    opts: Options,
    sink: S,
    original: AuthLease,
) {
    let env = node.env().clone();
    // Owned checkpoint jobs retain their real sink state if the follower stops waiting.
    let sink = Arc::new(tokio::sync::Mutex::new(sink));
    let control = RetainedDisclosure::native_checkpoint(original.clone());
    let name = stream.name.as_ref();
    let labels = [("stream", name)];
    let batch = opts.batch.max(1);
    let mut entry = stream.cursors.get(name).unwrap_or_else(|| Entry {
        lsn: stream.progress().cursor,
        ..Entry::default()
    });
    let mut noticed = entry.lsn;
    let mut gap_backoff = FIRST_BACKOFF;
    let mut prepare_backoff = FIRST_BACKOFF;
    stream.update(|p| p.started_wall_ms = Some(env.clock.wall_ms()));
    let lag = |cursor: Lsn| {
        kronik_metrics::set(
            "kronik_export_lag_records",
            &labels,
            node.applied_lsn().saturating_sub(cursor) as f64,
        );
    };
    'records: loop {
        if stream.is_stopping() || original.check().is_err() {
            return;
        }
        if rewind_requested(&stream, entry.generation()) {
            // A management request cannot supersede the first generation
            // checkpoint while its manifest publication is being retried.
            let _control = tokio::select! {
                biased;
                () = stream.stopped() => return,
                control = stream.control.lock() => control,
            };
            let pending = stream.cursors.get(name).and_then(|e| e.pending_rewind());
            if let Some(pending) = pending.filter(|r| r.generation != entry.generation()) {
                let reader = match node.capture_system_export_reader().await {
                    Ok(reader) => reader,
                    Err(error) => {
                        failure(&stream, error.code.as_str().to_owned());
                        drop(_control);
                        pause(&env, &stream, prepare_backoff).await;
                        continue;
                    }
                };
                if let Err(code) = sink
                    .lock()
                    .await
                    .rewind(pending.to, pending.generation, &reader)
                    .await
                {
                    failure(&stream, code);
                    drop(_control);
                    pause(&env, &stream, prepare_backoff).await;
                    prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
                let candidate = Entry {
                    lsn: pending.to,
                    control: Some(Control::new(pending.generation)),
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &sink, candidate, control.clone()).await {
                    Ok(saved) => {
                        entry = saved;
                        noticed = entry.lsn;
                        prepare_backoff = FIRST_BACKOFF;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        drop(_control);
                        pause(&env, &stream, prepare_backoff).await;
                        prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                        continue;
                    }
                }
            }
        }
        let cursor = entry.lsn;
        let generation = entry.generation();
        if node.applied_lsn() <= cursor {
            sink.lock().await.caught_up();
            let tick = opts.interval.max(MIN_IDLE_TICK);
            tokio::select! {
                biased;
                () = stream.stopped() => return,
                () = stream.rewound.notified() => continue,
                woke = env.timeout(tick, node.store().applied.wait(cursor.saturating_add(1))) => {
                    if woke.is_err() {
                        continue;
                    }
                }
            }
            sink.lock().await.caught_up();
        }
        let end = cursor.saturating_add(batch);
        if node.applied_lsn() < end {
            tokio::select! {
                biased;
                () = stream.stopped() => return,
                () = stream.rewound.notified() => continue,
                _ = env.timeout(opts.interval, node.store().applied.wait(end)) => {}
            }
        }
        let gap = match gap_after(
            &node,
            &sink,
            &stream,
            cursor,
            &mut noticed,
            &mut gap_backoff,
            control.clone(),
        )
        .await
        {
            Ok(gap) => gap,
            Err(()) => continue,
        };
        if let Some(to) = gap {
            loop {
                if stream.is_stopping() {
                    return;
                }
                if rewind_requested(&stream, generation) {
                    continue 'records;
                }
                let candidate = Entry {
                    lsn: to,
                    control: entry.control,
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &sink, candidate, control.clone()).await {
                    Ok(saved) => {
                        entry = saved;
                        continue 'records;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        pause(&env, &stream, prepare_backoff).await;
                    }
                }
            }
        }
        let upto = node.applied_lsn().min(end);
        let (snapshot, publication) = match node.native_secret_snapshot_with_publication() {
            Ok(pair) => pair,
            Err(error) => {
                failure(&stream, error.code.as_str().to_owned());
                pause(&env, &stream, prepare_backoff).await;
                prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let reader = match node.capture_system_export_reader().await {
            Ok(reader) => Arc::new(reader),
            Err(error) => {
                failure(&stream, error.code.as_str().to_owned());
                pause(&env, &stream, prepare_backoff).await;
                continue;
            }
        };
        let page = match reader
            .local_export_page(
                cursor,
                usize::try_from(batch).unwrap_or(usize::MAX),
                BATCH_BYTES,
            )
            .await
        {
            Ok(page) => page,
            Err(error) => {
                failure(&stream, error.code.as_str().to_owned());
                pause(&env, &stream, MAX_BACKOFF).await;
                continue;
            }
        };
        let mut retained = RetainedDisclosure::native(
            reader.clone(),
            snapshot.clone(),
            publication,
            original.clone(),
        );
        let records = page.records;
        let Some(first) = records.first().map(|(_, record)| record.lsn) else {
            continue;
        };
        if first > cursor.saturating_add(1) {
            if !report_gap(
                &env,
                &sink,
                &stream,
                cursor.saturating_add(1),
                first - 1,
                &mut noticed,
                &mut gap_backoff,
                control.clone(),
            )
            .await
            {
                continue;
            }
            // Save the skipped range before preparing later records.
            loop {
                if stream.is_stopping() {
                    return;
                }
                if rewind_requested(&stream, generation) {
                    continue 'records;
                }
                let candidate = Entry {
                    lsn: first - 1,
                    control: entry.control,
                    ..Entry::default()
                };
                match checkpoint(&node, &stream, &sink, candidate, control.clone()).await {
                    Ok(saved) => {
                        entry = saved;
                        continue 'records;
                    }
                    Err(code) => {
                        failure(&stream, code);
                        pause(&env, &stream, prepare_backoff).await;
                    }
                }
            }
        }
        let upto = records.last().map_or(upto, |(_, record)| record.lsn);
        let count = records.len() as u64;
        let mut prepared = match sink
            .lock()
            .await
            .prepare(&records, generation, &reader, &snapshot, retained.clone())
            .await
        {
            Ok(batch) => {
                prepare_backoff = FIRST_BACKOFF;
                batch
            }
            Err(code) => {
                failure(&stream, code);
                lag(cursor);
                pause(&env, &stream, prepare_backoff).await;
                prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        drop(snapshot);
        let mut backoff = FIRST_BACKOFF;
        let mut disclosure_conflict = false;
        loop {
            if stream.is_stopping() {
                return;
            }
            if rewind_requested(&stream, generation) {
                continue 'records;
            }
            if disclosure_conflict {
                tokio::select! {
                    biased;
                    () = stream.stopped() => return,
                    () = original.cancelled() => return,
                    () = stream.rewound.notified() => continue,
                }
            }
            if retained.check().is_err() {
                if stream.is_stopping() || original.check().is_err() {
                    return;
                }
                let (refreshed, replacement) =
                    match reprepare(&node, &sink, &records, cursor, generation, original.clone())
                        .await
                    {
                        Ok(prepared) => prepared,
                        Err(code) => {
                            disclosure_conflict = code == "disclosure_conflict";
                            failure(&stream, code);
                            if !disclosure_conflict {
                                pause(&env, &stream, backoff).await;
                            }
                            continue;
                        }
                    };
                if refreshed != prepared {
                    failure(&stream, "disclosure_conflict".into());
                    disclosure_conflict = true;
                    continue;
                }
                prepared = refreshed;
                retained = replacement;
            }
            // Stop and rewind must not detach an already admitted owned send before its EOF.
            let delivery = sink.lock().await.deliver(&prepared, retained.clone()).await;
            if stream.is_stopping() {
                return;
            }
            match delivery {
                Delivery::Delivered => break,
                Delivery::Dropped { code } => {
                    tracing::warn!(
                        stream = name,
                        code,
                        from = cursor + 1,
                        upto,
                        "export: the sink refused a batch; skipped"
                    );
                    kronik_metrics::add("kronik_export_dropped_total", &labels, count);
                    stream.update(|p| p.last_error = Some(code));
                    break;
                }
                Delivery::Retry { code, after } => {
                    failure(&stream, code);
                    lag(cursor);
                    let wait = after.map_or(backoff, |a| a.min(MAX_RETRY_AFTER));
                    let asleep = env.clock.sleep(wait);
                    tokio::pin!(asleep);
                    loop {
                        if stream.is_stopping() {
                            return;
                        }
                        let _ = gap_after(
                            &node,
                            &sink,
                            &stream,
                            upto,
                            &mut noticed,
                            &mut gap_backoff,
                            control.clone(),
                        )
                        .await;
                        tokio::select! {
                                    biased;
                                    () = stream.stopped() => return,
                                    () = stream.rewound.notified() => {
                                        if stream.is_stopping() { return; }
                        if rewind_requested(&stream, generation) {
                                            continue 'records;
                                        }
                                    }
                                    () = &mut asleep => break,
                                    () = env.clock.sleep(FIRST_BACKOFF) => lag(cursor),
                                }
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        // A successful remote delivery is frozen while local persistence
        // retries: do not prepare/post a later batch or lose staged metadata.
        loop {
            if stream.is_stopping() {
                return;
            }
            if rewind_requested(&stream, generation) {
                continue 'records;
            }
            if disclosure_conflict {
                tokio::select! {
                    biased;
                    () = stream.stopped() => return,
                    () = original.cancelled() => return,
                    () = stream.rewound.notified() => continue,
                }
            }
            if retained.check().is_err() {
                if stream.is_stopping() || original.check().is_err() {
                    return;
                }
                let (refreshed, replacement) =
                    match reprepare(&node, &sink, &records, cursor, generation, original.clone())
                        .await
                    {
                        Ok(prepared) => prepared,
                        Err(code) => {
                            disclosure_conflict = code == "disclosure_conflict";
                            failure(&stream, code);
                            if !disclosure_conflict {
                                pause(&env, &stream, prepare_backoff).await;
                            }
                            continue;
                        }
                    };
                if refreshed != prepared {
                    failure(&stream, "disclosure_conflict".into());
                    disclosure_conflict = true;
                    continue;
                }
                prepared = refreshed;
                retained = replacement;
            }
            let candidate = Entry {
                lsn: upto,
                control: entry.control,
                ..Entry::default()
            };
            match checkpoint(&node, &stream, &sink, candidate, retained.clone()).await {
                Ok(saved) => {
                    entry = saved;
                    break;
                }
                Err(code) => {
                    failure(&stream, code);
                    pause(&env, &stream, prepare_backoff).await;
                    prepare_backoff = (prepare_backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        kronik_metrics::add("kronik_export_records_total", &labels, count);
        lag(entry.lsn);
    }
}

/// Retention deleted `from..=to` before the stream read it: logged, handed
/// to the sink and, once the sink recorded it, counted. False after a
/// failed record, once the backoff passed: the caller keeps its cursor
/// before the gap and tries again, so a restart still sees the gap.
// One sink-gap report's plumbing: env, sink, stream and cursors.
#[allow(clippy::too_many_arguments)]
async fn report_gap<S: Sink>(
    env: &Env,
    sink: &Arc<tokio::sync::Mutex<S>>,
    stream: &Stream,
    from: Lsn,
    to: Lsn,
    noticed: &mut Lsn,
    backoff: &mut Duration,
    original: AuthLease,
) -> bool {
    let from = from.max(noticed.saturating_add(1));
    if from > to {
        return true;
    }
    tracing::warn!(
        stream = stream.name.as_ref(),
        from,
        to,
        "export: retention deleted records before they were exported"
    );
    let labels = [("stream", stream.name.as_ref())];
    if let Err(code) = sink.lock().await.gap(from, to, original).await {
        tracing::warn!(
            stream = stream.name.as_ref(),
            code,
            from,
            to,
            "export: recording a gap failed; retrying"
        );
        kronik_metrics::inc("kronik_export_errors_total", &labels);
        stream.update(|p| p.last_error = Some(code));
        pause(env, stream, *backoff).await;
        *backoff = (*backoff * 2).min(MAX_BACKOFF);
        return false;
    }
    *backoff = FIRST_BACKOFF;
    *noticed = to;
    kronik_metrics::inc("kronik_export_gaps_total", &labels);
    stream.update(|p| p.gaps += 1);
    true
}

fn rewind_requested(stream: &Stream, generation: Generation) -> bool {
    stream
        .cursors
        .get(stream.name.as_ref())
        .and_then(|e| e.pending_rewind())
        .is_some_and(|r| r.generation != generation)
}

fn failure(stream: &Stream, code: String) {
    tracing::warn!(
        stream = stream.name.as_ref(),
        code,
        "export failed; retrying"
    );
    kronik_metrics::inc(
        "kronik_export_errors_total",
        &[("stream", stream.name.as_ref())],
    );
    stream.update(|p| p.last_error = Some(code));
}

async fn pause(env: &Env, stream: &Stream, duration: Duration) {
    tokio::select! {
        biased;
        () = stream.stopped() => {}
        () = stream.rewound.notified() => {}
        () = env.clock.sleep(duration) => {}
    }
}

async fn gap_after<S: Sink>(
    node: &Node,
    sink: &Arc<tokio::sync::Mutex<S>>,
    stream: &Stream,
    after: Lsn,
    noticed: &mut Lsn,
    backoff: &mut Duration,
    original: AuthLease,
) -> Result<Option<Lsn>, ()> {
    let first = match node.reader().starts().await {
        Ok(starts) => starts.first().copied(),
        Err(_) => {
            failure(stream, "log_read".into());
            pause(node.env(), stream, *backoff).await;
            return Err(());
        }
    };
    let Some(first) = first.filter(|first| *first > after.saturating_add(1)) else {
        return Ok(None);
    };
    if report_gap(
        node.env(),
        sink,
        stream,
        after.saturating_add(1),
        first - 1,
        noticed,
        backoff,
        original,
    )
    .await
    {
        Ok(Some(first - 1))
    } else {
        Err(())
    }
}

async fn reprepare<S: Sink>(
    node: &Arc<Node>,
    sink: &Arc<tokio::sync::Mutex<S>>,
    records: &[(pb::ActorSource, Committed)],
    cursor: Lsn,
    generation: Generation,
    original: AuthLease,
) -> Result<(S::Batch, AuthLease), String> {
    original
        .check()
        .map_err(|error| error.code.as_str().to_owned())?;
    let through = records
        .last()
        .ok_or_else(|| "STORAGE_CORRUPT".to_owned())?
        .1
        .lsn;
    let (snapshot, publication) = node
        .native_secret_snapshot_with_publication()
        .map_err(|error| error.code.as_str().to_owned())?;
    let reader = Arc::new(
        node.capture_system_export_reader()
            .await
            .map_err(|error| error.code.as_str().to_owned())?,
    );
    let page = reader
        .local_export_page(cursor, records.len(), BATCH_BYTES)
        .await
        .map_err(|error| error.code.as_str().to_owned())?;
    if page.retention_gap.is_some()
        || page.scanned_through != through
        || page.records.len() != records.len()
        || page
            .records
            .first()
            .is_none_or(|(_, record)| record.lsn != cursor.saturating_add(1))
    {
        return Err("disclosure_conflict".into());
    }
    let retained =
        RetainedDisclosure::native(reader.clone(), snapshot.clone(), publication, original);
    retained
        .check()
        .map_err(|error| error.code.as_str().to_owned())?;
    let mut sink = sink.lock().await;
    sink.rewind(cursor, generation, &reader).await?;
    let prepared = sink
        .prepare(
            &page.records,
            generation,
            &reader,
            &snapshot,
            retained.clone(),
        )
        .await?;
    Ok((prepared, retained))
}

async fn checkpoint<S: Sink + 'static>(
    node: &Node,
    stream: &Stream,
    sink: &Arc<tokio::sync::Mutex<S>>,
    mut entry: Entry,
    original: AuthLease,
) -> Result<Entry, String> {
    let owned_sink = sink.clone();
    let lsn = entry.lsn;
    entry.state = node
        .authorized_effect(original.clone(), move || async move {
            Ok(owned_sink.lock().await.checkpoint(lsn).await)
        })
        .await
        .map_err(|error| error.code.as_str().to_owned())??;
    let mut backoff = FIRST_BACKOFF;
    loop {
        if stream.is_stopping() {
            return Err("export_stopping".into());
        }
        let cursors = stream.cursors.clone();
        let candidate = entry.clone();
        let name = stream.name.clone();
        let saved = node
            .authorized_effect(original.clone(), move || async move {
                Ok(cursors.advance(name.as_ref(), candidate).await)
            })
            .await;
        match saved {
            Ok(Ok(saved)) => {
                sink.lock().await.committed(
                    saved.lsn,
                    saved.generation(),
                    saved.pending_rewind().is_some(),
                );
                stream.update(|p| {
                    p.cursor = saved.lsn;
                    p.last_success_wall_ms = Some(node.env().clock.wall_ms());
                });
                return Ok(saved);
            }
            Err(error) if original.check().is_err() => return Err(error.code.as_str().to_owned()),
            _ => {
                failure(stream, "cursor_save".into());
                pause(node.env(), stream, backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
