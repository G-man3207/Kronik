//! Snapshots of a node's state (docs/design/m6-storage.md §2-§3): taking
//! them (on a schedule, at shutdown, on demand), listing and pruning them,
//! and choosing state at startup when `state.db` is missing or behind the
//! log.

use kronik_core::authority::AuthLease;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use serde::{Deserialize, Serialize};

use crate::node::Node;

/// Where and how often a node keeps snapshots (`[retention]`).
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    /// `retention.snapshot_interval` (default 60 min).
    pub snapshot_interval: Duration,
    /// `retention.snapshots_kept` (default 48).
    pub snapshots_kept: usize,
    /// `retention.history` (default 7 d).
    pub history: Duration,
}

impl StorageConfig {
    pub fn new(data_dir: PathBuf) -> StorageConfig {
        StorageConfig {
            data_dir,
            snapshot_interval: Duration::from_secs(3600),
            snapshots_kept: 48,
            history: Duration::from_secs(7 * 86_400),
        }
    }
}

/// The audit export's floor under retention (ADR 0084, review H2). While
/// set, [`Node::compact`] keeps every segment that holds a record past the
/// floor, unless free disk is below `release_below` (before the disk
/// reserve refuses work: the node never waits on a sink) or the floor has
/// not been refreshed for `max_hold`. Then retention deletes as before, and
/// the exporter records the gap.
#[derive(Debug)]
pub struct RetentionHold {
    /// Records after this LSN are held; `u64::MAX`: no hold.
    floor: AtomicU64,
    /// Wall time of the last [`RetentionHold::set`].
    set_ms: AtomicU64,
    /// The latest pending generation and earliest requested cut. The lock
    /// orders rewind requests against durable completion and floor updates.
    rewind: std::sync::Mutex<Option<([u8; 16], Lsn)>>,
    release_below: AtomicU64,
    /// 0: no time cap.
    max_hold_ms: AtomicU64,
}

impl Default for RetentionHold {
    fn default() -> Self {
        RetentionHold {
            floor: AtomicU64::new(u64::MAX),
            set_ms: AtomicU64::new(0),
            rewind: std::sync::Mutex::new(None),
            release_below: AtomicU64::new(0),
            max_hold_ms: AtomicU64::new(0),
        }
    }
}

impl RetentionHold {
    /// `[audit] hold_release` (free bytes) and `max_hold` (zero: none).
    pub fn configure(&self, release_below: u64, max_hold: Duration) {
        self.release_below.store(release_below, Ordering::Relaxed);
        self.max_hold_ms
            .store(max_hold.as_millis() as u64, Ordering::Relaxed);
    }

    /// Refreshes the durable floor without completing any pending rewind.
    pub fn set(&self, floor: Lsn, now_ms: u64) {
        let rewind = self.rewind.lock().unwrap_or_else(|e| e.into_inner());
        let floor = rewind.map_or(floor, |(_, to)| floor.min(to));
        self.floor.store(floor, Ordering::Relaxed);
        self.set_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Holds the earliest cut until the latest generation durably completes.
    pub fn rewind(&self, generation: [u8; 16], to: Lsn, now_ms: u64) {
        let mut rewind = self.rewind.lock().unwrap_or_else(|e| e.into_inner());
        let to = rewind.map_or(to, |(_, cut)| cut.min(to));
        *rewind = Some((generation, to));
        self.floor.fetch_min(to, Ordering::Relaxed);
        self.set_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Only a durable completion of the current generation releases its cut.
    pub fn complete_rewind(&self, generation: [u8; 16], floor: Lsn, now_ms: u64) {
        let mut rewind = self.rewind.lock().unwrap_or_else(|e| e.into_inner());
        if rewind.is_some_and(|(pending, _)| pending == generation) {
            *rewind = None;
        }
        let floor = rewind.map_or(floor, |(_, to)| floor.min(to));
        self.floor.store(floor, Ordering::Relaxed);
        self.set_ms.store(now_ms, Ordering::Relaxed);
    }

    /// Rolls back only the failed request, using the current durable control.
    pub fn restore_control(
        &self,
        failed_generation: [u8; 16],
        pending: Option<([u8; 16], Lsn)>,
        durable_floor: Lsn,
        now_ms: u64,
    ) {
        let mut rewind = self.rewind.lock().unwrap_or_else(|e| e.into_inner());
        if !rewind.is_some_and(|(generation, _)| generation == failed_generation) {
            return;
        }
        *rewind = pending;
        self.floor.store(
            pending.map_or(durable_floor, |(_, to)| durable_floor.min(to)),
            Ordering::Relaxed,
        );
        self.set_ms.store(now_ms, Ordering::Relaxed);
    }

    /// The floor, when held.
    pub fn floor(&self) -> Option<Lsn> {
        let f = self.floor.load(Ordering::Relaxed);
        (f != u64::MAX).then_some(f)
    }

    /// How long the floor has not been refreshed, when held.
    pub fn age_ms(&self, now_ms: u64) -> Option<u64> {
        self.floor()
            .map(|_| now_ms.saturating_sub(self.set_ms.load(Ordering::Relaxed)))
    }

    /// Whether retention ignores the hold: free disk (when measured) is
    /// below `release_below`, or the hold is older than `max_hold`.
    fn released(&self, disk_free: Option<u64>, now_ms: u64) -> bool {
        let max = self.max_hold_ms.load(Ordering::Relaxed);
        disk_free.is_some_and(|free| free < self.release_below.load(Ordering::Relaxed))
            || (max > 0 && self.age_ms(now_ms).is_some_and(|age| age > max))
    }
}

/// Logical-time cutoff: `history` back from the newest record's logical time
/// (m6-storage §5). A fork point is outside the window when its turn's
/// logical time is strictly less than this.
pub fn history_cutoff(time_hwm: u64, history: Duration) -> u64 {
    time_hwm.saturating_sub(history.as_millis() as u64)
}

/// One file of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

/// `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub id: String,
    pub branch: String,
    pub lsn: Lsn,
    pub engine_version: String,
    pub created_wall_ms: u64,
    pub logical_time_ms: u64,
    /// Segments holding LSNs after `lsn` when the snapshot was taken.
    pub segments: Vec<String>,
    pub files: Vec<SnapshotFile>,
    pub state_hash: String,
    /// Why it was taken: `interval`, `shutdown`, `manual`.
    pub reason: String,
}

impl Manifest {
    pub fn bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

/// Actor databases raised under one hold of the apply lock by
/// [`Node::compact`]: turns wait for a batch, never for a whole pass.
const IDLE_RAISE_BATCH: usize = 64;

// Test hooks for the order of a compaction pass: the pass ends with an error
// as a crash would, after the raise before any delete, or after a delete.
#[cfg(test)]
thread_local! {
    static CRASH_AFTER_RAISE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CRASH_AFTER_DELETE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn snapshots_dir(data: &Path, branch: &str) -> PathBuf {
    data.join("snapshots").join(branch)
}

fn dir_name(lsn: Lsn) -> String {
    format!("{lsn:020}")
}

/// The branch's complete snapshots (those with a manifest), oldest first.
pub fn list(data: &Path, branch: &str) -> Vec<(PathBuf, Manifest)> {
    let root = snapshots_dir(data, branch);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, Manifest)> = entries
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|e| {
            let bytes = std::fs::read(e.path().join("manifest.json")).ok()?;
            let m: Manifest = serde_json::from_slice(&bytes).ok()?;
            Some((e.path(), m))
        })
        .collect();
    out.sort_by_key(|(_, m)| m.lsn);
    out
}

/// Deletes what an interrupted or failed snapshot left in `root`: `.tmp-*`
/// copies, and snapshot directories (`<lsn>`, 20 digits) without their
/// manifest, which `list` never sees. Called with the snapshot lock held,
/// or before the node runs.
pub fn sweep_partial(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let partial = name.starts_with(".tmp-")
            || (name.len() == 20
                && name.bytes().all(|b| b.is_ascii_digit())
                && !e.path().join("manifest.json").exists());
        if !partial {
            continue;
        }
        let path = e.path();
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => tracing::info!(path = %path.display(), "deleted a partial snapshot"),
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "could not delete a partial snapshot")
            }
        }
    }
}

fn io_err(what: &str, e: std::io::Error) -> ApiError {
    ApiError::new(ErrorCode::Internal, format!("{what}: {e}"))
}

fn hash_file(path: &Path) -> std::io::Result<(u64, String)> {
    let bytes = std::fs::read(path)?;
    Ok((
        bytes.len() as u64,
        blake3::hash(&bytes).to_hex().to_string(),
    ))
}

/// Writes `path` durably: a temporary file, fsynced, renamed into place,
/// and the directory fsynced.
pub fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent()
        && let Ok(d) = std::fs::File::open(parent)
    {
        d.sync_all()?;
    }
    Ok(())
}

/// What [`prepare_state`] decides, without doing it.
#[derive(Debug)]
pub struct StatePlan {
    /// The snapshot to install, when the branch's databases are behind the
    /// first LSN the log still holds (or there is no `state.db`).
    pub install: Option<(PathBuf, Manifest)>,
    /// `state.db`'s applied LSN and the lowest applied LSN of it and the
    /// actor databases, when there is a `state.db`. The start refuses to
    /// replay from the lowest one when the log no longer reaches it.
    pub state: Option<(Lsn, Lsn)>,
    /// Actor databases a read-only plan could not read. Always 0 on a plan
    /// that is returned: a non-zero count is an error, so the check does not
    /// pass while the start's question is unanswered. Always 0 for the plan
    /// the start makes.
    pub unread: usize,
}

/// Whether the databases of `branch` are behind the log, and the snapshot
/// that repairs it. The start refuses to replay from a point the log no
/// longer holds (`Node::start`, from [`kronik_store::Store::replay_from`]:
/// the lowest applied LSN of `state.db` and of every actor database), so
/// this asks the same question before the store opens. `read_only` is for
/// `kronik upgrade check`, which may run beside a daemon and so must neither
/// wait for the databases it holds nor write them. A held database's applied
/// LSN is read from a private copy. One that still cannot be read makes the
/// question unanswerable: this returns an error rather than a pass.
///
/// An error is a start that cannot succeed, or a check that cannot tell:
/// the log starts after what the databases hold and no snapshot reaches it,
/// or an actor database the check needed could not be read.
pub fn plan_state(data: &Path, branch: &str, read_only: bool) -> Result<StatePlan, String> {
    let branch_dir = data.join("branches").join(branch);
    let starts = kronik_log::segment_starts(&branch_dir.join("log")).map_err(|e| e.to_string())?;
    let log_first = starts.first().copied();
    let markers = kronik_store::snapshot::read_markers(&branch_dir, read_only, log_first)
        .map_err(|e| e.to_string())?;
    let behind = match markers {
        Some(m) => log_first.is_some_and(|f| m.lowest + 1 < f),
        // A fresh node (no log either) needs nothing.
        None => log_first.is_some_and(|f| f > 1) || !list(data, branch).is_empty(),
    };
    let state = markers.map(|m| (m.state, m.lowest));
    let unread = markers.map_or(0, |m| m.unread);
    // An unread database is left out of `lowest`. Passing would tell the
    // operator the start can proceed when that database may be the one the
    // start refuses. The same rule applies when a snapshot would repair a
    // gap the check has not actually seen.
    if read_only && unread > 0 {
        return Err(unread_actor_databases(unread));
    }
    if !behind {
        return Ok(StatePlan {
            install: None,
            state,
            unread,
        });
    }
    let usable = list(data, branch)
        .into_iter()
        .rev()
        .find(|(_, m)| log_first.is_none_or(|f| m.lsn + 1 >= f));
    let Some(found) = usable else {
        let first = log_first.unwrap_or(1);
        return Err(match state {
            Some((_, lowest)) => format!(
                "state is at lsn {lowest}, but the log starts at {first} (compacted) and no \
                 snapshot reaches it; restore one (kronik restore --from ...)"
            ),
            None => format!(
                "the log starts at LSN {first} and no snapshot reaches it; restore one \
                 (kronik restore --from ...)"
            ),
        });
    };
    Ok(StatePlan {
        install: Some(found),
        state,
        unread,
    })
}

/// Why a read-only plan cannot answer the start's question.
fn unread_actor_databases(unread: usize) -> String {
    let (subject, reaches) = if unread == 1 {
        ("1 actor database".to_owned(), "it")
    } else {
        (format!("{unread} actor databases"), "them")
    };
    format!(
        "{subject} could not be read, so the check cannot tell whether the log reaches {reaches}. \
         If a daemon is running, stop it and run the check again"
    )
}

/// Before the store opens: when `state.db` is missing, or the databases are
/// behind the first LSN the log still holds, install the newest snapshot the
/// log continues (m6-storage §3). "The databases" are `state.db` and every
/// actor database: an actor that has not changed for longer than `history`
/// would otherwise keep the start from the log that retention deleted (the
/// compaction raises their applied LSN before it deletes, but a directory an
/// older binary compacted has them behind). A `state.db` an interrupted bulk
/// replay left counts as missing. Returns the installed snapshot's LSN.
pub fn prepare_state(data: &Path, branch: &str) -> Result<Option<Lsn>, String> {
    let branch_dir = data.join("branches").join(branch);
    // Copies a crash left mid-snapshot: before anything reads the list.
    sweep_partial(&snapshots_dir(data, branch));
    if kronik_store::snapshot::discard_interrupted_bulk_replay(&branch_dir)
        .map_err(|e| e.to_string())?
    {
        tracing::warn!(
            "a bulk replay was interrupted; rebuilding state.db from the snapshot and the log"
        );
    }
    // Copies an interrupted integrity hash left (they hold actors' rows).
    let swept = kronik_store::snapshot::sweep_hash_copies(&branch_dir.join("sql"))
        .map_err(|e| e.to_string())?;
    if swept > 0 {
        tracing::info!(swept, "deleted copies an interrupted state hash left");
    }
    let plan = plan_state(data, branch, false)?;
    let Some((dir, m)) = plan.install else {
        return Ok(None);
    };
    if let Some((state, lowest)) = plan.state
        && lowest < state
    {
        tracing::warn!(
            state,
            lowest,
            "an actor database is older than the log retention kept: installing the newest \
             snapshot, whose cut is complete for every database"
        );
    }
    kronik_store::snapshot::install(&dir, &branch_dir).map_err(|e| e.to_string())?;
    let secrets = dir.join("secrets.db");
    let keys = data.join("keys");
    if secrets.exists() && !keys.join("secrets.db").exists() {
        std::fs::create_dir_all(&keys).map_err(|e| e.to_string())?;
        std::fs::copy(&secrets, keys.join("secrets.db")).map_err(|e| e.to_string())?;
    }
    tracing::warn!(lsn = m.lsn, snapshot = %m.id, "installed a snapshot as the branch's state");
    Ok(Some(m.lsn))
}
/// The newest StateRebase switch of `branch` as its state database has it:
/// (its LSN, its base LSN). Read-only, also while the node runs.
pub fn last_rebase_at(data: &Path, branch: &str) -> Option<(Lsn, Lsn)> {
    let state = data.join("branches").join(branch).join("state.db");
    let conn =
        rusqlite::Connection::open_with_flags(&state, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let get = |k: &str| -> Option<i64> {
        conn.query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .ok()
    };
    Some((get("rebase_lsn")? as Lsn, get("rebase_base")? as Lsn))
}

pub fn erasure_floor(data: &Path, branch: &str) -> Option<Lsn> {
    let state = data.join("branches").join(branch).join("state.db");
    let conn =
        rusqlite::Connection::open_with_flags(&state, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let min: Option<i64> = conn
        .query_row("SELECT min(lsn) FROM erasures", [], |r| r.get(0))
        .ok()?;
    min.map(|v| v as u64)
}

impl Node {
    /// Snapshots and retention, when this node keeps them. `None` in DST
    /// and when `Node::start` was given `storage: None`. `start_local` and
    /// `kronik serve` always install one (default history 7 days).
    pub fn storage_config(&self) -> Option<&StorageConfig> {
        self.cfg.storage.as_ref()
    }

    /// `history` back from `time_hwm`, when this node has a storage config.
    pub fn retention_cutoff(&self) -> Result<Option<u64>, ApiError> {
        let Some(storage) = self.storage_config() else {
            return Ok(None);
        };
        let hwm = self
            .store()
            .db()
            .time_hwm()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(Some(history_cutoff(hwm, storage.history)))
    }

    fn storage(&self) -> Result<&StorageConfig, ApiError> {
        self.storage_config()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "this node keeps no snapshots"))
    }

    /// The node's snapshots, oldest first.
    pub fn snapshots(&self) -> Result<Vec<Manifest>, ApiError> {
        let s = self.storage()?;
        Ok(list(&s.data_dir, self.branch())
            .into_iter()
            .map(|(_, m)| m)
            .collect())
    }

    /// Takes a snapshot at the applied LSN unless the newest one is already
    /// there (then returns it). `reason`: `interval`, `shutdown`, `manual`.
    /// Refused below `[log] disk_reserve`; retention still runs then (it
    /// only deletes), so the node can climb back above the reserve.
    pub async fn snapshot(&self, reason: &str, authority: AuthLease) -> Result<Manifest, ApiError> {
        authority.check()?;
        let held = tokio::select! {
            biased;
            () = authority.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated, "request revoked while waiting for snapshot lock")),
            held = self.snapshot_lock.clone().lock_owned() => held,
        };
        let node = self
            .arc()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let reason = reason.to_owned();
        self.authorized_effect(authority, move || async move {
            let _held = held;
            if let Err(error) = node.check_running() {
                if node.fatal().is_none()
                    && let Ok(storage) = node.storage()
                {
                    node.retain(storage);
                }
                return Err(error);
            }
            node.take_snapshot_locked(&reason).await
        })
        .await
    }

    /// Fixed configured interval/shutdown path, never an operator fallback.
    async fn snapshot_configured(&self, reason: &str) -> Result<Manifest, ApiError> {
        if let Err(e) = self.check_running() {
            if self.fatal().is_none()
                && let Ok(storage) = self.storage()
            {
                let _one = self.snapshot_lock.lock().await;
                self.retain(storage);
            }
            return Err(e);
        }
        self.take_snapshot(reason).await
    }

    /// [`Node::snapshot`] without the disk reserve check: an erasure and a
    /// reseal must complete (their snapshot drops plaintext) on a full disk
    /// too. A copy that fails (no space, I/O) is deleted at once, so a
    /// failed attempt never keeps what little space is left.
    pub(crate) async fn take_snapshot(&self, reason: &str) -> Result<Manifest, ApiError> {
        let _one = self.snapshot_lock.lock().await;
        self.take_snapshot_locked(reason).await
    }

    async fn take_snapshot_locked(&self, reason: &str) -> Result<Manifest, ApiError> {
        self.check_alive()?;
        let storage = self.storage()?.clone();
        let branch = self.branch().to_owned();
        let root = snapshots_dir(&storage.data_dir, &branch);
        sweep_partial(&root);
        if let Some((_, newest)) = list(&storage.data_dir, &branch).pop()
            && newest.lsn == self.store().applied.get()
        {
            return Ok(newest);
        }
        let tmp = root.join(format!(
            ".tmp-{}",
            self.env
                .random_bytes::<8>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let (manifest, bytes) = match self.write_snapshot(&storage, &branch, &tmp, reason) {
            Ok(done) => done,
            Err(e) => {
                // Neither the copy nor a directory without its manifest
                // stays; `list` would never see them and nothing else
                // deletes them.
                let _ = std::fs::remove_dir_all(&tmp);
                sweep_partial(&root);
                return Err(e);
            }
        };
        self.append(Record::SnapshotMarker(pb::SnapshotMarker {
            snapshot_id: manifest.id.clone(),
            lsn: manifest.lsn,
            manifest_hash: blake3::hash(&bytes).as_bytes().to_vec(),
            engine_version: manifest.engine_version.clone(),
        }))
        .await?;
        tracing::info!(
            lsn = manifest.lsn,
            bytes = manifest.bytes(),
            reason,
            "snapshot taken"
        );
        self.retain(&storage);
        // Foreign actors for forks, in step with snapshots (M14).
        self.checkpoint_foreign().await;
        Ok(manifest)
    }

    /// Copies the state into `tmp`, renames it to the snapshot's directory
    /// and writes its manifest last. Returns the manifest and its bytes.
    fn write_snapshot(
        &self,
        storage: &StorageConfig,
        branch: &str,
        tmp: &Path,
        reason: &str,
    ) -> Result<(Manifest, Vec<u8>), ApiError> {
        let root = snapshots_dir(&storage.data_dir, branch);
        let copy = self
            .store()
            .snapshot_to(tmp)
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("snapshot: {e}")))?;
        let mut rel: Vec<PathBuf> = copy.files.clone();
        if let Some(s) = &self.secrets {
            let stage = s.stage_encrypted_snapshot(tmp).map_err(|e| {
                ApiError::new(ErrorCode::Internal, format!("snapshot of secrets: {e}"))
            })?;
            std::fs::hard_link(stage.database_path(), tmp.join("secrets.db"))
                .map_err(|e| io_err("snapshot of secrets", e))?;
            rel.push(PathBuf::from("secrets.db"));
        }
        let mut files = Vec::with_capacity(rel.len());
        for r in &rel {
            let (size, hash) = hash_file(&tmp.join(r)).map_err(|e| io_err("snapshot file", e))?;
            files.push(SnapshotFile {
                path: r.to_string_lossy().replace('\\', "/"),
                size,
                blake3: hash,
            });
        }
        let log_dir = storage.data_dir.join("branches").join(branch).join("log");
        let starts = kronik_log::segment_starts(&log_dir).map_err(|e| io_err("log", e))?;
        let from = starts.iter().rposition(|s| *s <= copy.lsn + 1).unwrap_or(0);
        let segments = starts[from..]
            .iter()
            .map(|s| kronik_log::segment_name(*s))
            .collect();
        let manifest = Manifest {
            format: 1,
            id: format!("{branch}-{:020}", copy.lsn),
            branch: branch.to_owned(),
            lsn: copy.lsn,
            engine_version: kronik_runtime::ENGINE_VERSION.to_owned(),
            created_wall_ms: self.env.clock.wall_ms(),
            logical_time_ms: self.store().db().time_hwm().unwrap_or(0),
            segments,
            files,
            state_hash: copy.state_hash,
            reason: reason.to_owned(),
        };
        let dest = root.join(dir_name(copy.lsn));
        if dest.exists() {
            std::fs::remove_dir_all(&dest).map_err(|e| io_err("old snapshot", e))?;
        }
        std::fs::rename(tmp, &dest).map_err(|e| io_err("snapshot rename", e))?;
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        write_synced(&dest.join("manifest.json"), &bytes).map_err(|e| io_err("manifest", e))?;
        Ok((manifest, bytes))
    }

    /// Retention: deletes segments past `history`, snapshots beyond
    /// `snapshots_kept` and partial snapshots. Called with the snapshot
    /// lock held.
    fn retain(&self, storage: &StorageConfig) {
        sweep_partial(&snapshots_dir(&storage.data_dir, self.branch()));
        if let Err(e) = self.compact(storage) {
            tracing::warn!(error = %e.message, "compaction failed");
        }
        self.prune_snapshots(storage);
    }

    /// Retention between snapshot passes while the audit hold has given
    /// way (perf review R2): a sink down past `history` would otherwise
    /// keep free disk near `hold_release` until the next pass, and a busy
    /// node could drop below the disk reserve in between. Returns whether
    /// it ran. Only segments: the index rows follow when one was deleted.
    #[doc(hidden)]
    pub async fn retain_if_released(&self, free: u64) -> bool {
        let hold = self.retention_hold();
        if hold.floor().is_none()
            || !hold.released(Some(free), self.env.clock.wall_ms())
            || self.fatal().is_some()
        {
            return false;
        }
        let Ok(storage) = self.storage() else {
            return false;
        };
        let _one = self.snapshot_lock.lock().await;
        sweep_partial(&snapshots_dir(&storage.data_dir, self.branch()));
        if let Err(e) = self.compact_with(storage, false) {
            tracing::warn!(error = %e.message, "compaction failed");
        }
        self.prune_snapshots(storage);
        true
    }

    /// The snapshot `kronik serve` takes when it stops. None when nothing
    /// but snapshot markers follows the newest snapshot, so an idle restart
    /// writes no copy of the state and appends no marker.
    pub async fn shutdown_snapshot(&self) -> Result<Option<Manifest>, ApiError> {
        self.snapshot_if_changed("shutdown").await
    }

    /// A snapshot for `reason`, or None when nothing but the newest
    /// snapshot's marker follows it. A snapshot appends only its own
    /// marker, so a longer tail holds a change; reading one record keeps
    /// the check cheap on a busy node.
    async fn snapshot_if_changed(&self, reason: &str) -> Result<Option<Manifest>, ApiError> {
        let storage = self.storage()?;
        if let Some((_, newest)) = list(&storage.data_dir, self.branch()).pop() {
            let applied = self.store().applied.get();
            let mut idle = applied <= newest.lsn;
            if applied == newest.lsn + 1 {
                self.reader()
                    .read(applied, applied, |c| {
                        idle = matches!(c.record, Record::SnapshotMarker(_));
                        Ok(())
                    })
                    .await
                    .map_err(|e| ApiError::new(ErrorCode::Internal, format!("log: {e}")))?;
            }
            if idle {
                return Ok(None);
            }
        }
        self.snapshot_configured(reason).await.map(Some)
    }

    /// Checkpoints every running `fork_mode = "sandbox"` foreign actor (M14,
    /// ADR 0019), each at its own LSN. Main's turns are drained first, so no
    /// foreign call is in flight and the applied LSN is an exact cut of the
    /// boundary; the host releases the drain as soon as main's calls to the
    /// actor wait in the daemon, so main is held only that long, not for the
    /// copy and the runsc steps. When they do not pause in time, that
    /// actor gets no checkpoint.
    pub async fn checkpoint_foreign(
        &self,
    ) -> Vec<(String, Result<kronik_effects::foreign::Checkpoint, String>)> {
        let Some(host) = self.foreign.clone() else {
            return Vec::new();
        };
        let names: Vec<String> = self
            .config_now()
            .foreign_actors()
            .filter(|f| f.fork_mode == "sandbox")
            .map(|f| f.name.clone())
            .collect();
        let mut out = Vec::with_capacity(names.len());
        // Below `[log] disk_reserve` (erasure and reseal snapshots run
        // there too) no checkpoint is written: skipped with a warning,
        // never failing the snapshot or the erasure.
        if let Err(e) = self.check_running() {
            for name in names {
                tracing::warn!(foreign = %name, error = %e.message, "no foreign checkpoint");
                out.push((name, Err(e.message.clone())));
            }
            return out;
        }
        for name in names {
            // The gate's drain, without the deploy lock (crate::gate).
            let pause = match self.drain(std::time::Duration::from_secs(2)).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(foreign = %name, error = %e.message, "no foreign checkpoint: main's turns did not pause");
                    out.push((name, Err(e.message)));
                    continue;
                }
            };
            let lsn = self.applied_lsn();
            let r = host
                .checkpoint(&name, lsn, Box::new(pause), self.disk_budget())
                .await;
            if let Err(e) = &r {
                tracing::warn!(foreign = %name, lsn, error = %e, "foreign checkpoint failed");
            }
            out.push((name, r));
        }
        out
    }
    /// After an `Erasure` record is applied (docs/design/m8-privacy.md §6.6):
    /// take a snapshot, then delete local snapshots older than the erasure.
    /// The shipper deletes the matching remote snapshots on its next round
    /// (manifest first), because they are no longer local.
    /// The erasure has committed when this runs, so it never fails the
    /// erase: a snapshot that fails is retried, first at once, then every
    /// 30 s in the background until one at or after the erasure exists
    /// (each failure is logged).
    pub(crate) async fn after_erasure(&self, erasure_lsn: Lsn) -> Result<(), ApiError> {
        if self.cfg.storage.is_none() {
            return Ok(());
        }
        for attempt in 0..3u32 {
            match self.erasure_snapshot(erasure_lsn).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(lsn = erasure_lsn, attempt, error = %e.message, "the snapshot after an erasure failed");
                    self.env
                        .clock
                        .sleep(Duration::from_millis(200 << attempt))
                        .await;
                }
            }
        }
        if let Some(node) = self.me() {
            self.env.spawn("erasure-snapshot", async move {
                loop {
                    node.env.clock.sleep(Duration::from_secs(30)).await;
                    if node.fatal().is_some() {
                        return;
                    }
                    match node.erasure_snapshot(erasure_lsn).await {
                        Ok(()) => return,
                        Err(e) => tracing::error!(lsn = erasure_lsn, error = %e.message, "the snapshot after an erasure failed again; retrying"),
                    }
                }
            });
        }
        Ok(())
    }

    async fn erasure_snapshot(&self, erasure_lsn: Lsn) -> Result<(), ApiError> {
        let manifest = self.take_snapshot("erasure").await?;
        if manifest.lsn < erasure_lsn {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "the snapshot after an erasure is older than the erasure",
            ));
        }
        self.delete_snapshots_before(erasure_lsn)
    }

    fn delete_snapshots_before(&self, erasure_lsn: Lsn) -> Result<(), ApiError> {
        let storage = self.storage()?;
        let all = list(&storage.data_dir, self.branch());
        if !all.iter().any(|(_, m)| m.lsn >= erasure_lsn) {
            return Ok(());
        }
        for (dir, m) in &all {
            if m.lsn < erasure_lsn {
                std::fs::remove_dir_all(dir)
                    .map_err(|e| io_err("deleting a snapshot older than an erasure", e))?;
                tracing::info!(lsn = m.lsn, "deleted a snapshot older than an erasure");
            }
        }
        Ok(())
    }

    /// The first LSN the branch's log holds (the first retained record).
    pub fn log_first(&self, storage: &StorageConfig) -> Result<Lsn, ApiError> {
        let dir = storage
            .data_dir
            .join("branches")
            .join(self.branch())
            .join("log");
        Ok(kronik_log::segment_starts(&dir)
            .map_err(|e| io_err("log", e))?
            .first()
            .copied()
            .unwrap_or(1))
    }

    /// Keeps the newest `snapshots_kept`, plus the oldest snapshot the log
    /// still continues (the base for replay at the start of the window).
    fn prune_snapshots(&self, storage: &StorageConfig) {
        let all = list(&storage.data_dir, self.branch());
        let keep = storage.snapshots_kept.max(1);
        if all.len() <= keep {
            return;
        }
        // While the log still starts at LSN 1 replay needs no base.
        let log_first = self.log_first(storage).unwrap_or(1);
        let base = all
            .iter()
            .find(|(_, m)| log_first > 1 && m.lsn + 1 >= log_first)
            .map(|(_, m)| m.lsn);
        // Until a snapshot at or after the newest rebase switch exists, a
        // rebuild crosses it from a snapshot at or before its base (ADR 0017).
        let newest = all.last().map(|(_, m)| m.lsn);
        let rebase_base = self
            .last_rebase()
            .ok()
            .flatten()
            .filter(|(r, _)| newest.is_none_or(|n| n < *r))
            .and_then(|(_, b)| {
                all.iter()
                    .rev()
                    .find(|(_, m)| m.lsn <= b)
                    .map(|(_, m)| m.lsn)
            });
        for (dir, m) in &all[..all.len() - keep] {
            if Some(m.lsn) == base || Some(m.lsn) == rebase_base {
                continue;
            }
            if let Err(e) = std::fs::remove_dir_all(dir) {
                tracing::warn!(lsn = m.lsn, error = %e, "could not delete an old snapshot");
            }
        }
    }

    /// Before retention deletes the log up to `horizon`: every actor
    /// database that has not changed since before it learns that it is
    /// complete through what is applied now, durably. An actor database's
    /// applied LSN says where its last change was, and the start replays
    /// from the lowest one, so an actor idle for longer than `history` would
    /// refuse every start after this pass. Stops the pass, with a
    /// warning from [`Node::retain`], when a database cannot be raised.
    fn raise_idle_markers(&self, horizon: Lsn) -> Result<(), ApiError> {
        let started = self.env.clock.monotonic();
        let raised = self
            .store()
            .raise_idle_sql(horizon, IDLE_RAISE_BATCH)
            .map_err(|e| {
                ApiError::new(
                    ErrorCode::Internal,
                    format!("raising the idle actor databases before compaction: {e}"),
                )
            })?;
        if !raised.blocked.is_empty() {
            return Err(ApiError::new(
                ErrorCode::Internal,
                format!(
                    "compaction waits: {} actor database(s) could not be raised or made \
                     durable (a turn is open on them, or the file is missing), first {}",
                    raised.blocked.len(),
                    raised.blocked[0]
                ),
            ));
        }
        if raised.raised > 0 {
            tracing::info!(
                horizon,
                checked = raised.checked,
                raised = raised.raised,
                elapsed_ms = self
                    .env
                    .clock
                    .monotonic()
                    .saturating_sub(started)
                    .as_millis() as u64,
                "raised the applied LSN of idle actor databases before compaction"
            );
        }
        Ok(())
    }

    /// Retention (m6-storage §5): deletes closed segments older than
    /// `history` whose records a kept snapshot covers, then the index rows
    /// of what they held. Returns the log's first LSN afterwards.
    ///
    /// A segment's own time (the turn-time high-water mark at its last
    /// record) says nothing about records after its last turn: a
    /// configuration record, such as the first `Deployment` of a young
    /// node, has no logical time, and the mark it gets is that of an older
    /// turn, or 0. Such a record is at most as old as the next turn after
    /// it. So a segment is past retention only when a later segment holds a
    /// turn newer than everything in it and that later segment, too, is
    /// entirely older than the cutoff; without a later turn it is kept.
    pub fn compact(&self, storage: &StorageConfig) -> Result<Lsn, ApiError> {
        self.compact_with(storage, true)
    }

    /// [`Node::compact`]; with `always_index` false the index rows are
    /// compacted only when a segment was deleted: their deletes scan whole
    /// tables under the store's lock, which the disk loop must not take
    /// every minute while a released hold has nothing left to delete
    /// (perf review R2-cost).
    fn compact_with(&self, storage: &StorageConfig, always_index: bool) -> Result<Lsn, ApiError> {
        let dir = storage
            .data_dir
            .join("branches")
            .join(self.branch())
            .join("log");
        let starts = kronik_log::segment_starts(&dir).map_err(|e| io_err("log", e))?;
        let store_err =
            |e: kronik_store::StoreError| ApiError::new(ErrorCode::Internal, e.to_string());
        let hwm = self.store().db().time_hwm().map_err(store_err)?;
        let cutoff = history_cutoff(hwm, storage.history);
        let ranges = self.store().db().segments().map_err(store_err)?;
        let newest_snapshot = list(&storage.data_dir, self.branch())
            .last()
            .map(|(_, m)| m.lsn);
        let mut first = starts.first().copied().unwrap_or(1);
        let was_first = first;
        // A rebuild may still have to cross the newest rebase switch from
        // before its base (ADR 0017): keep everything until a snapshot at or
        // after the switch exists.
        let rebase_hold = self
            .last_rebase()?
            .is_some_and(|(r, _)| newest_snapshot.is_none_or(|n| n < r));
        let hold = self.retention_hold();
        let released = hold.released(self.measured_disk_free(), self.env.clock.wall_ms());
        // Closed segments only: never the newest (active) one, oldest first.
        // First decide which go, then make the databases not need them, then
        // delete (m6-storage §5): a crash anywhere in between leaves the log
        // whole or a prefix shorter, and every database ahead of it.
        let mut doomed: Vec<(Lsn, Lsn, Option<Lsn>)> = Vec::new();
        for w in starts.windows(2).take_while(|_| !rebase_hold) {
            let (start, next) = (w[0], w[1]);
            let last_lsn = next - 1;
            let Some(&(_, _, last_time)) = ranges.iter().find(|(s, _, _)| *s == start) else {
                break;
            };
            // An upper bound for the time of every record in this segment:
            // the time mark of the first later segment whose mark is
            // higher, which holds the first turn after this segment.
            let bound = ranges
                .iter()
                .filter(|(s, _, _)| *s > start)
                .map(|&(_, _, t)| t)
                .find(|t| *t > last_time);
            let covered = newest_snapshot.is_some_and(|l| l >= last_lsn);
            if bound.is_none_or(|b| b >= cutoff) || !covered {
                break;
            }
            let mut released_floor = None;
            if let Some(floor) = hold.floor().filter(|f| last_lsn > *f) {
                if !released {
                    break;
                }
                released_floor = Some(floor);
            }
            doomed.push((start, next, released_floor));
        }
        if let Some(&(_, next, _)) = doomed.last() {
            self.raise_idle_markers(next - 1)?;
            #[cfg(test)]
            if CRASH_AFTER_RAISE.with(std::cell::Cell::get) {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "test crash after the raise",
                ));
            }
        }
        for (start, next, released_floor) in doomed {
            let last_lsn = next - 1;
            if let Some(floor) = released_floor {
                tracing::warn!(
                    floor,
                    start,
                    last_lsn,
                    "retention released the audit hold: free disk is below [audit] hold_release \
                     or the hold is older than max_hold; the export records the gap"
                );
            }
            match kronik_log::delete_segment(&dir, start) {
                // Deleted by a pass under the snapshot lock while this one
                // (a test's direct call) ran without it.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                r => r.map_err(|e| io_err("segment", e))?,
            }
            tracing::info!(start, last_lsn, "deleted a segment past retention");
            first = next;
            #[cfg(test)]
            if CRASH_AFTER_DELETE.with(std::cell::Cell::get) {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "test crash after a delete",
                ));
            }
        }
        if !always_index && first == was_first {
            return Ok(first);
        }
        let ingress_ttl = self.cfg.ingress_ttl.as_millis() as u64;
        self.db_compactions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.store()
            .db()
            .compact(first, hwm.saturating_sub(ingress_ttl))
            .map_err(store_err)?;
        Ok(first)
    }
}

/// Takes a snapshot every `snapshot_interval` when something was applied
/// since the last one (its own marker does not count).
pub(crate) async fn snapshot_loop(node: std::sync::Weak<Node>, interval: Duration) {
    loop {
        let Some(n) = node.upgrade() else { return };
        let sleep = n.env.clock.sleep(interval);
        drop(n);
        sleep.await;
        let Some(n) = node.upgrade() else { return };
        if n.fatal().is_some() {
            return;
        }
        if let Err(e) = n.snapshot_if_changed("interval").await {
            tracing::warn!(error = %e.message, "scheduled snapshot failed");
        }
    }
}

#[cfg(test)]
mod retention_tests;
