//! Snapshots of a node's state (docs/design/m6-storage.md §2-§3): taking
//! them (on a schedule, at shutdown, on demand), listing and pruning them,
//! and choosing state at startup when `state.db` is missing or behind the
//! log.

use std::path::{Path, PathBuf};
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

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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

/// Before the store opens: when `state.db` is missing, or behind the first
/// LSN the log still holds, install the newest snapshot the log continues
/// (m6-storage §3). A `state.db` an interrupted bulk replay left counts as
/// missing. Returns the installed snapshot's LSN.
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
    let starts = kronik_log::segment_starts(&branch_dir.join("log")).map_err(|e| e.to_string())?;
    let log_first = starts.first().copied();
    let state = branch_dir.join("state.db");
    let behind = if state.exists() {
        let conn = rusqlite::Connection::open_with_flags(
            &state,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| e.to_string())?;
        let applied: Option<i64> = conn
            .query_row("SELECT v FROM meta WHERE k = 'applied_lsn'", [], |r| {
                r.get(0)
            })
            .ok();
        let applied = applied.unwrap_or(0) as Lsn;
        log_first.is_some_and(|f| applied + 1 < f)
    } else {
        // A fresh node (no log either) needs nothing.
        log_first.is_some_and(|f| f > 1) || !list(data, branch).is_empty()
    };
    if !behind {
        return Ok(None);
    }
    let usable = list(data, branch)
        .into_iter()
        .rev()
        .find(|(_, m)| log_first.is_none_or(|f| m.lsn + 1 >= f));
    let Some((dir, m)) = usable else {
        return Err(format!(
            "the log starts at LSN {} and no snapshot reaches it; restore one \
             (kronik restore --from ...)",
            log_first.unwrap_or(1)
        ));
    };
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
/// The earliest applied erasure's LSN, if `state.db` records one. A fork
/// or restore must not go back past it (docs/design/m8-privacy.md §6.6).
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
    pub async fn snapshot(&self, reason: &str) -> Result<Manifest, ApiError> {
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
        self.check_alive()?;
        let storage = self.storage()?.clone();
        let _one = self.snapshot_lock.lock().await;
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
            s.backup_to(&tmp.join("secrets.db")).map_err(|e| {
                ApiError::new(ErrorCode::Internal, format!("snapshot of secrets: {e}"))
            })?;
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
        self.snapshot(reason).await.map(Some)
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

    /// The first LSN the branch's log holds.
    fn log_first(&self, storage: &StorageConfig) -> Result<Lsn, ApiError> {
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
        for (dir, m) in &all[..all.len() - keep] {
            if Some(m.lsn) == base {
                continue;
            }
            if let Err(e) = std::fs::remove_dir_all(dir) {
                tracing::warn!(lsn = m.lsn, error = %e, "could not delete an old snapshot");
            }
        }
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
        // Closed segments only: never the newest (active) one, oldest first.
        for w in starts.windows(2) {
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
            kronik_log::delete_segment(&dir, start).map_err(|e| io_err("segment", e))?;
            tracing::info!(start, last_lsn, "deleted a segment past retention");
            first = next;
        }
        let ingress_ttl = self.cfg.ingress_ttl.as_millis() as u64;
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
