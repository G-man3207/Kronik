//! The blob collector (M25 slice B11; M26 §6, ADR 0120): which blob files
//! of main's store something keeps, and a pass that deletes the others.
//!
//! The roots of a pass ([`NodeRoots`]):
//!
//! - the index (`state.db`): blobs the state keeps (pins; M26 adds holds),
//!   and blobs a record at or after the *floor* references;
//! - every kept snapshot's `blobs.idx` (the blobs its state roots);
//! - every fork's `blobs.roots` (the blobs its base state roots);
//! - the store's leases and claims ([`kronik_blob::BlobStore::sweep`]).
//!
//! `floor = min(first LSN of main's log, fork_lsn + 1 of every fork, the
//! floor of every floor lease)` (M26 §6.2).
//!
//! A pass runs after every retention pass, every `[blobs] gc_interval`, and
//! on `kronik blobs gc`; never during startup recovery (the loop starts with
//! the node). After the sweep it deletes the index rows that no root keeps
//! and whose file is gone (M26 §5.4 step 3, done here so that the dry run
//! can still say why a file without roots has none).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_blob::{BlobError, BlobId, Roots, Space, SweepOptions, SweepReport};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;

use crate::Node;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The file a snapshot carries its blob roots in (M26 §7).
pub const SNAPSHOT_INDEX: &str = "blobs.idx";
/// The file a fork carries its base state's blob roots in (ADR 0120 §4).
pub const FORK_ROOTS: &str = "blobs.roots";

/// What a pass found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcOutcome {
    pub report: SweepReport,
    /// The floor of the pass: records at or after it are roots.
    pub floor: Lsn,
    /// Index rows the pass deleted (their files were gone).
    pub forgotten: u64,
    /// A dry run's files without a root, each with why (ADR 0120 §6).
    pub unrooted: Vec<Unrooted>,
}

/// Why a blob file has no root (ADR 0120 §6). M26 adds `released`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnrootedReason {
    /// No committed record ever referenced it: a turn that failed or never
    /// returned or kept what it wrote, a crash before the commit.
    Loose,
    /// Its last reference is below the floor, and nothing in the state
    /// keeps it.
    OutOfRetention,
    /// Its subject was erased through its key version.
    Erased,
}

impl UnrootedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UnrootedReason::Loose => "loose",
            UnrootedReason::OutOfRetention => "out-of-retention",
            UnrootedReason::Erased => "erased",
        }
    }
}

/// A file a dry run found without a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrooted {
    pub hash: String,
    /// The file's bytes on disk.
    pub bytes: u64,
    pub reason: UnrootedReason,
    /// The previous pass found it without a root too: the next pass deletes
    /// it.
    pub candidate: bool,
    /// From the index, when a record referenced it.
    pub size: Option<u64>,
    pub subject: Option<String>,
    pub last_ref_lsn: Option<Lsn>,
}

/// The collector's state on the node.
#[derive(Default)]
pub(crate) struct GcState {
    /// Wakes the loop: a retention pass finished.
    pub(crate) wake: Arc<tokio::sync::Notify>,
    /// The last pass that deleted (not a dry run).
    pub(crate) last: Mutex<Option<GcOutcome>>,
}

fn store_error(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, e.to_string())
}

fn blob_error(e: BlobError) -> ApiError {
    match e {
        BlobError::Corrupt { .. } => ApiError::new(ErrorCode::StorageCorrupt, e.to_string()),
        BlobError::StoreFull { .. } => ApiError::new(ErrorCode::BlobStoreFull, e.to_string()),
        _ => ApiError::new(ErrorCode::Internal, e.to_string()),
    }
}

/// Writes `ids` (hash text, sorted) as a roots file: `header` first, then
/// one identity per line, through a synced temporary file and a rename.
pub(crate) fn write_roots_file(
    path: &Path,
    header: Option<&str>,
    ids: &[String],
) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        if let Some(header) = header {
            writeln!(f, "{header}")?;
        }
        for id in ids {
            writeln!(f, "{id}")?;
        }
        f.flush()?;
        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// The identities of a roots file. Lines that are not blob identities (a
/// header) are skipped; a file that cannot be read is an error, never an
/// empty set.
fn read_roots_file(path: &Path) -> std::io::Result<BTreeSet<BlobId>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| BlobId::parse(line.trim()).ok())
        .collect())
}

/// Writes `branches/<fork>/blobs.roots` for a fork whose state is in
/// `fork_dir/state.db`: a `fork_lsn <n>` header and the identities that
/// state roots. Called when the fork is created.
pub fn write_fork_roots(fork_dir: &Path, fork_lsn: Lsn) -> Result<(), ApiError> {
    let ids: Vec<String> = kronik_store::snapshot::state_blob_roots(&fork_dir.join("state.db"))
        .map_err(store_error)?
        .into_iter()
        .map(|(hash, _)| hash)
        .collect();
    write_roots_file(
        &fork_dir.join(FORK_ROOTS),
        Some(&format!("fork_lsn {fork_lsn}")),
        &ids,
    )
    .map_err(store_error)
}

/// A fork of `<data>/branches`: its fork LSN and the blobs its base state
/// roots.
struct ForkRoots {
    fork_lsn: Option<Lsn>,
    ids: BTreeSet<BlobId>,
}

/// The fork LSN of a fork directory: the header of its `blobs.roots`, or
/// the `fork_lsn` of its `proposal.json` (a fork from before blobs).
fn fork_of(dir: &Path) -> ForkRoots {
    let roots = dir.join(FORK_ROOTS);
    if let Ok(text) = std::fs::read_to_string(&roots) {
        let fork_lsn = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("fork_lsn "))
            .and_then(|n| n.trim().parse().ok());
        let ids = text
            .lines()
            .filter_map(|line| BlobId::parse(line.trim()).ok())
            .collect();
        return ForkRoots { fork_lsn, ids };
    }
    #[derive(serde::Deserialize)]
    struct Proposal {
        fork_lsn: Lsn,
    }
    let fork_lsn = std::fs::read(dir.join("proposal.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Proposal>(&bytes).ok())
        .map(|p| p.fork_lsn);
    ForkRoots {
        fork_lsn,
        ids: BTreeSet::new(),
    }
}

/// The forks of `<data>/branches` (every branch but `branch`).
fn forks(data: &Path, branch: &str) -> Vec<ForkRoots> {
    let Ok(dir) = std::fs::read_dir(data.join("branches")) else {
        return Vec::new();
    };
    dir.flatten()
        .filter(|e| e.file_name() != branch && e.path().is_dir())
        .map(|e| fork_of(&e.path()))
        .collect()
}

/// The roots of one pass over main's store.
struct NodeRoots {
    node: Arc<Node>,
    floor: Lsn,
    /// Snapshots' and forks' roots, read when the pass began.
    other: BTreeSet<BlobId>,
}

impl Roots for NodeRoots {
    fn shard(&mut self, shard: u8) -> Result<BTreeSet<BlobId>, BlobError> {
        let hex = format!("{shard:02x}");
        let rooted = self
            .node
            .store()
            .db()
            .rooted_blobs_in_shard(&hex, self.floor)
            .map_err(|e| BlobError::Io(e.to_string()))?;
        let mut out: BTreeSet<BlobId> = rooted
            .iter()
            .filter_map(|hash| BlobId::parse(hash).ok())
            .collect();
        out.extend(
            self.other
                .iter()
                .filter(|id| id.digest()[0] == shard)
                .copied(),
        );
        Ok(out)
    }
}

impl Node {
    fn blob_data_dir(&self) -> Result<PathBuf, ApiError> {
        self.storage_config()
            .map(|s| s.data_dir.clone())
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node has no data directory"))
    }

    /// The floor of a pass now (M26 §6.2).
    pub fn blob_floor(&self) -> Result<Lsn, ApiError> {
        let storage = self.storage_config().ok_or_else(|| {
            ApiError::new(ErrorCode::Unavailable, "the node has no data directory")
        })?;
        let mut floor = self.log_first(storage)?;
        for fork in forks(&storage.data_dir, self.branch()) {
            // A fork whose point cannot be read keeps every record the log
            // holds: the floor goes to the start.
            floor = floor.min(fork.fork_lsn.map_or(1, |lsn| lsn + 1));
        }
        if let Some(store) = &self.blobs
            && let Some(lease) = store.leases().lowest_floor()
        {
            floor = floor.min(lease);
        }
        Ok(floor.max(1))
    }

    /// Every kept snapshot's and every fork's blob roots.
    fn other_blob_roots(&self) -> Result<BTreeSet<BlobId>, ApiError> {
        let data = self.blob_data_dir()?;
        let mut out = BTreeSet::new();
        for (dir, _) in crate::snapshots::list(&data, self.branch()) {
            match read_roots_file(&dir.join(SNAPSHOT_INDEX)) {
                Ok(ids) => out.extend(ids),
                // A snapshot from before blobs has no index: its state
                // roots no blob.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(store_error(format!("{}: {e}", dir.display()))),
            }
        }
        for fork in forks(&data, self.branch()) {
            out.extend(fork.ids);
        }
        Ok(out)
    }

    /// One collector pass over main's store, or a dry run. `None` when
    /// blobs are off.
    pub async fn blob_gc(&self, options: SweepOptions) -> Result<Option<GcOutcome>, ApiError> {
        let Some(store) = self.blobs.clone() else {
            return Ok(None);
        };
        // After a fatal error a record may be appended and not applied, its
        // blobs' leases gone: the index would not root them.
        if let Some(fatal) = self.fatal() {
            return Err(ApiError::new(ErrorCode::Unavailable, fatal));
        }
        let node = self
            .me()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let started = self.env.clock.monotonic();
        let floor = self.blob_floor()?;
        let mut roots = NodeRoots {
            node,
            floor,
            other: self.other_blob_roots()?,
        };
        let report = store
            .sweep(&Space::Main, &mut roots, options)
            .await
            .map_err(blob_error)?;
        let mut forgotten = 0;
        let mut unrooted = Vec::with_capacity(report.unrooted.len());
        for file in &report.unrooted {
            let hash = file.id.to_string();
            let row = self.store().db().blob(&hash).map_err(store_error)?;
            let reason = match &row {
                None => UnrootedReason::Loose,
                Some(row) if row.erased => UnrootedReason::Erased,
                Some(_) => UnrootedReason::OutOfRetention,
            };
            unrooted.push(Unrooted {
                hash,
                bytes: file.bytes,
                reason,
                candidate: file.candidate,
                size: row.as_ref().map(|r| r.size),
                subject: row.as_ref().and_then(|r| r.subject.clone()),
                last_ref_lsn: row.as_ref().map(|r| r.last_ref_lsn),
            });
        }
        kronik_metrics::set(
            "kronik_blob_leases",
            &[],
            store.leases().holders().len() as f64,
        );
        if !options.dry_run {
            let unrooted = self
                .store()
                .db()
                .unrooted_blobs(floor)
                .map_err(store_error)?;
            let mut gone = Vec::new();
            for hash in unrooted {
                let Ok(id) = BlobId::parse(&hash) else {
                    continue;
                };
                if !store
                    .contains(&Space::Main, &id)
                    .await
                    .map_err(blob_error)?
                {
                    gone.push(hash);
                }
            }
            forgotten = self
                .store()
                .db()
                .forget_blobs(&gone, floor)
                .map_err(store_error)?;
            kronik_metrics::set("kronik_blob_objects", &[], report.objects as f64);
            kronik_metrics::set("kronik_blob_bytes", &[], report.bytes as f64);
            kronik_metrics::set("kronik_blob_gc_candidates", &[], report.candidates as f64);
            kronik_metrics::inc("kronik_blob_gc_runs_total", &[]);
            kronik_metrics::add("kronik_blob_gc_deleted_total", &[], report.deleted);
            kronik_metrics::add(
                "kronik_blob_gc_freed_bytes_total",
                &[],
                report.deleted_bytes,
            );
            kronik_metrics::observe(
                "kronik_blob_gc_duration_seconds",
                &[],
                self.env.clock.monotonic().saturating_sub(started),
            );
        }
        let outcome = GcOutcome {
            report,
            floor,
            forgotten,
            unrooted,
        };
        if !options.dry_run {
            *lock(&self.blob_gc.last) = Some(outcome.clone());
        }
        Ok(Some(outcome))
    }

    /// The last pass that deleted, for `kronik blobs status`.
    pub fn blob_gc_last(&self) -> Option<GcOutcome> {
        lock(&self.blob_gc.last).clone()
    }

    /// Wakes the collector after a retention pass.
    pub(crate) fn wake_blob_gc(&self) {
        self.blob_gc.wake.notify_one();
    }
}

/// The collector's loop: a pass after every retention pass and every
/// `interval` (never when `interval` is zero: then only on demand).
pub(crate) async fn blob_gc_loop(node: std::sync::Weak<Node>, interval: Duration) {
    loop {
        // Wait without keeping the node alive.
        let (wake, env) = match node.upgrade() {
            Some(strong) => (strong.blob_gc.wake.clone(), strong.env.clone()),
            None => return,
        };
        if interval.is_zero() {
            wake.notified().await;
        } else {
            tokio::select! {
                biased;
                () = wake.notified() => {}
                () = env.clock.sleep(interval) => {}
            }
        }
        let Some(strong) = node.upgrade() else {
            return;
        };
        if strong.fatal().is_some() {
            return;
        }
        if let Err(e) = strong.blob_gc(SweepOptions::default()).await {
            tracing::warn!(error = %e.message, "the blob collector's pass failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest from before blobs (the v0.4.1 compatibility data) reads
    /// as a snapshot whose state roots no blob, and one with blobs keeps
    /// them through a round trip.
    #[test]
    fn a_manifest_from_before_blobs_reads_as_none() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/compatibility/v0.4.1/data/snapshots/main/00000000000000000020/manifest.json",
        );
        let old: crate::snapshots::Manifest =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(old.blobs, crate::snapshots::BlobTotals::default());
        let new = crate::snapshots::Manifest {
            blobs: crate::snapshots::BlobTotals {
                count: 2,
                bytes: 300,
            },
            ..old
        };
        let text = serde_json::to_string(&new).unwrap();
        assert!(
            text.contains(r#""blobs":{"count":2,"bytes":300}"#),
            "{text}"
        );
        let back: crate::snapshots::Manifest = serde_json::from_str(&text).unwrap();
        assert_eq!(back, new);
    }

    /// A roots file lists identities one per line after an optional header;
    /// a fork without one has its point from `proposal.json`.
    #[test]
    fn roots_files_and_fork_points() {
        let dir = tempfile::tempdir().unwrap();
        let a = format!("b3:{}", "0a".repeat(32));
        let b = format!("b3s:{}", "ff".repeat(32));
        let fork = dir.path().join("branches/f1");
        std::fs::create_dir_all(&fork).unwrap();
        write_roots_file(
            &fork.join(FORK_ROOTS),
            Some("fork_lsn 41"),
            &[a.clone(), b.clone()],
        )
        .unwrap();
        let roots = fork_of(&fork);
        assert_eq!(roots.fork_lsn, Some(41));
        let ids: Vec<String> = roots.ids.iter().map(|id| id.to_string()).collect();
        assert_eq!(ids, [a.clone(), b]);
        let proposal = dir.path().join("branches/p-1");
        std::fs::create_dir_all(&proposal).unwrap();
        std::fs::write(
            proposal.join("proposal.json"),
            br#"{"id": "p-1", "fork_lsn": 17, "status": "ready"}"#,
        )
        .unwrap();
        let from_proposal = fork_of(&proposal);
        assert_eq!(from_proposal.fork_lsn, Some(17));
        assert!(from_proposal.ids.is_empty());
        // Main is no fork; an unreadable fork point keeps everything.
        std::fs::create_dir_all(dir.path().join("branches/main")).unwrap();
        std::fs::create_dir_all(dir.path().join("branches/broken")).unwrap();
        let mut points: Vec<Option<Lsn>> = forks(dir.path(), "main")
            .into_iter()
            .map(|f| f.fork_lsn)
            .collect();
        points.sort();
        assert_eq!(points, [None, Some(17), Some(41)]);
        let snapshot = dir.path().join("idx");
        write_roots_file(&snapshot, None, std::slice::from_ref(&a)).unwrap();
        assert_eq!(
            read_roots_file(&snapshot).unwrap(),
            [BlobId::parse(&a).unwrap()].into()
        );
    }
}
