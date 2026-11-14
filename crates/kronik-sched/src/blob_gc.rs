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

use kronik_blob::{BlobError, BlobId, Roots, Space, SweepReport};
/// The store's options and reader, for the API.
pub use kronik_blob::{BlobReader, SweepOptions};
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

/// Why a blob file has no root (ADR 0120 §6, M26 §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnrootedReason {
    /// No committed record ever referenced it: a turn that failed or never
    /// returned or kept what it wrote, a crash before the commit.
    Loose,
    /// Its last holder released it, no record referenced it after that, and
    /// that record is below the floor now (M26).
    Released,
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
            UnrootedReason::Released => "released",
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
    /// The actor (`kind/key`) that released it last, and that record's LSN.
    pub released_by: Option<(String, Lsn)>,
}

/// The collector's state on the node.
#[derive(Default)]
pub(crate) struct GcState {
    /// Wakes the loop: a retention pass finished.
    pub(crate) wake: Arc<tokio::sync::Notify>,
    /// The last pass that deleted (not a dry run).
    pub(crate) last: Mutex<Option<GcOutcome>>,
    /// The erasures the collector is done with, through this LSN
    /// (`blob_erasure`); `None` until read from the data directory.
    pub(crate) erasures_swept: Mutex<Option<Lsn>>,
    /// A later pass is asked for already (`blob_erasure`).
    pub(crate) retry: std::sync::atomic::AtomicBool,
    /// Held by an erasure from before its record until its own deletion of
    /// its blobs' files is done; a pass reads what it is for under it, so it
    /// never deletes, uncounted, a file the erasure is about to count.
    pub(crate) erasing: tokio::sync::Mutex<()>,
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

/// The forks of `<data>/branches` (every branch but `branch`). A directory
/// with neither `blobs.roots` nor `proposal.json` is no fork: a creation
/// that stopped before its first record, with no state to keep. It is
/// skipped with a warning, rather than keeping every record the log holds
/// for as long as it lies there.
fn forks(data: &Path, branch: &str) -> Vec<ForkRoots> {
    let Ok(dir) = std::fs::read_dir(data.join("branches")) else {
        return Vec::new();
    };
    dir.flatten()
        .filter(|e| e.file_name() != branch && e.path().is_dir())
        .filter(|e| {
            let dir = e.path();
            let fork = dir.join(FORK_ROOTS).exists() || dir.join("proposal.json").exists();
            if !fork {
                tracing::warn!(
                    dir = %dir.display(),
                    "a branch directory without blobs.roots or proposal.json is not a fork; its blobs are not kept"
                );
            }
            fork
        })
        .map(|e| fork_of(&e.path()))
        .collect()
}

/// The roots of one pass over main's store.
struct NodeRoots {
    node: Arc<Node>,
    floor: Lsn,
    /// Snapshots' and forks' roots, read when the pass began.
    other: BTreeSet<BlobId>,
    /// Every erased subject and the last key version erased, when the pass
    /// began (`SweepOptions::erased_now`).
    erased: std::collections::HashMap<String, u32>,
}

/// Whether `erased` (subject → the last key version erased) covers a blob
/// of `subject` with `version`.
fn erased_through(
    erased: &std::collections::HashMap<String, u32>,
    subject: &str,
    version: u32,
) -> bool {
    erased.get(subject).is_some_and(|last| version <= *last)
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

    fn erased(&self, subject: &str, key_version: u32) -> bool {
        erased_through(&self.erased, subject, key_version)
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
        // The erasures this pass is for (M26 §9.3): it deletes their
        // subjects' files without a root at once, and every such file of a
        // fork space. The writers at the start may still name more.
        let (loose, writing, erased) = {
            let _quiet = self.blob_gc.erasing.lock().await;
            let loose = if options.dry_run {
                Vec::new()
            } else {
                self.loose_erasures().await?
            };
            let erased: std::collections::HashMap<String, u32> = self
                .store()
                .db()
                .erasures()
                .map_err(store_error)?
                .into_iter()
                .collect();
            (loose, store.live_writers(), erased)
        };
        let options = SweepOptions {
            erased_now: options.erased_now || !loose.is_empty(),
            ..options
        };
        let mut roots = NodeRoots {
            node,
            floor,
            other: self.other_blob_roots()?,
            erased: erased.clone(),
        };
        let report = store
            .sweep(&Space::Main, &mut roots, options)
            .await
            .map_err(blob_error)?;
        if options.erased_now
            && !options.dry_run
            && let Some(storage) = self.storage_config()
        {
            let is_erased =
                move |subject: &str, version: u32| erased_through(&erased, subject, version);
            for space in
                crate::blob_erasure::fork_spaces(&*self.env.fs, &storage.data_dir, self.branch())
                    .await?
            {
                let (files, bytes) = store
                    .delete_erased_subjects(&space, &is_erased)
                    .await
                    .map_err(blob_error)?;
                if files > 0 {
                    tracing::info!(?space, files, bytes, "deleted the files of erased subjects");
                }
            }
        }
        let mut forgotten = 0;
        let mut unrooted = Vec::with_capacity(report.unrooted.len());
        for file in &report.unrooted {
            let hash = file.id.to_string();
            let row = self.store().db().blob(&hash).map_err(store_error)?;
            let released = self.store().db().released_by(&hash).map_err(store_error)?;
            let reason = match &row {
                None => UnrootedReason::Loose,
                Some(row) if row.erased => UnrootedReason::Erased,
                // The release was its last reference (a RELEASE is one).
                Some(row)
                    if released
                        .as_ref()
                        .is_some_and(|(_, _, lsn)| *lsn >= row.last_ref_lsn) =>
                {
                    UnrootedReason::Released
                }
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
                released_by: released.map(|(kind, key, lsn)| (format!("{kind}/{key}"), lsn)),
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
            // An erased blob's row stays while the bucket still has its
            // object: privacy status ties the object to its subject through
            // it until the shipper has deleted it (ADR 0122 §4).
            let shipped = kronik_store::ship_blobs::shipped_names(&self.blob_data_dir()?)
                .map_err(store_error)?;
            let mut gone = Vec::new();
            for hash in unrooted {
                let Ok(id) = BlobId::parse(&hash) else {
                    continue;
                };
                if shipped.contains(&id.file_name())
                    && self
                        .store()
                        .db()
                        .blob(&hash)
                        .map_err(store_error)?
                        .is_some_and(|row| row.erased)
                {
                    continue;
                }
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
            self.loose_swept(&loose, &writing).await?;
        }
        Ok(Some(outcome))
    }

    /// Writes `branches/<fork>/blobs.roots` for a fork created at
    /// `fork_lsn` (ADR 0120 §4): a `fork_lsn <n>` header, then the blobs
    /// its base state roots. For a fork of the applied state that is the
    /// state's roots now; for an earlier point, which this node does not
    /// keep a state of, every blob of the index first referenced at or
    /// before it, a superset. Main's collector keeps them, and the records
    /// after the fork point, while the fork exists. Nothing when blobs are
    /// off.
    pub fn write_fork_roots(&self, fork_dir: &Path, fork_lsn: Lsn) -> Result<(), ApiError> {
        if self.blobs.is_none() {
            return Ok(());
        }
        let at_head = fork_lsn >= self.applied_lsn();
        let ids = {
            let db = self.store().db();
            if at_head {
                db.state_blob_roots()
            } else {
                db.blobs_referenced_through(fork_lsn)
            }
        }
        .map_err(store_error)?;
        write_roots_file(
            &fork_dir.join(FORK_ROOTS),
            Some(&format!("fork_lsn {fork_lsn}")),
            &ids,
        )
        .map_err(store_error)
    }

    /// A floor lease at `lsn` (ADR 0120 §4): while it lives (its holder
    /// renews it at least every 30 s), main's collector keeps every blob a
    /// record at or after `lsn` references. For a replay, proposal,
    /// catch-up, rebase or preview run, at its fork point. `None` when blobs
    /// are off.
    pub fn blob_floor_lease(&self, holder: &'static str, lsn: Lsn) -> Option<kronik_blob::Lease> {
        self.blobs
            .as_ref()
            .map(|store| store.leases().floor(holder, lsn))
    }

    /// `kronik blobs gc --dry-run --verify` (M26 §6.6): the differences
    /// between the index's pins and the rows they mirror, which should
    /// always be empty. An open turn's references come from its
    /// `TurnBegin`, read from the log. Empty when blobs are off.
    pub async fn blob_pin_drift(&self) -> Result<Vec<kronik_store::db::PinDrift>, ApiError> {
        if self.blobs.is_none() {
            return Ok(Vec::new());
        }
        let floor = self.blob_floor()?;
        let open = self.store().db().open_turns().map_err(store_error)?;
        let mut refs = std::collections::BTreeMap::new();
        for turn in open {
            let c = self.reader().read_at(turn.pos).await.map_err(|e| {
                store_error(format!("reading the open turn at lsn {}: {e}", turn.lsn))
            })?;
            let hashes: Vec<String> = kronik_proto::blobs::refs(&c.record)
                .into_iter()
                .map(|r| r.hash.clone())
                .collect();
            refs.insert(turn.execution_id, hashes);
        }
        self.store()
            .db()
            .blob_pin_drift(floor, &refs)
            .map_err(store_error)
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

/// What `kronik blobs status` shows (M25 §15).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlobStatus {
    /// `[blobs]` is on.
    pub enabled: bool,
    /// Blobs of the index (every blob a record within retention or the
    /// state references, not erased) and their bytes.
    pub indexed: u64,
    pub indexed_bytes: u64,
    /// The floor now: records at or after it keep their blobs.
    pub floor: Option<Lsn>,
    /// Live leases.
    pub leases: u64,
    /// Free bytes of the data directory's file system, `[blobs]
    /// disk_reserve`, and whether new blobs are refused.
    pub free_bytes: Option<u64>,
    pub reserve_bytes: u64,
    pub below_reserve: bool,
    /// The collector's last pass that deleted (not a dry run).
    pub last_gc: Option<GcOutcome>,
}

/// What keeps a blob, for `kronik blobs inspect` (M26 §6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobRoot {
    /// A record at or after the floor references it.
    Log { last_ref_lsn: Lsn, floor: Lsn },
    /// An actor (`kind/key`) holds it, since the record at `lsn` (M26).
    Held { actor: String, lsn: Lsn },
    /// A row of the state pins it.
    Pin {
        source: &'static str,
        owner: String,
        lsn: Lsn,
    },
    /// A kept snapshot's `blobs.idx` lists it.
    Snapshot { lsn: Lsn },
    /// A fork's `blobs.roots` lists it.
    Fork { name: String },
    /// A lease of this daemon holds it (a turn, an upload, a stream).
    Lease,
}

/// The state of a blob for `kronik blobs inspect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobState {
    /// In the index and in the store.
    Live,
    /// Its subject was erased through its key version.
    Erased,
    /// In the index, not in the store (`BLOB_MISSING`).
    Missing,
    /// In the store, not in the index: no record ever referenced it.
    Loose,
}

impl BlobState {
    pub fn as_str(self) -> &'static str {
        match self {
            BlobState::Live => "live",
            BlobState::Erased => "erased",
            BlobState::Missing => "missing",
            BlobState::Loose => "loose",
        }
    }
}

/// One blob, for `kronik blobs inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInspection {
    pub hash: String,
    pub state: BlobState,
    /// The index's row, when a record referenced it.
    pub row: Option<kronik_store::db::BlobRow>,
    /// The file's bytes on disk, when it is in the store.
    pub file_bytes: Option<u64>,
    /// Whether its frames are sealed, when the file could be opened.
    pub sealed: Option<bool>,
    pub roots: Vec<BlobRoot>,
    /// With `verify`: whether the whole file checked out, and why not.
    pub verified: Option<Result<(), String>>,
}

impl Node {
    /// `kronik blobs status`.
    pub fn blob_status(&self) -> Result<BlobStatus, ApiError> {
        let Some(store) = &self.blobs else {
            return Ok(BlobStatus::default());
        };
        let (indexed, indexed_bytes) = self.store().db().blob_totals().map_err(store_error)?;
        let below = store.below_reserve();
        Ok(BlobStatus {
            enabled: true,
            indexed,
            indexed_bytes,
            floor: self.blob_floor().ok(),
            leases: store.leases().holders().len() as u64,
            free_bytes: below.or_else(|| self.disk_free()),
            reserve_bytes: self.cfg.blobs.as_ref().map_or(0, |b| b.disk_reserve),
            below_reserve: below.is_some(),
            last_gc: self.blob_gc_last(),
        })
    }

    fn blob_id(hash: &str) -> Result<BlobId, ApiError> {
        BlobId::parse(hash).map_err(|_| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("{hash:?} is not a blob hash (b3:<64 hex> or b3s:<64 hex>)"),
            )
        })
    }

    fn blob_not_found(hash: &str) -> ApiError {
        ApiError::new(
            ErrorCode::BlobNotFound,
            format!("this node knows no blob {hash}"),
        )
    }

    /// `kronik blobs inspect`: what the index and the store know of `hash`,
    /// what keeps it, and with `verify` whether its whole file checks out.
    /// `BLOB_NOT_FOUND` when neither knows it (or blobs are off).
    pub async fn blob_inspect(&self, hash: &str, verify: bool) -> Result<BlobInspection, ApiError> {
        let id = Self::blob_id(hash)?;
        let hash = id.to_string();
        let Some(store) = self.blobs.clone() else {
            return Err(Self::blob_not_found(&hash));
        };
        let row = self.store().db().blob(&hash).map_err(store_error)?;
        let present = store
            .contains(&Space::Main, &id)
            .await
            .map_err(blob_error)?;
        let state = match (&row, present) {
            (None, false) => return Err(Self::blob_not_found(&hash)),
            (None, true) => BlobState::Loose,
            (Some(r), _) if r.erased => BlobState::Erased,
            (Some(_), false) => BlobState::Missing,
            (Some(_), true) => BlobState::Live,
        };
        let mut file_bytes = None;
        let mut sealed = None;
        let mut verified = None;
        if present {
            let file = self
                .env
                .fs
                .open(
                    store.object_path(&Space::Main, &id),
                    kronik_core::env::OpenMode::Read,
                )
                .await
                .map_err(|e| store_error(format!("opening the blob: {e}")))?;
            file_bytes = Some(
                file.len()
                    .await
                    .map_err(|e| store_error(format!("reading the blob's length: {e}")))?,
            );
            if let Some(r) = row.as_ref().filter(|r| !r.erased) {
                let meta = kronik_blob::BlobMeta::from_pb(&kronik_proto::log::v1::BlobRef {
                    hash: r.hash.clone(),
                    size: r.size,
                    subject: r.subject.clone(),
                    key_version: r.key_version,
                })
                .map_err(blob_error)?;
                let access = self.sealer().blob_key_access();
                match store.reader(&Space::Main, &meta, &access).await {
                    Ok(reader) => {
                        sealed = Some(reader.is_sealed());
                        if verify {
                            verified =
                                Some(reader.verify(&access).await.map_err(|e| e.to_string()));
                        }
                    }
                    Err(e) if verify => verified = Some(Err(e.to_string())),
                    Err(_) => {}
                }
            }
        }
        let mut roots = Vec::new();
        if let Some(r) = &row
            && !r.erased
        {
            let floor = self.blob_floor()?;
            if r.last_ref_lsn >= floor {
                roots.push(BlobRoot::Log {
                    last_ref_lsn: r.last_ref_lsn,
                    floor,
                });
            }
            for (kind, key, lsn) in self.store().db().holders(&hash).map_err(store_error)? {
                roots.push(BlobRoot::Held {
                    actor: format!("{kind}/{key}"),
                    lsn,
                });
            }
            for pin in self.store().db().blob_pins(&hash).map_err(store_error)? {
                roots.push(BlobRoot::Pin {
                    source: kronik_store::db::blob_source::name(pin.source),
                    owner: pin.owner,
                    lsn: pin.lsn,
                });
            }
        }
        let data = self.blob_data_dir()?;
        for (dir, manifest) in crate::snapshots::list(&data, self.branch()) {
            if read_roots_file(&dir.join(SNAPSHOT_INDEX)).is_ok_and(|ids| ids.contains(&id)) {
                roots.push(BlobRoot::Snapshot { lsn: manifest.lsn });
            }
        }
        if let Ok(entries) = std::fs::read_dir(data.join("branches")) {
            let mut forks: Vec<String> = entries
                .flatten()
                .filter(|e| e.file_name() != self.branch())
                .filter(|e| fork_of(&e.path()).ids.contains(&id))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            forks.sort();
            roots.extend(forks.into_iter().map(|name| BlobRoot::Fork { name }));
        }
        if store.leases().is_leased(&id) {
            roots.push(BlobRoot::Lease);
        }
        Ok(BlobInspection {
            hash,
            state,
            row,
            file_bytes,
            sealed,
            roots,
            verified,
        })
    }

    /// A reader of `hash`'s bytes for `kronik blobs get`, with its index
    /// row (its subject decides who may read it). `BLOB_NOT_FOUND` for a
    /// blob the index does not know (or with blobs off), `SUBJECT_ERASED`,
    /// `BLOB_MISSING`.
    pub async fn blob_content(
        &self,
        hash: &str,
    ) -> Result<(kronik_store::db::BlobRow, BlobReader), ApiError> {
        let id = Self::blob_id(hash)?;
        let hash = id.to_string();
        let Some(store) = self.blobs.clone() else {
            return Err(Self::blob_not_found(&hash));
        };
        let row = self
            .store()
            .db()
            .blob(&hash)
            .map_err(store_error)?
            .ok_or_else(|| Self::blob_not_found(&hash))?;
        if row.erased {
            return Err(ApiError::new(
                ErrorCode::SubjectErased,
                format!("blob {hash} belonged to a subject that was erased"),
            ));
        }
        let meta = kronik_blob::BlobMeta::from_pb(&kronik_proto::log::v1::BlobRef {
            hash: row.hash.clone(),
            size: row.size,
            subject: row.subject.clone(),
            key_version: row.key_version,
        })
        .map_err(blob_error)?;
        let access = self.sealer().blob_key_access();
        let reader = store
            .reader(&Space::Main, &meta, &access)
            .await
            .map_err(|e| match e {
                BlobError::NotFound(_) => {
                    kronik_metrics::inc("kronik_blob_missing_total", &[]);
                    ApiError::new(
                        ErrorCode::BlobMissing,
                        format!("blob {hash} is in the index but not in the blob store"),
                    )
                }
                BlobError::Erased => ApiError::new(
                    ErrorCode::SubjectErased,
                    format!("blob {hash} belonged to a subject that was erased"),
                ),
                BlobError::KeyMissing(_) => {
                    ApiError::new(ErrorCode::KeystoreIncomplete, e.to_string())
                }
                other => blob_error(other),
            })?;
        Ok((row, reader))
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
        // `broken`, with neither file, is no fork (review L-4).
        assert_eq!(points, [Some(17), Some(41)]);
        let snapshot = dir.path().join("idx");
        write_roots_file(&snapshot, None, std::slice::from_ref(&a)).unwrap();
        assert_eq!(
            read_roots_file(&snapshot).unwrap(),
            [BlobId::parse(&a).unwrap()].into()
        );
    }
}
