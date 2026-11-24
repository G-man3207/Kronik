//! The collector's sweep (ADR 0120 §5, M26 §6.4): deletes the blob files of
//! a space that nothing keeps.
//!
//! What keeps a blob is the caller's to say ([`Roots`]: the node's index,
//! its snapshots' indexes, its forks' roots), shard by shard, so memory is
//! bounded by one shard directory. The store adds its leases and its claims:
//!
//! - a file without roots becomes a candidate; the next pass deletes it if
//!   it still has none (`immediate` deletes it at once);
//! - deletion holds the shard's claim lock, the lock under which a writer
//!   names a new blob or claims an existing one, and skips a file that a
//!   lease holds or that was named or claimed after the pass began. A writer
//!   that deduplicates onto a file therefore either claims it before the
//!   sweep looks, or finds it gone and writes it again;
//! - the leases taken when the pass began count as roots too: a blob whose
//!   record is applied (and its lease ended) after the pass read its roots
//!   was leased when the pass began.
//!
//! A pass with [`SweepOptions::erased_now`] also deletes, at once, every
//! file without a root whose header names a subject erased through its key
//! version ([`Roots::erased`]), leased, touched or not: no record can make
//! such a blob readable again (a read answers erased), and with privacy
//! mode off its bytes are plain (M26 §9.3).

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use kronik_core::env::{File, OpenMode};
use kronik_core::ids::hex;
use kronik_core::sync::lock;

use crate::format::{HEADER_LEN, Header};
use crate::{BlobError, BlobId, BlobStore, Space};

/// What keeps the blobs of a space, shard by shard.
pub trait Roots: Send {
    /// The identities of shard `shard` (the first byte of the digest) that
    /// something keeps. Called once per shard, in increasing order, after
    /// the pass began.
    fn shard(&mut self, shard: u8) -> Result<BTreeSet<BlobId>, BlobError>;

    /// Whether `subject` is erased through `key_version`: its blobs of that
    /// version or an older one are erased data
    /// ([`SweepOptions::erased_now`]).
    fn erased(&self, _subject: &str, _key_version: u32) -> bool {
        false
    }
}

/// The subject and key version a blob file's header names; none for a
/// blob without a subject or a header that does not decode.
pub(crate) async fn header_subject(file: &dyn File) -> Option<(String, u32)> {
    let bytes = file.read_at(0, HEADER_LEN).await.ok()?;
    let header = Header::decode(&bytes).ok()?;
    Some((header.subject?, header.key_version))
}

/// How a pass deletes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepOptions {
    /// Delete every file without a root now, without the grace of a pass.
    pub immediate: bool,
    /// Delete nothing and leave the candidates as they are: list instead.
    pub dry_run: bool,
    /// Delete at once every file without a root whose subject is erased
    /// through its key version ([`Roots::erased`]), leased or not (not in a
    /// dry run).
    pub erased_now: bool,
}

/// One file without a root that a dry run found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrooted {
    pub id: BlobId,
    /// The file's size on disk.
    pub bytes: u64,
    /// The previous pass found it without a root too: the next pass deletes
    /// it.
    pub candidate: bool,
}

/// What a pass found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// The blob files of the space after the pass, and their bytes on disk.
    pub objects: u64,
    pub bytes: u64,
    /// The files it deleted, and their bytes.
    pub deleted: u64,
    pub deleted_bytes: u64,
    /// The files without a root that the next pass deletes if they still
    /// have none.
    pub candidates: u64,
    /// Of `deleted`, the files of erased subjects
    /// ([`SweepOptions::erased_now`]).
    pub erased_deleted: u64,
    /// A dry run's files without a root, in shard order.
    pub unrooted: Vec<Unrooted>,
}

/// The collector's state between passes.
#[derive(Default)]
pub(crate) struct SweepState {
    /// One pass at a time.
    running: tokio::sync::Mutex<()>,
    /// The candidates of the last pass, per space root. A restart forgets
    /// them, and the first pass after it starts over.
    candidates: Mutex<HashMap<PathBuf, BTreeSet<BlobId>>>,
}

impl BlobStore {
    /// One pass over `space`: the files that neither `roots` nor a lease
    /// keeps, and that nobody named or claimed since the pass began, are
    /// deleted if the previous pass found them without a root too (or at
    /// once with `immediate`); the others become the next pass's candidates.
    /// A file whose name is not a blob's is left alone.
    pub async fn sweep(
        &self,
        space: &Space,
        roots: &mut dyn Roots,
        options: SweepOptions,
    ) -> Result<SweepReport, BlobError> {
        let _one = self.sweep.running.lock().await;
        // First the touch sequence, then the leases: a blob named after the
        // first is skipped as touched, one named before is leased at the
        // second or referenced by a record the roots read later.
        let start = self.touch_seq.load(Ordering::Acquire);
        let leased_at_start = if self.mutation_sweep_ignores_leases {
            BTreeSet::new()
        } else {
            self.leases().leased()
        };
        let root = self.root(space);
        let previous = lock(&self.sweep.candidates)
            .get(&root)
            .cloned()
            .unwrap_or_default();
        let mut next = BTreeSet::new();
        let mut report = SweepReport::default();
        let fs = &self.env.fs;
        for shard in 0..=255u8 {
            let dir_path = root.join("objects").join(hex(&[shard]));
            let names = match fs.read_dir(dir_path.clone()).await {
                Ok(names) => names,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(BlobError::io("listing a blob directory", e)),
            };
            let rooted = roots.shard(shard)?;
            let dir = self.dir(&dir_path);
            let mut deleted_here = false;
            for name in names {
                let Some(id) = BlobId::from_file_name(&name) else {
                    continue;
                };
                let path = dir_path.join(&name);
                let file = match fs.open(path.clone(), OpenMode::Read).await {
                    Ok(file) => file,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(BlobError::io("opening a blob", e)),
                };
                let bytes = file
                    .len()
                    .await
                    .map_err(|e| BlobError::io("reading a blob's length", e))?;
                report.objects += 1;
                report.bytes += bytes;
                if rooted.contains(&id) {
                    continue;
                }
                let erased = options.erased_now
                    && !self.mutation_sweep_ignores_erasures
                    && !options.dry_run
                    && header_subject(&*file)
                        .await
                        .is_some_and(|(subject, version)| roots.erased(&subject, version));
                if erased {
                    drop(file);
                    let _claim = dir.claim.lock().await;
                    match fs.remove_file(path).await {
                        Ok(()) => {
                            report.deleted += 1;
                            report.deleted_bytes += bytes;
                            report.erased_deleted += 1;
                            deleted_here = true;
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                        Err(e) => return Err(BlobError::io("deleting an erased blob", e)),
                    }
                    report.objects -= 1;
                    report.bytes -= bytes;
                    continue;
                }
                drop(file);
                if leased_at_start.contains(&id) {
                    continue;
                }
                let _claim = dir.claim.lock().await;
                let touched = !self.mutation_sweep_ignores_touches
                    && lock(&dir.gens)
                        .touched
                        .get(&name)
                        .is_some_and(|seq| *seq > start);
                let leased = !self.mutation_sweep_ignores_leases && self.leases().is_leased(&id);
                if touched || leased {
                    continue;
                }
                let candidate = previous.contains(&id);
                if options.dry_run {
                    report.unrooted.push(Unrooted {
                        id,
                        bytes,
                        candidate,
                    });
                    continue;
                }
                if !(options.immediate || candidate) {
                    next.insert(id);
                    continue;
                }
                match fs.remove_file(path).await {
                    Ok(()) => {
                        report.objects -= 1;
                        report.bytes -= bytes;
                        report.deleted += 1;
                        report.deleted_bytes += bytes;
                        deleted_here = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        report.objects -= 1;
                        report.bytes -= bytes;
                    }
                    Err(e) => return Err(BlobError::io("deleting a blob", e)),
                }
            }
            if deleted_here {
                fs.sync_dir(dir_path)
                    .await
                    .map_err(|e| BlobError::io("syncing a blob directory", e))?;
            }
            // A later pass begins after every touch so far: these no longer
            // matter.
            if !options.dry_run {
                lock(&dir.gens).touched.retain(|_, seq| *seq > start);
            }
        }
        if !options.dry_run {
            report.candidates = next.len() as u64;
            lock(&self.sweep.candidates).insert(root, next);
        }
        if report.deleted > 0 {
            tracing::info!(
                deleted = report.deleted,
                bytes = report.deleted_bytes,
                candidates = report.candidates,
                "deleted blobs nothing keeps"
            );
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
