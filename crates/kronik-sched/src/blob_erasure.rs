//! The files of erased blobs (M26 §9.3). Applying an `Erasure` marks the
//! subject's rows of the blob index erased (in `kronik-store`); the node then
//! deletes their files at once, in main's store and in every fork space, and
//! writes nothing else. The collector would delete main's files in a later
//! pass, but a fork's roots or a snapshot's index keep a file from it, and
//! fork spaces are never swept: an erased blob's bytes must go now. The
//! rows stay (pins, holds and log references point at an erased blob) until
//! the collector forgets them.
//!
//! A *loose* file has no row: a blob a turn wrote and did not commit, or an
//! upload whose turn never came; a writer still writing has a part file.
//! The erasure cannot find those through the index. So every erasure waits
//! for the collector (review of log-integrity's blob DST, ruled by the
//! lead): a pass that begins after it was applied deletes every file
//! without a root whose header names an erased subject through its key
//! version (`SweepOptions::erased_now`), in main's store, and every such
//! file of every fork space. The erasure is done with once such a pass has
//! finished and no writer of the subject that began before the pass is
//! left; until then `privacy status` counts it as pending. The erasures done
//! with are kept as a watermark, `<data>/blobs/erasures-swept`.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use kronik_blob::{BlobId, Space};
use kronik_core::env::{Fs, OpenMode};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;
use kronik_core::sync::lock;

use crate::Node;

/// How often the collector looks again while a writer of an erased subject
/// is still writing: as often as a lease is renewed, at most.
const LOOSE_RETRY: Duration = Duration::from_secs(30);

/// The watermark file: every erasure at or below this LSN is done with.
fn swept_path(data: &Path) -> PathBuf {
    data.join("blobs").join("erasures-swept")
}

/// Reads the watermark; 0 when there is none or it does not parse.
async fn read_swept(fs: &dyn Fs, data: &Path) -> Lsn {
    let Ok(file) = fs.open(swept_path(data), OpenMode::Read).await else {
        return 0;
    };
    let Ok(bytes) = file.read_at(0, 21).await else {
        return 0;
    };
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// Writes the watermark durably: a fixed-width line written over the
/// previous one, through a part file and a rename.
async fn write_swept(fs: &dyn Fs, data: &Path, lsn: Lsn) -> std::io::Result<()> {
    fs.create_dir_all(data.join("blobs")).await?;
    let path = swept_path(data);
    let part = path.with_extension("part");
    crate::durable::replace(fs, part, path, format!("{lsn:020}\n").into_bytes()).await
}

/// The fork spaces of the data directory: every branch but `branch` that
/// has a blob space. Through the node's file system, so a simulation sees
/// the same directories as the rest of the node.
pub(crate) async fn fork_spaces(
    fs: &dyn Fs,
    data: &Path,
    branch: &str,
) -> Result<Vec<Space>, ApiError> {
    let branches = data.join("branches");
    let names = match fs.read_dir(branches.clone()).await {
        Ok(names) => names,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(ApiError::new(
                ErrorCode::Internal,
                format!("listing the branches: {e}"),
            ));
        }
    };
    let mut forks = Vec::new();
    for name in names {
        if name == branch {
            continue;
        }
        let has_space = fs
            .exists(branches.join(&name).join("blobs"))
            .await
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("a fork's blob space: {e}")))?;
        if has_space {
            forks.push(Space::Fork(name));
        }
    }
    forks.sort();
    Ok(forks)
}

impl Node {
    /// Deletes the files of every erased blob of the index, in main's store
    /// and in every fork space; returns how many files it deleted (none
    /// without a blob store). Idempotent: run after each erasure and at
    /// start, so a crash between an erasure's record and the deletion leaves
    /// no file behind.
    pub(crate) async fn delete_erased_blobs(&self) -> Result<u64, ApiError> {
        let Some(store) = self.blob_store() else {
            return Ok(0);
        };
        let internal =
            |what: &str, e: String| ApiError::new(ErrorCode::Internal, format!("{what}: {e}"));
        let hashes = self
            .store()
            .db()
            .erased_blobs()
            .map_err(|e| internal("reading the erased blobs", e.to_string()))?;
        if hashes.is_empty() {
            return Ok(0);
        }
        let ids: Vec<BlobId> = hashes
            .iter()
            .filter_map(|h| BlobId::parse(h).ok())
            .collect();
        let mut spaces = vec![Space::Main];
        if let Some(storage) = self.storage_config() {
            spaces.extend(fork_spaces(&*self.env.fs, &storage.data_dir, self.branch()).await?);
        }
        let mut deleted = 0;
        for space in spaces {
            let (files, bytes) = store
                .delete_erased(&space, &ids)
                .await
                .map_err(|e| internal("deleting erased blobs", e.to_string()))?;
            if files > 0 {
                tracing::info!(?space, files, bytes, "deleted the files of erased blobs");
            }
            deleted += files;
        }
        Ok(deleted)
    }

    /// The watermark of the erasures done with (module docs), read once
    /// from the data directory. A watermark above every erasure the index
    /// knows belongs to another history (a restore over this directory):
    /// it counts for nothing.
    async fn erasures_swept(&self) -> Result<Lsn, ApiError> {
        if let Some(lsn) = *lock(&self.blob_gc.erasures_swept) {
            return Ok(lsn);
        }
        let Some(data) = self.storage_config().map(|s| s.data_dir.clone()) else {
            return Ok(0);
        };
        let mut lsn = read_swept(&*self.env.fs, &data).await;
        let newest = self
            .store()
            .db()
            .erasure_records()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
            .into_iter()
            .map(|(_, _, at)| at)
            .max()
            .unwrap_or(0);
        if lsn > newest {
            lsn = 0;
        }
        let mut cached = lock(&self.blob_gc.erasures_swept);
        Ok(*cached.get_or_insert(lsn))
    }

    /// The erasures the collector has not done with yet (module docs):
    /// `(lsn, subject, key version)`, oldest first. None without a blob
    /// store: there are no blob files.
    pub(crate) async fn loose_erasures(&self) -> Result<Vec<(Lsn, String, u32)>, ApiError> {
        if self.blob_store().is_none() {
            return Ok(Vec::new());
        }
        let swept = self.erasures_swept().await?;
        let mut out: Vec<(Lsn, String, u32)> = self
            .store()
            .db()
            .erasure_records()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
            .into_iter()
            .filter(|(_, _, lsn)| *lsn > swept)
            .map(|(subject, version, lsn)| (lsn, subject, version))
            .collect();
        out.sort();
        Ok(out)
    }

    /// After a collector pass with `erased_now` over `loose` (the erasures
    /// it began with): the erasures it is done with are those below the
    /// first whose subject had a writer when it began (`writing`), which may
    /// still name a blob that no record references. Advances and stores the
    /// watermark; asks for another pass while a writer holds one back.
    pub(crate) async fn loose_swept(
        &self,
        loose: &[(Lsn, String, u32)],
        writing: &[kronik_blob::LiveWriter],
    ) -> Result<(), ApiError> {
        let Some(newest) = loose.last().map(|(lsn, _, _)| *lsn) else {
            return Ok(());
        };
        let held = loose
            .iter()
            .find(|(_, subject, version)| {
                writing
                    .iter()
                    .any(|w| w.subject.as_deref() == Some(subject) && w.key_version <= *version)
            })
            .map(|(lsn, _, _)| *lsn);
        let through = held.map_or(newest, |lsn| lsn - 1);
        let swept = self.erasures_swept().await?;
        if through > swept {
            if let Some(data) = self.storage_config().map(|s| s.data_dir.clone()) {
                write_swept(&*self.env.fs, &data, through)
                    .await
                    .map_err(|e| {
                        ApiError::new(
                            ErrorCode::Internal,
                            format!("writing the erasures the collector is done with: {e}"),
                        )
                    })?;
            }
            *lock(&self.blob_gc.erasures_swept) = Some(through);
        }
        if held.is_some() {
            self.wake_blob_gc_later(LOOSE_RETRY.min(self.blob_lease_ttl() / 4));
        }
        Ok(())
    }

    /// Wakes the collector for an erasure it has not done with yet: after
    /// one is applied, and at start.
    pub(crate) async fn wake_for_loose_erasures(&self) {
        match self.loose_erasures().await {
            Ok(loose) if !loose.is_empty() => self.wake_blob_gc(),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e.message, "reading the erasures for the collector"),
        }
    }

    /// Wakes the collector after `delay`, once at a time.
    fn wake_blob_gc_later(&self, delay: Duration) {
        if self.blob_gc.retry.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(node) = self.me() else {
            return;
        };
        let node = std::sync::Arc::downgrade(&node);
        let clock = self.env.clock.clone();
        drop(self.env.spawn("blob collector retry", async move {
            clock.sleep(delay).await;
            if let Some(node) = node.upgrade() {
                node.blob_gc.retry.store(false, Ordering::Release);
                node.wake_blob_gc();
            }
        }));
    }

    /// `[blobs] lease_ttl`; 5 minutes without a store.
    fn blob_lease_ttl(&self) -> Duration {
        self.blob_store()
            .map_or(Duration::from_secs(300), |store| store.lease_ttl())
    }

    /// [`Node::delete_erased_blobs`], whose failure is logged: the erasure or
    /// record that asked for it is done, and the next start and the
    /// collector try again.
    pub(crate) async fn delete_erased_blobs_logged(&self) -> u64 {
        match self.delete_erased_blobs().await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!(error = %e.message, "deleting the files of erased blobs failed");
                0
            }
        }
    }

    /// Per erased subject, its blobs that are not gone yet: how many still
    /// have a file on this node (main's store or a fork space) and how many
    /// an object in the bucket (the shipper's record; its step 6 deletes
    /// them, and the collector keeps their rows until it has). `privacy
    /// status` counts such an erasure as pending (M26 §9.3).
    pub(crate) async fn erased_blobs_left(
        &self,
    ) -> Result<std::collections::BTreeMap<String, BlobsLeft>, ApiError> {
        let internal =
            |what: &str, e: String| ApiError::new(ErrorCode::Internal, format!("{what}: {e}"));
        let rows = self
            .store()
            .db()
            .erased_subject_blobs()
            .map_err(|e| internal("reading the erased blobs", e.to_string()))?;
        let mut left: std::collections::BTreeMap<String, BlobsLeft> = Default::default();
        if rows.is_empty() {
            return Ok(left);
        }
        let data = self.storage_config().map(|s| s.data_dir.clone());
        let shipped = match &data {
            Some(data) => kronik_store::ship_blobs::shipped_names(data)
                .map_err(|e| internal("reading the shipper's blob record", e.to_string()))?,
            None => Default::default(),
        };
        let mut spaces = vec![Space::Main];
        if let Some(data) = &data {
            spaces.extend(fork_spaces(&*self.env.fs, data, self.branch()).await?);
        }
        for (hash, subject) in rows {
            let Ok(id) = BlobId::parse(&hash) else {
                continue;
            };
            let entry = left.entry(subject).or_default();
            if shipped.contains(&id.file_name()) {
                entry.objects += 1;
            }
            if let Some(store) = self.blob_store() {
                for space in &spaces {
                    if store
                        .contains(space, &id)
                        .await
                        .map_err(|e| internal("looking for an erased blob", e.to_string()))?
                    {
                        entry.files += 1;
                        break;
                    }
                }
            }
        }
        left.retain(|_, l| l.files + l.objects > 0);
        Ok(left)
    }
}

/// An erased subject's blobs that are not gone yet ([`Node::erased_blobs_left`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BlobsLeft {
    /// With a file on this node.
    pub files: u64,
    /// With an object in the bucket.
    pub objects: u64,
}
