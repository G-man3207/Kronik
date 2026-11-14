//! The files of erased blobs (M26 §9.3). Applying an `Erasure` marks the
//! subject's rows of the blob index erased (in `kronik-store`); the node then
//! deletes their files at once, in main's store and in every fork space, and
//! writes nothing else. The collector would delete main's files in a later
//! pass, but a fork's roots or a snapshot's index keep a file from it, and
//! fork spaces are never swept: an erased blob's bytes must go now. The
//! rows stay (pins, holds and log references point at an erased blob) until
//! the collector forgets them.

use std::path::Path;

use kronik_blob::{BlobId, Space};
use kronik_core::error::{ApiError, ErrorCode};

use crate::Node;

/// The fork spaces of the data directory: every branch but `branch` that
/// has a blob space.
fn fork_spaces(data: &Path, branch: &str) -> Vec<Space> {
    let Ok(dir) = std::fs::read_dir(data.join("branches")) else {
        return Vec::new();
    };
    let mut forks: Vec<Space> = dir
        .flatten()
        .filter(|e| e.file_name() != branch && e.path().join("blobs").is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .map(Space::Fork)
        .collect();
    forks.sort();
    forks
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
            spaces.extend(fork_spaces(&storage.data_dir, self.branch()));
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
}
