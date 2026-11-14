//! The blob pass of `kronik privacy reseal` (M26 §9.4): every subject's blob
//! of main's store whose file is plain (written while the mode was `off`) is
//! sealed in place under its key version, and marked for the shipper to
//! upload again: `<data>/blobs/reupload/<name>`
//! ([`kronik_store::ship_blobs::REUPLOAD_DIR`]). The shipper replaces the
//! bucket's plain object with the sealed file and removes the mark; until
//! then `GET /v1/privacy` counts it in `reseal.pending_blobs`. Fork spaces are
//! not resealed: a fork's blobs go with the fork.

use std::path::Path;

use kronik_blob::{BlobError, BlobId, Resealed, Space};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_store::ship_blobs::reupload_dir;

use crate::Node;

/// Marks `id` for the shipper to upload again, durably: the shipper then
/// replaces the bucket's plain object with the sealed file.
fn mark_reupload(data: &Path, id: &BlobId) -> Result<(), BlobError> {
    let dir = reupload_dir(data);
    let failed = |what: &str, e: std::io::Error| BlobError::Io(format!("{what}: {e}"));
    std::fs::create_dir_all(&dir).map_err(|e| failed("creating the reupload directory", e))?;
    let path = dir.join(id.file_name());
    std::fs::File::create(&path)
        .and_then(|f| f.sync_all())
        .map_err(|e| failed("marking a blob for reupload", e))?;
    std::fs::File::open(&dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| failed("syncing the reupload directory", e))
}

/// Blobs a reseal sealed whose shipped object the shipper has not replaced
/// yet (`reseal.pending_blobs`).
pub fn pending_blob_reuploads(data: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(reupload_dir(data)) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| BlobId::from_file_name(n).is_some())
        })
        .count() as u64
}

impl Node {
    /// The subjects' blobs of main's store whose files are plain: what the
    /// reseal pass would seal (a dry run's count).
    pub(crate) async fn plain_subject_blobs(&self) -> Result<u64, ApiError> {
        let Some(store) = self.blob_store() else {
            return Ok(0);
        };
        let mut n = 0;
        for hash in self.subject_blob_rows()? {
            let Ok(id) = BlobId::parse(&hash) else {
                continue;
            };
            if store
                .is_plain_subject_file(&Space::Main, &id)
                .await
                .map_err(blob_error)?
                == Some(true)
            {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Seals every subject's plain blob file of main's store (M26 §9.4) and
    /// marks it for the shipper; returns how many it sealed. A blob whose
    /// subject was erased meanwhile is left to the erasure's deletion.
    pub(crate) async fn reseal_blobs(&self) -> Result<u64, ApiError> {
        let (Some(store), Some(data)) = (self.blob_store(), self.data_dir()) else {
            return Ok(0);
        };
        let keys = self.sealer.blob_key_access();
        let mut sealed = 0;
        for hash in self.subject_blob_rows()? {
            let Ok(id) = BlobId::parse(&hash) else {
                continue;
            };
            let mark = || mark_reupload(data, &id);
            match store
                .seal_in_place(&Space::Main, &id, &keys, &mark)
                .await
                .map_err(blob_error)?
            {
                Resealed::Sealed => sealed += 1,
                Resealed::Unchanged | Resealed::Erased => {}
            }
        }
        if sealed > 0 {
            tracing::info!(blobs = sealed, "resealed plain blob files");
        }
        Ok(sealed)
    }

    fn subject_blob_rows(&self) -> Result<Vec<String>, ApiError> {
        self.store()
            .db()
            .subject_blobs()
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reading the blobs: {e}")))
    }
}

fn blob_error(e: BlobError) -> ApiError {
    let code = match &e {
        BlobError::Corrupt { .. } => ErrorCode::StorageCorrupt,
        BlobError::KeyMissing(_) => ErrorCode::KeystoreIncomplete,
        _ => ErrorCode::Internal,
    };
    ApiError::new(code, format!("resealing blobs: {e}"))
}
