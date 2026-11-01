//! Ordinary native reader resource registration, not source qualification or writer authority.
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use kronik_core::authority::Authority;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::snapshot_resources::{SnapshotRootPin, SnapshotRootRegistry};
use crate::node::Node;

fn unavailable(message: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Unavailable, message.to_string())
}
fn io(error: std::io::Error) -> ApiError { unavailable(error) }
fn same_directory(path: &Path, original: &File) -> Result<(), ApiError> {
    use std::os::unix::fs::MetadataExt;
    let actual = fs::metadata(path).map_err(io)?;
    let held = original.metadata().map_err(io)?;
    if !actual.is_dir() || !held.is_dir() || actual.dev() != held.dev() || actual.ino() != held.ino() {
        return Err(unavailable("native source directory no longer names its original owned resource"));
    }
    Ok(())
}
impl Node {
    fn native_source_directory(&self) -> Result<(PathBuf, Arc<File>), ApiError> {
        self.native_execution.check()?;
        let storage = self.cfg.storage.as_ref().ok_or_else(|| unavailable("native source storage is not configured"))?;
        let original = self.native_execution.ownership().ok_or_else(|| unavailable("native source has no original directory ownership"))?;
        let root = fs::canonicalize(&storage.data_dir).map_err(io)?;
        same_directory(&root, &original)?;
        if !fs::canonicalize(self.reader().dir()).map_err(io)?.starts_with(&root) {
            return Err(unavailable("native WAL is outside its original owned source directory"));
        }
        Ok((root, original))
    }
    pub(crate) fn retain_native_source_paths(&self) -> Result<SnapshotRootPin, ApiError> {
        let (root, _original) = self.native_source_directory()?;
        SnapshotRootRegistry::retain(&self.native_execution.source_roots(), vec![root]).map_err(unavailable)
    }
}
