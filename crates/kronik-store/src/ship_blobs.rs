//! A read-only view of the shipper's `<data>/ship-blobs.db` (ADR 0122 §2):
//! which blob objects are in the bucket. kronik-ship owns the file and
//! writes it; the collector and privacy status read it here, as they do not
//! depend on the shipper.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::StoreError;

/// `<data>/ship-blobs.db`.
pub fn path(data: &Path) -> PathBuf {
    data.join("ship-blobs.db")
}

/// Where `privacy reseal` marks a blob it sealed in place (M26 §9.4), below
/// the data directory: one empty file per blob, named as the blob's file.
/// The shipper uploads the sealed file over the bucket's plain object and
/// removes the mark.
pub const REUPLOAD_DIR: &str = "blobs/reupload";

/// `<data>/blobs/reupload`.
pub fn reupload_dir(data: &Path) -> PathBuf {
    data.join(REUPLOAD_DIR)
}

/// The file names (`b3-<hex>`, `b3s-<hex>`) of the blobs the shipper has
/// uploaded and not yet deleted from the bucket; none when it never shipped
/// a blob.
pub fn shipped_names(data: &Path) -> Result<BTreeSet<String>, StoreError> {
    let path = path(data);
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let conn = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let has: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'shipped')",
        [],
        |r| r.get(0),
    )?;
    if !has {
        return Ok(BTreeSet::new());
    }
    let mut st = conn.prepare("SELECT name FROM shipped")?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}
