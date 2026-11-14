//! The blob store (M25/M26, ADR 0117): content-addressed files for large
//! HTTP bodies, large effect responses and apps' blobs, outside the log.
//!
//! ```text
//! <data>/blobs/objects/<2 hex>/<name>   immutable blob files, 256 shard directories
//! <data>/blobs/tmp/<16 hex>.part        files being written
//! <data>/branches/<fork>/blobs/...      a fork's own space, the same layout
//! ```
//!
//! `<name>` is `b3-<64 hex>` for a blob without a subject (BLAKE3 of its
//! content) and `b3s-<64 hex>` for a subject's blob (BLAKE3 keyed per subject,
//! ADR 0118). A file is a 512-byte header and frames of 64 KiB of plaintext,
//! each with a CRC32C, or sealed with XChaCha20-Poly1305 ([`format`]).
//!
//! Durability (ADR 0117 §4): content is synced before its name exists (a
//! writer's [`BlobWriter::finish`] syncs the part file, then renames it), and
//! a name is synced before any record refers to it ([`BlobStore::ensure_durable`]).
//! A crash leaves at most loose bytes: a part file, which the next
//! [`BlobStore::open`] deletes, or an object nothing references, which the
//! collector removes. It never leaves a reference without its bytes.
//!
//! All I/O goes through [`kronik_core::env::Env`], so the simulator can crash
//! the store at every step. The crate holds no key: callers pass the keys of a
//! subject's blob ([`BlobKeys`], [`KeyAccess`]).

mod budget;
mod erase;
pub mod format;
mod id;
mod lease;
mod store;
mod sweep;

pub use budget::SpaceBudget;
pub use id::{BlobId, BlobMeta};
pub use lease::{Lease, Leases};
pub use store::{
    BlobKeys, BlobReader, BlobStore, BlobWriter, KeyAccess, KeyAnswer, NoKeys, Space, StoreConfig,
};
pub use sweep::{Roots, SweepOptions, SweepReport, Unrooted};

/// Why a blob operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// A blob is not in the store (`BLOB_MISSING` for a committed reference).
    #[error("blob {0} is not in the blob store")]
    NotFound(BlobId),
    /// A blob file failed a check: `STORAGE_CORRUPT`, never wrong bytes.
    #[error("STORAGE_CORRUPT: blob {id}: {why}")]
    Corrupt { id: BlobId, why: String },
    /// The blob store's file system is below `[blobs] disk_reserve`, or full.
    #[error(
        "the blob store's file system has {} MiB free, less than its reserve of {} MiB",
        free >> 20,
        reserve >> 20
    )]
    StoreFull { free: u64, reserve: u64 },
    /// The blob belongs to an erased subject (`SUBJECT_ERASED`).
    #[error("SUBJECT_ERASED: the blob belonged to an erased subject")]
    Erased,
    /// A sealed blob's key is not in this node's keystore (`KEYSTORE_INCOMPLETE`).
    #[error(
        "KEYSTORE_INCOMPLETE: a sealed blob of subject {0} cannot be opened: its key is not in this node's privacy keystore"
    )]
    KeyMissing(String),
    /// A writer went over its limit.
    #[error("the blob is over its limit of {limit} bytes")]
    TooLarge { limit: u64 },
    /// A writer went over its space's budget ([`SpaceBudget`]): a preview's
    /// blob space is full.
    #[error("the blob space holds at most {limit} bytes of blobs")]
    SpaceFull { limit: u64 },
    /// A malformed identity, reference or argument.
    #[error("invalid blob: {0}")]
    Invalid(String),
    /// The file system failed.
    #[error("blob store I/O failed: {0}")]
    Io(String),
}

impl BlobError {
    pub(crate) fn io(what: &str, error: std::io::Error) -> BlobError {
        if error.kind() == std::io::ErrorKind::StorageFull {
            return BlobError::StoreFull {
                free: 0,
                reserve: 0,
            };
        }
        BlobError::Io(format!("{what}: {error}"))
    }
}
