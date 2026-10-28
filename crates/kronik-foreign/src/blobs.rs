//! The content-addressed blob store (m7-foreign §3):
//! `<data>/foreign/blobs/sha256/<hex>`, shared by all foreign actors.
//!
//! A blob only ever appears under its final name after its size and SHA-256
//! matched its descriptor: writes go to a temporary file in the same
//! directory, are verified, fsynced and renamed. Reads of small JSON blobs
//! verify again, because the store is a cache on a disk Kronik does not
//! fully control. All I/O is blocking `std::fs`; async callers run it on a
//! blocking thread.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::image::{ImageError, validate_digest};

/// An OCI content descriptor: what a blob must be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// The blob's media type (may be empty when the referrer did not say).
    pub media_type: String,
    /// `sha256:<64 lowercase hex>`.
    pub digest: String,
    /// Size in bytes.
    pub size: u64,
}

impl Descriptor {
    /// Reads a descriptor object (`mediaType`, `digest`, `size`) from JSON.
    pub fn from_json(v: &Value) -> Result<Self, ImageError> {
        let digest = v["digest"]
            .as_str()
            .ok_or_else(|| ImageError::Invalid("descriptor without digest".into()))?;
        validate_digest(digest)?;
        Ok(Self {
            media_type: v["mediaType"].as_str().unwrap_or_default().to_string(),
            digest: digest.to_string(),
            size: v["size"]
                .as_u64()
                .ok_or_else(|| ImageError::Invalid(format!("descriptor {digest} without size")))?,
        })
    }

    /// The descriptor as an OCI JSON object.
    pub fn to_json(&self) -> Value {
        json!({ "mediaType": self.media_type, "digest": self.digest, "size": self.size })
    }
}

/// `sha256:<hex>` of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A reader that hashes and counts everything read through it.
pub(crate) struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    /// Bytes read so far.
    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    /// `sha256:<hex>` of everything read.
    pub(crate) fn digest(self) -> String {
        format!("sha256:{}", hex(&self.hasher.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += n as u64;
        Ok(n)
    }
}

/// Distinguishes temporary files of concurrent writers in one process; the
/// process id distinguishes processes.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn io_error(what: impl std::fmt::Display, e: io::Error) -> ImageError {
    ImageError::Io(format!("{what}: {e}"))
}

/// A temporary blob file, removed when this goes out of scope: on an error,
/// a panic, or when the future writing it is dropped (`pull_timeout`, an
/// add whose request went away). After the rename to the blob's name the
/// removal finds nothing.
pub(crate) struct TempFile(pub PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The blob store rooted at a directory (normally `<data>/foreign/blobs`).
#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// A store rooted at `root`. Nothing is created until the first `put`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store's root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the blob with `digest` lives. Rejects anything but
    /// `sha256:<64 lowercase hex>`, so a digest never names another path.
    pub fn path(&self, digest: &str) -> Result<PathBuf, ImageError> {
        validate_digest(digest)?;
        Ok(self.dir().join(&digest["sha256:".len()..]))
    }

    /// The directory holding the blobs (`<root>/sha256`).
    pub(crate) fn dir(&self) -> PathBuf {
        self.root.join("sha256")
    }

    /// Whether the blob exists with the descriptor's size. The content is
    /// verified when it is read.
    pub fn has(&self, desc: &Descriptor) -> bool {
        self.path(&desc.digest)
            .ok()
            .and_then(|p| fs::symlink_metadata(p).ok())
            .is_some_and(|md| md.is_file() && md.len() == desc.size)
    }

    /// A fresh temporary path in the blob directory, for writers that verify
    /// on their own and then move the file to [`BlobStore::path`]. The
    /// directory is not created.
    pub(crate) fn temp_name(&self) -> PathBuf {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.dir().join(format!(".tmp-{}-{n}", std::process::id()))
    }

    /// Deletes every blob not in `keep` (digests) and every temporary file.
    /// The caller holds the manager's fetch lock exclusively, so no fetch
    /// writes or reuses a blob meanwhile. Returns how many it deleted.
    pub fn collect_garbage(&self, keep: &std::collections::HashSet<String>) -> usize {
        let Ok(entries) = fs::read_dir(self.dir()) else {
            return 0;
        };
        let mut deleted = 0;
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let digest = format!("sha256:{name}");
            let temp = name.starts_with(".tmp-");
            if !temp && (validate_digest(&digest).is_err() || keep.contains(&digest)) {
                continue;
            }
            if fs::remove_file(e.path()).is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    /// Deletes the temporary files a stopped or killed daemon left (at
    /// start, before anything writes). Returns how many.
    pub fn remove_temps(&self) -> usize {
        let Ok(entries) = fs::read_dir(self.dir()) else {
            return 0;
        };
        entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .filter(|e| fs::remove_file(e.path()).is_ok())
            .count()
    }

    /// Moves a verified, fsynced temporary file to its final name and makes
    /// the rename durable.
    fn commit(&self, temp: &Path, digest: &str) -> Result<(), ImageError> {
        let path = self.path(digest)?;
        fs::rename(temp, &path).map_err(|e| io_error(format!("rename {}", path.display()), e))?;
        let dir = self.dir();
        File::open(&dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| io_error(format!("fsync {}", dir.display()), e))
    }

    /// Whether the blob exists and its content matches `desc`, reading it
    /// whole. A present but corrupt blob is removed so it can be fetched
    /// again.
    pub fn has_verified(&self, desc: &Descriptor) -> bool {
        if !self.has(desc) {
            return false;
        }
        if self.verify(desc).is_ok() {
            return true;
        }
        if let Ok(path) = self.path(&desc.digest) {
            tracing::warn!(digest = %desc.digest, "removing a corrupt blob from the store");
            let _ = fs::remove_file(path);
        }
        false
    }

    /// Streams a blob into the store and keeps it only if its size and
    /// SHA-256 match `desc`. At most `desc.size + 1` bytes are read from
    /// `reader`, so an oversized source is detected without reading it all.
    /// A blob that is already present and intact is not rewritten (`reader`
    /// is not read).
    pub fn put(&self, desc: &Descriptor, reader: impl Read) -> Result<(), ImageError> {
        if self.has_verified(desc) {
            return Ok(());
        }
        let dir = self.dir();
        fs::create_dir_all(&dir).map_err(|e| io_error(format!("create {}", dir.display()), e))?;
        let temp = TempFile(self.temp_name());
        // Removed on every exit but the rename, also on a panic.
        self.put_temp(&temp.0, desc, reader)
    }

    fn put_temp(
        &self,
        temp: &Path,
        desc: &Descriptor,
        reader: impl Read,
    ) -> Result<(), ImageError> {
        let what = || format!("write {}", temp.display());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(temp)
            .map_err(|e| io_error(what(), e))?;
        let mut hashing = HashingReader::new(reader.take(desc.size.saturating_add(1)));
        // Errors of the source (network, layout) are not local disk problems,
        // so read and write separately to classify them.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match hashing.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(ImageError::Invalid(format!(
                        "read blob {}: {e}",
                        desc.digest
                    )));
                }
            };
            file.write_all(&buf[..n]).map_err(|e| io_error(what(), e))?;
        }
        let n = hashing.count();
        let actual = hashing.digest();
        check(desc, n, &actual)?;
        file.sync_all().map_err(|e| io_error(what(), e))?;
        drop(file);
        self.commit(temp, &desc.digest)
    }

    /// Opens a blob for streaming. The caller verifies what it reads (see
    /// [`BlobStore::verify`]).
    pub fn open(&self, desc: &Descriptor) -> Result<File, ImageError> {
        let path = self.path(&desc.digest)?;
        File::open(&path).map_err(|e| missing_or_io(&path, &desc.digest, e))
    }

    /// Streams a whole blob through SHA-256 and checks size and digest.
    pub fn verify(&self, desc: &Descriptor) -> Result<(), ImageError> {
        let path = self.path(&desc.digest)?;
        let file = self.open(desc)?;
        let mut hashing =
            HashingReader::new(BufReader::new(file).take(desc.size.saturating_add(1)));
        io::copy(&mut hashing, &mut io::sink())
            .map_err(|e| io_error(format!("read {}", path.display()), e))?;
        let n = hashing.count();
        check(desc, n, &hashing.digest())
    }

    /// Reads a small blob (index, manifest, config) of at most `max` bytes
    /// and checks its size and digest.
    pub fn read_small(&self, desc: &Descriptor, max: u64) -> Result<Vec<u8>, ImageError> {
        if desc.size > max {
            return Err(ImageError::Invalid(format!(
                "blob {} has {} bytes, more than the {max} allowed",
                desc.digest, desc.size
            )));
        }
        let bytes = self.read_capped(&desc.digest, desc.size)?;
        check(desc, bytes.len() as u64, &sha256_digest(&bytes))?;
        Ok(bytes)
    }

    /// Reads a small blob known only by its digest (at most `max` bytes)
    /// and checks the digest.
    pub fn read_digest(&self, digest: &str, max: u64) -> Result<Vec<u8>, ImageError> {
        let bytes = self.read_capped(digest, max)?;
        if bytes.len() as u64 > max {
            return Err(ImageError::Invalid(format!(
                "blob {digest} is larger than the {max} bytes allowed"
            )));
        }
        let actual = sha256_digest(&bytes);
        if actual != digest {
            return Err(ImageError::Invalid(format!(
                "blob {digest} failed verification: its digest is {actual}"
            )));
        }
        Ok(bytes)
    }

    /// Reads up to `max + 1` bytes of a blob.
    fn read_capped(&self, digest: &str, max: u64) -> Result<Vec<u8>, ImageError> {
        let path = self.path(digest)?;
        let file = File::open(&path).map_err(|e| missing_or_io(&path, digest, e))?;
        let mut bytes = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io_error(format!("read {}", path.display()), e))?;
        Ok(bytes)
    }
}

fn missing_or_io(path: &Path, digest: &str, e: io::Error) -> ImageError {
    if e.kind() == io::ErrorKind::NotFound {
        ImageError::Invalid(format!("blob {digest} is not in the blob store"))
    } else {
        io_error(format!("open {}", path.display()), e)
    }
}

/// Checks a blob's observed size and digest against its descriptor.
pub(crate) fn check(desc: &Descriptor, size: u64, digest: &str) -> Result<(), ImageError> {
    if size != desc.size {
        return Err(ImageError::Invalid(format!(
            "blob {} has {}{size} bytes, its descriptor says {}",
            desc.digest,
            if size > desc.size { "more than " } else { "" },
            desc.size
        )));
    }
    if digest != desc.digest {
        return Err(ImageError::Invalid(format!(
            "blob {} failed verification: its digest is {digest}",
            desc.digest
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::Builder::new()
            .prefix("km7-blobs-")
            .tempdir_in(std::env::temp_dir())
            .unwrap();
        let store = BlobStore::new(dir.path().join("blobs"));
        (dir, store)
    }

    fn desc(bytes: &[u8]) -> Descriptor {
        Descriptor {
            media_type: "application/octet-stream".into(),
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
        }
    }

    fn leftovers(store: &BlobStore) -> Vec<String> {
        fs::read_dir(store.root().join("sha256"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn put_verifies_and_keeps_good_blobs() {
        let (_dir, store) = store();
        let d = desc(b"hello");
        assert!(!store.has(&d));
        store.put(&d, &b"hello"[..]).unwrap();
        assert!(store.has(&d));
        assert_eq!(store.read_small(&d, 100).unwrap(), b"hello");
        assert_eq!(store.read_digest(&d.digest, 100).unwrap(), b"hello");
        store.verify(&d).unwrap();
        assert_eq!(leftovers(&store), [&d.digest[7..]]);
    }

    #[test]
    fn garbage_collection_keeps_named_blobs_only() {
        let (_dir, store) = store();
        let (a, b) = (desc(b"kept"), desc(b"dropped"));
        store.put(&a, &b"kept"[..]).unwrap();
        store.put(&b, &b"dropped"[..]).unwrap();
        let keep: std::collections::HashSet<String> = [a.digest.clone()].into();
        // A temporary file (a fetch that was dropped) goes too.
        fs::write(store.dir().join(".tmp-1-1"), b"partial").unwrap();
        assert_eq!(store.collect_garbage(&keep), 2);
        assert!(store.has(&a) && !store.has(&b));
        fs::write(store.dir().join(".tmp-1-2"), b"partial").unwrap();
        assert_eq!(store.remove_temps(), 1);
        assert_eq!(leftovers(&store), [&a.digest[7..]]);
    }

    #[test]
    fn put_rejects_wrong_content_and_leaves_nothing() {
        let (_dir, store) = store();
        let d = desc(b"hello");
        assert!(store.put(&d, &b"hellO"[..]).is_err());
        assert!(store.put(&d, &b"hello!"[..]).is_err());
        assert!(store.put(&d, &b"hell"[..]).is_err());
        assert!(!store.has(&d));
        assert!(leftovers(&store).is_empty());
    }

    #[test]
    fn tampered_blobs_fail_reads() {
        let (_dir, store) = store();
        let d = desc(b"{}");
        store.put(&d, &b"{}"[..]).unwrap();
        let path = store.path(&d.digest).unwrap();
        fs::write(&path, b"{ }").unwrap();
        assert!(store.read_small(&d, 100).is_err());
        assert!(store.read_digest(&d.digest, 100).is_err());
        assert!(store.verify(&d).is_err());
        assert!(store.read_small(&d, 1).is_err());
    }

    #[test]
    fn paths_only_accept_sha256() {
        let (_dir, store) = store();
        assert!(store.path("sha256:../../etc/passwd").is_err());
        assert!(store.path("md5:00").is_err());
        assert!(store.path(&format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(store.path(&format!("sha256:{}", "a".repeat(64))).is_ok());
    }
}
