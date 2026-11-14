//! Shipping and restoring blobs (ADR 0122, M26 §8).
//!
//! ```text
//! <prefix>/blobs/<2 hex>/<name>    one object per blob: the local file's bytes
//! ```
//!
//! Main's store only; objects are the files as stored, not compressed.
//! `<data>/ship-blobs.db` records what was uploaded (node-local, like
//! `ship.json`; never shipped or restored). A round uploads the blobs that
//! the segments and snapshots it uploads reference before them, and deletes
//! the remote objects of blobs gone locally only after the remote snapshots
//! and segments gone locally are deleted (ADR 0122 §3). A referenced blob
//! whose file the node has lost ships as a reference only, and is recorded
//! (ADR 0122, amended 2026-11-14). A restore downloads
//! the snapshot's `blobs.idx` and every blob the staged segments reference,
//! and checks each before anything moves into place (ADR 0122 §5).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use kronik_blob::format::{self, FrameKey, HEADER_LEN, Header};
use kronik_blob::{BlobId, BlobMeta, KeyAccess, KeyAnswer};
use kronik_core::ids::Lsn;
use kronik_proto::log::v1 as pb;
use object_store::{ObjectStoreExt as _, PutPayload};
use rusqlite::{OptionalExtension, params};

use crate::{Remote, ShipError};

/// Uploads larger than this are multipart uploads of parts this large, read
/// from the local file (ADR 0122 §1): the shipper's memory stays bounded.
pub(crate) const PART_BYTES: u64 = 8 << 20;

/// The object of a blob, below the remote's prefix.
pub(crate) fn remote_name(id: &BlobId) -> String {
    format!("blobs/{}/{}", id.shard(), id.file_name())
}

/// Main's local file of a blob.
pub(crate) fn local_path(data: &Path, id: &BlobId) -> PathBuf {
    data.join("blobs/objects")
        .join(id.shard())
        .join(id.file_name())
}

/// `<data>/ship-blobs.db`: `shipped (name, body_digest)`.
pub(crate) struct Shipped {
    // A mutex makes the handle `Sync`, so that a round's future, which
    // holds it across uploads, is `Send`; no lock is held across an await.
    conn: std::sync::Mutex<rusqlite::Connection>,
}

fn locked(
    m: &std::sync::Mutex<rusqlite::Connection>,
) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shipped {
    pub(crate) fn path(data: &Path) -> PathBuf {
        data.join("ship-blobs.db")
    }

    pub(crate) fn open(data: &Path) -> Result<Shipped, ShipError> {
        let conn = rusqlite::Connection::open(Self::path(data)).map_err(sqlite)?;
        // `missing`: referenced blobs whose file this node no longer has; their
        // references shipped without them (ADR 0122, amended 2026-11-14).
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS shipped (
               name TEXT PRIMARY KEY, body_digest BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS missing (name TEXT PRIMARY KEY) WITHOUT ROWID;",
        )
        .map_err(sqlite)?;
        Ok(Shipped {
            conn: std::sync::Mutex::new(conn),
        })
    }

    fn digest(&self, name: &str) -> Result<Option<Vec<u8>>, ShipError> {
        locked(&self.conn)
            .query_row(
                "SELECT body_digest FROM shipped WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .optional()
            .map_err(sqlite)
    }

    fn put(&self, name: &str, digest: &[u8]) -> Result<(), ShipError> {
        locked(&self.conn)
            .execute(
                "INSERT OR REPLACE INTO shipped (name, body_digest) VALUES (?1, ?2)",
                params![name, digest],
            )
            .map_err(sqlite)?;
        Ok(())
    }

    /// Marks a row whose object is being deleted: an empty digest matches
    /// no file, so a blob referenced again before the deletion's end is
    /// uploaded again, and the row stays until the object is gone.
    fn mark_deleting(&self, name: &str) -> Result<(), ShipError> {
        locked(&self.conn)
            .execute(
                "UPDATE shipped SET body_digest = x'' WHERE name = ?1",
                [name],
            )
            .map_err(sqlite)?;
        Ok(())
    }

    /// Records a referenced blob whose file is missing; `true` the first
    /// time.
    fn note_missing(&self, name: &str) -> Result<bool, ShipError> {
        Ok(locked(&self.conn)
            .execute("INSERT OR IGNORE INTO missing (name) VALUES (?1)", [name])
            .map_err(sqlite)?
            > 0)
    }

    fn found(&self, name: &str) -> Result<(), ShipError> {
        locked(&self.conn)
            .execute("DELETE FROM missing WHERE name = ?1", [name])
            .map_err(sqlite)?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), ShipError> {
        locked(&self.conn)
            .execute("DELETE FROM shipped WHERE name = ?1", [name])
            .map_err(sqlite)?;
        Ok(())
    }

    fn names(&self) -> Result<Vec<String>, ShipError> {
        let conn = locked(&self.conn);
        let mut st = conn
            .prepare("SELECT name FROM shipped ORDER BY name")
            .map_err(sqlite)?;
        let rows = st.query_map([], |r| r.get(0)).map_err(sqlite)?;
        rows.collect::<Result<_, _>>().map_err(sqlite)
    }
}

/// The file names (`b3-<hex>`, `b3s-<hex>`) of the blobs whose objects the
/// shipper has uploaded and not yet deleted from the bucket; none when it
/// never shipped a blob. For `privacy status`: an erased subject's blob is
/// gone remotely once its name has left this set (ADR 0122 §4).
pub fn shipped_blob_names(data: &Path) -> Result<BTreeSet<String>, ShipError> {
    if !Shipped::path(data).exists() {
        return Ok(BTreeSet::new());
    }
    Ok(Shipped::open(data)?.names()?.into_iter().collect())
}

fn sqlite(e: rusqlite::Error) -> ShipError {
    ShipError::Io(std::io::Error::other(format!("ship-blobs.db: {e}")))
}

/// What the local index says about a blob, read from `state.db` without
/// changing it. A state without the blob tables knows no blob.
pub(crate) struct Index {
    conn: Option<std::sync::Mutex<rusqlite::Connection>>,
}

/// One blob of the local index.
pub(crate) enum Indexed {
    Absent,
    Erased,
    Live,
}

impl Index {
    pub(crate) fn open(state_db: &Path) -> Result<Index, ShipError> {
        if !state_db.exists() {
            return Ok(Index { conn: None });
        }
        let conn = rusqlite::Connection::open_with_flags(
            state_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite)?;
        let has: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'blobs')",
                [],
                |r| r.get(0),
            )
            .map_err(sqlite)?;
        Ok(Index {
            conn: has.then(|| std::sync::Mutex::new(conn)),
        })
    }

    pub(crate) fn get(&self, hash: &str) -> Result<Indexed, ShipError> {
        let Some(conn) = &self.conn else {
            return Ok(Indexed::Absent);
        };
        let erased: Option<bool> = locked(conn)
            .query_row("SELECT erased FROM blobs WHERE hash = ?1", [hash], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sqlite)?;
        Ok(match erased {
            None => Indexed::Absent,
            Some(true) => Indexed::Erased,
            Some(false) => Indexed::Live,
        })
    }

    /// Live blobs the index knows that were not uploaded
    /// (`kronik_blob_ship_pending`).
    pub(crate) fn pending(&self, shipped: &Shipped) -> Result<u64, ShipError> {
        let Some(conn) = &self.conn else {
            return Ok(0);
        };
        let done: BTreeSet<String> = shipped.names()?.into_iter().collect();
        let conn = locked(conn);
        let mut st = conn
            .prepare("SELECT hash FROM blobs WHERE erased = 0")
            .map_err(sqlite)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite)?;
        let mut pending = 0;
        for hash in rows {
            let hash = hash.map_err(sqlite)?;
            if let Ok(id) = BlobId::parse(&hash)
                && !done.contains(&id.file_name())
            {
                pending += 1;
            }
        }
        Ok(pending)
    }
}

/// The identities a roots file (`blobs.idx`) lists; none when it is absent.
pub(crate) fn roots_file(path: &Path) -> Result<Vec<BlobId>, ShipError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text
            .lines()
            .filter_map(|l| BlobId::parse(l.trim()).ok())
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// The header of a stored blob file.
fn read_header(file: &std::fs::File) -> Result<Header, String> {
    let mut bytes = vec![0u8; HEADER_LEN];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|e| format!("reading its header: {e}"))?;
    Header::decode(&bytes)
}

/// What [`ship_blob`] did with one blob.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlobShipped {
    /// Uploaded, this many bytes.
    Uploaded(u64),
    /// In the bucket already, or of an erased subject: nothing to do.
    Nothing,
    /// The node has no file for it: its reference ships without it.
    /// `first` the first time a round finds it so.
    Missing { first: bool },
}

/// Uploads one blob that a segment or snapshot of this round references,
/// unless it was uploaded with the same body digest. An erased subject's
/// blob is never uploaded. A blob whose file is gone is one the node itself
/// reads as missing (BLOB_MISSING): the reference ships without it and the
/// blob is recorded in `missing` (ADR 0122, amended 2026-11-14), so that one
/// lost file does not stop every later segment and snapshot. A blob whose
/// file exists is never referenced in the bucket before it is there.
pub(crate) async fn ship_blob(
    remote: &Remote,
    data: &Path,
    shipped: &Shipped,
    index: &Index,
    id: &BlobId,
) -> Result<BlobShipped, ShipError> {
    if matches!(index.get(&id.to_string())?, Indexed::Erased) {
        return Ok(BlobShipped::Nothing);
    }
    let path = local_path(data, id);
    let name = id.file_name();
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BlobShipped::Missing {
                first: shipped.note_missing(&name)?,
            });
        }
        Err(e) => return Err(e.into()),
    };
    shipped.found(&name)?;
    let header =
        read_header(&file).map_err(|why| ShipError::Restore(format!("blob {id}: {why}")))?;
    let digest = header.body_digest;
    if shipped.digest(&name)?.as_deref() == Some(digest.as_slice()) {
        return Ok(BlobShipped::Nothing);
    }
    let rel = remote_name(id);
    // Without a record (a lost ship-blobs.db, a restored node) the bucket may
    // hold it already: taken as it is only when its header has this file's
    // body digest. An object of a file that changed since is replaced.
    if shipped.digest(&name)?.is_none()
        && remote
            .header(&rel)
            .await?
            .is_some_and(|remote| remote.body_digest == digest)
    {
        shipped.put(&name, &digest)?;
        return Ok(BlobShipped::Nothing);
    }
    let len = file.metadata()?.len();
    remote.put_file(&rel, &file, len).await?;
    shipped.put(&name, &digest)?;
    Ok(BlobShipped::Uploaded(len))
}

/// The blobs whose references shipped without them: their files were
/// missing (ADR 0122, amended 2026-11-14). File names; none without a
/// ship-blobs.db.
pub fn missing_blob_names(data: &Path) -> Result<BTreeSet<String>, ShipError> {
    if !Shipped::path(data).exists() {
        return Ok(BTreeSet::new());
    }
    let shipped = Shipped::open(data)?;
    let conn = locked(&shipped.conn);
    let mut st = conn
        .prepare("SELECT name FROM missing ORDER BY name")
        .map_err(sqlite)?;
    let rows = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(sqlite)?;
    rows.collect::<Result<_, _>>().map_err(sqlite)
}

/// Step 6 of a round (ADR 0122 §3): deletes the remote objects of blobs
/// whose local file is gone, that have no live index row, and that no local
/// snapshot's `blobs.idx` lists. A shipped blob whose file is gone while its
/// row is live was not collected: its object stays, and it is logged and
/// counted. Returns how many objects it deleted.
pub(crate) async fn delete_gone(
    remote: &Remote,
    data: &Path,
    shipped: &Shipped,
    index: &Index,
    snapshot_roots: &BTreeSet<String>,
    fault: &(dyn Fn(&str) -> std::io::Result<()> + Sync),
) -> Result<u64, ShipError> {
    let mut deleted = 0;
    for name in shipped.names()? {
        let Some(id) = BlobId::from_file_name(&name) else {
            continue;
        };
        if local_path(data, &id).exists() || snapshot_roots.contains(&name) {
            continue;
        }
        match index.get(&id.to_string())? {
            Indexed::Live => {
                tracing::error!(
                    blob = %id,
                    "a shipped blob's file is gone while its index row is live; its object stays"
                );
                kronik_metrics::inc("kronik_blob_missing_total", &[]);
            }
            Indexed::Absent | Indexed::Erased => {
                // Marked first: a crash after the deletion leaves a row
                // that matches no file, so the blob is uploaded again if a
                // record references it before the next round's step 6.
                shipped.mark_deleting(&name)?;
                remote.delete_object(&remote_name(&id)).await?;
                fault("blob-deleted")?;
                shipped.remove(&name)?;
                deleted += 1;
            }
        }
    }
    Ok(deleted)
}

/// The blob references of a segment's records.
pub(crate) fn segment_refs(
    bytes: &[u8],
    branch: &str,
    start: Lsn,
    out: &mut BTreeMap<String, pb::BlobRef>,
) -> Result<(), ShipError> {
    // The active segment may end in a record being written.
    kronik_log::scan_segment_image(bytes, branch, start, 0, Lsn::MAX, true, |c| {
        for r in kronik_proto::blobs::refs(&c.record) {
            out.entry(r.hash.clone()).or_insert_with(|| r.clone());
        }
        Ok::<_, kronik_log::LogError>(())
    })
    .map(|_| ())
    .map_err(|e| ShipError::Restore(format!("segment {start}: {e}")))
}

/// What a restore did with blobs.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BlobRestore {
    /// Blobs downloaded and checked, and their bytes.
    pub restored: u64,
    pub bytes: u64,
    /// Blobs of erased subjects: not downloaded.
    pub erased: u64,
    /// With `--allow-missing-blobs`: the blobs the bucket lacked or that
    /// failed their check; the node reads them as `BLOB_MISSING`.
    pub missing: Vec<String>,
}

/// The blobs a restore staged, before the keystore step and the decision
/// on what failed.
#[derive(Debug, Default)]
pub(crate) struct StagedBlobs {
    pub(crate) restored: u64,
    pub(crate) bytes: u64,
    pub(crate) erased: u64,
    /// Missing from the bucket, or failing their check: (hash, why).
    pub(crate) failed: Vec<(String, String)>,
}

/// The `(subject, key version)` erasures of the snapshot's state.
fn snapshot_erasures(conn: &rusqlite::Connection) -> Result<Vec<(String, u32)>, ShipError> {
    let has: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'erasures')",
            [],
            |r| r.get(0),
        )
        .map_err(sqlite)?;
    if !has {
        return Ok(Vec::new());
    }
    let mut st = conn
        .prepare("SELECT subject, key_version FROM erasures")
        .map_err(sqlite)?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?)))
        .map_err(sqlite)?;
    rows.collect::<Result<_, _>>().map_err(sqlite)
}

/// Downloads into `stage/blobs` the blobs the restored state and log
/// reference (ADR 0122 §5): the snapshot's `blobs.idx` and `refs`, the
/// staged segments' references. A blob of a subject erased through its key
/// version (by the log's `erasures` or in the snapshot's state) is counted,
/// not downloaded. Each blob is checked without keys; a subject's blob is
/// returned to be checked with its keys in the keystore step.
pub(crate) async fn stage(
    remote: &Remote,
    stage: &Path,
    snap: &Path,
    refs: &BTreeMap<String, pb::BlobRef>,
    erasures: &[(String, u32, u64)],
) -> Result<(StagedBlobs, Vec<(BlobMeta, PathBuf)>), ShipError> {
    let mut staged = StagedBlobs::default();
    let mut wanted = refs.clone();
    let mut erased_through: BTreeMap<String, u32> = BTreeMap::new();
    for (subject, version, _) in erasures {
        let v = erased_through.entry(subject.clone()).or_default();
        *v = (*v).max(*version);
    }
    let state = snap.join("state.db");
    if state.exists() {
        let conn = rusqlite::Connection::open_with_flags(
            &state,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite)?;
        for (subject, version) in snapshot_erasures(&conn)? {
            let v = erased_through.entry(subject).or_default();
            *v = (*v).max(version);
        }
        let listed = roots_file(&snap.join("blobs.idx"))?;
        if !listed.is_empty() {
            let mut st = conn
                .prepare("SELECT size, subject, key_version FROM blobs WHERE hash = ?1")
                .map_err(sqlite)?;
            for id in listed {
                let hash = id.to_string();
                if wanted.contains_key(&hash) {
                    continue;
                }
                let row: Option<(i64, Option<String>, u32)> = st
                    .query_row([&hash], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .optional()
                    .map_err(sqlite)?;
                match row {
                    Some((size, subject, key_version)) => {
                        wanted.insert(
                            hash.clone(),
                            pb::BlobRef {
                                hash,
                                size: size as u64,
                                subject,
                                key_version,
                            },
                        );
                    }
                    None => staged.failed.push((
                        hash,
                        "the snapshot's blobs.idx lists it and its state does not".into(),
                    )),
                }
            }
        }
    }
    let mut keyed = Vec::new();
    for (hash, r) in wanted {
        let meta = match BlobMeta::from_pb(&r) {
            Ok(meta) => meta,
            Err(e) => {
                staged.failed.push((hash, e.to_string()));
                continue;
            }
        };
        if let Some(subject) = &meta.subject
            && erased_through
                .get(subject)
                .is_some_and(|v| *v >= meta.key_version)
        {
            staged.erased += 1;
            continue;
        }
        let path = stage
            .join("blobs/objects")
            .join(meta.id.shard())
            .join(meta.id.file_name());
        if !remote.get_to_file(&remote_name(&meta.id), &path).await? {
            staged.failed.push((hash, "it is not in the bucket".into()));
            continue;
        }
        match check_file(&path, &meta, &kronik_blob::NoKeys) {
            Ok(()) => {}
            Err(None) => {
                std::fs::remove_file(&path)?;
                staged.erased += 1;
                continue;
            }
            Err(Some(why)) => {
                std::fs::remove_file(&path)?;
                staged.failed.push((hash, why));
                continue;
            }
        }
        staged.restored += 1;
        staged.bytes += meta.size;
        if meta.subject.is_some() {
            keyed.push((meta, path));
        }
    }
    Ok((staged, keyed))
}

/// What a restore reports about blobs; without `allow_missing`, a blob that
/// is missing or failed its check fails the restore before anything moves
/// into place.
pub(crate) fn finish(staged: StagedBlobs, allow_missing: bool) -> Result<BlobRestore, ShipError> {
    if !staged.failed.is_empty() && !allow_missing {
        let shown: Vec<String> = staged
            .failed
            .iter()
            .take(5)
            .map(|(hash, why)| format!("{hash} ({why})"))
            .collect();
        let more = staged.failed.len().saturating_sub(shown.len());
        return Err(ShipError::BlobMissing(format!(
            "{} blob(s) that the restored data references are missing from the bucket or fail \
             their check: {}{}; nothing was installed. Restore the bucket's blobs, or run again \
             with --allow-missing-blobs to install anyway (the node then reads them as \
             BLOB_MISSING)",
            staged.failed.len(),
            shown.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            }
        )));
    }
    if !staged.failed.is_empty() {
        tracing::warn!(
            blobs = staged.failed.len(),
            "restore: --allow-missing-blobs: these blobs are missing and read as BLOB_MISSING"
        );
    }
    Ok(BlobRestore {
        restored: staged.restored,
        bytes: staged.bytes,
        erased: staged.erased,
        missing: staged.failed.into_iter().map(|(hash, _)| hash).collect(),
    })
}

/// Checks a stored blob file against the reference that names it (ADR 0122
/// §5): its header, size, length and body digest; each frame (a plain
/// frame's CRC, a sealed one's authentication with the subject's key); and
/// its identity: BLAKE3 of the content for `b3:`, and BLAKE3 keyed with the
/// subject's `K_id` for `b3s:` when `keys` has it. `Err(None)` for a blob
/// of an erased subject.
pub(crate) fn check_file(
    path: &Path,
    meta: &BlobMeta,
    keys: &dyn KeyAccess,
) -> Result<(), Option<String>> {
    let file = std::fs::File::open(path).map_err(|e| Some(format!("opening it: {e}")))?;
    let header = read_header(&file).map_err(Some)?;
    if header.size != meta.size
        || header.subject != meta.subject
        || header.key_version != meta.key_version
    {
        return Err(Some(
            "its header names another size, subject or key version than its reference".into(),
        ));
    }
    let len = file.metadata().map_err(|e| Some(e.to_string()))?.len();
    if len != header.file_len() {
        return Err(Some(format!(
            "it is {len} bytes, not the {} its header gives",
            header.file_len()
        )));
    }
    let answer = |a: KeyAnswer| match a {
        KeyAnswer::Found(k) => Ok(Some(k)),
        KeyAnswer::Missing => Ok(None),
        KeyAnswer::Erased => Err(None),
        KeyAnswer::Unavailable(why) => Err(Some(format!("its key: {why}"))),
    };
    let (seal, mut identity) = match &meta.subject {
        Some(subject) => {
            let seal = if header.sealed {
                answer(keys.seal_key(subject, meta.key_version))?
            } else {
                None
            };
            let id_key = answer(keys.identity_key(subject, meta.key_version))?;
            (seal, id_key.map(|k| blake3::Hasher::new_keyed(&k)))
        }
        None if header.sealed => {
            return Err(Some("a sealed file for a blob without a subject".into()));
        }
        None => (None, Some(blake3::Hasher::new())),
    };
    if let Some(key) = &seal {
        header
            .verify(key)
            .map_err(|why| Some(format!("its header: {why}")))?;
    }
    let mut body = blake3::Hasher::new();
    let overhead = header.overhead();
    for index in 0..header.frames() {
        let stored_len = header.frame_plain_len(index) + overhead;
        let mut raw = vec![0u8; stored_len];
        file.read_exact_at(&mut raw, header.frame_offset(index))
            .map_err(|e| Some(format!("reading frame {index}: {e}")))?;
        body.update(&raw);
        let plain = if header.sealed {
            match (&seal, &meta.subject) {
                (Some(key), Some(subject)) => format::open_sealed_frame(
                    &FrameKey {
                        key,
                        nonce_prefix: &header.nonce_prefix,
                        subject,
                        key_version: meta.key_version,
                    },
                    index,
                    index + 1 == header.frames(),
                    &raw,
                )
                .ok_or_else(|| Some(format!("frame {index} fails its authentication")))?,
                // Without the key a sealed frame cannot be opened; the body
                // digest still covers it.
                _ => continue,
            }
        } else {
            format::open_plain_frame(&raw)
                .ok_or_else(|| Some(format!("frame {index} fails its CRC")))?
                .to_vec()
        };
        if let Some(h) = identity.as_mut() {
            h.update(&plain);
        }
    }
    if *body.finalize().as_bytes() != header.body_digest {
        return Err(Some("its body digest does not match".into()));
    }
    if header.sealed && seal.is_none() {
        identity = None;
    }
    if let Some(h) = identity
        && h.finalize().as_bytes() != meta.id.digest()
    {
        return Err(Some("its content does not match its identity".into()));
    }
    Ok(())
}

impl Remote {
    /// Deletes the object under `rel`; one that is gone already is fine.
    pub async fn delete_object(&self, rel: &str) -> Result<(), ShipError> {
        match self.store.delete(&self.key(rel)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(self.store_error(e)),
        }
    }

    /// Uploads `len` bytes of `file` under `rel`: one put up to
    /// [`PART_BYTES`], a multipart upload of such parts above.
    pub(crate) async fn put_file(
        &self,
        rel: &str,
        file: &std::fs::File,
        len: u64,
    ) -> Result<(), ShipError> {
        let part = |offset: u64| -> Result<PutPayload, ShipError> {
            let n = usize::try_from(PART_BYTES.min(len - offset))
                .map_err(|_| ShipError::Config("a blob part does not fit in memory".into()))?;
            let mut bytes = vec![0u8; n];
            file.read_exact_at(&mut bytes, offset)?;
            Ok(PutPayload::from(bytes))
        };
        let key = self.key(rel);
        if len <= PART_BYTES {
            self.store
                .put(&key, part(0)?)
                .await
                .map_err(|e| self.store_error(e))?;
            return Ok(());
        }
        let mut upload = self
            .store
            .put_multipart(&key)
            .await
            .map_err(|e| self.store_error(e))?;
        let mut offset = 0;
        while offset < len {
            let payload = match part(offset) {
                Ok(p) => p,
                Err(e) => {
                    let _ = upload.abort().await;
                    return Err(e);
                }
            };
            if let Err(e) = upload.put_part(payload).await {
                let _ = upload.abort().await;
                return Err(self.store_error(e));
            }
            offset += PART_BYTES;
        }
        upload.complete().await.map_err(|e| self.store_error(e))?;
        Ok(())
    }

    /// The header of the blob object under `rel`; `None` when there is no
    /// such object, or none that starts with a blob header.
    pub(crate) async fn header(&self, rel: &str) -> Result<Option<Header>, ShipError> {
        let key = self.key(rel);
        match self.store.get_range(&key, 0..HEADER_LEN as u64).await {
            Ok(bytes) => Ok(Header::decode(&bytes).ok()),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(self.store_error(e)),
        }
    }

    /// Downloads the object under `rel` into a new file at `path`, in
    /// ranges of [`PART_BYTES`]. `false` when there is no such object.
    pub(crate) async fn get_to_file(&self, rel: &str, path: &Path) -> Result<bool, ShipError> {
        let key = self.key(rel);
        let meta = match self.store.head(&key).await {
            Ok(meta) => meta,
            Err(object_store::Error::NotFound { .. }) => return Ok(false),
            Err(e) => return Err(self.store_error(e)),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        let mut offset = 0u64;
        while offset < meta.size {
            let end = meta.size.min(offset + PART_BYTES);
            let bytes = self
                .store
                .get_range(&key, offset..end)
                .await
                .map_err(|e| self.store_error(e))?;
            file.write_all_at(&bytes, offset)?;
            offset = end;
        }
        file.sync_all()?;
        Ok(true)
    }
}
