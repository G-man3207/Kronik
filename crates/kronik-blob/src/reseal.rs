//! Sealing a plain blob file in place (M26 §9.4, ADR 0117 §2): `kronik privacy
//! reseal` seals the blobs a subject wrote while the mode was `off`. The
//! identity does not change (it is keyed, not sealed), so the sealed file
//! takes the plain one's name: written as a part file, made durable, renamed
//! over the plain file under the shard's claim lock, and the shard directory
//! synced. A reader that has the plain file open keeps reading it.

use std::io;

use bytes::Bytes;
use kronik_core::env::{BoxFuture, OpenMode};

use crate::format::{
    FrameKey, HEADER_LEN, Header, PLAIN_OVERHEAD, frame_count, open_plain_frame, seal_frame,
};
use crate::id::hex;
use crate::{BlobError, BlobId, BlobStore, KeyAccess, KeyAnswer, Space};

/// What sealing one blob file did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resealed {
    /// The plain file is sealed now.
    Sealed,
    /// Nothing to do: the file is sealed already, has no subject, or is gone.
    Unchanged,
    /// The subject was erased through the file's key version: the file is
    /// left for the erasure's deletion.
    Erased,
}

impl BlobStore {
    /// Whether the file of `id` in `space` is a subject's plain file, which
    /// [`BlobStore::seal_in_place`] would seal: `None` when it is not there.
    pub async fn is_plain_subject_file(
        &self,
        space: &Space,
        id: &BlobId,
    ) -> Result<Option<bool>, BlobError> {
        let fs = &self.env.fs;
        let file = match fs.open(self.object_path(space, id), OpenMode::Read).await {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BlobError::io("opening a blob", e)),
        };
        let bytes = file
            .read_at(0, HEADER_LEN)
            .await
            .map_err(|e| BlobError::io("reading a blob header", e))?;
        let h = Header::decode(&bytes).map_err(|why| BlobError::Corrupt { id: *id, why })?;
        Ok(Some(!h.sealed && h.subject.is_some()))
    }

    /// Seals the plain file of `id` in `space` under its subject's frame key
    /// of the file's key version, keeping its identity and name. The plain
    /// file's frames are checked (CRC and body digest) before anything is
    /// replaced; a damaged file is an error and stays as it is.
    /// `before_rename` runs once the sealed file is durable and before it
    /// replaces the plain one, under the shard's claim lock: the caller
    /// marks the blob for the shipper to upload again there, so that no
    /// sealed file ever replaces a plain one without its mark.
    pub async fn seal_in_place(
        &self,
        space: &Space,
        id: &BlobId,
        keys: &dyn KeyAccess,
        before_rename: &(dyn Fn() -> BoxFuture<'static, Result<(), BlobError>> + Send + Sync),
    ) -> Result<Resealed, BlobError> {
        let object = self.object_path(space, id);
        let Some(dir_path) = object.parent().map(std::path::Path::to_path_buf) else {
            return Err(BlobError::Invalid(
                "an object path without a directory".into(),
            ));
        };
        let fs = &self.env.fs;
        let dir = self.dir(&dir_path);
        let _claim = dir.claim.lock().await;
        let source = match fs.open(object.clone(), OpenMode::Read).await {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Resealed::Unchanged),
            Err(e) => return Err(BlobError::io("opening a blob to seal", e)),
        };
        let bytes = source
            .read_at(0, HEADER_LEN)
            .await
            .map_err(|e| BlobError::io("reading a blob header", e))?;
        let corrupt = |why: String| BlobError::Corrupt { id: *id, why };
        let plain = Header::decode(&bytes).map_err(corrupt)?;
        let Some(subject) = plain.subject.clone() else {
            return Ok(Resealed::Unchanged);
        };
        if plain.sealed {
            return Ok(Resealed::Unchanged);
        }
        let key = match keys.seal_key(&subject, plain.key_version) {
            KeyAnswer::Found(key) => key,
            KeyAnswer::Erased => return Ok(Resealed::Erased),
            KeyAnswer::Missing => return Err(BlobError::KeyMissing(subject)),
            KeyAnswer::Unavailable(why) => return Err(BlobError::Io(why)),
        };
        let len = source
            .len()
            .await
            .map_err(|e| BlobError::io("reading a blob's length", e))?;
        if len != plain.file_len() {
            return Err(corrupt(format!("{len} bytes, not {}", plain.file_len())));
        }
        let nonce_prefix = self.env.random_bytes::<16>();
        let part = self
            .root(space)
            .join("tmp")
            .join(format!("{}.part", hex(&self.env.random_bytes::<8>())));
        let target = fs
            .open(part.clone(), OpenMode::ReadWriteCreate)
            .await
            .map_err(|e| BlobError::io("creating a sealed blob", e))?;
        let written = async {
            let frame_key = FrameKey {
                key: &key,
                nonce_prefix: &nonce_prefix,
                subject: &subject,
                key_version: plain.key_version,
            };
            // The body digest is over the stored frames: the plain file's is
            // checked, the sealed file's is new.
            let frames = frame_count(plain.size, true);
            let mut old_body = blake3::Hasher::new();
            let mut new_body = blake3::Hasher::new();
            let mut at = HEADER_LEN as u64;
            for i in 0..frames {
                let text = if i < plain.frames() {
                    let want = plain.frame_plain_len(i) + PLAIN_OVERHEAD;
                    let stored = source
                        .read_at(plain.frame_offset(i), want)
                        .await
                        .map_err(|e| BlobError::io("reading a plain blob frame", e))?;
                    if stored.len() != want {
                        return Err(corrupt("the file ends early".into()));
                    }
                    old_body.update(&stored);
                    open_plain_frame(&stored)
                        .ok_or_else(|| corrupt(format!("frame {i} fails its CRC")))?
                        .to_vec()
                } else {
                    Vec::new()
                };
                let mut out = Vec::with_capacity(text.len() + 16);
                seal_frame(&frame_key, i, i + 1 == frames, &text, &mut out)
                    .map_err(BlobError::Io)?;
                new_body.update(&out);
                let n = out.len() as u64;
                target
                    .write_at(at, Bytes::from(out))
                    .await
                    .map_err(|e| BlobError::io("writing a sealed blob frame", e))?;
                at += n;
            }
            if *old_body.finalize().as_bytes() != plain.body_digest {
                return Err(corrupt("the body digest does not match".into()));
            }
            let mut sealed = Header {
                sealed: true,
                nonce_prefix,
                body_digest: *new_body.finalize().as_bytes(),
                tag: [0; 16],
                ..plain.clone()
            };
            sealed.seal(&key).map_err(BlobError::Io)?;
            target
                .write_at(0, Bytes::copy_from_slice(&sealed.encode()))
                .await
                .map_err(|e| BlobError::io("writing a sealed blob header", e))?;
            target
                .sync_data()
                .await
                .map_err(|e| BlobError::io("syncing a sealed blob", e))?;
            Ok(())
        }
        .await;
        let written = match written {
            Ok(()) => before_rename().await,
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            let _ = fs.remove_file(part).await;
            return Err(e);
        }
        fs.rename(part, object)
            .await
            .map_err(|e| BlobError::io("naming a sealed blob", e))?;
        fs.sync_dir(dir_path)
            .await
            .map_err(|e| BlobError::io("syncing a blob directory", e))?;
        Ok(Resealed::Sealed)
    }
}
