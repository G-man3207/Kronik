//! The files of erased blobs (M26 §9.3): once a subject's erasure is applied,
//! the node deletes every file of a blob the erasure covers, in main's store
//! and in every fork space, whatever keeps it: a lease, a fork's roots or a
//! snapshot's index. An erased blob's bytes must go; a later reader finds
//! nothing and answers that the blob was erased.

use std::collections::BTreeMap;
use std::io;

use kronik_core::env::OpenMode;
use kronik_core::ids::hex;

use crate::{BlobError, BlobId, BlobStore, Space};

impl BlobStore {
    /// Deletes the files of `ids` in `space`, under each shard's claim lock
    /// as the collector deletes, and makes each changed shard directory
    /// durable. A file that is not there is no error: a crash, the
    /// collector, or an earlier call deleted it. Returns the files deleted
    /// and their bytes.
    pub async fn delete_erased(
        &self,
        space: &Space,
        ids: &[BlobId],
    ) -> Result<(u64, u64), BlobError> {
        if self.mutation_erasure_keeps_files {
            return Ok((0, 0));
        }
        let mut by_shard: BTreeMap<String, Vec<&BlobId>> = BTreeMap::new();
        for id in ids {
            by_shard.entry(id.shard()).or_default().push(id);
        }
        let fs = &self.env.fs;
        let (mut files, mut bytes) = (0u64, 0u64);
        for (shard, ids) in by_shard {
            let dir_path = self.root(space).join("objects").join(shard);
            let dir = self.dir(&dir_path);
            let _claim = dir.claim.lock().await;
            let mut changed = false;
            for id in ids {
                let path = dir_path.join(id.file_name());
                let len = match fs.open(path.clone(), OpenMode::Read).await {
                    Ok(file) => file
                        .len()
                        .await
                        .map_err(|e| BlobError::io("reading an erased blob's length", e))?,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(BlobError::io("opening an erased blob", e)),
                };
                match fs.remove_file(path).await {
                    Ok(()) => {
                        files += 1;
                        bytes += len;
                        changed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(BlobError::io("deleting an erased blob", e)),
                }
            }
            if changed {
                fs.sync_dir(dir_path)
                    .await
                    .map_err(|e| BlobError::io("syncing a blob directory", e))?;
            }
        }
        Ok((files, bytes))
    }

    /// Deletes every blob file of `space` whose header names a subject
    /// erased through its key version (`erased`), whatever references it:
    /// for a fork's space, which no collector sweeps, and where a blob the
    /// fork wrote has no row of main's index (M26 §9.3). Under each shard's
    /// claim lock, each changed directory made durable. Returns the files
    /// deleted and their bytes.
    pub async fn delete_erased_subjects(
        &self,
        space: &Space,
        erased: &(dyn Fn(&str, u32) -> bool + Send + Sync),
    ) -> Result<(u64, u64), BlobError> {
        let fs = &self.env.fs;
        let root = self.root(space);
        let (mut files, mut bytes) = (0u64, 0u64);
        for shard in 0..=255u8 {
            let dir_path = root.join("objects").join(hex(&[shard]));
            let names = match fs.read_dir(dir_path.clone()).await {
                Ok(names) => names,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(BlobError::io("listing a blob directory", e)),
            };
            let mut doomed = Vec::new();
            for name in names {
                if BlobId::from_file_name(&name).is_none() {
                    continue;
                }
                let path = dir_path.join(&name);
                let file = match fs.open(path.clone(), OpenMode::Read).await {
                    Ok(file) => file,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(BlobError::io("opening a blob", e)),
                };
                let Some((subject, version)) = crate::sweep::header_subject(&*file).await else {
                    continue;
                };
                if erased(&subject, version) {
                    let len = file
                        .len()
                        .await
                        .map_err(|e| BlobError::io("reading an erased blob's length", e))?;
                    doomed.push((path, len));
                }
            }
            if doomed.is_empty() {
                continue;
            }
            let dir = self.dir(&dir_path);
            let _claim = dir.claim.lock().await;
            let mut changed = false;
            for (path, len) in doomed {
                match fs.remove_file(path).await {
                    Ok(()) => {
                        files += 1;
                        bytes += len;
                        changed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(BlobError::io("deleting an erased blob", e)),
                }
            }
            if changed {
                fs.sync_dir(dir_path)
                    .await
                    .map_err(|e| BlobError::io("syncing a blob directory", e))?;
            }
        }
        Ok((files, bytes))
    }
}
