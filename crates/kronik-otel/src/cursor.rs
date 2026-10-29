//! The export cursors, `<data>/export.json` (m28-otel §4.6, ADR 0084): per
//! named stream (`traces`, `audit`) the last LSN its sink acknowledged and
//! an opaque JSON state the stream needs to resume (the trace exporter's
//! open-turn set). Written as `snapshots.rs`' `write_synced` writes: a temp
//! file, fsync, rename, directory fsync, so a crash leaves the old file or
//! the new one.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bytes::Bytes;
use kronik_core::env::{Env, OpenMode};
use kronik_core::ids::Lsn;
use serde::{Deserialize, Serialize};

/// One stream's position.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// The last LSN delivered; the stream resumes after it.
    pub lsn: Lsn,
    /// The stream's own resume state (`null` for none).
    #[serde(default)]
    pub state: serde_json::Value,
}

/// The cursor file, shared by every stream of one data directory.
pub struct Cursors {
    env: Env,
    path: PathBuf,
    entries: Mutex<BTreeMap<String, Entry>>,
    /// Serializes writers: they share the temp file.
    write: tokio::sync::Mutex<()>,
}

impl Cursors {
    pub const FILE: &'static str = "export.json";

    /// Reads `<data>/export.json`; a missing file is no cursors. An
    /// unreadable one is an error rather than a silent restart from 0.
    pub async fn load(env: Env, data_dir: &Path) -> io::Result<Cursors> {
        let path = data_dir.join(Self::FILE);
        let entries = if env.fs.exists(path.clone()).await? {
            let f = env.fs.open(path.clone(), OpenMode::Read).await?;
            let len = f.len().await?;
            let bytes = f
                .read_at(0, usize::try_from(len).unwrap_or(usize::MAX))
                .await?;
            serde_json::from_slice(&bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?
        } else {
            BTreeMap::new()
        };
        Ok(Cursors {
            env,
            path,
            entries: Mutex::new(entries),
            write: tokio::sync::Mutex::new(()),
        })
    }

    /// The stream's saved position, if it has one.
    pub fn get(&self, stream: &str) -> Option<Entry> {
        self.lock().get(stream).cloned()
    }

    /// Sets the stream's position and makes the whole file durable.
    pub async fn save(&self, stream: &str, entry: Entry) -> io::Result<()> {
        let _writer = self.write.lock().await;
        let bytes = {
            let mut entries = self.lock();
            entries.insert(stream.to_owned(), entry);
            serde_json::to_vec(&*entries).map_err(io::Error::other)?
        };
        let tmp = self.path.with_extension("json.tmp");
        let f = self
            .env
            .fs
            .open(tmp.clone(), OpenMode::ReadWriteCreate)
            .await?;
        f.set_len(0).await?;
        f.write_at(0, Bytes::from(bytes)).await?;
        f.sync_data().await?;
        self.env.fs.rename(tmp, self.path.clone()).await?;
        if let Some(dir) = self.path.parent() {
            self.env.fs.sync_dir(dir.to_owned()).await?;
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}
