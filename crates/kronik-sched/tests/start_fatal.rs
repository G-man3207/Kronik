//! A start that a storage failure stops says so. Here an erasure whose
//! keys went before its record (a stop between the two steps of `privacy
//! erase`) is recovered by the next start, which commits the record and
//! takes the snapshot an erasure takes; the log's fsync of the snapshot's
//! marker fails, which stops the node (the log writer's rule: an fsync is
//! never retried). The start goes on until a later step fails because the
//! node is stopped: it must fail with the storage failure, so that an
//! operator reads it and a supervisor starts the daemon again, not with
//! the later step's own error ("the original native execution lifetime
//! ended", which the DST found).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::{BoxFuture, Env, File, Fs, OpenMode};
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{NodeConfig, start_local};

const INJECTED: &str = "injected fsync failure of the snapshot's marker";

/// The data directory has a snapshot's manifest: the erasure's snapshot is
/// written, and its marker is the next record the log syncs.
fn snapshot_written(data: &Path) -> bool {
    let root = data.join("snapshots").join("main");
    std::fs::read_dir(root).is_ok_and(|dirs| {
        dirs.flatten()
            .any(|d| d.path().join("manifest.json").exists())
    })
}

/// Real files, but an fsync of a log segment fails once a snapshot is
/// written.
struct MarkerFails {
    inner: Arc<dyn Fs>,
    data: PathBuf,
}

struct MarkerFile {
    inner: Arc<dyn File>,
    log: bool,
    data: PathBuf,
}

impl Fs for MarkerFails {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: PathBuf,
        mode: OpenMode,
    ) -> BoxFuture<'static, std::io::Result<Arc<dyn File>>> {
        let log = path.components().any(|c| c.as_os_str() == "log");
        let opened = self.inner.open(path, mode);
        let data = self.data.clone();
        Box::pin(async move {
            Ok(Arc::new(MarkerFile {
                inner: opened.await?,
                log,
                data,
            }) as Arc<dyn File>)
        })
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_dir(dir)
    }
}

impl File for MarkerFile {
    fn len(&self) -> BoxFuture<'static, std::io::Result<u64>> {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, std::io::Result<Vec<u8>>> {
        self.inner.read_at(offset, len)
    }
    fn write_at(&self, offset: u64, data: bytes::Bytes) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.write_at(offset, data)
    }
    fn set_len(&self, len: u64) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> BoxFuture<'static, std::io::Result<()>> {
        if self.log && snapshot_written(&self.data) {
            return Box::pin(async { Err(std::io::Error::other(INJECTED)) });
        }
        self.inner.sync_data()
    }
}

fn config(data: &Path) -> NodeConfig {
    let mut storage = StorageConfig::new(data.to_path_buf());
    storage.snapshot_interval = Duration::from_secs(3600);
    NodeConfig {
        concurrency: 2,
        storage: Some(storage),
        ..NodeConfig::default()
    }
}

#[test]
fn a_start_that_a_storage_failure_stops_fails_with_that_failure() {
    let dir = tempfile::tempdir().unwrap();
    // A subject's keys are erased, and the process stops before the
    // erasure's record.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let node = start_local(env, dir.path(), config(dir.path()))
            .await
            .unwrap();
        node.sealer().erase("user:1", 0).unwrap();
    });
    drop(runtime);
    assert!(!snapshot_written(dir.path()));

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = runtime.block_on(async {
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.fs = Arc::new(MarkerFails {
            inner: env.fs.clone(),
            data: dir.path().to_path_buf(),
        });
        match start_local(env, dir.path(), config(dir.path())).await {
            Ok(_) => panic!("the start went on although its log stopped"),
            Err(e) => e.to_string(),
        }
    });
    drop(runtime);
    assert!(snapshot_written(dir.path()), "the erasure's snapshot");
    assert!(
        error.contains(INJECTED),
        "the start failed without its cause: {error}"
    );
}
