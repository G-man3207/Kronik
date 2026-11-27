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

use std::path::Path;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::env::test_fs::{FsCall, Then, hooked};
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
        // Real files, but an fsync of a log segment fails once a snapshot
        // is written.
        let data = dir.path().to_path_buf();
        env.fs = hooked(env.fs.clone(), move |call| match call {
            FsCall::SyncData(path)
                if path.components().any(|c| c.as_os_str() == "log") && snapshot_written(&data) =>
            {
                Then::Fail(std::io::Error::other(INJECTED))
            }
            _ => Then::Forward,
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
