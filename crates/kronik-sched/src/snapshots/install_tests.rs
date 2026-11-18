//! Startup install of a snapshot (issue #218): the replacement is fsynced
//! before it replaces live state, and `secrets.db` on that path is too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::*;
use crate::durable::test_ops::{Op, watch};
use kronik_store::Store;
use kronik_store::sql::{FileOpener, Limits, SqlPool};

fn snapshot_dir(data: &Path) -> PathBuf {
    let built = data.join("built");
    std::fs::create_dir_all(built.join("sql")).unwrap();
    let store = Store::open(
        rusqlite::Connection::open(built.join("state.db")).unwrap(),
        SqlPool::new(
            Arc::new(FileOpener {
                root: built.join("sql"),
            }),
            Limits::default(),
            4,
        ),
    )
    .unwrap();
    let snap = data.join("snapshots/main/00000000000000000000");
    store.snapshot_to(&snap).unwrap();
    drop(store);
    std::fs::remove_dir_all(&built).unwrap();
    std::fs::write(snap.join("secrets.db"), b"sealed-secrets").unwrap();
    let manifest = Manifest {
        format: 1,
        id: "main-00000000000000000000".into(),
        branch: "main".into(),
        lsn: 0,
        engine_version: "test".into(),
        created_wall_ms: 0,
        logical_time_ms: 0,
        segments: Vec::new(),
        files: Vec::new(),
        state_hash: String::new(),
        reason: "manual".into(),
        blobs: BlobTotals::default(),
    };
    std::fs::write(
        snap.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    snap
}

#[test]
fn prepare_state_fsyncs_secrets_db_before_it_returns() {
    let dir = tempfile::tempdir().unwrap();
    let snap = snapshot_dir(dir.path());
    let keys = dir.path().join("keys");
    let dest = keys.join("secrets.db");
    let watching = watch(dir.path(), |_| false);
    assert_eq!(prepare_state(dir.path(), "main").unwrap(), Some(0));
    let ops = watching.ops();
    drop(watching);
    let tmp = dest.with_extension("tmp");
    let synced = ops.iter().position(|op| *op == Op::Sync(tmp.clone()));
    let renamed = ops
        .iter()
        .position(|op| matches!(op, Op::Rename(_, to) if to == &dest));
    let dir_synced = ops.iter().position(|op| *op == Op::Sync(keys.clone()));
    assert!(
        synced.is_some() && renamed.is_some() && dir_synced.is_some(),
        "{ops:?}"
    );
    assert!(synced < renamed && renamed < dir_synced, "{ops:?}");
    assert_eq!(std::fs::read(&dest).unwrap(), b"sealed-secrets");
    assert!(dir.path().join("branches/main/state.db").is_file());
    assert!(snap.join("secrets.db").is_file());
}

#[test]
fn a_secrets_copy_whose_directory_is_not_synced_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    snapshot_dir(dir.path());
    let keys = dir.path().join("keys");
    let dest = keys.join("secrets.db");
    let _failing = watch(dir.path(), {
        let keys = keys.clone();
        move |op| *op == Op::Sync(keys.clone())
    });
    let err = prepare_state(dir.path(), "main").unwrap_err();
    assert!(err.contains("injected failure"), "{err}");
    assert!(
        !dest.exists(),
        "an unsynced secrets.db would be skipped next start"
    );
    assert!(!dest.with_extension("tmp").exists());
    // The state replace has not run, so the next start retries both.
    assert!(!dir.path().join("branches/main/state.db").exists());
}

#[test]
fn prepare_state_restores_an_actor_tree_an_install_left_aside() {
    let dir = tempfile::tempdir().unwrap();
    let branch = dir.path().join("branches/main");
    let sql = branch.join("sql/ab");
    std::fs::create_dir_all(&sql).unwrap();
    std::fs::write(sql.join("actor.db"), b"live-rows").unwrap();
    std::fs::rename(branch.join("sql"), branch.join(".snapshot-install-old")).unwrap();
    assert_eq!(prepare_state(dir.path(), "main").unwrap(), None);
    assert_eq!(
        std::fs::read(branch.join("sql/ab/actor.db")).unwrap(),
        b"live-rows"
    );
    assert!(!branch.join(".snapshot-install-old").exists());
}
