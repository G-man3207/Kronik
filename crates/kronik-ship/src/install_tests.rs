//! Restore install (issue #219): staged files are fsynced before they replace
//! live names, and a failure before that fsync leaves the previous `state.db`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use kronik_sched::snapshots::{BlobTotals, Manifest};

use super::{FailInstallSync, Staged, dir_state_at_sync, install_staged, install_syncs};

const SEGMENT_NAME: &str = "00000000000000000001.seg";
const CODE_NAME: &str = "component.wasm";
const GOOD: &[u8] = b"good-state-db-not-short";
const RESTORED: &[u8] = b"short";
const ACTOR: &[u8] = b"actor-rows";
const SEGMENT: &[u8] = b"log-segment";
const CODE: &[u8] = b"component-bytes";

fn manifest() -> Manifest {
    Manifest {
        format: 1,
        id: "main-00000000000000000001".into(),
        branch: "main".into(),
        lsn: 1,
        engine_version: "test".into(),
        created_wall_ms: 0,
        logical_time_ms: 0,
        segments: vec![SEGMENT_NAME.into()],
        files: Vec::new(),
        state_hash: String::new(),
        reason: "manual".into(),
        blobs: BlobTotals::default(),
    }
}

fn staged() -> Staged {
    Staged {
        m: manifest(),
        segments: vec![SEGMENT_NAME.into()],
        components: vec![CODE_NAME.into()],
        keystore: "none_in_bucket",
        keystore_backup_ms: None,
        keystore_master: None,
        keys_missing: Vec::new(),
        older: None,
        through_lsn: 7,
        snapshots_skipped: Vec::new(),
        wrapped_path: None,
        blobs: super::BlobRestore::default(),
    }
}

/// A live branch with a good `state.db` and its write-ahead log, and a stage
/// whose `state.db` is shorter.
fn layout() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path();
    let branch = data.join("branches/main");
    std::fs::create_dir_all(&branch).unwrap();
    std::fs::write(branch.join("state.db"), GOOD).unwrap();
    std::fs::write(branch.join("state.db-wal"), b"old-wal").unwrap();

    let stage = data.join(".restore");
    let actor = stage.join("branch/sql/ab");
    std::fs::create_dir_all(&actor).unwrap();
    std::fs::write(stage.join("branch/state.db"), RESTORED).unwrap();
    std::fs::write(actor.join("actor.db"), ACTOR).unwrap();
    std::fs::create_dir_all(stage.join("log")).unwrap();
    std::fs::write(stage.join("log").join(SEGMENT_NAME), SEGMENT).unwrap();
    std::fs::create_dir_all(stage.join("code")).unwrap();
    std::fs::write(stage.join("code").join(CODE_NAME), CODE).unwrap();
    std::fs::create_dir_all(stage.join("snapshot")).unwrap();
    std::fs::write(stage.join("snapshot/state.db"), RESTORED).unwrap();
    (dir, branch, stage)
}

fn install(
    data: &Path,
    stage: &Path,
    branch: &Path,
    fault: &dyn Fn(&str) -> std::io::Result<()>,
) -> Result<super::RestoreReport, super::ShipError> {
    let ownership = kronik_privacy::key_source::lock_data(data).unwrap();
    let restore = ownership.begin_keystore_restore().unwrap();
    install_staged(data, stage, "main", branch, staged(), restore, fault)
}

fn at(syncs: &[PathBuf], path: &Path) -> usize {
    syncs
        .iter()
        .position(|synced| synced == path)
        .unwrap_or_else(|| panic!("{path:?} was not fsynced in {syncs:?}"))
}

#[test]
fn install_fsyncs_staged_files_before_their_directory_entries() {
    let (dir, branch, stage) = layout();
    install(dir.path(), &stage, &branch, &|_| Ok(())).unwrap();

    assert_eq!(std::fs::read(branch.join("state.db")).unwrap(), RESTORED);
    assert!(!branch.join("state.db-wal").exists());
    assert_eq!(
        std::fs::read(branch.join("sql/ab/actor.db")).unwrap(),
        ACTOR
    );
    assert_eq!(
        std::fs::read(branch.join("log").join(SEGMENT_NAME)).unwrap(),
        SEGMENT
    );
    assert_eq!(
        std::fs::read(dir.path().join("code").join(CODE_NAME)).unwrap(),
        CODE
    );
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(branch.join(super::RESTORE_MARKER)).unwrap())
            .unwrap();
    assert_eq!(marker["through_lsn"], 7);

    let syncs = install_syncs();
    let state_at = at(&syncs, &stage.join("branch/state.db"));
    let actor_at = at(&syncs, &stage.join("branch/sql/ab/actor.db"));
    let sql_dir = at(&syncs, &branch.join("sql"));
    let segment_at = at(&syncs, &stage.join("log").join(SEGMENT_NAME));
    let log_dir = at(&syncs, &branch.join("log"));
    let code_at = at(&syncs, &stage.join("code").join(CODE_NAME));
    let code_dir = at(&syncs, &dir.path().join("code"));
    let branch_at = syncs
        .iter()
        .rposition(|synced| synced == &branch)
        .expect("branch directory");
    assert!(
        state_at < branch_at && actor_at < sql_dir && segment_at < log_dir && code_at < code_dir,
        "{syncs:?}"
    );
    let live: Vec<Vec<u8>> = dir_state_at_sync()
        .into_iter()
        .filter(|(path, _)| path == &branch)
        .map(|(_, bytes)| bytes)
        .collect();
    // Before the rename the previous file is still the name; after it, the
    // directory fsync is what makes the replacement durable.
    assert_eq!(live, [GOOD.to_vec(), RESTORED.to_vec()]);
}

#[test]
fn a_failed_fsync_leaves_the_previous_state_db() {
    let (dir, branch, stage) = layout();
    let _fail = FailInstallSync::arm();
    let err = install(dir.path(), &stage, &branch, &|_| Ok(())).unwrap_err();
    assert!(
        err.to_string().contains("injected failure before fsync"),
        "{err}"
    );
    assert_eq!(std::fs::read(branch.join("state.db")).unwrap(), GOOD);
    assert_eq!(
        std::fs::read(branch.join("state.db-wal")).unwrap(),
        b"old-wal"
    );
    assert!(!branch.join(super::RESTORE_MARKER).exists());
    assert!(!branch.join("log").join(SEGMENT_NAME).exists());
}

#[test]
fn the_restore_marker_is_durable_before_state_db_is_replaced() {
    let (dir, branch, stage) = layout();
    let err = install(dir.path(), &stage, &branch, &|step| {
        if step == "commit" {
            Err(std::io::Error::other("injected at commit"))
        } else {
            Ok(())
        }
    })
    .unwrap_err();
    assert!(err.to_string().contains("injected at commit"), "{err}");
    assert_eq!(std::fs::read(branch.join("state.db")).unwrap(), GOOD);
    assert_eq!(
        std::fs::read(branch.join("state.db-wal")).unwrap(),
        b"old-wal"
    );
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(branch.join(super::RESTORE_MARKER)).unwrap())
            .unwrap();
    assert_eq!(marker["through_lsn"], 7);
}
