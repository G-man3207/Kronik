//! Keystore backup shipping (docs/design/m8-privacy.md §10) against a
//! `file://` remote: a change produces a backup that round-trips, an old
//! backup is deleted, the newest is kept, and restore installs it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kronik_core::env::Env;
use kronik_privacy::MasterKey;
use kronik_privacy::keystore::{KeyLookup, Keystore};
use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, start_local};
use kronik_ship::{
    KeystoreMode, Remote, ShipError, ShipState, current_keystore_revision, restore, ship_keystore,
    ship_once,
};
use tokio::runtime::Runtime;

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn a_keystore_change_is_shipped_pruned_and_restored() {
    let src = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let runtime = rt();
    let environment = Env::real(runtime.handle().clone());
    let node = runtime.block_on(async {
        start_local(environment.clone(), src.path(), NodeConfig::default())
            .await
            .unwrap()
    });
    node.sealer()
        .keystore()
        .unwrap()
        .key_for_sealing("user:1", [9; 32], [3; 24], 1)
        .unwrap();

    // Old backups. Retention must delete them and keep the newest.
    let old = bucket.path().join("keystore");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("1000.bin"), b"stale-old").unwrap();
    std::fs::write(old.join("2000.bin"), b"stale-newer").unwrap();

    let wall = 1_700_000_000_000u64;
    let mut state = ShipState::load(src.path()).unwrap();
    let report = runtime
        .block_on(ship_keystore(
            &environment,
            &remote,
            src.path(),
            &mut state,
            wall,
            Duration::from_secs(30 * 86_400),
            [7; 24],
            node.key_source().unwrap(),
            node.sealer().keystore().unwrap(),
        ))
        .unwrap();
    assert_eq!(report.objects, 1, "{report:?}");
    assert!(report.deleted >= 2, "{report:?}");
    let kept = bucket.path().join(format!("keystore/{wall}.bin"));
    let bytes = std::fs::read(&kept).unwrap();
    assert!(
        !bytes.windows(6).any(|w| w == b"user:1"),
        "the shipped backup contains the subject id"
    );
    assert!(!old.join("1000.bin").exists());
    assert!(!old.join("2000.bin").exists());

    let (master, _) = MasterKey::open(
        &src.path().join("keys/master.key"),
        &src.path().join("keys"),
        None,
    )
    .unwrap();
    let round = tempfile::tempdir().unwrap();
    let round_owner = kronik_privacy::key_source::lock_data(round.path()).unwrap();
    let restored = Keystore::restore_owned(&round_owner, &master, &bytes).unwrap();
    assert!(matches!(
        restored.key("user:1", 1).unwrap(),
        KeyLookup::Found(_)
    ));

    // A change inside the minute is not uploaded again.
    node.sealer()
        .keystore()
        .unwrap()
        .key_for_sealing("user:2", [8; 32], [5; 24], 2)
        .unwrap();
    let again = runtime
        .block_on(ship_keystore(
            &environment,
            &remote,
            src.path(),
            &mut state,
            wall + 1_000,
            Duration::from_secs(30 * 86_400),
            [8; 24],
            node.key_source().unwrap(),
            node.sealer().keystore().unwrap(),
        ))
        .unwrap();
    assert_eq!(again.objects, 0, "debounced: {again:?}");
    assert!(
        !bucket
            .path()
            .join(format!("keystore/{}.bin", wall + 1_000))
            .exists()
    );

    let snap = runtime
        .block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
    assert!(snap.created_wall_ms >= wall);
    let mut ship = ShipState::load(src.path()).unwrap();
    runtime
        .block_on(ship_once(&remote, src.path(), "main", &mut ship))
        .unwrap();
    drop(node);
    drop(runtime);

    let dst = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::copy(
        src.path().join("keys/master.key"),
        dst.path().join("keys/master.key"),
    )
    .unwrap();
    let runtime = rt();
    let report = runtime
        .block_on(restore(
            &remote,
            dst.path(),
            "main",
            false,
            &Env::real(runtime.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
        ))
        .unwrap();
    assert_eq!(report.keystore_backup_ms, Some(wall));
    let installed_owner = kronik_privacy::key_source::lock_data(dst.path()).unwrap();
    let installed = Keystore::open_owned(&installed_owner, &master).unwrap();
    assert!(matches!(
        installed.key("user:1", 1).unwrap(),
        KeyLookup::Found(_)
    ));
}

/// A settled view of the keystore's semantic content: export it, install it in
/// a fresh owned directory, close that database's only connection (checkpointing
/// and removing the WAL), then freeze and measure the database and WAL files.
/// This target holds no bare SQLite handle, so this settles the semantics the
/// way shipping does; shipping reads must not change what it observes.
fn settled_keystore_metadata(store: &Keystore, master: &MasterKey) -> [(u64, SystemTime); 2] {
    let backup = store.export_backup([42; 24]).unwrap();
    let round = tempfile::tempdir().unwrap();
    let owner = kronik_privacy::key_source::lock_data(round.path()).unwrap();
    drop(Keystore::restore_owned(&owner, master, &backup).unwrap());
    fixed_keystore_metadata(&round.path().join("keys/keystore.db"))
}

fn fixed_keystore_metadata(path: &Path) -> [(u64, SystemTime); 2] {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    // The settled database has no WAL sidecar; measure it as the empty file it
    // would leave behind, so the shape stays comparable to a live database's.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&wal)
        .unwrap();
    let fixed = UNIX_EPOCH + Duration::from_secs(1_000_000);
    [path.to_owned(), PathBuf::from(wal)].map(|path| {
        let file = std::fs::File::options()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.set_times(
            std::fs::FileTimes::new()
                .set_accessed(fixed)
                .set_modified(fixed),
        )
        .unwrap();
        let metadata = file.metadata().unwrap();
        (metadata.len(), metadata.modified().unwrap())
    })
}

fn sealed_at(sealer: &Sealer, version: u32, bytes: &[u8], nonce: u8) -> pb::Sealable {
    let mut value = pb::Sealable {
        subject: Some("user:revision".into()),
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    };
    sealer
        .seal_value_at(&mut value, version, &|bytes| bytes.fill(nonce))
        .unwrap();
    value
}

#[test]
fn semantic_revisions_ship_rotate_erase_and_import_with_identical_file_and_wal_metadata() {
    let source = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let runtime = rt();
    let environment = Env::real(runtime.handle().clone());
    let node = runtime
        .block_on(start_local(
            environment.clone(),
            source.path(),
            NodeConfig::default(),
        ))
        .unwrap();
    let store = node.sealer().keystore().unwrap().clone();
    let path = source.path().join("keys/keystore.db");
    let (master, _) = MasterKey::open(
        &source.path().join("keys/master.key"),
        &source.path().join("keys"),
        None,
    )
    .unwrap();
    let writer = store.reopen_owned().unwrap();
    store
        .key_for_sealing("user:revision", [11; 32], [12; 24], 1)
        .unwrap();
    let original = sealed_at(node.sealer(), 1, b"original-subject-value", 13);
    let metadata = settled_keystore_metadata(&store, &master);
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let wall = 1_700_000_000_000;

    // A legacy weak stamp can equal the semantic counter; it is still unknown.
    let mut legacy: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/ship-state-weak-stamp-v1.json")).unwrap();
    legacy["keystore_stamp"] = store.revision().unwrap().into();
    std::fs::write(
        source.path().join("ship.json"),
        serde_json::to_vec(&legacy).unwrap(),
    )
    .unwrap();
    let mut state = ShipState::load(source.path()).unwrap();
    assert!(state.keystore_revision.is_none());
    let ship = |state: &mut ShipState, wall, nonce| {
        runtime.block_on(ship_keystore(
            &environment,
            &remote,
            source.path(),
            state,
            wall,
            Duration::from_secs(30 * 86_400),
            [nonce; 24],
            node.key_source().unwrap(),
            &store,
        ))
    };
    assert_eq!(ship(&mut state, wall, 14).unwrap().objects, 1);
    state = ShipState::load(source.path()).unwrap();
    assert!(
        state.keystore_revision.unwrap().covers(
            runtime
                .block_on(current_keystore_revision(
                    &environment,
                    source.path(),
                    &store
                ))
                .unwrap()
        )
    );
    assert_eq!(ship(&mut state, wall + 60_000, 15).unwrap().objects, 0);

    writer
        .rotate("user:revision", [16; 32], [17; 24], 2)
        .unwrap();
    let current = sealed_at(node.sealer(), 2, b"current-subject-value", 18);
    assert_eq!(settled_keystore_metadata(&store, &master), metadata);
    assert_eq!(ship(&mut state, wall + 60_000, 19).unwrap().objects, 1);
    writer.erase_through("user:revision", 1, 3).unwrap();
    assert_eq!(settled_keystore_metadata(&store, &master), metadata);
    assert_eq!(ship(&mut state, wall + 120_000, 20).unwrap().objects, 1);

    let erased_backup = std::fs::read(
        bucket
            .path()
            .join(format!("keystore/{}.bin", wall + 120_000)),
    )
    .unwrap();
    let restored = Arc::new(Keystore::restore_memory(&master, &erased_backup).unwrap());
    let view = Sealer::new(restored);
    assert!(matches!(view.open(&original), Opened::Erased { .. }));
    assert_eq!(
        view.open(&current).bytes(),
        Some(b"current-subject-value".as_slice())
    );

    let incoming = Keystore::restore_memory(&master, &erased_backup).unwrap();
    incoming
        .key_for_sealing("user:other", [21; 32], [22; 24], 4)
        .unwrap();
    let incoming_backup = incoming.export_backup([23; 24]).unwrap();
    let imported =
        Keystore::restore_owned(store.data_ownership().unwrap(), &master, &incoming_backup)
            .unwrap();
    drop(imported);
    assert_eq!(settled_keystore_metadata(&store, &master), metadata);
    assert_eq!(ship(&mut state, wall + 180_000, 24).unwrap().objects, 1);
    let bytes = std::fs::read(
        bucket
            .path()
            .join(format!("keystore/{}.bin", wall + 180_000)),
    )
    .unwrap();
    let restored = Arc::new(Keystore::restore_memory(&master, &bytes).unwrap());
    assert!(matches!(
        restored.key("user:other", 1).unwrap(),
        KeyLookup::Found(_)
    ));
    let view = Sealer::new(restored);
    assert!(matches!(view.open(&original), Opened::Erased { .. }));
    assert_eq!(
        view.open(&current).bytes(),
        Some(b"current-subject-value".as_slice())
    );

    let before = state.clone();
    // Break the keystore held by the live path: the revision read must fail
    // as a keystore error, not be mistaken for an unchanged keystore.
    let detached = source.path().join("keys/keystore.db.detached");
    std::fs::rename(&path, &detached).unwrap();
    std::fs::write(&path, b"not the held keystore").unwrap();
    assert!(matches!(
        ship(&mut state, wall + 240_000, 25),
        Err(ShipError::Keystore(_))
    ));
    assert_eq!(state, before);
    assert!(
        !bucket
            .path()
            .join(format!("keystore/{}.bin", wall + 240_000))
            .exists()
    );
}

#[test]
fn shipping_state_format_is_strict_and_failures_are_not_fresh_defaults() {
    let bytes = include_bytes!("fixtures/ship-state-keystore-revision-v1.json");
    let state: ShipState = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
    );
    let data = tempfile::tempdir().unwrap();
    assert_eq!(ShipState::load(data.path()).unwrap(), ShipState::default());
    let mut future: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    future["keystore_revision"]["schema"] = "private-sentinel-unsupported-format".into();
    std::fs::write(
        data.path().join("ship.json"),
        serde_json::to_vec(&future).unwrap(),
    )
    .unwrap();
    let error = ShipState::load(data.path()).unwrap_err();
    assert!(matches!(error, ShipError::Config(_)));
    assert!(!error.to_string().contains("private-sentinel"));
    std::fs::remove_file(data.path().join("ship.json")).unwrap();
    std::fs::create_dir(data.path().join("ship.json")).unwrap();
    assert!(matches!(
        ShipState::load(data.path()),
        Err(ShipError::Io(_))
    ));
}

#[test]
fn prepared_restore_never_reloads_the_source_and_keeps_the_directory_lock() {
    let src = tempfile::tempdir().unwrap();
    let bucket = tempfile::tempdir().unwrap();
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let runtime = rt();
    let env = Env::real(runtime.handle().clone());
    let node = runtime
        .block_on(start_local(env.clone(), src.path(), NodeConfig::default()))
        .unwrap();
    node.sealer()
        .keystore()
        .unwrap()
        .key_for_sealing("prepared:subject", [9; 32], [3; 24], 1)
        .unwrap();
    runtime
        .block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
    let mut ship = ShipState::load(src.path()).unwrap();
    runtime
        .block_on(ship_once(&remote, src.path(), "main", &mut ship))
        .unwrap();
    runtime
        .block_on(ship_keystore(
            &env,
            &remote,
            src.path(),
            &mut ship,
            1_700_000_000_000,
            Duration::from_secs(86400),
            [7; 24],
            node.key_source().unwrap(),
            node.sealer().keystore().unwrap(),
        ))
        .unwrap();
    let dst = tempfile::tempdir().unwrap();
    let key = dst.path().join("source.key");
    std::fs::copy(src.path().join("keys/master.key"), &key).unwrap();
    let keys = kronik_privacy::key_source::Keys {
        master_key_file: Some(key.clone()),
        ..Default::default()
    };
    let held = kronik_privacy::key_source::lock_data(dst.path()).unwrap();
    let bad = dst.path().join("wrong.key");
    std::fs::write(&bad, [0x42; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong = kronik_privacy::key_source::Keys {
        master_key_file: Some(bad.clone()),
        ..Default::default()
    };
    assert!(
        runtime
            .block_on(kronik_ship::prepare_restore(
                &remote,
                dst.path(),
                "main",
                &env,
                &wrong,
                KeystoreMode::Require,
                &held
            ))
            .is_err()
    );
    assert_eq!(std::fs::read(&bad).unwrap(), [0x42; 32]);
    assert_eq!(
        std::fs::read_dir(dst.path()).unwrap().count(),
        2,
        "wrong source cannot create destination files"
    );
    std::fs::remove_file(bad).unwrap();
    let prepared = runtime
        .block_on(kronik_ship::prepare_restore(
            &remote,
            dst.path(),
            "main",
            &env,
            &keys,
            KeystoreMode::Require,
            &held,
        ))
        .unwrap();
    assert!(
        !dst.path().join(".restore").exists(),
        "preparation must not write into the destination"
    );
    assert!(!dst.path().join("branches").exists());
    assert!(matches!(
        kronik_privacy::key_source::lock_data(dst.path()),
        Err(kronik_privacy::key_source::KeySourceError::DataInUse)
    ));
    // The hand-over of the stage to the destination owner: here the owner is
    // the current user, so the change is allowed and the walk is the real one.
    // It also proves that the stage is private to the caller whatever the
    // umask is (the hand-over refuses a directory that others can enter), which
    // `tempdir()` alone does not give: it creates 0777 & !umask.
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    prepared.handover(uid, gid).unwrap();
    // The source key is gone: installing uses the keystore backup that was
    // decrypted while preparing, and never loads the source again.
    std::fs::remove_file(&key).unwrap();
    let report = kronik_ship::install_prepared(dst.path(), "main", false, prepared, &held).unwrap();
    assert_eq!(report.keystore, "installed");
    assert!(dst.path().join("branches/main/state.db").exists());
    assert!(matches!(
        kronik_privacy::key_source::lock_data(dst.path()),
        Err(kronik_privacy::key_source::KeySourceError::DataInUse)
    ));
}

#[test]
fn failed_preparation_leaves_an_empty_destination_empty() {
    let bucket = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let runtime = rt();
    let held = kronik_privacy::key_source::lock_data(dst.path()).unwrap();
    assert!(
        runtime
            .block_on(kronik_ship::prepare_restore(
                &remote,
                dst.path(),
                "main",
                &Env::real(runtime.handle().clone()),
                &Default::default(),
                KeystoreMode::Require,
                &held
            ))
            .is_err()
    );
    assert_eq!(std::fs::read_dir(dst.path()).unwrap().count(), 0);
}
