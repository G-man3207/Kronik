//! Keystore backup shipping (docs/design/m8-privacy.md §10) against a
//! `file://` remote: a change produces a backup that round-trips, an old
//! backup is deleted, the newest is kept, and restore installs it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::time::Duration;

use kronik_core::env::Env;
use kronik_privacy::MasterKey;
use kronik_privacy::keystore::{KeyLookup, Keystore};
use kronik_sched::{NodeConfig, start_local};
use kronik_ship::{Remote, ShipState, restore, ship_keystore, ship_once};
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
    let node = runtime.block_on(async {
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            src.path(),
            NodeConfig::default(),
        )
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
    let mut state = ShipState::load(src.path());
    let report = runtime
        .block_on(ship_keystore(
            &remote,
            src.path(),
            &mut state,
            wall,
            Duration::from_secs(30 * 86_400),
            [7; 24],
            &src.path().join("keys/master.key"),
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

    let (master, _) =
        MasterKey::load_or_create(&src.path().join("keys/master.key"), [0; 32]).unwrap();
    let round = tempfile::tempdir().unwrap();
    let restored =
        Keystore::import_backup_file(&round.path().join("keystore.db"), &master, &bytes).unwrap();
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
            &remote,
            src.path(),
            &mut state,
            wall + 1_000,
            Duration::from_secs(30 * 86_400),
            [8; 24],
            &src.path().join("keys/master.key"),
        ))
        .unwrap();
    assert_eq!(again.objects, 0, "debounced: {again:?}");
    assert!(
        !bucket
            .path()
            .join(format!("keystore/{}.bin", wall + 1_000))
            .exists()
    );

    let snap = runtime.block_on(node.snapshot("manual")).unwrap();
    assert!(snap.created_wall_ms >= wall);
    let mut ship = ShipState::load(src.path());
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
            &dst.path().join("keys/master.key"),
            false,
        ))
        .unwrap();
    assert_eq!(report.keystore_backup_ms, Some(wall));
    let installed = Keystore::open_file(&dst.path().join("keys/keystore.db"), &master).unwrap();
    assert!(matches!(
        installed.key("user:1", 1).unwrap(),
        KeyLookup::Found(_)
    ));
}
