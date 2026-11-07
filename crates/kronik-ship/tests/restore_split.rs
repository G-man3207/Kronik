//! The two phases of a restore (docs/design/m6-storage.md §6): what needs the
//! authority of the caller (the key, the keystore backup), and what the owner
//! of the data directory does with them (the downloads, the checks of the
//! directory's own stores, the install). `restore` runs both in one process;
//! `kronik restore` runs them on either side of a drop of privileges.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_privacy::key_source::{Keys, lock_data};
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{NodeConfig, start_local};
use kronik_ship::{
    KeystoreMode, Remote, RestoreReport, ShipError, ShipState, restore, restore_as_owner,
    root_phase, ship_keystore, ship_once,
};
use tokio::runtime::Runtime;

fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn message(name: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(Vec::new())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// A bucket that a node shipped into: a snapshot, the log and, if asked, a
/// keystore backup. The node's master key is kept aside, as an operator does.
struct Shipped {
    bucket: tempfile::TempDir,
    remote: Remote,
    key: Vec<u8>,
}

fn shipped(keystore_backup: bool) -> Shipped {
    shipped_with(keystore_backup, false)
}

/// With `late_subject`, the node also seals a value for a subject whose key
/// it made after the keystore backup was shipped, and ships a snapshot that
/// holds that value: the bucket's newest backup lacks that subject's key.
fn shipped_with(keystore_backup: bool, late_subject: bool) -> Shipped {
    let src = tempdir("split-src-");
    let bucket = tempdir("split-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let node = rt.block_on(async {
        start_local(
            env.clone(),
            src.path(),
            NodeConfig {
                storage: Some(StorageConfig::new(src.path().to_path_buf())),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    rt.block_on(node.deploy(
        &guest("counter"),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    for i in 0..5 {
        let reply = rt
            .block_on(node.send(
                ActorRef::parse(&format!("counter/c{}", i % 2)).unwrap(),
                message("increment"),
                audit(),
                false,
                node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert!(reply.committed(), "{reply:?}");
    }
    rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
    let mut state = ShipState::load(src.path()).unwrap();
    rt.block_on(ship_once(&remote, src.path(), "main", &mut state))
        .unwrap();
    if keystore_backup {
        node.sealer()
            .keystore()
            .unwrap()
            .key_for_sealing("user:1", [9; 32], [3; 24], 1)
            .unwrap();
        rt.block_on(ship_keystore(
            &env,
            &remote,
            src.path(),
            &mut state,
            1_700_000_000_000,
            Duration::from_secs(30 * 86_400),
            [7; 24],
            node.key_source().unwrap(),
            node.sealer().keystore().unwrap(),
        ))
        .unwrap();
    }
    if late_subject {
        rt.block_on(node.set_privacy_mode(
            pb::PrivacyState::On,
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        ))
        .unwrap();
        let reply = rt
            .block_on(node.send(
                ActorRef::parse("counter/on").unwrap(),
                message("subject"),
                audit(),
                false,
                node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap();
        assert!(reply.committed(), "{reply:?}");
        rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
            .unwrap();
        rt.block_on(ship_once(&remote, src.path(), "main", &mut state))
            .unwrap();
    }
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(node);
    Shipped {
        bucket,
        remote,
        key,
    }
}

impl Shipped {
    /// The newest snapshot's directory in the bucket.
    fn snapshot_dir(&self) -> PathBuf {
        let mut all: Vec<_> = std::fs::read_dir(self.bucket.path().join("main/snapshots"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        all.sort();
        all.pop().unwrap()
    }

    /// Takes the secret store out of the newest snapshot, or puts one in
    /// (`bytes`), in the manifest and as an object, so that it is the only
    /// thing that changes about what the snapshot holds.
    fn set_secret_store(&self, bytes: Option<&[u8]>) {
        let dir = self.snapshot_dir();
        let manifest_path = dir.join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let files = manifest["files"].as_array_mut().unwrap();
        files.retain(|f| f["path"] != "secrets.db");
        let object = dir.join("secrets.db.zst");
        let _ = std::fs::remove_file(&object);
        if let Some(bytes) = bytes {
            files.push(serde_json::json!({
                "path": "secrets.db",
                "size": bytes.len(),
                "blake3": blake3::hash(bytes).to_hex().to_string(),
            }));
            std::fs::write(&object, zstd::encode_all(bytes, 3).unwrap()).unwrap();
        }
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    fn destination(&self) -> tempfile::TempDir {
        let dst = tempdir("split-dst-");
        std::fs::create_dir_all(dst.path().join("keys")).unwrap();
        std::fs::write(dst.path().join("keys/master.key"), &self.key).unwrap();
        dst
    }
}

fn listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            out.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .display()
                    .to_string(),
            );
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn same(a: &RestoreReport, b: &RestoreReport) {
    assert_eq!(a.snapshot_lsn, b.snapshot_lsn);
    assert_eq!(a.snapshot_id, b.snapshot_id);
    assert_eq!(a.state_hash, b.state_hash);
    assert_eq!(a.segments, b.segments);
    assert_eq!(a.log_first_lsn, b.log_first_lsn);
    assert_eq!(a.components, b.components);
    assert_eq!(a.keystore, b.keystore);
    assert_eq!(a.keys_missing, b.keys_missing);
}

fn missing_key() -> Keys {
    Keys {
        master_key_file: Some(PathBuf::from("/nonexistent/kronik/master.key")),
        ..Keys::default()
    }
}

#[test]
fn the_two_phases_restore_what_one_call_restores() {
    let shipped = shipped(true);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let whole = shipped.destination();
    let one = rt
        .block_on(restore(
            &shipped.remote,
            whole.path(),
            "main",
            false,
            &env,
            &Keys::default(),
            KeystoreMode::Require,
        ))
        .unwrap();
    let split = shipped.destination();
    let ownership = lock_data(split.path()).unwrap();
    let two = rt
        .block_on(async {
            let phase = root_phase(
                &shipped.remote,
                split.path(),
                &env,
                &Keys::default(),
                KeystoreMode::Require,
            )
            .await?;
            restore_as_owner(
                &shipped.remote,
                split.path(),
                "main",
                false,
                &env,
                phase,
                &ownership,
            )
            .await
        })
        .unwrap();
    assert_eq!(one.keystore, "installed");
    same(&one, &two);
    assert_eq!(listing(whole.path()), listing(split.path()));
    for file in ["branches/main/state.db", "keys/keystore.db"] {
        assert_eq!(
            std::fs::read(whole.path().join(file)).unwrap().len(),
            std::fs::read(split.path().join(file)).unwrap().len(),
            "{file}"
        );
    }
}

#[test]
fn the_root_phase_writes_nothing_and_leaves_the_stores_of_the_directory_to_the_owner() {
    let shipped = shipped(true);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let dst = shipped.destination();
    // Stores that are not the key's: the owner's check must find them, and the
    // root phase must not have looked.
    std::fs::write(
        dst.path().join("keys/secrets.db"),
        b"not a database of this key",
    )
    .unwrap();
    let before = listing(dst.path());
    let ownership = lock_data(dst.path()).unwrap();
    let phase = rt
        .block_on(root_phase(
            &shipped.remote,
            dst.path(),
            &env,
            &Keys::default(),
            KeystoreMode::Require,
        ))
        .unwrap();
    assert_eq!(listing(dst.path()), before, "the root phase wrote");
    let error = rt
        .block_on(restore_as_owner(
            &shipped.remote,
            dst.path(),
            "main",
            false,
            &env,
            phase,
            &ownership,
        ))
        .unwrap_err();
    assert!(
        matches!(error, ShipError::Key(_) | ShipError::KeySource(_)),
        "{error:?}"
    );
    assert_eq!(
        listing(dst.path()),
        before,
        "the failed restore left something"
    );
}

#[test]
fn a_restore_needs_a_key_for_a_backup_at_once_and_for_a_secret_store_only_when_it_is_there() {
    // A backup to decrypt: the key is needed before anything else happens.
    let with_backup = shipped(true);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let dst = with_backup.destination();
    let error = rt
        .block_on(root_phase(
            &with_backup.remote,
            dst.path(),
            &env,
            &missing_key(),
            KeystoreMode::Require,
        ))
        .err()
        .expect("the root phase needs the key for the backup");
    assert!(matches!(error, ShipError::KeySource(_)), "{error:?}");

    // No backup, no secret store: no key is needed, and none is read.
    let plain = shipped(false);
    plain.set_secret_store(None);
    let dst = plain.destination();
    let ownership = lock_data(dst.path()).unwrap();
    let report = rt
        .block_on(async {
            let phase = root_phase(
                &plain.remote,
                dst.path(),
                &env,
                &missing_key(),
                KeystoreMode::Require,
            )
            .await?;
            restore_as_owner(
                &plain.remote,
                dst.path(),
                "main",
                false,
                &env,
                phase,
                &ownership,
            )
            .await
        })
        .unwrap();
    assert_eq!(report.keystore, "none_in_bucket");

    // No backup, but a secret store in the snapshot: the key is needed after
    // all, and the error that the root phase kept is the one reported, before
    // anything is installed.
    plain.set_secret_store(Some(b"a secret store of some key"));
    let dst = plain.destination();
    let before = listing(dst.path());
    let ownership = lock_data(dst.path()).unwrap();
    let error = rt
        .block_on(async {
            let phase = root_phase(
                &plain.remote,
                dst.path(),
                &env,
                &missing_key(),
                KeystoreMode::Require,
            )
            .await?;
            restore_as_owner(
                &plain.remote,
                dst.path(),
                "main",
                false,
                &env,
                phase,
                &ownership,
            )
            .await
        })
        .unwrap_err();
    assert!(matches!(error, ShipError::KeySource(_)), "{error:?}");
    assert!(error.to_string().contains("master key"), "{error}");
    assert_eq!(listing(dst.path()), before);
}

#[test]
fn without_the_keystore_no_key_is_read_at_all() {
    let shipped = shipped(true);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let dst = shipped.destination();
    let ownership = lock_data(dst.path()).unwrap();
    let report = rt
        .block_on(async {
            let phase = root_phase(
                &shipped.remote,
                dst.path(),
                &env,
                &missing_key(),
                KeystoreMode::Without,
            )
            .await?;
            restore_as_owner(
                &shipped.remote,
                dst.path(),
                "main",
                false,
                &env,
                phase,
                &ownership,
            )
            .await
        })
        .unwrap();
    assert_eq!(report.keystore, "skipped");
}

#[test]
fn a_directory_that_was_replaced_after_it_was_locked_is_not_restored_into() {
    let shipped = shipped(false);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let dst = shipped.destination();
    let ownership = lock_data(dst.path()).unwrap();
    let phase = rt
        .block_on(root_phase(
            &shipped.remote,
            dst.path(),
            &env,
            &Keys::default(),
            KeystoreMode::Require,
        ))
        .unwrap();
    // Another directory at the same path.
    let moved = dst.path().with_extension("moved");
    std::fs::rename(dst.path(), &moved).unwrap();
    std::fs::create_dir(dst.path()).unwrap();
    let error = rt
        .block_on(restore_as_owner(
            &shipped.remote,
            dst.path(),
            "main",
            false,
            &env,
            phase,
            &ownership,
        ))
        .unwrap_err();
    assert!(error.to_string().contains("was replaced"), "{error}");
    assert!(
        listing(dst.path()).is_empty(),
        "something was written into the other directory"
    );
    let _ = std::fs::remove_dir_all(&moved);
}

#[test]
fn a_stage_left_by_a_restore_that_was_killed_is_removed_by_the_next_and_is_not_data() {
    let shipped = shipped(false);
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let dst = shipped.destination();
    // What a kill in the middle leaves: a stage with part of a download in it.
    let stage = dst.path().join(".restore");
    std::fs::create_dir_all(stage.join("snapshot")).unwrap();
    std::fs::write(stage.join("snapshot/state.db"), b"half a database").unwrap();
    std::fs::create_dir_all(stage.join("branch")).unwrap();
    std::fs::write(stage.join("branch/state.db"), b"another half").unwrap();
    // A node starting on the directory does not read it as data, and leaves it
    // alone. (Its own runtime, so that the node is gone when the block ends.)
    {
        let other = self::rt();
        let started = other.block_on(async {
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                dst.path(),
                NodeConfig::default(),
            )
            .await
            .map(|node| node.applied_lsn())
        });
        assert!(started.is_ok(), "{:?}", started.err());
    }
    assert_eq!(
        std::fs::read(stage.join("snapshot/state.db")).unwrap(),
        b"half a database",
        "the start touched the stage"
    );
    // The next restore starts from nothing and leaves no stage.
    std::fs::remove_dir_all(dst.path().join("branches")).ok();
    let ownership = lock_data(dst.path()).unwrap();
    let report = rt
        .block_on(async {
            let phase = root_phase(
                &shipped.remote,
                dst.path(),
                &env,
                &Keys::default(),
                KeystoreMode::Require,
            )
            .await?;
            restore_as_owner(
                &shipped.remote,
                dst.path(),
                "main",
                true,
                &env,
                phase,
                &ownership,
            )
            .await
        })
        .unwrap();
    assert!(report.snapshot_lsn > 0);
    assert!(!stage.exists(), "the stage was left behind");
}

/// Restores `shipped` into a fresh destination in one process and in the two
/// phases, in the keystore mode `mode`, and returns what each said.
fn both_flows(
    shipped: &Shipped,
    mode: KeystoreMode,
) -> (
    Result<RestoreReport, ShipError>,
    Result<RestoreReport, ShipError>,
    Vec<String>,
) {
    let rt = rt();
    let env = Env::real(rt.handle().clone());
    let whole = shipped.destination();
    let one = rt.block_on(restore(
        &shipped.remote,
        whole.path(),
        "main",
        false,
        &env,
        &Keys::default(),
        mode,
    ));
    let split = shipped.destination();
    let before = listing(split.path());
    let ownership = lock_data(split.path()).unwrap();
    let two = rt.block_on(async {
        let phase = root_phase(&shipped.remote, split.path(), &env, &Keys::default(), mode).await?;
        restore_as_owner(
            &shipped.remote,
            split.path(),
            "main",
            false,
            &env,
            phase,
            &ownership,
        )
        .await
    });
    // What a refused restore leaves must be what it found, in both flows.
    if two.is_err() {
        assert_eq!(listing(split.path()), before);
        assert_eq!(listing(whole.path()), before);
    }
    (one, two, listing(split.path()))
}

#[test]
fn a_backup_that_lacks_a_key_is_refused_in_both_flows_and_nothing_is_installed() {
    let shipped = shipped_with(true, true);
    let (one, two, _) = both_flows(&shipped, KeystoreMode::Require);
    for result in [one, two] {
        let Err(ShipError::KeystoreIncomplete(message)) = result else {
            panic!("expected KEYSTORE_INCOMPLETE, got {result:?}");
        };
        assert!(message.contains("user:2"), "{message}");
    }
}

#[test]
fn allow_missing_keys_installs_the_backup_and_names_the_subjects_in_both_flows() {
    let shipped = shipped_with(true, true);
    let (one, two, _) = both_flows(&shipped, KeystoreMode::AllowMissingKeys);
    let (one, two) = (one.unwrap(), two.unwrap());
    assert_eq!(one.keystore, "installed");
    assert!(one.keys_missing.contains(&"user:2".to_string()), "{one:?}");
    same(&one, &two);
}

#[test]
fn without_the_keystore_installs_none_in_both_flows() {
    let shipped = shipped_with(true, true);
    let (one, two, files) = both_flows(&shipped, KeystoreMode::Without);
    let (one, two) = (one.unwrap(), two.unwrap());
    assert_eq!(one.keystore, "skipped");
    same(&one, &two);
    assert!(
        !files.iter().any(|f| f == "keys/keystore.db"),
        "a keystore was installed: {files:?}"
    );
}
