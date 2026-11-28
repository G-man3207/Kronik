use super::*;
use std::sync::Arc;

fn pair() -> (
    tempfile::TempDir,
    MasterKey,
    Arc<SecretStore>,
    Arc<SecretStore>,
) {
    let dir = tempfile::tempdir().unwrap();
    let (master, _) = MasterKey::load(None, &dir.path().join("master.key"), Some([7; 32])).unwrap();
    let source = Arc::new(
        SecretStore::open(
            Connection::open(dir.path().join("source.db")).unwrap(),
            &master,
        )
        .unwrap(),
    );
    let target = Arc::new(
        SecretStore::open(
            Connection::open(dir.path().join("target.db")).unwrap(),
            &master,
        )
        .unwrap(),
    );
    (dir, master, source, target)
}

fn write(store: &SecretStore, version: u64, nonce: u8) {
    store
        .set_at(
            "token",
            version,
            b"retained plaintext",
            [nonce; 24],
            12,
            "original-admin",
            "original set",
        )
        .unwrap();
}

fn changes(store: &SecretStore) -> i64 {
    store
        .conn()
        .query_row("SELECT total_changes()", [], |row| row.get(0))
        .unwrap()
}

/// Opens a staged snapshot read-only; the staged backup stays alive with it.
fn open_reader(
    staged: &EncryptedSecretSnapshot,
    master: &MasterKey,
) -> Result<SecretStore, PrivacyError> {
    let conn = Connection::open_with_flags(
        staged.database_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    SecretStore::open_readonly(conn, master)
}

#[test]
fn metadata_only_current_tracks_physical_set_delete_and_retained_history() {
    let (dir, master, _source, target) = pair();
    assert_eq!(target.current_meta("token").unwrap(), None);
    target
        .set_at(
            "token",
            1,
            b"retained plaintext",
            [3; 24],
            12,
            "original-admin",
            "original set",
        )
        .unwrap();
    assert_eq!(
        target.current_meta("token").unwrap(),
        Some(target.current("token").unwrap().unwrap().meta)
    );
    let second = target
        .set_at(
            "token",
            2,
            b"physical current two",
            [4; 24],
            20,
            "admin",
            "owned physical set",
        )
        .unwrap();
    assert_eq!(target.current_meta("token").unwrap(), Some(second));
    assert_eq!(
        target.current("token").unwrap().unwrap().value,
        b"physical current two"
    );
    assert_eq!(
        target
            .retained_version_for_scrub("token", 1)
            .unwrap()
            .unwrap()
            .value,
        b"retained plaintext"
    );
    target.delete("token", 2, 77).unwrap();
    assert_eq!(target.current_meta("token").unwrap(), None);
    assert!(target.current("token").unwrap().is_none());
    assert_eq!(
        target
            .retained_version_for_scrub("token", 1)
            .unwrap()
            .unwrap()
            .value,
        b"retained plaintext"
    );
    let third = target
        .set_at(
            "token",
            3,
            b"physical current three",
            [5; 24],
            80,
            "admin",
            "new owned physical set",
        )
        .unwrap();
    assert_eq!(target.current_meta("token").unwrap(), Some(third.clone()));
    assert_eq!(
        target.current("token").unwrap().unwrap().value,
        b"physical current three"
    );
    drop(target);
    let reopened = SecretStore::open(
        Connection::open(dir.path().join("target.db")).unwrap(),
        &master,
    )
    .unwrap();
    let before = changes(&reopened);
    assert_eq!(reopened.current_meta("token").unwrap(), Some(third.clone()));
    assert_eq!(changes(&reopened), before, "metadata current is read-only");
    assert!(reopened.version("token", 1).unwrap().is_none());
    assert_eq!(
        reopened
            .retained_version_for_scrub("token", 1)
            .unwrap()
            .unwrap()
            .value,
        b"retained plaintext"
    );
    // A metadata match is deliberately not proof that the ciphertext can be opened.
    reopened
        .conn()
        .execute(
            "UPDATE secrets SET ciphertext = x'00' WHERE name='token' AND version=3",
            [],
        )
        .unwrap();
    let before = changes(&reopened);
    assert_eq!(reopened.current_meta("token").unwrap(), Some(third));
    assert!(matches!(
        reopened.current("token"),
        Err(PrivacyError::Decrypt(_))
    ));
    assert_eq!(changes(&reopened), before);
    reopened
        .conn()
        .execute(
            "UPDATE secrets SET version=0 WHERE name='token' AND version=3",
            [],
        )
        .unwrap();
    assert!(matches!(
        reopened.current_meta("token"),
        Err(PrivacyError::InvalidStoredVersion(0))
    ));
}

#[test]
fn frozen_inventory_cannot_mutate_rows_or_claim_original_live_ownership() {
    let (dir, master, source, _target) = pair();
    write(&source, 7, 3);
    let reader = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &master,
    )
    .unwrap();
    let before = changes(&reader);
    assert!(matches!(
        reader.reopen_owned(),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    assert!(matches!(
        reader.set_at("token", 8, b"not installed", [4; 24], 20, "admin", "set"),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    assert!(matches!(
        reader.delete("token", 7, 21),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    assert_eq!(changes(&reader), before);
    assert_eq!(
        reader.current("token").unwrap().unwrap().value,
        b"retained plaintext"
    );
}

#[test]
fn owned_constructor_rejects_symlink_without_chmod_or_row_mutation() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    struct NoMutableData;
    impl SecretStoreData for NoMutableData {
        fn begin(&self, _: &str, _: u64) -> Result<u64, PrivacyError> {
            Err(PrivacyError::SecretStoreUnowned)
        }
        fn sql_committed(&self, _: &str, _: u64, _: u64) -> Result<(), PrivacyError> {
            Err(PrivacyError::SecretStoreUnknown)
        }
        fn sql_aborted(&self, _: &str, _: u64, _: u64) {
            panic!("a denied mutation cannot produce a running SQL interval");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let owner = key_source::lock_data(dir.path()).unwrap();
    std::fs::create_dir(dir.path().join("keys")).unwrap();
    let master = MasterKey::from_bytes([7; 32]).unwrap();
    let referent = dir.path().join("unrelated.db");
    let original = SecretStore::open(Connection::open(&referent).unwrap(), &master).unwrap();
    write(&original, 7, 3);
    std::fs::set_permissions(&referent, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = changes(&original);
    symlink(&referent, dir.path().join("keys/secrets.db")).unwrap();
    assert!(matches!(
        SecretStore::open_owned(&owner, &master, Arc::new(NoMutableData)),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    assert_eq!(
        std::fs::metadata(&referent).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(changes(&original), before);
    assert_eq!(
        original.current("token").unwrap().unwrap().value,
        b"retained plaintext"
    );
}

#[test]
fn readonly_stage_preserves_values_and_rejects_mutable_connections() {
    let (dir, master, source, _target) = pair();
    write(&source, 7, 3);
    let staged = source.stage_encrypted_snapshot(dir.path()).unwrap();
    let before = std::fs::read(staged.database_path()).unwrap();
    assert!(matches!(
        SecretStore::open_readonly(Connection::open(staged.database_path()).unwrap(), &master),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    let reader = open_reader(&staged, &master).unwrap();
    assert_eq!(
        reader.current("token").unwrap().unwrap().value,
        b"retained plaintext"
    );
    assert!(matches!(
        reader.delete("token", 7, 21),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    assert_eq!(std::fs::read(staged.database_path()).unwrap(), before);
}

#[test]
fn directory_sync_is_real_file_only_and_does_not_claim_memory_durability() {
    let (_dir, _master, source, _target) = pair();
    write(&source, 7, 3);
    source.sync_parent_directory().unwrap();
    let memory = SecretStore::open(
        Connection::open_in_memory().unwrap(),
        &MasterKey::from_bytes([7; 32]).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        memory.sync_parent_directory(),
        Err(PrivacyError::FileStoreRequired)
    ));
}

#[test]
fn closed_encrypted_stage_links_into_a_new_destination_without_overwriting_live_custody() {
    use std::os::unix::fs::PermissionsExt as _;
    let (dir, master, source, target) = pair();
    write(&source, 7, 3);
    write(&target, 2, 4);
    let staged = source.stage_encrypted_snapshot(dir.path()).unwrap();
    assert_eq!(
        std::fs::metadata(staged.database_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(staged.database_path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = staged.database_path().as_os_str().to_os_string();
        sidecar.push(suffix);
        assert!(!Path::new(&sidecar).exists());
    }
    let destination = dir.path().join("owned-snapshot");
    std::fs::create_dir(&destination).unwrap();
    let installed = destination.join("secrets.db");
    std::fs::hard_link(staged.database_path(), &installed).unwrap();
    assert_eq!(
        std::fs::hard_link(staged.database_path(), dir.path().join("target.db"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    let stage_path = staged.database_path().to_owned();
    drop(staged);
    assert!(!stage_path.exists());
    let reader = SecretStore::open_readonly(
        Connection::open_with_flags(&installed, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap(),
        &master,
    )
    .unwrap();
    assert_eq!(
        reader
            .retained_version_for_scrub("token", 7)
            .unwrap()
            .unwrap()
            .value,
        b"retained plaintext"
    );
    assert_eq!(
        target.current("token").unwrap().unwrap().value,
        b"retained plaintext"
    );
}

#[test]
fn stored_floor_is_read_only_name_bound_and_survives_without_a_row_at_the_delete_cut() {
    let (dir, master, source, target) = pair();
    write(&source, 7, 3);
    write(&target, 7, 3);
    assert_eq!(target.stored_deletion_floor("token").unwrap(), None);
    assert!(matches!(
        target.stored_deletion_floor("Bad Name"),
        Err(PrivacyError::InvalidName(_))
    ));
    target.delete("token", 9, 20).unwrap();
    let floor = Some(SecretDeletionFloor {
        through_version: 9,
        applied_wall_ms: 20,
    });
    let before = changes(&target);
    assert_eq!(target.stored_deletion_floor("token").unwrap(), floor);
    assert_eq!(target.stored_deletion_floor("other").unwrap(), None);
    assert!(target.version("token", 9).unwrap().is_none());
    assert_eq!(changes(&target), before);
    assert_eq!(
        source.stored_deletion_floor("token").unwrap(),
        None,
        "this is a local fact, not a fabricated global publication"
    );
    target.delete("token", 8, 30).unwrap();
    assert_eq!(target.stored_deletion_floor("token").unwrap(), floor);
    target
        .set_at(
            "token",
            10,
            b"after physical cut",
            [4; 24],
            31,
            "admin",
            "set",
        )
        .unwrap();
    drop(target);
    let reopened = SecretStore::open(
        Connection::open(dir.path().join("target.db")).unwrap(),
        &master,
    )
    .unwrap();
    assert_eq!(reopened.stored_deletion_floor("token").unwrap(), floor);
    assert!(reopened.version("token", 7).unwrap().is_none());
    assert_eq!(
        reopened.version("token", 10).unwrap().unwrap().value,
        b"after physical cut"
    );
    reopened
        .conn()
        .execute(
            "UPDATE secret_deletion_floors SET through_version=0 WHERE name='token'",
            [],
        )
        .unwrap();
    let before_error = changes(&reopened);
    assert!(matches!(
        reopened.stored_deletion_floor("token"),
        Err(PrivacyError::InvalidStoredVersion(0))
    ));
    assert_eq!(changes(&reopened), before_error);
    reopened.conn().execute("UPDATE secret_deletion_floors SET through_version=9, deleted_wall_ms=-1 WHERE name='token'", []).unwrap();
    assert!(matches!(
        reopened.stored_deletion_floor("token"),
        Err(PrivacyError::InvalidTimestamp)
    ));
}

#[test]
fn live_store_backup_reader_preserves_committed_wal_and_retained_history() {
    let (dir, master, source, _target) = pair();
    source
        .conn()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0;")
        .unwrap();
    let baseline = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &master,
    )
    .unwrap();
    let physical = u64::from(u32::MAX) + 1;
    write(&source, physical, 3);
    source.delete("token", physical, 77).unwrap();
    source
        .set_at(
            "token",
            physical + 1,
            b"current WAL value",
            [4; 24],
            78,
            "admin",
            "set",
        )
        .unwrap();
    let before = changes(&source);
    let reader = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &master,
    )
    .unwrap();
    assert_eq!(changes(&source), before);
    assert!(baseline.metadata_page(None, true).unwrap().is_empty());
    assert_eq!(reader.metadata_page(None, true).unwrap().len(), 2);
    assert_eq!(
        reader
            .retained_version_for_scrub("token", physical)
            .unwrap()
            .unwrap()
            .value,
        b"retained plaintext"
    );
    assert!(reader.version("token", physical).unwrap().is_none());
    assert_eq!(
        reader
            .version("token", physical + 1)
            .unwrap()
            .unwrap()
            .value,
        b"current WAL value"
    );
    assert_eq!(
        reader.stored_deletion_floor("token").unwrap(),
        Some(SecretDeletionFloor {
            through_version: physical,
            applied_wall_ms: 77,
        })
    );
    assert!(matches!(
        reader.set_at(
            "token",
            physical + 2,
            b"must not write",
            [5; 24],
            79,
            "admin",
            "set"
        ),
        Err(PrivacyError::SecretStoreUnowned)
    ));
    source
        .set_at(
            "token",
            physical + 2,
            b"later live value",
            [5; 24],
            80,
            "admin",
            "set",
        )
        .unwrap();
    assert_eq!(
        reader.current("token").unwrap().unwrap().value,
        b"current WAL value"
    );
    assert!(reader.version("token", physical + 2).unwrap().is_none());
    assert_eq!(
        source.current("token").unwrap().unwrap().value,
        b"later live value"
    );
}

#[test]
fn completed_legacy_reader_never_initializes_tables_or_certifies_erased_ciphertext() {
    let (dir, master, source, _target) = pair();
    write(&source, 7, 3);
    source.delete("token", 7, 20).unwrap();
    source
        .set_at(
            "other",
            1,
            b"real legacy value",
            [4; 24],
            21,
            "admin",
            "set",
        )
        .unwrap();
    source
        .conn()
        .execute_batch(
            "UPDATE secrets SET nonce=x'', ciphertext=x'' WHERE name='token'; \
         DROP TABLE key_check; DROP TABLE secret_deletion_floors;",
        )
        .unwrap();
    let reader = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &master,
    )
    .unwrap();
    let wrong = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &MasterKey::from_bytes([8; 32]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reader.stored_deletion_floor("token").unwrap(),
        None,
        "missing legacy floor table stays unknown"
    );
    assert_eq!(reader.metadata_page(None, true).unwrap().len(), 2);
    assert!(matches!(
        reader.retained_version_for_scrub("token", 7),
        Err(PrivacyError::Decrypt(_))
    ));
    assert!(matches!(reader.values(), Err(PrivacyError::Decrypt(_))));
    assert_eq!(
        reader
            .retained_version_for_scrub("other", 1)
            .unwrap()
            .unwrap()
            .value,
        b"real legacy value"
    );
    assert!(matches!(
        wrong.retained_version_for_scrub("other", 1),
        Err(PrivacyError::Decrypt(_))
    ));
    let initialized: i64 = reader.conn().query_row(
        "SELECT count(*) FROM sqlite_schema WHERE name IN ('key_check','secret_deletion_floors')",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(initialized, 0);
}

#[test]
fn completed_reader_rejects_wrong_recorded_keys_and_invalid_versions() {
    let (dir, master, source, _target) = pair();
    write(&source, 7, 3);
    let stage = source.stage_encrypted_snapshot(dir.path()).unwrap();
    assert!(matches!(
        open_reader(&stage, &MasterKey::from_bytes([8; 32]).unwrap()),
        Err(PrivacyError::KeyMismatch(_))
    ));
    // A version outside 1..=MAX_SECRET_VERSION is refused at open.
    for version in [
        0,
        i64::try_from(kronik_proto::secret::MAX_SECRET_VERSION + 1).unwrap(),
    ] {
        source
            .conn()
            .execute(
                "UPDATE secrets SET version=?1 WHERE name='token'",
                [version],
            )
            .unwrap();
        let stage = source.stage_encrypted_snapshot(dir.path()).unwrap();
        assert!(matches!(
            open_reader(&stage, &master),
            Err(PrivacyError::InvalidStoredVersion(v)) if v == version
        ));
    }
}

#[test]
fn physical_highwater_includes_orphans_and_floors_without_decrypting_or_allocating_a_version() {
    let (dir, master, source, target) = pair();
    assert_eq!(source.physical_highwater("token").unwrap(), 0);
    assert!(matches!(
        source.physical_highwater("Bad Name"),
        Err(PrivacyError::InvalidName(_))
    ));
    write(&source, 17, 3);
    // An unclaimed physical row still owns its AAD version even if its value is lost.
    source
        .conn()
        .execute(
            "UPDATE secrets SET nonce=x'', ciphertext=x'00' WHERE name='token'",
            [],
        )
        .unwrap();
    let before = changes(&source);
    assert_eq!(source.physical_highwater("token").unwrap(), 17);
    assert_eq!(changes(&source), before);
    assert_eq!(
        target.physical_highwater("token").unwrap(),
        0,
        "local metadata is not global publication"
    );
    source.delete("token", 19, 77).unwrap();
    assert!(source.version("token", 19).unwrap().is_none());
    assert_eq!(source.physical_highwater("token").unwrap(), 19);
    source
        .set_at(
            "token",
            20,
            b"new physical value",
            [4; 24],
            78,
            "admin",
            "set",
        )
        .unwrap();
    assert_eq!(source.physical_highwater("token").unwrap(), 20);
    assert_eq!(
        source.version("token", 20).unwrap().unwrap().value,
        b"new physical value"
    );
    source.delete("floor-only", 23, 79).unwrap();
    assert!(source.version("floor-only", 23).unwrap().is_none());
    assert_eq!(source.physical_highwater("floor-only").unwrap(), 23);
    let wide = u64::from(u32::MAX) + 1;
    source
        .set_at(
            "wide",
            wide,
            b"wide physical value",
            [5; 24],
            80,
            "admin",
            "set",
        )
        .unwrap();
    assert_eq!(source.physical_highwater("wide").unwrap(), wide);
    source
        .delete("wide", kronik_proto::secret::MAX_SECRET_VERSION, 81)
        .unwrap();
    assert_eq!(
        source.physical_highwater("wide").unwrap(),
        kronik_proto::secret::MAX_SECRET_VERSION
    );
    let snapshot = open_reader(
        &source.stage_encrypted_snapshot(dir.path()).unwrap(),
        &master,
    )
    .unwrap();
    assert_eq!(snapshot.physical_highwater("token").unwrap(), 20);
    assert_eq!(snapshot.physical_highwater("floor-only").unwrap(), 23);
    source
        .conn()
        .execute(
            "UPDATE secrets SET version=0 WHERE name='token' AND version=17",
            [],
        )
        .unwrap();
    assert!(matches!(
        source.physical_highwater("token"),
        Err(PrivacyError::InvalidStoredVersion(0))
    ));
}

#[test]
fn the_owned_file_check_accepts_the_held_file_and_refuses_a_replacement() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = tempfile::tempdir().unwrap();
    let owner = key_source::lock_data(dir.path()).unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let database = keys.join("secrets.db");
    let replacement = keys.join("replacement.db");
    std::fs::write(&database, b"original").unwrap();
    std::fs::write(&replacement, b"replacement").unwrap();

    let held = owner.directory(Path::new("keys"), false).unwrap();
    let original = std::fs::metadata(&database).unwrap();
    let identity = keystore::ffi::FileIdentity {
        device: original.dev(),
        inode: original.ino(),
    };
    assert!(
        owner
            .holds_file(Path::new("keys"), &held, "secrets.db", identity)
            .unwrap()
    );

    std::fs::rename(&replacement, &database).unwrap();
    assert!(
        !owner
            .holds_file(Path::new("keys"), &held, "secrets.db", identity)
            .unwrap()
    );
}
