use super::*;
use std::sync::Arc;
use kronik_proto::log::v1 as pb;
use secret_backend::{BackendError, SecretBackend, file::FileBackend};
use crate::key_source::providers::test_authority;

fn pair() -> (tempfile::TempDir, MasterKey, Arc<SecretStore>, Arc<SecretStore>) {
    let dir = tempfile::tempdir().unwrap();
    let (master, _) = MasterKey::load(None, &dir.path().join("master.key"), Some([7; 32])).unwrap();
    let source = Arc::new(SecretStore::open(
        Connection::open(dir.path().join("source.db")).unwrap(), &master,
    ).unwrap());
    let target = Arc::new(SecretStore::open(
        Connection::open(dir.path().join("target.db")).unwrap(), &master,
    ).unwrap());
    (dir, master, source, target)
}

fn expected(store: &SecretStore, logical: u64, physical: u64, value: &[u8]) -> pb::SecretVersion {
    expected_alias(store, "token", "token", logical, physical, value)
}

fn expected_alias(
    store: &SecretStore, logical_name: &str, physical_name: &str,
    logical: u64, physical: u64, value: &[u8],
) -> pb::SecretVersion {
    pb::SecretVersion {
        name: logical_name.into(), version: logical,
        version_hash: store.version_hash(logical_name, logical, value).unwrap(),
        backend: "file".into(), source_version: physical.to_string(), deleted: false,
        audit: Some(pb::Audit { token_id: "observer".into(), reason: "observe old row".into(), wall_time_ms: 90 }),
        r#ref: physical_name.into(), binding: "file".into(), link_generation: 0,
        canonical_ref: physical_name.into(), phase: pb::secret_version::Phase::Active as i32,
        hash_revision: if logical <= kronik_proto::secret::LEGACY_SECRET_VERSION_MAX { 1 } else { 2 },
    }
}

fn write(store: &SecretStore, version: u64, nonce: u8) -> EncryptedSecretRow {
    store.set_at("token", version, b"retained plaintext", [nonce; 24], 12, "original-admin", "original set").unwrap();
    store.export_encrypted_row("token", version).unwrap().unwrap()
}

fn changes(store: &SecretStore) -> i64 {
    store.conn().query_row("SELECT total_changes()", [], |row| row.get(0)).unwrap()
}

#[test]
fn metadata_only_current_tracks_physical_set_delete_and_retained_history() {
    let (dir, master, source, target) = pair();
    assert_eq!(target.current_meta("token").unwrap(), None);
    let first = write(&source, 1, 3);
    let identity = expected(&source, 1, 1, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &first, None, SecretImportDisposition::Operational).unwrap(),
        SecretImportDisposition::Operational);
    assert_eq!(target.current_meta("token").unwrap(), Some(target.current("token").unwrap().unwrap().meta));
    let second = target.set_at("token", 2, b"physical current two", [4; 24], 20, "admin", "owned physical set").unwrap();
    assert_eq!(target.current_meta("token").unwrap(), Some(second));
    assert_eq!(target.current("token").unwrap().unwrap().value, b"physical current two");
    assert_eq!(target.retained_version_for_scrub("token", 1).unwrap().unwrap().value, b"retained plaintext");
    target.delete("token", 2, 77).unwrap();
    assert_eq!(target.current_meta("token").unwrap(), None);
    assert!(target.current("token").unwrap().is_none());
    assert_eq!(target.retained_version_for_scrub("token", 1).unwrap().unwrap().value, b"retained plaintext");
    let third = target.set_at("token", 3, b"physical current three", [5; 24], 80, "admin", "new owned physical set").unwrap();
    assert_eq!(target.current_meta("token").unwrap(), Some(third.clone()));
    assert_eq!(target.current("token").unwrap().unwrap().value, b"physical current three");
    drop(target);
    let reopened = SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap();
    let before = changes(&reopened);
    assert_eq!(reopened.current_meta("token").unwrap(), Some(third.clone()));
    assert_eq!(changes(&reopened), before, "metadata current is read-only");
    assert!(reopened.version("token", 1).unwrap().is_none());
    assert_eq!(reopened.retained_version_for_scrub("token", 1).unwrap().unwrap().value, b"retained plaintext");
    // A metadata match is deliberately not proof that the ciphertext can be opened.
    reopened.conn().execute("UPDATE secrets SET ciphertext = x'00' WHERE name='token' AND version=3", []).unwrap();
    let before = changes(&reopened);
    assert_eq!(reopened.current_meta("token").unwrap(), Some(third));
    assert!(matches!(reopened.current("token"), Err(PrivacyError::Decrypt(_))));
    assert_eq!(changes(&reopened), before);
    reopened.conn().execute("UPDATE secrets SET version=0 WHERE name='token' AND version=3", []).unwrap();
    assert!(matches!(reopened.current_meta("token"), Err(PrivacyError::InvalidStoredVersion(0))));
}

#[test]
fn frozen_inventory_cannot_mutate_rows_or_claim_original_live_ownership() {
    let (dir, master, source, _target) = pair();
    let row = write(&source, 7, 3);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    let reader = source.stage_encrypted_snapshot(dir.path()).unwrap().open_readonly(&master).unwrap();
    let before = changes(&reader);
    assert!(matches!(reader.reopen_owned(), Err(PrivacyError::SecretStoreUnowned)));
    assert!(matches!(reader.set_at("token", 8, b"not installed", [4; 24], 20, "admin", "set"),
        Err(PrivacyError::SecretStoreUnowned)));
    assert!(matches!(reader.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational),
        Err(PrivacyError::SecretStoreUnowned)));
    assert!(matches!(reader.delete("token", 7, 21), Err(PrivacyError::SecretStoreUnowned)));
    assert_eq!(changes(&reader), before);
    assert_eq!(reader.export_encrypted_row("token", 7).unwrap(), Some(row.clone()));
    assert_eq!(reader.current("token").unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(source.export_encrypted_row("token", 7).unwrap(), Some(row));
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
    let row = write(&original, 7, 3);
    std::fs::set_permissions(&referent, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = changes(&original);
    symlink(&referent, dir.path().join("keys/secrets.db")).unwrap();
    assert!(matches!(SecretStore::open_owned(&owner, &master, Arc::new(NoMutableData)),
        Err(PrivacyError::SecretStoreUnowned)));
    assert_eq!(std::fs::metadata(&referent).unwrap().permissions().mode() & 0o777, 0o640);
    assert_eq!(changes(&original), before);
    assert_eq!(original.export_encrypted_row("token", 7).unwrap(), Some(row));
    assert_eq!(original.current("token").unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn readonly_stage_preserves_values_and_rejects_mutable_connections_and_wrong_master() {
    let (dir, master, source, _target) = pair();
    let row = write(&source, 7, 3);
    let staged = source.stage_encrypted_snapshot(dir.path()).unwrap();
    let before = std::fs::read(staged.database_path()).unwrap();
    assert!(matches!(SecretStore::open_readonly(Connection::open(staged.database_path()).unwrap(), &master),
        Err(PrivacyError::SecretStoreUnowned)));
    let readonly = Connection::open_with_flags(staged.database_path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let reader = SecretStore::open_readonly(readonly, &master).unwrap();
    assert_eq!(reader.current("token").unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(reader.export_encrypted_row("token", 7).unwrap(), Some(row.clone()));
    assert!(matches!(reader.delete("token", 7, 21), Err(PrivacyError::SecretStoreUnowned)));
    drop(reader);
    let readonly = Connection::open_with_flags(staged.database_path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert!(matches!(SecretStore::open_readonly(readonly, &MasterKey::from_bytes([8; 32]).unwrap()),
        Err(PrivacyError::KeyMismatch(_))));
    assert_eq!(std::fs::read(staged.database_path()).unwrap(), before);
    assert_eq!(source.export_encrypted_row("token", 7).unwrap(), Some(row));
}

#[tokio::test]
async fn real_file_consumer_reads_physical_row_for_a_distinct_wide_logical_identity() {
    let (_dir, _master, source, target) = pair();
    let physical = u64::from(u32::MAX) + 1;
    let logical = kronik_proto::secret::MAX_SECRET_VERSION;
    let row = write(&source, physical, 3);
    let before = changes(&source);
    assert_eq!(source.export_encrypted_row("token", physical).unwrap(), Some(row.clone()));
    assert_eq!(changes(&source), before, "export must be read-only");
    let identity = expected(&source, logical, physical, b"retained plaintext");
    assert_ne!(identity.version_hash, row.version_hash);
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    let after_import = changes(&target);
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(changes(&target), after_import, "exact-envelope retry does not rewrite audit");
    assert_eq!(target.export_encrypted_row("token", physical).unwrap(), Some(row.clone()));
    assert_eq!(target.version("token", physical).unwrap().unwrap().value, b"retained plaintext");
    assert!(target.version("token", logical).unwrap().is_none());
    let backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), target.clone());
    let fetched = backend.version("token", &identity.source_version, test_authority()).await.unwrap();
    assert_eq!(fetched.value.as_slice(), b"retained plaintext");
    assert_eq!(target.version_hash("token", identity.version, &fetched.value).unwrap(), identity.version_hash);
    assert!(matches!(backend.version("token", &logical.to_string(), test_authority()).await, Err(BackendError::VersionGone)));
    assert_eq!(row.token_id, "original-admin");
    assert_eq!(row.reason, "original set");
    assert_eq!(row.created_wall_ms, 12);
    assert_eq!(identity.audit.as_ref().unwrap().token_id, "observer");
}

#[test]
fn valid_different_encryption_or_audit_is_a_conflict_not_an_upsert() {
    let (dir, master, source, target) = pair();
    let row = write(&source, 7, 3);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    let alternative = SecretStore::open(Connection::open(dir.path().join("alternative.db")).unwrap(), &master).unwrap();
    let different = write(&alternative, 7, 4);
    assert_eq!(different.version_hash, row.version_hash);
    assert_ne!(different.ciphertext, row.ciphertext);
    assert!(matches!(target.import_encrypted_row(&identity, &different, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretRowConflict)));
    let mut changed_audit = row.clone(); changed_audit.reason = "replacement audit".into();
    assert!(matches!(target.import_encrypted_row(&identity, &changed_audit, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretRowConflict)));
    assert_eq!(target.export_encrypted_row("token", 7).unwrap(), Some(row));
    assert_eq!(target.current("token").unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn original_audit_larger_than_64_kib_is_not_silently_given_a_new_api_limit() {
    let (_dir, _master, source, target) = pair();
    let reason = "r".repeat(64 * 1024 + 1);
    source.set_at("token", 7, b"retained plaintext", [3; 24], 12, "original-admin", &reason).unwrap();
    let row = source.export_encrypted_row("token", 7).unwrap().unwrap();
    let identity = expected(&source, 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(target.export_encrypted_row("token", 7).unwrap().unwrap().reason, reason);
    assert_eq!(target.current("token").unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn wrong_master_tamper_and_noncanonical_expected_records_leave_original_rows_untouched() {
    let (dir, _master, source, target) = pair();
    let row = write(&source, 7, 3);
    let original = write(&target, 2, 8);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    let wrong = SecretStore::open(Connection::open(dir.path().join("wrong.db")).unwrap(), &MasterKey::from_bytes([8; 32]).unwrap()).unwrap();
    assert!(wrong.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).is_err());
    assert!(wrong.current("token").unwrap().is_none());
    let mut bad_rows = Vec::new();
    let mut bad = row.clone(); bad.ciphertext[0] ^= 1; bad_rows.push(bad);
    let mut bad = row.clone(); bad.nonce[0] ^= 1; bad_rows.push(bad);
    let mut bad = row.clone(); bad.nonce.pop(); bad_rows.push(bad);
    let mut bad = row.clone(); bad.ciphertext.truncate(15); bad_rows.push(bad);
    let mut bad = row.clone(); bad.version_hash[0] ^= 1; bad_rows.push(bad);
    let mut bad = row.clone(); bad.version_hash.push(0); bad_rows.push(bad);
    let mut bad = row.clone(); bad.physical_version = 0; bad_rows.push(bad);
    let mut bad = row.clone(); bad.physical_version = kronik_proto::secret::MAX_SECRET_VERSION + 1; bad_rows.push(bad);
    let mut bad = row.clone(); bad.created_wall_ms = u64::MAX; bad_rows.push(bad);
    let mut bad = row.clone(); bad.deletion_applied_wall_ms = Some(0); bad_rows.push(bad);
    let mut bad = row.clone(); bad.known_floor = Some(SecretDeletionFloor { through_version: 0, applied_wall_ms: 0 }); bad_rows.push(bad);
    for bad in bad_rows { assert!(target.import_encrypted_row(&identity, &bad, None, SecretImportDisposition::Operational).is_err()); }
    let mut bad_identities = Vec::new();
    let mut bad = identity.clone(); bad.version_hash = row.version_hash.clone(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.source_version = "07".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.source_version = "+7".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.source_version = "8".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.backend = "vault".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.binding = "other".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.r#ref = "other".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.canonical_ref = "other".into(); bad_identities.push(bad);
    let mut bad = identity.clone(); bad.link_generation = u64::MAX; bad_identities.push(bad);
    let mut bad = identity.clone(); bad.deleted = true; bad_identities.push(bad);
    let mut bad = identity.clone(); bad.phase = pb::secret_version::Phase::Failed as i32; bad_identities.push(bad);
    let mut bad = identity.clone(); bad.audit.as_mut().unwrap().wall_time_ms = u64::MAX; bad_identities.push(bad);
    for bad in bad_identities { assert!(target.import_encrypted_row(&bad, &row, None, SecretImportDisposition::Operational).is_err()); }
    assert!(target.version("token", 7).unwrap().is_none());
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original));
    assert_eq!(target.current("token").unwrap().unwrap().value, b"retained plaintext");
}

#[tokio::test]
async fn committed_floor_denies_late_old_rows_and_writers_but_allows_newer_set() {
    let (dir, master, source, target) = pair();
    let old = write(&source, 7, 3);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    let mut diagnostic = old.clone();
    diagnostic.known_floor = Some(SecretDeletionFloor { through_version: 100, applied_wall_ms: 99 });
    assert_eq!(target.import_encrypted_row(&identity, &diagnostic, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(target.export_encrypted_row("token", 7).unwrap().unwrap().known_floor, None);
    assert!(target.delete("token", 0, 0).is_err());
    assert_eq!(target.delete("token", 7, 0).unwrap(), 1, "epoch wall time zero is a valid timestamp");
    assert_eq!(target.delete("token", 6, 99).unwrap(), 0);
    let tombstone = target.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(tombstone.deletion_applied_wall_ms, Some(0));
    assert_eq!(tombstone.known_floor, Some(SecretDeletionFloor { through_version: 7, applied_wall_ms: 0 }));
    assert_eq!((&tombstone.token_id, &tombstone.reason, tombstone.created_wall_ms), (&old.token_id, &old.reason, old.created_wall_ms));
    assert_eq!(tombstone.nonce, old.nonce);
    assert_eq!(tombstone.ciphertext, old.ciphertext);
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert!(target.current("token").unwrap().is_none());
    assert!(target.version("token", 7).unwrap().is_none());
    assert!(target.list().unwrap().is_empty());
    assert!(target.import_encrypted_row(&identity, &tombstone, None, SecretImportDisposition::Operational).is_err());
    assert!(matches!(target.import_encrypted_row(&identity, &old, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
    assert!(matches!(target.set_at("token", 6, b"late writer", [1; 24], 1, "", ""), Err(PrivacyError::SecretDeleted)));
    target.set_at("token", 8, b"new plaintext", [9; 24], 100, "new-admin", "new set").unwrap();
    let backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), target.clone());
    assert!(matches!(backend.version("token", "7", test_authority()).await, Err(BackendError::VersionGone)));
    assert_eq!(backend.current("token", test_authority()).await.unwrap().value.as_slice(), b"new plaintext");
    assert_eq!(backend.versions("token", None, test_authority()).await.unwrap().ids, ["8"]);
    drop(backend); drop(target);
    let reopened = Arc::new(SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap());
    assert!(matches!(reopened.import_encrypted_row(&identity, &old, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
    assert_eq!(reopened.current("token").unwrap().unwrap().value, b"new plaintext");
    assert_eq!(reopened.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(reopened.values().unwrap(), vec![
        ("token".to_owned(), b"new plaintext".to_vec()),
        ("token".to_owned(), b"retained plaintext".to_vec()),
    ]);
    let reopened_backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), reopened.clone());
    assert!(matches!(reopened_backend.version("token", "7", test_authority()).await, Err(BackendError::VersionGone)));
    assert_eq!(reopened_backend.current("token", test_authority()).await.unwrap().value.as_slice(), b"new plaintext");
    assert_eq!(reopened.delete("missing", 9, 1).unwrap(), 0);
    assert!(reopened.export_encrypted_row("missing", 9).unwrap().is_none());
    assert!(matches!(reopened.set_at("missing", 8, b"late", [2; 24], 2, "", ""), Err(PrivacyError::SecretDeleted)));
}

#[test]
fn validation_and_sql_failure_roll_back_the_row_floor_and_prior_audit_together() {
    let (_dir, _master, source, target) = pair();
    let row = write(&source, 8, 3);
    let original = write(&target, 2, 8);
    let identity = expected(&source, 19, 8, b"retained plaintext");
    let floor = Some(SecretDeletionFloor { through_version: 3, applied_wall_ms: 50 });
    assert!(target.import_encrypted_row(&identity, &row, floor.map(|floor| ("another-name", floor)), SecretImportDisposition::Operational).is_err());
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original.clone()));
    let mut bad = identity.clone(); bad.version_hash[0] ^= 1;
    assert!(target.import_encrypted_row(&bad, &row, floor.map(|floor| ("token", floor)), SecretImportDisposition::Operational).is_err());
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original.clone()));
    target.conn().execute_batch("CREATE TRIGGER deny_erasure BEFORE UPDATE OF deleted_wall_ms ON secrets BEGIN SELECT RAISE(ABORT, 'injected rollback'); END;").unwrap();
    assert!(target.import_encrypted_row(&identity, &row, floor.map(|floor| ("token", floor)), SecretImportDisposition::Operational).is_err());
    assert!(target.version("token", 8).unwrap().is_none());
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original));
    assert_eq!(target.version("token", 2).unwrap().unwrap().value, b"retained plaintext");
    target.conn().execute_batch("DROP TRIGGER deny_erasure").unwrap();
    assert_eq!(target.import_encrypted_row(&identity, &row, floor.map(|floor| ("token", floor)), SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert!(target.version("token", 2).unwrap().is_none());
    assert_eq!(target.version("token", 8).unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(target.export_encrypted_row("token", 8).unwrap().unwrap().known_floor, floor);
}

#[test]
fn pre_floor_schema_keeps_legacy_crypto_and_does_not_invent_a_never_deleted_fact() {
    let (dir, master, source, _target) = pair();
    let original = write(&source, 7, 3);
    source.set_at("legacy-live", 1, b"old-format plaintext", [5; 24], 2, "legacy-admin", "legacy set").unwrap();
    let live = source.export_encrypted_row("legacy-live", 1).unwrap();
    source.delete("token", 7, 30).unwrap();
    // Fixture for the former destructive deletion format, not a new delete.
    source.conn().execute("UPDATE secrets SET nonce = x'', ciphertext = x'' WHERE name = 'token'", []).unwrap();
    source.conn().execute_batch("DROP TABLE secret_deletion_floors").unwrap();
    drop(source);
    let migrated = SecretStore::open(Connection::open(dir.path().join("source.db")).unwrap(), &master).unwrap();
    assert_eq!(migrated.export_encrypted_row("legacy-live", 1).unwrap(), live);
    assert_eq!(migrated.version("legacy-live", 1).unwrap().unwrap().value, b"old-format plaintext");
    let erased = migrated.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(erased.known_floor, None, "old per-row flags do not prove a through-version floor");
    assert_eq!(erased.deletion_applied_wall_ms, Some(30));
    assert_eq!(erased.version_hash, original.version_hash);
    assert_eq!(erased.token_id, original.token_id);
    assert!(migrated.current("token").unwrap().is_none());
    assert!(matches!(migrated.retained_version_for_scrub("token", 7), Err(PrivacyError::Decrypt(_))));
    assert!(matches!(migrated.values(), Err(PrivacyError::Decrypt(_))), "legacy lost needles are incomplete, not an empty successful inventory");
    migrated.delete("token", 7, 30).unwrap();
    assert_eq!(migrated.export_encrypted_row("token", 7).unwrap().unwrap().known_floor,
        Some(SecretDeletionFloor { through_version: 7, applied_wall_ms: 30 }));
    migrated.set_at("token", 8, b"legacy-compatible", [4; 24], 31, "admin", "set").unwrap();
    assert_eq!(migrated.version("token", 8).unwrap().unwrap().value, b"legacy-compatible");
}

#[test]
fn import_uses_the_actual_sqlite_limit_and_sqlite_checks_total_encoded_row_size() {
    use rusqlite::limits::Limit;
    let (_dir, _master, source, target) = pair();
    let original = write(&target, 2, 8);
    let large = vec![5; 1500];
    source.set_at("token", 8, &large, [3; 24], 12, "admin", "set").unwrap();
    let row = source.export_encrypted_row("token", 8).unwrap().unwrap();
    let identity = expected(&source, 19, 8, &large);
    let previous = target.conn().set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024).unwrap();
    assert!(matches!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidSecretRow)));
    target.conn().set_limit(Limit::SQLITE_LIMIT_LENGTH, previous).unwrap();
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original.clone()));
    assert!(target.version("token", 8).unwrap().is_none());

    let value = vec![6; 600];
    source.set_at("token", 9, &value, [4; 24], 13, "admin", &"r".repeat(600)).unwrap();
    let row = source.export_encrypted_row("token", 9).unwrap().unwrap();
    let identity = expected(&source, 20, 9, &value);
    let floor = Some(("token", SecretDeletionFloor { through_version: 3, applied_wall_ms: 50 }));
    target.conn().set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024).unwrap();
    assert!(matches!(target.import_encrypted_row(&identity, &row, floor, SecretImportDisposition::Operational), Err(PrivacyError::Sqlite(_))));
    target.conn().set_limit(Limit::SQLITE_LIMIT_LENGTH, previous).unwrap();
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(original));
    assert!(target.version("token", 9).unwrap().is_none());
}

#[test]
fn prepared_custody_bytes_are_pure_and_exactly_match_the_existing_writer() {
    let (_dir, _master, source, target) = pair();
    let physical = u64::from(u32::MAX) + 1;
    let before = changes(&source);
    let row = source.prepare_encrypted_row(
        "token", physical, b"retained plaintext", [3; 24], 12, "original-admin", "original set",
    ).unwrap();
    assert_eq!(changes(&source), before);
    assert!(source.version("token", physical).unwrap().is_none());
    assert!(source.metadata_page(None, true).unwrap().is_empty());
    source.set_at("token", physical, b"retained plaintext", [3; 24], 12, "original-admin", "original set").unwrap();
    assert_eq!(source.export_encrypted_row("token", physical).unwrap(), Some(row.clone()));
    let identity = expected(&source, kronik_proto::secret::MAX_SECRET_VERSION, physical, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(target.version("token", physical).unwrap().unwrap().value, b"retained plaintext");
    assert!(source.prepare_encrypted_row("token", 0, b"value", [4; 24], 1, "", "").is_err());
    assert!(source.prepare_encrypted_row("Bad Name", 1, b"value", [4; 24], 1, "", "").is_err());
    assert!(source.prepare_encrypted_row("token", physical, b"value", [4; 24], u64::MAX, "", "").is_err());
    target.delete("token", physical, 20).unwrap();
    let still_pure = target.prepare_encrypted_row(
        "token", physical, b"retained plaintext", [3; 24], 12, "original-admin", "original set",
    ).unwrap();
    assert_eq!(still_pure, row);
    assert!(matches!(target.import_encrypted_row(&identity, &still_pure, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
}

#[test]
fn bounded_export_checks_payload_and_all_original_metadata_before_loading_the_row() {
    let (_dir, _master, source, _target) = pair();
    let reason = "å".repeat(50);
    source.set_at("token", 7, &[3; 2048], [4; 24], 12, "original-admin", &reason).unwrap();
    let row = source.export_encrypted_row("token", 7).unwrap().unwrap();
    let total = 5 * std::mem::size_of::<u64>() + row.name.len() + row.nonce.len()
        + row.ciphertext.len() + row.version_hash.len() + row.token_id.len() + row.reason.len();
    let before = changes(&source);
    assert!(matches!(source.export_encrypted_row_bounded("token", 7, total - 1), Err(PrivacyError::SecretRowTooLarge)));
    assert_eq!(source.export_encrypted_row_bounded("token", 7, total).unwrap(), Some(row));
    assert_eq!(source.export_encrypted_row_bounded("missing", 7, 0).unwrap(), None);
    assert_eq!(changes(&source), before);
    // A zero budget is rejected before attempting to decode an invalid text field.
    source.conn().execute("UPDATE secrets SET reason = CAST(x'ff' AS TEXT) WHERE name = 'token'", []).unwrap();
    assert!(matches!(source.export_encrypted_row_bounded("token", 7, 0), Err(PrivacyError::SecretRowTooLarge)));
    assert!(matches!(source.export_encrypted_row("token", 7), Err(PrivacyError::Sqlite(_))));
}

#[test]
fn directory_sync_is_real_file_only_and_does_not_claim_memory_durability() {
    let (_dir, _master, source, _target) = pair();
    write(&source, 7, 3);
    source.sync_parent_directory().unwrap();
    let memory = SecretStore::open(
        Connection::open_in_memory().unwrap(), &MasterKey::from_bytes([7; 32]).unwrap(),
    ).unwrap();
    assert!(matches!(memory.sync_parent_directory(), Err(PrivacyError::FileStoreRequired)));
}

#[test]
fn closed_encrypted_stage_links_into_a_new_destination_without_overwriting_live_custody() {
    let (dir, master, source, target) = pair();
    let source_row = write(&source, 7, 3);
    let target_row = write(&target, 2, 4);
    let staged = source.stage_encrypted_snapshot(dir.path()).unwrap();
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = staged.database_path().as_os_str().to_os_string();
        sidecar.push(suffix);
        assert!(!Path::new(&sidecar).exists());
    }
    let destination = dir.path().join("owned-snapshot");
    std::fs::create_dir(&destination).unwrap();
    let installed = destination.join("secrets.db");
    std::fs::hard_link(staged.database_path(), &installed).unwrap();
    assert_eq!(std::fs::hard_link(staged.database_path(), dir.path().join("target.db")).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists);
    let stage_path = staged.database_path().to_owned();
    drop(staged);
    assert!(!stage_path.exists());
    let reader = SecretStore::open_readonly(Connection::open_with_flags(
        &installed, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap(), &master).unwrap();
    assert_eq!(reader.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(reader.export_encrypted_row("token", 7).unwrap(), Some(source_row.clone()));
    assert_eq!(source.export_encrypted_row("token", 7).unwrap(), Some(source_row));
    assert_eq!(target.export_encrypted_row("token", 2).unwrap(), Some(target_row));
    assert_eq!(target.current("token").unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn private_immutable_snapshot_exports_old_large_rows_without_replacing_live_stores() {
    use std::os::unix::fs::PermissionsExt as _;
    let (dir, _master, source, target) = pair();
    let old = write(&source, 7, 3);
    source.delete("token", 7, 20).unwrap();
    let value = vec![9; 2048];
    source.set_at("token", 8, &value, [4; 24], 21, "original-admin", "large old row").unwrap();
    assert!(matches!(source.export_encrypted_row_bounded("token", 8, 128), Err(PrivacyError::SecretRowTooLarge)));
    let staging_parent = dir.path().join("snapshot #? space");
    std::fs::create_dir(&staging_parent).unwrap();
    let staged = source.stage_encrypted_snapshot(&staging_parent).unwrap();
    let path = staged.database_path().to_path_buf();
    let stage_directory = path.parent().unwrap().to_path_buf();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&stage_directory).unwrap().permissions().mode() & 0o777, 0o700);
    let bytes = std::fs::read(&path).unwrap();
    let retained = staged.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(retained.nonce, old.nonce);
    assert_eq!(retained.ciphertext, old.ciphertext);
    assert_eq!(retained.deletion_applied_wall_ms, Some(20));
    let row = staged.export_encrypted_row("token", 8).unwrap().unwrap();
    assert!(matches!(SecretStore::export_encrypted_snapshot_row(&path, "token", 8, 128), Err(PrivacyError::SecretRowTooLarge)));
    source.set_at("token", 9, b"new current", [5; 24], 22, "admin", "rotate").unwrap();
    assert!(staged.export_encrypted_row("token", 9).unwrap().is_none());
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "staged exports never mutate the backup");
    target.set_at("other", 1, b"keep target row", [6; 24], 1, "admin", "set").unwrap();
    let identity = expected(&source, 19, 8, &value);
    assert_eq!(target.import_encrypted_row(&identity, &row, Some(("token", SecretDeletionFloor {
        through_version: 7, applied_wall_ms: 20,
    })), SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(target.version("token", 8).unwrap().unwrap().value, value);
    assert_eq!(target.current("other").unwrap().unwrap().value, b"keep target row");
    assert_eq!(source.current("token").unwrap().unwrap().value, b"new current");
    drop(staged);
    assert!(!path.exists() && !stage_directory.exists());
}

#[test]
fn readonly_pre_floor_snapshot_keeps_legacy_rows_and_rejects_sidecars_without_writes() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_dir, _master, source, target) = pair();
    let original = write(&source, 7, 3);
    let private = tempfile::tempdir().unwrap();
    let path = private.path().join("legacy #? snapshot.db");
    source.backup_to(&path).unwrap();
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE secret_deletion_floors").unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let row = SecretStore::export_encrypted_snapshot_row(&path, "token", 7, bytes.len()).unwrap().unwrap();
    assert_eq!(row, original);
    assert_eq!(row.known_floor, None, "no floor table is unknown, not never-deleted authority");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    assert_eq!(target.version("token", 7).unwrap().unwrap().value, b"retained plaintext");
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push("-wal");
    std::fs::write(&sidecar, b"unfinished staged sidecar").unwrap();
    assert!(matches!(SecretStore::export_encrypted_snapshot_row(&path, "token", 7, bytes.len()), Err(PrivacyError::InvalidSecretRow)));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[tokio::test]
async fn retained_import_in_both_delete_orders_is_scrub_only_even_after_restart() {
    for import_before_delete in [false, true] {
        let (dir, master, source, target) = pair();
        let physical = u64::from(u32::MAX) + 1;
        let live = write(&source, physical, 3);
        let identity = expected(&source, kronik_proto::secret::MAX_SECRET_VERSION, physical, b"retained plaintext");
        if import_before_delete {
            assert_eq!(target.import_encrypted_row(&identity, &live, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
        }
        target.delete("token", physical, 20).unwrap();
        source.delete("token", physical, 20).unwrap();
        let mut retained = source.export_encrypted_row("token", physical).unwrap().unwrap();
        assert_eq!(retained.ciphertext, live.ciphertext);
        let floor = SecretDeletionFloor { through_version: physical, applied_wall_ms: 20 };
        assert!(matches!(target.import_encrypted_row(&identity, &live, Some(("token", floor)), SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
        assert!(matches!(target.import_encrypted_row(&identity, &retained, None, SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretDeleted)));
        assert!(target.import_encrypted_row(&identity, &retained, Some(("other", floor)), SecretImportDisposition::ScrubOnly).is_err());
        assert!(matches!(target.import_encrypted_row(&identity, &retained, Some(("token", SecretDeletionFloor {
            through_version: 0, applied_wall_ms: 0,
        })), SecretImportDisposition::Operational), Err(PrivacyError::InvalidVersion(0))));
        // No source deletion clock is invented: purpose and the local application
        // clock come from the independently admitted context, not body diagnostics.
        retained.deletion_applied_wall_ms = None;
        retained.known_floor = None;
        assert_eq!(target.import_encrypted_row(&identity, &retained, Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(), SecretImportDisposition::ScrubOnly);
        assert_eq!(target.import_encrypted_row(&identity, &retained, Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(), SecretImportDisposition::ScrubOnly);
        assert!(target.current("token").unwrap().is_none());
        assert!(target.version("token", physical).unwrap().is_none());
        assert!(target.list().unwrap().is_empty());
        let stored = target.export_encrypted_row("token", physical).unwrap().unwrap();
        assert_eq!(stored.deletion_applied_wall_ms, Some(20));
        assert_eq!(stored.known_floor, Some(floor));
        assert_eq!(stored.nonce, live.nonce);
        assert_eq!(stored.ciphertext, live.ciphertext);
        assert_eq!((&stored.token_id, &stored.reason, stored.created_wall_ms),
            (&live.token_id, &live.reason, live.created_wall_ms));
        assert_eq!(target.retained_version_for_scrub("token", physical).unwrap().unwrap().value, b"retained plaintext");
        drop(target);
        let reopened = Arc::new(SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap());
        let backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), reopened.clone());
        assert!(matches!(backend.current("token", test_authority()).await, Err(BackendError::NotFound)));
        assert!(matches!(backend.version("token", &physical.to_string(), test_authority()).await, Err(BackendError::VersionGone)));
        assert!(backend.versions("token", None, test_authority()).await.unwrap().ids.is_empty());
        assert_eq!(reopened.values().unwrap(), vec![("token".to_owned(), b"retained plaintext".to_vec())]);
        assert!(matches!(reopened.import_encrypted_row(&identity, &live, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
        reopened.set_at("token", physical + 1, b"new authorized value", [5; 24], 21, "admin", "new set").unwrap();
        assert_eq!(backend.current("token", test_authority()).await.unwrap().value.as_slice(), b"new authorized value");
        assert!(matches!(backend.version("token", &physical.to_string(), test_authority()).await, Err(BackendError::VersionGone)));
    }
}

#[test]
fn legacy_erased_row_requires_the_real_original_envelope_and_atomic_scrub_restoration() {
    let (dir, master, source, target) = pair();
    let original = write(&source, 7, 3);
    write(&target, 7, 3);
    target.set_at("other", 1, b"unaffected", [6; 24], 1, "admin", "set").unwrap();
    target.delete("token", 7, 0).unwrap();
    target.conn().execute("UPDATE secrets SET nonce=x'', ciphertext=x'' WHERE name='token'", []).unwrap();
    let erased = target.export_encrypted_row("token", 7).unwrap().unwrap();
    source.delete("token", 7, 0).unwrap();
    source.delete("token", 8, 1).unwrap();
    let retained = source.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(retained.ciphertext, original.ciphertext);
    let identity = expected(&source, 19, 7, b"retained plaintext");
    let floor = SecretDeletionFloor { through_version: 8, applied_wall_ms: 1 };
    assert!(matches!(target.retained_version_for_scrub("token", 7), Err(PrivacyError::Decrypt(_))));
    assert!(matches!(target.import_encrypted_row(&identity, &erased, Some(("token", floor)), SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretRowIncomplete)));
    assert!(matches!(target.import_encrypted_row(&identity, &retained, None, SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretDeleted)));
    let mut changed_audit = retained.clone();
    changed_audit.reason = "not the original row audit".into();
    assert!(matches!(target.import_encrypted_row(&identity, &changed_audit, Some(("token", floor)), SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretRowConflict)));
    let mut tampered = retained.clone();
    tampered.ciphertext[0] ^= 1;
    assert!(target.import_encrypted_row(&identity, &tampered, Some(("token", floor)), SecretImportDisposition::ScrubOnly).is_err());
    let mut bad_logical = identity.clone();
    bad_logical.version_hash = retained.version_hash.clone();
    assert!(target.import_encrypted_row(&bad_logical, &retained, Some(("token", floor)), SecretImportDisposition::ScrubOnly).is_err());
    let wrong = SecretStore::open(Connection::open(dir.path().join("wrong-master.db")).unwrap(), &MasterKey::from_bytes([8; 32]).unwrap()).unwrap();
    write(&wrong, 7, 3);
    wrong.delete("token", 7, 0).unwrap();
    let wrong_row = wrong.export_encrypted_row("token", 7).unwrap().unwrap();
    assert!(target.import_encrypted_row(&identity, &wrong_row, Some(("token", floor)), SecretImportDisposition::ScrubOnly).is_err());
    assert_eq!(target.export_encrypted_row("token", 7).unwrap(), Some(erased.clone()));
    target.conn().execute_batch("CREATE TRIGGER fail_floor BEFORE UPDATE ON secret_deletion_floors BEGIN SELECT RAISE(ABORT, 'injected floor failure'); END;").unwrap();
    assert!(target.import_encrypted_row(&identity, &retained, Some(("token", floor)), SecretImportDisposition::ScrubOnly).is_err());
    assert_eq!(target.export_encrypted_row("token", 7).unwrap(), Some(erased.clone()), "the ciphertext repair and floor must roll back together");
    target.conn().execute_batch("DROP TRIGGER fail_floor").unwrap();
    assert_eq!(target.import_encrypted_row(&identity, &retained, Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(), SecretImportDisposition::ScrubOnly);
    let restored = target.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(restored.nonce, original.nonce);
    assert_eq!(restored.ciphertext, original.ciphertext);
    assert_eq!((restored.token_id, restored.reason, restored.created_wall_ms, restored.deletion_applied_wall_ms),
        (erased.token_id, erased.reason, erased.created_wall_ms, erased.deletion_applied_wall_ms));
    assert_eq!(restored.known_floor, Some(floor));
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert!(target.current("token").unwrap().is_none());
    assert!(target.version("token", 7).unwrap().is_none());
    drop(target);
    let reopened = SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap();
    assert_eq!(reopened.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert_eq!(reopened.current("other").unwrap().unwrap().value, b"unaffected");
    assert!(reopened.version("token", 7).unwrap().is_none());
    assert!(matches!(reopened.set_at("token", 8, b"resurrection", [7; 24], 2, "admin", "set"), Err(PrivacyError::SecretDeleted)));
}

#[test]
fn retained_import_never_overwrites_a_different_valid_nonempty_envelope() {
    let (_dir, _master, source, target) = pair();
    let original = write(&source, 7, 3);
    let other = write(&target, 7, 4);
    assert_eq!(original.version_hash, other.version_hash);
    assert_ne!(original.ciphertext, other.ciphertext);
    source.delete("token", 8, 21).unwrap();
    target.delete("token", 7, 20).unwrap();
    let retained = source.export_encrypted_row("token", 7).unwrap().unwrap();
    let acknowledged = target.export_encrypted_row("token", 7).unwrap();
    let identity = expected(&source, 19, 7, b"retained plaintext");
    assert!(matches!(target.import_encrypted_row(&identity, &retained, Some(("token", SecretDeletionFloor {
        through_version: 8, applied_wall_ms: 21,
    })), SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretRowConflict)));
    assert_eq!(target.export_encrypted_row("token", 7).unwrap(), acknowledged);
    assert!(target.version("token", 7).unwrap().is_none());
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn local_verifier_reads_real_committed_ciphertext_without_mutation_or_false_identity() {
    let (dir, _master, source, target) = pair();
    let physical = u64::from(u32::MAX) + 1;
    let row = write(&source, physical, 3);
    let ciphertext_hash = *blake3::hash(&row.ciphertext).as_bytes();
    let identity = expected(&source, kronik_proto::secret::MAX_SECRET_VERSION, physical, b"retained plaintext");
    assert_eq!(target.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational).unwrap(), None);
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    let before = changes(&target);
    assert_eq!(target.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational).unwrap(), Some(SecretImportDisposition::Operational));
    target.sync_parent_directory().unwrap();
    let mut wrong_hash = ciphertext_hash;
    wrong_hash[0] ^= 1;
    assert!(matches!(target.verify_encrypted_row(&identity, &wrong_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidSecretRow)));
    let mut wrong_logical = identity.clone();
    wrong_logical.version_hash = row.version_hash.clone();
    assert!(matches!(target.verify_encrypted_row(&wrong_logical, &ciphertext_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidSecretRow)));
    let mut noncanonical = identity.clone();
    noncanonical.source_version.insert(0, '0');
    assert!(target.verify_encrypted_row(&noncanonical, &ciphertext_hash, None, SecretImportDisposition::Operational).is_err());
    let wrong = SecretStore::open(Connection::open(dir.path().join("verify-wrong-master.db")).unwrap(), &MasterKey::from_bytes([8; 32]).unwrap()).unwrap();
    let wrong_row = write(&wrong, physical, 3);
    let wrong_master_hash = *blake3::hash(&wrong_row.ciphertext).as_bytes();
    assert!(matches!(wrong.verify_encrypted_row(&identity, &wrong_master_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidSecretRow)));
    assert_eq!(changes(&target), before);
    assert_eq!(target.export_encrypted_row("token", physical).unwrap(), Some(row.clone()));
    target.conn().execute("UPDATE secrets SET nonce=zeroblob(24) WHERE name='token'", []).unwrap();
    assert!(matches!(target.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::Decrypt(_))));
    target.conn().execute("UPDATE secrets SET nonce=?1 WHERE name='token'", params![row.nonce]).unwrap();
    target.conn().execute("UPDATE secrets SET created_wall_ms=-1 WHERE name='token'", []).unwrap();
    assert!(matches!(target.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidTimestamp)));
    target.conn().execute("UPDATE secrets SET created_wall_ms=12 WHERE name='token'", []).unwrap();
    assert_eq!(target.version("token", physical).unwrap().unwrap().value, b"retained plaintext");
}

#[test]
fn local_verifier_never_installs_a_floor_or_acknowledges_lost_or_memory_custody() {
    let (dir, master, source, target) = pair();
    let row = write(&source, 7, 3);
    let ciphertext_hash = *blake3::hash(&row.ciphertext).as_bytes();
    let identity = expected(&source, 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(), SecretImportDisposition::Operational);
    target.delete("token", 7, 0).unwrap();
    let floor = SecretDeletionFloor { through_version: 7, applied_wall_ms: 0 };
    let before = changes(&target);
    assert!(matches!(target.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational), Err(PrivacyError::SecretDeleted)));
    assert_eq!(target.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(), Some(SecretImportDisposition::ScrubOnly));
    assert!(target.verify_encrypted_row(&identity, &ciphertext_hash, Some(("other", floor)), SecretImportDisposition::Operational).is_err());
    assert!(matches!(target.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", SecretDeletionFloor {
        through_version: 0, applied_wall_ms: 0,
    })), SecretImportDisposition::Operational), Err(PrivacyError::InvalidVersion(0))));
    let stronger = SecretDeletionFloor { through_version: 8, applied_wall_ms: 1 };
    assert!(matches!(target.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", stronger)), SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretRowIncomplete)));
    assert_eq!(target.export_encrypted_row("token", 7).unwrap().unwrap().known_floor, Some(floor));
    assert_eq!(changes(&target), before);
    target.delete("token", 8, 1).unwrap();
    assert_eq!(target.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", stronger)), SecretImportDisposition::ScrubOnly).unwrap(), Some(SecretImportDisposition::ScrubOnly));
    assert!(target.version("token", 7).unwrap().is_none());
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    drop(target);
    let reopened = SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap();
    assert_eq!(reopened.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", stronger)), SecretImportDisposition::ScrubOnly).unwrap(), Some(SecretImportDisposition::ScrubOnly));
    reopened.sync_parent_directory().unwrap();
    reopened.conn().execute("UPDATE secrets SET nonce=x'', ciphertext=x'' WHERE name='token'", []).unwrap();
    let erased = reopened.export_encrypted_row("token", 7).unwrap();
    assert!(matches!(reopened.verify_encrypted_row(&identity, &ciphertext_hash, Some(("token", stronger)), SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretRowIncomplete)));
    assert_eq!(reopened.export_encrypted_row("token", 7).unwrap(), erased);
    let memory = SecretStore::open(Connection::open_in_memory().unwrap(), &master).unwrap();
    write(&memory, 7, 3);
    assert_eq!(memory.verify_encrypted_row(&identity, &ciphertext_hash, None, SecretImportDisposition::Operational).unwrap(), Some(SecretImportDisposition::Operational));
    assert!(matches!(memory.sync_parent_directory(), Err(PrivacyError::FileStoreRequired)), "read verification is not a durability receipt");
}

#[test]
fn stored_floor_is_read_only_name_bound_and_survives_without_a_row_at_the_delete_cut() {
    let (dir, master, source, target) = pair();
    write(&source, 7, 3);
    write(&target, 7, 3);
    assert_eq!(target.stored_deletion_floor("token").unwrap(), None);
    assert!(matches!(target.stored_deletion_floor("Bad Name"), Err(PrivacyError::InvalidName(_))));
    target.delete("token", 9, 20).unwrap();
    let floor = Some(SecretDeletionFloor { through_version: 9, applied_wall_ms: 20 });
    let before = changes(&target);
    assert_eq!(target.stored_deletion_floor("token").unwrap(), floor);
    assert_eq!(target.stored_deletion_floor("other").unwrap(), None);
    assert!(target.export_encrypted_row("token", 9).unwrap().is_none());
    assert_eq!(changes(&target), before);
    assert_eq!(source.stored_deletion_floor("token").unwrap(), None, "this is a local fact, not a fabricated global publication");
    target.delete("token", 8, 30).unwrap();
    assert_eq!(target.stored_deletion_floor("token").unwrap(), floor);
    target.set_at("token", 10, b"after physical cut", [4; 24], 31, "admin", "set").unwrap();
    drop(target);
    let reopened = SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap();
    assert_eq!(reopened.stored_deletion_floor("token").unwrap(), floor);
    assert!(reopened.version("token", 7).unwrap().is_none());
    assert_eq!(reopened.version("token", 10).unwrap().unwrap().value, b"after physical cut");
    reopened.conn().execute("UPDATE secret_deletion_floors SET through_version=0 WHERE name='token'", []).unwrap();
    let before_error = changes(&reopened);
    assert!(matches!(reopened.stored_deletion_floor("token"), Err(PrivacyError::InvalidStoredVersion(0))));
    assert_eq!(changes(&reopened), before_error);
    reopened.conn().execute("UPDATE secret_deletion_floors SET through_version=9, deleted_wall_ms=-1 WHERE name='token'", []).unwrap();
    assert!(matches!(reopened.stored_deletion_floor("token"), Err(PrivacyError::InvalidTimestamp)));
}

#[tokio::test]
async fn legacy_deleted_value_with_original_set_audit_installs_live_source_only_as_explicit_scrub() {
    let (_dir, _master, source, target) = pair();
    let row = write(&source, 7, 3);
    assert_eq!(row.deletion_applied_wall_ms, None);
    let mut legacy = expected(&source, 19, 7, b"retained plaintext");
    legacy.deleted = true;
    legacy.audit = Some(pb::Audit {
        token_id: row.token_id.clone(), reason: row.reason.clone(), wall_time_ms: row.created_wall_ms,
    });
    kronik_proto::Record::SecretVersion(legacy.clone()).validate().unwrap();
    let original_record = legacy.clone();
    let before = changes(&target);
    assert!(matches!(target.import_encrypted_row(&legacy, &row, None, SecretImportDisposition::Operational), Err(PrivacyError::InvalidSecretRow)));
    assert!(matches!(target.import_encrypted_row(&legacy, &row, None, SecretImportDisposition::ScrubOnly), Err(PrivacyError::SecretDeleted)));
    assert_eq!(changes(&target), before);
    let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
    let worker_env = env.clone();
    let file = target.clone();
    let expected_for_worker = legacy.clone();
    // Production admission/source proof belongs to the caller. The admitted worker
    // samples only a new LOCAL application clock, never this legacy SET audit.
    let (disposition, applied_wall_ms) = env.blocking("custody-local-application-test", move || {
        let applied_wall_ms = worker_env.clock.wall_ms();
        let floor = SecretDeletionFloor { through_version: 7, applied_wall_ms };
        let disposition = file.import_encrypted_row(
            &expected_for_worker, &row, Some(("token", floor)), SecretImportDisposition::ScrubOnly,
        )?;
        file.sync_parent_directory()?;
        Ok::<_, PrivacyError>((disposition, applied_wall_ms))
    }).await.unwrap().unwrap();
    assert_eq!(disposition, SecretImportDisposition::ScrubOnly);
    assert_eq!(legacy, original_record, "the canonical deleted value record is never forged into a SET");
    let stored = target.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(stored.created_wall_ms, 12);
    assert_eq!(stored.deletion_applied_wall_ms, Some(applied_wall_ms));
    assert_eq!(stored.known_floor, Some(SecretDeletionFloor { through_version: 7, applied_wall_ms }));
    assert_eq!(legacy.audit.as_ref().unwrap().wall_time_ms, 12);
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    assert!(target.current("token").unwrap().is_none());
    assert!(target.version("token", 7).unwrap().is_none());
    assert_eq!(source.export_encrypted_row("token", 7).unwrap().unwrap().deletion_applied_wall_ms, None);
}

#[test]
fn explicit_scrub_preserves_real_local_application_pin_without_a_body_timestamp_or_fake_value_identity() {
    let (_dir, _master, source, target) = pair();
    let row = write(&source, 7, 3);
    let mut legacy = expected(&source, 19, 7, b"retained plaintext");
    legacy.deleted = true;
    legacy.audit.as_mut().unwrap().wall_time_ms = row.created_wall_ms;
    target.delete("token", 7, 77).unwrap();
    let local_pin = target.stored_deletion_floor("token").unwrap().unwrap();
    assert_eq!(local_pin.applied_wall_ms, 77);
    assert_eq!(row.deletion_applied_wall_ms, None);
    assert!(target.import_encrypted_row(&legacy, &row, Some(("token", local_pin)), SecretImportDisposition::Operational).is_err());
    assert_eq!(target.import_encrypted_row(&legacy, &row, Some(("token", local_pin)), SecretImportDisposition::ScrubOnly).unwrap(), SecretImportDisposition::ScrubOnly);
    let stored = target.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!(stored.deletion_applied_wall_ms, Some(77));
    assert_eq!(stored.known_floor, Some(local_pin));
    assert_eq!(stored.created_wall_ms, 12);
    assert_eq!(target.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    let hash = *blake3::hash(&stored.ciphertext).as_bytes();
    assert_eq!(target.verify_encrypted_row(&legacy, &hash, Some(("token", local_pin)), SecretImportDisposition::ScrubOnly).unwrap(), Some(SecretImportDisposition::ScrubOnly));
    assert!(target.verify_encrypted_row(&legacy, &hash, Some(("token", local_pin)), SecretImportDisposition::Operational).is_err());
    let mut empty_hash_delete = legacy.clone();
    empty_hash_delete.version_hash.clear();
    kronik_proto::Record::SecretVersion(empty_hash_delete.clone()).validate().unwrap();
    assert!(matches!(target.import_encrypted_row(&empty_hash_delete, &stored, Some(("token", local_pin)), SecretImportDisposition::ScrubOnly), Err(PrivacyError::InvalidSecretRow)));
    assert!(target.current("token").unwrap().is_none());
    assert!(target.version("token", 7).unwrap().is_none());
}

#[test]
fn live_store_backup_reader_preserves_committed_wal_and_retained_history() {
    let (dir, master, source, _target) = pair();
    source.conn().execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=0;").unwrap();
    let baseline = source.stage_encrypted_snapshot(dir.path()).unwrap().open_readonly(&master).unwrap();
    let physical = u64::from(u32::MAX) + 1;
    write(&source, physical, 3);
    source.delete("token", physical, 77).unwrap();
    source.set_at("token", physical + 1, b"current WAL value", [4; 24], 78, "admin", "set").unwrap();
    let retained = source.export_encrypted_row("token", physical).unwrap().unwrap();
    let current = source.export_encrypted_row("token", physical + 1).unwrap().unwrap();
    let before = changes(&source);
    let reader = source.stage_encrypted_snapshot(dir.path()).unwrap().open_readonly(&master).unwrap();
    assert_eq!(changes(&source), before);
    assert!(baseline.metadata_page(None, true).unwrap().is_empty());
    assert_eq!(reader.metadata_page(None, true).unwrap().len(), 2);
    assert_eq!(reader.retained_version_for_scrub("token", physical).unwrap().unwrap().value, b"retained plaintext");
    assert!(reader.version("token", physical).unwrap().is_none());
    assert_eq!(reader.version("token", physical + 1).unwrap().unwrap().value, b"current WAL value");
    assert_eq!(reader.stored_deletion_floor("token").unwrap(), Some(SecretDeletionFloor {
        through_version: physical, applied_wall_ms: 77,
    }));
    assert!(matches!(reader.set_at("token", physical + 2, b"must not write", [5; 24], 79, "admin", "set"),
        Err(PrivacyError::SecretStoreUnowned)));
    assert_eq!(reader.export_encrypted_row("token", physical).unwrap(), Some(retained.clone()));
    assert_eq!(source.export_encrypted_row("token", physical).unwrap(), Some(retained));
    assert_eq!(source.export_encrypted_row("token", physical + 1).unwrap(), Some(current));
    source.set_at("token", physical + 2, b"later live value", [5; 24], 80, "admin", "set").unwrap();
    assert_eq!(reader.current("token").unwrap().unwrap().value, b"current WAL value");
    assert!(reader.version("token", physical + 2).unwrap().is_none());
    assert_eq!(source.current("token").unwrap().unwrap().value, b"later live value");
}

#[test]
fn completed_legacy_reader_never_initializes_tables_or_certifies_erased_ciphertext() {
    let (dir, master, source, _target) = pair();
    write(&source, 7, 3);
    source.delete("token", 7, 20).unwrap();
    source.set_at("other", 1, b"real legacy value", [4; 24], 21, "admin", "set").unwrap();
    source.conn().execute_batch(
        "UPDATE secrets SET nonce=x'', ciphertext=x'' WHERE name='token'; \
         DROP TABLE key_check; DROP TABLE secret_deletion_floors;",
    ).unwrap();
    let reader = source.stage_encrypted_snapshot(dir.path()).unwrap().open_readonly(&master).unwrap();
    let wrong = source.stage_encrypted_snapshot(dir.path()).unwrap()
        .open_readonly(&MasterKey::from_bytes([8; 32]).unwrap()).unwrap();
    assert_eq!(reader.stored_deletion_floor("token").unwrap(), None, "missing legacy floor table stays unknown");
    assert_eq!(reader.metadata_page(None, true).unwrap().len(), 2);
    let erased = reader.export_encrypted_row("token", 7).unwrap().unwrap();
    assert!(erased.nonce.is_empty() && erased.ciphertext.is_empty());
    assert_eq!(erased.deletion_applied_wall_ms, Some(20));
    assert!(matches!(reader.retained_version_for_scrub("token", 7), Err(PrivacyError::Decrypt(_))));
    assert!(matches!(reader.values(), Err(PrivacyError::Decrypt(_))));
    assert_eq!(reader.retained_version_for_scrub("other", 1).unwrap().unwrap().value, b"real legacy value");
    assert!(matches!(wrong.retained_version_for_scrub("other", 1), Err(PrivacyError::Decrypt(_))));
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
    assert!(matches!(stage.open_readonly(&MasterKey::from_bytes([8; 32]).unwrap()), Err(PrivacyError::KeyMismatch(_))));
    source.conn().execute("UPDATE secrets SET version=0 WHERE name='token'", []).unwrap();
    let stage = source.stage_encrypted_snapshot(dir.path()).unwrap();
    assert!(matches!(stage.open_readonly(&master), Err(PrivacyError::InvalidStoredVersion(0))));
}

#[test]
fn physical_highwater_includes_orphans_and_floors_without_decrypting_or_allocating_a_version() {
    let (dir, master, source, target) = pair();
    assert_eq!(source.physical_highwater("token").unwrap(), 0);
    assert!(matches!(source.physical_highwater("Bad Name"), Err(PrivacyError::InvalidName(_))));
    write(&source, 17, 3);
    // An unclaimed physical row still owns its AAD version even if its value is lost.
    source.conn().execute("UPDATE secrets SET nonce=x'', ciphertext=x'00' WHERE name='token'", []).unwrap();
    let before = changes(&source);
    assert_eq!(source.physical_highwater("token").unwrap(), 17);
    assert_eq!(changes(&source), before);
    assert_eq!(target.physical_highwater("token").unwrap(), 0, "local metadata is not global publication");
    source.delete("token", 19, 77).unwrap();
    assert!(source.export_encrypted_row("token", 19).unwrap().is_none());
    assert_eq!(source.physical_highwater("token").unwrap(), 19);
    source.set_at("token", 20, b"new physical value", [4; 24], 78, "admin", "set").unwrap();
    assert_eq!(source.physical_highwater("token").unwrap(), 20);
    assert_eq!(source.version("token", 20).unwrap().unwrap().value, b"new physical value");
    source.delete("floor-only", 23, 79).unwrap();
    assert!(source.export_encrypted_row("floor-only", 23).unwrap().is_none());
    assert_eq!(source.physical_highwater("floor-only").unwrap(), 23);
    let wide = u64::from(u32::MAX) + 1;
    source.set_at("wide", wide, b"wide physical value", [5; 24], 80, "admin", "set").unwrap();
    assert_eq!(source.physical_highwater("wide").unwrap(), wide);
    source.delete("wide", kronik_proto::secret::MAX_SECRET_VERSION, 81).unwrap();
    assert_eq!(source.physical_highwater("wide").unwrap(), kronik_proto::secret::MAX_SECRET_VERSION);
    let snapshot = source.stage_encrypted_snapshot(dir.path()).unwrap().open_readonly(&master).unwrap();
    assert_eq!(snapshot.physical_highwater("token").unwrap(), 20);
    assert_eq!(snapshot.physical_highwater("floor-only").unwrap(), 23);
    source.conn().execute("UPDATE secrets SET version=0 WHERE name='token' AND version=17", []).unwrap();
    assert!(matches!(source.physical_highwater("token"), Err(PrivacyError::InvalidStoredVersion(0))));
}

#[tokio::test]
async fn logical_alias_uses_original_physical_name_and_version_without_retagging() {
    let (_dir, _master, source, target) = pair();
    let original = test_authority();
    let physical = u64::from(u32::MAX) + 1;
    let row = write(&source, physical, 3);
    let digest = *blake3::hash(&row.ciphertext).as_bytes();
    // Both the equal-number case and the distinct wide logical version need
    // the alias HMAC, not the physical slot's already-checked keyed hash.
    for logical in [physical, kronik_proto::secret::MAX_SECRET_VERSION] {
        let identity = expected_alias(&source, "logical-alias", "token", logical, physical, b"retained plaintext");
        kronik_proto::Record::SecretVersion(identity.clone()).validate().unwrap();
        assert_ne!(identity.version_hash, row.version_hash);
        assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(),
            SecretImportDisposition::Operational);
        let after = changes(&target);
        assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(),
            SecretImportDisposition::Operational);
        assert_eq!(changes(&target), after);
        assert_eq!(target.verify_encrypted_row(&identity, &digest, None, SecretImportDisposition::Operational).unwrap(),
            Some(SecretImportDisposition::Operational));
        assert_eq!(changes(&target), after, "borrowed verification must not rewrite the original row");
        let backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), target.clone());
        let fetched = backend.version(&identity.r#ref, &identity.source_version, original.clone()).await.unwrap();
        assert_eq!(fetched.value.as_slice(), b"retained plaintext");
        assert_eq!(target.version_hash(&identity.name, logical, &fetched.value).unwrap(), identity.version_hash);
        assert!(matches!(backend.version(&identity.name, &identity.source_version, original.clone()).await,
            Err(BackendError::VersionGone)));
        assert_eq!(target.export_encrypted_row("token", physical).unwrap(), Some(row.clone()));
        assert!(target.export_encrypted_row("logical-alias", physical).unwrap().is_none());
    }
}

#[test]
fn alias_wrong_reference_hash_master_or_original_envelope_never_mutates_custody() {
    let (dir, master, source, target) = pair();
    let row = write(&source, 7, 3);
    let identity = expected_alias(&source, "logical-alias", "token", 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(),
        SecretImportDisposition::Operational);
    let before = changes(&target);
    let mut wrong_ref = identity.clone();
    wrong_ref.r#ref = "another-slot".into();
    wrong_ref.canonical_ref = "another-slot".into();
    assert!(target.import_encrypted_row(&wrong_ref, &row, None, SecretImportDisposition::Operational).is_err());
    assert_eq!(target.verify_encrypted_row(&wrong_ref, blake3::hash(&row.ciphertext).as_bytes(), None,
        SecretImportDisposition::Operational).unwrap(), None);
    let mut wrong_logical = identity.clone();
    wrong_logical.version_hash = row.version_hash.clone();
    assert!(target.import_encrypted_row(&wrong_logical, &row, None, SecretImportDisposition::Operational).is_err());
    assert!(target.verify_encrypted_row(&wrong_logical, blake3::hash(&row.ciphertext).as_bytes(), None,
        SecretImportDisposition::Operational).is_err());
    let mut wrong_name = identity.clone();
    wrong_name.name = "another-logical-alias".into();
    assert!(target.import_encrypted_row(&wrong_name, &row, None, SecretImportDisposition::Operational).is_err());
    assert!(target.verify_encrypted_row(&wrong_name, blake3::hash(&row.ciphertext).as_bytes(), None,
        SecretImportDisposition::Operational).is_err());
    let mut retagged = row.clone();
    retagged.name = "another-slot".into();
    assert!(target.import_encrypted_row(&wrong_ref, &retagged, None, SecretImportDisposition::Operational).is_err());
    let alternative = SecretStore::open(Connection::open(dir.path().join("alias-alternative.db")).unwrap(), &master).unwrap();
    let different = write(&alternative, 7, 4);
    assert!(matches!(target.import_encrypted_row(&identity, &different, None, SecretImportDisposition::Operational),
        Err(PrivacyError::SecretRowConflict)));
    let wrong = SecretStore::open(Connection::open(dir.path().join("alias-wrong-master.db")).unwrap(),
        &MasterKey::from_bytes([8; 32]).unwrap()).unwrap();
    assert!(wrong.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).is_err());
    assert!(wrong.current("token").unwrap().is_none());
    assert_eq!(changes(&target), before);
    assert_eq!(target.export_encrypted_row("token", 7).unwrap(), Some(row));
    assert_eq!(target.version("token", 7).unwrap().unwrap().value, b"retained plaintext");
}

#[tokio::test]
async fn alias_floor_is_not_a_shared_physical_revocation_but_a_genuine_physical_floor_is() {
    let (dir, master, source, target) = pair();
    let original = test_authority();
    let row = write(&source, 7, 3);
    let identity = expected_alias(&source, "logical-alias", "token", 19, 7, b"retained plaintext");
    assert_eq!(target.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational).unwrap(),
        SecretImportDisposition::Operational);
    let floor = SecretDeletionFloor { through_version: 7, applied_wall_ms: 77 };
    let before = changes(&target);
    for intended in [SecretImportDisposition::Operational, SecretImportDisposition::ScrubOnly] {
        assert!(target.import_encrypted_row(&identity, &row, Some(("logical-alias", floor)), intended).is_err());
        assert!(target.verify_encrypted_row(&identity, blake3::hash(&row.ciphertext).as_bytes(),
            Some(("logical-alias", floor)), intended).is_err());
    }
    assert_eq!(changes(&target), before);
    assert_eq!(target.stored_deletion_floor("token").unwrap(), None);
    assert_eq!(target.version("token", 7).unwrap().unwrap().value, b"retained plaintext");
    // A separately proven physical-name cut is a different fact. It revokes
    // the physical slot, retains its exact original envelope and survives reopen.
    assert_eq!(target.import_encrypted_row(&identity, &row, Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(),
        SecretImportDisposition::ScrubOnly);
    assert_eq!(target.verify_encrypted_row(&identity, blake3::hash(&row.ciphertext).as_bytes(),
        Some(("token", floor)), SecretImportDisposition::ScrubOnly).unwrap(), Some(SecretImportDisposition::ScrubOnly));
    drop(target);
    let reopened = Arc::new(SecretStore::open(Connection::open(dir.path().join("target.db")).unwrap(), &master).unwrap());
    assert!(matches!(reopened.import_encrypted_row(&identity, &row, None, SecretImportDisposition::Operational),
        Err(PrivacyError::SecretDeleted)));
    assert!(matches!(reopened.set_at("token", 7, b"late", [4; 24], 80, "", ""), Err(PrivacyError::SecretDeleted)));
    assert_eq!(reopened.retained_version_for_scrub("token", 7).unwrap().unwrap().value, b"retained plaintext");
    let retained = reopened.export_encrypted_row("token", 7).unwrap().unwrap();
    assert_eq!((&retained.nonce, &retained.ciphertext, &retained.version_hash, retained.created_wall_ms,
        &retained.token_id, &retained.reason),
        (&row.nonce, &row.ciphertext, &row.version_hash, row.created_wall_ms, &row.token_id, &row.reason));
    let backend = FileBackend::new(kronik_core::env::Env::real(tokio::runtime::Handle::current()), reopened.clone());
    assert!(matches!(backend.version("token", "7", original.clone()).await, Err(BackendError::VersionGone)));
    reopened.set_at("token", 8, b"new shared value", [9; 24], 81, "original-admin", "next physical set").unwrap();
    assert_eq!(backend.current("token", original).await.unwrap().value.as_slice(), b"new shared value");
}
