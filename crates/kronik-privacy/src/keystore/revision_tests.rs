#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::sealer::{Opened, ResealOp, Sealer};
use kronik_proto::log::v1 as pb;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::fs::{File, FileTimes};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[path = "revision_tests/erasure_floor.rs"]
mod erasure_floor_tests;

#[path = "revision_tests/plain_source_floor.rs"]
mod plain_source_floor_tests;

#[path = "revision_tests/wrapped_floor_clock.rs"]
mod wrapped_floor_clock_tests;

struct Pair {
    owner: crate::key_source::DataOwnership,
    path: PathBuf,
    master: MasterKey,
    first: Arc<Keystore>,
    second: Arc<Keystore>,
    a: Sealer,
    b: Sealer,
    entropy: AtomicU8,
    _dir: tempfile::TempDir,
}
impl Pair {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = crate::key_source::lock_data(dir.path()).unwrap();
        let path = dir.path().join("keys/keystore.db");
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let first = Keystore::open_owned(&owner, &master).unwrap();
        let second = first.reopen_owned().unwrap();
        let a = Sealer::new(first.clone()).with_pseudonyms(Pseudonyms::new(&master).unwrap());
        let b = Sealer::new(second.clone()).with_pseudonyms(Pseudonyms::new(&master).unwrap());
        a.set_on(true); b.set_on(true);
        Self { owner, path, master, first, second, a, b, entropy: AtomicU8::new(1), _dir: dir }
    }
    fn fill(&self, bytes: &mut [u8]) { bytes.fill(self.entropy.fetch_add(1, Ordering::Relaxed)); }
    fn seal(&self, sealer: &Sealer, bytes: &[u8]) -> pb::Sealable {
        let mut value = plain(bytes);
        sealer.seal_value(&mut value, &|bytes| self.fill(bytes), 1).unwrap();
        value
    }
}
fn plain(bytes: &[u8]) -> pb::Sealable {
    pb::Sealable { subject: Some("user:1".into()), value: Some(pb::sealable::Value::Plain(bytes.to_vec())) }
}
fn version(value: &pb::Sealable) -> u32 {
    match value.value.as_ref().unwrap() { pb::sealable::Value::Sealed(value) => value.key_version, _ => panic!("value was not sealed") }
}
#[derive(Debug, PartialEq, Eq)]
struct Stamp { bytes: u64, modified: SystemTime }

// Freeze only this fixture's DB/WAL metadata, never the host clock. The old
// mtime/length heuristic sees exactly the same evidence before and after writes.
fn settled_stamps(path: &Path) -> [Stamp; 2] {
    let conn = Connection::open(path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    let busy: i64 = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0)).unwrap();
    assert_eq!(busy, 0);
    drop(conn);
    fixed_stamps(path)
}
fn fixed_stamps(path: &Path) -> [Stamp; 2] {
    let fixed = UNIX_EPOCH + Duration::from_secs(1_000_000);
    [path.to_owned(), PathBuf::from(format!("{}-wal", path.display()))].map(|path| {
        let file = File::options().read(true).write(true).open(&path).unwrap();
        file.set_times(FileTimes::new().set_accessed(fixed).set_modified(fixed)).unwrap();
        let metadata = file.metadata().unwrap();
        Stamp { bytes: metadata.len(), modified: metadata.modified().unwrap() }
    })
}
fn warm(pair: &Pair) -> pb::Sealable {
    let value = pair.seal(&pair.a, b"cached-value");
    assert_eq!(pair.b.open(&value).bytes(), Some(b"cached-value".as_slice()));
    assert_eq!(version(&pair.seal(&pair.b, b"also-cached")), 1);
    value
}

#[test]
fn two_stores_and_two_sealers_observe_rotation_with_identical_db_and_wal_metadata() {
    let pair = Pair::new();
    let old = warm(&pair);
    let identity = pair.a.keyed_hash("kronik audit record v3", &[b"canonical metadata"]).unwrap();
    let before = settled_stamps(&pair.path);
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.second.rotate("user:1", [9; 32], [10; 24], 2).unwrap(), 2);
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(pair.first.revision().unwrap() > revision);
    assert_eq!(pair.first.revision().unwrap(), pair.second.revision().unwrap());
    let mut resealed = plain(b"resealed-current");
    assert_eq!(pair.a.reseal_value(&mut resealed, None, &|bytes| pair.fill(bytes), 3).unwrap(), ResealOp::Sealed);
    assert_eq!(version(&resealed), 2);
    assert_eq!(version(&pair.seal(&pair.b, b"rotated")), 2);
    assert_eq!(pair.a.open(&old).bytes(), Some(b"cached-value".as_slice()));
    assert_eq!(pair.b.open(&resealed).bytes(), Some(b"resealed-current".as_slice()));
    assert_eq!(pair.a.keyed_hash("kronik audit record v3", &[b"canonical metadata"]), Some(identity));
}

#[test]
fn erase_through_an_independent_store_revokes_both_warm_caches_with_equal_metadata() {
    let pair = Pair::new();
    let old = warm(&pair);
    let identity = pair.a.keyed_hash("kronik audit record v3", &[b"canonical metadata"]);
    let before = settled_stamps(&pair.path);
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.second.erase("user:1", 2).unwrap(), 1);
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(pair.first.revision().unwrap() > revision);
    assert!(matches!(pair.a.open(&old), Opened::Erased { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Erased { .. }));
    assert_eq!(version(&pair.seal(&pair.a, b"new subject epoch")), 2);
    assert!(matches!(pair.b.open(&old), Opened::Erased { .. }));
    assert_eq!(pair.a.keyed_hash("kronik audit record v3", &[b"canonical metadata"]), identity);
}

#[test]
fn own_connection_mutations_invalidate_other_sealers_even_when_data_version_is_unchanged() {
    let pair = Pair::new();
    let other = Sealer::new(pair.first.clone()); other.set_on(true);
    let old = pair.seal(&pair.a, b"same connection");
    assert!(other.open(&old).bytes().is_some());
    let data_before = data_version(&pair.first.conn()).unwrap();
    let revision = pair.first.revision().unwrap();
    pair.first.erase("user:1", 2).unwrap();
    assert_eq!(data_version(&pair.first.conn()).unwrap(), data_before);
    assert!(pair.first.revision().unwrap() > revision);
    assert!(matches!(pair.a.open(&old), Opened::Erased { .. }));
    assert!(matches!(other.open(&old), Opened::Erased { .. }));
}

#[test]
fn restoring_different_keys_at_the_same_version_invalidates_loaded_consumers() {
    let pair = Pair::new();
    let old = warm(&pair);
    let source = Keystore::open_memory(&pair.master).unwrap();
    source.key_for_sealing("user:1", [11; 32], [12; 24], 1).unwrap();
    let backup = source.export_backup([13; 24]).unwrap();
    let before = settled_stamps(&pair.path);
    let revision = pair.first.revision().unwrap();
    drop(Keystore::restore_owned(&pair.owner, &pair.master, &backup).unwrap());
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(pair.first.revision().unwrap() > revision);
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Unreadable { .. }));
    let current = pair.seal(&pair.a, b"replacement lineage");
    assert_eq!(version(&current), 1);
    let KeyLookup::Found(key) = source.key("user:1", 1).unwrap() else { panic!("missing backup key") };
    let Some(pb::sealable::Value::Sealed(value)) = &current.value else { panic!("not sealed") };
    let stored = SealedValue { key_version: value.key_version, nonce: value.nonce.as_slice().try_into().unwrap(), ciphertext: value.ciphertext.clone() };
    assert_eq!(unseal("user:1", &key, &stored).unwrap(), b"replacement lineage");
    assert_eq!(pair.b.open(&current).bytes(), Some(b"replacement lineage".as_slice()));
}

#[test]
fn logged_partial_erasure_preserves_newer_versions_and_noop_does_not_advance_revision() {
    let pair = Pair::new();
    let old = warm(&pair);
    pair.second.rotate("user:1", [21; 32], [22; 24], 2).unwrap();
    let newer = pair.seal(&pair.a, b"newer version");
    assert!(pair.b.open(&newer).bytes().is_some());
    let before = settled_stamps(&pair.path);
    pair.second.erase_through("user:1", 1, 3).unwrap();
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(matches!(pair.a.open(&old), Opened::Erased { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Erased { .. }));
    assert_eq!(pair.a.open(&newer).bytes(), Some(b"newer version".as_slice()));
    let revision = pair.first.revision().unwrap();
    pair.second.erase_through("user:1", 1, 4).unwrap();
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(version(&pair.seal(&pair.b, b"still version two")), 2);
}

#[test]
fn revision_read_failure_refuses_both_cached_opening_and_cached_sealing() {
    let pair = Pair::new();
    let old = warm(&pair);
    Connection::open(&pair.path).unwrap().execute_batch("DROP TABLE keystore_revision").unwrap();
    assert!(pair.first.revision().is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Unreadable { .. }));
    let mut value = plain(b"must remain uncommitted");
    assert!(pair.a.seal_value(&mut value, &|_| panic!("cannot allocate a nonce after revision failure"), 3).is_err());
    assert!(pair.b.seal_value(&mut value, &|_| panic!("cannot allocate a nonce after revision failure"), 3).is_err());
    assert!(pair.a.erase("user:1", 4).is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
}

#[test]
fn revision_overflow_aborts_the_whole_key_mutation_without_real_promotion() {
    let pair = Pair::new();
    warm(&pair);
    let conn = Connection::open(&pair.path).unwrap();
    conn.execute("UPDATE keystore_revision SET revision = ?1 WHERE id = 1", [i64::MAX]).unwrap();
    assert!(pair.second.rotate("user:1", [31; 32], [32; 24], 2).is_err());
    assert_eq!(pair.second.stats().unwrap().keys, 1);
    assert!(pair.a.erase("user:1", 3).is_err());
    assert_eq!(pair.first.stats().unwrap().keys, 1);
    let stored: (String, i64) = conn.query_row("SELECT typeof(revision), revision FROM keystore_revision", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(stored, ("integer".into(), i64::MAX));
}

#[test]
fn replacing_the_file_refuses_old_handles_even_with_same_revision_and_file_stamps() {
    let pair = Pair::new();
    let old = warm(&pair);
    let replacement_root = tempfile::tempdir().unwrap();
    let replacement_owner = crate::key_source::lock_data(replacement_root.path()).unwrap();
    let replacement = replacement_root.path().join("keys/keystore.db");
    let new = Keystore::open_owned(&replacement_owner, &pair.master).unwrap();
    new.key_for_sealing("user:1", [41; 32], [42; 24], 1).unwrap();
    assert_eq!(new.revision().unwrap(), pair.first.revision().unwrap());
    drop(new);
    let before = settled_stamps(&pair.path);
    std::fs::rename(&replacement, &pair.path).unwrap();
    assert_eq!(fixed_stamps(&pair.path), before);
    assert!(pair.first.revision().is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Unreadable { .. }));
    let mut value = plain(b"cannot use disconnected database");
    assert!(pair.a.seal_value(&mut value, &|_| panic!("replaced handle must not use cached keys"), 2).is_err());
}

#[test]
fn miss_key_and_revision_are_from_one_snapshot_despite_an_interleaved_external_commit() {
    let pair = Pair::new();
    warm(&pair);
    let before_metadata = settled_stamps(&pair.path);
    let before = pair.first.revision().unwrap();
    let data_before = data_version(&pair.first.conn()).unwrap();
    let rotated = Arc::new(AtomicBool::new(false));
    let observed = rotated.clone();
    let writer = pair.second.clone();
    pair.first.conn().authorizer(Some(move |context: AuthContext<'_>| {
        if matches!(context.action, AuthAction::Read { table_name: "keystore_revision", .. })
            && !observed.swap(true, Ordering::SeqCst)
        { writer.rotate("user:1", [51; 32], [52; 24], 2).unwrap(); }
        Authorization::Allow
    })).unwrap();
    let (stamp, key) = pair.first.sealing_key_at_revision("user:1", [53; 32], [54; 24], 3).unwrap();
    pair.first.conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>).unwrap();
    assert!(rotated.load(Ordering::SeqCst));
    assert_eq!(key.version, 1);
    assert_eq!(stamp.revision, before);
    assert_eq!(stamp.data_version, data_before);
    assert!(pair.first.revision().unwrap() > stamp.revision);
    assert_eq!(settled_stamps(&pair.path), before_metadata);
    assert_eq!(version(&pair.seal(&pair.a, b"latest after snapshot")), 2);
}

#[test]
fn legacy_schema_migrates_without_changing_wrapped_rows_or_krkstor1_backup_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let owner = crate::key_source::lock_data(dir.path()).unwrap();
    let path = dir.path().join("keys/keystore.db");
    let master = MasterKey::from_bytes([7; 32]).unwrap();
    let store = Keystore::open_owned(&owner, &master).unwrap();
    store.key_for_sealing("user:1", [61; 32], [62; 24], 1).unwrap();
    let backup = store.export_backup([63; 24]).unwrap();
    drop(store);
    Connection::open(&path).unwrap().execute_batch(
        "DROP TRIGGER subject_keys_revision_insert; DROP TRIGGER subject_keys_revision_update;
         DROP TRIGGER subject_keys_revision_delete; DROP TRIGGER erasures_revision_insert;
         DROP TRIGGER erasures_revision_update; DROP TRIGGER erasures_revision_delete;
         DROP TABLE keystore_revision;"
    ).unwrap();
    let migrated = Keystore::open_owned(&owner, &master).unwrap();
    assert_eq!(migrated.revision().unwrap(), 0);
    assert!(matches!(migrated.key("user:1", 1).unwrap(), KeyLookup::Found(_)));
    assert_eq!(migrated.export_backup([63; 24]).unwrap(), backup);
    let revision = migrated.revision().unwrap();
    migrated.rotate("user:1", [64; 32], [65; 24], 2).unwrap();
    assert!(migrated.revision().unwrap() > revision);
}

#[test]
fn even_an_empty_backup_install_advances_the_persistent_revision_and_checkpoints_do_not() {
    let pair = Pair::new();
    let backup = pair.first.export_backup([71; 24]).unwrap();
    let before = pair.first.revision().unwrap();
    drop(Keystore::restore_owned(&pair.owner, &pair.master, &backup).unwrap());
    let installed = pair.first.revision().unwrap();
    assert!(installed > before);
    settled_stamps(&pair.path);
    assert_eq!(pair.first.revision().unwrap(), installed);
    assert_eq!(pair.second.revision().unwrap(), installed);
}

#[test]
fn fixed_version_snapshot_sealing_never_promotes_v1_to_v2_or_resurrects_an_erased_key() {
    let pair = Pair::new();
    warm(&pair);
    pair.second.rotate("user:1", [81; 32], [82; 24], 2).unwrap();
    pair.a.set_on(false);
    let mut v1 = plain(b"original v1 snapshot row");
    pair.a.seal_value_at(&mut v1, 1, &|bytes| pair.fill(bytes)).unwrap();
    assert_eq!(version(&v1), 1);
    assert_eq!(pair.b.open(&v1).bytes(), Some(b"original v1 snapshot row".as_slice()));
    let mut v2 = plain(b"original v2 snapshot row");
    pair.a.seal_value_at(&mut v2, 2, &|bytes| pair.fill(bytes)).unwrap();
    assert_eq!(version(&v2), 2);
    pair.second.erase_through("user:1", 1, 3).unwrap();
    assert!(matches!(pair.a.open(&v1), Opened::Erased { .. }));
    assert!(matches!(pair.b.open(&v1), Opened::Erased { .. }));
    assert_eq!(pair.b.open(&v2).bytes(), Some(b"original v2 snapshot row".as_slice()));
    let before = pair.first.stats().unwrap();
    for missing in [0, 1, 99] {
        let mut value = plain(b"must not be promoted");
        let original = value.clone();
        assert!(pair.a.seal_value_at(&mut value, missing, &|_| panic!("missing key must not request randomness")).is_err());
        assert_eq!(value, original);
    }
    assert_eq!(pair.first.stats().unwrap(), before);
}

#[test]
fn maximum_subject_key_is_usable_but_rotation_never_wraps_or_creates_a_key() {
    let pair = Pair::new();
    {
        let conn = pair.first.conn();
        pair.first.insert_key(&conn, "user:1", u32::MAX, &[91; 32], [92; 24], 1).unwrap();
    }
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.first.key_for_sealing("user:1", [93; 32], [94; 24], 2).unwrap().version, u32::MAX);
    let value = pair.seal(&pair.a, b"last valid key");
    assert_eq!(version(&value), u32::MAX);
    assert_eq!(pair.b.open(&value).bytes(), Some(b"last valid key".as_slice()));
    assert!(matches!(pair.second.rotate("user:1", [95; 32], [96; 24], 3),
        Err(PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(_, next)))
            if next == i64::from(u32::MAX) + 1));
    assert!(pair.first.key("user:1", 0).is_err());
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(pair.a.open(&value).bytes(), Some(b"last valid key".as_slice()));
}

#[test]
fn maximum_erased_floor_refuses_plain_source_creation_and_rotation_without_mutating_rows() {
    let pair = Pair::new();
    pair.second.erase_through("user:1", u32::MAX, 1).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert!(matches!(pair.first.key_for_sealing("user:1", [101; 32], [102; 24], 2),
        Err(PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(_, next)))
            if next == i64::from(u32::MAX) + 1));
    assert!(pair.second.rotate("user:1", [103; 32], [104; 24], 3).is_err());
    let mut value = plain(b"cannot allocate a zero or wrapped version");
    let original = value.clone();
    assert!(pair.a.seal_value(&mut value, &|bytes| pair.fill(bytes), 4).is_err());
    assert_eq!(value, original);
    assert!(pair.a.seal_plain_source(&mut value, Some(u32::MAX), &|bytes| pair.fill(bytes), 4).is_err());
    assert_eq!(value, original);
    assert!(pair.a.require_key_version("user:1", u32::MAX).is_err());
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(pair.first.stats().unwrap().keys, 0);
}

#[test]
fn invalid_stored_subject_key_versions_fail_closed_before_creating_or_deleting_rows() {
    for version in [-1, 0, i64::from(u32::MAX) + 1] {
        let pair = Pair::new();
        pair.first.conn().execute(
            "INSERT INTO subject_keys(subject, version, nonce, wrapped, created_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["user:1", version, [111u8; 24].as_slice(), [112u8; 48].as_slice(), 1],
        ).unwrap();
        let before = pair.first.stats().unwrap();
        let revision = pair.first.revision().unwrap();
        assert!(pair.first.key_for_sealing("user:1", [113; 32], [114; 24], 2).is_err());
        assert!(pair.second.rotate("user:1", [115; 32], [116; 24], 3).is_err());
        assert!(pair.second.erase("user:1", 4).is_err());
        assert!(pair.first.export_backup([117; 24]).is_err());
        assert_eq!(pair.first.stats().unwrap(), before);
        assert_eq!(pair.first.revision().unwrap(), revision);
    }
}

#[test]
fn original_key_admission_is_noncreating_and_does_not_select_a_historical_key_as_newest() {
    let pair = Pair::new();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    for missing in [0, 1, u32::MAX] {
        assert!(pair.a.require_key_version("user:1", missing).is_err());
    }
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    warm(&pair);
    pair.second.rotate("user:1", [121; 32], [122; 24], 2).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    pair.a.require_key_version("user:1", 1).unwrap();
    assert!(pair.a.require_key_version("user:1", 99).is_err());
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(version(&pair.seal(&pair.a, b"must use v2")), 2);
    pair.a.require_key_version("user:1", 1).unwrap();
    assert_eq!(version(&pair.seal(&pair.a, b"still uses v2")), 2);
    pair.second.erase_through("user:1", 1, 3).unwrap();
    assert!(pair.a.require_key_version("user:1", 1).is_err());
    pair.a.require_key_version("user:1", 2).unwrap();
}

#[test]
fn never_erased_plain_source_receipt_rejects_history_even_with_a_newer_active_key() {
    let pair = Pair::new();
    pair.a.set_on(false);
    let mut initial = plain(b"proved initial source");
    pair.a.seal_plain_source(&mut initial, None, &|bytes| pair.fill(bytes), 1).unwrap();
    assert_eq!(version(&initial), 1);
    assert_eq!(pair.b.open(&initial).bytes(), Some(b"proved initial source".as_slice()));
    assert!(pair.a.seal_plain_source(&mut initial, None, &|_| panic!("sealed input must not request randomness"), 1).is_err());
    pair.second.rotate("user:1", [131; 32], [132; 24], 2).unwrap();
    let mut current = plain(b"proved source before any erasure");
    pair.a.seal_plain_source(&mut current, None, &|bytes| pair.fill(bytes), 2).unwrap();
    assert_eq!(version(&current), 2);
    let mut stale = plain(b"must not promote stale plaintext to v2");
    pair.second.erase_through("user:1", 1, 3).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    let original = stale.clone();
    assert!(pair.a.seal_plain_source(&mut stale, None, &|bytes| pair.fill(bytes), 4).is_err());
    assert_eq!(stale, original);
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    pair.a.set_on(true);
    assert_eq!(version(&pair.seal(&pair.a, b"legitimate live use of v2")), 2);
    let mut empty = plain(b"erasing an unknown subject still fences old plaintext");
    empty.subject = Some("user:empty".into());
    assert_eq!(pair.second.erase("user:empty", 5).unwrap(), 0);
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    let original = empty.clone();
    assert!(pair.a.seal_plain_source(&mut empty, None, &|bytes| pair.fill(bytes), 6).is_err());
    assert_eq!(empty, original);
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
}

#[test]
fn concurrent_erasure_after_plain_source_selection_never_mints_a_post_erasure_key() {
    for existing in [false, true] {
        let pair = Pair::new();
        if existing { warm(&pair); }
        let before = pair.first.revision().unwrap();
        let erased = Arc::new(AtomicBool::new(false));
        let observed = erased.clone();
        let writer = pair.second.clone();
        pair.first.conn().authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Read { table_name: "subject_keys", .. })
                && !observed.swap(true, Ordering::SeqCst)
            { writer.erase_through("user:1", if existing { 1 } else { 0 }, 2).unwrap(); }
            Authorization::Allow
        })).unwrap();
        let mut value = plain(b"source selected before concurrent erase");
        let original = value.clone();
        let result = pair.a.seal_plain_source(&mut value, None, &|bytes| pair.fill(bytes), 3);
        pair.first.conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>).unwrap();
        assert!(erased.load(Ordering::SeqCst));
        if existing {
            result.unwrap();
            assert_eq!(version(&value), 1);
            assert!(matches!(pair.b.open(&value), Opened::Erased { .. }));
        } else {
            assert!(result.is_err());
            assert_eq!(value, original);
        }
        assert_eq!(pair.first.stats().unwrap().keys, 0);
        assert_eq!(pair.first.stats().unwrap().erased, 1);
        assert_eq!(pair.first.revision().unwrap(), before + if existing { 2 } else { 1 });
    }
}

#[test]
fn wrapped_export_is_read_only_and_selects_the_original_version_not_current() {
    let source = Pair::new();
    warm(&source);
    let original = source.first.export_wrapped_version("user:1", 1).unwrap();
    source.second.rotate("user:1", [141; 32], [142; 24], 2).unwrap();
    let before = source.first.stats().unwrap();
    let revision = source.first.revision().unwrap();
    let data_before = data_version(&source.second.conn()).unwrap();
    assert_eq!(source.first.export_wrapped_version("user:1", 1).unwrap(), original);
    let missing = source.first.export_wrapped_version("user:missing", 7).unwrap();
    assert!(missing.key.is_none());
    assert!(missing.erasure.is_none());
    assert!(source.first.export_wrapped_version("user:1", 0).is_err());
    assert!(source.first.export_wrapped_version("bad subject", 1).is_err());
    assert_eq!(source.first.stats().unwrap(), before);
    assert_eq!(source.first.revision().unwrap(), revision);
    assert_eq!(data_version(&source.second.conn()).unwrap(), data_before);
    for statement in [
        "UPDATE subject_keys SET nonce = zeroblob(23) WHERE version = 1",
        "UPDATE subject_keys SET wrapped = zeroblob(47) WHERE version = 1",
        "UPDATE subject_keys SET created_wall_ms = -1 WHERE version = 1",
    ] {
        let malformed = Pair::new();
        warm(&malformed);
        malformed.first.conn().execute(statement, []).unwrap();
        let revision = malformed.first.revision().unwrap();
        assert!(malformed.first.export_wrapped_version("user:1", 1).is_err());
        assert_eq!(malformed.first.revision().unwrap(), revision);
    }
}

#[test]
fn wrapped_merge_bootstraps_only_original_v2_preserving_other_subjects_and_newer_keys() {
    let source = Pair::new();
    source.first.key_for_sealing("user:1", [151; 32], [152; 24], 10).unwrap();
    source.first.rotate("user:1", [153; 32], [154; 24], 11).unwrap();
    let original_v2 = source.seal(&source.a, b"original source v2");
    assert_eq!(version(&original_v2), 2);
    source.first.rotate("user:1", [155; 32], [156; 24], 12).unwrap();
    source.first.erase_through("user:1", 1, 13).unwrap();
    let capsule = source.first.export_wrapped_version("user:1", 2).unwrap();
    let receiver = Pair::new();
    let old = warm(&receiver);
    let mut other = plain(b"unrelated retained subject");
    other.subject = Some("user:other".into());
    receiver.a.seal_value(&mut other, &|bytes| receiver.fill(bytes), 1).unwrap();
    let proof = ("user:1", 1);
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 2, &capsule, Some(proof), 100).unwrap(), WrappedVersionStatus::Imported);
    assert_eq!(receiver.a.open(&original_v2).bytes(), Some(b"original source v2".as_slice()));
    assert!(matches!(receiver.a.open(&old), Opened::Erased { .. }));
    assert_eq!(receiver.b.open(&other).bytes(), Some(b"unrelated retained subject".as_slice()));
    let copied = receiver.first.export_wrapped_version("user:1", 2).unwrap();
    assert_eq!(copied.key, capsule.key);
    assert_eq!(copied.erasure, Some(SubjectErasure { last_version: 1, erased_wall_ms: 100 }));
    assert!(matches!(receiver.first.key("user:1", 3).unwrap(), KeyLookup::Missing));
    let revision = receiver.first.revision().unwrap();
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 2, &capsule, Some(proof), 200).unwrap(), WrappedVersionStatus::Present);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert_eq!(receiver.first.export_wrapped_version("user:1", 2).unwrap().erasure, Some(SubjectErasure { last_version: 1, erased_wall_ms: 100 }));
}

#[test]
fn wrapped_merge_never_guesses_floor_zero_or_resurrects_a_stale_sender_key() {
    let source = Pair::new();
    let receiver = Pair::new();
    let missing = source.first.export_wrapped_version("user:missing", 1).unwrap();
    assert_eq!(receiver.first.merge_wrapped_version("user:missing", 1, &missing, None, 10).unwrap(), WrappedVersionStatus::Missing);
    assert!(receiver.first.erasures().unwrap().is_empty());
    source.first.erase_through("user:zero", 0, 1).unwrap();
    let zero = source.first.export_wrapped_version("user:zero", 1).unwrap();
    let revision = receiver.first.revision().unwrap();
    assert!(receiver.first.merge_wrapped_version("user:zero", 1, &zero, None, 11).is_err());
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert!(receiver.first.erasures().unwrap().is_empty());
    let proof_zero = ("user:zero", 0);
    assert_eq!(receiver.first.merge_wrapped_version("user:zero", 1, &zero, Some(proof_zero), 12).unwrap(), WrappedVersionStatus::Missing);
    assert_eq!(receiver.first.erasures().unwrap(), vec![ErasureInfo { subject: "user:zero".into(), last_version: 0, erased_wall_ms: 12 }]);
    let old = warm(&source);
    let stale = source.first.export_wrapped_version("user:1", 1).unwrap();
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 1, &stale, None, 13).unwrap(), WrappedVersionStatus::Imported);
    assert!(receiver.a.open(&old).bytes().is_some());
    source.first.erase_through("user:1", 1, 2).unwrap();
    let erased = source.first.export_wrapped_version("user:1", 1).unwrap();
    assert!(erased.key.is_none());
    let revision = receiver.first.revision().unwrap();
    assert!(receiver.first.merge_wrapped_version("user:1", 1, &erased, None, 14).is_err());
    assert_eq!(receiver.first.revision().unwrap(), revision);
    let proof = ("user:1", 1);
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 1, &erased, Some(proof), 15).unwrap(), WrappedVersionStatus::Erased);
    let revision = receiver.first.revision().unwrap();
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 1, &stale, None, 16).unwrap(), WrappedVersionStatus::Erased);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert!(matches!(receiver.a.open(&old), Opened::Erased { .. }));
    let new = source.seal(&source.a, b"new A2 after erased A1");
    assert_eq!(version(&new), 2);
    let new_capsule = source.first.export_wrapped_version("user:1", 2).unwrap();
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 2, &new_capsule, None, 17).unwrap(), WrappedVersionStatus::Imported);
    assert_eq!(receiver.b.open(&new).bytes(), Some(b"new A2 after erased A1".as_slice()));
    assert!(matches!(receiver.a.open(&old), Opened::Erased { .. }));
}

#[test]
fn wrapped_merge_rejects_unbound_identity_wrong_master_tampering_and_unchecked_times() {
    let source = Pair::new();
    warm(&source);
    let capsule = source.first.export_wrapped_version("user:1", 1).unwrap();
    let receiver = Pair::new();
    let mut subject = capsule.clone(); subject.subject = "user:other".into();
    let mut version = capsule.clone(); version.version = 2;
    let mut nonce = capsule.clone(); nonce.key.as_mut().unwrap().nonce[0] ^= 1;
    let mut ciphertext = capsule.clone(); ciphertext.key.as_mut().unwrap().wrapped[0] ^= 1;
    let mut key_time = capsule.clone(); key_time.key.as_mut().unwrap().created_wall_ms = u64::MAX;
    let mut floor_time = capsule.clone();
    floor_time.erasure = Some(SubjectErasure { last_version: 0, erased_wall_ms: u64::MAX });
    let before = receiver.first.stats().unwrap();
    let revision = receiver.first.revision().unwrap();
    for bad in [subject, version, nonce, ciphertext, key_time, floor_time] {
        assert!(receiver.first.merge_wrapped_version("user:1", 1, &bad, None, 100).is_err());
        assert_eq!(receiver.first.stats().unwrap(), before);
        assert_eq!(receiver.first.revision().unwrap(), revision);
    }
    for (proof, wall_ms) in [
        (Some(("user:other", 1)), 100),
        (Some(("user:1", 1)), u64::MAX),
    ] {
        assert!(receiver.first.merge_wrapped_version("user:1", 1, &capsule, proof, wall_ms).is_err());
        assert_eq!(receiver.first.stats().unwrap(), before);
        assert_eq!(receiver.first.revision().unwrap(), revision);
    }
    let wrong_master = MasterKey::from_bytes([8; 32]).unwrap();
    let wrong = Keystore::open_memory(&wrong_master).unwrap();
    assert!(wrong.merge_wrapped_version("user:1", 1, &capsule, None, 100).is_err());
    assert_eq!(wrong.stats().unwrap().keys, 0);
    assert_eq!(wrong.stats().unwrap().erased, 0);
    assert_eq!(wrong.revision().unwrap(), 0);
}

#[test]
fn wrapped_merge_rejects_different_key_before_mutation_and_accepts_rewrap_without_changing_facts() {
    let receiver = Pair::new();
    let value = warm(&receiver);
    let source = Pair::new();
    source.first.key_for_sealing("user:1", [161; 32], [162; 24], 10).unwrap();
    let conflicting = source.first.export_wrapped_version("user:1", 1).unwrap();
    let proof_zero = ("user:1", 0);
    let before = receiver.first.stats().unwrap();
    let revision = receiver.first.revision().unwrap();
    assert!(receiver.first.merge_wrapped_version("user:1", 1, &conflicting, Some(proof_zero), 100).is_err());
    assert_eq!(receiver.first.stats().unwrap(), before);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert!(receiver.first.erasures().unwrap().is_empty());
    let original = receiver.first.export_wrapped_version("user:1", 1).unwrap();
    let mut rewrapped = original.clone();
    let KeyLookup::Found(key) = receiver.first.key("user:1", 1).unwrap() else { panic!("missing original key") };
    let wrapped = rewrapped.key.as_mut().unwrap();
    wrapped.nonce = [163; 24];
    wrapped.wrapped = XChaCha20Poly1305::new(receiver.first.wrap.bytes().into()).encrypt(
        &XNonce::from(wrapped.nonce),
        Payload { msg: &key.key[..], aad: &wrap_aad("user:1", 1) },
    ).unwrap().try_into().unwrap();
    wrapped.created_wall_ms = 99;
    assert_ne!(rewrapped, original);
    assert_eq!(receiver.first.merge_wrapped_version("user:1", 1, &rewrapped, None, 200).unwrap(), WrappedVersionStatus::Present);
    assert_eq!(receiver.first.export_wrapped_version("user:1", 1).unwrap(), original);
    assert_eq!(receiver.first.stats().unwrap(), before);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert_eq!(receiver.a.open(&value).bytes(), Some(b"cached-value".as_slice()));
}

#[test]
fn wrapped_merge_rolls_back_proved_erasure_and_revision_when_later_key_insert_fails() {
    let source = Pair::new();
    warm(&source);
    source.first.rotate("user:1", [171; 32], [172; 24], 2).unwrap();
    let capsule = source.first.export_wrapped_version("user:1", 2).unwrap();
    let receiver = Pair::new();
    let old = warm(&receiver);
    let before = receiver.first.stats().unwrap();
    let revision = receiver.first.revision().unwrap();
    receiver.first.conn().execute_batch(
        "CREATE TRIGGER reject_fixture_key BEFORE INSERT ON subject_keys
         WHEN NEW.version = 2 BEGIN SELECT RAISE(ABORT, 'fixture rejected key'); END;"
    ).unwrap();
    let proof = ("user:1", 1);
    assert!(receiver.first.merge_wrapped_version("user:1", 2, &capsule, Some(proof), 300).is_err());
    assert_eq!(receiver.first.stats().unwrap(), before);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert!(receiver.first.erasures().unwrap().is_empty());
    assert_eq!(receiver.a.open(&old).bytes(), Some(b"cached-value".as_slice()));
    assert!(matches!(receiver.first.key("user:1", 2).unwrap(), KeyLookup::Missing));
}

#[test]
fn wrapped_export_key_and_floor_stay_in_one_snapshot_during_a_concurrent_erasure() {
    let source = Pair::new();
    warm(&source);
    let erased = Arc::new(AtomicBool::new(false));
    let observed = erased.clone();
    let writer = source.second.clone();
    source.first.conn().authorizer(Some(move |context: AuthContext<'_>| {
        if matches!(context.action, AuthAction::Read { table_name: "subject_keys", .. })
            && !observed.swap(true, Ordering::SeqCst)
        { writer.erase_through("user:1", 1, 2).unwrap(); }
        Authorization::Allow
    })).unwrap();
    let before = source.first.export_wrapped_version("user:1", 1).unwrap();
    source.first.conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>).unwrap();
    assert!(erased.load(Ordering::SeqCst));
    assert!(before.key.is_some());
    assert!(before.erasure.is_none());
    let after = source.first.export_wrapped_version("user:1", 1).unwrap();
    assert!(after.key.is_none());
    assert_eq!(after.erasure, Some(SubjectErasure { last_version: 1, erased_wall_ms: 2 }));
}

#[test]
fn wrapped_import_cannot_bypass_checked_semantic_revision_overflow() {
    let source = Pair::new();
    warm(&source);
    let capsule = source.first.export_wrapped_version("user:1", 1).unwrap();
    let receiver = Pair::new();
    receiver.first.conn().execute("UPDATE keystore_revision SET revision = ?1", [i64::MAX]).unwrap();
    assert!(receiver.first.merge_wrapped_version("user:1", 1, &capsule, None, 100).is_err());
    assert_eq!(receiver.first.stats().unwrap().keys, 0);
    assert_eq!(receiver.first.revision().unwrap(), i64::MAX as u64);
    let kind: String = receiver.first.conn().query_row("SELECT typeof(revision) FROM keystore_revision", [], |row| row.get(0)).unwrap();
    assert_eq!(kind, "integer");
}

#[test]
fn wrapped_merge_never_reads_or_unwraps_a_covered_original_key() {
    for already_erased in [false, true] {
        let source = Pair::new();
        warm(&source);
        let mut capsule = source.first.export_wrapped_version("user:1", 1).unwrap();
        capsule.key.as_mut().unwrap().wrapped = [0; 48];
        let receiver = Pair::new();
        let original = warm(&receiver);
        receiver.first.conn().execute(
            "UPDATE subject_keys SET wrapped = zeroblob(48) WHERE subject = 'user:1' AND version = 1", [],
        ).unwrap();
        if already_erased { receiver.first.erase_through("user:1", 1, 2).unwrap(); }
        receiver.first.conn().authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Read {
                table_name: "subject_keys", column_name: "nonce" | "wrapped",
            }) {
                Authorization::Deny
            } else { Authorization::Allow }
        })).unwrap();
        let proof = if already_erased { None } else { Some(("user:1", 1)) };
        let result = receiver.first.merge_wrapped_version("user:1", 1, &capsule, proof, 3);
        receiver.first.conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>).unwrap();
        assert_eq!(result.unwrap(), WrappedVersionStatus::Erased);
        assert_eq!(receiver.first.stats().unwrap().keys, 0);
        assert_eq!(receiver.first.erasure_floor_at_revision("user:1").unwrap().1, Some(1));
        assert!(matches!(receiver.a.open(&original), Opened::Erased { .. }));
    }
}
