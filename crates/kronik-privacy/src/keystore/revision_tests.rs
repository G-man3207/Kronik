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
        a.set_on(true);
        b.set_on(true);
        Self {
            owner,
            path,
            master,
            first,
            second,
            a,
            b,
            entropy: AtomicU8::new(1),
            _dir: dir,
        }
    }
    fn fill(&self, bytes: &mut [u8]) {
        bytes.fill(self.entropy.fetch_add(1, Ordering::Relaxed));
    }
    fn seal(&self, sealer: &Sealer, bytes: &[u8]) -> pb::Sealable {
        let mut value = plain(bytes);
        sealer
            .seal_value(&mut value, &|bytes| self.fill(bytes), 1)
            .unwrap();
        value
    }
}
fn plain(bytes: &[u8]) -> pb::Sealable {
    pb::Sealable {
        subject: Some("user:1".into()),
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    }
}
fn version(value: &pb::Sealable) -> u32 {
    match value.value.as_ref().unwrap() {
        pb::sealable::Value::Sealed(value) => value.key_version,
        _ => panic!("value was not sealed"),
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    bytes: u64,
    modified: SystemTime,
}

// Freeze only this fixture's DB/WAL metadata, never the host clock. The old
// mtime/length heuristic sees exactly the same evidence before and after writes.
fn settled_stamps(path: &Path) -> [Stamp; 2] {
    let conn = Connection::open(path).unwrap();
    conn.busy_timeout(Duration::ZERO).unwrap();
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .unwrap();
    assert_eq!(busy, 0);
    drop(conn);
    fixed_stamps(path)
}
fn fixed_stamps(path: &Path) -> [Stamp; 2] {
    let fixed = UNIX_EPOCH + Duration::from_secs(1_000_000);
    [
        path.to_owned(),
        PathBuf::from(format!("{}-wal", path.display())),
    ]
    .map(|path| {
        let file = File::options().read(true).write(true).open(&path).unwrap();
        file.set_times(FileTimes::new().set_accessed(fixed).set_modified(fixed))
            .unwrap();
        let metadata = file.metadata().unwrap();
        Stamp {
            bytes: metadata.len(),
            modified: metadata.modified().unwrap(),
        }
    })
}
fn warm(pair: &Pair) -> pb::Sealable {
    let value = pair.seal(&pair.a, b"cached-value");
    assert_eq!(
        pair.b.open(&value).bytes(),
        Some(b"cached-value".as_slice())
    );
    assert_eq!(version(&pair.seal(&pair.b, b"also-cached")), 1);
    value
}

#[test]
fn two_stores_and_two_sealers_observe_rotation_with_identical_db_and_wal_metadata() {
    let pair = Pair::new();
    let old = warm(&pair);
    let identity = pair
        .a
        .keyed_hash("kronik audit record v3", &[b"canonical metadata"])
        .unwrap();
    let before = settled_stamps(&pair.path);
    let revision = pair.first.revision().unwrap();
    assert_eq!(
        pair.second.rotate("user:1", [9; 32], [10; 24], 2).unwrap(),
        2
    );
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(pair.first.revision().unwrap() > revision);
    assert_eq!(
        pair.first.revision().unwrap(),
        pair.second.revision().unwrap()
    );
    let mut resealed = plain(b"resealed-current");
    assert_eq!(
        pair.a
            .reseal_value(&mut resealed, None, &|bytes| pair.fill(bytes), 3)
            .unwrap(),
        ResealOp::Sealed
    );
    assert_eq!(version(&resealed), 2);
    assert_eq!(version(&pair.seal(&pair.b, b"rotated")), 2);
    assert_eq!(pair.a.open(&old).bytes(), Some(b"cached-value".as_slice()));
    assert_eq!(
        pair.b.open(&resealed).bytes(),
        Some(b"resealed-current".as_slice())
    );
    assert_eq!(
        pair.a
            .keyed_hash("kronik audit record v3", &[b"canonical metadata"]),
        Some(identity)
    );
}

#[test]
fn erase_through_an_independent_store_revokes_both_warm_caches_with_equal_metadata() {
    let pair = Pair::new();
    let old = warm(&pair);
    let identity = pair
        .a
        .keyed_hash("kronik audit record v3", &[b"canonical metadata"]);
    let before = settled_stamps(&pair.path);
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.second.erase("user:1", 2).unwrap(), 1);
    assert_eq!(settled_stamps(&pair.path), before);
    assert!(pair.first.revision().unwrap() > revision);
    assert!(matches!(pair.a.open(&old), Opened::Erased { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Erased { .. }));
    assert_eq!(version(&pair.seal(&pair.a, b"new subject epoch")), 2);
    assert!(matches!(pair.b.open(&old), Opened::Erased { .. }));
    assert_eq!(
        pair.a
            .keyed_hash("kronik audit record v3", &[b"canonical metadata"]),
        identity
    );
}

#[test]
fn own_connection_mutations_invalidate_other_sealers_even_when_data_version_is_unchanged() {
    let pair = Pair::new();
    let other = Sealer::new(pair.first.clone());
    other.set_on(true);
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
    assert_eq!(
        pair.a.open(&newer).bytes(),
        Some(b"newer version".as_slice())
    );
    let revision = pair.first.revision().unwrap();
    pair.second.erase_through("user:1", 1, 4).unwrap();
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(version(&pair.seal(&pair.b, b"still version two")), 2);
}

#[test]
fn revision_read_failure_refuses_both_cached_opening_and_cached_sealing() {
    let pair = Pair::new();
    let old = warm(&pair);
    Connection::open(&pair.path)
        .unwrap()
        .execute_batch("DROP TABLE keystore_revision")
        .unwrap();
    assert!(pair.first.revision().is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Unreadable { .. }));
    let mut value = plain(b"must remain uncommitted");
    assert!(
        pair.a
            .seal_value(
                &mut value,
                &|_| panic!("cannot allocate a nonce after revision failure"),
                3
            )
            .is_err()
    );
    assert!(
        pair.b
            .seal_value(
                &mut value,
                &|_| panic!("cannot allocate a nonce after revision failure"),
                3
            )
            .is_err()
    );
    assert!(pair.a.erase("user:1", 4).is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
}

#[test]
fn revision_overflow_aborts_the_whole_key_mutation_without_real_promotion() {
    let pair = Pair::new();
    warm(&pair);
    let conn = Connection::open(&pair.path).unwrap();
    conn.execute(
        "UPDATE keystore_revision SET revision = ?1 WHERE id = 1",
        [i64::MAX],
    )
    .unwrap();
    assert!(pair.second.rotate("user:1", [31; 32], [32; 24], 2).is_err());
    assert_eq!(pair.second.stats().unwrap().keys, 1);
    assert!(pair.a.erase("user:1", 3).is_err());
    assert_eq!(pair.first.stats().unwrap().keys, 1);
    let stored: (String, i64) = conn
        .query_row(
            "SELECT typeof(revision), revision FROM keystore_revision",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
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
    new.key_for_sealing("user:1", [41; 32], [42; 24], 1)
        .unwrap();
    assert_eq!(new.revision().unwrap(), pair.first.revision().unwrap());
    drop(new);
    let before = settled_stamps(&pair.path);
    std::fs::rename(&replacement, &pair.path).unwrap();
    assert_eq!(fixed_stamps(&pair.path), before);
    assert!(pair.first.revision().is_err());
    assert!(matches!(pair.a.open(&old), Opened::Unreadable { .. }));
    assert!(matches!(pair.b.open(&old), Opened::Unreadable { .. }));
    let mut value = plain(b"cannot use disconnected database");
    assert!(
        pair.a
            .seal_value(
                &mut value,
                &|_| panic!("replaced handle must not use cached keys"),
                2
            )
            .is_err()
    );
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
    pair.first
        .conn()
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Read {
                    table_name: "keystore_revision",
                    ..
                }
            ) && !observed.swap(true, Ordering::SeqCst)
            {
                writer.rotate("user:1", [51; 32], [52; 24], 2).unwrap();
            }
            Authorization::Allow
        }))
        .unwrap();
    let (stamp, key) = pair
        .first
        .sealing_key_at_revision("user:1", [53; 32], [54; 24], 3)
        .unwrap();
    pair.first
        .conn()
        .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
        .unwrap();
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
    store
        .key_for_sealing("user:1", [61; 32], [62; 24], 1)
        .unwrap();
    let backup = store.export_backup([63; 24]).unwrap();
    drop(store);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "DROP TRIGGER subject_keys_revision_insert; DROP TRIGGER subject_keys_revision_update;
         DROP TRIGGER subject_keys_revision_delete; DROP TRIGGER erasures_revision_insert;
         DROP TRIGGER erasures_revision_update; DROP TRIGGER erasures_revision_delete;
         DROP TABLE keystore_revision;",
        )
        .unwrap();
    let migrated = Keystore::open_owned(&owner, &master).unwrap();
    assert_eq!(migrated.revision().unwrap(), 0);
    assert!(matches!(
        migrated.key("user:1", 1).unwrap(),
        KeyLookup::Found(_)
    ));
    assert_eq!(migrated.export_backup([63; 24]).unwrap(), backup);
    let revision = migrated.revision().unwrap();
    migrated.rotate("user:1", [64; 32], [65; 24], 2).unwrap();
    assert!(migrated.revision().unwrap() > revision);
}

/// Stages `backup` under `pair`'s owner and installs it the way `kronik
/// restore` does: checkpoint and close the stage, rename it into `keys/`,
/// then finish the restore on the installed file.
fn install_backup(pair: &Pair, backup: &[u8]) -> Arc<Keystore> {
    let restore = pair.owner.begin_keystore_restore().unwrap();
    let staged =
        Keystore::restore_staged(&restore, Path::new(".restore"), &pair.master, backup).unwrap();
    let revision = staged.revision().unwrap();
    restore.close_stage(staged).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let from = pair
            ._dir
            .path()
            .join(format!(".restore/keystore.db{suffix}"));
        let to = pair._dir.path().join(format!("keys/keystore.db{suffix}"));
        if from.exists() {
            std::fs::rename(from, to).unwrap();
        } else if to.exists() {
            std::fs::remove_file(to).unwrap();
        }
    }
    let installed = restore.finish(Some(&pair.master)).unwrap().unwrap();
    assert_eq!(installed.revision().unwrap(), revision);
    installed
}

#[test]
fn even_an_empty_backup_install_advances_the_staged_revision_and_checkpoints_do_not() {
    let pair = Pair::new();
    let backup = pair.first.export_backup([71; 24]).unwrap();
    let before = pair.first.revision().unwrap();
    let installed = install_backup(&pair, &backup);
    let revision = installed.revision().unwrap();
    assert!(revision > before);
    settled_stamps(&pair.path);
    assert_eq!(installed.revision().unwrap(), revision);
}

#[test]
fn maximum_subject_key_is_usable_but_rotation_never_wraps_or_creates_a_key() {
    let pair = Pair::new();
    {
        let conn = pair.first.conn();
        pair.first
            .insert_key(&conn, "user:1", u32::MAX, &[91; 32], [92; 24], 1)
            .unwrap();
    }
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert_eq!(
        pair.first
            .key_for_sealing("user:1", [93; 32], [94; 24], 2)
            .unwrap()
            .version,
        u32::MAX
    );
    let value = pair.seal(&pair.a, b"last valid key");
    assert_eq!(version(&value), u32::MAX);
    assert_eq!(
        pair.b.open(&value).bytes(),
        Some(b"last valid key".as_slice())
    );
    assert!(
        matches!(pair.second.rotate("user:1", [95; 32], [96; 24], 3),
        Err(PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(_, next)))
            if next == i64::from(u32::MAX) + 1)
    );
    assert!(pair.first.key("user:1", 0).is_err());
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(
        pair.a.open(&value).bytes(),
        Some(b"last valid key".as_slice())
    );
}

#[test]
fn maximum_erased_floor_refuses_key_creation_and_rotation_without_mutating_rows() {
    let pair = Pair::new();
    pair.second.erase_through("user:1", u32::MAX, 1).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert!(
        matches!(pair.first.key_for_sealing("user:1", [101; 32], [102; 24], 2),
        Err(PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(_, next)))
            if next == i64::from(u32::MAX) + 1)
    );
    assert!(
        pair.second
            .rotate("user:1", [103; 32], [104; 24], 3)
            .is_err()
    );
    let mut value = plain(b"cannot allocate a zero or wrapped version");
    let original = value.clone();
    assert!(
        pair.a
            .seal_value(&mut value, &|bytes| pair.fill(bytes), 4)
            .is_err()
    );
    assert_eq!(value, original);
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
        assert!(
            pair.first
                .key_for_sealing("user:1", [113; 32], [114; 24], 2)
                .is_err()
        );
        assert!(
            pair.second
                .rotate("user:1", [115; 32], [116; 24], 3)
                .is_err()
        );
        assert!(pair.second.erase("user:1", 4).is_err());
        assert!(pair.first.export_backup([117; 24]).is_err());
        assert_eq!(pair.first.stats().unwrap(), before);
        assert_eq!(pair.first.revision().unwrap(), revision);
    }
}
