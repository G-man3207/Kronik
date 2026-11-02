use super::*;
use crate::sealer::Sealer;
use kronik_proto::log::v1 as pb;

const SUBJECT: &str = "oidc:1111111111111111111111111111111111111111111111111111111111111111";

fn fixture(root: &std::path::Path) -> (Arc<Keystore>, Sealer) {
    let owner = crate::key_source::lock_data(root).unwrap();
    let master = MasterKey::from_bytes([41; 32]).unwrap();
    let ks = Keystore::open_owned(&owner, &master).unwrap();
    let sealer = Sealer::new(ks.clone());
    (ks, sealer)
}
fn plain() -> pb::Sealable {
    pb::Sealable {
        subject: Some(SUBJECT.into()),
        value: Some(pb::sealable::Value::Plain(
            br#"{"issuer":"https://issuer.test","subject":"verified-user"}"#.to_vec(),
        )),
    }
}
fn prepare(sealer: &Sealer, floor: Option<u32>) -> PreparedSubjectKey {
    sealer
        .prepare_plain_source_holder(SUBJECT, floor, &|bytes| bytes.fill(7), 10)
        .unwrap()
}
fn found(key: KeyLookup) -> SubjectKey {
    match key {
        KeyLookup::Found(key) => key,
        other => panic!("expected a real key, got {other:?}"),
    }
}
fn replace(conn: &Connection, envelope: &WrappedSubjectKey) {
    assert_eq!(conn.execute(
        "UPDATE subject_keys SET nonce = ?1, wrapped = ?2, created_wall_ms = ?3 WHERE subject = ?4 AND version = 1",
        params![envelope.nonce.as_slice(), envelope.wrapped.as_slice(), i64::try_from(envelope.created_wall_ms).unwrap(), SUBJECT],
    ).unwrap(), 1);
}
fn sqlite_busy(error: rusqlite::Error) {
    assert!(matches!(error, rusqlite::Error::SqliteFailure(error, _)
        if matches!(error.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)));
}

#[test]
fn fixed_holder_seals_the_prepared_key_off_and_on_after_rotation() {
    for on in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (ks, sealer) = fixture(dir.path());
        sealer.set_on(on);
        let prepared = prepare(&sealer, None);
        assert_eq!(prepared.version(), 1);
        assert_eq!(ks.rotate(SUBJECT, [9; 32], [9; 24], 20).unwrap(), 2);
        let before = ks.revision().unwrap();
        let value = sealer
            .seal_value_with_prepared(plain(), &prepared, &|bytes| bytes.fill(5), |value| value)
            .unwrap();
        let Some(pb::sealable::Value::Sealed(sealed)) = &value.value else {
            panic!("verified identity was not encrypted");
        };
        assert_eq!(sealed.key_version, 1);
        assert_eq!(
            sealer.open(&value).bytes(),
            Some(br#"{"issuer":"https://issuer.test","subject":"verified-user"}"#.as_slice())
        );
        assert_eq!(ks.revision().unwrap(), before);
        assert_eq!(found(ks.key(SUBJECT, 2).unwrap()).version, 2);
    }
}

#[test]
fn another_sqlite_handle_cannot_write_during_crypto_or_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/keystore.db");
    let (ks, sealer) = fixture(dir.path());
    let prepared = prepare(&sealer, None);
    let other = Connection::open(&path).unwrap();
    other.busy_timeout(std::time::Duration::ZERO).unwrap();
    let before = ks.revision().unwrap();
    let value = sealer
        .seal_value_with_prepared(
            plain(),
            &prepared,
            &|bytes| {
                sqlite_busy(
                    other
                        .execute("DELETE FROM subject_keys WHERE subject = ?1", [SUBJECT])
                        .unwrap_err(),
                );
                bytes.fill(5);
            },
            |value| {
                sqlite_busy(
                    other
                        .execute(
                            "UPDATE subject_keys SET wrapped = zeroblob(48) WHERE subject = ?1",
                            [SUBJECT],
                        )
                        .unwrap_err(),
                );
                value
            },
        )
        .unwrap();
    assert!(matches!(value.value, Some(pb::sealable::Value::Sealed(_))));
    assert_eq!(ks.revision().unwrap(), before);
    // The real write can proceed only after the synchronous callback returned.
    assert_eq!(
        other
            .execute("DELETE FROM subject_keys WHERE subject = ?1", [SUBJECT])
            .unwrap(),
        1
    );
    assert!(ks.with_current_prepared(&prepared, || ()).is_err());
}

#[test]
fn valid_same_version_replacement_cannot_retarget_the_actual_prepared_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/keystore.db");
    let (ks, sealer) = fixture(dir.path());
    let prepared = prepare(&sealer, None);
    let actual = prepared.envelope.clone();
    let master = MasterKey::from_bytes([41; 32]).unwrap();
    let foreign = Keystore::open_memory(&master).unwrap();
    let replacement_key = foreign
        .key_for_sealing(SUBJECT, [19; 32], [19; 24], 30)
        .unwrap();
    let replacement = foreign
        .export_wrapped_version(SUBJECT, 1)
        .unwrap()
        .key
        .unwrap();
    let other = Connection::open(&path).unwrap();
    replace(&other, &replacement);
    let installed = found(ks.key(SUBJECT, 1).unwrap());
    assert_eq!(
        *installed.key, *replacement_key.key,
        "replacement is a valid authenticated same-version key"
    );
    let before = ks.revision().unwrap();
    assert!(
        sealer
            .seal_value_with_prepared(
                plain(),
                &prepared,
                &|_| panic!("nonce requested for a replaced key"),
                |_| { panic!("a replaced key reached publication") }
            )
            .is_err()
    );
    assert_eq!(ks.revision().unwrap(), before);
    // An A→B→A history never causes sealing under B: the actual captured A key
    // is used, and the SQLite guard excludes another swap through publication.
    replace(&other, &actual);
    let value = sealer
        .seal_value_with_prepared(plain(), &prepared, &|bytes| bytes.fill(5), |value| value)
        .unwrap();
    let Some(pb::sealable::Value::Sealed(value)) = value.value else {
        panic!("not sealed");
    };
    let sealed = SealedValue {
        key_version: value.key_version,
        nonce: value.nonce.try_into().unwrap(),
        ciphertext: value.ciphertext,
    };
    assert!(unseal(SUBJECT, &prepared.key, &sealed).is_ok());
    assert!(unseal(SUBJECT, &replacement_key, &sealed).is_err());
}

#[test]
fn even_a_valid_same_key_rewrap_changes_the_prepared_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/keystore.db");
    let (ks, sealer) = fixture(dir.path());
    let prepared = prepare(&sealer, None);
    let master = MasterKey::from_bytes([41; 32]).unwrap();
    let foreign = Keystore::open_memory(&master).unwrap();
    foreign
        .key_for_sealing(SUBJECT, *prepared.key.key, [29; 24], 30)
        .unwrap();
    let rewrapped = foreign
        .export_wrapped_version(SUBJECT, 1)
        .unwrap()
        .key
        .unwrap();
    assert_ne!(rewrapped, prepared.envelope);
    replace(&Connection::open(&path).unwrap(), &rewrapped);
    assert_eq!(*found(ks.key(SUBJECT, 1).unwrap()).key, *prepared.key.key);
    assert!(ks.with_current_prepared(&prepared, || ()).is_err());
}

#[test]
fn actual_erasure_and_the_real_zero_floor_invalidate_the_original_holder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys/keystore.db");
    let (ks, sealer) = fixture(dir.path());
    let before_floor = prepare(&sealer, None);
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, 0, 20)",
            [SUBJECT],
        )
        .unwrap();
    assert!(ks.with_current_prepared(&before_floor, || ()).is_err());
    assert!(
        sealer
            .prepare_plain_source_holder(SUBJECT, None, &|bytes| bytes.fill(8), 21)
            .is_err()
    );
    let zero_floor = prepare(&sealer, Some(0));
    assert_eq!(zero_floor.version(), 1);
    assert_eq!(ks.erase(SUBJECT, 30).unwrap(), 1);
    assert!(ks.with_current_prepared(&zero_floor, || ()).is_err());
    assert!(
        sealer
            .seal_value_with_prepared(
                plain(),
                &zero_floor,
                &|_| panic!("nonce requested for erased key"),
                |_| { panic!("erased key reached publication") }
            )
            .is_err()
    );
    // Only a separately admitted fresh assertion may prepare at this new floor.
    let fresh = prepare(&sealer, Some(1));
    assert_eq!(fresh.version(), 2);
    let protected = sealer
        .seal_value_with_prepared(plain(), &fresh, &|bytes| bytes.fill(6), |value| value)
        .unwrap();
    assert!(matches!(
        protected.value,
        Some(pb::sealable::Value::Sealed(_))
    ));
    assert!(ks.with_current_prepared(&before_floor, || ()).is_err());
}

#[test]
fn another_arc_of_the_same_physical_store_cannot_substitute_for_the_original() {
    let dir = tempfile::tempdir().unwrap();
    let (ks, sealer) = fixture(dir.path());
    let prepared = prepare(&sealer, None);
    let other = ks.reopen_owned().unwrap();
    let other_sealer = Sealer::new(other.clone());
    assert_eq!(
        other.export_wrapped_version(SUBJECT, 1).unwrap(),
        ks.export_wrapped_version(SUBJECT, 1).unwrap()
    );
    assert!(other.with_current_prepared(&prepared, || ()).is_err());
    assert!(
        other_sealer
            .seal_value_with_prepared(
                plain(),
                &prepared,
                &|_| panic!("nonce requested for foreign store"),
                |_| { panic!("foreign store reached publication") }
            )
            .is_err()
    );
    drop(sealer);
    drop(ks);
    assert!(prepared.store.upgrade().is_none());
    assert!(other.with_current_prepared(&prepared, || ()).is_err());
}

#[test]
fn deleted_corrupt_or_missing_original_store_denies_before_crypto_and_publication() {
    for fault in ["delete", "ciphertext", "master", "missing_path"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/keystore.db");
        let moved = dir.path().join("moved-keys");
        let (_ks, sealer) = fixture(dir.path());
        let prepared = prepare(&sealer, None);
        let other = Connection::open(&path).unwrap();
        let revision = || {
            other
                .query_row(
                    "SELECT revision FROM keystore_revision WHERE id = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };
        // A failed seal must publish nothing, so the baseline is the revision
        // the fault itself leaves behind. Moving the store directory strands its
        // WAL sidecars under the old names, so for the missing-path case that
        // baseline has to be taken before the move.
        let missing_baseline = (fault == "missing_path").then(revision);
        match fault {
            "delete" => {
                other
                    .execute("DELETE FROM subject_keys WHERE subject = ?1", [SUBJECT])
                    .unwrap();
            }
            "ciphertext" => {
                other
                    .execute(
                        "UPDATE subject_keys SET wrapped = zeroblob(48) WHERE subject = ?1",
                        [SUBJECT],
                    )
                    .unwrap();
            }
            "master" => {
                other
                    .execute("UPDATE key_check SET value = zeroblob(32) WHERE id = 1", [])
                    .unwrap();
            }
            // Deleting only the database file strands its WAL sidecars under the
            // old name, so even a fresh connection to the moved file cannot read
            // it. Moving the whole directory keeps the sidecars beside the
            // database: the original path is missing, and a witness can still
            // prove that nothing was published.
            "missing_path" => {
                std::fs::rename(dir.path().join("keys"), &moved).unwrap();
                assert!(!path.exists());
                assert!(!dir.path().join("keys").exists());
            }
            _ => unreachable!(),
        }
        let before = missing_baseline.unwrap_or_else(revision);
        assert!(
            sealer
                .seal_value_with_prepared(
                    plain(),
                    &prepared,
                    &|_| panic!("nonce requested for unavailable store"),
                    |_| { panic!("unavailable store reached publication") }
                )
                .is_err(),
            "{fault}"
        );
        let after = if fault == "missing_path" {
            Connection::open(moved.join("keystore.db"))
                .unwrap()
                .query_row(
                    "SELECT revision FROM keystore_revision WHERE id = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        } else {
            revision()
        };
        assert_eq!(after, before, "{fault}");
    }
}
