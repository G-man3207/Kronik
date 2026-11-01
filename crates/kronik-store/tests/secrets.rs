//! Durable secret publication and allocator recovery from committed records.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_log::{Committed, Position};
use kronik_proto::log::v1::secret_version::Phase;
use kronik_proto::{Record, log::v1 as pb};
use kronik_store::{StateDb, Store, StoreError};
use rusqlite::Connection;

fn audit() -> Option<pb::Audit> {
    Some(pb::Audit {
        token_id: "system".into(),
        reason: "legacy import".into(),
        wall_time_ms: 1,
    })
}

fn version(name: &str, v: u64, phase: Phase) -> pb::SecretVersion {
    pb::SecretVersion {
        name: name.into(),
        version: v,
        version_hash: vec![0x55; 16],
        backend: "file".into(),
        source_version: v.to_string(),
        audit: audit(),
        r#ref: name.into(),
        binding: "file".into(),
        canonical_ref: name.into(),
        phase: phase as i32,
        hash_revision: if v <= u32::MAX as u64 { 1 } else { 2 },
        ..Default::default()
    }
}

fn fence(floor: u64) -> Record {
    Record::SecretVersion(pb::SecretVersion {
        version: floor,
        phase: Phase::Fence as i32,
        audit: audit(),
        ..Default::default()
    })
}

fn link(generation: u64, epoch: u64) -> pb::SecretLink {
    pb::SecretLink {
        name: "key".into(),
        backend: "vault".into(),
        r#ref: "kv/key".into(),
        audit: audit(),
        binding: "trusted".into(),
        generation,
        epoch,
        canonical_ref: "kv/data/key".into(),
    }
}

fn external(v: u64, generation: u64, phase: Phase) -> pb::SecretVersion {
    pb::SecretVersion {
        backend: "vault".into(),
        r#ref: "kv/key".into(),
        binding: "trusted".into(),
        canonical_ref: "kv/data/key".into(),
        link_generation: generation,
        source_version: "provider-version-1".into(),
        ..version("key", v, phase)
    }
}

fn committed(lsn: u64, record: Record) -> Committed {
    // Exercise the durable wire boundary, not just in-memory constructors.
    let record = Record::decode(record.kind(), &record.encode()).unwrap();
    Committed {
        lsn,
        pos: Position {
            segment: 1,
            offset: lsn * 128,
        },
        record,
    }
}

fn apply(db: &mut StateDb, record: Record) -> Result<(), StoreError> {
    let lsn = db.applied_lsn()? + 1;
    db.apply(&[committed(lsn, record)])
}

fn memory() -> StateDb {
    StateDb::open(Connection::open_in_memory().unwrap()).unwrap()
}

fn current(db: &StateDb, name: &str) -> Option<pb::SecretVersion> {
    db.secret_versions(Some(name))
        .unwrap()
        .into_iter()
        .filter(|v| v.phase == Phase::Active as i32)
        .max_by_key(|v| v.version)
        .filter(|v| !v.deleted)
}

#[test]
fn crash_pending_and_failed_reservations_consume_numbers_without_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let mut db = StateDb::open(Connection::open(&path).unwrap()).unwrap();
    assert_eq!(db.secret_format_floor().unwrap(), None);
    apply(&mut db, fence(0)).unwrap();
    assert_eq!(db.secret_format_floor().unwrap(), Some(0));
    let mut first = version("key", 1, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(first.clone())).unwrap();
    assert!(current(&db, "key").is_none());
    first.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(first.clone())).unwrap();
    let mut pending = version("key", 2, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(pending.clone())).unwrap();
    drop(db);
    let mut db = StateDb::open(Connection::open(&path).unwrap()).unwrap();
    assert_eq!(db.secret_highwater("key").unwrap(), 2);
    assert_eq!(current(&db, "key"), Some(first.clone()));
    pending.phase = Phase::Failed as i32;
    apply(&mut db, Record::SecretVersion(pending.clone())).unwrap();
    assert_eq!(db.secret_highwater("key").unwrap(), 2);
    assert_eq!(current(&db, "key"), Some(first));
    let mut attempted_reuse = pending.clone();
    attempted_reuse.phase = Phase::Reserved as i32;
    assert!(apply(&mut db, Record::SecretVersion(attempted_reuse)).is_err());
    let mut deletion = version("key", 3, Phase::Reserved);
    deletion.deleted = true;
    deletion.version_hash.clear();
    apply(&mut db, Record::SecretVersion(deletion.clone())).unwrap();
    assert_eq!(current(&db, "key").unwrap().version, 1);
    deletion.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(deletion)).unwrap();
    assert!(current(&db, "key").is_none());
    assert_eq!(db.secret_versions(Some("key")).unwrap().len(), 3);
}

#[test]
fn exact_phase_replay_is_idempotent_but_identity_and_audit_changes_are_corrupt() {
    let mut db = memory();
    apply(&mut db, fence(0)).unwrap();
    let reserved = version("key", 1, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(reserved.clone())).unwrap();
    apply(&mut db, Record::SecretVersion(reserved.clone())).unwrap();
    for change in 0..6 {
        let mut bad = reserved.clone();
        bad.phase = Phase::Active as i32;
        match change {
            0 => bad.version_hash[0] ^= 1,
            1 => bad.source_version = "2".into(),
            2 => {
                bad.r#ref = "other".into();
                bad.canonical_ref = "other".into();
            }
            3 => bad.link_generation = 1,
            4 => bad.audit.as_mut().unwrap().reason = "changed".into(),
            _ => bad.deleted = true,
        }
        // Invalid wire provenance also fails at the direct apply trust boundary.
        let next = db.applied_lsn().unwrap() + 1;
        assert!(
            db.apply(&[Committed {
                lsn: next,
                pos: Position {
                    segment: 1,
                    offset: next
                },
                record: Record::SecretVersion(bad),
            }])
            .is_err()
        );
        assert_eq!(
            db.secret_versions(Some("key")).unwrap(),
            vec![reserved.clone()]
        );
    }
    let mut active = reserved.clone();
    active.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(active.clone())).unwrap();
    apply(&mut db, Record::SecretVersion(active.clone())).unwrap();
    assert_eq!(db.secret_versions(None).unwrap(), vec![active.clone()]);
    assert!(apply(&mut db, Record::SecretVersion(reserved)).is_err());
    active.phase = Phase::Failed as i32;
    assert!(apply(&mut db, Record::SecretVersion(active)).is_err());
}

#[test]
fn legacy_fence_preserves_known_max_value_and_floors_unknown_names() {
    let mut db = memory();
    let max = version("key", 4_294_967_295, Phase::Active);
    apply(&mut db, Record::SecretVersion(max.clone())).unwrap();
    assert!(apply(&mut db, fence(0)).is_err());
    let migrated = fence(4_294_967_295);
    apply(&mut db, migrated.clone()).unwrap();
    apply(&mut db, migrated).unwrap();
    assert_eq!(current(&db, "key"), Some(max));
    assert_eq!(db.secret_highwater("key").unwrap(), 4_294_967_295);
    assert_eq!(
        db.secret_highwater("lost-legacy-name").unwrap(),
        4_294_967_295
    );
    assert!(
        apply(
            &mut db,
            Record::SecretVersion(version("new", 1, Phase::Reserved))
        )
        .is_err()
    );
    let wide = version("new", 4_294_967_296, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(wide)).unwrap();
    assert_eq!(db.secret_highwater("new").unwrap(), 4_294_967_296);
    assert_eq!(db.secret_versions(None).unwrap().len(), 2);
    assert!(apply(&mut db, fence(0)).is_err());
    let mut unaudited_import = version("not-import", 1, Phase::Active);
    unaudited_import.audit.as_mut().unwrap().token_id = "admin".into();
    assert!(apply(&mut db, Record::SecretVersion(unaudited_import)).is_err());
    let mut false_source = version("not-import", 1, Phase::Active);
    false_source.source_version = "2".into();
    assert!(apply(&mut db, Record::SecretVersion(false_source)).is_err());
    assert!(
        apply(
            &mut db,
            Record::SecretVersion(version("wide", 4_294_967_296, Phase::Active))
        )
        .is_err()
    );
}

#[test]
fn links_are_configuration_barriers_with_monotone_history_and_bound_provenance() {
    let mut db = memory();
    assert!(apply(&mut db, Record::SecretLink(link(1, 1))).is_err());
    apply(&mut db, fence(0)).unwrap();
    let first = link(1, 1);
    apply(&mut db, Record::SecretLink(first.clone())).unwrap();
    apply(&mut db, Record::SecretLink(first.clone())).unwrap();
    assert_eq!(db.config_epoch().unwrap(), 1);
    assert_eq!(
        db.config_records().unwrap(),
        vec![Record::SecretLink(first.clone())]
    );
    for bad in [link(1, 2), link(2, 1)] {
        assert!(apply(&mut db, Record::SecretLink(bad)).is_err());
    }
    let reserved = external(1, 1, Phase::Reserved);
    for field in 0..4 {
        let mut bad = reserved.clone();
        match field {
            0 => bad.binding = "other".into(),
            1 => bad.r#ref = "kv/other".into(),
            2 => bad.canonical_ref = "kv/data/other".into(),
            _ => bad.link_generation = 2,
        }
        assert!(apply(&mut db, Record::SecretVersion(bad)).is_err());
    }
    apply(&mut db, Record::SecretVersion(reserved.clone())).unwrap();
    for field in 0..6 {
        let mut changed = reserved.clone();
        changed.phase = Phase::Active as i32;
        match field {
            0 => changed.version_hash[0] ^= 1,
            1 => changed.source_version = "another-version".into(),
            2 => changed.r#ref = "kv/other".into(),
            3 => changed.canonical_ref = "kv/data/other".into(),
            4 => changed.binding = "other".into(),
            _ => changed.link_generation = 2,
        }
        assert!(apply(&mut db, Record::SecretVersion(changed)).is_err());
    }
    let unlink = pb::SecretLink {
        name: "key".into(),
        generation: 2,
        epoch: 2,
        audit: audit(),
        ..Default::default()
    };
    apply(&mut db, Record::SecretLink(unlink.clone())).unwrap();
    let mut admitted = reserved;
    admitted.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(admitted)).unwrap();
    let mut file = version("key", 2, Phase::Reserved);
    file.source_version = "1".into();
    file.link_generation = 2;
    apply(&mut db, Record::SecretVersion(file.clone())).unwrap();
    file.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(file.clone())).unwrap();
    assert_eq!(current(&db, "key"), Some(file));
    assert_eq!(db.secret_link("key").unwrap(), Some(unlink.clone()));
    assert_eq!(db.secret_links().unwrap(), vec![unlink]);
    assert_eq!(db.config_records().unwrap().len(), 2);
    assert_eq!(db.config_record_lsns().unwrap(), vec![(1, 2), (2, 5)]);
    let relink = link(3, 3);
    apply(&mut db, Record::SecretLink(relink)).unwrap();
    assert_eq!(db.config_epoch().unwrap(), 3);
    assert!(apply(&mut db, Record::SecretLink(first)).is_err());
    let second_observation = external(3, 3, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(second_observation)).unwrap();
    assert_eq!(db.secret_versions(Some("key")).unwrap().len(), 3);
    // An old admission may finish after relink, but must retain its exact
    // historical identity rather than borrowing the replacement binding.
    let mut old_file = version("key", 4, Phase::Reserved);
    old_file.source_version = "1".into();
    old_file.link_generation = 2;
    apply(&mut db, Record::SecretVersion(old_file.clone())).unwrap();
    old_file.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(old_file)).unwrap();
    let mut old_external = external(5, 1, Phase::Reserved);
    for field in 0..2 {
        let mut wrong = old_external.clone();
        if field == 0 {
            wrong.binding = "replacement".into();
        } else {
            wrong.r#ref = "kv/replacement".into();
        }
        assert!(apply(&mut db, Record::SecretVersion(wrong)).is_err());
    }
    apply(&mut db, Record::SecretVersion(old_external.clone())).unwrap();
    old_external.phase = Phase::Active as i32;
    apply(&mut db, Record::SecretVersion(old_external)).unwrap();
    assert_eq!(db.secret_link("key").unwrap().unwrap().generation, 3);
}

#[test]
fn sqlite_snapshot_reopen_and_bulk_rebuild_preserve_ledger_and_state_hash() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::memory().unwrap();
    let mut active = version("old", 4_294_967_295, Phase::Active);
    active.deleted = true; // Retained legacy tombstone hashes are not rewritten.
    let reserved = external(4_294_967_296, 1, Phase::Reserved);
    let mut completed = reserved.clone();
    completed.phase = Phase::Active as i32;
    let records = vec![
        committed(1, Record::SecretVersion(active)),
        committed(2, fence(4_294_967_295)),
        committed(3, Record::SecretLink(link(1, 1))),
        committed(4, Record::SecretLink(link(3, 2))),
        committed(5, Record::SecretVersion(reserved)),
        committed(6, Record::SecretVersion(completed)),
    ];
    store.apply(&records[..5]).unwrap();
    let pending_hash = store.state_hash().unwrap();
    let snapshot_dir = dir.path().join("snapshot");
    let snapshot = store.snapshot_to(&snapshot_dir).unwrap();
    assert_eq!(snapshot.state_hash, pending_hash);
    let restored = Store::open_snapshot_in_memory(&snapshot_dir).unwrap();
    assert_eq!(restored.state_hash().unwrap(), pending_hash);
    restored.apply(&records[5..]).unwrap();
    store.apply(&records[5..]).unwrap();
    assert_ne!(store.state_hash().unwrap(), pending_hash);
    assert_eq!(restored.state_hash().unwrap(), store.state_hash().unwrap());
    let installed = dir.path().join("installed");
    kronik_store::snapshot::install(&snapshot_dir, &installed).unwrap();
    let mut reopened =
        StateDb::open(Connection::open(installed.join("state.db")).unwrap()).unwrap();
    assert_eq!(reopened.applied_lsn().unwrap(), 5);
    reopened.apply(&records[5..]).unwrap();
    let rebuilt = Store::memory().unwrap();
    rebuilt.db().begin_bulk_replay().unwrap();
    rebuilt.apply(&records).unwrap();
    rebuilt.db().end_bulk_replay().unwrap();
    assert_eq!(rebuilt.state_hash().unwrap(), store.state_hash().unwrap());
    assert_eq!(
        reopened.secret_versions(None).unwrap(),
        rebuilt.db().secret_versions(None).unwrap()
    );
    assert_eq!(
        reopened.secret_links().unwrap(),
        rebuilt.db().secret_links().unwrap()
    );
    assert_eq!(reopened.secret_format_floor().unwrap(), Some(4_294_967_295));
    assert_eq!(reopened.secret_highwater("unknown").unwrap(), 4_294_967_295);
    assert_eq!(reopened.secret_highwater("key").unwrap(), 4_294_967_296);
}

#[test]
fn previous_snapshot_schema_opens_without_claiming_a_format_or_value() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::memory().unwrap();
    let old_hash = store.state_hash().unwrap();
    store.snapshot_to(dir.path()).unwrap();
    let conn = Connection::open(dir.path().join("state.db")).unwrap();
    conn.execute_batch(
        "DROP TABLE secret_versions; DROP TABLE secret_highwater;
         DROP TABLE secret_format; DROP TABLE secret_links; DROP TABLE secret_link_history;",
    )
    .unwrap();
    drop(conn);
    let restored = Store::open_snapshot_in_memory(dir.path()).unwrap();
    assert_eq!(restored.state_hash().unwrap(), old_hash);
    assert_eq!(restored.db().secret_format_floor().unwrap(), None);
    assert!(restored.db().secret_versions(None).unwrap().is_empty());
    restored.apply(&[committed(1, fence(0))]).unwrap();
    assert_ne!(restored.state_hash().unwrap(), old_hash);
    assert_eq!(restored.db().secret_format_floor().unwrap(), Some(0));
    assert!(restored.db().secret_versions(None).unwrap().is_empty());
}

#[test]
fn range_ceiling_is_consumed_even_when_publication_fails() {
    let mut db = memory();
    apply(&mut db, fence(4_294_967_295)).unwrap();
    let mut ceiling = version("key", 9_007_199_254_740_991, Phase::Reserved);
    apply(&mut db, Record::SecretVersion(ceiling.clone())).unwrap();
    ceiling.phase = Phase::Failed as i32;
    apply(&mut db, Record::SecretVersion(ceiling)).unwrap();
    assert_eq!(db.secret_highwater("key").unwrap(), 9_007_199_254_740_991);
    assert!(current(&db, "key").is_none());
    assert!(
        apply(
            &mut db,
            Record::SecretVersion(version("key", 4_294_967_296, Phase::Reserved))
        )
        .is_err()
    );
}
