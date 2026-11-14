use super::*;
use crate::db::StateDb;
use kronik_log::{Committed, Position};
use rusqlite::Connection;

fn db() -> StateDb {
    StateDb::open(Connection::open_in_memory().unwrap()).unwrap()
}

fn at(lsn: Lsn, record: Record) -> Committed {
    Committed {
        lsn,
        pos: Position {
            segment: 1,
            offset: lsn * 100,
        },
        record,
    }
}

fn blob(n: u8, size: u64) -> pb::BlobRef {
    pb::BlobRef {
        hash: format!("b3:{}", format!("{n:02x}").repeat(32)),
        size,
        subject: None,
        key_version: 0,
    }
}

fn actor() -> Option<pb::ActorRef> {
    Some(pb::ActorRef {
        kind: "media".into(),
        key: "a".into(),
    })
}

/// An HTTP input with `body` as a blob, under `idempotency_key`.
fn http(body: Option<&pb::BlobRef>, idempotency_key: &str) -> Option<pb::Input> {
    Some(pb::Input {
        kind: Some(pb::input::Kind::Http(pb::HttpInput {
            method: "POST".into(),
            path: "/media/a/upload".into(),
            body: body.map(|r| pb::Body {
                value: Some(pb::body::Value::Blob(r.clone())),
            }),
            idempotency_key: idempotency_key.into(),
            request_hash: vec![1; 32],
            ..Default::default()
        })),
    })
}

/// A committed turn answering an HTTP response whose body is `answer`.
fn record(execution_id: &str, input: Option<pb::Input>, answer: Option<&pb::BlobRef>) -> Record {
    Record::TurnRecord(pb::TurnRecord {
        execution_id: execution_id.into(),
        actor: actor(),
        causal_key: Some(pb::CausalKey {
            root: execution_id.into(),
            path: vec![],
        }),
        input,
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                status: 200,
                body: answer.map(|r| pb::Body {
                    value: Some(pb::body::Value::Blob(r.clone())),
                }),
                ..Default::default()
            })),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn begin(execution_id: &str, input: Option<pb::Input>) -> Record {
    Record::TurnBegin(pb::TurnBegin {
        execution_id: execution_id.into(),
        actor: actor(),
        causal_key: Some(pb::CausalKey {
            root: execution_id.into(),
            path: vec![],
        }),
        input,
        ..Default::default()
    })
}

fn effect(execution_id: &str, ordinal: u32, blobs: Vec<pb::BlobRef>) -> Record {
    Record::EffectResult(pb::EffectResult {
        execution_id: execution_id.into(),
        effect: Some(pb::EffectRecord {
            ordinal,
            kind: "http.fetch".into(),
            blobs,
            ..Default::default()
        }),
    })
}

fn sources(db: &StateDb, hash: &str) -> Vec<(i64, String)> {
    db.blob_pins(hash)
        .unwrap()
        .into_iter()
        .map(|p| (p.source, p.owner))
        .collect()
}

/// Every reference of a committed record enters the index with its first
/// and last LSN; an open turn pins its input and its recorded effects until
/// its record; a saved idempotent response pins its body until its row is
/// gone; compaction then deletes the rows that nothing keeps below the
/// floor.
#[test]
fn the_index_follows_references_pins_and_the_floor() {
    let mut db = db();
    let (upload, fetched, answer) = (blob(1, 10 << 20), blob(2, 3 << 20), blob(3, 2 << 20));
    db.apply(&[
        at(1, begin("e1", http(Some(&upload), "k1"))),
        at(2, effect("e1", 0, vec![fetched.clone()])),
    ])
    .unwrap();
    // Open: the input and the effect are pinned.
    assert_eq!(
        sources(&db, &upload.hash),
        [(source::OPEN_TURN, "e1".into())]
    );
    assert_eq!(
        sources(&db, &fetched.hash),
        [(source::OPEN_EFFECT, "e1/0".into())]
    );
    let row = db.blob(&upload.hash).unwrap().unwrap();
    assert_eq!(
        (row.first_lsn, row.last_ref_lsn, row.size),
        (1, 1, 10 << 20)
    );

    // The record closes the turn and saves the response under its key.
    let mut done = record("e1", http(Some(&upload), "k1"), Some(&answer));
    if let Record::TurnRecord(t) = &mut done {
        t.effects.push(pb::EffectRecord {
            ordinal: 0,
            kind: "http.fetch".into(),
            blobs: vec![fetched.clone()],
            ..Default::default()
        });
    }
    db.apply(&[at(3, done)]).unwrap();
    assert!(sources(&db, &upload.hash).is_empty());
    assert!(sources(&db, &fetched.hash).is_empty());
    assert_eq!(
        sources(&db, &answer.hash),
        [(source::INGRESS_KEY, "media\u{1f}a\u{1f}k1".into())]
    );
    assert_eq!(db.blob(&upload.hash).unwrap().unwrap().last_ref_lsn, 3);
    assert_eq!(db.blob_totals().unwrap(), (3, 15 << 20));

    // The floor keeps every row the log still references.
    assert!(db.unrooted_blobs(3).unwrap().is_empty());
    let shard_of = |r: &pb::BlobRef| r.hash[3..5].to_owned();
    assert_eq!(
        db.rooted_blobs_in_shard(&shard_of(&upload), 3).unwrap(),
        std::slice::from_ref(&upload.hash)
    );
    // Past the floor only the saved response keeps its blob.
    assert!(
        db.rooted_blobs_in_shard(&shard_of(&upload), 4)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.rooted_blobs_in_shard(&shard_of(&answer), 4).unwrap(),
        std::slice::from_ref(&answer.hash)
    );
    assert_eq!(
        db.state_blob_roots().unwrap(),
        std::slice::from_ref(&answer.hash)
    );
    let unrooted = db.unrooted_blobs(4).unwrap();
    let mut expected = vec![upload.hash.clone(), fetched.hash.clone()];
    expected.sort();
    assert_eq!(unrooted, expected);
    assert_eq!(db.forget_blobs(&unrooted, 4).unwrap(), 2);
    assert!(db.blob(&upload.hash).unwrap().is_none());
    assert!(db.blob(&answer.hash).unwrap().is_some());
    // A row that a record referenced again meanwhile is not forgotten.
    assert_eq!(
        db.forget_blobs(std::slice::from_ref(&answer.hash), 4)
            .unwrap(),
        0
    );

    // The saved response expires: its pin goes, then its row.
    db.compact(4, 1).unwrap();
    assert_eq!(db.prune_blob_pins().unwrap(), 1);
    assert_eq!(
        db.unrooted_blobs(4).unwrap(),
        std::slice::from_ref(&answer.hash)
    );
    assert_eq!(
        db.forget_blobs(std::slice::from_ref(&answer.hash), 4)
            .unwrap(),
        1
    );
    assert_eq!(db.blob_totals().unwrap(), (0, 0));
}

/// One identity has one content: a reference whose size differs from the
/// row's is a damaged log, and nothing of its batch is applied.
#[test]
fn a_reference_with_other_metadata_is_storage_corrupt() {
    let mut db = db();
    let one = blob(7, 100);
    db.apply(&[at(1, record("e1", http(Some(&one), ""), None))])
        .unwrap();
    let other = pb::BlobRef { size: 101, ..one };
    let err = db
        .apply(&[at(2, record("e2", http(Some(&other), ""), None))])
        .unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    assert_eq!(db.applied_lsn().unwrap(), 1);
}

/// A blob of a subject erased through its key version before its first
/// reference is erased in the index: no root keeps it, and compaction
/// deletes the row.
#[test]
fn a_blob_of_an_erased_subject_is_marked_and_kept_by_nothing() {
    let mut db = db();
    db.apply(&[at(
        1,
        Record::Erasure(pb::Erasure {
            subject: "user:1".into(),
            key_version: 2,
            ..Default::default()
        }),
    )])
    .unwrap();
    let theirs = pb::BlobRef {
        hash: format!("b3s:{}", "ab".repeat(32)),
        size: 5,
        subject: Some("user:1".into()),
        key_version: 2,
    };
    db.apply(&[at(2, begin("e1", http(Some(&theirs), "")))])
        .unwrap();
    assert!(db.blob(&theirs.hash).unwrap().unwrap().erased);
    assert!(db.rooted_blobs_in_shard("ab", 1).unwrap().is_empty());
    assert!(db.state_blob_roots().unwrap().is_empty());
}

/// The bulk catch-up path keeps no index: a simple turn with a blob body
/// goes to the applier, so a rebuild indexes it as the live node did.
#[test]
fn the_bulk_catch_up_leaves_records_with_blobs_to_the_applier() {
    let body = blob(9, 42);
    let mut rows = crate::db::CatchupRows::new(0);
    assert!(
        !rows
            .push(&at(1, record("e1", http(Some(&body), ""), None)))
            .unwrap()
    );
    let mut rows = crate::db::CatchupRows::new(0);
    assert!(
        rows.push(&at(1, record("e1", http(None, ""), None)))
            .unwrap()
    );
}
