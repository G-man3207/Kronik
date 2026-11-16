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
        db.rooted_blobs_in_shard(&shard_of(&upload), 3, None)
            .unwrap(),
        std::slice::from_ref(&upload.hash)
    );
    // Past the floor only the saved response keeps its blob.
    assert!(
        db.rooted_blobs_in_shard(&shard_of(&upload), 4, None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.rooted_blobs_in_shard(&shard_of(&answer), 4, None)
            .unwrap(),
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
    assert_eq!(db.prune_blob_pins(4).unwrap(), 1);
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
    assert!(db.rooted_blobs_in_shard("ab", 1, None).unwrap().is_empty());
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

fn msg_with(blobs: Vec<pb::BlobRef>) -> pb::Message {
    pb::Message {
        name: "m".into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(b"x".to_vec())),
        }),
        blobs,
        retained_compensation_source: None,
    }
}

/// A committed turn of `media/a` with `input`, holding operations, outbound
/// messages and timer operations.
fn turn(
    execution_id: &str,
    input: pb::input::Kind,
    committed: bool,
    blob_refs: Vec<pb::BlobRefOp>,
    messages: Vec<pb::OutboundMessage>,
    timers: Vec<pb::TimerOp>,
) -> Record {
    Record::TurnRecord(pb::TurnRecord {
        execution_id: execution_id.into(),
        actor: actor(),
        causal_key: Some(pb::CausalKey {
            root: execution_id.into(),
            path: vec![],
        }),
        input: Some(pb::Input { kind: Some(input) }),
        outcome: Some(pb::Outcome {
            kind: if committed {
                pb::OutcomeKind::Committed as i32
            } else {
                pb::OutcomeKind::Failed as i32
            },
            error_code: if committed { String::new() } else { "X".into() },
            ..Default::default()
        }),
        blob_refs,
        messages,
        timers,
        ..Default::default()
    })
}

fn op(kind: pb::blob_ref_op::Kind, blob: &pb::BlobRef) -> pb::BlobRefOp {
    pb::BlobRefOp {
        kind: kind as i32,
        blob: Some(blob.clone()),
    }
}

fn operator() -> pb::input::Kind {
    pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::Operator as i32,
        msg: Some(msg_with(vec![])),
        message_id: "op".into(),
        ..Default::default()
    })
}

/// Holds follow the `RETAIN` and `RELEASE` of committed turns, keep a blob
/// below the floor, count against the actor's held bytes, and are in the
/// state hash only while there are any; a failed turn or an operation of
/// no kind is a damaged log.
#[test]
fn holds_follow_retain_and_release() {
    use pb::blob_ref_op::Kind;
    let mut db = db();
    let (a, b) = (blob(0x11, 1000), blob(0x12, 500));
    // Without holds `blob_refs` adds nothing to the state hash.
    let none = blake3::Hasher::new().finalize().to_hex().to_string();
    assert_eq!(crate::snapshot::hash_for_test(&db, &["blob_refs"]), none);
    db.apply(&[at(
        1,
        turn(
            "e1",
            operator(),
            true,
            vec![op(Kind::Retain, &a), op(Kind::Retain, &b)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    assert_eq!(db.held("media", "a", &a.hash).unwrap(), Some(a.clone()));
    assert_eq!(db.held("media", "b", &a.hash).unwrap(), None);
    assert_eq!(db.held_bytes("media", "a").unwrap(), 1500);
    assert_ne!(crate::snapshot::hash_for_test(&db, &["blob_refs"]), none);
    // Held, so kept far below the floor.
    assert_eq!(
        db.rooted_blobs_in_shard("11", 1000, None).unwrap(),
        std::slice::from_ref(&a.hash)
    );
    assert_eq!(db.state_blob_roots().unwrap().len(), 2);
    db.apply(&[at(
        2,
        turn(
            "e2",
            operator(),
            true,
            vec![op(Kind::Release, &a), op(Kind::Release, &b)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    assert_eq!(db.held_bytes("media", "a").unwrap(), 0);
    // Who let it go, for the dry run.
    assert_eq!(
        db.released_by(&a.hash).unwrap(),
        Some(("media".into(), "a".into(), 2))
    );
    assert!(
        db.rooted_blobs_in_shard("11", 1000, None)
            .unwrap()
            .is_empty()
    );
    assert_eq!(crate::snapshot::hash_for_test(&db, &["blob_refs"]), none);

    let err = db
        .apply(&[at(
            3,
            turn(
                "e3",
                operator(),
                false,
                vec![op(Kind::Retain, &a)],
                vec![],
                vec![],
            ),
        )])
        .unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    let none = pb::BlobRefOp {
        kind: 0,
        blob: Some(a.clone()),
    };
    let err = db
        .apply(&[at(
            3,
            turn("e3", operator(), true, vec![none], vec![], vec![]),
        )])
        .unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
}

/// Below the floor, a blob that only a pending timer keeps is rooted; the
/// simulator's mutation "a sweep that ignores timers" leaves exactly the
/// timers' pins out (a queued message's blob stays rooted).
#[test]
fn a_timer_keeps_its_blob_unless_the_roots_leave_timers_out() {
    let mut db = db();
    // Two blobs of shard 31.
    let in_31 = |n: u8, size| pb::BlobRef {
        hash: format!("b3:31{}", format!("{n:02x}").repeat(31)),
        size,
        subject: None,
        key_version: 0,
    };
    let (m, t) = (in_31(0x01, 10), in_31(0x02, 20));
    let out = pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        }),
        msg: Some(msg_with(vec![m.clone()])),
        ordinal: 1,
        message_id: "m1".into(),
    };
    let schedule = pb::TimerOp {
        kind: pb::TimerOpKind::Schedule as i32,
        timer_id: 7,
        due_ms: 99,
        msg: Some(msg_with(vec![t.clone()])),
        ordinal: 2,
    };
    db.apply(&[at(
        1,
        turn("e1", operator(), true, vec![], vec![out], vec![schedule]),
    )])
    .unwrap();
    let mut both = vec![m.hash.clone(), t.hash.clone()];
    both.sort();
    assert_eq!(db.rooted_blobs_in_shard("31", 1000, None).unwrap(), both);
    assert_eq!(
        db.rooted_blobs_in_shard("31", 1000, Some(source::TIMER))
            .unwrap(),
        std::slice::from_ref(&m.hash)
    );
}

/// A queued message, a scheduled timer, a dead letter and a saved call
/// outcome pin their blobs while their rows exist; a saved call outcome
/// below the floor goes unless an open turn began before it.
#[test]
fn pins_follow_their_rows() {
    let mut db = db();
    let (m, t, r) = (blob(0x21, 10), blob(0x22, 20), blob(0x23, 30));
    let out = pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        }),
        msg: Some(msg_with(vec![m.clone()])),
        ordinal: 1,
        message_id: "m1".into(),
    };
    let schedule = pb::TimerOp {
        kind: pb::TimerOpKind::Schedule as i32,
        timer_id: 7,
        due_ms: 99,
        msg: Some(msg_with(vec![t.clone()])),
        ordinal: 2,
    };
    db.apply(&[at(
        1,
        turn("e1", operator(), true, vec![], vec![out], vec![schedule]),
    )])
    .unwrap();
    assert_eq!(sources(&db, &m.hash), [(source::MAILBOX, "m1".into())]);
    assert_eq!(
        sources(&db, &t.hash),
        [(source::TIMER, "media\u{1f}a\u{1f}7".into())]
    );

    // The message fails at its receiver: no longer queued, a dead letter.
    let delivered = pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::Actor as i32,
        msg: Some(msg_with(vec![m.clone()])),
        message_id: "m1".into(),
        ..Default::default()
    });
    db.apply(&[at(2, turn("e2", delivered, false, vec![], vec![], vec![]))])
        .unwrap();
    assert_eq!(sources(&db, &m.hash), [(source::DEAD_LETTER, "2".into())]);
    // Its resend no longer pins: the resend's record references the blob.
    let resend = pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::DeadLetterResend as i32,
        msg: Some(msg_with(vec![m.clone()])),
        message_id: "r1".into(),
        resend_of: "main:2".into(),
        ..Default::default()
    });
    db.apply(&[at(3, turn("e3", resend, true, vec![], vec![], vec![]))])
        .unwrap();
    assert!(sources(&db, &m.hash).is_empty());

    // The timer fires.
    let fired = pb::input::Kind::Timer(pb::TimerInput {
        timer_id: 7,
        msg: Some(msg_with(vec![t.clone()])),
        due_ms: 99,
        ..Default::default()
    });
    db.apply(&[at(4, turn("e4", fired, true, vec![], vec![], vec![]))])
        .unwrap();
    assert!(sources(&db, &t.hash).is_empty());

    // A turn open from before the call, and the call's saved outcome with
    // a blob in its reply.
    db.apply(&[at(5, begin("e0", http(None, "")))]).unwrap();
    let call = pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::Call as i32,
        msg: Some(msg_with(vec![])),
        message_id: "c1".into(),
        ..Default::default()
    });
    let mut answered = turn("e6", call, true, vec![], vec![], vec![]);
    if let Record::TurnRecord(rec) = &mut answered {
        rec.outcome.as_mut().unwrap().output =
            Some(pb::outcome::Output::Reply(msg_with(vec![r.clone()])));
    }
    db.apply(&[at(6, answered)]).unwrap();
    assert_eq!(sources(&db, &r.hash), [(source::DELIVERY, "c1".into())]);
    // The open turn that began before it keeps it past the floor (a re-run
    // may repeat the call); once that turn is closed, it goes.
    db.prune_blob_pins(10).unwrap();
    assert_eq!(sources(&db, &r.hash).len(), 1);
    db.apply(&[at(7, record("e0", http(None, ""), None))])
        .unwrap();
    assert_eq!(db.prune_blob_pins(10).unwrap(), 1);
    assert!(sources(&db, &r.hash).is_empty());
}

/// A rebase switch takes the shadow's holds of the rebased actors, its
/// mailbox and dead-letter pins, its timers' pins of the rebased actors and
/// its delivery pins after the base, and the blobs only it knows; other
/// actors' holds stay.
#[test]
fn a_rebase_switch_takes_the_shadows_holds_and_pins() {
    use pb::blob_ref_op::Kind;
    let mut main = db();
    let mut shadow = db();
    // A shadow applies main's records with gaps (ADR 0017).
    shadow.set_allow_gaps();
    let (old, new, other) = (blob(0x31, 1), blob(0x32, 2), blob(0x33, 3));
    main.apply(&[at(
        1,
        turn(
            "e1",
            operator(),
            true,
            vec![op(Kind::Retain, &old)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    let mut b = turn(
        "e2",
        operator(),
        true,
        vec![op(Kind::Retain, &other)],
        vec![],
        vec![],
    );
    if let Record::TurnRecord(rec) = &mut b {
        rec.actor = Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        });
    }
    main.apply(&[at(2, b)]).unwrap();
    let queued = pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        }),
        msg: Some(msg_with(vec![new.clone()])),
        ordinal: 1,
        message_id: "s1".into(),
    };
    shadow
        .apply(&[at(
            5,
            turn(
                "r1",
                operator(),
                true,
                vec![op(Kind::Retain, &new)],
                vec![queued],
                vec![],
            ),
        )])
        .unwrap();
    let actors = [("media".to_owned(), "a".to_owned())];
    let tx = main.conn.savepoint().unwrap();
    super::apply_switch(&shadow.conn, &tx, &actors, 3).unwrap();
    tx.commit().unwrap();
    assert_eq!(main.held("media", "a", &old.hash).unwrap(), None);
    assert_eq!(
        main.held("media", "a", &new.hash).unwrap(),
        Some(new.clone())
    );
    assert_eq!(
        main.held("media", "b", &other.hash).unwrap(),
        Some(other.clone())
    );
    assert_eq!(sources(&main, &new.hash), [(source::MAILBOX, "s1".into())]);
    assert_eq!(main.blob(&new.hash).unwrap().unwrap().last_ref_lsn, 5);
}

/// An erased blob's row stays while a pin or a hold names it, so that the
/// hold still resolves and a read answers `erased` (M26 §9.3); once nothing
/// keeps it, the collector's forget step deletes it.
#[test]
fn an_erased_row_stays_while_a_pin_or_a_hold_keeps_it() {
    use pb::blob_ref_op::Kind;
    let mut db = db();
    let theirs = pb::BlobRef {
        hash: format!("b3s:{}", "cd".repeat(32)),
        size: 5,
        subject: Some("user:1".into()),
        key_version: 2,
    };
    // Held by media/a, and the input of a turn that is still open.
    db.apply(&[at(
        1,
        turn(
            "e0",
            operator(),
            true,
            vec![op(Kind::Retain, &theirs)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    db.apply(&[at(2, begin("e1", http(Some(&theirs), "")))])
        .unwrap();
    db.apply(&[at(
        3,
        Record::Erasure(pb::Erasure {
            subject: "user:1".into(),
            key_version: 2,
            ..Default::default()
        }),
    )])
    .unwrap();
    db.conn
        .execute(
            "UPDATE blobs SET erased = 1 WHERE hash = ?1",
            [&theirs.hash],
        )
        .unwrap();
    let forget = |db: &mut StateDb| {
        db.forget_blobs(std::slice::from_ref(&theirs.hash), 100)
            .unwrap()
    };
    assert_eq!(forget(&mut db), 0);
    assert!(db.held("media", "a", &theirs.hash).unwrap().is_some());
    // The open turn ends: the hold still keeps the row.
    db.apply(&[at(4, record("e1", http(Some(&theirs), ""), None))])
        .unwrap();
    assert_eq!(forget(&mut db), 0);
    // Released: nothing keeps it.
    db.apply(&[at(
        5,
        turn(
            "e2",
            operator(),
            true,
            vec![op(Kind::Release, &theirs)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    assert_eq!(forget(&mut db), 1);
    assert!(db.blob(&theirs.hash).unwrap().is_none());
}

/// What counts against an actor's quota (ADR 0119 as amended 2026-11-14):
/// its holds, its timers, the messages it sent while they wait, and the
/// dead letters of its messages; each blob once. A row that goes takes
/// its charge with it.
#[test]
fn an_actors_charge_is_its_holds_timers_messages_and_dead_letters() {
    use pb::blob_ref_op::Kind;
    let mut db = db();
    let (held, timed, sent) = (blob(0x41, 100), blob(0x42, 20), blob(0x43, 3));
    let out = pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        }),
        // The held blob again: it counts once.
        msg: Some(msg_with(vec![sent.clone(), held.clone()])),
        ordinal: 1,
        message_id: "m1".into(),
    };
    let schedule = pb::TimerOp {
        kind: pb::TimerOpKind::Schedule as i32,
        timer_id: 9,
        due_ms: 99,
        msg: Some(msg_with(vec![timed.clone()])),
        ordinal: 2,
    };
    db.apply(&[at(
        1,
        turn(
            "e1",
            operator(),
            true,
            vec![op(Kind::Retain, &held)],
            vec![out],
            vec![schedule],
        ),
    )])
    .unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 123);
    assert!(db.charged_by_pin("media", "a", &timed.hash).unwrap());
    assert!(db.charged_by_pin("media", "a", &sent.hash).unwrap());
    // The receiver is not charged for what it was sent.
    assert_eq!(db.charged_bytes("media", "b").unwrap(), 0);
    // The message fails at its receiver: a dead letter, still the sender's.
    let delivered = pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::Actor as i32,
        sender: Some(pb::ActorRef {
            kind: "media".into(),
            key: "a".into(),
        }),
        msg: Some(msg_with(vec![sent.clone(), held.clone()])),
        message_id: "m1".into(),
        ..Default::default()
    });
    let mut failed = turn("e2", delivered, false, vec![], vec![], vec![]);
    if let Record::TurnRecord(rec) = &mut failed {
        rec.actor = Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        });
    }
    db.apply(&[at(2, failed)]).unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 123);
    assert_eq!(db.charged_bytes("media", "b").unwrap(), 0);
    // The timer fires; the hold is released: only the dead letter's blobs.
    let fired = pb::input::Kind::Timer(pb::TimerInput {
        timer_id: 9,
        msg: Some(msg_with(vec![timed.clone()])),
        due_ms: 99,
        ..Default::default()
    });
    db.apply(&[at(
        3,
        turn(
            "e3",
            fired,
            true,
            vec![op(Kind::Release, &held)],
            vec![],
            vec![],
        ),
    )])
    .unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 103);
    assert!(!db.charged_by_pin("media", "a", &timed.hash).unwrap());
    // Another message, which its receiver takes: another actor's record
    // ends it, at a time media/a's turns do not order, so media/a sees it
    // gone only from its next turn on, as a replay at that turn's place
    // would.
    let other = blob(0x44, 7);
    let out = pb::OutboundMessage {
        to: Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        }),
        msg: Some(msg_with(vec![other.clone()])),
        ordinal: 1,
        message_id: "m2".into(),
    };
    db.apply(&[at(
        4,
        turn("e4", operator(), true, vec![], vec![out], vec![]),
    )])
    .unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 110);
    let taken = pb::input::Kind::Message(pb::MessageInput {
        source: pb::MessageSource::Actor as i32,
        sender: Some(pb::ActorRef {
            kind: "media".into(),
            key: "a".into(),
        }),
        msg: Some(msg_with(vec![other.clone()])),
        message_id: "m2".into(),
        ..Default::default()
    });
    let mut consumed = turn("e5", taken, true, vec![], vec![], vec![]);
    if let Record::TurnRecord(rec) = &mut consumed {
        rec.actor = Some(pb::ActorRef {
            kind: "media".into(),
            key: "b".into(),
        });
    }
    db.apply(&[at(5, consumed)]).unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 110);
    assert!(db.charged_by_pin("media", "a", &other.hash).unwrap());
    db.apply(&[at(6, turn("e6", operator(), true, vec![], vec![], vec![]))])
        .unwrap();
    assert_eq!(db.charged_bytes("media", "a").unwrap(), 103);
    assert!(!db.charged_by_pin("media", "a", &other.hash).unwrap());
    let pending: i64 = db
        .conn
        .query_row("SELECT count(*) FROM blob_charge_releases", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(pending, 0, "settled at media/a's turn");
}

/// The retention pass probes each pin's row through the owner index of its
/// source: 500 pins against 200 000 saved responses stay bounded by the pins,
/// not by the pins times the table.
#[test]
#[allow(clippy::disallowed_methods)] // the bound is wall time, not logical time
fn orphan_pin_pruning_probes_each_source_by_its_owner() {
    use std::time::{Duration, Instant};

    let mut db = db();
    db.conn
        .execute_batch(
            "INSERT INTO mailbox (message_id, to_kind, to_key, lsn, ordinal, input, causal) \
             VALUES ('m1', 'counter', 'a', 1, 0, x'', x'');
             INSERT INTO timers (kind, key, timer_id, due_ms, msg, causal, lsn) \
             VALUES ('counter', 'a', 7, 0, x'', x'', 1);
             INSERT INTO dead_letters \
               (lsn, kind, key, input, error_code, message, resent_as, subject) \
             VALUES (2, 'counter', 'a', x'', 'X', '', NULL, NULL);
             INSERT INTO ingress_keys \
               (kind, key, idem_key, request_hash, lsn, logical_time_ms, outcome, subject) \
             VALUES ('counter', 'a', 'idem', x'', 1, 0, x'', NULL);
             INSERT INTO deliveries (message_id, lsn, outcome, subject) \
             VALUES ('d1', 1, x'', NULL);",
        )
        .unwrap();
    for (hash, source, owner) in [
        ("h1", source::MAILBOX, "m1".to_owned()),
        ("h2", source::TIMER, timer_owner("counter", "a", 7)),
        ("h3", source::DEAD_LETTER, 2i64.to_string()),
        (
            "h4",
            source::INGRESS_KEY,
            ingress_owner("counter", "a", "idem"),
        ),
        ("h5", source::DELIVERY, "d1".to_owned()),
    ] {
        db.conn
            .execute(
                "INSERT INTO blob_pins (hash, source, owner, lsn, charged) \
                 VALUES (?1, ?2, ?3, 1, NULL)",
                rusqlite::params![hash, source, owner],
            )
            .unwrap();
    }
    let tx = db.conn.transaction().unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO ingress_keys \
                 (kind, key, idem_key, request_hash, lsn, logical_time_ms, outcome) \
                 VALUES ('counter', 'a', ?1, x'', ?2, 0, x'')",
            )
            .unwrap();
        for n in 0..200_000i64 {
            insert
                .execute(rusqlite::params![format!("saved-{n}"), n])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    let tx = db.conn.transaction().unwrap();
    {
        let mut insert = tx
            .prepare("INSERT INTO blob_pins (hash, source, owner, lsn) VALUES (?1, ?2, ?3, ?4)")
            .unwrap();
        for n in 0..500i64 {
            insert
                .execute(rusqlite::params![
                    format!("b3:{n:064x}"),
                    source::INGRESS_KEY,
                    format!("counter\u{1f}a\u{1f}missing-{n}"),
                    n + 2
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();

    for source in [
        source::MAILBOX,
        source::TIMER,
        source::DEAD_LETTER,
        source::INGRESS_KEY,
        source::DELIVERY,
    ] {
        let exists = pin_source_exists(source).unwrap();
        let mut statement = db
            .conn
            .prepare(&format!(
                "EXPLAIN QUERY PLAN DELETE FROM blob_pins WHERE source = ?1 AND NOT {exists}"
            ))
            .unwrap();
        let plan: Vec<String> = statement
            .query_map([source], |r| r.get(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            plan.iter().any(|detail| detail.starts_with("SEARCH ")),
            "source {source} has no indexed lookup: {plan:?}"
        );
        assert!(
            plan.iter()
                .all(|detail| !detail.starts_with("SCAN ") || detail.contains("blob_pins")),
            "source {source} scans its table once per pin: {plan:?}"
        );
    }

    let started = Instant::now();
    let deleted = db.prune_blob_pins(0).unwrap();
    let elapsed = started.elapsed();
    assert_eq!(deleted, 500, "the orphan pins, and only they");
    assert!(
        elapsed < Duration::from_secs(2),
        "500 pins over 200 000 saved responses took {elapsed:?}"
    );
    assert_eq!(db.blob_pins("h4").unwrap().len(), 1, "the live pin went");
}

/// The owner columns of the source tables are added to databases of an
/// earlier development build, filled from their rows, and indexed.
#[test]
fn source_owner_columns_migrate_old_databases() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE deliveries (
           message_id TEXT PRIMARY KEY, lsn INTEGER NOT NULL, outcome BLOB) WITHOUT ROWID;
         CREATE TABLE ingress_keys (
           kind TEXT NOT NULL, key TEXT NOT NULL, idem_key TEXT NOT NULL,
           request_hash BLOB NOT NULL, lsn INTEGER NOT NULL, logical_time_ms INTEGER NOT NULL,
           outcome BLOB NOT NULL,
           PRIMARY KEY (kind, key, idem_key)) WITHOUT ROWID;
         CREATE TABLE dead_letters (
           lsn INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, input BLOB NOT NULL,
           error_code TEXT NOT NULL, message TEXT NOT NULL, resent_as INTEGER);
         CREATE TABLE timers (
           kind TEXT NOT NULL, key TEXT NOT NULL, timer_id INTEGER NOT NULL,
           due_ms INTEGER NOT NULL, msg BLOB NOT NULL, causal BLOB NOT NULL, lsn INTEGER NOT NULL,
           PRIMARY KEY (kind, key, timer_id)) WITHOUT ROWID;
         INSERT INTO timers VALUES ('counter', 'a', 7, 0, x'', x'', 1);
         INSERT INTO ingress_keys VALUES ('counter', 'a', 'idem', x'', 1, 0, x'');
         INSERT INTO dead_letters VALUES (3, 'counter', 'a', x'', 'X', '', NULL);",
    )
    .unwrap();
    let db = StateDb::open(conn).unwrap();
    for (table, owner) in [
        ("timers", "counter\u{1f}a\u{1f}7"),
        ("ingress_keys", "counter\u{1f}a\u{1f}idem"),
        ("dead_letters", "3"),
    ] {
        let stored: String = db
            .conn
            .query_row(&format!("SELECT owner FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, owner, "{table}");
        let indexed: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [format!("{table}_owner")],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 1, "{table}_owner");
    }
}
