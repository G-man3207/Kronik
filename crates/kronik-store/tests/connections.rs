//! M24: the `connections` table of `state.db` (docs/design/m24-connections.md
//! §6.5), derived from the log like every table: the applier's rules, the
//! state hash, a snapshot and a bulk rebuild from the log.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_log::{Committed, Position};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_store::Store;
use kronik_store::db::{CatchupRows, ConnectionState};
use prost::Message as _;

const C1: &str = "c-0123456789abcdef0123456789abcdef";
const C2: &str = "c-fedcba9876543210fedcba9876543210";

fn committed(lsn: u64, record: Record) -> Committed {
    Committed {
        lsn,
        pos: Position {
            segment: 0,
            offset: lsn * 100,
        },
        record,
    }
}

fn plain(subject: Option<&str>, v: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.map(String::from),
        value: Some(pb::sealable::Value::Plain(v.to_vec())),
    })
}

fn text(t: &str) -> pb::Frame {
    pb::Frame {
        kind: pb::frame::Kind::Text as i32,
        data: plain(None, t.as_bytes()),
        ..Default::default()
    }
}

fn connection(id: &str, event: pb::connection_input::Event, resend_of: &str) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Connection(pb::ConnectionInput {
            connection: id.into(),
            protocol: pb::ConnectionProtocol::Websocket as i32,
            route: "/room/{key}/ws".into(),
            event: Some(event),
            resend_of: resend_of.into(),
            ..Default::default()
        })),
    }
}

fn open(id: &str) -> pb::Input {
    connection(
        id,
        pb::connection_input::Event::Open(pb::ConnectionOpen {
            request: Some(pb::HttpInput {
                method: "GET".into(),
                headers: vec![pb::Header {
                    name: "x".into(),
                    value: plain(Some("user:request"), b"1"),
                }],
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(plain(None, b"").unwrap())),
                }),
                ..Default::default()
            }),
        }),
        "",
    )
}

fn frame(id: &str, seq: u64, resend_of: &str) -> pb::Input {
    connection(
        id,
        pb::connection_input::Event::Frame(pb::ConnectionFrame {
            seq,
            frame: Some(text("say hi")),
        }),
        resend_of,
    )
}

fn close(id: &str, cause: pb::CloseCause, written: Option<u64>, resend_of: &str) -> pb::Input {
    connection(
        id,
        pb::connection_input::Event::Close(pb::ConnectionClose {
            cause: cause as i32,
            code: 1000,
            frames_written: written.unwrap_or(0),
            frames_written_known: written.is_some(),
            frames_received: 2,
            ..Default::default()
        }),
        resend_of,
    )
}

fn turn(input: pb::Input, kind: pb::OutcomeKind) -> pb::TurnRecord {
    pb::TurnRecord {
        execution_id: format!("{:032x}", input.encoded_len()),
        actor: Some(pb::ActorRef {
            kind: "room".into(),
            key: "lobby".into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: "0123456789abcdef0123456789abcdef".into(),
            path: vec![],
        }),
        input: Some(input),
        outcome: Some(pb::Outcome {
            kind: kind as i32,
            error_code: if kind == pb::OutcomeKind::Committed {
                String::new()
            } else {
                "TURN_FAILED".into()
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn send(targets: &[(&str, u64)], frame: pb::Frame) -> pb::ConnectionOp {
    pb::ConnectionOp {
        connections: targets.iter().map(|(c, _)| (*c).into()).collect(),
        seqs: targets.iter().map(|(_, s)| *s).collect(),
        op: Some(pb::connection_op::Op::Send(frame)),
        dropped: Vec::new(),
    }
}

fn close_op(id: &str) -> pb::ConnectionOp {
    pb::ConnectionOp {
        connections: vec![id.into()],
        seqs: vec![],
        op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
            code: 4000,
            reason: plain(None, b"kicked"),
        })),
        dropped: Vec::new(),
    }
}

fn send_now(ordinal: u32, id: &str, seq: u64, status: pb::EffectStatus) -> pb::EffectRecord {
    pb::EffectRecord {
        ordinal,
        kind: "connection.send-now".into(),
        target: format!("connection:{id}"),
        status: status as i32,
        grounding: pb::Grounding::Live as i32,
        delivery: "unsafe".into(),
        request: plain(
            None,
            &pb::ConnectionSendRequest {
                connection: id.into(),
                seq,
                kind: pb::frame::Kind::Text as i32,
                data: b"tok".to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        ),
        ..Default::default()
    }
}

/// A connection's life in the log: an accepted open with a welcome, a
/// refused one, a broadcast that names the refused id too, a failed frame
/// turn whose send-now still counts, its resend, an actor close and a
/// failing close input, then a resent close.
fn records() -> Vec<Committed> {
    let mut accepted = turn(open(C1), pb::OutcomeKind::Committed);
    if let Some(o) = accepted.outcome.as_mut() {
        o.output = Some(pb::outcome::Output::Accept(pb::ConnectionAccept {
            subject: Some("user:ada".into()),
            ..Default::default()
        }));
    }
    accepted.connection_ops = vec![send(&[(C1, 0)], text("welcome"))];

    let mut refused = turn(open(C2), pb::OutcomeKind::Committed);
    if let Some(o) = refused.outcome.as_mut() {
        o.output = Some(pb::outcome::Output::Http(pb::HttpResponse {
            status: 403,
            ..Default::default()
        }));
    }
    // Frames of a refused open's own turn have no row to change.
    refused.connection_ops = vec![send(&[(C2, 0)], text("no"))];

    let mut broadcast = turn(frame(C1, 0, ""), pb::OutcomeKind::Committed);
    broadcast.connection_ops = vec![send(&[(C1, 1), (C2, 1)], text("msg"))];

    // A failed frame turn: its OK send-now counts, its CLOSED one does not,
    // and its buffered operations are gone (the runtime drops them).
    let mut failed = turn(frame(C1, 1, ""), pb::OutcomeKind::Failed);
    failed.effects = vec![
        send_now(0, C1, 2, pb::EffectStatus::Ok),
        send_now(1, C1, 0, pb::EffectStatus::Closed),
    ];

    let resent = turn(frame(C1, 1, "main:4"), pb::OutcomeKind::Committed);

    let mut kick = turn(frame(C1, 2, ""), pb::OutcomeKind::Committed);
    kick.connection_ops = vec![send(&[(C1, 3)], text("bye")), close_op(C1)];
    let mut again = turn(frame(C1, 3, ""), pb::OutcomeKind::Committed);
    again.connection_ops = vec![close_op(C1), send(&[(C1, 4)], text("late"))];

    // The close input closes the row even though its turn fails.
    let closing = turn(
        close(C1, pb::CloseCause::Actor, Some(4), ""),
        pb::OutcomeKind::Trap,
    );
    let resent_close = turn(
        close(C1, pb::CloseCause::Client, Some(9), "main:8"),
        pb::OutcomeKind::Committed,
    );
    [
        accepted,
        refused,
        broadcast,
        failed,
        resent,
        kick,
        again,
        closing,
        resent_close,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, t)| committed(i as u64 + 1, Record::TurnRecord(t)))
    .collect()
}

#[test]
fn the_applier_follows_a_connection_from_open_to_close() {
    let store = Store::memory().unwrap();
    let records = records();
    // Up to the failed frame turn: open, counted, a dead letter.
    store.apply(&records[..4]).unwrap();
    let row = store.db().connection(C1).unwrap().unwrap();
    assert_eq!(
        (row.actor.kind.as_str(), row.actor.key.as_str()),
        ("room", "lobby")
    );
    assert_eq!(row.subject.as_deref(), Some("user:ada"));
    assert_eq!(row.opened_lsn, 1);
    assert_eq!((row.frames_in, row.next_seq), (2, 3));
    assert!(row.open());
    assert!(store.db().connection(C2).unwrap().is_none());
    let dead = store.db().dead_letters(0, 10).unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].lsn, 4);
    assert_eq!(
        store.db().open_connections().unwrap().len(),
        1,
        "the refused open has no row"
    );

    store.apply(&records[4..]).unwrap();
    // The close input moved the row out of the live table (ADR 0114,
    // amended): turns no longer see it; the API and history still do.
    assert!(store.db().connection(C1).unwrap().is_none());
    let row = store.db().connection_any(C1).unwrap().unwrap();
    // The resend does not count again; the closing lsn is the first close's.
    assert_eq!(row.frames_in, 4);
    assert_eq!(row.next_seq, 5);
    assert_eq!(row.closing_lsn, Some(6));
    // The failed close input closed it; the resent close changed nothing.
    assert_eq!(row.closed_lsn, Some(8));
    assert_eq!(row.cause, Some(pb::CloseCause::Actor as i32));
    assert_eq!(row.frames_written, Some(4));
    assert!(store.db().open_connections().unwrap().is_empty());
    let dead = store.db().dead_letters(0, 10).unwrap();
    assert_eq!(
        dead.iter()
            .map(|d| (d.lsn, d.resent_as))
            .collect::<Vec<_>>(),
        [(4, Some(5)), (8, Some(9))]
    );
    let all = store
        .db()
        .connections(None, ConnectionState::All, "", 10)
        .unwrap();
    assert_eq!(all.len(), 1);
    assert!(
        store
            .db()
            .connections(Some(("room", Some("other"))), ConnectionState::All, "", 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .db()
            .connections(Some(("room", None)), ConnectionState::Closed, "", 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.db().open_connection_count("room").unwrap(), 0);
}

/// The table is in the state hash, travels in snapshots and is the same
/// after a bulk rebuild from the log.
#[test]
fn snapshots_and_rebuilds_keep_the_connections_table() {
    let dir = tempfile::tempdir().unwrap();
    let records = records();
    let store = Store::memory().unwrap();
    store.apply(&records[..3]).unwrap();
    let before = store.state_hash().unwrap();
    let snapshot = dir.path().join("snapshot");
    assert_eq!(store.snapshot_to(&snapshot).unwrap().state_hash, before);
    // The hash covers the table.
    store
        .db()
        .conn()
        .execute("UPDATE connections SET next_seq = 99", [])
        .unwrap();
    assert_ne!(store.state_hash().unwrap(), before);
    store
        .db()
        .conn()
        .execute("UPDATE connections SET next_seq = 2", [])
        .unwrap();
    assert_eq!(store.state_hash().unwrap(), before);
    store.apply(&records[3..4]).unwrap();
    let restored = Store::open_snapshot_in_memory(&snapshot).unwrap();
    assert_eq!(restored.state_hash().unwrap(), before);
    assert!(restored.db().connection(C1).unwrap().is_some());
    restored.apply(&records[3..]).unwrap();
    store.apply(&records[4..]).unwrap();
    assert_eq!(restored.state_hash().unwrap(), store.state_hash().unwrap());

    let rebuilt = Store::memory().unwrap();
    rebuilt.db().begin_bulk_replay().unwrap();
    rebuilt.apply(&records).unwrap();
    rebuilt.db().end_bulk_replay().unwrap();
    assert_eq!(rebuilt.state_hash().unwrap(), store.state_hash().unwrap());
    assert_eq!(
        rebuilt.db().connection_any(C1).unwrap(),
        store.db().connection_any(C1).unwrap()
    );
    assert_eq!(
        rebuilt.db().open_connections().unwrap(),
        store.db().open_connections().unwrap()
    );
}

/// An HTTP turn that sends frames is not a "simple" turn for the startup
/// fast path, which would skip its connection operations.
#[test]
fn the_startup_fast_path_does_not_skip_frames_of_http_turns() {
    let http = |ops: Vec<pb::ConnectionOp>| {
        let mut t = turn(
            pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(plain(None, b"").unwrap())),
                    }),
                    ..Default::default()
                })),
            },
            pb::OutcomeKind::Committed,
        );
        t.connection_ops = ops;
        vec![committed(1, Record::TurnRecord(t))]
    };
    assert!(CatchupRows::of(&http(vec![]), 0).unwrap().is_some());
    assert!(
        CatchupRows::of(&http(vec![send(&[(C1, 0)], text("x"))]), 0)
            .unwrap()
            .is_none()
    );
}

/// Retention's index compaction deletes closed connections whose close is
/// below the retention base, and nothing else: the live table, which turns
/// read, and the state hash stay as they were (ADR 0114, amended).
#[test]
fn compaction_deletes_only_history_below_the_base() {
    let store = Store::memory().unwrap();
    let mut records = records();
    // A second connection that stays open.
    let mut other = turn(open(C2), pb::OutcomeKind::Committed);
    if let Some(o) = other.outcome.as_mut() {
        o.output = Some(pb::outcome::Output::Accept(pb::ConnectionAccept::default()));
    }
    records.push(committed(
        records.len() as u64 + 1,
        Record::TurnRecord(other),
    ));
    store.apply(&records).unwrap();
    let hash = store.state_hash().unwrap();
    let live = store.db().open_connections().unwrap();
    assert_eq!(live.len(), 1);
    // C1 closed at lsn 8: a base at 8 keeps it, one above deletes it.
    store.db().compact(8, u64::MAX).unwrap();
    assert!(store.db().connection_any(C1).unwrap().is_some());
    store.db().compact(9, u64::MAX).unwrap();
    assert!(store.db().connection_any(C1).unwrap().is_none());
    assert_eq!(store.db().open_connections().unwrap(), live);
    assert_eq!(store.state_hash().unwrap(), hash, "history is not hashed");
}

/// Every row update names the turn's actor as the owner (ADR 0114): a
/// record of another actor that names the connection moves nothing.
#[test]
fn another_actors_record_does_not_move_a_row() {
    let store = Store::memory().unwrap();
    let records = records();
    store.apply(&records[..1]).unwrap();
    let before = store.db().connection(C1).unwrap().unwrap();
    let mut foreign = turn(frame(C1, 9, ""), pb::OutcomeKind::Committed);
    foreign.actor = Some(pb::ActorRef {
        kind: "room".into(),
        key: "other".into(),
    });
    foreign.effects = vec![send_now(0, C1, 1, pb::EffectStatus::Ok)];
    foreign.connection_ops = vec![send(&[(C1, 1)], text("x")), close_op(C1)];
    let mut foreign_close = turn(
        close(C1, pb::CloseCause::Client, Some(0), ""),
        pb::OutcomeKind::Committed,
    );
    foreign_close.actor = foreign.actor.clone();
    store
        .apply(&[
            committed(2, Record::TurnRecord(foreign)),
            committed(3, Record::TurnRecord(foreign_close)),
        ])
        .unwrap();
    assert_eq!(store.db().connection(C1).unwrap().unwrap(), before);
}
