//! M24's compatibility fixture (docs/design/m24-connections.md §6.7): the
//! log of a short recorded session of the room test guest, written by this
//! version and kept in `tests/compatibility/m24-connections/log`: two
//! WebSocket opens, frames, a broadcast, a `send-now` stream, an actor's
//! close, a crash and the restart close of the connection left open. Later
//! versions must read it, apply it and rebuild the same state.
//!
//! `KRONIK_WRITE_FIXTURES=1 cargo test -p kronik-sched --test
//! connections_fixture` writes it again; without it, the test reads the
//! committed one.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_log::Committed;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::RecordingTransport;
use kronik_sched::{NodeConfig, start_local};
use kronik_store::Store;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/compatibility/m24-connections/log")
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "fixture".into(),
        reason: "the M24 compatibility fixture".into(),
        wall_time_ms: 0,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..1000 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}");
}

fn text(t: &str) -> pb::Frame {
    pb::Frame {
        kind: pb::frame::Kind::Text as i32,
        data: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(t.as_bytes().to_vec())),
        }),
        ..Default::default()
    }
}

/// Records the session in `dir` with a real node: the room deployed and
/// granted `connection:send-now`, ada and bob join, frames, bob leaves by
/// the actor's close, and the process dies with ada still open; the next
/// start closes her connection with `restart`.
fn record_session(dir: &Path) {
    {
        let rt = runtime();
        let node = rt.block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            start_local(env, dir, NodeConfig::default()).await.unwrap()
        });
        let owner = node.local_operator_authority().unwrap();
        rt.block_on(node.deploy(&std::fs::read(ROOM).unwrap(), audit(), false, owner.clone()))
            .unwrap();
        rt.block_on(node.grant(
            "room",
            "connection:send-now",
            None,
            None,
            kronik_effects::InForks::default(),
            audit(),
            false,
            owner,
        ))
        .unwrap();
        let join = |user: &str| {
            let request = pb::HttpInput {
                method: "GET".into(),
                path: "/room/lobby/ws".into(),
                query: format!("user={user}"),
                params: vec![pb::Param {
                    name: "key".into(),
                    value: "lobby".into(),
                    sealed_value: None,
                }],
                route: "/room/{key}/ws".into(),
                ..Default::default()
            };
            let (id, waiter) = node
                .connection_open(
                    ActorRef::parse("room/lobby").unwrap(),
                    request,
                    pb::ConnectionProtocol::Websocket,
                    None,
                    None,
                    false,
                )
                .unwrap();
            assert!(rt.block_on(waiter.wait()).unwrap().committed());
            let t = RecordingTransport::attach(node.hub(), &id).unwrap();
            (id, t)
        };
        let (ada, ta) = join("ada");
        let (bob, tb) = join("bob");
        for (conn, frame) in [
            (&ada, "say hello"),
            (&bob, "echo hi"),
            (&ada, "stream 2"),
            (&bob, "bye"),
        ] {
            rt.block_on(node.hub().incoming(conn, text(frame)));
        }
        until("bob's close", || {
            node.store()
                .db()
                .connection_any(&bob)
                .unwrap()
                .is_some_and(|r| r.closed_lsn.is_some())
        });
        until("ada's stream", || {
            ta.recording().frames.iter().any(|(_, f)| {
                f.data
                    .as_ref()
                    .is_some_and(|d| d.value == text("done 2").data.unwrap().value)
            })
        });
        assert!(tb.recording().closed.is_some());
        // The process dies here, ada's connection open.
    }
    let rt = runtime();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(env, dir, NodeConfig::default()).await.unwrap()
    });
    until("the restart close", || {
        node.store().db().open_connections().unwrap().is_empty()
    });
    // Let the close turn's record reach the log before the copy.
    std::thread::sleep(Duration::from_millis(300));
    drop(node);
}

/// Every record of the log in `dir`, in order.
fn read_log(dir: &Path) -> Vec<Committed> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dir.to_path_buf(), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                out.push(c);
                Ok(())
            })
            .await
            .unwrap();
        out
    })
}

#[test]
fn the_m24_connections_fixture_reads_applies_and_rebuilds() {
    let fixture = fixture_dir();
    if std::env::var_os("KRONIK_WRITE_FIXTURES").is_some() {
        let dir = tempfile::tempdir().unwrap();
        record_session(dir.path());
        let log = dir.path().join("branches/main/log");
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(&fixture).unwrap();
        for entry in std::fs::read_dir(&log).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), fixture.join(entry.file_name())).unwrap();
        }
    }
    let records = read_log(&fixture);
    assert!(
        !records.is_empty(),
        "no fixture log at {}",
        fixture.display()
    );

    // Every kind of M24 record is there, and decodes and validates.
    let turns: Vec<&pb::TurnRecord> = records
        .iter()
        .filter_map(|c| match &c.record {
            Record::TurnRecord(t) => Some(t),
            _ => None,
        })
        .collect();
    let event = |t: &pb::TurnRecord| match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
        Some(pb::input::Kind::Connection(c)) => c.event.clone(),
        _ => None,
    };
    let opens = turns
        .iter()
        .filter(|t| matches!(event(t), Some(pb::connection_input::Event::Open(_))))
        .count();
    let frames = turns
        .iter()
        .filter(|t| matches!(event(t), Some(pb::connection_input::Event::Frame(_))))
        .count();
    let closes: Vec<pb::ConnectionClose> = turns
        .iter()
        .filter_map(|t| match event(t) {
            Some(pb::connection_input::Event::Close(c)) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!((opens, frames), (2, 4));
    let causes: Vec<i32> = closes.iter().map(|c| c.cause).collect();
    assert!(
        causes.contains(&(pb::CloseCause::Actor as i32)),
        "{causes:?}"
    );
    assert!(
        causes.contains(&(pb::CloseCause::Restart as i32)),
        "{causes:?}"
    );
    assert!(turns.iter().any(|t| matches!(
        t.outcome.as_ref().and_then(|o| o.output.as_ref()),
        Some(pb::outcome::Output::Accept(_))
    )));
    let send_nows = turns
        .iter()
        .flat_map(|t| &t.effects)
        .filter(|e| e.kind == "connection.send-now" && e.status == pb::EffectStatus::Ok as i32)
        .count();
    assert_eq!(send_nows, 2);
    assert!(
        turns
            .iter()
            .flat_map(|t| &t.connection_ops)
            .any(|op| matches!(op.op, Some(pb::connection_op::Op::Close(_))))
    );

    // Applied, then applied again from scratch: the same state, both
    // connections closed with their causes.
    let apply = || {
        let store = Store::memory().unwrap();
        for chunk in records.chunks(64) {
            store.apply(chunk).unwrap();
        }
        store
    };
    let store = apply();
    assert!(store.db().open_connections().unwrap().is_empty());
    let rows = store
        .db()
        .connections(None, kronik_store::db::ConnectionState::Closed, "", 10)
        .unwrap();
    assert_eq!(rows.len(), 2);
    let ada = rows
        .iter()
        .find(|r| r.cause == Some(pb::CloseCause::Restart as i32))
        .unwrap();
    let bob = rows
        .iter()
        .find(|r| r.cause == Some(pb::CloseCause::Actor as i32))
        .unwrap();
    assert_eq!(ada.subject.as_deref(), Some("user:ada"));
    assert_eq!(bob.code, Some(1000));
    // ada: the welcome, bob's joined, her message, two send-now tokens and
    // the stream's `done`, at least.
    assert!(ada.next_seq >= 6, "{ada:?}");
    assert_eq!(ada.frames_written, None, "unknown after a restart");
    assert!(ada.restart_after_lsn.is_some());
    assert_eq!(apply().state_hash().unwrap(), store.state_hash().unwrap());
}
