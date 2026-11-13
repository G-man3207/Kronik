//! M24 (ADR 0113): the host binds `kronik:actor@0.1.1`. Components built
//! for 0.1.0 (the committed guests and every released corpus component)
//! link and run unchanged, and a component's optional `connection-handler`
//! export is found when it has one.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CodeStore, PoolSize, Program, StateView, TurnLimits, TurnRequest, build_engine,
};

const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");
const NOTES: &[u8] = include_bytes!("../../../tests/guests/notes.wasm");
const ROOM: &[u8] = include_bytes!("../../../tests/guests/room.wasm");
const ROOM_FMT2: &[u8] = include_bytes!("../../../tests/guests/room-fmt2.wasm");

struct Map(BTreeMap<String, Vec<u8>>);

impl StateView for Map {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.get(key).cloned())
    }
    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(None)
    }
}

fn store() -> CodeStore {
    CodeStore::new(build_engine(PoolSize { concurrency: 2 }).unwrap(), None).unwrap()
}

fn message(name: &str, body: &[u8]) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: name.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.to_vec())),
                }),
                blobs: vec![],
                retained_compensation_source: None,
            }),
            message_id: "m".into(),
            ..Default::default()
        })),
    }
}

async fn run(program: &Program, actor: &str, input: pb::Input) -> pb::Outcome {
    let out = program
        .run(
            TurnRequest {
                actor: ActorRef::parse(actor).unwrap(),
                causal_key: kronik_core::causal::root("r".into()),
                logical_time_ms: 1_761_300_000_000,
                seed: [7; 32],
                input,
                limits: TurnLimits::default(),
                subject: None,
            },
            Arc::new(Map(BTreeMap::new())),
            None,
            None,
        )
        .await
        .unwrap();
    out.outcome
}

fn reply(outcome: &pb::Outcome) -> String {
    match &outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            other => panic!("unexpected reply body {other:?}"),
        },
        other => panic!("unexpected output {other:?}: {outcome:?}"),
    }
}

/// A 0.1.0 component has no connection export, describes and runs; the
/// room guest (built for `actor-connections`) has it, and its `handler`
/// export runs under the same bindings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn components_with_and_without_the_connection_export_run() {
    let code = store();
    let (_, counter) = code.add(COUNTER).unwrap();
    assert!(!counter.handles_connections());
    assert_eq!(
        counter.describe(TurnLimits::default()).await.unwrap().kind,
        "counter"
    );
    let outcome = run(&counter, "counter/a", message("increment", b"")).await;
    assert_eq!(reply(&outcome), "1");

    for bytes in [ROOM, ROOM_FMT2] {
        let (_, room) = code.add(bytes).unwrap();
        assert!(room.handles_connections());
        let manifest = room.describe(TurnLimits::default()).await.unwrap();
        assert_eq!(manifest.kind, "room");
        let methods: Vec<&str> = manifest.routes.iter().map(|r| r.method.as_str()).collect();
        assert_eq!(methods, ["WEBSOCKET", "SSE", "GET", "POST"]);
        assert_eq!(manifest.capabilities, ["connection:send-now"]);
        let outcome = run(&room, "room/a", message("ping", b"")).await;
        assert_eq!(reply(&outcome), "pong");
    }
}

const CONN: &str = "c-0123456789abcdef0123456789abcdef";

fn connection(event: pb::connection_input::Event) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Connection(pb::ConnectionInput {
            connection: CONN.into(),
            protocol: pb::ConnectionProtocol::Websocket as i32,
            route: "/room/{key}/ws".into(),
            event: Some(event),
            ..Default::default()
        })),
    }
}

fn open(query: &str, subprotocols: &[&str]) -> pb::Input {
    connection(pb::connection_input::Event::Open(pb::ConnectionOpen {
        request: Some(pb::HttpInput {
            method: "GET".into(),
            path: "/room/a/ws".into(),
            query: query.into(),
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(vec![])),
                })),
            }),
            ..Default::default()
        }),
        subprotocols: subprotocols.iter().map(|s| (*s).into()).collect(),
    }))
}

async fn run_full(program: &Program, actor: &str, input: pb::Input) -> kronik_runtime::TurnOutput {
    program
        .run(
            TurnRequest {
                actor: ActorRef::parse(actor).unwrap(),
                causal_key: kronik_core::causal::root("r".into()),
                logical_time_ms: 1_761_300_000_000,
                seed: [7; 32],
                input,
                limits: TurnLimits::default(),
                subject: None,
            },
            Arc::new(Map(BTreeMap::new())),
            None,
            None,
        )
        .await
        .unwrap()
}

/// M24 §2.4: a turn may use only the connections it holds; anything else
/// traps with CONNECTION_NOT_HELD. An empty broadcast does nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_operations_need_held_connections() {
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let outcome = run(&room, "room/a", message("kick", CONN.as_bytes())).await;
    assert_eq!(outcome.kind, pb::OutcomeKind::Trap as i32, "{outcome:?}");
    assert_eq!(outcome.error_code, "CONNECTION_NOT_HELD", "{outcome:?}");
    assert!(outcome.message.contains(CONN), "{outcome:?}");
    let out = run_full(&room, "room/a", message("say", b"hi")).await;
    assert!(out.committed(), "{:?}", out.outcome);
    assert!(out.connection_ops.is_empty());
}

/// M24 §2.3, §4.2: a connection input calls `connection-handler`. The open
/// turn's accept selects an offered subprotocol and sets the subject; its
/// welcome frame to the connection it opens takes seq 0. A refusal is an
/// HTTP response. A component without the export fails the turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_inputs_call_the_connection_handler() {
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let out = run_full(&room, "room/a", open("user=ada", &["x", "room.v1"])).await;
    assert!(out.committed(), "{:?}", out.outcome);
    let Some(pb::outcome::Output::Accept(accept)) = &out.outcome.output else {
        panic!("{:?}", out.outcome)
    };
    assert_eq!(accept.subprotocol, "room.v1");
    assert_eq!(accept.subject.as_deref(), Some("user:ada"));
    assert_eq!(accept.headers[0].name, "x-room");
    assert_eq!(out.connection_ops.len(), 1);
    assert_eq!(out.connection_ops[0].connections, [CONN]);
    assert_eq!(out.connection_ops[0].seqs, [0]);
    // The member was written in the same turn.
    assert!(out.writes.iter().any(|w| w.key == format!("member/{CONN}")));

    let out = run_full(&room, "room/a", open("user=eve&deny=1", &[])).await;
    assert!(out.committed());
    assert!(matches!(&out.outcome.output, Some(pb::outcome::Output::Http(h)) if h.status == 403));

    let out = run_full(&room, "room/a", open("user=eve&fail=1", &[])).await;
    assert_eq!(out.outcome.kind, pb::OutcomeKind::Failed as i32);
    assert!(out.connection_ops.is_empty() && out.writes.is_empty());

    // A frame and a close of a connection the actor does not hold (the
    // state view here has no rows): the frame's `echo` traps, the close
    // handler runs.
    let frame = connection(pb::connection_input::Event::Frame(pb::ConnectionFrame {
        seq: 0,
        frame: Some(pb::Frame {
            kind: pb::frame::Kind::Text as i32,
            data: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b"echo hi".to_vec())),
            }),
            ..Default::default()
        }),
    }));
    let out = run_full(&room, "room/a", frame.clone()).await;
    assert_eq!(
        out.outcome.error_code, "CONNECTION_NOT_HELD",
        "{:?}",
        out.outcome
    );
    let close = connection(pb::connection_input::Event::Close(pb::ConnectionClose {
        cause: pb::CloseCause::Restart as i32,
        code: 1012,
        ..Default::default()
    }));
    let out = run_full(&room, "room/a", close.clone()).await;
    assert!(out.committed(), "{:?}", out.outcome);
    let w = out
        .writes
        .iter()
        .find(|w| w.key == format!("close/{CONN}"))
        .unwrap();
    let Some(pb::sealable::Value::Plain(v)) = w.value.as_ref().and_then(|v| v.value.as_ref())
    else {
        panic!()
    };
    assert_eq!(v, b"host 1012 restart");

    // Code built for `actor` takes no connection input: a failed turn.
    let (_, counter) = code.add(COUNTER).unwrap();
    for input in [open("", &[]), frame, close] {
        let out = run_full(&counter, "counter/a", input).await;
        assert_eq!(out.outcome.kind, pb::OutcomeKind::Failed as i32);
        assert!(
            out.outcome.message.contains("does not handle connections"),
            "{:?}",
            out.outcome
        );
        assert_eq!(out.fuel_used, 0);
    }
}

/// Every released component of the compatibility corpus (built for 0.1.0)
/// passes the import check, links without the connection export, describes
/// and runs a turn under the 0.1.1 bindings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn released_components_link_and_run_under_the_new_bindings() {
    let code = store();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/compatibility/components");
    let mut seen = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let bytes = std::fs::read(&path).unwrap();
        let (_, program) = code
            .add(&bytes)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(!program.handles_connections(), "{}", path.display());
        let manifest = program.describe(TurnLimits::default()).await.unwrap();
        // The counters run a key-value turn here; the notes components need
        // an SQL host, and their SQL turns run in the scheduler's tests.
        if manifest.kind == "counter" {
            let outcome = run(&program, "counter/released", message("increment", b"")).await;
            assert_eq!(reply(&outcome), "1", "{}", path.display());
        } else {
            assert_eq!(manifest.kind, "notes", "{}", path.display());
        }
        seen += 1;
    }
    assert!(seen >= 5, "the corpus has {seen} components");
    // The committed notes guest (0.1.0, SQL) also links.
    let (_, notes) = code.add(NOTES).unwrap();
    assert!(!notes.handles_connections());
}
