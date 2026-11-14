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

/// An open whose client offers `subprotocols` in one
/// `Sec-WebSocket-Protocol` header, as browsers send them.
fn open(query: &str, subprotocols: &[&str]) -> pb::Input {
    let headers = if subprotocols.is_empty() {
        vec![]
    } else {
        vec![pb::Header {
            name: "Sec-WebSocket-Protocol".into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(
                    subprotocols.join(" , ").into_bytes(),
                )),
            }),
        }]
    };
    connection(pb::connection_input::Event::Open(pb::ConnectionOpen {
        request: Some(pb::HttpInput {
            method: "GET".into(),
            path: "/room/a/ws".into(),
            query: query.into(),
            headers,
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(vec![])),
                })),
            }),
            ..Default::default()
        }),
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

/// A state view with live connections: id -> (owned by the turn's actor,
/// next seq).
struct Live(BTreeMap<String, (bool, u64)>);

impl StateView for Live {
    fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn keys(&self, _prefix: &str) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, id: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(self
            .0
            .get(id)
            .map(|(own, next_seq)| kronik_runtime::ConnectionView {
                owner_is_self: *own,
                protocol: pb::ConnectionProtocol::Websocket,
                next_seq: *next_seq,
                closing: false,
            }))
    }
}

async fn run_with(program: &Program, input: pb::Input, live: &Live) -> kronik_runtime::TurnOutput {
    program
        .run(
            TurnRequest {
                actor: ActorRef::parse("room/a").unwrap(),
                causal_key: kronik_core::causal::root("r".into()),
                logical_time_ms: 1_761_300_000_000,
                seed: [7; 32],
                input,
                limits: TurnLimits::default(),
                subject: None,
            },
            Arc::new(Live(live.0.clone())),
            None,
            None,
        )
        .await
        .unwrap()
}

/// ADR 0114 (amended 2026-11-13 and 2026-11-14): the turn's own live
/// connection takes the next seq; any other id, one that no live connection
/// has or another actor's live connection, is recorded as dropped, without
/// a seq, and the turn commits; a malformed id traps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_connections_are_held_dead_ids_are_dropped() {
    const MINE: &str = "c-11111111111111111111111111111111";
    const THEIRS: &str = "c-22222222222222222222222222222222";
    const GONE: &str = "c-33333333333333333333333333333333";
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let live = Live(BTreeMap::from([
        (MINE.to_owned(), (true, 7)),
        (THEIRS.to_owned(), (false, 0)),
    ]));
    // A message `kick <conn>` closes `conn` (buffered).
    let out = run_with(&room, message("kick", MINE.as_bytes()), &live).await;
    assert!(out.committed(), "{:?}", out.outcome);
    assert_eq!(out.connection_ops.len(), 1);
    assert_eq!(out.connection_ops[0].connections, [MINE]);
    assert!(out.connection_ops[0].dropped.is_empty());

    let out = run_with(&room, message("kick", GONE.as_bytes()), &live).await;
    assert!(out.committed(), "{:?}", out.outcome);
    assert!(out.connection_ops[0].connections.is_empty());
    assert_eq!(out.connection_ops[0].dropped, [GONE]);
    assert!(out.connection_ops[0].seqs.is_empty());

    // Another actor's live connection: the turn reads only its own actor's
    // rows, so it is dropped like a dead id.
    let out = run_with(&room, message("kick", THEIRS.as_bytes()), &live).await;
    assert!(out.committed(), "{:?}", out.outcome);
    assert!(out.connection_ops[0].connections.is_empty());
    assert_eq!(out.connection_ops[0].dropped, [THEIRS]);
    assert!(out.connection_ops[0].seqs.is_empty());

    let out = run_with(&room, message("kick", b"c-not-an-id"), &live).await;
    assert_eq!(
        out.outcome.kind,
        pb::OutcomeKind::Trap as i32,
        "{:?}",
        out.outcome
    );
    assert_eq!(out.outcome.error_code, "TURN_FAILED", "{:?}", out.outcome);
    assert!(
        out.outcome.message.contains("is not a connection id"),
        "{:?}",
        out.outcome
    );

    // A broadcast splits its targets: live ones with seqs from next_seq,
    // dead ones dropped; the operator's `say` broadcasts to the members in
    // state, here none, which records nothing.
    let out = run_with(&room, message("say", b"hi"), &live).await;
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
    // `room.v1` was offered second: the record keeps its position only.
    assert_eq!(accept.subprotocol_index, Some(1));
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

    // A frame and a close of a connection without a live row (the state
    // view here has none): the frame's `echo` is recorded as dropped, the
    // close handler runs.
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
    assert!(out.committed(), "{:?}", out.outcome);
    assert_eq!(out.connection_ops.len(), 1);
    assert_eq!(
        out.connection_ops[0].dropped,
        [CONN],
        "no live row: dropped"
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

/// Counts the connection rows a turn looks up.
struct Counting(std::sync::atomic::AtomicUsize);

impl StateView for Counting {
    fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn keys(&self, _prefix: &str) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _id: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(None)
    }
}

/// Review M7: a broadcast past the per-turn target limit traps before it
/// looks up a single id, so a list of a hundred thousand made-up ids costs
/// no state reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broadcast_past_the_target_limit_traps_before_any_lookup() {
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let view = Arc::new(Counting(std::sync::atomic::AtomicUsize::new(0)));
    let out = room
        .run(
            TurnRequest {
                actor: ActorRef::parse("room/a").unwrap(),
                causal_key: kronik_core::causal::root("r".into()),
                logical_time_ms: 1_761_300_000_000,
                seed: [7; 32],
                input: message("spray", b"100001"),
                limits: TurnLimits {
                    fuel: 5_000_000_000,
                    ..TurnLimits::default()
                },
                subject: None,
            },
            view.clone(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        out.outcome.kind,
        pb::OutcomeKind::Trap as i32,
        "{:?}",
        out.outcome
    );
    assert!(
        out.outcome
            .message
            .contains("more than 100000 frame targets"),
        "{:?}",
        out.outcome
    );
    assert_eq!(view.0.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// Review L5: an open's accept sets at most 64 headers, of 16 KiB together;
/// one with more fails the open turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accept_with_too_many_headers_fails_the_open() {
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let out = run_full(&room, "room/a", open("headers=63", &[])).await;
    assert!(out.committed(), "{:?}", out.outcome);
    let out = run_full(&room, "room/a", open("headers=64", &[])).await;
    assert!(!out.committed(), "{:?}", out.outcome);
    assert!(out.outcome.message.contains("headers"), "{:?}", out.outcome);
}
