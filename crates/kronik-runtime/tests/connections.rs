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

/// The connections import is linked: the room's `say` reaches the host's
/// `connections.broadcast`, which traps until its slice lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_connections_import_is_linked() {
    let code = store();
    let (_, room) = code.add(ROOM).unwrap();
    let outcome = run(&room, "room/a", message("say", b"hi")).await;
    assert_eq!(outcome.kind, pb::OutcomeKind::Trap as i32, "{outcome:?}");
    assert_eq!(outcome.error_code, "NOT_IMPLEMENTED", "{outcome:?}");
    assert!(
        outcome.message.contains("connections.broadcast"),
        "{outcome:?}"
    );
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
