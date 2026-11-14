//! Long-lived connections in replay and the behavior diff (M24,
//! docs/design/m24-connections.md §7, ADR 0116; the `cargo test` part of
//! criterion 2 in §18). A session of the room guest is recorded through the
//! hub with recording transports: three WebSocket clients and an SSE
//! follower, 30 `say` frames, a `stream 3` whose frames go out with
//! `send-now`, a client that vanishes, one that is kicked
//! (an actor close), one that says `bye`, an HTTP `say`, and a restart,
//! which closes the follower. Then:
//!
//! - identity replay is empty in isolated, continuous and both modes, and
//!   its diff is the same byte for byte with 1, 4 and 16 workers;
//! - the room with a changed message format (`room-fmt2.wasm`) shows changed
//!   outgoing frames and nothing else, and its diff matches the schema;
//! - a fork that refuses every open (`room-refuse.wasm`) shows the changed
//!   open answers, and continuous replay skips the frames and closes of the
//!   connections it never accepted (§7.2).
//!
//! The session's `stream 3` sends three frames with `send-now`: identity
//! replay answers them from the recording.

// Test helpers may unwrap; the shared harness's HTTP servers use std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_fork::diff::{DiffOptions, FrameInputs, Mode};
use kronik_fork::{ForkKind, ProductionIndex, ReplayOutput, ReplaySetup, config_at, fork_kinds};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::TurnLimits;
use kronik_sched::connections::RecordingTransport;
use kronik_sched::{Ingress, NodeConfig};
use serde_json::Value;

/// The said messages carry this word: a test checks where it may appear.
const WORD: &str = "quokka";

fn config() -> NodeConfig {
    NodeConfig {
        concurrency: 8,
        ..NodeConfig::default()
    }
}

fn plain_as(subject: Option<&str>, b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.map(str::to_owned),
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

/// The request that opens `/room/<key>/ws` (WebSocket, offering `room.v1`)
/// or `/room/<key>/events` (SSE), as the gateway builds it.
fn open_request(key: &str, query: &str, protocol: pb::ConnectionProtocol) -> pb::HttpInput {
    let (path, route, headers) = match protocol {
        pb::ConnectionProtocol::Sse => (
            format!("/room/{key}/events"),
            "/room/{key}/events",
            Vec::new(),
        ),
        _ => (
            format!("/room/{key}/ws"),
            "/room/{key}/ws",
            vec![pb::Header {
                name: "sec-websocket-protocol".into(),
                value: plain_as(None, b"room.v1"),
            }],
        ),
    };
    pb::HttpInput {
        method: "GET".into(),
        path,
        query: query.into(),
        params: vec![pb::Param {
            name: "key".into(),
            value: key.into(),
            sealed_value: None,
        }],
        headers,
        route: route.into(),
        ..Default::default()
    }
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

/// The room's sequence: how many messages it has stored.
fn room_seq(p: &Proc) -> u64 {
    p.node
        .store()
        .db()
        .kv_get("room", "lobby", "seq")
        .unwrap()
        .and_then(|v| String::from_utf8(v).ok()?.parse().ok())
        .unwrap_or(0)
}

/// Whether `conn`'s close input is applied.
fn closed(p: &Proc, conn: &str) -> bool {
    p.node
        .store()
        .db()
        .connection_any(conn)
        .unwrap()
        .is_some_and(|r| r.closed_lsn.is_some())
}

/// Opens a connection of `user` to room `lobby` and attaches a recording
/// transport.
fn join(
    p: &Proc,
    user: &str,
    protocol: pb::ConnectionProtocol,
) -> (String, Arc<RecordingTransport>) {
    let (id, waiter) = p
        .node
        .connection_open(
            ActorRef::parse("room/lobby").unwrap(),
            open_request("lobby", &format!("user={user}"), protocol),
            protocol,
            None,
            None,
            false,
        )
        .unwrap();
    let r = p.rt.block_on(waiter.wait()).unwrap();
    assert!(
        matches!(r.outcome.output, Some(pb::outcome::Output::Accept(_))),
        "{r:?}"
    );
    let t = RecordingTransport::attach(p.node.hub(), &id).unwrap();
    (id, t)
}

/// A text frame from the client of `conn`, admitted as the gateway does.
fn frame(p: &Proc, conn: &str, text: &str) {
    p.rt.block_on(p.node.hub().incoming(
        conn,
        pb::Frame {
            kind: pb::frame::Kind::Text as i32,
            data: plain_as(None, text.as_bytes()),
            ..Default::default()
        },
    ));
}

/// `POST /room/lobby/say` with `text`.
fn http_say(p: &Proc, text: &str) {
    let input = pb::HttpInput {
        method: "POST".into(),
        path: "/room/lobby/say".into(),
        params: vec![pb::Param {
            name: "key".into(),
            value: "lobby".into(),
            sealed_value: None,
        }],
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(
                plain_as(None, text.as_bytes()).unwrap(),
            )),
        }),
        route: "/room/{key}/say".into(),
        ..Default::default()
    };
    let r = match p
        .node
        .ingress(ActorRef::parse("room/lobby").unwrap(), input, None)
        .unwrap()
    {
        Ingress::Started(w) | Ingress::Joined(w) => p.rt.block_on(w.wait()).unwrap(),
        Ingress::Done(r) => *r,
    };
    assert!(r.committed(), "{r:?}");
}

/// The recorded session (see the module comment). Returns the restarted
/// node, the fork point before the session, and the connection ids.
fn session(dir: &Path) -> (Proc, Lsn, Vec<String>) {
    use pb::ConnectionProtocol::{Sse, Websocket};
    let (fork_lsn, ids) = {
        let p = Proc::open(dir, config());
        p.deploy("room");
        p.rt.block_on(p.node.grant(
            "room",
            "connection:send-now",
            None,
            None,
            kronik_effects::InForks::default(),
            audit(),
            false,
            p.owner(),
        ))
        .unwrap();
        let fork_lsn = p.settle();
        let (ada, ta) = join(&p, "ada", Websocket);
        let (bob, _tb) = join(&p, "bob", Websocket);
        let (cid, tc) = join(&p, "cid", Websocket);
        let clients = [&ada, &bob, &cid];
        let mut follower = None;
        for i in 0..30u64 {
            frame(&p, clients[i as usize % 3], &format!("say {WORD}-{i}"));
            until("the message", || room_seq(&p) == i + 1);
            // The follower joins with the history so far: its open sends
            // the stored messages.
            if i == 9 {
                follower = Some(join(&p, "dee", Sse));
            }
        }
        let (dee, _td) = follower.unwrap();
        // Three frames with send-now, then a buffered one (criterion 2).
        frame(&p, &ada, "stream 3");
        until("the stream", || {
            ta.recording().frames.iter().any(|(_, f)| {
                f.data.as_ref().and_then(|d| d.value.as_ref())
                    == Some(&pb::sealable::Value::Plain(b"done 3".to_vec()))
            })
        });
        http_say(&p, "lemur");
        // cid vanishes, ada kicks bob, then says bye.
        tc.client_close(None);
        until("cid's close", || closed(&p, &cid));
        frame(&p, &ada, &format!("kick {bob}"));
        until("bob's close", || closed(&p, &bob));
        frame(&p, &ada, "bye");
        until("ada's close", || closed(&p, &ada));
        p.settle();
        (fork_lsn, vec![ada, bob, cid, dee])
        // The runtime drops here: a crash, with the follower still open.
    };
    let p = Proc::open(dir, config());
    until("the restart close", || closed(&p, &ids[3]));
    p.settle();
    assert!(p.node.store().db().open_connections().unwrap().is_empty());
    (p, fork_lsn, ids)
}

/// A replay of main's window after `fork_lsn`, with the room's code from
/// `wasm` when given, as `kronik propose` runs it.
fn replay(
    p: &Proc,
    wasm: Option<&str>,
    fork_lsn: Lsn,
    options: &DiffOptions,
    workers: usize,
) -> ReplayOutput {
    let to = p.settle();
    let node = p.node.clone();
    let original = node.local_operator_authority().unwrap();
    p.rt.block_on(async move {
        let index = Arc::new(
            ProductionIndex::load_from(node.reader(), None, fork_lsn, to)
                .await
                .unwrap(),
        );
        let mut new = Vec::new();
        if let Some(w) = wasm {
            let bytes = std::fs::read(guest(w)).unwrap();
            let (hash, program) = node.code().add(&bytes).unwrap();
            let m = program.describe(TurnLimits::default()).await.unwrap();
            new.push((
                m.kind.clone(),
                ForkKind {
                    hash,
                    program,
                    schema_version: m.schema_version,
                },
            ));
        }
        let code = node.code().clone();
        let fc = fork_kinds(
            &index,
            fork_lsn,
            |h| code.get(h).map_err(|e| e.to_string()),
            &new,
        )
        .unwrap();
        let config = config_at(&index, fork_lsn);
        let mut setup = ReplaySetup::new(
            "f-test".into(),
            index.clone(),
            fc.kinds,
            config,
            node.secrets().cloned(),
            original,
        );
        setup.record_limit = node.turn_record_limit();
        kronik_fork::run(
            node.env(),
            Arc::new(setup),
            options,
            workers,
            None,
            fc.before,
            fc.after,
            &[],
        )
        .await
        .unwrap()
    })
}

fn opts(mode: Mode) -> DiffOptions {
    DiffOptions {
        mode,
        ..DiffOptions::default()
    }
}

/// The production turn records of the window, by LSN.
fn window(p: &Proc, fork_lsn: Lsn) -> BTreeMap<Lsn, pb::TurnRecord> {
    let to = p.settle();
    ((fork_lsn + 1)..=to)
        .filter_map(
            |lsn| match p.rt.block_on(p.node.read_record(lsn)).unwrap()?.record {
                Record::TurnRecord(t) => Some((lsn, t)),
                _ => None,
            },
        )
        .collect()
}

/// The root inputs of the window whose turns sent a `message` event: the
/// ones a changed message format changes.
fn message_roots(turns: &BTreeMap<Lsn, pb::TurnRecord>) -> BTreeSet<Lsn> {
    let mut roots: BTreeMap<&str, Lsn> = BTreeMap::new();
    let mut sent: BTreeSet<&str> = BTreeSet::new();
    for (lsn, t) in turns {
        let Some(k) = &t.causal_key else { continue };
        if k.path.is_empty() {
            roots.insert(&k.root, *lsn);
        }
        let message = t.connection_ops.iter().any(|op| {
            matches!(&op.op, Some(pb::connection_op::Op::Send(f))
                if f.kind == pb::frame::Kind::Event as i32 && f.event == "message")
        });
        if message {
            sent.insert(&k.root);
        }
    }
    sent.iter().filter_map(|r| roots.get(r).copied()).collect()
}

/// The diff document against `docs/reference/diff-v1.schema.json`.
fn check_schema(what: &str, v: &Value) {
    const URL: &str = "file:///kronik/docs/reference/diff-v1.schema.json";
    let mut compiled = boon::Schemas::new();
    let mut c = boon::Compiler::new();
    c.set_default_draft(boon::Draft::V2020_12);
    c.add_resource(
        URL,
        serde_json::from_str(include_str!("../../../docs/reference/diff-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let schema = c.compile(URL, &mut compiled).unwrap();
    if let Err(e) = compiled.validate(v, schema) {
        panic!(
            "{what} does not match the diff schema:\n{e:#}\n{}",
            serde_json::to_string_pretty(v).unwrap()
        );
    }
}

fn json(out: &ReplayOutput) -> Value {
    serde_json::from_slice(&out.bytes).unwrap()
}

/// §7.6 and criterion 2: identity replay of the session is empty in every
/// mode, the `frames` section counts what it compared, and the diff is the
/// same byte for byte with 1, 4 and 16 workers. Every input of a connection
/// replays under the connection's subject (§4.10), as the node ran it: a
/// frame or close turn without it would write untagged state.
#[test]
fn identity_replay_of_a_recorded_session_is_empty() {
    let dir = tempdir();
    let (p, fork_lsn, ids) = session(dir.path());
    let index =
        p.rt.block_on(ProductionIndex::load_from(
            p.node.reader(),
            None,
            fork_lsn,
            p.settle(),
        ))
        .unwrap();
    let users: BTreeMap<&str, &str> = ids
        .iter()
        .map(String::as_str)
        .zip(["ada", "bob", "cid", "dee"])
        .collect();
    let mut subjects = 0;
    for r in &index.roots {
        let Some(c) = kronik_proto::connection::input(Some(&r.input)) else {
            continue;
        };
        if matches!(c.event, Some(pb::connection_input::Event::Open(_))) {
            // The opens' requests had no subject; the accept set it.
            assert_eq!(r.subject, None, "{}", r.stratum);
            continue;
        }
        let user = users[c.connection.as_str()];
        assert_eq!(
            r.subject.as_deref(),
            Some(format!("user:{user}").as_str()),
            "{}",
            r.stratum
        );
        subjects += 1;
    }
    assert_eq!(subjects, 37);
    // 4 opens; 30 says, the stream, the kick and the bye; 4 closes (client,
    // actor twice, restart). The HTTP say sent frames, so it is compared too.
    let inputs = FrameInputs {
        open: 4,
        frame: 33,
        close: 4,
    };
    for mode in [Mode::Isolated, Mode::Continuous, Mode::Both] {
        let out = replay(&p, None, fork_lsn, &opts(mode), 1);
        let d = &out.diff;
        let text = String::from_utf8_lossy(&out.bytes);
        assert!(!d.summary.changed, "{mode:?}: {text}");
        assert_eq!(d.summary.divergent_turns, 0, "{mode:?}: {text}");
        assert_eq!(d.summary.frames_changed, 0);
        let f = d.frames.as_ref().expect("a frames section");
        assert_eq!(f.inputs, inputs, "{mode:?}");
        assert_eq!(
            (f.changed, f.unchanged, f.skipped),
            (0, 42, 0),
            "{mode:?}: {text}"
        );
        assert!(f.items.is_empty());
        assert_eq!(
            (f.send_now.recorded, f.send_now.modeled),
            (3, 0),
            "{mode:?}"
        );
        assert!(f.sent.prod > 0);
        assert_eq!(f.sent.prod, f.sent.fork, "{mode:?}");
        let room = d.kinds.iter().find(|k| k.kind == "room").unwrap();
        let k = room.frames.expect("the room's frames");
        assert_eq!((k.unchanged, k.changed), (42, 0));
        assert!(d.samples.frames_changed.is_empty() && d.samples.frames_skipped.is_empty());
        check_schema(&format!("identity {mode:?}"), &json(&out));
    }
    let one = replay(&p, None, fork_lsn, &opts(Mode::Both), 1);
    for workers in [4, 16] {
        let again = replay(&p, None, fork_lsn, &opts(Mode::Both), workers);
        assert_eq!(again.bytes, one.bytes, "{workers} workers give other bytes");
    }
}

/// Criterion 2: the room with a changed message format (`body` instead of
/// `text`) changes the frames of exactly the inputs that sent a message,
/// each operation by the format change, and nothing else. Values with a
/// subject are redacted; `--summary` shows counts only.
#[test]
fn a_changed_message_format_shows_as_changed_outgoing_frames() {
    let dir = tempdir();
    let (p, fork_lsn, ids) = session(dir.path());
    let turns = window(&p, fork_lsn);
    let expected = message_roots(&turns);
    // 30 says, the HTTP say, and the follower's open with the history.
    assert_eq!(expected.len(), 32);
    for mode in [Mode::Isolated, Mode::Continuous, Mode::Both] {
        let out = replay(&p, Some("room-fmt2"), fork_lsn, &opts(mode), 4);
        let d = &out.diff;
        let text = String::from_utf8_lossy(&out.bytes);
        let f = d.frames.as_ref().expect("a frames section");
        assert_eq!(f.changed, expected.len() as u64, "{mode:?}: {text}");
        assert_eq!(f.unchanged + f.changed, 42, "{mode:?}");
        assert_eq!(f.skipped, 0);
        assert_eq!(d.summary.frames_changed, f.changed);
        assert!(d.summary.changed);
        let items: BTreeSet<Lsn> = f.items.iter().map(|i| i.root_lsn).collect();
        assert_eq!(items, expected, "{mode:?}");
        for item in &f.items {
            assert!(item.open.is_none(), "{item:?}");
            assert!(!item.frames.is_empty(), "{item:?}");
            for c in &item.frames {
                assert_eq!(c.change, "changed", "{c:?}");
                assert_eq!(c.kind.prod.as_deref(), Some("event"));
                assert_eq!(c.kind.fork.as_deref(), Some("event"));
                assert!(c.event.is_none() && c.code.is_none() && c.send_now.is_none());
                assert!(c.targets > 0 && !c.connections.is_empty());
                let ops: Vec<(&str, &str)> = c
                    .data
                    .iter()
                    .map(|o| (o.op.as_ref(), o.path.as_str()))
                    .collect();
                assert_eq!(ops, [("add", "/body"), ("remove", "/text")], "{c:?}");
                // A WebSocket client's message has the connection's subject:
                // redacted. The HTTP say has none, and neither has the
                // follower's open (its request had none): shown.
                let value = &c.data[0].fork;
                if item.input.starts_with("connection frame") {
                    assert_eq!(value["redacted"], true, "{c:?}");
                } else if item.input.starts_with("POST") {
                    assert_eq!(value, "lemur");
                } else {
                    assert!(value.as_str().is_some_and(|v| v.starts_with(WORD)), "{c:?}");
                }
            }
            if item.input.starts_with("connection frame") {
                let shown = serde_json::to_string(item).unwrap();
                assert!(!shown.contains(WORD), "{shown}");
            }
        }
        // The origins are those inputs' turns, and nothing else changed.
        assert_eq!(d.summary.origins, f.changed, "{mode:?}: {text}");
        assert_eq!(d.summary.consequences, 0);
        assert_eq!(d.responses.changed, 0);
        assert!(d.state.isolated.is_empty() && d.state.continuous.is_empty());
        assert!(d.cumulative.items.is_empty());
        assert_eq!(d.errors.introduced, 0);
        assert_eq!(d.effects.added + d.effects.removed + d.effects.changed, 0);
        let mut causes: Vec<&str> = d.causes.iter().map(|c| c.input.as_str()).collect();
        causes.sort_unstable();
        assert_eq!(
            causes,
            [
                "POST /room/{key}/say",
                "connection frame WEBSOCKET /room/{key}/ws",
                "connection open SSE /room/{key}/events",
            ]
        );
        check_schema(&format!("fmt2 {mode:?}"), &json(&out));

        let md = kronik_fork::markdown::render(d, None);
        assert!(md.contains("\n## Frames\n"), "{md}");
        assert!(md.contains("`/body`") && md.contains("`/text`"), "{md}");
        let summary = kronik_fork::markdown::summary(d, None, &[]);
        assert!(
            summary.contains("| Frames | 32 changed, 10 unchanged, 0 skipped"),
            "{summary}"
        );
        for secret in ids
            .iter()
            .map(String::as_str)
            .chain([WORD, "lemur", "/body"])
        {
            assert!(!summary.contains(secret), "{secret} in {summary}");
        }
    }
    // The diff with its items is the same byte for byte with 1, 4 and 16
    // workers too.
    let four = replay(&p, Some("room-fmt2"), fork_lsn, &opts(Mode::Both), 4);
    for workers in [1, 16] {
        let again = replay(&p, Some("room-fmt2"), fork_lsn, &opts(Mode::Both), workers);
        assert_eq!(
            again.bytes, four.bytes,
            "{workers} workers give other bytes"
        );
    }
}

/// §7.2: a fork whose room refuses every open holds none of production's
/// connections. Continuous replay runs none of their frames and closes: it
/// counts them as skipped, and their production turns are missing. Isolated
/// replay runs them against production's state, which holds the
/// connections, so only the opens' answers change.
#[test]
fn a_fork_that_refuses_the_opens_skips_their_connections() {
    let dir = tempdir();
    let (p, fork_lsn, _) = session(dir.path());
    let out = replay(
        &p,
        Some("room-refuse"),
        fork_lsn,
        &opts(Mode::Continuous),
        1,
    );
    let d = &out.diff;
    let text = String::from_utf8_lossy(&out.bytes);
    let f = d.frames.as_ref().expect("a frames section");
    // Every frame and close input of the window: their opens are in it.
    assert_eq!(f.skipped, 37, "{text}");
    assert_eq!(d.samples.frames_skipped.len(), 20);
    assert!(
        d.samples
            .frames_skipped
            .iter()
            .all(|t| t.starts_with("main:"))
    );
    assert!(d.summary.changed);
    assert!(d.summary.divergent_turns >= 37, "{text}");
    let opens: Vec<_> = f.items.iter().filter_map(|i| i.open.as_ref()).collect();
    assert_eq!(opens.len(), 4, "{text}");
    for o in opens {
        assert_eq!((o.prod.as_str(), o.fork.as_str()), ("accept", "refuse 403"));
    }
    check_schema("refuse continuous", &json(&out));
    let md = kronik_fork::markdown::render(d, None);
    assert!(md.contains("  - open: accept → refuse 403"), "{md}");

    let out = replay(&p, Some("room-refuse"), fork_lsn, &opts(Mode::Isolated), 1);
    let f = out.diff.frames.as_ref().expect("a frames section");
    assert_eq!(f.skipped, 0);
    // The opens, each without its welcome or history and `joined`; every
    // other input sends what production sent.
    assert_eq!(f.changed, 4, "{}", String::from_utf8_lossy(&out.bytes));
    assert!(f.items.iter().all(|i| i.open.is_some()));
    check_schema("refuse isolated", &json(&out));
}
