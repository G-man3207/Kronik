//! M24 long-lived connections in the scheduler (docs/design/m24-connections.md):
//! deploy checks and route conflicts of connection routes, the turn path of
//! connection inputs and buffered operations (§4), and the hub (§5.2) with
//! recording transports: open, refuse and fail, frames in seq order,
//! ownership, broadcast, actor, client and host closes, dead letters and
//! resend, slow consumers, and the restart close after a crash.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::error::ErrorCode;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::{Recording, RecordingTransport};
use kronik_sched::{Ingress, Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");
const ROOM_BARE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/room-bare.wasm"
);

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start(dir: &Path) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    Proc { rt, node }
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

impl Proc {
    fn deploy(
        &self,
        path: &str,
        dry_run: bool,
    ) -> Result<kronik_sched::DeployResult, kronik_core::error::ApiError> {
        let bytes = std::fs::read(path).unwrap();
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), dry_run, owner))
    }
}

fn version(kind: &str, routes: &[(&str, &str)]) -> pb::KindVersion {
    pb::KindVersion {
        kind: kind.into(),
        manifest: Some(pb::Manifest {
            kind: kind.into(),
            schema_version: 0,
            routes: routes
                .iter()
                .map(|(method, pattern)| pb::Route {
                    method: (*method).into(),
                    pattern: (*pattern).into(),
                })
                .collect(),
            capabilities: vec![],
        }),
        ..Default::default()
    }
}

/// ADR 0113: a kind with WebSocket or SSE routes needs the
/// `connection-handler` export; deploy (and its dry run) refuse one
/// without it and change nothing. The room guest, which has it, deploys.
#[test]
fn connection_routes_need_the_connection_export() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    for dry_run in [true, false] {
        let err = p.deploy(ROOM_BARE, dry_run).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest, "{err}");
        assert_eq!(
            err.message,
            "kind room declares WebSocket or SSE routes but its component does not export \
             kronik:actor/connection-handler; build it with an SDK from v0.5"
        );
        assert!(!p.node.kind_exists("room"));
    }
    let deployed = p.deploy(ROOM, false).unwrap();
    assert!(p.node.kind_exists("room"));
    let methods: Vec<&str> = deployed
        .manifest
        .routes
        .iter()
        .map(|r| r.method.as_str())
        .collect();
    assert_eq!(methods, ["WEBSOCKET", "SSE", "GET", "POST"]);
    assert!(
        deployed
            .warnings
            .iter()
            .any(|w| w.contains("connection:send-now")),
        "{:?}",
        deployed.warnings
    );
    let (_, routes) = p.node.routes();
    assert!(
        routes
            .iter()
            .any(|r| r.kind == "room" && r.method == "WEBSOCKET" && r.pattern == "/room/{key}/ws")
    );
}

/// M24 §2.5: a WEBSOCKET route conflicts with a WEBSOCKET route on the same
/// pattern, an SSE route with an SSE or GET route; a WEBSOCKET and a GET
/// route (or SSE and HEAD) may share a pattern.
#[test]
fn connection_routes_conflict_with_the_routes_that_answer_the_same_requests() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(ROOM, false).unwrap();
    let check = |routes: &[(&str, &str)]| {
        p.node
            .check_set_routes(&[version("other", routes)])
            .err()
            .map(|e| e.code)
    };
    let conflict = Some(ErrorCode::RouteConflict);
    assert_eq!(check(&[("WEBSOCKET", "/room/{id}/ws")]), conflict);
    assert_eq!(check(&[("GET", "/room/{k}/events")]), conflict);
    assert_eq!(check(&[("SSE", "/room/{k}/{what}")]), conflict);
    assert_eq!(check(&[("SSE", "/room/{k}/events")]), conflict);
    assert_eq!(check(&[("GET", "/room/{k}/ws")]), None);
    assert_eq!(check(&[("HEAD", "/room/{k}/events")]), None);
    assert_eq!(check(&[("WEBSOCKET", "/room/{k}/events")]), None);
    assert_eq!(check(&[("POST", "/room/{k}/ws")]), None);
    // The room's own new code replaces its routes: no conflict with itself.
    assert_eq!(
        p.node
            .check_set_routes(&[version("room", &[("SSE", "/room/{key}/events")])])
            .err()
            .map(|e| e.code),
        None
    );
}

fn plain(subject: Option<&str>, b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: subject.map(String::from),
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

fn text_frame(t: &str) -> pb::Frame {
    pb::Frame {
        kind: pb::frame::Kind::Text as i32,
        data: plain(None, t.as_bytes()),
        ..Default::default()
    }
}

/// The upgrade request of `/room/<key>/ws?<query>`, as the gateway builds
/// it, offering the subprotocol `room.v1`.
fn open_request(key: &str, query: &str) -> pb::HttpInput {
    pb::HttpInput {
        method: "GET".into(),
        path: format!("/room/{key}/ws"),
        query: query.into(),
        params: vec![pb::Param {
            name: "key".into(),
            value: key.into(),
            sealed_value: None,
        }],
        headers: vec![pb::Header {
            name: "sec-websocket-protocol".into(),
            value: plain(None, b"room.v1"),
        }],
        route: "/room/{key}/ws".into(),
        ..Default::default()
    }
}

/// Text of a frame's data.
fn data(f: &pb::Frame) -> String {
    match f.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

fn reply(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    _ => String::new(),
                },
                _ => String::new(),
            }
        }
        _ => String::new(),
    }
}

impl Proc {
    /// Opens a WebSocket connection to room `key` and waits for its open
    /// turn.
    fn open(&self, key: &str, query: &str) -> (String, TurnResult) {
        let (id, waiter) = self
            .node
            .connection_open(
                ActorRef::parse(&format!("room/{key}")).unwrap(),
                open_request(key, query),
                pb::ConnectionProtocol::Websocket,
                None,
                None,
                false,
            )
            .unwrap();
        let r = self.rt.block_on(waiter.wait()).unwrap();
        (id, r)
    }

    /// Opens and attaches a recording transport.
    fn join(&self, key: &str, user: &str) -> (String, Arc<RecordingTransport>) {
        let (id, r) = self.open(key, &format!("user={user}"));
        assert!(r.committed(), "{r:?}");
        assert!(
            matches!(r.outcome.output, Some(pb::outcome::Output::Accept(_))),
            "{r:?}"
        );
        let t = RecordingTransport::attach(self.node.hub(), &id).unwrap();
        (id, t)
    }

    /// A message to an actor; its turn's result.
    fn send(&self, actor: &str, name: &str, body: &str) -> TurnResult {
        self.rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                pb::Message {
                    name: name.into(),
                    content_type: "text/plain".into(),
                    body: plain(None, body.as_bytes()),
                    blobs: vec![],
                    retained_compensation_source: None,
                },
                audit(),
                false,
                self.node.local_operator_authority().unwrap(),
            ))
            .unwrap()
            .unwrap()
    }

    /// An incoming frame on `conn`, admitted like the gateway's reader does.
    fn frame(&self, conn: &str, text: &str) {
        self.rt
            .block_on(self.node.hub().incoming(conn, text_frame(text)));
    }

    /// Waits until `f` holds (the turns of admitted inputs run on).
    fn until(&self, what: &str, f: impl Fn() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    fn row(&self, conn: &str) -> Option<kronik_store::db::ConnectionRow> {
        self.node.store().db().connection(conn).unwrap()
    }

    fn record(&self, lsn: u64) -> pb::TurnRecord {
        let c = self
            .rt
            .block_on(self.node.read_record(lsn))
            .unwrap()
            .unwrap();
        match c.record {
            Record::TurnRecord(t) => t,
            other => panic!("not a turn record: {other:?}"),
        }
    }
}

fn frames(r: &Recording) -> Vec<(u64, String)> {
    r.frames.iter().map(|(s, f)| (*s, data(f))).collect()
}

/// §4.2-§4.5: an accepted open records its accept and its welcome frame
/// (seq 0), the row appears, and the frames go out after the attach; a
/// frame turn's broadcast reaches every member in seq order; a refused or
/// failed open leaves no row and no dead letter.
#[test]
fn opens_frames_and_broadcasts_go_through_the_turn_and_the_hub() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(ROOM, false).unwrap();

    let (a, ta) = p.join("lobby", "ada");
    let row = p.row(&a).unwrap();
    assert_eq!(
        (row.actor.kind.as_str(), row.actor.key.as_str()),
        ("room", "lobby")
    );
    assert_eq!(row.subject.as_deref(), Some("user:ada"));
    assert_eq!(row.next_seq, 1);
    let open = p.record(row.opened_lsn);
    let Some(pb::outcome::Output::Accept(accept)) =
        open.outcome.as_ref().and_then(|o| o.output.clone())
    else {
        panic!("{open:?}")
    };
    assert_eq!(accept.subprotocol_index, Some(0), "room.v1, offered first");
    assert_eq!(accept.subject.as_deref(), Some("user:ada"));
    assert_eq!(open.connection_ops.len(), 1);
    assert_eq!(open.connection_ops[0].seqs, [0]);
    p.until("the welcome", || ta.recording().frames.len() == 1);
    assert!(
        frames(&ta.recording())[0]
            .1
            .contains("\"type\":\"welcome\"")
    );

    let (b, tb) = p.join("lobby", "bob");
    // Ada got `joined`; Bob his welcome.
    p.until("joined", || ta.recording().frames.len() == 2);
    assert!(frames(&ta.recording())[1].1.contains("\"joined\""));

    p.frame(&a, "say hello");
    p.until("the message", || {
        ta.recording().frames.len() == 3 && tb.recording().frames.len() == 2
    });
    let fa = frames(&ta.recording());
    let fb = frames(&tb.recording());
    assert_eq!(fa.iter().map(|f| f.0).collect::<Vec<_>>(), [0, 1, 2]);
    assert_eq!(fb.iter().map(|f| f.0).collect::<Vec<_>>(), [0, 1]);
    assert!(fa[2].1.contains("\"text\":\"hello\""), "{fa:?}");
    assert_eq!(fa[2].1, fb[1].1);
    // The frame input was tagged with the connection's subject.
    let row = p.row(&a).unwrap();
    assert_eq!(row.frames_in, 1);

    // An HTTP turn's broadcast (§4.3: the response waits for the frames).
    let members = p.send("room/lobby", "members", "");
    assert!(reply(&members).contains(&a) && reply(&members).contains(&b));
    let r = p.send("room/lobby", "say", "from the operator");
    assert!(r.committed(), "{r:?}");
    p.until("the operator's message", || {
        ta.recording().frames.len() == 4
    });
    assert!(frames(&ta.recording())[3].1.contains("from the operator"));

    // Refused (403) and failed opens: no row, no dead letter, no connection.
    let (denied, r) = p.open("lobby", "user=eve&deny=1");
    assert!(r.committed());
    assert!(matches!(&r.outcome.output, Some(pb::outcome::Output::Http(h)) if h.status == 403));
    assert!(p.row(&denied).is_none());
    assert!(RecordingTransport::attach(p.node.hub(), &denied).is_err());
    let (failed, r) = p.open("lobby", "user=eve&fail=1");
    assert!(!r.committed());
    assert_eq!(r.outcome.error_code, "TURN_FAILED");
    assert!(p.row(&failed).is_none());
    assert!(p.node.store().db().dead_letters(0, 10).unwrap().is_empty());
    assert_eq!(p.node.hub().live(), 2);
}

/// ADR 0114: only the owner may use a connection; another actor's id traps
/// with CONNECTION_NOT_HELD. The failed frame turn is a dead letter, and
/// its resend runs the same frame again as a new root input (§4.9).
#[test]
fn only_the_owner_uses_a_connection_and_failed_frames_are_dead_letters() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(ROOM, false).unwrap();
    let (a, ta) = p.join("lobby", "ada");
    let (other, _to) = p.join("kitchen", "bob");
    p.frame(&a, &format!("send-to {other} sneaky"));
    p.until("the dead letter", || {
        !p.node.store().db().dead_letters(0, 10).unwrap().is_empty()
    });
    let dl = p.node.store().db().dead_letters(0, 10).unwrap().remove(0);
    assert_eq!(dl.error_code, "CONNECTION_NOT_HELD");
    assert!(dl.message.contains(&other), "{}", dl.message);
    // Nothing reached the other connection, and the failed turn recorded
    // no operations.
    let t = p.record(dl.lsn);
    assert!(t.connection_ops.is_empty());
    // A made-up id traps the same way.
    p.frame(&a, "send-to c-00000000000000000000000000000000 x");
    p.until("the second dead letter", || {
        p.node.store().db().dead_letters(0, 10).unwrap().len() == 2
    });
    // Resend: a new root input of the same connection and frame.
    let r =
        p.rt.block_on(p.node.resend(
            dl.lsn,
            audit(),
            false,
            p.node.local_operator_authority().unwrap(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(r.outcome.error_code, "CONNECTION_NOT_HELD");
    let resent = p.record(r.turn_id.lsn);
    let Some(pb::input::Kind::Connection(c)) = resent.input.and_then(|i| i.kind) else {
        panic!("not a connection input")
    };
    assert_eq!(c.connection, a);
    assert_eq!(c.resend_of, format!("main:{}", dl.lsn));
    let dls = p.node.store().db().dead_letters(0, 10).unwrap();
    assert_eq!(dls[0].resent_as, Some(r.turn_id.lsn));
    // Resends are not counted as frames.
    assert_eq!(p.row(&a).unwrap().frames_in, 2);
    assert_eq!(ta.recording().frames.len(), 1, "only the welcome");
}

/// §4.8: every accepted connection gets exactly one close input: the
/// actor's close (after its frames), the client's, and a slow consumer's.
#[test]
fn actor_client_and_host_closes_are_admitted_once() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy(ROOM, false).unwrap();
    let (a, ta) = p.join("lobby", "ada");
    let (b, tb) = p.join("lobby", "bob");
    let (c, tc) = p.join("lobby", "cid");

    // The actor's close: `echo` first, then `bye` closes after it.
    p.frame(&a, "echo first");
    p.frame(&a, "bye");
    p.until("ada's close", || {
        p.row(&a).is_some_and(|r| r.closed_lsn.is_some())
    });
    let rec = ta.recording();
    assert_eq!(rec.closed, Some((1000, "bye".into())));
    assert!(frames(&rec).iter().any(|f| f.1 == "first"));
    let row = p.row(&a).unwrap();
    assert_eq!(row.cause, Some(pb::CloseCause::Actor as i32));
    assert_eq!(row.frames_written, Some(rec.frames.len() as u64));
    assert!(row.closing_lsn.is_some());

    // The client's close, with its code and reason.
    tb.client_close(Some((1001, "tab closed".into())));
    p.until("bob's close", || {
        p.row(&b).is_some_and(|r| r.closed_lsn.is_some())
    });
    let row = p.row(&b).unwrap();
    assert_eq!(
        (row.cause, row.code),
        (Some(pb::CloseCause::Client as i32), Some(1001))
    );
    let closes = reply(&p.send("room/lobby", "closes", ""));
    assert!(closes.contains(&format!("{a} actor 1000 bye")), "{closes}");
    assert!(
        closes.contains(&format!("{b} client 1001 tab closed")),
        "{closes}"
    );
    // A second report of the same end changes nothing.
    tb.client_close(None);

    // A slow consumer: it stops reading, the queue passes 1 MiB, and the
    // host closes it (1008) with its frames written so far.
    tc.stall(true);
    let big = "x".repeat(60 << 10);
    for _ in 0..20 {
        let r = p.send("room/lobby", "say", &big);
        assert!(r.committed(), "{r:?}");
    }
    p.until("cid's close", || {
        p.row(&c).is_some_and(|r| r.closed_lsn.is_some())
    });
    let row = p.row(&c).unwrap();
    assert_eq!(row.cause, Some(pb::CloseCause::SlowConsumer as i32));
    assert_eq!(row.code, Some(1008));
    assert_eq!(tc.recording().closed, Some((1008, "slow-consumer".into())));
    assert_eq!(row.frames_written, Some(tc.recording().frames.len() as u64));
    // The closes ran the close handler: no member is left.
    p.until("no member", || {
        reply(&p.send("room/lobby", "members", "")).is_empty()
    });
    assert_eq!(p.node.hub().live(), 0);
    assert_eq!(p.node.store().db().open_connections().unwrap().len(), 0);
    assert!(p.node.store().db().dead_letters(0, 10).unwrap().is_empty());
}

/// §4.8: after a crash every connection still open in state.db gets a host
/// close with the reason `restart` (1012), frames written unknown and the
/// log's last LSN at the start, before the node takes new inputs.
#[test]
fn a_restart_closes_every_connection_the_last_process_held() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = {
        let p = start(dir.path());
        p.deploy(ROOM, false).unwrap();
        let (a, _ta) = p.join("lobby", "ada");
        let (b, _tb) = p.join("kitchen", "bob");
        p.frame(&a, "say hi");
        p.until("the message", || {
            p.row(&a).is_some_and(|r| r.frames_in == 1)
        });
        (a, b)
        // The runtime drops here: a crash.
    };
    let p = start(dir.path());
    let last = p.node.applied_lsn();
    p.until("the restart closes", || {
        p.node.store().db().open_connections().unwrap().is_empty()
    });
    for id in [&a, &b] {
        let row = p.row(id).unwrap();
        assert_eq!(row.cause, Some(pb::CloseCause::Restart as i32), "{row:?}");
        assert_eq!(row.code, Some(1012));
        assert_eq!(row.frames_written, None);
        assert!(row.restart_after_lsn.is_some_and(|l| l <= last), "{row:?}");
        let close = p.record(row.closed_lsn.unwrap());
        assert!(close.outcome.unwrap().kind == pb::OutcomeKind::Committed as i32);
    }
    let closes = reply(&p.send("room/lobby", "closes", ""));
    assert!(
        closes.contains(&format!("{a} host 1012 restart")),
        "{closes}"
    );
    // The close turn kept the connection's subject (§4.10).
    let row = p.row(&a).unwrap();
    let close = p.record(row.closed_lsn.unwrap());
    let Some(pb::input::Kind::Connection(c)) = close.input.and_then(|i| i.kind) else {
        panic!()
    };
    let Some(pb::connection_input::Event::Close(cl)) = c.event else {
        panic!()
    };
    assert_eq!(
        cl.reason.and_then(|r| r.subject).as_deref(),
        Some("user:ada")
    );
    // New connections open as usual.
    let (_n, tn) = p.join("lobby", "ada");
    p.until("the new welcome", || tn.recording().frames.len() == 1);
    // The HTTP ingress path is unaffected by connections.
    let r = p.rt.block_on(async {
        match p
            .node
            .ingress(
                ActorRef::parse("room/lobby").unwrap(),
                pb::HttpInput {
                    method: "GET".into(),
                    path: "/room/lobby/seq".into(),
                    params: vec![
                        pb::Param {
                            name: "key".into(),
                            value: "lobby".into(),
                            sealed_value: None,
                        },
                        pb::Param {
                            name: "op".into(),
                            value: "seq".into(),
                            sealed_value: None,
                        },
                    ],
                    route: "/room/{key}/{op}".into(),
                    ..Default::default()
                },
                None,
            )
            .unwrap()
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
            Ingress::Done(r) => *r,
        }
    });
    assert_eq!(reply(&r), "1");
}
