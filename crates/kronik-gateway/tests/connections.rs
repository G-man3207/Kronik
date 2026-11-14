//! M24: the gateway's connection path as a service function
//! (docs/design/m24-connections.md §5.1, §5.3, §5.4): classification, the
//! WebSocket handshake, the open turn's accept (101 with the selected
//! subprotocol and the actor's headers), refusals and failures, the caps,
//! and requests that are not for this path.

// Test helpers outside #[test] functions may unwrap too, and wait on the
// test runtime's clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use kronik_core::env::Env;
use kronik_gateway::{
    Gateway, GatewayConfig, HttpRequest, HttpResponse, RequestKind, TURN_ID_HEADER,
};
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::{ConnectionsConfig, RecordingTransport};
use kronik_sched::{Node, NodeConfig, start_local};

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

/// RFC 6455 §1.3's example key and the accept it gives.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

async fn node(connections: ConnectionsConfig) -> (tempfile::TempDir, Arc<Node>) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(
        env,
        dir.path(),
        NodeConfig {
            connections,
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let audit = pb::Audit {
        token_id: "t".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    };
    node.deploy(
        &std::fs::read(ROOM).unwrap(),
        audit,
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    (dir, node)
}

fn upgrade(path_and_query: &str, extra: &[(&str, &str)]) -> HttpRequest {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let mut headers = vec![
        ("host".to_owned(), "example.test".to_owned()),
        ("upgrade".to_owned(), "websocket".to_owned()),
        ("connection".to_owned(), "keep-alive, Upgrade".to_owned()),
        ("sec-websocket-version".to_owned(), "13".to_owned()),
        ("sec-websocket-key".to_owned(), KEY.to_owned()),
    ];
    for (n, v) in extra {
        headers.retain(|(h, _)| !h.eq_ignore_ascii_case(n));
        if !v.is_empty() {
            headers.push(((*n).to_owned(), (*v).to_owned()));
        }
    }
    HttpRequest {
        method: "GET".into(),
        path: path.into(),
        query: query.into(),
        headers,
        body: Vec::new(),
        peer: None,
    }
}

fn get(path_and_query: &str) -> HttpRequest {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    HttpRequest {
        method: "GET".into(),
        path: path.into(),
        query: query.into(),
        headers: vec![("accept".into(), "text/event-stream".into())],
        body: Vec::new(),
        peer: None,
    }
}

fn header<'a>(r: &'a HttpResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn code(r: &HttpResponse) -> String {
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    v["error"]["code"].as_str().unwrap().to_owned()
}

async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// §5.3: an accepted WebSocket answers 101 with the handshake, the
/// selected subprotocol (the recorded position in the offered list), the
/// actor's headers and the turn id; the frames of the open turn wait for
/// the transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_websocket_answers_101() {
    let (_dir, node) = node(ConnectionsConfig::default()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let req = upgrade(
        "/room/lobby/ws?user=ada",
        &[("sec-websocket-protocol", "chat.v2, room.v1")],
    );
    assert_eq!(gw.classify(&req), RequestKind::WebSocket);
    let answer = gw.open_connection(req).await;
    let r = &answer.response;
    assert_eq!(r.status, 101, "{r:?}");
    assert_eq!(header(r, "upgrade"), Some("websocket"));
    assert_eq!(header(r, "connection"), Some("Upgrade"));
    assert_eq!(header(r, "sec-websocket-accept"), Some(ACCEPT));
    assert_eq!(header(r, "sec-websocket-protocol"), Some("room.v1"));
    assert_eq!(header(r, "x-room"), Some("lobby"));
    assert!(header(r, TURN_ID_HEADER).unwrap().starts_with("main:"));
    assert_eq!(answer.protocol, Some(pb::ConnectionProtocol::Websocket));
    let conn = answer.connection.unwrap();
    let t = RecordingTransport::attach(node.hub(), &conn).unwrap();
    until("the welcome", || t.recording().frames.len() == 1).await;
    // The connection holds a subject from the accept.
    let row = node.store().db().connection(&conn).unwrap().unwrap();
    assert_eq!(row.subject.as_deref(), Some("user:ada"));

    // Offered nothing: none selected.
    let answer = gw
        .open_connection(upgrade("/room/lobby/ws?user=bob", &[]))
        .await;
    assert_eq!(answer.response.status, 101);
    assert_eq!(header(&answer.response, "sec-websocket-protocol"), None);
    node.hub().abandon(&answer.connection.unwrap());
}

/// §4.2, §5.3: a refusal is the actor's response, a failure TURN_FAILED;
/// neither leaves a connection. A bad handshake, a body, an unknown route
/// and a non-GET are refused before any turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_failures_and_bad_requests() {
    let (_dir, node) = node(ConnectionsConfig::default()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let answer = gw
        .open_connection(upgrade("/room/lobby/ws?user=eve&deny=1", &[]))
        .await;
    assert_eq!(answer.response.status, 403);
    assert_eq!(answer.response.body, b"denied");
    assert!(answer.connection.is_none());
    let answer = gw
        .open_connection(upgrade("/room/lobby/ws?user=eve&fail=1", &[]))
        .await;
    assert_eq!(answer.response.status, 500);
    assert_eq!(code(&answer.response), "TURN_FAILED");
    assert!(header(&answer.response, TURN_ID_HEADER).is_some());
    assert!(answer.connection.is_none());
    assert_eq!(node.hub().live(), 0);

    let turns = node.applied_lsn();
    for (what, req) in [
        (
            "no version",
            upgrade("/room/lobby/ws", &[("sec-websocket-version", "")]),
        ),
        (
            "an old version",
            upgrade("/room/lobby/ws", &[("sec-websocket-version", "8")]),
        ),
        (
            "a short key",
            upgrade("/room/lobby/ws", &[("sec-websocket-key", "c2hvcnQ=")]),
        ),
        (
            "a body",
            HttpRequest {
                body: b"x".to_vec(),
                ..upgrade("/room/lobby/ws", &[])
            },
        ),
        (
            "a content length",
            upgrade("/room/lobby/ws", &[("content-length", "3")]),
        ),
    ] {
        let answer = gw.open_connection(req).await;
        assert_eq!(answer.response.status, 400, "{what}");
        assert_eq!(code(&answer.response), "BAD_REQUEST", "{what}");
    }
    let answer = gw.open_connection(upgrade("/nowhere/ws", &[])).await;
    assert_eq!(code(&answer.response), "ROUTE_NOT_FOUND");
    // A GET route is not a connection route.
    let answer = gw.open_connection(get("/room/lobby/members")).await;
    assert_eq!(code(&answer.response), "BAD_REQUEST");
    assert_eq!(node.applied_lsn(), turns, "no turn ran");
}

/// §5.1: a GET that an SSE route answers is classified SSE, the most
/// specific of the GET and SSE routes; the plain service function refuses
/// connection requests, and an SSE accept answers the event stream's
/// headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classification_and_the_service_function() {
    let (_dir, node) = node(ConnectionsConfig::default()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    assert_eq!(gw.classify(&get("/room/lobby/events")), RequestKind::Sse);
    assert_eq!(gw.classify(&get("/room/lobby/members")), RequestKind::Http);
    let r = gw.handle(get("/room/lobby/events")).await;
    assert_eq!((r.status, code(&r)), (400, "BAD_REQUEST".to_owned()));
    let r = gw.handle(upgrade("/room/lobby/ws", &[])).await;
    assert_eq!((r.status, code(&r)), (400, "BAD_REQUEST".to_owned()));
    let r = gw.handle(get("/room/lobby/seq")).await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"0".as_slice()));

    let answer = gw.open_connection(get("/room/lobby/events?user=ada")).await;
    let r = &answer.response;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(header(r, "content-type"), Some("text/event-stream"));
    assert_eq!(header(r, "cache-control"), Some("no-store"));
    assert_eq!(answer.protocol, Some(pb::ConnectionProtocol::Sse));
    node.hub().abandon(&answer.connection.unwrap());
}

/// §5.11: the caps answer 503 CONNECTION_LIMIT with retry-after before any
/// turn; a closed connection gives its slot back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_caps_answer_connection_limit() {
    let (_dir, node) = node(ConnectionsConfig {
        max_per_actor: 1,
        ..ConnectionsConfig::default()
    })
    .await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let first = gw
        .open_connection(upgrade("/room/lobby/ws?user=ada", &[]))
        .await;
    let conn = first.connection.unwrap();
    let t = RecordingTransport::attach(node.hub(), &conn).unwrap();
    let turns = node.applied_lsn();
    let second = gw
        .open_connection(upgrade("/room/lobby/ws?user=bob", &[]))
        .await;
    assert_eq!(second.response.status, 503);
    assert_eq!(code(&second.response), "CONNECTION_LIMIT");
    assert_eq!(header(&second.response, "retry-after"), Some("5"));
    assert_eq!(node.applied_lsn(), turns, "no turn ran");
    // Another room is another actor.
    let other = gw
        .open_connection(upgrade("/room/kitchen/ws?user=bob", &[]))
        .await;
    assert_eq!(other.response.status, 101);
    node.hub().abandon(&other.connection.unwrap());
    // The first closes: its slot is free again.
    t.client_close(Some((1000, String::new())));
    until("the slot", || node.hub().live() <= 1).await;
    let third = gw
        .open_connection(upgrade("/room/lobby/ws?user=cid", &[]))
        .await;
    assert_eq!(third.response.status, 101);
}

/// Review M1: `max_per_client` counts the client behind a trusted proxy
/// (the rightmost `X-Forwarded-For` address that is no trusted proxy), not
/// the proxy; an untrusted peer's header counts for nothing; IPv6 clients
/// count per /64; a trusted proxy that forwards nothing is exempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_per_client_cap_counts_the_forwarded_client() {
    let (_dir, node) = node(ConnectionsConfig {
        max_per_client: 1,
        ..ConnectionsConfig::default()
    })
    .await;
    let gw = Gateway::new(
        node.clone(),
        GatewayConfig {
            trusted_proxies: vec![kronik_gateway::IpNet::parse("127.0.0.1").unwrap()],
            ..GatewayConfig::default()
        },
    );
    let from = |peer: &str, forwarded: Option<&str>| {
        let mut req = upgrade("/room/lobby/ws?user=u", &[]);
        req.peer = Some(peer.parse().unwrap());
        if let Some(f) = forwarded {
            req.headers.push(("x-forwarded-for".into(), f.into()));
        }
        req
    };
    let mut transports = Vec::new();
    let mut open = async |req: HttpRequest| {
        let answer = gw.open_connection(req).await;
        if let Some(conn) = &answer.connection {
            transports.push(RecordingTransport::attach(node.hub(), conn).unwrap());
        }
        answer.response.status
    };
    // Behind the proxy: one connection per forwarded client.
    assert_eq!(open(from("127.0.0.1", Some("203.0.113.5"))).await, 101);
    assert_eq!(open(from("127.0.0.1", Some("203.0.113.5"))).await, 503);
    assert_eq!(
        open(from("127.0.0.1", Some("198.51.100.1, 203.0.113.6"))).await,
        101
    );
    // A proxy chain: trusted hops on the right are skipped.
    assert_eq!(
        open(from("127.0.0.1", Some("203.0.113.6, 127.0.0.1"))).await,
        503
    );
    // A peer that is no proxy cannot claim another address.
    assert_eq!(open(from("198.51.100.7", Some("203.0.113.9"))).await, 101);
    assert_eq!(open(from("198.51.100.7", Some("203.0.113.10"))).await, 503);
    // IPv6 clients count per /64.
    assert_eq!(open(from("2001:db8::1", None)).await, 101);
    assert_eq!(open(from("2001:db8::2", None)).await, 503);
    assert_eq!(open(from("2001:db8:0:1::1", None)).await, 101);
    // A trusted proxy that forwards nobody is exempt.
    assert_eq!(open(from("127.0.0.1", None)).await, 101);
    assert_eq!(open(from("127.0.0.1", None)).await, 101);
}
