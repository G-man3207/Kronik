//! M24 review S1-S3: clients that stop reading or leave mid-open never hold
//! a connection's slot (docs/design/m24-connections.md §5.3, §5.6). A
//! WebSocket or SSE client that takes nothing is closed as a slow consumer
//! within the ping timeout, and the hub hears of the end; an open whose
//! client left while its turn ran is abandoned; an accepted connection that
//! never gets a transport is freed, also after its actor closed it. The
//! drivers run over in-memory sockets whose client side does not read, and
//! the same cases run through the hyper server over TCP, with a client
//! whose receive buffer is tiny (the review's reproductions).
#![cfg(feature = "server")]
// Test helpers outside #[test] functions may unwrap too; the tests run the
// drivers on the tokio runtime directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use hyper_util::rt::TokioIo;
use kronik_core::env::Env;
use kronik_gateway::connections::Limits;
use kronik_gateway::{Gateway, GatewayConfig, HttpRequest};
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::ConnectionsConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpSocket, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::Role;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

const SHORT: Duration = Duration::from_millis(300);

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

/// Short timeouts, and reads that are not paced, for a quick test.
fn quick() -> ConnectionsConfig {
    ConnectionsConfig {
        ping_timeout: SHORT,
        close_timeout: SHORT,
        inbound_rate: 10_000,
        ..ConnectionsConfig::default()
    }
}

fn limits(cfg: &ConnectionsConfig) -> Limits {
    Limits {
        max_message: cfg.max_frame_bytes,
        outbound_queue_bytes: cfg.outbound_queue_bytes,
        ping_interval: cfg.ping_interval,
        ping_timeout: cfg.ping_timeout,
        close_timeout: cfg.close_timeout,
    }
}

fn request(path_and_query: &str, websocket: bool) -> HttpRequest {
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let mut headers = vec![("host".to_owned(), "example.test".to_owned())];
    if websocket {
        for (n, v) in [
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ] {
            headers.push((n.to_owned(), v.to_owned()));
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

/// Waits until `conn`'s close input is applied, and returns its row.
async fn closed(node: &Node, conn: &str) -> kronik_store::db::ConnectionRow {
    for _ in 0..1000 {
        if let Some(row) = node.store().db().connection_any(conn).unwrap()
            && row.closed_lsn.is_some()
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "{conn} was never closed; the hub still holds {} connections",
        node.hub().live()
    );
}

async fn say(node: &Node, text: &str) {
    ask(node, "say", text.as_bytes()).await;
}

/// A message to room/lobby; its reply's text.
async fn ask(node: &Node, name: &str, body: &[u8]) -> String {
    let r = node
        .send(
            kronik_core::ids::ActorRef::parse("room/lobby").unwrap(),
            pb::Message {
                name: name.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.to_vec())),
                }),
                blobs: vec![],
                retained_compensation_source: None,
            },
            pb::Audit {
                token_id: "t".into(),
                reason: "test".into(),
                wall_time_ms: 0,
            },
            false,
            node.local_operator_authority().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    match r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.and_then(|b| b.value) {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8(b).unwrap(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// S1: a WebSocket client that stops reading. The driver's writes stall;
/// the first one that the client does not take within the ping timeout
/// closes the connection as a slow consumer, the socket is dropped and the
/// hub frees the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_that_stops_reading_is_closed_and_freed() {
    let cfg = quick();
    let (_dir, node) = node(cfg.clone()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let answer = gw
        .open_connection(request("/room/lobby/ws?user=ada", true))
        .await;
    assert_eq!(answer.response.status, 101);
    let conn = answer.connection.unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let driver = tokio::spawn(kronik_gateway::connections::drive(
        node.hub().clone(),
        conn.clone(),
        TokioIo::new(server),
        limits(&cfg),
    ));
    let mut ws = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let welcome = ws.next().await.unwrap().unwrap();
    assert!(welcome.to_text().unwrap().contains("welcome"));
    // Echoes of 8 KiB each, and the client reads nothing from now on.
    let (mut tx, _rx) = ws.split();
    let sender = tokio::spawn(async move {
        for _ in 0..20 {
            if tx
                .send(Message::text(format!("echo {}", "x".repeat(8 << 10))))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    let row = closed(&node, &conn).await;
    assert_eq!(
        row.cause,
        Some(pb::CloseCause::SlowConsumer as i32),
        "{row:?}"
    );
    assert_eq!(row.code, Some(1008));
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("the driver ended")
        .unwrap();
    assert_eq!(node.hub().live(), 0);
    sender.abort();
}

/// S2: an SSE client that stops reading. Its response body takes no more
/// chunks; the driver's wait for room is bounded by the ping timeout, then
/// the connection closes as a slow consumer and the hub frees the slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sse_client_that_stops_reading_is_closed_and_freed() {
    let cfg = quick();
    let (_dir, node) = node(cfg.clone()).await;
    for text in ["one", "two", "three"] {
        say(&node, text).await;
    }
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    // The open turn queues the three messages.
    let answer = gw
        .open_connection(request("/room/lobby/events?user=ada", false))
        .await;
    assert_eq!(answer.response.status, 200);
    let conn = answer.connection.unwrap();
    // The body's receiver is alive and never polled: hyper writes nothing
    // more to a client that does not read.
    let (chunks, body) = tokio::sync::mpsc::channel(1);
    let driver = tokio::spawn(kronik_gateway::connections::sse::drive(
        node.hub().clone(),
        conn.clone(),
        chunks,
    ));
    let row = closed(&node, &conn).await;
    assert_eq!(
        row.cause,
        Some(pb::CloseCause::SlowConsumer as i32),
        "{row:?}"
    );
    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("the driver ended")
        .unwrap();
    assert_eq!(node.hub().live(), 0);
    drop(body);
}

/// S3: the client leaves while the open turn runs (hyper drops the
/// request's future). The accept that then commits is abandoned at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_whose_client_left_is_abandoned() {
    let (_dir, node) = node(quick()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let mut open = Box::pin(gw.open_connection(request("/room/lobby/ws?user=ada", true)));
    // One poll admits the open; then the client is gone.
    assert!(futures_util::poll!(open.as_mut()).is_pending());
    drop(open);
    let conn = loop {
        if let Some(row) = node
            .store()
            .db()
            .connections(None, kronik_store::db::ConnectionState::All, "", 10)
            .unwrap()
            .into_iter()
            .next()
        {
            break row.id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let row = closed(&node, &conn).await;
    assert_eq!(row.cause, Some(pb::CloseCause::Abandoned as i32), "{row:?}");
    assert_eq!(node.hub().live(), 0);
}

/// S3: an accepted connection that never gets a transport is freed after
/// the attach timeout, also when its actor closed it meanwhile: the actor's
/// close is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_connection_without_a_transport_is_freed() {
    let (_dir, node) = node(ConnectionsConfig {
        attach_timeout: Duration::from_millis(500),
        ..quick()
    })
    .await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let answer = gw
        .open_connection(request("/room/lobby/ws?user=ada", true))
        .await;
    let conn = answer.connection.unwrap();
    // Nobody attaches. The actor closes it.
    node.send(
        kronik_core::ids::ActorRef::parse("room/lobby").unwrap(),
        pb::Message {
            name: "kick".into(),
            content_type: "text/plain".into(),
            body: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(conn.as_bytes().to_vec())),
            }),
            blobs: vec![],
            retained_compensation_source: None,
        },
        pb::Audit {
            token_id: "t".into(),
            reason: "test".into(),
            wall_time_ms: 0,
        },
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let row = closed(&node, &conn).await;
    assert_eq!(row.cause, Some(pb::CloseCause::Actor as i32), "{row:?}");
    assert_eq!(row.code, Some(4000));
    assert_eq!(node.hub().live(), 0);
}

/// The gateway's hyper server on a free port.
async fn serve(node: &Arc<Node>) -> std::net::SocketAddr {
    let gw = Arc::new(Gateway::new(node.clone(), GatewayConfig::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kronik_gateway::server::serve(listener, gw, 64));
    addr
}

/// A TCP connection with a tiny receive buffer: the server's writes back up
/// as soon as the client stops reading.
async fn tiny_socket(addr: std::net::SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.connect(addr).await.unwrap()
}

/// Waits until the hub holds no connection; the room's recorded closes.
async fn all_freed(node: &Node, within: Duration) -> String {
    let deadline = tokio::time::Instant::now() + within;
    while node.hub().live() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub still holds {} connections",
            node.hub().live()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The close inputs are queued turns of the room: let them run.
    for _ in 0..200 {
        let closes = ask(node, "closes", b"").await;
        if !closes.is_empty() {
            return closes;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    String::new()
}

const UPGRADE: &str = "GET /room/lobby/ws?user=ghost HTTP/1.1\r\nHost: 127.0.0.1\r\n\
     Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

/// S1 over TCP: a WebSocket client that stops reading while 60 broadcasts
/// of 256 KiB fill its socket and its 1 MiB queue, with pings too late to
/// notice first, is closed as a slow consumer and freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_websocket_client_over_tcp_that_stops_reading_is_freed() {
    let (_dir, node) = node(ConnectionsConfig {
        ping_interval: Duration::from_secs(5),
        ping_timeout: Duration::from_secs(5),
        close_timeout: Duration::from_secs(1),
        ..ConnectionsConfig::default()
    })
    .await;
    let addr = serve(&node).await;
    let req = format!("ws://{addr}/room/lobby/ws?user=slow")
        .into_client_request()
        .unwrap();
    let (ws, _) = tokio_tungstenite::client_async(req, tiny_socket(addr).await)
        .await
        .unwrap();
    for _ in 0..60 {
        ask(&node, "say", &[b'x'; 256 << 10]).await;
    }
    let closes = all_freed(&node, Duration::from_secs(25)).await;
    assert!(closes.contains("host 1008 slow-consumer"), "{closes}");
    drop(ws);
}

/// S2 over TCP: an SSE client that reads only the response head is closed
/// as a slow consumer and freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sse_client_over_tcp_that_stops_reading_is_freed() {
    let (_dir, node) = node(ConnectionsConfig {
        sse_heartbeat: Duration::from_secs(1),
        close_timeout: Duration::from_secs(1),
        outbound_queue_bytes: 64 << 10,
        ..ConnectionsConfig::default()
    })
    .await;
    let addr = serve(&node).await;
    let mut stream = tiny_socket(addr).await;
    stream
        .write_all(
            b"GET /room/lobby/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n",
        )
        .await
        .unwrap();
    let mut head = [0u8; 256];
    let n = stream.read(&mut head).await.unwrap();
    assert!(head[..n].starts_with(b"HTTP/1.1 200"));
    for _ in 0..400 {
        ask(&node, "say", &[b'x'; 32 << 10]).await;
    }
    let closes = all_freed(&node, Duration::from_secs(15)).await;
    assert!(closes.contains("host 1008 slow-consumer"), "{closes}");
    drop(stream);
}

/// S3 over TCP: a client that sends the upgrade and leaves at once, or
/// while the open turn waits behind 300 others, leaves no connection
/// behind: the accept is abandoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_over_tcp_that_leaves_mid_open_is_freed() {
    let (_dir, node) = node(ConnectionsConfig::default()).await;
    let addr = serve(&node).await;
    for query in ["user=ghost", "user=ghost&call=1"] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(UPGRADE.replace("user=ghost", query).as_bytes())
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    }
    all_freed(&node, Duration::from_secs(10)).await;
    // Keep room/lobby busy: the open waits in its mailbox when the client
    // leaves.
    let busy: Vec<_> = (0..300)
        .map(|_| {
            let node = node.clone();
            tokio::spawn(async move { ask(&node, "say", &[b'x'; 16 << 10]).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(UPGRADE.as_bytes()).await.unwrap();
    let registered = tokio::time::Instant::now() + Duration::from_secs(10);
    while node.hub().live() == 0 && tokio::time::Instant::now() < registered {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(node.hub().live(), 1, "the open was admitted");
    stream.shutdown().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    drop(stream);
    for b in busy {
        b.await.unwrap();
    }
    let closes = all_freed(&node, Duration::from_secs(10)).await;
    assert!(closes.contains("host 1001 abandoned"), "{closes}");
    assert_eq!(ask(&node, "members", b"").await, "");
}
