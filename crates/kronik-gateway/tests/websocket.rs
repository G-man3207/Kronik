//! M24: WebSocket connections end to end through the hyper server
//! (docs/design/m24-connections.md §5.3 to §5.8), with a real client: the
//! upgrade, the welcome after the open turn, incoming frames as turns of
//! the owner, a broadcast to every member in order, binary frames, the
//! actor's close (its frames first), a too-large message, the client's
//! close, the ping keepalive, a graceful stop's 1012, and exactly one close
//! input each. Runs with the `server` feature (as in `cargo test
//! --workspace`).
#![cfg(feature = "server")]
// Test helpers outside #[test] functions may unwrap too; the test binds a
// listener on the tokio runtime directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use kronik_core::env::Env;
use kronik_gateway::{Gateway, GatewayConfig};
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::ConnectionsConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

type Client = WebSocketStream<TcpStream>;

struct Server {
    _dir: tempfile::TempDir,
    node: Arc<Node>,
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn server(connections: ConnectionsConfig) -> Server {
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
    let gw = Arc::new(Gateway::new(node.clone(), GatewayConfig::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(kronik_gateway::server::serve(listener, gw, 64));
    Server {
        _dir: dir,
        node,
        addr,
        task,
    }
}

impl Server {
    async fn connect(&self, path: &str, protocols: Option<&str>) -> (Client, Option<String>) {
        let mut req = format!("ws://{}{path}", self.addr)
            .into_client_request()
            .unwrap();
        if let Some(p) = protocols {
            req.headers_mut()
                .insert("sec-websocket-protocol", p.parse().unwrap());
        }
        let stream = TcpStream::connect(self.addr).await.unwrap();
        let (ws, response) = tokio_tungstenite::client_async(req, stream).await.unwrap();
        let selected = response
            .headers()
            .get("sec-websocket-protocol")
            .map(|v| v.to_str().unwrap().to_owned());
        (ws, selected)
    }

    /// The closes the room recorded (`<conn> <initiator> <code> <reason>`).
    async fn closes(&self) -> String {
        self.send("closes").await
    }

    async fn send(&self, name: &str) -> String {
        let r = self
            .node
            .send(
                kronik_core::ids::ActorRef::parse("room/lobby").unwrap(),
                pb::Message {
                    name: name.into(),
                    content_type: "text/plain".into(),
                    body: Some(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(vec![])),
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
                self.node.local_operator_authority().unwrap(),
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
}

/// The next text or binary message, skipping pings and pongs.
async fn next(ws: &mut Client) -> Message {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("a message within 10 s")
            .expect("the connection is open")
            .unwrap();
        match m {
            Message::Ping(_) | Message::Pong(_) => continue,
            m => return m,
        }
    }
}

async fn text(ws: &mut Client) -> String {
    match next(ws).await {
        Message::Text(t) => t.as_str().to_owned(),
        other => panic!("expected text, got {other:?}"),
    }
}

async fn until(what: &str, f: impl AsyncFn() -> bool) {
    for _ in 0..500 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_connections_end_to_end() {
    let s = server(ConnectionsConfig {
        max_frame_bytes: 1024,
        ..ConnectionsConfig::default()
    })
    .await;
    let (mut ada, selected) = s
        .connect("/room/lobby/ws?user=ada", Some("x.v0, room.v1"))
        .await;
    assert_eq!(selected.as_deref(), Some("room.v1"));
    let welcome = text(&mut ada).await;
    assert!(welcome.contains("\"type\":\"welcome\""), "{welcome}");
    let (mut bob, _) = s.connect("/room/lobby/ws?user=bob", None).await;
    assert!(text(&mut bob).await.contains("welcome"));
    assert!(text(&mut ada).await.contains("\"joined\""));

    // A frame is a turn of the owner; its broadcast reaches both, in order.
    ada.send(Message::text("say one")).await.unwrap();
    ada.send(Message::text("say two")).await.unwrap();
    for ws in [&mut ada, &mut bob] {
        let one = text(ws).await;
        let two = text(ws).await;
        assert!(
            one.contains("\"seq\":1") && one.contains("\"text\":\"one\""),
            "{one}"
        );
        assert!(
            two.contains("\"seq\":2") && two.contains("\"text\":\"two\""),
            "{two}"
        );
    }
    // A binary frame back to the sender only.
    bob.send(Message::text("binary bytes")).await.unwrap();
    assert_eq!(next(&mut bob).await, Message::binary(b"bytes".to_vec()));

    // A message over max_frame_bytes: a `too-large` host close (1009).
    let (mut eve, _) = s.connect("/room/lobby/ws?user=eve", None).await;
    assert!(text(&mut eve).await.contains("welcome"));
    let _ = text(&mut ada).await; // joined
    let _ = text(&mut bob).await;
    eve.send(Message::text("x".repeat(2048))).await.unwrap();
    match next(&mut eve).await {
        Message::Close(Some(f)) => assert_eq!(f.code, CloseCode::Size),
        other => panic!("expected a close, got {other:?}"),
    }
    // Her close input ran the room's close handler: `left` to the others.
    for ws in [&mut ada, &mut bob] {
        assert!(text(ws).await.contains("\"left\""));
    }

    // The actor's close: `echo` first, then `bye` closes after it.
    bob.send(Message::text("echo last words")).await.unwrap();
    bob.send(Message::text("bye")).await.unwrap();
    assert_eq!(text(&mut bob).await, "last words");
    match next(&mut bob).await {
        Message::Close(Some(f)) => {
            assert_eq!(u16::from(f.code), 1000);
            assert_eq!(f.reason.as_str(), "bye");
        }
        other => panic!("expected a close, got {other:?}"),
    }

    // The client's close.
    ada.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: CloseCode::Away,
        reason: "tab closed".into(),
    }))
    .await
    .unwrap();
    until("three closes", async || {
        s.closes().await.lines().count() == 3
    })
    .await;
    let closes = s.closes().await;
    assert!(closes.contains("host 1009 too-large"), "{closes}");
    assert!(closes.contains("actor 1000 bye"), "{closes}");
    assert!(closes.contains("client 1001 tab closed"), "{closes}");
    assert_eq!(s.node.hub().live(), 0);
    let db = s.node.store().db();
    assert!(db.open_connections().unwrap().is_empty());
    assert!(db.dead_letters(0, 10).unwrap().is_empty());
    s.task.abort();
}

/// §5.7: an idle connection gets pings and stays open while its client
/// answers them; a client that answers nothing is closed with
/// `ping-timeout` (1001).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_pings_and_the_ping_timeout() {
    let s = server(ConnectionsConfig {
        ping_interval: Duration::from_millis(200),
        ping_timeout: Duration::from_millis(300),
        ..ConnectionsConfig::default()
    })
    .await;
    let (mut ada, _) = s.connect("/room/lobby/ws?user=ada", None).await;
    assert!(text(&mut ada).await.contains("welcome"));
    // Reading answers pings: after several intervals it is still open and
    // still works.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1200);
    let mut pings = 0;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(Message::Ping(_)))) =
            tokio::time::timeout(Duration::from_millis(100), ada.next()).await
        {
            pings += 1;
        }
    }
    assert!(pings >= 2, "{pings} pings");
    ada.send(Message::text("echo still here")).await.unwrap();
    assert_eq!(text(&mut ada).await, "still here");
    let conn = s.node.store().db().open_connections().unwrap()[0]
        .id
        .clone();

    // Now nothing reads ada's socket, so nothing answers the pings.
    until("the ping timeout", async || {
        s.node
            .store()
            .db()
            .connection_any(&conn)
            .unwrap()
            .is_some_and(|r| r.closed_lsn.is_some())
    })
    .await;
    let row = s.node.store().db().connection_any(&conn).unwrap().unwrap();
    assert_eq!(row.cause, Some(pb::CloseCause::PingTimeout as i32));
    assert_eq!(row.code, Some(1001));
    drop(ada);
    s.task.abort();
}

/// §5.9: a graceful stop sends every WebSocket 1012 `kronik: restart`, and
/// leaves the close inputs to the next start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_graceful_stop_closes_with_1012() {
    let s = server(ConnectionsConfig::default()).await;
    let (mut ada, _) = s.connect("/room/lobby/ws?user=ada", None).await;
    assert!(text(&mut ada).await.contains("welcome"));
    let hub = s.node.hub().clone();
    let stop = tokio::spawn(async move { hub.shutdown(Duration::from_secs(2)).await });
    match next(&mut ada).await {
        Message::Close(Some(f)) => {
            assert_eq!(u16::from(f.code), 1012);
            assert_eq!(f.reason.as_str(), "kronik: restart");
        }
        other => panic!("expected a close, got {other:?}"),
    }
    stop.await.unwrap();
    // No close input during a stop: the next start admits it.
    assert_eq!(s.node.store().db().open_connections().unwrap().len(), 1);
    s.task.abort();
}
