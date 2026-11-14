//! M24: SSE connections end to end through the hyper server
//! (docs/design/m24-connections.md §5.4): the `200 text/event-stream`
//! answer after the open turn, the resume from `Last-Event-ID`, a
//! broadcast as an event, the heartbeat comment, the actor's close (the
//! stream ends), the client's disconnect (a client close, 1006), a refusal,
//! and a graceful stop's `retry:` before the end. Runs with the `server`
//! feature (as in `cargo test --workspace`).
#![cfg(feature = "server")]
// Test helpers outside #[test] functions may unwrap too; the test binds a
// listener and waits on the tokio runtime directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_gateway::{Gateway, GatewayConfig};
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::ConnectionsConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

struct Server {
    _dir: tempfile::TempDir,
    node: Arc<Node>,
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(
        env,
        dir.path(),
        NodeConfig {
            connections: ConnectionsConfig {
                sse_heartbeat: Duration::from_millis(300),
                ..ConnectionsConfig::default()
            },
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

/// A streaming HTTP/1.1 response: its status, its headers, and its body's
/// chunks as they arrive.
struct Stream {
    reader: BufReader<TcpStream>,
    status: u16,
    headers: Vec<(String, String)>,
    /// Bytes of the body received and not yet taken.
    buffer: String,
    ended: bool,
}

impl Stream {
    async fn open(addr: std::net::SocketAddr, target: &str, extra: &str) -> Stream {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(format!("GET {target} HTTP/1.1\r\nhost: test\r\n{extra}\r\n").as_bytes())
            .await
            .unwrap();
        let mut reader = BufReader::new(tcp);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).await.unwrap();
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let (n, v) = h.split_once(':').unwrap();
            headers.push((n.to_ascii_lowercase(), v.trim().to_owned()));
        }
        Stream {
            reader,
            status,
            headers,
            buffer: String::new(),
            ended: false,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Reads one chunk of the chunked body into the buffer; `false` at its
    /// end.
    async fn chunk(&mut self) -> bool {
        let mut size = String::new();
        self.reader.read_line(&mut size).await.unwrap();
        let size = usize::from_str_radix(size.trim(), 16)
            .unwrap_or_else(|_| panic!("not a chunk size: {size:?}"));
        let mut data = vec![0; size + 2];
        self.reader.read_exact(&mut data).await.unwrap();
        if size == 0 {
            self.ended = true;
            return false;
        }
        self.buffer
            .push_str(std::str::from_utf8(&data[..size]).unwrap());
        true
    }

    /// The next block (up to an empty line), or `None` at the end.
    async fn block(&mut self) -> Option<String> {
        loop {
            if let Some(at) = self.buffer.find("\n\n") {
                let block = self.buffer[..at].to_owned();
                self.buffer.drain(..at + 2);
                return Some(block);
            }
            if self.ended {
                return None;
            }
            let more = tokio::time::timeout(Duration::from_secs(10), self.chunk())
                .await
                .expect("a chunk within 10 s");
            if !more {
                return None;
            }
        }
    }

    /// The next event, skipping heartbeat comments.
    async fn event(&mut self) -> Option<String> {
        loop {
            let block = self.block().await?;
            if !block.starts_with(':') {
                return Some(block);
            }
        }
    }
}

async fn post(addr: std::net::SocketAddr, path: &str, body: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!(
            "POST {path} HTTP/1.1\r\nhost: test\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    tcp.read_to_string(&mut out).await.unwrap();
    out.split_once("\r\n\r\n").unwrap().1.to_owned()
}

async fn ask(node: &Node, name: &str, body: &str) -> String {
    let r = node
        .send(
            kronik_core::ids::ActorRef::parse("room/lobby").unwrap(),
            pb::Message {
                name: name.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
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
async fn sse_streams_end_to_end() {
    let s = server().await;
    // Two messages before anyone listens.
    assert_eq!(post(s.addr, "/room/lobby/say", "one").await, "1");
    assert_eq!(post(s.addr, "/room/lobby/say", "two").await, "2");

    // A reconnecting EventSource sends Last-Event-ID: the open turn resumes
    // after it.
    let mut ada = Stream::open(
        s.addr,
        "/room/lobby/events?user=ada",
        "last-event-id: 1\r\n",
    )
    .await;
    assert_eq!(ada.status, 200);
    assert_eq!(ada.header("content-type"), Some("text/event-stream"));
    assert_eq!(ada.header("cache-control"), Some("no-store"));
    assert_eq!(ada.header("x-accel-buffering"), Some("no"));
    assert!(ada.header("kronik-turn-id").unwrap().starts_with("main:"));
    let two = ada.event().await.unwrap();
    assert!(two.starts_with("id: 2\nevent: message\ndata: {"), "{two}");
    assert!(two.contains("\"text\":\"two\""), "{two}");

    // A broadcast reaches the stream as an event.
    assert_eq!(post(s.addr, "/room/lobby/say", "three").await, "3");
    let three = ada.event().await.unwrap();
    assert!(
        three.starts_with("id: 3\n") && three.contains("three"),
        "{three}"
    );
    // An idle stream gets heartbeat comments.
    assert_eq!(ada.block().await.as_deref(), Some(": keep-alive"));

    // The actor closes it: the stream ends.
    let members = ask(&s.node, "members", "").await;
    let conn = members.split_whitespace().next().unwrap().to_owned();
    assert!(members.contains("ada sse"), "{members}");
    assert_eq!(ask(&s.node, "kick", &conn).await, "kicked");
    assert_eq!(ada.event().await, None);
    until("ada's close", async || {
        ask(&s.node, "closes", "")
            .await
            .contains("actor 4000 kicked")
    })
    .await;

    // A client that goes away: a client close with 1006.
    let mut bob = Stream::open(s.addr, "/room/lobby/events?user=bob", "").await;
    assert_eq!(bob.status, 200);
    // The messages after 0: all three.
    for _ in 0..3 {
        assert!(bob.event().await.is_some());
    }
    drop(bob);
    until("bob's close", async || {
        ask(&s.node, "closes", "").await.contains("client 1006")
    })
    .await;

    // A refusal answers like an HTTP turn, without a stream.
    let eve = Stream::open(s.addr, "/room/lobby/events?user=eve&deny=1", "").await;
    assert_eq!(eve.status, 403);
    assert_eq!(eve.header("content-length"), Some("6"), "the actor's body");
    assert!(
        eve.header("content-type")
            .is_none_or(|c| c != "text/event-stream")
    );
    drop(eve);

    // A graceful stop: `retry: 5000`, then the end.
    let mut cid = Stream::open(
        s.addr,
        "/room/lobby/events?user=cid",
        "last-event-id: 3\r\n",
    )
    .await;
    assert_eq!(cid.status, 200);
    until("cid's open", async || {
        ask(&s.node, "members", "").await.contains("cid sse")
    })
    .await;
    let hub = s.node.hub().clone();
    let stop = tokio::spawn(async move { hub.shutdown(Duration::from_secs(2)).await });
    loop {
        match cid.block().await {
            Some(b) if b.starts_with(':') => continue,
            Some(b) => {
                assert_eq!(b, "retry: 5000");
                break;
            }
            None => panic!("the stream ended without retry"),
        }
    }
    assert_eq!(cid.block().await, None);
    stop.await.unwrap();
    assert!(s.node.store().db().dead_letters(0, 10).unwrap().is_empty());
    s.task.abort();
}
