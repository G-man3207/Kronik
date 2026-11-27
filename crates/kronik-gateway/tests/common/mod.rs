//! Helpers shared by the gateway's integration tests.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_gateway::HttpResponse;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::ConnectionsConfig;
use kronik_sched::{Node, NodeConfig, start_local};

pub const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "t".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

pub async fn deployed(dir: &std::path::Path, guest: &str, config: NodeConfig) -> Arc<Node> {
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir, config).await.unwrap();
    node.deploy(
        &std::fs::read(guest).unwrap(),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    node
}

pub async fn room_node(connections: ConnectionsConfig) -> (tempfile::TempDir, Arc<Node>) {
    let dir = tempfile::tempdir().unwrap();
    let node = deployed(
        dir.path(),
        ROOM,
        NodeConfig {
            connections,
            ..NodeConfig::default()
        },
    )
    .await;
    (dir, node)
}

/// A message to room/lobby; its reply's text.
pub async fn ask(node: &Node, name: &str, body: &[u8]) -> String {
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
            audit(),
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

pub fn header<'a>(r: &'a HttpResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn code(r: &HttpResponse) -> String {
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    v["error"]["code"].as_str().unwrap_or_default().to_owned()
}

/// Polls `f` every 10 ms until it is true, and fails at the wall-clock
/// deadline otherwise: a budget in time, not in sleeps, so that a slow
/// runner cannot decide whether the daemon met its timers. Returns when
/// the predicate was first seen true.
pub async fn until(
    what: &str,
    budget: Duration,
    f: impl AsyncFn() -> bool,
) -> tokio::time::Instant {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if f().await {
            return tokio::time::Instant::now();
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(feature = "server")]
pub async fn serve(
    node: &Arc<Node>,
    tls: Option<Arc<rustls::ServerConfig>>,
    max_connections: usize,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let gw = Arc::new(kronik_gateway::Gateway::new(
        node.clone(),
        kronik_gateway::GatewayConfig::default(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(kronik_gateway::server::serve(
        listener,
        gw,
        tls,
        max_connections,
    ));
    (addr, task)
}

#[cfg(feature = "server")]
pub struct Server {
    pub _dir: tempfile::TempDir,
    pub node: Arc<Node>,
    pub addr: std::net::SocketAddr,
    pub task: tokio::task::JoinHandle<std::io::Result<()>>,
}

#[cfg(feature = "server")]
pub async fn server(connections: ConnectionsConfig) -> Server {
    let (dir, node) = room_node(connections).await;
    let (addr, task) = serve(&node, None, 64).await;
    Server {
        _dir: dir,
        node,
        addr,
        task,
    }
}
