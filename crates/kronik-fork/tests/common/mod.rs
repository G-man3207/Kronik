//! Shared harness for the replay and proposal tests: a real node on a
//! multi-thread runtime, HTTP and message helpers, and a request-counting
//! HTTP server.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_proto::log::v1 as pb;
use kronik_sched::{Ingress, Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

/// Data directories live under the target directory, not /tmp (a shared
/// RAM-backed tmpfs on the build machines).
pub fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("replay-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

pub fn guest(name: &str) -> String {
    format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    )
}

pub struct Proc {
    pub rt: Runtime,
    pub node: Arc<Node>,
}

pub fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

pub fn plain(b: &str) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.as_bytes().to_vec())),
    })
}

pub fn http_body(r: &TurnResult) -> String {
    match &r.outcome.output {
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
    pub fn start(dir: &Path) -> Proc {
        Proc::start_with(
            dir,
            NodeConfig {
                concurrency: 8,
                ..NodeConfig::default()
            },
        )
    }

    pub fn start_with(dir: &Path, cfg: NodeConfig) -> Proc {
        let p = Proc::open(dir, cfg);
        p.deploy("counter");
        p
    }

    /// A node over `dir` as it is: nothing deployed (a restart).
    pub fn open(dir: &Path, cfg: NodeConfig) -> Proc {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            start_local(env, dir, cfg).await.unwrap()
        });
        Proc { rt, node }
    }

    /// Deploys a test guest on main (a kind without history).
    pub fn deploy(&self, name: &str) {
        let bytes = std::fs::read(guest(name)).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false))
            .unwrap();
    }

    pub fn grant(&self, cap: &str) {
        self.rt
            .block_on(self.node.grant("counter", cap, None, None, audit(), false))
            .unwrap();
    }

    fn http_input(key: &str, op: &str, body: &str) -> (ActorRef, pb::HttpInput) {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: format!("/counter/{key}/{op}"),
            params: vec![
                pb::Param {
                    name: "key".into(),
                    value: key.into(),
                    sealed_value: None,
                },
                pb::Param {
                    name: "op".into(),
                    value: op.into(),
                    sealed_value: None,
                },
            ],
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(plain(body).unwrap())),
            }),
            route: "/counter/{key}/{op}".into(),
            ..Default::default()
        };
        (ActorRef::parse(&format!("counter/{key}")).unwrap(), input)
    }

    pub fn http(&self, key: &str, op: &str, body: &str) -> TurnResult {
        let (actor, input) = Proc::http_input(key, op, body);
        match self.node.ingress(actor, input, None).unwrap() {
            Ingress::Started(w) | Ingress::Joined(w) => self.rt.block_on(w.wait()).unwrap(),
            Ingress::Done(r) => *r,
        }
    }

    /// An HTTP input that is not waited for.
    pub fn http_detached(&self, key: &str, op: &str, body: &str) {
        let (actor, input) = Proc::http_input(key, op, body);
        self.node.ingress(actor, input, None).unwrap();
    }

    pub fn send(&self, actor: &str, name: &str, body: &str) -> TurnResult {
        let m = pb::Message {
            name: name.into(),
            content_type: "text/plain".into(),
            body: plain(body),
            blobs: vec![],
        };
        self.rt
            .block_on(
                self.node
                    .send(ActorRef::parse(actor).unwrap(), m, audit(), false),
            )
            .unwrap()
            .unwrap()
    }

    /// Waits until the applied LSN stops moving (inner messages done).
    pub fn settle(&self) -> Lsn {
        let mut last = self.node.applied_lsn();
        let mut still = 0;
        while still < 5 {
            std::thread::sleep(Duration::from_millis(100));
            let now = self.node.applied_lsn();
            still = if now == last { still + 1 } else { 0 };
            last = now;
        }
        last
    }

    pub fn wait_kv(&self, actor: &str, k: &str) {
        let a = ActorRef::parse(actor).unwrap();
        for _ in 0..2000 {
            if self
                .node
                .store()
                .db()
                .kv_get(&a.kind, &a.key, k)
                .unwrap()
                .is_some()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{actor} never wrote {k}");
    }
}

// A tiny HTTP server counting requests (to prove replay sends none, I7).
pub fn server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || serve(stream, h));
        }
    });
    (addr, hits)
}

fn serve(stream: TcpStream, hits: Arc<AtomicUsize>) {
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut len = 0usize;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end().to_ascii_lowercase();
            if h.is_empty() {
                break;
            }
            if let Some(v) = h.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
        let reply = format!("charged {n}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{reply}",
            reply.len()
        );
        if w.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}
