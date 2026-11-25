//! Shared harness for the replay and proposal tests: a real node on a
//! multi-thread runtime, HTTP and message helpers, and a request-counting
//! HTTP server.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Clock, EntropySource, Env};
use kronik_core::ids::{ActorRef, CodeHash, Lsn};
use kronik_proto::Record;
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

/// The code hash of the test guest `name`.
pub fn hash(name: &str) -> Vec<u8> {
    CodeHash::of(&std::fs::read(guest(name)).unwrap())
        .0
        .to_vec()
}

/// Fails the next generated proposal/preview's atomic metadata rename,
/// without obstructing main's history or replacing real entropy.
pub struct ProposalSaveFault {
    source: Arc<dyn EntropySource>,
    target: std::sync::Mutex<Option<(std::path::PathBuf, &'static str)>>,
}

impl ProposalSaveFault {
    pub fn install(env: &mut Env) -> Arc<Self> {
        let fault = Arc::new(Self {
            source: env.entropy.clone(),
            target: std::sync::Mutex::new(None),
        });
        env.entropy = fault.clone();
        fault
    }

    pub fn arm(&self, data: &Path, prefix: &'static str) {
        *self.target.lock().unwrap() = Some((data.to_path_buf(), prefix));
    }
}

impl EntropySource for ProposalSaveFault {
    fn fill(&self, buf: &mut [u8]) {
        self.source.fill(buf);
        // random_id uses 16 bytes; proposal/preview IDs keep their first 12 hex digits.
        if buf.len() == 16
            && let Some((data, prefix)) = self.target.lock().unwrap().take()
        {
            let id = format!("{prefix}{}", &kronik_core::ids::hex(buf)[..12]);
            std::fs::create_dir_all(data.join("branches").join(id).join("proposal.json")).unwrap();
        }
    }

    fn sign_rs256(&self, pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        self.source.sign_rs256(pkcs8, message)
    }
}

/// A real clock with a movable wall offset, so a test can let logical time
/// pass without sleeping. Sleeps and monotonic time stay real.
pub struct ShiftedClock {
    pub inner: Arc<dyn Clock>,
    pub offset_ms: Arc<AtomicU64>,
}

impl Clock for ShiftedClock {
    fn wall_ms(&self) -> u64 {
        self.inner
            .wall_ms()
            .saturating_add(self.offset_ms.load(Ordering::SeqCst))
    }

    fn monotonic(&self) -> Duration {
        self.inner.monotonic()
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        self.inner.sleep(d)
    }
}

/// `Proc::start`, with the wall clock offset by the returned counter.
pub fn start_shifted(dir: &Path) -> (Proc, Arc<AtomicU64>) {
    let offset = Arc::new(AtomicU64::new(0));
    let at_start = offset.clone();
    let p = Proc::start_env(
        dir,
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
        move |env| {
            env.clock = Arc::new(ShiftedClock {
                inner: env.clock.clone(),
                offset_ms: at_start,
            });
        },
    );
    (p, offset)
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

/// A reply outcome's plain body, or `""` when it has none.
pub fn reply(outcome: &pb::Outcome) -> String {
    match &outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// `turn`'s reply body, or `""` when its outcome has no reply.
pub fn fork_reply(turn: &kronik_fork::ForkTurn) -> String {
    turn.record.outcome.as_ref().map(reply).unwrap_or_default()
}

/// Polls `done` until it holds; the limit only turns a hang into a failure.
pub fn wait_until(what: &str, done: impl Fn() -> bool) {
    for _ in 0..6000 {
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("never: {what}");
}

/// Every file under `dir` that contains `needle`.
pub fn files_with(dir: &Path, needle: &[u8]) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if std::fs::read(&path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
            {
                out.push(path);
            }
        }
    }
    out
}

/// Every turn record in main's log after `after`.
pub fn turns_after(p: &Proc, after: Lsn) -> Vec<(Lsn, pb::TurnRecord)> {
    let head = p.settle();
    (after + 1..=head)
        .filter_map(
            |lsn| match p.rt.block_on(p.node.read_record(lsn)).unwrap()?.record {
                Record::TurnRecord(t) => Some((lsn, t)),
                _ => None,
            },
        )
        .collect()
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
        Proc::start_env(dir, cfg, |_| {})
    }

    /// `start_with`, with `wrap` changing the node's environment first (a
    /// test file system, say).
    pub fn start_env(dir: &Path, cfg: NodeConfig, wrap: impl FnOnce(&mut Env)) -> Proc {
        let p = Proc::open_env(dir, cfg, wrap);
        p.deploy("counter");
        p
    }

    /// A node over `dir` as it is: nothing deployed (a restart).
    pub fn open(dir: &Path, cfg: NodeConfig) -> Proc {
        Proc::open_env(dir, cfg, |_| {})
    }

    fn open_env(dir: &Path, cfg: NodeConfig, wrap: impl FnOnce(&mut Env)) -> Proc {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(async {
            let mut env = Env::real(tokio::runtime::Handle::current());
            wrap(&mut env);
            start_local(env, dir, cfg).await.unwrap()
        });
        Proc { rt, node }
    }

    /// The local operator's original node-lifetime authority, as the daemon
    /// itself would hold it (`crates/kronik-sched/tests` uses the same).
    pub fn owner(&self) -> AuthLease {
        self.node.local_operator_authority().unwrap()
    }

    /// Deploys a test guest on main (a kind without history).
    pub fn deploy(&self, name: &str) {
        let bytes = std::fs::read(guest(name)).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false, self.owner()))
            .unwrap();
    }

    pub fn grant(&self, cap: &str) {
        self.grant_with_delivery(cap, None);
    }

    pub fn grant_with_delivery(&self, cap: &str, delivery: Option<kronik_effects::Delivery>) {
        self.rt
            .block_on(self.node.grant(
                "counter",
                cap,
                delivery,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    pub fn http_input(key: &str, op: &str, body: &str) -> (ActorRef, pb::HttpInput) {
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

    /// Ingress of `input` to `actor`, waited for.
    pub fn ingress(
        &self,
        actor: ActorRef,
        input: pb::HttpInput,
        subject: Option<&str>,
    ) -> TurnResult {
        self.rt.block_on(async {
            match self
                .node
                .ingress(actor, input, subject.map(str::to_owned))
                .unwrap()
            {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            }
        })
    }

    pub fn http(&self, key: &str, op: &str, body: &str) -> TurnResult {
        self.http_as(key, op, body, None)
    }

    /// `http` on behalf of a data subject (privacy mode).
    pub fn http_as(&self, key: &str, op: &str, body: &str, subject: Option<&str>) -> TurnResult {
        let (actor, input) = Proc::http_input(key, op, body);
        self.ingress(actor, input, subject)
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
            retained_compensation_source: None,
        };
        self.rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                m,
                audit(),
                false,
                self.owner(),
            ))
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

/// A fake OpenAI-compatible model: every call gets a different answer, so
/// a second call would change the diff. Keeps every request body.
pub fn model_server() -> (String, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 {
                    break;
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
                continue;
            }
            let n = {
                let mut seen = s.lock().unwrap();
                seen.push(body);
                seen.len()
            };
            let content = serde_json::json!({"status": 200,
                "headers": {"content-type": "text/plain"},
                "body": format!("model answer {n}")})
            .to_string();
            let reply =
                serde_json::json!({"choices": [{"message": {"role": "assistant", "content": content}}]})
                    .to_string();
            let _ = w.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .as_bytes(),
            );
        }
    });
    (addr, seen)
}

/// The model simulator's configuration for `model_server`.
pub fn model(addr: &str) -> kronik_fork::simulators::ModelConfig {
    kronik_fork::simulators::ModelConfig {
        endpoint: format!("http://{addr}/v1/chat/completions"),
        model: "fake".into(),
        api_key: None,
        timeout: Duration::from_secs(10),
        max_examples: 5,
        examples_under_privacy: false,
    }
}
