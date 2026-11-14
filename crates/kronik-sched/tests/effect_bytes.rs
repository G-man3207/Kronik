//! The effect bytes one turn may record (ADR 0145, issue #74): a kind's
//! `effect_bytes_per_turn` bounds the requests and responses its turns'
//! effect results hold inline. An effect that would pass it fails with
//! `EFFECT_BYTES_EXCEEDED` recorded as its result: before it is sent when
//! its request alone does not fit, else its response is not recorded. The
//! turn goes on, and the limit is exact.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// The log's record limit in these tests: the real one.
const LIMIT: u32 = kronik_log::MAX_RECORD;

/// A test server: `/big/<n>` answers `n` bytes, `/hang` never answers (for
/// a minute), anything else `ok`.
struct Server {
    addr: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let log = log.clone();
                std::thread::spawn(move || serve(stream, log));
            }
        });
        Server { addr, seen }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve(stream: TcpStream, seen: Arc<Mutex<Vec<String>>>) {
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let mut len = 0usize;
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                len = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        seen.lock().unwrap().push(path.clone());
        if path == "/hang" {
            std::thread::sleep(std::time::Duration::from_secs(60));
            return;
        }
        let reply = match path.strip_prefix("/big/") {
            Some(n) => "b".repeat(n.parse().unwrap_or(0)),
            None => "ok".to_owned(),
        };
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n",
            reply.len()
        );
        if w.write_all(head.as_bytes()).is_err() || w.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start(dir: &Path) -> Proc {
    start_limit(dir, LIMIT)
}

/// [`start`] with the log's record limit `limit`.
fn start_limit(dir: &Path, limit: u32) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(
            env,
            dir,
            NodeConfig {
                concurrency: 4,
                test_max_record_bytes: Some(limit),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
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

fn msg(name: &str, body: &[u8]) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.to_vec())),
        }),
        blobs: vec![],
        retained_compensation_source: None,
    }
}

impl Proc {
    fn owner(&self) -> kronik_core::authority::AuthLease {
        self.node.local_operator_authority().unwrap()
    }

    fn deploy(&self) {
        let bytes = std::fs::read(COUNTER).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false, self.owner()))
            .unwrap();
    }

    fn grant(&self, cap: &str) {
        self.rt
            .block_on(self.node.grant(
                "counter",
                cap,
                None,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    fn send(&self, actor: &str, m: pb::Message) -> TurnResult {
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

    /// The record at `lsn`, read by position as `history` does.
    fn record(&self, lsn: u64) -> Record {
        self.rt
            .block_on(self.node.read_record(lsn))
            .unwrap()
            .unwrap()
            .record
    }
}

fn turn_record(p: &Proc, r: &TurnResult) -> pb::TurnRecord {
    match p.record(r.turn_id.lsn) {
        Record::TurnRecord(t) => t,
        other => panic!("not a turn record: {other:?}"),
    }
}

impl Proc {
    /// Sets the counter type's effect bytes per turn.
    fn effect_bytes(&self, bytes: u64) {
        self.rt
            .block_on(self.node.set_limits(
                pb::Limits {
                    kind: "counter".into(),
                    effect_bytes_per_turn: Some(bytes),
                    ..Default::default()
                },
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    /// `counter/<key>` fetches `spec` in one turn; its only effect.
    fn fetch(&self, key: &str, spec: &str) -> (TurnResult, pb::EffectRecord) {
        let r = self.send(&format!("counter/{key}"), msg("fetch", spec.as_bytes()));
        let record = turn_record(self, &r);
        assert_eq!(record.effects.len(), 1, "{:?}", record.effects);
        (r, record.effects[0].clone())
    }
}

fn setup() -> (Server, tempfile::TempDir, Proc) {
    let server = Server::start();
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1");
    (server, dir, p)
}

/// The default is 32 MiB, recorded with the kind's other limits.
#[test]
fn the_default_is_32_mib_and_a_set_limit_is_in_the_log() {
    assert_eq!(
        kronik_effects::KindLimits::default().effect_bytes_per_turn,
        32 << 20
    );
    let (_server, _dir, p) = setup();
    p.effect_bytes(1 << 20);
    let config = p.node.config_now();
    assert_eq!(config.limits("counter").effect_bytes_per_turn, 1 << 20);
    assert_eq!(config.limits("other").effect_bytes_per_turn, 32 << 20);
}

/// A response that would pass what is left fails its effect: the request
/// was sent, the response is not recorded, and the result says
/// EFFECT_BYTES_EXCEEDED; the guest gets `too-large` and goes on (the
/// counter guest then fails its turn, as for any failed fetch).
#[test]
fn a_response_past_the_effect_bytes_is_sent_and_not_recorded() {
    let (server, _dir, p) = setup();
    p.effect_bytes(64 << 10);
    let (r, effect) = p.fetch("a", &format!("GET {}", server.url("/big/100000")));
    assert!(!r.committed());
    assert!(r.outcome.message.contains("TooLarge"), "{:?}", r.outcome);
    assert_eq!(effect.status, pb::EffectStatus::TooLarge as i32);
    assert!(effect.request.is_some() && effect.response.is_none());
    assert!(
        effect.error.starts_with("EFFECT_BYTES_EXCEEDED:") && effect.error.contains("not recorded"),
        "{}",
        effect.error
    );
    assert_eq!(server.seen(), ["/big/100000"]);
}

/// A request that alone would pass what is left is not sent.
#[test]
fn a_request_past_the_effect_bytes_is_not_sent() {
    let (server, _dir, p) = setup();
    p.effect_bytes(64 << 10);
    let spec = format!("POST {}\n\n{}", server.url("/post"), "a".repeat(100 << 10));
    let (r, effect) = p.fetch("a", &spec);
    assert!(!r.committed());
    assert_eq!(effect.status, pb::EffectStatus::TooLarge as i32);
    assert!(effect.request.is_none() && effect.response.is_none());
    assert!(effect.error.contains("not sent"), "{}", effect.error);
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// What a turn's earlier effects recorded counts: a second request that
/// no longer fits in what the first left is not sent.
#[test]
fn what_earlier_effects_recorded_counts() {
    let (server, _dir, p) = setup();
    p.effect_bytes(200 << 10);
    let body = "a".repeat(150 << 10);
    let spec = format!(
        "POST {}\n\n{body}\n---\nPOST {}\n\n{body}",
        server.url("/one"),
        server.url("/two")
    );
    let r = p.send("counter/a", msg("fetch2", spec.as_bytes()));
    assert!(!r.committed());
    let record = turn_record(&p, &r);
    assert_eq!(record.effects.len(), 2, "{:?}", record.effects);
    assert_eq!(record.effects[0].status, pb::EffectStatus::Ok as i32);
    assert!(
        record.effects[1].error.contains("not sent"),
        "{:?}",
        record.effects[1]
    );
    assert_eq!(server.seen(), ["/one"]);
}

/// The limit is exact: an effect that records exactly what is left fits,
/// one byte less does not.
#[test]
fn the_limit_is_exact() {
    let (server, _dir, p) = setup();
    let spec = format!("GET {}", server.url("/big/1000"));
    let (r, effect) = p.fetch("a", &spec);
    assert!(r.committed(), "{:?}", r.outcome);
    let exact = kronik_sched::record_budget::effect_bytes(&effect);
    p.effect_bytes(exact);
    let (r, effect) = p.fetch("b", &spec);
    assert!(r.committed(), "{:?}", r.outcome);
    assert_eq!(kronik_sched::record_budget::effect_bytes(&effect), exact);
    p.effect_bytes(exact - 1);
    let (r, effect) = p.fetch("c", &spec);
    assert!(!r.committed());
    assert!(
        effect.error.starts_with("EFFECT_BYTES_EXCEEDED:"),
        "{}",
        effect.error
    );
    assert_eq!(server.seen().len(), 3);
}

/// A crash and a re-run: the re-run is charged what the first execution
/// recorded and refuses the same effects (the failure is the recorded
/// result, so the turn ends the same way after a restart).
#[test]
fn the_failure_survives_a_restart() {
    let (server, dir, p) = setup();
    p.effect_bytes(64 << 10);
    let (r, effect) = p.fetch("a", &format!("GET {}", server.url("/big/100000")));
    assert!(!r.committed());
    drop(p);
    let p = start(dir.path());
    let record = turn_record(&p, &r);
    assert_eq!(record.effects[0], effect);
    assert_eq!(
        p.node.config_now().limits("counter").effect_bytes_per_turn,
        64 << 10
    );
}
