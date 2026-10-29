//! M2 effect tests against a test HTTP server, with crashes at exact points:
//! the daemon is a tokio runtime that the test drops (every task dies), while
//! the test server runs on its own threads and survives.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_effects::{Delivery, Rate};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, NodeConfig, TurnResult, start_local};
use tokio::runtime::Runtime;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

// ---------------------------------------------------------------- test server

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    at: Instant,
}

#[derive(Default)]
struct ServerState {
    seen: Vec<Seen>,
    /// Requests to /hang wait until released.
    released: bool,
}

struct Server {
    addr: String,
    state: Arc<(Mutex<ServerState>, Condvar)>,
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let state = Arc::new((Mutex::new(ServerState::default()), Condvar::new()));
        let st = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let st = st.clone();
                std::thread::spawn(move || serve(stream, st));
            }
        });
        Server { addr, state }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn seen_all(&self) -> Vec<Seen> {
        self.state.0.lock().unwrap().seen.clone()
    }

    fn seen(&self, path: &str) -> Vec<Seen> {
        let g = self.state.0.lock().unwrap();
        g.seen.iter().filter(|s| s.path == path).cloned().collect()
    }

    /// Waits until `n` requests to `path` arrived.
    fn wait_for(&self, path: &str, n: usize) {
        let (m, cv) = &*self.state;
        let mut g = m.lock().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while g.seen.iter().filter(|s| s.path == path).count() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no request {n} to {path}");
            g = cv.wait_timeout(g, left).unwrap().0;
        }
    }

    fn release(&self) {
        let (m, cv) = &*self.state;
        m.lock().unwrap().released = true;
        cv.notify_all();
    }
}

fn serve(stream: TcpStream, st: Arc<(Mutex<ServerState>, Condvar)>) {
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_owned();
        let path = parts.next().unwrap_or("").to_owned();
        let mut headers = BTreeMap::new();
        loop {
            let mut h = String::new();
            if r.read_line(&mut h).unwrap_or(0) == 0 {
                return;
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let (m, cv) = &*st;
        let count = {
            let mut g = m.lock().unwrap();
            g.seen.push(Seen {
                method: method.clone(),
                path: path.clone(),
                headers: headers.clone(),
                body: body.clone(),
                at: Instant::now(),
            });
            cv.notify_all();
            g.seen.iter().filter(|s| s.path == path).count()
        };
        let reply = match path.as_str() {
            "/hang" => {
                let mut g = m.lock().unwrap();
                while !g.released {
                    g = cv.wait(g).unwrap();
                }
                format!("released {count}")
            }
            p if p.starts_with("/echo") => {
                format!("{headers:?} {}", String::from_utf8_lossy(&body))
            }
            _ => format!("ok {count}"),
        };
        // An echo server answers with the request's x-api-key as a header too.
        let echo = headers
            .get("x-api-key")
            .filter(|_| path.starts_with("/echo"))
            .map(|v| format!("x-echo: {v}\r\n"))
            .unwrap_or_default();
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n{echo}\r\n{reply}",
            reply.len()
        );
        if w.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------- daemon

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn start_with(dir: &Path, config: NodeConfig) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        start_local(env, dir, config).await.unwrap()
    });
    Proc { rt, node }
}

fn start(dir: &Path) -> Proc {
    start_with(
        dir,
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
    )
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn msg(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: vec![],
    }
}

fn reply(r: &TurnResult) -> String {
    match &r.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

impl Proc {
    fn deploy(&self) {
        let bytes = std::fs::read(COUNTER).unwrap();
        self.rt
            .block_on(self.node.deploy(&bytes, audit(), false))
            .unwrap();
    }

    fn grant(&self, cap: &str, delivery: Option<Delivery>, rate: Option<Rate>) {
        self.rt
            .block_on(
                self.node
                    .grant("counter", cap, delivery, rate, audit(), false),
            )
            .unwrap();
    }

    fn send(&self, actor: &str, m: pb::Message) -> TurnResult {
        self.rt
            .block_on(
                self.node
                    .send(ActorRef::parse(actor).unwrap(), m, audit(), false),
            )
            .unwrap()
            .unwrap()
    }

    /// Sends without waiting (the turn may never finish in this process).
    fn send_detached(&self, actor: &str, m: pb::Message) {
        let node = self.node.clone();
        let actor = ActorRef::parse(actor).unwrap();
        self.rt.spawn(async move {
            let _ = node.send(actor, m, audit(), false).await;
        });
    }

    fn kv(&self, actor: &str, k: &str) -> Option<String> {
        let a = ActorRef::parse(actor).unwrap();
        self.node
            .store()
            .db()
            .kv_get(&a.kind, &a.key, k)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap())
    }

    fn wait_until(&self, what: &str, f: impl Fn(&Proc) -> bool) {
        for _ in 0..1000 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    fn records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        self.rt
            .block_on(self.node.reader().read(1, self.node.applied_lsn(), |c| {
                out.push(c.record);
                Ok(())
            }))
            .unwrap();
        out
    }
}

/// Every record in the log, read with a fresh runtime (the daemon is dead).
fn log_records(dir: &Path) -> Vec<Record> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let reader = kronik_log::LogReader::new(env, dir.join("branches/main/log"), "main");
        let mut out = Vec::new();
        reader
            .read(1, u64::MAX, |c| {
                out.push(c.record);
                Ok(())
            })
            .await
            .unwrap();
        out
    })
}

fn turn_records(records: &[Record]) -> Vec<pb::TurnRecord> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::TurnRecord(t) => Some(t.clone()),
            _ => None,
        })
        .collect()
}

/// The re-run rebuilt the recorded request byte-for-byte: method, URL,
/// every header and the body match the first attempt.
fn assert_same_wire_request(seen: &[Seen]) {
    for (i, s) in seen.iter().enumerate().skip(1) {
        assert_eq!(
            (
                &seen[0].method,
                &seen[0].path,
                &seen[0].headers,
                &seen[0].body
            ),
            (&s.method, &s.path, &s.headers, &s.body),
            "attempt {} rebuilt a different request",
            i
        );
    }
}

// ---------------------------------------------------------------- tests

#[test]
fn denied_without_grant_then_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    let spec = format!("GET {}", server.url("/ok"));
    let r = p.send("counter/a", msg("fetch-ok", &spec));
    assert!(
        reply(&r).contains("CAPABILITY_NOT_GRANTED: http:127.0.0.1"),
        "{}",
        reply(&r)
    );
    assert!(server.seen("/ok").is_empty());
    p.grant("http:127.0.0.1", None, None);
    let r = p.send("counter/a", msg("fetch-ok", &spec));
    assert_eq!(reply(&r), "200 ok 1");
    let records = p.records();
    let turns = turn_records(&records);
    let denied = &turns[turns.len() - 2].effects[0];
    assert_eq!(denied.status, pb::EffectStatus::Denied as i32);
    let ok = &turns[turns.len() - 1].effects[0];
    assert_eq!(ok.status, pb::EffectStatus::Ok as i32);
    assert_eq!(ok.delivery, "replay-safe");
    // The allowed fetch wrote a TurnBegin and an EffectResult first; the
    // denied one needed neither.
    let begins = records
        .iter()
        .filter(|r| matches!(r, Record::TurnBegin(_)))
        .count();
    let results = records
        .iter()
        .filter(|r| matches!(r, Record::EffectResult(_)))
        .count();
    assert_eq!((begins, results), (1, 1));
    // The request carried the idempotency key.
    let seen = server.seen("/ok");
    assert_eq!(
        seen[0].headers.get("idempotency-key"),
        Some(&ok.idempotency_key)
    );
}

#[test]
fn turn_begin_is_durable_before_the_effect_and_replay_safe_reruns() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", None, None);
    p.send_detached(
        "counter/a",
        msg("fetch", &format!("GET {}", server.url("/hang"))),
    );
    server.wait_for("/hang", 1);
    drop(p); // kill: the request is in flight, no result is recorded
    let records = log_records(dir.path());
    let begin = records
        .iter()
        .find_map(|r| match r {
            Record::TurnBegin(b) => Some(b.clone()),
            _ => None,
        })
        .expect("TurnBegin must be durable before the request was sent");
    assert!(!records.iter().any(|r| matches!(r, Record::EffectResult(_))));
    server.release();
    let p = start(dir.path());
    server.wait_for("/hang", 2);
    p.wait_until("the re-run's turn record", |p| {
        turn_records(&p.records())
            .iter()
            .any(|t| t.execution_id == begin.execution_id)
    });
    let seen = server.seen("/hang");
    assert_eq!(
        seen[0].headers.get("idempotency-key"),
        seen[1].headers.get("idempotency-key")
    );
    assert_eq!(
        (seen[0].method.as_str(), &seen[0].body),
        (seen[1].method.as_str(), &seen[1].body)
    );
    assert_same_wire_request(&seen);
    let t = turn_records(&p.records())
        .into_iter()
        .find(|t| t.execution_id == begin.execution_id)
        .unwrap();
    assert_eq!(
        t.outcome.as_ref().unwrap().kind,
        pb::OutcomeKind::Committed as i32
    );
}

#[test]
fn recorded_result_is_not_requested_again_and_the_rerun_is_identical() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", Some(Delivery::IdempotencyKeyed), None);
    let spec = format!(
        "POST {}\n\nfirst\n---\nPOST {}\n\nsecond",
        server.url("/ok"),
        server.url("/hang")
    );
    p.send_detached("counter/a", msg("fetch2", &spec));
    server.wait_for("/hang", 1);
    drop(p);
    server.release();
    let p = start(dir.path());
    server.wait_for("/hang", 2);
    p.wait_until("the re-run to commit", |p| {
        turn_records(&p.records()).iter().any(|t| {
            !t.effects.is_empty()
                && t.outcome
                    .as_ref()
                    .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
        })
    });
    // The first effect's result was recorded: the server saw it once.
    assert_eq!(server.seen("/ok").len(), 1);
    let hang = server.seen("/hang");
    assert_eq!(hang.len(), 2);
    assert_eq!(hang[0].body, hang[1].body);
    assert_eq!(
        hang[0].headers.get("idempotency-key"),
        hang[1].headers.get("idempotency-key")
    );
    assert_same_wire_request(&hang);
    let t = turn_records(&p.records()).pop().unwrap();
    assert_eq!(t.effects.len(), 2);
    assert!(
        reply_of(&t).contains("ok 1 | 200 released 2"),
        "{}",
        reply_of(&t)
    );
}

#[test]
fn an_erased_subjects_open_turn_reruns_as_a_subject_erased_dead_letter() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", None, None);
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false),
    )
    .unwrap();
    // A message of a subject whose effect hangs: the turn is open with a
    // durable, sealed TurnBegin.
    p.send_detached(
        "counter/a",
        pb::Message {
            name: "fetch".into(),
            content_type: "text/plain".into(),
            body: Some(pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Plain(
                    format!("GET {}", server.url("/hang")).into_bytes(),
                )),
            }),
            blobs: vec![],
        },
    );
    server.wait_for("/hang", 1);
    // The subject is erased while the turn is open, then the daemon dies.
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false))
        .unwrap();
    drop(p); // kill: the turn stays open

    // The restart re-runs the open turn, but its sealed input belongs to an
    // erased subject: the turn fails with SUBJECT_ERASED and dead-letters.
    let p = start(dir.path());
    p.wait_until("the SUBJECT_ERASED dead letter", |p| {
        p.node
            .store()
            .db()
            .dead_letters(0, 10)
            .unwrap()
            .iter()
            .any(|d| d.error_code == "SUBJECT_ERASED")
    });
    std::thread::sleep(Duration::from_millis(200));
    let dl = p.node.store().db().dead_letters(0, 10).unwrap();
    assert_eq!(dl.len(), 1, "{dl:?}");
    assert_eq!(dl[0].error_code, "SUBJECT_ERASED");
    assert_eq!(
        (dl[0].actor.kind.as_str(), dl[0].actor.key.as_str()),
        ("counter", "a")
    );
    assert!(
        matches!(dl[0].input.kind, Some(pb::input::Kind::Message(_))),
        "{:?}",
        dl[0].input
    );
    let t = turn_records(&p.records())
        .into_iter()
        .find(|t| {
            t.outcome
                .as_ref()
                .is_some_and(|o| o.error_code == "SUBJECT_ERASED")
        })
        .expect("the re-run's failed turn record");
    assert_eq!(
        t.outcome.as_ref().unwrap().kind,
        pb::OutcomeKind::Failed as i32
    );
    // The effect was never re-sent: the input never reached the guest.
    assert_eq!(server.seen("/hang").len(), 1);
    server.release();
}

#[test]
fn effect_timeout_fires_when_the_server_hangs() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", Some(Delivery::IdempotencyKeyed), None);
    // A 300 ms effect timeout for the kind: the hanging server never
    // answers, and the turn finishes with a timed-out effect instead of
    // waiting the 10 s default.
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "counter".into(),
            effect_timeout_ms: Some(300),
            ..Default::default()
        },
        audit(),
        false,
    ))
    .unwrap();
    let started = Instant::now();
    let r = p.send(
        "counter/a",
        msg("fetch-ok", &format!("GET {}", server.url("/hang"))),
    );
    assert!(
        reply(&r).starts_with("error"),
        "the guest saw no error: {}",
        reply(&r)
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the configured timeout did not fire: {:?}",
        started.elapsed()
    );
    let t = turn_records(&p.records()).pop().unwrap();
    assert_eq!(
        t.outcome.as_ref().unwrap().kind,
        pb::OutcomeKind::Committed as i32
    );
    assert_eq!(t.effects.len(), 1);
    assert_eq!(t.effects[0].status, pb::EffectStatus::Timeout as i32);
    assert_eq!(t.effects[0].error, "no response within 300 ms");
    assert!(
        t.effects[0].duration_us >= 300_000,
        "{}",
        t.effects[0].duration_us
    );
    server.release();
}

fn reply_of(t: &pb::TurnRecord) -> String {
    match t.outcome.as_ref().and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

#[test]
fn unsafe_effect_is_not_retried_and_dead_letters_with_outcome_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    // No delivery class: POST defaults to unsafe.
    p.grant("http:127.0.0.1", None, None);
    p.send_detached(
        "counter/a",
        msg("fetch", &format!("POST {}\n\ncharge", server.url("/hang"))),
    );
    server.wait_for("/hang", 1);
    drop(p);
    server.release();
    let p = start(dir.path());
    p.wait_until("the dead letter", |p| {
        !p.node.store().db().dead_letters(0, 10).unwrap().is_empty()
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        server.seen("/hang").len(),
        1,
        "an unsafe effect must not be sent again"
    );
    let dl = p.node.store().db().dead_letters(0, 10).unwrap();
    assert_eq!(dl[0].error_code, "EFFECT_OUTCOME_UNKNOWN");
    let t = turn_records(&p.records()).pop().unwrap();
    assert_eq!(
        t.outcome.as_ref().unwrap().kind,
        pb::OutcomeKind::EffectOutcomeUnknown as i32
    );
    let e = &t.effects[0];
    assert_eq!(e.status, pb::EffectStatus::OutcomeUnknown as i32);
    assert_eq!(e.delivery, "unsafe");
    // The dead letter's turn holds the unsent request.
    assert!(e.request.is_some());
}

#[test]
fn call_crash_before_the_result_is_recorded_reuses_the_saved_response() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            test_hold_after_call: true,
            ..NodeConfig::default()
        },
    );
    p.deploy();
    p.send_detached("counter/a", msg("call", "counter/b increment"));
    // B commits; A holds before recording the call's result.
    p.wait_until("the callee's commit", |p| {
        p.kv("counter/b", "n").as_deref() == Some("1")
    });
    drop(p);
    let p = start(dir.path());
    p.wait_until("the caller's re-run", |p| {
        turn_records(&p.records())
            .iter()
            .any(|t| t.actor.as_ref().is_some_and(|a| a.key == "a") && !t.effects.is_empty())
    });
    // B ran exactly once.
    assert_eq!(p.kv("counter/b", "n").as_deref(), Some("1"));
    let b_turns = p
        .node
        .store()
        .db()
        .actor("counter", "b")
        .unwrap()
        .unwrap()
        .turns;
    assert_eq!(b_turns, 1);
    let a = turn_records(&p.records())
        .into_iter()
        .find(|t| t.actor.as_ref().is_some_and(|a| a.key == "a"))
        .unwrap();
    assert_eq!(reply_of(&a), "reply 1");
    assert_eq!(a.effects[0].kind, "actor.call");
    assert_eq!(a.effects[0].status, pb::EffectStatus::Ok as i32);
}

/// Every effect records when it started in the turn and how long it took
/// (m28-otel §3.3), not only fetch: the call's span covers the callee.
#[test]
fn a_call_effect_records_its_offset_and_duration() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    let r = p.send("counter/a", msg("call", "counter/b increment"));
    assert!(r.committed(), "{r:?}");
    let a = turn_records(&p.records())
        .into_iter()
        .find(|t| t.actor.as_ref().is_some_and(|a| a.key == "a"))
        .unwrap();
    let call = &a.effects[0];
    assert_eq!(call.kind, "actor.call");
    assert!(call.offset_us > 0, "{call:?}");
    assert!(call.duration_us > 0, "{call:?}");
}

#[test]
fn compensations_and_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    // With a compensation that succeeds: B is incremented by the call and
    // again by the compensation (the test guest's "increment").
    let r = p.send(
        "counter/a",
        msg("call-fail", "counter/b increment increment"),
    );
    assert!(!r.committed());
    p.wait_until("the compensation", |p| {
        p.kv("counter/b", "n").as_deref() == Some("2")
    });
    p.wait_until("the orphan to resolve", |p| {
        p.node.store().db().orphans(false).unwrap().is_empty()
    });
    assert_eq!(p.node.store().db().orphans(true).unwrap().len(), 1);
    // Without a compensation: the change is an orphan.
    p.send("counter/a", msg("call-fail", "counter/c increment"));
    let orphans = p.node.store().db().orphans(false).unwrap();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].callee.to_string(), "counter/c");
    assert!(orphans[0].compensation_id.is_none());
    // A compensation that fails is a dead letter and the orphan stays.
    p.send("counter/a", msg("call-fail", "counter/d increment fail"));
    p.wait_until("the failed compensation", |p| {
        p.node
            .store()
            .db()
            .dead_letters(0, 10)
            .unwrap()
            .iter()
            .any(|d| d.actor.key == "d")
    });
    let orphans = p.node.store().db().orphans(false).unwrap();
    assert!(
        orphans
            .iter()
            .any(|o| o.callee.key == "d" && o.compensation_id.is_some())
    );
    // Reentrant calls fail at once.
    let r = p.send("counter/a", msg("call", "counter/a increment"));
    assert!(reply(&r).contains("Reentrant"), "{}", reply(&r));
}

#[test]
fn timers_fire_survive_restart_and_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    let id = reply(&p.send("counter/a", msg("schedule", "50 increment")));
    p.wait_until("the timer", |p| {
        p.kv("counter/a", "n").as_deref() == Some("1")
    });
    assert!(p.node.store().db().timers(None).unwrap().is_empty());
    let r = p.send("counter/a", msg("cancel", &id));
    assert_eq!(reply(&r), "false");
    let id = reply(&p.send("counter/a", msg("schedule", "100000 increment")));
    assert_eq!(reply(&p.send("counter/a", msg("cancel", &id))), "true");
    assert!(p.node.store().db().timers(None).unwrap().is_empty());
    p.send("counter/a", msg("schedule", "400 increment"));
    drop(p);
    let p = start(dir.path());
    // state.db shows the write before the applied LSN (which bounds what
    // `records` reads) moves past it, so wait for the record too.
    let is_timer = |t: &pb::TurnRecord| {
        matches!(
            t.input.as_ref().and_then(|i| i.kind.as_ref()),
            Some(pb::input::Kind::Timer(_))
        )
    };
    p.wait_until("the timer after restart", |p| {
        p.kv("counter/a", "n").as_deref() == Some("2")
            && turn_records(&p.records()).last().is_some_and(is_timer)
    });
    let t = turn_records(&p.records()).pop().unwrap();
    let Some(pb::input::Kind::Timer(input)) = t.input.and_then(|i| i.kind) else {
        panic!("not a timer turn");
    };
    assert!(t.logical_time_ms >= input.due_ms);
}

#[test]
fn rate_limit_holds_across_turns() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", None, Some(Rate::parse("2/s").unwrap()));
    let spec = format!("GET {}", server.url("/ok"));
    for i in 0..6 {
        p.send_detached(&format!("counter/r{i}"), msg("fetch-ok", &spec));
    }
    server.wait_for("/ok", 6);
    let times: Vec<Instant> = server.seen("/ok").iter().map(|s| s.at).collect();
    for (i, t) in times.iter().enumerate() {
        let in_window = times[i..]
            .iter()
            // The limiter bounds send times; arrivals carry scheduling
            // jitter under load, so the window leaves 300 ms for it (without
            // the limiter all six arrive within milliseconds).
            .take_while(|u| u.duration_since(*t) < Duration::from_millis(700))
            .count();
        assert!(in_window <= 2, "{in_window} calls within one second");
    }
}

#[test]
fn secrets_never_leak_without_reveal() {
    const SECRET: &str = "leak-test-value-7f3a9c2e";
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.node
        .secret_set("api-key", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    p.grant("http:127.0.0.1", None, None);
    p.grant("secret:api-key", None, None);
    // HMAC on the host matches a local computation.
    let r = p.send("counter/a", msg("hmac", "api-key\nhello"));
    let want: String = kronik_effects::crypto::hmac_sha256(SECRET.as_bytes(), b"hello")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(reply(&r), want);
    // Without secret-reveal, every exfiltration path comes back empty.
    let r = p.send(
        "counter/a",
        msg("exfiltrate", &format!("api-key {}", server.url("/echo"))),
    );
    let loot = reply(&r);
    assert!(
        loot.contains("CAPABILITY_NOT_GRANTED: secret-reveal:api-key"),
        "{loot}"
    );
    assert!(
        loot.contains("[secret:api-key]"),
        "the echo must be scrubbed: {loot}"
    );
    assert!(!loot.contains(SECRET));
    // The secret did go to the server as a header.
    assert_eq!(
        server.seen("/echo")[0]
            .headers
            .get("x-secret")
            .map(String::as_str),
        Some(SECRET)
    );
    p.wait_until("the sink", |p| p.kv("counter/sink", "stored").is_some());
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the secret value is in {leaks:?}");

    // With secret-reveal the guest gets the value, which the turn record
    // (and so the reply) holds only scrubbed.
    let p = start(dir.path());
    p.grant("secret-reveal:api-key", None, None);
    let r = p.send("counter/a", msg("reveal", "api-key"));
    assert_eq!(reply(&r), "[secret:api-key]");
}

const COUNTER_WASI_HTTP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-wasi-http.wasm"
);

/// M22 (ADR 0070): standard fetch through `wasi:http` is an `http.fetch`
/// effect. A `{{secret:NAME}}` header needs `secret:NAME`, carries the value
/// only on the wire, and the guest, the records, the logs and the data
/// directory never hold it; the echo comes back scrubbed.
#[test]
fn standard_fetch_secret_headers_never_reach_the_guest_or_the_log() {
    const SECRET: &str = "wasi-http-secret-4c1d9e7a";
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    let wasm = std::fs::read(COUNTER_WASI_HTTP).unwrap();
    p.rt.block_on(p.node.deploy(&wasm, audit(), false)).unwrap();
    p.node
        .secret_set("api-key", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    p.grant("http:127.0.0.1", None, None);
    let spec = |secret: &str| {
        format!(
            "POST {}\nx-api-key: Bearer {{{{secret:{secret}}}}}\n\necho",
            server.url("/echo")
        )
    };
    // Without `secret:api-key` the request is denied (a denied record).
    let r = p.send("counter/a", msg("wfetch", &spec("api-key")));
    assert_eq!(reply(&r), "error ErrorCode::HttpRequestDenied", "{r:?}");
    assert!(server.seen("/echo").is_empty());
    p.grant("secret:api-key", None, None);
    let r = p.send("counter/a", msg("wfetch", &spec("api-key")));
    let echo = reply(&r);
    assert!(echo.starts_with("200 "), "{echo}");
    assert!(echo.contains("Bearer [secret:api-key]"), "scrubbed: {echo}");
    assert!(!echo.contains(SECRET));
    assert_eq!(
        server.seen("/echo")[0]
            .headers
            .get("x-api-key")
            .map(String::as_str),
        Some(format!("Bearer {SECRET}").as_str())
    );
    // An unknown secret is denied too.
    p.grant("secret:missing", None, None);
    let r = p.send("counter/a", msg("wfetch", &spec("missing")));
    assert_eq!(reply(&r), "error ErrorCode::HttpRequestDenied");
    assert_eq!(server.seen("/echo").len(), 1);
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the secret value is in {leaks:?}");
}

fn scan(dir: &Path, needle: &[u8], hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            scan(&p, needle, hits);
        } else {
            let bytes = std::fs::read(&p).unwrap();
            if bytes.windows(needle.len()).any(|w| w == needle) {
                hits.push(p.display().to_string());
            }
        }
    }
}

const NOTES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/notes.wasm");

#[test]
fn failed_compensation_resend_resolves_the_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    // The compensation `flaky` fails until `allow` ran on B.
    let r = p.send("counter/a", msg("call-fail", "counter/b increment flaky"));
    assert!(!r.committed());
    p.wait_until("the failed compensation", |p| {
        p.node
            .store()
            .db()
            .dead_letters(0, 10)
            .unwrap()
            .iter()
            .any(|d| d.actor.key == "b")
    });
    let orphans = p.node.store().db().orphans(false).unwrap();
    assert_eq!(orphans.len(), 1, "the orphan stays visible: {orphans:?}");
    assert!(orphans[0].compensation_id.is_some());
    let dl = p.node.store().db().dead_letters(0, 10).unwrap();
    let dead = dl.iter().find(|d| d.actor.key == "b").unwrap().lsn;
    // Make the compensation succeed and resend it.
    p.send("counter/b", msg("allow", ""));
    let resent =
        p.rt.block_on(p.node.resend(dead, audit(), false))
            .unwrap()
            .unwrap();
    assert!(resent.committed(), "{resent:?}");
    assert!(p.node.store().db().orphans(false).unwrap().is_empty());
    let all = p.node.store().db().orphans(true).unwrap();
    assert_eq!(all[0].resolved_lsn, Some(resent.turn_id.lsn));
    // B: the call's increment and the compensation's.
    assert_eq!(p.kv("counter/b", "n").as_deref(), Some("2"));
}

#[test]
fn revealed_values_are_scrubbed_from_state_messages_replies_sql_and_files() {
    const SECRET: &str = "reveal-scrub-value-91c4e7";
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false),
    )
    .unwrap();
    p.node
        .secret_set("db-password", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    p.grant("secret-reveal:db-password", None, None);
    p.rt.block_on(p.node.grant(
        "notes",
        "secret-reveal:db-password",
        None,
        None,
        audit(),
        false,
    ))
    .unwrap();
    let r = p.send("counter/a", msg("reveal-persist", "db-password"));
    assert!(r.committed(), "{r:?}");
    assert_eq!(reply(&r), "value [secret:db-password]");
    assert_eq!(
        p.kv("counter/a", "revealed").as_deref(),
        Some("[secret:db-password]")
    );
    p.wait_until("the sink", |p| p.kv("counter/sink", "stored").is_some());
    assert_eq!(
        p.kv("counter/sink", "stored").as_deref(),
        Some("[secret:db-password]")
    );
    let r = p.send("notes/n", msg("add-secret", "db-password"));
    assert!(r.committed(), "{r:?}");
    let r = p.send("notes/n", msg("list", ""));
    assert_eq!(reply(&r), "secret is [secret:db-password] [-]\n");
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the revealed value is in {leaks:?}");
}

#[test]
fn sql_size_limit_per_kind() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false),
    )
    .unwrap();
    let limits = pb::Limits {
        kind: "notes".into(),
        sql_bytes_per_actor: Some(64 << 10),
        ..Default::default()
    };
    p.rt.block_on(p.node.set_limits(limits, audit(), false))
        .unwrap();
    let big = "x".repeat(8 << 10);
    let mut failed = None;
    for i in 0..40 {
        let r = p.send("notes/n", msg("add", &big));
        if !r.committed() {
            failed = Some((i, r.outcome.message.clone()));
            break;
        }
    }
    let (n, why) = failed.expect("the 64 KiB limit must stop inserts");
    assert!(n > 2, "failed too early: {n}");
    assert!(why.contains("TooLarge"), "{why}");
    // Raising the limit lets the actor grow again.
    let limits = pb::Limits {
        kind: "notes".into(),
        sql_bytes_per_actor: Some(16 << 20),
        ..Default::default()
    };
    p.rt.block_on(p.node.set_limits(limits, audit(), false))
        .unwrap();
    assert!(p.send("notes/n", msg("add", &big)).committed());
}

#[test]
fn sql_size_default_comes_from_the_node_and_limits_set_wins() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            sql_bytes_per_actor: 64 << 10,
            ..NodeConfig::default()
        },
    );
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false),
    )
    .unwrap();
    let big = "x".repeat(8 << 10);
    let mut failed = None;
    for i in 0..40 {
        let r = p.send("notes/n", msg("add", &big));
        if !r.committed() {
            failed = Some((i, r.outcome.message.clone()));
            break;
        }
    }
    let (n, why) = failed.expect("the installation 64 KiB limit must stop inserts");
    assert!(n > 2, "failed too early: {n}");
    assert!(why.contains("TooLarge"), "{why}");
    let limits = pb::Limits {
        kind: "notes".into(),
        sql_bytes_per_actor: Some(16 << 20),
        ..Default::default()
    };
    p.rt.block_on(p.node.set_limits(limits, audit(), false))
        .unwrap();
    assert!(p.send("notes/n", msg("add", &big)).committed());
}

#[test]
fn deploy_warns_only_about_capabilities_not_granted() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = start(dir.path());
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/webhook-relay.wasm"
    ))
    .unwrap();
    p.rt.block_on(p.node.grant(
        "webhook-relay",
        "secret:relay-signing-key",
        None,
        None,
        audit(),
        false,
    ))
    .unwrap();
    let r =
        p.rt.block_on(p.node.deploy(&bytes, audit(), false))
            .unwrap();
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert!(r.warnings[0].contains("http:webhooks.example.com"));
}

#[test]
fn bodiless_requests_and_messages_are_readable_from_the_log() {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let p = start(dir.path());
    p.deploy();
    let m = pb::Message {
        name: "increment".into(),
        content_type: String::new(),
        body: None,
        blobs: vec![],
    };
    assert!(p.send("counter/a", m).committed());
    let http = pb::HttpInput {
        method: "POST".into(),
        path: "/counter/a/increment".into(),
        params: vec![
            pb::Param {
                name: "key".into(),
                value: "a".into(),
                sealed_value: None,
            },
            pb::Param {
                name: "op".into(),
                value: "increment".into(),
                sealed_value: None,
            },
        ],
        route: "/counter/{key}/{op}".into(),
        ..Default::default()
    };
    let w = match p
        .node
        .ingress(ActorRef::parse("counter/a").unwrap(), http, None)
        .unwrap()
    {
        kronik_sched::Ingress::Started(w) => w,
        _ => panic!("expected a new root input"),
    };
    assert!(p.rt.block_on(w.wait()).unwrap().committed());
    // Every record decodes (the reader validates them).
    assert_eq!(turn_records(&p.records()).len(), 2);
}

const LEAKY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/leaky.wasm");

fn subject_msg(name: &str, body: &str, subject: &str) -> pb::Message {
    let mut m = msg(name, body);
    if let Some(b) = m.body.as_mut() {
        b.subject = Some(subject.into());
    }
    m
}

/// The node takes turns: it is not fatal.
fn takes_turns(p: &Proc) {
    let r = p.send("counter/alive", msg("increment", ""));
    assert!(r.committed(), "{r:?}");
}

/// Review H1 (v0.1): with privacy mode on, a subject's turn whose call
/// succeeded and which then fails is applied (its call request is sealed,
/// and routing never reads it), and the node restarts.
#[test]
fn a_subjects_failed_turn_after_a_call_keeps_the_node_running_with_privacy_on() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false),
    )
    .unwrap();
    let r = p.send(
        "counter/a",
        subject_msg("call-fail", "counter/b increment", "user:1"),
    );
    assert!(!r.committed(), "{r:?}");
    takes_turns(&p);
    let orphans = p.node.store().db().orphans(false).unwrap();
    assert_eq!(orphans.len(), 1, "{orphans:?}");
    assert_eq!(
        (
            orphans[0].callee.kind.as_str(),
            orphans[0].callee.key.as_str()
        ),
        ("counter", "b")
    );
    drop(p);
    let p = start(dir.path());
    takes_turns(&p);
}

/// Review H2 (v0.1): a revealed value passed in a call's compensation of a
/// failed turn is scrubbed in the structured message, so the record still
/// decodes, the node keeps running and restarts, and the value is nowhere
/// on disk; the compensation the callee gets is scrubbed as well.
#[test]
fn a_revealed_value_in_a_compensation_is_scrubbed_and_the_node_restarts() {
    const SECRET: &str = "VALUE-comp-5d1e9a";
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(LEAKY).unwrap(), audit(), false),
    )
    .unwrap();
    p.node
        .secret_set("k1", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    p.rt.block_on(
        p.node
            .grant("leaky", "secret-reveal:k1", None, None, audit(), false),
    )
    .unwrap();
    let r = p.send("leaky/a", msg("reveal-comp", "k1 leaky/b"));
    assert!(!r.committed(), "{r:?}");
    takes_turns(&p);
    let kv = |p: &Proc, k: &str| {
        p.node
            .store()
            .db()
            .kv_get("leaky", "b", k)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap())
    };
    p.wait_until("the compensation", |p| kv(p, "undone").is_some());
    assert_eq!(kv(&p, "undone").as_deref(), Some("[secret:k1]"));
    drop(p);
    let p = start(dir.path());
    takes_turns(&p);
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the revealed value is in {leaks:?}");
}

/// Review H3 (v0.1): a revealed value sent in a fetch's URL, a text header
/// and the body reaches the server, but neither the log (EffectResult and
/// TurnRecord), state.db nor a snapshot.
#[test]
fn a_revealed_value_in_a_fetch_is_not_written_anywhere() {
    const SECRET: &str = "VALUE-fetch-2b7c41";
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(LEAKY).unwrap(), audit(), false),
    )
    .unwrap();
    p.node
        .secret_set("k1", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    for cap in ["secret-reveal:k1", "http:127.0.0.1"] {
        p.rt.block_on(p.node.grant("leaky", cap, None, None, audit(), false))
            .unwrap();
    }
    let r = p.send(
        "leaky/a",
        msg("reveal-fetch", &format!("k1 {}", server.url("/echo"))),
    );
    assert!(r.committed(), "{r:?}");
    let seen = server.seen(&format!("/echo?key={SECRET}"));
    assert_eq!(
        seen[0].headers.get("x-api-key").map(String::as_str),
        Some(SECRET),
        "the value went out"
    );
    let _ = p.rt.block_on(p.node.snapshot("i8 test"));
    takes_turns(&p);
    drop(p);
    let mut leaks = Vec::new();
    scan(dir.path(), SECRET.as_bytes(), &mut leaks);
    assert!(leaks.is_empty(), "the revealed value is in {leaks:?}");
}

/// Re-review #2 (v0.1): the guest sees a response that echoes a revealed
/// value already scrubbed, live as on a crash re-run (which answers from
/// the scrubbed recording), so a request built from that response is the
/// same both times and the re-run does not diverge.
#[test]
fn a_rerun_after_an_echoed_revealed_value_does_not_diverge() {
    const SECRET: &str = "VALUE-echo-6a90c3";
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(LEAKY).unwrap(), audit(), false),
    )
    .unwrap();
    p.node
        .secret_set("k1", SECRET.as_bytes(), &audit(), false)
        .unwrap();
    for cap in ["secret-reveal:k1", "http:127.0.0.1"] {
        p.rt.block_on(p.node.grant("leaky", cap, None, None, audit(), false))
            .unwrap();
    }
    p.send_detached(
        "leaky/a",
        msg(
            "reveal-echo-len",
            &format!(
                "k1 {} {} {}",
                server.url("/echo"),
                server.url("/next"),
                server.url("/hang")
            ),
        ),
    );
    server.wait_for("/hang", 1);
    drop(p); // killed mid-turn: the echo and /next are recorded
    let p = start(dir.path());
    server.release();
    let is_it = |t: &pb::TurnRecord| {
        t.actor.as_ref().is_some_and(|a| a.kind == "leaky")
            && matches!(
                t.input.as_ref().and_then(|i| i.kind.as_ref()),
                Some(pb::input::Kind::Message(_))
            )
    };
    p.wait_until("the re-run's turn", |p| {
        turn_records(&p.records()).iter().any(is_it)
    });
    let t = turn_records(&p.records())
        .into_iter()
        .find(|t| is_it(t))
        .unwrap();
    let o = t.outcome.clone().unwrap();
    assert_eq!(
        (o.kind, o.error_code.as_str()),
        (pb::OutcomeKind::Committed as i32, ""),
        "{}",
        o.message
    );
    // /next was sent once: the re-run answered it from the recording.
    let next: Vec<_> = server
        .seen_all()
        .into_iter()
        .filter(|s| s.path.starts_with("/next"))
        .collect();
    assert_eq!(
        next.len(),
        1,
        "{:?}",
        next.iter().map(|s| &s.path).collect::<Vec<_>>()
    );
    server.release();
}
