//! M2 effect tests against a test HTTP server, with crashes at exact points:
//! the daemon is a tokio runtime that the test drops (every task dies), while
//! the test server runs on its own threads and survives.

// Test helpers outside #[test] functions may unwrap, and the test server
// uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::collections::BTreeMap;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use common::{
    Proc, audit, http, log_records, msg, repoint_open_turn, start_proc, start_proc_env, wait_parked,
};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_effects::{Delivery, Rate};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, TurnResult, start_local};
use prost::Message as _;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const COUNTER_BODY_V2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-body-v2.wasm"
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
        Self::start_on("127.0.0.1:0")
    }

    fn start_on(bind: &str) -> Server {
        let state = Arc::new((Mutex::new(ServerState::default()), Condvar::new()));
        let st = state.clone();
        let addr = http::serve_on(bind, move |req, w| serve(req, w, &st));
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

fn serve(req: http::Request, w: &mut TcpStream, st: &(Mutex<ServerState>, Condvar)) {
    let http::Request {
        method,
        path,
        headers,
        body,
        ..
    } = req;
    let headers: BTreeMap<String, String> = headers.into_iter().collect();
    let (m, cv) = st;
    let count = {
        let mut g = m.lock().unwrap();
        g.seen.push(Seen {
            method,
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
    let _ = w.write_all(resp.as_bytes());
}

// ---------------------------------------------------------------- daemon

fn start_with(dir: &Path, config: NodeConfig) -> Proc {
    start_proc(dir, config)
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
        self.deploy_file(COUNTER);
    }

    /// Counter and the leaky guest deployed, the secret `k1` set to `secret`,
    /// and `leaky` granted each of `caps`.
    fn leaky(&self, secret: &str, caps: &[&str]) {
        self.deploy();
        self.deploy_file(LEAKY);
        self.rt
            .block_on(self.node.secret_set(
                "k1",
                secret.as_bytes().to_vec(),
                &audit(),
                false,
                self.owner(),
            ))
            .unwrap();
        for cap in caps {
            self.rt
                .block_on(self.node.grant(
                    "leaky",
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
    }

    /// Sets `notes`' SQL bytes per actor.
    fn sql_limit(&self, bytes: u64) {
        self.rt
            .block_on(self.node.set_limits(
                pb::Limits {
                    kind: "notes".into(),
                    sql_bytes_per_actor: Some(bytes),
                    ..Default::default()
                },
                audit(),
                false,
                self.owner(),
            ))
            .unwrap();
    }

    fn grant(&self, cap: &str, delivery: Option<Delivery>, rate: Option<Rate>) {
        self.rt
            .block_on(self.node.grant(
                "counter",
                cap,
                delivery,
                rate,
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

    /// Sends without waiting (the turn may never finish in this process).
    fn send_detached(&self, actor: &str, m: pb::Message) {
        let node = self.node.clone();
        let actor = ActorRef::parse(actor).unwrap();
        self.rt.spawn(async move {
            let original = node.local_operator_authority().unwrap();
            let _ = node.send(actor, m, audit(), false, original).await;
        });
    }
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

/// `http:[::1]` is a grant, a fetch to `http://[::1]/` is not
/// `CAPABILITY_NOT_GRANTED`, and a port in the capability is refused.
#[test]
fn an_ipv6_literal_grant_authorizes_the_bracketed_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start_on("[::1]:0");
    let p = start(dir.path());
    p.deploy();
    let spec = format!("GET {}", server.url("/ok"));

    let denied = p.send("counter/a", msg("fetch-ok", &spec));
    let text = reply(&denied);
    assert!(text.contains("CAPABILITY_NOT_GRANTED: http:::1"), "{text}");
    assert!(!text.contains("http:[::1]"), "{text}");
    assert!(server.seen("/ok").is_empty());
    let turns = turn_records(&p.records());
    assert_eq!(
        turns.last().unwrap().effects[0].error,
        "CAPABILITY_NOT_GRANTED: http:::1"
    );

    let port = p.rt.block_on(p.node.grant(
        "counter",
        "http:example.com:8443",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        p.owner(),
    ));
    let err = port.unwrap_err();
    assert_eq!(err.code, kronik_core::error::ErrorCode::BadRequest);
    assert!(
        err.message.contains("ports are not part of the capability"),
        "{}",
        err.message
    );

    p.grant("http:[::1]", None, None);
    assert_eq!(
        p.node
            .config_now()
            .http_grant("counter", "[::1]")
            .unwrap()
            .capability,
        "http:::1"
    );
    let allowed = p.send("counter/b", msg("fetch-ok", &spec));
    assert_eq!(reply(&allowed), "200 ok 1");
    assert_eq!(server.seen("/ok").len(), 1);
}

/// #269: the `http:` capability names only a host. Beyond loopback an
/// explicit port is a target no grant can cover, and a secret header never
/// transits cleartext http. Loopback keeps both (the local servers of these
/// tests and of the identity examples).
#[test]
fn beyond_loopback_an_explicit_port_is_refused_even_when_the_host_is_granted() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:example.com", None, None);
    let r = p.send(
        "counter/a",
        msg("fetch-ok", "GET https://example.com:8443/x"),
    );
    assert!(
        reply(&r).contains("HTTP_PORT_REFUSED: example.com:8443"),
        "{}",
        reply(&r)
    );
    // A denial needs neither a TurnBegin nor an EffectResult.
    let records = p.records();
    assert!(!records.iter().any(|r| matches!(r, Record::TurnBegin(_))));
    assert!(!records.iter().any(|r| matches!(r, Record::EffectResult(_))));
    let turns = turn_records(&records);
    let denied = &turns.last().unwrap().effects[0];
    assert_eq!(denied.status, pb::EffectStatus::Denied as i32);
    assert_eq!(denied.target, "http:example.com");
    assert_eq!(denied.error, "HTTP_PORT_REFUSED: example.com:8443");
}

#[test]
fn beyond_loopback_a_secret_header_over_cleartext_http_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(p.node.secret_set(
        "api-key",
        b"secret-value-269".to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.grant("http:example.com", None, None);
    p.grant("secret:api-key", None, None);
    // The host is granted and the secret exists; the cleartext target is
    // what the gate refuses.
    let spec = "GET http://example.com/x\nS x-api-key api-key {}";
    let r = p.send("counter/a", msg("fetch-ok", spec));
    assert!(
        reply(&r).contains("SECRET_CLEARTEXT_REFUSED: example.com"),
        "{}",
        reply(&r)
    );
    let turns = turn_records(&p.records());
    let denied = &turns.last().unwrap().effects[0];
    assert_eq!(denied.status, pb::EffectStatus::Denied as i32);
    assert_eq!(denied.error, "SECRET_CLEARTEXT_REFUSED: example.com");
    // The secret was never resolved: no TurnBegin was written for its use.
    assert!(
        !p.records()
            .iter()
            .any(|r| matches!(r, Record::TurnBegin(_)))
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
        msg("fetch", format!("GET {}", server.url("/hang"))),
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

/// Crash after a recorded POST, then restart on guest code that builds a
/// different body for that ordinal. The gate must trap `REPLAY_DIVERGED`
/// and must not send the call again. `RecordedMatch` is unit-tested; this
/// is the gate. Returning `Ok(None)` from `EffectGate::recorded` on a
/// mismatch still passes that unit test and fails this one.
///
/// A re-run loads `TurnBegin.code_hash`, so a deploy would not change the
/// guest. The test installs `counter-body-v2` (the same actor, with `" v2"`
/// appended to fetch bodies) and points the open turn at that hash.
/// An identical re-run is
/// `recorded_result_is_not_requested_again_and_the_rerun_is_identical`.
#[test]
fn a_crash_rerun_with_a_different_body_traps_and_is_not_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let armed = dir.path().join("hold-armed");
    let reached = dir.path().join("hold-reached");
    std::fs::write(&armed, b"armed").unwrap();
    let p = start_with(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            test_hold: Some(kronik_sched::TestHold {
                point: kronik_sched::HoldPoint::BeforeCommit,
                armed: armed.clone(),
                reached: reached.clone(),
            }),
            ..NodeConfig::default()
        },
    );
    p.deploy();
    // POST's default delivery is unsafe. A mismatch must still trap, not
    // become outcome-unknown and not go out again.
    p.grant("http:127.0.0.1", None, None);
    let spec = format!("POST {}\n\nfirst", server.url("/ok"));
    p.send_detached("counter/a", msg("fetch", &spec));

    let open = wait_parked(&p, &reached, "http.fetch");
    server.wait_for("/ok", 1);
    assert_eq!(server.seen("/ok")[0].body, b"first");
    let execution_id = open.execution_id.clone();
    drop(p);

    repoint_open_turn(
        dir.path(),
        &execution_id,
        &std::fs::read(COUNTER_BODY_V2).unwrap(),
        open.lsn,
        open.pos.segment,
    );

    let p = start(dir.path());
    // Close, then assert the code. Waiting only for REPLAY_DIVERGED hides a
    // gate that treats the mismatch as unrecorded and closes another way.
    p.wait_until("the re-run to close", |p| {
        turn_records(&p.records())
            .iter()
            .any(|t| t.execution_id == execution_id)
    });
    let t = turn_records(&p.records())
        .into_iter()
        .find(|t| t.execution_id == execution_id)
        .unwrap();
    let outcome = t.outcome.as_ref().unwrap();
    assert_eq!(outcome.kind, pb::OutcomeKind::Trap as i32, "{outcome:?}");
    assert_eq!(outcome.error_code, "REPLAY_DIVERGED", "{outcome:?}");
    assert!(
        outcome.message.contains("http.fetch")
            && outcome
                .message
                .contains("differs from the recorded request"),
        "{}",
        outcome.message
    );
    assert!(
        t.effects
            .iter()
            .all(|e| e.status != pb::EffectStatus::OutcomeUnknown as i32),
        "a mismatch was treated as an unrecorded unsafe effect: {t:?}"
    );
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    let seen = server.seen("/ok");
    assert_eq!(seen.len(), 1, "the diverged POST was sent again: {seen:?}");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].body, b"first");
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
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
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
            retained_compensation_source: None,
        },
    );
    server.wait_for("/hang", 1);
    // The subject is erased while the turn is open, then the daemon dies.
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, p.owner()))
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
        p.owner(),
    ))
    .unwrap();
    let started = Instant::now();
    let r = p.send(
        "counter/a",
        msg("fetch-ok", format!("GET {}", server.url("/hang"))),
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
        msg("fetch", format!("POST {}\n\ncharge", server.url("/hang"))),
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

/// Issue #280: a store error while reading a due timer's row must not take
/// the id off the wheel. The read is retried until it recovers, and only
/// then does the timer fire; before the fix the wake was silently dropped.
#[test]
fn a_failing_timers_read_does_not_drop_the_timer() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.send("counter/a", msg("schedule", "50 increment"));
    // Rename the table so every `timers` read fails while the timer comes
    // due, then rename it back: the row itself survives both.
    p.node
        .store()
        .db()
        .conn()
        .execute_batch("ALTER TABLE timers RENAME TO timers_away")
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        p.kv("counter/a", "n"),
        None,
        "the timer must not fire while its row cannot be read"
    );
    p.node
        .store()
        .db()
        .conn()
        .execute_batch("ALTER TABLE timers_away RENAME TO timers")
        .unwrap();
    p.wait_until("the timer after the read recovers", |p| {
        p.kv("counter/a", "n").as_deref() == Some("1")
    });
    assert!(p.node.store().db().timers(None).unwrap().is_empty());
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
    p.rt.block_on(p.node.secret_set(
        "api-key",
        SECRET.as_bytes().to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.grant("http:127.0.0.1", None, None);
    p.grant("secret:api-key", None, None);
    // HMAC on the host matches a local computation.
    let r = p.send("counter/a", msg("hmac", "api-key\nhello"));
    let want = kronik_core::ids::hex(&kronik_effects::crypto::hmac_sha256(
        SECRET.as_bytes(),
        b"hello",
    ));
    assert_eq!(reply(&r), want);
    // Without secret-reveal, every exfiltration path comes back empty.
    let r = p.send(
        "counter/a",
        msg("exfiltrate", format!("api-key {}", server.url("/echo"))),
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
    p.rt.block_on(p.node.deploy(&wasm, audit(), false, p.owner()))
        .unwrap();
    p.rt.block_on(p.node.secret_set(
        "api-key",
        SECRET.as_bytes().to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.grant("http:127.0.0.1", None, None);
    let spec = |secret: &str| {
        format!(
            "POST {}\nx-api-key: Bearer {{{{secret:{secret}}}}}\n\necho",
            server.url("/echo")
        )
    };
    // Without `secret:api-key` the request is denied (a denied record).
    let r = p.send("counter/a", msg("wfetch", spec("api-key")));
    assert_eq!(reply(&r), "error ErrorCode::HttpRequestDenied", "{r:?}");
    assert!(server.seen("/echo").is_empty());
    p.grant("secret:api-key", None, None);
    let r = p.send("counter/a", msg("wfetch", spec("api-key")));
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
    let r = p.send("counter/a", msg("wfetch", spec("missing")));
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
        p.rt.block_on(p.node.resend(dead, audit(), false, p.owner()))
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
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false, p.owner()),
    )
    .unwrap();
    p.rt.block_on(p.node.secret_set(
        "db-password",
        SECRET.as_bytes().to_vec(),
        &audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    p.grant("secret-reveal:db-password", None, None);
    p.rt.block_on(p.node.grant(
        "notes",
        "secret-reveal:db-password",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        p.owner(),
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

/// Adds 8 KiB notes until one fails with `TooLarge` after more than two,
/// raises the limit to 16 MiB and checks that the next note commits.
fn fill_until_too_large(p: &Proc) {
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
    p.sql_limit(16 << 20);
    assert!(p.send("notes/n", msg("add", &big)).committed());
}

#[test]
fn sql_size_limit_per_kind() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false, p.owner()),
    )
    .unwrap();
    p.sql_limit(64 << 10);
    fill_until_too_large(&p);
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
            .deploy(&std::fs::read(NOTES).unwrap(), audit(), false, p.owner()),
    )
    .unwrap();
    fill_until_too_large(&p);
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
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let r =
        p.rt.block_on(p.node.deploy(&bytes, audit(), false, p.owner()))
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
        retained_compensation_source: None,
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
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
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
/// failed turn never reaches the callee: the whole call is denied
/// (`scrub::call_request`, UnsafeCompensation -> POLICY_DENIED), so no
/// compensation copy — scrubbed or not — can arrive. The node keeps running
/// and restarts, and the value is nowhere on disk.
#[test]
fn an_unsafe_compensation_denies_the_call_and_the_node_restarts() {
    const SECRET: &str = "VALUE-comp-5d1e9a";
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.leaky(SECRET, &["secret-reveal:k1"]);
    let r = p.send("leaky/a", msg("reveal-comp", "k1 leaky/b"));
    assert!(!r.committed(), "{r:?}");
    // The call with the unsafe compensation is denied outright; the guest's
    // own failure still closes the turn.
    let turn = turn_records(&p.records())
        .into_iter()
        .find(|t| {
            t.input.as_ref().and_then(|i| i.kind.as_ref()).is_some_and(|k| {
                matches!(k, pb::input::Kind::Message(m) if m.msg.as_ref().is_some_and(|m| m.name == "reveal-comp"))
            })
        })
        .expect("the reveal-comp turn record");
    assert_eq!(
        turn.outcome.as_ref().unwrap().kind,
        pb::OutcomeKind::Failed as i32
    );
    let denied = turn
        .effects
        .iter()
        .find(|e| e.status == pb::EffectStatus::Denied as i32)
        .expect("the denied call effect");
    assert_eq!(denied.error, "POLICY_DENIED");
    takes_turns(&p);
    // The callee never ran: neither its "keep" call nor any compensation
    // ("undone") arrived, scrubbed or not.
    let kv = |p: &Proc, k: &str| {
        p.node
            .store()
            .db()
            .kv_get("leaky", "b", k)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap())
    };
    assert_eq!(kv(&p, "kept"), None);
    assert_eq!(kv(&p, "undone"), None);
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
    // A secret mutation waits for its inventory publication for up to the
    // fetch timeout (2 s by default), which a loaded machine can exceed.
    let mut config = NodeConfig {
        concurrency: 8,
        ..NodeConfig::default()
    };
    config.secret_settings.fetch_timeout = Duration::from_secs(30);
    let p = start_with(dir.path(), config);
    p.leaky(SECRET, &["secret-reveal:k1", "http:127.0.0.1"]);
    let r = p.send(
        "leaky/a",
        msg("reveal-fetch", format!("k1 {}", server.url("/echo"))),
    );
    assert!(r.committed(), "{r:?}");
    let seen = server.seen(&format!("/echo?key={SECRET}"));
    assert_eq!(
        seen[0].headers.get("x-api-key").map(String::as_str),
        Some(SECRET),
        "the value went out"
    );
    let _ = p.rt.block_on(p.node.snapshot("i8 test", p.owner()));
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
    p.leaky(SECRET, &["secret-reveal:k1", "http:127.0.0.1"]);
    p.send_detached(
        "leaky/a",
        msg(
            "reveal-echo-len",
            format!(
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

/// Copies a data directory (the daemon is dead).
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).unwrap();
        }
    }
}

/// Removes `state.db` and the actor databases: the next start installs the
/// newest snapshot (a lost disk, a restore).
fn lose_state(dir: &Path) {
    let branch = dir.join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    let _ = std::fs::remove_dir_all(branch.join("sql"));
}

/// A snapshot taken while a turn is open holds the turn as open, with the
/// log position of its `TurnBegin` (#35). Retention keeps that segment while
/// the turn is open in the live state or in a snapshot, so a start from the
/// snapshot runs the turn again; a directory that lost the segment says so
/// with the turn's execution id instead of failing on a missing file.
#[test]
fn a_snapshot_with_an_open_turn_stays_a_start_point_through_retention() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let config = || {
        let mut storage = kronik_sched::snapshots::StorageConfig::new(dir.path().to_path_buf());
        storage.history = Duration::ZERO;
        storage.snapshots_kept = 1;
        NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(1024),
            ..NodeConfig::default()
        }
    };
    let p = start_with(dir.path(), config());
    p.deploy();
    p.grant("http:127.0.0.1", None, None);
    // The /hang fetch keeps the turn open until the server is released: the
    // default effect timeout (10 s) would close it in the middle of the
    // rounds below on a loaded machine, and then no snapshot holds it open.
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "counter".into(),
            effect_timeout_ms: Some(600_000),
            ..Default::default()
        },
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    // Segments before the one the open turn begins in, for retention to take.
    for _ in 0..20 {
        p.send("counter/w", msg("increment", ""));
    }
    p.send_detached(
        "counter/h",
        msg("fetch", format!("GET {}", server.url("/hang"))),
    );
    server.wait_for("/hang", 1);
    let open = p.node.store().db().open_turns().unwrap();
    assert_eq!(open.len(), 1);
    let begin_segment = open[0].pos.segment;
    let execution_id = open[0].execution_id.clone();
    let segment_file = dir
        .path()
        .join("branches/main/log")
        .join(kronik_log::segment_name(begin_segment));
    // Many segments after the TurnBegin, two snapshots, two compactions with
    // no history window: everything older than the newest snapshot would go.
    for round in 0..2 {
        for i in 0..30 {
            p.send(&format!("counter/x{}", i % 3), msg("increment", ""));
        }
        assert_eq!(
            p.node.store().db().open_turns().unwrap().len(),
            1,
            "round {round}: the /hang turn is still open"
        );
        let m = p.rt.block_on(p.node.snapshot("manual", p.owner())).unwrap();
        assert!(m.lsn > open[0].lsn, "round {round}");
        assert!(
            m.segments
                .contains(&kronik_log::segment_name(begin_segment)),
            "the manifest names the segment a start needs: {:?}",
            m.segments
        );
    }
    let first = kronik_log::segment_starts(&dir.path().join("branches/main/log")).unwrap()[0];
    assert!(first > 1, "compaction deleted nothing");
    assert!(
        segment_file.is_file(),
        "retention deleted the open turn's segment"
    );
    drop(p); // the turn is still open

    // A copy that lost the segment (a release before 0.5 deleted it) names
    // the turn instead of failing on a missing file.
    let lost = tempfile::tempdir().unwrap();
    copy_dir(dir.path(), lost.path());
    lose_state(lost.path());
    std::fs::remove_file(
        lost.path()
            .join("branches/main/log")
            .join(kronik_log::segment_name(begin_segment)),
    )
    .unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            let mut cfg = config();
            if let Some(s) = &mut cfg.storage {
                s.data_dir = lost.path().to_path_buf();
            }
            start_local(env, lost.path(), cfg).await
        })
        .err()
        .expect("the start must not succeed without the TurnBegin");
    let text = err.to_string();
    assert!(
        text.contains("STORAGE_CORRUPT") && text.contains(&execution_id),
        "{text}"
    );

    // The snapshot is a start point: the open turn runs again.
    lose_state(dir.path());
    server.release();
    let p = start_with(dir.path(), config());
    server.wait_for("/hang", 2);
    p.wait_until("the re-run's turn record", |p| {
        turn_records(&p.records())
            .iter()
            .any(|t| t.execution_id == execution_id)
    });
    p.wait_until("no open turn", |p| {
        p.node.store().db().open_turns().unwrap().is_empty()
    });
}

/// Makes `actor` busy for about 0.75 s (a bounded spin) before anything
/// queued after this returns, so a call to it times out (#30).
fn keep_busy(p: &Proc, actor: &str) {
    let started = p
        .node
        .probe
        .turns_run
        .load(std::sync::atomic::Ordering::SeqCst);
    p.send_detached(actor, msg("spin", "250000000"));
    p.wait_until("the spin to start", |p| {
        p.node
            .probe
            .turns_run
            .load(std::sync::atomic::Ordering::SeqCst)
            > started
    });
}

/// The turns of `actor` whose input came by `source`.
fn turns_from(p: &Proc, actor: &str, source: pb::MessageSource) -> usize {
    turn_records(&p.records())
        .iter()
        .filter(|t| {
            t.actor
                .as_ref()
                .is_some_and(|a| format!("{}/{}", a.kind, a.key) == actor)
                && matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Message(m)) if m.source == source as i32
                )
        })
        .count()
}

/// #30: a call that times out while its callee is busy still commits at the
/// callee. When the caller then fails, the callee's change is an orphan and
/// the call's compensation is delivered, once, as soon as the callee's turn
/// commits; a callee turn that fails leaves neither. Until then the
/// compensation is held, also across a restart that loses the queued call.
#[test]
fn a_call_that_times_out_is_an_orphan_once_its_callee_commits() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.deploy();
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "counter".into(),
            effect_timeout_ms: Some(100),
            fuel: Some(5_000_000_000),
            ..Default::default()
        },
        audit(),
        false,
        p.owner(),
    ))
    .unwrap();
    let orphan_of = |p: &Proc, key: &str| {
        p.node
            .store()
            .db()
            .orphans(true)
            .unwrap()
            .into_iter()
            .find(|o| o.callee.key == key)
    };

    // With a compensation.
    keep_busy(&p, "counter/b");
    let r = p.send(
        "counter/a",
        msg("call-fail", "counter/b increment increment"),
    );
    assert!(!r.committed());
    assert!(r.outcome.message.contains("Timeout"), "{:?}", r.outcome);
    // The callee has not run the call yet: nothing is known.
    assert!(orphan_of(&p, "b").is_none());
    assert_eq!(p.kv("counter/b", "n"), None);
    p.wait_until("the call and its compensation", |p| {
        p.kv("counter/b", "n").as_deref() == Some("2")
    });
    p.wait_until("the orphan to resolve", |p| {
        orphan_of(p, "b").is_some_and(|o| o.resolved_lsn.is_some())
    });
    assert!(orphan_of(&p, "b").unwrap().compensation_id.is_some());
    assert_eq!(
        turns_from(&p, "counter/b", pb::MessageSource::Compensation),
        1
    );

    // Without one: the change stays an orphan.
    keep_busy(&p, "counter/c");
    let r = p.send("counter/a", msg("call-fail", "counter/c increment"));
    assert!(!r.committed());
    p.wait_until("the orphan", |p| orphan_of(p, "c").is_some());
    let o = orphan_of(&p, "c").unwrap();
    assert!(
        o.compensation_id.is_none() && o.resolved_lsn.is_none(),
        "{o:?}"
    );
    assert_eq!(p.kv("counter/c", "n").as_deref(), Some("1"));

    // A callee turn that fails changed nothing: no orphan, no compensation.
    keep_busy(&p, "counter/d");
    let r = p.send("counter/a", msg("call-fail", "counter/d fail increment"));
    assert!(!r.committed());
    p.wait_until("the callee's failed turn", |p| {
        turns_from(p, "counter/d", pb::MessageSource::Call) == 1
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(orphan_of(&p, "d").is_none());
    assert_eq!(p.kv("counter/d", "n"), None);
    assert_eq!(
        turns_from(&p, "counter/d", pb::MessageSource::Compensation),
        0
    );

    // A restart loses the queued call. The next start closes it as a failed
    // turn of its callee (UNAVAILABLE): no orphan, and the held compensation
    // and the waiting row go, also from the store's tables.
    keep_busy(&p, "counter/e");
    let r = p.send(
        "counter/a",
        msg("call-fail", "counter/e increment increment"),
    );
    assert!(!r.committed());
    assert_eq!(
        p.node.store().db().waiting_timed_out_calls().unwrap().len(),
        1
    );
    drop(p);
    let p = start(dir.path());
    std::thread::sleep(Duration::from_millis(500));
    let lost_turns = |p: &Proc| {
        turn_records(&p.records())
            .into_iter()
            .filter(|t| {
                t.actor.as_ref().is_some_and(|a| a.key == "e")
                    && matches!(
                        t.input.as_ref().and_then(|i| i.kind.as_ref()),
                        Some(pb::input::Kind::Message(m))
                            if m.source == pb::MessageSource::Call as i32
                    )
            })
            .map(|t| t.outcome.unwrap_or_default())
            .collect::<Vec<_>>()
    };
    let closed = lost_turns(&p);
    assert_eq!(closed.len(), 1, "{closed:?}");
    assert_eq!(closed[0].kind, pb::OutcomeKind::Failed as i32);
    assert_eq!(closed[0].error_code, "UNAVAILABLE");
    assert!(
        p.node
            .store()
            .db()
            .waiting_timed_out_calls()
            .unwrap()
            .is_empty()
    );
    let held: i64 = p
        .node
        .store()
        .db()
        .conn()
        .query_row("SELECT count(*) FROM mailbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(held, 0, "the held compensation is dropped");
    assert!(orphan_of(&p, "e").is_none());
    assert_eq!(p.kv("counter/e", "n"), None);
    // The rest stands after the restart, and another start closes nothing
    // again.
    assert!(orphan_of(&p, "c").is_some_and(|o| o.resolved_lsn.is_none()));
    assert_eq!(p.kv("counter/b", "n").as_deref(), Some("2"));
    drop(p);
    let p = start(dir.path());
    assert_eq!(lost_turns(&p).len(), 1);
}

/// The real clock with a wall clock the test steps, as NTP or an operator
/// would.
struct SteppedClock {
    real: Arc<dyn kronik_core::env::Clock>,
    offset_ms: std::sync::atomic::AtomicI64,
}

impl kronik_core::env::Clock for SteppedClock {
    fn wall_ms(&self) -> u64 {
        let offset = self.offset_ms.load(std::sync::atomic::Ordering::SeqCst);
        u64::try_from(i64::try_from(self.real.wall_ms()).unwrap() + offset).unwrap()
    }

    fn monotonic(&self) -> Duration {
        self.real.monotonic()
    }

    fn sleep(&self, d: Duration) -> kronik_core::env::BoxFuture<'static, ()> {
        self.real.sleep(d)
    }
}

/// #40 (ADR 0006): after the host clock steps back 5 minutes, logical time
/// holds still at its high-water mark, but a 1 s timer set before the step
/// and one set after it both fire after about 1 s, not 5 minutes later.
/// Logical time never goes back, and each timer turn's time is at least its
/// due time.
#[test]
fn a_clock_step_back_delays_no_timer() {
    let dir = tempfile::tempdir().unwrap();
    let mut clock = None;
    let p = start_proc_env(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            ..NodeConfig::default()
        },
        |env| {
            let stepped = Arc::new(SteppedClock {
                real: env.clock.clone(),
                offset_ms: std::sync::atomic::AtomicI64::new(0),
            });
            env.clock = stepped.clone();
            clock = Some(stepped);
        },
    );
    let clock = clock.unwrap();
    p.deploy();
    let started = Instant::now();
    p.send("counter/before", msg("schedule", "1000 increment"));
    clock
        .offset_ms
        .fetch_sub(300_000, std::sync::atomic::Ordering::SeqCst);
    let after = Instant::now();
    p.send("counter/after", msg("schedule", "1000 increment"));
    // wait_until gives up after about 10 s.
    p.wait_until("the timer set before the step", |p| {
        p.kv("counter/before", "n").as_deref() == Some("1")
    });
    assert!(started.elapsed() >= Duration::from_secs(1));
    p.wait_until("the timer set after the step", |p| {
        p.kv("counter/after", "n").as_deref() == Some("1")
    });
    assert!(after.elapsed() >= Duration::from_secs(1));
    p.wait_until("both timer turns in the log", |p| {
        turn_records(&p.records())
            .iter()
            .filter(|t| {
                matches!(
                    t.input.as_ref().and_then(|i| i.kind.as_ref()),
                    Some(pb::input::Kind::Timer(_))
                )
            })
            .count()
            == 2
    });
    // Per actor, as ADR 0006 promises (concurrent turns of two actors may
    // commit in the other order of their times).
    let mut last: BTreeMap<String, u64> = BTreeMap::new();
    for t in turn_records(&p.records()) {
        let actor = t.actor.as_ref().map(|a| a.key.clone()).unwrap_or_default();
        let previous = last.insert(actor, t.logical_time_ms).unwrap_or(0);
        assert!(
            t.logical_time_ms >= previous,
            "logical time went back: {t:?}"
        );
        if let Some(pb::input::Kind::Timer(input)) = t.input.and_then(|i| i.kind) {
            assert!(t.logical_time_ms >= input.due_ms);
        }
    }
}

/// #39 (ADR 0134): an actor type's fingerprint rules leave out the header
/// and query-parameter names they list, for that type only. A request is
/// recorded with the rules of its turn's epoch (version 3 and the names) and
/// its fingerprint is recomputed from the recording alone.
#[test]
fn fingerprint_rules_apply_to_their_kind_only() {
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start();
    let p = start(dir.path());
    p.deploy();
    p.grant("http:127.0.0.1", None, None);
    let set = |kind: &str, headers: &[&str], query: &[&str]| {
        let list = |names: &[&str]| {
            Some(pb::NameList {
                names: names.iter().map(|n| (*n).to_owned()).collect(),
            })
        };
        p.rt.block_on(p.node.set_limits(
            pb::Limits {
                kind: kind.into(),
                fingerprint_exclude_headers: list(headers),
                fingerprint_exclude_query: list(query),
                ..Default::default()
            },
            audit(),
            false,
            p.owner(),
        ))
        .unwrap()
    };
    // The recorded request and fingerprint of one fetch.
    let fetch = |key: &str, ts: &str, tenant: &str| {
        let spec = format!(
            "GET http://{}/ok?ts={ts}&a=b\nH X-Api-Key key-{key}\nH x-tenant {tenant}",
            server.addr
        );
        let r = p.send(&format!("counter/{key}"), msg("fetch-ok", &spec));
        assert!(reply(&r).starts_with("200"), "{}", reply(&r));
        let turns = turn_records(&p.records());
        let effect = turns.last().unwrap().effects[0].clone();
        let Some(pb::sealable::Value::Plain(bytes)) =
            effect.request.as_ref().and_then(|r| r.value.as_ref())
        else {
            panic!("a plain request");
        };
        let request = pb::HttpEffectRequest::decode(bytes.as_slice()).unwrap();
        // The recording's fingerprint follows from the recording alone.
        let target = kronik_effects::http::prepared_target(&request).unwrap();
        assert_eq!(
            kronik_effects::http::fingerprint_v2(&request, &target).unwrap(),
            effect.fingerprint
        );
        (request, effect.fingerprint)
    };
    // Rules for another kind leave counter's fingerprints alone.
    let (_, _, _, rules) = set("billing", &["x-api-key"], &["ts"]);
    assert_eq!(rules.headers(), ["x-api-key"]);
    let (a, fa) = fetch("a", "1", "t1");
    let (_, fb) = fetch("b", "2", "t1");
    assert_eq!(a.fingerprint_version, 2);
    assert!(a.fingerprint_excluded_headers.is_empty());
    assert_ne!(fa, fb);
    // Counter's own rules: the names are canonical (lowercase, sorted, the
    // default user-agent dropped) and recorded in its requests.
    let (_, _, _, rules) = set("counter", &["X-Api-Key", "user-agent"], &["ts", "nonce"]);
    assert_eq!(rules.headers(), ["x-api-key"]);
    assert_eq!(rules.query(), ["nonce", "ts"]);
    let (c, fc) = fetch("c", "3", "t1");
    let (_, fd) = fetch("d", "4", "t1");
    assert_eq!(c.fingerprint_version, 3);
    assert_eq!(c.fingerprint_excluded_headers, ["x-api-key"]);
    assert_eq!(c.fingerprint_excluded_query, ["nonce", "ts"]);
    assert_eq!(fc, fd, "the key and ts differ only");
    // A header the rules do not name still counts.
    let (_, fe) = fetch("e", "5", "t2");
    assert_ne!(fc, fe);
    // An empty list clears; the other list stays.
    let (_, _, _, rules) =
        p.rt.block_on(p.node.set_limits(
            pb::Limits {
                kind: "counter".into(),
                fingerprint_exclude_headers: Some(pb::NameList { names: vec![] }),
                ..Default::default()
            },
            audit(),
            false,
            p.owner(),
        ))
        .unwrap();
    assert!(rules.headers().is_empty());
    assert_eq!(rules.query(), ["nonce", "ts"]);
    // An invalid name is refused before anything is written.
    let error =
        p.rt.block_on(p.node.set_limits(
            pb::Limits {
                kind: "counter".into(),
                fingerprint_exclude_headers: Some(pb::NameList {
                    names: vec!["bad header".into()],
                }),
                ..Default::default()
            },
            audit(),
            false,
            p.owner(),
        ))
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::BadRequest);
}
