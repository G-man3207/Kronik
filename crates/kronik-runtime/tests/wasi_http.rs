//! Standard `fetch` through `wasi:http` (M22, ADR 0070), with the
//! `counter-wasi-http` test guest, which uses `wasi:http` the way
//! StarlingMonkey's `fetch` does. A gate stands in for the scheduler's and
//! answers every effect after a random real-time delay: what the guest sees
//! must not depend on it.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CodeStore, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, FetchResponse, GateError, PoolSize, Program, StateView, TurnLimits, TurnRequest,
    build_engine,
};

const GUEST: &[u8] = include_bytes!("../../../tests/guests/counter-wasi-http.wasm");

struct Empty;

impl StateView for Empty {
    fn get(&self, _: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    fn keys(&self, _: &str) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
    fn timer_pending(&self, _: u64) -> Result<bool, String> {
        Ok(false)
    }
}

/// Logs each effect (ordinal and request) and echoes it, after 0 to 3 ms.
struct Gate {
    log: Mutex<Vec<(u32, FetchRequest)>>,
    jitter: AtomicU64,
}

impl Gate {
    fn new(seed: u64) -> Arc<Gate> {
        Arc::new(Gate {
            log: Mutex::new(Vec::new()),
            jitter: AtomicU64::new(seed | 1),
        })
    }
    fn effects(&self) -> Vec<(u32, FetchRequest)> {
        self.log.lock().unwrap().clone()
    }
}

impl EffectGate for Gate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        self.log.lock().unwrap().push((ordinal, req.clone()));
        let mut x = self.jitter.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter.store(x, Ordering::Relaxed);
        let delay = Duration::from_micros(x % 3000);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            let host = req.url.split('/').nth(2).unwrap_or("").to_owned();
            Ok(match host.as_str() {
                "denied.example" => {
                    FetchOutcome::Denied("CAPABILITY_NOT_GRANTED: http:denied.example".into())
                }
                "down.example" => FetchOutcome::Network("connection refused".into()),
                "unknown.example" => FetchOutcome::OutcomeUnknown,
                _ => FetchOutcome::Ok(FetchResponse {
                    status: 200,
                    headers: vec![("content-type".into(), "text/plain".into())],
                    body: format!(
                        "{} {} {}",
                        req.method,
                        req.url,
                        String::from_utf8_lossy(&req.body)
                    )
                    .into_bytes(),
                }),
            })
        })
    }
    fn call(
        &self,
        _: u32,
        _: ActorRef,
        _: pb::Message,
        _: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        Box::pin(async { Err(GateError::Host("not in this test".into())) })
    }
    fn crypto(
        &self,
        _: u32,
        _: CryptoAlgorithm,
        _: String,
        _: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        Box::pin(async { Err(GateError::Host("not in this test".into())) })
    }
    fn reveal(
        &self,
        _: u32,
        _: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        Box::pin(async { Err(GateError::Host("not in this test".into())) })
    }
}

fn program() -> Arc<Program> {
    let engine = build_engine(PoolSize { concurrency: 2 }).unwrap();
    let code = CodeStore::new(engine, None).unwrap();
    code.add(GUEST).unwrap().1
}

struct Run {
    outcome: pb::Outcome,
    reply: String,
    fuel: u64,
    logs: String,
    effects: Vec<(u32, FetchRequest)>,
}

async fn run(program: &Program, op: &str, body: &str, seed: u64) -> Run {
    let gate = Gate::new(seed);
    let input = pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: op.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
                }),
                blobs: vec![],
            }),
            message_id: "m".into(),
            ..Default::default()
        })),
    };
    let out = program
        .run(
            TurnRequest {
                actor: ActorRef::parse("counter/a").unwrap(),
                causal_key: kronik_core::causal::root("root".to_string()),
                logical_time_ms: 1_761_300_000_000,
                seed: [3; 32],
                input,
                limits: TurnLimits::default(),
                subject: None,
            },
            Arc::new(Empty),
            None,
            Some(gate.clone()),
        )
        .await
        .unwrap();
    let reply = match &out.outcome.output {
        Some(pb::outcome::Output::Reply(m)) => match m.body.as_ref().and_then(|b| b.value.as_ref())
        {
            Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
            _ => String::new(),
        },
        _ => String::new(),
    };
    Run {
        outcome: out.outcome.clone(),
        reply,
        fuel: out.fuel_used,
        logs: format!("{:?}", out.logs),
        effects: gate.effects(),
    }
}

fn seed(i: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (i << 32)
}

/// Two requests in flight at once, the first one's body written last: the
/// effects run in the order their bodies complete, each with the next
/// ordinal, and every run gives the same ready lists, replies and fuel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_requests_are_deterministic_under_random_latency() {
    let p = program();
    let body = "POST http://a.example/slow\ncontent-type: text/plain\n\nhello a\n---\nGET http://b.example/fast";
    let first = run(&p, "wfetch2", body, seed(0)).await;
    assert_eq!(
        first.reply,
        "ready [1] then [0, 1]: 200 POST http://a.example/slow hello a | 200 GET http://b.example/fast ",
        "{:?}",
        first.outcome
    );
    let order: Vec<(u32, &str)> = first
        .effects
        .iter()
        .map(|(o, r)| (*o, r.url.as_str()))
        .collect();
    assert_eq!(
        order,
        [(0, "http://b.example/fast"), (1, "http://a.example/slow")]
    );
    for i in 1..50 {
        let again = run(&p, "wfetch2", body, seed(i)).await;
        assert_eq!(again.reply, first.reply, "run {i}");
        assert_eq!(again.fuel, first.fuel, "run {i}: fuel");
        assert_eq!(again.logs, first.logs, "run {i}: logs");
        assert_eq!(again.effects, first.effects, "run {i}: effects");
    }
}

/// Review D1: two bodies finished before one poll (TypeScript's
/// `Promise.all` of fetches) drive together; the effects run in `handle`
/// order with ordinals 0 and 1, the same in every run whatever the latency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_completed_together_run_in_handle_order() {
    let p = program();
    let body = "POST http://a.example/slow\ncontent-type: text/plain\n\nhello a\n---\nGET http://b.example/fast";
    let first = run(&p, "wfetch3", body, seed(0)).await;
    assert_eq!(
        first.reply,
        "ready [0, 1]: 200 POST http://a.example/slow hello a | 200 GET http://b.example/fast ",
        "{:?}",
        first.outcome
    );
    let order: Vec<(u32, &str)> = first
        .effects
        .iter()
        .map(|(o, r)| (*o, r.url.as_str()))
        .collect();
    assert_eq!(
        order,
        [(0, "http://a.example/slow"), (1, "http://b.example/fast")]
    );
    for i in 1..50 {
        let again = run(&p, "wfetch3", body, seed(i)).await;
        assert_eq!(again.reply, first.reply, "run {i}");
        assert_eq!(again.fuel, first.fuel, "run {i}: fuel");
        assert_eq!(again.effects, first.effects, "run {i}: effects");
    }
}

/// `{{secret:NAME}}` in a header value is the secret-header template the
/// scheduler fills in; other headers stay text, and no `host` is added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_placeholder_reaches_the_gate_as_a_secret_header() {
    let p = program();
    let r = run(
        &p,
        "wfetch",
        "GET http://api.example/v1?q=1\nauthorization: Bearer {{secret:api-key}}\nx-n: 2\n\n",
        seed(0),
    )
    .await;
    assert!(
        r.reply.starts_with("200 GET http://api.example/v1?q=1"),
        "{}",
        r.reply
    );
    let (ordinal, req) = &r.effects[0];
    assert_eq!(*ordinal, 0);
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.headers,
        [
            (
                "authorization".to_string(),
                FetchHeader::Secret {
                    name: "api-key".into(),
                    template: "Bearer {}".into()
                }
            ),
            ("x-n".to_string(), FetchHeader::Text("2".into())),
        ]
    );
    // Two placeholders in one value: not sent, a warning in the turn's log.
    let r = run(
        &p,
        "wfetch",
        "GET http://api.example/\nx-k: {{secret:a}}{{secret:b}}\n\n",
        seed(1),
    )
    .await;
    assert_eq!(r.reply, "error ErrorCode::HttpRequestDenied");
    assert!(r.effects.is_empty());
    assert!(r.logs.contains("not sent"), "{}", r.logs);
}

/// A body written one byte at a time, more writes than the body buffer
/// holds: each wait drains what was written, the effect gets it whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_body_arrives_whole_and_deterministically() {
    let p = program();
    let payload: String = (0..200)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect();
    let spec = format!("POST http://up.example/x\n\n{payload}");
    let first = run(&p, "wstream", &spec, seed(0)).await;
    assert_eq!(first.effects.len(), 1);
    assert_eq!(first.effects[0].1.body, payload.as_bytes());
    for i in 1..10 {
        let again = run(&p, "wstream", &spec, seed(i)).await;
        assert_eq!(
            (again.reply.as_str(), again.fuel),
            (first.reply.as_str(), first.fuel)
        );
    }
}

/// Waiting for a response whose request body is never finished can never
/// end: the turn traps at once, without an effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_that_can_never_finish_fails_the_turn() {
    let p = program();
    let r = run(&p, "wstall", "POST http://a.example/\n\nbody", seed(0)).await;
    assert_eq!(
        r.outcome.kind,
        pb::OutcomeKind::Trap as i32,
        "{:?}",
        r.outcome
    );
    assert!(
        r.outcome.message.contains("can never be ready"),
        "{}",
        r.outcome.message
    );
    assert!(r.effects.is_empty());
}

/// A request the turn never waits for is never sent, and the turn's logs
/// say so (review M22 low).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_never_waited_for_is_not_sent_and_warned() {
    let p = program();
    let r = run(&p, "wleave", "GET http://a.example/\n\n", seed(0)).await;
    assert_eq!(r.reply, "left", "{:?}", r.outcome);
    assert!(r.effects.is_empty());
    assert!(
        r.logs
            .contains("1 request(s) the turn never waited for were not sent"),
        "{}",
        r.logs
    );
}

/// A request whose future the guest drops before it waits is never sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_request_is_never_sent() {
    let p = program();
    let r = run(
        &p,
        "wdrop",
        "POST http://first.example/\n\nx\n---\nGET http://second.example/",
        seed(0),
    )
    .await;
    let urls: Vec<&str> = r.effects.iter().map(|(_, q)| q.url.as_str()).collect();
    assert_eq!(urls, ["http://second.example/"]);
    assert_eq!(r.effects[0].0, 0);
}

/// Effect errors as `wasi:http` error codes (ADR 0070 §3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn effect_errors_become_wasi_http_error_codes() {
    let p = program();
    let mut seen = BTreeMap::new();
    for host in ["denied", "down", "unknown"] {
        let r = run(
            &p,
            "wfetch",
            &format!("GET http://{host}.example/\n\n"),
            seed(0),
        )
        .await;
        assert_eq!(r.effects.len(), 1);
        seen.insert(host, r.reply);
    }
    assert_eq!(seen["denied"], "error ErrorCode::HttpRequestDenied");
    assert_eq!(seen["down"], "error internal-error(connection refused)");
    assert_eq!(seen["unknown"], "error internal-error(outcome-unknown)");
}
