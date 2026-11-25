//! Standard `fetch` through `wasi:http` (M22, ADR 0070), with the
//! `counter-wasi-http` test guest, which uses `wasi:http` the way
//! StarlingMonkey's `fetch` does. A gate stands in for the scheduler's and
//! answers every effect after a random real-time delay: what the guest sees
//! must not depend on it.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Map, message, request, store};
use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    BlobHost, BlobHostError, CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchBody,
    FetchHeader, FetchOutcome, FetchRequest, FetchResponse, FetchResponseBody, GateError, Program,
    TurnLimits, TurnRequest,
};

const GUEST: &[u8] = include_bytes!("../../../tests/guests/counter-wasi-http.wasm");

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
                    body: FetchResponseBody::Inline(
                        format!(
                            "{} {} {}",
                            req.method,
                            req.url,
                            String::from_utf8_lossy(inline(&req.body))
                        )
                        .into_bytes(),
                    ),
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
    let code = store();
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
    let input = message(op, body.as_bytes());
    let out = program
        .run(
            TurnRequest {
                causal_key: kronik_core::causal::root("root".to_string()),
                seed: [3; 32],
                ..request("counter/a", input)
            },
            Arc::new(Map::default()),
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

/// An inline request body's bytes; this guest never sends a blob.
fn inline(body: &FetchBody) -> &[u8] {
    match body {
        FetchBody::Inline(bytes) => bytes,
        other => panic!("an inline body, not {other:?}"),
    }
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
    assert_eq!(inline(&first.effects[0].1.body), payload.as_bytes());
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

// Blob bodies (M25 §7.6, ADR 0121 §6), with `counter-wasi-http-blobs`,
// which imports `kronik:actor/blobs` and adds `wbig` (its crate docs).

const BLOB_GUEST: &[u8] = include_bytes!("../../../tests/guests/counter-wasi-http-blobs.wasm");

/// A delay of 0 to `max_us` microseconds from a xorshift state.
fn jitter(state: &AtomicU64, max_us: u64) -> Duration {
    let mut x = state.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.store(x, Ordering::Relaxed);
    Duration::from_micros(x % max_us)
}

/// Blobs in memory, under complete `b3:` references, that answer reads and
/// writes after a random delay of up to a millisecond, as a disk might:
/// what the guest sees must not depend on it. Logs every operation.
struct MemBlobs {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    writers: Mutex<HashMap<u64, Vec<u8>>>,
    next: AtomicU64,
    log: Mutex<Vec<String>>,
    jitter: AtomicU64,
    /// Reads of these blobs fail as erased.
    erased: Mutex<Vec<String>>,
    /// What `replaced` says of every writer.
    replaced: AtomicU64,
}

impl MemBlobs {
    fn new(seed: u64) -> Arc<MemBlobs> {
        Arc::new(MemBlobs {
            blobs: Mutex::new(HashMap::new()),
            writers: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            log: Mutex::new(Vec::new()),
            jitter: AtomicU64::new(seed.rotate_left(17) | 1),
            erased: Mutex::new(Vec::new()),
            replaced: AtomicU64::new(0),
        })
    }

    fn store(&self, bytes: Vec<u8>) -> pb::BlobRef {
        let blob = pb::BlobRef {
            hash: format!("b3:{}", blake3::hash(&bytes).to_hex()),
            size: bytes.len() as u64,
            subject: None,
            key_version: 0,
        };
        self.blobs.lock().unwrap().insert(blob.hash.clone(), bytes);
        blob
    }

    fn note(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }

    fn operations(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl BlobHost for MemBlobs {
    fn read(
        &self,
        blob: &pb::BlobRef,
        offset: u64,
        len: u32,
    ) -> BoxFuture<'static, Result<Vec<u8>, BlobHostError>> {
        self.note(format!("read {} {offset} {len}", &blob.hash[..11]));
        let delay = jitter(&self.jitter, 1000);
        let erased = self.erased.lock().unwrap().contains(&blob.hash);
        let found = self.blobs.lock().unwrap().get(&blob.hash).cloned();
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if erased {
                return Err(BlobHostError::Erased);
            }
            let bytes = found.ok_or_else(|| BlobHostError::Host("BLOB_MISSING".into()))?;
            let start = (offset as usize).min(bytes.len());
            let end = (start + len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        })
    }

    fn create(&self, subject: Option<String>) -> BoxFuture<'static, Result<u64, BlobHostError>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.note(format!("create {id} {subject:?}"));
        self.writers.lock().unwrap().insert(id, Vec::new());
        let delay = jitter(&self.jitter, 1000);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(id)
        })
    }

    fn write(&self, writer: u64, chunk: Vec<u8>) -> BoxFuture<'static, Result<(), BlobHostError>> {
        self.note(format!("write {writer} {}", chunk.len()));
        self.writers
            .lock()
            .unwrap()
            .get_mut(&writer)
            .unwrap()
            .extend_from_slice(&chunk);
        let delay = jitter(&self.jitter, 1000);
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(())
        })
    }

    fn finish(&self, writer: u64) -> BoxFuture<'static, Result<pb::BlobRef, BlobHostError>> {
        let bytes = self.writers.lock().unwrap().remove(&writer).unwrap();
        let blob = self.store(bytes);
        self.note(format!("finish {writer} {}", blob.size));
        Box::pin(async move { Ok(blob) })
    }

    fn discard(&self, writer: u64) {
        self.note(format!("discard {writer}"));
        self.writers.lock().unwrap().remove(&writer);
    }

    fn replaced(&self, _writer: u64) -> u64 {
        self.replaced.load(Ordering::Relaxed)
    }
}

/// Answers after 0 to 3 ms, as the scheduler's gate would: `/echo` with the
/// request body (a blob request with the same blob, as a response above the
/// threshold), `/gen/<n>` with a blob of `n` bytes. Logs every effect.
struct BlobGate {
    blobs: Arc<MemBlobs>,
    log: Mutex<Vec<(u32, FetchRequest)>>,
    jitter: AtomicU64,
}

impl EffectGate for BlobGate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        self.log.lock().unwrap().push((ordinal, req.clone()));
        let delay = jitter(&self.jitter, 3000);
        let generated = req
            .url
            .split("/gen/")
            .nth(1)
            .and_then(|n| n.parse::<u64>().ok())
            .map(|n| self.blobs.store((0..n).map(|i| (i % 253) as u8).collect()));
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            let body = match (generated, &req.body) {
                (Some(blob), _) => FetchResponseBody::Blob(blob),
                (None, FetchBody::Blob(blob)) => FetchResponseBody::Blob(blob.clone()),
                (None, FetchBody::Inline(bytes)) => FetchResponseBody::Inline(bytes.clone()),
                (None, FetchBody::NotHeld { .. }) => {
                    return Ok(FetchOutcome::Denied("BLOB_NOT_HELD".into()));
                }
            };
            Ok(FetchOutcome::Ok(FetchResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body,
            }))
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

fn blob_program() -> Arc<Program> {
    let code = store();
    code.add(BLOB_GUEST).unwrap().1
}

/// Enough fuel for the guest to make and digest a few MiB.
fn big_limits() -> TurnLimits {
    TurnLimits {
        fuel: 2_000_000_000,
        ..TurnLimits::default()
    }
}

struct BlobRun {
    outcome: pb::Outcome,
    reply: String,
    fuel: u64,
    logs: String,
    effects: Vec<(u32, FetchRequest)>,
    /// The blob store's operations, in order.
    store: Vec<String>,
}

/// Runs `op` with `text` on `program`, with a blob host unless `blobs` is
/// false, seeding the gate's and the store's latencies with `seed`.
async fn run_blobs(
    program: &Program,
    op: &str,
    text: &str,
    limits: TurnLimits,
    seed: u64,
    blobs: bool,
    prepare: impl FnOnce(&MemBlobs),
) -> BlobRun {
    let store = MemBlobs::new(seed);
    prepare(&store);
    let gate = Arc::new(BlobGate {
        blobs: store.clone(),
        log: Mutex::new(Vec::new()),
        jitter: AtomicU64::new(seed | 1),
    });
    let input = message(op, text.as_bytes());
    let host = blobs.then(|| store.clone() as Arc<dyn BlobHost>);
    let out = program
        .run_with_blobs(
            TurnRequest {
                causal_key: kronik_core::causal::root("root".to_string()),
                seed: [3; 32],
                limits,
                ..request("counter/a", input)
            },
            Arc::new(Map::default()),
            None,
            Some(gate.clone()),
            host,
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
    let effects = gate.log.lock().unwrap().clone();
    BlobRun {
        outcome: out.outcome.clone(),
        reply,
        fuel: out.fuel_used,
        logs: format!("{:?}", out.logs),
        effects,
        store: store.operations(),
    }
}

/// The value of `key=` in a `wbig` reply.
fn field<'a>(reply: &'a str, key: &str) -> &'a str {
    reply
        .split(' ')
        .find_map(|word| word.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {reply}"))
}

/// The request body an effect sent: its size, and whether as a blob.
fn sent(body: &FetchBody) -> (u64, bool) {
    match body {
        FetchBody::Inline(bytes) => (bytes.len() as u64, false),
        FetchBody::Blob(blob) => (blob.size, true),
        FetchBody::NotHeld { .. } => panic!("not held"),
    }
}

/// The transcript test of ADR 0070 with blob bodies (M25 §7.6): a 3 MiB
/// request body streamed through `check-write`, `write` and `poll` goes to
/// a blob, and its echo, a 3 MiB blob response, is read back with
/// non-blocking reads of mixed lengths, blocking reads and polls, while the
/// gate and the blob store answer after random delays. Every run gives the
/// same transcript of permits, read lengths and ready lists, the same
/// reply, fuel, logs and effects, and the same store operations: the
/// response is read one 64 KiB frame at a time, each frame once, in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blob_bodies_are_deterministic_under_random_latency() {
    const SIZE: u64 = 3 << 20;
    let p = blob_program();
    assert!(p.reads_blobs());
    let text = format!("POST http://big.example/echo\nsize={SIZE}");
    let first = run_blobs(&p, "wbig", &text, big_limits(), seed(0), true, |_| {}).await;
    assert!(
        first.reply.starts_with("200 "),
        "{:?}: {}",
        first.outcome,
        first.reply
    );
    assert_eq!(field(&first.reply, "sent="), field(&first.reply, "got="));
    assert_eq!(field(&first.reply, "end="), "eof");
    assert_eq!(field(&first.reply, "trailers="), "none");
    assert!(field(&first.reply, "sent=").starts_with(&format!("{SIZE}:")));
    // The request body went out as one blob; the guest never got it.
    assert_eq!(first.effects.len(), 1);
    assert_eq!(sent(&first.effects[0].1.body), (SIZE, true));
    // One writer, of the body's bytes, finished; then the response's
    // frames, each read once and in order.
    let store = &first.store;
    assert_eq!(store[0], "create 1 None");
    let written: u64 = store
        .iter()
        .filter_map(|e| e.strip_prefix("write 1 "))
        .map(|n| n.parse::<u64>().unwrap())
        .sum();
    assert_eq!(written, SIZE);
    let reads: Vec<&String> = store.iter().filter(|e| e.starts_with("read ")).collect();
    assert_eq!(reads.len() as u64, SIZE.div_ceil(65536));
    for (i, read) in reads.iter().enumerate() {
        assert!(
            read.ends_with(&format!(" {} 65536", i as u64 * 65536)),
            "{read}"
        );
    }
    for i in 1..100 {
        let again = run_blobs(&p, "wbig", &text, big_limits(), seed(i), true, |_| {}).await;
        assert_eq!(again.reply, first.reply, "run {i}");
        assert_eq!(again.fuel, first.fuel, "run {i}: fuel");
        assert_eq!(again.logs, first.logs, "run {i}: logs");
        assert_eq!(again.effects, first.effects, "run {i}: effects");
        assert_eq!(again.store, first.store, "run {i}: blob store operations");
    }
}

/// A body of exactly the threshold stays inline; one byte more becomes a
/// blob. Without a blob host, or for a component that does not import
/// blobs, a body above the threshold stays inline, up to `message_bytes`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_body_above_the_threshold_becomes_a_blob() {
    let p = blob_program();
    let limits = TurnLimits {
        blob_threshold: 4096,
        ..big_limits()
    };
    for (size, blobs, as_blob) in [
        (4096, true, false),
        (4097, true, true),
        (300_000, true, true),
        (4097, false, false),
    ] {
        let text = format!("POST http://big.example/echo\nsize={size}\nchunk=1000");
        let r = run_blobs(&p, "wbig", &text, limits, seed(size), blobs, |_| {}).await;
        assert!(r.reply.starts_with("200 "), "{size}: {}", r.reply);
        assert_eq!(field(&r.reply, "sent="), field(&r.reply, "got="), "{size}");
        assert_eq!(
            sent(&r.effects[0].1.body),
            (size, as_blob),
            "{size} {blobs}"
        );
        assert_eq!(r.store.iter().any(|e| e.starts_with("create")), as_blob);
    }
    // Without blobs the inline limit holds.
    let text = format!("POST http://big.example/echo\nsize={}", (1 << 20) + 1);
    let r = run_blobs(&p, "wbig", &text, limits, seed(1), false, |_| {}).await;
    assert!(
        r.reply
            .starts_with("error ErrorCode::HttpRequestBodySize(Some(1048576))"),
        "{}",
        r.reply
    );
    assert!(r.effects.is_empty());
    // A component that does not import blobs keeps its bodies inline.
    let plain = program();
    assert!(!plain.reads_blobs());
    let payload = "x".repeat(5000);
    let text = format!("POST http://big.example/echo\n\n{payload}");
    let r = run_blobs(&plain, "wfetch", &text, limits, seed(2), true, |_| {}).await;
    assert_eq!(r.reply, format!("200 {payload}"));
    assert_eq!(sent(&r.effects[0].1.body), (5000, false));
    assert!(r.store.is_empty(), "{:?}", r.store);
}

/// A spooled body counts against the bytes a turn may write into blobs:
/// past them the request is not sent, its writer is discarded and the
/// guest gets `HTTP-request-body-size` with the quota.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_body_past_the_turns_blob_quota_is_not_sent() {
    let p = blob_program();
    let limits = TurnLimits {
        blob_threshold: 4096,
        blob_bytes: 100_000,
        ..big_limits()
    };
    let text = "POST http://big.example/echo\nsize=200000\nchunk=1000";
    let r = run_blobs(&p, "wbig", text, limits, seed(3), true, |_| {}).await;
    assert!(
        r.reply
            .starts_with("error ErrorCode::HttpRequestBodySize(Some(100000))"),
        "{}",
        r.reply
    );
    assert!(r.effects.is_empty());
    assert!(r.store.contains(&"discard 1".to_string()), "{:?}", r.store);
    assert!(
        r.logs
            .contains("not sent: the request body passes the 100000 bytes"),
        "{}",
        r.logs
    );
}

/// Bodies are read only when the guest asks: a response read in part and
/// dropped reads no further frame, and one nobody reads is never read. A
/// guest that waits for the trailers of a body it stopped reading has the
/// rest read within that wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_response_is_read_only_as_far_as_the_guest_reads() {
    let p = blob_program();
    let n = 10 * 65536 + 5;
    let reads = |r: &BlobRun| r.store.iter().filter(|e| e.starts_with("read ")).count();
    for (options, expected, trailers) in [
        ("stop=131072\ntrailers=no", 2, "skipped"),
        ("stop=0\ntrailers=no", 0, "skipped"),
        ("stop=131072", 11, "none"),
        ("stop=0", 11, "none"),
    ] {
        let text = format!("GET http://big.example/gen/{n}\nreads=65536\n{options}");
        let r = run_blobs(&p, "wbig", &text, big_limits(), seed(4), true, |_| {}).await;
        assert_eq!(field(&r.reply, "end="), "stopped", "{options}: {}", r.reply);
        assert_eq!(
            field(&r.reply, "trailers="),
            trailers,
            "{options}: {}",
            r.reply
        );
        assert_eq!(reads(&r), expected, "{options}: {:?}", r.store);
    }
}

/// A response body whose subject is erased fails the guest's read; a
/// request body whose secret values were replaced in its blob is sent
/// with a warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erased_body_fails_the_read_and_a_scrubbed_one_warns() {
    let p = blob_program();
    let n = 3 * 65536;
    let generated = (0..n).map(|i| (i % 253) as u8).collect::<Vec<u8>>();
    let hash = format!("b3:{}", blake3::hash(&generated).to_hex());
    let text = format!("GET http://big.example/gen/{n}\nreads=65536");
    let r = run_blobs(&p, "wbig", &text, big_limits(), seed(6), true, |s| {
        s.erased.lock().unwrap().push(hash.clone());
    })
    .await;
    assert!(
        field(&r.reply, "end=").starts_with("failed("),
        "{}",
        r.reply
    );
    let limits = TurnLimits {
        blob_threshold: 4096,
        ..big_limits()
    };
    let text = "POST http://big.example/echo\nsize=10000";
    let r = run_blobs(&p, "wbig", text, limits, seed(7), true, |s| {
        s.replaced.store(2, Ordering::Relaxed);
    })
    .await;
    assert!(r.reply.starts_with("200 "), "{}", r.reply);
    assert!(
        r.logs.contains(
            "POST http://big.example/echo: 2 secret value(s) in the request body were replaced"
        ),
        "{}",
        r.logs
    );
}
