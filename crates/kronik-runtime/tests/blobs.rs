//! M25 slice B5: the runtime's side of blobs (ADR 0119, ADR 0121), with an
//! in-memory blob host. A component that imports `blobs` reads its input's
//! blobs in ranges, writes blobs and returns them as bodies; every use of a
//! reference outside the turn's references gives `BLOB_NOT_HELD`; the limits
//! of one call, of the bytes a turn creates and of the bytes it moves hold;
//! and the same turn gives the same result every time.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::{request, store};
use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    BlobHost, BlobHostError, CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchBody,
    FetchOutcome, FetchRequest, FetchResponse, FetchResponseBody, GateError, Program, StateView,
    TurnLimits, TurnOutput, TurnRequest,
};

const MEDIA: &[u8] = include_bytes!("../../../tests/guests/media.wasm");
const COUNTER: &[u8] = include_bytes!("../../../tests/guests/counter.wasm");

/// Blobs in memory: complete `b3:` references, writers and what was
/// discarded.
#[derive(Default)]
struct MemBlobs {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
    writers: Mutex<HashMap<u64, Vec<u8>>>,
    next: AtomicU64,
    discarded: Mutex<Vec<u64>>,
    reads: AtomicU64,
}

impl MemBlobs {
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

    fn bytes(&self, blob: &pb::BlobRef) -> Vec<u8> {
        self.blobs.lock().unwrap()[&blob.hash].clone()
    }
}

impl BlobHost for MemBlobs {
    fn read(
        &self,
        blob: &pb::BlobRef,
        offset: u64,
        len: u32,
    ) -> BoxFuture<'static, Result<Vec<u8>, BlobHostError>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let found = self.blobs.lock().unwrap().get(&blob.hash).cloned();
        Box::pin(async move {
            let bytes = found.ok_or_else(|| BlobHostError::Host("BLOB_MISSING".into()))?;
            let start = (offset as usize).min(bytes.len());
            let end = (start + len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        })
    }

    fn create(&self, _subject: Option<String>) -> BoxFuture<'static, Result<u64, BlobHostError>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.writers.lock().unwrap().insert(id, Vec::new());
        Box::pin(async move { Ok(id) })
    }

    fn write(&self, writer: u64, chunk: Vec<u8>) -> BoxFuture<'static, Result<(), BlobHostError>> {
        self.writers
            .lock()
            .unwrap()
            .get_mut(&writer)
            .unwrap()
            .extend_from_slice(&chunk);
        Box::pin(async { Ok(()) })
    }

    fn finish(&self, writer: u64) -> BoxFuture<'static, Result<pb::BlobRef, BlobHostError>> {
        let bytes = self.writers.lock().unwrap().remove(&writer).unwrap();
        let blob = self.store(bytes);
        Box::pin(async move { Ok(blob) })
    }

    fn discard(&self, writer: u64) {
        self.writers.lock().unwrap().remove(&writer);
        self.discarded.lock().unwrap().push(writer);
    }
}

/// Answers `files.test` with a blob response and `sink.test` with 201,
/// and denies a reference the turn may not use, as the scheduler's gate
/// does. Remembers the request bodies it saw.
struct Gate {
    blobs: Arc<MemBlobs>,
    document: pb::BlobRef,
    seen: Mutex<Vec<FetchBody>>,
}

impl EffectGate for Gate {
    fn fetch(
        &self,
        _ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        self.seen.lock().unwrap().push(req.body.clone());
        let outcome = match (&req.body, req.url.as_str()) {
            (FetchBody::NotHeld { .. }, _) => FetchOutcome::Denied("BLOB_NOT_HELD".into()),
            (_, "http://files.test/doc") => FetchOutcome::Ok(FetchResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/pdf".into())],
                body: FetchResponseBody::Blob(self.document.clone()),
            }),
            (FetchBody::Blob(blob), _) => {
                // The gate reads what it streams.
                assert_eq!(self.blobs.bytes(blob).len() as u64, blob.size);
                FetchOutcome::Ok(FetchResponse {
                    status: 201,
                    headers: Vec::new(),
                    body: FetchResponseBody::Inline(Vec::new()),
                })
            }
            _ => FetchOutcome::Network("no such host".into()),
        };
        Box::pin(async move { Ok(outcome) })
    }
    fn call(
        &self,
        _ordinal: u32,
        _to: ActorRef,
        _msg: pb::Message,
        _compensate: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        Box::pin(async { Ok(CallOutcome::NotFound) })
    }
    fn crypto(
        &self,
        _ordinal: u32,
        _algorithm: CryptoAlgorithm,
        _secret: String,
        _data: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        Box::pin(async { Ok(CryptoOutcome::Unsupported("none".into())) })
    }
    fn reveal(
        &self,
        _ordinal: u32,
        _name: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        Box::pin(async { Ok(Err("none".into())) })
    }
}

struct Map(Mutex<BTreeMap<String, Vec<u8>>>);

impl StateView for Map {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(None)
    }
}

struct World {
    program: Arc<Program>,
    blobs: Arc<MemBlobs>,
    gate: Arc<Gate>,
    state: Arc<Map>,
}

fn pattern(i: u64) -> u8 {
    ((i.wrapping_mul(31) + 7) % 251) as u8
}

fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn world() -> World {
    let code = store();
    let (_, program) = code.add(MEDIA).unwrap();
    let blobs = Arc::new(MemBlobs::default());
    let document = blobs.store((0..300_000u64).map(|i| (i % 7) as u8).collect());
    World {
        program,
        gate: Arc::new(Gate {
            blobs: blobs.clone(),
            document,
            seen: Mutex::new(Vec::new()),
        }),
        blobs,
        state: Arc::new(Map(Mutex::new(BTreeMap::new()))),
    }
}

fn http(op: &str, query: &str, body: pb::body::Value) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Http(pb::HttpInput {
            method: "POST".into(),
            path: format!("/media/a/{op}"),
            query: query.into(),
            body: Some(pb::Body { value: Some(body) }),
            route: "/media/{key}/{op}".into(),
            ..Default::default()
        })),
    }
}

fn inline(bytes: &[u8]) -> pb::body::Value {
    pb::body::Value::Inline(pb::Sealable::new_plain(None, bytes.to_vec()))
}

impl World {
    async fn run_limited(&self, input: pb::Input, limits: TurnLimits, blobs: bool) -> TurnOutput {
        let host: Option<Arc<dyn BlobHost>> = if blobs {
            Some(self.blobs.clone())
        } else {
            None
        };
        self.program
            .run_with_blobs(
                TurnRequest {
                    limits,
                    ..request("media/a", input)
                },
                self.state.clone(),
                None,
                Some(self.gate.clone()),
                host,
            )
            .await
            .unwrap()
    }

    async fn run(&self, input: pb::Input) -> TurnOutput {
        self.run_limited(input, TurnLimits::default(), true).await
    }

    /// Commits the turn's state writes, as the scheduler would.
    fn apply(&self, out: &TurnOutput) {
        for w in &out.writes {
            if let Some(pb::sealable::Value::Plain(v)) =
                w.value.as_ref().and_then(|v| v.value.as_ref())
            {
                self.state
                    .0
                    .lock()
                    .unwrap()
                    .insert(w.key.clone(), v.clone());
            }
        }
    }
}

fn answer(out: &TurnOutput) -> String {
    assert!(out.committed(), "{:?}", out.outcome);
    match &out.outcome.output {
        Some(pb::outcome::Output::Http(r)) => {
            match r.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => panic!("{other:?}"),
                },
                other => panic!("not an inline body: {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

fn blob_answer(out: &TurnOutput) -> pb::BlobRef {
    assert!(out.committed(), "{:?}", out.outcome);
    match &out.outcome.output {
        Some(pb::outcome::Output::Http(r)) => {
            match r.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Blob(blob)) => blob.clone(),
                other => panic!("not a blob body: {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_component_that_imports_blobs_reads_blobs() {
    let w = world();
    assert!(w.program.reads_blobs());
    let code = store();
    let (_, counter) = code.add(COUNTER).unwrap();
    assert!(!counter.reads_blobs());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uploaded_blob_is_read_in_ranges_and_returned_complete() {
    let w = world();
    let bytes: Vec<u8> = (0..2_500_000u64).map(pattern).collect();
    let upload = w.blobs.store(bytes.clone());
    let body = pb::body::Value::Blob(upload.clone());

    let info = w.run(http("info", "", body.clone())).await;
    assert_eq!(
        answer(&info),
        format!("blob {} {}", upload.hash, upload.size)
    );

    for chunk in [1 << 20, 100_000, 65_536] {
        let out = w
            .run(http("sum", &format!("chunk={chunk}"), body.clone()))
            .await;
        assert_eq!(answer(&out), format!("2500000 {}", fnv(&bytes)));
    }
    let out = w
        .run(http(
            "ranges",
            "at=0:10,1048570:20,2499990:100,2500000:5",
            body.clone(),
        ))
        .await;
    assert_eq!(
        answer(&out),
        format!(
            "0:10=10 {}\n1048570:20=20 {}\n2499990:100=10 {}\n2500000:5=0 {}\n",
            fnv(&bytes[..10]),
            fnv(&bytes[1_048_570..1_048_590]),
            fnv(&bytes[2_499_990..]),
            fnv(&[]),
        )
    );

    // Returned as the response body: the complete reference.
    let echo = w.run(http("echo", "", body.clone())).await;
    assert_eq!(blob_answer(&echo), upload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_length_get_reads_nothing_and_still_checks_the_reference() {
    let w = world();
    let upload = w.blobs.store(vec![5u8; 2_500_000]);
    let reads = w.blobs.reads.load(Ordering::Relaxed);

    // Inside the limits, and empty at either end of the blob.
    let out = w
        .run(http(
            "ranges",
            "at=0:0,1:0,2500000:0",
            pb::body::Value::Blob(upload.clone()),
        ))
        .await;
    assert_eq!(
        answer(&out),
        format!(
            "0:0=0 {}\n1:0=0 {}\n2500000:0=0 {}\n",
            fnv(&[]),
            fnv(&[]),
            fnv(&[])
        )
    );
    assert_eq!(
        w.blobs.reads.load(Ordering::Relaxed),
        reads,
        "nothing was read"
    );

    // The reference check still comes first: a stored reference the turn
    // did not receive is `not-held`, whatever the length.
    let first = w
        .run(http("remember", "", pb::body::Value::Blob(upload)))
        .await;
    assert_eq!(answer(&first), "remembered");
    w.apply(&first);
    let forged = w.run(http("forged-get", "len=0", inline(b""))).await;
    assert_eq!(answer(&forged), "not-held");
    assert_eq!(
        w.blobs.reads.load(Ordering::Relaxed),
        reads,
        "nothing was read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_written_blob_is_a_response_and_an_open_writer_is_discarded() {
    let w = world();
    let out = w
        .run(http("write", "size=2200000&chunk=1048576", inline(b"")))
        .await;
    let blob = blob_answer(&out);
    assert_eq!(blob.size, 2_200_000);
    let expected: Vec<u8> = (0..2_200_000u64).map(pattern).collect();
    assert_eq!(w.blobs.bytes(&blob), expected);
    assert_eq!(
        blob.hash,
        format!("b3:{}", blake3::hash(&expected).to_hex())
    );

    let open = w.run(http("open-writer", "", inline(b""))).await;
    assert_eq!(answer(&open), "left open");
    assert_eq!(w.blobs.discarded.lock().unwrap().len(), 1);
    assert!(w.blobs.writers.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reference_the_turn_did_not_receive_is_not_held() {
    let w = world();
    let upload = w.blobs.store(b"a blob of the first turn".to_vec());
    let first = w
        .run(http("remember", "", pb::body::Value::Blob(upload.clone())))
        .await;
    assert_eq!(answer(&first), "remembered");
    w.apply(&first);
    let reads = w.blobs.reads.load(Ordering::Relaxed);

    // The right hash, stored as data, is not a reference.
    let get = w.run(http("forged-get", "", inline(b""))).await;
    assert_eq!(answer(&get), "not-held");
    assert_eq!(
        w.blobs.reads.load(Ordering::Relaxed),
        reads,
        "nothing was read"
    );

    let echo = w.run(http("forged-echo", "", inline(b""))).await;
    assert!(!echo.committed());
    assert_eq!(echo.outcome.error_code, "BLOB_NOT_HELD");
    assert_eq!(echo.outcome.kind, pb::OutcomeKind::Trap as i32);
    assert!(echo.writes.is_empty());

    let post = w
        .run(http("forged-post", "url=http://sink.test/up", inline(b"")))
        .await;
    assert_eq!(answer(&post), "denied(BLOB_NOT_HELD)");
    assert_eq!(
        w.gate.seen.lock().unwrap().last(),
        Some(&FetchBody::NotHeld {
            hash: upload.hash.clone(),
            size: upload.size
        })
    );

    // Received in the input, the same reference is the turn's to send.
    let sent = w
        .run(http(
            "post",
            "url=http://sink.test/up",
            pb::body::Value::Blob(upload.clone()),
        ))
        .await;
    assert_eq!(answer(&sent), "status 201");
    assert_eq!(
        w.gate.seen.lock().unwrap().last(),
        Some(&FetchBody::Blob(upload))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetched_blob_joins_the_turns_references() {
    let w = world();
    let doc = w.gate.document.clone();
    let out = w
        .run(http("fetch-sum", "", inline(b"http://files.test/doc")))
        .await;
    let bytes = w.blobs.bytes(&doc);
    assert_eq!(
        answer(&out),
        format!(
            "blob {} {} {} {}",
            doc.hash,
            doc.size,
            doc.size,
            fnv(&bytes)
        )
    );
    let echo = w
        .run(http("fetch-echo", "", inline(b"http://files.test/doc")))
        .await;
    assert_eq!(blob_answer(&echo), doc);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limits_of_a_call_a_turns_writes_and_its_reads_hold() {
    let w = world();
    let upload = w.blobs.store(vec![5u8; 3 << 20]);
    let body = pb::body::Value::Blob(upload);
    let limits = w.run(http("limits", "", body.clone())).await;
    let lines: Vec<String> = answer(&limits).lines().map(str::to_owned).collect();
    assert_eq!(lines[0], "ok 0");
    assert!(
        lines[1].starts_with("invalid(get reads at most"),
        "{lines:?}"
    );
    assert!(
        lines[2].starts_with("invalid(write takes at most"),
        "{lines:?}"
    );

    // The bytes one turn may create.
    let small = TurnLimits {
        blob_bytes: 3 << 20,
        ..TurnLimits::default()
    };
    let quota = w
        .run_limited(http("quota", "size=1048576", inline(b"")), small, true)
        .await;
    assert_eq!(answer(&quota), format!("{} quota-exceeded", 3 << 20));

    // The bytes one turn may move: fuel × 64. A million units of fuel move
    // 64,000,000 bytes: 61 reads of a MiB fit, the 62nd does not. The guest's
    // own fuel is far from spent at either count, so the boundary is the
    // blob budget's.
    let fuel = TurnLimits {
        fuel: 1_000_000,
        ..TurnLimits::default()
    };
    let within = w
        .run_limited(http("touch", "count=61", body.clone()), fuel, true)
        .await;
    assert_eq!(answer(&within), format!("{}", 61u64 << 20));
    let over = w
        .run_limited(http("touch", "count=62", body), fuel, true)
        .await;
    assert_eq!(over.outcome.error_code, "FUEL_EXHAUSTED");
    assert_eq!(over.outcome.kind, pb::OutcomeKind::FuelExhausted as i32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_blob_host_blobs_are_not_available() {
    let w = world();
    let info = w
        .run_limited(
            http("info", "", inline(b"hello")),
            TurnLimits::default(),
            false,
        )
        .await;
    assert_eq!(answer(&info), "inline 5");
    let write = w
        .run_limited(
            http("write", "size=10", inline(b"")),
            TurnLimits::default(),
            false,
        )
        .await;
    assert_eq!(write.outcome.error_code, "NOT_IMPLEMENTED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blob_turn_is_deterministic() {
    let w = world();
    let upload = w.blobs.store((0..1_500_000u64).map(pattern).collect());
    let body = pb::body::Value::Blob(upload);
    let mut first = None;
    for _ in 0..5 {
        let out = w
            .run(http("ranges", "at=7:100000,1400000:200000", body.clone()))
            .await;
        let seen = (answer(&out), out.fuel_used);
        match &first {
            None => first = Some(seen),
            Some(f) => assert_eq!(f, &seen),
        }
    }
}

/// Review B-M1: a read is charged for every frame it touches, whole, so
/// tiny reads cannot make the store read far more than the budget says.
#[test]
fn reads_are_charged_by_the_frames_they_touch() {
    use kronik_runtime::{BLOB_FRAME_BYTES as F, read_charge};
    assert_eq!(read_charge(10 * F, 0, 1), F);
    assert_eq!(read_charge(10 * F, F - 1, 2), 2 * F);
    assert_eq!(read_charge(10 * F, 3 * F, F as u32), F);
    assert_eq!(read_charge(10 * F, 0, 1 << 20), 10 * F);
    assert_eq!(read_charge(100, 0, 1 << 20), F);
    assert_eq!(read_charge(100, 100, 5), 0);
    assert_eq!(read_charge(100, 7, 0), 0);
}
