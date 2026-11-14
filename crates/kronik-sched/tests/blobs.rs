//! M25 slice B6: a node with a blob store runs turns with blobs
//! (docs/design/m25-streaming-bodies.md §4.3, §5, §17 criterion 5), with the
//! test guest `media`.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use kronik_blob::{BlobMeta, BlobStore, NoKeys, Space, StoreConfig};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{
    BlobsConfig, BodyPolicy, Ingress, IngressExtras, Node, NodeConfig, TurnResult, start_local,
};
use tokio::runtime::Runtime;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn start(dir: &Path, blobs: Option<BlobsConfig>) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            blobs,
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    let p = Proc { rt, node };
    let bytes = std::fs::read(MEDIA).unwrap();
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.deploy(&bytes, audit(), false, owner))
        .unwrap();
    p
}

fn pattern(i: u64) -> u8 {
    ((i.wrapping_mul(31) + 7) % 251) as u8
}

fn http(op: &str, query: &str, body: pb::body::Value) -> pb::HttpInput {
    pb::HttpInput {
        method: "POST".into(),
        path: format!("/media/a/{op}"),
        query: query.into(),
        body: Some(pb::Body { value: Some(body) }),
        ..Default::default()
    }
}

fn inline(bytes: &[u8]) -> pb::body::Value {
    pb::body::Value::Inline(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    })
}

impl Proc {
    fn ingress(&self, input: pb::HttpInput) -> TurnResult {
        self.rt.block_on(async {
            match self
                .node
                .ingress(ActorRef::parse("media/a").unwrap(), input, None)
                .unwrap()
            {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            }
        })
    }

    fn record(&self, r: &TurnResult) -> pb::TurnRecord {
        match self
            .rt
            .block_on(self.node.read_record(r.turn_id.lsn))
            .unwrap()
            .unwrap()
            .record
        {
            Record::TurnRecord(t) => t,
            other => panic!("{other:?}"),
        }
    }

    /// A blob written into the node's store from outside, as the gateway
    /// will write an upload (slice B8).
    fn upload(&self, dir: &Path, bytes: &[u8]) -> pb::BlobRef {
        self.rt.block_on(async {
            let store = BlobStore::open(
                Env::real(tokio::runtime::Handle::current()),
                dir,
                StoreConfig::default(),
            )
            .await
            .unwrap();
            let mut w = store
                .writer(Space::Main, None, u64::MAX, store.leases().take("upload"))
                .await
                .unwrap();
            w.write(bytes).await.unwrap();
            let meta = w.finish().await.unwrap();
            store
                .ensure_durable(&Space::Main, &[meta.id])
                .await
                .unwrap();
            meta.to_pb()
        })
    }

    fn stored(&self, dir: &Path, blob: &pb::BlobRef) -> Vec<u8> {
        self.rt.block_on(async {
            let store = BlobStore::open(
                Env::real(tokio::runtime::Handle::current()),
                dir,
                StoreConfig::default(),
            )
            .await
            .unwrap();
            let reader = store
                .reader(&Space::Main, &BlobMeta::from_pb(blob).unwrap(), &NoKeys)
                .await
                .unwrap();
            reader.verify(&NoKeys).await.unwrap();
            reader
                .read_at(0, blob.size as usize)
                .await
                .unwrap()
                .to_vec()
        })
    }
}

fn answer(r: &TurnResult) -> String {
    assert!(r.committed(), "{r:?}");
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    other => panic!("{other:?}"),
                },
                other => panic!("not inline: {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

fn blob_answer(r: &TurnResult) -> pb::BlobRef {
    assert!(r.committed(), "{r:?}");
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Blob(blob)) => blob.clone(),
                other => panic!("not a blob: {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

/// A blob the guest writes is the response: the turn's record holds only
/// its reference, and its bytes are in the store, whole, once the record
/// is there.
#[test]
fn a_writers_blob_is_the_response_and_the_record_holds_only_its_reference() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let r = p.ingress(http("write", "size=2200000&chunk=1048576", inline(b"")));
    let blob = blob_answer(&r);
    assert_eq!(blob.size, 2_200_000);
    let expected: Vec<u8> = (0..2_200_000u64).map(pattern).collect();
    assert_eq!(
        blob.hash,
        format!("b3:{}", blake3::hash(&expected).to_hex())
    );
    assert_eq!(p.stored(dir.path(), &blob), expected);
    let record = p.record(&r);
    let refs: Vec<pb::BlobRef> = kronik_proto::blobs::refs(&Record::TurnRecord(record.clone()))
        .into_iter()
        .cloned()
        .collect();
    assert_eq!(refs, [blob]);
    let encoded = prost::Message::encode_to_vec(&record);
    assert!(encoded.len() < 4096, "{} bytes", encoded.len());
}

/// Criterion 5 (production half; the fork's replay of it comes with slice
/// B10): a hash stored as data and turned back into a `blob-ref` in a later
/// turn gives the turn nothing: `get` is `not-held`, a response with it
/// fails with BLOB_NOT_HELD, and a fetch with it as body is a recorded
/// denial that names no blob of the turn.
#[test]
fn a_reference_from_an_earlier_turn_is_not_held() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let upload = p.upload(dir.path(), &b"an upload of the first turn ".repeat(40_000));
    let first = p.ingress(http("remember", "", pb::body::Value::Blob(upload.clone())));
    assert_eq!(answer(&first), "remembered");
    // The upload reaches the turn whole.
    let sum = p.ingress(http("sum", "", pb::body::Value::Blob(upload.clone())));
    assert!(
        answer(&sum).starts_with(&format!("{} ", upload.size)),
        "{}",
        answer(&sum)
    );

    let get = p.ingress(http("forged-get", "", inline(b"")));
    assert_eq!(answer(&get), "not-held");

    let echo = p.ingress(http("forged-echo", "", inline(b"")));
    assert!(!echo.committed());
    assert_eq!(echo.outcome.error_code, "BLOB_NOT_HELD");
    assert_eq!(echo.outcome.kind, pb::OutcomeKind::Trap as i32);
    assert!(p.record(&echo).writes.is_empty());

    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.grant(
        "media",
        "http:sink.test",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner,
    ))
    .unwrap();
    let post = p.ingress(http("forged-post", "url=http://sink.test/up", inline(b"")));
    assert!(
        answer(&post).starts_with("denied(BLOB_NOT_HELD"),
        "{}",
        answer(&post)
    );
    let record = p.record(&post);
    let effect = &record.effects[0];
    assert_eq!(effect.status, pb::EffectStatus::Denied as i32);
    assert!(
        effect.error.starts_with("BLOB_NOT_HELD"),
        "{}",
        effect.error
    );
    assert!(effect.blobs.is_empty());
    assert!(kronik_proto::blobs::refs(&Record::TurnRecord(record)).is_empty());
}

/// Without a blob store the node runs `media` as before: inline bodies,
/// and the blob functions trap.
#[test]
fn without_a_blob_store_blob_functions_trap() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), None);
    let info = p.ingress(http("info", "", inline(b"hello")));
    assert_eq!(answer(&info), "inline 5");
    let write = p.ingress(http("write", "size=10", inline(b"")));
    assert_eq!(write.outcome.error_code, "NOT_IMPLEMENTED");
    assert!(!dir.path().join("blobs").exists());
}

/// Answers every request with 200 "ok" and counts them. A peer of the
/// node, outside its `Env`, so it runs on an OS thread of its own.
#[allow(clippy::disallowed_methods)]
fn counting_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{BufRead as _, BufReader, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                line.clear();
            }
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stream = stream;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (addr, count)
}

/// ADR 0117 §9: a turn whose blob write meets the reserve is not
/// recorded and runs again once there is room. One that had already
/// fetched runs again as a re-run with its recorded result, so the server
/// sees one request and the record one effect.
#[test]
fn a_turn_that_meets_a_full_store_runs_again_when_there_is_room() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.grant(
        "media",
        "http:127.0.0.1",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner,
    ))
    .unwrap();
    let (addr, requests) = counting_server();
    let store = p.node.blob_store().unwrap().clone();
    let body = format!("http://{addr}/doc");
    for (op, query, fetches) in [("write", "size=5000", 0), ("fetch-write", "size=5000", 1)] {
        store.set_reserve(u64::MAX);
        let node = p.node.clone();
        let input = http(op, query, inline(body.as_bytes()));
        let pending = p.rt.spawn(async move {
            match node
                .ingress(ActorRef::parse("media/a").unwrap(), input, None)
                .unwrap()
            {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(800));
        assert!(!pending.is_finished(), "{op} did not wait for room");
        let before = requests.load(std::sync::atomic::Ordering::SeqCst);
        store.set_reserve(0);
        let r = p.rt.block_on(pending).unwrap();
        let blob = blob_answer(&r);
        assert_eq!(blob.size, 5000);
        let expected: Vec<u8> = (0..5000u64).map(pattern).collect();
        assert_eq!(p.stored(dir.path(), &blob), expected);
        // The re-run used the recorded fetch: no request after the first.
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), before);
        let record = p.record(&r);
        assert_eq!(record.effects.len(), fetches, "{op}");
    }
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// The (head, body) of every request a peer kept.
type Sunk = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

/// A peer for the effect tests: `GET /bytes/<n>` answers `n` bytes of the
/// `write` pattern; `POST /sink` keeps the request's head and body and
/// answers 201.
#[allow(clippy::disallowed_methods)]
fn peer() -> (String, Sunk) {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let sunk = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = sunk.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                    head.push_str(&line);
                    line.clear();
                }
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let mut stream = stream;
                if let Some(n) = path.strip_prefix("/bytes/") {
                    let n: u64 = n.parse().unwrap();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n"
                    );
                    let mut at = 0;
                    while at < n {
                        let end = (at + 65_536).min(n);
                        let part: Vec<u8> = (at..end).map(pattern).collect();
                        if stream.write_all(&part).is_err() {
                            return;
                        }
                        at = end;
                    }
                } else {
                    seen.lock().unwrap().push((head, body));
                    let _ = stream.write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                }
            });
        }
    });
    (addr, sunk)
}

fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

impl Proc {
    fn effect_setup(&self, threshold: u64, response_limit: Option<u64>) {
        let owner = self.node.local_operator_authority().unwrap();
        self.rt
            .block_on(self.node.set_limits(
                pb::Limits {
                    kind: "media".into(),
                    blob_threshold_bytes: Some(threshold),
                    effect_response_bytes: response_limit,
                    ..Default::default()
                },
                audit(),
                false,
                owner.clone(),
            ))
            .unwrap();
        self.rt
            .block_on(self.node.grant(
                "media",
                "http:127.0.0.1",
                None,
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                owner,
            ))
            .unwrap();
    }
}

/// M25 §7.3: for a kind that reads blobs, a response above the threshold
/// is a blob of the turn, recorded as its reference; one at the threshold
/// stays inline.
#[test]
fn a_response_above_the_threshold_is_a_blob() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    p.effect_setup(65_536, None);
    let (addr, _) = peer();
    let fetch = |n: u64| {
        p.ingress(http(
            "fetch-sum",
            "",
            inline(format!("http://{addr}/bytes/{n}").as_bytes()),
        ))
    };
    let at = fetch(65_536);
    let expected: Vec<u8> = (0..65_536u64).map(pattern).collect();
    assert_eq!(
        answer(&at),
        format!("inline 65536 65536 {}", fnv(&expected))
    );
    assert!(p.record(&at).effects[0].blobs.is_empty());

    for n in [65_537u64, 3_000_000] {
        let r = fetch(n);
        let expected: Vec<u8> = (0..n).map(pattern).collect();
        let text = answer(&r);
        let hash = format!("b3:{}", blake3::hash(&expected).to_hex());
        assert_eq!(text, format!("blob {hash} {n} {n} {}", fnv(&expected)));
        let record = p.record(&r);
        let effect = &record.effects[0];
        assert_eq!(effect.status, pb::EffectStatus::Ok as i32);
        assert_eq!(effect.blobs.len(), 1);
        assert_eq!(
            (effect.blobs[0].hash.as_str(), effect.blobs[0].size),
            (hash.as_str(), n)
        );
        let Some(pb::sealable::Value::Plain(payload)) =
            effect.response.as_ref().and_then(|r| r.value.as_ref())
        else {
            panic!("{effect:?}")
        };
        let response: pb::HttpEffectResponse = prost::Message::decode(payload.as_slice()).unwrap();
        assert!(response.body.is_empty());
        assert_eq!(response.body_blob.as_ref(), Some(&effect.blobs[0]));
        assert_eq!(p.stored(dir.path(), &effect.blobs[0]), expected);
    }
}

/// M25 §7.2: a blob request body is recorded as its reference and streamed
/// from the store with its length.
#[test]
fn a_blob_request_body_streams_from_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    p.effect_setup(65_536, None);
    let (addr, sunk) = peer();
    let bytes: Vec<u8> = (0..1_500_000u64).map(|i| (i % 13) as u8).collect();
    let upload = p.upload(dir.path(), &bytes);
    let r = p.ingress(http(
        "post",
        &format!("url=http://{addr}/sink"),
        pb::body::Value::Blob(upload.clone()),
    ));
    assert_eq!(answer(&r), "status 201");
    let (head, body) = sunk.lock().unwrap().pop().unwrap();
    assert!(
        head.to_ascii_lowercase()
            .contains("content-length: 1500000"),
        "{head}"
    );
    assert!(body == bytes, "the peer got {} other bytes", body.len());
    let record = p.record(&r);
    let effect = &record.effects[0];
    assert_eq!(effect.blobs, std::slice::from_ref(&upload));
    let Some(pb::sealable::Value::Plain(payload)) =
        effect.request.as_ref().and_then(|r| r.value.as_ref())
    else {
        panic!("{effect:?}")
    };
    let request: pb::HttpEffectRequest = prost::Message::decode(payload.as_slice()).unwrap();
    assert!(request.body.is_empty());
    assert_eq!(request.body_blob, Some(upload));
}

/// A response past `effect_response_bytes` is TOO_LARGE, as before, and
/// leaves no blob behind.
#[test]
fn a_response_over_its_limit_is_too_large_and_leaves_no_blob() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    p.effect_setup(65_536, Some(1 << 20));
    let (addr, _) = peer();
    let r = p.ingress(http(
        "fetch-sum",
        "",
        inline(format!("http://{addr}/bytes/2000000").as_bytes()),
    ));
    assert_eq!(answer(&r), "too-large");
    let record = p.record(&r);
    assert_eq!(record.effects[0].status, pb::EffectStatus::TooLarge as i32);
    assert!(record.effects[0].blobs.is_empty());
    let objects = walk(&dir.path().join("blobs"));
    assert!(objects.is_empty(), "{objects:?}");
}

/// The object files of a blob store (`objects/<shard>/<file>`).
fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for shard in std::fs::read_dir(root.join("objects")).unwrap().flatten() {
        for file in std::fs::read_dir(shard.path()).unwrap().flatten() {
            out.push(file.path());
        }
    }
    out
}

/// Review B-H1 (ci-green's repro): a turn may hold 64 writers open at
/// once; constructing more traps, so one turn can never hold thousands of
/// files. Within the cap, each writer holds at most a frame of its data.
#[test]
fn a_turn_holds_a_bounded_number_of_open_writers() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let tmp = dir.path().join("blobs/tmp");
    let parts = || std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0);
    let within = p.ingress(http("many-writers", "n=64&size=1000000", inline(b"")));
    assert_eq!(answer(&within), "opened 64");
    let over = p.ingress(http("many-writers", "n=3000&size=0", inline(b"")));
    assert!(!over.committed());
    assert_eq!(over.outcome.kind, pb::OutcomeKind::Trap as i32);
    assert!(
        over.outcome.message.contains("too many open blob writers"),
        "{:?}",
        over.outcome
    );
    // Discarded writers leave no part files behind (deleted in the
    // background).
    for _ in 0..100 {
        if parts() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(parts(), 0);
}

/// A turn's lease ends with the turn (found in review: the turn's effect
/// state and its blob host held each other, so neither was freed, nor the
/// turn's lease, nor the secret values the turn used).
#[test]
fn a_turns_lease_ends_with_the_turn() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let store = p.node.blob_store().unwrap().clone();
    for _ in 0..3 {
        let r = p.ingress(http("write", "size=100000", inline(b"")));
        let blob = blob_answer(&r);
        let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
        let mut gone = false;
        for _ in 0..100 {
            if !store.leases().holders().contains(&"turn") && !store.leases().is_leased(&id) {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(gone, "holders: {:?}", store.leases().holders());
    }
}

/// Review B-M2: a turn that fills the store past its reserve by itself
/// cannot finish by waiting. After five attempts that began with room, the
/// caller gets BLOB_STORE_FULL, nothing is recorded, and the actor's next
/// input runs.
#[allow(clippy::disallowed_methods)]
#[test]
fn a_turn_that_fills_the_store_itself_stops_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let store = p.node.blob_store().unwrap().clone();
    let reserve = 1u64 << 30;
    store.set_reserve(reserve);
    // A disk reading every 20 ms, with less room above the reserve than
    // one frame: the turn's first frame takes the store below it, and only
    // a reading between a frame's write and the next frame's check (a few
    // microseconds) could let a frame more through.
    let room = reserve + 100;
    store.set_free(room);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reading = {
        let (stop, store) = (stop.clone(), store.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                store.set_free(room);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
    };
    let started = std::time::Instant::now();
    let result = p.rt.block_on(async {
        match p
            .node
            .ingress(
                ActorRef::parse("media/a").unwrap(),
                http("write", "size=1000000", inline(b"")),
                None,
            )
            .unwrap()
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await,
            Ingress::Done(r) => Ok(*r),
        }
    });
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    reading.join().unwrap();
    let error = result.expect_err("the turn cannot finish");
    assert_eq!(error.code, kronik_core::error::ErrorCode::BlobStoreFull);
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    store.set_reserve(0);
    store.set_free(u64::MAX - 1);
    let next = p.ingress(http("info", "", inline(b"x")));
    assert_eq!(answer(&next), "inline 1");
    // Nothing of the abandoned turn was recorded: the next turn is the
    // actor's first record.
    let record = p.record(&next);
    assert!(record.effects.is_empty());
}

/// Real files; records the blob store's renames into `objects/` and its
/// directory syncs, in order, with the events of the test's peer.
struct OrderFs {
    inner: Arc<dyn kronik_core::env::Fs>,
    events: Arc<std::sync::Mutex<Vec<String>>>,
}

impl kronik_core::env::Fs for OrderFs {
    fn create_dir_all(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: std::path::PathBuf,
        mode: kronik_core::env::OpenMode,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Arc<dyn kronik_core::env::File>>>
    {
        self.inner.open(path, mode)
    }
    fn exists(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(
        &self,
        dir: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(
        &self,
        from: std::path::PathBuf,
        to: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        if to.components().any(|c| c.as_os_str() == "objects") {
            self.events
                .lock()
                .unwrap()
                .push(format!("named {}", to.display()));
        }
        self.inner.rename(from, to)
    }
    fn remove_file(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(
        &self,
        dir: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        if dir.components().any(|c| c.as_os_str() == "objects") {
            self.events
                .lock()
                .unwrap()
                .push(format!("synced {}", dir.display()));
        }
        self.inner.sync_dir(dir)
    }
}

/// ADR 0117 §4: an effect's record never precedes its blobs. A turn that
/// writes a blob and POSTs it in the same turn has the blob's name synced
/// before the request leaves (so before its effect is recorded), not only
/// at the turn's commit.
#[allow(clippy::disallowed_methods)]
#[test]
fn a_blob_the_turn_wrote_is_durable_before_it_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.fs = Arc::new(OrderFs {
            inner: env.fs.clone(),
            events: events.clone(),
        });
        let config = NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        };
        start_local(env, dir.path(), config).await.unwrap()
    });
    let p = Proc { rt, node };
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.deploy(
        &std::fs::read(MEDIA).unwrap(),
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    p.rt.block_on(p.node.grant(
        "media",
        "http:127.0.0.1",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner,
    ))
    .unwrap();
    // A peer that notes when the request arrives.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = events.clone();
    std::thread::spawn(move || {
        use std::io::{BufRead as _, BufReader, Read as _, Write as _};
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                head.push_str(&line);
                line.clear();
            }
            seen.lock().unwrap().push("request".into());
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; len];
            let _ = reader.read_exact(&mut body);
            let mut stream = stream;
            let _ = stream.write_all(
                b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    events.lock().unwrap().clear();
    let r = p.ingress(http(
        "write-post",
        &format!("size=200000&url=http://{addr}/sink"),
        inline(b""),
    ));
    assert_eq!(answer(&r), "status 201");
    let events = events.lock().unwrap().clone();
    let named = events
        .iter()
        .position(|e| e.starts_with("named "))
        .expect("the blob was named");
    let shard = std::path::Path::new(events[named].trim_start_matches("named "))
        .parent()
        .unwrap()
        .display()
        .to_string();
    let synced = events
        .iter()
        .position(|e| *e == format!("synced {shard}"))
        .expect("its directory was synced");
    let request = events
        .iter()
        .position(|e| e == "request")
        .expect("the peer got the request");
    assert!(named < synced && synced < request, "{events:#?}");
}

impl Proc {
    fn ingress_with(
        &self,
        input: pb::HttpInput,
        extras: IngressExtras,
    ) -> Result<TurnResult, kronik_core::error::ApiError> {
        self.rt.block_on(async {
            match self.node.ingress_with(
                ActorRef::parse("media/a").unwrap(),
                input,
                None,
                extras,
            )? {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await,
                Ingress::Done(r) => Ok(*r),
            }
        })
    }
}

/// A request hash of `version`: a version byte and 32 bytes.
fn hash_v(version: u8, of: &[u8]) -> Vec<u8> {
    let mut h = vec![version];
    h.extend_from_slice(blake3::hash(of).as_bytes());
    h
}

fn keyed(op: &str, key: &str, hash: Vec<u8>) -> pb::HttpInput {
    let mut h = http(op, "", inline(b"x"));
    h.idempotency_key = key.into();
    h.request_hash = hash;
    h
}

/// M25 §6.3: request hashes are version 4. A row saved with version 3
/// matches only the version-3 hash of an inline body, which the gateway
/// passes unrecorded; without it (a spooled body) the row counts as
/// expired. M25 §6.2: `ingress_peek` sees turns in flight and version-4
/// rows only, and a withheld body joins or gets the saved answer but never
/// starts a turn.
#[test]
fn version_3_rows_match_only_the_legacy_hash_of_an_inline_body() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let actor = ActorRef::parse("media/a").unwrap();
    let legacy = |of: &[u8]| IngressExtras {
        legacy_hash: Some(hash_v(3, of)),
        ..IngressExtras::default()
    };
    let withheld = || IngressExtras {
        body_withheld: true,
        ..IngressExtras::default()
    };
    // A row saved before version 4.
    let old = p.ingress(keyed("info", "k3", hash_v(3, b"v3 x")));
    assert!(!p.node.ingress_peek(&actor, "k3").unwrap());
    let again = p
        .ingress_with(keyed("info", "k3", hash_v(4, b"x")), legacy(b"v3 x"))
        .unwrap();
    assert_eq!(again.turn_id, old.turn_id, "the saved answer");
    let reused = p
        .ingress_with(keyed("info", "k3", hash_v(4, b"y")), legacy(b"v3 y"))
        .unwrap_err();
    assert_eq!(
        reused.code,
        kronik_core::error::ErrorCode::IdempotencyKeyReused
    );
    // Without the legacy hash the version-3 row counts as expired.
    let anew = p
        .ingress_with(
            keyed("info", "k3", hash_v(4, b"x")),
            IngressExtras::default(),
        )
        .unwrap();
    assert_ne!(anew.turn_id, old.turn_id);
    // Now a version-4 row: peek sees it, and a withheld body gets its answer.
    assert!(p.node.ingress_peek(&actor, "k3").unwrap());
    let saved = p
        .ingress_with(keyed("info", "k3", hash_v(4, b"x")), withheld())
        .unwrap();
    assert_eq!(saved.turn_id, anew.turn_id);
    // A withheld body with nothing to join or answer never starts a turn.
    assert!(!p.node.ingress_peek(&actor, "k-new").unwrap());
    let refused = p
        .ingress_with(keyed("info", "k-new", hash_v(4, b"x")), withheld())
        .unwrap_err();
    assert_eq!(refused.code, kronik_core::error::ErrorCode::Unavailable);
    assert!(!p.node.ingress_peek(&actor, "k-new").unwrap());
}

/// M25 §6.2: an upload's lease lasts until the turn's result arrives (its
/// record, which references the blob, is applied by then), and a saved
/// answer ends it at once.
#[allow(clippy::disallowed_methods)]
#[test]
fn an_upload_lease_lasts_until_the_turns_result() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    p.effect_setup(1 << 20, None);
    let store = p.node.blob_store().unwrap().clone();
    let uploads = || {
        store
            .leases()
            .holders()
            .iter()
            .filter(|h| **h == "upload")
            .count()
    };
    // A server that answers after 500 ms keeps the turn running.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        use std::io::{BufRead as _, BufReader, Write as _};
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                line.clear();
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut stream = stream;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    let mut slow = http(
        "fetch",
        "",
        inline(format!("http://{addr}/slow").as_bytes()),
    );
    slow.idempotency_key = "up".into();
    slow.request_hash = hash_v(4, b"slow");
    let started = p.rt.block_on(async {
        p.node.ingress_with(
            ActorRef::parse("media/a").unwrap(),
            slow.clone(),
            None,
            IngressExtras {
                upload: Some(store.leases().take("upload")),
                ..IngressExtras::default()
            },
        )
    });
    let Ok(Ingress::Started(waiter)) = started else {
        panic!("not started")
    };
    assert_eq!(uploads(), 1, "the turn runs: the lease holds");
    let result = p.rt.block_on(waiter.wait()).unwrap();
    assert!(result.committed(), "{result:?}");
    assert_eq!(uploads(), 0, "the result arrived: the lease ended");
    // A retry gets the saved answer, and its lease ends at once.
    let retry = p
        .ingress_with(
            slow,
            IngressExtras {
                upload: Some(store.leases().take("upload")),
                ..IngressExtras::default()
            },
        )
        .unwrap();
    assert_eq!(retry.turn_id, result.turn_id);
    assert_eq!(uploads(), 0);
}

/// M25 §6.2: the gateway spools bodies only for a kind whose code reads
/// blobs on a node with a blob store.
#[test]
fn the_body_policy_follows_the_kinds_code_and_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    assert_eq!(
        p.node.body_policy("media"),
        BodyPolicy::Blobs {
            threshold: 1 << 20,
            upload_bytes: 64 << 20
        }
    );
    assert_eq!(p.node.body_policy("nobody"), BodyPolicy::Inline);
    drop(p);
    let p = start(dir.path(), None);
    assert_eq!(p.node.body_policy("media"), BodyPolicy::Inline);
}

/// Real files, except that naming a blob (the rename into `objects/`)
/// fails with an I/O error while `fail` is set.
struct FailingFs {
    inner: Arc<dyn kronik_core::env::Fs>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}

impl kronik_core::env::Fs for FailingFs {
    fn create_dir_all(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: std::path::PathBuf,
        mode: kronik_core::env::OpenMode,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Arc<dyn kronik_core::env::File>>>
    {
        self.inner.open(path, mode)
    }
    fn exists(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(
        &self,
        dir: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(
        &self,
        from: std::path::PathBuf,
        to: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst)
            && to.components().any(|c| c.as_os_str() == "objects")
        {
            return Box::pin(async { Err(std::io::Error::other("injected EIO")) });
        }
        self.inner.rename(from, to)
    }
    fn remove_file(
        &self,
        path: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(
        &self,
        dir: std::path::PathBuf,
    ) -> kronik_core::env::BoxFuture<'static, std::io::Result<()>> {
        self.inner.sync_dir(dir)
    }
}

/// Found by the blob simulation (B17): the blob store's disk failing in a
/// turn that already recorded an effect abandoned the turn while the node
/// kept running, so a retry under the same key started a second execution.
/// Now the node stops, as for a failure of its log; the retry is refused,
/// and after the restart the open turn runs again and answers it.
#[allow(clippy::disallowed_methods)]
#[test]
fn a_blob_store_io_failure_stops_the_node_and_the_turn_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.fs = Arc::new(FailingFs {
            inner: env.fs.clone(),
            fail: fail.clone(),
        });
        let config = NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        };
        start_local(env, dir.path(), config).await.unwrap()
    });
    let p = Proc { rt, node };
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(
        p.node
            .deploy(&std::fs::read(MEDIA).unwrap(), audit(), false, owner),
    )
    .unwrap();
    p.effect_setup(1 << 20, None);
    let (addr, requests) = counting_server();
    let keyed = || {
        let mut h = http(
            "fetch-write",
            "size=300000",
            inline(format!("http://{addr}/x").as_bytes()),
        );
        h.idempotency_key = "io-1".into();
        h.request_hash = {
            let mut v = vec![kronik_sched::INGRESS_HASH_VERSION];
            v.extend_from_slice(blake3::hash(b"io-1").as_bytes());
            v
        };
        h
    };
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let failed = p.ingress_with(keyed(), IngressExtras::default());
    assert!(failed.is_err(), "{:?}", failed.map(|r| r.outcome));
    assert!(p.node.fatal().is_some(), "the node stopped");
    let retry = p.ingress_with(keyed(), IngressExtras::default());
    assert!(retry.is_err(), "no second execution on a stopped node");
    assert_eq!(p.node.store().db().open_turns().unwrap().len(), 1);
    drop(p);

    // The restart runs the open turn again; the retry gets its answer.
    let p = start(dir.path(), Some(BlobsConfig::default()));
    p.effect_setup(1 << 20, None);
    for _ in 0..200 {
        if p.node.store().db().open_turns().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(p.node.store().db().open_turns().unwrap().is_empty());
    let answered = p.ingress_with(keyed(), IngressExtras::default()).unwrap();
    assert!(answered.committed(), "{:?}", answered.outcome);
    let blob = blob_answer(&answered);
    assert_eq!(blob.size, 300_000);
    assert!(requests.load(std::sync::atomic::Ordering::SeqCst) >= 1);
}

/// Review R-1 (erasure): a reply's blobs reached the turn's record
/// unchecked, so a made-up `b3s:` reference made the log undecodable at
/// the next start, and a known one with another size made the node fatal.
/// Since M26 a reply carries the references the turn may use (T), each
/// completed from it: a made-up one, or a known identity with another
/// size, fails the turn with BLOB_NOT_HELD; the node stays up, and it
/// starts again from its log.
#[test]
fn a_reply_carries_only_the_turns_references() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path(), Some(BlobsConfig::default()));
    let made_up = p.ingress(http("reply-forged", "", inline(b"")));
    assert!(!made_up.committed());
    assert_eq!(
        made_up.outcome.error_code, "BLOB_NOT_HELD",
        "{:?}",
        made_up.outcome
    );
    let written = blob_answer(&p.ingress(http("write", "size=100000", inline(b""))));
    let resized = p.ingress(http(
        "reply-forged",
        "kind=resized",
        pb::body::Value::Blob(written),
    ));
    assert!(!resized.committed());
    assert_eq!(
        resized.outcome.error_code, "BLOB_NOT_HELD",
        "{:?}",
        resized.outcome
    );
    assert!(p.node.fatal().is_none());
    assert_eq!(
        answer(&p.ingress(http("info", "", inline(b"x")))),
        "inline 1"
    );
    drop(p);
    let p = start(dir.path(), Some(BlobsConfig::default()));
    assert_eq!(
        answer(&p.ingress(http("info", "", inline(b"yz")))),
        "inline 2"
    );
}

/// Serves one request after reading its body, `delay` later.
#[allow(clippy::disallowed_methods)]
fn slow_server(delay: std::time::Duration) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(300)))
                .unwrap();
            let mut buf = vec![0u8; 64 << 10];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
            std::thread::sleep(delay);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}

/// Review R-2 (erasure): a turn's lease held only the blobs it wrote, so
/// its input could be collected while it ran. The turn's lease, renewed
/// while it runs, now holds its input too.
#[allow(clippy::disallowed_methods)]
#[test]
fn a_running_turn_leases_its_input() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(
        dir.path(),
        Some(BlobsConfig {
            lease_ttl: std::time::Duration::from_millis(200),
            ..BlobsConfig::default()
        }),
    );
    p.effect_setup(1 << 20, None);
    let addr = slow_server(std::time::Duration::from_millis(1500));
    let blob = p.upload(dir.path(), &vec![5u8; 300_000]);
    let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
    let store = p.node.blob_store().unwrap().clone();
    assert!(!store.leases().is_leased(&id));
    let node = p.node.clone();
    let input = http(
        "post",
        &format!("url=http://{addr}/sink"),
        pb::body::Value::Blob(blob),
    );
    let turn = p.rt.spawn(async move {
        match node
            .ingress(ActorRef::parse("media/a").unwrap(), input, None)
            .unwrap()
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
            Ingress::Done(r) => *r,
        }
    });
    std::thread::sleep(std::time::Duration::from_millis(900));
    assert!(
        store.leases().is_leased(&id),
        "the running turn holds its input past the lease TTL: {:?}",
        store.leases().holders()
    );
    let r = p.rt.block_on(turn).unwrap();
    assert_eq!(answer(&r), "status 200");
}
