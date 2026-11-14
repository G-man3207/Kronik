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
use kronik_sched::{BlobsConfig, Ingress, Node, NodeConfig, TurnResult, start_local};
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
