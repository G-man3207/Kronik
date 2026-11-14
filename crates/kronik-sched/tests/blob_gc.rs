//! M25 slice B11: the blob collector (docs/design/m26-blobs.md §6, ADR
//! 0120). A file no root keeps goes in the second pass that finds it so;
//! records within retention, saved idempotent responses and snapshots'
//! indexes keep theirs; a loose file (no record ever referenced it, such as
//! one a turn wrote and did not keep) goes; once compaction has deleted a
//! blob's last record, it goes too. The dry run says why each has no root.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_blob::{Space, SweepOptions};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::blob_gc::UnrootedReason;
use kronik_sched::snapshots::StorageConfig;
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

/// A node with blobs, no history window, small segments and no collector
/// loop of its own (`gc_interval` 0: the test drives the passes).
fn start(dir: &Path) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.history = Duration::ZERO;
        storage.snapshot_interval = Duration::from_secs(3600);
        let config = NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ingress_ttl: Duration::from_secs(3600),
            blobs: Some(BlobsConfig {
                gc_interval: Duration::ZERO,
                ..BlobsConfig::default()
            }),
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

fn http(op: &str, query: &str, idempotency_key: &str) -> pb::HttpInput {
    pb::HttpInput {
        method: "POST".into(),
        path: format!("/media/a/{op}"),
        query: query.into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(Vec::new())),
            })),
        }),
        idempotency_key: idempotency_key.into(),
        request_hash: if idempotency_key.is_empty() {
            Vec::new()
        } else {
            vec![7; 32]
        },
        ..Default::default()
    }
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

    /// A turn whose response is a new blob of `size` bytes.
    fn blob_turn(&self, size: u64, idempotency_key: &str) -> pb::BlobRef {
        let r = self.ingress(http(
            "write",
            &format!("size={size}&chunk=65536"),
            idempotency_key,
        ));
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

    /// A blob in the store that no record references (a crash before
    /// commit, a rejected upload), its writer's lease ended.
    fn loose(&self, bytes: &[u8]) -> pb::BlobRef {
        let store = self.node.blob_store().unwrap().clone();
        self.rt.block_on(async move {
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

    fn exists(&self, blob: &pb::BlobRef) -> bool {
        let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
        self.node
            .blob_store()
            .unwrap()
            .object_path(&Space::Main, &id)
            .exists()
    }

    fn gc(&self, options: SweepOptions) -> kronik_sched::blob_gc::GcOutcome {
        self.rt
            .block_on(self.node.blob_gc(options))
            .unwrap()
            .unwrap()
    }

    /// Small turns of another kind of input that roll segments and move
    /// logical time.
    fn traffic(&self, turns: usize) {
        for i in 0..turns {
            let r = self.ingress(http("info", &format!("n={i}"), ""));
            assert!(r.committed(), "{r:?}");
            if i % 20 == 19 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// A snapshot that a later turn makes the window's base, and a
    /// retention pass.
    fn compact(&self) {
        self.rt
            .block_on(
                self.node
                    .snapshot("manual", self.node.local_operator_authority().unwrap()),
            )
            .unwrap();
        let hwm = self.node.store().db().time_hwm().unwrap();
        while self.node.store().db().time_hwm().unwrap() <= hwm {
            std::thread::sleep(Duration::from_millis(2));
            self.traffic(1);
        }
        self.node
            .compact(self.node.storage_config().unwrap())
            .unwrap();
    }
}

fn dry(p: &Proc) -> Vec<kronik_sched::blob_gc::Unrooted> {
    let dry = p.gc(SweepOptions {
        dry_run: true,
        ..Default::default()
    });
    assert_eq!(dry.report.deleted, 0);
    dry.unrooted
}

#[test]
fn the_collector_keeps_what_records_responses_and_snapshots_keep() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let response = p.blob_turn(300_000, "");
    let saved = p.blob_turn(200_000, "k1");
    let loose = p.loose(b"no record references this");

    // The dry run lists only the loose file, and why; nothing is deleted.
    let unrooted = dry(&p);
    assert_eq!(unrooted.len(), 1, "{unrooted:?}");
    assert_eq!(unrooted[0].hash, loose.hash);
    assert_eq!(unrooted[0].reason, UnrootedReason::Loose);
    assert!(!unrooted[0].candidate);
    // Two passes: a candidate, then deleted.
    assert_eq!(p.gc(SweepOptions::default()).report.candidates, 1);
    assert!(p.exists(&loose));
    let second = p.gc(SweepOptions::default());
    assert_eq!(second.report.deleted, 1, "{second:?}");
    assert!(!p.exists(&loose));
    assert!(p.exists(&response) && p.exists(&saved));

    // Compaction deletes the records of both turns. The response then has
    // no root; the saved response is still pinned by its idempotency row,
    // and the snapshot's index lists it.
    p.traffic(80);
    p.compact();
    let storage = p.node.storage_config().unwrap().clone();
    let first = p.node.log_first(&storage).unwrap();
    assert!(first > 3, "nothing was compacted");
    let snapshot = p.node.snapshots().unwrap().into_iter().last().unwrap();
    let index = std::fs::read_to_string(
        dir.path()
            .join("snapshots/main")
            .join(format!("{:020}", snapshot.lsn))
            .join("blobs.idx"),
    )
    .unwrap();
    assert_eq!(index.lines().collect::<Vec<_>>(), [saved.hash.as_str()]);
    assert!(snapshot.files.iter().any(|f| f.path == "blobs.idx"));
    assert_eq!((snapshot.blobs.count, snapshot.blobs.bytes), (1, 200_000));

    let unrooted = dry(&p);
    assert_eq!(unrooted.len(), 1, "{unrooted:?}");
    assert_eq!(unrooted[0].hash, response.hash);
    assert_eq!(unrooted[0].reason, UnrootedReason::OutOfRetention);
    assert_eq!(unrooted[0].size, Some(300_000));
    assert!(unrooted[0].last_ref_lsn.unwrap() < first);
    let after = p.gc(SweepOptions {
        immediate: true,
        ..Default::default()
    });
    assert!(!p.exists(&response), "{after:?}");
    assert!(p.exists(&saved));
    assert_eq!(after.forgotten, 1, "{after:?}");
    assert!(p.node.store().db().blob(&response.hash).unwrap().is_none());
    assert!(p.node.store().db().blob(&saved.hash).unwrap().is_some());
}

/// The blobs turns wrote and did not keep are loose: one whose turn
/// committed with something else as its answer (`write-discard`), one whose
/// turn failed after its writer finished (`fail-after-write`). No record
/// references either. Once each turn's lease has ended with its record, the
/// dry run lists both as `loose` and two passes delete them, and nothing
/// else.
#[test]
fn the_blobs_that_turns_wrote_and_did_not_keep_are_collected() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let kept = p.blob_turn(70_000, "");
    let pattern = |n: u64| -> Vec<u8> {
        (0..n)
            .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
            .collect()
    };
    let r = p.ingress(http("write-discard", "size=300000", ""));
    assert!(r.committed(), "{r:?}");
    let r = p.ingress(http("fail-after-write", "", ""));
    assert!(!r.committed(), "{r:?}");
    let mut loose: Vec<String> = [pattern(300_000), pattern(1000)]
        .iter()
        .map(|bytes| format!("b3:{}", blake3::hash(bytes).to_hex()))
        .collect();
    loose.sort();
    let store = p.node.blob_store().unwrap().clone();
    for hash in &loose {
        let id = kronik_blob::BlobId::parse(hash).unwrap();
        assert!(store.object_path(&Space::Main, &id).exists());
        // The turn's lease ended with its record.
        assert!(!store.leases().is_leased(&id), "{hash} is still leased");
        assert!(p.node.store().db().blob(hash).unwrap().is_none());
    }

    let unrooted = dry(&p);
    let listed: Vec<String> = unrooted.iter().map(|u| u.hash.clone()).collect();
    assert_eq!(listed, loose, "{unrooted:?}");
    assert!(unrooted.iter().all(|u| u.reason == UnrootedReason::Loose));
    assert!(unrooted.iter().all(|u| u.last_ref_lsn.is_none()));
    let first = p.gc(SweepOptions::default());
    assert_eq!((first.report.deleted, first.report.candidates), (0, 2));
    let second = p.gc(SweepOptions::default());
    assert_eq!(second.report.deleted, 2, "{second:?}");
    for hash in &loose {
        let id = kronik_blob::BlobId::parse(hash).unwrap();
        assert!(!store.object_path(&Space::Main, &id).exists());
    }
    assert!(p.exists(&kept));
    assert_eq!(second.report.objects, 1);
}
