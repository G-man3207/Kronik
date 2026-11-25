//! M25 slice B11: the blob collector (docs/design/m26-blobs.md §6, ADR
//! 0120). A file no root keeps goes in the second pass that finds it so;
//! records within retention, saved idempotent responses and snapshots'
//! indexes keep theirs; a loose file (no record ever referenced it, such as
//! one a turn wrote and did not keep) goes; once compaction has deleted a
//! blob's last record, it goes too. The dry run says why each has no root.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{Proc, audit, slow_server, start_proc, wait_turn};
use kronik_blob::{Space, SweepOptions};
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::blob_gc::UnrootedReason;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

/// A node with blobs, no history window, small segments and no collector
/// loop of its own (`gc_interval` 0: the test drives the passes).
fn start(dir: &Path) -> Proc {
    start_with(dir, BlobsConfig::default().lease_ttl)
}

/// [`start`] with leases that live `lease_ttl` without renewal.
fn start_with(dir: &Path, lease_ttl: Duration) -> Proc {
    start_blobs(
        dir,
        BlobsConfig {
            gc_interval: Duration::ZERO,
            lease_ttl,
            ..BlobsConfig::default()
        },
    )
}

/// [`start`] with `blobs` as the node's `[blobs]` settings.
fn start_blobs(dir: &Path, blobs: BlobsConfig) -> Proc {
    let mut storage = StorageConfig::new(dir.to_path_buf());
    storage.history = Duration::ZERO;
    storage.snapshot_interval = Duration::from_secs(3600);
    let p = start_proc(
        dir,
        NodeConfig {
            concurrency: 8,
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ingress_ttl: Duration::from_secs(3600),
            blobs: Some(blobs),
            ..NodeConfig::default()
        },
    );
    p.deploy_file(MEDIA);
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
            wait_turn(
                self.node
                    .ingress(ActorRef::parse("media/a").unwrap(), input, None)
                    .unwrap(),
            )
            .await
            .unwrap()
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

/// A fork keeps the blobs of its base state (its `blobs.roots`, here the
/// superset of a point before the head) and those of main's records after
/// its point (the floor), after compaction has deleted those records from
/// main's log; once the fork is deleted, both go.
#[test]
fn a_fork_keeps_its_base_and_the_records_after_its_point() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let base = p.blob_turn(50_000, "");
    let fork_lsn = p.node.applied_lsn();
    let after = p.blob_turn(60_000, "");
    let fork = dir.path().join("branches/f1");
    std::fs::create_dir_all(&fork).unwrap();
    p.node.write_fork_roots(&fork, fork_lsn).unwrap();
    let roots = std::fs::read_to_string(fork.join("blobs.roots")).unwrap();
    assert_eq!(
        roots.lines().collect::<Vec<_>>(),
        [format!("fork_lsn {fork_lsn}").as_str(), base.hash.as_str()]
    );

    p.traffic(80);
    p.compact();
    let storage = p.node.storage_config().unwrap().clone();
    assert!(p.node.log_first(&storage).unwrap() > fork_lsn + 2);
    assert_eq!(p.node.blob_floor().unwrap(), fork_lsn + 1);
    assert!(dry(&p).is_empty());
    p.gc(SweepOptions {
        immediate: true,
        ..Default::default()
    });
    assert!(p.exists(&base) && p.exists(&after));

    std::fs::remove_dir_all(&fork).unwrap();
    let mut unrooted: Vec<(String, UnrootedReason)> =
        dry(&p).into_iter().map(|u| (u.hash, u.reason)).collect();
    unrooted.sort();
    let mut expected = vec![
        (base.hash.clone(), UnrootedReason::OutOfRetention),
        (after.hash.clone(), UnrootedReason::OutOfRetention),
    ];
    expected.sort();
    assert_eq!(unrooted, expected);
    let gone = p.gc(SweepOptions {
        immediate: true,
        ..Default::default()
    });
    assert_eq!(gone.report.deleted, 2, "{gone:?}");
    assert!(!p.exists(&base) && !p.exists(&after));
}

/// Review R-2 (erasure), the collector's side: an upload whose turn waits
/// longer than `[blobs] lease_ttl` for its actor, before any record names
/// it, is kept only by the upload's lease. The gateway keeps that lease
/// alive until the turn's result (Lease::keep_alive), so two immediate
/// passes after the TTL leave it, and the turn reads all of it. A lease
/// nobody renews ends with its TTL, and its blob goes.
#[allow(clippy::disallowed_methods)]
#[test]
fn an_upload_waiting_past_the_lease_ttl_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_with(dir.path(), Duration::from_secs(1));
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
    let store = p.node.blob_store().unwrap().clone();
    let write = |lease: kronik_blob::Lease, byte: u8| -> pb::BlobRef {
        let store = store.clone();
        p.rt.block_on(async move {
            let mut w = store
                .writer(Space::Main, None, u64::MAX, lease)
                .await
                .unwrap();
            w.write(&vec![byte; 200_000]).await.unwrap();
            let meta = w.finish().await.unwrap();
            store
                .ensure_durable(&Space::Main, &[meta.id])
                .await
                .unwrap();
            meta.to_pb()
        })
    };
    // media/a is busy for 3 s with a turn that waits for a slow server.
    let addr = slow_server(Duration::from_secs(3));
    let node = p.node.clone();
    let busy = http("post", &format!("url=http://{addr}/sink"), "");
    let first = p.rt.spawn(async move {
        wait_turn(
            node.ingress(ActorRef::parse("media/a").unwrap(), busy, None)
                .unwrap(),
        )
        .await
        .unwrap()
    });
    std::thread::sleep(Duration::from_millis(200));
    // An upload as the gateway takes it, and a lease nobody renews.
    let upload = store.leases().take("upload");
    upload.keep_alive(p.node.env());
    let kept = write(upload.clone(), 3);
    let stale = store.leases().take("stale");
    let gone = write(stale.clone(), 4);
    // Its turn waits behind the busy one.
    let mut input = http("sum", "", "");
    input.body = Some(pb::Body {
        value: Some(pb::body::Value::Blob(kept.clone())),
    });
    let node = p.node.clone();
    let second = p.rt.spawn(async move {
        wait_turn(
            node.ingress(ActorRef::parse("media/a").unwrap(), input, None)
                .unwrap(),
        )
        .await
        .unwrap()
    });
    std::thread::sleep(Duration::from_millis(1500));
    for _ in 0..2 {
        p.gc(SweepOptions {
            immediate: true,
            ..Default::default()
        });
    }
    assert!(p.exists(&kept), "the kept-alive upload was collected");
    assert!(!p.exists(&gone), "a lease past its TTL kept its blob");
    drop(stale);
    assert!(p.rt.block_on(first).unwrap().committed());
    let r = p.rt.block_on(second).unwrap();
    assert!(r.committed(), "{r:?}");
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => {
                        assert!(String::from_utf8_lossy(b).starts_with("200000 "), "{b:?}");
                    }
                    other => panic!("{other:?}"),
                },
                other => panic!("{other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
    drop(upload);
}

/// An erased blob's index row stays while the shipper's record says its
/// object is still in the bucket (privacy status ties the object to its
/// subject through the row), and goes once the shipper has deleted it.
#[test]
fn an_erased_row_stays_while_its_object_is_shipped() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let blob = p.blob_turn(40_000, "");
    // Stand-ins for an erasure (B15) and a shipped object (ADR 0122).
    p.node
        .store()
        .db()
        .conn()
        .execute("UPDATE blobs SET erased = 1 WHERE hash = ?1", [&blob.hash])
        .unwrap();
    let id = kronik_blob::BlobId::parse(&blob.hash).unwrap();
    let shipped = rusqlite::Connection::open(dir.path().join("ship-blobs.db")).unwrap();
    shipped
        .execute_batch(
            "CREATE TABLE shipped (name TEXT PRIMARY KEY, body_digest BLOB NOT NULL) WITHOUT ROWID;",
        )
        .unwrap();
    shipped
        .execute(
            "INSERT INTO shipped (name, body_digest) VALUES (?1, x'00')",
            [id.file_name()],
        )
        .unwrap();
    let gone = p.gc(SweepOptions {
        immediate: true,
        ..Default::default()
    });
    assert!(!p.exists(&blob), "{gone:?}");
    assert_eq!(gone.forgotten, 0);
    assert!(p.node.store().db().blob(&blob.hash).unwrap().is_some());
    shipped
        .execute("DELETE FROM shipped WHERE name = ?1", [id.file_name()])
        .unwrap();
    let after = p.gc(SweepOptions::default());
    assert_eq!(after.forgotten, 1, "{after:?}");
    assert!(p.node.store().db().blob(&blob.hash).unwrap().is_none());
}

/// The simulator's retention (`gc_floor_lag`): records more than `lag` LSNs
/// behind the applied one are below the collector's floor, as if compaction
/// had deleted them; a lag over the log, or none, leaves the floor at the
/// log's first record.
#[test]
fn a_floor_lag_moves_the_floor_behind_the_applied_record() {
    let lagged = |lag| BlobsConfig {
        gc_interval: Duration::ZERO,
        gc_floor_lag: lag,
        ..BlobsConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let p = start_blobs(dir.path(), lagged(Some(3)));
    for key in ["k1", "k2", "k3", "k4"] {
        p.blob_turn(1000, key);
    }
    let applied = p.node.applied_lsn();
    assert!(applied > 4, "{applied}");
    assert_eq!(p.node.blob_floor().unwrap(), applied + 1 - 3);
    drop(p);

    for lag in [None, Some(1_000_000)] {
        let dir = tempfile::tempdir().unwrap();
        let p = start_blobs(dir.path(), lagged(lag));
        p.blob_turn(1000, "k1");
        assert_eq!(p.node.blob_floor().unwrap(), 1, "lag {lag:?}");
    }
}
