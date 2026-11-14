//! Shipping and restoring blobs (ADR 0122, M25 slice B12) against a local
//! directory bucket, and against S3 when `KRONIK_TEST_S3_URL` is set
//! (scripts/minio.sh runs a MinIO container for it): blobs go up before what
//! references them, a multipart upload for a blob above 8 MiB; a round
//! stopped at any step never leaves a segment or snapshot in the bucket whose
//! blobs are not there; blobs the collector deleted leave the bucket after the
//! references; a restore downloads and checks the blobs, and refuses one that
//! is missing unless allowed. The bucket is read through `Remote` only, so the
//! same checks run on both.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_blob::{BlobId, Space, SweepOptions};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, Ingress, Node, NodeConfig, start_local};
use kronik_ship::{
    KeystoreMode, Remote, RestoreOptions, ShipError, ShipState, restore_with_options, ship_once,
    ship_once_with_fault,
};
use tokio::runtime::Runtime;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

struct Proc {
    rt: Runtime,
    node: Arc<Node>,
}

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

fn start(dir: &Path) -> Proc {
    let rt = rt();
    let node = rt.block_on(async {
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.history = Duration::ZERO;
        storage.snapshots_kept = 1;
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig {
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                ingress_ttl: Duration::from_secs(3600),
                blobs: Some(BlobsConfig {
                    gc_interval: Duration::ZERO,
                    ..BlobsConfig::default()
                }),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    Proc { rt, node }
}

impl Proc {
    fn deploy(&self) {
        self.rt
            .block_on(self.node.deploy(
                &std::fs::read(MEDIA).unwrap(),
                audit(),
                false,
                self.node.local_operator_authority().unwrap(),
            ))
            .unwrap();
    }

    fn ingress(&self, op: &str, query: &str, key: &str) -> pb::Outcome {
        self.ingress_with(
            op,
            query,
            key,
            pb::body::Value::Inline(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(Vec::new())),
            }),
        )
    }

    fn ingress_with(&self, op: &str, query: &str, key: &str, body: pb::body::Value) -> pb::Outcome {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: format!("/media/a/{op}"),
            query: query.into(),
            body: Some(pb::Body { value: Some(body) }),
            idempotency_key: key.into(),
            request_hash: if key.is_empty() { vec![] } else { vec![7; 32] },
            ..Default::default()
        };
        self.rt.block_on(async {
            let r = match self
                .node
                .ingress(ActorRef::parse("media/a").unwrap(), input, None)
                .unwrap()
            {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            };
            assert!(r.committed(), "{r:?}");
            r.outcome
        })
    }

    /// A turn whose response is a new blob of `size` bytes.
    fn blob(&self, size: u64, key: &str) -> pb::BlobRef {
        let outcome = self.ingress("write", &format!("size={size}&chunk=1048576"), key);
        match outcome.output {
            Some(pb::outcome::Output::Http(h)) => match h.body.and_then(|b| b.value) {
                Some(pb::body::Value::Blob(b)) => b,
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }

    /// A blob of `size` bytes written into the store as the gateway writes
    /// an upload, and a turn whose input body it is: its record references
    /// it.
    fn upload(&self, size: usize) -> pb::BlobRef {
        let store = self.node.blob_store().unwrap().clone();
        let blob = self.rt.block_on(async move {
            let mut w = store
                .writer(Space::Main, None, u64::MAX, store.leases().take("upload"))
                .await
                .unwrap();
            let chunk: Vec<u8> = (0..1u32 << 20).map(|i| (i % 253) as u8).collect();
            let mut left = size;
            while left > 0 {
                let n = left.min(chunk.len());
                w.write(&chunk[..n]).await.unwrap();
                left -= n;
            }
            let meta = w.finish().await.unwrap();
            store
                .ensure_durable(&Space::Main, &[meta.id])
                .await
                .unwrap();
            meta.to_pb()
        });
        self.ingress_with("info", "", "", pb::body::Value::Blob(blob.clone()));
        blob
    }

    fn traffic(&self, turns: usize) {
        for i in 0..turns {
            self.ingress("info", &format!("n={i}"), "");
        }
    }

    fn snapshot(&self) {
        self.rt
            .block_on(
                self.node
                    .snapshot("manual", self.node.local_operator_authority().unwrap()),
            )
            .unwrap();
    }

    /// A snapshot that a later turn makes the window's base, and a
    /// retention pass.
    fn compact(&self) {
        self.snapshot();
        let hwm = self.node.store().db().time_hwm().unwrap();
        while self.node.store().db().time_hwm().unwrap() <= hwm {
            std::thread::sleep(Duration::from_millis(2));
            self.traffic(1);
        }
        self.node
            .compact(self.node.storage_config().unwrap())
            .unwrap();
    }

    fn ship(&self, remote: &Remote, dir: &Path) -> Result<kronik_ship::ShipReport, ShipError> {
        let mut st = ShipState::load(dir).unwrap();
        self.rt.block_on(ship_once(remote, dir, "main", &mut st))
    }
}

fn object(hash: &str) -> String {
    let id = BlobId::parse(hash).unwrap();
    format!("blobs/{}/{}", id.shard(), id.file_name())
}

/// The blob objects in the bucket.
fn bucket_blobs(rt: &Runtime, remote: &Remote) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    rt.block_on(remote.list_each("blobs", |name| {
        if let Some(id) = name.rsplit('/').next().and_then(BlobId::from_file_name) {
            out.insert(id.to_string());
        }
        Ok(())
    }))
    .unwrap();
    out
}

/// Every blob that a segment or a complete snapshot in the bucket
/// references is in the bucket (ADR 0122 §3).
fn assert_references_complete(rt: &Runtime, remote: &Remote) {
    let have = bucket_blobs(rt, remote);
    let mut wanted = BTreeSet::new();
    let (segments, _) = rt.block_on(remote.list("main/segments")).unwrap();
    for name in segments {
        let start: u64 = name
            .strip_suffix(".seg.zst")
            .and_then(|s| s.parse().ok())
            .unwrap();
        let z = rt
            .block_on(remote.get(&format!("main/segments/{name}")))
            .unwrap();
        let bytes = zstd::decode_all(z.as_slice()).unwrap();
        kronik_log::scan_segment_image(&bytes, "main", start, 0, u64::MAX, true, |c| {
            for r in kronik_proto::blobs::refs(&c.record) {
                wanted.insert(r.hash.clone());
            }
            Ok::<_, kronik_log::LogError>(())
        })
        .unwrap();
    }
    let (_, snapshots) = rt.block_on(remote.list("main/snapshots")).unwrap();
    for lsn in snapshots {
        let base = format!("main/snapshots/{lsn}");
        if rt
            .block_on(remote.get(&format!("{base}/manifest.json")))
            .is_err()
        {
            continue;
        }
        if let Ok(z) = rt.block_on(remote.get(&format!("{base}/blobs.idx.zst"))) {
            let text = String::from_utf8(zstd::decode_all(z.as_slice()).unwrap()).unwrap();
            wanted.extend(text.lines().map(str::to_owned));
        }
    }
    let missing: Vec<&String> = wanted.difference(&have).collect();
    assert!(missing.is_empty(), "the bucket lacks {missing:?}");
}

/// Ships a node with blobs, stops rounds at every step, collects, restores.
fn ship_and_restore_blobs(remote: &Remote) {
    let src = tempdir("blob-ship-src-");
    let p = start(src.path());
    p.deploy();
    // An upload above 8 MiB (a multipart upload), a blob a saved response
    // keeps, and one a turn wrote and did not answer with.
    let big = p.upload((9 << 20) + 123);
    let saved = p.blob(100_000, "k1");
    p.ingress("write-discard", "size=5000", "");
    p.snapshot();

    // A round stopped after each step leaves the bucket's references
    // complete; the next round finishes the work.
    for stop in 1..=12usize {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let fault = |_: &str| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == stop {
                Err(std::io::Error::other("stopped"))
            } else {
                Ok(())
            }
        };
        let mut st = ShipState::load(src.path()).unwrap();
        let _ = p.rt.block_on(ship_once_with_fault(
            remote,
            src.path(),
            "main",
            &mut st,
            &fault,
        ));
        assert_references_complete(&p.rt, remote);
    }
    p.ship(remote, src.path()).unwrap();
    assert_references_complete(&p.rt, remote);
    let shipped = bucket_blobs(&p.rt, remote);
    assert!(shipped.contains(&big.hash) && shipped.contains(&saved.hash));
    let recorded = kronik_ship::shipped_blob_names(src.path()).unwrap();
    for hash in [&big.hash, &saved.hash] {
        assert!(recorded.contains(&BlobId::parse(hash).unwrap().file_name()));
    }
    // The bucket's objects are the files as stored.
    let local = p
        .node
        .blob_store()
        .unwrap()
        .object_path(&Space::Main, &BlobId::parse(&big.hash).unwrap());
    assert_eq!(
        p.rt.block_on(remote.get(&object(&big.hash))).unwrap(),
        std::fs::read(&local).unwrap()
    );
    // Nothing new, nothing shipped.
    assert_eq!(p.ship(remote, src.path()).unwrap().objects, 0);

    // A referenced blob whose file the node has lost does not stop the
    // backup: its reference ships without it and the blob is recorded
    // (ADR 0122, amended 2026-11-14); later records keep shipping. Once the
    // file is back, the next round that ships a reference uploads it.
    let gone = p.blob(70_000, "");
    let gone_id = BlobId::parse(&gone.hash).unwrap();
    let file = p
        .node
        .blob_store()
        .unwrap()
        .object_path(&Space::Main, &gone_id);
    let kept_bytes = std::fs::read(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    p.ship(remote, src.path()).unwrap();
    let later = p.blob(1_000, "");
    p.ship(remote, src.path()).unwrap();
    let have = bucket_blobs(&p.rt, remote);
    assert!(!have.contains(&gone.hash) && have.contains(&later.hash));
    assert_eq!(
        kronik_ship::missing_blob_names(src.path()).unwrap(),
        BTreeSet::from([gone_id.file_name()])
    );
    std::fs::write(&file, kept_bytes).unwrap();
    p.ingress_with("info", "", "", pb::body::Value::Blob(gone.clone()));
    p.ship(remote, src.path()).unwrap();
    assert!(bucket_blobs(&p.rt, remote).contains(&gone.hash));
    assert!(
        kronik_ship::missing_blob_names(src.path())
            .unwrap()
            .is_empty()
    );
    assert_references_complete(&p.rt, remote);

    // Compaction and the collector delete the response blobs locally; the
    // next round deletes their objects after the references; the saved
    // response's stays.
    p.traffic(80);
    p.compact();
    p.rt.block_on(p.node.blob_gc(SweepOptions {
        immediate: true,
        ..Default::default()
    }))
    .unwrap();
    assert!(!local.exists());
    p.ship(remote, src.path()).unwrap();
    assert_references_complete(&p.rt, remote);
    let after = bucket_blobs(&p.rt, remote);
    assert!(!after.contains(&big.hash), "{after:?}");
    assert!(after.contains(&saved.hash), "{after:?}");
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    let applied = p.node.applied_lsn();
    drop(p);

    // A restore downloads the saved response's blob, checks it, and the
    // restored node reads it.
    let restore_into = |allow: bool| {
        let dst = tempdir("blob-ship-dst-");
        std::fs::create_dir_all(dst.path().join("keys")).unwrap();
        std::fs::write(dst.path().join("keys/master.key"), &key).unwrap();
        let rt = rt();
        let r = rt.block_on(restore_with_options(
            remote,
            dst.path(),
            "main",
            false,
            &Env::real(rt.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
            RestoreOptions {
                allow_missing_blobs: allow,
            },
        ));
        (dst, r)
    };
    let (dst, r) = restore_into(false);
    let r = r.unwrap();
    assert_eq!(r.blobs.restored, 1, "{r:?}");
    assert!(r.blobs.missing.is_empty());
    let q = start(dst.path());
    assert_eq!(q.node.applied_lsn(), applied);
    let i =
        q.rt.block_on(q.node.blob_inspect(&saved.hash, true))
            .unwrap();
    assert_eq!(i.verified, Some(Ok(())), "{i:?}");
    drop(q);
    drop(dst);

    // Without the object, the restore fails before anything is installed;
    // with --allow-missing-blobs it installs and lists it.
    rt().block_on(remote.delete_object(&object(&saved.hash)))
        .unwrap();
    let (dst, r) = restore_into(false);
    let err = r.unwrap_err();
    assert!(matches!(err, ShipError::BlobMissing(_)), "{err}");
    assert!(!dst.path().join("branches/main/state.db").exists());
    drop(dst);
    let (_dst, r) = restore_into(true);
    let r = r.unwrap();
    assert_eq!(r.blobs.missing, std::slice::from_ref(&saved.hash), "{r:?}");
}

#[test]
fn ship_and_restore_blobs_from_a_directory_bucket() {
    let bucket = tempdir("blob-ship-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    ship_and_restore_blobs(&remote);
}

#[test]
fn ship_and_restore_blobs_from_s3() {
    let Ok(url) = std::env::var("KRONIK_TEST_S3_URL") else {
        eprintln!("KRONIK_TEST_S3_URL is not set; run scripts/minio.sh for this test");
        return;
    };
    // A prefix of its own: other tests share the bucket and its prefix.
    let url = format!("{}/blobs-{}", url.trim_end_matches('/'), std::process::id());
    let endpoint = std::env::var("KRONIK_TEST_S3_ENDPOINT").ok();
    let remote = Remote::open(&url, endpoint.as_deref()).unwrap();
    ship_and_restore_blobs(&remote);
}

/// An erased subject's blob is never uploaded, even while its file is
/// still there (ADR 0122, amended 2026-11-14).
#[test]
fn an_erased_blob_is_not_uploaded() {
    let src = tempdir("blob-erased-src-");
    let bucket = tempdir("blob-erased-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy();
    let blob = p.blob(5_000, "");
    p.node
        .store()
        .db()
        .conn()
        .execute("UPDATE blobs SET erased = 1 WHERE hash = ?1", [&blob.hash])
        .unwrap();
    p.ship(&remote, src.path()).unwrap();
    assert!(!bucket_blobs(&p.rt, &remote).contains(&blob.hash));
}

/// A crash after a blob's object was deleted and before its record went:
/// the record is marked, so a record that references the same blob again
/// before the next deletion step has it uploaded again.
#[test]
fn a_deletion_cut_short_never_skips_an_upload() {
    let src = tempdir("blob-deleted-src-");
    let bucket = tempdir("blob-deleted-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy();
    let blob = p.upload(3_000);
    p.ship(&remote, src.path()).unwrap();
    assert!(bucket_blobs(&p.rt, &remote).contains(&blob.hash));
    // Its records leave retention and the collector deletes it.
    p.traffic(80);
    p.compact();
    for _ in 0..2 {
        p.rt.block_on(p.node.blob_gc(SweepOptions {
            immediate: true,
            ..Default::default()
        }))
        .unwrap();
    }
    // The deletion step stops after deleting the object.
    let fault = |step: &str| {
        if step == "blob-deleted" {
            Err(std::io::Error::other("stopped"))
        } else {
            Ok(())
        }
    };
    let mut st = ShipState::load(src.path()).unwrap();
    let _ = p.rt.block_on(ship_once_with_fault(
        &remote,
        src.path(),
        "main",
        &mut st,
        &fault,
    ));
    assert!(!bucket_blobs(&p.rt, &remote).contains(&blob.hash));
    // The same bytes again, and a record that references them.
    let again = p.upload(3_000);
    assert_eq!(again.hash, blob.hash);
    p.ship(&remote, src.path()).unwrap();
    assert!(bucket_blobs(&p.rt, &remote).contains(&blob.hash));
    assert_references_complete(&p.rt, &remote);
}

/// A node restored from `remote` into a new directory, started; the
/// source's master key in place.
fn restored(remote: &Remote, key: &[u8]) -> (tempfile::TempDir, Proc) {
    let dst = tempdir("blob-restored-");
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::write(dst.path().join("keys/master.key"), key).unwrap();
    {
        let rt = rt();
        rt.block_on(restore_with_options(
            remote,
            dst.path(),
            "main",
            false,
            &Env::real(rt.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
            RestoreOptions::default(),
        ))
        .unwrap();
    }
    let q = start(dst.path());
    (dst, q)
}

/// A source node with a saved response's blob shipped in plain bytes;
/// its bucket, the blob and the master key.
fn shipped_plain_blob() -> (tempfile::TempDir, Remote, pb::BlobRef, Vec<u8>) {
    let src = tempdir("blob-plain-src-");
    let bucket = tempdir("blob-plain-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy();
    let blob = p.blob(70_000, "k1");
    p.snapshot();
    p.ship(&remote, src.path()).unwrap();
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(p);
    (bucket, remote, blob, key)
}

/// A stand-in for a local file whose bytes changed since its object was
/// shipped (M26's `privacy reseal` seals a file in place): its header's
/// body digest differs; the frames are kept, which the shipper does not
/// read. Returns the file's new bytes.
fn changed_stand_in(file: &Path) -> Vec<u8> {
    use kronik_blob::format::{HEADER_LEN, Header};
    let mut bytes = std::fs::read(file).unwrap();
    let mut header = Header::decode(&bytes[..HEADER_LEN]).unwrap();
    header.body_digest = *blake3::hash(&header.body_digest).as_bytes();
    bytes[..HEADER_LEN].copy_from_slice(&header.encode());
    std::fs::write(file, &bytes).unwrap();
    bytes
}

/// Review H-1: a restored node starts without ship-blobs.db, while its
/// bucket holds the source's objects. It takes a bucket's object as its own
/// only when the object's header has the local file's body digest; an
/// object of a file that changed since is replaced when a record references
/// it.
#[test]
fn a_restored_node_adopts_only_an_object_with_its_digest() {
    let (_bucket, remote, blob, key) = shipped_plain_blob();
    let (dst, q) = restored(&remote, &key);
    let id = BlobId::parse(&blob.hash).unwrap();
    let file = q.node.blob_store().unwrap().object_path(&Space::Main, &id);
    let sealed = changed_stand_in(&file);
    q.snapshot();
    q.ship(&remote, dst.path()).unwrap();
    let object = q.rt.block_on(remote.get(&object(&blob.hash))).unwrap();
    assert!(
        object == sealed,
        "the bucket does not have the changed object"
    );
}

/// A blob `privacy reseal` sealed in place (M26 §9.4) is marked in
/// `<data>/blobs/reupload`: the next round uploads the sealed file over the
/// bucket's plain object and removes the mark. A file still plain keeps its
/// mark; a mark whose file is gone, or whose blob was never shipped, goes
/// without an upload.
#[test]
fn a_resealed_blob_replaces_its_plain_object() {
    let src = tempdir("blob-reseal-src-");
    let bucket = tempdir("blob-reseal-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path());
    p.deploy();
    let shipped = p.blob(70_000, "k1");
    p.ship(&remote, src.path()).unwrap();
    let id = BlobId::parse(&shipped.hash).unwrap();
    let file = p.node.blob_store().unwrap().object_path(&Space::Main, &id);
    let marks = kronik_store::ship_blobs::reupload_dir(src.path());
    std::fs::create_dir_all(&marks).unwrap();
    let mark = |name: &str| marks.join(name);
    // Still plain: the mark stays, nothing is uploaded.
    std::fs::write(mark(&id.file_name()), b"").unwrap();
    assert_eq!(p.ship(&remote, src.path()).unwrap().objects, 0);
    assert!(mark(&id.file_name()).exists());
    // Sealed in place.
    let bytes = seal_stand_in(&file);
    // A mark whose file is gone, and one of a blob never shipped.
    let gone = "b3-".to_owned() + &"0".repeat(64);
    std::fs::write(mark(&gone), b"").unwrap();
    let local_only = p.upload(1000);
    let local_id = BlobId::parse(&local_only.hash).unwrap();
    seal_stand_in(
        &p.node
            .blob_store()
            .unwrap()
            .object_path(&Space::Main, &local_id),
    );
    std::fs::write(mark(&local_id.file_name()), b"").unwrap();
    let report = p.ship(&remote, src.path()).unwrap();
    assert!(report.objects >= 2, "{report:?}");
    let object = p.rt.block_on(remote.get(&object(&shipped.hash))).unwrap();
    assert!(
        object == bytes,
        "the bucket does not have the sealed object"
    );
    assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0);
    // Recorded with their new digests: nothing to upload again.
    assert_eq!(p.ship(&remote, src.path()).unwrap().objects, 0);
}

/// A stand-in for `privacy reseal` sealing a file in place: its header says
/// sealed, of subject `user:1` at key version 1, with another body digest;
/// the frames are kept, which the shipper does not read. Returns the file's new bytes.
fn seal_stand_in(file: &Path) -> Vec<u8> {
    use kronik_blob::format::{HEADER_LEN, Header};
    let mut bytes = std::fs::read(file).unwrap();
    let mut header = Header::decode(&bytes[..HEADER_LEN]).unwrap();
    header.sealed = true;
    header.subject = Some("user:1".into());
    header.key_version = 1;
    // Sealed frames have another body digest.
    header.body_digest = *blake3::hash(&header.body_digest).as_bytes();
    bytes[..HEADER_LEN].copy_from_slice(&header.encode());
    std::fs::write(file, &bytes).unwrap();
    bytes
}

/// Review H-1: a restored node starts without ship-blobs.db while its
/// bucket holds the plain objects. A blob it reseals (marked) is uploaded
/// over its plain object, although nothing records it as shipped.
#[test]
fn a_restored_node_replaces_a_plain_object_it_resealed() {
    let (_bucket, remote, blob, key) = shipped_plain_blob();
    let (dst, q) = restored(&remote, &key);
    let id = BlobId::parse(&blob.hash).unwrap();
    let file = q.node.blob_store().unwrap().object_path(&Space::Main, &id);
    let sealed = seal_stand_in(&file);
    let marks = kronik_store::ship_blobs::reupload_dir(dst.path());
    std::fs::create_dir_all(&marks).unwrap();
    std::fs::write(marks.join(id.file_name()), b"").unwrap();
    q.ship(&remote, dst.path()).unwrap();
    let object = q.rt.block_on(remote.get(&object(&blob.hash))).unwrap();
    assert!(
        object == sealed,
        "the bucket does not have the sealed object"
    );
    assert_eq!(std::fs::read_dir(&marks).unwrap().count(), 0);
}
