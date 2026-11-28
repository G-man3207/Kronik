//! M26 slice B15: erasing a subject erases its blobs (docs/design/m26-blobs.md
//! §9.3, criterion 12). Applying the `Erasure` record marks the subject's
//! rows of the blob index erased, and the node deletes their files at once,
//! in main's store and in every fork space; another subject's blob stays.
//! The erasure is pending while the shipper still has one of its objects.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Proc, audit, http_blob, http_text, start_proc, wait_turn};
use kronik_blob::{BlobId, BlobStore, Space, StoreConfig};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, NodeConfig, TurnResult};

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

fn start(dir: &Path) -> Proc {
    start_in(dir, pb::PrivacyState::On)
}

fn start_in(dir: &Path, mode: pb::PrivacyState) -> Proc {
    let p = start_proc(
        dir,
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    p.deploy_file(MEDIA);
    if mode == pb::PrivacyState::On {
        p.rt.block_on(p.node.set_privacy_mode(mode, audit(), false, p.owner()))
            .unwrap();
    }
    p
}

/// The header of a blob file: whether it is sealed.
fn sealed(path: &Path) -> bool {
    let bytes = std::fs::read(path).unwrap();
    kronik_blob::format::Header::decode(&bytes[..kronik_blob::format::HEADER_LEN])
        .unwrap()
        .sealed
}

impl Proc {
    /// A request of `subject` to the media guest's `op`.
    fn run(&self, op: &str, query: &str, subject: &str) -> TurnResult {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: format!("/media/a/{op}"),
            query: query.into(),
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable::new_plain(
                    Some(subject.into()),
                    Vec::new(),
                ))),
            }),
            ..Default::default()
        };
        self.rt.block_on(async {
            wait_turn(
                self.node
                    .ingress(
                        ActorRef::parse("media/a").unwrap(),
                        input,
                        Some(subject.into()),
                    )
                    .unwrap(),
            )
            .await
            .unwrap()
        })
    }

    /// A blob the media guest writes as the response of a request of
    /// `subject`: the default subject of its turn, so the blob's.
    fn write(&self, subject: &str) -> pb::BlobRef {
        let r = self.run("write", "size=200000&chunk=65536", subject);
        assert!(r.committed(), "{r:?}");
        http_blob(&r)
    }

    fn path(&self, dir: &Path, space: &Space, blob: &pb::BlobRef) -> PathBuf {
        self.rt.block_on(async {
            let store = BlobStore::open(
                Env::real(tokio::runtime::Handle::current()),
                dir,
                StoreConfig::default(),
            )
            .await
            .unwrap();
            store.object_path(space, &BlobId::parse(&blob.hash).unwrap())
        })
    }
}

/// Criterion 12: `erase` of a subject makes its blobs unreadable. Their index
/// rows are erased and their files are gone, from main's store and from a
/// fork's space, before `erase` returns, which counts them; another
/// subject's blob is untouched.
#[test]
fn erasing_a_subject_deletes_its_blobs_files_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let one = p.write("user:1");
    let two = p.write("user:2");
    assert!(one.hash.starts_with("b3s:"), "{one:?}");
    assert_eq!(one.subject.as_deref(), Some("user:1"));
    let main_one = p.path(dir.path(), &Space::Main, &one);
    let main_two = p.path(dir.path(), &Space::Main, &two);
    assert!(main_one.exists() && main_two.exists());
    // A fork's copy of the blob in its own space, which the collector never
    // sweeps.
    let fork = Space::Fork("f-test".into());
    let fork_one = p.path(dir.path(), &fork, &one);
    std::fs::create_dir_all(fork_one.parent().unwrap()).unwrap();
    std::fs::copy(&main_one, &fork_one).unwrap();

    // The shipper's record: both blobs are in the bucket.
    let shipped = rusqlite::Connection::open(dir.path().join("ship-blobs.db")).unwrap();
    shipped
        .execute_batch("CREATE TABLE shipped (name TEXT PRIMARY KEY, body_digest BLOB);")
        .unwrap();
    let name = |b: &pb::BlobRef| BlobId::parse(&b.hash).unwrap().file_name();
    for b in [&one, &two] {
        shipped
            .execute(
                "INSERT INTO shipped (name, body_digest) VALUES (?1, x'00')",
                [name(b)],
            )
            .unwrap();
    }

    let row = |hash: &str| p.node.store().db().blob(hash).unwrap().unwrap();
    assert!(!row(&one.hash).erased);
    let owner = p.node.local_operator_authority().unwrap();
    let done =
        p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
            .unwrap();
    assert_eq!(done.blobs, 2, "main's file and the fork's");
    assert!(row(&one.hash).erased, "the index row is erased");
    assert!(!main_one.exists(), "main's file is gone");
    assert!(!fork_one.exists(), "the fork's file is gone");
    assert!(!row(&two.hash).erased);
    assert!(main_two.exists(), "another subject's blob stays");

    // Its object is still in the bucket: the erasure is pending until the
    // shipper's next round deletes it (only user:2's object is left then).
    assert_eq!(done.pending_blob_objects, 1);
    let pending = || p.rt.block_on(p.node.pending_erasures()).unwrap();
    assert_eq!(pending(), 1);
    shipped
        .execute("DELETE FROM shipped WHERE name = ?1", [name(&one)])
        .unwrap();
    // And the collector has had its pass after the erasure (its loose files).
    p.rt.block_on(p.node.blob_gc(kronik_blob::SweepOptions::default()))
        .unwrap();
    assert_eq!(pending(), 0);
}

/// M26 §9.4: a subject's blob written while the mode was `off` is a plain
/// file (keyed, `b3s:`). `privacy reseal` with the mode on seals it in place:
/// the same name, readable with the subject's key, and marked for the
/// shipper to replace its object in the bucket. A second reseal finds
/// nothing to do.
#[test]
fn reseal_seals_a_subjects_plain_blob_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_in(dir.path(), pb::PrivacyState::Off);
    let blob = p.write("user:1");
    assert!(blob.hash.starts_with("b3s:"), "{blob:?}");
    let file = p.path(dir.path(), &Space::Main, &blob);
    assert!(!sealed(&file), "written in mode off");
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, owner.clone()),
    )
    .unwrap();
    let dry =
        p.rt.block_on(p.node.reseal(audit(), true, owner.clone()))
            .unwrap();
    assert_eq!(dry.blobs_sealed, 1);
    assert!(!sealed(&file), "a dry run writes nothing");
    let done =
        p.rt.block_on(p.node.reseal(audit(), false, owner.clone()))
            .unwrap();
    assert_eq!(done.blobs_sealed, 1, "{done:?}");
    assert!(sealed(&file), "sealed in place");
    let inspected =
        p.rt.block_on(p.node.blob_inspect(&blob.hash, true))
            .unwrap();
    assert_eq!(inspected.verified, Some(Ok(())), "{inspected:?}");
    let mark = dir
        .path()
        .join("blobs/reupload")
        .join(BlobId::parse(&blob.hash).unwrap().file_name());
    assert!(mark.exists(), "marked for the shipper");
    let progress = p.rt.block_on(p.node.reseal_progress());
    assert_eq!((progress.blobs_sealed, progress.pending_blobs), (1, 1));
    let again = p.rt.block_on(p.node.reseal(audit(), false, owner)).unwrap();
    assert_eq!(again.blobs_sealed, 0);
}

/// An HTTP peer on an OS thread of its own that answers each request only
/// once `release` gets a message; `arrived` gets one when a request is in.
#[allow(clippy::disallowed_methods)]
fn gated_server() -> (
    String,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    use std::io::{BufRead as _, BufReader, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (arrived_tx, arrived) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
                line.clear();
            }
            let _ = arrived_tx.send(());
            let _ = release_rx.recv();
            let mut stream = stream;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    (addr, arrived, release)
}

/// m8-privacy §6.8 for blobs: a turn that runs across its subject's erasure
/// writes no blob of that subject after it. Such a blob could only be keyed
/// with a version newer than the erased ones, and may hold what the turn
/// read before the erasure. So its writer answers `erased`, no new key is
/// made, and the subject's blob index stays empty.
#[test]
fn a_turn_across_its_subjects_erasure_writes_no_blob_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.grant(
        "media",
        "http:127.0.0.1",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    let (addr, arrived, release) = gated_server();
    // `fetch-write`: the turn fetches, then writes a blob of its subject.
    let input = pb::HttpInput {
        method: "POST".into(),
        path: "/media/a/fetch-write".into(),
        query: "size=5000".into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(pb::Sealable::new_plain(
                Some("user:1".into()),
                format!("http://{addr}/doc").into_bytes(),
            ))),
        }),
        ..Default::default()
    };
    let node = p.node.clone();
    let pending = p.rt.spawn(async move {
        wait_turn(
            node.ingress(
                ActorRef::parse("media/a").unwrap(),
                input,
                Some("user:1".into()),
            )
            .unwrap(),
        )
        .await
        .unwrap()
    });
    arrived
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // The turn waits for its fetch: the subject is erased meanwhile.
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
        .unwrap();
    release.send(()).unwrap();
    let r = p.rt.block_on(pending).unwrap();
    let blobs = p.node.store().db().subject_blobs().unwrap();
    eprintln!("outcome {:?}; subject blobs {blobs:?}", r.outcome);
    assert!(blobs.is_empty(), "a blob of the erased subject: {blobs:?}");
    assert!(
        p.node
            .sealer()
            .existing_blob_keys("user:1")
            .unwrap()
            .is_none(),
        "no new key of the erased subject"
    );
    assert!(
        format!("{:?}", r.outcome).contains("erased"),
        "the writer answered erased: {:?}",
        r.outcome
    );
}

/// A blob of the subject stored before its erasure but first referenced by
/// a record applied after it (an upload whose turn came later, a turn that
/// ran across the erasure): applying that record marks it erased, and its
/// file goes then, not at the collector's next passes.
#[test]
fn a_blob_first_referenced_after_its_erasure_is_deleted_when_the_record_applies() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let store = p.node.blob_store().unwrap().clone();
    let fill = |bytes: &mut [u8]| bytes.fill(7);
    let keys = p.node.sealer().blob_keys("user:1", &fill, 0).unwrap();
    // Spooled as the gateway does, under an upload lease.
    let (blob, lease) = p.rt.block_on(async {
        let lease = store.leases().take("upload");
        let mut w = store
            .writer(Space::Main, Some(keys), u64::MAX, lease.clone())
            .await
            .unwrap();
        w.write(&[5u8; 100_000]).await.unwrap();
        let meta = w.finish().await.unwrap();
        store
            .ensure_durable(&Space::Main, &[meta.id])
            .await
            .unwrap();
        (meta.to_pb(), lease)
    });
    let file = p.path(dir.path(), &Space::Main, &blob);
    assert!(file.exists());
    let owner = p.node.local_operator_authority().unwrap();
    let done =
        p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
            .unwrap();
    assert_eq!(done.blobs, 0, "no record referenced it yet");
    assert!(file.exists());
    // Its turn: `info` answers without reading the body.
    let input = pb::HttpInput {
        method: "POST".into(),
        path: "/media/a/info".into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Blob(blob.clone())),
        }),
        ..Default::default()
    };
    let r = p.rt.block_on(async {
        wait_turn(
            p.node
                .ingress_with(
                    ActorRef::parse("media/a").unwrap(),
                    input,
                    Some("user:1".into()),
                    kronik_sched::IngressExtras {
                        upload: Some(lease),
                        ..Default::default()
                    },
                )
                .unwrap(),
        )
        .await
        .unwrap()
    });
    assert!(r.committed(), "{r:?}");
    let row = p.node.store().db().blob(&blob.hash).unwrap().unwrap();
    assert!(row.erased, "{row:?}");
    assert!(!file.exists(), "the file went when the record applied");
}

/// The files of main's store whose header names `subject`, and whether each
/// is sealed.
fn files_of(dir: &Path, subject: &str) -> Vec<bool> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if e.path().is_dir() {
                    walk(&e.path(), out);
                } else {
                    out.push(e.path());
                }
            }
        }
    }
    let mut paths = Vec::new();
    walk(&dir.join("blobs/objects"), &mut paths);
    paths
        .iter()
        .filter_map(|path| {
            let bytes = std::fs::read(path).ok()?;
            let header =
                kronik_blob::format::Header::decode(bytes.get(..kronik_blob::format::HEADER_LEN)?)
                    .ok()?;
            (header.subject.as_deref() == Some(subject)).then_some(header.sealed)
        })
        .collect()
}

/// Review of log-integrity's blob DST (ruled by the lead): a blob a turn
/// wrote and did not commit has no row of the index, so the erasure's own
/// deletion cannot find it, and with privacy mode off its bytes are plain.
/// The collector's first pass after the erasure deletes every such file of
/// the subject at once: a failed turn's, one the turn discarded, and one a
/// lease still holds (an upload whose turn has not run), which no number of
/// ordinary passes would delete.
#[test]
fn the_first_pass_after_an_erasure_deletes_the_subjects_loose_plain_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = start_in(dir.path(), pb::PrivacyState::Off);
    let failed = p.run("fail-after-write", "", "user:1");
    assert!(!failed.committed(), "{failed:?}");
    let discarded = p.run("write-discard", "size=200000", "user:1");
    assert!(discarded.committed(), "{discarded:?}");
    let store = p.node.blob_store().unwrap().clone();
    let keys = p
        .node
        .sealer()
        .blob_keys("user:1", &|bytes: &mut [u8]| bytes.fill(7), 0)
        .unwrap();
    let lease = store.leases().take("upload");
    let mut upload =
        p.rt.block_on(store.writer(Space::Main, Some(keys), u64::MAX, lease.clone()))
            .unwrap();
    p.rt.block_on(upload.write(&[5u8; 90_000])).unwrap();
    p.rt.block_on(upload.finish()).unwrap();
    assert_eq!(
        files_of(dir.path(), "user:1"),
        [false, false, false],
        "plain loose files"
    );
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
        .unwrap();
    p.rt.block_on(p.node.blob_gc(kronik_blob::SweepOptions::default()))
        .unwrap();
    assert_eq!(files_of(dir.path(), "user:1"), Vec::<bool>::new());
    assert!(
        store.leases().holders().contains(&"upload"),
        "the lease did not keep it"
    );
}

/// The erasure is pending in `privacy status` until a collector pass after
/// it is done with the subject's loose files: a writer of the subject that
/// began before the erasure and still writes may yet leave one, so it
/// holds the erasure back; once it ended, the next pass deletes its file
/// and the erasure is done. The node remembers that over a restart.
#[test]
fn an_erasure_is_pending_until_the_collector_is_done_with_its_subjects_loose_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    p.write("user:1");
    let store = p.node.blob_store().unwrap().clone();
    let keys = p
        .node
        .sealer()
        .blob_keys("user:1", &|bytes: &mut [u8]| bytes.fill(7), 0)
        .unwrap();
    let mut writer =
        p.rt.block_on(store.writer(
            Space::Main,
            Some(keys),
            u64::MAX,
            store.leases().take("test"),
        ))
        .unwrap();
    p.rt.block_on(writer.write(&[9u8; 70_000])).unwrap();
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
        .unwrap();
    let pending = || p.rt.block_on(p.node.pending_erasures()).unwrap();
    let pass = || {
        p.rt.block_on(p.node.blob_gc(kronik_blob::SweepOptions::default()))
            .unwrap()
    };
    pass();
    assert_eq!(pending(), 1, "a writer of the subject still writes");
    // It ends with a blob no record references, sealed under the erased key.
    let meta = p.rt.block_on(writer.finish()).unwrap();
    assert_eq!(meta.subject.as_deref(), Some("user:1"));
    pass();
    assert_eq!(files_of(dir.path(), "user:1"), Vec::<bool>::new());
    assert_eq!(pending(), 0);
    assert!(dir.path().join("blobs/erasures-swept").exists());
    drop(p);
    let p = start_proc(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    let pending = p.rt.block_on(p.node.pending_erasures()).unwrap();
    assert_eq!(pending, 0, "remembered over a restart");
}

/// Review of B19 (B14's quota across an erasure; ADR 0119 as amended
/// 2026-11-14, second note): an actor keeps the hashes of what it holds in
/// rows of their subject, which the erasure deletes, so it can never release
/// the subject's blobs. Their bytes are gone, and they stop counting against
/// the holder's quota: not in the holder's first turn after the erasure,
/// whose answer a replay at its place must give too, but from its next turn
/// on. The holds stay, so a read of such a blob answers `erased`, and a
/// state rebuilt from the log charges the same.
#[test]
fn an_erased_subjects_blobs_stop_counting_against_the_holders_quota() {
    let dir = tempfile::tempdir().unwrap();
    let p = start(dir.path());
    let owner = p.node.local_operator_authority().unwrap();
    p.rt.block_on(p.node.set_limits(
        pb::Limits {
            kind: "media".into(),
            blob_bytes_per_actor: Some(5 << 19),
            ..Default::default()
        },
        audit(),
        false,
        owner.clone(),
    ))
    .unwrap();
    let put = |size: u64, subject: &str| {
        let r = p.run("put", &format!("size={size}"), subject);
        assert!(r.committed(), "{r:?}");
        http_text(&r)
    };
    // user:1's two blobs, about 2 MiB of the 2.5 MiB quota.
    let first = put(1 << 20, "user:1");
    assert!(first.starts_with("blob b3s:"), "{first}");
    assert!(put(1_000_000, "user:1").starts_with("blob b3s:"));
    assert_eq!(
        put(1 << 20, "user:2"),
        "quota-exceeded",
        "the quota is nearly full"
    );
    p.rt.block_on(p.node.erase_subject("user:1", audit(), false, owner))
        .unwrap();
    // The holder's first turn after the erasure still counts them.
    assert_eq!(put(1 << 20, "user:2"), "quota-exceeded");
    // From its next turn on they count for nothing.
    assert!(
        put(1 << 20, "user:2").starts_with("blob b3s:"),
        "the erased subject's blobs still count against media/a's quota"
    );
    // The holds stay: the erased blob is still media/a's, and erased.
    let erased = first.split(' ').nth(1).unwrap();
    let db = p.node.store().db();
    assert!(db.held("media", "a", erased).unwrap().is_some());
    assert!(db.blob(erased).unwrap().unwrap().erased);
    assert!(db.erased_for_charge("media", "a", erased).unwrap());
    let charged = db.charged_bytes("media", "a").unwrap();
    assert_eq!(charged, 1 << 20, "only user:2's blob");
    drop(db);
    drop(p);
    // Rebuilt from the log: the same charge.
    let main = dir.path().join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(main.join(f));
    }
    let _ = std::fs::remove_dir_all(dir.path().join("snapshots"));
    let p = start_proc(
        dir.path(),
        NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        },
    );
    let db = p.node.store().db();
    let rebuilt = (
        db.charged_bytes("media", "a").unwrap(),
        db.erased_for_charge("media", "a", erased).unwrap(),
    );
    assert_eq!(
        rebuilt,
        (charged, true),
        "the rebuilt state charges the same"
    );
}
