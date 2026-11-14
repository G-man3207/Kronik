//! M26 slice B15: erasing a subject erases its blobs (docs/design/m26-blobs.md
//! §9.3, criterion 12). Applying the `Erasure` record marks the subject's
//! rows of the blob index erased, and the node deletes their files at once,
//! in main's store and in every fork space; another subject's blob stays.
//! The erasure is pending while the shipper still has one of its objects.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kronik_blob::{BlobId, BlobStore, Space, StoreConfig};
use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
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

fn start(dir: &Path) -> Proc {
    start_in(dir, pb::PrivacyState::On)
}

fn start_in(dir: &Path, mode: pb::PrivacyState) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            blobs: Some(BlobsConfig::default()),
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
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
    if mode == pb::PrivacyState::On {
        p.rt.block_on(p.node.set_privacy_mode(mode, audit(), false, owner))
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
    /// A blob the media guest writes as the response of a request of
    /// `subject`: the default subject of its turn, so the blob's.
    fn write(&self, subject: &str) -> pb::BlobRef {
        let input = pb::HttpInput {
            method: "POST".into(),
            path: "/media/a/write".into(),
            query: "size=200000&chunk=65536".into(),
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: Some(subject.into()),
                    value: Some(pb::sealable::Value::Plain(Vec::new())),
                })),
            }),
            ..Default::default()
        };
        let r: TurnResult = self.rt.block_on(async {
            match self
                .node
                .ingress(
                    ActorRef::parse("media/a").unwrap(),
                    input,
                    Some(subject.into()),
                )
                .unwrap()
            {
                Ingress::Started(w) | Ingress::Joined(w) => w.wait().await.unwrap(),
                Ingress::Done(r) => *r,
            }
        });
        assert!(r.committed(), "{r:?}");
        match &r.outcome.output {
            Some(pb::outcome::Output::Http(h)) => {
                match h.body.as_ref().and_then(|b| b.value.clone()) {
                    Some(pb::body::Value::Blob(blob)) => blob,
                    other => panic!("not a blob: {other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }
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
    let progress = p.node.reseal_progress();
    assert_eq!((progress.blobs_sealed, progress.pending_blobs), (1, 1));
    let again = p.rt.block_on(p.node.reseal(audit(), false, owner)).unwrap();
    assert_eq!(again.blobs_sealed, 0);
}
