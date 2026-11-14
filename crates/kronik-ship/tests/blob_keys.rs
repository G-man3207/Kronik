//! M26 slice B15, the restore's key check for blobs (docs/design/m26-blobs.md
//! §9.6): every (subject, key version) that a restored blob reference names
//! must have its key in the installed keystore backup, or the subject must be
//! erased through that version; otherwise the restore fails with
//! `KEYSTORE_INCOMPLETE` before anything is installed. Privacy mode is off,
//! so the subject's blob is keyed but nothing is sealed: the blob is the only
//! thing that needs the key.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{BlobsConfig, Ingress, Node, NodeConfig, start_local};
use kronik_ship::{
    KeystoreMode, Remote, RestoreOptions, ShipError, ShipState, restore_with_options,
    ship_keystore, ship_once,
};
use tokio::runtime::Runtime;

const MEDIA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/media.wasm");

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

fn start(rt: &Runtime, dir: &Path) -> Arc<Node> {
    rt.block_on(async {
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.history = Duration::ZERO;
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig {
                storage: Some(storage),
                blobs: Some(BlobsConfig {
                    gc_interval: Duration::ZERO,
                    ..BlobsConfig::default()
                }),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    })
}

/// A subject's blob of `size` bytes: the response of a request of `subject`.
fn subject_blob(rt: &Runtime, node: &Node, subject: &str) -> pb::BlobRef {
    let input = pb::HttpInput {
        method: "POST".into(),
        path: "/media/a/write".into(),
        query: "size=100000&chunk=65536".into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(pb::Sealable {
                subject: Some(subject.into()),
                value: Some(pb::sealable::Value::Plain(Vec::new())),
            })),
        }),
        ..Default::default()
    };
    let r = rt.block_on(async {
        match node
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
    match r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => match h.body.and_then(|b| b.value) {
            Some(pb::body::Value::Blob(b)) => b,
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

/// §9.6: with the bucket's keystore backups, the subject's blob restores;
/// without them, the key its reference names is nowhere, and the restore
/// fails with `KEYSTORE_INCOMPLETE` naming the subject and installs nothing,
/// unless missing keys are allowed.
#[test]
fn a_restored_blob_reference_needs_its_subjects_key() {
    let src = tempdir("blob-keys-src-");
    let bucket = tempdir("blob-keys-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let rt = rt();
    let node = start(&rt, src.path());
    rt.block_on(node.deploy(
        &std::fs::read(MEDIA).unwrap(),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    let blob = subject_blob(&rt, &node, "user:1");
    assert!(blob.hash.starts_with("b3s:"), "{blob:?}");
    rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
    let mut state = ShipState::load(src.path()).unwrap();
    rt.block_on(ship_once(&remote, src.path(), "main", &mut state))
        .unwrap();
    // The keystore backup, with the subject's key the blob was keyed with.
    rt.block_on(ship_keystore(
        &Env::real(rt.handle().clone()),
        &remote,
        src.path(),
        &mut state,
        1_700_000_000_000,
        Duration::from_secs(30 * 86_400),
        [7; 24],
        node.key_source().unwrap(),
        node.sealer().keystore().unwrap(),
    ))
    .unwrap();
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(node);

    let restore_into = |mode: KeystoreMode| {
        let dst = tempdir("blob-keys-dst-");
        std::fs::create_dir_all(dst.path().join("keys")).unwrap();
        std::fs::write(dst.path().join("keys/master.key"), &key).unwrap();
        let restorer = crate::rt();
        let r = restorer.block_on(restore_with_options(
            &remote,
            dst.path(),
            "main",
            false,
            &Env::real(restorer.handle().clone()),
            &Default::default(),
            mode,
            RestoreOptions::default(),
        ));
        (dst, r)
    };
    let (dst, r) = restore_into(KeystoreMode::Require);
    let r = r.unwrap();
    assert!(r.blobs.missing.is_empty(), "{r:?}");
    drop(dst);

    // The bucket loses its keystore backups.
    let (names, _) = rt.block_on(remote.list("keystore")).unwrap();
    assert!(!names.is_empty(), "no keystore backup was shipped");
    for n in names {
        rt.block_on(remote.delete_object(&format!("keystore/{n}")))
            .unwrap();
    }
    let (dst, r) = restore_into(KeystoreMode::Require);
    let err = r.unwrap_err();
    assert!(
        matches!(&err, ShipError::KeystoreIncomplete(why) if why.contains("user:1")),
        "{err}"
    );
    assert!(!dst.path().join("branches/main/state.db").exists());
    drop(dst);
    let (_dst, r) = restore_into(KeystoreMode::AllowMissingKeys);
    r.unwrap();
}
