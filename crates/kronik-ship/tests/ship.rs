//! Shipping and restore (docs/design/m6-storage.md §4, §6) against a local
//! directory bucket, and against S3 when `KRONIK_TEST_S3_URL` is set
//! (scripts/minio.sh runs a MinIO container for it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use kronik_ship::{KeystoreMode, Remote, ShipState, restore, ship_once};
use tokio::runtime::Runtime;

fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn msg(name: &str, body: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: vec![],
    }
}

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

fn start(dir: &Path, history: Option<Duration>) -> Proc {
    let rt = rt();
    let node = rt.block_on(async {
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.snapshots_kept = 2;
        if let Some(h) = history {
            storage.history = h;
        }
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig {
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    Proc { rt, node }
}

impl Proc {
    fn send(&self, actor: &str, name: &str, body: &str) -> String {
        let r = self
            .rt
            .block_on(self.node.send(
                ActorRef::parse(actor).unwrap(),
                msg(name, body),
                audit(),
                false,
            ))
            .unwrap()
            .unwrap();
        assert!(r.committed(), "{r:?}");
        match &r.outcome.output {
            Some(pb::outcome::Output::Reply(m)) => {
                match m.body.as_ref().and_then(|b| b.value.as_ref()) {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    _ => String::new(),
                }
            }
            _ => String::new(),
        }
    }

    fn ship(&self, remote: &Remote, dir: &Path) -> kronik_ship::ShipReport {
        let mut st = ShipState::load(dir);
        self.rt
            .block_on(ship_once(remote, dir, "main", &mut st))
            .unwrap()
    }
}

fn tempdir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// Ships a node's data, destroys it, restores into an empty directory and
/// checks the restored node has the same state and runs turns.
fn ship_and_restore(remote: &Remote) {
    let src = tempdir("ship-src-");
    let p = start(src.path(), None);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.rt.block_on(p.node.deploy(&guest("notes"), audit(), false))
        .unwrap();
    for i in 0..30 {
        p.send(&format!("counter/c{}", i % 4), "increment", "");
        p.send(&format!("notes/n{}", i % 3), "add", &format!("note {i}"));
    }
    let m = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    let first = p.ship(remote, src.path());
    assert!(first.objects > 3, "{first:?}");
    // Records after the snapshot travel in the active segment.
    for i in 0..10 {
        p.send(&format!("counter/c{}", i % 4), "increment", "");
    }
    let second = p.ship(remote, src.path());
    assert!(second.objects >= 1, "{second:?}");
    // Nothing new, nothing shipped.
    assert_eq!(p.ship(remote, src.path()).objects, 0);
    let applied = p.node.applied_lsn();
    let hash = p.node.store().state_hash().unwrap();
    // The master key is never shipped: the operator keeps it apart.
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(p);
    drop(src);

    let dst = tempdir("ship-dst-");
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::write(dst.path().join("keys/master.key"), key).unwrap();
    let rt = rt();
    let r = rt
        .block_on(restore(
            remote,
            dst.path(),
            "main",
            false,
            &dst.path().join("keys/master.key"),
            KeystoreMode::Require,
        ))
        .unwrap();
    assert_eq!(r.snapshot_lsn, m.lsn);
    assert_eq!(r.state_hash, m.state_hash);
    assert!(r.components >= 2, "{r:?}");
    // A second restore over the restored state is refused without force.
    let err = rt
        .block_on(restore(
            remote,
            dst.path(),
            "main",
            false,
            &dst.path().join("keys/master.key"),
            KeystoreMode::Require,
        ))
        .unwrap_err();
    assert!(err.to_string().contains("--force"), "{err}");
    drop(rt);

    let q = start(dst.path(), None);
    assert_eq!(q.node.applied_lsn(), applied);
    assert_eq!(q.node.store().state_hash().unwrap(), hash);
    // c0 had 8 + 3 increments; the restored node continues from there.
    assert_eq!(q.send("counter/c0", "increment", ""), "12");
}

#[test]
fn ship_destroy_and_restore_from_a_directory_bucket() {
    let bucket = tempdir("ship-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    ship_and_restore(&remote);
}

/// Review F2: a restore interrupted while it moves into place leaves no
/// `state.db` (never the old state with the new log), so it can simply run
/// again; and nothing of the staging directory is left behind.
#[test]
fn an_interrupted_restore_leaves_a_consistent_directory() {
    let bucket = tempdir("ship-int-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let src = tempdir("ship-int-src-");
    let p = start(src.path(), None);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.send("counter/a", "increment", "");
    p.rt.block_on(p.node.snapshot("manual")).unwrap();
    p.ship(&remote, src.path());
    let hash = p.node.store().state_hash().unwrap();
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(p);

    let dst = tempdir("ship-int-dst-");
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::write(dst.path().join("keys/master.key"), key).unwrap();
    let key_path = dst.path().join("keys/master.key");
    let rt = rt();
    let run = |force: bool, at: Option<&'static str>| {
        rt.block_on(kronik_ship::restore_with_fault(
            &remote,
            dst.path(),
            "main",
            force,
            &key_path,
            KeystoreMode::Require,
            &|step| match at {
                Some(s) if s == step => Err(std::io::Error::other(format!("injected at {step}"))),
                _ => Ok(()),
            },
        ))
    };
    run(false, None).unwrap();
    let state = dst.path().join("branches/main/state.db");
    for step in ["state", "log", "sql", "snapshot", "code", "keys", "commit"] {
        let err = run(true, Some(step)).unwrap_err();
        assert!(err.to_string().contains("injected"), "{step}: {err}");
        // "state" fails before anything moved: the old restore is intact.
        assert_eq!(state.exists(), step == "state", "{step}");
        assert!(!dst.path().join(".restore").exists(), "{step}: stage left");
        // Without a state.db, a plain restore runs again and is complete.
        run(step == "state", None).unwrap();
        assert!(state.exists(), "{step}");
    }
    let q = start(dst.path(), None);
    assert_eq!(q.node.store().state_hash().unwrap(), hash);
    assert_eq!(q.send("counter/a", "increment", ""), "2");
}

#[test]
fn ship_destroy_and_restore_from_s3() {
    let Ok(url) = std::env::var("KRONIK_TEST_S3_URL") else {
        eprintln!("KRONIK_TEST_S3_URL is not set; run scripts/minio.sh for this test");
        return;
    };
    let endpoint = std::env::var("KRONIK_TEST_S3_ENDPOINT").ok();
    let remote = Remote::open(&url, endpoint.as_deref()).unwrap();
    ship_and_restore(&remote);
}

#[test]
fn retention_deletes_remote_segments_and_snapshots() {
    let src = tempdir("ship-ret-");
    let bucket = tempdir("ship-ret-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let p = start(src.path(), Some(Duration::ZERO));
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    for i in 0..80 {
        p.send(&format!("counter/k{}", i % 5), "increment", "");
    }
    p.ship(&remote, src.path());
    let remote_segments = || {
        std::fs::read_dir(bucket.path().join("main/segments"))
            .unwrap()
            .count()
    };
    let shipped = remote_segments();
    assert!(shipped > 3, "{shipped}");
    // Snapshots compact the log (history zero) and prune to two kept.
    for _ in 0..3 {
        p.send("counter/k0", "increment", "");
        p.rt.block_on(p.node.snapshot("manual")).unwrap();
    }
    let report = p.ship(&remote, src.path());
    assert!(report.deleted > 0, "{report:?}");
    let local = kronik_log::segment_starts(&src.path().join("branches/main/log")).unwrap();
    assert_eq!(remote_segments(), local.len());
    let remote_snapshots: Vec<_> = std::fs::read_dir(bucket.path().join("main/snapshots"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("manifest.json").exists())
        .collect();
    assert_eq!(remote_snapshots.len(), p.node.snapshots().unwrap().len());
}
