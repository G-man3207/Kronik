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
use kronik_ship::{KeystoreMode, RESTORE_MARKER, Remote, ShipState, restore, ship_once};
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
        retained_compensation_source: None,
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
                self.node.local_operator_authority().unwrap(),
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
        let mut st = ShipState::load(dir).unwrap();
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
    p.rt.block_on(p.node.deploy(
        &guest("counter"),
        audit(),
        false,
        p.node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    p.rt.block_on(p.node.deploy(
        &guest("notes"),
        audit(),
        false,
        p.node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    for i in 0..30 {
        p.send(&format!("counter/c{}", i % 4), "increment", "");
        p.send(&format!("notes/n{}", i % 3), "add", &format!("note {i}"));
    }
    let m =
        p.rt.block_on(
            p.node
                .snapshot("manual", p.node.local_operator_authority().unwrap()),
        )
        .unwrap();
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
            &Env::real(rt.handle().clone()),
            &Default::default(),
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
            &Env::real(rt.handle().clone()),
            &Default::default(),
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
/// again; and nothing of the staging directory is left behind. Perf review
/// R4: the restore marker is durable before the commit step, so restored
/// state never comes without it.
#[test]
fn an_interrupted_restore_leaves_a_consistent_directory() {
    let bucket = tempdir("ship-int-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let src = tempdir("ship-int-src-");
    let p = start(src.path(), None);
    p.rt.block_on(p.node.deploy(
        &guest("counter"),
        audit(),
        false,
        p.node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    p.send("counter/a", "increment", "");
    p.rt.block_on(
        p.node
            .snapshot("manual", p.node.local_operator_authority().unwrap()),
    )
    .unwrap();
    p.ship(&remote, src.path());
    let hash = p.node.store().state_hash().unwrap();
    let key = std::fs::read(src.path().join("keys/master.key")).unwrap();
    drop(p);

    let dst = tempdir("ship-int-dst-");
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::write(dst.path().join("keys/master.key"), key).unwrap();
    let rt = rt();
    let run = |force: bool, at: Option<&'static str>| {
        rt.block_on(kronik_ship::restore_with_fault(
            &remote,
            dst.path(),
            "main",
            force,
            &Env::real(rt.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
            &|step| match at {
                Some(s) if s == step => Err(std::io::Error::other(format!("injected at {step}"))),
                _ => Ok(()),
            },
        ))
    };
    let report = run(false, None).unwrap();
    let state = dst.path().join("branches/main/state.db");
    let marker = dst.path().join("branches/main").join(RESTORE_MARKER);
    let through = |when: &str| -> u64 {
        let body = std::fs::read(&marker).unwrap_or_else(|e| panic!("{when}: no marker: {e}"));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["through_lsn"].as_u64().unwrap()
    };
    let want = through("restore");
    assert!(want >= report.snapshot_lsn, "{want}");
    for step in [
        "state",
        "log",
        "sql",
        "snapshot",
        "code",
        "keys",
        "commit",
        "committed",
    ] {
        // As `kronik serve` leaves it after recording the restore.
        std::fs::remove_file(&marker).unwrap();
        let err = run(true, Some(step)).unwrap_err();
        assert!(err.to_string().contains("injected"), "{step}: {err}");
        // "state" fails before anything moved: the old restore is intact.
        // After "committed" the restore is in place.
        assert_eq!(
            state.exists(),
            matches!(step, "state" | "committed"),
            "{step}"
        );
        if matches!(step, "commit" | "committed") {
            assert_eq!(through(step), want, "{step}");
        }
        assert!(!dst.path().join(".restore").exists(), "{step}: stage left");
        // Without a state.db, a plain restore runs again and is complete.
        run(matches!(step, "state" | "committed"), None).unwrap();
        assert!(state.exists(), "{step}");
        through(step);
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
    p.rt.block_on(p.node.deploy(
        &guest("counter"),
        audit(),
        false,
        p.node.local_operator_authority().unwrap(),
    ))
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
        p.rt.block_on(
            p.node
                .snapshot("manual", p.node.local_operator_authority().unwrap()),
        )
        .unwrap();
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

// -------------------------------------------------------------------------
// Restore onto a log that retention compacted past an idle SQL actor. An
// actor database's applied LSN is where its last change was; a snapshot
// takes the actor databases as they are when it is taken, before the
// retention pass that follows it raises them (and before it deletes the log
// below the snapshot). So the newest snapshot in a bucket, whose log starts
// where retention left it, can hold an actor database that says "6" while the
// log starts at "30". The restore copies the snapshot as it is; the first
// start must still work.
//
// With a `history` longer than the time between snapshots, a node that has
// the raise in its retention pass carries the raised value from the pass
// before into its newest snapshot, and nothing is left to repair. These tests
// stand for the cases that remain: a bucket written by a release without the
// raise (every idle SQL actor on a compacted log), and a short `history`,
// which they take to the limit (zero).

/// Builds a node whose retention compacted the log past the only SQL change
/// of `notes/n`, which is idle since. With `ship_early` the node ships before
/// the compaction too (the remote then drops what retention drops); otherwise
/// shipping starts only after it, and the bucket's log starts mid-way. Returns
/// the LSN of the note, the log's first LSN, the node's applied LSN and state
/// hash at the end, and the master key (which never goes to the bucket). The
/// node is stopped.
fn compacted_node_shipped(
    src: &Path,
    remote: &Remote,
    ship_early: bool,
) -> (u64, u64, u64, String, Vec<u8>) {
    let p = start(src, Some(Duration::ZERO));
    for g in ["counter", "notes"] {
        p.rt.block_on(p.node.deploy(
            &guest(g),
            audit(),
            false,
            p.node.local_operator_authority().unwrap(),
        ))
        .unwrap();
    }
    p.send("notes/n", "add", "hello");
    let note = p
        .node
        .store()
        .db()
        .actor("notes", "n")
        .unwrap()
        .unwrap()
        .last_lsn;
    for i in 0..80 {
        p.send(&format!("counter/k{}", i % 5), "increment", "");
        if i % 20 == 19 {
            // Logical time moves, so that retention finds segments older
            // than a history of zero.
            std::thread::sleep(Duration::from_millis(5));
        }
        if ship_early && i == 40 {
            p.ship(remote, src);
        }
    }
    if ship_early {
        // A node ships every few seconds: what was the active segment has
        // long been uploaded as a closed one when retention gets to it.
        p.ship(remote, src);
    }
    // The snapshot's retention pass compacts the log.
    p.rt.block_on(
        p.node
            .snapshot("manual", p.node.local_operator_authority().unwrap()),
    )
    .unwrap();
    let storage = p.node.storage_config().unwrap().clone();
    let first = p.node.log_first(&storage).unwrap();
    assert!(first > note + 1, "first {first}, the note's lsn {note}");
    p.ship(remote, src);
    let applied = p.node.applied_lsn();
    let hash = p.node.store().state_hash().unwrap();
    let key = std::fs::read(src.join("keys/master.key")).unwrap();
    drop(p);
    (note, first, applied, hash, key)
}

/// The first LSN of the bucket's log.
fn bucket_first(bucket: &Path) -> u64 {
    std::fs::read_dir(bucket.join("main/segments"))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".seg.zst")?
                .parse::<u64>()
                .ok()
        })
        .min()
        .unwrap()
}

fn restore_compacted_log_with_an_idle_sql_actor(ship_early: bool) {
    let bucket = tempdir("ship-idle-bucket-");
    let remote = Remote::open(&format!("file://{}", bucket.path().display()), None).unwrap();
    let src = tempdir("ship-idle-src-");
    let (note, first, applied, hash, key) = compacted_node_shipped(src.path(), &remote, ship_early);
    drop(src);
    // The bucket's log starts mid-way, after the actor's last change.
    assert_eq!(bucket_first(bucket.path()), first);

    let dst = tempdir("ship-idle-dst-");
    std::fs::create_dir_all(dst.path().join("keys")).unwrap();
    std::fs::write(dst.path().join("keys/master.key"), key).unwrap();
    let rt = rt();
    let report = rt
        .block_on(restore(
            &remote,
            dst.path(),
            "main",
            false,
            &Env::real(rt.handle().clone()),
            &Default::default(),
            KeystoreMode::Require,
        ))
        .unwrap();
    drop(rt);
    assert!(report.snapshot_lsn + 1 >= first, "{report:?}");

    // The scenario is the one it claims to be: the restored actor database
    // still says where its change was, below the log the bucket kept.
    let branch = dst.path().join("branches/main");
    let markers = kronik_store::snapshot::read_markers(&branch, false, Some(first))
        .unwrap()
        .unwrap();
    assert_eq!(markers.lowest, note, "{markers:?}");
    assert!(markers.lowest + 1 < first, "{markers:?}, first {first}");
    // `kronik upgrade check` asks the start's question before the start does.
    let plan = kronik_sched::snapshots::plan_state(dst.path(), "main", true).unwrap();
    assert_eq!(
        plan.install.as_ref().map(|(_, m)| m.lsn),
        Some(report.snapshot_lsn)
    );

    // The first start repairs it from the snapshot the restore registered.
    let q = start(dst.path(), None);
    assert_eq!(q.node.applied_lsn(), applied);
    assert_eq!(q.node.store().state_hash().unwrap(), hash);
    let list = q.send("notes/n", "list", "");
    assert_eq!(list.matches("hello").count(), 1, "{list}");
    q.send("notes/n", "add", "after the restore");
    let list = q.send("notes/n", "list", "");
    assert_eq!(list.matches("hello").count(), 1, "{list}");
    assert_eq!(list.matches("after the restore").count(), 1, "{list}");
    assert!(q.node.store().replay_from().unwrap() + 1 >= first);
    drop(q);
    // And it stays repaired: a second start has nothing to do.
    assert!(
        kronik_sched::snapshots::plan_state(dst.path(), "main", false)
            .unwrap()
            .install
            .is_none()
    );
}

#[test]
fn restore_onto_a_log_compacted_before_shipping_started_keeps_an_idle_sql_actor() {
    restore_compacted_log_with_an_idle_sql_actor(false);
}

#[test]
fn restore_onto_a_log_the_remote_compacted_along_keeps_an_idle_sql_actor() {
    restore_compacted_log_with_an_idle_sql_actor(true);
}
