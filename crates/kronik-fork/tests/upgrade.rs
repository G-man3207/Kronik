//! `kronik upgrade check` and the startup gate (docs/design/m6-storage.md
//! §7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_runtime::ENGINE_VERSION;
use kronik_sched::upgrade::{REPORT_SCHEMA, UpgradeReport};
use kronik_sched::{Node, NodeConfig, StartError, start_local};
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

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn start(rt: &Runtime, dir: &Path) -> Result<Arc<Node>, StartError> {
    rt.block_on(async {
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir,
            NodeConfig::default(),
        )
        .await
    })
}

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("upgrade-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// A data directory with counter and notes turns, and a snapshot halfway.
fn workload(dir: &Path) -> u64 {
    let rt = rt();
    let node = start(&rt, dir).unwrap();
    rt.block_on(async {
        node.deploy(&guest("counter"), audit(), false)
            .await
            .unwrap();
        node.deploy(&guest("notes"), audit(), false).await.unwrap();
        for i in 0..40 {
            if i == 20 {
                node.snapshot("manual").await.unwrap();
            }
            let (actor, name, body) = if i % 2 == 0 {
                (format!("counter/c{}", i % 3), "increment", String::new())
            } else {
                (format!("notes/n{}", i % 4), "add", format!("note {i}"))
            };
            let r = node
                .send(
                    ActorRef::parse(&actor).unwrap(),
                    msg(name, &body),
                    audit(),
                    false,
                )
                .await
                .unwrap()
                .unwrap();
            assert!(r.committed(), "{r:?}");
        }
    });
    node.applied_lsn()
}

#[test]
fn the_check_replays_the_window_with_this_engine_and_passes() {
    let dir = tempdir();
    let head = workload(dir.path());
    let rt = rt();
    let checked = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(&env, dir.path(), Duration::from_secs(6 * 3600), 2).await
        })
        .unwrap();
    let r = &checked.report;
    assert!(r.passed, "{}", String::from_utf8_lossy(&checked.diff_bytes));
    assert_eq!(r.schema, REPORT_SCHEMA);
    assert_eq!(
        (r.from_engine.as_str(), r.to_engine.as_str()),
        (ENGINE_VERSION, ENGINE_VERSION)
    );
    assert_eq!(r.checked_through_lsn, head);
    // Six hours back covers the whole run: the window starts before the
    // first turn, and the replay reads from the log's start.
    assert_eq!(r.root_inputs, 40);
    assert!(r.fork_lsn < head);
    // A short window starts later; the snapshot serves as its base.
    let short = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(&env, dir.path(), Duration::ZERO, 2).await
        })
        .unwrap();
    assert!(short.report.passed);
    assert_eq!(short.report.root_inputs, 1);
}

#[test]
fn another_engine_needs_a_passing_report_and_records_the_upgrade() {
    let dir = tempdir();
    let head = workload(dir.path());
    // Pretend an older engine wrote the data.
    let old = "kronik-0.0.1+wasmtime-1.0.0";
    {
        let db = rusqlite::Connection::open(dir.path().join("branches/main/state.db")).unwrap();
        db.execute("UPDATE meta SET v = ?1 WHERE k = 'engine_version'", [old])
            .unwrap();
    }
    let rt = rt();
    let err = start(&rt, dir.path()).err().unwrap();
    assert!(matches!(err, StartError::EngineMismatch(_)), "{err}");
    assert!(
        err.to_string().contains("kronik upgrade check --window 6h"),
        "{err}"
    );

    let report = UpgradeReport {
        schema: REPORT_SCHEMA.into(),
        from_engine: old.into(),
        to_engine: ENGINE_VERSION.into(),
        window_ms: 6 * 3_600_000,
        fork_lsn: 1,
        checked_through_lsn: head,
        root_inputs: 40,
        turns: 40,
        diff_hash: "b3:00".into(),
        passed: true,
        checked_wall_ms: 0,
    };
    let path = report.write(dir.path()).unwrap();
    let node = start(&rt, dir.path()).unwrap();
    let mut upgrades = Vec::new();
    rt.block_on(node.reader().read(1, node.applied_lsn(), |c| {
        if let Record::EngineUpgrade(u) = c.record {
            upgrades.push(u);
        }
        Ok(())
    }))
    .unwrap();
    assert_eq!(upgrades.len(), 1);
    let u = &upgrades[0];
    assert_eq!(u.from_engine_version, old);
    assert_eq!(u.to_engine_version, ENGINE_VERSION);
    assert_eq!(u.checked_through_lsn, head);
    assert_eq!(
        u.check_report_hash,
        blake3::hash(&std::fs::read(&path).unwrap())
            .as_bytes()
            .to_vec()
    );
    assert_eq!(
        node.store().db().engine_version().unwrap().as_deref(),
        Some(ENGINE_VERSION)
    );
    drop(node);
    // From now on the data is this engine's: no second record.
    let node = start(&rt, dir.path()).unwrap();
    assert_eq!(node.applied_lsn(), head + 1);
}
