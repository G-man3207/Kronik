//! A simulated node lives on its simulated disk: what it writes while it
//! starts and runs goes to the `SimFs`, never to the host's file system, so a
//! DST run neither depends on nor changes the machine it runs on. Here the
//! node's data directory is a real, empty directory of the host; after a
//! start, a deploy, a turn and some seconds of virtual time it is still
//! empty.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::{Clock, Env};
use kronik_core::ids::ActorRef;
use kronik_log::LogConfig;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{CodeStore, PoolSize, build_engine};
use kronik_sched::{Node, NodeConfig, NodeParts};
use kronik_sim::exec::{Executor, RunEnd};
use kronik_sim::fs::{CrashModel, Disk, DiskFaults, SimFs};
use kronik_sim::scenario::COUNTER;
use kronik_sim::{SimClock, SimEntropy, SimNoNet, SimProcs, SimRng, SimSpawner};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool};

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "sim".into(),
        reason: "host disk test".into(),
        wall_time_ms: 0,
    }
}

/// Every entry under `dir`, recursively.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(entries(&path));
        }
        out.push(path);
    }
    out
}

#[test]
fn a_simulated_node_writes_nothing_on_the_host() {
    let host = tempfile::tempdir().unwrap();
    let data = host.path().to_path_buf();
    let exec = Executor::new(7);
    let handle = exec.handle();
    let clock: Arc<dyn Clock> = Arc::new(SimClock {
        exec: handle.clone(),
        wall_base_ms: 1_700_000_000_000,
        wall_offset_ms: Arc::new(AtomicI64::new(0)),
    });
    let node_id = 1;
    let env = Env {
        clock: clock.clone(),
        spawner: Arc::new(SimSpawner {
            exec: handle.clone(),
            node: node_id,
        }),
        entropy: Arc::new(SimEntropy(SimRng::new(7, b"entropy"))),
        fs: Arc::new(SimFs::new(
            Arc::new(Mutex::new(Disk::default())),
            clock.clone(),
            SimRng::new(7, b"faults"),
            DiskFaults {
                crash_model: CrashModel::PrefixTorn,
                fsync_error: 0.0,
            },
        )),
        net: Arc::new(SimNoNet),
        procs: Arc::new(SimProcs {
            clock: clock.clone(),
        }),
    };
    let engine = build_engine(PoolSize { concurrency: 2 }).unwrap();
    let code = Arc::new(CodeStore::new(engine, None).unwrap());
    code.add(COUNTER).unwrap();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let store = Store::open(
        conn,
        SqlPool::new(Arc::new(MemOpener), Limits::default(), usize::MAX),
    )
    .unwrap();
    let parts = NodeParts {
        env: env.clone(),
        config: NodeConfig {
            concurrency: 2,
            storage: Some(kronik_sched::snapshots::StorageConfig::new(data.clone())),
            ..NodeConfig::default()
        },
        log: LogConfig::new(data.join("branches").join("main").join("log"), "main"),
        store,
        code,
        secrets: None,
        sealer: None,
        key_source: None,
        ownership: None,
    };
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let failure = Arc::new(Mutex::new(None::<String>));
    let failed = failure.clone();
    let sleep_clock = clock.clone();
    handle.spawn(
        node_id,
        "test",
        Box::pin(async move {
            let result: Result<(), String> = async {
                let node = Node::start(parts).await.map_err(|e| e.to_string())?;
                let authority = node.local_operator_authority().map_err(|e| e.to_string())?;
                node.deploy(COUNTER, audit(), false, authority.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                let msg = pb::Message {
                    name: "increment".into(),
                    content_type: "text/plain".into(),
                    body: Some(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(Vec::new())),
                    }),
                    blobs: vec![],
                    retained_compensation_source: None,
                };
                let actor = ActorRef::parse("counter/a").map_err(|e| e.to_string())?;
                let r = node
                    .send(actor, msg, audit(), false, authority)
                    .await
                    .map_err(|e| e.to_string())?;
                if !r.is_some_and(|r| r.committed()) {
                    return Err("the turn did not commit".into());
                }
                // The node's loops run a while: disk space, timers, secrets.
                sleep_clock.sleep(Duration::from_secs(5)).await;
                drop(node);
                Ok(())
            }
            .await;
            if let Err(e) = result {
                *failed.lock().unwrap() = Some(e);
            }
            finished.store(true, Ordering::SeqCst);
        }),
    );
    let end = exec.run(50_000_000, || done.load(Ordering::SeqCst));
    handle.kill_node(node_id);
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(*failure.lock().unwrap(), None);
    let written = entries(&data);
    assert!(
        written.is_empty(),
        "the simulated node wrote on the host: {written:?}"
    );
}
