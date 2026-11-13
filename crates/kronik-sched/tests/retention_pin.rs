//! An open turn that keeps log segments from retention is visible (#35;
//! docs/guides/operations.md, "An open turn that keeps the log"): the
//! retention pass that keeps a segment only for it names the turn and sets
//! `kronik_retention_open_turn_segments`; a pass that keeps nothing for it
//! reports nothing. A file of its own: the gauge is the process's, and no
//! other test here runs a retention pass.

// Test helpers may unwrap; the test server uses plain std threads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Node, NodeConfig, start_local};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// A server that reads a request and answers nothing for two minutes; the
/// count of requests it read.
fn hanging_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let count = count.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(stream);
                let mut len = 0usize;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let line = line.trim_end().to_ascii_lowercase();
                    if line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; len];
                let _ = r.read_exact(&mut body);
                count.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_secs(120));
            });
        }
    });
    (addr, seen)
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

async fn send(node: &Node, actor: &str, name: &str, body: &str) {
    let r = node
        .send(
            ActorRef::parse(actor).unwrap(),
            msg(name, body),
            audit(),
            false,
            node.local_operator_authority().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(r.committed(), "{r:?}");
}

/// Turns of `counter/k*` that roll segments and move logical time.
async fn traffic(node: &Node, turns: usize) {
    for i in 0..turns {
        send(node, &format!("counter/k{}", i % 5), "increment", "").await;
        if i % 20 == 19 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

const METRIC: &str = "kronik_retention_open_turn_segments";

/// The gauge's value for `source`, from the process's metrics.
fn gauge(source: &str) -> Option<f64> {
    let prefix = format!("{METRIC}{{source=\"{source}\"}} ");
    kronik_metrics::render()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(|v| v.parse().unwrap()))
}

#[test]
fn an_open_turn_that_keeps_segments_from_retention_is_named() {
    let (addr, seen) = hanging_server();
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.path().to_path_buf());
        storage.history = Duration::ZERO;
        storage.snapshot_interval = Duration::from_secs(3600);
        start_local(
            env,
            dir.path(),
            NodeConfig {
                concurrency: 8,
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    let owner = || node.local_operator_authority().unwrap();
    rt.block_on(async {
        node.deploy(&std::fs::read(COUNTER).unwrap(), audit(), false, owner())
            .await
            .unwrap();
        node.grant(
            "counter",
            "http:127.0.0.1",
            None,
            None,
            kronik_effects::InForks::Recorded,
            audit(),
            false,
            owner(),
        )
        .await
        .unwrap();
        // The fetch below must outlast the test.
        node.set_limits(
            pb::Limits {
                kind: "counter".into(),
                effect_timeout_ms: Some(120_000),
                ..Default::default()
            },
            audit(),
            false,
            owner(),
        )
        .await
        .unwrap();
        traffic(&node, 40).await;
    });
    // A turn that stays open: its TurnBegin is written before its fetch,
    // which the server never answers.
    let open = node.clone();
    let spec = format!("GET http://{addr}/hang");
    rt.spawn(async move { send(&open, "counter/h", "fetch", &spec).await });
    for _ in 0..600 {
        if seen.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(seen.load(Ordering::SeqCst), 1, "the fetch never arrived");
    let turn = node.store().db().open_turns().unwrap();
    assert_eq!(turn.len(), 1, "{turn:?}");
    let turn = turn.into_iter().next().unwrap();

    let storage = node.storage_config().unwrap().clone();
    // Without a base nothing is deleted, so the open turn keeps nothing that
    // would have gone: nothing to report.
    assert_eq!(node.compact(&storage).unwrap(), 1);
    assert_eq!(node.retention_pin(), None);
    assert_eq!(gauge("live"), Some(0.0));
    rt.block_on(async {
        traffic(&node, 80).await;
        // A snapshot after it is the window's base once a later turn has put
        // it behind the (zero) window.
        node.snapshot("manual", owner()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        traffic(&node, 1).await;
    });
    let first = node.compact(&storage).unwrap();
    // Segments before the turn's begin went; from it on, retention kept
    // segments it would have deleted, and says for which turn.
    assert!(first > 1, "nothing was deleted");
    assert_eq!(
        first, turn.pos.segment,
        "the begin's segment is the first kept"
    );
    let pin = node.retention_pin().expect("the pin is reported");
    assert_eq!(pin.pin.execution_id, turn.execution_id);
    assert_eq!(pin.pin.actor.as_deref(), Some("counter/h"));
    assert_eq!(pin.pin.lsn, Some(turn.lsn));
    assert_eq!(pin.pin.snapshot, None);
    assert_eq!(pin.pin.segment, turn.pos.segment);
    assert!(pin.held_segments >= 1, "{pin:?}");
    assert!(pin.held_bytes > 0, "{pin:?}");
    assert_eq!(gauge("live"), Some(pin.held_segments as f64));
    assert_eq!(gauge("snapshot"), Some(0.0));
    // A later pass keeps the time it began to hold.
    let since = pin.since_ms;
    node.compact(&storage).unwrap();
    assert_eq!(node.retention_pin().unwrap().since_ms, since);
    // The fetch's thread is left to the server's timeout.
    drop(node);
    rt.shutdown_timeout(Duration::from_secs(1));
}
