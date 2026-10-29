//! The audit exporter against a real node (m28-otel §4.6, §5; ADR 0084):
//! a webhook that is down holds retention; once free disk is below
//! `hold_release` the hold gives way, retention deletes, the export records
//! an `audit.gap` and counts it, and the node keeps admitting root inputs.
//! After a restore reuses LSNs, no sink loses a line it got before.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_otel::audit::{Keys, Line, Mapper, verify};
use kronik_otel::cursor::Cursors;
use kronik_otel::sink::{Settings, Sink, start};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Node, NodeConfig, start_local};

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "token:ops".into(),
        reason: "test".into(),
        wall_time_ms: 1,
    }
}

/// A webhook that answers 503 until `up`, then 200, keeping what it got. It
/// honours `idempotency-key`: a key it has seen is answered from its cache
/// and not kept again.
fn webhook(up: Arc<AtomicBool>, got: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut seen = std::collections::HashSet::new();
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let (mut len, mut key) = (0, String::new());
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    if k.eq_ignore_ascii_case("content-length") {
                        len = v.trim().parse().unwrap();
                    } else if k.eq_ignore_ascii_case("idempotency-key") {
                        key = v.trim().to_owned();
                    }
                }
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            let status = if up.load(Ordering::SeqCst) {
                if seen.insert(key) {
                    got.lock().unwrap().push(String::from_utf8(body).unwrap());
                }
                "200 OK"
            } else {
                "503 Service Unavailable"
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        }
    });
    url
}

#[test]
fn a_released_hold_records_a_gap_and_the_node_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let mut storage = StorageConfig::new(dir.path().to_path_buf());
        storage.history = Duration::ZERO;
        start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            NodeConfig {
                concurrency: 8,
                storage: Some(storage),
                segment_max_bytes: Some(4096),
                // Free disk is measured, and always above this reserve.
                disk_reserve: 1,
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    let (up, got) = (Arc::new(AtomicBool::new(false)), Arc::default());
    let url = webhook(up.clone(), Arc::clone(&got));
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), dir.path()))
            .unwrap(),
    );
    let settings = Settings {
        sink: Sink::parse(&url, None).unwrap(),
        batch_records: 4,
        interval: Duration::from_millis(10),
        file_max_bytes: 1 << 20,
        headers_env: None,
        from_now: false,
        max_hold: Duration::ZERO,
        // More than any disk has free: the hold is always released.
        hold_release: u64::MAX,
    };
    let mapper = std::sync::Arc::new(Mapper {
        keys: Keys::Plain,
        sealer: node.sealer().clone(),
        branch: "main".into(),
    });
    let stream = rt
        .block_on(start(node.clone(), cursors, settings, mapper))
        .unwrap();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ))
    .unwrap();
    rt.block_on(node.deploy(&wasm, audit(), false)).unwrap();
    let send = || {
        let msg = pb::Message {
            name: "increment".into(),
            content_type: "text/plain".into(),
            ..Default::default()
        };
        rt.block_on(node.send(ActorRef::parse("counter/a").unwrap(), msg, audit(), false))
            .unwrap()
            .unwrap();
    };
    for i in 0..80 {
        send();
        if i % 20 == 19 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    // The sink is down, so the first batch is still pending; the snapshot's
    // retention deletes past the released hold.
    rt.block_on(node.snapshot("manual")).unwrap();
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(first > 5, "{first}");
    assert_eq!(node.disk_below_reserve(), None);
    send();
    up.store(true, Ordering::SeqCst);
    for _ in 0..600 {
        if stream.progress().cursor >= node.applied_lsn() && stream.progress().gaps > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let p = stream.progress();
    assert_eq!(p.gaps, 1, "{p:?}");
    // The gap is an audited, exported record of its own.
    let mut gap = None;
    rt.block_on(node.reader().read(first, node.applied_lsn(), |c| {
        if let Record::AuditEvent(e) = &c.record
            && e.action == "audit.gap"
        {
            gap = Some(e.clone());
        }
        Ok(())
    }))
    .unwrap();
    let gap = gap.expect("an audit.gap event");
    assert_eq!(gap.audit.clone().unwrap().token_id, "system");
    // The pending first batch (at most 4 records) was delivered; the gap
    // runs from after it to before the first retained record.
    let from: u64 = gap.details["from"].parse().unwrap();
    assert!((2..=5).contains(&from), "{gap:?}");
    assert_eq!(gap.details["to"], (first - 1).to_string());
    let lines: Vec<Line> = got
        .lock()
        .unwrap()
        .iter()
        .flat_map(|b| {
            b.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect::<Vec<Line>>()
        })
        .collect();
    assert!(lines.iter().any(|l| l.action == "audit.gap"), "{lines:?}");
    assert!(lines.iter().any(|l| l.action == "deploy"), "{lines:?}");
    assert!(
        kronik_metrics::render().contains("kronik_export_gaps_total{stream=\"audit\"} 1"),
        "{}",
        kronik_metrics::render()
    );
}

/// A node on `dir` with a runtime of its own; dropping both stops it.
fn node_at(dir: &Path) -> (tokio::runtime::Runtime, Arc<Node>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let node = rt
        .block_on(async {
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir,
                NodeConfig::default(),
            )
            .await
        })
        .unwrap();
    (rt, node)
}

fn grant(rt: &tokio::runtime::Runtime, node: &Node, host: &str, reason: &str) {
    let audit = pb::Audit {
        reason: reason.into(),
        ..audit()
    };
    rt.block_on(node.grant("counter", &format!("http:{host}"), None, None, audit, false))
        .unwrap();
}

fn mapper(node: &Node) -> Arc<Mapper> {
    Arc::new(Mapper {
        keys: Keys::Plain,
        sealer: node.sealer().clone(),
        branch: "main".into(),
    })
}

/// Exports the log of the node on `dir` to `sink` from its start, a record
/// per batch and a file per batch, until it is caught up.
fn export(rt: &tokio::runtime::Runtime, node: &Arc<Node>, dir: &Path, sink: Sink) {
    let cursors = Arc::new(rt.block_on(Cursors::load(node.env().clone(), dir)).unwrap());
    let settings = Settings {
        sink,
        batch_records: 1,
        interval: Duration::from_millis(10),
        file_max_bytes: 1,
        headers_env: None,
        from_now: false,
        max_hold: Duration::ZERO,
        hold_release: 0,
    };
    let stream = rt
        .block_on(start(node.clone(), cursors, settings, mapper(node)))
        .unwrap();
    for _ in 0..600 {
        if stream.progress().cursor >= node.applied_lsn() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("not exported: {:?}", stream.progress());
}

/// The sink's lines in the order they were written, read as `kronik audit
/// verify` reads them.
fn read_back(sink: &Sink, got: &Mutex<Vec<String>>) -> Vec<Line> {
    let text: String = match sink {
        Sink::File(dir) => kronik_otel::sink::files(dir)
            .unwrap()
            .iter()
            .map(|f| std::fs::read_to_string(f).unwrap())
            .collect(),
        Sink::S3 { url, .. } => {
            let dir = Path::new(url.strip_prefix("file://").unwrap()).join("audit");
            let mut names: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            names.sort();
            names
                .iter()
                .map(|f| std::fs::read_to_string(f).unwrap())
                .collect()
        }
        Sink::Webhook(_) => got.lock().unwrap().concat(),
    };
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// Review H-B: a node exports a tail that a restore then loses; the
/// restored node exports other records at the same LSNs, over the same
/// batch and file boundaries. The file sink, the object store (`file://`,
/// through `Remote`) and a webhook that honours `idempotency-key` keep both
/// versions, and the restored log verifies complete against them.
#[test]
fn a_restore_that_reuses_lsns_loses_no_exported_line() {
    let got = Arc::new(Mutex::new(Vec::new()));
    let hook = webhook(Arc::new(AtomicBool::new(true)), Arc::clone(&got));
    let (files, objects) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    for sink in [
        Sink::File(files.path().join("audit")),
        Sink::S3 {
            url: format!("file://{}", objects.path().display()),
            endpoint: None,
        },
        Sink::Webhook(hook),
    ] {
        let (old, restored) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        // The restore point: in both directories.
        let (rt, node) = node_at(old.path());
        grant(&rt, &node, "example.com", "before");
        let through = node.applied_lsn();
        drop(node);
        drop(rt);
        copy_dir(old.path(), restored.path());
        let (rt, node) = node_at(old.path());
        for host in ["example.org", "example.net", "example.edu"] {
            grant(&rt, &node, host, "lost tail");
        }
        export(&rt, &node, old.path(), sink.clone());
        drop(node);
        drop(rt);
        let (rt, node) = node_at(restored.path());
        let restore = pb::Audit {
            token_id: "system".into(),
            reason: "kronik restore".into(),
            wall_time_ms: 2,
        };
        let details = [("through_lsn".to_owned(), through.to_string())].into();
        rt.block_on(node.record_audit_event("restore", "", details, restore))
            .unwrap();
        for host in ["example.io", "example.dev", "example.app"] {
            grant(&rt, &node, host, "after restore");
        }
        export(&rt, &node, restored.path(), sink.clone());
        let lines = read_back(&sink, &got);
        let lost: Vec<&Line> = lines.iter().filter(|l| l.reason == "lost tail").collect();
        assert_eq!(lost.len(), 3, "{sink:?}: {lines:?}");
        assert!(
            lost.iter()
                .all(|o| lines.iter().any(|l| l.lsn == o.lsn && l.reason != o.reason)),
            "{sink:?}: {lines:?}"
        );
        let mut expected = Vec::new();
        let m = mapper(&node);
        rt.block_on(node.reader().read(1, node.applied_lsn(), |c| {
            expected.extend(m.lines(c.lsn, &c.record, &[]));
            Ok(())
        }))
        .unwrap();
        let r = verify(&expected, &lines, 0, node.applied_lsn());
        assert!(r.complete, "{sink:?}: {r:?}");
        assert_eq!(r.superseded, 3, "{sink:?}: {r:?}");
    }
}
