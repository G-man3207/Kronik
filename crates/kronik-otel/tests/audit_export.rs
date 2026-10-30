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
fn webhook(
    up: Arc<AtomicBool>,
    got: Arc<Mutex<Vec<String>>>,
    attempts: Arc<Mutex<Vec<(String, String)>>>,
) -> String {
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
            let body = String::from_utf8(body).unwrap();
            attempts.lock().unwrap().push((key.clone(), body.clone()));
            let status = if up.load(Ordering::SeqCst) {
                if seen.insert(key) {
                    got.lock().unwrap().push(body);
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
    let url = webhook(up.clone(), Arc::clone(&got), Arc::default());
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
    // A gap is local evidence: a remote outage must not delay its append.
    for _ in 0..400 {
        let mut recorded = false;
        rt.block_on(node.reader().read(first, node.applied_lsn(), |c| {
            recorded |= matches!(&c.record, Record::AuditEvent(e) if e.action == "audit.gap");
            Ok(())
        }))
        .unwrap();
        if recorded {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut local_gaps = 0;
    rt.block_on(node.reader().read(first, node.applied_lsn(), |c| {
        local_gaps +=
            usize::from(matches!(&c.record, Record::AuditEvent(e) if e.action == "audit.gap"));
        Ok(())
    }))
    .unwrap();
    assert_eq!(local_gaps, 1, "remote sink is still down");
    assert!(got.lock().unwrap().is_empty());
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
    // Other exporters in this test binary share the process-wide counter.
    let metrics = kronik_metrics::render();
    let counter = metrics
        .lines()
        .find_map(|line| {
            line.strip_prefix("kronik_export_gaps_total{stream=\"audit\"} ")?
                .parse::<f64>()
                .ok()
        })
        .unwrap_or(0.0);
    assert!(counter >= 1.0, "{metrics}");
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

#[test]
fn retries_keep_the_key_but_an_identical_rewind_reaches_the_receiver_again() {
    let data = tempfile::tempdir().unwrap();
    let (rt, node) = node_at(data.path());
    grant(&rt, &node, "same.example", "same source bytes");
    let up = Arc::new(AtomicBool::new(false));
    let got = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let url = webhook(up.clone(), got.clone(), attempts.clone());
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            Settings {
                sink: Sink::Webhook(url),
                batch_records: 1000,
                interval: Duration::from_millis(10),
                file_max_bytes: 1024,
                headers_env: None,
                from_now: false,
                max_hold: Duration::ZERO,
                hold_release: 0,
            },
            mapper(&node),
        ))
        .unwrap();
    for _ in 0..400 {
        if attempts.lock().unwrap().len() >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    {
        let attempts = attempts.lock().unwrap();
        assert!(attempts.len() >= 2, "{attempts:?}");
        assert_eq!(
            attempts[0], attempts[1],
            "same-generation retry changed key or bytes"
        );
    }
    assert!(got.lock().unwrap().is_empty());
    up.store(true, Ordering::SeqCst);
    for _ in 0..600 {
        if cursors
            .get("audit")
            .is_some_and(|entry| entry.lsn == node.applied_lsn())
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(cursors.get("audit").unwrap().lsn, node.applied_lsn());
    assert_eq!(got.lock().unwrap().len(), 1);
    let old_generation = cursors.get("audit").unwrap().generation();
    rt.block_on(stream.rewind(&node, 0)).unwrap();
    for _ in 0..600 {
        if cursors.get("audit").is_some_and(|entry| {
            entry.lsn == node.applied_lsn()
                && entry.generation() != old_generation
                && entry.pending_rewind().is_none()
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let entry = cursors.get("audit").unwrap();
    assert_eq!(entry.lsn, node.applied_lsn());
    assert_ne!(entry.generation(), old_generation);
    assert!(entry.pending_rewind().is_none());
    let got = got.lock().unwrap();
    assert_eq!(
        got.len(),
        2,
        "a cached old ACK must not swallow an explicit replay"
    );
    assert_eq!(
        got[0], got[1],
        "this case must replay identical source bytes"
    );
    let attempts = attempts.lock().unwrap();
    assert_eq!(attempts.first().unwrap().1, attempts.last().unwrap().1);
    assert_ne!(attempts.first().unwrap().0, attempts.last().unwrap().0);
}

#[test]
fn source_gap_coverage_survives_a_failed_checkpoint_but_not_a_new_incarnation() {
    let data = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let open = || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(async {
            let mut storage = StorageConfig::new(data.path().to_path_buf());
            storage.history = Duration::ZERO;
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                data.path(),
                NodeConfig {
                    storage: Some(storage),
                    segment_max_bytes: Some(1024),
                    ..NodeConfig::default()
                },
            )
            .await
            .unwrap()
        });
        (rt, node)
    };
    let settings = || Settings {
        sink: Sink::File(out.path().to_path_buf()),
        batch_records: 1000,
        interval: Duration::from_millis(10),
        file_max_bytes: 1 << 20,
        headers_env: None,
        from_now: false,
        max_hold: Duration::ZERO,
        hold_release: 0,
    };
    let gaps = |rt: &tokio::runtime::Runtime, node: &Node| {
        let mut gaps = Vec::new();
        rt.block_on(node.reader().read(1, node.applied_lsn(), |c| {
            if let Record::AuditEvent(event) = c.record
                && event.action == "audit.gap"
            {
                gaps.push((c.lsn, event.details));
            }
            Ok(())
        }))
        .unwrap();
        gaps
    };
    let wait = |cursors: &Cursors, node: &Node| {
        for _ in 0..600 {
            if cursors
                .get("audit")
                .is_some_and(|entry| entry.lsn == node.applied_lsn())
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "cursor did not reach source head: {:?}",
            cursors.get("audit")
        );
    };
    let (rt, node) = open();
    for i in 0..80 {
        grant(
            &rt,
            &node,
            &format!("initial-{i}.example"),
            "source before retention",
        );
    }
    // Retention needs a later, strictly older turn-time bound across segments.
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ))
    .unwrap();
    rt.block_on(node.deploy(&wasm, audit(), false)).unwrap();
    let advance = |rt: &tokio::runtime::Runtime, node: &Node| {
        for i in 0..80 {
            rt.block_on(node.send(
                ActorRef::parse("counter/a").unwrap(),
                pb::Message {
                    name: "increment".into(),
                    ..Default::default()
                },
                audit(),
                false,
            ))
            .unwrap()
            .unwrap();
            if i % 20 == 19 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    advance(&rt, &node);
    rt.block_on(node.snapshot("manual")).unwrap();
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(first > 1);
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    rt.block_on(cursors.save("audit", kronik_otel::cursor::Entry::default()))
        .unwrap();
    let temporary = data.path().join("export.json.tmp");
    std::fs::create_dir(&temporary).unwrap();
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            settings(),
            mapper(&node),
        ))
        .unwrap();
    for _ in 0..400 {
        if gaps(&rt, &node).len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = gaps(&rt, &node);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].1["from"], "1");
    assert_eq!(before[0].1["to"], (first - 1).to_string());
    // The source append succeeded, but the local publication cannot succeed.
    assert!(
        rt.block_on(cursors.advance(
            "audit",
            kronik_otel::cursor::Entry {
                lsn: first - 1,
                ..Default::default()
            }
        ))
        .is_err()
    );
    assert_eq!(cursors.get("audit").unwrap().lsn, 0);
    assert_eq!(node.retention_hold().floor(), Some(0));
    drop(stream);
    drop(cursors);
    drop(node);
    drop(rt);
    std::fs::remove_dir(&temporary).unwrap();

    let (rt, node) = open();
    assert_eq!(
        node.log_first(node.storage_config().unwrap()).unwrap(),
        first
    );
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            settings(),
            mapper(&node),
        ))
        .unwrap();
    wait(&cursors, &node);
    assert_eq!(
        gaps(&rt, &node),
        before,
        "restart duplicated an already durable source notice"
    );
    let old_head = node.applied_lsn();
    drop(stream);
    drop(cursors);
    drop(node);
    drop(rt);

    // A new deletion passes the old notice's own LSN. Its coverage cannot
    // justify suppressing this larger missing range.
    let (rt, node) = open();
    for i in 0..80 {
        grant(
            &rt,
            &node,
            &format!("later-{i}.example"),
            "source after retention",
        );
    }
    advance(&rt, &node);
    rt.block_on(node.snapshot("manual")).unwrap();
    let later_first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(later_first > old_head);
    assert!(
        gaps(&rt, &node).is_empty(),
        "the first notice must actually be deleted"
    );
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            settings(),
            mapper(&node),
        ))
        .unwrap();
    wait(&cursors, &node);
    let later = gaps(&rt, &node);
    assert_eq!(later.len(), 1);
    assert_eq!(later[0].1["from"], (old_head + 1).to_string());
    assert_eq!(later[0].1["to"], (later_first - 1).to_string());
    drop(stream);
    drop(cursors);
    drop(node);
    drop(rt);

    // A restore marker starts a new source incarnation, even if an old
    // notice with the identical range remains in the restored source.
    let (rt, node) = open();
    let through = node.applied_lsn();
    rt.block_on(node.record_audit_event(
        "restore",
        "",
        [("through_lsn".into(), through.to_string())].into(),
        pb::Audit {
            token_id: "system".into(),
            ..audit()
        },
    ))
    .unwrap();
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    rt.block_on(cursors.save(
        "audit",
        kronik_otel::cursor::Entry {
            lsn: old_head,
            ..Default::default()
        },
    ))
    .unwrap();
    let _stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            settings(),
            mapper(&node),
        ))
        .unwrap();
    wait(&cursors, &node);
    let restored = gaps(&rt, &node);
    assert_eq!(restored.len(), 2);
    assert_eq!(
        restored[0].1, restored[1].1,
        "new incarnation must append the same missing range anew"
    );
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
            let dir = Path::new(url.strip_prefix("file://").unwrap())
                .join(kronik_otel::sink::OBJECT_PREFIX);
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

#[test]
fn an_initially_unavailable_file_sink_retries_without_blocking_the_node() {
    let data = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let blocked = root.path().join("blocked");
    // A regular file in place of a parent is unavailable even when tests run as root.
    std::fs::write(&blocked, b"leave unchanged").unwrap();
    let sink = Sink::File(blocked.join("audit"));
    let (rt, node) = node_at(data.path());
    grant(&rt, &node, "before.example", "before exporter");
    let cursors = Arc::new(
        rt.block_on(Cursors::load(node.env().clone(), data.path()))
            .unwrap(),
    );
    let settings = Settings {
        sink: sink.clone(),
        batch_records: 1,
        interval: Duration::from_millis(10),
        file_max_bytes: 1 << 20,
        headers_env: None,
        from_now: false,
        max_hold: Duration::ZERO,
        hold_release: 0,
    };
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors.clone(),
            settings,
            mapper(&node),
        ))
        .unwrap();
    let initial = stream.progress().cursor;
    for _ in 0..200 {
        if stream.progress().last_error.as_deref() == Some("io") {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let progress = stream.progress();
    assert_eq!(progress.last_error.as_deref(), Some("io"), "{progress:?}");
    assert_eq!(progress.cursor, initial);
    assert_eq!(cursors.get("audit").unwrap().lsn, initial);
    grant(&rt, &node, "during.example", "while sink unavailable");
    assert!(node.applied_lsn() > initial);
    assert_eq!(stream.progress().cursor, initial);
    assert_eq!(std::fs::read(&blocked).unwrap(), b"leave unchanged");

    std::fs::remove_file(&blocked).unwrap();
    for _ in 0..600 {
        if stream.progress().cursor >= node.applied_lsn() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let progress = stream.progress();
    assert_eq!(progress.cursor, node.applied_lsn(), "{progress:?}");
    assert_eq!(cursors.get("audit").unwrap().lsn, node.applied_lsn());
    let lines = read_back(&sink, &Mutex::new(Vec::new()));
    let mut expected = Vec::new();
    let m = mapper(&node);
    rt.block_on(node.reader().read(1, node.applied_lsn(), |c| {
        expected.extend(m.expected(c.lsn, &c.record)?);
        Ok(())
    }))
    .unwrap();
    let report = verify(&expected, &lines, 0, node.applied_lsn());
    assert!(report.complete, "{report:?}");
    assert!(lines.iter().any(|line| line.reason == "before exporter"));
    assert!(
        lines
            .iter()
            .any(|line| line.reason == "while sink unavailable")
    );
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
    let hook = webhook(
        Arc::new(AtomicBool::new(true)),
        Arc::clone(&got),
        Arc::default(),
    );
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
            expected.extend(m.expected(c.lsn, &c.record)?);
            Ok(())
        }))
        .unwrap();
        let r = verify(&expected, &lines, 0, node.applied_lsn());
        assert!(r.complete, "{sink:?}: {r:?}");
        assert_eq!(r.superseded, 3, "{sink:?}: {r:?}");
    }
}
