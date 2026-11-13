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
    let original = node.local_operator_authority().unwrap();
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
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ))
    .unwrap();
    rt.block_on(node.deploy(
        &wasm,
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    // Start the exporter after the configuration is installed: a capture that
    // races a deploy epoch change retries, which this retention-zero test
    // cannot wait for without losing the records under test.
    let stream = rt
        .block_on(start(
            node.clone(),
            cursors,
            settings,
            mapper,
            original.clone(),
        ))
        .unwrap();
    let send = || {
        let msg = pb::Message {
            name: "increment".into(),
            content_type: "text/plain".into(),
            ..Default::default()
        };
        rt.block_on(node.send(
            ActorRef::parse("counter/a").unwrap(),
            msg,
            audit(),
            false,
            original.clone(),
        ))
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
    rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
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
    let original = node.local_operator_authority().unwrap();
    let audit = pb::Audit {
        reason: reason.into(),
        ..audit()
    };
    rt.block_on(node.grant(
        "counter",
        &format!("http:{host}"),
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit,
        false,
        original,
    ))
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
            node.local_operator_authority().unwrap(),
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
    rt.block_on(stream.rewind(&node, 0, node.local_operator_authority().unwrap()))
        .unwrap();
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
    rt.block_on(node.deploy(
        &wasm,
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    ))
    .unwrap();
    let advance = |rt: &tokio::runtime::Runtime, node: &Node| {
        let original = node.local_operator_authority().unwrap();
        for i in 0..80 {
            rt.block_on(node.send(
                ActorRef::parse("counter/a").unwrap(),
                pb::Message {
                    name: "increment".into(),
                    ..Default::default()
                },
                audit(),
                false,
                original.clone(),
            ))
            .unwrap()
            .unwrap();
            if i % 20 == 19 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    advance(&rt, &node);
    rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
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
            node.local_operator_authority().unwrap(),
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
            node.local_operator_authority().unwrap(),
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
    rt.block_on(node.snapshot("manual", node.local_operator_authority().unwrap()))
        .unwrap();
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
            node.local_operator_authority().unwrap(),
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
    rt.block_on(node.record_system_audit_event(
        kronik_sched::SystemAudit::Restore,
        "",
        [("through_lsn".into(), through.to_string())].into(),
        pb::Audit {
            token_id: "system".into(),
            ..audit()
        },
        node.local_operator_authority().unwrap(),
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
            node.local_operator_authority().unwrap(),
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
        .block_on(start(
            node.clone(),
            cursors,
            settings,
            mapper(node),
            node.local_operator_authority().unwrap(),
        ))
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
            node.local_operator_authority().unwrap(),
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
        expected.extend(
            m.expected(c.lsn, &c.record)
                .map_err(|error| kronik_log::LogError::Corrupt(error.message))?,
        );
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
        rt.block_on(node.record_system_audit_event(
            kronik_sched::SystemAudit::Restore,
            "",
            details,
            restore,
            node.local_operator_authority().unwrap(),
        ))
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
            expected.extend(
                m.expected(c.lsn, &c.record)
                    .map_err(|error| kronik_log::LogError::Corrupt(error.message))?,
            );
            Ok(())
        }))
        .unwrap();
        let r = verify(&expected, &lines, 0, node.applied_lsn());
        assert!(r.complete, "{sink:?}: {r:?}");
        assert_eq!(r.superseded, 3, "{sink:?}: {r:?}");
    }
}

#[test]
fn changed_persisted_reason_holds_a_pending_delivery_until_explicit_rewind() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let data = tempfile::tempdir().unwrap();
    let (rt, node) = node_at(data.path());
    let original = node.local_operator_authority().unwrap();
    let needle = "reason-that-later-becomes-a-secret";
    grant(&rt, &node, "pending.example", needle);
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}/audit", listener.local_addr().unwrap());
    let (first_send, first_receive) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let (second_send, mut second_receive) = tokio::sync::oneshot::channel();
    let server = rt.spawn(async move {
        let (mut first_send, mut second_send, mut released) =
            (Some(first_send), Some(second_send), Some(released));
        for attempt in 0..2 {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                let mut length = None;
                loop {
                    line.clear();
                    assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    { length = Some(value.trim().parse::<usize>().unwrap()); }
                }
                let mut body = vec![0; length.unwrap()];
                socket.read_exact(&mut body).await.unwrap();
                if attempt == 0 {
                    first_send.take().unwrap().send(body).unwrap();
                    released.take().unwrap().await.unwrap();
                    socket.get_mut().write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    ).await.unwrap();
                } else {
                    second_send.take().unwrap().send(body).unwrap();
                    socket.get_mut().write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    ).await.unwrap();
                }
            }).await.expect("the controlled real webhook must finish");
        }
    });
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
            original.clone(),
        ))
        .unwrap();
    let first = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), first_receive)
            .await
            .unwrap()
            .unwrap()
    });
    let lines = |body: &[u8]| {
        std::str::from_utf8(body)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let first_lines = lines(&first);
    let source = first_lines
        .iter()
        .find(|line| line["reason"] == needle)
        .unwrap();
    let audit = pb::Audit {
        reason: "new FILE value".into(),
        ..audit()
    };
    rt.block_on(node.secret_set(
        "pending-reason",
        needle.as_bytes().to_vec(),
        &audit,
        false,
        original.clone(),
    ))
    .unwrap()
    .unwrap();
    release.send(()).unwrap();
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            while stream.progress().last_error.as_deref() != Some("disclosure_conflict") {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a changed projection must visibly hold the original pending bytes");
    });
    assert!(matches!(
        second_receive.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(cursors.get("audit").is_none_or(|entry| entry.lsn == 0));
    rt.block_on(stream.rewind(&node, 0, original)).unwrap();
    let second = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), &mut second_receive)
            .await
            .unwrap()
            .unwrap()
    });
    let second_lines = lines(&second);
    let projected = second_lines
        .iter()
        .find(|line| line["lsn"] == source["lsn"])
        .unwrap();
    assert!(!projected["reason"].as_str().unwrap().contains(needle));
    for field in [
        "lsn",
        "kind",
        "action",
        "at_wall_ms",
        "token_id",
        "branch",
        "record_hash",
    ] {
        assert_eq!(projected[field], source[field], "{field}");
    }
    rt.block_on(server).unwrap();
    node.stop_native_execution().unwrap();
}

#[tokio::test]
async fn ordinary_native_reader_maps_the_actual_committed_frame_not_the_mapper_target_branch() {
    let data = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        data.path(),
        NodeConfig {
            branch: "actual-frame".into(),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let original = node.local_operator_authority().unwrap();
    let lsn = node
        .record_audit_event_authorized(
            "keys.rewrap",
            "actual-key",
            Default::default(),
            audit(),
            original.clone(),
        )
        .await
        .unwrap();
    let reader = node.capture_system_export_reader().await.unwrap();
    let page = reader.page(lsn - 1, 1, 1 << 20).await.unwrap();
    assert_eq!(page.records.len(), 1);
    let (source, committed) = &page.records[0];
    assert_eq!(
        (source.shard, source.lsn, source.branch.as_str()),
        (None, lsn, "actual-frame")
    );
    assert_eq!(committed.lsn, lsn);
    let exact = committed.record.encode();
    let mapper = Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: "not-the-frame".into(),
    };
    let ordinary = mapper
        .lines_actor_at(source, &committed.record, &[])
        .unwrap();
    let operational = mapper
        .operational_lines_actor_at(source, &committed.record, &[])
        .unwrap();
    assert_eq!(ordinary.len(), 1);
    assert_eq!(ordinary, operational);
    assert_eq!(ordinary[0].branch, "actual-frame");
    assert_eq!(ordinary[0].lsn, Some(lsn));
    assert_eq!(
        ordinary[0].record_hash,
        kronik_otel::audit::record_hash(&committed.record, &mapper.sealer).unwrap()
    );
    assert_eq!(committed.record.encode(), exact);
    let expected = mapper.expected_actor_at(source, &committed.record).unwrap();
    assert!(verify(&expected, &ordinary, lsn, lsn).complete);
    assert_eq!(mapper.branch, "not-the-frame");
    assert_eq!(
        mapper.lines(lsn, &committed.record, &[]).unwrap()[0].branch,
        "not-the-frame"
    );
    for field in 0..3 {
        let mut invalid = source.clone();
        match field {
            0 => invalid.branch.clear(),
            1 => invalid.lsn = 0,
            _ => invalid.shard = Some(u32::MAX),
        }
        assert!(
            mapper
                .lines_actor_at(&invalid, &committed.record, &[])
                .is_err()
        );
        assert!(
            mapper
                .operational_lines_actor_at(&invalid, &committed.record, &[])
                .is_err()
        );
        assert!(
            mapper
                .expected_actor_at(&invalid, &committed.record)
                .is_err()
        );
    }
}

// Read-only metadata view fixtures, not Raft/SQLite commits or member readiness.
// The Record45 body is the actual immutable protobuf golden fixture; all mappers
// use this suite's real local node and loaded protected master.
fn metadata_identity_fixture() -> Record {
    let wire = kronik_core::ids::unhex(
        include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex").trim(),
    )
    .unwrap();
    let record = Record::decode(45, &wire).unwrap();
    assert_eq!(record.encode(), wire);
    record
}

fn metadata_origin_fixture(known: bool, current: bool) -> kronik_log::MetadataAuditRecord {
    kronik_log::MetadataAuditRecord {
        index: 97,
        record: metadata_identity_fixture(),
        native_origin: Some(pb::NativeAuthorityOrigin {
            source: known.then(|| pb::ActorSource {
                shard: None,
                lsn: 41,
                branch: "original-fork".into(),
            }),
            adoption_audit: Some(pb::Audit {
                token_id: "unix:uid=0".into(),
                reason: "private-adoption-reason-NEEDLE".into(),
                wall_time_ms: 37,
            }),
            current_projection: current,
        }),
    }
}

fn metadata_view_complete(
    mapper: &Mapper,
    source: &kronik_log::MetadataAuditRecord,
    lines: &[Line],
) -> bool {
    use kronik_core::ids::SourcePos;
    kronik_otel::audit::verify_at(
        &mapper.expected_metadata(source).unwrap(),
        lines,
        SourcePos::Metadata { index: 96 },
        SourcePos::Metadata { index: 97 },
    )
    .unwrap()
    .complete
}

#[test]
fn metadata_identity_origin_keeps_known_facts_and_unknown_absence_out_of_the_body_hash() {
    use kronik_core::ids::SourcePos;
    let data = tempfile::tempdir().unwrap();
    let (_rt, node) = node_at(data.path());
    let mapper = mapper(&node);
    let secrets: &[(&str, &[u8])] = &[
        ("field", b"native_origin"),
        ("source", b"original_source"),
        ("branch", b"original-fork"),
        ("one", b"1"),
        ("wall", b"37"),
        ("lsn", b"41"),
        ("adoption", b"private-adoption-reason-NEEDLE"),
    ];
    for known in [false, true] {
        for current in [false, true] {
            let source = metadata_origin_fixture(known, current);
            let exact = source.record.encode();
            let ordinary = mapper
                .lines_at(SourcePos::Metadata { index: 97 }, &source.record, secrets)
                .unwrap();
            let lines = mapper.lines_metadata(&source, secrets).unwrap();
            let line = &lines[0];
            assert_eq!(
                (&*line.schema, &*line.kind, &*line.action),
                ("kronik.audit/v3", "secret_version", "secret.version")
            );
            assert_eq!(
                (line.lsn, line.source),
                (None, Some(SourcePos::Metadata { index: 97 }))
            );
            assert!(line.branch.is_empty());
            let mut expected =
                serde_json::json!({"adopted_at_wall_ms":37,"current_projection":current});
            if known {
                expected["original_source"] =
                    serde_json::json!({"shard":null,"lsn":41,"branch":"original-fork"});
            }
            assert_eq!(line.details["native_origin"], expected);
            assert_eq!(
                (line.at_wall_ms, &line.token_id, &line.reason),
                (
                    ordinary[0].at_wall_ms,
                    &ordinary[0].token_id,
                    &ordinary[0].reason
                )
            );
            assert_eq!(
                line.record_hash,
                kronik_otel::audit::record_hash(&source.record, &mapper.sealer).unwrap()
            );
            assert_eq!(line.record_hash, ordinary[0].record_hash);
            assert_eq!(source.record.encode(), exact);
            assert!(!line.to_json().contains("private-adoption-reason-NEEDLE"));
            assert!(!line.to_json().contains("unix:uid=0"));
            assert!(metadata_view_complete(&mapper, &source, &lines));
        }
    }
}

#[test]
fn metadata_verification_checks_the_same_image_origin_even_when_record_identity_is_unchanged() {
    let data = tempfile::tempdir().unwrap();
    let (_rt, node) = node_at(data.path());
    let mapper = mapper(&node);
    let original = metadata_origin_fixture(true, true);
    let original_lines = mapper.lines_metadata(&original, &[]).unwrap();
    for mutation in 0..6 {
        let mut changed = metadata_origin_fixture(true, true);
        let origin = changed.native_origin.as_mut().unwrap();
        match mutation {
            0 => origin.source.as_mut().unwrap().lsn = 42,
            1 => origin.source.as_mut().unwrap().branch = "different-real-branch".into(),
            2 => origin.source = None,
            3 => origin.current_projection = false,
            4 => origin.adoption_audit.as_mut().unwrap().wall_time_ms = 38,
            _ => changed.native_origin = None,
        }
        let lines = mapper.lines_metadata(&changed, &[]).unwrap();
        assert_eq!(lines[0].record_hash, original_lines[0].record_hash);
        assert!(!metadata_view_complete(&mapper, &original, &lines));
    }
    let mut missing = original_lines.clone();
    missing[0].details.remove("native_origin");
    assert!(!metadata_view_complete(&mapper, &original, &missing));
    let ordinary = kronik_log::MetadataAuditRecord {
        index: 97,
        record: metadata_identity_fixture(),
        native_origin: None,
    };
    assert!(!metadata_view_complete(&mapper, &ordinary, &original_lines));
}

#[test]
fn metadata_view_rejects_malformed_or_unrepresentable_supplied_origin_instead_of_dropping_it() {
    use kronik_core::error::ErrorCode;
    let data = tempfile::tempdir().unwrap();
    let (_rt, node) = node_at(data.path());
    let mapper = mapper(&node);
    for mutation in 0..9 {
        let mut source = metadata_origin_fixture(true, true);
        match mutation {
            0 => source.index = 0,
            1 => source.index = i64::MAX as u64 + 1,
            2 => {
                source
                    .native_origin
                    .as_mut()
                    .unwrap()
                    .source
                    .as_mut()
                    .unwrap()
                    .shard = Some(0)
            }
            3 => {
                source
                    .native_origin
                    .as_mut()
                    .unwrap()
                    .source
                    .as_mut()
                    .unwrap()
                    .lsn = 0
            }
            4 => source
                .native_origin
                .as_mut()
                .unwrap()
                .source
                .as_mut()
                .unwrap()
                .branch
                .clear(),
            5 => source.native_origin.as_mut().unwrap().adoption_audit = None,
            6 => source
                .native_origin
                .as_mut()
                .unwrap()
                .adoption_audit
                .as_mut()
                .unwrap()
                .token_id
                .clear(),
            7 => {
                source.record = Record::decode(
                    46,
                    &kronik_core::ids::unhex(
                        include_str!("../../kronik-proto/tests/fixtures/secret-link-v1.hex").trim(),
                    )
                    .unwrap(),
                )
                .unwrap()
            }
            _ => {
                source.record = Record::AuditEvent(pb::AuditEvent {
                    action: "operator.note".into(),
                    audit: Some(audit()),
                    ..Default::default()
                })
            }
        }
        assert_eq!(
            mapper.lines_metadata(&source, &[]).unwrap_err().code,
            ErrorCode::StorageCorrupt
        );
        assert_eq!(
            mapper
                .operational_lines_metadata(&source, &[])
                .unwrap_err()
                .code,
            ErrorCode::StorageCorrupt
        );
        assert_eq!(
            mapper.expected_metadata(&source).err().unwrap().code,
            ErrorCode::StorageCorrupt
        );
    }
}

/// The fixture secrets collide with closed stream markers. Longer matches win,
/// the same way the export scrubber does.
fn scrub_closed_secret_spellings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = text
                .replace("events-control:metadata", "[secret:stream]")
                .replace("metadata", "[secret:domain]");
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_closed_secret_spellings),
        serde_json::Value::Object(map) => {
            map.values_mut().for_each(scrub_closed_secret_spellings);
        }
        _ => {}
    }
}

fn portable_metadata_control_fixtures() -> [(Record, serde_json::Value); 3] {
    let audit = Some(pb::Audit {
        token_id: "system:metadata".into(),
        reason: "exact-prefix private-NEEDLE exact-suffix".into(),
        wall_time_ms: 19,
    });
    [
        (
            Record::AuditEvent(pb::AuditEvent {
                action: "audit.gap".into(),
                details: [
                    ("namespace".into(), "metadata".into()),
                    ("stream".into(), "events-control:metadata".into()),
                    ("from_index".into(), "1".into()),
                    ("through_index".into(), "17".into()),
                ]
                .into(),
                audit: audit.clone(),
                ..Default::default()
            }),
            serde_json::json!({"namespace":"metadata","stream":"events-control:metadata","from_index":1,"through_index":17}),
        ),
        (
            Record::AuditEvent(pb::AuditEvent {
                action: "audit.config".into(),
                target: "events-control:metadata".into(),
                details: [
                    ("change".into(), "webhook.signing_key".into()),
                    ("source".into(), "metadata".into()),
                    ("from_version".into(), "4294967296".into()),
                    ("to_version".into(), "9007199254740991".into()),
                ]
                .into(),
                audit: audit.clone(),
                ..Default::default()
            }),
            serde_json::json!({"change":"webhook.signing_key","source":"metadata","from_version":4294967296u64,
                "to_version":9007199254740991u64,"target":"events-control:metadata"}),
        ),
        (
            Record::AuditEvent(pb::AuditEvent {
                action: "events.webhook.replay".into(),
                target: "events-control:metadata".into(),
                details: [
                    ("source".into(), "metadata".into()),
                    ("position".into(), "9223372036854775807".into()),
                ]
                .into(),
                audit,
                ..Default::default()
            }),
            serde_json::json!({"source":"metadata","position":9223372036854775807u64,"target":"events-control:metadata"}),
        ),
    ]
}

#[test]
fn decoded_metadata_control_views_preserve_only_closed_facts_and_the_whole_persisted_reason_policy()
{
    use kronik_core::ids::SourcePos;
    let data = tempfile::tempdir().unwrap();
    let (_rt, node) = node_at(data.path());
    let mapper = mapper(&node);
    let secrets: &[(&str, &[u8])] = &[
        ("domain", b"metadata"),
        ("stream", b"events-control:metadata"),
        ("one", b"1"),
        ("seventeen", b"17"),
        ("wide", b"4294967296"),
        ("wider", b"9007199254740991"),
        ("maximum", b"9223372036854775807"),
        ("private", b"private-NEEDLE"),
    ];
    for (record, details) in portable_metadata_control_fixtures() {
        let exact = record.encode();
        let decoded = Record::decode(40, &exact).unwrap();
        let source = kronik_log::MetadataAuditRecord {
            index: 97,
            record: decoded,
            native_origin: None,
        };
        let lines = mapper.lines_metadata(&source, secrets).unwrap();
        assert_eq!(
            (lines[0].lsn, lines[0].source),
            (None, Some(SourcePos::Metadata { index: 97 }))
        );
        assert!(lines[0].branch.is_empty());
        assert_eq!(
            (&*lines[0].schema, &*lines[0].kind),
            ("kronik.audit/v3", "audit_event")
        );
        let Record::AuditEvent(event) = &source.record else {
            unreachable!()
        };
        assert_eq!(lines[0].action, event.action);
        // Numeric coordinates stay exact. String spellings that match a loaded
        // secret are scrubbed; they are not a generic exemption (ADR 0082).
        let mut scrubbed = details.clone();
        scrub_closed_secret_spellings(&mut scrubbed);
        assert_eq!(lines[0].details, scrubbed.as_object().unwrap().clone());
        assert!(!lines[0].to_json().contains("events-control:metadata"));
        assert!(!lines[0].reason.contains("private-NEEDLE"));
        assert!(!lines[0].reason.contains("exact-prefix"));
        assert!(!lines[0].reason.contains("exact-suffix"));
        let unambiguous = mapper.lines_metadata(&source, &[]).unwrap();
        assert_eq!(unambiguous[0].reason, event.audit.as_ref().unwrap().reason);
        assert_eq!(lines[0].record_hash, unambiguous[0].record_hash);
        assert_eq!(lines[0].at_wall_ms, 19);
        assert_eq!(lines[0].token_id, "system:metadata");
        assert_eq!(source.record.encode(), exact);
        assert!(metadata_view_complete(&mapper, &source, &lines));
        let mut invalid = source;
        let Record::AuditEvent(event) = &mut invalid.record else {
            unreachable!()
        };
        event
            .details
            .insert("secret_value".into(), "private-NEEDLE".into());
        assert!(mapper.lines_metadata(&invalid, secrets).is_err());
        assert!(mapper.expected_metadata(&invalid).is_err());
    }
    let (gap, _) = portable_metadata_control_fixtures()
        .into_iter()
        .next()
        .unwrap();
    let source = kronik_log::MetadataAuditRecord {
        index: 97,
        record: gap,
        native_origin: None,
    };
    let lines = mapper.lines_metadata(&source, secrets).unwrap();
    for field in ["from_index", "through_index"] {
        let mut changed = lines.clone();
        changed[0]
            .details
            .insert(field.into(), serde_json::json!(18));
        assert_eq!(changed[0].record_hash, lines[0].record_hash);
        assert!(!metadata_view_complete(&mapper, &source, &changed));
    }
    let mut ordinary = source;
    let Record::AuditEvent(event) = &mut ordinary.record else {
        unreachable!()
    };
    event.action = "operator.note".into();
    let lines = mapper.lines_metadata(&ordinary, secrets).unwrap();
    assert_ne!(
        lines[0].details.get("namespace"),
        Some(&serde_json::json!("metadata"))
    );
    assert_ne!(
        lines[0].details.get("stream"),
        Some(&serde_json::json!("events-control:metadata"))
    );
    assert_ne!(
        lines[0].details.get("from_index"),
        Some(&serde_json::json!(1))
    );
}

#[test]
fn decoded_protected_approval_uses_the_metadata_receipt_without_publishing_its_identity_payload() {
    use kronik_core::ids::SourcePos;
    let data = tempfile::tempdir().unwrap();
    let (_rt, node) = node_at(data.path());
    let mapper = mapper(&node);
    let owner = format!("oidc:{}", "ab".repeat(32));
    let record = Record::Approval(pb::Approval {
        proposal_id: "p-real-history".into(),
        diff_hash: vec![7; 32],
        verified_through_lsn: 17,
        audit: Some(pb::Audit {
            token_id: owner.clone(),
            reason: "approval private-NEEDLE".into(),
            wall_time_ms: 19,
        }),
        verified_identity: Some(pb::Sealable {
            subject: Some(owner),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 2,
                nonce: vec![3; 24],
                ciphertext: vec![5; 16],
            })),
        }),
        ..Default::default()
    });
    let exact = record.encode();
    let source = kronik_log::MetadataAuditRecord {
        index: 97,
        record: Record::decode(8, &exact).unwrap(),
        native_origin: None,
    };
    let lines = mapper
        .lines_metadata(&source, &[("private", b"private-NEEDLE")])
        .unwrap();
    assert_eq!(
        (&*lines[0].schema, &*lines[0].kind, &*lines[0].action),
        ("kronik.audit/v3", "approval", "approve")
    );
    assert_eq!(
        (lines[0].lsn, lines[0].source),
        (None, Some(SourcePos::Metadata { index: 97 }))
    );
    assert!(lines[0].branch.is_empty());
    assert!(!lines[0].to_json().contains("private-NEEDLE"));
    assert!(!lines[0].details.contains_key("verified_identity"));
    assert!(!lines[0].details.contains_key("ciphertext"));
    assert!(metadata_view_complete(&mapper, &source, &lines));
    assert_eq!(source.record.encode(), exact);
    for mutation in 0..3 {
        let mut invalid = Record::decode(8, &exact).unwrap();
        let Record::Approval(approval) = &mut invalid else {
            unreachable!()
        };
        match mutation {
            0 => {
                approval.verified_identity.as_mut().unwrap().subject =
                    Some("different-owner".into())
            }
            1 => {
                approval.verified_identity.as_mut().unwrap().value =
                    Some(pb::sealable::Value::Plain(b"private identity".to_vec()))
            }
            _ => approval.verified_identity.as_mut().unwrap().value = None,
        }
        let invalid = kronik_log::MetadataAuditRecord {
            index: 97,
            record: invalid,
            native_origin: None,
        };
        assert!(mapper.lines_metadata(&invalid, &[]).is_err());
        assert!(mapper.expected_metadata(&invalid).is_err());
    }
}

#[test]
fn metadata_coverage_notice_in_native_log_keeps_its_actual_fsynced_actor_receipt() {
    let data = tempfile::tempdir().unwrap();
    let (rt, node) = node_at(data.path());
    let original = node.local_operator_authority().unwrap();
    // A namespaced metadata coverage notice has one fixed native producer; the
    // ordinary actor audit producer refuses to forge it.
    let details = serde_json::json!({"namespace": "metadata", "stream": "events-control:metadata",
        "from_index": 1, "through_index": 17});
    let gap = kronik_log::MetadataAuditGap {
        stream: "events-control:metadata".into(),
        from_index: 1,
        through_index: 17,
    };
    let pos = rt
        .block_on(node.record_metadata_audit_gap(gap, original))
        .unwrap();
    let kronik_core::ids::SourcePos::Actor { shard: None, lsn } = pos else {
        panic!("a metadata coverage notice is a native actor receipt");
    };
    let reader = rt.block_on(node.capture_system_export_reader()).unwrap();
    let page = rt.block_on(reader.page(lsn - 1, 1, 1 << 20)).unwrap();
    let (source, committed) = &page.records[0];
    assert_eq!((source.shard, source.lsn), (None, lsn));
    assert_eq!(committed.lsn, lsn);
    let exact = committed.record.encode();
    let mapper = mapper(&node);
    let lines = mapper
        .lines_actor_at(
            source,
            &committed.record,
            &[
                ("domain", b"metadata"),
                ("stream", b"events-control:metadata"),
                ("one", b"1"),
                ("seventeen", b"17"),
                ("private", b"private-NEEDLE"),
            ],
        )
        .unwrap();
    assert_eq!(
        (&*lines[0].kind, &*lines[0].action),
        ("audit_event", "audit.gap")
    );
    let mut scrubbed = details.clone();
    scrub_closed_secret_spellings(&mut scrubbed);
    assert_eq!(lines[0].details, scrubbed.as_object().unwrap().clone());
    assert_eq!(lines[0].details["from_index"], 1);
    assert_eq!(lines[0].details["through_index"], 17);
    assert!(!lines[0].to_json().contains("events-control:metadata"));
    assert_eq!((lines[0].lsn, lines[0].source), (Some(lsn), None));
    assert_eq!(lines[0].branch, source.branch);
    let expected = mapper.expected_actor_at(source, &committed.record).unwrap();
    assert!(verify(&expected, &lines, lsn, lsn).complete);
    assert_eq!(
        mapper
            .operational_lines_actor_at(source, &committed.record, &[])
            .unwrap()[0]
            .source,
        None
    );
    assert_eq!(committed.record.encode(), exact);
    // The metadata index range in the notice is not an actor-log coverage range.
    assert_eq!(
        kronik_sched::scrub::AuditPositions::parse(
            "audit.gap",
            &kronik_log::MetadataAuditGap {
                stream: "events-control:metadata".into(),
                from_index: 1,
                through_index: 17
            }
            .into_details()
        )
        .unwrap()
        .unwrap()
        .value("from"),
        None
    );
}
