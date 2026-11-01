//! The export follower against a real node (m28-otel §3.6, §4.6, §5; ADR
//! 0084), with a sink that records what it is handed: a failed gap record
//! is retried before the cursor passes the gap, batches have a byte
//! budget, the lag gauge moves during an outage, a dead follower restarts,
//! the audit hold does not age while idle, and a trace rewind resends the
//! same spans.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::disallowed_methods,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_log::Committed;
use kronik_otel::audit::{Keys, Mapper};
use kronik_otel::cursor::{Cursors, Entry, Generation};
use kronik_otel::follow::{BATCH_BYTES, Delivery, Options, Sink, Stream, follow, supervise};
use kronik_otel::keys::KeyHasher;
use kronik_otel::otlp::collector::trace::v1::ExportTraceServiceRequest;
use kronik_otel::otlp::trace::v1::Span;
use kronik_otel::traces::{KeyMode, Settings, TraceSink};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::secrets::CertifiedSecretSnapshot;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Node, NodeConfig, start_local};
use prost::Message as _;

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "token:ops".into(),
        reason: "test".into(),
        wall_time_ms: 1,
    }
}

struct Fixture {
    rt: tokio::runtime::Runtime,
    node: Arc<Node>,
    original: AuthLease,
    cursors: Arc<Cursors>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A node with the counter deployed; `storage` turns on snapshots and
    /// retention with no history and small segments.
    fn new(storage: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(async {
            let storage = storage.then(|| {
                let mut s = StorageConfig::new(dir.path().to_path_buf());
                s.history = Duration::ZERO;
                s
            });
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir.path(),
                NodeConfig {
                    concurrency: 8,
                    segment_max_bytes: storage.as_ref().map(|_| 4096),
                    storage,
                    ..NodeConfig::default()
                },
            )
            .await
            .unwrap()
        });
        let cursors = Arc::new(
            rt.block_on(Cursors::load(node.env().clone(), dir.path()))
                .unwrap(),
        );
        let wasm = std::fs::read(COUNTER).unwrap();
        let original = node.local_operator_authority().unwrap();
        rt.block_on(node.deploy(&wasm, audit(), false, original.clone()))
            .unwrap();
        Fixture {
            rt,
            node,
            original,
            cursors,
            _dir: dir,
        }
    }

    fn send(&self, to: &str, name: &str, body: &[u8]) {
        let msg = pb::Message {
            name: name.into(),
            content_type: "text/plain".into(),
            body: Some(pb::Sealable {
                value: Some(pb::sealable::Value::Plain(body.to_vec())),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.rt
            .block_on(self.node.send(
                ActorRef::parse(to).unwrap(),
                msg,
                audit(),
                false,
                self.original.clone(),
            ))
            .unwrap()
            .unwrap();
    }

    /// Runs the follower of a new stream from `cursor` on `sink`.
    fn follow(&self, name: &'static str, cursor: Lsn, sink: Fake) -> Arc<Stream> {
        let stream = if name == kronik_otel::sink::STREAM {
            Stream::new_audit(name, true, String::new(), cursor, self.cursors.clone())
        } else {
            Stream::new(name, true, String::new(), cursor, self.cursors.clone())
        };
        stream.own_task(self.node.env().spawn(
            "test-follow",
            follow(
                self.node.clone(),
                stream.clone(),
                OPTS,
                sink,
                self.original.clone(),
            ),
        ));
        stream
    }

    fn wait(&self, what: &str, done: impl Fn() -> bool) {
        for _ in 0..600 {
            if done() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("timed out waiting for {what}");
    }

    fn caught_up(&self, stream: &Stream) -> bool {
        stream.progress().cursor >= self.node.applied_lsn()
    }

    /// Every committed record, in LSN order.
    fn records(
        &self,
        reader: &kronik_sched::ShardReader,
        from: Lsn,
    ) -> Vec<(pb::ActorSource, Committed)> {
        let kronik_core::ids::SourcePos::Actor {
            shard: None,
            lsn: through,
        } = reader.point().source
        else {
            panic!("native actor source")
        };
        let mut out = Vec::new();
        let mut after = from.saturating_sub(1);
        while after < through {
            let page = self
                .rt
                .block_on(reader.local_export_page(after, 256, kronik_otel::follow::BATCH_BYTES))
                .unwrap();
            assert!(page.retention_gap.is_none());
            assert!(page.scanned_through > after);
            after = page.scanned_through;
            out.extend(page.records);
        }
        out
    }
}

const OPTS: Options = Options {
    batch: 4,
    interval: Duration::from_millis(10),
};

/// What the fake sink saw, and how it misbehaves.
#[derive(Default)]
struct Seen {
    /// (records, encoded bytes) per prepared batch.
    batches: Mutex<Vec<(usize, usize)>>,
    /// Retry every delivery while set.
    down: AtomicBool,
    /// Refuse preparation while complete secret coverage is unavailable.
    preparation_down: AtomicBool,
    /// Fail this many gap records.
    gap_failures: AtomicU32,
    /// (from, to, the saved cursor then) per gap call.
    gaps: Mutex<Vec<(Lsn, Lsn, Option<Lsn>)>>,
    /// Panic in this many prepares.
    panics: AtomicU32,
}

struct Fake {
    seen: Arc<Seen>,
    cursors: Arc<Cursors>,
    name: &'static str,
}

impl Sink for Fake {
    type Batch = ();

    async fn prepare(
        &mut self,
        records: &[(pb::ActorSource, Committed)],
        _generation: Generation,
        _reader: &kronik_sched::ShardReader,
        _snapshot: &CertifiedSecretSnapshot,
        original: AuthLease,
    ) -> Result<(), String> {
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        if self.seen.preparation_down.load(Ordering::SeqCst) {
            return Err("SECRET_UNAVAILABLE".into());
        }
        if self.seen.panics.load(Ordering::SeqCst) > 0 {
            self.seen.panics.fetch_sub(1, Ordering::SeqCst);
            panic!("a bug in a sink");
        }
        let bytes = records
            .iter()
            .map(|(_, record)| record.record.encoded_len())
            .sum();
        self.seen
            .batches
            .lock()
            .unwrap()
            .push((records.len(), bytes));
        Ok(())
    }

    async fn deliver(&mut self, _: &(), original: AuthLease) -> Delivery {
        if let Err(error) = original.check() {
            return Delivery::Retry {
                code: error.code.as_str().to_owned(),
                after: None,
            };
        }
        if self.seen.down.load(Ordering::SeqCst) {
            Delivery::Retry {
                code: "down".into(),
                after: Some(Duration::from_millis(20)),
            }
        } else {
            Delivery::Delivered
        }
    }

    async fn gap(&mut self, from: Lsn, to: Lsn, original: AuthLease) -> Result<(), String> {
        original
            .check()
            .map_err(|error| error.code.as_str().to_owned())?;
        let saved = self.cursors.get(self.name).map(|e| e.lsn);
        self.seen.gaps.lock().unwrap().push((from, to, saved));
        if self.seen.gap_failures.load(Ordering::SeqCst) > 0 {
            self.seen.gap_failures.fetch_sub(1, Ordering::SeqCst);
            return Err("gap_failed".into());
        }
        Ok(())
    }
}

fn fake(f: &Fixture, name: &'static str, seen: &Arc<Seen>) -> Fake {
    Fake {
        seen: seen.clone(),
        cursors: f.cursors.clone(),
        name,
    }
}

/// Review M2: the gap record fails once; the follower neither counts the
/// gap nor saves a cursor past it, and records it on the next try.
#[test]
fn a_failed_gap_record_keeps_the_cursor_before_the_gap_and_is_retried() {
    let f = Fixture::new(true);
    for _ in 0..80 {
        f.send("counter/a", "increment", b"");
    }
    let seen = Arc::new(Seen::default());
    seen.down.store(true, Ordering::SeqCst);
    seen.gap_failures.store(1, Ordering::SeqCst);
    let stream = f.follow("gaps", 0, fake(&f, "gaps", &seen));
    f.wait("a pending batch", || {
        !seen.batches.lock().unwrap().is_empty()
    });
    // The first batch is pending; nothing holds retention.
    f.rt.block_on(f.node.snapshot("manual", f.original.clone()))
        .unwrap();
    let first = f.node.log_first(f.node.storage_config().unwrap()).unwrap();
    assert!(first > 5, "{first}");
    seen.down.store(false, Ordering::SeqCst);
    f.wait("the gap and the rest", || {
        f.caught_up(&stream) && stream.progress().gaps > 0
    });
    let gaps = seen.gaps.lock().unwrap().clone();
    assert_eq!(gaps.len(), 2, "{gaps:?}");
    let (from, to, saved) = gaps[1];
    assert_eq!((gaps[0].0, gaps[0].1), (from, to), "the same gap again");
    assert_eq!(to, first - 1);
    assert!(saved.unwrap() < from, "{gaps:?}");
    assert_eq!(stream.progress().gaps, 1);
}

#[test]
fn failed_preparation_keeps_cursor_and_sink_state_until_coverage_recovers() {
    let f = Fixture::new(false);
    let seen = Arc::new(Seen::default());
    seen.preparation_down.store(true, Ordering::SeqCst);
    let stream = f.follow("preparation", 0, fake(&f, "preparation", &seen));
    f.wait("unavailable inventory", || {
        stream.progress().last_error.as_deref() == Some("SECRET_UNAVAILABLE")
    });
    assert_eq!(stream.progress().cursor, 0);
    assert!(f.cursors.get("preparation").is_none());
    assert!(seen.batches.lock().unwrap().is_empty());
    seen.preparation_down.store(false, Ordering::SeqCst);
    f.wait("recovered preparation", || f.caught_up(&stream));
    assert_eq!(
        f.cursors.get("preparation").unwrap().lsn,
        f.node.applied_lsn()
    );
    let prepared: usize = seen.batches.lock().unwrap().iter().map(|b| b.0).sum();
    assert_eq!(prepared as u64, f.node.applied_lsn());
}

#[test]
fn a_failed_cursor_save_cannot_escape_through_an_unrelated_stream_save() {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let env = Env::real(rt.handle().clone());
    let cursors = rt.block_on(Cursors::load(env.clone(), dir.path())).unwrap();
    let entry = |lsn| kronik_otel::cursor::Entry {
        lsn,
        state: serde_json::json!({"checkpoint": lsn}),
        ..Default::default()
    };
    rt.block_on(cursors.save("traces", entry(1))).unwrap();
    let temporary = dir.path().join("export.json.tmp");
    std::fs::create_dir(&temporary).unwrap();
    assert!(rt.block_on(cursors.save("traces", entry(2))).is_err());
    assert_eq!(cursors.get("traces").unwrap().lsn, 1);
    std::fs::remove_dir(temporary).unwrap();
    rt.block_on(cursors.save("audit", entry(5))).unwrap();
    let restored = rt.block_on(Cursors::load(env, dir.path())).unwrap();
    assert_eq!(restored.get("traces").unwrap().lsn, 1);
    assert_eq!(restored.get("traces").unwrap().state["checkpoint"], 1);
    assert_eq!(restored.get("audit").unwrap().lsn, 5);
}

/// Review M3: a backlog of large records is read in batches of at most
/// `BATCH_BYTES`, however many records the count allows.
#[test]
fn a_backlog_of_large_records_is_batched_by_bytes() {
    let f = Fixture::new(false);
    let body = vec![b'x'; 900_000];
    for i in 0..12 {
        f.send(&format!("counter/n{i}"), "note", &body);
    }
    let seen = Arc::new(Seen::default());
    let stream = Stream::new("bytes", true, String::new(), 0, f.cursors.clone());
    let opts = Options { batch: 500, ..OPTS };
    stream.own_task(f.node.env().spawn(
        "test-follow",
        follow(
            f.node.clone(),
            stream.clone(),
            opts,
            fake(&f, "bytes", &seen),
            f.original.clone(),
        ),
    ));
    f.wait("the backlog", || f.caught_up(&stream));
    let batches = seen.batches.lock().unwrap().clone();
    let records: usize = batches.iter().map(|b| b.0).sum();
    assert_eq!(records as u64, f.node.applied_lsn());
    assert!(batches.len() > 2, "{batches:?}");
    for (n, bytes) in &batches {
        assert!(*n == 1 || *bytes <= BATCH_BYTES, "{batches:?}");
    }
}

fn lag(stream: &str) -> Option<f64> {
    let prefix = format!("kronik_export_lag_records{{stream=\"{stream}\"}} ");
    kronik_metrics::render()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix)?.parse().ok())
}

/// Review Low: while the sink is down the lag gauge counts the backlog,
/// not the zero of the last delivery.
#[test]
fn the_lag_gauge_counts_up_while_the_sink_is_down() {
    let f = Fixture::new(false);
    let seen = Arc::new(Seen::default());
    let stream = f.follow("lag", 0, fake(&f, "lag", &seen));
    f.wait("caught up", || f.caught_up(&stream));
    f.wait("a zero lag", || lag("lag") == Some(0.0));
    seen.down.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        f.send("counter/a", "increment", b"");
    }
    f.wait("a lag", || lag("lag").is_some_and(|l| l > 0.0));
}

/// Review Low: a follower that panicked runs again from the saved cursor.
#[test]
fn a_panicked_follower_restarts() {
    let f = Fixture::new(false);
    for _ in 0..3 {
        f.send("counter/a", "increment", b"");
    }
    let seen = Arc::new(Seen::default());
    seen.panics.store(1, Ordering::SeqCst);
    let stream = Stream::new("panics", true, String::new(), 0, f.cursors.clone());
    let (sink_seen, cursors) = (seen.clone(), f.cursors.clone());
    let make = move |_: Entry| {
        let sink = Fake {
            seen: sink_seen.clone(),
            cursors: cursors.clone(),
            name: "panics",
        };
        async move { Ok(sink) }
    };
    stream.own_task(f.node.env().spawn(
        "test-supervise",
        supervise(
            f.node.clone(),
            stream.clone(),
            OPTS,
            make,
            f.original.clone(),
        ),
    ));
    f.wait("a restarted follower", || f.caught_up(&stream));
    assert_eq!(f.cursors.get("panics").unwrap().lsn, f.node.applied_lsn());
    assert_eq!(stream.progress().last_error.as_deref(), Some("panic"));
}

/// Review Low: the audit hold's age is the time the export lagged, so an
/// export that is caught up and idle longer than `max_hold` keeps its hold.
#[test]
fn the_audit_hold_does_not_age_while_the_export_is_idle() {
    let f = Fixture::new(true);
    let dir = tempfile::tempdir().unwrap();
    let max_hold = Duration::from_millis(500);
    let settings = kronik_otel::sink::Settings {
        sink: kronik_otel::sink::Sink::File(dir.path().to_path_buf()),
        batch_records: 4,
        interval: Duration::from_millis(10),
        file_max_bytes: 1 << 20,
        headers_env: None,
        from_now: false,
        max_hold,
        hold_release: 0,
    };
    let mapper = Arc::new(Mapper {
        keys: Keys::Plain,
        sealer: f.node.sealer().clone(),
        branch: "main".into(),
    });
    let stream =
        f.rt.block_on(kronik_otel::sink::start(
            f.node.clone(),
            f.cursors.clone(),
            settings,
            mapper,
            f.original.clone(),
        ))
        .unwrap();
    f.send("counter/a", "increment", b"");
    f.wait("the audit export", || f.caught_up(&stream));
    std::thread::sleep(3 * max_hold);
    let hold = f.node.retention_hold();
    let age = hold.age_ms(f.node.env().clock.wall_ms()).unwrap();
    assert!(age < max_hold.as_millis() as u64, "{age} ms");
}

fn decode(batch: Option<bytes::Bytes>) -> BTreeMap<Vec<u8>, Span> {
    let req = ExportTraceServiceRequest::decode(batch.unwrap()).unwrap();
    req.resource_spans
        .into_iter()
        .flat_map(|rs| rs.scope_spans)
        .flat_map(|ss| ss.spans)
        .map(|s| (s.span_id.clone(), s))
        .collect()
}

/// Review M8: a rewind to just after the caller's `TurnBegin` resends the
/// callees' spans with the same trace, parents and links, as the open-turn
/// set is rebuilt as it was there.
#[test]
fn a_trace_rewind_resends_the_same_spans() {
    let f = Fixture::new(false);
    // counter/a calls counter/b, which calls counter/x.
    f.send("counter/a", "call", b"counter/b call");
    let (snapshot, publication) = f.node.native_secret_snapshot_with_publication().unwrap();
    let reader = Arc::new(
        f.rt.block_on(f.node.capture_system_export_reader())
            .unwrap(),
    );
    let retained = kronik_otel::follow::RetainedDisclosure::native(
        reader.clone(),
        snapshot.clone(),
        publication,
        f.original.clone(),
    );
    let all = f.records(&reader, 1);
    let settings = Settings {
        endpoint: "http://127.0.0.1:9".into(),
        headers: Vec::new(),
        service_name: "kronik".into(),
        keys: KeyMode::Omit,
    };
    let mut sink =
        f.rt.block_on(TraceSink::open(
            f.node.clone(),
            settings,
            KeyHasher::Local([7; 32]),
            f._dir.path(),
            &serde_json::Value::Null,
            0,
        ))
        .unwrap();
    let begin = all
        .iter()
        .find(|(_, record)| matches!(record.record, Record::TurnBegin(_)))
        .unwrap()
        .1
        .lsn;
    let first = decode(
        f.rt.block_on(sink.prepare(&all, [0; 16], &reader, &snapshot, retained.clone()))
            .unwrap(),
    );
    f.rt.block_on(sink.rewind(begin, [1; 16], &reader)).unwrap();
    let again = decode(
        f.rt.block_on(sink.prepare(
            &f.records(&reader, begin + 1),
            [1; 16],
            &reader,
            &snapshot,
            retained.clone(),
        ))
        .unwrap(),
    );
    // The two callees' turn spans and their effects, and the caller's.
    assert!(again.len() >= 5, "{again:?}");
    for (id, s) in &again {
        assert_eq!(Some(s), first.get(id), "a resent span changed");
    }
}

#[test]
fn a_revoked_native_rewind_cannot_publish_durable_control() {
    let f = Fixture::new(false);
    let stream = Stream::new("revoked-rewind", true, String::new(), 0, f.cursors.clone());
    let before = f.node.applied_lsn();
    f.node.stop_native_execution().unwrap();
    let expected = f.original.check().unwrap_err().code;
    let error =
        f.rt.block_on(stream.rewind(&f.node, 0, f.original.clone()))
            .unwrap_err();
    assert_eq!(error.code, expected);
    assert!(f.cursors.get("revoked-rewind").is_none());
    assert!(!f._dir.path().join("export.json").exists());
    assert_eq!(f.node.applied_lsn(), before);
}

#[test]
fn stopped_native_follower_joins_before_later_real_appends() {
    let f = Fixture::new(false);
    let seen = Arc::new(Seen::default());
    let stream = f.follow("lifecycle", 0, fake(&f, "lifecycle", &seen));
    f.wait("the initial real source head", || f.caught_up(&stream));
    f.rt.block_on(stream.stop_and_join()).unwrap();
    let cursor = stream.progress().cursor;
    f.send("counter/a", "increment", b"after stop");
    assert!(f.node.applied_lsn() > cursor);
    assert_eq!(stream.progress().cursor, cursor);
    f.rt.block_on(stream.stop_and_join()).unwrap();
}

#[tokio::test]
async fn concurrent_stop_joins_the_real_worker_and_keeps_dynamic_names_and_exact_cursors() {
    let directory = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let foreign = Arc::new(Cursors::load(env.clone(), other.path()).await.unwrap());
    let name = format!("events-{}:metadata", "actual-dynamic-worker");
    let stream = Stream::new(name.clone(), true, String::new(), 0, cursors.clone());
    assert_eq!(stream.name.as_ref(), name);
    assert!(stream.is_for_cursors(&cursors));
    assert!(!stream.is_for_cursors(&foreign));
    assert!(!stream.is_audit());
    assert!(Stream::new_audit("actual-audit", false, String::new(), 0, cursors).is_audit());
    let completed = Arc::new(AtomicBool::new(false));
    let (release, released) = tokio::sync::oneshot::channel();
    let worker = stream.clone();
    let done = completed.clone();
    stream.own_task(env.spawn("export-lifecycle-test", async move {
        worker.stopped().await;
        // An already admitted bounded operation is allowed to finish.
        released.await.unwrap();
        done.store(true, Ordering::SeqCst);
    }));
    let first = stream.stop_and_join();
    let second = stream.stop_and_join();
    tokio::pin!(first, second);
    tokio::select! {
        biased;
        result = first.as_mut() => panic!("stop returned before its worker completed: {result:?}"),
        () = stream.stopped() => {},
    }
    assert!(!completed.load(Ordering::SeqCst));
    release.send(()).unwrap();
    let (a, b) = tokio::join!(first, second);
    a.unwrap();
    b.unwrap();
    assert!(completed.load(Ordering::SeqCst));
    stream.stop_and_join().await.unwrap();
}

#[tokio::test]
async fn cancelled_stop_waiter_does_not_lose_the_real_join_handle() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let stream = Stream::new("cancelled-stop", true, String::new(), 0, cursors);
    let completed = Arc::new(AtomicBool::new(false));
    let (release, released) = tokio::sync::oneshot::channel();
    let worker = stream.clone();
    let done = completed.clone();
    stream.own_task(env.spawn("export-lifecycle-cancel-test", async move {
        worker.stopped().await;
        released.await.unwrap();
        done.store(true, Ordering::SeqCst);
    }));
    let waiter = {
        let stream = stream.clone();
        tokio::spawn(async move { stream.stop_and_join().await })
    };
    stream.stopped().await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let next = stream.stop_and_join();
    tokio::pin!(next);
    tokio::select! {
        biased;
        result = next.as_mut() => panic!("cancelled waiter detached the real worker: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    release.send(()).unwrap();
    next.await.unwrap();
    assert!(completed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn stopping_drains_actual_control_and_refuses_the_queued_metadata_rewind() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env.clone(), directory.path(), NodeConfig::default())
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    // A persisted control fixture, not a fabricated metadata history or authority grant.
    let entry = Entry {
        lsn: 17,
        state: serde_json::json!({"source":kronik_core::ids::SourcePos::Metadata {index:17}}),
        ..Default::default()
    };
    cursors
        .save("metadata-control", entry.clone())
        .await
        .unwrap();
    let stream = Stream::new("metadata-control", true, String::new(), 17, cursors.clone());
    let held = stream.control_guard().await;
    let queued = stream.rewind_metadata(&env, 3, original.clone());
    tokio::pin!(queued);
    tokio::select! {
        biased;
        result = queued.as_mut() => panic!("rewind bypassed actual control serialization: {result:?}"),
        () = tokio::task::yield_now() => {},
    }
    let stopped = stream.stop_and_join();
    tokio::pin!(stopped);
    tokio::select! {
        biased;
        result = stopped.as_mut() => panic!("stop failed to drain active control: {result:?}"),
        () = stream.stopped() => {},
    }
    drop(held);
    let (stop, rewind) = tokio::join!(stopped, queued);
    stop.unwrap();
    assert_eq!(
        rewind.unwrap_err().code,
        kronik_core::error::ErrorCode::Unavailable
    );
    assert_eq!(cursors.get("metadata-control").unwrap(), entry);
    assert_eq!(
        Cursors::load(env.clone(), directory.path())
            .await
            .unwrap()
            .get("metadata-control")
            .unwrap(),
        entry
    );
}

#[test]
fn genuine_native_initializer_preserves_existing_rewind_and_refuses_a_future_cut() {
    let f = Fixture::new(false);
    let stream = Stream::new(
        format!("events-{}", "native-init"),
        true,
        String::new(),
        0,
        f.cursors.clone(),
    );
    let head = f.node.applied_lsn();
    let future = Entry {
        lsn: head + 1,
        ..Default::default()
    };
    assert_eq!(
        f.rt.block_on(stream.initialize_native_cursor(&f.node, future, f.original.clone()))
            .unwrap_err()
            .code,
        kronik_core::error::ErrorCode::Unavailable
    );
    assert!(f.cursors.get(stream.name.as_ref()).is_none());
    f.rt.block_on(stream.initialize_native_cursor(
        &f.node,
        Entry {
            lsn: head,
            ..Default::default()
        },
        f.original.clone(),
    ))
    .unwrap();
    f.rt.block_on(stream.rewind(&f.node, 0, f.original.clone()))
        .unwrap();
    let pending = f.cursors.get(stream.name.as_ref()).unwrap();
    assert!(pending.pending_rewind().is_some());
    let selected = f
        .rt
        .block_on(stream.initialize_native_cursor(&f.node, Entry::default(), f.original.clone()))
        .unwrap();
    assert_eq!(selected, pending);
    assert_eq!(f.cursors.get(stream.name.as_ref()).unwrap(), pending);
    f.rt.block_on(stream.stop_and_join()).unwrap();
}

#[tokio::test]
async fn real_metric_worker_stops_and_joins_while_waiting_for_its_next_push() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env.clone(), directory.path(), NodeConfig::default())
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let stream = Stream::new("actual-metric-owner", false, String::new(), 0, cursors);
    let pushed = Arc::new(AtomicBool::new(false));
    let before = pushed.clone();
    stream.own_task(env.spawn(
        "metric-stop-test",
        kronik_otel::metrics::push_loop(
            node,
            "http://127.0.0.1:9".into(),
            Vec::new(),
            "kronik".into(),
            "main".into(),
            Duration::from_secs(3600),
            move || {
                before.store(true, Ordering::SeqCst);
            },
            stream.clone(),
            original,
        ),
    ));
    stream.stop_and_join().await.unwrap();
    assert!(!pushed.load(Ordering::SeqCst));
}
