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

use kronik_core::env::Env;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_log::Committed;
use kronik_otel::audit::{Keys, Mapper};
use kronik_otel::cursor::Cursors;
use kronik_otel::follow::{BATCH_BYTES, Delivery, Options, Sink, Stream, follow, supervise};
use kronik_otel::keys::KeyHasher;
use kronik_otel::otlp::collector::trace::v1::ExportTraceServiceRequest;
use kronik_otel::otlp::trace::v1::Span;
use kronik_otel::traces::{KeyMode, Settings, TraceSink};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
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
        rt.block_on(node.deploy(&wasm, audit(), false)).unwrap();
        Fixture {
            rt,
            node,
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
            .block_on(
                self.node
                    .send(ActorRef::parse(to).unwrap(), msg, audit(), false),
            )
            .unwrap()
            .unwrap();
    }

    /// Runs the follower of a new stream from `cursor` on `sink`.
    fn follow(&self, name: &'static str, cursor: Lsn, sink: Fake) -> Arc<Stream> {
        let stream = Stream::new(name, true, String::new(), cursor);
        drop(self.node.env().spawn(
            "test-follow",
            follow(
                self.node.clone(),
                self.cursors.clone(),
                stream.clone(),
                OPTS,
                sink,
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
    fn records(&self, from: Lsn) -> Vec<Committed> {
        let mut out = Vec::new();
        self.rt
            .block_on(self.node.reader().read(from, self.node.applied_lsn(), |c| {
                out.push(c);
                Ok(())
            }))
            .unwrap();
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

    async fn prepare(&mut self, records: Vec<Committed>) {
        if self.seen.panics.load(Ordering::SeqCst) > 0 {
            self.seen.panics.fetch_sub(1, Ordering::SeqCst);
            panic!("a bug in a sink");
        }
        let bytes = records.iter().map(|c| c.record.encoded_len()).sum();
        self.seen
            .batches
            .lock()
            .unwrap()
            .push((records.len(), bytes));
    }

    async fn deliver(&mut self, _: &()) -> Delivery {
        if self.seen.down.load(Ordering::SeqCst) {
            Delivery::Retry {
                code: "down".into(),
                after: Some(Duration::from_millis(20)),
            }
        } else {
            Delivery::Delivered
        }
    }

    async fn gap(&mut self, from: Lsn, to: Lsn) -> Result<(), String> {
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
    f.rt.block_on(f.node.snapshot("manual")).unwrap();
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
    let stream = Stream::new("bytes", true, String::new(), 0);
    let opts = Options { batch: 500, ..OPTS };
    drop(f.node.env().spawn(
        "test-follow",
        follow(
            f.node.clone(),
            f.cursors.clone(),
            stream.clone(),
            opts,
            fake(&f, "bytes", &seen),
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
    let stream = Stream::new("panics", true, String::new(), 0);
    let builds = Arc::new(AtomicU32::new(0));
    let (sink_seen, count, cursors) = (seen.clone(), builds.clone(), f.cursors.clone());
    let make = move |_: &serde_json::Value| {
        count.fetch_add(1, Ordering::SeqCst);
        Fake {
            seen: sink_seen.clone(),
            cursors: cursors.clone(),
            name: "panics",
        }
    };
    drop(f.node.env().spawn(
        "test-supervise",
        supervise(
            f.node.clone(),
            f.cursors.clone(),
            stream.clone(),
            OPTS,
            make,
        ),
    ));
    f.wait("a restarted follower", || f.caught_up(&stream));
    assert_eq!(builds.load(Ordering::SeqCst), 2);
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
        ))
        .unwrap();
    f.send("counter/a", "increment", b"");
    f.wait("the audit export", || f.caught_up(&stream));
    std::thread::sleep(3 * max_hold);
    let hold = f.node.retention_hold();
    let age = hold.age_ms(f.node.env().clock.wall_ms()).unwrap();
    assert!(age < max_hold.as_millis() as u64, "{age} ms");
}

fn decode(batch: Option<Vec<u8>>) -> BTreeMap<Vec<u8>, Span> {
    let req = ExportTraceServiceRequest::decode(batch.unwrap().as_slice()).unwrap();
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
    let all = f.records(1);
    let settings = Settings {
        endpoint: "http://127.0.0.1:9".into(),
        headers: Vec::new(),
        service_name: "kronik".into(),
        keys: KeyMode::Omit,
    };
    let mut sink = TraceSink::new(
        f.node.clone(),
        settings,
        KeyHasher::Local([7; 32]),
        &serde_json::Value::Null,
    );
    let first = decode(f.rt.block_on(sink.prepare(all.clone())));
    let begin = all
        .iter()
        .find(|c| matches!(c.record, Record::TurnBegin(_)))
        .unwrap()
        .lsn;
    f.rt.block_on(sink.rewind(begin));
    let again = decode(f.rt.block_on(sink.prepare(f.records(begin + 1))));
    // The two callees' turn spans and their effects, and the caller's.
    assert!(again.len() >= 5, "{again:?}");
    for (id, s) in &again {
        assert_eq!(Some(s), first.get(id), "a resent span changed");
    }
}
