//! Snapshots (docs/design/m6-storage.md §2-§3): consistency under
//! concurrent turns, startup from a snapshot without `state.db`, pruning,
//! the log's `SnapshotMarker`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::snapshots::StorageConfig;
use kronik_sched::{Ingress, Node, NodeConfig, start_local};
use kronik_store::Store;
use kronik_store::sql::{Limits, MemOpener, SqlPool};
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

fn start(dir: &Path, kept: usize) -> Proc {
    start_with(dir, kept, None, None, None)
}

fn start_with(
    dir: &Path,
    kept: usize,
    history: Option<std::time::Duration>,
    segment: Option<u64>,
    interval: Option<std::time::Duration>,
) -> Proc {
    let (rt, node) = try_start_with(dir, kept, history, segment, interval);
    Proc {
        rt,
        node: node.unwrap(),
    }
}

fn try_start_with(
    dir: &Path,
    kept: usize,
    history: Option<std::time::Duration>,
    segment: Option<u64>,
    interval: Option<std::time::Duration>,
) -> (Runtime, Result<Arc<Node>, kronik_sched::StartError>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.snapshots_kept = kept;
        if let Some(h) = history {
            storage.history = h;
        }
        if let Some(i) = interval {
            storage.snapshot_interval = i;
        }
        start_local(
            env,
            dir,
            NodeConfig {
                concurrency: 8,
                storage: Some(storage),
                segment_max_bytes: segment,
                ..NodeConfig::default()
            },
        )
        .await
    });
    (rt, node)
}

impl Proc {
    fn send(&self, actor: &str, name: &str, body: &str) {
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
    }

    fn records(&self, upto: u64) -> Vec<kronik_log::Committed> {
        let mut out = Vec::new();
        self.rt
            .block_on(self.node.reader().read(1, upto, |c| {
                out.push(c);
                Ok(())
            }))
            .unwrap();
        out
    }

    /// The `SnapshotMarker` records in the log: every durable record, not
    /// only the applied ones (a snapshot's append resolves after its fsync,
    /// before its apply).
    fn markers(&self) -> usize {
        self.records(u64::MAX)
            .iter()
            .filter(|c| matches!(c.record, Record::SnapshotMarker(_)))
            .count()
    }
}

fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("snapshots-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// The state hash of a store rebuilt in memory from the log up to `upto`.
fn rebuilt_hash(records: &[kronik_log::Committed]) -> String {
    let store = Store::open(
        rusqlite::Connection::open_in_memory().unwrap(),
        SqlPool::new(Arc::new(MemOpener), Limits::default(), usize::MAX),
    )
    .unwrap();
    store.apply(records).unwrap();
    store.state_hash().unwrap()
}

#[test]
fn snapshots_are_consistent_under_concurrent_turns_and_startup_uses_them() {
    let dir = tempdir();
    let p = start(dir.path(), 48);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.rt.block_on(p.node.deploy(&guest("notes"), audit(), false))
        .unwrap();
    for i in 0..20 {
        p.send(&format!("counter/c{}", i % 4), "increment", "");
        p.send(&format!("notes/n{}", i % 3), "add", &format!("note {i}"));
    }
    // Turns keep running while the snapshot is taken.
    let node = p.node.clone();
    let busy = p.rt.spawn(async move {
        for i in 0..200 {
            let _ = node
                .send(
                    ActorRef::parse(&format!("counter/b{}", i % 8)).unwrap(),
                    msg("increment", ""),
                    audit(),
                    false,
                )
                .await;
        }
    });
    let m = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    p.rt.block_on(busy).unwrap();
    assert!(m.files.iter().any(|f| f.path == "state.db"));
    assert_eq!(
        m.files
            .iter()
            .filter(|f| f.path.starts_with("sql/"))
            .count(),
        3
    );
    assert!(m.files.iter().any(|f| f.path == "secrets.db"));
    // The snapshot's state is exactly the log's up to its LSN.
    let upto = p.records(m.lsn);
    assert_eq!(rebuilt_hash(&upto), m.state_hash);
    let snap_dir = dir
        .path()
        .join("snapshots/main")
        .join(format!("{:020}", m.lsn));
    assert_eq!(
        Store::open_snapshot_in_memory(&snap_dir)
            .unwrap()
            .state_hash()
            .unwrap(),
        m.state_hash
    );
    // The log records it.
    let after = p.records(p.node.applied_lsn());
    assert!(after.iter().any(|c| matches!(&c.record, Record::SnapshotMarker(s) if s.lsn == m.lsn && s.snapshot_id == m.id)));
    // The same LSN twice gives the existing snapshot.
    let again = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    assert!(again.lsn >= m.lsn);
    let hash_before = p.node.store().state_hash().unwrap();
    drop(p);

    // Without state.db and the actor databases, startup installs the
    // newest snapshot and applies the rest of the log.
    let branch = dir.path().join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    std::fs::remove_dir_all(branch.join("sql")).unwrap();
    let p = start(dir.path(), 48);
    let now = p.node.store().state_hash().unwrap();
    // The second snapshot's marker (if any) was applied after the hash
    // above was taken; markers do not change state.
    assert_eq!(now, hash_before);
    p.send("counter/c0", "increment", "");
}

/// R1 (v0.1 re-review): a snapshot while an SQL turn has its savepoint
/// open (the test hook parks `add-call` after its call answered, between
/// its statements) succeeds and holds the applied rows only.
#[test]
fn a_snapshot_during_an_open_sql_turn_succeeds() {
    let dir = tempdir();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            storage: Some(StorageConfig::new(dir.path().to_path_buf())),
            test_hold_after_call: true,
            ..NodeConfig::default()
        };
        start_local(env, dir.path(), config).await.unwrap()
    });
    let p = Proc { rt, node };
    for g in ["counter", "notes-sql-call"] {
        p.rt.block_on(p.node.deploy(&guest(g), audit(), false))
            .unwrap();
    }
    p.send("notes/n", "add", "applied");
    let before = p.node.applied_lsn();
    let node = p.node.clone();
    let held = p.rt.spawn(async move {
        let to = ActorRef::parse("notes/n").unwrap();
        node.send(to, msg("add-call", "in the turn"), audit(), false)
            .await
    });
    // The callee's turn commits; the caller then parks with its row open.
    for _ in 0..500 {
        if p.node.applied_lsn() > before {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(p.node.applied_lsn() > before, "the call never answered");
    let m = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    assert_eq!(rebuilt_hash(&p.records(m.lsn)), m.state_hash);
    // The integrity hash (GET /v1/integrity) is the applied state's too
    // (v0.1 re-review M2).
    let applied = p.node.applied_lsn();
    let integrity = p.node.store().state_hash().unwrap();
    assert_eq!(integrity, rebuilt_hash(&p.records(applied)));
    // Its copy is gone again.
    let sql = dir.path().join("branches/main/sql");
    assert_eq!(sql_files(&sql, ".hash-copy-"), Vec::<String>::new());
    held.abort();
}

/// The files under `sql/<xx>/` whose names start with `prefix`.
fn sql_files(sql: &Path, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for d in std::fs::read_dir(sql).unwrap().flatten() {
        for e in std::fs::read_dir(d.path()).unwrap().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

/// v0.1 re-review: copies an interrupted integrity hash left next to an
/// actor database (a file and a staging directory) are deleted at the
/// next start; the database stays.
#[test]
fn copies_an_interrupted_state_hash_left_are_swept_at_start() {
    let dir = tempdir();
    let sql = dir.path().join("branches/main/sql");
    {
        let p = start(dir.path(), 5);
        p.rt.block_on(p.node.deploy(&guest("notes"), audit(), false))
            .unwrap();
        p.send("notes/n", "add", "kept");
    }
    let db = std::fs::read_dir(&sql)
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    std::fs::write(db.join(".hash-copy-n.db.tmp"), b"rows").unwrap();
    std::fs::create_dir(db.join(".hash-copy-n.db.committed")).unwrap();
    assert_eq!(sql_files(&sql, ".hash-copy-").len(), 2);
    let p = start(dir.path(), 5);
    assert_eq!(sql_files(&sql, ".hash-copy-"), Vec::<String>::new());
    let r =
        p.rt.block_on(p.node.send(
            ActorRef::parse("notes/n").unwrap(),
            msg("count", ""),
            audit(),
            false,
        ))
        .unwrap()
        .unwrap();
    assert!(r.committed(), "{r:?}");
}

/// R1 (v0.1 re-review): an erasure whose snapshot fails still succeeds
/// (the Erasure is committed), and the snapshot is retried until one at
/// or after the erasure exists.
#[test]
fn an_erasure_whose_snapshot_fails_succeeds_and_retries_it() {
    let dir = tempdir();
    let p = start(dir.path(), 5);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.send("counter/a", "increment", "");
    // Snapshots cannot be written while their directory is a file.
    let snapshots = kronik_sched::snapshots::snapshots_dir(dir.path(), "main");
    let _ = std::fs::remove_dir_all(&snapshots);
    std::fs::create_dir_all(snapshots.parent().unwrap()).unwrap();
    std::fs::write(&snapshots, b"not a directory").unwrap();
    let done =
        p.rt.block_on(p.node.erase_subject("user:1", audit(), false))
            .unwrap();
    let erased = done.lsn.unwrap();
    std::fs::remove_file(&snapshots).unwrap();
    // The background retry runs every 30 s.
    for _ in 0..450 {
        if kronik_sched::snapshots::list(dir.path(), "main")
            .iter()
            .any(|(_, m)| m.lsn >= erased)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("no snapshot at or after the erasure at {erased}");
}

#[test]
fn old_snapshots_are_pruned_to_the_number_kept() {
    let dir = tempdir();
    let p = start(dir.path(), 2);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    let mut lsns = Vec::new();
    for i in 0..4 {
        p.send(&format!("counter/k{i}"), "increment", "");
        lsns.push(p.rt.block_on(p.node.snapshot("manual")).unwrap().lsn);
    }
    let kept: Vec<u64> = p.node.snapshots().unwrap().iter().map(|m| m.lsn).collect();
    assert_eq!(kept, lsns[2..].to_vec());
}

/// The stop of `kronik serve` (`Node::shutdown_snapshot`, then the node
/// goes): two stops with no turn in between write one snapshot and one
/// marker; a turn in between makes the next stop snapshot again.
#[test]
fn an_idle_restart_takes_no_shutdown_snapshot() {
    let dir = tempdir();
    let p = start(dir.path(), 48);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.send("counter/a", "increment", "");
    let first = p.rt.block_on(p.node.shutdown_snapshot()).unwrap().unwrap();
    drop(p);

    let p = start(dir.path(), 48);
    assert!(p.rt.block_on(p.node.shutdown_snapshot()).unwrap().is_none());
    assert_eq!(p.node.snapshots().unwrap().len(), 1);
    assert_eq!(p.markers(), 1);
    drop(p);

    let p = start(dir.path(), 48);
    p.send("counter/a", "increment", "");
    let second = p.rt.block_on(p.node.shutdown_snapshot()).unwrap().unwrap();
    assert!(second.lsn > first.lsn, "{} {}", second.lsn, first.lsn);
    assert_eq!(p.node.snapshots().unwrap().len(), 2);
    assert_eq!(p.markers(), 2);
}

/// The interval task: an idle node takes no snapshot, interval after
/// interval; a turn makes the next interval snapshot again.
#[test]
fn an_idle_node_takes_no_interval_snapshot() {
    let dir = tempdir();
    // The setup runs before the task's first tick (the default is an hour).
    let p = start(dir.path(), 48);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.send("counter/a", "increment", "");
    drop(p);

    let every = Duration::from_millis(20);
    let p = start_with(dir.path(), 48, None, None, Some(every));
    // Snapshots and markers once the task has taken `n` and then let 20
    // more intervals pass.
    let after = |n: usize| {
        for _ in 0..1000 {
            if p.node.snapshots().unwrap().len() >= n {
                break;
            }
            std::thread::sleep(every / 2);
        }
        std::thread::sleep(every * 20);
        (p.node.snapshots().unwrap().len(), p.markers())
    };
    assert_eq!(after(1), (1, 1));
    p.send("counter/a", "increment", "");
    assert_eq!(after(2), (2, 2));
}

#[test]
fn retention_deletes_old_segments_a_snapshot_covers() {
    let dir = tempdir();
    let log_dir = dir.path().join("branches/main/log");
    let p = start_with(dir.path(), 2, Some(Duration::ZERO), Some(4096), None);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    for i in 0..80 {
        p.send(&format!("counter/k{}", i % 5), "increment", "");
        if i % 20 == 19 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let before = kronik_log::segment_starts(&log_dir).unwrap();
    assert!(before.len() > 3, "{before:?}");
    assert_eq!(before[0], 1);
    // Without a snapshot nothing is deleted.
    let storage = StorageConfig {
        history: std::time::Duration::ZERO,
        ..StorageConfig::new(dir.path().to_path_buf())
    };
    assert_eq!(p.node.compact(&storage).unwrap(), 1);
    // A snapshot covers them: closed segments past the window go.
    let m = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    let after = kronik_log::segment_starts(&log_dir).unwrap();
    assert!(
        after[0] > 1 && after[0] <= m.lsn + 1,
        "{after:?} snapshot {}",
        m.lsn
    );
    let hash = p.node.store().state_hash().unwrap();
    // The index forgets what the deleted segments held.
    let early = p.node.store().db().turn(2).unwrap();
    assert!(early.is_none());
    p.send("counter/k0", "increment", "");
    let hash_after_send = p.node.store().state_hash().unwrap();
    drop(p);
    // A restart with state.db works on the compacted log.
    let p = start_with(dir.path(), 2, Some(Duration::ZERO), Some(4096), None);
    assert_eq!(p.node.store().state_hash().unwrap(), hash_after_send);
    drop(p);
    // Without state.db the snapshot is installed and the log applied.
    let branch = dir.path().join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    let _ = std::fs::remove_dir_all(branch.join("sql"));
    let p = start_with(dir.path(), 2, Some(Duration::ZERO), Some(4096), None);
    assert_eq!(p.node.store().state_hash().unwrap(), hash_after_send);
    assert_ne!(hash, hash_after_send);
    drop(p);
    // Without state.db and without snapshots the gap is reported.
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    std::fs::remove_dir_all(dir.path().join("snapshots")).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(async {
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                dir.path(),
                NodeConfig::default(),
            )
            .await
        })
        .err()
        .unwrap();
    assert!(err.to_string().contains("no snapshot reaches it"), "{err}");
}

/// What `state.db` holds after the log is applied: the state hash and the
/// tables it leaves out.
fn applied_state(p: &Proc) -> Vec<String> {
    let mut out = vec![p.node.store().state_hash().unwrap()];
    let store = p.node.store();
    let db = store.db();
    for table in [
        "turn_index",
        "trees",
        "open_turns",
        "open_effects",
        "segments",
        "meta",
    ] {
        let mut st = db
            .conn()
            .prepare(&format!("SELECT * FROM {table}"))
            .unwrap();
        let n = st.column_count();
        let mut rows: Vec<String> = st
            .query_map([], |r| {
                (0..n)
                    .map(|i| r.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap()
            .map(|r| format!("{table} {:?}", r.unwrap()))
            .collect();
        rows.sort();
        out.extend(rows);
    }
    out
}

fn has_actor_index(p: &Proc) -> bool {
    let store = p.node.store();
    let db = store.db();
    db.conn()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'turn_index_actor'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        == 1
}

const SEGMENT: Option<u64> = Some(256 * 1024);

/// A snapshot, then a log past the bulk threshold over many segments:
/// segments of simple HTTP turns and some with message, SQL and call turns,
/// at least one call turn with its `TurnBegin` and `TurnRecord` in
/// different segments (the startup replay applies each segment on its
/// own). Returns the live node's applied state; state.db and sql/ are
/// removed.
fn record_long_gap(dir: &Path) -> Vec<String> {
    let p = start_with(dir, 2, None, SEGMENT, None);
    p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
        .unwrap();
    p.rt.block_on(p.node.deploy(&guest("notes"), audit(), false))
        .unwrap();
    let snapshot = p.rt.block_on(p.node.snapshot("manual")).unwrap();
    for round in 0.. {
        if round >= 40 && a_turn_spans_segments(&p, dir) {
            break;
        }
        assert!(round < 200, "no call turn spans two segments");
        if round % 10 == 5 {
            p.send("counter/k0", "increment", "");
            p.send("notes/n0", "add", &format!("note {round}"));
        }
        // Calls into actors the round's requests also increment: the call
        // turn ends behind them, many records after it began.
        let calls: Vec<_> = (0..4)
            .map(|i| {
                let node = p.node.clone();
                let callee = format!("counter/k{} increment", (round * 7 + i * 61) % 256);
                p.rt.spawn(async move {
                    node.send(
                        ActorRef::parse(&format!("counter/c{i}")).unwrap(),
                        msg("call", &callee),
                        audit(),
                        false,
                    )
                    .await
                })
            })
            .collect();
        let mut waiters = Vec::new();
        for a in 0..256 {
            let key = format!("k{a}");
            let http = pb::HttpInput {
                method: "POST".into(),
                path: format!("/counter/{key}/increment"),
                params: vec![
                    pb::Param {
                        name: "key".into(),
                        value: key.clone(),
                        sealed_value: None,
                    },
                    pb::Param {
                        name: "op".into(),
                        value: "increment".into(),
                        sealed_value: None,
                    },
                ],
                route: "/counter/{key}/{op}".into(),
                ..Default::default()
            };
            let actor = ActorRef::parse(&format!("counter/{key}")).unwrap();
            match p.node.ingress(actor, http, None).unwrap() {
                Ingress::Started(w) | Ingress::Joined(w) => waiters.push(w),
                Ingress::Done(_) => {}
            }
        }
        for w in waiters {
            assert!(p.rt.block_on(w.wait()).unwrap().committed());
        }
        for c in calls {
            let r = p.rt.block_on(c).unwrap().unwrap().unwrap();
            assert!(r.committed(), "{r:?}");
        }
    }
    let last = p.records(u64::MAX).last().unwrap().lsn;
    p.rt.block_on(p.node.store().applied.wait(last));
    assert!(last - snapshot.lsn > 8_192, "{last}");
    let segments = kronik_log::segment_starts(&dir.join("branches/main/log")).unwrap();
    assert!(segments.len() > 4, "{segments:?}");
    // Every node has the actor history index, not only after a bulk replay.
    assert!(has_actor_index(&p));
    let live = applied_state(&p);
    drop(p);
    let branch = dir.join("branches/main");
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let _ = std::fs::remove_file(branch.join(f));
    }
    std::fs::remove_dir_all(branch.join("sql")).unwrap();
    live
}

/// Whether a turn's `TurnBegin` and `TurnRecord` are in different segments.
fn a_turn_spans_segments(p: &Proc, dir: &Path) -> bool {
    let segments = kronik_log::segment_starts(&dir.join("branches/main/log")).unwrap();
    let segment = |lsn: u64| segments.iter().rposition(|s| *s <= lsn);
    let mut begun = std::collections::HashMap::new();
    p.records(u64::MAX).iter().any(|c| match &c.record {
        Record::TurnBegin(b) => {
            begun.insert(b.execution_id.clone(), c.lsn);
            false
        }
        Record::TurnRecord(t) => begun
            .get(&t.execution_id)
            .is_some_and(|&b| segment(b) != segment(c.lsn)),
        _ => false,
    })
}

/// A gap past the bulk threshold replays to the state the live applier
/// reached: segments of simple HTTP turns through the catch-up rows,
/// segments with message and SQL turns the normal way.
#[test]
fn a_long_gap_replays_to_the_live_state() {
    let dir = tempdir();
    let live = record_long_gap(dir.path());
    let p = start_with(dir.path(), 2, None, SEGMENT, None);
    assert!(applied_state(&p) == live, "the replayed state differs");
    assert!(has_actor_index(&p));
    assert!(!dir.path().join("branches/main/state.db-bulk").exists());
    p.send("counter/k0", "increment", "");
}

/// A bulk replay that fails partway (here at a damaged closed segment,
/// after it applied the segments before it) keeps its marker: journaling
/// was off, so the next start must rebuild state.db rather than trust it.
#[test]
fn a_failed_bulk_replay_keeps_its_marker() {
    let dir = tempdir();
    record_long_gap(dir.path());
    let log = dir.path().join("branches/main/log");
    let segments = kronik_log::segment_starts(&log).unwrap();
    let damaged = log.join(kronik_log::segment_name(segments[segments.len() - 2]));
    let mut bytes = std::fs::read(&damaged).unwrap();
    let mid = bytes.len() / 2;
    for b in &mut bytes[mid..mid + 64] {
        *b ^= 0xff;
    }
    std::fs::write(&damaged, bytes).unwrap();
    let (_rt, node) = try_start_with(dir.path(), 2, None, SEGMENT, None);
    assert!(node.is_err(), "the damaged segment was replayed");
    assert!(dir.path().join("branches/main/state.db-bulk").exists());
}

/// Run by `a_crash_during_a_bulk_replay_rebuilds_on_the_next_start` in a
/// child process, which it kills during the startup replay.
#[test]
#[ignore = "a helper process of the bulk replay crash test"]
fn bulk_replay_child() {
    let Ok(dir) = std::env::var("KRONIK_TEST_CRASH_DIR") else {
        return;
    };
    let _p = start_with(Path::new(&dir), 2, None, SEGMENT, None);
    std::thread::sleep(std::time::Duration::from_secs(600));
}

/// A crash during a bulk replay (journaling off) leaves its marker; the
/// next start discards the half-applied, possibly torn state.db and gets
/// the state a clean replay gives.
#[test]
fn a_crash_during_a_bulk_replay_rebuilds_on_the_next_start() {
    let dir = tempdir();
    let live = record_long_gap(dir.path());
    let branch = dir.path().join("branches/main");
    let state = branch.join("state.db");
    let marker = branch.join("state.db-bulk");
    let mut crashed = false;
    for _attempt in 0..5 {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "bulk_replay_child",
                "--exact",
                "--ignored",
                "--test-threads=1",
            ])
            .env("KRONIK_TEST_CRASH_DIR", dir.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Kill it once the replay has committed some of the log.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut seen = false;
        while std::time::Instant::now() < deadline {
            let present = marker.exists();
            if (seen && !present) || child.try_wait().unwrap().is_some() {
                break;
            }
            seen |= present;
            // `immutable`: no locks, so the child never waits on us.
            let applied = if present {
                rusqlite::Connection::open_with_flags(
                    format!("file:{}?immutable=1", state.display()),
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                )
                .and_then(|c| {
                    c.query_row("SELECT v FROM meta WHERE k = 'applied_lsn'", [], |r| {
                        r.get::<_, i64>(0)
                    })
                })
                .unwrap_or(0)
            } else {
                0
            };
            if applied > 2_000 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        if marker.exists() {
            crashed = true;
            break;
        }
        // The replay finished first: start over from the snapshot.
        for f in ["state.db", "state.db-wal", "state.db-shm"] {
            let _ = std::fs::remove_file(branch.join(f));
        }
        let _ = std::fs::remove_dir_all(branch.join("sql"));
    }
    assert!(crashed, "no attempt crashed during the replay");
    // A torn write as well: garbage over a page in the middle.
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&state)
            .unwrap();
        f.seek(SeekFrom::Start(65_536)).unwrap();
        f.write_all(&[0xA5; 4096]).unwrap();
    }
    let p = start_with(dir.path(), 2, None, SEGMENT, None);
    assert!(!marker.exists());
    assert!(applied_state(&p) == live, "the rebuilt state differs");
    p.send("counter/k0", "increment", "");
}

fn start_reserving(dir: &Path, kept: usize, disk_reserve: u64) -> Proc {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let mut storage = StorageConfig::new(dir.to_path_buf());
        storage.snapshots_kept = kept;
        start_local(
            env,
            dir,
            NodeConfig {
                concurrency: 8,
                storage: Some(storage),
                disk_reserve,
                ..NodeConfig::default()
            },
        )
        .await
        .unwrap()
    });
    Proc { rt, node }
}

/// An HTTP increment with an `Idempotency-Key` (request hash v2).
fn keyed_increment(
    p: &Proc,
    key: &str,
) -> Result<kronik_sched::TurnResult, kronik_core::error::ApiError> {
    let http = pb::HttpInput {
        method: "POST".into(),
        path: "/counter/a/increment".into(),
        params: vec![
            pb::Param {
                name: "key".into(),
                value: "a".into(),
                sealed_value: None,
            },
            pb::Param {
                name: "op".into(),
                value: "increment".into(),
                sealed_value: None,
            },
        ],
        route: "/counter/{key}/{op}".into(),
        idempotency_key: key.into(),
        request_hash: [&[kronik_sched::INGRESS_HASH_VERSION][..], &[7; 32]].concat(),
        ..Default::default()
    };
    p.rt.block_on(async {
        match p
            .node
            .ingress(ActorRef::parse("counter/a").unwrap(), http, None)?
        {
            Ingress::Started(w) | Ingress::Joined(w) => w.wait().await,
            Ingress::Done(r) => Ok(*r),
        }
    })
}

/// Below `[log] disk_reserve` new work is refused, but what an incident
/// needs still works: rollback, `foreign remove`, revoke, limits and an
/// idempotent retry (it writes nothing). Retention deletes old snapshots
/// although no new one is taken, so the node can climb back above the
/// reserve.
#[test]
fn below_the_disk_reserve_incident_actions_and_retention_still_work() {
    let dir = tempfile::tempdir().unwrap();
    {
        let p = start_reserving(dir.path(), 10, 0);
        p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
            .unwrap();
        for _ in 0..3 {
            p.send("counter/a", "increment", "");
            p.rt.block_on(p.node.snapshot("manual")).unwrap();
        }
        p.rt.block_on(
            p.node
                .grant("counter", "http:example.com", None, None, audit(), false),
        )
        .unwrap();
        let foreign = pb::ForeignActor {
            name: "pay".into(),
            image: format!("oci-layout:/srv/pay@sha256:{}", "0".repeat(64)),
            port: 8080,
            isolation: pb::Isolation::Gvisor as i32,
            platform: "systrap".into(),
            ..Default::default()
        };
        p.rt.block_on(p.node.foreign_add(foreign, audit(), false))
            .unwrap();
        assert!(keyed_increment(&p, "k1").unwrap().committed());
    }
    // More than any disk has: the reserve is never met.
    let p = start_reserving(dir.path(), 1, u64::MAX);
    assert!(p.node.disk_below_reserve().is_some());
    let refused =
        p.rt.block_on(p.node.send(
            ActorRef::parse("counter/a").unwrap(),
            msg("increment", ""),
            audit(),
            false,
        ))
        .unwrap_err();
    assert_eq!(refused.code, kronik_core::error::ErrorCode::Unavailable);
    // No new snapshot, but the two beyond `snapshots_kept` go.
    assert_eq!(p.node.snapshots().unwrap().len(), 3);
    p.rt.block_on(p.node.snapshot("interval")).unwrap_err();
    assert_eq!(p.node.snapshots().unwrap().len(), 1);
    // The saved response of the retry, not a 503.
    assert!(keyed_increment(&p, "k1").unwrap().committed());
    let bytes = guest("counter-step2");
    let (hash, _, manifest) = p.rt.block_on(p.node.prepare_code(&bytes)).unwrap();
    let rollback = kronik_sched::CodeSwitch {
        kinds: vec![pb::KindVersion {
            kind: manifest.kind.clone(),
            code_hash: hash.0.to_vec(),
            schema_version: manifest.schema_version,
            manifest: Some(manifest),
            code_size: bytes.len() as u64,
        }],
        pinned: vec![],
        cause: pb::DeploymentCause::Rollback,
        verified_through_lsn: 0,
        unverified_inputs: 0,
        proposal_id: String::new(),
        rollback_of_epoch: 1,
    };
    p.rt.block_on(p.node.switch_code(rollback, audit(), false))
        .unwrap();
    p.rt.block_on(p.node.revoke("counter", "http:example.com", audit(), false))
        .unwrap();
    let limits = pb::Limits {
        kind: "counter".into(),
        ..Default::default()
    };
    p.rt.block_on(p.node.set_limits(limits, audit(), false))
        .unwrap();
    p.rt.block_on(p.node.foreign_remove("pay", audit(), false))
        .unwrap();
    assert_eq!(p.node.fatal(), None);
}

/// What a failed or interrupted snapshot leaves (`.tmp-*` copies, a
/// snapshot directory without its manifest) is deleted: at the next start,
/// and by retention also when the snapshot itself is refused below the
/// reserve. Before, nothing deleted them and they held their space forever.
#[test]
fn partial_snapshots_are_swept() {
    let dir = tempfile::tempdir().unwrap();
    let root = kronik_sched::snapshots::snapshots_dir(dir.path(), "main");
    let leave_partials = || {
        std::fs::create_dir_all(root.join(".tmp-0011223344556677/sql")).unwrap();
        std::fs::write(root.join(".tmp-0011223344556677/state.db"), b"partial").unwrap();
        // An LSN no snapshot of this test has: a directory without manifest.
        std::fs::create_dir_all(root.join("00000000000000000099")).unwrap();
        std::fs::write(root.join("00000000000000000099/state.db"), b"partial").unwrap();
    };
    let names = || -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    {
        let p = start_reserving(dir.path(), 10, 0);
        p.rt.block_on(p.node.deploy(&guest("counter"), audit(), false))
            .unwrap();
        p.send("counter/a", "increment", "");
        p.rt.block_on(p.node.snapshot("manual")).unwrap();
        leave_partials();
    }
    // At start.
    let p = start_reserving(dir.path(), 10, 0);
    assert_eq!(names().len(), 1, "{:?}", names());
    drop(p);
    // By retention, with the snapshot refused below the reserve.
    leave_partials();
    std::fs::create_dir_all(root.join(".tmp-later")).unwrap();
    let p = start_reserving(dir.path(), 10, u64::MAX);
    std::fs::create_dir_all(root.join(".tmp-8899aabbccddeeff")).unwrap();
    p.rt.block_on(p.node.snapshot("interval")).unwrap_err();
    assert_eq!(names().len(), 1, "{:?}", names());
    assert_eq!(p.node.snapshots().unwrap().len(), 1);
}
