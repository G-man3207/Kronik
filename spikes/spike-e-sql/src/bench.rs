//! Cost measurements for ADR 0005.

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::types::Value;

use crate::checks::{Stmt, actor, commit, migrate_opts, s, sp, turn};
use crate::sqlstate::{FileOpener, MemOpener, SqlActor, SqliteOpener, TurnOpts};

struct Stats {
    p50: Duration,
    p99: Duration,
    mean: Duration,
}

fn stats(mut v: Vec<Duration>) -> Stats {
    v.sort();
    let pct = |p: f64| v[((v.len() as f64 - 1.0) * p).round() as usize];
    let mean = v.iter().sum::<Duration>() / v.len().max(1) as u32;
    Stats {
        p50: pct(0.5),
        p99: pct(0.99),
        mean,
    }
}

fn fmt(s: &Stats) -> String {
    format!(
        "p50 {:>8.1?}  p99 {:>8.1?}  mean {:>8.1?}",
        s.p50, s.p99, s.mean
    )
}

const SCHEMA: &[&str] = &[
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, _subject TEXT)",
    "CREATE TABLE counters (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
];

/// The benchmark turn: insert a note, bump a counter, every 5th turn delete
/// the oldest note.
fn bench_turn(i: u64) -> Vec<Stmt> {
    let mut v = vec![
        sp(
            "INSERT INTO notes (body, _subject) VALUES (?1, 'user:1')",
            vec![Value::Text(format!("note number {i} with some text"))],
        ),
        s("INSERT INTO counters (k, v) VALUES ('n', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1"),
    ];
    if i.is_multiple_of(5) {
        v.push(s(
            "DELETE FROM notes WHERE id = (SELECT min(id) FROM notes)",
        ));
    }
    v
}

fn setup(opener: &dyn SqliteOpener, name: &str) -> SqlActor {
    let mut a = actor(opener, name);
    let schema: Vec<Stmt> = SCHEMA.iter().map(|q| s(q)).collect();
    commit(&mut a, &migrate_opts(), &schema, 1);
    a
}

fn per_turn(opener: &dyn SqliteOpener, label: &str, n: u64) {
    let none = BTreeSet::new();
    // Kronik path: savepoint + session + changeset + split + rollback + apply.
    let mut a = setup(opener, &format!("bench-{label}-kronik"));
    let (mut exec, mut capture, mut apply, mut total) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for i in 0..n {
        let opts = TurnOpts::new((i % 251) as u8, 1_761_300_000_000 + i as i64);
        let stmts = bench_turn(i);
        let t0 = Instant::now();
        a.begin_turn(&opts).unwrap_or_else(|e| panic!("{e}"));
        for (q, p) in &stmts {
            a.execute(q, p).unwrap_or_else(|e| panic!("{e:?}"));
        }
        let t1 = Instant::now();
        let ts = a.end_turn(true).unwrap_or_else(|e| panic!("{e}"));
        let t2 = Instant::now();
        a.apply(&ts, i + 2, &none).unwrap_or_else(|e| panic!("{e}"));
        let t3 = Instant::now();
        exec.push(t1 - t0);
        capture.push(t2 - t1);
        apply.push(t3 - t2);
        total.push(t3 - t0);
    }
    // Baseline: the same statements executed directly in a transaction.
    let mut d = setup(opener, &format!("bench-{label}-direct"));
    let mut direct = Vec::new();
    for i in 0..n {
        let opts = TurnOpts::new((i % 251) as u8, 1_761_300_000_000 + i as i64);
        let stmts = bench_turn(i);
        let refs: Vec<(&str, Vec<Value>)> =
            stmts.iter().map(|(q, p)| (q.as_str(), p.clone())).collect();
        let t0 = Instant::now();
        d.direct(&opts, &refs).unwrap_or_else(|e| panic!("{e}"));
        direct.push(t0.elapsed());
    }
    println!("[{label}] {n} turns of INSERT + UPSERT (+ DELETE every 5th)");
    println!(
        "  direct (BEGIN; stmts; COMMIT)         {}",
        fmt(&stats(direct))
    );
    println!(
        "  kronik total                          {}",
        fmt(&stats(total))
    );
    println!(
        "    execute in savepoint + session      {}",
        fmt(&stats(exec))
    );
    println!(
        "    changeset + split + rollback        {}",
        fmt(&stats(capture))
    );
    println!(
        "    apply (savepoint, changeset, meta)  {}",
        fmt(&stats(apply))
    );
}

fn open_close(root: &Path, n: usize) {
    let opener = FileOpener {
        root: root.to_path_buf(),
    };
    for i in 0..n {
        let mut a = setup(&opener, &format!("oc/{i}"));
        commit(&mut a, &TurnOpts::new(1, 1), &bench_turn(1), 2);
    }
    let (mut open, mut first, mut close) = (Vec::new(), Vec::new(), Vec::new());
    for round in 0..3 {
        for i in 0..n {
            let t0 = Instant::now();
            let mut a = SqlActor::open(&opener, &format!("oc/{i}"), Default::default())
                .unwrap_or_else(|e| panic!("{e}"));
            let t1 = Instant::now();
            let _ = turn(
                &mut a,
                &TurnOpts::new(1, 1),
                &[s("SELECT count(*) FROM notes")],
            );
            let t2 = Instant::now();
            drop(a);
            let t3 = Instant::now();
            if round > 0 {
                open.push(t1 - t0);
                first.push(t2 - t1);
                close.push(t3 - t2);
            }
        }
    }
    println!("[open/close] {n} existing actor files, warm page cache");
    println!(
        "  open + configure (VFS, functions, authorizer, pragmas) {}",
        fmt(&stats(open))
    );
    println!(
        "  first read turn (schema load)                          {}",
        fmt(&stats(first))
    );
    println!(
        "  close (no checkpoint on close)                         {}",
        fmt(&stats(close))
    );
}

fn dir_size(p: &Path) -> (u64, u64) {
    let mut bytes = 0;
    let mut files = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                let (b, f) = dir_size(&path);
                bytes += b;
                files += f;
            } else if let Ok(m) = e.metadata() {
                bytes += m.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

/// N actor files, random access with an LRU of open connections.
fn scaling(root: &Path, actors: usize, lru_cap: usize, turns: usize) {
    let opener = FileOpener {
        root: root.to_path_buf(),
    };
    let t = Instant::now();
    for i in 0..actors {
        let mut a = setup(&opener, &format!("scale/{i}"));
        commit(&mut a, &TurnOpts::new(1, 1), &bench_turn(1), 2);
    }
    let create = t.elapsed();
    let (bytes, files) = dir_size(root);
    println!(
        "[scale] {actors} actor databases created in {:.1?} ({:.0} µs each); {files} files, {:.1} MiB ({:.1} KiB per actor)",
        create,
        create.as_micros() as f64 / actors as f64,
        bytes as f64 / (1 << 20) as f64,
        bytes as f64 / 1024.0 / actors as f64
    );
    let mut lru: VecDeque<(usize, SqlActor)> = VecDeque::new();
    let mut rng = 0x9e3779b97f4a7c15u64;
    let (mut hits, mut misses) = (0, 0);
    let none = BTreeSet::new();
    let t = Instant::now();
    let mut lat = Vec::with_capacity(turns);
    for k in 0..turns {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let id = (rng % actors as u64) as usize;
        let t0 = Instant::now();
        let pos = lru.iter().position(|(i, _)| *i == id);
        let mut a = match pos {
            Some(p) => {
                hits += 1;
                lru.remove(p)
                    .map(|(_, a)| a)
                    .unwrap_or_else(|| unreachable!())
            }
            None => {
                misses += 1;
                if lru.len() >= lru_cap {
                    lru.pop_back();
                }
                SqlActor::open(&opener, &format!("scale/{id}"), Default::default())
                    .unwrap_or_else(|e| panic!("{e}"))
            }
        };
        let lsn = a.applied_lsn().unwrap_or(0) + 1;
        let opts = TurnOpts::new((k % 251) as u8, 1_761_300_000_000 + k as i64);
        let (ts, res) = turn(&mut a, &opts, &bench_turn(k as u64));
        if res.iter().all(Result::is_ok) {
            a.apply(&ts, lsn, &none).unwrap_or_else(|e| panic!("{e}"));
        }
        lat.push(t0.elapsed());
        lru.push_front((id, a));
    }
    let el = t.elapsed();
    println!(
        "[scale] {turns} turns over {actors} actors, LRU {lru_cap}: {:.0} turns/s, hit rate {:.1}%, latency {}",
        turns as f64 / el.as_secs_f64(),
        100.0 * hits as f64 / (hits + misses) as f64,
        fmt(&stats(lat))
    );
}

/// Snapshot and roll-forward costs for "SQL state at LSN".
fn at_lsn_costs() {
    let none = BTreeSet::new();
    let mut p = setup(&MemOpener, "lsn-bench");
    let mut log = Vec::new();
    for i in 0..2000u64 {
        let (ts, _) = commit(
            &mut p,
            &TurnOpts::new((i % 251) as u8, i as i64),
            &bench_turn(i),
            i + 2,
        );
        log.push((i + 2, ts));
    }
    let bytes = {
        p.set_host();
        p.conn
            .query_row(
                "SELECT page_count * page_size FROM pragma_page_count, pragma_page_size",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
    };
    let t = Instant::now();
    let _snap = crate::checks::snapshot(&p, "lsn-bench-snap");
    let snap_time = t.elapsed();
    let mut cursor = setup(&MemOpener, "lsn-bench-cursor");
    let t = Instant::now();
    for (lsn, ts) in &log {
        cursor
            .apply(ts, *lsn, &none)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let roll = t.elapsed();
    let t = Instant::now();
    let back = crate::checks::snapshot(&p, "lsn-bench-back");
    for (_, ts) in log.iter().rev().take(1000) {
        for (_, cs) in ts.changesets.iter().rev() {
            let inv = crate::ffi::invert(cs).unwrap_or_else(|e| panic!("{e}"));
            back.set_host();
            crate::ffi::apply(&back.conn, &inv).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    let inv = t.elapsed();
    let cs_bytes: usize = log
        .iter()
        .flat_map(|(_, t)| t.changesets.iter().map(|(_, c)| c.len()))
        .sum();
    println!(
        "[at-lsn] actor with 2000 turns, {:.0} KiB database, {} changeset bytes total",
        bytes as f64 / 1024.0,
        cs_bytes
    );
    println!("  snapshot (backup API, in memory)  {:.1?}", snap_time);
    println!(
        "  roll forward 2000 changesets      {:.1?} ({:.1} µs each)",
        roll,
        roll.as_micros() as f64 / 2000.0
    );
    println!(
        "  invert + apply 1000 back from HEAD {:.1?} ({:.1} µs each)",
        inv,
        inv.as_micros() as f64 / 1000.0
    );
}

pub fn run(actors: usize, dir: &Path) -> bool {
    let _ = std::fs::remove_dir_all(dir);
    per_turn(&MemOpener, "memory", 20_000);
    per_turn(
        &FileOpener {
            root: dir.join("per-turn"),
        },
        "file WAL",
        20_000,
    );
    open_close(&dir.join("open-close"), 2000);
    open_profile(&dir.join("open-profile"));
    scaling(&dir.join("scale-hot"), 256, 256, 20_000);
    scaling(&dir.join("scale"), actors, 256, 20_000);
    at_lsn_costs();
    let _ = std::fs::remove_dir_all(dir);
    true
}

/// Where the open cost goes (warm page cache).
pub fn open_profile(root: &Path) {
    let opener = FileOpener {
        root: root.to_path_buf(),
    };
    let n = 500;
    for i in 0..n {
        let mut a = setup(&opener, &format!("op/{i}"));
        commit(&mut a, &TurnOpts::new(1, 1), &bench_turn(1), 2);
    }
    let path = |i: usize| crate::sqlstate::actor_file(root, &format!("op/{i}"));
    let time = |f: &mut dyn FnMut(usize)| {
        let t = Instant::now();
        for i in 0..n {
            f(i);
        }
        t.elapsed() / n as u32
    };
    let raw = time(&mut |i| {
        let c = rusqlite::Connection::open(path(i)).unwrap_or_else(|e| panic!("{e}"));
        let _: i64 = c
            .query_row("SELECT count(*) FROM notes", [], |r| r.get(0))
            .unwrap_or(0);
    });
    let vfs = time(&mut |_| {
        let v = crate::ffi::TimeVfs::new().unwrap_or_else(|e| panic!("{e}"));
        drop(v);
    });
    let pragmas = time(&mut |i| {
        let v = crate::ffi::TimeVfs::new().unwrap_or_else(|e| panic!("{e}"));
        let c = opener
            .open(&format!("op/{i}"), v.name())
            .unwrap_or_else(|e| panic!("{e}"));
        let _: i64 = c
            .query_row("SELECT count(*) FROM notes", [], |r| r.get(0))
            .unwrap_or(0);
        drop(c);
    });
    let full = time(&mut |i| {
        let a = SqlActor::open(&opener, &format!("op/{i}"), Default::default())
            .unwrap_or_else(|e| panic!("{e}"));
        drop(a);
    });
    println!(
        "[open profile] per open, warm cache: plain open + query {raw:?}; TimeVfs register/unregister {vfs:?}; opener (VFS + WAL/exclusive pragmas) + query {pragmas:?}; full SqlActor::open {full:?}"
    );
}
