//! Spike E acceptance checks. Each check prints PASS/FAIL with evidence.

use std::collections::BTreeSet;
use std::time::Instant;

use chacha20::ChaCha8Rng;
use chacha20::rand_core::{Rng, SeedableRng};
use rusqlite::Connection;
use rusqlite::types::Value;

use crate::ffi::{self, Op};
use crate::sqlstate::{
    FileOpener, Limits, MemOpener, Rows, SqlActor, SqlError, SqlResult, SqliteOpener, TurnOpts,
    TurnSql,
};

pub struct Report {
    pub failures: u32,
}

impl Report {
    pub fn check(&mut self, name: &str, ok: bool, detail: impl AsRef<str>) {
        println!(
            "{}  {name}: {}",
            if ok { "PASS" } else { "FAIL" },
            detail.as_ref()
        );
        if !ok {
            self.failures += 1;
        }
    }
}

pub type Stmt = (String, Vec<Value>);

pub fn s(sql: &str) -> Stmt {
    (sql.to_string(), Vec::new())
}

pub fn sp(sql: &str, params: Vec<Value>) -> Stmt {
    (sql.to_string(), params)
}

pub fn actor(opener: &dyn SqliteOpener, name: &str) -> SqlActor {
    actor_with(opener, name, Limits::default())
}

pub fn actor_with(opener: &dyn SqliteOpener, name: &str, limits: Limits) -> SqlActor {
    SqlActor::open(opener, name, limits).unwrap_or_else(|e| panic!("open {name}: {e}"))
}

/// Runs one turn; commits when every statement succeeded.
pub fn turn(a: &mut SqlActor, opts: &TurnOpts, stmts: &[Stmt]) -> (TurnSql, Vec<SqlResult<Rows>>) {
    a.begin_turn(opts)
        .unwrap_or_else(|e| panic!("begin_turn: {e}"));
    let results: Vec<SqlResult<Rows>> = stmts.iter().map(|(q, p)| a.query(q, p)).collect();
    let ok = results.iter().all(Result::is_ok);
    let t = a.end_turn(ok).unwrap_or_else(|e| panic!("end_turn: {e}"));
    (t, results)
}

/// Runs and applies one turn (what the daemon does after the record is durable).
/// Returns the turn as it is written to the log: without the unsplit
/// changeset, so every rebuild below uses only the per-subject changesets.
pub fn commit(
    a: &mut SqlActor,
    opts: &TurnOpts,
    stmts: &[Stmt],
    lsn: u64,
) -> (TurnSql, Vec<SqlResult<Rows>>) {
    let (mut t, r) = turn(a, opts, stmts);
    if r.iter().all(Result::is_ok) {
        a.apply(&t, lsn, &BTreeSet::new())
            .unwrap_or_else(|e| panic!("apply lsn {lsn}: {e}"));
    }
    t.whole.clear();
    (t, r)
}

pub fn hash(a: &SqlActor) -> String {
    a.canonical_hash()
        .unwrap_or_else(|e| format!("hash error: {e}"))
}

pub const NOTES_SCHEMA: &[&str] = &[
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, _subject TEXT)",
    "CREATE TABLE counters (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
    "CREATE INDEX notes_body ON notes(body)",
];

pub fn migrate_opts() -> TurnOpts {
    let mut o = TurnOpts::new(1, 1_761_300_000_000);
    o.migrate = true;
    o
}

/// A deterministic mixed workload turn: inserts, an upsert, updates and,
/// every fourth turn, a delete.
pub fn workload(t: u64) -> Vec<Stmt> {
    let mut rng = ChaCha8Rng::seed_from_u64(t);
    let mut v = Vec::new();
    for i in 0..1 + rng.next_u64() % 3 {
        let subject = format!("user:{}", rng.next_u64() % 3);
        v.push(sp(
            "INSERT INTO notes (body, _subject) VALUES (?1, ?2)",
            vec![Value::Text(format!("note {t}.{i}")), Value::Text(subject)],
        ));
    }
    v.push(s(
        "INSERT INTO counters (k, v) VALUES ('turns', 1) ON CONFLICT(k) DO UPDATE SET v = v + 1",
    ));
    v.push(sp(
        "UPDATE notes SET body = body || '!' WHERE id % 3 = ?1",
        vec![Value::Integer((t % 3) as i64)],
    ));
    if t.is_multiple_of(4) {
        v.push(s(
            "DELETE FROM notes WHERE id = (SELECT min(id) FROM notes)",
        ));
    }
    v
}

fn count_ops(ts: &[TurnSql]) -> (usize, usize, usize) {
    let (mut i, mut u, mut d) = (0, 0, 0);
    for t in ts {
        for (_, cs) in &t.changesets {
            for c in ffi::changes(cs).unwrap_or_default() {
                match c.op {
                    Op::Insert => i += 1,
                    Op::Update => u += 1,
                    Op::Delete => d += 1,
                }
            }
        }
    }
    (i, u, d)
}

/// Check 1: savepoint + session + rollback + apply builds the same database
/// as direct execution, and a clean copy rebuilt from the changesets matches.
pub fn check_changesets(r: &mut Report, opener: &dyn SqliteOpener, label: &str) {
    let mut a = actor(opener, &format!("{label}/kronik"));
    let mut direct = actor(&MemOpener, &format!("{label}/direct"));
    let mut log = Vec::new();
    let schema: Vec<Stmt> = NOTES_SCHEMA.iter().map(|q| s(q)).collect();
    let (t, res) = commit(&mut a, &migrate_opts(), &schema, 1);
    let direct_stmts: Vec<(&str, Vec<Value>)> = schema
        .iter()
        .map(|(q, p)| (q.as_str(), p.clone()))
        .collect();
    direct
        .direct(&migrate_opts(), &direct_stmts)
        .unwrap_or_else(|e| panic!("direct: {e}"));
    let mut ok = res.iter().all(Result::is_ok) && t.ddl.len() == 3;
    log.push((1, t));
    let mut mismatch = None;
    for lsn in 2..=60u64 {
        let opts = TurnOpts::new(lsn as u8, 1_761_300_000_000 + lsn as i64);
        let stmts = workload(lsn);
        let (t, res) = commit(&mut a, &opts, &stmts, lsn);
        ok &= res.iter().all(Result::is_ok);
        let ds: Vec<(&str, Vec<Value>)> =
            stmts.iter().map(|(q, p)| (q.as_str(), p.clone())).collect();
        direct
            .direct(&opts, &ds)
            .unwrap_or_else(|e| panic!("direct: {e}"));
        if mismatch.is_none() && hash(&a) != hash(&direct) {
            mismatch = Some(lsn);
        }
        log.push((lsn, t));
    }
    let mut clean = actor(&MemOpener, &format!("{label}/clean"));
    for (lsn, t) in &log {
        if let Err(e) = clean.apply(t, *lsn, &BTreeSet::new()) {
            ok = false;
            println!("  clean apply {lsn}: {e}");
        }
    }
    let ts: Vec<TurnSql> = log.iter().map(|(_, t)| t.clone()).collect();
    let (i, u, d) = count_ops(&ts);
    let bytes: usize = ts
        .iter()
        .flat_map(|t| t.changesets.iter().map(|(_, c)| c.len()))
        .sum();
    r.check(
        &format!("changesets/{label}"),
        ok && mismatch.is_none() && hash(&clean) == hash(&a) && clean.applied_lsn().ok() == Some(60),
        format!(
            "60 turns ({i} inserts, {u} updates, {d} deletes, {bytes} changeset bytes): kronik {} = direct {} = clean copy {}",
            hash(&a),
            hash(&direct),
            hash(&clean)
        ),
    );
}

/// Check 2: why DDL may only come first in `migrate`, and that recorded DDL
/// replays before the changeset.
pub fn check_ddl(r: &mut Report) {
    // 2a. The raw mechanism, without Kronik's rule: DML, DDL, DML in one
    // session. The changeset is a per-row *net* result at the end of the
    // turn; recorded DDL is replayed as a separate list before it.
    let raw = |before: &str, ddl: &[&str], after: &str| -> (bool, String) {
        let conn = Connection::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
        let base = "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT); INSERT INTO t VALUES (1, 'x', 'p');";
        conn.execute_batch(base).unwrap_or_else(|e| panic!("{e}"));
        conn.execute_batch("SAVEPOINT turn")
            .unwrap_or_else(|e| panic!("{e}"));
        let session = ffi::Session::new(&conn, true).unwrap_or_else(|e| panic!("{e}"));
        let run = |q: &str| conn.execute_batch(q).map_err(|e| e.to_string());
        let mut errors = Vec::new();
        for q in std::iter::once(before)
            .chain(ddl.iter().copied())
            .chain(std::iter::once(after))
        {
            if !q.is_empty()
                && let Err(e) = run(q)
            {
                errors.push(format!("{q}: {e}"));
            }
        }
        let direct = crate::sqlstate::canonical_hash_raw(&conn).unwrap_or_default();
        let cs = session.changeset();
        drop(session);
        conn.execute_batch("ROLLBACK TO turn; RELEASE turn")
            .unwrap_or_else(|e| panic!("{e}"));
        let cs = match cs {
            Ok(cs) => cs,
            Err(e) => return (false, format!("changeset capture failed: {e}")),
        };
        let described: Vec<String> = ffi::changes(&cs)
            .unwrap_or_default()
            .iter()
            .map(|c| {
                format!(
                    "{:?} {}[{} cols]",
                    c.op,
                    c.table,
                    c.new.len().max(c.old.len())
                )
            })
            .collect();
        let clean = Connection::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
        clean.execute_batch(base).unwrap_or_else(|e| panic!("{e}"));
        clean
            .execute_batch("BEGIN")
            .unwrap_or_else(|e| panic!("{e}"));
        for d in ddl {
            clean.execute_batch(d).unwrap_or_else(|e| panic!("{e}"));
        }
        let applied = ffi::apply(&clean, &cs);
        clean
            .execute_batch("COMMIT")
            .unwrap_or_else(|e| panic!("{e}"));
        let rebuilt = crate::sqlstate::canonical_hash_raw(&clean).unwrap_or_default();
        let same = rebuilt == direct && applied.is_ok() && errors.is_empty();
        (
            same,
            format!(
                "changeset {described:?}; apply {}; rebuild {} direct{}",
                match &applied {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.clone(),
                },
                if rebuilt == direct { "==" } else { "!=" },
                if errors.is_empty() {
                    String::new()
                } else {
                    format!(" (errors {errors:?})")
                }
            ),
        )
    };
    let cases: &[(&str, &str, &[&str], &str)] = &[
        (
            "DDL first",
            "",
            &["ALTER TABLE t ADD COLUMN c TEXT"],
            "INSERT INTO t VALUES (2, 'y', 'q', 'r')",
        ),
        (
            "INSERT, ADD COLUMN, UPDATE",
            "INSERT INTO t VALUES (2, 'y', 'q')",
            &["ALTER TABLE t ADD COLUMN c TEXT"],
            "UPDATE t SET c = 'z' WHERE id = 1",
        ),
        (
            "UPDATE, DROP COLUMN",
            "UPDATE t SET b = 'changed' WHERE id = 1",
            &["ALTER TABLE t DROP COLUMN b"],
            "",
        ),
        (
            "INSERT, RENAME COLUMN, UPDATE",
            "INSERT INTO t VALUES (2, 'y', 'q')",
            &["ALTER TABLE t RENAME COLUMN a TO a2"],
            "UPDATE t SET a2 = 'z' WHERE id = 2",
        ),
        (
            "INSERT, RENAME TABLE, UPDATE",
            "INSERT INTO t VALUES (2, 'y', 'q')",
            &["ALTER TABLE t RENAME TO t2"],
            "UPDATE t2 SET a = 'z' WHERE id = 1",
        ),
        (
            "INSERT, DROP + CREATE TABLE, INSERT",
            "INSERT INTO t VALUES (2, 'y', 'q')",
            &[
                "DROP TABLE t",
                "CREATE TABLE t (id INTEGER PRIMARY KEY, z INTEGER)",
            ],
            "INSERT INTO t VALUES (7, 42)",
        ),
    ];
    let mut broken = Vec::new();
    for (name, before, ddl, after) in cases {
        let (same, detail) = raw(before, ddl, after);
        println!(
            "      {:<36} {} {detail}",
            name,
            if same { "same" } else { "DIFFERS" }
        );
        if !same {
            broken.push(*name);
        }
    }
    let first_ok = raw(cases[0].1, cases[0].2, cases[0].3).0;
    r.check(
        "ddl/mid-turn-breaks-rebuild",
        first_ok && !broken.is_empty(),
        format!("DDL before DML replays exactly; DDL after DML breaks the rebuild in: {broken:?}"),
    );

    // 2b. The rule.
    let mut a = actor(&MemOpener, "ddl/rule");
    let (_, res) = commit(
        &mut a,
        &migrate_opts(),
        &[s("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT)")],
        1,
    );
    let mut m = migrate_opts();
    m.seed = [2; 32];
    let (_, res2) = turn(
        &mut a,
        &m,
        &[
            s("INSERT INTO t VALUES (1, 'x')"),
            s("ALTER TABLE t ADD COLUMN b TEXT"),
        ],
    );
    let (_, res3) = turn(
        &mut a,
        &TurnOpts::new(3, 1),
        &[s("CREATE INDEX t_a ON t(a)")],
    );
    let after_dml = matches!(&res2[1], Err(SqlError::Denied(_)));
    let outside = matches!(&res3[0], Err(SqlError::Denied(_)));
    r.check(
        "ddl/rule",
        res.iter().all(Result::is_ok) && after_dml && outside,
        format!(
            "DDL after DML in migrate -> {:?}; DDL outside migrate -> {:?}",
            res2[1], res3[0]
        ),
    );

    // 2c. A proper migrate: DDL first, then DML; recorded DDL replays first.
    let mut a = actor(&MemOpener, "ddl/migrate");
    let (t1, _) = commit(
        &mut a,
        &migrate_opts(),
        &[s("CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT)")],
        1,
    );
    let (t2, _) = commit(
        &mut a,
        &TurnOpts::new(2, 2),
        &[s("INSERT INTO t (a) VALUES ('x'), ('y')")],
        2,
    );
    let mut m = migrate_opts();
    m.seed = [3; 32];
    let (t3, res) = commit(
        &mut a,
        &m,
        &[
            s("ALTER TABLE t ADD COLUMN b TEXT NOT NULL DEFAULT 'none'"),
            s("CREATE INDEX t_b ON t(b)"),
            s("UPDATE t SET b = upper(a)"),
            s("INSERT INTO t (a, b) VALUES ('z', 'Z')"),
        ],
        3,
    );
    let mut clean = actor(&MemOpener, "ddl/clean");
    let mut ok = res.iter().all(Result::is_ok) && t3.ddl.len() == 2;
    for (lsn, t) in [(1, &t1), (2, &t2), (3, &t3)] {
        ok &= clean.apply(t, lsn, &BTreeSet::new()).is_ok();
    }
    r.check(
        "ddl/recorded-and-replayed",
        ok && hash(&clean) == hash(&a),
        format!(
            "migrate recorded {:?}; rebuild {} = live {}",
            t3.ddl,
            hash(&clean),
            hash(&a)
        ),
    );
}

/// 3. Tables without PRIMARY KEY.
pub fn check_rowid(r: &mut Report) {
    let run = |track: bool| -> (String, String, usize) {
        let limits = Limits {
            track_rowid_tables: track,
            ..Limits::default()
        };
        let mut a = actor_with(&MemOpener, "rowid/a", limits);
        let mut log = vec![
            commit(
                &mut a,
                &migrate_opts(),
                &[s("CREATE TABLE events (kind TEXT, payload TEXT)")],
                1,
            )
            .0,
        ];
        log.push(
            commit(
                &mut a,
                &TurnOpts::new(2, 2),
                &[
                    s("INSERT INTO events VALUES ('a', 'x'), ('a', 'x'), ('b', 'y')"),
                    s("INSERT INTO events SELECT kind, payload || '2' FROM events"),
                ],
                2,
            )
            .0,
        );
        log.push(
            commit(
                &mut a,
                &TurnOpts::new(3, 3),
                &[
                    s("UPDATE events SET payload = 'u' WHERE rowid = 2"),
                    s("DELETE FROM events WHERE rowid = 1"),
                ],
                3,
            )
            .0,
        );
        let mut clean = actor_with(&MemOpener, "rowid/clean", limits);
        for (i, t) in log.iter().enumerate() {
            let _ = clean.apply(t, i as u64 + 1, &BTreeSet::new());
        }
        let n: usize = log
            .iter()
            .map(|t| {
                t.changesets
                    .iter()
                    .map(|(_, c)| ffi::changes(c).unwrap_or_default().len())
                    .sum::<usize>()
            })
            .sum();
        (hash(&a), hash(&clean), n)
    };
    let (live, clean, n) = run(true);
    r.check(
        "rowid/tracked-with-objconfig-rowid",
        live == clean && n == 8,
        format!("{n} changes recorded (rowid as implicit key); rebuild {clean} = live {live}"),
    );
    let (live, clean, n) = run(false);
    let mut direct = actor(&MemOpener, "rowid/direct");
    direct
        .direct(
            &migrate_opts(),
            &[("CREATE TABLE events (kind TEXT, payload TEXT)", vec![])],
        )
        .unwrap_or_else(|e| panic!("{e}"));
    direct
        .direct(
            &TurnOpts::new(2, 2),
            &[
                (
                    "INSERT INTO events VALUES ('a', 'x'), ('a', 'x'), ('b', 'y')",
                    vec![],
                ),
                (
                    "INSERT INTO events SELECT kind, payload || '2' FROM events",
                    vec![],
                ),
            ],
        )
        .unwrap_or_else(|e| panic!("{e}"));
    direct
        .direct(
            &TurnOpts::new(3, 3),
            &[
                ("UPDATE events SET payload = 'u' WHERE rowid = 2", vec![]),
                ("DELETE FROM events WHERE rowid = 1", vec![]),
            ],
        )
        .unwrap_or_else(|e| panic!("{e}"));
    r.check(
        "rowid/ignored-without-it",
        live == clean && live != hash(&direct) && n == 0,
        format!("default sessions record {n} changes for a table without PRIMARY KEY: the turns' writes are silently lost (kronik {live} != direct execution {})", hash(&direct)),
    );
    let mut a = actor(&MemOpener, "rowid/max");
    commit(
        &mut a,
        &migrate_opts(),
        &[
            s("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"),
            s("CREATE TABLE e (v TEXT)"),
        ],
        1,
    );
    let (_, res) = turn(
        &mut a,
        &TurnOpts::new(2, 2),
        &[s("INSERT INTO t VALUES (9223372036854775807, 'max')")],
    );
    let (_, res2) = turn(
        &mut a,
        &TurnOpts::new(2, 2),
        &[s(
            "INSERT INTO e (rowid, v) VALUES (9223372036854775806, 'a'), (NULL, 'b')",
        )],
    );
    r.check(
        "rowid/max-denied",
        matches!(res[0], Err(SqlError::Denied(_))) && matches!(res2[0], Err(SqlError::Denied(_))),
        format!(
            "explicit max rowid -> {:?}; reaching it -> {:?}",
            res[0], res2[0]
        ),
    );
}

pub const PROBE: &[&str] = &[
    "SELECT random(), hex(randomblob(8))",
    "SELECT datetime('now'), CURRENT_TIMESTAMP, CURRENT_DATE, CURRENT_TIME, julianday('now'), unixepoch(), strftime('%s','now'), unixepoch('now','subsec')",
    "SELECT datetime('now','localtime'), date('now','localtime'), time('now','localtime'), datetime('2026-06-01 12:00','utc')",
    "INSERT INTO t DEFAULT VALUES RETURNING id, created, r",
    "INSERT INTO t DEFAULT VALUES RETURNING id, created, r",
    "SELECT id FROM t ORDER BY random()",
    "SELECT last_insert_rowid()",
];

pub fn probe(time_ms: i64, seed: u8) -> (Vec<String>, Vec<u8>) {
    let mut a = actor(&MemOpener, "probe");
    commit(
        &mut a,
        &migrate_opts(),
        &[s(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, created TEXT DEFAULT CURRENT_TIMESTAMP, r INTEGER DEFAULT (random()))",
        )],
        1,
    );
    commit(
        &mut a,
        &TurnOpts::new(9, time_ms - 5000),
        &[s("INSERT INTO t DEFAULT VALUES")],
        2,
    );
    let stmts: Vec<Stmt> = PROBE.iter().map(|q| s(q)).collect();
    let (t, res) = turn(&mut a, &TurnOpts::new(seed, time_ms), &stmts);
    let out = res.iter().map(|r| format!("{r:?}")).collect();
    (
        out,
        t.changesets.iter().flat_map(|(_, c)| c.clone()).collect(),
    )
}

/// 4. Determinism of time and randomness.
pub fn check_determinism(r: &mut Report, exe: &std::path::Path) {
    let t0 = 1_761_300_000_000;
    let (a, ca) = probe(t0, 7);
    let (b, cb) = probe(t0, 7);
    r.check(
        "determinism/re-execution",
        a == b && ca == cb,
        format!(
            "{} results and {} changeset bytes identical",
            a.len(),
            ca.len()
        ),
    );
    for line in &a {
        println!("      {line}");
    }
    let (c, _) = probe(t0, 8);
    r.check(
        "determinism/seed-drives-random",
        c[0] != a[0] && c[1] == a[1],
        "random()/randomblob() change with the seed; time does not",
    );
    let (d, _) = probe(t0 + 86_400_000, 7);
    r.check(
        "determinism/time-drives-now",
        d[1] != a[1] && d[0] == a[0],
        "'now' changes with logical time; random() does not",
    );
    let expect = "2025-10-24 10:00:00";
    r.check(
        "determinism/now-is-logical-time",
        a[1].contains(expect),
        format!("datetime('now') = {expect} for logical time {t0}"),
    );
    let last = a.last().cloned().unwrap_or_default();
    r.check(
        "determinism/last-insert-rowid-turn-local",
        last.contains("Integer(3)"),
        format!("last_insert_rowid() = {last}"),
    );
    // Time zone independence: the same probe in child processes with TZ set.
    let mut same = true;
    let mut detail = String::new();
    for tz in ["UTC", "Pacific/Kiritimati", "America/Los_Angeles"] {
        let out = std::process::Command::new(exe)
            .arg("probe")
            .env("TZ", tz)
            .output();
        match out {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout).to_string();
                let line = text.lines().nth(2).unwrap_or("").to_string();
                same &= line == a[2];
                detail = format!(
                    "{detail}{tz}: {}; ",
                    line.chars().take(60).collect::<String>()
                );
            }
            Err(e) => {
                same = false;
                detail = format!("{detail}{tz}: {e}; ");
            }
        }
    }
    r.check("determinism/localtime-is-utc", same, detail);

    // SQLite's random column-name suffixes (>= 6 duplicate names).
    let conn = Connection::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
    let q = "SELECT * FROM (SELECT 1 a, 2 a, 3 a, 4 a, 5 a, 6 a, 7 a)";
    let names = |c: &Connection| -> Vec<String> {
        c.prepare(q)
            .map(|s| s.column_names().map(|n| n.to_string()).collect())
            .unwrap_or_default()
    };
    let n1 = names(&conn);
    let n2 = names(&conn);
    let mut a = actor(&MemOpener, "colnames");
    let (_, res) = turn(&mut a, &TurnOpts::new(1, 1), &[s(q)]);
    r.check(
        "determinism/random-column-names-denied",
        n1 != n2 && matches!(res[0], Err(SqlError::Denied(_))),
        format!(
            "raw SQLite names {:?} then {:?}; Kronik -> {:?}",
            &n1[4..],
            &n2[4..],
            res[0]
        ),
    );
}

/// 5. Denied statements and limits.
pub fn check_deny(r: &mut Report) {
    let mut a = actor(&MemOpener, "deny");
    commit(
        &mut a,
        &migrate_opts(),
        &NOTES_SCHEMA.iter().map(|q| s(q)).collect::<Vec<_>>(),
        1,
    );
    let denied = [
        "SELECT load_extension('/tmp/x.so')",
        "ATTACH DATABASE '/tmp/other.db' AS other",
        "DETACH DATABASE other",
        "VACUUM",
        "VACUUM INTO '/tmp/copy.db'",
        "ANALYZE",
        "REINDEX",
        "PRAGMA journal_mode = DELETE",
        "PRAGMA synchronous = OFF",
        "PRAGMA foreign_keys = OFF",
        "PRAGMA cache_size = 100000",
        "PRAGMA writable_schema = ON",
        "PRAGMA user_version = 5",
        "PRAGMA reverse_unordered_selects = ON",
        "PRAGMA automatic_index = OFF",
        "PRAGMA page_count",
        "SELECT * FROM pragma_journal_mode",
        "BEGIN",
        "COMMIT",
        "SAVEPOINT x",
        "RELEASE kronik_turn",
        "ROLLBACK TO kronik_turn",
        "CREATE TEMP TABLE scratch (x)",
        "SELECT changes()",
        "SELECT total_changes()",
        "SELECT * FROM dbstat",
        "SELECT * FROM _kronik_meta",
        "UPDATE notes SET _subject = 'user:9'",
    ];
    let mut fails = Vec::new();
    for q in denied {
        let (_, res) = turn(&mut a, &TurnOpts::new(2, 2), &[s(q)]);
        match &res[0] {
            Err(SqlError::Denied(why)) => println!("      denied  {q:<55} {why}"),
            other => fails.push(format!("{q} -> {other:?}")),
        }
    }
    let mut m = migrate_opts();
    m.seed = [4; 32];
    for q in [
        "CREATE VIRTUAL TABLE fts USING fts5(body)",
        "CREATE TABLE copy AS SELECT * FROM notes",
        "CREATE TABLE _kronik_x (a)",
    ] {
        let (_, res) = turn(&mut a, &m, &[s(q)]);
        match &res[0] {
            Err(SqlError::Denied(why)) => println!("      denied  {q:<55} {why}"),
            other => fails.push(format!("{q} -> {other:?}")),
        }
    }
    r.check(
        "deny/list",
        fails.is_empty(),
        if fails.is_empty() {
            format!("{} statements denied", denied.len() + 3)
        } else {
            fails.join("; ")
        },
    );
    let allowed = [
        "PRAGMA table_info(notes)",
        "PRAGMA index_list(notes)",
        "PRAGMA foreign_key_list(notes)",
        "PRAGMA user_version",
        "SELECT name FROM pragma_table_info('notes')",
        "SELECT json_extract('{\"a\":1}', '$.a')",
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 10) SELECT sum(x) FROM c",
        "EXPLAIN QUERY PLAN SELECT * FROM notes WHERE body = 'x'",
    ];
    let mut fails = Vec::new();
    for q in allowed {
        let (_, res) = turn(&mut a, &TurnOpts::new(2, 2), &[s(q)]);
        if res[0].is_err() {
            fails.push(format!("{q} -> {:?}", res[0]));
        }
    }
    r.check(
        "deny/allowed-introspection",
        fails.is_empty(),
        if fails.is_empty() {
            format!("{} statements allowed", allowed.len())
        } else {
            fails.join("; ")
        },
    );

    // Size cap -> too-large; the failed turn leaves no trace.
    let mut small = actor_with(
        &MemOpener,
        "cap",
        Limits {
            max_bytes: 256 * 1024,
            ..Limits::default()
        },
    );
    commit(
        &mut small,
        &migrate_opts(),
        &[s("CREATE TABLE b (id INTEGER PRIMARY KEY, data BLOB)")],
        1,
    );
    let before = hash(&small);
    let stmts: Vec<Stmt> = (0..400)
        .map(|_| s("INSERT INTO b (data) VALUES (randomblob(1024))"))
        .collect();
    let (t, res) = turn(&mut small, &TurnOpts::new(5, 5), &stmts);
    let first_err = res.iter().position(Result::is_err);
    r.check(
        "limits/size-cap",
        res.iter().any(|x| matches!(x, Err(SqlError::TooLarge)))
            && t.changesets.is_empty()
            && hash(&small) == before,
        format!(
            "256 KiB cap: insert #{:?} -> too-large; turn discarded",
            first_err
        ),
    );
    let (_, res) = turn(
        &mut small,
        &TurnOpts::new(5, 5),
        &[s("SELECT length(randomblob(2000000))")],
    );
    let (_, res2) = turn(
        &mut small,
        &TurnOpts::new(5, 5),
        &[s("INSERT INTO b (data) VALUES (zeroblob(2000000))")],
    );
    r.check(
        "limits/value-size",
        matches!(res[0], Err(SqlError::TooLarge)) || matches!(res2[0], Err(SqlError::TooLarge)),
        format!(
            "2 MB value with a 1 MiB limit -> {:?} / {:?}",
            res[0], res2[0]
        ),
    );
    // Runaway SQL is interrupted deterministically.
    let q =
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c";
    let mut o = TurnOpts::new(6, 6);
    o.sql_budget = 2_000_000;
    let (t1, res1) = turn(&mut a, &o, &[s(q)]);
    let (t2, res2) = turn(&mut a, &o, &[s(q)]);
    r.check(
        "limits/sql-fuel",
        matches!(res1[0], Err(SqlError::FuelExhausted)) && t1.vm_steps == t2.vm_steps,
        format!(
            "infinite recursive CTE -> {:?} after {} VM steps (same in a second run: {})",
            res1[0], t1.vm_steps, t2.vm_steps
        ),
    );
    let _ = res2;
}

/// 6. Per-subject changesets and erasure.
pub fn check_subjects(r: &mut Report) {
    let mut a = actor(&MemOpener, "subjects");
    let schema = vec![
        s("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, _subject TEXT)"),
        s("CREATE TABLE stats (k TEXT PRIMARY KEY, v INTEGER NOT NULL)"),
    ];
    let mut log = vec![(1u64, commit(&mut a, &migrate_opts(), &schema, 1).0)];
    let mut o = TurnOpts::new(2, 2);
    o.default_subject = Some("user:1".into());
    let (t, res) = commit(
        &mut a,
        &o,
        &[
            s(
                "INSERT INTO notes (body, _subject) VALUES ('a', 'user:2'), ('b', 'user:2'), ('c', 'user:3')",
            ),
            s("INSERT INTO stats VALUES ('notes', 3) ON CONFLICT(k) DO UPDATE SET v = v + 3"),
        ],
        2,
    );
    let subjects: Vec<Option<String>> = t.changesets.iter().map(|(k, _)| k.clone()).collect();
    log.push((2, t.clone()));
    // Each subject's changeset applies on its own.
    let mut alone_ok = true;
    for (k, cs) in &t.changesets {
        let mut c = actor(&MemOpener, "subjects/alone");
        c.apply(&log[0].1, 1, &BTreeSet::new())
            .unwrap_or_else(|e| panic!("{e}"));
        let single = TurnSql {
            ddl: Vec::new(),
            changesets: vec![(k.clone(), cs.clone())],
            vm_steps: 0,
            whole: Vec::new(),
        };
        alone_ok &= c.apply(&single, 2, &BTreeSet::new()).is_ok();
    }
    r.check(
        "subjects/split",
        res.iter().all(Result::is_ok)
            && subjects == vec![Some("user:1".into()), Some("user:2".into()), Some("user:3".into())]
            && alone_ok,
        format!("one turn (default subject user:1) -> changesets for {subjects:?}, each applicable alone"),
    );
    // An update of user:2's row in a turn whose default subject is user:3
    // belongs to user:2 (the row's subject), not to the turn's subject.
    let mut o = TurnOpts::new(3, 3);
    o.default_subject = Some("user:3".into());
    let (t3, _) = commit(
        &mut a,
        &o,
        &[
            s("UPDATE notes SET body = 'a2' WHERE body = 'a'"),
            s("DELETE FROM notes WHERE body = 'c'"),
        ],
        3,
    );
    let keys3: Vec<Option<String>> = t3.changesets.iter().map(|(k, _)| k.clone()).collect();
    log.push((3, t3));
    r.check(
        "subjects/row-subject-wins",
        keys3 == vec![Some("user:2".into()), Some("user:3".into())],
        format!("UPDATE user:2 row + DELETE user:3 row -> {keys3:?}"),
    );
    // Erasure: live deletes user:2's rows; rebuild skips user:2's changesets.
    let n = a
        .erase_subject("user:2", 4)
        .unwrap_or_else(|e| panic!("{e}"));
    let erased: BTreeSet<String> = ["user:2".to_string()].into();
    let mut rebuilt = actor(&MemOpener, "subjects/rebuilt");
    let mut ok = true;
    for (lsn, t) in &log {
        ok &= rebuilt.apply(t, *lsn, &erased).is_ok();
    }
    ok &= rebuilt.erase_subject("user:2", 4).is_ok();
    r.check(
        "subjects/erasure",
        ok && n == 2 && hash(&rebuilt) == hash(&a),
        format!(
            "erasure turn deleted {n} rows; rebuild without user:2's changesets {} = live {}",
            hash(&rebuilt),
            hash(&a)
        ),
    );
    let mut o = TurnOpts::new(5, 5);
    o.default_subject = Some("user:1".into());
    commit(
        &mut a,
        &o,
        &[s(
            "INSERT INTO notes (id, body, _subject) VALUES (50, 'x', 'user:1')",
        )],
        5,
    );
    let before = hash(&a);
    a.begin_turn(&o).unwrap_or_else(|e| panic!("{e}"));
    let stmt = a.query(
        "INSERT OR REPLACE INTO notes (id, body, _subject) VALUES (50, 'moved', 'user:9')",
        &[],
    );
    let end = a.end_turn(true);
    r.check(
        "subjects/move-detected",
        stmt.is_ok() && end.is_err() && hash(&a) == before,
        format!("REPLACE moving a row to another subject: statement ok, end of turn -> {:?}; turn discarded", end.err()),
    );
    // The gap: a table without `_subject` written under two subjects.
    let mut g = actor(&MemOpener, "subjects/gap");
    let mut glog = vec![
        commit(
            &mut g,
            &migrate_opts(),
            &[s("CREATE TABLE prefs (k TEXT PRIMARY KEY, v TEXT)")],
            1,
        )
        .0,
    ];
    let mut oa = TurnOpts::new(2, 2);
    oa.default_subject = Some("user:A".into());
    glog.push(
        commit(
            &mut g,
            &oa,
            &[s("INSERT INTO prefs VALUES ('theme', 'dark')")],
            2,
        )
        .0,
    );
    let mut ob = TurnOpts::new(3, 3);
    ob.default_subject = Some("user:B".into());
    glog.push(
        commit(
            &mut g,
            &ob,
            &[s("UPDATE prefs SET v = 'light' WHERE k = 'theme'")],
            3,
        )
        .0,
    );
    let erased: BTreeSet<String> = ["user:A".to_string()].into();
    let mut gr = actor(&MemOpener, "subjects/gap-rebuilt");
    let errs: Vec<String> = glog
        .iter()
        .enumerate()
        .filter_map(|(i, t)| gr.apply(t, i as u64 + 1, &erased).err())
        .collect();
    r.check(
        "subjects/gap-without-column",
        !errs.is_empty(),
        format!("row inserted under user:A, updated under user:B, user:A erased -> rebuild error {errs:?} (live row was never erasable)"),
    );
}

/// 7. Triggers and foreign-key actions during apply.
pub fn check_triggers(r: &mut Report) {
    let mut a = actor(&MemOpener, "trig");
    let schema = vec![
        s("CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT)"),
        s(
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE)",
        ),
        s("CREATE TABLE audit (id INTEGER PRIMARY KEY, what TEXT)"),
        s(
            "CREATE TRIGGER parent_audit AFTER INSERT ON parent BEGIN INSERT INTO audit (what) VALUES ('insert ' || NEW.name); END",
        ),
    ];
    let mut log = vec![commit(&mut a, &migrate_opts(), &schema, 1).0];
    log.push(
        commit(
            &mut a,
            &TurnOpts::new(2, 2),
            &[
                s("INSERT INTO parent VALUES (1, 'p')"),
                s("INSERT INTO child VALUES (10, 1), (11, 1)"),
            ],
            2,
        )
        .0,
    );
    log.push(
        commit(
            &mut a,
            &TurnOpts::new(3, 3),
            &[s("DELETE FROM parent WHERE id = 1")],
            3,
        )
        .0,
    );
    let mut c = actor(&MemOpener, "trig/clean");
    let mut errs = Vec::new();
    for (i, t) in log.iter().enumerate() {
        if let Err(e) = c.apply(t, i as u64 + 1, &BTreeSet::new()) {
            errs.push(e);
        }
    }
    let audit_rows: i64 = c
        .conn
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap_or(-1);
    r.check(
        "apply/triggers-and-cascades",
        errs.is_empty() && hash(&c) == hash(&a) && audit_rows == 1,
        format!(
            "trigger and ON DELETE CASCADE effects are in the changeset; apply (FKNOACTION) -> errors {errs:?}, audit rows {audit_rows}, rebuild {} vs live {}",
            hash(&c),
            hash(&a)
        ),
    );
}

/// Copies a database (snapshot) with the backup API into a fresh actor.
pub fn snapshot(src: &SqlActor, name: &str) -> SqlActor {
    let mut dst = actor(&MemOpener, name);
    src.set_host();
    dst.set_host();
    {
        let b = rusqlite::backup::Backup::new(&src.conn, &mut dst.conn)
            .unwrap_or_else(|e| panic!("{e}"));
        b.run_to_completion(256, std::time::Duration::ZERO, None)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    dst
}

/// 8. SQL state at an LSN: forks, isolated replay, inversion, fuzzy snapshots.
pub fn check_at_lsn(r: &mut Report) {
    let mut p = actor(&MemOpener, "lsn/prod");
    let schema: Vec<Stmt> = NOTES_SCHEMA.iter().map(|q| s(q)).collect();
    let mut log = vec![(1u64, commit(&mut p, &migrate_opts(), &schema, 1).0)];
    let mut hashes = vec![String::new(), hash(&p)];
    let mut snap100 = None;
    for lsn in 2..=200u64 {
        let opts = TurnOpts::new(lsn as u8, 1_761_300_000_000 + lsn as i64);
        log.push((lsn, commit(&mut p, &opts, &workload(lsn), lsn).0));
        hashes.push(hash(&p));
        if lsn == 100 {
            snap100 = Some(snapshot(&p, "lsn/snap100"));
        }
    }
    let Some(snap) = snap100 else { return };
    let none = BTreeSet::new();

    // (a) fork at 150 = snapshot at 100 + changesets 101..=150.
    let t = Instant::now();
    let mut fork = snapshot(&snap, "lsn/fork");
    for (lsn, ts) in &log[100..150] {
        fork.apply(ts, *lsn, &none)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let fork_time = t.elapsed();
    r.check(
        "at-lsn/fork-roll-forward",
        hash(&fork) == hashes[150],
        format!(
            "snapshot@100 + 50 changesets = production@150 {} ({:?})",
            hashes[150], fork_time
        ),
    );

    // (b) isolated replay: a cursor at production state, one overlay per
    // root input, rolled back afterwards.
    let t = Instant::now();
    let mut cursor = snapshot(&snap, "lsn/cursor");
    let mut at = 100u64;
    let mut ok = true;
    let mut overlays = 0;
    for root in (110..=200u64).step_by(10) {
        for (lsn, ts) in &log[at as usize..(root - 1) as usize] {
            cursor
                .apply(ts, *lsn, &none)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        at = root - 1;
        ok &= hash(&cursor) == hashes[at as usize];
        cursor.set_host();
        cursor
            .conn
            .execute_batch("SAVEPOINT kronik_overlay")
            .unwrap_or_else(|e| panic!("{e}"));
        // The fork's new code: a different SQL turn for the same input.
        let mut stmts = workload(root);
        stmts.push(s("UPDATE counters SET v = v * 100"));
        let (ft, res) = turn(&mut cursor, &TurnOpts::new(root as u8, 1), &stmts);
        ok &= res.iter().all(Result::is_ok);
        cursor
            .apply(&ft, root, &none)
            .unwrap_or_else(|e| panic!("{e}"));
        ok &= hash(&cursor) != hashes[root as usize];
        cursor.set_host();
        cursor
            .conn
            .execute_batch("ROLLBACK TO kronik_overlay; RELEASE kronik_overlay")
            .unwrap_or_else(|e| panic!("{e}"));
        ok &= hash(&cursor) == hashes[at as usize];
        overlays += 1;
    }
    r.check(
        "at-lsn/isolated-replay-overlay",
        ok,
        format!("{overlays} root inputs: cursor rolled forward in LSN order, each fork turn in a rolled-back overlay; cursor always equals production ({:?})", t.elapsed()),
    );

    // (c) backwards from HEAD with inverted changesets (no DDL in range).
    let t = Instant::now();
    let back = snapshot(&p, "lsn/back");
    for (lsn, ts) in log[150..200].iter().rev() {
        back.set_host();
        back.conn
            .execute_batch("SAVEPOINT inv")
            .unwrap_or_else(|e| panic!("{e}"));
        for (_, cs) in ts.changesets.iter().rev() {
            let inv = ffi::invert(cs).unwrap_or_else(|e| panic!("{e}"));
            ffi::apply(&back.conn, &inv).unwrap_or_else(|e| panic!("invert lsn {lsn}: {e}"));
        }
        back.conn
            .execute(
                "UPDATE _kronik_meta SET v = ?1 WHERE k = 'applied_lsn'",
                [*lsn as i64 - 1],
            )
            .unwrap_or_else(|e| panic!("{e}"));
        back.conn
            .execute_batch("RELEASE inv")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    r.check(
        "at-lsn/inverted-from-head",
        hash(&back) == hashes[150],
        format!(
            "HEAD@200 + 50 inverted changesets = production@150 ({:?})",
            t.elapsed()
        ),
    );

    // (d) fuzzy snapshot: copies taken at different applied LSNs roll
    // forward independently to the same target.
    let mut q = actor(&MemOpener, "lsn/q");
    let mut qlog = vec![(1u64, commit(&mut q, &migrate_opts(), &schema, 1).0)];
    let mut q_at = None;
    for lsn in 2..=200u64 {
        if lsn % 2 == 0 {
            qlog.push((
                lsn,
                commit(
                    &mut q,
                    &TurnOpts::new(lsn as u8, lsn as i64),
                    &workload(lsn + 1000),
                    lsn,
                )
                .0,
            ));
        }
        if lsn == 130 {
            q_at = Some(snapshot(&q, "lsn/q130"));
        }
    }
    let Some(mut q130) = q_at else { return };
    let mut p120 = snapshot(&snap, "lsn/p120");
    for (lsn, ts) in &log[100..120] {
        p120.apply(ts, *lsn, &none)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let p_from = p120.applied_lsn().unwrap_or(0);
    for (lsn, ts) in log.iter().filter(|(l, _)| *l > p_from) {
        p120.apply(ts, *lsn, &none)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let q_from = q130.applied_lsn().unwrap_or(0);
    for (lsn, ts) in qlog.iter().filter(|(l, _)| *l > q_from) {
        q130.apply(ts, *lsn, &none)
            .unwrap_or_else(|e| panic!("{e}"));
    }
    r.check(
        "at-lsn/fuzzy-snapshot",
        hash(&p120) == hash(&p) && hash(&q130) == hash(&q),
        "copies at applied_lsn 120 and 130 each roll forward from their own applied_lsn to 200 and match the live databases",
    );
}

pub fn run_all(exe: &std::path::Path) -> bool {
    let mut r = Report { failures: 0 };
    check_changesets(&mut r, &MemOpener, "memory");
    let dir = std::env::temp_dir().join(format!("kronik-spike-e-{}", std::process::id()));
    check_changesets(&mut r, &FileOpener { root: dir.clone() }, "file");
    let _ = std::fs::remove_dir_all(&dir);
    check_ddl(&mut r);
    check_rowid(&mut r);
    check_determinism(&mut r, exe);
    check_deny(&mut r);
    check_subjects(&mut r);
    check_triggers(&mut r);
    check_at_lsn(&mut r);
    println!("{} check(s) failed", r.failures);
    r.failures == 0
}
