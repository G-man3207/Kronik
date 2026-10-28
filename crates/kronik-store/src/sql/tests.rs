//! M1 SQL acceptance checks on the real module (ported from spike E).

use std::collections::BTreeSet;

use rusqlite::types::Value;

use super::*;

fn opts(seed: u8, time_ms: i64, migrate: bool) -> TurnOpts {
    TurnOpts {
        seed: [seed; 32],
        time_ms,
        default_subject: None,
        migrate,
        sql_budget: 50_000_000,
        max_bytes: 0,
    }
}

fn actor(name: &str) -> SqlActor {
    SqlActor::open(&MemOpener, name, Limits::default()).unwrap()
}

/// Runs one turn and applies it when every statement succeeded; returns the
/// turn as logged (without the unsplit changeset) and the results.
fn commit(
    a: &mut SqlActor,
    o: &TurnOpts,
    stmts: &[&str],
    lsn: u64,
) -> (TurnSql, Vec<SqlResult<Rows>>) {
    a.begin_turn(o).unwrap();
    let res: Vec<_> = stmts.iter().map(|q| a.query(q, &[])).collect();
    let ok = res.iter().all(Result::is_ok);
    let mut t = a.end_turn(ok).unwrap();
    if ok {
        a.apply(&t, lsn, &BTreeSet::new()).unwrap();
    }
    t.whole.clear();
    (t, res)
}

const SCHEMA: &[&str] = &[
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
     _subject TEXT DEFAULT (kronik_subject()))",
    "ALTER TABLE notes ADD COLUMN tag TEXT",
    "CREATE INDEX notes_body ON notes(body)",
];

#[test]
fn ddl_is_recorded_and_a_rebuild_has_the_same_hash() {
    let mut live = actor("live");
    let mut log = Vec::new();
    let (t, res) = commit(&mut live, &opts(1, 1_000, true), SCHEMA, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert_eq!(t.ddl, SCHEMA);
    log.push(t);
    for i in 0..20u64 {
        let mut o = opts(i as u8, 2_000 + i as i64, false);
        o.default_subject = Some(format!("user:{}", i % 3));
        let stmts = [
            format!(
                "INSERT INTO notes(body, tag) VALUES ('note {i}', 't{}')",
                i % 2
            ),
            "UPDATE notes SET tag = 'x' WHERE id % 5 = 0".to_string(),
            format!("DELETE FROM notes WHERE id = {}", i / 2),
        ];
        let stmts: Vec<&str> = stmts.iter().map(String::as_str).collect();
        let (t, res) = commit(&mut live, &o, &stmts, i + 2);
        assert!(res.iter().all(Result::is_ok), "{res:?}");
        log.push(t);
    }
    let mut rebuilt = actor("rebuilt");
    for (i, t) in log.iter().enumerate() {
        rebuilt.apply(t, i as u64 + 1, &BTreeSet::new()).unwrap();
    }
    assert_eq!(
        live.canonical_hash().unwrap(),
        rebuilt.canonical_hash().unwrap()
    );
    assert_eq!(rebuilt.applied_lsn().unwrap(), 21);
    // Subjects come from the _subject column (default kronik_subject()).
    let q = "SELECT count(DISTINCT _subject) FROM notes";
    rebuilt.begin_turn(&opts(0, 0, false)).unwrap();
    let r = rebuilt.query(q, &[]).unwrap();
    rebuilt.end_turn(false).unwrap();
    assert_eq!(r.values[0][0], Value::Integer(3));
    // One changeset per subject.
    assert!(
        log[1..]
            .iter()
            .all(|t| t.changesets.iter().all(|(s, _)| s.is_some()))
    );
}

#[test]
fn ddl_outside_migrate_or_after_dml_is_denied() {
    let mut a = actor("ddl");
    commit(&mut a, &opts(1, 1, true), &SCHEMA[..1], 1);
    let (_, res) = commit(&mut a, &opts(1, 2, false), &["CREATE TABLE x (y)"], 2);
    assert!(
        matches!(&res[0], Err(SqlError::Denied(m)) if m.contains("only allowed in migrate")),
        "{res:?}"
    );
    let (_, res) = commit(
        &mut a,
        &opts(1, 3, true),
        &[
            "INSERT INTO notes(body) VALUES ('a')",
            "ALTER TABLE notes ADD COLUMN z",
        ],
        3,
    );
    assert!(res[0].is_ok());
    assert!(
        matches!(&res[1], Err(SqlError::Denied(m)) if m.contains("before the first DML")),
        "{res:?}"
    );
}

#[test]
fn random_and_now_are_deterministic() {
    let probe = |seed: u8, time: i64| {
        let mut a = actor("probe");
        commit(&mut a, &opts(1, 1, true), &["CREATE TABLE t (x)"], 1);
        a.begin_turn(&opts(seed, time, false)).unwrap();
        let out: Vec<_> = [
            "SELECT random(), hex(randomblob(8))",
            "SELECT datetime('now'), strftime('%s','now'), date('now','localtime')",
            "SELECT julianday('now')",
        ]
        .iter()
        .map(|q| a.query(q, &[]).unwrap().values)
        .collect();
        a.end_turn(false).unwrap();
        out
    };
    let a = probe(7, 1_761_300_000_000);
    assert_eq!(a, probe(7, 1_761_300_000_000));
    assert_ne!(a[0], probe(8, 1_761_300_000_000)[0]);
    assert_eq!(a[1][0][0], Value::Text("2025-10-24 10:00:00".into()));
}

#[test]
fn storage_affecting_statements_are_denied() {
    let mut a = actor("deny");
    commit(&mut a, &opts(1, 1, true), &SCHEMA[..1], 1);
    for q in [
        "SELECT load_extension('/tmp/x.so')",
        "ATTACH DATABASE '/tmp/other.db' AS other",
        "VACUUM",
        "ANALYZE",
        "PRAGMA journal_mode = DELETE",
        "PRAGMA synchronous = OFF",
        "PRAGMA foreign_keys = OFF",
        "PRAGMA writable_schema = ON",
        "BEGIN",
        "SAVEPOINT x",
        "CREATE TEMP TABLE scratch (x)",
        "SELECT * FROM _kronik_meta",
        "UPDATE notes SET _subject = 'user:9'",
    ] {
        a.begin_turn(&opts(2, 2, false)).unwrap();
        let r = a.query(q, &[]);
        a.end_turn(false).unwrap();
        assert!(matches!(r, Err(SqlError::Denied(_))), "{q} -> {r:?}");
    }
}

#[test]
fn a_caught_sql_error_does_not_fail_the_turn() {
    let mut a = actor("recover");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &SCHEMA[..1], 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    for bad in [
        "THIS IS NOT SQL",
        "VACUUM",
        "CREATE TABLE x(a)",
        "SELECT * FROM missing",
    ] {
        let mut o = opts(2, 2, false);
        o.max_bytes = 1 << 30;
        a.begin_turn(&o).unwrap();
        assert!(a.query(bad, &[]).is_err(), "{bad}");
        a.query("INSERT INTO notes(body) VALUES ('after')", &[])
            .unwrap();
        let t = a.end_turn(true).unwrap();
        assert_eq!(t.changesets.len(), 1, "{bad}");
        a.apply(&t, 2, &BTreeSet::new()).unwrap();
    }
    a.begin_turn(&opts(3, 3, false)).unwrap();
    let rows = a.query("SELECT count(*) FROM notes", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(rows.values[0][0], Value::Integer(4));
}

#[test]
fn a_caught_sql_error_without_tables_does_not_fail_the_turn() {
    let mut a = actor("empty");
    // With a per-kind size limit, as the scheduler always sets one.
    let mut o = opts(1, 1, false);
    o.max_bytes = 1 << 30;
    a.begin_turn(&o).unwrap();
    assert!(a.query("THIS IS NOT SQL", &[]).is_err());
    let t = a.end_turn(true).unwrap();
    assert!(t.changesets.is_empty());
}

/// R1 (v0.1 re-review): a snapshot copy is taken while an actor turn has
/// `SAVEPOINT kronik_turn` open (between its statements). `VACUUM INTO`
/// on the actor's own connection refused that ("cannot VACUUM from within
/// a transaction"); the copy now comes from a fresh read-only connection,
/// and holds exactly the committed (applied) rows, not the turn's.
#[test]
fn a_copy_during_an_open_turn_holds_the_applied_rows() {
    let dir = tempfile::tempdir().unwrap();
    let opener = FileOpener {
        root: dir.path().to_path_buf(),
    };
    let mut a = SqlActor::open(&opener, "notes/n", Limits::default()).unwrap();
    let (_, res) = commit(&mut a, &opts(1, 1_000, true), &SCHEMA[..1], 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (_, res) = commit(
        &mut a,
        &opts(2, 2_000, false),
        &["INSERT INTO notes(body) VALUES ('applied')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    a.begin_turn(&opts(3, 3_000, false)).unwrap();
    a.query("INSERT INTO notes(body) VALUES ('in the turn')", &[])
        .unwrap();
    let copy = dir.path().join("copy.db");
    a.backup_to(&copy).unwrap();
    let rows: Vec<String> = rusqlite::Connection::open(&copy)
        .unwrap()
        .prepare("SELECT body FROM notes ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, ["applied"]);
    // The turn goes on as if nothing happened.
    a.query("INSERT INTO notes(body) VALUES ('after the copy')", &[])
        .unwrap();
    a.end_turn(true).unwrap();
}
