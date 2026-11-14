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
fn physical_diagnostics_are_denied_in_guest_private_prepare_and_schema_replay() {
    let raw = rusqlite::Connection::open_in_memory().unwrap();
    for function in ["sqlite_filestat", "sqlite_walstat"] {
        let available: String = raw
            .query_row(
                &format!("SELECT {function}('__missing_kronik_schema__')"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(available, "{}", "the real pinned builtin must be enabled");
    }
    let root = tempfile::tempdir().unwrap();
    for pool in [
        SqlPool::new(Arc::new(MemOpener), Limits::default(), 8),
        SqlPool::new(
            Arc::new(FileOpener {
                root: root.path().to_owned(),
            }),
            Limits::default(),
            8,
        ),
    ] {
        let actor = pool.get("diagnostics/denied").unwrap();
        let mut actor = actor.lock().unwrap();
        actor
            .conn
            .execute_batch(
                "CREATE TABLE kept(id INTEGER PRIMARY KEY, value INTEGER NOT NULL);
             INSERT INTO kept VALUES(1,7);
             CREATE TABLE watched(id INTEGER PRIMARY KEY);",
            )
            .unwrap();
        for function in ["sqlite_filestat", "sqlite_walstat"] {
            let direct = format!("SELECT {function}('main')");
            assert!(
                actor.conn.prepare(&direct).is_err(),
                "host preparation must not bypass denial"
            );
            assert!(
                actor.conn.prepare_cached(&direct).is_err(),
                "private statement caching must not bypass denial"
            );
            for (setup, query) in [
                (String::new(), direct),
                (
                    String::new(),
                    format!("SELECT {}('main')", function.to_ascii_uppercase()),
                ),
                (
                    String::new(),
                    format!(
                        "WITH diagnostic(value) AS (SELECT {function}('main')) SELECT value FROM diagnostic"
                    ),
                ),
                (
                    format!("CREATE VIEW diagnostic_view AS SELECT {function}('main') AS value"),
                    "SELECT value FROM diagnostic_view".into(),
                ),
                (
                    format!(
                        "CREATE TRIGGER diagnostic_trigger AFTER INSERT ON watched BEGIN SELECT {function}('main'); END"
                    ),
                    "INSERT INTO watched VALUES(1)".into(),
                ),
            ] {
                actor.begin_turn(&opts(9, 9, true)).unwrap();
                let setup = if setup.is_empty() {
                    Ok(0)
                } else {
                    actor.execute(&setup, &[])
                };
                let result = setup.and_then(|_| {
                    actor.execute("UPDATE kept SET value=99 WHERE id=1", &[])?;
                    actor.query(&query, &[])
                });
                assert!(
                    matches!(&result,
                    Err(SqlError::Denied(message) | SqlError::Syntax(message))
                        if message.to_ascii_lowercase().contains(function)
                            && !message.contains("no such function")),
                    "{query}: {result:?}"
                );
                actor.end_turn(false).unwrap();
                actor.begin_turn(&opts(10, 10, false)).unwrap();
                let ordinary = actor.query(
                    "SELECT abs(-7), value, (SELECT count(*) FROM watched), 'sqlite_filestat', 'sqlite_walstat' FROM kept", &[],
                ).unwrap();
                assert_eq!(
                    ordinary.values,
                    vec![vec![
                        Value::Integer(7),
                        Value::Integer(7),
                        Value::Integer(0),
                        Value::Text("sqlite_filestat".into()),
                        Value::Text("sqlite_walstat".into())
                    ]]
                );
                actor.end_turn(false).unwrap();
            }
            let statement =
                format!("CREATE TABLE diagnostic_replay AS SELECT {function}('main') AS value");
            let replay = TurnSql {
                ddl: vec![statement],
                ..Default::default()
            };
            let error = actor.apply(&replay, 1, &BTreeSet::new()).unwrap_err();
            assert!(error.to_ascii_lowercase().contains(function), "{error}");
            assert_eq!(
                actor.applied_lsn().unwrap(),
                0,
                "denied schema replay must roll back its checkpoint"
            );
            assert!(
                !actor
                    .conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='diagnostic_replay')",
                        [],
                        |row| row.get::<_, bool>(0),
                    )
                    .unwrap()
            );
        }
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

/// Text and blob cells are replaced; an integer primary key and `_subject`
/// stay, and a later UPDATE still matches the rewritten old image.
#[test]
fn a_rewritten_changeset_applies_pseudonyms_and_keeps_the_primary_key() {
    let schema = [
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
         payload BLOB, _subject TEXT DEFAULT (kronik_subject()))",
    ];
    let mut live = actor("rewrite-live");
    let (_, res) = commit(&mut live, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let mut o = opts(2, 2, false);
    o.default_subject = Some("user:1".into());
    let (t, res) = commit(
        &mut live,
        &o,
        &[
            "INSERT INTO notes(body, payload) VALUES ('ROW-u1-5e2c', x'0102')",
            "INSERT INTO notes(body, payload) VALUES ('ROW-u1-5e2c', x'0102')",
            "UPDATE notes SET body = 'ROW-u1-5e2c-next' WHERE id = 1",
            "DELETE FROM notes WHERE id = 2",
        ],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (subject, cs) = t.changesets.first().expect("one changeset");
    assert_eq!(subject.as_deref(), Some("user:1"));
    let rewritten = pseudonymize_changeset(cs, "user:1", |v| match v {
        b"ROW-u1-5e2c" => b"pii:aaaa".to_vec(),
        b"ROW-u1-5e2c-next" => b"pii:bbbb".to_vec(),
        other => {
            let mut out = b"pii:".to_vec();
            out.extend_from_slice(&blake3::hash(other).as_bytes()[..6]);
            out
        }
    })
    .unwrap();
    assert!(
        !rewritten
            .windows(b"ROW-u1-5e2c".len())
            .any(|w| w == b"ROW-u1-5e2c"),
        "rewritten changeset still holds the plaintext"
    );
    let mut fork = actor("rewrite-fork");
    fork.apply(
        &TurnSql {
            ddl: schema.iter().map(|s| (*s).to_string()).collect(),
            ..TurnSql::default()
        },
        1,
        &BTreeSet::new(),
    )
    .unwrap();
    fork.apply(
        &TurnSql {
            changesets: vec![(subject.clone(), rewritten)],
            ..TurnSql::default()
        },
        2,
        &BTreeSet::new(),
    )
    .unwrap();
    fork.begin_turn(&opts(0, 0, false)).unwrap();
    let rows = fork
        .query(
            "SELECT id, body, payload, _subject FROM notes ORDER BY id",
            &[],
        )
        .unwrap();
    fork.end_turn(false).unwrap();
    assert_eq!(rows.values.len(), 1, "{rows:?}");
    assert_eq!(rows.values[0][0], Value::Integer(1));
    assert_eq!(rows.values[0][1], Value::Text("pii:bbbb".into()));
    let Value::Blob(payload) = &rows.values[0][2] else {
        panic!("payload was not a blob: {rows:?}");
    };
    assert_ne!(payload.as_slice(), &[1, 2]);
    assert!(payload.starts_with(b"pii:"), "{payload:?}");
    assert_eq!(rows.values[0][3], Value::Text("user:1".into()));
}

/// A turn with a default subject may not write a table that has no
/// `_subject` column. A turn without a subject may. Erasure of a tagged
/// row is unchanged.
#[test]
fn a_subject_turn_cannot_write_a_table_without_subject_column() {
    let schema = [
        "CREATE TABLE tagged (id INTEGER PRIMARY KEY, body TEXT, \
         _subject TEXT DEFAULT (kronik_subject()))",
        "CREATE TABLE plain (id INTEGER PRIMARY KEY, body TEXT)",
    ];
    let mut a = actor("untagged");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let mut with_subject = opts(2, 2, false);
    with_subject.default_subject = Some("user:1".into());
    a.begin_turn(&with_subject).unwrap();
    assert!(
        a.query("INSERT INTO plain(body) VALUES ('secret')", &[])
            .is_ok()
    );
    let err = a.end_turn(true).unwrap_err();
    assert!(err.contains("subjects/table-without-subject"), "{err}");
    assert!(err.contains("plain"), "{err}");

    a.begin_turn(&opts(3, 3, false)).unwrap();
    let left = a.query("SELECT count(*) FROM plain", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(left.values[0][0], Value::Integer(0), "{left:?}");

    let (t, res) = commit(
        &mut a,
        &opts(4, 4, false),
        &["INSERT INTO plain(body) VALUES ('system')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert!(!t.changesets.is_empty());

    let (t, res) = commit(
        &mut a,
        &with_subject,
        &["INSERT INTO tagged(body) VALUES ('kept')"],
        3,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert!(
        t.changesets
            .iter()
            .any(|(s, _)| s.as_deref() == Some("user:1")),
        "{t:?}"
    );
    let erased = a.erase_subject("user:1", 4).unwrap();
    assert!(erased >= 1, "tagged row was not erased");

    a.begin_turn(&opts(5, 5, false)).unwrap();
    let tagged = a.query("SELECT count(*) FROM tagged", &[]).unwrap();
    let plain = a.query("SELECT body FROM plain", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(tagged.values[0][0], Value::Integer(0), "{tagged:?}");
    assert_eq!(plain.values, [[Value::Text("system".into())]]);
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// #37: a revealed secret is scrubbed from blob cells as from text cells,
/// so neither the changeset (the log) nor the applied database holds it. A
/// blob stays a blob, and a secret that is not UTF-8 is scrubbed from blobs.
#[test]
fn scrubbing_covers_blob_cells_and_binary_secrets() {
    let mut a = actor("scrub-blobs");
    let schema = ["CREATE TABLE keys (id INTEGER PRIMARY KEY, t TEXT, b BLOB)"];
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let text = "sk-live-0123456789";
    let binary: &[u8] = &[0x00, 0xff, 0x10, 0x80, 0x7f, 0x01];
    let blob = |parts: &[&[u8]]| Value::Blob(parts.concat());
    a.begin_turn(&opts(2, 2, false)).unwrap();
    for (sql, params) in [
        (
            "INSERT INTO keys(t, b) VALUES (?1, ?2)",
            vec![
                Value::Text(format!("x{text}y")),
                blob(&[b"pre-", text.as_bytes(), b"-post"]),
            ],
        ),
        (
            "INSERT INTO keys(t, b) VALUES ('binary', ?1)",
            vec![blob(&[b"\x00\x01", binary, b"\x02", binary])],
        ),
        (
            "INSERT INTO keys(t, b) VALUES ('cast', CAST(?1 AS BLOB))",
            vec![Value::Text(text.into())],
        ),
    ] {
        a.execute(sql, &params).unwrap();
    }
    let changed = a
        .scrub(&[("api", text.as_bytes()), ("bin", binary)])
        .unwrap();
    assert_eq!(changed, 4, "the text cell and three blob cells");
    let t = a.end_turn(true).unwrap();
    for (_, cs) in &t.changesets {
        assert!(!holds(cs, text.as_bytes()), "the log holds the text secret");
        assert!(!holds(cs, binary), "the log holds the binary secret");
    }
    a.apply(&t, 2, &BTreeSet::new()).unwrap();
    a.begin_turn(&opts(3, 3, false)).unwrap();
    let rows = a
        .query("SELECT t, typeof(b), b FROM keys ORDER BY id", &[])
        .unwrap();
    // The host's replace is not the guest's.
    assert!(
        a.query("SELECT kronik_scrub_replace(x'01', x'01', 'x')", &[])
            .is_err()
    );
    a.end_turn(false).unwrap();
    assert_eq!(
        rows.values,
        [
            vec![
                Value::Text("x[secret:api]y".into()),
                Value::Text("blob".into()),
                blob(&[b"pre-[secret:api]-post"]),
            ],
            vec![
                Value::Text("binary".into()),
                Value::Text("blob".into()),
                blob(&[b"\x00\x01[secret:bin]\x02[secret:bin]"]),
            ],
            vec![
                Value::Text("cast".into()),
                Value::Text("blob".into()),
                blob(&[b"[secret:api]"]),
            ],
        ]
    );
}
