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

const SUBJECT_TABLE: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
     _subject TEXT DEFAULT (kronik_subject()))";

/// A turn on behalf of `subject`.
fn as_subject(seed: u8, subject: &str) -> TurnOpts {
    let mut o = opts(seed, i64::from(seed), false);
    o.default_subject = Some(subject.to_owned());
    o
}

/// An actor with [`SUBJECT_TABLE`], created at LSN 1.
fn subject_actor(name: &str) -> SqlActor {
    let mut a = actor(name);
    let (_, res) = commit(&mut a, &opts(1, 1, true), &[SUBJECT_TABLE], 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    a
}

/// Every row of a table, with no subject in force: (id, body, _subject).
fn subject_rows(a: &mut SqlActor) -> Vec<(i64, String, String)> {
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let rows = a
        .query("SELECT id, body, _subject FROM notes ORDER BY id", &[])
        .unwrap();
    a.end_turn(false).unwrap();
    rows.values
        .into_iter()
        .map(|row| match row.as_slice() {
            [Value::Integer(id), Value::Text(body), Value::Text(subject)] => {
                (*id, body.clone(), subject.clone())
            }
            other => panic!("unexpected row {other:?}"),
        })
        .collect()
}

/// (op, body, `_subject`) of each change in a changeset of [`SUBJECT_TABLE`];
/// an UPDATE's `_subject` is its unchanged old one, absent from the record.
fn subject_changes(cs: &[u8]) -> Vec<(ffi::Op, Option<String>, Option<String>)> {
    let text = |v: Option<&Option<ffi::Val>>| match v {
        Some(Some(ffi::Val::Text(t))) => Some(t.clone()),
        _ => None,
    };
    ffi::changes(cs)
        .unwrap()
        .into_iter()
        .map(|c| {
            let image = if c.op == ffi::Op::Delete {
                &c.old
            } else {
                &c.new
            };
            (c.op, text(image.get(1)), text(image.get(2)))
        })
        .collect()
}

/// `subjects/split` (ADR 0005 §6): one turn with the default subject
/// `user:1` writes a row of its own and rows that name `user:2` and
/// `user:3`. Each subject gets one changeset that holds its rows and no
/// other's, and that applies on its own. Filing every row under the turn's
/// default subject would put `user:2`'s and `user:3`'s rows in `user:1`'s
/// changeset, which an erasure of `user:2` leaves readable.
#[test]
fn subjects_split_one_turn_into_a_changeset_per_row_subject() {
    let mut live = subject_actor("split-live");
    let (t, res) = commit(
        &mut live,
        &as_subject(2, "user:1"),
        &[
            "INSERT INTO notes(body) VALUES ('one')",
            "INSERT INTO notes(body, _subject) VALUES ('two', 'user:2')",
            "INSERT INTO notes(body, _subject) VALUES ('three', 'user:3')",
        ],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let subjects: Vec<Option<&str>> = t.changesets.iter().map(|(s, _)| s.as_deref()).collect();
    assert_eq!(
        subjects,
        [Some("user:1"), Some("user:2"), Some("user:3")],
        "one changeset per row subject"
    );
    for ((subject, cs), body) in t.changesets.iter().zip(["one", "two", "three"]) {
        assert_eq!(
            subject_changes(cs),
            [(ffi::Op::Insert, Some(body.to_owned()), subject.clone())],
            "the changeset of {subject:?} holds its row and no other"
        );
        // Applicable on its own, as a rebuild after another subject's
        // erasure applies it.
        let mut alone = subject_actor("split-alone");
        alone
            .apply(
                &TurnSql {
                    changesets: vec![(subject.clone(), cs.clone())],
                    ..TurnSql::default()
                },
                2,
                &BTreeSet::new(),
            )
            .unwrap();
        let rows = subject_rows(&mut alone);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            (rows[0].1.as_str(), Some(rows[0].2.as_str())),
            (body, subject.as_deref())
        );
    }
    assert_eq!(
        subject_rows(&mut live),
        [
            (1, "one".to_owned(), "user:1".to_owned()),
            (2, "two".to_owned(), "user:2".to_owned()),
            (3, "three".to_owned(), "user:3".to_owned()),
        ]
    );
}

/// `subjects/row-subject-wins` (ADR 0005 §6): an UPDATE record carries only
/// the changed columns, so the subject of an updated row is looked up by
/// key; a DELETE carries the old row. A change to `user:2`'s row in a turn
/// whose default subject is `user:3` goes to `user:2`'s changeset.
#[test]
fn subjects_row_subject_wins_over_the_turns_default_subject() {
    let mut a = subject_actor("row-subject");
    let (_, res) = commit(
        &mut a,
        &as_subject(2, "user:2"),
        &["INSERT INTO notes(body) VALUES ('two')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (t, res) = commit(
        &mut a,
        &as_subject(3, "user:3"),
        &["UPDATE notes SET body = 'two, edited' WHERE id = 1"],
        3,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert_eq!(t.changesets.len(), 1, "{t:?}");
    assert_eq!(t.changesets[0].0.as_deref(), Some("user:2"));
    assert_eq!(
        subject_changes(&t.changesets[0].1),
        [(ffi::Op::Update, Some("two, edited".to_owned()), None)]
    );
    let (t, res) = commit(
        &mut a,
        &as_subject(4, "user:3"),
        &["DELETE FROM notes WHERE id = 1"],
        4,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert_eq!(t.changesets.len(), 1, "{t:?}");
    assert_eq!(t.changesets[0].0.as_deref(), Some("user:2"));
    assert_eq!(
        subject_changes(&t.changesets[0].1),
        [(
            ffi::Op::Delete,
            Some("two, edited".to_owned()),
            Some("user:2".to_owned())
        )]
    );
}

/// `subjects/move-detected` (ADR 0005 §6): a row cannot move to another
/// subject. An UPDATE of `_subject`, an upsert's too, is denied when the
/// statement runs. A REPLACE, or a DELETE and an INSERT of the same key in
/// one turn, is recorded as one UPDATE whose old values are one subject's
/// and new values another's: the turn fails when it ends, and nothing is
/// written. Deleting the row in one turn and inserting it in a later one
/// moves it, each change in its own subject's changeset.
#[test]
fn subjects_move_detected() {
    let mut a = subject_actor("move");
    let (_, res) = commit(
        &mut a,
        &as_subject(2, "user:1"),
        &["INSERT INTO notes(body) VALUES ('one')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    for statements in [
        &["INSERT OR REPLACE INTO notes(id, body, _subject) VALUES (1, 'moved', 'user:2')"][..],
        &[
            "DELETE FROM notes WHERE id = 1",
            "INSERT INTO notes(id, body, _subject) VALUES (1, 'moved', 'user:2')",
        ][..],
    ] {
        a.begin_turn(&as_subject(3, "user:2")).unwrap();
        for q in statements {
            a.query(q, &[]).unwrap();
        }
        let err = a.end_turn(true).unwrap_err();
        assert!(
            err.contains("subjects/move-detected"),
            "{statements:?}: {err}"
        );
        assert!(err.contains("notes"), "{err}");
    }

    a.begin_turn(&as_subject(4, "user:2")).unwrap();
    let err = a
        .query(
            "INSERT INTO notes(id, body, _subject) VALUES (1, 'moved', 'user:2') \
             ON CONFLICT(id) DO UPDATE SET _subject = excluded._subject",
            &[],
        )
        .unwrap_err();
    assert!(format!("{err:?}").contains("_subject"), "{err:?}");
    let t = a.end_turn(true).unwrap();
    assert!(t.changesets.is_empty(), "{t:?}");
    assert_eq!(
        subject_rows(&mut a),
        [(1, "one".to_owned(), "user:1".to_owned())]
    );

    let (deleted, res) = commit(
        &mut a,
        &as_subject(5, "user:1"),
        &["DELETE FROM notes WHERE id = 1"],
        3,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (inserted, res) = commit(
        &mut a,
        &as_subject(6, "user:2"),
        &["INSERT INTO notes(id, body) VALUES (1, 'moved')"],
        4,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert_eq!(deleted.changesets[0].0.as_deref(), Some("user:1"));
    assert_eq!(inserted.changesets[0].0.as_deref(), Some("user:2"));
    assert_eq!(
        subject_rows(&mut a),
        [(1, "moved".to_owned(), "user:2".to_owned())]
    );
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

/// The write path already treats any ASCII case of `_subject` as the subject
/// column. Erasure, `has_table_without_subject`, and `--no-pii` must too:
/// a declared `_Subject` is not a table without a subject column.
#[test]
fn a_subject_column_of_any_ascii_case_is_erased_and_pseudonymized() {
    let schema = [
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
         payload BLOB, \"_Subject\" TEXT DEFAULT (kronik_subject()))",
    ];
    let mut a = actor("case-subject");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert!(
        !a.has_table_without_subject().unwrap(),
        "a case-variant subject column is still a subject column"
    );

    let mut first = opts(2, 2, false);
    first.default_subject = Some("user:1".into());
    let (_, res) = commit(
        &mut a,
        &first,
        &["INSERT INTO notes(body, payload) VALUES ('ROW-secret', x'0102')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let mut second = opts(3, 3, false);
    second.default_subject = Some("user:2".into());
    let (_, res) = commit(
        &mut a,
        &second,
        &["INSERT INTO notes(body, payload) VALUES ('ROW-other', x'0304')"],
        3,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    a.pseudonymize_subject_cells(|_, value| {
        let mut out = b"pii:".to_vec();
        out.extend_from_slice(value);
        out
    })
    .unwrap();
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let rows = a
        .query(
            "SELECT body, payload, \"_Subject\" FROM notes ORDER BY id",
            &[],
        )
        .unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        rows.values,
        [
            vec![
                Value::Text("pii:ROW-secret".into()),
                Value::Blob(b"pii:\x01\x02".to_vec()),
                Value::Text("user:1".into()),
            ],
            vec![
                Value::Text("pii:ROW-other".into()),
                Value::Blob(b"pii:\x03\x04".to_vec()),
                Value::Text("user:2".into()),
            ],
        ],
        "text and blob cells are rewritten; the subject id is not"
    );

    let n = a.erase_subject("user:1", 4).unwrap();
    assert_eq!(n, 1, "the case-variant row was not erased");
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let left = a
        .query("SELECT body, \"_Subject\" FROM notes", &[])
        .unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        left.values,
        [[
            Value::Text("pii:ROW-other".into()),
            Value::Text("user:2".into())
        ]]
    );
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

/// #198: a turn that uses a secret and does not write SQL does not run `instr`.
#[test]
fn a_read_only_sql_turn_does_not_scrub() {
    let mut a = actor("no-write");
    let (_, res) = commit(
        &mut a,
        &opts(1, 1, true),
        &["CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"],
        1,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let text = "sk-live-0123456789";
    let (_, res) = commit(
        &mut a,
        &opts(2, 2, false),
        &[&format!("INSERT INTO notes(body) VALUES ('{text}')")],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    a.begin_turn(&opts(3, 3, false)).unwrap();
    a.query("SELECT body FROM notes", &[]).unwrap();
    assert_eq!(a.scrub(&[("api", text.as_bytes())]).unwrap(), 0);
    assert_eq!(a.last_scrub_fullscan_steps, 0);
    a.end_turn(true).unwrap();
    a.begin_turn(&opts(4, 4, false)).unwrap();
    let rows = a.query("SELECT body FROM notes", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(rows.values, [[Value::Text(text.into())]]);
}

/// #198: the first write that sees a secret removes it from cells that turn
/// did not write, and a rebuild applies the same replacement.
#[test]
fn the_first_write_that_sees_a_secret_scrubs_untouched_cells() {
    let mut a = actor("once");
    let schema = ["CREATE TABLE keys (id INTEGER PRIMARY KEY, t TEXT, b BLOB)"];
    let (schema_turn, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let text = "sk-live-0123456789";
    let binary: &[u8] = &[0x00, 0xff, 0x10, 0x80, 0x7f, 0x01];
    a.begin_turn(&opts(2, 2, false)).unwrap();
    a.execute(
        "INSERT INTO keys(t, b) VALUES (?1, ?2)",
        &[
            Value::Text(format!("x{text}y")),
            Value::Blob([&b"\x00\x01"[..], binary, &b"\x02"[..]].concat()),
        ],
    )
    .unwrap();
    let seed = a.end_turn(true).unwrap();
    a.apply(&seed, 2, &BTreeSet::new()).unwrap();
    a.begin_turn(&opts(3, 3, false)).unwrap();
    a.execute("INSERT INTO keys(t) VALUES ('other')", &[])
        .unwrap();
    let changed = a
        .scrub(&[("api", text.as_bytes()), ("bin", binary)])
        .unwrap();
    assert!(changed >= 2, "the untouched text and blob cells");
    assert!(
        a.last_scrub_fullscan_steps > 0,
        "the first sighting did not scan"
    );
    let scan = a.end_turn(true).unwrap();
    a.apply(&scan, 3, &BTreeSet::new()).unwrap();
    a.begin_turn(&opts(4, 4, false)).unwrap();
    let rows = a.query("SELECT t, b FROM keys ORDER BY id", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        rows.values[0][0],
        Value::Text("x[secret:api]y".into()),
        "the untouched text cell kept the secret"
    );
    assert!(
        !holds(&blob_of(&rows.values[0][1]), binary),
        "the untouched blob cell kept the secret"
    );
    let mut rebuilt = actor("once-rebuilt");
    for (i, t) in [&schema_turn, &seed, &scan].into_iter().enumerate() {
        let mut t = t.clone();
        t.whole.clear();
        rebuilt.apply(&t, i as u64 + 1, &BTreeSet::new()).unwrap();
    }
    rebuilt.begin_turn(&opts(5, 5, false)).unwrap();
    let again = rebuilt
        .query("SELECT t, b FROM keys ORDER BY id", &[])
        .unwrap();
    rebuilt.end_turn(false).unwrap();
    assert_eq!(again.values, rows.values);
}

/// #198: once a secret has been seen, SQL end of a one-row update does not
/// scan a large table, and a text or blob cell that turn wrote loses the secret.
#[test]
fn a_seen_secret_is_scrubbed_from_written_cells_without_scanning() {
    let mut a = actor("seen");
    let schema = [
        "CREATE TABLE keys (id INTEGER PRIMARY KEY, t TEXT, b BLOB)",
        "CREATE TABLE loose (body TEXT)",
    ];
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let text = "sk-live-0123456789";
    let binary: &[u8] = &[0x00, 0xff, 0x10, 0x80, 0x7f, 0x01];
    a.begin_turn(&opts(2, 2, false)).unwrap();
    a.execute("INSERT INTO keys(t) VALUES ('warm')", &[])
        .unwrap();
    a.execute("INSERT INTO loose(body) VALUES ('warm')", &[])
        .unwrap();
    a.scrub(&[("api", text.as_bytes()), ("bin", binary)])
        .unwrap();
    let warm = a.end_turn(true).unwrap();
    a.apply(&warm, 2, &BTreeSet::new()).unwrap();

    a.begin_turn(&opts(3, 3, false)).unwrap();
    for i in 0..1_000 {
        a.execute(
            "INSERT INTO keys(t) VALUES (?1)",
            &[Value::Text(format!("row-{i}"))],
        )
        .unwrap();
    }
    a.execute(
        "INSERT INTO keys(t, b) VALUES (?1, ?2)",
        &[
            Value::Text(format!("x{text}y")),
            Value::Blob(text.as_bytes().to_vec()),
        ],
    )
    .unwrap();
    let seeded = a.end_turn(true).unwrap();
    a.apply(&seeded, 3, &BTreeSet::new()).unwrap();

    a.begin_turn(&opts(4, 4, false)).unwrap();
    let written_blob = [&b"aa"[..], binary, &b"bb"[..]].concat();
    a.execute(
        "INSERT INTO keys(t, b) VALUES (?1, ?2)",
        &[
            Value::Text(format!("pre-{text}-post")),
            Value::Blob(written_blob.clone()),
        ],
    )
    .unwrap();
    a.execute(
        "INSERT INTO loose(body) VALUES (?1)",
        &[Value::Text(text.into())],
    )
    .unwrap();
    let changed = a
        .scrub(&[("api", text.as_bytes()), ("bin", binary)])
        .unwrap();
    assert!(
        changed >= 3,
        "the written text cell, its blob, and the rowid-table cell"
    );
    assert_eq!(a.last_scrub_fullscan_steps, 0, "SQL end scanned the table");
    let t = a.end_turn(true).unwrap();
    assert!(
        !holds(&t.whole, text.as_bytes()),
        "the log holds the text secret"
    );
    assert!(!holds(&t.whole, binary), "the log holds the binary secret");
    for (_, cs) in &t.changesets {
        assert!(!holds(cs, text.as_bytes()), "the log holds the text secret");
        assert!(!holds(cs, binary), "the log holds the binary secret");
    }
    a.apply(&t, 4, &BTreeSet::new()).unwrap();
    a.begin_turn(&opts(5, 5, false)).unwrap();
    let rows = a
        .query(
            "SELECT t, b FROM keys WHERE t LIKE 'pre-%' OR t LIKE 'x%' ORDER BY id",
            &[],
        )
        .unwrap();
    let loose = a
        .query("SELECT body FROM loose ORDER BY rowid", &[])
        .unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(rows.values.len(), 2);
    assert_eq!(rows.values[0][0], Value::Text(format!("x{text}y")));
    assert!(holds(&blob_of(&rows.values[0][1]), text.as_bytes()));
    assert_eq!(
        rows.values[1][0],
        Value::Text("pre-[secret:api]-post".into())
    );
    assert_eq!(
        blob_of(&rows.values[1][1]),
        [&b"aa"[..], b"[secret:bin]", &b"bb"[..]].concat()
    );
    assert!(!holds(&blob_of(&rows.values[1][1]), binary));
    assert_eq!(
        loose.values,
        [
            vec![Value::Text("warm".into())],
            vec![Value::Text("[secret:api]".into())]
        ]
    );
}

/// #198: the one-time scan is remembered in the actor database, so a restart
/// does not scan again.
#[test]
fn reopening_an_actor_does_not_rescan_a_scrubbed_secret() {
    let dir = tempfile::tempdir().unwrap();
    let opener = FileOpener {
        root: dir.path().to_path_buf(),
    };
    let text: &[u8] = b"sk-live-0123456789";
    {
        let mut a = SqlActor::open(&opener, "notes/n", Limits::default()).unwrap();
        let (_, res) = commit(
            &mut a,
            &opts(1, 1, true),
            &["CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"],
            1,
        );
        assert!(res.iter().all(Result::is_ok), "{res:?}");
        a.begin_turn(&opts(2, 2, false)).unwrap();
        a.execute("INSERT INTO notes(body) VALUES ('warm')", &[])
            .unwrap();
        a.scrub(&[("api", text)]).unwrap();
        let t = a.end_turn(true).unwrap();
        a.apply(&t, 2, &BTreeSet::new()).unwrap();
    }
    let mut a = SqlActor::open(&opener, "notes/n", Limits::default()).unwrap();
    a.begin_turn(&opts(3, 3, false)).unwrap();
    a.execute("UPDATE notes SET body = 'later' WHERE id = 1", &[])
        .unwrap();
    a.scrub(&[("api", text)]).unwrap();
    assert_eq!(
        a.last_scrub_fullscan_steps, 0,
        "a restart scanned for a secret already scrubbed"
    );
    a.end_turn(false).unwrap();
}

fn blob_of(value: &Value) -> Vec<u8> {
    match value {
        Value::Blob(b) => b.clone(),
        other => panic!("expected a blob, got {other:?}"),
    }
}

/// Found with #72: an erasure applied while a turn of the actor has its
/// savepoint open. Before, the deletes ran inside the savepoint, so the
/// turn's end rolled them back (and the applied LSN with them): the
/// subject's rows stayed in the live database, which a rebuild deletes. Now
/// the erasure runs right after the turn's savepoint is rolled back, and the
/// turn's changeset holds only its own changes.
#[test]
fn an_erasure_during_a_turn_is_not_rolled_back_by_its_end() {
    let mut a = actor("mid-turn");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &SCHEMA[..1], 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let mut o = opts(2, 2, false);
    o.default_subject = Some("user:1".into());
    let (_, res) = commit(
        &mut a,
        &o,
        &["INSERT INTO notes(body) VALUES ('personal')"],
        2,
    );
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let mut o = opts(3, 3, false);
    o.default_subject = Some("user:2".into());
    a.begin_turn(&o).unwrap();
    a.query("INSERT INTO notes(body) VALUES ('other')", &[])
        .unwrap();
    // The erasure's record is applied while the turn is open.
    a.erase_subject("user:1", 4).unwrap();
    let mut t = a.end_turn(true).unwrap();
    assert!(
        t.changesets
            .iter()
            .all(|(s, _)| s.as_deref() == Some("user:2")),
        "the erasure's deletes became the turn's changes: {t:?}"
    );
    assert_eq!(a.applied_lsn().unwrap(), 4, "the erasure was rolled back");
    t.whole.clear();
    a.apply(&t, 5, &BTreeSet::new()).unwrap();
    a.begin_turn(&opts(6, 6, false)).unwrap();
    let rows = a
        .query("SELECT body, _subject FROM notes ORDER BY id", &[])
        .unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        rows.values,
        [[Value::Text("other".into()), Value::Text("user:2".into())]]
    );
}

/// A migrate may create a table whose name or primary-key column contains
/// `"`. Erasure, subject lookup on an UPDATE, and the actor database hash
/// must quote those names. The erasure deletes the subject's rows, advances
/// the applied LSN, and a replay of the same records (what a restart applies)
/// still answers queries.
#[test]
fn a_quoted_table_name_erases_splits_and_hashes() {
    let schema = [
        "CREATE TABLE \"a\"\"b\" (\"id\"\"x\" INTEGER PRIMARY KEY, body TEXT NOT NULL, \
         _subject TEXT DEFAULT (kronik_subject()))",
        "CREATE TABLE \"c\"\"d\" (body TEXT NOT NULL, \
         _subject TEXT DEFAULT (kronik_subject()))",
    ];
    let mut live = actor("quoted-live");
    let (schema_turn, res) = commit(&mut live, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let inserts = [
        "INSERT INTO \"a\"\"b\"(body) VALUES ('pk-mine')",
        "INSERT INTO \"a\"\"b\"(body, _subject) VALUES ('pk-theirs', 'user:2')",
        "INSERT INTO \"c\"\"d\"(body) VALUES ('row-mine')",
        "INSERT INTO \"c\"\"d\"(body, _subject) VALUES ('row-theirs', 'user:2')",
    ];
    let (inserted, res) = commit(&mut live, &as_subject(2, "user:1"), &inserts, 2);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let updates = [
        "UPDATE \"a\"\"b\" SET body = 'pk-edited' WHERE \"id\"\"x\" = 1",
        "UPDATE \"c\"\"d\" SET body = 'row-edited' WHERE rowid = 1",
    ];
    let (updated, res) = commit(&mut live, &as_subject(3, "user:3"), &updates, 3);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    assert!(
        updated
            .changesets
            .iter()
            .all(|(s, _)| s.as_deref() == Some("user:1")),
        "subject lookup must attribute the update to the row's subject: {updated:?}"
    );
    let before = live.canonical_hash().unwrap();
    assert!(
        live.table_rows()
            .unwrap()
            .iter()
            .any(|(name, _)| name.contains('"')),
        "inspect must read a quoted table name"
    );
    assert!(
        live.canonical_rows()
            .unwrap()
            .iter()
            .any(|table| table.name.contains('"')),
        "a behavior diff must read a quoted table name"
    );

    let erased = live.erase_subject("user:1", 4).unwrap();
    assert!(erased >= 2, "quoted tables were not erased: {erased}");
    assert_eq!(live.applied_lsn().unwrap(), 4);
    assert!(live.conn.is_autocommit());
    assert_eq!(quoted_bodies(&mut live), ["pk-theirs", "row-theirs"]);

    let mut rebuilt = actor("quoted-rebuilt");
    for (lsn, turn) in [schema_turn, inserted, updated].into_iter().enumerate() {
        rebuilt
            .apply(&turn, lsn as u64 + 1, &BTreeSet::new())
            .unwrap();
    }
    assert_eq!(rebuilt.canonical_hash().unwrap(), before);
    rebuilt.erase_subject("user:1", 4).unwrap();
    assert_eq!(rebuilt.applied_lsn().unwrap(), 4);
    assert_eq!(
        rebuilt.canonical_hash().unwrap(),
        live.canonical_hash().unwrap()
    );
    assert_eq!(quoted_bodies(&mut rebuilt), ["pk-theirs", "row-theirs"]);
}

fn quoted_bodies(a: &mut SqlActor) -> Vec<String> {
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let mut bodies = Vec::new();
    for sql in [
        "SELECT body FROM \"a\"\"b\" ORDER BY \"id\"\"x\"",
        "SELECT body FROM \"c\"\"d\" ORDER BY rowid",
    ] {
        let rows = a.query(sql, &[]).unwrap();
        bodies.extend(rows.values.into_iter().map(|row| match row.as_slice() {
            [Value::Text(body)] => body.clone(),
            other => panic!("unexpected row {other:?}"),
        }));
    }
    a.end_turn(false).unwrap();
    bodies
}

/// A statement that fails during erasure rolls `kronik_apply` back before
/// the error is returned. The failure is a trigger, not parent-before-child
/// order. Rows deleted earlier in the same erasure come back, the applied
/// LSN does not move, the savepoint is not left open, and a later erasure
/// of the same quoted parent and child still deletes both.
#[test]
fn a_failed_erasure_statement_rolls_the_savepoint_back() {
    let schema = [
        "CREATE TABLE early (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
         _subject TEXT DEFAULT (kronik_subject()))",
        "CREATE TRIGGER block_early BEFORE DELETE ON early \
         BEGIN SELECT RAISE(ABORT, 'erasure trigger'); END",
        "CREATE TABLE \"m\"\"parent\" (id INTEGER PRIMARY KEY, _subject TEXT)",
        "CREATE TABLE \"z\"\"child\" (id INTEGER PRIMARY KEY, \
         parent INTEGER NOT NULL REFERENCES \"m\"\"parent\"(id), _subject TEXT)",
    ];
    let mut a = actor("erasure-rollback");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let inserts = [
        "INSERT INTO early(body) VALUES ('kept')",
        "INSERT INTO early(body, _subject) VALUES ('other', 'user:2')",
        "INSERT INTO \"m\"\"parent\"(id, _subject) VALUES (1, 'user:1')",
        "INSERT INTO \"z\"\"child\"(id, parent, _subject) VALUES (1, 1, 'user:1')",
    ];
    let (_, res) = commit(&mut a, &as_subject(2, "user:1"), &inserts, 2);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let err = a.erase_subject("user:1", 3).unwrap_err();
    assert!(
        err.contains("erasure trigger"),
        "the quoted names parse; a trigger, not delete order, fails the statement: {err}"
    );
    assert!(
        !err.contains("FOREIGN KEY"),
        "parent-before-child must not be the failure: {err}"
    );
    assert!(
        a.conn.is_autocommit(),
        "kronik_apply was left open after {err}"
    );
    assert_eq!(
        a.applied_lsn().unwrap(),
        2,
        "a failed erasure advanced the LSN"
    );
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let kept = a.query("SELECT body FROM early ORDER BY id", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        kept.values,
        [[Value::Text("kept".into())], [Value::Text("other".into())]],
        "the earlier delete in the same erasure was committed"
    );

    let (_, res) = commit(&mut a, &opts(4, 4, true), &["DROP TRIGGER block_early"], 3);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let n = a.erase_subject("user:1", 4).unwrap();
    assert!(n >= 3, "erasure after the rollback did not delete: {n}");
    assert_eq!(a.applied_lsn().unwrap(), 4);
    assert!(a.conn.is_autocommit());
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let left = a.query("SELECT body FROM early ORDER BY id", &[]).unwrap();
    let parents = a.query("SELECT id FROM \"m\"\"parent\"", &[]).unwrap();
    let children = a.query("SELECT id FROM \"z\"\"child\"", &[]).unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(left.values, [[Value::Text("other".into())]]);
    assert!(parents.values.is_empty() && children.values.is_empty());
}

/// Issue #241: a parent and child of the same subject erase together even
/// though the parent table sorts first. The other subject's row stays. A
/// fresh actor applying the same turns and erasure (a restart) matches.
#[test]
fn a_same_subject_parent_and_child_erase_together() {
    let schema = [
        "CREATE TABLE account (id INTEGER PRIMARY KEY, _subject TEXT)",
        "CREATE TABLE line (id INTEGER PRIMARY KEY, \
         account_id INTEGER NOT NULL REFERENCES account(id), _subject TEXT)",
    ];
    let inserts = [
        "INSERT INTO account(id, _subject) VALUES (1, 'user:1')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:1')",
        "INSERT INTO account(id, _subject) VALUES (2, 'user:2')",
        "INSERT INTO line(id, account_id, _subject) VALUES (2, 2, 'user:2')",
    ];
    let mut live = actor("fk-live");
    let (schema_turn, res) = commit(&mut live, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (inserted, res) = commit(&mut live, &as_subject(2, "user:1"), &inserts, 2);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let n = live.erase_subject("user:1", 3).unwrap();
    assert!(n >= 2, "parent and child were not both deleted: {n}");
    assert_eq!(live.applied_lsn().unwrap(), 3);
    assert!(live.conn.is_autocommit());
    assert_eq!(fk_rows(&mut live), [(2, 2, "user:2".into())]);

    let mut rebuilt = actor("fk-rebuilt");
    rebuilt.apply(&schema_turn, 1, &BTreeSet::new()).unwrap();
    rebuilt.apply(&inserted, 2, &BTreeSet::new()).unwrap();
    rebuilt.erase_subject("user:1", 3).unwrap();
    assert_eq!(rebuilt.applied_lsn().unwrap(), 3);
    assert_eq!(fk_rows(&mut rebuilt), fk_rows(&mut live));
}

fn fk_rows(a: &mut SqlActor) -> Vec<(i64, i64, String)> {
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let rows = a
        .query(
            "SELECT a.id, l.id, l._subject FROM line l JOIN account a ON a.id = l.account_id \
             ORDER BY l.id",
            &[],
        )
        .unwrap();
    a.end_turn(false).unwrap();
    rows.values
        .into_iter()
        .map(|row| match row.as_slice() {
            [
                Value::Integer(account),
                Value::Integer(line),
                Value::Text(subject),
            ] => (*account, *line, subject.clone()),
            other => panic!("unexpected row {other:?}"),
        })
        .collect()
}

/// A row of another subject that references the erased parent is not
/// deleted, and the failure does not leave the savepoint open or advance
/// the applied LSN. Cascade would otherwise delete that row.
#[test]
fn another_subjects_reference_blocks_erasure() {
    let schema = [
        "CREATE TABLE account (id INTEGER PRIMARY KEY, _subject TEXT)",
        "CREATE TABLE line (id INTEGER PRIMARY KEY, \
         account_id INTEGER REFERENCES account(id) ON DELETE CASCADE, _subject TEXT)",
        "CREATE TABLE \"z\"\"child\" (id INTEGER PRIMARY KEY, \
         account_id INTEGER REFERENCES account(id), _subject TEXT)",
    ];
    let inserts = [
        "INSERT INTO account(id, _subject) VALUES (1, 'user:1')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:2')",
        "INSERT INTO \"z\"\"child\"(id, account_id, _subject) VALUES (1, 1, 'user:2')",
    ];
    let mut a = actor("fk-blocked");
    let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    let (_, res) = commit(&mut a, &as_subject(2, "user:1"), &inserts, 2);
    assert!(res.iter().all(Result::is_ok), "{res:?}");

    let err = a.erase_subject("user:1", 3).unwrap_err();
    assert!(
        err.starts_with("constraint:"),
        "a cross-subject reference is not a corrupt database: {err}"
    );
    assert!(a.conn.is_autocommit(), "savepoint left open after {err}");
    assert_eq!(a.applied_lsn().unwrap(), 2);
    a.begin_turn(&opts(0, 0, false)).unwrap();
    let accounts = a.query("SELECT id, _subject FROM account", &[]).unwrap();
    let lines = a.query("SELECT id, _subject FROM line", &[]).unwrap();
    let quoted = a
        .query("SELECT id, _subject FROM \"z\"\"child\"", &[])
        .unwrap();
    a.end_turn(false).unwrap();
    assert_eq!(
        accounts.values,
        [[Value::Integer(1), Value::Text("user:1".into())]]
    );
    assert_eq!(
        lines.values,
        [[Value::Integer(1), Value::Text("user:2".into())]]
    );
    assert_eq!(
        quoted.values,
        [[Value::Integer(1), Value::Text("user:2".into())]]
    );
}

/// `REFERENCES parent` leaves the parent column NULL, and an unquoted name
/// may not match the table's spelling. Same-subject rows still erase. A
/// cross-subject child is seen before any delete. A dangling key that was
/// already there is not this erasure's failure.
#[test]
fn an_implicit_parent_key_erases_and_a_cross_subject_child_blocks() {
    let schema = [
        "CREATE TABLE Account (id INTEGER PRIMARY KEY, _subject TEXT)",
        "CREATE TABLE line (id INTEGER PRIMARY KEY, \
         account_id INTEGER NOT NULL REFERENCES account, _subject TEXT)",
        "CREATE TABLE pair (a INTEGER NOT NULL, b INTEGER NOT NULL, _subject TEXT, \
         PRIMARY KEY (a, b))",
        "CREATE TABLE edge (id INTEGER PRIMARY KEY, x INTEGER, y INTEGER, _subject TEXT, \
         FOREIGN KEY (x, y) REFERENCES pair)",
        "CREATE TABLE dangling (id INTEGER PRIMARY KEY, \
         account_id INTEGER REFERENCES Account(id))",
    ];
    let mut live = actor("fk-implicit");
    let (_, res) = commit(&mut live, &opts(1, 1, true), &schema, 1);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    live.set_host();
    live.conn
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             INSERT INTO dangling(id, account_id) VALUES (1, 99);
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
    let inserts = [
        "INSERT INTO Account(id, _subject) VALUES (1, 'user:1')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:1')",
        "INSERT INTO pair(a, b, _subject) VALUES (1, 2, 'user:1')",
        "INSERT INTO edge(id, x, y, _subject) VALUES (1, 1, 2, 'user:1')",
    ];
    let (_, res) = commit(&mut live, &as_subject(2, "user:1"), &inserts, 2);
    assert!(res.iter().all(Result::is_ok), "{res:?}");
    live.erase_subject("user:1", 3).unwrap();
    assert_eq!(live.applied_lsn().unwrap(), 3);
    assert!(live.conn.is_autocommit());
    live.begin_turn(&opts(0, 0, false)).unwrap();
    let left = live
        .query(
            "SELECT (SELECT count(*) FROM Account) + (SELECT count(*) FROM line) \
             + (SELECT count(*) FROM pair) + (SELECT count(*) FROM edge), \
             (SELECT count(*) FROM dangling)",
            &[],
        )
        .unwrap();
    live.end_turn(false).unwrap();
    assert_eq!(
        left.values,
        [[Value::Integer(0), Value::Integer(1)]],
        "a pre-existing dangling key blocked erasure, or a subject row remained"
    );

    let blocked = [
        (
            "fk-case",
            "line",
            &[
                "INSERT INTO Account(id, _subject) VALUES (1, 'user:1')",
                "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:2')",
            ][..],
        ),
        (
            "fk-composite",
            "edge",
            &[
                "INSERT INTO pair(a, b, _subject) VALUES (1, 2, 'user:1')",
                "INSERT INTO edge(id, x, y, _subject) VALUES (1, 1, 2, 'user:2')",
            ][..],
        ),
    ];
    for (name, needle, inserts) in blocked {
        let mut a = actor(name);
        let (_, res) = commit(&mut a, &opts(1, 1, true), &schema, 1);
        assert!(res.iter().all(Result::is_ok), "{name}: {res:?}");
        let (_, res) = commit(&mut a, &as_subject(2, "user:1"), inserts, 2);
        assert!(res.iter().all(Result::is_ok), "{name}: {res:?}");
        let why = a
            .erasure_blocked_by("user:1")
            .unwrap()
            .unwrap_or_else(|| panic!("{name}: pre-check missed the other subject's row"));
        assert!(
            why.contains(needle),
            "{name}: pre-check did not name {needle}: {why}"
        );
        let err = a.erase_subject("user:1", 3).unwrap_err();
        assert!(err.starts_with("constraint:"), "{name}: {err}");
        assert!(a.conn.is_autocommit(), "{name}: {err}");
        assert_eq!(a.applied_lsn().unwrap(), 2, "{name}");
    }
}

#[test]
fn a_small_pool_still_evicts_when_nothing_asks_it_to_grow() {
    let pool = SqlPool::new(Arc::new(MemOpener), Limits::default(), 1);
    drop(pool.get("a/1").unwrap());
    drop(pool.get("b/1").unwrap());
    let open = &pool.inner.lock().unwrap().open;
    assert_eq!(open.len(), 1);
    assert!(open.contains_key("b/1"));
    assert!(!open.contains_key("a/1"));
}

#[test]
fn retain_opened_keeps_actors_past_the_constructed_capacity() {
    let pool = SqlPool::new(Arc::new(MemOpener), Limits::default(), 1);
    pool.retain_opened(3);
    for name in ["a/1", "b/1", "c/1"] {
        drop(pool.get(name).unwrap());
    }
    let g = pool.inner.lock().unwrap();
    assert_eq!(g.open.len(), 3);
    assert!(g.capacity >= 3);
}

#[test]
fn the_live_pool_can_grow_past_256() {
    let pool = SqlPool::for_node(Arc::new(MemOpener), Limits::default());
    let g = pool.inner.lock().unwrap();
    assert_eq!(g.capacity, 256);
    assert!(g.retain_max.is_some_and(|n| n >= 256));
}
