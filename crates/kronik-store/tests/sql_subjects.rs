//! Per-subject SQL changesets through the store (ADR 0005 §6,
//! `subjects/erasure`). One turn writes rows of two subjects, and the node
//! seals each changeset of its record under that changeset's subject.
//! Erasing one subject destroys its key, so its changeset cannot be read
//! again: the other subject's rows stay, live and in a rebuild from the log,
//! and a rebuild that stops before the erasure record holds no row of the
//! erased subject either. Filing every row under the turn's default subject
//! would leave the erased subject's rows readable in the other subject's
//! changeset.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use kronik_log::{Committed, Position};
use kronik_privacy::MasterKey;
use kronik_privacy::keystore::Keystore;
use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_store::Store;
use kronik_store::StoreError;
use kronik_store::sql::{Limits, MemOpener, SqlActor, TurnOpts, TurnSql, changeset_rows};

const SCHEMA: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, \
     _subject TEXT DEFAULT (kronik_subject()))";
/// The row the turn writes for its own subject, `user:1`.
const MINE: &str = "ROW-of-user-1-7f3a";
/// The row the same turn writes for `user:2`.
const THEIRS: &str = "ROW-of-user-2-9c1e";

fn turn_opts(seed: u8, subject: Option<&str>, migrate: bool) -> TurnOpts {
    TurnOpts {
        seed: [seed; 32],
        time_ms: i64::from(seed),
        default_subject: subject.map(str::to_owned),
        migrate,
        sql_budget: 50_000_000,
        max_bytes: 0,
    }
}

fn committed(lsn: u64, record: Record) -> Committed {
    Committed {
        lsn,
        pos: Position {
            segment: 0,
            offset: 0,
        },
        record,
    }
}

fn turn(lsn: u64, ddl: &[String], sql_changes: Vec<pb::SqlChangeset>) -> Committed {
    committed(
        lsn,
        Record::TurnRecord(pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "notes".into(),
                key: "n".into(),
            }),
            causal_key: Some(kronik_core::causal::root(format!("r{lsn}"))),
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    method: "POST".into(),
                    path: "/notes".into(),
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(pb::Sealable {
                            subject: None,
                            value: Some(pb::sealable::Value::Plain(Vec::new())),
                        })),
                    }),
                    ..Default::default()
                })),
            }),
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            sql_schema: ddl
                .iter()
                .map(|statement| pb::SqlSchemaChange {
                    statement: statement.clone(),
                })
                .collect(),
            sql_changes,
            ..Default::default()
        }),
    )
}

/// The records as a rebuild reads them back from the log: each one encoded
/// and decoded again.
fn from_log(records: &[Committed]) -> Vec<Committed> {
    records
        .iter()
        .map(|c| {
            let record = Record::decode(c.record.kind(), &c.record.encode()).unwrap();
            committed(c.lsn, record)
        })
        .collect()
}

/// A store that opens sealed changesets with `sealer`, after `records`.
fn store_after(sealer: &Arc<Sealer>, records: &[Committed]) -> Arc<Store> {
    let store = Store::memory().unwrap();
    store.set_sealer(sealer.clone());
    store.apply(records).unwrap();
    store
}

/// A sealer that seals with the keys of an in-memory keystore, as the node's
/// does. `seed` selects the master key.
fn sealer_on(seed: u8) -> Arc<Sealer> {
    let master = MasterKey::from_bytes([seed; 32]).unwrap();
    let sealer = Arc::new(Sealer::new(Arc::new(
        Keystore::open_memory(&master).unwrap(),
    )));
    sealer.set_on(true);
    sealer
}

/// The two columns of `sql`, read from the actor's database as its host.
fn select<A: rusqlite::types::FromSql, B: rusqlite::types::FromSql>(
    store: &Store,
    sql: &str,
) -> Vec<(A, B)> {
    let db = store.sql.get("notes/n").unwrap();
    let actor = db.lock().unwrap();
    actor.set_host();
    let mut st = actor.conn.prepare(sql).unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The actor's rows: (body, `_subject`).
fn rows(store: &Store) -> Vec<(String, String)> {
    select(store, "SELECT body, _subject FROM notes ORDER BY id")
}

fn row(body: &str, subject: &str) -> (String, String) {
    (body.to_owned(), subject.to_owned())
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn erasing_one_subject_of_a_turn_keeps_the_other_subjects_rows_live_and_rebuilt() {
    let sealer = sealer_on(5);
    let insert_mine = format!("INSERT INTO notes(body) VALUES ('{MINE}')");
    let insert_theirs = format!("INSERT INTO notes(body, _subject) VALUES ('{THEIRS}', 'user:2')");
    let schema: &[&str] = &[SCHEMA];
    let writes: &[&str] = &[insert_mine.as_str(), insert_theirs.as_str()];
    let turns = guest_turns(&[schema, writes]);
    // The node seals each changeset of the turn record under its subject.
    let sealed = seal_changes(&sealer, &turns[1].changesets, 2);
    let subjects: Vec<Option<&str>> = sealed
        .iter()
        .map(|c| c.changeset.as_ref().and_then(|v| v.subject.as_deref()))
        .collect();
    assert_eq!(subjects, [Some("user:1"), Some("user:2")]);
    let mut log = vec![
        turn(1, &turns[0].ddl, Vec::new()),
        turn(2, &[], sealed.clone()),
    ];

    let live = store_after(&sealer, &log);
    assert_eq!(
        rows(&live),
        [row(MINE, "user:1"), row(THEIRS, "user:2")],
        "both subjects' rows before the erasure"
    );

    // `privacy erase user:2`: the subject's key is destroyed, then its
    // Erasure record is logged and applied.
    let key_version = sealer.erase("user:2", 3).unwrap();
    log.push(committed(
        3,
        Record::Erasure(pb::Erasure {
            subject: "user:2".into(),
            key_version,
            ..Default::default()
        }),
    ));
    live.apply(&log[2..]).unwrap();
    assert_eq!(
        rows(&live),
        [row(MINE, "user:1")],
        "live, after the erasure"
    );

    // What the log keeps of the turn: `user:2`'s row only in its own
    // changeset, which no one can open any more; the changeset that still
    // opens holds `user:1`'s row and nothing of `user:2`'s.
    for change in &sealed {
        let value = change.changeset.as_ref().unwrap();
        match sealer.open(value) {
            Opened::Value(bytes) => {
                assert_eq!(value.subject.as_deref(), Some("user:1"));
                assert!(holds(&bytes, MINE));
                assert!(
                    !holds(&bytes, THEIRS),
                    "an erased subject's row is readable in another subject's changeset"
                );
            }
            Opened::Erased { subject } => assert_eq!(subject, "user:2"),
            Opened::Unreadable { subject, why } => panic!("{subject}: {why}"),
        }
    }

    // A rebuild from the log equals the live database.
    let rebuilt = store_after(&sealer, &from_log(&log));
    assert_eq!(
        rows(&rebuilt),
        [row(MINE, "user:1")],
        "rebuilt from the log"
    );
    let hash = |store: &Store| {
        let db = store.sql.get("notes/n").unwrap();
        let actor = db.lock().unwrap();
        actor.canonical_hash().unwrap()
    };
    assert_eq!(hash(&live), hash(&rebuilt));

    // A rebuild that stops before the Erasure record, as a fork from that
    // point starts, has no row of `user:2` either: its changeset is skipped
    // as erased, and nothing else holds the row.
    let before = store_after(&sealer, &from_log(&log[..2]));
    assert_eq!(
        rows(&before),
        [row(MINE, "user:1")],
        "rebuilt to a point before the erasure record"
    );
}

fn actor_applied(store: &Store) -> u64 {
    let db = store.sql.get("notes/n").unwrap();
    db.lock().unwrap().applied_lsn().unwrap()
}

type SubjectChanges = Vec<(Option<String>, Vec<u8>)>;

fn sealable_changes(changes: SubjectChanges) -> Vec<pb::SqlChangeset> {
    changes
        .into_iter()
        .map(|(subject, cs)| pb::SqlChangeset {
            changeset: Some(pb::Sealable {
                subject,
                value: Some(pb::sealable::Value::Plain(cs)),
            }),
        })
        .collect()
}

fn account_line(store: &Store) -> Vec<(i64, String)> {
    select(store, "SELECT id, _subject FROM account ORDER BY id")
}

const FK_SCHEMA: &[&str] = &[
    "CREATE TABLE account (id INTEGER PRIMARY KEY, _subject TEXT)",
    "CREATE TABLE line (id INTEGER PRIMARY KEY, \
     account_id INTEGER NOT NULL REFERENCES account(id), _subject TEXT)",
];

/// A cross-subject reference is not `STORAGE_CORRUPT`. Apply refuses it,
/// leaves the rows, and a second apply (a restart of that record) does too.
#[test]
fn a_cross_subject_reference_is_not_a_corrupt_erasure() {
    let inserts = [
        "INSERT INTO account(id, _subject) VALUES (1, 'user:1')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'user:2')",
    ];
    let turns = guest_turns(&[FK_SCHEMA, &inserts]);
    let sealer = Arc::new(Sealer::plain());
    let log = [
        turn(1, &turns[0].ddl, Vec::new()),
        turn(2, &[], sealable_changes(turns[1].changesets.clone())),
        committed(
            3,
            Record::Erasure(pb::Erasure {
                subject: "user:1".into(),
                ..Default::default()
            }),
        ),
    ];
    let live = store_after(&sealer, &log[..2]);
    let blocked = live.erasure_blocked("user:1").unwrap().unwrap();
    assert!(blocked.contains("line"), "{blocked}");
    assert!(blocked.contains("user:1"), "{blocked}");
    for _ in 0..2 {
        let err = live.apply(&log[2..]).unwrap_err();
        assert!(
            matches!(err, StoreError::Constraint(_)),
            "foreign-key failure must not be STORAGE_CORRUPT: {err}"
        );
        assert!(!err.to_string().contains("STORAGE_CORRUPT"), "{err}");
    }
    assert_eq!(
        account_line(&live),
        [(1, "user:1".into())],
        "a refused erasure deleted the parent"
    );
    assert_eq!(actor_applied(&live), 2);
}

type FkRows = (Vec<(i64, String)>, Vec<(i64, i64, String)>);

fn guest_turns(turns: &[&[&str]]) -> Vec<TurnSql> {
    let mut actor = SqlActor::open(&MemOpener, "notes/n", Limits::default()).unwrap();
    let mut out = Vec::new();
    for (i, stmts) in turns.iter().enumerate() {
        let migrate = i == 0;
        actor
            .begin_turn(&turn_opts(
                (i + 1) as u8,
                (!migrate).then_some("user:1"),
                migrate,
            ))
            .unwrap();
        for statement in *stmts {
            actor
                .query(statement, &[])
                .unwrap_or_else(|e| panic!("{statement}: {e:?}"));
        }
        let mut recorded = actor.end_turn(true).unwrap();
        actor
            .apply(&recorded, (i + 1) as u64, &BTreeSet::new())
            .unwrap_or_else(|e| panic!("guest apply: {e}"));
        recorded.whole.clear();
        out.push(recorded);
    }
    out
}

fn subject_names(changes: &[(Option<String>, Vec<u8>)]) -> Vec<Option<&str>> {
    changes
        .iter()
        .map(|(subject, _)| subject.as_deref())
        .collect()
}

fn read_fk(conn: &rusqlite::Connection) -> FkRows {
    let accounts = conn
        .prepare("SELECT id, _subject FROM account ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let lines = conn
        .prepare("SELECT id, account_id, _subject FROM line ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (accounts, lines)
}

fn store_fk(store: &Store) -> FkRows {
    let db = store.sql.get("notes/n").unwrap();
    let actor = db.lock().unwrap();
    actor.set_host();
    read_fk(&actor.conn)
}

fn direct_fk(statements: &[&str]) -> FkRows {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    for statement in statements {
        conn.execute(statement, []).unwrap();
    }
    read_fk(&conn)
}

fn seal_changes(
    sealer: &Sealer,
    changes: &[(Option<String>, Vec<u8>)],
    lsn: u64,
) -> Vec<pb::SqlChangeset> {
    changes
        .iter()
        .map(|(subject, cs)| {
            let mut value = pb::Sealable {
                subject: subject.clone(),
                value: Some(pb::sealable::Value::Plain(cs.clone())),
            };
            sealer
                .seal_value(&mut value, &|b: &mut [u8]| b.fill(9), lsn)
                .unwrap();
            assert!(
                matches!(value.value, Some(pb::sealable::Value::Sealed(_))),
                "sealing must keep a per-subject ciphertext"
            );
            pb::SqlChangeset {
                changeset: Some(value),
            }
        })
        .collect()
}

/// Issue #242: a parent for `z` and a child for `a` in one turn. Apply used
/// to insert `a` first and fail the foreign-key check after the record was
/// durable. The rows match a direct execution, a restart, and an erasure of
/// the child still opens only that subject's changeset.
#[test]
fn a_cross_subject_parent_insert_commits_and_survives_restart() {
    let inserts = [
        "INSERT INTO account(id, _subject) VALUES (1, 'z')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'a')",
    ];
    let turns = guest_turns(&[FK_SCHEMA, &inserts]);
    let changes = &turns[1].changesets;
    assert_eq!(subject_names(changes), [Some("a"), Some("z")]);
    for (subject, cs) in changes {
        let rows = changeset_rows(cs).unwrap();
        assert_eq!(rows.len(), 1, "{subject:?}");
        assert_eq!(rows[0].op, "insert");
        assert_eq!(
            rows[0].table,
            match subject.as_deref() {
                Some("a") => "line",
                Some("z") => "account",
                other => panic!("unexpected subject {other:?}"),
            }
        );
    }
    let sealer = sealer_on(9);
    let sealed = seal_changes(&sealer, changes, 2);
    assert_eq!(
        sealed
            .iter()
            .map(|c| c.changeset.as_ref().and_then(|v| v.subject.as_deref()))
            .collect::<Vec<_>>(),
        [Some("a"), Some("z")]
    );
    let mut log = vec![
        turn(1, &turns[0].ddl, Vec::new()),
        turn(2, &[], sealed.clone()),
    ];
    let expect = direct_fk(&[FK_SCHEMA[0], FK_SCHEMA[1], inserts[0], inserts[1]]);
    let live = store_after(&sealer, &log);
    assert_eq!(store_fk(&live), expect, "live apply");
    assert_eq!(
        store_fk(&store_after(&sealer, &from_log(&log))),
        expect,
        "restart"
    );
    let blocked = live.erasure_blocked("z").unwrap().unwrap();
    assert!(blocked.contains("line"), "{blocked}");
    assert!(live.erasure_blocked("a").unwrap().is_none());

    let key_version = sealer.erase("a", 3).unwrap();
    log.push(committed(
        3,
        Record::Erasure(pb::Erasure {
            subject: "a".into(),
            key_version,
            ..Default::default()
        }),
    ));
    live.apply(&log[2..])
        .expect("erasing the child must still apply");
    assert_eq!(store_fk(&live), (vec![(1, "z".into())], vec![]));
    for change in &sealed {
        let value = change.changeset.as_ref().unwrap();
        match sealer.open(value) {
            Opened::Value(bytes) => {
                assert_eq!(value.subject.as_deref(), Some("z"));
                let rows = changeset_rows(&bytes).unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].table, "account");
            }
            Opened::Erased { subject } => assert_eq!(subject, "a"),
            Opened::Unreadable { subject, why } => panic!("{subject}: {why}"),
        }
    }
    assert_eq!(
        store_fk(&store_after(&sealer, &from_log(&log))),
        store_fk(&live),
        "restart after erasure"
    );
}

/// Issue #242: delete the child for `z` and the parent for `a` in one turn.
/// Apply used to delete `a` first. A row of another subject stays.
#[test]
fn a_cross_subject_parent_delete_commits_and_survives_restart() {
    let setup = [
        "INSERT INTO account(id, _subject) VALUES (1, 'a')",
        "INSERT INTO line(id, account_id, _subject) VALUES (1, 1, 'z')",
        "INSERT INTO account(id, _subject) VALUES (2, 'keep')",
    ];
    let deletes = [
        "DELETE FROM line WHERE id = 1",
        "DELETE FROM account WHERE id = 1",
    ];
    let turns = guest_turns(&[FK_SCHEMA, &setup, &deletes]);
    let delete = &turns[2].changesets;
    assert_eq!(subject_names(delete), [Some("a"), Some("z")]);
    for (subject, cs) in delete {
        let rows = changeset_rows(cs).unwrap();
        assert_eq!(rows.len(), 1, "{subject:?}");
        assert_eq!(rows[0].op, "delete");
        assert_eq!(
            rows[0].table,
            match subject.as_deref() {
                Some("a") => "account",
                Some("z") => "line",
                other => panic!("unexpected subject {other:?}"),
            }
        );
    }
    let log: Vec<Committed> = turns
        .iter()
        .enumerate()
        .map(|(i, t)| turn(i as u64 + 1, &t.ddl, sealable_changes(t.changesets.clone())))
        .collect();
    let expect = direct_fk(&[
        FK_SCHEMA[0],
        FK_SCHEMA[1],
        setup[0],
        setup[1],
        setup[2],
        deletes[0],
        deletes[1],
    ]);
    let sealer = Arc::new(Sealer::plain());
    assert_eq!(store_fk(&store_after(&sealer, &log)), expect, "live apply");
    assert_eq!(
        store_fk(&store_after(&sealer, &from_log(&log))),
        expect,
        "restart"
    );
    assert_eq!(expect.0, [(2, "keep".into())]);
    assert!(expect.1.is_empty());
}

/// Issue #242: combining the changesets must not hide a conflict that is
/// still there. The apply rolls back, and a restart of that record fails
/// the same way.
#[test]
fn a_combined_changeset_conflict_fails_closed() {
    let turns = guest_turns(&[
        FK_SCHEMA,
        &["INSERT INTO account(id, _subject) VALUES (99, 'z')"],
        &[
            "INSERT INTO account(id, _subject) VALUES (1, 'z')",
            "INSERT INTO line(id, account_id, _subject) VALUES (1, 99, 'a')",
        ],
    ]);
    assert_eq!(subject_names(&turns[2].changesets), [Some("a"), Some("z")]);
    let sealer = Arc::new(Sealer::plain());
    let log = [
        turn(1, &turns[0].ddl, Vec::new()),
        turn(2, &[], sealable_changes(turns[2].changesets.clone())),
    ];
    let live = store_after(&sealer, &log[..1]);
    let again = from_log(&log[1..]);
    for record in [&log[1..], again.as_slice()] {
        let err = live.apply(record).unwrap_err();
        assert!(
            matches!(&err, StoreError::Corrupt(msg) if msg.contains("FOREIGN_KEY")),
            "a remaining foreign-key conflict must fail closed: {err}"
        );
        assert_eq!(store_fk(&live), (vec![], vec![]));
        assert_eq!(actor_applied(&live), 1);
        let db = live.sql.get("notes/n").unwrap();
        assert!(
            db.lock().unwrap().conn.is_autocommit(),
            "a failed apply left a transaction open"
        );
    }
}
