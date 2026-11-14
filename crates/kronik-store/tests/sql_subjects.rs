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
use kronik_store::sql::{Limits, MemOpener, SqlActor, TurnOpts};

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

/// What the actor's turns record.
struct Recorded {
    /// The schema turn's DDL.
    ddl: Vec<String>,
    /// The changesets, by subject, of one turn on behalf of `user:1` that
    /// writes its own row and one that names `user:2`.
    changesets: Vec<(Option<String>, Vec<u8>)>,
}

fn recorded_sql() -> Recorded {
    let mut actor = SqlActor::open(&MemOpener, "notes/n", Limits::default()).unwrap();
    actor.begin_turn(&turn_opts(1, None, true)).unwrap();
    actor.query(SCHEMA, &[]).unwrap();
    let schema = actor.end_turn(true).unwrap();
    actor.apply(&schema, 1, &BTreeSet::new()).unwrap();
    actor
        .begin_turn(&turn_opts(2, Some("user:1"), false))
        .unwrap();
    actor
        .query(&format!("INSERT INTO notes(body) VALUES ('{MINE}')"), &[])
        .unwrap();
    actor
        .query(
            &format!("INSERT INTO notes(body, _subject) VALUES ('{THEIRS}', 'user:2')"),
            &[],
        )
        .unwrap();
    let dml = actor.end_turn(true).unwrap();
    Recorded {
        ddl: schema.ddl,
        changesets: dml.changesets,
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

/// The actor's rows: (body, `_subject`).
fn rows(store: &Store) -> Vec<(String, String)> {
    let db = store.sql.get("notes/n").unwrap();
    let actor = db.lock().unwrap();
    actor.set_host();
    let mut st = actor
        .conn
        .prepare("SELECT body, _subject FROM notes ORDER BY id")
        .unwrap();
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn row(body: &str, subject: &str) -> (String, String) {
    (body.to_owned(), subject.to_owned())
}

fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn erasing_one_subject_of_a_turn_keeps_the_other_subjects_rows_live_and_rebuilt() {
    let master = MasterKey::from_bytes([5; 32]).unwrap();
    let sealer = Arc::new(Sealer::new(Arc::new(
        Keystore::open_memory(&master).unwrap(),
    )));
    sealer.set_on(true);
    let Recorded { ddl, changesets } = recorded_sql();
    // The node seals each changeset of the turn record under its subject.
    let sealed: Vec<pb::SqlChangeset> = changesets
        .into_iter()
        .map(|(subject, cs)| {
            let mut value = pb::Sealable {
                subject,
                value: Some(pb::sealable::Value::Plain(cs)),
            };
            sealer
                .seal_value(&mut value, &|b: &mut [u8]| b.fill(3), 2)
                .unwrap();
            pb::SqlChangeset {
                changeset: Some(value),
            }
        })
        .collect();
    let subjects: Vec<Option<&str>> = sealed
        .iter()
        .map(|c| c.changeset.as_ref().and_then(|v| v.subject.as_deref()))
        .collect();
    assert_eq!(subjects, [Some("user:1"), Some("user:2")]);
    let mut log = vec![turn(1, &ddl, Vec::new()), turn(2, &[], sealed.clone())];

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
