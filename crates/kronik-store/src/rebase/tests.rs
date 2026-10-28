use super::*;
use kronik_log::Position;

fn at(lsn: Lsn, record: Record) -> Committed {
    Committed {
        lsn,
        pos: Position {
            segment: 0,
            offset: lsn * 100,
        },
        record,
    }
}

fn set(kind: &str, key: &str, root: &str, k: &str, v: &str) -> pb::TurnRecord {
    pb::TurnRecord {
        execution_id: format!("{root}-{v}"),
        actor: Some(pb::ActorRef {
            kind: kind.into(),
            key: key.into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: root.into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput::default())),
        }),
        writes: vec![pb::StateWrite {
            op: pb::StateOp::Set as i32,
            key: k.into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(v.as_bytes().to_vec())),
            }),
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn deployment(epoch: u64) -> pb::Deployment {
    pb::Deployment {
        epoch,
        kinds: vec![pb::KindVersion {
            kind: "counter".into(),
            code_hash: vec![epoch as u8; 32],
            manifest: Some(pb::Manifest {
                kind: "counter".into(),
                ..Default::default()
            }),
            ..Default::default()
        }],
        cause: pb::DeploymentCause::Deploy as i32,
        ..Default::default()
    }
}

fn rebased(fork_lsn: Lsn, record: pb::TurnRecord) -> Record {
    Record::StateRebase(pb::StateRebase {
        rebase_id: "r-1".into(),
        part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
            fork_lsn,
            record: Some(record),
        })),
    })
}

/// Main's log: old code up to 2, the new code's turns, the rebase's turns
/// staged among them, the switch at 8.
fn log() -> Vec<Committed> {
    let mut d = deployment(2);
    d.cause = pb::DeploymentCause::Rollback as i32;
    d.rollback_of_epoch = 1;
    vec![
        at(1, Record::Deployment(deployment(1))),
        at(2, Record::TurnRecord(set("counter", "a", "r1", "n", "1"))),
        at(3, Record::Deployment(deployment(3))),
        // The new code: a migrated key and a new actor.
        at(
            4,
            Record::TurnRecord(set("counter", "a", "r2", "schema", "1")),
        ),
        at(5, Record::TurnRecord(set("counter", "b", "r3", "n", "7"))),
        // The old code's replay of r2 and r3, staged.
        at(6, rebased(4, set("counter", "a", "r2", "n", "2"))),
        at(7, rebased(5, set("counter", "c", "r3", "n", "1"))),
        at(
            8,
            Record::StateRebase(pb::StateRebase {
                rebase_id: "r-1".into(),
                part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                    base_lsn: 2,
                    rolled_back_epoch: 3,
                    verified_through_lsn: 5,
                    first_turn_lsn: 6,
                    last_turn_lsn: 7,
                    turns: 2,
                    deployment: Some(d),
                    ..Default::default()
                })),
            }),
        ),
        at(9, Record::TurnRecord(set("counter", "a", "r4", "n", "3"))),
    ]
}

fn kv(store: &Store, key: &str, k: &str) -> Option<String> {
    store
        .db()
        .kv_get("counter", key, k)
        .unwrap()
        .map(|v| String::from_utf8(v).unwrap())
}

fn rebuild(records: &[Committed]) -> Arc<Store> {
    let store = Store::memory().unwrap();
    store
        .apply_with(records, &mut |c| {
            let (id, sw) = c.record.rebase_switch().unwrap();
            shadow_for(id, sw, c.lsn, None, records, Arc::new(Sealer::plain()))
        })
        .unwrap();
    store
}

#[test]
fn a_switch_installs_the_rebased_state_and_rebuilds_the_same() {
    let records = log();
    // Live: main applies its records; the staged turns change nothing.
    let main = Store::memory().unwrap();
    main.apply(&records[..7]).unwrap();
    assert_eq!(kv(&main, "a", "schema").as_deref(), Some("1"));
    assert_eq!(kv(&main, "a", "n").as_deref(), Some("1"));
    assert!(
        main.apply(&records[7..8]).is_err(),
        "a switch needs its shadow"
    );
    let mut shadow = Shadow::at_base("r-1", 2, None, &records, Arc::new(Sealer::plain())).unwrap();
    shadow.feed(&records[2..7]).unwrap();
    let (_, sw) = records[7].record.rebase_switch().unwrap();
    shadow.check(sw).unwrap();
    let s = shadow.store.clone();
    main.apply_with(&records[7..], &mut |_| Ok(s.clone()))
        .unwrap();

    // The old code's state: no migrated key, the replayed n, no actor b,
    // the replay's actor c; main continues on it.
    assert_eq!(kv(&main, "a", "schema"), None);
    assert_eq!(kv(&main, "a", "n").as_deref(), Some("3"));
    assert_eq!(kv(&main, "b", "n"), None);
    assert!(main.db().actor("counter", "b").unwrap().is_none());
    assert_eq!(kv(&main, "c", "n").as_deref(), Some("1"));
    assert_eq!(main.db().config_epoch().unwrap(), 2);
    assert_eq!(main.db().last_rebase().unwrap(), Some((8, 2)));
    // The rebased turns resolve as turns; main's history is kept.
    assert!(main.db().turn(6).unwrap().is_some());
    assert!(main.db().turn(4).unwrap().is_some());

    // A rebuild from the log alone gives the same state.
    let rebuilt = rebuild(&records);
    assert_eq!(rebuilt.state_hash().unwrap(), main.state_hash().unwrap());
    // A switch that names other turns is refused.
    let mut bad = records.clone();
    bad.remove(6);
    let store = Store::memory().unwrap();
    let err = store
        .apply_with(&bad, &mut |c| {
            let (id, sw) = c.record.rebase_switch().unwrap();
            shadow_for(id, sw, c.lsn, None, &bad, Arc::new(Sealer::plain()))
        })
        .unwrap_err();
    assert!(err.to_string().contains("names turns"), "{err}");
}

fn ddl(key: &str, root: &str, statement: &str) -> pb::TurnRecord {
    let mut t = set("notes", key, root, "k", root);
    t.writes.clear();
    t.sql_schema = vec![pb::SqlSchemaChange {
        statement: statement.into(),
    }];
    t
}

/// An actor database: old code up to 2, the new code's tables at 4 and 6
/// around the rebase's staged turn at 5, the switch at 7.
fn sql_log() -> Vec<Committed> {
    let mut d = deployment(2);
    d.cause = pb::DeploymentCause::Rollback as i32;
    d.rollback_of_epoch = 1;
    vec![
        at(1, Record::Deployment(deployment(1))),
        at(2, Record::TurnRecord(ddl("n", "r1", "CREATE TABLE t1 (x)"))),
        at(3, Record::Deployment(deployment(3))),
        at(4, Record::TurnRecord(ddl("n", "r2", "CREATE TABLE t2 (x)"))),
        at(5, rebased(4, ddl("n", "r2", "CREATE TABLE t3 (x)"))),
        at(
            6,
            Record::TurnRecord(ddl("n", "r3", "ALTER TABLE t2 ADD COLUMN y")),
        ),
        at(
            7,
            Record::StateRebase(pb::StateRebase {
                rebase_id: "r-1".into(),
                part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                    base_lsn: 2,
                    rolled_back_epoch: 3,
                    verified_through_lsn: 6,
                    first_turn_lsn: 5,
                    last_turn_lsn: 5,
                    turns: 1,
                    deployment: Some(d),
                    ..Default::default()
                })),
            }),
        ),
    ]
}

fn tables(store: &Store) -> Vec<String> {
    let db = store.sql.get("notes/n").unwrap();
    let db = db.lock().unwrap();
    db.table_rows()
        .unwrap()
        .into_iter()
        .map(|(t, _)| t)
        .collect()
}

fn apply_log(store: &Store, records: &[Committed]) -> Result<(), StoreError> {
    let from = store.replay_from()?;
    let todo: Vec<Committed> = records.iter().filter(|c| c.lsn > from).cloned().collect();
    store.apply_with(&todo, &mut |c| {
        let (id, sw) = c.record.rebase_switch().unwrap();
        shadow_for(id, sw, c.lsn, None, records, Arc::new(Sealer::plain()))
    })
}

/// A crash right after an actor database's copy, before `state.db` has the
/// switch: the copy already carries the switch's LSN, so the restart does
/// not replay main's new-code changes onto the old code's database.
#[test]
fn a_crash_after_an_actor_copy_repeats_the_switch() {
    let records = sql_log();
    let main = Store::memory().unwrap();
    crate::CRASH_AFTER_COPY.with(|c| c.set(true));
    let crashed = apply_log(&main, &records);
    crate::CRASH_AFTER_COPY.with(|c| c.set(false));
    assert!(crashed.is_err());
    assert_eq!(main.applied.get(), 6, "state.db stops before the switch");
    apply_log(&main, &records).unwrap();
    assert_eq!(tables(&main), ["t1", "t3"]);
    assert_eq!(
        main.state_hash().unwrap(),
        rebuild(&records).state_hash().unwrap()
    );
}

/// A power loss that keeps `state.db`'s switch but loses an actor
/// database's copy: the restart redoes the copy.
#[test]
fn a_lost_actor_copy_is_redone() {
    let records = sql_log();
    let main = Store::memory().unwrap();
    apply_log(&main, &records).unwrap();
    assert_eq!(tables(&main), ["t1", "t3"]);
    // The actor database as it was before the switch.
    let before = Store::memory().unwrap();
    before.apply(&records[..6]).unwrap();
    {
        let src = before.sql.get("notes/n").unwrap();
        let dst = main.sql.get("notes/n").unwrap();
        dst.lock().unwrap().copy_from(&src.lock().unwrap()).unwrap();
    }
    assert_eq!(tables(&main), ["t1", "t2"]);
    apply_log(&main, &records).unwrap();
    assert_eq!(tables(&main), ["t1", "t3"]);
}

/// An erasure after the base comes before the staged turns that replay
/// inputs from before it: the subject's values do not come back.
#[test]
fn an_erasure_in_the_window_holds_after_the_switch() {
    let mut records = log();
    let mut tagged = set("counter", "c", "r3", "secret", "x");
    tagged.writes[0].value.as_mut().unwrap().subject = Some("alice".into());
    // The erasure at 5, the staged turn that recreates alice's value at 7.
    records[3] = at(
        5,
        Record::Erasure(pb::Erasure {
            epoch: 4,
            subject: "alice".into(),
            ..Default::default()
        }),
    );
    records[4] = at(4, Record::TurnRecord(set("counter", "b", "r3", "n", "7")));
    records.swap(3, 4);
    records[6] = at(7, rebased(5, tagged));
    let main = rebuild(&records);
    assert_eq!(kv(&main, "c", "secret"), None);
}

/// Review M6: the erasure applied again after the switch removes all an
/// `Erasure` removes, not only kv and SQL: a staged turn that dead-letters a
/// message of the erased subject leaves no dead letter in main.
#[test]
fn an_erasure_in_the_window_removes_the_subjects_dead_letters_after_the_switch() {
    let mut records = log();
    let mut failed = set("counter", "c", "r3", "n", "1");
    failed.writes.clear();
    failed.input = Some(pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Actor as i32,
            sender: Some(pb::ActorRef {
                kind: "counter".into(),
                key: "b".into(),
            }),
            msg: Some(pb::Message {
                name: "note".into(),
                body: Some(pb::Sealable {
                    subject: Some("alice".into()),
                    value: Some(pb::sealable::Value::Plain(b"alice's data".to_vec())),
                }),
                ..Default::default()
            }),
            message_id: "m-alice".into(),
            ..Default::default()
        })),
    });
    failed.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        message: "failed".into(),
        output: None,
    });
    records[3] = at(
        5,
        Record::Erasure(pb::Erasure {
            epoch: 4,
            subject: "alice".into(),
            ..Default::default()
        }),
    );
    records[4] = at(4, Record::TurnRecord(set("counter", "b", "r3", "n", "7")));
    records.swap(3, 4);
    records[6] = at(7, rebased(5, failed));
    let main = rebuild(&records);
    let letters = main.db().dead_letters(0, 100).unwrap();
    assert!(letters.is_empty(), "{letters:?}");
}
