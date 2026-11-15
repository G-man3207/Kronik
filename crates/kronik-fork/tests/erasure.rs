//! A fork's copy of plaintext predating its subject's erasure is the
//! erasure's tombstone (ADR 0123 §6, docs/design/m8-privacy.md §6.8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use common::*;
use kronik_core::ids::ActorRef;
use kronik_fork::diff::DiffOptions;
use kronik_fork::proposal::{Proposals, ProposeRequest};
use kronik_privacy::sealer::Opened;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;

fn subject_msg(name: &str, body: &str, subject: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: Some(pb::Sealable {
            subject: Some(subject.into()),
            value: Some(pb::sealable::Value::Plain(body.as_bytes().to_vec())),
        }),
        blobs: Vec::new(),
        retained_compensation_source: None,
    }
}

fn send_subject(p: &Proc, name: &str, body: &str, subject: &str) -> kronik_sched::TurnResult {
    p.rt.block_on(p.node.send(
        ActorRef::parse("counter/a").unwrap(),
        subject_msg(name, body, subject),
        audit(),
        false,
        p.owner(),
    ))
    .unwrap()
    .unwrap()
}

/// Mode `off`: a turn writes plaintext of `user:1`. Erase it. Mode `on`: a
/// new turn of the subject creates key version 1. A fork over the first turn
/// then seals its log from the subject's erasure, not under version 1.
#[test]
fn a_fork_log_tombstones_plaintext_from_before_a_come_back_subjects_erasure() {
    let dir = tempdir();
    let p = Proc::start(dir.path());
    let fork_lsn = p.node.applied_lsn();

    let before = send_subject(&p, "note", "NEEDLE-BEFORE", "user:1");
    assert!(before.committed(), "{before:?}");
    let erased =
        p.rt.block_on(p.node.erase_subject("user:1", audit(), false, p.owner()))
            .unwrap();
    assert_eq!(erased.key_version, 0, "the subject had no key");
    let erasure_lsn = erased.lsn.unwrap();
    assert!(
        before.turn_id.lsn < erasure_lsn,
        "the copied turn predates the erasure"
    );
    p.rt.block_on(
        p.node
            .set_privacy_mode(pb::PrivacyState::On, audit(), false, p.owner()),
    )
    .unwrap();
    let after = send_subject(&p, "note", "NEW-AFTER", "user:1");
    assert!(after.committed(), "{after:?}");
    p.settle();
    assert_eq!(
        p.node
            .sealer()
            .keystore()
            .unwrap()
            .newest_version("user:1")
            .unwrap(),
        Some(1),
        "the subject came back with key version 1"
    );

    let props =
        std::sync::Arc::new(Proposals::open(p.node.clone(), dir.path().to_path_buf()).unwrap());
    let (prop, dry) =
        p.rt.block_on(props.propose(
            ProposeRequest {
                wasm: vec![std::fs::read(guest("counter-step2")).unwrap()],
                names: Vec::new(),
                window_ms: None,
                at: Some(fork_lsn),
                options: DiffOptions::default(),
                workers: Some(2),
                audit: audit(),
                dry_run: false,
            },
            p.owner(),
        ))
        .unwrap();
    assert!(!dry);
    assert_eq!(prop.fork_lsn, fork_lsn);

    // The fork's log holds both turns (the migrate and the first note may
    // precede them); take the subject-tagged turns in log order.
    let mut turns = Vec::new();
    for lsn in prop.fork_lsn + 1..=prop.created_lsn {
        if let Some(t) = p.rt.block_on(props.fork_turn(&prop.id, lsn)).unwrap() {
            let tagged = t.writes.iter().any(|w| {
                w.value
                    .as_ref()
                    .and_then(|v| v.subject.as_deref())
                    .is_some_and(|s| s == "user:1")
            });
            if tagged {
                turns.push((lsn, t));
            }
        }
    }
    assert_eq!(turns.len(), 2, "one turn before the erasure, one after");

    // The pre-erasure copy is the erasure's tombstone, not a value sealed
    // under key version 1 that the fork's sealer opens again.
    let (pre_lsn, pre) = &turns[0];
    assert!(*pre_lsn > fork_lsn);
    assert!(
        !pre.encode_to_vec()
            .windows(b"NEEDLE-BEFORE".len())
            .any(|w| w == b"NEEDLE-BEFORE"),
        "the pre-erasure turn at {pre_lsn} kept its plaintext"
    );
    for write in &pre.writes {
        assert!(matches!(
            p.node.sealer().open(write.value.as_ref().unwrap()),
            Opened::Erased { ref subject } if subject == "user:1"
        ));
    }

    // The turn after the erasure was new data and still opens under the
    // new key.
    let (after_lsn, after) = &turns[1];
    assert!(*after_lsn > *pre_lsn);
    let opened: Vec<_> = after
        .writes
        .iter()
        .filter_map(|w| w.value.as_ref())
        .map(|v| p.node.sealer().open(v).into_owned())
        .collect();
    assert!(
        opened.iter().any(|v| v.as_deref() == Some(b"NEW-AFTER")),
        "the post-erasure value did not open: {opened:?}"
    );

    // Main's own record at the pre-erasure LSN is still the off-mode plain
    // value; only a reseal rewrites history, and the fork never needed one.
    let mut main = None;
    p.rt.block_on(
        p.node
            .reader()
            .read(before.turn_id.lsn, before.turn_id.lsn, |c| {
                if let Record::TurnRecord(t) = c.record {
                    main = Some(t);
                }
                Ok(())
            }),
    )
    .unwrap();
    let main = main.unwrap();
    assert!(main.writes.iter().any(|w| {
        w.value
            .as_ref()
            .and_then(|v| v.subject.as_deref())
            .is_some_and(|s| s == "user:1")
            && matches!(
                w.value.as_ref().and_then(|v| v.value.as_ref()),
                Some(pb::sealable::Value::Plain(_))
            )
    }));
}
