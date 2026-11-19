//! #228: a fire already taken must not run, or delete, a later schedule of
//! the same timer id. Cancel still suppresses the taken fire.

use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use super::Node;
use crate::{NodeConfig, start_local};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

fn plain(bytes: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
    })
}

fn turn(exec: &str, key: &str, logical: u64, timers: Vec<pb::TimerOp>) -> Record {
    Record::TurnRecord(pb::TurnRecord {
        execution_id: exec.into(),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: key.into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: exec.into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Operator as i32,
                msg: Some(pb::Message {
                    name: "op".into(),
                    body: plain(b""),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }),
        timers,
        logical_time_ms: logical,
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn schedule(id: u64, due: u64, name: &str, body: &str) -> pb::TimerOp {
    pb::TimerOp {
        kind: pb::TimerOpKind::Schedule as i32,
        timer_id: id,
        due_ms: due,
        msg: Some(pb::Message {
            name: name.into(),
            body: plain(body.as_bytes()),
            ..Default::default()
        }),
        ordinal: 0,
    }
}

fn arm(node: &Node, actor: &ActorRef, id: u64, due: u64) {
    let now = node.timer_now();
    super::lock(&node.wheel).add(actor.clone(), id, due, now);
    node.wheel_notify.notify_one();
}

async fn until_queued(node: &Node, actor: &ActorRef) {
    let start = node.env().clock.monotonic();
    loop {
        if node.queued_jobs(actor) >= 1 {
            return;
        }
        let waited = node.env().clock.monotonic().saturating_sub(start);
        assert!(
            waited < Duration::from_secs(5),
            "timer {actor} was not queued; rows {:?}",
            node.store().db().timers(Some((&actor.kind, &actor.key)))
        );
        node.env().clock.sleep(Duration::from_millis(10)).await;
    }
}

async fn until(node: &Node, what: &str, ready: impl Fn() -> bool) {
    let start = node.env().clock.monotonic();
    while !ready() {
        let waited = node.env().clock.monotonic().saturating_sub(start);
        assert!(
            waited < Duration::from_secs(5),
            "{what}: stored={:?} n_a={:?} n_b={:?} timers={:?}",
            kv(node, "a", "stored"),
            kv(node, "a", "n"),
            kv(node, "b", "n"),
            node.store().db().timers(None)
        );
        node.env().clock.sleep(Duration::from_millis(10)).await;
    }
}

fn kv(node: &Node, key: &str, k: &str) -> Option<Vec<u8>> {
    node.store().db().kv_get("counter", key, k).unwrap()
}

async fn taken(node: &Node, actor: &ActorRef, exec: &str, due: u64, name: &str, body: &str) {
    node.commit(turn(
        exec,
        &actor.key,
        due,
        vec![schedule(7, due, name, body)],
    ))
    .await
    .unwrap();
    arm(node, actor, 7, due);
    until_queued(node, actor).await;
}

async fn timer_fires(node: &Node) -> Vec<(String, String, u64)> {
    let mut fired = Vec::new();
    node.reader()
        .read(1, node.applied_lsn(), |c| {
            if let Record::TurnRecord(t) = &c.record
                && let Some(pb::input::Kind::Timer(tm)) =
                    t.input.as_ref().and_then(|i| i.kind.as_ref())
            {
                fired.push((
                    t.actor.as_ref().map(|a| a.key.clone()).unwrap_or_default(),
                    tm.msg.as_ref().map(|m| m.name.clone()).unwrap_or_default(),
                    tm.due_ms,
                ));
            }
            Ok(())
        })
        .await
        .unwrap();
    fired
}

/// Rescheduling timer 7 after it has been taken, but before its turn runs,
/// leaves the new row and fires it at the new time with the new message.
/// The stale turn does not run. Cancelling still suppresses a taken fire.
#[tokio::test(flavor = "current_thread")]
async fn a_queued_fire_does_not_delete_a_later_schedule() {
    let dir = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    node.deploy(
        &std::fs::read(COUNTER).unwrap(),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    let drain = node.drain(Duration::from_secs(5)).await.unwrap();
    let a = ActorRef::parse("counter/a").unwrap();
    let b = ActorRef::parse("counter/b").unwrap();

    let stale = node.timer_now().logical_ms;
    taken(&node, &a, "a-old", stale, "increment", "").await;
    let later = node.timer_now().logical_ms.saturating_add(400);
    node.commit(turn(
        "a-new",
        "a",
        node.timer_now().logical_ms,
        vec![schedule(7, later, "store", "fresh")],
    ))
    .await
    .unwrap();
    arm(&node, &a, 7, later);
    let replaced = node.store().db().timers(Some(("counter", "a"))).unwrap();
    assert_eq!(replaced.len(), 1);
    assert_eq!(
        (replaced[0].due_ms, replaced[0].msg.name.as_str()),
        (later, "store")
    );

    let b_due = node.timer_now().logical_ms;
    taken(&node, &b, "b-old", b_due, "increment", "").await;
    node.commit(turn(
        "b-cancel",
        "b",
        b_due,
        vec![pb::TimerOp {
            kind: pb::TimerOpKind::Cancel as i32,
            timer_id: 7,
            ..Default::default()
        }],
    ))
    .await
    .unwrap();
    super::lock(&node.wheel).remove(&b, 7);

    drop(drain);
    until(&node, "the replacement", || {
        kv(&node, "a", "stored").as_deref() == Some(b"fresh".as_slice()) && node.actors_idle()
    })
    .await;
    assert!(kv(&node, "a", "n").is_none(), "the stale increment ran");
    assert!(kv(&node, "b", "n").is_none(), "the cancelled fire ran");
    assert!(node.store().db().timers(None).unwrap().is_empty());
    assert_eq!(
        timer_fires(&node).await,
        vec![("a".into(), "store".into(), later)]
    );
}
