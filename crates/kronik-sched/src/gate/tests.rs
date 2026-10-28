use std::sync::atomic::Ordering;

use kronik_core::env::Env;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;

use super::*;
use crate::{NodeConfig, SwitchHold, start_local};

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

/// A node with counter deployed; `hold.arrived` counts the turns that start.
async fn node(dir: &std::path::Path) -> (Arc<Node>, Arc<SwitchHold>) {
    let hold = Arc::new(SwitchHold::default());
    let env = Env::real(tokio::runtime::Handle::current());
    let config = NodeConfig {
        concurrency: 8,
        test_hold_switch: Some(hold.clone()),
        ..NodeConfig::default()
    };
    let node = start_local(env, dir, config).await.unwrap();
    let bytes = std::fs::read(COUNTER).unwrap();
    node.deploy(&bytes, audit(), false).await.unwrap();
    (node, hold)
}

fn call(
    node: &Node,
    n: u32,
) -> tokio::sync::oneshot::Receiver<Result<crate::TurnResult, ApiError>> {
    let input = pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Call as i32,
            msg: Some(pb::Message {
                name: "increment".into(),
                ..Default::default()
            }),
            message_id: format!("m{n}"),
            ..Default::default()
        })),
    };
    let key = kronik_core::causal::root(format!("r{n}"));
    node.enqueue_call(ActorRef::parse("counter/c").unwrap(), input, key, 0)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// While drained, the callee turn of a call whose caller still waits runs
/// (the caller can finish); one whose caller gave up waits for the drain.
/// One thread: the orphan's caller is gone before its worker looks.
#[tokio::test(flavor = "current_thread")]
async fn a_drain_runs_waited_calls_only() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let drain = node.drain(Duration::from_secs(5)).await.unwrap();
    let before = hold.arrived.load(Ordering::SeqCst);
    // The caller gave up on this one.
    drop(call(&node, 1));
    // This caller waits: its callee turn runs during the drain.
    let waited = tokio::time::timeout(Duration::from_secs(10), call(&node, 2))
        .await
        .unwrap()
        .unwrap();
    assert!(waited.is_ok(), "{waited:?}");
    settle().await;
    assert_eq!(
        hold.arrived.load(Ordering::SeqCst),
        before + 1,
        "only the waited call ran"
    );
    assert!(drain.check_quiet().is_ok());
    drop(drain);
    settle().await;
    assert_eq!(
        hold.arrived.load(Ordering::SeqCst),
        before + 2,
        "the other runs after the drain"
    );
}

/// Two drains (a checkpoint against a rebase pause): the second waits for
/// the first within its bound, and fails with its own error when the bound
/// passes; a plain drain's error does not name the rebase's bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn competing_drains_wait_or_fail_with_their_own_error() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _hold) = node(dir.path()).await;
    let first = node.drain(Duration::from_secs(5)).await.unwrap();
    let Err(e) = node.drain(Duration::from_millis(50)).await else {
        panic!("a second drain while the first holds");
    };
    assert_eq!(e.code, ErrorCode::Unavailable, "{e}");
    assert!(!e.message.contains("max_pause"), "{e}");
    let Err(e) = node.rebase_pause(Duration::from_millis(50)).await else {
        panic!("a rebase pause while a drain holds");
    };
    assert_eq!(e.code, ErrorCode::ProposalStale, "{e}");
    assert!(e.message.contains("max_pause"), "{e}");
    // A waiting drain gets its turn when the first ends.
    let waiting = {
        let node = node.clone();
        tokio::spawn(async move { node.drain(Duration::from_secs(5)).await.map(|_| ()) })
    };
    settle().await;
    assert!(!waiting.is_finished());
    drop(first);
    waiting.await.unwrap().unwrap();
}

/// Review M9: a callee turn that runs during the drain (its caller waits)
/// makes the pause not quiet; the switch refuses then, and is quiet again
/// once the turn ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_running_in_the_drain_is_not_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let drain = node.drain(Duration::from_secs(5)).await.unwrap();
    assert!(drain.check_quiet().is_ok());
    let before = hold.arrived.load(Ordering::SeqCst);
    let input = pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Call as i32,
            msg: Some(pb::Message {
                name: "spin".into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(b"20000000".to_vec())),
                }),
                ..Default::default()
            }),
            message_id: "spin".into(),
            ..Default::default()
        })),
    };
    let reply = node.enqueue_call(
        ActorRef::parse("counter/s").unwrap(),
        input,
        kronik_core::causal::root("spin".to_string()),
        0,
    );
    // While the callee turn runs, the pause is not quiet.
    let mut seen = None;
    for _ in 0..2500 {
        if let Err(e) = drain.check_quiet() {
            seen = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
        hold.arrived.load(Ordering::SeqCst) > before,
        "the callee turn started"
    );
    let err = seen.expect("check_quiet never saw the running turn");
    assert_eq!(
        err.code,
        kronik_core::error::ErrorCode::ProposalStale,
        "{err}"
    );
    let _ = tokio::time::timeout(Duration::from_secs(30), reply).await;
    for _ in 0..500 {
        if drain.check_quiet().is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(drain.check_quiet().is_ok(), "quiet once the turn ended");
}
