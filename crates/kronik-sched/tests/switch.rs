//! Code switches and the rebase switch (ADR 0013, 0018) against the cases
//! the happy path does not show: a caller that goes away mid-switch, a
//! deployment that lands before the rebase switch, a pause past its bound,
//! a resend held by the pause.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, Lsn};
use kronik_proto::log::v1 as pb;
use kronik_sched::{CodeSwitch, Node, NodeConfig, SwitchHold, start_local};

fn guest(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../tests/guests/{name}.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

/// A node whose code switches park on `hold` (deploys do not), with
/// counter deployed (epoch 1).
async fn node(dir: &std::path::Path) -> (Arc<Node>, Arc<SwitchHold>) {
    let hold = Arc::new(SwitchHold::default());
    let env = Env::real(tokio::runtime::Handle::current());
    let config = NodeConfig {
        concurrency: 8,
        test_hold_switch: Some(hold.clone()),
        ..NodeConfig::default()
    };
    let node = start_local(env, dir, config).await.unwrap();
    node.deploy(&guest("counter"), audit(), false)
        .await
        .unwrap();
    (node, hold)
}

async fn version(node: &Node, name: &str) -> pb::KindVersion {
    let bytes = guest(name);
    let (hash, _, manifest) = node.prepare_code(&bytes).await.unwrap();
    pb::KindVersion {
        kind: manifest.kind.clone(),
        code_hash: hash.0.to_vec(),
        schema_version: manifest.schema_version,
        manifest: Some(manifest),
        code_size: bytes.len() as u64,
    }
}

fn promote(v: pb::KindVersion) -> CodeSwitch {
    CodeSwitch {
        kinds: vec![v],
        pinned: vec![],
        cause: pb::DeploymentCause::Promote,
        verified_through_lsn: 0,
        unverified_inputs: 0,
        proposal_id: "p-test".into(),
        rollback_of_epoch: 0,
    }
}

/// Promotes `name` with its hold released at once; the new epoch.
async fn promote_now(node: &Node, hold: &SwitchHold, name: &str) -> u64 {
    let v = version(node, name).await;
    hold.release.add_permits(1);
    node.switch_code(promote(v), audit(), false)
        .await
        .unwrap()
        .0
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what} never happened");
}

fn deployed_hash(node: &Node) -> Vec<u8> {
    node.deployed("counter").unwrap().code_hash
}

/// The rebase of the newest deployment, `epoch`: (switch, kinds, not_after).
async fn prepare_rebase(
    node: &Node,
    id: &str,
    epoch: u64,
) -> (pb::RebaseSwitch, Vec<pb::KindVersion>, Lsn) {
    let deployments = node.store().db().deployments().unwrap();
    let (dlsn, _) = deployments.iter().find(|(_, d)| d.epoch == epoch).unwrap();
    let before = deployments
        .iter()
        .rfind(|(_, d)| d.epoch < epoch)
        .map(|(_, d)| d.kinds.clone())
        .unwrap();
    let base = dlsn - 1;
    node.rebase_prepare(id, base).await.unwrap();
    let sw = pb::RebaseSwitch {
        base_lsn: base,
        rolled_back_epoch: epoch,
        verified_through_lsn: node.applied_lsn(),
        ..Default::default()
    };
    (sw, before, node.applied_lsn())
}

/// A set switch whose caller goes away after its record is committed
/// still installs its code: the switch runs on a task of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_set_switch_still_installs_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let v = version(&node, "counter-step2").await;
    let switch = {
        let node = node.clone();
        let v = v.clone();
        tokio::spawn(async move { node.switch_code(promote(v), audit(), false).await })
    };
    wait_until("the switch parks", || {
        hold.parked.load(Ordering::SeqCst) == 1
    })
    .await;
    switch.abort();
    let _ = switch.await;
    hold.release.add_permits(1);
    wait_until("the code is installed", || {
        deployed_hash(&node) == v.code_hash
    })
    .await;
    assert_eq!(node.epoch(), 2);
    // The deploy lock is free again.
    promote_now(&node, &hold, "counter").await;
}

/// The same for the rebase switch: the code, the reload and the end of the
/// pause all happen though the caller went away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_rebase_switch_still_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let old = deployed_hash(&node);
    let epoch = promote_now(&node, &hold, "counter-step2").await;
    let (sw, kinds, not_after) = prepare_rebase(&node, "r-cancel", epoch).await;
    let pause = node.rebase_pause(Duration::from_secs(5)).await.unwrap();
    let switch = {
        let node = node.clone();
        tokio::spawn(async move {
            node.rebase_switch(pause, "r-cancel", sw, kinds, not_after, audit())
                .await
        })
    };
    wait_until("the switch parks", || {
        hold.parked.load(Ordering::SeqCst) == 2
    })
    .await;
    switch.abort();
    let _ = switch.await;
    hold.release.add_permits(1);
    wait_until("the old code is installed", || deployed_hash(&node) == old).await;
    assert_eq!(node.epoch(), epoch + 1);
    assert_eq!(
        node.rebase_staged_to("r-cancel"),
        None,
        "the shadow is gone"
    );
    assert!(node.last_rebase().unwrap().is_some());
    // The pause ended.
    drop(node.drain(Duration::from_secs(5)).await.unwrap());
}

/// A deployment after the rolled-back one, before the switch: the switch
/// refuses instead of silently reverting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebase_switch_refuses_after_a_later_deployment() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let epoch = promote_now(&node, &hold, "counter-step2").await;
    let (sw, kinds, not_after) = prepare_rebase(&node, "r-late", epoch).await;
    promote_now(&node, &hold, "counter-body-v2").await;
    let pause = node.rebase_pause(Duration::from_secs(5)).await.unwrap();
    // Without the re-check the switch would commit and park on the hold:
    // a permit lets it finish, so the test fails instead of hanging.
    hold.release.add_permits(1);
    let err = node
        .rebase_switch(pause, "r-late", sw, kinds, not_after, audit())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert_eq!(node.last_rebase().unwrap(), None, "nothing was switched");
}

/// Nothing is staged once the pause's bound has passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_staged_after_the_pause_bound() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let epoch = promote_now(&node, &hold, "counter-step2").await;
    let (_, _, not_after) = prepare_rebase(&node, "r-late", epoch).await;
    let pause = node.rebase_pause(Duration::from_millis(20)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(pause.remaining().is_zero());
    let turn = pb::TurnRecord {
        execution_id: "x".into(),
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: "z".into(),
        }),
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    };
    let head = node.applied_lsn();
    let err = node
        .rebase_stage("r-late", vec![(head, turn)], not_after, Some(&pause))
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ProposalStale, "{err}");
    assert_eq!(node.applied_lsn(), head, "nothing was written");
}

/// A resend held by the pause whose dead letter the rebased state no
/// longer has is dropped at the switch, not run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_resend_of_a_dead_letter_gone_by_the_switch_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let epoch = promote_now(&node, &hold, "counter-step2").await;
    // A dead letter after the fork point: the rebase (no turns) drops it.
    let failed = node
        .send(
            ActorRef::parse("counter/a").unwrap(),
            pb::Message {
                name: "fail".into(),
                content_type: "text/plain".into(),
                ..Default::default()
            },
            audit(),
            false,
        )
        .await
        .unwrap()
        .unwrap();
    let dead = failed.turn_id.lsn;
    assert!(node.store().db().dead_letter(dead).unwrap().is_some());
    let (sw, kinds, not_after) = prepare_rebase(&node, "r-dead", epoch).await;
    let pause = node.rebase_pause(Duration::from_secs(5)).await.unwrap();
    let resend = {
        let node = node.clone();
        tokio::spawn(async move { node.resend(dead, audit(), false).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!resend.is_finished(), "held by the pause");
    hold.release.add_permits(1);
    node.rebase_switch(pause, "r-dead", sw, kinds, not_after, audit())
        .await
        .unwrap();
    let r: Result<_, ApiError> = resend.await.unwrap();
    assert_eq!(r.unwrap_err().code, ErrorCode::DeadLetterNotFound);
}

/// Re-review #3 (v0.1): a configuration change whose caller goes away while
/// its record is being committed is still applied in memory (configuration,
/// epoch, privacy mode), on a task that holds the deploy lock; the next
/// change gets the next epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_configuration_change_is_still_applied() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let config = NodeConfig {
        concurrency: 8,
        group_commit_window: Some(Duration::from_millis(300)),
        ..NodeConfig::default()
    };
    let node = start_local(env, dir.path(), config).await.unwrap();
    node.deploy(&guest("counter"), audit(), false)
        .await
        .unwrap();
    let before = node.applied_lsn();
    let task = {
        let node = node.clone();
        tokio::spawn(async move {
            node.grant("counter", "http:example.com", None, None, audit(), false)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    let _ = task.await;
    wait_until("the grant is applied", || node.applied_lsn() > before).await;
    wait_until("the grant is in memory", || {
        node.config_now()
            .grant("counter", "http:example.com")
            .is_some()
    })
    .await;
    assert_eq!(node.epoch(), 2);

    let before = node.applied_lsn();
    let task = {
        let node = node.clone();
        tokio::spawn(async move {
            node.set_privacy_mode(pb::PrivacyState::On, audit(), false)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    let _ = task.await;
    wait_until("the mode is applied", || node.applied_lsn() > before).await;
    wait_until("the mode is in memory", || {
        node.privacy_mode().0 == pb::PrivacyState::On
    })
    .await;
    assert_eq!(node.epoch(), 3);
    // The deploy lock is free, and the next change gets epoch 4.
    let (epoch, _) = node
        .grant("counter", "http:example.org", None, None, audit(), false)
        .await
        .unwrap();
    assert_eq!(epoch, 4);
}

/// One "process": its own runtime; dropping it cancels every task like a
/// crash.
fn process(dir: &std::path::Path) -> (tokio::runtime::Runtime, Arc<Node>, Arc<SwitchHold>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let hold = Arc::new(SwitchHold::default());
    let node = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let config = NodeConfig {
            concurrency: 8,
            test_hold_switch: Some(hold.clone()),
            ..NodeConfig::default()
        };
        start_local(env, dir, config).await.unwrap()
    });
    (rt, node, hold)
}

async fn send(node: &Node, key: &str) {
    let r = node
        .send(
            ActorRef::parse(&format!("counter/{key}")).unwrap(),
            pb::Message {
                name: "increment".into(),
                content_type: "text/plain".into(),
                ..Default::default()
            },
            audit(),
            false,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(r.committed(), "{r:?}");
}

/// `state.db` and the actor databases of the branch (not the log).
fn state_files(branch: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(branch)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            name.starts_with("state.db") || name == "sql"
        })
        .collect()
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    if from.is_dir() {
        std::fs::create_dir_all(to).unwrap();
        for e in std::fs::read_dir(from).unwrap().flatten() {
            copy_tree(&e.path(), &to.join(e.file_name()));
        }
    } else {
        std::fs::copy(from, to).unwrap();
    }
}

/// A crash after the switch record is durable and before `state.db` has
/// it (m13-rebase §6): the restart applies the switch from the log, with a
/// shadow rebuilt from the log, to the same state.
#[test]
fn a_crash_between_the_switch_record_and_state_db_repeats_the_switch() {
    let dir = tempfile::tempdir().unwrap();
    let branch = dir.path().join("branches/main");
    let saved = tempfile::tempdir().unwrap();
    let epoch = {
        let (rt, node, hold) = process(dir.path());
        rt.block_on(async {
            node.deploy(&guest("counter"), audit(), false)
                .await
                .unwrap();
            let epoch = promote_now(&node, &hold, "counter-step2").await;
            send(&node, "a").await;
            send(&node, "b").await;
            epoch
        })
    };
    // The state before the switch, as a crash would leave it.
    for p in state_files(&branch) {
        copy_tree(&p, &saved.path().join(p.file_name().unwrap()));
    }
    let (switched, hash) = {
        let (rt, node, hold) = process(dir.path());
        let r = rt.block_on(async {
            let (sw, kinds, not_after) = prepare_rebase(&node, "r-crash", epoch).await;
            let pause = node.rebase_pause(Duration::from_secs(5)).await.unwrap();
            hold.release.add_permits(1);
            node.rebase_switch(pause, "r-crash", sw, kinds, not_after, audit())
                .await
                .unwrap()
        });
        assert_eq!(node.store().db().kv_get("counter", "a", "n").unwrap(), None);
        (r, node.store().state_hash().unwrap())
    };
    // The switch record is in the log; state.db and the actor databases
    // lose it.
    for p in state_files(&branch) {
        if p.is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
    copy_tree(saved.path(), &branch);
    let (_rt, node, _hold) = process(dir.path());
    assert_eq!(
        node.last_rebase().unwrap().map(|(l, _)| l),
        Some(switched.1)
    );
    assert_eq!(node.epoch(), switched.0);
    assert_eq!(node.store().state_hash().unwrap(), hash);
}
