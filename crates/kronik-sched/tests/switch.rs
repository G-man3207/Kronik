//! A code switch whose caller goes away mid-switch (ADR 0013).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_proto::log::v1 as pb;
use kronik_sched::{CodeSwitch, NodeConfig, SwitchHold, start_local};

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

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what} never happened");
}

/// A set switch whose caller goes away after its `Deployment` is
/// committed still installs its code: the switch runs on a task of its own
/// that holds the deploy lock and the switch gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_code_switch_still_installs_its_code() {
    let dir = tempfile::tempdir().unwrap();
    let hold = Arc::new(SwitchHold::default());
    let env = Env::real(tokio::runtime::Handle::current());
    let config = NodeConfig {
        concurrency: 8,
        test_hold_switch: Some(hold.clone()),
        ..NodeConfig::default()
    };
    let node = start_local(env, dir.path(), config).await.unwrap();
    node.deploy(&guest("counter"), audit(), false)
        .await
        .unwrap();
    let bytes = guest("counter-step2");
    let (hash, _, manifest) = node.prepare_code(&bytes).await.unwrap();
    let v = pb::KindVersion {
        kind: manifest.kind.clone(),
        code_hash: hash.0.to_vec(),
        schema_version: manifest.schema_version,
        manifest: Some(manifest),
        code_size: bytes.len() as u64,
    };
    let switch = CodeSwitch {
        kinds: vec![v.clone()],
        pinned: vec![],
        cause: pb::DeploymentCause::Promote,
        verified_through_lsn: 0,
        unverified_inputs: 0,
        proposal_id: "p-test".into(),
        rollback_of_epoch: 0,
    };
    let task = {
        let node = node.clone();
        tokio::spawn(async move { node.switch_code(switch, audit(), false).await })
    };
    wait_until("the switch parks", || {
        hold.parked.load(Ordering::SeqCst) == 1
    })
    .await;
    task.abort();
    let _ = task.await;
    hold.release.add_permits(1);
    wait_until("the code is installed", || {
        node.deployed("counter").unwrap().code_hash == v.code_hash
    })
    .await;
    assert_eq!(node.epoch(), 2);
    // The deploy lock is free again.
    node.deploy(&guest("notes"), audit(), false).await.unwrap();
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
