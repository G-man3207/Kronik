#[path = "../../tests/common/mod.rs"]
mod common;
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
    node.deploy(&bytes, audit(), false, common::lease())
        .await
        .unwrap();
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
    node.enqueue_call(
        ActorRef::parse("counter/c").unwrap(),
        input,
        key,
        0,
        node.born_now(),
    )
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
    let Err(e) = node
        .rebase_pause(Duration::from_millis(50), common::lease())
        .await
    else {
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
        node.born_now(),
    );
    // While the callee turn runs, the pause is not quiet. The turn running is
    // what ends the wait; the attempts only bound a turn that never starts,
    // and are far more than a loaded machine needs to schedule it.
    let mut seen = None;
    for _ in 0..30_000 {
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
    for _ in 0..12_000 {
        if drain.check_quiet().is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(drain.check_quiet().is_ok(), "quiet once the turn ended");
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_operator_root_queued_behind_drain_never_runs_or_logs() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let drain = node.drain(Duration::from_secs(5)).await.unwrap();
    let before = node.applied_lsn();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.send(
        ActorRef::parse("counter/revoked").unwrap(),
        pb::Message {
            name: "increment".into(),
            ..Default::default()
        },
        audit(),
        false,
        authority.lease(),
    ));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    assert_eq!(
        request.await.unwrap_err().code,
        kronik_core::error::ErrorCode::Unauthenticated
    );
    assert_eq!(node.applied_lsn(), before);
    drop(drain);
    settle().await;
    assert_eq!(node.applied_lsn(), before);
    assert!(
        node.store()
            .db()
            .actor("counter", "revoked")
            .unwrap()
            .is_none()
    );
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_deploy_waiting_for_lock_never_installs_or_logs() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.deploy_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let epoch = node.epoch();
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/notes.wasm"
    ))
    .unwrap();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.deploy(&wasm, audit(), false, authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.epoch(), epoch);
    assert!(!node.kind_exists("notes"));
    drop(held);
    let deployed = node
        .deploy(&wasm, audit(), false, common::lease())
        .await
        .unwrap();
    assert_eq!(deployed.lsn, before + 1);
    assert_eq!(node.config_now().epoch, deployed.epoch);
    assert!(node.kind_exists("notes"));
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_resend_queued_behind_drain_releases_its_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let failed = node
        .send(
            ActorRef::parse("counter/resend-revocation").unwrap(),
            pb::Message {
                name: "fail".into(),
                ..Default::default()
            },
            audit(),
            false,
            common::lease(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!failed.committed());
    let dead = failed.turn_id.lsn;
    let drain = node.drain(Duration::from_secs(5)).await.unwrap();
    let before = node.applied_lsn();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.resend(dead, audit(), false, authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(
        node.store()
            .db()
            .dead_letter(dead)
            .unwrap()
            .unwrap()
            .resent_as,
        None
    );
    drop(drain);
    let resent = node
        .resend(dead, audit(), false, common::lease())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        node.store()
            .db()
            .dead_letter(dead)
            .unwrap()
            .unwrap()
            .resent_as,
        Some(resent.turn_id.lsn)
    );
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn approval_keeps_original_lease_through_actual_final_log_admission() {
    struct RevokeAtAdmission(Arc<common::Revocable>);
    impl kronik_core::authority::Authority for RevokeAtAdmission {
        fn check(&self) -> Result<(), ApiError> {
            kronik_core::authority::Authority::check(self.0.as_ref())
        }
        fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
            kronik_core::authority::Authority::cancelled(self.0.as_ref())
        }
        fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
            self.0.revoke();
            kronik_core::authority::Authority::admit(self.0.as_ref(), effect)
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let before = node.applied_lsn();
    let approval = pb::Approval {
        proposal_id: "revoked-proposal".into(),
        diff_hash: vec![1; 32],
        verified_through_lsn: before,
        audit: Some(audit()),
        request: true,
        command: "kronik approve revoked-proposal".into(),
        verified_identity: None,
    };
    let authority = Arc::new(RevokeAtAdmission(common::Revocable::new()));
    let error = node
        .record_approval(approval.clone(), authority)
        .await
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert!(
        node.store()
            .db()
            .approvals("revoked-proposal")
            .unwrap()
            .is_empty()
    );
    let lsn = node
        .record_approval(approval, common::lease())
        .await
        .unwrap();
    assert_eq!(lsn, before + 1);
    assert_eq!(
        node.store()
            .db()
            .approvals("revoked-proposal")
            .unwrap()
            .len(),
        1
    );
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_remaining_admin_lock_waiter_cannot_publish_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.deploy_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let epoch = node.epoch();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.grant(
        "counter",
        "http:revoked.test",
        None,
        None,
        kronik_effects::InForks::Recorded,
        audit(),
        false,
        authority.lease(),
    ));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.epoch(), epoch);
    assert!(
        node.config_now()
            .grant("counter", "http:revoked.test")
            .is_none()
    );
    drop(held);
    let (_, lsn) = node
        .grant(
            "counter",
            "http:accepted.test",
            None,
            None,
            kronik_effects::InForks::Recorded,
            audit(),
            false,
            common::lease(),
        )
        .await
        .unwrap();
    assert_eq!(lsn, before + 1);
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_privacy_mode_waiter_cannot_toggle_the_sealer() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.deploy_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let mode = node.privacy_mode();
    let sealing = node.sealer().is_on();
    let authority = common::Revocable::new();
    let mut request =
        Box::pin(node.set_privacy_mode(pb::PrivacyState::On, audit(), false, authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.privacy_mode(), mode);
    assert_eq!(node.sealer().is_on(), sealing);
    drop(held);
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_snapshot_waiter_creates_neither_files_nor_marker() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.snapshot_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let snapshots = node.snapshots().unwrap().len();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.snapshot("manual", authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.snapshots().unwrap().len(), snapshots);
    drop(held);
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_erasure_lock_waiter_deletes_no_keys_or_state() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.deploy_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let keys = node.keystore_stats().unwrap();
    let authority = common::Revocable::new();
    let mut request =
        Box::pin(node.erase_subject("revoked-subject", audit(), false, authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let error = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.keystore_stats().unwrap(), keys);
    assert!(
        !node
            .store()
            .db()
            .erasures()
            .unwrap()
            .iter()
            .any(|(subject, _)| subject == "revoked-subject")
    );
    drop(held);
}

#[tokio::test(flavor = "current_thread")]
async fn admitted_irreversible_erasure_finishes_after_revoke() {
    struct RevokeAfterAdmission(Arc<common::Revocable>);
    impl kronik_core::authority::Authority for RevokeAfterAdmission {
        fn check(&self) -> Result<(), ApiError> {
            kronik_core::authority::Authority::check(self.0.as_ref())
        }
        fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
            kronik_core::authority::Authority::cancelled(self.0.as_ref())
        }
        fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
            kronik_core::authority::Authority::admit(self.0.as_ref(), effect)?;
            self.0.revoke();
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let authority = Arc::new(RevokeAfterAdmission(common::Revocable::new()));
    let done = node
        .erase_subject("accepted-subject", audit(), false, authority.clone())
        .await
        .unwrap();
    assert!(done.lsn.is_some());
    assert!(kronik_core::authority::Authority::check(authority.as_ref()).is_err());
    assert!(
        node.store()
            .db()
            .erasures()
            .unwrap()
            .iter()
            .any(|(subject, _)| subject == "accepted-subject")
    );
    assert!(node.fatal().is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn revoked_rebase_pause_releases_its_configuration_lock_waiter() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let held = node.deploy_lock.clone().lock_owned().await;
    let before = node.applied_lsn();
    let authority = common::Revocable::new();
    let mut request = Box::pin(node.rebase_pause(Duration::from_secs(5), authority.lease()));
    std::future::poll_fn(|cx| {
        assert!(request.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    authority.revoke();
    let result = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .unwrap();
    assert!(
        matches!(result, Err(error) if error.code == kronik_core::error::ErrorCode::Unauthenticated)
    );
    assert_eq!(node.applied_lsn(), before);
    drop(held);
    let pause = node
        .rebase_pause(Duration::from_secs(5), common::lease())
        .await
        .unwrap();
    assert!(pause.check_quiet().is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn admitted_code_switch_retains_live_config_after_request_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let (node, hold) = node(dir.path()).await;
    let version = node.deployed("counter").unwrap();
    let switch = crate::CodeSwitch {
        kinds: vec![version.clone()],
        pinned: vec![version],
        cause: pb::DeploymentCause::Rollback,
        verified_through_lsn: 0,
        unverified_inputs: 0,
        proposal_id: String::new(),
        rollback_of_epoch: node.epoch(),
    };
    let authority = common::Revocable::new();
    let parked = hold.parked.load(Ordering::SeqCst);
    let request = {
        let node = node.clone();
        let authority = authority.lease();
        tokio::spawn(async move { node.switch_code(switch, audit(), false, authority).await })
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        while hold.parked.load(Ordering::SeqCst) == parked {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    authority.revoke();
    hold.release.add_permits(1);
    let (epoch, lsn) = request.await.unwrap().unwrap();
    assert_eq!(node.epoch(), epoch);
    assert_eq!(node.config_now().epoch, epoch);
    assert!(node.applied_lsn() >= lsn);
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_watch_switch_rejects_arbitrary_ordinary_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let version = node.deployed("counter").unwrap();
    let valid = crate::CodeSwitch {
        kinds: vec![version.clone()],
        pinned: vec![version],
        cause: pb::DeploymentCause::Rollback,
        verified_through_lsn: 0,
        unverified_inputs: 0,
        proposal_id: String::new(),
        rollback_of_epoch: node.epoch(),
    };
    let before = node.applied_lsn();
    for case in 0..8 {
        let mut switch = valid.clone();
        match case {
            0 => switch.cause = pb::DeploymentCause::Deploy,
            1 => switch.rollback_of_epoch = 0,
            2 => switch.pinned.clear(),
            3 => switch.pinned.push(switch.pinned[0].clone()),
            4 => switch.pinned[0].kind = "other".into(),
            5 => switch.proposal_id = "operator".into(),
            6 => switch.verified_through_lsn = 1,
            _ => switch.unverified_inputs = 1,
        }
        let mut metadata = audit();
        metadata.reason = "watch fixed: guard `error-rate` fired".into();
        assert_eq!(
            node.switch_code_from_guard(switch, metadata)
                .await
                .unwrap_err()
                .code,
            kronik_core::error::ErrorCode::BadRequest
        );
        assert_eq!(node.applied_lsn(), before);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fixed_system_audit_selects_identity_without_granting_ordinary_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (node, _) = node(dir.path()).await;
    let authority = common::Revocable::new();
    authority.revoke();
    let before = node.applied_lsn();
    let mut metadata = audit();
    metadata.token_id = "system".into();
    assert_eq!(
        node.record_audit_event_authorized(
            "keys.rewrap",
            "node",
            Default::default(),
            metadata.clone(),
            authority.lease()
        )
        .await
        .unwrap_err()
        .code,
        kronik_core::error::ErrorCode::Unauthenticated
    );
    assert_eq!(node.applied_lsn(), before);
    metadata.token_id = "arbitrary-metadata".into();
    assert_eq!(
        node.record_system_audit_event(
            crate::SystemAudit::KeySource,
            "node",
            Default::default(),
            metadata.clone(),
            authority.lease()
        )
        .await
        .unwrap_err()
        .code,
        kronik_core::error::ErrorCode::Unauthenticated
    );
    assert_eq!(node.applied_lsn(), before);
    let original = node.local_operator_authority().unwrap();
    let lsn = node
        .record_system_audit_event(
            crate::SystemAudit::KeySource,
            "node",
            Default::default(),
            metadata,
            original,
        )
        .await
        .unwrap();
    let mut event = None;
    node.reader()
        .read(lsn, lsn, |record| {
            event = Some(record.record);
            Ok(())
        })
        .await
        .unwrap();
    let Some(kronik_proto::Record::AuditEvent(event)) = event else {
        panic!("wrong record");
    };
    assert_eq!(event.action, "keys.source");
    assert_eq!(event.audit.unwrap().token_id, "system");
}
