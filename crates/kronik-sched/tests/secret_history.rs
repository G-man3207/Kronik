#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use kronik_core::env::Env;
use kronik_proto::log::v1 as pb;
use kronik_sched::{NodeConfig, start_local};

#[tokio::test]
async fn native_mutation_ack_certifies_immediate_history_versions_and_reason_redaction() {
    let data = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        data.path(),
        NodeConfig { group_commit_window: Some(Duration::ZERO), ..Default::default() },
    ).await.unwrap();
    let original = node.local_operator_authority().unwrap();
    let mut audit = pb::Audit { token_id: "operator".into(), reason: String::new(), wall_time_ms: 19 };
    for bytes in [b"alpha".as_slice(), b"true".as_slice()] {
        audit.reason = format!("prefix|{}|suffix", std::str::from_utf8(bytes).unwrap());
        let written = node.secret_set("wake", bytes.to_vec(), &audit, false, original.clone())
            .await.unwrap().unwrap();
        let inventory = node.secret_values().unwrap();
        let history = node.secret_history("wake").await.unwrap();
        let latest = history.last().unwrap();
        assert_eq!(latest.version, written.version);
        assert_eq!(latest.audit.as_ref().unwrap().reason, "prefix|[secret:wake]|suffix");
        assert!(inventory.iter().any(|(name, value)| name == "wake" && value.as_slice() == bytes));
        let explicit = node.resolve_secret("wake", Some(written.version), &node.config_now(), original.clone())
            .await.unwrap().unwrap();
        assert_eq!(explicit.value, bytes);
        assert_eq!(explicit.meta.version_hash, written.version_hash);
    }
    audit.reason = "rotate credential".into();
    node.secret_refresh("wake", &audit, false, original.clone()).await.unwrap();
    assert!(node.secret_values().is_ok());
    node.secret_delete("wake", &audit, false, original).await.unwrap();
    let history = node.secret_history("wake").await.unwrap();
    assert!(history.last().unwrap().deleted);
    let inventory = node.secret_values().unwrap();
    assert!(inventory.iter().any(|(name, value)| name == "wake" && value.as_slice() == b"alpha"));
    assert!(inventory.iter().any(|(name, value)| name == "wake" && value.as_slice() == b"true"));
}

#[tokio::test]
async fn privacy_configuration_ack_requalifies_the_actual_cached_native_inventory() {
    let data = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        data.path(),
        NodeConfig { group_commit_window: Some(Duration::ZERO), ..Default::default() },
    ).await.unwrap();
    let original = node.local_operator_authority().unwrap();
    let audit = pb::Audit { token_id: "operator".into(), reason: "configure privacy".into(), wall_time_ms: 23 };
    let written = node.secret_set("transition", b"retained transition needle".to_vec(), &audit, false, original.clone())
        .await.unwrap().unwrap();
    let before = node.native_secret_snapshot().unwrap();
    let previous_epoch = node.epoch();
    let changed = node.set_privacy_mode(pb::PrivacyState::On, audit, false, original).await.unwrap();
    assert!(changed.changed);
    assert_eq!(changed.epoch, Some(previous_epoch + 1));
    assert_eq!(node.epoch(), previous_epoch + 1);
    let values = node.secret_values().unwrap();
    let history = node.secret_history("transition").await.unwrap();
    assert_eq!(history.last().unwrap().version, written.version);
    assert_eq!(history.last().unwrap().version_hash, written.version_hash);
    assert!(values.iter().any(|(name, value)| name == "transition" && value.as_slice() == b"retained transition needle"));
    let after = node.native_secret_snapshot().unwrap();
    assert_ne!(before.fingerprint, after.fingerprint);
}

#[tokio::test]
async fn held_native_publication_cannot_enqueue_after_same_content_recertification() {
    let data = tempfile::tempdir().unwrap();
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()), data.path(),
        NodeConfig { group_commit_window: Some(Duration::ZERO), ..Default::default() },
    ).await.unwrap();
    let original = node.local_operator_authority().unwrap();
    let audit = pb::Audit { token_id: "operator".into(), reason: "publication boundary".into(), wall_time_ms: 29 };
    node.secret_set("publication", b"held native needle".to_vec(), &audit, false, original.clone()).await.unwrap();
    let (before, held) = node.native_secret_snapshot_with_publication().unwrap();
    node.refresh_secret_inventory(original.clone()).await.unwrap();
    let (after, current) = node.native_secret_snapshot_with_publication().unwrap();
    assert_eq!(before.fingerprint, after.fingerprint);
    tokio::time::timeout(Duration::from_secs(2), held.cancelled()).await.unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let mut denied = kronik_core::ApiError::new(kronik_core::ErrorCode::SecretUnavailable, "the captured publication is no longer current");
    let error = original.admit(&mut || held.with_current_publication(&mut denied, || {
        sender.try_send(before.fingerprint).unwrap();
        Ok(())
    })).unwrap_err();
    assert_eq!(error.code, kronik_core::ErrorCode::SecretUnavailable);
    assert!(matches!(receiver.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)));
    let mut denied = kronik_core::ApiError::new(kronik_core::ErrorCode::SecretUnavailable, "the captured publication is no longer current");
    original.admit(&mut || current.with_current_publication(&mut denied, || {
        sender.try_send(after.fingerprint).unwrap();
        Ok(())
    })).unwrap();
    assert_eq!(receiver.recv().await.unwrap(), after.fingerprint);
}
