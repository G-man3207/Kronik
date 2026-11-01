use super::*;

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "native-reader-test".into(),
        reason: "ordinary native record reader regression".into(),
        wall_time_ms: 1,
    }
}

async fn append(node: &Node, target: &str) -> Lsn {
    let original = node.local_operator_authority().unwrap();
    node.record_audit_event_authorized(
        "test.native.reader",
        target,
        BTreeMap::new(),
        audit(),
        original,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn native_record_consumer_keeps_actual_cut_namespace_and_soft_batch_contract() {
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = crate::start_local(env, data.path(), NodeConfig::default())
        .await
        .unwrap();
    let first = append(&node, "first").await;
    let reader = node.capture_system_export_reader().await.unwrap();
    let SourcePos::Actor {
        shard: None,
        lsn: head,
    } = reader.point().source
    else {
        panic!("actual native source")
    };
    assert!(head >= first);
    let second = append(&node, "after-the-captured-cut").await;
    assert!(second > head);
    let page = reader.page(0, 256, 4 << 20).await.unwrap();
    assert_eq!(page.scanned_through, head);
    assert_eq!(page.retention_gap, None);
    assert!(
        page.records
            .iter()
            .any(|(_, committed)| committed.lsn == first)
    );
    assert!(
        page.records
            .iter()
            .all(|(source, committed)| source.shard.is_none()
                && source.lsn == committed.lsn
                && committed.lsn <= head
                && source.branch == reader.point().branch)
    );
    assert!(
        !page
            .records
            .iter()
            .any(|(_, committed)| committed.lsn == second)
    );
    assert!(reader.page(first - 1, 1, 1).await.is_err());
    let soft = reader.local_export_page(first - 1, 1, 1).await.unwrap();
    assert_eq!(soft.records.len(), 1);
    assert_eq!(soft.records[0].1.lsn, first);
    assert!(reader.page(head + 1, 1, 1024).await.is_err());
    assert!(reader.page(0, 0, 1024).await.is_err());
    assert!(reader.page(0, 1, MAX_RECORD_PAGE_BYTES + 1).await.is_err());
    let end = reader.local_export_page(head, 1, 1024).await.unwrap();
    assert!(end.records.is_empty());
    assert_eq!(end.scanned_through, head);
}

#[tokio::test]
async fn configuration_change_invalidates_original_reader_and_not_yet_polled_capture() {
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = crate::start_local(env, data.path(), NodeConfig::default())
        .await
        .unwrap();
    append(&node, "before-configuration").await;
    let reader = node.capture_system_export_reader().await.unwrap();
    let pending = node.capture_system_export_reader();
    let original = node.local_operator_authority().unwrap();
    node.set_policy("", audit(), false, original).await.unwrap();
    assert!(
        pending.await.is_err(),
        "a queued old capture must not acquire the new epoch"
    );
    assert!(reader.check().is_err());
    assert!(!reader.data_is_live_under_publication());
    assert!(reader.page(0, 256, 4 << 20).await.is_err());
    let fresh = node.capture_system_export_reader().await.unwrap();
    fresh.check().unwrap();
}

#[tokio::test]
async fn stopped_original_native_role_denies_a_capture_waiting_on_actual_deploy_lock() {
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = crate::start_local(env, data.path(), NodeConfig::default())
        .await
        .unwrap();
    append(&node, "before-stop").await;
    let reader = node.capture_system_export_reader().await.unwrap();
    let deploy = node.deploy_lock.clone().lock_owned().await;
    let pending = node.capture_system_export_reader();
    node.stop_native_execution().unwrap();
    assert!(pending.await.is_err());
    assert!(reader.check().is_err());
    assert!(!reader.data_is_live_under_publication());
    assert!(reader.local_export_page(0, 256, 4 << 20).await.is_err());
    assert!(node.capture_system_export_reader().await.is_err());
    drop(deploy);
}

#[tokio::test]
async fn actual_native_record_guard_keeps_same_registry_root_until_the_last_owned_reader_drops() {
    use kronik_core::snapshot_resources::SnapshotRootRegistry;
    let data = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = crate::start_local(env, data.path(), NodeConfig::default())
        .await
        .unwrap();
    append(&node, "actual-root-pin").await;
    let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
    let roots = node.native_execution.source_roots();
    let pin = reader
        .root_pin
        .as_ref()
        .expect("actual start_local has protected physical storage");
    assert!(SnapshotRootRegistry::contains(&roots, pin));
    let path = std::fs::canonicalize(data.path()).unwrap();
    let owned_frames = reader.clone();
    drop(reader);
    let planned = SnapshotRootRegistry::prepare_deletion(&roots, vec![path.clone()]).unwrap();
    assert!(SnapshotRootRegistry::begin_deletion(&roots, planned).is_err());
    owned_frames
        .local_export_page(0, 256, 4 << 20)
        .await
        .unwrap();
    drop(owned_frames);
    let planned = SnapshotRootRegistry::prepare_deletion(&roots, vec![path]).unwrap();
    let unknown = SnapshotRootRegistry::begin_deletion(&roots, planned).unwrap();
    assert!(node.capture_system_export_reader().await.is_err());
    drop(unknown);
    assert!(SnapshotRootRegistry::deletion_pending(&roots));
    assert!(
        node.capture_system_export_reader().await.is_err(),
        "unknown deletion is not completion"
    );
}
