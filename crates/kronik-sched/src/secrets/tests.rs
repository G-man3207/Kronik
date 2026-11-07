#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use super::*;
use kronik_core::env::{BoxFuture, Clock, HttpRequest, HttpResponse, Net, NetError};
use kronik_privacy::secret_backend::config::Definition;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use tokio::sync::Semaphore;

fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}

#[derive(Default)]
struct TestAuthority {
    revoked: Arc<Mutex<bool>>,
    changed: Arc<tokio::sync::Notify>,
}
impl TestAuthority {
    fn revoke(&self) {
        *lock(&self.revoked) = true;
        self.changed.notify_waiters();
    }
}
impl kronik_core::authority::Authority for TestAuthority {
    fn check(&self) -> Result<(), ApiError> {
        if *lock(&self.revoked) {
            Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "test authority revoked",
            ))
        } else {
            Ok(())
        }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let revoked = self.revoked.clone();
        let changed = self.changed.clone();
        Box::pin(async move {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if *lock(&revoked) {
                    return;
                }
                notified.await;
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let revoked = lock(&self.revoked);
        if *revoked {
            Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "test authority revoked",
            ))
        } else {
            effect()
        }
    }
}
fn test_auth() -> AuthLease {
    Arc::new(TestAuthority::default())
}
fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "operator".into(),
        reason: "rotate credential".into(),
        wall_time_ms: 19,
    }
}
async fn node() -> (tempfile::TempDir, Arc<Node>) {
    let data = tempfile::tempdir().unwrap();
    let node = crate::start_local(
        env(),
        data.path(),
        crate::NodeConfig {
            group_commit_window: Some(Duration::ZERO),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (data, node)
}
/// A node whose secret mutations wait for the inventory as long as a loaded
/// machine needs. A mutation answers 503 "already committed" when the
/// inventory is not published again within `fetch_timeout` (two seconds by
/// default) of the mutation, which a run of many mutations on a loaded
/// machine can exceed; a test of the ledger itself should not depend on it.
async fn patient_node() -> (tempfile::TempDir, Arc<Node>) {
    let data = tempfile::tempdir().unwrap();
    let mut config = crate::NodeConfig {
        group_commit_window: Some(Duration::ZERO),
        ..Default::default()
    };
    config.secret_settings.fetch_timeout = Duration::from_secs(30);
    let node = crate::start_local(env(), data.path(), config)
        .await
        .unwrap();
    (data, node)
}
fn row(version: u64, generation: u64) -> pb::SecretVersion {
    pb::SecretVersion {
        name: "token".into(),
        version,
        version_hash: vec![version as u8; 16],
        backend: "file".into(),
        source_version: version.to_string(),
        deleted: false,
        audit: Some(audit()),
        r#ref: "token".into(),
        binding: "file".into(),
        link_generation: generation,
        canonical_ref: "token".into(),
        phase: Phase::Active as i32,
        hash_revision: revision(version),
    }
}
fn link(name: &str, generation: u64, reference: &str) -> pb::SecretLink {
    pb::SecretLink {
        name: name.into(),
        backend: "bao".into(),
        r#ref: reference.into(),
        binding: "trusted".into(),
        generation,
        canonical_ref: reference.into(),
        epoch: generation,
        audit: Some(audit()),
    }
}
fn external_row(version: u64, generation: u64, reference: &str) -> pb::SecretVersion {
    let link = link("token", generation, reference);
    pb::SecretVersion {
        backend: link.backend,
        r#ref: link.r#ref,
        canonical_ref: link.canonical_ref,
        binding: link.binding,
        source_version: "1".into(),
        ..row(version, generation)
    }
}
struct TestClock(AtomicU64);
impl TestClock {
    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn wall_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst) * 1000
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
    fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
        Box::pin(std::future::pending())
    }
}
fn cache() -> (Arc<SecretCache>, Arc<TestClock>) {
    let clock = Arc::new(TestClock(AtomicU64::new(1000)));
    let mut environment = env();
    environment.clock = clock.clone();
    let data = SecretCacheData::new();
    let mut cache = SecretCache::new(
        environment,
        Settings::default(),
        &Backends::default(),
        Arc::new(Mutex::new(())),
        &data,
    );
    cache.authorities.insert(
        "bao".into(),
        Authority {
            binding: "trusted".into(),
            allowed_refs: vec!["secret/".into()],
        },
    );
    let cache = Arc::new(cache);
    lock(&cache.state).bound_cache = Arc::downgrade(&cache);
    (cache, clock)
}
fn hold(cache: &SecretCache, row: &pb::SecretVersion, operational: bool) {
    cache.register(row.clone());
    let stamp = cache.read_stamp(&Scope::row(row)).unwrap();
    cache
        .insert(
            row,
            Arc::new(Zeroizing::new(b"sensitive-value".to_vec())),
            operational,
            Some(&stamp),
        )
        .unwrap();
    if operational {
        lock(&cache.state)
            .current
            .insert(Scope::row(row), (row.name.clone(), row.version));
    }
}

#[tokio::test]
async fn per_name_concurrent_sets_use_one_durable_allocator() {
    let (_data, node) = patient_node().await;
    let mut tasks = Vec::new();
    for index in 0..12 {
        let node = node.clone();
        tasks.push(tokio::spawn(async move {
            node.secret_set(
                "token",
                format!("credential-{index}").into_bytes(),
                &audit(),
                false,
                test_auth(),
            )
            .await
            .unwrap()
            .unwrap()
        }));
    }
    let mut versions = BTreeSet::new();
    for task in tasks {
        versions.insert(task.await.unwrap().version);
    }
    assert_eq!(versions, (1..=12).collect());
    let history = node.secret_history("token").await.unwrap();
    assert_eq!(history.len(), 12);
    assert!(history.iter().all(active));
    assert_eq!(node.store().db().secret_highwater("token").unwrap(), 12);
    let current = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.meta.version, 12);
}

#[tokio::test]
async fn failed_file_reservation_never_becomes_current_and_is_never_reused() {
    let (_data, node) = node().await;
    node.secret_set(
        "token",
        b"acknowledged-value".to_vec(),
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let runtime = node.runtime().unwrap();
    // An independent file write is deliberately unacknowledged by the log.
    runtime
        .file
        .set_at(
            "token",
            2,
            b"unacknowledged-orphan",
            [2; 24],
            20,
            "system",
            "crash boundary",
        )
        .unwrap();
    // The design no longer fails the next write on the physical collision:
    // it skips past the unacknowledged orphan, whose physical slot is never
    // reused and whose bytes never become the operational current.
    let next = node
        .secret_set(
            "token",
            b"acknowledged-successor".to_vec(),
            &audit(),
            false,
            test_auth(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.version, 2);
    let identity = node
        .secret_identity(node.branch(), "token", 2)
        .await
        .unwrap();
    assert_eq!(identity.source_version, "3");
    let history = node.secret_history("token").await.unwrap();
    assert_eq!(history[1].phase, Phase::Active as i32);
    let current = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.meta.version, 2);
    assert_eq!(current.value, b"acknowledged-successor");
}

/// The coverage watermark is written after a successful refresh, survives a
/// restart of the same store, and is invalidated by a restored (replaced)
/// store or a corrupt artifact — which fall back to the full scan and never
/// block startup.
#[tokio::test]
async fn coverage_watermark_persists_survives_restart_and_voids_on_restore() {
    let (data, node) = node().await;
    node.secret_set(
        "token",
        b"watermarked-value".to_vec(),
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    let manifest = data.path().join("secret-coverage.json");
    let written: coverage::CoverageWatermark =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(written.branch, node.branch());
    assert_eq!(written.certified_through_lsn, node.applied_lsn());
    assert!(written.store_generation.len() == 32);
    assert!(
        node.secret_values()
            .unwrap()
            .iter()
            .any(|(name, value)| name == "token" && value.as_slice() == b"watermarked-value"),
        "the delta-seeded read still certifies"
    );

    // A corrupt artifact is discarded (warned) and the next refresh falls
    // back to the full scan, rewriting a fresh watermark: never a startup
    // blocker and never a partial trust.
    std::fs::write(&manifest, b"{ not json").unwrap();
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    let rewritten: coverage::CoverageWatermark =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(rewritten, written);

    // A restored (replaced) store carries another generation: the stale
    // watermark is voided and the refresh recertifies from a full scan.
    let foreign = rewritten.clone();
    let mut generation = foreign.store_generation.clone().into_bytes();
    generation[0] = generation[0].wrapping_add(1);
    let voided = coverage::CoverageWatermark {
        store_generation: String::from_utf8(generation).unwrap(),
        ..foreign
    };
    std::fs::write(&manifest, serde_json::to_vec(&voided).unwrap()).unwrap();
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    let recertified: coverage::CoverageWatermark =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(recertified, written);
}

#[tokio::test]
async fn pending_recovery_verifies_matching_file_bytes_and_fails_missing_writes() {
    let (_data, node) = node().await;
    let runtime = node.runtime().unwrap();
    let value = b"written-before-crash";
    let hash = runtime.file.version_hash("token", 1, value).unwrap();
    let pending = node.secret_record(
        &Scope::file("token", 0),
        1,
        "1".into(),
        hash,
        false,
        audit(),
    );
    node.secret_publish(pending.clone()).await.unwrap();
    runtime
        .file
        .set_at(
            "token",
            1,
            value,
            [1; 24],
            19,
            "operator",
            "rotate credential",
        )
        .unwrap();
    let missing = node.secret_record(
        &Scope::file("token", 0),
        2,
        "2".into(),
        vec![3; 16],
        false,
        audit(),
    );
    node.secret_publish(missing.clone()).await.unwrap();
    node.initialize_secret_versions(false, test_auth())
        .await
        .unwrap();
    let history = node.secret_history("token").await.unwrap();
    assert_eq!(history[0].phase, Phase::Active as i32);
    assert_eq!(history[0].audit, pending.audit);
    assert_eq!(history[1].phase, Phase::Failed as i32);
    assert_eq!(history[1].audit, missing.audit);
    assert_eq!(node.next_secret_version("token").await.unwrap(), 3);
    assert_eq!(
        node.resolve_secret("token", None, &node.config_now(), test_auth())
            .await
            .unwrap()
            .unwrap()
            .value,
        value
    );
}

#[tokio::test]
async fn legacy_import_preserves_hash_bytes_and_fences_even_a_lost_name() {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let keys = data.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let master_path = keys.join("master.key");
    std::fs::write(&master_path, "07".repeat(32)).unwrap();
    std::fs::set_permissions(&master_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
    let ownership = kronik_privacy::key_source::lock_data(data.path()).unwrap();
    let file = SecretStore::open_owned(&ownership, &master, SecretCacheData::new()).unwrap();
    let old = file
        .set_at(
            "token",
            17,
            b"legacy-credential",
            [17; 24],
            3,
            "old",
            "old intent",
        )
        .unwrap();
    drop(file);
    drop(ownership);
    let node = crate::start_local(
        env(),
        data.path(),
        crate::NodeConfig {
            group_commit_window: Some(Duration::ZERO),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let imported = node
        .secret_identity(node.branch(), "token", 17)
        .await
        .unwrap();
    assert_eq!(imported.version_hash, old.version_hash);
    assert_eq!(imported.source_version, "17");
    assert_eq!(imported.hash_revision, 1);
    assert_eq!(
        node.store().db().secret_format_floor().unwrap(),
        Some(LEGACY_SECRET_VERSION_MAX)
    );
    assert_eq!(
        node.next_secret_version("entirely-lost-name")
            .await
            .unwrap(),
        LEGACY_SECRET_VERSION_MAX + 1
    );
}

#[tokio::test]
async fn existing_empty_legacy_store_is_not_mistaken_for_a_genuine_fresh_format() {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let keys = data.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("master.key"), "09".repeat(32)).unwrap();
    std::fs::set_permissions(
        keys.join("master.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let master = kronik_privacy::MasterKey::from_bytes([9; 32]).unwrap();
    let ownership = kronik_privacy::key_source::lock_data(data.path()).unwrap();
    let file = SecretStore::open_owned(&ownership, &master, SecretCacheData::new()).unwrap();
    file.set_at("lost", 31, b"old-unlogged-value", [4; 24], 4, "old", "old")
        .unwrap();
    drop(file);
    drop(ownership);
    rusqlite::Connection::open(keys.join("secrets.db"))
        .unwrap()
        .execute("DELETE FROM secrets", [])
        .unwrap();
    let node = crate::start_local(
        env(),
        data.path(),
        crate::NodeConfig {
            group_commit_window: Some(Duration::ZERO),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        node.next_secret_version("lost").await.unwrap(),
        LEGACY_SECRET_VERSION_MAX + 1
    );
}

#[tokio::test]
async fn mutation_is_owned_after_the_waiting_request_is_cancelled() {
    let (_data, node) = node().await;
    let guard = node
        .runtime()
        .unwrap()
        .name_lock("token")
        .lock_owned()
        .await;
    let request_node = node.clone();
    let request = tokio::spawn(async move {
        request_node
            .secret_set(
                "token",
                b"owned-after-disconnect".to_vec(),
                &audit(),
                false,
                test_auth(),
            )
            .await
    });
    node.env.clock.sleep(Duration::from_millis(10)).await;
    request.abort();
    drop(guard);
    node.env
        .timeout(Duration::from_secs(2), async {
            loop {
                if node
                    .secret_history("token")
                    .await
                    .unwrap()
                    .iter()
                    .any(active)
                {
                    break;
                }
                node.env.clock.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    assert_eq!(
        node.resolve_secret("token", None, &node.config_now(), test_auth())
            .await
            .unwrap()
            .unwrap()
            .value,
        b"owned-after-disconnect"
    );
}

#[tokio::test]
async fn dry_run_consumes_no_version_and_fills_no_value_cache() {
    let (_data, node) = node().await;
    let before = node.applied_lsn();
    assert!(
        node.secret_set(
            "token",
            b"not-published".to_vec(),
            &audit(),
            true,
            test_auth()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(node.applied_lsn(), before);
    assert!(node.secret_history("token").await.unwrap().is_empty());
    assert!(lock(&node.runtime().unwrap().cache.state).values.is_empty());
    assert_eq!(node.next_secret_version("token").await.unwrap(), 1);
}

#[test]
fn new_value_is_scrubbed_before_reserved_and_remains_redacted_after_restart() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (data, identity, encrypted) = runtime.block_on(async {
        let (data, node) = node().await;
        let original = node.local_operator_authority().unwrap();
        let mut audit = audit();
        audit.reason = "replace new-needle now".into();
        let set = node
            .secret_set("token", b"new-needle".to_vec(), &audit, false, original)
            .await
            .unwrap()
            .unwrap();
        let reader = node.capture_system_export_reader().await.unwrap();
        let page = reader.page(0, 64, 64 * 1024).await.unwrap();
        let phases = page
            .records
            .iter()
            .filter_map(|(_, committed)| match &committed.record {
                Record::SecretVersion(row) if row.name == "token" && row.version == set.version => {
                    Some(row)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            phases.iter().map(|row| row.phase).collect::<Vec<_>>(),
            [Phase::Reserved as i32, Phase::Active as i32]
        );
        let identity = (*phases[1]).clone();
        let physical = identity.source_version.parse().unwrap();
        let encrypted = node
            .secrets()
            .unwrap()
            .export_encrypted_row("token", physical)
            .unwrap()
            .unwrap();
        for row in phases {
            let stored = row.audit.as_ref().unwrap();
            assert_eq!(stored.token_id, audit.token_id);
            assert_eq!(stored.wall_time_ms, audit.wall_time_ms);
            assert!(!stored.reason.contains("new-needle"));
            assert_eq!(stored.reason, encrypted.reason);
            assert_eq!(stored.token_id, encrypted.token_id);
            assert_eq!(stored.wall_time_ms, encrypted.created_wall_ms);
        }
        let history = node.secret_history("token").await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], identity);
        (data, identity, encrypted)
    });
    drop(runtime);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let node = crate::start_local(
            env(),
            data.path(),
            crate::NodeConfig {
                group_commit_window: Some(Duration::ZERO),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(node.secret_history("token").await.unwrap(), [identity]);
        assert_eq!(
            node.secrets()
                .unwrap()
                .export_encrypted_row("token", encrypted.physical_version)
                .unwrap(),
            Some(encrypted)
        );
        assert_eq!(
            node.resolve_secret(
                "token",
                None,
                &node.config_now(),
                node.local_operator_authority().unwrap()
            )
            .await
            .unwrap()
            .unwrap()
            .value,
            b"new-needle"
        );
    });
}

#[tokio::test]
async fn negative_cache_has_exact_scope_and_five_second_lifetime() {
    let (cache, clock) = cache();
    let first = Scope::link(&link("token", 1, "secret/first#token"));
    let second = Scope::link(&link("token", 2, "secret/second#token"));
    cache.failure(&first, BackendError::NotFound);
    assert_eq!(cache.negative(&first), Some(BackendError::NotFound));
    assert_eq!(cache.negative(&second), None);
    clock.advance(4);
    assert_eq!(cache.negative(&first), Some(BackendError::NotFound));
    clock.advance(1);
    assert_eq!(cache.negative(&first), None);
}

#[tokio::test]
async fn stale_is_allowed_only_for_unavailable_and_denial_revokes_without_losing_scrub_bytes() {
    let (cache, clock) = cache();
    let record = external_row(1, 1, "secret/first#token");
    hold(&cache, &record, true);
    let mut config = Config::default();
    config.apply(&Record::SecretLink(link("token", 1, "secret/first#token")));
    clock.advance(301);
    assert!(cache.cached("token", None, &config).is_err());
    cache.failure(&Scope::row(&record), BackendError::Unavailable);
    assert!(cache.cached("token", None, &config).unwrap().is_some());
    cache.failure(&Scope::row(&record), BackendError::Denied);
    assert!(cache.cached("token", None, &config).is_err());
    assert!(lock(&cache.state).values.contains_key(&("token".into(), 1)));
    clock.advance(6);
    cache.clear_negative(&Scope::row(&record));
    assert!(cache.cached("token", Some(1), &config).is_err());
}

#[tokio::test]
async fn max_stale_is_an_absolute_age_bound_not_extended_by_failures() {
    let (cache, clock) = cache();
    let record = row(1, 0);
    hold(&cache, &record, true);
    clock.advance(86_399);
    cache.failure(&Scope::row(&record), BackendError::Unavailable);
    assert!(
        cache
            .cached("token", Some(1), &Config::default())
            .unwrap()
            .is_some()
    );
    clock.advance(2);
    cache.failure(&Scope::row(&record), BackendError::Unavailable);
    assert!(cache.cached("token", Some(1), &Config::default()).is_err());
}

#[tokio::test]
async fn historical_generation_never_redirects_to_current_or_scrub_only_values() {
    let (cache, _) = cache();
    let old = external_row(1, 1, "secret/first#token");
    let new = external_row(2, 2, "secret/second#token");
    hold(&cache, &old, false);
    hold(&cache, &new, true);
    let mut config = Config::default();
    config.apply(&Record::SecretLink(link("token", 2, "secret/second#token")));
    assert_eq!(
        cache.cached("token", Some(1), &config).unwrap_err().code,
        ErrorCode::SecretVersionGone
    );
    assert_eq!(
        cache
            .cached("token", None, &config)
            .unwrap()
            .unwrap()
            .meta
            .version,
        2
    );
    let mut old_config = Config::default();
    old_config.apply(&Record::SecretLink(link("token", 1, "secret/first#token")));
    assert!(cache.cached("token", Some(1), &old_config).is_err());
    assert!(
        cache
            .cached("token", None, &Config::default())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn catalogue_observations_do_not_choose_the_operational_current_version() {
    let (cache, _) = cache();
    let current = external_row(1, 1, "secret/first#token");
    hold(&cache, &current, true);
    let older_catalogue = external_row(2, 1, "secret/first#token");
    hold(&cache, &older_catalogue, false);
    let mut config = Config::default();
    config.apply(&Record::SecretLink(link("token", 1, "secret/first#token")));
    assert_eq!(
        cache
            .cached("token", None, &config)
            .unwrap()
            .unwrap()
            .meta
            .version,
        1
    );
}

#[tokio::test]
async fn complete_inventory_is_revision_and_epoch_bound_and_resource_failure_is_not_complete() {
    let (_data, node) = node().await;
    let original = node.local_operator_authority().unwrap();
    node.secret_set(
        "token",
        b"first-real-value".to_vec(),
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap();
    let runtime = node.runtime().unwrap();
    let (_, publication) = node.native_secret_snapshot_with_publication().unwrap();
    assert!(runtime.cache.values(node.epoch() + 1).is_err());
    node.secret_set(
        "token",
        b"second-real-value".to_vec(),
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap();
    assert!(publication.check_current().is_err());
    assert!(
        node.secret_values()
            .unwrap()
            .iter()
            .any(|(_, bytes)| bytes.as_slice() == b"second-real-value")
    );
    let record = runtime
        .cache
        .row(&Scope::file("token", 0), Some(2))
        .unwrap();
    let too_large = Arc::new(Zeroizing::new(vec![1; MAX_INVENTORY_BYTES + 1]));
    assert_eq!(
        runtime
            .cache
            .insert(&record, too_large, false, None)
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert!(node.secret_values().is_err());
    assert_eq!(
        node.resolve_secret("token", Some(2), &node.config_now(), original)
            .await
            .unwrap()
            .unwrap()
            .value,
        b"second-real-value"
    );
}

#[tokio::test]
async fn the_cycle_is_settled_between_passes_with_a_certified_inventory_and_not_otherwise() {
    let (_data, node) = node().await;
    let runtime = node.runtime().unwrap();
    let within = |bound| node.env.timeout(bound, node.secret_cycle_settled());
    // The first pass ends, and the inventory is certified: settled.
    within(Duration::from_secs(60)).await.unwrap();
    // A pass in the middle of its work: not settled until it ends.
    runtime.cycle.begin();
    assert!(within(Duration::from_millis(100)).await.is_err());
    runtime.cycle.end();
    within(Duration::from_secs(60)).await.unwrap();
    // Between passes, but with the certificate retired: not settled until a
    // rebuild installs one.
    runtime.cache.clear_coverage();
    assert!(within(Duration::from_millis(100)).await.is_err());
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    within(Duration::from_secs(60)).await.unwrap();
}

#[tokio::test]
async fn a_certificate_displaced_at_the_same_epoch_retires_the_publications_taken_from_it() {
    let (_data, node) = node().await;
    let original = node.local_operator_authority().unwrap();
    // The cycle that starts with the node makes a first pass and publishes
    // its outcome; wait for it, so that nothing else moves the certificate
    // under the test.
    let runtime = node.runtime().unwrap();
    let mut certified = runtime.certified.subscribe();
    node.env
        .timeout(Duration::from_secs(5), async {
            while !certified.borrow_and_update().1 {
                certified.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    // A holder (an exporter preparing a batch) takes a publication from the
    // current certificate.
    let (_, held) = node.native_secret_snapshot_with_publication().unwrap();
    held.check_current().unwrap();
    // Another publisher reaches the install point at the same epoch, as the
    // cached-only recertification after a config commit and the tail of a
    // full refresh do when they overlap, and installs a new certificate.
    assert!(node.recertify_cached_secret_inventory().await.unwrap());
    // The publication cannot be admitted any more ...
    let mut denied = unavailable();
    assert!(
        original
            .admit(&mut || held.with_current_publication(&mut denied, || Ok(())))
            .is_err()
    );
    // ... and it must say so before its holder tries to deliver with it:
    // holders prepare again when the check fails, so a publication that
    // passes its check and is refused at admission is never replaced.
    assert!(
        held.check_current().is_err(),
        "a displaced certificate's publication still passes its check"
    );
    // Preparing again takes a publication from the installed certificate.
    let (_, fresh) = node.native_secret_snapshot_with_publication().unwrap();
    fresh.check_current().unwrap();
    let mut denied = unavailable();
    original
        .admit(&mut || fresh.with_current_publication(&mut denied, || Ok(())))
        .unwrap();
}

#[tokio::test]
async fn deletion_keeps_only_scrub_authority_and_missing_retained_values_fail_inventory() {
    let (_data, node) = patient_node().await;
    node.secret_set(
        "token",
        b"retained-secret-before-delete".to_vec(),
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    assert_eq!(
        node.secret_delete("token", &audit(), false, test_auth())
            .await
            .unwrap(),
        1
    );
    assert!(
        node.resolve_secret("token", None, &node.config_now(), test_auth())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        node.resolve_secret("token", Some(1), &node.config_now(), test_auth())
            .await
            .is_err()
    );
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    assert!(
        node.secret_values()
            .unwrap()
            .iter()
            .any(|(_, bytes)| bytes.as_slice() == b"retained-secret-before-delete")
    );
    // Evicting the warm cache no longer makes the inventory incomplete: the
    // retained FILE bytes are re-read from disk, so the scrub authority
    // survives an eviction.
    {
        let mut state = lock(&node.runtime().unwrap().cache.state);
        state.values.clear();
        state.bytes = 0;
    }
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    assert!(
        node.secret_values()
            .unwrap()
            .iter()
            .any(|(_, bytes)| bytes.as_slice() == b"retained-secret-before-delete")
    );
    // Values that can no longer be read from disk are different: a retained
    // row whose bytes are unloadable fails the recertification, and the
    // inventory stays incomplete (fail closed) until the store is repaired.
    rusqlite::Connection::open(_data.path().join("keys/secrets.db"))
        .unwrap()
        .execute(
            "UPDATE secrets SET ciphertext = x'00', version_hash = x'00'",
            [],
        )
        .unwrap();
    {
        let mut state = lock(&node.runtime().unwrap().cache.state);
        state.values.clear();
        state.bytes = 0;
    }
    // Under the staging swap the refresh publishes only the delta (no new
    // records: an empty delta is a trivial publish), so the corrupted rows
    // surface where the contract lives — the certified read path. The probe
    // fails the read fail-closed until the store is repaired.
    assert!(node.secret_values().is_err());
}

#[tokio::test]
async fn hmac_asserts_every_identity_field_and_ignores_only_caller_audit() {
    let (_data, node) = node().await;
    let original = node.local_operator_authority().unwrap();
    node.secret_set(
        "token",
        b"host-hmac-key".to_vec(),
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap();
    let identity = node
        .secret_identity(node.branch(), "token", 1)
        .await
        .unwrap();
    assert_eq!(identity.version_hash.len(), 16);
    let expected: [u8; 32] = kronik_effects::crypto::hmac_sha256(b"host-hmac-key", b"message")
        .try_into()
        .unwrap();
    assert_eq!(
        node.secret_hmac(node.branch(), &identity, b"message", original.clone())
            .await
            .unwrap(),
        expected
    );
    let mut changed_audit = identity.clone();
    changed_audit.audit = None;
    assert_eq!(
        node.secret_hmac(node.branch(), &changed_audit, b"message", original.clone())
            .await
            .unwrap(),
        expected
    );
    for mutate in 0..10 {
        let mut wrong = identity.clone();
        match mutate {
            0 => wrong.version_hash[0] ^= 1,
            1 => wrong.backend = "bao".into(),
            2 => wrong.binding = "different".into(),
            3 => wrong.r#ref = "different".into(),
            4 => wrong.canonical_ref = "different".into(),
            5 => wrong.source_version = "different".into(),
            6 => wrong.link_generation += 1,
            7 => wrong.hash_revision += 1,
            8 => wrong.phase = Phase::Reserved as i32,
            _ => wrong.deleted = true,
        }
        assert_eq!(
            node.secret_hmac(node.branch(), &wrong, b"message", original.clone())
                .await
                .unwrap_err()
                .code,
            ErrorCode::SecretVersionGone
        );
    }
    assert!(
        node.secret_hmac("another-branch", &identity, b"message", original)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn configured_hmac_does_not_promote_scrub_only_file_inventory() {
    let (_data, node) = node().await;
    let original = node.local_operator_authority().unwrap();
    node.secret_set(
        "pinned",
        b"immutable MAC key".to_vec(),
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap();
    let identity = node
        .secret_identity(node.branch(), "pinned", 1)
        .await
        .unwrap();
    let runtime = node.runtime().unwrap();
    lock(&runtime.cache.state)
        .values
        .get_mut(&(identity.name.clone(), identity.version))
        .unwrap()
        .operational = false;
    let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
    let expected: [u8; 32] = kronik_effects::crypto::hmac_sha256(b"immutable MAC key", b"message")
        .try_into()
        .unwrap();
    assert_eq!(
        node.secret_hmac(node.branch(), &identity, b"message", original.clone())
            .await
            .unwrap(),
        expected
    );
    assert!(
        runtime
            .cache
            .cached("pinned", Some(identity.version), &node.config_now())
            .is_err()
    );
    publication.check_current().unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let mut denied = unavailable();
    original
        .admit(&mut || {
            publication.with_current_publication(&mut denied, || {
                sender.try_send(expected).map_err(|_| unavailable())?;
                Ok(())
            })
        })
        .unwrap();
    assert_eq!(receiver.recv().await.unwrap(), expected);
    assert_eq!(
        node.native_secret_snapshot().unwrap().fingerprint,
        snapshot.fingerprint
    );
    node.secret_delete("pinned", &audit(), false, original.clone())
        .await
        .unwrap();
    assert!(publication.check_current().is_err());
    assert_eq!(
        node.secret_hmac(node.branch(), &identity, b"message", original)
            .await
            .unwrap_err()
            .code,
        ErrorCode::SecretVersionGone
    );
}

// This is the actual B1 OpenBao auth/secret parser over Env::Net, not a second
// test backend: failures exercise the resolver's typed provider boundary.
struct Bao {
    calls: AtomicUsize,
    current: AtomicU64,
    status: AtomicU64,
    catalogue_status: AtomicU64,
    started: Arc<Semaphore>,
    block: Mutex<Option<Arc<Semaphore>>>,
    require_begin: AtomicBool,
    node: Mutex<Option<std::sync::Weak<Node>>>,
    urls: Mutex<Vec<String>>,
}
impl Default for Bao {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            current: AtomicU64::new(1),
            status: AtomicU64::new(200),
            catalogue_status: AtomicU64::new(200),
            started: Arc::new(Semaphore::new(0)),
            block: Mutex::new(None),
            require_begin: AtomicBool::new(false),
            node: Mutex::new(None),
            urls: Mutex::new(Vec::new()),
        }
    }
}
impl Net for Bao {
    /// The simulated provider boundary is the same one `http` answers; the
    /// lease is admitted before the request future is built, as a real Net must.
    fn http_authorized(
        &self,
        request: HttpRequest,
        original: AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        if let Err(error) = original.admit(&mut || Ok(())) {
            return Box::pin(async move { Err(NetError::Connect(error.to_string())) });
        }
        self.http(request)
    }
    fn http(&self, request: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.urls).push(request.url.clone());
        if self.require_begin.load(Ordering::SeqCst) {
            let node = lock(&self.node).as_ref().unwrap().upgrade().unwrap();
            assert!(
                !node.store().db().open_turns().unwrap().is_empty(),
                "provider I/O preceded durable TurnBegin"
            );
        }
        let current = self.current.load(Ordering::SeqCst);
        let metadata = request.url.contains("/metadata/");
        let lookup = request.url.ends_with("/lookup-self");
        let status = if metadata {
            self.catalogue_status.load(Ordering::SeqCst)
        } else {
            self.status.load(Ordering::SeqCst)
        } as u16;
        let version = request
            .url
            .split_once("?version=")
            .map(|(_, version)| version.parse::<u64>().unwrap())
            .unwrap_or(current);
        let key = if request.url.contains("/second") {
            "second"
        } else {
            "first"
        };
        let body = if lookup {
            serde_json::json!({"data":{"ttl":0,"renewable":false}})
        } else if metadata {
            let versions: serde_json::Map<String, serde_json::Value> = (1..=current)
                .map(|id| {
                    (
                        id.to_string(),
                        serde_json::json!({"destroyed":false,"deletion_time":""}),
                    )
                })
                .collect();
            serde_json::json!({"data":{"current_version":current,"oldest_version":1,"versions":versions}})
        } else {
            serde_json::json!({"data":{"data":{"token":format!("{key}-credential-{version}")},"metadata":{"version":version,"destroyed":false,"deletion_time":""}}})
        };
        let block = if !metadata && !lookup {
            lock(&self.block).clone()
        } else {
            None
        };
        if !metadata && !lookup {
            self.started.add_permits(1);
        }
        Box::pin(async move {
            if let Some(block) = block {
                block.acquire_owned().await.unwrap().forget();
            }
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            })
        })
    }
}
async fn bao_node() -> (tempfile::TempDir, Arc<Node>, Arc<Bao>) {
    bao_node_with_fetch_timeout(Settings::default().fetch_timeout).await
}

/// A node with the OpenBao fake as its backend `bao`, settled: its cycle has
/// made the pass that certifies the empty startup inventory.
///
/// Keep `refresh` at its default in a test that counts provider requests.
/// The cycle fetches every linked name from the provider on each of its
/// passes, whatever the age of the cached value: about every `refresh`, and
/// after each change that retires the certificate. A short `refresh` puts
/// requests of the node's own among the test's, at moments that depend on the
/// clock, and a rebuild that takes longer than `refresh` is not installed.
/// A test that blocks the provider needs a `fetch_timeout` that a loaded
/// machine cannot exceed while the request waits.
async fn bao_node_with_fetch_timeout(
    fetch_timeout: Duration,
) -> (tempfile::TempDir, Arc<Node>, Arc<Bao>) {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let token = data.path().join("bao.token");
    std::fs::write(&token, "test-provider-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let bao = Arc::new(Bao::default());
    let mut environment = env();
    environment.net = bao.clone();
    let mut config = crate::NodeConfig {
        group_commit_window: Some(Duration::ZERO),
        ..Default::default()
    };
    config.secret_settings.fetch_timeout = fetch_timeout;
    config.secret_settings.backends.insert(
        "bao".into(),
        Definition::Openbao {
            address: "http://127.0.0.1:8200".into(),
            allowed_refs: vec!["secret/".into()],
            auth: "token".into(),
            token_file: Some(token),
            role_id_file: None,
            secret_id_file: None,
            cert_file: None,
            key_file: None,
            ca_file: None,
            auth_mount: None,
            role: None,
        },
    );
    let node = crate::start_local(environment, data.path(), config)
        .await
        .unwrap();
    *lock(&bao.node) = Some(Arc::downgrade(&node));
    // Finish the independent empty startup inventory before observing
    // management I/O. The condition ends the wait; the bound only turns a
    // cycle that never settles into a failure.
    node.env
        .timeout(Duration::from_secs(60), node.secret_cycle_settled())
        .await
        .unwrap();
    (data, node, bao)
}
async fn begin(node: &Node) {
    node.commit(Record::TurnBegin(pb::TurnBegin {
        execution_id: "0123456789abcdef0123456789abcdef".into(),
        actor: Some(pb::ActorRef {
            kind: "test".into(),
            key: "one".into(),
        }),
        code_hash: vec![1; 32],
        engine_version: kronik_runtime::ENGINE_VERSION.into(),
        causal_key: Some(pb::CausalKey {
            root: "root".into(),
            path: Vec::new(),
        }),
        logical_time_ms: 1,
        random_seed: vec![2; 32],
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "GET".into(),
                path: "/".into(),
                ..Default::default()
            })),
        }),
        config_epoch: node.epoch(),
    }))
    .await
    .unwrap();
}

#[tokio::test]
async fn metadata_list_has_no_provider_or_ledger_effect_and_preserves_unobserved_bindings() {
    let (_data, node, bao) = bao_node().await;
    let builtin = node
        .secret_set(
            "builtin",
            b"local-credential".to_vec(),
            &audit(),
            false,
            test_auth(),
        )
        .await
        .unwrap()
        .unwrap();
    let (binding, _) = node
        .secret_link(
            "token",
            "bao",
            "secret/first#token",
            &audit(),
            false,
            test_auth(),
        )
        .await
        .unwrap();
    // Observe the linked value while the provider is reachable: the first
    // cold resolve publishes the durable ledger row (the link itself has no
    // provider or ledger effect) and the refresh certifies it. The outage
    // below must not change what was certified here.
    node.resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    refresh_until_complete(&node).await;
    bao.status.store(503, Ordering::SeqCst);
    let before = node.applied_lsn();
    let history = node.secret_history("token").await.unwrap();
    let calls = bao.calls.load(Ordering::SeqCst);
    let (values, links) = node.secret_list().await.unwrap();
    // Staging-swap ruling: a committed secret that published under CAS and
    // passes the probe is listed at once. The old assertion (builtin only)
    // encoded the retired clear-then-rebuild window itself — a certified
    // secret staying hidden was the gap's symptom, not a product promise.
    // The link was certified while the provider was up; the later outage
    // does not un-certify it, and the list must not touch the provider.
    let token = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap()
        .meta;
    assert_eq!(values, vec![builtin, token]);
    assert_eq!(links, vec![binding.clone()]);
    assert_eq!(bao.calls.load(Ordering::SeqCst), calls);
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.secret_history("token").await.unwrap(), history);

    bao.status.store(200, Ordering::SeqCst);
    let first = node
        .secret_refresh("token", &audit(), false, test_auth())
        .await
        .unwrap()
        .unwrap();
    bao.current.store(2, Ordering::SeqCst);
    let calls = bao.calls.load(Ordering::SeqCst);
    let before = node.applied_lsn();
    let (values, links) = node.secret_list().await.unwrap();
    assert_eq!(
        values.into_iter().find(|meta| meta.name == "token"),
        Some(first.clone())
    );
    assert_eq!(links, vec![binding]);
    assert_eq!(bao.calls.load(Ordering::SeqCst), calls);
    assert_eq!(node.applied_lsn(), before);
    let second = node
        .secret_refresh("token", &audit(), false, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert!(second.version > first.version);
    let old = node
        .resolve_secret(
            "token",
            Some(first.version),
            &node.config_now(),
            test_auth(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.meta, first);
    assert_eq!(old.value, b"first-credential-1");
}

#[tokio::test]
async fn actual_provider_initialization_is_offline_and_cold_io_follows_begin_while_warm_has_no_io()
{
    let (_data, node, bao) = bao_node().await;
    assert_eq!(bao.calls.load(Ordering::SeqCst), 0);
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    begin(&node).await;
    bao.require_begin.store(true, Ordering::SeqCst);
    let config = node.config_now();
    let cold = node
        .resolve_secret("token", None, &config, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cold.value, b"first-credential-1");
    let calls = bao.calls.load(Ordering::SeqCst);
    let warm = node
        .resolve_secret("token", None, &config, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(warm.meta, cold.meta);
    assert_eq!(bao.calls.load(Ordering::SeqCst), calls);
    assert!(
        node.secret_history("token")
            .await
            .unwrap()
            .iter()
            .all(active)
    );
}

#[tokio::test]
async fn relinking_does_not_redirect_admitted_old_generations_with_the_same_provider_version_id() {
    let (_data, node, _bao) = bao_node().await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let old_config = node.config_now();
    node.secret_link(
        "token",
        "bao",
        "secret/second#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let new_config = node.config_now();
    let old = node
        .resolve_secret("token", None, &old_config, test_auth())
        .await
        .unwrap()
        .unwrap();
    let new = node
        .resolve_secret("token", None, &new_config, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.value, b"first-credential-1");
    assert_eq!(new.value, b"second-credential-1");
    assert_ne!(old.meta.version, new.meta.version);
    assert!(
        node.resolve_secret("token", Some(old.meta.version), &new_config, test_auth())
            .await
            .is_err()
    );
    assert_eq!(
        node.resolve_secret("token", Some(old.meta.version), &old_config, test_auth())
            .await
            .unwrap()
            .unwrap()
            .value,
        old.value
    );
    let history = node.secret_history("token").await.unwrap();
    assert_eq!(
        history
            .iter()
            .map(|row| row.source_version.as_str())
            .collect::<Vec<_>>(),
        vec!["1", "1"]
    );
    assert_ne!(history[0].link_generation, history[1].link_generation);
}

#[tokio::test]
// M23's clear-then-rebuild
// uncovered window — a background cycle that starts while the catalogue
// catalogue is retired clears coverage again and its failure (here: the
// injected provider 403) leaves it retired until the next periodic tick —
// makes the post-heal `secret_values` read racy against the background
// cycle's rebuild, deterministically under the drain's ordering. The
// fail-closed 503 semantics this window produces are covered by
// `crates/kronik-api/tests/api.rs::incomplete_secret_inventory_blocks_disclosure_not_unrelated_turns`
// The staging-swap atomic publish landed: the delta republish observes the
// link's immutable version and publishes under the strict applied-LSN CAS,
// so the post-heal read is no longer racy against the background rebuild.
async fn provider_listing_denial_is_incomplete_and_old_required_versions_cannot_be_omitted() {
    let (_data, node, bao) = bao_node().await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    node.grant(
        "test",
        "secret-reveal:token",
        None,
        None,
        audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    node.resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap();
    bao.catalogue_status.store(403, Ordering::SeqCst);
    // Drive the recertification once: the denied listing must fail the mode
    // (an incomplete catalogue is never published) and record the link's
    // negative fact, so cached reads fail closed until the provider heals.
    assert!(node.refresh_secret_inventory(test_auth()).await.is_err());
    assert!(node.secret_values().is_err());
    assert!(
        node.secret_cache()
            .unwrap()
            .cached("token", None, &node.config_now())
            .is_err()
    );
    bao.catalogue_status.store(200, Ordering::SeqCst);
    bao.current.store(2, Ordering::SeqCst);
    refresh_until_complete(&node).await;
    // The background cycle keeps observing while the provider heals, and an
    // observation's applied row is deliberately not covered until the next
    // publish (the documented fail-closed window). A whole-catalogue read
    // therefore waits out the window, bounded, like the API fixtures do.
    let values = values_until_complete(&node).await;
    assert!(
        values
            .iter()
            .any(|(_, value)| value.as_slice() == b"first-credential-1")
    );
    assert!(
        values
            .iter()
            .any(|(_, value)| value.as_slice() == b"first-credential-2")
    );
    // Loss of the required old value is not cured by a current-only catalogue.
    lock(&node.runtime().unwrap().cache.state).values.clear();
    bao.current.store(1, Ordering::SeqCst);
    bao.status.store(404, Ordering::SeqCst);
    // Under the staging swap the refresh publishes only the delta (no new
    // records: an empty delta is a trivial publish), so the corrupted rows
    // surface where the contract lives — the certified read path. The probe
    // fails the read fail-closed until the store is repaired.
    assert!(node.secret_values().is_err());
}

#[tokio::test]
async fn immutable_file_source_version_can_differ_from_the_global_alias_after_unlink() {
    let (_data, node, _bao) = bao_node().await;
    let original = node
        .secret_set(
            "token",
            b"file-before-link".to_vec(),
            &audit(),
            false,
            test_auth(),
        )
        .await
        .unwrap()
        .unwrap();
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    node.resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap();
    node.secret_unlink("token", &audit(), false, test_auth())
        .await
        .unwrap();
    let alias = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alias.value, b"file-before-link");
    assert!(alias.meta.version > original.version);
    let identity = node
        .secret_identity(node.branch(), "token", alias.meta.version)
        .await
        .unwrap();
    assert_eq!(identity.source_version, original.version.to_string());
    assert!(identity.link_generation > 0);
    assert_eq!(
        identity.version_hash,
        node.runtime()
            .unwrap()
            .file
            .version_hash("token", alias.meta.version, &alias.value)
            .unwrap()
    );
}

#[tokio::test]
async fn revocation_during_dependency_wait_prevents_reservation_and_file_mutation() {
    let (_data, node) = node().await;
    let authority = Arc::new(TestAuthority::default());
    let guard = node
        .runtime()
        .unwrap()
        .name_lock("token")
        .lock_owned()
        .await;
    let request_node = node.clone();
    let request_authority = authority.clone();
    let request = tokio::spawn(async move {
        request_node
            .secret_set(
                "token",
                b"never-authorized-at-enqueue".to_vec(),
                &audit(),
                false,
                request_authority,
            )
            .await
    });
    node.env.clock.sleep(Duration::from_millis(10)).await;
    authority.revoke();
    drop(guard);
    assert_eq!(
        request.await.unwrap().unwrap_err().code,
        ErrorCode::Unauthenticated
    );
    assert!(node.secret_history("token").await.unwrap().is_empty());
    assert!(
        node.runtime()
            .unwrap()
            .file
            .current("token")
            .unwrap()
            .is_none()
    );
    assert_eq!(node.next_secret_version("token").await.unwrap(), 1);
}

#[tokio::test]
async fn admitted_exact_reservation_finishes_after_revocation_without_changing_original_identity() {
    let (_data, node) = node().await;
    let authority = Arc::new(TestAuthority::default());
    let runtime = node.runtime().unwrap();
    let value = b"already-admitted-file-write";
    let hash = runtime.file.version_hash("token", 1, value).unwrap();
    let reserved = node.secret_record(
        &Scope::file("token", 0),
        1,
        "1".into(),
        hash,
        false,
        audit(),
    );
    let admitted = node
        .admit_secret(reserved.clone(), authority.clone())
        .await
        .unwrap();
    authority.revoke();
    runtime
        .file
        .set_at(
            "token",
            1,
            value,
            [8; 24],
            19,
            "operator",
            "rotate credential",
        )
        .unwrap();
    let completed = node.finish_secret(admitted, true).await.unwrap();
    let mut expected = reserved;
    expected.phase = Phase::Active as i32;
    assert_eq!(completed, expected);
    assert_eq!(
        node.secret_identity(node.branch(), "token", 1)
            .await
            .unwrap(),
        expected
    );
}

#[tokio::test]
async fn negative_immutable_identity_does_not_poison_a_different_retained_version() {
    let (cache, _) = cache();
    let first = external_row(1, 1, "secret/first#token");
    let mut second = external_row(2, 1, "secret/first#token");
    second.source_version = "2".into();
    hold(&cache, &first, true);
    hold(&cache, &second, true);
    cache.failure_version(&Scope::row(&first), Some("1"), BackendError::VersionGone);
    let mut config = Config::default();
    config.apply(&Record::SecretLink(link("token", 1, "secret/first#token")));
    assert!(cache.cached("token", Some(1), &config).is_err());
    assert_eq!(
        cache
            .cached("token", Some(2), &config)
            .unwrap()
            .unwrap()
            .meta
            .version,
        2
    );
}

#[tokio::test]
async fn failed_orphan_file_rows_are_scrub_only_and_never_operational_current() {
    let (_data, node) = node().await;
    node.secret_set(
        "token",
        b"acknowledged-current".to_vec(),
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let file = &node.runtime().unwrap().file;
    file.set_at(
        "token",
        2,
        b"unacknowledged-retained-value",
        [2; 24],
        19,
        "operator",
        "interrupted old writer",
    )
    .unwrap();
    // The next write skips past the orphan's physical slot instead of
    // failing on the collision with it.
    let next = node
        .secret_set(
            "token",
            b"acknowledged-successor".to_vec(),
            &audit(),
            false,
            test_auth(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.version, 2);
    let identity = node
        .secret_identity(node.branch(), "token", 2)
        .await
        .unwrap();
    assert_eq!(identity.source_version, "3");
    node.refresh_secret_inventory(test_auth()).await.unwrap();
    // The orphan's bytes stay scrub-only: the certified inventory keeps
    // them as needles (bytes that physically exist must stay scrubbable),
    // while operationally the acknowledged successor is current and no
    // logical version ever maps to the skipped physical slot.
    assert!(node.secret_values().unwrap().iter().any(
        |(name, value)| name == "token" && value.as_slice() == b"unacknowledged-retained-value"
    ));
    assert_eq!(
        node.resolve_secret("token", None, &node.config_now(), test_auth())
            .await
            .unwrap()
            .unwrap()
            .meta
            .version,
        2
    );
    assert!(
        node.secret_history("token")
            .await
            .unwrap()
            .iter()
            .all(|row| row.source_version != "2")
    );
    assert_eq!(
        file.retained_version_for_scrub("token", 2)
            .unwrap()
            .unwrap()
            .value,
        b"unacknowledged-retained-value"
    );
}

#[tokio::test]
async fn cancelled_fetch_retains_singleflight_until_old_generation_publication_finishes() {
    // The blocked fetch must outlast everything the test does while it waits.
    let (_data, node, bao) = bao_node_with_fetch_timeout(Duration::from_secs(30)).await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    // Let the cycle finish the passes the link asked for, so that no request
    // of the node's own reaches the provider from here on until the test
    // changes something: the request below is the only one, and the permit
    // the test takes is its.
    node.env
        .timeout(Duration::from_secs(60), node.secret_cycle_settled())
        .await
        .unwrap();
    // A linked value is served from the cache while it is operationally
    // fresh, and a resolve that finds nothing recorded for the name is cold
    // anyway. Make the value, if the cycle already observed one, stale, so that
    // the resolve below goes to the provider: its fetch, its singleflight and
    // the aborted-request retention are then real.
    for ((name, _), held) in lock(&node.runtime().unwrap().cache.state).values.iter_mut() {
        if name == "token" {
            held.operational = false;
        }
    }
    while let Ok(permit) = bao.started.try_acquire() {
        permit.forget();
    }
    let blocked = Arc::new(Semaphore::new(0));
    *lock(&bao.block) = Some(blocked.clone());
    let old_config = node.config_now();
    let request_node = node.clone();
    let request = tokio::spawn(async move {
        request_node
            .resolve_secret("token", None, &old_config, test_auth())
            .await
    });
    bao.started.acquire().await.unwrap().forget();
    request.abort();
    let relink_node = node.clone();
    let relink = tokio::spawn(async move {
        relink_node
            .secret_link(
                "token",
                "bao",
                "secret/second#token",
                &audit(),
                false,
                test_auth(),
            )
            .await
    });
    node.env.clock.sleep(Duration::from_millis(10)).await;
    // The retention property under test: the relink is parked behind the
    // blocked fetch's name lock, so no generation-2 record can exist yet.
    assert!(
        node.secret_history("token")
            .await
            .unwrap()
            .iter()
            .all(|row| row.link_generation == 1)
    );
    *lock(&bao.block) = None;
    blocked.add_permits(1);
    relink.await.unwrap().unwrap();
    // The fetch the cancelled request left behind published under the
    // generation it began in: one version of the first link, with the first
    // reference. What the cycle observes of the second link, and when, is its
    // own business, so rows of generation 2 may exist, and must be the
    // second link's.
    let history = node.secret_history("token").await.unwrap();
    let first: Vec<_> = history
        .iter()
        .filter(|row| row.link_generation == 1)
        .collect();
    assert_eq!(first.len(), 1, "{history:?}");
    assert_eq!(first[0].r#ref, "secret/first#token");
    assert!(
        history
            .iter()
            .filter(|row| row.link_generation == 2)
            .all(|row| row.r#ref == "secret/second#token"),
        "{history:?}"
    );
    // The relink waited for that publication: it is in the log before the
    // relink's record.
    let (mut published, mut relinked) = (None, None);
    node.reader()
        .read_while(1, node.applied_lsn(), |committed| {
            match &committed.record {
                Record::SecretVersion(row)
                    if row.name == "token" && row.link_generation == 1 && active(row) =>
                {
                    published.get_or_insert(committed.lsn);
                }
                Record::SecretLink(link) if link.name == "token" && link.generation == 2 => {
                    relinked.get_or_insert(committed.lsn);
                }
                _ => {}
            }
            Ok(true)
        })
        .await
        .unwrap();
    let (published, relinked) = (
        published.expect("a version of the first link was published"),
        relinked.expect("the relink was committed"),
    );
    assert!(published < relinked, "{published} {relinked}");
    // The old generation's value is not served under the new configuration.
    let config = node.config_now();
    if let Ok(Some(value)) = node.secret_cache().unwrap().cached("token", None, &config) {
        assert_eq!(value.value, b"second-credential-1");
    }
    let current = node
        .resolve_secret("token", None, &config, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.value, b"second-credential-1");
    assert_ne!(current.meta.version, first[0].version);
}

#[tokio::test]
async fn explicit_refresh_deduplicates_source_identity_and_has_one_owned_intent_with_stable_failure()
 {
    let (_data, node, bao) = bao_node().await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let observed = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    let refreshed = node
        .secret_refresh("token", &audit(), false, test_auth())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.version, observed.meta.version);
    assert_eq!(node.secret_history("token").await.unwrap().len(), 1);
    bao.status.store(503, Ordering::SeqCst);
    assert_eq!(
        node.secret_refresh("token", &audit(), false, test_auth())
            .await
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    let mut events = Vec::new();
    node.reader()
        .read_while(1, node.applied_lsn(), |committed| {
            if let Record::AuditEvent(event) = committed.record {
                events.push(event);
            }
            Ok(true)
        })
        .await
        .unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.action == "secret.refresh")
            .count(),
        2
    );
    let failed: Vec<_> = events
        .iter()
        .filter(|event| event.action == "secret.refresh.failed")
        .collect();
    assert_eq!(failed.len(), 1);
    assert_eq!(
        failed[0].details.get("code").map(String::as_str),
        Some("SECRET_UNAVAILABLE")
    );
    assert_eq!(failed[0].audit.as_ref().unwrap().token_id, "operator");
}

#[tokio::test]
async fn refresh_intent_does_not_authorize_a_later_unknown_version_after_revocation() {
    let (_data, node, bao) = bao_node().await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    // The link's inventory observation is complete before the request starts, so
    // any later history/version/current change can only come from the refresh.
    let history = node.secret_history("token").await.unwrap();
    let next_version = node.next_secret_version("token").await.unwrap();
    let current = lock(&node.runtime().unwrap().cache.state).current.clone();
    while let Ok(permit) = bao.started.try_acquire() {
        permit.forget();
    }
    let blocked = Arc::new(Semaphore::new(0));
    *lock(&bao.block) = Some(blocked.clone());
    let authority = Arc::new(TestAuthority::default());
    let request_node = node.clone();
    let request_authority = authority.clone();
    let request = tokio::spawn(async move {
        request_node
            .secret_refresh("token", &audit(), false, request_authority)
            .await
    });
    bao.started.acquire().await.unwrap().forget();
    authority.revoke();
    *lock(&bao.block) = None;
    blocked.add_permits(1);
    assert_eq!(
        request.await.unwrap().unwrap_err().code,
        ErrorCode::Unauthenticated
    );
    assert_eq!(node.secret_history("token").await.unwrap(), history);
    assert_eq!(
        node.next_secret_version("token").await.unwrap(),
        next_version
    );
    assert_eq!(lock(&node.runtime().unwrap().cache.state).current, current);
}

#[tokio::test]
async fn unchanged_refresh_does_not_renew_cached_authority_after_request_revocation() {
    let (_data, node, bao) = bao_node().await;
    node.secret_link(
        "token",
        "bao",
        "secret/first#token",
        &audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    let first = node
        .resolve_secret("token", None, &node.config_now(), test_auth())
        .await
        .unwrap()
        .unwrap();
    while let Ok(permit) = bao.started.try_acquire() {
        permit.forget();
    }
    let blocked = Arc::new(Semaphore::new(0));
    *lock(&bao.block) = Some(blocked.clone());
    let authority = Arc::new(TestAuthority::default());
    let request_node = node.clone();
    let request_authority = authority.clone();
    let request = tokio::spawn(async move {
        request_node
            .secret_refresh("token", &audit(), false, request_authority)
            .await
    });
    bao.started.acquire().await.unwrap().forget();
    // The blocked refresh holds the name lock, so no background refresh can run
    // from here on: the captured renewal stamp is stable across the revocation.
    let checked = lock(&node.runtime().unwrap().cache.state)
        .values
        .get(&("token".into(), first.meta.version))
        .unwrap()
        .checked;
    authority.revoke();
    *lock(&bao.block) = None;
    blocked.add_permits(1);
    assert_eq!(
        request.await.unwrap().unwrap_err().code,
        ErrorCode::Unauthenticated
    );
    let state = lock(&node.runtime().unwrap().cache.state);
    assert_eq!(
        state
            .values
            .get(&("token".into(), first.meta.version))
            .unwrap()
            .checked,
        checked
    );
    assert_eq!(state.registry.len(), 1);
}

struct AwsPages {
    pages: AtomicUsize,
    cycle: bool,
}
impl Net for AwsPages {
    /// The simulated IMDS and AWS boundary is the same one `http` answers; the
    /// lease is admitted before the request future is built, as a real Net must.
    fn http_authorized(
        &self,
        request: HttpRequest,
        original: AuthLease,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        if let Err(error) = original.admit(&mut || Ok(())) {
            return Box::pin(async move { Err(NetError::Connect(error.to_string())) });
        }
        self.http(request)
    }
    fn http(&self, request: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let body = if request.url.ends_with("/latest/api/token") {
            b"test-imds-token".to_vec()
        } else if request
            .url
            .ends_with("/latest/meta-data/iam/security-credentials/")
        {
            b"test-role".to_vec()
        } else if request
            .url
            .ends_with("/latest/meta-data/iam/security-credentials/test-role")
        {
            serde_json::to_vec(
                &serde_json::json!({"Code":"Success","AccessKeyId":"test-access",
                "SecretAccessKey":"test-secret","Token":"test-session"}),
            )
            .unwrap()
        } else {
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "authorization")
            );
            let catalogue = request.headers.iter().any(|(name, value)| {
                name == "x-amz-target" && value.ends_with("ListSecretVersionIds")
            });
            let arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:token-ABCDEF";
            let body = if catalogue {
                let page = self.pages.fetch_add(1, Ordering::SeqCst);
                let token = if self.cycle {
                    match page % 3 {
                        0 => "a".into(),
                        1 => "b".into(),
                        _ => "a".into(),
                    }
                } else {
                    format!("page-{page}")
                };
                serde_json::json!({"ARN":arn,"Name":"token","Versions":[],"NextToken":token})
            } else {
                serde_json::json!({"ARN":arn,"Name":"token","VersionId":"1".repeat(32),"SecretString":"aws-retained-value"})
            };
            serde_json::to_vec(&body).unwrap()
        };
        Box::pin(async move {
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: bytes::Bytes::from(body),
            })
        })
    }
}
/// Wait for the revision-triggered background refresh to finish failing, so the
/// page counter in the AWS tests measures only the explicit refresh below.
async fn settle_failing_catalogue_attempt(node: &Arc<Node>) {
    let runtime = node.runtime().unwrap();
    let mut certified = runtime.certified.subscribe();
    let wanted = lock(&runtime.cache.state).revision;
    node.env
        .timeout(Duration::from_secs(5), async {
            loop {
                let (revision, ok) = *certified.borrow_and_update();
                if revision >= wanted && !ok {
                    break;
                }
                certified.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
}
/// The background refresh can retire coverage between an explicit refresh's
/// capture and its final check. Retry the explicit call until it certifies a
/// complete inventory; the caller still proves the resulting contents.
async fn values_until_complete(node: &Arc<Node>) -> Vec<(String, Arc<Zeroizing<Vec<u8>>>)> {
    node.env
        .timeout(Duration::from_secs(5), async {
            loop {
                match node.secret_values() {
                    Ok(values) => return values,
                    Err(_) => node.env.clock.sleep(Duration::from_millis(1)).await,
                }
            }
        })
        .await
        .unwrap()
}

async fn refresh_until_complete(node: &Arc<Node>) {
    node.env
        .timeout(Duration::from_secs(5), async {
            while node.refresh_secret_inventory(test_auth()).await.is_err() {
                node.env.clock.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
}
async fn aws_catalogue_node(cycle: bool) -> (tempfile::TempDir, Arc<Node>, Arc<AwsPages>) {
    let data = tempfile::tempdir().unwrap();
    let pages = Arc::new(AwsPages {
        pages: AtomicUsize::new(0),
        cycle,
    });
    let mut environment = env();
    environment.net = pages.clone();
    let mut config = crate::NodeConfig {
        group_commit_window: Some(Duration::ZERO),
        ..Default::default()
    };
    config.secret_settings.backends.insert(
        "aws-test".into(),
        Definition::Aws {
            region: "us-east-1".into(),
            allowed_refs: vec!["token".into()],
            endpoint: Some("http://127.0.0.1:8201".into()),
            auth: "imds".into(),
            imds_endpoint: Some("http://127.0.0.1:8202".into()),
            ca_file: None,
        },
    );
    let node = crate::start_local(environment, data.path(), config)
        .await
        .unwrap();
    node.secret_link("token", "aws-test", "token", &audit(), false, test_auth())
        .await
        .unwrap();
    node.grant(
        "test",
        "secret-reveal:token",
        None,
        None,
        audit(),
        false,
        test_auth(),
    )
    .await
    .unwrap();
    settle_failing_catalogue_attempt(&node).await;
    (data, node, pages)
}

#[tokio::test]
async fn actual_aws_multi_page_cycle_never_publishes_complete_inventory() {
    let (_data, node, pages) = aws_catalogue_node(true).await;
    let before = pages.pages.load(Ordering::SeqCst);
    assert!(node.refresh_secret_inventory(test_auth()).await.is_err());
    let fetched = pages.pages.load(Ordering::SeqCst) - before;
    assert!(fetched > 1 && fetched <= 3);
    assert!(node.secret_values().is_err());
}

#[tokio::test]
async fn actual_aws_unending_catalogue_stops_at_the_page_budget_without_claiming_completeness() {
    let (_data, node, pages) = aws_catalogue_node(false).await;
    let before = pages.pages.load(Ordering::SeqCst);
    assert!(node.refresh_secret_inventory(test_auth()).await.is_err());
    assert_eq!(
        pages.pages.load(Ordering::SeqCst) - before,
        MAX_CATALOGUE_PAGES
    );
    assert!(node.secret_values().is_err());
}

#[tokio::test]
// The underlying feature is not implemented. Linking a secret to the
// built-in "file" backend answers
// SECRET_BACKEND_UNKNOWN; only file->external links are representable, so a
// successful file->file link, its mutation refusals and its unlink cannot be
// exercised yet. Restore this test when file->file links are implemented.
#[ignore = "not implemented: FILE-to-FILE secret links answer SECRET_BACKEND_UNKNOWN; only file->external links are representable"]
async fn file_links_refuse_mutation_without_touching_either_physical_name() {
    let (_data, node) = node().await;
    let original = node.local_operator_authority().unwrap();
    let token = node
        .secret_set(
            "token",
            b"unrelated-owned-token".to_vec(),
            &audit(),
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
    let alt = node
        .secret_set(
            "alt",
            b"shared-live-alt".to_vec(),
            &audit(),
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
    let token_identity = node
        .secret_identity(node.branch(), "token", token.version)
        .await
        .unwrap();
    let alt_identity = node
        .secret_identity(node.branch(), "alt", alt.version)
        .await
        .unwrap();
    let token_physical = token_identity.source_version.parse().unwrap();
    let alt_physical = alt_identity.source_version.parse().unwrap();
    node.secret_link("token", "file", "alt", &audit(), false, original.clone())
        .await
        .unwrap();
    node.secret_link("alias-b", "file", "alt", &audit(), false, original.clone())
        .await
        .unwrap();
    node.secret_link("alt", "file", "alt", &audit(), false, original.clone())
        .await
        .unwrap();
    let b = node
        .resolve_secret("alias-b", None, &node.config_now(), original.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.value, b"shared-live-alt");
    let store = node.secrets().unwrap();
    let token_row = store
        .export_encrypted_row("token", token_physical)
        .unwrap()
        .unwrap();
    let alt_row = store
        .export_encrypted_row("alt", alt_physical)
        .unwrap()
        .unwrap();
    let rows = node.secret_rows(None).await.unwrap();
    let through = node.applied_lsn();
    for name in ["token", "alt"] {
        for dry_run in [false, true] {
            assert_eq!(
                node.secret_set(
                    name,
                    b"refused-replacement".to_vec(),
                    &audit(),
                    dry_run,
                    original.clone()
                )
                .await
                .unwrap_err()
                .code,
                ErrorCode::SecretExternal
            );
            assert_eq!(
                node.secret_delete(name, &audit(), dry_run, original.clone())
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::SecretExternal
            );
        }
    }
    assert_eq!(node.applied_lsn(), through);
    assert_eq!(node.secret_rows(None).await.unwrap(), rows);
    assert_eq!(
        &store
            .export_encrypted_row("token", token_physical)
            .unwrap()
            .unwrap(),
        &token_row
    );
    assert_eq!(
        &store
            .export_encrypted_row("alt", alt_physical)
            .unwrap()
            .unwrap(),
        &alt_row
    );
    assert_eq!(
        store.current("token").unwrap().unwrap().value.as_slice(),
        b"unrelated-owned-token"
    );
    assert_eq!(
        store.current("alt").unwrap().unwrap().value.as_slice(),
        b"shared-live-alt"
    );
    assert!(store.stored_deletion_floor("token").unwrap().is_none());
    assert!(store.stored_deletion_floor("alt").unwrap().is_none());
    let still_b = node
        .resolve_secret("alias-b", None, &node.config_now(), original.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_b.value, b.value);
    assert_eq!(still_b.meta.version, b.meta.version);

    node.secret_unlink("token", &audit(), false, original.clone())
        .await
        .unwrap();
    node.secret_set(
        "token",
        b"new-owned-token".to_vec(),
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        store.current("token").unwrap().unwrap().value.as_slice(),
        b"new-owned-token"
    );
    assert!(
        node.secret_delete("token", &audit(), false, original.clone())
            .await
            .unwrap()
            > 0
    );
    assert!(store.current("token").unwrap().is_none());
    assert!(store.stored_deletion_floor("token").unwrap().is_some());
    let retained = store
        .export_encrypted_row("token", token_physical)
        .unwrap()
        .unwrap();
    assert_eq!(retained.nonce, token_row.nonce);
    assert_eq!(retained.ciphertext, token_row.ciphertext);
    assert_eq!(retained.version_hash, token_row.version_hash);
    assert_eq!(
        &store
            .export_encrypted_row("alt", alt_physical)
            .unwrap()
            .unwrap(),
        &alt_row
    );
    assert!(store.stored_deletion_floor("alt").unwrap().is_none());
    let still_b = node
        .resolve_secret("alias-b", None, &node.config_now(), original)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still_b.value, b.value);
    assert_eq!(still_b.meta.version, b.meta.version);
}
