// Recovery fixtures race admitted work directly: the spawned tasks are
// the harness, not daemon paths.
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::Scope;
use super::*;
use crate::Ingress;
use kronik_core::env::{BoxFuture, Env, HttpRequest, HttpResponse, Net, NetError, Spawner};
use kronik_privacy::{SecretMeta, secret_backend::config::Definition};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
static TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}
fn audit() -> pb::Audit {
    super::super::system_audit(&env(), "recorded secret recovery fixture")
}
fn config() -> crate::NodeConfig {
    crate::NodeConfig {
        concurrency: 1,
        group_commit_window: Some(Duration::ZERO),
        ..Default::default()
    }
}
fn plain(bytes: Vec<u8>) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(bytes)),
    })
}
fn message(name: &str) -> pb::Message {
    pb::Message {
        name: name.into(),
        content_type: "text/plain".into(),
        body: plain(b"canonical compensation body".to_vec()),
        blobs: Vec::new(),
        retained_compensation_source: None,
    }
}
fn begin(node: &Node) -> pb::TurnBegin {
    pb::TurnBegin {
        execution_id: "0123456789abcdef0123456789abcdef".into(),
        actor: Some(pb::ActorRef {
            kind: "recover".into(),
            key: "blocked".into(),
        }),
        code_hash: vec![9; 32],
        engine_version: kronik_runtime::ENGINE_VERSION.into(),
        causal_key: Some(causal::root("recorded-root".into())),
        logical_time_ms: 29,
        random_seed: vec![6; 32],
        config_epoch: node.epoch(),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "GET".into(),
                path: "/original-input".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(plain(Vec::new()).unwrap())),
                }),
                ..Default::default()
            })),
        }),
    }
}
fn message_begin(node: &Node) -> pb::TurnBegin {
    let mut begin = begin(node);
    begin.input = Some(pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(message("recover")),
            message_id: "recorded-root".into(),
            sent_logical_time_ms: begin.logical_time_ms,
            ..Default::default()
        })),
    });
    begin
}
fn reveal(metadata: SecretMeta, ordinal: u32) -> pb::EffectRecord {
    let mut reference = pb::SecretRef {
        name: metadata.name.clone(),
        version_hash: metadata.version_hash,
        ..Default::default()
    };
    reference.set_resolved_version(metadata.version).unwrap();
    pb::EffectRecord {
        ordinal,
        kind: "secret.reveal".into(),
        status: pb::EffectStatus::Ok as i32,
        target: format!("secret-reveal:{}", metadata.name),
        fingerprint: vec![3; 32],
        grounding: pb::Grounding::Live as i32,
        request: plain(
            pb::RevealEffectRequest {
                secret: Some(reference),
            }
            .encode_to_vec(),
        ),
        ..Default::default()
    }
}
fn call(begin: &pb::TurnBegin, ordinal: u32, with_compensation: bool) -> pb::EffectRecord {
    let key = begin.causal_key.as_ref().unwrap();
    let to = ActorRef::parse("counter/callee").unwrap();
    let request = pb::CallEffectRequest {
        to: Some(to.to_pb()),
        msg: Some(message("increment")),
        compensate: with_compensation.then(|| message("increment")),
        message_id: causal::message_id(key, ordinal),
        fingerprint_version: 2,
    };
    pb::EffectRecord {
        ordinal,
        kind: "actor.call".into(),
        status: pb::EffectStatus::Ok as i32,
        target: format!("actor:{to}"),
        request: plain(request.encode_to_vec()),
        response: plain(
            pb::CallEffectResponse {
                reply: Some(message("recorded-reply")),
                turn_id: "main:7".into(),
            }
            .encode_to_vec(),
        ),
        fingerprint: vec![7; 32],
        grounding: pb::Grounding::Exact as i32,
        duration_us: 117,
        offset_us: 31,
        ..Default::default()
    }
}
async fn node() -> (tempfile::TempDir, Arc<Node>) {
    let data = tempfile::tempdir().unwrap();
    let node = crate::start_local(env(), data.path(), config())
        .await
        .unwrap();
    (data, node)
}
async fn install_file(node: &Node, value: &[u8]) -> SecretMeta {
    let runtime = node.runtime().unwrap();
    let version = node.next_secret_version("token").await.unwrap();
    let hash = runtime.file.version_hash("token", version, value).unwrap();
    let mut row = node.secret_record(
        &Scope::file("token", 0),
        version,
        version.to_string(),
        hash,
        false,
        audit(),
    );
    node.secret_publish(row.clone()).await.unwrap();
    let metadata = runtime
        .file
        .set_at("token", version, value, [5; 24], 29, "system", "fixture")
        .unwrap();
    row.phase = pb::secret_version::Phase::Active as i32;
    node.secret_publish(row).await.unwrap();
    metadata
}
async fn persist(node: &Node, begin: &pb::TurnBegin, effects: &[pb::EffectRecord]) -> Vec<u64> {
    node.commit(Record::TurnBegin(begin.clone())).await.unwrap();
    let mut positions = Vec::new();
    for effect in effects {
        positions.push(
            node.commit(Record::EffectResult(pb::EffectResult {
                execution_id: begin.execution_id.clone(),
                effect: Some(effect.clone()),
            }))
            .await
            .unwrap(),
        );
    }
    positions
}
async fn record(node: &Node, lsn: u64) -> Record {
    let mut result = None;
    node.reader()
        .read_while(lsn, lsn, |committed| {
            result = Some(committed.record);
            Ok(true)
        })
        .await
        .unwrap();
    result.unwrap()
}
/// Waits for the recovery under test to register its stall. The condition is
/// what ends the wait; the bound only turns a recovery that never stalls into
/// a failure, and is far above what a loaded machine needs.
async fn wait_stall(node: &Node) {
    node.env
        .timeout(Duration::from_secs(60), async {
            while *super::super::lock(&STALLED) == 0 {
                node.env.clock.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn matched_http_crypto_and_unsuccessful_reveals_never_resolve_a_value() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    node.runtime()
        .unwrap()
        .initialized
        .store(false, Ordering::Release);
    let effects = ["http.fetch", "crypto.hmac-sha256", "crypto.sign-ed25519"]
        .into_iter()
        .map(|kind| pb::EffectRecord {
            kind: kind.into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(b"not a secret request protobuf".to_vec()),
            ..Default::default()
        })
        .chain([pb::EffectRecord {
            kind: "secret.reveal".into(),
            status: pb::EffectStatus::Denied as i32,
            request: plain(b"not an admitted reveal".to_vec()),
            ..Default::default()
        }])
        .collect::<Vec<_>>();
    let before = node.applied_lsn();
    node.env
        .timeout(
            Duration::from_secs(1),
            node.prepare_recorded_secrets(
                &begin(&node),
                &effects,
                &node.config_now(),
                node.local_operator_authority().unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(*super::super::lock(&STALLED), 0);
}

#[tokio::test]
async fn recorded_hash_or_captured_epoch_mismatch_is_definitive_before_guest_execution() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let metadata = install_file(&node, b"immutable recorded value").await;
    let begin = begin(&node);
    let mut wrong = metadata.clone();
    wrong.version_hash[0] ^= 1;
    let bad_effect = reveal(wrong, 0);
    persist(&node, &begin, std::slice::from_ref(&bad_effect)).await;
    assert_eq!(
        node.prepare_recorded_secrets(
            &begin,
            &[bad_effect],
            &node.config_now(),
            node.local_operator_authority().unwrap()
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::SecretVersionGone
    );
    let mut different_epoch = (*node.config_now()).clone();
    different_epoch.epoch += 1;
    assert_eq!(
        node.prepare_recorded_secrets(
            &begin,
            &[reveal(metadata, 0)],
            &different_epoch,
            node.local_operator_authority().unwrap()
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::SecretVersionGone
    );
    assert_eq!(node.probe.turns_run.load(Ordering::Relaxed), 0);
    assert_eq!(*super::super::lock(&STALLED), 0);
}

struct Bao {
    status: AtomicUsize,
    gets: AtomicUsize,
    require_begin: AtomicBool,
    node: Mutex<Option<std::sync::Weak<Node>>>,
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
        if self.require_begin.load(Ordering::Acquire) {
            let node = self
                .node
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap();
            assert!(
                node.store()
                    .db()
                    .open_turns()
                    .unwrap()
                    .iter()
                    .any(|turn| turn.execution_id == "0123456789abcdef0123456789abcdef"),
                "recorded source I/O preceded its exact TurnBegin"
            );
            if request.url.contains("/data/") {
                assert!(
                    request.url.ends_with("?version=1"),
                    "recorded recovery fetched current instead of immutable version: {}",
                    request.url
                );
            }
        }
        let lookup = request.url.ends_with("/lookup-self");
        if !lookup {
            self.gets.fetch_add(1, Ordering::AcqRel);
        }
        let status = self.status.load(Ordering::Acquire) as u16;
        let body = if lookup {
            serde_json::json!({"data":{"ttl":0,"renewable":false}})
        } else if request.url.contains("/metadata/") {
            serde_json::json!({"data":{"current_version":1,"oldest_version":1,"versions":{"1":{"destroyed":false,"deletion_time":""}}}})
        } else {
            assert!(
                request.url.ends_with("/data/token")
                    || request.url.ends_with("/data/token?version=1")
            );
            serde_json::json!({"data":{"data":{"token":"immutable-provider-value"},"metadata":{"version":1,"destroyed":false,"deletion_time":""}}})
        };
        Box::pin(async move {
            Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            })
        })
    }
}
async fn provider(recovery_status: usize) -> (tempfile::TempDir, Arc<Node>, Arc<Bao>, SecretMeta) {
    use std::os::unix::fs::PermissionsExt;
    let data = tempfile::tempdir().unwrap();
    let token = data.path().join("provider.token");
    std::fs::write(&token, "fixture-bao-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let bao = Arc::new(Bao {
        status: AtomicUsize::new(200),
        gets: AtomicUsize::new(0),
        require_begin: AtomicBool::new(false),
        node: Mutex::new(None),
    });
    let mut environment = env();
    environment.net = bao.clone();
    let mut config = config();
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
    *bao.node.lock().unwrap() = Some(Arc::downgrade(&node));
    let runtime = node.runtime().unwrap();
    // Settle the startup inventory before the fixture takes over the name: the
    // background refresh must not race this link's single observation. The
    // condition ends the wait; the bound is far above a loaded machine's need.
    node.env
        .timeout(Duration::from_secs(60), async {
            while !runtime.cache.complete(node.epoch()) {
                node.env.clock.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    node.secret_link(
        "token",
        "bao",
        "secret/token#token",
        &audit(),
        false,
        original.clone(),
    )
    .await
    .unwrap();
    let observed = node
        .resolve_secret("token", None, &node.config_now(), original)
        .await
        .unwrap()
        .unwrap();
    let metadata = observed.meta;
    // Drain both operational warms and retained-inventory fetches before the outage.
    let _inventory = runtime.inventory.lock().await;
    let _name = runtime.name_lock("token").lock_owned().await;
    bao.status.store(recovery_status, Ordering::Release);
    {
        let mut state = runtime.cache.state.lock().unwrap();
        state.values.clear();
        state.bytes = 0;
    }
    drop(_name);
    drop(_inventory);
    (data, node, bao, metadata)
}

#[tokio::test]
async fn unavailable_recorded_reveal_waits_on_env_backoff_while_an_unrelated_actor_runs() {
    let _serial = TESTS.lock().await;
    let (_data, node, bao, metadata) = provider(503).await;
    node.deploy(
        &std::fs::read(COUNTER).unwrap(),
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    let begin = begin(&node);
    let effects = vec![reveal(metadata, 1)];
    persist(&node, &begin, &effects).await;
    bao.require_begin.store(true, Ordering::Release);
    let runner = node.clone();
    let captured = node.config_now();
    let original = begin.clone();
    let authority = node.local_operator_authority().unwrap();
    assert_eq!(captured.epoch, begin.config_epoch);
    let pending = tokio::spawn(async move {
        runner
            .prepare_recorded_secrets(&original, &effects, &captured, authority)
            .await
    });
    wait_stall(&node).await;
    let actor = ActorRef::parse("counter/free").unwrap();
    let input = pb::HttpInput {
        method: "POST".into(),
        path: "/counter/free/increment".into(),
        body: Some(pb::Body {
            value: Some(pb::body::Value::Inline(plain(Vec::new()).unwrap())),
        }),
        params: vec![
            pb::Param {
                name: "op".into(),
                value: "increment".into(),
                sealed_value: None,
            },
            pb::Param {
                name: "key".into(),
                value: "free".into(),
                sealed_value: None,
            },
        ],
        ..Default::default()
    };
    let outcome = node
        .env
        .timeout(Duration::from_secs(2), async {
            match node.ingress(actor, input, None).unwrap() {
                Ingress::Started(waiter) | Ingress::Joined(waiter) => waiter.wait().await.unwrap(),
                Ingress::Done(result) => *result,
            }
        })
        .await
        .unwrap();
    assert!(outcome.committed());
    assert_eq!(
        node.store()
            .db()
            .kv_get("counter", "free", "n")
            .unwrap()
            .unwrap(),
        b"1"
    );
    assert!(!pending.is_finished());
    bao.status.store(200, Ordering::Release);
    node.env
        .timeout(Duration::from_secs(12), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(*super::super::lock(&STALLED), 0);
}

#[tokio::test]
async fn definitive_gone_does_not_retry_and_cancellation_releases_the_owned_stall_gauge() {
    let _serial = TESTS.lock().await;
    let (_data, node, bao, metadata) = provider(404).await;
    let begin = begin(&node);
    let effects = vec![reveal(metadata.clone(), 1)];
    persist(&node, &begin, &effects).await;
    bao.require_begin.store(true, Ordering::Release);
    let before = bao.gets.load(Ordering::Acquire);
    assert_eq!(
        node.prepare_recorded_secrets(
            &begin,
            &effects,
            &node.config_now(),
            node.local_operator_authority().unwrap()
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::SecretVersionGone
    );
    // The staging swap's delta republish observes the link's immutable
    // version (replay-legal: ?version=1, never CURRENT) — exactly one extra
    // provider GET, as before the swap. The definitive-gone verdict still
    // comes from the recorded hash comparison.
    assert_eq!(bao.gets.load(Ordering::Acquire), before + 1);
    assert_eq!(*super::super::lock(&STALLED), 0);
    let runtime = node.runtime().unwrap();
    runtime
        .cache
        .clear_negative_version(&Scope::config("token", &node.config_now()), Some("1"));
    bao.status.store(503, Ordering::Release);
    let runner = node.clone();
    let captured = node.config_now();
    let original = begin.clone();
    let authority = node.local_operator_authority().unwrap();
    let pending = tokio::spawn(async move {
        runner
            .prepare_recorded_secrets(&original, &effects, &captured, authority)
            .await
    });
    wait_stall(&node).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(*super::super::lock(&STALLED), 0);
    assert_eq!(
        node.store().db().open_effects(&begin.execution_id).unwrap(),
        vec![reveal(metadata, 1)]
    );
}

#[tokio::test]
async fn terminal_failure_preserves_original_identity_and_effects_without_running_guest_code() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let metadata = install_file(&node, b"recorded value").await;
    let mut begin = message_begin(&node);
    begin.engine_version = "retired-engine-version".into();
    let effects = vec![reveal(metadata, 0)];
    let positions = persist(&node, &begin, &effects).await;
    let source_before = record(&node, positions[0]).await.encode();
    let result = node
        .fail_recorded_secret(begin.clone(), effects.clone(), ErrorCode::SecretVersionGone)
        .await
        .unwrap();
    let Record::TurnRecord(terminal) = record(&node, result.turn_id.lsn).await else {
        panic!("missing terminal record")
    };
    assert_eq!(terminal.execution_id, begin.execution_id);
    assert_eq!(terminal.code_hash, begin.code_hash);
    assert_eq!(terminal.engine_version, begin.engine_version);
    assert_eq!(terminal.random_seed, begin.random_seed);
    assert_eq!(terminal.logical_time_ms, begin.logical_time_ms);
    assert_eq!(terminal.config_epoch, begin.config_epoch);
    assert_eq!(terminal.input, begin.input);
    assert_eq!(terminal.effects, effects);
    assert!(
        terminal.writes.is_empty()
            && terminal.sql_changes.is_empty()
            && terminal.messages.is_empty()
    );
    assert_eq!(terminal.fuel_used, 0);
    assert_eq!(node.probe.turns_run.load(Ordering::Relaxed), 0);
    assert_eq!(record(&node, positions[0]).await.encode(), source_before);
    assert!(node.store().db().open_turns().unwrap().is_empty());
    assert_eq!(
        node.store()
            .db()
            .dead_letter(result.turn_id.lsn)
            .unwrap()
            .unwrap()
            .error_code,
        "SECRET_VERSION_GONE"
    );
}

#[tokio::test]
async fn transient_failure_cannot_be_committed_as_a_new_terminal_guest_outcome() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let begin = begin(&node);
    persist(&node, &begin, &[]).await;
    let before = node.applied_lsn();
    assert_eq!(
        node.fail_recorded_secret(begin, Vec::new(), ErrorCode::SecretUnavailable)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Internal
    );
    assert_eq!(node.applied_lsn(), before);
    assert_eq!(node.store().db().open_turns().unwrap().len(), 1);
}

#[tokio::test]
async fn unreadable_or_malformed_successful_call_never_silently_drops_compensation() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let begin = begin(&node);
    let mut effect = call(&begin, 2, true);
    effect.request = plain(b"invalid canonical call".to_vec());
    persist(&node, &begin, std::slice::from_ref(&effect)).await;
    let before = node.applied_lsn();
    assert_eq!(
        node.fail_recorded_secret(
            begin.clone(),
            vec![effect.clone()],
            ErrorCode::SecretVersionGone
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::StorageCorrupt
    );
    effect.request = Some(pb::Sealable {
        subject: Some("missing-subject".into()),
        value: Some(pb::sealable::Value::Sealed(pb::Sealed {
            key_version: 1,
            nonce: vec![1; 24],
            ciphertext: vec![1; 32],
        })),
    });
    assert_eq!(
        node.fail_recorded_secret(begin, vec![effect], ErrorCode::SecretVersionGone)
            .await
            .unwrap_err()
            .code,
        ErrorCode::SecretUnavailable
    );
    assert_eq!(node.applied_lsn(), before);
}

struct HoldActors {
    real: Arc<dyn Spawner>,
    held: Mutex<Vec<BoxFuture<'static, ()>>>,
}
impl Spawner for HoldActors {
    fn spawn(&self, name: &'static str, future: BoxFuture<'static, ()>) {
        if name == "actor" {
            self.held.lock().unwrap().push(future);
        } else {
            self.real.spawn(name, future);
        }
    }
    fn spawn_blocking(&self, name: &'static str, run: Box<dyn FnOnce() + Send + 'static>) {
        self.real.spawn_blocking(name, run);
    }
}

#[test]
fn terminal_compensation_is_durable_before_dispatch_and_survives_restart_exactly_once() {
    let data = tempfile::tempdir().unwrap();
    let terminal_lsn;
    {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        terminal_lsn = runtime.block_on(async {
            let mut environment = env();
            let held = Arc::new(HoldActors {
                real: environment.spawner.clone(),
                held: Mutex::new(Vec::new()),
            });
            environment.spawner = held.clone();
            let node = crate::start_local(environment, data.path(), config())
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
            let begin = message_begin(&node);
            let effect = call(&begin, 3, true);
            persist(&node, &begin, std::slice::from_ref(&effect)).await;
            let result = node
                .fail_recorded_secret(
                    begin.clone(),
                    vec![effect.clone()],
                    ErrorCode::SecretVersionGone,
                )
                .await
                .unwrap();
            let Record::TurnRecord(terminal) = record(&node, result.turn_id.lsn).await else {
                panic!("missing terminal")
            };
            let expected = compensation(
                &ActorRef::from_pb(begin.actor.as_ref().unwrap()),
                begin.causal_key.as_ref().unwrap(),
                3,
                &ActorRef::parse("counter/callee").unwrap(),
                message("increment"),
            );
            assert_eq!(terminal.effects, vec![effect]);
            assert_eq!(terminal.compensations, vec![expected.clone()]);
            let mailbox = node.store().db().mailbox().unwrap();
            assert_eq!(mailbox.len(), 1);
            assert_eq!(mailbox[0].message_id, expected.message_id);
            assert_eq!(node.probe.turns_run.load(Ordering::Relaxed), 0);
            assert_eq!(held.held.lock().unwrap().len(), 1);
            held.held.lock().unwrap().clear();
            result.turn_id.lsn
        });
    }
    for _ in 0..2 {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let node = crate::start_local(env(), data.path(), config())
                .await
                .unwrap();
            node.env
                .timeout(Duration::from_secs(5), async {
                    while node
                        .store()
                        .db()
                        .kv_get("counter", "callee", "n")
                        .unwrap()
                        .as_deref()
                        != Some(b"1")
                    {
                        node.env.clock.sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
            assert_eq!(
                node.store()
                    .db()
                    .kv_get("counter", "callee", "n")
                    .unwrap()
                    .unwrap(),
                b"1"
            );
            assert!(node.store().db().mailbox().unwrap().is_empty());
            assert!(
                node.store()
                    .db()
                    .dead_letter(terminal_lsn)
                    .unwrap()
                    .is_some()
            );
            let original = record(&node, terminal_lsn).await;
            let Record::TurnRecord(original) = original else {
                panic!("missing original terminal")
            };
            assert_eq!(original.outcome.unwrap().error_code, "SECRET_VERSION_GONE");
            assert_eq!(original.compensations.len(), 1);
        });
    }
}

#[tokio::test]
async fn current_privacy_seals_only_the_new_copy_without_rewriting_recorded_logical_outcomes() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let begin = begin(&node);
    let mut effect = call(&begin, 4, false);
    effect.request.as_mut().unwrap().subject = Some("person:1".into());
    effect.response.as_mut().unwrap().subject = Some("person:1".into());
    let positions = persist(&node, &begin, std::slice::from_ref(&effect)).await;
    let source = record(&node, positions[0]).await.encode();
    node.set_privacy_mode(
        pb::PrivacyState::On,
        audit(),
        false,
        node.local_operator_authority().unwrap(),
    )
    .await
    .unwrap();
    let result = node
        .fail_recorded_secret(begin, vec![effect.clone()], ErrorCode::SecretVersionGone)
        .await
        .unwrap();
    let Record::TurnRecord(terminal) = record(&node, result.turn_id.lsn).await else {
        panic!("missing terminal")
    };
    let copied = &terminal.effects[0];
    assert_eq!(copied.status, effect.status);
    assert_eq!(copied.fingerprint, effect.fingerprint);
    assert_eq!(
        node.sealer().open(copied.request.as_ref().unwrap()).bytes(),
        node.sealer().open(effect.request.as_ref().unwrap()).bytes()
    );
    assert_eq!(
        node.sealer()
            .open(copied.response.as_ref().unwrap())
            .bytes(),
        node.sealer()
            .open(effect.response.as_ref().unwrap())
            .bytes()
    );
    assert!(matches!(
        copied.request.as_ref().unwrap().value,
        Some(pb::sealable::Value::Sealed(_))
    ));
    assert_eq!(record(&node, positions[0]).await.encode(), source);
}

#[tokio::test]
async fn only_successful_calls_with_a_recorded_compensation_generate_a_message() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let begin = begin(&node);
    let successful = call(&begin, 2, false);
    let mut failed = call(&begin, 3, true);
    failed.status = pb::EffectStatus::Failed as i32;
    failed.request = plain(b"failed calls need no compensation decoding".to_vec());
    let effects = vec![successful, failed];
    persist(&node, &begin, &effects).await;
    let result = node
        .fail_recorded_secret(begin, effects.clone(), ErrorCode::SecretVersionGone)
        .await
        .unwrap();
    let Record::TurnRecord(terminal) = record(&node, result.turn_id.lsn).await else {
        panic!("missing terminal")
    };
    assert_eq!(terminal.effects, effects);
    assert!(terminal.compensations.is_empty());
    assert!(node.store().db().mailbox().unwrap().is_empty());
    assert_eq!(node.probe.turns_run.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn unavailable_recorded_reference_itself_waits_and_cancellation_drops_its_stall_owner() {
    let _serial = TESTS.lock().await;
    let (_data, node) = node().await;
    let begin = begin(&node);
    let effect = pb::EffectRecord {
        kind: "secret.reveal".into(),
        status: pb::EffectStatus::Ok as i32,
        target: "secret-reveal:token".into(),
        request: Some(pb::Sealable {
            subject: Some("missing".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: vec![2; 24],
                ciphertext: vec![3; 32],
            })),
        }),
        ..Default::default()
    };
    persist(&node, &begin, std::slice::from_ref(&effect)).await;
    let runner = node.clone();
    let captured = node.config_now();
    let authority = node.local_operator_authority().unwrap();
    let pending = tokio::spawn(async move {
        runner
            .prepare_recorded_secrets(&begin, &[effect], &captured, authority)
            .await
    });
    wait_stall(&node).await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(*super::super::lock(&STALLED), 0);
    assert_eq!(node.probe.turns_run.load(Ordering::Relaxed), 0);
}
