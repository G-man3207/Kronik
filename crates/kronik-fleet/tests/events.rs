#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::sync::Arc;

use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::ids::SourcePos;
use kronik_fleet::{events::{self, Identity, Position, ResumeCursor}, webhook::{self, Settings, SecretVersion, Webhook}};
use kronik_otel::{audit::{Keys, Mapper}, cursor::Cursors, follow::{Sink, Stream}};
use kronik_log::MetadataAuditRecord;
use kronik_privacy::sealer::Sealer;
use kronik_proto::{Record, log::v1 as pb};
use kronik_sched::{Node, NodeConfig, ShardReader,
    secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication}, start_local};
use serde_json::json;


struct RevokedAuthority;
impl kronik_core::authority::Authority for RevokedAuthority {
    fn check(&self) -> Result<(), kronik_core::error::ApiError> {
        Err(kronik_core::error::ApiError::new(kronik_core::error::ErrorCode::Unauthenticated, "revoked fixture"))
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> { Box::pin(async {}) }
    fn admit(&self, _effect: &mut dyn FnMut() -> Result<(), kronik_core::error::ApiError>)
        -> Result<(), kronik_core::error::ApiError> { self.check() }
}

fn identity() -> Identity { Identity { installation: "installation-1".into(), branch: "main".into() } }
fn native(lsn: u64) -> SourcePos { SourcePos::Actor { shard: None, lsn } }
// Unit projections declare the native "main" namespace; fsynced fixtures write
// that header. Live Node projections use the ActorSource from their held reader.
fn main_frame(lsn: u64) -> pb::ActorSource {
    pb::ActorSource { shard: None, lsn, branch: "main".into() }
}
fn mapper() -> Mapper {
    let master = kronik_privacy::MasterKey::from_bytes([7;32]).unwrap();
    let keyed = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
    Mapper { keys: Keys::Omit, sealer: Arc::new(Sealer::plain().with_pseudonyms(keyed)), branch: "main".into() }
}
fn audit() -> Option<pb::Audit> {
    Some(pb::Audit { token_id: "token:raw-name-PII-NEEDLE".into(),
        reason: "raw-reason-PII-NEEDLE rotate VALUE-NEEDLE".into(), wall_time_ms: 123 })
}

fn configured_stream(name: impl Into<Arc<str>>, cursors: &Arc<Cursors>, settings: &Settings) -> Arc<Stream> {
    let name = name.into();
    let cursor = cursors.get(name.as_ref()).map_or(0, |entry| entry.lsn);
    Stream::new(name, true, kronik_otel::http::scheme_host(&settings.url), cursor, cursors.clone())
}

async fn native_disclosure(node: &Arc<Node>, original: &AuthLease)
    -> (Arc<ShardReader>, Arc<CertifiedSecretSnapshot>, AuthLease)
{
    original.check().unwrap();
    let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
    let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
    let disclosure = kronik_otel::follow::RetainedDisclosure::native(
        reader.clone(), snapshot.clone(), publication, original.clone());
    disclosure.check().unwrap();
    (reader, snapshot, disclosure)
}

fn native_catalogue(node: &Node)
    -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication), kronik_core::error::ApiError>
{
    node.native_secret_snapshot_with_publication()
}

#[tokio::test]
async fn revoked_original_disclosure_creates_no_pending_manifest_or_transport() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(MetadataNetwork::default());
    env.net = network.clone();
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let stream = configured_stream("events-revoked-pending:actor-native", &cursors, &settings);
    let mac_calls = Arc::new(AtomicUsize::new(0));
    let counted = mac_calls.clone();
    let resolver: Arc<webhook::Resolver> = Arc::new(move |_, input, _original| {
        let counted = counted.clone();
        Box::pin(async move {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-revoked-before-pending").unwrap();
            mac.update(&input);
            Ok(mac.finalize().into_bytes().into())
        })
    });
    let mapper = Arc::new(Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: node.branch().into() });
    let mut sink = Webhook::open(node.clone(), mapper, identity(), None, stream.clone(),
        cursors.clone(), settings, resolver, execution.clone()).await.unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let page = reader.local_export_page(0, 1, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(page.records.iter().any(|(_, record)| matches!(record.record, Record::SecretVersion(_))));
    let before = cursors.get(stream.name.as_ref()).unwrap();
    let durable_before = std::fs::read(directory.path().join(Cursors::FILE)).unwrap();
    let batch = sink.prepare(&page.records, before.generation(), &reader, &snapshot, authorization.clone()).await.unwrap();
    assert_eq!(cursors.get(stream.name.as_ref()).unwrap(), before);
    node.stop_native_execution().unwrap();
    let denied = execution.check().unwrap_err();
    assert!(matches!(sink.deliver(&batch, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == denied.code.as_str()));
    assert_eq!(cursors.get(stream.name.as_ref()).unwrap(), before);
    assert_eq!(std::fs::read(directory.path().join(Cursors::FILE)).unwrap(), durable_before);
    assert!(before.state["pending"].is_null());
    assert_eq!(mac_calls.load(Ordering::SeqCst), 0);
    assert!(network.requests.lock().unwrap().is_empty());
}

/// Each fixture asserts its actual operation and meaningful projected fields.
fn fixtures() -> Vec<(Record, &'static str, &'static str, Option<u64>)> {
    vec![
        (Record::Deployment(pb::Deployment { epoch: 7, cause: pb::DeploymentCause::Promote as i32,
            proposal_id: "p-1".into(), audit: audit(), ..Default::default() }),
            "deployment", "promote", Some(7)),
        (Record::Grant(pb::Grant { epoch: 8, op: pb::GrantOp::Grant as i32, kind: "counter".into(),
            capability: "http:service".into(), audit: audit(), ..Default::default() }),
            "grant", "grant", Some(8)),
        (Record::Limits(pb::Limits { epoch: 9, kind: "counter".into(), fuel: Some(99), audit: audit(), ..Default::default() }),
            "limits", "limits", Some(9)),
        (Record::Policy(pb::Policy { epoch: 10,
            rules_toml: "[[rule]]\nname = \"approval-floor\"\nwhen = \"true\"\naction = \"deny\"\n".into(),
            audit: audit(), ..Default::default() }), "policy", "policy", Some(10)),
        (Record::Approval(pb::Approval { proposal_id: "p-1".into(), request: true, diff_hash: vec![0xab;32],
            verified_through_lsn: 20, command: "promote p-1".into(), audit: audit(), verified_identity: None }),
            "approval", "request_approval", None),
        (Record::Approval(pb::Approval { proposal_id: "p-1".into(), request: false, diff_hash: vec![0xab;32],
            verified_through_lsn: 20, command: "promote p-1".into(), audit: audit(), verified_identity: None }),
            "approval", "approve", None),
        (Record::PrivacyMode(pb::PrivacyMode { epoch: 11, mode: pb::PrivacyState::On as i32, audit: audit(), reseal_requested: false }),
            "privacy_mode", "privacy.mode", Some(11)),
        (Record::ForeignActor(pb::ForeignActor { epoch: 12, op: pb::ForeignOp::Add as i32,
            name: "payments".into(), image: "oci-layout:/private/path@sha256:1234".into(),
            port: 8080, isolation: pb::Isolation::Gvisor as i32, audit: audit(), ..Default::default() }),
            "foreign_actor", "foreign.add", Some(12)),
        (Record::Erasure(pb::Erasure { epoch: 13, subject: "subject-PII-NEEDLE".into(), key_version: 2, audit: audit() }),
            "erasure", "privacy.erase", Some(13)),
        (Record::EngineUpgrade(pb::EngineUpgrade { epoch: 14, from_engine_version: "0.5.0".into(),
            to_engine_version: "0.6.0".into(), audit: audit(), ..Default::default() }),
            "engine_upgrade", "engine.upgrade", Some(14)),
        (Record::SimulatorConfig(pb::SimulatorConfig { epoch: 15, target: "http:service".into(),
            neighbor: true, audit: audit(), ..Default::default() }),
            "simulator_config", "simulators.set", Some(15)),
        (Record::GuardTriggered(pb::GuardTriggered { watch_id: "watch-1".into(), guard: "error-rate".into(),
            action: pb::GuardAction::Rollback as i32, outcome: pb::GuardOutcome::RolledBack as i32,
            deployment_epoch: 7, rollback_epoch: 16, reason: "GUEST-TEXT-NEEDLE".into(), audit: audit(), ..Default::default() }),
            "guard_triggered", "watch.guard", None),
        (Record::StateRebase(pb::StateRebase { rebase_id: "rebase-1".into(),
            part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                base_lsn: 10, rolled_back_epoch: 7, turns: 3, first_turn_lsn: 11, last_turn_lsn: 13,
                deployment: Some(pb::Deployment { epoch: 17, cause: pb::DeploymentCause::Rollback as i32, ..Default::default() }),
                diff_hash: "b3:0011".into(), irreversible_effects: 2, audit: audit(), ..Default::default() })) }),
            "state_rebase", "rollback.rebase", Some(17)),
        (Record::AuditEvent(pb::AuditEvent { action: "proposal.create".into(), target: "p-1".into(),
            details: BTreeMap::from([("operator".into(), "raw-details-PII-NEEDLE".into())]), audit: audit(), ..Default::default() }),
            "audit_event", "proposal.create", None),
        (Record::TurnRecord(operator_turn()), "turn", "resend", None),
    ]
}

fn operator_turn() -> pb::TurnRecord {
    pb::TurnRecord { actor: Some(pb::ActorRef { kind: "counter".into(), key: "actor-PII-NEEDLE".into() }),
        logical_time_ms: 123,
        execution_id: "operator-root-execution".into(),
        causal_key: Some(pb::CausalKey { root: "operator-root".into(), ..Default::default() }),
        outcome: Some(pb::Outcome { kind: pb::OutcomeKind::Committed as i32, ..Default::default() }),
        input: Some(pb::Input { kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::DeadLetterResend as i32, resend_of: "main:12".into(), audit: audit(),
            msg: Some(pb::Message { name: "increment".into(), body: Some(pb::Sealable {
                subject: Some("subject-PII-NEEDLE".into()),
                value: Some(pb::sealable::Value::Plain(b"BODY-NEEDLE".to_vec())) }), ..Default::default() }),
            ..Default::default() })) }), ..Default::default() }
}

#[tokio::test]
async fn decoded_privacy_reseal_request_publishes_request_not_completion() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (committed_tx, mut committed_rx) = tokio::sync::mpsc::unbounded_channel();
    let (fatal_tx, _fatal_rx) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"),
        committed_tx, fatal_tx).await.unwrap();
    let mapper = mapper();
    let secrets = [
        ("public-mode", b"mode".as_slice()), ("public-state", b"on".as_slice()),
        ("public-request", b"reseal_requested".as_slice()), ("public-flag", b"true".as_slice()),
        ("public-epoch", b"7".as_slice()), ("private-value", b"VALUE-NEEDLE".as_slice()),
    ];
    let schema = events::schemas().unwrap();
    let variant = schema["$defs"]["metadata"]["allOf"].as_array().unwrap().iter()
        .find(|variant| variant["if"]["properties"]["kind"]["const"] == "privacy_mode").unwrap();
    let allowed = variant["then"]["properties"]["action"]["enum"].as_array().unwrap();
    for (wire, action) in [
        (b"\x08\x07\x10\x02".as_slice(), "privacy.mode"),
        (b"\x08\x07\x10\x02\x20\x01".as_slice(), "privacy.reseal.request"),
    ] {
        let mut record = Record::decode(9, wire).unwrap();
        assert_eq!(record.encode(), wire);
        let Record::PrivacyMode(mode) = &mut record else { unreachable!() };
        mode.audit = audit();
        let lsn = log.append(record).await.unwrap();
        let committed = committed_rx.recv().await.unwrap();
        assert_eq!(committed.lsn, lsn);
        let event = events::project(&mapper, &identity(), &main_frame(lsn), &committed.record, &secrets)
            .unwrap().remove(0);
        assert_eq!((event.record_kind, event.data.kind.as_str()), (9, "privacy_mode"));
        assert_eq!(event.data.action, action);
        assert_ne!(event.data.action, "privacy.reseal");
        assert_eq!(event.data.epoch, Some(7));
        assert_eq!(event.data.at_wall_ms, 123);
        assert!(allowed.contains(&json!(event.data.action)));
    }
}

#[tokio::test]
async fn every_operational_fixture_has_meaningful_versioned_committed_content() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (committed_tx, mut committed_rx) = tokio::sync::mpsc::unbounded_channel();
    let (fatal_tx, _fatal_rx) = tokio::sync::oneshot::channel();
    let (log, _opened) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"),
        committed_tx, fatal_tx).await.unwrap();
    let mapper = mapper();
    let secrets = [("webhook-key", b"VALUE-NEEDLE".as_slice())];
    let schema = events::schemas().unwrap();
    assert_eq!(schema["properties"]["schema"]["const"], events::SCHEMA);
    for (index, (record, kind, action, epoch)) in fixtures().into_iter().enumerate() {
        let decoded = Record::decode(record.kind(), &record.encode()).unwrap();
        let lsn = log.append(decoded).await.unwrap();
        assert_eq!(lsn, index as u64 + 1);
        let committed = committed_rx.recv().await.unwrap();
        assert_eq!(committed.lsn, lsn);
        let projected = events::project(&mapper, &identity(), &main_frame(lsn), &committed.record, &secrets).unwrap();
        let event = projected.iter().find(|event| event.data.action == action).unwrap();
        assert_eq!(event.data.kind, kind);
        assert_eq!(event.data.epoch, epoch, "{kind}/{action}");
        assert_eq!(event.record_kind, record.kind());
        assert_eq!(event.source, native(lsn));
        assert_eq!(event.data.at_wall_ms, 123);
        assert!(event.data.record_hash.starts_with("b3k:v3:"));
        assert_eq!(event.schema, "kronik.event/v1");
        assert_eq!(event.id, events::event_id(&identity(), native(lsn), Some("main"), event.subindex, &event.data.record_hash).unwrap());
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        for needle in ["VALUE-NEEDLE", "BODY-NEEDLE", "subject-PII-NEEDLE", "actor-PII-NEEDLE", "GUEST-TEXT-NEEDLE",
            "/private/path", "raw-name-PII-NEEDLE", "raw-reason-PII-NEEDLE", "raw-details-PII-NEEDLE"] {
            assert!(!body.contains(needle), "{kind} leaked {needle}");
        }
        assert_eq!(serde_json::from_str::<events::Event>(&body).unwrap(), *event);
        let constraints = schema["allOf"].as_array().unwrap().iter().find(|constraint|
            constraint["if"]["properties"]["record_kind"]["const"] == json!(record.kind())).unwrap();
        let kind_schema = &constraints["then"]["properties"]["data"]["properties"]["kind"];
        assert!(kind_schema["const"] == kind || kind_schema["enum"].as_array()
            .is_some_and(|allowed| allowed.contains(&json!(kind))));
    }
}

#[test]
fn effect_subindices_are_distinct_and_sse_resumes_after_each_event() {
    let mut turn = operator_turn();
    turn.effects = vec![pb::EffectRecord { ordinal: 2, kind: "secret.reveal".into(),
        target: "secret-reveal:webhook-key".into(), status: pb::EffectStatus::Ok as i32, ..Default::default() }];
    let events = events::project(&mapper(), &identity(), &main_frame(19), &Record::TurnRecord(turn), &[]).unwrap();
    assert_eq!(events[0].data.action, "resend");
    assert_eq!(events[1].data.action, "secret.reveal");
    assert_eq!(events[1].data.effect, Some(2));
    assert_ne!(events[0].id, events[1].id);
    let mut cursor = ResumeCursor::new(identity());
    cursor.rewind(Position { source: SourcePos::Actor { shard: Some(1), lsn: 90 }, subindex: 0 }).unwrap();
    let framed = events::sse_event(&events[0], &cursor).unwrap();
    let id_line = framed.lines().next().unwrap().strip_prefix("id: ").unwrap();
    let resumed: ResumeCursor = serde_json::from_str(id_line).unwrap();
    assert_eq!(resumed.streams["actor-native"], Position { source: native(19), subindex: 1 });
    assert_eq!(resumed.streams["actor-1"].source, SourcePos::Actor { shard: Some(1), lsn: 90 });
    let after = events::resume_after(&events[1], &resumed).unwrap();
    assert_eq!(after.streams["actor-native"].subindex, 2);
    let mut other = identity(); other.installation = "other".into();
    assert!(after.validate(&other).is_err());
    assert_ne!(events[0].id, events::event_id(&identity(), SourcePos::Actor { shard: Some(1), lsn: 19 },
        Some("main"), 0, &events[0].data.record_hash).unwrap());
}

#[test]
fn hmac_authenticates_version_timestamp_identity_and_exact_body() {
    let id = "ke1.69.6d.actor.native.9.0.0000000000000000000000000000000000000000000000000000000000000000";
    let signed = webhook::signature(b"dummy-key", 123, id, b"{\"a\":1}").unwrap();
    assert_eq!(signed, webhook::signature(b"dummy-key", 123, id, b"{\"a\":1}").unwrap());
    assert_ne!(signed, webhook::signature(b"dummy-key", 124, id, b"{\"a\":1}").unwrap());
    let different = "ke1.69.6d.actor.native.10.0.0000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(signed, webhook::signature(b"dummy-key", 123, different, b"{\"a\":1}").unwrap());
    assert_ne!(signed, webhook::signature(b"dummy-key", 123, id, b"{\"a\":2}").unwrap());
    assert_ne!(signed, webhook::signature(b"wrong-key", 123, id, b"{\"a\":1}").unwrap());
    assert!(webhook::signature(b"dummy-key", 123, "ke1.bad\nheader", b"{}").is_err());
    assert!(webhook::signature(b"", 123, id, b"{}").is_err());
    assert_eq!(webhook::signing_input(123, id, b"{}").unwrap(),
        format!("kronik.webhook/v1\n123\n{id}\n{{}}").into_bytes());
}

#[tokio::test]
async fn committed_pages_restart_rewind_and_prepared_webhook_survive_durable_reload() {
    use hmac::{KeyInit as _, Mac as _};
    let dir = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(MetadataNetwork::default());
    env.net = network.clone();
    let node = start_local(env.clone(), dir.path(), NodeConfig::default()).await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), dir.path()).await.unwrap());
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let mapper = Arc::new(Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: node.branch().into() });
    let stream = configured_stream("events-test:actor-native", &cursors, &settings);
    let (reader, snapshot, _authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    // Consume the real startup ledger records before taking this feed's resume
    // boundary. Startup SecretVersion fences remain public operational events.
    let startup = events::page(&reader, &mapper, &identity(),
        &ResumeCursor::new(identity()), &patterns, events::MAX_EVENTS).await.unwrap();
    assert!(!startup.more);
    assert!(startup.events.iter().any(|event|
        event.record_kind == 45 && event.data.action == "secret.range"));
    let startup_through = node.applied_lsn();
    let start = startup.cursor;
    let proposal_lsn = node.record_audit_event_authorized("proposal.create", "p-real",
        BTreeMap::new(), audit().unwrap(), execution.clone()).await.unwrap();
    node.record_audit_event_authorized("proposal.cancel", "p-real", BTreeMap::new(),
        audit().unwrap(), execution.clone()).await.unwrap();
    let (reader, snapshot, _authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let first = events::page(&reader, &mapper, &identity(), &start, &patterns, 1).await.unwrap();
    assert_eq!(first.events[0].data.action, "proposal.create");
    assert_eq!(first.events[0].source, native(proposal_lsn));
    assert_eq!(first.events[0].data.at_wall_ms, 123);
    let restored: ResumeCursor = serde_json::from_slice(&serde_json::to_vec(&first.cursor).unwrap()).unwrap();
    let second = events::page(&reader, &mapper, &identity(), &restored, &patterns, 1).await.unwrap();
    assert_eq!(second.events[0].data.action, "proposal.cancel");
    let mut rewound = second.cursor.clone();
    rewound.rewind(Position { source: first.events[0].source, subindex: 0 }).unwrap();
    let replay = events::page(&reader, &mapper, &identity(), &rewound, &patterns, 1).await.unwrap();
    assert_eq!(replay.events[0].id, first.events[0].id);
    let mut ahead = start.clone();
    ahead.rewind(Position { source: native(node.applied_lsn() + 2), subindex: 0 }).unwrap();
    assert!(events::page(&reader, &mapper, &identity(), &ahead, &patterns, 1).await.is_err());
    let signer: Arc<webhook::Resolver> = Arc::new(|reference, input, _original| Box::pin(async move {
        let key: &[u8] = match reference.version {
            7 => { assert_eq!(reference.version_hash, [7;16]); b"dummy-key" },
            8 => { assert_eq!(reference.version_hash, [8;16]); b"dummy-next-key" },
            _ => panic!("unexpected immutable version"),
        };
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(&input);
        Ok(mac.finalize().into_bytes().into())
    }));
    let mut sink = Webhook::open(node.clone(), mapper.clone(), identity(), None,
        stream.clone(), cursors.clone(), settings.clone(), signer.clone(), execution.clone()).await.unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let mut page = reader.local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(page.retention_gap.is_none());
    page.records.retain(|(source, _)| source.lsn <= startup_through);
    let prepared = sink.prepare(&page.records, [0;16], &reader, &snapshot, authorization.clone()).await.unwrap();
    assert!(matches!(sink.deliver(&prepared, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == "http_503"));
    let durable = std::fs::read(dir.path().join(Cursors::FILE)).unwrap();
    assert!(!String::from_utf8_lossy(&durable).contains("dummy-key"));
    assert_eq!(cursors.get("events-test:actor-native").unwrap().lsn, 0);
    drop(sink);
    let recovered_cursors = Arc::new(Cursors::load(env, dir.path()).await.unwrap());
    let mut rotated = settings.clone();
    rotated.secret.version = 8;
    rotated.secret.version_hash = [8;16];
    let recovered_stream = configured_stream("events-test:actor-native", &recovered_cursors, &rotated);
    let mut recovered = Webhook::open(node.clone(), mapper.clone(), identity(), None,
        recovered_stream.clone(), recovered_cursors.clone(), rotated.clone(), signer.clone(), execution.clone()).await.unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let mut page = reader.local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(page.retention_gap.is_none());
    page.records.retain(|(source, _)| source.lsn <= startup_through);
    let same = recovered.prepare(&page.records, [0;16], &reader, &snapshot, authorization.clone()).await.unwrap();
    assert_eq!(serde_json::to_value(prepared.as_ref()).unwrap(), serde_json::to_value(same.as_ref()).unwrap());
    let configured = recovered_cursors.get("events-test:actor-native").unwrap();
    assert_eq!(configured.state["secret"]["version"], 8);
    assert_eq!(configured.state["pending"]["pin"]["version"], 7);
    assert_eq!(recovered.deliver(&same, authorization.clone()).await, kronik_otel::follow::Delivery::Delivered);
    {
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].headers, requests[1].headers);
    }
    // The real follower retries the durable pending body before its own
    // guarded ACK checkpoint; the test never publishes a cursor directly.
    let (worker_node, worker_stream, original) = (node.clone(), recovered_stream.clone(), execution.clone());
    recovered_stream.own_task(node.env().spawn("events-ack-checkpoint", async move {
        let result = kronik_otel::follow::follow(worker_node, worker_stream,
            kronik_otel::follow::Options { batch: 1, interval: std::time::Duration::from_millis(1) },
            recovered, original).await;
        assert!(result.is_ok(), "actual event follower failed: {result:?}");
    }));
    let caught_up = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let entry = recovered_cursors.get("events-test:actor-native").unwrap();
            if entry.lsn == node.applied_lsn() && entry.state["pending"].is_null() { break; }
            node.env().clock.sleep(std::time::Duration::from_millis(5)).await;
        }
    }).await;
    recovered_stream.stop_and_join().await.unwrap();
    caught_up.unwrap();
    let entry = recovered_cursors.get("events-test:actor-native").unwrap();
    assert!(entry.lsn >= proposal_lsn);
    assert_eq!(entry.state["secret"]["version"], 8);
    let requests = network.requests.lock().unwrap();
    let request = requests.iter().find(|request| serde_json::from_slice::<events::Event>(&request.body)
        .is_ok_and(|event| event.source == native(proposal_lsn) && event.data.action == "proposal.create")).unwrap();
    let event: events::Event = serde_json::from_slice(&request.body).unwrap();
    let header = |name: &str| request.headers.iter().find(|(key, _)| key == name).unwrap().1.as_str();
    assert_eq!(header("kronik-signature"), webhook::signature(b"dummy-next-key",
        header("kronik-timestamp-ms").parse().unwrap(), &event.id, &request.body).unwrap());
    drop(requests);
    let mut rebound = rotated;
    rebound.secret.version_hash = [9;16];
    let rebound_stream = configured_stream("events-test:actor-native", &recovered_cursors, &rebound);
    assert!(Webhook::open(node, mapper, identity(), None,
        rebound_stream, recovered_cursors, rebound, signer, execution).await.is_err());
}

#[tokio::test]
async fn compacted_actor_pending_survives_restart_and_holds_gap_until_ack() {
    use hmac::{KeyInit as _, Mac as _};
    use kronik_otel::cursor::{Control, Entry};
    use kronik_sched::snapshots::StorageConfig;
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(MetadataNetwork { failures: 2, ..Default::default() });
    env.net = network.clone();
    let mut storage = StorageConfig::new(directory.path().to_path_buf());
    storage.history = Duration::ZERO;
    let node = start_local(env.clone(), directory.path(), NodeConfig {
        storage: Some(storage), segment_max_bytes: Some(4096), ..NodeConfig::default()
    }).await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    let mapper = Arc::new(Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: node.branch().into() });
    let receipt = node.record_audit_event_authorized("proposal.create", "pending-before-compaction",
        BTreeMap::new(), audit().unwrap(), execution.clone()).await.unwrap();
    let stream = "events-pending-gap:actor-native";
    let generation = [6; 16];
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    cursors.save(stream, Entry { lsn: receipt - 1, control: Some(Control::new(generation)),
        ..Entry::default() }).await.unwrap();
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let registered = configured_stream(stream, &cursors, &settings);
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let page = reader.local_export_page(receipt - 1, 1, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(page.retention_gap.is_none());
    let (source, committed) = page.records.iter().find(|(source, _)| source.lsn == receipt).unwrap();
    let expected = events::project(&mapper, &identity(), source, &committed.record, &patterns).unwrap()
        .into_iter().find(|event| event.data.action == "proposal.create").unwrap();
    let expected_body = expected.body().unwrap();
    let observed_pins = Arc::new(std::sync::Mutex::new(Vec::new()));
    let pins = observed_pins.clone();
    let resolver: Arc<webhook::Resolver> = Arc::new(move |pin, input, _original| {
        pins.lock().unwrap().push(pin);
        Box::pin(async move {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"pending-gap-key").unwrap();
            mac.update(&input);
            Ok(mac.finalize().into_bytes().into())
        })
    });
    let mut sink = Webhook::open(node.clone(), mapper.clone(), identity(), None, registered.clone(),
        cursors.clone(), settings.clone(), resolver.clone(), execution.clone()).await.unwrap();
    let prepared = sink.prepare(&page.records, generation, &reader, &snapshot, authorization.clone()).await.unwrap();
    let expected_batch = serde_json::to_value(prepared.as_ref()).unwrap();
    assert!(matches!(sink.deliver(&prepared, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == "http_503"));
    assert_eq!(cursors.get(stream).unwrap().state["pending"], expected_batch);
    drop(prepared);
    drop(sink);
    drop(cursors);
    drop(patterns);
    drop(snapshot);
    drop(authorization);
    drop(reader);
    drop(registered);

    // Actual closed-segment retention, not a forged source index or a deleted file.
    for n in 0..30 {
        node.record_audit_event_authorized("proposal.create", &format!("gap-padding-{n}"),
            BTreeMap::from([("fixture".into(), "x".repeat(1500))]), audit().unwrap(),
            execution.clone()).await.unwrap();
    }
    node.deploy(include_bytes!("../../../tests/guests/counter.wasm"), audit().unwrap(), false,
        execution.clone()).await.unwrap();
    for n in 0..80 {
        node.send(kronik_core::ids::ActorRef::parse("counter/pending-gap").unwrap(),
            pb::Message { name: "increment".into(), ..Default::default() }, audit().unwrap(), false,
            execution.clone()).await.unwrap().unwrap();
        if n % 20 == 19 { node.env().clock.sleep(Duration::from_millis(5)).await; }
    }
    node.snapshot("manual", execution.clone()).await.unwrap();
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(first > receipt, "the actual prepared source record must have compacted");
    node.refresh_secret_inventory(execution.clone()).await.unwrap();
    let through = first - 1;
    let mut rotated = settings.clone();
    rotated.secret.version = 8;
    rotated.secret.version_hash = [8;16];
    let recovered_cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let recovered_stream = configured_stream(stream, &recovered_cursors, &rotated);
    let mut recovered = Webhook::open(node.clone(), mapper.clone(), identity(), None, recovered_stream.clone(),
        recovered_cursors.clone(), rotated.clone(), resolver.clone(), execution.clone()).await.unwrap();
    let before = recovered_cursors.get(stream).unwrap();
    assert_eq!(before.lsn, receipt - 1);
    assert_eq!(before.generation(), generation);
    assert_eq!(before.state["pending"], expected_batch);
    assert_eq!(before.state["secret"]["version"], 8);
    assert_eq!(before.state["pending"]["pin"]["version"], 7);
    let (_reader, _snapshot, authorization) = native_disclosure(&node, &execution).await;
    assert_eq!(recovered.gap(receipt, through, authorization.clone()).await.unwrap_err(), "http_503");
    let held = recovered_cursors.get(stream).unwrap();
    assert_eq!(held.lsn, before.lsn);
    assert_eq!(held.control, before.control);
    assert_eq!(held.state, before.state);
    let observed = reader.local_export_page(first - 1, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(!observed.records.iter().any(|(_, record)| matches!(&record.record,
        Record::AuditEvent(event) if event.action == "audit.gap" && event.target == stream)),
        "a retry must not append the gap audit or checkpoint");
    drop(recovered);
    drop(recovered_cursors);
    drop(authorization);
    drop(reader);
    drop(recovered_stream);

    // Retry after another durable reload still uses the old prepared body and pin.
    let resumed_cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let resumed_stream = configured_stream(stream, &resumed_cursors, &rotated);
    let mut resumed = Webhook::open(node.clone(), mapper, identity(), None, resumed_stream.clone(),
        resumed_cursors.clone(), rotated, resolver, execution.clone()).await.unwrap();
    assert_eq!(resumed_cursors.get(stream).unwrap().state["pending"], expected_batch);
    let (_reader, _snapshot, authorization) = native_disclosure(&node, &execution).await;
    resumed.gap(receipt, through, authorization.clone()).await.unwrap();
    let acknowledged = resumed_cursors.get(stream).unwrap();
    assert_eq!(acknowledged.lsn, receipt - 1, "ACK alone is not a manifest checkpoint");
    assert_eq!(acknowledged.state["pending"], expected_batch);
    let observed_reader = node.capture_system_export_reader().await.unwrap();
    let observed = observed_reader.local_export_page(first - 1, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    let mut markers = Vec::new();
    for (source, record) in observed.records {
        if let Record::AuditEvent(event) = &record.record
            && event.action == "audit.gap" && event.target == stream {
            assert_eq!(source.lsn, record.lsn);
            assert_eq!(event.details.get("from"), Some(&receipt.to_string()));
            assert_eq!(event.details.get("to"), Some(&through.to_string()));
            markers.push(source.lsn);
        }
    }
    assert_eq!(markers.len(), 1, "only acknowledged delivery may append the real gap marker");
    {
        let requests = network.requests.lock().unwrap();
        assert!(!requests.is_empty());
        for request in requests.iter() {
            assert_eq!(request.body.as_ref(), expected_body.as_slice());
            assert_eq!(request.headers, requests.first().unwrap().headers);
            let event: events::Event = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(event.id, expected.id);
        }
    }
    {
        let pins = observed_pins.lock().unwrap();
        assert!(!pins.is_empty());
        assert!(pins.iter().all(|pin| pin == &settings.secret));
    }
    let (worker_node, worker_stream, original) = (node.clone(), resumed_stream.clone(), execution.clone());
    resumed_stream.own_task(node.env().spawn("events-gap-checkpoint", async move {
        let result = kronik_otel::follow::follow(worker_node, worker_stream,
            kronik_otel::follow::Options { batch: 1, interval: Duration::from_millis(1) },
            resumed, original).await;
        assert!(result.is_ok(), "actual pending/gap follower failed: {result:?}");
    }));
    let caught_up = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let entry = resumed_cursors.get(stream).unwrap();
            if entry.lsn == node.applied_lsn() && entry.state["pending"].is_null() { break; }
            node.env().clock.sleep(Duration::from_millis(5)).await;
        }
    }).await;
    resumed_stream.stop_and_join().await.unwrap();
    caught_up.unwrap();
    let checkpoint = resumed_cursors.get(stream).unwrap();
    assert!(checkpoint.lsn >= through);
    assert_eq!(checkpoint.generation(), generation);
    assert!(checkpoint.state["pending"].is_null());
    assert_eq!(checkpoint.state["secret"]["version"], 8);
}

#[tokio::test]
async fn compaction_returns_an_explicit_repeatable_shard_gap_before_later_events() {
    use std::time::Duration;
    use kronik_sched::snapshots::StorageConfig;

    let dir = tempfile::tempdir().unwrap();
    let mut storage = StorageConfig::new(dir.path().to_path_buf());
    storage.history = Duration::ZERO;
    let node = start_local(Env::real(tokio::runtime::Handle::current()), dir.path(),
        NodeConfig { storage: Some(storage), segment_max_bytes: Some(4096), ..NodeConfig::default() })
        .await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    let secret = b"retained-compaction-secret-needle";
    node.secret_set("retention-fixture", secret.to_vec(), &audit().unwrap(), false,
        execution.clone()).await.unwrap().unwrap();
    let secret_floor = node.store().db().secret_format_floor().unwrap().unwrap();
    for n in 0..30 {
        node.record_audit_event_authorized("proposal.create", &format!("p-{n}"),
            BTreeMap::from([("fixture".into(), "x".repeat(1500))]), audit().unwrap(), execution.clone()).await.unwrap();
    }
    // Audit-only records do not advance the logical turn-time retention bound.
    // Use the existing real actor fixture, as the snapshot retention tests do;
    // do not delete segments or release a protected retention floor by hand.
    node.deploy(include_bytes!("../../../tests/guests/counter.wasm"),
        audit().unwrap(), false, execution.clone()).await.unwrap();
    for n in 0..80 {
        node.send(kronik_core::ids::ActorRef::parse("counter/retention").unwrap(),
            pb::Message { name: "increment".into(), ..Default::default() },
            audit().unwrap(), false, execution.clone()).await.unwrap().unwrap();
        if n % 20 == 19 {
            node.env().clock.sleep(Duration::from_millis(5)).await;
        }
    }
    let snapshot = node.snapshot("manual", execution.clone()).await.unwrap();
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(first > 1);
    assert!(first <= snapshot.lsn + 1);
    assert_eq!(node.store().db().secret_format_floor().unwrap(), Some(secret_floor));
    node.refresh_secret_inventory(execution.clone()).await.unwrap();
    assert!(node.secret_values().unwrap().iter().any(|(name, value)|
        name == "retention-fixture" && value.as_slice() == secret.as_slice()));
    let mapper = Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: "main".into() };
    let mut cursor = ResumeCursor::new(identity());
    cursor.rewind(Position { source: native(1), subindex: 0 }).unwrap();
    cursor.rewind(Position { source: SourcePos::Actor { shard: Some(1), lsn: 900 }, subindex: 2 }).unwrap();
    let reader = node.capture_system_export_reader().await.unwrap();
    let (catalogue, publication) = native_catalogue(&node).unwrap();
    let patterns: Vec<_> = catalogue.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let page = events::page(&reader, &mapper, &identity(), &cursor, &patterns, 2).await.unwrap();
    let repeated = events::page(&reader, &mapper, &identity(), &cursor, &patterns, 2).await.unwrap();
    assert_eq!(page, repeated);
    assert!(page.events.is_empty());
    assert_eq!(page.gap, Some(events::Gap { from: native(1), through: native(first - 1) }));
    assert_eq!(page.cursor.streams["actor-native"], Position { source: native(first), subindex: 0 });
    assert_eq!(page.cursor.streams["actor-1"], cursor.streams["actor-1"]);
    let retained = events::page(&reader, &mapper, &identity(), &page.cursor, &patterns, 2).await.unwrap();
    assert!(retained.gap.is_none());
    assert!(retained.events.iter().all(|event| matches!(event.source, SourcePos::Actor { shard: None, lsn } if lsn >= first)));
    publication.check_current().unwrap();
    execution.check().unwrap();
}

#[test]
fn actual_failed_root_emits_safe_deadletter_creation_metadata() {
    let mut turn = operator_turn();
    turn.outcome = Some(pb::Outcome { kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(), message: "failure-PII-NEEDLE VALUE-NEEDLE".into(),
        ..Default::default() });
    let record = Record::TurnRecord(turn);
    let catalogue = [("webhook-key", b"VALUE-NEEDLE".as_slice())];
    let projected = events::project(&mapper(), &identity(), &main_frame(41), &record, &catalogue).unwrap();
    let created = projected.iter().find(|event| event.data.kind == "deadletter").unwrap();
    assert_eq!(created.data.action, "created");
    assert_eq!(created.data.schema, "kronik.operation/v1");
    assert_eq!(created.data.at_wall_ms, 123);
    assert_eq!(created.record_kind, 3);
    assert_eq!(created.source, native(41));
    assert_eq!(created.subindex, 1);
    assert_eq!(created.data.record_hash, projected[0].data.record_hash);
    let wire = String::from_utf8(created.body().unwrap()).unwrap();
    for needle in ["failure-PII-NEEDLE", "VALUE-NEEDLE", "BODY-NEEDLE", "actor-PII-NEEDLE",
        "raw-name-PII-NEEDLE", "raw-reason-PII-NEEDLE"] {
        assert!(!wire.contains(needle));
    }
    let metadata = serde_json::to_value(&created.data).unwrap();
    assert!(metadata.get("details").is_none());
    assert!(metadata.get("reason").is_none());
    assert!(metadata.get("token_id").is_none());
}

#[test]
fn empty_and_gap_sse_frames_publish_the_next_shard_cursor() {
    let mut cursor = ResumeCursor::new(identity());
    cursor.rewind(Position { source: native(90), subindex: 0 }).unwrap();
    let mut page = events::Page { events: Vec::new(),
        cursor: cursor.clone(), applied: native(89), gap: None, more: false };
    for gap in [None, Some(events::Gap { from: native(1), through: native(89) })] {
        page.gap = gap;
        let frame = events::sse_cursor(&page).unwrap();
        let id = frame.lines().next().unwrap().strip_prefix("id: ").unwrap();
        assert_eq!(serde_json::from_str::<ResumeCursor>(id).unwrap(), cursor);
        assert_eq!(frame.lines().nth(1).unwrap(),
            if page.gap.is_some() { "event: gap" } else { "event: cursor" });
    }
}

#[tokio::test]
async fn canonical_operational_identity_separates_visible_changes_not_sealable_values() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut records = Vec::new();
    let original = operator_turn();
    let mut changed_value = original.clone();
    if let Some(pb::input::Kind::Message(message)) = changed_value.input.as_mut().and_then(|input| input.kind.as_mut()) {
        message.msg.as_mut().unwrap().body.as_mut().unwrap().value =
            Some(pb::sealable::Value::Plain(b"DIFFERENT-PRIVATE-BODY-NEEDLE".to_vec()));
    }
    assert_ne!(original, changed_value);
    let mut sources = ["proposal.create", "proposal.cancel"].into_iter().map(|action|
        Record::AuditEvent(pb::AuditEvent {
            action: action.into(), target: "p-1".into(), audit: audit(), ..Default::default()
        })).collect::<Vec<_>>();
    sources.extend([Record::TurnRecord(original), Record::TurnRecord(changed_value)]);
    for (index, source) in sources.into_iter().enumerate() {
        let (tx, mut committed) = tokio::sync::mpsc::unbounded_channel();
        let (fatal, _failed) = tokio::sync::oneshot::channel();
        let mut config = kronik_log::LogConfig::new(directory.path().join(index.to_string()), "main");
        config.first_lsn = 9;
        let (log, _) = kronik_log::Log::open(&env, config, tx, fatal).await.unwrap();
        log.append(source).await.unwrap();
        records.push(committed.recv().await.unwrap());
    }
    // Actual tails reuse a position; only canonical operational identity is compared.
    assert_eq!(records[0].lsn, records[1].lsn);
    let first = events::project(&mapper(), &identity(), &main_frame(records[0].lsn), &records[0].record, &[]).unwrap();
    let retry = events::project(&mapper(), &identity(), &main_frame(records[0].lsn), &records[0].record, &[]).unwrap();
    let restored_tail = events::project(&mapper(), &identity(), &main_frame(records[1].lsn), &records[1].record, &[]).unwrap();
    assert_eq!(first[0].id, retry[0].id);
    assert_eq!(first[0].body().unwrap(), retry[0].body().unwrap());
    assert_ne!(first[0].data.action, restored_tail[0].data.action);
    assert_ne!(first[0].data.record_hash, restored_tail[0].data.record_hash);
    assert_ne!(first[0].id, restored_tail[0].id);
    assert_eq!(first[0].source, restored_tail[0].source);
    let private_first = events::project(&mapper(), &identity(), &main_frame(records[2].lsn), &records[2].record, &[]).unwrap();
    let private_changed = events::project(&mapper(), &identity(), &main_frame(records[3].lsn), &records[3].record, &[]).unwrap();
    assert_eq!(private_first[0].data, private_changed[0].data);
    assert_eq!(private_first[0].id, private_changed[0].id);
    assert_eq!(private_first[0].body().unwrap(), private_changed[0].body().unwrap());
    assert!(events::event_id(&identity(), native(9), Some("main"), 0, "b3:invalid").is_err());
    assert!(events::event_id(&identity(), native(9), Some("main"), 0, &format!("b3:{}", "0".repeat(64))).is_err());
}

#[tokio::test]
async fn decoded_operational_wire_records_fsynced_in_native_log_publish_exact_variants() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let schema = events::schemas().unwrap();
    for (kind, wire, expected_kind, expected_action, epoch) in [
        (20, include_str!("../../kronik-proto/tests/fixtures/shard-term-v1.hex"), "shard_term", "shard.term", None),
        (21, include_str!("../../kronik-proto/tests/fixtures/shard-membership-v1.hex"), "shard_membership", "shard.membership", None),
        (22, include_str!("../../kronik-proto/tests/fixtures/inbox-v1.hex"), "inbox", "shard.inbox", None),
        (23, include_str!("../../kronik-proto/tests/fixtures/outbox-ack-v1.hex"), "outbox_ack", "shard.outbox_ack", None),
        (24, include_str!("../../kronik-proto/tests/fixtures/epoch-barrier-v1.hex"), "epoch_barrier", "shard.epoch_barrier", Some(4)),
        (25, include_str!("../../kronik-proto/tests/fixtures/shard-origin-v1.hex"), "shard_origin", "shard.origin", None),
    ] {
        let bytes = kronik_core::ids::unhex(wire.trim()).unwrap();
        let record = Record::decode(kind, &bytes).unwrap();
        let lsn = log.append(record).await.unwrap();
        let source = committed.recv().await.unwrap();
        assert_eq!(source.lsn, lsn);
        assert_eq!(source.record.kind(), kind);
        let projected = events::project(&mapper(), &identity(), &main_frame(source.lsn), &source.record, &[]).unwrap();
        let event = projected.iter().find(|event| event.data.action == expected_action).unwrap();
        assert_eq!(event.data.kind, expected_kind);
        assert_eq!(event.data.epoch, epoch);
        assert_eq!(event.data.at_wall_ms, 0);
        assert_eq!(event.data.effect, None);
        assert_eq!(event.source, native(source.lsn));
        assert_eq!(event.record_kind, kind);
        assert_eq!(serde_json::to_value(event).unwrap().get("lsn"), None);
        assert_eq!(serde_json::to_value(event).unwrap().get("shard"), None);
        let metadata = serde_json::to_value(&event.data).unwrap();
        for private in ["reason", "token_id", "details", "body", "payload"] {
            assert!(metadata.get(private).is_none());
        }
        let constraint = schema["allOf"].as_array().unwrap().iter().find(|constraint|
            constraint["if"]["properties"]["record_kind"]["const"] == json!(kind)).unwrap();
        let published = &constraint["then"]["properties"]["data"]["properties"];
        assert_eq!(published["kind"]["const"], expected_kind);
        assert_eq!(published["action"]["const"], expected_action);
    }
}

#[tokio::test]
async fn real_secret_version_and_link_wire_records_publish_exact_phase_actions() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let schema = events::schemas().unwrap();
    for (kind, wire, expected_kind, expected_action, epoch) in [
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-reserved-v1.hex"), "secret_version", "secret.version.reserved", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex"), "secret_version", "secret.version", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-failed-v1.hex"), "secret_version", "secret.version.failed", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-version-legacy-v1.hex"), "secret_version", "secret.version", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-version-max-v1.hex"), "secret_version", "secret.version", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-fence-fresh-v1.hex"), "secret_version", "secret.range", None),
        (45, include_str!("../../kronik-proto/tests/fixtures/secret-fence-legacy-v1.hex"), "secret_version", "secret.range", None),
        (46, include_str!("../../kronik-proto/tests/fixtures/secret-link-v1.hex"), "secret_link", "secret.link", Some(7)),
        (46, include_str!("../../kronik-proto/tests/fixtures/secret-unlink-v1.hex"), "secret_link", "secret.unlink", Some(8)),
    ] {
        let record = Record::decode(kind, &kronik_core::ids::unhex(wire.trim()).unwrap()).unwrap();
        let lsn = log.append(record).await.unwrap();
        let source = committed.recv().await.unwrap();
        assert_eq!(source.lsn, lsn);
        let projected = events::project(&mapper(), &identity(), &main_frame(source.lsn), &source.record, &[]).unwrap();
        let event = projected.iter().find(|event| event.data.action == expected_action).unwrap();
        assert_eq!(event.data.kind, expected_kind);
        assert_eq!(event.data.epoch, epoch);
        assert_eq!(event.data.at_wall_ms, 1);
        assert_eq!(event.data.effect, None);
        assert_eq!(event.record_kind, kind);
        assert_eq!(event.source, native(source.lsn));
        // Separate captured-image UNIT projection: index 17 is a literal
        // metadata coordinate, not an actor LSN or a claimed Raft commit.
        let image = MetadataImage { floor: 1, head: 21,
            records: [(17, MetadataAuditRecord { index: 17, record: source.record.clone(), native_origin: None })].into() };
        let page = events::metadata_page(&image, &mapper(), &identity(),
            &ResumeCursor::new(identity()), &[], 1).unwrap();
        assert!(page.gap.is_none());
        let metadata_event = &page.events[0];
        assert_eq!(metadata_event.record_kind, kind);
        assert_eq!(metadata_event.data.kind, expected_kind);
        assert_eq!(metadata_event.data.action, expected_action);
        assert_eq!(metadata_event.data.epoch, epoch);
        assert_eq!(metadata_event.data.at_wall_ms, 1);
        assert_eq!(metadata_event.source, SourcePos::Metadata { index: 17 });
        assert!(metadata_event.branch.is_none());
        assert_ne!(metadata_event.id, event.id);
        // A full one-record source batch covers only through its last record,
        // not the durable head. The next bounded scan certifies the trailing
        // non-operational holes before its empty cursor frame can advance.
        assert_eq!(page.cursor.streams["metadata"].source, SourcePos::Metadata { index: 18 });
        assert!(page.more);
        let trailing = events::metadata_page(&image, &mapper(), &identity(), &page.cursor, &[], 1).unwrap();
        assert!(trailing.events.is_empty());
        assert!(trailing.gap.is_none());
        assert_eq!(trailing.cursor.streams["metadata"].source, SourcePos::Metadata { index: 22 });
        assert_eq!(trailing.applied, SourcePos::Metadata { index: 21 });
        assert!(!trailing.more);
        let metadata = serde_json::to_value(&event.data).unwrap();
        for private in ["name", "backend", "binding", "ref", "canonical_ref", "source_version",
            "version_hash", "reason", "token_id", "details"] {
            assert!(metadata.get(private).is_none());
        }
        let constraint = schema["allOf"].as_array().unwrap().iter().find(|constraint|
            constraint["if"]["properties"]["record_kind"]["const"] == json!(kind)).unwrap();
        let published = &constraint["then"]["properties"]["data"]["properties"];
        assert_eq!(published["kind"]["const"], expected_kind);
        assert!(published["action"]["enum"].as_array().unwrap().contains(&json!(expected_action)));
    }
}

fn control_record(operation: pb::audit_event::Operation) -> Record {
    let mut audit = audit().unwrap();
    if matches!(&operation, pb::audit_event::Operation::InstallationIdentity(_)) {
        audit.token_id = "system:installation".into();
    }
    Record::AuditEvent(pb::AuditEvent { action: operation.action().into(), target: operation.target().into(),
        operation: Some(operation), audit: Some(audit), details: BTreeMap::new(), ..Default::default() })
}

fn control_fixtures() -> Vec<(Record, &'static str, Option<events::FleetPhase>)> {
    use pb::audit_event::Operation;
    use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
        DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
    use sha2::Digest as _;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../kronik-proto/tests/fixtures/control-fleet-pending-v1.json")).unwrap();
    let bytes = |name: &str| kronik_core::ids::unhex(fixture[name].as_str().unwrap()).unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let ca_sha256 = sha2::Sha256::digest(root.der()).to_vec();
    let issuer = Issuer::new(ca, key);
    let mut fleet = pb::FleetState { installation: fixture["installation"].as_str().unwrap().into(),
        controller_origin: fixture["controller_origin"].as_str().unwrap().into(),
        scopes: vec!["read".into()], ca_sha256, request_id: bytes("request_id"),
        epoch: 1, phase: pb::fleet_state::Phase::Pending as i32, csr_der: bytes("csr_der_hex"),
        client_key_sha256: bytes("client_key_sha256"), ..Default::default() };
    let mut records = vec![(control_record(Operation::FleetState(fleet.clone())),
        "fleet.state", Some(events::FleetPhase::Pending))];
    fleet.phase = pb::fleet_state::Phase::Requested as i32;
    records.push((control_record(Operation::FleetState(fleet.clone())),
        "fleet.state", Some(events::FleetPhase::Requested)));
    let csr = CertificateSigningRequestParams::from_der(
        &rustls_pki_types::CertificateSigningRequestDer::from(fleet.csr_der.as_slice())).unwrap();
    let mut certificate = CertificateParams::default();
    certificate.distinguished_name = DistinguishedName::new();
    certificate.distinguished_name.push(DnType::CommonName, &fleet.installation);
    certificate.subject_alt_names = vec![SanType::URI(format!("urn:kronik:fleet:request:{}:{}",
        kronik_core::ids::hex(&fleet.request_id), fleet.epoch).try_into().unwrap())];
    certificate.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    certificate.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    fleet.client_cert_der = Some(certificate.signed_by(&csr.public_key, &issuer).unwrap().der().to_vec());
    fleet.controller_id = Some(kronik_core::ids::hex(&fleet.ca_sha256));
    fleet.phase = pb::fleet_state::Phase::Active as i32;
    records.push((control_record(Operation::FleetState(fleet.clone())),
        "fleet.state", Some(events::FleetPhase::Active)));
    fleet.phase = pb::fleet_state::Phase::Revoked as i32;
    records.push((control_record(Operation::FleetState(fleet)), "fleet.state", Some(events::FleetPhase::Revoked)));
    records.push((control_record(Operation::InstallationIdentity(pb::InstallationIdentity {
        installation: identity().installation })), "installation.identity", None));
    let mut auth = pb::AuthConfig { version: kronik_proto::control::AUTH_CONFIG_VERSION, ..Default::default() };
    auth.digest = kronik_proto::control::auth_config_digest(&auth).to_vec();
    records.push((control_record(Operation::AuthConfig(auth)), "auth.config", None));
    records
}

#[tokio::test]
async fn typed_controls_publish_real_native_records_and_closed_fleet_phase() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let mut phases = BTreeMap::new();
    for (record, action, phase) in control_fixtures() {
        let decoded = Record::decode(record.kind(), &record.encode()).unwrap();
        let lsn = log.append(decoded).await.unwrap();
        let record = committed.recv().await.unwrap();
        assert_eq!(record.lsn, lsn);
        let event = events::project(&mapper(), &identity(), &main_frame(lsn), &record.record, &[]).unwrap().remove(0);
        assert_eq!(event.data.kind, "audit_event");
        assert_eq!(event.data.action, action);
        assert_eq!(event.data.phase, phase);
        assert_eq!(event.data.epoch, phase.map(|_| 1));
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        for needle in ["raw-reason-PII-NEEDLE", "raw-name-PII-NEEDLE", "csr_der", "client_cert_der"] {
            assert!(!body.contains(needle));
        }
        if let Some(phase) = phase {
            let name = serde_json::to_value(phase).unwrap().as_str().unwrap().to_owned();
            assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["data"]["phase"], name);
            phases.insert(name, event);
        } else { assert!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["data"].get("phase").is_none()); }
    }
    let active = &phases["active"];
    let revoked = &phases["revoked"];
    assert_eq!(active.data.epoch, revoked.data.epoch);
    assert_ne!(active.data.phase, revoked.data.phase);
    assert_ne!(active.id, revoked.id);
    assert_ne!(active.data.record_hash, revoked.data.record_hash);
}

/// Unit captured-image adapter; these literal indexes do not claim a Raft commit.
struct MetadataImage {
    floor: u64,
    head: u64,
    records: BTreeMap<u64, MetadataAuditRecord>,
}

impl kronik_log::MetadataAuditSource for MetadataImage {
    fn read_from(&self, from: u64, limit: usize)
        -> Result<kronik_log::MetadataAuditBatch, kronik_core::error::ApiError> {
        assert!((1..=kronik_log::MAX_METADATA_AUDIT_RECORDS).contains(&limit));
        let records: Vec<_> = self.records.range(from..)
            .take_while(|(index, _)| **index <= self.head)
            .take(limit).map(|(_, source)| MetadataAuditRecord { index: source.index,
                record: source.record.clone(), native_origin: source.native_origin.clone() }).collect();
        let scanned_through = if records.len() == limit { records.last().unwrap().index } else { self.head };
        Ok(kronik_log::MetadataAuditBatch { covered_from: self.floor, durable_through: self.head,
            scanned_through, records })
    }
}

struct MutableMetadataImage(std::sync::RwLock<MetadataImage>);

impl kronik_log::MetadataAuditSource for MutableMetadataImage {
    fn read_from(&self, from: u64, limit: usize)
        -> Result<kronik_log::MetadataAuditBatch, kronik_core::error::ApiError> {
        kronik_log::MetadataAuditSource::read_from(&*self.0.read().unwrap(), from, limit)
    }
}

fn metadata_image() -> MetadataImage {
    let mut auth = pb::AuthConfig { version: kronik_proto::control::AUTH_CONFIG_VERSION, ..Default::default() };
    auth.digest = kronik_proto::control::auth_config_digest(&auth).to_vec();
    MetadataImage { floor: 1, head: 9, records: [
        (2, MetadataAuditRecord { index: 2, record: control_record(pb::audit_event::Operation::InstallationIdentity(
            pb::InstallationIdentity { installation: "installation-1".into() })), native_origin: None }),
        (5, MetadataAuditRecord { index: 5, record: control_record(pb::audit_event::Operation::AuthConfig(auth)), native_origin: None }),
    ].into() }
}

#[test]
fn metadata_unit_pages_cover_sparse_indexes_restart_rewind_and_real_source_domains() {
    let source = metadata_image();
    let start = ResumeCursor::new(identity());
    let first = events::metadata_page(&source, &mapper(), &identity(), &start, &[], 1).unwrap();
    assert_eq!(first.events[0].source, SourcePos::Metadata { index: 2 });
    assert_eq!(first.events[0].data.action, "installation.identity");
    assert_eq!(first.applied, SourcePos::Metadata { index: 9 });
    assert!(first.gap.is_none());
    assert_eq!(first.cursor.streams["metadata"].source, SourcePos::Metadata { index: 3 });
    assert!(first.events[0].branch.is_none());
    assert!(serde_json::to_value(&first.events[0]).unwrap().get("branch").is_none());
    let restored = serde_json::from_slice(&serde_json::to_vec(&first.cursor).unwrap()).unwrap();
    let second = events::metadata_page(&source, &mapper(), &identity(), &restored, &[], 1).unwrap();
    assert_eq!(second.events[0].data.action, "auth.config");
    assert_eq!(second.events[0].source, SourcePos::Metadata { index: 5 });
    let empty = events::metadata_page(&source, &mapper(), &identity(), &second.cursor, &[], 1).unwrap();
    assert!(empty.events.is_empty());
    assert_eq!(empty.cursor.streams["metadata"].source, SourcePos::Metadata { index: 10 });
    let mut replay = empty.cursor.clone();
    replay.rewind(Position { source: SourcePos::Metadata { index: 2 }, subindex: 0 }).unwrap();
    assert_eq!(events::metadata_page(&source, &mapper(), &identity(), &replay, &[], 1).unwrap().events[0], first.events[0]);
    let mut other_selection = identity();
    other_selection.branch = "another".into();
    let mut another_mapper = mapper();
    another_mapper.branch = other_selection.branch.clone();
    let event = events::metadata_page(&source, &another_mapper, &other_selection,
        &ResumeCursor::new(other_selection.clone()), &[], 1).unwrap().events.remove(0);
    assert_eq!(event.id, first.events[0].id);
    assert_eq!(event.body().unwrap(), first.events[0].body().unwrap());
    replay.rewind(Position { source: SourcePos::Metadata { index: 2 }, subindex: 1 }).unwrap();
    assert!(events::metadata_page(&source, &mapper(), &identity(), &replay, &[], 1).unwrap().events.is_empty());
    replay.rewind(Position { source: SourcePos::Metadata { index: 2 }, subindex: 2 }).unwrap();
    assert_eq!(events::metadata_page(&source, &mapper(), &identity(), &replay, &[], 1).unwrap_err().code,
        kronik_core::error::ErrorCode::BadRequest);
    let compacted = MetadataImage { floor: 4, ..source };
    // Known historical rows remain available for exact read-only verification.
    let known = kronik_log::MetadataAuditSource::read_from(&compacted, 1, 1).unwrap();
    assert_eq!(known.records[0].index, 2);
    assert!(known.records[0].index < known.covered_from);
    let gap = events::metadata_page(&compacted, &mapper(), &identity(), &start, &[], 1).unwrap();
    assert_eq!(gap.gap, Some(events::Gap { from: SourcePos::Metadata { index: 1 }, through: SourcePos::Metadata { index: 3 } }));
    assert!(gap.events.is_empty());
    assert_eq!(gap.cursor.streams["metadata"].source, SourcePos::Metadata { index: 4 });
    assert_eq!(gap, events::metadata_page(&compacted, &mapper(), &identity(), &start, &[], 1).unwrap());
    let unkeyed = Mapper { keys: Keys::Omit, sealer: Arc::new(Sealer::plain()), branch: "main".into() };
    assert_eq!(events::metadata_page(&metadata_image(), &unkeyed, &identity(), &start, &[], 1).unwrap_err().code,
        kronik_core::error::ErrorCode::Unavailable);
}

#[tokio::test]
async fn metadata_prepared_body_pin_and_typed_cursor_survive_reload_without_actor_reinterpretation() {
    let directory = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    env.net = Arc::new(MetadataNetwork::default());
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, _, _original| Box::pin(async { Ok([0;32]) }));
    let stream = configured_stream("events-unit:metadata", &cursors, &settings);
    let mut sink = Webhook::open_metadata(native_metadata_runtime(node.clone(), "events-unit:metadata"),
        Arc::new(mapper()), identity(), stream.clone(),
        cursors.clone(), settings.clone(), resolver.clone()).await.unwrap();
    let (snapshot, publication) = native_catalogue(&node).unwrap();
    let authorization = kronik_otel::follow::metadata_records(&stream, snapshot.clone(), publication, execution.clone());
    let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let page = events::metadata_page(&metadata_image(), &mapper(), &identity(),
        &ResumeCursor::new(identity()), &patterns, 1).unwrap();
    let prepared = sink.prepare_metadata(page, [0;16]).await.unwrap();
    assert!(matches!(sink.deliver(&prepared, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == "http_503"));
    authorization.check().unwrap();
    let entry = cursors.get("events-unit:metadata").unwrap();
    assert_eq!(entry.lsn, 0); // No ACK, including the covered index before this event.
    assert_eq!(webhook::cursor_source(&entry).unwrap(), SourcePos::Metadata { index: 0 });
    let serialized = serde_json::to_value(prepared.as_ref()).unwrap();
    assert_eq!(serialized["source"], json!({"kind":"metadata","index":2}));
    assert_eq!(serialized["through"], json!({"kind":"metadata","index":2}));
    drop(sink);
    let reloaded = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let recovered_stream = configured_stream("events-unit:metadata", &reloaded, &settings);
    let mut recovered = Webhook::open_metadata(native_metadata_runtime(node.clone(), "events-unit:metadata"),
        Arc::new(mapper()), identity(), recovered_stream.clone(),
        reloaded.clone(), settings.clone(), resolver.clone()).await.unwrap();
    let (snapshot, publication) = native_catalogue(&node).unwrap();
    let authorization = kronik_otel::follow::metadata_records(&recovered_stream, snapshot.clone(), publication, execution.clone());
    let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let page = events::metadata_page(&metadata_image(), &mapper(), &identity(),
        &ResumeCursor::new(identity()), &patterns, 1).unwrap();
    assert_eq!(serde_json::to_value(recovered.prepare_metadata(page, [0;16]).await.unwrap().as_ref()).unwrap(), serialized);
    authorization.check().unwrap();
    let reader = node.capture_system_export_reader().await.unwrap();
    let actor_page = reader.local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    assert!(matches!(recovered.prepare(&actor_page.records, [0;16], &reader, &snapshot, authorization.clone()).await,
        Err(code) if code == "metadata_requires_actual_metadata_source"));
    assert!(Webhook::open(node.clone(), Arc::new(mapper()), identity(), None, recovered_stream,
        reloaded.clone(), settings.clone(), resolver.clone(), execution).await.is_err());
    reloaded.save("events-legacy:metadata", kronik_otel::cursor::Entry { lsn: 5, ..Default::default() }).await.unwrap();
    assert_eq!(webhook::cursor_source(&reloaded.get("events-legacy:metadata").unwrap()).unwrap(), native(5));
    let legacy_stream = configured_stream("events-legacy:metadata", &reloaded, &settings);
    assert!(Webhook::open_metadata(native_metadata_runtime(node, "events-legacy:metadata"),
        Arc::new(mapper()), identity(), legacy_stream,
        reloaded, settings, resolver).await.is_err());
}

struct CapturedWebhook {
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
}

struct MetadataNetwork {
    requests: Arc<std::sync::Mutex<Vec<CapturedWebhook>>>,
    failures: usize,
}

impl Default for MetadataNetwork {
    fn default() -> Self {
        Self { requests: Default::default(), failures: 1 }
    }
}

impl kronik_core::env::Net for MetadataNetwork {
    fn http_authorized(&self, request: kronik_core::env::HttpRequest, original: kronik_core::authority::AuthLease)
        -> kronik_core::env::BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>>
    {
        let requests = self.requests.clone();
        let failures = self.failures;
        Box::pin(async move {
            let body = request.body;
            if body.len() > events::MAX_PAGE_BYTES {
                return Err(kronik_core::env::NetError::TooLarge);
            }
            let mut pending = Some(CapturedWebhook { headers: request.headers, body });
            let mut status = None;
            original.admit(&mut || {
                let request = pending.take().ok_or_else(|| kronik_core::error::ApiError::new(
                    kronik_core::error::ErrorCode::Internal, "metadata HTTP request admitted twice"))?;
                let mut requests = requests.lock().unwrap();
                status = Some(if requests.len() < failures { 503 } else { 200 });
                requests.push(request);
                Ok(())
            }).map_err(|error| kronik_core::env::NetError::Connect(error.code.as_str().into()))?;
            let status = status.ok_or_else(|| kronik_core::env::NetError::Connect("HTTP request was not admitted".into()))?;
            Ok(kronik_core::env::HttpResponse {
                status, headers: Vec::new(), body: bytes::Bytes::new(),
            })
        })
    }

    fn http(&self, _request: kronik_core::env::HttpRequest)
        -> kronik_core::env::BoxFuture<'static, Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>> {
        Box::pin(async { Err(kronik_core::env::NetError::Connect("unscoped metadata HTTP is forbidden".into())) })
    }
}

struct MetadataSpawner {
    inner: Arc<dyn kronik_core::env::Spawner>,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl kronik_core::env::Spawner for MetadataSpawner {
    fn spawn(&self, name: &'static str, future: kronik_core::env::BoxFuture<'static, ()>) {
        if name == "metadata-webhook" {
            let old = self.task.lock().unwrap().replace(tokio::spawn(future));
            assert!(old.is_none(), "the previous metadata worker must be stopped");
        } else { self.inner.spawn(name, future); }
    }
    fn spawn_blocking(&self, name: &'static str, work: Box<dyn FnOnce() + Send + 'static>) {
        self.inner.spawn_blocking(name, work);
    }
}

impl MetadataSpawner {
    async fn stop(&self) {
        let task = self.task.lock().unwrap().take().unwrap();
        task.abort();
        let _ = task.await;
    }
}

fn native_gap_recorder(node: Arc<kronik_sched::Node>, registered: &'static str)
    -> Arc<webhook::MetadataGapRecorder> {
    Arc::new(move |gap, original| {
        let node = node.clone();
        Box::pin(async move {
            if gap.stream != registered {
                return Err(kronik_core::error::ApiError::new(
                    kronik_core::error::ErrorCode::BadRequest, "unregistered metadata stream"));
            }
            node.record_metadata_audit_gap(gap, original).await
        })
    })
}

fn native_metadata_runtime(node: Arc<kronik_sched::Node>, registered: impl Into<Arc<str>>)
    -> webhook::MetadataRuntime {
    let registered = registered.into();
    let authority = node.local_operator_authority().unwrap();
    let config_node = node.clone();
    webhook::MetadataRuntime {
        env: node.env().clone(),
        execution: authority.clone(),
        catalogue: Arc::new(move || native_catalogue(&node)),
        config_recorder: Arc::new(move |change, original| {
            let (node, registered) = (config_node.clone(), registered.clone());
            Box::pin(async move {
                if change.stream != registered.as_ref() {
                    return Err(kronik_core::error::ApiError::new(
                        kronik_core::error::ErrorCode::BadRequest, "unregistered metadata stream"));
                }
                node.record_metadata_webhook_key_change(change, original).await
            })
        }),
    }
}

#[tokio::test]
async fn metadata_without_an_actor_holds_unavailable_certification_without_delivery() {
    use hmac::{KeyInit as _, Mac as _};
    use std::time::Duration;
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(MetadataNetwork::default());
    let mut env = Env::real(tokio::runtime::Handle::current());
    let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
    env.spawner = spawner.clone();
    env.net = network.clone();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    // No actor is deployed. The native boot supplies only its real original
    // execution; its available local catalogue must NOT replace the required
    // unavailable physical catalogue callback.
    let boot = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    assert!(boot.secret_values().is_ok());
    let runtime = webhook::MetadataRuntime {
        env: env.clone(),
        execution: boot.local_operator_authority().unwrap(),
        catalogue: Arc::new(|| Err(kronik_core::error::ApiError::new(
            kronik_core::error::ErrorCode::Unavailable, "physical catalogue is not certified"))),
        config_recorder: Arc::new(|_, _| Box::pin(async {
            Err(kronik_core::error::ApiError::new(
                kronik_core::error::ErrorCode::Unavailable, "physical producer is unavailable"))
        })),
    };
    let recorder: Arc<webhook::MetadataGapRecorder> = Arc::new(|_, _| Box::pin(async {
        Err(kronik_core::error::ApiError::new(
            kronik_core::error::ErrorCode::Unavailable, "physical producer is unavailable"))
    }));
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, message, _original| Box::pin(async move {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-no-actor-key").unwrap();
        mac.update(&message);
        Ok(mac.finalize().into_bytes().into())
    }));
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let binding = configured_stream("events-no-actor:metadata", &cursors, &settings);
    let original = runtime.execution.clone();
    let stream = webhook::start_metadata(runtime, Arc::new(mapper()), identity(),
        binding, cursors.clone(), settings, resolver,
        Arc::new(metadata_image()), recorder).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while stream.progress().unwrap().last_error.as_deref() != Some("UNAVAILABLE") {
            env.clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), stream.stream().stop_and_join())
        .await.unwrap().unwrap();
    assert!(original.check().is_ok());
    spawner.stop().await;
    assert!(network.requests.lock().unwrap().is_empty());
    let entry = cursors.get("events-no-actor:metadata").unwrap();
    assert_eq!(webhook::cursor_source(&entry).unwrap(), SourcePos::Metadata { index: 0 });
    assert!(entry.state["pending"].is_null());
}

#[tokio::test]
async fn metadata_worker_restart_rotates_next_pin_but_retries_pending_pin_and_replay_identity() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    const KEY: &[u8] = b"dummy-metadata-unit-key";
    const NEXT_KEY: &[u8] = b"dummy-metadata-unit-next-key";
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(MetadataNetwork::default());
    let mut env = Env::real(tokio::runtime::Handle::current());
    let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
    env.spawner = spawner.clone();
    env.net = network.clone();
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let execution = node.local_operator_authority().unwrap();
    // These real catalogue values collide with closed metadata markers and
    // numeric versions. Only typed facts may retain their canonical spelling.
    for (name, value) in [("keyword-source", b"metadata".as_slice()), ("keyword-version", b"7".as_slice())] {
        node.secret_set(name, value.to_vec(), &audit().unwrap(), false,
            execution.clone()).await.unwrap().unwrap();
    }
    // Mutation invalidates the previous inventory certificate. Complete the
    // real retained-ledger/file closure before this fixture starts delivery;
    // never replace unavailable certification with an empty catalogue or TTL.
    node.refresh_secret_inventory(execution.clone()).await.unwrap();
    let catalogue = node.secret_values().unwrap();
    assert!(catalogue.iter().any(|(name, value)| name == "keyword-source" && value.as_slice() == b"metadata"));
    assert!(catalogue.iter().any(|(name, value)| name == "keyword-version" && value.as_slice() == b"7"));
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let allowed = Arc::new(AtomicBool::new(true));
    let pins = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (resolve_allowed, resolve_pins) = (allowed.clone(), pins.clone());
    let resolver: Arc<webhook::Resolver> = Arc::new(move |pin, message, _original| {
        let (allowed, pins) = (resolve_allowed.clone(), resolve_pins.clone());
        Box::pin(async move {
            pins.lock().unwrap().push(pin.clone());
            let key = match pin.version {
                7 => {
                    assert_eq!(pin.version_hash, [7;16]);
                    if !allowed.load(Ordering::SeqCst) { return Err("SECRET_UNAVAILABLE".into()); }
                    KEY
                },
                8 => { assert_eq!(pin.version_hash, [8;16]); NEXT_KEY },
                _ => panic!("unexpected immutable version"),
            };
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(&message);
            Ok(mac.finalize().into_bytes().into())
        })
    });
    let mut runtime = native_metadata_runtime(node.clone(), "events-runner:metadata");
    let config_allowed = Arc::new(AtomicBool::new(false));
    let (permit_config, fixed_config) = (config_allowed.clone(), runtime.config_recorder.clone());
    runtime.config_recorder = Arc::new(move |change, original| {
        if !permit_config.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(kronik_core::error::ApiError::new(
                    kronik_core::error::ErrorCode::Unavailable, "configuration audit unavailable"))
            });
        }
        fixed_config(change, original)
    });
    let binding = configured_stream("events-runner:metadata", &cursors, &settings);
    let first_stream = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(), binding,
        cursors.clone(), settings.clone(), resolver.clone(), Arc::new(metadata_image()),
        native_gap_recorder(node.clone(), "events-runner:metadata")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while network.requests.lock().unwrap().is_empty() {
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    spawner.stop().await;
    drop(first_stream);
    let before = cursors.get("events-runner:metadata").unwrap();
    assert_eq!(before.lsn, 0);
    assert_eq!(before.state["pending"]["pin"]["version"], 7);
    let mut missing_pin = before.state["pending"].clone();
    missing_pin.as_object_mut().unwrap().remove("pin");
    assert!(serde_json::from_value::<webhook::Batch>(missing_pin).is_err());
    let mut rotated = settings.clone();
    rotated.secret.version = 8;
    rotated.secret.version_hash = [8;16];
    allowed.store(false, Ordering::SeqCst);
    let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let binding = configured_stream("events-runner:metadata", &cursors, &rotated);
    let refused = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(),
        binding, cursors.clone(), rotated.clone(), resolver.clone(),
        Arc::new(metadata_image()), native_gap_recorder(node.clone(), "events-runner:metadata")).await;
    let refused = match refused { Ok(_) => panic!("an unaudited pin must not activate"), Err(error) => error };
    assert_eq!(refused.code, kronik_core::error::ErrorCode::Unavailable);
    assert_eq!(cursors.get("events-runner:metadata").unwrap(), before);
    assert_eq!(network.requests.lock().unwrap().len(), 1);
    config_allowed.store(true, Ordering::SeqCst);
    let binding = configured_stream("events-runner:metadata", &cursors, &rotated);
    let stream = webhook::start_metadata(runtime, Arc::new(mapper()), identity(), binding,
        cursors.clone(), rotated.clone(), resolver, Arc::new(metadata_image()),
        native_gap_recorder(node.clone(), "events-runner:metadata")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while stream.progress().unwrap().last_error.as_deref() != Some("SECRET_UNAVAILABLE") {
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let observed_reader = node.capture_system_export_reader().await.unwrap();
    let observed = observed_reader.local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    let mut changes = Vec::new();
    for (source, record) in observed.records {
        if let Record::AuditEvent(event) = &record.record
            && event.action == "audit.config" && event.target == "events-runner:metadata" {
            assert_eq!(source.lsn, record.lsn);
            changes.push(record);
        }
    }
    assert_eq!(changes.len(), 1);
    let Record::AuditEvent(change_event) = &changes[0].record else { unreachable!() };
    let change = kronik_log::MetadataWebhookKeyChange::from_event(change_event).unwrap();
    assert_eq!(change, kronik_log::MetadataWebhookKeyChange {
        stream: "events-runner:metadata".into(), from_version: 7, to_version: 8,
    });
    assert_eq!(change_event.details, change.to_details());
    assert_eq!(change_event.details["source"], "metadata");
    assert_eq!(change_event.details["from_version"], "7");
    let pending = cursors.get("events-runner:metadata").unwrap();
    assert_eq!(pending.state["secret"], serde_json::to_value(&rotated.secret).unwrap());
    assert_eq!(pending.state["pending"], before.state["pending"]);
    assert_eq!(pending.lsn, 0);
    assert_eq!(network.requests.lock().unwrap().len(), 1);
    assert!(pins.lock().unwrap().iter().all(|pin| pin == &settings.secret));
    allowed.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), async {
        while stream.progress().unwrap().cursor != (SourcePos::Metadata { index: 9 }) {
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    {
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].headers, requests[1].headers);
    }
    let entry = cursors.get("events-runner:metadata").unwrap();
    assert_eq!(webhook::cursor_source(&entry).unwrap(), SourcePos::Metadata { index: 9 });
    assert_eq!(entry.state["secret"], serde_json::to_value(&rotated.secret).unwrap());
    assert!(entry.state["pending"].is_null());
    assert!(!serde_json::to_string(&entry).unwrap().contains(std::str::from_utf8(KEY).unwrap()));
    let denied = stream.rewind(Position { source: SourcePos::Metadata { index: 2 }, subindex: 0 },
        Arc::new(RevokedAuthority)).await.unwrap_err();
    assert_eq!(denied.code, kronik_core::error::ErrorCode::Unauthenticated);
    assert_eq!(cursors.get("events-runner:metadata").unwrap(), entry);
    stream.rewind(Position { source: SourcePos::Metadata { index: 2 }, subindex: 0 }, execution.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let entry = cursors.get("events-runner:metadata").unwrap();
            if entry.lsn == 9 && entry.generation() != [0;16] && entry.pending_rewind().is_none() { break; }
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    spawner.stop().await;
    let requests = network.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].body, requests[3].body);
    assert_eq!(requests[2].body, requests[4].body);
    for (index, request) in requests.iter().enumerate() {
        let event: events::Event = serde_json::from_slice(&request.body).unwrap();
        assert!(matches!(event.source, SourcePos::Metadata { .. }));
        assert!(event.branch.is_none());
        let header = |name: &str| request.headers.iter().find(|(key, _)| key == name).unwrap().1.as_str();
        assert_eq!(header("kronik-event-id"), event.id);
        let timestamp = header("kronik-timestamp-ms").parse().unwrap();
        let key = if index < 2 { KEY } else { NEXT_KEY };
        assert_eq!(header("kronik-signature"), webhook::signature(key, timestamp, &event.id, &request.body).unwrap());
    }
}

#[test]
fn metadata_unit_control_projection_has_closed_phase_without_actor_provenance() {
    for (record, action, phase) in control_fixtures() {
        let record = Record::decode(record.kind(), &record.encode()).unwrap();
        // An explicit unit coordinate, not derived from an actor log or claimed committed.
        let source = SourcePos::Metadata { index: 77 };
        let envelope = MetadataAuditRecord { index: 77, record, native_origin: None };
        let event = events::project_metadata(&mapper(), &identity(), &envelope, &[]).unwrap().remove(0);
        assert_eq!(event.source, source);
        assert!(event.branch.is_none());
        assert_eq!(event.data.action, action);
        assert_eq!(event.data.phase, phase);
        assert_eq!(event.data.epoch, phase.map(|_| 1));
        assert!(event.id.starts_with("ke1.696e7374616c6c6174696f6e2d31.metadata.77.0."));
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        assert!(!body.contains("\"branch\""));
        assert!(!body.contains("\"lsn\""));
        assert!(!body.contains("raw-reason-PII-NEEDLE"));
        assert!(!body.contains("raw-name-PII-NEEDLE"));
    }
}

#[test]
fn cursor_bound_covers_every_actual_source_and_rejects_overflow_without_truncation() {
    let mut identity = identity();
    identity.installation = "i".repeat(128);
    identity.branch = "b".repeat(128);
    let mut cursor = ResumeCursor::new(identity.clone());
    cursor.streams = (0..kronik_proto::MAX_SHARD_COUNT).map(|shard| {
        let source = SourcePos::Actor { shard: Some(shard), lsn: u64::MAX };
        (events::domain(source).into_owned(), Position { source, subindex: u32::MAX })
    }).collect();
    for source in [native(u64::MAX), SourcePos::Metadata { index: u64::MAX }] {
        cursor.streams.insert(events::domain(source).into_owned(), Position { source, subindex: u32::MAX });
    }
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS);
    cursor.validate(&identity).unwrap();
    let encoded = serde_json::to_vec(&cursor).unwrap();
    // Payload-only coverage, deliberately not a claim about HTTP header limits.
    assert!(encoded.len() > 65_536);
    assert!(encoded.len() <= events::MAX_CURSOR_BYTES);
    let decoded: ResumeCursor = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, cursor);
    assert_eq!(events::schemas().unwrap()["$defs"]["cursor"]["properties"]["streams"]["maxProperties"],
        events::MAX_STREAMS);
    assert!(cursor.rewind(Position { source: SourcePos::Actor {
        shard: Some(kronik_proto::MAX_SHARD_COUNT), lsn: 1 }, subindex: 0 }).is_err());
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS);
    cursor.streams.insert("overflow".into(), Position { source: native(1), subindex: 0 });
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS + 1);
    assert!(cursor.validate(&identity).is_err());
}

fn logout_wire_record(metadata: bool) -> (Record, serde_json::Value) {
    use prost::Message as _;
    let fixture: serde_json::Value = serde_json::from_str(if metadata {
        include_str!("../../kronik-proto/tests/fixtures/auth-session-revoked-metadata-v1.json")
    } else {
        include_str!("../../kronik-proto/tests/fixtures/auth-session-revoked-native-v1.json")
    }).unwrap();
    let wire = kronik_core::ids::unhex(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let operation = pb::AuthSessionRevoked::decode(wire.as_slice()).unwrap();
    assert_eq!(operation.encode_to_vec(), wire);
    let record = Record::AuditEvent(pb::AuditEvent { action: "auth.logout".into(),
        audit: Some(pb::Audit { token_id: format!("oidc:{}", kronik_core::ids::hex(&operation.principal_hash)),
            reason: "logout cookie-private-NEEDLE".into(), wall_time_ms: 1 }),
        operation: Some(pb::audit_event::Operation::AuthSessionRevoked(operation)), ..Default::default() });
    (Record::decode(record.kind(), &record.encode()).unwrap(), fixture)
}

fn assert_private_auth_event(record: &Record, fixture: &serde_json::Value, source: SourcePos, action: &str) {
    let mapper = mapper();
    let secrets = [("cookie", b"cookie-private-NEEDLE".as_slice()),
        ("claims", b"private-claims-NEEDLE".as_slice()),
        ("principal", fixture["principal_hash"].as_str().unwrap().as_bytes()),
        ("token-name", b"operator".as_slice())];
    let project = |record: &Record| match source {
        SourcePos::Actor { shard, lsn } => events::project(&mapper, &identity(),
            &pb::ActorSource { shard, lsn, branch: "main".into() }, record, &secrets),
        SourcePos::Metadata { index } => events::project_metadata(&mapper, &identity(),
            &MetadataAuditRecord { index, record: record.clone(), native_origin: None }, &secrets),
    };
    let event = project(record).unwrap().remove(0);
    assert_eq!(event.record_kind, 40);
    assert_eq!(event.source, source);
    assert_eq!(event.data.schema, "kronik.audit/v3");
    assert_eq!(event.data.kind, "audit_event");
    assert_eq!(event.data.action, action);
    assert_eq!(event.data.at_wall_ms, 1);
    assert_eq!((event.data.epoch, event.data.effect, event.data.phase), (None, None, None));
    assert_eq!(Some(event.data.record_hash.clone()), kronik_otel::audit::record_hash(record, &mapper.sealer));
    let body = event.body().unwrap();
    let published: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for private in ["details", "token_id", "reason", "session_hash", "principal_hash", "config_digest",
        "config_source", "token_name", "expires_at_ms", "metadata_token", "peer_boot"] {
        assert!(published["data"].get(private).is_none());
    }
    assert!(!String::from_utf8_lossy(&body).contains("cookie-private-NEEDLE"));
    assert!(!String::from_utf8_lossy(&body).contains("private-claims-NEEDLE"));
    assert!(!String::from_utf8_lossy(&body).contains(fixture["principal_hash"].as_str().unwrap()));
    assert_eq!(event.branch.is_none(), matches!(source, SourcePos::Metadata { .. }));
    assert_eq!(project(record).unwrap()[0].body().unwrap(), body);
    let mut invalid = record.clone();
    let Record::AuditEvent(audit) = &mut invalid else { unreachable!() };
    audit.details.insert("cookie".into(), "cookie-private-NEEDLE".into());
    assert_eq!(project(&invalid).unwrap_err().code,
        kronik_core::error::ErrorCode::StorageCorrupt);
}

#[tokio::test]
async fn native_logout_wire_record_is_fsynced_and_public_event_omits_session_identity() {
    let (record, fixture) = logout_wire_record(false);
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let lsn = log.append(record).await.unwrap();
    let record = committed.recv().await.unwrap();
    assert_eq!(record.lsn, lsn);
    assert_private_auth_event(&record.record, &fixture, native(record.lsn), "auth.logout");
}

#[test]
fn metadata_logout_wire_record_unit_projection_has_no_actor_or_session_identity_alias() {
    let (record, fixture) = logout_wire_record(true);
    // Fixture projection coordinate only: actual durable metadata consumer proof is separate.
    assert_private_auth_event(&record, &fixture, SourcePos::Metadata { index: 32 }, "auth.logout");
}

#[tokio::test]
async fn dynamic_webhook_names_are_owned_released_and_persist_beyond_sixty_four_targets() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, _, _original| Box::pin(async { panic!("opening a stream must not resolve a key") }));
    let mut sinks = Vec::new();
    let mut names = Vec::new();
    for number in 0..65 {
        let name: Arc<str> = format!("events-owned-{number}:metadata").into();
        names.push(Arc::downgrade(&name));
        let stream = configured_stream(name.clone(), &cursors, &settings);
        sinks.push(Webhook::open_metadata(native_metadata_runtime(node.clone(), name.clone()),
            Arc::new(mapper()), identity(), stream,
            cursors.clone(), settings.clone(), resolver.clone()).await.unwrap());
        drop(name);
        assert!(names.last().unwrap().upgrade().is_some());
    }
    assert_eq!(cursors.names().len(), 65);
    drop(sinks);
    assert!(names.iter().all(|name| name.upgrade().is_none()));
    let reloaded = Cursors::load(env, directory.path()).await.unwrap();
    assert_eq!(reloaded.names().len(), 65);
    for number in 0..65 {
        let name = format!("events-owned-{number}:metadata");
        let entry = reloaded.get(&name).unwrap();
        assert_eq!(webhook::cursor_source(&entry).unwrap(), SourcePos::Metadata { index: 0 });
        assert_eq!(entry.state["secret"], serde_json::to_value(&settings.secret).unwrap());
    }
}

#[test]
fn ordinary_metadata_audit_unit_records_publish_actions_without_identity_or_free_details() {
    let mapper = mapper();
    let secrets = [("fixture-value", b"VALUE-NEEDLE".as_slice())];
    for action in ["token.create", "token.revoke", "cluster.join_token.create", "cluster.leave"] {
        let record = Record::AuditEvent(pb::AuditEvent { action: action.into(),
            target: "target-PII-NEEDLE".into(),
            details: [("operator".into(), "raw-details-PII-NEEDLE".into())].into(),
            audit: audit(), operation: None, ..Default::default() });
        let decoded = Record::decode(record.kind(), &record.encode()).unwrap();
        // Exact record-shape projection only, not a claim of a durable metadata commit.
        let source = SourcePos::Metadata { index: 91 };
        let envelope = MetadataAuditRecord { index: 91, record: decoded, native_origin: None };
        let event = events::project_metadata(&mapper, &identity(), &envelope, &secrets).unwrap().remove(0);
        assert_eq!(event.source, source);
        assert_eq!(event.record_kind, 40);
        assert!(event.branch.is_none());
        assert_eq!(event.data.kind, "audit_event");
        assert_eq!(event.data.action, action);
        assert_eq!(event.data.at_wall_ms, 123);
        assert_eq!((event.data.epoch, event.data.effect, event.data.phase), (None, None, None));
        assert_eq!(Some(event.data.record_hash.clone()), kronik_otel::audit::record_hash(&envelope.record, &mapper.sealer));
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        for private in ["target-PII-NEEDLE", "raw-details-PII-NEEDLE", "raw-reason-PII-NEEDLE",
            "raw-name-PII-NEEDLE", "VALUE-NEEDLE", "\"branch\"", "\"lsn\"", "\"details\""] {
            assert!(!body.contains(private));
        }
    }
}

#[tokio::test]
async fn real_native_audit_free_details_cannot_publish_an_adoption_marker() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, directory.path(), NodeConfig::default()).await.unwrap();
    let original = node.local_operator_authority().unwrap();
    let lsn = node.record_audit_event_authorized("fleet.note", "ordinary-native-note",
        [("native_origin".into(), "{\"current_projection\":true,\"adoption_audit\":\"private-provenance-NEEDLE\"}".into()),
            ("current_projection".into(), "true".into())].into(),
        pb::Audit { token_id: "unix:uid=0".into(), reason: "exercise actual native projection".into(),
            wall_time_ms: node.env().clock.wall_ms() }, original.clone()).await.unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &original).await;
    let page = reader.local_export_page(lsn - 1, 1, kronik_otel::follow::BATCH_BYTES).await.unwrap();
    let (source, committed) = page.records.iter().find(|(_, committed)| committed.lsn == lsn).unwrap();
    let patterns: Vec<_> = snapshot.values.iter()
        .map(|(name, value)| (name.as_str(), value.as_slice())).collect();
    let mapper = Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: node.branch().into() };
    let event = events::project(&mapper, &identity(), source, &committed.record, &patterns).unwrap().remove(0);
    authorization.check().unwrap();
    assert_eq!(event.source, native(lsn));
    assert_eq!(event.data.action, "fleet.note");
    assert!(event.data.adoption.is_none());
    let body = event.body().unwrap();
    let public: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(public["data"].get("adoption").is_none());
    for private in ["native_origin", "current_projection", "adoption_audit", "private-provenance-NEEDLE",
        "unix:uid=0", "exercise actual native projection"] {
        assert!(!String::from_utf8_lossy(&body).contains(private));
    }
}

#[tokio::test]
async fn metadata_pending_restart_precedes_lost_coverage_but_known_coordinate_rewrite_holds() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    for rewrite in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let network = Arc::new(MetadataNetwork::default());
        let mut env = Env::real(tokio::runtime::Handle::current());
        let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
        env.spawner = spawner.clone();
        env.net = network.clone();
        let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
        let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
        let source = Arc::new(MutableMetadataImage(std::sync::RwLock::new(metadata_image())));
        let runtime = native_metadata_runtime(node.clone(), "events-pending:metadata");
        let audit_stage = Arc::new(AtomicUsize::new(0));
        let audit_attempts = Arc::new(AtomicUsize::new(0));
        let receipts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let block_checkpoint = Arc::new(AtomicBool::new(false));
        let blocked = block_checkpoint.clone();
        let fs = node.env().fs.clone();
        let cursor_path = directory.path().join(Cursors::FILE);
        let backup_path = directory.path().join("cursor-before-checkpoint-fault");
        let (target, backup) = (cursor_path.clone(), backup_path.clone());
        let native = native_gap_recorder(node.clone(), "events-pending:metadata");
        let (stage, attempts, recorded, received) = (audit_stage.clone(), audit_attempts.clone(),
            receipts.clone(), network.clone());
        let recorder: Arc<webhook::MetadataGapRecorder> = Arc::new(move |gap, original| {
            let (stage, attempts, recorded, received, native) =
                (stage.clone(), attempts.clone(), recorded.clone(), received.clone(), native.clone());
            let (blocked, fs, target, backup) =
                (blocked.clone(), fs.clone(), target.clone(), backup.clone());
            Box::pin(async move {
                // The old pending event must receive its real retry ACK first.
                assert_eq!(received.requests.lock().unwrap().len(), 2);
                attempts.fetch_add(1, Ordering::SeqCst);
                if stage.load(Ordering::SeqCst) == 0 {
                    return Err(kronik_core::error::ApiError::new(
                        kronik_core::error::ErrorCode::Unavailable, "fixture audit unavailable"));
                }
                let receipt = native(gap.clone(), original).await?;
                recorded.lock().unwrap().push((gap, receipt));
                if stage.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    return Err(kronik_core::error::ApiError::new(
                        kronik_core::error::ErrorCode::Unavailable, "fixture lost durable audit reply"));
                }
                if blocked.swap(false, Ordering::SeqCst) {
                    // Preserve the real old manifest, but make the next actual
                    // atomic file replacement fail with a directory target.
                    fs.rename(target.clone(), backup).await.unwrap();
                    fs.create_dir_all(target.clone()).await.unwrap();
                    fs.sync_dir(target.parent().unwrap().to_path_buf()).await.unwrap();
                }
                Ok(receipt)
            })
        });
        let settings = Settings { url: "http://127.0.0.1:9/events".into(),
            secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
                version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
                reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
        let resolver: Arc<webhook::Resolver> = Arc::new(|pin, message, _original| Box::pin(async move {
            assert_eq!(pin.version, 7);
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-pending-gap-key").unwrap();
            mac.update(&message);
            Ok(mac.finalize().into_bytes().into())
        }));
        let binding = configured_stream("events-pending:metadata", &cursors, &settings);
        let first = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(), binding,
            cursors.clone(), settings.clone(), resolver.clone(), source.clone(),
            recorder.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while network.requests.lock().unwrap().is_empty() {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        drop(first);
        let before = cursors.get("events-pending:metadata").unwrap();
        assert_eq!(before.lsn, 0);
        assert!(!before.state["pending"].is_null());
        {
            let mut image = source.0.write().unwrap();
            image.floor = 4;
            if rewrite {
                let Record::AuditEvent(record) = &mut image.records.get_mut(&2).unwrap().record else { unreachable!() };
                record.audit.as_mut().unwrap().wall_time_ms += 1;
            }
        }
        let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
        let binding = configured_stream("events-pending:metadata", &cursors, &settings);
        let restarted = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(), binding,
            cursors.clone(), settings.clone(), resolver.clone(), source.clone(),
            recorder.clone()).await.unwrap();
        let error = if rewrite { "webhook_history_conflict" } else { "UNAVAILABLE" };
        tokio::time::timeout(Duration::from_secs(3), async {
            while restarted.progress().unwrap().last_error.as_deref() != Some(error) {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        let after = cursors.get("events-pending:metadata").unwrap();
        {
            let requests = network.requests.lock().unwrap();
            if rewrite {
                assert_eq!(after, before);
                assert_eq!(requests.len(), 1);
                assert_eq!(audit_attempts.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(after.lsn, 2); // Only the pending record's real remote ACK.
                assert!(after.state["pending"].is_null());
                assert_eq!(requests.len(), 2);
                assert_eq!(requests[0].body, requests[1].body);
                assert_eq!(requests[0].headers, requests[1].headers);
                assert!(audit_attempts.load(Ordering::SeqCst) > 0);
                assert!(receipts.lock().unwrap().is_empty());
            }
        }
        assert_eq!(after.generation(), before.generation());
        assert!(source.0.read().unwrap().records.contains_key(&2));
        if rewrite { continue; }

        // Fail after the real fixed native producer's durable receipt, then
        // restart before its retry: no cursor advance is allowed on lost reply.
        audit_stage.store(1, Ordering::SeqCst);
        let reloaded = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
        let binding = configured_stream("events-pending:metadata", &reloaded, &settings);
        let lost_reply = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(),
            binding, reloaded.clone(), settings.clone(), resolver.clone(),
            source.clone(), recorder.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while receipts.lock().unwrap().is_empty()
                || lost_reply.progress().unwrap().last_error.as_deref() != Some("UNAVAILABLE") {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        assert_eq!(reloaded.get("events-pending:metadata").unwrap(), after);
        let (notice, receipt) = receipts.lock().unwrap()[0].clone();
        assert_eq!(notice, kronik_log::MetadataAuditGap {
            stream: "events-pending:metadata".into(), from_index: 3, through_index: 3,
        });
        let SourcePos::Actor { shard: None, lsn } = receipt else {
            panic!("native fixed producer must return its actual actor receipt");
        };
        let observed_reader = node.capture_system_export_reader().await.unwrap();
        let observed = observed_reader.local_export_page(lsn - 1, 1, kronik_otel::follow::BATCH_BYTES).await.unwrap();
        let (source, committed) = observed.records.iter().find(|(source, _)| source.lsn == lsn).unwrap();
        assert_eq!(source.lsn, committed.lsn);
        let Record::AuditEvent(event) = &committed.record else { unreachable!() };
        assert_eq!(event.action, "audit.gap");
        assert!(event.target.is_empty());
        assert_eq!(event.details, notice.to_details());
        assert!(event.audit.as_ref().unwrap().reason.contains("coverage"));
        assert!(!event.audit.as_ref().unwrap().reason.contains("retention"));

        block_checkpoint.store(true, Ordering::SeqCst);
        let fault_cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
        let binding = configured_stream("events-pending:metadata", &fault_cursors, &settings);
        let checkpoint_failure = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(),
            binding, fault_cursors.clone(), settings.clone(), resolver.clone(),
            source.clone(), recorder.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while checkpoint_failure.progress().unwrap().last_error.as_deref() != Some("webhook_checkpoint") {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        assert_eq!(fault_cursors.get("events-pending:metadata").unwrap(), after);
        node.env().fs.rename(cursor_path.clone(), directory.path().join("checkpoint-fault-directory")).await.unwrap();
        node.env().fs.rename(backup_path, cursor_path).await.unwrap();
        node.env().fs.sync_dir(directory.path().to_path_buf()).await.unwrap();
        let resumed_cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
        assert_eq!(resumed_cursors.get("events-pending:metadata").unwrap(), after);
        let binding = configured_stream("events-pending:metadata", &resumed_cursors, &settings);
        let resumed = webhook::start_metadata(runtime, Arc::new(mapper()), identity(),
            binding, resumed_cursors.clone(), settings, resolver,
            source.clone(), recorder).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while resumed.progress().unwrap().cursor != (SourcePos::Metadata { index: 9 }) {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        {
            let recorded = receipts.lock().unwrap();
            assert_eq!(recorded.len(), 3);
            assert!(recorded.iter().all(|entry| entry == &recorded[0]),
                "lost reply and checkpoint failure retry the exact durable marker");
        }
        assert_eq!(node.applied_lsn(), lsn, "deduplication must not append another audit");
        let resumed_entry = resumed_cursors.get("events-pending:metadata").unwrap();
        assert_eq!(resumed_entry.generation(), before.generation());
        assert!(resumed_entry.state["pending"].is_null());
        assert_eq!(resumed.progress().unwrap().gaps, 1);
        assert!(source.0.read().unwrap().records.contains_key(&2));
        assert_eq!(source.0.read().unwrap().floor, 4);
        {
            let requests = network.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            let future: events::Event = serde_json::from_slice(&requests[2].body).unwrap();
            assert_eq!(future.source, SourcePos::Metadata { index: 5 });
            assert_eq!(future.data.action, "auth.config");
        }

        // This remains a captured-image UNIT coordinate, not a claimed MetaRaft
        // commit. Its shape comes from the actual record45 compatibility wire.
        let future = Record::decode(45, &kronik_core::ids::unhex(
            include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex").trim()).unwrap()).unwrap();
        {
            let mut image = source.0.write().unwrap();
            image.records.insert(12, MetadataAuditRecord { index: 12, record: future, native_origin: None });
            image.head = 12;
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while resumed.progress().unwrap().cursor != (SourcePos::Metadata { index: 12 }) {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        let future: events::Event = serde_json::from_slice(&requests[3].body).unwrap();
        assert_eq!(future.record_kind, 45);
        assert_eq!(future.source, SourcePos::Metadata { index: 12 });
        assert_eq!(future.data.action, "secret.version");
        assert!(future.branch.is_none());
    }
}

#[tokio::test]
async fn metadata_gap_uses_fresh_coverage_not_the_stale_page_range() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    struct CoverageChange {
        reads: AtomicUsize,
        first: MetadataImage,
        later: MetadataImage,
    }
    impl kronik_log::MetadataAuditSource for CoverageChange {
        fn read_from(&self, from: u64, limit: usize)
            -> Result<kronik_log::MetadataAuditBatch, kronik_core::error::ApiError> {
            let image = if self.reads.fetch_add(1, Ordering::SeqCst) == 0 { &self.first } else { &self.later };
            kronik_log::MetadataAuditSource::read_from(image, from, limit)
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(MetadataNetwork::default());
    let mut env = Env::real(tokio::runtime::Handle::current());
    let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
    env.spawner = spawner.clone();
    env.net = network.clone();
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    // Each read captures a complete UNIT image. The actual coverage floor can
    // advance after a public page; literal indexes do not claim a Raft commit.
    let mut later = MetadataImage { floor: 6, ..metadata_image() };
    later.records.insert(8, MetadataAuditRecord { index: 8, record: Record::decode(45, &kronik_core::ids::unhex(
        include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex").trim()).unwrap()).unwrap(),
        native_origin: None });
    let source = Arc::new(CoverageChange {
        reads: AtomicUsize::new(0), first: MetadataImage { floor: 4, ..metadata_image() }, later,
    });
    let native = native_gap_recorder(node.clone(), "events-fresh-gap:metadata");
    let recorded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let notices = recorded.clone();
    let recorder: Arc<webhook::MetadataGapRecorder> = Arc::new(move |gap, original| {
        let (native, notices) = (native.clone(), notices.clone());
        Box::pin(async move {
            let receipt = native(gap.clone(), original).await?;
            notices.lock().unwrap().push((gap, receipt));
            Ok(receipt)
        })
    });
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, message, _original| Box::pin(async move {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-fresh-coverage-key").unwrap();
        mac.update(&message);
        Ok(mac.finalize().into_bytes().into())
    }));
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let binding = configured_stream("events-fresh-gap:metadata", &cursors, &settings);
    let stream = webhook::start_metadata(native_metadata_runtime(node.clone(), "events-fresh-gap:metadata"),
        Arc::new(mapper()), identity(),
        binding, cursors.clone(), settings, resolver, source.clone(), recorder).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while stream.progress().unwrap().cursor != (SourcePos::Metadata { index: 9 }) {
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    spawner.stop().await;
    let notices = recorded.lock().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].0, kronik_log::MetadataAuditGap {
        stream: "events-fresh-gap:metadata".into(), from_index: 1, through_index: 5,
    });
    assert!(matches!(notices[0].1, SourcePos::Actor { shard: None, lsn } if lsn > 0));
    assert_eq!(cursors.get("events-fresh-gap:metadata").unwrap().generation(), [0;16]);
    assert!(source.later.records.contains_key(&2));
    assert!(source.later.records.contains_key(&5));
    let requests = network.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    let event: events::Event = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(event.source, SourcePos::Metadata { index: 8 });
    assert_eq!(event.record_kind, 45);
    assert_eq!(event.data.action, "secret.version");
}

#[tokio::test]
async fn metadata_gap_receipt_preserves_a_late_durable_rewind_generation() {
    use hmac::{KeyInit as _, Mac as _};
    use std::time::Duration;
    let directory = tempfile::tempdir().unwrap();
    let network = Arc::new(MetadataNetwork::default());
    let mut env = Env::real(tokio::runtime::Handle::current());
    let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
    env.spawner = spawner.clone();
    env.net = network.clone();
    let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
    let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    // Literal metadata-image indexes are unit coordinates, not MetaRaft proof.
    let source = Arc::new(MutableMetadataImage(std::sync::RwLock::new(
        MetadataImage { floor: 4, ..metadata_image() })));
    let native = native_gap_recorder(node.clone(), "events-gap-race:metadata");
    let permits = Arc::new(tokio::sync::Semaphore::new(0));
    let (receipts, mut received) = tokio::sync::mpsc::unbounded_channel();
    let release = permits.clone();
    let recorder: Arc<webhook::MetadataGapRecorder> = Arc::new(move |gap, original| {
        let (native, receipts, release) = (native.clone(), receipts.clone(), release.clone());
        Box::pin(async move {
            let receipt = native(gap.clone(), original).await?;
            receipts.send((gap, receipt)).unwrap();
            release.acquire().await.unwrap().forget();
            Ok(receipt)
        })
    });
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, message, _original| Box::pin(async move {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-gap-race-key").unwrap();
        mac.update(&message);
        Ok(mac.finalize().into_bytes().into())
    }));
    let settings = Settings { url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
            version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
            reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
    let binding = configured_stream("events-gap-race:metadata", &cursors, &settings);
    let stream = webhook::start_metadata(native_metadata_runtime(node.clone(), "events-gap-race:metadata"),
        Arc::new(mapper()), identity(),
        binding, cursors.clone(), settings, resolver, source.clone(), recorder).await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(3), received.recv()).await.unwrap().unwrap();
    assert_eq!(first.0, kronik_log::MetadataAuditGap {
        stream: "events-gap-race:metadata".into(), from_index: 1, through_index: 3,
    });
    let before = cursors.get("events-gap-race:metadata").unwrap();
    assert_eq!(before.lsn, 0, "a durable audit is not yet a durable cursor checkpoint");
    assert_eq!(before.generation(), [0;16]);
    // Exercise the actual existing durable cursor writer while the receipt is
    // in flight. This is a control-merge unit test, not a public API admission
    // or an assertion that a below-floor replay would pass API validation.
    let generation = [9;16];
    let rewind = cursors.request_rewind("events-gap-race:metadata", generation, 0).await.unwrap();
    assert_eq!(rewind.to, 0);
    assert_eq!(cursors.get("events-gap-race:metadata").unwrap().lsn, 0);
    permits.add_permits(1);
    let second = tokio::time::timeout(Duration::from_secs(3), received.recv()).await.unwrap().unwrap();
    assert_eq!(second, first, "the already durable notice must be deduplicated");
    let active = cursors.get("events-gap-race:metadata").unwrap();
    assert_eq!(active.lsn, 0);
    assert_eq!(active.generation(), generation);
    assert_eq!(webhook::cursor_source(&active).unwrap(), SourcePos::Metadata { index: 0 });
    permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), async {
        while stream.progress().unwrap().cursor != (SourcePos::Metadata { index: 9 }) {
            node.env().clock.sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    spawner.stop().await;
    let final_entry = cursors.get("events-gap-race:metadata").unwrap();
    assert_eq!(final_entry.generation(), generation);
    assert!(final_entry.pending_rewind().is_none());
    assert!(final_entry.state["pending"].is_null());
    assert_eq!(stream.progress().unwrap().gaps, 1);
    assert!(source.0.read().unwrap().records.contains_key(&2));
    assert_eq!(source.0.read().unwrap().floor, 4);
    let requests = network.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    let event: events::Event = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(event.source, SourcePos::Metadata { index: 5 });
    assert_eq!(event.data.action, "auth.config");
}

fn login_wire_record(metadata: bool) -> (Record, serde_json::Value) {
    use prost::Message as _;
    let fixture: serde_json::Value = serde_json::from_str(if metadata {
        include_str!("../../kronik-proto/tests/fixtures/auth-oidc-login-metadata-v1.json")
    } else {
        include_str!("../../kronik-proto/tests/fixtures/auth-oidc-login-native-v1.json")
    }).unwrap();
    let wire = kronik_core::ids::unhex(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let login = pb::AuthOidcLogin::decode(wire.as_slice()).unwrap();
    assert_eq!(login.encode_to_vec(), wire);
    let record = Record::AuditEvent(pb::AuditEvent { action: "auth.oidc.login".into(),
        audit: Some(pb::Audit { token_id: format!("oidc:{}", kronik_core::ids::hex(&login.principal_hash)),
            reason: "login private-claims-NEEDLE".into(), wall_time_ms: 1 }),
        operation: Some(pb::audit_event::Operation::AuthOidcLogin(login)), ..Default::default() });
    (Record::decode(record.kind(), &record.encode()).unwrap(), fixture)
}

#[tokio::test]
async fn native_login_wire_record_is_fsynced_and_public_event_omits_claims_and_principal() {
    let (record, fixture) = login_wire_record(false);
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let lsn = log.append(record).await.unwrap();
    let record = committed.recv().await.unwrap();
    assert_eq!(record.lsn, lsn);
    assert_private_auth_event(&record.record, &fixture, native(record.lsn), "auth.oidc.login");
}

#[test]
fn metadata_login_wire_record_unit_projection_has_no_actor_or_private_identity_alias() {
    let (record, fixture) = login_wire_record(true);
    // Explicit unit coordinate, not a claimed metadata/Raft commit.
    assert_private_auth_event(&record, &fixture, SourcePos::Metadata { index: 18 }, "auth.oidc.login");
}

#[tokio::test]
async fn approval_wire_records_keep_protected_identity_private_and_value_only_reseal_identity_stable() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, mut commits) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, _failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(&env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"), send, fatal).await.unwrap();
    let mapper = mapper();
    for (wire, protected) in [
        (include_str!("../../kronik-proto/tests/fixtures/approval-native-v1.hex"), false),
        (include_str!("../../kronik-proto/tests/fixtures/approval-verified-identity-v1.hex"), true),
    ] {
        let record = Record::decode(8, &kronik_core::ids::unhex(wire.trim()).unwrap()).unwrap();
        let lsn = log.append(record).await.unwrap();
        let committed = commits.recv().await.unwrap();
        assert_eq!(committed.lsn, lsn);
        let event = events::project(&mapper, &identity(), &main_frame(lsn), &committed.record, &[]).unwrap().remove(0);
        assert_eq!((event.record_kind, event.data.kind.as_str(), event.data.action.as_str()), (8, "approval", "approve"));
        assert_eq!(event.data.at_wall_ms, 1);
        assert_eq!((event.data.epoch, event.data.effect, event.data.phase), (None, None, None));
        let body = event.body().unwrap();
        let published: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for private in ["verified_identity", "token_id", "reason", "details", "subject", "email", "display_name"] {
            assert!(published["data"].get(private).is_none());
        }
        assert!(!String::from_utf8_lossy(&body).contains("oidc:"));
        assert!(!String::from_utf8_lossy(&body).contains("unix:uid"));
        if protected {
            let mut resealed = committed.record.clone();
            let Record::Approval(approval) = &mut resealed else { unreachable!() };
            let Some(pb::sealable::Value::Sealed(value)) = approval.verified_identity.as_mut().unwrap().value.as_mut()
                else { panic!("the actual protected fixture must be sealed") };
            value.key_version += 1;
            value.nonce.fill(4);
            value.ciphertext.fill(5);
            let resealed = Record::decode(resealed.kind(), &resealed.encode()).unwrap();
            assert_ne!(resealed.encode(), committed.record.encode());
            // Unit reseal mutation at the original position, not another commit
            // or a claim that all changed records must change their identity.
            let same = events::project(&mapper, &identity(), &main_frame(lsn), &resealed, &[]).unwrap().remove(0);
            assert_eq!(same.id, event.id);
            assert_eq!(same.body().unwrap(), body);
        }
    }
}

#[tokio::test]
async fn real_http_execution_fence_rejects_after_mac_and_owns_already_admitted_delivery() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct HttpJobs {
        inner: Arc<dyn kronik_core::env::Spawner>,
        started_jobs: Arc<AtomicUsize>,
        completed: Arc<tokio::sync::Notify>,
    }
    impl kronik_core::env::Spawner for HttpJobs {
        fn spawn(&self, name: &'static str, work: kronik_core::env::BoxFuture<'static, ()>) {
            if name == "events-http" {
                self.started_jobs.fetch_add(1, Ordering::SeqCst);
                let completed = self.completed.clone();
                self.inner.spawn(name, Box::pin(async move {
                    work.await;
                    completed.notify_one();
                }));
            } else { self.inner.spawn(name, work); }
        }
        fn spawn_blocking(&self, name: &'static str, work: Box<dyn FnOnce() + Send + 'static>) {
            self.inner.spawn_blocking(name, work);
        }
    }
    async fn receive(stream: &mut tokio::net::TcpStream) -> (BTreeMap<String, String>, bytes::Bytes) {
        let mut wire = Vec::new();
        let mut buffer = [0;4096];
        let end = loop {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&buffer[..n]);
            assert!(wire.len() <= events::MAX_PAGE_BYTES + 8192);
            if let Some(at) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break at + 4; }
        };
        let mut lines = std::str::from_utf8(&wire[..end]).unwrap().split("\r\n");
        assert_eq!(lines.next().unwrap(), "POST /events HTTP/1.1");
        let mut headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').unwrap();
            assert!(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
        }
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(length <= events::MAX_PAGE_BYTES);
        while wire.len() < end + length {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&buffer[..n]);
            assert!(wire.len() <= events::MAX_PAGE_BYTES + 8192);
        }
        assert_eq!(wire.len(), end + length);
        (headers, bytes::Bytes::from(wire).slice(end..))
    }
    const KEY: &[u8] = b"dummy-real-http-execution-key";
    for revoke_after_mac in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let started_jobs = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(tokio::sync::Notify::new());
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.spawner = Arc::new(HttpJobs { inner: env.spawner.clone(),
            started_jobs: started_jobs.clone(), completed: completed.clone() });
        let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
        let execution = node.local_operator_authority().unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = format!("http://{}/events", listener.local_addr().unwrap());
        let settings = Settings { url,
            secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
                version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
                reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
        let signing_node = node.clone();
        let resolver: Arc<webhook::Resolver> = Arc::new(move |_, message, _original| {
            let node = signing_node.clone();
            Box::pin(async move {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(KEY).unwrap();
                mac.update(&message);
                let result = mac.finalize().into_bytes().into();
                // Real physical publication occurs AFTER computing the MAC and
                // before returning it: a check-before-sign implementation loses.
                if revoke_after_mac { node.stop_native_execution().unwrap(); }
                Ok(result)
            })
        });
        let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
        let mapper = Arc::new(Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: "main".into() });
        let stream = configured_stream("events-http-fence:actor-native", &cursors, &settings);
        let mut sink = Webhook::open(node.clone(), mapper.clone(), identity(), None,
            stream.clone(), cursors.clone(), settings, resolver, execution.clone()).await.unwrap();
        let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
        let patterns: Vec<_> = snapshot.values.iter().map(|(name, value)| (name.as_str(), value.as_slice())).collect();
        let page = reader.local_export_page(0, 1, kronik_otel::follow::BATCH_BYTES).await.unwrap();
        let (frame, committed) = page.records.iter().find(|(_, record)| matches!(record.record, Record::SecretVersion(_))).unwrap();
        let source = SourcePos::Actor { shard: frame.shard, lsn: frame.lsn };
        let expected = events::project(&mapper, &identity(), frame, &committed.record, &patterns).unwrap()
            .into_iter().find(|event| event.source == source && event.record_kind == 45).unwrap().id;
        let batch = sink.prepare(&page.records, [0;16], &reader, &snapshot, authorization.clone()).await.unwrap();
        let prepared = serde_json::to_value(batch.as_ref()).unwrap();
        if revoke_after_mac {
            let result = tokio::time::timeout(Duration::from_secs(3), sink.deliver(&batch, authorization.clone())).await.unwrap();
            let denied = execution.check().unwrap_err();
            assert!(matches!(result, kronik_otel::follow::Delivery::Retry { code, .. }
                if code == denied.code.as_str() || code == "execution_revoked"));
            assert_eq!(started_jobs.load(Ordering::SeqCst), 0);
            assert!(tokio::time::timeout(Duration::from_millis(150), listener.accept()).await.is_err());
        } else {
            let (arrived, received) = tokio::sync::oneshot::channel();
            let (release, response) = tokio::sync::oneshot::channel();
            let receiver = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = receive(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
                arrived.send(request).unwrap();
                response.await.unwrap();
                stream.write_all(b"ok").await.unwrap();
            });
            let sending = tokio::spawn(async move { sink.deliver(&batch, authorization).await });
            let (headers, body) = tokio::time::timeout(Duration::from_secs(5), received).await.unwrap().unwrap();
            let event: events::Event = serde_json::from_slice(&body).unwrap();
            assert_eq!(event.id, expected);
            assert_eq!(event.source, source);
            assert_eq!(event.record_kind, 45);
            assert_eq!(event.data.action, "secret.range");
            assert_eq!(headers["kronik-event-id"], expected);
            assert_eq!(headers["idempotency-key"], expected);
            assert_eq!(headers["kronik-signature-version"], "v1");
            assert_eq!(headers["content-type"], "application/json");
            let timestamp: u64 = headers["kronik-timestamp-ms"].parse().unwrap();
            assert_eq!(timestamp.to_string(), headers["kronik-timestamp-ms"]);
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(KEY).unwrap();
            mac.update(format!("kronik.webhook/v1\n{timestamp}\n{expected}\n").as_bytes());
            mac.update(&body);
            mac.verify_slice(&kronik_core::ids::unhex(
                headers["kronik-signature"].strip_prefix("v1=").unwrap()).unwrap()).unwrap();
            assert_eq!(started_jobs.load(Ordering::SeqCst), 1);
            // Dropping the waiter must not cancel the admitted owned HTTP job.
            sending.abort();
            assert!(sending.await.unwrap_err().is_cancelled());
            node.stop_native_execution().unwrap();
            assert!(tokio::time::timeout(Duration::from_millis(150), completed.notified()).await.is_err(),
                "response headers must not complete the owned HTTP job before body EOF");
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), completed.notified()).await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), receiver).await.unwrap().unwrap();
            assert!(execution.check().is_err());
            assert_eq!(started_jobs.load(Ordering::SeqCst), 1);
        }
        let pending = cursors.get("events-http-fence:actor-native").unwrap();
        assert_eq!(pending.lsn, 0);
        assert_eq!(pending.state["pending"], prepared);
    }
}

#[tokio::test]
async fn original_physical_execution_cancels_metadata_resolver_wait_and_retry_backoff() {
    use hmac::{KeyInit as _, Mac as _};
    use std::time::Duration;
    for resolver_wait in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let network = Arc::new(MetadataNetwork::default());
        let mut env = Env::real(tokio::runtime::Handle::current());
        let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
        env.spawner = spawner.clone();
        env.net = network.clone();
        let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
        let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
        let name = if resolver_wait { "events-cancel-resolver:metadata" } else { "events-cancel-backoff:metadata" };
        let entered = Arc::new(tokio::sync::Notify::new());
        let blocked = Arc::new(tokio::sync::Notify::new());
        let (entered_mac, blocked_mac) = (entered.clone(), blocked.clone());
        let resolver: Arc<webhook::Resolver> = Arc::new(move |_, message, _original| {
            let (entered, blocked) = (entered_mac.clone(), blocked_mac.clone());
            Box::pin(async move {
                if resolver_wait {
                    entered.notify_one();
                    blocked.notified().await;
                }
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-cancel-metadata-key").unwrap();
                mac.update(&message);
                Ok(mac.finalize().into_bytes().into())
            })
        });
        let settings = Settings { url: "http://127.0.0.1:9/events".into(),
            secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
                version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
                reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
        let binding = configured_stream(name, &cursors, &settings);
        let stream = webhook::start_metadata(native_metadata_runtime(node.clone(), name),
            Arc::new(mapper()), identity(), binding, cursors.clone(), settings, resolver,
            Arc::new(metadata_image()), native_gap_recorder(node.clone(), name)).await.unwrap();
        if resolver_wait {
            tokio::time::timeout(Duration::from_secs(3), entered.notified()).await.unwrap();
        } else {
            tokio::time::timeout(Duration::from_secs(3), async {
                while stream.progress().unwrap().last_error.as_deref() != Some("http_503") {
                    node.env().clock.sleep(Duration::from_millis(10)).await;
                }
            }).await.unwrap();
        }
        let pending = cursors.get(name).unwrap();
        assert_eq!(pending.lsn, 0);
        assert!(!pending.state["pending"].is_null());
        node.stop_native_execution().unwrap();
        let worker = spawner.task.lock().unwrap().take().unwrap();
        tokio::time::timeout(Duration::from_secs(3), worker).await.unwrap().unwrap();
        assert_eq!(stream.progress().unwrap().last_error.as_deref(), Some("execution_revoked"));
        assert_eq!(cursors.get(name).unwrap(), pending);
        assert_eq!(network.requests.lock().unwrap().len(), if resolver_wait { 0 } else { 1 });
    }
}

#[test]
fn ordinary_metadata_unit_has_no_adoption_marker_or_extra_public_fields() {
    let mapper = mapper();
    let ordinary = control_record(pb::audit_event::Operation::InstallationIdentity(pb::InstallationIdentity {
        installation: "installation-1".into(),
    }));
    let ordinary = events::project_metadata(&mapper, &identity(),
        &MetadataAuditRecord { index: 53, record: ordinary, native_origin: None }, &[]).unwrap().remove(0);
    assert!(ordinary.data.adoption.is_none());
    assert!(serde_json::to_value(&ordinary).unwrap()["data"].get("adoption").is_none());
    assert!(serde_json::from_value::<events::NativeAdoption>(
        json!({ "current_projection": true, "issuer": "not-public" })).is_err());
}

#[tokio::test]
async fn imported_record45_sidecar_survives_retry_restart_replay_and_visible_rewrite_holds() {
    use hmac::{KeyInit as _, Mac as _};
    use std::time::Duration;
    for rewrite in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let network = Arc::new(MetadataNetwork::default());
        let mut env = Env::real(tokio::runtime::Handle::current());
        let spawner = Arc::new(MetadataSpawner { inner: env.spawner.clone(), task: std::sync::Mutex::new(None) });
        env.spawner = spawner.clone();
        env.net = network.clone();
        let node = start_local(env.clone(), directory.path(), NodeConfig::default()).await.unwrap();
        let execution = node.local_operator_authority().unwrap();
        let record = Record::decode(45, &kronik_core::ids::unhex(
            include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex").trim()).unwrap()).unwrap();
        let body = record.encode();
        let origin = |current_projection| pb::NativeAuthorityOrigin {
            source: None, // The golden shape does not establish an original actor LSN.
            adoption_audit: Some(pb::Audit { token_id: "unix:uid=0".into(),
                reason: "private-adoption-NEEDLE".into(), wall_time_ms: 37 }),
            current_projection,
        };
        // These are explicit captured-image UNIT coordinates, not Raft commits.
        // The authoritative sidecar is retained independently of the unchanged
        // compatibility Record45 body; never reconstruct it from the record.
        let source = Arc::new(MutableMetadataImage(std::sync::RwLock::new(MetadataImage {
            floor: 1, head: 23, records: [
                (11, MetadataAuditRecord { index: 11, record: record.clone(), native_origin: Some(origin(false)) }),
                (23, MetadataAuditRecord { index: 23, record, native_origin: Some(origin(true)) }),
            ].into(),
        })));
        let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
        let runtime = native_metadata_runtime(node.clone(), "events-secret-origin:metadata");
        let settings = Settings { url: "http://127.0.0.1:9/events".into(),
            secret: SecretVersion { name: "webhook-key".into(), version: 7, branch: "main".into(),
                version_hash: [7;16], hash_revision: 1, backend: "local".into(), binding: String::new(),
                reference: String::new(), canonical_ref: String::new(), link_generation: 0, source_version: String::new() } };
        let resolver: Arc<webhook::Resolver> = Arc::new(|_, message, _original| Box::pin(async move {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-imported-record45-key").unwrap();
            mac.update(&message);
            Ok(mac.finalize().into_bytes().into())
        }));
        let binding = configured_stream("events-secret-origin:metadata", &cursors, &settings);
        let first = webhook::start_metadata(runtime.clone(), Arc::new(mapper()), identity(),
            binding, cursors.clone(), settings.clone(), resolver.clone(),
            source.clone(), native_gap_recorder(node.clone(), "events-secret-origin:metadata")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while first.progress().unwrap().last_error.as_deref() != Some("http_503") {
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        let before = cursors.get("events-secret-origin:metadata").unwrap();
        let original_body = before.state["pending"]["events"][0]["body"].as_str().unwrap();
        let original: events::Event = serde_json::from_str(original_body).unwrap();
        assert_eq!(original.record_kind, 45);
        assert_eq!(original.source, SourcePos::Metadata { index: 11 });
        assert_eq!(original.data.action, "secret.version");
        assert_eq!(original.data.adoption, Some(events::NativeAdoption { current_projection: false }));
        assert_eq!(before.lsn, 0);
        for private in ["native_origin", "adoption_audit", "private-adoption-NEEDLE", "unix:uid=0"] {
            assert!(!original_body.contains(private));
        }
        {
            let mut image = source.0.write().unwrap();
            assert_eq!(image.records[&11].record.encode(), body);
            assert_eq!(image.records[&23].record.encode(), body);
            let current = events::project_metadata(&mapper(), &identity(), &image.records[&23], &[]).unwrap().remove(0);
            assert_ne!(current.id, original.id, "different actual metadata indexes retain distinct identities");
            assert_eq!(current.data.record_hash, original.data.record_hash);
            assert_eq!(current.data.adoption, Some(events::NativeAdoption { current_projection: true }));
            if rewrite {
                image.records.get_mut(&11).unwrap().native_origin.as_mut().unwrap().current_projection = true;
                let changed = events::project_metadata(&mapper(), &identity(), &image.records[&11], &[]).unwrap().remove(0);
                assert_eq!(changed.id, original.id, "the frozen body hash intentionally excludes the sidecar");
                assert_ne!(changed.body().unwrap().as_slice(), original_body.as_bytes());
            }
        }
        let recovered = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
        let binding = configured_stream("events-secret-origin:metadata", &recovered, &settings);
        let stream = webhook::start_metadata(runtime, Arc::new(mapper()), identity(),
            binding, recovered.clone(), settings, resolver, source.clone(),
            native_gap_recorder(node.clone(), "events-secret-origin:metadata")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let progress = stream.progress().unwrap();
                if rewrite && progress.last_error.as_deref() == Some("webhook_history_conflict")
                    || !rewrite && progress.cursor == (SourcePos::Metadata { index: 23 }) { break; }
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        if rewrite {
            spawner.stop().await;
            assert_eq!(recovered.get("events-secret-origin:metadata").unwrap(), before);
            assert_eq!(network.requests.lock().unwrap().len(), 1);
            continue;
        }
        {
            let requests = network.requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].body, requests[1].body);
            assert_eq!(requests[0].headers, requests[1].headers);
            let current: events::Event = serde_json::from_slice(&requests[2].body).unwrap();
            assert_eq!(current.source, SourcePos::Metadata { index: 23 });
            assert_eq!(current.data.adoption, Some(events::NativeAdoption { current_projection: true }));
        }
        stream.rewind(Position { source: SourcePos::Metadata { index: 11 }, subindex: 0 },
            execution).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let saved = recovered.get("events-secret-origin:metadata").unwrap();
                if saved.lsn == 23 && saved.generation() != before.generation()
                    && saved.pending_rewind().is_none() { break; }
                node.env().clock.sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        spawner.stop().await;
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[0].body, requests[3].body);
        assert_eq!(requests[2].body, requests[4].body);
        assert_eq!(recovered.get("events-secret-origin:metadata").unwrap().state["pending"], serde_json::Value::Null);
    }
}

#[tokio::test]
async fn actual_mixed_wal_headers_bind_event_identity_not_reader_head_or_feed_selection() {
    use kronik_log::{LogConfig, SegmentWriter, SegmentWriterConfig};
    use kronik_sched::{NodeParts, NodeShared};
    use std::{collections::BTreeSet, time::Duration};
    // Pure source projection, using the maintained M28 mixed-header fixture.
    // This replay Node has no M23 runtime; it is never a live disclosure host.
    let root = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let producer = start_local(env.clone(), &root.path().join("producer"), NodeConfig::default()).await.unwrap();
    let original = producer.local_operator_authority().unwrap();
    let audit = || pb::Audit { token_id: "system".into(),
        reason: "genuine mixed source fixture".into(), wall_time_ms: 1 };
    producer.deploy(include_bytes!("../../../tests/guests/counter.wasm"),
        audit(), false, original.clone()).await.unwrap();
    producer.refresh_secret_inventory(original.clone()).await.unwrap();
    producer.send(kronik_core::ids::ActorRef::parse("counter/mixed").unwrap(),
        pb::Message { name: "increment".into(), ..Default::default() },
        audit(), false, original.clone()).await.unwrap().unwrap();
    let fork_at = producer.record_audit_event_authorized("operator.note", "fork-edge",
        BTreeMap::new(), audit(), original.clone()).await.unwrap();
    let rebased_at = producer.record_audit_event_authorized("operator.note", "rebased-edge",
        BTreeMap::new(), audit(), original).await.unwrap();
    let captured = producer.capture_system_export_reader().await.unwrap();
    let SourcePos::Actor { shard: None, lsn: head } = captured.point().source else {
        panic!("the actual producer must be native");
    };
    let page = captured.local_export_page(0, 256, 4 << 20).await.unwrap();
    assert_eq!(page.scanned_through, head);
    let records: Vec<_> = page.records.into_iter().map(|(_, committed)| committed).collect();
    let code = producer.code().clone();
    drop(captured);
    producer.stop_native_execution().unwrap();
    drop(producer);

    let directory = root.path().join("retained/log");
    let ranges = [("main", 1, fork_at - 1), ("fork-original", fork_at, rebased_at - 1),
        ("rebased-main", rebased_at, head)];
    for (index, (branch, from, through)) in ranges.iter().enumerate() {
        let config = SegmentWriterConfig { dir: directory.clone(), branch: (*branch).into(),
            also_accept: ranges[..index].iter().map(|(name, _, _)| (*name).to_owned()).collect(),
            segment_max_bytes: u64::MAX, segment_max_age_ms: u64::MAX, first_lsn: *from };
        let (mut writer, _) = SegmentWriter::open(&env, config, from - 1).await.unwrap();
        writer.roll().await.unwrap();
        for committed in records.iter().filter(|committed| committed.lsn >= *from && committed.lsn <= *through) {
            writer.append(committed.lsn, &committed.record).await.unwrap();
        }
        writer.roll().await.unwrap();
    }
    let config = NodeConfig { branch: "rebased-main".into(), concurrency: 1, ..Default::default() };
    let mut log = LogConfig::new(directory, config.branch.clone());
    log.also_accept = vec!["main".into(), "fork-original".into()];
    log.group_commit_window = Duration::ZERO;
    let mut mapper = mapper();
    mapper.branch = config.branch.clone();
    let shared = NodeShared::new(env, &config, code, None, None, None);
    let node = Node::start(NodeParts { shared, config, log, store: kronik_store::Store::memory().unwrap(),
        sealer: Some(mapper.sealer.clone()), replica_reader: None, replica_role_source: None,
        actor_host: None, replica_identity: None, replica_snapshots: None }).await.unwrap();
    let reader = node.capture_system_export_reader().await.unwrap();
    assert_eq!(reader.point().branch, "rebased-main");
    let page = reader.local_export_page(0, 256, 4 << 20).await.unwrap();
    let mut selection = identity();
    selection.branch = "rebased-main".into();
    let mut another_selection = selection.clone();
    another_selection.branch = "another-feed".into();
    let mut branches = BTreeSet::new();
    for (source, committed) in &page.records {
        assert_eq!(source.lsn, committed.lsn);
        let projected = events::project(&mapper, &selection, source, &committed.record, &[]).unwrap();
        let replay = events::project(&mapper, &another_selection, source, &committed.record, &[]).unwrap();
        for event in projected {
            branches.insert(source.branch.as_str());
            assert_eq!(event.branch.as_deref(), Some(source.branch.as_str()));
            assert_eq!(event.source, SourcePos::Actor { shard: source.shard, lsn: source.lsn });
            assert_eq!(event.id, events::event_id(&selection, event.source,
                Some(&source.branch), event.subindex, &event.data.record_hash).unwrap());
            let same = replay.iter().find(|candidate| candidate.subindex == event.subindex).unwrap();
            assert_eq!(same.id, event.id);
            assert_eq!(same.body().unwrap(), event.body().unwrap());
            let cursor = ResumeCursor::new(another_selection.clone());
            let resumed = events::resume_after(&event, &cursor).unwrap();
            assert_eq!(resumed.identity.branch, "another-feed");
            let frame = events::sse_event(&event, &cursor).unwrap();
            let encoded = frame.lines().find_map(|line| line.strip_prefix("id: ")).unwrap();
            assert_eq!(serde_json::from_str::<ResumeCursor>(encoded).unwrap(), resumed);
        }
    }
    assert_eq!(branches, BTreeSet::from(["main", "fork-original", "rebased-main"]));
}

#[test]
fn actor_branch_identity_uses_canonical_utf8_bytes_not_feed_label_rules() {
    let record = Record::AuditEvent(pb::AuditEvent { action: "proposal.create".into(),
        target: "p-branch".into(), audit: audit(), ..Default::default() });
    let mapper = mapper();
    let hash = kronik_otel::audit::record_hash(&record, &mapper.sealer).unwrap();
    let schema = events::schemas().unwrap();
    assert_eq!(schema["properties"]["branch"]["$ref"], "#/$defs/source_branch");
    assert_eq!(schema["$defs"]["cursor"]["properties"]["identity"]["properties"]["branch"]["$ref"], "#/$defs/label");
    for branch in ["a".repeat(256), "é".repeat(128), "fork original#000".into()] {
        kronik_proto::validate_source_branch(&branch).unwrap();
        let source = pb::ActorSource { shard: None, lsn: 1, branch };
        let event = events::project(&mapper, &identity(), &source, &record, &[]).unwrap()
            .into_iter().find(|event| event.data.action == "proposal.create").unwrap();
        assert_eq!(event.branch.as_deref(), Some(source.branch.as_str()));
        assert_eq!(event.id, events::event_id(&identity(), native(1), Some(&source.branch), 0, &hash).unwrap());
    }
    for branch in ["a".repeat(257), "é".repeat(129), String::new(), "a:b".into(),
        "a/b".into(), "a\\b".into(), "a\nb".into(), "a\u{7f}b".into()] {
        assert!(kronik_proto::validate_source_branch(&branch).is_err());
        assert!(events::event_id(&identity(), native(1), Some(&branch), 0, &hash).is_err());
    }
    assert!(events::event_id(&identity(), native(1), None, 0, &hash).is_err());
    assert!(events::event_id(&identity(), SourcePos::Metadata { index: 1 }, Some("main"), 0, &hash).is_err());
    assert!(events::event_id(&identity(), SourcePos::Metadata { index: 1 }, None, 0, &hash).is_ok());
}
