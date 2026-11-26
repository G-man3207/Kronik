#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::sync::Arc;

use kronik_core::authority::AuthLease;
use kronik_core::env::Env;
use kronik_core::ids::SourcePos;
use kronik_fleet::{
    events::{self, Identity, Position, ResumeCursor},
    webhook::{self, SecretVersion, Settings, Webhook},
};
use kronik_otel::{
    audit::{Keys, Mapper},
    cursor::Cursors,
    follow::{Sink, Stream},
};
use kronik_privacy::sealer::Sealer;
use kronik_proto::{Record, log::v1 as pb};
use kronik_sched::{
    Node, NodeConfig, ShardReader,
    secrets::{CertifiedSecretSnapshot, SecretSnapshotPublication},
    start_local,
};
use serde_json::json;

/// The receiver's keyed check of a delivery, recomputed here as the tests
/// sign: the crate itself signs through the key resolver.
fn signature(key: &[u8], timestamp_ms: u64, event_id: &str, body: &[u8]) -> Result<String, String> {
    use hmac::{KeyInit as _, Mac as _};
    let input = kronik_fleet::webhook::signing_input(timestamp_ms, event_id, body)?;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
        .map_err(|_| "webhook_signature".to_owned())?;
    mac.update(&input);
    Ok(format!(
        "{}={}",
        kronik_fleet::webhook::SIGNATURE_VERSION,
        kronik_core::ids::hex(&mac.finalize().into_bytes())
    ))
}

fn identity() -> Identity {
    Identity {
        installation: "installation-1".into(),
        branch: "main".into(),
    }
}
fn native(lsn: u64) -> SourcePos {
    SourcePos::Actor { shard: None, lsn }
}
// Unit projections declare the native "main" namespace; fsynced fixtures write
// that header. Live Node projections use the ActorSource from their held reader.
fn main_frame(lsn: u64) -> pb::ActorSource {
    pb::ActorSource {
        shard: None,
        lsn,
        branch: "main".into(),
    }
}
fn mapper() -> Mapper {
    let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
    let keyed = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
    Mapper {
        keys: Keys::Omit,
        sealer: Arc::new(Sealer::plain().with_pseudonyms(keyed)),
        branch: "main".into(),
    }
}
fn audit() -> Option<pb::Audit> {
    Some(pb::Audit {
        token_id: "token:raw-name-PII-NEEDLE".into(),
        reason: "raw-reason-PII-NEEDLE rotate VALUE-NEEDLE".into(),
        wall_time_ms: 123,
    })
}

/// The webhook settings most tests use: a closed local port and key version 7.
fn webhook_settings() -> Settings {
    Settings {
        url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion {
            name: "webhook-key".into(),
            version: 7,
            branch: "main".into(),
            version_hash: [7; 16],
            hash_revision: 1,
            backend: "local".into(),
            binding: String::new(),
            reference: String::new(),
            canonical_ref: String::new(),
            link_generation: 0,
            source_version: String::new(),
        },
    }
}

/// A native log in a fresh temporary directory. Keep the directory and the
/// fatal receiver bound (as `_directory`, `_fatal`, never `_`) until the
/// test ends.
async fn native_log() -> (
    tempfile::TempDir,
    kronik_log::Log,
    tokio::sync::mpsc::UnboundedReceiver<kronik_log::Committed>,
    tokio::sync::oneshot::Receiver<String>,
) {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let (send, committed) = tokio::sync::mpsc::unbounded_channel();
    let (fatal, failed) = tokio::sync::oneshot::channel();
    let (log, _) = kronik_log::Log::open(
        &env,
        kronik_log::LogConfig::new(directory.path().to_path_buf(), "main"),
        send,
        fatal,
    )
    .await
    .unwrap();
    (directory, log, committed, failed)
}

fn configured_stream(
    name: impl Into<Arc<str>>,
    cursors: &Arc<Cursors>,
    settings: &Settings,
) -> Arc<Stream> {
    let name = name.into();
    let cursor = cursors.get(name.as_ref()).map_or(0, |entry| entry.lsn);
    Stream::new(
        name,
        true,
        kronik_otel::http::scheme_host(&settings.url),
        cursor,
        cursors.clone(),
    )
}

async fn native_disclosure(
    node: &Arc<Node>,
    original: &AuthLease,
) -> (Arc<ShardReader>, Arc<CertifiedSecretSnapshot>, AuthLease) {
    original.check().unwrap();
    // The background secret refresh can still replace a just-captured
    // publication; rebuild the disclosure until one survives its own check.
    for _ in 0..500 {
        let (snapshot, publication) = certified_catalogue(node).await;
        let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
        let disclosure = kronik_otel::follow::RetainedDisclosure::native(
            reader.clone(),
            snapshot.clone(),
            publication,
            original.clone(),
        );
        if disclosure.check().is_ok() {
            return (reader, snapshot, disclosure);
        }
        node.env()
            .clock
            .sleep(std::time::Duration::from_millis(2))
            .await;
    }
    panic!("the native secret catalogue never stayed published");
}

/// The checkout certifies the retained secret catalogue asynchronously after
/// start (a second refresh settles shortly after the first). Require a quiet
/// window of current publications so a settling refresh cannot invalidate the
/// disclosure handed to a test.
async fn certified_catalogue(
    node: &Arc<Node>,
) -> (Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication) {
    let mut stable = 0;
    for _ in 0..3000 {
        match node.native_secret_snapshot_with_publication() {
            Ok((snapshot, publication)) if publication.check_current().is_ok() => {
                stable += 1;
                if stable == 40 {
                    return (snapshot, publication);
                }
            }
            _ => stable = 0,
        }
        node.env()
            .clock
            .sleep(std::time::Duration::from_millis(5))
            .await;
    }
    panic!("the native secret catalogue was never certified");
}

#[tokio::test]
async fn revoked_original_disclosure_creates_no_pending_manifest_or_transport() {
    use hmac::{KeyInit as _, Mac as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(RecordingNetwork::default());
    env.net = network.clone();
    let node = start_local(env.clone(), directory.path(), NodeConfig::default())
        .await
        .unwrap();
    let execution = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let settings = webhook_settings();
    let stream = configured_stream("events-revoked-pending:actor-native", &cursors, &settings);
    let mac_calls = Arc::new(AtomicUsize::new(0));
    let counted = mac_calls.clone();
    let resolver: Arc<webhook::Resolver> = Arc::new(move |_, input, _original| {
        let counted = counted.clone();
        Box::pin(async move {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut mac =
                hmac::Hmac::<sha2::Sha256>::new_from_slice(b"dummy-revoked-before-pending")
                    .unwrap();
            mac.update(&input);
            Ok(mac.finalize().into_bytes().into())
        })
    });
    let mapper = Arc::new(Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: node.branch().into(),
    });
    let mut sink = Webhook::open(
        node.clone(),
        mapper,
        identity(),
        None,
        stream.clone(),
        cursors.clone(),
        settings,
        resolver,
        execution.clone(),
    )
    .await
    .unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let page = reader
        .local_export_page(0, 1, kronik_otel::follow::BATCH_BYTES)
        .await
        .unwrap();
    assert!(
        page.records
            .iter()
            .any(|(_, record)| matches!(record.record, Record::SecretVersion(_)))
    );
    let before = cursors.get(stream.name.as_ref()).unwrap();
    let durable_before = std::fs::read(directory.path().join(Cursors::FILE)).unwrap();
    let batch = sink
        .prepare(
            &page.records,
            before.generation(),
            &reader,
            &snapshot,
            authorization.clone(),
        )
        .await
        .unwrap();
    assert_eq!(cursors.get(stream.name.as_ref()).unwrap(), before);
    node.stop_native_execution().unwrap();
    let denied = execution.check().unwrap_err();
    assert!(matches!(sink.deliver(&batch, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == denied.code.as_str()));
    assert_eq!(cursors.get(stream.name.as_ref()).unwrap(), before);
    assert_eq!(
        std::fs::read(directory.path().join(Cursors::FILE)).unwrap(),
        durable_before
    );
    assert!(before.state["pending"].is_null());
    assert_eq!(mac_calls.load(Ordering::SeqCst), 0);
    assert!(network.requests.lock().unwrap().is_empty());
}

/// Each fixture asserts its actual operation and meaningful projected fields.
fn fixtures() -> Vec<(Record, &'static str, &'static str, Option<u64>)> {
    vec![
        (
            Record::Deployment(pb::Deployment {
                epoch: 7,
                cause: pb::DeploymentCause::Promote as i32,
                proposal_id: "p-1".into(),
                audit: audit(),
                ..Default::default()
            }),
            "deployment",
            "promote",
            Some(7),
        ),
        (
            Record::Grant(pb::Grant {
                epoch: 8,
                op: pb::GrantOp::Grant as i32,
                kind: "counter".into(),
                capability: "http:service".into(),
                audit: audit(),
                ..Default::default()
            }),
            "grant",
            "grant",
            Some(8),
        ),
        (
            Record::Limits(pb::Limits {
                epoch: 9,
                kind: "counter".into(),
                fuel: Some(99),
                audit: audit(),
                ..Default::default()
            }),
            "limits",
            "limits",
            Some(9),
        ),
        (
            Record::Policy(pb::Policy {
                epoch: 10,
                rules_toml:
                    "[[rule]]\nname = \"approval-floor\"\nwhen = \"true\"\naction = \"deny\"\n"
                        .into(),
                audit: audit(),
                ..Default::default()
            }),
            "policy",
            "policy",
            Some(10),
        ),
        (
            Record::Approval(pb::Approval {
                proposal_id: "p-1".into(),
                request: true,
                diff_hash: vec![0xab; 32],
                verified_through_lsn: 20,
                command: "promote p-1".into(),
                audit: audit(),
                verified_identity: None,
            }),
            "approval",
            "request_approval",
            None,
        ),
        (
            Record::Approval(pb::Approval {
                proposal_id: "p-1".into(),
                request: false,
                diff_hash: vec![0xab; 32],
                verified_through_lsn: 20,
                command: "promote p-1".into(),
                audit: audit(),
                verified_identity: None,
            }),
            "approval",
            "approve",
            None,
        ),
        (
            Record::PrivacyMode(pb::PrivacyMode {
                epoch: 11,
                mode: pb::PrivacyState::On as i32,
                audit: audit(),
                reseal_requested: false,
            }),
            "privacy_mode",
            "privacy.mode",
            Some(11),
        ),
        (
            Record::ForeignActor(pb::ForeignActor {
                epoch: 12,
                op: pb::ForeignOp::Add as i32,
                name: "payments".into(),
                image: "oci-layout:/private/path@sha256:1234".into(),
                port: 8080,
                isolation: pb::Isolation::Gvisor as i32,
                audit: audit(),
                ..Default::default()
            }),
            "foreign_actor",
            "foreign.add",
            Some(12),
        ),
        (
            Record::Erasure(pb::Erasure {
                epoch: 13,
                subject: "subject-PII-NEEDLE".into(),
                key_version: 2,
                audit: audit(),
            }),
            "erasure",
            "privacy.erase",
            Some(13),
        ),
        (
            Record::EngineUpgrade(pb::EngineUpgrade {
                epoch: 14,
                from_engine_version: "0.5.0".into(),
                to_engine_version: "0.6.0".into(),
                audit: audit(),
                ..Default::default()
            }),
            "engine_upgrade",
            "engine.upgrade",
            Some(14),
        ),
        (
            Record::SimulatorConfig(pb::SimulatorConfig {
                epoch: 15,
                target: "http:service".into(),
                neighbor: true,
                audit: audit(),
                ..Default::default()
            }),
            "simulator_config",
            "simulators.set",
            Some(15),
        ),
        (
            Record::GuardTriggered(pb::GuardTriggered {
                watch_id: "watch-1".into(),
                guard: "error-rate".into(),
                action: pb::GuardAction::Rollback as i32,
                outcome: pb::GuardOutcome::RolledBack as i32,
                deployment_epoch: 7,
                rollback_epoch: 16,
                reason: "GUEST-TEXT-NEEDLE".into(),
                audit: audit(),
                ..Default::default()
            }),
            "guard_triggered",
            "watch.guard",
            None,
        ),
        (
            Record::StateRebase(pb::StateRebase {
                rebase_id: "rebase-1".into(),
                part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
                    base_lsn: 10,
                    rolled_back_epoch: 7,
                    turns: 3,
                    first_turn_lsn: 11,
                    last_turn_lsn: 13,
                    deployment: Some(pb::Deployment {
                        epoch: 17,
                        cause: pb::DeploymentCause::Rollback as i32,
                        ..Default::default()
                    }),
                    diff_hash: "b3:0011".into(),
                    irreversible_effects: 2,
                    audit: audit(),
                    ..Default::default()
                })),
            }),
            "state_rebase",
            "rollback.rebase",
            Some(17),
        ),
        (
            Record::AuditEvent(pb::AuditEvent {
                action: "proposal.create".into(),
                target: "p-1".into(),
                details: BTreeMap::from([("operator".into(), "raw-details-PII-NEEDLE".into())]),
                audit: audit(),
                ..Default::default()
            }),
            "audit_event",
            "proposal.create",
            None,
        ),
        (Record::TurnRecord(operator_turn()), "turn", "resend", None),
    ]
}

fn operator_turn() -> pb::TurnRecord {
    pb::TurnRecord {
        actor: Some(pb::ActorRef {
            kind: "counter".into(),
            key: "actor-PII-NEEDLE".into(),
        }),
        logical_time_ms: 123,
        execution_id: "operator-root-execution".into(),
        causal_key: Some(pb::CausalKey {
            root: "operator-root".into(),
            ..Default::default()
        }),
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::DeadLetterResend as i32,
                resend_of: "main:12".into(),
                audit: audit(),
                msg: Some(pb::Message {
                    name: "increment".into(),
                    body: Some(pb::Sealable {
                        subject: Some("subject-PII-NEEDLE".into()),
                        value: Some(pb::sealable::Value::Plain(b"BODY-NEEDLE".to_vec())),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn decoded_privacy_reseal_request_publishes_request_not_completion() {
    let (_directory, log, mut committed_rx, _fatal) = native_log().await;
    let mapper = mapper();
    let secrets = [
        ("public-mode", b"mode".as_slice()),
        ("public-state", b"on".as_slice()),
        ("public-request", b"reseal_requested".as_slice()),
        ("public-flag", b"true".as_slice()),
        ("public-epoch", b"7".as_slice()),
        ("private-value", b"VALUE-NEEDLE".as_slice()),
    ];
    let schema = events::schemas().unwrap();
    let variant = schema["$defs"]["metadata"]["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["if"]["properties"]["kind"]["const"] == "privacy_mode")
        .unwrap();
    let allowed = variant["then"]["properties"]["action"]["enum"]
        .as_array()
        .unwrap();
    for (wire, action) in [
        (b"\x08\x07\x10\x02".as_slice(), "privacy.mode"),
        (
            b"\x08\x07\x10\x02\x20\x01".as_slice(),
            "privacy.reseal.request",
        ),
    ] {
        let mut record = Record::decode(9, wire).unwrap();
        assert_eq!(record.encode(), wire);
        let Record::PrivacyMode(mode) = &mut record else {
            unreachable!()
        };
        mode.audit = audit();
        let lsn = log.append(record).await.unwrap();
        let committed = committed_rx.recv().await.unwrap();
        assert_eq!(committed.lsn, lsn);
        let event = events::project(
            &mapper,
            &identity(),
            &main_frame(lsn),
            &committed.record,
            &secrets,
        )
        .unwrap()
        .remove(0);
        assert_eq!(
            (event.record_kind, event.data.kind.as_str()),
            (9, "privacy_mode")
        );
        assert_eq!(event.data.action, action);
        assert_ne!(event.data.action, "privacy.reseal");
        assert_eq!(event.data.epoch, Some(7));
        assert_eq!(event.data.at_wall_ms, 123);
        assert!(allowed.contains(&json!(event.data.action)));
    }
}

#[tokio::test]
async fn every_operational_fixture_has_meaningful_versioned_committed_content() {
    let (_directory, log, mut committed_rx, _fatal) = native_log().await;
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
        let projected = events::project(
            &mapper,
            &identity(),
            &main_frame(lsn),
            &committed.record,
            &secrets,
        )
        .unwrap();
        let event = projected
            .iter()
            .find(|event| event.data.action == action)
            .unwrap();
        assert_eq!(event.data.kind, kind);
        assert_eq!(event.data.epoch, epoch, "{kind}/{action}");
        assert_eq!(event.record_kind, record.kind());
        assert_eq!(event.source, native(lsn));
        assert_eq!(event.data.at_wall_ms, 123);
        assert!(event.data.record_hash.starts_with("b3k:v3:"));
        assert_eq!(event.schema, "kronik.event/v1");
        assert_eq!(
            event.id,
            events::event_id(
                &identity(),
                native(lsn),
                Some("main"),
                event.subindex,
                &event.data.record_hash
            )
            .unwrap()
        );
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        for needle in [
            "VALUE-NEEDLE",
            "BODY-NEEDLE",
            "subject-PII-NEEDLE",
            "actor-PII-NEEDLE",
            "GUEST-TEXT-NEEDLE",
            "/private/path",
            "raw-name-PII-NEEDLE",
            "raw-reason-PII-NEEDLE",
            "raw-details-PII-NEEDLE",
        ] {
            assert!(!body.contains(needle), "{kind} leaked {needle}");
        }
        assert_eq!(
            serde_json::from_str::<events::Event>(&body).unwrap(),
            *event
        );
        let constraints = schema["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|constraint| {
                constraint["if"]["properties"]["record_kind"]["const"] == json!(record.kind())
            })
            .unwrap();
        let kind_schema = &constraints["then"]["properties"]["data"]["properties"]["kind"];
        assert!(
            kind_schema["const"] == kind
                || kind_schema["enum"]
                    .as_array()
                    .is_some_and(|allowed| allowed.contains(&json!(kind)))
        );
    }
}

#[test]
fn effect_subindices_are_distinct_and_sse_resumes_after_each_event() {
    let mut turn = operator_turn();
    turn.effects = vec![pb::EffectRecord {
        ordinal: 2,
        kind: "secret.reveal".into(),
        target: "secret-reveal:webhook-key".into(),
        status: pb::EffectStatus::Ok as i32,
        ..Default::default()
    }];
    let events = events::project(
        &mapper(),
        &identity(),
        &main_frame(19),
        &Record::TurnRecord(turn),
        &[],
    )
    .unwrap();
    assert_eq!(events[0].data.action, "resend");
    assert_eq!(events[1].data.action, "secret.reveal");
    assert_eq!(events[1].data.effect, Some(2));
    assert_ne!(events[0].id, events[1].id);
    let mut cursor = ResumeCursor::new(identity());
    cursor
        .rewind(Position {
            source: SourcePos::Actor {
                shard: Some(1),
                lsn: 90,
            },
            subindex: 0,
        })
        .unwrap();
    let framed = events::sse_event(&events[0], &cursor).unwrap();
    let id_line = framed.lines().next().unwrap().strip_prefix("id: ").unwrap();
    let resumed: ResumeCursor = serde_json::from_str(id_line).unwrap();
    assert_eq!(
        resumed.streams["actor-native"],
        Position {
            source: native(19),
            subindex: 1
        }
    );
    assert_eq!(
        resumed.streams["actor-1"].source,
        SourcePos::Actor {
            shard: Some(1),
            lsn: 90
        }
    );
    let after = events::resume_after(&events[1], &resumed).unwrap();
    assert_eq!(after.streams["actor-native"].subindex, 2);
    let mut other = identity();
    other.installation = "other".into();
    assert!(after.validate(&other).is_err());
    assert_ne!(
        events[0].id,
        events::event_id(
            &identity(),
            SourcePos::Actor {
                shard: Some(1),
                lsn: 19
            },
            Some("main"),
            0,
            &events[0].data.record_hash
        )
        .unwrap()
    );
}

#[test]
fn signing_input_is_versioned_exact_and_refuses_a_bad_event_id() {
    let id = "ke1.69.6d.actor.native.9.0.0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(
        webhook::signing_input(123, id, b"{}").unwrap(),
        format!("kronik.webhook/v1\n123\n{id}\n{{}}").into_bytes()
    );
    assert!(webhook::signing_input(123, "ke1.bad\nheader", b"{}").is_err());
}

#[tokio::test]
async fn committed_pages_restart_rewind_and_prepared_webhook_survive_durable_reload() {
    use hmac::{KeyInit as _, Mac as _};
    let dir = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(RecordingNetwork::default());
    env.net = network.clone();
    let node = start_local(env.clone(), dir.path(), NodeConfig::default())
        .await
        .unwrap();
    let execution = node.local_operator_authority().unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), dir.path()).await.unwrap());
    let settings = webhook_settings();
    let mapper = Arc::new(Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: node.branch().into(),
    });
    let stream = configured_stream("events-test:actor-native", &cursors, &settings);
    let (reader, snapshot, _authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    // Consume the real startup ledger records before taking this feed's resume
    // boundary. Startup SecretVersion fences remain public operational events.
    let startup = events::page(
        &reader,
        &mapper,
        &identity(),
        &ResumeCursor::new(identity()),
        &patterns,
        events::MAX_EVENTS,
    )
    .await
    .unwrap();
    assert!(!startup.more);
    assert!(
        startup
            .events
            .iter()
            .any(|event| event.record_kind == 45 && event.data.action == "secret.range")
    );
    let startup_through = node.applied_lsn();
    let start = startup.cursor;
    let proposal_lsn = node
        .record_audit_event_authorized(
            "proposal.create",
            "p-real",
            BTreeMap::new(),
            audit().unwrap(),
            execution.clone(),
        )
        .await
        .unwrap();
    node.record_audit_event_authorized(
        "proposal.cancel",
        "p-real",
        BTreeMap::new(),
        audit().unwrap(),
        execution.clone(),
    )
    .await
    .unwrap();
    let (reader, snapshot, _authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let first = events::page(&reader, &mapper, &identity(), &start, &patterns, 1)
        .await
        .unwrap();
    assert_eq!(first.events[0].data.action, "proposal.create");
    assert_eq!(first.events[0].source, native(proposal_lsn));
    assert_eq!(first.events[0].data.at_wall_ms, 123);
    let restored: ResumeCursor =
        serde_json::from_slice(&serde_json::to_vec(&first.cursor).unwrap()).unwrap();
    let second = events::page(&reader, &mapper, &identity(), &restored, &patterns, 1)
        .await
        .unwrap();
    assert_eq!(second.events[0].data.action, "proposal.cancel");
    let mut rewound = second.cursor.clone();
    rewound
        .rewind(Position {
            source: first.events[0].source,
            subindex: 0,
        })
        .unwrap();
    let replay = events::page(&reader, &mapper, &identity(), &rewound, &patterns, 1)
        .await
        .unwrap();
    assert_eq!(replay.events[0].id, first.events[0].id);
    let mut ahead = start.clone();
    ahead
        .rewind(Position {
            source: native(node.applied_lsn() + 2),
            subindex: 0,
        })
        .unwrap();
    assert!(
        events::page(&reader, &mapper, &identity(), &ahead, &patterns, 1)
            .await
            .is_err()
    );
    let signer: Arc<webhook::Resolver> = Arc::new(|reference, input, _original| {
        Box::pin(async move {
            let key: &[u8] = match reference.version {
                7 => {
                    assert_eq!(reference.version_hash, [7; 16]);
                    b"dummy-key"
                }
                8 => {
                    assert_eq!(reference.version_hash, [8; 16]);
                    b"dummy-next-key"
                }
                _ => panic!("unexpected immutable version"),
            };
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
            mac.update(&input);
            Ok(mac.finalize().into_bytes().into())
        })
    });
    let mut sink = Webhook::open(
        node.clone(),
        mapper.clone(),
        identity(),
        None,
        stream.clone(),
        cursors.clone(),
        settings.clone(),
        signer.clone(),
        execution.clone(),
    )
    .await
    .unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let mut page = reader
        .local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES)
        .await
        .unwrap();
    assert!(page.retention_gap.is_none());
    page.records
        .retain(|(source, _)| source.lsn <= startup_through);
    let prepared = sink
        .prepare(
            &page.records,
            [0; 16],
            &reader,
            &snapshot,
            authorization.clone(),
        )
        .await
        .unwrap();
    assert!(
        matches!(sink.deliver(&prepared, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == "http_503")
    );
    let durable = std::fs::read(dir.path().join(Cursors::FILE)).unwrap();
    assert!(!String::from_utf8_lossy(&durable).contains("dummy-key"));
    assert_eq!(cursors.get("events-test:actor-native").unwrap().lsn, 0);
    drop(sink);
    let recovered_cursors = Arc::new(Cursors::load(env, dir.path()).await.unwrap());
    let mut rotated = settings.clone();
    rotated.secret.version = 8;
    rotated.secret.version_hash = [8; 16];
    let recovered_stream =
        configured_stream("events-test:actor-native", &recovered_cursors, &rotated);
    let mut recovered = Webhook::open(
        node.clone(),
        mapper.clone(),
        identity(),
        None,
        recovered_stream.clone(),
        recovered_cursors.clone(),
        rotated.clone(),
        signer.clone(),
        execution.clone(),
    )
    .await
    .unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let mut page = reader
        .local_export_page(0, events::MAX_EVENTS, kronik_otel::follow::BATCH_BYTES)
        .await
        .unwrap();
    assert!(page.retention_gap.is_none());
    page.records
        .retain(|(source, _)| source.lsn <= startup_through);
    let same = recovered
        .prepare(
            &page.records,
            [0; 16],
            &reader,
            &snapshot,
            authorization.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(prepared.as_ref()).unwrap(),
        serde_json::to_value(same.as_ref()).unwrap()
    );
    let configured = recovered_cursors.get("events-test:actor-native").unwrap();
    assert_eq!(configured.state["secret"]["version"], 8);
    assert_eq!(configured.state["pending"]["pin"]["version"], 7);
    assert_eq!(
        recovered.deliver(&same, authorization.clone()).await,
        kronik_otel::follow::Delivery::Delivered
    );
    {
        let requests = network.requests.lock().unwrap();
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].headers, requests[1].headers);
    }
    // The real follower retries the durable pending body before its own
    // guarded ACK checkpoint; the test never publishes a cursor directly.
    let (worker_node, worker_stream, original) =
        (node.clone(), recovered_stream.clone(), execution.clone());
    recovered_stream.own_task(node.env().spawn("events-ack-checkpoint", async move {
        // The follower reports failure through the durable cursor and the
        // stream, not a return value; the catch-up loop below proves success.
        kronik_otel::follow::follow(
            worker_node,
            worker_stream,
            kronik_otel::follow::Options {
                batch: 1,
                interval: std::time::Duration::from_millis(1),
            },
            recovered,
            original,
        )
        .await;
    }));
    let caught_up = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let entry = recovered_cursors.get("events-test:actor-native").unwrap();
            if entry.lsn == node.applied_lsn() && entry.state["pending"].is_null() {
                break;
            }
            node.env()
                .clock
                .sleep(std::time::Duration::from_millis(5))
                .await;
        }
    })
    .await;
    recovered_stream.stop_and_join().await.unwrap();
    caught_up.unwrap();
    let entry = recovered_cursors.get("events-test:actor-native").unwrap();
    assert!(entry.lsn >= proposal_lsn);
    assert_eq!(entry.state["secret"]["version"], 8);
    let _event = {
        let requests = network.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|request| {
                serde_json::from_slice::<events::Event>(&request.body).is_ok_and(|event| {
                    event.source == native(proposal_lsn) && event.data.action == "proposal.create"
                })
            })
            .unwrap();
        let event: events::Event = serde_json::from_slice(&request.body).unwrap();
        let header = |name: &str| {
            request
                .headers
                .iter()
                .find(|(key, _)| key == name)
                .unwrap()
                .1
                .as_str()
        };
        assert_eq!(
            header("kronik-signature"),
            signature(
                b"dummy-next-key",
                header("kronik-timestamp-ms").parse().unwrap(),
                &event.id,
                &request.body
            )
            .unwrap()
        );
        event
    };
    let mut rebound = rotated;
    rebound.secret.version_hash = [9; 16];
    let rebound_stream =
        configured_stream("events-test:actor-native", &recovered_cursors, &rebound);
    assert!(
        Webhook::open(
            node,
            mapper,
            identity(),
            None,
            rebound_stream,
            recovered_cursors,
            rebound,
            signer,
            execution
        )
        .await
        .is_err()
    );
}

/// One turn of `counter/tick` in a later millisecond than every turn so far,
/// then a retention pass. With `history` 0 the window holds the fork points
/// of the newest millisecond, so a snapshot becomes the window's base only
/// once a later turn has put it behind the window.
async fn age_and_compact(node: &Node, execution: &AuthLease) {
    let hwm = node.store().db().time_hwm().unwrap();
    while node.store().db().time_hwm().unwrap() <= hwm {
        node.env()
            .clock
            .sleep(std::time::Duration::from_millis(2))
            .await;
        node.send(
            kronik_core::ids::ActorRef::parse("counter/tick").unwrap(),
            pb::Message {
                name: "increment".into(),
                ..Default::default()
            },
            audit().unwrap(),
            false,
            execution.clone(),
        )
        .await
        .unwrap()
        .unwrap();
    }
    node.compact(node.storage_config().unwrap()).unwrap();
}

#[tokio::test]
async fn compacted_actor_pending_survives_restart_and_holds_gap_until_ack() {
    use hmac::{KeyInit as _, Mac as _};
    use kronik_otel::cursor::{Control, Entry};
    use kronik_sched::snapshots::StorageConfig;
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let mut env = Env::real(tokio::runtime::Handle::current());
    let network = Arc::new(RecordingNetwork {
        failures: 2,
        ..Default::default()
    });
    env.net = network.clone();
    let mut storage = StorageConfig::new(directory.path().to_path_buf());
    storage.history = Duration::ZERO;
    let node = start_local(
        env.clone(),
        directory.path(),
        NodeConfig {
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let execution = node.local_operator_authority().unwrap();
    let mapper = Arc::new(Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: node.branch().into(),
    });
    let receipt = node
        .record_audit_event_authorized(
            "proposal.create",
            "pending-before-compaction",
            BTreeMap::new(),
            audit().unwrap(),
            execution.clone(),
        )
        .await
        .unwrap();
    let stream = "events-pending-gap:actor-native";
    let generation = [6; 16];
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    cursors
        .save(
            stream,
            Entry {
                lsn: receipt - 1,
                control: Some(Control::new(generation)),
                ..Entry::default()
            },
        )
        .await
        .unwrap();
    let settings = webhook_settings();
    let registered = configured_stream(stream, &cursors, &settings);
    let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
    let patterns: Vec<_> = snapshot
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let page = reader
        .local_export_page(receipt - 1, 1, kronik_otel::follow::BATCH_BYTES)
        .await
        .unwrap();
    assert!(page.retention_gap.is_none());
    let (source, committed) = page
        .records
        .iter()
        .find(|(source, _)| source.lsn == receipt)
        .unwrap();
    let expected = events::project(&mapper, &identity(), source, &committed.record, &patterns)
        .unwrap()
        .into_iter()
        .find(|event| event.data.action == "proposal.create")
        .unwrap();
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
    let mut sink = Webhook::open(
        node.clone(),
        mapper.clone(),
        identity(),
        None,
        registered.clone(),
        cursors.clone(),
        settings.clone(),
        resolver.clone(),
        execution.clone(),
    )
    .await
    .unwrap();
    let prepared = sink
        .prepare(
            &page.records,
            generation,
            &reader,
            &snapshot,
            authorization.clone(),
        )
        .await
        .unwrap();
    let expected_batch = serde_json::to_value(prepared.as_ref()).unwrap();
    assert!(
        matches!(sink.deliver(&prepared, authorization.clone()).await,
        kronik_otel::follow::Delivery::Retry { code, .. } if code == "http_503")
    );
    assert_eq!(
        cursors.get(stream).unwrap().state["pending"],
        expected_batch
    );
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
        node.record_audit_event_authorized(
            "proposal.create",
            &format!("gap-padding-{n}"),
            BTreeMap::from([("fixture".into(), "x".repeat(1500))]),
            audit().unwrap(),
            execution.clone(),
        )
        .await
        .unwrap();
    }
    node.deploy(
        include_bytes!("../../../tests/guests/counter.wasm"),
        audit().unwrap(),
        false,
        execution.clone(),
    )
    .await
    .unwrap();
    for n in 0..80 {
        node.send(
            kronik_core::ids::ActorRef::parse("counter/pending-gap").unwrap(),
            pb::Message {
                name: "increment".into(),
                ..Default::default()
            },
            audit().unwrap(),
            false,
            execution.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        if n % 20 == 19 {
            node.env().clock.sleep(Duration::from_millis(5)).await;
        }
    }
    node.snapshot("manual", execution.clone()).await.unwrap();
    age_and_compact(&node, &execution).await;
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(
        first > receipt,
        "the actual prepared source record must have compacted"
    );
    node.refresh_secret_inventory(execution.clone())
        .await
        .unwrap();
    let through = first - 1;
    let mut rotated = settings.clone();
    rotated.secret.version = 8;
    rotated.secret.version_hash = [8; 16];
    let recovered_cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let recovered_stream = configured_stream(stream, &recovered_cursors, &rotated);
    let mut recovered = Webhook::open(
        node.clone(),
        mapper.clone(),
        identity(),
        None,
        recovered_stream.clone(),
        recovered_cursors.clone(),
        rotated.clone(),
        resolver.clone(),
        execution.clone(),
    )
    .await
    .unwrap();
    let before = recovered_cursors.get(stream).unwrap();
    assert_eq!(before.lsn, receipt - 1);
    assert_eq!(before.generation(), generation);
    assert_eq!(before.state["pending"], expected_batch);
    assert_eq!(before.state["secret"]["version"], 8);
    assert_eq!(before.state["pending"]["pin"]["version"], 7);
    // The follower hands `gap` its ordinary original lease; the sink builds
    // the retained disclosure itself. Handing it a RetainedDisclosure here
    // would nest the same secret-publication lock and be denied.
    assert_eq!(
        recovered
            .gap(receipt, through, execution.clone())
            .await
            .unwrap_err(),
        "http_503"
    );
    let held = recovered_cursors.get(stream).unwrap();
    assert_eq!(held.lsn, before.lsn);
    assert_eq!(held.control, before.control);
    assert_eq!(held.state, before.state);
    let observed_reader = node.capture_system_export_reader().await.unwrap();
    let observed = observed_reader
        .local_export_page(
            first - 1,
            events::MAX_EVENTS,
            kronik_otel::follow::BATCH_BYTES,
        )
        .await
        .unwrap();
    assert!(
        !observed
            .records
            .iter()
            .any(|(_, record)| matches!(&record.record,
        Record::AuditEvent(event) if event.action == "audit.gap" && event.target == stream)),
        "a retry must not append the gap audit or checkpoint"
    );
    drop(recovered);
    drop(recovered_cursors);
    drop(recovered_stream);

    // Retry after another durable reload still uses the old prepared body and pin.
    let resumed_cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
    let resumed_stream = configured_stream(stream, &resumed_cursors, &rotated);
    let mut resumed = Webhook::open(
        node.clone(),
        mapper,
        identity(),
        None,
        resumed_stream.clone(),
        resumed_cursors.clone(),
        rotated,
        resolver,
        execution.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        resumed_cursors.get(stream).unwrap().state["pending"],
        expected_batch
    );
    resumed
        .gap(receipt, through, execution.clone())
        .await
        .unwrap();
    let acknowledged = resumed_cursors.get(stream).unwrap();
    assert_eq!(
        acknowledged.lsn,
        receipt - 1,
        "ACK alone is not a manifest checkpoint"
    );
    assert_eq!(acknowledged.state["pending"], expected_batch);
    let observed_reader = node.capture_system_export_reader().await.unwrap();
    let observed = observed_reader
        .local_export_page(
            first - 1,
            events::MAX_EVENTS,
            kronik_otel::follow::BATCH_BYTES,
        )
        .await
        .unwrap();
    let mut markers = Vec::new();
    for (source, record) in observed.records {
        if let Record::AuditEvent(event) = &record.record
            && event.action == "audit.gap"
            && event.target == stream
        {
            assert_eq!(source.lsn, record.lsn);
            assert_eq!(event.details.get("from"), Some(&receipt.to_string()));
            assert_eq!(event.details.get("to"), Some(&through.to_string()));
            markers.push(source.lsn);
        }
    }
    assert_eq!(
        markers.len(),
        1,
        "only acknowledged delivery may append the real gap marker"
    );
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
    let (worker_node, worker_stream, original) =
        (node.clone(), resumed_stream.clone(), execution.clone());
    resumed_stream.own_task(node.env().spawn("events-gap-checkpoint", async move {
        // The follower reports failure through the durable cursor and the
        // stream, not a return value; the catch-up loop below proves success.
        kronik_otel::follow::follow(
            worker_node,
            worker_stream,
            kronik_otel::follow::Options {
                batch: 1,
                interval: Duration::from_millis(1),
            },
            resumed,
            original,
        )
        .await;
    }));
    let caught_up = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let entry = resumed_cursors.get(stream).unwrap();
            if entry.lsn == node.applied_lsn() && entry.state["pending"].is_null() {
                break;
            }
            node.env().clock.sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
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
    use kronik_sched::snapshots::StorageConfig;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let mut storage = StorageConfig::new(dir.path().to_path_buf());
    storage.history = Duration::ZERO;
    let node = start_local(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        NodeConfig {
            storage: Some(storage),
            segment_max_bytes: Some(4096),
            ..NodeConfig::default()
        },
    )
    .await
    .unwrap();
    let execution = node.local_operator_authority().unwrap();
    let secret = b"retained-compaction-secret-needle";
    node.secret_set(
        "retention-fixture",
        secret.to_vec(),
        &audit().unwrap(),
        false,
        execution.clone(),
    )
    .await
    .unwrap()
    .unwrap();
    let secret_floor = node.store().db().secret_format_floor().unwrap().unwrap();
    for n in 0..30 {
        node.record_audit_event_authorized(
            "proposal.create",
            &format!("p-{n}"),
            BTreeMap::from([("fixture".into(), "x".repeat(1500))]),
            audit().unwrap(),
            execution.clone(),
        )
        .await
        .unwrap();
    }
    // Audit-only records do not advance the logical turn-time retention bound.
    // Use the existing real actor fixture, as the snapshot retention tests do;
    // do not delete segments or release a protected retention floor by hand.
    node.deploy(
        include_bytes!("../../../tests/guests/counter.wasm"),
        audit().unwrap(),
        false,
        execution.clone(),
    )
    .await
    .unwrap();
    for n in 0..80 {
        node.send(
            kronik_core::ids::ActorRef::parse("counter/retention").unwrap(),
            pb::Message {
                name: "increment".into(),
                ..Default::default()
            },
            audit().unwrap(),
            false,
            execution.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        if n % 20 == 19 {
            node.env().clock.sleep(Duration::from_millis(5)).await;
        }
    }
    let snapshot = node.snapshot("manual", execution.clone()).await.unwrap();
    age_and_compact(&node, &execution).await;
    let first = node.log_first(node.storage_config().unwrap()).unwrap();
    assert!(first > 1);
    assert!(first <= snapshot.lsn + 1);
    assert_eq!(
        node.store().db().secret_format_floor().unwrap(),
        Some(secret_floor)
    );
    node.refresh_secret_inventory(execution.clone())
        .await
        .unwrap();
    assert!(
        node.secret_values()
            .unwrap()
            .iter()
            .any(|(name, value)| name == "retention-fixture"
                && value.as_slice() == secret.as_slice())
    );
    let mapper = Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: "main".into(),
    };
    let mut cursor = ResumeCursor::new(identity());
    cursor
        .rewind(Position {
            source: native(1),
            subindex: 0,
        })
        .unwrap();
    cursor
        .rewind(Position {
            source: SourcePos::Actor {
                shard: Some(1),
                lsn: 900,
            },
            subindex: 2,
        })
        .unwrap();
    let reader = node.capture_system_export_reader().await.unwrap();
    let (catalogue, publication) = certified_catalogue(&node).await;
    let patterns: Vec<_> = catalogue
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let page = events::page(&reader, &mapper, &identity(), &cursor, &patterns, 2)
        .await
        .unwrap();
    let repeated = events::page(&reader, &mapper, &identity(), &cursor, &patterns, 2)
        .await
        .unwrap();
    assert_eq!(page, repeated);
    assert!(page.events.is_empty());
    assert_eq!(
        page.gap,
        Some(events::Gap {
            from: native(1),
            through: native(first - 1)
        })
    );
    assert_eq!(
        page.cursor.streams["actor-native"],
        Position {
            source: native(first),
            subindex: 0
        }
    );
    assert_eq!(page.cursor.streams["actor-1"], cursor.streams["actor-1"]);
    let retained = events::page(&reader, &mapper, &identity(), &page.cursor, &patterns, 2)
        .await
        .unwrap();
    assert!(retained.gap.is_none());
    assert!(retained.events.iter().all(
        |event| matches!(event.source, SourcePos::Actor { shard: None, lsn } if lsn >= first)
    ));
    publication.check_current().unwrap();
    execution.check().unwrap();
}

#[test]
fn actual_failed_root_emits_safe_deadletter_creation_metadata() {
    let mut turn = operator_turn();
    turn.outcome = Some(pb::Outcome {
        kind: pb::OutcomeKind::Failed as i32,
        error_code: "TURN_FAILED".into(),
        message: "failure-PII-NEEDLE VALUE-NEEDLE".into(),
        ..Default::default()
    });
    let record = Record::TurnRecord(turn);
    let catalogue = [("webhook-key", b"VALUE-NEEDLE".as_slice())];
    let projected =
        events::project(&mapper(), &identity(), &main_frame(41), &record, &catalogue).unwrap();
    let created = projected
        .iter()
        .find(|event| event.data.kind == "deadletter")
        .unwrap();
    assert_eq!(created.data.action, "created");
    assert_eq!(created.data.schema, "kronik.operation/v1");
    assert_eq!(created.data.at_wall_ms, 123);
    assert_eq!(created.record_kind, 3);
    assert_eq!(created.source, native(41));
    assert_eq!(created.subindex, 1);
    assert_eq!(created.data.record_hash, projected[0].data.record_hash);
    let wire = String::from_utf8(created.body().unwrap()).unwrap();
    for needle in [
        "failure-PII-NEEDLE",
        "VALUE-NEEDLE",
        "BODY-NEEDLE",
        "actor-PII-NEEDLE",
        "raw-name-PII-NEEDLE",
        "raw-reason-PII-NEEDLE",
    ] {
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
    cursor
        .rewind(Position {
            source: native(90),
            subindex: 0,
        })
        .unwrap();
    let mut page = events::Page {
        events: Vec::new(),
        cursor: cursor.clone(),
        applied: native(89),
        gap: None,
        more: false,
    };
    for gap in [
        None,
        Some(events::Gap {
            from: native(1),
            through: native(89),
        }),
    ] {
        page.gap = gap;
        let frame = events::sse_cursor(&page).unwrap();
        let id = frame.lines().next().unwrap().strip_prefix("id: ").unwrap();
        assert_eq!(serde_json::from_str::<ResumeCursor>(id).unwrap(), cursor);
        assert_eq!(
            frame.lines().nth(1).unwrap(),
            if page.gap.is_some() {
                "event: gap"
            } else {
                "event: cursor"
            }
        );
    }
}

#[tokio::test]
async fn canonical_operational_identity_separates_visible_changes_not_sealable_values() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut records = Vec::new();
    let original = operator_turn();
    let mut changed_value = original.clone();
    if let Some(pb::input::Kind::Message(message)) = changed_value
        .input
        .as_mut()
        .and_then(|input| input.kind.as_mut())
    {
        message.msg.as_mut().unwrap().body.as_mut().unwrap().value = Some(
            pb::sealable::Value::Plain(b"DIFFERENT-PRIVATE-BODY-NEEDLE".to_vec()),
        );
    }
    assert_ne!(original, changed_value);
    let mut sources = ["proposal.create", "proposal.cancel"]
        .into_iter()
        .map(|action| {
            Record::AuditEvent(pb::AuditEvent {
                action: action.into(),
                target: "p-1".into(),
                audit: audit(),
                ..Default::default()
            })
        })
        .collect::<Vec<_>>();
    sources.extend([
        Record::TurnRecord(original),
        Record::TurnRecord(changed_value),
    ]);
    for (index, source) in sources.into_iter().enumerate() {
        let (tx, mut committed) = tokio::sync::mpsc::unbounded_channel();
        let (fatal, _failed) = tokio::sync::oneshot::channel();
        let mut config =
            kronik_log::LogConfig::new(directory.path().join(index.to_string()), "main");
        config.first_lsn = 9;
        let (log, _) = kronik_log::Log::open(&env, config, tx, fatal)
            .await
            .unwrap();
        log.append(source).await.unwrap();
        records.push(committed.recv().await.unwrap());
    }
    // Actual tails reuse a position; only canonical operational identity is compared.
    assert_eq!(records[0].lsn, records[1].lsn);
    let first = events::project(
        &mapper(),
        &identity(),
        &main_frame(records[0].lsn),
        &records[0].record,
        &[],
    )
    .unwrap();
    let retry = events::project(
        &mapper(),
        &identity(),
        &main_frame(records[0].lsn),
        &records[0].record,
        &[],
    )
    .unwrap();
    let restored_tail = events::project(
        &mapper(),
        &identity(),
        &main_frame(records[1].lsn),
        &records[1].record,
        &[],
    )
    .unwrap();
    assert_eq!(first[0].id, retry[0].id);
    assert_eq!(first[0].body().unwrap(), retry[0].body().unwrap());
    assert_ne!(first[0].data.action, restored_tail[0].data.action);
    assert_ne!(first[0].data.record_hash, restored_tail[0].data.record_hash);
    assert_ne!(first[0].id, restored_tail[0].id);
    assert_eq!(first[0].source, restored_tail[0].source);
    let private_first = events::project(
        &mapper(),
        &identity(),
        &main_frame(records[2].lsn),
        &records[2].record,
        &[],
    )
    .unwrap();
    let private_changed = events::project(
        &mapper(),
        &identity(),
        &main_frame(records[3].lsn),
        &records[3].record,
        &[],
    )
    .unwrap();
    assert_eq!(private_first[0].data, private_changed[0].data);
    assert_eq!(private_first[0].id, private_changed[0].id);
    assert_eq!(
        private_first[0].body().unwrap(),
        private_changed[0].body().unwrap()
    );
    assert!(events::event_id(&identity(), native(9), Some("main"), 0, "b3:invalid").is_err());
    assert!(
        events::event_id(
            &identity(),
            native(9),
            Some("main"),
            0,
            &format!("b3:{}", "0".repeat(64))
        )
        .is_err()
    );
}

#[tokio::test]
async fn real_secret_version_and_link_wire_records_publish_exact_phase_actions() {
    let (_directory, log, mut committed, _fatal) = native_log().await;
    let schema = events::schemas().unwrap();
    for (kind, wire, expected_kind, expected_action, epoch) in [
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-reserved-v1.hex"),
            "secret_version",
            "secret.version.reserved",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex"),
            "secret_version",
            "secret.version",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-version-wide-failed-v1.hex"),
            "secret_version",
            "secret.version.failed",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-version-legacy-v1.hex"),
            "secret_version",
            "secret.version",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-version-max-v1.hex"),
            "secret_version",
            "secret.version",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-fence-fresh-v1.hex"),
            "secret_version",
            "secret.range",
            None,
        ),
        (
            45,
            include_str!("../../kronik-proto/tests/fixtures/secret-fence-legacy-v1.hex"),
            "secret_version",
            "secret.range",
            None,
        ),
        (
            46,
            include_str!("../../kronik-proto/tests/fixtures/secret-link-v1.hex"),
            "secret_link",
            "secret.link",
            Some(7),
        ),
        (
            46,
            include_str!("../../kronik-proto/tests/fixtures/secret-unlink-v1.hex"),
            "secret_link",
            "secret.unlink",
            Some(8),
        ),
    ] {
        let record = Record::decode(kind, &kronik_core::ids::unhex(wire.trim()).unwrap()).unwrap();
        let lsn = log.append(record).await.unwrap();
        let source = committed.recv().await.unwrap();
        assert_eq!(source.lsn, lsn);
        let projected = events::project(
            &mapper(),
            &identity(),
            &main_frame(source.lsn),
            &source.record,
            &[],
        )
        .unwrap();
        let event = projected
            .iter()
            .find(|event| event.data.action == expected_action)
            .unwrap();
        assert_eq!(event.data.kind, expected_kind);
        assert_eq!(event.data.epoch, epoch);
        assert_eq!(event.data.at_wall_ms, 1);
        assert_eq!(event.data.effect, None);
        assert_eq!(event.record_kind, kind);
        assert_eq!(event.source, native(source.lsn));
        let metadata = serde_json::to_value(&event.data).unwrap();
        for private in [
            "name",
            "backend",
            "binding",
            "ref",
            "canonical_ref",
            "source_version",
            "version_hash",
            "reason",
            "token_id",
            "details",
        ] {
            assert!(metadata.get(private).is_none());
        }
        let constraint = schema["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|constraint| {
                constraint["if"]["properties"]["record_kind"]["const"] == json!(kind)
            })
            .unwrap();
        let published = &constraint["then"]["properties"]["data"]["properties"];
        assert_eq!(published["kind"]["const"], expected_kind);
        assert!(
            published["action"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!(expected_action))
        );
    }
}

fn control_record(operation: pb::audit_event::Operation) -> Record {
    let mut audit = audit().unwrap();
    if matches!(
        &operation,
        pb::audit_event::Operation::InstallationIdentity(_)
    ) {
        audit.token_id = "system:installation".into();
    }
    Record::AuditEvent(pb::AuditEvent {
        action: operation.action().into(),
        target: operation.target().into(),
        operation: Some(operation),
        audit: Some(audit),
        details: BTreeMap::new(),
    })
}

fn control_fixtures() -> Vec<(Record, &'static str, Option<events::FleetPhase>)> {
    use pb::audit_event::Operation;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
        DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };
    use sha2::Digest as _;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../kronik-proto/tests/fixtures/control-fleet-pending-v1.json"
    ))
    .unwrap();
    let bytes = |name: &str| kronik_core::ids::unhex(fixture[name].as_str().unwrap()).unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let ca_sha256 = sha2::Sha256::digest(root.der()).to_vec();
    let issuer = Issuer::new(ca, key);
    let mut fleet = pb::FleetState {
        installation: fixture["installation"].as_str().unwrap().into(),
        controller_origin: fixture["controller_origin"].as_str().unwrap().into(),
        scopes: vec!["read".into()],
        ca_sha256,
        request_id: bytes("request_id"),
        epoch: 1,
        phase: pb::fleet_state::Phase::Pending as i32,
        csr_der: bytes("csr_der_hex"),
        client_key_sha256: bytes("client_key_sha256"),
        ..Default::default()
    };
    let mut records = vec![(
        control_record(Operation::FleetState(fleet.clone())),
        "fleet.state",
        Some(events::FleetPhase::Pending),
    )];
    fleet.phase = pb::fleet_state::Phase::Requested as i32;
    records.push((
        control_record(Operation::FleetState(fleet.clone())),
        "fleet.state",
        Some(events::FleetPhase::Requested),
    ));
    let csr = CertificateSigningRequestParams::from_der(
        &rustls_pki_types::CertificateSigningRequestDer::from(fleet.csr_der.as_slice()),
    )
    .unwrap();
    let mut certificate = CertificateParams::default();
    certificate.distinguished_name = DistinguishedName::new();
    certificate
        .distinguished_name
        .push(DnType::CommonName, &fleet.installation);
    certificate.subject_alt_names = vec![SanType::URI(
        format!(
            "urn:kronik:fleet:request:{}:{}",
            kronik_core::ids::hex(&fleet.request_id),
            fleet.epoch
        )
        .try_into()
        .unwrap(),
    )];
    certificate.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    certificate.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    fleet.client_cert_der = Some(
        certificate
            .signed_by(&csr.public_key, &issuer)
            .unwrap()
            .der()
            .to_vec(),
    );
    fleet.controller_id = Some(kronik_core::ids::hex(&fleet.ca_sha256));
    fleet.phase = pb::fleet_state::Phase::Active as i32;
    records.push((
        control_record(Operation::FleetState(fleet.clone())),
        "fleet.state",
        Some(events::FleetPhase::Active),
    ));
    fleet.phase = pb::fleet_state::Phase::Revoked as i32;
    records.push((
        control_record(Operation::FleetState(fleet)),
        "fleet.state",
        Some(events::FleetPhase::Revoked),
    ));
    records.push((
        control_record(Operation::InstallationIdentity(pb::InstallationIdentity {
            installation: identity().installation,
        })),
        "installation.identity",
        None,
    ));
    let mut auth = pb::AuthConfig {
        version: kronik_proto::control::AUTH_CONFIG_VERSION,
        ..Default::default()
    };
    auth.digest = kronik_proto::control::auth_config_digest(&auth).to_vec();
    records.push((
        control_record(Operation::AuthConfig(auth)),
        "auth.config",
        None,
    ));
    records
}

#[tokio::test]
async fn typed_controls_publish_real_native_records_and_closed_fleet_phase() {
    let (_directory, log, mut committed, _fatal) = native_log().await;
    let mut phases = BTreeMap::new();
    for (record, action, phase) in control_fixtures() {
        let decoded = Record::decode(record.kind(), &record.encode()).unwrap();
        let lsn = log.append(decoded).await.unwrap();
        let record = committed.recv().await.unwrap();
        assert_eq!(record.lsn, lsn);
        let event = events::project(
            &mapper(),
            &identity(),
            &main_frame(lsn),
            &record.record,
            &[],
        )
        .unwrap()
        .remove(0);
        assert_eq!(event.data.kind, "audit_event");
        assert_eq!(event.data.action, action);
        assert_eq!(event.data.phase, phase);
        assert_eq!(event.data.epoch, phase.map(|_| 1));
        let body = String::from_utf8(event.body().unwrap()).unwrap();
        for needle in [
            "raw-reason-PII-NEEDLE",
            "raw-name-PII-NEEDLE",
            "csr_der",
            "client_cert_der",
        ] {
            assert!(!body.contains(needle));
        }
        if let Some(phase) = phase {
            let name = serde_json::to_value(phase)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["data"]["phase"],
                name
            );
            phases.insert(name, event);
        } else {
            assert!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["data"]
                    .get("phase")
                    .is_none()
            );
        }
    }
    let active = &phases["active"];
    let revoked = &phases["revoked"];
    assert_eq!(active.data.epoch, revoked.data.epoch);
    assert_ne!(active.data.phase, revoked.data.phase);
    assert_ne!(active.id, revoked.id);
    assert_ne!(active.data.record_hash, revoked.data.record_hash);
}

struct CapturedWebhook {
    headers: Vec<(String, String)>,
    body: bytes::Bytes,
}

struct RecordingNetwork {
    requests: Arc<std::sync::Mutex<Vec<CapturedWebhook>>>,
    failures: usize,
}

impl Default for RecordingNetwork {
    fn default() -> Self {
        Self {
            requests: Default::default(),
            failures: 1,
        }
    }
}

impl kronik_core::env::Net for RecordingNetwork {
    fn http_authorized(
        &self,
        request: kronik_core::env::HttpRequest,
        original: kronik_core::authority::AuthLease,
    ) -> kronik_core::env::BoxFuture<
        'static,
        Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>,
    > {
        let requests = self.requests.clone();
        let failures = self.failures;
        Box::pin(async move {
            let body = request.body;
            if body.len() > events::MAX_PAGE_BYTES {
                return Err(kronik_core::env::NetError::TooLarge);
            }
            let mut pending = Some(CapturedWebhook {
                headers: request.headers,
                body,
            });
            let mut status = None;
            original
                .admit(&mut || {
                    let request = pending.take().ok_or_else(|| {
                        kronik_core::error::ApiError::new(
                            kronik_core::error::ErrorCode::Internal,
                            "HTTP request admitted twice",
                        )
                    })?;
                    let mut requests = requests.lock().unwrap();
                    status = Some(if requests.len() < failures { 503 } else { 200 });
                    requests.push(request);
                    Ok(())
                })
                .map_err(|error| kronik_core::env::NetError::Connect(error.code.as_str().into()))?;
            let status = status.ok_or_else(|| {
                kronik_core::env::NetError::Connect("HTTP request was not admitted".into())
            })?;
            Ok(kronik_core::env::HttpResponse {
                status,
                headers: Vec::new(),
                body: bytes::Bytes::new(),
            })
        })
    }

    fn http(
        &self,
        _request: kronik_core::env::HttpRequest,
    ) -> kronik_core::env::BoxFuture<
        'static,
        Result<kronik_core::env::HttpResponse, kronik_core::env::NetError>,
    > {
        Box::pin(async {
            Err(kronik_core::env::NetError::Connect(
                "unscoped HTTP is forbidden".into(),
            ))
        })
    }
}

#[test]
fn cursor_bound_covers_every_actual_source_and_rejects_overflow_without_truncation() {
    let mut identity = identity();
    identity.installation = "i".repeat(128);
    identity.branch = "b".repeat(128);
    let mut cursor = ResumeCursor::new(identity.clone());
    cursor.streams = (0..kronik_proto::MAX_SHARD_COUNT)
        .map(|shard| {
            let source = SourcePos::Actor {
                shard: Some(shard),
                lsn: u64::MAX,
            };
            (
                events::domain(source).into_owned(),
                Position {
                    source,
                    subindex: u32::MAX,
                },
            )
        })
        .collect();
    for source in [native(u64::MAX), SourcePos::Metadata { index: u64::MAX }] {
        cursor.streams.insert(
            events::domain(source).into_owned(),
            Position {
                source,
                subindex: u32::MAX,
            },
        );
    }
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS);
    cursor.validate(&identity).unwrap();
    let encoded = serde_json::to_vec(&cursor).unwrap();
    // Payload-only coverage, deliberately not a claim about HTTP header limits.
    assert!(encoded.len() > 65_536);
    assert!(encoded.len() <= events::MAX_CURSOR_BYTES);
    let decoded: ResumeCursor = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, cursor);
    assert_eq!(
        events::schemas().unwrap()["$defs"]["cursor"]["properties"]["streams"]["maxProperties"],
        events::MAX_STREAMS
    );
    assert!(
        cursor
            .rewind(Position {
                source: SourcePos::Actor {
                    shard: Some(kronik_proto::MAX_SHARD_COUNT),
                    lsn: 1
                },
                subindex: 0
            })
            .is_err()
    );
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS);
    cursor.streams.insert(
        "overflow".into(),
        Position {
            source: native(1),
            subindex: 0,
        },
    );
    assert_eq!(cursor.streams.len(), events::MAX_STREAMS + 1);
    assert!(cursor.validate(&identity).is_err());
}

fn logout_wire_record() -> (Record, serde_json::Value) {
    use prost::Message as _;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../kronik-proto/tests/fixtures/auth-session-revoked-native-v1.json"
    ))
    .unwrap();
    let wire = kronik_core::ids::unhex(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let operation = pb::AuthSessionRevoked::decode(wire.as_slice()).unwrap();
    assert_eq!(operation.encode_to_vec(), wire);
    let record = Record::AuditEvent(pb::AuditEvent {
        action: "auth.logout".into(),
        audit: Some(pb::Audit {
            token_id: format!("oidc:{}", kronik_core::ids::hex(&operation.principal_hash)),
            reason: "logout cookie-private-NEEDLE".into(),
            wall_time_ms: 1,
        }),
        operation: Some(pb::audit_event::Operation::AuthSessionRevoked(operation)),
        ..Default::default()
    });
    (
        Record::decode(record.kind(), &record.encode()).unwrap(),
        fixture,
    )
}

fn assert_private_auth_event(record: &Record, fixture: &serde_json::Value, lsn: u64, action: &str) {
    let mapper = mapper();
    let secrets = [
        ("cookie", b"cookie-private-NEEDLE".as_slice()),
        ("claims", b"private-claims-NEEDLE".as_slice()),
        (
            "principal",
            fixture["principal_hash"].as_str().unwrap().as_bytes(),
        ),
        ("token-name", b"operator".as_slice()),
    ];
    let project =
        |record: &Record| events::project(&mapper, &identity(), &main_frame(lsn), record, &secrets);
    let event = project(record).unwrap().remove(0);
    assert_eq!(event.record_kind, 40);
    assert_eq!(event.source, native(lsn));
    assert_eq!(event.data.schema, "kronik.audit/v3");
    assert_eq!(event.data.kind, "audit_event");
    assert_eq!(event.data.action, action);
    assert_eq!(event.data.at_wall_ms, 1);
    assert_eq!(
        (event.data.epoch, event.data.effect, event.data.phase),
        (None, None, None)
    );
    assert_eq!(
        Some(event.data.record_hash.clone()),
        kronik_otel::audit::record_hash(record, &mapper.sealer)
    );
    let body = event.body().unwrap();
    let published: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for private in [
        "details",
        "token_id",
        "reason",
        "session_hash",
        "principal_hash",
        "config_digest",
        "config_source",
        "token_name",
        "expires_at_ms",
        "metadata_token",
        "peer_boot",
    ] {
        assert!(published["data"].get(private).is_none());
    }
    assert!(!String::from_utf8_lossy(&body).contains("cookie-private-NEEDLE"));
    assert!(!String::from_utf8_lossy(&body).contains("private-claims-NEEDLE"));
    assert!(!String::from_utf8_lossy(&body).contains(fixture["principal_hash"].as_str().unwrap()));
    assert_eq!(event.branch.as_deref(), Some("main"));
    assert_eq!(project(record).unwrap()[0].body().unwrap(), body);
    let mut invalid = record.clone();
    let Record::AuditEvent(audit) = &mut invalid else {
        unreachable!()
    };
    audit
        .details
        .insert("cookie".into(), "cookie-private-NEEDLE".into());
    assert_eq!(
        project(&invalid).unwrap_err().code,
        kronik_core::error::ErrorCode::StorageCorrupt
    );
}

#[tokio::test]
async fn native_logout_wire_record_is_fsynced_and_public_event_omits_session_identity() {
    let (record, fixture) = logout_wire_record();
    let (_directory, log, mut committed, _fatal) = native_log().await;
    let lsn = log.append(record).await.unwrap();
    let record = committed.recv().await.unwrap();
    assert_eq!(record.lsn, lsn);
    assert_private_auth_event(&record.record, &fixture, record.lsn, "auth.logout");
}

#[tokio::test]
async fn dynamic_webhook_names_are_owned_released_and_persist_beyond_sixty_four_targets() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env.clone(), directory.path(), NodeConfig::default())
        .await
        .unwrap();
    let cursors = Arc::new(Cursors::load(env.clone(), directory.path()).await.unwrap());
    let settings = Settings {
        url: "http://127.0.0.1:9/events".into(),
        secret: SecretVersion {
            name: "webhook-key".into(),
            version: 7,
            branch: "main".into(),
            version_hash: [7; 16],
            hash_revision: 1,
            backend: "local".into(),
            binding: String::new(),
            reference: String::new(),
            canonical_ref: String::new(),
            link_generation: 0,
            source_version: String::new(),
        },
    };
    let resolver: Arc<webhook::Resolver> = Arc::new(|_, _, _original| {
        Box::pin(async { panic!("opening a stream must not resolve a key") })
    });
    let mut sinks = Vec::new();
    let mut names = Vec::new();
    for number in 0..65 {
        let name: Arc<str> = format!("events-owned-{number}").into();
        names.push(Arc::downgrade(&name));
        let stream = configured_stream(name.clone(), &cursors, &settings);
        sinks.push(
            Webhook::open(
                node.clone(),
                Arc::new(mapper()),
                identity(),
                None,
                stream,
                cursors.clone(),
                settings.clone(),
                resolver.clone(),
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap(),
        );
        drop(name);
        assert!(names.last().unwrap().upgrade().is_some());
    }
    // The durable manifest is the count of owned stream names; `Cursors` has
    // no public name enumeration, so read the file the loader reads.
    let manifest = || -> usize {
        let bytes = std::fs::read(directory.path().join(Cursors::FILE)).unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .as_object()
            .unwrap()
            .len()
    };
    assert_eq!(manifest(), 65);
    drop(sinks);
    assert!(names.iter().all(|name| name.upgrade().is_none()));
    let reloaded = Cursors::load(env, directory.path()).await.unwrap();
    assert_eq!(manifest(), 65);
    for number in 0..65 {
        let name = format!("events-owned-{number}");
        let entry = reloaded.get(&name).unwrap();
        assert_eq!(webhook::cursor_source(&entry).unwrap(), native(0));
        assert_eq!(
            entry.state["secret"],
            serde_json::to_value(&settings.secret).unwrap()
        );
    }
}

#[tokio::test]
async fn real_native_audit_free_details_cannot_publish_an_adoption_marker() {
    let directory = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, directory.path(), NodeConfig::default())
        .await
        .unwrap();
    let original = node.local_operator_authority().unwrap();
    let lsn = node.record_audit_event_authorized("fleet.note", "ordinary-native-note",
        [("native_origin".into(), "{\"current_projection\":true,\"adoption_audit\":\"private-provenance-NEEDLE\"}".into()),
            ("current_projection".into(), "true".into())].into(),
        pb::Audit { token_id: "unix:uid=0".into(), reason: "exercise actual native projection".into(),
            wall_time_ms: node.env().clock.wall_ms() }, original.clone()).await.unwrap();
    let (reader, snapshot, authorization) = native_disclosure(&node, &original).await;
    let page = reader
        .local_export_page(lsn - 1, 1, kronik_otel::follow::BATCH_BYTES)
        .await
        .unwrap();
    let (source, committed) = page
        .records
        .iter()
        .find(|(_, committed)| committed.lsn == lsn)
        .unwrap();
    let patterns: Vec<_> = snapshot
        .values
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let mapper = Mapper {
        keys: Keys::Omit,
        sealer: node.sealer().clone(),
        branch: node.branch().into(),
    };
    let event = events::project(&mapper, &identity(), source, &committed.record, &patterns)
        .unwrap()
        .remove(0);
    authorization.check().unwrap();
    assert_eq!(event.source, native(lsn));
    assert_eq!(event.data.action, "fleet.note");
    assert!(event.data.adoption.is_none());
    let body = event.body().unwrap();
    let public: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(public["data"].get("adoption").is_none());
    for private in [
        "native_origin",
        "current_projection",
        "adoption_audit",
        "private-provenance-NEEDLE",
        "unix:uid=0",
        "exercise actual native projection",
    ] {
        assert!(!String::from_utf8_lossy(&body).contains(private));
    }
}

fn login_wire_record() -> (Record, serde_json::Value) {
    use prost::Message as _;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../kronik-proto/tests/fixtures/auth-oidc-login-native-v1.json"
    ))
    .unwrap();
    let wire = kronik_core::ids::unhex(fixture["wire_hex"].as_str().unwrap()).unwrap();
    let login = pb::AuthOidcLogin::decode(wire.as_slice()).unwrap();
    assert_eq!(login.encode_to_vec(), wire);
    let record = Record::AuditEvent(pb::AuditEvent {
        action: "auth.oidc.login".into(),
        audit: Some(pb::Audit {
            token_id: format!("oidc:{}", kronik_core::ids::hex(&login.principal_hash)),
            reason: "login private-claims-NEEDLE".into(),
            wall_time_ms: 1,
        }),
        operation: Some(pb::audit_event::Operation::AuthOidcLogin(login)),
        ..Default::default()
    });
    (
        Record::decode(record.kind(), &record.encode()).unwrap(),
        fixture,
    )
}

#[tokio::test]
async fn native_login_wire_record_is_fsynced_and_public_event_omits_claims_and_principal() {
    let (record, fixture) = login_wire_record();
    let (_directory, log, mut committed, _fatal) = native_log().await;
    let lsn = log.append(record).await.unwrap();
    let record = committed.recv().await.unwrap();
    assert_eq!(record.lsn, lsn);
    assert_private_auth_event(&record.record, &fixture, record.lsn, "auth.oidc.login");
}

#[tokio::test]
async fn approval_wire_records_keep_protected_identity_private_and_value_only_reseal_identity_stable()
 {
    let (_directory, log, mut commits, _fatal) = native_log().await;
    let mapper = mapper();
    // The project now keeps approval wire data private; the proto fixture files
    // named by an earlier revision were never committed, so encode the same
    // native and sealed-identity approvals through the real wire codec.
    let protected_owner = format!("oidc:{}", "ab".repeat(32));
    let approval_audit = |owner: &str| pb::Audit {
        token_id: owner.into(),
        reason: "raw-reason-PII-NEEDLE".into(),
        wall_time_ms: 1,
    };
    let native = pb::Approval {
        proposal_id: "p-7h3k2a9c1d0e".into(),
        diff_hash: vec![0xab; 32],
        verified_through_lsn: 1,
        audit: Some(approval_audit("token:raw-name-PII-NEEDLE")),
        request: false,
        command: String::new(),
        verified_identity: None,
    };
    let verified = pb::Approval {
        verified_identity: Some(pb::Sealable {
            subject: Some(protected_owner.clone()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: vec![1; 24],
                ciphertext: vec![2; 32],
            })),
        }),
        audit: Some(approval_audit(&protected_owner)),
        ..native.clone()
    };
    for (approval, protected) in [(native, false), (verified, true)] {
        let record = Record::decode(8, &Record::Approval(approval).encode()).unwrap();
        let lsn = log.append(record).await.unwrap();
        let committed = commits.recv().await.unwrap();
        assert_eq!(committed.lsn, lsn);
        let event = events::project(
            &mapper,
            &identity(),
            &main_frame(lsn),
            &committed.record,
            &[],
        )
        .unwrap()
        .remove(0);
        assert_eq!(
            (
                event.record_kind,
                event.data.kind.as_str(),
                event.data.action.as_str()
            ),
            (8, "approval", "approve")
        );
        assert_eq!(event.data.at_wall_ms, 1);
        assert_eq!(
            (event.data.epoch, event.data.effect, event.data.phase),
            (None, None, None)
        );
        let body = event.body().unwrap();
        let published: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for private in [
            "verified_identity",
            "token_id",
            "reason",
            "details",
            "subject",
            "email",
            "display_name",
        ] {
            assert!(published["data"].get(private).is_none());
        }
        assert!(!String::from_utf8_lossy(&body).contains("oidc:"));
        assert!(!String::from_utf8_lossy(&body).contains("unix:uid"));
        if protected {
            let mut resealed = committed.record.clone();
            let Record::Approval(approval) = &mut resealed else {
                unreachable!()
            };
            let Some(pb::sealable::Value::Sealed(value)) =
                approval.verified_identity.as_mut().unwrap().value.as_mut()
            else {
                panic!("the actual protected fixture must be sealed")
            };
            value.key_version += 1;
            value.nonce.fill(4);
            value.ciphertext.fill(5);
            let resealed = Record::decode(resealed.kind(), &resealed.encode()).unwrap();
            assert_ne!(resealed.encode(), committed.record.encode());
            // Unit reseal mutation at the original position, not another commit
            // or a claim that all changed records must change their identity.
            let same = events::project(&mapper, &identity(), &main_frame(lsn), &resealed, &[])
                .unwrap()
                .remove(0);
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
                self.inner.spawn(
                    name,
                    Box::pin(async move {
                        work.await;
                        completed.notify_one();
                    }),
                );
            } else {
                self.inner.spawn(name, work);
            }
        }
        fn spawn_blocking(&self, name: &'static str, work: Box<dyn FnOnce() + Send + 'static>) {
            self.inner.spawn_blocking(name, work);
        }
    }
    async fn receive(
        stream: &mut tokio::net::TcpStream,
    ) -> (BTreeMap<String, String>, bytes::Bytes) {
        let mut wire = Vec::new();
        let mut buffer = [0; 4096];
        let end = loop {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&buffer[..n]);
            assert!(wire.len() <= events::MAX_PAGE_BYTES + 8192);
            if let Some(at) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let mut lines = std::str::from_utf8(&wire[..end]).unwrap().split("\r\n");
        assert_eq!(lines.next().unwrap(), "POST /events HTTP/1.1");
        let mut headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').unwrap();
            assert!(
                headers
                    .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                    .is_none()
            );
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
        env.spawner = Arc::new(HttpJobs {
            inner: env.spawner.clone(),
            started_jobs: started_jobs.clone(),
            completed: completed.clone(),
        });
        let node = start_local(env.clone(), directory.path(), NodeConfig::default())
            .await
            .unwrap();
        let execution = node.local_operator_authority().unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let url = format!("http://{}/events", listener.local_addr().unwrap());
        let settings = Settings {
            url,
            ..webhook_settings()
        };
        let signing_node = node.clone();
        let resolver: Arc<webhook::Resolver> = Arc::new(move |_, message, _original| {
            let node = signing_node.clone();
            Box::pin(async move {
                let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(KEY).unwrap();
                mac.update(&message);
                let result = mac.finalize().into_bytes().into();
                // Real physical publication occurs AFTER computing the MAC and
                // before returning it: a check-before-sign implementation loses.
                if revoke_after_mac {
                    node.stop_native_execution().unwrap();
                }
                Ok(result)
            })
        });
        let cursors = Arc::new(Cursors::load(env, directory.path()).await.unwrap());
        let mapper = Arc::new(Mapper {
            keys: Keys::Omit,
            sealer: node.sealer().clone(),
            branch: "main".into(),
        });
        let stream = configured_stream("events-http-fence:actor-native", &cursors, &settings);
        let mut sink = Webhook::open(
            node.clone(),
            mapper.clone(),
            identity(),
            None,
            stream.clone(),
            cursors.clone(),
            settings,
            resolver,
            execution.clone(),
        )
        .await
        .unwrap();
        let (reader, snapshot, authorization) = native_disclosure(&node, &execution).await;
        let patterns: Vec<_> = snapshot
            .values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let page = reader
            .local_export_page(0, 1, kronik_otel::follow::BATCH_BYTES)
            .await
            .unwrap();
        let (frame, committed) = page
            .records
            .iter()
            .find(|(_, record)| matches!(record.record, Record::SecretVersion(_)))
            .unwrap();
        let source = SourcePos::Actor {
            shard: frame.shard,
            lsn: frame.lsn,
        };
        let expected = events::project(&mapper, &identity(), frame, &committed.record, &patterns)
            .unwrap()
            .into_iter()
            .find(|event| event.source == source && event.record_kind == 45)
            .unwrap()
            .id;
        let batch = sink
            .prepare(
                &page.records,
                [0; 16],
                &reader,
                &snapshot,
                authorization.clone(),
            )
            .await
            .unwrap();
        let prepared = serde_json::to_value(batch.as_ref()).unwrap();
        if revoke_after_mac {
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                sink.deliver(&batch, authorization.clone()),
            )
            .await
            .unwrap();
            let denied = execution.check().unwrap_err();
            assert!(
                matches!(result, kronik_otel::follow::Delivery::Retry { code, .. }
                if code == denied.code.as_str() || code == "execution_revoked")
            );
            assert_eq!(started_jobs.load(Ordering::SeqCst), 0);
            assert!(
                tokio::time::timeout(Duration::from_millis(150), listener.accept())
                    .await
                    .is_err()
            );
        } else {
            let (arrived, received) = tokio::sync::oneshot::channel();
            let (release, response) = tokio::sync::oneshot::channel();
            let receiver = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = receive(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                arrived.send(request).unwrap();
                response.await.unwrap();
                stream.write_all(b"ok").await.unwrap();
            });
            let sending = tokio::spawn(async move { sink.deliver(&batch, authorization).await });
            let (headers, body) = tokio::time::timeout(Duration::from_secs(5), received)
                .await
                .unwrap()
                .unwrap();
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
            mac.verify_slice(
                &kronik_core::ids::unhex(headers["kronik-signature"].strip_prefix("v1=").unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(started_jobs.load(Ordering::SeqCst), 1);
            // Dropping the waiter must not cancel the admitted owned HTTP job.
            sending.abort();
            assert!(sending.await.unwrap_err().is_cancelled());
            node.stop_native_execution().unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(150), completed.notified())
                    .await
                    .is_err(),
                "response headers must not complete the owned HTTP job before body EOF"
            );
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), completed.notified())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), receiver)
                .await
                .unwrap()
                .unwrap();
            assert!(execution.check().is_err());
            assert_eq!(started_jobs.load(Ordering::SeqCst), 1);
        }
        let pending = cursors.get("events-http-fence:actor-native").unwrap();
        assert_eq!(pending.lsn, 0);
        assert_eq!(pending.state["pending"], prepared);
    }
}

#[tokio::test]
async fn actual_branch_headers_bind_event_identity_not_reader_head_or_feed_selection() {
    use kronik_log::{Log, LogConfig, LogReader};
    use std::{collections::BTreeSet, time::Duration};
    // Current format: one branch header per log directory. The mixed-header
    // single-WAL writer an earlier revision of this test used (kronik_log's
    // SegmentWriter/SegmentWriterConfig/LogConfig::also_accept and
    // kronik_sched::NodeShared) is not in this checkout. Build one real log
    // per branch from the same committed producer records instead: the durable
    // header namespace, never the reader head or the feed selection, binds each
    // event identity.
    let root = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let producer = start_local(
        env.clone(),
        &root.path().join("producer"),
        NodeConfig::default(),
    )
    .await
    .unwrap();
    let original = producer.local_operator_authority().unwrap();
    let audit = || pb::Audit {
        token_id: "system".into(),
        reason: "genuine branch source fixture".into(),
        wall_time_ms: 1,
    };
    producer
        .deploy(
            include_bytes!("../../../tests/guests/counter.wasm"),
            audit(),
            false,
            original.clone(),
        )
        .await
        .unwrap();
    producer
        .send(
            kronik_core::ids::ActorRef::parse("counter/mixed").unwrap(),
            pb::Message {
                name: "increment".into(),
                ..Default::default()
            },
            audit(),
            false,
            original.clone(),
        )
        .await
        .unwrap()
        .unwrap();
    producer
        .record_audit_event_authorized(
            "operator.note",
            "fork-edge",
            BTreeMap::new(),
            audit(),
            original.clone(),
        )
        .await
        .unwrap();
    producer
        .record_audit_event_authorized(
            "operator.note",
            "rebased-edge",
            BTreeMap::new(),
            audit(),
            original,
        )
        .await
        .unwrap();
    let captured = producer.capture_system_export_reader().await.unwrap();
    let SourcePos::Actor {
        shard: None,
        lsn: head,
    } = captured.point().source
    else {
        panic!("the actual producer must be native");
    };
    let page = captured.local_export_page(0, 256, 4 << 20).await.unwrap();
    assert_eq!(page.scanned_through, head);
    let records: Vec<_> = page
        .records
        .into_iter()
        .map(|(_, committed)| committed)
        .collect();
    drop(captured);
    producer.stop_native_execution().unwrap();
    drop(producer);
    assert!(!records.is_empty());

    // The same committed record bytes, each under a real branch header.
    let branches = ["main", "fork-original", "rebased-main"];
    let mut logs = Vec::new();
    for branch in branches {
        let dir = root.path().join(format!("wal-{branch}"));
        let mut config = LogConfig::new(dir.clone(), branch);
        config.group_commit_window = Duration::ZERO;
        let (committed_tx, _committed_rx) = tokio::sync::mpsc::unbounded_channel();
        let (fatal_tx, _fatal_rx) = tokio::sync::oneshot::channel();
        let (log, _) = Log::open(&env, config, committed_tx, fatal_tx)
            .await
            .unwrap();
        let mut last = 0;
        for committed in &records {
            last = log.append(committed.record.clone()).await.unwrap();
        }
        drop(log);
        logs.push((branch, dir, last));
    }

    let mapper = mapper();
    let mut branches_seen = BTreeSet::new();
    let mut ids_per_record: Vec<Vec<String>> = vec![Vec::new(); records.len()];
    for (branch, dir, last) in &logs {
        let reader = LogReader::new(env.clone(), dir.clone(), *branch);
        let mut read = Vec::new();
        reader
            .read_while_with_namespace(0, *last, |header, committed| {
                read.push((header.to_owned(), committed));
                Ok(true)
            })
            .await
            .unwrap();
        assert_eq!(read.len(), records.len());
        let mut selection = identity();
        selection.branch = (*branch).into();
        let mut another_selection = selection.clone();
        another_selection.branch = "another-feed".into();
        for (index, (header, committed)) in read.iter().enumerate() {
            // The namespace comes from the held segment header, never from the
            // reader head, the feed selection or the record content.
            assert_eq!(header.as_str(), *branch);
            assert_eq!(committed.lsn, index as u64 + 1);
            let source = pb::ActorSource {
                shard: None,
                lsn: committed.lsn,
                branch: header.clone(),
            };
            let projected =
                events::project(&mapper, &selection, &source, &committed.record, &[]).unwrap();
            let replay =
                events::project(&mapper, &another_selection, &source, &committed.record, &[])
                    .unwrap();
            assert_eq!(projected.len(), replay.len());
            for (event, again) in projected.iter().zip(&replay) {
                branches_seen.insert(header.clone());
                // This record's own durable coordinate and header branch bind
                // its identity; nothing here uses the reader head.
                assert_eq!(event.branch.as_deref(), Some(header.as_str()));
                assert_eq!(
                    event.source,
                    SourcePos::Actor {
                        shard: None,
                        lsn: committed.lsn
                    }
                );
                assert_eq!(
                    event.id,
                    events::event_id(
                        &selection,
                        event.source,
                        Some(header),
                        event.subindex,
                        &event.data.record_hash
                    )
                    .unwrap()
                );
                // A different feed selection changes neither identity nor body.
                assert_eq!(again.id, event.id);
                assert_eq!(again.body().unwrap(), event.body().unwrap());
                ids_per_record[index].push(event.id.clone());
                let cursor = ResumeCursor::new(another_selection.clone());
                let resumed = events::resume_after(event, &cursor).unwrap();
                assert_eq!(resumed.identity.branch, "another-feed");
                let frame = events::sse_event(event, &cursor).unwrap();
                let encoded = frame
                    .lines()
                    .find_map(|line| line.strip_prefix("id: "))
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<ResumeCursor>(encoded).unwrap(),
                    resumed
                );
            }
        }
    }
    assert_eq!(
        branches_seen,
        branches.into_iter().map(str::to_owned).collect()
    );
    // Identical committed record bytes under three different headers must get
    // three different event identities.
    for ids in &ids_per_record {
        if ids.is_empty() {
            continue;
        }
        assert_eq!(ids.len() % 3, 0);
        let per_branch = ids.len() / 3;
        for subindex in 0..per_branch {
            let distinct: BTreeSet<_> = (0..3)
                .map(|branch| ids[branch * per_branch + subindex].clone())
                .collect();
            assert_eq!(distinct.len(), 3);
        }
    }
    // A header namespace is validated, never aliased: a reader opened for
    // another branch rejects this directory instead of rebinding its records.
    let (_, main_dir, main_last) = &logs[0];
    let foreign = LogReader::new(env.clone(), main_dir.clone(), "fork-original");
    assert!(
        foreign
            .read_while(0, *main_last, |_| Ok(true))
            .await
            .is_err(),
        "a segment header branch must never be accepted as another feed branch"
    );
}

#[test]
fn actor_branch_identity_uses_canonical_utf8_bytes_not_feed_label_rules() {
    let record = Record::AuditEvent(pb::AuditEvent {
        action: "proposal.create".into(),
        target: "p-branch".into(),
        audit: audit(),
        ..Default::default()
    });
    let mapper = mapper();
    let hash = kronik_otel::audit::record_hash(&record, &mapper.sealer).unwrap();
    let schema = events::schemas().unwrap();
    assert_eq!(
        schema["properties"]["branch"]["$ref"],
        "#/$defs/source_branch"
    );
    assert_eq!(
        schema["$defs"]["cursor"]["properties"]["identity"]["properties"]["branch"]["$ref"],
        "#/$defs/label"
    );
    for branch in ["a".repeat(256), "é".repeat(128), "fork original#000".into()] {
        kronik_proto::validate_source_branch(&branch).unwrap();
        let source = pb::ActorSource {
            shard: None,
            lsn: 1,
            branch,
        };
        let event = events::project(&mapper, &identity(), &source, &record, &[])
            .unwrap()
            .into_iter()
            .find(|event| event.data.action == "proposal.create")
            .unwrap();
        assert_eq!(event.branch.as_deref(), Some(source.branch.as_str()));
        assert_eq!(
            event.id,
            events::event_id(&identity(), native(1), Some(&source.branch), 0, &hash).unwrap()
        );
    }
    for branch in [
        "a".repeat(257),
        "é".repeat(129),
        String::new(),
        "a:b".into(),
        "a/b".into(),
        "a\\b".into(),
        "a\nb".into(),
        "a\u{7f}b".into(),
    ] {
        assert!(kronik_proto::validate_source_branch(&branch).is_err());
        assert!(events::event_id(&identity(), native(1), Some(&branch), 0, &hash).is_err());
    }
    assert!(events::event_id(&identity(), native(1), None, 0, &hash).is_err());
    assert!(
        events::event_id(
            &identity(),
            SourcePos::Metadata { index: 1 },
            Some("main"),
            0,
            &hash
        )
        .is_err()
    );
    assert!(
        events::event_id(
            &identity(),
            SourcePos::Metadata { index: 1 },
            None,
            0,
            &hash
        )
        .is_ok()
    );
}
