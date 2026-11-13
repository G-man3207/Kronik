//! Compatibility fixtures (SPEC, "Format changes"): bytes written by a
//! format version must keep decoding to the same values. Regenerate a
//! fixture only for a new record or field, with `KRONIK_WRITE_FIXTURES=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

fn fixture(name: &str, record: &Record) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}.hex", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("KRONIK_WRITE_FIXTURES").is_some() {
        let hex: String = record.encode().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, hex + "\n").unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let text = text.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// `SimulatorConfig`, kind 15 (M12, ADR 0014).
#[test]
fn simulator_config_v1() {
    let record = Record::SimulatorConfig(pb::SimulatorConfig {
        epoch: 7,
        target: "http:payments.internal".into(),
        stubs: vec![pb::StubRuleSpec {
            method: "GET".into(),
            url_prefix: "https://payments.internal/v1/charges/".into(),
            status: 200,
            headers: vec![pb::HeaderPair {
                name: "content-type".into(),
                value: "application/json".into(),
            }],
            body: br#"{"id":"ch_1"}"#.to_vec(),
            error: String::new(),
        }],
        contract: br#"{"openapi":"3.0.3"}"#.to_vec(),
        neighbor: true,
        model: false,
        audit: Some(pb::Audit {
            token_id: "admin".into(),
            reason: "payments contract".into(),
            wall_time_ms: 1_793_000_000_000,
        }),
    });
    let bytes = fixture("simulator-config-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::SIMULATOR_CONFIG, &bytes).unwrap(),
        record
    );
}

/// `EffectRecord.simulator` (field 13, M12) inside a `TurnRecord`; a record
/// without it still decodes with the field empty.
#[test]
fn effect_record_simulator_v1() {
    let record = Record::TurnRecord(pb::TurnRecord {
        execution_id: "00112233445566778899aabbccddeeff".into(),
        actor: Some(pb::ActorRef {
            kind: "billing".into(),
            key: "a".into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: "r1".into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(vec![])),
                    })),
                }),
                ..Default::default()
            })),
        }),
        effects: vec![pb::EffectRecord {
            ordinal: 1,
            kind: "http.fetch".into(),
            status: pb::EffectStatus::Ok as i32,
            grounding: pb::Grounding::Synthetic as i32,
            target: "http:payments.internal".into(),
            simulator: "contract".into(),
            ..Default::default()
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        ..Default::default()
    });
    let bytes = fixture("effect-record-simulator-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::TURN_RECORD, &bytes).unwrap(),
        record
    );
}

/// A small committed turn record, as a rebase fork records one.
fn turn() -> pb::TurnRecord {
    pb::TurnRecord {
        execution_id: "ffeeddccbbaa99887766554433221100".into(),
        actor: Some(pb::ActorRef {
            kind: "billing".into(),
            key: "a".into(),
        }),
        causal_key: Some(pb::CausalKey {
            root: "r2".into(),
            path: vec![],
        }),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method: "POST".into(),
                path: "/billing/a/increment".into(),
                body: Some(pb::Body {
                    value: Some(pb::body::Value::Inline(pb::Sealable {
                        subject: None,
                        value: Some(pb::sealable::Value::Plain(vec![])),
                    })),
                }),
                ..Default::default()
            })),
        }),
        writes: vec![pb::StateWrite {
            op: pb::StateOp::Set as i32,
            key: "n".into(),
            value: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b"3".to_vec())),
            }),
        }],
        outcome: Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        }),
        config_epoch: 4,
        ..Default::default()
    }
}

/// `StateRebase`, kind 16 (M13, ADR 0017): a rebased turn.
#[test]
fn state_rebase_turn_v1() {
    let record = Record::StateRebase(pb::StateRebase {
        rebase_id: "r-0123456789ab".into(),
        part: Some(pb::state_rebase::Part::Turn(pb::RebasedTurn {
            fork_lsn: 13,
            record: Some(turn()),
        })),
    });
    let bytes = fixture("state-rebase-turn-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::STATE_REBASE, &bytes).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.turn(), Some(&turn()));
}

/// `StateRebase`, kind 16: the switch.
#[test]
fn state_rebase_switch_v1() {
    let record = Record::StateRebase(pb::StateRebase {
        rebase_id: "r-0123456789ab".into(),
        part: Some(pb::state_rebase::Part::Switch(pb::RebaseSwitch {
            base_lsn: 10,
            rolled_back_epoch: 3,
            verified_through_lsn: 40,
            first_turn_lsn: 41,
            last_turn_lsn: 70,
            turns: 30,
            deployment: Some(pb::Deployment {
                epoch: 5,
                kinds: vec![pb::KindVersion {
                    kind: "billing".into(),
                    code_hash: vec![7; 32],
                    schema_version: 0,
                    manifest: Some(pb::Manifest {
                        kind: "billing".into(),
                        ..Default::default()
                    }),
                    code_size: 100,
                }],
                cause: pb::DeploymentCause::Rollback as i32,
                proposal_id: "r-0123456789ab".into(),
                rollback_of_epoch: 3,
                ..Default::default()
            }),
            diff_hash: "b3:00ff".into(),
            irreversible_effects: 2,
            audit: Some(pb::Audit {
                token_id: "admin".into(),
                reason: "undo the schema change".into(),
                wall_time_ms: 1_793_000_000_000,
            }),
        })),
    });
    let bytes = fixture("state-rebase-switch-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::STATE_REBASE, &bytes).unwrap();
    assert_eq!(decoded, record);
    assert!(decoded.turn().is_none());
    assert_eq!(
        decoded.rebase_switch().map(|(id, s)| (id, s.turns)),
        Some(("r-0123456789ab", 30))
    );
}

/// `Grant.in_forks` (field 8, ADR 0112). A record that writes `recorded`
/// keeps that value. An older record without the field decodes with it
/// empty, which is compute.
#[test]
fn grant_in_forks_v1() {
    let record = Record::Grant(pb::Grant {
        epoch: 4,
        op: pb::GrantOp::Grant as i32,
        kind: "counter".into(),
        capability: "secret:signing-key".into(),
        in_forks: "recorded".into(),
        audit: Some(pb::Audit {
            token_id: "admin".into(),
            reason: "forks must not sign".into(),
            wall_time_ms: 1_793_000_000_000,
        }),
        ..Default::default()
    });
    let bytes = fixture("grant-in-forks-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::GRANT, &bytes).unwrap(),
        record
    );
}

/// Bytes of a grant written before field 8. Decoding leaves `in_forks`
/// empty, and empty is compute (ADR 0112), not the default of a new grant.
#[test]
fn grant_without_in_forks_decodes_as_compute() {
    let older = Record::Grant(pb::Grant {
        epoch: 2,
        op: pb::GrantOp::Grant as i32,
        kind: "counter".into(),
        capability: "secret:signing-key".into(),
        ..Default::default()
    });
    let bytes = older.encode();
    let decoded = Record::decode(kronik_proto::kind::GRANT, &bytes).unwrap();
    let Record::Grant(grant) = decoded else {
        panic!("not a grant");
    };
    assert!(grant.in_forks.is_empty(), "{grant:?}");
    // The same rule Grant application uses: empty stays compute.
    let mode = match grant.in_forks.as_str() {
        "" | "compute" => "compute",
        "recorded" => "recorded",
        other => other,
    };
    assert_eq!(mode, "compute");
}

/// `ForeignActor.fork_mode` (field 12, M14, ADR 0019); an older record
/// without it reads as empty (recorded).
#[test]
fn foreign_actor_fork_mode_v1() {
    let record = Record::ForeignActor(pb::ForeignActor {
        epoch: 3,
        op: pb::ForeignOp::Add as i32,
        name: "pg".into(),
        image: "oci-layout:/srv/foreign-pg.oci@sha256:".to_owned() + &"ab".repeat(32),
        port: 8080,
        cpu_millis: 1000,
        memory_bytes: 536_870_912,
        isolation: pb::Isolation::Gvisor as i32,
        platform: "systrap".into(),
        fork_mode: "sandbox".into(),
        ..Default::default()
    });
    let bytes = fixture("foreign-actor-fork-mode-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::FOREIGN_ACTOR, &bytes).unwrap(),
        record
    );
}

/// `GROUNDING_FORKED` (5, M14, ADR 0020) on an effect of a fork turn.
#[test]
fn effect_record_forked_v1() {
    let mut t = turn();
    t.effects.push(pb::EffectRecord {
        ordinal: 1,
        kind: "foreign.http".into(),
        target: "foreign:pg".into(),
        status: pb::EffectStatus::Ok as i32,
        grounding: pb::Grounding::Forked as i32,
        ..Default::default()
    });
    let record = Record::TurnRecord(t);
    let bytes = fixture("effect-record-forked-v1", &record);
    assert_eq!(
        Record::decode(kronik_proto::kind::TURN_RECORD, &bytes).unwrap(),
        record
    );
}

fn secret_audit() -> Option<pb::Audit> {
    Some(pb::Audit {
        token_id: "system".into(),
        reason: "import".into(),
        wall_time_ms: 1,
    })
}

fn secret_version(version: u64, phase: pb::secret_version::Phase) -> pb::SecretVersion {
    pb::SecretVersion {
        name: "key".into(),
        version,
        version_hash: vec![0x55; 16],
        backend: "file".into(),
        source_version: version.to_string(),
        deleted: false,
        audit: secret_audit(),
        r#ref: "key".into(),
        binding: "file".into(),
        link_generation: 0,
        canonical_ref: "key".into(),
        phase: phase as i32,
        hash_revision: if version <= u32::MAX as u64 { 1 } else { 2 },
    }
}

#[test]
fn secret_identity_committed_formats() {
    use pb::secret_version::Phase;
    let cases = [
        (
            "secret-version-legacy-v1",
            secret_version(4_294_967_295, Phase::Active),
        ),
        (
            "secret-version-wide-reserved-v1",
            secret_version(4_294_967_296, Phase::Reserved),
        ),
        (
            "secret-version-wide-active-v1",
            secret_version(4_294_967_296, Phase::Active),
        ),
        (
            "secret-version-wide-failed-v1",
            secret_version(4_294_967_296, Phase::Failed),
        ),
        (
            "secret-version-max-v1",
            secret_version(9_007_199_254_740_991, Phase::Active),
        ),
        (
            "secret-fence-fresh-v1",
            pb::SecretVersion {
                audit: secret_audit(),
                phase: Phase::Fence as i32,
                ..Default::default()
            },
        ),
        (
            "secret-fence-legacy-v1",
            pb::SecretVersion {
                version: 4_294_967_295,
                audit: secret_audit(),
                phase: Phase::Fence as i32,
                ..Default::default()
            },
        ),
    ];
    for (name, m) in cases {
        let record = Record::SecretVersion(m);
        let bytes = fixture(name, &record);
        assert_eq!(record.encoded_len(), bytes.len());
        assert_eq!(record.encode(), bytes);
        assert_eq!(Record::decode(45, &bytes).unwrap(), record);
    }
    for (name, backend, reference, binding, canonical, generation, epoch) in [
        (
            "secret-link-v1",
            "vault",
            "kv/key",
            "trusted",
            "kv/data/key",
            1,
            7,
        ),
        ("secret-unlink-v1", "", "", "", "", 2, 8),
    ] {
        let record = Record::SecretLink(pb::SecretLink {
            name: "key".into(),
            backend: backend.into(),
            r#ref: reference.into(),
            audit: secret_audit(),
            binding: binding.into(),
            generation,
            epoch,
            canonical_ref: canonical.into(),
        });
        let bytes = fixture(name, &record);
        assert_eq!(record.encoded_len(), bytes.len());
        assert_eq!(record.encode(), bytes);
        assert_eq!(Record::decode(46, &bytes).unwrap(), record);
    }
}

#[test]
fn secret_identity_rejects_invalid_boundaries_and_provenance() {
    use pb::secret_version::Phase;
    let valid = secret_version(4_294_967_296, Phase::Reserved);
    let mut bad = Vec::new();
    for version in [0, 9_007_199_254_740_992, u64::MAX] {
        let mut m = valid.clone();
        m.version = version;
        bad.push(m);
    }
    for phase in [0, 5, -1] {
        let mut m = valid.clone();
        m.phase = phase;
        bad.push(m);
    }
    let mut m = valid.clone();
    m.audit = None;
    bad.push(m);
    let mut m = valid.clone();
    m.hash_revision = 1;
    bad.push(m);
    let mut m = valid.clone();
    m.version_hash.pop();
    bad.push(m);
    let mut m = valid.clone();
    m.canonical_ref.clear();
    bad.push(m);
    let mut m = valid.clone();
    m.binding.clear();
    bad.push(m);
    let mut m = valid.clone();
    m.source_version = "01".into();
    bad.push(m);
    let mut m = valid.clone();
    m.phase = Phase::Fence as i32;
    bad.push(m);
    for m in bad {
        let record = Record::SecretVersion(m);
        assert!(Record::decode(45, &record.encode()).is_err(), "{record:?}");
    }
    let fence = pb::SecretVersion {
        audit: secret_audit(),
        phase: Phase::Fence as i32,
        ..Default::default()
    };
    for version in [1, 4_294_967_296, u64::MAX] {
        let mut m = fence.clone();
        m.version = version;
        assert!(Record::SecretVersion(m).validate().is_err());
    }
    let mut m = fence.clone();
    m.audit.as_mut().unwrap().token_id = "admin".into();
    assert!(Record::SecretVersion(m).validate().is_err());
    let mut tombstone = valid.clone();
    tombstone.deleted = true;
    tombstone.version_hash.clear();
    assert!(Record::SecretVersion(tombstone.clone()).validate().is_ok());
    tombstone.backend = "vault".into();
    tombstone.link_generation = 1;
    assert!(Record::SecretVersion(tombstone).validate().is_err());
    let mut link = pb::SecretLink {
        name: "key".into(),
        generation: 1,
        epoch: 1,
        audit: secret_audit(),
        ..Default::default()
    };
    assert!(Record::SecretLink(link.clone()).validate().is_ok());
    for field in 0..4 {
        let mut bad = link.clone();
        match field {
            0 => bad.generation = 0,
            1 => bad.epoch = 0,
            2 => bad.audit = None,
            _ => bad.generation = u64::MAX,
        }
        assert!(Record::decode(46, &Record::SecretLink(bad).encode()).is_err());
    }
    link.r#ref = "not-an-unlink".into();
    assert!(Record::SecretLink(link.clone()).validate().is_err());
    link.backend = "vault".into();
    assert!(Record::SecretLink(link).validate().is_err());
}

#[test]
fn file_alias_records_preserve_distinct_logical_and_physical_identity() {
    let mut identity = secret_version(4_294_967_296, pb::secret_version::Phase::Active);
    identity.name = "alias-a".into();
    identity.r#ref = "physical-alt".into();
    identity.canonical_ref = "physical-alt".into();
    identity.source_version = "7".into();
    identity.link_generation = 3;
    let link = pb::SecretLink {
        name: identity.name.clone(),
        backend: "file".into(),
        r#ref: identity.r#ref.clone(),
        audit: secret_audit(),
        binding: "file".into(),
        generation: 3,
        epoch: 4,
        canonical_ref: identity.canonical_ref.clone(),
    };
    for record in [
        Record::SecretVersion(identity.clone()),
        Record::SecretLink(link.clone()),
    ] {
        let kind = if matches!(&record, Record::SecretVersion(_)) {
            45
        } else {
            46
        };
        assert_eq!(Record::decode(kind, &record.encode()).unwrap(), record);
    }
    for physical in ["", "Uppercase", "/path", "contains space", "_prefix"] {
        let mut bad_identity = identity.clone();
        bad_identity.r#ref = physical.into();
        bad_identity.canonical_ref = physical.into();
        assert!(Record::decode(45, &Record::SecretVersion(bad_identity).encode()).is_err());
        let mut bad_link = link.clone();
        bad_link.r#ref = physical.into();
        bad_link.canonical_ref = physical.into();
        assert!(Record::decode(46, &Record::SecretLink(bad_link).encode()).is_err());
    }
    let mut mismatched = link.clone();
    mismatched.canonical_ref = "different-physical".into();
    assert!(Record::SecretLink(mismatched).validate().is_err());
    let mut wrong_binding = link;
    wrong_binding.binding = "untrusted-file".into();
    assert!(Record::SecretLink(wrong_binding).validate().is_err());
    let mut self_link = identity;
    self_link.name = self_link.r#ref.clone();
    assert!(Record::SecretVersion(self_link).validate().is_ok());
}

#[test]
fn privacy_mode_and_explicit_reseal_request_formats() {
    for (name, reseal_requested) in [
        ("privacy-mode-v1", false),
        ("privacy-reseal-request-v1", true),
    ] {
        let record = Record::PrivacyMode(pb::PrivacyMode {
            epoch: 7,
            mode: pb::PrivacyState::On as i32,
            audit: None,
            reseal_requested,
        });
        let bytes = fixture(name, &record);
        assert_eq!(record.encode(), bytes);
        assert_eq!(
            Record::decode(kronik_proto::kind::PRIVACY_MODE, &bytes).unwrap(),
            record
        );
    }
    for mode in [pb::PrivacyState::Off, pb::PrivacyState::Unspecified] {
        let record = Record::PrivacyMode(pb::PrivacyMode {
            epoch: 7,
            mode: mode as i32,
            audit: None,
            reseal_requested: true,
        });
        assert!(Record::decode(kronik_proto::kind::PRIVACY_MODE, &record.encode()).is_err());
    }
}

#[test]
fn portable_metadata_history_validators_read_real_record_bytes_in_their_own_namespace() {
    use kronik_proto::control;
    let audit = Some(pb::Audit {
        token_id: "system:metadata".into(),
        reason: "the exact registered metadata control request".into(),
        wall_time_ms: 17,
    });
    let fixtures = [
        pb::AuditEvent {
            action: "audit.gap".into(),
            details: [
                ("namespace".into(), "metadata".into()),
                ("stream".into(), "events-control:metadata".into()),
                ("from_index".into(), "1".into()),
                ("through_index".into(), "17".into()),
            ]
            .into(),
            audit: audit.clone(),
            ..Default::default()
        },
        pb::AuditEvent {
            action: "audit.config".into(),
            target: "events-control:metadata".into(),
            details: [
                ("change".into(), "webhook.signing_key".into()),
                ("source".into(), "metadata".into()),
                ("from_version".into(), "4294967296".into()),
                ("to_version".into(), "9007199254740991".into()),
            ]
            .into(),
            audit: audit.clone(),
            ..Default::default()
        },
        pb::AuditEvent {
            action: "events.webhook.replay".into(),
            target: "events-control:metadata".into(),
            details: [
                ("source".into(), "metadata".into()),
                ("position".into(), "9223372036854775807".into()),
            ]
            .into(),
            audit,
            ..Default::default()
        },
    ];
    for event in fixtures {
        let record = Record::AuditEvent(event.clone());
        let exact = record.encode();
        let decoded = Record::decode(record.kind(), &exact).unwrap();
        assert_eq!(decoded.encode(), exact);
        let Record::AuditEvent(mut decoded) = decoded else {
            panic!("actual Record40 fixture")
        };
        match event.action.as_str() {
            "audit.gap" => {
                control::validate_metadata_gap_event(&decoded).unwrap();
                assert_eq!(
                    control::metadata_audit_gap_details(&decoded.details).unwrap(),
                    ("events-control:metadata", 1, 17)
                );
                decoded.details.insert("from_lsn".into(), "1".into());
                assert!(control::validate_metadata_gap_event(&decoded).is_err());
            }
            "audit.config" => {
                control::validate_metadata_webhook_key_change_event(&decoded).unwrap();
                assert_eq!(
                    control::metadata_webhook_key_change_details(&decoded.details).unwrap(),
                    (4294967296, 9007199254740991)
                );
                decoded
                    .details
                    .insert("secret_value".into(), "not public metadata".into());
                assert!(control::validate_metadata_webhook_key_change_event(&decoded).is_err());
            }
            _ => {
                control::validate_metadata_webhook_replay_event(&decoded).unwrap();
                assert_eq!(
                    control::metadata_webhook_replay_details(&decoded.details).unwrap(),
                    i64::MAX as u64
                );
                decoded.details.insert("from_lsn".into(), "1".into());
                assert!(control::validate_metadata_webhook_replay_event(&decoded).is_err());
            }
        }
    }
}

#[test]
fn metadata_approval_read_domain_checks_all_fields_without_changing_native_record_bytes() {
    use prost::Message as _;
    let owner = format!("oidc:{}", "ab".repeat(32));
    let base = pb::Approval {
        proposal_id: "p-real-history".into(),
        diff_hash: vec![7; 32],
        verified_through_lsn: 17,
        audit: Some(pb::Audit {
            token_id: owner.clone(),
            reason: "actual protocol history fixture".into(),
            wall_time_ms: 19,
        }),
        ..Default::default()
    };
    kronik_proto::validate_proposal_approval(&base).unwrap();
    for (nonce, ciphertext) in [(vec![3; 24], vec![5; 16]), (vec![0; 24], Vec::new())] {
        let approval = pb::Approval {
            verified_identity: Some(pb::Sealable {
                subject: Some(owner.clone()),
                value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                    key_version: 2,
                    nonce,
                    ciphertext,
                })),
            }),
            ..base.clone()
        };
        let record = Record::Approval(approval.clone());
        let exact = record.encode();
        let decoded = Record::decode(kronik_proto::kind::APPROVAL, &exact).unwrap();
        let Record::Approval(decoded) = decoded else {
            panic!("actual Record8 fixture")
        };
        kronik_proto::validate_proposal_approval(&decoded).unwrap();
        assert_eq!(Record::Approval(decoded).encode(), exact);
        for mutation in 0..7 {
            let mut invalid = approval.clone();
            match mutation {
                0 => invalid.proposal_id.clear(),
                1 => {
                    invalid.diff_hash.pop();
                }
                2 => invalid.audit = None,
                3 => invalid.audit.as_mut().unwrap().token_id.clear(),
                4 => {
                    invalid.verified_identity.as_mut().unwrap().subject =
                        Some("different-owner".into())
                }
                5 => {
                    invalid.verified_identity.as_mut().unwrap().value = Some(
                        pb::sealable::Value::Plain(b"not a protected identity".to_vec()),
                    )
                }
                _ => invalid.verified_identity.as_mut().unwrap().value = None,
            }
            assert!(kronik_proto::validate_proposal_approval(&invalid).is_err());
        }
    }
    let mut future = pb::Sealable {
        subject: Some(owner),
        value: None,
    }
    .encode_to_vec();
    future.extend_from_slice(&[0x22, 0]); // Unsupported value field, not a new reader capability.
    let future = pb::Sealable::decode(future.as_slice()).unwrap();
    assert!(future.value.is_none());
    let invalid = pb::Approval {
        verified_identity: Some(future),
        ..base
    };
    assert!(kronik_proto::validate_proposal_approval(&invalid).is_err());
}

#[test]
fn native_origin_message_is_data_only_and_field10_is_not_an_old_reader_write_fence() {
    use prost::Message as _;
    // Existing approved future carrier: action, known original audit, then NativeAuthorityOrigin field10.
    // This reader deliberately does NOT attach field10; decoding is not permission to emit/import it.
    let text = "0a0d6f70657261746f722e6e6f7465221c0a0e746f6b656e3a6f726967696e616c12086f726967696e616c18075231122f0a0a756e69783a7569643d30121f6e617469766520617574686f7269747920696e697469616c697a6174696f6e1801";
    let wire: Vec<u8> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let Record::AuditEvent(old) = Record::decode(kronik_proto::kind::AUDIT_EVENT, &wire).unwrap()
    else {
        panic!("actual old-layout Record40 decoder")
    };
    let expected = pb::AuditEvent {
        action: "operator.note".into(),
        audit: Some(pb::Audit {
            token_id: "token:original".into(),
            reason: "original".into(),
            wall_time_ms: 7,
        }),
        ..Default::default()
    };
    assert_eq!(old, expected);
    assert_ne!(
        old.encode_to_vec(),
        wire,
        "the actual old reader silently drops field10; it is NOT a compatibility fence"
    );
    let mut origin = pb::NativeAuthorityOrigin {
        source: Some(pb::ActorSource {
            shard: None,
            lsn: 37,
            branch: "actual-native".into(),
        }),
        adoption_audit: Some(pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual initialization operator".into(),
            wall_time_ms: 23,
        }),
        current_projection: true,
    };
    let exact = origin.encode_to_vec();
    let decoded = pb::NativeAuthorityOrigin::decode(exact.as_slice()).unwrap();
    kronik_proto::control::validate_native_authority_origin(&decoded).unwrap();
    assert_eq!(decoded, origin);
    for shard in [0, 7] {
        origin.source.as_mut().unwrap().shard = Some(shard);
        assert!(kronik_proto::control::validate_native_authority_origin(&origin).is_err());
    }
    origin.source = None; // Explicit historical unknown, never Native source zero or the adoption index.
    kronik_proto::control::validate_native_authority_origin(&origin).unwrap();
    origin.adoption_audit = None;
    assert!(kronik_proto::control::validate_native_authority_origin(&origin).is_err());
    // This fixture performs no Log append, metadata apply or activation.
}

/// `Limits.fingerprint_exclude_headers` and `fingerprint_exclude_query`
/// (fields 11 and 12, ADR 0134). A record without them decodes with both
/// unset, which keeps a kind's lists.
#[test]
fn limits_fingerprint_rules_v1() {
    let names = |n: &[&str]| {
        Some(pb::NameList {
            names: n.iter().map(|s| (*s).to_owned()).collect(),
        })
    };
    let record = Record::Limits(pb::Limits {
        epoch: 9,
        kind: "billing".into(),
        fuel: Some(100_000_000),
        fingerprint_exclude_headers: names(&["x-api-key", "x-request-nonce"]),
        fingerprint_exclude_query: names(&[]),
        audit: Some(pb::Audit {
            token_id: "admin".into(),
            reason: "volatile headers".into(),
            wall_time_ms: 1_794_000_000_000,
        }),
        ..Default::default()
    });
    let bytes = fixture("limits-fingerprint-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::LIMITS, &bytes).unwrap();
    assert_eq!(decoded, record);
    // An empty list is a list (it clears), not an unset field.
    let Record::Limits(limits) = decoded else {
        unreachable!("a Limits record")
    };
    assert_eq!(limits.fingerprint_exclude_query, names(&[]));
    let older = Record::Limits(pb::Limits {
        epoch: 9,
        kind: "billing".into(),
        fuel: Some(100_000_000),
        ..Default::default()
    });
    let Record::Limits(older) =
        Record::decode(kronik_proto::kind::LIMITS, &older.encode()).unwrap()
    else {
        unreachable!("a Limits record")
    };
    assert!(older.fingerprint_exclude_headers.is_none());
    assert!(older.fingerprint_exclude_query.is_none());
}

/// An `http.fetch` effect whose request is fingerprint version 3 with the
/// names its actor type's rules left out (`HttpEffectRequest` fields 6 and
/// 7, ADR 0134), inside a `TurnRecord`.
#[test]
fn effect_record_http_v3_v1() {
    use prost::Message as _;
    let request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: "https://payments.internal/v1/charges?ts=1&a=b".into(),
        headers: vec![pb::HttpEffectHeader {
            name: "x-api-key".into(),
            value: Some(pb::http_effect_header::Value::Text("k1".into())),
        }],
        body: Vec::new(),
        fingerprint_version: 3,
        fingerprint_excluded_headers: vec!["x-api-key".into()],
        fingerprint_excluded_query: vec!["nonce".into(), "ts".into()],
    };
    let mut turn = turn();
    turn.effects = vec![pb::EffectRecord {
        ordinal: 1,
        kind: "http.fetch".into(),
        status: pb::EffectStatus::Ok as i32,
        target: "http:payments.internal".into(),
        fingerprint: vec![7; 32],
        grounding: pb::Grounding::Live as i32,
        request: Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(request.encode_to_vec())),
        }),
        ..Default::default()
    }];
    let record = Record::TurnRecord(turn);
    let bytes = fixture("effect-record-http-v3-v1", &record);
    let decoded = Record::decode(kronik_proto::kind::TURN_RECORD, &bytes).unwrap();
    assert_eq!(decoded, record);
    let Record::TurnRecord(turn) = decoded else {
        unreachable!("a TurnRecord")
    };
    let Some(pb::sealable::Value::Plain(inner)) = turn.effects[0]
        .request
        .as_ref()
        .and_then(|request| request.value.as_ref())
    else {
        unreachable!("a plain request")
    };
    assert_eq!(
        pb::HttpEffectRequest::decode(inner.as_slice()).unwrap(),
        request
    );
}
