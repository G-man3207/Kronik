//! The metadata view of `Mapper` (m28-otel §4.4): read-only identity images,
//! not Raft/SQLite commits. These live in the crate because only
//! `verify_range` can compare `Expected` against lines; the free `verify`
//! covers only the actor LSN domain.

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "token:ops".into(),
        reason: "test".into(),
        wall_time_ms: 1,
    }
}

fn mapper() -> Mapper {
    // The tempdir stays alive with the sealer: the keystore reads its files
    // lazily, so dropping it would break later keyed hashes.
    static STATE: std::sync::LazyLock<(
        tempfile::TempDir,
        std::sync::Arc<kronik_privacy::sealer::Sealer>,
    )> = std::sync::LazyLock::new(|| {
        let dir = tempfile::tempdir().unwrap();
        let owner = kronik_privacy::key_source::lock_data(dir.path()).unwrap();
        let (master, _) = kronik_privacy::MasterKey::open(
            &dir.path().join("master.key"),
            dir.path(),
            Some([7; 32]),
        )
        .unwrap();
        let keystore = kronik_privacy::keystore::Keystore::open_owned(&owner, &master).unwrap();
        let pseudonyms = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
        (
            dir,
            std::sync::Arc::new(
                kronik_privacy::sealer::Sealer::new(keystore).with_pseudonyms(pseudonyms),
            ),
        )
    });
    Mapper {
        keys: Keys::Plain,
        sealer: STATE.1.clone(),
        branch: "main".into(),
    }
}

// The Record45 body is the actual immutable protobuf golden fixture.
fn metadata_identity_fixture() -> Record {
    let wire = kronik_core::ids::unhex(
        include_str!("../../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex")
            .trim(),
    )
    .unwrap();
    let record = Record::decode(45, &wire).unwrap();
    assert_eq!(record.encode(), wire);
    record
}

fn metadata_origin_fixture(known: bool, current: bool) -> kronik_log::MetadataAuditRecord {
    kronik_log::MetadataAuditRecord {
        index: 97,
        record: metadata_identity_fixture(),
        native_origin: Some(pb::NativeAuthorityOrigin {
            source: known.then(|| pb::ActorSource {
                shard: None,
                lsn: 41,
                branch: "original-fork".into(),
            }),
            adoption_audit: Some(pb::Audit {
                token_id: "unix:uid=0".into(),
                reason: "private-adoption-reason-NEEDLE".into(),
                wall_time_ms: 37,
            }),
            current_projection: current,
        }),
    }
}

fn metadata_view_complete(
    mapper: &Mapper,
    source: &kronik_log::MetadataAuditRecord,
    lines: &[Line],
) -> bool {
    verify_range(
        &mapper.expected_metadata(source).unwrap(),
        lines,
        96,
        97,
        Some((
            SourcePos::Metadata { index: 96 },
            SourcePos::Metadata { index: 97 },
        )),
    )
    .complete
}

#[test]
fn metadata_identity_origin_keeps_known_facts_and_unknown_absence_out_of_the_body_hash() {
    let mapper = mapper();
    let secrets: &[(&str, &[u8])] = &[
        ("field", b"native_origin"),
        ("source", b"original_source"),
        ("branch", b"original-fork"),
        ("one", b"1"),
        ("wall", b"37"),
        ("lsn", b"41"),
        ("adoption", b"private-adoption-reason-NEEDLE"),
    ];
    for known in [false, true] {
        for current in [false, true] {
            let source = metadata_origin_fixture(known, current);
            let exact = source.record.encode();
            let ordinary = mapper
                .lines_at(SourcePos::Metadata { index: 97 }, &source.record, secrets)
                .unwrap();
            let lines = mapper.lines_metadata(&source, secrets).unwrap();
            let line = &lines[0];
            assert_eq!(
                (&*line.schema, &*line.kind, &*line.action),
                ("kronik.audit/v3", "secret_version", "secret.version")
            );
            assert_eq!(
                (line.lsn, line.source),
                (None, Some(SourcePos::Metadata { index: 97 }))
            );
            assert!(line.branch.is_empty());
            let mut expected =
                serde_json::json!({"adopted_at_wall_ms":37,"current_projection":current});
            if known {
                expected["original_source"] =
                    serde_json::json!({"shard":null,"lsn":41,"branch":"original-fork"});
            }
            assert_eq!(line.details["native_origin"], expected);
            assert_eq!(
                (line.at_wall_ms, &*line.token_id, &*line.reason),
                (
                    ordinary[0].at_wall_ms,
                    &*ordinary[0].token_id,
                    &*ordinary[0].reason
                )
            );
            assert_eq!(
                line.record_hash,
                record_hash(&source.record, &mapper.sealer).unwrap()
            );
            assert_eq!(line.record_hash, ordinary[0].record_hash);
            assert_eq!(source.record.encode(), exact);
            assert!(!line.to_json().contains("private-adoption-reason-NEEDLE"));
            assert!(!line.to_json().contains("unix:uid=0"));
            assert!(metadata_view_complete(&mapper, &source, &lines));
        }
    }
}

#[test]
fn metadata_verification_checks_the_same_image_origin_even_when_record_identity_is_unchanged() {
    let mapper = mapper();
    let original = metadata_origin_fixture(true, true);
    let original_lines = mapper.lines_metadata(&original, &[]).unwrap();
    for mutation in 0..6 {
        let mut changed = metadata_origin_fixture(true, true);
        let origin = changed.native_origin.as_mut().unwrap();
        match mutation {
            0 => origin.source.as_mut().unwrap().lsn = 42,
            1 => origin.source.as_mut().unwrap().branch = "different-real-branch".into(),
            2 => origin.source = None,
            3 => origin.current_projection = false,
            4 => origin.adoption_audit.as_mut().unwrap().wall_time_ms = 38,
            _ => changed.native_origin = None,
        }
        let lines = mapper.lines_metadata(&changed, &[]).unwrap();
        assert_eq!(lines[0].record_hash, original_lines[0].record_hash);
        assert!(!metadata_view_complete(&mapper, &original, &lines));
    }
    let mut missing = original_lines.clone();
    missing[0].details.remove("native_origin");
    assert!(!metadata_view_complete(&mapper, &original, &missing));
    let ordinary = kronik_log::MetadataAuditRecord {
        index: 97,
        record: metadata_identity_fixture(),
        native_origin: None,
    };
    assert!(!metadata_view_complete(&mapper, &ordinary, &original_lines));
}

#[test]
fn metadata_view_rejects_malformed_or_unrepresentable_supplied_origin_instead_of_dropping_it() {
    let mapper = mapper();
    for mutation in 0..9 {
        let mut source = metadata_origin_fixture(true, true);
        match mutation {
            0 => source.index = 0,
            1 => source.index = i64::MAX as u64 + 1,
            2 => {
                source
                    .native_origin
                    .as_mut()
                    .unwrap()
                    .source
                    .as_mut()
                    .unwrap()
                    .shard = Some(0)
            }
            3 => {
                source
                    .native_origin
                    .as_mut()
                    .unwrap()
                    .source
                    .as_mut()
                    .unwrap()
                    .lsn = 0
            }
            4 => source
                .native_origin
                .as_mut()
                .unwrap()
                .source
                .as_mut()
                .unwrap()
                .branch
                .clear(),
            5 => source.native_origin.as_mut().unwrap().adoption_audit = None,
            6 => source
                .native_origin
                .as_mut()
                .unwrap()
                .adoption_audit
                .as_mut()
                .unwrap()
                .token_id
                .clear(),
            7 => {
                source.record = Record::decode(
                    46,
                    &kronik_core::ids::unhex(
                        include_str!("../../../kronik-proto/tests/fixtures/secret-link-v1.hex")
                            .trim(),
                    )
                    .unwrap(),
                )
                .unwrap()
            }
            _ => {
                source.record = Record::AuditEvent(pb::AuditEvent {
                    action: "operator.note".into(),
                    audit: Some(audit()),
                    ..Default::default()
                })
            }
        }
        assert_eq!(
            mapper.lines_metadata(&source, &[]).unwrap_err().code,
            ErrorCode::StorageCorrupt
        );
        assert_eq!(
            mapper
                .operational_lines_metadata(&source, &[])
                .unwrap_err()
                .code,
            ErrorCode::StorageCorrupt
        );
        assert_eq!(
            mapper.expected_metadata(&source).err().unwrap().code,
            ErrorCode::StorageCorrupt
        );
    }
}

/// The fixture secrets collide with closed stream markers. Longer matches win,
/// the same way the export scrubber does.
fn scrub_closed_secret_spellings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            *text = text
                .replace("events-control:metadata", "[secret:stream]")
                .replace("metadata", "[secret:domain]");
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_closed_secret_spellings),
        serde_json::Value::Object(map) => {
            map.values_mut().for_each(scrub_closed_secret_spellings);
        }
        _ => {}
    }
}

fn portable_metadata_control_fixtures() -> [(Record, serde_json::Value); 3] {
    let audit = Some(pb::Audit {
        token_id: "system:metadata".into(),
        reason: "exact-prefix private-NEEDLE exact-suffix".into(),
        wall_time_ms: 19,
    });
    [
        (
            Record::AuditEvent(pb::AuditEvent {
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
            }),
            serde_json::json!({"namespace":"metadata","stream":"events-control:metadata","from_index":1,"through_index":17}),
        ),
        (
            Record::AuditEvent(pb::AuditEvent {
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
            }),
            serde_json::json!({"change":"webhook.signing_key","source":"metadata","from_version":4294967296u64,
                "to_version":9007199254740991u64,"target":"events-control:metadata"}),
        ),
        (
            Record::AuditEvent(pb::AuditEvent {
                action: "events.webhook.replay".into(),
                target: "events-control:metadata".into(),
                details: [
                    ("source".into(), "metadata".into()),
                    ("position".into(), "9223372036854775807".into()),
                ]
                .into(),
                audit,
                ..Default::default()
            }),
            serde_json::json!({"source":"metadata","position":9223372036854775807u64,"target":"events-control:metadata"}),
        ),
    ]
}

#[test]
fn decoded_metadata_control_views_preserve_only_closed_facts_and_the_whole_persisted_reason_policy()
{
    let mapper = mapper();
    let secrets: &[(&str, &[u8])] = &[
        ("domain", b"metadata"),
        ("stream", b"events-control:metadata"),
        ("one", b"1"),
        ("seventeen", b"17"),
        ("wide", b"4294967296"),
        ("wider", b"9007199254740991"),
        ("maximum", b"9223372036854775807"),
        ("private", b"private-NEEDLE"),
    ];
    for (record, details) in portable_metadata_control_fixtures() {
        let exact = record.encode();
        let decoded = Record::decode(40, &exact).unwrap();
        let source = kronik_log::MetadataAuditRecord {
            index: 97,
            record: decoded,
            native_origin: None,
        };
        let lines = mapper.lines_metadata(&source, secrets).unwrap();
        assert_eq!(
            (lines[0].lsn, lines[0].source),
            (None, Some(SourcePos::Metadata { index: 97 }))
        );
        assert!(lines[0].branch.is_empty());
        assert_eq!(
            (&*lines[0].schema, &*lines[0].kind),
            ("kronik.audit/v3", "audit_event")
        );
        let Record::AuditEvent(event) = &source.record else {
            unreachable!()
        };
        assert_eq!(lines[0].action, event.action);
        // Numeric coordinates stay exact. String spellings that match a loaded
        // secret are scrubbed; they are not a generic exemption (ADR 0082).
        let mut scrubbed = details.clone();
        scrub_closed_secret_spellings(&mut scrubbed);
        assert_eq!(lines[0].details, scrubbed.as_object().unwrap().clone());
        assert!(!lines[0].to_json().contains("events-control:metadata"));
        assert!(!lines[0].reason.contains("private-NEEDLE"));
        assert!(!lines[0].reason.contains("exact-prefix"));
        assert!(!lines[0].reason.contains("exact-suffix"));
        let unambiguous = mapper.lines_metadata(&source, &[]).unwrap();
        assert_eq!(unambiguous[0].reason, event.audit.as_ref().unwrap().reason);
        assert_eq!(lines[0].record_hash, unambiguous[0].record_hash);
        assert_eq!(lines[0].at_wall_ms, 19);
        assert_eq!(lines[0].token_id, "system:metadata");
        assert_eq!(source.record.encode(), exact);
        assert!(metadata_view_complete(&mapper, &source, &lines));
        let mut invalid = source;
        let Record::AuditEvent(event) = &mut invalid.record else {
            unreachable!()
        };
        event
            .details
            .insert("secret_value".into(), "private-NEEDLE".into());
        assert!(mapper.lines_metadata(&invalid, secrets).is_err());
        assert!(mapper.expected_metadata(&invalid).is_err());
    }
    let (gap, _) = portable_metadata_control_fixtures()
        .into_iter()
        .next()
        .unwrap();
    let source = kronik_log::MetadataAuditRecord {
        index: 97,
        record: gap,
        native_origin: None,
    };
    let lines = mapper.lines_metadata(&source, secrets).unwrap();
    for field in ["from_index", "through_index"] {
        let mut changed = lines.clone();
        changed[0]
            .details
            .insert(field.into(), serde_json::json!(18));
        assert_eq!(changed[0].record_hash, lines[0].record_hash);
        assert!(!metadata_view_complete(&mapper, &source, &changed));
    }
    let mut ordinary = source;
    let Record::AuditEvent(event) = &mut ordinary.record else {
        unreachable!()
    };
    event.action = "operator.note".into();
    let lines = mapper.lines_metadata(&ordinary, secrets).unwrap();
    assert_ne!(
        lines[0].details.get("namespace"),
        Some(&serde_json::json!("metadata"))
    );
    assert_ne!(
        lines[0].details.get("stream"),
        Some(&serde_json::json!("events-control:metadata"))
    );
    assert_ne!(
        lines[0].details.get("from_index"),
        Some(&serde_json::json!(1))
    );
}

#[test]
fn decoded_protected_approval_uses_the_metadata_receipt_without_publishing_its_identity_payload() {
    let mapper = mapper();
    let owner = format!("oidc:{}", "ab".repeat(32));
    let record = Record::Approval(pb::Approval {
        proposal_id: "p-real-history".into(),
        diff_hash: vec![7; 32],
        verified_through_lsn: 17,
        audit: Some(pb::Audit {
            token_id: owner.clone(),
            reason: "approval private-NEEDLE".into(),
            wall_time_ms: 19,
        }),
        verified_identity: Some(pb::Sealable {
            subject: Some(owner),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 2,
                nonce: vec![3; 24],
                ciphertext: vec![5; 16],
            })),
        }),
        ..Default::default()
    });
    let exact = record.encode();
    let source = kronik_log::MetadataAuditRecord {
        index: 97,
        record: Record::decode(8, &exact).unwrap(),
        native_origin: None,
    };
    let lines = mapper
        .lines_metadata(&source, &[("private", b"private-NEEDLE")])
        .unwrap();
    assert_eq!(
        (&*lines[0].schema, &*lines[0].kind, &*lines[0].action),
        ("kronik.audit/v3", "approval", "approve")
    );
    assert_eq!(
        (lines[0].lsn, lines[0].source),
        (None, Some(SourcePos::Metadata { index: 97 }))
    );
    assert!(lines[0].branch.is_empty());
    assert!(!lines[0].to_json().contains("private-NEEDLE"));
    assert!(!lines[0].details.contains_key("verified_identity"));
    assert!(!lines[0].details.contains_key("ciphertext"));
    assert!(metadata_view_complete(&mapper, &source, &lines));
    assert_eq!(source.record.encode(), exact);
    for mutation in 0..3 {
        let mut invalid = Record::decode(8, &exact).unwrap();
        let Record::Approval(approval) = &mut invalid else {
            unreachable!()
        };
        match mutation {
            0 => {
                approval.verified_identity.as_mut().unwrap().subject =
                    Some("different-owner".into())
            }
            1 => {
                approval.verified_identity.as_mut().unwrap().value =
                    Some(pb::sealable::Value::Plain(b"private identity".to_vec()))
            }
            _ => approval.verified_identity.as_mut().unwrap().value = None,
        }
        let invalid = kronik_log::MetadataAuditRecord {
            index: 97,
            record: invalid,
            native_origin: None,
        };
        assert!(mapper.lines_metadata(&invalid, &[]).is_err());
        assert!(mapper.expected_metadata(&invalid).is_err());
    }
}
