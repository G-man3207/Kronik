//! `Mapper` at a metadata source position (m28-otel §4.4): the closed control
//! schemas and protected approvals that a Member's metadata log carries. These
//! live in the crate because only `verify_range` can compare `Expected`
//! against lines; the free `verify` covers only the actor LSN domain.

// Test helpers outside #[test] functions may unwrap.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

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

const AT: SourcePos = SourcePos::Metadata { index: 97 };

fn metadata_view_complete(mapper: &Mapper, record: &Record, lines: &[Line]) -> bool {
    verify_range(
        &mapper.expected_at(AT, record).unwrap(),
        lines,
        96,
        97,
        Some((SourcePos::Metadata { index: 96 }, AT)),
    )
    .complete
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
        let source = Record::decode(40, &exact).unwrap();
        let lines = mapper.lines_at(AT, &source, secrets).unwrap();
        assert_eq!((lines[0].lsn, lines[0].source), (None, Some(AT)));
        assert!(lines[0].branch.is_empty());
        assert_eq!(
            (&*lines[0].schema, &*lines[0].kind),
            ("kronik.audit/v3", "audit_event")
        );
        let Record::AuditEvent(event) = &source else {
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
        let unambiguous = mapper.lines_at(AT, &source, &[]).unwrap();
        assert_eq!(unambiguous[0].reason, event.audit.as_ref().unwrap().reason);
        assert_eq!(lines[0].record_hash, unambiguous[0].record_hash);
        assert_eq!(lines[0].at_wall_ms, 19);
        assert_eq!(lines[0].token_id, "system:metadata");
        assert_eq!(source.encode(), exact);
        assert!(metadata_view_complete(&mapper, &source, &lines));
        let mut invalid = source;
        let Record::AuditEvent(event) = &mut invalid else {
            unreachable!()
        };
        event
            .details
            .insert("secret_value".into(), "private-NEEDLE".into());
        assert!(mapper.lines_at(AT, &invalid, secrets).is_err());
        assert!(mapper.expected_at(AT, &invalid).is_err());
    }
    let (source, _) = portable_metadata_control_fixtures()
        .into_iter()
        .next()
        .unwrap();
    let lines = mapper.lines_at(AT, &source, secrets).unwrap();
    for field in ["from_index", "through_index"] {
        let mut changed = lines.clone();
        changed[0]
            .details
            .insert(field.into(), serde_json::json!(18));
        assert_eq!(changed[0].record_hash, lines[0].record_hash);
        assert!(!metadata_view_complete(&mapper, &source, &changed));
    }
    let mut ordinary = source;
    let Record::AuditEvent(event) = &mut ordinary else {
        unreachable!()
    };
    event.action = "operator.note".into();
    let lines = mapper.lines_at(AT, &ordinary, secrets).unwrap();
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
    let source = Record::decode(8, &exact).unwrap();
    let lines = mapper
        .lines_at(AT, &source, &[("private", b"private-NEEDLE")])
        .unwrap();
    assert_eq!(
        (&*lines[0].schema, &*lines[0].kind, &*lines[0].action),
        ("kronik.audit/v3", "approval", "approve")
    );
    assert_eq!((lines[0].lsn, lines[0].source), (None, Some(AT)));
    assert!(lines[0].branch.is_empty());
    assert!(!lines[0].to_json().contains("private-NEEDLE"));
    assert!(!lines[0].details.contains_key("verified_identity"));
    assert!(!lines[0].details.contains_key("ciphertext"));
    assert!(metadata_view_complete(&mapper, &source, &lines));
    assert_eq!(source.encode(), exact);
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
        assert!(mapper.lines_at(AT, &invalid, &[]).is_err());
        assert!(mapper.expected_at(AT, &invalid).is_err());
    }
}
