use kronik_proto::log::v1 as pb;
use kronik_sched::scrub::original_secret_prefix;
use prost::Message as _;

#[test]
fn historical_http_identity_is_inventory_but_not_prepared_coverage() {
    let reference = pb::SecretRef {
        name: "old".into(),
        version: 7,
        version_hash: vec![7; 16],
        ..Default::default()
    };
    let mut request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: "http://h/".into(),
        headers: vec![pb::HttpEffectHeader {
            name: "authorization".into(),
            value: Some(pb::http_effect_header::Value::Secret(reference.clone())),
        }],
        ..Default::default()
    };
    let input = pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
            from_schema_version: 1,
            to_schema_version: 2,
        })),
    };
    let effect = |kind: &str, bytes: Vec<u8>| pb::EffectRecord {
        ordinal: 1,
        kind: kind.into(),
        status: pb::EffectStatus::Ok as i32,
        request: Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(bytes)),
            ..Default::default()
        }),
        ..Default::default()
    };
    // Version-0 identities remain inventory: the prepared prefix rejects them.
    assert!(
        original_secret_prefix(
            &input,
            std::slice::from_ref(&effect("http.fetch", request.encode_to_vec())),
            1
        )
        .is_none()
    );
    request.fingerprint_version = 2;
    assert_eq!(
        original_secret_prefix(&input, &[effect("http.fetch", request.encode_to_vec())], 1)
            .unwrap()
            .as_ref(),
        &[reference]
    );
    // An unknown fingerprint version never certifies prepared bytes.
    request.fingerprint_version = 7;
    assert!(
        original_secret_prefix(&input, &[effect("http.fetch", request.encode_to_vec())], 1)
            .is_none()
    );
    // A payload that does not decode as its kind contributes no references.
    assert!(
        original_secret_prefix(
            &input,
            &[effect(
                "secret.reveal",
                pb::RevealEffectRequest::default().encode_to_vec()
            )],
            1
        )
        .is_none()
    );
    assert!(
        original_secret_prefix(
            &input,
            &[effect(
                "crypto.hmac-sha256",
                pb::CryptoEffectRequest::default().encode_to_vec()
            )],
            1
        )
        .is_none()
    );
    assert!(
        original_secret_prefix(&input, &[effect("http.fetch", b"\x22\x05ab".to_vec())], 1)
            .is_none()
    );
}
