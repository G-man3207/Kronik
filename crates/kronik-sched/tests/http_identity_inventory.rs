use kronik_effects::http::ScrubError;
use kronik_proto::log::v1 as pb;
use kronik_sched::scrub::{effect_secret_references, original_secret_prefix};
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
    assert_eq!(
        effect_secret_references(
            "http.fetch",
            pb::EffectStatus::Ok as i32,
            &request.encode_to_vec()
        )
        .unwrap(),
        vec![reference.clone()]
    );
    let input = pb::Input {
        kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
            from_schema_version: 1,
            to_schema_version: 2,
        })),
    };
    let mut effect = pb::EffectRecord {
        ordinal: 1,
        kind: "http.fetch".into(),
        status: pb::EffectStatus::Ok as i32,
        request: Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(request.encode_to_vec())),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(original_secret_prefix(&input, std::slice::from_ref(&effect), 1).is_none());
    request.fingerprint_version = 2;
    effect.request = Some(pb::Sealable {
        value: Some(pb::sealable::Value::Plain(request.encode_to_vec())),
        ..Default::default()
    });
    assert_eq!(
        original_secret_prefix(&input, &[effect], 1)
            .unwrap()
            .as_ref(),
        &[reference]
    );
    request.fingerprint_version = 7;
    assert_eq!(
        effect_secret_references(
            "http.fetch",
            pb::EffectStatus::Ok as i32,
            &request.encode_to_vec()
        ),
        Err(ScrubError::SourceScopeUnavailable)
    );
    assert_eq!(
        effect_secret_references(
            "secret.reveal",
            pb::EffectStatus::Ok as i32,
            &pb::RevealEffectRequest::default().encode_to_vec()
        ),
        Err(ScrubError::SourceScopeUnavailable)
    );
    assert_eq!(
        effect_secret_references(
            "crypto.hmac-sha256",
            pb::EffectStatus::Ok as i32,
            &pb::CryptoEffectRequest::default().encode_to_vec()
        ),
        Err(ScrubError::SourceScopeUnavailable)
    );
    assert_eq!(
        effect_secret_references("http.fetch", pb::EffectStatus::Ok as i32, b"\x22\x05ab"),
        Err(ScrubError::SourceScopeUnavailable)
    );
}
