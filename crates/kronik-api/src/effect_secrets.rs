//! The secret versions an effect used: `secrets` on the effects of `history`,
//! of the turn JSON, of a trace and of the answer to a message into a fork
//! (M23, docs/design/m23-secret-backends.md §5.2).

use kronik_proto::log::v1 as pb;

use crate::types::EffectSecret;

/// The secret versions an effect's recorded request names, each once, in the
/// order of first use: the `SecretRef`s of an HTTP effect's headers, of a
/// `crypto.*` effect and of a `secret.reveal`. They are shown as the log holds
/// them (name, version and the first 8 hex characters of the keyed version
/// hash), never a value (I8).
///
/// Like `request_line`, this reads only a plain request: one sealed for a data
/// subject, or erased with it, gives none (a caller who may read it gets it
/// unsealed before this point). A reference that never resolved, as in a
/// denied effect, is no use of a version and gives none.
pub(crate) fn of(e: &pb::EffectRecord) -> Vec<EffectSecret> {
    use prost::Message as _;
    let Some(pb::sealable::Value::Plain(bytes)) = e.request.as_ref().and_then(|r| r.value.as_ref())
    else {
        return Vec::new();
    };
    let references: Vec<pb::SecretRef> = match e.kind.as_str() {
        "http.fetch" | "foreign.http" => pb::HttpEffectRequest::decode(bytes.as_slice())
            .map(|request| {
                request
                    .headers
                    .into_iter()
                    .filter_map(|header| match header.value {
                        Some(pb::http_effect_header::Value::Secret(reference)) => Some(reference),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        "crypto.hmac-sha256" | "crypto.sign-ed25519" => {
            pb::CryptoEffectRequest::decode(bytes.as_slice())
                .ok()
                .and_then(|request| request.secret)
                .into_iter()
                .collect()
        }
        "secret.reveal" => pb::RevealEffectRequest::decode(bytes.as_slice())
            .ok()
            .and_then(|request| request.secret)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    };
    let mut used: Vec<EffectSecret> = Vec::new();
    for reference in &references {
        if reference.is_unresolved() || reference.name.is_empty() {
            continue;
        }
        // The one reading of the legacy `version` and of `wide_version`; it
        // also refuses a version hash that is not 16 bytes.
        let (Ok(version), Some(prefix)) = (
            reference.resolved_version(),
            reference.version_hash.get(..4),
        ) else {
            continue;
        };
        let secret = EffectSecret {
            name: reference.name.clone(),
            version,
            version_hash: kronik_core::ids::hex(prefix),
        };
        if !used.contains(&secret) {
            used.push(secret);
        }
    }
    used
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prost::Message as _;

    use super::*;
    use crate::types::{EffectSummary, HistoryResponse};

    /// A resolved reference as the effect gate records it, with a version
    /// hash of 16 bytes given in hex.
    fn reference(name: &str, version: u64, hash: &str) -> pb::SecretRef {
        let mut reference = pb::SecretRef {
            name: name.into(),
            template: "Bearer {}".into(),
            version_hash: kronik_core::ids::unhex(hash).unwrap(),
            ..Default::default()
        };
        reference.set_resolved_version(version).unwrap();
        reference
    }

    /// A reference no version was resolved for: what a denied effect holds.
    fn unresolved(name: &str) -> pb::SecretRef {
        pb::SecretRef {
            name: name.into(),
            template: "Bearer {}".into(),
            ..Default::default()
        }
    }

    fn secret_header(name: &str, reference: pb::SecretRef) -> pb::HttpEffectHeader {
        pb::HttpEffectHeader {
            name: name.into(),
            value: Some(pb::http_effect_header::Value::Secret(reference)),
        }
    }

    fn text_header(name: &str, value: &str) -> pb::HttpEffectHeader {
        pb::HttpEffectHeader {
            name: name.into(),
            value: Some(pb::http_effect_header::Value::Text(value.into())),
        }
    }

    fn http_request(headers: Vec<pb::HttpEffectHeader>) -> Vec<u8> {
        pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://api.example.com/hooks".into(),
            headers,
            body: b"payload".to_vec(),
            fingerprint_version: 2,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn crypto_request(secret: Option<pb::SecretRef>) -> Vec<u8> {
        pb::CryptoEffectRequest {
            algorithm: "hmac-sha256".into(),
            secret,
            data_hash: vec![7; 32],
        }
        .encode_to_vec()
    }

    fn reveal_request(secret: Option<pb::SecretRef>) -> Vec<u8> {
        pb::RevealEffectRequest { secret }.encode_to_vec()
    }

    fn effect(kind: &str, request: Vec<u8>) -> pb::EffectRecord {
        pb::EffectRecord {
            kind: kind.into(),
            request: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(request)),
            }),
            ..Default::default()
        }
    }

    fn used(name: &str, version: u64, version_hash: &str) -> EffectSecret {
        EffectSecret {
            name: name.into(),
            version,
            version_hash: version_hash.into(),
        }
    }

    const STRIPE_HASH: &str = "8b705664281cdfcde70f57adae0396f7";
    const SIGNING_HASH: &str = "00112233445566778899aabbccddeeff";
    const OTHER_HASH: &str = "c0ffee00c0ffee00c0ffee00c0ffee00";

    #[test]
    fn effect_secrets_name_the_version_of_the_legacy_and_the_wide_identity() {
        // The legacy identity: the unchanged u32 field.
        let legacy = effect(
            "crypto.hmac-sha256",
            crypto_request(Some(reference("stripe-key", 1, STRIPE_HASH))),
        );
        assert_eq!(of(&legacy), vec![used("stripe-key", 1, "8b705664")]);
        // The largest legacy version and the first wide ones, up to 2^53 - 1.
        for (version, hash8) in [
            (u64::from(u32::MAX), "00112233"),
            (u64::from(u32::MAX) + 1, "00112233"),
            ((1 << 53) - 1, "00112233"),
        ] {
            let e = effect(
                "secret.reveal",
                reveal_request(Some(reference("signing", version, SIGNING_HASH))),
            );
            assert_eq!(
                of(&e),
                vec![used("signing", version, hash8)],
                "version {version}"
            );
        }
        // The wide field is what the record holds for a wide version.
        let wide = reference("signing", 1 << 40, SIGNING_HASH);
        assert_eq!((wide.version, wide.wide_version), (0, 1 << 40));
    }

    #[test]
    fn effect_secrets_cover_every_effect_kind_that_records_a_secret() {
        let one = Some(reference("stripe-key", 3, STRIPE_HASH));
        for (kind, request) in [
            ("crypto.hmac-sha256", crypto_request(one.clone())),
            ("crypto.sign-ed25519", crypto_request(one.clone())),
            ("secret.reveal", reveal_request(one.clone())),
            (
                "http.fetch",
                http_request(vec![secret_header("authorization", one.clone().unwrap())]),
            ),
            (
                "foreign.http",
                http_request(vec![secret_header("x-api-key", one.clone().unwrap())]),
            ),
        ] {
            assert_eq!(
                of(&effect(kind, request)),
                vec![used("stripe-key", 3, "8b705664")],
                "{kind}"
            );
        }
    }

    #[test]
    fn effect_secrets_list_several_secrets_once_each_in_order_of_first_use() {
        let a = reference("stripe-key", 3, STRIPE_HASH);
        let b = reference("signing", 2, SIGNING_HASH);
        let e = effect(
            "http.fetch",
            http_request(vec![
                secret_header("authorization", a.clone()),
                text_header("content-type", "application/json"),
                secret_header("x-signature", b),
                // The same secret and version in a second header is one use.
                secret_header("x-api-key", a.clone()),
                // Another version of a name is another entry.
                secret_header("x-previous", reference("stripe-key", 2, OTHER_HASH)),
            ]),
        );
        assert_eq!(
            of(&e),
            vec![
                used("stripe-key", 3, "8b705664"),
                used("signing", 2, "00112233"),
                used("stripe-key", 2, "c0ffee00"),
            ]
        );
    }

    #[test]
    fn effect_secrets_are_empty_for_an_effect_without_a_secret() {
        // An HTTP effect with text headers only.
        let plain = effect(
            "http.fetch",
            http_request(vec![text_header("accept", "application/json")]),
        );
        assert!(of(&plain).is_empty());
        // No headers, a call, a kind that records none, and no request.
        assert!(of(&effect("http.fetch", http_request(Vec::new()))).is_empty());
        let call = pb::CallEffectRequest::default().encode_to_vec();
        assert!(of(&effect("actor.call", call)).is_empty());
        assert!(of(&effect("crypto.hmac-sha256", crypto_request(None))).is_empty());
        let unknown = effect(
            "mystery.kind",
            crypto_request(Some(reference("stripe-key", 1, STRIPE_HASH))),
        );
        assert!(of(&unknown).is_empty());
        let bare = pb::EffectRecord {
            kind: "http.fetch".into(),
            ..Default::default()
        };
        assert!(of(&bare).is_empty());
        // Bytes that are no request for the kind.
        assert!(of(&effect("secret.reveal", b"\xff\xff\xff".to_vec())).is_empty());
    }

    #[test]
    fn a_reference_that_never_resolved_is_no_use_of_a_version() {
        // A denied effect: the secret was not found, so nothing was used.
        let denied = effect(
            "http.fetch",
            http_request(vec![secret_header("authorization", unresolved("missing"))]),
        );
        assert!(of(&denied).is_empty());
        // Next to a resolved one, only the resolved one is listed.
        let mixed = effect(
            "http.fetch",
            http_request(vec![
                secret_header("x-first", unresolved("missing")),
                secret_header("x-second", reference("stripe-key", 4, STRIPE_HASH)),
            ]),
        );
        assert_eq!(of(&mixed), vec![used("stripe-key", 4, "8b705664")]);
        // A reference the log should not hold is not shown as a version.
        let mut short_hash = reference("stripe-key", 4, STRIPE_HASH);
        short_hash.version_hash.pop();
        let mut both = reference("stripe-key", 4, STRIPE_HASH);
        both.wide_version = 1 << 40;
        let mut zero = reference("stripe-key", 4, STRIPE_HASH);
        zero.version = 0;
        let mut narrow_wide = reference("stripe-key", 4, STRIPE_HASH);
        narrow_wide.version = 0;
        narrow_wide.wide_version = 4;
        let nameless = reference("", 4, STRIPE_HASH);
        for (what, bad) in [
            ("a short hash", short_hash),
            ("two version fields", both),
            ("version zero", zero),
            ("a wide field below the wide range", narrow_wide),
            ("no name", nameless),
        ] {
            let e = effect("secret.reveal", reveal_request(Some(bad)));
            assert!(of(&e).is_empty(), "{what}");
        }
    }

    #[test]
    fn a_request_sealed_for_a_data_subject_shows_no_secrets() {
        let requests = [
            (
                "http.fetch",
                http_request(vec![secret_header(
                    "authorization",
                    reference("stripe-key", 3, STRIPE_HASH),
                )]),
            ),
            (
                "crypto.hmac-sha256",
                crypto_request(Some(reference("stripe-key", 3, STRIPE_HASH))),
            ),
        ];
        let sealable = |value| pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(value),
        };
        for (kind, bytes) in requests {
            let record = |value| pb::EffectRecord {
                kind: kind.into(),
                request: Some(sealable(value)),
                ..Default::default()
            };
            // Recorded with `off` protects nothing: a tagged plain request is
            // read as recorded.
            assert_eq!(
                of(&record(pb::sealable::Value::Plain(bytes.clone()))),
                vec![used("stripe-key", 3, "8b705664")],
                "{kind}: tagged, not sealed"
            );
            // Sealed with the subject's key.
            let sealed = pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: vec![9; 24],
                ciphertext: bytes.clone(),
            });
            assert!(of(&record(sealed)).is_empty(), "{kind}: sealed");
            // After erasure: the tombstone that can never be opened.
            let tombstone = pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: Vec::new(),
                ciphertext: Vec::new(),
            });
            assert!(of(&record(tombstone)).is_empty(), "{kind}: erased");
            // What redaction leaves of such a value for the caller: the
            // placeholder text, which no request decodes from.
            for shown in ["[sealed]", "[erased]", "[unreadable:user:1]"] {
                let placeholder = pb::sealable::Value::Plain(shown.as_bytes().to_vec());
                assert!(of(&record(placeholder)).is_empty(), "{kind}: {shown}");
            }
        }
    }

    /// The same sealing rule through the turn views: a sealed effect request
    /// is a placeholder after redaction for a caller without `pii:read`, an
    /// erased one for every caller.
    #[test]
    fn redacted_turns_show_no_secrets_of_sealed_or_erased_requests() {
        let sealer = kronik_privacy::sealer::Sealer::plain();
        let bytes = crypto_request(Some(reference("stripe-key", 3, STRIPE_HASH)));
        let turn = |value| pb::TurnRecord {
            effects: vec![pb::EffectRecord {
                kind: "crypto.hmac-sha256".into(),
                request: Some(pb::Sealable {
                    subject: Some("user:1".into()),
                    value: Some(value),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let secrets_of = |mut t: pb::TurnRecord, pii| {
            crate::redact::redact_turn(&mut t, &sealer, pii);
            crate::turn_summary("main", 7, &t, pii)
                .effects
                .remove(0)
                .secrets
        };
        let sealed = pb::sealable::Value::Sealed(pb::Sealed {
            key_version: 1,
            nonce: vec![9; 24],
            ciphertext: bytes.clone(),
        });
        assert!(secrets_of(turn(sealed), false).is_empty());
        let tombstone = pb::sealable::Value::Sealed(pb::Sealed {
            key_version: 1,
            nonce: Vec::new(),
            ciphertext: Vec::new(),
        });
        assert!(secrets_of(turn(tombstone.clone()), false).is_empty());
        assert!(secrets_of(turn(tombstone), true).is_empty());
        // A plain request is shown to a caller with and without pii:read.
        let plain = pb::sealable::Value::Plain(bytes);
        for pii in [false, true] {
            assert_eq!(
                secrets_of(turn(plain.clone()), pii),
                vec![used("stripe-key", 3, "8b705664")]
            );
        }
    }

    /// The privacy contract with real keys: a subject's request is sealed in
    /// the log and shows no secrets to a caller who may not read it; a caller
    /// who may read it gets them where the turn is unsealed for the caller
    /// (the turn JSON and the trace); and once the subject is erased nobody
    /// gets them again.
    #[test]
    fn sealed_request_secrets_follow_the_caller_and_stay_hidden_after_erasure() {
        let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
        let keystore = Arc::new(kronik_privacy::keystore::Keystore::open_memory(&master).unwrap());
        let sealer = kronik_privacy::sealer::Sealer::new(keystore);
        sealer.set_on(true);

        let mut request = pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Plain(http_request(vec![
                secret_header("authorization", reference("stripe-key", 3, STRIPE_HASH)),
            ]))),
        };
        sealer
            .seal_value(&mut request, &|b: &mut [u8]| b.fill(3), 1)
            .unwrap();
        assert!(matches!(
            request.value,
            Some(pb::sealable::Value::Sealed(_))
        ));
        let turn = pb::TurnRecord {
            effects: vec![pb::EffectRecord {
                kind: "http.fetch".into(),
                request: Some(request),
                ..Default::default()
            }],
            ..Default::default()
        };
        // As the log holds it: sealed, so nothing is read here.
        assert!(of(&turn.effects[0]).is_empty());
        let shown = |pii| {
            let mut t = turn.clone();
            crate::redact::redact_turn(&mut t, &sealer, pii);
            crate::turn_summary("main", 7, &t, pii).effects.remove(0)
        };
        let without = shown(false);
        assert!(without.secrets.is_empty() && without.request.is_none());
        let with = shown(true);
        assert_eq!(with.secrets, vec![used("stripe-key", 3, "8b705664")]);
        assert_eq!(with.request.as_deref(), Some("POST api.example.com/hooks"));

        sealer.erase("user:1", 2).unwrap();
        for pii in [false, true] {
            let erased = shown(pii);
            assert!(erased.secrets.is_empty(), "pii {pii}: {erased:?}");
            assert!(erased.request.is_none(), "pii {pii}: {erased:?}");
        }
    }

    /// Criterion 3 of M23: the rotation of a secret shows up as a new version
    /// in `history`, and the turns before it keep the version they used.
    #[test]
    fn a_rotation_shows_as_a_new_version_and_the_old_turn_keeps_its_own() {
        let turn = |version, hash| pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "billing".into(),
                key: "acme".into(),
            }),
            effects: vec![
                pb::EffectRecord {
                    ordinal: 0,
                    kind: "http.fetch".into(),
                    target: "http:api.example.com".into(),
                    status: pb::EffectStatus::Ok as i32,
                    ..effect(
                        "http.fetch",
                        http_request(vec![secret_header(
                            "authorization",
                            reference("stripe-key", version, hash),
                        )]),
                    )
                },
                effect(
                    "crypto.hmac-sha256",
                    crypto_request(Some(reference("signing", 1, SIGNING_HASH))),
                ),
            ],
            ..Default::default()
        };
        let before = turn(1, STRIPE_HASH);
        let after = turn(2, OTHER_HASH);
        let history = HistoryResponse {
            turns: vec![
                crate::turn_summary("main", 9, &after, true),
                crate::turn_summary("main", 5, &before, true),
            ],
            next: None,
        };
        let json = serde_json::to_value(&history).unwrap();
        // The newer turn used version 2, the older one version 1; the secret
        // that was not rotated is unchanged.
        assert_eq!(
            json["turns"][0]["effects"][0]["secrets"],
            serde_json::json!([{"name": "stripe-key", "version": 2, "version_hash": "c0ffee00"}])
        );
        assert_eq!(
            json["turns"][1]["effects"][0]["secrets"],
            serde_json::json!([{"name": "stripe-key", "version": 1, "version_hash": "8b705664"}])
        );
        for turn in 0..2 {
            assert_eq!(
                json["turns"][turn]["effects"][1]["secrets"],
                serde_json::json!([{"name": "signing", "version": 1, "version_hash": "00112233"}])
            );
        }
        // The turn JSON shows the same.
        let old_turn = crate::turn_json("main", 5, &before);
        assert_eq!(
            old_turn["effects"][0]["secrets"][0]["version"],
            serde_json::json!(1)
        );
    }

    /// The field is additive: absent when there is no secret, and a reader
    /// that does not know it (or an older server) still parses everything.
    #[test]
    fn the_secrets_field_is_additive_in_json() {
        let e = effect(
            "http.fetch",
            http_request(vec![text_header("accept", "*/*")]),
        );
        let t = pb::TurnRecord {
            effects: vec![e],
            ..Default::default()
        };
        let summary = crate::turn_summary("main", 1, &t, true);
        let json = serde_json::to_value(&summary).unwrap();
        assert!(json["effects"][0].get("secrets").is_none(), "{json}");
        assert!(
            crate::turn_json("main", 1, &t)["effects"][0]
                .get("secrets")
                .is_none()
        );
        // An older server's effect has no `secrets`.
        let old: EffectSummary = serde_json::from_value(serde_json::json!({
            "ordinal": 0, "kind": "http.fetch", "target": "http:api.example.com",
            "status": "ok", "delivery": null, "error": null, "hint": null
        }))
        .unwrap();
        assert!(old.secrets.is_empty());
        // And a value is never part of it: only these three keys exist.
        let with = EffectSummary {
            secrets: vec![used("stripe-key", 2, "8b705664")],
            ..old
        };
        let json = serde_json::to_value(&with).unwrap();
        let keys: Vec<&str> = json["secrets"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["name", "version", "version_hash"]);
    }
}
