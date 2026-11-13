use super::*;
use kronik_effects::http::{
    fingerprint, fingerprint_v2, parse_request_url, parse_url, prepared_target, target_of,
};

fn body(value: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(value.to_vec())),
    })
}

fn msg(value: &[u8]) -> pb::Message {
    pb::Message {
        name: "message".into(),
        content_type: "text/plain".into(),
        body: body(value),
        ..Default::default()
    }
}

fn bytes(value: &Option<pb::Sealable>) -> &[u8] {
    match value.as_ref().and_then(|value| value.value.as_ref()) {
        Some(pb::sealable::Value::Plain(value)) => value,
        _ => panic!("expected plain test value"),
    }
}

fn plan<'a>(secrets: &'a [(&'a str, &'a [u8])]) -> CompiledScrubber<'a> {
    CompiledScrubber::new(secrets, MAX_SECRET_PATTERN_BYTES).unwrap()
}

fn reference(name: &str, version: u64) -> pb::SecretRef {
    let mut reference = pb::SecretRef {
        name: name.into(),
        version_hash: vec![7; 16],
        ..Default::default()
    };
    reference.set_resolved_version(version).unwrap();
    reference
}

#[test]
fn operator_tokens_and_secrets_match_original_text_once() {
    let token = format!("kronik_{}", "A-_9".repeat(10) + "abc");
    let secrets = [
        ("E", b"e".as_slice()),
        (token.as_str(), b"x".as_slice()),
        ("duplicate", token.as_bytes()),
    ];
    assert_eq!(
        for_log(&format!("x {token}"), Some(&secrets)),
        format!("[secret:{token}] [secret:token]")
    );
    assert_eq!(for_log("unknown", None), WITHHELD);
    assert_eq!(for_target(&token, None), "[secret:token]");
    assert_eq!(for_target(&format!("x{token}Z"), None), "x[secret:token]Z");
}

#[test]
fn literal_marker_is_not_an_output_provenance_exemption() {
    let secrets = [("A", b"a".as_slice()), ("E", b"e".as_slice())];
    let mut generated = body(b"a");
    sealable(&mut generated, &secrets).unwrap();
    assert_eq!(bytes(&generated), b"[secret:A]");
    let mut literal = body(b"[secret:A]");
    sealable(&mut literal, &secrets).unwrap();
    assert_eq!(bytes(&literal), b"[s[secret:E]cr[secret:E]t:A]");
}

#[test]
fn fresh_unsafe_call_is_denied_without_changing_either_intent() {
    let secrets = [("credential", b"needle".as_slice())];
    let matcher = plan(&secrets);
    let mut request = pb::CallEffectRequest {
        msg: Some(msg(b"safe")),
        compensate: Some(msg(b"needle")),
        ..Default::default()
    };
    let original = request.encode_to_vec();
    assert_eq!(
        call_request(&mut request, &matcher, 4096),
        Err(CallRequestError::UnsafeCompensation)
    );
    assert_eq!(request.encode_to_vec(), original);
    request.compensate = Some(msg(b"safe cleanup"));
    request.msg.as_mut().unwrap().name = "needle".into();
    let original = request.encode_to_vec();
    assert_eq!(
        call_request(&mut request, &matcher, 4096),
        Err(CallRequestError::UnsafeMessage)
    );
    assert_eq!(request.encode_to_vec(), original);
    request.msg.as_mut().unwrap().name = "safe".into();
    request.msg.as_mut().unwrap().body.as_mut().unwrap().subject =
        Some("label-is-not-protection".into());
    request.msg.as_mut().unwrap().body.as_mut().unwrap().value =
        Some(pb::sealable::Value::Plain(b"needle".to_vec()));
    assert_eq!(
        call_request(&mut request, &matcher, 4096),
        Err(CallRequestError::UnsafeMessage)
    );
}

#[test]
fn call_budget_failure_is_not_a_policy_denial_and_safe_inputs_stay_exact() {
    let secrets = [("credential", b"needle".as_slice())];
    let matcher = plan(&secrets);
    let mut unsafe_request = pb::CallEffectRequest {
        msg: Some(msg(b"needle")),
        ..Default::default()
    };
    assert_eq!(
        call_request(&mut unsafe_request, &matcher, 1),
        Err(CallRequestError::Redaction(ScrubError::OutputLimit))
    );
    let mut safe = pb::CallEffectRequest {
        msg: Some(msg(b"safe")),
        compensate: Some(msg(b"safe cleanup")),
        ..Default::default()
    };
    let message = safe.msg.clone();
    let compensation = safe.compensate.clone();
    call_request(&mut safe, &matcher, 4096).unwrap();
    assert_eq!(safe.msg, message);
    assert_eq!(safe.compensate, compensation);
    assert_eq!(safe.fingerprint_version, 2);
}

#[test]
fn byte_identical_sensitive_literal_still_denies_fresh_call() {
    let secrets = [("marker", b"[secret:marker]".as_slice())];
    let mut request = pb::CallEffectRequest {
        msg: Some(msg(b"[secret:marker]")),
        ..Default::default()
    };
    assert_eq!(
        call_request(&mut request, &plan(&secrets), 4096),
        Err(CallRequestError::UnsafeMessage)
    );
}

#[test]
fn closed_cleanup_reference_is_not_an_ordinary_call_argument() {
    let mut request = pb::CallEffectRequest {
        msg: Some(pb::Message {
            retained_compensation_source: Some(pb::ActorSource {
                shard: None,
                lsn: 9,
                branch: "main".into(),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        call_request(&mut request, &plan(&[]), 4096),
        Err(CallRequestError::Redaction(ScrubError::InvalidText))
    );
}

#[test]
fn prepared_markers_need_exact_identity_scope_not_a_name_or_empty_guess() {
    let secrets = [("a", b"a".as_slice()), ("e", b"e".as_slice())];
    let matcher = plan(&secrets);
    let current = [reference("a", 1), reference("e", 2)];
    let prepared = b"[secret:a]".as_slice();
    assert!(prepared_fields_safe(Some(&current), Some(&current), &matcher, [prepared]).is_ok());
    assert_eq!(
        prepared_fields_safe(Some(&current), None, &matcher, [prepared]),
        Err(ScrubError::SourceScopeUnavailable)
    );
    assert_eq!(
        prepared_fields_safe(Some(&current), Some(&[]), &matcher, [prepared]),
        Err(ScrubError::SourceScopeUnavailable)
    );
    assert!(prepared_fields_safe(Some(&current), None, &matcher, [b"XYZ".as_slice()]).is_ok());
    let mut wrong = current.clone();
    wrong[0].version_hash[0] ^= 1;
    assert!(!secret_scope_is_subset(Some(&current), Some(&wrong)).unwrap());
    assert!(secret_scope_is_subset(Some(&[]), Some(&[])).unwrap());
    assert!(!secret_scope_is_subset(None, Some(&[])).unwrap());
    wrong[0].template = "free original template".into();
    assert_eq!(
        secret_scope_is_subset(Some(&current), Some(&wrong)),
        Err(ScrubError::SourceScopeUnavailable)
    );
}

#[test]
fn url_grammar_is_original_and_encoded_free_delimiters_are_redacted() {
    let secrets = [
        ("H&=UP", b"alpha".as_slice()),
        ("S", b"/".as_slice()),
        ("A", b"&".as_slice()),
        ("Q", b"=".as_slice()),
    ];
    let original = "https://alpha.test/a%2fb?p=x%26y&q=x%3dy";
    let mut request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: original.into(),
        ..Default::default()
    };
    let (original_target, raw_host) = parse_request_url(original).unwrap();
    let target = http_request(
        &mut request,
        &original_target,
        raw_host,
        &plan(&secrets),
        4096,
    )
    .unwrap();
    assert_eq!(request.fingerprint_version, 2);
    assert_eq!(
        request.url,
        "https://%5bsecret%3aH%26%3dUP%5d.test/a%5bsecret%3aS%5db?p=x%5bsecret%3aA%5dy&q=x%5bsecret%3aQ%5dy"
    );
    assert_eq!(target_of(&request).unwrap().1, target.host);
    assert_eq!(target.query.split('&').count(), 2);
    assert_eq!(fingerprint_v2(&request, &target).unwrap().len(), 32);
    assert!(fingerprint(&request).is_err());
}

#[test]
fn core_spelling_is_not_guest_code_provenance_but_real_host_traps_remain_structural() {
    let turn = |kind| kronik_runtime::TurnOutput {
        outcome: pb::Outcome {
            kind: kind as i32,
            error_code: kronik_core::error::ErrorCode::HostRedactionFailure
                .as_str()
                .into(),
            message: String::new(),
            output: None,
        },
        writes: Vec::new(),
        messages: Vec::new(),
        timers: Vec::new(),
        connection_ops: Vec::new(),
        fuel_used: 13,
        memory_peak_bytes: 29,
        logs: Vec::new(),
        sql: None,
    };
    let secrets = [("H", b"H".as_slice())];
    let matcher = plan(&secrets);
    let mut host = turn(pb::OutcomeKind::Trap);
    output(&mut host, &matcher).unwrap();
    assert_eq!(host.outcome.error_code, "HOST_REDACTION_FAILURE");
    assert_eq!((host.fuel_used, host.memory_peak_bytes), (13, 29));
    for kind in [pb::OutcomeKind::Failed, pb::OutcomeKind::Rejected] {
        assert_eq!(
            output(&mut turn(kind), &matcher),
            Err(ScrubError::SourceScopeUnavailable)
        );
    }
}

#[test]
fn ipv6_redacted_data_becomes_a_parseable_opaque_reg_name() {
    for original in [
        "http://[::ffff:192.0.2.1]:8080/p",
        "http://[dead:beef::1]/p",
    ] {
        let mut request = pb::HttpEffectRequest {
            method: "GET".into(),
            url: original.into(),
            ..Default::default()
        };
        let (target, raw_host) = parse_request_url(original).unwrap();
        http_request(&mut request, &target, raw_host, &plan(&[]), 4096).unwrap();
        assert_eq!(request.url, original);
        assert!(parse_url(&request.url).is_ok());
    }
    let original = "http://[dead:beef::1]/p";
    let mut request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: original.into(),
        ..Default::default()
    };
    let secrets = [("IP", b"dead".as_slice())];
    let (original_target, raw_host) = parse_request_url(original).unwrap();
    let target = http_request(
        &mut request,
        &original_target,
        raw_host,
        &plan(&secrets),
        4096,
    )
    .unwrap();
    assert_eq!(target.host, "%5bsecret%3aIP%5d%3abeef%3a%3a1");
    assert_eq!(prepared_target(&request).unwrap(), target);
    assert!(!request.url.contains("dead"));
}

#[test]
fn free_header_names_cannot_bypass_redaction_or_turn_into_invalid_wire_names() {
    let secrets = [("N", b"needle".as_slice())];
    let matcher = plan(&secrets);
    let mut request = pb::HttpEffectRequest {
        method: "GET".into(),
        url: "http://h/".into(),
        headers: vec![pb::HttpEffectHeader {
            name: "x-needle".into(),
            value: Some(pb::http_effect_header::Value::Text("ok".into())),
        }],
        ..Default::default()
    };
    let (target, raw_host) = parse_request_url("http://h/").unwrap();
    http_request(&mut request, &target, raw_host, &matcher, 4096).unwrap();
    assert_eq!(request.headers[0].name, "x-[secret:N]");
    let mut response = pb::HttpEffectResponse {
        status: 206,
        headers: vec![pb::HeaderPair {
            name: "x-needle".into(),
            value: "ok".into(),
        }],
        body: b"ok".to_vec(),
    };
    assert_eq!(
        http_response(&mut response, &matcher, 4096),
        Err(ScrubError::InvalidText)
    );
    assert_eq!(response.status, 206);
}

#[test]
fn reply_free_name_type_and_body_share_one_plan() {
    let secrets = [("N", b"needle".as_slice())];
    let mut response = pb::CallEffectResponse {
        reply: Some(pb::Message {
            name: "needle".into(),
            content_type: "needle".into(),
            body: body(b"needle"),
            ..Default::default()
        }),
        ..Default::default()
    };
    call_response(&mut response, &plan(&secrets), 4096).unwrap();
    let reply = response.reply.unwrap();
    assert_eq!(reply.name, "[secret:N]");
    assert_eq!(reply.content_type, "[secret:N]");
    assert_eq!(bytes(&reply.body), b"[secret:N]");
}

#[test]
fn body_and_header_expansion_share_the_response_budget() {
    let secrets = [("X", b"a".as_slice())];
    let mut response = pb::HttpEffectResponse {
        status: 200,
        headers: vec![pb::HeaderPair {
            name: "x".into(),
            value: "a".into(),
        }],
        body: b"a".to_vec(),
    };
    assert_eq!(
        http_response(&mut response, &plan(&secrets), 20),
        Err(ScrubError::OutputLimit)
    );
    let secrets = [
        ("T", b"true".as_slice()),
        ("F", b"false".as_slice()),
        ("N", b"null".as_slice()),
        ("A", b"a".as_slice()),
    ];
    let mut response = pb::HttpEffectResponse {
        status: 200,
        body: b"true false null a".to_vec(),
        ..Default::default()
    };
    http_response(&mut response, &plan(&secrets), 128).unwrap();
    assert_eq!(
        response.body,
        b"[secret:T] [secret:F] [secret:N] [secret:A]"
    );
}

#[test]
fn partial_utf8_matches_fail_closed_in_text_not_lossy() {
    let secrets = [("partial", [0xa9].as_slice())];
    assert_eq!(for_log("é", Some(&secrets)), WITHHELD);
    let mut response = pb::HttpEffectResponse {
        status: 200,
        headers: vec![pb::HeaderPair {
            name: "x".into(),
            value: "é".into(),
        }],
        ..Default::default()
    };
    assert_eq!(
        http_response(&mut response, &plan(&secrets), 128),
        Err(ScrubError::InvalidText)
    );
}

#[test]
fn private_legacy_verifier_keeps_old_filter_and_restores_inputs() {
    let secrets = [
        ("L", b"LONG-credential".as_slice()),
        ("S", b"a".as_slice()),
        ("T", b"true".as_slice()),
        ("F", b"false".as_slice()),
        ("N", b"null".as_slice()),
    ];
    let mut request = pb::HttpEffectRequest {
        method: "post".into(),
        url: "https://h:443/x?z=2&a=1".into(),
        headers: vec![pb::HttpEffectHeader {
            name: "x-LONG-credential".into(),
            value: Some(pb::http_effect_header::Value::Text(
                "LONG-credential a true false null".into(),
            )),
        }],
        body: b"LONG-credential a true false null".to_vec(),
        ..Default::default()
    };
    let original = request.clone();
    let mut exact_old = request.clone();
    exact_old.body = b"[secret:L] a true false null".to_vec();
    exact_old.headers[0].value = Some(pb::http_effect_header::Value::Text(
        "[secret:L] a true false null".into(),
    ));
    assert_eq!(
        legacy_verification_fingerprint(&mut request, &exact_old, &secrets).unwrap(),
        fingerprint(&exact_old).unwrap()
    );
    assert_eq!(request, original);
    request.url = "invalid".into();
    let invalid = request.clone();
    assert_eq!(
        legacy_verification_fingerprint(&mut request, &exact_old, &secrets),
        Err(ScrubError::InvalidText)
    );
    assert_eq!(request, invalid);
}

#[test]
fn actual_strict_request_producer_matches_original_host_case_before_canonicalization() {
    for (original, value) in [
        ("https://ABC.Example:8443/p?q=v", b"ABC".as_slice()),
        ("http://[ABCD::1]:8080/p", b"ABCD".as_slice()),
        ("foreign://PayMENTS/run", b"Pay".as_slice()),
    ] {
        let (canonical, raw_host) = parse_request_url(original).unwrap();
        assert!(
            !canonical
                .host
                .as_bytes()
                .windows(value.len())
                .any(|part| part == value)
        );
        let secrets = [("Host", value)];
        let matcher = plan(&secrets);
        assert!(http_url_contains(&canonical, raw_host, &|bytes| matcher.is_match(bytes)).unwrap());
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: original.into(),
            ..Default::default()
        };
        let original_bytes = source.encode_to_vec();
        let legacy_fingerprint = fingerprint(&source).unwrap();
        let mut prepared = source.clone();
        let target = http_request(&mut prepared, &canonical, raw_host, &matcher, 4096).unwrap();
        assert!(
            !prepared
                .url
                .as_bytes()
                .windows(value.len())
                .any(|part| part == value)
        );
        assert_eq!(prepared_target(&prepared).unwrap(), target);
        assert_eq!(target_of(&prepared).unwrap().1, target.host);
        let hash = fingerprint_v2(&prepared, &target).unwrap();
        assert_eq!(
            hash,
            fingerprint_v2(&prepared, &prepared_target(&prepared).unwrap()).unwrap()
        );
        assert_eq!(
            source.encode_to_vec(),
            original_bytes,
            "the original wire source is unchanged"
        );
        assert_eq!(fingerprint(&source).unwrap(), legacy_fingerprint);
        let mut too_small = source.clone();
        assert_eq!(
            http_request(&mut too_small, &canonical, raw_host, &matcher, 8),
            Err(ScrubError::OutputLimit)
        );
    }
}
#[test]
fn persisted_candidate_reason_is_withheld_instead_of_rescrubbing_its_generated_label() {
    let values = [
        ("short", b"a".as_slice()),
        ("new-candidate", b"new-needle".as_slice()),
    ];
    let stored = pb::Audit {
        token_id: "operator".into(),
        wall_time_ms: 17,
        reason: for_log("prefix|new-needle|suffix", Some(&values)),
    };
    assert_eq!(stored.reason, "prefix|[secret:new-candidate]|suffix");
    let output_plan = CompiledScrubber::new_output(&values, MAX_SECRET_PATTERN_BYTES).unwrap();
    assert!(output_plan.is_match(stored.reason.as_bytes()));
    let projected = persisted_audit_reason(stored.reason.as_str().into(), Some(&output_plan));
    assert_eq!(projected.as_ref(), WITHHELD);
    assert!(!projected.contains("[secret:short]"));
    assert_eq!(
        stored.reason, "prefix|[secret:new-candidate]|suffix",
        "the durable reason is immutable"
    );
    assert_eq!(
        (stored.token_id.as_str(), stored.wall_time_ms),
        ("operator", 17)
    );
    // Mutable input still uses the original one-pass replacement policy.
    assert_eq!(
        for_log("prefix|new-needle|suffix", Some(&values)),
        stored.reason
    );
}

#[test]
fn historical_free_reason_later_matching_a_secret_is_wholly_withheld() {
    let values = [("later", b"old-public-data".as_slice())];
    let output_plan = CompiledScrubber::new_output(&values, MAX_SECRET_PATTERN_BYTES).unwrap();
    let stored = pb::Audit {
        token_id: "original".into(),
        reason: "prefix old-public-data suffix".into(),
        wall_time_ms: 29,
    };
    assert_eq!(
        persisted_audit_reason(stored.reason.as_str().into(), Some(&output_plan)).as_ref(),
        WITHHELD
    );
    assert_eq!(stored.reason, "prefix old-public-data suffix");
    assert_eq!(
        (stored.token_id.as_str(), stored.wall_time_ms),
        ("original", 29)
    );
}

#[test]
fn persisted_reason_projection_preserves_no_match_and_matches_even_identical_marker_bytes() {
    let values = [("marker", b"[secret:marker]".as_slice())];
    let output_plan = CompiledScrubber::new_output(&values, MAX_SECRET_PATTERN_BYTES).unwrap();
    let literal = "[secret:marker]";
    assert!(output_plan.is_match(literal.as_bytes()));
    assert_eq!(
        persisted_audit_reason(literal.into(), Some(&output_plan)).as_ref(),
        WITHHELD
    );
    let original = " \tPUBLIC\nλ [secret:unrelated] ";
    assert_eq!(
        persisted_audit_reason(original.to_owned().into(), Some(&output_plan)).as_ref(),
        original
    );
    assert_eq!(
        persisted_audit_reason(original.into(), Some(&output_plan)).as_ref(),
        original
    );
    assert_eq!(
        persisted_audit_reason(original.into(), None).as_ref(),
        WITHHELD
    );
}

#[test]
fn persisted_reason_uses_the_existing_credential_aware_output_predicate() {
    let no_values: &[(&str, &[u8])] = &[];
    let output_plan = CompiledScrubber::new_output(no_values, MAX_SECRET_PATTERN_BYTES).unwrap();
    let token = format!("kronik_{}", "A-_9".repeat(10) + "abc");
    assert!(output_plan.is_match(token.as_bytes()));
    assert_eq!(
        persisted_audit_reason(token.as_str().into(), Some(&output_plan)).as_ref(),
        WITHHELD
    );
    assert_eq!(for_log(&token, Some(no_values)), "[secret:token]");
}
