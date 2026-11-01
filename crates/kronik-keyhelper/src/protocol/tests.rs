use super::*;
use serde_json::{Value, json};

const ENROLL: &[u8] = include_bytes!("fixtures/enroll-v1.json");

fn fixture() -> Value {
    serde_json::from_slice(ENROLL).unwrap()
}

fn accepted(value: &Value) -> bool {
    let bytes = serde_json::to_vec(value).unwrap();
    parse(&bytes).is_ok()
}

#[test]
fn enrollment_fixture_and_one_request_only() {
    assert_eq!(parse(ENROLL).unwrap().op, "enroll");
    let mut multiple = ENROLL.to_vec();
    multiple.extend_from_slice(ENROLL);
    assert!(matches!(parse(&multiple), Err(Error::Protocol)));
    for input in [b"".as_slice(), b"null", b"[]", b"{", b"{\"op\":\"enroll\"}"] {
        assert!(matches!(parse(input), Err(Error::Protocol)));
    }
}

#[test]
fn exact_input_limit_and_overflow_stop_without_module_loading() {
    let mut exact = ENROLL.to_vec();
    exact.resize(LIMIT, b' ');
    assert!(parse(&exact).is_ok());
    assert_eq!(read_bounded(exact.as_slice(), LIMIT).unwrap().len(), LIMIT);
    exact.push(b' ');
    assert!(matches!(parse(&exact), Err(Error::Protocol)));
    assert!(matches!(read_bounded(exact.as_slice(), LIMIT), Err(Error::Protocol)));

    struct Endless(usize);
    impl Read for Endless {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            output.fill(b'x');
            self.0 += output.len();
            assert!(self.0 <= LIMIT + 1);
            Ok(output.len())
        }
    }
    let mut endless = Endless(0);
    assert!(matches!(read_bounded(&mut endless, LIMIT), Err(Error::Protocol)));
    assert_eq!(endless.0, LIMIT + 1);
}

#[test]
fn duplicate_unknown_and_secret_channels_are_rejected() {
    let duplicate = String::from_utf8(ENROLL.to_vec()).unwrap()
        .replacen("{", "{\"op\":\"wrap\",", 1);
    assert!(matches!(parse(duplicate.as_bytes()), Err(Error::Protocol)));
    for field in ["pin", "password", "slot", "label", "aad", "provider_error"] {
        let mut request = fixture();
        request[field] = json!("secret-needle");
        assert!(!accepted(&request));
    }
}

#[test]
fn escaped_utf8_trusted_identity_roundtrips_and_preserves_canonical_aad() {
    let mut value = fixture();
    value["module"] = json!("/trusted/模块/quoted\"back\\slash.so");
    value["manufacturer"] = json!("厂商\"\\");
    value["model"] = json!("模型\"\\");
    value["serial"] = json!("序列\"\\");
    value["key_version"] = json!("version-版本\"\\");
    let input = serde_json::to_vec(&value).unwrap();
    let request = parse(&input).unwrap();
    assert_eq!(request.module, "/trusted/模块/quoted\"back\\slash.so");
    assert_eq!(request.manufacturer, "厂商\"\\");
    assert_eq!(request.model, "模型\"\\");
    assert_eq!(request.serial, "序列\"\\");
    assert_eq!(request.key_version, "version-版本\"\\");
    assert!(matches!(request.module, Cow::Owned(_)));
    assert!(matches!(request.key_version, Cow::Owned(_)));
    assert!(matches!(request.purpose, Cow::Borrowed(_)));

    let mut escaped = String::from_utf8(input.clone()).unwrap();
    escaped = escaped.replace("版本", "\\u7248\\u672c");
    escaped = escaped.replace("kronik master v1", "kronik master \\u00761");
    let decoded = parse(escaped.as_bytes()).unwrap();
    assert_eq!(aad(&request, false), aad(&decoded, false));
    assert_eq!(aad(&request, true), aad(&decoded, true));
    assert!(matches!(decoded.purpose, Cow::Owned(_)));
    let mut different = decoded;
    different.key_version = "version-另一个".into();
    assert_ne!(aad(&request, false), aad(&different, false));
}

#[test]
fn required_identity_and_purpose_are_strict() {
    for field in ["schema", "module", "module_sha256", "manufacturer", "model", "serial", "key_id", "key_version", "purpose"] {
        let mut request = fixture();
        request.as_object_mut().unwrap().remove(field);
        assert!(!accepted(&request), "missing {field}");
        request = fixture();
        request[field] = json!("");
        assert!(!accepted(&request), "empty {field}");
    }
    for (field, value) in [
        ("schema", "kronik.pkcs11/v2"), ("purpose", "another purpose"),
        ("module", "relative.so"), ("serial", " serial"), ("key_id", "abc"),
        ("key_id", "ABCD"), ("key_id", "gg"), ("key_version", "v1\n"),
    ] {
        let mut request = fixture();
        request[field] = json!(value);
        assert!(!accepted(&request), "invalid {field}");
    }
}

#[test]
fn wrap_requires_an_explicit_complete_enrolled_probe() {
    let mut request = fixture();
    request["op"] = json!("wrap");
    request["plaintext"] = json!("11".repeat(32));
    assert!(!accepted(&request));
    request["probe"] = json!({"nonce":"22".repeat(12),"ciphertext":"33".repeat(48)});
    assert!(accepted(&request));
    for field in ["nonce", "ciphertext"] {
        let saved = request["probe"][field].clone();
        request["probe"].as_object_mut().unwrap().remove(field);
        assert!(!accepted(&request));
        request["probe"][field] = saved;
    }
    request["probe"]["pin"] = json!("forbidden");
    assert!(!accepted(&request));
}

#[test]
fn operations_reject_cross_operation_fields_and_wrong_sizes() {
    for field in ["plaintext", "nonce", "ciphertext", "probe"] {
        let mut request = fixture();
        request[field] = json!("11");
        assert!(!accepted(&request));
    }
    let mut request = fixture();
    request["op"] = json!("unwrap");
    request["nonce"] = json!("11".repeat(12));
    request["ciphertext"] = json!("22".repeat(48));
    assert!(accepted(&request));
    for (field, size) in [("nonce", 12), ("ciphertext", 48)] {
        for wrong in [size - 1, size + 1] {
            let mut wrong_request = request.clone();
            wrong_request[field] = json!("11".repeat(wrong));
            assert!(!accepted(&wrong_request));
        }
    }
    request["probe"] = json!({"nonce":"11".repeat(12),"ciphertext":"22".repeat(48)});
    assert!(!accepted(&request));
}

#[test]
fn canonical_aad_binds_each_identity_field_and_separates_probe_from_seed() {
    let request = parse(ENROLL).unwrap();
    let seed = aad(&request, false);
    assert_ne!(seed, aad(&request, true));
    let mut expected = b"kronik.pkcs11/seed/v1\0".to_vec();
    for field in ["SoftHSM project", "SoftHSM v2", "244b62a631d0dce3",
        "58809dacd6a0a338e60c233610601d75", "fixture-v1", "kronik master v1"] {
        expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
        expected.extend_from_slice(field.as_bytes());
    }
    assert_eq!(seed.as_slice(), expected);
    for field in ["manufacturer", "model", "serial", "key_id", "key_version"] {
        let mut changed = fixture();
        changed[field] = json!(if field == "key_id" { "aa" } else { "different" });
        let bytes = serde_json::to_vec(&changed).unwrap();
        assert_ne!(seed, aad(&parse(&bytes).unwrap(), false), "unbound {field}");
    }
    let mut changed = parse(ENROLL).unwrap();
    changed.purpose = "different".into();
    assert_ne!(seed, aad(&changed, false));
}

#[test]
fn canonical_lengths_prevent_field_concatenation_collisions() {
    let mut left = parse(ENROLL).unwrap();
    left.manufacturer = "ab".into();
    left.model = "c".into();
    let mut right = parse(ENROLL).unwrap();
    right.manufacturer = "a".into();
    right.model = "bc".into();
    assert_ne!(aad(&left, false), aad(&right, false));
}

#[test]
fn trusted_module_upgrade_does_not_change_cryptographic_identity() {
    let original = parse(ENROLL).unwrap();
    let mut updated = parse(ENROLL).unwrap();
    updated.module = "/usr/lib/updated-module.so".into();
    updated.module_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert_eq!(aad(&original, false), aad(&updated, false));
    assert_eq!(aad(&original, true), aad(&updated, true));
}

#[test]
fn hex_is_canonical_and_roundtrips_all_bytes() {
    let bytes: Vec<_> = (0..=255).collect();
    assert_eq!(decode(&encode(&bytes)).unwrap().as_slice(), bytes);
    for invalid in ["0", "AA", "0g", " a", "\n0"] {
        assert!(matches!(decode(invalid), Err(Error::Protocol)));
    }
}

#[test]
fn response_overflow_never_partially_writes_and_errors_have_no_body() {
    let oversized = "secret-needle".repeat(LIMIT);
    let response = Response::success("unwrap", "", &oversized);
    let mut output = Vec::new();
    assert_eq!(response.write(&mut output), Err(Error::Protocol));
    assert!(output.is_empty());
    for error in [Error::Protocol, Error::Resource, Error::Pin, Error::Module, Error::Token,
        Error::Key, Error::Attributes, Error::Authentication, Error::Provider] {
        let mut output = Vec::new();
        Response::failure(error).write(&mut output).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["ok"], false);
        assert!(value["code"].is_string());
        assert!(output.len() <= LIMIT);
    }
}

#[test]
fn maximum_valid_result_is_single_bounded_json_without_extra_fields() {
    for op in ["enroll", "wrap", "unwrap"] {
        let nonce = "11".repeat(12);
        let data = "22".repeat(if op == "unwrap" { 32 } else { 48 });
        let mut output = Vec::new();
        Response::success(op, &nonce, &data).write(&mut output).unwrap();
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["schema"], SCHEMA);
        assert!(value.get("code").is_none());
        assert!(output.len() < LIMIT);
        if op == "unwrap" {
            assert_eq!(value["plaintext"], data);
            assert!(value.get("ciphertext").is_none());
        } else if op == "enroll" {
            assert_eq!(value["probe"]["ciphertext"], data);
        } else {
            assert_eq!(value["nonce"], nonce);
            assert_eq!(value["ciphertext"], data);
        }
    }
}
