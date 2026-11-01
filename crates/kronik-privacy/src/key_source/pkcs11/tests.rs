use super::*;

fn config() -> Pkcs11 {
    Pkcs11 {
        helper_path: "/opt/kronik/bin/kronik-keyhelper".into(),
        module: "/opt/hsm/module.so".into(),
        module_sha256: "a1".repeat(32),
        pin_file: "/opt/kronik/private/pin".into(),
        manufacturer: "Example HSM".into(),
        model: "AES model".into(),
        serial: "123456789".into(),
        key_id: "0001".into(),
        key_version: "v1".into(),
        probe: Some(Probe { nonce: "ab".repeat(12), ciphertext: "cd".repeat(48) }),
    }
}

fn envelope(cfg: &Pkcs11) -> Wrapped {
    Wrapped {
        schema: "kronik.wrapped-key/v1".into(), source: "pkcs11".into(), key: key_ref(cfg).unwrap(),
        key_version: cfg.key_version.clone(),
        ciphertext: STANDARD.encode(include_bytes!("../../../tests/fixtures/pkcs11-envelope-v1.json")),
        aad: PURPOSE.into(), created_wall_ms: 1,
    }
}

#[test]
fn identity_survives_module_and_helper_security_updates() {
    let cfg = config();
    let expected = key_ref(&cfg).unwrap();
    let mut patched = cfg;
    patched.helper_path = "/new/kronik-keyhelper".into();
    patched.module = "/new/module.so".into();
    patched.module_sha256 = "b2".repeat(32);
    patched.pin_file = "/new/pin".into();
    assert_eq!(key_ref(&patched).unwrap(), expected);
}

#[test]
fn every_trusted_identity_component_and_probe_is_bound() {
    let cfg = config();
    let expected = key_ref(&cfg).unwrap();
    for field in 0..7 {
        let mut changed = config();
        match field {
            0 => changed.manufacturer.push('x'),
            1 => changed.model.push('x'),
            2 => changed.serial.push('x'),
            3 => changed.key_id.push_str("02"),
            4 => changed.key_version.push('x'),
            5 => changed.probe.as_mut().unwrap().nonce = "ef".repeat(12),
            6 => changed.probe.as_mut().unwrap().ciphertext = "ef".repeat(48),
            _ => unreachable!(),
        }
        assert_ne!(key_ref(&changed).unwrap(), expected);
        assert!(validate_wrapped(&changed, &envelope(&cfg)).is_err());
    }
    let mut left = config();
    left.manufacturer = "ab".into();
    left.model = "c".into();
    let mut right = config();
    right.manufacturer = "a".into();
    right.model = "bc".into();
    assert_ne!(key_ref(&left).unwrap(), key_ref(&right).unwrap());
}

#[test]
fn enrollment_is_the_only_operation_allowing_a_missing_probe() {
    let mut cfg = config();
    cfg.probe = None;
    assert!(check(&cfg, false).is_ok());
    assert!(check(&cfg, true).is_err());
    assert!(key_ref(&cfg).is_err());
    assert!(request(&cfg, "enroll").is_ok());
    assert!(request(&cfg, "wrap").is_err());
    assert!(request(&cfg, "unwrap").is_err());
}

#[test]
fn configuration_rejects_noncanonical_hex_and_invalid_public_fields() {
    for field in 0..10 {
        let mut cfg = config();
        match field {
            0 => cfg.module_sha256 = "AB".repeat(32),
            1 => cfg.module_sha256.pop().map(|_| ()).unwrap(),
            2 => cfg.key_id = "001".into(),
            3 => cfg.key_id = "AA".into(),
            4 => cfg.model = "long".repeat(5),
            5 => cfg.serial = " padded".into(),
            6 => cfg.manufacturer.push('\n'),
            7 => cfg.module = "relative.so".into(),
            8 => cfg.helper_path = "/opt/../helper".into(),
            9 => cfg.probe.as_mut().unwrap().nonce = "00".repeat(11),
            _ => unreachable!(),
        }
        assert_eq!(check(&cfg, false).unwrap_err(), CONFIG);
    }
}

#[test]
fn request_preserves_utf8_and_escaped_public_identity_without_secret_transports() {
    let mut cfg = config();
    cfg.manufacturer = "Example \"HSM\" é".into();
    cfg.module = "/opt/hsm/a\"b.so".into();
    let bytes = serialize(&request(&cfg, "unwrap").unwrap()).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["manufacturer"], cfg.manufacturer);
    assert_eq!(decoded["module"], cfg.module.to_str().unwrap());
    assert_eq!(decoded["purpose"], PURPOSE);
    assert!(decoded.get("pin_file").is_none());
    assert!(decoded.get("helper_path").is_none());
}

#[test]
fn request_writer_rejects_overflow_without_reallocating_plaintext() {
    let cfg = config();
    let mut req = request(&cfg, "wrap").unwrap();
    let oversized = Zeroizing::new("00".repeat(LIMIT));
    req.plaintext = Some(&oversized);
    assert_eq!(serialize(&req).unwrap_err(), CONFIG);
}

#[test]
fn response_accepts_only_the_requested_operation_shape() {
    let probe = format!(r#"{{"schema":"{SCHEMA}","ok":true,"probe":{{"nonce":"{}","ciphertext":"{}"}}}}"#,
        "ab".repeat(12), "cd".repeat(48));
    let wrap = format!(r#"{{"schema":"{SCHEMA}","ok":true,"nonce":"{}","ciphertext":"{}"}}"#,
        "ab".repeat(12), "cd".repeat(48));
    let unwrap = format!(r#"{{"schema":"{SCHEMA}","ok":true,"plaintext":"{}"}}"#, "12".repeat(32));
    for (bytes, own) in [(&probe, "enroll"), (&wrap, "wrap"), (&unwrap, "unwrap")] {
        for op in ["enroll", "wrap", "unwrap"] {
            assert_eq!(response(bytes.as_bytes(), op).is_ok(), op == own);
        }
    }
}

#[test]
fn malformed_duplicate_unknown_trailing_null_and_secret_escapes_fail_closed() {
    let good = format!(r#"{{"schema":"{SCHEMA}","ok":true,"plaintext":"{}"}}"#, "12".repeat(32));
    let cases = [
        good.replace("true", "true,\"ok\":true"),
        good.replace("true", "true,\"module\":\"/evil/module.so\""),
        good.replace("true", "true,\"code\":null"),
        good.replace("1212", "\\u0031\\u003212"),
        format!("{good} {{}}"),
        good.replace(SCHEMA, "kronik.pkcs11/v2"),
        good.replace("1212", "ABCD"),
        good.replace("1212", "12"),
        "{}".into(),
        "x".repeat(LIMIT + 1),
    ];
    for bytes in cases {
        assert!(response(bytes.as_bytes(), "unwrap").is_err());
    }
    assert!(response(&[0xff], "unwrap").is_err());
}

#[test]
fn stable_helper_failures_never_contain_response_data() {
    for (code, expected) in [
        ("protocol", PROTOCOL), ("resource", "PKCS11_RESOURCE"), ("pin", "PKCS11_PIN"),
        ("module", "PKCS11_MODULE"), ("token", "PKCS11_TOKEN"), ("key", "PKCS11_KEY"),
        ("attributes", "PKCS11_ATTRIBUTES"), ("authentication", "PKCS11_AUTHENTICATION"),
        ("provider", "PKCS11_PROVIDER"), ("private-needle", PROTOCOL),
    ] {
        let bytes = format!(r#"{{"schema":"{SCHEMA}","ok":false,"code":"{code}"}}"#);
        assert_eq!(response(bytes.as_bytes(), "unwrap").err().unwrap(), expected);
        let extra = bytes.replace("false", "false,\"plaintext\":\"private-needle\"");
        assert_eq!(response(extra.as_bytes(), "unwrap").err().unwrap(), PROTOCOL);
    }
}

#[test]
fn seed_decode_is_exact_and_zeroizing() {
    let encoded = encode_hex(&[0xa5; 32]);
    let decoded = decode_seed(&encoded).unwrap();
    assert_eq!(decoded.as_slice(), &[0xa5; 32]);
    for invalid in ["AA".repeat(32), "00".repeat(31), "00".repeat(33), "zz".repeat(32)] {
        assert!(decode_seed(&invalid).is_err());
    }
}

#[test]
fn envelope_metadata_and_typed_payload_cannot_select_a_different_key() {
    let cfg = config();
    let good = envelope(&cfg);
    validate_wrapped(&cfg, &good).unwrap();
    for field in 0..6 {
        let mut bad = good.clone();
        match field {
            0 => bad.schema.push('x'),
            1 => bad.source = "aws".into(),
            2 => bad.key.push('x'),
            3 => bad.key_version = "v2".into(),
            4 => bad.aad = "other purpose".into(),
            5 => bad.ciphertext.push('\n'),
            _ => unreachable!(),
        }
        assert!(validate_wrapped(&cfg, &bad).is_err());
    }
    let raw = String::from_utf8(STANDARD.decode(&good.ciphertext).unwrap()).unwrap();
    for altered in [
        raw.replace(PAYLOAD_SCHEMA, "kronik.pkcs11/envelope/v2"),
        raw.replace("\"nonce\":", "\"module\":\"/evil.so\",\"nonce\":"),
        raw.replace("\"nonce\":", "\"nonce\":\"00\",\"nonce\":"),
        raw.replace("1010", "AAAA"),
        raw.replace("2020", "20"),
        raw.replace("1010", "\\u0031\\u003010"),
        format!("{raw} {{}}"),
    ] {
        let mut bad = good.clone();
        bad.ciphertext = STANDARD.encode(altered);
        assert!(validate_wrapped(&cfg, &bad).is_err());
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn real_owned_failure_process_is_reaped_before_classification() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.helper_path = dir.path().join("failure-helper");
    cfg.pin_file = dir.path().join("pin");
    std::fs::write(&cfg.pin_file, b"owned-test-pin\n").unwrap();
    std::fs::set_permissions(&cfg.pin_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pid_file = dir.path().join("pid");
    let env = Env::real(tokio::runtime::Handle::current());
    for (body, expected) in [
        (format!(r#"{{"schema":"{SCHEMA}","ok":false,"code":"authentication"}}"#), "PKCS11_AUTHENTICATION"),
        (format!(r#"{{"schema":"{SCHEMA}","ok":false,"code":"authentication","extra":"private-needle"}}"#), PROTOCOL),
        ("malformed-private-needle".into(), PROTOCOL),
    ] {
        let script = format!("#!/bin/sh\nprintf '%s' \"$$\" > '{}'\ncat >/dev/null\nprintf '%s' '{}'\nexit 0\n",
            pid_file.display(), body);
        std::fs::write(&cfg.helper_path, script).unwrap();
        std::fs::set_permissions(&cfg.helper_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let failure = decrypt(&env, &cfg, &envelope(&cfg)).await.unwrap_err();
        assert_eq!(failure, expected);
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists(), "failure child remains live or unreaped");
        assert!(!failure.contains("needle"));
        assert!(!failure.contains("owned-test-pin"));
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn malformed_metadata_and_missing_probe_never_start_the_helper() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.helper_path = dir.path().join("must-not-start");
    let marker = dir.path().join("started");
    std::fs::write(&cfg.helper_path, format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display())).unwrap();
    std::fs::set_permissions(&cfg.helper_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let mut wrapped = envelope(&cfg);
    wrapped.key_version = "untrusted".into();
    assert!(decrypt(&env, &cfg, &wrapped).await.is_err());
    assert!(encrypt(&env, &cfg, &[0u8; 32], b"wrong purpose").await.is_err());
    cfg.probe = None;
    assert!(encrypt(&env, &cfg, &[0u8; 32], PURPOSE.as_bytes()).await.is_err());
    assert!(decrypt(&env, &cfg, &wrapped).await.is_err());
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn existing_probe_enrollment_cannot_silently_replace_a_rejected_key() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.helper_path = dir.path().join("reject-replacement");
    cfg.pin_file = dir.path().join("pin");
    std::fs::write(&cfg.pin_file, b"owned-test-pin\n").unwrap();
    std::fs::set_permissions(&cfg.pin_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A failure-process fixture, not an HSM or a successful-crypto substitute.
    let script = format!("#!/bin/sh\ncat >/dev/null\nprintf '%s' '{{\"schema\":\"{SCHEMA}\",\"ok\":false,\"code\":\"authentication\"}}'\n");
    std::fs::write(&cfg.helper_path, script).unwrap();
    std::fs::set_permissions(&cfg.helper_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let expected = cfg.probe.as_ref().unwrap().ciphertext.clone();
    assert_eq!(enroll(&env, &cfg).await.err().unwrap(), "PKCS11_AUTHENTICATION");
    assert_eq!(cfg.probe.as_ref().unwrap().ciphertext, expected);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn startup_pin_failure_is_not_retried_and_never_persists_a_seed() {
    use std::os::unix::fs::PermissionsExt as _;
    use crate::key_source::{KeySource, KeySourceError, config::{Keys, Source}};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config();
    cfg.helper_path = dir.path().join("pin-failure");
    cfg.pin_file = dir.path().join("pin");
    let attempts = dir.path().join("attempts");
    std::fs::write(&cfg.pin_file, b"owned-test-pin\n").unwrap();
    std::fs::set_permissions(&cfg.pin_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Repeating a rejected PIN could lock the token; this child never claims crypto success.
    let script = format!("#!/bin/sh\nprintf 'x' >> '{}'\ncat >/dev/null\nprintf '%s' '{{\"schema\":\"{SCHEMA}\",\"ok\":false,\"code\":\"pin\"}}'\n", attempts.display());
    std::fs::write(&cfg.helper_path, script).unwrap();
    std::fs::set_permissions(&cfg.helper_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let keys = Keys { source: Source::Pkcs11, pkcs11: Some(cfg), ..Default::default() };
    let result = KeySource::load(Env::real(tokio::runtime::Handle::current()), keys, dir.path(), true).await;
    assert!(matches!(result, Err(KeySourceError::Pkcs11(code)) if code == "PKCS11_PIN"));
    assert_eq!(std::fs::read(attempts).unwrap(), b"x");
    assert!(!dir.path().join("keys/master.wrapped").exists());
    assert!(!dir.path().join("keys/master.key").exists());
    assert!(!dir.path().join("keys/keystore.db").exists());
}
