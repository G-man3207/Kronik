//! Trusted PKCS#11 configuration goes only to the isolated, one-shot helper.
use std::io::Cursor;
use std::path::{Component, Path};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kronik_core::env::{Env, ProcessSpec, SensitiveProcessRequest, Stdio};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    Wrapped,
    config::{Pkcs11, Probe},
};

const SCHEMA: &str = "kronik.pkcs11/v1";
const PAYLOAD_SCHEMA: &str = "kronik.pkcs11/envelope/v1";
const PURPOSE: &str = "kronik master v1";
const LIMIT: usize = 4096;
const CONFIG: &str = "PKCS11_CONFIG";
const PROTOCOL: &str = "PKCS11_PROTOCOL";

fn text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && value.chars().all(|c| !c.is_control())
}

fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn path(value: &Path) -> bool {
    value.is_absolute()
        && value.file_name().is_some()
        && value.to_str().is_some_and(|s| text(s, 1024))
        && value
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

pub(crate) fn check(cfg: &Pkcs11, require_probe: bool) -> Result<(), String> {
    if !path(&cfg.helper_path)
        || !path(&cfg.module)
        || !path(&cfg.pin_file)
        || !is_hex(&cfg.module_sha256, 32)
        || !text(&cfg.manufacturer, 32)
        || !text(&cfg.model, 16)
        || !text(&cfg.serial, 16)
        || !text(&cfg.key_version, 128)
        || cfg.key_id.is_empty()
        || cfg.key_id.len() > 128
        || cfg.key_id.len() % 2 != 0
        || !is_hex(&cfg.key_id, cfg.key_id.len() / 2)
        || (require_probe && cfg.probe.is_none())
        || cfg
            .probe
            .as_ref()
            .is_some_and(|p| !is_hex(&p.nonce, 12) || !is_hex(&p.ciphertext, 48))
    {
        return Err(CONFIG.into());
    }
    Ok(())
}

pub(crate) fn key_ref(cfg: &Pkcs11) -> Result<String, String> {
    check(cfg, true)?;
    let probe = cfg.probe.as_ref().ok_or(CONFIG)?;
    let mut hash = blake3::Hasher::new();
    hash.update(b"kronik.pkcs11/identity/v1\0");
    // Deployment integrity changes must not change cryptographic key identity.
    for field in [
        &cfg.manufacturer,
        &cfg.model,
        &cfg.serial,
        &cfg.key_id,
        &cfg.key_version,
        &probe.nonce,
        &probe.ciphertext,
    ] {
        hash.update(&(field.len() as u32).to_be_bytes());
        hash.update(field.as_bytes());
    }
    Ok(format!("pkcs11:b3:{}", hash.finalize().to_hex()))
}

#[derive(Serialize)]
struct Request<'a> {
    schema: &'static str,
    op: &'a str,
    module: &'a str,
    module_sha256: &'a str,
    manufacturer: &'a str,
    model: &'a str,
    serial: &'a str,
    key_id: &'a str,
    key_version: &'a str,
    purpose: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    probe: Option<ProbeData<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeData<'a> {
    nonce: &'a str,
    ciphertext: &'a str,
}

// Missing is allowed, explicit null is not part of the helper's wire schema.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response<'a> {
    schema: &'a str,
    ok: bool,
    #[serde(default, deserialize_with = "present")]
    code: Option<&'a str>,
    #[serde(borrow, default, deserialize_with = "present")]
    probe: Option<ProbeData<'a>>,
    #[serde(default, deserialize_with = "present")]
    nonce: Option<&'a str>,
    #[serde(default, deserialize_with = "present")]
    ciphertext: Option<&'a str>,
    #[serde(default, deserialize_with = "present")]
    plaintext: Option<&'a str>,
}

fn response<'a>(bytes: &'a [u8], op: &str) -> Result<Response<'a>, String> {
    if bytes.is_empty() || bytes.len() > LIMIT || bytes.contains(&b'\\') {
        return Err(PROTOCOL.into());
    }
    let result: Response<'a> = serde_json::from_slice(bytes).map_err(|_| PROTOCOL)?;
    if result.schema != SCHEMA {
        return Err(PROTOCOL.into());
    }
    if !result.ok {
        if result.probe.is_some()
            || result.nonce.is_some()
            || result.ciphertext.is_some()
            || result.plaintext.is_some()
        {
            return Err(PROTOCOL.into());
        }
        return Err(match result.code {
            Some("protocol") => PROTOCOL,
            Some("resource") => "PKCS11_RESOURCE",
            Some("pin") => "PKCS11_PIN",
            Some("module") => "PKCS11_MODULE",
            Some("token") => "PKCS11_TOKEN",
            Some("key") => "PKCS11_KEY",
            Some("attributes") => "PKCS11_ATTRIBUTES",
            Some("authentication") => "PKCS11_AUTHENTICATION",
            Some("provider") => "PKCS11_PROVIDER",
            _ => PROTOCOL,
        }
        .into());
    }
    let valid = result.code.is_none()
        && match op {
            "enroll" => {
                result
                    .probe
                    .as_ref()
                    .is_some_and(|p| is_hex(p.nonce, 12) && is_hex(p.ciphertext, 48))
                    && result.nonce.is_none()
                    && result.ciphertext.is_none()
                    && result.plaintext.is_none()
            }
            "wrap" => {
                result.probe.is_none()
                    && result.plaintext.is_none()
                    && result.nonce.is_some_and(|n| is_hex(n, 12))
                    && result.ciphertext.is_some_and(|c| is_hex(c, 48))
            }
            "unwrap" => {
                result.probe.is_none()
                    && result.nonce.is_none()
                    && result.ciphertext.is_none()
                    && result.plaintext.is_some_and(|p| is_hex(p, 32))
            }
            _ => false,
        };
    if !valid {
        return Err(PROTOCOL.into());
    }
    Ok(result)
}

fn request<'a>(cfg: &'a Pkcs11, op: &'a str) -> Result<Request<'a>, String> {
    check(cfg, op != "enroll")?;
    Ok(Request {
        schema: SCHEMA,
        op,
        module: cfg.module.to_str().ok_or(CONFIG)?,
        module_sha256: &cfg.module_sha256,
        manufacturer: &cfg.manufacturer,
        model: &cfg.model,
        serial: &cfg.serial,
        key_id: &cfg.key_id,
        key_version: &cfg.key_version,
        purpose: PURPOSE,
        probe: None,
        plaintext: None,
        nonce: None,
        ciphertext: None,
    })
}

fn serialize(request: &Request<'_>) -> Result<Zeroizing<Vec<u8>>, String> {
    // A fixed writer cannot reallocate and abandon a previous plaintext buffer.
    let mut buffer = Zeroizing::new([0u8; LIMIT]);
    let mut cursor = Cursor::new(buffer.as_mut_slice());
    serde_json::to_writer(&mut cursor, request).map_err(|_| CONFIG)?;
    let len = cursor.position() as usize;
    Ok(Zeroizing::new(buffer[..len].to_vec()))
}

async fn exchange(
    env: &Env,
    cfg: &Pkcs11,
    request: &Request<'_>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let stdin = serialize(request)?;
    // ProcessRunner returns only after exit AND reap; never parse a live child's output.
    env.procs
        .exchange(SensitiveProcessRequest {
            spec: ProcessSpec {
                program: cfg.helper_path.clone(),
                args: Vec::new(),
                env: Vec::new(),
                cwd: None,
                stdout: Stdio::Null,
                stderr: Stdio::Null,
            },
            stdin,
            pin_file: cfg.pin_file.clone(),
            timeout: Duration::from_secs(10),
        })
        .await
        .map_err(|_| "PKCS11_UNAVAILABLE".into())
}

fn encode_hex(bytes: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

fn decode_seed(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if !is_hex(value, 32) {
        return Err(PROTOCOL.into());
    }
    let mut output = Zeroizing::new(vec![0u8; 32]);
    for (out, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *out = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(output)
}

pub(crate) async fn enroll(env: &Env, cfg: &Pkcs11) -> Result<Probe, String> {
    check(cfg, false)?;
    if let Some(probe) = &cfg.probe {
        // A wrap verifies the enrollment-domain probe inside the helper before encrypting.
        // Never replace a configured probe with a new key's successful enrollment.
        let public = encode_hex(&[0x4b; 32]);
        let mut req = request(cfg, "wrap")?;
        req.probe = Some(ProbeData {
            nonce: &probe.nonce,
            ciphertext: &probe.ciphertext,
        });
        req.plaintext = Some(&public);
        let bytes = exchange(env, cfg, &req).await?;
        response(&bytes, "wrap")?;
        return Ok(Probe {
            nonce: probe.nonce.clone(),
            ciphertext: probe.ciphertext.clone(),
        });
    }
    let req = request(cfg, "enroll")?;
    let bytes = exchange(env, cfg, &req).await?;
    let probe = response(&bytes, "enroll")?.probe.ok_or(PROTOCOL)?;
    Ok(Probe {
        nonce: probe.nonce.into(),
        ciphertext: probe.ciphertext.into(),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload<'a> {
    schema: &'a str,
    nonce: &'a str,
    ciphertext: &'a str,
}

fn payload(bytes: &[u8]) -> Result<Payload<'_>, String> {
    if bytes.contains(&b'\\') {
        return Err(PROTOCOL.into());
    }
    let p: Payload<'_> = serde_json::from_slice(bytes).map_err(|_| PROTOCOL)?;
    if p.schema != PAYLOAD_SCHEMA || !is_hex(p.nonce, 12) || !is_hex(p.ciphertext, 48) {
        return Err(PROTOCOL.into());
    }
    Ok(p)
}

fn ciphertext(cfg: &Pkcs11, wrapped: &Wrapped) -> Result<Vec<u8>, String> {
    check(cfg, true)?;
    if wrapped.schema != "kronik.wrapped-key/v1"
        || wrapped.source != "pkcs11"
        || wrapped.key != key_ref(cfg)?
        || wrapped.key_version != cfg.key_version
        || wrapped.aad != PURPOSE
        || wrapped.ciphertext.len() > LIMIT
    {
        return Err(PROTOCOL.into());
    }
    let bytes = STANDARD.decode(&wrapped.ciphertext).map_err(|_| PROTOCOL)?;
    if STANDARD.encode(&bytes) != wrapped.ciphertext {
        return Err(PROTOCOL.into());
    }
    payload(&bytes)?;
    Ok(bytes)
}

pub(crate) fn validate_wrapped(cfg: &Pkcs11, wrapped: &Wrapped) -> Result<(), String> {
    ciphertext(cfg, wrapped).map(|_| ())
}

pub(crate) async fn encrypt(
    env: &Env,
    cfg: &Pkcs11,
    seed: &[u8; 32],
    aad: &[u8],
) -> Result<Wrapped, String> {
    check(cfg, true)?;
    if aad != PURPOSE.as_bytes() {
        return Err(PROTOCOL.into());
    }
    let probe = cfg.probe.as_ref().ok_or(CONFIG)?;
    let plaintext = encode_hex(seed);
    let mut req = request(cfg, "wrap")?;
    req.probe = Some(ProbeData {
        nonce: &probe.nonce,
        ciphertext: &probe.ciphertext,
    });
    req.plaintext = Some(&plaintext);
    let bytes = exchange(env, cfg, &req).await?;
    let result = response(&bytes, "wrap")?;
    let payload = Payload {
        schema: PAYLOAD_SCHEMA,
        nonce: result.nonce.ok_or(PROTOCOL)?,
        ciphertext: result.ciphertext.ok_or(PROTOCOL)?,
    };
    let encoded = serde_json::to_vec(&payload).map_err(|_| PROTOCOL)?;
    Ok(Wrapped {
        schema: "kronik.wrapped-key/v1".into(),
        source: "pkcs11".into(),
        key: key_ref(cfg)?,
        key_version: cfg.key_version.clone(),
        ciphertext: STANDARD.encode(encoded),
        aad: PURPOSE.into(),
        created_wall_ms: env.clock.wall_ms(),
    })
}

pub(crate) async fn decrypt(
    env: &Env,
    cfg: &Pkcs11,
    wrapped: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let decoded = ciphertext(cfg, wrapped)?;
    let payload = payload(&decoded)?;
    let mut req = request(cfg, "unwrap")?;
    req.nonce = Some(payload.nonce);
    req.ciphertext = Some(payload.ciphertext);
    let bytes = exchange(env, cfg, &req).await?;
    decode_seed(response(&bytes, "unwrap")?.plaintext.ok_or(PROTOCOL)?)
}

#[cfg(test)]
mod tests;
