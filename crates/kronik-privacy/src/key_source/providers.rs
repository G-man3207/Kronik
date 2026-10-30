//! Small REST clients. Neither provider bodies nor credentials become diagnostics.
use std::ops::Deref;
use std::path::Path;
use std::time::Duration;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use kronik_core::env::{Env, HttpRequest, OpenMode, TlsConfig};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Wrapped,
    config::{self, Keys, Source},
};
mod aws;
mod azure;
mod gcp;
mod openbao;
pub mod sigv4;

const CAP: usize = 128 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const AAD: &str = "kronik master v1";
const SCHEMA: &str = "kronik.wrapped-key/v1";

// serde_json::Value has no Zeroize implementation; scrub every owned string on drop.
struct SecretJson(Value);
impl Deref for SecretJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
impl Drop for SecretJson {
    fn drop(&mut self) {
        fn scrub(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(scrub),
                Value::Object(o) => o.values_mut().for_each(scrub),
                _ => {}
            }
        }
        scrub(&mut self.0);
    }
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "invalid provider response".into())
}
fn header_secret(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > CAP || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("invalid provider credential".into());
    }
    Ok(())
}
fn secret_body(body: Vec<u8>) -> Bytes {
    Bytes::from_owner(Zeroizing::new(body))
}
async fn request_bytes(
    env: &Env,
    method: &str,
    url: String,
    mut headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut body = Zeroizing::new(body);
    let size = headers.iter().fold(
        method
            .len()
            .saturating_add(url.len())
            .saturating_add(body.len()),
        |n, (k, v)| {
            n.saturating_add(k.len())
                .saturating_add(v.len())
                .saturating_add(4)
        },
    );
    if size > CAP {
        for (_, value) in &mut headers {
            value.zeroize();
        }
        return Err("provider request too large".into());
    }
    let req = HttpRequest {
        method: method.into(),
        url,
        headers,
        body: secret_body(std::mem::take(&mut *body)),
        max_response_bytes: CAP as u64,
    };
    let response = env
        .timeout(REQUEST_TIMEOUT, env.net.http(req))
        .await
        .map_err(|_| "provider request timed out")?
        .map_err(|_| "provider connection failed")?;
    let status = response.status;
    let data = Zeroizing::new(Vec::<u8>::from(response.body));
    if data.len() > CAP {
        return Err("provider response too large".into());
    }
    if !(200..300).contains(&status) {
        return Err(format!("provider returned HTTP {status}"));
    }
    Ok(data)
}
async fn request(
    env: &Env,
    method: &str,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<SecretJson, String> {
    let data = request_bytes(env, method, url, headers, body).await?;
    serde_json::from_slice(&data)
        .map(SecretJson)
        .map_err(|_| "invalid provider JSON response".into())
}
async fn json_request(
    env: &Env,
    url: String,
    mut headers: Vec<(String, String)>,
    value: SecretJson,
) -> Result<SecretJson, String> {
    headers.push(("content-type".into(), "application/json".into()));
    let body = serde_json::to_vec(&value.0).map_err(|_| "invalid provider request")?;
    request(env, "POST", url, headers, body).await
}
async fn credential(env: &Env, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
            .ok_or("relative credentials require CREDENTIALS_DIRECTORY")?;
        std::path::PathBuf::from(dir).join(path)
    };
    let f = env
        .fs
        .open(path, OpenMode::Read)
        .await
        .map_err(|_| "cannot open credential file")?;
    let len = f.len().await.map_err(|_| "cannot read credential file")?;
    if len == 0 || len > CAP as u64 {
        return Err("invalid credential file size".into());
    }
    let data = Zeroizing::new(
        f.read_at(0, len as usize)
            .await
            .map_err(|_| "cannot read credential file")?,
    );
    if data.len() != len as usize {
        return Err("incomplete credential file".into());
    }
    Ok(data)
}
async fn credential_text(env: &Env, p: &Path) -> Result<Zeroizing<String>, String> {
    let data = credential(env, p).await?;
    let s = std::str::from_utf8(&data).map_err(|_| "invalid credential encoding")?;
    let text = Zeroizing::new(s.trim().to_owned());
    if text.is_empty() {
        return Err("empty credential file".into());
    }
    Ok(text)
}
fn pem(data: &[u8], label: &str) -> Result<Vec<Vec<u8>>, String> {
    let s = std::str::from_utf8(data).map_err(|_| "invalid PEM encoding")?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = s;
    let mut out = Vec::new();
    while let Some((prefix, after)) = rest.split_once(&begin) {
        if !prefix.trim().is_empty() {
            return Err("unsupported PEM block".into());
        }
        let (body, next) = after.split_once(&end).ok_or("invalid PEM block")?;
        let encoded = Zeroizing::new(
            body.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        );
        out.push(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| "invalid PEM data")?,
        );
        rest = next;
    }
    if out.is_empty() || !rest.trim().is_empty() {
        return Err("unsupported PEM block".into());
    }
    Ok(out)
}
async fn tls_env(
    env: &Env,
    ca: Option<&Path>,
    identity: Option<(&Path, &Path)>,
) -> Result<Env, String> {
    if ca.is_none() && identity.is_none() {
        return Ok(env.clone());
    }
    let ca = if let Some(p) = ca {
        pem(&credential(env, p).await?, "CERTIFICATE")?
    } else {
        Vec::new()
    };
    let identity = if let Some((cert, key)) = identity {
        let chain = pem(&credential(env, cert).await?, "CERTIFICATE")?;
        let mut keys = pem(&credential(env, key).await?, "PRIVATE KEY")?;
        if keys.len() != 1 {
            for k in &mut keys {
                k.zeroize();
            }
            return Err("TLS identity requires one PKCS8 private key".into());
        }
        Some((chain, keys.remove(0)))
    } else {
        None
    };
    let mut scoped = env.clone();
    scoped.net = env
        .net
        .with_tls(TlsConfig { ca, identity })
        .map_err(|_| "provider TLS configuration failed")?;
    Ok(scoped)
}
fn envelope(cfg: &Keys, version: String, ciphertext: String, env: &Env) -> Result<Wrapped, String> {
    Ok(Wrapped {
        schema: SCHEMA.into(),
        source: cfg.source.as_str().into(),
        key: cfg.key_ref()?,
        key_version: version,
        ciphertext,
        aad: AAD.into(),
        created_wall_ms: env.clock.wall_ms(),
    })
}
pub(super) fn validate_wrapped(cfg: &Keys, wrapped: &Wrapped) -> Result<(), String> {
    cfg.check()?;
    if wrapped.schema != SCHEMA
        || wrapped.source != cfg.source.as_str()
        || wrapped.key != cfg.key_ref()?
        || wrapped.aad != AAD
        || wrapped.ciphertext.is_empty()
        || wrapped.ciphertext.len() > CAP
    {
        return Err("wrapped key does not match configured provider".into());
    }
    match cfg.source {
        Source::Openbao => {
            if !config::positive_version(&wrapped.key_version)
                || openbao::version(&wrapped.ciphertext)? != wrapped.key_version
            {
                return Err("invalid OpenBao key version".into());
            }
        }
        Source::Aws => {
            if wrapped.key_version != cfg.key_ref()? {
                return Err("invalid AWS key version".into());
            }
            decode(&wrapped.ciphertext)?;
        }
        Source::Gcp => {
            gcp::version(&cfg.key_ref()?, &wrapped.key_version)?;
            decode(&wrapped.ciphertext)?;
        }
        Source::Azure => {
            if !azure::valid_version(&wrapped.key_version) {
                return Err("invalid Azure key version".into());
            }
            URL_SAFE_NO_PAD
                .decode(&wrapped.ciphertext)
                .map_err(|_| "invalid Azure ciphertext encoding")?;
        }
        _ => return Err("source is not a KMS".into()),
    }
    Ok(())
}
pub(super) async fn encrypt(
    env: &Env,
    cfg: &Keys,
    seed: &[u8; 32],
    aad: &[u8],
) -> Result<Wrapped, String> {
    cfg.check()?;
    if aad != AAD.as_bytes() {
        return Err("invalid key purpose".into());
    }
    match cfg.source {
        Source::Openbao => openbao::encrypt(env, cfg, seed, aad).await,
        Source::Aws => aws::encrypt(env, cfg, seed, aad).await,
        Source::Gcp => gcp::encrypt(env, cfg, seed, aad).await,
        Source::Azure => azure::encrypt(env, cfg, seed).await,
        _ => Err("source is not a KMS".into()),
    }
}
pub(super) async fn decrypt(
    env: &Env,
    cfg: &Keys,
    wrapped: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    validate_wrapped(cfg, wrapped)?;
    let plain = match cfg.source {
        Source::Openbao => openbao::decrypt(env, cfg, wrapped).await,
        Source::Aws => aws::decrypt(env, cfg, wrapped).await,
        Source::Gcp => gcp::decrypt(env, cfg, wrapped).await,
        Source::Azure => azure::decrypt(env, cfg, wrapped).await,
        _ => Err("source is not a KMS".into()),
    }?;
    if plain.len() != 32 {
        return Err("provider returned invalid seed length".into());
    }
    Ok(plain)
}
fn decode(s: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    STANDARD
        .decode(s)
        .map(Zeroizing::new)
        .map_err(|_| "invalid provider base64".into())
}
fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        form.append_pair(k, v);
    }
    form.finish().into_bytes()
}
fn bearer(token: &str) -> Result<Vec<(String, String)>, String> {
    header_secret(token)?;
    Ok(vec![("authorization".into(), format!("Bearer {token}"))])
}

/// Invalid local credential configuration is not a transient KMS outage.
pub(super) async fn preflight(env: &Env, cfg: &Keys) -> Result<(), String> {
    if cfg.source == Source::Aws {
        for name in [
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        ] {
            if std::env::var_os(name).is_some() {
                return Err(format!("unsupported AWS credential source {name}"));
            }
        }
    }
    if let Some(file) = cfg
        .gcp
        .as_ref()
        .and_then(|c| c.service_account_file.as_deref())
    {
        let bytes = credential(env, file).await?;
        let account = SecretJson(
            serde_json::from_slice(&bytes).map_err(|_| "invalid GCP service account file")?,
        );
        match account.get("type").and_then(Value::as_str) {
            Some("service_account") => {}
            Some("external_account") => {
                return Err(
                    "GCP external_account/workload identity federation is not supported".into(),
                );
            }
            _ => return Err("GCP credentials must be a service_account file".into()),
        }
        if account
            .get("token_uri")
            .and_then(Value::as_str)
            .is_some_and(|uri| uri != "https://oauth2.googleapis.com/token")
        {
            return Err("unsupported GCP service-account token URI".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
