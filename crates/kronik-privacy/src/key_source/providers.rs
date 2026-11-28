//! Small REST clients. Neither provider bodies nor credentials become diagnostics.
//! Ordinary secret operations retain their caller's lease through credentials,
//! token refresh and bounded collection; only fixed B1 startup uses unleased HTTP.
use std::ops::Deref;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Env, HttpRequest, OpenMode, TlsConfig};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use super::{
    Wrapped,
    config::{self, Keys, Source},
};
pub(crate) mod aws;
pub(crate) mod azure;
pub(crate) mod gcp;
pub(crate) mod openbao;
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
/// A pagination token a backend returned: not empty, at most `CAP` bytes,
/// no control byte. AWS has a stricter rule of its own.
fn page_token(value: &str) -> Result<(), crate::secret_backend::BackendError> {
    if value.is_empty() || value.len() > CAP || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(crate::secret_backend::BackendError::Invalid);
    }
    Ok(())
}
/// The `access_token` of an OAuth token response, checked to be usable as a header.
fn access_token(response: &Value) -> Result<Zeroizing<String>, String> {
    let token = Zeroizing::new(field(response, "access_token")?.to_owned());
    header_secret(&token)?;
    Ok(token)
}
fn secret_body(body: Vec<u8>) -> Bytes {
    Bytes::from_owner(Zeroizing::new(body))
}

// Bootstrap is confined to the fixed-cause B1 master-key callers below.
#[derive(Clone, Copy)]
enum Dispatch<'a> {
    StartupBootstrap,
    Authorized(&'a AuthLease),
}
impl Dispatch<'_> {
    fn check(self) -> Result<(), crate::secret_backend::BackendError> {
        match self {
            Self::StartupBootstrap => Ok(()),
            Self::Authorized(original) => original
                .check()
                .map_err(|_| crate::secret_backend::BackendError::Unauthorized),
        }
    }

    async fn wait<T>(
        self,
        future: impl Future<Output = T>,
    ) -> Result<T, crate::secret_backend::BackendError> {
        self.check()?;
        let result = match self {
            Self::StartupBootstrap => future.await,
            Self::Authorized(original) => tokio::select! {
                biased;
                () = original.cancelled() => return Err(crate::secret_backend::BackendError::Unauthorized),
                result = future => result,
            },
        };
        self.check()?;
        Ok(result)
    }
}
async fn request_raw(
    env: &Env,
    method: &str,
    url: String,
    mut headers: Vec<(String, String)>,
    body: Vec<u8>,
    cap: usize,
    dispatch: Dispatch<'_>,
) -> Result<(u16, Zeroizing<Vec<u8>>), crate::secret_backend::BackendError> {
    use crate::secret_backend::BackendError;
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
    if size > cap {
        for (_, value) in &mut headers {
            value.zeroize();
        }
        return Err(BackendError::Invalid);
    }
    let req = HttpRequest {
        method: method.into(),
        url,
        headers,
        body: secret_body(std::mem::take(&mut *body)),
        max_response_bytes: cap as u64,
    };
    dispatch
        .wait(async {
            env.timeout(REQUEST_TIMEOUT, async {
                let response = match dispatch {
                    Dispatch::StartupBootstrap => env.net.http(req).await,
                    Dispatch::Authorized(original) => {
                        env.net.http_authorized(req, original.clone()).await
                    }
                }
                .map_err(|error| match error {
                    kronik_core::env::NetError::TooLarge => BackendError::Invalid,
                    _ => BackendError::Unavailable,
                })?;
                dispatch.check()?;
                let status = response.status;
                let data = Zeroizing::new(Vec::<u8>::from(response.body));
                if data.len() > cap {
                    return Err(BackendError::Invalid);
                }
                Ok((status, data))
            })
            .await
            .map_err(|_| BackendError::Unavailable)?
        })
        .await?
}

async fn request(
    env: &Env,
    method: &str,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<SecretJson, String> {
    let (status, data) = request_raw(
        env,
        method,
        url,
        headers,
        body,
        CAP,
        Dispatch::StartupBootstrap,
    )
    .await
    .map_err(|error| error.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("provider returned HTTP {status}"));
    }
    serde_json::from_slice(&data)
        .map(SecretJson)
        .map_err(|_| "invalid provider JSON response".into())
}

fn http_status(status: u16) -> Result<(), crate::secret_backend::BackendError> {
    use crate::secret_backend::BackendError;
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(BackendError::Denied),
        404 => Err(BackendError::NotFound),
        410 => Err(BackendError::VersionGone),
        408 | 425 | 429 | 500..=599 => Err(BackendError::Unavailable),
        _ => Err(BackendError::Invalid),
    }
}
// Secret services expose larger payloads/catalogues than a 32-byte KMS operation.
// Exceeding this bound is incomplete coverage, never a successful truncated page.
const SECRET_RESPONSE_CAP: usize = 32 * 1024 * 1024;

async fn secret_request(
    env: &Env,
    method: &str,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    dispatch: Dispatch<'_>,
) -> Result<SecretJson, crate::secret_backend::BackendError> {
    use crate::secret_backend::BackendError;
    let (status, data) = request_raw(
        env,
        method,
        url,
        headers,
        body,
        SECRET_RESPONSE_CAP,
        dispatch,
    )
    .await?;
    http_status(status)?;
    serde_json::from_slice(&data)
        .map(SecretJson)
        .map_err(|_| BackendError::Invalid)
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
async fn credential(
    env: &Env,
    path: &Path,
    dispatch: Dispatch<'_>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    dispatch
        .wait(async {
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
            dispatch.check().map_err(|error| error.to_string())?;
            let len = f.len().await.map_err(|_| "cannot read credential file")?;
            if len == 0 || len > CAP as u64 {
                return Err("invalid credential file size".into());
            }
            dispatch.check().map_err(|error| error.to_string())?;
            let data = Zeroizing::new(
                f.read_at(0, len as usize)
                    .await
                    .map_err(|_| "cannot read credential file")?,
            );
            if data.len() != len as usize {
                return Err("incomplete credential file".into());
            }
            Ok(data)
        })
        .await
        .map_err(|error| error.to_string())?
}
async fn credential_text(
    env: &Env,
    p: &Path,
    dispatch: Dispatch<'_>,
) -> Result<Zeroizing<String>, String> {
    let data = credential(env, p, dispatch).await?;
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
/// A provider's standard-base64 secret value of at most 64 KiB, in a
/// buffer wiped on drop, also when decoding fails half-way. `STANDARD`
/// requires canonical padding and zero trailing bits, so a value has
/// exactly one accepted encoding; any other text gives `None`.
fn secret_base64(encoded: &str) -> Option<Zeroizing<Vec<u8>>> {
    if encoded.len() > 65_536_usize.div_ceil(3) * 4 {
        return None;
    }
    let mut value = Zeroizing::new(vec![0; base64::decoded_len_estimate(encoded.len())]);
    let len = STANDARD.decode_slice(encoded, &mut value).ok()?;
    if len > 65_536 {
        return None;
    }
    value.truncate(len);
    Some(value)
}
async fn tls_env(
    env: &Env,
    ca: Option<&Path>,
    identity: Option<(&Path, &Path)>,
    dispatch: Dispatch<'_>,
) -> Result<Env, String> {
    dispatch.check().map_err(|error| error.to_string())?;
    if ca.is_none() && identity.is_none() {
        return Ok(env.clone());
    }
    let ca = if let Some(p) = ca {
        pem(&credential(env, p, dispatch).await?, "CERTIFICATE")?
    } else {
        Vec::new()
    };
    let identity = if let Some((cert, key)) = identity {
        let chain = pem(&credential(env, cert, dispatch).await?, "CERTIFICATE")?;
        let mut keys = pem(&credential(env, key, dispatch).await?, "PRIVATE KEY")?;
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
        Source::Pkcs11 => {
            super::pkcs11::validate_wrapped(cfg.pkcs11.as_ref().ok_or("PKCS11_CONFIG")?, wrapped)?
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
        Source::Pkcs11 => {
            super::pkcs11::encrypt(env, cfg.pkcs11.as_ref().ok_or("PKCS11_CONFIG")?, seed, aad)
                .await
        }
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
        Source::Pkcs11 => {
            super::pkcs11::decrypt(env, cfg.pkcs11.as_ref().ok_or("PKCS11_CONFIG")?, wrapped).await
        }
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

/// One bearer-token cache per provider: TLS scoping, expiry, admission and
/// denial invalidation are shared; only the auth request and the `expires_in`
/// spelling differ between the Azure and GCP backends.
struct BearerCache(Mutex<Option<(Zeroizing<String>, Duration)>>);

impl BearerCache {
    fn new() -> Self {
        Self(Mutex::new(None))
    }

    // A refused admission means the caller's authority ended mid-authentication,
    // not that the secret was denied, so every provider answers Unauthorized.
    async fn token<'a>(
        &self,
        net: &Env,
        original: &'a AuthLease,
        auth: impl FnOnce(Env) -> BoxFuture<'a, Result<SecretJson, crate::secret_backend::BackendError>>,
        expires_in: fn(&Value) -> Option<u64>,
    ) -> Result<Zeroizing<String>, crate::secret_backend::BackendError> {
        use crate::secret_backend::BackendError;
        original.check().map_err(|_| BackendError::Unauthorized)?;
        let now = net.clock.monotonic();
        {
            let cache = self.0.lock().map_err(|_| BackendError::Invalid)?;
            if let Some((token, expires)) = &*cache
                && now < *expires
            {
                return Ok(Zeroizing::new(token.to_string()));
            }
        }
        let response = auth(net.clone()).await?;
        let token = access_token(&response).map_err(|_| BackendError::Invalid)?;
        let seconds = expires_in(&response)
            .filter(|seconds| *seconds > 0)
            .ok_or(BackendError::Invalid)?;
        let expires = now
            .checked_add(Duration::from_secs(seconds.saturating_sub(30)))
            .ok_or(BackendError::Invalid)?;
        let mut cache = self.0.lock().map_err(|_| BackendError::Invalid)?;
        original
            .admit(&mut || {
                *cache = Some((token.clone(), expires));
                Ok(())
            })
            .map_err(|_| BackendError::Unauthorized)?;
        Ok(token)
    }

    async fn get<'a>(
        &self,
        env: &'a Env,
        ca: Option<&'a Path>,
        url: String,
        original: &'a AuthLease,
        auth: impl FnOnce(Env) -> BoxFuture<'a, Result<SecretJson, crate::secret_backend::BackendError>>,
        expires_in: fn(&Value) -> Option<u64>,
    ) -> Result<SecretJson, crate::secret_backend::BackendError> {
        use crate::secret_backend::BackendError;
        let dispatch = Dispatch::Authorized(original);
        let net = dispatch
            .wait(tls_env(env, ca, None, dispatch))
            .await?
            .map_err(|_| BackendError::Invalid)?;
        let token = self.token(&net, original, auth, expires_in).await?;
        let result = secret_request(
            &net,
            "GET",
            url,
            bearer(&token).map_err(|_| BackendError::Invalid)?,
            vec![],
            dispatch,
        )
        .await;
        if matches!(result, Err(BackendError::Denied)) {
            *self.0.lock().map_err(|_| BackendError::Invalid)? = None;
        }
        result
    }
}

/// Invalid local credential configuration is not a transient KMS outage.
pub(crate) async fn preflight(env: &Env, cfg: &Keys) -> Result<(), String> {
    if cfg.source == Source::Pkcs11 {
        if !cfg!(target_os = "linux") {
            return Err("PKCS11_UNSUPPORTED_PLATFORM".into());
        }
        super::pkcs11::check(cfg.pkcs11.as_ref().ok_or("PKCS11_CONFIG")?, true)?;
    }
    if cfg.source == Source::Aws
        && let Some(name) = aws::unsupported_source()
    {
        return Err(format!("unsupported AWS credential source {name}"));
    }
    if let Some(file) = cfg
        .gcp
        .as_ref()
        .and_then(|c| c.service_account_file.as_deref())
    {
        let bytes = credential(env, file, Dispatch::StartupBootstrap).await?;
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
#[cfg(test)]
pub(crate) use tests::NoNetwork;

#[cfg(test)]
mod authorized_tests;
#[cfg(test)]
pub(crate) use authorized_tests::test_authority;
