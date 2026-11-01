use super::*;
use config::OpenBao;
use crate::secret_backend::BackendError;

mod secrets;
pub(crate) use secrets::Secrets;

pub(super) fn version(cipher: &str) -> Result<String, String> {
    let mut p = cipher.split(':');
    if p.next() != Some("vault") {
        return Err("invalid OpenBao ciphertext".into());
    }
    let v = p
        .next()
        .and_then(|v| v.strip_prefix('v'))
        .ok_or("invalid OpenBao ciphertext")?;
    let body = p.next().ok_or("invalid OpenBao ciphertext")?;
    if !config::positive_version(v)
        || body.is_empty()
        || STANDARD.decode(body).is_err()
        || p.next().is_some()
    {
        return Err("invalid OpenBao ciphertext".into());
    }
    Ok(v.into())
}
struct Session {
    env: Env,
    token: Zeroizing<String>,
    renew_at: Duration,
    expires_at: Duration,
    renewable: bool,
}

fn lease(env: &Env, value: &Value) -> Result<(Duration, Duration, bool), BackendError> {
    let ttl = value.get("lease_duration").or_else(|| value.get("ttl"))
        .and_then(Value::as_u64).ok_or(BackendError::Invalid)?;
    let renewable = value.get("renewable").and_then(Value::as_bool)
        .ok_or(BackendError::Invalid)?;
    let now = env.clock.monotonic();
    Ok(if ttl == 0 {
        (Duration::MAX, Duration::MAX, false)
    } else {
        (now.saturating_add(Duration::from_secs((ttl / 2).max(1))),
         now.saturating_add(Duration::from_secs(ttl)), renewable)
    })
}

async fn login(env: &Env, c: &OpenBao, dispatch: Dispatch<'_>) -> Result<Session, BackendError> {
    dispatch.check()?;
    let identity = if c.auth == "cert" {
        Some((
            c.cert_file.as_deref().ok_or(BackendError::Invalid)?,
            c.key_file.as_deref().ok_or(BackendError::Invalid)?,
        ))
    } else {
        None
    };
    let env = dispatch.wait(tls_env(env, c.ca_file.as_deref(), identity, dispatch)).await?
        .map_err(|_| BackendError::Invalid)?;
    let (token, renew_at, expires_at, renewable) = match c.auth.as_str() {
        "token" => (
            dispatch.wait(credential_text(&env, c.token_file.as_deref().ok_or(BackendError::Invalid)?, dispatch))
                .await?.map_err(|_| BackendError::Invalid)?,
            Duration::MAX, Duration::MAX, false,
        ),
        "approle" | "cert" => {
            let body = if c.auth == "approle" {
                let role = dispatch.wait(credential_text(&env, c.role_id_file.as_deref().ok_or(BackendError::Invalid)?, dispatch))
                    .await?.map_err(|_| BackendError::Invalid)?;
                let secret = dispatch.wait(credential_text(&env, c.secret_id_file.as_deref().ok_or(BackendError::Invalid)?, dispatch))
                    .await?.map_err(|_| BackendError::Invalid)?;
                SecretJson(json!({"role_id":role.as_str(),"secret_id":secret.as_str()}))
            } else {
                SecretJson(c.role.as_ref().map_or_else(|| json!({}), |role| json!({"name":role})))
            };
            let path = c.auth_mount.as_deref().unwrap_or(&c.auth);
            let mut body = Zeroizing::new(serde_json::to_vec(&body.0).map_err(|_| BackendError::Invalid)?);
            let (status, bytes) = request_raw(
                &env, "POST",
                format!("{}/v1/auth/{path}/login", c.address.trim_end_matches('/')),
                vec![("content-type".into(), "application/json".into())], std::mem::take(&mut *body), CAP, dispatch,
            ).await?;
            match status {
                200..=299 => {}
                401 | 403 => return Err(BackendError::Denied),
                408 | 425 | 429 | 500..=599 => return Err(BackendError::Unavailable),
                _ => return Err(BackendError::Invalid),
            }
            let r = SecretJson(serde_json::from_slice(&bytes).map_err(|_| BackendError::Invalid)?);
            let token = Zeroizing::new(field(&r["auth"], "client_token")
                .map_err(|_| BackendError::Invalid)?.to_owned());
            // Transit does not retain sessions; secrets require lease metadata.
            let (renew_at, expires_at, renewable) = if r["auth"].get("lease_duration").is_some() {
                lease(&env, &r["auth"])?
            } else {
                (Duration::ZERO, Duration::ZERO, false)
            };
            (token, renew_at, expires_at, renewable)
        }
        _ => return Err(BackendError::Invalid),
    };
    header_secret(&token).map_err(|_| BackendError::Invalid)?;
    Ok(Session { env, token, renew_at, expires_at, renewable })
}

async fn auth(env: &Env, c: &OpenBao) -> Result<(Env, Zeroizing<String>), String> {
    let session = login(env, c, Dispatch::StartupBootstrap).await.map_err(|error| error.to_string())?;
    Ok((session.env, session.token))
}
pub(super) async fn encrypt(
    env: &Env,
    cfg: &Keys,
    seed: &[u8; 32],
    aad: &[u8],
) -> Result<Wrapped, String> {
    let c = cfg
        .openbao
        .as_ref()
        .ok_or("missing OpenBao configuration")?;
    let (net, token) = auth(env, c).await?;
    let plaintext = Zeroizing::new(STANDARD.encode(seed));
    let r = json_request(
        &net,
        format!(
            "{}/v1/{}/encrypt/{}",
            c.address.trim_end_matches('/'),
            c.mount,
            c.key
        ),
        vec![("X-Vault-Token".into(), token.to_string())],
        SecretJson(json!({"plaintext":plaintext.as_str(),"context":STANDARD.encode(aad)})),
    )
    .await?;
    let ciphertext = field(&r["data"], "ciphertext")?.to_owned();
    envelope(cfg, version(&ciphertext)?, ciphertext, env)
}
pub(super) async fn decrypt(
    env: &Env,
    cfg: &Keys,
    w: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let c = cfg
        .openbao
        .as_ref()
        .ok_or("missing OpenBao configuration")?;
    let (net, token) = auth(env, c).await?;
    let r = json_request(
        &net,
        format!(
            "{}/v1/{}/decrypt/{}",
            c.address.trim_end_matches('/'),
            c.mount,
            c.key
        ),
        vec![("X-Vault-Token".into(), token.to_string())],
        SecretJson(json!({"ciphertext":w.ciphertext,"context":STANDARD.encode(w.aad.as_bytes())})),
    )
    .await?;
    decode(field(&r["data"], "plaintext")?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transit_ciphertext_versions_are_canonical() {
        assert_eq!(version("vault:v12:YWJj").unwrap(), "12");
        for bad in [
            "vault:v0:YWJj",
            "vault:v01:YWJj",
            "https://evil/v1",
            "vault:v1:???",
            "vault:v1:YWJj:extra",
        ] {
            assert!(version(bad).is_err());
        }
    }
}
