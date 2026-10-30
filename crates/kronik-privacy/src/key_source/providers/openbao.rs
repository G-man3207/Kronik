use super::*;
use config::OpenBao;

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
async fn auth(env: &Env, c: &OpenBao) -> Result<(Env, Zeroizing<String>), String> {
    let identity = if c.auth == "cert" {
        Some((
            c.cert_file.as_deref().ok_or("missing TLS certificate")?,
            c.key_file.as_deref().ok_or("missing TLS key")?,
        ))
    } else {
        None
    };
    let env = tls_env(env, c.ca_file.as_deref(), identity).await?;
    let token = match c.auth.as_str() {
        "token" => {
            credential_text(&env, c.token_file.as_deref().ok_or("missing token file")?).await?
        }
        "approle" => {
            let role = credential_text(&env, c.role_id_file.as_deref().ok_or("missing role file")?)
                .await?;
            let secret = credential_text(
                &env,
                c.secret_id_file.as_deref().ok_or("missing secret file")?,
            )
            .await?;
            let path = c.auth_mount.as_deref().unwrap_or("approle");
            let r = json_request(
                &env,
                format!("{}/v1/auth/{path}/login", c.address.trim_end_matches('/')),
                vec![],
                SecretJson(json!({"role_id":role.as_str(),"secret_id":secret.as_str()})),
            )
            .await?;
            Zeroizing::new(field(&r["auth"], "client_token")?.to_owned())
        }
        "cert" => {
            let path = c.auth_mount.as_deref().unwrap_or("cert");
            let body = if let Some(role) = &c.role {
                json!({"name":role})
            } else {
                json!({})
            };
            let r = json_request(
                &env,
                format!("{}/v1/auth/{path}/login", c.address.trim_end_matches('/')),
                vec![],
                SecretJson(body),
            )
            .await?;
            Zeroizing::new(field(&r["auth"], "client_token")?.to_owned())
        }
        _ => return Err("unsupported OpenBao authentication".into()),
    };
    header_secret(&token)?;
    Ok((env, token))
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
