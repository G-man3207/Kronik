use super::*;
use config::Azure;

pub(super) fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
fn kid_version<'a>(c: &Azure, kid: &'a str) -> Result<&'a str, String> {
    let v = kid
        .strip_prefix(&c.key)
        .and_then(|s| s.strip_prefix('/'))
        .ok_or("Azure returned a different key")?;
    if !valid_version(v) {
        return Err("invalid Azure key version".into());
    }
    Ok(v)
}
async fn auth_response(
    env: &Env,
    c: &Azure,
    dispatch: Dispatch<'_>,
) -> Result<SecretJson, crate::secret_backend::BackendError> {
    use crate::secret_backend::BackendError::Invalid;
    dispatch.check()?;
    if let Some(p) = &c.client_secret_file {
        let secret = dispatch.wait(credential_text(env, p, dispatch)).await?.map_err(|_| Invalid)?;
        let tenant = c.tenant_id.as_deref().ok_or(Invalid)?;
        let client = c.client_id.as_deref().ok_or(Invalid)?;
        let authority = c
            .authority_endpoint
            .as_deref()
            .unwrap_or("https://login.microsoftonline.com")
            .trim_end_matches('/');
        secret_request(
            env,
            "POST",
            format!("{authority}/{tenant}/oauth2/v2.0/token"),
            vec![("content-type".into(), "application/x-www-form-urlencoded".into())],
            form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client),
                ("client_secret", secret.as_str()),
                ("scope", "https://vault.azure.net/.default"),
            ]),
            dispatch,
        )
        .await
    } else {
        let base = c
            .metadata_endpoint
            .as_deref()
            .unwrap_or("http://169.254.169.254/metadata/identity/oauth2/token");
        let mut u = url::Url::parse(base).map_err(|_| Invalid)?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("api-version", "2018-02-01")
                .append_pair("resource", "https://vault.azure.net");
            if let Some(client) = &c.client_id {
                q.append_pair("client_id", client);
            }
        }
        secret_request(
            env,
            "GET",
            u.into(),
            vec![("Metadata".into(), "true".into())],
            vec![],
            dispatch,
        )
        .await
    }
}
async fn auth(env: &Env, c: &Azure) -> Result<Zeroizing<String>, String> {
    let response = auth_response(env, c, Dispatch::StartupBootstrap).await.map_err(|error| error.to_string())?;
    let token = Zeroizing::new(field(&response, "access_token")?.to_owned());
    header_secret(&token)?;
    Ok(token)
}
async fn wrap(
    env: &Env,
    c: &Azure,
    token: &str,
    version: &str,
    operation: &str,
    value: &str,
) -> Result<SecretJson, String> {
    if !valid_version(version) {
        return Err("invalid Azure key version".into());
    }
    let r = json_request(
        env,
        format!("{}/{version}/{operation}?api-version=7.4", c.key),
        bearer(token)?,
        SecretJson(json!({"alg":"RSA-OAEP-256","value":value})),
    )
    .await?;
    if kid_version(c, field(&r, "kid")?)? != version {
        return Err("Azure returned a different key version".into());
    }
    Ok(r)
}
pub(super) async fn encrypt(env: &Env, cfg: &Keys, seed: &[u8; 32]) -> Result<Wrapped, String> {
    let c = cfg.azure.as_ref().ok_or("missing Azure configuration")?;
    let net = tls_env(env, c.ca_file.as_deref(), None, Dispatch::StartupBootstrap).await?;
    let token = auth(&net, c).await?;
    let key = request(
        &net,
        "GET",
        format!("{}?api-version=7.4", c.key),
        bearer(&token)?,
        vec![],
    )
    .await?;
    let version = kid_version(c, field(&key["key"], "kid")?)?;
    let plaintext = Zeroizing::new(URL_SAFE_NO_PAD.encode(seed));
    let r = wrap(&net, c, &token, version, "wrapkey", &plaintext).await?;
    let cipher = field(&r, "value")?.to_owned();
    URL_SAFE_NO_PAD
        .decode(&cipher)
        .map_err(|_| "invalid Azure ciphertext encoding")?;
    envelope(cfg, version.into(), cipher, env)
}
pub(super) async fn decrypt(
    env: &Env,
    cfg: &Keys,
    w: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let c = cfg.azure.as_ref().ok_or("missing Azure configuration")?;
    let net = tls_env(env, c.ca_file.as_deref(), None, Dispatch::StartupBootstrap).await?;
    let token = auth(&net, c).await?;
    let r = wrap(&net, c, &token, &w.key_version, "unwrapkey", &w.ciphertext).await?;
    URL_SAFE_NO_PAD
        .decode(field(&r, "value")?)
        .map(Zeroizing::new)
        .map_err(|_| "invalid Azure plaintext encoding".into())
}

mod secrets;
pub(crate) use secrets::Secrets;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_are_not_provider_targets() {
        let c = Azure {
            key: "https://v.vault.azure.net/keys/k".into(),
            ..Azure::default()
        };
        assert_eq!(
            kid_version(&c, "https://v.vault.azure.net/keys/k/0123ab").unwrap(),
            "0123ab"
        );
        for bad in ["../wrapkey", "https://evil", "v?api-version=1", "", "."] {
            assert!(!valid_version(bad));
        }
        assert!(kid_version(&c, "https://evil/keys/k/v1").is_err());
        assert!(kid_version(&c, "https://v.vault.azure.net/keys/k2/v1").is_err());
    }
}
