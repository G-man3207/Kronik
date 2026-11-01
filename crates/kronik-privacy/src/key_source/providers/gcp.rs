use super::*;
use config::Gcp;
const OAUTH: &str = "https://oauth2.googleapis.com/token";

pub(super) fn version<'a>(key: &str, name: &'a str) -> Result<&'a str, String> {
    let suffix = name
        .strip_prefix(key)
        .and_then(|s| s.strip_prefix("/cryptoKeyVersions/"))
        .ok_or("GCP returned a different key")?;
    if !config::positive_version(suffix) {
        return Err("invalid GCP key version".into());
    }
    Ok(suffix)
}
async fn auth_response(
    env: &Env,
    c: &Gcp,
    scope: &str,
    dispatch: Dispatch<'_>,
) -> Result<SecretJson, crate::secret_backend::BackendError> {
    use crate::secret_backend::BackendError::Invalid;
    dispatch.check()?;
    if let Some(file) = &c.service_account_file {
        let bytes = dispatch
            .wait(credential(env, file, dispatch))
            .await?
            .map_err(|_| Invalid)?;
        let account = SecretJson(serde_json::from_slice(&bytes).map_err(|_| Invalid)?);
        if field(&account, "type").map_err(|_| Invalid)? != "service_account" {
            return Err(Invalid);
        }
        let email = field(&account, "client_email").map_err(|_| Invalid)?;
        if !email.contains('@') || email.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
            return Err(Invalid);
        }
        // The credential file cannot redirect a signed assertion to a different service.
        if account
            .get("token_uri")
            .and_then(Value::as_str)
            .is_some_and(|s| s != OAUTH)
        {
            return Err(Invalid);
        }
        let mut keys = pem(
            field(&account, "private_key")
                .map_err(|_| Invalid)?
                .as_bytes(),
            "PRIVATE KEY",
        )
        .map_err(|_| Invalid)?;
        if keys.len() != 1 {
            for key in &mut keys {
                key.zeroize();
            }
            return Err(Invalid);
        }
        let pkcs8 = Zeroizing::new(keys.remove(0));
        let now = env.clock.wall_ms() / 1000;
        let expires = now.checked_add(3600).ok_or(Invalid)?;
        let token_url = c.token_endpoint.as_deref().unwrap_or(OAUTH);
        let claims = SecretJson(json!({
            "iss":email,"scope":scope,"aud":token_url,"iat":now,"exp":expires
        }));
        let header = json!({"alg":"RS256","typ":"JWT"});
        let encoded_claims = Zeroizing::new(serde_json::to_vec(&claims.0).map_err(|_| Invalid)?);
        let mut assertion = Zeroizing::new(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| Invalid)?),
            URL_SAFE_NO_PAD.encode(&encoded_claims)
        ));
        let signature = Zeroizing::new(
            env.entropy
                .sign_rs256(&pkcs8, assertion.as_bytes())
                .map_err(|_| Invalid)?,
        );
        assertion.push('.');
        assertion.push_str(&URL_SAFE_NO_PAD.encode(&signature));
        secret_request(
            env,
            "POST",
            token_url.into(),
            vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ]),
            dispatch,
        )
        .await
    } else {
        secret_request(
            env,
            "GET",
            c.metadata_endpoint.as_deref().unwrap_or("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token").into(),
            vec![("Metadata-Flavor".into(), "Google".into())],
            vec![],
            dispatch,
        )
        .await
    }
}
async fn auth(env: &Env, c: &Gcp) -> Result<Zeroizing<String>, String> {
    let response = auth_response(
        env,
        c,
        "https://www.googleapis.com/auth/cloudkms",
        Dispatch::StartupBootstrap,
    )
    .await
    .map_err(|error| error.to_string())?;
    let token = Zeroizing::new(field(&response, "access_token")?.to_owned());
    header_secret(&token)?;
    Ok(token)
}
async fn kms(env: &Env, c: &Gcp, operation: &str, body: SecretJson) -> Result<SecretJson, String> {
    let net = tls_env(env, c.ca_file.as_deref(), None, Dispatch::StartupBootstrap).await?;
    let token = auth(&net, c).await?;
    let base = c
        .endpoint
        .as_deref()
        .unwrap_or("https://cloudkms.googleapis.com")
        .trim_end_matches('/');
    json_request(
        &net,
        format!("{base}/v1/{}:{operation}", c.key),
        bearer(&token)?,
        body,
    )
    .await
}
pub(super) async fn encrypt(
    env: &Env,
    cfg: &Keys,
    seed: &[u8; 32],
    aad: &[u8],
) -> Result<Wrapped, String> {
    let c = cfg.gcp.as_ref().ok_or("missing GCP configuration")?;
    let seed = Zeroizing::new(STANDARD.encode(seed));
    let r = kms(
        env,
        c,
        "encrypt",
        SecretJson(
            json!({"plaintext":seed.as_str(),"additionalAuthenticatedData":STANDARD.encode(aad)}),
        ),
    )
    .await?;
    let name = field(&r, "name")?;
    version(&c.key, name)?;
    let ciphertext = field(&r, "ciphertext")?.to_owned();
    decode(&ciphertext)?;
    envelope(cfg, name.to_owned(), ciphertext, env)
}
pub(super) async fn decrypt(
    env: &Env,
    cfg: &Keys,
    w: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let c = cfg.gcp.as_ref().ok_or("missing GCP configuration")?;
    version(&c.key, &w.key_version)?;
    // Symmetric KMS decrypt takes the CryptoKey; its ciphertext identifies the immutable version.
    let r = kms(env,c,"decrypt",SecretJson(json!({"ciphertext":w.ciphertext,"additionalAuthenticatedData":STANDARD.encode(w.aad.as_bytes())}))).await?;
    decode(field(&r, "plaintext")?)
}

mod secrets;
pub(crate) use secrets::Secrets;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_cannot_change_key_or_endpoint() {
        let key = "projects/p/locations/l/keyRings/r/cryptoKeys/k";
        assert_eq!(
            version(key, &format!("{key}/cryptoKeyVersions/2")).unwrap(),
            "2"
        );
        for suffix in [
            "/cryptoKeyVersions/0",
            "/cryptoKeyVersions/01",
            "/cryptoKeyVersions/2:decrypt",
            "/cryptoKeyVersions/../2",
        ] {
            assert!(version(key, &format!("{key}{suffix}")).is_err());
        }
        assert!(version(key, "https://attacker/cryptoKeyVersions/2").is_err());
    }
}
