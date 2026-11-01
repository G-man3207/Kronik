use super::*;
use crate::secret_backend::BackendError;
use config::Aws;

mod secrets;
pub(crate) use secrets::Secrets;

struct Credentials {
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}
fn unsupported_source() -> Option<&'static str> {
    [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ]
    .into_iter()
    .find(|name| std::env::var_os(name).is_some())
}

fn env_value(name: &str) -> Result<Option<Zeroizing<String>>, BackendError> {
    match std::env::var(name) {
        Ok(s) => {
            let s = Zeroizing::new(s);
            header_secret(&s).map_err(|_| BackendError::Invalid)?;
            Ok(Some(s))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(BackendError::Invalid),
    }
}

fn http_status(status: u16) -> Result<(), BackendError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(BackendError::Denied),
        404 => Err(BackendError::NotFound),
        410 => Err(BackendError::VersionGone),
        408 | 425 | 429 | 500..=599 => Err(BackendError::Unavailable),
        _ => Err(BackendError::Invalid),
    }
}

async fn imds(
    env: &Env,
    method: &str,
    url: String,
    headers: Vec<(String, String)>,
    dispatch: Dispatch<'_>,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let (status, body) = request_raw(env, method, url, headers, vec![], CAP, dispatch).await?;
    http_status(status)?;
    Ok(body)
}

async fn credentials(
    env: &Env,
    c: &Aws,
    dispatch: Dispatch<'_>,
) -> Result<Credentials, BackendError> {
    dispatch.check()?;
    if unsupported_source().is_some() {
        return Err(BackendError::Invalid);
    }
    if c.auth != "imds" {
        let access = env_value("AWS_ACCESS_KEY_ID")?;
        let secret = env_value("AWS_SECRET_ACCESS_KEY")?;
        let token = env_value("AWS_SESSION_TOKEN")?;
        match (access, secret) {
            (Some(access), Some(secret)) => {
                return Ok(Credentials {
                    access,
                    secret,
                    token,
                });
            }
            (None, None) if token.is_none() && c.auth != "env" => {}
            _ => return Err(BackendError::Invalid),
        }
    }
    if std::env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        return Err(BackendError::Invalid);
    }
    let base = c
        .imds_endpoint
        .as_deref()
        .unwrap_or("http://169.254.169.254")
        .trim_end_matches('/');
    let token = imds(
        env,
        "PUT",
        format!("{base}/latest/api/token"),
        vec![("X-aws-ec2-metadata-token-ttl-seconds".into(), "60".into())],
        dispatch,
    )
    .await?;
    let token = std::str::from_utf8(&token).map_err(|_| BackendError::Invalid)?;
    header_secret(token).map_err(|_| BackendError::Invalid)?;
    let headers = vec![("X-aws-ec2-metadata-token".into(), token.to_owned())];
    let role = imds(
        env,
        "GET",
        format!("{base}/latest/meta-data/iam/security-credentials/"),
        headers.clone(),
        dispatch,
    )
    .await?;
    let role = std::str::from_utf8(&role)
        .map_err(|_| BackendError::Invalid)?
        .trim();
    if !config::segment(role) {
        return Err(BackendError::Invalid);
    }
    let body = imds(
        env,
        "GET",
        format!("{base}/latest/meta-data/iam/security-credentials/{role}"),
        headers,
        dispatch,
    )
    .await?;
    let r = SecretJson(serde_json::from_slice(&body).map_err(|_| BackendError::Invalid)?);
    match field(&r, "Code").map_err(|_| BackendError::Invalid)? {
        "Success" => {}
        "AssumeRoleUnauthorizedAccess" => return Err(BackendError::Denied),
        _ => return Err(BackendError::Unavailable),
    }
    let access = Zeroizing::new(
        field(&r, "AccessKeyId")
            .map_err(|_| BackendError::Invalid)?
            .to_owned(),
    );
    let secret = Zeroizing::new(
        field(&r, "SecretAccessKey")
            .map_err(|_| BackendError::Invalid)?
            .to_owned(),
    );
    let token = Zeroizing::new(
        field(&r, "Token")
            .map_err(|_| BackendError::Invalid)?
            .to_owned(),
    );
    header_secret(&access).map_err(|_| BackendError::Invalid)?;
    header_secret(&secret).map_err(|_| BackendError::Invalid)?;
    header_secret(&token).map_err(|_| BackendError::Invalid)?;
    Ok(Credentials {
        access,
        secret,
        token: Some(token),
    })
}
async fn kms(env: &Env, c: &Aws, operation: &str, value: SecretJson) -> Result<SecretJson, String> {
    let scoped = tls_env(env, c.ca_file.as_deref(), None, Dispatch::StartupBootstrap).await?;
    let env = &scoped;
    let creds = credentials(env, c, Dispatch::StartupBootstrap)
        .await
        .map_err(|error| error.to_string())?;
    let default_endpoint = if c.region.starts_with("cn-") {
        format!("https://kms.{}.amazonaws.com.cn", c.region)
    } else {
        format!("https://kms.{}.amazonaws.com", c.region)
    };
    let endpoint = c.endpoint.as_deref().unwrap_or(&default_endpoint);
    let url = config::endpoint(endpoint)?;
    let host = match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().ok_or("missing AWS host")?),
        None => url.host_str().ok_or("missing AWS host")?.into(),
    };
    let date = sigv4::timestamp(env.clock.wall_ms())?;
    let mut headers = vec![
        ("host".into(), host),
        ("x-amz-date".into(), date.clone()),
        ("x-amz-target".into(), format!("TrentService.{operation}")),
        ("content-type".into(), "application/x-amz-json-1.1".into()),
    ];
    if let Some(token) = &creds.token {
        headers.push(("x-amz-security-token".into(), token.to_string()));
    }
    let mut body = Zeroizing::new(serde_json::to_vec(&value.0).map_err(|_| "invalid AWS request")?);
    let authorization = sigv4::authorization(
        "POST",
        "/",
        "",
        &headers,
        &body,
        &creds.access,
        &creds.secret,
        &c.region,
        "kms",
        &date,
    )?;
    headers.push(("authorization".into(), authorization));
    request(
        env,
        "POST",
        url.to_string(),
        headers,
        std::mem::take(&mut *body),
    )
    .await
}
pub(super) async fn encrypt(
    env: &Env,
    cfg: &Keys,
    seed: &[u8; 32],
    aad: &[u8],
) -> Result<Wrapped, String> {
    let c = cfg.aws.as_ref().ok_or("missing AWS configuration")?;
    let seed = Zeroizing::new(STANDARD.encode(seed));
    let purpose = std::str::from_utf8(aad).map_err(|_| "invalid key purpose")?;
    let r = kms(
        env,
        c,
        "Encrypt",
        SecretJson(json!({"KeyId":c.key_id,"Plaintext":seed.as_str(),
        "EncryptionAlgorithm":"SYMMETRIC_DEFAULT","EncryptionContext":{"purpose":purpose}})),
    )
    .await?;
    if field(&r, "KeyId")? != c.key_id {
        return Err("AWS returned a different key".into());
    }
    let ciphertext = field(&r, "CiphertextBlob")?.to_owned();
    decode(&ciphertext)?;
    envelope(cfg, c.key_id.clone(), ciphertext, env)
}
pub(super) async fn decrypt(
    env: &Env,
    cfg: &Keys,
    w: &Wrapped,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let c = cfg.aws.as_ref().ok_or("missing AWS configuration")?;
    let r = kms(
        env,
        c,
        "Decrypt",
        SecretJson(json!({"KeyId":c.key_id,"CiphertextBlob":w.ciphertext,
        "EncryptionAlgorithm":"SYMMETRIC_DEFAULT","EncryptionContext":{"purpose":w.aad}})),
    )
    .await?;
    if field(&r, "KeyId")? != c.key_id {
        return Err("AWS returned a different key".into());
    }
    decode(field(&r, "Plaintext")?)
}
