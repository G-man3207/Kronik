use super::*;
use config::Aws;

struct Credentials {
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}
fn env_value(name: &str) -> Result<Option<Zeroizing<String>>, String> {
    match std::env::var(name) {
        Ok(s) => {
            header_secret(&s)?;
            Ok(Some(Zeroizing::new(s)))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err("invalid AWS environment credential".into()),
    }
}
async fn credentials(env: &Env, c: &Aws) -> Result<Credentials, String> {
    for unsupported in [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ] {
        if std::env::var_os(unsupported).is_some() {
            return Err(format!("unsupported AWS credential source: {unsupported}"));
        }
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
            _ => return Err("AWS environment credentials are missing or incomplete".into()),
        }
    }
    if std::env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        return Err("AWS IMDSv2 disabled".into());
    }
    let base = c
        .imds_endpoint
        .as_deref()
        .unwrap_or("http://169.254.169.254")
        .trim_end_matches('/');
    let token = request_bytes(
        env,
        "PUT",
        format!("{base}/latest/api/token"),
        vec![("X-aws-ec2-metadata-token-ttl-seconds".into(), "60".into())],
        vec![],
    )
    .await?;
    let token = std::str::from_utf8(&token).map_err(|_| "invalid AWS IMDSv2 token")?;
    header_secret(token)?;
    let headers = vec![("X-aws-ec2-metadata-token".into(), token.to_owned())];
    let role = request_bytes(
        env,
        "GET",
        format!("{base}/latest/meta-data/iam/security-credentials/"),
        headers.clone(),
        vec![],
    )
    .await?;
    let role = std::str::from_utf8(&role)
        .map_err(|_| "invalid AWS role response")?
        .trim();
    if !config::segment(role) {
        return Err("invalid AWS instance role".into());
    }
    let r = request(
        env,
        "GET",
        format!("{base}/latest/meta-data/iam/security-credentials/{role}"),
        headers,
        vec![],
    )
    .await?;
    if field(&r, "Code")? != "Success" {
        return Err("AWS IMDSv2 credentials unavailable".into());
    }
    let access = Zeroizing::new(field(&r, "AccessKeyId")?.to_owned());
    let secret = Zeroizing::new(field(&r, "SecretAccessKey")?.to_owned());
    let token = Zeroizing::new(field(&r, "Token")?.to_owned());
    header_secret(&access)?;
    header_secret(&secret)?;
    header_secret(&token)?;
    Ok(Credentials {
        access,
        secret,
        token: Some(token),
    })
}
async fn kms(env: &Env, c: &Aws, operation: &str, value: SecretJson) -> Result<SecretJson, String> {
    let scoped = tls_env(env, c.ca_file.as_deref(), None).await?;
    let env = &scoped;
    let creds = credentials(env, c).await?;
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
