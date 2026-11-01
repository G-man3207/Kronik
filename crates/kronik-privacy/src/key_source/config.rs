//! Checked KMS configuration. Credentials are paths, never inline values.
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    #[default]
    File,
    Env,
    Openbao,
    Aws,
    Gcp,
    Azure,
    Pkcs11,
}
impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Env => "env",
            Self::Openbao => "openbao",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::Pkcs11 => "pkcs11",
        }
    }
    pub fn is_kms(self) -> bool {
        !matches!(self, Self::File | Self::Env)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Keys {
    pub source: Source,
    pub master_key_file: Option<PathBuf>,
    pub wrapped_file: PathBuf,
    pub start_timeout: String,
    pub openbao: Option<OpenBao>,
    pub aws: Option<Aws>,
    pub gcp: Option<Gcp>,
    pub azure: Option<Azure>,
    pub pkcs11: Option<Pkcs11>,
}
impl Default for Keys {
    fn default() -> Self {
        Self {
            source: Source::File,
            master_key_file: None,
            wrapped_file: "keys/master.wrapped".into(),
            start_timeout: "60s".into(),
            openbao: None,
            aws: None,
            gcp: None,
            azure: None,
            pkcs11: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OpenBao {
    pub address: String,
    pub mount: String,
    pub key: String,
    pub auth: String,
    pub token_file: Option<PathBuf>,
    pub role_id_file: Option<PathBuf>,
    pub secret_id_file: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    pub auth_mount: Option<String>,
    pub role: Option<String>,
}
impl Default for OpenBao {
    fn default() -> Self {
        Self {
            address: String::new(),
            mount: "transit".into(),
            key: String::new(),
            auth: "token".into(),
            token_file: None,
            role_id_file: None,
            secret_id_file: None,
            cert_file: None,
            key_file: None,
            ca_file: None,
            auth_mount: None,
            role: None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Aws {
    pub region: String,
    pub key_id: String,
    pub endpoint: Option<String>,
    pub auth: String,
    pub imds_endpoint: Option<String>,
    pub ca_file: Option<PathBuf>,
}
impl Default for Aws {
    fn default() -> Self {
        Self {
            region: String::new(),
            key_id: String::new(),
            endpoint: None,
            auth: "auto".into(),
            imds_endpoint: None,
            ca_file: None,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Gcp {
    pub key: String,
    pub service_account_file: Option<PathBuf>,
    pub endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub metadata_endpoint: Option<String>,
    pub ca_file: Option<PathBuf>,
}
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Azure {
    pub key: String,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_file: Option<PathBuf>,
    pub authority_endpoint: Option<String>,
    pub metadata_endpoint: Option<String>,
    pub ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pkcs11 {
    pub helper_path: PathBuf,
    pub module: PathBuf,
    pub module_sha256: String,
    pub pin_file: PathBuf,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub key_id: String,
    pub key_version: String,
    pub probe: Option<Probe>,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub nonce: String,
    pub ciphertext: String,
}

pub(super) fn segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}
pub(super) fn positive_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|c| c.is_ascii_digit())
        && s.parse::<u64>().is_ok_and(|n| n > 0 && n.to_string() == s)
}
pub(crate) fn endpoint(s: &str) -> Result<Url, String> {
    let u = Url::parse(s).map_err(|_| "invalid provider endpoint".to_owned())?;
    let loopback = u.host_str().is_some_and(|h| {
        h == "localhost"
            || h.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_loopback())
    });
    if !matches!(u.scheme(), "https" | "http")
        || (u.scheme() == "http" && !loopback)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || !matches!(u.path(), "" | "/")
    {
        return Err(
            "provider endpoint must be HTTPS (HTTP only on loopback), without path or credentials"
                .into(),
        );
    }
    Ok(u)
}
fn path(p: &Path) -> Result<(), String> {
    if p.as_os_str().is_empty() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("invalid credential path".into());
    }
    Ok(())
}
pub(super) fn local_auth_endpoint(s: &str, origin_only: bool) -> Result<(), String> {
    let u = Url::parse(s).map_err(|_| "invalid local auth endpoint")?;
    let host = u.host_str().ok_or("invalid local auth endpoint")?;
    let local = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback());
    if !local
        || !matches!(u.scheme(), "http" | "https")
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || (origin_only && !matches!(u.path(), "" | "/"))
    {
        return Err(
            "auth endpoint overrides must be loopback URLs without credentials or query".into(),
        );
    }
    Ok(())
}
impl Keys {
    pub fn start_timeout(&self) -> Result<Duration, String> {
        let (value, scale) = if let Some(v) = self.start_timeout.strip_suffix("ms") {
            (v, 1)
        } else if let Some(v) = self.start_timeout.strip_suffix('s') {
            (v, 1000)
        } else if let Some(v) = self.start_timeout.strip_suffix('m') {
            (v, 60_000)
        } else {
            return Err("keys.start_timeout requires ms, s or m".into());
        };
        let ms = value
            .parse::<u64>()
            .ok()
            .and_then(|v| v.checked_mul(scale))
            .filter(|v| *v > 0)
            .ok_or("invalid keys.start_timeout")?;
        Ok(Duration::from_millis(ms))
    }
    pub fn check(&self) -> Result<(), String> {
        self.check_with_probe(true)
    }
    pub fn check_pkcs11_enrollment(&self) -> Result<(), String> {
        if self.source != Source::Pkcs11 {
            return Err("PKCS11_CONFIG".into());
        }
        self.check_with_probe(false)
    }
    fn check_with_probe(&self, require_probe: bool) -> Result<(), String> {
        self.start_timeout()?;
        if self.wrapped_file.as_os_str().is_empty()
            || self
                .wrapped_file
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("wrapped_file must be a relative path without . or ..".into());
        }
        for (source, present) in [
            (Source::Openbao, self.openbao.is_some()),
            (Source::Aws, self.aws.is_some()),
            (Source::Gcp, self.gcp.is_some()),
            (Source::Azure, self.azure.is_some()),
            (Source::Pkcs11, self.pkcs11.is_some()),
        ] {
            if present != (self.source == source) {
                return Err("keys provider configuration must match source".into());
            }
        }
        if self.source.is_kms() && self.master_key_file.is_some() {
            return Err("master_key_file cannot be used with KMS".into());
        }
        if let Some(c) = &self.openbao {
            endpoint(&c.address)?;
            if !segment(&c.mount)
                || !segment(&c.key)
                || c.auth_mount.as_ref().is_some_and(|s| !segment(s))
                || c.role.as_ref().is_some_and(|s| !segment(s))
            {
                return Err("invalid OpenBao mount, key or role".into());
            }
            let token = c.token_file.is_some();
            let approle = c.role_id_file.is_some() && c.secret_id_file.is_some();
            let cert = c.cert_file.is_some() && c.key_file.is_some();
            let valid = match c.auth.as_str() {
                "token" => {
                    token
                        && !approle
                        && !cert
                        && c.role_id_file.is_none()
                        && c.secret_id_file.is_none()
                        && c.cert_file.is_none()
                        && c.key_file.is_none()
                        && c.role.is_none()
                        && c.auth_mount.is_none()
                }
                "approle" => {
                    approle
                        && !token
                        && c.cert_file.is_none()
                        && c.key_file.is_none()
                        && c.role.is_none()
                }
                "cert" => cert && !token && c.role_id_file.is_none() && c.secret_id_file.is_none(),
                _ => false,
            };
            if !valid {
                return Err(
                    "OpenBao requires exactly one supported auth method: token, approle or cert"
                        .into(),
                );
            }
            for p in [
                &c.token_file,
                &c.role_id_file,
                &c.secret_id_file,
                &c.cert_file,
                &c.key_file,
                &c.ca_file,
            ]
            .into_iter()
            .flatten()
            {
                path(p)?;
            }
        }
        if let Some(c) = &self.aws {
            if !segment(&c.region) || !matches!(c.auth.as_str(), "auto" | "env" | "imds") {
                return Err("AWS supports only environment credentials or IMDSv2".into());
            }
            if let Some(e) = &c.endpoint {
                endpoint(e)?;
            }
            if let Some(e) = &c.imds_endpoint {
                local_auth_endpoint(e, true)?;
            }
            if let Some(p) = &c.ca_file {
                path(p)?;
            }
            aws_key(&c.key_id, &c.region)?;
        }
        if let Some(c) = &self.gcp {
            let p: Vec<_> = c.key.split('/').collect();
            if p.len() != 8
                || p[0] != "projects"
                || p[2] != "locations"
                || p[4] != "keyRings"
                || p[6] != "cryptoKeys"
                || ![p[1], p[3], p[5], p[7]].into_iter().all(segment)
            {
                return Err("GCP key must be a full cryptoKeys resource path".into());
            }
            if let Some(e) = &c.endpoint {
                endpoint(e)?;
            }
            if let Some(p) = &c.service_account_file {
                path(p)?;
            }
            if let Some(e) = &c.token_endpoint {
                local_auth_endpoint(e, false)?;
            }
            if let Some(e) = &c.metadata_endpoint {
                local_auth_endpoint(e, false)?;
            }
            if let Some(p) = &c.ca_file {
                path(p)?;
            }
        }
        if let Some(c) = &self.azure {
            let u = Url::parse(&c.key).map_err(|_| "invalid Azure key URL")?;
            let origin = u.origin().ascii_serialization();
            endpoint(&origin)?;
            let p: Vec<_> = u.path().split('/').collect();
            let host = u.host_str().ok_or("invalid Azure key host")?;
            let loopback = host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|a| a.is_loopback());
            if !u.username().is_empty()
                || u.password().is_some()
                || u.query().is_some()
                || u.fragment().is_some()
                || p.len() != 3
                || p[1] != "keys"
                || !segment(p[2])
                || (!loopback && !host.ends_with(".vault.azure.net"))
            {
                return Err("Azure key must be an unversioned Key Vault keys URL".into());
            }
            if c.client_secret_file.is_some() {
                if !c.tenant_id.as_ref().is_some_and(|s| segment(s))
                    || !c.client_id.as_ref().is_some_and(|s| segment(s))
                {
                    return Err("Azure client-secret auth requires tenant_id and client_id".into());
                }
            } else if c.tenant_id.is_some() || c.client_id.as_ref().is_some_and(|s| !segment(s)) {
                return Err("invalid Azure managed identity configuration".into());
            }
            if let Some(e) = &c.authority_endpoint {
                local_auth_endpoint(e, true)?;
            }
            if let Some(e) = &c.metadata_endpoint {
                local_auth_endpoint(e, false)?;
            }
            if let Some(p) = &c.ca_file {
                path(p)?;
            }
            if let Some(p) = &c.client_secret_file {
                path(p)?;
            }
        }
        if let Some(c) = &self.pkcs11 {
            super::pkcs11::check(c, require_probe)?;
        }
        Ok(())
    }
    pub fn key_ref(&self) -> Result<String, String> {
        self.check()?;
        if let Some(c) = &self.pkcs11 {
            return super::pkcs11::key_ref(c);
        }
        match self.source {
            Source::Openbao => self
                .openbao
                .as_ref()
                .map(|c| format!("{}/keys/{}", c.mount, c.key)),
            Source::Aws => self.aws.as_ref().map(|c| c.key_id.clone()),
            Source::Gcp => self.gcp.as_ref().map(|c| c.key.clone()),
            Source::Azure => self.azure.as_ref().map(|c| c.key.clone()),
            _ => None,
        }
        .ok_or_else(|| "source has no KMS key reference".into())
    }
}
pub(super) fn aws_key(key: &str, region: &str) -> Result<(), String> {
    let p: Vec<_> = key.split(':').collect();
    if p.len() != 6
        || p[0] != "arn"
        || !matches!(p[1], "aws" | "aws-cn" | "aws-us-gov")
        || p[2] != "kms"
        || p[3] != region
        || p[4].len() != 12
        || !p[4].bytes().all(|c| c.is_ascii_digit())
        || !p[5].strip_prefix("key/").is_some_and(segment)
    {
        return Err("AWS key_id must be a full immutable KMS key ARN in the configured region (not an alias)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inline_credentials_and_unsupported_sources_are_refused() {
        for bad in [
            r#"{"source":"pkcs11","pkcs11":{"pin":"secret"}}"#,
            r#"{"aws":{"secret_access_key":"secret"}}"#,
            r#"{"openbao":{"token":"secret"}}"#,
            r#"{"gcp":{"credentials":"inline"}}"#,
        ] {
            assert!(serde_json::from_str::<Keys>(bad).is_err());
        }
    }
    #[test]
    fn endpoints_and_paths_are_not_remote_instructions() {
        for bad in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/a",
            "https://example.com?x=1",
        ] {
            assert!(endpoint(bad).is_err());
        }
        for good in [
            "http://127.0.0.1:8200",
            "http://[::1]:8200",
            "https://bao.internal:8200",
        ] {
            assert!(endpoint(good).is_ok());
        }
        for bad in ["../x", "%2f", "x/y", "x?x", ""] {
            assert!(!segment(bad));
        }
        for bad in ["0", "01", "-1", "1/../2"] {
            assert!(!positive_version(bad));
        }
        for bad in [
            "https://google.com/token",
            "http://169.254.169.254/token",
            "http://localhost/token?x=1",
        ] {
            assert!(local_auth_endpoint(bad, false).is_err());
        }
        assert!(local_auth_endpoint("http://127.0.0.1:1000/token", false).is_ok());
    }
    #[test]
    fn configuration_must_match_source() {
        let mut k = Keys {
            source: Source::Aws,
            aws: Some(Aws {
                region: "us-east-1".into(),
                key_id: "arn:aws:kms:us-east-1:123456789012:key/1234-abcd".into(),
                ..Aws::default()
            }),
            ..Keys::default()
        };
        assert!(k.check().is_ok());
        k.master_key_file = Some("master.key".into());
        assert!(k.check().is_err());
        k.master_key_file = None;
        k.azure = Some(Azure::default());
        assert!(k.check().is_err());
        assert!(aws_key("alias/test", "us-east-1").is_err());
    }
}
