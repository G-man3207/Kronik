//! Node-local source definitions: credentials never enter the configuration log.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use super::{EnvBackend, SecretBackend};
use crate::MasterKey;
use crate::key_source::{config as kms, providers};

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Definition {
    Env {
        #[serde(default)]
        allowed_refs: Vec<String>,
    },
    Openbao {
        address: String,
        #[serde(default)]
        allowed_refs: Vec<String>,
        #[serde(default = "token")]
        auth: String,
        token_file: Option<PathBuf>,
        role_id_file: Option<PathBuf>,
        secret_id_file: Option<PathBuf>,
        cert_file: Option<PathBuf>,
        key_file: Option<PathBuf>,
        ca_file: Option<PathBuf>,
        auth_mount: Option<String>,
        role: Option<String>,
    },
    Aws {
        region: String,
        #[serde(default)]
        allowed_refs: Vec<String>,
        endpoint: Option<String>,
        #[serde(default = "auto")]
        auth: String,
        imds_endpoint: Option<String>,
        ca_file: Option<PathBuf>,
    },
    Gcp {
        #[serde(default)]
        allowed_refs: Vec<String>,
        service_account_file: Option<PathBuf>,
        endpoint: Option<String>,
        token_endpoint: Option<String>,
        metadata_endpoint: Option<String>,
        ca_file: Option<PathBuf>,
    },
    Azure {
        #[serde(default)]
        allowed_refs: Vec<String>,
        tenant_id: Option<String>,
        client_id: Option<String>,
        client_secret_file: Option<PathBuf>,
        authority_endpoint: Option<String>,
        metadata_endpoint: Option<String>,
        ca_file: Option<PathBuf>,
    },
}
fn token() -> String {
    "token".into()
}
fn auto() -> String {
    "auto".into()
}

impl Definition {
    pub fn allowed_refs(&self) -> &[String] {
        match self {
            Self::Env { allowed_refs }
            | Self::Openbao { allowed_refs, .. }
            | Self::Aws { allowed_refs, .. }
            | Self::Gcp { allowed_refs, .. }
            | Self::Azure { allowed_refs, .. } => allowed_refs,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Env { .. } => "env",
            Self::Openbao { .. } => "openbao",
            Self::Aws { .. } => "aws",
            Self::Gcp { .. } => "gcp",
            Self::Azure { .. } => "azure",
        }
    }
    pub fn check(&self) -> Result<(), String> {
        for prefix in self.allowed_refs() {
            if prefix.is_empty()
                || prefix.len() > 2048
                || prefix.chars().any(char::is_control)
                || prefix.contains('\\')
                || prefix.split('/').any(|part| matches!(part, "." | ".."))
            {
                return Err("invalid allowed_refs prefix".into());
            }
        }
        if let Self::Azure { .. } = self {
            self.azure_origins()?;
        }
        Ok(())
    }
    fn azure_origins(&self) -> Result<Vec<String>, String> {
        let mut origins = BTreeSet::new();
        for prefix in self.allowed_refs() {
            let url = Url::parse(prefix)
                .map_err(|_| "Azure allowed_refs need full vault URL prefixes")?;
            if !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !url.path().starts_with("/secrets/")
            {
                return Err(
                    "Azure allowed_refs need credential-free vault secret URL prefixes".into(),
                );
            }
            let origin = url.origin().ascii_serialization();
            kms::endpoint(&origin)?;
            origins.insert(origin);
        }
        Ok(origins.into_iter().collect())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub backends: BTreeMap<String, Definition>,
    pub refresh: Duration,
    pub max_stale: Duration,
    pub fetch_timeout: Duration,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            backends: BTreeMap::new(),
            refresh: Duration::from_secs(300),
            max_stale: Duration::from_secs(24 * 60 * 60),
            fetch_timeout: Duration::from_secs(2),
        }
    }
}
impl Settings {
    pub fn check(&self) -> Result<(), String> {
        if self.refresh.is_zero()
            || self.max_stale.is_zero()
            || self.fetch_timeout.is_zero()
            || self.fetch_timeout > Duration::from_secs(60)
        {
            return Err(
                "secret refresh/max_stale must be positive and fetch_timeout in (0, 60s]".into(),
            );
        }
        for (id, definition) in &self.backends {
            if !crate::valid_name(id) || id == "file" {
                return Err("secret backend IDs must be valid names other than file".into());
            }
            definition
                .check()
                .map_err(|error| format!("secret backend {id}: {error}"))?;
        }
        Ok(())
    }
}

pub struct Source {
    pub kind: &'static str,
    pub binding: String,
    pub allowed_refs: Vec<String>,
    pub client: Arc<dyn SecretBackend>,
}
impl Source {
    pub fn allows(&self, path: &str) -> bool {
        !path.is_empty()
            && path.len() <= 2048
            && !path.chars().any(char::is_control)
            && self
                .allowed_refs
                .iter()
                .any(|prefix| path.starts_with(prefix))
    }
}

#[derive(Default)]
pub struct Backends {
    sources: BTreeMap<String, Source>,
}
impl Backends {
    /// Local configuration/credential preflight only; no provider network I/O.
    pub async fn new(
        env: &Env,
        settings: &Settings,
        master: Option<&MasterKey>,
    ) -> Result<Self, String> {
        settings.check()?;
        let env_prefixes: Vec<&str> = settings
            .backends
            .values()
            .filter(|definition| matches!(definition, Definition::Env { .. }))
            .flat_map(|definition| definition.allowed_refs().iter().map(String::as_str))
            .collect();
        let has_environment = settings
            .backends
            .values()
            .any(|definition| matches!(definition, Definition::Env { .. }));
        let environment: Option<Arc<dyn SecretBackend>> = if !has_environment {
            None
        } else {
            let mut values = BTreeMap::new();
            for (name, value) in std::env::vars_os() {
                let value = Zeroizing::new(value.into_encoded_bytes());
                let Ok(name) = name.into_string() else {
                    continue;
                };
                if env_prefixes.iter().any(|prefix| name.starts_with(prefix)) {
                    values.insert(name, value);
                }
            }
            Some(Arc::new(
                EnvBackend::new(
                    values,
                    master.ok_or("environment secret backend needs the loaded master")?,
                )
                .map_err(|_| "environment secret key protection unavailable")?,
            ))
        };
        let mut sources = BTreeMap::new();
        for (id, definition) in &settings.backends {
            let mut public_identity = vec![definition.kind().to_owned()];
            let client: Arc<dyn SecretBackend> = match definition {
                Definition::Env { .. } => environment
                    .as_ref()
                    .ok_or("Environment secret snapshot is unavailable")?
                    .clone(),
                Definition::Openbao {
                    address,
                    auth,
                    token_file,
                    role_id_file,
                    secret_id_file,
                    cert_file,
                    key_file,
                    ca_file,
                    auth_mount,
                    role,
                    ..
                } => {
                    let config = kms::OpenBao {
                        address: address.clone(),
                        auth: auth.clone(),
                        token_file: token_file.clone(),
                        role_id_file: role_id_file.clone(),
                        secret_id_file: secret_id_file.clone(),
                        cert_file: cert_file.clone(),
                        key_file: key_file.clone(),
                        ca_file: ca_file.clone(),
                        auth_mount: auth_mount.clone(),
                        role: role.clone(),
                        ..Default::default()
                    };
                    public_identity.push(kms::endpoint(address)?.origin().ascii_serialization());
                    Arc::new(
                        providers::openbao::Secrets::new(env.clone(), config)
                            .map_err(|_| format!("invalid OpenBao secret backend {id}"))?,
                    )
                }
                Definition::Aws {
                    region,
                    endpoint,
                    auth,
                    imds_endpoint,
                    ca_file,
                    ..
                } => {
                    let config = kms::Aws {
                        region: region.clone(),
                        endpoint: endpoint.clone(),
                        auth: auth.clone(),
                        imds_endpoint: imds_endpoint.clone(),
                        ca_file: ca_file.clone(),
                        ..Default::default()
                    };
                    providers::preflight(
                        env,
                        &kms::Keys {
                            source: kms::Source::Aws,
                            aws: Some(config.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                    public_identity.push(region.clone());
                    public_identity.push(match endpoint {
                        Some(endpoint) => kms::endpoint(endpoint)?.origin().ascii_serialization(),
                        None => "default-secretsmanager".into(),
                    });
                    Arc::new(
                        providers::aws::Secrets::new(env.clone(), config)
                            .map_err(|_| format!("invalid AWS secret backend {id}"))?,
                    )
                }
                Definition::Gcp {
                    service_account_file,
                    endpoint,
                    token_endpoint,
                    metadata_endpoint,
                    ca_file,
                    ..
                } => {
                    let config = kms::Gcp {
                        service_account_file: service_account_file.clone(),
                        endpoint: endpoint.clone(),
                        token_endpoint: token_endpoint.clone(),
                        metadata_endpoint: metadata_endpoint.clone(),
                        ca_file: ca_file.clone(),
                        ..Default::default()
                    };
                    providers::preflight(
                        env,
                        &kms::Keys {
                            source: kms::Source::Gcp,
                            gcp: Some(config.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                    public_identity.push(match endpoint {
                        Some(endpoint) => kms::endpoint(endpoint)?.origin().ascii_serialization(),
                        None => "https://secretmanager.googleapis.com".into(),
                    });
                    Arc::new(
                        providers::gcp::Secrets::new(env.clone(), config)
                            .map_err(|_| format!("invalid GCP secret backend {id}"))?,
                    )
                }
                Definition::Azure {
                    tenant_id,
                    client_id,
                    client_secret_file,
                    authority_endpoint,
                    metadata_endpoint,
                    ca_file,
                    ..
                } => {
                    let config = kms::Azure {
                        tenant_id: tenant_id.clone(),
                        client_id: client_id.clone(),
                        client_secret_file: client_secret_file.clone(),
                        authority_endpoint: authority_endpoint.clone(),
                        metadata_endpoint: metadata_endpoint.clone(),
                        ca_file: ca_file.clone(),
                        ..Default::default()
                    };
                    let origins = definition.azure_origins()?;
                    public_identity.extend(origins.iter().cloned());
                    Arc::new(
                        providers::azure::Secrets::new(env.clone(), config, origins)
                            .map_err(|_| format!("invalid Azure secret backend {id}"))?,
                    )
                }
            };
            let mut binding = blake3::Hasher::new();
            binding.update(b"kronik secret source binding v1\0");
            for part in public_identity {
                binding.update(part.as_bytes());
                binding.update(b"\0");
            }
            sources.insert(
                id.clone(),
                Source {
                    kind: definition.kind(),
                    binding: binding.finalize().to_hex().to_string(),
                    allowed_refs: definition.allowed_refs().to_vec(),
                    client,
                },
            );
        }
        Ok(Self { sources })
    }
    pub fn get(&self, id: &str) -> Option<&Source> {
        self.sources.get(id)
    }
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.sources.keys().map(String::as_str)
    }
}
