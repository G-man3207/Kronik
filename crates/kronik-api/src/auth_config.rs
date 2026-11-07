//! Converts private operator OIDC configuration to bounded public control metadata.

use kronik_core::error::ApiError;
use kronik_privacy::sealer::Sealer;
use kronik_proto::log::v1 as pb;

use crate::oidc::Config;

/// The caller supplies the exact provider roots and prior durable digest.
/// Raw subjects, CA paths and credentials never enter the control operation.
pub fn prepare(
    sealer: &Sealer,
    config: Option<&Config>,
    roots: &[Vec<u8>],
    previous_digest: Option<&[u8]>,
) -> Result<pb::audit_event::Operation, ApiError> {
    if previous_digest.is_some_and(|digest| digest.len() != 32) {
        return Err(crate::bad(
            "invalid prior authentication configuration digest",
        ));
    }
    let mut public = pb::AuthConfig {
        version: kronik_proto::control::AUTH_CONFIG_VERSION,
        ..Default::default()
    };
    if let Some(config) = config {
        config.check()?;
        if roots.len() > 16 || (config.ca_file.is_none() != roots.is_empty()) {
            return Err(crate::bad(
                "OIDC provider roots differ from configured trust policy",
            ));
        }
        public.enabled = true;
        public.issuer = config.issuer.clone();
        public.client_id = config.client_id.clone();
        public.redirect_uri = config.redirect_uri.clone();
        public.system_roots = config.ca_file.is_none();
        public.trust_roots_sha256 = roots
            .iter()
            .map(|root| {
                ring::digest::digest(&ring::digest::SHA256, root)
                    .as_ref()
                    .to_vec()
            })
            .collect();
        public.trust_roots_sha256.sort_unstable();
        public.trust_roots_sha256.dedup();
        public.bindings = config
            .bindings
            .iter()
            .map(|binding| {
                let principal_hash = sealer
                    .keyed_hash(
                        "kronik oidc binding v1",
                        &[config.issuer.as_bytes(), binding.subject.as_bytes()],
                    )
                    .ok_or_else(|| {
                        ApiError::new(
                            kronik_core::error::ErrorCode::Unavailable,
                            "OIDC principal identity key is unavailable",
                        )
                    })?;
                Ok(pb::AuthBinding {
                    principal_hash: principal_hash.to_vec(),
                    token_name: binding.token.clone(),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        public
            .bindings
            .sort_unstable_by(|left, right| left.principal_hash.cmp(&right.principal_hash));
        if public
            .bindings
            .windows(2)
            .any(|pair| pair[0].principal_hash == pair[1].principal_hash)
        {
            return Err(crate::bad("ambiguous authentication principal mapping"));
        }
        public.flow_ttl_ms = kronik_proto::control::AUTH_FLOW_TTL_MS;
        public.session_ttl_ms = kronik_proto::control::AUTH_SESSION_TTL_MS;
    } else if !roots.is_empty() {
        return Err(crate::bad(
            "disabled OIDC configuration cannot contain provider roots",
        ));
    }
    public.digest = kronik_proto::control::auth_config_digest(&public).to_vec();
    public.previous_digest = previous_digest.unwrap_or_default().to_vec();
    let operation = pb::audit_event::Operation::AuthConfig(public);
    operation
        .validate()
        .map_err(|error| crate::bad(error.to_string()))?;
    Ok(operation)
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ProfileInput {
    Enabled(Config),
    Disabled(()),
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub config: ProfileInput,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
pub struct Status {
    pub source: Option<kronik_core::ids::SourcePos>,
    pub digest: Option<String>,
    pub enabled: bool,
    pub active: bool,
    pub oidc_reason: Option<crate::oidc::OidcReason>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
pub struct Changed {
    pub dry_run: bool,
    pub changed: bool,
    pub source: Option<kronik_core::ids::SourcePos>,
    pub digest: String,
    pub restart_required: bool,
    pub active: bool,
    pub oidc_reason: Option<crate::oidc::OidcReason>,
}

impl crate::Api {
    pub(crate) fn auth_config_status(
        &self,
        req: &crate::AuthorizedRequest,
    ) -> crate::Result<crate::ApiResponse> {
        req.authority.check()?;
        let current = self
            .node
            .control_operation(kronik_proto::control::ControlKind::Auth)?;
        let (active, oidc_reason) = self
            .browser
            .as_ref()
            .map(|browser| browser.availability())
            .unwrap_or((false, Some(crate::oidc::OidcReason::NotConfigured)));
        let mut status = Status {
            source: None,
            digest: None,
            enabled: false,
            active,
            oidc_reason,
        };
        if let Some((source, pb::audit_event::Operation::AuthConfig(config))) = current {
            status.source = Some(source);
            status.digest = Some(kronik_core::ids::hex(&config.digest));
            status.enabled = config.enabled;
        }
        crate::ok(&status)
    }

    pub(crate) async fn auth_config_change(
        &self,
        req: &crate::AuthorizedRequest,
    ) -> crate::Result<crate::ApiResponse> {
        let change: Change = crate::json(&req.body)?;
        crate::reason(&change.reason)?;
        let config = match &change.config {
            ProfileInput::Enabled(config) => Some(config),
            ProfileInput::Disabled(()) => None,
        };
        let browser = self
            .browser
            .as_ref()
            .ok_or_else(|| crate::bad("the admin browser authentication runtime is unavailable"))?;
        let current = self
            .node
            .control_operation(kronik_proto::control::ControlKind::Auth)?;
        let activation = match &current {
            Some((source, pb::audit_event::Operation::AuthConfig(config))) => {
                browser.activation(*source, &config.digest)
            }
            _ => None,
        };
        let previous = match &current {
            Some((_, pb::audit_event::Operation::AuthConfig(config))) => {
                Some(config.digest.as_slice())
            }
            Some(_) => return Err(crate::internal("unexpected authentication control family")),
            None => None,
        };
        let (operation, roots) = browser.prepare_config(config, previous).await?;
        req.authority.check()?;
        let pb::audit_event::Operation::AuthConfig(public) = &operation else {
            return Err(crate::internal(
                "unexpected authentication control operation",
            ));
        };
        let digest = kronik_core::ids::hex(&public.digest);
        let restart_required = browser.restart_required(public);
        let changed = previous != Some(public.digest.as_slice());
        let original_source = current.as_ref().map(|(source, _)| *source);
        if !changed && change.dry_run {
            let (active, oidc_reason) = browser.availability();
            return crate::ok(&Changed {
                dry_run: true,
                changed: false,
                source: original_source,
                digest,
                restart_required,
                active,
                oidc_reason,
            });
        }
        let profile = std::sync::Arc::new(public.clone());
        // Preflight under the original administrator before our own epoch denial.
        let (provider, provider_reason) = if change.dry_run {
            (None, None)
        } else {
            browser
                .initialize(profile.clone(), roots, req.authority.clone())
                .await?
        };
        req.authority.check()?;
        let authority = std::sync::Arc::new(ConfigMutation {
            inner: req.authority.clone(),
            browser: browser.clone(),
            generation: std::sync::atomic::AtomicU64::new(0),
            runtime_generation: std::sync::atomic::AtomicU64::new(0),
            activation: if changed {
                None
            } else {
                Some(activation.ok_or_else(|| {
                    ApiError::new(
                        kronik_core::error::ErrorCode::Unavailable,
                        "authentication activation is pending or superseded",
                    )
                })?)
            },
        });
        let audit = self.audit(req, change.reason).await;
        let node = self.node.clone();
        let worker_browser = browser.clone();
        let dry_run = change.dry_run;
        let (done, result) = tokio::sync::oneshot::channel();
        self.node.env().spawn("oidc-config", async move {
            let completion = authority.clone();
            let committed = if changed {
                match node
                    .record_control_operation(operation, audit, dry_run, authority.clone())
                    .await
                {
                    Ok(Some(source)) => worker_browser
                        .publish_current(
                            &node,
                            source,
                            profile,
                            provider,
                            provider_reason,
                            &authority.generation,
                            &authority.runtime_generation,
                        )
                        .await
                        .map(|()| Some(source)),
                    other => other,
                }
            } else {
                let worker_node = node.clone();
                node.authorized_effect(authority.clone(), move || async move {
                    let source = original_source.ok_or_else(|| {
                        crate::internal("idempotent authentication configuration lacks its source")
                    })?;
                    worker_browser
                        .publish_current(
                            &worker_node,
                            source,
                            profile,
                            provider,
                            provider_reason,
                            &authority.generation,
                            &authority.runtime_generation,
                        )
                        .await?;
                    Ok(Some(source))
                })
                .await
            };
            let committed = match committed {
                Err(error) => completion
                    .browser
                    .configuration_failed(&completion.generation)
                    .and(Err(error)),
                other => other,
            };
            let _ = done.send(committed);
        });
        let source = result.await.map_err(|_| {
            kronik_core::error::ApiError::new(
                kronik_core::error::ErrorCode::Unavailable,
                "authentication configuration worker stopped",
            )
        })??;
        let (active, oidc_reason) = browser.availability();
        crate::ok(&Changed {
            dry_run,
            changed,
            source,
            digest,
            restart_required,
            active,
            oidc_reason,
        })
    }
}

struct ConfigMutation {
    inner: kronik_core::authority::AuthLease,
    browser: std::sync::Arc<crate::oidc::BrowserAuth>,
    generation: std::sync::atomic::AtomicU64,
    runtime_generation: std::sync::atomic::AtomicU64,
    activation: Option<crate::oidc::Activation>,
}

impl kronik_core::authority::Authority for ConfigMutation {
    fn check(&self) -> Result<(), ApiError> {
        self.inner.check()
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        self.inner.cancelled()
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.inner.admit(&mut || {
            if let Some(activation) = &self.activation {
                self.browser.check_activation(activation)?;
            }
            let generation = self.browser.next_configuration_generation()?;
            effect()?;
            let runtime = self.browser.deny_in_admission(generation);
            self.runtime_generation
                .store(runtime, std::sync::atomic::Ordering::Release);
            self.generation
                .store(generation, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_profile_is_typed_and_prior_digest_is_not_profile_identity() {
        let first = prepare(&Sealer::plain(), None, &[], None).unwrap();
        let next = prepare(&Sealer::plain(), None, &[], Some(&[7; 32])).unwrap();
        let (
            pb::audit_event::Operation::AuthConfig(first),
            pb::audit_event::Operation::AuthConfig(next),
        ) = (first, next)
        else {
            panic!("wrong control operation")
        };
        assert!(!first.enabled);
        assert!(first.bindings.is_empty() && first.issuer.is_empty());
        assert_eq!(first.digest.len(), 32);
        assert_eq!(first.digest, next.digest);
        assert!(first.previous_digest.is_empty());
        assert_eq!(next.previous_digest, [7; 32]);
        assert!(prepare(&Sealer::plain(), None, &[vec![1]], None).is_err());
        assert!(prepare(&Sealer::plain(), None, &[], Some(&[])).is_err());
    }

    #[test]
    fn missing_profile_is_not_implicit_disable() {
        assert!(serde_json::from_str::<Change>(r#"{"reason":"disable"}"#).is_err());
        let explicit: Change =
            serde_json::from_str(r#"{"config":null,"reason":"disable","dry_run":true}"#).unwrap();
        assert!(matches!(explicit.config, ProfileInput::Disabled(())) && explicit.dry_run);
        assert!(serde_json::from_str::<Change>(r#"{"config":{},"reason":"invalid"}"#).is_err());
        let schema = serde_json::to_value(schemars::schema_for!(Change)).unwrap();
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "config")
        );
        let nullable = serde_json::to_value(schemars::schema_for!(ProfileInput)).unwrap();
        assert!(
            nullable["anyOf"]
                .as_array()
                .unwrap()
                .iter()
                .any(|variant| variant["type"] == "null")
        );
    }

    #[tokio::test]
    async fn missing_reason_uses_the_real_api_reason_boundary_without_defaulting_config() {
        let dir = tempfile::tempdir().unwrap();
        let node = kronik_sched::start_local(
            kronik_core::env::Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        let api = crate::Api::new(node.clone());
        let before = node.applied_lsn();
        for (body, code) in [
            (r#"{"config":null}"#, "REASON_REQUIRED"),
            (r#"{"config":null,"reason":" "}"#, "REASON_REQUIRED"),
            (
                r#"{"reason":"missing mandatory profile","dry_run":true}"#,
                "BAD_REQUEST",
            ),
        ] {
            let response = api
                .handle(crate::ApiRequest {
                    method: "PUT".into(),
                    path: "/v1/auth/config".into(),
                    query: String::new(),
                    body: body.as_bytes().to_vec(),
                    token_id: "unix:uid=0".into(),
                    bearer: None,
                })
                .await;
            let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(
                (response.status, value["error"]["code"].as_str()),
                (400, Some(code))
            );
            assert_eq!(node.applied_lsn(), before);
        }
    }

    #[test]
    fn principal_metadata_never_falls_back_to_an_unkeyed_subject_hash() {
        let config: Config = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example",
            "client_id": "public-client",
            "redirect_uri": "https://admin.example/v1/auth/callback",
            "ca_file": null,
            "bindings": [{"subject": "synthetic-private-subject", "token": "reviewer"}]
        }))
        .unwrap();
        let error = prepare(&Sealer::plain(), Some(&config), &[], None).unwrap_err();
        assert!(error.message.contains("identity key"));
    }
}
