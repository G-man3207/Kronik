//! Optional outbound fleet lifecycle; never opens a listener.

use std::sync::Arc;
use std::time::Duration;

use kronik_api::fleet::{Fleet, FleetConfig};
use kronik_api::{Api, ApiRequest};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_fleet::enrollment::{ControllerConfig, FleetIdentity};
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use zeroize::Zeroize as _;

pub async fn installation(node: &Arc<Node>, configured: Option<&str>) -> Result<String, ApiError> {
    let current = node.control_operation(kronik_proto::control::ControlKind::Installation)?;
    if let Some((_, operation)) = current {
        operation
            .validate()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
        let kronik_proto::log::v1::audit_event::Operation::InstallationIdentity(identity) =
            operation
        else {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "installation control family mismatch",
            ));
        };
        let id = identity.installation;
        if configured.is_some_and(|value| value != id) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "configured installation differs from durable installation identity",
            ));
        }
        return Ok(id);
    }
    let id = match configured {
        Some(value) => value.to_owned(),
        None => kronik_core::ids::hex(&node.env().random_bytes::<32>()),
    };
    node.record_installation_identity(pb::InstallationIdentity {
        installation: id.clone(),
    })
    .await?;
    Ok(id)
}

pub async fn open(
    node: Arc<Node>,
    tokens: Arc<kronik_api::tokens::TokenStore>,
    config: &crate::config::Config,
    startup_original: kronik_core::authority::AuthLease,
) -> Result<Option<Arc<Fleet>>, ApiError> {
    let Some(fleet) = &config.fleet else {
        return Ok(None);
    };
    let directory = config.server.data_dir.join("keys/fleet");
    Fleet::open(
        node,
        tokens,
        FleetConfig {
            controller: ControllerConfig {
                url: fleet.url.clone(),
                ca_file: fleet.ca_file.clone(),
                client_key_file: directory.join("client.key"),
            },
            identity: FleetIdentity {
                installation: fleet.installation.clone(),
                node: fleet.node.clone(),
                cluster: fleet.cluster.clone(),
            },
            scopes: fleet.scopes.clone(),
        },
        directory.join("bearer"),
        startup_original,
    )
    .await
    .map(Some)
}

pub fn start(
    node: &Arc<Node>,
    fleet: Arc<Fleet>,
    api: &Arc<Api>,
    mount: Option<(&'static str, kronik_api::server::Mount)>,
) {
    let env = node.env().clone();
    let api = Arc::downgrade(api);
    let task_env = env.clone();
    drop(env.spawn("fleet-control", async move {
        let changed = fleet.changes();
        let opening_capacity = Arc::new(tokio::sync::Semaphore::new(1));
        let mut delay = Duration::from_secs(1);
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match fleet.active_connection().await {
                Ok(Some((client, record, bearer, guard))) => {
                    let Some(control_api) = api.upgrade() else {
                        return;
                    };
                    let mut request = ApiRequest {
                        method: "GET".into(),
                        path: "/".into(),
                        query: String::new(),
                        body: Vec::new(),
                        token_id: "fleet".into(),
                        bearer: Some(bearer.to_string()),
                    };
                    let captured = control_api.capture_fleet_binding(&request, guard.clone());
                    if let Some(credential) = request.bearer.as_mut() {
                        credential.zeroize();
                    }
                    drop(control_api);
                    match captured {
                        Ok(captured) => {
                            let api = api.clone();
                            let lifetime = captured.authority().clone();
                            let mount = mount.clone();
                            let opening_audit = fleet.control_opening_audit(&captured);
                            let session = kronik_fleet::transport::run_control(
                                &task_env,
                                &client,
                                &record,
                                &bearer,
                                guard,
                                lifetime.clone(),
                                opening_capacity.clone(),
                                |prepared| {
                                    Box::pin(
                                        prepared.dispatch_with_admission(move || opening_audit),
                                    )
                                },
                                move |stream, _guard| {
                                    Box::pin(async move {
                                        if let Some(api) = api.upgrade() {
                                            if kronik_api::server::serve_fleet_connection(
                                                stream, api, captured, mount,
                                            )
                                            .await
                                            .is_err()
                                            {
                                                tracing::warn!(
                                                    "fleet HTTP connection authority unavailable"
                                                );
                                            }
                                        }
                                    })
                                },
                            );
                            tokio::select! {
                                biased;
                                () = lifetime.cancelled() => {
                                    delay = Duration::from_secs(1);
                                    continue;
                                },
                                _ = session => {},
                            }
                        }
                        Err(error) => tracing::warn!(
                            code = error.code.as_str(),
                            "fleet connection authority unavailable"
                        ),
                    }
                }
                Ok(None) => {
                    notified.await;
                    delay = Duration::from_secs(1);
                    continue;
                }
                Err(_) => tracing::warn!(
                    "fleet connection unavailable; local authority remains fail closed"
                ),
            }
            if api.upgrade().is_none() {
                return;
            }
            tokio::select! {
                biased;
                _ = task_env.clock.sleep(delay) => {},
                _ = &mut notified => {},
            }
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }));
}
