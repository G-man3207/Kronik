//! Fixed trusted native installation startup; ordinary control routes cannot select it.
use super::*;
use kronik_core::ids::SourcePos;
use kronik_proto::control::ControlKind;

impl Node {
    /// Fixed trusted host startup: no caller-supplied system identity or replacement lease.
    pub async fn record_installation_identity(
        &self,
        identity: pb::InstallationIdentity,
    ) -> Result<SourcePos, ApiError> {
        let authority = self.local_operator_authority()?;
        let operation = pb::audit_event::Operation::InstallationIdentity(identity);
        operation
            .validate()
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        let held = self.lock_deploy_authorized(&authority).await?;
        let node = self
            .arc()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let (done, result) = oneshot::channel();
        self.env.spawn("installation-identity", async move {
            let _held = held;
            let outcome = async {
                authority.check()?;
                let previous = node
                    .store
                    .db()
                    .control_state(ControlKind::Installation)
                    .map_err(store_err)?;
                operation
                    .validate_transition(previous.as_ref().map(|(_, previous)| previous))
                    .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
                if let Some((lsn, _)) = previous {
                    authority.check()?;
                    return Ok(SourcePos::Actor { shard: None, lsn });
                }
                let audit = pb::Audit {
                    token_id: "system:installation".into(),
                    reason: "initialize installation identity".into(),
                    wall_time_ms: node.env.clock.wall_ms(),
                };
                let record = node.control_audit_record(operation, audit)?;
                let lsn = node.commit_authorized(record, authority).await?;
                Ok(SourcePos::Actor { shard: None, lsn })
            }
            .await;
            let _ = done.send(outcome);
        });
        result.await.map_err(|_| {
            ApiError::new(
                ErrorCode::Unavailable,
                "installation identity worker stopped",
            )
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(node: &Node) -> pb::Audit {
        pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "actual native control consumer".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        }
    }

    fn pending() -> pb::FleetState {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../kronik-proto/tests/fixtures/control-fleet-pending-v1.json"
        ))
        .unwrap();
        let bytes = |field: &str| {
            value[field]
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        pb::FleetState {
            installation: value["installation"].as_str().unwrap().into(),
            node: None,
            cluster: None,
            controller_origin: value["controller_origin"].as_str().unwrap().into(),
            scopes: vec!["read".into()],
            ca_sha256: bytes("ca_sha256"),
            request_id: bytes("request_id"),
            epoch: 1,
            phase: pb::fleet_state::Phase::Pending as i32,
            controller_id: None,
            csr_der: bytes("csr_der_hex"),
            client_key_sha256: bytes("client_key_sha256"),
            client_cert_der: None,
        }
    }

    #[tokio::test]
    async fn a_control_operation_that_begins_in_a_rebuild_window_waits_and_records_the_reason() {
        let data = tempfile::tempdir().unwrap();
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            data.path(),
            NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        node.record_installation_identity(pb::InstallationIdentity {
            installation: "test".into(),
        })
        .await
        .unwrap();
        node.env()
            .timeout(Duration::from_secs(60), node.secret_cycle_settled())
            .await
            .unwrap();
        let window = node.hold_secret_rebuild_window().await.unwrap();
        let mut change = {
            let node = node.clone();
            let operation = pb::audit_event::Operation::FleetState(pending());
            node.env()
                .clone()
                .spawn("control-operation-test", async move {
                    let audit = audit(&node);
                    node.record_control_operation(operation, audit, false, original)
                        .await
                })
        };
        // It waits for the inventory; one that did not would be done long
        // before this, with the placeholder as the reason of its record.
        assert!(
            node.env()
                .timeout(Duration::from_millis(300), &mut change)
                .await
                .is_err(),
            "the control operation did not wait for the inventory"
        );
        drop(window);
        let SourcePos::Actor { lsn, .. } = change.await.unwrap().unwrap().unwrap() else {
            panic!("a native record has an actor position")
        };
        let mut reasons = Vec::new();
        node.reader()
            .read(lsn, lsn, |c| {
                if let Record::AuditEvent(event) = c.record {
                    reasons.push(event.audit.unwrap().reason);
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(reasons, [audit(&node).reason]);
    }

    #[tokio::test]
    async fn exact_native_control_sources_survive_unrelated_records_and_reject_stale_transitions() {
        let data = tempfile::tempdir().unwrap();
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            data.path(),
            NodeConfig::default(),
        )
        .await
        .unwrap();
        let original = node.local_operator_authority().unwrap();
        let identity = pb::InstallationIdentity {
            installation: "test".into(),
        };
        let installed = node
            .record_installation_identity(identity.clone())
            .await
            .unwrap();
        let start = node.applied_lsn();
        assert_eq!(
            node.record_installation_identity(identity).await.unwrap(),
            installed
        );
        assert_eq!(node.applied_lsn(), start);
        assert!(
            node.record_installation_identity(pb::InstallationIdentity {
                installation: "other".into()
            })
            .await
            .is_err()
        );
        let state = pending();
        let operation = pb::audit_event::Operation::FleetState(state.clone());
        assert_eq!(
            node.record_control_operation(operation.clone(), audit(&node), true, original.clone())
                .await
                .unwrap(),
            None
        );
        assert_eq!(node.applied_lsn(), start);
        let source = node
            .record_control_operation(operation.clone(), audit(&node), false, original.clone())
            .await
            .unwrap()
            .unwrap();
        let unrelated = node
            .record_audit_event_authorized(
                "test.following",
                "unrelated",
                Default::default(),
                audit(&node),
                original.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            node.control_operation(ControlKind::Fleet).unwrap(),
            Some((source, operation))
        );
        assert_eq!(
            node.control_operation(ControlKind::Installation).unwrap(),
            Some((
                installed,
                pb::audit_event::Operation::InstallationIdentity(pb::InstallationIdentity {
                    installation: "test".into()
                })
            ))
        );
        let mut requested = state.clone();
        requested.phase = pb::fleet_state::Phase::Requested as i32;
        node.record_control_operation(
            pb::audit_event::Operation::FleetState(requested),
            audit(&node),
            false,
            original.clone(),
        )
        .await
        .unwrap();
        let before = node.applied_lsn();
        assert!(before > unrelated);
        assert_eq!(
            node.record_control_operation(
                pb::audit_event::Operation::FleetState(state),
                audit(&node),
                false,
                original.clone()
            )
            .await
            .unwrap_err()
            .code,
            ErrorCode::BadRequest
        );
        assert_eq!(node.applied_lsn(), before);
        for operation in [
            pb::audit_event::Operation::AuthSessionRevoked(Default::default()),
            pb::audit_event::Operation::AuthOidcLogin(Default::default()),
            pb::audit_event::Operation::InstallationIdentity(pb::InstallationIdentity {
                installation: "test".into(),
            }),
        ] {
            assert_eq!(
                node.record_control_operation(operation, audit(&node), false, original.clone())
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::BadRequest
            );
        }
        assert_eq!(node.applied_lsn(), before);
        node.stop_native_execution().unwrap();
        assert!(node.control_operation(ControlKind::Fleet).is_err());
        assert!(
            node.record_control_operation(
                pb::audit_event::Operation::FleetState(pending()),
                audit(&node),
                false,
                original
            )
            .await
            .is_err()
        );
        assert_eq!(node.applied_lsn(), before);
    }
}
