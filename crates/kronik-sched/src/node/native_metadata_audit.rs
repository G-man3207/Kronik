//! Fixed native coverage receipts; public metadata indices never select an actor source.
use super::*;

impl Node {
    pub async fn record_metadata_audit_gap(
        &self,
        gap: kronik_log::MetadataAuditGap,
        authority: AuthLease,
    ) -> Result<kronik_core::ids::SourcePos, ApiError> {
        authority.check()?;
        self.check_alive()?;
        let native = self.local_operator_authority()?;
        if !Arc::ptr_eq(&authority, &native) {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "metadata system audit requires the original native execution lease",
            ));
        }
        let (action, identity) = SystemAudit::RetentionGap.identity();
        let reason = {
            let secrets = self.secret_values().ok();
            let patterns = secrets
                .as_ref()
                .map(|values| crate::effects::secret_patterns(values));
            crate::scrub::for_log("metadata audit schema coverage floor", patterns.as_deref())
        };
        let event = pb::AuditEvent {
            action: action.into(),
            target: String::new(),
            details: gap.into_details(),
            audit: Some(pb::Audit {
                token_id: identity.into(),
                reason,
                wall_time_ms: self.env.clock.wall_ms(),
            }),
            operation: None,
            ..Default::default()
        };
        kronik_proto::control::validate_metadata_gap_event(&event)
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        let held = self.lock_deploy_authorized(&authority).await?;
        let node = self
            .arc()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        let (done, result) = oneshot::channel();
        self.env.spawn("metadata-gap-audit", async move {
            let _held = held;
            let outcome = async {
                authority.check()?;
                let mut receipt = None;
                node.reader
                    .read_while(1, node.applied_lsn(), |committed| {
                        if let Record::AuditEvent(previous) = committed.record
                            && previous.action == "audit.gap"
                            && previous.details.contains_key("namespace")
                        {
                            kronik_proto::control::validate_metadata_gap_event(&previous).map_err(
                                |_| {
                                    kronik_log::LogError::Corrupt(
                                        "invalid metadata gap audit receipt".into(),
                                    )
                                },
                            )?;
                            if previous.details == event.details
                                && previous
                                    .audit
                                    .as_ref()
                                    .is_some_and(|audit| audit.token_id == identity)
                            {
                                receipt = Some(committed.lsn);
                                return Ok(false);
                            }
                        }
                        Ok(true)
                    })
                    .await
                    .map_err(|error| {
                        ApiError::new(
                            if matches!(error, kronik_log::LogError::Corrupt(_)) {
                                ErrorCode::StorageCorrupt
                            } else {
                                ErrorCode::Unavailable
                            },
                            "metadata gap audit receipt lookup failed",
                        )
                    })?;
                authority.check()?;
                let lsn = match receipt {
                    Some(lsn) => lsn,
                    None => {
                        node.commit_authorized(Record::AuditEvent(event), authority)
                            .await?
                    }
                };
                Ok(kronik_core::ids::SourcePos::Actor { shard: None, lsn })
            }
            .await;
            let _ = done.send(outcome);
        });
        result.await.map_err(|_| {
            ApiError::new(ErrorCode::Unavailable, "metadata gap audit worker stopped")
        })?
    }
}

impl Node {
    /// Fixed native signing-key receipt, durable before publishing a replacement pin.
    pub async fn record_metadata_webhook_key_change(
        &self,
        change: kronik_log::MetadataWebhookKeyChange,
        authority: AuthLease,
    ) -> Result<kronik_core::ids::SourcePos, ApiError> {
        authority.check()?;
        self.check_alive()?;
        let native = self.local_operator_authority()?;
        if !Arc::ptr_eq(&authority, &native) {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "metadata system audit requires the original native execution lease",
            ));
        }
        let (action, identity) = SystemAudit::ExportConfiguration.identity();
        let reason = {
            let values = self.secret_values().ok();
            let patterns = values
                .as_ref()
                .map(|values| crate::effects::secret_patterns(values));
            crate::scrub::for_log(
                "the configured webhook signing version changed",
                patterns.as_deref(),
            )
        };
        let details = change.to_details();
        let event = pb::AuditEvent {
            action: action.into(),
            target: change.stream,
            details,
            audit: Some(pb::Audit {
                token_id: identity.into(),
                reason,
                wall_time_ms: self.env.clock.wall_ms(),
            }),
            ..Default::default()
        };
        kronik_proto::control::validate_metadata_webhook_key_change_event(&event)
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))?;
        let lsn = self
            .commit_authorized(Record::AuditEvent(event), authority)
            .await?;
        Ok(kronik_core::ids::SourcePos::Actor { shard: None, lsn })
    }
}
