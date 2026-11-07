//! Native Fleet uses the ordinary token table and existing exact owned effect boundary.
use super::*;

impl TokenStore {
    // The fleet token creation's admission: node, name, scopes, bearer and
    // authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_authorized(
        self: &Arc<Self>,
        node: Arc<kronik_sched::Node>,
        name: &str,
        scopes: BTreeSet<Scope>,
        mut audit: kronik_proto::log::v1::Audit,
        dry_run: bool,
        fleet: Option<FleetToken>,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<(TokenMeta, Option<String>), ApiError> {
        authority.check()?;
        if self.metadata_revision()?.is_some() {
            return Err(metadata_unavailable());
        }
        audit.reason = {
            let values = node.certified_secret_values().await;
            let patterns = values
                .as_ref()
                .map(|values| kronik_sched::effects::secret_patterns(values));
            kronik_sched::scrub::for_log(&audit.reason, patterns.as_deref())
        };
        let meta = self.preview_create(
            name,
            scopes,
            &Change {
                by: &audit.token_id,
                reason: &audit.reason,
                wall_ms: audit.wall_time_ms,
            },
            fleet,
        )?;
        if dry_run {
            return Ok((meta, None));
        }
        let secret = new_secret(node.env().random_bytes::<32>());
        let digest = hash(&secret);
        node.record_audit_event_authorized(
            "token.create",
            name,
            [
                ("scopes".to_owned(), scopes_text(&meta.scopes)),
                ("token_id".to_owned(), token_id(name)),
            ]
            .into_iter()
            .collect(),
            audit,
            authority.clone(),
        )
        .await?;
        let store = self.clone();
        let env = node.env().clone();
        node.authorized_effect(authority, move || async move {
            env.blocking("token-change", move || {
                store.insert_prepared(meta, secret, digest)
            })
            .await
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "token change worker stopped"))?
        })
        .await
    }

    pub(crate) async fn revoke_authorized(
        self: &Arc<Self>,
        node: Arc<kronik_sched::Node>,
        name: &str,
        mut audit: kronik_proto::log::v1::Audit,
        dry_run: bool,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<TokenMeta, ApiError> {
        authority.check()?;
        if self.metadata_revision()?.is_some() {
            return Err(metadata_unavailable());
        }
        audit.reason = {
            let values = node.certified_secret_values().await;
            let patterns = values
                .as_ref()
                .map(|values| kronik_sched::effects::secret_patterns(values));
            kronik_sched::scrub::for_log(&audit.reason, patterns.as_deref())
        };
        let change = Change {
            by: &audit.token_id,
            reason: &audit.reason,
            wall_ms: audit.wall_time_ms,
        };
        let meta = self.revoke(name, &change, true)?;
        if dry_run {
            return Ok(meta);
        }
        node.record_audit_event_authorized(
            "token.revoke",
            name,
            [("token_id".to_owned(), token_id(name))]
                .into_iter()
                .collect(),
            audit.clone(),
            authority.clone(),
        )
        .await?;
        let (store, name) = (self.clone(), name.to_owned());
        let env = node.env().clone();
        node.authorized_effect(authority, move || async move {
            env.blocking("token-change", move || {
                store.revoke(
                    &name,
                    &Change {
                        by: &audit.token_id,
                        reason: &audit.reason,
                        wall_ms: audit.wall_time_ms,
                    },
                    false,
                )
            })
            .await
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "token change worker stopped"))?
        })
        .await
    }
}
