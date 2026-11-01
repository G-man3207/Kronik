//! Native verified-login key custody. Receipts are cuts, never minting authority.
use super::*;
use crate::subject_keys::SubjectKeyPlan;
use kronik_core::authority::{Authority, SessionLease};
use kronik_core::ids::SourcePos;
use kronik_privacy::keystore::{Keystore, PreparedSubjectKey};
use zeroize::{Zeroize, Zeroizing};

// Completed decoded fields own an allocation only for escaped JSON strings.
// Wipe those owned fallbacks too, including partially decoded identity objects.
#[derive(serde::Deserialize)]
#[serde(transparent)]
struct IdentityText<'a>(#[serde(borrow)] std::borrow::Cow<'a, str>);
impl Drop for IdentityText<'_> {
    fn drop(&mut self) {
        if let std::borrow::Cow::Owned(value) = &mut self.0 {
            value.zeroize();
        }
    }
}

fn denied_identity() -> ApiError {
    ApiError::new(
        ErrorCode::Unauthenticated,
        "the original verified identity binding changed",
    )
}
fn unavailable_identity_key() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        "the prepared verified identity key is unavailable",
    )
}

fn native_login(session: &SessionLease, now: u64) -> Result<pb::AuthOidcLogin, ApiError> {
    session.check()?;
    let binding = session.revocation();
    kronik_proto::control::validate_auth_session_revoked(binding).map_err(|_| denied_identity())?;
    let Some(pb::auth_session_revoked::ConfigSource::NativeLsn(source)) =
        binding.config_source.as_ref()
    else {
        return Err(denied_identity());
    };
    if binding.expires_at_ms <= now {
        return Err(denied_identity());
    }
    Ok(pb::AuthOidcLogin {
        principal_hash: binding.principal_hash.clone(),
        config_digest: binding.config_digest.clone(),
        config_source: Some(pb::auth_oidc_login::ConfigSource::NativeLsn(*source)),
        token_name: binding.token_name.clone(),
    })
}

/// This final outer data guard is retained only by the private callback plan.
/// It is never installed as a browser Session.token or used as its original cap.
struct NativeIdentityAuthority {
    original: SessionLease,
    execution: AuthLease,
    keystore: Arc<Keystore>,
    prepared: Arc<PreparedSubjectKey>,
}

impl Authority for NativeIdentityAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.execution.check()?;
        self.original.check()?;
        // Call outside publication: this is a real read, not a cached floor proof.
        self.keystore
            .with_current_prepared(&self.prepared, || ())
            .map_err(|_| unavailable_identity_key())
    }

    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let original = self.original.clone();
        let execution = self.execution.clone();
        Box::pin(async move {
            tokio::select! {
                biased;
                () = original.cancelled() => {},
                () = execution.cancelled() => {},
            }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.execution.check()?;
        self.original.check()?;
        // KS mutex + SQLite writer exclusion are acquired BEFORE publication.
        // SQL/envelope checks finish before original.admit enters its single fence.
        self.keystore
            .with_current_prepared(&self.prepared, || {
                self.original.admit(&mut || {
                    self.execution.check()?;
                    effect()
                })
            })
            .map_err(|_| unavailable_identity_key())?
    }
}

impl Node {
    /// The actual holder is sealed and published in one synchronous local data
    /// critical section. The callback only inserts the protected pending draft.
    /// Call on an Env.blocking worker. Check the returned guard there before
    /// returning a cookie; never install it as the original Session.token.
    pub fn seal_native_identity_at<F>(
        &self,
        sealer: Arc<Sealer>,
        mut value: pb::Sealable,
        plan: SubjectKeyPlan,
        original: SessionLease,
        publish: F,
    ) -> Result<AuthLease, ApiError>
    where
        F: FnOnce(pb::Sealable) -> Result<(), ApiError>,
    {
        let Some(pb::sealable::Value::Plain(bytes)) = value.value.take() else {
            return Err(denied_identity());
        };
        let mut bytes = Zeroizing::new(bytes);
        self.check_alive()?;
        if !Arc::ptr_eq(&self.sealer, &sealer) {
            return Err(denied_identity());
        }
        let expected = native_login(&original, self.env.clock.wall_ms())?;
        let owner = format!("oidc:{}", kronik_core::ids::hex(&expected.principal_hash));
        if value.subject.as_deref() != Some(owner.as_str()) {
            return Err(denied_identity());
        }
        // The original plaintext is already guarded before every validation error.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Identity<'a> {
            #[serde(borrow)]
            issuer: IdentityText<'a>,
            #[serde(borrow)]
            subject: IdentityText<'a>,
        }
        let pair: Identity<'_> = serde_json::from_slice(&bytes).map_err(|_| denied_identity())?;
        let issuer = pair.issuer.0.as_ref();
        let subject = pair.subject.0.as_ref();
        if issuer.is_empty()
            || issuer.len() > 1024
            || issuer.chars().any(char::is_control)
            || subject.is_empty()
            || subject.len() > 255
            || subject.chars().any(char::is_control)
        {
            return Err(denied_identity());
        }
        let principal = sealer
            .keyed_hash(
                "kronik oidc binding v1",
                &[issuer.as_bytes(), subject.as_bytes()],
            )
            .ok_or_else(unavailable_identity_key)?;
        if principal.as_slice() != expected.principal_hash.as_slice() {
            return Err(denied_identity());
        }
        drop(pair);
        let (prepared, refined) = plan.into_native(&original)?;
        if prepared.subject() != owner {
            return Err(denied_identity());
        }
        let execution = self.local_operator_authority()?;
        // Transfer ownership without copying only after all identity validation.
        // The sealer immediately installs its own zeroizing plaintext guard.
        value.value = Some(pb::sealable::Value::Plain(std::mem::take(&mut *bytes)));
        let mut publish = Some(publish);
        sealer
            .seal_value_with_prepared(
                value,
                &prepared,
                &|bytes| self.env.entropy.fill(bytes),
                |sealed| -> Result<(), ApiError> {
                    let mut sealed = Some(sealed);
                    // The sealer already holds and has validated the KS transaction.
                    // Do not call refined.admit/check here: either would reenter KS.
                    original.admit(&mut || {
                        execution.check()?;
                        let publish = publish
                            .take()
                            .ok_or_else(|| internal("Identity published twice"))?;
                        let sealed = sealed
                            .take()
                            .ok_or_else(|| internal("Identity sealed value consumed twice"))?;
                        publish(sealed)
                    })?;
                    if publish.is_some() {
                        return Err(internal("Identity authority did not publish"));
                    }
                    Ok(())
                },
            )
            .map_err(|_| unavailable_identity_key())??;
        Ok(refined)
    }

    /// Own original admission, durable local key preparation and the actual
    /// login ACK as one callback operation. The tuple never leaves this stack.
    pub async fn record_oidc_login(
        &self,
        mut audit: pb::Audit,
        original: SessionLease,
    ) -> Result<(SourcePos, SubjectKeyPlan), ApiError> {
        self.check_alive()?;
        let login = native_login(&original, self.env.clock.wall_ms())?;
        audit.token_id = format!("oidc:{}", kronik_core::ids::hex(&login.principal_hash));
        let subject = audit.token_id.clone();
        let execution = self.local_operator_authority()?;
        let authority: AuthLease =
            kronik_core::authority::guard_session(original.clone(), execution.clone());
        let held = self.lock_deploy_authorized(&authority).await?;
        let node = self.arc().ok_or_else(unavailable_identity_key)?;
        let (done, result) = oneshot::channel();
        self.env.spawn("oidc-login", async move {
            let _held = held;
            let outcome = async {
                let prepare_node = node.clone();
                let (record, plan, refined) = node
                    .authorized_effect(authority.clone(), move || async move {
                        let env = prepare_node.env.clone();
                        env.blocking("oidc-login-prepare", move || -> Result<_, ApiError> {
                            prepare_node
                                .store
                                .db()
                                .validate_auth_oidc_login(&login)
                                .map_err(store_err)?;
                            let record = prepare_node.control_audit_record(
                                pb::audit_event::Operation::AuthOidcLogin(login),
                                audit,
                            )?;
                            let sealer = &prepare_node.sealer;
                            // No KS read or floor CAS precedes the real original
                            // admission; all preparation I/O runs on this worker.
                            let floor = sealer
                                .erasure_floor(&subject)
                                .map_err(|_| unavailable_identity_key())?;
                            let prepared = Arc::new(
                                sealer
                                    .prepare_plain_source_holder(
                                        &subject,
                                        floor,
                                        &|bytes| prepare_node.env.entropy.fill(bytes),
                                        prepare_node.env.clock.wall_ms(),
                                    )
                                    .map_err(|_| unavailable_identity_key())?,
                            );
                            let keystore = sealer
                                .keystore()
                                .cloned()
                                .ok_or_else(unavailable_identity_key)?;
                            let refined: AuthLease = Arc::new(NativeIdentityAuthority {
                                original: original.clone(),
                                execution,
                                keystore,
                                prepared: prepared.clone(),
                            });
                            Ok((
                                record,
                                SubjectKeyPlan::new_native(prepared, original, refined.clone()),
                                refined,
                            ))
                        })
                        .await
                        .ok_or_else(unavailable_identity_key)?
                    })
                    .await?;
                // The audit is admitted by the original pure session/execution
                // guard. Never run the KS-reading refined guard on Log's async
                // caller, and never retain a KS transaction across its ACK.
                let lsn = node.commit_authorized(record, authority).await?;
                node.env
                    .blocking("oidc-login-check", move || refined.check())
                    .await
                    .ok_or_else(unavailable_identity_key)??;
                Ok((SourcePos::Actor { shard: None, lsn }, plan))
            }
            .await;
            let _ = done.send(outcome);
        });
        result
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "login history worker stopped"))?
    }
}
