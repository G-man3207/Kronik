//! Fleet admission follows durable control state; the private file holds only restart credentials.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use kronik_core::error::{ApiError, ErrorCode};
use kronik_fleet::enrollment::{
    self, ControllerClient, ControllerConfig, EnrollmentPhase, EnrollmentPlan, EnrollmentRecord,
    FleetError, FleetIdentity,
};
use kronik_fleet::transport::{EpochAuthority, EpochGuard};
use kronik_proto::control::ControlKind;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::tokens::{self, FleetToken, TokenStore};

#[derive(Clone)]
pub struct FleetConfig {
    pub controller: ControllerConfig,
    pub identity: FleetIdentity,
    pub scopes: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FleetEnrollRequest {
    pub url: String,
    pub token: Option<String>,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FleetRevokeRequest {
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct FleetStatus {
    pub configured: bool,
    pub dry_run: bool,
    /// Current local admission for reads; publication-time admission for mutation ACKs.
    pub admitting: bool,
    pub admission_error: Option<&'static str>,
    pub recovery_hint: Option<&'static str>,
    pub state: Option<EnrollmentRecord>,
    pub plan: Option<EnrollmentPlan>,
}

impl FleetStatus {
    fn acknowledged(record: EnrollmentRecord, admitting: bool) -> Self {
        Self {
            configured: true,
            dry_run: false,
            admitting,
            admission_error: None,
            recovery_hint: None,
            state: Some(record),
            plan: None,
        }
    }
}

pub struct Fleet {
    node: Arc<Node>,
    tokens: Arc<TokenStore>,
    config: FleetConfig,
    custody: PathBuf,
    // The caller's original ACTIVE physical startup operation; never reacquired.
    startup_original: kronik_core::authority::AuthLease,
    operation: tokio::sync::Mutex<()>,
    enrollment_http: Arc<tokio::sync::Semaphore>,
    authority: Arc<EpochAuthority>,
    changed: Arc<tokio::sync::Notify>,
    admission: RwLock<Option<u64>>,
    request: RwLock<Option<Arc<EnrollmentRecord>>>,
    custody_error: RwLock<Option<ErrorCode>>,
}

const CUSTODY_RECOVERY_HINT: &str =
    "Use local fleet revoke, then enroll with a fresh one-time credential.";

fn bad(message: &str) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}
fn internal(_: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorCode::Internal,
        "fleet durable state or credential custody unavailable",
    )
}
fn custody_unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        "fleet credential custody unavailable",
    )
    .with_hint(CUSTODY_RECOVERY_HINT)
}
fn fleet_error(error: FleetError) -> ApiError {
    match error {
        FleetError::Revoked => ApiError::new(
            ErrorCode::Unauthenticated,
            "fleet enrollment was revoked or superseded",
        ),
        _ => bad("fleet enrollment failed; retry the durable request without its one-time token"),
    }
}
fn next_epoch(record: Option<&EnrollmentRecord>) -> Result<u64, ApiError> {
    record
        .map_or(Some(1), |r| r.epoch.checked_add(1))
        .ok_or_else(|| bad("fleet epoch exhausted"))
}
fn token_name(record: &EnrollmentRecord) -> Result<String, ApiError> {
    let bytes = record.request_id.as_bytes();
    if bytes.len() != 64 {
        return Err(internal("invalid fleet request identity"));
    }
    let mut request = [0; 32];
    for (byte, pair) in request.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let nibble = |value| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(internal("invalid fleet request identity")),
        };
        *byte = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    kronik_proto::control::fleet_token_name(record.epoch, &request).map_err(internal)
}
fn validate_caller(token_id: &str, reason: &str) -> Result<(), ApiError> {
    if token_id.trim().is_empty() {
        return Err(ApiError::new(
            ErrorCode::Unauthenticated,
            "fleet mutation needs an authenticated caller",
        ));
    }
    crate::reason(reason)
}

fn digest_bytes(value: &str) -> Result<Vec<u8>, ApiError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(bad("invalid typed fleet digest"));
    }
    kronik_core::ids::unhex(value).ok_or_else(|| bad("invalid typed fleet digest"))
}

fn validate_plan(plan: &EnrollmentPlan) -> Result<(), ApiError> {
    kronik_proto::control::validate_fleet_plan(
        &plan.identity.installation,
        plan.identity.node.as_deref(),
        plan.identity.cluster.as_deref(),
        &plan.controller_url,
        &plan.scopes,
        &digest_bytes(&plan.ca_sha256)?,
    )
    .map_err(internal)
}

fn state_from_record(record: &EnrollmentRecord) -> Result<pb::FleetState, ApiError> {
    let state = pb::FleetState {
        installation: record.plan.identity.installation.clone(),
        node: record.plan.identity.node.clone(),
        cluster: record.plan.identity.cluster.clone(),
        controller_origin: record.plan.controller_url.clone(),
        scopes: record.plan.scopes.clone(),
        ca_sha256: digest_bytes(&record.plan.ca_sha256)?,
        request_id: digest_bytes(&record.request_id)?,
        epoch: record.epoch,
        phase: match record.phase {
            EnrollmentPhase::Pending => pb::fleet_state::Phase::Pending,
            EnrollmentPhase::Requested => pb::fleet_state::Phase::Requested,
            EnrollmentPhase::Active => pb::fleet_state::Phase::Active,
            EnrollmentPhase::Revoked => pb::fleet_state::Phase::Revoked,
        } as i32,
        controller_id: record.controller_id.clone(),
        csr_der: record.csr_der.clone(),
        client_key_sha256: digest_bytes(&record.client_key_sha256)?,
        client_cert_der: record.client_cert_der.clone(),
    };
    kronik_proto::control::validate_fleet_state(&state).map_err(internal)?;
    Ok(state)
}

fn record_from_state(state: pb::FleetState) -> Result<EnrollmentRecord, ApiError> {
    kronik_proto::control::validate_fleet_state(&state).map_err(internal)?;
    let phase = match pb::fleet_state::Phase::try_from(state.phase).map_err(internal)? {
        pb::fleet_state::Phase::Pending => EnrollmentPhase::Pending,
        pb::fleet_state::Phase::Requested => EnrollmentPhase::Requested,
        pb::fleet_state::Phase::Active => EnrollmentPhase::Active,
        pb::fleet_state::Phase::Revoked => EnrollmentPhase::Revoked,
        pb::fleet_state::Phase::Unspecified => return Err(bad("missing typed fleet phase")),
    };
    Ok(EnrollmentRecord {
        plan: EnrollmentPlan {
            controller_url: state.controller_origin,
            identity: FleetIdentity {
                installation: state.installation,
                node: state.node,
                cluster: state.cluster,
            },
            scopes: state.scopes,
            ca_sha256: kronik_core::ids::hex(&state.ca_sha256),
        },
        request_id: kronik_core::ids::hex(&state.request_id),
        epoch: state.epoch,
        phase,
        controller_id: state.controller_id,
        csr_der: state.csr_der,
        client_key_sha256: kronik_core::ids::hex(&state.client_key_sha256),
        client_cert_der: state.client_cert_der,
    })
}

fn load_record(node: &Node) -> Result<Option<EnrollmentRecord>, ApiError> {
    match node.control_operation(ControlKind::Fleet)? {
        Some((_, pb::audit_event::Operation::FleetState(state))) => {
            record_from_state(state).map(Some)
        }
        None => Ok(None),
        _ => Err(internal("fleet control family mismatch")),
    }
}

impl Fleet {
    pub(crate) fn validate_attachment(&self, api: &crate::Api) -> Result<(), ApiError> {
        if !Arc::ptr_eq(&self.node, &api.node)
            || api
                .tokens
                .as_ref()
                .is_none_or(|tokens| !Arc::ptr_eq(&self.tokens, tokens))
        {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "fleet service belongs to another physical API",
            ));
        }
        self.tokens.execution()?.check()
    }

    pub async fn open(
        node: Arc<Node>,
        tokens: Arc<TokenStore>,
        mut config: FleetConfig,
        custody: PathBuf,
        startup_original: kronik_core::authority::AuthLease,
    ) -> Result<Arc<Self>, ApiError> {
        startup_original.check()?;
        if tokens.metadata_revision()?.is_some() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "native fleet cannot select a member token authority",
            ));
        }
        config.scopes = tokens::parse_scopes(&config.scopes)?
            .into_iter()
            .map(|scope| scope.as_str().to_owned())
            .collect();
        if enrollment::canonical_controller_url(&config.controller.url).map_err(fleet_error)?
            != config.controller.url
        {
            return Err(bad("fleet controller URL must be canonical"));
        }
        match node.control_operation(ControlKind::Installation)? {
            Some((_, pb::audit_event::Operation::InstallationIdentity(identity)))
                if identity.installation == config.identity.installation => {}
            _ => {
                return Err(bad(
                    "fleet installation differs from durable installation identity",
                ));
            }
        }
        let record = load_record(&node)?;
        let authority = EpochAuthority::new(record.as_ref().map_or(0, |r| r.epoch));
        let service = Arc::new(Self {
            node,
            tokens,
            config,
            custody,
            startup_original,
            operation: tokio::sync::Mutex::new(()),
            enrollment_http: Arc::new(tokio::sync::Semaphore::new(1)),
            authority,
            changed: Arc::new(tokio::sync::Notify::new()),
            admission: RwLock::new(None),
            request: RwLock::new(record.clone().map(Arc::new)),
            custody_error: RwLock::new(None),
        });
        // Any crash before Active leaves a denied bearer; Requested alone may resume.
        let keep = record.as_ref().filter(|r| {
            matches!(
                r.phase,
                EnrollmentPhase::Active | EnrollmentPhase::Requested
            )
        });
        service.recover_tokens(keep).await?;
        if let Some(record) = record
            .as_ref()
            .filter(|r| r.phase == EnrollmentPhase::Active)
        {
            let client =
                enrollment::load_controller(service.node.env(), &service.config.controller)
                    .await
                    .map_err(fleet_error)?;
            let plan = client
                .plan(
                    service.config.identity.clone(),
                    tokens::parse_scopes(&service.config.scopes)?
                        .iter()
                        .map(|s| s.as_str().to_owned())
                        .collect(),
                )
                .map_err(fleet_error)?;
            if plan == record.plan {
                match service.bearer(record).await {
                    Ok(_) => {
                        service.publish_record(record)?;
                    }
                    Err(error) if error.code == ErrorCode::Unavailable => {
                        service.publish_custody_denial()?
                    }
                    Err(error) => return Err(error),
                }
            }
        } else if let Some(record) = &record {
            service.publish_record(record)?;
        }
        service.startup_original.check()?;
        Ok(service)
    }

    async fn lock_operation(
        &self,
        authority: &kronik_core::authority::AuthLease,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, ApiError> {
        let held = tokio::select! {
            biased;
            () = authority.cancelled() => return Err(ApiError::new(ErrorCode::Unauthenticated, "fleet request revoked while queued")),
            held = self.operation.lock() => held,
        };
        authority.check()?;
        Ok(held)
    }

    fn record(&self) -> Result<Option<EnrollmentRecord>, ApiError> {
        load_record(&self.node)
    }

    pub fn status(&self) -> Result<FleetStatus, ApiError> {
        Ok(self.status_for_record(self.record()?))
    }

    fn status_for_record(&self, state: Option<EnrollmentRecord>) -> FleetStatus {
        let admitting = state
            .as_ref()
            .is_some_and(|record| self.admitting_record(record, None));
        let admission_error = self
            .custody_error
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|code| code.as_str());
        FleetStatus {
            configured: true,
            dry_run: false,
            admitting,
            admission_error,
            recovery_hint: admission_error.map(|_| CUSTODY_RECOVERY_HINT),
            state,
            plan: None,
        }
    }

    fn admitting_record(&self, record: &EnrollmentRecord, token_name: Option<&str>) -> bool {
        let admitted = *self.admission.read().unwrap_or_else(|e| e.into_inner());
        if self.startup_original.check().is_err() {
            return false;
        }
        if !self
            .tokens
            .execution()
            .is_ok_and(|execution| execution.check().is_ok())
            || record.phase != EnrollmentPhase::Active
            || admitted != Some(record.epoch)
            || record.plan.controller_url != self.config.controller.url
            || record.plan.identity != self.config.identity
            || record.plan.scopes != self.config.scopes
        {
            return false;
        }
        let request = self.request.read().unwrap_or_else(|e| e.into_inner());
        request.as_deref() == Some(record)
            && self.tokens.fleet_receipt_is_live(
                record.epoch,
                &record.request_id,
                &record.plan.scopes,
                token_name,
            )
    }

    /// Called at ordinary authentication and again under final mutation admission.
    pub fn allows_token_id(&self, token_id: &str) -> bool {
        let Some(managed) = self.tokens.fleet_token(token_id) else {
            return true;
        };
        self.record().ok().flatten().is_some_and(|record| {
            managed.epoch == record.epoch
                && managed.request_id == record.request_id
                && self.admitting_record(&record, token_id.strip_prefix("token:"))
        })
    }

    pub fn accepts(&self, guard: &EpochGuard) -> bool {
        guard.check().is_ok()
            && self.record().ok().flatten().is_some_and(|record| {
                record.epoch == guard.epoch()
                    && guard.request_id() == Some(record.request_id.as_str())
                    && self.admitting_record(&record, None)
            })
    }

    pub fn lease(
        self: &Arc<Self>,
        inner: kronik_core::authority::AuthLease,
        guard: Option<EpochGuard>,
        receipt: Arc<FleetToken>,
    ) -> kronik_core::authority::AuthLease {
        let epoch = Some(receipt.epoch);
        Arc::new(FleetLease {
            fleet: self.clone(),
            inner,
            guard,
            epoch,
            receipt,
        })
    }

    pub fn changes(&self) -> Arc<tokio::sync::Notify> {
        self.changed.clone()
    }
    fn auth_changes(&self) -> Arc<tokio::sync::Notify> {
        self.tokens.changes()
    }

    fn wake(&self) {
        self.changed.notify_waiters();
    }

    fn publish_record(&self, record: &EnrollmentRecord) -> Result<bool, ApiError> {
        let mut admitting = false;
        self.tokens.publish_auth_change(&mut || {
            self.startup_original.check()?;
            let exact = self
                .request
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref()
                == Some(record);
            admitting = exact
                && record.phase == EnrollmentPhase::Active
                && record.plan.controller_url == self.config.controller.url
                && record.plan.identity == self.config.identity
                && record.plan.scopes == self.config.scopes
                && self.tokens.fleet_receipt_is_live(
                    record.epoch,
                    &record.request_id,
                    &record.plan.scopes,
                    None,
                );
            self.authority.publish(record).map_err(fleet_error)?;
            *self.admission.write().unwrap_or_else(|e| e.into_inner()) =
                admitting.then_some(record.epoch);
            *self
                .custody_error
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            self.wake();
            Ok(())
        })?;
        Ok(admitting)
    }

    fn publish_custody_denial(&self) -> Result<(), ApiError> {
        self.tokens.publish_auth_change(&mut || {
            *self.admission.write().unwrap_or_else(|e| e.into_inner()) = None;
            *self
                .custody_error
                .write()
                .unwrap_or_else(|e| e.into_inner()) = Some(ErrorCode::Unavailable);
            self.wake();
            Ok(())
        })
    }

    fn audit(&self, token_id: &str, reason: &str) -> pb::Audit {
        pb::Audit {
            token_id: token_id.to_owned(),
            reason: reason.to_owned(),
            wall_time_ms: self.node.env().clock.wall_ms(),
        }
    }

    /// A durable ordinary intent is a cause, never permission to open the socket.
    pub fn control_opening_audit(
        &self,
        captured: &crate::CapturedRequest,
    ) -> impl Future<Output = Result<(), FleetError>> + Send + 'static + use<> {
        let node = self.node.clone();
        let target = self.config.identity.installation.clone();
        let audit = self.audit(
            &captured.caller.token_id,
            "open the configured outbound fleet control connection",
        );
        let original = captured.authority().clone();
        async move {
            node.record_audit_event_authorized(
                "fleet.control.open",
                &target,
                Default::default(),
                audit,
                original,
            )
            .await
            .map(|_| ())
            .map_err(|error| {
                if error.code == ErrorCode::Unauthenticated {
                    FleetError::Revoked
                } else {
                    FleetError::Unavailable
                }
            })
        }
    }

    async fn persist(
        self: &Arc<Self>,
        record: &EnrollmentRecord,
        token_id: &str,
        reason: &str,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<bool, ApiError> {
        let operation = pb::audit_event::Operation::FleetState(state_from_record(record)?);
        let authority = Arc::new(StateAuthority {
            fleet: self.clone(),
            inner: authority,
            record: Arc::new(record.clone()),
        });
        self.node
            .record_control_operation(operation, self.audit(token_id, reason), false, authority)
            .await?;
        let admitting = self.publish_record(record)?;
        self.wake();
        Ok(admitting)
    }

    async fn revoke_other_tokens(
        &self,
        token_id: &str,
        reason: &str,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<(), ApiError> {
        for meta in self.tokens.list()? {
            if meta.fleet.is_none() || meta.revoked.is_some() {
                continue;
            }
            self.tokens
                .revoke_authorized(
                    self.node.clone(),
                    &meta.name,
                    self.audit(token_id, reason),
                    false,
                    authority.clone(),
                )
                .await?;
        }
        Ok(())
    }

    async fn recover_tokens(&self, keep: Option<&EnrollmentRecord>) -> Result<(), ApiError> {
        self.startup_original.check()?;
        let (token_id, reason) = ("system:fleet-recovery", "recover durable fleet authority");
        for meta in self.tokens.list()? {
            let Some(managed) = &meta.fleet else {
                continue;
            };
            if meta.revoked.is_some()
                || keep.is_some_and(|record| {
                    managed.epoch == record.epoch && managed.request_id == record.request_id
                })
            {
                continue;
            }
            self.node
                .record_system_audit_event(
                    kronik_sched::SystemAudit::FleetRecovery,
                    &meta.name,
                    Default::default(),
                    self.audit(token_id, reason),
                    self.startup_original.clone(),
                )
                .await?;
            self.tokens
                .revoke_authorized(
                    self.node.clone(),
                    &meta.name,
                    self.audit(token_id, reason),
                    false,
                    self.startup_original.clone(),
                )
                .await?;
        }
        Ok(())
    }

    async fn bearer(&self, record: &EnrollmentRecord) -> Result<Zeroizing<String>, ApiError> {
        let bytes = Zeroizing::new(
            self.node
                .env()
                .fs
                .read_secure(self.custody.clone(), 4096)
                .await
                .map_err(|_| custody_unavailable())?,
        );
        let bearer = Zeroizing::new(
            std::str::from_utf8(&bytes)
                .map_err(|_| custody_unavailable())?
                .to_owned(),
        );
        if !self.tokens.fleet_credential_matches(
            &bearer,
            record.epoch,
            &record.request_id,
            &tokens::parse_scopes(&self.config.scopes)?,
        ) {
            return Err(custody_unavailable());
        }
        Ok(bearer)
    }

    pub async fn enroll(
        self: &Arc<Self>,
        token_id: &str,
        request: FleetEnrollRequest,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<FleetStatus, ApiError> {
        let (fleet, caller) = (self.clone(), token_id.to_owned());
        self.node
            .env()
            .spawn("fleet-enroll", async move {
                fleet.enroll_inner(&caller, request, authority).await
            })
            .await
            .ok_or_else(|| {
                ApiError::new(ErrorCode::Unavailable, "fleet enrollment worker stopped")
            })?
    }

    async fn enroll_inner(
        self: &Arc<Self>,
        token_id: &str,
        mut request: FleetEnrollRequest,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<FleetStatus, ApiError> {
        let one_time = request.token.take().map(Zeroizing::new);
        validate_caller(token_id, &request.reason)?;
        authority.check()?;
        if request.url != self.config.controller.url {
            return Err(bad("fleet URL must equal the pinned operator controller"));
        }
        let _operation = self.lock_operation(&authority).await?;
        let client = enrollment::load_controller(self.node.env(), &self.config.controller)
            .await
            .map_err(fleet_error)?;
        let scopes = tokens::parse_scopes(&self.config.scopes)?;
        let plan = client
            .plan(
                self.config.identity.clone(),
                scopes.iter().map(|s| s.as_str().to_owned()).collect(),
            )
            .map_err(fleet_error)?;
        validate_plan(&plan)?;
        let previous = self.record()?;
        let resume = previous
            .as_ref()
            .filter(|r| r.phase == EnrollmentPhase::Requested);
        if let Some(record) = resume {
            if record.plan != plan {
                return Err(bad(
                    "requested enrollment pins a different plan; revoke before rotation",
                ));
            }
            if one_time.as_ref().is_some_and(|s| !s.is_empty()) {
                return Err(bad("retry Requested enrollment without a one-time token"));
            }
        } else if !request.dry_run
            && one_time.as_ref().is_none_or(|s| {
                s.is_empty() || s.len() > 4096 || s.bytes().any(|b| b.is_ascii_control())
            })
        {
            return Err(bad("initial enrollment requires a bounded one-time token"));
        }
        if request.dry_run {
            let mut status = self.status_for_record(previous);
            status.dry_run = true;
            status.plan = Some(plan);
            return Ok(status);
        }
        let (record, bearer) = if let Some(record) = resume {
            self.node
                .record_audit_event_authorized(
                    "fleet.enroll",
                    &self.config.identity.installation,
                    Default::default(),
                    self.audit(token_id, &request.reason),
                    authority.clone(),
                )
                .await?;
            (record.clone(), self.bearer(record).await?)
        } else {
            self.node
                .record_audit_event_authorized(
                    "fleet.enroll",
                    &self.config.identity.installation,
                    Default::default(),
                    self.audit(token_id, &request.reason),
                    authority.clone(),
                )
                .await?;
            let record = EnrollmentRecord::prepare(
                self.node.env(),
                &client,
                plan,
                next_epoch(previous.as_ref())?,
            )
            .await
            .map_err(fleet_error)?;
            self.persist(&record, token_id, &request.reason, authority.clone())
                .await?;
            let continuation: kronik_core::authority::AuthLease = Arc::new(RequestAuthority {
                fleet: self.clone(),
                receipt: Arc::new(record.clone()),
                original: authority.clone(),
            });
            self.revoke_other_tokens(token_id, &request.reason, continuation.clone())
                .await?;
            let name = token_name(&record)?;
            let (_, bearer) = self
                .tokens
                .create_authorized(
                    self.node.clone(),
                    &name,
                    scopes,
                    self.audit(token_id, &request.reason),
                    false,
                    Some(tokens::FleetToken {
                        epoch: record.epoch,
                        request_id: record.request_id.clone(),
                    }),
                    continuation.clone(),
                )
                .await?;
            let bearer = Zeroizing::new(bearer.ok_or_else(|| internal("token not created"))?);
            if let Err(e) = self
                .node
                .env()
                .fs
                .write_secure(self.custody.clone(), bearer.as_bytes().to_vec())
                .await
            {
                self.revoke_other_tokens(token_id, &request.reason, continuation)
                    .await?;
                return Err(internal(e));
            }
            (record, bearer)
        };
        drop(_operation);
        let this = self.clone();
        let caller = token_id.to_owned();
        let reason = request.reason;
        let admission: kronik_core::authority::AuthLease = Arc::new(RequestAuthority {
            fleet: self.clone(),
            receipt: Arc::new(record.clone()),
            original: authority,
        });
        let completed = Arc::new(std::sync::Mutex::new(None));
        let callback_completed = completed.clone();
        let enrollment = enrollment::enroll(
            self.node.env(),
            &client,
            record,
            one_time,
            &bearer,
            admission.clone(),
            self.enrollment_http.clone(),
            |prepared| Box::pin(prepared.dispatch()),
            move |record| {
                let (this, caller, reason, authority) = (
                    this.clone(),
                    caller.clone(),
                    reason.clone(),
                    admission.clone(),
                );
                let completed = callback_completed.clone();
                Box::pin(async move {
                    let _operation = this
                        .lock_operation(&authority)
                        .await
                        .map_err(|_| FleetError::Revoked)?;
                    let current = this
                        .record()
                        .map_err(|_| FleetError::Persistence)?
                        .ok_or(FleetError::Persistence)?;
                    if current.epoch != record.epoch
                        || current.request_id != record.request_id
                        || !matches!(
                            current.phase,
                            EnrollmentPhase::Pending | EnrollmentPhase::Requested
                        )
                    {
                        return Err(FleetError::Revoked);
                    }
                    let admitting = this
                        .persist(&record, &caller, &reason, authority)
                        .await
                        .map_err(|_| FleetError::Persistence)?;
                    if record.phase == EnrollmentPhase::Active {
                        *completed.lock().unwrap_or_else(|e| e.into_inner()) = Some(admitting);
                    }
                    Ok(())
                })
            },
        );
        let accepted = enrollment.await.map_err(fleet_error)?;
        let admitting = completed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| internal("fleet completion missing"))?;
        Ok(FleetStatus::acknowledged(accepted, admitting))
    }

    pub async fn revoke(
        self: &Arc<Self>,
        token_id: &str,
        request: FleetRevokeRequest,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<FleetStatus, ApiError> {
        let (fleet, caller) = (self.clone(), token_id.to_owned());
        self.node
            .env()
            .spawn("fleet-revoke", async move {
                fleet.revoke_inner(&caller, request, authority).await
            })
            .await
            .ok_or_else(|| {
                ApiError::new(ErrorCode::Unavailable, "fleet revocation worker stopped")
            })?
    }

    async fn revoke_inner(
        self: &Arc<Self>,
        token_id: &str,
        request: FleetRevokeRequest,
        authority: kronik_core::authority::AuthLease,
    ) -> Result<FleetStatus, ApiError> {
        validate_caller(token_id, &request.reason)?;
        authority.check()?;
        let _operation = self.lock_operation(&authority).await?;
        let record = self.record()?.ok_or_else(|| bad("fleet is not enrolled"))?;
        if request.dry_run {
            let mut status = self.status_for_record(Some(record));
            status.dry_run = true;
            return Ok(status);
        }
        let revoked = if record.phase == EnrollmentPhase::Revoked {
            record
        } else {
            record.revoke().map_err(fleet_error)?
        };
        // Even an idempotent revoke commits this exact typed state before acknowledging it.
        self.persist(&revoked, token_id, &request.reason, authority)
            .await?;
        let cleanup = Arc::new(CleanupAuthority {
            fleet: self.clone(),
            receipt: Arc::new(revoked.clone()),
        });
        self.revoke_other_tokens(token_id, &request.reason, cleanup)
            .await?;
        Ok(FleetStatus::acknowledged(revoked, false))
    }

    pub async fn active_connection(
        &self,
    ) -> Result<
        Option<(
            ControllerClient,
            EnrollmentRecord,
            Zeroizing<String>,
            EpochGuard,
        )>,
        ApiError,
    > {
        let _operation = self.operation.lock().await;
        let Some(record) = self
            .record()?
            .filter(|r| r.phase == EnrollmentPhase::Active)
        else {
            return Ok(None);
        };
        if !self.admitting_record(&record, None) {
            return Ok(None);
        }
        let client = enrollment::load_controller(self.node.env(), &self.config.controller)
            .await
            .map_err(fleet_error)?;
        client.validate_plan(&record.plan).map_err(fleet_error)?;
        if client
            .plan(
                self.config.identity.clone(),
                tokens::parse_scopes(&self.config.scopes)?
                    .iter()
                    .map(|s| s.as_str().to_owned())
                    .collect(),
            )
            .map_err(fleet_error)?
            != record.plan
        {
            return Err(bad(
                "active fleet configuration changed; re-enroll to rotate",
            ));
        }
        let bearer = match self.bearer(&record).await {
            Ok(bearer) => bearer,
            Err(error) if error.code == ErrorCode::Unavailable => {
                self.publish_custody_denial()?;
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let guard = self.authority.guard();
        if !self.accepts(&guard) {
            return Ok(None);
        }
        Ok(Some((client, record, bearer, guard)))
    }
}

struct StateAuthority {
    fleet: Arc<Fleet>,
    inner: kronik_core::authority::AuthLease,
    record: Arc<EnrollmentRecord>,
}

impl kronik_core::authority::Authority for StateAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.inner.check()
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        self.inner.cancelled()
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.inner.admit(&mut || {
            effect()?;
            if self.record.phase != EnrollmentPhase::Active {
                *self
                    .fleet
                    .admission
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
            }
            *self
                .fleet
                .request
                .write()
                .unwrap_or_else(|e| e.into_inner()) = Some(self.record.clone());
            self.fleet.wake();
            self.fleet.tokens.notify_auth_change();
            Ok(())
        })
    }
}

/// Exact enrollment guard composed with its original ordinary caller, never replacement authority.
struct RequestAuthority {
    fleet: Arc<Fleet>,
    receipt: Arc<EnrollmentRecord>,
    original: kronik_core::authority::AuthLease,
}

impl RequestAuthority {
    fn current(&self) -> Result<(), ApiError> {
        self.original.check()?;
        if self
            .fleet
            .tokens
            .fleet_phase(self.receipt.epoch, &self.receipt.request_id)?
            .is_some_and(|phase| {
                !matches!(
                    phase,
                    pb::fleet_state::Phase::Pending | pb::fleet_state::Phase::Requested
                )
            })
        {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "fleet enrollment superseded or revoked",
            ));
        }
        let request = self.fleet.request.read().unwrap_or_else(|e| e.into_inner());
        if !request.as_ref().is_some_and(|r| {
            r.epoch == self.receipt.epoch
                && r.request_id == self.receipt.request_id
                && r.plan == self.receipt.plan
                && r.csr_der == self.receipt.csr_der
                && r.client_key_sha256 == self.receipt.client_key_sha256
                && matches!(
                    r.phase,
                    EnrollmentPhase::Pending | EnrollmentPhase::Requested
                )
        }) {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "fleet enrollment superseded or revoked",
            ));
        }
        Ok(())
    }
}

impl kronik_core::authority::Authority for RequestAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.current()
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let this = Self {
            fleet: self.fleet.clone(),
            receipt: self.receipt.clone(),
            original: self.original.clone(),
        };
        let changes = this.fleet.changes();
        let auth_changes = this.fleet.auth_changes();
        Box::pin(async move {
            let mut original = this.original.cancelled();
            loop {
                let notified = changes.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let auth_notified = auth_changes.notified();
                tokio::pin!(auth_notified);
                auth_notified.as_mut().enable();
                if this.current().is_err() {
                    return;
                }
                tokio::select! {
                biased;
                () = original.as_mut() => return, () = notified => {}, () = auth_notified => {} }
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.fleet.tokens.publish_auth_change(&mut || {
            self.current()?;
            effect()
        })
    }
}

/// Only private token-revocation cleanup uses this exact admitted state receipt.
struct CleanupAuthority {
    fleet: Arc<Fleet>,
    receipt: Arc<EnrollmentRecord>,
}

impl CleanupAuthority {
    fn current(&self) -> Result<(), ApiError> {
        self.fleet.startup_original.check()?;
        if self
            .fleet
            .tokens
            .fleet_phase(self.receipt.epoch, &self.receipt.request_id)?
            .is_some_and(|phase| phase != pb::fleet_state::Phase::Revoked)
        {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "fleet cleanup superseded",
            ));
        }
        if self
            .fleet
            .request
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref()
            != Some(self.receipt.as_ref())
        {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "fleet cleanup superseded",
            ));
        }
        Ok(())
    }
}

impl kronik_core::authority::Authority for CleanupAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.current()
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let this = Self {
            fleet: self.fleet.clone(),
            receipt: self.receipt.clone(),
        };
        let changed = this.fleet.changes();
        let auth_changes = this.fleet.auth_changes();
        Box::pin(async move {
            let mut execution = this.fleet.startup_original.cancelled();
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let auth_notified = auth_changes.notified();
                tokio::pin!(auth_notified);
                auth_notified.as_mut().enable();
                if this.current().is_err() {
                    return;
                }
                tokio::select! {
                biased;
                () = execution.as_mut() => return, () = notified => {}, () = auth_notified => {} }
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.fleet.tokens.publish_auth_change(&mut || {
            self.current()?;
            effect()
        })
    }
}

struct FleetLease {
    fleet: Arc<Fleet>,
    inner: kronik_core::authority::AuthLease,
    guard: Option<EpochGuard>,
    epoch: Option<u64>,
    receipt: Arc<FleetToken>,
}

impl FleetLease {
    fn current(&self, admitted: Option<u64>) -> Result<(), ApiError> {
        let exact = self
            .fleet
            .request
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|record| {
                record.phase == EnrollmentPhase::Active
                    && record.epoch == self.receipt.epoch
                    && record.request_id == self.receipt.request_id
            });
        if !exact
            || self.epoch != admitted
            || self.guard.as_ref().is_some_and(|g| g.check().is_err())
        {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "fleet authority revoked or superseded",
            ));
        }
        Ok(())
    }
}

impl kronik_core::authority::Authority for FleetLease {
    fn check(&self) -> Result<(), ApiError> {
        self.current(
            *self
                .fleet
                .admission
                .read()
                .unwrap_or_else(|e| e.into_inner()),
        )?;
        self.inner.check()
    }

    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let this = FleetLease {
            fleet: self.fleet.clone(),
            inner: self.inner.clone(),
            guard: self.guard.clone(),
            epoch: self.epoch,
            receipt: self.receipt.clone(),
        };
        let changes = this.fleet.changes();
        Box::pin(async move {
            loop {
                let notified = changes.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if this
                    .current(
                        *this
                            .fleet
                            .admission
                            .read()
                            .unwrap_or_else(|e| e.into_inner()),
                    )
                    .is_err()
                {
                    return;
                }
                tokio::select! {
                    biased;
                    _ = this.inner.cancelled() => return,
                    _ = notified => {},
                }
            }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.inner.admit(&mut || {
            let admitted = *self
                .fleet
                .admission
                .read()
                .unwrap_or_else(|e| e.into_inner());
            self.current(admitted)?;
            effect()
        })
    }
}

impl crate::Api {
    pub(crate) fn fleet_status(&self) -> crate::Result<crate::ApiResponse> {
        let status = match &self.fleet {
            Some(fleet) => {
                fleet.validate_attachment(self)?;
                fleet.status()?
            }
            None => FleetStatus {
                configured: false,
                dry_run: false,
                admitting: false,
                admission_error: None,
                recovery_hint: None,
                state: None,
                plan: None,
            },
        };
        crate::ok(&status)
    }

    pub(crate) async fn fleet_enroll(
        &self,
        req: &crate::AuthorizedRequest,
    ) -> crate::Result<crate::ApiResponse> {
        let request: FleetEnrollRequest = crate::json(&req.body)?;
        // I12: the reason is validated before any service lookup or effect.
        crate::reason(&request.reason)?;
        let fleet = self.fleet_service()?;
        let status = fleet
            .enroll(&req.token_id, request, req.authority.clone())
            .await?;
        crate::ok(&status)
    }

    pub(crate) async fn fleet_revoke(
        &self,
        req: &crate::AuthorizedRequest,
    ) -> crate::Result<crate::ApiResponse> {
        let request: FleetRevokeRequest = crate::json(&req.body)?;
        // I12: the reason is validated before any service lookup or effect.
        crate::reason(&request.reason)?;
        let fleet = self.fleet_service()?;
        let status = fleet
            .revoke(&req.token_id, request, req.authority.clone())
            .await?;
        crate::ok(&status)
    }
}

#[cfg(test)]
mod tests {
    // The fixtures race real time and spawned tasks around admitted work:
    // the direct calls are the harness, not daemon paths.
    #![allow(clippy::disallowed_methods)]

    use super::*;
    use crate::tokens::Change;
    use kronik_core::env::{
        BoxFuture, EntropySource, Env, HttpRequest, HttpResponse, Net, NetError, TlsConfig,
    };
    use prost::bytes::Bytes;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[cfg(feature = "server")]
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct Network {
        requests: Arc<Mutex<Vec<HttpRequest>>>,
        request_bodies: Arc<Mutex<Vec<Bytes>>>,
        issuer: Arc<Mutex<Option<rcgen::Issuer<'static, rcgen::KeyPair>>>>,
        reply: Arc<AtomicBool>,
        reflection: Arc<AtomicUsize>,
        hold: Arc<Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
        started: Arc<tokio::sync::Notify>,
    }

    impl Network {
        fn certificate(
            &self,
            csr: &[u8],
            plan: &EnrollmentPlan,
            request: &str,
            epoch: u64,
        ) -> Vec<u8> {
            use rcgen::{
                CertificateParams, CertificateSigningRequestParams, DnType,
                ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType,
            };
            let csr = CertificateSigningRequestParams::from_der(
                &rustls_pki_types::CertificateSigningRequestDer::from(csr),
            )
            .unwrap();
            let mut params = CertificateParams::default();
            params.distinguished_name = rcgen::DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, &plan.identity.installation);
            if let Some(cluster) = &plan.identity.cluster {
                params
                    .distinguished_name
                    .push(DnType::OrganizationName, cluster);
            }
            if let Some(node) = &plan.identity.node {
                params
                    .distinguished_name
                    .push(DnType::OrganizationalUnitName, node);
            }
            params.subject_alt_names = vec![SanType::URI(
                format!("urn:kronik:fleet:request:{request}:{epoch}")
                    .try_into()
                    .unwrap(),
            )];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params
                .signed_by(
                    &csr.public_key,
                    self.issuer.lock().unwrap().as_ref().unwrap(),
                )
                .unwrap()
                .der()
                .to_vec()
        }

        fn response(
            &self,
            body: &[u8],
            headers: &[(String, String)],
        ) -> Result<HttpResponse, NetError> {
            if self.reply.load(Ordering::SeqCst) {
                let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
                let plan: EnrollmentPlan = serde_json::from_value(value["plan"].clone()).unwrap();
                let csr: Vec<u8> = serde_json::from_value(value["csr_der"].clone()).unwrap();
                let certificate = self.certificate(
                    &csr,
                    &plan,
                    value["request_id"].as_str().unwrap(),
                    value["epoch"].as_u64().unwrap(),
                );
                let controller_id = match self.reflection.load(Ordering::SeqCst) {
                    0 => plan.ca_sha256,
                    1 => value["api_bearer"].as_str().unwrap().to_owned(),
                    2 => headers
                        .iter()
                        .find(|(name, _)| name == "authorization")
                        .unwrap()
                        .1
                        .strip_prefix("Bearer ")
                        .unwrap()
                        .to_owned(),
                    _ => panic!("invalid fixture reflection mode"),
                };
                for key in ["api_bearer", "csr_der", "client_key_sha256"] {
                    value.as_object_mut().unwrap().remove(key);
                }
                value["controller_id"] = controller_id.into();
                value["client_cert_der"] = serde_json::to_value(certificate).unwrap();
                Ok(HttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: serde_json::to_vec(&value).unwrap().into(),
                })
            } else {
                Err(NetError::Io("lost enrollment response".into()))
            }
        }
    }

    impl Net for Network {
        fn with_pinned_tls(&self, tls: TlsConfig) -> Result<Arc<dyn Net>, NetError> {
            assert!(!tls.ca.is_empty());
            Ok(Arc::new(self.clone()))
        }
        fn http(
            &self,
            _request: HttpRequest,
        ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            Box::pin(async { Err(NetError::Io("unscoped enrollment HTTP is forbidden".into())) })
        }

        fn http_authorized(
            &self,
            request: HttpRequest,
            original: kronik_core::authority::AuthLease,
        ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            let network = self.clone();
            Box::pin(async move {
                let HttpRequest {
                    method,
                    url,
                    headers,
                    body,
                    max_response_bytes,
                } = request;
                original
                    .check()
                    .map_err(|_| NetError::Connect("HTTP authorization refused".into()))?;
                if body.len() > enrollment::MAX_ENROLLMENT_BYTES {
                    return Err(NetError::TooLarge);
                }
                let response = network.response(&body, &headers);
                let hold = network.hold.lock().unwrap().clone();
                let mut request = Some(HttpRequest {
                    method,
                    url,
                    headers,
                    body: body.clone(),
                    max_response_bytes,
                });
                let mut captured_body = Some(body);
                original
                    .admit(&mut || {
                        network
                            .requests
                            .lock()
                            .unwrap()
                            .push(request.take().unwrap());
                        network
                            .request_bodies
                            .lock()
                            .unwrap()
                            .push(captured_body.take().unwrap());
                        network.started.notify_waiters();
                        Ok(())
                    })
                    .map_err(|_| NetError::Connect("HTTP authorization refused".into()))?;
                let _original = original;
                if let Some(hold) = hold {
                    hold.acquire_owned().await.unwrap().forget();
                }
                response
            })
        }
    }

    struct CountEntropy {
        source: Arc<dyn EntropySource>,
        count: Arc<AtomicUsize>,
    }
    impl EntropySource for CountEntropy {
        fn fill(&self, bytes: &mut [u8]) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.source.fill(bytes);
        }
    }

    fn authority(fleet: &Arc<Fleet>) -> kronik_core::authority::AuthLease {
        crate::auth::Authenticator::capture(
            &tokens::TokenAuthenticator::new(fleet.tokens.clone()),
            &crate::ApiRequest {
                method: "POST".into(),
                path: "/v1/fleet/enroll".into(),
                query: String::new(),
                body: Vec::new(),
                token_id: "unix:uid=0".into(),
                bearer: None,
            },
            crate::auth::Scope::Admin,
        )
        .unwrap()
        .authority
    }

    async fn setup() -> (tempfile::TempDir, Arc<Fleet>, Network, Arc<AtomicUsize>) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let network = Network::default();
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.net = Arc::new(network.clone());
        let count = Arc::new(AtomicUsize::new(0));
        env.entropy = Arc::new(CountEntropy {
            source: env.entropy.clone(),
            count: count.clone(),
        });
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        node.record_installation_identity(pb::InstallationIdentity {
            installation: "installation-test".into(),
        })
        .await
        .unwrap();
        let mut root_params = rcgen::CertificateParams::default();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let root_key = kronik_core::identity::ed25519_key(&[31; 32]).unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        *network.issuer.lock().unwrap() = Some(rcgen::Issuer::new(root_params, root_key));
        let mut ca = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        ca.write_all(root.pem().as_bytes()).unwrap();
        let ca_path = dir.path().join("ca.pem");
        ca.persist(&ca_path).unwrap();
        let keys = dir.path().join("keys");
        let mut tokens = TokenStore::open_file(&keys.join("tokens.db")).unwrap();
        tokens
            .bind_before_any_issuer(node.publication_domain())
            .unwrap();
        let startup_original = node.local_operator_authority().unwrap();
        tokens
            .bind_execution_before_any_issuer(&node.publication_domain(), startup_original.clone())
            .unwrap();
        let tokens = Arc::new(tokens);
        let config = FleetConfig {
            controller: ControllerConfig {
                url: "https://controller.test".into(),
                ca_file: ca_path,
                client_key_file: keys.join("fleet/client.key"),
            },
            identity: FleetIdentity {
                installation: "installation-test".into(),
                node: None,
                cluster: None,
            },
            scopes: vec!["read".into(), "fork".into()],
        };
        let fleet = Fleet::open(
            node,
            tokens,
            config,
            keys.join("fleet/bearer"),
            startup_original,
        )
        .await
        .unwrap();
        (dir, fleet, network, count)
    }

    #[tokio::test]
    async fn startup_recovery_revokes_the_actual_orphan_under_its_retained_original() {
        let (_dir, fleet, network, _) = setup().await;
        fleet
            .tokens
            .create_with_fleet(
                "startup-orphan",
                [crate::auth::Scope::Read].into(),
                [66; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "an actual interrupted enrollment fixture",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
                Some(FleetToken {
                    epoch: 91,
                    request_id: "ab".repeat(32),
                }),
            )
            .unwrap();
        let before = fleet.node.applied_lsn();
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        let orphan = fleet
            .tokens
            .list()
            .unwrap()
            .into_iter()
            .find(|row| row.name == "startup-orphan")
            .unwrap();
        assert!(orphan.revoked.is_some());
        assert!(!reopened.status().unwrap().admitting);
        assert!(network.requests.lock().unwrap().is_empty());
        let mut durable_recovery = false;
        fleet
            .node
            .reader()
            .read(before + 1, fleet.node.applied_lsn(), |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record
                    && event.action == "token.revoke"
                    && event.target == "startup-orphan"
                {
                    let audit = event.audit.unwrap();
                    assert_eq!(audit.token_id, "system:fleet-recovery");
                    durable_recovery = true;
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(durable_recovery);
    }

    #[tokio::test]
    async fn stopped_startup_original_cannot_reconcile_or_publish_a_new_service() {
        let (_dir, fleet, network, _) = setup().await;
        fleet
            .tokens
            .create_with_fleet(
                "startup-orphan",
                [crate::auth::Scope::Read].into(),
                [67; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "retain an actual denied recovery fixture",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
                Some(FleetToken {
                    epoch: 92,
                    request_id: "cd".repeat(32),
                }),
            )
            .unwrap();
        let startup_original = fleet.startup_original.clone();
        fleet.node.stop_native_execution().unwrap();
        let before = fleet.node.applied_lsn();
        let denied = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            startup_original,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(denied.code, ErrorCode::Unavailable);
        assert_eq!(fleet.node.applied_lsn(), before);
        assert!(
            fleet
                .tokens
                .list()
                .unwrap()
                .into_iter()
                .find(|row| row.name == "startup-orphan")
                .unwrap()
                .revoked
                .is_none()
        );
        assert!(network.requests.lock().unwrap().is_empty());
        let mut following = 0;
        fleet
            .node
            .reader()
            .read(before + 1, u64::MAX, |_| {
                following += 1;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(following, 0);
    }

    fn request(token: Option<&str>, dry_run: bool) -> FleetEnrollRequest {
        FleetEnrollRequest {
            url: "https://controller.test".into(),
            token: token.map(str::to_owned),
            reason: "connect owned controller".into(),
            dry_run,
        }
    }

    #[tokio::test]
    async fn current_root_fleet_routes_require_ordinary_admin_before_any_effect() {
        use crate::auth::Scope;
        let (_directory, fleet, network, entropy) = setup().await;
        let (_, bearer) = fleet
            .tokens
            .create(
                "fleet-reader",
                [Scope::Read].into(),
                [61; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "ordinary reader fixture",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let api = crate::Api::new(fleet.node.clone())
            .with_tokens(fleet.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        let before = fleet.node.applied_lsn();
        let random = entropy.load(Ordering::SeqCst);
        for (method, path) in [
            ("GET", "/v1/fleet"),
            ("POST", "/v1/fleet/enroll"),
            ("POST", "/v1/fleet/revoke"),
        ] {
            let response = api
                .handle(crate::ApiRequest {
                    method: method.into(),
                    path: path.into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: String::new(),
                    bearer: bearer.clone(),
                })
                .await;
            assert_eq!(response.status, 403);
        }
        assert_eq!(fleet.node.applied_lsn(), before);
        assert_eq!(entropy.load(Ordering::SeqCst), random);
        assert!(network.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn current_root_named_managed_capture_uses_the_actual_fleet_and_original_wal_fence() {
        use crate::auth::Scope;
        let (_directory, fleet, network, _entropy) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        let accepted = fleet
            .enroll(
                "unix:uid=0",
                request(Some("owned-once"), false),
                authority(&fleet),
            )
            .await
            .unwrap()
            .state
            .unwrap();
        let name = token_name(&accepted).unwrap();
        let api = crate::Api::new(fleet.node.clone())
            .with_tokens(fleet.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        let captured = api
            .capture_context(fleet.tokens.capture_name(&name, Scope::Read).unwrap(), None)
            .unwrap();
        assert_eq!(captured.caller.token_id, format!("token:{name}"));
        let audit = || {
            fleet.audit(
                &captured.caller.token_id,
                "exercise the original managed publication",
            )
        };
        let accepted_lsn = fleet
            .node
            .record_audit_event_authorized(
                "test.named-fleet",
                &name,
                Default::default(),
                audit(),
                captured.authority.clone(),
            )
            .await
            .unwrap();
        assert_eq!(fleet.node.applied_lsn(), accepted_lsn);
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "revoke exact named managed operation".into(),
                    dry_run: false,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        fleet
            .node
            .env()
            .timeout(
                std::time::Duration::from_secs(5),
                captured.authority.cancelled(),
            )
            .await
            .unwrap();
        let fenced = fleet.node.applied_lsn();
        assert!(
            fleet
                .node
                .record_audit_event_authorized(
                    "test.named-fleet",
                    "must-not-append",
                    Default::default(),
                    audit(),
                    captured.authority.clone()
                )
                .await
                .is_err()
        );
        assert_eq!(fleet.node.applied_lsn(), fenced);
        assert!(
            fleet
                .tokens
                .capture_name(&name, Scope::Read)
                .and_then(|captured| api.capture_context(captured, None))
                .is_err()
        );
    }

    #[tokio::test]
    async fn current_root_fleet_provider_rejects_another_actual_node_or_token_store() {
        let (directory, fleet, _network, _entropy) = setup().await;
        let api = crate::Api::new(fleet.node.clone())
            .with_tokens(fleet.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        assert!(Arc::ptr_eq(api.fleet_service().unwrap(), &fleet));
        let (_other_directory, other, _network, _entropy) = setup().await;
        let wrong_node = crate::Api::new(other.node.clone())
            .with_tokens(other.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        assert_eq!(
            wrong_node.fleet_service().err().unwrap().code,
            ErrorCode::Unavailable
        );
        let mut isolated =
            TokenStore::open_file(&directory.path().join("isolated-tokens.db")).unwrap();
        isolated
            .bind_before_any_issuer(fleet.node.publication_domain())
            .unwrap();
        let wrong_tokens = crate::Api::new(fleet.node.clone())
            .with_tokens(Arc::new(isolated))
            .unwrap()
            .with_fleet(fleet);
        assert_eq!(
            wrong_tokens.fleet_service().err().unwrap().code,
            ErrorCode::Unavailable
        );
    }

    #[tokio::test]
    async fn admitted_request_and_cleanup_never_outlive_the_original_execution() {
        for cleanup in [false, true] {
            let (_dir, fleet, _network, _entropy) = setup().await;
            assert!(
                fleet
                    .enroll(
                        "unix:uid=0",
                        request(Some("private-once"), false),
                        authority(&fleet)
                    )
                    .await
                    .is_err()
            );
            assert_eq!(
                fleet.record().unwrap().unwrap().phase,
                EnrollmentPhase::Requested
            );
            if cleanup {
                fleet
                    .revoke(
                        "unix:uid=0",
                        FleetRevokeRequest {
                            reason: "fence owned request".into(),
                            dry_run: false,
                        },
                        authority(&fleet),
                    )
                    .await
                    .unwrap();
            }
            let receipt = Arc::new(fleet.record().unwrap().unwrap());
            let lease: kronik_core::authority::AuthLease = if cleanup {
                Arc::new(CleanupAuthority {
                    fleet: fleet.clone(),
                    receipt,
                })
            } else {
                Arc::new(RequestAuthority {
                    fleet: fleet.clone(),
                    receipt,
                    original: authority(&fleet),
                })
            };
            lease.check().unwrap();
            let before = fleet.node.applied_lsn();
            fleet.node.stop_native_execution().unwrap();
            assert_eq!(lease.check().unwrap_err().code, ErrorCode::Unavailable);
            fleet
                .node
                .env()
                .timeout(std::time::Duration::from_secs(1), lease.cancelled())
                .await
                .unwrap();
            let denied = fleet
                .node
                .record_audit_event_authorized(
                    "test.denied",
                    "stopped-continuation",
                    Default::default(),
                    fleet.audit("unix:uid=0", "must not enqueue"),
                    lease,
                )
                .await
                .unwrap_err();
            assert_eq!(denied.code, ErrorCode::Unavailable);
            assert_eq!(fleet.node.applied_lsn(), before);
            assert!(fleet.node.fatal().is_none());
            let mut following = 0;
            fleet
                .node
                .reader()
                .read(before + 1, u64::MAX, |_| {
                    following += 1;
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(following, 0);
        }
    }

    #[tokio::test]
    async fn revoked_queued_enrollment_cancels_before_unlock_and_never_writes_or_connects() {
        use crate::auth::{Authenticator as _, Scope};
        use std::future::Future as _;
        for dry_run in [false, true] {
            let (_dir, fleet, network, entropy) = setup().await;
            let change = Change {
                by: "unix:uid=0",
                reason: "queued enrollment fixture",
                wall_ms: fleet.node.env().clock.wall_ms(),
            };
            let (_, secret) = fleet
                .tokens
                .create("queued", [Scope::Admin].into(), [17; 32], &change, false)
                .unwrap();
            let captured = tokens::TokenAuthenticator::new(fleet.tokens.clone())
                .capture(
                    &crate::ApiRequest {
                        method: "POST".into(),
                        path: "/v1/fleet/enroll".into(),
                        query: String::new(),
                        body: Vec::new(),
                        token_id: "tcp:fixture".into(),
                        bearer: secret,
                    },
                    Scope::Admin,
                )
                .unwrap();
            let _held = fleet.operation.lock().await;
            let before = fleet.node.applied_lsn();
            let random = entropy.load(Ordering::SeqCst);
            let queued = fleet.enroll_inner(
                &captured.caller.token_id,
                request(Some("private-once"), dry_run),
                captured.authority,
            );
            tokio::pin!(queued);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(queued.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            fleet.tokens.revoke("queued", &change, false).unwrap();
            let denied = fleet
                .node
                .env()
                .timeout(std::time::Duration::from_secs(1), queued.as_mut())
                .await
                .unwrap()
                .err()
                .unwrap();
            assert_eq!(denied.code, ErrorCode::Unauthenticated);
            assert_eq!(entropy.load(Ordering::SeqCst), random);
            assert!(network.requests.lock().unwrap().is_empty());
            assert_eq!(fleet.node.applied_lsn(), before);
            let following = fleet
                .node
                .record_audit_event_authorized(
                    "test.following",
                    "queue-proof",
                    Default::default(),
                    fleet.audit("unix:uid=0", "following authorized record"),
                    authority(&fleet),
                )
                .await
                .unwrap();
            let mut actions = Vec::new();
            fleet
                .node
                .reader()
                .read(before + 1, following, |record| {
                    if let kronik_proto::Record::AuditEvent(event) = &record.record {
                        actions.push(event.action.clone());
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(actions, ["test.following"]);
        }
    }

    #[tokio::test]
    async fn dry_run_has_no_entropy_credentials_network_or_history() {
        let (_dir, fleet, network, entropy) = setup().await;
        let lsn = fleet.node.applied_lsn();
        let random = entropy.load(Ordering::SeqCst);
        let preview = fleet
            .enroll("unix:uid=0", request(None, true), authority(&fleet))
            .await
            .unwrap();
        assert!(preview.dry_run);
        assert!(preview.state.is_none());
        assert_eq!(fleet.node.applied_lsn(), lsn);
        assert_eq!(entropy.load(Ordering::SeqCst), random);
        assert!(network.requests.lock().unwrap().is_empty());
        assert!(fleet.tokens.list().unwrap().is_empty());
        assert!(!fleet.custody.exists());
        assert!(!fleet.config.controller.client_key_file.exists());
        let mut wrong = request(Some("once"), true);
        wrong.url = "https://attacker.test".into();
        assert!(
            fleet
                .enroll("unix:uid=0", wrong, authority(&fleet))
                .await
                .is_err()
        );
        assert_eq!(fleet.node.applied_lsn(), lsn);
    }

    #[tokio::test]
    async fn requested_restart_preserves_request_and_bearer_without_one_time_reuse() {
        let (_dir, fleet, network, _entropy) = setup().await;
        assert!(
            fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("once"), false),
                    authority(&fleet)
                )
                .await
                .is_err()
        );
        let requested = fleet.record().unwrap().unwrap();
        assert_eq!(requested.phase, EnrollmentPhase::Requested);
        let bearer = fleet.bearer(&requested).await.unwrap();
        assert!(!fleet.allows_token_id(&fleet.tokens.list().unwrap()[0].token_id()));
        let state =
            record_from_state(fleet.node.store().db().fleet_state().unwrap().unwrap()).unwrap();
        let public = serde_json::to_string(&state).unwrap();
        assert!(!public.contains(bearer.as_str()));
        assert!(!public.contains("once"));
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            reopened.bearer(&requested).await.unwrap().as_str(),
            bearer.as_str()
        );
        assert!(
            reopened
                .enroll("unix:uid=0", request(None, false), authority(&fleet))
                .await
                .is_err()
        );
        {
            let requests = network.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            let bodies = network.request_bodies.lock().unwrap();
            assert_eq!(bodies[0], bodies[1]);
            assert!(
                requests[0]
                    .headers
                    .iter()
                    .any(|(key, _)| key == "authorization")
            );
            assert!(
                !requests[1]
                    .headers
                    .iter()
                    .any(|(key, _)| key == "authorization")
            );
        }
        assert_eq!(reopened.record().unwrap().unwrap(), requested);
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&fleet.custody)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let custody = fleet.custody.clone();
        std::fs::remove_file(&custody).unwrap();
        std::os::unix::fs::symlink(&fleet.config.controller.ca_file, &custody).unwrap();
        assert!(reopened.bearer(&requested).await.is_err());
    }

    #[tokio::test]
    async fn revoke_fences_captured_authority_and_persists_before_restart() {
        let (_dir, fleet, network, _entropy) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        let enrolled = fleet
            .enroll(
                "unix:uid=0",
                request(Some("once"), false),
                authority(&fleet),
            )
            .await
            .unwrap();
        let active = enrolled.state.unwrap();
        assert_eq!(active.phase, EnrollmentPhase::Active);
        assert!(active.client_cert_der.is_some());
        assert_eq!(
            active.controller_id.as_deref(),
            Some(active.plan.ca_sha256.as_str())
        );
        let guard = fleet.authority.guard();
        let receipt = Arc::new(FleetToken {
            epoch: guard.epoch(),
            request_id: fleet.record().unwrap().unwrap().request_id,
        });
        let lease = fleet.lease(authority(&fleet), Some(guard.clone()), receipt);
        assert!(lease.check().is_ok());
        let before = fleet.node.applied_lsn();
        // An old managed receipt cannot acquire the current epoch during capture.
        let stale = fleet.lease(
            authority(&fleet),
            None,
            Arc::new(FleetToken {
                epoch: guard.epoch(),
                request_id: "retired-request".into(),
            }),
        );
        let denied = fleet
            .node
            .record_audit_event_authorized(
                "token.revoke",
                "stale-receipt",
                Default::default(),
                fleet.audit("token:old", "old managed request"),
                stale,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.code, ErrorCode::Unauthenticated);
        assert_eq!(fleet.node.applied_lsn(), before);
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "preview".into(),
                    dry_run: true,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        assert_eq!(fleet.node.applied_lsn(), before);
        assert!(lease.check().is_ok());
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "disconnect".into(),
                    dry_run: false,
                },
                lease.clone(),
            )
            .await
            .unwrap();
        let mut ran = false;
        assert!(
            lease
                .admit(&mut || {
                    ran = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!ran);
        assert!(guard.check().is_err());
        assert!(!fleet.allows_token_id(&fleet.tokens.list().unwrap()[0].token_id()));
        assert!(fleet.tokens.list().unwrap()[0].revoked.is_some());
        let record = fleet.record().unwrap().unwrap();
        assert_eq!(
            (record.epoch, record.phase),
            (active.epoch, EnrollmentPhase::Revoked)
        );
        assert_eq!(record.client_cert_der, active.client_cert_der);
        assert_eq!(record.request_id, active.request_id);
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.record().unwrap().unwrap(), record);
        assert!(!reopened.allows_token_id(&fleet.tokens.list().unwrap()[0].token_id()));
        assert!(reopened.active_connection().await.unwrap().is_none());
        let next = reopened
            .enroll(
                "unix:uid=0",
                request(Some("fresh-one-time"), false),
                authority(&reopened),
            )
            .await
            .unwrap()
            .state
            .unwrap();
        assert_eq!(next.epoch, active.epoch + 1);
        assert_ne!(next.request_id, active.request_id);
        assert!(guard.check().is_err());
        assert!(lease.check().is_err());
        assert!(reopened.authority.guard().check().is_ok());
    }

    #[tokio::test]
    async fn reenrollment_uses_latest_operator_ca_and_fences_the_old_epoch() {
        let (_dir, fleet, network, _entropy) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        let old = fleet
            .enroll(
                "unix:uid=0",
                request(Some("initial-once"), false),
                authority(&fleet),
            )
            .await
            .unwrap()
            .state
            .unwrap();
        let old_guard = fleet.authority.guard();
        let old_lease = fleet.lease(
            authority(&fleet),
            Some(old_guard.clone()),
            Arc::new(FleetToken {
                epoch: old.epoch,
                request_id: old.request_id.clone(),
            }),
        );
        let old_bearer = fleet.bearer(&old).await.unwrap();
        let mut root_params = rcgen::CertificateParams::default();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let root_key = kronik_core::identity::ed25519_key(&[32; 32]).unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        std::fs::write(&fleet.config.controller.ca_file, root.pem()).unwrap();
        *network.issuer.lock().unwrap() = Some(rcgen::Issuer::new(root_params, root_key));
        let next = fleet
            .enroll(
                "unix:uid=0",
                request(Some("rotated-once"), false),
                authority(&fleet),
            )
            .await
            .unwrap();
        assert!(next.admitting);
        let next = next.state.unwrap();
        assert_eq!(next.epoch, old.epoch + 1);
        assert_ne!(next.request_id, old.request_id);
        assert_ne!(next.plan.ca_sha256, old.plan.ca_sha256);
        assert_eq!(
            next.controller_id.as_deref(),
            Some(next.plan.ca_sha256.as_str())
        );
        assert!(fleet.tokens.caller(&old_bearer).is_none());
        assert!(old_guard.check().is_err());
        assert!(old_lease.check().is_err());
        assert!(!fleet.accepts(&old_guard));
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.record().unwrap(), Some(next));
        assert!(reopened.status().unwrap().admitting);
    }

    #[tokio::test]
    async fn ordinary_managed_token_revocation_changes_admission_not_durable_enrollment() {
        let (_dir, fleet, network, _entropy) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        let active = fleet
            .enroll(
                "unix:uid=0",
                request(Some("initial-once"), false),
                authority(&fleet),
            )
            .await
            .unwrap()
            .state
            .unwrap();
        let guard = fleet.authority.guard();
        assert!(fleet.status().unwrap().admitting);
        assert!(fleet.accepts(&guard));
        let meta = fleet
            .tokens
            .list()
            .unwrap()
            .into_iter()
            .find(|row| row.fleet.is_some())
            .unwrap();
        let api = crate::Api::new(fleet.node.clone())
            .with_tokens(fleet.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        let response = api
            .handle(crate::ApiRequest {
                method: "POST".into(),
                path: format!("/v1/tokens/{}/revoke", meta.name),
                query: String::new(),
                body: serde_json::to_vec(
                    &serde_json::json!({"reason":"ordinary managed token revoke","dry_run":false}),
                )
                .unwrap(),
                token_id: "unix:uid=0".into(),
                bearer: None,
            })
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(fleet.record().unwrap(), Some(active.clone()));
        assert!(!fleet.status().unwrap().admitting);
        assert!(!fleet.accepts(&guard));
        assert!(!fleet.allows_token_id(&meta.token_id()));
        assert!(fleet.active_connection().await.unwrap().is_none());
        let response = api
            .handle(crate::ApiRequest {
                method: "GET".into(),
                path: "/v1/fleet".into(),
                query: String::new(),
                body: Vec::new(),
                token_id: "unix:uid=0".into(),
                bearer: None,
            })
            .await;
        assert_eq!(response.status, 200);
        let status: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(status["admitting"], false);
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.record().unwrap(), Some(active));
        assert!(!reopened.status().unwrap().admitting);
        assert!(reopened.active_connection().await.unwrap().is_none());
        assert_eq!(network.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn lost_active_custody_keeps_local_recovery_without_remote_admission() {
        for replace_with_bad_private_file in [false, true] {
            let (_dir, fleet, network, entropy) = setup().await;
            network.reply.store(true, Ordering::SeqCst);
            let active = fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("initial-once"), false),
                    authority(&fleet),
                )
                .await
                .unwrap()
                .state
                .unwrap();
            assert!(fleet.status().unwrap().admitting);
            let old_bearer = fleet.bearer(&active).await.unwrap();
            let old_token_id = fleet.tokens.caller(&old_bearer).unwrap().token_id;
            let (node, tokens, config, custody, startup_original) = (
                fleet.node.clone(),
                fleet.tokens.clone(),
                fleet.config.clone(),
                fleet.custody.clone(),
                fleet.startup_original.clone(),
            );
            drop(fleet);
            if replace_with_bad_private_file {
                // Retain the owned 0600 inode; corrupt only credential contents.
                std::fs::write(&custody, b"not-an-issued-fleet-credential").unwrap();
            } else {
                std::fs::remove_file(&custody).unwrap();
            }
            let (before_lsn, before_entropy, before_network) = (
                node.applied_lsn(),
                entropy.load(Ordering::SeqCst),
                network.requests.lock().unwrap().len(),
            );
            let reopened = Fleet::open(
                node.clone(),
                tokens.clone(),
                config.clone(),
                custody.clone(),
                startup_original.clone(),
            )
            .await
            .unwrap();
            let status = reopened.status().unwrap();
            assert_eq!(status.state, Some(active.clone()));
            assert!(!status.admitting);
            assert_eq!(status.admission_error, Some("UNAVAILABLE"));
            assert!(status.recovery_hint.is_some());
            assert!(reopened.authority.guard().check().is_err());
            assert!(!reopened.allows_token_id(&old_token_id));
            assert!(reopened.active_connection().await.unwrap().is_none());
            assert_eq!(node.applied_lsn(), before_lsn);
            assert_eq!(entropy.load(Ordering::SeqCst), before_entropy);
            assert_eq!(network.requests.lock().unwrap().len(), before_network);
            let api = crate::Api::new(node.clone())
                .with_tokens(tokens.clone())
                .unwrap()
                .with_fleet(reopened.clone());
            let response = api
                .handle(crate::ApiRequest {
                    method: "GET".into(),
                    path: "/v1/fleet".into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: "unix:uid=0".into(),
                    bearer: None,
                })
                .await;
            assert_eq!(response.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["admitting"], false);
            assert_eq!(body["admission_error"], "UNAVAILABLE");
            // A custody diagnosis does not swallow unrelated pinned TLS failures.
            let mut invalid_tls = config;
            invalid_tls.controller.ca_file = custody.with_file_name("missing-controller-ca");
            assert!(
                Fleet::open(node, tokens, invalid_tls, custody, startup_original)
                    .await
                    .is_err()
            );
            let revoked = reopened
                .revoke(
                    "unix:uid=0",
                    FleetRevokeRequest {
                        reason: "recover lost custody".into(),
                        dry_run: false,
                    },
                    authority(&reopened),
                )
                .await
                .unwrap();
            assert!(!revoked.admitting);
            assert_eq!(revoked.state.unwrap().phase, EnrollmentPhase::Revoked);
            assert!(reopened.tokens.caller(&old_bearer).is_none());
            let next = reopened
                .enroll(
                    "unix:uid=0",
                    request(Some("fresh-once"), false),
                    authority(&reopened),
                )
                .await
                .unwrap();
            assert!(next.admitting);
            assert!(next.admission_error.is_none());
            let next = next.state.unwrap();
            assert_eq!(next.epoch, active.epoch + 1);
            assert_ne!(next.request_id, active.request_id);
            assert_ne!(
                reopened.bearer(&next).await.unwrap().as_str(),
                old_bearer.as_str()
            );
            let requests = network.requests.lock().unwrap();
            assert_eq!(requests.len(), before_network + 1);
            assert!(
                requests
                    .last()
                    .unwrap()
                    .headers
                    .iter()
                    .any(|(name, value)| name == "authorization" && value == "Bearer fresh-once")
            );
        }
    }

    #[tokio::test]
    async fn requested_missing_custody_never_regenerates_or_reuses_bootstrap_credential() {
        let (_dir, fleet, network, entropy) = setup().await;
        assert!(
            fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("spent-once"), false),
                    authority(&fleet)
                )
                .await
                .is_err()
        );
        let requested = fleet.record().unwrap().unwrap();
        assert_eq!(requested.phase, EnrollmentPhase::Requested);
        std::fs::remove_file(&fleet.custody).unwrap();
        let before_entropy = entropy.load(Ordering::SeqCst);
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert!(!reopened.status().unwrap().admitting);
        assert!(reopened.active_connection().await.unwrap().is_none());
        let error = reopened
            .enroll("unix:uid=0", request(None, false), authority(&reopened))
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(error.hint.as_deref(), Some(CUSTODY_RECOVERY_HINT));
        assert!(
            reopened
                .enroll(
                    "unix:uid=0",
                    request(Some("spent-once"), false),
                    authority(&reopened)
                )
                .await
                .is_err()
        );
        assert_eq!(reopened.record().unwrap().unwrap(), requested);
        assert_eq!(entropy.load(Ordering::SeqCst), before_entropy);
        assert_eq!(network.requests.lock().unwrap().len(), 1);
        assert!(!reopened.custody.exists());
        assert_eq!(reopened.tokens.list().unwrap().len(), 1);
        reopened
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "abandon unrecoverable Requested custody".into(),
                    dry_run: false,
                },
                authority(&reopened),
            )
            .await
            .unwrap();
        assert_eq!(
            reopened.record().unwrap().unwrap().phase,
            EnrollmentPhase::Revoked
        );
    }

    #[tokio::test]
    async fn failed_custody_never_sends_and_new_enrollment_advances_epoch() {
        let (_dir, fleet, network, _entropy) = setup().await;
        // The owned directory exists before the malicious destination is installed.
        let client = enrollment::load_controller(fleet.node.env(), &fleet.config.controller)
            .await
            .unwrap();
        let plan = client
            .plan(fleet.config.identity.clone(), fleet.config.scopes.clone())
            .unwrap();
        EnrollmentRecord::prepare(fleet.node.env(), &client, plan, 1)
            .await
            .unwrap();
        std::os::unix::fs::symlink(&fleet.config.controller.ca_file, &fleet.custody).unwrap();
        assert!(
            fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("once"), false),
                    authority(&fleet)
                )
                .await
                .is_err()
        );
        assert!(network.requests.lock().unwrap().is_empty());
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Pending
        );
        assert!(fleet.tokens.list().unwrap()[0].revoked.is_some());
        assert!(!fleet.allows_token_id(&fleet.tokens.list().unwrap()[0].token_id()));
        let stale: kronik_core::authority::AuthLease = Arc::new(RequestAuthority {
            fleet: fleet.clone(),
            receipt: Arc::new(fleet.record().unwrap().unwrap()),
            original: authority(&fleet),
        });
        std::fs::remove_file(&fleet.custody).unwrap();
        assert!(
            fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("new-once"), false),
                    authority(&fleet)
                )
                .await
                .is_err()
        );
        assert_eq!(fleet.record().unwrap().unwrap().epoch, 2);
        assert_eq!(fleet.tokens.list().unwrap().len(), 2);
        assert_eq!(network.requests.lock().unwrap().len(), 1);
        let mut restored_old_epoch = false;
        assert!(
            stale
                .admit(&mut || {
                    restored_old_epoch = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!restored_old_epoch);
    }

    #[tokio::test]
    async fn ordinary_fleet_named_tokens_survive_enrollment_restart_and_revoke() {
        let (dir, fleet, network, _entropy) = setup().await;
        let mut ordinary = Vec::new();
        for (index, name) in ["fleet-1", "fleet-team"].into_iter().enumerate() {
            let (meta, bearer) = fleet
                .tokens
                .create(
                    name,
                    [crate::auth::Scope::Read].into(),
                    [index as u8 + 70; 32],
                    &Change {
                        by: "unix:uid=0",
                        reason: "existing ordinary token",
                        wall_ms: 0,
                    },
                    false,
                )
                .unwrap();
            assert!(meta.fleet.is_none());
            ordinary.push((meta.token_id(), bearer.unwrap()));
        }
        assert!(
            fleet
                .enroll(
                    "unix:uid=0",
                    request(Some("once"), false),
                    authority(&fleet)
                )
                .await
                .is_err()
        );
        let mut restart_tokens = TokenStore::open_file(&dir.path().join("keys/tokens.db")).unwrap();
        restart_tokens
            .bind_before_any_issuer(fleet.node.publication_domain())
            .unwrap();
        restart_tokens
            .bind_execution_before_any_issuer(
                &fleet.node.publication_domain(),
                fleet.startup_original.clone(),
            )
            .unwrap();
        let restart_tokens = Arc::new(restart_tokens);
        let reopened = Fleet::open(
            fleet.node.clone(),
            restart_tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        for (id, bearer) in &ordinary {
            assert!(reopened.allows_token_id(id));
            assert!(restart_tokens.caller(bearer).is_some());
            assert!(restart_tokens.fleet_token(id).is_none());
        }
        network.reply.store(true, Ordering::SeqCst);
        let status = reopened
            .enroll("unix:uid=0", request(None, false), authority(&reopened))
            .await
            .unwrap();
        assert_eq!(status.state.unwrap().phase, EnrollmentPhase::Active);
        reopened
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "disconnect managed installation".into(),
                    dry_run: false,
                },
                authority(&reopened),
            )
            .await
            .unwrap();
        let mut final_tokens = TokenStore::open_file(&dir.path().join("keys/tokens.db")).unwrap();
        final_tokens
            .bind_before_any_issuer(fleet.node.publication_domain())
            .unwrap();
        final_tokens
            .bind_execution_before_any_issuer(
                &fleet.node.publication_domain(),
                fleet.startup_original.clone(),
            )
            .unwrap();
        let final_tokens = Arc::new(final_tokens);
        let final_service = Fleet::open(
            fleet.node.clone(),
            final_tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        for (id, bearer) in ordinary {
            assert!(final_service.allows_token_id(&id));
            assert!(final_tokens.caller(&bearer).is_some());
        }
        let metadata = final_tokens.list().unwrap();
        assert_eq!(
            metadata.iter().filter(|meta| meta.fleet.is_some()).count(),
            1
        );
        assert!(
            metadata
                .iter()
                .filter(|meta| meta.fleet.is_some())
                .all(|meta| meta.revoked.is_some())
        );
        assert!(
            metadata
                .iter()
                .filter(|meta| meta.fleet.is_none())
                .all(|meta| meta.revoked.is_none())
        );
    }

    #[tokio::test]
    async fn real_fleet_mutations_preserve_metadata_when_live_secrets_match_schema_words() {
        use kronik_proto::Record;
        let (dir, fleet, network, _entropy) = setup().await;
        let reason = "schema https 1";
        let audit = fleet.audit("unix:uid=0", "install legitimate short secret");
        for (name, value) in [
            ("word-schema", "schema"),
            ("word-https", "https"),
            ("digit-one", "1"),
        ] {
            fleet
                .node
                .secret_set(
                    name,
                    value.as_bytes().to_vec(),
                    &audit,
                    false,
                    authority(&fleet),
                )
                .await
                .unwrap();
        }
        fleet
            .node
            .refresh_secret_inventory(authority(&fleet))
            .await
            .unwrap();
        let secrets = fleet.node.secret_values().unwrap();
        let patterns = kronik_sched::effects::secret_patterns(&secrets);
        let clean = kronik_sched::scrub::for_log(reason, Some(&patterns));
        assert_ne!(clean, reason);
        assert!(
            !clean.contains('1'),
            "the one-byte secret must not survive in free-text audit reasons"
        );
        let mut enroll = request(Some("single-use-credential"), false);
        enroll.reason = reason.into();
        network.reply.store(true, Ordering::SeqCst);
        let status = fleet
            .enroll("unix:uid=0", enroll, authority(&fleet))
            .await
            .unwrap();
        let requested = status.state.unwrap();
        assert_eq!(requested.phase, EnrollmentPhase::Active);
        assert_eq!(requested.plan.controller_url, "https://controller.test");
        assert_eq!(requested.plan.identity.installation, "installation-test");
        assert_eq!(requested.plan.scopes, ["read", "fork"]);
        assert!(!requested.csr_der.is_empty());
        let sent: serde_json::Value =
            serde_json::from_slice(&network.request_bodies.lock().unwrap()[0]).unwrap();
        assert_eq!(sent["request_id"], requested.request_id);
        assert_eq!(
            sent["csr_der"],
            serde_json::to_value(&requested.csr_der).unwrap()
        );
        assert_eq!(sent["plan"], serde_json::to_value(&requested.plan).unwrap());
        let api = crate::Api::new(fleet.node.clone())
            .with_tokens(fleet.tokens.clone())
            .unwrap()
            .with_fleet(fleet.clone());
        let status = api
            .handle(crate::ApiRequest {
                method: "GET".into(),
                path: "/v1/fleet".into(),
                query: String::new(),
                body: Vec::new(),
                token_id: "unix:uid=0".into(),
                bearer: None,
            })
            .await;
        assert_eq!(status.status, 200);
        let status: serde_json::Value = serde_json::from_slice(&status.body).unwrap();
        assert_eq!(status["state"], serde_json::to_value(&requested).unwrap());
        fleet
            .node
            .record_audit_event_authorized(
                "fleet.note",
                "free-target",
                [("note".into(), reason.into())].into_iter().collect(),
                fleet.audit("unix:uid=0", reason),
                authority(&fleet),
            )
            .await
            .unwrap();
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: reason.into(),
                    dry_run: false,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        let revoked = fleet.record().unwrap().unwrap();
        assert_eq!(revoked.phase, EnrollmentPhase::Revoked);
        assert_eq!(revoked.plan, requested.plan);
        assert_eq!(revoked.request_id, requested.request_id);
        assert_eq!(revoked.csr_der, requested.csr_der);
        assert_eq!(revoked.epoch, requested.epoch);
        assert_eq!(revoked.client_cert_der, requested.client_cert_der);
        let mut events = Vec::new();
        fleet
            .node
            .reader()
            .read(1, fleet.node.applied_lsn(), |committed| {
                if let Record::AuditEvent(event) = &committed.record {
                    events.push(event.clone());
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            events
                .iter()
                .filter(|event| event.action == "fleet.state")
                .all(|event| event.audit.as_ref().unwrap().reason == clean)
        );
        let note = events
            .iter()
            .find(|event| event.action == "fleet.note")
            .unwrap();
        assert_eq!(note.details["note"], clean);
        assert_eq!(note.audit.as_ref().unwrap().reason, clean);
        let gap = kronik_log::MetadataAuditGap {
            stream: "events-schema-https-1:metadata".into(),
            from_index: 1,
            through_index: 17,
        };
        let before = fleet.node.applied_lsn();
        assert_eq!(
            fleet
                .node
                .record_metadata_audit_gap(gap.clone(), authority(&fleet))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthenticated
        );
        assert_eq!(fleet.node.applied_lsn(), before);
        let physical = fleet.node.local_operator_authority().unwrap();
        let receipt = fleet
            .node
            .record_metadata_audit_gap(gap.clone(), physical.clone())
            .await
            .unwrap();
        assert_eq!(
            fleet
                .node
                .record_metadata_audit_gap(gap.clone(), physical.clone())
                .await
                .unwrap(),
            receipt
        );
        let kronik_core::ids::SourcePos::Actor { shard: None, lsn } = receipt else {
            panic!("the native receipt must retain its actual actor-log namespace");
        };
        assert_eq!(fleet.node.applied_lsn(), lsn);
        fleet
            .node
            .reader()
            .read(lsn, lsn, |committed| {
                let Record::AuditEvent(event) = committed.record else {
                    panic!("missing durable metadata gap");
                };
                assert_eq!(event.details, gap.to_details());
                kronik_proto::control::validate_metadata_gap_event(&event).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            fleet
                .node
                .record_audit_event_authorized(
                    "audit.gap",
                    "",
                    gap.to_details(),
                    fleet.audit("unix:uid=0", reason),
                    authority(&fleet)
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::BadRequest
        );
        assert_eq!(fleet.node.applied_lsn(), lsn);
        // Unknown inventory cannot turn free text into an unsanitized success.
        // Warm certified bytes survive ciphertext damage; the physical identity must become uncertifiable too.
        rusqlite::Connection::open(dir.path().join("keys/secrets.db"))
            .unwrap()
            .execute(
                "UPDATE secrets SET ciphertext = x'00', version_hash = x'00'",
                [],
            )
            .unwrap();
        assert!(
            fleet
                .node
                .refresh_secret_inventory(authority(&fleet))
                .await
                .is_err()
        );
        assert!(fleet.node.secret_values().is_err());
        let unavailable_gap = kronik_log::MetadataAuditGap {
            from_index: 18,
            through_index: 19,
            ..gap
        };
        let receipt = fleet
            .node
            .record_metadata_audit_gap(unavailable_gap.clone(), physical)
            .await
            .unwrap();
        let kronik_core::ids::SourcePos::Actor { shard: None, lsn } = receipt else {
            panic!("the native receipt must retain its actual actor-log namespace");
        };
        fleet
            .node
            .reader()
            .read(lsn, lsn, |committed| {
                let Record::AuditEvent(event) = committed.record else {
                    panic!("missing durable metadata gap");
                };
                assert_eq!(event.details, unavailable_gap.to_details());
                assert_eq!(
                    event.audit.as_ref().unwrap().reason,
                    kronik_sched::scrub::WITHHELD
                );
                Ok(())
            })
            .await
            .unwrap();
        let result = fleet
            .node
            .record_audit_event_authorized(
                "fleet.note",
                "free-target",
                [("note".into(), reason.into())].into_iter().collect(),
                fleet.audit("unix:uid=0", reason),
                authority(&fleet),
            )
            .await;
        if let Ok(lsn) = result {
            fleet
                .node
                .reader()
                .read(lsn, lsn, |committed| {
                    let Record::AuditEvent(event) = &committed.record else {
                        panic!("missing free-text audit event");
                    };
                    assert_eq!(event.details["note"], kronik_sched::scrub::WITHHELD);
                    assert_eq!(
                        event.audit.as_ref().unwrap().reason,
                        kronik_sched::scrub::WITHHELD
                    );
                    Ok(())
                })
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn real_tls_controller_and_ordinary_admin_revocation_share_the_native_pipeline() {
        use crate::auth::{Authenticator as _, Scope};
        use std::io::{Read as _, Write as _};
        use std::os::unix::fs::DirBuilderExt as _;
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        let issuer = Network::default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = kronik_core::identity::ed25519_key(&[31; 32]).unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        *issuer.issuer.lock().unwrap() = Some(rcgen::Issuer::new(ca_params, ca_key));
        let mut protected_ca = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        protected_ca.write_all(ca.pem().as_bytes()).unwrap();
        let ca_file = directory.path().join("ca.pem");
        protected_ca.persist(&ca_file).unwrap();
        let server_key = kronik_core::identity::ed25519_key(&[32; 32]).unwrap();
        let mut server_params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params
            .signed_by(&server_key, issuer.issuer.lock().unwrap().as_ref().unwrap())
            .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.der().clone()],
            rustls_pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
        let (probe, probed) = std::sync::mpsc::sync_channel(1);
        let no_connection = Arc::new(tokio::sync::Notify::new());
        let received = Arc::new(tokio::sync::Notify::new());
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let observed = Arc::new(Mutex::new(Vec::<EnrollmentRecord>::new()));
        let finished = {
            let (no_connection, received, observed) =
                (no_connection.clone(), received.clone(), observed.clone());
            env.blocking("api-real-fleet-controller", move || {
                probed.recv_timeout(Duration::from_secs(15)).unwrap();
                assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                    "a capacity-blocked revoked command must not reach the real controller");
                no_connection.notify_one();
                let tls = Arc::new(tls);
                for number in 0..2 {
                    let deadline = std::time::Instant::now() + Duration::from_secs(15);
                    let stream = loop {
                        match listener.accept() {
                            Ok((stream, _)) => break stream,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(std::time::Instant::now() < deadline, "owned controller accept deadline");
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => panic!("owned controller accept: {}", error.kind()),
                        }
                    };
                    stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
                    let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(), stream);
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        assert!(header.len() < 8192);
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        header.push(byte[0]);
                    }
                    let header = std::str::from_utf8(&header).unwrap();
                    assert!(header.starts_with("POST /v1/enroll HTTP/1.1\r\n"));
                    let authorization = header.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("authorization").then_some(value.trim())
                    }).unwrap();
                    assert!(authorization == if number == 0 { "Bearer fresh-once" } else { "Bearer held-once" });
                    let length: usize = header.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                    }).unwrap();
                    assert!(length > 0 && length <= enrollment::MAX_ENROLLMENT_BYTES);
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert!(!value["api_bearer"].as_str().unwrap().is_empty());
                    let plan: EnrollmentPlan = serde_json::from_value(value["plan"].clone()).unwrap();
                    let csr: Vec<u8> = serde_json::from_value(value["csr_der"].clone()).unwrap();
                    let request_id = value["request_id"].as_str().unwrap().to_owned();
                    let epoch = value["epoch"].as_u64().unwrap();
                    let certificate = issuer.certificate(&csr, &plan, &request_id, epoch);
                    let record = EnrollmentRecord {
                        controller_id: Some(plan.ca_sha256.clone()), plan, request_id, epoch,
                        phase: EnrollmentPhase::Active, csr_der: csr,
                        client_key_sha256: value["client_key_sha256"].as_str().unwrap().to_owned(),
                        client_cert_der: Some(certificate),
                    };
                    let response = serde_json::to_vec(&serde_json::json!({
                        "schema": enrollment::ENROLLMENT_SCHEMA, "request_id": &record.request_id,
                        "epoch": record.epoch, "plan": &record.plan, "controller_id": &record.controller_id,
                        "client_cert_der": &record.client_cert_der,
                    })).unwrap();
                    observed.lock().unwrap().push(record);
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                    stream.flush().unwrap();
                    if number == 1 {
                        received.notify_one();
                        released.recv_timeout(Duration::from_secs(15)).unwrap();
                    }
                    stream.write_all(&response).unwrap();
                    stream.flush().unwrap();
                }
            })
        };
        let keys = directory.path().join("keys");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&keys)
            .unwrap();
        let node = kronik_sched::start_local(
            env.clone(),
            directory.path(),
            kronik_sched::NodeConfig::default(),
        )
        .await
        .unwrap();
        node.record_installation_identity(pb::InstallationIdentity {
            installation: "installation-real-tls".into(),
        })
        .await
        .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(keys.join("fleet"))
            .unwrap();
        let mut store = TokenStore::open_file(&keys.join("tokens.db")).unwrap();
        store
            .bind_before_any_issuer(node.publication_domain())
            .unwrap();
        let startup_original = node.local_operator_authority().unwrap();
        store
            .bind_execution_before_any_issuer(&node.publication_domain(), startup_original.clone())
            .unwrap();
        let tokens = Arc::new(store);
        let api = crate::Api::new(node.clone())
            .with_tokens(tokens.clone())
            .unwrap();
        let fleet = Fleet::open(
            node.clone(),
            tokens.clone(),
            FleetConfig {
                controller: ControllerConfig {
                    url: url.clone(),
                    ca_file,
                    client_key_file: keys.join("fleet/client.key"),
                },
                identity: FleetIdentity {
                    installation: "installation-real-tls".into(),
                    node: None,
                    cluster: None,
                },
                scopes: vec!["read".into(), "fork".into()],
            },
            keys.join("fleet/bearer"),
            startup_original,
        )
        .await
        .unwrap();
        let api = Arc::new(api.with_fleet(fleet.clone()));
        let (first, bearer) = tokens
            .create(
                "tls-first",
                [Scope::Admin].into(),
                [23; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "admit original TLS enroller",
                    wall_ms: env.clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let original = tokens::TokenAuthenticator::new(tokens.clone())
            .capture(
                &crate::ApiRequest {
                    method: "POST".into(),
                    path: "/v1/fleet/enroll".into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: String::new(),
                    bearer,
                },
                Scope::Admin,
            )
            .unwrap()
            .authority;
        let held = fleet.enrollment_http.clone().acquire_owned().await.unwrap();
        let mut initial = request(Some("denied-once"), false);
        initial.url = url.clone();
        let denied = {
            let (fleet, lease) = (fleet.clone(), original.clone());
            env.spawn("real-tls-capacity-enroller", async move {
                fleet.enroll(&first.token_id(), initial, lease).await
            })
        };
        tokio::pin!(denied);
        env.timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = denied.as_mut() => match result {
                    Some(Err(error)) => panic!("enrollment ended before Requested: {:?}", error.code),
                    Some(Ok(_)) => panic!("enrollment completed before HTTP capacity was released"),
                    None => panic!("enrollment worker stopped before Requested"),
                },
                () = async {
                    loop {
                        let changed = fleet.changed.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        if fleet.record().unwrap().is_some_and(|record| record.phase == EnrollmentPhase::Requested) { break; }
                        changed.await;
                    }
                } => {},
            }
        }).await.unwrap();
        let denied_record = fleet.record().unwrap().unwrap();
        let denied_bearer = fleet.bearer(&denied_record).await.unwrap();
        let revoke = api.handle(crate::ApiRequest { method: "POST".into(), path: "/v1/tokens/tls-first/revoke".into(),
            query: String::new(), body: serde_json::to_vec(&serde_json::json!({"reason":"revoke while real HTTP capacity is held","dry_run":false})).unwrap(),
            token_id: "unix:uid=0".into(), bearer: None });
        assert_eq!(
            env.timeout(Duration::from_secs(5), revoke)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            original.check().unwrap_err().code,
            ErrorCode::Unauthenticated
        );
        assert!(
            env.timeout(Duration::from_secs(5), denied)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(fleet.enrollment_http.available_permits(), 0);
        assert!(!fleet.status().unwrap().admitting);
        assert_eq!(fleet.record().unwrap().unwrap(), denied_record);
        probe.send(()).unwrap();
        env.timeout(Duration::from_secs(5), no_connection.notified())
            .await
            .unwrap();
        assert!(observed.lock().unwrap().is_empty());
        drop(held);
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "retire never-sent TLS request".into(),
                    dry_run: false,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        let (next, bearer) = tokens
            .create(
                "tls-next",
                [Scope::Admin].into(),
                [24; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "independently admit fresh TLS enrollment",
                    wall_ms: env.clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let next_authority = tokens::TokenAuthenticator::new(tokens.clone())
            .capture(
                &crate::ApiRequest {
                    method: "POST".into(),
                    path: "/v1/fleet/enroll".into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: String::new(),
                    bearer,
                },
                Scope::Admin,
            )
            .unwrap()
            .authority;
        let mut fresh = request(Some("fresh-once"), false);
        fresh.url = url.clone();
        assert!(
            env.timeout(
                Duration::from_secs(5),
                fleet.enroll(&next.token_id(), fresh, next_authority.clone())
            )
            .await
            .unwrap()
            .unwrap()
            .admitting
        );
        let active = fleet.record().unwrap().unwrap();
        assert_eq!(active.phase, EnrollmentPhase::Active);
        assert_eq!(active.epoch, denied_record.epoch + 1);
        assert_ne!(active.request_id, denied_record.request_id);
        assert_eq!(active, observed.lock().unwrap()[0]);
        assert!(denied_bearer.as_str() != fleet.bearer(&active).await.unwrap().as_str());
        let active_id = format!("token:{}", token_name(&active).unwrap());
        assert!(fleet.allows_token_id(&active_id));
        let mut pending = request(Some("held-once"), false);
        pending.url = url;
        let work = {
            let (fleet, lease) = (fleet.clone(), next_authority.clone());
            env.spawn("real-tls-started-enroller", async move {
                fleet.enroll(&next.token_id(), pending, lease).await
            })
        };
        env.timeout(Duration::from_secs(5), received.notified())
            .await
            .unwrap();
        let requested = fleet.record().unwrap().unwrap();
        assert_eq!(requested.phase, EnrollmentPhase::Requested);
        assert_eq!(requested.epoch, active.epoch + 1);
        assert_ne!(requested.request_id, active.request_id);
        assert!(!fleet.allows_token_id(&active_id));
        let revoke = api.handle(crate::ApiRequest { method: "POST".into(), path: "/v1/tokens/tls-next/revoke".into(),
            query: String::new(), body: serde_json::to_vec(&serde_json::json!({"reason":"revoke after actual controller POST before response","dry_run":false})).unwrap(),
            token_id: "unix:uid=0".into(), bearer: None });
        assert_eq!(
            env.timeout(Duration::from_secs(5), revoke)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            next_authority.check().unwrap_err().code,
            ErrorCode::Unauthenticated
        );
        let fenced = node.applied_lsn();
        assert!(
            env.timeout(Duration::from_secs(5), work)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(fleet.enrollment_http.available_permits(), 0);
        release.send(()).unwrap();
        env.timeout(Duration::from_secs(5), finished)
            .await
            .unwrap()
            .unwrap();
        let completed = env
            .timeout(
                Duration::from_secs(5),
                fleet.enrollment_http.clone().acquire_owned(),
            )
            .await
            .unwrap()
            .unwrap();
        drop(completed);
        let following = node
            .record_audit_event_authorized(
                "test.following",
                "after-real-tls-enroller-fence",
                Default::default(),
                fleet.audit("unix:uid=0", "observe completed real TLS response"),
                authority(&fleet),
            )
            .await
            .unwrap();
        let mut following_seen = false;
        node.reader()
            .read(fenced + 1, following, |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record {
                    assert!(!matches!(event.operation,
                    Some(pb::audit_event::Operation::FleetState(pb::FleetState { phase, .. }))
                        if phase == pb::fleet_state::Phase::Active as i32));
                    following_seen |=
                        committed.lsn == following && event.action == "test.following";
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(following_seen);
        assert_eq!(observed.lock().unwrap().len(), 2);
        assert_eq!(fleet.record().unwrap().unwrap(), requested);
        assert!(!fleet.status().unwrap().admitting);
        let pending_id = format!("token:{}", token_name(&requested).unwrap());
        assert!(!fleet.allows_token_id(&pending_id));
        let bearer = fleet.bearer(&requested).await.unwrap();
        let response = api
            .handle(crate::ApiRequest {
                method: "GET".into(),
                path: "/v1/branches".into(),
                query: String::new(),
                body: Vec::new(),
                token_id: String::new(),
                bearer: Some(bearer.to_string()),
            })
            .await;
        assert_eq!(response.status, 401);
    }

    #[tokio::test]
    async fn requested_http_capacity_wait_does_not_stall_revoke_or_send_for_a_revoked_enroller() {
        use crate::auth::{Authenticator as _, Scope};
        let (_dir, fleet, network, _entropy) = setup().await;
        let held = fleet.enrollment_http.clone().acquire_owned().await.unwrap();
        let (token, bearer) = fleet
            .tokens
            .create(
                "capacity-enroller",
                [Scope::Admin].into(),
                [29; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "admit bounded enrollment",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let original = tokens::TokenAuthenticator::new(fleet.tokens.clone())
            .capture(
                &crate::ApiRequest {
                    method: "POST".into(),
                    path: "/v1/fleet/enroll".into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: String::new(),
                    bearer,
                },
                Scope::Admin,
            )
            .unwrap()
            .authority;
        network.reply.store(true, Ordering::SeqCst);
        let work = {
            let fleet = fleet.clone();
            let lease = original.clone();
            fleet
                .node
                .env()
                .clone()
                .spawn("bounded-enroller-race", async move {
                    fleet
                        .enroll(&token.token_id(), request(Some("once"), false), lease)
                        .await
                })
        };
        fleet
            .node
            .env()
            .timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let changed = fleet.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if fleet
                        .record()
                        .unwrap()
                        .is_some_and(|record| record.phase == EnrollmentPhase::Requested)
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await
            .unwrap();
        assert!(network.requests.lock().unwrap().is_empty());
        fleet
            .node
            .env()
            .timeout(
                std::time::Duration::from_secs(5),
                fleet.tokens.revoke_authorized(
                    fleet.node.clone(),
                    "capacity-enroller",
                    fleet.audit("unix:uid=0", "revoke while HTTP capacity is unavailable"),
                    false,
                    authority(&fleet),
                ),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            original.check().unwrap_err().code,
            ErrorCode::Unauthenticated
        );
        let fenced = fleet.node.applied_lsn();
        assert!(
            fleet
                .node
                .env()
                .timeout(std::time::Duration::from_secs(5), work)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_eq!(fleet.enrollment_http.available_permits(), 0);
        drop(held);
        let following = fleet
            .node
            .record_audit_event_authorized(
                "test.following",
                "after-capacity-enroller-fence",
                Default::default(),
                fleet.audit("unix:uid=0", "observe bounded cancellation"),
                authority(&fleet),
            )
            .await
            .unwrap();
        let mut following_seen = false;
        fleet
            .node
            .reader()
            .read(fenced + 1, following, |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record {
                    assert!(!matches!(event.operation,
                    Some(pb::audit_event::Operation::FleetState(pb::FleetState { phase, .. }))
                        if phase == pb::fleet_state::Phase::Active as i32));
                    following_seen |=
                        committed.lsn == following && event.action == "test.following";
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(following_seen);
        assert!(network.requests.lock().unwrap().is_empty());
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Requested
        );
    }

    #[tokio::test]
    async fn revoked_ordinary_enroller_cannot_activate_a_durable_requested_operation() {
        use crate::auth::{Authenticator as _, Scope};
        let (_dir, fleet, network, _entropy) = setup().await;
        let (token, bearer) = fleet
            .tokens
            .create(
                "enroller",
                [Scope::Admin].into(),
                [23; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "admit exact enroller",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let captured = tokens::TokenAuthenticator::new(fleet.tokens.clone())
            .capture(
                &crate::ApiRequest {
                    method: "POST".into(),
                    path: "/v1/fleet/enroll".into(),
                    query: String::new(),
                    body: Vec::new(),
                    token_id: String::new(),
                    bearer,
                },
                Scope::Admin,
            )
            .unwrap();
        let original = captured.authority;
        network.reply.store(true, Ordering::SeqCst);
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        *network.hold.lock().unwrap() = Some(hold.clone());
        let started = network.started.notified();
        tokio::pin!(started);
        started.as_mut().enable();
        let work = {
            let fleet = fleet.clone();
            let lease = original.clone();
            fleet
                .node
                .env()
                .clone()
                .spawn("original-enroller-race", async move {
                    fleet
                        .enroll(&token.token_id(), request(Some("once"), false), lease)
                        .await
                })
        };
        started.await;
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Requested
        );
        fleet
            .tokens
            .revoke_authorized(
                fleet.node.clone(),
                "enroller",
                fleet.audit("unix:uid=0", "revoke while certificate body is pending"),
                false,
                authority(&fleet),
            )
            .await
            .unwrap();
        assert_eq!(
            original.check().unwrap_err().code,
            ErrorCode::Unauthenticated
        );
        let fenced = fleet.node.applied_lsn();
        let result = fleet
            .node
            .env()
            .timeout(std::time::Duration::from_secs(1), work)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "durable request metadata must not replace the revoked ordinary caller"
        );
        hold.add_permits(1);
        let following = fleet
            .node
            .record_audit_event_authorized(
                "test.following",
                "after-enroller-fence",
                Default::default(),
                fleet.audit("unix:uid=0", "observe the next actual record"),
                authority(&fleet),
            )
            .await
            .unwrap();
        let mut following_seen = false;
        fleet
            .node
            .reader()
            .read(fenced + 1, following, |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record {
                    assert!(!matches!(event.operation,
                    Some(pb::audit_event::Operation::FleetState(pb::FleetState { phase, .. }))
                        if phase == pb::fleet_state::Phase::Active as i32));
                    following_seen |=
                        committed.lsn == following && event.action == "test.following";
                }
                Ok(())
            })
            .await
            .unwrap();
        assert!(following_seen);
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Requested
        );
    }

    #[tokio::test]
    async fn revoke_while_certificate_reply_is_delayed_never_reactivates_the_request() {
        let (_dir, fleet, network, _entropy) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        let hold = Arc::new(tokio::sync::Semaphore::new(0));
        *network.hold.lock().unwrap() = Some(hold.clone());
        let started = network.started.notified();
        tokio::pin!(started);
        started.as_mut().enable();
        let work = {
            let fleet = fleet.clone();
            let env = fleet.node.env().clone();
            env.spawn("delayed-fleet-enroll-test", async move {
                let lease = authority(&fleet);
                fleet
                    .enroll("unix:uid=0", request(Some("once"), false), lease)
                    .await
            })
        };
        started.await;
        let pending = fleet.record().unwrap().unwrap();
        assert_eq!(pending.phase, EnrollmentPhase::Requested);
        let receipt: kronik_core::authority::AuthLease = Arc::new(RequestAuthority {
            fleet: fleet.clone(),
            receipt: Arc::new(pending.clone()),
            original: authority(&fleet),
        });
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "revoke before controller reply".into(),
                    dry_run: false,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        let revoked = fleet.record().unwrap().unwrap();
        assert_eq!(revoked.phase, EnrollmentPhase::Revoked);
        assert_eq!(revoked.epoch, pending.epoch);
        hold.add_permits(1);
        assert!(work.await.unwrap().is_err());
        assert_eq!(fleet.record().unwrap().unwrap(), revoked);
        assert!(receipt.check().is_err());
        let reopened = Fleet::open(
            fleet.node.clone(),
            fleet.tokens.clone(),
            fleet.config.clone(),
            fleet.custody.clone(),
            fleet.startup_original.clone(),
        )
        .await
        .unwrap();
        assert!(reopened.active_connection().await.unwrap().is_none());
        assert_eq!(reopened.record().unwrap().unwrap(), revoked);
        *network.hold.lock().unwrap() = None;
        let fresh = reopened
            .enroll(
                "unix:uid=0",
                request(Some("fresh-one-time"), false),
                authority(&reopened),
            )
            .await
            .unwrap()
            .state
            .unwrap();
        assert_eq!(fresh.epoch, pending.epoch + 1);
        assert_ne!(fresh.request_id, pending.request_id);
        assert!(receipt.check().is_err());
    }

    #[tokio::test]
    async fn controller_cannot_reflect_enrollment_credentials_into_durable_public_identity() {
        use kronik_proto::Record;
        for reflection in [1, 2] {
            let (_dir, fleet, network, _entropy) = setup().await;
            network.reply.store(true, Ordering::SeqCst);
            network.reflection.store(reflection, Ordering::SeqCst);
            let one_time = "42".repeat(32);
            assert!(
                fleet
                    .enroll(
                        "unix:uid=0",
                        request(Some(&one_time), false),
                        authority(&fleet)
                    )
                    .await
                    .is_err()
            );
            let state = fleet.record().unwrap().unwrap();
            assert_eq!(state.phase, EnrollmentPhase::Requested);
            assert!(state.controller_id.is_none());
            assert!(state.client_cert_der.is_none());
            assert_ne!(state.plan.ca_sha256, one_time);
            let transmitted: serde_json::Value =
                serde_json::from_slice(&network.request_bodies.lock().unwrap()[0]).unwrap();
            let bearer = transmitted["api_bearer"].as_str().unwrap();
            fleet
                .node
                .reader()
                .read(1, fleet.node.applied_lsn(), |committed| {
                    if let Record::AuditEvent(event) = &committed.record {
                        if let Some(pb::audit_event::Operation::FleetState(state)) =
                            &event.operation
                        {
                            assert!(state.controller_id.is_none());
                            let public =
                                serde_json::to_string(&record_from_state(state.clone()).unwrap())
                                    .unwrap();
                            assert!(!public.contains(bearer));
                            assert!(!public.contains(&one_time));
                        }
                        assert!(!event.audit.as_ref().unwrap().reason.contains(bearer));
                        assert!(
                            event
                                .details
                                .values()
                                .all(|value| !value.contains(bearer) && !value.contains(&one_time))
                        );
                    }
                    Ok(())
                })
                .await
                .unwrap();
        }
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn current_root_reverse_http_keeps_original_managed_capture_before_body_and_ignores_remote_credentials()
     {
        use crate::auth::Scope;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use zeroize::Zeroize as _;
        let (_directory, fleet, network, _) = setup().await;
        network.reply.store(true, Ordering::SeqCst);
        fleet
            .enroll(
                "unix:uid=0",
                request(Some("single-use-credential"), false),
                authority(&fleet),
            )
            .await
            .unwrap();
        let record = fleet.record().unwrap().unwrap();
        let bearer = fleet.bearer(&record).await.unwrap();
        let (_, admin) = fleet
            .tokens
            .create(
                "remote-admin",
                [Scope::Admin].into(),
                [77; 32],
                &Change {
                    by: "unix:uid=0",
                    reason: "ordinary stronger credential fixture",
                    wall_ms: fleet.node.env().clock.wall_ms(),
                },
                false,
            )
            .unwrap();
        let admin = admin.unwrap();
        let api = Arc::new(
            crate::Api::new(fleet.node.clone())
                .with_tokens(fleet.tokens.clone())
                .unwrap()
                .with_fleet(fleet.clone()),
        );
        let mut binding = crate::ApiRequest {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            body: Vec::new(),
            token_id: "fleet".into(),
            bearer: Some(bearer.to_string()),
        };
        let captured = api
            .capture_fleet_binding(&binding, fleet.authority.guard())
            .unwrap();
        binding.bearer.as_mut().unwrap().zeroize();
        let before = fleet.node.applied_lsn();
        let (mut peer, stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(crate::server::serve_fleet_connection(
            stream,
            api.clone(),
            captured.clone(),
            None,
        ));
        let head = format!(
            "POST /v1/fleet/revoke HTTP/1.1\r\nHost: controller.test\r\nAuthorization: Bearer {admin}\r\nCookie: session=untrusted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        peer.write_all(head.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert!(
            !response
                .windows(admin.len())
                .any(|value| value == admin.as_bytes())
        );
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fleet.node.applied_lsn(), before);
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Active
        );
        captured.authority().check().unwrap();

        // Hyper emits Continue only when the genuine pre-body handler polls Incoming.
        // The managed token allows Fork, not Admin; no remote header can upgrade it.
        let (mut peer, stream) = tokio::io::duplex(4096);
        let server = tokio::spawn(crate::server::serve_fleet_connection(
            stream,
            api,
            captured.clone(),
            None,
        ));
        peer.write_all(b"POST /v1/forks HTTP/1.1\r\nHost: controller.test\r\nExpect: 100-continue\r\nContent-Length: 200\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut interim = [0; 25];
        tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut interim))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        peer.write_all(b"{").await.unwrap();
        fleet
            .revoke(
                "unix:uid=0",
                FleetRevokeRequest {
                    reason: "revoke the original reverse channel".into(),
                    dry_run: false,
                },
                authority(&fleet),
            )
            .await
            .unwrap();
        let revoked = fleet.node.applied_lsn();
        assert!(captured.authority().check().is_err());
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut after = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut after))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fleet.node.applied_lsn(), revoked);
        assert_eq!(
            fleet.record().unwrap().unwrap().phase,
            EnrollmentPhase::Revoked
        );
    }

    #[cfg(feature = "server")]
    mod control;
}
