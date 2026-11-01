//! Operator-pinned mTLS enrollment. The caller admits every state through its
//! ordinary durable audit/metadata path; this module never grants file-only authority.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Env, HttpRequest, HttpResponse, Net, TlsConfig};
use kronik_core::identity::LeafKeys;
use rustls_pki_types::pem::{PemObject as _, SectionKind};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer as _, X509Certificate, X509CertificationRequest};
use zeroize::{Zeroize as _, Zeroizing};

pub const ENROLLMENT_SCHEMA: &str = "kronik.fleet-enrollment/v1";
pub const MAX_ENROLLMENT_BYTES: usize = 65_536;
const MAX_PEM_BYTES: usize = 262_144;

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("invalid fleet configuration: {0}")]
    Invalid(&'static str),
    #[error("fleet controller unavailable; enrollment outcome may be unknown")]
    Unavailable,
    #[error("fleet controller rejected the request")]
    Rejected,
    #[error("invalid fleet controller protocol response")]
    Protocol,
    #[error("fleet authority revoked or superseded")]
    Revoked,
    #[error("fleet durable admission failed")]
    Persistence,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    pub url: String,
    pub ca_file: PathBuf,
    /// Installation-owned generated leaf key; never supplied by the controller.
    /// Secure Env persistence creates a missing immediate private parent; it
    /// never changes permissions of an existing directory.
    pub client_key_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FleetIdentity {
    pub installation: String,
    pub node: Option<String>,
    pub cluster: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPlan {
    pub controller_url: String,
    pub identity: FleetIdentity,
    pub scopes: Vec<String>,
    // The private leaf identity belongs to the durable request, not a preview.
    pub ca_sha256: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentPhase {
    Pending,
    Requested,
    Active,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRecord {
    pub plan: EnrollmentPlan,
    pub request_id: String,
    pub epoch: u64,
    pub phase: EnrollmentPhase,
    pub controller_id: Option<String>,
    pub csr_der: Vec<u8>,
    pub client_key_sha256: String,
    pub client_cert_der: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct ControllerClient {
    pub(crate) net: Arc<dyn Net>,
    url: String,
    ca: Vec<Vec<u8>>,
    key_path: PathBuf,
    ca_hash: String,
}

/// Strict origin-only URLs make enrollment and stream destinations immutable.
pub fn canonical_controller_url(value: &str) -> Result<String, FleetError> {
    let u = url::Url::parse(value).map_err(|_| FleetError::Invalid("controller URL"))?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err(FleetError::Invalid("controller must be an HTTPS origin"));
    }
    Ok(u.as_str().trim_end_matches('/').to_owned())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl EnrollmentPlan {
    pub fn validate(&self) -> Result<(), FleetError> {
        if canonical_controller_url(&self.controller_url)? != self.controller_url {
            return Err(FleetError::Invalid("controller URL must be canonical"));
        }
        if !identifier(&self.identity.installation)
            || self
                .identity
                .node
                .as_deref()
                .is_some_and(|v| !identifier(v))
            || self
                .identity
                .cluster
                .as_deref()
                .is_some_and(|v| !identifier(v))
        {
            return Err(FleetError::Invalid("installation/node/cluster identity"));
        }
        kronik_proto::control::validate_scopes(&self.scopes)
            .map_err(|_| FleetError::Invalid("allowed ordinary scope list"))?;
        for hash in [&self.ca_sha256] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(FleetError::Invalid("TLS identity fingerprint"));
            }
        }
        Ok(())
    }
}

impl EnrollmentRecord {
    /// Preview calls only `plan.validate()`: preparing an identity is an admitted mutation.
    pub async fn prepare(
        env: &Env,
        client: &ControllerClient,
        plan: EnrollmentPlan,
        epoch: u64,
    ) -> Result<Self, FleetError> {
        plan.validate()?;
        if epoch == 0 {
            return Err(FleetError::Invalid("zero enrollment epoch"));
        }
        client.validate_plan(&plan)?;
        let keys = client.local_key(env, true).await?;
        let csr_der = keys
            .csr_der()
            .map_err(|_| FleetError::Invalid("local leaf CSR"))?;
        let client_key_sha256 = csr_fingerprint(&csr_der)?;
        Ok(Self {
            plan,
            request_id: hex(&env.random_bytes::<32>()),
            epoch,
            phase: EnrollmentPhase::Pending,
            controller_id: None,
            csr_der,
            client_key_sha256,
            client_cert_der: None,
        })
    }

    pub fn revoke(&self) -> Result<Self, FleetError> {
        let mut revoked = self.clone();
        // The issued certificate binds this enrollment's request and epoch.
        revoked.phase = EnrollmentPhase::Revoked;
        Ok(revoked)
    }
}

impl ControllerClient {
    pub fn plan(
        &self,
        identity: FleetIdentity,
        scopes: Vec<String>,
    ) -> Result<EnrollmentPlan, FleetError> {
        let plan = EnrollmentPlan {
            controller_url: self.url.clone(),
            identity,
            scopes,
            ca_sha256: self.ca_hash.clone(),
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate_plan(&self, plan: &EnrollmentPlan) -> Result<(), FleetError> {
        plan.validate()?;
        if plan.controller_url != self.url || plan.ca_sha256 != self.ca_hash {
            return Err(FleetError::Invalid(
                "enrollment differs from pinned local plan",
            ));
        }
        Ok(())
    }

    async fn local_key(&self, env: &Env, create: bool) -> Result<LeafKeys, FleetError> {
        let material = match env
            .fs
            .read_secure(self.key_path.clone(), MAX_PEM_BYTES)
            .await
        {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                let key = LeafKeys::generate(env.entropy.as_ref())
                    .map_err(|_| FleetError::Invalid("local leaf generation"))?;
                let pem = Zeroizing::new(key.key_pem().into_bytes());
                env.fs
                    .write_secure_new(self.key_path.clone(), Bytes::from_owner(pem))
                    .await
                    .map_err(|_| FleetError::Persistence)?;
                return Ok(key);
            }
            Err(_) => return Err(FleetError::Invalid("protected local client key file")),
        };
        let text =
            std::str::from_utf8(&material).map_err(|_| FleetError::Invalid("local key PEM"))?;
        LeafKeys::from_pem(text).map_err(|_| FleetError::Invalid("local key PEM"))
    }

    async fn request_key(
        &self,
        env: &Env,
        record: &EnrollmentRecord,
    ) -> Result<LeafKeys, FleetError> {
        let keys = self.local_key(env, false).await?;
        let csr = keys
            .csr_der()
            .map_err(|_| FleetError::Invalid("local leaf CSR"))?;
        if csr != record.csr_der || csr_fingerprint(&csr)? != record.client_key_sha256 {
            return Err(FleetError::Invalid(
                "durable CSR differs from local leaf key",
            ));
        }
        Ok(keys)
    }

    pub(crate) async fn authenticated_net(
        &self,
        env: &Env,
        record: &EnrollmentRecord,
    ) -> Result<Arc<dyn Net>, FleetError> {
        self.validate_plan(&record.plan)?;
        let keys = self.request_key(env, record).await?;
        let cert = record
            .client_cert_der
            .as_ref()
            .ok_or(FleetError::Protocol)?;
        self.validate_certificate(env, record, cert)?;
        env.net
            .with_pinned_tls(TlsConfig {
                ca: self.ca.clone(),
                identity: Some((vec![cert.clone()], keys.key_der())),
            })
            .map_err(|_| FleetError::Invalid("issued client TLS identity"))
    }

    fn validate_certificate(
        &self,
        env: &Env,
        record: &EnrollmentRecord,
        der: &[u8],
    ) -> Result<(), FleetError> {
        let (remaining, cert) = X509Certificate::from_der(der).map_err(|_| FleetError::Protocol)?;
        let (csr_remaining, csr) = X509CertificationRequest::from_der(&record.csr_der)
            .map_err(|_| FleetError::Protocol)?;
        if !remaining.is_empty()
            || !csr_remaining.is_empty()
            || cert.public_key().raw != csr.certification_request_info.subject_pki.raw
        {
            return Err(FleetError::Protocol);
        }
        if !exact_name(
            cert.subject()
                .iter_common_name()
                .map(|value| value.as_str()),
            Some(record.plan.identity.installation.as_str()),
        ) || !exact_name(
            cert.subject()
                .iter_organization()
                .map(|value| value.as_str()),
            record.plan.identity.cluster.as_deref(),
        ) || !exact_name(
            cert.subject()
                .iter_organizational_unit()
                .map(|value| value.as_str()),
            record.plan.identity.node.as_deref(),
        ) {
            return Err(FleetError::Protocol);
        }
        let binding = format!(
            "urn:kronik:fleet:request:{}:{}",
            record.request_id, record.epoch
        );
        let san = cert
            .subject_alternative_name()
            .map_err(|_| FleetError::Protocol)?
            .ok_or(FleetError::Protocol)?;
        if san.value.general_names.len() != 1
            || !matches!(&san.value.general_names[0], x509_parser::extensions::GeneralName::URI(uri) if *uri == binding)
        {
            return Err(FleetError::Protocol);
        }
        let mut roots = rustls::RootCertStore::empty();
        for root in &self.ca {
            roots
                .add(CertificateDer::from(root.clone()))
                .map_err(|_| FleetError::Invalid("controller CA certificate"))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| FleetError::Invalid("controller CA verifier"))?;
        verifier
            .verify_client_cert(
                &CertificateDer::from(der),
                &[],
                UnixTime::since_unix_epoch(Duration::from_millis(env.clock.wall_ms())),
            )
            .map_err(|_| FleetError::Protocol)?;
        Ok(())
    }

    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url)
    }
}

fn exact_name<'a, E>(
    mut names: impl Iterator<Item = Result<&'a str, E>>,
    expected: Option<&str>,
) -> bool {
    match (names.next(), expected) {
        (None, None) => true,
        (Some(Ok(value)), Some(expected)) if value == expected => names.next().is_none(),
        _ => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        value.push(DIGITS[(b >> 4) as usize] as char);
        value.push(DIGITS[(b & 15) as usize] as char);
    }
    value
}

fn csr_fingerprint(der: &[u8]) -> Result<String, FleetError> {
    let (remaining, csr) =
        X509CertificationRequest::from_der(der).map_err(|_| FleetError::Protocol)?;
    if !remaining.is_empty() {
        return Err(FleetError::Protocol);
    }
    Ok(hex(&Sha256::digest(
        csr.certification_request_info.subject_pki.raw,
    )))
}

fn pem(data: &[u8], expected: SectionKind) -> Result<Vec<Vec<u8>>, FleetError> {
    let mut blocks = Vec::new();
    for section in <(SectionKind, Vec<u8>)>::pem_slice_iter(data) {
        let (kind, mut der) = section.map_err(|_| FleetError::Invalid("PEM data"))?;
        if kind != expected {
            der.zeroize();
            blocks.zeroize();
            return Err(FleetError::Invalid("unsupported PEM block"));
        }
        blocks.push(der);
    }
    if blocks.is_empty() {
        return Err(FleetError::Invalid("empty PEM file"));
    }
    Ok(blocks)
}

/// Protected reads fail closed without secure-file custody. Custom CA roots
/// are exclusive in this scoped Net; the guest Net is untouched.
pub async fn load_controller(
    env: &Env,
    config: &ControllerConfig,
) -> Result<ControllerClient, FleetError> {
    let url = canonical_controller_url(&config.url)?;
    let read = |path: PathBuf| env.fs.read_secure(path, MAX_PEM_BYTES);
    let ca_pem = Zeroizing::new(
        read(config.ca_file.clone())
            .await
            .map_err(|_| FleetError::Invalid("protected controller CA file"))?,
    );
    let ca = pem(&ca_pem, SectionKind::Certificate)?;
    let mut roots = Sha256::new();
    for cert in &ca {
        roots.update((cert.len() as u64).to_be_bytes());
        roots.update(cert);
    }
    let ca_hash = hex(&roots.finalize());
    let net = env
        .net
        .with_pinned_tls(TlsConfig {
            ca: ca.clone(),
            identity: None,
        })
        .map_err(|_| FleetError::Invalid("controller TLS configuration"))?;
    Ok(ControllerClient {
        net,
        url,
        ca,
        key_path: config.client_key_file.clone(),
        ca_hash,
    })
}

#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    schema: &'static str,
    request_id: &'a str,
    epoch: u64,
    plan: &'a EnrollmentPlan,
    api_bearer: &'a str,
    csr_der: &'a [u8],
    client_key_sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentResponse {
    pub schema: String,
    pub request_id: String,
    pub epoch: u64,
    pub plan: EnrollmentPlan,
    pub controller_id: String,
    pub client_cert_der: Vec<u8>,
}

// Bound before Requested; no permit or peer result can replace this command.
struct EnrollmentDraft {
    env: Env,
    net: Arc<dyn Net>,
    request: HttpRequest,
    original: AuthLease,
    body_hash: [u8; 32],
    command_hash: [u8; 32],
}

/// Once-owned, already-capacity-reserved controller command. Neither its raw
/// credentials nor a replacement authority are exposed to the dispatcher.
pub struct PreparedEnrollment {
    draft: EnrollmentDraft,
    permit: tokio::sync::OwnedSemaphorePermit,
}

impl PreparedEnrollment {
    pub fn destination(&self) -> &str {
        &self.draft.request.url
    }
    pub fn body_hash(&self) -> [u8; 32] {
        self.draft.body_hash
    }
    pub fn command_hash(&self) -> [u8; 32] {
        self.draft.command_hash
    }

    pub async fn dispatch(self) -> Result<HttpResponse, FleetError> {
        self.dispatch_with_hold(()).await
    }

    /// `hold` retains a transport resource, never supplies or replaces authority.
    /// The bounded control response is collected through actual network EOF.
    pub async fn dispatch_with_hold<H: Send + 'static>(
        self,
        hold: H,
    ) -> Result<HttpResponse, FleetError> {
        self.dispatch_with_admission(move || std::future::ready(Ok(hold)))
            .await
    }

    /// The complete original command is owned by its bounded job before this
    /// callback runs. Confirmation can return resources, never another command.
    pub async fn dispatch_with_admission<F, Fut, H>(
        self,
        before_io: F,
    ) -> Result<HttpResponse, FleetError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<H, FleetError>> + Send + 'static,
        H: Send + 'static,
    {
        let Self { draft, permit } = self;
        let env = draft.env.clone();
        let original = draft.original.clone();
        let job = async move {
            let _permit = permit;
            let EnrollmentDraft {
                env: job_env,
                net,
                request,
                original: retained_original,
                body_hash,
                command_hash,
            } = draft;
            let _descriptor = (body_hash, command_hash);
            job_env
                .timeout(Duration::from_secs(30), async move {
                    let _hold = before_io().await?;
                    // Retain the original lease here through body EOF, not only head.
                    let response = net
                        .http_authorized(request, retained_original.clone())
                        .await
                        .map_err(|_| FleetError::Unavailable)?;
                    if response.body.len() > MAX_ENROLLMENT_BYTES {
                        return Err(FleetError::Unavailable);
                    }
                    Ok::<_, FleetError>(response)
                })
                .await
                .map_err(|_| FleetError::Unavailable)?
        };
        let accepted = env.spawn("fleet-enrollment-http", job);
        tokio::select! {
            biased;
            () = original.cancelled() => Err(FleetError::Revoked),
            response = accepted => response.ok_or(FleetError::Unavailable)?,
        }
    }
}

fn command_hash(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    max: u64,
) -> [u8; 32] {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    field(&mut hash, b"kronik.fleet-enrollment-http/v1");
    field(&mut hash, method.as_bytes());
    field(&mut hash, url.as_bytes());
    field(&mut hash, &(headers.len() as u64).to_be_bytes());
    for (name, value) in headers {
        field(&mut hash, name.as_bytes());
        field(&mut hash, value.as_bytes());
    }
    field(&mut hash, body);
    field(&mut hash, &max.to_be_bytes());
    hash.finalize().into()
}

/// `Requested` is durable before any token transmission. Ambiguous failure must
/// resume this exact durable CSR/request identity, never reuse the one-time token.
/// The callback must compare-and-admit the epoch and preserve prior history.
/// Canonical `Net::http_authorized` admits the exact request at its final queue.
/// Already-started HTTP may finish after revocation; Active still requires the
/// callback's original compare-and-admit fence, never a refreshed authority.
/// The caller shares one capacity slot across enrollment epochs. Its owned
/// permit follows the actual HTTP job to completion, not the cancelled waiter.
/// The required dispatcher receives the reserved producer after Requested.
/// Member callers must complete their sealed original-origin handoff before
/// consuming it; a local receipt or these public hashes are not a Member grant.
pub async fn enroll<P, D>(
    env: &Env,
    client: &ControllerClient,
    mut record: EnrollmentRecord,
    one_time_token: Option<Zeroizing<String>>,
    api_bearer: &str,
    authority: AuthLease,
    capacity: Arc<tokio::sync::Semaphore>,
    dispatch: D,
    mut persist: P,
) -> Result<EnrollmentRecord, FleetError>
where
    P: FnMut(EnrollmentRecord) -> BoxFuture<'static, Result<(), FleetError>>,
    D: FnOnce(PreparedEnrollment) -> BoxFuture<'static, Result<HttpResponse, FleetError>>,
{
    client.validate_plan(&record.plan)?;
    if record.epoch == 0
        || record.request_id.len() != 64
        || !record.request_id.bytes().all(|b| b.is_ascii_hexdigit())
        || api_bearer.is_empty()
        || api_bearer.len() > 4096
        || api_bearer.bytes().any(|b| b.is_ascii_control())
    {
        return Err(FleetError::Invalid(
            "enrollment differs from pinned local plan",
        ));
    }
    if !matches!(
        record.phase,
        EnrollmentPhase::Pending | EnrollmentPhase::Requested
    ) {
        return Err(FleetError::Invalid("enrollment is not pending"));
    }
    let _key = client.request_key(env, &record).await?;
    let initial = record.phase == EnrollmentPhase::Pending;
    let mut headers = vec![("content-type".into(), "application/json".into())];
    if initial {
        let token = one_time_token.as_ref().ok_or(FleetError::Invalid(
            "initial enrollment requires a one-time token",
        ))?;
        if token.is_empty() || token.len() > 4096 || token.bytes().any(|b| b.is_ascii_control()) {
            return Err(FleetError::Invalid("one-time token"));
        }
        headers.push(("authorization".into(), format!("Bearer {}", token.as_str())));
    }
    let body = serde_json::to_vec(&EnrollmentRequest {
        schema: ENROLLMENT_SCHEMA,
        request_id: &record.request_id,
        epoch: record.epoch,
        plan: &record.plan,
        api_bearer,
        csr_der: &record.csr_der,
        client_key_sha256: &record.client_key_sha256,
    })
    .map_err(|_| FleetError::Protocol)?;
    if body.len() > MAX_ENROLLMENT_BYTES {
        return Err(FleetError::Invalid("enrollment body too large"));
    }
    let url = client.endpoint("/v1/enroll");
    let body_hash = Sha256::digest(&body).into();
    let command_hash = command_hash("POST", &url, &headers, &body, MAX_ENROLLMENT_BYTES as u64);
    let draft = EnrollmentDraft {
        env: env.clone(),
        net: client.net.clone(),
        original: authority.clone(),
        body_hash,
        command_hash,
        request: HttpRequest {
            method: "POST".into(),
            url,
            headers,
            body: Bytes::from_owner(Zeroizing::new(body)),
            max_response_bytes: MAX_ENROLLMENT_BYTES as u64,
        },
    };
    if initial {
        persist(record.clone()).await?;
        record.phase = EnrollmentPhase::Requested;
        persist(record.clone()).await?;
    }
    let permit = tokio::select! {
        biased;
        () = authority.cancelled() => return Err(FleetError::Revoked),
        permit = capacity.acquire_owned() => permit.map_err(|_| FleetError::Unavailable)?,
    };
    let response = dispatch(PreparedEnrollment { draft, permit }).await?;
    if response.status != 200 {
        return Err(FleetError::Rejected);
    }
    if response.body.len() > MAX_ENROLLMENT_BYTES {
        return Err(FleetError::Protocol);
    }
    let response: EnrollmentResponse =
        serde_json::from_slice(&response.body).map_err(|_| FleetError::Protocol)?;
    if response.schema != ENROLLMENT_SCHEMA
        || response.request_id != record.request_id
        || response.epoch != record.epoch
        || response.plan != record.plan
        || response.controller_id != record.plan.ca_sha256
    {
        return Err(FleetError::Protocol);
    }
    client.validate_certificate(env, &record, &response.client_cert_der)?;
    record.client_cert_der = Some(response.client_cert_der);
    record.phase = EnrollmentPhase::Active;
    record.controller_id = Some(response.controller_id);
    persist(record.clone()).await?;
    Ok(record)
}
