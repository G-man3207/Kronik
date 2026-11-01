//! Admin-listener OIDC authorization code + PKCE and opaque browser sessions.
//! Product calls still pass through `Api::handle` and the ordinary scopes.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use kronik_core::env::{Env, HttpRequest, OpenMode, TlsConfig};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::SourcePos;
use kronik_proto::log::v1 as pb;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::auth::{Authenticator, Caller, Scope};
use crate::tokens::{TokenAuthenticator, TokenStore};
use crate::{ApiRequest, Query, reason};

const LOGIN_COOKIE: &str = "__Host-kronik-login";
const SESSION_COOKIE: &str = "__Host-kronik-session";
const SESSION_PREFIX: &str = "kronik_ui_";
const LOGIN_MS: u64 = 5 * 60 * 1000;
const SESSION_MS: u64 = 60 * 60 * 1000;
const MAX_PENDING: usize = 256;
const MAX_SESSIONS: usize = 4096;
const PROVIDER_LIMIT: u64 = 256 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub subject: String,
    pub token: String,
}

fn bad(message: &'static str) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}

fn denied() -> ApiError {
    ApiError::new(ErrorCode::Unauthenticated, "OIDC login or browser session is invalid, expired, revoked, or not authorized")
        .with_hint("Sign in again; an operator must explicitly map the verified issuer and subject to a live scoped token.")
}

fn https(value: &str) -> Result<Url, ApiError> {
    let url = Url::parse(value).map_err(|_| bad("OIDC requires an absolute HTTPS URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(bad(
            "OIDC URLs require HTTPS, an authority, and no credentials, query or fragment",
        ));
    }
    Ok(url)
}

impl Config {
    pub fn check(&self) -> Result<(), ApiError> {
        https(&self.issuer)?;
        let redirect = https(&self.redirect_uri)?;
        if self.issuer.len() > 1024
            || self.issuer.ends_with('/')
            || self.redirect_uri.len() > 2048
            || self
                .issuer
                .chars()
                .chain(self.redirect_uri.chars())
                .any(char::is_control)
            || redirect.path() != "/v1/auth/callback"
            || self.client_id.is_empty()
            || self.client_id.len() > 255
            || self.client_id.chars().any(char::is_control)
        {
            return Err(bad(
                "OIDC requires a bounded issuer without a trailing slash, a client_id, and redirect_uri ending /v1/auth/callback",
            ));
        }
        let mut subjects = BTreeSet::new();
        for binding in &self.bindings {
            validate_identity(&self.issuer, &binding.subject)?;
            if !crate::tokens::valid_name(&binding.token) || !subjects.insert(&binding.subject) {
                return Err(bad(
                    "OIDC bindings require unique subjects and valid existing token names",
                ));
            }
        }
        if self.bindings.len() > 1024 {
            return Err(bad("OIDC allows at most 1024 explicit subject bindings"));
        }
        Ok(())
    }

    pub fn origin(&self) -> Result<String, ApiError> {
        Ok(https(&self.redirect_uri)?.origin().ascii_serialization())
    }
}

/// Bound verified claims independently of their opaque public principal.
pub(crate) fn validate_identity(issuer: &str, subject: &str) -> Result<(), ApiError> {
    if issuer.is_empty()
        || issuer.len() > 1024
        || subject.is_empty()
        || subject.len() > 255
        || issuer.chars().chain(subject.chars()).any(char::is_control)
    {
        return Err(denied());
    }
    Ok(())
}

pub(crate) fn principal(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(69);
    value.push_str("oidc:");
    for byte in hash {
        write!(&mut value, "{byte:02x}").expect("writing to String");
    }
    value
}

fn binding_hash(
    sealer: &kronik_privacy::sealer::Sealer,
    issuer: &str,
    subject: &str,
) -> Result<[u8; 32], ApiError> {
    validate_identity(issuer, subject)?;
    sealer
        .keyed_hash(
            "kronik oidc binding v1",
            &[issuer.as_bytes(), subject.as_bytes()],
        )
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "OIDC principal identity key is unavailable",
            )
        })
}

fn verified_identity_value(
    sealer: &kronik_privacy::sealer::Sealer,
    issuer: &str,
    subject: &str,
    owner: &str,
) -> Result<pb::Sealable, ApiError> {
    if principal(&binding_hash(sealer, issuer, subject)?) != owner {
        return Err(denied());
    }
    #[derive(Serialize)]
    struct Payload<'a> {
        issuer: &'a str,
        subject: &'a str,
    }
    Ok(pb::Sealable {
        subject: Some(owner.to_owned()),
        value: Some(pb::sealable::Value::Plain(
            serde_json::to_vec(&Payload { issuer, subject })
                .map_err(|_| crate::internal("cannot encode verified identity"))?,
        )),
    })
}

/// Only authenticated historical evidence, never the current browser profile.
pub(crate) fn open_verified_identity(
    sealer: &kronik_privacy::sealer::Sealer,
    value: &pb::Sealable,
    token_id: &str,
) -> Result<Option<(String, String)>, ApiError> {
    if value.subject.as_deref() != Some(token_id)
        || !matches!(value.value, Some(pb::sealable::Value::Sealed(_)))
    {
        return Err(denied());
    }
    let bytes = match sealer.open(value) {
        kronik_privacy::sealer::Opened::Value(bytes) => bytes,
        kronik_privacy::sealer::Opened::Erased { .. } => return Ok(None),
        kronik_privacy::sealer::Opened::Unreadable { .. } => {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "historical verified identity is unreadable",
            ));
        }
    };
    let identity: Identity = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    if principal(&binding_hash(sealer, &identity.issuer, &identity.subject)?) != token_id {
        return Err(denied());
    }
    Ok(Some((identity.issuer, identity.subject)))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

pub(crate) struct Provider {
    profile: Arc<kronik_proto::log::v1::AuthConfig>,
    env: Env,
    discovery: Discovery,
}

fn same_transport(
    left: &kronik_proto::log::v1::AuthConfig,
    right: &kronik_proto::log::v1::AuthConfig,
) -> bool {
    left.enabled
        && right.enabled
        && left.issuer == right.issuer
        && left.client_id == right.client_id
        && left.redirect_uri == right.redirect_uri
        && left.system_roots == right.system_roots
        && left.trust_roots_sha256 == right.trust_roots_sha256
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcReason {
    NotConfigured,
    ProfileMismatch,
    ProviderUnavailable,
    ConfigurationPending,
    RestartRequired,
}

fn inactive() -> ApiError {
    ApiError::new(ErrorCode::Unavailable, "OIDC login is inactive").with_hint(
        "An authorized administrator can inspect and admit the authentication configuration.",
    )
}

struct Pending {
    browser: [u8; 32],
    verifier: Zeroizing<String>,
    nonce: Zeroizing<String>,
    expires: u64,
    revision: SourcePos,
    generation: u64,
}

#[derive(Clone)]
struct Session {
    principal_hash: [u8; 32],
    verified_identity: Option<Arc<pb::Sealable>>,
    token_name: String,
    token: kronik_core::authority::AuthLease,
    csrf: String,
    expires: u64,
    revision: SourcePos,
    generation: u64,
}

#[derive(Default)]
struct State {
    pending: HashMap<[u8; 32], Pending>,
    sessions: HashMap<[u8; 32], Session>,
    admitted: bool,
    revision: Option<SourcePos>,
    digest: Vec<u8>,
    configuration_generation: u64,
    pending_configuration: Option<u64>,
    runtime_generation: u64,
    profile: Option<Arc<kronik_proto::log::v1::AuthConfig>>,
    provider: Option<Arc<Provider>>,
    oidc_reason: Option<OidcReason>,
}

/// A provider exchange is not a verified session: retain its original physical
/// or administrator lease and exact auth epoch before the first network await.
#[derive(Clone)]
struct ProviderAuthority {
    original: kronik_core::authority::AuthLease,
    state: Arc<Mutex<State>>,
    tokens: Arc<TokenStore>,
    env: Env,
    revision: Option<SourcePos>,
    configuration_generation: u64,
    runtime_generation: u64,
    pending_configuration: Option<u64>,
    admitted: bool,
    expires: u64,
}

impl ProviderAuthority {
    fn new(
        auth: &BrowserAuth,
        state: &State,
        original: kronik_core::authority::AuthLease,
        expires: u64,
    ) -> Self {
        Self {
            original,
            state: auth.state.clone(),
            tokens: auth.tokens.clone(),
            env: auth.env.clone(),
            revision: state.revision,
            configuration_generation: state.configuration_generation,
            runtime_generation: state.runtime_generation,
            pending_configuration: state.pending_configuration,
            admitted: state.admitted,
            expires,
        }
    }
    fn current(&self, state: &State) -> Result<(), ApiError> {
        if state.revision != self.revision
            || state.configuration_generation != self.configuration_generation
            || state.runtime_generation != self.runtime_generation
            || state.pending_configuration != self.pending_configuration
            || state.admitted != self.admitted
            || self.expires <= self.env.clock.wall_ms()
        {
            return Err(denied());
        }
        Ok(())
    }
}

impl kronik_core::authority::Authority for ProviderAuthority {
    fn check(&self) -> Result<(), ApiError> {
        self.original.check()?;
        self.current(&self.state.lock().unwrap_or_else(|error| error.into_inner()))
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.original.admit(&mut || {
            self.current(&self.state.lock().unwrap_or_else(|error| error.into_inner()))?;
            effect()
        })
    }
    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let authority = self.clone();
        Box::pin(async move {
            let changed = authority.tokens.changes();
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if kronik_core::authority::Authority::check(&authority).is_err() {
                    return;
                }
                let remaining = Duration::from_millis(
                    authority
                        .expires
                        .saturating_sub(authority.env.clock.wall_ms()),
                );
                tokio::select! {
                    biased;
                    () = authority.original.cancelled() => return,
                    result = authority.env.timeout(remaining, notified) => if result.is_err() { return; },
                }
            }
        })
    }
}

impl State {
    fn proof_for(
        &self,
        key: [u8; 32],
        session: &Session,
        now: u64,
    ) -> Result<crate::tokens::OidcSessionProof, ApiError> {
        if !self.admitted
            || self.revision != Some(session.revision)
            || self.runtime_generation != session.generation
            || session.expires <= now
        {
            return Err(denied());
        }
        let profile = self.profile.as_ref().ok_or_else(denied)?;
        if BrowserAuth::binding(profile, &session.principal_hash)? != session.token_name {
            return Err(denied());
        }
        Ok(crate::tokens::OidcSessionProof {
            session_blake3: key,
            principal_hash: session.principal_hash,
            config_digest: self.digest.as_slice().try_into().map_err(|_| denied())?,
            config_source: session.revision,
            expires_wall_ms: session.expires,
        })
    }
}

/// The exact durable actor or metadata control source, never a shard maximum.
#[derive(Clone)]
pub struct Admission {
    pub revision: SourcePos,
    pub config: kronik_proto::log::v1::AuthConfig,
}

/// Prepared outside the common publication fence by the durable projection owner.
pub struct PreparedProjection {
    revision: SourcePos,
    profile: Arc<kronik_proto::log::v1::AuthConfig>,
    provider: Option<Arc<Provider>>,
    reason: Option<OidcReason>,
    generation: Option<(u64, u64)>,
}

pub(crate) struct Activation {
    source: SourcePos,
    digest: Vec<u8>,
    configuration_generation: u64,
    runtime_generation: u64,
}

/// Composes the existing token authenticator; it never grants token scopes.
pub struct BrowserAuth {
    env: Env,
    tokens: Arc<TokenStore>,
    ordinary: TokenAuthenticator,
    origin: Option<String>,
    admin_tls: bool,
    sealer: Arc<kronik_privacy::sealer::Sealer>,
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SessionInfo {
    pub authenticated: bool,
    pub oidc_enabled: bool,
    pub oidc_reason: Option<OidcReason>,
    pub principal: Option<String>,
    pub identity: Option<Identity>,
    pub scopes: Vec<String>,
    pub csrf_token: Option<String>,
    pub expires_at_ms: Option<u64>,
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Bytes,
    pub headers: Arc<Vec<(&'static str, String)>>,
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        self.body.as_ref()
    }
}

fn json<T: Serialize>(value: &T) -> Result<Response, ApiError> {
    Ok(Response {
        status: 200,
        content_type: "application/json",
        body: serde_json::to_vec(value)
            .map_err(|_| bad("cannot encode authentication response"))?
            .into(),
        headers: Arc::new(Vec::new()),
    })
}

fn redirect(location: String, cookie: String) -> Response {
    Response {
        status: 303,
        content_type: "text/plain; charset=utf-8",
        body: Bytes::new(),
        headers: Arc::new(vec![("location", location), ("set-cookie", cookie)]),
    }
}

fn cookie(name: &str, value: &str, seconds: u64) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}")
}

fn cookie_value<'a>(header: Option<&'a str>, name: &str) -> Result<Option<&'a str>, ApiError> {
    let mut matches = header.unwrap_or("").split(';').filter_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    });
    let value = matches.next();
    if matches.next().is_some() {
        return Err(denied());
    }
    Ok(value)
}

fn digest(value: &str) -> [u8; 32] {
    *blake3::hash(value.as_bytes()).as_bytes()
}

fn session_credential(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix(SESSION_PREFIX) else {
        return false;
    };
    if encoded.len() != 43 {
        return false;
    }
    let mut decoded = Zeroizing::new([0u8; 33]);
    URL_SAFE_NO_PAD
        .decode_slice(encoded, &mut decoded[..])
        .is_ok_and(|length| length == 32)
}

fn random(env: &Env) -> String {
    URL_SAFE_NO_PAD.encode(env.random_bytes::<32>())
}

async fn pem_ca(env: &Env, path: &std::path::Path) -> Result<Vec<Vec<u8>>, ApiError> {
    use rustls_pki_types::pem::PemObject as _;
    let file = env
        .fs
        .open(path.to_owned(), OpenMode::Read)
        .await
        .map_err(|_| bad("cannot open OIDC CA file"))?;
    let len = file
        .len()
        .await
        .map_err(|_| bad("cannot read OIDC CA file"))?;
    if len == 0 || len > PROVIDER_LIMIT {
        return Err(bad("OIDC CA file exceeds its size limit"));
    }
    let bytes = file
        .read_at(0, len as usize)
        .await
        .map_err(|_| bad("cannot read OIDC CA file"))?;
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(&bytes)
        .map(|cert| cert.map(|cert| cert.as_ref().to_vec()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| bad("invalid OIDC CA file"))?;
    if certs.is_empty() {
        return Err(bad("OIDC CA file has no certificates"));
    }
    Ok(certs)
}

async fn request<T: for<'de> Deserialize<'de>>(
    env: &Env,
    url: &str,
    body: Option<&str>,
    authority: &kronik_core::authority::AuthLease,
) -> Result<T, ApiError> {
    authority.check()?;
    let request = HttpRequest {
        method: if body.is_some() { "POST" } else { "GET" }.into(),
        url: url.into(),
        headers: vec![
            ("accept".into(), "application/json".into()),
            (
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ],
        body: body.unwrap_or("").as_bytes().to_vec().into(),
        max_response_bytes: PROVIDER_LIMIT,
    };
    let response = tokio::select! {
        biased;
        () = authority.cancelled() => return Err(denied()),
        response = env.timeout(Duration::from_secs(10), env.net.http_authorized(request, authority.clone())) => response
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "OIDC provider timed out"))?
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "OIDC provider transport failed"))?,
    };
    authority.check()?;
    // Net performs a single HTTP exchange: redirects are never followed.
    if response.status != 200 {
        return Err(denied());
    }
    serde_json::from_slice(&response.body).map_err(|_| denied())
}

impl BrowserAuth {
    pub async fn open(
        env: Env,
        tokens: Arc<TokenStore>,
        config: Option<Config>,
        admission: Option<Admission>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        admin_tls: bool,
    ) -> Result<Arc<Self>, ApiError> {
        crate::oidc_crypto::install();
        if let Some(config) = &config {
            config.check()?;
        }
        if (config.is_some()
            || admission
                .as_ref()
                .is_some_and(|admission| admission.config.enabled))
            && sealer.keyed_hash("kronik oidc binding v1", &[]).is_none()
        {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "OIDC principal identity key is unavailable",
            ));
        }
        let origin = config.as_ref().map(Config::origin).transpose()?;
        let mut state = State {
            oidc_reason: Some(OidcReason::NotConfigured),
            ..State::default()
        };
        if let Some(admission) = admission {
            if !Self::valid_revision(admission.revision) {
                return Err(bad("authentication configuration lacks a durable source"));
            }
            let operation =
                kronik_proto::log::v1::audit_event::Operation::AuthConfig(admission.config);
            operation
                .validate()
                .map_err(|error| crate::bad(error.to_string()))?;
            let kronik_proto::log::v1::audit_event::Operation::AuthConfig(config) = operation
            else {
                return Err(crate::internal(
                    "unexpected authentication control operation",
                ));
            };
            state.revision = Some(admission.revision);
            state.digest = config.digest.clone();
            state.profile = Some(Arc::new(config));
        }
        let auth = Arc::new(Self {
            env,
            ordinary: TokenAuthenticator::new(tokens.clone()),
            tokens,
            origin,
            admin_tls,
            sealer,
            state: Arc::new(Mutex::new(state)),
        });
        if let Some(config) = config {
            let (operation, roots) = auth.prepare_config(Some(&config), None).await?;
            let kronik_proto::log::v1::audit_event::Operation::AuthConfig(profile) = operation
            else {
                return Err(crate::internal(
                    "unexpected authentication control operation",
                ));
            };
            let admitted = auth.state().profile.clone();
            if let Some(admitted) = admitted {
                if admitted.digest != profile.digest {
                    auth.state().oidc_reason = Some(OidcReason::ProfileMismatch);
                } else {
                    let original = auth.tokens.execution()?.clone();
                    let (provider, reason) = auth.initialize(admitted, roots, original).await?;
                    let mut state = auth.state();
                    state.admitted = provider.is_some();
                    state.provider = provider;
                    state.oidc_reason = reason;
                }
            }
        } else {
            let mut state = auth.state();
            if state
                .profile
                .as_ref()
                .is_some_and(|profile| profile.enabled)
            {
                state.oidc_reason = Some(OidcReason::ProfileMismatch);
            }
        }
        Ok(auth)
    }

    pub(crate) async fn initialize(
        &self,
        profile: Arc<kronik_proto::log::v1::AuthConfig>,
        roots: Vec<Vec<u8>>,
        original: kronik_core::authority::AuthLease,
    ) -> Result<(Option<Arc<Provider>>, Option<OidcReason>), ApiError> {
        original.check()?;
        if !profile.enabled {
            return Ok((None, Some(OidcReason::NotConfigured)));
        }
        if !self.admin_tls
            || https(&profile.redirect_uri)
                .ok()
                .map(|url| url.origin().ascii_serialization())
                .as_deref()
                != self.origin()
        {
            return Ok((None, Some(OidcReason::RestartRequired)));
        }
        let authority: kronik_core::authority::AuthLease = {
            let state = self.state();
            Arc::new(ProviderAuthority::new(
                self,
                &state,
                original,
                self.env.clock.wall_ms().saturating_add(LOGIN_MS),
            ))
        };
        authority.check()?;
        let initialized = async {
            let mut env = self.env.clone();
            let tls = TlsConfig {
                ca: roots,
                identity: None,
            };
            env.net = if profile.system_roots {
                self.env.net.with_tls(tls)
            } else {
                self.env.net.with_pinned_tls(tls)
            }
            .map_err(|_| inactive())?;
            let discovery: Discovery = request(
                &env,
                &format!("{}/.well-known/openid-configuration", profile.issuer),
                None,
                &authority,
            )
            .await?;
            let issuer = https(&profile.issuer)?;
            if discovery.issuer != profile.issuer
                || !discovery
                    .response_types_supported
                    .iter()
                    .any(|v| v == "code")
                || !discovery
                    .id_token_signing_alg_values_supported
                    .iter()
                    .any(|v| v == "RS256")
                || !discovery
                    .code_challenge_methods_supported
                    .iter()
                    .any(|v| v == "S256")
            {
                return Err(denied());
            }
            for endpoint in [
                &discovery.authorization_endpoint,
                &discovery.token_endpoint,
                &discovery.jwks_uri,
            ] {
                if https(endpoint)?.origin() != issuer.origin() {
                    return Err(denied());
                }
            }
            Ok(Arc::new(Provider {
                profile,
                env,
                discovery,
            }))
        }
        .await;
        authority.check()?;
        Ok(match initialized {
            Ok(provider) => (Some(provider), None),
            Err(_) => (None, Some(OidcReason::ProviderUnavailable)),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn session(&self, credential: &str) -> Result<Session, ApiError> {
        if !session_credential(credential) {
            return Err(denied());
        }
        let state = self.state();
        let session = state
            .sessions
            .get(&digest(credential))
            .cloned()
            .ok_or_else(denied)?;
        if !state.admitted
            || Some(session.revision) != state.revision
            || session.generation != state.runtime_generation
            || session.expires <= self.env.clock.wall_ms()
        {
            return Err(denied());
        }
        Ok(session)
    }

    fn session_authority(
        &self,
        state: &State,
        key: [u8; 32],
        session: &Session,
        unpublished: Option<Arc<AtomicBool>>,
    ) -> Result<kronik_core::authority::SessionLease, ApiError> {
        let proof = state.proof_for(key, session, self.env.clock.wall_ms())?;
        let config_source = match proof.config_source {
            SourcePos::Actor { shard: None, lsn } if lsn > 0 => {
                pb::auth_session_revoked::ConfigSource::NativeLsn(lsn)
            }
            _ => return Err(denied()),
        };
        Ok(Arc::new(SessionAuthority {
            state: self.state.clone(),
            env: self.env.clone(),
            tokens: self.tokens.clone(),
            revision: proof.config_source,
            generation: session.generation,
            key,
            expires: proof.expires_wall_ms,
            token: session.token.clone(),
            unpublished,
            revocation: pb::AuthSessionRevoked {
                session_hash: proof.session_blake3.to_vec(),
                principal_hash: proof.principal_hash.to_vec(),
                config_digest: proof.config_digest.to_vec(),
                config_source: Some(config_source),
                token_name: session.token_name.clone(),
                expires_at_ms: proof.expires_wall_ms,
                metadata_token: None,
                peer_boot: None,
            },
        }))
    }

    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// The owner validates the control transition and supplies its durable source.
    pub fn prepare_projection(
        &self,
        operation: &kronik_proto::log::v1::audit_event::Operation,
        revision: SourcePos,
    ) -> Result<PreparedProjection, ApiError> {
        operation
            .validate()
            .map_err(|error| crate::bad(error.to_string()))?;
        let kronik_proto::log::v1::audit_event::Operation::AuthConfig(config) = operation else {
            return Err(bad("expected typed authentication configuration"));
        };
        if !Self::valid_revision(revision) {
            return Err(bad("authentication configuration lacks a durable source"));
        }
        Ok(PreparedProjection {
            revision,
            profile: Arc::new(config.clone()),
            provider: None,
            reason: None,
            generation: None,
        })
    }

    /// Called under TokenStore's single fence after durable local or metadata apply.
    pub fn publish_prepared(&self, projection: PreparedProjection) -> Result<(), ApiError> {
        let mut state = self.state();
        if projection.generation.is_some_and(|(ticket, runtime)| {
            ticket != state.configuration_generation
                || state.pending_configuration != Some(ticket)
                || runtime != state.runtime_generation
        }) {
            return Err(denied());
        }
        match (state.revision, projection.revision) {
            (Some(old), next) if old == next => {
                if projection.profile.digest != state.digest {
                    return Err(denied());
                }
                if projection.generation.is_none() {
                    return Ok(());
                }
            }
            (
                Some(SourcePos::Actor { shard: a, lsn: old }),
                SourcePos::Actor {
                    shard: b,
                    lsn: next,
                },
            ) if a == b && next > old => {}
            (Some(SourcePos::Metadata { index: old }), SourcePos::Metadata { index: next })
                if next > old => {}
            (None, _) => {}
            _ => return Err(denied()),
        }
        let runtime = state.runtime_generation.checked_add(1).ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "authentication runtime generation exhausted",
            )
        })?;
        let (provider, reason) = if projection.generation.is_some() {
            (projection.provider, projection.reason)
        } else if !projection.profile.enabled {
            (None, Some(OidcReason::NotConfigured))
        } else {
            match state
                .provider
                .as_ref()
                .filter(|provider| same_transport(&provider.profile, &projection.profile))
            {
                Some(provider) => (Some(provider.clone()), None),
                None => (None, Some(OidcReason::RestartRequired)),
            }
        };
        state.sessions.clear();
        state.pending.clear();
        state.runtime_generation = runtime;
        state.revision = Some(projection.revision);
        state.digest = projection.profile.digest.clone();
        state.profile = Some(projection.profile);
        state.provider = provider;
        if projection.generation.is_some() {
            state.pending_configuration = None;
        }
        state.admitted = state.provider.is_some() && state.pending_configuration.is_none();
        state.oidc_reason = if state.pending_configuration.is_some() {
            Some(OidcReason::ConfigurationPending)
        } else {
            reason
        };
        Ok(())
    }

    fn valid_revision(revision: SourcePos) -> bool {
        match revision {
            SourcePos::Actor { lsn, .. } => lsn > 0,
            SourcePos::Metadata { index } => index > 0,
        }
    }

    pub(crate) fn next_configuration_generation(&self) -> Result<u64, ApiError> {
        let state = self.state();
        state
            .runtime_generation
            .checked_add(2)
            .and_then(|_| state.configuration_generation.checked_add(1))
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Unavailable,
                    "authentication configuration generation exhausted",
                )
            })
    }

    /// The original admission fence is already held by the successful enqueue.
    pub(crate) fn deny_in_admission(&self, generation: u64) -> u64 {
        let mut state = self.state();
        state.configuration_generation = generation;
        state.pending_configuration = Some(generation);
        state.admitted = false;
        state.runtime_generation += 1;
        state.oidc_reason = Some(OidcReason::ConfigurationPending);
        let runtime = state.runtime_generation;
        state.sessions.clear();
        state.pending.clear();
        drop(state);
        self.tokens.notify_auth_change();
        runtime
    }

    pub(crate) fn configuration_failed(
        &self,
        ticket: &std::sync::atomic::AtomicU64,
    ) -> Result<(), ApiError> {
        let ticket = ticket.load(std::sync::atomic::Ordering::Acquire);
        if ticket == 0 {
            return Ok(());
        }
        self.tokens.publish_auth_change(&mut || {
            let mut state = self.state();
            if state.pending_configuration == Some(ticket) {
                state.pending_configuration = None;
                state.admitted = false;
                state.oidc_reason = Some(OidcReason::ProfileMismatch);
            }
            Ok(())
        })
    }

    pub(crate) async fn prepare_config(
        &self,
        config: Option<&Config>,
        previous: Option<&[u8]>,
    ) -> Result<(kronik_proto::log::v1::audit_event::Operation, Vec<Vec<u8>>), ApiError> {
        if let Some(config) = config {
            config.check()?;
        }
        let roots = match config.and_then(|config| config.ca_file.as_ref()) {
            Some(path) => pem_ca(&self.env, path).await?,
            None => Vec::new(),
        };
        Ok((
            crate::auth_config::prepare(&self.sealer, config, &roots, previous)?,
            roots,
        ))
    }

    pub(crate) fn availability(&self) -> (bool, Option<OidcReason>) {
        let state = self.state();
        (state.admitted, state.oidc_reason)
    }

    pub(crate) fn activation(&self, source: SourcePos, digest: &[u8]) -> Option<Activation> {
        let state = self.state();
        (state.pending_configuration.is_none()
            && state.revision == Some(source)
            && state.digest == digest)
            .then(|| Activation {
                source,
                digest: digest.to_vec(),
                configuration_generation: state.configuration_generation,
                runtime_generation: state.runtime_generation,
            })
    }

    pub(crate) fn check_activation(&self, activation: &Activation) -> Result<(), ApiError> {
        let state = self.state();
        if state.pending_configuration.is_some()
            || state.revision != Some(activation.source)
            || state.digest != activation.digest
            || state.configuration_generation != activation.configuration_generation
            || state.runtime_generation != activation.runtime_generation
        {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn restart_required(&self, profile: &kronik_proto::log::v1::AuthConfig) -> bool {
        profile.enabled
            && (!self.admin_tls
                || https(&profile.redirect_uri)
                    .ok()
                    .map(|url| url.origin().ascii_serialization())
                    .as_deref()
                    != self.origin())
    }

    /// Provider I/O is outside the fence; only this exact committed receipt may activate it.
    pub(crate) async fn publish_current(
        &self,
        node: &kronik_sched::Node,
        source: SourcePos,
        profile: Arc<kronik_proto::log::v1::AuthConfig>,
        provider: Option<Arc<Provider>>,
        reason: Option<OidcReason>,
        ticket: &std::sync::atomic::AtomicU64,
        runtime: &std::sync::atomic::AtomicU64,
    ) -> Result<(), ApiError> {
        let current = node.control_operation(kronik_proto::control::ControlKind::Auth)?;
        if !matches!(&current, Some((revision, kronik_proto::log::v1::audit_event::Operation::AuthConfig(config)))
            if *revision == source && config.digest == profile.digest)
        {
            return Err(denied());
        }
        let mut projection = Some(PreparedProjection {
            revision: source,
            profile,
            provider,
            reason,
            generation: None,
        });
        self.tokens.publish_auth_change(&mut || {
            let mut projection = projection
                .take()
                .ok_or_else(|| crate::internal("authentication projection already consumed"))?;
            let ticket = ticket.load(std::sync::atomic::Ordering::Acquire);
            if ticket == 0 {
                return Err(crate::internal(
                    "configuration completion lacks its original admission",
                ));
            }
            projection.generation =
                Some((ticket, runtime.load(std::sync::atomic::Ordering::Acquire)));
            self.publish_prepared(projection)
        })
    }

    /// Startup reads authority only; an absent profile requires the ordinary authorized PUT.
    pub fn existing_admission(node: &kronik_sched::Node) -> Result<Option<Admission>, ApiError> {
        match node.control_operation(kronik_proto::control::ControlKind::Auth)? {
            Some((revision, kronik_proto::log::v1::audit_event::Operation::AuthConfig(config))) => {
                Ok(Some(Admission { revision, config }))
            }
            Some(_) => Err(crate::internal(
                "unexpected durable authentication configuration family",
            )),
            None => Ok(None),
        }
    }

    fn binding<'a>(
        profile: &'a kronik_proto::log::v1::AuthConfig,
        principal: &[u8; 32],
    ) -> Result<&'a str, ApiError> {
        let index = profile
            .bindings
            .binary_search_by(|binding| binding.principal_hash.as_slice().cmp(principal.as_slice()))
            .map_err(|_| denied())?;
        Ok(&profile.bindings[index].token_name)
    }

    pub fn capture_protocol_request(
        &self,
        req: &ApiRequest,
        api: &crate::Api,
    ) -> Result<Option<crate::CapturedRequest>, ApiError> {
        if req.method == "GET" && req.path == "/v1/auth/session" {
            return if req.bearer.is_some() {
                api.capture_binding(req).map(Some)
            } else {
                Ok(None)
            };
        }
        if req.method != "POST" || req.path != "/v1/auth/logout" {
            return Ok(None);
        }
        let credential = req
            .bearer
            .as_deref()
            .filter(|value| session_credential(value))
            .ok_or_else(denied)?;
        self.session(credential)?;
        api.capture_binding(req).map(Some)
    }

    async fn flow_cancelled(&self, source: SourcePos, generation: u64, expires: u64) {
        let changed = self.tokens.changes();
        loop {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state();
                if !state.admitted
                    || state.revision != Some(source)
                    || state.runtime_generation != generation
                {
                    return;
                }
            }
            let remaining = Duration::from_millis(expires.saturating_sub(self.env.clock.wall_ms()));
            if self.env.timeout(remaining, notified).await.is_err() {
                return;
            }
        }
    }

    /// The bearer wins only when explicitly supplied; cookie credentials never
    /// gain the Unix socket's local identity. Check again in Api after body I/O.
    pub fn credential(
        &self,
        bearer: Option<String>,
        cookies: Option<&str>,
        method: &str,
        origin: Option<&str>,
        csrf: Option<&str>,
    ) -> Result<Option<String>, ApiError> {
        if bearer.is_some() {
            return Ok(bearer);
        }
        let Some(value) = cookie_value(cookies, SESSION_COOKIE)? else {
            return Ok(None);
        };
        let session = self.session(value)?;
        let expected_origin = self.origin().ok_or_else(denied)?;
        if !matches!(method, "GET" | "HEAD" | "OPTIONS")
            && (origin != Some(expected_origin) || csrf != Some(session.csrf.as_str()))
        {
            return Err(ApiError::new(
                ErrorCode::ScopeMissing,
                "browser mutation requires its CSRF token and exact configured Origin",
            ));
        }
        Ok(Some(value.to_owned()))
    }

    /// Authentication operations are public OpenAPI operations on the admin
    /// listener only; product operations are never routed here.
    pub async fn route(
        &self,
        req: &ApiRequest,
        cookies: Option<&str>,
        api: &crate::Api,
        original: Option<crate::CapturedRequest>,
    ) -> Option<Result<Response, ApiError>> {
        let segments: Vec<&str> = req.path.split('/').skip(1).collect();
        let result = match (req.method.as_str(), segments.as_slice()) {
            ("GET", ["v1", "auth", "session"]) => match self.session_info(req, original.as_ref()) {
                Ok(response) => match original {
                    Some(original) => api.complete_browser_response(response, original).await,
                    None => Ok(response),
                },
                Err(error) => Err(error),
            },
            ("GET", ["v1", "auth", "login"]) => self.login(),
            ("GET", ["v1", "auth", "callback"]) => self.callback(req, cookies, api).await,
            ("POST", ["v1", "auth", "logout"]) => match original {
                Some(original) => self.logout(req, api, original).await,
                None => Err(denied()),
            },
            _ => return None,
        };
        Some(result)
    }

    fn session_info(
        &self,
        req: &ApiRequest,
        original: Option<&crate::CapturedRequest>,
    ) -> Result<Response, ApiError> {
        let (active, oidc_reason) = self.availability();
        let mut info = SessionInfo {
            authenticated: false,
            oidc_enabled: active,
            oidc_reason,
            principal: None,
            identity: None,
            scopes: Vec::new(),
            csrf_token: None,
            expires_at_ms: None,
        };
        if req.bearer.is_none() {
            return json(&info);
        }
        let original = original.ok_or_else(denied)?;
        original.authority().check()?;
        let caller = &original.caller;
        info.authenticated = true;
        info.principal = Some(caller.token_id.clone());
        info.scopes = Scope::ALL
            .into_iter()
            .filter(|scope| caller.has(*scope))
            .map(|scope| scope.as_str().to_owned())
            .collect();
        if let Some(credential) = &req.bearer
            && session_credential(credential)
        {
            let session = self.session(credential)?;
            let state = self.state();
            if state.revision != Some(session.revision)
                || state.runtime_generation != session.generation
            {
                return Err(denied());
            }
            drop(state);
            info.identity = open_verified_identity(
                &self.sealer,
                original.verified_identity.as_deref().ok_or_else(denied)?,
                &caller.token_id,
            )?
            .map(|(issuer, subject)| Identity { issuer, subject });
            info.csrf_token = Some(session.csrf);
            info.expires_at_ms = Some(session.expires);
        }
        json(&info)
    }

    fn login(&self) -> Result<Response, ApiError> {
        let mut inner = self.state();
        if !inner.admitted {
            return Err(inactive());
        }
        let provider = inner.provider.clone().ok_or_else(inactive)?;
        let now = self.env.clock.wall_ms();
        let state = random(&self.env);
        let browser = random(&self.env);
        let nonce = Zeroizing::new(random(&self.env));
        let verifier = Zeroizing::new(random(&self.env));
        let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
            &ring::digest::SHA256,
            verifier.as_bytes(),
        ));
        let mut url = https(&provider.discovery.authorization_endpoint)?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", provider.profile.client_id.as_str()),
            ("redirect_uri", provider.profile.redirect_uri.as_str()),
            ("scope", "openid"),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]);
        inner.pending.retain(|_, pending| pending.expires > now);
        if inner.pending.len() >= MAX_PENDING {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "too many pending OIDC logins",
            ));
        }
        let revision = inner.revision.ok_or_else(denied)?;
        let generation = inner.runtime_generation;
        inner.pending.insert(
            digest(&state),
            Pending {
                browser: digest(&browser),
                verifier,
                nonce,
                expires: now.saturating_add(LOGIN_MS),
                revision,
                generation,
            },
        );
        Ok(redirect(
            url.into(),
            cookie(LOGIN_COOKIE, &browser, LOGIN_MS / 1000),
        ))
    }

    fn insert_native_session(
        state: &Mutex<State>,
        now: u64,
        key: [u8; 32],
        session: Session,
        unpublished: &AtomicBool,
    ) -> Result<(), ApiError> {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        if !unpublished.load(Ordering::Acquire) {
            return Err(denied());
        }
        state.sessions.retain(|_, session| session.expires > now);
        if state.sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "too many browser sessions",
            ));
        }
        state.sessions.insert(key, session);
        unpublished.store(false, Ordering::Release);
        Ok(())
    }

    async fn finish_native_login(
        &self,
        api: &crate::Api,
        credential: &str,
        mut session: Session,
        issuer: &str,
        subject: &str,
        required: Scope,
    ) -> Result<(crate::CapturedRequest, PendingSession), ApiError> {
        let key = digest(credential);
        let unpublished = Arc::new(AtomicBool::new(true));
        let cleanup = PendingSession {
            tokens: self.tokens.clone(),
            state: self.state.clone(),
            key: Some(key),
            unpublished: unpublished.clone(),
        };
        let original =
            self.session_authority(&self.state(), key, &session, Some(unpublished.clone()))?;
        let captured =
            self.tokens
                .capture_oidc(required, original, self.env.clock.clone(), None)?;
        let original = captured.session().ok_or_else(denied)?.clone();
        let owner = captured.caller.token_id.clone();
        let (_receipt, plan) = api
            .record_native_oidc_login(
                pb::Audit {
                    token_id: owner.clone(),
                    reason: "verified OIDC authorization-code login".into(),
                    wall_time_ms: self.env.clock.wall_ms(),
                },
                original.clone(),
            )
            .await?;
        let value = verified_identity_value(&self.sealer, issuer, subject, &owner)?;
        let sealer = self.sealer.clone();
        let state = self.state.clone();
        let env = self.env.clone();
        api.seal_native_oidc_identity(sealer, value, plan, original, move |sealed| {
            if sealed.subject.as_deref() != Some(owner.as_str())
                || !matches!(sealed.value, Some(pb::sealable::Value::Sealed(_)))
            {
                return Err(denied());
            }
            session.verified_identity = Some(Arc::new(sealed));
            Self::insert_native_session(&state, env.clock.wall_ms(), key, session, &unpublished)
        })
        .await?;
        Ok((captured, cleanup))
    }

    async fn callback(
        &self,
        req: &ApiRequest,
        cookies: Option<&str>,
        api: &crate::Api,
    ) -> Result<Response, ApiError> {
        let physical = self.tokens.execution()?.clone();
        let query = Query::parse(&req.query)?;
        if query.0.len() > 4
            || query
                .0
                .iter()
                .any(|(key, _)| query.0.iter().filter(|(other, _)| other == key).count() != 1)
        {
            return Err(denied());
        }
        let state = query
            .get("state")
            .filter(|value| value.len() == 43)
            .ok_or_else(denied)?;
        let browser = cookie_value(cookies, LOGIN_COOKIE)?
            .filter(|value| value.len() == 43)
            .ok_or_else(denied)?;
        // Removing before any provider I/O makes even a failed exchange single use.
        let (pending, provider, profile, authority) =
            {
                let mut inner = self.state();
                let pending = inner.pending.remove(&digest(state)).ok_or_else(denied)?;
                if !inner.admitted
                    || inner.revision != Some(pending.revision)
                    || inner.runtime_generation != pending.generation
                {
                    return Err(denied());
                }
                let authority: kronik_core::authority::AuthLease = Arc::new(
                    ProviderAuthority::new(self, &inner, physical, pending.expires),
                );
                (
                    pending,
                    inner.provider.clone().ok_or_else(denied)?,
                    inner.profile.clone().ok_or_else(denied)?,
                    authority,
                )
            };
        if pending.browser != digest(browser)
            || pending.expires <= self.env.clock.wall_ms()
            || query.get("error").is_some()
            || query
                .get("iss")
                .is_some_and(|issuer| issuer != profile.issuer)
        {
            return Err(denied());
        }
        authority.check()?;
        let code = query
            .get("code")
            .filter(|value| !value.is_empty() && value.len() <= 4096)
            .ok_or_else(denied)?;
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", profile.client_id.as_str()),
                    ("redirect_uri", profile.redirect_uri.as_str()),
                    ("code_verifier", pending.verifier.as_str()),
                ])
                .finish(),
        );
        #[derive(Deserialize)]
        struct Token {
            id_token: String,
        }
        let exchange = async {
            let token: Token = request(
                &provider.env,
                &provider.discovery.token_endpoint,
                Some(&form),
                &authority,
            )
            .await?;
            let id_token = Zeroizing::new(token.id_token);
            let keys: JwkSet = request(
                &provider.env,
                &provider.discovery.jwks_uri,
                None,
                &authority,
            )
            .await?;
            verify(
                &profile,
                &id_token,
                &keys,
                &pending.nonce,
                self.env.clock.wall_ms(),
            )
        };
        let claims = tokio::select! {
            biased;
            () = self.flow_cancelled(pending.revision, pending.generation, pending.expires) => return Err(denied()),
            claims = exchange => claims?,
        };
        authority.check()?;
        let principal_hash = binding_hash(&self.sealer, &claims.iss, &claims.sub)?;
        let token_name = Self::binding(&profile, &principal_hash)?;
        let caller = self.tokens.caller_for_name(token_name).ok_or_else(denied)?;
        let required = caller.scopes.iter().next().copied().ok_or_else(denied)?;
        let binding = api.capture_context(self.tokens.capture_name(token_name, required)?, None)?;
        let token_authority = binding.authority;
        let credential = Zeroizing::new(format!("{SESSION_PREFIX}{}", random(&self.env)));
        let now = self.env.clock.wall_ms();
        let expires = claims
            .exp
            .checked_mul(1000)
            .ok_or_else(denied)?
            .min(now.saturating_add(SESSION_MS));
        let session = Session {
            principal_hash,
            verified_identity: None,
            token_name: token_name.to_owned(),
            csrf: random(&self.env),
            token: token_authority,
            expires,
            revision: pending.revision,
            generation: pending.generation,
        };
        let (captured, mut cleanup) = self
            .finish_native_login(
                api,
                &credential,
                session,
                &claims.iss,
                &claims.sub,
                required,
            )
            .await?;
        let mut response = redirect(
            "/ui/".into(),
            cookie(
                SESSION_COOKIE,
                &credential,
                expires.saturating_sub(now) / 1000,
            ),
        );
        Arc::make_mut(&mut response.headers).push(("set-cookie", cookie(LOGIN_COOKIE, "", 0)));
        let response = api.complete_browser_response(response, captured).await?;
        cleanup.key = None;
        Ok(response)
    }

    async fn logout(
        &self,
        req: &ApiRequest,
        api: &crate::Api,
        original: crate::CapturedRequest,
    ) -> Result<Response, ApiError> {
        let body: crate::types::ResendRequest = crate::json(&req.body)?;
        reason(&body.reason)?;
        let mut session = original.session.ok_or_else(denied)?;
        let session_authority: kronik_core::authority::AuthLease = session.clone();
        if !Arc::ptr_eq(&session_authority, &original.authority) {
            session = kronik_core::authority::guard_session(session, original.authority.clone());
        }
        let caller = original.caller;
        original.authority.check()?;
        let credential = req
            .bearer
            .as_deref()
            .filter(|value| session_credential(value))
            .ok_or_else(denied)?;
        let key = digest(credential);
        let revoked = session.revocation();
        let principal_hash = revoked
            .principal_hash
            .as_slice()
            .try_into()
            .map_err(|_| denied())?;
        if key.as_slice() != revoked.session_hash.as_slice()
            || caller.token_id != principal(principal_hash)
        {
            return Err(denied());
        }
        let (node, tokens, state) = (api.node.clone(), self.tokens.clone(), self.state.clone());
        let audit = kronik_proto::log::v1::Audit {
            token_id: caller.token_id,
            reason: body.reason,
            wall_time_ms: self.env.clock.wall_ms(),
        };
        if body.dry_run {
            api.node
                .record_auth_session_revoked(audit, true, session)
                .await?;
            return logout_session(&self.tokens, &self.state, key, true);
        }
        let (done, result) = tokio::sync::oneshot::channel();
        self.env.spawn("oidc-logout", async move {
            let outcome = async {
                node.record_auth_session_revoked(audit, false, session)
                    .await?;
                logout_session(&tokens, &state, key, false)
            }
            .await;
            let _ = done.send(outcome);
        });
        result
            .await
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "browser logout worker stopped"))?
    }
}

/// Neither a draft capability nor its active entry may survive an abandoned callback.
struct PendingSession {
    tokens: Arc<TokenStore>,
    state: Arc<Mutex<State>>,
    key: Option<[u8; 32]>,
    unpublished: Arc<AtomicBool>,
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            let _ = self.tokens.publish_auth_change(&mut || {
                self.unpublished.store(false, Ordering::Release);
                self.state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .sessions
                    .remove(&key);
                Ok(())
            });
        }
    }
}

fn logout_session(
    tokens: &TokenStore,
    state: &Mutex<State>,
    key: [u8; 32],
    dry_run: bool,
) -> Result<Response, ApiError> {
    if !dry_run {
        tokens.publish_auth_change(&mut || {
            state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .sessions
                .remove(&key);
            Ok(())
        })?;
    }
    let mut response = json(&serde_json::json!({"dry_run": dry_run, "logged_out": !dry_run}))?;
    if !dry_run {
        Arc::make_mut(&mut response.headers).push(("set-cookie", cookie(SESSION_COOKIE, "", 0)));
    }
    Ok(response)
}

impl Authenticator for BrowserAuth {
    fn caller(&self, req: &ApiRequest) -> Result<Caller, ApiError> {
        if let Some(credential) = &req.bearer
            && session_credential(credential)
        {
            let session = self.session(credential)?;
            let caller = self
                .tokens
                .caller_for_name(&session.token_name)
                .ok_or_else(denied)?;
            let required = caller.scopes.iter().next().copied().ok_or_else(denied)?;
            return Ok(self.capture(req, required)?.caller);
        }
        self.ordinary.caller(req)
    }

    fn capture(
        &self,
        req: &ApiRequest,
        required: Scope,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let Some(credential) = req
            .bearer
            .as_deref()
            .filter(|value| session_credential(value))
        else {
            return self.ordinary.capture(req, required);
        };
        let key = digest(credential);
        let (original, verified_identity) = {
            let state = self.state();
            let session = state.sessions.get(&key).ok_or_else(denied)?;
            let verified_identity = if req.method == "POST" || req.path == "/v1/auth/session" {
                session.verified_identity.clone()
            } else {
                None
            };
            (
                self.session_authority(&state, key, session, None)?,
                verified_identity,
            )
        };
        let captured = self.tokens.capture_oidc(
            required,
            original,
            self.env.clock.clone(),
            verified_identity,
        )?;
        if req.method == "POST"
            && required == Scope::Approve
            && captured.verified_identity.is_none()
        {
            return Err(denied());
        }
        Ok(captured)
    }

    fn token_source(&self, req: &ApiRequest) -> Result<Option<String>, ApiError> {
        if let Some(credential) = req
            .bearer
            .as_ref()
            .filter(|value| session_credential(value))
        {
            let session = self.session(credential)?;
            return Ok(Some(crate::tokens::token_id(&session.token_name)));
        }
        self.ordinary.token_source(req)
    }

    fn authority(
        &self,
        req: &ApiRequest,
        required: Scope,
    ) -> Result<kronik_core::authority::AuthLease, ApiError> {
        Ok(self.capture(req, required)?.authority)
    }

    fn changes(&self) -> Option<Arc<tokio::sync::Notify>> {
        Some(self.tokens.changes())
    }

    fn expires_at_ms(&self, req: &ApiRequest) -> Option<u64> {
        req.bearer
            .as_ref()
            .filter(|value| session_credential(value))
            .and_then(|value| self.session(value).ok())
            .map(|session| session.expires)
    }
}

#[derive(Clone)]
struct SessionAuthority {
    unpublished: Option<Arc<AtomicBool>>,
    state: Arc<Mutex<State>>,
    env: Env,
    tokens: Arc<TokenStore>,
    key: [u8; 32],
    expires: u64,
    revision: SourcePos,
    generation: u64,
    token: kronik_core::authority::AuthLease,
    revocation: pb::AuthSessionRevoked,
}

impl SessionAuthority {
    fn current(&self, state: &State) -> Result<(), ApiError> {
        if !state.admitted
            || state.revision != Some(self.revision)
            || state.runtime_generation != self.generation
            || self.expires <= self.env.clock.wall_ms()
        {
            return Err(denied());
        }
        if self
            .unpublished
            .as_ref()
            .is_some_and(|pending| pending.load(Ordering::Acquire))
        {
            return Ok(());
        }
        let session = state.sessions.get(&self.key).ok_or_else(denied)?;
        if session.revision != self.revision
            || session.generation != self.generation
            || session.expires != self.expires
        {
            return Err(denied());
        }
        Ok(())
    }
}

impl kronik_core::authority::Authority for SessionAuthority {
    fn check(&self) -> Result<(), ApiError> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        self.current(&state)?;
        drop(state);
        self.token.check()
    }

    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let lease = self.clone();
        Box::pin(async move {
            let changed = lease.tokens.changes();
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if kronik_core::authority::Authority::check(&lease).is_err() {
                    return;
                }
                let remaining =
                    Duration::from_millis(lease.expires.saturating_sub(lease.env.clock.wall_ms()));
                tokio::select! {
                    biased;
                    () = lease.token.cancelled() => return,
                    result = lease.env.timeout(remaining, notified) => if result.is_err() { return; },
                }
            }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        // The ordinary token's publication fence orders logout and final enqueue.
        self.token.admit(&mut || {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            self.current(&state)?;
            drop(state);
            effect()
        })
    }
}

impl kronik_core::authority::SessionAuthority for SessionAuthority {
    fn revocation(&self) -> &pb::AuthSessionRevoked {
        &self.revocation
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    azp: Option<String>,
    nonce: String,
}

fn verify(
    config: &kronik_proto::log::v1::AuthConfig,
    token: &str,
    keys: &JwkSet,
    nonce: &str,
    wall_ms: u64,
) -> Result<Claims, ApiError> {
    if token.len() > 32 << 10 || keys.keys.is_empty() || keys.keys.len() > 64 {
        return Err(denied());
    }
    let header = jsonwebtoken::decode_header(token).map_err(|_| denied())?;
    if header.alg != Algorithm::RS256
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.crit.is_some()
        || header.enc.is_some()
        || header.zip.is_some()
    {
        return Err(denied());
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty() && kid.len() <= 255)
        .ok_or_else(denied)?;
    let mut ids = BTreeSet::new();
    for key in &keys.keys {
        if let Some(id) = &key.common.key_id
            && !ids.insert(id)
        {
            return Err(denied());
        }
    }
    let key = keys
        .keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == Some(kid))
        .ok_or_else(denied)?;
    if key
        .common
        .key_algorithm
        .is_some_and(|algorithm| algorithm != KeyAlgorithm::RS256)
        || key
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| usage != &PublicKeyUse::Signature)
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|ops| ops.as_slice() != [KeyOperations::Verify])
        || !matches!(key.algorithm, AlgorithmParameters::RSA(_))
    {
        return Err(denied());
    }
    let key = DecodingKey::from_jwk(key).map_err(|_| denied())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    // NumericDate checks use Env's clock, not jsonwebtoken's system clock.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|_| denied())?
        .claims;
    let now = wall_ms / 1000;
    let audiences = match &claims.aud {
        Audience::One(value) => vec![value.as_str()],
        Audience::Many(values) => values.iter().map(String::as_str).collect(),
    };
    if claims.iss != config.issuer
        || !audiences.contains(&config.client_id.as_str())
        || (audiences.len() > 1 && claims.azp.as_deref() != Some(config.client_id.as_str()))
        || claims
            .azp
            .as_deref()
            .is_some_and(|azp| azp != config.client_id)
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.iat > now.saturating_add(30)
        || claims.iat.saturating_add(LOGIN_MS / 1000) < now
        || claims.nbf.is_some_and(|nbf| nbf > now)
        || claims.nonce != nonce
    {
        return Err(denied());
    }
    validate_identity(&claims.iss, &claims.sub)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_claim_bounds_and_strict_historical_codec() {
        assert!(validate_identity("https://issuer", "").is_err());
        assert!(validate_identity("https://issuer", &"a".repeat(256)).is_err());
        assert!(validate_identity("https://issuer", "subject\nforged-audit").is_err());
        assert!(validate_identity("https://issuer", "stable|subject").is_ok());
        assert!(
            serde_json::from_str::<Identity>(r#"{"issuer":"a","issuer":"b","subject":"c"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Identity>(r#"{"issuer":"a","subject":"c","jwt":"secret"}"#)
                .is_err()
        );
    }

    fn identity_sealer() -> kronik_privacy::sealer::Sealer {
        let master = kronik_privacy::MasterKey::from_bytes([9; 32]).unwrap();
        let keys = kronik_privacy::keystore::Keystore::open_memory(&master).unwrap();
        kronik_privacy::sealer::Sealer::new(Arc::new(keys))
            .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master).unwrap())
    }

    fn seal_identity(
        sealer: &kronik_privacy::sealer::Sealer,
        env: &Env,
        issuer: &str,
        subject: &str,
        owner: &str,
    ) -> Result<pb::Sealable, ApiError> {
        let mut value = verified_identity_value(sealer, issuer, subject, owner)?;
        sealer
            .reseal_value(
                &mut value,
                None,
                &|bytes| env.entropy.fill(bytes),
                env.clock.wall_ms(),
            )
            .map_err(|_| denied())?;
        if !matches!(value.value, Some(pb::sealable::Value::Sealed(_))) {
            return Err(denied());
        }
        Ok(value)
    }

    #[tokio::test]
    async fn historical_identity_requires_protection_owner_and_exact_binding() {
        let env = Env::real(tokio::runtime::Handle::current());
        let sealer = identity_sealer();
        assert!(!sealer.is_on());
        let owner =
            principal(&binding_hash(&sealer, "https://issuer", "historical-subject").unwrap());
        let value = seal_identity(
            &sealer,
            &env,
            "https://issuer",
            "historical-subject",
            &owner,
        )
        .unwrap();
        assert!(matches!(value.value, Some(pb::sealable::Value::Sealed(_))));
        assert_eq!(
            open_verified_identity(&sealer, &value, &owner).unwrap(),
            Some(("https://issuer".into(), "historical-subject".into()))
        );
        let other = principal(&binding_hash(&sealer, "https://issuer", "other-subject").unwrap());
        assert!(open_verified_identity(&sealer, &value, &other).is_err());
        let mut rebound = value.clone();
        rebound.subject = Some(other.clone());
        assert!(open_verified_identity(&sealer, &rebound, &other).is_err());
        let mut forged = pb::Sealable {
            subject: Some(owner.clone()),
            value: Some(pb::sealable::Value::Plain(
                br#"{"issuer":"https://issuer","subject":"other-subject"}"#.to_vec(),
            )),
        };
        assert!(open_verified_identity(&sealer, &forged, &owner).is_err());
        sealer
            .reseal_value(
                &mut forged,
                None,
                &|bytes| env.entropy.fill(bytes),
                env.clock.wall_ms(),
            )
            .unwrap();
        assert!(open_verified_identity(&sealer, &forged, &owner).is_err());
        let no_keys = kronik_privacy::sealer::Sealer::plain().with_pseudonyms(
            kronik_privacy::keystore::Pseudonyms::new(
                &kronik_privacy::MasterKey::from_bytes([9; 32]).unwrap(),
            )
            .unwrap(),
        );
        assert!(
            seal_identity(
                &no_keys,
                &env,
                "https://issuer",
                "historical-subject",
                &owner
            )
            .is_err()
        );
        assert!(open_verified_identity(&no_keys, &value, &owner).is_err());
        sealer.erase(&owner, env.clock.wall_ms()).unwrap();
        assert_eq!(
            open_verified_identity(&sealer, &value, &owner).unwrap(),
            None
        );
    }

    #[test]
    fn configuration_and_cookie_boundaries_default_deny() {
        let mut config = Config {
            issuer: "https://issuer".into(),
            client_id: "ui".into(),
            redirect_uri: "https://admin/v1/auth/callback".into(),
            ca_file: None,
            bindings: Vec::new(),
        };
        assert!(config.check().is_ok());
        config.issuer = "http://issuer".into();
        assert!(config.check().is_err());
        config.issuer = "https://u:p@issuer".into();
        assert!(config.check().is_err());
        config.issuer = "https://issuer".into();
        config.bindings = vec![
            Binding {
                subject: "reviewer".into(),
                token: "scoped".into()
            };
            2
        ];
        assert!(config.check().is_err());
        assert!(
            cookie_value(
                Some("__Host-kronik-session=a; __Host-kronik-session=b"),
                SESSION_COOKIE
            )
            .is_err()
        );
        assert_eq!(cookie_value(Some("other=a"), SESSION_COOKIE).unwrap(), None);
    }

    fn request(credential: String) -> ApiRequest {
        ApiRequest {
            method: "GET".into(),
            path: "/v1/actors".into(),
            query: String::new(),
            body: Vec::new(),
            token_id: "admin:browser".into(),
            bearer: Some(credential),
        }
    }

    async fn fixture() -> (
        Arc<BrowserAuth>,
        String,
        String,
        (tempfile::TempDir, Arc<kronik_sched::Node>),
    ) {
        fixture_with_scopes([Scope::Read].into()).await
    }

    async fn fixture_with_scopes(
        scopes: BTreeSet<Scope>,
    ) -> (
        Arc<BrowserAuth>,
        String,
        String,
        (tempfile::TempDir, Arc<kronik_sched::Node>),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, credential, bearer) =
            fixture_for_node(&node, scopes, Arc::new(identity_sealer())).await;
        (auth, credential, bearer, (dir, node))
    }

    async fn fixture_for_node(
        node: &Arc<kronik_sched::Node>,
        scopes: BTreeSet<Scope>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
    ) -> (Arc<BrowserAuth>, String, String) {
        fixture_for_node_subject(node, scopes, sealer, "stable-subject").await
    }

    /// The daemon publishes its certified secret inventory from a background
    /// task; a fixture that later reads scrubbed output waits until one
    /// publication has actually landed (the first attempts can race the task).
    async fn wait_for_secret_inventory(node: &Arc<kronik_sched::Node>) {
        let operator = node.local_operator_authority().unwrap();
        for _ in 0..200 {
            if node
                .refresh_secret_inventory(operator.clone())
                .await
                .is_ok()
            {
                return;
            }
            node.env()
                .clock
                .sleep(std::time::Duration::from_millis(5))
                .await;
        }
        panic!("the daemon's certified secret inventory never published");
    }

    async fn fixture_for_node_subject(
        node: &Arc<kronik_sched::Node>,
        scopes: BTreeSet<Scope>,
        sealer: Arc<kronik_privacy::sealer::Sealer>,
        subject: &str,
    ) -> (Arc<BrowserAuth>, String, String) {
        let env = node.env().clone();
        let mut tokens = TokenStore::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
        let publication = node.publication_domain();
        tokens.bind_before_any_issuer(publication.clone()).unwrap();
        tokens
            .bind_execution_before_any_issuer(
                &publication,
                node.local_operator_authority().unwrap(),
            )
            .unwrap();
        let tokens = Arc::new(tokens);
        let (_, bearer) = tokens
            .create(
                "reader",
                scopes.clone(),
                [7; 32],
                &crate::tokens::Change {
                    wall_ms: env.clock.wall_ms(),
                    by: "unix:uid=0",
                    reason: "fixture",
                },
                false,
            )
            .unwrap();
        let credential = format!("{SESSION_PREFIX}{}", random(&env));
        let config = Config {
            issuer: "https://issuer".into(),
            client_id: "ui".into(),
            redirect_uri: "https://admin/v1/auth/callback".into(),
            ca_file: None,
            bindings: vec![Binding {
                subject: subject.to_owned(),
                token: "reader".into(),
            }],
        };
        let kronik_proto::log::v1::audit_event::Operation::AuthConfig(profile) =
            crate::auth_config::prepare(&sealer, Some(&config), &[], None).unwrap()
        else {
            panic!("wrong control family")
        };
        let principal_hash: [u8; 32] = profile.bindings[0]
            .principal_hash
            .as_slice()
            .try_into()
            .unwrap();
        let profile = Arc::new(profile);
        let source = node
            .record_control_operation(
                pb::audit_event::Operation::AuthConfig((*profile).clone()),
                pb::Audit {
                    token_id: "unix:uid=0".into(),
                    reason: "admit real browser fixture".into(),
                    wall_time_ms: env.clock.wall_ms(),
                },
                false,
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let provider = Arc::new(Provider {
            profile: profile.clone(),
            env: env.clone(),
            discovery: Discovery {
                issuer: "https://issuer".into(),
                authorization_endpoint: "https://issuer/authorize".into(),
                token_endpoint: "https://issuer/token".into(),
                jwks_uri: "https://issuer/keys".into(),
                response_types_supported: vec!["code".into()],
                id_token_signing_alg_values_supported: vec!["RS256".into()],
                code_challenge_methods_supported: vec!["S256".into()],
            },
        });
        let token = tokens
            .authority_for_name("reader", *scopes.iter().next().unwrap())
            .unwrap();
        let auth = Arc::new(BrowserAuth {
            env: env.clone(),
            tokens: tokens.clone(),
            ordinary: TokenAuthenticator::new(tokens),
            origin: Some("https://admin".into()),
            admin_tls: true,
            sealer,
            state: Arc::new(Mutex::new(State {
                admitted: true,
                revision: Some(source),
                digest: profile.digest.clone(),
                profile: Some(profile),
                provider: Some(provider),
                ..State::default()
            })),
        });
        auth.state().sessions.insert(
            digest(&credential),
            Session {
                principal_hash,
                verified_identity: Some(Arc::new(
                    seal_identity(
                        &auth.sealer,
                        &env,
                        "https://issuer",
                        subject,
                        &principal(&principal_hash),
                    )
                    .unwrap(),
                )),
                token_name: "reader".into(),
                token,
                csrf: "csrf".into(),
                expires: env.clock.wall_ms() + 60_000,
                revision: source,
                generation: 0,
            },
        );
        // The auth-config record bumped the epoch; re-publish the certified
        // inventory so a test that reads scrubbed output does not race it.
        wait_for_secret_inventory(node).await;
        (auth, credential, bearer.unwrap())
    }

    #[tokio::test]
    async fn provider_epoch_revocation_fences_real_queue_without_revoking_unrelated_bearer() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (auth, _, bearer, (_dir, node)) =
                fixture_with_scopes([Scope::Read, Scope::Operate].into()).await;
            let original = auth.tokens.execution().unwrap().clone();
            let authority: kronik_core::authority::AuthLease = {
                let state = auth.state();
                Arc::new(ProviderAuthority::new(
                    &auth,
                    &state,
                    original,
                    auth.env.clock.wall_ms() + LOGIN_MS,
                ))
            };
            let audit = || pb::Audit {
                token_id: "unix:uid=0".into(),
                reason: "provider epoch consumer".into(),
                wall_time_ms: auth.env.clock.wall_ms(),
            };
            node.record_audit_event_authorized(
                "test.provider",
                "initial-exchange",
                Default::default(),
                audit(),
                authority.clone(),
            )
            .await
            .unwrap();
            let profile = auth.state().profile.clone().unwrap();
            let disabled =
                crate::auth_config::prepare(&auth.sealer, None, &[], Some(&profile.digest))
                    .unwrap();
            let source = node
                .record_control_operation(
                    disabled.clone(),
                    audit(),
                    false,
                    node.local_operator_authority().unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
            let mut projection = Some(auth.prepare_projection(&disabled, source).unwrap());
            auth.tokens
                .publish_auth_change(&mut || auth.publish_prepared(projection.take().unwrap()))
                .unwrap();
            authority.cancelled().await;
            let before = node.applied_lsn();
            assert!(
                node.record_audit_event_authorized(
                    "test.provider",
                    "stale-exchange",
                    Default::default(),
                    audit(),
                    authority
                )
                .await
                .is_err()
            );
            assert_eq!(node.applied_lsn(), before);
            let unrelated = auth
                .tokens
                .authority_for_token(&bearer, Scope::Operate)
                .unwrap();
            let accepted = node
                .record_audit_event_authorized(
                    "test.provider",
                    "ordinary-bearer",
                    Default::default(),
                    audit(),
                    unrelated,
                )
                .await
                .unwrap();
            let mut targets = Vec::new();
            node.reader()
                .read(before + 1, accepted, |entry| {
                    if let kronik_proto::Record::AuditEvent(event) = &entry.record {
                        targets.push(event.target.clone());
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(targets, ["ordinary-bearer"]);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn typed_config_publication_does_not_upgrade_old_sessions_or_source_domains() {
        let (auth, credential, _, (_dir, node)) = fixture().await;
        let lease = auth.authority(&request(credential), Scope::Read).unwrap();
        auth.login().unwrap();
        let original_source = auth.state().revision.unwrap();
        let profile = auth.state().profile.clone().unwrap();
        let disabled =
            crate::auth_config::prepare(&auth.sealer, None, &[], Some(&profile.digest)).unwrap();
        let SourcePos::Actor { shard: None, lsn } = original_source else {
            panic!("expected actual native fixture source")
        };
        let mut foreign = Some(
            auth.prepare_projection(&disabled, SourcePos::Metadata { index: lsn })
                .unwrap(),
        );
        assert!(
            auth.tokens
                .publish_auth_change(&mut || auth.publish_prepared(foreign.take().unwrap()))
                .is_err()
        );
        assert!(lease.check().is_ok());
        let committed = node
            .record_control_operation(
                disabled.clone(),
                pb::Audit {
                    token_id: "unix:uid=0".into(),
                    reason: "commit disabled authentication profile".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                false,
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let mut next = Some(auth.prepare_projection(&disabled, committed).unwrap());
        auth.tokens
            .publish_auth_change(&mut || auth.publish_prepared(next.take().unwrap()))
            .unwrap();
        assert!(lease.check().is_err());
        assert!(auth.state().pending.is_empty());
        assert!(auth.state().sessions.is_empty());
        assert!(auth.login().is_err());
        let mut stale = Some(auth.prepare_projection(&disabled, original_source).unwrap());
        assert!(
            auth.tokens
                .publish_auth_change(&mut || auth.publish_prepared(stale.take().unwrap()))
                .is_err()
        );
    }

    #[tokio::test]
    async fn older_owned_completion_cannot_reopen_a_newer_enqueue_denial() {
        let (auth, _, _, _fixture) = fixture().await;
        let first = auth.next_configuration_generation().unwrap();
        auth.tokens
            .publish_auth_change(&mut || {
                auth.deny_in_admission(first);
                Ok(())
            })
            .unwrap();
        let (profile, provider, runtime) = {
            let state = auth.state();
            (
                state.profile.clone().unwrap(),
                state.provider.clone(),
                state.runtime_generation,
            )
        };
        let mut earlier = Some(PreparedProjection {
            revision: auth.state().revision.unwrap(),
            profile,
            provider,
            reason: None,
            generation: Some((first, runtime)),
        });
        let newer = auth.next_configuration_generation().unwrap();
        auth.tokens
            .publish_auth_change(&mut || {
                auth.deny_in_admission(newer);
                Ok(())
            })
            .unwrap();
        auth.configuration_failed(&std::sync::atomic::AtomicU64::new(first))
            .unwrap();
        assert!(
            auth.tokens
                .publish_auth_change(&mut || auth.publish_prepared(earlier.take().unwrap()))
                .is_err()
        );
        assert!(auth.login().is_err());
        assert_eq!(auth.state().pending_configuration, Some(newer));
    }

    #[tokio::test]
    async fn successful_enqueue_can_deny_sessions_inside_the_same_original_fence() {
        let (auth, credential, _, (_dir, node)) = fixture().await;
        let lease = auth.authority(&request(credential), Scope::Read).unwrap();
        let profile = auth.state().profile.clone().unwrap();
        let original_source = auth.state().revision.unwrap();
        let activation = auth.activation(original_source, &profile.digest).unwrap();
        let (_, administrator) = auth
            .tokens
            .create(
                "configuration-administrator",
                [Scope::Admin].into(),
                [9; 32],
                &crate::tokens::Change {
                    wall_ms: auth.env.clock.wall_ms(),
                    by: "unix:uid=0",
                    reason: "configuration consumer",
                },
                false,
            )
            .unwrap();
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let mut mutation = request(administrator.unwrap());
        mutation.method = "PUT".into();
        mutation.path = "/v1/auth/config".into();
        mutation.body = serde_json::to_vec(&serde_json::json!({
            "config": null, "reason": "disable through the ordinary authorized API", "dry_run": false
        })).unwrap();
        assert_eq!(api.handle(mutation).await.status, 200);
        let committed = node
            .control_operation(kronik_proto::control::ControlKind::Auth)
            .unwrap()
            .unwrap()
            .0;
        assert_ne!(committed, original_source);
        assert_eq!(auth.state().revision, Some(committed));
        assert!(lease.check().is_err());
        assert!(auth.check_activation(&activation).is_err());
    }

    #[tokio::test]
    async fn inactive_oidc_preserves_ordinary_bearer_and_unix_authority() {
        let (configured, credential, bearer, _fixture) = fixture().await;
        let auth = BrowserAuth::open(
            configured.env.clone(),
            configured.tokens.clone(),
            None,
            None,
            configured.sealer.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            auth.availability(),
            (false, Some(OidcReason::NotConfigured))
        );
        assert_eq!(auth.login().err().unwrap().code, ErrorCode::Unavailable);
        assert!(auth.caller(&request(credential)).is_err());
        let ordinary = request(bearer);
        assert!(auth.caller(&ordinary).unwrap().has(Scope::Read));
        auth.authority(&ordinary, Scope::Read)
            .unwrap()
            .check()
            .unwrap();
        let mut local = request(String::new());
        local.bearer = None;
        local.token_id = "unix:uid=0".into();
        assert!(auth.caller(&local).unwrap().has(Scope::Admin));
        auth.authority(&local, Scope::Admin)
            .unwrap()
            .check()
            .unwrap();
        local.token_id = "admin:browser".into();
        assert!(auth.caller(&local).is_err());
    }

    #[tokio::test]
    async fn ordinary_session_prefix_token_keeps_its_real_api_authority() {
        let (configured, credential, _, (_dir, node)) = fixture().await;
        let mut entropy = [0; 32];
        entropy[..3].copy_from_slice(&[0xba, 0x2f, 0xc0]);
        let change = crate::tokens::Change {
            wall_ms: configured.env.clock.wall_ms(),
            by: "unix:uid=0",
            reason: "ordinary token with a session-looking prefix",
        };
        let (_, bearer) = configured
            .tokens
            .create(
                "prefix-collision",
                [Scope::Read].into(),
                entropy,
                &change,
                false,
            )
            .unwrap();
        let bearer = bearer.unwrap();
        assert!(bearer.starts_with("kronik_ui_A"));
        let ordinary = request(bearer.clone());
        let disabled = BrowserAuth::open(
            configured.env.clone(),
            configured.tokens.clone(),
            None,
            None,
            configured.sealer.clone(),
            true,
        )
        .await
        .unwrap();
        for auth in [configured.clone(), disabled] {
            let api = crate::Api::new(node.clone())
                .with_tokens(auth.tokens.clone())
                .unwrap()
                .with_browser(auth.clone());
            assert_eq!(
                auth.caller(&ordinary).unwrap().token_id,
                "token:prefix-collision"
            );
            assert_eq!(
                auth.token_source(&ordinary).unwrap().as_deref(),
                Some("token:prefix-collision")
            );
            assert!(auth.expires_at_ms(&ordinary).is_none());
            let captured = api.capture(&ordinary).unwrap();
            assert!(captured.session().is_none());
            assert_eq!(
                api.handle_admitted(ordinary.clone(), captured).await.status,
                200
            );
            let mut info_request = ordinary.clone();
            info_request.path = "/v1/auth/session".into();
            let captured = auth.capture_protocol_request(&info_request, &api).unwrap();
            let info = auth
                .route(&info_request, None, &api, captured)
                .await
                .unwrap()
                .unwrap();
            let info: serde_json::Value = serde_json::from_slice(&info.body).unwrap();
            assert_eq!(info["principal"], "token:prefix-collision");
            assert_eq!(info["authenticated"], true);
            assert!(info.get("identity").is_none_or(serde_json::Value::is_null));
            assert!(
                auth.credential(
                    None,
                    Some(&format!("{SESSION_COOKIE}={bearer}")),
                    "GET",
                    None,
                    None
                )
                .is_err()
            );
            for invalid in [
                format!("{SESSION_PREFIX}{}", URL_SAFE_NO_PAD.encode([0xff; 32])),
                format!("{SESSION_PREFIX}{}!", "A".repeat(42)),
                format!("{SESSION_PREFIX}{}B", "A".repeat(42)),
            ] {
                let request = request(invalid);
                assert!(auth.caller(&request).is_err());
                assert!(api.capture(&request).is_err());
                assert_eq!(api.handle(request).await.status, 401);
            }
        }
        let api = crate::Api::new(node)
            .with_tokens(configured.tokens.clone())
            .unwrap()
            .with_browser(configured.clone());
        let session_request = request(credential);
        let original_session = api.capture(&session_request).unwrap();
        assert_eq!(api.handle(session_request.clone()).await.status, 200);
        configured
            .tokens
            .revoke("prefix-collision", &change, false)
            .unwrap();
        assert_eq!(api.handle(ordinary).await.status, 401);
        assert_eq!(api.handle(session_request.clone()).await.status, 200);
        configured.tokens.revoke("reader", &change, false).unwrap();
        assert!(original_session.authority().check().is_err());
        assert!(configured.caller(&session_request).is_err());
        assert!(api.capture(&session_request).is_err());
        assert_eq!(api.handle(session_request).await.status, 401);
    }

    #[tokio::test]
    async fn valid_startup_file_does_not_admit_or_replace_durable_authority() {
        let (configured, _, _, _fixture) = fixture().await;
        let profile = configured.state().profile.clone().unwrap();
        let config = Config {
            issuer: profile.issuer.clone(),
            client_id: "different-valid-client".into(),
            redirect_uri: profile.redirect_uri.clone(),
            ca_file: None,
            bindings: Vec::new(),
        };
        let fresh = BrowserAuth::open(
            configured.env.clone(),
            configured.tokens.clone(),
            Some(config.clone()),
            None,
            configured.sealer.clone(),
            true,
        )
        .await
        .unwrap();
        assert!(fresh.state().profile.is_none());
        assert_eq!(
            fresh.availability(),
            (false, Some(OidcReason::NotConfigured))
        );
        let revision = configured.state().revision.unwrap();
        let reopened = BrowserAuth::open(
            configured.env.clone(),
            configured.tokens.clone(),
            Some(config),
            Some(Admission {
                revision,
                config: (*profile).clone(),
            }),
            configured.sealer.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            reopened.availability(),
            (false, Some(OidcReason::ProfileMismatch))
        );
        assert_eq!(reopened.state().revision, Some(revision));
        assert_eq!(reopened.state().digest, profile.digest);
        assert_eq!(reopened.login().err().unwrap().code, ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn same_source_refresh_never_upgrades_old_pending_or_session() {
        let (auth, credential, _, _fixture) = fixture().await;
        let lease = auth
            .authority(&request(credential.clone()), Scope::Read)
            .unwrap();
        let old_session = auth.session(&credential).unwrap();
        auth.login().unwrap();
        let (profile, provider, revision, old_flow_generation) = {
            let state = auth.state();
            (
                state.profile.clone().unwrap(),
                state.provider.clone(),
                state.revision.unwrap(),
                state.pending.values().next().unwrap().generation,
            )
        };
        let mut projection = None;
        auth.tokens
            .publish_auth_change(&mut || {
                let ticket = auth.next_configuration_generation()?;
                let runtime = auth.deny_in_admission(ticket);
                projection = Some(PreparedProjection {
                    revision,
                    profile: profile.clone(),
                    provider: provider.clone(),
                    reason: None,
                    generation: Some((ticket, runtime)),
                });
                Ok(())
            })
            .unwrap();
        auth.tokens
            .publish_auth_change(&mut || auth.publish_prepared(projection.take().unwrap()))
            .unwrap();
        assert!(auth.availability().0);
        assert_eq!(auth.state().revision, Some(revision));
        assert!(auth.state().pending.is_empty());
        assert_ne!(auth.state().runtime_generation, old_flow_generation);
        assert!(lease.check().is_err());
        auth.flow_cancelled(
            revision,
            old_flow_generation,
            auth.env.clock.wall_ms() + LOGIN_MS,
        )
        .await;
        // Even retaining a tentative old session cannot upgrade its runtime epoch.
        auth.state()
            .sessions
            .insert(digest(&credential), old_session);
        assert!(auth.session(&credential).is_err());
    }

    #[tokio::test]
    async fn mapping_publication_acknowledges_without_reopening_local_pending() {
        let (auth, credential, _, (_dir, node)) = fixture().await;
        let original = auth.authority(&request(credential), Scope::Read).unwrap();
        let mut profile = (*auth.state().profile.clone().unwrap()).clone();
        profile.bindings.clear();
        profile.previous_digest = profile.digest.clone();
        profile.digest = kronik_proto::control::auth_config_digest(&profile).to_vec();
        let operation = kronik_proto::log::v1::audit_event::Operation::AuthConfig(profile);
        let source = node
            .record_control_operation(
                operation.clone(),
                pb::Audit {
                    token_id: "unix:uid=0".into(),
                    reason: "commit actual incoming mapping change".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                false,
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let mut projection = Some(auth.prepare_projection(&operation, source).unwrap());
        let ticket = auth.next_configuration_generation().unwrap();
        auth.tokens
            .publish_auth_change(&mut || {
                auth.deny_in_admission(ticket);
                Ok(())
            })
            .unwrap();
        auth.tokens
            .publish_auth_change(&mut || auth.publish_prepared(projection.take().unwrap()))
            .unwrap();
        assert!(original.check().is_err());
        let state = auth.state();
        assert_eq!(state.revision, Some(source));
        assert_eq!(state.pending_configuration, Some(ticket));
        assert!(state.profile.as_ref().unwrap().bindings.is_empty());
        assert!(!state.admitted);
        assert_eq!(state.oidc_reason, Some(OidcReason::ConfigurationPending));
        let source = state.revision.unwrap();
        let digest = state.digest.clone();
        drop(state);
        auth.configuration_failed(&std::sync::atomic::AtomicU64::new(ticket))
            .unwrap();
        assert!(!auth.availability().0);
        assert!(auth.state().pending_configuration.is_none());
        assert!(auth.activation(source, &digest).is_some());
    }

    #[tokio::test]
    async fn authenticated_reader_post_is_scope_denied_before_identity_evidence() {
        let (auth, credential, _bearer, (_dir, _node)) = fixture().await;
        let mut req = request(credential);
        req.method = "POST".into();
        assert_eq!(
            auth.capture(&req, Scope::Approve)
                .err()
                .unwrap()
                .code
                .http_status(),
            403
        );

        let (auth, credential, _bearer, (_dir, _node)) =
            fixture_with_scopes([Scope::Approve].into()).await;
        auth.state()
            .sessions
            .get_mut(&digest(&credential))
            .unwrap()
            .verified_identity = None;
        let mut req = request(credential);
        req.method = "POST".into();
        assert_eq!(
            auth.capture(&req, Scope::Approve)
                .err()
                .unwrap()
                .code
                .http_status(),
            401
        );
    }

    #[tokio::test]
    async fn captured_revoked_session_cannot_mutate_log_while_unrelated_bearer_can() {
        let (auth, credential, bearer, (_dir, node)) = fixture().await;
        let req = request(credential.clone());
        let captured = auth.capture(&req, Scope::Read).unwrap();
        captured.require_scope(Scope::Read).unwrap();
        assert!(captured.principal.is_none());
        let session = captured.session().unwrap();
        let caller = auth.caller(&req).unwrap();
        assert_eq!(
            caller.token_id,
            principal(&auth.session(&credential).unwrap().principal_hash)
        );
        assert_eq!(caller.token_id.len(), 69);
        assert!(
            caller.token_id[5..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(!caller.token_id.contains("stable-subject"));
        assert!(captured.verified_identity.is_none());
        assert!(caller.has(Scope::Read));
        assert!(!caller.has(Scope::Approve));
        assert!(auth.authority(&req, Scope::Approve).is_err());
        let change = crate::tokens::Change {
            wall_ms: auth.env.clock.wall_ms(),
            by: "unix:uid=0",
            reason: "unrelated bearer",
        };
        let (_, unrelated) = auth
            .tokens
            .create("unrelated", [Scope::Read].into(), [8; 32], &change, false)
            .unwrap();
        assert!(auth.caller(&request(bearer)).unwrap().has(Scope::Read));
        auth.tokens
            .revoke(
                "reader",
                &crate::tokens::Change {
                    wall_ms: auth.env.clock.wall_ms(),
                    by: "unix:uid=0",
                    reason: "revoke fixture",
                },
                false,
            )
            .unwrap();
        assert!(auth.caller(&req).is_err());
        assert!(captured.require_scope(Scope::Read).is_err());
        assert!(session.check().is_err());
        let before = node.applied_lsn();
        let denied = node
            .record_audit_event_authorized(
                "operator.note",
                "stale-browser",
                Default::default(),
                pb::Audit {
                    token_id: caller.token_id,
                    reason: "captured before body".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                session.clone(),
            )
            .await;
        assert!(denied.is_err());
        assert_eq!(node.applied_lsn(), before);
        let unrelated = auth
            .tokens
            .capture_token(&unrelated.unwrap(), Scope::Read)
            .unwrap();
        let lsn = node
            .record_audit_event_authorized(
                "operator.note",
                "unrelated-bearer",
                Default::default(),
                pb::Audit {
                    token_id: unrelated.caller.token_id,
                    reason: "still authorized".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                unrelated.authority,
            )
            .await
            .unwrap();
        assert!(lsn > before);
        assert_eq!(node.applied_lsn(), lsn);
    }

    #[tokio::test]
    async fn revoked_full_guard_denies_real_log_mutation_without_revoking_original_session() {
        let (auth, credential, _, (_dir, node)) = fixture().await;
        let req = request(credential.clone());
        let captured = auth.capture(&req, Scope::Read).unwrap();
        let session = captured.session().unwrap().clone();
        let mut guards = TokenStore::open(rusqlite::Connection::open_in_memory().unwrap()).unwrap();
        let publication = node.publication_domain();
        guards.bind_before_any_issuer(publication.clone()).unwrap();
        guards
            .bind_execution_before_any_issuer(
                &publication,
                node.local_operator_authority().unwrap(),
            )
            .unwrap();
        let guards = Arc::new(guards);
        let change = crate::tokens::Change {
            wall_ms: auth.env.clock.wall_ms(),
            by: "unix:uid=0",
            reason: "guard fixture",
        };
        guards
            .create("guard", [Scope::Read].into(), [4; 32], &change, false)
            .unwrap();
        let guarded = kronik_core::authority::guard_session(
            session.clone(),
            guards.authority_for_name("guard", Scope::Read).unwrap(),
        );
        guards.revoke("guard", &change, false).unwrap();
        let audit = pb::Audit {
            token_id: captured.caller.token_id,
            reason: "guarded consumer".into(),
            wall_time_ms: auth.env.clock.wall_ms(),
        };
        let before = node.applied_lsn();
        assert!(
            node.record_audit_event_authorized(
                "operator.note",
                "revoked-guard",
                Default::default(),
                audit.clone(),
                guarded
            )
            .await
            .is_err()
        );
        assert_eq!(node.applied_lsn(), before);
        let lsn = node
            .record_audit_event_authorized(
                "operator.note",
                "original-session",
                Default::default(),
                audit,
                session.clone(),
            )
            .await
            .unwrap();
        assert!(lsn > before);
        assert_eq!(node.applied_lsn(), lsn);
        {
            let mut state = auth.state();
            let Some(SourcePos::Actor { lsn, .. }) = state.revision else {
                panic!("expected original native profile")
            };
            let foreign = SourcePos::Metadata { index: lsn };
            state.revision = Some(foreign);
            state
                .sessions
                .get_mut(&digest(&credential))
                .unwrap()
                .revision = foreign;
        }
        assert!(auth.capture(&req, Scope::Read).is_err());
        assert!(session.check().is_err());
    }

    #[tokio::test]
    async fn nested_post_capture_reaches_protected_approval_consumer_without_refreshing_identity() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, credential, bearer) = fixture_for_node(
            &node,
            [Scope::Read, Scope::Approve].into(),
            node.sealer().clone(),
        )
        .await;
        let other_credential = format!("{SESSION_PREFIX}{}", random(&auth.env));
        let other_session = auth.session(&credential).unwrap();
        auth.state()
            .sessions
            .insert(digest(&other_credential), other_session);
        let mut req = request(credential.clone());
        req.method = "POST".into();
        req.path = "/mcp".into();
        let captured = auth.capture(&req, Scope::Read).unwrap();
        req.token_id = "oidc:spoofed-body-authority".into();
        req.body = br#"{"issuer":"https://attacker","subject":"spoofed"}"#.to_vec();
        auth.state()
            .sessions
            .get_mut(&digest(&credential))
            .unwrap()
            .verified_identity = None;
        captured.require_scope(Scope::Approve).unwrap();
        let approval = pb::Approval {
            proposal_id: "p-nested-original".into(),
            diff_hash: vec![3; 32],
            verified_through_lsn: node.applied_lsn(),
            audit: Some(pb::Audit {
                token_id: captured.caller.token_id.clone(),
                reason: "original prebody capture".into(),
                wall_time_ms: auth.env.clock.wall_ms(),
            }),
            verified_identity: captured.verified_identity.as_deref().cloned(),
            ..Default::default()
        };
        let lsn = node
            .record_approval(approval.clone(), captured.authority.clone())
            .await
            .unwrap();
        let mut durable = None;
        node.reader()
            .read(lsn, lsn, |committed| {
                if let kronik_proto::Record::Approval(value) = committed.record {
                    durable = Some(value);
                }
                Ok(())
            })
            .await
            .unwrap();
        let durable = durable.unwrap();
        assert_eq!(
            open_verified_identity(
                node.sealer(),
                durable.verified_identity.as_ref().unwrap(),
                &durable.audit.as_ref().unwrap().token_id
            )
            .unwrap(),
            Some(("https://issuer".into(), "stable-subject".into()))
        );
        let fresh = auth.capture(&req, Scope::Read).unwrap();
        let mut missing = approval.clone();
        missing.verified_identity = fresh.verified_identity.as_deref().cloned();
        assert!(
            node.record_approval(missing, fresh.authority)
                .await
                .is_err()
        );
        assert_eq!(node.applied_lsn(), lsn);
        logout_session(&auth.tokens, &auth.state, digest(&credential), false).unwrap();
        assert!(
            node.record_approval(approval, captured.authority)
                .await
                .is_err()
        );
        assert_eq!(node.applied_lsn(), lsn);
        for credential in [other_credential, bearer] {
            let unrelated = auth.capture(&request(credential), Scope::Read).unwrap();
            node.record_audit_event_authorized(
                "operator.note",
                "unrelated-session-or-bearer",
                Default::default(),
                pb::Audit {
                    token_id: unrelated.caller.token_id,
                    reason: "self logout is isolated".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                unrelated.authority,
            )
            .await
            .unwrap();
        }
        assert!(node.applied_lsn() > lsn);
    }

    async fn committed_browser_fixture(
        node: &Arc<kronik_sched::Node>,
    ) -> (Arc<BrowserAuth>, String, String) {
        fixture_for_node(node, [Scope::Read].into(), node.sealer().clone()).await
    }

    #[tokio::test]
    async fn typed_login_history_uses_the_original_session_and_actual_durable_receipt() {
        let (auth, credential, bearer, (_dir, node)) = fixture().await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let captured = api.capture_binding(&request(credential.clone())).unwrap();
        let session = captured.session().unwrap().clone();
        let (source, _plan) = api
            .record_native_oidc_login(
                pb::Audit {
                    token_id: captured.caller.token_id.clone(),
                    reason: "verified login fixture".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                session.clone(),
            )
            .await
            .unwrap();
        let SourcePos::Actor { shard: None, lsn } = source else {
            panic!("native login must return its real log source")
        };
        let mut durable = None;
        node.reader()
            .read(lsn, lsn, |record| {
                if let kronik_proto::Record::AuditEvent(event) = record.record {
                    durable = Some(event);
                }
                Ok(())
            })
            .await
            .unwrap();
        let event = durable.unwrap();
        assert_eq!(event.action, "auth.oidc.login");
        assert!(event.target.is_empty() && event.details.is_empty());
        let Some(pb::audit_event::Operation::AuthOidcLogin(login)) = event.operation else {
            panic!("missing typed login history")
        };
        assert_eq!(login.token_name, "reader");
        assert_eq!(login.principal_hash, session.revocation().principal_hash);
        assert_eq!(auth.state().sessions.len(), 1);
        logout_session(&auth.tokens, &auth.state, digest(&credential), false).unwrap();
        let before = node.applied_lsn();
        assert!(
            api.record_native_oidc_login(
                pb::Audit {
                    token_id: captured.caller.token_id,
                    reason: "stale login".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                session
            )
            .await
            .is_err()
        );
        assert_eq!(node.applied_lsn(), before);
        assert!(api.capture_binding(&request(bearer)).is_ok());
    }

    #[tokio::test]
    async fn abandoned_callback_removes_its_private_session_without_revoking_bearer() {
        let (auth, existing, bearer, _fixture) = fixture().await;
        let (credential, _, original, cleanup) = pending_native_session(&auth, &existing);
        let (ready, entered) = tokio::sync::oneshot::channel();
        let callback = tokio::spawn(async move {
            let _cleanup = cleanup;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        entered.await.unwrap();
        callback.abort();
        assert!(callback.await.unwrap_err().is_cancelled());
        assert!(auth.session(&credential).is_err());
        assert!(original.check().is_err());
        assert!(auth.capture(&request(existing), Scope::Read).is_ok());
        assert!(auth.capture(&request(bearer), Scope::Read).is_ok());
    }

    fn pending_native_session(
        auth: &Arc<BrowserAuth>,
        credential: &str,
    ) -> (
        String,
        Session,
        kronik_core::authority::SessionLease,
        PendingSession,
    ) {
        let mut draft = auth.session(credential).unwrap();
        draft.verified_identity = None;
        let credential = format!("{SESSION_PREFIX}{}", random(&auth.env));
        let key = digest(&credential);
        let unpublished = Arc::new(AtomicBool::new(true));
        let original = auth
            .session_authority(&auth.state(), key, &draft, Some(unpublished.clone()))
            .unwrap();
        let captured = auth
            .tokens
            .capture_oidc(Scope::Read, original, auth.env.clock.clone(), None)
            .unwrap();
        let cleanup = PendingSession {
            tokens: auth.tokens.clone(),
            state: auth.state.clone(),
            key: Some(key),
            unpublished,
        };
        (
            credential,
            draft,
            captured.session().unwrap().clone(),
            cleanup,
        )
    }

    #[tokio::test]
    async fn cancelled_callback_denies_its_detached_blocking_identity_continuation() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, existing, bearer) = committed_browser_fixture(&node).await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let (credential, mut draft, original, cleanup) = pending_native_session(&auth, &existing);
        let owner = principal(
            original
                .revocation()
                .principal_hash
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let (_receipt, plan) = api
            .record_native_oidc_login(
                pb::Audit {
                    token_id: owner.clone(),
                    reason: "real detached blocking callback".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                original.clone(),
            )
            .await
            .unwrap();
        let value =
            verified_identity_value(&auth.sealer, "https://issuer", "stable-subject", &owner)
                .unwrap();
        let (release, paused) = std::sync::mpsc::sync_channel(0);
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (finished, result) = tokio::sync::oneshot::channel();
        let (worker_node, sealer, state, clock) = (
            node.clone(),
            auth.sealer.clone(),
            auth.state.clone(),
            auth.env.clock.clone(),
        );
        let unpublished = cleanup.unpublished.clone();
        let worker_original = original.clone();
        let key = digest(&credential);
        let job = auth.env.blocking("oidc-cancel-fixture", move || {
            let _ = entered.send(());
            paused.recv().unwrap();
            let outcome = worker_node.seal_native_identity_at(
                sealer,
                value,
                plan,
                worker_original,
                |sealed| {
                    draft.verified_identity = Some(Arc::new(sealed));
                    BrowserAuth::insert_native_session(
                        &state,
                        clock.wall_ms(),
                        key,
                        draft,
                        &unpublished,
                    )
                },
            );
            let _ = finished.send(outcome.is_err());
        });
        let callback = tokio::spawn(async move {
            let _cleanup = cleanup;
            job.await
        });
        ready.await.unwrap();
        callback.abort();
        assert!(callback.await.unwrap_err().is_cancelled());
        original
            .check()
            .err()
            .expect("dropping the callback must close its private latch");
        release.send(()).unwrap();
        assert!(
            result.await.unwrap(),
            "the detached real worker must refuse the abandoned original session"
        );
        assert!(auth.session(&credential).is_err());
        assert!(auth.capture(&request(existing), Scope::Read).is_ok());
        assert!(auth.capture(&request(bearer), Scope::Read).is_ok());
    }

    #[tokio::test]
    async fn unpublished_callback_is_not_a_browser_session_or_a_replayable_login() {
        let (auth, existing, bearer, (_dir, node)) = fixture().await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let (credential, _, original, cleanup) = pending_native_session(&auth, &existing);
        original.check().unwrap();
        assert!(auth.session(&credential).is_err());
        assert!(
            auth.capture(&request(credential.clone()), Scope::Read)
                .is_err()
        );
        assert!(
            auth.credential(
                None,
                Some(&format!("{SESSION_COOKIE}={credential}")),
                "GET",
                None,
                None
            )
            .is_err()
        );
        drop(cleanup);
        assert!(original.check().is_err());
        let before = node.applied_lsn();
        assert!(
            api.record_native_oidc_login(
                pb::Audit {
                    token_id: principal(
                        original
                            .revocation()
                            .principal_hash
                            .as_slice()
                            .try_into()
                            .unwrap()
                    ),
                    reason: "abandoned unpublished callback".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                original
            )
            .await
            .is_err()
        );
        assert_eq!(node.applied_lsn(), before);
        assert_eq!(auth.state().sessions.len(), 1);
        assert!(auth.capture(&request(existing), Scope::Read).is_ok());
        assert!(auth.capture(&request(bearer), Scope::Read).is_ok());
    }

    #[tokio::test]
    async fn genuine_browser_session_requires_its_attached_store_and_original_protocol_capture() {
        let (auth, credential, bearer, (_dir, node)) = fixture().await;
        let detached = crate::Api::new(node.clone()).with_browser(auth.clone());
        assert!(
            detached
                .capture_for_scope(&request(credential.clone()), Scope::Read)
                .is_err()
        );
        let api = crate::Api::new(node)
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let mut req = request(credential);
        req.path = "/v1/auth/session".into();
        assert!(auth.route(&req, None, &api, None).await.unwrap().is_err());
        let original = auth.capture_protocol_request(&req, &api).unwrap();
        let response = auth
            .route(&req, None, &api, original)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(api.handle(request(bearer)).await.status, 200);
    }

    #[tokio::test]
    async fn original_approval_only_session_info_is_fenced_before_body_and_complete_response() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, credential, _) = fixture_for_node_subject(
            &node,
            [Scope::Approve].into(),
            node.sealer().clone(),
            "approval-only-owner",
        )
        .await;
        let (_, unrelated) = auth
            .tokens
            .create(
                "unrelated-reader",
                [Scope::Read].into(),
                [8; 32],
                &crate::tokens::Change {
                    wall_ms: auth.env.clock.wall_ms(),
                    by: "unix:uid=0",
                    reason: "independent native bearer",
                },
                false,
            )
            .unwrap();
        let api = crate::Api::new(node)
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let mut req = request(credential.clone());
        req.path = "/v1/auth/session".into();
        let before_body = auth.capture_protocol_request(&req, &api).unwrap().unwrap();
        let original = auth.capture_protocol_request(&req, &api).unwrap().unwrap();
        assert!(original.caller.has(Scope::Approve));
        assert!(!original.caller.has(Scope::Read));
        let candidate = auth.session_info(&req, Some(&original)).unwrap();
        let session = auth.session(&credential).unwrap();
        auth.tokens
            .revoke(
                &session.token_name,
                &crate::tokens::Change {
                    wall_ms: auth.env.clock.wall_ms(),
                    by: "unix:uid=0",
                    reason: "revoke original identity response",
                },
                false,
            )
            .unwrap();
        assert!(auth.session_info(&req, Some(&before_body)).is_err());
        assert!(
            api.complete_browser_response(candidate, original)
                .await
                .is_err()
        );
        assert_eq!(api.handle(request(unrelated.unwrap())).await.status, 200);
    }

    #[tokio::test]
    async fn abandoned_native_cookie_candidate_is_not_admitted_after_its_login_ack() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, existing, bearer) = committed_browser_fixture(&node).await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let credential = format!("{SESSION_PREFIX}{}", random(&auth.env));
        let mut draft = auth.session(&existing).unwrap();
        draft.verified_identity = None;
        let (original, cleanup) = auth
            .finish_native_login(
                &api,
                &credential,
                draft,
                "https://issuer",
                "stable-subject",
                Scope::Read,
            )
            .await
            .unwrap();
        let mut candidate = redirect(
            "/ui/".into(),
            cookie(SESSION_COOKIE, &credential, SESSION_MS / 1000),
        );
        Arc::make_mut(&mut candidate.headers).push(("set-cookie", cookie(LOGIN_COOKIE, "", 0)));
        drop(cleanup);
        assert!(
            api.complete_browser_response(candidate, original)
                .await
                .is_err()
        );
        assert!(auth.session(&credential).is_err());
        assert_eq!(api.handle(request(bearer)).await.status, 200);
    }

    #[tokio::test]
    async fn native_callback_publishes_only_protected_identity_after_real_login_ack_in_both_privacy_modes()
     {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let subject = r#"stable-"subject\escaped"#;
        let (auth, existing, bearer) = fixture_for_node_subject(
            &node,
            [Scope::Read, Scope::Approve].into(),
            node.sealer().clone(),
            subject,
        )
        .await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        for mode in [pb::PrivacyState::Off, pb::PrivacyState::On] {
            node.set_privacy_mode(
                mode,
                pb::Audit {
                    token_id: "unix:uid=0".into(),
                    reason: "actual identity protection mode fixture".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                false,
                node.local_operator_authority().unwrap(),
            )
            .await
            .unwrap();
            let credential = format!("{SESSION_PREFIX}{}", random(&auth.env));
            let mut draft = auth.session(&existing).unwrap();
            draft.verified_identity = None;
            let before = node.applied_lsn();
            let (original, mut cleanup) = auth
                .finish_native_login(
                    &api,
                    &credential,
                    draft,
                    "https://issuer",
                    subject,
                    Scope::Read,
                )
                .await
                .unwrap();
            let response = redirect(
                "/ui/".into(),
                cookie(SESSION_COOKIE, &credential, SESSION_MS / 1000),
            );
            let response = api
                .complete_browser_response(response, original)
                .await
                .unwrap();
            assert_eq!(response.status, 303);
            cleanup.key = None;
            let published = auth.session(&credential).unwrap();
            let value = published.verified_identity.as_ref().unwrap();
            let Some(pb::sealable::Value::Sealed(sealed)) = &value.value else {
                panic!("callback identity must be protected in either mode")
            };
            assert!(sealed.key_version > 0);
            assert_eq!(
                open_verified_identity(node.sealer(), value, &principal(&published.principal_hash))
                    .unwrap(),
                Some(("https://issuer".into(), subject.to_owned()))
            );
            let mut req = request(credential.clone());
            req.path = "/v1/auth/session".into();
            let original = auth.capture_protocol_request(&req, &api).unwrap();
            let info = auth.session_info(&req, original.as_ref()).unwrap();
            let info: serde_json::Value = serde_json::from_slice(&info.body).unwrap();
            assert_eq!(info["identity"]["subject"], subject);
            let mut receipts = Vec::new();
            node.reader()
                .read(before + 1, node.applied_lsn(), |record| {
                    if let kronik_proto::Record::AuditEvent(event) = record.record
                        && let Some(pb::audit_event::Operation::AuthOidcLogin(login)) =
                            event.operation
                    {
                        receipts.push(login);
                    }
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].principal_hash, published.principal_hash);
            assert_eq!(receipts[0].token_name, published.token_name);
            let mut mutation = request(credential);
            mutation.method = "POST".into();
            assert!(
                auth.capture(&mutation, Scope::Approve)
                    .unwrap()
                    .verified_identity
                    .is_some()
            );
        }
        assert!(auth.capture(&request(existing), Scope::Read).is_ok());
        assert!(auth.capture(&request(bearer), Scope::Read).is_ok());
    }

    #[derive(Clone, Copy)]
    enum IdentityKeyChange {
        Erase,
        Missing,
        Corrupt,
    }

    fn change_identity_key(
        node: &kronik_sched::Node,
        data: &std::path::Path,
        owner: &str,
        change: IdentityKeyChange,
    ) {
        let ks = node.sealer().keystore().unwrap();
        match change {
            IdentityKeyChange::Erase => {
                ks.erase(owner, node.env().clock.wall_ms()).unwrap();
            }
            IdentityKeyChange::Missing | IdentityKeyChange::Corrupt => {
                let conn = rusqlite::Connection::open(data.join("keys/keystore.db")).unwrap();
                let sql = if matches!(change, IdentityKeyChange::Missing) {
                    "DELETE FROM subject_keys WHERE subject = ?1"
                } else {
                    "UPDATE subject_keys SET wrapped = zeroblob(length(wrapped)) WHERE subject = ?1"
                };
                assert!(conn.execute(sql, [owner]).unwrap() > 0);
            }
        }
    }

    #[tokio::test]
    async fn native_rotation_uses_its_original_retained_holder_not_the_latest_version() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, existing, bearer) = committed_browser_fixture(&node).await;
        let retained = auth.session(&existing).unwrap().verified_identity.unwrap();
        let Some(pb::sealable::Value::Sealed(retained)) = &retained.value else {
            panic!("expected protected original identity")
        };
        let retained_version = retained.key_version;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        let (credential, mut draft, original, cleanup) = pending_native_session(&auth, &existing);
        let owner = principal(
            original
                .revocation()
                .principal_hash
                .as_slice()
                .try_into()
                .unwrap(),
        );
        let (_receipt, plan) = api
            .record_native_oidc_login(
                pb::Audit {
                    token_id: owner.clone(),
                    reason: "retain exact callback key through ordinary rotation".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                original.clone(),
            )
            .await
            .unwrap();
        let rotated_version = node
            .sealer()
            .keystore()
            .unwrap()
            .rotate(
                &owner,
                node.env().random_bytes(),
                node.env().random_bytes(),
                node.env().clock.wall_ms(),
            )
            .unwrap();
        assert_ne!(rotated_version, retained_version);
        let value =
            verified_identity_value(&auth.sealer, "https://issuer", "stable-subject", &owner)
                .unwrap();
        node.seal_native_identity_at(auth.sealer.clone(), value, plan, original, |sealed| {
            draft.verified_identity = Some(Arc::new(sealed));
            BrowserAuth::insert_native_session(
                &auth.state,
                auth.env.clock.wall_ms(),
                digest(&credential),
                draft,
                &cleanup.unpublished,
            )
        })
        .unwrap();
        let published = auth.session(&credential).unwrap();
        let protected = published.verified_identity.as_ref().unwrap();
        let Some(pb::sealable::Value::Sealed(sealed)) = &protected.value else {
            panic!("expected protected published identity")
        };
        assert_eq!(sealed.key_version, retained_version);
        assert_eq!(
            open_verified_identity(node.sealer(), protected, &owner).unwrap(),
            Some(("https://issuer".into(), "stable-subject".into()))
        );
        auth.capture(&request(credential), Scope::Read).unwrap();
        drop(cleanup);
        assert!(auth.capture(&request(existing), Scope::Read).is_ok());
        assert!(auth.capture(&request(bearer), Scope::Read).is_ok());
    }

    #[tokio::test]
    async fn exact_native_key_changes_after_the_actual_ack_cannot_reach_active_session_insertion() {
        for change in [
            IdentityKeyChange::Erase,
            IdentityKeyChange::Missing,
            IdentityKeyChange::Corrupt,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::real(tokio::runtime::Handle::current());
            let node =
                kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
                    .await
                    .unwrap();
            let (auth, existing, bearer) = committed_browser_fixture(&node).await;
            let api = crate::Api::new(node.clone())
                .with_tokens(auth.tokens.clone())
                .unwrap()
                .with_browser(auth.clone());
            let (credential, mut draft, original, cleanup) =
                pending_native_session(&auth, &existing);
            let owner = principal(
                original
                    .revocation()
                    .principal_hash
                    .as_slice()
                    .try_into()
                    .unwrap(),
            );
            let (receipt, plan) = api
                .record_native_oidc_login(
                    pb::Audit {
                        token_id: owner.clone(),
                        reason: "actual pending callback key fence".into(),
                        wall_time_ms: auth.env.clock.wall_ms(),
                    },
                    original.clone(),
                )
                .await
                .unwrap();
            let value =
                verified_identity_value(&auth.sealer, "https://issuer", "stable-subject", &owner)
                    .unwrap();
            change_identity_key(&node, dir.path(), &owner, change);
            assert!(
                node.seal_native_identity_at(
                    auth.sealer.clone(),
                    value,
                    plan,
                    original.clone(),
                    |sealed| {
                        draft.verified_identity = Some(Arc::new(sealed));
                        BrowserAuth::insert_native_session(
                            &auth.state,
                            auth.env.clock.wall_ms(),
                            digest(&credential),
                            draft,
                            &cleanup.unpublished,
                        )
                    }
                )
                .is_err()
            );
            assert!(auth.session(&credential).is_err());
            assert!(auth.capture(&request(credential), Scope::Read).is_err());
            assert_eq!(auth.state().sessions.len(), 1);
            drop(cleanup);
            assert!(original.check().is_err());
            let SourcePos::Actor { shard: None, lsn } = receipt else {
                panic!("expected native ACK")
            };
            assert_eq!(node.applied_lsn(), lsn);
            for credential in [existing, bearer] {
                let unrelated = auth.capture(&request(credential), Scope::Read).unwrap();
                node.record_audit_event_authorized(
                    "operator.note",
                    "unrelated-after-key-change",
                    Default::default(),
                    pb::Audit {
                        token_id: unrelated.caller.token_id,
                        reason: "pending callback failure is isolated".into(),
                        wall_time_ms: auth.env.clock.wall_ms(),
                    },
                    unrelated.authority,
                )
                .await
                .unwrap();
            }
            assert!(node.applied_lsn() > lsn);
        }
    }

    #[tokio::test]
    async fn native_callback_plan_rejects_a_foreign_physical_sealer_or_another_genuine_session() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
            .await
            .unwrap();
        let (auth, existing, bearer) = committed_browser_fixture(&node).await;
        let api = crate::Api::new(node.clone())
            .with_tokens(auth.tokens.clone())
            .unwrap()
            .with_browser(auth.clone());
        for wrong_sealer in [true, false] {
            let (credential, mut draft, original, cleanup) =
                pending_native_session(&auth, &existing);
            let owner = principal(
                original
                    .revocation()
                    .principal_hash
                    .as_slice()
                    .try_into()
                    .unwrap(),
            );
            let (_receipt, plan) = api
                .record_native_oidc_login(
                    pb::Audit {
                        token_id: owner.clone(),
                        reason: "actual physical and original-session binding".into(),
                        wall_time_ms: auth.env.clock.wall_ms(),
                    },
                    original.clone(),
                )
                .await
                .unwrap();
            let mut other_cleanup = None;
            let candidate = if wrong_sealer {
                original.clone()
            } else {
                let (_, _, other, cleanup) = pending_native_session(&auth, &existing);
                other_cleanup = Some(cleanup);
                other
            };
            candidate.check().unwrap();
            let sealer = if wrong_sealer {
                Arc::new(identity_sealer())
            } else {
                auth.sealer.clone()
            };
            let value =
                verified_identity_value(&auth.sealer, "https://issuer", "stable-subject", &owner)
                    .unwrap();
            let before = node.applied_lsn();
            assert!(
                node.seal_native_identity_at(sealer, value, plan, candidate, |sealed| {
                    draft.verified_identity = Some(Arc::new(sealed));
                    BrowserAuth::insert_native_session(
                        &auth.state,
                        auth.env.clock.wall_ms(),
                        digest(&credential),
                        draft,
                        &cleanup.unpublished,
                    )
                })
                .is_err()
            );
            assert!(auth.session(&credential).is_err());
            assert_eq!(auth.state().sessions.len(), 1);
            assert_eq!(node.applied_lsn(), before);
            original.check().unwrap();
            drop(other_cleanup);
            drop(cleanup);
            assert!(original.check().is_err());
        }
        for credential in [existing, bearer] {
            let unrelated = auth.capture(&request(credential), Scope::Read).unwrap();
            node.record_audit_event_authorized(
                "operator.note",
                "unrelated-after-plan-substitution",
                Default::default(),
                pb::Audit {
                    token_id: unrelated.caller.token_id,
                    reason: "failed callback cannot affect other credentials".into(),
                    wall_time_ms: auth.env.clock.wall_ms(),
                },
                unrelated.authority,
            )
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn token_revocation_before_native_reservation_or_final_insertion_cannot_activate_the_callback()
     {
        for before_reservation in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::real(tokio::runtime::Handle::current());
            let node =
                kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
                    .await
                    .unwrap();
            let (auth, existing, _) = committed_browser_fixture(&node).await;
            let api = crate::Api::new(node.clone())
                .with_tokens(auth.tokens.clone())
                .unwrap()
                .with_browser(auth.clone());
            let change = crate::tokens::Change {
                wall_ms: auth.env.clock.wall_ms(),
                by: "unix:uid=0",
                reason: "actual callback token fence",
            };
            let (_, bearer) = auth
                .tokens
                .create("unrelated", [Scope::Read].into(), [8; 32], &change, false)
                .unwrap();
            let (credential, mut draft, original, cleanup) =
                pending_native_session(&auth, &existing);
            let before = node.applied_lsn();
            let owner = principal(
                original
                    .revocation()
                    .principal_hash
                    .as_slice()
                    .try_into()
                    .unwrap(),
            );
            let audit = pb::Audit {
                token_id: owner.clone(),
                reason: "actual callback token fence".into(),
                wall_time_ms: auth.env.clock.wall_ms(),
            };
            if before_reservation {
                let keys_before = node.sealer().keystore().unwrap().stats().unwrap();
                auth.tokens
                    .revoke(&original.revocation().token_name, &change, false)
                    .unwrap();
                assert!(
                    api.record_native_oidc_login(audit, original.clone())
                        .await
                        .is_err()
                );
                assert_eq!(
                    node.sealer().keystore().unwrap().stats().unwrap(),
                    keys_before
                );
                assert_eq!(node.applied_lsn(), before);
            } else {
                let (_receipt, plan) = api
                    .record_native_oidc_login(audit, original.clone())
                    .await
                    .unwrap();
                let value = verified_identity_value(
                    &auth.sealer,
                    "https://issuer",
                    "stable-subject",
                    &owner,
                )
                .unwrap();
                auth.tokens
                    .revoke(&original.revocation().token_name, &change, false)
                    .unwrap();
                assert!(
                    node.seal_native_identity_at(
                        auth.sealer.clone(),
                        value,
                        plan,
                        original.clone(),
                        |sealed| {
                            draft.verified_identity = Some(Arc::new(sealed));
                            BrowserAuth::insert_native_session(
                                &auth.state,
                                auth.env.clock.wall_ms(),
                                digest(&credential),
                                draft,
                                &cleanup.unpublished,
                            )
                        }
                    )
                    .is_err()
                );
            }
            assert!(original.check().is_err());
            assert!(auth.session(&credential).is_err());
            drop(cleanup);
            let unrelated = auth
                .capture(&request(bearer.unwrap()), Scope::Read)
                .unwrap();
            let lsn = node
                .record_audit_event_authorized(
                    "operator.note",
                    "unrelated-after-token-revocation",
                    Default::default(),
                    pb::Audit {
                        token_id: unrelated.caller.token_id,
                        reason: "not revoked".into(),
                        wall_time_ms: auth.env.clock.wall_ms(),
                    },
                    unrelated.authority,
                )
                .await
                .unwrap();
            assert!(lsn > before);
        }
    }

    enum SessionTransition {
        RevokeTokenBeforeEnqueue,
        LogoutAfterEnqueue(Mutex<Option<tokio::sync::oneshot::Sender<()>>>),
    }

    // Delegate the real capability; mutate real authority at its actual final admission.
    struct TransitionSession {
        inner: kronik_core::authority::SessionLease,
        auth: Arc<BrowserAuth>,
        key: [u8; 32],
        transition: SessionTransition,
    }

    impl kronik_core::authority::Authority for TransitionSession {
        fn check(&self) -> Result<(), ApiError> {
            self.inner.check()
        }
        fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
            self.inner.cancelled()
        }
        fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
            match &self.transition {
                SessionTransition::RevokeTokenBeforeEnqueue => {
                    self.auth.tokens.revoke(
                        &self.inner.revocation().token_name,
                        &crate::tokens::Change {
                            wall_ms: self.auth.env.clock.wall_ms(),
                            by: "unix:uid=0",
                            reason: "revoke at final log admission",
                        },
                        false,
                    )?;
                    self.inner.admit(effect)
                }
                SessionTransition::LogoutAfterEnqueue(admitted) => {
                    self.inner.admit(effect)?;
                    logout_session(&self.auth.tokens, &self.auth.state, self.key, false)?;
                    if let Some(done) = admitted.lock().unwrap().take() {
                        let _ = done.send(());
                    }
                    Ok(())
                }
            }
        }
    }

    impl kronik_core::authority::SessionAuthority for TransitionSession {
        fn revocation(&self) -> &pb::AuthSessionRevoked {
            self.inner.revocation()
        }
    }

    #[tokio::test]
    async fn ordinary_api_candidate_rejects_revocation_at_the_real_final_queue() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (auth, credential, _, (_dir, node)) =
                fixture_with_scopes([Scope::Read, Scope::Admin].into()).await;
            let api = crate::Api::new(node.clone())
                .with_tokens(auth.tokens.clone())
                .unwrap()
                .with_browser(auth.clone());
            let mut req = request(credential.clone());
            req.path = "/v1/tokens".into();
            let permitted = api.handle(req.clone()).await;
            assert_eq!(permitted.status, 200);
            assert!(String::from_utf8_lossy(&permitted.body).contains("reader"));
            let mut original = api.capture(&req).unwrap();
            original.authority = Arc::new(TransitionSession {
                inner: original.session().unwrap().clone(),
                auth: auth.clone(),
                key: digest(&credential),
                transition: SessionTransition::RevokeTokenBeforeEnqueue,
            });
            let before = node.applied_lsn();
            let response = api.handle_admitted(req, original).await;
            assert_eq!(response.status, 401);
            assert!(!String::from_utf8_lossy(&response.body).contains("\"name\":\"reader\""));
            assert!(auth.tokens.caller_for_name("reader").is_none());
            assert_eq!(node.applied_lsn(), before);
        })
        .await
        .expect("real ordinary API final admission must finish within five seconds");
    }

    #[tokio::test]
    async fn ordinary_api_candidate_admitted_before_logout_is_not_replaced() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (auth, credential, _, (_dir, node)) =
                fixture_with_scopes([Scope::Read, Scope::Admin].into()).await;
            let api = crate::Api::new(node.clone())
                .with_tokens(auth.tokens.clone())
                .unwrap()
                .with_browser(auth.clone());
            let mut req = request(credential.clone());
            req.path = "/v1/tokens".into();
            let permitted = api.handle(req.clone()).await;
            assert_eq!(permitted.status, 200);
            let mut original = api.capture(&req).unwrap();
            original.authority = Arc::new(TransitionSession {
                inner: original.session().unwrap().clone(),
                auth: auth.clone(),
                key: digest(&credential),
                transition: SessionTransition::LogoutAfterEnqueue(Mutex::new(None)),
            });
            let before = node.applied_lsn();
            let response = api.handle_admitted(req.clone(), original).await;
            assert_eq!(response.status, permitted.status);
            assert_eq!(response.content_type, permitted.content_type);
            assert_eq!(response.body, permitted.body);
            assert!(!auth.state().sessions.contains_key(&digest(&credential)));
            assert_eq!(api.handle(req).await.status, 401);
            assert_eq!(node.applied_lsn(), before);
        })
        .await
        .expect("an exact admitted API candidate must finish within five seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_revoked_at_final_log_admission_cannot_persist_a_session_tombstone() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::real(tokio::runtime::Handle::current());
            let node =
                kronik_sched::start_local(env, dir.path(), kronik_sched::NodeConfig::default())
                    .await
                    .unwrap();
            let (auth, credential, _) = committed_browser_fixture(&node).await;
            let original = auth
                .capture(&request(credential.clone()), Scope::Read)
                .unwrap();
            let original_session = original.session().unwrap().clone();
            let audit = pb::Audit {
                token_id: original.caller.token_id,
                reason: "self logout".into(),
                wall_time_ms: auth.env.clock.wall_ms(),
            };
            node.record_auth_session_revoked(audit.clone(), true, original_session.clone())
                .await
                .unwrap();
            let (_, bearer) = auth
                .tokens
                .create(
                    "unrelated",
                    [Scope::Read].into(),
                    [8; 32],
                    &crate::tokens::Change {
                        wall_ms: auth.env.clock.wall_ms(),
                        by: "unix:uid=0",
                        reason: "independent bearer",
                    },
                    false,
                )
                .unwrap();
            let session: kronik_core::authority::SessionLease = Arc::new(TransitionSession {
                inner: original_session,
                auth: auth.clone(),
                key: digest(&credential),
                transition: SessionTransition::RevokeTokenBeforeEnqueue,
            });
            let before = node.applied_lsn();
            let error = node
                .record_auth_session_revoked(audit, false, session)
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::Unauthenticated);
            assert!(auth.tokens.caller_for_name("reader").is_none());
            assert_eq!(node.applied_lsn(), before);
            assert_eq!(node.store().db().applied_lsn().unwrap(), before);
            let mut unexpected = Vec::new();
            node.reader()
                .read(before + 1, u64::MAX, |record| {
                    unexpected.push(record);
                    Ok(())
                })
                .await
                .unwrap();
            assert!(unexpected.is_empty());
            let unrelated = auth
                .tokens
                .capture_token(&bearer.unwrap(), Scope::Read)
                .unwrap();
            let lsn = node
                .record_audit_event_authorized(
                    "operator.note",
                    "unrelated-bearer",
                    Default::default(),
                    pb::Audit {
                        token_id: unrelated.caller.token_id,
                        reason: "not revoked".into(),
                        wall_time_ms: auth.env.clock.wall_ms(),
                    },
                    unrelated.authority,
                )
                .await
                .unwrap();
            assert!(lsn > before);
        })
        .await
        .expect("real final-admission revocation must finish within five seconds");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_self_logout_survives_own_revocation_and_caller_disconnect() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let dir = tempfile::tempdir().unwrap();
            let env = Env::real(tokio::runtime::Handle::current());
            let config = kronik_sched::NodeConfig { group_commit_window: Some(Duration::from_millis(500)),
                ..kronik_sched::NodeConfig::default() };
            let node = kronik_sched::start_local(env, dir.path(), config).await.unwrap();
            let (auth, credential, bearer) = committed_browser_fixture(&node).await;
            let other_credential = format!("{SESSION_PREFIX}{}", random(&auth.env));
            let other_session = auth.session(&credential).unwrap();
            auth.state().sessions.insert(digest(&other_credential), other_session);
            let cookies = format!("{SESSION_COOKIE}={credential}");
            let mut req = request(credential.clone());
            req.method = "POST".into();
            req.path = "/v1/auth/logout".into();
            req.body = br#"{"reason":"self logout despite caller disconnect","dry_run":false}"#.to_vec();
            req.bearer = auth.credential(None, Some(&cookies), "POST", Some("https://admin"), Some("csrf")).unwrap();
            let api = Arc::new(crate::Api::new(node.clone()).with_tokens(auth.tokens.clone()).unwrap().with_browser(auth.clone()));
            let mut original = api.capture_binding(&req).unwrap();
            let (admitted, observed) = tokio::sync::oneshot::channel();
            let session: kronik_core::authority::SessionLease = Arc::new(TransitionSession {
                inner: original.session().unwrap().clone(), auth: auth.clone(), key: digest(&credential),
                transition: SessionTransition::LogoutAfterEnqueue(Mutex::new(Some(admitted))),
            });
            original.authority = session.clone();
            original.session = Some(session);
            let before = node.applied_lsn();
            let worker_auth = auth.clone();
            let caller = tokio::spawn(async move { worker_auth.logout(&req, &api, original).await });
            observed.await.unwrap();
            assert!(auth.session(&credential).is_err());
            assert_eq!(node.applied_lsn(), before);
            assert!(!caller.is_finished());
            caller.abort();
            assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
            node.store().applied.wait(before + 1).await;
            assert_eq!(node.store().db().applied_lsn().unwrap(), before + 1);
            let mut durable = None;
            node.reader().read(before + 1, before + 1, |committed| {
                if let kronik_proto::Record::AuditEvent(event) = committed.record { durable = Some(event); }
                Ok(())
            }).await.unwrap();
            let durable = durable.unwrap();
            assert_eq!(durable.action, "auth.logout");
            assert!(durable.details.is_empty());
            assert!(matches!(durable.operation, Some(pb::audit_event::Operation::AuthSessionRevoked(value))
                if value.session_hash.as_slice() == digest(&credential).as_slice()));
            for credential in [other_credential, bearer] {
                let unrelated = auth.capture(&request(credential), Scope::Read).unwrap();
                node.record_audit_event_authorized("operator.note", "unrelated-after-self-logout", Default::default(),
                    pb::Audit { token_id: unrelated.caller.token_id, reason: "still usable".into(),
                        wall_time_ms: auth.env.clock.wall_ms() }, unrelated.authority).await.unwrap();
            }
            assert!(node.applied_lsn() > before + 1);
        }).await.expect("owned admitted self logout must finish within five seconds after disconnect");
    }

    #[tokio::test]
    async fn approve_only_get_selects_identity_without_copying_protected_payload() {
        let (auth, credential, _, _fixture) = fixture_with_scopes([Scope::Approve].into()).await;
        let req = request(credential);
        assert!(auth.caller(&req).unwrap().has(Scope::Approve));
        assert!(
            auth.capture(&req, Scope::Approve)
                .unwrap()
                .verified_identity
                .is_none()
        );
    }

    #[tokio::test]
    async fn cookie_csrf_origin_logout_and_expiry_boundaries() {
        let (auth, credential, _, _fixture) = fixture().await;
        let cookies = format!("{SESSION_COOKIE}={credential}");
        assert!(
            auth.credential(None, Some(&cookies), "POST", None, Some("csrf"))
                .is_err()
        );
        assert!(
            auth.credential(
                None,
                Some(&cookies),
                "POST",
                Some("https://evil"),
                Some("csrf")
            )
            .is_err()
        );
        assert!(
            auth.credential(None, Some(&cookies), "POST", Some("https://admin"), None)
                .is_err()
        );
        assert_eq!(
            auth.credential(
                None,
                Some(&cookies),
                "POST",
                Some("https://admin"),
                Some("csrf")
            )
            .unwrap(),
            Some(credential.clone())
        );
        // Explicit bearer clients do not inherit browser CSRF requirements.
        assert_eq!(
            auth.credential(Some("ordinary".into()), Some(&cookies), "POST", None, None)
                .unwrap(),
            Some("ordinary".into())
        );
        let req = request(credential.clone());
        let lease = auth.authority(&req, Scope::Read).unwrap();
        assert_eq!(
            logout_session(&auth.tokens, &auth.state, digest(&credential), true)
                .unwrap()
                .headers
                .len(),
            0
        );
        assert!(lease.check().is_ok());
        assert!(
            logout_session(&auth.tokens, &auth.state, digest(&credential), false)
                .unwrap()
                .headers
                .iter()
                .any(|(_, value)| value.contains("Max-Age=0"))
        );
        assert!(lease.check().is_err());
        let (auth, credential, _, _fixture) = fixture().await;
        auth.state()
            .sessions
            .get_mut(&digest(&credential))
            .unwrap()
            .expires = 0;
        assert!(auth.caller(&request(credential)).is_err());
    }
}
