//! Closed public control metadata. Free text is never an authority representation.

use prost::Message as _;
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer as _, X509Certificate, X509CertificationRequest};

use crate::{DecodeError, log::v1 as pb};
use pb::audit_event::Operation;

pub const MAX_PUBLIC_DER_BYTES: usize = 65_536;
pub const AUTH_CONFIG_VERSION: u32 = 1;
pub const AUTH_FLOW_TTL_MS: u64 = 300_000;
pub const AUTH_SESSION_TTL_MS: u64 = 3_600_000;
pub const TOKEN_SCOPES: [&str; 8] = [
    "read", "fork", "propose", "approve", "promote", "operate", "pii:read", "admin",
];

/// The exact existing Native control TLS-version framing. Public certificate
/// validation/custody and current Active-command admission remain separate.
pub fn fleet_control_tls_version(
    ca_sha256: &str,
    client_key_sha256: &str,
    cert_der: &[u8],
) -> Result<[u8; 32], DecodeError> {
    if [ca_sha256, client_key_sha256].iter().any(|value| {
        value.len() != 64
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }) || cert_der.is_empty()
        || cert_der.len() > MAX_PUBLIC_DER_BYTES
    {
        return Err(invalid("FleetControlTLSVersion"));
    }
    let mut key = Sha256::new();
    for field in [
        b"kronik.fleet-control-tls/v1".as_slice(),
        ca_sha256.as_bytes(),
        client_key_sha256.as_bytes(),
        cert_der,
    ] {
        key.update((field.len() as u64).to_be_bytes());
        key.update(field);
    }
    Ok(key.finalize().into())
}

/// The managed token's public name, not an authority marker. The complete
/// request id must still match its independently recorded fleet provenance.
pub fn fleet_token_name(epoch: u64, request: &[u8]) -> Result<String, DecodeError> {
    if epoch == 0 || request.len() != 32 {
        return Err(invalid("FleetToken.identity"));
    }
    let mut name = String::with_capacity(59);
    std::fmt::Write::write_fmt(&mut name, format_args!("fleet-{epoch}-"))
        .map_err(|_| invalid("FleetToken.name"))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &request[..16] {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(name)
}

/// Validate a public managed name without allocating or treating it as provenance.
pub fn fleet_token_name_matches(name: &str, epoch: u64, request: &[u8]) -> bool {
    if epoch == 0 || request.len() != 32 || name.len() > 59 {
        return false;
    }
    let Some(name) = name.strip_prefix("fleet-") else {
        return false;
    };
    let Some((number, suffix)) = name.split_once('-') else {
        return false;
    };
    !number.starts_with('0')
        && number.bytes().all(|byte| byte.is_ascii_digit())
        && number.parse::<u64>() == Ok(epoch)
        && matches_hex(suffix, &request[..16])
}

#[cfg(test)]
mod native_managed_name_tests {
    use super::*;

    #[test]
    fn managed_name_codec_retains_exact_existing_format_and_full_unsigned_epoch() {
        let request = [0xab; 32];
        for epoch in [1, u64::MAX] {
            let name = fleet_token_name(epoch, &request).unwrap();
            assert_eq!(name, format!("fleet-{epoch}-{}", "ab".repeat(16)));
            assert!(name.len() <= 59);
            assert!(fleet_token_name_matches(&name, epoch, &request));
            assert!(!fleet_token_name_matches(&name, epoch, &[0xcd; 32]));
            assert!(!fleet_token_name_matches(
                &name.to_uppercase(),
                epoch,
                &request
            ));
        }
        assert!(fleet_token_name(0, &request).is_err());
        for request in [&[][..], &[0; 31][..], &[0; 33][..]] {
            assert!(fleet_token_name(1, request).is_err());
            assert!(!fleet_token_name_matches("fleet-1-ab", 1, request));
        }
        let name = fleet_token_name(1, &request).unwrap();
        assert!(!fleet_token_name_matches(&name, 0, &request));
        assert!(!fleet_token_name_matches(&name, 2, &request));
        assert!(!fleet_token_name_matches(
            &name.replacen("fleet-1-", "fleet-01-", 1),
            1,
            &request
        ));
        assert!(!fleet_token_name_matches(
            &name.replacen("fleet-1-", "fleet-+1-", 1),
            1,
            &request
        ));
        assert!(!fleet_token_name_matches(&(name + "0"), 1, &request));
    }
}

/// The three durable control families; this selector is not a wire operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    Fleet,
    Installation,
    Auth,
}

impl ControlKind {
    pub fn action(self) -> &'static str {
        match self {
            Self::Fleet => "fleet.state",
            Self::Installation => "installation.identity",
            Self::Auth => "auth.config",
        }
    }
}

pub fn scope_rank(scope: &str) -> Option<usize> {
    TOKEN_SCOPES.iter().position(|known| *known == scope)
}

pub fn validate_scopes(scopes: &[String]) -> Result<(), DecodeError> {
    if scopes.is_empty() || scopes.len() > TOKEN_SCOPES.len() {
        return Err(invalid("control.scopes"));
    }
    let mut previous = None;
    for scope in scopes {
        let position = scope_rank(scope).ok_or_else(|| invalid("control.scopes"))?;
        if previous.is_some_and(|prior| position <= prior) {
            return Err(invalid("control.scopes"));
        }
        previous = Some(position);
    }
    Ok(())
}

fn invalid(what: &'static str) -> DecodeError {
    DecodeError::Invalid {
        what,
        detail: "invalid typed control metadata".into(),
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

fn token_name(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn https(value: &str, max: usize) -> Result<url::Url, DecodeError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(invalid("control.https"));
    }
    let parsed = url::Url::parse(value).map_err(|_| invalid("control.https"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid("control.https"));
    }
    Ok(parsed)
}

pub fn validate_fleet_plan(
    installation: &str,
    node: Option<&str>,
    cluster: Option<&str>,
    controller_origin: &str,
    scopes: &[String],
    ca_sha256: &[u8],
) -> Result<(), DecodeError> {
    if !identifier(installation)
        || node.is_some_and(|v| !identifier(v))
        || cluster.is_some_and(|v| !identifier(v))
    {
        return Err(invalid("FleetState.identity"));
    }
    let origin = https(controller_origin, 2048)?;
    if origin.path() != "/" || origin.as_str().trim_end_matches('/') != controller_origin {
        return Err(invalid("FleetState.controller_origin"));
    }
    if ca_sha256.len() != 32 {
        return Err(invalid("FleetState.ca_sha256"));
    }
    validate_scopes(scopes)?;
    Ok(())
}

fn request_hex(request: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(request.len() * 2);
    for byte in request {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

fn matches_hex(value: &str, bytes: &[u8]) -> bool {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    value.len() == bytes.len() * 2
        && value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .zip(bytes)
            .all(|(pair, byte)| {
                pair[0] == HEX[(byte >> 4) as usize] && pair[1] == HEX[(byte & 15) as usize]
            })
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

/// Structural public DER/key/identity binding only. The enrollment producer
/// separately verifies trusted chain, EKU and possession of the owned leaf key.
pub fn validate_fleet_state(state: &pb::FleetState) -> Result<(), DecodeError> {
    validate_fleet_plan(
        &state.installation,
        state.node.as_deref(),
        state.cluster.as_deref(),
        &state.controller_origin,
        &state.scopes,
        &state.ca_sha256,
    )?;
    if state.epoch == 0
        || state.request_id.len() != 32
        || state.client_key_sha256.len() != 32
        || state.csr_der.is_empty()
        || state.csr_der.len() > MAX_PUBLIC_DER_BYTES
    {
        return Err(invalid("FleetState.request"));
    }
    let phase =
        pb::fleet_state::Phase::try_from(state.phase).map_err(|_| invalid("FleetState.phase"))?;
    if phase == pb::fleet_state::Phase::Unspecified {
        return Err(invalid("FleetState.phase"));
    }
    if state
        .controller_id
        .as_deref()
        .is_some_and(|value| !matches_hex(value, &state.ca_sha256))
        || state.controller_id.is_some() != state.client_cert_der.is_some()
        || (matches!(
            phase,
            pb::fleet_state::Phase::Pending | pb::fleet_state::Phase::Requested
        ) && state.controller_id.is_some())
        || (phase == pb::fleet_state::Phase::Active && state.controller_id.is_none())
    {
        return Err(invalid("FleetState.controller"));
    }
    let (remainder, csr) = X509CertificationRequest::from_der(&state.csr_der)
        .map_err(|_| invalid("FleetState.csr_der"))?;
    let public = &csr.certification_request_info.subject_pki;
    if !remainder.is_empty()
        || &Sha256::digest(public.raw)[..] != state.client_key_sha256.as_slice()
    {
        return Err(invalid("FleetState.client_key_sha256"));
    }
    if let Some(der) = &state.client_cert_der {
        if der.is_empty() || der.len() > MAX_PUBLIC_DER_BYTES {
            return Err(invalid("FleetState.client_cert_der"));
        }
        let (remaining, cert) =
            X509Certificate::from_der(der).map_err(|_| invalid("FleetState.client_cert_der"))?;
        if !remaining.is_empty() || cert.public_key().raw != public.raw {
            return Err(invalid("FleetState.client_cert_der"));
        }
        if !exact_name(
            cert.subject().iter_common_name().map(|v| v.as_str()),
            Some(&state.installation),
        ) || !exact_name(
            cert.subject().iter_organization().map(|v| v.as_str()),
            state.cluster.as_deref(),
        ) || !exact_name(
            cert.subject()
                .iter_organizational_unit()
                .map(|v| v.as_str()),
            state.node.as_deref(),
        ) {
            return Err(invalid("FleetState.certificate_identity"));
        }
        let binding = format!(
            "urn:kronik:fleet:request:{}:{}",
            request_hex(&state.request_id),
            state.epoch
        );
        let alternative = cert
            .subject_alternative_name()
            .map_err(|_| invalid("FleetState.certificate_binding"))?
            .ok_or_else(|| invalid("FleetState.certificate_binding"))?;
        if alternative.value.general_names.len() != 1
            || !matches!(&alternative.value.general_names[0], x509_parser::extensions::GeneralName::URI(uri) if *uri == binding)
        {
            return Err(invalid("FleetState.certificate_binding"));
        }
    }
    Ok(())
}

pub fn auth_config_digest(config: &pb::AuthConfig) -> [u8; 32] {
    let mut canonical = config.clone();
    canonical.digest.clear();
    canonical.previous_digest.clear();
    *blake3::hash(&canonical.encode_to_vec()).as_bytes()
}

pub fn validate_auth_config(config: &pb::AuthConfig) -> Result<(), DecodeError> {
    if config.version != AUTH_CONFIG_VERSION
        || config.digest.len() != 32
        || !matches!(config.previous_digest.len(), 0 | 32)
        || config.issuer.len() > 1024
        || config.client_id.len() > 256
        || config.redirect_uri.len() > 2048
        || config.trust_roots_sha256.len() > 16
        || config.bindings.len() > 1024
        || config
            .trust_roots_sha256
            .iter()
            .any(|root| root.len() != 32)
        || config
            .bindings
            .iter()
            .any(|binding| binding.principal_hash.len() != 32 || !token_name(&binding.token_name))
    {
        return Err(invalid("AuthConfig.digest"));
    }
    if !config.enabled {
        if !config.issuer.is_empty()
            || !config.client_id.is_empty()
            || !config.redirect_uri.is_empty()
            || config.system_roots
            || !config.trust_roots_sha256.is_empty()
            || !config.bindings.is_empty()
            || config.flow_ttl_ms != 0
            || config.session_ttl_ms != 0
        {
            return Err(invalid("AuthConfig.disabled"));
        }
        if config.digest != auth_config_digest(config) {
            return Err(invalid("AuthConfig.digest"));
        }
        return Ok(());
    }
    https(&config.issuer, 1024)?;
    let redirect = https(&config.redirect_uri, 2048)?;
    if redirect.path() != "/v1/auth/callback"
        || config.client_id.is_empty()
        || config.client_id.len() > 256
        || config.client_id.chars().any(char::is_control)
        || config.flow_ttl_ms != AUTH_FLOW_TTL_MS
        || config.session_ttl_ms != AUTH_SESSION_TTL_MS
        || config.trust_roots_sha256.len() > 16
        || config.system_roots == !config.trust_roots_sha256.is_empty()
        || config.bindings.len() > 1024
    {
        return Err(invalid("AuthConfig.profile"));
    }
    if config
        .trust_roots_sha256
        .iter()
        .any(|root| root.len() != 32)
        || config
            .trust_roots_sha256
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("AuthConfig.trust_roots_sha256"));
    }
    if config
        .bindings
        .iter()
        .any(|binding| binding.principal_hash.len() != 32 || !token_name(&binding.token_name))
        || config
            .bindings
            .windows(2)
            .any(|pair| pair[0].principal_hash >= pair[1].principal_hash)
    {
        return Err(invalid("AuthConfig.bindings"));
    }
    if config.digest != auth_config_digest(config) {
        return Err(invalid("AuthConfig.digest"));
    }
    Ok(())
}

fn positive_session_integer(value: u64) -> bool {
    value > 0 && value <= i64::MAX as u64
}

/// Structural public tombstone binding. Its dedicated self-only producer must
/// additionally bind this exact proof to the live original session and token.
pub fn validate_auth_session_revoked(session: &pb::AuthSessionRevoked) -> Result<(), DecodeError> {
    use pb::auth_session_revoked::ConfigSource;
    if session.session_hash.len() != 32
        || session.principal_hash.len() != 32
        || session.config_digest.len() != 32
        || !token_name(&session.token_name)
        || !positive_session_integer(session.expires_at_ms)
    {
        return Err(invalid("AuthSessionRevoked.binding"));
    }
    match session.config_source.as_ref() {
        Some(ConfigSource::NativeLsn(lsn))
            if positive_session_integer(*lsn)
                && session.metadata_token.is_none()
                && session.peer_boot.is_none() =>
        {
            Ok(())
        }
        Some(ConfigSource::MetadataIndex(index)) if positive_session_integer(*index) => {
            let token = session
                .metadata_token
                .as_ref()
                .ok_or_else(|| invalid("AuthSessionRevoked.metadata_token"))?;
            let peer = session
                .peer_boot
                .as_ref()
                .ok_or_else(|| invalid("AuthSessionRevoked.peer_boot"))?;
            if !positive_session_integer(token.metadata_revision)
                || !positive_session_integer(token.created_index)
                || token.created_index > token.token_revision
                || token.token_revision > token.metadata_revision
                || *index > token.metadata_revision
                || token.fleet_revision > token.metadata_revision
                || !positive_session_integer(peer.member_id)
                || !positive_session_integer(peer.incarnation)
                || peer.boot_id.len() != 32
                || !positive_session_integer(peer.registration_index)
            {
                return Err(invalid("AuthSessionRevoked.metadata"));
            }
            Ok(())
        }
        _ => Err(invalid("AuthSessionRevoked.config_source")),
    }
}

/// Structural history only; the original SessionLease supplies authorization.
pub fn validate_auth_oidc_login(login: &pb::AuthOidcLogin) -> Result<(), DecodeError> {
    use pb::auth_oidc_login::ConfigSource;
    if login.principal_hash.len() != 32
        || login.config_digest.len() != 32
        || !token_name(&login.token_name)
    {
        return Err(invalid("AuthOidcLogin.binding"));
    }
    match login.config_source.as_ref() {
        Some(ConfigSource::NativeLsn(position) | ConfigSource::MetadataIndex(position))
            if positive_session_integer(*position) =>
        {
            Ok(())
        }
        _ => Err(invalid("AuthOidcLogin.config_source")),
    }
}

pub fn is_control_action(action: &str) -> bool {
    matches!(
        action,
        "fleet.state" | "installation.identity" | "auth.config" | "auth.logout" | "auth.oidc.login"
    )
}

impl Operation {
    /// Session tombstones and login history have no single-current control family.
    pub fn kind(&self) -> Option<ControlKind> {
        match self {
            Self::FleetState(_) => Some(ControlKind::Fleet),
            Self::InstallationIdentity(_) => Some(ControlKind::Installation),
            Self::AuthConfig(_) => Some(ControlKind::Auth),
            Self::AuthSessionRevoked(_) | Self::AuthOidcLogin(_) => None,
        }
    }

    pub fn validate(&self) -> Result<(), DecodeError> {
        match self {
            Self::FleetState(state) => validate_fleet_state(state),
            Self::InstallationIdentity(identity) if identifier(&identity.installation) => Ok(()),
            Self::InstallationIdentity(_) => Err(invalid("InstallationIdentity.installation")),
            Self::AuthConfig(config) => validate_auth_config(config),
            Self::AuthSessionRevoked(session) => validate_auth_session_revoked(session),
            Self::AuthOidcLogin(login) => validate_auth_oidc_login(login),
        }
    }

    pub fn action(&self) -> &'static str {
        match self {
            Self::FleetState(_) => "fleet.state",
            Self::InstallationIdentity(_) => "installation.identity",
            Self::AuthConfig(_) => "auth.config",
            Self::AuthSessionRevoked(_) => "auth.logout",
            Self::AuthOidcLogin(_) => "auth.oidc.login",
        }
    }

    pub fn target(&self) -> &str {
        match self {
            Self::FleetState(state) => &state.installation,
            Self::InstallationIdentity(identity) => &identity.installation,
            Self::AuthConfig(_) => "oidc",
            Self::AuthSessionRevoked(_) | Self::AuthOidcLogin(_) => "",
        }
    }

    pub fn validate_transition(&self, previous: Option<&Self>) -> Result<(), DecodeError> {
        self.validate()?;
        if let Some(previous) = previous {
            previous.validate()?;
        }
        match (self, previous) {
            (Self::FleetState(next), Some(Self::FleetState(old))) => fleet_transition(old, next),
            (Self::FleetState(next), None)
                if next.epoch == 1 && next.phase == pb::fleet_state::Phase::Pending as i32 =>
            {
                Ok(())
            }
            (Self::InstallationIdentity(next), Some(Self::InstallationIdentity(old)))
                if next == old =>
            {
                Ok(())
            }
            (Self::InstallationIdentity(_), None) => Ok(()),
            (Self::AuthConfig(next), Some(Self::AuthConfig(old)))
                if next.previous_digest == old.digest =>
            {
                Ok(())
            }
            (Self::AuthConfig(next), None) if next.previous_digest.is_empty() => Ok(()),
            _ => Err(invalid("ControlOperation.transition")),
        }
    }
}

fn fleet_transition(old: &pb::FleetState, next: &pb::FleetState) -> Result<(), DecodeError> {
    use pb::fleet_state::Phase;
    if old.installation != next.installation {
        return Err(invalid("FleetState.transition"));
    }
    let same_request = old.node == next.node
        && old.cluster == next.cluster
        && old.controller_origin == next.controller_origin
        && old.scopes == next.scopes
        && old.ca_sha256 == next.ca_sha256
        && old.request_id == next.request_id
        && old.csr_der == next.csr_der
        && old.client_key_sha256 == next.client_key_sha256;
    let allowed = if old.epoch == next.epoch {
        old == next
            || (same_request
                && ((old.phase == Phase::Pending as i32 && next.phase == Phase::Requested as i32)
                    || (old.phase == Phase::Requested as i32
                        && next.phase == Phase::Active as i32)
                    || (old.phase != Phase::Revoked as i32
                        && next.phase == Phase::Revoked as i32
                        && old.controller_id == next.controller_id
                        && old.client_cert_der == next.client_cert_der)))
    } else if old.epoch.checked_add(1) == Some(next.epoch) {
        next.phase == Phase::Pending as i32
            && old.phase != Phase::Requested as i32
            && old.request_id != next.request_id
    } else {
        false
    };
    if allowed {
        Ok(())
    } else {
        Err(invalid("FleetState.transition"))
    }
}

/// The closed metadata retention-gap schema; indices are never actor LSNs.
pub fn metadata_audit_gap_details(
    details: &std::collections::BTreeMap<String, String>,
) -> Result<(&str, u64, u64), DecodeError> {
    if details.len() != 4 || details.get("namespace").map(String::as_str) != Some("metadata") {
        return Err(invalid("MetadataAuditGap"));
    }
    let stream = details
        .get("stream")
        .ok_or_else(|| invalid("MetadataAuditGap.stream"))?;
    if stream.is_empty() || stream.len() > 1024 || stream.chars().any(char::is_control) {
        return Err(invalid("MetadataAuditGap.stream"));
    }
    let index = |name| -> Result<u64, DecodeError> {
        let text = details
            .get(name)
            .ok_or_else(|| invalid("MetadataAuditGap.index"))?;
        if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("MetadataAuditGap.index"));
        }
        let value = text
            .parse::<u64>()
            .map_err(|_| invalid("MetadataAuditGap.index"))?;
        if value == 0 || value > i64::MAX as u64 {
            return Err(invalid("MetadataAuditGap.index"));
        }
        Ok(value)
    };
    let from = index("from_index")?;
    let through = index("through_index")?;
    if from > through {
        return Err(invalid("MetadataAuditGap"));
    }
    Ok((stream, from, through))
}

/// History-only Meta26 exception, never a generic authorization action.
pub fn validate_metadata_gap_event(event: &pb::AuditEvent) -> Result<(), DecodeError> {
    if event.action != "audit.gap" || !event.target.is_empty() || event.operation.is_some() {
        return Err(invalid("MetadataAuditGap"));
    }
    let audit = event
        .audit
        .as_ref()
        .ok_or_else(|| invalid("MetadataAuditGap.audit"))?;
    if audit.reason.is_empty() || audit.reason.len() > 4096 || audit.token_id.len() > 1024 {
        return Err(invalid("MetadataAuditGap.audit"));
    }
    metadata_audit_gap_details(&event.details).map(|_| ())
}

/// Closed metadata webhook rotation fields; versions retain their exact M23 domain.
pub fn metadata_webhook_key_change_details(
    details: &std::collections::BTreeMap<String, String>,
) -> Result<(u64, u64), DecodeError> {
    if details.len() != 4
        || details.get("change").map(String::as_str) != Some("webhook.signing_key")
        || details.get("source").map(String::as_str) != Some("metadata")
    {
        return Err(invalid("MetadataWebhookKeyChange"));
    }
    let version = |field| -> Result<u64, DecodeError> {
        let text = details
            .get(field)
            .ok_or_else(|| invalid("MetadataWebhookKeyChange.version"))?;
        if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("MetadataWebhookKeyChange.version"));
        }
        let value = text
            .parse::<u64>()
            .map_err(|_| invalid("MetadataWebhookKeyChange.version"))?;
        if value == 0 || value > crate::secret::MAX_SECRET_VERSION {
            return Err(invalid("MetadataWebhookKeyChange.version"));
        }
        Ok(value)
    };
    Ok((version("from_version")?, version("to_version")?))
}

/// Fixed history-only configuration receipt; audit metadata is not authority.
pub fn validate_metadata_webhook_key_change_event(
    event: &pb::AuditEvent,
) -> Result<(), DecodeError> {
    if event.action != "audit.config"
        || event.operation.is_some()
        || !event.target.starts_with("events-")
        || event.target.len() > 128
        || event.target.chars().any(char::is_control)
    {
        return Err(invalid("MetadataWebhookKeyChange"));
    }
    let audit = event
        .audit
        .as_ref()
        .ok_or_else(|| invalid("MetadataWebhookKeyChange.audit"))?;
    if audit.reason.is_empty() || audit.reason.len() > 4096 || audit.token_id.len() > 1024 {
        return Err(invalid("MetadataWebhookKeyChange.audit"));
    }
    metadata_webhook_key_change_details(&event.details).map(|_| ())
}

/// Closed metadata replay position; actor LSNs are a separate domain.
pub fn metadata_webhook_replay_details(
    details: &std::collections::BTreeMap<String, String>,
) -> Result<u64, DecodeError> {
    if details.len() != 2 || details.get("source").map(String::as_str) != Some("metadata") {
        return Err(invalid("MetadataWebhookReplay"));
    }
    let text = details
        .get("position")
        .ok_or_else(|| invalid("MetadataWebhookReplay.position"))?;
    if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("MetadataWebhookReplay.position"));
    }
    let position = text
        .parse::<u64>()
        .map_err(|_| invalid("MetadataWebhookReplay.position"))?;
    if position == 0 || position > i64::MAX as u64 {
        return Err(invalid("MetadataWebhookReplay.position"));
    }
    Ok(position)
}

/// Structural history only; the fixed producer binds the registered stream and lease.
pub fn validate_metadata_webhook_replay_event(event: &pb::AuditEvent) -> Result<(), DecodeError> {
    let registered_name = event
        .target
        .strip_prefix("events-")
        .and_then(|name| name.strip_suffix(":metadata"));
    if event.action != "events.webhook.replay"
        || event.operation.is_some()
        || event.target.len() > 128
        || registered_name.is_none_or(|name| !token_name(name))
    {
        return Err(invalid("MetadataWebhookReplay"));
    }
    let audit = event
        .audit
        .as_ref()
        .ok_or_else(|| invalid("MetadataWebhookReplay.audit"))?;
    if audit.reason.is_empty() || audit.reason.len() > 4096 || audit.token_id.len() > 1024 {
        return Err(invalid("MetadataWebhookReplay.audit"));
    }
    metadata_webhook_replay_details(&event.details).map(|_| ())
}

/// Structural provenance only. The private initialization producer must bind the
/// adoption audit to its actual already-admitted initialization operation.
/// Archive/current purpose is interpreted by the materializer, never as authority here.
pub fn validate_native_authority_origin(
    origin: &pb::NativeAuthorityOrigin,
) -> Result<(), DecodeError> {
    if let Some(source) = &origin.source {
        source.validate()?;
        if source.shard.is_some() {
            return Err(invalid("NativeAuthorityOrigin.source"));
        }
    }
    if origin
        .adoption_audit
        .as_ref()
        .is_none_or(|audit| audit.token_id.is_empty())
    {
        return Err(invalid("NativeAuthorityOrigin.adoption_audit"));
    }
    Ok(())
}
pub fn validate_event(event: &pb::AuditEvent) -> Result<(), DecodeError> {
    if event.audit.is_none() || event.action.is_empty() {
        return Err(invalid("AuditEvent.audit"));
    }
    match &event.operation {
        Some(operation) => {
            operation.validate()?;
            if event.action != operation.action()
                || event.target != operation.target()
                || !event.details.is_empty()
            {
                return Err(invalid("AuditEvent.operation"));
            }
            if matches!(operation, Operation::InstallationIdentity(_))
                && event
                    .audit
                    .as_ref()
                    .is_none_or(|audit| audit.token_id != "system:installation")
            {
                return Err(invalid("InstallationIdentity.origin"));
            }
            let principal_hash = match operation {
                Operation::AuthSessionRevoked(session) => Some(&session.principal_hash),
                Operation::AuthOidcLogin(login) => Some(&login.principal_hash),
                _ => None,
            };
            if let Some(principal_hash) = principal_hash {
                let principal = event
                    .audit
                    .as_ref()
                    .and_then(|audit| audit.token_id.strip_prefix("oidc:"));
                if principal.is_none_or(|principal| !matches_hex(principal, principal_hash)) {
                    return Err(invalid("AuditEvent.session_origin"));
                }
            }
            Ok(())
        }
        None if is_control_action(&event.action) => Err(invalid("AuditEvent.operation")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_state() -> pb::FleetState {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/control-fleet-pending-v1.json"
        ))
        .unwrap();
        let bytes = |field: &str| {
            fixture[field]
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
            installation: fixture["installation"].as_str().unwrap().into(),
            node: None,
            cluster: None,
            controller_origin: fixture["controller_origin"].as_str().unwrap().into(),
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

    fn fixture_session(member: bool) -> (pb::AuthSessionRevoked, Vec<u8>) {
        let fixture: serde_json::Value = serde_json::from_str(if member {
            include_str!("../tests/fixtures/auth-session-revoked-metadata-v1.json")
        } else {
            include_str!("../tests/fixtures/auth-session-revoked-native-v1.json")
        })
        .unwrap();
        let bytes = |value: &serde_json::Value| {
            value
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect()
        };
        let config_source = if member {
            pb::auth_session_revoked::ConfigSource::MetadataIndex(
                fixture["config_source"]["metadata_index"].as_u64().unwrap(),
            )
        } else {
            pb::auth_session_revoked::ConfigSource::NativeLsn(
                fixture["config_source"]["native_lsn"].as_u64().unwrap(),
            )
        };
        let metadata_token = member.then(|| pb::SessionMetadataToken {
            metadata_revision: fixture["metadata_token"]["metadata_revision"]
                .as_u64()
                .unwrap(),
            created_index: fixture["metadata_token"]["created_index"].as_u64().unwrap(),
            token_revision: fixture["metadata_token"]["token_revision"]
                .as_u64()
                .unwrap(),
            fleet_revision: fixture["metadata_token"]["fleet_revision"]
                .as_u64()
                .unwrap(),
        });
        let peer_boot = member.then(|| pb::SessionPeerBoot {
            member_id: fixture["peer_boot"]["member_id"].as_u64().unwrap(),
            incarnation: fixture["peer_boot"]["incarnation"].as_u64().unwrap(),
            boot_id: bytes(&fixture["peer_boot"]["boot_id"]),
            registration_index: fixture["peer_boot"]["registration_index"].as_u64().unwrap(),
        });
        (
            pb::AuthSessionRevoked {
                session_hash: bytes(&fixture["session_hash"]),
                principal_hash: bytes(&fixture["principal_hash"]),
                config_digest: bytes(&fixture["config_digest"]),
                config_source: Some(config_source),
                token_name: fixture["token_name"].as_str().unwrap().into(),
                expires_at_ms: fixture["expires_at_ms"].as_u64().unwrap(),
                metadata_token,
                peer_boot,
            },
            bytes(&fixture["wire_hex"]),
        )
    }

    fn event(operation: Operation) -> pb::AuditEvent {
        let token_id = match &operation {
            Operation::InstallationIdentity(_) => "system:installation".into(),
            Operation::AuthSessionRevoked(pb::AuthSessionRevoked { principal_hash, .. })
            | Operation::AuthOidcLogin(pb::AuthOidcLogin { principal_hash, .. }) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut identity = String::with_capacity(69);
                identity.push_str("oidc:");
                for byte in principal_hash {
                    identity.push(HEX[(byte >> 4) as usize] as char);
                    identity.push(HEX[(byte & 15) as usize] as char);
                }
                identity
            }
            _ => "token:operator".into(),
        };
        pb::AuditEvent {
            action: operation.action().into(),
            target: operation.target().into(),
            audit: Some(pb::Audit {
                token_id,
                reason: "free text is not classified by this structural validator".into(),
                wall_time_ms: 1,
            }),
            operation: Some(operation),
            ..Default::default()
        }
    }

    #[test]
    fn oidc_login_wire_is_protected_history_not_a_session_or_control_ledger() {
        for member in [false, true] {
            let (session, _) = fixture_session(member);
            let source = if member {
                pb::auth_oidc_login::ConfigSource::MetadataIndex(17)
            } else {
                pb::auth_oidc_login::ConfigSource::NativeLsn(17)
            };
            let login = pb::AuthOidcLogin {
                principal_hash: session.principal_hash,
                config_digest: session.config_digest,
                config_source: Some(source),
                token_name: session.token_name,
            };
            let fixture: serde_json::Value = serde_json::from_str(if member {
                include_str!("../tests/fixtures/auth-oidc-login-metadata-v1.json")
            } else {
                include_str!("../tests/fixtures/auth-oidc-login-native-v1.json")
            })
            .unwrap();
            let wire = fixture["wire_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(login.encode_to_vec(), wire);
            let operation = Operation::AuthOidcLogin(login);
            assert_eq!(
                (operation.kind(), operation.action(), operation.target()),
                (None, "auth.oidc.login", "")
            );
            assert!(operation.validate_transition(None).is_err());
            let record = crate::Record::AuditEvent(event(operation));
            assert_eq!(
                crate::Record::decode(crate::kind::AUDIT_EVENT, &record.encode()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn oidc_login_rejects_unbound_ranges_origins_or_legacy_payloads() {
        let login = pb::AuthOidcLogin {
            principal_hash: vec![2; 32],
            config_digest: vec![3; 32],
            config_source: Some(pb::auth_oidc_login::ConfigSource::NativeLsn(17)),
            token_name: "operator".into(),
        };
        assert!(validate_auth_oidc_login(&pb::AuthOidcLogin::default()).is_err());
        for field in ["principal", "digest", "token", "source", "zero", "large"] {
            let mut invalid = login.clone();
            match field {
                "principal" => {
                    invalid.principal_hash.pop();
                }
                "digest" => invalid.config_digest.push(0),
                "token" => invalid.token_name = "raw:subject".into(),
                "source" => invalid.config_source = None,
                "zero" => {
                    invalid.config_source = Some(pb::auth_oidc_login::ConfigSource::NativeLsn(0))
                }
                "large" => {
                    invalid.config_source =
                        Some(pb::auth_oidc_login::ConfigSource::MetadataIndex(u64::MAX))
                }
                _ => unreachable!(),
            }
            assert!(validate_auth_oidc_login(&invalid).is_err(), "{field}");
        }
        let valid = event(Operation::AuthOidcLogin(login));
        validate_event(&valid).unwrap();
        for field in ["origin", "action", "target", "details", "missing"] {
            let mut invalid = valid.clone();
            match field {
                "origin" => invalid.audit.as_mut().unwrap().token_id = "token:operator".into(),
                "action" => invalid.action = "auth.logout".into(),
                "target" => invalid.target = "operator".into(),
                "details" => {
                    invalid
                        .details
                        .insert("principal".into(), "raw-subject".into());
                }
                "missing" => invalid.operation = None,
                _ => unreachable!(),
            }
            assert!(validate_event(&invalid).is_err(), "{field}");
        }
    }

    #[test]
    fn session_tombstone_wire_fixtures_are_not_current_control_families() {
        for member in [false, true] {
            let (session, expected_wire) = fixture_session(member);
            validate_auth_session_revoked(&session).unwrap();
            assert_eq!(session.encode_to_vec(), expected_wire);
            let operation = Operation::AuthSessionRevoked(session);
            assert_eq!(operation.kind(), None);
            assert_eq!(operation.action(), "auth.logout");
            assert_eq!(operation.target(), "");
            assert!(operation.validate_transition(None).is_err());
            assert!(operation.validate_transition(Some(&operation)).is_err());
            let record = crate::Record::AuditEvent(event(operation));
            assert_eq!(
                crate::Record::decode(crate::kind::AUDIT_EVENT, &record.encode()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn session_tombstones_reject_default_mixed_unbounded_or_unbound_fields() {
        assert!(validate_auth_session_revoked(&pb::AuthSessionRevoked::default()).is_err());
        let (native, _) = fixture_session(false);
        for field in [
            "session",
            "principal",
            "digest",
            "name",
            "expires",
            "source",
            "zero",
            "large",
            "token",
            "peer",
        ] {
            let mut invalid = native.clone();
            match field {
                "session" => {
                    invalid.session_hash.pop();
                }
                "principal" => {
                    invalid.principal_hash.pop();
                }
                "digest" => invalid.config_digest.push(0),
                "name" => invalid.token_name = "Operator".into(),
                "expires" => invalid.expires_at_ms = 0,
                "source" => invalid.config_source = None,
                "zero" => {
                    invalid.config_source =
                        Some(pb::auth_session_revoked::ConfigSource::NativeLsn(0))
                }
                "large" => invalid.expires_at_ms = u64::MAX,
                "token" => invalid.metadata_token = Some(pb::SessionMetadataToken::default()),
                "peer" => invalid.peer_boot = Some(pb::SessionPeerBoot::default()),
                _ => unreachable!(),
            }
            assert!(validate_auth_session_revoked(&invalid).is_err(), "{field}");
        }
        let (member, _) = fixture_session(true);
        assert_eq!(member.metadata_token.as_ref().unwrap().fleet_revision, 0);
        // Peer registration can legitimately follow the last effective auth change.
        assert!(
            member.peer_boot.as_ref().unwrap().registration_index
                > member.metadata_token.as_ref().unwrap().metadata_revision
        );
        for field in [
            "token",
            "peer",
            "source",
            "revision",
            "created",
            "token-order",
            "created-order",
            "fleet",
            "config",
            "owner",
            "incarnation",
            "boot",
            "registration",
        ] {
            let mut invalid = member.clone();
            match field {
                "token" => invalid.metadata_token = None,
                "peer" => invalid.peer_boot = None,
                "source" => {
                    invalid.config_source =
                        Some(pb::auth_session_revoked::ConfigSource::NativeLsn(17))
                }
                "revision" => invalid.metadata_token.as_mut().unwrap().metadata_revision = u64::MAX,
                "created" => invalid.metadata_token.as_mut().unwrap().created_index = 0,
                "token-order" => invalid.metadata_token.as_mut().unwrap().token_revision = 22,
                "created-order" => invalid.metadata_token.as_mut().unwrap().created_index = 4,
                "fleet" => invalid.metadata_token.as_mut().unwrap().fleet_revision = 22,
                "config" => {
                    invalid.config_source =
                        Some(pb::auth_session_revoked::ConfigSource::MetadataIndex(22))
                }
                "owner" => invalid.peer_boot.as_mut().unwrap().member_id = 0,
                "incarnation" => invalid.peer_boot.as_mut().unwrap().incarnation = u64::MAX,
                "boot" => invalid.peer_boot.as_mut().unwrap().boot_id.truncate(16),
                "registration" => invalid.peer_boot.as_mut().unwrap().registration_index = 0,
                _ => unreachable!(),
            }
            assert!(validate_auth_session_revoked(&invalid).is_err(), "{field}");
        }
    }

    #[test]
    fn session_logout_requires_exact_protected_self_origin_and_no_free_details() {
        let valid = event(Operation::AuthSessionRevoked(fixture_session(false).0));
        validate_event(&valid).unwrap();
        for origin in [
            "token:operator",
            "system:startup",
            "oidc:issuer:raw-subject",
            "oidc:00",
        ] {
            let mut invalid = valid.clone();
            invalid.audit.as_mut().unwrap().token_id = origin.into();
            assert!(validate_event(&invalid).is_err());
        }
        for field in ["action", "target", "record", "missing"] {
            let mut invalid = valid.clone();
            match field {
                "action" => invalid.action = "auth.config".into(),
                "target" => invalid.target = "oidc".into(),
                "record" => {
                    invalid.details.insert("record".into(), "{}".into());
                }
                "missing" => invalid.operation = None,
                _ => unreachable!(),
            }
            assert!(validate_event(&invalid).is_err(), "{field}");
        }
    }

    #[test]
    fn actual_public_csr_control_wire_round_trips_without_a_json_authority() {
        let operation = Operation::FleetState(fixture_state());
        operation.validate_transition(None).unwrap();
        let record = crate::Record::AuditEvent(event(operation));
        let encoded = record.encode();
        assert_eq!(
            crate::Record::decode(crate::kind::AUDIT_EVENT, &encoded).unwrap(),
            record
        );
    }

    #[test]
    fn fleet_domains_reject_unspecified_invalid_or_unbound_metadata() {
        let valid = fixture_state();
        for phase in [0, -1, 99] {
            let mut state = valid.clone();
            state.phase = phase;
            assert!(validate_fleet_state(&state).is_err());
        }
        for field in ["epoch", "request", "ca", "key", "csr", "origin", "scopes"] {
            let mut state = valid.clone();
            match field {
                "epoch" => state.epoch = 0,
                "request" => {
                    state.request_id.pop();
                }
                "ca" => {
                    state.ca_sha256.pop();
                }
                "key" => state.client_key_sha256[0] ^= 1,
                "csr" => state.csr_der.push(0),
                "origin" => state.controller_origin = "https://controller.test/path".into(),
                "scopes" => state.scopes = vec!["fork".into(), "read".into()],
                _ => unreachable!(),
            }
            assert!(validate_fleet_state(&state).is_err(), "{field}");
        }
    }

    #[test]
    fn revoke_keeps_the_enrollment_epoch_and_no_late_reply_can_reactivate_it() {
        let pending = fixture_state();
        let mut requested = pending.clone();
        requested.phase = pb::fleet_state::Phase::Requested as i32;
        Operation::FleetState(requested.clone())
            .validate_transition(Some(&Operation::FleetState(pending.clone())))
            .unwrap();
        let mut revoked = requested.clone();
        revoked.phase = pb::fleet_state::Phase::Revoked as i32;
        Operation::FleetState(revoked.clone())
            .validate_transition(Some(&Operation::FleetState(requested.clone())))
            .unwrap();
        assert!(
            Operation::FleetState(requested)
                .validate_transition(Some(&Operation::FleetState(revoked.clone())))
                .is_err()
        );
        let mut wrong_epoch = revoked.clone();
        wrong_epoch.epoch += 1;
        assert!(
            Operation::FleetState(wrong_epoch)
                .validate_transition(Some(&Operation::FleetState(pending.clone())))
                .is_err()
        );
        let mut fresh = pending;
        fresh.epoch += 1;
        fresh.request_id[0] ^= 1;
        Operation::FleetState(fresh)
            .validate_transition(Some(&Operation::FleetState(revoked)))
            .unwrap();
        let mut last = fixture_state();
        last.epoch = u64::MAX;
        last.phase = pb::fleet_state::Phase::Requested as i32;
        let mut revoked_last = last.clone();
        revoked_last.phase = pb::fleet_state::Phase::Revoked as i32;
        Operation::FleetState(revoked_last)
            .validate_transition(Some(&Operation::FleetState(last)))
            .unwrap();
    }

    #[test]
    fn typed_fields_cannot_mix_with_free_json_or_claim_another_action_origin() {
        let valid = event(Operation::FleetState(fixture_state()));
        for field in ["record", "config", "note"] {
            let mut mixed = valid.clone();
            mixed.details.insert(field.into(), "{}".into());
            assert!(validate_event(&mixed).is_err());
        }
        let mut missing = valid.clone();
        missing.operation = None;
        assert!(validate_event(&missing).is_err());
        let mut mismatch = valid;
        mismatch.target = "another-installation".into();
        assert!(validate_event(&mismatch).is_err());
        let mut identity = event(Operation::InstallationIdentity(pb::InstallationIdentity {
            installation: "1".into(),
        }));
        identity.audit.as_mut().unwrap().token_id = "token:operator".into();
        assert!(validate_event(&identity).is_err());
    }

    #[test]
    fn auth_digest_is_public_canonical_and_requires_exact_current_predecessor() {
        let mut disabled = pb::AuthConfig {
            version: AUTH_CONFIG_VERSION,
            ..Default::default()
        };
        disabled.digest = auth_config_digest(&disabled).to_vec();
        let initial = Operation::AuthConfig(disabled.clone());
        initial.validate_transition(None).unwrap();
        assert!(initial.validate_transition(Some(&initial)).is_err());
        let mut next = disabled.clone();
        next.enabled = true;
        next.previous_digest = disabled.digest.clone();
        next.issuer = "https://issuer.test".into();
        next.client_id = "schema".into();
        next.redirect_uri = "https://app.test/v1/auth/callback".into();
        next.system_roots = true;
        next.flow_ttl_ms = AUTH_FLOW_TTL_MS;
        next.session_ttl_ms = AUTH_SESSION_TTL_MS;
        next.digest = auth_config_digest(&next).to_vec();
        Operation::AuthConfig(next.clone())
            .validate_transition(Some(&initial))
            .unwrap();
        next.previous_digest[0] ^= 1;
        assert!(
            Operation::AuthConfig(next)
                .validate_transition(Some(&initial))
                .is_err()
        );
        disabled.issuer = "https://must-not-be-ignored.test".into();
        disabled.digest = auth_config_digest(&disabled).to_vec();
        assert!(validate_auth_config(&disabled).is_err());
    }
}
