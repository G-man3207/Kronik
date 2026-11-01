//! Prepared durable metadata, published by the existing TokenStore fence.
use super::*;
use kronik_core::authority::AuthLease;
use kronik_core::ids::SourcePos;
use std::collections::BTreeMap;

/// Immutable proof, not a bearer credential or a forwarded scope snapshot.
#[derive(Clone, PartialEq, Eq)]
pub enum ForwardedPrincipal {
    Bearer {
        hash: [u8; 32],
        expected: ExpectedRevision,
    },
    Local {
        owner_member: u64,
        uid: u32,
        expected: ExpectedRevision,
    },
}

impl std::fmt::Debug for ForwardedPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer { expected, .. } => f
                .debug_struct("BearerPrincipal")
                .field("expected", expected)
                .finish(),
            Self::Local {
                owner_member,
                uid,
                expected,
            } => f
                .debug_struct("LocalPrincipal")
                .field("owner_member", owner_member)
                .field("uid", uid)
                .field("expected", expected)
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedRevision {
    pub metadata_revision: u64,
    pub created_index: u64,
    pub token_revision: u64,
    pub auth_config_revision: u64,
    pub fleet_revision: u64,
}

/// The actual browser session binding; no cookie, JWT or subject leaves its owner.
#[derive(Clone, PartialEq, Eq)]
pub struct OidcSessionProof {
    pub session_blake3: [u8; 32],
    pub principal_hash: [u8; 32],
    pub config_digest: [u8; 32],
    pub config_source: SourcePos,
    pub expires_wall_ms: u64,
}

impl std::fmt::Debug for OidcSessionProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcSessionProof")
            .field("config_source", &self.config_source)
            .field("expires_wall_ms", &self.expires_wall_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataToken {
    pub meta: TokenMeta,
    pub hash: [u8; 32],
    pub created_index: u64,
    pub revision: u64,
    pub revoked_index: Option<u64>,
}

/// All fields come from one durable metadata image, never local tokens.db.
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataSource {
    pub revision: u64,
    pub owner_member: u64,
    pub auth_config_revision: u64,
    pub auth_config: Option<kronik_proto::log::v1::AuthConfig>,
    pub fleet_revision: u64,
    pub fleet: Option<kronik_proto::log::v1::FleetState>,
    pub tokens: BTreeMap<String, MetadataToken>,
}

pub struct PreparedMetadata {
    source: Arc<MetadataSource>,
    live: Live,
    managed: HashMap<String, Arc<FleetToken>>,
}

pub(super) enum MetadataState {
    Native,
    Pending,
    Ready(Arc<MetadataSource>),
    Failed,
}

pub(super) fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        "durable member authentication is unavailable",
    )
}

impl MetadataSource {
    pub(super) fn expected(&self, token: Option<&MetadataToken>) -> ExpectedRevision {
        ExpectedRevision {
            metadata_revision: self.revision,
            created_index: token.map_or(0, |row| row.created_index),
            token_revision: token.map_or(0, |row| row.revision),
            auth_config_revision: self.auth_config_revision,
            fleet_revision: self.fleet_revision,
        }
    }

    pub(super) fn matches(
        &self,
        expected: ExpectedRevision,
        token: Option<&MetadataToken>,
    ) -> bool {
        let current = self.expected(token);
        self.revision >= expected.metadata_revision
            && current.created_index == expected.created_index
            && current.token_revision == expected.token_revision
            && current.auth_config_revision == expected.auth_config_revision
            && current.fleet_revision == expected.fleet_revision
    }

    pub(super) fn current_fleet_receipt(
        &self,
        epoch: u64,
        request_id: &str,
    ) -> Result<&kronik_proto::log::v1::FleetState, ApiError> {
        let state = self
            .fleet
            .as_ref()
            .ok_or_else(|| unauthenticated("managed fleet authority is unavailable"))?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let request = request_id.as_bytes();
        let same_request = request.len() == 64
            && state.request_id.len() == 32
            && state.request_id.iter().enumerate().all(|(index, byte)| {
                request[index * 2] == HEX[(byte >> 4) as usize]
                    && request[index * 2 + 1] == HEX[(byte & 15) as usize]
            });
        if state.epoch != epoch || !same_request {
            return Err(unauthenticated("the managed fleet receipt was superseded"));
        }
        Ok(state)
    }

    pub(super) fn require_fleet(&self, token: &MetadataToken) -> Result<(), ApiError> {
        let Some(provenance) = &token.meta.fleet else {
            return Ok(());
        };
        let state = self.current_fleet_receipt(provenance.epoch, &provenance.request_id)?;
        if state.phase != kronik_proto::log::v1::fleet_state::Phase::Active as i32
            || token.meta.scopes.len() != state.scopes.len()
            || !token
                .meta
                .scopes
                .iter()
                .all(|scope| state.scopes.iter().any(|value| value == scope.as_str()))
        {
            return Err(unauthenticated(
                "the managed fleet receipt is no longer active",
            ));
        }
        Ok(())
    }
}

impl TokenStore {
    pub(super) fn metadata(&self) -> MutexGuard<'_, MetadataState> {
        self.metadata
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Call before exposing a member listener; native SQLite can never authorize it.
    pub fn require_metadata(&self) -> Result<(), ApiError> {
        self.publish_auth_change(&mut || {
            let mut state = self.metadata();
            match &*state {
                MetadataState::Native => {
                    *state = MetadataState::Pending;
                    Ok(())
                }
                _ => Err(internal("member authentication was already attached")),
            }
        })
    }

    /// Parse and allocate outside the publisher, before acquiring any admission fence.
    pub fn prepare_metadata(source: MetadataSource) -> Result<PreparedMetadata, ApiError> {
        if source.owner_member == 0
            || source.auth_config_revision > source.revision
            || source.fleet_revision > source.revision
        {
            return Err(internal("invalid metadata authentication revision"));
        }
        if source.auth_config.is_some() != (source.auth_config_revision > 0) {
            return Err(internal(
                "metadata authentication profile lacks its exact source",
            ));
        }
        if source.fleet.is_some() != (source.fleet_revision > 0) {
            return Err(internal("metadata fleet receipt lacks its exact source"));
        }
        if let Some(config) = &source.auth_config {
            kronik_proto::control::validate_auth_config(config).map_err(internal)?;
        }
        if let Some(fleet) = &source.fleet {
            kronik_proto::control::validate_fleet_state(fleet).map_err(internal)?;
        }
        let (mut live, mut managed) = (HashMap::new(), HashMap::new());
        let mut hashes = BTreeSet::new();
        for (name, row) in &source.tokens {
            if name != &row.meta.name
                || !valid_name(name)
                || row.meta.scopes.is_empty()
                || row.created_index == 0
                || row.created_index > row.revision
                || row.revision > source.revision
                || row.revoked_index.is_some_and(|index| index != row.revision)
                || row.meta.revoked.is_some() != row.revoked_index.is_some()
            {
                return Err(internal("invalid metadata token row"));
            }
            if !hashes.insert(row.hash) {
                return Err(internal("duplicate metadata token identity"));
            }
            if let Some(fleet) = &row.meta.fleet {
                if fleet.epoch == 0
                    || fleet.request_id.len() != 64
                    || !fleet
                        .request_id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(internal("invalid metadata fleet provenance"));
                }
                managed.insert(name.clone(), Arc::new(fleet.clone()));
            }
            if row.meta.revoked.is_none() {
                live.insert(row.hash, (name.clone(), row.meta.scopes.clone()));
            }
        }
        Ok(PreparedMetadata {
            source: Arc::new(source),
            live,
            managed,
        })
    }

    /// The image and parent directory are durable before this bounded swap.
    pub fn publish_prepared(&self, prepared: PreparedMetadata) -> Result<(), ApiError> {
        let PreparedMetadata {
            source,
            live,
            managed,
        } = prepared;
        let previous = match &*self.metadata() {
            MetadataState::Pending => None,
            MetadataState::Ready(previous) => Some(previous.clone()),
            _ => return Err(unavailable()),
        };
        if previous.as_ref().is_some_and(|previous| {
            source.revision < previous.revision
                || (source.revision == previous.revision && source != *previous)
        }) {
            return Err(unavailable());
        }
        let publication = self.publication();
        let mut state = self.metadata();
        match (&*state, previous.as_ref()) {
            (MetadataState::Pending, None) => {}
            (MetadataState::Ready(current), Some(previous)) if Arc::ptr_eq(current, previous) => {}
            _ => return Err(unavailable()),
        }
        let retired_managed = std::mem::replace(
            &mut *self
                .managed
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            managed,
        );
        let retired_live = std::mem::replace(&mut *self.live(), live);
        let retired_state = std::mem::replace(&mut *state, MetadataState::Ready(source));
        self.notify_auth_change();
        drop(state);
        drop(publication);
        drop((retired_managed, retired_live, retired_state, previous));
        Ok(())
    }

    pub fn fail_metadata(&self) {
        let publication = self.publication();
        let retired = std::mem::replace(&mut *self.metadata(), MetadataState::Failed);
        self.notify_auth_change();
        drop(publication);
        drop(retired);
    }

    /// None means explicitly native; a missing member projection is never native.
    pub fn metadata_revision(&self) -> Result<Option<u64>, ApiError> {
        match &*self.metadata() {
            MetadataState::Native => Ok(None),
            MetadataState::Ready(source) => Ok(Some(source.revision)),
            _ => Err(unavailable()),
        }
    }

    /// Read-only receipt check for one admitted enrollment continuation.
    /// Native state is held by Fleet; an unavailable member is never native.
    pub(crate) fn fleet_phase(
        &self,
        epoch: u64,
        request_id: &str,
    ) -> Result<Option<kronik_proto::log::v1::fleet_state::Phase>, ApiError> {
        match &*self.metadata() {
            MetadataState::Native => Ok(None),
            MetadataState::Ready(source) => {
                let state = source.current_fleet_receipt(epoch, request_id)?;
                kronik_proto::log::v1::fleet_state::Phase::try_from(state.phase)
                    .map(Some)
                    .map_err(internal)
            }
            _ => Err(unavailable()),
        }
    }

    pub fn lookup(&self, name: &str) -> Result<Option<TokenMeta>, ApiError> {
        match &*self.metadata() {
            MetadataState::Ready(source) => {
                return Ok(source.tokens.get(name).map(|row| row.meta.clone()));
            }
            MetadataState::Native => {}
            _ => return Err(unavailable()),
        }
        self.inner()?
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM tokens WHERE name = ?1"),
                [name],
                meta,
            )
            .optional()
            .map_err(internal)
    }

    pub fn lookup_metadata(&self, name: &str) -> Result<Option<MetadataToken>, ApiError> {
        match &*self.metadata() {
            MetadataState::Ready(source) => Ok(source.tokens.get(name).cloned()),
            MetadataState::Native => Ok(None),
            _ => Err(unavailable()),
        }
    }

    pub fn token_source(
        &self,
        name: &str,
    ) -> Result<Option<(SourcePos, Option<SourcePos>)>, ApiError> {
        match &*self.metadata() {
            MetadataState::Ready(source) => Ok(source.tokens.get(name).map(|row| {
                (
                    SourcePos::Metadata {
                        index: row.created_index,
                    },
                    row.revoked_index.map(|index| SourcePos::Metadata { index }),
                )
            })),
            MetadataState::Native => Ok(None),
            _ => Err(unavailable()),
        }
    }

    pub fn capture_token(
        self: &Arc<Self>,
        token: &str,
        required: Scope,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let digest = hash(token);
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        self.capture_hash_under_publication(digest, required, execution)
    }

    /// Capture one actual named row and all its grants under the same publisher.
    pub(crate) fn capture_name(
        self: &Arc<Self>,
        name: &str,
        required: Scope,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        let digest = match &*self.metadata() {
            MetadataState::Ready(source) => source
                .tokens
                .get(name)
                .map(|row| row.hash)
                .ok_or_else(|| unauthenticated("the named token is unknown or revoked"))?,
            MetadataState::Native => self
                .live()
                .iter()
                .find_map(|(hash, (candidate, _))| (candidate == name).then_some(*hash))
                .ok_or_else(|| unauthenticated("the named token is unknown or revoked"))?,
            _ => return Err(unavailable()),
        };
        self.capture_hash_under_publication(digest, required, execution)
    }

    /// The caller holds publication; bearer and named capture share this path.
    fn capture_hash_under_publication(
        self: &Arc<Self>,
        digest: [u8; 32],
        required: Scope,
        execution: kronik_core::authority::AuthLease,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let state = self.metadata();
        if !matches!(&*state, MetadataState::Native | MetadataState::Ready(_)) {
            return Err(unavailable());
        }
        let live = self.live();
        let (name, scopes) = live
            .get(&digest)
            .ok_or_else(|| unauthenticated("the bearer token is unknown or revoked"))?;
        let caller = Caller {
            token_id: token_id(name),
            scopes: scopes.clone(),
        };
        caller.require(required)?;
        let expected = match &*state {
            MetadataState::Native => None,
            MetadataState::Ready(source) => {
                let row = source.tokens.get(name).ok_or_else(unavailable)?;
                source.require_fleet(row)?;
                Some(source.expected(Some(row)))
            }
            _ => return Err(unavailable()),
        };
        let principal = expected.map(|expected| ForwardedPrincipal::Bearer {
            hash: digest,
            expected,
        });
        let authority = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity: TokenIdentity::Hash(digest),
            required,
            expected,
            peer: None,
        });
        Ok(crate::CapturedRequest {
            caller,
            authority,
            principal,
            verified_identity: None,
            session: None,
        })
    }

    pub(super) fn capture_local(
        self: &Arc<Self>,
        req: &ApiRequest,
        required: Scope,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let uid = crate::auth::local_uid(req)?;
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        let (expected, principal) = match &*self.metadata() {
            MetadataState::Native => (None, None),
            MetadataState::Ready(source) => {
                let expected = source.expected(None);
                (
                    Some(expected),
                    Some(ForwardedPrincipal::Local {
                        owner_member: source.owner_member,
                        uid,
                        expected,
                    }),
                )
            }
            _ => return Err(unavailable()),
        };
        let caller = Caller::local(format!("unix:uid={uid}"));
        let authority: AuthLease = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity: TokenIdentity::Local,
            required,
            expected,
            peer: None,
        });
        Ok(crate::CapturedRequest {
            caller,
            authority,
            principal,
            verified_identity: None,
            session: None,
        })
    }

    /// Native browser capture retains its original sticky session lease.
    /// A member without its real session-proof provider is explicitly unavailable.
    pub(crate) fn capture_oidc(
        self: &Arc<Self>,
        required: Scope,
        original_session: kronik_core::authority::SessionLease,
        clock: Arc<dyn kronik_core::env::Clock>,
        verified_identity: Option<Arc<kronik_proto::log::v1::Sealable>>,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        original_session.check()?;
        let revocation = original_session.revocation();
        kronik_proto::control::validate_auth_session_revoked(revocation)
            .map_err(|_| unauthenticated("the original browser session binding is invalid"))?;
        if revocation.expires_at_ms <= clock.wall_ms() {
            return Err(unauthenticated("the original browser session expired"));
        }
        let state = self.metadata();
        match &*state {
            MetadataState::Native
                if matches!(
                    revocation.config_source,
                    Some(kronik_proto::log::v1::auth_session_revoked::ConfigSource::NativeLsn(_))
                ) => {}
            _ => return Err(unavailable()),
        }
        let live = self.live();
        let (digest, (_, scopes)) = live
            .iter()
            .find(|(_, (token, _))| token == &revocation.token_name)
            .ok_or_else(|| unauthenticated("the browser token binding is revoked"))?;
        let principal_hash: &[u8; 32] = revocation
            .principal_hash
            .as_slice()
            .try_into()
            .map_err(|_| unauthenticated("the original browser principal binding is invalid"))?;
        let audit_id = format!("oidc:{}", kronik_core::ids::hex(principal_hash));
        if verified_identity.as_ref().is_some_and(|value| {
            value.subject.as_deref() != Some(audit_id.as_str())
                || !matches!(
                    value.value,
                    Some(kronik_proto::log::v1::sealable::Value::Sealed(_))
                )
        }) {
            return Err(unauthenticated(
                "the original verified identity protection is invalid",
            ));
        }
        let caller = Caller {
            token_id: audit_id,
            scopes: scopes.clone(),
        };
        caller.require(required)?;
        let ordinary: AuthLease = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity: TokenIdentity::Hash(*digest),
            required,
            expected: None,
            peer: None,
        });
        let session = kronik_core::authority::guard_session(original_session, ordinary);
        let authority: AuthLease = session.clone();
        Ok(crate::CapturedRequest {
            caller,
            authority,
            principal: None,
            verified_identity,
            session: Some(session),
        })
    }

    pub fn resolve_forwarded(
        self: &Arc<Self>,
        proof: &ForwardedPrincipal,
        required: Scope,
        peer_owner: u64,
        peer: AuthLease,
    ) -> Result<crate::CapturedRequest, ApiError> {
        peer.check()?;
        if peer_owner == 0 {
            return Err(unauthenticated(
                "the forwarding peer is not a registered owner",
            ));
        }
        let _publication = self.publication();
        let execution = self.capture_execution()?;
        let state = self.metadata();
        let MetadataState::Ready(source) = &*state else {
            return Err(unavailable());
        };
        let (caller, identity, expected) = match proof {
            ForwardedPrincipal::Bearer { hash, expected } => {
                let live = self.live();
                let (name, _) = live
                    .get(hash)
                    .ok_or_else(|| unauthenticated("the forwarded token is revoked or unknown"))?;
                let row = source.tokens.get(name).ok_or_else(unavailable)?;
                if !source.matches(*expected, Some(row)) {
                    return Err(unauthenticated("the forwarded token authority changed"));
                }
                source.require_fleet(row)?;
                (
                    Caller {
                        token_id: row.meta.token_id(),
                        scopes: row.meta.scopes.clone(),
                    },
                    TokenIdentity::Hash(*hash),
                    *expected,
                )
            }
            ForwardedPrincipal::Local {
                owner_member,
                uid,
                expected,
            } => {
                if *owner_member != peer_owner || !source.matches(*expected, None) {
                    return Err(unauthenticated(
                        "the forwarded local owner authority changed",
                    ));
                }
                (
                    Caller::local(format!("unix:uid={uid}")),
                    TokenIdentity::Local,
                    *expected,
                )
            }
        };
        caller.require(required)?;
        let authority: AuthLease = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity,
            required,
            expected: Some(expected),
            peer: Some(peer),
        });
        Ok(crate::CapturedRequest {
            caller,
            authority,
            principal: Some(proof.clone()),
            verified_identity: None,
            session: None,
        })
    }
}
