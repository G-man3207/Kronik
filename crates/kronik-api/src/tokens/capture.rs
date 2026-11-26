//! Native token capture: the original identity and its live lease.
use super::*;
use kronik_core::authority::AuthLease;
use kronik_core::ids::SourcePos;

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

impl TokenStore {
    pub fn lookup(&self, name: &str) -> Result<Option<TokenMeta>, ApiError> {
        self.inner()
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM tokens WHERE name = ?1"),
                [name],
                meta,
            )
            .optional()
            .map_err(internal)
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
        let digest = self
            .live()
            .iter()
            .find_map(|(hash, (candidate, _))| (candidate == name).then_some(*hash))
            .ok_or_else(|| unauthenticated("the named token is unknown or revoked"))?;
        self.capture_hash_under_publication(digest, required, execution)
    }

    /// The caller holds publication; bearer and named capture share this path.
    fn capture_hash_under_publication(
        self: &Arc<Self>,
        digest: [u8; 32],
        required: Scope,
        execution: kronik_core::authority::AuthLease,
    ) -> Result<crate::CapturedRequest, ApiError> {
        let live = self.live();
        let (name, scopes) = live
            .get(&digest)
            .ok_or_else(|| unauthenticated("the bearer token is unknown or revoked"))?;
        let caller = Caller {
            token_id: token_id(name),
            scopes: scopes.clone(),
        };
        caller.require(required)?;
        let authority = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity: TokenIdentity::Hash(digest),
            required,
        });
        Ok(crate::CapturedRequest {
            caller,
            authority,
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
        let caller = Caller::local(format!("unix:uid={uid}"));
        let authority: AuthLease = Arc::new(TokenAuthority {
            store: self.clone(),
            execution,
            identity: TokenIdentity::Local,
            required,
        });
        Ok(crate::CapturedRequest {
            caller,
            authority,
            verified_identity: None,
            session: None,
        })
    }

    /// Native browser capture retains its original sticky session lease.
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
        if !matches!(
            revocation.config_source,
            Some(kronik_proto::log::v1::auth_session_revoked::ConfigSource::NativeLsn(_))
        ) {
            return Err(unauthenticated(
                "the original browser session has no native configuration source",
            ));
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
        let audit_id = crate::oidc::principal(principal_hash);
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
        });
        let session = kronik_core::authority::guard_session(original_session, ordinary);
        let authority: AuthLease = session.clone();
        Ok(crate::CapturedRequest {
            caller,
            authority,
            verified_identity,
            session: Some(session),
        })
    }
}
