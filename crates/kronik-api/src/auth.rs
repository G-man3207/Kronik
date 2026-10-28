//! Caller identity and scopes. Every request is resolved to a [`Caller`] by
//! the [`Authenticator`] and checked against [`required_scope`] before it
//! is routed. [`crate::tokens::TokenAuthenticator`] (M5) resolves bearer
//! tokens; without a token, the local socket's caller has every scope.

use std::collections::BTreeSet;

use kronik_core::error::{ApiError, ErrorCode};

use crate::ApiRequest;

/// A token scope (brief: tokens and scopes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Read,
    Fork,
    Propose,
    Approve,
    Promote,
    /// Grants, limits, secrets, foreign actors, privacy, messages and
    /// resends on main.
    Operate,
    PiiRead,
    /// Implies every other scope.
    Admin,
}

impl Scope {
    pub const ALL: [Scope; 8] = [
        Scope::Read,
        Scope::Fork,
        Scope::Propose,
        Scope::Approve,
        Scope::Promote,
        Scope::Operate,
        Scope::PiiRead,
        Scope::Admin,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Fork => "fork",
            Scope::Propose => "propose",
            Scope::Approve => "approve",
            Scope::Promote => "promote",
            Scope::Operate => "operate",
            Scope::PiiRead => "pii:read",
            Scope::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// Who is calling, as recorded in `Audit.token_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub token_id: String,
    pub scopes: BTreeSet<Scope>,
}

impl Caller {
    /// A caller with every scope: the local socket without a token.
    pub fn local(token_id: impl Into<String>) -> Caller {
        Caller {
            token_id: token_id.into(),
            scopes: Scope::ALL.into_iter().collect(),
        }
    }

    pub fn has(&self, s: Scope) -> bool {
        self.scopes.contains(&s) || self.scopes.contains(&Scope::Admin)
    }

    /// `SCOPE_MISSING` unless the caller has `s`.
    pub fn require(&self, s: Scope) -> Result<(), ApiError> {
        if self.has(s) {
            return Ok(());
        }
        Err(ApiError::new(
            ErrorCode::ScopeMissing,
            format!("token {} lacks scope {}", self.token_id, s.as_str()),
        )
        .with_hint(format!(
            "Use a token with the {0} scope; an operator creates one with \
             `kronik token create --name <name> --scopes {0} --reason \"...\"`.",
            s.as_str()
        )))
    }
}

/// Resolves a request's credentials to a caller.
pub trait Authenticator: Send + Sync {
    fn caller(&self, req: &ApiRequest) -> Result<Caller, ApiError>;
}

/// The local socket: file permissions decide who connects, and that caller
/// has every scope.
pub struct LocalAuthenticator;

impl Authenticator for LocalAuthenticator {
    fn caller(&self, req: &ApiRequest) -> Result<Caller, ApiError> {
        Ok(Caller::local(req.token_id.clone()))
    }
}

/// The scope a request needs (decoded path segments without the leading
/// empty one, e.g. `["v1", "forks"]`).
pub fn required_scope(method: &str, segs: &[&str]) -> Scope {
    match (method, segs) {
        ("POST", ["v1", "policy", "test"]) => Scope::Read,
        // Tokens are credentials: listing them is not reading the system.
        (_, ["v1", "tokens", ..]) => Scope::Admin,
        ("GET" | "HEAD", ["v1", "foreign", _, "logs"]) => Scope::Operate,
        ("GET" | "HEAD", _) => Scope::Read,
        ("PUT", ["v1", "policy"]) => Scope::Admin,
        ("POST", ["v1", "forks", ..]) | ("DELETE", ["v1", "forks", ..]) => Scope::Fork,
        // A preview is a fork with a proposal's code: it changes nothing on
        // main, and its requests never leave it (I7).
        ("POST", ["v1", "previews"]) | ("DELETE", ["v1", "previews", _]) => Scope::Fork,
        ("POST", ["v1", "proposals"]) => Scope::Propose,
        ("POST", ["v1", "proposals", _, "request-approval"]) => Scope::Propose,
        ("POST", ["v1", "proposals", _, "approve"]) => Scope::Approve,
        ("POST", ["v1", "proposals", _, "promote"]) => Scope::Promote,
        ("POST", ["v1", "deployments"]) => Scope::Promote,
        ("POST", ["v1", "deployments", _, "rollback"]) => Scope::Promote,
        ("POST", ["v1", "deployments", _, "watch"]) => Scope::Promote,
        // Stopping a watch gives up its rollback: as much as starting one.
        ("POST", ["v1", "watches", _, "stop"]) => Scope::Promote,
        // Grants, limits, secrets, messages and resends on main.
        _ => Scope::Operate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_and_routes() {
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
        }
        let agent = Caller {
            token_id: "agent-1".into(),
            scopes: [Scope::Read, Scope::Fork, Scope::Propose]
                .into_iter()
                .collect(),
        };
        let need = |m, p: &str| {
            let segs: Vec<&str> = p.split('/').skip(1).collect();
            required_scope(m, &segs)
        };
        assert!(agent.has(need("GET", "/v1/actors")));
        assert!(agent.has(need("POST", "/v1/forks/f-1/replay")));
        assert!(agent.has(need("POST", "/v1/proposals")));
        assert!(!agent.has(need("POST", "/v1/proposals/p-1/approve")));
        assert!(!agent.has(need("POST", "/v1/proposals/p-1/promote")));
        assert_eq!(need("POST", "/v1/watches/w-1/stop"), Scope::Promote);
        assert!(!agent.has(need("POST", "/v1/grants")));
        assert!(!agent.has(need("PUT", "/v1/policy")));
        assert!(agent.has(need("POST", "/v1/proposals/p-1/request-approval")));
        assert!(agent.has(need("GET", "/v1/turns/main:3/trace")));
        assert_eq!(need("GET", "/v1/tokens"), Scope::Admin);
        assert_eq!(need("POST", "/v1/tokens"), Scope::Admin);
        assert_eq!(need("POST", "/v1/tokens/agent-1/revoke"), Scope::Admin);
        assert_eq!(need("GET", "/v1/foreign/pdf/logs"), Scope::Operate);
        assert_eq!(
            need("POST", "/v1/actors/counter/a/messages"),
            Scope::Operate
        );
        assert_eq!(
            agent.require(Scope::Promote).unwrap_err().code,
            ErrorCode::ScopeMissing
        );
        assert!(Caller::local("unix:uid=0").has(Scope::Admin));
    }
}
