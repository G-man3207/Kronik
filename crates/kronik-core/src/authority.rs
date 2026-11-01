//! Ephemeral ordinary request authority. Never serialized into history or upgraded
//! to a newer principal/configuration epoch while an operation is queued.

use std::sync::Arc;

use crate::env::BoxFuture;
use crate::error::ApiError;

/// A revocable capability for one ordinary, already-authenticated operation.
///
/// The issuer captures the exact principal, required scope and configuration
/// epoch. `admit` checks them and calls `effect` exactly once under the SAME
/// synchronous fence used to publish revocation. The callback only enqueues the
/// final mutation; it must not wait, perform I/O or acquire another auth fence.
/// Already-admitted effects can finish after revocation; they are not undone.
pub trait Authority: Send + Sync {
    fn check(&self) -> Result<(), ApiError>;
    fn cancelled(&self) -> BoxFuture<'static, ()>;
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError>;
}

pub type AuthLease = Arc<dyn Authority>;

/// An original verified-session capability for login and self-only session history.
/// Ordinary bearer and Unix authorities cannot supply arbitrary session operations.
pub trait SessionAuthority: Authority {
    fn revocation(&self) -> &kronik_proto::log::v1::AuthSessionRevoked;
}
pub type SessionLease = Arc<dyn SessionAuthority>;

/// Retain every original request guard without entering a second auth fence.
pub fn guard_session(session: SessionLease, authority: AuthLease) -> SessionLease {
    Arc::new(GuardedSession { session, authority })
}
struct GuardedSession {
    session: SessionLease,
    authority: AuthLease,
}
impl Authority for GuardedSession {
    fn check(&self) -> Result<(), ApiError> {
        self.authority.check()?;
        self.session.check()
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let (authority, session) = (self.authority.clone(), self.session.clone());
        Box::pin(async move {
            tokio::select! {
                biased;
                () = authority.cancelled() => {},
                () = session.cancelled() => {},
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        self.authority.admit(&mut || {
            self.session.check()?;
            effect()
        })
    }
}
impl SessionAuthority for GuardedSession {
    fn revocation(&self) -> &kronik_proto::log::v1::AuthSessionRevoked {
        self.session.revocation()
    }
}
