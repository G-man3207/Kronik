//! Fixed key assignments retain their original authority; a plan cannot mint keys.
use kronik_core::authority::{AuthLease, SessionLease};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_privacy::keystore::PreparedSubjectKey;
use std::sync::Arc;

/// Only canonical scheduler adapters construct fixed assignments from actual
/// accepted key state. The sealer receives data, never a minting capability.
pub struct SubjectKeyPlan {
    authority: AuthLease,
    native: (Arc<PreparedSubjectKey>, SessionLease),
}

impl SubjectKeyPlan {
    pub(crate) fn new_native(
        prepared: Arc<PreparedSubjectKey>,
        original: SessionLease,
        authority: AuthLease,
    ) -> Self {
        Self {
            authority,
            native: (prepared, original),
        }
    }

    pub(crate) fn into_native(
        self,
        original: &SessionLease,
    ) -> Result<(Arc<PreparedSubjectKey>, AuthLease), ApiError> {
        let (prepared, bound) = self.native;
        if !Arc::ptr_eq(&bound, original) {
            return Err(ApiError::new(
                ErrorCode::Unauthenticated,
                "the identity plan belongs to another original session",
            ));
        }
        original.check()?;
        self.authority.check()?;
        Ok((prepared, self.authority))
    }
}
