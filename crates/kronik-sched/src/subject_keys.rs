//! Fixed key assignments retain their original authority; a plan cannot mint keys.
use kronik_core::authority::{AuthLease, SessionLease};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_privacy::keystore::PreparedSubjectKey;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Only canonical scheduler adapters construct fixed assignments from actual
/// accepted key state. The sealer receives data, never a minting capability.
pub struct SubjectKeyPlan {
    // Unused while subject keys ride the M23 track; the plan keeps the
    // parsed mapping for when it lands.
    #[allow(dead_code)]
    versions: BTreeMap<String, u32>,
    authority: AuthLease,
    native: Option<(Arc<PreparedSubjectKey>, SessionLease)>,
}

impl SubjectKeyPlan {
    #[allow(dead_code)]
    pub(crate) fn new(versions: BTreeMap<String, u32>, authority: AuthLease) -> Self {
        Self {
            versions,
            authority,
            native: None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts(self) -> Result<(BTreeMap<String, u32>, AuthLease), ApiError> {
        if self.native.is_some() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "a native identity plan requires its original prepared-key consumer",
            ));
        }
        Ok((self.versions, self.authority))
    }

    pub(crate) fn new_native(
        prepared: Arc<PreparedSubjectKey>,
        original: SessionLease,
        authority: AuthLease,
    ) -> Self {
        let versions = BTreeMap::new();
        Self {
            versions,
            authority,
            native: Some((prepared, original)),
        }
    }

    pub(crate) fn into_native(
        self,
        original: &SessionLease,
    ) -> Result<(Arc<PreparedSubjectKey>, AuthLease), ApiError> {
        let (prepared, bound) = self.native.ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "this identity plan has no native prepared-key binding",
            )
        })?;
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
