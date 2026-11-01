//! Secret values and immutable provider versions. Endpoints and credentials are
//! selected by trusted node configuration, never by retained version metadata.
pub mod config;
pub mod file;

use std::collections::BTreeMap;

use kronik_core::authority::AuthLease;
use kronik_core::env::BoxFuture;
use zeroize::Zeroizing;

use crate::{MasterKey, PrivacyError, key_memory::ProtectedKey};

/// Safe categories retain revocation semantics without retaining provider bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    #[error("the secret backend is unavailable")]
    Unavailable,
    #[error("the secret was not found")]
    NotFound,
    #[error("the immutable secret version is no longer available")]
    VersionGone,
    #[error("the secret backend denied access")]
    Denied,
    #[error("the secret backend returned an invalid identity or value")]
    Invalid,
}

pub struct Fetched {
    pub value: Zeroizing<Vec<u8>>,
    pub source_version: String,
    pub canonical_ref: String,
}
impl std::fmt::Debug for Fetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetched")
            .field("source_version", &self.source_version)
            .field("canonical_ref", &self.canonical_ref)
            .field("value", &"[redacted]")
            .finish()
    }
}

#[derive(Debug)]
pub struct VersionPage {
    pub canonical_ref: String,
    pub ids: Vec<String>,
    pub next: Option<String>,
}

/// List every retained version by following pages; a truncated catalogue is not
/// complete. A turn may initiate provider I/O only after its durable TurnBegin.
/// Every operation carries its original caller/boot lease through credential
/// renewal and final HTTP enqueue; backends never capture a replacement scope.
pub trait SecretBackend: Send + Sync + 'static {
    fn current<'a>(&'a self, path: &'a str, original: AuthLease) -> BoxFuture<'a, Result<Fetched, BackendError>>;
    fn version<'a>(
        &'a self,
        path: &'a str,
        id: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>>;
    fn versions<'a>(
        &'a self,
        path: &'a str,
        cursor: Option<&'a str>,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<VersionPage, BackendError>>;
}

/// One startup snapshot shared by configured environment backends. Old values
/// are not written to disk: a changed or missing old identity is VersionGone.
pub struct EnvBackend {
    values: BTreeMap<String, Zeroizing<Vec<u8>>>,
    hash_key: ProtectedKey,
}
impl EnvBackend {
    pub fn new(
        values: BTreeMap<String, Zeroizing<Vec<u8>>>,
        master: &MasterKey,
    ) -> Result<Self, PrivacyError> {
        Ok(Self {
            values,
            hash_key: master.derive("kronik env secret v1")?,
        })
    }

    fn identity(&self, path: &str, value: &[u8]) -> String {
        let mut hash = Zeroizing::new(blake3::Hasher::new_keyed(self.hash_key.bytes()));
        hash.update(path.as_bytes());
        hash.update(b"\0");
        hash.update(value);
        format!("k:{}", &hash.finalize().to_hex().as_str()[..16])
    }

    fn fetched(&self, path: &str) -> Result<Fetched, BackendError> {
        let value = self.values.get(path).ok_or(BackendError::NotFound)?;
        Ok(Fetched {
            value: Zeroizing::new(value.to_vec()),
            source_version: self.identity(path, value),
            canonical_ref: path.to_owned(),
        })
    }
}
impl SecretBackend for EnvBackend {
    fn current<'a>(&'a self, path: &'a str, original: AuthLease) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move { original.check().map_err(|_| BackendError::Denied)?; self.fetched(path) })
    }

    fn version<'a>(
        &'a self,
        path: &'a str,
        id: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move {
            original.check().map_err(|_| BackendError::Denied)?;
            let value = self.values.get(path).ok_or(BackendError::VersionGone)?;
            if self.identity(path, value) != id {
                return Err(BackendError::VersionGone);
            }
            Ok(Fetched {
                value: Zeroizing::new(value.to_vec()),
                source_version: id.to_owned(),
                canonical_ref: path.to_owned(),
            })
        })
    }

    fn versions<'a>(
        &'a self,
        path: &'a str,
        cursor: Option<&'a str>,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<VersionPage, BackendError>> {
        Box::pin(async move {
            original.check().map_err(|_| BackendError::Denied)?;
            if cursor.is_some() {
                return Err(BackendError::Invalid);
            }
            let value = self.values.get(path).ok_or(BackendError::NotFound)?;
            Ok(VersionPage {
                canonical_ref: path.to_owned(),
                ids: vec![self.identity(path, value)],
                next: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_source::providers::test_authority;

    #[tokio::test]
    async fn environment_rotation_never_substitutes_current_for_a_retained_identity() {
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let snapshot = |bytes: &[u8]| {
            EnvBackend::new(
                BTreeMap::from([("SERVICE_TOKEN".into(), Zeroizing::new(bytes.to_vec()))]),
                &master,
            )
            .unwrap()
        };
        let old = snapshot(b"old-environment-secret");
        let original = test_authority();
        let old_id = old.current("SERVICE_TOKEN", original.clone()).await.unwrap().source_version;
        let changed = snapshot(b"new-environment-secret");
        assert!(matches!(
            changed.version("SERVICE_TOKEN", &old_id, original.clone()).await,
            Err(BackendError::VersionGone)
        ));
        let missing = EnvBackend::new(BTreeMap::new(), &master).unwrap();
        assert!(matches!(
            missing.version("SERVICE_TOKEN", &old_id, original.clone()).await,
            Err(BackendError::VersionGone)
        ));
        let other = EnvBackend::new(
            BTreeMap::from([(
                "OTHER_TOKEN".into(),
                Zeroizing::new(b"old-environment-secret".to_vec()),
            )]),
            &master,
        )
        .unwrap();
        assert!(matches!(
            other.version("OTHER_TOKEN", &old_id, original).await,
            Err(BackendError::VersionGone)
        ));
    }
}
