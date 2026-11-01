//! The retained encrypted store implements the same immutable backend contract.
use std::sync::Arc;

use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Env};
use zeroize::Zeroizing;

use super::{BackendError, Fetched, SecretBackend, VersionPage};
use crate::{PrivacyError, SecretStore, SecretValue, valid_name};

pub struct FileBackend {
    env: Env,
    store: Arc<SecretStore>,
}
impl FileBackend {
    pub fn new(env: Env, store: Arc<SecretStore>) -> Self {
        Self { env, store }
    }
}
fn error(error: PrivacyError) -> BackendError {
    match error {
        PrivacyError::Decrypt(_) => BackendError::VersionGone,
        PrivacyError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            BackendError::Denied
        }
        PrivacyError::Io { .. } => BackendError::Unavailable,
        PrivacyError::Sqlite(rusqlite::Error::SqliteFailure(code, _)) => match code.code {
            rusqlite::ErrorCode::PermissionDenied
            | rusqlite::ErrorCode::AuthorizationForStatementDenied => BackendError::Denied,
            rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                BackendError::Invalid
            }
            _ => BackendError::Unavailable,
        },
        _ => BackendError::Invalid,
    }
}
fn fetched(path: String, value: SecretValue) -> Fetched {
    Fetched {
        value: Zeroizing::new(value.value),
        source_version: value.meta.version.to_string(),
        canonical_ref: path,
    }
}
fn version(id: &str) -> Result<u64, BackendError> {
    let version: u64 = id.parse().map_err(|_| BackendError::Invalid)?;
    if version == 0
        || version > kronik_proto::secret::MAX_SECRET_VERSION
        || id.starts_with('0')
        || !id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BackendError::Invalid);
    }
    Ok(version)
}

/// Projects physical FILE claims without allocating a logical ledger version.
pub fn source_highwater(
    name: &str,
    rows: &[kronik_proto::log::v1::SecretVersion],
    floor: Option<crate::SecretDeletionFloor>,
) -> Result<u64, BackendError> {
    let mut high = floor.map_or(0, |floor| floor.through_version);
    for row in rows
        .iter()
        .filter(|row| row.name == name && row.backend == "file")
    {
        high = high.max(version(&row.source_version)?);
    }
    if high > kronik_proto::secret::MAX_SECRET_VERSION {
        return Err(BackendError::Invalid);
    }
    Ok(high)
}
impl SecretBackend for FileBackend {
    fn current<'a>(
        &'a self,
        path: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move {
            original.check().map_err(|_| BackendError::Unauthorized)?;
            if !valid_name(path) {
                return Err(BackendError::Invalid);
            }
            let store = self.store.clone();
            let path = path.to_owned();
            let result = self
                .env
                .blocking("secret-current", move || {
                    store
                        .current(&path)
                        .map_err(error)?
                        .map(|value| fetched(path, value))
                        .ok_or(BackendError::NotFound)
                })
                .await
                .ok_or(BackendError::Unavailable)?;
            original.check().map_err(|_| BackendError::Unauthorized)?;
            result
        })
    }
    fn version<'a>(
        &'a self,
        path: &'a str,
        id: &'a str,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<Fetched, BackendError>> {
        Box::pin(async move {
            original.check().map_err(|_| BackendError::Unauthorized)?;
            if !valid_name(path) {
                return Err(BackendError::Invalid);
            }
            let version = version(id)?;
            let store = self.store.clone();
            let path = path.to_owned();
            let result = self
                .env
                .blocking("secret-version", move || {
                    store
                        .version(&path, version)
                        .map_err(error)?
                        .map(|value| fetched(path, value))
                        .ok_or(BackendError::VersionGone)
                })
                .await
                .ok_or(BackendError::Unavailable)?;
            original.check().map_err(|_| BackendError::Unauthorized)?;
            result
        })
    }
    fn versions<'a>(
        &'a self,
        path: &'a str,
        cursor: Option<&'a str>,
        original: AuthLease,
    ) -> BoxFuture<'a, Result<VersionPage, BackendError>> {
        Box::pin(async move {
            original.check().map_err(|_| BackendError::Unauthorized)?;
            if !valid_name(path) {
                return Err(BackendError::Invalid);
            }
            let after = cursor.map(version).transpose()?.unwrap_or(0);
            let store = self.store.clone();
            let path = path.to_owned();
            let result = self
                .env
                .blocking("secret-versions", move || {
                    let page = store
                        .metadata_page(Some((&path, after)), false)
                        .map_err(error)?;
                    let full = page.len() == 256;
                    let same_name = page.iter().all(|row| row.meta.name == path);
                    let ids: Vec<String> = page
                        .into_iter()
                        .take_while(|row| row.meta.name == path)
                        .map(|row| row.meta.version.to_string())
                        .collect();
                    let next = if full && same_name {
                        ids.last().cloned()
                    } else {
                        None
                    };
                    Ok(VersionPage {
                        canonical_ref: path,
                        ids,
                        next,
                    })
                })
                .await
                .ok_or(BackendError::Unavailable)?;
            original.check().map_err(|_| BackendError::Unauthorized)?;
            result
        })
    }
}
