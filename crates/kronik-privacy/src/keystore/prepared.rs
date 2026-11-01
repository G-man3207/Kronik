//! Fixed local data-key custody; neither a source receipt nor an authorization grant.
use super::*;
use std::sync::{Arc, Weak};

#[cfg(test)]
mod tests;

/// A real selected key, kept zeroizing and bound to its original physical store.
/// Only the sealer's admitted preparation path can construct this holder.
pub struct PreparedSubjectKey {
    store: Weak<Keystore>,
    subject: String,
    key: SubjectKey,
    erasure_floor: Option<u32>,
    envelope: WrappedSubjectKey,
}

impl std::fmt::Debug for PreparedSubjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSubjectKey")
            .field("version", &self.key.version)
            .finish_non_exhaustive()
    }
}

impl PreparedSubjectKey {
    pub(crate) fn new(
        store: &Arc<Keystore>, subject: &str, key: SubjectKey, erasure_floor: Option<u32>,
    ) -> Result<Self, PrivacyError> {
        let unavailable = || PrivacyError::Decrypt("the prepared subject key is unavailable".into());
        let version = subject_key_version(key.version)?;
        let mut conn = store.checked_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        store.check_master(&tx)?;
        semantic_revision(&tx)?;
        let floor = Keystore::erased_through(&tx, subject)?;
        if floor != erasure_floor || floor.is_some_and(|floor| version <= floor) {
            return Err(unavailable());
        }
        let envelope = Keystore::wrapped_subject_key(&tx, subject, version)?.ok_or_else(unavailable)?;
        // The original CAS released its transaction before this capture. Verify
        // this exact envelope still contains the ACTUAL selected key, not a
        // different valid key installed under the same numeric version.
        let current = store.unwrap_key(subject, version, &envelope.nonce, &envelope.wrapped)?;
        let different = current.key.iter().zip(key.key.iter())
            .fold(0_u8, |different, (a, b)| different | (a ^ b));
        if different != 0 { return Err(unavailable()); }
        Ok(Self {
            store: Arc::downgrade(store), subject: subject.to_owned(), key, erasure_floor, envelope,
        })
    }

    pub fn subject(&self) -> &str { &self.subject }
    pub fn version(&self) -> u32 { self.key.version }

    pub(crate) fn seal(&self, nonce: [u8; 24], plain: &[u8]) -> Result<SealedValue, PrivacyError> {
        seal(&self.subject, &self.key, nonce, plain)
    }
}

impl Keystore {
    /// Authenticate the original holder under a read-only local critical section.
    /// Acquire this BEFORE an authority's publication fence. `action` must be
    /// synchronous and bounded, must not reenter this keystore, and must release
    /// publication before returning. No SQL runs inside `action` itself.
    pub fn with_current_prepared<T>(
        &self, prepared: &PreparedSubjectKey, action: impl FnOnce() -> T,
    ) -> Result<T, PrivacyError> {
        let unavailable = || PrivacyError::Decrypt("the prepared subject key is unavailable".into());
        let owner = prepared.store.upgrade().ok_or_else(unavailable)?;
        if !std::ptr::eq(self, owner.as_ref()) { return Err(unavailable()); }
        let version = subject_key_version(prepared.key.version)?;
        let mut conn = self.checked_conn()?;
        // The connection mutex alone does not exclude another SQLite handle.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        self.check_master(&tx)?;
        semantic_revision(&tx)?;
        let floor = Self::erased_through(&tx, &prepared.subject)?;
        if floor != prepared.erasure_floor || floor.is_some_and(|floor| version <= floor) {
            return Err(unavailable());
        }
        let row = Self::wrapped_subject_key(&tx, &prepared.subject, version)?
            .ok_or_else(unavailable)?;
        // This exact envelope was authenticated against the retained key at
        // preparation. Its identity includes nonce, wrapped bytes and timestamp.
        // Even a valid same-key rewrap cannot silently replace that identity.
        if row != prepared.envelope { return Err(unavailable()); }
        let result = action();
        // Dropping this read-only transaction rolls it back only AFTER action
        // has returned and its publication guard has been released.
        drop(tx);
        drop(conn);
        Ok(result)
    }
}
