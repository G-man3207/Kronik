//! Preparation and fixed-holder sealing for an already-admitted fresh source.
use super::*;
use crate::keystore::PreparedSubjectKey;

impl Sealer {
    /// Select and retain the actual key under the existing erasure-floor CAS.
    /// The floor is a local CAS expectation, not caller-supplied source proof.
    /// Native OIDC calls this only for its original newly verified assertion;
    /// this does not authorize historical or unknown plaintext after erasure.
    pub fn prepare_plain_source_holder(
        &self,
        subject: &str,
        expected_erasure_floor: Option<u32>,
        fill: Fill<'_>,
        wall_ms: u64,
    ) -> Result<PreparedSubjectKey, PrivacyError> {
        if !crate::keystore::valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let ks = self.keystore.as_ref().ok_or_else(|| {
            PrivacyError::Decrypt("source key preparation needs a keystore".into())
        })?;
        let key =
            self.load_sealing_key(ks, subject, fill, wall_ms, Some(expected_erasure_floor))?;
        PreparedSubjectKey::new(ks, subject, key, expected_erasure_floor)
    }

    /// Seal with the actual retained key even with privacy off, and retain the
    /// SAME local read guard through the caller's synchronous publication.
    /// `publish` may enter its original authority fence once for a bounded
    /// insertion/enqueue. It must release publication before returning and must
    /// not reenter this store, wait or perform I/O under that fence.
    pub fn seal_value_with_prepared<T>(
        &self,
        mut value: pb::Sealable,
        prepared: &PreparedSubjectKey,
        fill: Fill<'_>,
        publish: impl FnOnce(pb::Sealable) -> T,
    ) -> Result<T, PrivacyError> {
        let Some(pb::sealable::Value::Plain(plain)) = value.value.take() else {
            return Err(PrivacyError::Decrypt(
                "prepared sealing requires tagged plaintext".into(),
            ));
        };
        let plain = Zeroizing::new(plain);
        if value.subject.as_deref() != Some(prepared.subject()) {
            return Err(PrivacyError::Decrypt(
                "prepared sealing requires its own tagged plaintext".into(),
            ));
        }
        let ks = self.keystore.as_ref().ok_or_else(|| {
            PrivacyError::Decrypt("prepared sealing needs its physical keystore".into())
        })?;
        ks.with_current_prepared(prepared, || {
            let mut nonce = [0_u8; 24];
            fill(&mut nonce);
            let sealed = prepared.seal(nonce, &plain)?;
            value.value = Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: sealed.key_version,
                nonce: sealed.nonce.to_vec(),
                ciphertext: sealed.ciphertext,
            }));
            Ok(publish(value))
        })?
    }
}
