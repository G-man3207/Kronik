//! Shared local TLS leaf keys, extracted from M16 cluster identity.
//! Seeds come only from the caller's Env entropy; private keys never leave custody.

use rcgen::{CertificateParams, KeyPair};
use rustls_pki_types::PrivatePkcs8KeyDer;
use zeroize::Zeroizing;

use crate::env::EntropySource;

/// An Ed25519 key from a 32-byte seed (PKCS#8 v1).
pub fn ed25519_key(seed: &[u8; 32]) -> Result<KeyPair, rcgen::Error> {
    const PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = Zeroizing::new([0; 48]);
    der[..16].copy_from_slice(&PKCS8_PREFIX);
    der[16..].copy_from_slice(seed);
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(&der[..]), &rcgen::PKCS_ED25519)
}

/// A locally owned TLS leaf key. Persistence belongs to its caller's secure custody.
pub struct LeafKeys {
    key: KeyPair,
}

impl std::fmt::Debug for LeafKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeafKeys(..)")
    }
}

impl LeafKeys {
    pub fn generate(entropy: &dyn EntropySource) -> Result<LeafKeys, rcgen::Error> {
        let mut seed = Zeroizing::new([0; 32]);
        entropy.fill(&mut *seed);
        Ok(LeafKeys {
            key: ed25519_key(&seed)?,
        })
    }

    pub fn from_pem(key_pem: &str) -> Result<LeafKeys, rcgen::Error> {
        Ok(LeafKeys {
            key: KeyPair::from_pem(key_pem)?,
        })
    }

    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// PKCS#8.
    pub fn key_der(&self) -> Vec<u8> {
        self.key.serialize_der()
    }

    pub fn csr_der(&self) -> Result<Vec<u8>, rcgen::Error> {
        let params = CertificateParams::default();
        Ok(params.serialize_request(&self.key)?.der().to_vec())
    }
}
