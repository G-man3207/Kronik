//! jsonwebtoken owns JOSE parsing/validation; this provider only calls the
//! already-linked ring RS256 verifier. It cannot load keys or sign tokens.

use jsonwebtoken::crypto::{CryptoProvider, JwkUtils, JwtVerifier};
use jsonwebtoken::errors::{ErrorKind, Result};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::{Algorithm, DecodingKey, DecodingKeyKind};

struct RsaVerifier {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl signature::Verifier<Vec<u8>> for RsaVerifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> std::result::Result<(), signature::Error> {
        ring::signature::RsaPublicKeyComponents { n: &self.n, e: &self.e }
            .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
            .map_err(|_| signature::Error::new())
    }
}

impl JwtVerifier for RsaVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS256
    }
}

fn verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if *algorithm != Algorithm::RS256 {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    match key.kind() {
        DecodingKeyKind::RsaModulusExponent { n, e } => Ok(Box::new(RsaVerifier {
            n: n.clone(),
            e: e.clone(),
        })),
        _ => Err(ErrorKind::InvalidKeyFormat.into()),
    }
}

static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| Err(ErrorKind::InvalidAlgorithm.into()),
    verifier_factory: verifier,
    jwk_utils: JwkUtils {
        extract_rsa_public_key_components: |_| Err(ErrorKind::InvalidKeyFormat.into()),
        extract_ec_public_key_coordinates: |_, _| Err(ErrorKind::InvalidKeyFormat.into()),
        compute_digest: |data, algorithm| {
            let algorithm = match algorithm {
                ThumbprintHash::SHA256 => &ring::digest::SHA256,
                ThumbprintHash::SHA384 => &ring::digest::SHA384,
                ThumbprintHash::SHA512 => &ring::digest::SHA512,
            };
            ring::digest::digest(algorithm, data).as_ref().to_vec()
        },
    },
};

pub(super) fn install() {
    // Immutable algorithms only; issuer, JWKS and credentials stay per instance.
    let _ = PROVIDER.install_default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_has_no_signing_or_symmetric_verification() {
        assert!(verifier(&Algorithm::HS256, &DecodingKey::from_secret(b"untrusted")).is_err());
        assert!((PROVIDER.signer_factory)(
            &Algorithm::RS256,
            &jsonwebtoken::EncodingKey::from_secret(b"not-a-private-key")
        ).is_err());
        assert!(verifier(&Algorithm::RS256, &DecodingKey::from_rsa_raw_components(&[1], &[3]))
            .unwrap().verify(b"payload", &vec![0; 256]).is_err());
    }
}
