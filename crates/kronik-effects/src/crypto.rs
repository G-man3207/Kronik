//! Host-side cryptography with secret values that never enter guest memory.

use hmac::{KeyInit, Mac};

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length.
    let mut mac = match hmac::Hmac::<sha2::Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// An Ed25519 signature of `data` with the 32-byte seed in `secret` (raw, or
/// 64 hex characters).
pub fn sign_ed25519(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use ed25519_dalek::Signer as _;
    let seed: [u8; 32] = match secret.len() {
        32 => secret.try_into().map_err(|_| "bad key")?,
        64 | 65 => {
            let t = std::str::from_utf8(secret)
                .map_err(|_| "the key is not hex")?
                .trim();
            let mut s = [0u8; 32];
            for (i, b) in s.iter_mut().enumerate() {
                *b = u8::from_str_radix(t.get(2 * i..2 * i + 2).ok_or("the key is not hex")?, 16)
                    .map_err(|_| "the key is not hex")?;
            }
            s
        }
        _ => return Err("an ed25519 key must be a 32-byte seed (raw or 64 hex characters)".into()),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(key.sign(data).to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn ed25519_rfc8032_test_1() {
        let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let sig = sign_ed25519(seed.as_bytes(), b"").unwrap();
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            hex.starts_with("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
        );
        assert!(sign_ed25519(b"short", b"").is_err());
    }
}
