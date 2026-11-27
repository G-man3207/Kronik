//! Host-side cryptography with secret values that never enter guest memory.

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&key, data).as_ref().to_vec()
}

/// An Ed25519 signature of `data` with the 32-byte seed in `secret` (raw, or
/// 64 hex characters). The decoded seed is wiped on drop.
pub fn sign_ed25519(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use ed25519_dalek::Signer as _;
    // Decode into the buffer that is wiped, instead of a `[u8; 32]` that is
    // copied out of the match and left on the stack.
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    match secret.len() {
        32 => seed.copy_from_slice(secret),
        64 | 65 => {
            let t = std::str::from_utf8(secret)
                .map_err(|_| "the key is not hex")?
                .trim();
            for (i, b) in seed.iter_mut().enumerate() {
                *b = u8::from_str_radix(t.get(2 * i..2 * i + 2).ok_or("the key is not hex")?, 16)
                    .map_err(|_| "the key is not hex")?;
            }
        }
        _ => return Err("an ed25519 key must be a 32-byte seed (raw or 64 hex characters)".into()),
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(key.sign(data).to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex = kronik_core::ids::hex(&mac);
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn ed25519_rfc8032_test_1() {
        let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let sig = sign_ed25519(seed.as_bytes(), b"").unwrap();
        let hex = kronik_core::ids::hex(&sig);
        // RFC 8032 §7.1 test 1, the full 64-byte signature.
        assert_eq!(
            hex,
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        // The same seed as raw 32 bytes, and as 65 characters with the trim
        // the decoder allows, must produce that signature too.
        let raw = kronik_core::ids::unhex(seed).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(
            kronik_core::ids::hex(&sign_ed25519(&raw, b"").unwrap()),
            hex
        );
        let padded = format!("\n{seed}");
        assert_eq!(padded.len(), 65);
        assert_eq!(
            kronik_core::ids::hex(&sign_ed25519(padded.as_bytes(), b"").unwrap()),
            hex
        );
        assert!(sign_ed25519(b"short", b"").is_err());
    }
}
