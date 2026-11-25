//! What the `media` test guest writes, for the blob tests.

#![allow(dead_code)]

/// The bytes the media guest's `write` and `put` produce for a blob of `n`
/// bytes.
pub fn pattern(n: u64) -> Vec<u8> {
    (0..n)
        .map(|i| ((i.wrapping_mul(31) + 7) % 251) as u8)
        .collect()
}

/// The identity of a blob without a subject: `b3:` and its BLAKE3.
pub fn hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

/// What the media guest's `sum` and `held-sum` answer for `size` bytes of
/// the pattern: the size and its FNV-1a 64 digest.
pub fn pattern_sum(size: u64) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in pattern(size) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{size} {h:016x}")
}
