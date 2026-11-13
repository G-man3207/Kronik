//! The blob file format, version 1 (ADR 0117 §2, amended 2026-11-13).
//!
//! A 512-byte header, then frames of [`FRAME_SIZE`] plaintext bytes each:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 8 | magic `KRNKBLOB` |
//! | 8 | 4 | format, `u32` = 1 |
//! | 12 | 4 | flags, `u32`: bit 0 sealed |
//! | 16 | 8 | size: plaintext bytes, `u64` |
//! | 24 | 4 | frame size, `u32` = 65 536 |
//! | 28 | 4 | key version, `u32` (0 without a subject) |
//! | 32 | 32 | identity digest |
//! | 64 | 32 | body digest: BLAKE3 of every byte after the header |
//! | 96 | 16 | nonce prefix (sealed, random per file; zero otherwise) |
//! | 112 | 2 | subject length, `u16`, at most 256 |
//! | 114 | 256 | subject, zero padded |
//! | 370 | 16 | header tag (sealed; zero otherwise) |
//! | 386 | 122 | reserved, zero |
//! | 508 | 4 | CRC32C of bytes 0 to 507 |
//!
//! Integers are little endian. Frame `i` holds plaintext bytes
//! `[i * 65536, min(size, (i + 1) * 65536))`:
//!
//! - **plain:** the bytes, then their CRC32C (4 bytes);
//! - **sealed:** XChaCha20-Poly1305, whose 24-byte nonce holds the file's
//!   16-byte nonce prefix followed by `u64_le(i)`, with associated data
//!   `"kronik blob v1" 0x00 subject 0x00 u32_le(key version) u64_le(i)
//!   u8(last)`: the ciphertext and its 16-byte tag. A sealed blob has at
//!   least one frame, so even an empty one authenticates its end.
//!
//! The header tag is the XChaCha20-Poly1305 tag of an empty message with
//! the header's bytes 0 to 369 as associated data and the nonce prefix
//! followed by `u64_le(u64::MAX)`, which no frame uses. It authenticates the
//! identity, size, body digest and nonce prefix: the identity is a hash of
//! all the plaintext, known only when the last frame is written, so it binds
//! the frames through the header rather than through each frame. A reader of
//! a sealed file checks the header tag before it trusts any header field.
//!
//! The file length is a function of the header ([`file_len`]), so a
//! truncated file is detected before a frame is read; a frame sealed as the
//! last one in another position, or a missing last frame, fails its tag.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// The magic at the start of every blob file.
pub const MAGIC: &[u8; 8] = b"KRNKBLOB";
/// The file format version this crate writes and reads.
pub const FORMAT_VERSION: u32 = 1;
/// Header bytes before the first frame.
pub const HEADER_LEN: usize = 512;
/// Plaintext bytes per frame.
pub const FRAME_SIZE: usize = 64 * 1024;
/// Bytes after each plain frame (its CRC32C).
pub const PLAIN_OVERHEAD: usize = 4;
/// Bytes after each sealed frame (its AEAD tag).
pub const SEALED_OVERHEAD: usize = 16;
/// The longest subject a header holds.
pub const MAX_SUBJECT: usize = 256;

const FLAG_SEALED: u32 = 1;
const FRAME_AD: &[u8] = b"kronik blob v1";
const SUBJECT_AT: usize = 114;
const TAG_AT: usize = 370;
const CRC_AT: usize = 508;
/// The frame index whose nonce the header tag uses.
const HEADER_NONCE_INDEX: u64 = u64::MAX;

/// A blob file's header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub sealed: bool,
    pub size: u64,
    pub key_version: u32,
    pub identity: [u8; 32],
    pub body_digest: [u8; 32],
    pub nonce_prefix: [u8; 16],
    pub subject: Option<String>,
    /// The header tag (sealed); zero otherwise.
    pub tag: [u8; 16],
}

/// Frames a blob of `size` plaintext bytes has on disk.
pub fn frame_count(size: u64, sealed: bool) -> u64 {
    let n = size.div_ceil(FRAME_SIZE as u64);
    if sealed { n.max(1) } else { n }
}

/// Bytes of overhead after each frame.
pub fn overhead(sealed: bool) -> usize {
    if sealed {
        SEALED_OVERHEAD
    } else {
        PLAIN_OVERHEAD
    }
}

/// The exact length of a blob file of `size` plaintext bytes.
pub fn file_len(size: u64, sealed: bool) -> u64 {
    HEADER_LEN as u64 + size + frame_count(size, sealed) * overhead(sealed) as u64
}

impl Header {
    pub fn frames(&self) -> u64 {
        frame_count(self.size, self.sealed)
    }

    pub fn overhead(&self) -> usize {
        overhead(self.sealed)
    }

    pub fn file_len(&self) -> u64 {
        file_len(self.size, self.sealed)
    }

    /// Where frame `i` starts in the file.
    pub fn frame_offset(&self, i: u64) -> u64 {
        HEADER_LEN as u64 + i * (FRAME_SIZE + self.overhead()) as u64
    }

    /// Plaintext bytes in frame `i`.
    pub fn frame_plain_len(&self, i: u64) -> usize {
        let start = i * FRAME_SIZE as u64;
        (self.size.saturating_sub(start)).min(FRAME_SIZE as u64) as usize
    }

    /// Bytes 0 to 369: what the header tag authenticates.
    fn authenticated(&self) -> [u8; TAG_AT] {
        let mut h = [0u8; TAG_AT];
        h[..8].copy_from_slice(MAGIC);
        h[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        let flags = if self.sealed { FLAG_SEALED } else { 0 };
        h[12..16].copy_from_slice(&flags.to_le_bytes());
        h[16..24].copy_from_slice(&self.size.to_le_bytes());
        h[24..28].copy_from_slice(&(FRAME_SIZE as u32).to_le_bytes());
        h[28..32].copy_from_slice(&self.key_version.to_le_bytes());
        h[32..64].copy_from_slice(&self.identity);
        h[64..96].copy_from_slice(&self.body_digest);
        h[96..112].copy_from_slice(&self.nonce_prefix);
        let subject = self.subject.as_deref().unwrap_or("").as_bytes();
        let len = subject.len().min(MAX_SUBJECT);
        h[112..114].copy_from_slice(&(len as u16).to_le_bytes());
        h[SUBJECT_AT..SUBJECT_AT + len].copy_from_slice(&subject[..len]);
        h
    }

    /// The 512 header bytes, with the tag as set and the CRC computed.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..TAG_AT].copy_from_slice(&self.authenticated());
        h[TAG_AT..TAG_AT + 16].copy_from_slice(&self.tag);
        let crc = crc32c::crc32c(&h[..CRC_AT]);
        h[CRC_AT..].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// Computes and sets the header tag under `key` (sealed headers).
    pub fn seal(&mut self, key: &[u8; 32]) -> Result<(), String> {
        let ad = self.authenticated();
        let tag = XChaCha20Poly1305::new(key.into())
            .encrypt(
                &nonce(&self.nonce_prefix, HEADER_NONCE_INDEX),
                Payload { msg: &[], aad: &ad },
            )
            .map_err(|_| "sealing the header failed".to_string())?;
        self.tag = tag
            .as_slice()
            .try_into()
            .map_err(|_| "unexpected header tag length".to_string())?;
        Ok(())
    }

    /// Checks the header tag under `key`. A reader of a sealed file calls
    /// this before it trusts any field of the header.
    pub fn verify(&self, key: &[u8; 32]) -> Result<(), String> {
        let ad = self.authenticated();
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                &nonce(&self.nonce_prefix, HEADER_NONCE_INDEX),
                Payload {
                    msg: &self.tag,
                    aad: &ad,
                },
            )
            .map(|_| ())
            .map_err(|_| "the header tag does not match".to_string())
    }

    /// Parses and checks the structure of a header (magic, version, CRC,
    /// frame size, flags, subject, zero padding). For a sealed file, the
    /// fields are trustworthy only after [`Header::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Header, String> {
        if bytes.len() != HEADER_LEN {
            return Err(format!("a header of {} bytes", bytes.len()));
        }
        if &bytes[..8] != MAGIC {
            return Err("not a blob file (bad magic)".into());
        }
        let crc = u32::from_le_bytes(take(&bytes[CRC_AT..]));
        if crc32c::crc32c(&bytes[..CRC_AT]) != crc {
            return Err("the header CRC does not match".into());
        }
        let version = u32::from_le_bytes(take(&bytes[8..]));
        if version != FORMAT_VERSION {
            return Err(format!("unknown blob format version {version}"));
        }
        let flags = u32::from_le_bytes(take(&bytes[12..]));
        if flags & !FLAG_SEALED != 0 {
            return Err(format!("unknown flags {flags:#x}"));
        }
        let frame = u32::from_le_bytes(take(&bytes[24..]));
        if frame as usize != FRAME_SIZE {
            return Err(format!("a frame size of {frame}"));
        }
        let sealed = flags & FLAG_SEALED != 0;
        let len = usize::from(u16::from_le_bytes(take(&bytes[112..])));
        if len > MAX_SUBJECT {
            return Err(format!("a subject of {len} bytes"));
        }
        if bytes[SUBJECT_AT + len..TAG_AT].iter().any(|b| *b != 0)
            || bytes[TAG_AT + 16..CRC_AT].iter().any(|b| *b != 0)
        {
            return Err("non-zero padding".into());
        }
        let subject = match len {
            0 => None,
            _ => {
                let s = std::str::from_utf8(&bytes[SUBJECT_AT..SUBJECT_AT + len])
                    .map_err(|_| "a subject that is not text".to_string())?;
                if !kronik_proto::blobs::valid_subject(s) {
                    return Err("an invalid subject".into());
                }
                Some(s.to_owned())
            }
        };
        let header = Header {
            sealed,
            size: u64::from_le_bytes(take(&bytes[16..])),
            key_version: u32::from_le_bytes(take(&bytes[28..])),
            identity: take(&bytes[32..]),
            body_digest: take(&bytes[64..]),
            nonce_prefix: take(&bytes[96..]),
            subject,
            tag: take(&bytes[TAG_AT..]),
        };
        if !sealed && (header.nonce_prefix != [0; 16] || header.tag != [0; 16]) {
            return Err("a plain file with a nonce prefix or tag".into());
        }
        if header.subject.is_some() != (header.key_version > 0) {
            return Err("a subject without a key version, or the reverse".into());
        }
        if sealed && header.subject.is_none() {
            return Err("a sealed file without a subject".into());
        }
        Ok(header)
    }
}

fn take<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

fn nonce(prefix: &[u8; 16], index: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&index.to_le_bytes());
    XNonce::from(n)
}

fn frame_ad(subject: &str, key_version: u32, index: u64, last: bool) -> Vec<u8> {
    let mut ad = Vec::with_capacity(FRAME_AD.len() + subject.len() + 16);
    ad.extend_from_slice(FRAME_AD);
    ad.push(0);
    ad.extend_from_slice(subject.as_bytes());
    ad.push(0);
    ad.extend_from_slice(&key_version.to_le_bytes());
    ad.extend_from_slice(&index.to_le_bytes());
    ad.push(u8::from(last));
    ad
}

/// What a sealed frame is bound to: the file's key, nonce prefix, subject
/// and key version.
pub struct FrameKey<'a> {
    pub key: &'a [u8; 32],
    pub nonce_prefix: &'a [u8; 16],
    pub subject: &'a str,
    pub key_version: u32,
}

/// A plain frame: the bytes and their CRC32C.
pub fn plain_frame(plain: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(plain);
    out.extend_from_slice(&crc32c::crc32c(plain).to_le_bytes());
}

/// The plaintext of a stored plain frame, if its CRC matches.
pub fn open_plain_frame(stored: &[u8]) -> Option<&[u8]> {
    let (plain, crc) = stored.split_at_checked(stored.len().checked_sub(PLAIN_OVERHEAD)?)?;
    (crc32c::crc32c(plain).to_le_bytes() == crc).then_some(plain)
}

/// A sealed frame: ciphertext and tag, appended to `out`.
pub fn seal_frame(
    k: &FrameKey<'_>,
    index: u64,
    last: bool,
    plain: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let ad = frame_ad(k.subject, k.key_version, index, last);
    let sealed = XChaCha20Poly1305::new(k.key.into())
        .encrypt(
            &nonce(k.nonce_prefix, index),
            Payload {
                msg: plain,
                aad: &ad,
            },
        )
        .map_err(|_| "sealing a frame failed".to_string())?;
    out.extend_from_slice(&sealed);
    Ok(())
}

/// The plaintext of a stored sealed frame, if its tag matches as frame
/// `index` (and as the last frame exactly when `last`).
pub fn open_sealed_frame(
    k: &FrameKey<'_>,
    index: u64,
    last: bool,
    stored: &[u8],
) -> Option<Vec<u8>> {
    let ad = frame_ad(k.subject, k.key_version, index, last);
    XChaCha20Poly1305::new(k.key.into())
        .decrypt(
            &nonce(k.nonce_prefix, index),
            Payload {
                msg: stored,
                aad: &ad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(sealed: bool) -> Header {
        Header {
            sealed,
            size: 200_000,
            key_version: 2,
            identity: [3; 32],
            body_digest: [4; 32],
            nonce_prefix: if sealed { [5; 16] } else { [0; 16] },
            subject: Some("user:1".into()),
            tag: [0; 16],
        }
    }

    #[test]
    fn lengths_follow_from_the_size() {
        assert_eq!(frame_count(0, false), 0);
        assert_eq!(frame_count(0, true), 1);
        assert_eq!(frame_count(1, false), 1);
        assert_eq!(frame_count(65_536, true), 1);
        assert_eq!(frame_count(65_537, true), 2);
        assert_eq!(file_len(0, false), 512);
        assert_eq!(file_len(0, true), 512 + 16);
        assert_eq!(file_len(65_537, false), 512 + 65_537 + 8);
        let h = header(false);
        assert_eq!(h.frames(), 4);
        assert_eq!(h.frame_plain_len(0), 65_536);
        assert_eq!(h.frame_plain_len(3), 200_000 - 3 * 65_536);
        assert_eq!(h.frame_offset(1), 512 + 65_540);
    }

    #[test]
    fn a_header_round_trips_and_detects_damage() {
        let h = header(false);
        let bytes = h.encode();
        assert_eq!(Header::decode(&bytes).unwrap(), h);
        for at in [0, 9, 13, 17, 25, 40, 120, 400, 509] {
            let mut damaged = bytes;
            damaged[at] ^= 1;
            assert!(Header::decode(&damaged).is_err(), "byte {at}");
        }
        assert!(Header::decode(&bytes[..511]).is_err());
    }

    #[test]
    fn the_header_tag_authenticates_every_field() {
        let key = [9u8; 32];
        let mut h = header(true);
        h.seal(&key).unwrap();
        let decoded = Header::decode(&h.encode()).unwrap();
        decoded.verify(&key).unwrap();
        assert!(decoded.verify(&[8u8; 32]).is_err());
        // A change to any authenticated field, with a CRC an attacker can
        // recompute, fails the tag.
        let changes: [fn(&mut Header); 6] = [
            |h| h.size -= 1,
            |h| h.identity[0] ^= 1,
            |h| h.body_digest[31] ^= 1,
            |h| h.nonce_prefix[0] ^= 1,
            |h| h.key_version += 1,
            |h| h.subject = Some("user:2".into()),
        ];
        for change in changes {
            let mut tampered = decoded.clone();
            change(&mut tampered);
            let reread = Header::decode(&tampered.encode()).unwrap();
            assert!(reread.verify(&key).is_err(), "{reread:?}");
        }
    }

    #[test]
    fn frames_open_only_where_they_were_sealed() {
        let key = [1u8; 32];
        let prefix = [2u8; 16];
        let k = FrameKey {
            key: &key,
            nonce_prefix: &prefix,
            subject: "user:1",
            key_version: 1,
        };
        let mut f0 = Vec::new();
        seal_frame(&k, 0, false, b"first", &mut f0).unwrap();
        assert_eq!(open_sealed_frame(&k, 0, false, &f0).unwrap(), b"first");
        // Another position, the last flag, another file, another subject
        // or version: no plaintext.
        assert!(open_sealed_frame(&k, 1, false, &f0).is_none());
        assert!(open_sealed_frame(&k, 0, true, &f0).is_none());
        let other_prefix = [3u8; 16];
        let other_file = FrameKey {
            nonce_prefix: &other_prefix,
            ..k
        };
        assert!(open_sealed_frame(&other_file, 0, false, &f0).is_none());
        let other_subject = FrameKey {
            key: &key,
            nonce_prefix: &prefix,
            subject: "user:2",
            key_version: 1,
        };
        assert!(open_sealed_frame(&other_subject, 0, false, &f0).is_none());

        let mut p = Vec::new();
        plain_frame(b"abc", &mut p);
        assert_eq!(open_plain_frame(&p), Some(&b"abc"[..]));
        p[1] ^= 1;
        assert_eq!(open_plain_frame(&p), None);
        assert_eq!(open_plain_frame(b"ab"), None);
    }
}
