//! Blob identities and complete references (ADR 0117 §3, ADR 0118).

use std::fmt;

use kronik_proto::blobs::{KEYED_PREFIX, PLAIN_PREFIX, parse_hash, validate_ref};
use kronik_proto::log::v1 as pb;

use crate::BlobError;

/// A blob's identity: `b3:` + BLAKE3 of the content, or `b3s:` + BLAKE3
/// keyed per subject. Displayed in its canonical text form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId {
    keyed: bool,
    digest: [u8; 32],
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

impl BlobId {
    /// The identity of a blob without a subject.
    pub const fn plain(digest: [u8; 32]) -> BlobId {
        BlobId {
            keyed: false,
            digest,
        }
    }

    /// The identity of a subject's blob.
    pub const fn keyed(digest: [u8; 32]) -> BlobId {
        BlobId {
            keyed: true,
            digest,
        }
    }

    /// Whether this is a subject's (`b3s:`) identity.
    pub fn is_keyed(&self) -> bool {
        self.keyed
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Parses `b3:<64 hex>` or `b3s:<64 hex>` (lowercase).
    pub fn parse(text: &str) -> Result<BlobId, BlobError> {
        let (keyed, digest) =
            parse_hash(text).map_err(|why| BlobError::Invalid(format!("{text:?}: {why}")))?;
        Ok(BlobId { keyed, digest })
    }

    /// The object's file name: `b3-<hex>` or `b3s-<hex>`.
    pub fn file_name(&self) -> String {
        let prefix = if self.keyed { "b3s-" } else { "b3-" };
        format!("{prefix}{}", hex(&self.digest))
    }

    /// The identity a file name names, if it is one.
    pub fn from_file_name(name: &str) -> Option<BlobId> {
        let text = match name.strip_prefix("b3s-") {
            Some(rest) => format!("{KEYED_PREFIX}{rest}"),
            None => format!("{PLAIN_PREFIX}{}", name.strip_prefix("b3-")?),
        };
        BlobId::parse(&text).ok()
    }

    /// The shard directory: the first byte of the digest as two hex digits.
    pub fn shard(&self) -> String {
        hex(&self.digest[..1])
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = if self.keyed {
            KEYED_PREFIX
        } else {
            PLAIN_PREFIX
        };
        write!(f, "{prefix}{}", hex(&self.digest))
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A complete reference (ADR 0118 §3): identity, plaintext size, and for a
/// subject's blob its subject and the key version that names and seals it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BlobMeta {
    pub id: BlobId,
    pub size: u64,
    pub subject: Option<String>,
    pub key_version: u32,
}

impl BlobMeta {
    /// The reference as the log records it.
    pub fn to_pb(&self) -> pb::BlobRef {
        pb::BlobRef {
            hash: self.id.to_string(),
            size: self.size,
            subject: self.subject.clone(),
            key_version: self.key_version,
        }
    }

    /// A recorded reference, validated (ADR 0118 §3).
    pub fn from_pb(r: &pb::BlobRef) -> Result<BlobMeta, BlobError> {
        validate_ref(r).map_err(|e| BlobError::Invalid(e.to_string()))?;
        Ok(BlobMeta {
            id: BlobId::parse(&r.hash)?,
            size: r.size,
            subject: r.subject.clone(),
            key_version: r.key_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_text_round_trip() {
        let id = BlobId::plain([0xab; 32]);
        assert_eq!(id.to_string(), format!("b3:{}", "ab".repeat(32)));
        assert_eq!(id.file_name(), format!("b3-{}", "ab".repeat(32)));
        assert_eq!(id.shard(), "ab");
        assert_eq!(BlobId::from_file_name(&id.file_name()), Some(id));
        assert_eq!(BlobId::parse(&id.to_string()).unwrap(), id);
        let keyed = BlobId::keyed([1; 32]);
        assert_eq!(keyed.to_string(), format!("b3s:{}", "01".repeat(32)));
        assert_eq!(BlobId::from_file_name(&keyed.file_name()), Some(keyed));
        assert_ne!(keyed, BlobId::plain([1; 32]));
        for bad in ["", "b3-", "x.part", "b3-AB", "b3s-00"] {
            assert_eq!(BlobId::from_file_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_reference_round_trips_and_is_validated() {
        let meta = BlobMeta {
            id: BlobId::keyed([7; 32]),
            size: 10,
            subject: Some("user:1".into()),
            key_version: 2,
        };
        assert_eq!(BlobMeta::from_pb(&meta.to_pb()).unwrap(), meta);
        let mut bad = meta.to_pb();
        bad.key_version = 0;
        assert!(BlobMeta::from_pb(&bad).is_err());
    }
}
