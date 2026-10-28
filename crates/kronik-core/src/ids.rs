//! Identifiers: actor references, code hashes, turn ids and random ids.

use std::fmt;

use crate::env::Env;

/// A log sequence number. LSNs start at 1 and increase by 1 per record.
pub type Lsn = u64;

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

/// Parses lowercase or uppercase hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

/// Why an actor reference is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActorRefError {
    #[error("actor kind {0:?} must match [a-z][a-z0-9-]{{0,62}}")]
    Kind(String),
    #[error("actor key {0:?} must be 1-256 bytes without '/', whitespace or control characters")]
    Key(String),
    #[error("actor reference {0:?} must be kind/key")]
    Format(String),
}

/// `kind/key`, for example `billing/acme`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActorRef {
    pub kind: String,
    pub key: String,
}

/// Whether `kind` is a valid actor kind name.
pub fn valid_kind(kind: &str) -> bool {
    let b = kind.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Whether `key` is a valid actor key.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key
            .chars()
            .all(|c| c != '/' && !c.is_whitespace() && !c.is_control())
}

impl ActorRef {
    pub fn new(kind: impl Into<String>, key: impl Into<String>) -> Result<ActorRef, ActorRefError> {
        let (kind, key) = (kind.into(), key.into());
        if !valid_kind(&kind) {
            return Err(ActorRefError::Kind(kind));
        }
        if !valid_key(&key) {
            return Err(ActorRefError::Key(key));
        }
        Ok(ActorRef { kind, key })
    }

    /// Parses `kind/key`.
    pub fn parse(s: &str) -> Result<ActorRef, ActorRefError> {
        let (kind, key) = s
            .split_once('/')
            .ok_or_else(|| ActorRefError::Format(s.to_owned()))?;
        ActorRef::new(kind, key)
    }

    pub fn to_pb(&self) -> kronik_proto::log::v1::ActorRef {
        kronik_proto::log::v1::ActorRef {
            kind: self.kind.clone(),
            key: self.key.clone(),
        }
    }

    /// From a validated record (the log validated it is non-empty).
    pub fn from_pb(a: &kronik_proto::log::v1::ActorRef) -> ActorRef {
        ActorRef {
            kind: a.kind.clone(),
            key: a.key.clone(),
        }
    }
}

impl fmt::Display for ActorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.key)
    }
}

/// BLAKE3 of a component's bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeHash(pub [u8; 32]);

impl CodeHash {
    pub fn of(bytes: &[u8]) -> CodeHash {
        CodeHash(*blake3::hash(bytes).as_bytes())
    }

    pub fn from_slice(bytes: &[u8]) -> Option<CodeHash> {
        Some(CodeHash(bytes.try_into().ok()?))
    }

    /// 64 hex characters, used in file names.
    pub fn hex(&self) -> String {
        hex(&self.0)
    }

    /// `b3:` + 12 hex characters, for humans.
    pub fn short(&self) -> String {
        format!("b3:{}", &self.hex()[..12])
    }
}

impl fmt::Debug for CodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

/// `<branch>:<lsn>` of a turn record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TurnId {
    pub branch: String,
    pub lsn: Lsn,
}

impl TurnId {
    pub fn parse(s: &str) -> Option<TurnId> {
        let (branch, lsn) = s.rsplit_once(':')?;
        if branch.is_empty() {
            return None;
        }
        Some(TurnId {
            branch: branch.to_owned(),
            lsn: lsn.parse().ok()?,
        })
    }
}

impl fmt::Display for TurnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.branch, self.lsn)
    }
}

/// 16 bytes from the entropy source as 32 hex characters (root ids,
/// execution ids).
pub fn random_id(env: &Env) -> String {
    hex(&env.random_bytes::<16>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_ref_validation() {
        assert!(ActorRef::parse("billing/acme").is_ok());
        assert!(ActorRef::parse("billing/a/b").is_err());
        assert!(ActorRef::parse("Billing/a").is_err());
        assert!(ActorRef::parse("billing/").is_err());
        assert!(ActorRef::parse("billing").is_err());
        assert!(ActorRef::parse("b/a b").is_err());
    }

    #[test]
    fn hex_roundtrip_and_turn_id() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xab, 0xff])).unwrap(),
            vec![0, 1, 0xab, 0xff]
        );
        let t = TurnId::parse("main:42").unwrap();
        assert_eq!(t.to_string(), "main:42");
        assert!(TurnId::parse("main:x").is_none());
    }
}
