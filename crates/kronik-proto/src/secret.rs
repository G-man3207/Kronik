//! Immutable secret identity encoding. Field 3 and its legacy hash stay exact;
//! field 5 explicitly selects the wide identity and versioned hash domain.
use crate::{DecodeError, invalid, log::v1 as pb};

/// Every accepted identity is exact in the existing numeric JSON API and SQLite.
pub const MAX_SECRET_VERSION: u64 = (1_u64 << 53) - 1;
pub const LEGACY_SECRET_VERSION_MAX: u64 = u32::MAX as u64;

impl pb::SecretRef {
    pub fn is_unresolved(&self) -> bool {
        self.version == 0 && self.wide_version == 0 && self.version_hash.is_empty()
    }

    /// The exact resolved identity, never a truncated wide value or version zero.
    /// Unresolved request/fingerprint placeholders must not call this accessor.
    pub fn resolved_version(&self) -> Result<u64, DecodeError> {
        if self.version_hash.len() != 16 {
            return Err(invalid("secret reference", "invalid version hash length"));
        }
        match (self.version, self.wide_version) {
            (version, 0) if version != 0 => Ok(u64::from(version)),
            (0, version)
                if version > LEGACY_SECRET_VERSION_MAX && version <= MAX_SECRET_VERSION =>
            {
                Ok(version)
            }
            _ => Err(invalid(
                "secret reference",
                "ambiguous, unresolved or noncanonical version identity",
            )),
        }
    }

    /// Sets the single canonical version encoding without changing the hash.
    pub fn set_resolved_version(&mut self, version: u64) -> Result<(), DecodeError> {
        if version == 0 || version > MAX_SECRET_VERSION {
            return Err(invalid("secret reference", "version is outside the supported domain"));
        }
        match u32::try_from(version) {
            Ok(version) => {
                self.version = version;
                self.wide_version = 0;
            }
            Err(_) => {
                self.version = 0;
                self.wide_version = version;
            }
        }
        Ok(())
    }
}

pub(crate) fn peer_name(name: &str) -> Result<(), DecodeError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64
        || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        || !bytes.iter().all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-'))
    { return Err(invalid("peer secret name", "not a canonical FILE secret name")); }
    Ok(())
}
