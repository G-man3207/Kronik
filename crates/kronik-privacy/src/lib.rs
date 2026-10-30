//! The key store, the secret store and its backends, sealed values, erasure,
//! reseal and pseudonyms.
//!
//! M2 provides the master key and the secret store (docs/design/m2-effects.md
//! §7): values are sealed with XChaCha20-Poly1305 under a key derived from
//! the master key, versioned, and identified in the log only by a keyed
//! version hash. M8 adds the per-subject [`keystore`]
//! (docs/design/m8-privacy.md).

mod key_memory;
pub mod key_source;
pub mod keystore;
pub mod sealer;

use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::{Zeroize, Zeroizing};

use key_memory::ProtectedKey;

#[derive(Debug, thiserror::Error)]
pub enum PrivacyError {
    #[error("secret store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("master key file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("master key {0} must hold 64 hex characters (32 bytes)")]
    BadKey(String),
    #[error("secret {0:?} cannot be decrypted with this master key")]
    Decrypt(String),
    #[error("secret names must match [a-z0-9][a-z0-9_.-]{{0,63}}, got {0:?}")]
    InvalidName(String),
    #[error("a subject is 1 to 256 bytes of printable ASCII without spaces, got {0:?}")]
    InvalidSubject(String),
    #[error("not a keystore backup, or a damaged one")]
    BadBackup,
    #[error("MASTER_KEY_MISSING: {0}")]
    KeyMissing(String),
    #[error("MASTER_KEY_MISMATCH: {0}")]
    KeyMismatch(String),
    #[error("KEY_PROTECTION_UNAVAILABLE: key memory protection unavailable")]
    KeyProtection,
}

/// The installation's 32-byte seed, retained only in protected memory.
/// [`key_source::KeySource`] selects its file/env or wrapped KMS custody.
#[derive(Clone)]
pub struct MasterKey(ProtectedKey);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // Leave room for the key-file newline without reallocating secret material.
    let mut text = String::with_capacity(b.len() * 2 + 1);
    for byte in b {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

/// The environment variable that, when set, holds the master key material
/// itself (64 hex characters) instead of a key file.
pub const MASTER_KEY_ENV: &str = "KRONIK_MASTER_KEY";

/// How `MASTER_KEY_ENV` is named in error messages.
const ENV_SOURCE: &str = "environment variable KRONIK_MASTER_KEY";

fn encrypted_stores(keys: &Path) -> Result<bool, std::io::Error> {
    for file in ["secrets.db", "keystore.db"] {
        match std::fs::metadata(keys.join(file)) {
            Ok(meta) if meta.len() > 0 => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}
impl MasterKey {
    /// Locks the input and excludes standard core dumps, then zeroizes the input.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<MasterKey, PrivacyError> {
        let result = ProtectedKey::from_slice(&bytes).map(MasterKey);
        bytes.zeroize();
        result
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        self.0.bytes()
    }

    /// Compares seeds without copying them or exiting at the first differing byte.
    pub fn same_key(&self, other: &MasterKey) -> bool {
        self.bytes()
            .iter()
            .zip(other.bytes())
            .fold(0_u8, |different, (a, b)| different | (a ^ b))
            == 0
    }

    /// Parses 64 hex characters of key material. `source` names where the
    /// material comes from (`file <path>` or
    /// `environment variable KRONIK_MASTER_KEY`) for the error, which never
    /// includes the material itself.
    fn from_hex(text: &str, source: String) -> Result<MasterKey, PrivacyError> {
        let t = text.trim();
        // Bytes, not chars: the slicing below needs ASCII.
        if t.len() != 64 || !t.is_ascii() {
            return Err(PrivacyError::BadKey(source));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        for (i, k) in key.iter_mut().enumerate() {
            *k = u8::from_str_radix(&t[2 * i..2 * i + 2], 16)
                .map_err(|_| PrivacyError::BadKey(source.clone()))?;
        }
        ProtectedKey::from_slice(&key).map(MasterKey)
    }

    /// The master key: `material` (the `KRONIK_MASTER_KEY` environment
    /// variable), or the key file (64 hex characters), which is created
    /// with `fresh` (32 bytes from the OS CSPRNG) and mode 0600 when it
    /// does not exist. Returns whether the file was created.
    fn load(
        material: Option<&str>,
        path: &Path,
        fresh: Option<[u8; 32]>,
    ) -> Result<(MasterKey, bool), PrivacyError> {
        let fresh = fresh.map(Zeroizing::new);
        if let Some(text) = material {
            // No key file is created, but the secret store and the privacy
            // keystore live in the same directory, so make sure it exists;
            // a caller that only reads the key (`fresh` is None: shipping,
            // restore) creates nothing.
            if let Some(dir) = path.parent().filter(|_| fresh.is_some()) {
                std::fs::create_dir_all(dir).map_err(|source| PrivacyError::Io {
                    path: dir.display().to_string(),
                    source,
                })?;
            }
            return Self::from_hex(text, ENV_SOURCE.to_owned()).map(|k| (k, false));
        }
        let io = |source| PrivacyError::Io {
            path: path.display().to_string(),
            source,
        };
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let text = Zeroizing::new(text);
                Self::from_hex(&text, format!("file {}", path.display())).map(|k| (k, false))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::OpenOptionsExt as _;
                // Never a key file without fresh randomness (the file can
                // vanish between a caller's check and this read).
                let Some(fresh) = fresh else {
                    return Err(PrivacyError::KeyMissing(format!(
                        "no master key: {} does not exist and KRONIK_MASTER_KEY is not set",
                        path.display()
                    )));
                };
                let key = MasterKey(ProtectedKey::from_slice(&fresh)?);
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(io)?;
                }
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(io)?;
                let mut encoded = Zeroizing::new(hex(key.bytes()));
                encoded.push('\n');
                f.write_all(encoded.as_bytes()).map_err(io)?;
                f.sync_all().map_err(io)?;
                if let Some(dir) = path.parent() {
                    std::fs::File::open(dir)
                        .and_then(|d| d.sync_all())
                        .map_err(io)?;
                }
                Ok((key, true))
            }
            Err(e) => Err(io(e)),
        }
    }

    /// Retained file/env loader: `KRONIK_MASTER_KEY`, else `path`.
    /// A missing file is created from `fresh` only when `keys` holds no
    /// encrypted store. `None` never creates one. Runtime/offline source
    /// selection belongs to [`key_source::KeySource`].
    pub fn open(
        path: &Path,
        keys: &Path,
        mut fresh: Option<[u8; 32]>,
    ) -> Result<(MasterKey, bool), PrivacyError> {
        let result = (|| {
            let material = env_material()?;
            if material.is_none()
                && !path.try_exists().map_err(|source| PrivacyError::Io {
                    path: path.display().to_string(),
                    source,
                })?
            {
                let stores = encrypted_stores(keys).map_err(|source| PrivacyError::Io {
                    path: keys.display().to_string(),
                    source,
                })?;
                if fresh.is_none() || stores {
                    let held = if stores {
                        format!(
                            ", and {} holds stores encrypted under a key",
                            keys.display()
                        )
                    } else {
                        String::new()
                    };
                    return Err(PrivacyError::KeyMissing(format!(
                        "no master key: {} does not exist and KRONIK_MASTER_KEY is not set{held}",
                        path.display()
                    )));
                }
            }
            MasterKey::load(material.as_deref().map(String::as_str), path, fresh)
        })();
        fresh.zeroize();
        result
    }

    /// Checks stores without creating schemas or recording a key verifier.
    /// Use staged copies when SQLite WAL sidecar activity must be excluded too.
    pub fn validate_stores(&self, keys: &Path) -> Result<(), PrivacyError> {
        for (file, table) in [("secrets.db", "secrets"), ("keystore.db", "subject_keys")] {
            let path = keys.join(file);
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.len() == 0 => continue,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(PrivacyError::Io {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
            let conn =
                Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let has_check: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='key_check')",
                [],
                |row| row.get(0),
            )?;
            let have: Option<Vec<u8>> = if has_check {
                conn.query_row("SELECT value FROM key_check WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .optional()?
            } else {
                None
            };
            let matches = if let Some(have) = have {
                have.as_slice() == self.check_value()
            } else {
                let has_data: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )?;
                if !has_data {
                    true
                } else if file == "secrets.db" {
                    SecretStore::validate_legacy_key(&conn, self)?
                } else {
                    keystore::Keystore::validate_legacy_key(&conn, self)?
                }
            };
            if !matches {
                return Err(PrivacyError::KeyMismatch(format!(
                    "{file} was encrypted under another master key"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn derive(&self, context: &str) -> Result<ProtectedKey, PrivacyError> {
        ProtectedKey::derive(context, self.bytes())
    }

    /// What each store's `key_check` row holds: a deliberately persisted verifier.
    fn check_value(&self) -> [u8; 32] {
        let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key("kronik master check v1"));
        hasher.update(self.bytes());
        *hasher.finalize().as_bytes()
    }
}

fn env_material() -> Result<Option<Zeroizing<String>>, PrivacyError> {
    std::env::var_os(MASTER_KEY_ENV)
        .map(|v| {
            v.into_string()
                .map(Zeroizing::new)
                .map_err(|_| PrivacyError::BadKey(ENV_SOURCE.to_owned()))
        })
        .transpose()
}

/// Which master key a store's database was encrypted under: a value derived
/// from the key, one row.
pub(crate) const KEY_CHECK: &str = "CREATE TABLE IF NOT EXISTS key_check (id INTEGER PRIMARY KEY CHECK (id = 1), value BLOB NOT NULL);";

/// Refuses `master` for a database written under another key, and records
/// the key for one that has no record yet. A store from before the record
/// is checked by `legacy`, which decrypts one of its values if it has any.
pub(crate) fn check_key(
    conn: &Connection,
    master: &MasterKey,
    store: &str,
    legacy: impl FnOnce() -> Result<bool, PrivacyError>,
) -> Result<(), PrivacyError> {
    conn.execute_batch(KEY_CHECK)?;
    let want = master.check_value();
    let have: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM key_check WHERE id = 1", [], |r| r.get(0))
        .optional()?;
    let ok = match &have {
        Some(h) => h[..] == want[..],
        None => legacy()?,
    };
    if !ok {
        return Err(PrivacyError::KeyMismatch(format!(
            "{store} was encrypted under another master key"
        )));
    }
    if have.is_none() {
        conn.execute(
            "INSERT INTO key_check (id, value) VALUES (1, ?1)",
            [&want[..]],
        )?;
    }
    Ok(())
}

/// Public facts about one secret version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    pub version: u32,
    /// 16 bytes; safe to record in the log.
    pub version_hash: Vec<u8>,
    pub created_wall_ms: u64,
}

/// A secret value with its version.
pub struct SecretValue {
    pub meta: SecretMeta,
    pub value: Vec<u8>,
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("meta", &self.meta)
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Whether `name` is a valid secret name.
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        })
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS secrets (
  name TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL, version_hash BLOB NOT NULL,
  created_wall_ms INTEGER NOT NULL, token_id TEXT NOT NULL, reason TEXT NOT NULL,
  deleted_wall_ms INTEGER,
  PRIMARY KEY (name, version)) WITHOUT ROWID;
";

/// `keys/secrets.db`.
pub struct SecretStore {
    conn: Mutex<Connection>,
    // Cipher instances copy keys, so create only zeroizing per-operation instances.
    cipher: ProtectedKey,
    hash_key: ProtectedKey,
}

impl SecretStore {
    /// A consistent copy of the store's database (snapshots); the values
    /// stay encrypted under the master key.
    pub fn backup_to(&self, path: &std::path::Path) -> Result<(), PrivacyError> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner()).backup(
            rusqlite::MAIN_DB,
            path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        Ok(())
    }

    pub fn open(conn: Connection, master: &MasterKey) -> Result<SecretStore, PrivacyError> {
        let cipher = master.derive("kronik secrets v1")?;
        let hash_key = master.derive("kronik secret version v1")?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        conn.execute_batch(SCHEMA)?;
        let store = SecretStore {
            conn: Mutex::new(conn),
            cipher,
            hash_key,
        };
        {
            let conn = store.conn();
            check_key(&conn, master, "the secret store", || {
                let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = conn
                    .query_row(
                        "SELECT name, version, nonce, ciphertext FROM secrets \
                         WHERE length(ciphertext) > 0 LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                Ok(row.is_none_or(|(name, version, nonce, ct)| {
                    store
                        .decrypt(&name, version, &nonce, &ct)
                        .map(Zeroizing::new)
                        .is_ok()
                }))
            })?;
        }
        Ok(store)
    }

    fn validate_legacy_key(conn: &Connection, master: &MasterKey) -> Result<bool, PrivacyError> {
        let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT name, version, nonce, ciphertext FROM secrets WHERE length(ciphertext) > 0 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((name, version, nonce, ciphertext)) = row else {
            return Ok(true);
        };
        let Ok(nonce) = XNonce::try_from(nonce.as_slice()) else {
            return Ok(false);
        };
        let key = master.derive("kronik secrets v1")?;
        Ok(XChaCha20Poly1305::new(key.bytes().into())
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &Self::aad(&name, version),
                },
            )
            .map(Zeroizing::new)
            .is_ok())
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn version_hash(&self, name: &str, version: u32, value: &[u8]) -> Vec<u8> {
        let mut h = Zeroizing::new(blake3::Hasher::new_keyed(self.hash_key.bytes()));
        h.update(name.as_bytes());
        h.update(b"\0");
        h.update(&version.to_le_bytes());
        h.update(b"\0");
        h.update(value);
        h.finalize().as_bytes()[..16].to_vec()
    }

    fn aad(name: &str, version: u32) -> Vec<u8> {
        format!("{name}|{version}").into_bytes()
    }

    /// Stores a new version of `name`. `nonce` must be fresh randomness.
    pub fn set(
        &self,
        name: &str,
        value: &[u8],
        nonce: [u8; 24],
        wall_ms: u64,
        token_id: &str,
        reason: &str,
    ) -> Result<SecretMeta, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        let conn = self.conn();
        let last: Option<i64> = conn
            .query_row(
                "SELECT max(version) FROM secrets WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let version = last.map_or(1, |v| v as u32 + 1);
        let ciphertext = XChaCha20Poly1305::new(self.cipher.bytes().into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: value,
                    aad: &Self::aad(name, version),
                },
            )
            .map_err(|_| PrivacyError::Decrypt(name.to_owned()))?;
        let version_hash = self.version_hash(name, version, value);
        conn.execute(
            "INSERT INTO secrets (name, version, nonce, ciphertext, version_hash, created_wall_ms, token_id, reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![name, version, &nonce[..], ciphertext, version_hash, wall_ms as i64, token_id, reason],
        )?;
        Ok(SecretMeta {
            name: name.to_owned(),
            version,
            version_hash,
            created_wall_ms: wall_ms,
        })
    }

    fn decrypt(
        &self,
        name: &str,
        version: u32,
        nonce: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, PrivacyError> {
        let nonce = XNonce::try_from(nonce).map_err(|_| PrivacyError::Decrypt(name.to_owned()))?;
        XChaCha20Poly1305::new(self.cipher.bytes().into())
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: &Self::aad(name, version),
                },
            )
            .map_err(|_| PrivacyError::Decrypt(name.to_owned()))
    }

    fn read(&self, name: &str, version: Option<u32>) -> Result<Option<SecretValue>, PrivacyError> {
        let conn = self.conn();
        type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);
        let row: Option<Row> = match version {
            None => conn
                .query_row(
                    "SELECT version, nonce, ciphertext, version_hash, created_wall_ms FROM secrets \
                     WHERE name = ?1 AND deleted_wall_ms IS NULL ORDER BY version DESC LIMIT 1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?,
            Some(v) => conn
                .query_row(
                    "SELECT version, nonce, ciphertext, version_hash, created_wall_ms FROM secrets \
                     WHERE name = ?1 AND version = ?2 AND deleted_wall_ms IS NULL",
                    params![name, v],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?,
        };
        drop(conn);
        let Some((version, nonce, ct, version_hash, created)) = row else {
            return Ok(None);
        };
        let value = self.decrypt(name, version as u32, &nonce, &ct)?;
        Ok(Some(SecretValue {
            meta: SecretMeta {
                name: name.to_owned(),
                version: version as u32,
                version_hash,
                created_wall_ms: created as u64,
            },
            value,
        }))
    }

    /// The newest version of `name`, unless deleted.
    pub fn current(&self, name: &str) -> Result<Option<SecretValue>, PrivacyError> {
        self.read(name, None)
    }

    /// One specific version (re-runs use the recorded version).
    pub fn version(&self, name: &str, version: u32) -> Result<Option<SecretValue>, PrivacyError> {
        self.read(name, Some(version))
    }

    /// The newest version of every secret that is not deleted.
    pub fn list(&self) -> Result<Vec<SecretMeta>, PrivacyError> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT name, max(version), created_wall_ms, version_hash FROM secrets \
             WHERE deleted_wall_ms IS NULL GROUP BY name ORDER BY name",
        )?;
        let rows = st.query_map([], |r| {
            Ok(SecretMeta {
                name: r.get(0)?,
                version: r.get::<_, i64>(1)? as u32,
                created_wall_ms: r.get::<_, i64>(2)? as u64,
                version_hash: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Marks every version of `name` deleted and drops the ciphertexts.
    /// Returns how many versions existed.
    pub fn delete(&self, name: &str, wall_ms: u64) -> Result<u32, PrivacyError> {
        let n = self.conn().execute(
            "UPDATE secrets SET deleted_wall_ms = ?2, ciphertext = x'', nonce = x'' \
             WHERE name = ?1 AND deleted_wall_ms IS NULL",
            params![name, wall_ms as i64],
        )?;
        Ok(n as u32)
    }

    /// Every stored secret value, every version of it (a rotated value can
    /// still be in logs and outputs written before the rotation), for
    /// scanning outputs (scrubbing). Deleted secrets have no value left.
    pub fn values(&self) -> Result<Vec<(String, Vec<u8>)>, PrivacyError> {
        let rows: Vec<(String, i64, Vec<u8>, Vec<u8>)> = {
            let conn = self.conn();
            let mut st = conn.prepare(
                "SELECT name, version, nonce, ciphertext FROM secrets \
                 WHERE deleted_wall_ms IS NULL ORDER BY name, version DESC",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (name, version, nonce, ct) in rows {
            let value = self.decrypt(&name, version as u32, &nonce, &ct)?;
            out.push((name, value));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(key: u8) -> SecretStore {
        SecretStore::open(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([key; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn protected_keys_preserve_cipher_hash_and_verifier_bytes() {
        fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroizes_on_drop::<XChaCha20Poly1305>();
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let s = SecretStore::open(Connection::open_in_memory().unwrap(), &master).unwrap();
        let meta = s.set("token", b"value", [3; 24], 0, "", "").unwrap();
        let old_cipher_key = blake3::derive_key("kronik secrets v1", &[7; 32]);
        let expected_ciphertext = XChaCha20Poly1305::new((&old_cipher_key).into())
            .encrypt(
                &XNonce::from([3; 24]),
                Payload {
                    msg: b"value",
                    aad: b"token|1",
                },
            )
            .unwrap();
        let ciphertext: Vec<u8> = s
            .conn()
            .query_row(
                "SELECT ciphertext FROM secrets WHERE name='token' AND version=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);
        let old_hash_key = blake3::derive_key("kronik secret version v1", &[7; 32]);
        let mut h = blake3::Hasher::new_keyed(&old_hash_key);
        h.update(b"token\0");
        h.update(&1_u32.to_le_bytes());
        h.update(b"\0value");
        assert_eq!(meta.version_hash, h.finalize().as_bytes()[..16]);
        assert_eq!(
            master.check_value(),
            blake3::derive_key("kronik master check v1", &[7; 32])
        );
        assert!(std::ptr::eq(master.bytes(), master.clone().bytes()));
        assert!(master.same_key(&master.clone()));
        assert!(!master.same_key(&MasterKey::from_bytes([8; 32]).unwrap()));
    }

    #[test]
    fn store_preflight_checks_current_and_legacy_keys_without_blessing_them() {
        for legacy in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let right = MasterKey::from_bytes([1; 32]).unwrap();
            let wrong = MasterKey::from_bytes([2; 32]).unwrap();
            right.validate_stores(dir.path()).unwrap();
            let secrets = dir.path().join("secrets.db");
            let subjects = dir.path().join("keystore.db");
            SecretStore::open(Connection::open(&secrets).unwrap(), &right)
                .unwrap()
                .set("token", b"value", [1; 24], 0, "", "")
                .unwrap();
            keystore::Keystore::open_file(&subjects, &right)
                .unwrap()
                .key_for_sealing("user:1", [3; 32], [2; 24], 0)
                .unwrap();
            if legacy {
                for path in [&secrets, &subjects] {
                    Connection::open(path)
                        .unwrap()
                        .execute_batch("DROP TABLE key_check")
                        .unwrap();
                }
            }
            let before = [
                std::fs::read(&secrets).unwrap(),
                std::fs::read(&subjects).unwrap(),
            ];
            right.validate_stores(dir.path()).unwrap();
            assert!(matches!(
                wrong.validate_stores(dir.path()),
                Err(PrivacyError::KeyMismatch(_))
            ));
            assert_eq!(
                before,
                [
                    std::fs::read(&secrets).unwrap(),
                    std::fs::read(&subjects).unwrap()
                ]
            );
        }
    }

    #[test]
    fn versions_hashes_and_deletion() {
        let s = store(1);
        let a = s
            .set("stripe-key", b"sk_live_1", [1; 24], 10, "t", "r")
            .unwrap();
        let b = s
            .set("stripe-key", b"sk_live_2", [2; 24], 11, "t", "r")
            .unwrap();
        assert_eq!((a.version, b.version), (1, 2));
        assert_ne!(a.version_hash, b.version_hash);
        assert_eq!(
            s.current("stripe-key").unwrap().unwrap().value,
            b"sk_live_2"
        );
        assert_eq!(
            s.version("stripe-key", 1).unwrap().unwrap().value,
            b"sk_live_1"
        );
        assert_eq!(s.list().unwrap(), vec![b.clone()]);
        // Scrubbing knows both versions: the old one can be in old output.
        assert_eq!(
            s.values().unwrap(),
            vec![
                ("stripe-key".to_owned(), b"sk_live_2".to_vec()),
                ("stripe-key".to_owned(), b"sk_live_1".to_vec()),
            ]
        );
        // The hash is keyed: another master key gives another hash.
        let other = store(2)
            .set("stripe-key", b"sk_live_1", [1; 24], 10, "t", "r")
            .unwrap();
        assert_ne!(other.version_hash, a.version_hash);
        assert_eq!(s.delete("stripe-key", 12).unwrap(), 2);
        assert!(s.current("stripe-key").unwrap().is_none());
        assert!(s.values().unwrap().is_empty());
        assert!(s.list().unwrap().is_empty());
        assert!(matches!(
            s.set("Bad Name", b"x", [0; 24], 0, "t", "r"),
            Err(PrivacyError::InvalidName(_))
        ));
    }

    #[test]
    fn values_are_encrypted_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.db");
        let key_path = dir.path().join("keys/master.key");
        let (key, created) =
            MasterKey::open(&key_path, &dir.path().join("keys"), Some([7; 32])).unwrap();
        assert!(created);
        let (again, created) =
            MasterKey::open(&key_path, &dir.path().join("keys"), Some([9; 32])).unwrap();
        assert!(!created);
        assert_eq!(again.bytes(), key.bytes());
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        {
            let s = SecretStore::open(Connection::open(&path).unwrap(), &key).unwrap();
            s.set("db-password", b"hunter2-very-secret", [3; 24], 1, "t", "r")
                .unwrap();
        }
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let p = entry.unwrap().path();
            if p.is_file() {
                let bytes = std::fs::read(&p).unwrap();
                assert!(
                    !bytes.windows(19).any(|w| w == b"hunter2-very-secret"),
                    "plaintext in {}",
                    p.display()
                );
            }
        }
        let wrong = SecretStore::open(
            Connection::open(&path).unwrap(),
            &MasterKey::from_bytes([8; 32]).unwrap(),
        );
        assert!(matches!(wrong, Err(PrivacyError::KeyMismatch(_))));
    }

    #[test]
    fn a_store_from_before_the_key_check_is_checked_by_its_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.db");
        let right = MasterKey::from_bytes([7; 32]).unwrap();
        SecretStore::open(Connection::open(&path).unwrap(), &right)
            .unwrap()
            .set("a", b"value-1", [3; 24], 1, "t", "r")
            .unwrap();
        let forget = || {
            Connection::open(&path)
                .unwrap()
                .execute_batch("DROP TABLE key_check")
                .unwrap()
        };
        forget();
        let wrong = SecretStore::open(
            Connection::open(&path).unwrap(),
            &MasterKey::from_bytes([8; 32]).unwrap(),
        );
        assert!(matches!(wrong, Err(PrivacyError::KeyMismatch(_))));
        // The right key passes and is recorded, so an empty store can't be
        // opened with another key afterwards either.
        let s = SecretStore::open(Connection::open(&path).unwrap(), &right).unwrap();
        s.delete("a", 2).unwrap();
        drop(s);
        assert!(matches!(
            SecretStore::open(
                Connection::open(&path).unwrap(),
                &MasterKey::from_bytes([8; 32]).unwrap()
            ),
            Err(PrivacyError::KeyMismatch(_))
        ));
    }

    #[test]
    fn open_makes_a_key_only_for_a_directory_without_stores() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let key_path = dir.path().join("etc/master.key");
        // Nothing to read without a key file, and `None` never makes one.
        assert!(matches!(
            MasterKey::open(&key_path, &keys, None),
            Err(PrivacyError::KeyMissing(_))
        ));
        let (key, created) = MasterKey::open(&key_path, &keys, Some([7; 32])).unwrap();
        assert!(created);
        std::fs::create_dir_all(&keys).unwrap();
        SecretStore::open(Connection::open(keys.join("secrets.db")).unwrap(), &key).unwrap();
        // The low-level load never makes a key without fresh randomness.
        let gone = dir.path().join("gone/master.key");
        assert!(matches!(
            MasterKey::load(None, &gone, None),
            Err(PrivacyError::KeyMissing(_))
        ));
        assert!(!gone.exists());
        // Lost: with a store in `keys`, no new key is made.
        std::fs::remove_file(&key_path).unwrap();
        let err = MasterKey::open(&key_path, &keys, Some([9; 32])).unwrap_err();
        assert!(matches!(err, PrivacyError::KeyMissing(_)), "{err}");
        assert!(err.to_string().starts_with("MASTER_KEY_MISSING: "), "{err}");
        assert!(!key_path.exists());
    }

    #[test]
    fn the_environment_material_beats_the_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("keys/master.key");
        let material = hex(&[7; 32]);
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, format!("{}\n", hex(&[9; 32]))).unwrap();

        // The material comes first: the directory is created (the secret
        // store and the keystore live there) but no key file is, and an
        // existing file is left alone.
        let fresh_path = dir.path().join("other-keys/master.key");
        let (key, created) = MasterKey::load(Some(&material), &fresh_path, Some([1; 32])).unwrap();
        assert!(!created);
        assert!(fresh_path.parent().unwrap().is_dir());
        assert!(!fresh_path.exists());
        assert_eq!(key.bytes(), &[7; 32]);
        let (key, created) = MasterKey::load(Some(&material), &key_path, Some([1; 32])).unwrap();
        assert!(!created);
        assert_eq!(key.bytes(), &[7; 32]);
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().trim(),
            hex(&[9; 32]),
            "the key file must be left alone"
        );

        // Material that is not 64 hex characters is an error naming the
        // source, never the material itself.
        let bad = vec![
            String::new(),
            "zz".to_owned(),
            "z".repeat(64),
            format!("{}0", hex(&[7; 32])),
            // 64 bytes with a char across a hex pair's boundary.
            format!("{}éa", "a".repeat(61)),
        ];
        for material in &bad {
            let err = MasterKey::load(Some(material), &key_path, Some([1; 32])).unwrap_err();
            assert!(matches!(err, PrivacyError::BadKey(_)), "{err}");
            assert!(err.to_string().contains(ENV_SOURCE), "{err}");
            if !material.trim().is_empty() {
                assert!(!err.to_string().contains(material.trim()), "{err}");
            }
        }

        // Without material, the file is read as before.
        let (key, created) = MasterKey::load(None, &key_path, Some([1; 32])).unwrap();
        assert!(!created);
        assert_eq!(key.bytes(), &[9; 32]);
    }
}
