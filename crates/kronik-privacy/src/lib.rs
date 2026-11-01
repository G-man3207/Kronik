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
mod publication;
pub mod sealer;
pub mod secret_backend;
pub mod secret_selection;
pub use publication::PublicationError;

#[cfg(test)]
mod file_custody_tests;

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
    #[error("secret version {0} is outside 1..=2^53-1")]
    InvalidVersion(u64),
    #[error("secret store contains invalid version {0}")]
    InvalidStoredVersion(i64),
    #[error("secret store contains an invalid timestamp")]
    InvalidTimestamp,
    #[error("invalid encrypted secret row or expected file identity")]
    InvalidSecretRow,
    #[error("the original encrypted secret row is unavailable for complete scrub custody")]
    SecretRowIncomplete,
    #[error("encrypted secret row conflicts with retained custody")]
    SecretRowConflict,
    #[error("secret version is covered by a retained deletion floor")]
    SecretDeleted,
    #[error("encrypted secret row requires snapshot transport")]
    SecretRowTooLarge,
    #[error("secret store is not backed by a database file")]
    FileStoreRequired,
    #[error("the original secret-store writer is busy")]
    SecretStoreBusy,
    #[error("the secret store has no original mutable ownership")]
    SecretStoreUnowned,
    #[error("the original secret-store DATA state is unknown")]
    SecretStoreUnknown,
    #[error("secret custody file {path}: {source}")]
    CustodyIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
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
    #[error(transparent)]
    Publication(#[from] PublicationError),
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

    /// Pure secret version identities using one protected derivation, without opening a store.
    pub fn secret_version_hasher(
        &self,
    ) -> Result<
        impl Fn(&str, u64, &[u8]) -> Result<Vec<u8>, PrivacyError> + Send + Sync + 'static,
        PrivacyError,
    > {
        let key = self.derive("kronik secret version v1")?;
        Ok(move |name: &str, version: u64, value: &[u8]| {
            secret_version_hash(&key, name, version, value)
        })
    }

    /// What each store's `key_check` row holds: a deliberately persisted verifier.
    fn check_value(&self) -> [u8; 32] {
        let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key("kronik master check v1"));
        hasher.update(self.bytes());
        *hasher.finalize().as_bytes()
    }
}

fn secret_version_hash(
    key: &ProtectedKey,
    name: &str,
    version: u64,
    value: &[u8],
) -> Result<Vec<u8>, PrivacyError> {
    sql_version(version)?;
    if !valid_name(name) {
        return Err(PrivacyError::InvalidName(name.to_owned()));
    }
    let mut h = Zeroizing::new(blake3::Hasher::new_keyed(key.bytes()));
    if version > kronik_proto::secret::LEGACY_SECRET_VERSION_MAX {
        h.update(b"kronik secret version v2\0");
    }
    h.update(name.as_bytes());
    h.update(b"\0");
    if let Ok(version) = u32::try_from(version) {
        h.update(&version.to_le_bytes());
    } else {
        h.update(&version.to_le_bytes());
    }
    h.update(b"\0");
    h.update(value);
    Ok(h.finalize().as_bytes()[..16].to_vec())
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
    pub version: u64,
    /// 16 bytes; safe to record in the log.
    pub version_hash: Vec<u8>,
    pub created_wall_ms: u64,
}

/// Retained metadata, including tombstones, without values or operator text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRowMeta {
    pub meta: SecretMeta,
    /// Local revocation application marker, never the original/global deletion clock.
    pub deletion_applied_wall_ms: Option<u64>,
}

/// A physical-name-bound committed version cut with its local application clock.
/// Callers prove that physical name and cut from canonical Meta28/current source authority,
/// never from a logical alias deletion or a capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretDeletionFloor {
    pub through_version: u64,
    /// Preserve an actual local floor pin; otherwise sample Env inside the admitted worker.
    /// This is not an original/global deletion time or a retention/expiry boundary.
    pub applied_wall_ms: u64,
}

/// A successful commit is not necessarily operational authorization.
#[must_use = "ScrubOnly must never authorize an operational secret or READY value"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretImportDisposition {
    /// Stored live; the caller still owns current operational authorization.
    Operational,
    /// Host scrub custody only, never a READY or operational secret.
    ScrubOnly,
}

/// Original SQLite row facts; no plaintext and deliberately no Serde format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSecretRow {
    /// Physical FILE reference used by SQLite, AEAD and the physical keyed hash;
    /// a canonical identity's logical name may differ.
    pub name: String,
    pub physical_version: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub version_hash: Vec<u8>,
    pub created_wall_ms: u64,
    pub token_id: String,
    pub reason: String,
    /// Source-local application diagnostic; absent is unknown, never permission.
    pub deletion_applied_wall_ms: Option<u64>,
    /// Diagnostic only: absence means unknown, not "never deleted".
    pub known_floor: Option<SecretDeletionFloor>,
}

/// An owned private encrypted backup, never a replacement for a live store.
pub struct EncryptedSecretSnapshot {
    _directory: tempfile::TempDir,
    database: std::path::PathBuf,
}

impl EncryptedSecretSnapshot {
    pub fn database_path(&self) -> &Path {
        &self.database
    }

    /// Only this staged, immutable database is opened; no schema/key check writes.
    pub fn export_encrypted_row(
        &self,
        name: &str,
        physical_version: u64,
    ) -> Result<Option<EncryptedSecretRow>, PrivacyError> {
        let max_bytes = std::fs::metadata(&self.database)
            .map_err(|source| PrivacyError::CustodyIo {
                path: self.database.display().to_string(),
                source,
            })?
            .len();
        let max_bytes = usize::try_from(max_bytes).map_err(|_| PrivacyError::SecretRowTooLarge)?;
        SecretStore::export_encrypted_snapshot_row(
            &self.database,
            name,
            physical_version,
            max_bytes,
        )
    }

    /// Retains this completed SQLite backup through the read-only reader's lifetime.
    pub fn open_readonly(self, master: &MasterKey) -> Result<SecretStore, PrivacyError> {
        require_no_snapshot_sidecars(&self.database)?;
        let conn = Connection::open_with_flags(
            &self.database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut store = SecretStore::open_readonly(conn, master)?;
        store._snapshot = Some(self);
        Ok(store)
    }
}

fn require_no_snapshot_sidecars(snapshot: &Path) -> Result<(), PrivacyError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = snapshot.as_os_str().to_os_string();
        sidecar.push(suffix);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => return Err(PrivacyError::InvalidSecretRow),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(PrivacyError::CustodyIo {
                    path: Path::new(&sidecar).display().to_string(),
                    source,
                });
            }
        }
    }
    Ok(())
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

// Historical SQLite column names are retained for format compatibility only.
// Both deleted_wall_ms slots hold local application diagnostics, never a Meta28 audit clock.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS secrets (
  name TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL, version_hash BLOB NOT NULL,
  created_wall_ms INTEGER NOT NULL, token_id TEXT NOT NULL, reason TEXT NOT NULL,
  deleted_wall_ms INTEGER,
  PRIMARY KEY (name, version)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS secret_deletion_floors (
  name TEXT PRIMARY KEY NOT NULL, through_version INTEGER NOT NULL,
  deleted_wall_ms INTEGER NOT NULL) WITHOUT ROWID;
";

// Keep metadata-only and value reads on exactly the same current-row selector.
macro_rules! current_secret_query {
    ($columns:literal) => {
        concat!(
            "SELECT ",
            $columns,
            " FROM secrets \
            WHERE name = ?1 AND deleted_wall_ms IS NULL ORDER BY version DESC LIMIT 1"
        )
    };
}

fn sql_version(version: u64) -> Result<i64, PrivacyError> {
    if version == 0 || version > kronik_proto::secret::MAX_SECRET_VERSION {
        return Err(PrivacyError::InvalidVersion(version));
    }
    i64::try_from(version).map_err(|_| PrivacyError::InvalidVersion(version))
}

fn stored_version(version: i64) -> Result<u64, PrivacyError> {
    let value = u64::try_from(version).map_err(|_| PrivacyError::InvalidStoredVersion(version))?;
    sql_version(value).map_err(|_| PrivacyError::InvalidStoredVersion(version))?;
    Ok(value)
}

fn stored_wall(wall: i64) -> Result<u64, PrivacyError> {
    u64::try_from(wall).map_err(|_| PrivacyError::InvalidTimestamp)
}

fn file_source_version(
    expected: &kronik_proto::log::v1::SecretVersion,
    intended: SecretImportDisposition,
) -> Result<u64, PrivacyError> {
    use kronik_proto::log::v1::secret_version::Phase;
    kronik_proto::validate_secret_version(expected).map_err(|_| PrivacyError::InvalidSecretRow)?;
    if !valid_name(&expected.name)
        || !valid_name(&expected.r#ref)
        || expected.backend != "file"
        || expected.version_hash.len() != 16
        || !matches!(expected.phase, p if p == Phase::Reserved as i32 || p == Phase::Active as i32)
        || (expected.deleted
            && (intended != SecretImportDisposition::ScrubOnly
                || expected.phase != Phase::Active as i32))
    {
        return Err(PrivacyError::InvalidSecretRow);
    }
    let source = expected
        .source_version
        .parse::<u64>()
        .map_err(|_| PrivacyError::InvalidSecretRow)?;
    sql_version(source)?;
    let audit = expected
        .audit
        .as_ref()
        .ok_or(PrivacyError::InvalidSecretRow)?;
    i64::try_from(audit.wall_time_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
    Ok(source)
}

fn row_disposition(
    physical: u64,
    deleted: bool,
    local: Option<SecretDeletionFloor>,
    committed: Option<SecretDeletionFloor>,
    intended: SecretImportDisposition,
) -> Result<SecretImportDisposition, PrivacyError> {
    if intended == SecretImportDisposition::ScrubOnly
        && committed.is_some_and(|floor| physical <= floor.through_version)
    {
        Ok(SecretImportDisposition::ScrubOnly)
    } else if intended == SecretImportDisposition::Operational
        && !deleted
        && ![local, committed]
            .into_iter()
            .flatten()
            .any(|floor| physical <= floor.through_version)
    {
        Ok(SecretImportDisposition::Operational)
    } else {
        Err(PrivacyError::SecretDeleted)
    }
}

fn deletion_floor(
    conn: &Connection,
    name: &str,
) -> Result<Option<SecretDeletionFloor>, PrivacyError> {
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT through_version, deleted_wall_ms FROM secret_deletion_floors WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(version, wall)| {
        Ok(SecretDeletionFloor {
            through_version: stored_version(version)?,
            applied_wall_ms: stored_wall(wall)?,
        })
    })
    .transpose()
}

fn encrypted_row(
    conn: &Connection,
    name: &str,
    version: u64,
    max_bytes: Option<usize>,
    read_floor: bool,
) -> Result<Option<EncryptedSecretRow>, PrivacyError> {
    if let Some(max_bytes) = max_bytes {
        let lengths: Option<[i64; 6]> = conn
            .query_row(
                "SELECT length(CAST(name AS BLOB)), length(nonce), length(ciphertext), \
             length(version_hash), length(CAST(token_id AS BLOB)), length(CAST(reason AS BLOB)) \
             FROM secrets WHERE name = ?1 AND version = ?2",
                params![name, sql_version(version)?],
                |row| {
                    Ok([
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ])
                },
            )
            .optional()?;
        let Some(lengths) = lengths else {
            return Ok(None);
        };
        // Include space for every scalar fact, even absent deletion diagnostics.
        let mut total = 5 * std::mem::size_of::<u64>();
        for length in lengths {
            let length = usize::try_from(length).map_err(|_| PrivacyError::InvalidSecretRow)?;
            total = total
                .checked_add(length)
                .ok_or(PrivacyError::SecretRowTooLarge)?;
        }
        if total > max_bytes {
            return Err(PrivacyError::SecretRowTooLarge);
        }
    }
    let mut row = conn.query_row(
        "SELECT nonce, ciphertext, version_hash, created_wall_ms, token_id, reason, deleted_wall_ms \
         FROM secrets WHERE name = ?1 AND version = ?2",
        params![name, sql_version(version)?],
        |row| Ok((EncryptedSecretRow {
            name: name.to_owned(), physical_version: version,
            nonce: row.get(0)?, ciphertext: row.get(1)?, version_hash: row.get(2)?,
            created_wall_ms: 0, token_id: row.get(4)?, reason: row.get(5)?,
            deletion_applied_wall_ms: None, known_floor: None,
        }, row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(6)?)),
    ).optional()?;
    if let Some((row, created, deleted)) = row.as_mut() {
        row.created_wall_ms = stored_wall(*created)?;
        row.deletion_applied_wall_ms = deleted.map(stored_wall).transpose()?;
        if read_floor {
            row.known_floor = deletion_floor(conn, name)?;
        }
    }
    Ok(row.map(|(row, _, _)| row))
}

fn apply_deletion(
    conn: &Connection,
    name: &str,
    floor: SecretDeletionFloor,
) -> Result<u32, PrivacyError> {
    let version = sql_version(floor.through_version)?;
    let wall = i64::try_from(floor.applied_wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
    conn.execute(
        "INSERT INTO secret_deletion_floors (name, through_version, deleted_wall_ms) VALUES (?1, ?2, ?3) \
         ON CONFLICT(name) DO UPDATE SET through_version = excluded.through_version, \
         deleted_wall_ms = excluded.deleted_wall_ms \
         WHERE excluded.through_version > secret_deletion_floors.through_version",
        params![name, version, wall],
    )?;
    let n = conn.execute(
        "UPDATE secrets SET deleted_wall_ms = ?3 \
         WHERE name = ?1 AND version <= ?2 AND deleted_wall_ms IS NULL",
        params![name, version, wall],
    )?;
    u32::try_from(n).map_err(|_| PrivacyError::InvalidSecretRow)
}

/// DATA-only routing into the original runtime's existing current-name state.
/// This neither grants caller authority nor proves canonical source custody.
pub trait SecretStoreData: std::any::Any + Send + Sync {
    /// Atomically refuse overlap and keep this physical source pending before SQL.
    fn begin(&self, name: &str, physical_version: u64) -> Result<u64, PrivacyError>;
    /// Record FULL commit only; actual canonical reconciliation still owns readiness.
    fn sql_committed(
        &self,
        name: &str,
        physical_version: u64,
        ticket: u64,
    ) -> Result<(), PrivacyError>;
    /// End only the running interval on error/drop; keep source/current DATA unknown.
    /// This is not rollback evidence, pending settlement or readiness.
    fn sql_aborted(&self, name: &str, physical_version: u64, ticket: u64);
}

struct SecretStoreMutation<'a> {
    data: &'a dyn SecretStoreData,
    name: &'a str,
    physical_version: u64,
    ticket: u64,
    finished: bool,
}

impl SecretStoreMutation<'_> {
    fn committed(mut self) -> Result<(), PrivacyError> {
        self.data
            .sql_committed(self.name, self.physical_version, self.ticket)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for SecretStoreMutation<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.data
                .sql_aborted(self.name, self.physical_version, self.ticket);
        }
    }
}

enum SecretStoreCustody {
    Owned(std::sync::Arc<SecretStoreOwner>),
    Memory(std::sync::Arc<dyn SecretStoreData>),
    ReadOnly,
    #[cfg(test)]
    Fixture,
}

pub(crate) struct SecretStoreOwner {
    root: key_source::DataOwnership,
    directory: std::sync::Arc<std::fs::File>,
    identity: keystore::ffi::FileIdentity,
    data: std::sync::Arc<dyn SecretStoreData>,
}

impl SecretStoreOwner {
    fn check(&self) -> Result<(), PrivacyError> {
        self.root.check_location()?;
        self.root
            .check_directory(Path::new("keys"), &self.directory)?;
        let named = rustix::fs::statat(
            self.directory.as_ref(),
            "secrets.db",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|source| self.root.io(source.into()))?;
        if rustix::fs::FileType::from_raw_mode(named.st_mode) != rustix::fs::FileType::RegularFile
            || named.st_dev as u64 != self.identity.device
            || named.st_ino as u64 != self.identity.inode
        {
            return Err(PrivacyError::SecretStoreUnowned);
        }
        Ok(())
    }
}

/// `keys/secrets.db`.
pub struct SecretStore {
    conn: Mutex<Connection>,
    // Cipher instances copy keys, so create only zeroizing per-operation instances.
    cipher: ProtectedKey,
    hash_key: ProtectedKey,
    fresh_at_open: bool,
    // A pinned legacy read-only snapshot may predate the derived floor table.
    has_floor_table: bool,
    // Declared after the connection so SQLite closes before private staging is removed.
    _snapshot: Option<EncryptedSecretSnapshot>,
    custody: SecretStoreCustody,
}

impl SecretStore {
    /// Reuses an existing original-root DATA route before opening another live connection.
    /// None means only that no live group exists; it proves no database/history absence.
    pub fn owned_data(
        owner: &key_source::DataOwnership,
    ) -> Result<Option<std::sync::Arc<dyn SecretStoreData>>, PrivacyError> {
        let owned = {
            let route = owner.secret_store_route()?;
            route.upgrade()
        };
        owned
            .map(|owned| {
                owned.check()?;
                Ok(owned.data.clone())
            })
            .transpose()
    }

    /// Opens the original root-owned live FILE store with its existing DATA routing.
    /// Every independent connection must reuse that same owner, identity and DATA state.
    pub fn open_owned(
        owner: &key_source::DataOwnership,
        master: &MasterKey,
        data: std::sync::Arc<dyn SecretStoreData>,
    ) -> Result<std::sync::Arc<Self>, PrivacyError> {
        use std::os::unix::fs::PermissionsExt as _;
        let mut route = owner.secret_store_route()?;
        let existing = route.upgrade();
        if let Some(existing) = &existing {
            existing.check()?;
            if !std::sync::Arc::ptr_eq(&existing.data, &data) {
                return Err(PrivacyError::SecretStoreUnowned);
            }
        }
        let directory = owner.directory(Path::new("keys"), true)?;
        owner.check_location()?;
        let path = owner.path().join("keys/secrets.db");
        let conn = Mutex::new(Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?);
        let identity = keystore::ffi::file_identity(
            &conn.lock().map_err(|_| PrivacyError::SecretStoreUnknown)?,
        )?;
        let owned = match existing {
            Some(existing) if existing.identity == identity => existing,
            Some(_) => return Err(PrivacyError::SecretStoreUnowned),
            None => std::sync::Arc::new(SecretStoreOwner {
                root: owner.clone(),
                directory,
                identity,
                data,
            }),
        };
        owned.check()?;
        let conn = conn
            .into_inner()
            .map_err(|_| PrivacyError::SecretStoreUnknown)?;
        let store = Self::open_connection(conn, master, SecretStoreCustody::Owned(owned.clone()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|source| owner.io(source))?;
        owned.check()?;
        *route = std::sync::Arc::downgrade(&owned);
        Ok(std::sync::Arc::new(store))
    }

    /// An independent connection under the SAME original file owner and DATA state.
    pub fn reopen_owned(&self) -> Result<std::sync::Arc<Self>, PrivacyError> {
        let SecretStoreCustody::Owned(owned) = &self.custody else {
            return Err(PrivacyError::SecretStoreUnowned);
        };
        owned.check()?;
        let conn = Mutex::new(Connection::open_with_flags(
            owned.root.path().join("keys/secrets.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?);
        {
            let conn = conn.lock().map_err(|_| PrivacyError::SecretStoreUnknown)?;
            if keystore::ffi::file_identity(&conn)? != owned.identity {
                return Err(PrivacyError::SecretStoreUnowned);
            }
            conn.execute_batch("PRAGMA synchronous = FULL;")?;
        }
        owned.check()?;
        Ok(std::sync::Arc::new(Self {
            conn,
            cipher: self.cipher.clone(),
            hash_key: self.hash_key.clone(),
            fresh_at_open: false,
            has_floor_table: self.has_floor_table,
            _snapshot: None,
            custody: SecretStoreCustody::Owned(owned.clone()),
        }))
    }

    /// Actual original mutable-file ownership; never inferred from a path or DATA adapter.
    /// Performs filesystem identity checks, so call outside bounded DATA publication.
    pub fn data_ownership(&self) -> Result<&key_source::DataOwnership, PrivacyError> {
        let SecretStoreCustody::Owned(owned) = &self.custody else {
            return Err(PrivacyError::SecretStoreUnowned);
        };
        owned.check().map_err(|error| match error {
            PrivacyError::SecretStoreUnowned => PrivacyError::Publication(
                PublicationError::FileIdentity("the original secret-store file changed"),
            ),
            error => error,
        })?;
        Ok(&owned.root)
    }

    /// Private memory has no file-owner certificate, but shares its actual runtime DATA state.
    pub fn open_memory(
        master: &MasterKey,
        data: std::sync::Arc<dyn SecretStoreData>,
    ) -> Result<Self, PrivacyError> {
        Self::open_connection(
            Connection::open_in_memory()?,
            master,
            SecretStoreCustody::Memory(data),
        )
    }

    /// The existing DATA adapter, never a caller authority or complete source proof.
    pub fn data(&self) -> Option<&std::sync::Arc<dyn SecretStoreData>> {
        match &self.custody {
            SecretStoreCustody::Owned(owned) => Some(&owned.data),
            SecretStoreCustody::Memory(data) => Some(data),
            SecretStoreCustody::ReadOnly => None,
            #[cfg(test)]
            SecretStoreCustody::Fixture => None,
        }
    }

    fn begin_mutation<'a>(
        &'a self,
        name: &'a str,
        physical_version: u64,
    ) -> Result<Option<SecretStoreMutation<'a>>, PrivacyError> {
        if let SecretStoreCustody::Owned(owned) = &self.custody {
            owned.check()?;
        }
        let data = match &self.custody {
            SecretStoreCustody::Owned(owned) => owned.data.as_ref(),
            SecretStoreCustody::Memory(data) => data.as_ref(),
            SecretStoreCustody::ReadOnly => return Err(PrivacyError::SecretStoreUnowned),
            #[cfg(test)]
            SecretStoreCustody::Fixture => return Ok(None),
        };
        let ticket = data.begin(name, physical_version)?;
        Ok(Some(SecretStoreMutation {
            data,
            name,
            physical_version,
            ticket,
            finished: false,
        }))
    }

    /// Host recovery fact from the persisted name-bound floor, even without a row at its cut.
    /// None means unknown; this is neither deletion authority nor a durability receipt.
    pub fn stored_deletion_floor(
        &self,
        name: &str,
    ) -> Result<Option<SecretDeletionFloor>, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        if !self.has_floor_table {
            return Ok(None);
        }
        deletion_floor(&self.conn(), name)
    }

    /// Actual per-name physical maximum, including orphan rows and any persisted floor.
    /// Zero is only an empty lower bound, never fresh/never-used evidence or an allocator.
    pub fn physical_highwater(&self, name: &str) -> Result<u64, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // Two primary-key edge seeks also reject an invalid low version without
        // scanning or allocating every row in the name's retained history.
        let (low, high): (Option<i64>, Option<i64>) = tx.query_row(
            "SELECT (SELECT version FROM secrets WHERE name=?1 ORDER BY version LIMIT 1), \
             (SELECT version FROM secrets WHERE name=?1 ORDER BY version DESC LIMIT 1)",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if let Some(low) = low {
            stored_version(low)?;
        }
        let mut high = high.map(stored_version).transpose()?.unwrap_or(0);
        if self.has_floor_table {
            if let Some(floor) = deletion_floor(&tx, name)? {
                high = high.max(floor.through_version);
            }
        }
        tx.commit()?;
        Ok(high)
    }

    /// Reads original row and diagnostic floor from one SQLite snapshot; never decrypts.
    pub fn export_encrypted_row(
        &self,
        name: &str,
        physical_version: u64,
    ) -> Result<Option<EncryptedSecretRow>, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        sql_version(physical_version)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row = encrypted_row(&tx, name, physical_version, None, self.has_floor_table)?;
        tx.commit()?;
        Ok(row)
    }

    /// Caps row payload plus scalar facts before allocating any SQLite BLOB/text.
    /// The caller supplies its actual peer budget and still preflights exact wire size.
    pub fn export_encrypted_row_bounded(
        &self,
        name: &str,
        physical_version: u64,
        max_bytes: usize,
    ) -> Result<Option<EncryptedSecretRow>, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        sql_version(physical_version)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row = encrypted_row(
            &tx,
            name,
            physical_version,
            Some(max_bytes),
            self.has_floor_table,
        )?;
        tx.commit()?;
        Ok(row)
    }

    /// Reads one row from a privately staged, completed and verified encrypted snapshot.
    /// The caller owns snapshot authorization/completion; never pass a live database.
    /// No WAL/journal sidecars, schema writes, or live-store replacement are permitted.
    pub fn export_encrypted_snapshot_row(
        snapshot: &Path,
        name: &str,
        physical_version: u64,
        max_row_bytes: usize,
    ) -> Result<Option<EncryptedSecretRow>, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        sql_version(physical_version)?;
        let snapshot = snapshot
            .canonicalize()
            .map_err(|source| PrivacyError::CustodyIo {
                path: snapshot.display().to_string(),
                source,
            })?;
        require_no_snapshot_sidecars(&snapshot)?;
        let mut uri =
            url::Url::from_file_path(&snapshot).map_err(|_| PrivacyError::InvalidSecretRow)?;
        uri.query_pairs_mut()
            .append_pair("mode", "ro")
            .append_pair("immutable", "1");
        let mut conn = Connection::open_with_flags(
            uri.as_str(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let tx = conn.transaction()?;
        let has_floor_table: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'secret_deletion_floors')",
            [], |row| row.get(0),
        )?;
        let row = encrypted_row(
            &tx,
            name,
            physical_version,
            Some(max_row_bytes),
            has_floor_table,
        )?;
        tx.commit()?;
        Ok(row)
    }

    /// Performs the actual directory fsync; an in-memory SQLite database cannot pass.
    /// This does not replace SQLite's FULL transaction acknowledgement.
    pub fn sync_parent_directory(&self) -> Result<(), PrivacyError> {
        let conn = self.conn();
        let path = conn
            .path()
            .filter(|path| !path.is_empty())
            .ok_or(PrivacyError::FileStoreRequired)?;
        let parent = Path::new(path)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or(PrivacyError::FileStoreRequired)?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| PrivacyError::CustodyIo {
                path: parent.display().to_string(),
                source,
            })
    }

    /// Stages a private, synced encrypted backup for existing snapshot transport.
    pub fn stage_encrypted_snapshot(
        &self,
        parent: &Path,
    ) -> Result<EncryptedSecretSnapshot, PrivacyError> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let io_error = |path: &Path, source| PrivacyError::CustodyIo {
            path: path.display().to_string(),
            source,
        };
        let directory = tempfile::Builder::new()
            .prefix(".secret-custody-")
            .tempdir_in(parent)
            .map_err(|source| io_error(parent, source))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error(directory.path(), source))?;
        let database = directory.path().join("secrets.db");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)
            .map_err(|source| io_error(&database, source))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(&database, source))?;
        self.backup_to(&database)?;
        // rusqlite closes its local destination connection before returning.
        require_no_snapshot_sidecars(&database)?;
        file.sync_all()
            .map_err(|source| io_error(&database, source))?;
        std::fs::File::open(directory.path())
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(directory.path(), source))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))?;
        let database = database
            .canonicalize()
            .map_err(|source| io_error(&database, source))?;
        Ok(EncryptedSecretSnapshot {
            _directory: directory,
            database,
        })
    }

    /// Validates both physical and logical identities, then commits the exact envelope.
    /// `committed_floor` binds an actual physical-name global cut to its local application clock;
    /// a logical alias deletion is never authority to revoke its shared physical reference.
    /// Callers prove current role and canonical identity/source before immutable handoff.
    /// Retained/legacy repair additionally requires the actual original Meta13 descriptor
    /// and old Meta28 binding; a fresh local SET uses its accepted original producer.
    /// Explicit ScrubOnly can install genuine original LIVE bytes without inventing source
    /// deletion history; legacy canonical deleted-value identities stay unchanged.
    /// Body diagnostics never grant authority. Success acknowledges SQLite's FULL commit,
    /// not a separate receipt or operational authorization.
    pub fn import_encrypted_row(
        &self,
        expected: &kronik_proto::log::v1::SecretVersion,
        row: &EncryptedSecretRow,
        committed_floor: Option<(&str, SecretDeletionFloor)>,
        intended: SecretImportDisposition,
    ) -> Result<SecretImportDisposition, PrivacyError> {
        if !valid_name(&row.name) {
            return Err(PrivacyError::InvalidName(row.name.clone()));
        }
        sql_version(row.physical_version)?;
        let mutation = self.begin_mutation(&row.name, row.physical_version)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let byte_limit = usize::try_from(tx.limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)?)
            .map_err(|_| PrivacyError::InvalidSecretRow)?;
        if [
            row.name.len(),
            row.nonce.len(),
            row.ciphertext.len(),
            row.version_hash.len(),
            row.token_id.len(),
            row.reason.len(),
        ]
        .into_iter()
        .any(|length| length > byte_limit)
        {
            return Err(PrivacyError::InvalidSecretRow);
        }
        let committed_floor = committed_floor
            .map(|(name, floor)| {
                if name != row.name {
                    return Err(PrivacyError::InvalidSecretRow);
                }
                Ok(floor)
            })
            .transpose()?;
        let source = file_source_version(expected, intended)?;
        let created =
            i64::try_from(row.created_wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        if expected.r#ref != row.name
            || source != row.physical_version
            || row.version_hash.len() != 16
        {
            return Err(PrivacyError::InvalidSecretRow);
        }
        if let Some(wall) = row.deletion_applied_wall_ms {
            i64::try_from(wall).map_err(|_| PrivacyError::InvalidTimestamp)?;
        }
        for floor in [committed_floor, row.known_floor].into_iter().flatten() {
            sql_version(floor.through_version)?;
            i64::try_from(floor.applied_wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        }
        if row.nonce.is_empty() && row.ciphertext.is_empty() {
            return Err(PrivacyError::SecretRowIncomplete);
        }
        if row.nonce.len() != 24 || row.ciphertext.len() < 16 {
            return Err(PrivacyError::InvalidSecretRow);
        }
        // Diagnostics never choose purpose or grant authority. Operational cannot upgrade
        // to ScrubOnly; only the explicit intent plus independent canonical floor permits it.
        let local_floor = deletion_floor(&tx, &row.name)?;
        let disposition = row_disposition(
            row.physical_version,
            row.deletion_applied_wall_ms.is_some(),
            local_floor,
            committed_floor,
            intended,
        )?;
        self.check_encrypted_identity(
            expected,
            row.physical_version,
            &row.nonce,
            &row.ciphertext,
            &row.version_hash,
        )?;
        // Compare borrowed SQLite fields without copying a second large ciphertext.
        let existing: Option<(bool, bool, bool, Option<i64>)> = tx.query_row(
            "SELECT nonce, ciphertext, version_hash, created_wall_ms, token_id, reason, deleted_wall_ms \
             FROM secrets WHERE name = ?1 AND version = ?2",
            params![row.name, sql_version(row.physical_version)?],
            |existing| {
                use rusqlite::types::ValueRef::{Blob, Text};
                let nonce = existing.get_ref(0)?;
                let ciphertext = existing.get_ref(1)?;
                let facts_match = existing.get_ref(2)? == Blob(&row.version_hash)
                    && existing.get::<_, i64>(3)? == created
                    && existing.get_ref(4)? == Text(row.token_id.as_bytes())
                    && existing.get_ref(5)? == Text(row.reason.as_bytes());
                Ok((facts_match, nonce == Blob(&[]) && ciphertext == Blob(&[]),
                    nonce == Blob(&row.nonce) && ciphertext == Blob(&row.ciphertext), existing.get(6)?))
            },
        ).optional()?;
        if let Some((facts_match, legacy_empty, envelope_matches, deleted)) = existing {
            let deleted = deleted.map(stored_wall).transpose()?;
            if deleted.is_some() && disposition == SecretImportDisposition::Operational {
                return Err(PrivacyError::SecretDeleted);
            }
            if !facts_match {
                return Err(PrivacyError::SecretRowConflict);
            }
            if legacy_empty
                && deleted.is_some()
                && disposition == SecretImportDisposition::ScrubOnly
            {
                // Only genuine caller-authenticated original ciphertext may repair
                // a legacy erased row; its retained audit and deletion facts stay put.
                tx.execute(
                    "UPDATE secrets SET nonce = ?3, ciphertext = ?4 WHERE name = ?1 AND version = ?2",
                    params![row.name, sql_version(row.physical_version)?, row.nonce, row.ciphertext],
                )?;
            } else if !envelope_matches {
                return Err(PrivacyError::SecretRowConflict);
            }
        } else {
            tx.execute(
                "INSERT INTO secrets (name, version, nonce, ciphertext, version_hash, created_wall_ms, \
                 token_id, reason, deleted_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
                params![row.name, sql_version(row.physical_version)?, row.nonce, row.ciphertext,
                    row.version_hash, created, row.token_id, row.reason],
            )?;
        }
        if let Some(floor) = committed_floor {
            apply_deletion(&tx, &row.name, floor)?;
        }
        tx.commit()?;
        drop(conn);
        if let Some(mutation) = mutation {
            mutation.committed()?;
        }
        Ok(disposition)
    }

    /// Read-only validation of an already committed local copy, without cloning its ciphertext.
    /// The caller still proves source/role and performs actual parent-directory sync before ACK.
    /// The expected raw ciphertext digest is identity data, never authority or a receipt.
    /// A supplied deletion floor must already be committed locally; this never installs it.
    pub fn verify_encrypted_row(
        &self,
        expected: &kronik_proto::log::v1::SecretVersion,
        ciphertext_hash: &[u8; 32],
        committed_floor: Option<(&str, SecretDeletionFloor)>,
        intended: SecretImportDisposition,
    ) -> Result<Option<SecretImportDisposition>, PrivacyError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let physical = file_source_version(expected, intended)?;
        let committed_floor = committed_floor
            .map(|(name, floor)| {
                if name != expected.r#ref {
                    return Err(PrivacyError::InvalidSecretRow);
                }
                sql_version(floor.through_version)?;
                i64::try_from(floor.applied_wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
                Ok(floor)
            })
            .transpose()?;
        let local_floor = deletion_floor(&tx, &expected.r#ref)?;
        let byte_limit = usize::try_from(tx.limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH)?)
            .map_err(|_| PrivacyError::InvalidSecretRow)?;
        let disposition = {
            let mut statement = tx.prepare(
                "SELECT nonce, ciphertext, version_hash, created_wall_ms, token_id, reason, deleted_wall_ms \
                 FROM secrets WHERE name = ?1 AND version = ?2",
            )?;
            let mut rows = statement.query(params![expected.r#ref, sql_version(physical)?])?;
            if let Some(stored) = rows.next()? {
                let nonce = stored
                    .get_ref(0)?
                    .as_blob()
                    .map_err(|_| PrivacyError::InvalidSecretRow)?;
                let ciphertext = stored
                    .get_ref(1)?
                    .as_blob()
                    .map_err(|_| PrivacyError::InvalidSecretRow)?;
                let physical_hash = stored
                    .get_ref(2)?
                    .as_blob()
                    .map_err(|_| PrivacyError::InvalidSecretRow)?;
                stored_wall(stored.get(3)?)?;
                let token = stored
                    .get_ref(4)?
                    .as_str()
                    .map_err(|_| PrivacyError::InvalidSecretRow)?;
                let reason = stored
                    .get_ref(5)?
                    .as_str()
                    .map_err(|_| PrivacyError::InvalidSecretRow)?;
                let deleted = stored
                    .get::<_, Option<i64>>(6)?
                    .map(stored_wall)
                    .transpose()?;
                if nonce.is_empty() && ciphertext.is_empty() {
                    return Err(PrivacyError::SecretRowIncomplete);
                }
                if nonce.len() != 24
                    || ciphertext.len() < 16
                    || physical_hash.len() != 16
                    || [
                        expected.r#ref.len(),
                        nonce.len(),
                        ciphertext.len(),
                        physical_hash.len(),
                        token.len(),
                        reason.len(),
                    ]
                    .into_iter()
                    .any(|length| length > byte_limit)
                {
                    return Err(PrivacyError::InvalidSecretRow);
                }
                if committed_floor.is_some_and(|floor| {
                    local_floor.is_none_or(|local| local.through_version < floor.through_version)
                }) {
                    return Err(PrivacyError::SecretRowIncomplete);
                }
                if intended == SecretImportDisposition::ScrubOnly && deleted.is_none() {
                    return Err(PrivacyError::SecretRowIncomplete);
                }
                let disposition = row_disposition(
                    physical,
                    deleted.is_some(),
                    local_floor,
                    committed_floor,
                    intended,
                )?;
                if blake3::hash(ciphertext).as_bytes() != ciphertext_hash {
                    return Err(PrivacyError::InvalidSecretRow);
                }
                self.check_encrypted_identity(
                    expected,
                    physical,
                    nonce,
                    ciphertext,
                    physical_hash,
                )?;
                Some(disposition)
            } else {
                None
            }
        };
        tx.commit()?;
        Ok(disposition)
    }

    // Only the private create-new encrypted stage selects a backup destination.
    fn backup_to(&self, path: &std::path::Path) -> Result<(), PrivacyError> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner()).backup(
            rusqlite::MAIN_DB,
            path,
            None::<fn(rusqlite::backup::Progress)>,
        )?;
        Ok(())
    }

    /// Uses an actual SQLite read-only connection; the caller retains its source lifetime.
    /// No schema/key-check writes or mutable/current-source ownership are created.
    /// Live inventory must complete the SQLite backup stage before qualifying its rows.
    pub fn open_readonly(conn: Connection, master: &MasterKey) -> Result<Self, PrivacyError> {
        if !conn.is_readonly("main")? {
            return Err(PrivacyError::SecretStoreUnowned);
        }
        let invalid: Option<i64> = conn
            .query_row(
                "SELECT version FROM secrets WHERE version <= 0 OR version > ?1 LIMIT 1",
                [sql_version(kronik_proto::secret::MAX_SECRET_VERSION)?],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(version) = invalid {
            return Err(PrivacyError::InvalidStoredVersion(version));
        }
        let (has_check, has_floor_table): (bool, bool) = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='key_check'), \
             EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='secret_deletion_floors')",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if has_check {
            let want = master.check_value();
            let matches: Option<bool> = conn
                .query_row("SELECT value FROM key_check WHERE id=1", [], |row| {
                    Ok(row.get_ref(0)? == rusqlite::types::ValueRef::Blob(&want))
                })
                .optional()?;
            if matches == Some(false) {
                return Err(PrivacyError::KeyMismatch(
                    "the secret snapshot was encrypted under another master key".into(),
                ));
            }
        }
        // Legacy sources without a verifier prove the key by actual per-row decryption.
        // Never pre-copy/decrypt an entire large row or certify erased values at open.
        Ok(SecretStore {
            conn: Mutex::new(conn),
            cipher: master.derive("kronik secrets v1")?,
            hash_key: master.derive("kronik secret version v1")?,
            fresh_at_open: false,
            has_floor_table,
            _snapshot: None,
            custody: SecretStoreCustody::ReadOnly,
        })
    }

    #[cfg(test)]
    fn open(conn: Connection, master: &MasterKey) -> Result<SecretStore, PrivacyError> {
        Self::open_connection(conn, master, SecretStoreCustody::Fixture)
    }

    fn open_connection(
        conn: Connection,
        master: &MasterKey,
        custody: SecretStoreCustody,
    ) -> Result<SecretStore, PrivacyError> {
        // Lost/deleted rows in an existing schema do not make legacy history fresh.
        let schema_version: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        let fresh_at_open = schema_version == 0
            && conn.query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
        let cipher = master.derive("kronik secrets v1")?;
        let hash_key = master.derive("kronik secret version v1")?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        conn.execute_batch(SCHEMA)?;
        let store = SecretStore {
            conn: Mutex::new(conn),
            cipher,
            hash_key,
            fresh_at_open,
            has_floor_table: true,
            _snapshot: None,
            custody,
        };
        {
            let conn = store.conn();
            let invalid: Option<i64> = conn
                .query_row(
                    "SELECT version FROM secrets WHERE version <= 0 OR version > ?1 LIMIT 1",
                    [sql_version(kronik_proto::secret::MAX_SECRET_VERSION)?],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(version) = invalid {
                return Err(PrivacyError::InvalidStoredVersion(version));
            }
            let mut floors = conn.prepare(
                "SELECT name, through_version, deleted_wall_ms FROM secret_deletion_floors",
            )?;
            let rows = floors.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (name, version, wall) = row?;
                if !valid_name(&name) {
                    return Err(PrivacyError::InvalidSecretRow);
                }
                stored_version(version)?;
                stored_wall(wall)?;
            }
            check_key(&conn, master, "the secret store", || {
                let row: Option<(String, i64, Vec<u8>, Vec<u8>)> = conn
                    .query_row(
                        "SELECT name, version, nonce, ciphertext FROM secrets \
                         WHERE length(ciphertext) > 0 LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                let Some((name, version, nonce, ct)) = row else {
                    return Ok(true);
                };
                let version = stored_version(version)?;
                Ok(store
                    .decrypt(&name, version, &nonce, &ct)
                    .map(Zeroizing::new)
                    .is_ok())
            })?;
        }
        Ok(store)
    }

    /// Pre-schema evidence used with the journal's own fresh-at-open evidence.
    pub fn fresh_at_open(&self) -> bool {
        self.fresh_at_open
    }

    fn validate_legacy_key(conn: &Connection, master: &MasterKey) -> Result<bool, PrivacyError> {
        let row: Option<(String, i64, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT name, version, nonce, ciphertext FROM secrets WHERE length(ciphertext) > 0 LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((name, version, nonce, ciphertext)) = row else {
            return Ok(true);
        };
        let version = stored_version(version)?;
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

    /// The keyed immutable identity; legacy identities retain their exact bytes.
    pub fn version_hash(
        &self,
        name: &str,
        version: u64,
        value: &[u8],
    ) -> Result<Vec<u8>, PrivacyError> {
        secret_version_hash(&self.hash_key, name, version, value)
    }

    fn aad(name: &str, version: u64) -> Vec<u8> {
        format!("{name}|{version}").into_bytes()
    }

    fn encrypt(
        &self,
        name: &str,
        version: u64,
        value: &[u8],
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, PrivacyError> {
        XChaCha20Poly1305::new(self.cipher.bytes().into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: value,
                    aad: &Self::aad(name, version),
                },
            )
            .map_err(|_| PrivacyError::Decrypt(name.to_owned()))
    }

    /// Prepares exact custody bytes for reservation preflight without accessing SQLite.
    /// This is not persistence or authorization; import still checks the committed floor.
    /// `nonce` must be fresh randomness for this physical version and value.
    pub fn prepare_encrypted_row(
        &self,
        name: &str,
        physical_version: u64,
        value: &[u8],
        nonce: [u8; 24],
        wall_ms: u64,
        token_id: &str,
        reason: &str,
    ) -> Result<EncryptedSecretRow, PrivacyError> {
        i64::try_from(wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        let version_hash = self.version_hash(name, physical_version, value)?;
        let ciphertext = self.encrypt(name, physical_version, value, nonce)?;
        Ok(EncryptedSecretRow {
            name: name.to_owned(),
            physical_version,
            nonce: nonce.to_vec(),
            ciphertext,
            version_hash,
            created_wall_ms: wall_ms,
            token_id: token_id.to_owned(),
            reason: reason.to_owned(),
            deletion_applied_wall_ms: None,
            known_floor: None,
        })
    }

    /// Stores an explicitly reserved immutable version. `nonce` must be fresh randomness.
    pub fn set_at(
        &self,
        name: &str,
        version: u64,
        value: &[u8],
        nonce: [u8; 24],
        wall_ms: u64,
        token_id: &str,
        reason: &str,
    ) -> Result<SecretMeta, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        let sql_version = sql_version(version)?;
        let wall = i64::try_from(wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        let mutation = self.begin_mutation(name, version)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        if deletion_floor(&tx, name)?.is_some_and(|floor| version <= floor.through_version) {
            return Err(PrivacyError::SecretDeleted);
        }
        let ciphertext = self.encrypt(name, version, value, nonce)?;
        let version_hash = self.version_hash(name, version, value)?;
        tx.execute(
            "INSERT INTO secrets (name, version, nonce, ciphertext, version_hash, created_wall_ms, token_id, reason) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![name, sql_version, &nonce[..], ciphertext, version_hash, wall, token_id, reason],
        )?;
        tx.commit()?;
        drop(conn);
        if let Some(mutation) = mutation {
            mutation.committed()?;
        }
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
        version: u64,
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

    fn check_encrypted_identity(
        &self,
        expected: &kronik_proto::log::v1::SecretVersion,
        physical: u64,
        nonce: &[u8],
        ciphertext: &[u8],
        stored_hash: &[u8],
    ) -> Result<(), PrivacyError> {
        let value = Zeroizing::new(self.decrypt(&expected.r#ref, physical, nonce, ciphertext)?);
        let physical_hash = self.version_hash(&expected.r#ref, physical, &value)?;
        if physical_hash.as_slice() != stored_hash {
            return Err(PrivacyError::InvalidSecretRow);
        }
        let logical_hash = if expected.name == expected.r#ref && expected.version == physical {
            physical_hash
        } else {
            self.version_hash(&expected.name, expected.version, &value)?
        };
        if logical_hash != expected.version_hash {
            return Err(PrivacyError::InvalidSecretRow);
        }
        Ok(())
    }

    fn read(
        &self,
        name: &str,
        version: Option<u64>,
        retained_for_scrub: bool,
    ) -> Result<Option<SecretValue>, PrivacyError> {
        let version = version.map(sql_version).transpose()?;
        let conn = self.conn();
        type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);
        let row: Option<Row> = match version {
            None => conn
                .query_row(
                    current_secret_query!(
                        "version, nonce, ciphertext, version_hash, created_wall_ms"
                    ),
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?,
            Some(v) => conn
                .query_row(
                    "SELECT version, nonce, ciphertext, version_hash, created_wall_ms FROM secrets \
                     WHERE name = ?1 AND version = ?2 AND (?3 OR deleted_wall_ms IS NULL)",
                    params![name, v, retained_for_scrub],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?,
        };
        drop(conn);
        let Some((version, nonce, ct, version_hash, created)) = row else {
            return Ok(None);
        };
        let version = stored_version(version)?;
        let value = self.decrypt(name, version, &nonce, &ct)?;
        Ok(Some(SecretValue {
            meta: SecretMeta {
                name: name.to_owned(),
                version,
                version_hash,
                created_wall_ms: stored_wall(created)?,
            },
            value,
        }))
    }

    /// The newest version of `name`, unless deleted.
    pub fn current(&self, name: &str) -> Result<Option<SecretValue>, PrivacyError> {
        self.read(name, None, false)
    }

    /// The same current physical row as `current`, without reading or decrypting its ciphertext.
    /// Metadata is not custody/authority proof; absence does not establish complete history.
    pub fn current_meta(&self, name: &str) -> Result<Option<SecretMeta>, PrivacyError> {
        let conn = self.conn();
        let row: Option<(i64, Vec<u8>, i64)> = conn
            .query_row(
                current_secret_query!("version, version_hash, created_wall_ms"),
                [name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(version, version_hash, created)| {
            Ok(SecretMeta {
                name: name.to_owned(),
                version: stored_version(version)?,
                version_hash,
                created_wall_ms: stored_wall(created)?,
            })
        })
        .transpose()
    }

    /// One specific version (re-runs use the recorded version).
    pub fn version(&self, name: &str, version: u64) -> Result<Option<SecretValue>, PrivacyError> {
        self.read(name, Some(version), false)
    }

    /// Host inventory only: a deleted encrypted value remains a scrub needle,
    /// never operational authorization. Legacy erased rows return a decrypt error.
    /// Do not expose this path through FileBackend, guests, replay, or HMAC.
    pub fn retained_version_for_scrub(
        &self,
        name: &str,
        physical_version: u64,
    ) -> Result<Option<SecretValue>, PrivacyError> {
        self.read(name, Some(physical_version), true)
    }

    /// The newest version of every secret that is not deleted.
    pub fn list(&self) -> Result<Vec<SecretMeta>, PrivacyError> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT name, max(version), created_wall_ms, version_hash FROM secrets \
             WHERE deleted_wall_ms IS NULL GROUP BY name ORDER BY name",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (name, version, created, version_hash) = row?;
            Ok(SecretMeta {
                name,
                version: stored_version(version)?,
                created_wall_ms: stored_wall(created)?,
                version_hash,
            })
        })
        .collect()
    }

    /// At most 256 rows, ordered by `(name, version)`, without reading values.
    /// Pass the last row's identity to continue; include tombstones for legacy import.
    pub fn metadata_page(
        &self,
        after: Option<(&str, u64)>,
        include_deleted: bool,
    ) -> Result<Vec<SecretRowMeta>, PrivacyError> {
        let (name, version) = match after {
            // Zero is only a lower-bound cursor; never a stored/resolved identity.
            Some((name, 0)) => (name, 0),
            Some((name, version)) => (name, sql_version(version)?),
            None => ("", 0),
        };
        let conn = self.conn();
        let mut statement = conn.prepare(
            "SELECT name, version, created_wall_ms, version_hash, deleted_wall_ms \
             FROM secrets WHERE (name, version) > (?1, ?2) \
             AND (?3 OR deleted_wall_ms IS NULL) ORDER BY name, version LIMIT 256",
        )?;
        let rows = statement.query_map(params![name, version, include_deleted], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (name, version, created, version_hash, deleted) = row?;
            Ok(SecretRowMeta {
                meta: SecretMeta {
                    name,
                    version: stored_version(version)?,
                    version_hash,
                    created_wall_ms: stored_wall(created)?,
                },
                deletion_applied_wall_ms: deleted.map(stored_wall).transpose()?,
            })
        })
        .collect()
    }

    /// Denies all physical versions through a committed floor; retains encrypted scrub needles.
    /// A missing row is not evidence of no prior deletion; no synthetic row is made.
    /// `applied_wall_ms` is an actual local pin or worker-sampled application time, not audit time.
    pub fn delete(
        &self,
        name: &str,
        through_version: u64,
        applied_wall_ms: u64,
    ) -> Result<u32, PrivacyError> {
        if !valid_name(name) {
            return Err(PrivacyError::InvalidName(name.to_owned()));
        }
        sql_version(through_version)?;
        i64::try_from(applied_wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        let mutation = self.begin_mutation(name, through_version)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let n = apply_deletion(
            &tx,
            name,
            SecretDeletionFloor {
                through_version,
                applied_wall_ms,
            },
        )?;
        tx.commit()?;
        drop(conn);
        if let Some(mutation) = mutation {
            mutation.committed()?;
        }
        Ok(n)
    }

    /// Every stored secret value, every version of it (a rotated value can
    /// still be in logs and outputs written before the rotation), for
    /// scanning outputs (scrubbing), including deleted encrypted versions.
    /// Legacy erased rows fail rather than claiming complete scrub coverage.
    pub fn values(&self) -> Result<Vec<(String, Vec<u8>)>, PrivacyError> {
        let rows: Vec<(String, i64, Vec<u8>, Vec<u8>)> = {
            let conn = self.conn();
            let mut st = conn.prepare(
                "SELECT name, version, nonce, ciphertext FROM secrets ORDER BY name, version DESC",
            )?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(rows.len());
        for (name, version, nonce, ct) in rows {
            let value = match stored_version(version)
                .and_then(|version| self.decrypt(&name, version, &nonce, &ct))
            {
                Ok(value) => value,
                Err(error) => {
                    for (_, value) in &mut out {
                        value.zeroize();
                    }
                    return Err(error);
                }
            };
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
    fn an_empty_or_deleted_legacy_store_is_not_fresh_allocation_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.db");
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        {
            let store = SecretStore::open(Connection::open(&path).unwrap(), &master).unwrap();
            assert!(store.fresh_at_open());
            store
                .set_at("lost-name", 7, b"retained", [3; 24], 1, "admin", "set")
                .unwrap();
            store.conn().execute("DELETE FROM secrets", []).unwrap();
        }
        let reopened = SecretStore::open(Connection::open(&path).unwrap(), &master).unwrap();
        assert!(reopened.list().unwrap().is_empty());
        assert!(!reopened.fresh_at_open());
        drop(reopened);
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        assert!(!SecretStore::open(conn, &master).unwrap().fresh_at_open());
    }

    #[test]
    fn explicit_versions_cross_legacy_boundary_and_reopen_immutably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.db");
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let versions = [
            kronik_proto::secret::LEGACY_SECRET_VERSION_MAX,
            kronik_proto::secret::LEGACY_SECRET_VERSION_MAX + 1,
            kronik_proto::secret::MAX_SECRET_VERSION,
        ];
        {
            let s = SecretStore::open(Connection::open(&path).unwrap(), &master).unwrap();
            for (i, version) in versions.into_iter().enumerate() {
                let value = [i as u8; 8];
                let meta = s
                    .set_at(
                        "token",
                        version,
                        &value,
                        [i as u8; 24],
                        10,
                        "admin",
                        "rotate",
                    )
                    .unwrap();
                assert_eq!(meta.version, version);
                assert_eq!(s.version("token", version).unwrap().unwrap().value, value);
                assert!(
                    s.set_at(
                        "token",
                        version,
                        b"replacement",
                        [9; 24],
                        11,
                        "other",
                        "replace"
                    )
                    .is_err()
                );
                assert_eq!(s.version("token", version).unwrap().unwrap().meta, meta);
                assert_eq!(s.version("token", version).unwrap().unwrap().value, value);
            }
            assert!(s.version("token", versions[1] + 1).unwrap().is_none());
            assert!(s.version("missing", versions[0]).unwrap().is_none());
        }
        let s = SecretStore::open(Connection::open(&path).unwrap(), &master).unwrap();
        assert_eq!(
            s.current("token").unwrap().unwrap().meta.version,
            versions[2]
        );
        assert_eq!(s.list().unwrap()[0].version, versions[2]);
        assert_eq!(s.values().unwrap().len(), 3);
        assert_eq!(s.delete("token", versions[2], 12).unwrap(), 3);
        assert!(s.current("token").unwrap().is_none());
        for version in versions {
            assert!(s.version("token", version).unwrap().is_none());
            assert!(
                s.set_at("token", version, b"resurrect", [8; 24], 13, "", "")
                    .is_err()
            );
        }
        assert_eq!(s.values().unwrap().len(), 3);
        assert_eq!(s.metadata_page(None, true).unwrap().len(), 3);
        assert!(s.metadata_page(None, false).unwrap().is_empty());
        drop(s);
        let s = SecretStore::open(Connection::open(&path).unwrap(), &master).unwrap();
        assert!(s.current("token").unwrap().is_none());
        assert_eq!(
            s.metadata_page(None, true).unwrap()[2].meta.version,
            versions[2]
        );
    }

    #[test]
    fn wide_hash_domain_and_decimal_aad_are_explicit() {
        let s = store(7);
        let version = u64::from(u32::MAX) + 1;
        let meta = s
            .set_at("token", version, b"value", [3; 24], 0, "", "")
            .unwrap();
        let key = blake3::derive_key("kronik secret version v1", &[7; 32]);
        let mut hash = blake3::Hasher::new_keyed(&key);
        hash.update(b"kronik secret version v2\0token\0");
        hash.update(&[0, 0, 0, 0, 1, 0, 0, 0]);
        hash.update(b"\0value");
        assert_eq!(meta.version_hash, hash.finalize().as_bytes()[..16]);
        assert_eq!(
            s.version_hash("token", version, b"value").unwrap(),
            meta.version_hash
        );
        let cipher_key = blake3::derive_key("kronik secrets v1", &[7; 32]);
        let expected = XChaCha20Poly1305::new((&cipher_key).into())
            .encrypt(
                &XNonce::from([3; 24]),
                Payload {
                    msg: b"value",
                    aad: b"token|4294967296",
                },
            )
            .unwrap();
        let ciphertext: Vec<u8> = s
            .conn()
            .query_row(
                "SELECT ciphertext FROM secrets WHERE name='token'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ciphertext, expected);
        s.conn().execute_batch("DROP TABLE key_check").unwrap();
        assert!(
            SecretStore::validate_legacy_key(&s.conn(), &MasterKey::from_bytes([7; 32]).unwrap())
                .unwrap()
        );
        assert!(
            !SecretStore::validate_legacy_key(&s.conn(), &MasterKey::from_bytes([8; 32]).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn invalid_versions_and_corrupt_sql_rows_fail_closed() {
        let s = store(7);
        for version in [0, kronik_proto::secret::MAX_SECRET_VERSION + 1, u64::MAX] {
            assert!(
                matches!(s.set_at("token", version, b"value", [3; 24], 0, "", ""), Err(PrivacyError::InvalidVersion(v)) if v == version)
            );
            assert!(
                matches!(s.version_hash("token", version, b"value"), Err(PrivacyError::InvalidVersion(v)) if v == version)
            );
            assert!(
                matches!(s.version("token", version), Err(PrivacyError::InvalidVersion(v)) if v == version)
            );
        }
        s.set_at("token", 1, b"value", [3; 24], 0, "", "").unwrap();
        for version in [
            -1,
            0,
            i64::try_from(kronik_proto::secret::MAX_SECRET_VERSION + 1).unwrap(),
        ] {
            s.conn()
                .execute("UPDATE secrets SET version=?1", [version])
                .unwrap();
            assert!(
                matches!(s.current("token"), Err(PrivacyError::InvalidStoredVersion(v)) if v == version)
            );
            assert!(matches!(s.list(), Err(PrivacyError::InvalidStoredVersion(v)) if v == version));
            assert!(
                matches!(s.values(), Err(PrivacyError::InvalidStoredVersion(v)) if v == version)
            );
            assert!(
                matches!(s.metadata_page(None, true), Err(PrivacyError::InvalidStoredVersion(v)) if v == version)
            );
            assert!(
                matches!(SecretStore::validate_legacy_key(&s.conn(), &MasterKey::from_bytes([7; 32]).unwrap()), Err(PrivacyError::InvalidStoredVersion(v)) if v == version)
            );
        }
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO secrets VALUES ('token', -1, x'', x'', x'', 0, '', '', NULL)",
            [],
        )
        .unwrap();
        assert!(matches!(
            SecretStore::open(conn, &MasterKey::from_bytes([7; 32]).unwrap()),
            Err(PrivacyError::InvalidStoredVersion(-1))
        ));
    }

    #[test]
    fn metadata_pages_retain_every_version_and_tombstone_audit() {
        let s = store(7);
        for version in 1..=258 {
            s.set_at(
                "token",
                version,
                b"value",
                [version as u8; 24],
                version,
                "admin",
                "import",
            )
            .unwrap();
        }
        let first = s.metadata_page(None, false).unwrap();
        assert_eq!(first.len(), 256);
        assert_eq!(first[0].meta.version, 1);
        assert_eq!(first[255].meta.version, 256);
        let rest = s.metadata_page(Some(("token", 256)), false).unwrap();
        assert_eq!(rest.len(), 2);
        assert_eq!(rest[1].meta.version, 258);
        assert!(
            s.metadata_page(Some(("token", 258)), false)
                .unwrap()
                .is_empty()
        );
        s.delete("token", 258, 300).unwrap();
        let first = s.metadata_page(None, true).unwrap();
        assert_eq!(first.len(), 256);
        assert_eq!(first[0].deletion_applied_wall_ms, Some(300));
        assert!(!first[0].meta.version_hash.is_empty());
        assert!(s.metadata_page(None, false).unwrap().is_empty());
    }

    #[test]
    fn protected_keys_preserve_cipher_hash_and_verifier_bytes() {
        fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroizes_on_drop::<XChaCha20Poly1305>();
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        let s = SecretStore::open(Connection::open_in_memory().unwrap(), &master).unwrap();
        let meta = s.set_at("token", 1, b"value", [3; 24], 0, "", "").unwrap();
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
            let owner = key_source::lock_data(dir.path()).unwrap();
            let keys = dir.path().join("keys");
            std::fs::create_dir(&keys).unwrap();
            let right = MasterKey::from_bytes([1; 32]).unwrap();
            let wrong = MasterKey::from_bytes([2; 32]).unwrap();
            right.validate_stores(&keys).unwrap();
            let secrets = keys.join("secrets.db");
            let subjects = keys.join("keystore.db");
            SecretStore::open(Connection::open(&secrets).unwrap(), &right)
                .unwrap()
                .set_at("token", 1, b"value", [1; 24], 0, "", "")
                .unwrap();
            keystore::Keystore::open_owned(&owner, &right)
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
            right.validate_stores(&keys).unwrap();
            assert!(matches!(
                wrong.validate_stores(&keys),
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
            .set_at("stripe-key", 1, b"sk_live_1", [1; 24], 10, "t", "r")
            .unwrap();
        let b = s
            .set_at("stripe-key", 2, b"sk_live_2", [2; 24], 11, "t", "r")
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
            .set_at("stripe-key", 1, b"sk_live_1", [1; 24], 10, "t", "r")
            .unwrap();
        assert_ne!(other.version_hash, a.version_hash);
        assert_eq!(s.delete("stripe-key", b.version, 12).unwrap(), 2);
        assert!(s.current("stripe-key").unwrap().is_none());
        assert_eq!(s.values().unwrap().len(), 2);
        assert!(s.list().unwrap().is_empty());
        assert!(matches!(
            s.set_at("Bad Name", 1, b"x", [0; 24], 0, "t", "r"),
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
            s.set_at(
                "db-password",
                1,
                b"hunter2-very-secret",
                [3; 24],
                1,
                "t",
                "r",
            )
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
            .set_at("a", 1, b"value-1", [3; 24], 1, "t", "r")
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
        // The right key passes and is recorded; deletion cannot bless another key.
        let s = SecretStore::open(Connection::open(&path).unwrap(), &right).unwrap();
        s.delete("a", 1, 2).unwrap();
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
