//! The privacy keystore, `keys/keystore.db` (docs/design/m8-privacy.md): one
//! XChaCha20-Poly1305 key per subject, versioned, each stored wrapped
//! (encrypted) under a key derived from the master key. Erasing a subject
//! deletes its keys and records the last version, so values sealed with any
//! of them read as erased forever, even if the subject id is used again.
//! Also: sealing and unsealing one value, the keyed pseudonyms of `--no-pii`
//! forks, and an encrypted backup of the whole keystore for shipping.
//!
//! Keys never leave this module except as [`SubjectKey`], whose `Debug`
//! hides them, and nothing here logs.

use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::key_memory::ProtectedKey;
use crate::{MasterKey, PrivacyError, hex};

mod prepared;
pub use prepared::PreparedSubjectKey;
mod owned;
pub(crate) mod ffi;
pub use owned::KeystoreRestore;
use owned::Custody;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS subject_keys (
  subject TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL,
  wrapped BLOB NOT NULL, created_wall_ms INTEGER NOT NULL,
  PRIMARY KEY (subject, version)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS erasures (
  subject TEXT PRIMARY KEY, last_version INTEGER NOT NULL,
  erased_wall_ms INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS keystore_revision (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  revision INTEGER NOT NULL CHECK (typeof(revision) = 'integer' AND revision >= 0));
INSERT OR IGNORE INTO keystore_revision VALUES (1, 0);
CREATE TRIGGER IF NOT EXISTS subject_keys_revision_insert AFTER INSERT ON subject_keys
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS subject_keys_revision_update AFTER UPDATE ON subject_keys
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS subject_keys_revision_delete AFTER DELETE ON subject_keys
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS erasures_revision_insert AFTER INSERT ON erasures
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS erasures_revision_update AFTER UPDATE ON erasures
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER IF NOT EXISTS erasures_revision_delete AFTER DELETE ON erasures
BEGIN UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1; END;
";

/// The start of an exported backup; also its associated data.
const BACKUP_MAGIC: &[u8; 8] = b"KRKSTOR1";

/// The longest subject accepted, in bytes.
pub const MAX_SUBJECT_BYTES: usize = 256;

/// Whether `subject` can be a subject: 1 to [`MAX_SUBJECT_BYTES`] bytes of
/// printable ASCII without spaces, such as `user:123`.
pub fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_SUBJECT_BYTES
        && subject.bytes().all(|b| b.is_ascii_graphic())
}

/// One version of a subject's key.
#[derive(Clone)]
pub struct SubjectKey {
    pub version: u32,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SubjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectKey")
            .field("version", &self.version)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// What looking up a subject's key version finds.
#[derive(Debug)]
pub enum KeyLookup {
    Found(SubjectKey),
    /// The subject was erased, and this version with it.
    Erased,
    /// No such key: never created (a value sealed elsewhere, or a lost
    /// keystore).
    Missing,
}

/// A value sealed with a subject's key: what `pb::Sealed` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedValue {
    pub key_version: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// One erased subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureInfo {
    pub subject: String,
    /// Versions up to this one are erased.
    pub last_version: u32,
    /// This host's physical floor-application time, not a global proof clock.
    pub erased_wall_ms: u64,
}

/// One existing subject-key envelope, never an unwrapped data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSubjectKey {
    pub nonce: [u8; 24],
    pub wrapped: [u8; 48],
    pub created_wall_ms: u64,
}

/// An exporter's observed erasure metadata, not authority to erase locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectErasure {
    pub last_version: u32,
    pub erased_wall_ms: u64,
}

/// A same-read-snapshot view of one requested original subject-key version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSubjectVersion {
    pub subject: String,
    pub version: u32,
    pub key: Option<WrappedSubjectKey>,
    pub erasure: Option<SubjectErasure>,
}

/// The receiver's local state after a wrapped-version merge. This is not a
/// production/key grant or proof that a follower's source cut is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedVersionStatus {
    Imported,
    Present,
    Erased,
    /// An expected, noncovered original key is still absent.
    Missing,
}

/// Counts for `privacy status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeystoreStats {
    /// Subjects with at least one key.
    pub subjects: u64,
    pub keys: u64,
    pub erased: u64,
}

/// `keys/keystore.db`.
pub struct Keystore {
    conn: Mutex<Connection>,
    wrap: ProtectedKey,
    backup: ProtectedKey,
    check: [u8; 32],
    custody: Custody,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyRevision {
    revision: u64,
    data_version: u64,
}

fn semantic_revision(conn: &Connection) -> Result<u64, PrivacyError> {
    let value: i64 = conn.query_row("SELECT revision FROM keystore_revision WHERE id = 1", [], |row| row.get(0))?;
    u64::try_from(value).map_err(|_| PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, value)))
}

fn data_version(conn: &Connection) -> Result<u64, PrivacyError> {
    let value: i64 = conn.pragma_query_value(None, "data_version", |row| row.get(0))?;
    u64::try_from(value).map_err(|_| PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, value)))
}

fn subject_key_version(version: u32) -> Result<u32, PrivacyError> {
    if version == 0 {
        return Err(PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, 0)));
    }
    Ok(version)
}

fn next_subject_key_version(version: u32) -> Result<u32, PrivacyError> {
    version.checked_add(1).ok_or_else(|| {
        PrivacyError::Sqlite(rusqlite::Error::IntegralValueOutOfRange(0, i64::from(version) + 1))
    })
}

fn row_wall_ms(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn sql_wall_ms(value: u64) -> Result<i64, PrivacyError> {
    i64::try_from(value).map_err(|error| {
        PrivacyError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
    })
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keystore(..)")
    }
}

fn wrap_aad(subject: &str, version: u32) -> Vec<u8> {
    let mut aad = b"kronik subject key v1\0".to_vec();
    aad.extend_from_slice(subject.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

fn seal_aad(subject: &str, version: u32) -> Vec<u8> {
    let mut aad = b"kronik sealed v1\0".to_vec();
    aad.extend_from_slice(subject.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

impl Keystore {
    pub(crate) fn validate_legacy_key(
        conn: &Connection,
        master: &MasterKey,
    ) -> Result<bool, PrivacyError> {
        let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT subject, version, nonce, wrapped FROM subject_keys LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((subject, version, nonce, wrapped)) = row else {
            return Ok(true);
        };
        let Ok(nonce) = XNonce::try_from(nonce.as_slice()) else {
            return Ok(false);
        };
        let key = master.derive("kronik keystore v1")?;
        Ok(XChaCha20Poly1305::new(key.bytes().into())
            .decrypt(
                &nonce,
                Payload {
                    msg: &wrapped,
                    aad: &wrap_aad(&subject, version),
                },
            )
            .map(Zeroizing::new)
            .is_ok_and(|bytes| bytes.len() == 32))
    }

    fn open_connection(conn: Mutex<Connection>, master: &MasterKey, custody: Custody) -> Result<Keystore, PrivacyError> {
        let store = Keystore {
            conn,
            wrap: master.derive("kronik keystore v1")?,
            backup: master.derive("kronik keystore backup v1")?,
            check: master.check_value(),
            custody,
        };
        {
            let conn = store.conn();
            if store.custody.readonly() {
                store.check_master(&conn)?;
            } else {
                conn.execute_batch(
                    "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;",
                )?;
                conn.execute_batch(SCHEMA)?;
                crate::check_key(&conn, master, "the privacy keystore", || {
                    let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = conn
                        .query_row(
                            "SELECT subject, version, nonce, wrapped FROM subject_keys LIMIT 1",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                        )
                        .optional()?;
                    Ok(row.is_none_or(|(subject, version, nonce, wrapped)| {
                        store.unwrap_key(&subject, version, &nonce, &wrapped).is_ok()
                    }))
                })?;
            }
        }
        Ok(store)
    }

    fn reopen_connection(&self, conn: Mutex<Connection>, custody: Custody) -> Result<Self, PrivacyError> {
        let store = Self {
            conn, wrap: self.wrap.clone(), backup: self.backup.clone(),
            check: self.check, custody,
        };
        drop(store.checked_conn()?);
        Ok(store)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn checked_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, PrivacyError> {
        let conn = self.conn();
        self.custody.check()?;
        self.check_master(&conn)?;
        Ok(conn)
    }

    fn check_master(&self, conn: &Connection) -> Result<(), PrivacyError> {
        let matches = conn.query_row("SELECT value FROM key_check WHERE id = 1", [], |row| {
            Ok(matches!(row.get_ref(0)?, rusqlite::types::ValueRef::Blob(value) if value == self.check))
        })?;
        if matches { Ok(()) } else {
            Err(PrivacyError::KeyMismatch("the privacy keystore was replaced under another master key".into()))
        }
    }

    /// Persistent semantic change counter; checkpointing and file timestamps do
    /// not determine whether a keystore backup or retained inventory changed.
    pub fn revision(&self) -> Result<u64, PrivacyError> {
        let conn = self.checked_conn()?;
        semantic_revision(&conn)
    }

    pub(crate) fn cache_revision(&self) -> Result<KeyRevision, PrivacyError> {
        let conn = self.checked_conn()?;
        let data_version = data_version(&conn)?;
        Ok(KeyRevision { revision: semantic_revision(&conn)?, data_version })
    }

    pub(crate) fn erasure_floor_at_revision(
        &self,
        subject: &str,
    ) -> Result<(KeyRevision, Option<u32>), PrivacyError> {
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let mut conn = self.checked_conn()?;
        let data_version = data_version(&conn)?;
        let tx = conn.transaction()?;
        self.check_master(&tx)?;
        let floor = Self::erased_through(&tx, subject)?;
        let revision = KeyRevision { revision: semantic_revision(&tx)?, data_version };
        tx.commit()?;
        Ok((revision, floor))
    }

    fn unwrap_key(
        &self,
        subject: &str,
        version: u32,
        nonce: &[u8],
        wrapped: &[u8],
    ) -> Result<SubjectKey, PrivacyError> {
        let version = subject_key_version(version)?;
        let decrypt = || PrivacyError::Decrypt(format!("the key of {subject} (version {version})"));
        let nonce = XNonce::try_from(nonce).map_err(|_| decrypt())?;
        let bytes = Zeroizing::new(
            XChaCha20Poly1305::new(self.wrap.bytes().into())
                .decrypt(
                    &nonce,
                    Payload {
                        msg: wrapped,
                        aad: &wrap_aad(subject, version),
                    },
                )
                .map_err(|_| decrypt())?,
        );
        let bytes: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| decrypt())?;
        let key = Zeroizing::new(*bytes);
        Ok(SubjectKey { version, key })
    }

    fn erased_through(conn: &Connection, subject: &str) -> Result<Option<u32>, PrivacyError> {
        let last: Option<u32> = conn
            .query_row(
                "SELECT last_version FROM erasures WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(last)
    }

    fn subject_erasure(conn: &Connection, subject: &str) -> Result<Option<SubjectErasure>, PrivacyError> {
        Ok(conn.query_row(
            "SELECT last_version, erased_wall_ms FROM erasures WHERE subject = ?1",
            [subject],
            |row| Ok(SubjectErasure { last_version: row.get(0)?, erased_wall_ms: row_wall_ms(row, 1)? }),
        ).optional()?)
    }

    fn wrapped_subject_key(
        conn: &Connection,
        subject: &str,
        version: u32,
    ) -> Result<Option<WrappedSubjectKey>, PrivacyError> {
        Ok(conn.query_row(
            "SELECT nonce, wrapped, created_wall_ms FROM subject_keys WHERE subject = ?1 AND version = ?2",
            params![subject, version],
            |row| Ok(WrappedSubjectKey {
                nonce: row.get(0)?,
                wrapped: row.get(1)?,
                created_wall_ms: row_wall_ms(row, 2)?,
            }),
        ).optional()?)
    }

    /// Internal shard-bootstrap export. The requested identity must come from
    /// an already committed assigned-shard record/snapshot. This read neither
    /// creates keys nor exports the master or an unwrapped subject key.
    pub fn export_wrapped_version(
        &self,
        expected_subject: &str,
        expected_version: u32,
    ) -> Result<WrappedSubjectVersion, PrivacyError> {
        if !valid_subject(expected_subject) {
            return Err(PrivacyError::InvalidSubject(expected_subject.to_owned()));
        }
        let version = subject_key_version(expected_version)?;
        let mut conn = self.checked_conn()?;
        let tx = conn.transaction()?;
        self.check_master(&tx)?;
        let erasure = Self::subject_erasure(&tx, expected_subject)?;
        let key = if erasure.is_some_and(|floor| version <= floor.last_version) {
            None
        } else {
            Self::wrapped_subject_key(&tx, expected_subject, version)?
        };
        tx.commit()?;
        Ok(WrappedSubjectVersion { subject: expected_subject.to_owned(), version, key, erasure })
    }

    /// Internal shard-bootstrap merge under the already shared protected master.
    /// The caller admits an immutable identity/capsule/proved-floor command at
    /// its bounded queue under the original member/install/source-cut/term fence.
    /// This admitted continuation may wait for SQLite and finish after revocation;
    /// data installation/readiness needs its own original assignment admission.
    /// This does not bootstrap a master or grant authority to the imported key.
    ///
    /// `proved_floor` is a subject-bound projection, not the deletion proof.
    /// The caller must verify the actual GLOBAL epoch/all-required-replica
    /// barrier plus LOCAL hosted-shard cuts before authorizing physical key
    /// deletion; one shard's erasure/intent is insufficient. Never derive the
    /// floor from the capsule. Absence proves neither zero nor complete history.
    /// The already-admitted receiving worker samples `receiving_host_applied_wall_ms`;
    /// it stamps only a newly advanced local floor, not global/wire authority.
    pub fn merge_wrapped_version(
        &self,
        expected_subject: &str,
        expected_version: u32,
        capsule: &WrappedSubjectVersion,
        proved_floor: Option<(&str, u32)>,
        receiving_host_applied_wall_ms: u64,
    ) -> Result<WrappedVersionStatus, PrivacyError> {
        if !valid_subject(expected_subject) {
            return Err(PrivacyError::InvalidSubject(expected_subject.to_owned()));
        }
        let version = subject_key_version(expected_version)?;
        if capsule.subject != expected_subject || capsule.version != version {
            return Err(PrivacyError::Decrypt("wrapped key identity does not match committed source".into()));
        }
        let proved = if let Some((subject, floor)) = proved_floor {
            if subject != expected_subject {
                return Err(PrivacyError::Decrypt("erasure proof does not match committed subject".into()));
            }
            Some(floor)
        } else { None };
        let applied_wall_ms = sql_wall_ms(receiving_host_applied_wall_ms)?;
        if let Some(observed) = capsule.erasure { sql_wall_ms(observed.erased_wall_ms)?; }
        let incoming = match capsule.key.as_ref() {
            Some(key) => Some((key, sql_wall_ms(key.created_wall_ms)?)),
            None => None,
        };
        self.custody.require_mutable()?;
        let mut conn = self.checked_conn()?;
        let tx = conn.transaction()?;
        self.check_master(&tx)?;
        semantic_revision(&tx)?;
        let local = Self::subject_erasure(&tx, expected_subject)?;
        let advance = proved.filter(|floor| local.is_none_or(|local| *floor > local.last_version));
        let floor = advance.or(local.map(|local| local.last_version));
        if capsule.erasure.is_some_and(|observed| floor.is_none_or(|floor| observed.last_version > floor)) {
            return Err(PrivacyError::Decrypt("wrapped erasure floor lacks committed source proof".into()));
        }
        let covered = floor.is_some_and(|floor| version <= floor);
        let existing = if covered {
            None
        } else {
            Self::wrapped_subject_key(&tx, expected_subject, version)?
        };
        let existing_key = existing.as_ref().map(|key| {
            self.unwrap_key(expected_subject, version, &key.nonce, &key.wrapped)
        }).transpose()?;
        let incoming_key = if covered {
            None
        } else {
            incoming.as_ref().map(|(key, _)| {
                self.unwrap_key(expected_subject, version, &key.nonce, &key.wrapped)
            }).transpose()?
        };
        if let (Some(existing), Some(incoming)) = (&existing_key, &incoming_key)
            && existing.key[..] != incoming.key[..]
        {
            return Err(PrivacyError::Decrypt("subject key version has a different key lineage".into()));
        }
        // Covered versions are never read or unwrapped. Validate only uncovered
        // lineage before applying the proved erasure and original envelope.
        let mutation = advance.map(|_| self.begin_erasure()).transpose()?;
        if let Some(floor) = advance {
            tx.execute(
                "DELETE FROM subject_keys WHERE subject = ?1 AND version <= ?2",
                params![expected_subject, floor],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
                params![expected_subject, floor, applied_wall_ms],
            )?;
        }
        let status = if covered {
            WrappedVersionStatus::Erased
        } else if existing.is_some() {
            WrappedVersionStatus::Present
        } else if let Some((key, wall_ms)) = incoming {
            tx.execute(
                "INSERT INTO subject_keys (subject, version, nonce, wrapped, created_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![expected_subject, version, &key.nonce[..], &key.wrapped[..], wall_ms],
            )?;
            WrappedVersionStatus::Imported
        } else {
            WrappedVersionStatus::Missing
        };
        tx.commit()?;
        if let Some(mutation) = mutation { mutation.finish()?; }
        Ok(status)
    }

    fn insert_key(
        &self,
        conn: &Connection,
        subject: &str,
        version: u32,
        fresh: &[u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        self.custody.require_mutable()?;
        let version = subject_key_version(version)?;
        let wrapped = XChaCha20Poly1305::new(self.wrap.bytes().into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: fresh,
                    aad: &wrap_aad(subject, version),
                },
            )
            .map_err(|_| PrivacyError::Decrypt(format!("the key of {subject}")))?;
        conn.execute(
            "INSERT INTO subject_keys (subject, version, nonce, wrapped, created_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![subject, version, &nonce[..], wrapped, wall_ms as i64],
        )?;
        Ok(SubjectKey {
            version,
            key: Zeroizing::new(*fresh),
        })
    }

    /// The subject's newest key, to seal with. A subject without one gets a
    /// new key from `fresh` and `nonce` (fresh randomness), numbered after
    /// any erased versions.
    pub fn key_for_sealing(
        &self,
        subject: &str,
        fresh: [u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        let fresh = Zeroizing::new(fresh);
        self.sealing_key_inner(subject, &fresh, nonce, wall_ms, None).map(|(_, key)| key)
    }

    pub(crate) fn sealing_key_at_revision(
        &self,
        subject: &str,
        fresh: [u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<(KeyRevision, SubjectKey), PrivacyError> {
        let fresh = Zeroizing::new(fresh);
        self.sealing_key_inner(subject, &fresh, nonce, wall_ms, None)
    }

    pub(crate) fn plain_source_key_at_revision(
        &self,
        subject: &str,
        expected_erasure_floor: Option<u32>,
        fresh: [u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<(KeyRevision, SubjectKey), PrivacyError> {
        let fresh = Zeroizing::new(fresh);
        self.sealing_key_inner(subject, &fresh, nonce, wall_ms, Some(expected_erasure_floor))
    }

    fn sealing_key_inner(
        &self,
        subject: &str,
        fresh: &[u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
        expected_erasure_floor: Option<Option<u32>>,
    ) -> Result<(KeyRevision, SubjectKey), PrivacyError> {
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let mut conn = self.checked_conn()?;
        // Sample before the snapshot: a later commit must never tag an older key.
        let data_version = data_version(&conn)?;
        let tx = conn.transaction()?;
        self.check_master(&tx)?;
        // None is ordinary live sealing; Some(expected) is a source receipt CAS.
        let source_floor = if let Some(expected) = expected_erasure_floor {
            let actual = Self::erased_through(&tx, subject)?;
            if actual != expected {
                return Err(PrivacyError::Decrypt("historical plaintext erasure floor changed".into()));
            }
            actual
        } else { None };
        type Row = (u32, Vec<u8>, Vec<u8>);
        let newest: Option<Row> = tx
            .query_row(
                "SELECT version, nonce, wrapped FROM subject_keys WHERE subject = ?1 ORDER BY version DESC LIMIT 1",
                [subject],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let key = if let Some((version, nonce, wrapped)) = newest {
            self.unwrap_key(subject, version, &nonce, &wrapped)?
        } else {
            let floor = if expected_erasure_floor.is_some() { source_floor.unwrap_or(0) } else { Self::erased_through(&tx, subject)?.unwrap_or(0) };
            let version = next_subject_key_version(floor)?;
            self.insert_key(&tx, subject, version, fresh, nonce, wall_ms)?
        };
        let revision = KeyRevision { revision: semantic_revision(&tx)?, data_version };
        tx.commit()?;
        Ok((revision, key))
    }

    /// One version of a subject's key, to unseal with.
    pub fn key(&self, subject: &str, version: u32) -> Result<KeyLookup, PrivacyError> {
        self.key_at_revision(subject, version).map(|(_, key)| key)
    }

    pub(crate) fn key_at_revision(&self, subject: &str, version: u32) -> Result<(KeyRevision, KeyLookup), PrivacyError> {
        let version = subject_key_version(version)?;
        let mut conn = self.checked_conn()?;
        let data_version = data_version(&conn)?;
        let tx = conn.transaction()?;
        self.check_master(&tx)?;
        let revision = KeyRevision { revision: semantic_revision(&tx)?, data_version };
        let key = if Self::erased_through(&tx, subject)?.is_some_and(|last| version <= last) {
            KeyLookup::Erased
        } else {
            let row: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT nonce, wrapped FROM subject_keys WHERE subject = ?1 AND version = ?2",
                    params![subject, version],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                Some((nonce, wrapped)) => KeyLookup::Found(self.unwrap_key(subject, version, &nonce, &wrapped)?),
                None => KeyLookup::Missing,
            }
        };
        tx.commit()?;
        Ok((revision, key))
    }

    /// Adds a new version of the subject's key, which seals from now on;
    /// older versions still unseal. Returns the new version.
    pub fn rotate(
        &self,
        subject: &str,
        fresh: [u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<u32, PrivacyError> {
        let fresh = Zeroizing::new(fresh);
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let conn = self.checked_conn()?;
        let newest: Option<u32> = conn
            .query_row(
                "SELECT max(version) FROM subject_keys WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let floor = Self::erased_through(&conn, subject)?.unwrap_or(0);
        let version = next_subject_key_version(newest.map(subject_key_version).transpose()?.unwrap_or(floor).max(floor))?;
        self.insert_key(&conn, subject, version, &fresh, nonce, wall_ms)
            .map(|k| k.version)
    }

    /// Re-applies a logged erasure of `subject`'s keys through `version`
    /// (a restore whose keystore backup predates it). Newer keys of the
    /// subject stay; already covered, it changes nothing.
    pub fn erase_through(
        &self,
        subject: &str,
        version: u32,
        wall_ms: u64,
    ) -> Result<(), PrivacyError> {
        self.custody.require_mutable()?;
        let mut conn = self.checked_conn()?;
        let tx = conn.transaction()?;
        if Self::erased_through(&tx, subject)?.is_some_and(|v| v >= version) {
            return Ok(());
        }
        let mutation = self.begin_erasure()?;
        tx.execute(
            "DELETE FROM subject_keys WHERE subject = ?1 AND version <= ?2",
            params![subject, version],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
            params![subject, version, wall_ms as i64],
        )?;
        tx.commit()?;
        mutation.finish()?;
        Ok(())
    }

    /// Whether a value sealed under `subject`'s key `version` can be
    /// accounted for: the subject was erased through that version (its
    /// values are tombstones), or the key is here and opens `sample`, one
    /// value sealed with it (a key of the same version from another lineage,
    /// after a restore without the keystore, would not).
    pub fn covers(
        &self,
        subject: &str,
        version: u32,
        sample: &kronik_proto::log::v1::Sealed,
    ) -> Result<bool, PrivacyError> {
        let erased = {
            let conn = self.checked_conn()?;
            Self::erased_through(&conn, subject)?
        };
        if erased.is_some_and(|last| last >= version) {
            return Ok(true);
        }
        let Ok(nonce) = <[u8; 24]>::try_from(sample.nonce.as_slice()) else {
            return Ok(false);
        };
        let sample = SealedValue {
            key_version: version,
            nonce,
            ciphertext: sample.ciphertext.clone(),
        };
        match self.key(subject, version)? {
            KeyLookup::Found(k) => Ok(unseal(subject, &k, &sample).is_ok()),
            _ => Ok(false),
        }
    }

    /// Deletes every key of the subject and records the erasure; returns the
    /// last version erased (0 when the subject never had a key). Values sealed
    /// with those keys are unreadable from now on; copies of this keystore in
    /// backups keep them until the backups expire.
    pub fn erase(&self, subject: &str, wall_ms: u64) -> Result<u32, PrivacyError> {
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        self.custody.require_mutable()?;
        let mut conn = self.checked_conn()?;
        let tx = conn.transaction()?;
        let newest: Option<u32> = tx
            .query_row(
                "SELECT max(version) FROM subject_keys WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let floor = Self::erased_through(&tx, subject)?.unwrap_or(0);
        let last = newest.map(subject_key_version).transpose()?.unwrap_or(floor).max(floor);
        let mutation = self.begin_erasure()?;
        tx.execute("DELETE FROM subject_keys WHERE subject = ?1", [subject])?;
        tx.execute(
            "INSERT OR REPLACE INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
            params![subject, last, wall_ms as i64],
        )?;
        tx.commit()?;
        mutation.finish()?;
        // The WAL still holds the pages with the wrapped keys; the key is
        // deleted durably already, so a failure here is only logged.
        match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        }) {
            Ok(0) => {}
            Ok(_) => tracing::warn!("the keystore WAL checkpoint after an erasure was blocked"),
            Err(e) => tracing::warn!(error = %e, "keystore WAL checkpoint after erasure failed"),
        }
        Ok(last)
    }

    /// Every erased subject, oldest erasure first.
    pub fn erasures(&self) -> Result<Vec<ErasureInfo>, PrivacyError> {
        let conn = self.checked_conn()?;
        let mut stmt = conn.prepare_cached(
            "SELECT subject, last_version, erased_wall_ms FROM erasures ORDER BY erased_wall_ms, subject",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ErasureInfo {
                subject: r.get(0)?,
                last_version: r.get(1)?,
                erased_wall_ms: r.get::<_, i64>(2)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn stats(&self) -> Result<KeystoreStats, PrivacyError> {
        let conn = self.checked_conn()?;
        let (subjects, keys): (i64, i64) = conn.query_row(
            "SELECT count(DISTINCT subject), count(*) FROM subject_keys",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let erased: i64 = conn.query_row("SELECT count(*) FROM erasures", [], |r| r.get(0))?;
        Ok(KeystoreStats {
            subjects: subjects as u64,
            keys: keys as u64,
            erased: erased as u64,
        })
    }

    /// The whole keystore, encrypted under a key derived from the master key
    /// with the fresh `nonce`, for shipping: subject ids and erasures are
    /// hidden too. [`Keystore::restore_owned`] restores it under the original owner.
    pub fn export_backup(&self, nonce: [u8; 24]) -> Result<Vec<u8>, PrivacyError> {
        let conn = self.checked_conn()?;
        let mut payload = Zeroizing::new(Vec::new());
        {
            let mut stmt = conn.prepare_cached(
                "SELECT subject, version, nonce, wrapped, created_wall_ms FROM subject_keys ORDER BY subject, version",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                payload.push(1u8);
                put(&mut payload, r.get::<_, String>(0)?.as_bytes());
                payload.extend_from_slice(&subject_key_version(r.get(1)?)?.to_le_bytes());
                put(&mut payload, &r.get::<_, Vec<u8>>(2)?);
                put(&mut payload, &r.get::<_, Vec<u8>>(3)?);
                payload.extend_from_slice(&(r.get::<_, i64>(4)? as u64).to_le_bytes());
            }
            let mut stmt = conn.prepare_cached(
                "SELECT subject, last_version, erased_wall_ms FROM erasures ORDER BY subject",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                payload.push(2u8);
                put(&mut payload, r.get::<_, String>(0)?.as_bytes());
                payload.extend_from_slice(&r.get::<_, u32>(1)?.to_le_bytes());
                payload.extend_from_slice(&(r.get::<_, i64>(2)? as u64).to_le_bytes());
            }
        }
        let ciphertext = XChaCha20Poly1305::new(self.backup.bytes().into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &payload,
                    aad: BACKUP_MAGIC,
                },
            )
            .map_err(|_| PrivacyError::Decrypt("the keystore backup".into()))?;
        let mut out = BACKUP_MAGIC.to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts and parses `backup` under `master` without touching any
    /// store, so a restore can check it before it installs anything.
    pub fn read_backup(master: &MasterKey, backup: &[u8]) -> Result<BackupRows, PrivacyError> {
        let bad = || PrivacyError::BadBackup;
        let rest = backup
            .strip_prefix(BACKUP_MAGIC.as_slice())
            .ok_or_else(bad)?;
        if rest.len() < 24 {
            return Err(bad());
        }
        let (nonce, ciphertext) = rest.split_at(24);
        let nonce = XNonce::try_from(nonce).map_err(|_| bad())?;
        let key = master.derive("kronik keystore backup v1")?;
        let payload = Zeroizing::new(
            XChaCha20Poly1305::new(key.bytes().into())
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: BACKUP_MAGIC,
                    },
                )
                .map_err(|_| PrivacyError::Decrypt("the keystore backup".into()))?,
        );
        let mut rows = BackupRows::default();
        let mut r = Reader(&payload);
        while let Some(tag) = r.byte() {
            match tag {
                1 => rows
                    .keys
                    .push((r.string()?, subject_key_version(r.u32()?).map_err(|_| bad())?, r.bytes()?, r.bytes()?, r.u64()?)),
                2 => rows.erasures.push((r.string()?, r.u32()?, r.u64()?)),
                _ => return Err(bad()),
            }
        }
        Ok(rows)
    }

    /// The owned restore phase authenticates and invalidates publication first.
    fn replace_backup(
        conn: &mut Connection,
        master: &MasterKey,
        rows: &BackupRows,
    ) -> Result<(), PrivacyError> {
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(crate::KEY_CHECK)?;
        let tx = conn.transaction()?;
        tx.execute("UPDATE keystore_revision SET revision = revision + 1 WHERE id = 1", [])?;
        tx.execute_batch("DELETE FROM subject_keys; DELETE FROM erasures; DELETE FROM key_check;")?;
        for (subject, version, nonce, wrapped, created) in &rows.keys {
            tx.execute(
                "INSERT INTO subject_keys (subject, version, nonce, wrapped, created_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![subject, version, nonce, wrapped, sql_wall_ms(*created)?],
            )?;
        }
        for (subject, last, erased) in &rows.erasures {
            tx.execute(
                "INSERT INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
                params![subject, last, sql_wall_ms(*erased)?],
            )?;
        }
        tx.execute(
            "INSERT INTO key_check (id, value) VALUES (1, ?1)",
            [&master.check_value()[..]],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Reads what [`put`] and the fixed-width fields wrote.
/// A keystore backup's rows, decrypted: (subject, version, nonce, wrapped,
/// created) per key and (subject, last version, erased) per erasure.
#[derive(Default)]
pub struct BackupRows {
    keys: Vec<BackupKey>,
    erasures: Vec<(String, u32, u64)>,
}

type BackupKey = (String, u32, Vec<u8>, Vec<u8>, u64);

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], PrivacyError> {
        if self.0.len() < n {
            return Err(PrivacyError::BadBackup);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Option<u8> {
        let (&b, tail) = self.0.split_first()?;
        self.0 = tail;
        Some(b)
    }
    fn u32(&mut self) -> Result<u32, PrivacyError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, PrivacyError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, PrivacyError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, PrivacyError> {
        String::from_utf8(self.bytes()?).map_err(|_| PrivacyError::BadBackup)
    }
}

/// Seals `plaintext` for `subject` with `key`; `nonce` must be fresh
/// randomness. The subject and key version are bound as associated data,
/// so a value can't be moved to another subject or version.
pub fn seal(
    subject: &str,
    key: &SubjectKey,
    nonce: [u8; 24],
    plaintext: &[u8],
) -> Result<SealedValue, PrivacyError> {
    let cipher = XChaCha20Poly1305::new((&*key.key).into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &seal_aad(subject, key.version),
            },
        )
        .map_err(|_| PrivacyError::Decrypt(format!("a value of {subject}")))?;
    Ok(SealedValue {
        key_version: key.version,
        nonce,
        ciphertext,
    })
}

/// Opens a value sealed for `subject` with `key` (of the value's version).
pub fn unseal(
    subject: &str,
    key: &SubjectKey,
    sealed: &SealedValue,
) -> Result<Vec<u8>, PrivacyError> {
    let cipher = XChaCha20Poly1305::new((&*key.key).into());
    cipher
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &seal_aad(subject, sealed.key_version),
            },
        )
        .map_err(|_| PrivacyError::Decrypt(format!("a value of {subject}")))
}

/// The pseudonyms of `--no-pii` forks: `pii:` and 12 hex characters, from a
/// keyed BLAKE3 of the subject and the value. Equal values get equal
/// pseudonyms within an installation, so equality survives, while without
/// the key (derived from the master key) a pseudonym can't be checked
/// against a guessed value. The same holds for [`Pseudonyms::keyed_hash`],
/// the hashes that sit next to sealed values (diff redactions, ingress
/// request hashes, effect fingerprints).
pub struct Pseudonyms {
    key: ProtectedKey,
    hashes: ProtectedKey,
}

impl std::fmt::Debug for Pseudonyms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pseudonyms(..)")
    }
}

impl Pseudonyms {
    pub fn new(master: &MasterKey) -> Result<Pseudonyms, PrivacyError> {
        Ok(Pseudonyms {
            key: master.derive("kronik pseudonym v1")?,
            hashes: master.derive("kronik keyed hash v1")?,
        })
    }

    pub fn of(&self, subject: &str, value: &[u8]) -> String {
        let mut h = Zeroizing::new(blake3::Hasher::new_keyed(self.key.bytes()));
        h.update(subject.as_bytes());
        h.update(b"\0");
        h.update(value);
        format!("pii:{}", hex(&h.finalize().as_bytes()[..6]))
    }

    /// A keyed BLAKE3 of `parts` for `purpose` (a fixed domain string):
    /// each part is length-prefixed, so part boundaries can't be shifted.
    pub fn keyed_hash(&self, purpose: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Zeroizing::new(blake3::Hasher::new_keyed(self.hashes.bytes()));
        h.update(purpose.as_bytes());
        h.update(b"\0");
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(master: u8) -> Keystore {
        Keystore::open_memory(&MasterKey::from_bytes([master; 32]).unwrap())
        .unwrap()
    }

    fn found(lookup: KeyLookup) -> SubjectKey {
        match lookup {
            KeyLookup::Found(k) => k,
            other => panic!("expected a key, got {other:?}"),
        }
    }

    #[test]
    fn a_subject_gets_one_key_that_seals_and_unseals_only_for_it() {
        let ks = store(1);
        let k = ks.key_for_sealing("user:1", [7; 32], [1; 24], 10).unwrap();
        assert_eq!(k.version, 1);
        // The second call returns the stored key, not the new material.
        let again = ks.key_for_sealing("user:1", [8; 32], [2; 24], 11).unwrap();
        assert_eq!((again.version, *again.key), (1, [7; 32]));
        let sealed = seal("user:1", &k, [3; 24], b"alice@example.com").unwrap();
        assert!(!sealed.ciphertext.windows(5).any(|w| w == b"alice"));
        assert_eq!(
            unseal("user:1", &found(ks.key("user:1", 1).unwrap()), &sealed).unwrap(),
            b"alice@example.com"
        );
        // Bound to the subject and the version.
        let other = ks.key_for_sealing("user:2", [7; 32], [4; 24], 12).unwrap();
        assert!(unseal("user:2", &other, &sealed).is_err());
        let mut moved = sealed.clone();
        moved.key_version = 2;
        assert!(unseal("user:1", &k, &moved).is_err());
        assert!(matches!(ks.key("user:3", 1).unwrap(), KeyLookup::Missing));
        assert!(!format!("{k:?}").contains('7'), "{k:?}");
        assert!(matches!(
            ks.key_for_sealing("user 1", [7; 32], [1; 24], 0),
            Err(PrivacyError::InvalidSubject(_))
        ));
        assert!(matches!(
            ks.key_for_sealing("", [7; 32], [1; 24], 0),
            Err(PrivacyError::InvalidSubject(_))
        ));
    }

    #[test]
    fn rotation_seals_with_the_new_version_and_old_values_still_open() {
        let ks = store(1);
        let v1 = ks.key_for_sealing("user:1", [1; 32], [1; 24], 0).unwrap();
        let old = seal("user:1", &v1, [9; 24], b"old").unwrap();
        assert_eq!(ks.rotate("user:1", [2; 32], [2; 24], 1).unwrap(), 2);
        let v2 = ks.key_for_sealing("user:1", [3; 32], [3; 24], 2).unwrap();
        assert_eq!((v2.version, *v2.key), (2, [2; 32]));
        assert_eq!(
            unseal(
                "user:1",
                &found(ks.key("user:1", old.key_version).unwrap()),
                &old
            )
            .unwrap(),
            b"old"
        );
        assert_eq!(
            ks.stats().unwrap(),
            KeystoreStats {
                subjects: 1,
                keys: 2,
                erased: 0
            }
        );
    }

    #[test]
    fn erasure_makes_every_version_unreadable_for_good() {
        let ks = store(1);
        let v1 = ks.key_for_sealing("user:1", [1; 32], [1; 24], 0).unwrap();
        let sealed = seal("user:1", &v1, [9; 24], b"secret").unwrap();
        ks.rotate("user:1", [2; 32], [2; 24], 1).unwrap();
        ks.key_for_sealing("user:2", [5; 32], [5; 24], 2).unwrap();
        assert_eq!(ks.erase("user:1", 100).unwrap(), 2);
        assert!(matches!(
            ks.key("user:1", sealed.key_version).unwrap(),
            KeyLookup::Erased
        ));
        assert!(matches!(ks.key("user:1", 2).unwrap(), KeyLookup::Erased));
        // Other subjects are untouched.
        assert!(matches!(ks.key("user:2", 1).unwrap(), KeyLookup::Found(_)));
        // The id used again gets a key numbered after the erased ones.
        let fresh = ks.key_for_sealing("user:1", [3; 32], [3; 24], 200).unwrap();
        assert_eq!(fresh.version, 3);
        assert!(matches!(ks.key("user:1", 2).unwrap(), KeyLookup::Erased));
        assert!(matches!(ks.key("user:1", 3).unwrap(), KeyLookup::Found(_)));
        // Erasing a subject that never had a key still records it.
        assert_eq!(ks.erase("user:9", 300).unwrap(), 0);
        let erased = ks.erasures().unwrap();
        assert_eq!(erased.len(), 2);
        assert_eq!(
            erased[0],
            ErasureInfo {
                subject: "user:1".into(),
                last_version: 2,
                erased_wall_ms: 100
            }
        );
        assert_eq!(
            ks.stats().unwrap(),
            KeystoreStats {
                subjects: 2,
                keys: 2,
                erased: 2
            }
        );
    }

    #[test]
    fn keys_are_stored_wrapped_under_the_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let owner = crate::key_source::lock_data(dir.path()).unwrap();
        let path = dir.path().join("keys/keystore.db");
        let ks = Keystore::open_owned(&owner, &MasterKey::from_bytes([1; 32]).unwrap()).unwrap();
        ks.key_for_sealing("user:1", [0xab; 32], [1; 24], 0)
            .unwrap();
        drop(ks);
        let conn = Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let wrapped: Vec<u8> = conn
            .query_row("SELECT wrapped FROM subject_keys", [], |r| r.get(0))
            .unwrap();
        assert!(!wrapped.windows(4).any(|w| w == [0xab; 4]));
        // Another master key is refused before it can try to unwrap.
        drop(conn);
        let other = Keystore::open_owned(&owner, &MasterKey::from_bytes([2; 32]).unwrap());
        assert!(matches!(other, Err(PrivacyError::KeyMismatch(_))));
    }

    #[test]
    fn the_backup_hides_subjects_and_restores_keys_and_erasures() {
        let ks = store(1);
        let k = ks.key_for_sealing("user:1", [1; 32], [1; 24], 0).unwrap();
        let sealed = seal("user:1", &k, [9; 24], b"kept").unwrap();
        ks.key_for_sealing("user:2", [2; 32], [2; 24], 0).unwrap();
        ks.erase("user:2", 5).unwrap();
        let backup = ks.export_backup([4; 24]).unwrap();
        assert!(backup.starts_with(BACKUP_MAGIC));
        assert!(!backup.windows(6).any(|w| w == b"user:1" || w == b"user:2"));

        let restored = Keystore::restore_memory(&MasterKey::from_bytes([1; 32]).unwrap(), &backup)
        .unwrap();
        assert_eq!(
            unseal(
                "user:1",
                &found(restored.key("user:1", 1).unwrap()),
                &sealed
            )
            .unwrap(),
            b"kept"
        );
        assert!(matches!(
            restored.key("user:2", 1).unwrap(),
            KeyLookup::Erased
        ));
        assert_eq!(restored.stats().unwrap(), ks.stats().unwrap());

        let wrong = Keystore::restore_memory(&MasterKey::from_bytes([2; 32]).unwrap(), &backup);
        assert!(matches!(wrong, Err(PrivacyError::Decrypt(_))));
        let mut tampered = backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = Keystore::restore_memory(&MasterKey::from_bytes([1; 32]).unwrap(), &tampered);
        assert!(matches!(tampered, Err(PrivacyError::Decrypt(_))));
        let junk = Keystore::restore_memory(&MasterKey::from_bytes([1; 32]).unwrap(), b"junk");
        assert!(matches!(junk, Err(PrivacyError::BadBackup)));

        // A backup under another key leaves an existing store untouched,
        // its key check included.
        let dir = tempfile::tempdir().unwrap();
        let owner = crate::key_source::lock_data(dir.path()).unwrap();
        let kept_master = MasterKey::from_bytes([3; 32]).unwrap();
        let kept = Keystore::open_owned(&owner, &kept_master).unwrap();
        kept.key_for_sealing("user:7", [7; 32], [7; 24], 0).unwrap();
        assert!(matches!(
            Keystore::restore_owned(&owner, &kept_master, &backup),
            Err(PrivacyError::Decrypt(_))
        ));
        found(kept.key("user:7", 1).unwrap());
        found(kept.reopen_owned().unwrap().key("user:7", 1).unwrap());

        // A restore over a keystore of another key replaces it, key included.
        let replacement = tempfile::tempdir().unwrap();
        let replacement_owner = crate::key_source::lock_data(replacement.path()).unwrap();
        let old = Keystore::open_owned(&replacement_owner, &kept_master).unwrap();
        old.key_for_sealing("user:9", [9; 32], [9; 24], 0).unwrap();
        let restored_master = MasterKey::from_bytes([1; 32]).unwrap();
        let replaced = Keystore::restore_owned(&replacement_owner, &restored_master, &backup).unwrap();
        found(replaced.key("user:1", 1).unwrap());
        assert!(matches!(old.key("user:9", 1), Err(PrivacyError::KeyMismatch(_))));
        drop(replaced);
        Keystore::open_owned(&replacement_owner, &restored_master).unwrap();
    }

    /// Review F4: a key of the right version from another lineage (a new
    /// keystore after a restore without one) does not cover old values.
    #[test]
    fn covers_tries_the_key_on_a_sealed_value() {
        let old = store(1);
        let k = old.key_for_sealing("user:1", [1; 32], [1; 24], 0).unwrap();
        let v = seal("user:1", &k, [9; 24], b"kept").unwrap();
        let sample = kronik_proto::log::v1::Sealed {
            key_version: v.key_version,
            nonce: v.nonce.to_vec(),
            ciphertext: v.ciphertext.clone(),
        };
        assert!(old.covers("user:1", 1, &sample).unwrap());
        let new = store(1);
        new.key_for_sealing("user:1", [2; 32], [2; 24], 1).unwrap();
        assert!(!new.covers("user:1", 1, &sample).unwrap());
        new.erase("user:1", 2).unwrap();
        assert!(new.covers("user:1", 1, &sample).unwrap());
    }

    #[test]
    fn a_logged_erasure_is_applied_again_through_its_version_only() {
        let ks = store(1);
        ks.key_for_sealing("user:1", [1; 32], [1; 24], 0).unwrap();
        ks.rotate("user:1", [2; 32], [2; 24], 1).unwrap();
        let sample = |version| {
            let KeyLookup::Found(k) = ks.key("user:1", version).unwrap() else {
                panic!("no key {version}")
            };
            let v = seal("user:1", &k, [9; 24], b"x").unwrap();
            kronik_proto::log::v1::Sealed {
                key_version: version,
                nonce: v.nonce.to_vec(),
                ciphertext: v.ciphertext,
            }
        };
        let (s1, s2) = (sample(1), sample(2));
        assert!(ks.covers("user:1", 1, &s1).unwrap() && ks.covers("user:1", 2, &s2).unwrap());
        assert!(!ks.covers("user:1", 3, &s2).unwrap() && !ks.covers("user:2", 1, &s1).unwrap());
        // Erased through version 1 (a restore's backup predates it): the
        // version-1 values are tombstones, version 2 still has its key.
        ks.erase_through("user:1", 1, 5).unwrap();
        assert!(matches!(ks.key("user:1", 1).unwrap(), KeyLookup::Erased));
        found(ks.key("user:1", 2).unwrap());
        assert!(ks.covers("user:1", 1, &s1).unwrap() && ks.covers("user:1", 2, &s2).unwrap());
        ks.erase_through("user:1", 1, 6).unwrap();
        found(ks.key("user:1", 2).unwrap());
    }

    #[test]
    fn pseudonyms_are_deterministic_short_and_keyed() {
        let p = Pseudonyms::new(&MasterKey::from_bytes([1; 32]).unwrap()).unwrap();
        let a = p.of("user:1", b"alice@example.com");
        assert_eq!(a.len(), 16);
        assert!(
            a.starts_with("pii:")
                && a[4..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(a, p.of("user:1", b"alice@example.com"));
        assert_ne!(a, p.of("user:2", b"alice@example.com"));
        assert_ne!(a, p.of("user:1", b"bob@example.com"));
        assert_ne!(
            a,
            Pseudonyms::new(&MasterKey::from_bytes([2; 32]).unwrap())
                .unwrap()
                .of("user:1", b"alice@example.com")
        );
    }
}

#[cfg(test)]
#[path = "keystore/revision_tests.rs"]
mod revision_tests;
