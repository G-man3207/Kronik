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

use crate::{MasterKey, PrivacyError, hex};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS subject_keys (
  subject TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL,
  wrapped BLOB NOT NULL, created_wall_ms INTEGER NOT NULL,
  PRIMARY KEY (subject, version)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS erasures (
  subject TEXT PRIMARY KEY, last_version INTEGER NOT NULL,
  erased_wall_ms INTEGER NOT NULL) WITHOUT ROWID;
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
    key: [u8; 32],
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
    pub erased_wall_ms: u64,
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
    wrap: XChaCha20Poly1305,
    backup: XChaCha20Poly1305,
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
    pub fn open(conn: Connection, master: &MasterKey) -> Result<Keystore, PrivacyError> {
        // secure_delete: an erased key's bytes are zeroed in its page, and
        // `erase` truncates the WAL that still holds older copies.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;",
        )?;
        conn.execute_batch(SCHEMA)?;
        let store = Keystore {
            conn: Mutex::new(conn),
            wrap: XChaCha20Poly1305::new(&master.derive("kronik keystore v1").into()),
            backup: XChaCha20Poly1305::new(&master.derive("kronik keystore backup v1").into()),
        };
        {
            let conn = store.conn();
            crate::check_key(&conn, master, "the privacy keystore", || {
                let row: Option<(String, u32, Vec<u8>, Vec<u8>)> = conn
                    .query_row(
                        "SELECT subject, version, nonce, wrapped FROM subject_keys LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                Ok(row.is_none_or(|(subject, version, nonce, wrapped)| {
                    store
                        .unwrap_key(&subject, version, &nonce, &wrapped)
                        .is_ok()
                }))
            })?;
        }
        Ok(store)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn unwrap_key(
        &self,
        subject: &str,
        version: u32,
        nonce: &[u8],
        wrapped: &[u8],
    ) -> Result<SubjectKey, PrivacyError> {
        let decrypt = || PrivacyError::Decrypt(format!("the key of {subject} (version {version})"));
        let nonce = XNonce::try_from(nonce).map_err(|_| decrypt())?;
        let bytes = self
            .wrap
            .decrypt(
                &nonce,
                Payload {
                    msg: wrapped,
                    aad: &wrap_aad(subject, version),
                },
            )
            .map_err(|_| decrypt())?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| decrypt())?;
        Ok(SubjectKey { version, key })
    }

    fn erased_through(conn: &Connection, subject: &str) -> Result<Option<u32>, PrivacyError> {
        let last: Option<i64> = conn
            .query_row(
                "SELECT last_version FROM erasures WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?;
        Ok(last.map(|v| v as u32))
    }

    fn insert_key(
        &self,
        conn: &Connection,
        subject: &str,
        version: u32,
        fresh: [u8; 32],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<SubjectKey, PrivacyError> {
        let wrapped = self
            .wrap
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &fresh,
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
            key: fresh,
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
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let conn = self.conn();
        type Row = (i64, Vec<u8>, Vec<u8>);
        let newest: Option<Row> = conn
            .query_row(
                "SELECT version, nonce, wrapped FROM subject_keys WHERE subject = ?1 ORDER BY version DESC LIMIT 1",
                [subject],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((version, n, wrapped)) = newest {
            return self.unwrap_key(subject, version as u32, &n, &wrapped);
        }
        let version = Self::erased_through(&conn, subject)?.unwrap_or(0) + 1;
        self.insert_key(&conn, subject, version, fresh, nonce, wall_ms)
    }

    /// One version of a subject's key, to unseal with.
    pub fn key(&self, subject: &str, version: u32) -> Result<KeyLookup, PrivacyError> {
        let conn = self.conn();
        if Self::erased_through(&conn, subject)?.is_some_and(|last| version <= last) {
            return Ok(KeyLookup::Erased);
        }
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT nonce, wrapped FROM subject_keys WHERE subject = ?1 AND version = ?2",
                params![subject, version],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        drop(conn);
        match row {
            Some((nonce, wrapped)) => Ok(KeyLookup::Found(
                self.unwrap_key(subject, version, &nonce, &wrapped)?,
            )),
            None => Ok(KeyLookup::Missing),
        }
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
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let conn = self.conn();
        let newest: Option<i64> = conn
            .query_row(
                "SELECT max(version) FROM subject_keys WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let floor = Self::erased_through(&conn, subject)?.unwrap_or(0);
        let version = newest.map_or(floor, |v| v as u32).max(floor) + 1;
        self.insert_key(&conn, subject, version, fresh, nonce, wall_ms)
            .map(|k| k.version)
    }

    /// Deletes every key of the subject and records the erasure; returns the
    /// last version erased (0 when the subject never had a key). Values sealed
    /// with those keys are unreadable from now on; copies of this keystore in
    /// backups keep them until the backups expire.
    pub fn erase(&self, subject: &str, wall_ms: u64) -> Result<u32, PrivacyError> {
        if !valid_subject(subject) {
            return Err(PrivacyError::InvalidSubject(subject.to_owned()));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let newest: Option<i64> = tx
            .query_row(
                "SELECT max(version) FROM subject_keys WHERE subject = ?1",
                [subject],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let floor = Self::erased_through(&tx, subject)?.unwrap_or(0);
        let last = newest.map_or(floor, |v| v as u32).max(floor);
        tx.execute("DELETE FROM subject_keys WHERE subject = ?1", [subject])?;
        tx.execute(
            "INSERT OR REPLACE INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
            params![subject, last, wall_ms as i64],
        )?;
        tx.commit()?;
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
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT subject, last_version, erased_wall_ms FROM erasures ORDER BY erased_wall_ms, subject",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ErasureInfo {
                subject: r.get(0)?,
                last_version: r.get::<_, i64>(1)? as u32,
                erased_wall_ms: r.get::<_, i64>(2)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn stats(&self) -> Result<KeystoreStats, PrivacyError> {
        let conn = self.conn();
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
    /// hidden too. [`Keystore::import_backup`] reads it.
    pub fn export_backup(&self, nonce: [u8; 24]) -> Result<Vec<u8>, PrivacyError> {
        let conn = self.conn();
        let mut payload = Vec::new();
        {
            let mut stmt = conn.prepare_cached(
                "SELECT subject, version, nonce, wrapped, created_wall_ms FROM subject_keys ORDER BY subject, version",
            )?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                payload.push(1u8);
                put(&mut payload, r.get::<_, String>(0)?.as_bytes());
                payload.extend_from_slice(&(r.get::<_, i64>(1)? as u32).to_le_bytes());
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
                payload.extend_from_slice(&(r.get::<_, i64>(1)? as u32).to_le_bytes());
                payload.extend_from_slice(&(r.get::<_, i64>(2)? as u64).to_le_bytes());
            }
        }
        let ciphertext = self
            .backup
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
        let payload = XChaCha20Poly1305::new(&master.derive("kronik keystore backup v1").into())
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: BACKUP_MAGIC,
                },
            )
            .map_err(|_| PrivacyError::Decrypt("the keystore backup".into()))?;
        let mut rows = BackupRows::default();
        let mut r = Reader(&payload);
        while let Some(tag) = r.byte() {
            match tag {
                1 => rows
                    .keys
                    .push((r.string()?, r.u32()?, r.bytes()?, r.bytes()?, r.u64()?)),
                2 => rows.erasures.push((r.string()?, r.u32()?, r.u64()?)),
                _ => return Err(bad()),
            }
        }
        Ok(rows)
    }

    /// Opens `conn` as a keystore holding exactly the backup's keys and
    /// erasures (a restore); the backup must come from the same master key.
    /// The store is replaced in one transaction after the backup decrypted,
    /// so a failure leaves it as it was, key check included.
    pub fn import_backup(
        mut conn: Connection,
        master: &MasterKey,
        backup: &[u8],
    ) -> Result<Keystore, PrivacyError> {
        let rows = Self::read_backup(master, backup)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(crate::KEY_CHECK)?;
        let tx = conn.transaction()?;
        tx.execute_batch("DELETE FROM subject_keys; DELETE FROM erasures; DELETE FROM key_check;")?;
        for (subject, version, nonce, wrapped, created) in &rows.keys {
            tx.execute(
                "INSERT INTO subject_keys (subject, version, nonce, wrapped, created_wall_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![subject, version, nonce, wrapped, *created as i64],
            )?;
        }
        for (subject, last, erased) in &rows.erasures {
            tx.execute(
                "INSERT INTO erasures (subject, last_version, erased_wall_ms) VALUES (?1, ?2, ?3)",
                params![subject, last, *erased as i64],
            )?;
        }
        tx.execute(
            "INSERT INTO key_check (id, value) VALUES (1, ?1)",
            [&master.check_value()[..]],
        )?;
        tx.commit()?;
        Keystore::open(conn, master)
    }
    /// Opens the keystore file at `path` (created if missing).
    pub fn open_file(path: &std::path::Path, master: &MasterKey) -> Result<Keystore, PrivacyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| PrivacyError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let conn = Connection::open(path)?;
        Self::open(conn, master)
    }

    /// [`Keystore::import_backup`] into `path`, replacing whatever is there.
    pub fn import_backup_file(
        path: &std::path::Path,
        master: &MasterKey,
        backup: &[u8],
    ) -> Result<Keystore, PrivacyError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| PrivacyError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let conn = Connection::open(path)?;
        Self::import_backup(conn, master, backup)
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
    let cipher = XChaCha20Poly1305::new(&key.key.into());
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
    let cipher = XChaCha20Poly1305::new(&key.key.into());
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
    key: [u8; 32],
    hashes: [u8; 32],
}

impl std::fmt::Debug for Pseudonyms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pseudonyms(..)")
    }
}

impl Pseudonyms {
    pub fn new(master: &MasterKey) -> Pseudonyms {
        Pseudonyms {
            key: master.derive("kronik pseudonym v1"),
            hashes: master.derive("kronik keyed hash v1"),
        }
    }

    pub fn of(&self, subject: &str, value: &[u8]) -> String {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(subject.as_bytes());
        h.update(b"\0");
        h.update(value);
        format!("pii:{}", hex(&h.finalize().as_bytes()[..6]))
    }

    /// A keyed BLAKE3 of `parts` for `purpose` (a fixed domain string):
    /// each part is length-prefixed, so part boundaries can't be shifted.
    pub fn keyed_hash(&self, purpose: &str, parts: &[&[u8]]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(&self.hashes);
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
        Keystore::open(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([master; 32]),
        )
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
        assert_eq!((again.version, again.key), (1, [7; 32]));
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
        assert_eq!((v2.version, v2.key), (2, [2; 32]));
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
        let path = dir.path().join("keystore.db");
        let ks = Keystore::open(
            Connection::open(&path).unwrap(),
            &MasterKey::from_bytes([1; 32]),
        )
        .unwrap();
        ks.key_for_sealing("user:1", [0xab; 32], [1; 24], 0)
            .unwrap();
        drop(ks);
        let conn = Connection::open(&path).unwrap();
        let wrapped: Vec<u8> = conn
            .query_row("SELECT wrapped FROM subject_keys", [], |r| r.get(0))
            .unwrap();
        assert!(!wrapped.windows(4).any(|w| w == [0xab; 4]));
        // Another master key is refused before it can try to unwrap.
        let other = Keystore::open(conn, &MasterKey::from_bytes([2; 32]));
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

        let restored = Keystore::import_backup(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([1; 32]),
            &backup,
        )
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

        let wrong = Keystore::import_backup(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([2; 32]),
            &backup,
        );
        assert!(matches!(wrong, Err(PrivacyError::Decrypt(_))));
        let mut tampered = backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = Keystore::import_backup(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([1; 32]),
            &tampered,
        );
        assert!(matches!(tampered, Err(PrivacyError::Decrypt(_))));
        let junk = Keystore::import_backup(
            Connection::open_in_memory().unwrap(),
            &MasterKey::from_bytes([1; 32]),
            b"junk",
        );
        assert!(matches!(junk, Err(PrivacyError::BadBackup)));

        // A backup under another key leaves an existing store untouched,
        // its key check included.
        let dir = tempfile::tempdir().unwrap();
        let kept = dir.path().join("kept.db");
        Keystore::open_file(&kept, &MasterKey::from_bytes([3; 32]))
            .unwrap()
            .key_for_sealing("user:7", [7; 32], [7; 24], 0)
            .unwrap();
        assert!(matches!(
            Keystore::import_backup_file(&kept, &MasterKey::from_bytes([3; 32]), &backup),
            Err(PrivacyError::Decrypt(_))
        ));
        let still = Keystore::open_file(&kept, &MasterKey::from_bytes([3; 32])).unwrap();
        found(still.key("user:7", 1).unwrap());

        // A restore over a keystore of another key replaces it, key included.
        let path = dir.path().join("keystore.db");
        Keystore::open_file(&path, &MasterKey::from_bytes([3; 32]))
            .unwrap()
            .key_for_sealing("user:9", [9; 32], [9; 24], 0)
            .unwrap();
        let replaced =
            Keystore::import_backup_file(&path, &MasterKey::from_bytes([1; 32]), &backup).unwrap();
        found(replaced.key("user:1", 1).unwrap());
        drop(replaced);
        Keystore::open_file(&path, &MasterKey::from_bytes([1; 32])).unwrap();
    }

    #[test]
    fn pseudonyms_are_deterministic_short_and_keyed() {
        let p = Pseudonyms::new(&MasterKey::from_bytes([1; 32]));
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
            Pseudonyms::new(&MasterKey::from_bytes([2; 32])).of("user:1", b"alice@example.com")
        );
    }
}
