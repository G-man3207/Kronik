//! Encrypted scrub-only copies of recorded external secret versions (ADR
//! 0142): the value of each version of a secret linked to an external
//! backend that this node recorded, kept in `keys/secrets.db` so that the
//! views that remove secret values can still remove it after a restart when
//! the backend no longer serves that version.
//!
//! A copy is only ever read back into the scrub inventory. It never answers
//! an effect, a fork computation, a reveal or a foreign actor, and no API
//! serves it.
//!
//! Each copy is sealed with XChaCha20-Poly1305 under its own key, derived
//! from the store's storage key (itself derived from the master seed) with
//! the context `kronik external scrub copies v1`, so a copy cannot be read
//! as a built-in secret or the other way round. The associated data binds
//! the version's whole identity: name, Kronik version, backend, canonical
//! reference, the backend's version id and the keyed version hash.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{OptionalExtension, params};
use zeroize::Zeroizing;

use crate::{
    PrivacyError, SecretStore, SecretStoreCustody, sql_version, stored_version, valid_name,
};

/// The table, created with the rest of the schema by every writer.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS external_scrub_copies (
  name TEXT NOT NULL, version INTEGER NOT NULL, backend TEXT NOT NULL,
  canonical_ref TEXT NOT NULL, source_version TEXT NOT NULL,
  version_hash BLOB NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  created_wall_ms INTEGER NOT NULL,
  PRIMARY KEY (name, version)) WITHOUT ROWID;
";

/// A stored copy's identity columns and its sealed value: backend, canonical
/// reference, version id, version hash, nonce and ciphertext.
type StoredCopy = (String, String, String, Vec<u8>, Vec<u8>, Vec<u8>);
/// A stored copy's identity: name, version, backend, canonical reference,
/// version id and version hash.
type CopyIdentity = (String, i64, String, String, String, Vec<u8>);

/// The identity of one recorded external version: what its `SecretVersion`
/// record says. A copy opens only for exactly this identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubCopy {
    pub name: String,
    pub version: u64,
    pub backend: String,
    pub canonical_ref: String,
    pub source_version: String,
    pub version_hash: Vec<u8>,
}

impl ScrubCopy {
    fn check(&self) -> Result<(), PrivacyError> {
        if !valid_name(&self.name) {
            return Err(PrivacyError::InvalidName(self.name.clone()));
        }
        sql_version(self.version)?;
        // The built-in store keeps its own versions; a copy is of an
        // external backend's version only.
        if self.backend.is_empty()
            || self.backend == "file"
            || self.canonical_ref.is_empty()
            || self.source_version.is_empty()
            || self.version_hash.len() != 16
        {
            return Err(PrivacyError::InvalidSecretRow);
        }
        Ok(())
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = b"kronik external scrub copy v1".to_vec();
        for field in [
            self.name.as_bytes(),
            self.version.to_string().as_bytes(),
            self.backend.as_bytes(),
            self.canonical_ref.as_bytes(),
            self.source_version.as_bytes(),
            &self.version_hash,
        ] {
            // Length-prefixed, so no two identities share their bytes.
            aad.extend_from_slice(&(field.len() as u64).to_le_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }
}

impl SecretStore {
    /// The copies' own key, derived for one operation and wiped after it.
    fn copy_cipher(&self) -> XChaCha20Poly1305 {
        let key = Zeroizing::new(blake3::derive_key(
            "kronik external scrub copies v1",
            self.cipher.bytes(),
        ));
        XChaCha20Poly1305::new((&*key).into())
    }

    fn copy_writer(&self) -> Result<(), PrivacyError> {
        match &self.custody {
            SecretStoreCustody::Owned(owned) => owned.check(),
            SecretStoreCustody::Memory(_) => Ok(()),
            SecretStoreCustody::ReadOnly => Err(PrivacyError::SecretStoreUnowned),
            #[cfg(test)]
            SecretStoreCustody::Fixture => Ok(()),
        }
    }

    /// Keeps `value` as the scrub-only copy of `copy`, sealed under a fresh
    /// nonce. `false` when a copy of exactly that version is there already:
    /// a version's value never changes, so the stored one is kept. A stored
    /// copy of the same name and version with another identity is replaced.
    /// The value must be the version's: its keyed hash is checked.
    pub fn put_scrub_copy(
        &self,
        copy: &ScrubCopy,
        value: &[u8],
        nonce: [u8; 24],
        wall_ms: u64,
    ) -> Result<bool, PrivacyError> {
        copy.check()?;
        if self.version_hash(&copy.name, copy.version, value)? != copy.version_hash {
            return Err(PrivacyError::InvalidSecretRow);
        }
        self.copy_writer()?;
        let ciphertext = self
            .copy_cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: value,
                    aad: &copy.aad(),
                },
            )
            .map_err(|_| PrivacyError::Decrypt(copy.name.clone()))?;
        let wall = i64::try_from(wall_ms).map_err(|_| PrivacyError::InvalidTimestamp)?;
        let inserted = self.conn().execute(
            "INSERT INTO external_scrub_copies (name, version, backend, canonical_ref, \
             source_version, version_hash, nonce, ciphertext, created_wall_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT(name, version) DO UPDATE SET \
             backend = excluded.backend, canonical_ref = excluded.canonical_ref, \
             source_version = excluded.source_version, version_hash = excluded.version_hash, \
             nonce = excluded.nonce, ciphertext = excluded.ciphertext, \
             created_wall_ms = excluded.created_wall_ms \
             WHERE backend IS NOT excluded.backend OR canonical_ref IS NOT excluded.canonical_ref \
             OR source_version IS NOT excluded.source_version \
             OR version_hash IS NOT excluded.version_hash",
            params![
                copy.name,
                sql_version(copy.version)?,
                copy.backend,
                copy.canonical_ref,
                copy.source_version,
                copy.version_hash,
                nonce.to_vec(),
                ciphertext,
                wall,
            ],
        )?;
        Ok(inserted == 1)
    }

    /// The value kept for `copy`, when a copy of exactly that identity is
    /// there and opens. A copy of the same name and version with another
    /// identity (the records were replaced, as a restore from another
    /// node's snapshot can do) is no copy of this version: `None`.
    pub fn scrub_copy(&self, copy: &ScrubCopy) -> Result<Option<Zeroizing<Vec<u8>>>, PrivacyError> {
        copy.check()?;
        if !self.has_copy_table {
            return Ok(None);
        }
        let stored: Option<StoredCopy> = self
            .conn()
            .query_row(
                "SELECT backend, canonical_ref, source_version, version_hash, nonce, ciphertext \
                 FROM external_scrub_copies WHERE name = ?1 AND version = ?2",
                params![copy.name, sql_version(copy.version)?],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((backend, canonical_ref, source_version, version_hash, nonce, ciphertext)) =
            stored
        else {
            return Ok(None);
        };
        if backend != copy.backend
            || canonical_ref != copy.canonical_ref
            || source_version != copy.source_version
            || version_hash != copy.version_hash
        {
            return Ok(None);
        }
        let nonce = XNonce::try_from(nonce.as_slice())
            .map_err(|_| PrivacyError::Decrypt(copy.name.clone()))?;
        let value = Zeroizing::new(
            self.copy_cipher()
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &copy.aad(),
                    },
                )
                .map_err(|_| PrivacyError::Decrypt(copy.name.clone()))?,
        );
        if self.version_hash(&copy.name, copy.version, &value)? != copy.version_hash {
            return Err(PrivacyError::InvalidSecretRow);
        }
        Ok(Some(value))
    }

    /// The identity of every copy, without opening any, for the sweep of
    /// copies whose version is not an active recorded one.
    pub fn scrub_copy_identities(&self) -> Result<Vec<ScrubCopy>, PrivacyError> {
        if !self.has_copy_table {
            return Ok(Vec::new());
        }
        let conn = self.conn();
        let mut statement = conn.prepare(
            "SELECT name, version, backend, canonical_ref, source_version, version_hash \
             FROM external_scrub_copies ORDER BY name, version",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut copies = Vec::new();
        for row in rows {
            let (name, version, backend, canonical_ref, source_version, version_hash) = row?;
            copies.push(ScrubCopy {
                name,
                version: stored_version(version)?,
                backend,
                canonical_ref,
                source_version,
                version_hash,
            });
        }
        Ok(copies)
    }

    /// Deletes the copy of `name` version `version`; whether there was one.
    pub fn delete_scrub_copy(&self, name: &str, version: u64) -> Result<bool, PrivacyError> {
        self.copy_writer()?;
        if !self.has_copy_table {
            return Ok(false);
        }
        let deleted = self.conn().execute(
            "DELETE FROM external_scrub_copies WHERE name = ?1 AND version = ?2",
            params![name, sql_version(version)?],
        )?;
        Ok(deleted == 1)
    }

    /// Every copy's value, for scanning text (the built-in store's
    /// [`SecretStore::values`] adds them). A copy that does not open fails
    /// the whole list rather than claim complete coverage.
    pub(crate) fn scrub_copy_values(&self) -> Result<Vec<(String, Vec<u8>)>, PrivacyError> {
        if !self.has_copy_table {
            return Ok(Vec::new());
        }
        let rows: Vec<CopyIdentity> = {
            let conn = self.conn();
            let mut statement = conn.prepare(
                "SELECT name, version, backend, canonical_ref, source_version, version_hash \
                 FROM external_scrub_copies ORDER BY name, version",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        let mut values = Vec::with_capacity(rows.len());
        for (name, version, backend, canonical_ref, source_version, version_hash) in rows {
            let copy = ScrubCopy {
                name: name.clone(),
                version: stored_version(version)?,
                backend,
                canonical_ref,
                source_version,
                version_hash,
            };
            let value = self
                .scrub_copy(&copy)?
                .ok_or(PrivacyError::SecretRowIncomplete)?;
            values.push((name, value.to_vec()));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MasterKey;

    fn store() -> SecretStore {
        let master = MasterKey::from_bytes([7; 32]).unwrap();
        SecretStore::open(rusqlite::Connection::open_in_memory().unwrap(), &master).unwrap()
    }

    fn copy(store: &SecretStore, value: &[u8]) -> ScrubCopy {
        ScrubCopy {
            name: "stripe".into(),
            version: 3,
            backend: "bao".into(),
            canonical_ref: "secret/payments#stripe".into(),
            source_version: "7".into(),
            version_hash: store.version_hash("stripe", 3, value).unwrap(),
        }
    }

    /// A copy opens only for its exact identity, keeps the first value of a
    /// version, and never holds the plaintext in the database.
    #[test]
    fn a_copy_opens_only_for_its_own_identity() {
        let store = store();
        let value = b"sk_live_needle_4f1c";
        let meta = copy(&store, value);
        assert!(store.put_scrub_copy(&meta, value, [1; 24], 10).unwrap());
        assert!(!store.put_scrub_copy(&meta, value, [2; 24], 11).unwrap());
        assert_eq!(&**store.scrub_copy(&meta).unwrap().unwrap(), value);
        for other in [
            ScrubCopy {
                source_version: "8".into(),
                ..meta.clone()
            },
            ScrubCopy {
                backend: "aws".into(),
                ..meta.clone()
            },
            ScrubCopy {
                canonical_ref: "secret/other#stripe".into(),
                ..meta.clone()
            },
        ] {
            assert_eq!(store.scrub_copy(&other).unwrap(), None, "{other:?}");
        }
        // A wrong value for the version is refused before anything is kept.
        let wrong = ScrubCopy {
            version: 4,
            ..meta.clone()
        };
        assert!(store.put_scrub_copy(&wrong, value, [3; 24], 12).is_err());
        // The built-in store's backend has no copies.
        let file = ScrubCopy {
            backend: "file".into(),
            ..meta.clone()
        };
        assert!(store.put_scrub_copy(&file, value, [4; 24], 13).is_err());
        // Ciphertext only: the needle is in no column.
        let conn = store.conn();
        let mut statement = conn
            .prepare("SELECT nonce, ciphertext, version_hash FROM external_scrub_copies")
            .unwrap();
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(rows.len(), 1);
        for (nonce, ciphertext, hash) in &rows {
            for column in [nonce, ciphertext, hash] {
                assert!(!column.windows(value.len()).any(|w| w == value));
            }
        }
        drop(statement);
        drop(conn);
        assert_eq!(store.scrub_copy_identities().unwrap(), vec![meta.clone()]);
        // The same version under another identity replaces it.
        let moved = ScrubCopy {
            source_version: "8".into(),
            ..meta.clone()
        };
        assert!(store.put_scrub_copy(&moved, value, [5; 24], 14).unwrap());
        assert_eq!(store.scrub_copy(&meta).unwrap(), None);
        assert_eq!(&**store.scrub_copy(&moved).unwrap().unwrap(), value);
        assert!(store.put_scrub_copy(&meta, value, [6; 24], 15).unwrap());
        assert_eq!(
            store.scrub_copy_values().unwrap(),
            vec![("stripe".to_owned(), value.to_vec())]
        );
        assert!(store.delete_scrub_copy("stripe", 3).unwrap());
        assert_eq!(store.scrub_copy(&meta).unwrap(), None);
    }

    /// Another master key opens no copy, and a copy whose bytes changed
    /// fails instead of giving a wrong value.
    #[test]
    fn a_copy_opens_only_under_its_master_key_and_unchanged() {
        let store = store();
        let value = b"sk_live_needle_4f1c";
        let meta = copy(&store, value);
        store.put_scrub_copy(&meta, value, [1; 24], 10).unwrap();
        {
            let conn = store.conn();
            conn.execute(
                "UPDATE external_scrub_copies SET ciphertext = \
                 substr(ciphertext, 1, 4) || X'00' || substr(ciphertext, 6)",
                [],
            )
            .unwrap();
        }
        assert!(store.scrub_copy(&meta).is_err());
        let other = MasterKey::from_bytes([8; 32]).unwrap();
        let elsewhere =
            SecretStore::open(rusqlite::Connection::open_in_memory().unwrap(), &other).unwrap();
        let meta_elsewhere = ScrubCopy {
            version_hash: elsewhere.version_hash("stripe", 3, value).unwrap(),
            ..meta
        };
        elsewhere
            .put_scrub_copy(&meta_elsewhere, value, [1; 24], 10)
            .unwrap();
        // The same row under the first key does not open.
        let row: (Vec<u8>, Vec<u8>) = elsewhere
            .conn()
            .query_row(
                "SELECT nonce, ciphertext FROM external_scrub_copies",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(
            store
                .copy_cipher()
                .decrypt(
                    &XNonce::try_from(row.0.as_slice()).unwrap(),
                    Payload {
                        msg: &row.1,
                        aad: &meta_elsewhere.aad(),
                    },
                )
                .is_err()
        );
    }
}
