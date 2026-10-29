//! Hashed actor keys (`[otel] actor_keys = "hashed"`, m28-otel §3.5, ADR
//! 0082): `kh:` + 12 hex of a keyed hash of `[kind, key]`, stable for
//! correlation and not reversible without the key. The key is the master
//! key's hash key when the node has one, else a node-local key (review M5).

use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::Arc;

use kronik_privacy::sealer::Sealer;

use crate::spans::{ID_KEY_PURPOSE, IdKey, KEY_HASH_PURPOSE, key_label};

/// The node-local hash key, 32 random bytes, mode 0600.
pub const LOCAL_KEY_FILE: &str = "otel.key";

#[derive(Clone)]
pub enum KeyHasher {
    /// `Sealer::keyed_hash` with the master-derived key.
    Master(Arc<Sealer>),
    /// The same construction keyed with `<data>/otel.key`.
    Local([u8; 32]),
}

impl KeyHasher {
    /// The master key's hasher, else the local key, created at first use
    /// from `random`.
    pub fn open(
        sealer: Arc<Sealer>,
        data_dir: &Path,
        random: impl FnOnce() -> [u8; 32],
    ) -> io::Result<KeyHasher> {
        if sealer.keyed_hash(KEY_HASH_PURPOSE, &[]).is_some() {
            return Ok(KeyHasher::Master(sealer));
        }
        let path = data_dir.join(LOCAL_KEY_FILE);
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path);
        match created {
            Ok(mut f) => {
                let key = random();
                f.write_all(&key)?;
                f.sync_all()?;
                if let Ok(dir) = std::fs::File::open(data_dir) {
                    dir.sync_all()?;
                }
                Ok(KeyHasher::Local(key))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let mut key = [0; 32];
                std::fs::File::open(&path)?.read_exact(&mut key)?;
                Ok(KeyHasher::Local(key))
            }
            Err(e) => Err(e),
        }
    }

    /// `kh:<12 hex>` of `[kind, key]`.
    pub fn label(&self, kind: &str, key: &str) -> String {
        let parts: [&[u8]; 2] = [kind.as_bytes(), key.as_bytes()];
        let hash = match self {
            KeyHasher::Master(s) => s.keyed_hash(KEY_HASH_PURPOSE, &parts),
            KeyHasher::Local(k) => Some(keyed_hash(k, KEY_HASH_PURPOSE, &parts)),
        };
        hash.map_or_else(String::new, |h| key_label(&h))
    }

    /// The key of exported span and trace ids, under its own purpose.
    pub fn id_key(&self) -> IdKey {
        IdKey(match self {
            // `open` makes `Master` only when the sealer hashes.
            KeyHasher::Master(s) => s.keyed_hash(ID_KEY_PURPOSE, &[]).unwrap_or_default(),
            KeyHasher::Local(k) => keyed_hash(k, ID_KEY_PURPOSE, &[]),
        })
    }
}

/// `Pseudonyms::keyed_hash`'s construction: purpose, NUL, then each part
/// with its length.
fn keyed_hash(key: &[u8; 32], purpose: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(purpose.as_bytes());
    h.update(b"\0");
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_master_key_the_local_key_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let sealer = Arc::new(Sealer::plain());
        let a = KeyHasher::open(sealer.clone(), dir.path(), || [7; 32]).unwrap();
        let b = KeyHasher::open(sealer, dir.path(), || [9; 32]).unwrap();
        let label = a.label("counter", "carol@example.com");
        assert_eq!(label, b.label("counter", "carol@example.com"));
        assert!(label.starts_with("kh:") && label.len() == 15, "{label}");
        assert_ne!(label, a.label("counter", "dave@example.com"));
        let meta = std::fs::metadata(dir.path().join(LOCAL_KEY_FILE)).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
