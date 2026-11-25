//! Shared helpers for the blob store's integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kronik_blob::{BlobKeys, BlobMeta, BlobStore, KeyAccess, KeyAnswer, Space, StoreConfig};
use kronik_core::env::Env;
use zeroize::Zeroizing;

pub fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.finalize_xof().fill(&mut out);
    out
}

pub fn derived(label: &str, subject: &str, version: u32) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(label);
    h.update(subject.as_bytes());
    h.update(&version.to_le_bytes());
    Zeroizing::new(*h.finalize().as_bytes())
}

/// Test keys: a frame key and an identity key per (subject, version), and a
/// set of erased subjects.
#[derive(Default)]
pub struct TestKeys {
    erased: Mutex<Vec<String>>,
}

impl TestKeys {
    pub fn keys(&self, subject: &str, version: u32, sealed: bool) -> BlobKeys {
        BlobKeys {
            subject: subject.into(),
            key_version: version,
            identity: derived("test identity", subject, version),
            seal: sealed.then(|| derived("test seal", subject, version)),
        }
    }

    /// The keys of a subject's blob written while the mode is off: keyed,
    /// not sealed.
    pub fn plain(&self, subject: &str) -> BlobKeys {
        self.keys(subject, 1, false)
    }

    pub fn erase(&self, subject: &str) {
        self.erased.lock().unwrap().push(subject.into());
    }

    fn answer(&self, label: &str, subject: &str, version: u32) -> KeyAnswer {
        if self.erased.lock().unwrap().iter().any(|s| s == subject) {
            return KeyAnswer::Erased;
        }
        KeyAnswer::Found(derived(label, subject, version))
    }
}

impl KeyAccess for TestKeys {
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer {
        self.answer("test seal", subject, version)
    }
    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer {
        self.answer("test identity", subject, version)
    }
}

pub async fn open(dir: &Path) -> Arc<BlobStore> {
    open_with(dir, StoreConfig::default()).await
}

pub async fn open_with(dir: &Path, config: StoreConfig) -> Arc<BlobStore> {
    BlobStore::open(Env::real(tokio::runtime::Handle::current()), dir, config)
        .await
        .unwrap()
}

pub async fn put_in(
    store: &Arc<BlobStore>,
    space: &Space,
    keys: Option<BlobKeys>,
    data: &[u8],
    chunk: usize,
) -> BlobMeta {
    let lease = store.leases().take("test");
    let mut w = store
        .writer(space.clone(), keys, u64::MAX, lease)
        .await
        .unwrap();
    for c in data.chunks(chunk.max(1)) {
        w.write(c).await.unwrap();
    }
    let meta = w.finish().await.unwrap();
    store.ensure_durable(space, &[meta.id]).await.unwrap();
    meta
}

pub async fn put(
    store: &Arc<BlobStore>,
    keys: Option<BlobKeys>,
    data: &[u8],
    chunk: usize,
) -> BlobMeta {
    put_in(store, &Space::Main, keys, data, chunk).await
}

pub fn object(dir: &Path, meta: &BlobMeta) -> PathBuf {
    dir.join("blobs/objects")
        .join(meta.id.shard())
        .join(meta.id.file_name())
}
