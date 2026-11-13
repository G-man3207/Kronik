//! Compatibility fixtures of the blob file format, version 1 (ADR 0117 §2):
//! a plain and a sealed file written by this format must keep reading to the
//! same bytes. Regenerate them only for a new format version, with
//! `KRONIK_WRITE_FIXTURES=1`.
//!
//! The sealed fixture's keys are derived as the privacy crate derives them
//! (`kronik_privacy::sealer::BLOB_IDENTITY_LABEL` and `BLOB_SEAL_LABEL`) from
//! a fixed subject key, so a changed label fails here too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use kronik_blob::{
    BlobId, BlobKeys, BlobMeta, BlobStore, KeyAccess, KeyAnswer, NoKeys, Space, StoreConfig,
};
use kronik_core::env::Env;
use zeroize::Zeroizing;

const SUBJECT_KEY: [u8; 32] = [7; 32];
const IDENTITY_LABEL: &str = "kronik blob identity v1";
const SEAL_LABEL: &str = "kronik blob seal v1";
/// Two frames: one full, one of four bytes.
const SIZE: usize = 65_540;

fn content() -> Vec<u8> {
    let mut out = vec![0u8; SIZE];
    blake3::Hasher::new()
        .update(b"kronik blob fixture v1")
        .finalize_xof()
        .fill(&mut out);
    out
}

struct FixtureKeys;

impl KeyAccess for FixtureKeys {
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer {
        if (subject, version) != ("user:7", 1) {
            return KeyAnswer::Missing;
        }
        KeyAnswer::Found(Zeroizing::new(blake3::derive_key(SEAL_LABEL, &SUBJECT_KEY)))
    }
    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer {
        if (subject, version) != ("user:7", 1) {
            return KeyAnswer::Missing;
        }
        KeyAnswer::Found(Zeroizing::new(blake3::derive_key(
            IDENTITY_LABEL,
            &SUBJECT_KEY,
        )))
    }
}

fn plain_meta() -> BlobMeta {
    BlobMeta {
        id: BlobId::plain(*blake3::hash(&content()).as_bytes()),
        size: SIZE as u64,
        subject: None,
        key_version: 0,
    }
}

fn sealed_meta() -> BlobMeta {
    let key = blake3::derive_key(IDENTITY_LABEL, &SUBJECT_KEY);
    BlobMeta {
        id: BlobId::keyed(*blake3::keyed_hash(&key, &content()).as_bytes()),
        size: SIZE as u64,
        subject: Some("user:7".into()),
        key_version: 1,
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

async fn write_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        StoreConfig::default(),
    )
    .await
    .unwrap();
    let keys = BlobKeys {
        subject: "user:7".into(),
        key_version: 1,
        identity: Zeroizing::new(blake3::derive_key(IDENTITY_LABEL, &SUBJECT_KEY)),
        seal: Some(Zeroizing::new(blake3::derive_key(SEAL_LABEL, &SUBJECT_KEY))),
    };
    for (name, keys) in [("plain-v1.blob", None), ("sealed-v1.blob", Some(keys))] {
        let mut w = store
            .writer(Space::Main, keys, u64::MAX, store.leases().take("fixture"))
            .await
            .unwrap();
        w.write(&content()).await.unwrap();
        let meta = w.finish().await.unwrap();
        std::fs::create_dir_all(fixture("")).unwrap();
        std::fs::copy(store.object_path(&Space::Main, &meta.id), fixture(name)).unwrap();
    }
}

/// Installs a fixture file in a fresh store under its object name.
async fn install(name: &str, meta: &BlobMeta) -> (tempfile::TempDir, std::sync::Arc<BlobStore>) {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        StoreConfig::default(),
    )
    .await
    .unwrap();
    std::fs::copy(fixture(name), store.object_path(&Space::Main, &meta.id)).unwrap();
    (dir, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn version_1_files_still_read() {
    if std::env::var_os("KRONIK_WRITE_FIXTURES").is_some() {
        write_fixtures().await;
    }
    let plain = plain_meta();
    let (_dir, store) = install("plain-v1.blob", &plain).await;
    let r = store.reader(&Space::Main, &plain, &NoKeys).await.unwrap();
    assert!(!r.is_sealed());
    assert_eq!(r.read_at(0, SIZE).await.unwrap(), content());
    r.verify(&NoKeys).await.unwrap();

    let sealed = sealed_meta();
    let (_dir, store) = install("sealed-v1.blob", &sealed).await;
    let r = store
        .reader(&Space::Main, &sealed, &FixtureKeys)
        .await
        .unwrap();
    assert!(r.is_sealed());
    assert_eq!(r.read_at(0, SIZE).await.unwrap(), content());
    r.verify(&FixtureKeys).await.unwrap();
    let bytes = std::fs::read(fixture("sealed-v1.blob")).unwrap();
    assert!(!bytes.windows(32).any(|w| w == &content()[100..132]));
}
