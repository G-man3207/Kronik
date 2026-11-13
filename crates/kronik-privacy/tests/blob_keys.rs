//! A subject's sealed blob end to end: written with the sealer's blob keys,
//! read with its key access, and unreadable once the subject is erased.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use kronik_blob::{BlobError, BlobStore, Space, StoreConfig};
use kronik_core::env::Env;
use kronik_privacy::MasterKey;
use kronik_privacy::keystore::Keystore;
use kronik_privacy::sealer::Sealer;

#[tokio::test]
async fn sealed_blobs_open_with_the_sealers_keys_until_erased() {
    let dir = tempfile::tempdir().unwrap();
    let sealer = Sealer::new(Arc::new(
        Keystore::open_memory(&MasterKey::from_bytes([2; 32]).unwrap()).unwrap(),
    ));
    sealer.set_on(true);
    let store = BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        StoreConfig::default(),
    )
    .await
    .unwrap();
    let document = b"a document of user:1 ".repeat(5000);
    let keys = sealer
        .blob_keys("user:1", &|b: &mut [u8]| b.fill(3), 1)
        .unwrap();
    let mut w = store
        .writer(Space::Main, Some(keys), u64::MAX, store.leases().take("t"))
        .await
        .unwrap();
    w.write(&document).await.unwrap();
    let meta = w.finish().await.unwrap();
    assert_eq!(
        (meta.subject.as_deref(), meta.key_version),
        (Some("user:1"), 1)
    );
    let access = sealer.blob_key_access();
    let r = store.reader(&Space::Main, &meta, &access).await.unwrap();
    assert!(r.is_sealed());
    assert_eq!(r.read_at(0, document.len()).await.unwrap(), document);
    r.verify(&access).await.unwrap();

    // Without the keystore the blob cannot be read.
    assert!(matches!(
        store
            .reader(&Space::Main, &meta, &Sealer::plain().blob_key_access())
            .await,
        Err(BlobError::KeyMissing(_))
    ));
    sealer.erase("user:1", 2).unwrap();
    assert!(matches!(
        store
            .reader(&Space::Main, &meta, &sealer.blob_key_access())
            .await,
        Err(BlobError::Erased)
    ));
}
