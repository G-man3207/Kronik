//! The blob store's part of privacy (M26 §9.3, §9.4): sealing a subject's
//! plain file in place for a reseal, deleting the files of erased blobs, and
//! a read of an erased subject's deleted blob answering `Erased`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kronik_blob::format::{FRAME_SIZE, HEADER_LEN, Header};
use kronik_blob::{
    BlobError, BlobKeys, BlobMeta, BlobStore, KeyAccess, KeyAnswer, Resealed, Space, StoreConfig,
};
use kronik_core::env::Env;
use zeroize::Zeroizing;

fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.finalize_xof().fill(&mut out);
    out
}

fn derived(label: &str, subject: &str, version: u32) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(label);
    h.update(subject.as_bytes());
    h.update(&version.to_le_bytes());
    Zeroizing::new(*h.finalize().as_bytes())
}

/// Keys per (subject, version), and a set of erased subjects.
#[derive(Default)]
struct TestKeys {
    erased: Mutex<Vec<String>>,
}

impl TestKeys {
    /// The keys of a subject's blob written while the mode is off: keyed,
    /// not sealed.
    fn plain(&self, subject: &str) -> BlobKeys {
        BlobKeys {
            subject: subject.into(),
            key_version: 1,
            identity: derived("test identity", subject, 1),
            seal: None,
        }
    }

    fn erase(&self, subject: &str) {
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

async fn open(dir: &Path) -> Arc<BlobStore> {
    BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir,
        StoreConfig::default(),
    )
    .await
    .unwrap()
}

async fn put(store: &Arc<BlobStore>, keys: BlobKeys, data: &[u8]) -> BlobMeta {
    let mut w = store
        .writer(
            Space::Main,
            Some(keys),
            u64::MAX,
            store.leases().take("test"),
        )
        .await
        .unwrap();
    w.write(data).await.unwrap();
    let meta = w.finish().await.unwrap();
    store
        .ensure_durable(&Space::Main, &[meta.id])
        .await
        .unwrap();
    meta
}

fn object(dir: &Path, meta: &BlobMeta) -> PathBuf {
    dir.join("blobs/objects")
        .join(meta.id.shard())
        .join(meta.id.file_name())
}

fn header(path: &Path) -> Header {
    let bytes = std::fs::read(path).unwrap();
    Header::decode(&bytes[..HEADER_LEN]).unwrap()
}

async fn read_all(store: &BlobStore, meta: &BlobMeta, keys: &TestKeys) -> Vec<u8> {
    let reader = store.reader(&Space::Main, meta, keys).await.unwrap();
    reader.verify(keys).await.unwrap();
    reader
        .read_at(0, usize::try_from(meta.size).unwrap())
        .await
        .unwrap()
        .to_vec()
}

/// The error of opening a reader of `meta`, if any.
async fn read_error(store: &BlobStore, meta: &BlobMeta, keys: &TestKeys) -> Option<BlobError> {
    store.reader(&Space::Main, meta, keys).await.err()
}

fn tmp_files(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("blobs/tmp")).map_or(0, |d| d.count())
}

/// §9.4: a subject's plain file is sealed in place at every frame border:
/// the same name and identity, a sealed header, the same content through a
/// reader with the subject's keys, and the mark hook called once before the
/// rename. Sealing again changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_subject_file_is_sealed_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    for (i, size) in [
        0,
        1,
        FRAME_SIZE - 1,
        FRAME_SIZE,
        FRAME_SIZE + 1,
        3 * FRAME_SIZE + 5,
    ]
    .into_iter()
    .enumerate()
    {
        let data = content(i as u64, size);
        let meta = put(&store, keys.plain("user:1"), &data).await;
        let path = object(dir.path(), &meta);
        assert!(!header(&path).sealed);
        assert_eq!(
            store
                .is_plain_subject_file(&Space::Main, &meta.id)
                .await
                .unwrap(),
            Some(true)
        );
        let marks = Arc::new(AtomicUsize::new(0));
        let counted = marks.clone();
        let mark = move || -> kronik_core::env::BoxFuture<'static, Result<(), BlobError>> {
            counted.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        };
        let r = store
            .seal_in_place(&Space::Main, &meta.id, &keys, &mark)
            .await
            .unwrap();
        assert_eq!(r, Resealed::Sealed, "size {size}");
        assert_eq!(marks.load(Ordering::Relaxed), 1);
        let h = header(&path);
        assert!(h.sealed, "size {size}");
        assert_eq!(h.size, size as u64);
        assert_eq!(read_all(&store, &meta, &keys).await, data, "size {size}");
        assert_eq!(
            store
                .is_plain_subject_file(&Space::Main, &meta.id)
                .await
                .unwrap(),
            Some(false)
        );
        let again = store
            .seal_in_place(&Space::Main, &meta.id, &keys, &mark)
            .await
            .unwrap();
        assert_eq!(again, Resealed::Unchanged);
        assert_eq!(marks.load(Ordering::Relaxed), 1, "no second mark");
    }
    assert_eq!(tmp_files(dir.path()), 0, "no part file is left");
}

/// A damaged plain file is not sealed: the error is `Corrupt`, the file stays
/// as it was, no mark is made and no part file is left. A subject erased
/// meanwhile leaves its file to the erasure's deletion.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_or_erased_file_is_not_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let meta = put(&store, keys.plain("user:1"), &content(7, 3 * FRAME_SIZE)).await;
    let path = object(dir.path(), &meta);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[HEADER_LEN + FRAME_SIZE + 10] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let mark = || -> kronik_core::env::BoxFuture<'static, Result<(), BlobError>> {
        panic!("a damaged file is never marked")
    };
    let err = store
        .seal_in_place(&Space::Main, &meta.id, &keys, &mark)
        .await
        .unwrap_err();
    assert!(matches!(err, BlobError::Corrupt { .. }), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(tmp_files(dir.path()), 0);

    let other = put(&store, keys.plain("user:2"), b"two").await;
    keys.erase("user:2");
    let r = store
        .seal_in_place(&Space::Main, &other.id, &keys, &mark)
        .await
        .unwrap();
    assert_eq!(r, Resealed::Erased);
    assert!(!header(&object(dir.path(), &other)).sealed);
}

/// §9.3: the files of erased blobs go from a space, counted once; a read of a
/// subject's blob whose file is gone answers `Erased` once its subject is
/// erased, and `NotFound` otherwise.
#[tokio::test(flavor = "multi_thread")]
async fn erased_blobs_files_go_and_a_read_says_erased() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let one = put(&store, keys.plain("user:1"), &content(1, 1000)).await;
    let two = put(&store, keys.plain("user:2"), &content(2, 1000)).await;
    let (files, bytes) = store.delete_erased(&Space::Main, &[one.id]).await.unwrap();
    assert_eq!(files, 1);
    assert!(bytes > 1000);
    assert!(!object(dir.path(), &one).exists());
    assert!(object(dir.path(), &two).exists());
    assert_eq!(
        store.delete_erased(&Space::Main, &[one.id]).await.unwrap(),
        (0, 0),
        "idempotent"
    );
    let err = read_error(&store, &one, &keys).await;
    assert!(matches!(err, Some(BlobError::NotFound(_))), "{err:?}");
    keys.erase("user:1");
    assert_eq!(
        read_error(&store, &one, &keys).await,
        Some(BlobError::Erased)
    );
}
