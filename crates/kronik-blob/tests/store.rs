//! The blob store on a real file system (ADR 0117): round trips across frame
//! borders, identities, deduplication, limits, the disk reserve, damage, and
//! the attacks on sealed files that the format's tags must catch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_blob::format::{self, FRAME_SIZE, FrameKey, HEADER_LEN, Header, SEALED_OVERHEAD};
use kronik_blob::{
    BlobError, BlobKeys, BlobMeta, BlobStore, KeyAccess, KeyAnswer, NoKeys, Space, StoreConfig,
};
use kronik_core::env::{BoxFuture, Env, File, Fs, OpenMode};
use zeroize::Zeroizing;

fn content(seed: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut h = blake3::Hasher::new();
    h.update(&seed.to_le_bytes());
    h.finalize_xof().fill(&mut out);
    out
}

/// Test keys: a frame key and an identity key per (subject, version), and a
/// set of erased subjects.
#[derive(Default)]
struct TestKeys {
    erased: Mutex<Vec<String>>,
}

fn derived(label: &str, subject: &str, version: u32) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(label);
    h.update(subject.as_bytes());
    h.update(&version.to_le_bytes());
    Zeroizing::new(*h.finalize().as_bytes())
}

impl TestKeys {
    fn keys(&self, subject: &str, version: u32, sealed: bool) -> BlobKeys {
        BlobKeys {
            subject: subject.into(),
            key_version: version,
            identity: derived("test identity", subject, version),
            seal: sealed.then(|| derived("test seal", subject, version)),
        }
    }
}

impl KeyAccess for TestKeys {
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer {
        if self.erased.lock().unwrap().iter().any(|s| s == subject) {
            return KeyAnswer::Erased;
        }
        KeyAnswer::Found(derived("test seal", subject, version))
    }
    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer {
        if self.erased.lock().unwrap().iter().any(|s| s == subject) {
            return KeyAnswer::Erased;
        }
        KeyAnswer::Found(derived("test identity", subject, version))
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

async fn put(
    store: &Arc<BlobStore>,
    keys: Option<BlobKeys>,
    data: &[u8],
    chunk: usize,
) -> BlobMeta {
    let lease = store.leases().take("test");
    let mut w = store
        .writer(Space::Main, keys, u64::MAX, lease)
        .await
        .unwrap();
    for c in data.chunks(chunk.max(1)) {
        w.write(c).await.unwrap();
    }
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

const SIZES: [usize; 8] = [
    0,
    1,
    FRAME_SIZE - 1,
    FRAME_SIZE,
    FRAME_SIZE + 1,
    3 * FRAME_SIZE + 5,
    4 * FRAME_SIZE,
    (1 << 20) + 123,
];

#[tokio::test(flavor = "multi_thread")]
async fn plain_blobs_round_trip_at_every_frame_border() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    for (i, size) in SIZES.into_iter().enumerate() {
        let data = content(i as u64, size);
        for chunk in [1, 1000, FRAME_SIZE, 1 << 20] {
            if size > 200_000 && chunk == 1 {
                continue;
            }
            let meta = put(&store, None, &data, chunk).await;
            assert_eq!(
                meta.id.to_string(),
                format!("b3:{}", blake3::hash(&data).to_hex())
            );
            assert_eq!(
                (meta.size, meta.subject.clone(), meta.key_version),
                (size as u64, None, 0)
            );
            let r = store.reader(&Space::Main, &meta, &NoKeys).await.unwrap();
            assert_eq!(r.read_at(0, size + 10).await.unwrap(), data);
            r.verify(&NoKeys).await.unwrap();
            let len = std::fs::metadata(object(dir.path(), &meta)).unwrap().len();
            assert_eq!(len, format::file_len(size as u64, false));
        }
        // Ranges across frame borders, at the end and past it.
        let meta = put(&store, None, &data, 4096).await;
        let r = store.reader(&Space::Main, &meta, &NoKeys).await.unwrap();
        for (offset, len) in [
            (0, 1),
            (FRAME_SIZE - 3, 7),
            (FRAME_SIZE, FRAME_SIZE),
            (size.saturating_sub(2), 100),
            (size, 5),
            (size + 9, 5),
        ] {
            let want = &data[offset.min(size)..(offset + len).min(size)];
            assert_eq!(
                r.read_at(offset as u64, len).await.unwrap(),
                want,
                "size {size} offset {offset} len {len}"
            );
        }
    }
    // Nothing is left in tmp/.
    assert_eq!(
        std::fs::read_dir(dir.path().join("blobs/tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn equal_content_is_one_object_and_a_claim_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let data = content(7, 3 * FRAME_SIZE);
    let a = put(&store, None, &data, 5000).await;
    let modified = std::fs::metadata(object(dir.path(), &a))
        .unwrap()
        .modified()
        .unwrap();
    let b = put(&store, None, &data, 70_000).await;
    assert_eq!(a, b);
    assert_eq!(
        std::fs::metadata(object(dir.path(), &a))
            .unwrap()
            .modified()
            .unwrap(),
        modified,
        "a claim does not rewrite the object"
    );
    let shard = dir.path().join("blobs/objects").join(a.id.shard());
    assert_eq!(std::fs::read_dir(&shard).unwrap().count(), 1);
    assert_eq!(
        std::fs::read_dir(dir.path().join("blobs/tmp"))
            .unwrap()
            .count(),
        0
    );

    // A damaged object is replaced by the next writer of the same content,
    // not claimed.
    let path = object(dir.path(), &a);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[3] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        store.reader(&Space::Main, &a, &NoKeys).await,
        Err(BlobError::Corrupt { .. })
    ));
    put(&store, None, &data, 4096).await;
    let r = store.reader(&Space::Main, &a, &NoKeys).await.unwrap();
    assert_eq!(r.read_at(0, data.len()).await.unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subjects_blob_is_keyed_and_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let data = content(3, 2 * FRAME_SIZE + 77);
    let sealed = put(&store, Some(keys.keys("user:1", 2, true)), &data, 9000).await;
    let plain = put(&store, Some(keys.keys("user:1", 2, false)), &data, 9000).await;
    // One identity for the content of one subject and key version, sealed
    // or not: keyed, not the plain hash.
    assert_eq!(sealed, plain);
    assert!(sealed.id.is_keyed());
    let k = derived("test identity", "user:1", 2);
    assert_eq!(
        *sealed.id.digest(),
        *blake3::keyed_hash(&k, &data).as_bytes()
    );
    assert_eq!(
        (sealed.subject.as_deref(), sealed.key_version),
        (Some("user:1"), 2)
    );
    // Another subject or version: another identity.
    let other = put(&store, Some(keys.keys("user:2", 2, true)), &data, 9000).await;
    assert_ne!(other.id, sealed.id);

    // The claim kept the first (sealed) file: no plaintext on disk.
    let bytes = std::fs::read(object(dir.path(), &sealed)).unwrap();
    assert!(!bytes.windows(64).any(|w| w == &data[1000..1064]));
    let r = store.reader(&Space::Main, &sealed, &keys).await.unwrap();
    assert!(r.is_sealed());
    assert_eq!(r.read_at(5, data.len()).await.unwrap(), data[5..]);
    r.verify(&keys).await.unwrap();
    assert!(matches!(
        store.reader(&Space::Main, &sealed, &NoKeys).await,
        Err(BlobError::KeyMissing(s)) if s == "user:1"
    ));
    keys.erased.lock().unwrap().push("user:1".into());
    assert!(matches!(
        store.reader(&Space::Main, &sealed, &keys).await,
        Err(BlobError::Erased)
    ));

    // A plain file of a subject (privacy mode off) reads without keys.
    let data2 = content(4, 100);
    let p = put(&store, Some(keys.keys("user:3", 1, false)), &data2, 64).await;
    let r = store.reader(&Space::Main, &p, &NoKeys).await.unwrap();
    assert!(!r.is_sealed());
    assert_eq!(r.read_at(0, 100).await.unwrap(), data2);

    // An empty sealed blob has one frame that authenticates its end.
    let empty = put(&store, Some(keys.keys("user:4", 1, true)), b"", 1).await;
    assert_eq!(
        std::fs::metadata(object(dir.path(), &empty)).unwrap().len(),
        (HEADER_LEN + SEALED_OVERHEAD) as u64
    );
    let r = store.reader(&Space::Main, &empty, &keys).await.unwrap();
    assert!(r.read_at(0, 10).await.unwrap().is_empty());
    r.verify(&keys).await.unwrap();
}

fn rewrite(path: &Path, f: impl FnOnce(&mut Vec<u8>)) {
    let mut bytes = std::fs::read(path).unwrap();
    f(&mut bytes);
    std::fs::write(path, bytes).unwrap();
}

/// Re-encodes a header after a change, with a CRC an attacker can
/// recompute; only the header tag stands in the way.
fn edit_header(bytes: &mut [u8], change: impl FnOnce(&mut Header)) {
    let mut h = Header::decode(&bytes[..HEADER_LEN]).unwrap();
    change(&mut h);
    bytes[..HEADER_LEN].copy_from_slice(&h.encode());
}

#[tokio::test(flavor = "multi_thread")]
async fn sealed_frames_cannot_be_reordered_truncated_or_swapped() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let data = content(11, 3 * FRAME_SIZE + 10);
    let meta = put(&store, Some(keys.keys("user:1", 1, true)), &data, 50_000).await;
    let other_data = content(12, 3 * FRAME_SIZE + 10);
    let other = put(
        &store,
        Some(keys.keys("user:1", 1, true)),
        &other_data,
        50_000,
    )
    .await;
    let path = object(dir.path(), &meta);
    let pristine = std::fs::read(&path).unwrap();
    let stored = FRAME_SIZE + SEALED_OVERHEAD;
    let frame = |i: usize| HEADER_LEN + i * stored..HEADER_LEN + (i + 1) * stored;

    let reader_fails = |label: &'static str| {
        let store = store.clone();
        let meta = meta.clone();
        let keys = &keys;
        async move {
            let failed = match store.reader(&Space::Main, &meta, keys).await {
                Err(BlobError::Corrupt { .. }) => true,
                Err(other) => panic!("{label}: {other}"),
                Ok(r) => matches!(
                    r.read_at(0, data_len()).await,
                    Err(BlobError::Corrupt { .. })
                ),
            };
            assert!(failed, "{label} was not detected");
        }
    };
    fn data_len() -> usize {
        3 * FRAME_SIZE + 10
    }

    // Two frames swapped.
    rewrite(&path, |b| {
        let (f0, f1) = (frame(0), frame(1));
        let first = b[f0.clone()].to_vec();
        let second = b[f1.clone()].to_vec();
        b[f0].copy_from_slice(&second);
        b[f1].copy_from_slice(&first);
    });
    reader_fails("reordered frames").await;

    // A frame from another file of the same subject and key version.
    let other_bytes = std::fs::read(object(dir.path(), &other)).unwrap();
    std::fs::write(&path, &pristine).unwrap();
    rewrite(&path, |b| {
        b[frame(1)].copy_from_slice(&other_bytes[frame(1)])
    });
    reader_fails("a frame swapped in from another file").await;

    // The last frame cut off, with the header's size and CRC adjusted.
    std::fs::write(&path, &pristine).unwrap();
    rewrite(&path, |b| {
        b.truncate(frame(3).start);
        edit_header(b, |h| h.size = 3 * FRAME_SIZE as u64);
    });
    reader_fails("a truncated file with a rewritten size").await;

    // The file cut off without touching the header.
    std::fs::write(&path, &pristine).unwrap();
    rewrite(&path, |b| b.truncate(b.len() - 1));
    reader_fails("a truncated file").await;

    // Header fields changed with a recomputed CRC.
    let changes: [fn(&mut Header); 4] = [
        |h| h.identity[0] ^= 1,
        |h| h.body_digest[0] ^= 1,
        |h| h.nonce_prefix[3] ^= 1,
        |h| h.key_version = 2,
    ];
    for change in changes {
        std::fs::write(&path, &pristine).unwrap();
        rewrite(&path, |b| edit_header(b, change));
        reader_fails("a tampered header").await;
    }

    // An extra frame sealed as the last one in the middle: built with the
    // real key, so only the position check catches it.
    std::fs::write(&path, &pristine).unwrap();
    let header = Header::decode(&pristine[..HEADER_LEN]).unwrap();
    let key = derived("test seal", "user:1", 1);
    let mut early_last = Vec::new();
    format::seal_frame(
        &FrameKey {
            key: &key,
            nonce_prefix: &header.nonce_prefix,
            subject: "user:1",
            key_version: 1,
        },
        1,
        true,
        &data[FRAME_SIZE..2 * FRAME_SIZE],
        &mut early_last,
    )
    .unwrap();
    rewrite(&path, |b| b[frame(1)].copy_from_slice(&early_last));
    reader_fails("a last frame before the declared size").await;

    // Untouched, it still reads.
    std::fs::write(&path, &pristine).unwrap();
    let r = store.reader(&Space::Main, &meta, &keys).await.unwrap();
    assert_eq!(r.read_at(0, data.len()).await.unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn damage_fails_only_the_frames_it_touches() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let data = content(5, 3 * FRAME_SIZE);
    let meta = put(&store, None, &data, 65_000).await;
    let path = object(dir.path(), &meta);
    let stored = FRAME_SIZE + format::PLAIN_OVERHEAD;
    rewrite(&path, |b| b[HEADER_LEN + stored + 10] ^= 0x40);
    let r = store.reader(&Space::Main, &meta, &NoKeys).await.unwrap();
    assert_eq!(r.read_at(0, 100).await.unwrap(), data[..100]);
    assert_eq!(
        r.read_at(2 * FRAME_SIZE as u64, 100).await.unwrap(),
        data[2 * FRAME_SIZE..2 * FRAME_SIZE + 100]
    );
    let err = r.read_at(FRAME_SIZE as u64, 10).await.unwrap_err();
    assert!(
        matches!(&err, BlobError::Corrupt { id, .. } if *id == meta.id),
        "{err}"
    );
    assert!(err.to_string().starts_with("STORAGE_CORRUPT"));
    assert!(r.verify(&NoKeys).await.is_err());

    // A file that is not the blob its name says.
    let other = put(&store, None, &content(6, 10), 10).await;
    let wrong = BlobMeta {
        size: 11,
        ..other.clone()
    };
    assert!(matches!(
        store.reader(&Space::Main, &wrong, &NoKeys).await,
        Err(BlobError::Corrupt { .. })
    ));
    assert!(matches!(
        store
            .reader(
                &Space::Main,
                &BlobMeta {
                    id: kronik_blob::BlobId::plain([0; 32]),
                    ..other
                },
                &NoKeys
            )
            .await,
        Err(BlobError::NotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_the_reserve_and_aborts_leave_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        StoreConfig {
            reserve: 1 << 20,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    let tmp = dir.path().join("blobs/tmp");
    let lease = store.leases().take("test");

    let mut w = store
        .writer(Space::Main, None, 10, lease.clone())
        .await
        .unwrap();
    w.write(b"0123456789").await.unwrap();
    assert_eq!(
        w.write(b"x").await.unwrap_err(),
        BlobError::TooLarge { limit: 10 }
    );
    w.abort().await;
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);

    store.set_free(1000);
    assert_eq!(store.below_reserve(), Some(1000));
    assert!(matches!(
        store.writer(Space::Main, None, 10, lease.clone()).await,
        Err(BlobError::StoreFull { .. })
    ));
    store.set_free(2 << 20);
    let mut w = store
        .writer(Space::Main, None, u64::MAX, lease.clone())
        .await
        .unwrap();
    w.write(b"abc").await.unwrap();
    store.set_free(10);
    assert!(matches!(
        w.write(b"def").await,
        Err(BlobError::StoreFull { .. })
    ));
    // Dropped, the writer deletes its part file in the background.
    drop(w);
    let env = Env::real(tokio::runtime::Handle::current());
    for _ in 0..400 {
        if std::fs::read_dir(&tmp).unwrap().count() == 0 {
            break;
        }
        env.clock.sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(std::fs::read_dir(&tmp).unwrap().count(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn opening_deletes_unfinished_writes_and_keeps_objects() {
    let dir = tempfile::tempdir().unwrap();
    let meta = {
        let store = open(dir.path()).await;
        put(&store, None, &content(1, 70_000), 7000).await
    };
    let part = dir.path().join("blobs/tmp/0011223344556677.part");
    std::fs::write(&part, b"left by a crash").unwrap();
    let store = open(dir.path()).await;
    assert!(!part.exists());
    let r = store.reader(&Space::Main, &meta, &NoKeys).await.unwrap();
    r.verify(&NoKeys).await.unwrap();
    // 256 shard directories.
    assert_eq!(
        std::fs::read_dir(dir.path().join("blobs/objects"))
            .unwrap()
            .count(),
        256
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forks_space_reads_main_and_writes_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let main_blob = put(&store, None, &content(1, 1000), 100).await;
    let fork = Space::Fork("f-0123456789ab".into());
    let lease = store.leases().take("fork");
    let mut w = store
        .writer(fork.clone(), None, u64::MAX, lease)
        .await
        .unwrap();
    w.write(&content(2, 500)).await.unwrap();
    let fork_blob = w.finish().await.unwrap();
    store.ensure_durable(&fork, &[fork_blob.id]).await.unwrap();
    assert!(store.contains(&fork, &fork_blob.id).await.unwrap());
    assert!(!store.contains(&Space::Main, &fork_blob.id).await.unwrap());
    assert!(
        dir.path()
            .join("branches/f-0123456789ab/blobs/objects")
            .join(fork_blob.id.shard())
            .join(fork_blob.id.file_name())
            .exists()
    );
    // A fork reads its own blobs and main's; main does not read the fork's.
    store.reader(&fork, &fork_blob, &NoKeys).await.unwrap();
    store.reader(&fork, &main_blob, &NoKeys).await.unwrap();
    assert!(matches!(
        store.reader(&Space::Main, &fork_blob, &NoKeys).await,
        Err(BlobError::NotFound(_))
    ));
}

/// Real files, with `sync_dir` calls counted.
struct CountingFs {
    inner: Arc<dyn Fs>,
    syncs: Mutex<Vec<PathBuf>>,
}

impl Fs for CountingFs {
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.create_dir_all(path)
    }
    fn open(
        &self,
        path: PathBuf,
        mode: OpenMode,
    ) -> BoxFuture<'static, std::io::Result<Arc<dyn File>>> {
        self.inner.open(path, mode)
    }
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<bool>> {
        self.inner.exists(path)
    }
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<Vec<String>>> {
        self.inner.read_dir(dir)
    }
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, std::io::Result<()>> {
        self.syncs.lock().unwrap().push(dir.clone());
        self.inner.sync_dir(dir)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_directory_sync_covers_every_name_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let real = Env::real(tokio::runtime::Handle::current());
    let fs = Arc::new(CountingFs {
        inner: real.fs.clone(),
        syncs: Mutex::new(Vec::new()),
    });
    let env = Env {
        fs: fs.clone(),
        ..real
    };
    let store = BlobStore::open(env, dir.path(), StoreConfig::default())
        .await
        .unwrap();
    // Two contents in one shard directory, and a third elsewhere.
    let mut same: Vec<Vec<u8>> = Vec::new();
    let mut elsewhere = None;
    for seed in 0.. {
        let data = content(seed, 100);
        let shard = blake3::hash(&data).as_bytes()[0];
        if same.is_empty() || blake3::hash(&same[0]).as_bytes()[0] == shard {
            if same.len() < 2 {
                same.push(data);
            }
        } else if elsewhere.is_none() {
            elsewhere = Some(data);
        }
        if same.len() == 2 && elsewhere.is_some() {
            break;
        }
    }
    let write = |data: Vec<u8>| {
        let store = store.clone();
        async move {
            let mut w = store
                .writer(Space::Main, None, u64::MAX, store.leases().take("t"))
                .await
                .unwrap();
            w.write(&data).await.unwrap();
            w.finish().await.unwrap()
        }
    };
    let a = write(same[0].clone()).await;
    let b = write(same[1].clone()).await;
    let c = write(elsewhere.clone().unwrap()).await;
    let shard_of = |m: &BlobMeta| dir.path().join("blobs/objects").join(m.id.shard());
    fs.syncs.lock().unwrap().clear();
    store.ensure_durable(&Space::Main, &[a.id]).await.unwrap();
    assert_eq!(*fs.syncs.lock().unwrap(), [shard_of(&a)]);
    // b was named before that sync: already durable.
    store
        .ensure_durable(&Space::Main, &[b.id, a.id])
        .await
        .unwrap();
    assert_eq!(fs.syncs.lock().unwrap().len(), 1);
    store.ensure_durable(&Space::Main, &[c.id]).await.unwrap();
    assert_eq!(*fs.syncs.lock().unwrap(), [shard_of(&a), shard_of(&c)]);
    // A claim of a durable object needs no sync; a claim of one whose name
    // is not durable yet waits for it.
    let again = write(same[0].clone()).await;
    store
        .ensure_durable(&Space::Main, &[again.id])
        .await
        .unwrap();
    assert_eq!(fs.syncs.lock().unwrap().len(), 2);
    let d = write(content(999, 33)).await;
    let claim = write(content(999, 33)).await;
    store
        .ensure_durable(&Space::Main, &[claim.id])
        .await
        .unwrap();
    assert_eq!(fs.syncs.lock().unwrap().last(), Some(&shard_of(&d)));
}

/// Review B-H1: a writer holds no file until its first frame is complete,
/// and buffers one frame at most, whatever it is given.
#[tokio::test(flavor = "multi_thread")]
async fn a_writer_holds_no_file_until_a_frame_and_buffers_one_frame() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let tmp = dir.path().join("blobs/tmp");
    let parts = || std::fs::read_dir(&tmp).unwrap().count();
    let mut writers = Vec::new();
    for _ in 0..200 {
        let mut w = store
            .writer(Space::Main, None, u64::MAX, store.leases().take("t"))
            .await
            .unwrap();
        w.write(&[1; 1000]).await.unwrap();
        writers.push(w);
    }
    assert_eq!(parts(), 0, "200 writers of less than a frame hold no file");
    // A write of many frames leaves at most one frame buffered: the file
    // grows with every complete frame.
    let mut w = store
        .writer(Space::Main, None, u64::MAX, store.leases().take("t"))
        .await
        .unwrap();
    let data = content(9, 10 * FRAME_SIZE + 5);
    w.write(&data).await.unwrap();
    assert_eq!(parts(), 1);
    let part = std::fs::read_dir(&tmp)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let on_disk = std::fs::metadata(&part).unwrap().len();
    assert!(
        on_disk >= (HEADER_LEN + 10 * FRAME_SIZE) as u64,
        "{on_disk} bytes on disk after 10 frames"
    );
    let meta = w.finish().await.unwrap();
    assert_eq!(meta.size, data.len() as u64);
    drop(writers);
    // An empty plain blob still gets its file at finish.
    let empty = put(&store, None, &[], 1).await;
    let r = store.reader(&Space::Main, &empty, &NoKeys).await.unwrap();
    assert!(r.read_at(0, 0).await.unwrap().is_empty());
}

/// Review B-H2: written bytes count against the last free-space reading,
/// so writers between two readings stop at the reserve.
#[tokio::test(flavor = "multi_thread")]
async fn writes_count_against_the_reserve_between_readings() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir.path(),
        StoreConfig {
            reserve: 1 << 20,
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    // Four frames above the reserve.
    store.set_free((1 << 20) + 4 * FRAME_SIZE as u64);
    let mut w = store
        .writer(Space::Main, None, u64::MAX, store.leases().take("t"))
        .await
        .unwrap();
    let mut written = 0;
    let error = loop {
        match w.write(&[7; FRAME_SIZE]).await {
            Ok(()) => written += 1,
            Err(e) => break e,
        }
        assert!(written < 100, "the reserve never stopped the writer");
    };
    assert!(matches!(error, BlobError::StoreFull { .. }), "{error}");
    assert!((4..=6).contains(&written), "{written} frames written");
    assert!(store.below_reserve().is_some());
    // A new reading replaces the estimate.
    store.set_free(u64::MAX - 1);
    assert!(store.below_reserve().is_none());
}

/// Review B-M4: a sealed write does not claim a plain file of the same
/// identity (privacy mode was turned on since); it replaces it.
#[tokio::test(flavor = "multi_thread")]
async fn a_sealed_write_replaces_a_plain_file_of_the_same_blob() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let data = content(4, FRAME_SIZE + 10);
    let plain = put(&store, Some(keys.keys("user:5", 1, false)), &data, 5000).await;
    let bytes = std::fs::read(object(dir.path(), &plain)).unwrap();
    assert!(bytes.windows(64).any(|w| w == &data[100..164]));
    let sealed = put(&store, Some(keys.keys("user:5", 1, true)), &data, 5000).await;
    assert_eq!(sealed, plain);
    let bytes = std::fs::read(object(dir.path(), &sealed)).unwrap();
    assert!(!bytes.windows(64).any(|w| w == &data[100..164]));
    let r = store.reader(&Space::Main, &sealed, &keys).await.unwrap();
    assert!(r.is_sealed());
}

/// Review B-M3: an erased subject's blob is gone, plain or sealed
/// (ADR 0118 §4).
#[tokio::test(flavor = "multi_thread")]
async fn an_erased_subjects_plain_blob_reads_as_erased() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let plain = put(
        &store,
        Some(keys.keys("user:6", 1, false)),
        &content(5, 500),
        100,
    )
    .await;
    store.reader(&Space::Main, &plain, &keys).await.unwrap();
    keys.erased.lock().unwrap().push("user:6".into());
    assert!(matches!(
        store.reader(&Space::Main, &plain, &keys).await,
        Err(BlobError::Erased)
    ));
    // A blob without a subject never asks for keys.
    let shared = put(&store, None, &content(6, 500), 100).await;
    store.reader(&Space::Main, &shared, &keys).await.unwrap();
}

/// Review R-2 (erasure): a lease held longer than its TTL expired, so an
/// upload waiting for its turn lost its blob to the collector. A kept-alive
/// lease stays in force while held and ends when dropped.
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_alive_lease_outlives_its_ttl_while_held() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::real(tokio::runtime::Handle::current());
    let store = BlobStore::open(
        env.clone(),
        dir.path(),
        StoreConfig {
            lease_ttl: Duration::from_millis(80),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    let meta = put(&store, None, &content(8, 1000), 100).await;
    let plain = store.leases().take("plain");
    plain.add(meta.id);
    let kept = store.leases().take("kept");
    kept.add(meta.id);
    kept.keep_alive(&env);
    env.clock.sleep(Duration::from_millis(400)).await;
    assert!(!plain.is_live(), "an unrenewed lease expires");
    assert!(kept.is_live(), "a kept-alive lease does not");
    assert!(store.leases().is_leased(&meta.id));
    drop(kept);
    drop(plain);
    env.clock.sleep(Duration::from_millis(50)).await;
    assert!(store.leases().holders().is_empty(), "it ends when dropped");
}

/// Review R-4 (erasure): a rebase's blobs move from its fork's space into
/// main's as they are: the same file, so the same reference, plain or
/// sealed; one main has already is claimed; one neither has is NotFound.
#[tokio::test(flavor = "multi_thread")]
async fn import_copies_a_fork_blob_into_main_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let keys = TestKeys::default();
    let fork = Space::Fork("r-1".into());
    let put_in = |space: Space, k: Option<BlobKeys>, data: Vec<u8>| {
        let store = store.clone();
        async move {
            let mut w = store
                .writer(space.clone(), k, u64::MAX, store.leases().take("t"))
                .await
                .unwrap();
            w.write(&data).await.unwrap();
            let meta = w.finish().await.unwrap();
            store.ensure_durable(&space, &[meta.id]).await.unwrap();
            meta
        }
    };
    let plain_data = content(21, 3 * FRAME_SIZE + 9);
    let sealed_data = content(22, FRAME_SIZE + 1);
    let plain = put_in(fork.clone(), None, plain_data.clone()).await;
    let sealed = put_in(
        fork.clone(),
        Some(keys.keys("user:4", 1, true)),
        sealed_data.clone(),
    )
    .await;
    for (meta, data) in [(&plain, &plain_data), (&sealed, &sealed_data)] {
        assert!(!store.contains(&Space::Main, &meta.id).await.unwrap());
        let lease = store.leases().take("rebase");
        store
            .import(&fork, &Space::Main, meta, &lease)
            .await
            .unwrap();
        store
            .ensure_durable(&Space::Main, &[meta.id])
            .await
            .unwrap();
        assert!(store.leases().is_leased(&meta.id));
        let main_file = std::fs::read(object(dir.path(), meta)).unwrap();
        let fork_file = std::fs::read(
            dir.path()
                .join("branches/r-1/blobs/objects")
                .join(meta.id.shard())
                .join(meta.id.file_name()),
        )
        .unwrap();
        assert!(main_file == fork_file, "the same file");
        // Readable from main alone, once the fork is gone.
        std::fs::remove_dir_all(
            dir.path()
                .join("branches/r-1/blobs/objects")
                .join(meta.id.shard()),
        )
        .unwrap();
        let r = store.reader(&Space::Main, meta, &keys).await.unwrap();
        assert_eq!(r.read_at(0, data.len()).await.unwrap(), data[..]);
        std::fs::create_dir_all(
            dir.path()
                .join("branches/r-1/blobs/objects")
                .join(meta.id.shard()),
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("branches/r-1/blobs/objects")
                .join(meta.id.shard())
                .join(meta.id.file_name()),
            fork_file,
        )
        .unwrap();
    }
    // Main has it already (and the fork does not): claimed.
    let only_main = put_in(Space::Main, None, content(23, 500)).await;
    let lease = store.leases().take("rebase");
    store
        .import(&fork, &Space::Main, &only_main, &lease)
        .await
        .unwrap();
    assert!(store.leases().is_leased(&only_main.id));
    // Neither has it.
    let mut missing = only_main.clone();
    missing.size += 1;
    let made_up = BlobMeta {
        id: kronik_blob::BlobId::parse(&format!("b3:{}", "09".repeat(32))).unwrap(),
        ..missing
    };
    assert!(matches!(
        store.import(&fork, &Space::Main, &made_up, &lease).await,
        Err(BlobError::NotFound(_))
    ));
}
