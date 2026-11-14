// A test drives a concurrent writer from a plain thread while a pass waits
// in its roots.
#![allow(clippy::disallowed_methods)]

use super::*;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use kronik_core::env::Env;

use crate::{BlobMeta, Lease, StoreConfig};

async fn open(dir: &Path) -> Arc<BlobStore> {
    BlobStore::open(
        Env::real(tokio::runtime::Handle::current()),
        dir,
        StoreConfig::default(),
    )
    .await
    .unwrap()
}

/// Writes `data` as a plain blob under `lease`.
async fn put(store: &Arc<BlobStore>, data: &[u8], lease: Lease) -> BlobMeta {
    let mut w = store
        .writer(Space::Main, None, u64::MAX, lease)
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

/// Roots from a fixed set.
struct Fixed(BTreeSet<BlobId>);

impl Roots for Fixed {
    fn shard(&mut self, shard: u8) -> Result<BTreeSet<BlobId>, BlobError> {
        Ok(self
            .0
            .iter()
            .filter(|id| id.digest()[0] == shard)
            .copied()
            .collect())
    }
}

/// Roots that run `f` before they answer the first shard: something that
/// happens while a pass runs.
struct During<F: FnOnce() + Send>(BTreeSet<BlobId>, Option<F>);

impl<F: FnOnce() + Send> Roots for During<F> {
    fn shard(&mut self, shard: u8) -> Result<BTreeSet<BlobId>, BlobError> {
        if let Some(f) = self.1.take() {
            f();
        }
        Fixed(self.0.clone()).shard(shard)
    }
}

fn exists(store: &BlobStore, id: &BlobId) -> bool {
    store.object_path(&Space::Main, id).exists()
}

/// A file without a root goes in the second pass that finds it without
/// one, not in the first; a rooted or leased file stays; `immediate` skips
/// the grace; a dry run lists and deletes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_without_roots_goes_in_the_second_pass() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let kept = put(&store, b"kept by a root", store.leases().take("t")).await;
    let loose = put(&store, b"kept by nothing", store.leases().take("t")).await;
    let lease = store.leases().take("upload");
    let leased = put(&store, b"kept by a lease", lease.clone()).await;
    let mut roots = Fixed([kept.id].into());

    let dry = store
        .sweep(
            &Space::Main,
            &mut roots,
            SweepOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(dry.objects, 3);
    assert_eq!(
        dry.unrooted.iter().map(|u| u.id).collect::<Vec<_>>(),
        [loose.id]
    );
    assert!(!dry.unrooted[0].candidate);

    let first = store
        .sweep(&Space::Main, &mut roots, SweepOptions::default())
        .await
        .unwrap();
    assert_eq!((first.deleted, first.candidates), (0, 1));
    assert!(exists(&store, &loose.id));
    // The dry run now marks it as the next pass's.
    let dry = store
        .sweep(
            &Space::Main,
            &mut roots,
            SweepOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(dry.unrooted[0].candidate);

    let second = store
        .sweep(&Space::Main, &mut roots, SweepOptions::default())
        .await
        .unwrap();
    assert_eq!(second.deleted, 1);
    assert_eq!(second.objects, 2);
    assert!(!exists(&store, &loose.id));
    assert!(exists(&store, &kept.id) && exists(&store, &leased.id));

    // The lease ends: `immediate` deletes at once.
    drop(lease);
    let now = store
        .sweep(
            &Space::Main,
            &mut roots,
            SweepOptions {
                immediate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!((now.deleted, now.objects), (1, 1));
    assert!(!exists(&store, &leased.id) && exists(&store, &kept.id));
}

/// A candidate that a writer claims again (same content) between the
/// pass's start and its look is not deleted, even though its lease has
/// ended by then (the record that references it was applied after the
/// roots were read): the claim was after the pass began.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_after_the_pass_began_keeps_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let first = put(&store, b"twice", store.leases().take("t")).await;
    let mut nothing = Fixed(BTreeSet::new());
    store
        .sweep(&Space::Main, &mut nothing, SweepOptions::default())
        .await
        .unwrap();
    // It is a candidate. While the next pass runs, a turn writes the same
    // content (a claim), and its lease ends before the pass looks.
    let claimer = store.clone();
    let rt = tokio::runtime::Handle::current();
    let mut during = During(
        BTreeSet::new(),
        Some(move || {
            let store = claimer.clone();
            std::thread::spawn(move || {
                rt.block_on(async {
                    let lease = store.leases().take("t");
                    put(&store, b"twice", lease).await;
                })
            })
            .join()
            .unwrap();
        }),
    );
    let report = store
        .sweep(
            &Space::Main,
            &mut during,
            SweepOptions {
                immediate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(report.deleted, 0, "{report:?}");
    assert!(exists(&store, &first.id));
    // The pass after that deletes it: nothing has touched it since.
    let report = store
        .sweep(
            &Space::Main,
            &mut nothing,
            SweepOptions {
                immediate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(report.deleted, 1);
}

/// A blob whose lease was live when the pass began is kept even if the
/// lease ends before the pass looks: its record was applied after the
/// roots were read.
#[tokio::test(flavor = "multi_thread")]
async fn a_lease_live_at_the_start_keeps_the_file_for_the_pass() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let lease = store.leases().take("turn");
    let meta = put(&store, b"leased at the start", lease.clone()).await;
    // The lease ends while the pass runs, after it began.
    let mut during = During(BTreeSet::new(), Some(move || drop(lease)));
    let report = store
        .sweep(
            &Space::Main,
            &mut during,
            SweepOptions {
                immediate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(report.deleted, 0);
    assert!(exists(&store, &meta.id));
}

/// A file whose name is not a blob's is left alone, and so is a part file.
#[tokio::test(flavor = "multi_thread")]
async fn other_files_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(dir.path()).await;
    let stray = dir.path().join("blobs/objects/00/notes.txt");
    std::fs::write(&stray, b"not a blob").unwrap();
    let report = store
        .sweep(
            &Space::Main,
            &mut Fixed(BTreeSet::new()),
            SweepOptions {
                immediate: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!((report.objects, report.deleted), (0, 0));
    assert!(stray.exists());
}
