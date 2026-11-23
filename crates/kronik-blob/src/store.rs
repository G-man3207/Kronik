//! The store: spaces, writers, readers and durability (ADR 0117 §1, §4-§6).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{Env, File, OpenMode};
use kronik_core::sync::lock;
use zeroize::Zeroizing;

use crate::SpaceBudget;
use crate::format::{self, FRAME_SIZE, FrameKey, HEADER_LEN, Header};
use crate::id::hex;
use crate::{BlobError, BlobId, BlobMeta, Lease, Leases};

/// Where blobs are written and first looked for.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Space {
    /// Main's store, `<data>/blobs`.
    Main,
    /// A fork's own space, `<data>/branches/<fork>/blobs`; it reads main's
    /// store too.
    Fork(String),
    /// A scratch space at a path (one isolated replay tree, `upgrade check`);
    /// it reads main's store too.
    Scratch(PathBuf),
}

/// Store settings.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// `[blobs] disk_reserve`: below this much free space new blobs are
    /// refused (0: no reserve).
    pub reserve: u64,
    /// `[blobs] lease_ttl`.
    pub lease_ttl: Duration,
    /// Deliberate bug (mutation testing of the harness); never set outside
    /// the simulator: [`BlobStore::ensure_durable`] returns without syncing.
    pub mutation_skip_ensure_durable: bool,
    /// Deliberate bug (mutation testing of the harness); never set outside
    /// the simulator: a sweep deletes what a lease keeps.
    pub mutation_sweep_ignores_leases: bool,
    /// Deliberate bug (mutation testing of the harness); never set outside
    /// the simulator: a sweep deletes what was named or claimed after it
    /// began.
    pub mutation_sweep_ignores_touches: bool,
    /// Deliberate bug (mutation testing of the harness); never set outside
    /// the simulator: [`BlobStore::delete_erased`] deletes nothing.
    pub mutation_erasure_keeps_files: bool,
    /// Deliberate bug (mutation testing of the harness); never set outside
    /// the simulator: a sweep ignores [`SweepOptions::erased_now`], so an
    /// erased subject's loose files stay.
    ///
    /// [`SweepOptions::erased_now`]: crate::SweepOptions::erased_now
    pub mutation_sweep_ignores_erasures: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig {
            reserve: 0,
            lease_ttl: Duration::from_secs(300),
            mutation_skip_ensure_durable: false,
            mutation_sweep_ignores_leases: false,
            mutation_sweep_ignores_touches: false,
            mutation_erasure_keeps_files: false,
            mutation_sweep_ignores_erasures: false,
        }
    }
}

/// The keys of a subject's blob (ADR 0118), derived by the privacy crate
/// from the subject key of `key_version`.
pub struct BlobKeys {
    pub subject: String,
    pub key_version: u32,
    /// `K_id`, which keys the identity hash.
    pub identity: Zeroizing<[u8; 32]>,
    /// The frame key when the blob is sealed (privacy mode on).
    pub seal: Option<Zeroizing<[u8; 32]>>,
}

/// What a key lookup gives.
pub enum KeyAnswer {
    Found(Zeroizing<[u8; 32]>),
    /// The subject was erased through this version: the blob is gone.
    Erased,
    /// This node has no such key (`KEYSTORE_INCOMPLETE`).
    Missing,
    /// The keystore could not answer (an I/O or database failure): neither
    /// erased nor missing.
    Unavailable(String),
}

/// Keys for reading subjects' blobs, never created by a lookup.
pub trait KeyAccess: Send + Sync {
    /// The frame key of `(subject, version)`, for sealed files.
    fn seal_key(&self, subject: &str, version: u32) -> KeyAnswer;
    /// `K_id` of `(subject, version)`, to check a keyed identity.
    fn identity_key(&self, subject: &str, version: u32) -> KeyAnswer;
}

/// No keys at all: plain blobs only.
pub struct NoKeys;

impl KeyAccess for NoKeys {
    fn seal_key(&self, _subject: &str, _version: u32) -> KeyAnswer {
        KeyAnswer::Missing
    }
    fn identity_key(&self, _subject: &str, _version: u32) -> KeyAnswer {
        KeyAnswer::Missing
    }
}

/// One shard directory's name generations: `renamed` counts names created
/// in it, `synced` is the count a completed `sync_dir` covers.
#[derive(Default)]
pub(crate) struct Gens {
    renamed: u64,
    synced: u64,
    /// Objects named in this process and not yet covered by a sync.
    pending: BTreeMap<String, u64>,
    /// The store's touch sequence number of the last naming or claim of
    /// each object, until the collector's next pass has started after it
    /// ([`crate::sweep`]).
    pub(crate) touched: BTreeMap<String, u64>,
}

#[derive(Default)]
pub(crate) struct Dir {
    /// Serializes naming and deleting objects in this directory (claims).
    pub(crate) claim: tokio::sync::Mutex<()>,
    /// Serializes syncs of this directory, so concurrent callers share one.
    sync: tokio::sync::Mutex<()>,
    pub(crate) gens: Mutex<Gens>,
}

/// The blob store of one data directory.
pub struct BlobStore {
    pub(crate) env: Env,
    data_dir: PathBuf,
    /// `[blobs] disk_reserve`; a test can change it ([`BlobStore::set_reserve`]).
    reserve: AtomicU64,
    lease_ttl: Duration,
    leases: Arc<Leases>,
    /// The last free-space reading of `<data>/blobs`; `u64::MAX`: none yet.
    free: AtomicU64,
    /// Space roots prepared by this process.
    prepared: tokio::sync::Mutex<BTreeSet<PathBuf>>,
    dirs: Mutex<HashMap<PathBuf, Arc<Dir>>>,
    /// Counts the namings and claims of objects, for the collector: a pass
    /// skips a name touched after it began ([`crate::sweep`]).
    pub(crate) touch_seq: AtomicU64,
    /// The collector's state between passes.
    pub(crate) sweep: crate::sweep::SweepState,
    /// The writers that have not ended ([`BlobStore::live_writers`]).
    writers: Arc<Writers>,
    /// The harness's mutations ([`StoreConfig`]).
    pub(crate) mutation_skip_ensure_durable: bool,
    pub(crate) mutation_sweep_ignores_leases: bool,
    pub(crate) mutation_sweep_ignores_touches: bool,
    pub(crate) mutation_erasure_keeps_files: bool,
    pub(crate) mutation_sweep_ignores_erasures: bool,
}

fn shard_dirs(root: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    (0u8..=255).map(move |b| root.join("objects").join(hex(&[b])))
}

impl BlobStore {
    /// Opens main's store: creates its layout if missing, makes every name
    /// in it durable and deletes the part files a crashed process left
    /// (ADR 0117 §4.4).
    pub async fn open(
        env: Env,
        data_dir: &Path,
        cfg: StoreConfig,
    ) -> Result<Arc<BlobStore>, BlobError> {
        let leases = Leases::new(env.clock.clone(), cfg.lease_ttl);
        let store = Arc::new(BlobStore {
            env,
            data_dir: data_dir.to_path_buf(),
            reserve: AtomicU64::new(cfg.reserve),
            lease_ttl: cfg.lease_ttl,
            leases,
            free: AtomicU64::new(u64::MAX),
            prepared: tokio::sync::Mutex::new(BTreeSet::new()),
            dirs: Mutex::new(HashMap::new()),
            touch_seq: AtomicU64::new(0),
            sweep: crate::sweep::SweepState::default(),
            writers: Arc::new(Writers::default()),
            mutation_skip_ensure_durable: cfg.mutation_skip_ensure_durable,
            mutation_sweep_ignores_leases: cfg.mutation_sweep_ignores_leases,
            mutation_sweep_ignores_touches: cfg.mutation_sweep_ignores_touches,
            mutation_erasure_keeps_files: cfg.mutation_erasure_keeps_files,
            mutation_sweep_ignores_erasures: cfg.mutation_sweep_ignores_erasures,
        });
        store.prepare(&Space::Main).await?;
        Ok(store)
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    pub fn leases(&self) -> &Arc<Leases> {
        &self.leases
    }

    /// The writers that have not ended: created, and neither finished,
    /// aborted nor dropped with their part file deleted. A writer of an
    /// erased subject that began before the erasure may still name a blob
    /// no record references (M26 §9.3), so the erasure waits for it.
    pub fn live_writers(&self) -> Vec<LiveWriter> {
        lock(&self.writers.live).values().cloned().collect()
    }

    /// `[blobs] lease_ttl`: how long a lease lives without renewal.
    pub fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }

    /// The root directory of a space.
    pub fn root(&self, space: &Space) -> PathBuf {
        match space {
            Space::Main => self.data_dir.join("blobs"),
            Space::Fork(name) => self.data_dir.join("branches").join(name).join("blobs"),
            Space::Scratch(path) => path.clone(),
        }
    }

    /// The path of `id`'s object in `space`.
    pub fn object_path(&self, space: &Space, id: &BlobId) -> PathBuf {
        self.root(space)
            .join("objects")
            .join(id.shard())
            .join(id.file_name())
    }

    /// Creates a space's layout, makes every name in it durable and deletes
    /// its part files; once per space per process.
    pub async fn prepare(&self, space: &Space) -> Result<(), BlobError> {
        let root = self.root(space);
        let mut prepared = self.prepared.lock().await;
        if prepared.contains(&root) {
            return Ok(());
        }
        let fs = &self.env.fs;
        let failed = |what: &str| {
            let what = what.to_owned();
            move |e: io::Error| BlobError::io(&what, e)
        };
        for dir in shard_dirs(&root).chain([root.join("tmp")]) {
            fs.create_dir_all(dir)
                .await
                .map_err(failed("creating the blob directories"))?;
        }
        // Names a crashed process renamed into place become durable now, so
        // a name seen after a restart is durable before anything uses it.
        for dir in shard_dirs(&root) {
            fs.sync_dir(dir)
                .await
                .map_err(failed("syncing a blob directory"))?;
        }
        fs.sync_dir(root.join("objects"))
            .await
            .map_err(failed("syncing the blob directories"))?;
        fs.sync_dir(root.clone())
            .await
            .map_err(failed("syncing the blob directories"))?;
        let tmp = root.join("tmp");
        let parts = fs
            .read_dir(tmp.clone())
            .await
            .map_err(failed("listing blob part files"))?;
        let removed = parts.len();
        for name in parts {
            match fs.remove_file(tmp.join(&name)).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(BlobError::io("deleting a blob part file", e)),
            }
        }
        if removed > 0 {
            fs.sync_dir(tmp)
                .await
                .map_err(failed("syncing the blob part directory"))?;
            tracing::info!(removed, root = %root.display(), "deleted unfinished blob writes");
        }
        prepared.insert(root);
        Ok(())
    }

    pub(crate) fn dir(&self, path: &Path) -> Arc<Dir> {
        lock(&self.dirs)
            .entry(path.to_path_buf())
            .or_default()
            .clone()
    }

    /// Measures the free space of `<data>/blobs`'s file system.
    pub async fn refresh_free(&self) -> Result<u64, BlobError> {
        let free = self
            .env
            .fs
            .available(self.data_dir.join("blobs"))
            .await
            .map_err(|e| BlobError::io("measuring free disk", e))?;
        self.free.store(free, Ordering::Relaxed);
        Ok(free)
    }

    /// Test hook: changes `[blobs] disk_reserve` of a running store, so a
    /// test can fill the store and give room back.
    #[doc(hidden)]
    pub fn set_reserve(&self, bytes: u64) {
        self.reserve.store(bytes, Ordering::Relaxed);
    }

    /// Sets the free-space reading (the node's disk loop, tests).
    pub fn set_free(&self, bytes: u64) {
        self.free.store(bytes, Ordering::Relaxed);
    }

    /// Counts `bytes` just written against the last free-space reading, so
    /// that writes between two readings cannot pass the reserve unseen; the
    /// next reading replaces the estimate.
    fn charge(&self, bytes: u64) {
        let _ = self
            .free
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |free| {
                (free != u64::MAX).then(|| free.saturating_sub(bytes))
            });
    }

    /// The free bytes when below `[blobs] disk_reserve`, else None.
    pub fn below_reserve(&self) -> Option<u64> {
        let free = self.free.load(Ordering::Relaxed);
        let reserve = self.reserve.load(Ordering::Relaxed);
        (reserve > 0 && free != u64::MAX && free < reserve).then_some(free)
    }

    fn check_reserve(&self) -> Result<(), BlobError> {
        match self.below_reserve() {
            Some(free) => Err(BlobError::StoreFull {
                free,
                reserve: self.reserve.load(Ordering::Relaxed),
            }),
            None => Ok(()),
        }
    }

    /// A writer of one blob in `space`, of at most `limit` plaintext bytes.
    /// With `keys` it is a subject's blob (`b3s:`), sealed when `keys.seal`
    /// is set. The finished blob joins `lease`.
    pub async fn writer(
        self: &Arc<Self>,
        space: Space,
        keys: Option<BlobKeys>,
        limit: u64,
        lease: Lease,
    ) -> Result<BlobWriter, BlobError> {
        self.check_reserve()?;
        if let Some(k) = &keys
            && (k.key_version == 0 || !kronik_proto::blobs::valid_subject(&k.subject))
        {
            return Err(BlobError::Invalid(
                "a subject's blob needs a valid subject and key version".into(),
            ));
        }
        self.prepare(&space).await?;
        // The part file is created with the first frame: a writer that has
        // written less than a frame holds no file.
        let planned = self
            .root(&space)
            .join("tmp")
            .join(format!("{}.part", hex(&self.env.random_bytes::<8>())));
        let sealed = keys.as_ref().is_some_and(|k| k.seal.is_some());
        let nonce_prefix = if sealed {
            self.env.random_bytes::<16>()
        } else {
            [0u8; 16]
        };
        let identity = match &keys {
            Some(k) => blake3::Hasher::new_keyed(&k.identity),
            None => blake3::Hasher::new(),
        };
        let registration = self.writers.register(LiveWriter {
            space: space.clone(),
            subject: keys.as_ref().map(|k| k.subject.clone()),
            key_version: keys.as_ref().map_or(0, |k| k.key_version),
        });
        Ok(BlobWriter {
            registration: Some(registration),
            store: self.clone(),
            space,
            planned,
            part: None,
            file: None,
            keys,
            nonce_prefix,
            identity,
            body: blake3::Hasher::new(),
            pending: Vec::new(),
            out: Vec::new(),
            next_frame: 0,
            file_pos: HEADER_LEN as u64,
            written: 0,
            limit,
            lease,
            budget: None,
        })
    }

    /// Names a finished part file as `meta`'s object, or claims an existing
    /// object of the same identity, under the directory's claim lock; either
    /// way the blob joins `lease` before the lock is released (ADR 0117 §6).
    async fn install(
        &self,
        space: &Space,
        part: &Path,
        meta: &BlobMeta,
        sealed: bool,
        lease: &Lease,
    ) -> Result<bool, BlobError> {
        let object = self.object_path(space, &meta.id);
        let dir_path = object
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| BlobError::Invalid("an object path without a directory".into()))?;
        let dir = self.dir(&dir_path);
        let fs = &self.env.fs;
        let _claim = dir.claim.lock().await;
        let claimable = match fs.open(object.clone(), OpenMode::Read).await {
            Ok(file) => existing_matches(&*file, meta, sealed).await,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(BlobError::io("opening a blob", e)),
        };
        if claimable {
            match fs.remove_file(part.to_path_buf()).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(error = %e, "could not delete a duplicate blob write"),
            }
        } else {
            fs.rename(part.to_path_buf(), object.clone())
                .await
                .map_err(|e| BlobError::io("naming a blob", e))?;
            let mut gens = lock(&dir.gens);
            gens.renamed += 1;
            let generation = gens.renamed;
            gens.pending.insert(meta.id.file_name(), generation);
        }
        // Named or claimed now, under the claim lock: a collector pass that
        // began before does not delete it (ADR 0120 §5).
        let touched = self.touch_seq.fetch_add(1, Ordering::AcqRel) + 1;
        lock(&dir.gens).touched.insert(meta.id.file_name(), touched);
        lease.add(meta.id);
        Ok(claimable)
    }

    /// The bytes of the objects of `space` (its `objects` shards, not its
    /// part files), for a [`SpaceBudget`]'s seed.
    pub async fn space_bytes(&self, space: &Space) -> Result<u64, BlobError> {
        let fs = &self.env.fs;
        let mut total = 0u64;
        for dir in shard_dirs(&self.root(space)) {
            let names = match fs.read_dir(dir.clone()).await {
                Ok(names) => names,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(BlobError::io("listing a blob directory", e)),
            };
            for name in names {
                if BlobId::from_file_name(&name).is_none() {
                    continue;
                }
                match fs.open(dir.join(&name), OpenMode::Read).await {
                    Ok(file) => {
                        total += file
                            .len()
                            .await
                            .map_err(|e| BlobError::io("reading a blob's length", e))?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(BlobError::io("opening a blob", e)),
                }
            }
        }
        Ok(total)
    }

    /// Makes blob `meta` present in `to` and joins it to `lease`: its file
    /// is copied byte for byte from `from` (its identity, sealing and key
    /// version unchanged), or, when `to` has it already, claimed there as a
    /// writer's finish claims an equal object. A rebase's turns become
    /// main's this way (M25 §4.3). Named durably only after
    /// [`BlobStore::ensure_durable`].
    pub async fn import(
        self: &Arc<Self>,
        from: &Space,
        to: &Space,
        meta: &BlobMeta,
        lease: &Lease,
    ) -> Result<(), BlobError> {
        self.check_reserve()?;
        self.prepare(to).await?;
        let fs = &self.env.fs;
        let source = match fs
            .open(self.object_path(from, &meta.id), OpenMode::Read)
            .await
        {
            Ok(file) => file,
            // Not in `from`: a blob of `to` the turns received there.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return if self.claim_existing(to, meta, lease).await? {
                    Ok(())
                } else {
                    Err(BlobError::NotFound(meta.id))
                };
            }
            Err(e) => return Err(BlobError::io("opening a blob", e)),
        };
        // The source must be the blob its name says.
        let corrupt = |why: String| BlobError::Corrupt { id: meta.id, why };
        let head = source
            .read_at(0, HEADER_LEN)
            .await
            .map_err(|e| BlobError::io("reading a blob header", e))?;
        let header = Header::decode(&head).map_err(corrupt)?;
        let len = source
            .len()
            .await
            .map_err(|e| BlobError::io("reading a blob's length", e))?;
        if header.identity != *meta.id.digest()
            || header.size != meta.size
            || header.subject != meta.subject
            || header.key_version != meta.key_version
            || len != header.file_len()
        {
            return Err(corrupt("the file is not the blob its name says".into()));
        }
        let part = self
            .root(to)
            .join("tmp")
            .join(format!("{}.part", hex(&self.env.random_bytes::<8>())));
        let target = fs
            .open(part.clone(), OpenMode::ReadWriteCreate)
            .await
            .map_err(|e| BlobError::io("creating a blob part file", e))?;
        let copied = async {
            let mut at = 0u64;
            while at < len {
                self.check_reserve()?;
                let n = (len - at).min(1 << 20) as usize;
                let bytes = source
                    .read_at(at, n)
                    .await
                    .map_err(|e| BlobError::io("reading a blob", e))?;
                if bytes.is_empty() {
                    return Err(corrupt(format!("the blob ends at {at} of {len} bytes")));
                }
                let got = bytes.len() as u64;
                target
                    .write_at(at, Bytes::from(bytes))
                    .await
                    .map_err(|e| BlobError::io("copying a blob", e))?;
                self.charge(got);
                at += got;
            }
            target
                .sync_data()
                .await
                .map_err(|e| BlobError::io("syncing a blob", e))?;
            self.install(to, &part, meta, header.sealed, lease).await
        }
        .await;
        if copied.is_err() {
            let _ = fs.remove_file(part).await;
        }
        copied.map(|_claimed| ())
    }

    /// Claims an object of `space` equal to `meta` for `lease`, under its
    /// directory's claim lock, as [`BlobStore::install`] does; false when
    /// there is none.
    async fn claim_existing(
        &self,
        space: &Space,
        meta: &BlobMeta,
        lease: &Lease,
    ) -> Result<bool, BlobError> {
        let object = self.object_path(space, &meta.id);
        let dir_path = object
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| BlobError::Invalid("an object path without a directory".into()))?;
        let dir = self.dir(&dir_path);
        let _claim = dir.claim.lock().await;
        let claimable = match self.env.fs.open(object, OpenMode::Read).await {
            Ok(file) => existing_matches(&*file, meta, false).await,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(BlobError::io("opening a blob", e)),
        };
        if claimable {
            // Claimed under the claim lock, as install's claim: a collector
            // pass that began before does not delete it (ADR 0120 §5).
            let touched = self.touch_seq.fetch_add(1, Ordering::AcqRel) + 1;
            lock(&dir.gens).touched.insert(meta.id.file_name(), touched);
            lease.add(meta.id);
        }
        Ok(claimable)
    }

    /// Makes the names of `ids` in `space` durable: one `sync_dir` per
    /// shard directory that holds a name this process created and has not
    /// synced yet, shared between concurrent callers (ADR 0117 §4.3). Call it
    /// before appending a record that references the blobs.
    pub async fn ensure_durable(&self, space: &Space, ids: &[BlobId]) -> Result<(), BlobError> {
        if self.mutation_skip_ensure_durable {
            return Ok(());
        }
        let mut need: BTreeMap<PathBuf, u64> = BTreeMap::new();
        for id in ids {
            let object = self.object_path(space, id);
            let Some(dir_path) = object.parent() else {
                continue;
            };
            let dir = self.dir(dir_path);
            let generation = lock(&dir.gens).pending.get(&id.file_name()).copied();
            if let Some(generation) = generation {
                let entry = need.entry(dir_path.to_path_buf()).or_default();
                *entry = (*entry).max(generation);
            }
        }
        for (dir_path, generation) in need {
            let dir = self.dir(&dir_path);
            let _one = dir.sync.lock().await;
            let target = {
                let gens = lock(&dir.gens);
                if gens.synced >= generation {
                    continue;
                }
                gens.renamed
            };
            self.env
                .fs
                .sync_dir(dir_path.clone())
                .await
                .map_err(|e| BlobError::io("syncing a blob directory", e))?;
            let mut gens = lock(&dir.gens);
            gens.synced = gens.synced.max(target);
            gens.pending.retain(|_, g| *g > target);
        }
        Ok(())
    }

    /// A reader of `meta`'s blob: from `space`, else from main's store.
    pub async fn reader(
        &self,
        space: &Space,
        meta: &BlobMeta,
        keys: &dyn KeyAccess,
    ) -> Result<BlobReader, BlobError> {
        let mut spaces = vec![space.clone()];
        if *space != Space::Main {
            spaces.push(Space::Main);
        }
        for s in spaces {
            match self
                .env
                .fs
                .open(self.object_path(&s, &meta.id), OpenMode::Read)
                .await
            {
                Ok(file) => return BlobReader::open(file, meta, keys).await,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(BlobError::io("opening a blob", e)),
            }
        }
        // A subject's blob whose file its erasure deleted is erased, not
        // missing (M26 §9.3).
        if let Some(subject) = &meta.subject
            && matches!(
                keys.identity_key(subject, meta.key_version),
                KeyAnswer::Erased
            )
        {
            return Err(BlobError::Erased);
        }
        Err(BlobError::NotFound(meta.id))
    }

    /// Whether `id`'s object exists in `space` (not falling back to main).
    pub async fn contains(&self, space: &Space, id: &BlobId) -> Result<bool, BlobError> {
        self.env
            .fs
            .exists(self.object_path(space, id))
            .await
            .map_err(|e| BlobError::io("looking for a blob", e))
    }
}

/// Whether an existing object is the same blob as `meta` (its header
/// structure, identity and size), so a writer may claim it instead of
/// replacing it. A damaged header is not claimed, nor a plain file when the
/// new one is sealed (privacy mode was turned on since): the new file
/// replaces it. A sealed file serves a plain writer as well.
async fn existing_matches(file: &dyn File, meta: &BlobMeta, sealed: bool) -> bool {
    let Ok(bytes) = file.read_at(0, HEADER_LEN).await else {
        return false;
    };
    let Ok(h) = Header::decode(&bytes) else {
        return false;
    };
    let Ok(len) = file.len().await else {
        return false;
    };
    h.identity == *meta.id.digest()
        && (h.sealed || !sealed)
        && h.size == meta.size
        && h.subject == meta.subject
        && h.key_version == meta.key_version
        && len == h.file_len()
}

/// Writes one blob. Dropping it before [`BlobWriter::finish`] discards it.
pub struct BlobWriter {
    /// Ends when the writer is done with its files: after the blob is named
    /// or claimed, or after its part file is deleted.
    registration: Option<WriterRegistration>,
    store: Arc<BlobStore>,
    space: Space,
    /// The part file's name, created with the first frame.
    planned: PathBuf,
    /// The part file once created, until the blob is named or discarded.
    part: Option<PathBuf>,
    file: Option<Arc<dyn File>>,
    keys: Option<BlobKeys>,
    nonce_prefix: [u8; 16],
    identity: blake3::Hasher,
    body: blake3::Hasher,
    /// Plaintext of the frame being filled, at most one frame.
    pending: Vec<u8>,
    /// The encoded frame not written yet: one at most, as every frame is
    /// written when it is complete.
    out: Vec<u8>,
    next_frame: u64,
    file_pos: u64,
    written: u64,
    limit: u64,
    lease: Lease,
    /// The space's budget, if it has one, and the bytes this writer took
    /// from it.
    budget: Option<(Arc<SpaceBudget>, u64)>,
}

impl BlobWriter {
    /// Charges what this writer accepts to `budget` (a preview's blob
    /// space): past it, `write` answers [`BlobError::SpaceFull`]. Set before
    /// the first write.
    pub fn with_budget(mut self, budget: Arc<SpaceBudget>) -> BlobWriter {
        self.budget = Some((budget, 0));
        self
    }

    /// Gives back what this writer took from its budget.
    fn refund(&mut self) {
        if let Some((budget, charged)) = &mut self.budget {
            budget.refund(*charged);
            *charged = 0;
        }
    }

    /// The space the blob is written to.
    pub fn space(&self) -> &Space {
        &self.space
    }

    fn frame_key(&self) -> Option<FrameKey<'_>> {
        let keys = self.keys.as_ref()?;
        Some(FrameKey {
            key: keys.seal.as_deref()?,
            nonce_prefix: &self.nonce_prefix,
            subject: &keys.subject,
            key_version: keys.key_version,
        })
    }

    fn encode_frame(&mut self, last: bool) -> Result<(), BlobError> {
        let index = self.next_frame;
        let mut out = std::mem::take(&mut self.out);
        let sealed = match self.frame_key() {
            Some(k) => Some(format::seal_frame(&k, index, last, &self.pending, &mut out)),
            None => None,
        };
        match sealed {
            Some(result) => result.map_err(BlobError::Io)?,
            None => format::plain_frame(&self.pending, &mut out),
        }
        self.out = out;
        self.pending.clear();
        self.next_frame += 1;
        Ok(())
    }

    /// The part file, created on first use.
    async fn file(&mut self) -> Result<Arc<dyn File>, BlobError> {
        if let Some(file) = &self.file {
            return Ok(file.clone());
        }
        let file = self
            .store
            .env
            .fs
            .open(self.planned.clone(), OpenMode::ReadWriteCreate)
            .await
            .map_err(|e| BlobError::io("creating a blob part file", e))?;
        self.part = Some(self.planned.clone());
        self.file = Some(file.clone());
        Ok(file)
    }

    /// Writes the encoded frame, below the store's reserve only, and counts
    /// it against the store's free space.
    async fn flush(&mut self) -> Result<(), BlobError> {
        if self.out.is_empty() {
            return Ok(());
        }
        self.store.check_reserve()?;
        let file = self.file().await?;
        let bytes = Bytes::from(std::mem::take(&mut self.out));
        self.body.update(&bytes);
        let len = bytes.len() as u64;
        file.write_at(self.file_pos, bytes)
            .await
            .map_err(|e| BlobError::io("writing a blob", e))?;
        self.store.charge(len);
        self.file_pos += len;
        Ok(())
    }

    /// Appends plaintext. Refused past the writer's limit and below the
    /// store's disk reserve; the blob is then unusable and should be dropped.
    pub async fn write(&mut self, mut data: &[u8]) -> Result<(), BlobError> {
        if self.written.saturating_add(data.len() as u64) > self.limit {
            return Err(BlobError::TooLarge { limit: self.limit });
        }
        self.store.check_reserve()?;
        if let Some((budget, charged)) = &mut self.budget {
            budget.seed(&self.store, &self.space).await?;
            budget.charge(data.len() as u64)?;
            *charged += data.len() as u64;
        }
        self.identity.update(data);
        self.written += data.len() as u64;
        while !data.is_empty() {
            if self.pending.len() == FRAME_SIZE {
                // More data follows, so this frame is not the last; it is
                // written now, so a writer buffers one frame at most.
                self.encode_frame(false)?;
                self.flush().await?;
            }
            let take = (FRAME_SIZE - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(())
    }

    /// Writes the last frame and the header, syncs the file, and names the
    /// blob (or claims an existing object with the same identity). The name
    /// is durable only after [`BlobStore::ensure_durable`].
    pub async fn finish(mut self) -> Result<BlobMeta, BlobError> {
        let sealed = self.frame_key().is_some();
        if !self.pending.is_empty() || (sealed && self.next_frame == 0) {
            self.encode_frame(true)?;
        }
        self.flush().await?;
        let identity = *self.identity.finalize().as_bytes();
        let id = match &self.keys {
            Some(_) => BlobId::keyed(identity),
            None => BlobId::plain(identity),
        };
        let mut header = Header {
            sealed,
            size: self.written,
            key_version: self.keys.as_ref().map_or(0, |k| k.key_version),
            identity,
            body_digest: *self.body.finalize().as_bytes(),
            nonce_prefix: self.nonce_prefix,
            subject: self.keys.as_ref().map(|k| k.subject.clone()),
            tag: [0; 16],
        };
        if let Some(key) = self.keys.as_ref().and_then(|k| k.seal.as_deref()) {
            header.seal(key).map_err(BlobError::Io)?;
        }
        // An empty plain blob has no frame: its file is created here.
        let file = self.file().await?;
        file.write_at(0, Bytes::copy_from_slice(&header.encode()))
            .await
            .map_err(|e| BlobError::io("writing a blob header", e))?;
        file.sync_data()
            .await
            .map_err(|e| BlobError::io("syncing a blob", e))?;
        let meta = BlobMeta {
            id,
            size: self.written,
            subject: header.subject.clone(),
            key_version: header.key_version,
        };
        let part = self
            .part
            .clone()
            .ok_or_else(|| BlobError::Invalid("a finished writer".into()))?;
        let claimed = self
            .store
            .install(&self.space, &part, &meta, sealed, &self.lease)
            .await?;
        self.part = None;
        // A new object keeps what it took from the budget; an object that
        // was there already took it before.
        if claimed {
            self.refund();
        } else if let Some((_, charged)) = &mut self.budget {
            *charged = 0;
        }
        Ok(meta)
    }

    /// Discards the blob and deletes its part file now.
    pub async fn abort(mut self) {
        self.refund();
        if let Some(part) = self.part.take() {
            let _ = self.store.env.fs.remove_file(part).await;
        }
    }
}

impl Drop for BlobWriter {
    fn drop(&mut self) {
        // Unfinished (or finished with an error): nothing new is named.
        self.refund();
        let registration = self.registration.take();
        if let Some(part) = self.part.take() {
            let fs = self.store.env.fs.clone();
            drop(self.store.env.spawn("blob part cleanup", async move {
                let _ = fs.remove_file(part).await;
                // The writer ends with its part file.
                drop(registration);
            }));
        }
    }
}

/// A writer that has not ended ([`BlobStore::live_writers`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveWriter {
    pub space: Space,
    /// Its blob's subject and key version; none and 0 without a subject.
    pub subject: Option<String>,
    pub key_version: u32,
}

/// The live writers of a store.
#[derive(Default)]
struct Writers {
    next: AtomicU64,
    live: Mutex<BTreeMap<u64, LiveWriter>>,
}

impl Writers {
    fn register(self: &Arc<Self>, writer: LiveWriter) -> WriterRegistration {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.live).insert(id, writer);
        WriterRegistration {
            writers: self.clone(),
            id,
        }
    }
}

/// A writer's entry in [`Writers`]; dropping it ends the writer.
struct WriterRegistration {
    writers: Arc<Writers>,
    id: u64,
}

impl Drop for WriterRegistration {
    fn drop(&mut self) {
        lock(&self.writers.live).remove(&self.id);
    }
}

/// Reads one blob: header checked at open, frames checked as they are read.
pub struct BlobReader {
    file: Arc<dyn File>,
    header: Header,
    meta: BlobMeta,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl BlobReader {
    async fn open(
        file: Arc<dyn File>,
        meta: &BlobMeta,
        keys: &dyn KeyAccess,
    ) -> Result<BlobReader, BlobError> {
        let corrupt = |why: String| BlobError::Corrupt { id: meta.id, why };
        let bytes = file
            .read_at(0, HEADER_LEN)
            .await
            .map_err(|e| BlobError::io("reading a blob header", e))?;
        let header = Header::decode(&bytes).map_err(corrupt)?;
        // Keys are looked up with the reference's subject and version, never
        // the header's: nothing in a header is trusted before its tag.
        let key = if header.sealed {
            let subject = meta
                .subject
                .clone()
                .ok_or_else(|| corrupt("a sealed file for a blob without a subject".into()))?;
            let key = match keys.seal_key(&subject, meta.key_version) {
                KeyAnswer::Found(key) => key,
                KeyAnswer::Erased => return Err(BlobError::Erased),
                KeyAnswer::Missing => return Err(BlobError::KeyMissing(subject)),
                KeyAnswer::Unavailable(why) => {
                    return Err(BlobError::Io(format!("reading a blob key: {why}")));
                }
            };
            header.verify(&key).map_err(corrupt)?;
            Some(key)
        } else {
            // ADR 0118 §4: an erased subject's blob is gone, plain or sealed.
            if let Some(subject) = &meta.subject {
                match keys.identity_key(subject, meta.key_version) {
                    KeyAnswer::Erased => return Err(BlobError::Erased),
                    KeyAnswer::Unavailable(why) => {
                        return Err(BlobError::Io(format!("reading a blob key: {why}")));
                    }
                    KeyAnswer::Found(_) | KeyAnswer::Missing => {}
                }
            }
            None
        };
        if header.identity != *meta.id.digest()
            || header.size != meta.size
            || header.subject != meta.subject
            || header.key_version != meta.key_version
        {
            return Err(corrupt("the file is not the blob its name says".into()));
        }
        let len = file
            .len()
            .await
            .map_err(|e| BlobError::io("reading a blob's length", e))?;
        if len != header.file_len() {
            return Err(corrupt(format!(
                "{len} bytes where its header needs {}",
                header.file_len()
            )));
        }
        Ok(BlobReader {
            file,
            header,
            meta: meta.clone(),
            key,
        })
    }

    pub fn meta(&self) -> &BlobMeta {
        &self.meta
    }

    /// Whether the file is sealed.
    pub fn is_sealed(&self) -> bool {
        self.header.sealed
    }

    fn corrupt(&self, why: String) -> BlobError {
        BlobError::Corrupt {
            id: self.meta.id,
            why,
        }
    }

    fn open_frame(&self, index: u64, stored: &[u8]) -> Result<Vec<u8>, BlobError> {
        let last = index + 1 == self.header.frames();
        let plain = match (&self.key, self.header.subject.as_deref()) {
            (Some(key), Some(subject)) => format::open_sealed_frame(
                &FrameKey {
                    key,
                    nonce_prefix: &self.header.nonce_prefix,
                    subject,
                    key_version: self.header.key_version,
                },
                index,
                last,
                stored,
            ),
            _ => format::open_plain_frame(stored).map(<[u8]>::to_vec),
        };
        let plain = plain.ok_or_else(|| self.corrupt(format!("frame {index} fails its check")))?;
        if plain.len() != self.header.frame_plain_len(index) {
            return Err(self.corrupt(format!("frame {index} has the wrong length")));
        }
        Ok(plain)
    }

    /// Up to `len` bytes from `offset`: fewer only at the end of the blob,
    /// none at or past it. Reads and checks only the frames the range
    /// touches.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<Bytes, BlobError> {
        let size = self.header.size;
        if offset >= size || len == 0 {
            return Ok(Bytes::new());
        }
        let end = size.min(offset.saturating_add(len as u64));
        let frame = FRAME_SIZE as u64;
        let (first, last) = (offset / frame, (end - 1) / frame);
        let start = self.header.frame_offset(first);
        let stop = self.header.frame_offset(last)
            + (self.header.frame_plain_len(last) + self.header.overhead()) as u64;
        let raw = self
            .file
            .read_at(start, (stop - start) as usize)
            .await
            .map_err(|e| BlobError::io("reading a blob", e))?;
        if raw.len() as u64 != stop - start {
            return Err(self.corrupt("the file ends early".into()));
        }
        let mut out = Vec::with_capacity((end - offset) as usize);
        for index in first..=last {
            let at = (self.header.frame_offset(index) - start) as usize;
            let stored_len = self.header.frame_plain_len(index) + self.header.overhead();
            let plain = self.open_frame(index, &raw[at..at + stored_len])?;
            let frame_start = index * frame;
            let from = offset.max(frame_start) - frame_start;
            let to = end.min(frame_start + plain.len() as u64) - frame_start;
            out.extend_from_slice(&plain[from as usize..to as usize]);
        }
        Ok(Bytes::from(out))
    }

    /// The plaintext of frame `index`, checked (sequential readers: the
    /// gateway, the shipper, the API).
    pub async fn frame(&self, index: u64) -> Result<Bytes, BlobError> {
        if index >= self.header.frames() {
            return Ok(Bytes::new());
        }
        let start = self.header.frame_offset(index);
        let stored_len = self.header.frame_plain_len(index) + self.header.overhead();
        let raw = self
            .file
            .read_at(start, stored_len)
            .await
            .map_err(|e| BlobError::io("reading a blob", e))?;
        if raw.len() != stored_len {
            return Err(self.corrupt("the file ends early".into()));
        }
        self.open_frame(index, &raw).map(Bytes::from)
    }

    /// The number of frames the blob has on disk.
    pub fn frames(&self) -> u64 {
        self.header.frames()
    }

    /// Checks the whole file: every frame, the body digest, and the identity
    /// (for a subject's blob with its identity key from `keys`).
    pub async fn verify(&self, keys: &dyn KeyAccess) -> Result<(), BlobError> {
        let mut body = blake3::Hasher::new();
        let mut identity = match (&self.meta.subject, self.meta.id.is_keyed()) {
            (Some(subject), true) => match keys.identity_key(subject, self.meta.key_version) {
                KeyAnswer::Found(k) => Some(blake3::Hasher::new_keyed(&k)),
                KeyAnswer::Erased => return Err(BlobError::Erased),
                KeyAnswer::Missing => None,
                KeyAnswer::Unavailable(why) => {
                    return Err(BlobError::Io(format!("reading a blob key: {why}")));
                }
            },
            _ => Some(blake3::Hasher::new()),
        };
        for index in 0..self.header.frames() {
            let start = self.header.frame_offset(index);
            let stored_len = self.header.frame_plain_len(index) + self.header.overhead();
            let raw = self
                .file
                .read_at(start, stored_len)
                .await
                .map_err(|e| BlobError::io("reading a blob", e))?;
            if raw.len() != stored_len {
                return Err(self.corrupt("the file ends early".into()));
            }
            body.update(&raw);
            let plain = self.open_frame(index, &raw)?;
            if let Some(h) = identity.as_mut() {
                h.update(&plain);
            }
        }
        if *body.finalize().as_bytes() != self.header.body_digest {
            return Err(self.corrupt("the body digest does not match".into()));
        }
        if let Some(h) = identity
            && h.finalize().as_bytes() != self.meta.id.digest()
        {
            return Err(self.corrupt("the content does not match its identity".into()));
        }
        Ok(())
    }
}
