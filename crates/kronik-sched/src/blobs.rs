//! The scheduler's blob host (M25, docs/design/m25-streaming-bodies.md §5.4):
//! one turn's access to the blob store, behind `kronik_runtime::BlobHost`.
//!
//! The runtime keeps the rules (the turn's references, the limits); this
//! host reads and writes the bytes. Every blob the turn creates joins the
//! turn's lease, which the turn keeps until its record is applied
//! (ADR 0120 §4), and [`TurnBlobs::ensure_durable`] names them durably
//! before the record that refers to them is appended (ADR 0117 §4). A
//! writer's bytes are scrubbed of the secret values the turn has used or
//! revealed so far (§5.2), with the matcher of turn outputs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kronik_blob::{BlobError, BlobId, BlobMeta, BlobReader, BlobStore, BlobWriter, Lease, Space};
use kronik_core::env::{BodySource, BoxFuture, Env};
use kronik_effects::http::{CompiledScrubber, ScrubError, StreamScrubber};
use kronik_privacy::sealer::Sealer;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{BlobHost, BlobHostError};

use crate::effects::{FxState, secret_patterns};

/// The most one push of a writer's scrubber may emit: a 1 MiB chunk whose
/// secrets turn into longer markers.
const SCRUB_BUFFER_BYTES: usize = 16 << 20;
/// Readers a turn keeps open; reading another blob closes the oldest. The
/// results do not depend on it, only how often a header is read again.
const OPEN_READERS: usize = 32;
/// How often a running turn renews its lease (ADR 0120 §4), at most a
/// quarter of the lease's lifetime.
const RENEW_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// The secret values a turn has used or revealed, by name.
pub type SecretValues = Vec<(String, Arc<zeroize::Zeroizing<Vec<u8>>>)>;
/// Where a turn's blob host reads them, at each write.
pub type SecretSource = Arc<dyn Fn() -> SecretValues + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// How a blob host treats keys and subjects' blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOptions {
    /// Whether a subject's blob takes its key as production's do
    /// (`Sealer::blob_keys`). A fork's take theirs by the rule of the fork's
    /// record sealing (`Sealer::fork_blob_keys`): with privacy on, a new
    /// subject's key is created, as the fork's record creates it, and an
    /// erased subject's blob is refused.
    pub create_keys: bool,
    /// A `--no-pii` fork: a read of a subject's blob gives its pseudonym
    /// (M25 §9), never its bytes.
    pub pseudonymize: bool,
}

impl HostOptions {
    /// A production turn's host.
    pub fn production() -> HostOptions {
        HostOptions {
            create_keys: true,
            pseudonymize: false,
        }
    }

    /// A fork turn's host; `no_pii` for a `--no-pii` fork.
    pub fn fork(no_pii: bool) -> HostOptions {
        HostOptions {
            create_keys: false,
            pseudonymize: no_pii,
        }
    }
}

/// One turn's blob host. Cloning shares it. The scheduler gives one to
/// every turn; the fork engine to every fork turn, in the fork's space.
#[derive(Clone)]
pub struct TurnBlobs(Arc<Inner>);

struct Inner {
    store: Arc<BlobStore>,
    space: Space,
    env: Env,
    sealer: Arc<Sealer>,
    /// The turn's effect state: the secret values it used or revealed.
    secrets: SecretSource,
    lease: Lease,
    /// What one blob of the turn may hold (the turn's created-bytes limit).
    limit: u64,
    next: AtomicU64,
    writers: Mutex<HashMap<u64, Slot>>,
    /// Open readers, oldest first ([`OPEN_READERS`] at most).
    readers: Mutex<Vec<(String, Arc<BlobReader>)>>,
    /// Blobs the turn finished, to make durable before its record.
    created: Mutex<Vec<BlobId>>,
    /// The secret values each finished writer's scrubber replaced (§7.6).
    replaced: Mutex<HashMap<u64, u64>>,
    options: HostOptions,
    /// The turn read an erased subject's blob (a fork marks it unverifiable).
    read_erased: std::sync::atomic::AtomicBool,
    /// The turn got a pseudonym for a subject's blob (`--no-pii`).
    read_masked: std::sync::atomic::AtomicBool,
    /// The byte budget of the space it writes to: a preview's
    /// ([`TurnBlobs::with_budget`]).
    budget: std::sync::OnceLock<Arc<kronik_blob::SpaceBudget>>,
}

struct Slot {
    /// None while a write is in flight.
    writer: Option<BlobWriter>,
    /// The scrubber, and how many secret values it matches.
    scrub: Option<(StreamScrubber<'static>, usize)>,
}

impl TurnBlobs {
    /// A host writing to `space` of `store` under a new lease, reading
    /// subjects' keys from `sealer`, scrubbing writes of what `secrets`
    /// gives, at most `limit` bytes per blob.
    pub fn new(
        store: Arc<BlobStore>,
        space: Space,
        env: Env,
        sealer: Arc<Sealer>,
        fx_state: SecretSource,
        limit: u64,
        options: HostOptions,
    ) -> TurnBlobs {
        let lease = store.leases().take("turn");
        let inner = Arc::new(Inner {
            store,
            space,
            env,
            sealer,
            secrets: fx_state,
            lease,
            limit,
            next: AtomicU64::new(0),
            writers: Mutex::new(HashMap::new()),
            readers: Mutex::new(Vec::new()),
            created: Mutex::new(Vec::new()),
            replaced: Mutex::new(HashMap::new()),
            options,
            read_erased: std::sync::atomic::AtomicBool::new(false),
            read_masked: std::sync::atomic::AtomicBool::new(false),
            budget: std::sync::OnceLock::new(),
        });
        // The lease lives as long as the host, renewed while the turn runs,
        // however long it waits (ADR 0120 §4); the loop ends with the host.
        let weak = Arc::downgrade(&inner);
        let every = RENEW_EVERY.min(inner.store.lease_ttl() / 4);
        let clock = inner.env.clock.clone();
        drop(inner.env.spawn("blob lease renewal", async move {
            loop {
                clock.sleep(every).await;
                match weak.upgrade() {
                    Some(inner) => inner.lease.renew(),
                    None => return,
                }
            }
        }));
        TurnBlobs(inner)
    }

    /// Charges what the turn writes to `budget`, a preview's blob space
    /// (`[fork] preview_blob_bytes`): past it, a write answers
    /// `quota-exceeded`, and an effect's response is too large to store.
    pub fn with_budget(self, budget: Arc<kronik_blob::SpaceBudget>) -> TurnBlobs {
        let _ = self.0.budget.set(budget);
        self
    }

    /// The secret values of a turn's effect state, for its blob host. It
    /// holds the turn's effects weakly: the gate holds the host, and a
    /// strong reference here would keep both, the turn's secrets and its
    /// lease, alive for good.
    pub(crate) fn secrets_of(state: Arc<crate::effects::TurnFx>) -> SecretSource {
        let state = Arc::downgrade(&state);
        Arc::new(move || match state.upgrade() {
            Some(state) => {
                let s: std::sync::MutexGuard<'_, FxState> = lock(&state.state);
                s.secrets.clone()
            }
            None => Vec::new(),
        })
    }

    /// Stores an effect's response body as a blob of `subject` (M25 §7.3):
    /// `first` and the rest of `rest`, at most `limit` bytes as they arrive,
    /// scrubbed with `matcher`, and named durably before it returns, so the
    /// effect's result never precedes its blob.
    pub(crate) async fn store_stream(
        &self,
        subject: Option<&str>,
        first: bytes::Bytes,
        rest: &mut dyn BodySource,
        matcher: CompiledScrubber<'static>,
        limit: u64,
    ) -> Result<pb::BlobRef, StreamError> {
        let inner = &self.0;
        let keys = match subject {
            None => None,
            Some(subject) => Some(
                inner
                    .keys(subject)
                    .map_err(|e| StreamError::Store(format!("{e:?}")))?,
            ),
        };
        let writer = inner
            .store
            .writer(inner.space.clone(), keys, u64::MAX, inner.lease.clone())
            .await
            .map_err(StreamError::from_blob)?;
        let mut writer = match inner.budget.get() {
            Some(budget) => writer.with_budget(budget.clone()),
            None => writer,
        };
        let mut scrubber = StreamScrubber::from_compiled(
            matcher,
            crate::scrub::limits(usize::MAX),
            SCRUB_BUFFER_BYTES,
        )
        .map_err(|e| StreamError::Store(e.to_string()))?;
        let mut read = 0u64;
        let mut chunk = Some(first);
        loop {
            let bytes = match chunk.take() {
                Some(bytes) => bytes,
                None => match rest.next().await {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => break,
                    Err(e) => {
                        writer.abort().await;
                        return Err(if kronik_core::env::is_response_too_large(&e) {
                            StreamError::TooLarge
                        } else {
                            StreamError::Source(e.to_string())
                        });
                    }
                },
            };
            read = read.saturating_add(bytes.len() as u64);
            if read > limit {
                writer.abort().await;
                return Err(StreamError::TooLarge);
            }
            let scrubbed = match scrubber.push(&bytes) {
                Ok(out) => out.to_vec(),
                Err(e) => {
                    writer.abort().await;
                    return Err(StreamError::Store(format!("scrubbing a response: {e}")));
                }
            };
            if let Err(e) = writer.write(&scrubbed).await {
                writer.abort().await;
                return Err(StreamError::from_blob(e));
            }
        }
        let tail = match scrubber.finish() {
            Ok(tail) => tail,
            Err(e) => {
                writer.abort().await;
                return Err(StreamError::Store(format!("scrubbing a response: {e}")));
            }
        };
        if let Err(e) = writer.write(&tail).await {
            writer.abort().await;
            return Err(StreamError::from_blob(e));
        }
        let meta = writer.finish().await.map_err(StreamError::from_blob)?;
        inner
            .store
            .ensure_durable(&inner.space, &[meta.id])
            .await
            .map_err(StreamError::from_blob)?;
        lock(&inner.created).push(meta.id);
        kronik_metrics::add(
            "kronik_blob_written_bytes_total",
            &[("source", "effect")],
            meta.size,
        );
        Ok(meta.to_pb())
    }

    /// A blob the turn may use, as a request body read frame by frame
    /// (M25 §7.2); a sealed blob is opened with its subject's key.
    pub(crate) async fn source(
        &self,
        blob: &pb::BlobRef,
    ) -> Result<Box<dyn BodySource>, BlobHostError> {
        let reader = self.0.reader(blob).await?;
        Ok(Box::new(FrameSource { reader, next: 0 }))
    }

    /// Adds the blobs `input` references to the turn's lease, which is
    /// renewed while the turn runs: its input stays while the turn reads it
    /// (ADR 0120 §4), however long it waits before its record.
    pub(crate) fn lease_input(&self, input: &pb::Input) {
        let mut refs = Vec::new();
        kronik_proto::blobs::input(Some(input), &mut refs);
        for blob in refs {
            if let Ok(id) = BlobId::parse(&blob.hash) {
                self.0.lease.add(id);
            }
        }
    }

    /// Whether the turn read an erased subject's blob.
    pub fn read_erased(&self) -> bool {
        self.0.read_erased.load(Ordering::Relaxed)
    }

    /// Whether the turn got a pseudonym for a subject's blob.
    pub fn read_masked(&self) -> bool {
        self.0.read_masked.load(Ordering::Relaxed)
    }

    /// Names every blob the turn finished durably (ADR 0117 §4); called
    /// before the turn's record is appended.
    pub async fn ensure_durable(&self) -> Result<(), BlobError> {
        let ids = lock(&self.0.created).clone();
        if ids.is_empty() {
            return Ok(());
        }
        self.0.store.ensure_durable(&self.0.space, &ids).await
    }
}

/// Why an effect's response could not become a blob.
#[derive(Debug)]
pub(crate) enum StreamError {
    /// Past the effect's response limit: `TOO_LARGE` is recorded.
    TooLarge,
    /// Reading the response failed: a network error is recorded.
    Source(String),
    /// The blob store is below its reserve: the turn runs again later, as
    /// after a crash once the request left (M25 §4.7).
    StoreFull(String),
    /// The blob store's disk failed: the node stops (M25 §4.7).
    Io(String),
    /// Any other store failure: a host failure.
    Store(String),
}

impl StreamError {
    fn from_blob(error: BlobError) -> StreamError {
        match error {
            BlobError::StoreFull { .. } => StreamError::StoreFull(error.to_string()),
            BlobError::Io(message) => StreamError::Io(message),
            // A preview's blob space is full: the response does not fit.
            BlobError::SpaceFull { .. } => StreamError::TooLarge,
            other => StreamError::Store(other.to_string()),
        }
    }
}

/// A blob's plaintext, one frame per chunk.
struct FrameSource {
    reader: Arc<BlobReader>,
    next: u64,
}

impl BodySource for FrameSource {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<bytes::Bytes>>> {
        Box::pin(async move {
            if self.next >= self.reader.frames() {
                return Ok(None);
            }
            let frame = self
                .reader
                .frame(self.next)
                .await
                .map_err(std::io::Error::other)?;
            self.next += 1;
            kronik_metrics::add(
                "kronik_blob_read_bytes_total",
                &[("reader", "effect")],
                frame.len() as u64,
            );
            Ok(Some(frame))
        })
    }
}

/// A store error as the runtime sees it.
fn host_error(error: BlobError) -> BlobHostError {
    match error {
        BlobError::Erased => BlobHostError::Erased,
        BlobError::KeyMissing(subject) => BlobHostError::KeyMissing(subject),
        BlobError::StoreFull { free, reserve } => BlobHostError::StoreFull(format!(
            "the blob store has {free} bytes free, below its reserve of {reserve}"
        )),
        BlobError::TooLarge { .. } | BlobError::SpaceFull { .. } => BlobHostError::TooLarge,
        BlobError::NotFound(id) => {
            kronik_metrics::inc("kronik_blob_missing_total", &[]);
            BlobHostError::Missing(format!("blob {id} is not in the blob store"))
        }
        BlobError::Io(message) => BlobHostError::Io(message),
        other => BlobHostError::Host(other.to_string()),
    }
}

fn scrub_error(error: ScrubError) -> BlobHostError {
    match error {
        ScrubError::OutputLimit => BlobHostError::TooLarge,
        other => BlobHostError::Host(format!("scrubbing a blob of secrets: {other}")),
    }
}

impl Inner {
    /// The keys of a subject's new blob: created when the host may, else
    /// the subject's existing key, else a fork-local test key (never
    /// sealed), so a fork never changes the keystore.
    fn keys(&self, subject: &str) -> Result<kronik_blob::BlobKeys, BlobHostError> {
        let privacy = |e: kronik_privacy::PrivacyError| match e {
            kronik_privacy::PrivacyError::KeyMissing(s) => BlobHostError::KeyMissing(s),
            other => BlobHostError::Host(other.to_string()),
        };
        if self.options.create_keys {
            let entropy = self.env.entropy.clone();
            let fill = move |bytes: &mut [u8]| entropy.fill(bytes);
            return self
                .sealer
                .blob_keys(subject, &fill, self.env.clock.wall_ms())
                .map_err(privacy);
        }
        // A fork's blob is sealed as the fork's record that names it is
        // (review P-1): never plain on disk with privacy on.
        let entropy = self.env.entropy.clone();
        let fill = move |bytes: &mut [u8]| entropy.fill(bytes);
        match self
            .sealer
            .fork_blob_keys(subject, &fill, self.env.clock.wall_ms())
            .map_err(privacy)?
        {
            Some(keys) => Ok(keys),
            None => {
                // An erased subject: no new key version in a fork (M8 §6.8),
                // and the turn cannot be checked against production's.
                self.read_erased
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Err(BlobHostError::Erased)
            }
        }
    }

    /// Brings the writer's scrubber up to the turn's secrets: none while
    /// the turn has used no secret, a new matcher when it has more.
    /// Returns bytes the switch emitted.
    fn rescrub(&self, slot: &mut Slot) -> Result<Vec<u8>, BlobHostError> {
        let secrets = (self.secrets)();
        let known = slot.scrub.as_ref().map_or(0, |(_, n)| *n);
        if secrets.len() <= known {
            return Ok(Vec::new());
        }
        let patterns = secret_patterns(&secrets);
        let matcher = CompiledScrubber::new(&patterns, crate::scrub::MAX_SECRET_PATTERN_BYTES)
            .map_err(scrub_error)?
            .into_owned();
        let limits = crate::scrub::limits(usize::try_from(self.limit).unwrap_or(usize::MAX));
        let (scrubber, emitted) = match slot.scrub.take() {
            None => (
                StreamScrubber::from_compiled(matcher, limits, SCRUB_BUFFER_BYTES)
                    .map_err(scrub_error)?,
                Vec::new(),
            ),
            Some((old, _)) => old.rematch(matcher).map_err(scrub_error)?,
        };
        slot.scrub = Some((scrubber, secrets.len()));
        Ok(emitted)
    }

    async fn reader(&self, blob: &pb::BlobRef) -> Result<Arc<BlobReader>, BlobHostError> {
        if let Some((_, reader)) = lock(&self.readers).iter().find(|(h, _)| *h == blob.hash) {
            return Ok(reader.clone());
        }
        let meta = BlobMeta::from_pb(blob).map_err(host_error)?;
        let access = self.sealer.blob_key_access();
        let reader = Arc::new(
            self.store
                .reader(&self.space, &meta, &access)
                .await
                .map_err(host_error)?,
        );
        let mut readers = lock(&self.readers);
        if readers.len() >= OPEN_READERS {
            readers.remove(0);
        }
        readers.push((blob.hash.clone(), reader.clone()));
        Ok(reader)
    }
}

impl BlobHost for TurnBlobs {
    fn read(
        &self,
        blob: &pb::BlobRef,
        offset: u64,
        len: u32,
    ) -> BoxFuture<'static, Result<Vec<u8>, BlobHostError>> {
        let inner = self.0.clone();
        let blob = blob.clone();
        Box::pin(async move {
            // A `--no-pii` fork reads a subject's blob as its pseudonym:
            // 16 bytes, then nothing (M25 §9).
            if inner.options.pseudonymize
                && let Some(subject) = &blob.subject
            {
                inner.read_masked.store(true, Ordering::Relaxed);
                let digest = kronik_proto::blobs::parse_hash(&blob.hash)
                    .map(|(_, digest)| digest)
                    .map_err(BlobHostError::Host)?;
                let pseudonym = inner
                    .sealer
                    .pseudonym(subject, &digest)
                    .unwrap_or_default()
                    .into_bytes();
                let start = (offset as usize).min(pseudonym.len());
                let end = start.saturating_add(len as usize).min(pseudonym.len());
                return Ok(pseudonym[start..end].to_vec());
            }
            let reader = match inner.reader(&blob).await {
                Ok(reader) => reader,
                Err(BlobHostError::Erased) => {
                    inner.read_erased.store(true, Ordering::Relaxed);
                    return Err(BlobHostError::Erased);
                }
                Err(e) => return Err(e),
            };
            let len = (len as usize)
                .min(usize::try_from(blob.size.saturating_sub(offset)).unwrap_or(usize::MAX));
            if len == 0 {
                return Ok(Vec::new());
            }
            let bytes = reader.read_at(offset, len).await.map_err(host_error)?;
            kronik_metrics::add(
                "kronik_blob_read_bytes_total",
                &[("reader", "guest")],
                bytes.len() as u64,
            );
            Ok(bytes.to_vec())
        })
    }

    fn create(&self, subject: Option<String>) -> BoxFuture<'static, Result<u64, BlobHostError>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let keys = match &subject {
                None => None,
                Some(subject) => Some(inner.keys(subject)?),
            };
            let writer = inner
                .store
                .writer(inner.space.clone(), keys, inner.limit, inner.lease.clone())
                .await
                .map_err(host_error)?;
            let writer = match inner.budget.get() {
                Some(budget) => writer.with_budget(budget.clone()),
                None => writer,
            };
            let id = inner.next.fetch_add(1, Ordering::Relaxed);
            let mut slot = Slot {
                writer: Some(writer),
                scrub: None,
            };
            // A turn that used secrets before the writer starts scrubs from
            // its first byte.
            let emitted = inner.rescrub(&mut slot)?;
            debug_assert!(emitted.is_empty());
            lock(&inner.writers).insert(id, slot);
            Ok(id)
        })
    }

    fn write(&self, writer: u64, chunk: Vec<u8>) -> BoxFuture<'static, Result<(), BlobHostError>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let (mut w, bytes) = {
                let mut writers = lock(&inner.writers);
                let slot = writers
                    .get_mut(&writer)
                    .ok_or_else(|| BlobHostError::Host(format!("no blob writer {writer}")))?;
                let mut bytes = inner.rescrub(slot)?;
                match &mut slot.scrub {
                    Some((scrubber, _)) => {
                        bytes.extend_from_slice(scrubber.push(&chunk).map_err(scrub_error)?);
                    }
                    None if bytes.is_empty() => bytes = chunk,
                    None => bytes.extend_from_slice(&chunk),
                }
                let w = slot
                    .writer
                    .take()
                    .ok_or_else(|| BlobHostError::Host(format!("blob writer {writer} is busy")))?;
                (w, bytes)
            };
            let result = w.write(&bytes).await.map_err(host_error);
            if let Some(slot) = lock(&inner.writers).get_mut(&writer) {
                slot.writer = Some(w);
            }
            result
        })
    }

    fn finish(&self, writer: u64) -> BoxFuture<'static, Result<pb::BlobRef, BlobHostError>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let slot = lock(&inner.writers)
                .remove(&writer)
                .ok_or_else(|| BlobHostError::Host(format!("no blob writer {writer}")))?;
            let mut w = slot
                .writer
                .ok_or_else(|| BlobHostError::Host(format!("blob writer {writer} is busy")))?;
            if let Some((scrubber, _)) = slot.scrub {
                let (tail, replaced) = scrubber.finish_counted().map_err(scrub_error)?;
                lock(&inner.replaced).insert(writer, replaced);
                w.write(&tail).await.map_err(host_error)?;
            }
            let meta = w.finish().await.map_err(host_error)?;
            kronik_metrics::add(
                "kronik_blob_written_bytes_total",
                &[("source", "guest")],
                meta.size,
            );
            lock(&inner.created).push(meta.id);
            Ok(meta.to_pb())
        })
    }

    fn replaced(&self, writer: u64) -> u64 {
        if let Some(slot) = lock(&self.0.writers).get(&writer) {
            return slot.scrub.as_ref().map_or(0, |(s, _)| s.replaced());
        }
        lock(&self.0.replaced).get(&writer).copied().unwrap_or(0)
    }

    fn discard(&self, writer: u64) {
        let slot = lock(&self.0.writers).remove(&writer);
        if let Some(Slot {
            writer: Some(w), ..
        }) = slot
        {
            // Dropping a writer deletes its part file in the background.
            drop(w);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    type Secrets = Arc<Mutex<SecretValues>>;

    async fn host(dir: &std::path::Path, secrets: &Secrets) -> (TurnBlobs, Arc<BlobStore>) {
        let env = Env::real(tokio::runtime::Handle::current());
        let store = BlobStore::open(env.clone(), dir, kronik_blob::StoreConfig::default())
            .await
            .unwrap();
        let seen = secrets.clone();
        let blobs = TurnBlobs::new(
            store.clone(),
            Space::Main,
            env,
            Arc::new(Sealer::plain()),
            Arc::new(move || lock(&seen).clone()),
            1 << 30,
            HostOptions::production(),
        );
        (blobs, store)
    }

    fn secret(name: &str, value: &[u8]) -> (String, Arc<zeroize::Zeroizing<Vec<u8>>>) {
        (
            name.into(),
            Arc::new(zeroize::Zeroizing::new(value.to_vec())),
        )
    }

    /// What `replaced` said after each finish of `written`, in order.
    static COUNTED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

    async fn written(
        blobs: &TurnBlobs,
        store: &BlobStore,
        chunks: &[&[u8]],
        reveal: Option<(&Secrets, usize)>,
    ) -> Vec<u8> {
        let id = blobs.create(None).await.unwrap();
        for (i, chunk) in chunks.iter().enumerate() {
            if let Some((secrets, at)) = reveal
                && at == i
            {
                lock(secrets).push(secret("late", b"LATE-VALUE"));
            }
            blobs.write(id, chunk.to_vec()).await.unwrap();
        }
        let blob = blobs.finish(id).await.unwrap();
        blobs.ensure_durable().await.unwrap();
        lock(&COUNTED).push(blobs.replaced(id));
        let meta = BlobMeta::from_pb(&blob).unwrap();
        let reader = store
            .reader(&Space::Main, &meta, &kronik_blob::NoKeys)
            .await
            .unwrap();
        reader
            .read_at(0, blob.size as usize)
            .await
            .unwrap()
            .to_vec()
    }

    /// A turn that used no secret writes its bytes as they are; one that
    /// did has them scrubbed, also across write borders, and a value
    /// revealed between writes is scrubbed from then on, including where it
    /// straddles the switch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writes_are_scrubbed_of_the_turns_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let secrets: Secrets = Arc::default();
        let (blobs, store) = host(dir.path(), &secrets).await;
        let plain = written(&blobs, &store, &[b"key s3cr3t-v", b"alue here"], None).await;
        assert_eq!(plain, b"key s3cr3t-value here");

        lock(&secrets).push(secret("api-key", b"s3cr3t-value"));
        let scrubbed = written(&blobs, &store, &[b"key s3cr3t-v", b"alue here"], None).await;
        assert_eq!(scrubbed, b"key [secret:api-key] here");

        // "LATE-" is written before the value is revealed and held back by
        // the scrubber; the rest comes after.
        let late = written(
            &blobs,
            &store,
            &[b"LATE-", b"VALUE and s3cr3t-value", b" and LATE-VALUE"],
            Some((&secrets, 1)),
        )
        .await;
        assert_eq!(
            late,
            b"[secret:late] and [secret:api-key] and [secret:late]"
        );
        // How many values each writer replaced, readable after its finish
        // (M25 §7.6): the last one's include the value held back across the
        // reveal.
        assert_eq!(*lock(&COUNTED), [0, 1, 3]);
    }

    /// An unfinished writer leaves nothing behind but what the store's
    /// own cleanup removes; a finished one is durable after ensure_durable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_discarded_writer_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let secrets: Secrets = Arc::default();
        let (blobs, _store) = host(dir.path(), &secrets).await;
        let id = blobs.create(None).await.unwrap();
        blobs.write(id, b"never finished".to_vec()).await.unwrap();
        blobs.discard(id);
        assert!(lock(&blobs.0.created).is_empty());
        assert!(blobs.write(id, b"more".to_vec()).await.is_err());
        blobs.ensure_durable().await.unwrap();
    }
}
