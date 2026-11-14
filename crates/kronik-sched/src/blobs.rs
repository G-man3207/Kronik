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
use kronik_core::env::{BoxFuture, Env};
use kronik_effects::http::{CompiledScrubber, ScrubError, StreamScrubber};
use kronik_privacy::sealer::Sealer;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{BlobHost, BlobHostError};

use crate::effects::{FxState, secret_patterns};

/// The most one push of a writer's scrubber may emit: a 1 MiB chunk whose
/// secrets turn into longer markers.
const SCRUB_BUFFER_BYTES: usize = 16 << 20;

/// The secret values a turn has used or revealed, by name.
pub(crate) type SecretValues = Vec<(String, Arc<zeroize::Zeroizing<Vec<u8>>>)>;
/// Where a turn's blob host reads them, at each write.
pub(crate) type SecretSource = Arc<dyn Fn() -> SecretValues + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One turn's blob host. Cloning shares it.
#[derive(Clone)]
pub(crate) struct TurnBlobs(Arc<Inner>);

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
    readers: Mutex<HashMap<String, Arc<BlobReader>>>,
    /// Blobs the turn finished, to make durable before its record.
    created: Mutex<Vec<BlobId>>,
}

struct Slot {
    /// None while a write is in flight.
    writer: Option<BlobWriter>,
    /// The scrubber, and how many secret values it matches.
    scrub: Option<(StreamScrubber<'static>, usize)>,
}

impl TurnBlobs {
    pub(crate) fn new(
        store: Arc<BlobStore>,
        space: Space,
        env: Env,
        sealer: Arc<Sealer>,
        fx_state: SecretSource,
        limit: u64,
    ) -> TurnBlobs {
        let lease = store.leases().take("turn");
        TurnBlobs(Arc::new(Inner {
            store,
            space,
            env,
            sealer,
            secrets: fx_state,
            lease,
            limit,
            next: AtomicU64::new(0),
            writers: Mutex::new(HashMap::new()),
            readers: Mutex::new(HashMap::new()),
            created: Mutex::new(Vec::new()),
        }))
    }

    /// The secret values of a turn's effect state, for its blob host.
    pub(crate) fn secrets_of(state: Arc<crate::effects::TurnFx>) -> SecretSource {
        Arc::new(move || {
            let s: std::sync::MutexGuard<'_, FxState> = lock(&state.state);
            s.secrets.clone()
        })
    }

    /// Names every blob the turn finished durably (ADR 0117 §4); called
    /// before the turn's record is appended.
    pub(crate) async fn ensure_durable(&self) -> Result<(), BlobError> {
        let ids = lock(&self.0.created).clone();
        if ids.is_empty() {
            return Ok(());
        }
        self.0.store.ensure_durable(&self.0.space, &ids).await
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
        BlobError::TooLarge { .. } => BlobHostError::TooLarge,
        BlobError::NotFound(id) => {
            kronik_metrics::inc("kronik_blob_missing_total", &[]);
            BlobHostError::Missing(format!("blob {id} is not in the blob store"))
        }
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
        if let Some(reader) = lock(&self.readers).get(&blob.hash) {
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
        lock(&self.readers).insert(blob.hash.clone(), reader.clone());
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
            let reader = inner.reader(&blob).await?;
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
                Some(subject) => {
                    let entropy = inner.env.entropy.clone();
                    let fill = move |bytes: &mut [u8]| entropy.fill(bytes);
                    Some(
                        inner
                            .sealer
                            .blob_keys(subject, &fill, inner.env.clock.wall_ms())
                            .map_err(|e| match e {
                                kronik_privacy::PrivacyError::KeyMissing(s) => {
                                    BlobHostError::KeyMissing(s)
                                }
                                other => BlobHostError::Host(other.to_string()),
                            })?,
                    )
                }
            };
            let writer = inner
                .store
                .writer(inner.space.clone(), keys, inner.limit, inner.lease.clone())
                .await
                .map_err(host_error)?;
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
                let tail = scrubber.finish().map_err(scrub_error)?;
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
        );
        (blobs, store)
    }

    fn secret(name: &str, value: &[u8]) -> (String, Arc<zeroize::Zeroizing<Vec<u8>>>) {
        (
            name.into(),
            Arc::new(zeroize::Zeroizing::new(value.to_vec())),
        )
    }

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
