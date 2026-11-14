//! The host side of `kronik:actor/blobs` (M25/M26, ADR 0121,
//! docs/design/m25-streaming-bodies.md §5).
//!
//! The rules live here, so production and replay apply the same ones: the
//! turn's references `T` (ADR 0119 §2), the 1 MiB limit of one call, the
//! bytes a turn may create (`TurnLimits::blob_bytes`) and the bytes it may
//! move (fuel × [`BLOB_BYTES_PER_FUEL`]). Storage is behind [`BlobHost`],
//! which the scheduler and the fork engine implement. Without a blob host
//! (a node with blobs off, `describe`), every function traps with
//! `NOT_IMPLEMENTED`. `put`, `retain` and `release` arrive with M26.

use std::collections::BTreeMap;

use kronik_core::env::BoxFuture;
use kronik_proto::log::v1 as pb;
use wasmtime::component::Resource;
use wasmtime::{Trap, bail};

use super::TurnHost;
use super::bindings::kronik::actor::blobs as wit;
use super::bindings::kronik::actor::types::BlobRef;
use crate::turn::RunError;

/// The most data one `get`, `put` or `write` call moves.
pub const MAX_BLOB_CALL_BYTES: usize = 1 << 20;
/// Blob bytes a turn may move per unit of its fuel limit (ADR 0121 §4): host
/// calls are not metered by Wasm fuel, so this bounds a turn's disk I/O.
pub const BLOB_BYTES_PER_FUEL: u64 = 64;
/// The frame size of the blob format (`kronik_blob::format::FRAME_SIZE`):
/// a read is charged for every frame it touches, as the store reads and
/// checks whole frames.
pub const BLOB_FRAME_BYTES: u64 = 65_536;
/// The writers one turn may hold open at once: each holds a part file and
/// up to a frame of data. Constructing another traps; finished and dropped
/// writers do not count.
pub const MAX_OPEN_WRITERS: usize = 64;

/// The bytes a read of `blob_size` bytes at `offset`, `len` bytes long,
/// is charged: every frame it touches, whole.
pub fn read_charge(blob_size: u64, offset: u64, len: u32) -> u64 {
    let end = blob_size.min(offset.saturating_add(u64::from(len)));
    if end <= offset {
        return 0;
    }
    ((end - 1) / BLOB_FRAME_BYTES - offset / BLOB_FRAME_BYTES + 1) * BLOB_FRAME_BYTES
}

/// Why the blob host could not do what the turn asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobHostError {
    /// The blob belonged to an erased subject: `blob-error::erased`.
    Erased,
    /// A sealed blob's key is not in this node's keystore: the turn is
    /// abandoned (`KEYSTORE_INCOMPLETE`).
    KeyMissing(String),
    /// The blob store is below its disk reserve or full: the turn attempt
    /// is abandoned without a record and runs again later (ADR 0117 §9).
    StoreFull(String),
    /// The blob would pass its size limit, for instance once secrets are
    /// scrubbed from it: `blob-error::quota-exceeded`.
    TooLarge,
    /// A committed reference's bytes are not in the store (`BLOB_MISSING`):
    /// the turn fails.
    Missing(String),
    /// The blob store's disk failed (an I/O error, a failed sync): what is
    /// durable there is unknown, so the node stops, as for a failure of its
    /// log, and the restart runs the turn again.
    Io(String),
    /// A host failure (a missing or damaged blob, I/O): the turn is
    /// abandoned without a record.
    Host(String),
}

/// The blob store as one turn sees it. The scheduler's implementation
/// writes to main's store or a fork's space and keeps the turn's lease.
pub trait BlobHost: Send + Sync {
    /// Up to `len` bytes of `blob` from `offset`: fewer only at its end.
    fn read(
        &self,
        blob: &pb::BlobRef,
        offset: u64,
        len: u32,
    ) -> BoxFuture<'static, Result<Vec<u8>, BlobHostError>>;
    /// Starts a blob of `subject`; returns the writer's id.
    fn create(&self, subject: Option<String>) -> BoxFuture<'static, Result<u64, BlobHostError>>;
    /// Appends to writer `writer`.
    fn write(&self, writer: u64, chunk: Vec<u8>) -> BoxFuture<'static, Result<(), BlobHostError>>;
    /// Ends writer `writer` and names its blob: a complete reference.
    fn finish(&self, writer: u64) -> BoxFuture<'static, Result<pb::BlobRef, BlobHostError>>;
    /// Drops an unfinished writer and its bytes.
    fn discard(&self, writer: u64);
    /// How many secret values the turn revealed were replaced by their
    /// placeholders in writer `writer`'s bytes (§5.2); after `finish`, the
    /// final count, readable until the turn ends. A `wasi:http` request body
    /// spooled into a blob warns the guest with it (§7.6).
    fn replaced(&self, _writer: u64) -> u64 {
        0
    }
}

/// The host's state of a guest's `writer` resource.
pub struct GuestWriter {
    id: u64,
}

/// The turn's blob state.
#[derive(Default)]
pub(crate) struct TurnBlobs {
    /// `T`: every reference the turn may use, complete, by (hash, size).
    refs: BTreeMap<(String, u64), pb::BlobRef>,
    /// Ids of writers not yet finished or dropped, a `wasi:http` request
    /// body's spool writer included.
    pub(super) open: Vec<u64>,
    /// Bytes `get` and `write` moved, against fuel × 64.
    moved: u64,
    /// Bytes the turn wrote into blobs, against `TurnLimits::blob_bytes`.
    pub(super) created: u64,
}

impl TurnBlobs {
    /// Adds a reference that entered the turn (its input, a fetch
    /// response, a finished writer) to `T`.
    pub(crate) fn admit(&mut self, blob: pb::BlobRef) {
        self.refs.insert((blob.hash.clone(), blob.size), blob);
    }

    /// The complete reference of a guest's `blob-ref`, when the turn may use
    /// it.
    pub(crate) fn complete(&self, blob: &BlobRef) -> Option<pb::BlobRef> {
        self.refs.get(&(blob.hash.clone(), blob.size)).cloned()
    }

    /// The writers still open, which the turn's end discards.
    pub(crate) fn take_open(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.open)
    }
}

/// The text a trap carries when a guest uses a reference it may not; the
/// turn's outcome code becomes `BLOB_NOT_HELD`.
pub(crate) fn not_held(blob: &BlobRef) -> String {
    format!(
        "BLOB_NOT_HELD: the turn neither holds nor received the blob {} ({} bytes)",
        blob.hash, blob.size
    )
}

/// The guest's view of a complete reference.
pub(crate) fn to_wit(blob: &pb::BlobRef) -> BlobRef {
    BlobRef {
        hash: blob.hash.clone(),
        size: blob.size,
    }
}

impl TurnHost {
    fn blob_host(&self, what: &str) -> wasmtime::Result<std::sync::Arc<dyn BlobHost>> {
        self.deny_in_describe("blobs")?;
        match &self.blobs {
            Some(host) => Ok(host.clone()),
            None => bail!("NOT_IMPLEMENTED: {what} is not available in this turn"),
        }
    }

    /// Counts `bytes` against the turn's blob I/O budget; past it the turn
    /// runs out of fuel.
    pub(super) fn charge_blob_bytes(&mut self, bytes: u64) -> wasmtime::Result<()> {
        let budget = self.limits.fuel.saturating_mul(BLOB_BYTES_PER_FUEL);
        self.blob_state.moved = self.blob_state.moved.saturating_add(bytes);
        if self.blob_state.moved > budget {
            return Err(wasmtime::Error::from(Trap::OutOfFuel));
        }
        Ok(())
    }

    /// A storage failure that is not guest-visible.
    pub(super) fn blob_failure(&mut self, error: BlobHostError) -> wasmtime::Error {
        match error {
            BlobHostError::Erased => {
                self.host_failure("an erased blob where nothing was read".into())
            }
            BlobHostError::KeyMissing(subject) => {
                self.fatal = Some(RunError::KeyMissing(subject.clone()));
                wasmtime::format_err!("KEYSTORE_INCOMPLETE: a blob of subject {subject}")
            }
            BlobHostError::StoreFull(message) => {
                self.fatal = Some(RunError::BlobStoreFull(message.clone()));
                wasmtime::format_err!("BLOB_STORE_FULL: {message}")
            }
            BlobHostError::Missing(message) => {
                self.fatal = Some(RunError::BlobMissing(message.clone()));
                wasmtime::format_err!("BLOB_MISSING: {message}")
            }
            BlobHostError::TooLarge => {
                self.host_failure("a blob too large where nothing was written".into())
            }
            BlobHostError::Io(message) => {
                self.fatal = Some(RunError::BlobIo(message.clone()));
                wasmtime::format_err!("the blob store failed: {message}")
            }
            BlobHostError::Host(message) => self.host_failure(message),
        }
    }

    fn writer_id(&self, writer: &Resource<GuestWriter>) -> wasmtime::Result<u64> {
        Ok(self.table.get(writer)?.id)
    }
}

fn invalid(message: String) -> wit::BlobError {
    wit::BlobError::Invalid(message)
}

impl wit::Host for TurnHost {
    async fn get(
        &mut self,
        blob: BlobRef,
        offset: u64,
        len: u32,
    ) -> wasmtime::Result<Result<Vec<u8>, wit::BlobError>> {
        let host = self.blob_host("blobs.get")?;
        if len == 0 || len as usize > MAX_BLOB_CALL_BYTES {
            return Ok(Err(invalid(format!(
                "get reads 1 to {MAX_BLOB_CALL_BYTES} bytes, not {len}"
            ))));
        }
        let Some(full) = self.blob_state.complete(&blob) else {
            return Ok(Err(wit::BlobError::NotHeld));
        };
        self.charge_blob_bytes(read_charge(full.size, offset, len))?;
        if offset >= full.size {
            return Ok(Ok(Vec::new()));
        }
        match host.read(&full, offset, len).await {
            Ok(bytes) => Ok(Ok(bytes)),
            Err(BlobHostError::Erased) => Ok(Err(wit::BlobError::Erased)),
            Err(error) => Err(self.blob_failure(error)),
        }
    }

    async fn put(&mut self, _bytes: Vec<u8>) -> wasmtime::Result<Result<BlobRef, wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.put is not available yet")
    }

    async fn retain(&mut self, _blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.retain is not available yet")
    }

    async fn release(&mut self, _blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.deny_in_describe("blobs")?;
        bail!("NOT_IMPLEMENTED: blobs.release is not available yet")
    }
}

impl wit::HostWriter for TurnHost {
    async fn new(&mut self) -> wasmtime::Result<Resource<GuestWriter>> {
        let host = self.blob_host("blobs.writer")?;
        if self.blob_state.open.len() >= MAX_OPEN_WRITERS {
            bail!(
                "too many open blob writers: a turn holds at most {MAX_OPEN_WRITERS} at once \
                 (finish or drop one first)"
            );
        }
        let id = match host.create(self.subject.clone()).await {
            Ok(id) => id,
            Err(error) => return Err(self.blob_failure(error)),
        };
        self.blob_state.open.push(id);
        Ok(self.table.push(GuestWriter { id })?)
    }

    async fn write(
        &mut self,
        writer: Resource<GuestWriter>,
        chunk: Vec<u8>,
    ) -> wasmtime::Result<Result<(), wit::BlobError>> {
        let host = self.blob_host("blobs.writer")?;
        let id = self.writer_id(&writer)?;
        if !self.blob_state.open.contains(&id) {
            return Ok(Err(invalid("the writer is finished".into())));
        }
        if chunk.len() > MAX_BLOB_CALL_BYTES {
            return Ok(Err(invalid(format!(
                "write takes at most {MAX_BLOB_CALL_BYTES} bytes, not {}",
                chunk.len()
            ))));
        }
        let created = self.blob_state.created.saturating_add(chunk.len() as u64);
        if created > self.limits.blob_bytes {
            return Ok(Err(wit::BlobError::QuotaExceeded));
        }
        self.charge_blob_bytes(chunk.len() as u64)?;
        self.blob_state.created = created;
        match host.write(id, chunk).await {
            Ok(()) => Ok(Ok(())),
            Err(BlobHostError::Erased) => Ok(Err(wit::BlobError::Erased)),
            Err(BlobHostError::TooLarge) => Ok(Err(wit::BlobError::QuotaExceeded)),
            Err(error) => Err(self.blob_failure(error)),
        }
    }

    async fn finish(
        &mut self,
        writer: Resource<GuestWriter>,
    ) -> wasmtime::Result<Result<BlobRef, wit::BlobError>> {
        let host = self.blob_host("blobs.writer")?;
        let id = self.writer_id(&writer)?;
        if !self.blob_state.open.contains(&id) {
            return Ok(Err(invalid("the writer is finished".into())));
        }
        self.blob_state.open.retain(|open| *open != id);
        match host.finish(id).await {
            Ok(blob) => {
                let wit_ref = to_wit(&blob);
                self.blob_state.admit(blob);
                Ok(Ok(wit_ref))
            }
            Err(BlobHostError::Erased) => Ok(Err(wit::BlobError::Erased)),
            Err(BlobHostError::TooLarge) => Ok(Err(wit::BlobError::QuotaExceeded)),
            Err(error) => Err(self.blob_failure(error)),
        }
    }

    async fn drop(&mut self, writer: Resource<GuestWriter>) -> wasmtime::Result<()> {
        let id = self.table.delete(writer)?.id;
        if self.blob_state.open.contains(&id) {
            self.blob_state.open.retain(|open| *open != id);
            if let Some(host) = &self.blobs {
                host.discard(id);
            }
        }
        Ok(())
    }
}
