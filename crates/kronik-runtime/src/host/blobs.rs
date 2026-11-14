//! The host side of `kronik:actor/blobs` (M25/M26, ADR 0121,
//! docs/design/m25-streaming-bodies.md §5).
//!
//! The rules live here, so production and replay apply the same ones: the
//! turn's references `T` (ADR 0119 §2), the 1 MiB limit of one call, the
//! bytes a turn may create (`TurnLimits::blob_bytes`) and the bytes it may
//! move (fuel × [`BLOB_BYTES_PER_FUEL`]). Storage is behind [`BlobHost`],
//! which the scheduler and the fork engine implement. Without a blob host
//! (a node with blobs off, `describe`), every function traps with
//! `NOT_IMPLEMENTED`. M26 adds what an actor holds: `put`, `retain` and
//! `release` buffer net hold changes that the turn's record carries
//! (`TurnRecord.blob_refs`), within `blob_bytes_per_actor`.

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
/// The hold changes one turn may make (M26 §3): its record carries one
/// operation for each.
pub const MAX_HOLD_CHANGES: usize = 1024;
/// The references one message may carry (M26 §3).
pub const MAX_MESSAGE_BLOBS: usize = 256;

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
    /// The complete reference of `hash` when the turn's actor held it when
    /// the turn started (M26 §2): held references are in `T`.
    fn held(&self, _hash: &str) -> Result<Option<pb::BlobRef>, BlobHostError> {
        Ok(None)
    }
    /// The bytes charged to the actor when the turn started, for its quota
    /// (ADR 0117 §8, ADR 0119 as amended 2026-11-14): the distinct blobs it
    /// holds, and those its earlier turns keep in rows: its timers, the
    /// messages and compensations it sent that wait in a mailbox, the dead
    /// letters of its messages and timers.
    fn charged_bytes(&self) -> Result<u64, BlobHostError> {
        Ok(0)
    }
    /// Whether a row of the actor's earlier turns (a timer, a queued message
    /// or compensation, a dead letter) carried `hash` when the turn started:
    /// it is charged to the actor without a hold.
    fn charged_by_pin(&self, _hash: &str) -> Result<bool, BlobHostError> {
        Ok(false)
    }
    /// Whether `hash`'s subject was erased before the actor's last turn: the
    /// blob then counts for nothing in its quota, as in
    /// [`BlobHost::charged_bytes`] (ADR 0119 as amended 2026-11-14).
    fn erased_for_charge(&self, _hash: &str) -> Result<bool, BlobHostError> {
        Ok(false)
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
    /// Whether the actor held a blob when the turn started, by hash, as
    /// the blob host answered (looked up when first needed).
    held_start: BTreeMap<String, Option<pb::BlobRef>>,
    /// The bytes charged to the actor when the turn started, once asked.
    charged_bytes_start: Option<u64>,
    /// Whether a row of the actor's earlier turns carried a blob when the
    /// turn started, by hash, as the blob host answered.
    pinned_start: BTreeMap<String, bool>,
    /// Whether a blob counts for nothing in the actor's quota (its subject
    /// was erased before the actor's last turn), by hash, as the blob host
    /// answered.
    erased_start: BTreeMap<String, bool>,
    /// The blobs this turn's timers, sent messages and compensations carry:
    /// charged to the actor once the turn commits.
    sent: BTreeMap<String, pb::BlobRef>,
    /// The blobs whose hold this turn changed: their reference, and
    /// whether the actor holds them now.
    holds: BTreeMap<String, (pb::BlobRef, bool)>,
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

    /// Whether the actor holds `hash` now, after this turn's operations so
    /// far; `None` when the turn did not change it (its start decides).
    fn held_now(&self, hash: &str) -> Option<bool> {
        self.holds.get(hash).map(|(_, now)| *now)
    }

    /// The hold changes that differ from the turn's start.
    fn changes(&self) -> usize {
        self.holds
            .iter()
            .filter(|(hash, (_, now))| {
                let start = self.held_start.get(*hash).is_some_and(Option::is_some);
                *now != start
            })
            .count()
    }

    /// The net hold operations of the turn (M26 §3): `RETAIN` for what it
    /// holds now and did not at its start, `RELEASE` for the reverse,
    /// sorted by identity.
    pub(crate) fn ops(&self) -> Vec<pb::BlobRefOp> {
        self.holds
            .iter()
            .filter_map(|(hash, (blob, now))| {
                let start = self.held_start.get(hash).is_some_and(Option::is_some);
                (*now != start).then(|| pb::BlobRefOp {
                    kind: if *now {
                        pb::blob_ref_op::Kind::Retain as i32
                    } else {
                        pb::blob_ref_op::Kind::Release as i32
                    },
                    blob: Some(blob.clone()),
                })
            })
            .collect()
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

    /// Whether the actor held `hash` when the turn started, and its
    /// complete reference then; asked of the blob host once per blob.
    fn held_at_start(&mut self, hash: &str) -> wasmtime::Result<Option<pb::BlobRef>> {
        if let Some(known) = self.blob_state.held_start.get(hash) {
            return Ok(known.clone());
        }
        let answer = match &self.blobs {
            Some(host) => host.held(hash),
            None => Ok(None),
        };
        let held = answer.map_err(|error| self.blob_failure(error))?;
        self.blob_state
            .held_start
            .insert(hash.to_owned(), held.clone());
        Ok(held)
    }

    /// The complete reference of a guest's `blob-ref` when it is in `T`:
    /// it entered the turn, or the actor held it when the turn started
    /// (then it joins `T`).
    pub(crate) fn complete_ref(&mut self, blob: &BlobRef) -> wasmtime::Result<Option<pb::BlobRef>> {
        if let Some(full) = self.blob_state.complete(blob) {
            return Ok(Some(full));
        }
        if self.blobs.is_none() {
            return Ok(None);
        }
        Ok(match self.held_at_start(&blob.hash)? {
            Some(full) if full.size == blob.size => {
                self.blob_state.admit(full.clone());
                Some(full)
            }
            _ => None,
        })
    }

    /// Whether the actor holds `hash` now.
    fn holds_now(&mut self, hash: &str) -> wasmtime::Result<bool> {
        if let Some(now) = self.blob_state.held_now(hash) {
            return Ok(now);
        }
        Ok(self.held_at_start(hash)?.is_some())
    }

    /// Whether a row of the actor's earlier turns carried `hash` when the
    /// turn started; asked of the blob host once per blob.
    fn pinned_at_start(&mut self, hash: &str) -> wasmtime::Result<bool> {
        if let Some(known) = self.blob_state.pinned_start.get(hash) {
            return Ok(*known);
        }
        let answer = match &self.blobs {
            Some(host) => host.charged_by_pin(hash),
            None => Ok(false),
        };
        let pinned = answer.map_err(|error| self.blob_failure(error))?;
        self.blob_state.pinned_start.insert(hash.to_owned(), pinned);
        Ok(pinned)
    }

    /// The bytes `blob` adds to the actor's quota: none when its subject was
    /// erased before the actor's last turn, which the actor cannot release
    /// any more; asked of the blob host once per blob.
    fn charge_of(&mut self, hash: &str, size: u64) -> wasmtime::Result<u64> {
        let erased = match self.blob_state.erased_start.get(hash) {
            Some(known) => *known,
            None => {
                let answer = match &self.blobs {
                    Some(host) => host.erased_for_charge(hash),
                    None => Ok(false),
                };
                let erased = answer.map_err(|error| self.blob_failure(error))?;
                self.blob_state.erased_start.insert(hash.to_owned(), erased);
                erased
            }
        };
        Ok(if erased { 0 } else { size })
    }

    /// Whether `hash` was charged to the actor when the turn started.
    fn charged_at_start(&mut self, hash: &str) -> wasmtime::Result<bool> {
        Ok(self.held_at_start(hash)?.is_some() || self.pinned_at_start(hash)?)
    }

    /// The bytes charged to the actor after the turn's changes so far and
    /// `extra`: what was charged at the turn's start, plus each blob the
    /// turn retained, put, or put into a timer, message or compensation that
    /// was not charged then, minus each hold it released that nothing else
    /// of the actor keeps. Each blob counts once.
    fn would_charge(&mut self, extra: &[pb::BlobRef]) -> wasmtime::Result<u64> {
        let start = match self.blob_state.charged_bytes_start {
            Some(bytes) => bytes,
            None => {
                let answer = match &self.blobs {
                    Some(host) => host.charged_bytes(),
                    None => Ok(0),
                };
                let bytes = answer.map_err(|error| self.blob_failure(error))?;
                self.blob_state.charged_bytes_start = Some(bytes);
                bytes
            }
        };
        // What the turn charges now: held now, or carried by its edges.
        let mut now: BTreeMap<String, u64> = BTreeMap::new();
        let mut released: Vec<(String, u64)> = Vec::new();
        for (hash, (blob, held)) in &self.blob_state.holds {
            if *held {
                now.insert(hash.clone(), blob.size);
            } else {
                released.push((hash.clone(), blob.size));
            }
        }
        for (hash, blob) in &self.blob_state.sent {
            now.insert(hash.clone(), blob.size);
        }
        for blob in extra {
            now.insert(blob.hash.clone(), blob.size);
        }
        // A blob whose subject was erased before the actor's last turn adds
        // nothing, and its release takes nothing off: `start` left it out.
        let mut total = start;
        for (hash, size) in now.clone() {
            if !self.charged_at_start(&hash)? {
                total = total.saturating_add(self.charge_of(&hash, size)?);
            }
        }
        for (hash, size) in released {
            if now.contains_key(&hash) {
                continue;
            }
            if self.held_at_start(&hash)?.is_some() && !self.pinned_at_start(&hash)? {
                total = total.saturating_sub(self.charge_of(&hash, size)?);
            }
        }
        Ok(total)
    }

    /// Charges the blobs a timer, sent message or compensation of the turn
    /// carries to the actor (ADR 0119 as amended 2026-11-14): past
    /// `blob_bytes_per_actor` the turn traps with `BLOB_QUOTA_EXCEEDED`, as
    /// these calls have no error to answer with.
    pub(crate) fn charge_edge(&mut self, blobs: &[pb::BlobRef]) -> wasmtime::Result<()> {
        if blobs.is_empty() {
            return Ok(());
        }
        let total = self.would_charge(blobs)?;
        if total > self.limits.blob_bytes {
            bail!(
                "BLOB_QUOTA_EXCEEDED: the actor would keep {total} blob bytes in its holds, \
                 timers and messages, more than its quota of {} (blob_bytes_per_actor)",
                self.limits.blob_bytes
            );
        }
        for blob in blobs {
            self.blob_state
                .sent
                .entry(blob.hash.clone())
                .or_insert_with(|| blob.clone());
        }
        Ok(())
    }

    /// Holds `blob`, which is in `T`: `quota-exceeded` past
    /// `blob_bytes_per_actor`, and an error past [`MAX_HOLD_CHANGES`].
    fn hold(&mut self, blob: pb::BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        if self.holds_now(&blob.hash)? {
            return Ok(Ok(()));
        }
        let was = self.held_at_start(&blob.hash)?.is_some();
        if !was && self.would_charge(std::slice::from_ref(&blob))? > self.limits.blob_bytes {
            return Ok(Err(wit::BlobError::QuotaExceeded));
        }
        if !was && self.blob_state.changes() >= MAX_HOLD_CHANGES {
            return Ok(Err(invalid(format!(
                "a turn changes at most {MAX_HOLD_CHANGES} holds"
            ))));
        }
        self.blob_state
            .holds
            .insert(blob.hash.clone(), (blob, true));
        Ok(Ok(()))
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
        let Some(full) = self.complete_ref(&blob)? else {
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

    async fn put(&mut self, bytes: Vec<u8>) -> wasmtime::Result<Result<BlobRef, wit::BlobError>> {
        let host = self.blob_host("blobs.put")?;
        if bytes.len() > MAX_BLOB_CALL_BYTES {
            return Ok(Err(invalid(format!(
                "put stores at most {MAX_BLOB_CALL_BYTES} bytes, not {}",
                bytes.len()
            ))));
        }
        let created = self.blob_state.created.saturating_add(bytes.len() as u64);
        if created > self.limits.blob_bytes {
            return Ok(Err(wit::BlobError::QuotaExceeded));
        }
        // The holds' quota is checked with the blob's identity once it is
        // written (`hold`): a blob the actor holds already adds nothing.
        if self.blob_state.open.len() >= MAX_OPEN_WRITERS {
            bail!(
                "too many open blob writers: a turn holds at most {MAX_OPEN_WRITERS} at once \
                 (finish or drop one first)"
            );
        }
        self.charge_blob_bytes(bytes.len() as u64)?;
        self.blob_state.created = created;
        let id = match host.create(self.subject.clone()).await {
            Ok(id) => id,
            Err(error) => return Err(self.blob_failure(error)),
        };
        self.blob_state.open.push(id);
        let written = host.write(id, bytes).await;
        let blob = match written {
            Ok(()) => {
                self.blob_state.open.retain(|open| *open != id);
                host.finish(id).await
            }
            Err(error) => {
                self.blob_state.open.retain(|open| *open != id);
                host.discard(id);
                Err(error)
            }
        };
        let blob = match blob {
            Ok(blob) => blob,
            Err(BlobHostError::Erased) => return Ok(Err(wit::BlobError::Erased)),
            Err(BlobHostError::TooLarge) => return Ok(Err(wit::BlobError::QuotaExceeded)),
            Err(error) => return Err(self.blob_failure(error)),
        };
        // `put` holds what it stored (M26 §3). Over the quota, the blob is
        // neither held nor in `T`: the collector takes it.
        let wit_ref = to_wit(&blob);
        match self.hold(blob.clone())? {
            Ok(()) => {
                self.blob_state.admit(blob);
                Ok(Ok(wit_ref))
            }
            Err(error) => Ok(Err(error)),
        }
    }

    async fn retain(&mut self, blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.blob_host("blobs.retain")?;
        let Some(full) = self.complete_ref(&blob)? else {
            return Ok(Err(wit::BlobError::NotHeld));
        };
        self.hold(full)
    }

    async fn release(&mut self, blob: BlobRef) -> wasmtime::Result<Result<(), wit::BlobError>> {
        self.blob_host("blobs.release")?;
        // Only the actor's own hold: at the turn's start, or retained since.
        let Some(full) = self.complete_ref(&blob)? else {
            return Ok(Err(wit::BlobError::NotHeld));
        };
        if !self.holds_now(&full.hash)? {
            return Ok(Err(wit::BlobError::NotHeld));
        }
        let was = self.held_at_start(&full.hash)?.is_some();
        if was && self.blob_state.changes() >= MAX_HOLD_CHANGES {
            return Ok(Err(invalid(format!(
                "a turn changes at most {MAX_HOLD_CHANGES} holds"
            ))));
        }
        // `T` only grows: a released blob stays readable in this turn.
        self.blob_state
            .holds
            .insert(full.hash.clone(), (full, false));
        Ok(Ok(()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(n: u8) -> pb::BlobRef {
        pb::BlobRef {
            hash: format!("b3:{}", format!("{n:02x}").repeat(32)),
            size: u64::from(n),
            subject: None,
            key_version: 0,
        }
    }

    /// The record gets the net change of each hold against the turn's
    /// start, sorted by identity: a hold taken and let go in the turn, or
    /// let go and taken again, is no operation.
    #[test]
    fn the_record_gets_the_net_hold_changes() {
        let mut state = TurnBlobs::default();
        // Held at the start: 1 and 2; not: 3, 4 and 5.
        for n in [1, 2] {
            state.held_start.insert(blob(n).hash, Some(blob(n)));
        }
        for n in [3, 4, 5] {
            state.held_start.insert(blob(n).hash, None);
        }
        // 1 released; 2 released and retained again; 3 retained; 4
        // retained and released; 5 untouched.
        state.holds.insert(blob(1).hash, (blob(1), false));
        state.holds.insert(blob(2).hash, (blob(2), true));
        state.holds.insert(blob(3).hash, (blob(3), true));
        state.holds.insert(blob(4).hash, (blob(4), false));
        assert_eq!(state.changes(), 2);
        let ops: Vec<(i32, String)> = state
            .ops()
            .into_iter()
            .map(|op| (op.kind, op.blob.unwrap().hash))
            .collect();
        assert_eq!(
            ops,
            [
                (pb::blob_ref_op::Kind::Release as i32, blob(1).hash),
                (pb::blob_ref_op::Kind::Retain as i32, blob(3).hash),
            ]
        );
    }
}
