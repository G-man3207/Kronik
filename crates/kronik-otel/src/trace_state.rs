//! Versioned causal metadata, selected only by a durable export cursor.
//!
//! Two generation files and a scratch file bound file count. Frames share the
//! log's byte budget; oversized metadata stalls traces rather than being dropped.
//! Variable causal keys still make the entry cap distinct from a heap bound.
//! Normal deltas cost changed keys; compaction is amortized by appended bytes.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use kronik_core::env::{Env, File, OpenMode};
use kronik_core::ids::{Lsn, hex};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

use crate::spans::{IdKey, Kept, OpenTurns};

const MAGIC: &[u8; 16] = b"KRONIK-TRACE-V1\0";
const HEADER: u64 = 24;
const FRAME_HEADER: u64 = 40;
const FORMAT: &str = "kronik.trace-state/v1";
const MAX_FRAME_BYTES: usize = kronik_log::MAX_RECORD as usize;
const MAX_SELECTED_BYTES: u64 = HEADER + 2 * (FRAME_HEADER + MAX_FRAME_BYTES as u64);

#[derive(Debug)]
struct LimitExceeded;

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("trace metadata exceeds the log record byte budget")
    }
}

impl std::error::Error for LimitExceeded {}

fn limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, LimitExceeded)
}

pub(crate) struct LimitedVec {
    bytes: Vec<u8>,
    limit: usize,
}

impl LimitedVec {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for LimitedVec {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(limit_error());
        }
        let end = self.bytes.len() + bytes.len();
        if end > self.bytes.capacity() {
            let capacity = end
                .max(self.bytes.capacity().saturating_mul(2).max(64))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let mut writer = LimitedVec {
        bytes: Vec::new(),
        limit: MAX_FRAME_BYTES,
    };
    serde_json::to_writer(&mut writer, value).map_err(io::Error::from)?;
    Ok(writer.bytes)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    format: String,
    slot: u8,
    generation: u64,
    end: u64,
    lsn: Lsn,
    hash: String,
}

type DeltaChange = (Vec<u8>, Option<[u8; 16]>, Option<Kept>);

#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Frame {
    Snapshot {
        lsn: Lsn,
        next: u64,
        open: Vec<(Vec<u8>, [u8; 16])>,
        kept: Vec<(Vec<u8>, Kept)>,
    },
    Delta {
        base_lsn: Lsn,
        lsn: Lsn,
        next: u64,
        changes: Vec<DeltaChange>,
    },
}

struct Entries<'a>(&'a OpenTurns, bool);
impl Serialize for Entries<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(if self.1 {
            self.0.traces.len()
        } else {
            self.0.kept.len()
        }))?;
        if self.1 {
            for entry in &self.0.traces {
                seq.serialize_element(&entry)?;
            }
        } else {
            for entry in &self.0.kept {
                seq.serialize_element(&entry)?;
            }
        }
        seq.end()
    }
}

struct Changes<'a>(&'a OpenTurns);
impl Serialize for Changes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.dirty.len()))?;
        for key in &self.0.dirty {
            seq.serialize_element(&(key, self.0.traces.get(key), self.0.kept.get(key)))?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct Snapshot<'a> {
    kind: &'static str,
    lsn: Lsn,
    next: u64,
    open: Entries<'a>,
    kept: Entries<'a>,
}

#[derive(Serialize)]
struct Delta<'a> {
    kind: &'static str,
    base_lsn: Lsn,
    lsn: Lsn,
    next: u64,
    changes: Changes<'a>,
}

struct Candidate {
    reference: Reference,
    json: serde_json::Value,
    file: Arc<dyn File>,
    snapshot_bytes: u64,
}

#[derive(Clone, Debug)]
struct Failure {
    source: Arc<io::Error>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl Failure {
    fn error(&self) -> io::Error {
        io::Error::new(self.source.kind(), self.clone())
    }
}

/// Stable metadata failure classification; ordinary I/O errors return `None`.
/// The original I/O error remains available through the error's source chain.
pub fn failure_code(error: &io::Error) -> Option<&'static str> {
    if error
        .get_ref()
        .is_some_and(|error| error.is::<LimitExceeded>())
    {
        return Some("trace_state_limit");
    }
    if error.get_ref().is_some_and(|error| error.is::<Failure>())
        || error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
    {
        Some("storage_sync")
    } else {
        None
    }
}

fn sync_error(source: io::Error) -> io::Error {
    Failure {
        source: Arc::new(source),
    }
    .error()
}

/// A metadata writer. `committed` is called only after export.json is durable.
/// Sync failures and EIO are fatal; ordinary I/O failures can be retried.
pub struct TraceState {
    env: Env,
    dir: PathBuf,
    selected: Option<Reference>,
    file: Option<Arc<dyn File>>,
    snapshot_bytes: u64,
    pending: Option<Candidate>,
    fresh: bool,
    failed: Option<Failure>,
}

fn path(dir: &Path, slot: u8) -> PathBuf {
    dir.join(format!("trace-state.{slot}"))
}

fn header(generation: u64) -> [u8; HEADER as usize] {
    let mut bytes = [0; HEADER as usize];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()..].copy_from_slice(&generation.to_le_bytes());
    bytes
}

fn checksum(generation: u64, offset: u64, previous: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(MAGIC);
    hash.update(&generation.to_le_bytes());
    hash.update(&offset.to_le_bytes());
    hash.update(previous);
    hash.update(&(payload.len() as u64).to_le_bytes());
    hash.update(payload);
    *hash.finalize().as_bytes()
}

fn hash_bytes(text: &str) -> io::Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid trace metadata hash"));
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(invalid_error)?;
    }
    Ok(bytes)
}

fn invalid_error(error: impl std::fmt::Display) -> io::Error {
    invalid(error.to_string())
}

async fn exact(file: &Arc<dyn File>, offset: u64, len: u64) -> io::Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(invalid_error)?;
    let bytes = file.read_at(offset, len).await?;
    if bytes.len() != len {
        return Err(invalid("truncated selected trace metadata"));
    }
    Ok(bytes)
}

fn key_valid(key: &[u8]) -> io::Result<()> {
    if !key.starts_with(b"kronik.causal.v1\0") {
        return Err(invalid("invalid trace metadata causal key"));
    }
    Ok(())
}

fn insert_kept(open: &mut OpenTurns, key: Vec<u8>, kept: Kept) -> io::Result<()> {
    key_valid(&key)?;
    if kept.seq >= open.next || (kept.children.is_empty() && !kept.caller) {
        return Err(invalid("invalid kept trace metadata"));
    }
    if open.order.insert(kept.seq, key.clone()).is_some() || open.kept.insert(key, kept).is_some() {
        return Err(invalid("duplicate kept trace metadata"));
    }
    Ok(())
}

fn apply(open: &mut OpenTurns, frame: Frame, previous_lsn: Option<Lsn>) -> io::Result<Lsn> {
    let lsn = match frame {
        Frame::Snapshot {
            lsn,
            next,
            open: entries,
            kept,
        } => {
            if previous_lsn.is_some() {
                return Err(invalid("snapshot after first trace metadata frame"));
            }
            open.next = next;
            if entries.len() > OpenTurns::CAP || kept.len() > OpenTurns::CAP {
                return Err(invalid("trace metadata limits exceeded"));
            }
            open.traces.reserve(entries.len());
            open.kept.reserve(kept.len());
            for (key, trace) in entries {
                key_valid(&key)?;
                if open.traces.insert(key, trace).is_some() {
                    return Err(invalid("duplicate open trace metadata"));
                }
            }
            for (key, entry) in kept {
                insert_kept(open, key, entry)?;
            }
            lsn
        }
        Frame::Delta {
            base_lsn,
            lsn,
            next,
            changes,
        } => {
            if previous_lsn != Some(base_lsn) || lsn < base_lsn || next < open.next {
                return Err(invalid("invalid trace metadata delta position"));
            }
            open.next = next;
            let mut seen = std::collections::HashSet::new();
            for (key, _, _) in &changes {
                key_valid(key)?;
                if !seen.insert(key.as_slice()) {
                    return Err(invalid("duplicate trace metadata delta key"));
                }
                open.traces.remove(key);
                if let Some(old) = open.kept.remove(key) {
                    open.order.remove(&old.seq);
                }
            }
            drop(seen);
            for (key, trace, kept) in changes {
                if let Some(trace) = trace {
                    if kept.is_some() {
                        open.traces.insert(key.clone(), trace);
                    } else {
                        open.traces.insert(key, trace);
                        continue;
                    }
                }
                if let Some(kept) = kept {
                    insert_kept(open, key, kept)?;
                }
            }
            lsn
        }
    };
    if open.traces.len() > OpenTurns::CAP
        || open.kept.len() > OpenTurns::CAP
        || open.next == u64::MAX
    {
        return Err(invalid("trace metadata limits exceeded"));
    }
    Ok(lsn)
}

type LegacyKept = (String, String, Vec<(u32, bool)>, bool);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    open: Vec<(String, String)>,
    kept: Vec<LegacyKept>,
}

fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid historical trace metadata hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(invalid_error))
        .collect()
}

fn legacy(value: &serde_json::Value, ids: IdKey) -> io::Result<OpenTurns> {
    let mut out = OpenTurns::new(ids);
    if value.is_null() {
        return Ok(out);
    }
    let legacy = if value.is_array() {
        Legacy {
            open: Vec::deserialize(value).map_err(invalid_error)?,
            kept: Vec::new(),
        }
    } else {
        Legacy::deserialize(value).map_err(invalid_error)?
    };
    for (key, trace) in legacy.open {
        let key = unhex(&key)?;
        key_valid(&key)?;
        let trace = unhex(&trace)?
            .try_into()
            .map_err(|_| invalid("invalid historical trace id"))?;
        if out.traces.insert(key, trace).is_some() {
            return Err(invalid("duplicate historical open turn"));
        }
    }
    for (key, trace, children, caller) in legacy.kept {
        let seq = out.next;
        out.next += 1;
        insert_kept(
            &mut out,
            unhex(&key)?,
            Kept {
                trace: unhex(&trace)?
                    .try_into()
                    .map_err(|_| invalid("invalid historical trace id"))?,
                children,
                caller,
                seq,
            },
        )?;
    }
    if out.len() > OpenTurns::CAP || out.kept() > OpenTurns::CAP {
        return Err(invalid("historical trace metadata limits exceeded"));
    }
    Ok(out)
}

/// Loads exactly the prefix selected by `state`, bound to the cursor's LSN.
/// Null and the two historical inline representations migrate on checkpoint.
/// The caller stabilizes any indeterminate export.json rename before loading.
pub async fn load(
    env: Env,
    data_dir: &Path,
    state: &serde_json::Value,
    lsn: Lsn,
    ids: IdKey,
) -> io::Result<(TraceState, OpenTurns)> {
    let mut store = TraceState {
        env,
        dir: data_dir.to_owned(),
        selected: None,
        file: None,
        snapshot_bytes: 0,
        pending: None,
        fresh: true,
        failed: None,
    };
    if state.is_null() || state.is_array() || state.get("open").is_some() {
        return Ok((store, legacy(state, ids)?));
    }
    let reference = Reference::deserialize(state).map_err(invalid_error)?;
    if reference.format != FORMAT
        || reference.slot > 1
        || reference.generation == 0
        || reference.end < HEADER + FRAME_HEADER
        || reference.lsn != lsn
    {
        return Err(invalid("invalid trace metadata reference"));
    }
    if reference.end > MAX_SELECTED_BYTES {
        return Err(limit_error());
    }
    let expected = hash_bytes(&reference.hash)?;
    let file = store
        .env
        .fs
        .open(path(data_dir, reference.slot), OpenMode::Read)
        .await?;
    if file.len().await? < reference.end
        || exact(&file, 0, HEADER).await? != header(reference.generation)
    {
        return Err(invalid("invalid selected trace metadata header or length"));
    }
    let mut open = OpenTurns::new(ids);
    let mut offset = HEADER;
    let mut previous = [0; 32];
    let mut previous_lsn = None;
    while offset < reference.end {
        if reference.end - offset < FRAME_HEADER {
            return Err(invalid("truncated trace metadata frame header"));
        }
        let prefix = exact(&file, offset, FRAME_HEADER).await?;
        let len = u64::from_le_bytes(prefix[..8].try_into().map_err(invalid_error)?);
        if len > MAX_FRAME_BYTES as u64 {
            return Err(limit_error());
        }
        let end = offset
            .checked_add(FRAME_HEADER)
            .and_then(|n| n.checked_add(len))
            .filter(|end| *end <= reference.end)
            .ok_or_else(|| invalid("invalid trace metadata frame length"))?;
        let payload = exact(&file, offset + FRAME_HEADER, len).await?;
        let hash = checksum(reference.generation, offset, &previous, &payload);
        if prefix[8..] != hash {
            return Err(invalid("trace metadata checksum mismatch"));
        }
        let frame = serde_json::from_slice(&payload).map_err(invalid_error)?;
        previous_lsn = Some(apply(&mut open, frame, previous_lsn)?);
        if offset == HEADER {
            store.snapshot_bytes = end - HEADER;
        }
        offset = end;
        previous = hash;
    }
    if previous != expected || previous_lsn != Some(lsn) {
        return Err(invalid("trace metadata reference hash or LSN mismatch"));
    }
    store.selected = Some(reference);
    // A reopened inode may have suffered a failed append sync. Read its selected
    // prefix, but write the next checkpoint to a new inode rather than resync it.
    Ok((store, open))
}

impl TraceState {
    /// Stages and syncs a candidate. Retries return that identical small
    /// reference until `committed`; callers freeze mutations while it is pending.
    pub async fn checkpoint(
        &mut self,
        open: &mut OpenTurns,
        lsn: Lsn,
    ) -> io::Result<serde_json::Value> {
        if let Some(failure) = &self.failed {
            return Err(failure.error());
        }
        if let Some(pending) = &self.pending {
            if pending.reference.lsn != lsn {
                return Err(invalid("trace metadata checkpoint already pending"));
            }
            return Ok(pending.json.clone());
        }
        if !self.fresh && self.selected.as_ref().is_some_and(|r| lsn < r.lsn) {
            return Err(invalid(
                "trace metadata checkpoint moved backwards without reset",
            ));
        }
        match self.stage(open, lsn).await {
            Ok(reference) => Ok(reference),
            Err(error) => {
                let failure = error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<Failure>())
                    .cloned();
                let failure = match failure {
                    Some(failure) => failure,
                    None if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) => {
                        Failure {
                            source: Arc::new(error),
                        }
                    }
                    None => return Err(error),
                };
                let error = failure.error();
                self.failed = Some(failure);
                Err(error)
            }
        }
    }

    async fn stage(&mut self, open: &OpenTurns, lsn: Lsn) -> io::Result<serde_json::Value> {
        let delta = if !self.fresh {
            match encode_frame(&Delta {
                kind: "Delta",
                base_lsn: self
                    .selected
                    .as_ref()
                    .ok_or_else(|| invalid("missing selected metadata"))?
                    .lsn,
                lsn,
                next: open.next,
                changes: Changes(open),
            }) {
                Ok(bytes) => Some(bytes),
                Err(error) if failure_code(&error) == Some("trace_state_limit") => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let compact = self.fresh
            || delta.is_none()
            || self.selected.as_ref().is_some_and(|r| {
                r.end - HEADER - self.snapshot_bytes
                    + delta.as_ref().map_or(0, |d| d.len() as u64 + FRAME_HEADER)
                    >= self.snapshot_bytes.max(64 * 1024)
            });
        let (slot, generation, offset, previous, file, payload) = if compact {
            drop(delta);
            let payload = encode_frame(&Snapshot {
                kind: "Snapshot",
                lsn,
                next: open.next,
                open: Entries(open, true),
                kept: Entries(open, false),
            })?;
            let slot = self.selected.as_ref().map_or(0, |r| 1 - r.slot);
            let generation = self
                .selected
                .as_ref()
                .map_or(Some(1), |r| r.generation.checked_add(1))
                .ok_or_else(|| invalid("trace metadata generation exhausted"))?;
            let scratch = self.dir.join("trace-state.tmp");
            match self.env.fs.remove_file(scratch.clone()).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let file = self.env.fs.open(scratch, OpenMode::ReadWriteCreate).await?;
            file.write_at(0, Bytes::copy_from_slice(&header(generation)))
                .await?;
            (slot, generation, HEADER, [0; 32], file, payload)
        } else {
            let reference = self
                .selected
                .as_ref()
                .ok_or_else(|| invalid("missing trace metadata reference"))?;
            let file = self
                .file
                .as_ref()
                .ok_or_else(|| invalid("missing trace metadata file"))?
                .clone();
            // Drop only the uncommitted suffix, never the selected prefix.
            file.set_len(reference.end).await?;
            (
                reference.slot,
                reference.generation,
                reference.end,
                hash_bytes(&reference.hash)?,
                file,
                delta.ok_or_else(|| invalid("missing trace metadata delta"))?,
            )
        };
        let hash = checksum(generation, offset, &previous, &payload);
        let end = offset
            .checked_add(FRAME_HEADER)
            .and_then(|n| n.checked_add(payload.len() as u64))
            .ok_or_else(|| invalid("trace metadata length overflow"))?;
        if end > MAX_SELECTED_BYTES {
            return Err(limit_error());
        }
        let mut frame = Vec::with_capacity(FRAME_HEADER as usize);
        frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        frame.extend_from_slice(&hash);
        file.write_at(offset, Bytes::from(frame)).await?;
        file.write_at(offset + FRAME_HEADER, Bytes::from(payload))
            .await?;
        file.sync_data().await.map_err(sync_error)?;
        if compact {
            self.env
                .fs
                .rename(self.dir.join("trace-state.tmp"), path(&self.dir, slot))
                .await?;
            self.env
                .fs
                .sync_dir(self.dir.clone())
                .await
                .map_err(sync_error)?;
        }
        let reference = Reference {
            format: FORMAT.into(),
            slot,
            generation,
            end,
            lsn,
            hash: hex(&hash),
        };
        let json = serde_json::to_value(&reference).map_err(invalid_error)?;
        self.pending = Some(Candidate {
            reference,
            json: json.clone(),
            file,
            snapshot_bytes: if compact {
                end - HEADER
            } else {
                self.snapshot_bytes
            },
        });
        Ok(json)
    }

    /// Acknowledges durable export.json publication, then clears dirty keys.
    pub fn committed(&mut self, open: &mut OpenTurns) {
        if let Some(pending) = self.pending.take() {
            self.selected = Some(pending.reference);
            self.file = Some(pending.file);
            self.snapshot_bytes = pending.snapshot_bytes;
            self.fresh = false;
            // HashSet iteration scans capacity: do not retain a giant old batch.
            open.dirty = Default::default();
        }
    }

    /// Forces a fresh generation for rewind. The caller must finish any pending
    /// cursor publication first; selected metadata remains intact until commit.
    pub fn reset(&mut self) {
        self.fresh = true;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use kronik_core::causal;
    use kronik_core::env::{BoxFuture, Fs};
    use kronik_core::ids::ActorRef;
    use kronik_proto::log::v1 as pb;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    const IDS: IdKey = IdKey([9; 32]);

    fn env() -> Env {
        Env::real(tokio::runtime::Handle::current())
    }

    fn call() -> pb::Input {
        pb::Input {
            kind: Some(pb::input::Kind::Message(pb::MessageInput {
                source: pb::MessageSource::Call as i32,
                ..Default::default()
            })),
        }
    }

    fn record(key: pb::CausalKey) -> pb::TurnRecord {
        pb::TurnRecord {
            causal_key: Some(key),
            actor: Some(ActorRef::parse("counter/a").unwrap().to_pb()),
            ..Default::default()
        }
    }

    async fn start(env: Env, dir: &Path) -> (TraceState, OpenTurns) {
        load(env, dir, &serde_json::Value::Null, 0, IDS)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn historical_inputs_migrate_once_and_preserve_causal_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let root = causal::root("historical".into());
        let actor = ActorRef::parse("counter/a").unwrap();
        let parent = causal::child(&root, &actor, 1);
        let late = causal::child(&parent, &actor, 3);
        let key = hex(&causal::encode(&parent));
        for value in [
            serde_json::json!([[key, hex(&[4; 16])]]),
            serde_json::json!({"open": [], "kept": [[key, hex(&[4; 16]), [[3, true], [5, false]], true]]}),
        ] {
            let (mut state, mut open) =
                load(env.clone(), dir.path(), &value, 7, IDS).await.unwrap();
            assert_eq!(open.trace(&late, Some(&call())), [4; 16]);
            let reference = state.checkpoint(&mut open, 7).await.unwrap();
            assert!(reference.to_string().len() < 250);
            state.committed(&mut open);
            let (_, restored) = load(env.clone(), dir.path(), &reference, 7, IDS)
                .await
                .unwrap();
            assert_eq!(restored.trace(&late, Some(&call())), [4; 16]);
            assert_eq!(
                restored.kept.get(&causal::encode(&parent)),
                open.kept.get(&causal::encode(&parent))
            );
        }
        for junk in [
            serde_json::json!("junk"),
            serde_json::json!({}),
            serde_json::json!([["xx", "yy"]]),
            serde_json::json!({"open": [], "kept": [], "unknown": 1}),
        ] {
            assert!(load(env.clone(), dir.path(), &junk, 7, IDS).await.is_err());
        }
    }

    #[tokio::test]
    async fn snapshot_delta_replay_preserves_callers_children_late_callees_and_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let (mut state, mut open) = start(env.clone(), dir.path()).await;
        let actor = ActorRef::parse("counter/a").unwrap();
        let root = causal::root("root".into());
        let callee = causal::child(&root, &actor, 3);
        open.begin(&root, None);
        let mut child = record(callee.clone());
        child.input = Some(call());
        child.messages.push(pb::OutboundMessage {
            ordinal: 5,
            ..Default::default()
        });
        open.commit(&child);
        assert!(open.kept[&causal::encode(&callee)].caller);
        let first = state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        let mut caller = record(root.clone());
        caller.effects.push(pb::EffectRecord {
            kind: "actor.call".into(),
            ordinal: 3,
            ..Default::default()
        });
        caller.compensations.push(pb::OutboundMessage {
            ordinal: 3,
            ..Default::default()
        });
        open.commit(&caller);
        let late_parent = causal::root("late".into());
        let mut timed_out = record(late_parent.clone());
        timed_out.effects.push(pb::EffectRecord {
            kind: "actor.call".into(),
            ordinal: 9,
            status: pb::EffectStatus::Timeout as i32,
            ..Default::default()
        });
        open.commit(&timed_out);
        let next = open.next;
        let second = state.checkpoint(&mut open, 2).await.unwrap();
        assert_eq!(first["generation"], second["generation"]);
        assert!(!open.dirty.is_empty());
        assert_eq!(state.checkpoint(&mut open, 2).await.unwrap(), second);
        assert!(state.checkpoint(&mut open, 3).await.is_err());
        let (_, before) = load(env.clone(), dir.path(), &first, 1, IDS).await.unwrap();
        assert!(before.kept[&causal::encode(&callee)].caller);
        state.committed(&mut open);
        assert!(open.dirty.is_empty());
        let (_, after) = load(env.clone(), dir.path(), &second, 2, IDS)
            .await
            .unwrap();
        assert_eq!(after.kept, open.kept);
        assert_eq!(after.order, open.order);
        assert_eq!(after.next, next);
        assert_eq!(after.traces, open.traces);
        let kept = &after.kept[&causal::encode(&callee)];
        assert!(!kept.caller);
        assert!(kept.children.contains(&(5, false)));
        assert!(
            kept.children
                .contains(&(causal::COMPENSATION_ORDINAL, false))
        );
        assert_eq!(
            after.trace(&causal::child(&late_parent, &actor, 9), Some(&call())),
            crate::spans::trace_id("late")
        );
        // A child commit settles only its producer; replay includes the deletion.
        let mut open = after;
        open.commit(&record(causal::child(&callee, &actor, 5)));
        open.commit(&record(causal::child(
            &callee,
            &actor,
            causal::COMPENSATION_ORDINAL,
        )));
        let third = state.checkpoint(&mut open, 3).await.unwrap();
        state.committed(&mut open);
        let (_, final_open) = load(env, dir.path(), &third, 3, IDS).await.unwrap();
        assert!(!final_open.kept.contains_key(&causal::encode(&callee)));
    }

    #[tokio::test]
    async fn mostly_unchanged_state_writes_only_batch_deltas_and_small_references() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let (mut state, mut open) = start(env.clone(), dir.path()).await;
        for i in 0..20_000 {
            open.begin(&causal::root(format!("root-{i}")), None);
        }
        let mut reference = state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        let original_end = reference["end"].as_u64().unwrap();
        for lsn in 2..12 {
            let key = causal::root(format!("new-{lsn}"));
            open.begin(&key, None);
            open.begin(&key, None);
            assert_eq!(open.dirty.len(), 1);
            let next = state.checkpoint(&mut open, lsn).await.unwrap();
            assert_eq!(next["generation"], reference["generation"]);
            assert!(next["end"].as_u64().unwrap() - reference["end"].as_u64().unwrap() < 1024);
            assert!(next.to_string().len() < 250);
            state.committed(&mut open);
            reference = next;
        }
        assert!(original_end > 1_000_000);
        let (_, restored) = load(env, dir.path(), &reference, 11, IDS).await.unwrap();
        assert_eq!(restored.len(), 20_010);
    }

    #[tokio::test]
    async fn kept_cap_eviction_and_next_survive_snapshot_and_delta() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let (mut state, mut open) = start(env.clone(), dir.path()).await;
        for seq in 0..OpenTurns::CAP as u64 {
            open.next = seq + 1;
            insert_kept(
                &mut open,
                causal::encode(&causal::root(format!("old-{seq}"))),
                Kept {
                    trace: [2; 16],
                    children: vec![(1, false)],
                    caller: false,
                    seq,
                },
            )
            .unwrap();
        }
        let first = state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        let mut newest = record(causal::root("newest".into()));
        newest.effects.push(pb::EffectRecord {
            kind: "actor.call".into(),
            ordinal: 8,
            status: pb::EffectStatus::Timeout as i32,
            ..Default::default()
        });
        open.commit(&newest);
        assert_eq!(open.dirty.len(), 2);
        let next = state.checkpoint(&mut open, 2).await.unwrap();
        assert_eq!(first["generation"], next["generation"]);
        state.committed(&mut open);
        let (_, restored) = load(env, dir.path(), &next, 2, IDS).await.unwrap();
        assert_eq!(restored.kept(), OpenTurns::CAP);
        assert_eq!(restored.next, OpenTurns::CAP as u64 + 1);
        assert_eq!(restored.order.first_key_value().unwrap().0, &1);
        assert!(
            !restored
                .kept
                .contains_key(&causal::encode(&causal::root("old-0".into())))
        );
    }

    #[tokio::test]
    async fn durable_v1_fixture_and_strict_selected_prefix_validation() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/golden/trace-state-v1.json")).unwrap();
        let reference = &fixture["reference"];
        let bytes = unhex(fixture["file_hex"].as_str().unwrap()).unwrap();
        let file = env
            .fs
            .open(path(dir.path(), 0), OpenMode::ReadWriteCreate)
            .await
            .unwrap();
        file.write_at(0, Bytes::from(bytes.clone())).await.unwrap();
        file.sync_data().await.unwrap();
        env.fs.sync_dir(dir.path().to_owned()).await.unwrap();
        let (_, open) = load(env.clone(), dir.path(), reference, 41, IDS)
            .await
            .unwrap();
        assert_eq!((open.len(), open.kept(), open.next), (1, 1, 8));
        assert_eq!(
            open.kept.values().next().unwrap().children,
            vec![(3, true), (5, false)]
        );
        let actor = ActorRef::parse("counter/a").unwrap();
        let callee = causal::child(&causal::root("1".repeat(32)), &actor, 3);
        assert!(open.kept[&causal::encode(&callee)].caller);
        assert_eq!(
            open.trace(&causal::child(&callee, &actor, 3), Some(&call())),
            [17; 16]
        );
        file.write_at(bytes.len() as u64, Bytes::from_static(b"uncommitted junk"))
            .await
            .unwrap();
        assert!(
            load(env.clone(), dir.path(), reference, 41, IDS)
                .await
                .is_ok()
        );
        for (key, value) in [
            ("format", serde_json::json!("kronik.trace-state/v2")),
            ("slot", serde_json::json!(2)),
            ("generation", serde_json::json!(2)),
            ("hash", serde_json::json!("0".repeat(64))),
            ("lsn", serde_json::json!(42)),
            ("end", serde_json::json!(65)),
            ("extra", serde_json::json!(1)),
        ] {
            let mut bad = reference.clone();
            bad[key] = value;
            assert!(
                load(env.clone(), dir.path(), &bad, 41, IDS).await.is_err(),
                "{key}"
            );
        }
        assert!(
            load(env.clone(), dir.path(), reference, 40, IDS)
                .await
                .is_err()
        );
        file.write_at(0, Bytes::from_static(b"X")).await.unwrap();
        assert!(
            load(env.clone(), dir.path(), reference, 41, IDS)
                .await
                .is_err()
        );
        file.write_at(0, Bytes::from(bytes.clone())).await.unwrap();
        file.write_at(HEADER + 8, Bytes::from_static(&[0; 32]))
            .await
            .unwrap();
        assert!(
            load(env.clone(), dir.path(), reference, 41, IDS)
                .await
                .is_err()
        );
        file.write_at(0, Bytes::from(bytes.clone())).await.unwrap();
        file.set_len(bytes.len() as u64 - 1).await.unwrap();
        assert!(
            load(env.clone(), dir.path(), reference, 41, IDS)
                .await
                .is_err()
        );
        env.fs.remove_file(path(dir.path(), 0)).await.unwrap();
        assert!(load(env, dir.path(), reference, 41, IDS).await.is_err());
    }

    #[tokio::test]
    async fn oversized_sparse_selected_frames_are_rejected_before_payload_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let len = MAX_FRAME_BYTES as u64 + 1;
        let end = HEADER + FRAME_HEADER + len;
        let file = env
            .fs
            .open(path(dir.path(), 0), OpenMode::ReadWriteCreate)
            .await
            .unwrap();
        file.write_at(0, Bytes::copy_from_slice(&header(1)))
            .await
            .unwrap();
        file.write_at(HEADER, Bytes::copy_from_slice(&len.to_le_bytes()))
            .await
            .unwrap();
        file.set_len(end).await.unwrap();
        let mut reference = serde_json::json!({
            "format": FORMAT, "slot": 0, "generation": 1,
            "end": end, "lsn": 1, "hash": "0".repeat(64),
        });
        let error = load(env.clone(), dir.path(), &reference, 1, IDS)
            .await
            .err()
            .unwrap();
        assert_eq!(failure_code(&error), Some("trace_state_limit"));
        reference["end"] = (MAX_SELECTED_BYTES + 1).into();
        let error = load(env, dir.path(), &reference, 1, IDS)
            .await
            .err()
            .unwrap();
        assert_eq!(failure_code(&error), Some("trace_state_limit"));

        let mut writer = LimitedVec {
            bytes: Vec::new(),
            limit: 32,
        };
        let error = serde_json::to_writer(&mut writer, &"x".repeat(64))
            .map_err(io::Error::from)
            .unwrap_err();
        assert_eq!(failure_code(&error), Some("trace_state_limit"));
        assert!(writer.bytes.len() <= writer.limit);

        let mut writer = LimitedVec::new(10);
        io::Write::write_all(&mut writer, b"1234567").unwrap();
        io::Write::write_all(&mut writer, b"890").unwrap();
        assert_eq!(writer.bytes.len(), 10);
        assert!(writer.bytes.capacity() <= writer.limit);
        let capacity = writer.bytes.capacity();
        let error = io::Write::write_all(&mut writer, b"x").unwrap_err();
        assert_eq!(failure_code(&error), Some("trace_state_limit"));
        assert_eq!(writer.bytes, b"1234567890");
        assert_eq!(writer.bytes.capacity(), capacity);
    }

    struct FaultFs {
        inner: Arc<dyn Fs>,
        fail: Arc<AtomicU8>,
        syncs: Arc<AtomicUsize>,
    }
    struct FaultFile {
        inner: Arc<dyn File>,
        fail: Arc<AtomicU8>,
        syncs: Arc<AtomicUsize>,
    }
    fn inject(fail: &AtomicU8, point: u8) -> io::Result<()> {
        if fail
            .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            Err(io::Error::from_raw_os_error(match point {
                4 => rustix::io::Errno::ACCESS.raw_os_error(),
                5 | 6 | 8 => rustix::io::Errno::NOSPC.raw_os_error(),
                _ => rustix::io::Errno::IO.raw_os_error(),
            }))
        } else {
            Ok(())
        }
    }
    impl File for FaultFile {
        fn len(&self) -> BoxFuture<'static, io::Result<u64>> {
            self.inner.len()
        }
        fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>> {
            self.inner.read_at(offset, len)
        }
        fn write_at(&self, offset: u64, bytes: Bytes) -> BoxFuture<'static, io::Result<()>> {
            for point in [5, 7] {
                if let Err(e) = inject(&self.fail, point) {
                    return Box::pin(async { Err(e) });
                }
            }
            self.inner.write_at(offset, bytes)
        }
        fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>> {
            self.inner.set_len(len)
        }
        fn sync_data(&self) -> BoxFuture<'static, io::Result<()>> {
            self.syncs.fetch_add(1, Ordering::SeqCst);
            if let Err(e) = inject(&self.fail, 1) {
                return Box::pin(async { Err(e) });
            }
            if let Err(e) = inject(&self.fail, 6) {
                return Box::pin(async { Err(e) });
            }
            self.inner.sync_data()
        }
    }
    impl Fs for FaultFs {
        fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.inner.create_dir_all(path)
        }
        fn open(
            &self,
            path: PathBuf,
            mode: OpenMode,
        ) -> BoxFuture<'static, io::Result<Arc<dyn File>>> {
            if let Err(e) = inject(&self.fail, 4) {
                return Box::pin(async { Err(e) });
            }
            let future = self.inner.open(path, mode);
            let fail = self.fail.clone();
            let syncs = self.syncs.clone();
            Box::pin(async move {
                Ok(Arc::new(FaultFile {
                    inner: future.await?,
                    fail,
                    syncs,
                }) as Arc<dyn File>)
            })
        }
        fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
            self.inner.exists(path)
        }
        fn read_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
            self.inner.read_dir(path)
        }
        fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.inner.remove_file(path)
        }
        fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            if let Err(e) = inject(&self.fail, 2) {
                return Box::pin(async { Err(e) });
            }
            if let Err(e) = inject(&self.fail, 8) {
                return Box::pin(async { Err(e) });
            }
            self.inner.rename(from, to)
        }
        fn sync_dir(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            if let Err(e) = inject(&self.fail, 3) {
                return Box::pin(async { Err(e) });
            }
            self.inner.sync_dir(path)
        }
    }

    #[tokio::test]
    async fn checkpoint_retry_is_frozen_and_failed_compaction_preserves_selected_prefix() {
        for point in [1, 2, 3, 6] {
            let dir = tempfile::tempdir().unwrap();
            let mut env = env();
            let fail = Arc::new(AtomicU8::new(0));
            let syncs = Arc::new(AtomicUsize::new(0));
            env.fs = Arc::new(FaultFs {
                inner: env.fs.clone(),
                fail: fail.clone(),
                syncs: syncs.clone(),
            });
            let (mut state, mut open) = start(env.clone(), dir.path()).await;
            open.begin(&causal::root("chosen".into()), None);
            let chosen = state.checkpoint(&mut open, 1).await.unwrap();
            let count = syncs.load(Ordering::SeqCst);
            assert!(!open.dirty.is_empty());
            assert_eq!(state.checkpoint(&mut open, 1).await.unwrap(), chosen);
            assert_eq!(syncs.load(Ordering::SeqCst), count);
            state.committed(&mut open);
            open.begin(&causal::root("candidate".into()), None);
            state.reset();
            fail.store(point, Ordering::SeqCst);
            let error = state.checkpoint(&mut open, 2).await.err().unwrap();
            assert_eq!(failure_code(&error), Some("storage_sync"));
            let count = syncs.load(Ordering::SeqCst);
            state.reset();
            let error = state.checkpoint(&mut open, 2).await.err().unwrap();
            assert_eq!(failure_code(&error), Some("storage_sync"));
            assert_eq!(syncs.load(Ordering::SeqCst), count);
            assert!(!open.dirty.is_empty());
            let (mut reopened, mut restored) = load(env.clone(), dir.path(), &chosen, 1, IDS)
                .await
                .unwrap();
            assert_eq!(restored.len(), 1);
            assert!(
                restored
                    .traces
                    .contains_key(&causal::encode(&causal::root("chosen".into())))
            );
            let recovered = reopened.checkpoint(&mut restored, 1).await.unwrap();
            assert_ne!(recovered["slot"], chosen["slot"]);
            reopened.committed(&mut restored);
            assert!(load(env, dir.path(), &recovered, 1, IDS).await.is_ok());
        }
    }

    #[tokio::test]
    async fn byte_amortized_compaction_switches_generation_without_touching_chosen_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let (mut state, mut open) = start(env.clone(), dir.path()).await;
        open.begin(&causal::root("base".into()), None);
        let first = state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        let mut lsn = 2;
        loop {
            // Large keys prove that the limit is a byte budget, not an entry count.
            open.begin(&causal::root(format!("{lsn}-{}", "x".repeat(8192))), None);
            let candidate = state.checkpoint(&mut open, lsn).await.unwrap();
            if candidate["generation"] != first["generation"] {
                let (_, old) = load(env.clone(), dir.path(), &first, 1, IDS).await.unwrap();
                assert_eq!(old.len(), 1);
                let (_, new) = load(env, dir.path(), &candidate, lsn, IDS).await.unwrap();
                assert_eq!(new.len(), open.len());
                state.committed(&mut open);
                break;
            }
            state.committed(&mut open);
            lsn += 1;
            assert!(lsn < 20);
        }
    }

    #[tokio::test]
    async fn failed_delta_sync_never_resyncs_inode_and_old_prefix_remains_selected() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = env();
        let fail = Arc::new(AtomicU8::new(0));
        let syncs = Arc::new(AtomicUsize::new(0));
        env.fs = Arc::new(FaultFs {
            inner: env.fs.clone(),
            fail: fail.clone(),
            syncs: syncs.clone(),
        });
        let (mut state, mut open) = start(env.clone(), dir.path()).await;
        open.begin(&causal::root("durable".into()), None);
        let chosen = state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        open.begin(&causal::root("unpublished".into()), None);
        fail.store(1, Ordering::SeqCst);
        assert!(state.checkpoint(&mut open, 2).await.is_err());
        let attempts = syncs.load(Ordering::SeqCst);
        assert!(state.checkpoint(&mut open, 2).await.is_err());
        assert_eq!(syncs.load(Ordering::SeqCst), attempts);
        let (mut restored_state, mut restored) = load(env.clone(), dir.path(), &chosen, 1, IDS)
            .await
            .unwrap();
        assert_eq!(restored.len(), 1);
        let replacement = restored_state.checkpoint(&mut restored, 1).await.unwrap();
        assert_ne!(replacement["slot"], chosen["slot"]);
        assert_eq!(syncs.load(Ordering::SeqCst), attempts + 1);
        restored_state.committed(&mut restored);
        assert!(load(env, dir.path(), &replacement, 1, IDS).await.is_ok());
    }

    #[tokio::test]
    async fn valid_checksums_do_not_hide_invalid_frames_or_positions() {
        let dir = tempfile::tempdir().unwrap();
        let env = env();
        let key = causal::encode(&causal::root("frame".into()));
        let trace = [1; 16];
        let file = env
            .fs
            .open(path(dir.path(), 0), OpenMode::ReadWriteCreate)
            .await
            .unwrap();
        for value in [
            serde_json::json!({"kind": "Unknown", "lsn": 1}),
            serde_json::json!({"kind": "Snapshot", "lsn": 1, "next": 0, "open": [], "kept": [], "extra": 1}),
            serde_json::json!({"kind": "Snapshot", "lsn": 2, "next": 0, "open": [], "kept": []}),
            serde_json::json!({"kind": "Snapshot", "lsn": 1, "next": 0, "open": [[key, trace], [key, trace]], "kept": []}),
            serde_json::json!({"kind": "Snapshot", "lsn": 1, "next": 0, "open": [], "kept": [[key, {"trace": trace, "children": [[3,true]], "caller": false, "seq": 0}]]}),
            serde_json::json!({"kind": "Delta", "base_lsn": 0, "lsn": 1, "next": 0, "changes": []}),
        ] {
            let payload = serde_json::to_vec(&value).unwrap();
            let hash = checksum(1, HEADER, &[0; 32], &payload);
            let mut bytes = header(1).to_vec();
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&hash);
            bytes.extend_from_slice(&payload);
            let reference = serde_json::json!({
                "format": FORMAT, "slot": 0, "generation": 1, "end": bytes.len(),
                "lsn": 1, "hash": hex(&hash),
            });
            file.set_len(0).await.unwrap();
            file.write_at(0, Bytes::from(bytes)).await.unwrap();
            assert!(
                load(env.clone(), dir.path(), &reference, 1, IDS)
                    .await
                    .is_err()
            );
        }
        for (base_lsn, lsn, next) in [(2, 3, 0), (1, 0, 0), (1, 2, 0)] {
            let mut open = OpenTurns::new(IDS);
            open.next = 1;
            assert!(
                apply(
                    &mut open,
                    Frame::Delta {
                        base_lsn,
                        lsn,
                        next,
                        changes: Vec::new(),
                    },
                    Some(1)
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn ordinary_open_write_and_rename_failures_retry_without_latching() {
        for point in [4, 5, 8] {
            let dir = tempfile::tempdir().unwrap();
            let mut env = env();
            let fail = Arc::new(AtomicU8::new(0));
            let syncs = Arc::new(AtomicUsize::new(0));
            env.fs = Arc::new(FaultFs {
                inner: env.fs.clone(),
                fail: fail.clone(),
                syncs,
            });
            let (mut state, mut open) = start(env.clone(), dir.path()).await;
            open.begin(&causal::root("snapshot".into()), None);
            fail.store(point, Ordering::SeqCst);
            let error = state.checkpoint(&mut open, 1).await.err().unwrap();
            assert_eq!(failure_code(&error), None);
            assert!(!open.dirty.is_empty());
            let chosen = state.checkpoint(&mut open, 1).await.unwrap();
            state.committed(&mut open);
            assert!(open.dirty.is_empty());
            let (_, restored) = load(env.clone(), dir.path(), &chosen, 1, IDS)
                .await
                .unwrap();
            assert_eq!(restored.len(), 1);
            open.begin(&causal::root("delta".into()), None);
            fail.store(5, Ordering::SeqCst);
            let error = state.checkpoint(&mut open, 2).await.err().unwrap();
            assert_eq!(failure_code(&error), None);
            let (_, restored) = load(env.clone(), dir.path(), &chosen, 1, IDS)
                .await
                .unwrap();
            assert_eq!(restored.len(), 1);
            let next = state.checkpoint(&mut open, 2).await.unwrap();
            state.committed(&mut open);
            let (_, restored) = load(env, dir.path(), &next, 2, IDS).await.unwrap();
            assert_eq!(restored.len(), 2);
        }
    }

    #[tokio::test]
    async fn write_eio_latches_preserves_cause_and_performs_no_retry_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = env();
        let fail = Arc::new(AtomicU8::new(0));
        let syncs = Arc::new(AtomicUsize::new(0));
        env.fs = Arc::new(FaultFs {
            inner: env.fs.clone(),
            fail: fail.clone(),
            syncs: syncs.clone(),
        });
        let (mut state, mut open) = start(env, dir.path()).await;
        open.begin(&causal::root("first".into()), None);
        state.checkpoint(&mut open, 1).await.unwrap();
        state.committed(&mut open);
        open.begin(&causal::root("second".into()), None);
        fail.store(7, Ordering::SeqCst);
        let error = state.checkpoint(&mut open, 2).await.err().unwrap();
        assert_eq!(failure_code(&error), Some("storage_sync"));
        let source = error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(
            source.raw_os_error(),
            Some(rustix::io::Errno::IO.raw_os_error())
        );
        let attempts = syncs.load(Ordering::SeqCst);
        fail.store(5, Ordering::SeqCst);
        let error = state.checkpoint(&mut open, 2).await.err().unwrap();
        assert_eq!(failure_code(&error), Some("storage_sync"));
        assert_eq!(fail.load(Ordering::SeqCst), 5);
        assert_eq!(syncs.load(Ordering::SeqCst), attempts);
    }
}
