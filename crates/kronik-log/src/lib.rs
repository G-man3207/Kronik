//! The append-only log: segment files of Protobuf records with CRC, LSN and a
//! group-commit writer that acknowledges only after `fdatasync`.
//!
//! Format (docs/design/m1-core.md §2, ADR 0011):
//! - Segment `<dir>/<start lsn, 20 digits>.seg`, header: magic `KRNK`, `u32`
//!   format version, `u64` start LSN, `u32` branch length, branch, `u32`
//!   crc32c of the preceding header bytes.
//! - Entries: `[u32 len][u32 crc32c][u64 lsn][u8 kind][protobuf]`, the crc
//!   covering lsn, kind and protobuf. LSNs increase by exactly 1 across all
//!   record kinds and segments.
//! - A closed segment ends with a footer of kind 255. That entry is not an
//!   LSN and not a [`Record`]. Its payload, little-endian, is `FIDX`, `u32`
//!   version 1, then repeated entries of `u16` kind length, kind, `u16` key
//!   length, key, `u32` count, and `count` times `u64` file offset. Offsets
//!   are that actor's `TurnBegin` and `TurnRecord` entries in this segment,
//!   ascending. Actors are sorted by kind, then key. Empty actor strings are
//!   omitted. The envelope LSN is 0. A segment with no footer still reads;
//!   a torn footer is a torn tail and is truncated on open.
//!
//! Recovery (ADR 0004): in the active (last) segment, everything from the
//! first entry that fails its length, CRC or LSN check is a torn tail and is
//! truncated durably. Any such failure in a closed segment, and any entry
//! that passes its CRC but does not decode or validate, is `STORAGE_CORRUPT`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{Env, File, OpenMode};
use kronik_core::ids::Lsn;
use kronik_proto::Record;
use tokio::sync::{mpsc, oneshot};

pub const MAGIC: &[u8; 4] = b"KRNK";
pub const FORMAT_VERSION: u32 = 1;
/// Envelope bytes before the protobuf: len, crc, lsn, kind.
pub const ENVELOPE_LEN: usize = 17;
/// The largest record body accepted (a turn's writes, messages and SQL
/// changes together).
pub const MAX_RECORD: u32 = 128 << 20;
/// Closed-segment footer index (ADR 0011). Not an LSN and not a [`Record`];
/// readers skip it. See [`footer_index`].
pub const FOOTER_KIND: u8 = 255;
/// Magic at the start of a footer payload.
const FOOTER_MAGIC: &[u8; 4] = b"FIDX";
/// Footer payload version. A different version does not parse.
const FOOTER_VERSION: u32 = 1;

/// Actor `(kind, key)` to that actor's `TurnBegin` and `TurnRecord` offsets
/// in one segment, ascending.
pub type FooterIndex = BTreeMap<(String, String), Vec<u64>>;

/// Log settings.
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub dir: PathBuf,
    pub branch: String,
    /// A segment is closed after reaching this size (default 64 MiB).
    pub segment_max_bytes: u64,
    /// A segment is closed after this age at the next append (default 60 s).
    pub segment_max_age: Duration,
    /// Appends arriving within this window after the first one share an
    /// fsync (default 2 ms).
    pub group_commit_window: Duration,
    /// Deliberate bug for testing the simulator: acknowledge before fsync.
    #[doc(hidden)]
    pub mutation_ack_before_fsync: bool,
    /// The LSN of a new log's first record (default 1; a fork's log starts
    /// after its fork point, docs/design/m3-fork.md §2).
    pub first_lsn: Lsn,
}

impl LogConfig {
    pub fn new(dir: PathBuf, branch: impl Into<String>) -> LogConfig {
        LogConfig {
            dir,
            branch: branch.into(),
            segment_max_bytes: 64 << 20,
            segment_max_age: Duration::from_secs(60),
            group_commit_window: Duration::from_millis(2),
            mutation_ack_before_fsync: false,
            first_lsn: 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// Maps to the stable code `STORAGE_CORRUPT`.
    #[error("STORAGE_CORRUPT: {0}")]
    Corrupt(String),
    #[error("log I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("log writer stopped: {0}")]
    Stopped(String),
}

fn corrupt(msg: impl Into<String>) -> LogError {
    LogError::Corrupt(msg.into())
}

/// Where a record lives: its segment (by start LSN) and byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub segment: Lsn,
    pub offset: u64,
}

/// A durable record, as delivered to the applier and by the reader.
#[derive(Debug, Clone)]
pub struct Committed {
    pub lsn: Lsn,
    pub pos: Position,
    pub record: Record,
}

pub fn segment_name(start_lsn: Lsn) -> String {
    format!("{start_lsn:020}.seg")
}

/// The start LSNs of the segments in `dir`, ascending (offline tools:
/// snapshots, retention, restore). A missing directory has none.
pub fn segment_starts(dir: &Path) -> io::Result<Vec<Lsn>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for e in entries {
        if let Some(start) = parse_segment_name(&e?.file_name().to_string_lossy()) {
            out.push(start);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// Deletes a closed segment (retention). Never the active one: the caller
/// passes only segments older than the newest.
pub fn delete_segment(dir: &Path, start: Lsn) -> io::Result<()> {
    std::fs::remove_file(dir.join(segment_name(start)))?;
    if let Ok(d) = std::fs::File::open(dir) {
        d.sync_all()?;
    }
    Ok(())
}

fn parse_segment_name(name: &str) -> Option<Lsn> {
    let digits = name.strip_suffix(".seg")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn header_bytes(branch: &str, start_lsn: Lsn) -> Vec<u8> {
    let mut h = Vec::with_capacity(24 + branch.len());
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    h.extend_from_slice(&start_lsn.to_le_bytes());
    h.extend_from_slice(&(branch.len() as u32).to_le_bytes());
    h.extend_from_slice(branch.as_bytes());
    let crc = crc32c::crc32c(&h);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

struct Header {
    start_lsn: Lsn,
    branch: String,
    len: usize,
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn turn_actor(record: &Record) -> Option<(&str, &str)> {
    let actor = match record {
        Record::TurnBegin(m) => m.actor.as_ref(),
        Record::TurnRecord(m) => m.actor.as_ref(),
        _ => return None,
    }?;
    if actor.kind.is_empty() || actor.key.is_empty() {
        return None;
    }
    Some((actor.kind.as_str(), actor.key.as_str()))
}

fn remember_turn(index: &mut FooterIndex, record: &Record, offset: u64) {
    if let Some((kind, key)) = turn_actor(record) {
        index
            .entry((kind.to_owned(), key.to_owned()))
            .or_default()
            .push(offset);
    }
}

fn footer_payload(index: &FooterIndex) -> Result<Vec<u8>, LogError> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(FOOTER_MAGIC);
    out.extend_from_slice(&FOOTER_VERSION.to_le_bytes());
    for ((kind, key), offsets) in index {
        if kind.is_empty() || key.is_empty() {
            continue;
        }
        let kind_b = kind.as_bytes();
        let key_b = key.as_bytes();
        let kind_len = u16::try_from(kind_b.len())
            .map_err(|_| corrupt(format!("actor kind longer than {}", u16::MAX)))?;
        let key_len = u16::try_from(key_b.len())
            .map_err(|_| corrupt(format!("actor key longer than {}", u16::MAX)))?;
        let count = u32::try_from(offsets.len())
            .map_err(|_| corrupt("footer offset count does not fit in u32"))?;
        out.extend_from_slice(&kind_len.to_le_bytes());
        out.extend_from_slice(kind_b);
        out.extend_from_slice(&key_len.to_le_bytes());
        out.extend_from_slice(key_b);
        out.extend_from_slice(&count.to_le_bytes());
        for offset in offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
    }
    if out.len() > MAX_RECORD as usize {
        return Err(corrupt("segment footer exceeds the record limit"));
    }
    Ok(out)
}

fn parse_footer_payload(
    payload: &[u8],
    image_len: u64,
    header_len: u64,
) -> Result<FooterIndex, LogError> {
    if payload.len() < 8 || payload.get(..4) != Some(FOOTER_MAGIC) {
        return Err(corrupt("segment footer is not FIDX"));
    }
    let version = u32_at(payload, 4).ok_or_else(|| corrupt("segment footer is truncated"))?;
    if version != FOOTER_VERSION {
        return Err(corrupt(format!("segment footer version {version}")));
    }
    let mut off = 8;
    let mut index = BTreeMap::new();
    let mut prev_actor: Option<(String, String)> = None;
    while off < payload.len() {
        let kind_len =
            u16_at(payload, off).ok_or_else(|| corrupt("segment footer is truncated"))? as usize;
        off += 2;
        let kind = utf8_at(payload, &mut off, kind_len)?;
        let key_len =
            u16_at(payload, off).ok_or_else(|| corrupt("segment footer is truncated"))? as usize;
        off += 2;
        let key = utf8_at(payload, &mut off, key_len)?;
        let count =
            u32_at(payload, off).ok_or_else(|| corrupt("segment footer is truncated"))? as usize;
        off += 4;
        if kind.is_empty() || key.is_empty() {
            return Err(corrupt("segment footer has an empty actor"));
        }
        let mut offsets = Vec::with_capacity(count);
        let mut prev_off = None;
        for _ in 0..count {
            let o = u64_at(payload, off).ok_or_else(|| corrupt("segment footer is truncated"))?;
            off += 8;
            if o < header_len || o >= image_len {
                return Err(corrupt(format!("footer offset {o} is outside the segment")));
            }
            if let Some(prev) = prev_off
                && o <= prev
            {
                return Err(corrupt("footer offsets are not ascending"));
            }
            prev_off = Some(o);
            offsets.push(o);
        }
        let pair = (kind, key);
        if let Some(prev) = &prev_actor
            && pair <= *prev
        {
            return Err(corrupt("footer actors are not sorted"));
        }
        prev_actor = Some(pair.clone());
        index.insert(pair, offsets);
    }
    Ok(index)
}

fn utf8_at(payload: &[u8], off: &mut usize, n: usize) -> Result<String, LogError> {
    let end = off
        .checked_add(n)
        .ok_or_else(|| corrupt("segment footer is truncated"))?;
    let bytes = payload
        .get(*off..end)
        .ok_or_else(|| corrupt("segment footer is truncated"))?;
    *off = end;
    std::str::from_utf8(bytes)
        .map(|s| s.to_owned())
        .map_err(|_| corrupt("segment footer actor is not utf-8"))
}

fn turn_index_from_image(image: &[u8]) -> Result<FooterIndex, LogError> {
    let header = parse_header(image).ok_or_else(|| corrupt("segment has no valid header"))?;
    let mut index = BTreeMap::new();
    let mut off = header.len;
    let mut expected = header.start_lsn;
    while let Some(e) = parse_entry(image, off) {
        if e.kind == FOOTER_KIND {
            off = e.end;
            continue;
        }
        if e.lsn != expected {
            break;
        }
        if e.kind == kronik_proto::kind::TURN_BEGIN || e.kind == kronik_proto::kind::TURN_RECORD {
            let record = Record::decode(e.kind, e.payload)
                .map_err(|err| corrupt(format!("record at lsn {}: {err}", e.lsn)))?;
            remember_turn(&mut index, &record, off as u64);
        }
        expected += 1;
        off = e.end;
    }
    Ok(index)
}

/// The actor-to-offset index of a segment file.
///
/// Keys are `(kind, key)`. `None` when the segment has no footer (every
/// segment written before footers, the active segment, or a crash before
/// the footer was fsynced). `Err` when a footer is present but does not
/// parse, or an offset is outside the segment or is not a `TurnBegin` or
/// `TurnRecord` entry in it.
pub fn footer_index(path: &Path) -> Result<Option<FooterIndex>, LogError> {
    let image = std::fs::read(path)?;
    let header = parse_header(&image)
        .ok_or_else(|| corrupt(format!("segment {} has no valid header", path.display())))?;
    let mut off = header.len;
    let mut expected = header.start_lsn;
    let mut parsed = None;
    let mut turns = BTreeSet::new();
    while let Some(e) = parse_entry(&image, off) {
        if e.kind == FOOTER_KIND {
            parsed = Some(parse_footer_payload(
                e.payload,
                image.len() as u64,
                header.len as u64,
            )?);
            off = e.end;
            continue;
        }
        if e.lsn != expected {
            break;
        }
        if e.kind == kronik_proto::kind::TURN_BEGIN || e.kind == kronik_proto::kind::TURN_RECORD {
            turns.insert(off as u64);
        }
        expected += 1;
        off = e.end;
    }
    let Some(index) = parsed else {
        return Ok(None);
    };
    for offsets in index.values() {
        for o in offsets {
            if !turns.contains(o) {
                return Err(corrupt(format!(
                    "footer offset {o} is not a turn in this segment"
                )));
            }
        }
    }
    Ok(Some(index))
}

/// `None` for a missing, torn or foreign header.
fn parse_header(image: &[u8]) -> Option<Header> {
    if image.get(..4)? != MAGIC || u32_at(image, 4)? != FORMAT_VERSION {
        return None;
    }
    let start_lsn = u64_at(image, 8)?;
    let blen = u32_at(image, 16)? as usize;
    let end = 20usize.checked_add(blen)?;
    let branch = std::str::from_utf8(image.get(20..end)?).ok()?.to_owned();
    if u32_at(image, end)? != crc32c::crc32c(&image[..end]) {
        return None;
    }
    Some(Header {
        start_lsn,
        branch,
        len: end + 4,
    })
}

/// Encodes one entry.
pub fn encode_entry(lsn: Lsn, record: &Record, out: &mut Vec<u8>) {
    encode_raw_entry(lsn, record.kind(), &record.encode(), out);
}

/// Encodes an entry from raw parts (tests write invalid bodies with it).
pub fn encode_raw_entry(lsn: Lsn, kind: u8, payload: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&lsn.to_le_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    let crc = crc32c::crc32c(&out[start + 8..]);
    out[start + 4..start + 8].copy_from_slice(&crc.to_le_bytes());
}

struct RawEntry<'a> {
    lsn: Lsn,
    kind: u8,
    payload: &'a [u8],
    end: usize,
}

fn parse_entry(image: &[u8], off: usize) -> Option<RawEntry<'_>> {
    let len = u32_at(image, off)?;
    if len > MAX_RECORD {
        return None;
    }
    let crc = u32_at(image, off + 4)?;
    let end = off + ENVELOPE_LEN + len as usize;
    let body = image.get(off + 8..end)?;
    if crc32c::crc32c(body) != crc {
        return None;
    }
    Some(RawEntry {
        lsn: u64_at(body, 0)?,
        kind: body[8],
        payload: &body[9..],
        end,
    })
}

/// The result of parsing one segment image.
struct SegmentScan {
    /// Offset just past the last valid entry.
    valid_end: u64,
    /// Whether bytes follow `valid_end`.
    has_tail: bool,
    /// The LSN the next entry would carry.
    next_lsn: Lsn,
    /// The last valid entry is a footer, so the segment is closed.
    ends_with_footer: bool,
}

/// Parses entries of a segment whose header is valid and hands each record
/// to `f`. Stops at the first invalid entry (`has_tail`); entries with lsn
/// < `from` are skipped without decoding, entries above `upto` end the
/// scan. A footer is not an LSN.
fn scan_entries<E: From<LogError>>(
    image: &[u8],
    header: &Header,
    from: Lsn,
    upto: Lsn,
    mut f: impl FnMut(Committed) -> Result<(), E>,
) -> Result<SegmentScan, E> {
    let mut off = header.len;
    let mut expected = header.start_lsn;
    let mut ends_with_footer = false;
    while let Some(e) = parse_entry(image, off) {
        if e.kind == FOOTER_KIND {
            off = e.end;
            ends_with_footer = true;
            continue;
        }
        if e.lsn != expected {
            break;
        }
        if e.lsn > upto {
            return Ok(SegmentScan {
                valid_end: off as u64,
                has_tail: false,
                next_lsn: expected,
                ends_with_footer,
            });
        }
        ends_with_footer = false;
        if e.lsn >= from {
            let record = Record::decode(e.kind, e.payload)
                .map_err(|err| corrupt(format!("record at lsn {}: {err}", e.lsn)))?;
            f(Committed {
                lsn: e.lsn,
                pos: Position {
                    segment: header.start_lsn,
                    offset: off as u64,
                },
                record,
            })?;
        } else if e.kind == 0 || !kronik_proto::kind::ALL.contains(&e.kind) {
            return Err(corrupt(format!("record at lsn {} has kind {}", e.lsn, e.kind)).into());
        }
        expected += 1;
        off = e.end;
    }
    Ok(SegmentScan {
        valid_end: off as u64,
        has_tail: off < image.len(),
        next_lsn: expected,
        ends_with_footer,
    })
}
/// The callback of a scan that decodes no record (`from` past the end).
fn no_records(_: Committed) -> Result<(), LogError> {
    Ok(())
}

/// One segment, decoded. Startup replay overlaps this with apply.
#[derive(Debug)]
pub struct DecodedSegment {
    pub records: Vec<Committed>,
    /// The LSN the next segment must start at.
    pub next_lsn: Lsn,
}

/// Decodes a segment image. `allow_tail` is true only for the active
/// segment, whose torn tail is truncated rather than corrupt.
pub fn decode_segment_image(
    image: &[u8],
    branch: &str,
    expected_start: Lsn,
    from: Lsn,
    upto: Lsn,
    allow_tail: bool,
) -> Result<DecodedSegment, LogError> {
    let mut records = Vec::new();
    let next_lsn =
        scan_segment_image(image, branch, expected_start, from, upto, allow_tail, |c| {
            records.push(c);
            Ok::<_, LogError>(())
        })?;
    Ok(DecodedSegment { records, next_lsn })
}

/// [`decode_segment_image`] that hands each record to `f` as it is decoded
/// instead of collecting them, and returns the LSN the next segment must
/// start at. `f` may have seen records of a segment that turns out corrupt.
pub fn scan_segment_image<E: From<LogError>>(
    image: &[u8],
    branch: &str,
    expected_start: Lsn,
    from: Lsn,
    upto: Lsn,
    allow_tail: bool,
    f: impl FnMut(Committed) -> Result<(), E>,
) -> Result<Lsn, E> {
    let header = parse_header(image)
        .ok_or_else(|| corrupt(format!("segment {expected_start} has no valid header")))?;
    if header.start_lsn != expected_start || header.branch != branch {
        return Err(corrupt(format!("segment {expected_start} header mismatch")).into());
    }
    let scan = scan_entries(image, &header, from, upto, f)?;
    if scan.has_tail && !allow_tail {
        return Err(corrupt(format!(
            "closed segment {expected_start} is invalid at offset {}",
            scan.valid_end
        ))
        .into());
    }
    Ok(scan.next_lsn)
}

/// What [`rewrite_segment`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRewrite {
    /// False when no record changed: the file was left as it was.
    pub changed: bool,
    /// `(lsn, offset)` of every record, after the rewrite when `changed`.
    pub offsets: Vec<(Lsn, u64)>,
}

/// Rewrites a closed segment in place: the new image is written beside the
/// old one, fsynced and renamed over it (docs/design/m8-privacy.md §8).
/// LSNs, record order and the header stay. `edit` may change a record and
/// returns whether it did; checksums are recomputed for changed records.
///
/// If any record changed, the old footer is dropped and a new one is written
/// at the end with the new offsets, then fsynced with the image. If nothing
/// changed, the file is left alone, including a missing footer: a no-op
/// rewrite must not invent one.
///
/// The active segment must not be passed here: the writer holds it open.
pub fn rewrite_segment(
    path: &Path,
    mut edit: impl FnMut(Lsn, &mut Record) -> Result<bool, String>,
) -> Result<SegmentRewrite, LogError> {
    let image = std::fs::read(path)?;
    let header = parse_header(&image)
        .ok_or_else(|| corrupt(format!("segment {} has no valid header", path.display())))?;
    let mut off = header.len;
    let mut expected = header.start_lsn;
    let mut out = image[..header.len].to_vec();
    let mut offsets = Vec::new();
    let mut index = BTreeMap::new();
    let mut changed = false;
    while let Some(e) = parse_entry(&image, off) {
        if e.kind == FOOTER_KIND {
            off = e.end;
            continue;
        }
        if e.lsn != expected {
            break;
        }
        if e.kind == 0 || !kronik_proto::kind::ALL.contains(&e.kind) {
            return Err(corrupt(format!(
                "record at lsn {} has kind {}",
                e.lsn, e.kind
            )));
        }
        let mut record = Record::decode(e.kind, e.payload)
            .map_err(|err| corrupt(format!("record at lsn {}: {err}", e.lsn)))?;
        let edited = edit(e.lsn, &mut record).map_err(corrupt)?;
        let new_off = out.len() as u64;
        offsets.push((e.lsn, new_off));
        remember_turn(&mut index, &record, new_off);
        if edited {
            changed = true;
            encode_entry(e.lsn, &record, &mut out);
        } else {
            out.extend_from_slice(&image[off..e.end]);
        }
        expected += 1;
        off = e.end;
    }
    if off < image.len() {
        return Err(corrupt(format!(
            "segment {} is invalid at offset {off}",
            path.display()
        )));
    }
    if !changed {
        return Ok(SegmentRewrite {
            changed: false,
            offsets,
        });
    }
    let payload = footer_payload(&index)?;
    encode_raw_entry(0, FOOTER_KIND, &payload, &mut out);
    let tmp = path.with_extension("seg.tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent()
        && let Ok(d) = std::fs::File::open(parent)
    {
        let _ = d.sync_all();
    }
    Ok(SegmentRewrite {
        changed: true,
        offsets,
    })
}

async fn list_segments(env: &Env, dir: &Path) -> Result<Vec<Lsn>, LogError> {
    let mut starts: Vec<Lsn> = env
        .fs
        .read_dir(dir.to_path_buf())
        .await?
        .iter()
        .filter_map(|n| parse_segment_name(n))
        .collect();
    starts.sort_unstable();
    Ok(starts)
}

async fn read_file(env: &Env, path: PathBuf) -> Result<Vec<u8>, LogError> {
    let file = env.fs.open(path, OpenMode::Read).await?;
    let len = file.len().await?;
    Ok(file.read_at(0, len as usize).await?)
}

/// What `Log::open` found.
#[derive(Debug, Clone)]
pub struct Opened {
    /// The LSN the next append gets.
    pub next_lsn: Lsn,
    /// Bytes truncated from the active segment's torn tail.
    pub truncated_bytes: u64,
    pub segments: usize,
    /// The active segment's header was torn and has been rewritten.
    pub recreated_active: bool,
    /// The first LSN the log holds (the oldest segment's start; later than
    /// 1 after compaction or for a fork's log).
    pub first_lsn: Lsn,
}

struct Append {
    record: Record,
    done: oneshot::Sender<Result<Lsn, String>>,
}

/// Handle to the group-commit writer task. Cheap to clone.
#[derive(Clone)]
pub struct Log {
    tx: mpsc::UnboundedSender<Append>,
}

struct Segment {
    start_lsn: Lsn,
    file: Arc<dyn File>,
    offset: u64,
    opened_at: Duration,
    /// `TurnBegin` and `TurnRecord` offsets in this segment, for the footer
    /// written when it rolls. Empty actor strings are not recorded.
    index: FooterIndex,
}

async fn create_segment(env: &Env, cfg: &LogConfig, start_lsn: Lsn) -> Result<Segment, LogError> {
    let file = env
        .fs
        .open(
            cfg.dir.join(segment_name(start_lsn)),
            OpenMode::ReadWriteCreate,
        )
        .await?;
    file.set_len(0).await?;
    let header = header_bytes(&cfg.branch, start_lsn);
    let offset = header.len() as u64;
    file.write_at(0, Bytes::from(header)).await?;
    file.sync_data().await?;
    env.fs.sync_dir(cfg.dir.clone()).await?;
    Ok(Segment {
        start_lsn,
        file,
        offset,
        opened_at: env.clock.monotonic(),
        index: BTreeMap::new(),
    })
}

impl Log {
    /// Opens the log, truncates a torn tail durably and starts the writer.
    /// Every durable record is sent to `committed` in LSN order after its
    /// fsync; `fatal` fires if the writer stops on an I/O error (the daemon
    /// must then exit and recover on restart, never retry an fsync).
    pub async fn open(
        env: &Env,
        cfg: LogConfig,
        committed: mpsc::UnboundedSender<Committed>,
        fatal: oneshot::Sender<String>,
    ) -> Result<(Log, Opened), LogError> {
        env.fs.create_dir_all(cfg.dir.clone()).await?;
        let starts = list_segments(env, &cfg.dir).await?;
        let mut truncated_bytes = 0;
        let mut recreated_active = false;
        let mut extra_segment = false;
        let (segment, next_lsn) = match starts.last() {
            None => {
                extra_segment = true;
                (
                    create_segment(env, &cfg, cfg.first_lsn).await?,
                    cfg.first_lsn,
                )
            }
            Some(&start) => {
                let path = cfg.dir.join(segment_name(start));
                let image = read_file(env, path.clone()).await?;
                match parse_header(&image) {
                    None => {
                        // A torn header: the segment was being created and
                        // can hold no acknowledged record.
                        recreated_active = true;
                        truncated_bytes = image.len() as u64;
                        (create_segment(env, &cfg, start).await?, start)
                    }
                    Some(h) => {
                        if h.start_lsn != start || h.branch != cfg.branch {
                            return Err(corrupt(format!(
                                "segment {} has start lsn {} and branch {:?}",
                                path.display(),
                                h.start_lsn,
                                h.branch
                            )));
                        }
                        let scan = scan_entries(&image, &h, Lsn::MAX, Lsn::MAX, no_records)?;
                        if scan.ends_with_footer {
                            // Closed. Do not append after the footer. A torn
                            // tail after a valid footer is truncated so a
                            // later read does not see a corrupt closed
                            // segment; the next segment starts at next_lsn.
                            if scan.has_tail {
                                let file = env.fs.open(path, OpenMode::ReadWriteCreate).await?;
                                truncated_bytes = image.len() as u64 - scan.valid_end;
                                file.set_len(scan.valid_end).await?;
                                file.sync_data().await?;
                            }
                            extra_segment = true;
                            (
                                create_segment(env, &cfg, scan.next_lsn).await?,
                                scan.next_lsn,
                            )
                        } else {
                            let file = env.fs.open(path, OpenMode::ReadWriteCreate).await?;
                            if scan.has_tail {
                                truncated_bytes = image.len() as u64 - scan.valid_end;
                                file.set_len(scan.valid_end).await?;
                                file.sync_data().await?;
                            }
                            let end = scan.valid_end as usize;
                            let index =
                                turn_index_from_image(image.get(..end).ok_or_else(|| {
                                    corrupt("segment valid end is past the file")
                                })?)?;
                            (
                                Segment {
                                    start_lsn: start,
                                    file,
                                    offset: scan.valid_end,
                                    opened_at: env.clock.monotonic(),
                                    index,
                                },
                                scan.next_lsn,
                            )
                        }
                    }
                }
            }
        };
        let segments = starts.len() + usize::from(extra_segment);
        let first_lsn = starts.first().copied().unwrap_or(cfg.first_lsn);
        let (tx, rx) = mpsc::unbounded_channel();
        env.spawn(
            "log-writer",
            writer(env.clone(), cfg, segment, rx, next_lsn, committed, fatal),
        );
        Ok((
            Log { tx },
            Opened {
                next_lsn,
                truncated_bytes,
                segments,
                recreated_active,
                first_lsn,
            },
        ))
    }

    /// Appends records in order; resolves with the last LSN once all are
    /// fsynced. Records queued together share writes and fsyncs.
    pub async fn append_all(&self, records: Vec<Record>) -> Result<Option<Lsn>, LogError> {
        let mut waiting = Vec::with_capacity(records.len());
        for record in records {
            let (done, rx) = oneshot::channel();
            self.tx
                .send(Append { record, done })
                .map_err(|_| LogError::Stopped("writer task ended".into()))?;
            waiting.push(rx);
        }
        let mut last = None;
        for rx in waiting {
            let lsn = rx
                .await
                .map_err(|_| LogError::Stopped("writer task ended".into()))?
                .map_err(LogError::Stopped)?;
            last = Some(lsn);
        }
        Ok(last)
    }

    /// Appends a record; resolves with its LSN once it is fsynced.
    pub async fn append(&self, record: Record) -> Result<Lsn, LogError> {
        let (done, rx) = oneshot::channel();
        self.tx
            .send(Append { record, done })
            .map_err(|_| LogError::Stopped("writer task ended".into()))?;
        rx.await
            .map_err(|_| LogError::Stopped("writer task ended".into()))?
            .map_err(LogError::Stopped)
    }
}

async fn writer(
    env: Env,
    cfg: LogConfig,
    mut seg: Segment,
    mut rx: mpsc::UnboundedReceiver<Append>,
    mut next_lsn: Lsn,
    committed: mpsc::UnboundedSender<Committed>,
    fatal: oneshot::Sender<String>,
) {
    while let Some(first) = rx.recv().await {
        if !cfg.group_commit_window.is_zero() {
            env.clock.sleep(cfg.group_commit_window).await;
        }
        let mut batch = vec![first];
        while let Ok(a) = rx.try_recv() {
            batch.push(a);
        }
        let result = write_batch(&env, &cfg, &mut seg, &mut next_lsn, batch, &committed).await;
        if let Err((msg, batch)) = result {
            // Never retry a failed write or fsync: fail every waiter and stop.
            for a in batch {
                let _ = a.done.send(Err(msg.clone()));
            }
            while let Ok(a) = rx.try_recv() {
                let _ = a.done.send(Err(msg.clone()));
            }
            let _ = fatal.send(msg);
            return;
        }
    }
}

type BatchError = (String, Vec<Append>);

/// Appends the footer at the segment's current end and fsyncs it. The caller
/// then switches to a new segment; nothing is appended after the footer.
async fn write_footer(seg: &Segment) -> Result<(), LogError> {
    let payload = footer_payload(&seg.index)?;
    let mut buf = Vec::new();
    encode_raw_entry(0, FOOTER_KIND, &payload, &mut buf);
    seg.file.write_at(seg.offset, Bytes::from(buf)).await?;
    seg.file.sync_data().await?;
    Ok(())
}

async fn write_batch(
    env: &Env,
    cfg: &LogConfig,
    seg: &mut Segment,
    next_lsn: &mut Lsn,
    batch: Vec<Append>,
    committed: &mpsc::UnboundedSender<Committed>,
) -> Result<(), BatchError> {
    let has_entries = *next_lsn > seg.start_lsn;
    let age = env.clock.monotonic().saturating_sub(seg.opened_at);
    if has_entries && (seg.offset >= cfg.segment_max_bytes || age >= cfg.segment_max_age) {
        if let Err(e) = write_footer(seg).await {
            return Err((format!("segment footer failed: {e}"), batch));
        }
        match create_segment(env, cfg, *next_lsn).await {
            Ok(new) => *seg = new,
            Err(e) => return Err((format!("segment roll failed: {e}"), batch)),
        }
    }
    let mut buf = Vec::new();
    let mut offsets = Vec::with_capacity(batch.len());
    for (i, a) in batch.iter().enumerate() {
        let at = seg.offset + buf.len() as u64;
        offsets.push(at);
        remember_turn(&mut seg.index, &a.record, at);
        encode_entry(*next_lsn + i as u64, &a.record, &mut buf);
    }
    let len = buf.len() as u64;
    let first_lsn = *next_lsn;
    let mut res = seg.file.write_at(seg.offset, Bytes::from(buf)).await;
    let mut batch = batch;
    if cfg.mutation_ack_before_fsync && res.is_ok() {
        deliver(
            seg.start_lsn,
            first_lsn,
            &offsets,
            batch.drain(..),
            committed,
        );
    }
    if res.is_ok() {
        let started = env.clock.monotonic();
        res = seg.file.sync_data().await;
        kronik_metrics::observe(
            "kronik_log_fsync_duration_seconds",
            &[],
            env.clock.monotonic().saturating_sub(started),
        );
    }
    if let Err(e) = res {
        return Err((format!("log write/fsync failed: {e}"), batch));
    }
    seg.offset += len;
    *next_lsn += offsets.len() as u64;
    kronik_metrics::add(
        "kronik_log_records_appended_total",
        &[],
        offsets.len() as u64,
    );
    deliver(
        seg.start_lsn,
        first_lsn,
        &offsets,
        batch.into_iter(),
        committed,
    );
    Ok(())
}

fn deliver(
    segment: Lsn,
    first_lsn: Lsn,
    offsets: &[u64],
    batch: impl Iterator<Item = Append>,
    committed: &mpsc::UnboundedSender<Committed>,
) {
    for (i, a) in batch.enumerate() {
        let lsn = first_lsn + i as u64;
        let _ = committed.send(Committed {
            lsn,
            pos: Position {
                segment,
                offset: offsets[i],
            },
            record: a.record,
        });
        let _ = a.done.send(Ok(lsn));
    }
}

/// Reads durable records. Safe to use while the writer appends, as long as
/// `upto` is at most the last acknowledged LSN.
#[derive(Clone)]
pub struct LogReader {
    env: Env,
    dir: PathBuf,
    branch: String,
}

impl LogReader {
    pub fn new(env: Env, dir: PathBuf, branch: impl Into<String>) -> LogReader {
        LogReader {
            env,
            dir,
            branch: branch.into(),
        }
    }

    /// The directory the segments live in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Segment start LSNs, ascending. Uses the env filesystem so the
    /// simulator sees the same directory the writer does.
    pub async fn starts(&self) -> Result<Vec<Lsn>, LogError> {
        list_segments(&self.env, &self.dir).await
    }

    /// The raw bytes of the segment that starts at `start`.
    pub async fn read_image(&self, start: Lsn) -> Result<Vec<u8>, LogError> {
        read_file(&self.env, self.dir.join(segment_name(start))).await
    }

    /// Calls `f` for every record with `from <= lsn <= upto`, in LSN order.
    pub async fn read(
        &self,
        from: Lsn,
        upto: Lsn,
        mut f: impl FnMut(Committed) -> Result<(), LogError>,
    ) -> Result<(), LogError> {
        let starts = list_segments(&self.env, &self.dir).await?;
        let mut expected: Option<Lsn> = None;
        for (i, &start) in starts.iter().enumerate() {
            let last = i + 1 == starts.len();
            if let Some(&next) = starts.get(i + 1)
                && next <= from
            {
                continue;
            }
            if start > upto {
                break;
            }
            let path = self.dir.join(segment_name(start));
            let image = read_file(&self.env, path.clone()).await?;
            let header = parse_header(&image).ok_or_else(|| {
                corrupt(format!("segment {} has no valid header", path.display()))
            })?;
            if header.start_lsn != start || header.branch != self.branch {
                return Err(corrupt(format!(
                    "segment {} header mismatch",
                    path.display()
                )));
            }
            if let Some(exp) = expected
                && exp != start
            {
                return Err(corrupt(format!(
                    "segment {} starts at lsn {start}, expected {exp}",
                    path.display()
                )));
            }
            let mut records = Vec::new();
            let scan = scan_entries(&image, &header, from, upto, |c| {
                records.push(c);
                Ok::<_, LogError>(())
            })?;
            if scan.has_tail && !last {
                return Err(corrupt(format!(
                    "closed segment {} is invalid at offset {}",
                    path.display(),
                    scan.valid_end
                )));
            }
            expected = Some(scan.next_lsn);
            for c in records {
                f(c)?;
            }
            if scan.next_lsn > upto {
                break;
            }
        }
        Ok(())
    }

    /// Reads the record at a known position.
    pub async fn read_at(&self, pos: Position) -> Result<Committed, LogError> {
        let path = self.dir.join(segment_name(pos.segment));
        let file = self.env.fs.open(path, OpenMode::Read).await?;
        let head = file.read_at(pos.offset, ENVELOPE_LEN).await?;
        let len = u32_at(&head, 0).ok_or_else(|| corrupt("short entry header"))?;
        if len > MAX_RECORD {
            return Err(corrupt(format!("entry length {len} at {pos:?}")));
        }
        let mut image = head;
        image.extend(
            file.read_at(pos.offset + ENVELOPE_LEN as u64, len as usize)
                .await?,
        );
        let e = parse_entry(&image, 0).ok_or_else(|| corrupt(format!("bad entry at {pos:?}")))?;
        let record = Record::decode(e.kind, e.payload)
            .map_err(|err| corrupt(format!("record at lsn {}: {err}", e.lsn)))?;
        Ok(Committed {
            lsn: e.lsn,
            pos,
            record,
        })
    }
}

#[cfg(test)]
mod tests;
