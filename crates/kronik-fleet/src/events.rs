//! Versioned operational events. The shared keyed Mapper is the disclosure boundary.

use std::borrow::Cow;
use std::collections::BTreeMap;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{SourcePos, hex};
use kronik_log::MetadataAuditRecord;
use kronik_otel::audit::{Line, Mapper};
use kronik_proto::{Record, log::v1 as pb};
use kronik_sched::ShardReader;
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "kronik.event/v1";
pub const CURSOR_SCHEMA: &str = "kronik.events-cursor/v1";
pub const MAX_STREAMS: usize = kronik_proto::MAX_SHARD_COUNT as usize + 2;
/// Canonical cursor payload budget; HTTP request/header limits are separate.
pub const MAX_CURSOR_BYTES: usize = MAX_STREAMS * 128 + 1024;
pub const MAX_EVENTS: usize = 256;
pub const MAX_PAGE_BYTES: usize = 1 << 20;
pub const MAX_SCAN_RECORDS: u64 = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub installation: String,
    /// Actor-feed selection only; metadata has no actor-branch provenance.
    pub branch: String,
}

impl Identity {
    pub fn validate(&self) -> Result<(), String> {
        if !label(&self.installation) || !label(&self.branch) {
            return Err("events_identity".into());
        }
        Ok(())
    }
}

fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}

/// A namespace, never a global ordering relation or a caller-selected authority.
pub fn domain(source: SourcePos) -> Cow<'static, str> {
    match source {
        SourcePos::Actor { shard: None, .. } => Cow::Borrowed("actor-native"),
        SourcePos::Actor { shard: Some(shard), .. } => Cow::Owned(format!("actor-{shard}")),
        SourcePos::Metadata { .. } => Cow::Borrowed("metadata"),
    }
}

/// The coordinate is meaningful only within this exact typed source namespace.
pub fn coordinate(source: SourcePos) -> u64 {
    match source {
        SourcePos::Actor { lsn, .. } => lsn,
        SourcePos::Metadata { index } => index,
    }
}

fn valid_source(source: SourcePos) -> bool {
    coordinate(source) > 0 && match source {
        SourcePos::Actor { shard: Some(shard), .. } => shard < kronik_proto::MAX_SHARD_COUNT,
        _ => true,
    }
}

/// Next event to read in one actual source, not a synthetic actor LSN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Position {
    pub source: SourcePos,
    pub subindex: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumeCursor {
    pub schema: String,
    pub identity: Identity,
    pub streams: BTreeMap<String, Position>,
}

impl ResumeCursor {
    pub fn new(identity: Identity) -> Self {
        Self { schema: CURSOR_SCHEMA.into(), identity, streams: BTreeMap::new() }
    }

    pub fn validate(&self, identity: &Identity) -> Result<(), String> {
        identity.validate()?;
        if self.schema != CURSOR_SCHEMA || &self.identity != identity
            || self.streams.len() > MAX_STREAMS
            || self.streams.iter().any(|(key, position)|
                !valid_source(position.source) || key != domain(position.source).as_ref())
        {
            return Err("events_cursor".into());
        }
        Ok(())
    }

    /// Explicit rewind; ordinary authorization, reason and audit belong to the caller.
    pub fn rewind(&mut self, to: Position) -> Result<(), String> {
        self.validate(&self.identity)?;
        let key = domain(to.source);
        if !valid_source(to.source)
            || (!self.streams.contains_key(key.as_ref()) && self.streams.len() == MAX_STREAMS)
        {
            return Err("events_cursor".into());
        }
        self.streams.insert(key.into_owned(), to);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FleetPhase {
    Pending,
    Requested,
    Active,
    Revoked,
}

/// Presence marks imported native history, never a new creation or permission
/// grant. False is archival history; true is the captured current projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeAdoption {
    pub current_projection: bool,
}

/// Free text and identity-bearing audit details stay behind the ordinary record API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventData {
    pub schema: String,
    pub kind: String,
    pub action: String,
    pub at_wall_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<FleetPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adoption: Option<NativeAdoption>,
    /// Sole shared M28 keyed identity, never a legacy plaintext digest.
    pub record_hash: String,
}

impl EventData {
    fn from_line(line: Line, record: &Record) -> Result<Self, ApiError> {
        let phase = if matches!(record, Record::AuditEvent(event)
            if matches!(event.operation.as_ref(), Some(kronik_proto::log::v1::audit_event::Operation::FleetState(_))))
        {
            let value = line.details.get("phase").ok_or_else(||
                ApiError::new(ErrorCode::StorageCorrupt, "missing typed fleet phase"))?;
            Some(FleetPhase::deserialize(value).map_err(|_|
                ApiError::new(ErrorCode::StorageCorrupt, "invalid typed fleet phase"))?)
        } else { None };
        // Only the canonical mapper sets this closed fact after source validation.
        // Wire-origin fields and free Line.details are not consumer provenance.
        let adoption = line.native_adoption_current_projection()
            .map(|current_projection| NativeAdoption { current_projection });
        Ok(Self { schema: line.schema, kind: line.kind, action: line.action,
            at_wall_ms: line.at_wall_ms, epoch: line.epoch, effect: line.effect, phase, adoption,
            record_hash: line.record_hash })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: String,
    pub id: String,
    pub installation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub source: SourcePos,
    pub subindex: u32,
    pub record_kind: u8,
    pub data: EventData,
}

impl Event {
    /// Canonical v1 wire bytes: struct field order, compact JSON, no newline.
    pub fn body(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|_| "events_encode".into())
    }
}

/// Canonical operational identity, not sealed-value identity; no legacy hash fallback.
pub fn event_id(identity: &Identity, source: SourcePos, actor_branch: Option<&str>,
    subindex: u32, record_hash: &str) -> Result<String, String> {
    identity.validate()?;
    match (source, actor_branch) {
        (SourcePos::Actor { .. }, Some(branch)) => {
            kronik_proto::validate_source_branch(branch).map_err(|_| "events_source")?;
        }
        (SourcePos::Metadata { .. }, None) => {},
        _ => return Err("events_source".into()),
    }
    if !valid_source(source) { return Err("events_source".into()); }
    let hash = record_hash.strip_prefix("b3k:v3:").ok_or("events_record_hash")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("events_record_hash".into());
    }
    let installation = hex(identity.installation.as_bytes());
    Ok(match source {
        SourcePos::Actor { shard, lsn } => {
            let branch = hex(actor_branch.ok_or("events_source")?.as_bytes());
            match shard {
                None => format!("ke1.{installation}.{branch}.actor.native.{lsn}.{subindex}.{hash}"),
                Some(shard) => format!("ke1.{installation}.{branch}.actor.{shard}.{lsn}.{subindex}.{hash}"),
            }
        }
        SourcePos::Metadata { index } => format!("ke1.{installation}.metadata.{index}.{subindex}.{hash}"),
    })
}

/// Projects an actual committed actor record or actual typed metadata AuditEvent.
/// Never substitute an empty catalogue for a failed Node inventory or invent a source LSN.
pub fn project(
    mapper: &Mapper,
    identity: &Identity,
    source: &pb::ActorSource,
    record: &Record,
    secrets: &[(&str, &[u8])],
) -> Result<Vec<Event>, ApiError> {
    identity.validate().map_err(bad_cursor)?;
    source.validate().map_err(|_| ApiError::new(ErrorCode::StorageCorrupt, "invalid operational actor source"))?;
    let position = SourcePos::Actor { shard: source.shard, lsn: source.lsn };
    let lines = mapper.operational_lines_actor_at(source, record, secrets)?;
    project_lines(identity, position, Some(&source.branch), record, lines)
}

/// Consume an actual metadata record envelope without dropping its adoption
/// sidecar. The sole canonical mapper validates the record/origin relationship.
pub fn project_metadata(mapper: &Mapper, identity: &Identity, source: &MetadataAuditRecord,
    secrets: &[(&str, &[u8])]) -> Result<Vec<Event>, ApiError>
{
    identity.validate().map_err(bad_cursor)?;
    let lines = mapper.operational_lines_metadata(source, secrets)?;
    project_lines(identity, SourcePos::Metadata { index: source.index }, None, &source.record, lines)
}

fn project_lines(identity: &Identity, source: SourcePos, actor_branch: Option<&str>, record: &Record,
    lines: Vec<Line>) -> Result<Vec<Event>, ApiError>
{
    lines.into_iter().enumerate().map(|(index, data)| {
            let subindex = u32::try_from(index).map_err(|_| ApiError::new(ErrorCode::Internal, "events_limit"))?;
            let id = event_id(identity, source, actor_branch, subindex, &data.record_hash)
                .map_err(|_| ApiError::new(ErrorCode::Unavailable, "keyed operational identity is unavailable"))?;
            Ok(Event { schema: SCHEMA.into(), id, installation: identity.installation.clone(),
                branch: actor_branch.map(str::to_owned),
                source, subindex, record_kind: record.kind(), data: EventData::from_line(data, record)? })
        }).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub from: SourcePos,
    pub through: SourcePos,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub events: Vec<Event>,
    pub cursor: ResumeCursor,
    pub applied: SourcePos,
    pub gap: Option<Gap>,
    pub more: bool,
}

/// Bounded actor-log page. Metadata adapters retain their actual envelopes for `project_metadata`.
/// A gap is acknowledged explicitly before reading events at its returned cursor.
pub async fn page(
    reader: &ShardReader,
    mapper: &Mapper,
    identity: &Identity,
    cursor: &ResumeCursor,
    secrets: &[(&str, &[u8])],
    limit: usize,
) -> Result<Page, ApiError> {
    cursor.validate(identity).map_err(bad_cursor)?;
    reader.check()?;
    let SourcePos::Actor { shard, lsn: applied } = reader.point().source else {
        return Err(ApiError::new(ErrorCode::StorageCorrupt, "actor events require an actual actor reader"));
    };
    let source_at = |lsn| SourcePos::Actor { shard, lsn };
    if !valid_source(source_at(1)) || limit == 0 || limit > MAX_EVENTS {
        return Err(bad_cursor("events_cursor"));
    }
    let first = reader.point().retained_from.max(1);
    let key = domain(source_at(1));
    let position = cursor.streams.get(key.as_ref()).copied()
        .unwrap_or(Position { source: source_at(first), subindex: 0 });
    let mut next_lsn = coordinate(position.source);
    let mut subindex = position.subindex;
    if next_lsn > applied.saturating_add(1) || (next_lsn > applied && subindex != 0) {
        return Err(bad_cursor("events_cursor_ahead"));
    }
    let mut result = Page { events: Vec::new(), cursor: cursor.clone(), applied: source_at(applied),
        gap: None, more: false };
    if next_lsn < first {
        result.gap = Some(Gap { from: source_at(next_lsn), through: source_at(first - 1) });
        result.cursor.rewind(Position { source: source_at(first), subindex: 0 }).map_err(bad_cursor)?;
        result.more = first <= applied;
        return Ok(result);
    }
    let scan = reader.local_export_page(next_lsn - 1, MAX_SCAN_RECORDS as usize, MAX_PAGE_BYTES).await?;
    let mut bytes = 0;
    let mut complete = true;
    'records: for (source, committed) in scan.records {
        if source.shard != shard || source.lsn != committed.lsn {
            return Err(ApiError::new(ErrorCode::StorageCorrupt, "operational frame left its captured source"));
        }
        if committed.lsn > next_lsn {
            if result.events.is_empty() {
                result.gap = Some(Gap { from: source_at(next_lsn), through: source_at(committed.lsn - 1) });
                next_lsn = committed.lsn;
                subindex = 0;
            }
            complete = false;
            break;
        }
        let events = project(mapper, identity, &source, &committed.record, secrets)?;
        if subindex as usize > events.len() { return Err(bad_cursor("events_cursor_subindex")); }
        for event in events.into_iter().skip(subindex as usize) {
            let size = event.body().map_err(|error| ApiError::new(ErrorCode::Internal, error))?.len();
            if size > MAX_PAGE_BYTES { return Err(ApiError::new(ErrorCode::Internal, "events_limit")); }
            if result.events.len() == limit || bytes + size > MAX_PAGE_BYTES {
                complete = false;
                break 'records;
            }
            bytes += size;
            subindex += 1;
            result.events.push(event);
        }
        next_lsn = committed.lsn.saturating_add(1);
        subindex = 0;
    }
    if complete { next_lsn = next_lsn.max(scan.scanned_through.saturating_add(1)); }
    reader.check()?;
    result.more = next_lsn <= applied;
    result.cursor.rewind(Position { source: source_at(next_lsn), subindex }).map_err(bad_cursor)?;
    Ok(result)
}

pub(crate) fn metadata_batch(
    source: &dyn kronik_log::MetadataAuditSource,
    from: u64,
    limit: usize,
) -> Result<kronik_log::MetadataAuditBatch, ApiError> {
    if from == 0 || limit == 0 || limit > kronik_log::MAX_METADATA_AUDIT_RECORDS {
        return Err(bad_cursor("events_limit"));
    }
    let batch = source.read_from(from, limit)?;
    if batch.covered_from == 0 || batch.scanned_through > batch.durable_through
        || batch.covered_from > batch.durable_through.saturating_add(1)
        || batch.records.len() > limit
        || (batch.records.len() == limit
            && batch.records.last().is_none_or(|record| record.index != batch.scanned_through))
        || (batch.records.len() < limit && batch.scanned_through != batch.durable_through)
        || (from <= batch.durable_through && batch.scanned_through < from)
        || batch.records.windows(2).any(|pair| pair[0].index >= pair[1].index)
        || batch.records.iter().any(|record| record.index < from || record.index > batch.scanned_through)
    {
        return Err(ApiError::new(ErrorCode::StorageCorrupt, "invalid metadata audit coverage"));
    }
    Ok(batch)
}

/// One captured durable metadata image; non-audit indexes are covered, not gaps.
/// The caller must obtain this complete catalogue fail closed before calling.
pub fn metadata_page(
    source: &dyn kronik_log::MetadataAuditSource,
    mapper: &Mapper,
    identity: &Identity,
    cursor: &ResumeCursor,
    secrets: &[(&str, &[u8])],
    limit: usize,
) -> Result<Page, ApiError> {
    cursor.validate(identity).map_err(bad_cursor)?;
    if limit == 0 || limit > MAX_EVENTS { return Err(bad_cursor("events_limit")); }
    let from = cursor.streams.get("metadata").map_or(1, |position| coordinate(position.source));
    let batch = metadata_batch(source, from, limit)?;
    metadata_page_from_batch(batch, mapper, identity, cursor, secrets, limit)
}

// Callers validate the cursor and capture this exact bounded image before rendering.
pub(crate) fn metadata_page_from_batch(
    batch: kronik_log::MetadataAuditBatch,
    mapper: &Mapper,
    identity: &Identity,
    cursor: &ResumeCursor,
    secrets: &[(&str, &[u8])],
    limit: usize,
) -> Result<Page, ApiError> {
    let at = |index| SourcePos::Metadata { index };
    let start = cursor.streams.get("metadata").copied()
        .unwrap_or(Position { source: at(1), subindex: 0 });
    let from = coordinate(start.source);
    if from > batch.durable_through.saturating_add(1)
        || (from > batch.durable_through && start.subindex != 0)
    {
        return Err(bad_cursor("events_cursor_ahead"));
    }
    let mut result = Page { events: Vec::new(), cursor: cursor.clone(),
        applied: at(batch.durable_through), gap: None, more: false };
    if from < batch.covered_from {
        result.gap = Some(Gap { from: at(from), through: at(batch.covered_from - 1) });
        result.cursor.rewind(Position { source: at(batch.covered_from), subindex: 0 }).map_err(bad_cursor)?;
        result.more = batch.covered_from <= batch.durable_through;
        return Ok(result);
    }
    if start.subindex > 0 && batch.records.first().is_none_or(|record| record.index != from) {
        return Err(bad_cursor("events_cursor_subindex"));
    }
    let mut next = from;
    let mut subindex = start.subindex;
    let mut bytes = 0;
    for record in batch.records {
        let index = record.index;
        if index != next { next = index; subindex = 0; }
        let events = project_metadata(mapper, identity, &record, secrets)?;
        if subindex as usize > events.len() { return Err(bad_cursor("events_cursor_subindex")); }
        for event in events.into_iter().skip(subindex as usize) {
            let size = event.body().map_err(|error| ApiError::new(ErrorCode::Internal, error))?.len();
            if size > MAX_PAGE_BYTES { return Err(ApiError::new(ErrorCode::Internal, "events_limit")); }
            if result.events.len() == limit || bytes + size > MAX_PAGE_BYTES {
                result.cursor.rewind(Position { source: at(next), subindex }).map_err(bad_cursor)?;
                result.more = next <= batch.durable_through;
                return Ok(result);
            }
            bytes += size;
            subindex += 1;
            result.events.push(event);
        }
        next = index.checked_add(1).ok_or_else(|| bad_cursor("metadata position exhausted"))?;
        subindex = 0;
    }
    next = next.max(batch.scanned_through.checked_add(1)
        .ok_or_else(|| bad_cursor("metadata position exhausted"))?);
    result.cursor.rewind(Position { source: at(next), subindex: 0 }).map_err(bad_cursor)?;
    result.more = next <= batch.durable_through;
    Ok(result)
}

pub fn resume_after(event: &Event, cursor: &ResumeCursor) -> Result<ResumeCursor, String> {
    cursor.validate(&cursor.identity)?;
    let branch_matches = match event.source {
        SourcePos::Actor { .. } => event.branch.as_deref().is_some_and(|branch|
            kronik_proto::validate_source_branch(branch).is_ok()),
        SourcePos::Metadata { .. } => event.branch.is_none(),
    };
    if event.installation != cursor.identity.installation || !branch_matches {
        return Err("events_identity".into());
    }
    let mut next = cursor.clone();
    next.rewind(Position { source: event.source,
        subindex: event.subindex.checked_add(1).ok_or("events_cursor")? })?;
    Ok(next)
}

pub fn sse_event(event: &Event, cursor: &ResumeCursor) -> Result<String, String> {
    let body = serde_json::to_string(event).map_err(|_| "events_encode".to_owned())?;
    let id = serde_json::to_string(&resume_after(event, cursor)?)
        .map_err(|_| "events_encode".to_owned())?;
    Ok(format!("id: {id}\nevent: operational\ndata: {body}\n\n"))
}

/// Publish the cursor even when a page contains only omitted records or a gap.
pub fn sse_cursor(page: &Page) -> Result<String, String> {
    let body = serde_json::to_string(page).map_err(|_| "events_encode".to_owned())?;
    let id = serde_json::to_string(&page.cursor).map_err(|_| "events_encode".to_owned())?;
    Ok(format!("id: {id}\nevent: {}\ndata: {body}\n\n", if page.gap.is_some() { "gap" } else { "cursor" }))
}

fn bad_cursor(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}

pub fn schemas() -> Result<serde_json::Value, serde_json::Error> {
    serde_json::from_str(include_str!("../../../docs/reference/events.schema.json"))
}
