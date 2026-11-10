//! The audit line mapping (docs/design/m28-otel.md §4.1, §4.3; ADRs 0082,
//! 0083): which records are audited, and the `kronik.audit/v3` line of each,
//! as pure functions of the record. The exporter, `kronik audit show` and
//! `kronik audit verify` all build lines here.

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{SourcePos, hex};
use kronik_log::LogError;
use kronik_privacy::sealer::Sealer;
use kronik_proto::log::v1 as pb;
use kronik_proto::{Record, sealables};
use kronik_sched::scrub::AuditPositions;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::spans::ActorKeys;

/// The `schema` of every line.
pub const SCHEMA: &str = "kronik.audit/v3";

const LEGACY_SCHEMA: &str = "kronik.audit/v1";
const LEGACY_V2_SCHEMA: &str = "kronik.audit/v2";

/// Source-derived operational events that do not change archive completeness.
pub const OPERATIONAL_SCHEMA: &str = "kronik.operation/v1";

/// The cap on a line's `reason`, in bytes (§4.3).
pub const REASON_MAX: usize = 4096;

/// What the export does with a record (§4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// One line per record.
    Record,
    /// A line for an operator send or resend, and one per `secret.reveal`
    /// effect.
    Turn,
    /// Carries an `Audit`, but is not exported: a `TurnBegin` copies its
    /// `TurnRecord`'s, and only fork logs have `BranchCreated`.
    Copy,
    /// Carries no audit and holds no reveal.
    None,
}

/// The classifier. No wildcard arm: a new record kind must be classified
/// here to compile, and `tests/audit.rs` checks every message with an
/// `Audit` field against it (review M4).
pub fn class(record: &Record) -> Class {
    match record {
        Record::Deployment(_)
        | Record::Grant(_)
        | Record::Limits(_)
        | Record::Policy(_)
        | Record::Approval(_)
        | Record::PrivacyMode(_)
        | Record::ForeignActor(_)
        | Record::Erasure(_)
        | Record::EngineUpgrade(_)
        | Record::SimulatorConfig(_)
        | Record::GuardTriggered(_)
        | Record::AuditEvent(_)
        | Record::SecretVersion(_)
        | Record::SecretLink(_) => Class::Record,
        // A rebase's switch is the mutation (`rollback --by-replay`); its
        // rebased turns are what the fork recorded, not operator actions.
        Record::StateRebase(r) => match &r.part {
            Some(pb::state_rebase::Part::Switch(_)) => Class::Record,
            _ => Class::Copy,
        },
        Record::TurnRecord(_) => Class::Turn,
        Record::TurnBegin(_) | Record::BranchCreated(_) => Class::Copy,
        Record::EffectResult(_) | Record::SnapshotMarker(_) => Class::None,
    }
}

/// One exported line, keys in §4.3's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Line {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourcePos>,
    /// The effect ordinal of a reveal line; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<u32>,
    pub kind: String,
    pub action: String,
    pub at_wall_ms: u64,
    pub token_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reason_truncated: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    pub details: Map<String, Value>,
    pub record_hash: String,
    #[serde(skip)]
    #[schemars(skip)]
    native_adoption_current_projection: Option<bool>,
}

impl Line {
    /// Closed source provenance from the Mapper, never inferred from free details.
    pub fn native_adoption_current_projection(&self) -> Option<bool> {
        self.native_adoption_current_projection
    }

    /// The line as written to a sink, without its `\n`.
    pub fn to_json(&self) -> String {
        // A struct of strings, integers and JSON values always serializes.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Exact source namespace, position and optional effect ordinal.
    pub fn item(&self) -> (&str, Option<SourcePos>, Option<u64>, Option<u32>) {
        (&self.branch, self.source, self.lsn, self.effect)
    }
}

/// What a line needs from outside the record.
pub struct Ctx<'a> {
    pub branch: &'a str,
    /// `[otel] actor_keys`, for the actor of a send, a reveal and a
    /// `fork.send` (§3.5).
    pub keys: &'a ActorKeys<'a>,
    /// A subject id as `s:` + 12 hex (the diff's keyed subject hash).
    pub subject: &'a dyn Fn(&str) -> String,
    /// The protected, already-loaded identity key; absence fails closed.
    pub sealer: &'a Sealer,
    /// Every stored secret value, scrubbed from free text (I8).
    pub secrets: &'a [(&'a str, &'a [u8])],
}

/// `[otel] actor_keys`, owned by the exporter and the API.
pub enum Keys {
    Hashed(crate::keys::KeyHasher),
    Plain,
    Omit,
}

/// A node's line builder: its key setting and its subject hash.
pub struct Mapper {
    pub keys: Keys,
    pub sealer: std::sync::Arc<kronik_privacy::sealer::Sealer>,
    pub branch: String,
}

impl Mapper {
    /// [`lines`] of a committed record, with `secrets` scrubbed.
    pub fn lines(
        &self,
        lsn: u64,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        self.lines_at(SourcePos::Actor { shard: None, lsn }, record, secrets)
    }

    pub fn lines_at(
        &self,
        source: SourcePos,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        self.lines_in(source, &self.branch, record, secrets)
    }

    pub fn lines_actor_at(
        &self,
        source: &pb::ActorSource,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        source
            .validate()
            .map_err(|_| corruption(LogError::Corrupt("invalid actor source".into())))?;
        self.lines_in(
            SourcePos::Actor {
                shard: source.shard,
                lsn: source.lsn,
            },
            &source.branch,
            record,
            secrets,
        )
    }

    /// Consume the record and adoption facts from one authoritative metadata image.
    pub fn lines_metadata(
        &self,
        source: &kronik_log::MetadataAuditRecord,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        source.validate()?;
        let mut lines = self.lines_at(
            SourcePos::Metadata {
                index: source.index,
            },
            &source.record,
            secrets,
        )?;
        if let Some(origin) = &source.native_origin {
            for line in &mut lines {
                line.details
                    .insert("native_origin".into(), native_origin_details(origin)?);
                line.native_adoption_current_projection = Some(origin.current_projection);
            }
        }
        Ok(lines)
    }

    /// The metadata union contains no actor turns or separate dead-letter events.
    pub fn operational_lines_metadata(
        &self,
        source: &kronik_log::MetadataAuditRecord,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        self.lines_metadata(source, secrets)
    }

    fn lines_in(
        &self,
        source: SourcePos,
        branch: &str,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        let hashed = |kind: &str, key: &str| match &self.keys {
            Keys::Hashed(h) => h.label(kind, key),
            _ => String::new(),
        };
        let keys = match &self.keys {
            Keys::Hashed(_) => ActorKeys::Hashed(&hashed),
            Keys::Plain => ActorKeys::Plain,
            Keys::Omit => ActorKeys::Omit,
        };
        let subject = |s: &str| subject_label(&self.sealer, s);
        lines_at(
            source,
            record,
            &Ctx {
                branch,
                keys: &keys,
                subject: &subject,
                sealer: &self.sealer,
                secrets,
            },
        )
    }

    pub fn operational_lines(
        &self,
        lsn: u64,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        self.operational_lines_at(SourcePos::Actor { shard: None, lsn }, record, secrets)
    }

    /// The same Mapper pipeline, with actual actor or metadata source positions.
    pub fn operational_lines_at(
        &self,
        source: SourcePos,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        self.operational_lines_in(source, &self.branch, record, secrets)
    }

    pub fn operational_lines_actor_at(
        &self,
        source: &pb::ActorSource,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        source
            .validate()
            .map_err(|_| corruption(LogError::Corrupt("invalid actor source".into())))?;
        self.operational_lines_in(
            SourcePos::Actor {
                shard: source.shard,
                lsn: source.lsn,
            },
            &source.branch,
            record,
            secrets,
        )
    }

    fn operational_lines_in(
        &self,
        source: SourcePos,
        branch: &str,
        record: &Record,
        secrets: &[(&str, &[u8])],
    ) -> Result<Vec<Line>, ApiError> {
        let mut out = self.lines_in(source, branch, record, secrets)?;
        let Record::TurnRecord(turn) = record else {
            return Ok(out);
        };
        let Some((outcome_kind, outcome, input_class)) = dead_letter(turn) else {
            return Ok(out);
        };
        // Runtime producers use CoreErrorCode; guest rejection text is never projected.
        let error_code = ErrorCode::parse(&outcome.error_code).ok_or_else(|| {
            corruption(LogError::Corrupt("invalid dead-letter error code".into()))
        })?;
        let hash = match out.first() {
            Some(line) => line.record_hash.clone(),
            None => record_hash(record, &self.sealer).ok_or_else(identity_unavailable)?,
        };
        let mut details = obj(json!({
            "input_class": input_class,
            "outcome": label(outcome_kind.as_str_name(), "OUTCOME_KIND_"),
            "error_code": error_code.as_str(),
        }));
        if let Some(actor) = &turn.actor {
            if !kronik_core::ids::valid_kind(&actor.kind)
                || !kronik_core::ids::valid_key(&actor.key)
            {
                return Err(corruption(LogError::Corrupt(
                    "invalid dead-letter actor identity".into(),
                )));
            }
            let key = match &self.keys {
                Keys::Hashed(hasher) => Some(hasher.label(&actor.kind, &actor.key)),
                Keys::Plain => Some(actor.key.clone()),
                Keys::Omit => None,
            };
            if let Some(key) = key {
                details.insert("actor".into(), format!("{}/{key}", actor.kind).into());
            }
        }
        let audit = match turn.input.as_ref().and_then(|input| input.kind.as_ref()) {
            Some(pb::input::Kind::Message(message)) => message.audit.as_ref(),
            _ => None,
        };
        out.push(Line {
            schema: OPERATIONAL_SCHEMA.into(),
            lsn: match source {
                SourcePos::Actor { lsn, .. } => Some(lsn),
                SourcePos::Metadata { .. } => None,
            },
            source: match source {
                SourcePos::Actor { shard: None, .. } => None,
                _ => Some(source),
            },
            effect: None,
            kind: "deadletter".into(),
            action: "created".into(),
            at_wall_ms: turn.logical_time_ms,
            token_id: audit
                .map(|audit| audit.token_id.as_str())
                .filter(|token| !token.is_empty())
                .unwrap_or("system")
                .into(),
            reason: "failed input stored as dead letter".into(),
            reason_truncated: false,
            branch: branch.to_owned(),
            epoch: None,
            details,
            record_hash: hash,
            native_adoption_current_projection: None,
        });
        Ok(out)
    }

    /// Record-derived verification identities; legacy hashes never leave this type.
    pub fn expected(&self, lsn: u64, record: &Record) -> Result<Vec<Expected>, ApiError> {
        self.expected_at(SourcePos::Actor { shard: None, lsn }, record)
    }

    pub fn expected_at(
        &self,
        source: SourcePos,
        record: &Record,
    ) -> Result<Vec<Expected>, ApiError> {
        self.expected_in(source, &self.branch, record)
    }

    pub fn expected_actor_at(
        &self,
        source: &pb::ActorSource,
        record: &Record,
    ) -> Result<Vec<Expected>, ApiError> {
        source
            .validate()
            .map_err(|_| corruption(LogError::Corrupt("invalid actor source".into())))?;
        self.expected_in(
            SourcePos::Actor {
                shard: source.shard,
                lsn: source.lsn,
            },
            &source.branch,
            record,
        )
    }

    pub fn expected_metadata(
        &self,
        source: &kronik_log::MetadataAuditRecord,
    ) -> Result<Vec<Expected>, ApiError> {
        source.validate()?;
        let mut expected = self.expected_at(
            SourcePos::Metadata {
                index: source.index,
            },
            &source.record,
        )?;
        if let Some(origin) = &source.native_origin {
            for item in &mut expected {
                item.line
                    .details
                    .insert("native_origin".into(), native_origin_details(origin)?);
                item.line.native_adoption_current_projection = Some(origin.current_projection);
            }
        }
        Ok(expected)
    }

    fn expected_in(
        &self,
        source: SourcePos,
        branch: &str,
        record: &Record,
    ) -> Result<Vec<Expected>, ApiError> {
        expected_at(
            source,
            record,
            &Ctx {
                branch,
                keys: &ActorKeys::Omit,
                subject: &|s| subject_label(&self.sealer, s),
                sealer: &self.sealer,
                secrets: &[],
            },
        )
    }
}

/// A subject as the diff shows it: `s:` + 12 hex of its keyed hash, `-`
/// without the master key (ADR 0082).
pub fn subject_label(sealer: &kronik_privacy::sealer::Sealer, subject: &str) -> String {
    match sealer.keyed_hash("kronik diff subject v1", &[subject.as_bytes()]) {
        Some(h) => format!("s:{}", hex(&h[..6])),
        None => "-".into(),
    }
}

/// A private-keyed identity of the existing canonical record metadata.
/// Missing protected key material never falls back to a public digest.
pub fn record_hash(record: &Record, sealer: &Sealer) -> Option<String> {
    let canon = canonical_record(record, &|subject| subject_label(sealer, subject));
    private_identity(canon.kind(), &canon.encode(), sealer)
}

fn private_identity(kind: u8, encoded: &[u8], sealer: &Sealer) -> Option<String> {
    sealer
        .keyed_hash("kronik audit record v3", &[&[kind], encoded])
        .map(|hash| format!("b3k:v3:{}", hex(&hash)))
}

fn canonical_record(record: &Record, subject: &dyn Fn(&str) -> String) -> Record {
    let mut canon = record.clone();
    sealables::record_mut(&mut canon, &mut |s| s.value = None);
    canonical_subjects(record, &mut canon, subject);
    canon
}

fn canonical_subjects(
    record: &Record,
    canon: &mut Record,
    subject: &dyn Fn(&str) -> String,
) -> bool {
    let mut changed = false;
    match (record, canon) {
        (Record::Erasure(original), Record::Erasure(canonical)) => {
            let label = subject(&original.subject);
            if let (Some(original_audit), Some(audit)) = (&original.audit, &mut canonical.audit)
                && !original.subject.is_empty()
            {
                let reason = mask_subject(&original_audit.reason, &original.subject, &label);
                if audit.reason != reason {
                    audit.reason = reason;
                    changed = true;
                }
            }
            if canonical.subject != label {
                canonical.subject = label;
                changed = true;
            }
        }
        (Record::AuditEvent(original), Record::AuditEvent(canonical)) => {
            if let (Some(original), Some(value)) = (
                original.details.get("actor"),
                canonical.details.get_mut("actor"),
            ) {
                let (kind, key) = original.split_once('/').unwrap_or((original.as_str(), ""));
                let label = format!("{kind}/{}", subject(key));
                if *value != label {
                    *value = label;
                    changed = true;
                }
            }
        }
        _ => {}
    }
    changed
}

/// Historical digests stay source-derived, private and read-only.
fn legacy_hashes(
    record: &Record,
    canon: &mut Record,
    encoded: &mut Vec<u8>,
    subject: &dyn Fn(&str) -> String,
) -> (String, String) {
    if canonical_subjects(record, canon, subject) {
        *encoded = canon.encode();
    }
    let kind = canon.kind();
    let v2 = encoded_hash(kind, encoded, false);
    if let (Record::Erasure(original), Record::Erasure(canonical)) = (record, &mut *canon)
        && !original.subject.is_empty()
        && let (Some(original_audit), Some(canonical_audit)) =
            (&original.audit, &mut canonical.audit)
    {
        let reason = original_audit
            .reason
            .replace(&original.subject, &canonical.subject);
        if reason != canonical_audit.reason {
            canonical_audit.reason = reason;
            *encoded = canon.encode();
        }
    }
    (v2, encoded_hash(kind, encoded, true))
}

fn encoded_hash(kind: u8, encoded: &[u8], legacy: bool) -> String {
    let mut hash = blake3::Hasher::new();
    if !legacy {
        hash.update(b"kronik.audit/v2\0");
    }
    hash.update(&[kind]);
    hash.update(encoded);
    format!("b3:{}", hash.finalize().to_hex())
}

/// Match case and percent-encoded subject spellings, but not part of another id.
fn mask_subject(text: &str, subject: &str, label: &str) -> String {
    if subject.is_empty() {
        return text.to_owned();
    }
    let mut decoded = Vec::with_capacity(text.len());
    let mut positions = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let escape = bytes.get(i..i + 3).filter(|b| b[0] == b'%').and_then(|b| {
            let hi = (b[1] as char).to_digit(16)?;
            let lo = (b[2] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        });
        let end = i + if escape.is_some() { 3 } else { 1 };
        decoded.push(escape.unwrap_or(bytes[i]));
        positions.push((i, end));
        i = end;
    }
    let mut folded = Vec::with_capacity(decoded.len());
    let mut offset = 0;
    for chunk in decoded.utf8_chunks() {
        for (at, ch) in chunk.valid().char_indices() {
            let (start, _) = positions[offset + at];
            let (_, end) = positions[offset + at + ch.len_utf8() - 1];
            folded.extend(ch.to_lowercase().map(|ch| (ch, start, end)));
        }
        offset += chunk.valid().len();
        for _ in chunk.invalid() {
            let (start, end) = positions[offset];
            folded.push(('\u{fffd}', start, end));
            offset += 1;
        }
    }
    let identifier = |ch: char| ch.is_alphanumeric() || ch == '_';
    let needle: Vec<char> = subject.chars().flat_map(char::to_lowercase).collect();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut at = 0;
    while at + needle.len() <= folded.len() {
        let end = at + needle.len();
        if folded[at..end]
            .iter()
            .map(|c| c.0)
            .eq(needle.iter().copied())
            && (at == 0 || (folded[at - 1].2 <= folded[at].1 && !identifier(folded[at - 1].0)))
            && (end == folded.len()
                || (folded[end - 1].2 <= folded[end].1 && !identifier(folded[end].0)))
        {
            out.push_str(&text[copied..folded[at].1]);
            out.push_str(label);
            copied = folded[end - 1].2;
            at = end;
        } else {
            at += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// The lines of one committed record, in order: none for a record that is
/// not audited.
pub fn lines(lsn: u64, record: &Record, ctx: &Ctx) -> Result<Vec<Line>, ApiError> {
    lines_at(SourcePos::Actor { shard: None, lsn }, record, ctx)
}

pub fn lines_at(source: SourcePos, record: &Record, ctx: &Ctx) -> Result<Vec<Line>, ApiError> {
    validate_source(source, record)?;
    projected_lines(
        source,
        record,
        ctx,
        audit_positions(record).map_err(corruption)?,
        || record_hash(record, ctx.sealer).ok_or_else(identity_unavailable),
    )
}

fn validate_source(source: SourcePos, record: &Record) -> Result<(), ApiError> {
    if matches!(source, SourcePos::Metadata { .. })
        && let Record::Approval(approval) = record
    {
        kronik_proto::validate_proposal_approval(approval).map_err(|_| {
            corruption(LogError::Corrupt(
                "invalid canonical metadata approval".into(),
            ))
        })?;
    }
    let valid = match source {
        SourcePos::Actor { shard, lsn } => lsn > 0 && shard.is_none_or(|shard| shard < 4096),
        SourcePos::Metadata { index } => {
            index > 0
                && index <= i64::MAX as u64
                && (matches!(record, Record::AuditEvent(_))
                    || matches!(
                        record,
                        Record::SecretVersion(_) | Record::SecretLink(_) | Record::Approval(_)
                    ))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(corruption(LogError::Corrupt(
            "invalid audit source position".into(),
        )))
    }
}

fn identity_unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::Unavailable,
        "audit identity requires the protected master key",
    )
}

fn corruption(_: LogError) -> ApiError {
    ApiError::new(ErrorCode::StorageCorrupt, "invalid audit source metadata")
}

fn audit_positions(record: &Record) -> Result<Option<AuditPositions>, LogError> {
    if matches!(record, Record::SecretVersion(_) | Record::SecretLink(_)) {
        record
            .validate()
            .map_err(|_| LogError::Corrupt("invalid typed secret metadata".into()))?;
    }
    match record {
        Record::AuditEvent(event) => {
            kronik_proto::control::validate_event(event)
                .map_err(|_| LogError::Corrupt("invalid typed audit operation".into()))?;
            if event.action == "audit.gap" && event.details.contains_key("namespace") {
                kronik_proto::control::validate_metadata_gap_event(event).map_err(|_| {
                    LogError::Corrupt("invalid closed metadata coverage gap".into())
                })?;
            }
            if metadata_key_change(event) {
                kronik_proto::control::validate_metadata_webhook_key_change_event(event).map_err(
                    |_| LogError::Corrupt("invalid closed metadata signing-key change".into()),
                )?;
            }
            if metadata_replay(event) {
                kronik_proto::control::validate_metadata_webhook_replay_event(event).map_err(
                    |_| LogError::Corrupt("invalid closed metadata replay receipt".into()),
                )?;
            }
            AuditPositions::parse(&event.action, &event.details)
                .map_err(|error| LogError::Corrupt(error.into()))
        }
        _ => Ok(None),
    }
}

fn metadata_key_change(event: &pb::AuditEvent) -> bool {
    event.action == "audit.config"
        && event
            .details
            .get("change")
            .is_some_and(|change| change == "webhook.signing_key")
        && event
            .details
            .get("source")
            .is_some_and(|source| source == "metadata")
}

fn metadata_replay(event: &pb::AuditEvent) -> bool {
    event.action == "events.webhook.replay"
        && event
            .details
            .get("source")
            .is_some_and(|source| source == "metadata")
}

fn projected_lines(
    source: SourcePos,
    record: &Record,
    ctx: &Ctx,
    positions: Option<AuditPositions>,
    hash: impl FnOnce() -> Result<String, ApiError>,
) -> Result<Vec<Line>, ApiError> {
    let mut out = Vec::new();
    // The same subject label serves the typed identity and reason projection.
    let erasure_subject = match record {
        Record::Erasure(erasure) => {
            Some((erasure.subject.as_str(), (ctx.subject)(&erasure.subject)))
        }
        _ => None,
    };
    // Compile once, only for actual persisted Audit fields. Operational lines
    // without an Audit retain their empty reason rather than inventing one.
    let reason_plan = std::cell::OnceCell::new();
    let line = |kind: &str, action: &str, audit: Option<&pb::Audit>, epoch, details| Line {
        schema: SCHEMA.into(),
        lsn: match source {
            SourcePos::Actor { lsn, .. } => Some(lsn),
            SourcePos::Metadata { .. } => None,
        },
        source: match source {
            SourcePos::Actor { shard: None, .. } => None,
            _ => Some(source),
        },
        effect: None,
        kind: kind.into(),
        action: action.into(),
        at_wall_ms: audit.map_or(0, |a| a.wall_time_ms),
        token_id: audit.map(|a| a.token_id.clone()).unwrap_or_default(),
        reason: audit
            .map(|audit| {
                let reason = match &erasure_subject {
                    Some((subject, label)) if !subject.is_empty() => {
                        std::borrow::Cow::Owned(mask_subject(&audit.reason, subject, label))
                    }
                    _ => std::borrow::Cow::Borrowed(audit.reason.as_str()),
                };
                let plan = reason_plan.get_or_init(|| {
                    kronik_effects::http::CompiledScrubber::new_output(
                        ctx.secrets,
                        kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES,
                    )
                    .ok()
                });
                kronik_sched::scrub::persisted_audit_reason(reason, plan.as_ref()).into_owned()
            })
            .unwrap_or_default(),
        reason_truncated: false,
        branch: match source {
            SourcePos::Actor { .. } => ctx.branch.into(),
            SourcePos::Metadata { .. } => String::new(),
        },
        epoch,
        details,
        record_hash: String::new(),
        native_adoption_current_projection: None,
    };
    match record {
        Record::Deployment(d) => {
            let action = match pb::DeploymentCause::try_from(d.cause) {
                Ok(pb::DeploymentCause::Promote) => "promote",
                Ok(pb::DeploymentCause::Rollback) => "rollback",
                _ => "deploy",
            };
            let kinds = deployment_kinds(&d.kinds);
            let details = obj(json!({"kinds": kinds, "proposal_id": d.proposal_id,
                                     "rollback_of_epoch": d.rollback_of_epoch}));
            out.push(line(
                "deployment",
                action,
                d.audit.as_ref(),
                Some(d.epoch),
                details,
            ));
        }
        Record::Grant(g) => {
            let action = match pb::GrantOp::try_from(g.op) {
                Ok(pb::GrantOp::Revoke) => "revoke",
                _ => "grant",
            };
            let delivery = g.delivery.and_then(|d| pb::Delivery::try_from(d).ok());
            let details = obj(json!({
                "kind": g.kind,
                "capability": g.capability,
                "delivery": delivery.map(|d| label(d.as_str_name(), "DELIVERY_")),
                "rate": g.rate.as_ref().map(|r| json!({"count": r.count, "per_ms": r.per_ms})),
            }));
            out.push(line(
                "grant",
                action,
                g.audit.as_ref(),
                Some(g.epoch),
                details,
            ));
        }
        Record::Limits(l) => {
            let mut details = obj(json!({"kind": l.kind}));
            for (name, v) in [
                ("fuel", l.fuel),
                ("memory_bytes", l.memory_bytes),
                ("message_bytes", l.message_bytes),
                ("state_value_bytes", l.state_value_bytes),
                ("sql_bytes_per_actor", l.sql_bytes_per_actor),
                ("effect_timeout_ms", l.effect_timeout_ms),
                ("effect_response_bytes", l.effect_response_bytes),
            ] {
                if let Some(v) = v {
                    details.insert(name.into(), v.into());
                }
            }
            out.push(line(
                "limits",
                "limits",
                l.audit.as_ref(),
                Some(l.epoch),
                details,
            ));
        }
        Record::Policy(p) => {
            let details = obj(json!({
                "rules_hash": format!("b3:{}", blake3::hash(p.rules_toml.as_bytes()).to_hex()),
                "rules": rule_names(&p.rules_toml),
            }));
            out.push(line(
                "policy",
                "policy",
                p.audit.as_ref(),
                Some(p.epoch),
                details,
            ));
        }
        Record::Approval(a) => {
            let action = if a.request {
                "request_approval"
            } else {
                "approve"
            };
            let details = obj(json!({
                "proposal_id": a.proposal_id,
                "diff_hash": format!("b3:{}", hex(&a.diff_hash)),
                "verified_through_lsn": a.verified_through_lsn,
                "command": a.command,
            }));
            out.push(line("approval", action, a.audit.as_ref(), None, details));
        }
        Record::PrivacyMode(p) => {
            let mode = pb::PrivacyState::try_from(p.mode).unwrap_or(pb::PrivacyState::Unspecified);
            // ADR 0106: an explicit, validated reseal request (mode ON) is a
            // request event; it is never evidence that history was rewritten.
            let action = if p.reseal_requested && mode == pb::PrivacyState::On {
                "privacy.reseal.request"
            } else {
                "privacy.mode"
            };
            let details = obj(json!({"mode": label(mode.as_str_name(), "PRIVACY_STATE_")}));
            out.push(line(
                "privacy_mode",
                action,
                p.audit.as_ref(),
                Some(p.epoch),
                details,
            ));
        }
        Record::ForeignActor(f) => {
            // The digest only: the reference of an `oci-layout:` image is
            // a local path.
            let digest = f.image.rsplit_once('@').map_or("", |(_, d)| d);
            let (action, details) = match pb::ForeignOp::try_from(f.op) {
                Ok(pb::ForeignOp::Remove) => ("foreign.remove", obj(json!({"name": f.name}))),
                _ => (
                    "foreign.add",
                    obj(json!({"name": f.name, "image": digest, "port": f.port,
                               "secrets": f.secrets})),
                ),
            };
            out.push(line(
                "foreign_actor",
                action,
                f.audit.as_ref(),
                Some(f.epoch),
                details,
            ));
        }
        Record::Erasure(e) => {
            let hashed = erasure_subject.as_ref().map(|(_, label)| label);
            let details = obj(json!({"subject": hashed, "key_version": e.key_version}));
            out.push(line(
                "erasure",
                "privacy.erase",
                e.audit.as_ref(),
                Some(e.epoch),
                details,
            ));
        }
        Record::EngineUpgrade(u) => {
            let details = obj(json!({"from": u.from_engine_version, "to": u.to_engine_version}));
            out.push(line(
                "engine_upgrade",
                "engine.upgrade",
                u.audit.as_ref(),
                Some(u.epoch),
                details,
            ));
        }
        Record::SimulatorConfig(c) => {
            let details = obj(json!({
                "target": c.target,
                "stubs": c.stubs.len(),
                "contract": !c.contract.is_empty(),
                "neighbor": c.neighbor,
                "model": c.model,
            }));
            out.push(line(
                "simulator_config",
                "simulators.set",
                c.audit.as_ref(),
                Some(c.epoch),
                details,
            ));
        }
        Record::GuardTriggered(g) => {
            let action = match pb::GuardAction::try_from(g.action) {
                Ok(pb::GuardAction::Rollback) => "rollback",
                _ => "alert",
            };
            let outcome = pb::GuardOutcome::try_from(g.outcome).map_or_else(
                |_| "unspecified".into(),
                |o| label(o.as_str_name(), "GUARD_OUTCOME_"),
            );
            let details = obj(json!({
                "watch_id": g.watch_id,
                "guard": g.guard,
                "action": action,
                "outcome": outcome,
                "deployment_epoch": g.deployment_epoch,
                "rollback_epoch": g.rollback_epoch,
            }));
            out.push(line(
                "guard_triggered",
                "watch.guard",
                g.audit.as_ref(),
                None,
                details,
            ));
        }
        Record::StateRebase(r) => {
            if let Some(pb::state_rebase::Part::Switch(s)) = &r.part {
                let details = obj(json!({
                    "rebase_id": r.rebase_id,
                    "rolled_back_epoch": s.rolled_back_epoch,
                    "base_lsn": s.base_lsn,
                    "turns": s.turns,
                    "diff_hash": s.diff_hash,
                    "irreversible_effects": s.irreversible_effects,
                    "kinds": s.deployment.as_ref().map(|d| deployment_kinds(&d.kinds)).unwrap_or_default(),
                }));
                out.push(line(
                    "state_rebase",
                    "rollback.rebase",
                    s.audit.as_ref(),
                    s.deployment.as_ref().map(|d| d.epoch),
                    details,
                ));
            }
        }
        Record::SecretVersion(version) => {
            let (phase, action) = match pb::secret_version::Phase::try_from(version.phase) {
                Ok(pb::secret_version::Phase::Reserved) => ("reserved", "secret.version.reserved"),
                Ok(pb::secret_version::Phase::Active) => ("active", "secret.version"),
                Ok(pb::secret_version::Phase::Failed) => ("failed", "secret.version.failed"),
                Ok(pb::secret_version::Phase::Fence) => ("fence", "secret.range"),
                _ => return Err(corruption(LogError::Corrupt("invalid secret phase".into()))),
            };
            let details = obj(json!({"name":version.name, "version":version.version,
                "version_hash":hex(&version.version_hash), "hash_revision":version.hash_revision,
                "backend":version.backend, "source_version":version.source_version,
                "ref":version.r#ref, "binding":version.binding, "link_generation":version.link_generation,
                "canonical_ref":version.canonical_ref, "deleted":version.deleted, "phase":phase}));
            out.push(line(
                "secret_version",
                action,
                version.audit.as_ref(),
                None,
                details,
            ));
        }
        Record::SecretLink(link) => {
            if !matches!(source, SourcePos::Actor { shard: Some(_), .. }) {
                let action = if link.backend.is_empty() {
                    "secret.unlink"
                } else {
                    "secret.link"
                };
                let details = obj(
                    json!({"name":link.name, "backend":link.backend, "ref":link.r#ref,
                    "binding":link.binding, "generation":link.generation, "canonical_ref":link.canonical_ref}),
                );
                out.push(line(
                    "secret_link",
                    action,
                    link.audit.as_ref(),
                    Some(link.epoch),
                    details,
                ));
            }
        }
        Record::AuditEvent(a) => {
            if let Some(operation) = &a.operation {
                let details = operation_details(operation)?;
                let epoch = match operation {
                    pb::audit_event::Operation::FleetState(state) => Some(state.epoch),
                    _ => None,
                };
                out.push(line(
                    "audit_event",
                    operation.action(),
                    a.audit.as_ref(),
                    epoch,
                    details,
                ));
            } else if matches!(positions, Some(AuditPositions::MetadataGap { .. })) {
                let (stream, from_index, through_index) =
                    kronik_proto::control::metadata_audit_gap_details(&a.details).map_err(
                        |_| corruption(LogError::Corrupt("invalid metadata gap schema".into())),
                    )?;
                out.push(line(
                    "audit_event",
                    "audit.gap",
                    a.audit.as_ref(),
                    None,
                    obj(json!({"namespace":"metadata", "stream":stream,
                        "from_index":from_index, "through_index":through_index})),
                ));
            } else if metadata_key_change(a) {
                let (from_version, to_version) =
                    kronik_proto::control::metadata_webhook_key_change_details(&a.details)
                        .map_err(|_| {
                            corruption(LogError::Corrupt(
                                "invalid metadata signing-key schema".into(),
                            ))
                        })?;
                out.push(line(
                    "audit_event",
                    "audit.config",
                    a.audit.as_ref(),
                    None,
                    obj(json!({"change":"webhook.signing_key", "source":"metadata",
                        "from_version":from_version, "to_version":to_version, "target":a.target})),
                ));
            } else if metadata_replay(a) {
                let position = kronik_proto::control::metadata_webhook_replay_details(&a.details)
                    .map_err(|_| {
                    corruption(LogError::Corrupt("invalid metadata replay schema".into()))
                })?;
                out.push(line(
                    "audit_event",
                    "events.webhook.replay",
                    a.audit.as_ref(),
                    None,
                    obj(json!({"source":"metadata", "position":position, "target":a.target})),
                ));
            } else {
                let mut details = Map::new();
                for (k, v) in &a.details {
                    if let Some(value) = positions.and_then(|positions| positions.value(k)) {
                        details.insert(k.clone(), value.into());
                        continue;
                    }
                    let v = v.as_str();
                    // fork.send names its actor plain (kronik-api m3.rs).
                    if k == "actor" {
                        let (kind, key) = v.split_once('/').unwrap_or((v, ""));
                        if let Some(key) = ctx.keys.export(kind, key) {
                            details.insert(k.clone(), format!("{kind}/{key}").into());
                        }
                        continue;
                    }
                    details.insert(k.clone(), v.into());
                }
                details.insert("target".into(), a.target.clone().into());
                out.push(line(
                    "audit_event",
                    &a.action,
                    a.audit.as_ref(),
                    None,
                    details,
                ));
            }
        }
        Record::TurnRecord(t) => turn_lines(t, ctx, &line, &mut out)?,
        Record::TurnBegin(_)
        | Record::EffectResult(_)
        | Record::BranchCreated(_)
        | Record::SnapshotMarker(_) => {}
    }
    if out.is_empty() {
        return Ok(out);
    }
    let hash = hash()?;
    for l in &mut out {
        // ADR 0082/0083: every string detail is scrubbed, including secret
        // versions, secret links, typed operations, and metadata signing-key,
        // replay, and coverage-gap maps. Validated positions, epochs, and
        // digest spellings stay intact. A scrub that cannot run withholds the
        // string; export preparation stalls when the inventory cannot be loaded.
        scrub_details(&mut l.details, ctx.secrets, positions);
        if l.reason.len() > REASON_MAX {
            let mut cut = REASON_MAX;
            while !l.reason.is_char_boundary(cut) {
                cut -= 1;
            }
            l.reason.truncate(cut);
            l.reason_truncated = true;
        }
        l.record_hash.clone_from(&hash);
    }

    Ok(out)
}

/// Only the shared validated NativeAuthorityOrigin schema reaches this projection.
fn native_origin_details(origin: &pb::NativeAuthorityOrigin) -> Result<Value, ApiError> {
    let adoption = origin
        .adoption_audit
        .as_ref()
        .ok_or_else(|| corruption(LogError::Corrupt("missing native adoption audit".into())))?;
    let mut public = obj(json!({
        "adopted_at_wall_ms": adoption.wall_time_ms,
        "current_projection": origin.current_projection,
    }));
    if let Some(original) = &origin.source {
        public.insert(
            "original_source".into(),
            json!({
                "shard": original.shard, "lsn": original.lsn, "branch": original.branch,
            }),
        );
    }
    Ok(public.into())
}
fn operation_details(
    operation: &pb::audit_event::Operation,
) -> Result<Map<String, Value>, ApiError> {
    use pb::audit_event::Operation;
    Ok(match operation {
        Operation::FleetState(state) => {
            let phase = match pb::fleet_state::Phase::try_from(state.phase) {
                Ok(pb::fleet_state::Phase::Pending) => "pending",
                Ok(pb::fleet_state::Phase::Requested) => "requested",
                Ok(pb::fleet_state::Phase::Active) => "active",
                Ok(pb::fleet_state::Phase::Revoked) => "revoked",
                _ => return Err(corruption(LogError::Corrupt("invalid fleet phase".into()))),
            };
            obj(
                json!({"operation":"fleet_state", "phase":phase, "epoch":state.epoch,
                "installation":state.installation, "node":state.node, "cluster":state.cluster,
                "controller_origin":state.controller_origin, "scopes":state.scopes,
                "ca_sha256":hex(&state.ca_sha256), "request_id":hex(&state.request_id),
                "controller_id":state.controller_id, "client_key_sha256":hex(&state.client_key_sha256)}),
            )
        }
        Operation::InstallationIdentity(identity) => obj(json!({
            "operation":"installation_identity", "installation":identity.installation,
        })),
        Operation::AuthConfig(config) => obj(json!({
            "operation":"auth_config", "version":config.version, "enabled":config.enabled,
            "digest":hex(&config.digest), "previous_digest":hex(&config.previous_digest),
            "issuer":config.issuer, "client_id":config.client_id, "redirect_uri":config.redirect_uri,
            "system_roots":config.system_roots,
            "trust_roots_sha256":config.trust_roots_sha256.iter().map(|hash| hex(hash)).collect::<Vec<_>>(),
            "bindings":config.bindings.iter().map(|binding| json!({
                "principal_hash":hex(&binding.principal_hash), "token_name":binding.token_name,
            })).collect::<Vec<_>>(),
            "flow_ttl_ms":config.flow_ttl_ms, "session_ttl_ms":config.session_ttl_ms,
        })),
        Operation::AuthSessionRevoked(session) => {
            let config_source = match &session.config_source {
                Some(pb::auth_session_revoked::ConfigSource::NativeLsn(lsn)) => {
                    json!({"native_lsn":lsn})
                }
                Some(pb::auth_session_revoked::ConfigSource::MetadataIndex(index)) => {
                    json!({"metadata_index":index})
                }
                None => {
                    return Err(corruption(LogError::Corrupt(
                        "missing session config source".into(),
                    )));
                }
            };
            obj(json!({
                "operation":"auth_session_revoked", "session_hash":hex(&session.session_hash),
                "principal_hash":hex(&session.principal_hash), "config_digest":hex(&session.config_digest),
                "config_source":config_source, "token_name":session.token_name,
                "expires_at_ms":session.expires_at_ms,
                "metadata_token":session.metadata_token.as_ref().map(|token| json!({
                    "metadata_revision":token.metadata_revision, "created_index":token.created_index,
                    "token_revision":token.token_revision, "fleet_revision":token.fleet_revision,
                })),
                "peer_boot":session.peer_boot.as_ref().map(|peer| json!({
                    "member_id":peer.member_id, "incarnation":peer.incarnation,
                    "boot_id":hex(&peer.boot_id), "registration_index":peer.registration_index,
                })),
            }))
        }
        Operation::AuthOidcLogin(login) => {
            let config_source = match &login.config_source {
                Some(pb::auth_oidc_login::ConfigSource::NativeLsn(lsn)) => {
                    json!({"native_lsn":lsn})
                }
                Some(pb::auth_oidc_login::ConfigSource::MetadataIndex(index)) => {
                    json!({"metadata_index":index})
                }
                None => {
                    return Err(corruption(LogError::Corrupt(
                        "missing login config source".into(),
                    )));
                }
            };
            obj(json!({
                "operation":"auth_oidc_login", "principal_hash":hex(&login.principal_hash),
                "config_digest":hex(&login.config_digest), "config_source":config_source,
                "token_name":login.token_name,
            }))
        }
    })
}

type LineFn<'a> =
    dyn Fn(&str, &str, Option<&pb::Audit>, Option<u64>, Map<String, Value>) -> Line + 'a;

/// An operator send or resend, then one line per `secret.reveal` effect
/// (review H3).
fn turn_lines(
    t: &pb::TurnRecord,
    ctx: &Ctx,
    line: &LineFn,
    out: &mut Vec<Line>,
) -> Result<(), ApiError> {
    let actor = t.actor.clone().unwrap_or_default();
    let actor_label = |details: &mut Map<String, Value>| {
        if let Some(key) = ctx.keys.export(&actor.kind, &actor.key) {
            details.insert("actor".into(), format!("{}/{key}", actor.kind).into());
        }
    };
    let message = match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
        Some(pb::input::Kind::Message(m)) => Some(m),
        _ => None,
    };
    let operator = message.and_then(|m| {
        let action = match pb::MessageSource::try_from(m.source) {
            Ok(pb::MessageSource::Operator) => "send",
            Ok(pb::MessageSource::DeadLetterResend) => "resend",
            _ => return None,
        };
        Some((m, action))
    });
    if let Some((m, action)) = operator {
        let mut details = Map::new();
        actor_label(&mut details);
        details.insert(
            "message".into(),
            m.msg
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_default()
                .into(),
        );
        if !m.resend_of.is_empty() {
            details.insert("resend_of".into(), m.resend_of.clone().into());
        }
        out.push(line("turn", action, m.audit.as_ref(), None, details));
    }
    // A reveal inside an operator send carries its audit; one by guest code
    // in any other turn is the actor's, at the turn's logical time.
    let audit = operator.and_then(|(m, _)| m.audit.as_ref());
    for e in t.effects.iter().filter(|e| e.kind == "secret.reveal") {
        let mut details = Map::new();
        details.insert("effect".into(), e.ordinal.into());
        actor_label(&mut details);
        let secret = e.target.strip_prefix("secret-reveal:").unwrap_or(&e.target);
        details.insert("secret".into(), secret.into());
        // The version is in the request, unless it is sealed.
        if let Some(pb::Sealable {
            value: Some(pb::sealable::Value::Plain(b)),
            ..
        }) = &e.request
        {
            let request = pb::RevealEffectRequest::decode(b.as_slice()).map_err(|_| {
                ApiError::new(ErrorCode::StorageCorrupt, "invalid secret reveal request")
            })?;
            let secret = request.secret.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "secret reveal has no resolved identity",
                )
            })?;
            let version = secret.resolved_version().map_err(|_| {
                ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "invalid resolved secret reveal identity",
                )
            })?;
            details.insert("version".into(), version.into());
        }
        let status = pb::EffectStatus::try_from(e.status).unwrap_or(pb::EffectStatus::Unspecified);
        details.insert(
            "status".into(),
            label(status.as_str_name(), "EFFECT_STATUS_").into(),
        );
        let mut l = line("turn", "secret.reveal", audit, None, details);
        l.effect = Some(e.ordinal);
        if audit.is_none() {
            l.token_id = "guest".into();
            l.at_wall_ms = t.logical_time_ms;
        }
        out.push(l);
    }
    Ok(())
}

fn deployment_kinds(kinds: &[pb::KindVersion]) -> Vec<Value> {
    kinds
        .iter()
        .map(|k| {
            json!({"kind": k.kind, "code_hash": format!("b3:{}", hex(&k.code_hash)),
                   "schema_version": k.schema_version})
        })
        .collect()
}

fn scrub_details(
    details: &mut Map<String, Value>,
    secrets: &[(&str, &[u8])],
    positions: Option<AuditPositions>,
) {
    fn scrub(value: &mut Value, secrets: &[(&str, &[u8])]) {
        match value {
            Value::String(text) => *text = kronik_sched::scrub::for_log(text, Some(secrets)),
            Value::Array(values) => values.iter_mut().for_each(|v| scrub(v, secrets)),
            Value::Object(values) => scrub_details(values, secrets, None),
            _ => {}
        }
    }
    *details = std::mem::take(details)
        .into_iter()
        .map(|(key, mut value)| {
            if let Some(value) = positions.and_then(|positions| positions.value(&key)) {
                return (key, value.into());
            }
            // Digests, epochs, and other structured numbers are not free text.
            // Substring replacement would corrupt them; a secret that only
            // coincides with that spelling is not a disclosure of the field.
            if leave_structured(&key, &value) {
                return (key, value);
            }
            scrub(&mut value, secrets);
            (kronik_sched::scrub::for_log(&key, Some(secrets)), value)
        })
        .collect();
}

/// Projection-emitted coordinates and digests. Operator strings that merely
/// share a key name are still scrubbed: a number or digest spelling is required.
fn leave_structured(key: &str, value: &Value) -> bool {
    if value.is_number() && structured_number_key(key) {
        return true;
    }
    if value.is_boolean() && matches!(key, "deleted" | "enabled" | "system_roots") {
        return true;
    }
    match key {
        "trust_roots_sha256" => match value {
            Value::Array(items) => items.iter().all(digest_value),
            other => digest_value(other),
        },
        "version_hash" | "ca_sha256" | "request_id" | "client_key_sha256" | "digest"
        | "previous_digest" | "principal_hash" | "session_hash" | "config_digest" | "boot_id"
        | "code_hash" | "rules_hash" | "diff_hash" | "controller_id" => digest_value(value),
        _ => false,
    }
}

fn structured_number_key(key: &str) -> bool {
    matches!(
        key,
        "epoch"
            | "version"
            | "hash_revision"
            | "link_generation"
            | "generation"
            | "from_version"
            | "to_version"
            | "position"
            | "flow_ttl_ms"
            | "session_ttl_ms"
            | "expires_at_ms"
            | "native_lsn"
            | "metadata_index"
            | "metadata_revision"
            | "created_index"
            | "token_revision"
            | "fleet_revision"
            | "member_id"
            | "incarnation"
            | "registration_index"
    )
}

fn digest_value(value: &Value) -> bool {
    match value {
        Value::String(text) => is_digest(text),
        _ => false,
    }
}

/// `hex` or `b3:` plus hex. Free text that is not a digest spelling is scrubbed
/// even when its key is one of the digest names.
fn is_digest(text: &str) -> bool {
    let hex = text.strip_prefix("b3:").unwrap_or(text);
    !hex.is_empty()
        && hex.len().is_multiple_of(2)
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn label(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// The `name`s of a rules file's `[[rule]]` tables; the text itself stays
/// in the node (its hash is exported).
fn rule_names(rules_toml: &str) -> Vec<String> {
    let Ok(file) = rules_toml.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(toml::Value::Array(rules)) = file.get("rule") else {
        return Vec::new();
    };
    rules
        .iter()
        .filter_map(|r| r.get("name")?.as_str().map(str::to_owned))
        .collect()
}

/// One item of a verification report.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct Item {
    /// Authoritative logical branch; unverified sink claims remain omitted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourcePos>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<u32>,
    pub kind: String,
    pub action: String,
    /// The current source hash; absent when no authoritative source item exists.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub record_hash: String,
}

impl From<&Line> for Item {
    fn from(l: &Line) -> Item {
        Item {
            branch: l.branch.clone(),
            lsn: l.lsn,
            source: l.source,
            effect: l.effect,
            kind: l.kind.clone(),
            action: l.action.clone(),
            record_hash: l.record_hash.clone(),
        }
    }
}

/// `kronik audit verify` (§4.5): a sink's lines against the log's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Report {
    /// Nothing missing, extra or conflicting.
    pub complete: bool,
    /// The range checked, `(from, to]`.
    pub from: u64,
    pub to: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_source: Option<SourcePos>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_source: Option<SourcePos>,
    /// Audited items of the log in the range.
    pub expected: usize,
    /// Distinct sink lines in the range.
    pub lines: usize,
    pub missing: Vec<Item>,
    /// Lines for no item of the log.
    pub extra: Vec<Item>,
    /// Lines whose (lsn, effect) the log has with a different record, or
    /// with other fields.
    pub conflicting: Vec<Item>,
    /// Lines of a tail that a later `restore` event replaced: exported
    /// before the restore, with LSNs past its `through_lsn`.
    pub superseded: usize,
}

/// A source record's verification identity. The historical hash is deliberately
/// private and not serializable: only the v3 projection may leave the node.
#[derive(Clone)]
pub struct Expected {
    line: Line,
    legacy_hash: String,
    legacy_v2_hash: String,
    positions: Option<AuditPositions>,
    verify_native_origin: bool,
}

/// Builds both format readers' identities from the authoritative record.
pub fn expected(lsn: u64, record: &Record, ctx: &Ctx) -> Result<Vec<Expected>, ApiError> {
    expected_at(SourcePos::Actor { shard: None, lsn }, record, ctx)
}

pub fn expected_at(
    source: SourcePos,
    record: &Record,
    ctx: &Ctx,
) -> Result<Vec<Expected>, ApiError> {
    validate_source(source, record)?;
    let positions = audit_positions(record).map_err(corruption)?;
    let (mut legacy_v2_hash, mut legacy_hash) = (String::new(), String::new());
    let projected = projected_lines(source, record, ctx, positions, || {
        let mut canon = canonical_record(record, &|subject| subject_label(ctx.sealer, subject));
        let mut encoded = canon.encode();
        let current = private_identity(canon.kind(), &encoded, ctx.sealer)
            .ok_or_else(identity_unavailable)?;
        (legacy_v2_hash, legacy_hash) =
            legacy_hashes(record, &mut canon, &mut encoded, ctx.subject);
        Ok(current)
    })?;
    if projected.is_empty() {
        return Ok(Vec::new());
    }
    Ok(projected
        .into_iter()
        .map(|line| Expected {
            line,
            legacy_hash: legacy_hash.clone(),
            legacy_v2_hash: legacy_v2_hash.clone(),
            positions,
            verify_native_origin: matches!(
                record,
                Record::SecretVersion(_) | Record::SecretLink(_)
            ),
        })
        .collect())
}

impl Expected {
    fn matches(&self, line: &Line) -> bool {
        let hash = match line.schema.as_str() {
            SCHEMA => &self.line.record_hash,
            LEGACY_SCHEMA => &self.legacy_hash,
            LEGACY_V2_SCHEMA => &self.legacy_v2_hash,
            _ => return false,
        };
        fn identity(l: &Line) -> (&str, &str, &str, u64, &str, Option<u64>) {
            (
                l.kind.as_str(),
                l.action.as_str(),
                l.token_id.as_str(),
                l.at_wall_ms,
                l.branch.as_str(),
                l.epoch,
            )
        }
        if &line.record_hash != hash || identity(line) != identity(&self.line) {
            return false;
        }
        if self.verify_native_origin
            && line.details.get("native_origin") != self.line.details.get("native_origin")
        {
            return false;
        }
        if let Some(positions) = self.positions {
            for field in ["through_lsn", "from", "to", "from_index", "through_index"] {
                let Some(expected) = positions.value(field) else {
                    continue;
                };
                let value = line.details.get(field).and_then(|value| {
                    if matches!(line.schema.as_str(), SCHEMA | LEGACY_V2_SCHEMA) {
                        value.as_u64()
                    } else {
                        value
                            .as_str()
                            .filter(|text| {
                                !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
                            })
                            .and_then(|text| text.parse::<u64>().ok())
                    }
                });
                if value != Some(expected) {
                    return false;
                }
            }
        }
        true
    }
}

/// Mirrors Store::apply_turn's message/timer insertion, excluding corrupt inputs.
fn dead_letter(turn: &pb::TurnRecord) -> Option<(pb::OutcomeKind, &pb::Outcome, &'static str)> {
    turn.actor.as_ref()?;
    let outcome = turn.outcome.as_ref()?;
    let kind = pb::OutcomeKind::try_from(outcome.kind).ok()?;
    if matches!(
        kind,
        pb::OutcomeKind::Committed | pb::OutcomeKind::Unspecified
    ) {
        return None;
    }
    let input_class = match turn.input.as_ref()?.kind.as_ref()? {
        pb::input::Kind::Message(message) => {
            match pb::MessageSource::try_from(message.source).ok()? {
                pb::MessageSource::Actor => "message.actor",
                pb::MessageSource::Operator => "message.operator",
                pb::MessageSource::DeadLetterResend => "message.dead_letter_resend",
                pb::MessageSource::Compensation => "message.compensation",
                pb::MessageSource::Call | pb::MessageSource::Unspecified => return None,
            }
        }
        pb::input::Kind::Timer(_) => "timer",
        pb::input::Kind::Http(_) | pb::input::Kind::Migrate(_) => return None,
    };
    Some((kind, outcome, input_class))
}

fn same_namespace(a: &Line, b: &Line) -> bool {
    if a.branch != b.branch {
        return false;
    }
    match (a.source, b.source) {
        (None, None) => true,
        (Some(SourcePos::Actor { shard: a, .. }), Some(SourcePos::Actor { shard: b, .. })) => {
            a == b
        }
        (Some(SourcePos::Metadata { .. }), Some(SourcePos::Metadata { .. })) => true,
        _ => false,
    }
}

/// Compares versioned sink lines against record-derived identities in `(from, to]`.
/// A restore cut is trusted only after its source identity and cut have matched.
pub fn verify(expected: &[Expected], sink: &[Line], from: u64, to: u64) -> Report {
    verify_range(expected, sink, from, to, None)
}

/// Verifies an explicit actor-shard or metadata-index range without aliasing domains.
pub fn verify_at(
    expected: &[Expected],
    sink: &[Line],
    from: SourcePos,
    to: SourcePos,
) -> Result<Report, ApiError> {
    let positions = match (from, to) {
        (
            SourcePos::Actor {
                shard: a,
                lsn: from,
            },
            SourcePos::Actor { shard: b, lsn: to },
        ) if a == b && a.is_none_or(|shard| shard < 4096) && from <= to => (from, to),
        (SourcePos::Metadata { index: from }, SourcePos::Metadata { index: to }) if from <= to => {
            (from, to)
        }
        _ => {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "audit range requires one source namespace",
            ));
        }
    };
    Ok(verify_range(
        expected,
        sink,
        positions.0,
        positions.1,
        Some((from, to)),
    ))
}

fn verify_range(
    expected: &[Expected],
    sink: &[Line],
    from: u64,
    to: u64,
    sources: Option<(SourcePos, SourcePos)>,
) -> Report {
    use std::collections::{BTreeMap, BTreeSet};
    let in_range = |line: &Line| match sources.map(|(from, _)| from) {
        None => line.lsn.is_some_and(|lsn| lsn > from && lsn <= to),
        Some(SourcePos::Actor { shard, .. }) => {
            let namespace = match line.source {
                None => shard.is_none(),
                Some(SourcePos::Actor { shard: actual, lsn }) => {
                    actual == shard && line.lsn == Some(lsn)
                }
                _ => false,
            };
            namespace && line.lsn.is_some_and(|lsn| lsn > from && lsn <= to)
        }
        Some(SourcePos::Metadata { .. }) => {
            line.lsn.is_none()
                && matches!(line.source, Some(SourcePos::Metadata { index }) if index > from && index <= to)
        }
    };
    let want: BTreeMap<_, _> = expected
        .iter()
        .filter(|e| in_range(&e.line))
        .map(|e| (e.line.item(), e))
        .collect();
    let mut superseded = vec![false; sink.len()];
    let mut restores = BTreeSet::new();
    for (i, line) in sink.iter().enumerate() {
        let Some(source) = want.get(&line.item()).filter(|e| e.matches(line)) else {
            continue;
        };
        if let Some(AuditPositions::Restore {
            through_lsn: through,
        }) = source.positions
            && restores.insert(line.item())
        {
            for (j, prior) in sink[..i].iter().enumerate() {
                let invalid_current = want.get(&prior.item()).is_some_and(|expected| {
                    (prior.record_hash == expected.line.record_hash
                        || prior.record_hash == expected.legacy_hash
                        || prior.record_hash == expected.legacy_v2_hash)
                        && !expected.matches(prior)
                });
                superseded[j] |= prior.lsn.is_some_and(|lsn| lsn > through)
                    && same_namespace(prior, line)
                    && matches!(
                        prior.schema.as_str(),
                        SCHEMA | LEGACY_V2_SCHEMA | LEGACY_SCHEMA
                    )
                    && !invalid_current;
            }
        }
    }
    let mut report = Report {
        from,
        to,
        from_source: sources.map(|(from, _)| from),
        to_source: sources.map(|(_, to)| to),
        expected: want.len(),
        ..Report::default()
    };
    let (mut seen, mut matched) = (BTreeSet::new(), BTreeSet::new());
    let (mut extra, mut conflicting) = (BTreeSet::new(), BTreeSet::new());
    for (line, gone) in sink.iter().zip(superseded) {
        if gone {
            report.superseded += 1;
            continue;
        }
        if !in_range(line) {
            continue;
        }
        match want.get(&line.item()) {
            Some(source) if source.matches(line) => {
                if matched.insert(line.item()) {
                    report.lines += 1;
                }
            }
            source => {
                let key = (
                    line.item(),
                    &line.schema,
                    &line.record_hash,
                    &line.kind,
                    &line.action,
                    &line.token_id,
                    line.at_wall_ms,
                    &line.branch,
                    line.epoch,
                    line.details.get("through_lsn").and_then(Value::as_str),
                    line.details.get("through_lsn").and_then(Value::as_u64),
                );
                if !seen.insert(key) {
                    continue;
                }
                report.lines += 1;
                if let Some(expected) = source {
                    conflicting.insert(Item::from(&expected.line));
                } else {
                    extra.insert(Item {
                        branch: String::new(),
                        lsn: line.lsn,
                        source: line.source,
                        effect: line.effect,
                        kind: "unverified".into(),
                        action: "unverified".into(),
                        record_hash: String::new(),
                    });
                }
            }
        }
    }
    report.missing = want
        .iter()
        .filter(|(key, _)| !matched.contains(*key))
        .map(|(_, source)| Item::from(&source.line))
        .collect();
    report.extra = extra.into_iter().collect();
    report.conflicting = conflicting.into_iter().collect();
    report.complete =
        report.missing.is_empty() && report.extra.is_empty() && report.conflicting.is_empty();
    report
}
