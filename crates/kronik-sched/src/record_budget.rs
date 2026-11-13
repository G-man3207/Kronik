//! One log record holds everything a turn records (docs/design/m1-core.md
//! §2, "Record size"): its input, the request and result of every effect,
//! its compensations, state writes, messages, timers, SQL changes and schema
//! changes, and its outcome. A turn is charged for all of it in one budget:
//! the effect gate charges each effect as it is recorded and refuses one
//! that no longer fits before it happens, and the end of the turn checks the
//! whole record. A turn that would not fit fails with `TURN_TOO_LARGE` and
//! writes a failed record that does fit: the effects the gate admitted always
//! fit, by construction.
//!
//! The decisions depend only on what the turn records, never on timing,
//! execution ids or the engine version, and production and fork replay use
//! these same functions, so a replay makes the same decisions (I1).

use kronik_core::error::ErrorCode;
use kronik_proto::log::v1 as pb;
use kronik_proto::sealables;
use kronik_runtime::GateError;
use prost::Message as _;

/// What sealing can add to one value: the key version, the nonce, the tag
/// and the length prefixes around them (docs/design/m8-privacy.md §4). Every
/// value is charged for it, sealed or not, so the decisions do not depend on
/// the privacy mode.
pub const SEAL_ALLOWANCE: usize = 64;

/// What every turn keeps free besides what it is charged for: its execution
/// id, engine version and duration (which differ between a run and its
/// replay, so they are not charged), the outcome of a failed record, and the
/// `StateRebase` record a rollback by replay wraps a fork turn in (M13).
pub const TURN_RESERVE: usize = 4 << 10;

/// What an effect needs besides its request before it may happen: a result
/// without a body (a status and an error text).
pub const EFFECT_RESERVE: usize = 4 << 10;

/// The two timing fields of an effect, which a replay may not reproduce:
/// a key and a varint of at most 10 bytes each.
const TIMING_ALLOWANCE: usize = 2 * (2 + 10);

/// What a failed record holds besides its input, effects and compensations:
/// its outcome (a `TURN_TOO_LARGE` trap with its message) and the turn's
/// fuel, memory peak and schema version. The gate's budget starts with it
/// taken ([`base_cost`]), so that record always fits.
const FAILED_OUTCOME_ALLOWANCE: usize = 512;

/// The budget of a turn whose log holds records of at most `log_limit`
/// bytes.
pub fn turn_limit(log_limit: usize) -> usize {
    log_limit.saturating_sub(TURN_RESERVE)
}

fn varint(v: usize) -> usize {
    prost::encoding::encoded_len_varint(v as u64)
}

/// A nested message or bytes field of `len` bytes: its key (at most two
/// bytes for field numbers below 2048), its length prefix and its body.
fn field(len: usize) -> usize {
    2 + varint(len) + len
}

/// What a turn's input costs, measured in the plaintext form its guest
/// sees: a production turn may record a sealed input (a message from the
/// mailbox) where its replay holds the plain one, and both must be charged
/// the same.
pub fn input_cost(input: &mut pb::Input) -> usize {
    let mut values = 0;
    sealables::input_mut(Some(input), &mut |_| values += 1);
    field(input.encoded_len()) + values * SEAL_ALLOWANCE
}

/// What a turn record holds before its effects and outputs: its actor, code
/// hash, causal key, logical time, seed, input ([`input_cost`]) and
/// configuration epoch, and room for the outcome of a failed record.
pub fn base_cost(
    actor: &pb::ActorRef,
    code_hash: &[u8],
    causal_key: &pb::CausalKey,
    logical_time_ms: u64,
    random_seed: &[u8],
    input_cost: usize,
    config_epoch: u64,
) -> usize {
    field(actor.encoded_len())
        + field(code_hash.len())
        + field(causal_key.encoded_len())
        + 2
        + varint(logical_time_ms as usize)
        + field(random_seed.len())
        + input_cost
        + 2
        + varint(config_epoch as usize)
        + FAILED_OUTCOME_ALLOWANCE
}

/// What an effect adds to its turn record (its `EffectResult` holds the
/// same): the record without its timing fields, an allowance for them, and
/// the sealing allowance for its request and response.
pub fn effect_cost(e: &mut pb::EffectRecord) -> usize {
    let duration = std::mem::take(&mut e.duration_us);
    let offset = std::mem::take(&mut e.offset_us);
    let mut values = 0;
    sealables::effect_mut(e, &mut |_| values += 1);
    let len = e.encoded_len();
    e.duration_us = duration;
    e.offset_us = offset;
    field(len + TIMING_ALLOWANCE) + values * SEAL_ALLOWANCE
}

/// What a compensation message adds to a failed turn's record.
pub fn message_cost(m: &mut pb::OutboundMessage) -> usize {
    let mut values = 0;
    sealables::message_mut(m.msg.as_mut(), &mut |_| values += 1);
    field(m.encoded_len()) + values * SEAL_ALLOWANCE
}

/// What a whole turn record costs: its body without the execution id,
/// engine version and duration ([`TURN_RESERVE`] covers them) and without
/// its effects' timing fields (allowed for), plus the sealing allowance for
/// every value. Its input is charged `input_cost` ([`input_cost`] of the
/// plaintext input), whatever form the record holds it in.
pub fn turn_cost(t: &mut pb::TurnRecord, input_cost: usize) -> usize {
    let input = t.input.take();
    let execution_id = std::mem::take(&mut t.execution_id);
    let engine_version = std::mem::take(&mut t.engine_version);
    let duration = std::mem::take(&mut t.duration_us);
    let timing: Vec<(u64, u64)> = t
        .effects
        .iter_mut()
        .map(|e| {
            (
                std::mem::take(&mut e.duration_us),
                std::mem::take(&mut e.offset_us),
            )
        })
        .collect();
    let mut values = 0;
    sealables::turn_mut(t, &mut |_| values += 1);
    let len = t.encoded_len();
    for (e, (duration, offset)) in t.effects.iter_mut().zip(timing) {
        e.duration_us = duration;
        e.offset_us = offset;
    }
    t.execution_id = execution_id;
    t.engine_version = engine_version;
    t.duration_us = duration;
    t.input = input;
    len + input_cost + t.effects.len() * TIMING_ALLOWANCE + values * SEAL_ALLOWANCE
}

/// The outcome of a turn whose record did not fit in `limit` bytes.
pub fn too_large_outcome(limit: usize) -> pb::Outcome {
    pb::Outcome {
        kind: pb::OutcomeKind::Trap as i32,
        error_code: ErrorCode::TurnTooLarge.as_str().into(),
        message: format!(
            "the turn's record does not fit in one log record (at most {limit} bytes for a \
             turn); its state writes, messages, timers, SQL changes and output were dropped"
        ),
        output: None,
    }
}

/// What [`fit`] did to a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// The record fits as it is.
    Fits,
    /// The record became a failed turn with `TURN_TOO_LARGE`.
    Failed,
    /// Even the failed turn was too large, which only effects recorded
    /// before this budget existed can cause (the re-run of a turn an earlier
    /// release began): their requests and responses were left out of the
    /// turn record. The log's `EffectResult` records of the execution still
    /// hold them.
    Stripped,
}

/// Makes a finished turn's record fit `limit` ([`turn_limit`]). A record
/// over it becomes the failed turn the brief describes: its input, effects
/// and compensations stay; its state writes, messages, timers, SQL changes,
/// schema changes and output go; its outcome is `TURN_TOO_LARGE`.
/// `compensations` are the turn's compensation messages, which a committed
/// turn did not record; `input_cost` is [`input_cost`] of its plaintext
/// input.
pub fn fit(
    record: &mut pb::TurnRecord,
    compensations: &[pb::OutboundMessage],
    limit: usize,
    input_cost: usize,
) -> Fit {
    if turn_cost(record, input_cost) <= limit {
        return Fit::Fits;
    }
    fail(record, compensations, limit, input_cost)
}

/// [`fit`] for a turn already known not to fit, for instance because its
/// output could not be prepared within the record limit.
pub fn fail(
    record: &mut pb::TurnRecord,
    compensations: &[pb::OutboundMessage],
    limit: usize,
    input_cost: usize,
) -> Fit {
    record.writes.clear();
    record.messages.clear();
    record.timers.clear();
    record.sql_changes.clear();
    record.sql_schema.clear();
    record.blob_refs.clear();
    record.compensations = compensations.to_vec();
    record.schema_version = 0;
    record.outcome = Some(too_large_outcome(limit));
    if turn_cost(record, input_cost) <= limit {
        return Fit::Failed;
    }
    for e in &mut record.effects {
        e.request = None;
        e.response = None;
    }
    if let Some(outcome) = &mut record.outcome {
        outcome
            .message
            .push_str("; the requests and responses of its effects are only in its effect results");
    }
    Fit::Stripped
}

/// Makes a failed record that closes an open turn without running its guest
/// (a re-run whose recorded secret version is gone) fit `limit`, keeping
/// its outcome. Only effects an earlier release recorded past the budget can
/// make it too large: then their requests and responses are left out of the
/// turn record; the log's `EffectResult` records of the execution keep them.
pub fn fit_closing(record: &mut pb::TurnRecord, limit: usize, input_cost: usize) -> Fit {
    if turn_cost(record, input_cost) <= limit {
        return Fit::Fits;
    }
    for e in &mut record.effects {
        e.request = None;
        e.response = None;
    }
    Fit::Stripped
}

/// What a turn's record may still take, charged as the turn records
/// effects and compensations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Budget {
    limit: usize,
    used: usize,
}

impl Budget {
    /// A turn with `limit` bytes ([`turn_limit`]) of which `base`
    /// ([`base_cost`]) are taken.
    pub fn new(limit: usize, base: usize) -> Budget {
        Budget { limit, used: base }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// What is left.
    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.used)
    }

    /// Whether `bytes` more fit.
    pub fn fits(&self, bytes: usize) -> bool {
        bytes <= self.remaining()
    }

    /// Takes `bytes`, which may go past the limit: effects a re-run
    /// replays happened and are recorded whatever their size.
    pub fn charge(&mut self, bytes: usize) {
        self.used = self.used.saturating_add(bytes);
    }

    /// Takes `bytes` when they fit; else the refusal the effect gate
    /// returns: the effect does not happen and the turn traps with
    /// `TURN_TOO_LARGE`.
    pub fn take(&mut self, bytes: usize, ordinal: u32, kind: &str) -> Result<(), GateError> {
        if !self.fits(bytes) {
            return Err(self.refuse(ordinal, kind));
        }
        self.charge(bytes);
        Ok(())
    }

    /// The refusal of effect `ordinal` of `kind`: the turn traps with
    /// `TURN_TOO_LARGE` before the effect happens.
    pub fn refuse(&self, ordinal: u32, kind: &str) -> GateError {
        GateError::TurnTooLarge(format!(
            "effect {ordinal} ({kind}) does not fit in what is left of the turn's record \
             (at most {} bytes for a turn); it did not happen",
            self.limit
        ))
    }
}

/// What a new `http.fetch` or `foreign.http` needs before it may happen:
/// its request as recorded and a result without a body. Its response may
/// take at most what is left after that ([`response_room`]).
pub fn fetch_need(recorded_request_len: usize) -> usize {
    field(recorded_request_len) + 2 * SEAL_ALLOWANCE + EFFECT_RESERVE
}

/// The most response body bytes a fetch may read once `need`
/// ([`fetch_need`]) is set aside: a larger response is `too-large`, as one
/// over the actor type's `effect_response_bytes` is.
pub fn response_room(budget: &Budget, need: usize, effect_response_bytes: u64) -> u64 {
    let room = budget.remaining().saturating_sub(need) as u64;
    room.min(effect_response_bytes)
}

/// What a new `actor.call` needs before it may happen: its request as
/// recorded, the second copy of its compensation a failed turn records, and
/// a result without a body. Its reply may take at most what is left after
/// that; a larger one is withheld as one over `effect_response_bytes` is.
pub fn call_need(
    recorded_request_len: usize,
    compensation: Option<&pb::Message>,
    to: &pb::ActorRef,
) -> usize {
    // The compensation's OutboundMessage: destination, message, ordinal
    // (a varint of at most 5 bytes) and a 32-character message id.
    let compensation = compensation.map_or(0, |m| {
        field(field(to.encoded_len()) + field(m.encoded_len()) + 6 + field(32)) + SEAL_ALLOWANCE
    });
    field(recorded_request_len) + compensation + 2 * SEAL_ALLOWANCE + EFFECT_RESERVE
}

/// What a new effect without a request body (crypto, a secret reveal) or a
/// denial needs before it is recorded.
pub const SMALL_NEED: usize = EFFECT_RESERVE;

#[cfg(test)]
mod tests;
