//! The Protobuf schema for the Kronik log and the Rust code generated from it
//! with prost.
//!
//! The schema lives in `proto/kronik/log/v1/`. [`Record`] is the closed set of
//! log record types with their envelope kind bytes, and [`Record::decode`]
//! validates what it decodes: a value 0 or an unknown value in any enum, or a
//! missing required field, is an error (the log treats it as
//! `STORAGE_CORRUPT`), never a default operation.

pub mod http;
pub mod sealables;

#[allow(clippy::all, missing_docs)]
pub mod log {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/kronik.log.v1.rs"));
    }
}

use log::v1 as pb;
use prost::Message as _;

/// Why a record failed to decode or validate.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("unknown record kind {0}")]
    UnknownKind(u8),
    #[error("protobuf decode failed for record kind {kind}: {source}")]
    Protobuf {
        kind: u8,
        #[source]
        source: prost::DecodeError,
    },
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
}

fn invalid(what: &'static str, detail: impl Into<String>) -> DecodeError {
    DecodeError::Invalid {
        what,
        detail: detail.into(),
    }
}

/// One log record. The discriminant is the envelope `kind` byte.
// Records are built once per turn and moved a few times; boxing the large
// variants would only add noise at every construction and match.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Record {
    TurnBegin(pb::TurnBegin),
    EffectResult(pb::EffectResult),
    TurnRecord(pb::TurnRecord),
    Deployment(pb::Deployment),
    Grant(pb::Grant),
    Limits(pb::Limits),
    Policy(pb::Policy),
    Approval(pb::Approval),
    PrivacyMode(pb::PrivacyMode),
    ForeignActor(pb::ForeignActor),
    BranchCreated(pb::BranchCreated),
    Erasure(pb::Erasure),
    EngineUpgrade(pb::EngineUpgrade),
    SnapshotMarker(pb::SnapshotMarker),
    SimulatorConfig(pb::SimulatorConfig),
    StateRebase(pb::StateRebase),
    GuardTriggered(pb::GuardTriggered),
    AuditEvent(pb::AuditEvent),
}

/// Envelope kind bytes. 0 and every value not listed here are invalid.
pub mod kind {
    pub const TURN_BEGIN: u8 = 1;
    pub const EFFECT_RESULT: u8 = 2;
    pub const TURN_RECORD: u8 = 3;
    pub const DEPLOYMENT: u8 = 4;
    pub const GRANT: u8 = 5;
    pub const LIMITS: u8 = 6;
    pub const POLICY: u8 = 7;
    pub const APPROVAL: u8 = 8;
    pub const PRIVACY_MODE: u8 = 9;
    pub const FOREIGN_ACTOR: u8 = 10;
    pub const BRANCH_CREATED: u8 = 11;
    pub const ERASURE: u8 = 12;
    pub const ENGINE_UPGRADE: u8 = 13;
    pub const SNAPSHOT_MARKER: u8 = 14;
    pub const SIMULATOR_CONFIG: u8 = 15;
    pub const STATE_REBASE: u8 = 16;
    pub const GUARD_TRIGGERED: u8 = 17;
    pub const AUDIT_EVENT: u8 = 40;
    /// All valid kinds, in order.
    pub const ALL: [u8; 18] = [
        TURN_BEGIN,
        EFFECT_RESULT,
        TURN_RECORD,
        DEPLOYMENT,
        GRANT,
        LIMITS,
        POLICY,
        APPROVAL,
        PRIVACY_MODE,
        FOREIGN_ACTOR,
        BRANCH_CREATED,
        ERASURE,
        ENGINE_UPGRADE,
        SNAPSHOT_MARKER,
        SIMULATOR_CONFIG,
        STATE_REBASE,
        GUARD_TRIGGERED,
        AUDIT_EVENT,
    ];
}

impl Record {
    /// The envelope kind byte.
    pub fn kind(&self) -> u8 {
        match self {
            Record::TurnBegin(_) => kind::TURN_BEGIN,
            Record::EffectResult(_) => kind::EFFECT_RESULT,
            Record::TurnRecord(_) => kind::TURN_RECORD,
            Record::Deployment(_) => kind::DEPLOYMENT,
            Record::Grant(_) => kind::GRANT,
            Record::Limits(_) => kind::LIMITS,
            Record::Policy(_) => kind::POLICY,
            Record::Approval(_) => kind::APPROVAL,
            Record::PrivacyMode(_) => kind::PRIVACY_MODE,
            Record::ForeignActor(_) => kind::FOREIGN_ACTOR,
            Record::BranchCreated(_) => kind::BRANCH_CREATED,
            Record::Erasure(_) => kind::ERASURE,
            Record::EngineUpgrade(_) => kind::ENGINE_UPGRADE,
            Record::SnapshotMarker(_) => kind::SNAPSHOT_MARKER,
            Record::SimulatorConfig(_) => kind::SIMULATOR_CONFIG,
            Record::StateRebase(_) => kind::STATE_REBASE,
            Record::GuardTriggered(_) => kind::GUARD_TRIGGERED,
            Record::AuditEvent(_) => kind::AUDIT_EVENT,
        }
    }

    /// The protobuf encoding of the record body (without envelope).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Record::TurnBegin(m) => m.encode_to_vec(),
            Record::EffectResult(m) => m.encode_to_vec(),
            Record::TurnRecord(m) => m.encode_to_vec(),
            Record::Deployment(m) => m.encode_to_vec(),
            Record::Grant(m) => m.encode_to_vec(),
            Record::Limits(m) => m.encode_to_vec(),
            Record::Policy(m) => m.encode_to_vec(),
            Record::Approval(m) => m.encode_to_vec(),
            Record::PrivacyMode(m) => m.encode_to_vec(),
            Record::ForeignActor(m) => m.encode_to_vec(),
            Record::BranchCreated(m) => m.encode_to_vec(),
            Record::Erasure(m) => m.encode_to_vec(),
            Record::EngineUpgrade(m) => m.encode_to_vec(),
            Record::SnapshotMarker(m) => m.encode_to_vec(),
            Record::SimulatorConfig(m) => m.encode_to_vec(),
            Record::StateRebase(m) => m.encode_to_vec(),
            Record::GuardTriggered(m) => m.encode_to_vec(),
            Record::AuditEvent(m) => m.encode_to_vec(),
        }
    }

    /// The length of [`Record::encode`], without encoding.
    pub fn encoded_len(&self) -> usize {
        match self {
            Record::TurnBegin(m) => m.encoded_len(),
            Record::EffectResult(m) => m.encoded_len(),
            Record::TurnRecord(m) => m.encoded_len(),
            Record::Deployment(m) => m.encoded_len(),
            Record::Grant(m) => m.encoded_len(),
            Record::Limits(m) => m.encoded_len(),
            Record::Policy(m) => m.encoded_len(),
            Record::Approval(m) => m.encoded_len(),
            Record::PrivacyMode(m) => m.encoded_len(),
            Record::ForeignActor(m) => m.encoded_len(),
            Record::BranchCreated(m) => m.encoded_len(),
            Record::Erasure(m) => m.encoded_len(),
            Record::EngineUpgrade(m) => m.encoded_len(),
            Record::SnapshotMarker(m) => m.encoded_len(),
            Record::SimulatorConfig(m) => m.encoded_len(),
            Record::StateRebase(m) => m.encoded_len(),
            Record::GuardTriggered(m) => m.encoded_len(),
            Record::AuditEvent(m) => m.encoded_len(),
        }
    }

    /// Decodes and validates a record body.
    pub fn decode(kind: u8, bytes: &[u8]) -> Result<Record, DecodeError> {
        fn de<M: prost::Message + Default>(kind: u8, bytes: &[u8]) -> Result<M, DecodeError> {
            M::decode(bytes).map_err(|source| DecodeError::Protobuf { kind, source })
        }
        let record = match kind {
            kind::TURN_BEGIN => Record::TurnBegin(de(kind, bytes)?),
            kind::EFFECT_RESULT => Record::EffectResult(de(kind, bytes)?),
            kind::TURN_RECORD => Record::TurnRecord(de(kind, bytes)?),
            kind::DEPLOYMENT => Record::Deployment(de(kind, bytes)?),
            kind::GRANT => Record::Grant(de(kind, bytes)?),
            kind::LIMITS => Record::Limits(de(kind, bytes)?),
            kind::POLICY => Record::Policy(de(kind, bytes)?),
            kind::APPROVAL => Record::Approval(de(kind, bytes)?),
            kind::PRIVACY_MODE => Record::PrivacyMode(de(kind, bytes)?),
            kind::FOREIGN_ACTOR => Record::ForeignActor(de(kind, bytes)?),
            kind::BRANCH_CREATED => Record::BranchCreated(de(kind, bytes)?),
            kind::ERASURE => Record::Erasure(de(kind, bytes)?),
            kind::ENGINE_UPGRADE => Record::EngineUpgrade(de(kind, bytes)?),
            kind::SNAPSHOT_MARKER => Record::SnapshotMarker(de(kind, bytes)?),
            kind::SIMULATOR_CONFIG => Record::SimulatorConfig(de(kind, bytes)?),
            kind::STATE_REBASE => Record::StateRebase(de(kind, bytes)?),
            kind::GUARD_TRIGGERED => Record::GuardTriggered(de(kind, bytes)?),
            kind::AUDIT_EVENT => Record::AuditEvent(de(kind, bytes)?),
            other => return Err(DecodeError::UnknownKind(other)),
        };
        record.validate()?;
        Ok(record)
    }

    /// Checks enum values (0 and unknown are invalid) and required fields.
    pub fn validate(&self) -> Result<(), DecodeError> {
        match self {
            Record::TurnBegin(m) => {
                actor(m.actor.as_ref(), "TurnBegin.actor")?;
                causal(m.causal_key.as_ref(), "TurnBegin.causal_key")?;
                input(m.input.as_ref(), "TurnBegin.input")
            }
            Record::EffectResult(m) => effect(m.effect.as_ref(), "EffectResult.effect"),
            Record::TurnRecord(m) => turn_record(m),
            Record::Deployment(m) => deployment(m),
            Record::Grant(m) => {
                enum_value::<pb::GrantOp>(m.op, "Grant.op")?;
                if let Some(delivery) = m.delivery {
                    enum_value::<pb::Delivery>(delivery, "Grant.delivery")?;
                }
                Ok(())
            }
            Record::Limits(_) | Record::Policy(_) | Record::Approval(_) => Ok(()),
            Record::PrivacyMode(m) => enum_value::<pb::PrivacyState>(m.mode, "PrivacyMode.mode"),
            Record::ForeignActor(m) => {
                enum_value::<pb::ForeignOp>(m.op, "ForeignActor.op")?;
                if m.op == pb::ForeignOp::Add as i32 {
                    enum_value::<pb::Isolation>(m.isolation, "ForeignActor.isolation")?;
                }
                if !matches!(m.fork_mode.as_str(), "" | "recorded" | "sandbox") {
                    return Err(invalid(
                        "ForeignActor.fork_mode",
                        "recorded or sandbox required",
                    ));
                }
                Ok(())
            }
            Record::BranchCreated(_)
            | Record::Erasure(_)
            | Record::EngineUpgrade(_)
            | Record::SnapshotMarker(_) => Ok(()),
            Record::SimulatorConfig(m) => {
                let ok = m.target.split_once(':').is_some_and(|(scheme, host)| {
                    matches!(scheme, "http" | "foreign") && !host.is_empty()
                });
                if !ok {
                    return Err(invalid(
                        "SimulatorConfig.target",
                        "http:<host> or foreign:<name> required",
                    ));
                }
                Ok(())
            }
            Record::StateRebase(m) => {
                if m.rebase_id.is_empty() {
                    return Err(invalid("StateRebase.rebase_id", "required"));
                }
                match &m.part {
                    Some(pb::state_rebase::Part::Turn(t)) => {
                        turn_record(some(t.record.as_ref(), "RebasedTurn.record")?)
                    }
                    Some(pb::state_rebase::Part::Switch(s)) => {
                        deployment(some(s.deployment.as_ref(), "RebaseSwitch.deployment")?)?;
                        let range_ok = if s.turns == 0 {
                            s.first_turn_lsn == 0 && s.last_turn_lsn == 0
                        } else {
                            s.base_lsn < s.first_turn_lsn
                                && s.first_turn_lsn <= s.last_turn_lsn
                                && s.last_turn_lsn - s.first_turn_lsn + 1 >= s.turns
                        };
                        if !range_ok {
                            return Err(invalid(
                                "RebaseSwitch.turns",
                                "turn LSN range after base_lsn holding `turns` records required",
                            ));
                        }
                        Ok(())
                    }
                    None => Err(invalid("StateRebase.part", "turn or switch required")),
                }
            }
            Record::GuardTriggered(m) => {
                enum_value::<pb::GuardAction>(m.action, "GuardTriggered.action")?;
                enum_value::<pb::GuardOutcome>(m.outcome, "GuardTriggered.outcome")
            }
            Record::AuditEvent(m) => {
                some(m.audit.as_ref(), "AuditEvent.audit")?;
                if m.action.is_empty() {
                    return Err(invalid("AuditEvent.action", "empty"));
                }
                Ok(())
            }
        }
    }

    /// The turn a record holds: a `TurnRecord`, or a rebased turn copied
    /// into main's log by a rollback via replay (ADR 0017).
    pub fn turn(&self) -> Option<&pb::TurnRecord> {
        match self {
            Record::TurnRecord(t) => Some(t),
            Record::StateRebase(pb::StateRebase {
                part: Some(pb::state_rebase::Part::Turn(t)),
                ..
            }) => t.record.as_ref(),
            _ => None,
        }
    }

    /// [`Record::turn`], mutable (reseal).
    pub fn turn_mut(&mut self) -> Option<&mut pb::TurnRecord> {
        match self {
            Record::TurnRecord(t) => Some(t),
            Record::StateRebase(pb::StateRebase {
                part: Some(pb::state_rebase::Part::Turn(t)),
                ..
            }) => t.record.as_mut(),
            _ => None,
        }
    }

    /// The switch of a rollback via replay, if this is one.
    pub fn rebase_switch(&self) -> Option<(&str, &pb::RebaseSwitch)> {
        match self {
            Record::StateRebase(pb::StateRebase {
                rebase_id,
                part: Some(pb::state_rebase::Part::Switch(s)),
            }) => Some((rebase_id, s)),
            _ => None,
        }
    }
}

fn deployment(m: &pb::Deployment) -> Result<(), DecodeError> {
    enum_value::<pb::DeploymentCause>(m.cause, "Deployment.cause")?;
    for k in &m.kinds {
        if k.kind.is_empty() || k.code_hash.len() != 32 {
            return Err(invalid(
                "Deployment.kinds",
                "kind and 32-byte code_hash required",
            ));
        }
        some(k.manifest.as_ref(), "KindVersion.manifest")?;
    }
    Ok(())
}

fn enum_value<E: TryFrom<i32>>(value: i32, what: &'static str) -> Result<(), DecodeError> {
    if value == 0 {
        return Err(invalid(what, "enum value 0 (UNSPECIFIED)"));
    }
    E::try_from(value)
        .map(|_| ())
        .map_err(|_| invalid(what, format!("unknown enum value {value}")))
}

fn some<'a, T>(value: Option<&'a T>, what: &'static str) -> Result<&'a T, DecodeError> {
    value.ok_or_else(|| invalid(what, "missing"))
}

fn actor(value: Option<&pb::ActorRef>, what: &'static str) -> Result<(), DecodeError> {
    let a = some(value, what)?;
    if a.kind.is_empty() || a.key.is_empty() {
        return Err(invalid(what, "empty kind or key"));
    }
    Ok(())
}

fn causal(value: Option<&pb::CausalKey>, what: &'static str) -> Result<(), DecodeError> {
    let c = some(value, what)?;
    if c.root.is_empty() {
        return Err(invalid(what, "empty root"));
    }
    for step in &c.path {
        actor(step.actor.as_ref(), "CausalStep.actor")?;
    }
    Ok(())
}

fn sealable(value: Option<&pb::Sealable>, what: &'static str) -> Result<(), DecodeError> {
    match some(value, what)?.value {
        Some(_) => Ok(()),
        None => Err(invalid(what, "neither plain nor sealed")),
    }
}

fn body(value: Option<&pb::Body>, what: &'static str) -> Result<(), DecodeError> {
    match &some(value, what)?.value {
        Some(pb::body::Value::Inline(s)) => sealable(Some(s), what),
        Some(pb::body::Value::Blob(_)) => Ok(()),
        None => Err(invalid(what, "neither inline nor blob")),
    }
}

fn headers(headers: &[pb::Header]) -> Result<(), DecodeError> {
    for h in headers {
        sealable(h.value.as_ref(), "Header.value")?;
    }
    Ok(())
}

fn message(value: Option<&pb::Message>, what: &'static str) -> Result<(), DecodeError> {
    sealable(some(value, what)?.body.as_ref(), what)
}

fn input(value: Option<&pb::Input>, what: &'static str) -> Result<(), DecodeError> {
    use pb::input::Kind;
    match &some(value, what)?.kind {
        Some(Kind::Http(h)) => {
            // The sealable request line is optional (records from before
            // it, requests without a subject), but a present one has a value.
            for (s, what) in [
                (h.sealed_path.as_ref(), "HttpInput.sealed_path"),
                (h.sealed_query.as_ref(), "HttpInput.sealed_query"),
            ] {
                if s.is_some() {
                    sealable(s, what)?;
                }
            }
            for p in &h.params {
                if p.sealed_value.is_some() {
                    sealable(p.sealed_value.as_ref(), "Param.sealed_value")?;
                }
            }
            headers(&h.headers)?;
            body(h.body.as_ref(), "HttpInput.body")
        }
        Some(Kind::Message(m)) => {
            enum_value::<pb::MessageSource>(m.source, "MessageInput.source")?;
            if m.source == pb::MessageSource::Actor as i32 {
                actor(m.sender.as_ref(), "MessageInput.sender")?;
            }
            message(m.msg.as_ref(), "MessageInput.msg")
        }
        Some(Kind::Timer(t)) => message(t.msg.as_ref(), "TimerInput.msg"),
        Some(Kind::Migrate(_)) => Ok(()),
        None => Err(invalid(what, "no input case set")),
    }
}

fn effect(value: Option<&pb::EffectRecord>, what: &'static str) -> Result<(), DecodeError> {
    let e = some(value, what)?;
    enum_value::<pb::EffectStatus>(e.status, "EffectRecord.status")?;
    enum_value::<pb::Grounding>(e.grounding, "EffectRecord.grounding")?;
    match e.delivery.as_str() {
        "" | "replay-safe" | "idempotency-keyed" | "unsafe" => Ok(()),
        other => Err(invalid(
            "EffectRecord.delivery",
            format!("unknown delivery {other:?}"),
        )),
    }
}

fn outbound(m: &pb::OutboundMessage, what: &'static str) -> Result<(), DecodeError> {
    actor(m.to.as_ref(), what)?;
    message(m.msg.as_ref(), what)
}

fn turn_record(m: &pb::TurnRecord) -> Result<(), DecodeError> {
    actor(m.actor.as_ref(), "TurnRecord.actor")?;
    causal(m.causal_key.as_ref(), "TurnRecord.causal_key")?;
    input(m.input.as_ref(), "TurnRecord.input")?;
    for e in &m.effects {
        effect(Some(e), "TurnRecord.effects")?;
    }
    for w in &m.writes {
        enum_value::<pb::StateOp>(w.op, "StateWrite.op")?;
        if w.op == pb::StateOp::Set as i32 {
            sealable(w.value.as_ref(), "StateWrite.value")?;
        }
    }
    for o in &m.messages {
        outbound(o, "TurnRecord.messages")?;
    }
    for o in &m.compensations {
        outbound(o, "TurnRecord.compensations")?;
    }
    for t in &m.timers {
        enum_value::<pb::TimerOpKind>(t.kind, "TimerOp.kind")?;
        if t.kind == pb::TimerOpKind::Schedule as i32 {
            message(t.msg.as_ref(), "TimerOp.msg")?;
        }
    }
    let outcome = some(m.outcome.as_ref(), "TurnRecord.outcome")?;
    enum_value::<pb::OutcomeKind>(outcome.kind, "Outcome.kind")?;
    match &outcome.output {
        Some(pb::outcome::Output::Reply(r)) => message(Some(r), "Outcome.reply")?,
        Some(pb::outcome::Output::Http(h)) => {
            headers(&h.headers)?;
            body(h.body.as_ref(), "Outcome.http.body")?;
        }
        None => {}
    }
    for c in &m.sql_changes {
        sealable(c.changeset.as_ref(), "SqlChangeset.changeset")?;
    }
    for b in &m.blob_refs {
        enum_value::<pb::blob_ref_op::Kind>(b.kind, "BlobRefOp.kind")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(bytes: &[u8]) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
        })
    }

    fn turn_record() -> pb::TurnRecord {
        pb::TurnRecord {
            execution_id: "e".into(),
            actor: Some(pb::ActorRef {
                kind: "counter".into(),
                key: "a".into(),
            }),
            causal_key: Some(pb::CausalKey {
                root: "r".into(),
                path: vec![],
            }),
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Message(pb::MessageInput {
                    source: pb::MessageSource::Operator as i32,
                    msg: Some(pb::Message {
                        name: "inc".into(),
                        body: plain(b""),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }),
            writes: vec![pb::StateWrite {
                op: pb::StateOp::Set as i32,
                key: "n".into(),
                value: plain(b"1"),
            }],
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_turn_record() {
        let record = Record::TurnRecord(turn_record());
        let bytes = record.encode();
        assert_eq!(Record::decode(kind::TURN_RECORD, &bytes).unwrap(), record);
    }

    #[test]
    fn enum_zero_and_unknown_are_invalid() {
        let mut t = turn_record();
        t.writes[0].op = 0;
        let err = Record::decode(kind::TURN_RECORD, &Record::TurnRecord(t).encode());
        assert!(matches!(err, Err(DecodeError::Invalid { .. })));

        let mut t = turn_record();
        t.writes[0].op = 99;
        let err = Record::decode(kind::TURN_RECORD, &Record::TurnRecord(t).encode());
        assert!(matches!(err, Err(DecodeError::Invalid { .. })));

        let mut t = turn_record();
        t.outcome = Some(pb::Outcome::default());
        let err = Record::decode(kind::TURN_RECORD, &Record::TurnRecord(t).encode());
        assert!(matches!(err, Err(DecodeError::Invalid { .. })));
    }

    #[test]
    fn missing_oneof_is_invalid() {
        let mut t = turn_record();
        t.input = Some(pb::Input { kind: None });
        let err = Record::decode(kind::TURN_RECORD, &Record::TurnRecord(t).encode());
        assert!(matches!(err, Err(DecodeError::Invalid { .. })));
    }

    #[test]
    fn unknown_kind_is_invalid() {
        assert!(matches!(
            Record::decode(0, &[]),
            Err(DecodeError::UnknownKind(0))
        ));
        assert!(matches!(
            Record::decode(18, &[]),
            Err(DecodeError::UnknownKind(18))
        ));
    }

    /// The committed bytes of an M28 `EffectRecord` with `offset_us` (field
    /// 80) set decode, and the encoder still writes exactly them (I16).
    /// Fixture: `tests/fixtures/effect-record-v2.hex`, the v1 fixture plus
    /// field 80 = 250.
    #[test]
    fn effect_record_fixture_with_offset_us_round_trips() {
        use prost::Message as _;
        let hex = include_str!("../tests/fixtures/effect-record-v2.hex").trim();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let e = pb::EffectRecord::decode(bytes.as_slice()).unwrap();
        assert_eq!(
            (e.kind.as_str(), e.duration_us, e.offset_us),
            ("http.fetch", 1_500, 250)
        );
        assert_eq!(e.encode_to_vec(), bytes);
    }

    /// The committed bytes of an M28 `AuditEvent` decode, and the encoder
    /// still writes exactly them (I16). Fixture: `tests/fixtures/audit-event-v1.hex`.
    #[test]
    fn audit_event_fixture_decodes_and_requires_action_and_audit() {
        let hex = include_str!("../tests/fixtures/audit-event-v1.hex").trim();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let record = Record::decode(kind::AUDIT_EVENT, &bytes).unwrap();
        let Record::AuditEvent(e) = &record else {
            panic!("{record:?}")
        };
        assert_eq!((e.action.as_str(), e.target.as_str()), ("secret.set", "db"));
        assert_eq!(e.details.get("version").map(String::as_str), Some("2"));
        let audit = e.audit.as_ref().unwrap();
        assert_eq!(
            (audit.token_id.as_str(), audit.reason.as_str()),
            ("kronik", "rotate")
        );
        assert_eq!(record.encode(), bytes);

        let mut no_audit = e.clone();
        no_audit.audit = None;
        let mut no_action = e.clone();
        no_action.action.clear();
        for bad in [no_audit, no_action] {
            let err = Record::decode(kind::AUDIT_EVENT, &Record::AuditEvent(bad).encode());
            assert!(matches!(err, Err(DecodeError::Invalid { .. })), "{err:?}");
        }
    }

    /// A present sealable path, query or parameter value must hold a value,
    /// like a header or body (v0.1 re-review R4); absent ones are fine.
    #[test]
    fn the_sealable_request_line_is_validated() {
        let http = |path: Option<pb::Sealable>, param: Option<pb::Sealable>| {
            let mut t = turn_record();
            t.input = Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    method: "POST".into(),
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(plain(b"").unwrap_or_default())),
                    }),
                    sealed_path: path,
                    params: vec![pb::Param {
                        name: "key".into(),
                        value: String::new(),
                        sealed_value: param,
                    }],
                    ..Default::default()
                })),
            });
            Record::decode(kind::TURN_RECORD, &Record::TurnRecord(t).encode())
        };
        let empty = Some(pb::Sealable {
            subject: Some("user:1".into()),
            value: None,
        });
        assert!(http(None, None).is_ok());
        assert!(http(plain(b"/notes/n1"), plain(b"n1")).is_ok());
        assert!(matches!(
            http(empty.clone(), None),
            Err(DecodeError::Invalid { .. })
        ));
        assert!(matches!(
            http(None, empty),
            Err(DecodeError::Invalid { .. })
        ));
    }

    fn unhex(hex: &str) -> Vec<u8> {
        let hex = hex.trim();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A TurnRecord written before `duration_us` existed decodes with 0.
    /// Fixture: `tests/fixtures/turn-record-v1.hex`.
    #[test]
    fn turn_records_from_before_duration_decode_with_zero() {
        let bytes = unhex(include_str!("../tests/fixtures/turn-record-v1.hex"));
        let Record::TurnRecord(t) = Record::decode(kind::TURN_RECORD, &bytes).unwrap() else {
            panic!("not a TurnRecord");
        };
        assert_eq!(t, turn_record());
        assert_eq!(t.duration_us, 0);
    }

    fn guard_triggered() -> pb::GuardTriggered {
        let window = |from_lsn, to_lsn, from_time_ms, turns, failed| pb::GuardWindow {
            from_lsn,
            to_lsn,
            from_time_ms,
            to_time_ms: from_time_ms + 600_000,
            turns,
            failed,
            error_rate: failed as f64 / turns as f64,
            latency_p50_us: 1_200,
            latency_p99_us: 9_800,
        };
        pb::GuardTriggered {
            deployment_epoch: 7,
            deployment_lsn: 120,
            watch_id: "w-3k9x2a7b1c0d".into(),
            guard: "error-rate-up".into(),
            action: pb::GuardAction::Rollback as i32,
            outcome: pb::GuardOutcome::RolledBack as i32,
            before: Some(window(20, 119, 1_000, 40, 0)),
            after: Some(window(121, 180, 601_000, 20, 10)),
            observed_lsn: 181,
            rollback_epoch: 8,
            reason: "guard.after.error_rate > guard.before.error_rate + 0.05".into(),
            audit: Some(pb::Audit {
                token_id: "kronik".into(),
                reason: "watch w-3k9x2a7b1c0d".into(),
                wall_time_ms: 1_700_000_000_000,
            }),
        }
    }

    /// The first GuardTriggered format stays readable.
    /// Fixture: `tests/fixtures/guard-triggered-v1.hex`.
    #[test]
    fn guard_triggered_v1_decodes() {
        let bytes = unhex(include_str!("../tests/fixtures/guard-triggered-v1.hex"));
        let record = Record::decode(kind::GUARD_TRIGGERED, &bytes).unwrap();
        assert_eq!(record, Record::GuardTriggered(guard_triggered()));

        let mut g = guard_triggered();
        g.outcome = 0;
        let err = Record::decode(kind::GUARD_TRIGGERED, &Record::GuardTriggered(g).encode());
        assert!(matches!(err, Err(DecodeError::Invalid { .. })));
    }
}
