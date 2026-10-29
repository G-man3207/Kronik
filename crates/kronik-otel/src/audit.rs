//! The audit line mapping (docs/design/m28-otel.md §4.1, §4.3; ADRs 0082,
//! 0083): which records are audited, and the `kronik.audit/v1` line of each,
//! as pure functions of the record. The exporter, `kronik audit show` and
//! `kronik audit verify` all build lines here.

use kronik_core::ids::hex;
use kronik_proto::log::v1 as pb;
use kronik_proto::{Record, sealables};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::spans::ActorKeys;

/// The `schema` of every line.
pub const SCHEMA: &str = "kronik.audit/v1";

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
        | Record::AuditEvent(_) => Class::Record,
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
    pub lsn: u64,
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
    pub branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    pub details: Map<String, Value>,
    pub record_hash: String,
}

impl Line {
    /// The line as written to a sink, without its `\n`.
    pub fn to_json(&self) -> String {
        // A struct of strings, integers and JSON values always serializes.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The (lsn, effect) pair two lines of one item share.
    pub fn item(&self) -> (u64, Option<u32>) {
        (self.lsn, self.effect)
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
    /// Every stored secret value, scrubbed from free text (I8).
    pub secrets: &'a [(String, Vec<u8>)],
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
    pub fn lines(&self, lsn: u64, record: &Record, secrets: &[(String, Vec<u8>)]) -> Vec<Line> {
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
        lines(
            lsn,
            record,
            &Ctx {
                branch: &self.branch,
                keys: &keys,
                subject: &subject,
                secrets,
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

/// The blake3 of the record's canonical form: its encoding with every
/// `Sealable` reduced to its subject tag (review M2), so a reseal leaves it
/// unchanged and it reveals no value. An erasure's subject, the one field
/// its line leaves out, is replaced by its keyed `subject` label, in the
/// reason too: hashed in plain, it would let a backend test guessed
/// subjects against the hash (review M6). So is the key of an audit
/// event's `actor` detail (`fork.send`, review R1), which its line hashes
/// or omits.
pub fn record_hash(record: &Record, subject: &dyn Fn(&str) -> String) -> String {
    let mut canon = record.clone();
    sealables::record_mut(&mut canon, &mut |s| s.value = None);
    match &mut canon {
        Record::Erasure(e) => {
            let label = subject(&e.subject);
            if let Some(a) = e.audit.as_mut().filter(|_| !e.subject.is_empty()) {
                a.reason = a.reason.replace(&e.subject, &label);
            }
            e.subject = label;
        }
        Record::AuditEvent(e) => {
            if let Some(v) = e.details.get_mut("actor") {
                let (kind, key) = v.split_once('/').unwrap_or((v.as_str(), ""));
                *v = format!("{kind}/{}", subject(key));
            }
        }
        _ => {}
    }
    let mut h = blake3::Hasher::new();
    h.update(&[canon.kind()]);
    h.update(&canon.encode());
    format!("b3:{}", h.finalize().to_hex())
}

/// The lines of one committed record, in order: none for a record that is
/// not audited.
pub fn lines(lsn: u64, record: &Record, ctx: &Ctx) -> Vec<Line> {
    let mut out = Vec::new();
    let line = |kind: &str, action: &str, audit: Option<&pb::Audit>, epoch, details| Line {
        schema: SCHEMA.into(),
        lsn,
        effect: None,
        kind: kind.into(),
        action: action.into(),
        at_wall_ms: audit.map_or(0, |a| a.wall_time_ms),
        token_id: audit.map(|a| a.token_id.clone()).unwrap_or_default(),
        reason: audit.map(|a| a.reason.clone()).unwrap_or_default(),
        reason_truncated: false,
        branch: ctx.branch.into(),
        epoch,
        details,
        record_hash: String::new(),
    };
    match record {
        Record::Deployment(d) => {
            let action = match pb::DeploymentCause::try_from(d.cause) {
                Ok(pb::DeploymentCause::Promote) => "promote",
                Ok(pb::DeploymentCause::Rollback) => "rollback",
                _ => "deploy",
            };
            let kinds: Vec<Value> = d
                .kinds
                .iter()
                .map(|k| {
                    json!({"kind": k.kind, "code_hash": format!("b3:{}", hex(&k.code_hash)),
                           "schema_version": k.schema_version})
                })
                .collect();
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
                "command": kronik_effects::http::scrub_str(&a.command, ctx.secrets),
            }));
            out.push(line("approval", action, a.audit.as_ref(), None, details));
        }
        Record::PrivacyMode(p) => {
            let mode = pb::PrivacyState::try_from(p.mode).unwrap_or(pb::PrivacyState::Unspecified);
            let details = obj(json!({"mode": label(mode.as_str_name(), "PRIVACY_STATE_")}));
            out.push(line(
                "privacy_mode",
                "privacy.mode",
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
            let hashed = (ctx.subject)(&e.subject);
            let details = obj(json!({"subject": hashed, "key_version": e.key_version}));
            let mut l = line(
                "erasure",
                "privacy.erase",
                e.audit.as_ref(),
                Some(e.epoch),
                details,
            );
            // Review M8: the reason usually names the subject.
            if !e.subject.is_empty() {
                l.reason = l.reason.replace(&e.subject, &hashed);
            }
            out.push(l);
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
            let outcome =
                pb::GuardOutcome::try_from(g.outcome).map_or("unspecified", |o| o.as_str_name());
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
        Record::AuditEvent(a) => {
            let mut details = Map::new();
            for (k, v) in &a.details {
                let v = kronik_effects::http::scrub_str(v, ctx.secrets);
                // fork.send names its actor plain (kronik-api m3.rs).
                if k == "actor" {
                    let (kind, key) = v.split_once('/').unwrap_or((&v, ""));
                    if let Some(key) = ctx.keys.export(kind, key) {
                        details.insert(k.clone(), format!("{kind}/{key}").into());
                    }
                    continue;
                }
                details.insert(k.clone(), v.into());
            }
            details.insert(
                "target".into(),
                kronik_effects::http::scrub_str(&a.target, ctx.secrets).into(),
            );
            out.push(line(
                "audit_event",
                &a.action,
                a.audit.as_ref(),
                None,
                details,
            ));
        }
        Record::TurnRecord(t) => turn_lines(t, ctx, &line, &mut out),
        Record::TurnBegin(_)
        | Record::EffectResult(_)
        | Record::BranchCreated(_)
        | Record::SnapshotMarker(_) => {}
    }
    if out.is_empty() {
        return out;
    }
    let hash = record_hash(record, ctx.subject);
    for l in &mut out {
        l.reason = kronik_effects::http::scrub_str(&l.reason, ctx.secrets);
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
    out
}

type LineFn<'a> =
    dyn Fn(&str, &str, Option<&pb::Audit>, Option<u64>, Map<String, Value>) -> Line + 'a;

/// An operator send or resend, then one line per `secret.reveal` effect
/// (review H3).
fn turn_lines(t: &pb::TurnRecord, ctx: &Ctx, line: &LineFn, out: &mut Vec<Line>) {
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
            && let Ok(r) = pb::RevealEffectRequest::decode(b.as_slice())
        {
            details.insert("version".into(), r.secret.map_or(0, |s| s.version).into());
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
    pub lsn: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<u32>,
    pub kind: String,
    pub action: String,
    pub record_hash: String,
}

impl From<&Line> for Item {
    fn from(l: &Line) -> Item {
        Item {
            lsn: l.lsn,
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

/// Compares `sink` lines (in the order they were written) with the log's
/// `expected` lines in `(from, to]`. Lines are deduplicated by (`lsn`,
/// `effect`, `record_hash`), and equal when `kind`, `action`, `token_id`
/// and `at_wall_ms` agree too. A `restore` line supersedes the lines
/// written before it with LSNs past its `through_lsn` (review H4).
pub fn verify(expected: &[Line], sink: &[Line], from: u64, to: u64) -> Report {
    use std::collections::{BTreeMap, BTreeSet};
    let mut superseded = vec![false; sink.len()];
    let mut restores = BTreeSet::new();
    for (i, l) in sink.iter().enumerate() {
        if l.kind == "audit_event"
            && l.action == "restore"
            && restores.insert((l.lsn, l.record_hash.clone()))
        {
            let through: u64 = l.details["through_lsn"]
                .as_str()
                .and_then(|t| t.parse().ok())
                .unwrap_or(u64::MAX);
            for (j, s) in sink[..i].iter().enumerate() {
                superseded[j] |= s.lsn > through;
            }
        }
    }
    let in_range = |l: &Line| l.lsn > from && l.lsn <= to;
    let want: BTreeMap<(u64, Option<u32>), &Line> = expected
        .iter()
        .filter(|l| in_range(l))
        .map(|l| (l.item(), l))
        .collect();
    let same = |a: &Line, b: &Line| {
        (
            &a.record_hash,
            &a.kind,
            &a.action,
            &a.token_id,
            a.at_wall_ms,
        ) == (
            &b.record_hash,
            &b.kind,
            &b.action,
            &b.token_id,
            b.at_wall_ms,
        )
    };
    let mut r = Report {
        from,
        to,
        expected: want.len(),
        ..Report::default()
    };
    let (mut seen, mut matched) = (BTreeSet::new(), BTreeSet::new());
    let (mut extra, mut conflicting) = (BTreeSet::new(), BTreeSet::new());
    for (l, gone) in sink.iter().zip(superseded) {
        if gone {
            r.superseded += 1;
            continue;
        }
        // A repeat of a line (a re-sent batch) counts once; a line that
        // differs in a compared field is a line of its own.
        let key = (
            l.lsn,
            l.effect,
            &l.record_hash,
            &l.kind,
            &l.action,
            &l.token_id,
            l.at_wall_ms,
        );
        if !in_range(l) || !seen.insert(key) {
            continue;
        }
        r.lines += 1;
        match want.get(&l.item()) {
            Some(w) if same(w, l) => {
                matched.insert(l.item());
            }
            Some(_) => {
                conflicting.insert(Item::from(l));
            }
            None => {
                extra.insert(Item::from(l));
            }
        }
    }
    r.missing = want
        .iter()
        .filter(|(k, _)| !matched.contains(*k))
        .map(|(_, l)| Item::from(*l))
        .collect();
    r.extra = extra.into_iter().collect();
    r.conflicting = conflicting.into_iter().collect();
    r.complete = r.missing.is_empty() && r.extra.is_empty() && r.conflicting.is_empty();
    r
}
