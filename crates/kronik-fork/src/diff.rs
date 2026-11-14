//! Comparison of fork turns with production turns and the `kronik.diff/v1`
//! document (docs/design/m3-fork.md §4-§5).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine as _;
use kronik_core::causal;
use kronik_core::ids::{ActorRef, CodeHash, Lsn};
use kronik_effects::http::target_of;
use kronik_privacy::sealer::Sealer;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_store::Store;
use kronik_store::sql::{RowChange, TableRows, changeset_rows};
use prost::Message as _;
use rusqlite::types::Value as SqlValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::index::{ProductionIndex, RootInput, input_label};
use crate::privacy::SQL_CONCEALED;
use crate::replay::{ForkTurn, ReplayError, TreeResult};

/// At most this many items per list in the diff; counts cover everything.
pub const MAX_ITEMS: usize = 200;
/// At most this many turn ids per sample category.
pub const MAX_SAMPLES: usize = 20;
/// At most this many samples per cause.
pub const MAX_CAUSE_SAMPLES: usize = 5;
/// At most this many error items per kind.
pub const MAX_ERRORS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Isolated,
    Continuous,
    Both,
}

impl Mode {
    pub fn isolated(self) -> bool {
        matches!(self, Mode::Isolated | Mode::Both)
    }

    pub fn continuous(self) -> bool {
        matches!(self, Mode::Continuous | Mode::Both)
    }
}

/// Replay options as recorded in the diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffOptions {
    pub mode: Mode,
    pub sample: f64,
    pub ignore_headers: Vec<String>,
    pub ignore_json_paths: Vec<String>,
    pub fuel_threshold: f64,
    /// Canned answers for effects without a recording (synthetic).
    #[serde(default)]
    pub stubs: Vec<crate::stubs::StubRule>,
    /// The `[fork] live_allowlist` hosts in force (live GETs).
    #[serde(default)]
    pub live_allowlist: Vec<String>,
    /// A fork without access to the privacy keys (`--no-pii`; values are
    /// pseudonymized from M8 on).
    #[serde(default)]
    pub no_pii: bool,
    /// The simulator configuration the replay used: main's as of the fork
    /// point plus `simulator_overrides` (M12, I5, ADR 0014); set when the
    /// diff is built.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub simulators: Vec<crate::simulators::SimulatorOption>,
    /// Per-target simulator configuration the replay request carried; it
    /// replaces main's for this fork, and catch-up and a replay after a
    /// restart use it again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub simulator_overrides: Vec<crate::simulators::SimulatorOverride>,
    /// The fork's `fork_mode = "sandbox"` foreign actors (M14, ADR 0019):
    /// the checkpoint each copy started from, or why it stayed recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub foreign: Vec<ForeignFork>,
}

/// What a fork did with one `fork_mode = "sandbox"` foreign actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignFork {
    pub name: String,
    /// `sandbox` (a copy answered) or `recorded` (no copy; see `why`).
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_lsn: Option<Lsn>,
    /// Main's recorded calls sent to the copy to bring it to the fork point.
    #[serde(default)]
    pub replayed_calls: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            mode: Mode::Both,
            sample: 1.0,
            ignore_headers: Vec::new(),
            ignore_json_paths: Vec::new(),
            fuel_threshold: 0.02,
            stubs: Vec::new(),
            live_allowlist: Vec::new(),
            no_pii: false,
            simulators: Vec::new(),
            simulator_overrides: Vec::new(),
            foreign: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base {
    pub branch: String,
    pub fork_lsn: Lsn,
    pub from_lsn: Lsn,
    pub to_lsn: Lsn,
    /// Set when retention cut the window short: the history it asked for
    /// starts before what the log and snapshots still hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_cut: Option<WindowCut>,
}

/// A proposal window cut short by retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowCut {
    /// The logical time the proposal asked to replay, back from the newest
    /// root input.
    pub window_ms: u64,
    /// The oldest snapshot the log continues: history before it is no
    /// longer kept, so the fork starts there.
    pub kept_from_lsn: Lsn,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CodeEntry {
    pub kind: String,
    pub code_hash: String,
    pub schema_version: u32,
}

impl CodeEntry {
    pub fn new(kind: &str, hash: &CodeHash, schema_version: u32) -> CodeEntry {
        CodeEntry {
            kind: kind.to_owned(),
            code_hash: hash.short(),
            schema_version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Code {
    pub before: Vec<CodeEntry>,
    pub after: Vec<CodeEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub root_inputs: u64,
    pub replayed: u64,
    pub sample: f64,
    pub turns_prod: u64,
    pub turns_fork: u64,
    pub divergent_turns: u64,
    pub origins: u64,
    pub consequences: u64,
    pub exact: u64,
    pub approximate: u64,
    pub synthetic: u64,
    /// Synthetic answers per simulator over all targets (M12).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub synthetic_by: BTreeMap<String, u64>,
    /// Live GETs from the fork (`[fork] live_allowlist`).
    #[serde(default)]
    pub live: u64,
    /// Answers of the fork's copies of foreign actors (M14, ADR 0020).
    #[serde(default)]
    pub forked: u64,
    /// Fork turns that read a pseudonym (`--no-pii`) or met erased data and
    /// differ from production, and production turns missing below them:
    /// `pii-masked`, not divergent (M8 §9, ADR 0109). Always present, so a
    /// rule can read it; diffs of older binaries lack it when 0.
    #[serde(default)]
    pub pii_masked: u64,
    /// Fork turns of a kind whose code changed that read a pseudonym or an
    /// erased value and came out identical to production: they did not
    /// run on the real value either, so they are unverified too (ADR 0031).
    /// Always present; 0 in identity replays.
    #[serde(default)]
    pub pii_unverified: u64,
    /// Turns that met erased data, differing or not: their recorded input,
    /// a state value they read, or an input or state that erased data
    /// shaped (a message of such a turn, state it or a production turn
    /// missing below it left different, an actor database lacking an erased
    /// subject's rows), and production turns missing below one. The replay
    /// ran them on what is left, so a difference is unverifiable rather than
    /// a change (S-16, ADR 0109). Always present; 0 when none.
    #[serde(default)]
    pub unverifiable: u64,
    /// Requests sent to a preview fork (M11): root inputs of their own,
    /// never compared with production nor counted as divergent.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub preview_inputs: u64,
    /// `frames.changed` (M24); absent when 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub frames_changed: u64,
    pub confidence: f64,
    pub verified_through_lsn: Lsn,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cause {
    pub kind: String,
    pub input: String,
    pub origins: u64,
    pub consequences: u64,
    pub root_inputs: u64,
    pub samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundingRow {
    pub kind: String,
    pub method: String,
    pub host: String,
    pub route: String,
    pub exact: u64,
    pub approximate: u64,
    pub synthetic: u64,
    /// Synthetic answers per simulator (`stub`, `contract`, `neighbor`,
    /// `model`, `fail-closed`, `placeholder`), M12.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub synthetic_by: BTreeMap<String, u64>,
    #[serde(default)]
    pub live: u64,
    /// Answers of a fork's copy of the foreign actor (M14).
    #[serde(default)]
    pub forked: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProdFork<T> {
    pub prod: T,
    pub fork: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderDiff {
    pub name: String,
    pub prod: Value,
    pub fork: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyOp {
    pub op: Cow<'static, str>,
    pub path: String,
    pub prod: Value,
    pub fork: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseItem {
    pub root_lsn: Lsn,
    pub route: String,
    pub turn_prod: String,
    pub turn_fork: Option<String>,
    pub status: ProdFork<Option<u32>>,
    pub headers: Vec<HeaderDiff>,
    pub body: Vec<BodyOp>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Responses {
    pub unchanged: u64,
    pub changed: u64,
    pub items: Vec<ResponseItem>,
}

/// The connection root inputs of the window, by event (M24 §7.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameInputs {
    pub open: u64,
    pub frame: u64,
    pub close: u64,
}

/// How the fork's `connection.send-now` effects were answered (M24 §7.3):
/// from the recording (exact or approximate), or by the connection model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendNowAnswers {
    pub recorded: u64,
    pub modeled: u64,
}

/// One changed outgoing connection operation of a root input's tree: a
/// frame (`send`, `broadcast` or `send-now`) or a close (M24 §7.4, §7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameChange {
    /// The operation's position in the tree: its turns in causal order,
    /// each with its `send-now` frames, then its buffered operations.
    pub index: u64,
    /// `added`, `removed` or `changed`.
    pub change: Cow<'static, str>,
    /// How many connections the operation names (production's, else the
    /// fork's).
    pub targets: u64,
    /// The first 5 of them.
    pub connections: Vec<String>,
    /// `text`, `binary`, `event` or `close` on each side; null when that
    /// side has no operation here.
    pub kind: ProdFork<Option<String>>,
    /// Whether each side's frame went out with `send-now`; absent when
    /// neither did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_now: Option<ProdFork<bool>>,
    /// The SSE `event:` and `id:` fields on each side, when they differ;
    /// null otherwise.
    pub event: Option<ProdFork<Value>>,
    /// The data (a close's reason): JSON pointer operations when both sides
    /// are JSON, else one operation at `""`. Values with a subject are
    /// redacted.
    pub data: Vec<BodyOp>,
    /// A close's code on each side, when they differ; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ProdFork<Option<u32>>>,
}

/// A root input whose tree sends other frames, or whose open is answered
/// otherwise, in the fork (M24 §7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameItem {
    pub root_lsn: Lsn,
    /// The input's label (`kronik_fork::index::input_label`): never a
    /// connection id, path or data.
    pub input: String,
    pub turn_prod: String,
    pub turn_fork: String,
    /// `accept`, `refuse <status>` or `fail <error code>` on each side, when
    /// the open's answer changed; null otherwise.
    pub open: Option<ProdFork<String>>,
    /// The changed operations, at most 20.
    pub frames: Vec<FrameChange>,
}

/// The `frames` section (M24 §7.5, ADR 0116): what the root inputs sent to
/// long-lived connections, production against the fork. Absent when the
/// window has no connection input and no turn sent a frame.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Frames {
    pub inputs: FrameInputs,
    /// Replayed root inputs (connection inputs, and any input whose tree
    /// sent frames) whose operations and open answer are identical.
    pub unchanged: u64,
    pub changed: u64,
    /// Continuous replay: frame and close inputs not run because the fork's
    /// actor never accepted their connection (§7.2).
    pub skipped: u64,
    /// Outgoing frame targets: every live target of a send or broadcast,
    /// and every `send-now` answered `ok`.
    pub sent: ProdFork<u64>,
    pub send_now: SendNowAnswers,
    /// The changed inputs, in root LSN order, at most 200.
    pub items: Vec<FrameItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    pub prod: Value,
    pub fork: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectItem {
    pub change: Cow<'static, str>,
    pub kind: String,
    pub method: String,
    pub host: String,
    pub route: String,
    /// `exact`, `approximate`, `synthetic` or `live`, as in v0.1.
    pub grounding: Cow<'static, str>,
    /// The simulator of a synthetic answer (`stub`, `contract`, `neighbor`,
    /// `model`, `fail-closed`, `placeholder`; M12); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulator: Option<String>,
    pub turn_prod: Option<String>,
    pub turn_fork: Option<String>,
    pub fields: Vec<FieldDiff>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Effects {
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
    pub items: Vec<EffectItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDiff {
    pub key: String,
    pub op: Cow<'static, str>,
    pub prod: Value,
    pub fork: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlDiff {
    pub table: String,
    pub op: Cow<'static, str>,
    pub pk: Vec<Value>,
    pub prod: Value,
    pub fork: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedState {
    pub root_lsn: Lsn,
    pub actor: String,
    pub keys: Vec<KeyDiff>,
    pub sql: Vec<SqlDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorState {
    pub actor: String,
    pub keys: Vec<KeyDiff>,
    pub sql: Vec<SqlDiff>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub isolated: Vec<IsolatedState>,
    pub continuous: Vec<ActorState>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cumulative {
    pub actors_changed: u64,
    pub items: Vec<ActorState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorItem {
    pub kind: Cow<'static, str>,
    pub error_code: String,
    pub message: String,
    pub turn_prod: Option<String>,
    pub turn_fork: Option<String>,
    pub input: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Errors {
    pub introduced: u64,
    pub fixed: u64,
    pub new_orphans: u64,
    pub outcome_unknown: u64,
    pub items: Vec<ErrorItem>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Percentiles {
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    pub fuel: ProdFork<Percentiles>,
    pub memory: ProdFork<Percentiles>,
    pub fuel_p99_change: f64,
    pub memory_p99_change: f64,
}

impl<T: Default> Default for ProdFork<T> {
    fn default() -> Self {
        ProdFork {
            prod: T::default(),
            fork: T::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Samples {
    pub origins: Vec<String>,
    pub consequences: Vec<String>,
    pub responses_changed: Vec<String>,
    pub effects_changed: Vec<String>,
    pub errors_introduced: Vec<String>,
    pub synthetic: Vec<String>,
    /// Fork turns whose difference is `pii-masked`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pii_masked: Vec<String>,
    /// Requests sent to a preview fork (M11).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preview: Vec<PreviewSample>,
    /// The fork's root turns of the inputs in `frames.items` (M24).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames_changed: Vec<String>,
    /// The production turns of the inputs counted in `frames.skipped`
    /// (M24 §7.2): the fork has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frames_skipped: Vec<String>,
}

/// A request sent to a preview fork: its root turn, method, route pattern
/// (never the raw path, ADR 0023), HTTP status and outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewSample {
    pub turn: String,
    pub method: String,
    pub route: String,
    pub status: Option<u32>,
    pub outcome: String,
}

/// The causal root of every preview request starts with this, so the diff
/// tells them from replayed production inputs (M11).
pub const PREVIEW_ROOT: &str = "preview-";

/// Whether a fork turn belongs to a preview request's tree.
fn is_preview(t: &ForkTurn) -> bool {
    t.record
        .causal_key
        .as_ref()
        .is_some_and(|k| k.root.starts_with(PREVIEW_ROOT))
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct KindResponses {
    pub unchanged: u64,
    pub changed: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct KindEffects {
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct KindErrors {
    pub introduced: u64,
    pub fixed: u64,
    pub new_orphans: u64,
    pub outcome_unknown: u64,
}

/// One actor kind's share of the diff (M9, ADR 0012): the counts of
/// `summary`, `responses`, `effects`, `state` and `errors` over the turns
/// and actors of that kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KindReport {
    pub kind: String,
    /// The kind's code in the fork against production's at the fork point:
    /// `changed`, `unchanged`, `new` or `absent` (no code on either side).
    pub code: Cow<'static, str>,
    /// Root inputs of the window addressed to an actor of this kind.
    pub root_inputs: u64,
    pub turns_prod: u64,
    pub turns_fork: u64,
    pub divergent_turns: u64,
    pub origins: u64,
    pub consequences: u64,
    /// HTTP root inputs served by this kind.
    pub responses: KindResponses,
    /// Root inputs of this kind counted in `frames` (M24); absent for a
    /// kind without connections or frames.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames: Option<KindResponses>,
    /// External effects of this kind's turns.
    pub effects: KindEffects,
    /// Actors of this kind whose state differs (isolated or continuous).
    pub actors_changed: u64,
    /// Errors of this kind's turns.
    pub errors: KindErrors,
}

/// The `kronik.diff/v1` document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub schema: Cow<'static, str>,
    pub fork: String,
    pub proposal_id: Option<String>,
    pub base: Base,
    pub code: Code,
    pub options: DiffOptions,
    pub summary: Summary,
    /// Per actor kind, sorted by kind (M9). Absent from diffs written before
    /// M9.
    #[serde(default)]
    pub kinds: Vec<KindReport>,
    pub causes: Vec<Cause>,
    pub grounding: Vec<GroundingRow>,
    pub responses: Responses,
    /// Long-lived connections (M24, ADR 0116). Absent when the window has
    /// no connection input and no turn sent a frame, and in diffs written
    /// before M24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frames: Option<Frames>,
    pub effects: Effects,
    pub state: State,
    pub cumulative: Cumulative,
    pub errors: Errors,
    pub resources: Resources,
    pub samples: Samples,
    /// A rebase diff only (M13): main's external effects since the
    /// rolled-back deployment that the old code would not have made the
    /// same way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub irreversible: Option<Irreversible>,
}

/// Effects that happened under the code a rebase rolls back and that the
/// rebased state does not account for (docs/design/m13-rebase.md section 5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Irreversible {
    pub count: u64,
    pub items: Vec<IrreversibleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrreversibleItem {
    pub turn_prod: String,
    pub kind: String,
    pub method: String,
    pub host: String,
    pub route: String,
    /// `ok`, `outcome_unknown`, `network`, `timeout`, ...
    pub status: String,
    /// `replay-safe`, `idempotency-keyed` or `unsafe`.
    pub delivery: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub idempotency_key: String,
}

/// Main's effects that reached (or may have reached) the world: HTTP and
/// foreign calls that were not denied before they left.
fn reached_world(e: &pb::EffectRecord) -> bool {
    (e.kind == "http.fetch" || e.kind == "foreign.http")
        && e.status != pb::EffectStatus::Denied as i32
        && e.status != pb::EffectStatus::Unspecified as i32
}

/// The irreversible effects of a rebase: each of main's effects in the
/// window without an exact counterpart in the fork's continuous history.
fn irreversible(index: &ProductionIndex, fork: &[ForkTurn]) -> Irreversible {
    let by_prod: BTreeMap<Lsn, &pb::TurnRecord> = fork
        .iter()
        .filter_map(|f| f.prod_lsn.map(|l| (l, &f.record)))
        .collect();
    let mut out = Irreversible::default();
    for c in index.records.iter() {
        if c.lsn <= index.fork_lsn || c.lsn > index.to_lsn {
            continue;
        }
        let Record::TurnRecord(t) = &c.record else {
            continue;
        };
        for e in t.effects.iter().filter(|e| reached_world(e)) {
            let exact = by_prod.get(&c.lsn).is_some_and(|f| {
                f.effects.iter().any(|x| {
                    x.ordinal == e.ordinal
                        && x.kind == e.kind
                        && x.grounding == pb::Grounding::Exact as i32
                })
            });
            if exact {
                continue;
            }
            out.count += 1;
            let (kind, method, host, route) = target(e);
            push_capped(
                &mut out.items,
                MAX_ITEMS,
                IrreversibleItem {
                    turn_prod: prod_id(c.lsn),
                    kind,
                    method,
                    host,
                    route,
                    status: pb::EffectStatus::try_from(e.status)
                        .map(|s| {
                            s.as_str_name()
                                .trim_start_matches("EFFECT_STATUS_")
                                .to_ascii_lowercase()
                        })
                        .unwrap_or_default(),
                    delivery: e.delivery.clone(),
                    idempotency_key: e.idempotency_key.clone(),
                },
            );
        }
    }
    out
}

impl Diff {
    /// Canonical bytes (`diff_hash = blake3(bytes)`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }

    /// For a caller without `pii:read`: the values of credential headers
    /// (`kronik_core::http::credential_header`) in the responses' and the
    /// effects' differences read `[redacted]`, as in a turn's JSON. A list of
    /// values keeps its shape, so that policy rules see the same types.
    pub fn redact_credentials(&mut self) {
        let hide = |v: &mut Value| match v {
            Value::Null => {}
            Value::Array(values) => values
                .iter_mut()
                .for_each(|value| *value = json!("[redacted]")),
            _ => *v = json!("[redacted]"),
        };
        let headers = self.responses.items.iter_mut().flat_map(|r| &mut r.headers);
        for h in headers.filter(|h| kronik_core::http::credential_header(&h.name)) {
            hide(&mut h.prod);
            hide(&mut h.fork);
        }
        let fields = self.effects.items.iter_mut().flat_map(|e| &mut e.fields);
        for f in fields.filter(|f| {
            f.field
                .strip_prefix("header:")
                .is_some_and(kronik_core::http::credential_header)
        }) {
            hide(&mut f.prod);
            hide(&mut f.fork);
        }
    }
}

/// `blake3(bytes)` as `b3:<64 hex>`.
pub fn diff_hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

/// Ratios: at most 6 decimals, rounded half-even.
pub fn r6(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    (x * 1e6).round_ties_even() / 1e6
}

// ---------------------------------------------------------------------------
// Rendering of values.

/// 16 hex of a hash that already is one (effect fingerprints).
fn hex16(bytes: &[u8]) -> String {
    format!("b3:{}", &blake3::hash(bytes).to_hex()[..16])
}

/// What a diff shows of a subject (M3): never the id, which every `read`
/// caller would see, but a keyed pseudonym `s:` + 12 hex (equal subjects
/// stay equal within an installation); `-` without the master key.
/// [`SQL_CONCEALED`] (M5) is no subject and shows as is.
fn shown_subject(sealer: &Sealer, subject: &str) -> String {
    if subject == SQL_CONCEALED {
        return subject.to_owned();
    }
    match sealer.keyed_hash("kronik diff subject v1", &[subject.as_bytes()]) {
        Some(h) => format!("s:{}", &blake3::Hash::from(h).to_hex()[..12]),
        None => "-".into(),
    }
}

/// The hash a redacted value shows (H12): keyed with a master-derived key
/// over the subject and the value, so it can't be checked against a
/// guessed value; `-` without the key (the offline upgrade check).
// shortcut: without the key, redacted SQL rows and continuous state values
// compare equal (their rendering is compared), so the offline upgrade check
// misses changes of a subject's values there; load the master key read-only
// there if that matters.
fn redacted_hash(sealer: &Sealer, subject: &str, value: &[u8]) -> String {
    match sealer.keyed_hash("kronik diff redaction v1", &[subject.as_bytes(), value]) {
        Some(h) => format!("k:{}", &blake3::Hash::from(h).to_hex()[..16]),
        None => "-".into(),
    }
}

/// A subject's value as the diff shows it: that it is there, not what.
fn redacted(sealer: &Sealer, subject: &str, value: &[u8]) -> Value {
    json!({
        "redacted": true,
        "subject": shown_subject(sealer, subject),
        "hash": redacted_hash(sealer, subject, value),
    })
}

/// `--no-pii` fork turns that may hold real SQL rows (M5) as the diff
/// compares and shows them: every value they produced under the subject
/// [`SQL_CONCEALED`] (so it is redacted like a subject's), and no outcome
/// message. The input stays: the diff never shows it, and it decides
/// whether a difference is an origin.
/// What a value of a subject [`ProductionIndex::erased_outputs`] names
/// becomes on both sides of a comparison.
const ERASED_OUTPUT: &[u8] = b"[erased]";

/// Every value of `subjects` in `t` becomes [`ERASED_OUTPUT`].
fn mask_subjects(t: &mut pb::TurnRecord, subjects: &BTreeSet<String>) {
    kronik_proto::sealables::turn_mut(t, &mut |s| {
        if s.subject.as_ref().is_some_and(|x| subjects.contains(x)) {
            s.value = Some(pb::sealable::Value::Plain(ERASED_OUTPUT.to_vec()));
        }
    });
}

/// A production turn whose guest read no erased value but whose own outputs
/// held values of subjects erased since ([`ProductionIndex::erased_outputs`]):
/// production's values of those subjects are gone, so they are masked on
/// both sides and cannot differ; everything else of the turn is compared
/// (ADR 0109 point 9). The production side, owned.
fn masked_production(index: &ProductionIndex) -> BTreeMap<Lsn, pb::TurnRecord> {
    index
        .erased_outputs
        .iter()
        .filter_map(|(lsn, subjects)| match &index.record(*lsn)?.record {
            Record::TurnRecord(t) => {
                let mut t = t.clone();
                mask_subjects(&mut t, subjects);
                Some((*lsn, t))
            }
            _ => None,
        })
        .collect()
}

/// `prod` with the turns [`masked_production`] holds replaced by theirs.
fn with_masked<'a>(
    prod: Vec<(Lsn, &'a pb::TurnRecord)>,
    masked: &'a BTreeMap<Lsn, pb::TurnRecord>,
) -> Vec<(Lsn, &'a pb::TurnRecord)> {
    if masked.is_empty() {
        return prod;
    }
    prod.into_iter()
        .map(|(lsn, t)| (lsn, masked.get(&lsn).unwrap_or(t)))
        .collect()
}

/// The fork side of [`masked_production`]: the replayed counterpart's values
/// of the same subjects.
fn masked_fork<'t>(turns: &'t [ForkTurn], index: &ProductionIndex) -> Cow<'t, [ForkTurn]> {
    let subjects = |f: &ForkTurn| f.prod_lsn.and_then(|l| index.erased_outputs.get(&l));
    if !turns.iter().any(|f| subjects(f).is_some()) {
        return Cow::Borrowed(turns);
    }
    Cow::Owned(
        turns
            .iter()
            .map(|f| {
                let mut f = f.clone();
                if let Some(s) = subjects(&f).cloned() {
                    mask_subjects(&mut f.record, &s);
                }
                f
            })
            .collect(),
    )
}

fn sql_tagged(turns: &[ForkTurn]) -> Cow<'_, [ForkTurn]> {
    if !turns.iter().any(|t| t.sql) {
        return Cow::Borrowed(turns);
    }
    Cow::Owned(
        turns
            .iter()
            .map(|t| {
                let mut t = t.clone();
                if t.sql {
                    let input = t.record.input.take();
                    kronik_proto::sealables::turn_mut(&mut t.record, &mut |s| {
                        s.subject.get_or_insert_with(|| SQL_CONCEALED.into());
                    });
                    t.record.input = input;
                    if let Some(o) = t.record.outcome.as_mut().filter(|o| !o.message.is_empty()) {
                        o.message = SQL_CONCEALED.into();
                    }
                }
                t
            })
            .collect(),
    )
}

fn bytes_json(b: &[u8]) -> Value {
    match std::str::from_utf8(b) {
        Ok(t) => Value::String(t.to_owned()),
        Err(_) => json!({ "base64": base64::engine::general_purpose::STANDARD.encode(b) }),
    }
}

fn sealable_bytes(s: Option<&pb::Sealable>) -> Option<&[u8]> {
    match s.and_then(|s| s.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => Some(b),
        _ => None,
    }
}

/// A sealable value: redacted when it has a subject.
fn sealable_json(sealer: &Sealer, s: Option<&pb::Sealable>) -> Value {
    let Some(s) = s else { return Value::Null };
    let bytes = sealable_bytes(Some(s)).unwrap_or_default();
    if let Some(subject) = &s.subject {
        return redacted(sealer, subject, bytes);
    }
    match &s.value {
        Some(pb::sealable::Value::Sealed(_)) => json!({ "sealed": true }),
        _ => bytes_json(bytes),
    }
}

fn sql_json(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(i) => json!(i),
        SqlValue::Real(r) => json!(r),
        SqlValue::Text(t) => Value::String(t.clone()),
        SqlValue::Blob(b) => {
            json!({ "base64": base64::engine::general_purpose::STANDARD.encode(b) })
        }
    }
}

fn prod_id(lsn: Lsn) -> String {
    format!("main:{lsn}")
}

// ---------------------------------------------------------------------------
// Noise filters and normalized views.

#[derive(Debug, Clone, PartialEq)]
enum PathSeg {
    Key(String),
    Index(usize),
    Any,
}

/// Parses the JSONPath subset `$.a.b[*].c` / `$.a[0]`.
fn parse_json_path(p: &str) -> Option<Vec<PathSeg>> {
    let rest = p.strip_prefix('$')?;
    let mut out = Vec::new();
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => {
                let mut name = String::new();
                while let Some(&n) = chars.peek() {
                    if n == '.' || n == '[' {
                        break;
                    }
                    name.push(n);
                    chars.next();
                }
                if name.is_empty() {
                    return None;
                }
                out.push(PathSeg::Key(name));
            }
            '[' => {
                let mut inner = String::new();
                for n in chars.by_ref() {
                    if n == ']' {
                        break;
                    }
                    inner.push(n);
                }
                if inner == "*" {
                    out.push(PathSeg::Any);
                } else if let Ok(i) = inner.parse() {
                    out.push(PathSeg::Index(i));
                } else {
                    let key = inner.trim_matches(|c| c == '\'' || c == '"');
                    out.push(PathSeg::Key(key.to_owned()));
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

fn remove_path(v: &mut Value, path: &[PathSeg]) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    let last = rest.is_empty();
    match (first, v) {
        (PathSeg::Key(k), Value::Object(m)) => {
            if last {
                m.remove(k);
            } else if let Some(c) = m.get_mut(k) {
                remove_path(c, rest);
            }
        }
        (PathSeg::Index(i), Value::Array(a)) => {
            if last {
                if *i < a.len() {
                    a.remove(*i);
                }
            } else if let Some(c) = a.get_mut(*i) {
                remove_path(c, rest);
            }
        }
        (PathSeg::Any, Value::Array(a)) => {
            if last {
                a.clear();
            } else {
                for c in a.iter_mut() {
                    remove_path(c, rest);
                }
            }
        }
        (PathSeg::Any, Value::Object(m)) => {
            if last {
                m.clear();
            } else {
                for c in m.values_mut() {
                    remove_path(c, rest);
                }
            }
        }
        _ => {}
    }
}

struct Norm {
    ignore_headers: BTreeSet<String>,
    json_paths: Vec<Vec<PathSeg>>,
    /// Keys the hashes and subjects of redacted values (H12, M3).
    sealer: Arc<Sealer>,
}

/// Rejects a noise filter that is not in the supported JSONPath subset.
pub fn check_options(o: &DiffOptions) -> Result<(), String> {
    for p in &o.ignore_json_paths {
        if parse_json_path(p).is_none() {
            return Err(format!(
                "ignore_json_paths: {p:?} is not a supported JSONPath ($.a.b[*].c)"
            ));
        }
    }
    crate::stubs::check(&o.stubs)?;
    let mut targets = BTreeSet::new();
    for s in &o.simulator_overrides {
        s.record()
            .map_err(|e| format!("simulator_overrides: {e}"))?;
        if !targets.insert(s.target.as_str()) {
            return Err(format!("simulator_overrides: {} twice", s.target));
        }
    }
    if !(o.sample > 0.0 && o.sample <= 1.0) {
        return Err(format!("sample must be in (0, 1], got {}", o.sample));
    }
    Ok(())
}

impl Norm {
    fn new(o: &DiffOptions, sealer: Arc<Sealer>) -> Norm {
        Norm {
            sealer,
            ignore_headers: o
                .ignore_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            json_paths: o
                .ignore_json_paths
                .iter()
                .filter_map(|p| parse_json_path(p))
                .collect(),
        }
    }

    /// The body as JSON (noise removed) when it parses, else `None`.
    fn json_body(&self, b: &[u8]) -> Option<Value> {
        let mut v: Value = serde_json::from_slice(b).ok()?;
        for p in &self.json_paths {
            remove_path(&mut v, p);
        }
        Some(v)
    }

    fn body_key(&self, s: Option<&pb::Sealable>) -> Vec<u8> {
        let Some(b) = sealable_bytes(s) else {
            return s.map(|s| s.encode_to_vec()).unwrap_or_default();
        };
        match self.json_body(b) {
            Some(v) => serde_json::to_vec(&v).unwrap_or_default(),
            None => b.to_vec(),
        }
    }

    fn headers(&self, h: &[pb::Header]) -> BTreeMap<String, Vec<Vec<u8>>> {
        let mut out: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
        for x in h {
            let name = x.name.to_ascii_lowercase();
            if self.ignore_headers.contains(&name) {
                continue;
            }
            out.entry(name).or_default().push(
                sealable_bytes(x.value.as_ref())
                    .unwrap_or_default()
                    .to_vec(),
            );
        }
        out
    }
}

fn http_body(r: &pb::HttpResponse) -> Option<&pb::Sealable> {
    match r.body.as_ref().and_then(|b| b.value.as_ref()) {
        Some(pb::body::Value::Inline(s)) => Some(s),
        _ => None,
    }
}

/// Everything §4 compares, normalized.
#[derive(PartialEq)]
struct TurnView {
    outcome: (i32, String),
    output: Vec<u8>,
    writes: Vec<(i32, String, Vec<u8>)>,
    messages: Vec<Vec<u8>>,
    timers: Vec<(i32, u64, i64, Vec<u8>)>,
    effects: Vec<(u32, String, String, Vec<u8>)>,
    sql: Vec<Vec<u8>>,
    /// The outgoing connection operations, `send-now` frames included,
    /// normalized and without their seqs (M24 §7.4, [`conn_ops`]).
    connection_ops: Vec<Vec<u8>>,
}

fn view(t: &pb::TurnRecord, n: &Norm) -> TurnView {
    let o = t.outcome.clone().unwrap_or_default();
    let output = match &o.output {
        Some(pb::outcome::Output::Reply(m)) => {
            let mut v = b"reply\0".to_vec();
            v.extend_from_slice(m.name.as_bytes());
            v.push(0);
            v.extend(n.body_key(m.body.as_ref()));
            v
        }
        Some(pb::outcome::Output::Http(r)) => {
            let mut v = format!("http\0{}\0", r.status).into_bytes();
            for (name, vals) in n.headers(&r.headers) {
                v.extend_from_slice(name.as_bytes());
                for x in vals {
                    v.push(1);
                    v.extend(x);
                }
                v.push(0);
            }
            v.extend(n.body_key(http_body(r)));
            v
        }
        // M24 (ADR 0116): an open turn's accept, against a refusal's
        // `http` above.
        Some(pb::outcome::Output::Accept(a)) => {
            // The subprotocol's position, never its value: within one root
            // input the offered list is the same in production and fork.
            let mut v = format!(
                "accept\0{:?}\0{}\0",
                a.subprotocol_index,
                a.subject.as_deref().unwrap_or("")
            )
            .into_bytes();
            for (name, vals) in n.headers(&a.headers) {
                v.extend_from_slice(name.as_bytes());
                for x in vals {
                    v.push(1);
                    v.extend(x);
                }
                v.push(0);
            }
            v
        }
        None => Vec::new(),
    };
    TurnView {
        outcome: (o.kind, o.error_code),
        output,
        writes: t
            .writes
            .iter()
            .map(|w| {
                (
                    w.op,
                    w.key.clone(),
                    w.value
                        .as_ref()
                        .map(|v| v.encode_to_vec())
                        .unwrap_or_default(),
                )
            })
            .collect(),
        messages: t
            .messages
            .iter()
            .map(|m| {
                let mut x = m.to.as_ref().map(|a| a.encode_to_vec()).unwrap_or_default();
                x.push(0);
                x.extend(
                    m.msg
                        .as_ref()
                        .map(|m| m.encode_to_vec())
                        .unwrap_or_default(),
                );
                x
            })
            .collect(),
        timers: t
            .timers
            .iter()
            .map(|x| {
                (
                    x.kind,
                    x.timer_id,
                    x.due_ms as i64 - t.logical_time_ms as i64,
                    x.msg
                        .as_ref()
                        .map(|m| m.encode_to_vec())
                        .unwrap_or_default(),
                )
            })
            .collect(),
        effects: t
            .effects
            .iter()
            // A `send-now` is compared as the frame it sent, with the
            // buffered operations below (M24 §7.4).
            .filter(|e| e.kind != SEND_NOW)
            .map(|e| {
                (
                    e.ordinal,
                    e.kind.clone(),
                    e.target.clone(),
                    e.fingerprint.clone(),
                )
            })
            .collect(),
        sql: t
            .sql_changes
            .iter()
            .map(|c| {
                c.changeset
                    .as_ref()
                    .map(|s| s.encode_to_vec())
                    .unwrap_or_default()
            })
            .chain(
                t.sql_schema
                    .iter()
                    .map(|s| s.statement.clone().into_bytes()),
            )
            .collect(),
        connection_ops: conn_ops(t).iter().map(|op| op.key(n)).collect(),
    }
}

fn input_bytes(t: &pb::TurnRecord) -> Vec<u8> {
    t.input
        .as_ref()
        .map(|i| i.encode_to_vec())
        .unwrap_or_default()
}

fn committed(t: &pb::TurnRecord) -> bool {
    t.outcome
        .as_ref()
        .is_some_and(|o| o.kind == pb::OutcomeKind::Committed as i32)
}

/// Any outcome but committed (rejected, failed, trap, fuel, memory, outcome
/// unknown): writes are undone and the input is answered with an error.
fn failed(t: &pb::TurnRecord) -> bool {
    !committed(t)
}

// ---------------------------------------------------------------------------
// Long-lived connections (M24 §7.4, §7.5, ADR 0116).

/// The kind of the `connection.send-now` effect (M24 §6.2). It is not
/// [`external`]: its answer says nothing about a system outside, so it
/// counts in no grounding and no confidence (§7.3).
const SEND_NOW: &str = "connection.send-now";

/// Changed operations listed per item of `frames.items`.
const MAX_FRAME_CHANGES: usize = 20;

/// Targets listed per changed operation.
const MAX_FRAME_TARGETS: usize = 5;

/// One outgoing connection operation of a turn, as the diff compares it: a
/// frame the turn sent with `send-now`, or a buffered send, broadcast or
/// close. Never its seqs, which an earlier change shifts (ADR 0116 point 2),
/// nor a `send-now`'s answer.
struct ConnOp {
    send_now: bool,
    /// The live targets, then those that no live connection had.
    connections: Vec<String>,
    dropped: Vec<String>,
    /// The targets the frame went to: a send's live ones, or the one of a
    /// `send-now` answered `ok`; 0 for a close.
    delivered: u64,
    /// `text`, `binary`, `event` or `close`.
    kind: &'static str,
    /// A frame's data, or a close's reason.
    data: Option<pb::Sealable>,
    /// An SSE event's `event:` and `id:` fields.
    event: String,
    id: String,
    /// A close's code.
    code: Option<u32>,
}

impl ConnOp {
    /// The bytes compared: every field but `delivered`, the data normalized
    /// like a body (`ignore_json_paths`) and with its subject.
    fn key(&self, n: &Norm) -> Vec<u8> {
        let mut v = Vec::new();
        let mut put = |b: &[u8]| {
            v.extend_from_slice(&(b.len() as u64).to_le_bytes());
            v.extend_from_slice(b);
        };
        put(if self.send_now {
            b"send-now"
        } else {
            b"buffered"
        });
        put(self.kind.as_bytes());
        for list in [&self.connections, &self.dropped] {
            put(&(list.len() as u64).to_le_bytes());
            for c in list {
                put(c.as_bytes());
            }
        }
        put(self
            .data
            .as_ref()
            .and_then(|d| d.subject.as_deref())
            .unwrap_or("")
            .as_bytes());
        put(&n.body_key(self.data.as_ref()));
        put(self.event.as_bytes());
        put(self.id.as_bytes());
        put(&self.code.map_or(Vec::new(), |c| c.to_le_bytes().to_vec()));
        v
    }

    /// The targets it names, live ones first.
    fn targets(&self) -> impl Iterator<Item = &String> {
        self.connections.iter().chain(&self.dropped)
    }

    /// The SSE fields of an event frame; null for any other operation.
    fn event_json(&self) -> Value {
        if self.kind == "event" {
            json!({"event": self.event, "id": self.id})
        } else {
            Value::Null
        }
    }
}

/// The frame a `send-now` effect record sent (its `ConnectionSendRequest`,
/// tagged with the request's subject), or `None` for a record without one
/// (a denial).
fn send_now_op(e: &pb::EffectRecord) -> Option<ConnOp> {
    let request = e.request.as_ref()?;
    let r = pb::ConnectionSendRequest::decode(sealable_bytes(Some(request))?).ok()?;
    let delivered = u64::from(e.status == pb::EffectStatus::Ok as i32);
    Some(ConnOp {
        send_now: true,
        connections: vec![r.connection],
        dropped: Vec::new(),
        delivered,
        kind: kronik_proto::connection::frame_kind_name(r.kind),
        data: Some(pb::Sealable {
            subject: request.subject.clone(),
            value: Some(pb::sealable::Value::Plain(r.data)),
        }),
        event: r.event,
        id: r.id,
        code: None,
    })
}

/// A turn's outgoing connection operations in the order they went out: its
/// `send-now` frames, in ordinal order, as it sent them, then its buffered
/// operations, in call order, when it committed (M24 §4.5).
fn conn_ops(t: &pb::TurnRecord) -> Vec<ConnOp> {
    let mut out: Vec<ConnOp> = t
        .effects
        .iter()
        .filter(|e| e.kind == SEND_NOW)
        .filter_map(send_now_op)
        .collect();
    for op in &t.connection_ops {
        out.push(match &op.op {
            Some(pb::connection_op::Op::Send(f)) => ConnOp {
                send_now: false,
                connections: op.connections.clone(),
                dropped: op.dropped.clone(),
                delivered: op.connections.len() as u64,
                kind: kronik_proto::connection::frame_kind_name(f.kind),
                data: f.data.clone(),
                event: f.event.clone(),
                id: f.id.clone(),
                code: None,
            },
            Some(pb::connection_op::Op::Close(c)) => ConnOp {
                send_now: false,
                connections: op.connections.clone(),
                dropped: op.dropped.clone(),
                delivered: 0,
                kind: "close",
                data: c.reason.clone(),
                event: String::new(),
                id: String::new(),
                code: Some(c.code),
            },
            // Refused by validation; compared as what it is, nothing.
            None => ConnOp {
                send_now: false,
                connections: op.connections.clone(),
                dropped: op.dropped.clone(),
                delivered: 0,
                kind: "unspecified",
                data: None,
                event: String::new(),
                id: String::new(),
                code: None,
            },
        });
    }
    out
}

/// The open's answer for `frames.items[].open`: `accept`, `refuse <status>`
/// (the refusal's HTTP response) or `fail <error code>` (the open turn did
/// not commit).
fn open_answer(t: &pb::TurnRecord) -> String {
    let o = t.outcome.clone().unwrap_or_default();
    if o.kind != pb::OutcomeKind::Committed as i32 {
        return format!("fail {}", o.error_code);
    }
    match &o.output {
        Some(pb::outcome::Output::Accept(_)) => "accept".into(),
        Some(pb::outcome::Output::Http(r)) => format!("refuse {}", r.status),
        _ => "fail".into(),
    }
}

/// A JSON value of a frame on one side: redacted when the frame has a
/// subject, like any value with one (§7.5).
fn frame_value(sealer: &Sealer, s: Option<&pb::Sealable>, v: &Value) -> Value {
    match s.and_then(|s| s.subject.as_deref()) {
        Some(subject) if !v.is_null() => {
            redacted(sealer, subject, &serde_json::to_vec(v).unwrap_or_default())
        }
        _ => v.clone(),
    }
}

/// The data operations of a changed frame (a close's reason): JSON pointer
/// operations when both sides are JSON, with the values of a side that has
/// a subject redacted; otherwise one operation at `""` with each value.
fn frame_data_ops(n: &Norm, p: Option<&pb::Sealable>, f: Option<&pb::Sealable>) -> Vec<BodyOp> {
    let json = |s: Option<&pb::Sealable>| sealable_bytes(s).and_then(|b| n.json_body(b));
    if let (Some(a), Some(b)) = (json(p), json(f)) {
        let mut out = Vec::new();
        json_diff("", Some(&a), Some(&b), &mut out);
        for op in &mut out {
            op.prod = frame_value(&n.sealer, p, &op.prod);
            op.fork = frame_value(&n.sealer, f, &op.fork);
        }
        return out;
    }
    let subject = |s: Option<&pb::Sealable>| s.and_then(|s| s.subject.clone());
    if n.body_key(p) == n.body_key(f) && subject(p) == subject(f) {
        return Vec::new();
    }
    let op = match (p, f) {
        (Some(_), None) => "remove",
        (None, Some(_)) => "add",
        _ => "replace",
    };
    vec![BodyOp {
        op: op.into(),
        path: String::new(),
        prod: sealable_json(&n.sealer, p),
        fork: sealable_json(&n.sealer, f),
    }]
}

/// One position of a tree's operations, production's against the fork's.
fn frame_change(
    n: &Norm,
    index: u64,
    p: Option<&ConnOp>,
    f: Option<&ConnOp>,
) -> Option<FrameChange> {
    let change = match (p, f) {
        (Some(a), Some(b)) if a.key(n) == b.key(n) => return None,
        (Some(_), Some(_)) => "changed",
        (Some(_), None) => "removed",
        (None, Some(_)) => "added",
        (None, None) => return None,
    };
    let shown = p.or(f)?;
    let event = (p.map(ConnOp::event_json) != f.map(ConnOp::event_json)
        && (p.is_some_and(|o| o.kind == "event") || f.is_some_and(|o| o.kind == "event")))
    .then(|| ProdFork {
        prod: p.map_or(Value::Null, ConnOp::event_json),
        fork: f.map_or(Value::Null, ConnOp::event_json),
    });
    let send_now =
        (p.is_some_and(|o| o.send_now) || f.is_some_and(|o| o.send_now)).then(|| ProdFork {
            prod: p.is_some_and(|o| o.send_now),
            fork: f.is_some_and(|o| o.send_now),
        });
    let code = (p.and_then(|o| o.code) != f.and_then(|o| o.code)).then(|| ProdFork {
        prod: p.and_then(|o| o.code),
        fork: f.and_then(|o| o.code),
    });
    Some(FrameChange {
        index,
        change: change.into(),
        targets: shown.targets().count() as u64,
        connections: shown.targets().take(MAX_FRAME_TARGETS).cloned().collect(),
        kind: ProdFork {
            prod: p.map(|o| o.kind.to_owned()),
            fork: f.map(|o| o.kind.to_owned()),
        },
        send_now,
        event,
        data: frame_data_ops(
            n,
            p.and_then(|o| o.data.as_ref()),
            f.and_then(|o| o.data.as_ref()),
        ),
        code,
    })
}

fn external(kind: &str) -> bool {
    kind == "http.fetch"
        || kind == "foreign.http"
        || kind.starts_with("crypto.")
        || kind == "secret.reveal"
}

/// The simulator label of a synthetic answer (M12); `None` otherwise, or
/// for a record written before M12.
fn simulator_label(e: &pb::EffectRecord) -> Option<&str> {
    (e.grounding == pb::Grounding::Synthetic as i32 && !e.simulator.is_empty())
        .then_some(e.simulator.as_str())
}

fn grounding_name(g: i32) -> &'static str {
    match pb::Grounding::try_from(g) {
        Ok(pb::Grounding::Exact) => "exact",
        Ok(pb::Grounding::Approximate) => "approximate",
        Ok(pb::Grounding::Synthetic) => "synthetic",
        Ok(pb::Grounding::Forked) => "forked",
        _ => "live",
    }
}

/// The request of an HTTP effect (`http.fetch`, or `foreign.http`, whose
/// host is the foreign actor's name).
fn http_request(e: &pb::EffectRecord) -> Option<pb::HttpEffectRequest> {
    if e.kind != "http.fetch" && e.kind != "foreign.http" {
        return None;
    }
    pb::HttpEffectRequest::decode(sealable_bytes(e.request.as_ref())?).ok()
}

/// (kind, method, host, route) of an external effect.
fn target(e: &pb::EffectRecord) -> (String, String, String, String) {
    if let Some((m, h, r)) = http_request(e).as_ref().and_then(target_of) {
        return (e.kind.clone(), m, h, r);
    }
    let host = e
        .target
        .strip_prefix("secret-reveal:")
        .or_else(|| e.target.strip_prefix("secret:"))
        .or_else(|| e.target.strip_prefix("http:"))
        .or_else(|| e.target.strip_prefix("foreign:"))
        .unwrap_or(&e.target);
    (
        e.kind.clone(),
        String::new(),
        host.to_owned(),
        String::new(),
    )
}

fn header_value(h: &pb::HttpEffectHeader) -> Value {
    match &h.value {
        Some(pb::http_effect_header::Value::Text(t)) => Value::String(t.clone()),
        Some(pb::http_effect_header::Value::Secret(s)) => json!({
            "secret": s.name,
            "version_hash": base64::engine::general_purpose::STANDARD.encode(&s.version_hash),
        }),
        None => Value::Null,
    }
}

/// Field differences of two effects (requests decoded for HTTP). A request
/// recorded under a subject is its data: like state values, the diff shows
/// that its URL, headers or body changed, not what to.
fn effect_fields(
    sealer: &Sealer,
    p: Option<&pb::EffectRecord>,
    f: Option<&pb::EffectRecord>,
) -> Vec<FieldDiff> {
    let pr = p.and_then(http_request);
    let fr = f.and_then(http_request);
    let subject = |e: Option<&pb::EffectRecord>| {
        e.and_then(|e| e.request.as_ref())
            .and_then(|s| s.subject.clone())
    };
    // One effect of one turn: either side's subject makes both its data.
    let s = subject(p).or_else(|| subject(f));
    let (ps, fs) = (s.clone(), s);
    // A field value as shown: redacted when the request has a subject.
    let shown = |subject: &Option<String>, v: Value| -> Value {
        match subject {
            Some(s) if !v.is_null() => redacted(sealer, s, v.to_string().as_bytes()),
            _ => v,
        }
    };
    let mut out = Vec::new();
    if pr.is_some() || fr.is_some() {
        let pm = pr.as_ref().map(|r| r.method.clone());
        let fm = fr.as_ref().map(|r| r.method.clone());
        if pm != fm {
            out.push(FieldDiff {
                field: "method".into(),
                prod: json!(pm),
                fork: json!(fm),
            });
        }
        let pu = pr.as_ref().map(|r| r.url.clone());
        let fu = fr.as_ref().map(|r| r.url.clone());
        if pu != fu {
            out.push(FieldDiff {
                field: "url".into(),
                prod: shown(&ps, json!(pu)),
                fork: shown(&fs, json!(fu)),
            });
        }
        let hs = |r: &Option<pb::HttpEffectRequest>| -> BTreeMap<String, Value> {
            r.iter()
                .flat_map(|r| r.headers.iter())
                .map(|h| (h.name.to_ascii_lowercase(), header_value(h)))
                .collect()
        };
        let (ph, fh) = (hs(&pr), hs(&fr));
        let names: BTreeSet<&String> = ph.keys().chain(fh.keys()).collect();
        for n in names {
            let (a, b) = (
                ph.get(n).cloned().unwrap_or(Value::Null),
                fh.get(n).cloned().unwrap_or(Value::Null),
            );
            if a != b {
                out.push(FieldDiff {
                    field: format!("header:{n}"),
                    prod: shown(&ps, a),
                    fork: shown(&fs, b),
                });
            }
        }
        let pb_ = pr.as_ref().map(|r| r.body.clone());
        let fb = fr.as_ref().map(|r| r.body.clone());
        if pb_ != fb {
            out.push(FieldDiff {
                field: "body".into(),
                prod: shown(&ps, pb_.map_or(Value::Null, |b| bytes_json(&b))),
                fork: shown(&fs, fb.map_or(Value::Null, |b| bytes_json(&b))),
            });
        }
    } else {
        let a = p.map(|e| json!(hex16(&e.fingerprint)));
        let b = f.map(|e| json!(hex16(&e.fingerprint)));
        if a != b {
            out.push(FieldDiff {
                field: "fingerprint".into(),
                prod: a.unwrap_or(Value::Null),
                fork: b.unwrap_or(Value::Null),
            });
        }
    }
    out
}

fn escape_pointer(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

/// JSON body diff in document order.
fn json_diff(path: &str, a: Option<&Value>, b: Option<&Value>, out: &mut Vec<BodyOp>) {
    match (a, b) {
        (Some(Value::Object(x)), Some(Value::Object(y))) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                json_diff(
                    &format!("{path}/{}", escape_pointer(k)),
                    x.get(k),
                    y.get(k),
                    out,
                );
            }
        }
        (Some(Value::Array(x)), Some(Value::Array(y))) => {
            for i in 0..x.len().max(y.len()) {
                json_diff(&format!("{path}/{i}"), x.get(i), y.get(i), out);
            }
        }
        (Some(x), Some(y)) if x == y => {}
        (Some(x), Some(y)) => out.push(BodyOp {
            op: "replace".into(),
            path: path.into(),
            prod: x.clone(),
            fork: y.clone(),
        }),
        (None, Some(y)) => out.push(BodyOp {
            op: "add".into(),
            path: path.into(),
            prod: Value::Null,
            fork: y.clone(),
        }),
        (Some(x), None) => out.push(BodyOp {
            op: "remove".into(),
            path: path.into(),
            prod: x.clone(),
            fork: Value::Null,
        }),
        (None, None) => {}
    }
}

fn body_ops(n: &Norm, p: Option<&pb::Sealable>, f: Option<&pb::Sealable>) -> Vec<BodyOp> {
    let pb_ = sealable_bytes(p).unwrap_or_default();
    let fb = sealable_bytes(f).unwrap_or_default();
    let redacted = p.is_some_and(|s| s.subject.is_some()) || f.is_some_and(|s| s.subject.is_some());
    if !redacted && let (Some(a), Some(b)) = (n.json_body(pb_), n.json_body(fb)) {
        let mut out = Vec::new();
        json_diff("", Some(&a), Some(&b), &mut out);
        return out;
    }
    if n.body_key(p) == n.body_key(f) {
        return Vec::new();
    }
    vec![BodyOp {
        op: "replace".into(),
        path: String::new(),
        prod: sealable_json(&n.sealer, p),
        fork: sealable_json(&n.sealer, f),
    }]
}

pub(crate) fn percentiles(mut v: Vec<u64>) -> Percentiles {
    if v.is_empty() {
        return Percentiles::default();
    }
    v.sort_unstable();
    let at = |p: f64| {
        let rank = ((p / 100.0) * v.len() as f64).ceil() as usize;
        v[rank.clamp(1, v.len()) - 1]
    };
    Percentiles {
        p50: at(50.0),
        p95: at(95.0),
        p99: at(99.0),
    }
}

fn change(prod: u64, fork: u64) -> f64 {
    if prod == 0 {
        0.0
    } else {
        r6((fork as f64 - prod as f64) / prod as f64)
    }
}

fn push_capped<T>(v: &mut Vec<T>, cap: usize, x: T) {
    if v.len() < cap {
        v.push(x);
    }
}

// ---------------------------------------------------------------------------
// Accumulation.

#[derive(Default)]
struct CauseAcc {
    origins: u64,
    consequences: u64,
    roots: BTreeSet<Lsn>,
    samples: Vec<String>,
}

enum Change<'a> {
    Changed {
        prod: (Lsn, &'a pb::TurnRecord),
        fork: &'a ForkTurn,
        same_input: bool,
    },
    New {
        fork: &'a ForkTurn,
    },
    Missing {
        prod: (Lsn, &'a pb::TurnRecord),
    },
}

struct Acc {
    norm: Norm,
    /// Divergent turns by causal key, with their actor kind.
    divergent: BTreeMap<Vec<u8>, String>,
    /// Differences of turns that read pseudonyms (`--no-pii`) or met erased
    /// data, and production turns missing below them.
    pii_masked: BTreeSet<Vec<u8>>,
    /// Production turns missing below a turn that met erased data (S-16,
    /// ADR 0109 point 3).
    unverifiable: BTreeSet<Vec<u8>>,
    /// Every replayed turn that met erased data ([`ForkTurn::erased`]),
    /// differing or not: the replay cannot verify what the guest read
    /// (S-16, ADR 0109).
    erased_seen: BTreeSet<Vec<u8>>,
    /// The current turn pair is unverifiable: do not count its effects.
    quiet: bool,
    /// Turns that read pseudonyms and came out identical, with their kind.
    pii_same: BTreeMap<Vec<u8>, String>,
    /// Requests sent to a preview fork (M11).
    preview_inputs: u64,
    origins: u64,
    consequences: u64,
    causes: BTreeMap<(String, String), CauseAcc>,
    grounding: BTreeMap<(String, String, String, String), [u64; 5]>,
    /// Synthetic answers per target and simulator (M12).
    synthetic_by: BTreeMap<(String, String, String, String), BTreeMap<String, u64>>,
    responses: Responses,
    effects: Effects,
    effect_items: Vec<EffectItem>,
    errors: Errors,
    error_keys: BTreeSet<(&'static str, Vec<u8>)>,
    fuel: (Vec<u64>, Vec<u64>),
    memory: (Vec<u64>, Vec<u64>),
    samples: Samples,
    turns_prod: u64,
    turns_fork: u64,
    isolated_state: Vec<IsolatedState>,
    /// Actor -> root inputs whose isolated tree changed its state.
    isolated_actor_roots: BTreeMap<String, BTreeSet<Lsn>>,
    /// The per-kind counts (`kind` and `code` are set by `build`).
    by_kind: BTreeMap<String, KindReport>,
    /// Targets of foreign actors with a copy (`foreign:<name>`), when both
    /// views exist: their effects and the responses of the root inputs that
    /// call them come from the continuous view, where the copy answered.
    copied: BTreeSet<String>,
    /// Root inputs whose response the continuous view gives.
    deferred: BTreeSet<Lsn>,
    /// The `frames` section so far (M24 §7.5); its inputs and skipped
    /// counts are set by `build`.
    frames: Frames,
    /// A compared tree was a connection input or sent frames.
    frames_seen: bool,
}

/// The actor kind of a turn.
fn kind_of(t: &pb::TurnRecord) -> String {
    t.actor.as_ref().map(|a| a.kind.clone()).unwrap_or_default()
}

/// A turn the replay could not run on the recorded data: it read pseudonyms
/// (`--no-pii`) or met a value whose subject was erased. What such a turn
/// did measures stand-in data, not the code, so none of its differences
/// count as changes (S-16, ADR 0109 points 3-4; ADR 0031).
fn unverified_input(t: &ForkTurn) -> bool {
    t.pseudonyms || t.erased
}

/// Causal keys of the production turns whose state writes are not evidence
/// of a behavior change: the matched fork turn is [`unverified_input`], or
/// the turn is missing below one that is (its absence is that turn's
/// difference, not a verified change; S-16, ADR 0109 points 3-4).
fn unverified_state_keys(prod: &[(Lsn, &pb::TurnRecord)], fork: &[ForkTurn]) -> BTreeSet<Vec<u8>> {
    let unverified: BTreeSet<Vec<u8>> = fork
        .iter()
        .filter(|f| unverified_input(f))
        .filter_map(|f| f.record.causal_key.as_ref().map(causal::encode))
        .collect();
    let replayed: BTreeSet<Vec<u8>> = fork
        .iter()
        .filter_map(|f| f.record.causal_key.as_ref().map(causal::encode))
        .collect();
    let mut out = unverified.clone();
    for (_, t) in prod {
        let Some(ck) = t.causal_key.as_ref() else {
            continue;
        };
        let key = causal::encode(ck);
        if !replayed.contains(&key)
            && (0..ck.path.len()).any(|n| unverified.contains(&path_prefix(ck, n)))
        {
            out.insert(key);
        }
    }
    out
}

fn path_prefix(key: &pb::CausalKey, n: usize) -> Vec<u8> {
    causal::encode(&pb::CausalKey {
        root: key.root.clone(),
        path: key.path[..n].to_vec(),
    })
}

/// Whether the turn with a causal key committed, on one side of a diff.
type CommittedAt<'a> = &'a dyn Fn(&pb::CausalKey) -> bool;

impl Acc {
    fn new(opts: &DiffOptions, sealer: Arc<Sealer>) -> Acc {
        Acc {
            norm: Norm::new(opts, sealer),
            divergent: BTreeMap::new(),
            pii_masked: BTreeSet::new(),
            unverifiable: BTreeSet::new(),
            erased_seen: BTreeSet::new(),
            quiet: false,
            pii_same: BTreeMap::new(),
            preview_inputs: 0,
            origins: 0,
            consequences: 0,
            causes: BTreeMap::new(),
            grounding: BTreeMap::new(),
            synthetic_by: BTreeMap::new(),
            responses: Responses::default(),
            effects: Effects::default(),
            effect_items: Vec::new(),
            errors: Errors::default(),
            error_keys: BTreeSet::new(),
            fuel: (Vec::new(), Vec::new()),
            memory: (Vec::new(), Vec::new()),
            samples: Samples::default(),
            turns_prod: 0,
            turns_fork: 0,
            isolated_state: Vec::new(),
            isolated_actor_roots: BTreeMap::new(),
            by_kind: BTreeMap::new(),
            copied: BTreeSet::new(),
            deferred: BTreeSet::new(),
            frames: Frames::default(),
            frames_seen: false,
        }
    }

    fn kind(&mut self, kind: String) -> &mut KindReport {
        self.by_kind.entry(kind).or_default()
    }

    /// The root turns of preview requests (M11), in log order.
    fn preview(&mut self, turns: &[ForkTurn]) {
        for t in turns.iter().filter(|t| {
            t.record
                .causal_key
                .as_ref()
                .is_some_and(|k| k.path.is_empty())
        }) {
            self.preview_inputs += 1;
            let (method, route) = match t.record.input.as_ref().and_then(|i| i.kind.as_ref()) {
                Some(pb::input::Kind::Http(h)) => (h.method.clone(), h.route.clone()),
                _ => (String::new(), String::new()),
            };
            let outcome = t.record.outcome.as_ref();
            let status = match outcome.and_then(|o| o.output.as_ref()) {
                Some(pb::outcome::Output::Http(r)) => Some(r.status),
                _ => None,
            };
            let outcome = pb::OutcomeKind::try_from(outcome.map_or(0, |o| o.kind))
                .unwrap_or(pb::OutcomeKind::Unspecified)
                .as_str_name()
                .trim_start_matches("OUTCOME_KIND_")
                .to_ascii_lowercase();
            push_capped(
                &mut self.samples.preview,
                MAX_SAMPLES,
                PreviewSample {
                    turn: t.id.clone(),
                    method,
                    route,
                    status,
                    outcome,
                },
            );
        }
    }

    fn error(
        &mut self,
        kind: &'static str,
        key: Vec<u8>,
        t: &pb::TurnRecord,
        turn_prod: Option<Lsn>,
        turn_fork: Option<&str>,
    ) {
        if !self.error_keys.insert((kind, key)) {
            return;
        }
        let e = &mut self.kind(kind_of(t)).errors;
        match kind {
            "introduced" => e.introduced += 1,
            "fixed" => e.fixed += 1,
            "new_orphan" => e.new_orphans += 1,
            _ => e.outcome_unknown += 1,
        }
        match kind {
            "introduced" => self.errors.introduced += 1,
            "fixed" => self.errors.fixed += 1,
            "new_orphan" => self.errors.new_orphans += 1,
            _ => self.errors.outcome_unknown += 1,
        }
        if kind == "introduced"
            && let Some(id) = turn_fork
        {
            push_capped(
                &mut self.samples.errors_introduced,
                MAX_SAMPLES,
                id.to_owned(),
            );
        }
        if self.errors.items.iter().filter(|i| i.kind == kind).count() >= MAX_ERRORS {
            return;
        }
        let o = t.outcome.clone().unwrap_or_default();
        self.errors.items.push(ErrorItem {
            kind: kind.into(),
            error_code: o.error_code,
            message: o.message,
            turn_prod: turn_prod.map(prod_id),
            turn_fork: turn_fork.map(str::to_owned),
            input: input_label(t.input.as_ref()),
        });
    }

    /// Orphans a failed turn leaves: calls whose callee committed, without a
    /// compensation. A successful call (status OK, or a withheld reply whose
    /// callee committed), or one that timed out while its callee's turn
    /// still committed (#30), which `callee_committed` tells by that turn's
    /// causal key, as the store's `orphans` table does.
    fn orphans(
        t: &pb::TurnRecord,
        callee_committed: &dyn Fn(&pb::CausalKey) -> bool,
    ) -> BTreeSet<u32> {
        if !failed(t) {
            return BTreeSet::new();
        }
        let callee_key = |ordinal: u32| {
            let caller = ActorRef::from_pb(t.actor.as_ref()?);
            Some(causal::child(t.causal_key.as_ref()?, &caller, ordinal))
        };
        t.effects
            .iter()
            .filter(|e| {
                e.successful_call()
                    || (e.timed_out_call()
                        && callee_key(e.ordinal).is_some_and(|k| callee_committed(&k)))
            })
            .filter(|e| {
                sealable_bytes(e.request.as_ref())
                    .and_then(|b| pb::CallEffectRequest::decode(b).ok())
                    .is_none_or(|r| r.compensate.is_none())
            })
            .map(|e| e.ordinal)
            .collect()
    }

    /// Errors of one fork turn against its production counterpart (both
    /// modes, deduplicated by causal key). `committed` tells whether the
    /// production and the fork turn with a causal key committed.
    fn turn_errors(
        &mut self,
        prod: Option<(Lsn, &pb::TurnRecord)>,
        fork: &ForkTurn,
        committed: (CommittedAt<'_>, CommittedAt<'_>),
    ) {
        let (prod_committed, fork_committed) = committed;
        let key = fork
            .record
            .causal_key
            .as_ref()
            .map(causal::encode)
            .unwrap_or_default();
        let f = &fork.record;
        // A turn that read pseudonyms or erased data did not run on the
        // recorded input: how it differs from production (failing included,
        // and any SQL it wrote) is `pii-masked`/`unverifiable`, not an error
        // of the code (issue #16, ADR 0109 points 3-4).
        match (prod, unverified_input(fork)) {
            (_, true) => {}
            (Some((lsn, p)), false) => {
                if failed(f) && !failed(p) {
                    self.error("introduced", key.clone(), f, Some(lsn), Some(&fork.id));
                } else if !failed(f) && failed(p) {
                    self.error("fixed", key.clone(), p, Some(lsn), Some(&fork.id));
                }
                if !Self::orphans(f, fork_committed).is_subset(&Self::orphans(p, prod_committed)) {
                    self.error("new_orphan", key.clone(), f, Some(lsn), Some(&fork.id));
                }
            }
            (None, false) => {
                if failed(f) {
                    self.error("introduced", key.clone(), f, None, Some(&fork.id));
                }
                if !Self::orphans(f, fork_committed).is_empty() {
                    self.error("new_orphan", key.clone(), f, None, Some(&fork.id));
                }
            }
        }
        if f.effects.iter().any(|e| {
            e.status == pb::EffectStatus::OutcomeUnknown as i32
                && matches!(
                    pb::Grounding::try_from(e.grounding),
                    Ok(pb::Grounding::Exact | pb::Grounding::Approximate)
                )
        }) {
            self.error("outcome_unknown", key, f, prod.map(|p| p.0), Some(&fork.id));
        }
    }

    fn effect_item(
        &mut self,
        change: &'static str,
        p: Option<&pb::EffectRecord>,
        f: Option<&pb::EffectRecord>,
        turn_prod: Option<Lsn>,
        turn_fork: Option<&str>,
    ) {
        if !self.quiet {
            match change {
                "added" => self.effects.added += 1,
                "removed" => self.effects.removed += 1,
                _ => self.effects.changed += 1,
            }
        }
        if let Some(id) = turn_fork {
            let s = &mut self.samples.effects_changed;
            if !s.iter().any(|x| x == id) {
                push_capped(s, MAX_SAMPLES, id.to_owned());
            }
        }
        let Some(e) = f.or(p) else { return };
        let (kind, method, host, route) = target(e);
        self.effect_items.push(EffectItem {
            change: change.into(),
            kind,
            method,
            host,
            route,
            grounding: f.map_or("live", |f| grounding_name(f.grounding)).into(),
            simulator: f.and_then(simulator_label).map(str::to_owned),
            turn_prod: turn_prod.map(prod_id),
            turn_fork: turn_fork.map(str::to_owned),
            fields: effect_fields(&self.norm.sealer, p, f),
        });
    }

    /// External effect differences of one turn pair: those to targets with
    /// a copy when `copied`, else the others. `quiet`: the replay could not
    /// run the turn on the recorded data (the fork turn read pseudonyms or
    /// met erased data, or the production turn is missing below one that
    /// did), so its effects are compared only for grounding and a
    /// difference is not a change (S-16, ADR 0109 points 3-4).
    fn turn_effects(
        &mut self,
        prod: Option<(Lsn, &pb::TurnRecord)>,
        fork: Option<&ForkTurn>,
        copied: bool,
        quiet: bool,
    ) {
        self.quiet = quiet;
        let pick =
            |e: &&pb::EffectRecord| external(&e.kind) && self.copied.contains(&e.target) == copied;
        let pe: BTreeMap<u32, &pb::EffectRecord> = prod
            .iter()
            .flat_map(|(_, t)| t.effects.iter())
            .filter(pick)
            .map(|e| (e.ordinal, e))
            .collect();
        let fe: BTreeMap<u32, &pb::EffectRecord> = fork
            .iter()
            .flat_map(|t| t.record.effects.iter())
            .filter(pick)
            .map(|e| (e.ordinal, e))
            .collect();
        let pl = prod.map(|p| p.0);
        let fid = fork.map(|f| f.id.as_str());
        let ordinals: BTreeSet<u32> = pe.keys().chain(fe.keys()).copied().collect();
        let counted = (
            self.effects.added,
            self.effects.removed,
            self.effects.changed,
        );
        for o in ordinals {
            match (pe.get(&o).copied(), fe.get(&o).copied()) {
                (Some(p), Some(f)) => {
                    if p.kind != f.kind {
                        self.effect_item("removed", Some(p), None, pl, fid);
                        self.effect_item("added", None, Some(f), pl, fid);
                    } else if p.target != f.target || p.fingerprint != f.fingerprint {
                        self.effect_item("changed", Some(p), Some(f), pl, fid);
                    }
                }
                (Some(p), None) => self.effect_item("removed", Some(p), None, pl, fid),
                (None, Some(f)) => self.effect_item("added", None, Some(f), pl, fid),
                (None, None) => {}
            }
        }
        let actor = fork
            .map(|f| kind_of(&f.record))
            .or_else(|| prod.map(|p| kind_of(p.1)))
            .unwrap_or_default();
        let (added, removed, changed) = (
            self.effects.added - counted.0,
            self.effects.removed - counted.1,
            self.effects.changed - counted.2,
        );
        if added + removed + changed > 0 {
            let e = &mut self.kind(actor).effects;
            e.added += added;
            e.removed += removed;
            e.changed += changed;
        }
        if let Some(f) = fork {
            let mut synthetic = false;
            for e in fe.values() {
                let slot = match pb::Grounding::try_from(e.grounding) {
                    Ok(pb::Grounding::Exact) => 0,
                    Ok(pb::Grounding::Approximate) => 1,
                    Ok(pb::Grounding::Synthetic) => {
                        synthetic = true;
                        if let Some(sim) = simulator_label(e) {
                            *self
                                .synthetic_by
                                .entry(target(e))
                                .or_default()
                                .entry(sim.to_owned())
                                .or_insert(0) += 1;
                        }
                        2
                    }
                    // Live and not denied by configuration: a live GET.
                    Ok(pb::Grounding::Live) if e.status != pb::EffectStatus::Denied as i32 => 3,
                    Ok(pb::Grounding::Forked) => 4,
                    _ => continue,
                };
                self.grounding.entry(target(e)).or_insert([0; 5])[slot] += 1;
            }
            if synthetic {
                push_capped(&mut self.samples.synthetic, MAX_SAMPLES, f.id.clone());
            }
        }
        self.quiet = false;
    }

    fn response(&mut self, root_lsn: Lsn, prod: (Lsn, &pb::TurnRecord), fork: Option<&ForkTurn>) {
        let Some(pb::input::Kind::Http(h)) = prod.1.input.as_ref().and_then(|i| i.kind.as_ref())
        else {
            return;
        };
        // The response of a turn the replay could not run on the recorded
        // data is not a change either (S-16, ADR 0109 points 3-4).
        if fork.is_some_and(unverified_input) {
            return;
        }
        let http = |t: &pb::TurnRecord| match t.outcome.as_ref().and_then(|o| o.output.as_ref()) {
            Some(pb::outcome::Output::Http(r)) => Some(r.clone()),
            _ => None,
        };
        let pr = http(prod.1);
        let fr = fork.and_then(|f| http(&f.record));
        let status = ProdFork {
            prod: pr.as_ref().map(|r| r.status),
            fork: fr.as_ref().map(|r| r.status),
        };
        let empty = Vec::new();
        let ph = self
            .norm
            .headers(pr.as_ref().map_or(&empty, |r| &r.headers));
        let fh = self
            .norm
            .headers(fr.as_ref().map_or(&empty, |r| &r.headers));
        let names: BTreeSet<&String> = ph.keys().chain(fh.keys()).collect();
        // A header value with a subject is that subject's data.
        let subjects = |r: Option<&pb::HttpResponse>| -> BTreeMap<String, String> {
            r.iter()
                .flat_map(|r| &r.headers)
                .filter_map(|h| {
                    let s = h.value.as_ref()?.subject.clone()?;
                    Some((h.name.to_ascii_lowercase(), s))
                })
                .collect()
        };
        let (psub, fsub) = (subjects(pr.as_ref()), subjects(fr.as_ref()));
        let sealer = &self.norm.sealer;
        let hv = |v: Option<&Vec<Vec<u8>>>, s: Option<&String>| match (v, s) {
            (None, _) => Value::Null,
            (Some(v), Some(s)) => Value::Array(v.iter().map(|b| redacted(sealer, s, b)).collect()),
            (Some(v), None) => Value::Array(v.iter().map(|b| bytes_json(b)).collect()),
        };
        let headers: Vec<HeaderDiff> = names
            .into_iter()
            .filter(|n| ph.get(*n) != fh.get(*n))
            .map(|n| HeaderDiff {
                name: n.clone(),
                prod: hv(ph.get(n), psub.get(n)),
                fork: hv(fh.get(n), fsub.get(n)),
            })
            .collect();
        let body = body_ops(
            &self.norm,
            pr.as_ref().and_then(http_body),
            fr.as_ref().and_then(http_body),
        );
        let kind = kind_of(prod.1);
        if status.prod == status.fork && headers.is_empty() && body.is_empty() {
            self.kind(kind).responses.unchanged += 1;
            self.responses.unchanged += 1;
            return;
        }
        self.kind(kind).responses.changed += 1;
        self.responses.changed += 1;
        if let Some(f) = fork {
            push_capped(
                &mut self.samples.responses_changed,
                MAX_SAMPLES,
                f.id.clone(),
            );
        }
        // The route pattern, never the path: paths can hold user data.
        let route = format!(
            "{} {}",
            h.method,
            if h.route.is_empty() {
                "(no route)"
            } else {
                &h.route
            }
        );
        push_capped(
            &mut self.responses.items,
            MAX_ITEMS,
            ResponseItem {
                root_lsn,
                route,
                turn_prod: prod_id(prod.0),
                turn_fork: fork.map(|f| f.id.clone()),
                status,
                headers,
                body,
            },
        );
    }

    /// Compares one set of production turns with the fork turns that
    /// replaced them: an isolated tree (`root_lsn` set) or the whole
    /// continuous window. `full = false` only records divergence and errors
    /// (continuous replay next to isolated replay).
    fn compare<'a>(
        &mut self,
        prod: &[(Lsn, &'a pb::TurnRecord)],
        fork: &'a [ForkTurn],
        root_lsn: Option<Lsn>,
        full: bool,
    ) {
        let pmap: BTreeMap<Vec<u8>, (Lsn, &pb::TurnRecord)> = prod
            .iter()
            .filter_map(|(l, t)| Some((causal::encode(t.causal_key.as_ref()?), (*l, *t))))
            .collect();
        let fmap: BTreeMap<Vec<u8>, &ForkTurn> = fork
            .iter()
            .filter_map(|f| Some((causal::encode(f.record.causal_key.as_ref()?), f)))
            .collect();
        if full {
            self.turns_prod += pmap.len() as u64;
            self.turns_fork += fmap.len() as u64;
            for (_, t) in pmap.values() {
                self.kind(kind_of(t)).turns_prod += 1;
            }
            for f in fmap.values() {
                self.kind(kind_of(&f.record)).turns_fork += 1;
            }
        }
        // Fork turns the replay could not run on the recorded data, and of
        // them those that met erased data: a production turn missing below
        // one is not evidence of a change either (issue #28).
        let unverified_turns: BTreeSet<Vec<u8>> = fork
            .iter()
            .filter(|f| unverified_input(f))
            .filter_map(|f| f.record.causal_key.as_ref().map(causal::encode))
            .collect();
        let erased_turns: BTreeSet<Vec<u8>> = fork
            .iter()
            .filter(|f| f.erased)
            .filter_map(|f| f.record.causal_key.as_ref().map(causal::encode))
            .collect();
        let below = |set: &BTreeSet<Vec<u8>>, ck: Option<&pb::CausalKey>| {
            ck.is_some_and(|ck| (0..ck.path.len()).any(|n| set.contains(&path_prefix(ck, n))))
        };
        // Whether the turn with a causal key committed, on each side: the
        // callee's turn of a call that timed out (#30).
        let prod_committed = |k: &pb::CausalKey| {
            pmap.get(&causal::encode(k))
                .is_some_and(|(_, t)| committed(t))
        };
        let fork_committed = |k: &pb::CausalKey| {
            fmap.get(&causal::encode(k))
                .is_some_and(|f| committed(&f.record))
        };
        let mut changes: BTreeMap<Vec<u8>, Change<'a>> = BTreeMap::new();
        for f in fork {
            let Some(key) = f.record.causal_key.as_ref().map(causal::encode) else {
                continue;
            };
            let p = pmap.get(&key).copied();
            // A turn the replay met with an erased recording is unverifiable
            // even when it comes out identical: identity there is the served
            // recording's, not the guest's (S-16, ADR 0109).
            if f.erased {
                self.erased_seen.insert(key.clone());
            }
            self.turn_errors(p, f, (&prod_committed, &fork_committed));
            match p {
                Some(p) => {
                    if full && !unverified_input(f) {
                        // The fuel of a turn the replay could not run on the
                        // recorded data measured a run on stand-in values,
                        // not the code, so it feeds no percentile (ADR 0109
                        // points 3-4).
                        self.fuel.0.push(p.1.fuel_used);
                        self.fuel.1.push(f.record.fuel_used);
                        self.memory.0.push(p.1.memory_peak_bytes);
                        self.memory.1.push(f.record.memory_peak_bytes);
                    }
                    if full || !self.copied.is_empty() {
                        self.turn_effects(Some(p), Some(f), !full, unverified_input(f));
                    }
                    if view(p.1, &self.norm) != view(&f.record, &self.norm) {
                        let same_input = input_bytes(p.1) == input_bytes(&f.record);
                        changes.insert(
                            key,
                            Change::Changed {
                                prod: p,
                                fork: f,
                                same_input,
                            },
                        );
                    } else if f.pseudonyms {
                        // Identical on pseudonyms: unverified if its code changed.
                        self.pii_same.insert(key, kind_of(&f.record));
                    }
                }
                None => {
                    if full || !self.copied.is_empty() {
                        self.turn_effects(None, Some(f), !full, unverified_input(f));
                    }
                    changes.insert(key, Change::New { fork: f });
                }
            }
        }
        for (key, p) in &pmap {
            if !fmap.contains_key(key) {
                if full || !self.copied.is_empty() {
                    let quiet = below(&unverified_turns, p.1.causal_key.as_ref());
                    self.turn_effects(Some(*p), None, !full, quiet);
                }
                changes.insert(key.clone(), Change::Missing { prod: *p });
            }
        }
        // Differences of turns that read pseudonyms, and production turns
        // missing below one (it differed, so it sent otherwise): not
        // verified, so pii-masked, and neither an origin nor a consequence.
        let pseudonymous = |c: Option<&Change<'_>>| matches!(c, Some(Change::Changed { fork, .. } | Change::New { fork }) if fork.pseudonyms);
        let unverified: BTreeSet<Vec<u8>> = changes
            .iter()
            .filter(|(_, c)| match c {
                Change::Changed { .. } | Change::New { .. } => pseudonymous(Some(c)),
                Change::Missing { prod } => prod.1.causal_key.as_ref().is_some_and(|ck| {
                    (0..ck.path.len()).any(|n| pseudonymous(changes.get(&path_prefix(ck, n))))
                }),
            })
            .map(|(k, _)| k.clone())
            .collect();
        // The differences that are evidence of a change, in this call: every
        // other one is pii-masked or unverifiable, and neither an origin nor
        // a consequence.
        let mut counted: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (key, change) in &changes {
            let (masked, erased) = match change {
                Change::Changed { fork, .. } | Change::New { fork } => (fork.masked, fork.erased),
                // A production turn missing below a turn that met erased
                // data: its absence is that turn's unverifiable difference,
                // not a verified one (issue #28, ADR 0109 point 3).
                Change::Missing { prod } => {
                    let erased = below(&erased_turns, prod.1.causal_key.as_ref());
                    (unverified.contains(key) || erased, erased)
                }
            };
            // A replayed erased turn is counted once (`erased_seen`), whether
            // it came out identical or differs; a production turn missing
            // below one is counted here.
            if erased && matches!(change, Change::Missing { .. }) {
                self.unverifiable.insert(key.clone());
            }
            if masked {
                if self.pii_masked.insert(key.clone())
                    && let Change::Changed { fork, .. } | Change::New { fork } = change
                {
                    push_capped(&mut self.samples.pii_masked, MAX_SAMPLES, fork.id.clone());
                }
            } else {
                let t = match change {
                    Change::Changed { fork, .. } | Change::New { fork } => &fork.record,
                    Change::Missing { prod } => prod.1,
                };
                self.divergent.insert(key.clone(), kind_of(t));
                counted.insert(key.clone());
            }
        }
        // Responses of the HTTP root inputs; an isolated tree that calls a
        // copied actor leaves its response to the continuous view.
        let calls_copy =
            |effects: &[pb::EffectRecord]| effects.iter().any(|e| self.copied.contains(&e.target));
        let defer = full
            && root_lsn.is_some()
            && (prod.iter().any(|(_, t)| calls_copy(&t.effects))
                || fork.iter().any(|f| calls_copy(&f.record.effects)));
        for (key, p) in &pmap {
            let is_root = p.1.causal_key.as_ref().is_some_and(|k| k.path.is_empty());
            let lsn = root_lsn.unwrap_or(p.0);
            if !is_root {
                continue;
            }
            if defer {
                self.deferred.insert(lsn);
            } else if full || self.deferred.contains(&lsn) {
                self.response(lsn, *p, fmap.get(key).copied());
            }
        }
        if !full {
            return;
        }
        self.tree_frames(prod, fork, root_lsn);
        // Causal grouping.
        let root_turns: BTreeMap<&str, (Lsn, &pb::TurnRecord)> = pmap
            .values()
            .filter_map(|(l, r)| {
                let k = r.causal_key.as_ref()?;
                k.path.is_empty().then_some((k.root.as_str(), (*l, *r)))
            })
            .collect();
        let origins: BTreeSet<Vec<u8>> = changes
            .iter()
            .filter(|(k, c)| {
                matches!(
                    c,
                    Change::Changed {
                        same_input: true,
                        ..
                    }
                ) && counted.contains(*k)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for (key, c) in &changes {
            if !counted.contains(key) {
                continue;
            }
            let (t, id, lsn) = match c {
                Change::Changed { prod, fork, .. } => {
                    (&fork.record, Some(fork.id.clone()), Some(prod.0))
                }
                Change::New { fork } => (&fork.record, Some(fork.id.clone()), None),
                Change::Missing { prod } => (prod.1, None, Some(prod.0)),
            };
            let Some(ck) = t.causal_key.as_ref() else {
                continue;
            };
            let root_turn = root_turns.get(ck.root.as_str()).copied();
            let root = root_lsn.or(root_turn.map(|r| r.0)).or(lsn).unwrap_or(0);
            if origins.contains(key) {
                self.origins += 1;
                let actor = kind_of(t);
                self.kind(actor.clone()).origins += 1;
                let g = self
                    .causes
                    .entry((actor, input_label(t.input.as_ref())))
                    .or_default();
                g.origins += 1;
                g.roots.insert(root);
                if let Some(id) = &id {
                    push_capped(&mut g.samples, MAX_CAUSE_SAMPLES, id.clone());
                    push_capped(&mut self.samples.origins, MAX_SAMPLES, id.clone());
                }
                continue;
            }
            self.consequences += 1;
            self.kind(kind_of(t)).consequences += 1;
            if let Some(id) = &id {
                push_capped(&mut self.samples.consequences, MAX_SAMPLES, id.clone());
            }
            // The nearest differing ancestor that is an origin, else the
            // tree's root input.
            let ancestor = (0..ck.path.len())
                .rev()
                .map(|n| path_prefix(ck, n))
                .find(|k| origins.contains(k));
            let group = match ancestor.and_then(|k| changes.get(&k)) {
                Some(Change::Changed { fork, .. }) => (
                    fork.record
                        .actor
                        .as_ref()
                        .map(|a| a.kind.clone())
                        .unwrap_or_default(),
                    input_label(fork.record.input.as_ref()),
                ),
                _ => match root_turn {
                    Some((_, r)) => (
                        r.actor.as_ref().map(|a| a.kind.clone()).unwrap_or_default(),
                        input_label(r.input.as_ref()),
                    ),
                    None => (
                        t.actor.as_ref().map(|a| a.kind.clone()).unwrap_or_default(),
                        input_label(t.input.as_ref()),
                    ),
                },
            };
            let g = self.causes.entry(group).or_default();
            g.consequences += 1;
            g.roots.insert(root);
        }
        if let Some(root_lsn) = root_lsn {
            self.tree_state(root_lsn, prod, fork);
        }
    }

    /// The frames of the root inputs among `prod` and `fork` (M24 §7.5), in
    /// root LSN order: one isolated tree (`root_lsn` set), or every tree of
    /// the continuous window.
    fn tree_frames(
        &mut self,
        prod: &[(Lsn, &pb::TurnRecord)],
        fork: &[ForkTurn],
        root_lsn: Option<Lsn>,
    ) {
        type Tree<'t> = (Vec<(Lsn, &'t pb::TurnRecord)>, Vec<&'t ForkTurn>);
        let mut trees: BTreeMap<&str, Tree<'_>> = BTreeMap::new();
        for (l, t) in prod {
            if let Some(k) = &t.causal_key {
                trees.entry(k.root.as_str()).or_default().0.push((*l, *t));
            }
        }
        for f in fork {
            if let Some(k) = &f.record.causal_key {
                trees.entry(k.root.as_str()).or_default().1.push(f);
            }
        }
        let mut ordered: Vec<(Lsn, (Lsn, &pb::TurnRecord), Tree<'_>)> = trees
            .into_values()
            .filter_map(|(p, f)| {
                let root = p
                    .iter()
                    .find(|(_, t)| t.causal_key.as_ref().is_some_and(|k| k.path.is_empty()))
                    .copied()?;
                Some((root_lsn.unwrap_or(root.0), root, (p, f)))
            })
            .collect();
        ordered.sort_by_key(|(lsn, ..)| *lsn);
        for (lsn, root, (p, f)) in ordered {
            self.frames(lsn, root, &p, &f);
        }
    }

    /// One root input's frames: what its tree sent to connections in
    /// production against the fork, operation by operation (its turns in
    /// causal order, each turn's in the order they went out), and its open's
    /// answer. Counted when the input is a connection input or a side sent
    /// frames; the counts of what was sent always, the comparison only for a
    /// tree whose turns all ran on the recorded data (as `response`).
    fn frames(
        &mut self,
        root_lsn: Lsn,
        root: (Lsn, &pb::TurnRecord),
        prod: &[(Lsn, &pb::TurnRecord)],
        fork: &[&ForkTurn],
    ) {
        let mut sides: BTreeMap<Vec<u8>, (Vec<ConnOp>, Vec<ConnOp>)> = BTreeMap::new();
        for (_, t) in prod {
            if let Some(k) = &t.causal_key {
                sides.entry(causal::encode(k)).or_default().0 = conn_ops(t);
            }
        }
        for f in fork {
            if let Some(k) = &f.record.causal_key {
                sides.entry(causal::encode(k)).or_default().1 = conn_ops(&f.record);
            }
        }
        let connection = kronik_proto::connection::input(root.1.input.as_ref());
        let sent_any = sides.values().any(|(p, f)| !p.is_empty() || !f.is_empty());
        if connection.is_none() && !sent_any {
            return;
        }
        self.frames_seen = true;
        for (p, f) in sides.values() {
            self.frames.sent.prod += p.iter().map(|o| o.delivered).sum::<u64>();
            self.frames.sent.fork += f.iter().map(|o| o.delivered).sum::<u64>();
        }
        for e in fork
            .iter()
            .flat_map(|f| &f.record.effects)
            .filter(|e| e.kind == SEND_NOW)
        {
            match pb::Grounding::try_from(e.grounding) {
                Ok(pb::Grounding::Exact | pb::Grounding::Approximate) => {
                    self.frames.send_now.recorded += 1;
                }
                Ok(pb::Grounding::Synthetic) => self.frames.send_now.modeled += 1,
                _ => {}
            }
        }
        // What a turn the replay could not run on the recorded data sent is
        // not a change either (S-16, ADR 0109 points 3-4).
        if fork.iter().any(|f| unverified_input(f)) {
            return;
        }
        // An input the fork did not run (continuous replay skips the frames
        // of a connection its actor never accepted) is `skipped`, not a
        // comparison.
        let root_key = root.1.causal_key.as_ref().map(causal::encode);
        let Some(fork_root) = fork
            .iter()
            .copied()
            .find(|f| f.record.causal_key.as_ref().map(causal::encode) == root_key)
        else {
            return;
        };
        let open = match connection.and_then(|c| c.event.as_ref()) {
            Some(pb::connection_input::Event::Open(_)) => {
                let answered = |t: &pb::TurnRecord| {
                    let v = view(t, &self.norm);
                    (v.outcome, v.output)
                };
                (answered(root.1) != answered(&fork_root.record)).then(|| ProdFork {
                    prod: open_answer(root.1),
                    fork: open_answer(&fork_root.record),
                })
            }
            _ => None,
        };
        let mut changes = Vec::new();
        let mut changed = false;
        let mut index = 0u64;
        for (p, f) in sides.values() {
            for i in 0..p.len().max(f.len()) {
                if let Some(c) = frame_change(&self.norm, index, p.get(i), f.get(i)) {
                    changed = true;
                    push_capped(&mut changes, MAX_FRAME_CHANGES, c);
                }
                index += 1;
            }
        }
        let kind = kind_of(root.1);
        if !changed && open.is_none() {
            self.frames.unchanged += 1;
            self.kind(kind)
                .frames
                .get_or_insert_with(KindResponses::default)
                .unchanged += 1;
            return;
        }
        self.frames.changed += 1;
        self.kind(kind)
            .frames
            .get_or_insert_with(KindResponses::default)
            .changed += 1;
        push_capped(
            &mut self.samples.frames_changed,
            MAX_SAMPLES,
            fork_root.id.clone(),
        );
        push_capped(
            &mut self.frames.items,
            MAX_ITEMS,
            FrameItem {
                root_lsn,
                input: input_label(root.1.input.as_ref()),
                turn_prod: prod_id(root.0),
                turn_fork: fork_root.id.clone(),
                open,
                frames: changes,
            },
        );
    }

    /// Isolated state: the final writes of a tree per actor.
    fn tree_state(&mut self, root_lsn: Lsn, prod: &[(Lsn, &pb::TurnRecord)], fork: &[ForkTurn]) {
        type Writes = BTreeMap<String, BTreeMap<String, (i32, Option<pb::Sealable>)>>;
        type Rows = BTreeMap<String, Vec<RowChange>>;
        fn collect<'t>(
            turns: impl Iterator<Item = &'t pb::TurnRecord>,
            sealer: &Sealer,
        ) -> (Writes, Rows) {
            let mut w: Writes = BTreeMap::new();
            let mut r: Rows = BTreeMap::new();
            for t in turns.filter(|t| committed(t)) {
                let actor = t
                    .actor
                    .as_ref()
                    .map(|a| format!("{}/{}", a.kind, a.key))
                    .unwrap_or_default();
                for x in &t.writes {
                    w.entry(actor.clone())
                        .or_default()
                        .insert(x.key.clone(), (x.op, x.value.clone()));
                }
                for c in &t.sql_changes {
                    if let Some(b) = sealable_bytes(c.changeset.as_ref())
                        && let Ok(mut rows) = changeset_rows(b)
                    {
                        // A subject's rows are its data: like state values,
                        // the diff shows that they changed, not what to.
                        if let Some(subject) = c.changeset.as_ref().and_then(|s| s.subject.as_ref())
                        {
                            for row in &mut rows {
                                redact_row(&mut row.old, sealer, subject);
                                redact_row(&mut row.new, sealer, subject);
                            }
                        }
                        r.entry(actor.clone()).or_default().extend(rows);
                    }
                }
            }
            (w, r)
        }
        let sealer = self.norm.sealer.clone();
        // The state a turn the replay could not run on the recorded data
        // wrote is not evidence of a behavior change: neither the turn nor
        // its production counterpart contributes, and a production turn
        // missing below one does not either (S-16, ADR 0109 points 3-4).
        let skip = unverified_state_keys(prod, fork);
        let (pw, pr) = collect(
            prod.iter().map(|(_, t)| *t).filter(|t| {
                t.causal_key
                    .as_ref()
                    .is_none_or(|k| !skip.contains(&causal::encode(k)))
            }),
            &sealer,
        );
        let (fw, fr) = collect(
            fork.iter()
                .filter(|f| !unverified_input(f))
                .map(|f| &f.record),
            &sealer,
        );
        let actors: BTreeSet<&String> = pw
            .keys()
            .chain(fw.keys())
            .chain(pr.keys())
            .chain(fr.keys())
            .collect();
        for a in actors {
            let empty = BTreeMap::new();
            let (p, f) = (pw.get(a).unwrap_or(&empty), fw.get(a).unwrap_or(&empty));
            let keys: BTreeSet<&String> = p.keys().chain(f.keys()).collect();
            let mut kd = Vec::new();
            for k in keys {
                let (pv, fv) = (p.get(k), f.get(k));
                if pv == fv {
                    continue;
                }
                let render = |v: Option<&(i32, Option<pb::Sealable>)>| match v {
                    Some((op, val)) if *op == pb::StateOp::Set as i32 => {
                        sealable_json(&sealer, val.as_ref())
                    }
                    _ => Value::Null,
                };
                let op = match fv {
                    Some((op, _)) if *op == pb::StateOp::Set as i32 => "set",
                    Some(_) => "delete",
                    None => "unchanged-missing",
                };
                push_capped(
                    &mut kd,
                    MAX_ITEMS,
                    KeyDiff {
                        key: k.clone(),
                        op: op.into(),
                        prod: render(pv),
                        fork: render(fv),
                    },
                );
            }
            let none = Vec::new();
            let sql = row_change_diff(pr.get(a).unwrap_or(&none), fr.get(a).unwrap_or(&none));
            if kd.is_empty() && sql.is_empty() {
                continue;
            }
            self.isolated_actor_roots
                .entry(a.clone())
                .or_default()
                .insert(root_lsn);
            push_capped(
                &mut self.isolated_state,
                MAX_ITEMS,
                IsolatedState {
                    root_lsn,
                    actor: a.clone(),
                    keys: kd,
                    sql,
                },
            );
        }
    }
}

/// Replaces the values of a subject's SQL row with a hash placeholder.
fn redact_row(values: &mut [Option<SqlValue>], sealer: &Sealer, subject: &str) {
    for v in values.iter_mut().flatten() {
        redact_sql(v, sealer, subject);
    }
}

fn redact_sql(v: &mut SqlValue, sealer: &Sealer, subject: &str) {
    let bytes = match v {
        SqlValue::Null => return,
        SqlValue::Integer(i) => i.to_le_bytes().to_vec(),
        SqlValue::Real(f) => f.to_le_bytes().to_vec(),
        SqlValue::Text(t) => t.as_bytes().to_vec(),
        SqlValue::Blob(b) => b.clone(),
    };
    *v = SqlValue::Text(format!(
        "[redacted:{}:{}]",
        shown_subject(sealer, subject),
        redacted_hash(sealer, subject, &bytes)
    ));
}

fn row_json(values: &[Option<SqlValue>]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|v| v.as_ref().map_or(Value::Null, sql_json))
            .collect(),
    )
}

/// Row changes in one side and not the other, keyed by (table, op, pk).
fn row_change_diff(p: &[RowChange], f: &[RowChange]) -> Vec<SqlDiff> {
    type Key = (String, &'static str, String);
    let key = |r: &RowChange| -> Key {
        (
            r.table.clone(),
            r.op,
            serde_json::to_string(&r.pk.iter().map(sql_json).collect::<Vec<_>>())
                .unwrap_or_default(),
        )
    };
    let side = |rows: &[RowChange]| -> BTreeMap<Key, (Vec<Value>, Value)> {
        rows.iter()
            .map(|r| {
                let v = if r.op == "delete" {
                    row_json(&r.old)
                } else {
                    row_json(&r.new)
                };
                (key(r), (r.pk.iter().map(sql_json).collect(), v))
            })
            .collect()
    };
    let (ps, fs) = (side(p), side(f));
    let keys: BTreeSet<&Key> = ps.keys().chain(fs.keys()).collect();
    let mut out = Vec::new();
    for k in keys {
        let (a, b) = (ps.get(k), fs.get(k));
        if a.map(|x| &x.1) == b.map(|x| &x.1) {
            continue;
        }
        let pk = a.or(b).map(|x| x.0.clone()).unwrap_or_default();
        push_capped(
            &mut out,
            MAX_ITEMS,
            SqlDiff {
                table: k.0.clone(),
                op: k.1.into(),
                pk,
                prod: a.map_or(Value::Null, |x| x.1.clone()),
                fork: b.map_or(Value::Null, |x| x.1.clone()),
            },
        );
    }
    out
}

/// Final-state rows by (table, pk) -> (columns, values). A row with a
/// `_subject` is that subject's data: its values are redacted, as in the
/// isolated side's row changes.
fn table_map(
    tables: &[TableRows],
    sealer: &Sealer,
) -> BTreeMap<(String, String), (Vec<Value>, Value)> {
    let mut out = BTreeMap::new();
    for t in tables {
        let subject_col = t.columns.iter().position(|c| c == "_subject");
        for row in &t.rows {
            let pk: Vec<Value> =
                t.pk.iter()
                    .map(|i| row.get(*i).map_or(Value::Null, sql_json))
                    .collect();
            let subject = subject_col.and_then(|i| match row.get(i) {
                Some(SqlValue::Text(s)) => Some(s.clone()),
                _ => None,
            });
            let obj: serde_json::Map<String, Value> = t
                .columns
                .iter()
                .zip(row)
                .map(|(c, v)| match &subject {
                    Some(s) => {
                        let mut v = v.clone();
                        redact_sql(&mut v, sealer, s);
                        (c.clone(), sql_json(&v))
                    }
                    None => (c.clone(), sql_json(v)),
                })
                .collect();
            out.insert(
                (
                    t.name.clone(),
                    serde_json::to_string(&pk).unwrap_or_default(),
                ),
                (pk, Value::Object(obj)),
            );
        }
    }
    out
}

fn actor_rows(store: &Store, actor: &str) -> Result<Vec<TableRows>, ReplayError> {
    let db = store
        .sql
        .get(actor)
        .map_err(|e| ReplayError::Host(e.to_string()))?;
    let g = db.lock().unwrap_or_else(|e| e.into_inner());
    g.canonical_rows()
        .map_err(|e| ReplayError::Host(e.to_string()))
}

fn all_actors(store: &Store) -> Result<Vec<(ActorRef, bool)>, ReplayError> {
    let mut out = Vec::new();
    let mut after: Option<(String, String)> = None;
    loop {
        let page = store.db().actors(
            None,
            after.as_ref().map(|(k, y)| (k.as_str(), y.as_str())),
            1000,
        )?;
        let Some(last) = page.last() else { break };
        after = Some((last.kind.clone(), last.key.clone()));
        out.extend(page.into_iter().map(|a| {
            (
                ActorRef::from_pb(&pb::ActorRef {
                    kind: a.kind,
                    key: a.key,
                }),
                a.sql,
            )
        }));
    }
    Ok(out)
}

/// The state a turn the replay could not run on the recorded data wrote
/// ([`unverified_input`]): keys and SQL rows that are not evidence of a
/// behavior change, so the continuous state comparison skips them (S-16,
/// ADR 0109 points 3-4; ADR 0031).
#[derive(Default)]
struct StateTouches {
    /// (actor, state key)
    keys: BTreeSet<(String, String)>,
    /// (actor, table, primary key as JSON)
    rows: BTreeSet<(String, String, String)>,
}

impl StateTouches {
    fn record(&mut self, t: &pb::TurnRecord) {
        let actor = t
            .actor
            .as_ref()
            .map(|a| format!("{}/{}", a.kind, a.key))
            .unwrap_or_default();
        for w in &t.writes {
            self.keys.insert((actor.clone(), w.key.clone()));
        }
        for c in &t.sql_changes {
            let Some(b) = sealable_bytes(c.changeset.as_ref()) else {
                continue;
            };
            let Ok(rows) = changeset_rows(b) else {
                continue;
            };
            for r in rows {
                let pk = serde_json::to_string(&r.pk.iter().map(sql_json).collect::<Vec<_>>())
                    .unwrap_or_default();
                self.rows.insert((actor.clone(), r.table.clone(), pk));
            }
        }
    }
}

/// Each actor's final state in the fork store against production's.
/// `excluded` holds the keys and rows written by turns the replay could not
/// run on the recorded data; they are skipped, so they cannot set `changed`.
fn continuous_state(
    fork: &Store,
    prod: &Store,
    sealer: &Sealer,
    excluded: &StateTouches,
) -> Result<Vec<ActorState>, ReplayError> {
    let mut actors: BTreeMap<String, (ActorRef, bool, bool)> = BTreeMap::new();
    for (a, sql) in all_actors(prod)? {
        actors.entry(a.to_string()).or_insert((a, false, false)).1 = sql;
    }
    for (a, sql) in all_actors(fork)? {
        actors.entry(a.to_string()).or_insert((a, false, false)).2 = sql;
    }
    let mut out = Vec::new();
    for (name, (a, psql, fsql)) in actors {
        let pk = prod.db().kv_list(&a.kind, &a.key)?;
        let fk = fork.db().kv_list(&a.kind, &a.key)?;
        let side = |rows: Vec<kronik_store::db::KvRow>| -> BTreeMap<String, Value> {
            rows.into_iter()
                .map(|r| {
                    let v = pb::Sealable {
                        subject: r.subject,
                        value: Some(pb::sealable::Value::Plain(r.value)),
                    };
                    (r.k, sealable_json(sealer, Some(&v)))
                })
                .collect()
        };
        let (pk, fk) = (side(pk), side(fk));
        let names: BTreeSet<&String> = pk.keys().chain(fk.keys()).collect();
        let mut keys = Vec::new();
        for k in names {
            if excluded.keys.contains(&(name.clone(), k.clone())) {
                continue;
            }
            let (p, f) = (pk.get(k), fk.get(k));
            if p == f {
                continue;
            }
            let op = if f.is_some() { "set" } else { "delete" };
            push_capped(
                &mut keys,
                MAX_ITEMS,
                KeyDiff {
                    key: k.clone(),
                    op: op.into(),
                    prod: p.cloned().unwrap_or(Value::Null),
                    fork: f.cloned().unwrap_or(Value::Null),
                },
            );
        }
        let mut sql = Vec::new();
        if psql || fsql {
            let pt = if psql {
                table_map(&actor_rows(prod, &name)?, sealer)
            } else {
                BTreeMap::new()
            };
            let ft = if fsql {
                table_map(&actor_rows(fork, &name)?, sealer)
            } else {
                BTreeMap::new()
            };
            let rows: BTreeSet<&(String, String)> = pt.keys().chain(ft.keys()).collect();
            for r in rows {
                if excluded
                    .rows
                    .contains(&(name.clone(), r.0.clone(), r.1.clone()))
                {
                    continue;
                }
                let (p, f) = (pt.get(r), ft.get(r));
                if p.map(|x| &x.1) == f.map(|x| &x.1) {
                    continue;
                }
                let op = match (p, f) {
                    (None, _) => "insert",
                    (_, None) => "delete",
                    _ => "update",
                };
                push_capped(
                    &mut sql,
                    MAX_ITEMS,
                    SqlDiff {
                        table: r.0.clone(),
                        op: op.into(),
                        pk: p.or(f).map(|x| x.0.clone()).unwrap_or_default(),
                        prod: p.map_or(Value::Null, |x| x.1.clone()),
                        fork: f.map_or(Value::Null, |x| x.1.clone()),
                    },
                );
            }
        }
        if !keys.is_empty() || !sql.is_empty() {
            out.push(ActorState {
                actor: name,
                keys,
                sql,
            });
        }
    }
    Ok(out)
}

/// The continuous side of a diff.
pub struct ContinuousView<'a> {
    pub turns: &'a [ForkTurn],
    pub fork: &'a Store,
    pub prod: &'a Store,
    /// The production LSNs of the connection inputs the fork did not run
    /// ([`crate::replay::Continuous::skipped`], M24 §7.2).
    pub skipped: &'a [Lsn],
}

/// Everything a diff is built from.
pub struct DiffInput<'a> {
    pub fork: &'a str,
    pub proposal_id: Option<&'a str>,
    pub index: &'a ProductionIndex,
    pub before: Vec<CodeEntry>,
    pub after: Vec<CodeEntry>,
    pub options: &'a DiffOptions,
    /// Isolated results, for the replayed (sampled) root inputs.
    pub isolated: Option<&'a [TreeResult]>,
    pub continuous: Option<ContinuousView<'a>>,
    /// A rebase (M13): the diff lists the irreversible effects.
    pub rebase: bool,
}

/// A kind's `code` in `kinds`: its code at the fork point against the
/// fork's. `absent`: no code on either side (a kind only turns that found
/// no deployed kind ran as).
fn code_status(before: Option<&CodeEntry>, after: Option<&CodeEntry>) -> &'static str {
    match (before, after) {
        (None, None) => "absent",
        (None, Some(_)) => "new",
        (b, a) if b != a => "changed",
        _ => "unchanged",
    }
}

/// Builds the diff (§5). Deterministic: the same inputs give the same
/// document.
pub fn build(input: DiffInput<'_>) -> Result<Diff, ReplayError> {
    let index = input.index;
    let mut acc = Acc::new(input.options, index.sealer.clone());
    if input.isolated.is_some() && input.continuous.is_some() {
        acc.copied = input
            .options
            .foreign
            .iter()
            .filter(|f| f.mode == "sandbox")
            .map(|f| format!("foreign:{}", f.name))
            .collect();
    }
    let roots: BTreeMap<Lsn, &RootInput> = index.roots.iter().map(|r| (r.lsn, r)).collect();
    let masked = masked_production(index);
    let mut replayed = 0u64;
    if let Some(trees) = input.isolated {
        for t in trees {
            let Some(root) = roots.get(&t.root_lsn) else {
                continue;
            };
            replayed += 1;
            let prod = with_masked(index.tree(root), &masked);
            let fork = masked_fork(&t.turns, index);
            acc.compare(&prod, &sql_tagged(&fork), Some(t.root_lsn), true);
        }
    }
    let mut state_continuous = Vec::new();
    if let Some(c) = &input.continuous {
        let prod: Vec<(Lsn, &pb::TurnRecord)> = with_masked(
            index
                .records
                .iter()
                .filter(|r| r.lsn > index.fork_lsn)
                .filter_map(|r| match &r.record {
                    Record::TurnRecord(t) => Some((r.lsn, t)),
                    _ => None,
                })
                .collect(),
            &masked,
        );
        let full = input.isolated.is_none();
        if full {
            replayed = index.roots.len() as u64;
        }
        // Preview requests (M11) have no production counterpart: listed on
        // their own, never compared.
        let mut own: Cow<'_, [ForkTurn]> = Cow::Borrowed(c.turns);
        if c.turns.iter().any(is_preview) {
            let (preview, rest): (Vec<ForkTurn>, Vec<ForkTurn>) =
                c.turns.iter().cloned().partition(is_preview);
            acc.preview(&preview);
            own = Cow::Owned(rest);
        }
        let compared = masked_fork(&own, index);
        acc.compare(&prod, &sql_tagged(&compared), None, full);
        // The state a turn the replay could not run on the recorded data
        // wrote is not evidence of a behavior change: every key and row such
        // turns touched on either side is skipped in the comparison below
        // (S-16, ADR 0109 points 3-4).
        let mut touches = StateTouches::default();
        for f in own.iter().filter(|f| unverified_input(f)) {
            touches.record(&f.record);
        }
        let skip = unverified_state_keys(&prod, &own);
        for t in prod.iter().map(|(_, t)| *t).filter(|t| {
            t.causal_key
                .as_ref()
                .is_some_and(|k| skip.contains(&causal::encode(k)))
        }) {
            touches.record(t);
        }
        state_continuous = continuous_state(c.fork, c.prod, &index.sealer, &touches)?;
    }
    let cumulative: Vec<ActorState> = state_continuous
        .iter()
        .filter(|a| {
            input.isolated.is_none()
                || acc
                    .isolated_actor_roots
                    .get(&a.actor)
                    .is_none_or(|r| r.len() != 1)
        })
        .cloned()
        .collect();

    let mut causes: Vec<Cause> = acc
        .causes
        .into_iter()
        .map(|((kind, inp), g)| Cause {
            kind,
            input: inp,
            origins: g.origins,
            consequences: g.consequences,
            root_inputs: g.roots.len() as u64,
            samples: g.samples,
        })
        .collect();
    causes.sort_by(|a, b| {
        b.origins
            .cmp(&a.origins)
            .then(a.kind.cmp(&b.kind))
            .then(a.input.cmp(&b.input))
    });
    let mut synthetic_by_target = acc.synthetic_by;
    let mut synthetic_by: BTreeMap<String, u64> = BTreeMap::new();
    for counts in synthetic_by_target.values() {
        for (sim, n) in counts {
            *synthetic_by.entry(sim.clone()).or_insert(0) += n;
        }
    }
    let grounding: Vec<GroundingRow> = acc
        .grounding
        .into_iter()
        .map(|(key, [e, a, s, l, f])| {
            let by = synthetic_by_target.remove(&key).unwrap_or_default();
            (key, [e, a, s, l, f], by)
        })
        .map(
            |((kind, method, host, route), [e, a, s, l, f], by)| GroundingRow {
                kind,
                method,
                host,
                route,
                exact: e,
                approximate: a,
                synthetic: s,
                synthetic_by: by,
                live: l,
                forked: f,
                confidence: r6(e as f64 / (e + a + s + l + f).max(1) as f64),
            },
        )
        .collect();
    let (exact, approximate, synthetic, live, forked) =
        grounding
            .iter()
            .fold((0, 0, 0, 0, 0), |(e, a, s, l, f), g| {
                (
                    e + g.exact,
                    a + g.approximate,
                    s + g.synthetic,
                    l + g.live,
                    f + g.forked,
                )
            });
    let total = exact + approximate + synthetic + live + forked;
    let mut effects = acc.effects;
    let mut items = acc.effect_items;
    items.sort_by(|a, b| {
        (&a.kind, &a.host, &a.route, &a.turn_fork, &a.turn_prod).cmp(&(
            &b.kind,
            &b.host,
            &b.route,
            &b.turn_fork,
            &b.turn_prod,
        ))
    });
    items.truncate(MAX_ITEMS);
    effects.items = items;
    let fuel = ProdFork {
        prod: percentiles(acc.fuel.0),
        fork: percentiles(acc.fuel.1),
    };
    let memory = ProdFork {
        prod: percentiles(acc.memory.0),
        fork: percentiles(acc.memory.1),
    };
    let resources = Resources {
        fuel_p99_change: change(fuel.prod.p99, fuel.fork.p99),
        memory_p99_change: change(memory.prod.p99, memory.fork.p99),
        fuel,
        memory,
    };
    let root_inputs = index.roots.len() as u64;
    // Per kind (M9): every kind of the fork's code and every kind a turn ran
    // as, each with its share of the counts.
    let mut by_kind = std::mem::take(&mut acc.by_kind);
    for k in input.after.iter().chain(&input.before) {
        by_kind.entry(k.kind.clone()).or_default();
    }
    for r in &index.roots {
        by_kind.entry(r.actor.kind.clone()).or_default().root_inputs += 1;
    }
    for kind in acc.divergent.values() {
        by_kind.entry(kind.clone()).or_default().divergent_turns += 1;
    }
    let changed_actors: BTreeSet<&str> = acc
        .isolated_actor_roots
        .keys()
        .chain(state_continuous.iter().map(|a| &a.actor))
        .map(String::as_str)
        .collect();
    for a in changed_actors {
        let kind = a.split_once('/').map_or(a, |(k, _)| k);
        by_kind.entry(kind.to_owned()).or_default().actors_changed += 1;
    }
    let kinds: Vec<KindReport> = by_kind
        .into_iter()
        .filter(|(kind, _)| !kind.is_empty())
        .map(|(kind, mut r)| {
            r.code = code_status(
                input.before.iter().find(|b| b.kind == kind),
                input.after.iter().find(|a| a.kind == kind),
            )
            .into();
            r.kind = kind;
            r
        })
        .collect();
    let errors = acc.errors;
    // Long-lived connections (M24 §7.5): the window's connection inputs,
    // what continuous replay skipped, and what the compared trees sent.
    let mut samples = acc.samples;
    let mut frames = acc.frames;
    for r in &index.roots {
        match kronik_proto::connection::input(Some(&r.input)).and_then(|c| c.event.as_ref()) {
            Some(pb::connection_input::Event::Open(_)) => frames.inputs.open += 1,
            Some(pb::connection_input::Event::Frame(_)) => frames.inputs.frame += 1,
            Some(pb::connection_input::Event::Close(_)) => frames.inputs.close += 1,
            None => {}
        }
    }
    if let Some(c) = &input.continuous {
        frames.skipped = c.skipped.len() as u64;
        samples.frames_skipped = c
            .skipped
            .iter()
            .take(MAX_SAMPLES)
            .map(|l| prod_id(*l))
            .collect();
    }
    let inputs = frames.inputs;
    let frames = (acc.frames_seen
        || inputs.open + inputs.frame + inputs.close + frames.skipped > 0)
        .then_some(frames);
    let frames_changed = frames.as_ref().map_or(0, |f| f.changed);
    let changed_code: BTreeSet<&str> = kinds
        .iter()
        .filter(|k| matches!(&*k.code, "changed" | "new"))
        .map(|k| k.kind.as_str())
        .collect();
    // In `both` mode a key can be identical in one replay and masked in the
    // other: it counts once, as masked.
    let pii_unverified = acc
        .pii_same
        .iter()
        .filter(|(key, kind)| {
            changed_code.contains(kind.as_str()) && !acc.pii_masked.contains(*key)
        })
        .count() as u64;
    // `pii_masked` and `unverifiable` turns are not changes (S-16, ADR 0109;
    // ADR 0031): their difference was not verified, so it is not evidence of
    // a behavior change either. Every other difference stays fail-closed.
    let changed = !acc.divergent.is_empty()
        || acc.responses.changed > 0
        || frames_changed > 0
        || effects.added + effects.removed + effects.changed > 0
        || !acc.isolated_state.is_empty()
        || !state_continuous.is_empty()
        // outcome_unknown is a property of the recording (the fork reused
        // production's unknown outcome), not a change.
        || errors.introduced + errors.fixed + errors.new_orphans > 0
        || resources.fuel_p99_change.abs() >= input.options.fuel_threshold;
    let summary = Summary {
        root_inputs,
        replayed,
        sample: if root_inputs == 0 {
            1.0
        } else {
            r6(replayed as f64 / root_inputs as f64)
        },
        turns_prod: acc.turns_prod,
        turns_fork: acc.turns_fork,
        divergent_turns: acc.divergent.len() as u64,
        pii_masked: acc.pii_masked.len() as u64,
        pii_unverified,
        // A key can be a replayed erased turn in one mode and a production
        // turn missing below one in the other: it counts once.
        unverifiable: acc.erased_seen.union(&acc.unverifiable).count() as u64,
        preview_inputs: acc.preview_inputs,
        frames_changed,
        origins: acc.origins,
        consequences: acc.consequences,
        exact,
        approximate,
        synthetic,
        synthetic_by,
        live,
        forked,
        confidence: if total == 0 {
            1.0
        } else {
            r6(exact as f64 / total as f64)
        },
        verified_through_lsn: index.to_lsn,
        changed,
    };
    Ok(Diff {
        schema: "kronik.diff/v1".into(),
        fork: input.fork.to_owned(),
        proposal_id: input.proposal_id.map(str::to_owned),
        base: Base {
            branch: "main".into(),
            fork_lsn: index.fork_lsn,
            from_lsn: index.fork_lsn + 1,
            to_lsn: index.to_lsn,
            window_cut: None,
        },
        code: Code {
            before: input.before,
            after: input.after,
        },
        options: DiffOptions {
            // A rebase uses none (m13-rebase §8).
            simulators: if input.rebase {
                Vec::new()
            } else {
                crate::simulators::Simulators::new(index, &input.options.simulator_overrides)
                    .options()
            },
            ..input.options.clone()
        },
        summary,
        kinds,
        causes,
        grounding,
        responses: acc.responses,
        frames,
        effects,
        state: State {
            isolated: acc.isolated_state,
            continuous: state_continuous,
        },
        cumulative: Cumulative {
            actors_changed: cumulative.len() as u64,
            items: cumulative.into_iter().take(MAX_ITEMS).collect(),
        },
        errors,
        resources,
        samples,
        irreversible: match (input.rebase, &input.continuous) {
            (true, Some(c)) => Some(irreversible(index, c.turns)),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The diff's orphans are the store's (#30): a failed turn's call whose
    /// callee committed and that has no compensation. That is a successful
    /// call, one whose reply was withheld after its callee committed, or one
    /// that timed out while its callee's turn still committed.
    #[test]
    fn orphans_are_calls_whose_callee_committed() {
        let call = |ordinal: u32, status: pb::EffectStatus, compensate: bool| {
            let request = pb::CallEffectRequest {
                compensate: compensate.then(pb::Message::default),
                ..Default::default()
            };
            pb::EffectRecord {
                ordinal,
                kind: "actor.call".into(),
                target: "actor:counter/b".into(),
                status: status as i32,
                request: Some(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(request.encode_to_vec())),
                }),
                ..Default::default()
            }
        };
        let mut withheld = call(4, pb::EffectStatus::HostRedactionFailure, false);
        withheld.callee_source = Some(pb::ActorSource {
            shard: None,
            lsn: 9,
            branch: "main".into(),
        });
        withheld.observed_callee_status = Some(pb::EffectStatus::Ok as i32);
        let caller = pb::ActorRef {
            kind: "counter".into(),
            key: "a".into(),
        };
        let key = pb::CausalKey {
            root: "r".into(),
            path: vec![],
        };
        let mut turn = pb::TurnRecord {
            actor: Some(caller.clone()),
            causal_key: Some(key.clone()),
            effects: vec![
                call(1, pb::EffectStatus::Ok, false),
                call(2, pb::EffectStatus::Ok, true),
                call(3, pb::EffectStatus::Failed, false),
                withheld,
                call(5, pb::EffectStatus::Timeout, false),
                call(6, pb::EffectStatus::Timeout, false),
                call(7, pb::EffectStatus::Timeout, true),
            ],
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Failed as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        // The callee of ordinal 5 committed, the one of 6 did not.
        let committed_callee = causal::child(&key, &ActorRef::from_pb(&caller), 5);
        let committed = |k: &pb::CausalKey| *k == committed_callee;
        assert_eq!(Acc::orphans(&turn, &committed), BTreeSet::from([1, 4, 5]));
        // A committed turn leaves none.
        turn.outcome = Some(pb::Outcome {
            kind: pb::OutcomeKind::Committed as i32,
            ..Default::default()
        });
        assert!(Acc::orphans(&turn, &committed).is_empty());
    }

    #[test]
    fn json_paths() {
        let mut v = json!({"a": {"b": [{"c": 1, "d": 2}, {"c": 3}]}, "t": 5});
        remove_path(&mut v, &parse_json_path("$.a.b[*].c").unwrap());
        remove_path(&mut v, &parse_json_path("$.t").unwrap());
        assert_eq!(v, json!({"a": {"b": [{"d": 2}, {}]}}));
        assert!(parse_json_path("a.b").is_none());
    }

    #[test]
    fn body_diff_ops() {
        let mut out = Vec::new();
        json_diff(
            "",
            Some(&json!({"n": 1, "a": [1], "x/y": 0})),
            Some(&json!({"n": 2, "a": [1, 2], "z": true})),
            &mut out,
        );
        let ops: Vec<(&str, &str)> = out
            .iter()
            .map(|o| (o.op.as_ref(), o.path.as_str()))
            .collect();
        assert_eq!(
            ops,
            vec![
                ("add", "/a/1"),
                ("replace", "/n"),
                ("remove", "/x~1y"),
                ("add", "/z")
            ]
        );
    }

    #[test]
    fn rounding_and_percentiles() {
        assert_eq!(r6(5.0 / 7.0), 0.714286);
        assert_eq!(r6(0.0000005), 0.0);
        let p = percentiles((1..=100).collect());
        assert_eq!((p.p50, p.p95, p.p99), (50, 95, 99));
    }

    #[test]
    fn code_status_of_a_kind() {
        let a = CodeEntry::new("k", &CodeHash([1; 32]), 0);
        let b = CodeEntry::new("k", &CodeHash([2; 32]), 0);
        assert_eq!(code_status(None, None), "absent");
        assert_eq!(code_status(None, Some(&a)), "new");
        assert_eq!(code_status(Some(&a), Some(&b)), "changed");
        assert_eq!(code_status(Some(&a), Some(&a)), "unchanged");
    }

    /// H12, M3: a redacted value's hash is keyed per subject (not the
    /// plain BLAKE3 a guess could be checked against), its subject a keyed
    /// pseudonym; without the key neither is shown.
    #[test]
    fn redacted_values_hash_keyed_and_hide_the_subject() {
        let master = kronik_privacy::MasterKey::from_bytes([1; 32]).unwrap();
        let ks = kronik_privacy::keystore::Keystore::open_memory(&master).unwrap();
        let keyed = Sealer::new(Arc::new(ks))
            .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master).unwrap());
        let v = redacted(&keyed, "user:9", b"alice");
        let hash = v["hash"].as_str().unwrap();
        assert_eq!(hash.len(), 2 + 16, "{v}");
        assert!(
            !hash.contains(&blake3::hash(b"alice").to_hex()[..16]),
            "{v}"
        );
        assert_ne!(v["hash"], redacted(&keyed, "user:8", b"alice")["hash"]);
        assert_eq!(v, redacted(&keyed, "user:9", b"alice"), "stable");
        assert!(!v.to_string().contains("user:9"), "{v}");
        let mut sql = SqlValue::Text("alice".into());
        redact_sql(&mut sql, &keyed, "user:9");
        let SqlValue::Text(t) = &sql else { panic!() };
        assert!(!t.contains("user:9") && !t.contains("alice"), "{t}");
        let plain = redacted(&Sealer::plain(), "user:9", b"alice");
        assert_eq!(
            plain,
            json!({"redacted": true, "subject": "-", "hash": "-"})
        );
    }

    /// M5: what a `--no-pii` turn that used SQL produced is shown like a
    /// subject's value; other turns are left alone.
    #[test]
    fn sql_turns_show_no_values() {
        let row = || pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(b"ROW-1".to_vec())),
        };
        let turn = |sql| ForkTurn {
            erased: false,
            id: "f:1".into(),
            record: pb::TurnRecord {
                input: Some(pb::Input::default()),
                effects: vec![pb::EffectRecord {
                    request: Some(row()),
                    ..Default::default()
                }],
                outcome: Some(pb::Outcome {
                    message: "ROW-1".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            lsn: 1,
            prod_lsn: None,
            masked: sql,
            pseudonyms: false,
            sql,
            personal: sql,
        };
        let plain = [turn(false)];
        assert!(matches!(sql_tagged(&plain), Cow::Borrowed(_)));
        let tagged = sql_tagged(&[turn(true)]).into_owned();
        let r = &tagged[0].record;
        let shown = sealable_json(&Sealer::plain(), r.effects[0].request.as_ref());
        assert!(!shown.to_string().contains("ROW"), "{shown}");
        assert_eq!(shown["subject"], SQL_CONCEALED);
        assert_eq!(r.outcome.as_ref().unwrap().message, SQL_CONCEALED);
        assert_eq!(r.input, Some(pb::Input::default()), "the input stays");
    }

    /// M24 §7.3-§7.5: a turn's connection operations compare without their
    /// seqs and with `ignore_json_paths`. A `send-now` compares as the frame
    /// it sent, counts as recorded (exact or approximate) or modeled
    /// (synthetic), and never in grounding. A changed frame shows as JSON
    /// pointer operations with the values of its subject redacted.
    #[test]
    fn connection_operations_compare_without_seqs_and_send_now_is_no_grounding() {
        let conn = |n: u8| format!("c-{}", format!("{n:x}").repeat(32));
        let tagged = |b: &[u8]| {
            Some(pb::Sealable {
                subject: Some("user:1".into()),
                value: Some(pb::sealable::Value::Plain(b.to_vec())),
            })
        };
        let send_now = |seq: u64, text: &str, grounding: pb::Grounding| pb::EffectRecord {
            ordinal: 1,
            kind: SEND_NOW.into(),
            target: format!("connection:{}", conn(1)),
            status: pb::EffectStatus::Ok as i32,
            grounding: grounding as i32,
            request: tagged(
                &pb::ConnectionSendRequest {
                    connection: conn(1),
                    seq,
                    kind: pb::frame::Kind::Text as i32,
                    data: text.as_bytes().to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let ops = |seq: u64, data: &str| {
            vec![
                pb::ConnectionOp {
                    connections: vec![conn(1), conn(2)],
                    seqs: vec![seq, seq + 1],
                    op: Some(pb::connection_op::Op::Send(pb::Frame {
                        kind: pb::frame::Kind::Text as i32,
                        data: tagged(data.as_bytes()),
                        ..Default::default()
                    })),
                    dropped: vec![conn(3)],
                },
                pb::ConnectionOp {
                    connections: vec![conn(2)],
                    seqs: vec![],
                    op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
                        code: 4000,
                        reason: tagged(b"kicked"),
                    })),
                    dropped: vec![],
                },
            ]
        };
        let turn = |root: &str, effects, connection_ops| pb::TurnRecord {
            actor: Some(pb::ActorRef {
                kind: "room".into(),
                key: "lobby".into(),
            }),
            causal_key: Some(pb::CausalKey {
                root: root.into(),
                path: vec![],
            }),
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Connection(pb::ConnectionInput {
                    connection: conn(1),
                    protocol: pb::ConnectionProtocol::Websocket as i32,
                    route: "/room/{key}/ws".into(),
                    event: Some(pb::connection_input::Event::Frame(pb::ConnectionFrame {
                        seq: 0,
                        frame: Some(pb::Frame::default()),
                    })),
                    ..Default::default()
                })),
            }),
            effects,
            connection_ops,
            outcome: Some(pb::Outcome {
                kind: pb::OutcomeKind::Committed as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        let fork = |root: &str, record| ForkTurn {
            id: format!("f:r{root}.0"),
            record,
            lsn: 1,
            prod_lsn: None,
            masked: false,
            pseudonyms: false,
            erased: false,
            sql: false,
            personal: false,
        };
        let options = DiffOptions {
            ignore_json_paths: vec!["$.at".into()],
            ..DiffOptions::default()
        };
        let mut acc = Acc::new(&options, Arc::new(Sealer::plain()));

        // The same operations with other seqs and another ignored `at`.
        let prod = turn(
            "1",
            vec![send_now(5, "tok", pb::Grounding::Live)],
            ops(6, r#"{"text":"hi","at":1}"#),
        );
        let same = turn(
            "1",
            vec![send_now(9, "tok", pb::Grounding::Exact)],
            ops(10, r#"{"text":"hi","at":2}"#),
        );
        acc.compare(&[(1, &prod)], &[fork("1", same)], Some(1), true);
        assert!(acc.divergent.is_empty());
        assert_eq!((acc.frames.unchanged, acc.frames.changed), (1, 0));

        // Another format, and a `send-now` the connection model answered.
        let prod = turn(
            "2",
            vec![send_now(5, "tok", pb::Grounding::Live)],
            ops(6, r#"{"text":"hi"}"#),
        );
        let other = turn(
            "2",
            vec![send_now(5, "tok 0", pb::Grounding::Synthetic)],
            ops(6, r#"{"body":"hi"}"#),
        );
        acc.compare(&[(2, &prod)], &[fork("2", other)], Some(2), true);
        assert_eq!(acc.divergent.len(), 1);
        let f = &acc.frames;
        assert_eq!((f.unchanged, f.changed), (1, 1));
        assert_eq!((f.send_now.recorded, f.send_now.modeled), (1, 1));
        // Two live targets of each send, and each `ok` send-now.
        assert_eq!((f.sent.prod, f.sent.fork), (6, 6));
        assert!(acc.grounding.is_empty() && acc.effects.changed == 0);
        let item = &f.items[0];
        assert_eq!(
            (item.root_lsn, item.input.as_str(), item.turn_fork.as_str()),
            (2, "connection frame WEBSOCKET /room/{key}/ws", "f:r2.0")
        );
        let [now, send] = item.frames.as_slice() else {
            panic!("{:?}", item.frames);
        };
        assert_eq!((now.index, now.change.as_ref()), (0, "changed"));
        assert!(now.send_now.as_ref().is_some_and(|s| s.prod && s.fork));
        assert_eq!(now.data.len(), 1);
        assert_eq!(now.data[0].path, "");
        assert_eq!(now.data[0].prod["redacted"], true);
        assert_eq!((send.index, send.targets), (1, 3));
        assert_eq!(send.connections, [conn(1), conn(2), conn(3)]);
        let changes: Vec<(&str, &str, bool, bool)> = send
            .data
            .iter()
            .map(|o| {
                (
                    o.op.as_ref(),
                    o.path.as_str(),
                    o.prod.get("redacted").is_some(),
                    o.fork.get("redacted").is_some(),
                )
            })
            .collect();
        assert_eq!(
            changes,
            [
                ("add", "/body", false, true),
                ("remove", "/text", true, false)
            ]
        );
        assert_eq!(acc.samples.frames_changed, ["f:r2.0"]);
        assert_eq!(
            acc.by_kind["room"].frames.map(|k| (k.unchanged, k.changed)),
            Some((1, 1))
        );
    }
}
