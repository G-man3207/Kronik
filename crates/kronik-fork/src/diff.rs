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
    /// Live GETs from the fork (`[fork] live_allowlist`).
    #[serde(default)]
    pub live: u64,
    /// Fork turns that read a pseudonym or an erased value (`--no-pii`)
    /// and differ from production, and production turns missing below
    /// them: `pii-masked`, not divergent (M8 §9). Always present, so a rule
    /// can read it; diffs of older binaries lack it when 0.
    #[serde(default)]
    pub pii_masked: u64,
    /// Fork turns of a kind whose code changed that read a pseudonym or an
    /// erased value and came out identical to production: they did not
    /// run on the real value either, so they are unverified too (ADR 0031).
    /// Always present; 0 in identity replays.
    #[serde(default)]
    pub pii_unverified: u64,
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
    #[serde(default)]
    pub live: u64,
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
    pub grounding: Cow<'static, str>,
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
    pub effects: Effects,
    pub state: State,
    pub cumulative: Cumulative,
    pub errors: Errors,
    pub resources: Resources,
    pub samples: Samples,
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

fn external(kind: &str) -> bool {
    kind == "http.fetch"
        || kind == "foreign.http"
        || kind.starts_with("crypto.")
        || kind == "secret.reveal"
}

fn grounding_name(g: i32) -> &'static str {
    match pb::Grounding::try_from(g) {
        Ok(pb::Grounding::Exact) => "exact",
        Ok(pb::Grounding::Approximate) => "approximate",
        Ok(pb::Grounding::Synthetic) => "synthetic",
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

fn percentiles(mut v: Vec<u64>) -> Percentiles {
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
    /// Differences of turns that read pseudonyms (`--no-pii`).
    pii_masked: BTreeSet<Vec<u8>>,
    /// Turns that read pseudonyms and came out identical, with their kind.
    pii_same: BTreeMap<Vec<u8>, String>,
    origins: u64,
    consequences: u64,
    causes: BTreeMap<(String, String), CauseAcc>,
    grounding: BTreeMap<(String, String, String, String), [u64; 4]>,
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
}

/// The actor kind of a turn.
fn kind_of(t: &pb::TurnRecord) -> String {
    t.actor.as_ref().map(|a| a.kind.clone()).unwrap_or_default()
}

fn path_prefix(key: &pb::CausalKey, n: usize) -> Vec<u8> {
    causal::encode(&pb::CausalKey {
        root: key.root.clone(),
        path: key.path[..n].to_vec(),
    })
}

impl Acc {
    fn new(opts: &DiffOptions, sealer: Arc<Sealer>) -> Acc {
        Acc {
            norm: Norm::new(opts, sealer),
            divergent: BTreeMap::new(),
            pii_masked: BTreeSet::new(),
            pii_same: BTreeMap::new(),
            origins: 0,
            consequences: 0,
            causes: BTreeMap::new(),
            grounding: BTreeMap::new(),
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
        }
    }

    fn kind(&mut self, kind: String) -> &mut KindReport {
        self.by_kind.entry(kind).or_default()
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

    /// Orphans a failed turn leaves: OK calls without a compensation.
    fn orphans(t: &pb::TurnRecord) -> BTreeSet<u32> {
        if !failed(t) {
            return BTreeSet::new();
        }
        t.effects
            .iter()
            .filter(|e| e.kind == "actor.call" && e.status == pb::EffectStatus::Ok as i32)
            .filter(|e| {
                sealable_bytes(e.request.as_ref())
                    .and_then(|b| pb::CallEffectRequest::decode(b).ok())
                    .is_none_or(|r| r.compensate.is_none())
            })
            .map(|e| e.ordinal)
            .collect()
    }

    /// Errors of one fork turn against its production counterpart (both
    /// modes, deduplicated by causal key).
    fn turn_errors(&mut self, prod: Option<(Lsn, &pb::TurnRecord)>, fork: &ForkTurn) {
        let key = fork
            .record
            .causal_key
            .as_ref()
            .map(causal::encode)
            .unwrap_or_default();
        let f = &fork.record;
        // A turn that read pseudonyms did not run on real data: how it
        // differs from production (failing included) is `pii-masked`, not
        // an error of the code. SQL turns ran on real rows and count.
        match (prod, fork.pseudonyms) {
            (_, true) => {}
            (Some((lsn, p)), false) => {
                if failed(f) && !failed(p) {
                    self.error("introduced", key.clone(), f, Some(lsn), Some(&fork.id));
                } else if !failed(f) && failed(p) {
                    self.error("fixed", key.clone(), p, Some(lsn), Some(&fork.id));
                }
                if !Self::orphans(f).is_subset(&Self::orphans(p)) {
                    self.error("new_orphan", key.clone(), f, Some(lsn), Some(&fork.id));
                }
            }
            (None, false) => {
                if failed(f) {
                    self.error("introduced", key.clone(), f, None, Some(&fork.id));
                }
                if !Self::orphans(f).is_empty() {
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
        match change {
            "added" => self.effects.added += 1,
            "removed" => self.effects.removed += 1,
            _ => self.effects.changed += 1,
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
            turn_prod: turn_prod.map(prod_id),
            turn_fork: turn_fork.map(str::to_owned),
            fields: effect_fields(&self.norm.sealer, p, f),
        });
    }

    /// External effect differences of one turn pair.
    fn turn_effects(&mut self, prod: Option<(Lsn, &pb::TurnRecord)>, fork: Option<&ForkTurn>) {
        let pe: BTreeMap<u32, &pb::EffectRecord> = prod
            .iter()
            .flat_map(|(_, t)| t.effects.iter())
            .filter(|e| external(&e.kind))
            .map(|e| (e.ordinal, e))
            .collect();
        let fe: BTreeMap<u32, &pb::EffectRecord> = fork
            .iter()
            .flat_map(|t| t.record.effects.iter())
            .filter(|e| external(&e.kind))
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
                        2
                    }
                    // Live and not denied by configuration: a live GET.
                    Ok(pb::Grounding::Live) if e.status != pb::EffectStatus::Denied as i32 => 3,
                    _ => continue,
                };
                self.grounding.entry(target(e)).or_insert([0; 4])[slot] += 1;
            }
            if synthetic {
                push_capped(&mut self.samples.synthetic, MAX_SAMPLES, f.id.clone());
            }
        }
    }

    fn response(&mut self, root_lsn: Lsn, prod: (Lsn, &pb::TurnRecord), fork: Option<&ForkTurn>) {
        let Some(pb::input::Kind::Http(h)) = prod.1.input.as_ref().and_then(|i| i.kind.as_ref())
        else {
            return;
        };
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
        let mut changes: BTreeMap<Vec<u8>, Change<'a>> = BTreeMap::new();
        for f in fork {
            let Some(key) = f.record.causal_key.as_ref().map(causal::encode) else {
                continue;
            };
            let p = pmap.get(&key).copied();
            self.turn_errors(p, f);
            match p {
                Some(p) => {
                    if full {
                        self.fuel.0.push(p.1.fuel_used);
                        self.fuel.1.push(f.record.fuel_used);
                        self.memory.0.push(p.1.memory_peak_bytes);
                        self.memory.1.push(f.record.memory_peak_bytes);
                        self.turn_effects(Some(p), Some(f));
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
                    if full {
                        self.turn_effects(None, Some(f));
                    }
                    changes.insert(key, Change::New { fork: f });
                }
            }
        }
        for (key, p) in &pmap {
            if !fmap.contains_key(key) {
                if full {
                    self.turn_effects(Some(*p), None);
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
        for (key, change) in &changes {
            let masked = match change {
                Change::Changed { fork, .. } | Change::New { fork } => fork.masked,
                Change::Missing { .. } => unverified.contains(key),
            };
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
            }
        }
        if !full {
            return;
        }
        // Responses of the HTTP root inputs.
        for (key, p) in &pmap {
            let is_root = p.1.causal_key.as_ref().is_some_and(|k| k.path.is_empty());
            if is_root {
                self.response(root_lsn.unwrap_or(p.0), *p, fmap.get(key).copied());
            }
        }
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
                ) && !unverified.contains(*k)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for (key, c) in &changes {
            if unverified.contains(key) {
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
        let (pw, pr) = collect(prod.iter().map(|(_, t)| *t), &sealer);
        let (fw, fr) = collect(fork.iter().map(|f| &f.record), &sealer);
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

/// Each actor's final state in the fork store against production's.
fn continuous_state(
    fork: &Store,
    prod: &Store,
    sealer: &Sealer,
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
    let roots: BTreeMap<Lsn, &RootInput> = index.roots.iter().map(|r| (r.lsn, r)).collect();
    let mut replayed = 0u64;
    if let Some(trees) = input.isolated {
        for t in trees {
            let Some(root) = roots.get(&t.root_lsn) else {
                continue;
            };
            replayed += 1;
            let prod = index.tree(root);
            acc.compare(&prod, &sql_tagged(&t.turns), Some(t.root_lsn), true);
        }
    }
    let mut state_continuous = Vec::new();
    if let Some(c) = &input.continuous {
        let prod: Vec<(Lsn, &pb::TurnRecord)> = index
            .records
            .iter()
            .filter(|r| r.lsn > index.fork_lsn)
            .filter_map(|r| match &r.record {
                Record::TurnRecord(t) => Some((r.lsn, t)),
                _ => None,
            })
            .collect();
        let full = input.isolated.is_none();
        if full {
            replayed = index.roots.len() as u64;
        }
        acc.compare(&prod, &sql_tagged(c.turns), None, full);
        state_continuous = continuous_state(c.fork, c.prod, &index.sealer)?;
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
    let grounding: Vec<GroundingRow> = acc
        .grounding
        .into_iter()
        .map(|((kind, method, host, route), [e, a, s, l])| GroundingRow {
            kind,
            method,
            host,
            route,
            exact: e,
            approximate: a,
            synthetic: s,
            live: l,
            confidence: r6(e as f64 / (e + a + s + l).max(1) as f64),
        })
        .collect();
    let (exact, approximate, synthetic, live) =
        grounding.iter().fold((0, 0, 0, 0), |(e, a, s, l), g| {
            (e + g.exact, a + g.approximate, s + g.synthetic, l + g.live)
        });
    let total = exact + approximate + synthetic + live;
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
    let changed = !acc.divergent.is_empty()
        || !acc.pii_masked.is_empty()
        || acc.responses.changed > 0
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
        origins: acc.origins,
        consequences: acc.consequences,
        exact,
        approximate,
        synthetic,
        live,
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
        options: input.options.clone(),
        summary,
        kinds,
        causes,
        grounding,
        responses: acc.responses,
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
        samples: acc.samples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let master = kronik_privacy::MasterKey::from_bytes([1; 32]);
        let ks = kronik_privacy::keystore::Keystore::open(
            rusqlite::Connection::open_in_memory().unwrap(),
            &master,
        )
        .unwrap();
        let keyed = Sealer::new(Arc::new(ks))
            .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master));
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
}
