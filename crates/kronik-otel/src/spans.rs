//! Committed turn records as OTLP spans (docs/design/m28-otel.md §3, ADRs
//! 0080 and 0082).
//!
//! Every id and time is a function of the records and the node's id key
//! alone, so any exporter on the node (a restarted one, a rewound one)
//! sends the same spans. Only what ADR 0082 allows leaves: no sealable
//! value, no `Outcome.message` or `EffectRecord.error`, no path or query,
//! no subject. The caller hashes actor keys and supplies the id key.

use std::collections::{BTreeMap, HashMap};

use kronik_core::causal;
use kronik_core::ids::{ActorRef, hex};
use kronik_proto::log::v1 as pb;

use crate::otlp::collector::trace::v1::ExportTraceServiceRequest;
use crate::otlp::common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value};
use crate::otlp::resource::v1::Resource as OtlpResource;
use crate::otlp::trace::v1::{ResourceSpans, ScopeSpans, Span, Status, span, status};

/// A span in a trace: what a parent or a link names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpanRef {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
}

/// The key of every exported id but a root's trace id (review P1): the ids
/// derive from the causal key, which holds every step's actor key in plain,
/// so unkeyed they would let a backend confirm a guessed key.
/// [`crate::keys::KeyHasher::id_key`] derives it as the `kh:` labels are.
#[derive(Clone, Copy)]
pub struct IdKey(pub [u8; 32]);

impl std::fmt::Debug for IdKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdKey(..)")
    }
}

/// The purpose under which [`IdKey`] is derived.
pub const ID_KEY_PURPOSE: &str = "kronik otel ids v1";

fn digest<const N: usize>(mut h: blake3::Hasher, parts: &[&[u8]]) -> [u8; N] {
    for p in parts {
        h.update(p);
    }
    let mut out = [0; N];
    out.copy_from_slice(&h.finalize().as_bytes()[..N]);
    out
}

fn keyed<const N: usize>(ids: &IdKey, parts: &[&[u8]]) -> [u8; N] {
    digest(blake3::Hasher::new_keyed(&ids.0), parts)
}

/// `N` bytes from exactly `2N` lowercase hex characters.
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The trace id of a causal root: its 16 bytes, or for a root that is not
/// 32 lowercase hex characters (only tests make those) 16 bytes of
/// `blake3("kronik trace v1" ‖ root)`.
pub fn trace_id(root: &str) -> [u8; 16] {
    unhex(root).unwrap_or_else(|| {
        digest(
            blake3::Hasher::new(),
            &[b"kronik trace v1", root.as_bytes()],
        )
    })
}

/// The trace a turn starts that is not a root's: 16 bytes of
/// `blake3_keyed(ids, "kronik trace v1" ‖ encode(key))`. Timers and sends
/// start new traces (review M1), so that a timer that reschedules itself,
/// or two actors messaging each other, do not grow one trace for their
/// lifetime.
pub fn new_trace_id(ids: &IdKey, key: &pb::CausalKey) -> [u8; 16] {
    keyed(ids, &[b"kronik trace v1", &causal::encode(key)])
}

/// What a turn's own ids derive from: `encode(key)`, and for a migrate turn
/// also `u32_le(to_schema_version)`. One input migrates twice under one key
/// when a code switch lands during its first migration, and the two
/// migrate turns must not share their ids.
fn id_bytes(key: &pb::CausalKey, input: Option<&pb::Input>) -> Vec<u8> {
    let mut ids = causal::encode(key);
    if let Some(pb::input::Kind::Migrate(m)) = input.and_then(|i| i.kind.as_ref()) {
        ids.extend_from_slice(&m.to_schema_version.to_le_bytes());
    }
    ids
}

/// [`new_trace_id`] of the turn with `input`: a migrate turn's includes the
/// schema version it migrates to.
pub fn started_trace_id(ids: &IdKey, key: &pb::CausalKey, input: Option<&pb::Input>) -> [u8; 16] {
    keyed(ids, &[b"kronik trace v1", &id_bytes(key, input)])
}

/// [`turn_span_id`] of the turn with `input`: a migrate turn's includes the
/// schema version it migrates to. Nothing names a migrate turn by its key
/// alone: it produces no turns.
pub fn own_span_id(ids: &IdKey, key: &pb::CausalKey, input: Option<&pb::Input>) -> [u8; 8] {
    keyed(ids, &[b"kronik span v1", &id_bytes(key, input)])
}

/// The producing turn's key: the path minus its last step.
fn parent(key: &pb::CausalKey) -> Option<pb::CausalKey> {
    let (_, up) = key.path.split_last()?;
    Some(pb::CausalKey {
        root: key.root.clone(),
        path: up.to_vec(),
    })
}

/// Whether the input continues the turn its key's parent names (a call, a
/// compensation, a migrate) when that turn is open.
fn joins_parent(input: Option<&pb::Input>) -> bool {
    use pb::input::Kind;
    match input.and_then(|i| i.kind.as_ref()) {
        Some(Kind::Migrate(_)) => true,
        Some(Kind::Message(m)) => matches!(
            pb::MessageSource::try_from(m.source),
            Ok(pb::MessageSource::Call | pb::MessageSource::Compensation)
        ),
        _ => false,
    }
}

/// The traces of begun, uncommitted turns (§3.1), which their callees
/// join. The causal key does not say whether an ancestor started a trace,
/// so the exporter records each turn's trace from its `TurnBegin` and
/// drops it once the `TurnRecord` is exported. A call is synchronous, so a
/// caller (which writes `TurnBegin` before its call) is open when its
/// callee's record arrives; the set is bounded by the turns in flight.
///
/// A committed turn stays, as kept, while turns still to come name it
/// (review M7): a callee that joined its caller's trace, for the links of
/// its messages, timers and a compensation, and a caller whose call timed
/// out, for its late callee to join. Other committed turns are named
/// right by their keys alone.
#[derive(Debug, Clone)]
pub struct OpenTurns {
    ids: IdKey,
    traces: HashMap<Vec<u8>, [u8; 16]>,
    kept: HashMap<Vec<u8>, Kept>,
    /// The kept turns' keys by `Kept::seq`, oldest first.
    order: BTreeMap<u64, Vec<u8>>,
    next: u64,
}

#[derive(Debug, Clone)]
struct Kept {
    trace: [u8; 16],
    /// The last step's ordinal of each turn still to come that this one
    /// produced, and whether that turn joins this trace (only a timed-out
    /// call's callee does).
    children: Vec<(u32, bool)>,
    /// A callee whose caller has not committed: a failed caller sends it
    /// a compensation, which links to it.
    caller: bool,
    seq: u64,
}

impl OpenTurns {
    /// shortcut: past this many open turns new ones are not recorded (the
    /// exporter warns), so their callees start traces of their own; past
    /// this many kept turns the oldest is dropped (a cancelled timer never
    /// comes), and what names it falls back to the trace its key starts.
    /// Raise it or spill to disk if a node ever runs that many turns at once.
    pub const CAP: usize = 100_000;

    /// An empty set whose turns' ids are keyed with `ids`.
    pub fn new(ids: IdKey) -> OpenTurns {
        OpenTurns {
            ids,
            traces: HashMap::new(),
            kept: HashMap::new(),
            order: BTreeMap::new(),
            next: 0,
        }
    }

    /// The key of the ids of the turns in this set.
    pub fn ids(&self) -> &IdKey {
        &self.ids
    }

    fn get(&self, key: &[u8]) -> Option<[u8; 16]> {
        self.traces
            .get(key)
            .copied()
            .or_else(|| self.kept.get(key).map(|e| e.trace))
    }

    /// The trace of the turn `key` with `input`: its entry while open or
    /// kept, else where its input places it.
    pub fn trace(&self, key: &pb::CausalKey, input: Option<&pb::Input>) -> [u8; 16] {
        self.get(&causal::encode(key))
            .unwrap_or_else(|| self.place(key, input))
    }

    /// The trace of the turn that produced `key` when a turn `key` that
    /// joins its producer would join it: while the producer is open, or
    /// once it committed if it waits for `key` as a timed-out call's
    /// callee.
    fn producer(&self, key: &pb::CausalKey) -> Option<[u8; 16]> {
        let step = key.path.last()?;
        let up = causal::encode(&parent(key)?);
        self.traces.get(&up).copied().or_else(|| {
            self.kept
                .get(&up)
                .filter(|e| e.children.contains(&(step.ordinal, true)))
                .map(|e| e.trace)
        })
    }

    /// A root's trace is its own; a call, compensation or migrate joins
    /// the turn its key names while that is open (a call also once its
    /// caller timed out on it); every other turn (and those whose turn is
    /// gone) starts a new trace.
    fn place(&self, key: &pb::CausalKey, input: Option<&pb::Input>) -> [u8; 16] {
        if key.path.is_empty() {
            return trace_id(&key.root);
        }
        joins_parent(input)
            .then(|| self.producer(key))
            .flatten()
            .unwrap_or_else(|| started_trace_id(&self.ids, key, input))
    }

    /// Records a begun turn's trace. False, and nothing recorded, past
    /// [`OpenTurns::CAP`].
    pub fn begin(&mut self, key: &pb::CausalKey, input: Option<&pb::Input>) -> bool {
        let k = causal::encode(key);
        if self.traces.contains_key(&k) {
            return true;
        }
        if self.traces.len() >= Self::CAP {
            return false;
        }
        let trace = self.place(key, input);
        self.traces.insert(k, trace);
        true
    }

    /// The turn `r` committed and its spans were mapped: it leaves the open
    /// set, and is kept while turns still to come name it.
    pub fn commit(&mut self, r: &pb::TurnRecord) {
        use pb::input::Kind;
        let Some(key) = r.causal_key.as_ref() else {
            return;
        };
        let input = r.input.as_ref();
        let k = causal::encode(key);
        let trace = self.trace(key, input);
        self.traces.remove(&k);
        let up = parent(key).map(|p| causal::encode(&p));
        // A turn its producer waited for came.
        if let (Some(up), Some(step)) = (&up, key.path.last()) {
            self.settle(up, |e| {
                if let Some(i) = e.children.iter().position(|c| c.0 == step.ordinal) {
                    e.children.swap_remove(i);
                }
            });
        }
        let mut children = Vec::new();
        let actor = r.actor.as_ref().map(ActorRef::from_pb);
        for e in r.effects.iter().filter(|e| e.kind == "actor.call") {
            let Some(actor) = &actor else { break };
            let callee = causal::encode(&causal::child(key, actor, e.ordinal));
            if self.kept.contains_key(&callee) {
                // Its caller is done: a compensation comes when it failed.
                let compensated = r.compensations.iter().any(|m| m.ordinal == e.ordinal);
                self.settle(&callee, |c| {
                    c.caller = false;
                    if compensated {
                        c.children.push((causal::COMPENSATION_ORDINAL, false));
                    }
                });
            } else if e.status == pb::EffectStatus::Timeout as i32
                && !self.traces.contains_key(&callee)
            {
                // The callee still runs, after its caller (review Low).
                children.push((e.ordinal, true));
            }
        }
        // A turn that started its trace, or a root, is named right by its
        // key; one that joined another's trace is kept for what it sent.
        let joined = !key.path.is_empty() && trace != started_trace_id(&self.ids, key, input);
        let mut caller = false;
        if joined {
            children.extend(r.messages.iter().map(|m| (m.ordinal, false)));
            children.extend(
                r.timers
                    .iter()
                    .filter(|t| t.kind == pb::TimerOpKind::Schedule as i32)
                    .map(|t| (t.ordinal, false)),
            );
            let call = matches!(
                input.and_then(|i| i.kind.as_ref()),
                Some(Kind::Message(m)) if m.source == pb::MessageSource::Call as i32
            );
            caller = call && up.as_ref().is_some_and(|u| self.traces.contains_key(u));
        }
        if !children.is_empty() || caller {
            self.keep(k, trace, children, caller);
        }
    }

    fn keep(&mut self, k: Vec<u8>, trace: [u8; 16], children: Vec<(u32, bool)>, caller: bool) {
        let seq = self.next;
        self.next += 1;
        if let Some(old) = self.kept.insert(
            k.clone(),
            Kept {
                trace,
                children,
                caller,
                seq,
            },
        ) {
            self.order.remove(&old.seq);
        }
        self.order.insert(seq, k);
        while self.kept.len() > Self::CAP {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.kept.remove(&oldest);
        }
    }

    /// Changes a kept turn, which leaves once nothing to come names it.
    fn settle(&mut self, k: &[u8], f: impl FnOnce(&mut Kept)) {
        let Some(e) = self.kept.get_mut(k) else {
            return;
        };
        f(e);
        if e.children.is_empty() && !e.caller {
            let seq = e.seq;
            self.kept.remove(k);
            self.order.remove(&seq);
        }
    }

    /// The open turns (kept ones not counted).
    pub fn len(&self) -> usize {
        self.traces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.traces.is_empty()
    }

    /// The committed turns kept for what is still to come.
    pub fn kept(&self) -> usize {
        self.kept.len()
    }

    /// The trace of a turn a link names, without its record: its entry
    /// while open or kept, else the one its key gives (the root's, its
    /// open caller's, or the trace it started). Also the trace a migrate
    /// turn's input will have: a migration runs before its input begins.
    fn linked(&self, key: &pb::CausalKey) -> [u8; 16] {
        self.get(&causal::encode(key)).unwrap_or_else(|| {
            if key.path.is_empty() {
                trace_id(&key.root)
            } else {
                // Only a call (or what joins like one) can come from an open
                // turn: messages and timers are sent once it committed.
                self.producer(key)
                    .unwrap_or_else(|| new_trace_id(&self.ids, key))
            }
        })
    }

    /// The set as the trace stream's cursor state: `{"open": [[key hex,
    /// trace hex], …] sorted, "kept": [[key hex, trace hex, [[ordinal,
    /// joins], …], caller], …] oldest first}`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut open: Vec<(String, String)> =
            self.traces.iter().map(|(k, t)| (hex(k), hex(t))).collect();
        open.sort();
        let kept: Vec<_> = self
            .order
            .values()
            .filter_map(|k| {
                let e = self.kept.get(k)?;
                Some((hex(k), hex(&e.trace), &e.children, e.caller))
            })
            .collect();
        serde_json::json!({ "open": open, "kept": kept })
    }

    /// The set from [`OpenTurns::to_json`], or from the open pairs alone
    /// that came before kept turns; what does not parse is left out.
    pub fn from_json(v: &serde_json::Value, ids: IdKey) -> OpenTurns {
        let open = v.get("open").unwrap_or(v);
        let pairs: Vec<(String, String)> = serde_json::from_value(open.clone()).unwrap_or_default();
        type KeptJson = Vec<(String, String, Vec<(u32, bool)>, bool)>;
        let kept: KeptJson = v
            .get("kept")
            .and_then(|k| serde_json::from_value(k.clone()).ok())
            .unwrap_or_default();
        let mut out = OpenTurns {
            traces: pairs
                .iter()
                .filter_map(|(k, t)| Some((unhex_vec(k)?, unhex(t)?)))
                .collect(),
            ..OpenTurns::new(ids)
        };
        for (k, t, children, caller) in kept {
            if let (Some(k), Some(t)) = (unhex_vec(&k), unhex(&t)) {
                out.keep(k, t, children, caller);
            }
        }
        out
    }
}

fn unhex_vec(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// A turn's span id: 8 bytes of `blake3_keyed(ids, "kronik span v1" ‖
/// encode(key))`.
pub fn turn_span_id(ids: &IdKey, key: &pb::CausalKey) -> [u8; 8] {
    keyed(ids, &[b"kronik span v1", &causal::encode(key)])
}

/// An effect's span id: 8 bytes of `blake3_keyed(ids, "kronik effect span
/// v1" ‖ encode(key) ‖ u32_le(ordinal))`. A callee names its caller's call
/// effect span with it, without a lookup.
pub fn effect_span_id(ids: &IdKey, key: &pb::CausalKey, ordinal: u32) -> [u8; 8] {
    effect_id(ids, &causal::encode(key), ordinal)
}

/// [`effect_span_id`] from a turn's id bytes ([`id_bytes`]).
fn effect_id(ids: &IdKey, bytes: &[u8], ordinal: u32) -> [u8; 8] {
    keyed(
        ids,
        &[b"kronik effect span v1", bytes, &ordinal.to_le_bytes()],
    )
}

/// A W3C `traceparent` value, strictly: version `00`, lowercase hex,
/// non-zero ids, nothing else. Only the two ids are kept.
pub fn parse_traceparent(value: &str) -> Option<SpanRef> {
    let mut parts = value.split('-');
    let (version, trace, parent, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || version != "00" || unhex::<1>(flags).is_none() {
        return None;
    }
    let r = SpanRef {
        trace_id: unhex(trace)?,
        span_id: unhex(parent)?,
    };
    (r.trace_id != [0; 16] && r.span_id != [0; 8]).then_some(r)
}

/// The incoming trace context of an HTTP input: its one plain
/// `traceparent` header. A sealed one counts only once the caller has
/// unsealed the input; two headers are ambiguous and count as none.
pub fn traceparent_of(input: &pb::Input) -> Option<SpanRef> {
    let Some(pb::input::Kind::Http(h)) = &input.kind else {
        return None;
    };
    let mut found = h
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("traceparent"));
    let header = found.next()?;
    if found.next().is_some() {
        return None;
    }
    match header.value.as_ref()?.value.as_ref()? {
        pb::sealable::Value::Plain(b) => parse_traceparent(std::str::from_utf8(b).ok()?),
        pb::sealable::Value::Sealed(_) => None,
    }
}

/// The purpose of the keyed hash of `[kind, key]` behind a hashed actor key.
pub const KEY_HASH_PURPOSE: &str = "kronik otel key v1";

/// A hashed actor key as exported: `kh:` + 12 hex of the keyed hash.
pub fn key_label(keyed_hash: &[u8; 32]) -> String {
    format!("kh:{}", hex(&keyed_hash[..6]))
}

/// How actor keys leave the node (`[otel] actor_keys`, §3.5).
pub enum ActorKeys<'a> {
    /// Through the caller's keyed hasher of `(kind, key)` ([`key_label`]).
    Hashed(&'a dyn Fn(&str, &str) -> String),
    Plain,
    /// `"none"`: never exported.
    Omit,
}

impl ActorKeys<'_> {
    /// The key as exported, or None for `"none"`.
    pub fn export(&self, kind: &str, key: &str) -> Option<String> {
        match self {
            ActorKeys::Hashed(f) => Some(f(kind, key)),
            ActorKeys::Plain => Some(key.to_owned()),
            ActorKeys::Omit => None,
        }
    }
}

/// A committed turn and what its spans need from outside the record.
pub struct Turn<'a> {
    pub record: &'a pb::TurnRecord,
    pub lsn: u64,
    pub branch: &'a str,
    /// The exporter's open turns, this turn's own entry included while its
    /// record is mapped.
    pub open: &'a OpenTurns,
    /// For a resend: the dead-lettered turn's span ([`turn_ref`] of the
    /// record its `resend_of` names).
    pub resend_of: Option<SpanRef>,
}

/// A turn's span, as a parent or link target.
pub fn turn_ref(record: &pb::TurnRecord, open: &OpenTurns) -> SpanRef {
    let empty = pb::CausalKey::default();
    let key = record.causal_key.as_ref().unwrap_or(&empty);
    SpanRef {
        trace_id: open.trace(key, record.input.as_ref()),
        span_id: own_span_id(&open.ids, key, record.input.as_ref()),
    }
}

fn kv(key: &str, value: any_value::Value) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue { value: Some(value) }),
    }
}

fn s(key: &str, value: impl Into<String>) -> KeyValue {
    kv(key, any_value::Value::StringValue(value.into()))
}

fn int(key: &str, value: impl TryInto<i64>) -> KeyValue {
    kv(
        key,
        any_value::Value::IntValue(value.try_into().unwrap_or(i64::MAX)),
    )
}

/// `OUTCOME_KIND_FUEL_EXHAUSTED` → `fuel_exhausted`.
fn label(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn error(message: impl Into<String>) -> Option<Status> {
    Some(Status {
        message: message.into(),
        code: status::StatusCode::Error as i32,
    })
}

/// The span that caused a turn, and the `kronik.link` naming how.
type Link = Option<(SpanRef, &'static str)>;

/// The parent span id (in the turn's own trace), the link and the span kind
/// of a turn (§3.2), whose span is `me`.
fn cause(turn: &Turn, key: &pb::CausalKey, me: SpanRef) -> (Option<[u8; 8]>, Link, span::SpanKind) {
    use pb::input::Kind;
    use span::SpanKind;
    // A turn that is not a root joined its parent's trace exactly when it
    // did not start one: no other turn's trace is derived from its key.
    let ids = &turn.open.ids;
    let joined = !key.path.is_empty()
        && me.trace_id != started_trace_id(ids, key, turn.record.input.as_ref());
    // The producing turn's turn span, or with an ordinal its effect span,
    // in this trace when joined, else in the producing turn's.
    let up = parent(key);
    let up_ref = |effect: Option<u32>| {
        up.as_ref().map(|k| SpanRef {
            trace_id: if joined {
                me.trace_id
            } else {
                turn.open.linked(k)
            },
            span_id: effect.map_or_else(|| turn_span_id(ids, k), |o| effect_span_id(ids, k, o)),
        })
    };
    let (link, name, kind) = match turn.record.input.as_ref().and_then(|i| i.kind.as_ref()) {
        // An incoming traceparent is a link, never the parent: the trace
        // stays the causal root's, which every turn under it can compute.
        Some(Kind::Http(_)) => {
            let incoming = turn
                .record
                .input
                .as_ref()
                .and_then(traceparent_of)
                .filter(|_| key.path.is_empty());
            return (None, incoming.map(|t| (t, "traceparent")), SpanKind::Server);
        }
        // The input turn runs after its migrate turn: a link only.
        Some(Kind::Migrate(_)) => {
            return (
                None,
                up_ref(None).map(|l| (l, "migrate")),
                SpanKind::Internal,
            );
        }
        // A new trace, linked to the scheduling turn in its own.
        Some(Kind::Timer(_)) => {
            return (None, up_ref(None).map(|l| (l, "timer")), SpanKind::Internal);
        }
        Some(Kind::Message(m)) => match pb::MessageSource::try_from(m.source) {
            // The last step's ordinal is the caller's call effect ordinal.
            Ok(pb::MessageSource::Call) => (
                up_ref(key.path.last().map(|step| step.ordinal)),
                "call",
                SpanKind::Server,
            ),
            // A new trace, linked to the sender's turn in its own.
            Ok(pb::MessageSource::Actor) => {
                return (
                    None,
                    up_ref(None).map(|l| (l, "message")),
                    SpanKind::Consumer,
                );
            }
            // The key is the callee's call turn key plus a step, so that
            // turn is the parent while it is open.
            Ok(pb::MessageSource::Compensation) => {
                (up_ref(None), "compensation", SpanKind::Internal)
            }
            // Operator sends and resends are roots; a resend links to the
            // dead-lettered turn, in that turn's trace.
            _ => {
                let link = turn.resend_of.filter(|_| !m.resend_of.is_empty());
                return (None, link.map(|l| (l, "resend")), SpanKind::Internal);
            }
        },
        None => return (None, None, SpanKind::Internal),
    };
    let parent = link.filter(|_| joined).map(|p| p.span_id);
    (parent, link.map(|p| (p, name)), kind)
}

fn effect_span(
    e: &pb::EffectRecord,
    id_key: &IdKey,
    ids: &[u8],
    turn: SpanRef,
    turn_start: u64,
    keys: &ActorKeys,
) -> Span {
    // Records from before offset_us start at the turn's start.
    let start = turn_start.saturating_add(e.offset_us.saturating_mul(1_000));
    let status = pb::EffectStatus::try_from(e.status).unwrap_or(pb::EffectStatus::Unspecified);
    let status_label = label(status.as_str_name(), "EFFECT_STATUS_");
    let grounding = pb::Grounding::try_from(e.grounding).unwrap_or(pb::Grounding::Unspecified);
    let mut a = vec![
        s("kronik.effect.kind", &e.kind),
        int("kronik.effect.ordinal", e.ordinal),
        s("kronik.effect.status", &status_label),
        s(
            "kronik.effect.grounding",
            label(grounding.as_str_name(), "GROUNDING_"),
        ),
    ];
    if !e.delivery.is_empty() {
        a.push(s("kronik.effect.delivery", &e.delivery));
    }
    if let Some((kind, rest)) = e.target.split_once(':') {
        a.push(s("kronik.effect.target", kind));
        match kind {
            "http" | "foreign" => a.push(s("server.address", rest)),
            "actor" => {
                let (k, key) = rest.split_once('/').unwrap_or((rest, ""));
                a.push(s("kronik.target.actor.kind", k));
                if let Some(key) = keys.export(k, key) {
                    a.push(s("kronik.target.actor.key", key));
                }
            }
            "secret" | "secret-reveal" => a.push(s("kronik.secret.name", rest)),
            _ => {}
        }
    }
    use pb::EffectStatus as S;
    let failed = matches!(
        status,
        S::Failed | S::Network | S::Timeout | S::OutcomeUnknown
    );
    Span {
        trace_id: turn.trace_id.to_vec(),
        span_id: effect_id(id_key, ids, e.ordinal).to_vec(),
        parent_span_id: turn.span_id.to_vec(),
        name: e.kind.clone(),
        kind: span::SpanKind::Client as i32,
        start_time_unix_nano: start,
        end_time_unix_nano: start.saturating_add(e.duration_us.saturating_mul(1_000)),
        attributes: a,
        status: if failed { error(status_label) } else { None },
        ..Default::default()
    }
}

/// The turn's span and one child span per effect, each effect inside the
/// turn.
pub fn spans(turn: &Turn, keys: &ActorKeys) -> Vec<Span> {
    use pb::input::Kind;
    let r = turn.record;
    let empty = pb::CausalKey::default();
    let key = r.causal_key.as_ref().unwrap_or(&empty);
    let me = turn_ref(r, turn.open);
    let start = r.logical_time_ms.saturating_mul(1_000_000);
    let mut out = Vec::with_capacity(1 + r.effects.len());
    // The turn's own duration (M11's TurnRecord.duration_us); records from
    // before it end with their last effect, else 1 µs after the start.
    let mut end = start.saturating_add(r.duration_us.max(1).saturating_mul(1_000));
    let ids = id_bytes(key, r.input.as_ref());
    for e in &r.effects {
        let span = effect_span(e, &turn.open.ids, &ids, me, start, keys);
        end = end.max(span.end_time_unix_nano);
        out.push(span);
    }
    let (parent, link, kind) = cause(turn, key, me);
    let (actor_kind, actor_key) = r
        .actor
        .as_ref()
        .map_or(("", ""), |a| (a.kind.as_str(), a.key.as_str()));
    let mut a = vec![
        s("kronik.turn_id", format!("{}:{}", turn.branch, turn.lsn)),
        s("kronik.actor.kind", actor_kind),
    ];
    if let Some(k) = keys.export(actor_kind, actor_key) {
        a.push(s("kronik.actor.key", k));
    }
    let source = |m: &pb::MessageInput| {
        let s = pb::MessageSource::try_from(m.source).unwrap_or(pb::MessageSource::Unspecified);
        label(s.as_str_name(), "MESSAGE_SOURCE_")
    };
    let msg_name = |m: &Option<pb::Message>| m.as_ref().map_or("", |m| m.name.as_str()).to_owned();
    // Only the method and the route pattern of an HTTP input: never its
    // path, query, headers or body.
    let input = match r.input.as_ref().and_then(|i| i.kind.as_ref()) {
        Some(Kind::Http(h)) => {
            a.push(s("kronik.input", "http"));
            a.push(s("http.request.method", &h.method));
            a.push(s("http.route", &h.route));
            format!("{} {}", h.method, h.route)
        }
        Some(Kind::Message(m)) => {
            let name = msg_name(&m.msg);
            a.push(s("kronik.input", "message"));
            a.push(s("kronik.message.name", &name));
            a.push(s("kronik.message.source", source(m)));
            format!("message {name}")
        }
        Some(Kind::Timer(t)) => {
            let name = msg_name(&t.msg);
            a.push(s("kronik.input", "timer"));
            a.push(s("kronik.message.name", &name));
            format!("timer {name}")
        }
        Some(Kind::Migrate(_)) => {
            a.push(s("kronik.input", "migrate"));
            "migrate".into()
        }
        None => "turn".into(),
    };
    let outcome = r.outcome.clone().unwrap_or_default();
    let outcome_kind =
        pb::OutcomeKind::try_from(outcome.kind).unwrap_or(pb::OutcomeKind::Unspecified);
    a.push(s(
        "kronik.outcome",
        label(outcome_kind.as_str_name(), "OUTCOME_KIND_"),
    ));
    if !outcome.error_code.is_empty() {
        a.push(s("kronik.error_code", &outcome.error_code));
    }
    if let Some(pb::outcome::Output::Http(h)) = &outcome.output {
        a.push(int("http.response.status_code", h.status));
    }
    a.push(s("kronik.code_hash", format!("b3:{}", hex(&r.code_hash))));
    a.push(int("kronik.config_epoch", r.config_epoch));
    a.push(int("kronik.fuel_used", r.fuel_used));
    // The error code only: Outcome.message is guest text (ADR 0082).
    let status = (outcome_kind != pb::OutcomeKind::Committed).then(|| error(&outcome.error_code));
    out.insert(
        0,
        Span {
            trace_id: me.trace_id.to_vec(),
            span_id: me.span_id.to_vec(),
            parent_span_id: parent.map_or_else(Vec::new, |p| p.to_vec()),
            name: format!("{actor_kind} {input}"),
            kind: kind as i32,
            start_time_unix_nano: start,
            end_time_unix_nano: end,
            attributes: a,
            links: link
                .map(|(to, name)| {
                    let mut attributes = vec![s("kronik.link", name)];
                    // Jaeger (and the Collector's Jaeger translator) merges a link
                    // to the parent into the parent reference and types it
                    // FOLLOWS_FROM unless the link says otherwise.
                    if to.trace_id == me.trace_id && Some(to.span_id) == parent {
                        attributes.push(s("opentracing.ref_type", "child_of"));
                    }
                    span::Link {
                        trace_id: to.trace_id.to_vec(),
                        span_id: to.span_id.to_vec(),
                        attributes,
                        ..Default::default()
                    }
                })
                .into_iter()
                .collect(),
            status: status.flatten(),
            ..Default::default()
        },
    );
    clamp(&mut out);
    out
}

/// Clamps every span whose parent is in `spans` into the parent's time,
/// until nothing moves (each pass settles one more level). Turn times have
/// millisecond resolution and can run ahead of the wall clock, so a callee
/// may otherwise start outside its caller's call effect.
///
/// shortcut: a callee is clamped only when its caller's span is in the same
/// batch (callees commit first, so often it is not), so a re-export cut
/// differently can send a callee with other times; record a wall-clock
/// start in µs with M11's duration if backends complain of skew.
pub fn clamp(spans: &mut [Span]) {
    let parents: Vec<Option<usize>> = {
        let index: HashMap<(&[u8], &[u8]), usize> = spans
            .iter()
            .enumerate()
            .map(|(i, s)| ((s.trace_id.as_slice(), s.span_id.as_slice()), i))
            .collect();
        spans
            .iter()
            .map(|s| {
                index
                    .get(&(s.trace_id.as_slice(), s.parent_span_id.as_slice()))
                    .copied()
            })
            .collect()
    };
    for _ in 0..spans.len() {
        let mut moved = false;
        for (i, p) in parents.iter().enumerate() {
            let Some(p) = *p else { continue };
            let (lo, hi) = (spans[p].start_time_unix_nano, spans[p].end_time_unix_nano);
            let s = &mut spans[i];
            if lo > hi {
                continue;
            }
            let clamped = (
                s.start_time_unix_nano.clamp(lo, hi),
                s.end_time_unix_nano.clamp(lo, hi),
            );
            if clamped != (s.start_time_unix_nano, s.end_time_unix_nano) {
                (s.start_time_unix_nano, s.end_time_unix_nano) = clamped;
                moved = true;
            }
        }
        if !moved {
            break;
        }
    }
}

/// The node, as the OTLP resource of its spans (§3.4).
pub struct Resource<'a> {
    /// `[otel] service_name`.
    pub service_name: &'a str,
    pub service_version: &'a str,
    /// The branch, `main`.
    pub node: &'a str,
    pub engine: &'a str,
}

/// One export request with `spans` under the node's resource.
pub fn request(resource: &Resource, spans: Vec<Span>) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(OtlpResource {
                attributes: vec![
                    s("service.name", resource.service_name),
                    s("service.version", resource.service_version),
                    s("kronik.node", resource.node),
                    s("kronik.engine", resource.engine),
                ],
                ..Default::default()
            }),
            scope_spans: vec![ScopeSpans {
                scope: Some(InstrumentationScope {
                    name: "kronik".into(),
                    version: resource.service_version.into(),
                    ..Default::default()
                }),
                spans,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}
