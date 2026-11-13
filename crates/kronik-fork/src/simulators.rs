//! M12 effect simulators in a replay (docs/design/m12-simulators.md): the
//! per-target configuration main had at the fork point (I5, ADR 0014) plus
//! the overrides the replay request carries, `ContractFake` and
//! `RecordedNeighbor` from `kronik-effects`, and the `ModelSimulator` with
//! its per-proposal cache (ADR 0015).

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use kronik_core::authority::{AuthLease, Authority};
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;
use kronik_effects::contract::Contract;
use kronik_effects::http::ScrubError;
use kronik_effects::http::{
    CompiledScrubber, Target, parse_request_url, parse_url, prepared_version, route_pattern,
};
use kronik_effects::simulator::{ContractFake, NeighborSource, RecordedNeighbor};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::scrub::original_secret_prefix;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::index::ProductionIndex;
use crate::stubs::StubRule;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// One target's simulators.
pub struct TargetSimulators {
    pub stubs: Vec<StubRule>,
    pub contract: Option<ContractFake>,
    pub neighbor: bool,
    pub model: bool,
    /// What the diff records about this configuration.
    pub option: SimulatorOption,
}

/// A target's simulator configuration as recorded in the diff's
/// `options.simulators`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimulatorOption {
    pub target: String,
    pub epoch: u64,
    pub lsn: Lsn,
    pub stubs: usize,
    /// BLAKE3 of the OpenAPI document, `b3:` + hex; absent without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    pub neighbor: bool,
    pub model: bool,
    /// From the replay request's `simulator_overrides`, not from main's
    /// log (epoch and LSN are then 0).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request: bool,
}

/// A target's simulator configuration carried by a replay or proposal
/// request: it replaces main's configuration as of the fork point for that
/// replay only (I5) and is kept in the fork's options, so catch-up and a
/// replay after a restart use it again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulatorOverride {
    /// `http:<host>` or `foreign:<name>`.
    pub target: String,
    #[serde(default)]
    pub stubs: Vec<StubRule>,
    /// An OpenAPI 3 document (JSON); absent or null for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<serde_json::Value>,
    #[serde(default)]
    pub neighbor: bool,
    #[serde(default)]
    pub model: bool,
}

impl SimulatorOverride {
    /// The `SimulatorConfig` record it stands for, validated as `PUT
    /// /v1/simulators/{target}` validates one.
    pub fn record(&self) -> Result<pb::SimulatorConfig, String> {
        crate::stubs::check(&self.stubs)?;
        let contract = match &self.contract {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(doc) => serde_json::to_vec(doc).map_err(|e| format!("contract: {e}"))?,
        };
        let m = pb::SimulatorConfig {
            epoch: 0,
            target: self.target.clone(),
            stubs: self
                .stubs
                .iter()
                .map(|s| pb::StubRuleSpec {
                    method: s.method.clone().unwrap_or_default(),
                    url_prefix: s.url_prefix.clone(),
                    status: u32::from(s.status),
                    headers: s
                        .headers
                        .iter()
                        .map(|(name, value)| pb::HeaderPair {
                            name: name.clone(),
                            value: value.clone(),
                        })
                        .collect(),
                    body: s.body.clone().into_bytes(),
                    error: s.error.clone().unwrap_or_default(),
                })
                .collect(),
            contract,
            neighbor: self.neighbor,
            model: self.model,
            audit: None,
        };
        kronik_effects::simulator::check_config(&m)?;
        Ok(m)
    }
}

/// Converts recorded stub rules.
pub fn stub_rules(specs: &[pb::StubRuleSpec]) -> Vec<StubRule> {
    specs
        .iter()
        .map(|s| StubRule {
            method: (!s.method.is_empty()).then(|| s.method.clone()),
            url_prefix: s.url_prefix.clone(),
            status: u16::try_from(s.status).unwrap_or(200),
            headers: s
                .headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
            body: String::from_utf8_lossy(&s.body).into_owned(),
            error: (!s.error.is_empty()).then(|| s.error.clone()),
        })
        .collect()
}

/// The contract digest the diff and `GET /v1/simulators` show.
pub fn contract_digest(doc: &[u8]) -> String {
    format!("b3:{}", blake3::hash(doc).to_hex())
}

/// The simulators of one replay: main's configuration of every target as
/// of the fork point, with the request's overrides.
#[derive(Default)]
pub struct Simulators {
    targets: BTreeMap<String, TargetSimulators>,
    /// `RecordedNeighbor` per target, built on first use.
    neighbors: Mutex<BTreeMap<String, Arc<RecordedNeighbor>>>,
}

impl Simulators {
    pub fn new(index: &ProductionIndex, overrides: &[SimulatorOverride]) -> Simulators {
        let mut latest: BTreeMap<String, (Lsn, pb::SimulatorConfig, bool)> = BTreeMap::new();
        for (lsn, record) in index.config_records_upto(index.fork_lsn) {
            if let Record::SimulatorConfig(m) = record {
                latest.insert(m.target.clone(), (lsn, m, false));
            }
        }
        // Validated when the request came in (`diff::check_options`). An
        // override may turn the model off, never on: whether a target's
        // recorded exchanges may go to the model endpoint is main's
        // configuration at the fork point (ADR 0015), not the caller's.
        for o in overrides {
            if let Ok(mut m) = o.record() {
                let main_model = latest.get(&m.target).is_some_and(|(_, c, _)| c.model);
                m.model &= main_model;
                latest.insert(m.target.clone(), (0, m, true));
            }
        }
        let mut targets = BTreeMap::new();
        for (target, (lsn, m, request)) in latest {
            if kronik_effects::config::simulator_config_empty(&m) {
                continue;
            }
            // A record that does not parse was refused when written; skip
            // the contract rather than fail the replay.
            let contract = (!m.contract.is_empty())
                .then(|| Contract::parse(&m.contract).ok())
                .flatten()
                .map(|contract| ContractFake { contract });
            let option = SimulatorOption {
                target: target.clone(),
                epoch: m.epoch,
                lsn,
                stubs: m.stubs.len(),
                contract: (!m.contract.is_empty()).then(|| contract_digest(&m.contract)),
                neighbor: m.neighbor,
                model: m.model,
                request,
            };
            targets.insert(
                target,
                TargetSimulators {
                    stubs: stub_rules(&m.stubs),
                    contract,
                    neighbor: m.neighbor,
                    model: m.model,
                    option,
                },
            );
        }
        Simulators {
            targets,
            neighbors: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn target(&self, target: &str) -> Option<&TargetSimulators> {
        self.targets.get(target)
    }

    pub fn options(&self) -> Vec<SimulatorOption> {
        self.targets.values().map(|t| t.option.clone()).collect()
    }

    /// Production's recorded effects of `target` in the window, newest
    /// first. Neighbor hits use [`Self::neighbor`], which also keeps each
    /// effect's source secret-use prefix.
    pub fn recorded(index: &ProductionIndex, target: &str) -> Vec<(Lsn, pb::EffectRecord)> {
        Self::recorded_where(index, target, |_| true)
    }

    /// The recorded effects the model may learn from: only those of turns
    /// that show no personal data anywhere (no subject or sealed value in
    /// the input, effects, writes, messages, timers, reply or SQL, and no
    /// SQL at all). State reads are not recorded, so this is not enough
    /// under privacy mode (see [`ModelAccess::privacy`]).
    // The recorded-effect view a simulator replays: LSN, effect, secrets.
    #[allow(clippy::type_complexity)]
    pub fn model_sources<'a>(
        index: &'a ProductionIndex,
        target: &str,
    ) -> Vec<(Lsn, &'a pb::EffectRecord, Option<Arc<[pb::SecretRef]>>)> {
        Self::recorded_sources(index, target, |turn| !turn_tainted(turn))
    }

    fn recorded_where(
        index: &ProductionIndex,
        target: &str,
        keep: impl Fn(&pb::TurnRecord) -> bool,
    ) -> Vec<(Lsn, pb::EffectRecord)> {
        let mut out: Vec<(Lsn, pb::EffectRecord)> = index
            .records
            .iter()
            .filter_map(|c| match &c.record {
                Record::TurnRecord(t) if t.effects.iter().any(|e| e.target == target) => {
                    keep(t).then_some((c.lsn, t))
                }
                _ => None,
            })
            .flat_map(|(lsn, t)| {
                t.effects
                    .iter()
                    .filter(|e| e.target == target)
                    .map(move |e| (lsn, e.clone()))
            })
            .collect();
        out.reverse();
        out
    }

    // The recorded-effect view a simulator replays: LSN, effect, secrets.
    #[allow(clippy::type_complexity)]
    fn recorded_sources<'a>(
        index: &'a ProductionIndex,
        target: &str,
        keep: impl Fn(&pb::TurnRecord) -> bool,
    ) -> Vec<(Lsn, &'a pb::EffectRecord, Option<Arc<[pb::SecretRef]>>)> {
        let mut candidates = Vec::new();
        for item in index.records.iter() {
            let Record::TurnRecord(turn) = &item.record else {
                continue;
            };
            let mut matching = turn.effects.iter().filter(|effect| effect.target == target);
            let Some(first) = matching.next() else {
                continue;
            };
            if !keep(turn) {
                continue;
            }
            for effect in std::iter::once(first).chain(matching) {
                let prefix = turn
                    .input
                    .as_ref()
                    .and_then(|input| original_secret_prefix(input, &turn.effects, effect.ordinal));
                candidates.push((item.lsn, effect, prefix));
            }
        }
        candidates.reverse();
        candidates
    }

    pub fn neighbor(&self, index: &ProductionIndex, target: &str) -> Arc<RecordedNeighbor> {
        let mut n = lock(&self.neighbors);
        n.entry(target.to_owned())
            .or_insert_with(|| {
                // The prefix is the source turn's, through that ordinal.
                // A missing prefix stays missing; inventory is not a substitute.
                let sources = Self::recorded_sources(index, target, |_| true)
                    .into_iter()
                    .map(|(lsn, effect, prefix)| NeighborSource {
                        lsn,
                        effect: effect.clone(),
                        prefix,
                    });
                Arc::new(RecordedNeighbor::from_sources(sources))
            })
            .clone()
    }
}

/// Whether a production turn shows personal data or SQL anywhere.
fn turn_tainted(t: &pb::TurnRecord) -> bool {
    if !t.sql_changes.is_empty() || !t.sql_schema.is_empty() {
        return true;
    }
    if matches!(t.input.as_ref().and_then(|input| input.kind.as_ref()),
        Some(pb::input::Kind::Message(input))
            if input.msg.as_ref().is_some_and(|message| message.retained_compensation_source.is_some()))
        || t.messages.iter().chain(&t.compensations).any(|outbound| {
            outbound
                .msg
                .as_ref()
                .is_some_and(|message| message.retained_compensation_source.is_some())
        })
    {
        return true;
    }
    let mut tainted = false;
    let mut copy = t.clone();
    kronik_proto::sealables::turn_mut(&mut copy, &mut |s| {
        tainted |= s.subject.is_some() || matches!(s.value, Some(pb::sealable::Value::Sealed(_)));
    });
    tainted
}

/// `[simulators.model]` in `kronik.toml` (ADR 0015).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelConfig {
    /// An OpenAI-compatible chat completions URL.
    pub endpoint: String,
    pub model: String,
    /// The API key, read from `api_key_env` at start; never logged.
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub max_examples: usize,
    /// `examples_under_privacy`: send recorded examples even when privacy
    /// mode is or was on in the window (off by default: state reads are
    /// not recorded, so a turn's personal data cannot be ruled out).
    pub examples_under_privacy: bool,
}

/// A model answer as cached: `None` is a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAnswer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModelCacheError {
    Redaction(ScrubError),
    SourceUnavailable,
}

type ModelResult = Result<Option<ModelAnswer>, ModelCacheError>;

enum ModelAdmissionDenial {
    Original(ApiError),
    Source(ApiError),
}

impl ModelAdmissionDenial {
    fn error(&self) -> &ApiError {
        match self {
            Self::Original(error) | Self::Source(error) => error,
        }
    }
}

fn source_scope_error() -> ApiError {
    ApiError::new(
        ErrorCode::SecretUnavailable,
        ScrubError::SourceScopeUnavailable.to_string(),
    )
}

/// One concrete handoff: the original physical publisher precedes the actual
/// source try-lock. Error construction and denial-state publication happen
/// after BOTH fences have been released.
fn admit_model_data(
    original: &AuthLease,
    publication: &kronik_sched::secrets::SecretSnapshotPublication,
    effect: &mut dyn FnMut() -> Result<(), ApiError>,
) -> Result<(), ModelAdmissionDenial> {
    let mut denied = ApiError {
        code: ErrorCode::SecretUnavailable,
        message: String::new(),
        hint: None,
    };
    let mut original_entered = false;
    let mut data_entered = false;
    let result = original.admit(&mut || {
        original_entered = true;
        publication.with_current_publication(&mut denied, || {
            data_entered = true;
            effect()
        })
    });
    result.map_err(|error| {
        if original_entered && !data_entered {
            ModelAdmissionDenial::Source(source_scope_error())
        } else {
            ModelAdmissionDenial::Original(error)
        }
    })
}

/// A conjunction for ONE owned model HTTP job, never a new issuer or a field
/// of shared ModelAccess. Retain the actual typed failure when Core Net maps
/// admission errors into Connect strings; a later live check cannot erase it.
struct ModelHttpAdmission {
    original: AuthLease,
    publication: kronik_sched::secrets::SecretSnapshotPublication,
    denial: OnceLock<ModelAdmissionDenial>,
    me: std::sync::Weak<Self>,
}

impl ModelHttpAdmission {
    fn new(
        original: AuthLease,
        publication: kronik_sched::secrets::SecretSnapshotPublication,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            original,
            publication,
            denial: OnceLock::new(),
            me: me.clone(),
        })
    }

    fn denied(&self) -> Option<ApiError> {
        self.denial.get().map(|denial| denial.error().clone())
    }

    fn record_denial(&self, denial: ModelAdmissionDenial) -> &ModelAdmissionDenial {
        self.denial.get_or_init(|| denial)
    }
}

impl Authority for ModelHttpAdmission {
    fn check(&self) -> Result<(), ApiError> {
        if let Some(error) = self.denied() {
            return Err(error);
        }
        if let Err(error) = self.original.check() {
            return Err(self
                .record_denial(ModelAdmissionDenial::Original(error))
                .error()
                .clone());
        }
        if let Err(error) = self.publication.check_current() {
            return Err(self
                .record_denial(ModelAdmissionDenial::Source(error))
                .error()
                .clone());
        }
        Ok(())
    }

    fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let Some(held) = self.me.upgrade() else {
            return Box::pin(std::future::ready(()));
        };
        Box::pin(async move {
            if held.denial.get().is_some() {
                return;
            }
            tokio::select! {
                biased;
                () = held.original.cancelled() => {
                    let error = held.original.check().err().unwrap_or_else(||
                        ApiError::new(ErrorCode::Unavailable, "The original model operation was cancelled"));
                    held.record_denial(ModelAdmissionDenial::Original(error));
                }
                () = held.publication.cancelled() => {
                    let error = held.publication.check_current().err().unwrap_or_else(source_scope_error);
                    held.record_denial(ModelAdmissionDenial::Source(error));
                }
            }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        if let Some(error) = self.denied() {
            return Err(error);
        }
        match admit_model_data(&self.original, &self.publication, effect) {
            Ok(()) => Ok(()),
            Err(denial) => Err(self.record_denial(denial).error().clone()),
        }
    }
}

struct Slot {
    source_fingerprint: Option<[u8; 32]>,
    answer: tokio::sync::OnceCell<ModelResult>,
    initialization: tokio::sync::Mutex<()>,
}

/// Immutable per-proposal facts, certified against the exact secret source
/// snapshot which scrubbed them. A different snapshot cannot reuse or rewrite
/// these answers, including refusals and redaction failures.
#[derive(Default)]
pub struct ModelCache {
    path: Option<PathBuf>,
    slots: Mutex<BTreeMap<String, Arc<Slot>>>,
    dirty: AtomicBool,
    save: Mutex<()>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedAnswer<T> {
    source_fingerprint: Option<[u8; 32]>,
    answer: T,
}

/// Serde remains the JSON parser. Its input budget is reset for each cell,
/// before a key or value can grow; the whole proposal has no byte cap.
struct CacheRead<R> {
    inner: R,
    remaining: Rc<Cell<usize>>,
}

impl<R: std::io::Read> std::io::Read for CacheRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let available = self.remaining.get();
        let allowed = bytes.len().min(available);
        if allowed == 0 {
            return Err(std::io::Error::other("model cache cell limit"));
        }
        let count = self.inner.read(&mut bytes[..allowed])?;
        self.remaining.set(available - count);
        Ok(count)
    }
}

struct CacheSeed {
    remaining: Rc<Cell<usize>>,
}

impl<'de> serde::de::DeserializeSeed<'de> for CacheSeed {
    type Value = BTreeMap<String, Arc<Slot>>;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for CacheSeed {
    type Value = BTreeMap<String, Arc<Slot>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a model cache envelope")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut version = None;
        let mut answers = None;
        loop {
            self.remaining
                .set(kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES);
            let Some(field) = map.next_key::<String>()? else {
                break;
            };
            match field.as_str() {
                "version" => {
                    if version.is_some() {
                        return Err(serde::de::Error::duplicate_field("version"));
                    }
                    let value = map.next_value::<u32>()?;
                    if value != 2 {
                        return Err(serde::de::Error::custom("unsupported model cache version"));
                    }
                    version = Some(value);
                }
                "answers" => {
                    if answers.is_some() {
                        return Err(serde::de::Error::duplicate_field("answers"));
                    }
                    answers = Some(map.next_value_seed(CacheCellsSeed {
                        remaining: self.remaining.clone(),
                    })?);
                }
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        &field,
                        &["version", "answers"],
                    ));
                }
            }
        }
        let answers = answers.ok_or_else(|| serde::de::Error::missing_field("answers"))?;
        if (version.is_none() && answers.stamped) || (version.is_some() && answers.legacy) {
            return Err(serde::de::Error::custom(
                "model cache cells do not match their envelope",
            ));
        }
        Ok(answers.slots)
    }
}

struct CacheCells {
    slots: BTreeMap<String, Arc<Slot>>,
    legacy: bool,
    stamped: bool,
}

struct CacheCellsSeed {
    remaining: Rc<Cell<usize>>,
}

impl<'de> serde::de::DeserializeSeed<'de> for CacheCellsSeed {
    type Value = CacheCells;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}

impl<'de> serde::de::Visitor<'de> for CacheCellsSeed {
    type Value = CacheCells;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("model cache answers")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut answers = CacheCells {
            slots: BTreeMap::new(),
            legacy: false,
            stamped: false,
        };
        loop {
            self.remaining
                .set(kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES);
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            // Only one bounded cell is materialized. Consuming from_value
            // moves its strings into the one retained immutable slot map.
            let value = map.next_value::<serde_json::Value>()?;
            let current = value.as_object().is_some_and(|object| {
                object.contains_key("source_fingerprint") || object.contains_key("answer")
            });
            let (source_fingerprint, answer) = if current {
                let object = value
                    .as_object()
                    .ok_or_else(|| serde::de::Error::custom("invalid model cache cell"))?;
                if !object.contains_key("source_fingerprint") || !object.contains_key("answer") {
                    return Err(serde::de::Error::custom("incomplete model cache cell"));
                }
                let cell: CachedAnswer<ModelResult> =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                answers.stamped = true;
                (cell.source_fingerprint, cell.answer)
            } else {
                let answer: Option<ModelAnswer> =
                    serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                answers.legacy = true;
                (None, Ok(answer))
            };
            match answers.slots.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Arc::new(Slot {
                        source_fingerprint,
                        answer: tokio::sync::OnceCell::new_with(Some(answer)),
                        initialization: tokio::sync::Mutex::new(()),
                    }));
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(serde::de::Error::custom("duplicate model cache key"));
                }
            }
        }
        Ok(answers)
    }
}

struct CacheWrite<'a, W> {
    inner: &'a mut W,
    remaining: usize,
}

impl<W: std::io::Write> std::io::Write for CacheWrite<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("model cache cell limit"))?;
        self.inner.write_all(bytes)?;
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// The existing record bound applies before serialization grows a buffer,
/// not after an unbounded serde_json::to_vec has already allocated it.
struct JsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Drop for JsonWriter {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::io::Write for JsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|&n| n <= self.limit)
            .ok_or_else(|| std::io::Error::other("model JSON output limit"))?;
        if needed > self.bytes.capacity() {
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .max(64)
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(|_| std::io::Error::other("model JSON output limit"))?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, ScrubError> {
    let mut writer = JsonWriter {
        bytes: Vec::new(),
        limit: kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| ScrubError::OutputLimit)?;
    Ok(std::mem::take(&mut writer.bytes))
}

fn unavailable(message: &'static str) -> ApiError {
    ApiError::new(ErrorCode::SecretUnavailable, message)
}

impl ModelCache {
    /// Parse old captures without inventing a producer certificate. Their
    /// exact saved disclosure is qualified separately at lookup time.
    pub fn open(path: &Path) -> Result<ModelCache, String> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ModelCache {
                    path: Some(path.to_owned()),
                    dirty: AtomicBool::new(true),
                    ..Self::default()
                });
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let remaining = Rc::new(Cell::new(kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES));
        let reader = CacheRead {
            inner: std::io::BufReader::new(file),
            remaining: remaining.clone(),
        };
        let mut decoder = serde_json::Deserializer::from_reader(reader);
        let slots = serde::de::DeserializeSeed::deserialize(
            CacheSeed {
                remaining: remaining.clone(),
            },
            &mut decoder,
        )
        .map_err(|_| format!("{}: not a model cache", path.display()))?;
        remaining.set(kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES);
        decoder
            .end()
            .map_err(|_| format!("{}: trailing model cache data", path.display()))?;
        Ok(ModelCache {
            path: Some(path.to_owned()),
            slots: Mutex::new(slots),
            ..Self::default()
        })
    }

    pub fn read_only(path: &Path) -> Result<ModelCache, String> {
        let mut cache = Self::open(path)?;
        cache.path = None;
        Ok(cache)
    }

    pub fn memory() -> ModelCache {
        ModelCache::default()
    }

    // The recorded-effect view a simulator replays: LSN, effect, secrets.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::type_complexity)]
    fn slot(&self, key: &str, source_fingerprint: [u8; 32]) -> Result<Arc<Slot>, ApiError> {
        let mut slots = lock(&self.slots);
        if let Some(slot) = slots.get(key) {
            if slot.source_fingerprint == Some(source_fingerprint) {
                return Ok(slot.clone());
            }
            if slot.answer.get().is_some() {
                return Err(unavailable(
                    "The model cache belongs to a different certified secret snapshot",
                ));
            }
        }
        let slot = Arc::new(Slot {
            source_fingerprint: Some(source_fingerprint),
            answer: tokio::sync::OnceCell::new(),
            initialization: tokio::sync::Mutex::new(()),
        });
        // An uninitialized slot is not an immutable model fact. A new genuine
        // operation may replace it after source change; never rewrite an answer.
        let retired = if let Some(current) = slots.get_mut(key) {
            Some(std::mem::replace(current, slot.clone()))
        } else {
            slots.insert(key.to_owned(), slot.clone());
            None
        };
        drop(slots);
        drop(retired);
        Ok(slot)
    }

    /// Stream immutable cells through the existing atomic file protocol.
    /// Bounds apply to each cell, never to the proposal's aggregate capture.
    pub fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let _save = lock(&self.save);
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let result = crate::write_atomic_with(path, |file| {
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(b"{\"version\":2,\"answers\":{")?;
            let slots = lock(&self.slots);
            let mut first = true;
            for (key, slot) in slots.iter() {
                let Some(answer) = slot.answer.get() else {
                    continue;
                };
                if !first {
                    writer.write_all(b",")?;
                }
                first = false;
                let mut cell = CacheWrite {
                    inner: &mut writer,
                    remaining: kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES,
                };
                serde_json::to_writer(&mut cell, key).map_err(std::io::Error::other)?;
                cell.write_all(b":")?;
                serde_json::to_writer(
                    &mut cell,
                    &CachedAnswer {
                        source_fingerprint: slot.source_fingerprint,
                        answer,
                    },
                )
                .map_err(std::io::Error::other)?;
            }
            drop(slots);
            writer.write_all(b"}}")?;
            writer.flush()
        });
        if result.is_err() {
            self.dirty.store(true, Ordering::Release);
        }
        result.map_err(|error| format!("{}: {error}", path.display()))
    }

    pub fn len(&self) -> usize {
        lock(&self.slots).len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Source facts alone never authorize a new model request.
pub enum ModelSecretSnapshot {
    Recorded(Arc<kronik_sched::secrets::CertifiedSecretSnapshot>),
    Live {
        snapshot: Arc<kronik_sched::secrets::CertifiedSecretSnapshot>,
        publication: kronik_sched::secrets::SecretSnapshotPublication,
    },
}

impl ModelSecretSnapshot {
    pub(crate) fn snapshot(&self) -> &Arc<kronik_sched::secrets::CertifiedSecretSnapshot> {
        match self {
            Self::Recorded(snapshot) | Self::Live { snapshot, .. } => snapshot,
        }
    }
}

/// The model simulator of a replay: configuration, network and cache.
#[derive(Clone)]
pub struct ModelAccess {
    pub config: ModelConfig,
    pub env: Env,
    pub cache: Arc<ModelCache>,
    /// Privacy mode is on, or was on in the replay's window: no recorded
    /// examples unless `config.examples_under_privacy`.
    pub privacy: bool,
    /// ONE qualified source getter: pinned read-only facts, or the actual
    /// atomic snapshot/publication pair. No source facts mint dispatch authority.
    pub secret_snapshot: Arc<dyn Fn() -> Result<ModelSecretSnapshot, ApiError> + Send + Sync>,
    /// A dry run (I12): answers come from saved facts only. A miss is an
    /// explicit prerequisite, never a call, slot creation, or saved refusal.
    pub offline: bool,
}

/// The longest body of an example or the request sent to the model.
const MAX_BODY: usize = 4096;

fn text(b: &[u8]) -> Option<String> {
    Some(
        std::str::from_utf8(b)
            .ok()?
            .chars()
            .take(MAX_BODY)
            .collect(),
    )
}

/// A plain value without a subject, else `None`: the model never sees a
/// value with a subject, sealed or not.
fn subject_free(s: Option<&pb::Sealable>) -> Option<&[u8]> {
    let s = s?;
    if s.subject.is_some() {
        return None;
    }
    match s.value.as_ref()? {
        pb::sealable::Value::Plain(b) => Some(b),
        pb::sealable::Value::Sealed(_) => None,
    }
}

/// The request as the model sees it, or `None` when it carries a secret.
fn request_view(req: &pb::HttpEffectRequest) -> Option<serde_json::Value> {
    let mut headers = BTreeMap::new();
    for h in &req.headers {
        match &h.value {
            Some(pb::http_effect_header::Value::Text(v)) => {
                // Credentials never go to the model: the list API readers
                // without pii:read are also spared (kronik-core http).
                if !kronik_core::http::credential_header(&h.name) {
                    let name = if prepared_version(req.fingerprint_version) {
                        h.name.clone()
                    } else {
                        h.name.to_ascii_lowercase()
                    };
                    headers.insert(name, v.clone());
                }
            }
            // A secret header (I8): never described to the model.
            _ => return None,
        }
    }
    // Versions 2 and 3 already rendered their typed, scrubbed components.
    // Never lowercase or otherwise reparse a generated marker in its host.
    if req.fingerprint_version == 0 {
        parse_url(&req.url).ok()?;
    } else if !prepared_version(req.fingerprint_version) {
        return None;
    }
    let body = text(&req.body)?;
    Some(serde_json::json!({
        "method": if prepared_version(req.fingerprint_version) { req.method.clone() } else { req.method.to_ascii_uppercase() },
        "url": req.url,
        "headers": headers,
        "body": body,
    }))
}

/// Private inspection of original legacy fields, never a version-2 model
/// request or a second scan of a prepared request's generated markers.
fn request_holds(
    req: &pb::HttpEffectRequest,
    holds: &dyn Fn(&[u8]) -> bool,
) -> Result<bool, ScrubError> {
    // A caller with a scoped Ready body resolves it before building this
    // model-only view. An opaque reference is never an empty request body.
    if req.fingerprint_version != 0 {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    let (target, raw_host) = parse_request_url(&req.url).map_err(|_| ScrubError::InvalidText)?;
    Ok(
        kronik_sched::scrub::http_url_contains(&target, raw_host, holds)?
            || holds(&req.body)
            || req.headers.iter().any(|header| {
                holds(header.name.as_bytes())
                    || match &header.value {
                        Some(pb::http_effect_header::Value::Text(value)) => holds(value.as_bytes()),
                        _ => true,
                    }
            }),
    )
}

/// Validate already-prepared request data without reparsing its rendered URI.
/// A genuine covering scope bypasses matching; otherwise the canonical guard
/// treats a match as ambiguous rather than producing replacement markers.
fn prepared_request_safe(
    req: &pb::HttpEffectRequest,
    target: &Target,
    matcher: &CompiledScrubber<'_>,
    current_scope: Option<&[pb::SecretRef]>,
    prepared_scope: Option<&[pb::SecretRef]>,
) -> Result<(), ScrubError> {
    if !prepared_version(req.fingerprint_version) {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    if req.encoded_len() > kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES {
        return Err(ScrubError::OutputLimit);
    }
    if kronik_sched::scrub::secret_scope_is_subset(current_scope, prepared_scope)? {
        return Ok(());
    }
    if kronik_sched::scrub::http_url_contains(target, &target.host, &|bytes| {
        matcher.is_match(bytes)
    })? {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    let method =
        (!kronik_sched::scrub::protocol_method(&req.method)).then_some(req.method.as_bytes());
    let fields = method
        .into_iter()
        .chain(std::iter::once(req.body.as_slice()))
        .chain(req.headers.iter().flat_map(|header| {
            [
                header.name.as_bytes(),
                match &header.value {
                    Some(pb::http_effect_header::Value::Text(value)) => value.as_bytes(),
                    _ => &[],
                },
            ]
        }));
    // Coverage was checked above. No second metadata sort or matcher is needed.
    kronik_sched::scrub::prepared_fields_safe(None, None, matcher, fields)
}

fn model_scope(
    snapshot: &kronik_sched::secrets::CertifiedSecretSnapshot,
    prepared_scope: Option<&[pb::SecretRef]>,
) -> Result<Arc<[pb::SecretRef]>, ScrubError> {
    let current = kronik_sched::effects::combined_secret_scope(snapshot, &[], Some(&[]))?
        .ok_or(ScrubError::SourceScopeUnavailable)?;
    // The cache certificate covers its actual matcher. It cannot certify an
    // additional held historical value absent from that physical source.
    if !kronik_sched::scrub::secret_scope_is_subset(prepared_scope, Some(&current))? {
        return Err(ScrubError::SourceScopeUnavailable);
    }
    Ok(current)
}

/// Optional subject-free exchanges, using their original source identity
/// prefix. Unknown/ambiguous examples are omitted, never marked complete.
// The recorded-effect view a simulator replays: LSN, effect, secrets.
#[allow(clippy::type_complexity)]
pub fn model_examples(
    recorded: &[(Lsn, &pb::EffectRecord, Option<Arc<[pb::SecretRef]>>)],
    max: usize,
    matcher: &CompiledScrubber<'_>,
    current_scope: Option<&[pb::SecretRef]>,
) -> Vec<serde_json::Value> {
    let no_literals: &[(&str, &[u8])] = &[];
    let Ok(credentials) = CompiledScrubber::new_output(no_literals, 0) else {
        return Vec::new();
    };
    fn contains_credential(value: &serde_json::Value, matcher: &CompiledScrubber<'_>) -> bool {
        match value {
            serde_json::Value::String(value) => matcher.is_match(value.as_bytes()),
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| contains_credential(value, matcher)),
            serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
                matcher.is_match(key.as_bytes()) || contains_credential(value, matcher)
            }),
            _ => false,
        }
    }
    /// Whether a model that parses a quoted string as JSON sees a credential
    /// the raw bytes hide: `\u006bronik_...` names one only after decoding.
    fn decodes_to_credential(
        value: &serde_json::Value,
        matcher: &CompiledScrubber<'_>,
        depth: u8,
    ) -> bool {
        match value {
            serde_json::Value::String(text) => {
                if matcher.is_match(text.as_bytes()) {
                    return true;
                }
                depth < 4
                    && serde_json::from_str::<serde_json::Value>(text)
                        .is_ok_and(|decoded| decodes_to_credential(&decoded, matcher, depth + 1))
            }
            serde_json::Value::Array(values) => values
                .iter()
                .any(|value| decodes_to_credential(value, matcher, depth)),
            serde_json::Value::Object(values) => values.iter().any(|(key, value)| {
                matcher.is_match(key.as_bytes()) || decodes_to_credential(value, matcher, depth)
            }),
            _ => false,
        }
    }
    recorded
        .iter()
        .filter(|(_, effect, _)| effect.status == pb::EffectStatus::Ok as i32)
        .filter_map(|(_, effect, prefix)| {
            let req = pb::HttpEffectRequest::decode(subject_free(effect.request.as_ref())?).ok()?;
            let resp =
                pb::HttpEffectResponse::decode(subject_free(effect.response.as_ref())?).ok()?;
            match req.fingerprint_version {
                0 => {
                    let holds = |bytes: &[u8]| matcher.is_match(bytes);
                    if request_holds(&req, &holds).ok()?
                        || holds(&resp.body)
                        || resp.headers.iter().any(|header| {
                            holds(header.name.as_bytes()) || holds(header.value.as_bytes())
                        })
                    {
                        return None;
                    }
                }
                2 | 3 => {
                    let target = kronik_effects::http::prepared_target(&req).ok()?;
                    prepared_request_safe(&req, &target, matcher, current_scope, prefix.as_deref())
                        .ok()?;
                    kronik_sched::scrub::prepared_fields_safe(
                        current_scope,
                        prefix.as_deref(),
                        matcher,
                        std::iter::once(resp.body.as_slice()).chain(
                            resp.headers.iter().flat_map(|header| {
                                [header.name.as_bytes(), header.value.as_bytes()]
                            }),
                        ),
                    )
                    .ok()?;
                }
                _ => return None,
            }
            let response_body = text(&resp.body)?;
            let request = request_view(&req)?;
            let quote = serde_json::json!({
                "request": request,
                "response": {
                    "status": resp.status,
                    "headers": resp.headers.iter()
                        .filter(|header| header.name.eq_ignore_ascii_case("content-type"))
                        .map(|header| (header.name.to_ascii_lowercase(), header.value.clone()))
                        .collect::<BTreeMap<_, _>>(),
                    "body": response_body,
                },
            });
            // This is output to another model, not a new request policy.
            // Check the actual decoded quote; JSON escapes may introduce a
            // credential absent from the original encoded body bytes.
            if contains_credential(&quote, &credentials)
                || decodes_to_credential(&quote, &credentials, 0)
            {
                return None;
            }
            Some(quote)
        })
        .take(max)
        .collect()
}

/// The chat completions request for one effect, or `None` when the request
/// may not be shown (a secret header).
pub fn model_request(
    config: &ModelConfig,
    target: &Target,
    examples: &[serde_json::Value],
    req: &pb::HttpEffectRequest,
) -> Result<Option<serde_json::Value>, ScrubError> {
    let Some(request) = request_view(req) else {
        return Ok(None);
    };
    let route = route_pattern(&target.path);
    let kind = if target.scheme == "foreign" {
        "foreign"
    } else {
        "http"
    };
    let system = format!(
        "You simulate the HTTP API {kind}:{} for a deterministic replay. Answer the \
         request with one JSON object and nothing else: {{\"status\": <int>, \
         \"headers\": {{<name>: <value>}}, \"body\": <string>}}. Follow the recorded \
         examples for this API (route {route}) as closely as possible.",
        target.host,
    );
    let user = serde_json::json!({ "examples": examples, "request": request });
    let content = String::from_utf8(json_bytes(&user)?).map_err(|_| ScrubError::InvalidText)?;
    Ok(Some(serde_json::json!({
        "model": config.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": content},
        ],
    })))
}

/// Parses a chat completions response into an answer.
pub fn parse_model_reply(bytes: &[u8]) -> Option<ModelAnswer> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let content = v.pointer("/choices/0/message/content")?.as_str()?;
    let content = content.trim();
    // Models sometimes wrap JSON in a code fence.
    let content = content
        .strip_prefix("```json")
        .or_else(|| content.strip_prefix("```"))
        .and_then(|c| c.strip_suffix("```"))
        .unwrap_or(content)
        .trim();
    let a: serde_json::Value = serde_json::from_str(content).ok()?;
    let status = u16::try_from(a.get("status")?.as_u64()?).ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let headers = a
        .get("headers")
        .and_then(serde_json::Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.to_ascii_lowercase(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let body = match a.get("body") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    Some(ModelAnswer {
        status,
        headers,
        body,
    })
}

fn model_result(result: ModelResult) -> Result<Option<ModelAnswer>, ApiError> {
    match result {
        Ok(answer) => Ok(answer),
        Err(ModelCacheError::Redaction(error)) => Err(ApiError::new(
            ErrorCode::SecretUnavailable,
            error.to_string(),
        )),
        Err(ModelCacheError::SourceUnavailable) => Err(unavailable(
            "The certified model secret source changed before publication",
        )),
    }
}

fn wipe_model_result(result: &mut ModelResult) {
    if let Ok(Some(answer)) = result {
        answer.body.zeroize();
        for (name, value) in &mut answer.headers {
            name.zeroize();
            value.zeroize();
        }
    }
}

/// An unstamped historical answer is not producer-scope evidence. It can be
/// disclosed unchanged only when the actual complete current plan finds no
/// sensitive occurrence; even an identical generated marker is ambiguous.
fn qualify_legacy_answer(
    snapshot: &kronik_sched::secrets::CertifiedSecretSnapshot,
    result: &ModelResult,
) -> Result<(), ApiError> {
    let Ok(Some(answer)) = result else {
        return Ok(());
    };
    let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
    let matcher =
        CompiledScrubber::new_output(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES)
            .map_err(|error| ApiError::new(ErrorCode::SecretUnavailable, error.to_string()))?;
    kronik_sched::scrub::prepared_fields_safe(
        None,
        None,
        &matcher,
        std::iter::once(answer.body.as_bytes()).chain(
            answer
                .headers
                .iter()
                .flat_map(|(name, value)| [name.as_bytes(), value.as_bytes()]),
        ),
    )
    .map_err(|error| ApiError::new(ErrorCode::SecretUnavailable, error.to_string()))
}

/// Read immutable cache data before publication; its final callback only moves.
fn deliver_model_result(
    source: &ModelSecretSnapshot,
    original: &AuthLease,
    result: ModelResult,
) -> Result<Option<ModelAnswer>, ApiError> {
    let mut pending = Some(result);
    let mut delivered = None;
    let mut transfer = || {
        delivered = pending.take();
        Ok(())
    };
    let admitted = match source {
        ModelSecretSnapshot::Recorded(_) => original.admit(&mut transfer),
        ModelSecretSnapshot::Live { publication, .. } => {
            admit_model_data(original, publication, &mut transfer)
                .map_err(|denial| denial.error().clone())
        }
    };
    if let Err(error) = admitted {
        if let Some(result) = &mut pending {
            wipe_model_result(result);
        }
        if let Some(result) = &mut delivered {
            wipe_model_result(result);
        }
        return Err(error);
    }
    model_result(delivered.ok_or_else(|| unavailable("The model result was not admitted"))?)
}

impl ModelAccess {
    fn cached_slot(
        &self,
        target: &str,
        fingerprint: &[u8],
    ) -> Result<(ModelSecretSnapshot, Option<Arc<Slot>>), ApiError> {
        let source = (self.secret_snapshot)()?;
        let key = format!("{target} {}", hex(fingerprint));
        let slot = { lock(&self.cache.slots).get(&key).cloned() };
        if let Some(found) = &slot
            && found
                .source_fingerprint
                .is_some_and(|fingerprint| fingerprint != source.snapshot().fingerprint)
        {
            if found.answer.get().is_none() {
                return Ok((source, None));
            }
            return Err(unavailable(
                "The model cache belongs to a different certified secret snapshot",
            ));
        }
        Ok((source, slot))
    }

    /// Metadata-only saved-fact probe; never creates a slot or clones a body.
    pub fn has_cached_answer(&self, target: &str, fingerprint: &[u8]) -> Result<bool, ApiError> {
        let (_, slot) = self.cached_slot(target, fingerprint)?;
        Ok(slot.is_some_and(|slot| slot.answer.get().is_some()))
    }

    /// RecordedOnly lookup uses genuinely qualified source facts, not authority.
    pub fn cached_answer(
        &self,
        target: &str,
        fingerprint: &[u8],
    ) -> Result<Option<Option<ModelAnswer>>, ApiError> {
        let (source, slot) = self.cached_slot(target, fingerprint)?;
        let mut result = None;
        if let Some(slot) = slot
            && let Some(saved) = slot.answer.get()
        {
            if slot.source_fingerprint.is_none() {
                qualify_legacy_answer(source.snapshot(), saved)?;
            }
            result = Some(saved.clone());
        }
        if let ModelSecretSnapshot::Live { publication, .. } = &source
            && let Err(error) = publication.check_current()
        {
            if let Some(result) = &mut result {
                wipe_model_result(result);
            }
            return Err(error);
        }
        result.map(model_result).transpose()
    }

    async fn fetch_body(
        &self,
        body: Vec<u8>,
        job: &Arc<ModelHttpAdmission>,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        job.check()?;
        let deadline = self
            .env
            .clock
            .monotonic()
            .checked_add(self.config.timeout)
            .ok_or_else(|| {
                ApiError::new(ErrorCode::Unavailable, "The model deadline is invalid")
            })?;
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if let Some(key) = &self.config.api_key {
            headers.push(("authorization".to_owned(), format!("Bearer {key}")));
        }
        let authority: AuthLease = job.clone();
        let call = self.env.net.http_authorized(
            kronik_core::env::HttpRequest {
                method: "POST".into(),
                url: self.config.endpoint.clone(),
                headers,
                body: body.into(),
                max_response_bytes: 1 << 20,
            },
            authority,
        );
        let Some(remaining) = deadline
            .checked_sub(self.env.clock.monotonic())
            .filter(|remaining| !remaining.is_zero())
        else {
            job.check()?;
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "The model deadline expired before dispatch",
            ));
        };
        let response = tokio::select! {
            biased;
            () = job.cancelled() => {
                return Err(job.check().err().unwrap_or_else(source_scope_error));
            }
            response = self.env.timeout(remaining, call) => response,
        };
        let response = match response {
            Ok(Ok(response)) => response,
            failed => {
                // Net's Connect string must not erase the exact job denial.
                job.check()?;
                return Err(ApiError::new(
                    ErrorCode::Unavailable,
                    if failed.is_err() {
                        "The model request timed out"
                    } else {
                        "The model request failed"
                    },
                ));
            }
        };
        // Native Core Net owns the bounded materialized response future.
        // The same job and absolute deadline above span its entire body.
        let output = Zeroizing::new(Vec::from(response.body));
        job.check()?;
        if !(200..300).contains(&response.status) {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "The model service returned an unsuccessful status",
            ));
        }
        if output.len() > 1 << 20 {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "The model response exceeded its size limit",
            ));
        }
        Ok(output)
    }

    /// Saved facts match first. A new request needs BOTH the caller's original
    /// dispatch lease and the source's actual atomic live publication resource.
    // The simulator answer's inputs: target, fingerprint, request, scopes
    // and the caller's authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn answer(
        &self,
        target: &str,
        fingerprint: &[u8],
        req: &pb::HttpEffectRequest,
        prepared_target: &Target,
        prepared_scope: Option<&[pb::SecretRef]>,
        examples: impl FnOnce(&CompiledScrubber<'_>, Option<&[pb::SecretRef]>) -> Vec<serde_json::Value>,
        original: &AuthLease,
    ) -> Result<Option<ModelAnswer>, ApiError> {
        original.check()?;
        let (source, existing) = self.cached_slot(target, fingerprint)?;
        if let Some(slot) = existing.as_ref()
            && let Some(saved) = slot.answer.get()
        {
            if slot.source_fingerprint.is_none() {
                qualify_legacy_answer(source.snapshot(), saved)?;
            }
            return deliver_model_result(&source, original, saved.clone());
        }
        if self.offline {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "A recorded model answer is required",
            ));
        }
        let ModelSecretSnapshot::Live {
            snapshot,
            publication,
        } = &source
        else {
            return Err(source_scope_error());
        };
        publication.check_current()?;
        if req.headers.iter().any(|header| {
            matches!(
                header.value.as_ref(),
                Some(pb::http_effect_header::Value::Secret(_))
            )
        }) {
            return deliver_model_result(&source, original, Ok(None));
        }
        let redact_error =
            |error: ScrubError| ApiError::new(ErrorCode::SecretUnavailable, error.to_string());
        let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
        let matcher =
            CompiledScrubber::new(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES)
                .map_err(redact_error)?;
        if req.fingerprint_version == 0 {
            if req.encoded_len() > kronik_sched::scrub::MAX_JSON_OUTPUT_BYTES {
                return Err(redact_error(ScrubError::OutputLimit));
            }
            // Private inspection may preserve a genuine old known-sensitive
            // refusal, but never emits version-0 request data or a new fact.
            if request_holds(req, &|bytes| matcher.is_match(bytes)).map_err(redact_error)? {
                return deliver_model_result(&source, original, Ok(None));
            }
        }
        let current_scope = model_scope(snapshot, prepared_scope).map_err(redact_error)?;
        prepared_request_safe(
            req,
            prepared_target,
            &matcher,
            Some(&current_scope),
            prepared_scope,
        )
        .map_err(redact_error)?;
        publication.check_current()?;
        let key = format!("{target} {}", hex(fingerprint));
        let slot = match existing {
            Some(slot) => slot,
            None => self.cache.slot(&key, snapshot.fingerprint)?,
        };
        let _initialization = match slot.initialization.try_lock() {
            Ok(guard) => guard,
            Err(_) => tokio::select! {
                biased;
                () = original.cancelled() => {
                    return Err(original.check().err().unwrap_or_else(||
                        ApiError::new(ErrorCode::Unavailable, "The original model operation was cancelled")));
                }
                () = publication.cancelled() => {
                    return Err(publication.check_current().err().unwrap_or_else(source_scope_error));
                }
                guard = slot.initialization.lock() => guard,
            },
        };
        // Same fingerprint does not revive a retired generation after a wait.
        publication.check_current()?;
        if slot.answer.get().is_none() {
            let prepared = (|| -> Result<_, ScrubError> {
                let examples = if self.privacy && !self.config.examples_under_privacy {
                    Vec::new()
                } else {
                    examples(&matcher, Some(&current_scope))
                };
                let Some(body) = model_request(&self.config, prepared_target, &examples, req)?
                else {
                    return Ok(None);
                };
                Ok(Some(json_bytes(&body)?))
            })()
            .map_err(|error| ApiError::new(ErrorCode::SecretUnavailable, error.to_string()))?;
            drop(matcher);
            let mut job = None;
            let result: ModelResult = match prepared {
                None => Ok(None),
                Some(request_body) => {
                    let output = CompiledScrubber::new_output(
                        &patterns,
                        kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES,
                    )
                    .map_err(redact_error)?;
                    let request = ModelHttpAdmission::new(original.clone(), publication.clone());
                    let fetched = self.fetch_body(request_body, &request).await?;
                    job = Some(request);
                    match parse_model_reply(&fetched) {
                        None => {
                            return Err(ApiError::new(
                                ErrorCode::Internal,
                                "The model response is invalid",
                            ));
                        }
                        Some(answer) => {
                            let mut response = pb::HttpEffectResponse {
                                status: u32::from(answer.status),
                                headers: answer
                                    .headers
                                    .into_iter()
                                    .map(|(name, value)| pb::HeaderPair { name, value })
                                    .collect(),
                                body: answer.body.into_bytes(),
                            };
                            match kronik_sched::scrub::http_response(
                                &mut response,
                                &output,
                                1 << 20,
                            ) {
                                Err(error) => {
                                    response.body.zeroize();
                                    for header in &mut response.headers {
                                        header.name.zeroize();
                                        header.value.zeroize();
                                    }
                                    return Err(ApiError::new(
                                        ErrorCode::SecretUnavailable,
                                        error.to_string(),
                                    ));
                                }
                                Ok(()) => match String::from_utf8(response.body) {
                                    Err(error) => {
                                        let _bytes = Zeroizing::new(error.into_bytes());
                                        return Err(ApiError::new(
                                            ErrorCode::SecretUnavailable,
                                            ScrubError::InvalidText.to_string(),
                                        ));
                                    }
                                    Ok(body) => Ok(Some(ModelAnswer {
                                        status: answer.status,
                                        headers: response
                                            .headers
                                            .into_iter()
                                            .map(|header| (header.name, header.value))
                                            .collect(),
                                        body,
                                    })),
                                },
                            }
                        }
                    }
                }
            };
            let mut pending = Some(result);
            let mut repeated = false;
            let mut publish = || {
                let Some(result) = pending.take() else {
                    repeated = true;
                    return Err(ApiError {
                        code: ErrorCode::StorageCorrupt,
                        message: String::new(),
                        hint: None,
                    });
                };
                match slot.answer.set(result) {
                    Ok(()) => {
                        self.cache.dirty.store(true, Ordering::Release);
                        Ok(())
                    }
                    Err(
                        tokio::sync::SetError::AlreadyInitializedError(result)
                        | tokio::sync::SetError::InitializingError(result),
                    ) => {
                        pending = Some(result);
                        repeated = true;
                        Err(ApiError {
                            code: ErrorCode::StorageCorrupt,
                            message: String::new(),
                            hint: None,
                        })
                    }
                }
            };
            let admitted = match &job {
                Some(job) => job.admit(&mut publish),
                None => admit_model_data(original, publication, &mut publish)
                    .map_err(|denial| denial.error().clone()),
            };
            // Retired/unadmitted payloads and SetError values are kept until
            // after BOTH publication fences have been released.
            if let Some(result) = &mut pending {
                wipe_model_result(result);
            }
            if repeated {
                return Err(ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "The immutable model result was already initialized",
                ));
            }
            admitted?;
        }
        let saved = slot
            .answer
            .get()
            .cloned()
            .ok_or_else(|| unavailable("The model result is unavailable"))?;
        deliver_model_result(&source, original, saved)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_parse_and_requests_hide_sensitive_headers() {
        let reply = br#"{"choices":[{"message":{"content":"```json\n{\"status\": 201, \"headers\": {\"X-A\": \"1\"}, \"body\": {\"ok\": true}}\n```"}}]}"#;
        let a = parse_model_reply(reply).unwrap();
        assert_eq!(a.status, 201);
        assert_eq!(a.headers, vec![("x-a".into(), "1".into())]);
        assert_eq!(a.body, r#"{"ok":true}"#);
        assert!(parse_model_reply(br#"{"choices":[{"message":{"content":"no"}}]}"#).is_none());

        let cfg = ModelConfig {
            endpoint: "http://127.0.0.1:1/v1/chat/completions".into(),
            model: "m".into(),
            api_key: None,
            timeout: Duration::from_secs(1),
            max_examples: 2,
            examples_under_privacy: false,
        };
        let text_header = |n: &str, v: &str| pb::HttpEffectHeader {
            name: n.into(),
            value: Some(pb::http_effect_header::Value::Text(v.into())),
        };
        let req = pb::HttpEffectRequest {
            method: "post".into(),
            url: "https://api.example.com/v1/x?q=1".into(),
            headers: vec![
                text_header("Authorization", "Bearer t0p"),
                text_header("x-b", "2"),
            ],
            body: b"hello".to_vec(),
            ..Default::default()
        };
        let target = parse_url(&req.url).unwrap();
        let body = model_request(&cfg, &target, &[], &req)
            .unwrap()
            .unwrap()
            .to_string();
        assert!(!body.contains("t0p"));
        assert!(body.contains("x-b") && body.contains("hello"));
        let secret = pb::HttpEffectRequest {
            headers: vec![pb::HttpEffectHeader {
                name: "authorization".into(),
                value: Some(pb::http_effect_header::Value::Secret(pb::SecretRef {
                    name: "k".into(),
                    ..Default::default()
                })),
            }],
            ..req
        };
        assert!(
            model_request(&cfg, &target, &[], &secret)
                .unwrap()
                .is_none()
        );
    }

    fn plain(b: Vec<u8>) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(b)),
        })
    }

    fn exchange() -> pb::EffectRecord {
        pb::EffectRecord {
            kind: "http.fetch".into(),
            target: "http:h".into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(
                pb::HttpEffectRequest {
                    method: "GET".into(),
                    url: "https://h/x".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            response: plain(
                pb::HttpEffectResponse {
                    status: 200,
                    headers: vec![
                        pb::HeaderPair {
                            name: "Set-Cookie".into(),
                            value: "sid=abc".into(),
                        },
                        pb::HeaderPair {
                            name: "Content-Type".into(),
                            value: "text/plain".into(),
                        },
                    ],
                    body: b"ok".to_vec(),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        }
    }

    /// L4: examples show the model only the content type of a response.
    #[test]
    fn examples_keep_only_the_content_type() {
        let patterns: &[(&str, &[u8])] = &[];
        let matcher = CompiledScrubber::new(patterns, 0).unwrap();
        let ex = model_examples(&[(1, &exchange(), None)], 5, &matcher, Some(&[]));
        assert_eq!(
            ex[0]["response"]["headers"],
            serde_json::json!({"content-type": "text/plain"})
        );
    }

    /// N12-4: every credential header of main's list (kronik-core http)
    /// stays away from the model, not only `authorization` and friends.
    #[test]
    fn credential_headers_never_reach_the_model() {
        let text = |name: &str, value: &str| pb::HttpEffectHeader {
            name: name.into(),
            value: Some(pb::http_effect_header::Value::Text(value.into())),
        };
        let req = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://h/x".into(),
            headers: vec![
                text("X-Auth-Token", "tok-1"),
                text("X-Session-Id", "sess-1"),
                text("Api-Key", "key-1"),
                text("X-Client-Secret", "sec-1"),
                text("Accept", "application/json"),
            ],
            body: Vec::new(),
            ..Default::default()
        };
        let view = request_view(&req).unwrap();
        assert_eq!(
            view["headers"],
            serde_json::json!({"accept": "application/json"})
        );
    }

    /// N12-5: secret values are looked for in the raw values, so a secret
    /// with a quote (escaped in JSON) or past the cut of a long body still
    /// keeps an example out.
    #[test]
    fn examples_holding_a_secret_raw_are_left_out() {
        let secret: &[u8] = b"s\"q";
        let patterns = [("secret", secret)];
        let matcher = CompiledScrubber::new(&patterns, 1024).unwrap();
        let mut quoted = exchange();
        quoted.request = plain(
            pb::HttpEffectRequest {
                method: "GET".into(),
                url: "https://h/x".into(),
                headers: vec![pb::HttpEffectHeader {
                    name: "x-trace".into(),
                    value: Some(pb::http_effect_header::Value::Text("a s\"q b".into())),
                }],
                body: Vec::new(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut long = exchange();
        let mut body = vec![b'x'; 5000];
        body.extend_from_slice(secret);
        long.response = plain(
            pb::HttpEffectResponse {
                status: 200,
                headers: vec![],
                body,
            }
            .encode_to_vec(),
        );
        let ex = model_examples(
            &[(1, &quoted, None), (2, &long, None), (3, &exchange(), None)],
            5,
            &matcher,
            None,
        );
        assert_eq!(ex.len(), 1, "{ex:?}");
    }

    /// H9: a turn is a source of examples only when nothing in it has a
    /// subject and it ran no SQL.
    #[test]
    fn turns_with_personal_data_are_tainted() {
        let clean = pb::TurnRecord {
            effects: vec![exchange()],
            ..Default::default()
        };
        assert!(!turn_tainted(&clean));
        let mut write = clean.clone();
        write.writes.push(pb::StateWrite {
            op: pb::StateOp::Set as i32,
            key: "k".into(),
            value: Some(pb::Sealable {
                subject: Some("user:a".into()),
                value: Some(pb::sealable::Value::Plain(b"v".to_vec())),
            }),
        });
        assert!(turn_tainted(&write));
        let mut sql = clean.clone();
        sql.sql_schema.push(pb::SqlSchemaChange {
            statement: "CREATE TABLE t (a)".into(),
        });
        assert!(turn_tainted(&sql));
    }

    /// M3: a cache file that does not parse is an error, not an empty cache.
    #[test]
    fn a_corrupt_cache_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("simulator-cache.json");
        assert!(ModelCache::open(&path).unwrap().is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(ModelCache::open(&path).is_err());
    }

    #[test]
    fn an_invalid_cache_envelope_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let original = br#"{"http:h fp":{"status":200,"headers":[],"body":"old fact"}}"#;
        std::fs::write(&path, original).unwrap();
        assert!(ModelCache::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn stamped_cache_roundtrips_refusal_and_typed_failure_without_rewriting_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let cache = ModelCache::open(&path).unwrap();
        let source = [9; 32];
        let answer = ModelAnswer {
            status: 206,
            headers: Vec::new(),
            body: "[secret:E]".into(),
        };
        cache
            .slot("answer", source)
            .unwrap()
            .answer
            .set(Ok(Some(answer.clone())))
            .unwrap();
        cache
            .slot("refusal", source)
            .unwrap()
            .answer
            .set(Ok(None))
            .unwrap();
        cache
            .slot("failure", source)
            .unwrap()
            .answer
            .set(Err(ModelCacheError::Redaction(
                ScrubError::SourceScopeUnavailable,
            )))
            .unwrap();
        cache.save().unwrap();
        let original = std::fs::read(&path).unwrap();
        let reopened = ModelCache::read_only(&path).unwrap();
        assert_eq!(
            reopened.slot("answer", source).unwrap().answer.get(),
            Some(&Ok(Some(answer)))
        );
        assert_eq!(
            reopened.slot("refusal", source).unwrap().answer.get(),
            Some(&Ok(None))
        );
        assert_eq!(
            reopened.slot("failure", source).unwrap().answer.get(),
            Some(&Err(ModelCacheError::Redaction(
                ScrubError::SourceScopeUnavailable
            )))
        );
        assert!(reopened.slot("answer", [10; 32]).is_err());
        reopened.save().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), original);
    }

    #[tokio::test]
    async fn recorded_only_cache_checks_source_before_hit_and_never_creates_a_miss() {
        let cache = Arc::new(ModelCache::memory());
        let snapshot = Arc::new(Mutex::new(Arc::new(
            kronik_sched::secrets::CertifiedSecretSnapshot {
                values: Vec::new(),
                references: Some(Arc::from([])),
                fingerprint: [3; 32],
            },
        )));
        let source = snapshot.clone();
        let access = ModelAccess {
            config: ModelConfig {
                endpoint: "http://127.0.0.1:1/never-used".into(),
                model: "test".into(),
                api_key: None,
                timeout: Duration::from_secs(1),
                max_examples: 1,
                examples_under_privacy: false,
            },
            env: Env::real(tokio::runtime::Handle::current()),
            cache: cache.clone(),
            privacy: false,
            offline: true,
            secret_snapshot: Arc::new(move || {
                Ok(ModelSecretSnapshot::Recorded(lock(&source).clone()))
            }),
        };
        assert_eq!(access.cached_answer("http:h", &[1]).unwrap(), None);
        assert!(!access.has_cached_answer("http:h", &[1]).unwrap());
        assert_eq!(cache.len(), 0);
        let key = "http:h 01";
        cache
            .slot(key, [3; 32])
            .unwrap()
            .answer
            .set(Ok(None))
            .unwrap();
        assert_eq!(access.cached_answer("http:h", &[1]).unwrap(), Some(None));
        assert!(access.has_cached_answer("http:h", &[1]).unwrap());
        *lock(&snapshot) = Arc::new(kronik_sched::secrets::CertifiedSecretSnapshot {
            values: Vec::new(),
            references: Some(Arc::from([])),
            fingerprint: [4; 32],
        });
        assert!(access.cached_answer("http:h", &[1]).is_err());
        assert!(access.has_cached_answer("http:h", &[1]).is_err());
        assert_eq!(cache.len(), 1);
        assert_eq!(lock(&cache.slots)[key].answer.get(), Some(&Ok(None)));
    }

    #[test]
    fn json_writer_refuses_growth_before_allocation_and_does_not_lose_accepted_bytes() {
        let mut writer = JsonWriter {
            bytes: Vec::new(),
            limit: 4,
        };
        writer.write_all(b"1234").unwrap();
        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.bytes, b"1234");
    }

    #[test]
    fn neighbor_scope_contains_only_original_prefix_not_future_references() {
        let reference = |name: &str| pb::SecretRef {
            name: name.into(),
            version: 1,
            version_hash: vec![1; 16],
            ..Default::default()
        };
        let reveal = |ordinal, name| pb::EffectRecord {
            ordinal,
            kind: "secret.reveal".into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(
                pb::RevealEffectRequest {
                    secret: Some(reference(name)),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let mut source = exchange();
        source.ordinal = 2;
        let mut request =
            pb::HttpEffectRequest::decode(subject_free(source.request.as_ref()).unwrap()).unwrap();
        request.fingerprint_version = 2;
        source.request = plain(request.encode_to_vec());
        let mut turn = pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                    from_schema_version: 1,
                    to_schema_version: 2,
                })),
            }),
            effects: vec![reveal(1, "before"), source, reveal(3, "future")],
            ..Default::default()
        };
        let prefix =
            original_secret_prefix(turn.input.as_ref().unwrap(), &turn.effects, 2).unwrap();
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0].name, "before");
        turn.effects[0].request = None;
        assert!(original_secret_prefix(turn.input.as_ref().unwrap(), &turn.effects, 2).is_none());
        turn.effects = vec![exchange()];
        assert!(original_secret_prefix(turn.input.as_ref().unwrap(), &turn.effects, 0).is_none());
    }

    /// A neighbor hit stored for the fork log keeps the source effect's
    /// fingerprint and fingerprint version. A prefix that cannot be taken
    /// refuses the hit. A covering source prefix is what lets a matching
    /// body through; unknown scope is not that prefix.
    #[test]
    fn neighbor_hit_keeps_source_identity_not_a_fresh_fingerprint() {
        use kronik_effects::http::{CompiledScrubber, fingerprint_v2, prepared_target};
        use kronik_effects::simulator::{NeighborSource, RecordedNeighbor};
        use kronik_privacy::sealer::Sealer;

        let secret_value = b"sekret-value";
        let reference = |name: &str| pb::SecretRef {
            name: name.into(),
            version: 1,
            version_hash: vec![9; 16],
            ..Default::default()
        };
        let reveal = |ordinal, name: &str| pb::EffectRecord {
            ordinal,
            kind: "secret.reveal".into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(
                pb::RevealEffectRequest {
                    secret: Some(reference(name)),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let source_req = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://pay.example/v1/charges/1".into(),
            headers: vec![pb::HttpEffectHeader {
                name: "authorization".into(),
                value: Some(pb::http_effect_header::Value::Secret(pb::SecretRef {
                    name: "api-key".into(),
                    template: "Bearer {}".into(),
                    version: 1,
                    version_hash: vec![9; 16],
                    ..Default::default()
                })),
            }],
            body: br#"{"amount":5}"#.to_vec(),
            fingerprint_version: 2,
            ..Default::default()
        };
        let source_target = prepared_target(&source_req).unwrap();
        let source_fp = fingerprint_v2(&source_req, &source_target).unwrap();
        let source = pb::EffectRecord {
            ordinal: 2,
            kind: "http.fetch".into(),
            target: "http:pay.example".into(),
            fingerprint: source_fp.clone(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(source_req.encode_to_vec()),
            response: plain(
                pb::HttpEffectResponse {
                    status: 200,
                    body: secret_value.to_vec(),
                    headers: vec![pb::HeaderPair {
                        name: "x-echo".into(),
                        value: "sekret-value".into(),
                    }],
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let input = pb::Input {
            kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                from_schema_version: 1,
                to_schema_version: 2,
            })),
        };
        let effects = vec![reveal(1, "before"), source.clone(), reveal(3, "future")];
        let prefix = original_secret_prefix(&input, &effects, 2).unwrap();
        assert_eq!(
            prefix
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["before", "api-key"]
        );

        let neighbor = RecordedNeighbor::from_sources([NeighborSource {
            lsn: 7,
            effect: source.clone(),
            prefix: Some(prefix.clone()),
        }]);
        let fork_req = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://pay.example/v1/charges/9".into(),
            body: br#"{"amount":8}"#.to_vec(),
            fingerprint_version: 2,
            ..Default::default()
        };
        let fork_fp = fingerprint_v2(&fork_req, &prepared_target(&fork_req).unwrap()).unwrap();
        assert_ne!(fork_fp, source_fp);
        let hit = neighbor
            .find(&fork_req)
            .expect("the fork request is a neighbor");
        assert_eq!(hit.source.fingerprint, source_fp);
        assert_eq!(hit.prefix.map(|item| item.len()), Some(2));

        let patterns = [
            ("api-key", secret_value.as_slice()),
            ("before", b"before-value".as_slice()),
            ("future", b"later-value".as_slice()),
        ];
        let matcher = CompiledScrubber::new(&patterns, 1024).unwrap();
        let sealer = Sealer::plain();
        let disclosed = crate::replay::disclose_neighbor(
            &hit,
            4,
            "http.fetch",
            Some(prefix.as_ref()),
            &matcher,
            &sealer,
        )
        .unwrap();
        let crate::replay::NeighborDisclosure::Recorded(recorded) = disclosed else {
            panic!("a covered neighbor hit must be recorded");
        };
        let record = recorded.record;
        let outcome = recorded.outcome;
        assert_eq!(record.ordinal, 4);
        assert_eq!(record.simulator, "neighbor");
        assert_eq!(record.grounding, pb::Grounding::Synthetic as i32);
        assert_eq!(record.fingerprint, source_fp);
        assert_ne!(record.fingerprint, fork_fp);
        let stored =
            pb::HttpEffectRequest::decode(subject_free(record.request.as_ref()).unwrap()).unwrap();
        assert_eq!(stored.fingerprint_version, source_req.fingerprint_version);
        assert_eq!(stored.url, source_req.url);
        assert_ne!(stored.url, fork_req.url);
        let stored_secret = stored
            .headers
            .iter()
            .find_map(|header| match &header.value {
                Some(pb::http_effect_header::Value::Secret(secret)) => Some(secret),
                _ => None,
            });
        let stored_secret = stored_secret.expect("the source secret reference");
        assert_eq!(stored_secret.name, "api-key");
        assert_eq!(stored_secret.version, 1);
        assert_eq!(stored_secret.version_hash, vec![9; 16]);
        match outcome {
            kronik_runtime::FetchOutcome::Ok(response) => {
                assert_eq!(response.body, secret_value);
            }
            other => panic!("covered source bytes must stay unchanged, got {other:?}"),
        }

        let refused = RecordedNeighbor::from_sources([NeighborSource {
            lsn: 7,
            effect: source,
            prefix: None,
        }]);
        let refused_hit = refused.find(&fork_req).unwrap();
        assert!(matches!(
            crate::replay::disclose_neighbor(
                &refused_hit,
                4,
                "http.fetch",
                Some(prefix.as_ref()),
                &matcher,
                &sealer,
            )
            .unwrap(),
            crate::replay::NeighborDisclosure::Decline
        ));

        let future = [reference("future")];
        assert!(matches!(
            crate::replay::disclose_neighbor(
                &hit,
                4,
                "http.fetch",
                Some(&future),
                &matcher,
                &sealer
            ),
            Err(kronik_runtime::GateError::Prerequisite(
                kronik_core::error::ErrorCode::SecretUnavailable
            ))
        ));
    }

    /// A version-0 neighbor keeps the source fingerprint and is disclosed by
    /// the legacy verifier, not by a manufactured version-2 prefix.
    #[test]
    fn legacy_neighbor_hit_keeps_the_source_fingerprint_version() {
        use kronik_effects::http::{CompiledScrubber, fingerprint};
        use kronik_effects::simulator::{NeighborSource, RecordedNeighbor};
        use kronik_privacy::sealer::Sealer;

        let source_req = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "http://pay.example/v1/charges/1".into(),
            ..Default::default()
        };
        let source_fp = fingerprint(&source_req).unwrap();
        let source = pb::EffectRecord {
            ordinal: 1,
            kind: "http.fetch".into(),
            target: "http:pay.example".into(),
            fingerprint: source_fp.clone(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(source_req.encode_to_vec()),
            response: plain(
                pb::HttpEffectResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: b"recorded-body".to_vec(),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let neighbor = RecordedNeighbor::from_sources([NeighborSource {
            lsn: 3,
            effect: source,
            prefix: None,
        }]);
        let fork_req = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "http://pay.example/v1/charges/9".into(),
            ..Default::default()
        };
        let fork_fp = fingerprint(&fork_req).unwrap();
        assert_ne!(fork_fp, source_fp);
        let hit = neighbor.find(&fork_req).expect("legacy neighbor match");
        let patterns = [("other", b"not-in-the-body".as_slice())];
        let matcher = CompiledScrubber::new(&patterns, 1024).unwrap();
        let disclosed = crate::replay::disclose_neighbor(
            &hit,
            5,
            "http.fetch",
            None,
            &matcher,
            &Sealer::plain(),
        )
        .unwrap();
        let crate::replay::NeighborDisclosure::Recorded(recorded) = disclosed else {
            panic!("a verified legacy neighbor hit must be recorded");
        };
        assert_eq!(recorded.record.fingerprint, source_fp);
        assert_ne!(recorded.record.fingerprint, fork_fp);
        assert_eq!(recorded.record.simulator, "neighbor");
        let stored =
            pb::HttpEffectRequest::decode(subject_free(recorded.record.request.as_ref()).unwrap())
                .unwrap();
        assert_eq!(stored.fingerprint_version, 0);
        assert_eq!(stored.url, source_req.url);
        match recorded.outcome {
            kronik_runtime::FetchOutcome::Ok(response) => {
                assert_eq!(response.body, b"recorded-body");
            }
            other => panic!("clean legacy bytes must stay unchanged, got {other:?}"),
        }
    }

    #[test]
    fn prepared_model_capture_keeps_the_actual_producer_markers_and_typed_target() {
        let value = Arc::new(Zeroizing::new(b"e".to_vec()));
        let reference = pb::SecretRef {
            name: "upper".into(),
            version: 1,
            version_hash: vec![7; 16],
            ..Default::default()
        };
        let scope: Arc<[pb::SecretRef]> = Arc::from([reference]);
        let snapshot = kronik_sched::secrets::CertifiedSecretSnapshot {
            values: vec![("upper".into(), value)],
            references: Some(scope.clone()),
            fingerprint: [1; 32],
        };
        let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
        let matcher =
            CompiledScrubber::new(&patterns, kronik_sched::scrub::MAX_SECRET_PATTERN_BYTES)
                .unwrap();
        let mut request = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://example.test/e".into(),
            body: b"e".to_vec(),
            ..Default::default()
        };
        let original_url = Zeroizing::new(std::mem::take(&mut request.url));
        let (original, raw_host) = parse_request_url(&original_url).unwrap();
        let target =
            kronik_sched::scrub::http_request(&mut request, &original, raw_host, &matcher, 4096)
                .unwrap();
        assert!(
            matcher.is_match(&request.body),
            "the generated marker deliberately overlaps a needle"
        );
        let current = model_scope(&snapshot, Some(&scope)).unwrap();
        prepared_request_safe(&request, &target, &matcher, Some(&current), Some(&scope)).unwrap();
        let config = ModelConfig {
            endpoint: "http://127.0.0.1:1/unused".into(),
            model: "m".into(),
            api_key: None,
            timeout: Duration::from_secs(1),
            max_examples: 1,
            examples_under_privacy: false,
        };
        let captured = model_request(&config, &target, &[], &request)
            .unwrap()
            .unwrap();
        let content: serde_json::Value =
            serde_json::from_str(captured["messages"][1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(content["request"]["body"], "[secret:upper]");
        assert_eq!(content["request"]["url"], request.url);
        assert!(
            captured["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains(&target.host)
        );
        assert_eq!(request.body, b"[secret:upper]");
    }

    #[test]
    fn new_identity_ambiguity_is_a_prerequisite_before_a_model_slot_exists() {
        let old = pb::SecretRef {
            name: "old".into(),
            version: 1,
            version_hash: vec![1; 16],
            ..Default::default()
        };
        let new = pb::SecretRef {
            name: "new".into(),
            version: 1,
            version_hash: vec![2; 16],
            ..Default::default()
        };
        let previous_scope = [old.clone()];
        let previous_values = [("old", b"a".as_slice())];
        let previous_matcher = CompiledScrubber::new(&previous_values, 1024).unwrap();
        let mut request = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "http://h/".into(),
            body: b"a".to_vec(),
            ..Default::default()
        };
        let original_url = Zeroizing::new(std::mem::take(&mut request.url));
        let (original, raw_host) = parse_request_url(&original_url).unwrap();
        let target = kronik_sched::scrub::http_request(
            &mut request,
            &original,
            raw_host,
            &previous_matcher,
            4096,
        )
        .unwrap();
        let snapshot = kronik_sched::secrets::CertifiedSecretSnapshot {
            values: vec![
                ("old".into(), Arc::new(Zeroizing::new(b"a".to_vec()))),
                ("new".into(), Arc::new(Zeroizing::new(b"secret".to_vec()))),
            ],
            references: Some(Arc::from([old, new])),
            fingerprint: [2; 32],
        };
        let current = model_scope(&snapshot, Some(&previous_scope)).unwrap();
        let patterns = kronik_sched::effects::secret_patterns(&snapshot.values);
        let matcher = CompiledScrubber::new(&patterns, 1024).unwrap();
        let cache = ModelCache::memory();
        assert_eq!(
            prepared_request_safe(
                &request,
                &target,
                &matcher,
                Some(&current),
                Some(&previous_scope)
            ),
            Err(ScrubError::SourceScopeUnavailable)
        );
        assert!(cache.is_empty());
        assert_eq!(request.body, b"[secret:old]");
        assert!(model_scope(&snapshot, None).is_err());
    }

    #[test]
    fn prepared_examples_use_the_actual_original_prefix_without_rematching_markers() {
        let reference = pb::SecretRef {
            name: "upper".into(),
            version: 1,
            version_hash: vec![7; 16],
            ..Default::default()
        };
        let scope: Arc<[pb::SecretRef]> = Arc::from([reference.clone()]);
        let patterns = [("upper", b"e".as_slice())];
        let matcher = CompiledScrubber::new(&patterns, 1024).unwrap();
        let mut request = pb::HttpEffectRequest {
            method: "POST".into(),
            url: "https://example.test/e".into(),
            body: b"e".to_vec(),
            ..Default::default()
        };
        let original_url = Zeroizing::new(std::mem::take(&mut request.url));
        let (original, raw_host) = parse_request_url(&original_url).unwrap();
        let target =
            kronik_sched::scrub::http_request(&mut request, &original, raw_host, &matcher, 4096)
                .unwrap();
        let reveal = pb::EffectRecord {
            ordinal: 1,
            kind: "secret.reveal".into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(
                pb::RevealEffectRequest {
                    secret: Some(reference),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let source = pb::EffectRecord {
            ordinal: 2,
            kind: "http.fetch".into(),
            target: "http:example.test".into(),
            status: pb::EffectStatus::Ok as i32,
            request: plain(request.encode_to_vec()),
            response: plain(
                pb::HttpEffectResponse {
                    status: 200,
                    body: b"[secret:upper]".to_vec(),
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        let turn = pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Migrate(pb::MigrateInput {
                    from_schema_version: 1,
                    to_schema_version: 2,
                })),
            }),
            effects: vec![reveal, source],
            ..Default::default()
        };
        let prefix =
            original_secret_prefix(turn.input.as_ref().unwrap(), &turn.effects, 2).unwrap();
        let examples = model_examples(
            &[(2, &turn.effects[1], Some(prefix))],
            1,
            &matcher,
            Some(&scope),
        );
        assert_eq!(examples.len(), 1);
        assert_eq!(examples[0]["request"]["url"], request.url);
        assert_eq!(examples[0]["request"]["body"], "[secret:upper]");
        assert_eq!(examples[0]["response"]["body"], "[secret:upper]");
        assert_eq!(
            kronik_effects::http::prepared_target(&request).unwrap(),
            target
        );
        assert!(
            model_examples(&[(2, &turn.effects[1], None)], 1, &matcher, Some(&scope)).is_empty()
        );
    }
}

#[cfg(test)]
mod publication_tests;
