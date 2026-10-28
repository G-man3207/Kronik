//! M12 effect simulators in a replay (docs/design/m12-simulators.md): the
//! per-target configuration main had at the fork point (I5, ADR 0014) plus
//! the overrides the replay request carries, `ContractFake` and
//! `RecordedNeighbor` from `kronik-effects`, and the `ModelSimulator` with
//! its per-proposal cache (ADR 0015).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_effects::contract::Contract;
use kronik_effects::http::{parse_url, route_pattern};
use kronik_effects::simulator::{ContractFake, RecordedNeighbor};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use prost::Message as _;
use serde::{Deserialize, Serialize};

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
    /// first: `RecordedNeighbor`'s candidates.
    pub fn recorded(index: &ProductionIndex, target: &str) -> Vec<(Lsn, pb::EffectRecord)> {
        Self::recorded_where(index, target, |_| true)
    }

    /// The recorded effects the model may learn from: only those of turns
    /// that show no personal data anywhere (no subject or sealed value in
    /// the input, effects, writes, messages, timers, reply or SQL, and no
    /// SQL at all). State reads are not recorded, so this is not enough
    /// under privacy mode (see [`ModelAccess::privacy`]).
    pub fn model_sources(index: &ProductionIndex, target: &str) -> Vec<(Lsn, pb::EffectRecord)> {
        Self::recorded_where(index, target, |t| !turn_tainted(t))
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

    pub fn neighbor(&self, index: &ProductionIndex, target: &str) -> Arc<RecordedNeighbor> {
        let mut n = lock(&self.neighbors);
        n.entry(target.to_owned())
            .or_insert_with(|| Arc::new(RecordedNeighbor::new(Self::recorded(index, target))))
            .clone()
    }
}

/// Whether a production turn shows personal data or SQL anywhere.
fn turn_tainted(t: &pb::TurnRecord) -> bool {
    if !t.sql_changes.is_empty() || !t.sql_schema.is_empty() {
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

type Slot = Arc<tokio::sync::OnceCell<Option<ModelAnswer>>>;

/// Model answers of one proposal by (target, fingerprint), loaded from and
/// saved to `branches/<id>/simulator-cache.json`. Workers that ask for the
/// same key at once share one call.
#[derive(Default)]
pub struct ModelCache {
    path: Option<PathBuf>,
    slots: Mutex<BTreeMap<String, Slot>>,
}

#[derive(Serialize, Deserialize, Default)]
struct CacheFile {
    /// key -> answer (`null` for a refusal).
    answers: BTreeMap<String, Option<ModelAnswer>>,
}

impl ModelCache {
    /// The cache at `path`, with what an earlier replay saved. A file that
    /// cannot be read or parsed is an error: answering again would silently
    /// change the proposal's diff.
    pub fn open(path: &Path) -> Result<ModelCache, String> {
        let file: CacheFile = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("{}: not a model cache: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => CacheFile::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let slots = file
            .answers
            .into_iter()
            .map(|(k, v)| (k, Arc::new(tokio::sync::OnceCell::new_with(Some(v)))))
            .collect();
        Ok(ModelCache {
            path: Some(path.to_owned()),
            slots: Mutex::new(slots),
        })
    }

    /// What an earlier replay saved at `path`, never written back (dry runs).
    pub fn read_only(path: &Path) -> Result<ModelCache, String> {
        let mut c = ModelCache::open(path)?;
        c.path = None;
        Ok(c)
    }

    /// An in-memory cache (tests, a fork without a directory).
    pub fn memory() -> ModelCache {
        ModelCache::default()
    }

    fn slot(&self, key: &str) -> Slot {
        lock(&self.slots).entry(key.to_owned()).or_default().clone()
    }

    /// Writes every answer obtained so far, durably.
    pub fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let answers: BTreeMap<String, Option<ModelAnswer>> = lock(&self.slots)
            .iter()
            .filter_map(|(k, v)| v.get().map(|a| (k.clone(), a.clone())))
            .collect();
        let bytes = serde_json::to_vec_pretty(&CacheFile { answers }).map_err(|e| e.to_string())?;
        crate::write_atomic(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// How many keys the cache holds.
    pub fn len(&self) -> usize {
        lock(&self.slots).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// The node's secrets: a request that holds one is never sent, and an
    /// answer is scrubbed of them before it is cached (I8).
    pub secrets: Option<Arc<kronik_privacy::SecretStore>>,
    /// A dry run (I12): answers come from the cache only; a miss is a
    /// refusal without a call.
    pub offline: bool,
}

/// The longest body of an example or the request sent to the model.
const MAX_BODY: usize = 4096;

fn text(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    s.chars().take(MAX_BODY).collect()
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
                    headers.insert(h.name.to_ascii_lowercase(), v.clone());
                }
            }
            // A secret header (I8): never described to the model.
            _ => return None,
        }
    }
    let t = parse_url(&req.url).ok()?;
    let port = t.port.map(|p| format!(":{p}")).unwrap_or_default();
    let query = if t.query.is_empty() {
        String::new()
    } else {
        format!("?{}", t.query)
    };
    Some(serde_json::json!({
        "method": req.method.to_ascii_uppercase(),
        "url": format!("{}://{}{port}{}{query}", t.scheme, t.host, t.path),
        "headers": headers,
        "body": text(&req.body),
    }))
}

/// Whether a request holds a secret value anywhere, scanned raw (before
/// any encoding or truncation): its URL, text header values and body.
fn request_holds(req: &pb::HttpEffectRequest, holds: &dyn Fn(&[u8]) -> bool) -> bool {
    holds(req.url.as_bytes())
        || holds(&req.body)
        || req.headers.iter().any(|h| match &h.value {
            Some(pb::http_effect_header::Value::Text(v)) => holds(v.as_bytes()),
            _ => false,
        })
}

/// Recorded exchanges with a target that the model may see (subject-free,
/// plain, no secret value per `holds`), newest first, at most `max`.
pub fn model_examples(
    recorded: &[(Lsn, pb::EffectRecord)],
    max: usize,
    holds: &dyn Fn(&[u8]) -> bool,
) -> Vec<serde_json::Value> {
    recorded
        .iter()
        .filter(|(_, e)| e.status == pb::EffectStatus::Ok as i32)
        .filter_map(|(_, e)| {
            let req = pb::HttpEffectRequest::decode(subject_free(e.request.as_ref())?).ok()?;
            let resp = pb::HttpEffectResponse::decode(subject_free(e.response.as_ref())?).ok()?;
            if request_holds(&req, holds)
                || holds(&resp.body)
                || resp.headers.iter().any(|h| holds(h.value.as_bytes()))
            {
                return None;
            }
            let request = request_view(&req)?;
            Some(serde_json::json!({
                "request": request,
                "response": {
                    "status": resp.status,
                    // Only the content type: cookies and other headers are
                    // not the model's business.
                    "headers": resp.headers.iter()
                        .filter(|h| h.name.eq_ignore_ascii_case("content-type"))
                        .map(|h| (h.name.to_ascii_lowercase(), h.value.clone()))
                        .collect::<BTreeMap<_, _>>(),
                    "body": text(&resp.body),
                },
            }))
        })
        .take(max)
        .collect()
}

/// The chat completions request for one effect, or `None` when the request
/// may not be shown (a secret header).
pub fn model_request(
    config: &ModelConfig,
    target: &str,
    examples: &[serde_json::Value],
    req: &pb::HttpEffectRequest,
) -> Option<serde_json::Value> {
    let request = request_view(req)?;
    let route = parse_url(&req.url)
        .map(|t| route_pattern(&t.path))
        .unwrap_or_default();
    let system = format!(
        "You simulate the HTTP API {target} for a deterministic replay. Answer the \
         request with one JSON object and nothing else: {{\"status\": <int>, \
         \"headers\": {{<name>: <value>}}, \"body\": <string>}}. Follow the recorded \
         examples for this API (route {route}) as closely as possible."
    );
    let user = serde_json::json!({ "examples": examples, "request": request });
    Some(serde_json::json!({
        "model": config.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user.to_string()},
        ],
    }))
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

impl ModelAccess {
    /// The model's answer for `req` to `target`, from the cache or one call.
    /// `examples` is computed only on a cache miss, and not at all under
    /// privacy mode without `examples_under_privacy`. A request holding a
    /// secret's value is never sent (a refusal), and an answer is scrubbed
    /// of secret values before it is cached.
    pub async fn answer(
        &self,
        target: &str,
        fingerprint: &[u8],
        req: &pb::HttpEffectRequest,
        examples: impl FnOnce(&dyn Fn(&[u8]) -> bool) -> Vec<serde_json::Value>,
    ) -> Option<ModelAnswer> {
        let key = format!("{target} {}", hex(fingerprint));
        let slot = self.cache.slot(&key);
        slot.get_or_init(|| async {
            let secrets = match &self.secrets {
                Some(s) => s.values().ok()?,
                None => Vec::new(),
            };
            // Raw values are scanned, before JSON encoding and truncation
            // could hide a secret that holds quotes, backslashes or control
            // characters, or that sits past the cut.
            let holds_secret = |b: &[u8]| kronik_effects::http::scrub(b, &secrets) != b;
            if request_holds(req, &holds_secret) {
                return None;
            }
            let examples = if self.privacy && !self.config.examples_under_privacy {
                Vec::new()
            } else {
                examples(&holds_secret)
            };
            if self.offline {
                return None;
            }
            let body = model_request(&self.config, target, &examples, req)?;
            let body = serde_json::to_vec(&body).ok()?;
            let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
            if let Some(k) = &self.config.api_key {
                headers.push(("authorization".to_owned(), format!("Bearer {k}")));
            }
            let call = self.env.net.http(kronik_core::env::HttpRequest {
                method: "POST".into(),
                url: self.config.endpoint.clone(),
                headers,
                body: body.into(),
                max_response_bytes: 1 << 20,
            });
            let resp = self
                .env
                .timeout(self.config.timeout, call)
                .await
                .ok()?
                .ok()?;
            if !(200..300).contains(&resp.status) {
                return None;
            }
            let mut a = parse_model_reply(&resp.body)?;
            let scrub = |s: &str| kronik_effects::http::scrub_str(s, &secrets);
            a.body = scrub(&a.body);
            for (_, v) in &mut a.headers {
                *v = scrub(v);
            }
            Some(a)
        })
        .await
        .clone()
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
        };
        let body = model_request(&cfg, "http:api.example.com", &[], &req)
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
        assert!(model_request(&cfg, "http:api.example.com", &[], &secret).is_none());
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
        let ex = model_examples(&[(1, exchange())], 5, &|_| false);
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
        let holds = |b: &[u8]| b.windows(secret.len()).any(|w| w == secret);
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
        let ex = model_examples(&[(1, quoted), (2, long), (3, exchange())], 5, &holds);
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
        let dir = std::env::temp_dir().join(format!("kronik-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("simulator-cache.json");
        assert!(ModelCache::open(&path).unwrap().is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(ModelCache::open(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
