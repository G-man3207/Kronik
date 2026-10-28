//! Effect simulators (brief, "Simulator-trait"): where an effect's result
//! comes from when it is not performed live. Crash re-runs and forks ask a
//! simulator first; v0.1 has `RecordedMatch` and `FailClosed` (`StubRules`
//! arrives with forks in M3). M12 adds `ContractFake` and
//! `RecordedNeighbor` here; the model simulator, which needs the network,
//! is in `kronik-fork` (docs/design/m12-simulators.md).

use kronik_proto::log::v1 as pb;
use prost::Message as _;

use crate::contract::Contract;
use crate::http::{parse_url, target_of};

/// The labels of synthetic answers (`EffectRecord.simulator`).
pub mod label {
    pub const STUB: &str = "stub";
    pub const CONTRACT: &str = "contract";
    pub const NEIGHBOR: &str = "neighbor";
    pub const MODEL: &str = "model";
    pub const FAIL_CLOSED: &str = "fail-closed";
    /// A fork's `secret.reveal` where production revealed nothing at that
    /// point: the placeholder `[secret:<name>]`, never the value.
    pub const PLACEHOLDER: &str = "placeholder";
}

/// An effect as seen by a simulator.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectRequest {
    pub ordinal: u32,
    pub kind: String,
    pub target: String,
    pub fingerprint: Vec<u8>,
    /// The HTTP request, for simulators that answer from its content
    /// (forks); `None` for crash re-runs and non-HTTP effects.
    pub http: Option<pb::HttpEffectRequest>,
}

/// A simulated result: the record to hand to the guest.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectResponse {
    pub record: pb::EffectRecord,
}

/// What the simulator may look at: the recorded effects of the matching
/// turn.
pub struct ReplayContext<'a> {
    pub recorded: &'a [pb::EffectRecord],
}

/// The answer when a recorded effect exists at the ordinal but its
/// fingerprint differs: the replay diverged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diverged {
    pub ordinal: u32,
}

pub trait EffectSimulator: Send + Sync {
    fn respond(&self, req: &EffectRequest, ctx: &ReplayContext<'_>) -> Option<EffectResponse>;
}

/// Answers with the recorded result for the same ordinal and fingerprint,
/// marked with `grounding` (`LIVE` for crash re-runs of the same execution,
/// `EXACT` in forks).
pub struct RecordedMatch {
    pub grounding: pb::Grounding,
}

impl RecordedMatch {
    /// Like `respond`, but tells a fingerprint mismatch apart from a missing
    /// record.
    pub fn lookup(
        &self,
        req: &EffectRequest,
        ctx: &ReplayContext<'_>,
    ) -> Result<Option<EffectResponse>, Diverged> {
        let Some(rec) = ctx.recorded.iter().find(|r| r.ordinal == req.ordinal) else {
            return Ok(None);
        };
        if rec.kind != req.kind || rec.fingerprint != req.fingerprint {
            return Err(Diverged {
                ordinal: req.ordinal,
            });
        }
        let mut record = rec.clone();
        record.grounding = self.grounding as i32;
        Ok(Some(EffectResponse { record }))
    }
}

impl EffectSimulator for RecordedMatch {
    fn respond(&self, req: &EffectRequest, ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        self.lookup(req, ctx).ok().flatten()
    }
}

/// Never answers: an effect without a recording is denied (forks, I7).
pub struct FailClosed;

impl EffectSimulator for FailClosed {
    fn respond(&self, _req: &EffectRequest, _ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        None
    }
}

/// The largest OpenAPI document a `SimulatorConfig` may carry.
pub const MAX_CONTRACT_BYTES: usize = 1 << 20;

/// Validates a `SimulatorConfig` before it is written
/// (docs/design/m12-simulators.md §2).
pub fn check_config(m: &pb::SimulatorConfig) -> Result<(), String> {
    let (scheme, host) = m
        .target
        .split_once(':')
        .filter(|(s, h)| matches!(*s, "http" | "foreign") && !h.is_empty())
        .ok_or_else(|| {
            format!(
                "{:?} is not a target (http:<host> or foreign:<name>)",
                m.target
            )
        })?;
    if host.contains('*') || host.contains('/') || host != host.to_ascii_lowercase() {
        return Err(format!(
            "target host {host:?} must be one lowercase host name, without wildcards"
        ));
    }
    let schemes: &[&str] = if scheme == "http" {
        &["http://", "https://"]
    } else {
        &["foreign://"]
    };
    for r in &m.stubs {
        let rest = schemes
            .iter()
            .find_map(|s| r.url_prefix.strip_prefix(s))
            .ok_or_else(|| {
                format!(
                    "stub url_prefix {:?} must start with {}{host}",
                    r.url_prefix, schemes[0]
                )
            })?;
        let on_host = rest
            .strip_prefix(host)
            .is_some_and(|after| after.is_empty() || after.starts_with(['/', ':', '?']));
        if !on_host {
            return Err(format!(
                "stub url_prefix {:?} is not on the target's host {host}",
                r.url_prefix
            ));
        }
        if !r.error.is_empty()
            && !matches!(
                r.error.as_str(),
                "network" | "timeout" | "too-large" | "denied"
            )
        {
            return Err(format!(
                "stub error must be network, timeout, too-large or denied, not {:?}",
                r.error
            ));
        }
        if r.error.is_empty() && !(100..=599).contains(&r.status) {
            return Err(format!("stub status {} is not an HTTP status", r.status));
        }
    }
    if m.contract.len() > MAX_CONTRACT_BYTES {
        return Err(format!(
            "the contract is {} bytes; at most {MAX_CONTRACT_BYTES}",
            m.contract.len()
        ));
    }
    if !m.contract.is_empty() {
        Contract::parse(&m.contract)?;
    }
    Ok(())
}

/// A synthetic OK answer with an HTTP response, labeled `simulator`.
fn synthetic_http(
    req: &EffectRequest,
    simulator: &str,
    response: pb::HttpEffectResponse,
) -> EffectResponse {
    EffectResponse {
        record: pb::EffectRecord {
            ordinal: req.ordinal,
            kind: req.kind.clone(),
            target: req.target.clone(),
            fingerprint: req.fingerprint.clone(),
            status: pb::EffectStatus::Ok as i32,
            grounding: pb::Grounding::Synthetic as i32,
            simulator: simulator.into(),
            response: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(response.encode_to_vec())),
            }),
            ..Default::default()
        },
    }
}

/// Schema-valid answers from a target's OpenAPI document, the same bytes
/// for the same request (docs/design/m12-simulators.md §3.1, ADR 0016).
pub struct ContractFake {
    pub contract: Contract,
}

impl EffectSimulator for ContractFake {
    fn respond(&self, req: &EffectRequest, _ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        let http = req.http.as_ref()?;
        let mut seed = req.target.as_bytes().to_vec();
        seed.push(0);
        seed.extend_from_slice(&req.fingerprint);
        let a = self.contract.answer(&http.method, &http.url, &seed)?;
        Some(synthetic_http(
            req,
            label::CONTRACT,
            pb::HttpEffectResponse {
                status: u32::from(a.status),
                headers: vec![pb::HeaderPair {
                    name: "content-type".into(),
                    value: "application/json".into(),
                }],
                body: a.body,
            },
        ))
    }
}

/// One recorded exchange `RecordedNeighbor` may reuse.
struct Neighbor {
    lsn: u64,
    ordinal: u32,
    target: (String, String, String),
    items: std::collections::BTreeSet<Vec<u8>>,
    response: pb::HttpEffectResponse,
}

/// The recorded answer of the most similar recorded request to the same
/// route (docs/design/m12-simulators.md §3.2).
#[derive(Default)]
pub struct RecordedNeighbor {
    candidates: Vec<Neighbor>,
}

fn plain_bytes(s: Option<&pb::Sealable>) -> Option<&[u8]> {
    let s = s?;
    if s.subject.is_some() {
        return None;
    }
    match s.value.as_ref()? {
        pb::sealable::Value::Plain(b) => Some(b),
        pb::sealable::Value::Sealed(_) => None,
    }
}

/// The comparable items of a request: path segments by position, query
/// parameters, and the JSON body's leaves (or the body's hash).
fn items(req: &pb::HttpEffectRequest) -> std::collections::BTreeSet<Vec<u8>> {
    fn leaves(v: &serde_json::Value, path: &str, out: &mut std::collections::BTreeSet<Vec<u8>>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    leaves(x, &format!("{path}/{k}"), out);
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    leaves(x, &format!("{path}/{i}"), out);
                }
            }
            leaf => {
                out.insert(format!("b{path}={leaf}").into_bytes());
            }
        }
    }
    let mut out = std::collections::BTreeSet::new();
    if let Ok(t) = parse_url(&req.url) {
        for (i, seg) in t.path.split('/').enumerate() {
            out.insert(format!("p{i}={seg}").into_bytes());
        }
        for q in t.query.split('&').filter(|q| !q.is_empty()) {
            out.insert(format!("q{q}").into_bytes());
        }
    }
    match serde_json::from_slice::<serde_json::Value>(&req.body) {
        Ok(v) => leaves(&v, "", &mut out),
        Err(_) if !req.body.is_empty() => {
            let mut h = b"h".to_vec();
            h.extend_from_slice(blake3::hash(&req.body).as_bytes());
            out.insert(h);
        }
        Err(_) => {}
    }
    out
}

impl RecordedNeighbor {
    /// Candidates from recorded effects `(lsn, record)`: HTTP effects with
    /// status OK whose request and response are plain without a subject.
    pub fn new(records: impl IntoIterator<Item = (u64, pb::EffectRecord)>) -> RecordedNeighbor {
        let mut candidates = Vec::new();
        for (lsn, e) in records {
            if !matches!(e.kind.as_str(), "http.fetch" | "foreign.http")
                || e.status != pb::EffectStatus::Ok as i32
            {
                continue;
            }
            let Some(req) =
                plain_bytes(e.request.as_ref()).and_then(|b| pb::HttpEffectRequest::decode(b).ok())
            else {
                continue;
            };
            let Some(response) = plain_bytes(e.response.as_ref())
                .and_then(|b| pb::HttpEffectResponse::decode(b).ok())
            else {
                continue;
            };
            let Some(target) = target_of(&req) else {
                continue;
            };
            candidates.push(Neighbor {
                lsn,
                ordinal: e.ordinal,
                target,
                items: items(&req),
                response,
            });
        }
        RecordedNeighbor { candidates }
    }

    /// The most similar candidate's response: most equal items, then the
    /// highest LSN, then the lowest ordinal.
    pub fn find(&self, req: &pb::HttpEffectRequest) -> Option<&pb::HttpEffectResponse> {
        let target = target_of(req)?;
        let mine = items(req);
        self.candidates
            .iter()
            .filter(|c| c.target == target)
            .max_by(|a, b| {
                let sa = a.items.intersection(&mine).count();
                let sb = b.items.intersection(&mine).count();
                sa.cmp(&sb)
                    .then(a.lsn.cmp(&b.lsn))
                    .then(b.ordinal.cmp(&a.ordinal))
            })
            .map(|c| &c.response)
    }
}

impl EffectSimulator for RecordedNeighbor {
    fn respond(&self, req: &EffectRequest, _ctx: &ReplayContext<'_>) -> Option<EffectResponse> {
        let response = self.find(req.http.as_ref()?)?.clone();
        Some(synthetic_http(req, label::NEIGHBOR, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_match_by_ordinal_and_fingerprint() {
        let rec = pb::EffectRecord {
            ordinal: 2,
            kind: "http.fetch".into(),
            fingerprint: vec![1],
            grounding: pb::Grounding::Live as i32,
            ..Default::default()
        };
        let ctx = ReplayContext {
            recorded: std::slice::from_ref(&rec),
        };
        let m = RecordedMatch {
            grounding: pb::Grounding::Exact,
        };
        let req = |ordinal, fp: u8| EffectRequest {
            ordinal,
            kind: "http.fetch".into(),
            target: "http:x".into(),
            fingerprint: vec![fp],
            http: None,
        };
        let hit = m.lookup(&req(2, 1), &ctx).unwrap().unwrap();
        assert_eq!(hit.record.grounding, pb::Grounding::Exact as i32);
        assert!(m.lookup(&req(3, 1), &ctx).unwrap().is_none());
        assert_eq!(m.lookup(&req(2, 9), &ctx), Err(Diverged { ordinal: 2 }));
        assert!(FailClosed.respond(&req(2, 1), &ctx).is_none());
    }

    fn recorded(lsn: u64, url: &str, body: &str, answer: &str) -> (u64, pb::EffectRecord) {
        let plain = |b: Vec<u8>| {
            Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(b)),
            })
        };
        (
            lsn,
            pb::EffectRecord {
                ordinal: 1,
                kind: "http.fetch".into(),
                status: pb::EffectStatus::Ok as i32,
                request: plain(
                    pb::HttpEffectRequest {
                        method: "POST".into(),
                        url: url.into(),
                        headers: vec![],
                        body: body.as_bytes().to_vec(),
                    }
                    .encode_to_vec(),
                ),
                response: plain(
                    pb::HttpEffectResponse {
                        status: 200,
                        headers: vec![],
                        body: answer.as_bytes().to_vec(),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
        )
    }

    #[test]
    fn neighbor_picks_the_most_similar_request_on_the_route() {
        let mut sealed = recorded(9, "http://a/v1/charges/1", r#"{"amount": 5}"#, "sealed");
        sealed.1.response = Some(pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Plain(b"x".to_vec())),
        });
        let n = RecordedNeighbor::new([
            recorded(
                1,
                "http://a/v1/charges/1",
                r#"{"amount": 5, "currency": "sek"}"#,
                "five-sek",
            ),
            recorded(
                2,
                "http://a/v1/charges/2",
                r#"{"amount": 7, "currency": "eur"}"#,
                "seven",
            ),
            recorded(
                3,
                "http://a/v1/refunds/2",
                r#"{"amount": 5, "currency": "sek"}"#,
                "refund",
            ),
            sealed,
        ]);
        let req = |url: &str, body: &str| pb::HttpEffectRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![],
            body: body.as_bytes().to_vec(),
        };
        let body = |r: Option<&pb::HttpEffectResponse>| {
            r.map(|r| String::from_utf8_lossy(&r.body).into_owned())
        };
        assert_eq!(
            body(n.find(&req(
                "http://a/v1/charges/3",
                r#"{"amount": 5, "currency": "sek"}"#
            ))),
            Some("five-sek".into())
        );
        assert_eq!(
            body(n.find(&req(
                "http://a/v1/charges/3",
                r#"{"amount": 7, "currency": "eur"}"#
            ))),
            Some("seven".into())
        );
        // Ties: the latest recording.
        assert_eq!(
            body(n.find(&req("http://a/v1/charges/3", "{}"))),
            Some("seven".into())
        );
        assert!(n.find(&req("http://b/v1/charges/3", "{}")).is_none());
    }
}
