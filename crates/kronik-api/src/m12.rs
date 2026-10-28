//! The M12 endpoints: effect simulators (docs/design/m12-simulators.md §6).

use kronik_core::error::{ApiError, ErrorCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Api, ApiRequest, ApiResponse, Result, json, ok, reason};

/// `PUT /v1/simulators/{target}`: the target's whole simulator
/// configuration; everything empty or false clears it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulatorsSetRequest {
    /// Stub rules, tried in order: `[{"method", "url_prefix", "status",
    /// "headers", "body"} | {"url_prefix", "error": "network" | "timeout" |
    /// "too-large" | "denied"}]`. Each `url_prefix` must be on the target.
    #[serde(default)]
    #[schemars(with = "Vec<serde_json::Map<String, serde_json::Value>>")]
    pub stubs: Vec<kronik_fork::stubs::StubRule>,
    /// An OpenAPI 3 document (JSON) for contract fakes; null for none.
    #[serde(default)]
    pub contract: Option<serde_json::Value>,
    /// Reuse the most similar recorded request to the same route.
    #[serde(default)]
    pub neighbor: bool,
    /// Allow the model simulator (it also needs `[simulators.model]`).
    #[serde(default)]
    pub model: bool,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SimulatorsSetResponse {
    pub dry_run: bool,
    pub target: String,
    pub epoch: u64,
    /// 0 for a dry run.
    pub lsn: u64,
}

/// One simulator Kronik has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SimulatorInfo {
    /// `recorded`, `stub`, `contract`, `neighbor`, `model`, `fail-closed`,
    /// `placeholder`.
    pub name: String,
    /// `recorded` (exact and approximate matches) or `synthetic`.
    pub grounding: String,
    pub description: String,
}

/// The contract of a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContractView {
    /// The document's `info.title`.
    pub title: Option<String>,
    /// BLAKE3 of the document, `b3:` + hex.
    pub digest: String,
    pub bytes: u64,
}

/// A target's simulator configuration in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetSimulatorsView {
    pub target: String,
    /// The number of stub rules.
    pub stubs: u64,
    pub contract: Option<ContractView>,
    pub neighbor: bool,
    pub model: bool,
    pub epoch: u64,
    pub lsn: u64,
    pub reason: String,
}

/// The server's model simulator (`[simulators.model]`); never the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ModelView {
    pub configured: bool,
    /// The endpoint's host, when configured.
    pub endpoint_host: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SimulatorsResponse {
    pub simulators: Vec<SimulatorInfo>,
    pub targets: Vec<TargetSimulatorsView>,
    pub model: ModelView,
}

/// The simulators, in the order a fork effect without a recording tries
/// them.
pub fn simulator_infos() -> Vec<SimulatorInfo> {
    let s = |name: &str, grounding: &str, description: &str| SimulatorInfo {
        name: name.into(),
        grounding: grounding.into(),
        description: description.into(),
    };
    vec![
        s(
            "recorded",
            "recorded",
            "The recorded result of the same call (exact), or of a call to the same target with another request (approximate).",
        ),
        s(
            "stub",
            "synthetic",
            "A stub rule of the replay request or of the target: a canned response or error.",
        ),
        s(
            "contract",
            "synthetic",
            "A schema-valid answer from the target's OpenAPI document, the same for the same request.",
        ),
        s(
            "neighbor",
            "synthetic",
            "The recorded answer of the most similar recorded request to the same route.",
        ),
        s(
            "model",
            "synthetic",
            "A configured model's answer from recorded examples; never sees personal data; cached per proposal. Off by default.",
        ),
        s(
            "fail-closed",
            "synthetic",
            "No answer: the guest gets denied(\"replay: no recording\").",
        ),
        s(
            "placeholder",
            "synthetic",
            "A fork's secret.reveal where production revealed nothing at that point: the placeholder [secret:<name>], never the value.",
        ),
    ]
}

impl Api {
    pub(crate) async fn route_m12(
        &self,
        req: &ApiRequest,
        segs: &[&str],
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("GET", ["v1", "simulators"]) => self.simulators(),
            ("PUT", ["v1", "simulators", target]) => self.simulators_set(req, target).await,
            _ => return None,
        })
    }

    fn simulators(&self) -> Result<ApiResponse> {
        let config = self.node.config_now();
        let lsns = self.config_lsns();
        let targets = config
            .simulators()
            .values()
            .map(|m| TargetSimulatorsView {
                target: m.target.clone(),
                stubs: m.stubs.len() as u64,
                contract: (!m.contract.is_empty()).then(|| ContractView {
                    title: kronik_effects::contract::Contract::parse(&m.contract)
                        .ok()
                        .and_then(|c| c.title().map(str::to_owned)),
                    digest: kronik_fork::simulators::contract_digest(&m.contract),
                    bytes: m.contract.len() as u64,
                }),
                neighbor: m.neighbor,
                model: m.model,
                epoch: m.epoch,
                lsn: lsns.get(&m.epoch).copied().unwrap_or(0),
                reason: m
                    .audit
                    .as_ref()
                    .map(|a| a.reason.clone())
                    .unwrap_or_default(),
            })
            .collect();
        let model = match self.proposals.as_ref().and_then(|p| p.model_config()) {
            Some(m) => ModelView {
                configured: true,
                endpoint_host: kronik_effects::http::parse_url(&m.endpoint)
                    .ok()
                    .map(|t| t.host),
                model: Some(m.model.clone()),
            },
            None => ModelView {
                configured: false,
                endpoint_host: None,
                model: None,
            },
        };
        ok(&SimulatorsResponse {
            simulators: simulator_infos(),
            targets,
            model,
        })
    }

    async fn simulators_set(&self, req: &ApiRequest, target: &str) -> Result<ApiResponse> {
        let r: SimulatorsSetRequest = json(&req.body)?;
        reason(&r.reason)?;
        let record = kronik_fork::simulators::SimulatorOverride {
            target: target.to_owned(),
            stubs: r.stubs.clone(),
            contract: r.contract.clone(),
            neighbor: r.neighbor,
            model: r.model,
        }
        .record()
        .map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let audit = self.audit(req, r.reason.clone());
        let (epoch, lsn) = self.node.set_simulators(record, audit, r.dry_run).await?;
        ok(&SimulatorsSetResponse {
            dry_run: r.dry_run,
            target: target.to_owned(),
            epoch,
            lsn,
        })
    }
}
