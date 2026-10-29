//! Request and response bodies of the `/v1` API (docs/design/m1-core.md §4),
//! shared with the CLI client.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Bytes as JSON: `text` when valid UTF-8 (responses), and always `base64`.
/// Requests give either one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Payload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

impl Payload {
    pub fn from_bytes(b: &[u8]) -> Payload {
        Payload {
            text: std::str::from_utf8(b).ok().map(str::to_owned),
            base64: Some(STANDARD.encode(b)),
        }
    }

    /// The bytes; `base64` wins when both are given.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        match (&self.base64, &self.text) {
            (Some(b), _) => STANDARD
                .decode(b)
                .map_err(|e| format!("invalid base64: {e}")),
            (None, Some(t)) => Ok(t.clone().into_bytes()),
            (None, None) => Ok(Vec::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeployRequest {
    pub wasm_base64: String,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Route {
    pub method: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Deployment {
    pub epoch: u64,
    /// 0 for dry runs and unchanged deploys.
    pub lsn: u64,
    pub kind: String,
    pub code_hash: String,
    pub schema_version: u32,
    pub routes: Vec<Route>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeployResponse {
    pub dry_run: bool,
    pub unchanged: bool,
    pub deployment: Deployment,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentKind {
    pub kind: String,
    pub code_hash: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentEntry {
    pub epoch: u64,
    pub lsn: u64,
    pub cause: String,
    pub kinds: Vec<DeploymentKind>,
    /// Why, as recorded with the deployment.
    #[serde(default)]
    pub reason: String,
    /// Who: `token:<name>`, or `unix:uid=<n>` on the socket without a token.
    #[serde(default)]
    pub token_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeploymentsResponse {
    pub deployments: Vec<DeploymentEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SendRequest {
    pub name: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(flatten)]
    pub body: Payload,
    #[serde(default)]
    pub subject: Option<String>,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Outcome {
    /// committed, rejected, failed, trap, fuel_exhausted, memory_limit,
    /// effect_outcome_unknown.
    pub kind: String,
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Reply {
    pub name: String,
    pub content_type: String,
    #[serde(flatten)]
    pub body: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TurnResponse {
    pub dry_run: bool,
    /// Absent for dry runs.
    pub turn_id: Option<String>,
    pub outcome: Option<Outcome>,
    pub reply: Option<Reply>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResendRequest {
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Actor {
    pub kind: String,
    pub key: String,
    pub schema_version: u32,
    pub turns: u64,
    pub last_turn_id: String,
    pub sql: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActorsResponse {
    pub actors: Vec<Actor>,
    /// `kind/key` to pass as `after` for the next page.
    pub next: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StateEntry {
    pub key: String,
    #[serde(flatten)]
    pub value: Payload,
    /// The value's subject; null for a caller without `pii:read`.
    pub subject: Option<String>,
    pub lsn: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SqlTable {
    pub name: String,
    pub rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SqlSummary {
    pub tables: Vec<SqlTable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InspectResponse {
    pub actor: Actor,
    pub state: Vec<StateEntry>,
    pub sql: Option<SqlSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InputSummary {
    /// http, message, timer or migrate.
    #[serde(rename = "type")]
    pub kind: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WriteSummary {
    pub op: String,
    pub key: String,
    /// The value's subject; null for a caller without `pii:read`.
    pub subject: Option<String>,
    /// The value was sealed for a subject that has been erased since: it
    /// reads as `[erased]` (docs/design/m8-privacy.md §5). Omitted when
    /// false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erased: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MessageSummary {
    pub to: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TurnSummary {
    pub turn_id: String,
    pub lsn: u64,
    pub logical_time_ms: u64,
    pub code_hash: String,
    pub input: InputSummary,
    pub outcome: Outcome,
    pub writes: Vec<WriteSummary>,
    pub messages: Vec<MessageSummary>,
    pub sql_changes: u64,
    pub fuel_used: u64,
    #[serde(default)]
    pub effects: Vec<EffectSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HistoryResponse {
    pub turns: Vec<TurnSummary>,
    /// LSN to pass as `before` for the next page.
    pub next: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeadLetter {
    pub id: String,
    pub actor: String,
    pub input: InputSummary,
    pub error_code: String,
    pub message: String,
    pub resent_as: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeadLettersResponse {
    pub dead_letters: Vec<DeadLetter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HealthResponse {
    /// `ok` while the node runs (a stopped node answers an error).
    pub status: String,
    pub version: String,
    pub engine: String,
    pub applied_lsn: u64,
    pub branch: String,
    /// The gateway's bound address, e.g. 127.0.0.1:8080.
    #[serde(default)]
    pub http_listen: Option<String>,
    /// Free bytes on the log's file system, when `[log] disk_reserve` is
    /// set and read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_bytes: Option<u64>,
    /// The log's file system is below `[log] disk_reserve`: new inputs and
    /// changes are refused. Omitted when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub low_disk: bool,
}

// ------------------------------------------------------------------ M2

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantRequest {
    pub kind: String,
    pub capability: String,
    /// replay-safe, idempotency-keyed or unsafe; the method's default when
    /// absent.
    #[serde(default)]
    pub delivery: Option<String>,
    /// `N/s`, `N/m` or `N/h`.
    #[serde(default)]
    pub rate: Option<String>,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantView {
    pub kind: String,
    pub capability: String,
    pub delivery: Option<String>,
    pub rate: Option<String>,
    pub epoch: u64,
    /// 0 for dry runs.
    pub lsn: u64,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantResponse {
    pub dry_run: bool,
    pub grant: GrantView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantsResponse {
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RevokeRequest {
    pub kind: String,
    pub capability: String,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Revoked {
    pub kind: String,
    pub capability: String,
    pub epoch: u64,
    pub lsn: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RevokeResponse {
    pub dry_run: bool,
    pub revoked: Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LimitsRequest {
    pub kind: String,
    #[serde(default)]
    pub fuel: Option<u64>,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub message_bytes: Option<u64>,
    #[serde(default)]
    pub state_value_bytes: Option<u64>,
    #[serde(default)]
    pub sql_bytes_per_actor: Option<u64>,
    #[serde(default)]
    pub effect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub effect_response_bytes: Option<u64>,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LimitsView {
    pub kind: String,
    pub fuel: u64,
    pub memory_bytes: u64,
    pub message_bytes: u64,
    pub state_value_bytes: u64,
    pub sql_bytes_per_actor: u64,
    pub effect_timeout_ms: u64,
    pub effect_response_bytes: u64,
    /// Set in responses to `POST /v1/limits` (lsn 0 for dry runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsn: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LimitsResponse {
    pub dry_run: bool,
    pub limits: LimitsView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LimitsListResponse {
    pub limits: Vec<LimitsView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretSetRequest {
    #[serde(flatten)]
    pub value: Payload,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretView {
    pub name: String,
    pub version: u32,
    /// Hex of the keyed version hash; never the value.
    pub version_hash: String,
    pub created_wall_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretResponse {
    pub dry_run: bool,
    /// Absent for dry runs.
    pub secret: Option<SecretView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretsResponse {
    pub secrets: Vec<SecretView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretDeleteRequest {
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretDeleted {
    pub name: String,
    pub versions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SecretDeleteResponse {
    pub dry_run: bool,
    pub deleted: SecretDeleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Compensation {
    pub message_id: String,
    /// pending, dead_letter or done.
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Orphan {
    /// The callee.
    pub actor: String,
    /// The callee's turn that made the change.
    pub turn_id: String,
    pub caller: String,
    pub caller_turn_id: String,
    pub call_message_id: String,
    pub compensation: Option<Compensation>,
    pub resolved_turn_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OrphansResponse {
    pub orphans: Vec<Orphan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Timer {
    /// Decimal string: the u64 does not fit a JSON number exactly.
    pub id: String,
    pub due_ms: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimersResponse {
    pub timers: Vec<Timer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EffectSummary {
    pub ordinal: u32,
    pub kind: String,
    pub target: String,
    /// ok, denied, network, timeout, too_large, outcome_unknown, not_found,
    /// rejected, failed, reentrant.
    pub status: String,
    pub delivery: Option<String>,
    pub error: Option<String>,
    /// For denied effects: the exact command that grants the capability.
    pub hint: Option<String>,
    /// In history, for an HTTP effect: the request's method, host and path,
    /// such as `POST api.example.com/hooks`. Omitted otherwise, and when the
    /// request is sealed for a data subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    /// Fork turns only: how the effect was answered, `exact`,
    /// `approximate`, `synthetic` or `forked` (a copy of a foreign actor,
    /// M14). Absent for production and live effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounding: Option<String>,
    /// Synthetic fork effects only: the simulator that answered (`stub`,
    /// `contract`, `neighbor`, `model`, `fail-closed`, `placeholder`; M12). Absent for a
    /// fork turn recorded before M12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulator: Option<String>,
}

// ------------------------------------------------------------------ M3
// Forks, replay, proposals, policy (docs/design/m3-fork.md §9).

fn default_mode() -> String {
    "both".into()
}

fn default_sample() -> f64 {
    1.0
}

/// Replay options shared by fork replay and propose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayOptions {
    /// `isolated`, `continuous` or `both`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// The isolated sample, in (0, 1].
    #[serde(default = "default_sample")]
    pub sample: f64,
    #[serde(default)]
    pub ignore_headers: Vec<String>,
    #[serde(default)]
    pub ignore_json_paths: Vec<String>,
    /// Isolated replay workers (default: the machine's cores, at most 16).
    #[serde(default)]
    pub threads: Option<usize>,
    /// Canned answers for effects without a recording (synthetic
    /// grounding): `[{"method", "url_prefix", "status", "headers",
    /// "body"} | {"url_prefix", "error": "network" | "timeout" |
    /// "too-large" | "denied"}]`.
    #[serde(default)]
    #[schemars(with = "Vec<serde_json::Map<String, serde_json::Value>>")]
    pub stubs: Vec<kronik_fork::stubs::StubRule>,
    /// A fork without access to the privacy keys (propose; a plain fork
    /// keeps the flag it was created with).
    #[serde(default)]
    pub no_pii: bool,
    /// Simulator configuration for this replay only, per target: `[{"target",
    /// "stubs", "contract", "neighbor", "model"}]`, each replacing main's
    /// configuration as of the fork point (I5; the fields of `PUT
    /// /v1/simulators/{target}`). Recorded in the diff's options.
    #[serde(default)]
    #[schemars(with = "Vec<serde_json::Map<String, serde_json::Value>>")]
    pub simulator_overrides: Vec<kronik_fork::simulators::SimulatorOverride>,
}

/// `at`: an LSN, `"now"`, or an RFC 3339 time (logical time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ForkPoint {
    Lsn(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkCreateRequest {
    pub at: ForkPoint,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub no_pii: bool,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkInfo {
    pub name: String,
    pub fork_lsn: u64,
    pub no_pii: bool,
    pub proposal_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkCreateResponse {
    pub dry_run: bool,
    pub fork: ForkInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkEntry {
    pub name: String,
    pub fork_lsn: u64,
    pub head_lsn: u64,
    pub proposal_id: Option<String>,
    pub verified_through_lsn: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForksResponse {
    pub forks: Vec<ForkEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkDeleteResponse {
    pub dry_run: bool,
    pub deleted: String,
}

/// `POST /v1/previews` (M11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewCreateRequest {
    /// The proposal whose code the preview runs.
    pub proposal: String,
    /// How long the preview lives, in milliseconds [default: `[fork]
    /// preview_ttl`, 24 h].
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    /// A preview without access to personal data; always so for a caller
    /// without pii:read, and when the proposal has it.
    #[serde(default)]
    pub no_pii: bool,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// A preview fork: where its requests go and when it expires.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewInfo {
    /// The fork's name, `v-<12 hex>`.
    pub id: String,
    pub proposal: String,
    /// `<scheme>://<id>.<preview_domain>/` with `[gateway] preview_domain`,
    /// else `<scheme>://<gateway host>/__preview/<id>/`; `https` when the
    /// gateway serves TLS, else `http`.
    pub url: String,
    pub fork_lsn: u64,
    pub no_pii: bool,
    /// Wall-clock Unix milliseconds after which it is deleted.
    pub expires_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewCreateResponse {
    pub dry_run: bool,
    pub preview: PreviewInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewsResponse {
    pub previews: Vec<PreviewInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewDeleteResponse {
    pub dry_run: bool,
    pub deleted: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ForkDeployResponse {
    pub dry_run: bool,
    pub fork: String,
    pub deployment: DeploymentKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayRequest {
    #[serde(default)]
    pub to_lsn: Option<u64>,
    #[serde(flatten)]
    pub options: ReplayOptions,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayResponse {
    pub fork: String,
    /// The diff's summary (§5.1).
    #[schemars(schema_with = "crate::openapi::diff_summary")]
    pub summary: serde_json::Value,
    pub diff_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposeRequest {
    pub wasm_base64: Vec<String>,
    /// A name per component, such as its file name, used in error
    /// messages (M9); optional.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(default)]
    pub window_ms: Option<u64>,
    #[serde(default)]
    pub at: Option<u64>,
    #[serde(flatten)]
    pub options: ReplayOptions,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
    /// Return at once with the `running` proposal; the replay runs on in
    /// the daemon (M10). Not with `dry_run`.
    #[serde(default, rename = "async")]
    pub run_async: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposalInfo {
    pub id: String,
    pub fork: String,
    /// `running`, `evaluated`, `approved`, `promoted`, `rejected`, `stale`
    /// or `failed`.
    pub status: String,
    pub fork_lsn: u64,
    pub verified_through_lsn: u64,
    pub diff_hash: String,
    /// The policy evaluation (§7); null while `running`.
    #[schemars(schema_with = "crate::openapi::policy_evaluation_or_null")]
    pub policy: serde_json::Value,
    /// The diff's summary (§5.1); null while `running`.
    #[schemars(schema_with = "crate::openapi::diff_summary_or_null")]
    pub summary: serde_json::Value,
    /// The code the proposal switches: one entry per changed actor kind.
    pub kinds: Vec<DeploymentKind>,
    /// Components of the request whose code main already ran: skipped, not
    /// in the fork's code (M9).
    #[serde(default)]
    pub unchanged: Vec<DeploymentKind>,
    #[serde(default)]
    pub approval_requests: Vec<ApprovalRequestInfo>,
    /// What a reader must know about how the proposal was verified, e.g.
    /// that retention cut its window short.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// While `running`: how far the replay has come (M10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<ProposalProgress>,
    /// When `failed`: why, as the error JSON (M10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::openapi::error_schema")]
    pub error: Option<serde_json::Value>,
    /// A rollback via replay (M13): what it rolls back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebase: Option<RebaseView>,
}

/// Root inputs replayed so far and to replay, per replay mode (0 and 0 for
/// a mode that does not run, or has not counted its inputs yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProposalProgress {
    pub isolated_done: u64,
    pub isolated_total: u64,
    pub continuous_done: u64,
    pub continuous_total: u64,
}

/// What a rebase proposal rolls back (M13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RebaseView {
    pub rolled_back_epoch: u64,
    /// The fork point: main's last LSN before the rolled-back deployment.
    pub base_lsn: u64,
    /// External effects of the rolled-back code the old code would not
    /// have made (the diff's `irreversible`).
    pub irreversible_effects: u64,
    /// The `StateRebase` switch, once promoted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switch_lsn: Option<u64>,
}

/// `POST /v1/deployments/{epoch}/rebase`: a rollback via replay (M13).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RebaseRequest {
    /// `continuous` (default) or `both`; the switch needs continuous replay.
    #[serde(default)]
    pub mode: Option<String>,
    /// Isolated replay workers, for `both`.
    #[serde(default)]
    pub threads: Option<usize>,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// The switch of a rollback via replay (M13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RebaseSwitchInfo {
    /// The `StateRebase` record (0 for a dry run).
    pub lsn: u64,
    pub base_lsn: u64,
    /// The replayed turns that became main's state.
    pub turns: u64,
    pub irreversible_effects: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposeResponse {
    pub dry_run: bool,
    pub proposal: ProposalInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposalsResponse {
    pub proposals: Vec<ProposalInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalInfo {
    pub proposal_id: String,
    pub diff_hash: String,
    pub verified_through_lsn: u64,
    pub lsn: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApproveResponse {
    pub dry_run: bool,
    pub approval: ApprovalInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SwitchInfo {
    pub epoch: u64,
    pub lsn: u64,
    /// 0 means "at its own LSN".
    pub effective_lsn: u64,
    pub verified_through_lsn: u64,
    pub unverified_inputs: u64,
    pub kinds: Vec<DeploymentKind>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PromoteResponse {
    pub dry_run: bool,
    pub deployment: SwitchInfo,
    #[schemars(schema_with = "crate::openapi::policy_evaluation")]
    pub policy: serde_json::Value,
    /// Set for a rollback via replay (M13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebase: Option<RebaseSwitchInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RollbackResponse {
    pub dry_run: bool,
    pub deployment: SwitchInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchRequest {
    /// How long to watch after the deployment, and how long the window
    /// before it is that the metrics are compared with, in milliseconds:
    /// more than 0 and at most 86400000 (24h).
    pub for_ms: u64,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
    /// Return at once with the `watching` watch; it runs on in the daemon.
    /// Not with `dry_run`.
    #[serde(default, rename = "async")]
    pub run_async: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchResponse {
    pub dry_run: bool,
    /// In a dry run: the current metrics, and in `triggered` (with `lsn`
    /// 0) the guards that would fire now.
    pub watch: WatchInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchesResponse {
    pub watches: Vec<WatchInfo>,
}

/// A watch of a deployment (M11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchInfo {
    /// `w-` and 12 hex characters.
    pub id: String,
    /// The watched deployment's epoch and the LSN of its record.
    pub epoch: u64,
    pub deployment_lsn: u64,
    pub for_ms: u64,
    /// Logical time where the window after the deployment starts.
    pub deployment_time_ms: u64,
    /// `watching`, `done` (the window passed), `rolled_back`, `superseded`
    /// (a later deployment of its kinds replaced the watched one; nothing
    /// acted), `stopped` or `failed`.
    pub status: String,
    pub reason: String,
    pub token_id: String,
    pub created_ms: u64,
    /// The guards that fired, in order. Each fires once; a guard that could
    /// not be evaluated also alerts once, with a reason starting "the
    /// guard could not be evaluated: ".
    pub triggered: Vec<WatchTriggered>,
    /// The metrics of the last evaluation (the CEL variable `guard`);
    /// null before the first.
    pub metrics: Option<GuardMetrics>,
    /// When `failed`: why, as the error JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::openapi::error_schema")]
    pub error: Option<serde_json::Value>,
    /// When `stopped`: who stopped it and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped: Option<WatchStopped>,
}

/// `kronik watches stop`'s audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchStopped {
    pub token_id: String,
    pub reason: String,
    pub wall_time_ms: u64,
}

/// A guard that fired: its `GuardTriggered` record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WatchTriggered {
    pub guard: String,
    /// `alert` or `rollback`.
    pub action: String,
    /// `alerted`, `rolled_back`, `rollback_refused_schema` or
    /// `rollback_failed`.
    pub outcome: String,
    /// The `GuardTriggered` record's LSN.
    pub lsn: u64,
    /// The rollback deployment's epoch; 0 without one.
    pub rollback_epoch: u64,
    pub reason: String,
}

/// What a guard sees: the deployment's kinds' turns after it and in the
/// equally long window before it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GuardMetrics {
    pub epoch: u64,
    pub kinds: Vec<String>,
    /// A rollback would move a schema version back: guards alert instead.
    pub schema_changed: bool,
    /// Logical time of the window after the deployment seen so far.
    pub observed_ms: u64,
    pub before: GuardWindowMetrics,
    pub after: GuardWindowMetrics,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GuardWindowMetrics {
    pub turns: u64,
    /// Turns whose outcome is not committed.
    pub failed: u64,
    /// `failed / turns`; 0 without turns.
    pub error_rate: f64,
    pub latency_p50_ms: f64,
    pub latency_p99_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyResponse {
    pub rules_toml: String,
    pub epoch: u64,
    pub default: bool,
    /// The guards `kronik watch` evaluates (M11). The policy's own when its
    /// file has a `guard` key (`guard = []`: none), else the defaults.
    pub guards: Vec<PolicyGuard>,
    /// `guards` are the default guards: the policy has no `guard` key.
    pub default_guards: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyGuard {
    pub name: String,
    pub when: String,
    /// `alert` or `rollback`.
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySetRequest {
    pub rules_toml: String,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySetResponse {
    pub dry_run: bool,
    pub epoch: u64,
    pub lsn: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyTestRequest {
    /// Rules to test; the rules in force when absent.
    #[serde(default)]
    pub rules_toml: Option<String>,
    /// The proposal (or fork) whose diff is evaluated.
    pub proposal: String,
}

/// One node of a causal tree (`GET /v1/turns/{id}/trace`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceNode {
    pub turn_id: String,
    pub actor: String,
    pub input: InputSummary,
    pub outcome: Outcome,
    pub children: Vec<TraceNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceRoot {
    pub lsn: u64,
    pub root_id: String,
    pub input: InputSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceResponse {
    pub turn: TurnSummary,
    pub actor: String,
    /// The tree's root input (absent when it is outside the log).
    pub root: Option<TraceRoot>,
    /// From the root input down to the turn's parent.
    pub ancestors: Vec<TurnSummary>,
    /// What the turn caused, as a tree (at most 1000 turns).
    pub descendants: Vec<TraceNode>,
    pub truncated: bool,
}

/// A turn run in a fork (`POST /v1/forks/{name}/actors/{kind}/{key}/messages`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForkTurnResponse {
    pub fork: String,
    pub turn_id: String,
    pub outcome: Outcome,
    pub reply: Option<Reply>,
    pub effects: Vec<EffectSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalRequestInfo {
    pub lsn: u64,
    pub command: String,
    pub token_id: String,
    pub reason: String,
    /// No approval followed it yet.
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalRequest {
    pub proposal_id: String,
    pub diff_hash: String,
    pub verified_through_lsn: u64,
    pub lsn: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestApprovalResponse {
    pub dry_run: bool,
    pub request: ApprovalRequest,
}

// Tokens (M5): `POST /v1/tokens`, `GET /v1/tokens`,
// `POST /v1/tokens/{name}/revoke`, all with the `admin` scope.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenCreateRequest {
    /// A lowercase letter, then up to 62 lowercase letters, digits and
    /// dashes; never reused.
    pub name: String,
    /// `read`, `fork`, `propose`, `approve`, `promote`, `operate`,
    /// `pii:read`, `admin`; `read`, `fork` and `propose` when absent.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenView {
    pub name: String,
    /// How the token's actions are recorded: `token:<name>`.
    pub token_id: String,
    pub scopes: Vec<String>,
    pub created_wall_ms: u64,
    /// The caller that created it.
    pub created_by: String,
    pub reason: String,
    pub revoked: bool,
    pub revoked_wall_ms: Option<u64>,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenCreateResponse {
    pub dry_run: bool,
    pub token: TokenView,
    /// The bearer token. It is returned only here, once, and never stored;
    /// absent for dry runs.
    pub secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokensResponse {
    pub tokens: Vec<TokenView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenRevokeRequest {
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenRevokeResponse {
    pub dry_run: bool,
    pub token: TokenView,
}

// ------------------------------------------------------------------ M6
// Snapshots and integrity (docs/design/m6-storage.md).

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotCreateRequest {
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotEntry {
    /// `<branch>-<lsn>`.
    pub id: String,
    /// The state is exactly the log's through this LSN.
    pub lsn: u64,
    pub created_wall_ms: u64,
    pub engine_version: String,
    /// The files' total size.
    pub bytes: u64,
    /// `interval`, `shutdown` or `manual`.
    pub reason: String,
    /// BLAKE3 over the materialized state at `lsn` (m6-storage §8).
    pub state_hash: String,
    /// True when this snapshot's LSN is recorded in `<data_dir>/ship.json`.
    /// False when shipping is off or the snapshot has not been uploaded.
    /// Missing on an older response decodes as false.
    #[serde(default)]
    pub shipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotsResponse {
    /// Newest first.
    pub snapshots: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotCreateResponse {
    pub dry_run: bool,
    /// The snapshot's LSN (for a dry run: the applied LSN it would take).
    pub lsn: u64,
    pub snapshot: Option<SnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityResponse {
    pub applied_lsn: u64,
    /// BLAKE3 over the materialized state (m6-storage §8).
    pub state_hash: String,
    /// The first LSN the log still holds (retention deletes older segments).
    pub log_first_lsn: u64,
    /// BLAKE3 over the records `log_first_lsn..=through_lsn` (LSN, kind and
    /// encoded record of each).
    pub log_hash: String,
    /// The last LSN `log_hash` covers: `applied_lsn`, or the `through`
    /// asked for. An older response that omits it decodes as 0.
    #[serde(default)]
    pub through_lsn: u64,
    /// `[retention] history` in milliseconds. Zero when the node has no
    /// storage config (`Node::start` with `storage: None`, including DST).
    /// `start_local` and `kronik serve` always install one; the default is
    /// 7 days. An older response that omits the field decodes as 0.
    #[serde(default)]
    pub retention_history_ms: u64,
    /// Newest record's logical time (`time_hwm`). Zero when the node has
    /// no storage config, or when nothing has advanced logical time.
    #[serde(default)]
    pub newest_logical_time_ms: u64,
    /// Forks whose turn logical time is strictly before this are outside
    /// the window. Zero when the node has no storage config.
    #[serde(default)]
    pub retention_cutoff_ms: u64,
    /// Subjects with sealed values (in the state or the log) whose key the
    /// privacy keystore lacks and that were not erased: those values can't
    /// be read (`KEYSTORE_INCOMPLETE`). Empty on a healthy node.
    #[serde(default)]
    pub keys_missing: Vec<String>,
}

/// `GET /v1/audit`: `kronik.audit/v1` lines in LSN order (m28-otel §4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditResponse {
    pub lines: Vec<kronik_otel::audit::Line>,
    /// The `from` of the next page; absent at the applied LSN.
    pub next: Option<u64>,
    pub applied_lsn: u64,
}

// Export (docs/design/m28-otel.md §6.2).

/// `GET /v1/export`: every export stream of the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportStatusResponse {
    pub streams: Vec<ExportStream>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportStream {
    /// `traces` or `audit`.
    pub name: String,
    pub enabled: bool,
    /// The sink's or endpoint's scheme and host only (never a path, query
    /// or credentials); empty when not configured.
    pub sink: String,
    /// The last LSN the sink acknowledged.
    pub cursor: u64,
    pub applied_lsn: u64,
    /// `applied_lsn - cursor` while enabled, else 0.
    pub lag: u64,
    /// Wall-clock milliseconds of the last delivered batch since the start.
    pub last_success_wall_ms: Option<u64>,
    /// While there is lag: milliseconds since the last delivered batch, or
    /// since the stream started without one. `kronik doctor` warns on it.
    #[serde(default)]
    pub stalled_ms: Option<u64>,
    /// The last failure's code (`http_503`, `connect`, `timeout`, ...),
    /// never its text.
    pub last_error: Option<String>,
    /// Ranges retention deleted before the stream read them, since the
    /// start.
    pub gaps: u64,
}

/// `POST /v1/export/{stream}/rewind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportRewindRequest {
    /// Resend the records after this LSN; at most the stream's cursor, and
    /// not before the first retained record (`AUDIT_RANGE_GONE`).
    pub to: u64,
    /// Required: missing or blank answers REASON_REQUIRED.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportRewindResponse {
    pub dry_run: bool,
    pub stream: String,
    /// The cursor before the rewind.
    pub from: u64,
    pub to: u64,
}
