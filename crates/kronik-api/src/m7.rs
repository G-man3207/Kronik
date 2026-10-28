//! The M7 endpoints: foreign actors (docs/design/m7-foreign.md §12).

use std::time::Duration;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_proto::log::v1 as pb;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Api, ApiRequest, ApiResponse, Query, Result, json, ok, reason};

/// How long `add` waits for the actor to leave `starting`.
const ADD_WAIT: Duration = Duration::from_secs(10);

/// `POST /v1/foreign`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ForeignAddRequest {
    pub name: String,
    pub image: String,
    pub port: u32,
    #[serde(default)]
    pub cpu_millis: Option<u32>,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub isolation: Option<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// How the last run of a foreign actor ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LastExitView {
    pub code: Option<i32>,
    pub oom: bool,
    pub at_ms: u64,
}

/// A foreign actor's supervision state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForeignStatusView {
    /// `starting`, `running`, `backoff`, `stopping` or `stopped`.
    pub state: String,
    pub since_ms: u64,
    pub starts: u64,
    pub restarts: u64,
    pub last_exit: Option<LastExitView>,
    pub next_start_ms: Option<u64>,
    pub error: Option<String>,
}

/// A declared foreign actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForeignView {
    pub name: String,
    pub image: String,
    pub port: u32,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub isolation: String,
    pub platform: String,
    /// `ENV=secret-name`; never values.
    pub secrets: Vec<String>,
    pub epoch: u64,
    /// 0 for a dry run.
    pub lsn: u64,
    pub reason: String,
    /// Null for a dry run, or when this daemon does not run foreign actors.
    pub status: Option<ForeignStatusView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignAddResponse {
    pub dry_run: bool,
    pub foreign: ForeignView,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignListResponse {
    pub foreign: Vec<ForeignView>,
    /// Why this daemon runs no foreign actor (another daemon holds
    /// `run_dir`, or the foreign actors' directory could not be prepared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignShowResponse {
    pub foreign: ForeignView,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignLogsResponse {
    pub name: String,
    pub lines: Vec<String>,
    pub truncated: bool,
}

/// `DELETE /v1/foreign/{name}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ForeignRemoveRequest {
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignRemoved {
    pub name: String,
    pub epoch: u64,
    pub lsn: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForeignRemoveResponse {
    pub dry_run: bool,
    pub removed: ForeignRemoved,
}

fn isolation_name(v: i32) -> String {
    kronik_foreign::Isolation::from_pb(v)
        .map_or("gvisor", kronik_foreign::Isolation::as_str)
        .to_owned()
}

fn status_view(s: kronik_foreign::Status) -> ForeignStatusView {
    ForeignStatusView {
        state: s.state.as_str().to_owned(),
        since_ms: s.since_ms,
        starts: s.starts,
        restarts: s.restarts,
        last_exit: s.last_exit.map(|e| LastExitView {
            code: e.code,
            oom: e.oom,
            at_ms: e.at_ms,
        }),
        next_start_ms: s.next_start_ms,
        error: s.error,
    }
}

fn not_found(name: &str) -> ApiError {
    ApiError::new(
        ErrorCode::ForeignNotFound,
        format!("no foreign actor {name} is declared"),
    )
}

impl Api {
    pub(crate) async fn route_m7(
        &self,
        req: &ApiRequest,
        segs: &[&str],
        q: &Query,
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("POST", ["v1", "foreign"]) => self.foreign_add(req).await,
            ("GET", ["v1", "foreign"]) => self.foreign_list(),
            ("GET", ["v1", "foreign", name]) => self.foreign_show(name),
            ("GET", ["v1", "foreign", name, "logs"]) => self.foreign_logs(name, q).await,
            ("DELETE", ["v1", "foreign", name]) => self.foreign_remove(req, name).await,
            _ => return None,
        })
    }

    fn foreign_manager(&self) -> Result<&std::sync::Arc<kronik_foreign::Foreign>> {
        self.foreign.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::ForeignUnavailable,
                "this daemon does not run foreign actors",
            )
        })
    }

    fn foreign_view(&self, r: &pb::ForeignActor, lsn: u64) -> ForeignView {
        ForeignView {
            name: r.name.clone(),
            image: r.image.clone(),
            port: r.port,
            cpu_millis: r.cpu_millis,
            memory_bytes: r.memory_bytes,
            isolation: isolation_name(r.isolation),
            platform: r.platform.clone(),
            secrets: r.secrets.clone(),
            epoch: r.epoch,
            lsn,
            reason: r
                .audit
                .as_ref()
                .map(|a| a.reason.clone())
                .unwrap_or_default(),
            status: self
                .foreign
                .as_ref()
                .and_then(|f| f.status(&r.name))
                .map(status_view),
        }
    }

    async fn foreign_add(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: ForeignAddRequest = json(&req.body)?;
        reason(&r.reason)?;
        let foreign = self.foreign_manager()?.clone();
        // Before the image is fetched (up to 8 GiB), also for a dry run.
        self.node.check_running()?;
        if self.node.config_now().foreign(&r.name).is_some() {
            return Err(ApiError::new(
                ErrorCode::ForeignExists,
                format!("foreign actor {} is already declared", r.name),
            ));
        }
        let plan = foreign
            .prepare_add(
                kronik_foreign::AddRequest {
                    name: r.name.clone(),
                    image: r.image.clone(),
                    port: r.port,
                    cpu_millis: r.cpu_millis,
                    memory_bytes: r.memory_bytes,
                    isolation: r.isolation.clone(),
                    secrets: r.secrets.clone(),
                    any_layout_dir: self.caller(req)?.has(crate::auth::Scope::Admin),
                    // The image's new layers must fit above the reserve.
                    max_new_bytes: self.node.disk_budget(),
                },
                self.node.secrets().map(|s| s.as_ref()),
            )
            .await?;
        let audit = self.audit(req, r.reason.clone());
        let mut record = plan.record.clone();
        record.audit = Some(audit.clone());
        let added = self
            .node
            .foreign_add(plan.record.clone(), audit, r.dry_run)
            .await;
        let warnings = plan.warnings.clone();
        // A dry run or a refused write keeps no blob of the image.
        foreign.finish_add(plan, added.is_ok() && !r.dry_run).await;
        let (epoch, lsn) = added?;
        record.epoch = epoch;
        if !r.dry_run {
            foreign.settled(&record.name, ADD_WAIT).await;
        }
        let mut view = self.foreign_view(&record, lsn);
        if r.dry_run {
            view.status = None;
        }
        ok(&ForeignAddResponse {
            dry_run: r.dry_run,
            foreign: view,
            warnings,
        })
    }

    fn foreign_list(&self) -> Result<ApiResponse> {
        let config = self.node.config_now();
        let lsns = self.config_lsns();
        ok(&ForeignListResponse {
            foreign: config
                .foreign_actors()
                .map(|r| self.foreign_view(r, lsns.get(&r.epoch).copied().unwrap_or(0)))
                .collect(),
            unavailable: self.foreign.as_ref().and_then(|f| f.off()),
        })
    }

    fn foreign_show(&self, name: &str) -> Result<ApiResponse> {
        let config = self.node.config_now();
        let r = config.foreign(name).ok_or_else(|| not_found(name))?;
        let lsn = self.config_lsns().get(&r.epoch).copied().unwrap_or(0);
        ok(&ForeignShowResponse {
            foreign: self.foreign_view(r, lsn),
        })
    }

    async fn foreign_logs(&self, name: &str, q: &Query) -> Result<ApiResponse> {
        let tail = q.num("tail")?.unwrap_or(200).clamp(1, 10_000) as usize;
        let declared = self.node.config_now().foreign(name).is_some();
        let foreign = self.foreign_manager()?;
        let logs = foreign.logs(name, tail, self.node.secret_values()).await?;
        let (lines, truncated) = match logs {
            Some(t) => (t.lines, t.truncated),
            None if declared => (Vec::new(), false),
            None => return Err(not_found(name)),
        };
        ok(&ForeignLogsResponse {
            name: name.to_owned(),
            lines,
            truncated,
        })
    }

    async fn foreign_remove(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: ForeignRemoveRequest = json(&req.body)?;
        reason(&r.reason)?;
        let audit = self.audit(req, r.reason.clone());
        let (epoch, lsn) = self.node.foreign_remove(name, audit, r.dry_run).await?;
        ok(&ForeignRemoveResponse {
            dry_run: r.dry_run,
            removed: ForeignRemoved {
                name: name.to_owned(),
                epoch,
                lsn,
            },
        })
    }
}
