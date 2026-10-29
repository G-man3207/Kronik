//! The export endpoints (docs/design/m28-otel.md §6.2): the status of the
//! daemon's export streams, and moving a stream's cursor back.

use kronik_core::error::{ApiError, ErrorCode};

use crate::types::{ExportRewindRequest, ExportRewindResponse, ExportStatusResponse, ExportStream};
use crate::{Api, ApiRequest, ApiResponse, Result, json, ok, reason};

impl Api {
    pub(crate) async fn route_export(
        &self,
        req: &ApiRequest,
        segs: &[&str],
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("GET", ["v1", "export"]) => self.export_status(),
            ("POST", ["v1", "export", stream, "rewind"]) => self.export_rewind(req, stream).await,
            _ => return None,
        })
    }

    /// `GET /v1/export` (scope `read`): no URL beyond scheme and host, and
    /// no error text, which can hold one (review M6).
    fn export_status(&self) -> Result<ApiResponse> {
        let applied_lsn = self.node.applied_lsn();
        let now = self.node.env().clock.wall_ms();
        let streams = self
            .exports
            .iter()
            .map(|s| {
                let p = s.progress();
                let lag = if s.enabled {
                    applied_lsn.saturating_sub(p.cursor)
                } else {
                    0
                };
                ExportStream {
                    name: s.name.into(),
                    enabled: s.enabled,
                    sink: s.sink.clone(),
                    cursor: p.cursor,
                    applied_lsn,
                    lag,
                    last_success_wall_ms: p.last_success_wall_ms,
                    stalled_ms: (lag > 0)
                        .then(|| p.last_success_wall_ms.or(p.started_wall_ms))
                        .flatten()
                        .map(|t| now.saturating_sub(t)),
                    last_error: p.last_error,
                    gaps: p.gaps,
                }
            })
            .collect();
        ok(&ExportStatusResponse { streams })
    }

    /// `POST /v1/export/{stream}/rewind` (scope `operate`): resend from
    /// after `to`, after a sink lost data. For the audit stream, retention
    /// is held from `to` at once, before the follower picks the rewind up.
    async fn export_rewind(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: ExportRewindRequest = json(&req.body)?;
        reason(&r.reason)?;
        let Some(stream) = self.exports.iter().find(|s| s.name == name && s.enabled) else {
            return Err(ApiError::new(
                ErrorCode::ExportNotConfigured,
                format!("the export stream {name:?} is not on in this daemon"),
            )
            .with_hint("Configure [otel] (traces) or [audit] (audit) and restart; `kronik export status` lists the streams."));
        };
        let from = stream.progress().cursor;
        if r.to > from {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "--to {} is past the cursor, LSN {from}: a rewind moves back only",
                    r.to
                ),
            ));
        }
        let first = self.log_first()?;
        if r.to + 1 < first {
            return Err(crate::audit::range_gone(r.to, first));
        }
        let answer = ExportRewindResponse {
            dry_run: r.dry_run,
            stream: name.to_owned(),
            from,
            to: r.to,
        };
        if r.dry_run {
            return ok(&answer);
        }
        if stream.name == kronik_otel::sink::STREAM {
            self.node
                .retention_hold()
                .rewind(r.to, self.node.env().clock.wall_ms());
        }
        stream.rewind(r.to);
        let details = [("from", from.to_string()), ("to", r.to.to_string())];
        self.audit_event(req, "export.rewind", name, &details, r.reason)
            .await?;
        ok(&answer)
    }
}
