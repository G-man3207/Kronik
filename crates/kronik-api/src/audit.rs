//! `GET /v1/audit` (docs/design/m28-otel.md §6.2): the audit lines of
//! main's log, as an audit sink receives them, built from the log also when
//! the export is off. Scope `admin`: the lines name tokens and callers.

use kronik_core::error::{ApiError, ErrorCode};
use kronik_otel::audit::{Keys, Mapper};

use crate::types::AuditResponse;
use crate::{Api, ApiResponse, Query, Result, internal, ok};

/// Records read per step while filling a page.
const STEP: u64 = 1024;

impl Api {
    /// The first retained record's LSN.
    pub(crate) fn log_first(&self) -> Result<u64> {
        match self.node.storage_config() {
            Some(s) => self.node.log_first(s),
            None => Ok(1),
        }
    }

    /// `GET /v1/audit`.
    pub(crate) async fn audit_lines(&self, q: &Query) -> Result<ApiResponse> {
        let limit = q.limit()?;
        let first = self.log_first()?;
        let from = match q.num("from")? {
            Some(f) if f < first => return Err(range_gone(f, first)),
            Some(f) => f,
            None => first,
        };
        let applied = self.node.applied_lsn();
        let secrets = self.node.secret_values();
        let fallback;
        let mapper = match &self.audit_mapper {
            Some(m) => m.as_ref(),
            None => {
                fallback = Mapper {
                    keys: Keys::Omit,
                    sealer: self.node.sealer().clone(),
                    branch: self.node.branch().to_owned(),
                };
                &fallback
            }
        };
        let mut lines = Vec::new();
        let mut at = from.max(1);
        // A page ends between records, never inside one's lines.
        'pages: while at <= applied {
            let upto = applied.min(at + STEP - 1);
            let mut records = Vec::new();
            self.node
                .reader()
                .read(at, upto, |c| {
                    records.push(c);
                    Ok(())
                })
                .await
                .map_err(internal)?;
            for c in records {
                let more = if lines.len() < limit {
                    mapper.lines(c.lsn, &c.record, &secrets)
                } else {
                    Vec::new()
                };
                if lines.len() >= limit || (!lines.is_empty() && lines.len() + more.len() > limit) {
                    at = c.lsn;
                    break 'pages;
                }
                lines.extend(more);
                at = c.lsn + 1;
            }
            at = at.max(upto + 1);
        }
        ok(&AuditResponse {
            next: (at <= applied).then_some(at),
            applied_lsn: applied,
            lines,
        })
    }
}

/// `AUDIT_RANGE_GONE`: `lsn` is before the first retained record.
pub(crate) fn range_gone(lsn: u64, first: u64) -> ApiError {
    ApiError::new(
        ErrorCode::AuditRangeGone,
        format!("LSN {lsn} is before the first retained record, LSN {first}"),
    )
    .with_hint(format!(
        "Start at LSN {first} or later; retention deleted what came before."
    ))
}
