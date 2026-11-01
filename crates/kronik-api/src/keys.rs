//! KMS source metadata and audited online rewrap (M23 B1).
use crate::types::{KeysChangeResponse, KeysRewrapRequest};
use crate::{Api, AuthorizedRequest, ApiResponse, Result, json, ok, reason};
use kronik_core::error::{ApiError, ErrorCode};

impl Api {
    pub(crate) fn keys_status(&self) -> Result<ApiResponse> {
        let source = self.node.key_source().ok_or_else(|| {
            ApiError::new(ErrorCode::Unavailable, "the node has no loaded key source")
        })?;
        ok(&source.status())
    }

    pub(crate) async fn keys_rewrap(&self, req: &AuthorizedRequest) -> Result<ApiResponse> {
        let r: KeysRewrapRequest = json(&req.body)?;
        reason(&r.reason)?;
        let source = self.node.key_source().ok_or_else(|| {
            ApiError::new(ErrorCode::Unavailable, "the node has no loaded key source")
        })?;
        if !source.config().source.is_kms() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "rewrap requires a KMS source; use keys wrap offline first",
            ));
        }
        if !r.dry_run {
            self.audit_event(
                req,
                "keys.rewrap",
                source.config().source.as_str(),
                &[],
                r.reason.clone(),
            )
            .await?;
        }
        let wrapping = source.clone();
        let dry_run = r.dry_run;
        let keys = match self.node.authorized_effect(req.authority.clone(), move || async move {
            wrapping.rewrap(dry_run).await.map_err(|error| error.api_error())
        }).await {
            Ok(keys) => keys,
            Err(e) => {
                if !r.dry_run {
                    let _ = self
                        .audit_event(
                            req,
                            "keys.rewrap.failed",
                            source.config().source.as_str(),
                            &[("code", e.code.as_str().into())],
                            r.reason,
                        )
                        .await;
                }
                return Err(e);
            }
        };
        ok(&KeysChangeResponse {
            dry_run: r.dry_run,
            keys,
        })
    }
}
