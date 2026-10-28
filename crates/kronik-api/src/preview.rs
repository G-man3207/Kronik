//! The preview endpoints (M11, docs/design/m11-preview.md): create, list
//! and delete preview forks. Their requests go through the gateway, not
//! this API.

use std::time::Duration;

use kronik_fork::proposal::Proposal;

use crate::auth::{Caller, Scope};
use crate::types::*;
use crate::{Api, ApiRequest, ApiResponse, Result, internal, json, ok, reason};

impl Api {
    pub(crate) async fn route_preview(
        &self,
        req: &ApiRequest,
        segs: &[&str],
        caller: &Caller,
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("POST", ["v1", "previews"]) => self.preview_create(req, caller).await,
            ("GET", ["v1", "previews"]) => self.previews().await,
            ("DELETE", ["v1", "previews", id]) => self.preview_delete(req, id).await,
            _ => return None,
        })
    }

    fn preview_info(&self, p: &Proposal) -> Result<PreviewInfo> {
        let preview = p
            .preview
            .as_ref()
            .ok_or_else(|| internal(format!("{} is not a preview", p.id)))?;
        let url = preview_url(
            self.gateway_tls,
            self.preview_domain.as_deref(),
            self.preview_host.as_deref(),
            &p.id,
        );
        Ok(PreviewInfo {
            id: p.id.clone(),
            proposal: preview.proposal.clone(),
            url,
            fork_lsn: p.fork_lsn,
            no_pii: p.options.no_pii,
            expires_ms: preview.expires_ms,
        })
    }

    async fn preview_create(&self, req: &ApiRequest, caller: &Caller) -> Result<ApiResponse> {
        let r: PreviewCreateRequest = json(&req.body)?;
        reason(&r.reason)?;
        // New work, refused like a fork on a fatal node or a full disk.
        self.node.check_running()?;
        // Like forks: no personal data for a caller without pii:read.
        let no_pii = r.no_pii || !caller.has(Scope::PiiRead);
        let (p, dry_run) = self
            .proposals()?
            .create_preview(
                &r.proposal,
                r.ttl_ms.map(Duration::from_millis),
                no_pii,
                self.audit(req, r.reason.clone()),
                r.dry_run,
            )
            .await?;
        ok(&PreviewCreateResponse {
            dry_run,
            preview: self.preview_info(&p)?,
        })
    }

    async fn previews(&self) -> Result<ApiResponse> {
        let previews = self
            .proposals()?
            .previews()
            .await
            .iter()
            .map(|p| self.preview_info(p))
            .collect::<Result<_>>()?;
        ok(&PreviewsResponse { previews })
    }

    async fn preview_delete(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        self.proposals()?.delete_preview(id, r.dry_run).await?;
        ok(&PreviewDeleteResponse {
            dry_run: r.dry_run,
            deleted: id.to_owned(),
        })
    }
}

/// A preview's URL: on its own host with a preview domain (the gateway
/// serves the prefix only without one, P-F1), with the public host's port
/// when it is not the scheme's default, else under the prefix on the
/// gateway's public `host`.
fn preview_url(tls: bool, domain: Option<&str>, host: Option<&str>, id: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    match (domain, host) {
        (Some(domain), host) => {
            // `public_host` adds `:port` only when it is not the default.
            let port = host
                .and_then(|h| h.rsplit_once(':'))
                .filter(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                .map_or(String::new(), |(_, p)| format!(":{p}"));
            format!("{scheme}://{id}.{domain}{port}/")
        }
        (None, Some(host)) => format!("{scheme}://{host}/__preview/{id}/"),
        (None, None) => format!("/__preview/{id}/"),
    }
}

#[cfg(test)]
mod tests {
    use super::preview_url;

    #[test]
    fn preview_urls_use_the_domain_else_the_public_host() {
        let id = "v-9f8e7d6c5b4a";
        assert_eq!(
            preview_url(
                true,
                Some("preview.example.net"),
                Some("app.example.com"),
                id
            ),
            "https://v-9f8e7d6c5b4a.preview.example.net/"
        );
        assert_eq!(
            preview_url(false, Some("preview.test"), None, id),
            "http://v-9f8e7d6c5b4a.preview.test/"
        );
        assert_eq!(
            preview_url(true, None, Some("app.example.com"), id),
            "https://app.example.com/__preview/v-9f8e7d6c5b4a/"
        );
        assert_eq!(
            preview_url(false, None, Some("127.0.0.1:8080"), id),
            "http://127.0.0.1:8080/__preview/v-9f8e7d6c5b4a/"
        );
        assert_eq!(
            preview_url(false, Some("preview.test"), Some("[::1]:8080"), id),
            "http://v-9f8e7d6c5b4a.preview.test:8080/"
        );
        assert_eq!(
            preview_url(false, Some("preview.test"), Some("[::1]"), id),
            "http://v-9f8e7d6c5b4a.preview.test/"
        );
        assert_eq!(
            preview_url(false, None, None, id),
            "/__preview/v-9f8e7d6c5b4a/"
        );
    }
}
