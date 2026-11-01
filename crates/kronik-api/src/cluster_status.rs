//! The ordinary read route's concrete adapter; no independent membership cache.
use std::sync::Arc;

use kronik_core::env::BoxFuture;
use kronik_core::error::ApiError;
use serde::Serialize;

use crate::{Api, ApiResponse, Result, ok};

/// Trusted host adapter to the real member producer; never an API caller's map.
pub type ClusterStatusRead =
    Arc<dyn Fn() -> BoxFuture<'static, Result<serde_json::Value, ApiError>> + Send + Sync>;

#[derive(Serialize)]
struct NonMemberStatus {
    member: bool,
}

impl Api {
    /// Install only for a real member runtime backed by its own MetaService.
    /// An installed source's error never becomes the native non-member response.
    pub fn with_cluster_status(mut self, source: ClusterStatusRead) -> Self {
        self.cluster_status = Some(source);
        self
    }

    pub(crate) async fn cluster_status(&self) -> Result<ApiResponse> {
        match &self.cluster_status {
            None => ok(&NonMemberStatus { member: false }),
            Some(source) => {
                let status = source().await?;
                ok(&status)
            }
        }
    }
}
