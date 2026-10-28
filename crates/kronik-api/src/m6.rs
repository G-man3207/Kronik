//! The M6 storage endpoints (docs/design/m6-storage.md): snapshots and the
//! integrity hashes a restore is checked against.

use std::collections::BTreeSet;
use std::path::Path;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::snapshots::Manifest;

use crate::types::*;
use crate::{Api, ApiRequest, ApiResponse, Result, internal, json, ok, reason};

fn entry(m: &Manifest, shipped: bool) -> SnapshotEntry {
    SnapshotEntry {
        id: m.id.clone(),
        lsn: m.lsn,
        created_wall_ms: m.created_wall_ms,
        engine_version: m.engine_version.clone(),
        bytes: m.bytes(),
        reason: m.reason.clone(),
        state_hash: m.state_hash.clone(),
        shipped,
    }
}

/// Snapshot LSNs recorded as uploaded in `<data>/ship.json`. Empty when
/// shipping is off or the file is missing or unreadable.
fn shipped_snapshots(data: &Path) -> BTreeSet<u64> {
    let Ok(bytes) = std::fs::read(data.join("ship.json")) else {
        return BTreeSet::new();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return BTreeSet::new();
    };
    v.get("snapshots")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|n| n.as_u64()).collect())
        .unwrap_or_default()
}

impl Api {
    pub(crate) async fn route_m6(
        &self,
        req: &ApiRequest,
        segs: &[&str],
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("GET", ["v1", "snapshots"]) => self.snapshots(),
            ("POST", ["v1", "snapshots"]) => self.snapshot_create(req).await,
            ("GET", ["v1", "integrity"]) => self.integrity().await,
            _ => return None,
        })
    }

    fn snapshots(&self) -> Result<ApiResponse> {
        let shipped = self.shipped_lsns();
        let snapshots = self
            .node
            .snapshots()?
            .iter()
            .rev()
            .map(|m| entry(m, shipped.contains(&m.lsn)))
            .collect();
        ok(&SnapshotsResponse { snapshots })
    }

    fn shipped_lsns(&self) -> BTreeSet<u64> {
        self.node
            .storage_config()
            .map(|s| shipped_snapshots(&s.data_dir))
            .unwrap_or_default()
    }

    async fn snapshot_create(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: SnapshotCreateRequest = json(&req.body)?;
        reason(&r.reason)?;
        if r.dry_run {
            return ok(&SnapshotCreateResponse {
                dry_run: true,
                snapshot: None,
                lsn: self.node.applied_lsn(),
            });
        }
        let m = self.node.snapshot("manual").await?;
        let shipped = self.shipped_lsns().contains(&m.lsn);
        ok(&SnapshotCreateResponse {
            dry_run: false,
            lsn: m.lsn,
            snapshot: Some(entry(&m, shipped)),
        })
    }

    async fn integrity(&self) -> Result<ApiResponse> {
        let store = self.node.store();
        let state_hash = store.state_hash().map_err(internal)?;
        let applied = self.node.applied_lsn();
        let mut first = None;
        let mut h = blake3::Hasher::new();
        self.node
            .reader()
            .read(1, applied, |c| {
                first.get_or_insert(c.lsn);
                if c.lsn > applied {
                    return Ok(());
                }
                h.update(&c.lsn.to_le_bytes());
                h.update(&[c.record.kind()]);
                h.update(&c.record.encode());
                Ok(())
            })
            .await
            .map_err(internal)?;
        if applied > 0 && first.is_none() {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "the log holds no records",
            ));
        }
        let (retention_history_ms, newest_logical_time_ms, retention_cutoff_ms) =
            match self.node.storage_config() {
                Some(storage) => {
                    let newest = self.node.store().db().time_hwm().map_err(internal)?;
                    let cutoff = kronik_sched::snapshots::history_cutoff(newest, storage.history);
                    (storage.history.as_millis() as u64, newest, cutoff)
                }
                // Genuinely absent (DST, `Node::start` with `storage: None`).
                // `start_local` and `kronik serve` always install a config.
                None => (0, 0, 0),
            };
        ok(&IntegrityResponse {
            applied_lsn: applied,
            state_hash,
            log_first_lsn: first.unwrap_or(1),
            log_hash: format!("b3:{}", h.finalize().to_hex()),
            retention_history_ms,
            newest_logical_time_ms,
            retention_cutoff_ms,
        })
    }
}
