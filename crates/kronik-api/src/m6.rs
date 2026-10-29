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
            ("GET", ["v1", "integrity"]) => self.integrity(req).await,
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
        let details = [("lsn", m.lsn.to_string())];
        self.audit_event(req, "snapshot.create", &m.id, &details, r.reason)
            .await?;
        let shipped = self.shipped_lsns().contains(&m.lsn);
        ok(&SnapshotCreateResponse {
            dry_run: false,
            lsn: m.lsn,
            snapshot: Some(entry(&m, shipped)),
        })
    }

    /// `through`: hash the log only through that LSN, to compare a
    /// restored node, whose first start adds its `restore` event, with the
    /// source up to the source's applied LSN.
    async fn integrity(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let through = crate::Query::parse(&req.query)?.num("through")?;
        let store = self.node.store();
        let state_hash = store.state_hash().map_err(internal)?;
        let applied = self.node.applied_lsn();
        if let Some(t) = through.filter(|t| *t == 0 || *t > applied) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("through {t} is not in 1..={applied}, the applied LSN"),
            ));
        }
        let upto = through.unwrap_or(applied);
        let mut first = None;
        let mut h = blake3::Hasher::new();
        let mut needed = kronik_store::db::SubjectKeys::new();
        self.node
            .reader()
            .read(1, applied, |mut c| {
                first.get_or_insert(c.lsn);
                if c.lsn > applied {
                    return Ok(());
                }
                if c.lsn <= upto {
                    h.update(&c.lsn.to_le_bytes());
                    h.update(&[c.record.kind()]);
                    h.update(&c.record.encode());
                }
                kronik_proto::sealables::record_mut(
                    &mut c.record,
                    &mut kronik_store::db::note_sealed(&mut needed),
                );
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
        // Sealed values whose subject key the keystore lacks (a restore
        // with --without-keystore, a lost keystore.db): unreadable data.
        for ((subject, _), sample) in
            kronik_store::db::sealed_keys(store.db().conn()).map_err(internal)?
        {
            kronik_store::db::note_key(&mut needed, &subject, &sample);
        }
        let mut keys_missing: Vec<String> = Vec::new();
        if let Some(ks) = self.node.sealer().keystore() {
            for ((subject, version), sample) in &needed {
                if !ks.covers(subject, *version, sample).map_err(internal)?
                    && keys_missing.last() != Some(subject)
                {
                    keys_missing.push(subject.clone());
                }
            }
        } else {
            keys_missing.extend(needed.keys().map(|(s, _)| s.clone()));
            keys_missing.dedup();
        }
        ok(&IntegrityResponse {
            keys_missing,
            applied_lsn: applied,
            state_hash,
            log_first_lsn: first.unwrap_or(1),
            log_hash: format!("b3:{}", h.finalize().to_hex()),
            through_lsn: upto,
            retention_history_ms,
            newest_logical_time_ms,
            retention_cutoff_ms,
        })
    }
}
