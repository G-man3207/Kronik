//! The M6 storage endpoints (docs/design/m6-storage.md): snapshots and the
//! integrity hashes a restore is checked against.

use std::collections::BTreeSet;
use std::path::Path;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::snapshots::Manifest;

use crate::types::*;
use crate::{Api, ApiResponse, AuthorizedRequest, Result, internal, json, ok, reason};

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
        req: &AuthorizedRequest,
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

    async fn snapshot_create(&self, req: &AuthorizedRequest) -> Result<ApiResponse> {
        let r: SnapshotCreateRequest = json(&req.body)?;
        reason(&r.reason)?;
        if r.dry_run {
            return ok(&SnapshotCreateResponse {
                dry_run: true,
                snapshot: None,
                lsn: self.node.applied_lsn(),
            });
        }
        let m = self.node.snapshot("manual", req.authority.clone()).await?;
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
    async fn integrity(&self, req: &AuthorizedRequest) -> Result<ApiResponse> {
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
        let (log_first_lsn, log_hash, mut needed) = self.hashed_log(applied, upto).await?;
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
            log_first_lsn,
            log_hash,
            through_lsn: upto,
            retention_history_ms,
            newest_logical_time_ms,
            retention_cutoff_ms,
        })
    }
}

/// Resumes the log hash from the last LSN this process hashed, not from LSN 1
/// on every request (ADR 0153). Marks let a `through` behind the tip resume
/// from a saved prefix.
pub(super) struct IntegrityLog {
    inner: tokio::sync::Mutex<LogHashState>,
}

struct LogHashState {
    ready: bool,
    origin: Option<u64>,
    tip: u64,
    hasher: blake3::Hasher,
    needed: kronik_store::db::SubjectKeys,
    /// `(lsn, hasher after records through lsn)`, ascending. `0` is the empty prefix.
    marks: Vec<(u64, blake3::Hasher)>,
    first: Option<u64>,
}

const LOG_MARKS: usize = 64;

impl IntegrityLog {
    pub(super) fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(LogHashState::fresh(None)),
        }
    }
}

impl LogHashState {
    fn fresh(origin: Option<u64>) -> Self {
        let hasher = blake3::Hasher::new();
        Self {
            ready: false,
            origin,
            tip: 0,
            hasher: hasher.clone(),
            needed: kronik_store::db::SubjectKeys::new(),
            marks: vec![(0, hasher)],
            first: None,
        }
    }
}

#[cfg(test)]
static INTEGRITY_LOG_FROM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn reset_log_from() {
    #[cfg(test)]
    INTEGRITY_LOG_FROM.store(0, std::sync::atomic::Ordering::Relaxed);
}

fn note_log_from(from: u64) {
    #[cfg(test)]
    {
        use std::sync::atomic::Ordering;
        let cur = INTEGRITY_LOG_FROM.load(Ordering::Relaxed);
        if cur == 0 || from < cur {
            INTEGRITY_LOG_FROM.store(from, Ordering::Relaxed);
        }
    }
    #[cfg(not(test))]
    let _ = from;
}

fn mix_record(h: &mut blake3::Hasher, c: &kronik_log::Committed) {
    h.update(&c.lsn.to_le_bytes());
    h.update(&[c.record.kind()]);
    h.update(&c.record.encode());
}

fn push_mark(marks: &mut Vec<(u64, blake3::Hasher)>, lsn: u64, hasher: &blake3::Hasher) {
    if marks.last().is_none_or(|(have, _)| *have != lsn) {
        marks.push((lsn, hasher.clone()));
    }
}

fn trim_marks(marks: &mut Vec<(u64, blake3::Hasher)>) {
    if marks.len() <= LOG_MARKS {
        return;
    }
    let mut kept = Vec::with_capacity(LOG_MARKS);
    if marks.first().is_some_and(|(lsn, _)| *lsn == 0) {
        kept.push(marks[0].clone());
    }
    let skip = marks.len() - (LOG_MARKS - kept.len());
    kept.extend(marks.iter().skip(skip).cloned());
    *marks = kept;
}

impl Api {
    /// Log hash through `upto`, and the sealed keys of records through `applied`.
    async fn hashed_log(
        &self,
        applied: u64,
        upto: u64,
    ) -> Result<(u64, String, kronik_store::db::SubjectKeys)> {
        reset_log_from();
        let starts = self.node.reader().starts().await.map_err(internal)?;
        let origin = starts.first().copied();
        let boundaries: std::collections::BTreeSet<u64> = starts.into_iter().skip(1).collect();
        let mut cache = self.integrity_log.inner.lock().await;
        if !cache.ready || cache.origin != origin || cache.tip > applied {
            *cache = LogHashState::fresh(origin);
        }
        if cache.tip < applied {
            let from = cache.tip.saturating_add(1).max(1);
            let tip = cache.tip;
            let at_tip = cache.hasher.clone();
            push_mark(&mut cache.marks, tip, &at_tip);
            let mut hasher = cache.hasher.clone();
            let mut needed = cache.needed.clone();
            let mut marks = cache.marks.clone();
            let mut first = cache.first;
            note_log_from(from);
            self.node
                .reader()
                .read(from, applied, |mut c| {
                    if c.lsn > applied {
                        return Ok(());
                    }
                    if c.lsn > 0 && boundaries.contains(&c.lsn) {
                        push_mark(&mut marks, c.lsn - 1, &hasher);
                    }
                    mix_record(&mut hasher, &c);
                    first.get_or_insert(c.lsn);
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
            push_mark(&mut marks, applied, &hasher);
            trim_marks(&mut marks);
            cache.hasher = hasher;
            cache.needed = needed;
            cache.marks = marks;
            cache.first = first;
            cache.tip = applied;
            cache.origin = origin;
            cache.ready = true;
        } else if applied > 0 && cache.first.is_none() {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "the log holds no records",
            ));
        }
        let hash = hash_through(&cache, upto, self).await?;
        Ok((cache.first.unwrap_or(1), hash, cache.needed.clone()))
    }
}

async fn hash_through(cache: &LogHashState, upto: u64, api: &Api) -> Result<String> {
    if upto >= cache.tip {
        return Ok(format!("b3:{}", cache.hasher.finalize().to_hex()));
    }
    let Some((idx, _)) = cache
        .marks
        .iter()
        .enumerate()
        .rev()
        .find(|(_, (lsn, _))| *lsn <= upto)
    else {
        return Err(internal("log hash has no prefix mark"));
    };
    let (lsn, hasher) = &cache.marks[idx];
    if *lsn == upto {
        return Ok(format!("b3:{}", hasher.finalize().to_hex()));
    }
    let from = lsn.saturating_add(1).max(1);
    note_log_from(from);
    let mut hasher = hasher.clone();
    api.node
        .reader()
        .read(from, upto, |c| {
            if c.lsn <= upto {
                mix_record(&mut hasher, &c);
            }
            Ok(())
        })
        .await
        .map_err(internal)?;
    Ok(format!("b3:{}", hasher.finalize().to_hex()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)]

    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use kronik_core::env::Env;
    use kronik_sched::{NodeConfig, start_local};
    use serde_json::{Value, json};

    use super::INTEGRITY_LOG_FROM;
    use crate::{Api, ApiRequest};

    async fn call(api: &Api, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let r = api
            .handle(ApiRequest {
                method: method.into(),
                path: path.into(),
                query: query.into(),
                body: if body.is_null() {
                    vec![]
                } else {
                    body.to_string().into_bytes()
                },
                token_id: "unix:uid=0".into(),
                bearer: None,
            })
            .await;
        (r.status, serde_json::from_slice(&r.body).unwrap())
    }

    async fn snapshot(api: &Api, node: &kronik_sched::Node) -> u64 {
        let before = node.applied_lsn();
        let (status, body) = call(api, "POST", "/v1/snapshots", json!({"reason": "r"})).await;
        assert_eq!(status, 200, "{body}");
        for _ in 0..500 {
            if node.applied_lsn() > before {
                return node.applied_lsn();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("snapshot did not apply past {before}");
    }

    /// Issue #163: the log hash resumes. A repeat does not read, a later tip
    /// reads only the new records, and `through` of a saved tip does not
    /// start at LSN 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn integrity_log_hash_resumes_instead_of_scanning_from_lsn_1() {
        let dir = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = start_local(env, dir.path(), NodeConfig::default())
            .await
            .unwrap();
        let api = Arc::new(Api::new(node.clone()));
        snapshot(&api, &node).await;

        let (status, first) = call(&api, "GET", "/v1/integrity", Value::Null).await;
        assert_eq!(status, 200, "{first}");
        let applied = first["applied_lsn"].as_u64().unwrap();
        let (status, again) = call(&api, "GET", "/v1/integrity", Value::Null).await;
        assert_eq!(status, 200, "{again}");
        assert_eq!(again, first);
        assert_eq!(
            INTEGRITY_LOG_FROM.load(Ordering::Relaxed),
            0,
            "a repeat integrity read the log"
        );

        snapshot(&api, &node).await;
        let (status, later) = call(&api, "GET", "/v1/integrity", Value::Null).await;
        assert_eq!(status, 200, "{later}");
        let from = INTEGRITY_LOG_FROM.load(Ordering::Relaxed);
        assert!(from > 1, "extended the log hash from LSN {from}");
        assert_ne!(later["log_hash"], first["log_hash"]);

        let (status, through) = call(
            &api,
            "GET",
            &format!("/v1/integrity?through={applied}"),
            Value::Null,
        )
        .await;
        assert_eq!(status, 200, "{through}");
        assert_eq!(through["log_hash"], first["log_hash"]);
        assert_eq!(through["through_lsn"], applied);
        assert_eq!(
            INTEGRITY_LOG_FROM.load(Ordering::Relaxed),
            0,
            "through a saved tip scanned the log"
        );
    }
}
