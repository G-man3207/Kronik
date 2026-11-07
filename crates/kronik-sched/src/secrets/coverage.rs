//! The durable secret-coverage watermark (`<data>/secret-coverage.json`),
//! a daemon-local cache in the style of the M28 export cursors
//! (temp file + atomic rename, byte budget). It records how far the
//! certified catalogue's reference scan had read, so a restart certifies
//! the prefix from the watermark and re-scans only what came after it.
//! It is written once per fully successful refresh and never with partial
//! progress: a manifest of a scan still under way would replace the
//! watermark the next restart needs.
//!
//! Error semantics are the opposite of the cursors' on purpose: a missing,
//! corrupt, unparseable or failed-validation manifest is discarded with a
//! warning and the next refresh falls back to the full scan. A cache
//! artifact may cost re-scan time; it may never cost availability or
//! correctness, and it must never block startup. The file is daemon-local:
//! it is never shipped and never restored (a restored store's generation
//! voids any copy that could have survived anyway).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes as IoBytes;
use serde::{Deserialize, Serialize};

use kronik_core::env::{Env, OpenMode};

/// The manifest's byte budget: one small record, like an export cursor.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

/// The schema this build writes. `certified_through_lsn` is the last record
/// the finished certification's scan read, so a restart may skip everything up
/// to it. The fingerprint hashes the inventory only (ledger rows, links and
/// file rows), and is information: nothing compares it.
pub const SCHEMA: &str = "kronik.secret-coverage/v2";

/// The schema v0.4.0 wrote, never trusted. v0.4.0 stored the applied LSN of
/// the moment it wrote the file, which can lie ahead of the last record its
/// scan read by every record applied while that refresh ran, so skipping up to
/// it could skip records that no scan read. A v1 manifest is treated like a
/// missing one: the node reads the whole retained log once and the next
/// certification writes v2.
const SCHEMA_V1: &str = "kronik.secret-coverage/v1";

/// The persisted coverage watermark of one native branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageWatermark {
    pub schema: String,
    pub branch: String,
    /// The last record the certified reference scan read: everything up to
    /// it is covered.
    pub certified_through_lsn: u64,
    /// The epoch the certified catalogue was captured under (informational:
    /// a publication retires coverage and the next cycle writes a fresh
    /// watermark).
    pub coverage_epoch: u64,
    /// The certified snapshot's pattern fingerprint, as hex.
    pub coverage_fingerprint: String,
    /// The secret store's random generation (hex): a restored or replaced
    /// store carries another generation and voids the watermark.
    pub store_generation: String,
}

/// Loads the watermark, if a valid one exists. Every problem — missing
/// file, oversize, parse failure, schema or field mismatch — is a warning
/// and `None`: the caller falls back to the full scan. A v0.4.0 (v1)
/// manifest is not trusted either (see `SCHEMA_V1`); it is noted once at
/// info level, not warned about, since the upgrade is not a fault.
pub async fn load(env: &Env, data_dir: &Path, branch: &str) -> Option<CoverageWatermark> {
    let path = path(data_dir);
    if !env.fs.exists(path.clone()).await.unwrap_or(false) {
        return None;
    }
    match read(env, &path).await {
        Ok(watermark) => {
            if watermark.schema == SCHEMA_V1 {
                note_v1(&path);
                return None;
            }
            let valid = watermark.schema == SCHEMA
                && watermark.branch == branch
                && watermark.certified_through_lsn > 0;
            if valid {
                Some(watermark)
            } else {
                warn(&path, "unusable watermark fields").await;
                None
            }
        }
        Err(error) => {
            warn(&path, &format!("unreadable watermark: {error}")).await;
            None
        }
    }
}

/// Persists the watermark after a fully successful refresh cycle. A failure
/// here only costs the next restart its delta (the file is a cache), so it
/// is logged, never propagated.
pub async fn persist(env: &Env, data_dir: &Path, watermark: &CoverageWatermark) {
    let path = path(data_dir);
    let bytes = match serde_json::to_vec(watermark) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn(&path, &format!("watermark encode: {error}")).await;
            return;
        }
    };
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        warn(&path, "watermark exceeds its byte budget").await;
        return;
    }
    let temp = path.with_extension("json.tmp");
    let write = async {
        let file = env
            .fs
            .open(temp.clone(), OpenMode::ReadWriteCreate)
            .await
            .map_err(|error| format!("open: {error}"))?;
        file.set_len(0)
            .await
            .map_err(|error| format!("len: {error}"))?;
        file.write_at(0, IoBytes::from(bytes))
            .await
            .map_err(|error| format!("write: {error}"))?;
        file.sync_data()
            .await
            .map_err(|error| format!("sync: {error}"))?;
        env.fs
            .rename(temp, path.clone())
            .await
            .map_err(|error| format!("rename: {error}"))?;
        if let Some(dir) = path.parent() {
            env.fs
                .sync_dir(dir.to_owned())
                .await
                .map_err(|error| format!("sync dir: {error}"))?;
        }
        Ok::<(), String>(())
    };
    if let Err(error) = write.await {
        warn(&path, &format!("watermark write: {error}")).await;
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("secret-coverage.json")
}

async fn read(env: &Env, path: &Path) -> Result<CoverageWatermark, String> {
    let file = env
        .fs
        .open(path.to_path_buf(), OpenMode::Read)
        .await
        .map_err(|error| format!("open: {error}"))?;
    let len = file.len().await.map_err(|error| format!("len: {error}"))?;
    if len > MAX_MANIFEST_BYTES {
        return Err("the watermark exceeds its byte budget".into());
    }
    let bytes = file
        .read_at(0, usize::try_from(len).unwrap_or(usize::MAX))
        .await
        .map_err(|error| format!("read: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse: {error}"))
}

/// Says once per process that a v0.4.0 manifest is not trusted.
fn note_v1(path: &Path) {
    static NOTED: AtomicBool = AtomicBool::new(false);
    if !NOTED.swap(true, Ordering::Relaxed) {
        tracing::info!(
            target: "kronik::secrets",
            file = %path.display(),
            "a v0.4.0 secret-coverage watermark is not trusted; \
             recertifying from the first retained record"
        );
    }
}

async fn warn(path: &Path, message: &str) {
    tracing::warn!(
        target: "kronik::secrets",
        file = %path.display(),
        "{message}; recertifying from a full scan"
    );
}
