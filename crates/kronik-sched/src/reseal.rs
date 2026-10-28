//! Reseal via compaction (docs/design/m8-privacy.md §8): rewrite closed
//! segments so tagged plain values are sealed and erased subjects become
//! tombstones, then fix offsets and the state.db rows those records still
//! own (`kv`, saved responses, dead letters).

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;
use kronik_privacy::sealer::{ResealOp, Sealer};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use serde::{Deserialize, Serialize};

use crate::Node;

/// What `kronik privacy reseal` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResealDone {
    /// False for a dry run, and when nothing needed rewriting.
    pub started: bool,
    /// Closed segments rewritten, or that a dry run would rewrite.
    pub segments: u64,
    pub values_sealed: u64,
    pub tombstones: u64,
}

/// Last reseal's progress, plus segments whose shipped copy is still the
/// pre-reseal bytes (docs/design/m8-privacy.md §8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResealProgress {
    pub segments_done: u64,
    pub segments_total: u64,
    pub values_sealed: u64,
    pub tombstones: u64,
    /// Rewritten segments not yet replaced in object storage.
    pub pending_segments: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ProgressFile {
    segments_done: u64,
    segments_total: u64,
    values_sealed: u64,
    tombstones: u64,
}

fn privacy_dir(data: &Path) -> PathBuf {
    data.join("privacy")
}

fn progress_path(data: &Path) -> PathBuf {
    privacy_dir(data).join("reseal.json")
}

fn reupload_dir(data: &Path) -> PathBuf {
    privacy_dir(data).join("reupload")
}

fn reupload_path(data: &Path, start: Lsn) -> PathBuf {
    reupload_dir(data).join(format!("{start:020}"))
}

fn retention_path(data: &Path) -> PathBuf {
    privacy_dir(data).join("keystore_retention_ms")
}

/// Writes the retention the shipper uses for keystore backups. A missing
/// file means the default (30 days).
pub fn publish_keystore_retention(data: &Path, retention_ms: u64) {
    let dir = privacy_dir(data);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %e, "could not create the privacy directory");
        return;
    }
    if let Err(e) = std::fs::write(retention_path(data), retention_ms.to_string()) {
        tracing::warn!(error = %e, "could not record keystore backup retention");
    }
}

/// `privacy.keystore_backup_retention` as published by the node, or 30 days.
pub fn keystore_retention_ms(data: &Path) -> u64 {
    std::fs::read_to_string(retention_path(data))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(30 * 86_400 * 1000)
}

/// Marks a rewritten segment so the shipper uploads it again. The file
/// holds the BLAKE3 of the bytes that must be shipped; a shipper that sees
/// a different file leaves the mark (the rename has not happened yet).
pub fn mark_reupload(data: &Path, start: Lsn, bytes: &[u8]) -> std::io::Result<()> {
    let path = reupload_path(data, start);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let hash = blake3::hash(bytes).to_hex().to_string();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, hash)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Whether `bytes` are the rewritten segment the mark is waiting to ship.
pub fn reupload_ready(data: &Path, start: Lsn, bytes: &[u8]) -> bool {
    let Ok(want) = std::fs::read_to_string(reupload_path(data, start)) else {
        return false;
    };
    blake3::hash(bytes).to_hex().to_string() == want.trim()
}

/// Drops the mark after a successful re-upload.
pub fn clear_reupload(data: &Path, start: Lsn) -> std::io::Result<()> {
    match std::fs::remove_file(reupload_path(data, start)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Rewritten segments whose shipped copy has not been replaced.
pub fn pending_reuploads(data: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(reupload_dir(data)) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.len() == 20 && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .count() as u64
}

fn load_progress(data: &Path) -> ProgressFile {
    std::fs::read(progress_path(data))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_progress(data: &Path, p: &ProgressFile) -> Result<(), ApiError> {
    let dir = privacy_dir(data);
    std::fs::create_dir_all(&dir)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("privacy directory: {e}")))?;
    let bytes = serde_json::to_vec_pretty(p)
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let path = progress_path(data);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reseal progress: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reseal progress: {e}")))?;
    Ok(())
}

/// Progress for `GET /v1/privacy`. `data` is the node's data directory.
pub fn reseal_progress(data: &Path) -> ResealProgress {
    let p = load_progress(data);
    ResealProgress {
        segments_done: p.segments_done,
        segments_total: p.segments_total,
        values_sealed: p.values_sealed,
        tombstones: p.tombstones,
        pending_segments: pending_reuploads(data),
    }
}

fn is_tombstone(s: &pb::Sealable, version: u32) -> bool {
    matches!(
        &s.value,
        Some(pb::sealable::Value::Sealed(x))
            if x.key_version == version
                && x.ciphertext.is_empty()
                && x.nonce.iter().all(|b| *b == 0)
    )
}

fn needs_reseal(record: &Record, erased: &HashMap<String, u32>) -> bool {
    let mut need = false;
    let mut copy = record.clone();
    kronik_proto::sealables::record_mut(&mut copy, &mut |s| {
        let Some(subject) = s.subject.as_deref() else {
            return;
        };
        if let Some(&ver) = erased.get(subject) {
            if !is_tombstone(s, ver) {
                need = true;
            }
        } else if matches!(s.value, Some(pb::sealable::Value::Plain(_))) {
            need = true;
        }
    });
    need
}

fn reseal_record(
    sealer: &Sealer,
    record: &mut Record,
    erased: &HashMap<String, u32>,
    fill: &dyn Fn(&mut [u8]),
    wall_ms: u64,
) -> Result<(u64, u64), String> {
    let mut sealed = 0u64;
    let mut tombs = 0u64;
    let mut err = None;
    kronik_proto::sealables::record_mut(record, &mut |s| {
        if err.is_some() {
            return;
        }
        let ver = s.subject.as_ref().and_then(|sub| erased.get(sub).copied());
        match sealer.reseal_value(s, ver, &fill, wall_ms) {
            Ok(ResealOp::Sealed) => sealed += 1,
            Ok(ResealOp::Tombstone) => tombs += 1,
            Ok(ResealOp::Unchanged) => {}
            Err(e) => err = Some(e.to_string()),
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok((sealed, tombs)),
    }
}

impl Node {
    fn erasure_versions(&self) -> Result<HashMap<String, u32>, ApiError> {
        self.sealer
            .erasures()
            .map(|rows| {
                rows.into_iter()
                    .map(|e| (e.subject, e.last_version))
                    .collect()
            })
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("keystore: {e}")))
    }

    fn data_dir(&self) -> Option<&Path> {
        self.cfg.storage.as_ref().map(|s| s.data_dir.as_path())
    }

    /// Closed segments that still hold a tagged plain value, or a value of
    /// an erased subject that is not yet a tombstone. The active segment is
    /// never included.
    async fn segments_to_reseal(&self) -> Result<Vec<Lsn>, ApiError> {
        let log_dir = self.reader().dir();
        let starts = kronik_log::segment_starts(log_dir)
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("log: {e}")))?;
        let Some(&active) = starts.last() else {
            return Ok(Vec::new());
        };
        let erased = self.erasure_versions()?;
        let mut need = BTreeSet::new();
        let upto = self.applied_lsn();
        if upto >= 1 {
            self.reader()
                .read(1, upto, |c| {
                    if c.pos.segment != active && needs_reseal(&c.record, &erased) {
                        need.insert(c.pos.segment);
                    }
                    Ok(())
                })
                .await
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reading the log: {e}")))?;
        }
        Ok(need.into_iter().collect())
    }

    /// Waits until every closed segment's records are applied, so the offset
    /// fix cannot race the applier. Turns may still append to the active
    /// segment; a roll during the wait is waited out.
    async fn wait_closed_applied(&self) -> Result<Lsn, ApiError> {
        let log_dir = self.reader().dir();
        loop {
            let starts = kronik_log::segment_starts(log_dir)
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("log: {e}")))?;
            let Some(&active) = starts.last() else {
                return Ok(1);
            };
            let covered = active.saturating_sub(1);
            if covered > 0 {
                self.store().applied.wait(covered).await;
            }
            let again = kronik_log::segment_starts(log_dir)
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("log: {e}")))?;
            if again.last() == Some(&active) {
                return Ok(active);
            }
        }
    }

    /// `kronik privacy reseal` (docs/design/m8-privacy.md §8). Requires the
    /// mode to be `on`. Rewrites closed segments only; the active segment
    /// waits for the next roll. A dry run writes nothing.
    pub async fn reseal(&self, dry_run: bool) -> Result<ResealDone, ApiError> {
        self.check_running()?;
        if self.privacy_mode().0 != pb::PrivacyState::On {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "privacy mode is off, so reseal cannot seal history",
            )
            .with_hint("kronik privacy mode on --reason '...'"));
        }
        if self.sealer.keystore().is_none() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "this node has no keystore, so reseal cannot seal history",
            ));
        }
        if dry_run {
            let n = self.segments_to_reseal().await?.len() as u64;
            return Ok(ResealDone {
                started: false,
                segments: n,
                values_sealed: 0,
                tombstones: 0,
            });
        }
        let _guard = self.deploy_lock.lock().await;
        let active = self.wait_closed_applied().await?;
        let todo = self.segments_to_reseal().await?;
        let todo: Vec<Lsn> = todo.into_iter().filter(|s| *s != active).collect();
        if todo.is_empty() {
            return Ok(ResealDone {
                started: false,
                segments: 0,
                values_sealed: 0,
                tombstones: 0,
            });
        }
        let data = self.data_dir().map(Path::to_path_buf);
        let total = todo.len() as u64;
        if let Some(data) = &data {
            save_progress(
                data,
                &ProgressFile {
                    segments_done: 0,
                    segments_total: total,
                    values_sealed: 0,
                    tombstones: 0,
                },
            )?;
        }
        let erased = self.erasure_versions()?;
        let wall = self.env.clock.wall_ms();
        let entropy = self.env.entropy.clone();
        let fill = |b: &mut [u8]| entropy.fill(b);
        let mut done = 0u64;
        let mut values_sealed = 0u64;
        let mut tombstones = 0u64;
        let log_dir = self.reader().dir();
        for start in todo {
            let starts = kronik_log::segment_starts(log_dir)
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("log: {e}")))?;
            if starts.last() == Some(&start) {
                continue;
            }
            if let Some(next) = starts.iter().copied().find(|s| *s > start) {
                self.store().applied.wait(next - 1).await;
            }
            let path = log_dir.join(kronik_log::segment_name(start));
            let mut counts = (0u64, 0u64);
            // The changed turns: fix_reseal rewrites the state.db rows
            // they still own (kv, saved responses, dead letters).
            let mut turns: Vec<(Lsn, pb::TurnRecord)> = Vec::new();
            let rewritten = kronik_log::rewrite_segment(&path, |lsn, record| {
                reseal_record(self.sealer(), record, &erased, &fill, wall).map(|(s, t)| {
                    counts.0 += s;
                    counts.1 += t;
                    // A rebased turn owns the state rows it wrote, as a turn
                    // record does (M13).
                    if s + t > 0
                        && let Some(turn) = record.turn()
                    {
                        turns.push((lsn, turn.clone()));
                    }
                    s + t > 0
                })
            })
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reseal: {e}")))?;
            if !rewritten.changed {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| {
                ApiError::new(
                    ErrorCode::Internal,
                    format!("reading the rewritten segment: {e}"),
                )
            })?;
            if let Some(data) = &data {
                mark_reupload(data, start, &bytes).map_err(|e| {
                    ApiError::new(
                        ErrorCode::Internal,
                        format!("marking the segment for re-upload: {e}"),
                    )
                })?;
            }
            self.store()
                .db()
                .fix_reseal(start, &rewritten.offsets, &turns)
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reseal: {e}")))?;
            values_sealed += counts.0;
            tombstones += counts.1;
            done += 1;
            if let Some(data) = &data {
                save_progress(
                    data,
                    &ProgressFile {
                        segments_done: done,
                        segments_total: total,
                        values_sealed,
                        tombstones,
                    },
                )?;
            }
            tracing::info!(
                start,
                values_sealed = counts.0,
                tombstones = counts.1,
                "resealed a closed segment"
            );
        }
        if done > 0 && self.cfg.storage.is_some() {
            // The segments are rewritten already: the snapshot that drops
            // the plaintext copies must not wait for disk space.
            self.take_snapshot("reseal").await?;
        }
        Ok(ResealDone {
            started: done > 0,
            segments: done,
            values_sealed,
            tombstones,
        })
    }
}
