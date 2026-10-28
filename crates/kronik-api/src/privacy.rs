//! Privacy mode endpoints (docs/design/m8-privacy.md §12):
//! `GET /v1/privacy`, `POST /v1/privacy/mode`, `POST /v1/privacy/erase`
//! and `POST /v1/privacy/reseal`.

use kronik_proto::log::v1 as pb;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Api, ApiRequest, ApiResponse, Result, json, ok, reason};

/// A privacy mode as the API writes it: `"off"` or `"on"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyModeName {
    Off,
    On,
}

impl From<pb::PrivacyState> for PrivacyModeName {
    fn from(s: pb::PrivacyState) -> Self {
        match s {
            pb::PrivacyState::On => PrivacyModeName::On,
            pb::PrivacyState::Off | pb::PrivacyState::Unspecified => PrivacyModeName::Off,
        }
    }
}

impl From<PrivacyModeName> for pb::PrivacyState {
    fn from(m: PrivacyModeName) -> Self {
        match m {
            PrivacyModeName::On => pb::PrivacyState::On,
            PrivacyModeName::Off => pb::PrivacyState::Off,
        }
    }
}

/// `POST /v1/privacy/mode`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyModeRequest {
    pub mode: PrivacyModeName,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// The answer to `POST /v1/privacy/mode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyModeResponse {
    pub dry_run: bool,
    /// False when the mode already was the one asked for; nothing was
    /// recorded.
    pub changed: bool,
    pub mode: PrivacyModeName,
    pub previous: PrivacyModeName,
    /// The `PrivacyMode` record's configuration epoch (the would-be one for
    /// a dry run); `null` before the first record.
    pub epoch: Option<u64>,
    /// The new record's LSN; `null` for a dry run or when nothing changed.
    pub lsn: Option<u64>,
}

/// The keystore's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeystoreCounts {
    /// Subjects with at least one key.
    pub subjects: u64,
    pub keys: u64,
    /// Erased subjects.
    pub erased: u64,
}

/// `GET /v1/privacy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyStatus {
    pub mode: PrivacyModeName,
    /// The latest `PrivacyMode` record's epoch; `null` before the first.
    pub epoch: Option<u64>,
    /// `null` when the daemon runs without a keystore.
    pub keystore: Option<KeystoreCounts>,
    /// Erasures that still have a plain value in the log (§6.5). The count
    /// names no subject.
    #[serde(default)]
    pub pending_erasures: u64,
    /// Reseal progress (§8). Zero until the first reseal.
    #[serde(default)]
    pub reseal: ResealStatus,
}

/// Progress of the latest reseal, and segments whose shipped copy is still
/// the pre-reseal bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResealStatus {
    pub segments_done: u64,
    pub segments_total: u64,
    pub values_sealed: u64,
    pub tombstones: u64,
    /// Rewritten segments not yet replaced in object storage.
    pub pending_segments: u64,
}

/// `POST /v1/privacy/erase` (§6).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErasureRequest {
    pub subject: String,
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// The answer to `POST /v1/privacy/erase`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErasureResponse {
    pub dry_run: bool,
    pub subject: String,
    /// The last erased key version (0: the subject had no key); 0 for a dry
    /// run.
    pub key_version: u32,
    /// The `Erasure` record's epoch (the would-be one for a dry run).
    pub epoch: u64,
    /// The record's LSN; `null` for a dry run.
    pub lsn: Option<u64>,
    /// The subject's values written in `off` mode that are still plain in
    /// the log, until a reseal (§8).
    pub plain_values: u64,
    /// When shipped keystore backups of this erasure expire
    /// (`erased_at + privacy.keystore_backup_retention`, §6.7). For a dry
    /// run, the would-be time.
    #[serde(default)]
    pub complete_after_ms: u64,
}

/// `POST /v1/privacy/reseal` (§8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResealRequest {
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// The answer to `POST /v1/privacy/reseal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResealResponse {
    pub dry_run: bool,
    /// False for a dry run, and when no closed segment needed rewriting.
    pub started: bool,
    /// Closed segments rewritten, or that a dry run would rewrite.
    pub segments: u64,
}

impl Api {
    pub(crate) async fn route_privacy(
        &self,
        req: &ApiRequest,
        segs: &[&str],
    ) -> Option<Result<ApiResponse>> {
        Some(match (req.method.as_str(), segs) {
            ("GET", ["v1", "privacy"]) => self.privacy_status().await,
            ("POST", ["v1", "privacy", "mode"]) => self.privacy_mode(req).await,
            ("POST", ["v1", "privacy", "erase"]) => self.privacy_erase(req).await,
            ("POST", ["v1", "privacy", "reseal"]) => self.privacy_reseal(req).await,
            _ => return None,
        })
    }

    async fn privacy_status(&self) -> Result<ApiResponse> {
        let (mode, epoch) = self.node.privacy_mode();
        let keystore = self.node.keystore_stats()?.map(|s| KeystoreCounts {
            subjects: s.subjects,
            keys: s.keys,
            erased: s.erased,
        });
        let progress = self.node.reseal_progress();
        ok(&PrivacyStatus {
            mode: mode.into(),
            epoch,
            keystore,
            pending_erasures: self.node.pending_erasures().await?,
            reseal: ResealStatus {
                segments_done: progress.segments_done,
                segments_total: progress.segments_total,
                values_sealed: progress.values_sealed,
                tombstones: progress.tombstones,
                pending_segments: progress.pending_segments,
            },
        })
    }

    async fn privacy_erase(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: ErasureRequest = json(&req.body)?;
        reason(&r.reason)?;
        let audit = self.audit(req, r.reason.clone());
        let done = self
            .node
            .erase_subject(&r.subject, audit, r.dry_run)
            .await?;
        ok(&ErasureResponse {
            dry_run: r.dry_run,
            subject: r.subject,
            key_version: done.key_version,
            epoch: done.epoch,
            lsn: done.lsn,
            plain_values: done.plain_values,
            complete_after_ms: done.complete_after_ms,
        })
    }

    async fn privacy_reseal(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: ResealRequest = json(&req.body)?;
        reason(&r.reason)?;
        let done = self.node.reseal(r.dry_run).await?;
        ok(&ResealResponse {
            dry_run: r.dry_run,
            started: done.started,
            segments: done.segments,
        })
    }

    async fn privacy_mode(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: PrivacyModeRequest = json(&req.body)?;
        reason(&r.reason)?;
        let audit = self.audit(req, r.reason.clone());
        let change = self
            .node
            .set_privacy_mode(r.mode.into(), audit, r.dry_run)
            .await?;
        ok(&PrivacyModeResponse {
            dry_run: r.dry_run,
            changed: change.changed,
            mode: change.mode.into(),
            previous: change.previous.into(),
            epoch: change.epoch,
            lsn: change.lsn,
        })
    }
}
