//! Privacy mode (docs/design/m8-privacy.md §3): the `PrivacyMode` record and
//! the per-subject keystore.

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::Lsn;
use kronik_privacy::keystore::KeystoreStats;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

use crate::Node;

/// What `kronik privacy mode on|off` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyModeChange {
    /// False when the mode already was the one asked for; nothing was
    /// recorded.
    pub changed: bool,
    pub mode: pb::PrivacyState,
    pub previous: pb::PrivacyState,
    /// The new record's epoch, or the current record's when nothing changed
    /// (`None` before the first record).
    pub epoch: Option<u64>,
    /// The new record's LSN; `None` for a dry run or when nothing changed.
    pub lsn: Option<Lsn>,
}

/// What `kronik privacy erase` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErasureDone {
    /// The last erased key version (0: the subject had no key).
    pub key_version: u32,
    pub epoch: u64,
    /// `None` for a dry run.
    pub lsn: Option<Lsn>,
    /// The subject's plain values still in the log (written in `off` mode).
    pub plain_values: u64,
    /// When shipped keystore backups of this erasure expire
    /// (`erased_at + privacy.keystore_backup_retention`).
    pub complete_after_ms: u64,
}

impl Node {
    /// The privacy mode in effect, with its record's epoch.
    pub fn privacy_mode(&self) -> (pb::PrivacyState, Option<u64>) {
        self.config_now().privacy()
    }

    /// `kronik privacy mode on|off`: commits a `PrivacyMode` record with the
    /// next configuration epoch, unless the mode already is `mode`. Values
    /// are sealed by the mode in effect when their record is assembled.
    pub async fn set_privacy_mode(
        &self,
        mode: pb::PrivacyState,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<PrivacyModeChange, ApiError> {
        self.check_running()?;
        if mode == pb::PrivacyState::Unspecified {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "the privacy mode is on or off",
            ));
        }
        let guard = self.deploy_lock.clone().lock_owned().await;
        let (previous, current) = self.privacy_mode();
        let mut change = PrivacyModeChange {
            changed: previous != mode,
            mode,
            previous,
            epoch: current,
            lsn: None,
        };
        if !change.changed {
            return Ok(change);
        }
        let epoch = self.epoch() + 1;
        change.epoch = Some(epoch);
        if dry_run {
            return Ok(change);
        }
        let record = Record::PrivacyMode(pb::PrivacyMode {
            epoch,
            mode: mode as i32,
            audit: Some(audit),
        });
        // Turning on seals from before the record is durable, so no value
        // written after it is left plain; turning off waits for it.
        if mode == pb::PrivacyState::On {
            self.sealer.set_on(true);
        }
        // commit_config sets the sealer to the mode in force afterwards.
        change.lsn = Some(self.commit_config(guard, epoch, record).await?);
        Ok(change)
    }

    /// `kronik privacy erase <subject>` (docs/design/m8-privacy.md §6):
    ///
    /// 1. the subject's keys are deleted first, durably, so its sealed
    ///    values are unreadable even if the daemon stops before step 2
    ///    (the next start commits the record: [`Node::recover_erasures`]);
    /// 2. an `Erasure` record is committed with the next epoch;
    /// 3. applying it deletes the subject's state values and its rows in
    ///    every actor database's tables with a `_subject` column (replayed
    ///    on every rebuild).
    ///
    /// Values of other subjects, also those written in the same turns, are
    /// separate and stay. Plain values the subject wrote in `off` mode stay
    /// readable in the log until a reseal (§8); they are counted.
    pub async fn erase_subject(
        &self,
        subject: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<ErasureDone, ApiError> {
        self.check_alive()?;
        if !kronik_privacy::keystore::valid_subject(subject) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "{subject:?} is not a subject (1 to 256 printable ASCII characters without spaces)"
                ),
            ));
        }
        let plain_values = self.plain_values_of(subject).await?;
        let guard = self.deploy_lock.clone().lock_owned().await;
        let epoch = self.epoch() + 1;
        let complete_after_ms = self
            .env
            .clock
            .wall_ms()
            .saturating_add(self.cfg.keystore_backup_retention.as_millis() as u64);
        if dry_run {
            return Ok(ErasureDone {
                key_version: 0,
                epoch,
                lsn: None,
                plain_values,
                complete_after_ms,
            });
        }
        let key_version = self
            .sealer
            .erase(subject, self.env.clock.wall_ms())
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("keystore: {e}")))?;
        let record = Record::Erasure(pb::Erasure {
            epoch,
            subject: subject.to_owned(),
            key_version,
            audit: Some(audit),
        });
        let lsn = self.commit_config(guard, epoch, record).await?;
        tracing::info!(epoch, lsn, key_version, "subject erased");
        Ok(ErasureDone {
            key_version,
            epoch,
            lsn: Some(lsn),
            plain_values,
            complete_after_ms,
        })
    }

    /// Commits an `Erasure` record for every subject the keystore erased
    /// but the log has no record for (a stop between the two steps of
    /// [`Node::erase_subject`]), so its state values and SQL rows go too.
    /// Runs at start; returns how many records it committed.
    pub(crate) async fn recover_erasures(&self) -> Result<usize, ApiError> {
        let keystore = self
            .sealer
            .erasures()
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("keystore: {e}")))?;
        if keystore.is_empty() {
            return Ok(0);
        }
        let recorded: std::collections::HashMap<String, u32> = self
            .store()
            .db()
            .erasures()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
            .into_iter()
            .collect();
        let mut n = 0;
        for e in keystore {
            if recorded
                .get(&e.subject)
                .is_some_and(|v| *v >= e.last_version)
            {
                continue;
            }
            let guard = self.deploy_lock.clone().lock_owned().await;
            let epoch = self.epoch() + 1;
            let record = Record::Erasure(pb::Erasure {
                epoch,
                subject: e.subject,
                key_version: e.last_version,
                audit: Some(pb::Audit {
                    token_id: "kronik".to_owned(),
                    reason: "recovery: the subject's keys were erased, its Erasure record was \
                             not committed"
                        .to_owned(),
                    wall_time_ms: self.env.clock.wall_ms(),
                }),
            });
            let lsn = self.commit_config(guard, epoch, record).await?;
            tracing::warn!(epoch, lsn, "erasure recovered: its record is committed now");
            n += 1;
        }
        Ok(n)
    }

    /// Plain (never sealed) values of `subject` in the log (§6.5).
    async fn plain_values_of(&self, subject: &str) -> Result<u64, ApiError> {
        let mut n = 0u64;
        self.reader()
            .read(1, self.applied_lsn(), |mut c| {
                kronik_proto::sealables::record_mut(&mut c.record, &mut |s| {
                    if s.subject.as_deref() == Some(subject)
                        && matches!(s.value, Some(pb::sealable::Value::Plain(_)))
                    {
                        n += 1;
                    }
                });
                Ok(())
            })
            .await
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reading the log: {e}")))?;
        Ok(n)
    }

    /// The keystore's counts for `kronik privacy status`; `None` when the
    /// node runs without one.
    pub fn keystore_stats(&self) -> Result<Option<KeystoreStats>, ApiError> {
        self.sealer
            .keystore()
            .map(|k| k.stats())
            .transpose()
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("keystore: {e}")))
    }
    /// Erasures that still have a plain value in the log (§6.5). The count
    /// names no subject.
    pub async fn pending_erasures(&self) -> Result<u64, ApiError> {
        let erased: std::collections::HashSet<String> = self
            .store()
            .db()
            .erasures()
            .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        if erased.is_empty() {
            return Ok(0);
        }
        let upto = self.applied_lsn();
        if upto < 1 {
            return Ok(0);
        }
        let mut pending = std::collections::HashSet::new();
        self.reader()
            .read(1, upto, |mut c| {
                kronik_proto::sealables::record_mut(&mut c.record, &mut |s| {
                    if let Some(subject) = s.subject.as_ref()
                        && erased.contains(subject)
                        && matches!(s.value, Some(pb::sealable::Value::Plain(_)))
                    {
                        pending.insert(subject.clone());
                    }
                });
                Ok(())
            })
            .await
            .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reading the log: {e}")))?;
        Ok(pending.len() as u64)
    }

    /// Reseal progress for `GET /v1/privacy`.
    pub fn reseal_progress(&self) -> crate::ResealProgress {
        match self.cfg.storage.as_ref() {
            Some(s) => crate::reseal::reseal_progress(&s.data_dir),
            None => crate::ResealProgress::default(),
        }
    }
}
