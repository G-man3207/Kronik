//! Privacy mode (docs/design/m8-privacy.md §3): the `PrivacyMode` record and
//! the per-subject keystore.

use kronik_core::authority::AuthLease;
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
    /// The files of the subject's erased blobs deleted, in main's store and
    /// in the fork spaces (M26 §9.3); 0 for a dry run.
    pub blobs: u64,
    /// Its blobs' objects still in the bucket: the shipper deletes them in
    /// its next round (M26 §9.3); 0 for a dry run.
    pub pending_blob_objects: u64,
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
        authority: AuthLease,
    ) -> Result<PrivacyModeChange, ApiError> {
        authority.check()?;
        self.check_running()?;
        if mode == pb::PrivacyState::Unspecified {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "the privacy mode is on or off",
            ));
        }
        let guard = self.lock_deploy_authorized(&authority).await?;
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
            reseal_requested: false,
        });
        change.lsn = Some(
            self.commit_config_authorized(guard, epoch, record, authority)
                .await?,
        );
        Ok(change)
    }

    /// `kronik privacy erase <subject>` (docs/design/m8-privacy.md §6):
    ///
    /// 1. the subject's keys are deleted, durably, so its sealed values are
    ///    unreadable even if the daemon stops before step 2 (the next start
    ///    commits the record: [`Node::recover_erasures`]); from then on, a
    ///    value of the subject the node held before is never handed to a
    ///    guest nor sealed under a newer key (§6.8, crate::erasure);
    /// 2. an `Erasure` record is committed with the next epoch;
    /// 3. applying it deletes the subject's state values and its rows in
    ///    every actor database's tables with a `_subject` column (replayed
    ///    on every rebuild), and tombstones its queued values.
    ///
    /// Values of other subjects, also those written in the same turns, are
    /// separate and stay. Plain values the subject wrote in `off` mode stay
    /// readable in the log until a reseal (§8); they are counted.
    pub async fn erase_subject(
        &self,
        subject: &str,
        audit: pb::Audit,
        dry_run: bool,
        authority: AuthLease,
    ) -> Result<ErasureDone, ApiError> {
        authority.check()?;
        self.check_alive()?;
        if !kronik_privacy::keystore::valid_subject(subject) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "{subject:?} is not a subject (1 to {} printable ASCII characters without spaces)",
                    kronik_proto::blobs::MAX_SUBJECT_BYTES
                ),
            ));
        }
        let plain_values = self.plain_values_of(subject).await?;
        let guard = self.lock_deploy_authorized(&authority).await?;
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
                blobs: 0,
                pending_blob_objects: 0,
            });
        }
        let node = self
            .arc()
            .ok_or_else(|| ApiError::new(ErrorCode::Unavailable, "the node is stopping"))?;
        // A collector pass waits for this erasure's own deletion of its
        // blobs' files, which counts them (M26 §9.3).
        let erasing = self.blob_gc.erasing.lock().await;
        let erased = subject.to_owned();
        let subject = subject.to_owned();
        let (key_version, lsn) = self
            .authorized_effect(authority, move || async move {
                // Key deletion is irreversible: this admitted private continuation must finish its record or durable recovery.
                let (key_version, fence) = node
                    .erase_keys(&subject, || {
                        node.sealer
                            .erase(&subject, node.env.clock.wall_ms())
                            .map_err(|error| {
                                ApiError::new(ErrorCode::Internal, format!("keystore: {error}"))
                            })
                    })
                    .await?;
                let record = Record::Erasure(pb::Erasure {
                    epoch,
                    subject,
                    key_version,
                    audit: Some(audit),
                });
                let lsn = node.commit_erasure(guard, epoch, record, fence).await?;
                Ok((key_version, lsn))
            })
            .await?;
        tracing::info!(epoch, lsn, key_version, "subject erased");
        // Its blobs' files go now (M26 §9.3). A failure leaves them to the
        // next start's pass and to the collector: the erasure itself is done.
        let blobs = self.delete_erased_blobs_logged().await;
        drop(erasing);
        // Its files that no record references go in the collector's next
        // pass, which this asks for.
        self.wake_for_loose_erasures().await;
        // What the shipper still has in the bucket goes in its next round.
        let pending_blob_objects = self
            .erased_blobs_left()
            .await?
            .get(&erased)
            .map_or(0, |left| left.objects);
        Ok(ErasureDone {
            key_version,
            epoch,
            lsn: Some(lsn),
            plain_values,
            complete_after_ms,
            blobs,
            pending_blob_objects,
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
    /// Erasures that still have a plain value in the log or in `state.db`
    /// (§6.5, §8): a value written in `off` mode that no reseal has sealed
    /// or tombstoned yet, there or in a row the log's records left in
    /// `state.db` (state values, queued timer and message bodies, saved
    /// responses, dead letters, open turns' effects; issue #31), or in this
    /// process from before the erasure: an input still queued, or a turn that
    /// runs across it (§6.8); or while one of its blobs has a file on this
    /// node or an object in the bucket, or the collector has not yet deleted
    /// the files of its blobs that no record references (M26 §9.3). The
    /// count names no subject.
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
        let mut pending: std::collections::HashSet<String> =
            kronik_store::db::plain_subjects(self.store().db().conn())
                .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
                .into_iter()
                .filter(|s| erased.contains(s))
                .collect();
        // Plaintext from before an erasure still waiting in a queue, or held
        // by a turn that runs across it (§6.8).
        pending.extend(self.queued_predating());
        pending.extend(self.running_predating());
        // A resealed segment whose state.db rows are not fixed yet: they may
        // still hold any erased subject's plaintext.
        if self.reseal_fix_pending().await {
            pending.extend(erased.iter().cloned());
        }
        // A blob of the subject with a file on this node or an object in the
        // bucket (M26 §9.3).
        pending.extend(self.erased_blobs_left().await?.into_keys());
        // A file of the subject that no record references (a blob a turn
        // wrote and did not commit, a writer still writing): until the
        // collector has deleted such files after the erasure (M26 §9.3).
        pending.extend(
            self.loose_erasures()
                .await?
                .into_iter()
                .map(|(_, subject, _)| subject),
        );
        let upto = self.applied_lsn();
        if upto < 1 {
            return Ok(pending.len() as u64);
        }
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
    pub async fn reseal_progress(&self) -> crate::ResealProgress {
        match self.cfg.storage.as_ref() {
            Some(s) => {
                let mut progress = crate::reseal::reseal_progress(&s.data_dir);
                progress.pending_blobs = self.pending_blob_reuploads().await;
                progress
            }
            None => crate::ResealProgress::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use kronik_core::env::Env;
    use kronik_core::error::ErrorCode;
    use kronik_proto::log::v1 as pb;

    fn audit() -> pb::Audit {
        pb::Audit {
            token_id: "test".into(),
            reason: "test".into(),
            wall_time_ms: 0,
        }
    }

    /// Erasure uses the same subject rule as the log format, and the refusal
    /// names [`kronik_proto::blobs::MAX_SUBJECT_BYTES`].
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn erasure_uses_the_shared_subject_rule() {
        let dir = tempfile::tempdir().unwrap();
        let node = crate::start_local(
            Env::real(tokio::runtime::Handle::current()),
            dir.path(),
            crate::NodeConfig::default(),
        )
        .await
        .unwrap();
        let authority = node.local_operator_authority().unwrap();
        let limit = kronik_proto::blobs::MAX_SUBJECT_BYTES;
        let max = "a".repeat(limit);
        let over = "a".repeat(limit + 1);
        for subject in ["", " ", "user 1", "\n", "é", over.as_str()] {
            assert!(
                !kronik_proto::blobs::valid_subject(subject),
                "{subject:?} must be one the shared rule rejects"
            );
            let err = node
                .erase_subject(subject, audit(), true, authority.clone())
                .await
                .expect_err(subject);
            assert_eq!(err.code, ErrorCode::BadRequest, "{subject:?} {err}");
            assert!(
                err.message.contains(&format!("1 to {limit} printable")),
                "{subject:?}: {}",
                err.message
            );
        }
        for subject in ["user:1", max.as_str()] {
            assert!(kronik_proto::blobs::valid_subject(subject), "{subject:?}");
            node.erase_subject(subject, audit(), true, authority.clone())
                .await
                .unwrap_or_else(|err| {
                    panic!("{subject:?} is a subject, erasure rejected it: {err}")
                });
        }
    }
}
