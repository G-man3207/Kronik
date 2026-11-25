//! Native-only ordinary record reads from one original active execution and
//! finite applied cut. No body, historical materializer or member constructor.
use super::*;
use kronik_core::authority::Authority as _;
use kronik_core::ids::SourcePos;
use kronik_log::{CapturedLogReadset, Position};
use prost::Message as _;
use std::future::Future;

// The canonical record-page bound, without importing a member transport into
// the native profile. Local export alone may admit one MAX_RECORD-sized frame.
const MAX_RECORD_PAGE_BYTES: usize = 64 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardReadPoint {
    pub branch: String,
    pub source: SourcePos,
    pub retained_from: Lsn,
}

pub struct ShardRecordPage {
    pub records: Vec<(pb::ActorSource, Committed)>,
    pub scanned_through: Lsn,
    pub retention_gap: Option<(Lsn, Lsn)>,
}

/// The constructor is private and requires the actual native writer binding.
/// Held files are source data, never user authority or a complete census.
pub struct ShardReader {
    readset: CapturedLogReadset,
    execution: Arc<crate::native_execution::NativeExecution>,
    epoch: Arc<AtomicU64>,
    expected_epoch: u64,
    point: ShardReadPoint,
    /// Next record's file offset, when the caller has one. A page that
    /// starts there does not CRC-walk the segment prefix.
    resume: Option<ExportResume>,
}

/// Where the next export read should start. The offset is the caller's,
/// observed from a record it already consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportResume {
    pub segment: Lsn,
    pub offset: u64,
    pub lsn: Lsn,
}

impl ExportResume {
    /// The record itself.
    pub fn at(record: &Committed) -> Self {
        Self {
            segment: record.pos.segment,
            offset: record.pos.offset,
            lsn: record.lsn,
        }
    }

    /// The byte after `record`, where the next LSN should be.
    pub fn after(record: &Committed) -> Self {
        Self {
            segment: record.pos.segment,
            offset: record.pos.offset
                + kronik_log::ENVELOPE_LEN as u64
                + record.record.encoded_len() as u64,
            lsn: record.lsn.saturating_add(1),
        }
    }
}

/// File position of the newest applied record whose position is known.
/// The pending slot is staged before apply, so a waiter that sees the new
/// applied LSN also sees the position and does not walk to find it.
#[derive(Debug, Default)]
pub(crate) struct AppliedCut {
    visible: Mutex<Option<(Lsn, Position)>>,
    pending: Mutex<Option<(Lsn, Position)>>,
}

impl AppliedCut {
    pub(crate) fn stage(&self, lsn: Lsn, pos: Position) {
        *lock(&self.pending) = Some((lsn, pos));
    }

    pub(crate) fn clear_staged(&self) {
        *lock(&self.pending) = None;
    }

    pub(crate) fn publish(&self, lsn: Lsn, pos: Position) {
        let mut visible = lock(&self.visible);
        if visible.as_ref().is_none_or(|(known, _)| *known <= lsn) {
            *visible = Some((lsn, pos));
        }
    }

    pub(crate) fn publish_staged(&self) {
        let staged = *lock(&self.pending);
        let Some((lsn, pos)) = staged else {
            return;
        };
        self.publish(lsn, pos);
        let mut pending = lock(&self.pending);
        if pending.as_ref().is_some_and(|(got, _)| *got == lsn) {
            *pending = None;
        }
    }

    /// A reseal moved this LSN. A later head is left alone.
    pub(crate) fn moved(&self, lsn: Lsn, pos: Position) {
        let mut visible = lock(&self.visible);
        if let Some((known, at)) = visible.as_mut()
            && *known == lsn
        {
            *at = pos;
        }
        let mut pending = lock(&self.pending);
        if let Some((known, at)) = pending.as_mut()
            && *known == lsn
        {
            *at = pos;
        }
    }

    /// Newest published frame at or below `applied`.
    pub(crate) fn frame(&self, applied: Lsn) -> Option<(Lsn, Position)> {
        let pending = lock(&self.pending).filter(|(lsn, _)| *lsn <= applied);
        let visible = lock(&self.visible).filter(|(lsn, _)| *lsn <= applied);
        match (visible, pending) {
            (Some(known), Some(staged)) => Some(if staged.0 >= known.0 { staged } else { known }),
            (known, staged) => known.or(staged),
        }
    }
}

fn source_error(error: LogError) -> ApiError {
    let code = match &error {
        LogError::Corrupt(_) => ErrorCode::StorageCorrupt,
        LogError::Io(_) | LogError::Stopped(_) | LogError::RenameNotDurable(_) => {
            ErrorCode::Unavailable
        }
        // Only appends refuse a body; a read never returns this.
        LogError::TooLarge { .. } => ErrorCode::Internal,
    };
    ApiError::new(code, error.to_string())
}

impl ShardReader {
    pub fn point(&self) -> &ShardReadPoint {
        &self.point
    }

    /// This is the original active execution and configuration, never a fresh
    /// lookup of current authority. No Node is retained by the returned reader.
    pub fn check(&self) -> Result<(), ApiError> {
        self.execution.check()?;
        if !self.data_is_live_under_publication() {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "the original native source configuration changed",
            ));
        }
        Ok(())
    }

    /// DATA only. The configured exporter invokes this inside its SAME original
    /// admission and existing certificate/cache publication fence. No I/O,
    /// authority getter, lock, fence or allocation occurs here.
    pub fn data_is_live_under_publication(&self) -> bool {
        self.execution.active_source_is_live_under_publication()
            && self.epoch.load(Ordering::Acquire) == self.expected_epoch
    }

    pub async fn page(
        &self,
        after: Lsn,
        max_records: usize,
        max_encoded_bytes: usize,
    ) -> Result<ShardRecordPage, ApiError> {
        self.read_page(after, max_records, max_encoded_bytes, false)
            .await
    }

    /// The existing native soft budget: one oversized record may stand alone,
    /// bounded by the canonical decoder's MAX_RECORD, never by an unbounded read.
    pub async fn local_export_page(
        &self,
        after: Lsn,
        max_records: usize,
        soft_bytes: usize,
    ) -> Result<ShardRecordPage, ApiError> {
        self.read_page(after, max_records, soft_bytes, true).await
    }

    async fn read_page(
        &self,
        after: Lsn,
        max_records: usize,
        max_encoded_bytes: usize,
        soft: bool,
    ) -> Result<ShardRecordPage, ApiError> {
        self.check()?;
        if max_records == 0 || max_encoded_bytes == 0 || max_encoded_bytes > MAX_RECORD_PAGE_BYTES {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "source page requires positive bounded record and encoded-byte limits",
            ));
        }
        let SourcePos::Actor {
            shard: None,
            lsn: through,
        } = self.point.source
        else {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "a native reader lost its original native domain",
            ));
        };
        if after > through {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "source cursor is above its original captured head",
            ));
        }
        if after == through {
            self.check()?;
            return Ok(ShardRecordPage {
                records: Vec::new(),
                scanned_through: through,
                retention_gap: None,
            });
        }
        let first = self.point.retained_from;
        let requested = after + 1;
        let gap = (requested < first).then(|| (requested, through.min(first - 1)));
        let mut scanned = gap.map_or(after, |(_, last)| last);
        if scanned == through {
            self.check()?;
            return Ok(ShardRecordPage {
                records: Vec::new(),
                scanned_through: scanned,
                retention_gap: gap,
            });
        }
        let mut records = Vec::new();
        let mut bytes = 0usize;
        let mut oversized = None;
        let start = requested.max(first);
        let mut consume = |namespace: &str, committed: Committed| -> Result<bool, LogError> {
            let mut source = pb::ActorSource {
                shard: None,
                lsn: committed.lsn,
                branch: String::new(),
            };
            // ActorSource.branch is field 3; count its actual held header before
            // allocating the owned string, as in the canonical member reader.
            let source_bytes = source
                .encoded_len()
                .saturating_add(1 + prost::length_delimiter_len(namespace.len()) + namespace.len());
            let record_bytes = committed.record.encoded_len();
            let frame_bytes = 1
                + prost::length_delimiter_len(source_bytes)
                + source_bytes
                + 1
                + prost::encoding::encoded_len_varint(u64::from(committed.record.kind()))
                + 1
                + prost::length_delimiter_len(record_bytes)
                + record_bytes;
            let size = 1 + prost::length_delimiter_len(frame_bytes) + frame_bytes;
            if size > max_encoded_bytes.saturating_sub(bytes) && (!soft || !records.is_empty()) {
                if records.is_empty() && size > max_encoded_bytes {
                    oversized = Some(committed.lsn);
                }
                return Ok(false);
            }
            bytes += size;
            scanned = committed.lsn;
            source.branch = namespace.to_owned();
            source
                .validate()
                .map_err(|error| LogError::Corrupt(error.to_string()))?;
            records.push((source, committed));
            Ok(records.len() < max_records && bytes < max_encoded_bytes)
        };
        let read = async {
            if let Some(resume) = self.resume
                && resume.lsn == start
            {
                let anchored = self
                    .readset
                    .read_from_offset(
                        Position {
                            segment: resume.segment,
                            offset: resume.offset,
                        },
                        resume.lsn,
                        through,
                        &mut consume,
                    )
                    .await?;
                if anchored {
                    return Ok(());
                }
                // shortcut: a reseal moved this offset, walk this page once and resume after it
            }
            self.readset
                .read_while_with_namespace(start, through, &mut consume)
                .await
        };
        tokio::select! {
            biased;
            () = self.execution.cancelled() => return Err(ApiError::new(ErrorCode::Unavailable, "the original native source execution ended")),
            result = read => result.map_err(source_error)?,
        }
        if let Some(lsn) = oversized {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("source record at LSN {lsn} exceeds this page's encoded-byte bound"),
            ));
        }
        self.check()?;
        Ok(ShardRecordPage {
            records,
            scanned_through: scanned,
            retention_gap: gap,
        })
    }
}

impl Node {
    /// Capture the actual ACTIVE original native role before constructing the
    /// future. This fixed configured source grants no operator mutation scope.
    pub fn capture_system_export_reader(
        self: &Arc<Self>,
    ) -> impl Future<Output = Result<ShardReader, ApiError>> + Send + 'static {
        self.capture_export_reader(None)
    }

    /// As [`Self::capture_system_export_reader`], resuming at `resume` when
    /// the caller has the next record's file offset. The applied head is one
    /// `read_at`. The snapshot lock is not held across either read.
    pub fn capture_export_reader(
        self: &Arc<Self>,
        resume: Option<ExportResume>,
    ) -> impl Future<Output = Result<ShardReader, ApiError>> + Send + 'static {
        let captured = (|| {
            self.native_execution.check()?;
            self.native_execution.native_source_start(self, &self.log)?;
            Ok::<_, ApiError>((
                self.clone(),
                self.native_execution.clone(),
                self.epoch.clone(),
                self.epoch(),
            ))
        })();
        async move {
            let (node, execution, epoch, expected_epoch) = captured?;
            let original: AuthLease = execution.clone();
            let _deploy = node.lock_deploy_authorized(&original).await?;
            let (through, head) = {
                let _snapshot = tokio::select! {
                    biased;
                    () = original.cancelled() => return Err(ApiError::new(ErrorCode::Unavailable,
                        "the original native source ended before retention capture")),
                    held = node.snapshot_lock.clone().lock_owned() => held,
                };
                original.check()?;
                if epoch.load(Ordering::Acquire) != expected_epoch {
                    return Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the original native source configuration changed before capture",
                    ));
                }
                if node.cfg.storage.is_some() {
                    let owner = node.clone();
                    node.env
                        .blocking("native-record-reader-roots", move || {
                            owner.check_native_source_directory()
                        })
                        .await
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::Unavailable,
                                "the original native source root capture was interrupted",
                            )
                        })??;
                }
                let applied = node.store.db().applied_lsn().map_err(store_err)?;
                let head = node.applied_cut.frame(applied);
                if applied > 0 && head.is_none() {
                    return Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the applied head position is not published yet",
                    ));
                }
                let through = head.map(|(lsn, _)| lsn).unwrap_or(0);
                (through, head)
            };
            let (branch, retained_from, readset) = if through == 0 {
                let readset = node
                    .reader
                    .capture_readset(1, 0)
                    .await
                    .map_err(source_error)?;
                (
                    node.reader.branch().to_owned(),
                    readset.retained_from().unwrap_or(0),
                    readset,
                )
            } else {
                let (_, pos) = head.ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::StorageCorrupt,
                        "the native applied source has no published head position",
                    )
                })?;
                let (branch, committed) = node
                    .reader
                    .read_at_with_namespace(pos)
                    .await
                    .map_err(source_error)?;
                if committed.lsn != through {
                    return Err(ApiError::new(
                        ErrorCode::Unavailable,
                        "the applied head moved before its position was read",
                    ));
                }
                let actual = pb::ActorSource {
                    shard: None,
                    lsn: committed.lsn,
                    branch: branch.clone(),
                };
                actual
                    .validate()
                    .map_err(|error| ApiError::new(ErrorCode::StorageCorrupt, error.to_string()))?;
                let from = resume
                    .map(|point| point.lsn.max(1))
                    .unwrap_or(1)
                    .min(through);
                let starts = node.reader.starts().await.map_err(source_error)?;
                let retained_from = starts.first().copied().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::StorageCorrupt,
                        "the native applied source has no retained segment",
                    )
                })?;
                let readset = node
                    .reader
                    .capture_readset(from, through)
                    .await
                    .map_err(source_error)?;
                (branch, retained_from, readset)
            };
            let reader = ShardReader {
                readset,
                execution,
                epoch,
                expected_epoch,
                resume,
                point: ShardReadPoint {
                    branch,
                    source: SourcePos::Actor {
                        shard: None,
                        lsn: through,
                    },
                    retained_from,
                },
            };
            reader.check()?;
            Ok(reader)
        }
    }
}

#[cfg(test)]
mod export_reads;
#[cfg(test)]
mod tests;
