//! Native-only ordinary record reads from one original active execution and
//! finite applied cut. No body, historical materializer or member constructor.
use super::*;
use kronik_core::authority::Authority as _;
use kronik_core::ids::SourcePos;
use kronik_log::CapturedLogReadset;
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
    // Absent only when this native constructor has no configured physical
    // storage. Its actual EnvFs handles are still retained by the readset.
    root_pin: Option<kronik_core::snapshot_resources::SnapshotRootPin>,
}

fn source_error(error: LogError) -> ApiError {
    let code = match &error {
        LogError::Corrupt(_) => ErrorCode::StorageCorrupt,
        LogError::Io(_) | LogError::Stopped(_) => ErrorCode::Unavailable,
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
            && self
                .root_pin
                .as_ref()
                .is_none_or(|pin| pin.data_is_live_under_publication())
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
        let read = self.readset.read_while_with_namespace(
            requested.max(first),
            through,
            |namespace, committed| {
                let mut source = pb::ActorSource {
                    shard: None,
                    lsn: committed.lsn,
                    branch: String::new(),
                };
                // ActorSource.branch is field 3; count its actual held header before
                // allocating the owned string, as in the canonical member reader.
                let source_bytes = source.encoded_len().saturating_add(
                    1 + prost::length_delimiter_len(namespace.len()) + namespace.len(),
                );
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
                if size > max_encoded_bytes.saturating_sub(bytes) && (!soft || !records.is_empty())
                {
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
            },
        );
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
            let root_pin = if node.cfg.storage.is_some() {
                let owner = node.clone();
                Some(
                    node.env
                        .blocking("native-record-reader-roots", move || {
                            owner.retain_native_source_paths()
                        })
                        .await
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::Unavailable,
                                "the original native source root capture was interrupted",
                            )
                        })??,
                )
            } else {
                None
            };
            let through = node.store.db().applied_lsn().map_err(store_err)?;
            let readset = node
                .reader
                .capture_readset(1, through)
                .await
                .map_err(source_error)?;
            let (branch, retained_from) = if through == 0 {
                // An empty native writer has no positive frame. This is only
                // its configured root label, not an invented ActorSource.
                (
                    node.reader.branch().to_owned(),
                    readset.retained_from().unwrap_or(0),
                )
            } else {
                let first = readset.retained_from().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::StorageCorrupt,
                        "the native applied source has no retained segment",
                    )
                })?;
                let mut head = None;
                readset
                    .read_while_with_namespace(through, through, |namespace, committed| {
                        let actual = pb::ActorSource {
                            shard: None,
                            lsn: committed.lsn,
                            branch: namespace.to_owned(),
                        };
                        actual
                            .validate()
                            .map_err(|error| LogError::Corrupt(error.to_string()))?;
                        head = Some(actual);
                        Ok(false)
                    })
                    .await
                    .map_err(source_error)?;
                let head = head.ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::StorageCorrupt,
                        "the held native source has no frame at its acknowledged head",
                    )
                })?;
                (head.branch, first)
            };
            let reader = ShardReader {
                readset,
                execution,
                epoch,
                expected_epoch,
                root_pin,
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
mod tests;
