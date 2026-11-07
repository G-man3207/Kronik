//! The reference scan of the retained log: which secret versions its effect
//! records cite, and which secret names its ledger and link records touch.
//!
//! A certification re-reads only the records the durable coverage watermark
//! (`coverage.rs`) has not covered, so its cost follows the log appended
//! since, never the whole log. The scan reads whole segment images and
//! decodes them on the blocking pool, up to `SCAN_WIDTH` segments at a
//! time, as the startup replay does. `LogReader::read_while` is not used
//! here: it validates the part of a segment before the first requested
//! record with two blocking-pool round trips per record on every call, so
//! a scan that starts late in a long segment costs time in proportion to
//! the segment, and a scan made of many short calls costs time in proportion
//! to the square of it.

use std::collections::VecDeque;

use kronik_core::env::JoinHandle;
use kronik_privacy::sealer::Sealer;

use super::*;

/// Segment images in flight at once: 64 MiB each at the default segment size.
pub(super) const SCAN_WIDTH: usize = 4;

/// What a pass over a range of the retained log found.
#[derive(Debug, Default)]
pub(super) struct LogScan {
    /// Every `(name, version)` the range's effect records cite, with the
    /// version hash each cites it by.
    pub(super) references: BTreeMap<(String, u64), Vec<u8>>,
    /// Names of the ledger and link records in the range.
    pub(super) touched: BTreeSet<String>,
    /// How many records the range held.
    pub(super) records: u64,
    /// How many effect requests of erased subjects it met: they cite nothing
    /// anyone can read, so they are not in `references`. The effect of a
    /// finished turn is in the log twice, in its own record and in its
    /// turn's, and counts twice.
    pub(super) erased: u64,
}

impl LogScan {
    pub(super) fn visit(&mut self, record: &Record, sealer: &Sealer) -> Result<(), ApiError> {
        self.records += 1;
        self.erased += collect_secret_references(record, sealer, &mut self.references)?;
        match record {
            Record::SecretVersion(row) => {
                self.touched.insert(row.name.clone());
            }
            Record::SecretLink(link) => {
                self.touched.insert(link.name.clone());
            }
            _ => {}
        }
        Ok(())
    }

    /// Adds the findings of a later part of the log. Two parts that cite
    /// one version by different hashes are in conflict, as within one part.
    fn merge(&mut self, later: LogScan) -> Result<(), ApiError> {
        for (key, hash) in later.references {
            if self
                .references
                .get(&key)
                .is_some_and(|known| *known != hash)
            {
                return Err(unavailable());
            }
            self.references.insert(key, hash);
        }
        if self.references.len() > MAX_INVENTORY_VALUES {
            return Err(unavailable());
        }
        self.touched.extend(later.touched);
        self.records += later.records;
        self.erased += later.erased;
        Ok(())
    }
}

/// One segment's part of a scan, and the LSN the next segment must start at.
type SegmentScan = (LogScan, u64);

impl Node {
    /// Scans the records `from..=upto` of the retained log. A range the log
    /// does not hold completely (a missing or torn acknowledged record, a
    /// gap between segments) is an error, as for `LogReader::read_while`.
    pub(super) async fn scan_secret_use(&self, from: u64, upto: u64) -> Result<LogScan, ApiError> {
        let mut found = LogScan::default();
        if from > upto || upto == 0 {
            return Ok(found);
        }
        let reader = self.reader().clone();
        let starts = reader.starts().await.map_err(|_| unavailable())?;
        let mut segments = Vec::new();
        for (index, &start) in starts.iter().enumerate() {
            if starts.get(index + 1).is_some_and(|&next| next <= from) {
                continue;
            }
            if start > upto {
                break;
            }
            segments.push((start, index + 1 == starts.len()));
        }
        let spawn = |(start, last): (u64, bool)| -> JoinHandle<Result<SegmentScan, ApiError>> {
            let (reader, sealer, env) = (reader.clone(), self.sealer.clone(), self.env.clone());
            self.env.spawn("secret-reference-scan", async move {
                let image = reader.read_image(start).await.map_err(|_| unavailable())?;
                let branch = reader.branch().to_owned();
                env.blocking("secret-reference-scan", move || {
                    let mut part = LogScan::default();
                    let next = kronik_log::scan_segment_image(
                        &image,
                        &branch,
                        start,
                        from,
                        upto,
                        last,
                        |committed| {
                            part.visit(&committed.record, &sealer).map_err(|_| {
                                kronik_log::LogError::Corrupt(
                                    "invalid retained secret reference".into(),
                                )
                            })
                        },
                    )
                    .map_err(|_: kronik_log::LogError| unavailable())?;
                    Ok((part, next))
                })
                .await
                .ok_or_else(unavailable)?
            })
        };
        let mut pending = VecDeque::new();
        let mut queued = segments.into_iter();
        let mut expected: Option<u64> = None;
        loop {
            while pending.len() < SCAN_WIDTH
                && let Some(segment) = queued.next()
            {
                pending.push_back((segment.0, spawn(segment)));
            }
            let Some((start, handle)) = pending.pop_front() else {
                break;
            };
            let (part, next) = handle.await.ok_or_else(unavailable)??;
            if expected.is_some_and(|expected| expected != start) {
                return Err(unavailable());
            }
            expected = Some(next);
            found.merge(part)?;
        }
        if expected.is_none_or(|next| next <= upto) {
            return Err(unavailable());
        }
        Ok(found)
    }
}
