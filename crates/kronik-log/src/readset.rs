//! Fixed-range record readsets retaining the actual EnvFs files, never authority.
use super::*;

struct CapturedSegment {
    start: Lsn,
    path: PathBuf,
    file: Arc<dyn File>,
    length: u64,
    header: Header,
    last: bool,
}

/// A finite held set of original log files and validated headers/lengths.
/// Handles survive replacement/unlink in both native and memory Fs. This is
/// source DATA, not permission, a complete physical census or a deletion proof.
pub struct CapturedLogReadset {
    from: Lsn,
    through: Lsn,
    files: Vec<CapturedSegment>,
}

impl LogReader {
    /// Capture while the caller retains its actual source/retention guards.
    /// A fixed zero cut is an empty data view, never a positive source frame.
    pub async fn capture_readset(&self, from: Lsn, through: Lsn) -> Result<CapturedLogReadset, LogError> {
        if through == Lsn::MAX {
            return Err(corrupt("a captured readset requires a finite acknowledged cut"));
        }
        let mut files = Vec::new();
        if from > through || through == 0 {
            return Ok(CapturedLogReadset { from, through, files });
        }
        let starts = self.starts().await?;
        for (index, &start) in starts.iter().enumerate() {
            if starts.get(index + 1).is_some_and(|&next| next <= from) { continue; }
            if start > through { break; }
            let path = self.dir.join(segment_name(start));
            let file = self.env.fs.open(path.clone(), OpenMode::Read).await?;
            let length = file.len().await?;
            // The native writer has one configured namespace. Never allocate a
            // header buffer from an untrusted on-disk branch length.
            let image = file.read_at(0, 24 + self.branch.len()).await?;
            let header = parse_header(&image).ok_or_else(||
                corrupt(format!("segment {} has no valid header", path.display())))?;
            if header.start_lsn != start || header.branch != self.branch {
                return Err(corrupt(format!("segment {} header mismatch", path.display())));
            }
            files.push(CapturedSegment { start, path, file, length, header,
                last: index + 1 == starts.len() });
        }
        Ok(CapturedLogReadset { from, through, files })
    }
}

impl CapturedLogReadset {
    pub fn from(&self) -> Lsn { self.from }
    pub fn through(&self) -> Lsn { self.through }
    pub fn retained_from(&self) -> Option<Lsn> { self.files.first().map(|file| file.start) }

    /// The canonical CRC/header/dense-frame walker on the SAME held files.
    /// Only the visited prefix is decoded, as for the ordinary LogReader.
    pub async fn read_while_with_namespace(&self, from: Lsn, through: Lsn,
        mut consume: impl FnMut(&str, Committed) -> Result<bool, LogError>) -> Result<(), LogError>
    {
        if from < self.from || through > self.through {
            return Err(corrupt("the requested range exceeds its fixed captured log readset"));
        }
        if from > through || through == 0 { return Ok(()); }
        let mut expected = None;
        for (index, segment) in self.files.iter().enumerate() {
            if self.files.get(index + 1).is_some_and(|next| next.start <= from) { continue; }
            if segment.start > through { break; }
            let progress = read_segment(segment.file.as_ref(), segment.length, &segment.header,
                &segment.path, segment.start, from, through, segment.last, expected, &mut consume).await?;
            if progress.stopped { return Ok(()); }
            expected = Some(progress.next_lsn);
        }
        if expected.is_none_or(|next| next <= through) {
            return Err(corrupt(format!("log has no record at lsn {through}")));
        }
        Ok(())
    }
}

pub(super) struct SegmentProgress {
    pub(super) next_lsn: Lsn,
    pub(super) stopped: bool,
}

/// Shared with the live LogReader, not a second decoder or a pathname reopen.
pub(super) async fn read_segment(file: &dyn File, file_len: u64, header: &Header,
    path: &Path, start: Lsn, from: Lsn, through: Lsn, last: bool, expected: Option<Lsn>,
    consume: &mut impl FnMut(&str, Committed) -> Result<bool, LogError>) -> Result<SegmentProgress, LogError>
{
    if let Some(expected) = expected && expected != start {
        return Err(corrupt(format!("segment {} starts at lsn {start}, expected {expected}", path.display())));
    }
    let mut next_lsn = start;
    let mut off = header.len as u64;
    while off < file_len {
        if next_lsn > through { return Ok(SegmentProgress { next_lsn, stopped: true }); }
        if file_len - off < ENVELOPE_LEN as u64 { break; }
        let envelope = file.read_at(off, ENVELOPE_LEN).await?;
        if envelope.len() != ENVELOPE_LEN { break; }
        let (Some(len), Some(stored_crc), Some(lsn)) =
            (u32_at(&envelope, 0), u32_at(&envelope, 4), u64_at(&envelope, 8))
        else { break; };
        if len > MAX_RECORD || ENVELOPE_LEN as u64 + len as u64 > file_len - off { break; }
        let kind = envelope[16];
        if kind != FOOTER_KIND && lsn != next_lsn { break; }
        let mut crc = crc32c::crc32c(&envelope[8..]);
        let mut payload = Vec::new();
        if kind != FOOTER_KIND && lsn >= from {
            payload = file.read_at(off + ENVELOPE_LEN as u64, len as usize).await?;
            if payload.len() != len as usize { break; }
            crc = crc32c::crc32c_append(crc, &payload);
        } else {
            let mut read = 0;
            while read < len as usize {
                let size = (len as usize - read).min(64 << 10);
                let chunk = file.read_at(off + ENVELOPE_LEN as u64 + read as u64, size).await?;
                if chunk.len() != size { break; }
                crc = crc32c::crc32c_append(crc, &chunk);
                read += size;
            }
            if read != len as usize { break; }
        }
        if crc != stored_crc { break; }
        if kind == FOOTER_KIND {
            off += ENVELOPE_LEN as u64 + len as u64;
            continue;
        }
        if lsn >= from {
            let record = Record::decode(kind, &payload)
                .map_err(|error| corrupt(format!("record at lsn {lsn}: {error}")))?;
            if !consume(&header.branch, Committed { lsn, pos: Position { segment: start, offset: off }, record })? {
                return Ok(SegmentProgress { next_lsn, stopped: true });
            }
        } else if kind == 0 || !kronik_proto::kind::ALL.contains(&kind) {
            return Err(corrupt(format!("record at lsn {lsn} has kind {kind}")));
        }
        next_lsn += 1;
        off += ENVELOPE_LEN as u64 + len as u64;
    }
    if (off < file_len && !last) || (last && through != Lsn::MAX && next_lsn <= through) {
        return Err(corrupt(format!("segment {} is invalid at offset {off}", path.display())));
    }
    Ok(SegmentProgress { next_lsn, stopped: false })
}

#[cfg(test)]
mod tests;
