//! `foreign/actors/<name>/output.log`: what the program and the runtime write
//! (docs/design/m7-foreign.md §12). Blocking file I/O; callers run it on
//! `Env::blocking`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use kronik_effects::http::{CompiledScrubber, ScrubError};

#[derive(Debug)]
pub(crate) enum TailError {
    Io(io::Error),
    Redaction(ScrubError),
}

impl From<io::Error> for TailError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A log over this size is rotated.
pub(crate) const ROTATE_BYTES: u64 = 8 << 20;

pub(crate) fn rotated(log: &Path) -> PathBuf {
    let mut s = log.as_os_str().to_owned();
    s.push(".1");
    PathBuf::from(s)
}

/// Copies a log over `limit` bytes to `<log>.1` and truncates it. The
/// writers use `O_APPEND`, so they continue at the new end; lines written
/// between the copy and the truncation are lost.
pub(crate) fn rotate(log: &Path, limit: u64) -> io::Result<bool> {
    let len = match fs::metadata(log) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if len <= limit {
        return Ok(false);
    }
    fs::copy(log, rotated(log))?;
    OpenOptions::new().write(true).open(log)?.set_len(0)?;
    Ok(true)
}

/// The last `n` lines of the rotated and the current log, with exact
/// occurrences of `secrets` replaced by `[secret:<name>]`. Returns the lines
/// and whether older lines exist; redaction failure returns no lines.
pub(crate) fn tail(
    log: &Path,
    n: usize,
    secrets: &[(&str, &[u8])],
) -> Result<(Vec<String>, bool), TailError> {
    // Reading at most this much keeps a tail cheap; lines beyond it count
    // as truncated.
    const WINDOW: u64 = 4 << 20;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut truncated = false;
    let mut cut_prefix = false;
    for path in [rotated(log), log.to_path_buf()] {
        match File::open(&path) {
            Ok(mut f) => {
                let len = f.metadata()?.len();
                if len > WINDOW {
                    f.seek(SeekFrom::Start(len - WINDOW))?;
                    truncated = true;
                    bytes.clear();
                    cut_prefix = true;
                }
                f.take(len.min(WINDOW)).read_to_end(&mut bytes)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if cut_prefix {
        match bytes.iter().position(|byte| *byte == b'\n') {
            Some(end) => { bytes.drain(..=end); }
            None => bytes.clear(),
        }
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| TailError::Redaction(ScrubError::InvalidText))?;
    let matcher = CompiledScrubber::new_output(secrets, 64 << 20)
        .map_err(TailError::Redaction)?;
    let redacted = zeroize::Zeroizing::new(matcher
        .scrub_if_matched(&bytes, (WINDOW * 2) as usize)
        .map_err(TailError::Redaction)?);
    let text = std::str::from_utf8(redacted.as_deref().unwrap_or(&bytes))
        .map_err(|_| TailError::Redaction(ScrubError::InvalidText))?;
    let mut source = text.lines().rev();
    let mut lines: Vec<_> = source.by_ref().take(n).map(str::to_owned).collect();
    truncated |= source.next().is_some();
    lines.reverse();
    Ok((lines, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_keeps_the_previous_chunk_and_tail_reads_both() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        fs::write(&log, "a\nb\nc\n").unwrap();
        assert!(!rotate(&log, 100).unwrap());
        assert!(rotate(&log, 2).unwrap());
        assert_eq!(fs::read_to_string(rotated(&log)).unwrap(), "a\nb\nc\n");
        assert_eq!(fs::metadata(&log).unwrap().len(), 0);
        fs::write(&log, "d\ne\n").unwrap();
        let (lines, truncated) = tail(&log, 10, &[]).unwrap();
        assert_eq!(lines, ["a", "b", "c", "d", "e"]);
        assert!(!truncated);
        let (lines, truncated) = tail(&log, 2, &[]).unwrap();
        assert_eq!(lines, ["d", "e"]);
        assert!(truncated);
        assert!(!rotate(&dir.path().join("missing"), 1).unwrap());
    }

    #[test]
    fn secrets_are_scrubbed_from_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        fs::write(&log, "token=hunter2hunter2 ok\n").unwrap();
        let secrets = [
            ("api-key", b"hunter2hunter2".as_slice()),
        ];
        let (lines, _) = tail(&log, 10, &secrets).unwrap();
        assert_eq!(lines, ["token=[secret:api-key] ok"]);
    }

    #[test]
    fn original_tail_literals_overlap_and_one_byte_values_are_redacted_once() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        fs::write(&log, "ab a true [secret:literal] retained\n").unwrap();
        let secrets = [
            ("short-a", b"a".as_slice()),
            ("long", b"ab".as_slice()),
            ("truth", b"true".as_slice()),
            ("deleted", b"retained".as_slice()),
        ];
        let (lines, _) = tail(&log, 10, &secrets).unwrap();
        assert_eq!(lines, ["[secret:long] [secret:short-a] [secret:truth] [secret:liter[secret:short-a]l] [secret:deleted]"]);
    }

    #[test]
    fn invalid_text_or_partial_utf8_secret_never_returns_lossy_or_raw_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        fs::write(&log, b"\xff\n").unwrap();
        assert!(matches!(tail(&log, 10, &[]), Err(TailError::Redaction(ScrubError::InvalidText))));
        fs::write(&log, "é\n").unwrap();
        assert!(matches!(
            tail(&log, 10, &[("partial", &[0xc3])]),
            Err(TailError::Redaction(ScrubError::InvalidText))
        ));
    }

    #[test]
    fn marker_expansion_obeys_the_existing_bounded_tail_window() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        fs::write(&log, vec![b'a'; (ROTATE_BYTES / 4) as usize]).unwrap();
        let error = tail(&log, 10, &[("expansion", b"a".as_slice())]).unwrap_err();
        assert!(matches!(error, TailError::Redaction(ScrubError::OutputLimit)));
    }

    #[test]
    fn complete_empty_inventory_still_redacts_credentials_in_a_bounded_tail() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("output.log");
        let token = format!("kronik_{}", "A".repeat(43));
        fs::write(&log, format!("older\n{token}\nnewer\n")).unwrap();
        let (lines, truncated) = tail(&log, 2, &[]).unwrap();
        assert_eq!(lines, ["[secret:token]", "newer"]);
        assert!(truncated);
        let (lines, truncated) = tail(&log, 0, &[]).unwrap();
        assert!(lines.is_empty() && truncated);
    }
}
