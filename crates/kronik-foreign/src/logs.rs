//! `foreign/actors/<name>/output.log`: what the program and the runtime write
//! (docs/design/m7-foreign.md §12). Blocking file I/O; callers run it on
//! `Env::blocking`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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
/// and whether older lines exist.
pub(crate) fn tail(
    log: &Path,
    n: usize,
    secrets: &[(String, Vec<u8>)],
) -> io::Result<(Vec<String>, bool)> {
    // Reading at most this much keeps a tail cheap; lines beyond it count
    // as truncated.
    const WINDOW: u64 = 4 << 20;
    let mut bytes = Vec::new();
    let mut truncated = false;
    for path in [rotated(log), log.to_path_buf()] {
        match File::open(&path) {
            Ok(mut f) => {
                let len = f.metadata()?.len();
                if len > WINDOW {
                    f.seek(SeekFrom::Start(len - WINDOW))?;
                    truncated = true;
                    bytes.clear();
                }
                f.read_to_end(&mut bytes)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    let scrubbed = kronik_effects::http::scrub(&bytes, secrets);
    let text = String::from_utf8_lossy(&scrubbed);
    let mut lines: Vec<&str> = text.lines().collect();
    if truncated && !lines.is_empty() {
        // The first line of a window is probably cut.
        lines.remove(0);
    }
    if lines.len() > n {
        truncated = true;
        lines.drain(..lines.len() - n);
    }
    Ok((lines.into_iter().map(str::to_owned).collect(), truncated))
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
        fs::write(&log, "token=hunter2hunter2 ok\nshort=ab\n").unwrap();
        let secrets = vec![
            ("api-key".to_owned(), b"hunter2hunter2".to_vec()),
            ("tiny".to_owned(), b"ab".to_vec()),
        ];
        let (lines, _) = tail(&log, 10, &secrets).unwrap();
        assert_eq!(lines, ["token=[secret:api-key] ok", "short=ab"]);
    }
}
