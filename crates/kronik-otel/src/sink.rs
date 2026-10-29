//! The audit export (docs/design/m28-otel.md §4.4–§4.6, §5; ADRs 0083,
//! 0084): the sinks (a directory of JSON-lines files, a webhook, object
//! storage) and the [`follow::Sink`] that turns committed records into
//! `kronik.audit/v1` lines for them. It holds retention at its cursor and
//! records a gap as a system `audit.gap` event when the hold gave way.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;

use crate::audit::Mapper;
use crate::cursor::Cursors;
use crate::follow::{self, Delivery, Stream};
use crate::http;

/// The stream's name: its cursor and its metrics' label.
pub const STREAM: &str = "audit";

/// A parsed `[audit] sink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    /// `file:///dir/`: `audit-<first lsn:020>.jsonl` files.
    File(PathBuf),
    /// `https://…`, or `http://` to a loopback address.
    Webhook(String),
    /// `s3://bucket/prefix`, with `[audit] endpoint` for S3-compatible
    /// servers.
    S3 {
        url: String,
        endpoint: Option<String>,
    },
}

impl Sink {
    /// Checks `[audit] sink` and `endpoint` (§6.1): a known scheme, a
    /// bucket, an absolute directory, plain HTTP only to loopback, and
    /// `endpoint` only with `s3://`. Errors never repeat a webhook's path,
    /// which can hold a credential.
    pub fn parse(url: &str, endpoint: Option<&str>) -> Result<Sink, String> {
        let endpoint = endpoint.filter(|e| !e.is_empty());
        if endpoint.is_some() && !url.starts_with("s3://") {
            return Err("[audit] endpoint is for an s3:// sink only".into());
        }
        if let Some(path) = url.strip_prefix("file://") {
            let path = Path::new(path);
            if !path.is_absolute() {
                return Err(format!(
                    "[audit] sink = {url:?}: use an absolute directory, as in file:///var/log/kronik/audit/"
                ));
            }
            return Ok(Sink::File(path.to_owned()));
        }
        if let Some(rest) = url.strip_prefix("s3://") {
            if rest.split('/').next().unwrap_or("").is_empty() {
                return Err(format!("[audit] sink = {url:?} names no bucket"));
            }
            return Ok(Sink::S3 {
                url: url.to_owned(),
                endpoint: endpoint.map(str::to_owned),
            });
        }
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(format!(
                "[audit] sink {:?}: use file:///dir/, https://… or s3://bucket/prefix",
                http::scheme_host(url)
            ));
        }
        if http::host(url).is_none_or(str::is_empty) {
            return Err(format!(
                "[audit] sink {:?} names no host",
                http::scheme_host(url)
            ));
        }
        if url.starts_with("http://") && !http::is_loopback(url) {
            return Err(format!(
                "[audit] sink {:?}: plain http:// is allowed only to a loopback address; use https://",
                http::scheme_host(url)
            ));
        }
        Ok(Sink::Webhook(url.to_owned()))
    }

    /// The sink's scheme and host only, as `export status` shows it
    /// (review M6).
    pub fn shown(&self) -> String {
        match self {
            Sink::File(_) => "file://".into(),
            Sink::Webhook(url) | Sink::S3 { url, .. } => http::scheme_host(url),
        }
    }
}

/// The name of the file a batch starting at line LSN `first` opens; when it
/// exists (LSNs repeat after a restore or a rewind), `.1`, `.2`, ... before
/// `.jsonl`.
pub fn file_name(first: Lsn) -> String {
    format!("audit-{first:020}.jsonl")
}

/// The `audit-*.jsonl` files of a directory sink in the order they were
/// written: by modification time, then name. After a restore, LSNs repeat,
/// so a later file can have a smaller first LSN.
pub fn files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("audit-") && name.ends_with(".jsonl") {
            out.push((e.metadata()?.modified()?, dir.join(name)));
        }
    }
    out.sort();
    Ok(out.into_iter().map(|(_, p)| p).collect())
}

/// The object a batch is stored under: the wall time it was prepared at,
/// then its record range. A retried batch overwrites itself, and no other
/// batch overwrites it when a restore reuses its LSNs (review H-B); names
/// sort in the order the batches were written, as `audit verify` reads
/// them.
// shortcut: write order is the wall clock's, so a clock stepped back between two batches sorts them wrong for `audit verify`; upgrade to a counter kept in the cursor's state if that is ever seen.
pub fn object_name(prepared_ms: u64, first: Lsn, last: Lsn) -> String {
    format!("audit/{prepared_ms:020}-{first:020}-{last:020}.jsonl")
}

/// `create_dir_all`, and an fsync of the parent of every directory it
/// created, so that a power loss cannot take the sink's directory away
/// from under lines that were acknowledged.
fn create_dirs(dir: &Path) -> std::io::Result<()> {
    let missing: Vec<&Path> = dir.ancestors().take_while(|d| !d.exists()).collect();
    std::fs::create_dir_all(dir)?;
    for d in missing {
        if let Some(parent) = d.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

/// A directory sink. Kronik never deletes its files: rotation is the
/// operator's (review L3).
#[derive(Debug)]
pub struct FileSink {
    dir: PathBuf,
    max_bytes: u64,
    /// The newest file, the length of its whole lines and its inode.
    current: Option<(PathBuf, u64, u64)>,
}

impl FileSink {
    /// Opens (creates) the directory and truncates its newest file to its
    /// last `\n`, so a crash mid-append leaves no torn line for the next
    /// batch to continue (review M7).
    pub fn open(dir: &Path, max_bytes: u64) -> std::io::Result<FileSink> {
        create_dirs(dir)?;
        let current = match files(dir)?.pop() {
            Some(path) => {
                let mut f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)?;
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes)?;
                let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
                if keep < bytes.len() {
                    f.set_len(keep as u64)?;
                    f.sync_data()?;
                    tracing::warn!(file = %path.display(), cut = bytes.len() - keep, "audit sink: truncated a torn line");
                }
                Some((path, keep as u64, f.metadata()?.ino()))
            }
            None => None,
        };
        Ok(FileSink {
            dir: dir.to_owned(),
            max_bytes,
            current,
        })
    }

    /// Appends whole lines after the last whole line and fsyncs them; a
    /// failed append is overwritten by its retry. A new file starts once
    /// the newest one has reached `max_bytes`, under a name no file has:
    /// an existing file is never opened at offset 0 (review H-B).
    pub fn append(&mut self, first: Lsn, body: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let open = match &self.current {
            Some((path, len, ino)) if *len < self.max_bytes => {
                match std::fs::OpenOptions::new().write(true).open(path) {
                    // Gone, another file (logrotate create) or shorter
                    // (copytruncate) means rotated away (review R5): start a
                    // new file rather than write at the old offset. Longer
                    // is our own failed append, which the retry overwrites.
                    Ok(f) => {
                        let m = f.metadata()?;
                        (m.ino() == *ino && m.len() >= *len).then(|| (f, path.clone(), *len, *ino))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e),
                }
            }
            _ => None,
        };
        let (mut f, path, len, ino) = match open {
            Some(open) => open,
            None => {
                let path = (0u64..)
                    .map(|n| match n {
                        0 => self.dir.join(file_name(first)),
                        n => self.dir.join(format!("audit-{first:020}.{n}.jsonl")),
                    })
                    .find(|p| !p.exists())
                    .unwrap_or_default();
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o640)
                    .open(&path)?;
                std::fs::File::open(&self.dir)?.sync_all()?;
                let ino = f.metadata()?.ino();
                // Ours now: a failed append is overwritten by its retry.
                self.current = Some((path.clone(), 0, ino));
                (f, path, 0, ino)
            }
        };
        f.seek(SeekFrom::Start(len))?;
        f.write_all(body)?;
        let end = len + body.len() as u64;
        f.set_len(end)?;
        f.sync_data()?;
        self.current = Some((path, end, ino));
        Ok(())
    }
}

/// Where the lines go.
enum Target {
    File(Arc<Mutex<FileSink>>),
    Webhook {
        url: String,
        headers: Vec<(String, String)>,
    },
    S3(kronik_ship::Remote),
}

/// `[audit]`, as `kronik serve` read it.
pub struct Settings {
    pub sink: Sink,
    pub batch_records: u64,
    pub interval: Duration,
    pub file_max_bytes: u64,
    pub headers_env: Option<String>,
    /// `from = "now"`: a new cursor starts at the applied LSN.
    pub from_now: bool,
    pub max_hold: Duration,
    /// Free bytes below which retention ignores the hold.
    pub hold_release: u64,
}

/// One prepared batch.
pub struct Batch {
    /// The record range it covers.
    first: Lsn,
    last: Lsn,
    /// The LSN of its first line, for a new file's name.
    first_line: Option<Lsn>,
    /// When it was prepared, for its object's name.
    prepared_ms: u64,
    /// Lines, each ending in `\n`.
    body: Vec<u8>,
}

/// The audit stream's [`follow::Sink`].
pub struct AuditExport {
    node: Arc<Node>,
    mapper: Arc<Mapper>,
    target: Target,
}

impl AuditExport {
    async fn put(&self, batch: &Batch) -> Result<(), (String, Option<Duration>)> {
        let env = self.node.env();
        match &self.target {
            Target::File(sink) => {
                let (sink, body) = (sink.clone(), batch.body.clone());
                let first = batch.first_line.unwrap_or(batch.first);
                let done = env
                    .blocking("audit-file", move || {
                        follow_lock(&sink)
                            .append(first, &body)
                            .map_err(|e| e.to_string())
                    })
                    .await;
                match done {
                    Some(Ok(())) => Ok(()),
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "audit sink: appending to the file failed");
                        Err(("io".into(), None))
                    }
                    None => Err(("io".into(), None)),
                }
            }
            Target::Webhook { url, headers } => {
                let range = format!("{}-{}", batch.first, batch.last);
                // The content's hash too: after a restore the same range
                // brings other lines, which a receiver that honours the
                // key must not answer from its cache (review H-B).
                let key = format!("{range}-{}", &blake3::hash(&batch.body).to_hex()[..32]);
                let mut h = headers.clone();
                h.push(("kronik-audit-range".into(), range));
                h.push(("idempotency-key".into(), key));
                match http::post(
                    env,
                    url.clone(),
                    h,
                    "application/x-ndjson",
                    batch.body.clone(),
                )
                .await
                {
                    Ok(r) if (200..300).contains(&r.status) => Ok(()),
                    Ok(r) => {
                        // Dropping audit lines is never automatic: a 4xx
                        // other than 408 and 429 needs the operator, and is
                        // retried until it is fixed.
                        if (400..500).contains(&r.status) && r.status != 408 && r.status != 429 {
                            tracing::warn!(
                                status = r.status,
                                "audit sink: the webhook refuses the batch; retrying until it accepts it"
                            );
                        }
                        Err((format!("http_{}", r.status), http::retry_after(&r)))
                    }
                    Err(code) => Err((code.into(), None)),
                }
            }
            Target::S3(remote) => remote
                .put(
                    &object_name(batch.prepared_ms, batch.first, batch.last),
                    batch.body.clone(),
                )
                .await
                .map_err(|e| {
                    tracing::warn!(code = e.code(), "audit sink: storing the batch failed");
                    (e.code().into(), None)
                }),
        }
    }
}

fn follow_lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl follow::Sink for AuditExport {
    type Batch = Batch;

    async fn prepare(&mut self, records: Vec<Committed>) -> Batch {
        let first = records.first().map_or(0, |c| c.lsn);
        let last = records.last().map_or(0, |c| c.lsn);
        let secrets = self.node.secret_values();
        let mut body = Vec::new();
        let mut first_line = None;
        for c in &records {
            for l in self.mapper.lines(c.lsn, &c.record, &secrets) {
                first_line.get_or_insert(l.lsn);
                body.extend_from_slice(l.to_json().as_bytes());
                body.push(b'\n');
            }
        }
        Batch {
            first,
            last,
            first_line,
            prepared_ms: self.node.env().clock.wall_ms(),
            body,
        }
    }

    async fn deliver(&mut self, batch: &Batch) -> Delivery {
        if !batch.body.is_empty()
            && let Err((code, after)) = self.put(batch).await
        {
            return Delivery::Retry { code, after };
        }
        self.node.retention_hold().set(
            batch.first.saturating_sub(1),
            self.node.env().clock.wall_ms(),
        );
        Delivery::Delivered
    }

    /// Records the gap as an `audit.gap` event. A failure is returned, so
    /// that the follower keeps its cursor before the gap and tries again
    /// (review M2).
    async fn gap(&mut self, from: Lsn, to: Lsn) -> Result<(), String> {
        let now = self.node.env().clock.wall_ms();
        let audit = pb::Audit {
            token_id: "system".into(),
            reason: "retention deleted these records before the audit export read them".into(),
            wall_time_ms: now,
        };
        let details = [
            ("from".to_owned(), from.to_string()),
            ("to".to_owned(), to.to_string()),
        ]
        .into();
        if let Err(e) = self
            .node
            .record_audit_event("audit.gap", STREAM, details, audit)
            .await
        {
            tracing::error!(from, to, error = %e.message, "audit export: recording the gap failed");
            return Err("audit_gap".into());
        }
        // The follower reads on from the gap: a rewind it took is done
        // (RetentionHold::set).
        self.node.retention_hold().set(from.saturating_sub(1), now);
        Ok(())
    }

    /// The hold's age is the time the export lagged: refreshed, at the same
    /// floor, while nothing lags.
    fn caught_up(&mut self) {
        let hold = self.node.retention_hold();
        if let Some(floor) = hold.floor() {
            hold.set(floor, self.node.env().clock.wall_ms());
        }
    }
}

/// The cursor a stream starts from: the saved one, else `[audit] from`'s
/// (the record before the first retained one, or the applied LSN). After
/// `kronik restore`, `kronik serve` has clamped a saved one to the
/// restored log already (review H-A).
pub fn start_cursor(saved: Option<Lsn>, from_now: bool, log_first: Lsn, applied: Lsn) -> Lsn {
    saved.unwrap_or(if from_now {
        applied
    } else {
        log_first.saturating_sub(1)
    })
}

/// Starts the audit stream: opens the sink, holds retention at the cursor
/// and spawns the follower. Errors name what could not be opened.
pub async fn start(
    node: Arc<Node>,
    cursors: Arc<Cursors>,
    settings: Settings,
    mapper: Arc<Mapper>,
) -> Result<Arc<Stream>, String> {
    let storage = node
        .storage_config()
        .ok_or("the audit export needs a data directory")?
        .clone();
    let log_first = node.log_first(&storage).map_err(|e| e.message)?;
    let saved = cursors.get(STREAM).map(|e| e.lsn);
    let cursor = start_cursor(saved, settings.from_now, log_first, node.applied_lsn());
    if Some(cursor) != saved {
        cursors
            .save(
                STREAM,
                crate::cursor::Entry {
                    lsn: cursor,
                    state: serde_json::Value::Null,
                },
            )
            .await
            .map_err(|e| format!("saving the audit cursor: {e}"))?;
    }
    let hold = node.retention_hold();
    hold.configure(settings.hold_release, settings.max_hold);
    hold.set(cursor, node.env().clock.wall_ms());
    let target = match &settings.sink {
        Sink::File(dir) => Target::File(Arc::new(Mutex::new(
            FileSink::open(dir, settings.file_max_bytes)
                .map_err(|e| format!("opening the audit directory {}: {e}", dir.display()))?,
        ))),
        Sink::Webhook(url) => Target::Webhook {
            url: url.clone(),
            headers: http::env_headers(settings.headers_env.as_deref())?,
        },
        Sink::S3 { url, endpoint } => Target::S3(
            kronik_ship::Remote::open(url, endpoint.as_deref())
                .map_err(|e| format!("opening the audit bucket: {e}"))?,
        ),
    };
    let stream = Stream::new(STREAM, true, settings.sink.shown(), cursor);
    let export = AuditExport {
        node: node.clone(),
        mapper,
        target,
    };
    let opts = follow::Options {
        batch: settings.batch_records.max(1),
        interval: settings.interval,
    };
    drop(node.env().spawn(
        "audit-export",
        follow::follow(node.clone(), cursors, stream.clone(), opts, export),
    ));
    tracing::info!(sink = %settings.sink.shown(), cursor, "exporting the audit log");
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sinks_parse_and_show_scheme_and_host_only() {
        let ok = |u: &str| Sink::parse(u, None).unwrap();
        assert_eq!(
            ok("file:///var/log/kronik/audit/"),
            Sink::File("/var/log/kronik/audit/".into())
        );
        assert_eq!(
            ok("https://user:pw@hooks.example.com:8443/t/SECRET?k=v").shown(),
            "https://hooks.example.com:8443"
        );
        assert_eq!(
            ok("http://127.0.0.1:9000/a").shown(),
            "http://127.0.0.1:9000"
        );
        ok("http://[::1]:9000/a");
        assert_eq!(
            Sink::parse("s3://bucket/kronik", Some("http://127.0.0.1:3900"))
                .unwrap()
                .shown(),
            "s3://bucket"
        );
        for (bad, why) in [
            ("ftp://x/SECRET", "use file://"),
            ("file://relative/dir", "absolute"),
            ("s3:///prefix", "no bucket"),
            ("http://hooks.example.com/t/SECRET", "loopback"),
            ("https:///x", "no host"),
        ] {
            let e = Sink::parse(bad, None).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
            assert!(!e.contains("SECRET"), "{e}");
        }
        let e = Sink::parse("file:///x/", Some("http://127.0.0.1:3900")).unwrap_err();
        assert!(e.contains("s3:// sink only"), "{e}");
    }

    #[test]
    fn a_new_cursor_starts_per_from() {
        // Saved wins; else the record before the first retained, or applied.
        assert_eq!(start_cursor(Some(40), false, 10, 90), 40);
        assert_eq!(start_cursor(None, false, 10, 90), 9);
        assert_eq!(start_cursor(None, true, 10, 90), 90);
    }

    /// Review M7: a torn last line is cut at start; whole lines stay, and
    /// the next batch starts on a line of its own. Files roll at the cap.
    #[test]
    fn a_rotated_away_file_sink_starts_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FileSink::open(dir.path(), 1 << 20).unwrap();
        s.append(1, b"{\"lsn\":1}\n").unwrap();
        std::fs::rename(dir.path().join(file_name(1)), dir.path().join("old")).unwrap();
        s.append(2, b"{\"lsn\":2}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(file_name(2))).unwrap(),
            "{\"lsn\":2}\n"
        );
    }

    /// Review R5: logrotate's `create` (the file renamed away, an empty one
    /// made under its name) and `copytruncate` (the file cut to 0) leave a
    /// file shorter than the sink recorded. The next batch starts a new
    /// file instead of writing at the old offset after NUL bytes, and what
    /// stays in the directory verifies.
    #[test]
    fn a_logrotated_file_is_not_written_at_the_old_offset() {
        use crate::audit::{Ctx, lines, verify};
        use crate::spans::ActorKeys;
        let record = |lsn: u64| {
            let r = kronik_proto::Record::PrivacyMode(pb::PrivacyMode {
                epoch: lsn,
                mode: pb::PrivacyState::Off as i32,
                audit: Some(pb::Audit {
                    token_id: "token:ci".into(),
                    reason: "rotate".into(),
                    wall_time_ms: 1,
                }),
            });
            let ctx = Ctx {
                branch: "main",
                keys: &ActorKeys::Omit,
                subject: &|s: &str| s.to_owned(),
                secrets: &[],
            };
            lines(lsn, &r, &ctx)
        };
        let body = |lsn: u64| {
            record(lsn)
                .iter()
                .map(|l| format!("{}\n", l.to_json()))
                .collect::<String>()
        };
        for copytruncate in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut s = FileSink::open(dir.path(), 1 << 20).unwrap();
            s.append(1, body(1).as_bytes()).unwrap();
            let first = dir.path().join(file_name(1));
            if copytruncate {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&first)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
            } else {
                std::fs::rename(&first, dir.path().join("rotated")).unwrap();
                std::fs::File::create(&first).unwrap();
            }
            s.append(2, body(2).as_bytes()).unwrap();
            let mut got = Vec::new();
            for f in files(dir.path()).unwrap() {
                let bytes = std::fs::read(&f).unwrap();
                assert!(!bytes.contains(&0), "NUL bytes in {}", f.display());
                for l in String::from_utf8(bytes).unwrap().lines() {
                    got.push(serde_json::from_str(l).unwrap());
                }
            }
            let report = verify(&[record(1), record(2)].concat(), &got, 1, 2);
            assert!(report.complete, "{report:?}");
        }
    }

    #[test]
    fn the_file_sink_truncates_a_torn_line_and_rolls() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("audit");
        let mut s = FileSink::open(&dir, 20).unwrap();
        s.append(1, b"{\"lsn\":1}\n").unwrap();
        drop(s);
        let first = dir.join(file_name(1));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&first)
            .unwrap()
            .write_all(b"{\"lsn\":2,\"ki")
            .unwrap();
        let mut s = FileSink::open(&dir, 20).unwrap();
        s.append(2, b"{\"lsn\":2}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            "{\"lsn\":1}\n{\"lsn\":2}\n"
        );
        s.append(3, b"{\"lsn\":3}\n").unwrap();
        assert_eq!(files(&dir).unwrap(), [first, dir.join(file_name(3))]);
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(dir.join(file_name(3)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    /// Review H-B: a rollover to a first LSN that has a file already (a
    /// restore or a rewind repeats it) starts a file of its own, and the
    /// old one keeps its lines.
    #[test]
    fn a_rollover_never_reuses_a_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("a/b/audit");
        let mut s = FileSink::open(&dir, 1).unwrap();
        s.append(10, b"{\"lsn\":10,\"v\":\"old\"}\n").unwrap();
        s.append(20, b"{\"lsn\":20,\"v\":\"old\"}\n").unwrap();
        let mut s = FileSink::open(&dir, 1).unwrap();
        s.append(10, b"{\"lsn\":10,\"v\":\"new\"}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(file_name(10))).unwrap(),
            "{\"lsn\":10,\"v\":\"old\"}\n"
        );
        let new = dir.join("audit-00000000000000000010.1.jsonl");
        assert_eq!(
            std::fs::read_to_string(new).unwrap(),
            "{\"lsn\":10,\"v\":\"new\"}\n"
        );
        assert_eq!(files(&dir).unwrap().len(), 3);
    }
}
