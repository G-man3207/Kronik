//! The audit export (docs/design/m28-otel.md §4.4–§4.6, §5; ADRs 0083,
//! 0084): the sinks (a directory of JSON-lines files, a webhook, object
//! storage) and the [`follow::Sink`] that turns committed records into
//! `kronik.audit/v2` lines for them. It holds retention at its cursor and
//! records a gap as a system `audit.gap` event when the hold gave way.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use kronik_core::authority::AuthLease;
use kronik_core::ids::Lsn;
use kronik_log::Committed;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use kronik_sched::secrets::CertifiedSecretSnapshot;

use crate::audit::Mapper;
use crate::cursor::{Cursors, Generation};
use crate::follow::{self, Delivery, Stream};
use crate::http;
use rustix::fs::{AtFlags, Mode, OFlags};

/// Largest configurable rotation threshold; batches are never split or dropped.
pub const MAX_FILE_BYTES: u64 = 1 << 30;

/// A sink I/O failure. Failed durability barriers and EIO poison the writer.
#[derive(Debug)]
pub struct FileError {
    source: std::io::Error,
    sync: bool,
}

impl FileError {
    fn fatal(&self) -> bool {
        self.sync || self.source.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
    }

    fn code(&self) -> &'static str {
        if self.fatal() { "storage_sync" } else { "io" }
    }

    fn poisoned() -> Self {
        Self {
            source: std::io::Error::other("audit file writer requires storage repair"),
            sync: true,
        }
    }
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.source, f)
    }
}

impl std::error::Error for FileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<std::io::Error> for FileError {
    fn from(source: std::io::Error) -> Self {
        Self {
            source,
            sync: false,
        }
    }
}

impl From<rustix::io::Errno> for FileError {
    fn from(source: rustix::io::Errno) -> Self {
        std::io::Error::from(source).into()
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_SYNC_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static DIRECTORY_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_DIRECTORY: std::cell::Cell<Option<rustix::io::Errno>> = const { std::cell::Cell::new(None) };
}

fn sync_file(file: &std::fs::File, data: bool) -> Result<(), FileError> {
    #[cfg(test)]
    if FAIL_SYNC_AFTER.with(|remaining| match remaining.get() {
        Some(0) => {
            remaining.set(None);
            true
        }
        Some(n) => {
            remaining.set(Some(n - 1));
            false
        }
        None => false,
    }) {
        return Err(FileError {
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            sync: true,
        });
    }
    (if data {
        file.sync_data()
    } else {
        file.sync_all()
    })
    .map_err(|source| FileError { source, sync: true })
}

/// The stream's name: its cursor and its metrics' label.
pub const STREAM: &str = "audit";

/// A parsed `[audit] sink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    /// `file:///dir/`: versioned, monotonically numbered JSON-lines files.
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

fn file_name(sequence: u64) -> String {
    format!("audit-v2-{sequence:020}.jsonl")
}

/// Historical files in their original mtime/name order, then v2 files by
/// publication sequence. New ordering never depends on the wall clock or LSN.
pub fn files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let handle = directory(dir, false).map_err(|e| e.source)?;
    Ok(file_names(&handle)?
        .into_iter()
        .map(|name| dir.join(name))
        .collect())
}

fn file_names(dir: &std::fs::File) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in rustix::fs::Dir::read_from(dir)? {
        let entry = entry?;
        let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
        let text = name.to_string_lossy();
        if text.starts_with("audit-") && text.ends_with(".jsonl") {
            let m = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
            if rustix::fs::FileType::from_raw_mode(m.st_mode) != rustix::fs::FileType::RegularFile
                || m.st_nlink != 1
            {
                return Err(std::io::Error::other(
                    "audit sink requires singly linked regular files",
                ));
            }
            let sequence = if let Some(number) = text.strip_prefix("audit-v2-") {
                Some(object_sequence(number).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "noncanonical audit file sequence",
                    )
                })?)
            } else if text.starts_with("audit-v") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported audit file namespace",
                ));
            } else {
                None
            };
            let stamp = if sequence.is_some() {
                (0, 0)
            } else {
                (m.st_mtime, m.st_mtime_nsec)
            };
            out.push((sequence, stamp, PathBuf::from(name)));
        }
    }
    out.sort();
    Ok(out.into_iter().map(|(_, _, name)| name).collect())
}

/// Ordered object storage is separate from historical wall-time names.
pub const OBJECT_PREFIX: &str = "audit/v2";

/// One confirmed publication slot; wall-clock time and LSN reuse cannot reorder it.
pub fn object_name(sequence: u64) -> String {
    format!("{OBJECT_PREFIX}/{sequence:020}.jsonl")
}

/// Only the canonical, nonzero u64 representation belongs to this namespace.
pub fn object_sequence(name: &str) -> Option<u64> {
    let number = name.strip_suffix(".jsonl")?;
    if number.len() != 20 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok().filter(|&sequence| sequence != 0)
}

/// Walk through directory descriptors: no component can redirect an open
/// through a symlink, even if its name is replaced during the walk.
fn directory(dir: &Path, create: bool) -> Result<std::fs::File, FileError> {
    #[cfg(test)]
    DIRECTORY_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    #[cfg(test)]
    if let Some(error) = FAIL_DIRECTORY.with(|fault| fault.take()) {
        return Err(error.into());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = std::fs::File::from(rustix::fs::open(
        if dir.is_absolute() { "/" } else { "." },
        flags,
        Mode::empty(),
    )?);
    for component in dir.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Prefix(_) => {
                return Err(std::io::Error::other("invalid audit directory").into());
            }
        };
        let child = match rustix::fs::openat(&parent, name, flags, Mode::empty()) {
            Err(rustix::io::Errno::NOENT) if create => {
                match rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                sync_file(&parent, false)?;
                rustix::fs::openat(&parent, name, flags, Mode::empty())?
            }
            result => result?,
        };
        parent = std::fs::File::from(child);
    }
    Ok(parent)
}

fn validate_file_max_bytes(max_bytes: u64) -> std::io::Result<()> {
    if !(1..=MAX_FILE_BYTES).contains(&max_bytes) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "[audit] file_max_bytes must be between 1B and 1GiB",
        ));
    }
    Ok(())
}

fn regular_file(file: &std::fs::File) -> std::io::Result<std::fs::Metadata> {
    let m = file.metadata()?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(std::io::Error::other(
            "audit sink requires singly linked regular files",
        ));
    }
    Ok(m)
}

/// A directory sink. Kronik never deletes its files: rotation is the
/// operator's (review L3).
#[derive(Debug)]
pub struct FileSink {
    dir: PathBuf,
    max_bytes: u64,
    occupied: u64,
    /// The newest name, acknowledged length, device and inode.
    current: Option<(PathBuf, u64, u64, u64)>,
    failed: bool,
}

impl FileSink {
    /// Recovers a torn tail by scanning backwards through the initial file
    /// length with a fixed buffer, preserving every whole line.
    pub fn open(dir: &Path, max_bytes: u64) -> Result<FileSink, FileError> {
        validate_file_max_bytes(max_bytes)?;
        let handle = directory(dir, true)?;
        let mut names = file_names(&handle)?;
        let occupied = names
            .last()
            .and_then(|name| name.to_str()?.strip_prefix("audit-v2-"))
            .and_then(object_sequence)
            .unwrap_or(0);
        let mut current = match names.pop() {
            Some(name) => {
                let mut f = std::fs::File::from(rustix::fs::openat(
                    &handle,
                    &name,
                    OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                let m = regular_file(&f)?;
                let mut end = m.len();
                let mut buffer = [0; 64 << 10];
                let keep = loop {
                    if end == 0 {
                        break 0;
                    }
                    let start = end.saturating_sub(buffer.len() as u64);
                    let bytes = &mut buffer[..(end - start) as usize];
                    f.seek(SeekFrom::Start(start))?;
                    f.read_exact(bytes)?;
                    if let Some(i) = bytes.iter().rposition(|b| *b == b'\n') {
                        break start + i as u64 + 1;
                    }
                    end = start;
                };
                if keep < m.len() {
                    f.set_len(keep)?;
                    sync_file(&f, true)?;
                    tracing::warn!(file = %dir.join(&name).display(), cut = m.len() - keep, "audit sink: truncated a torn line");
                }
                Some((name, keep, m.dev(), m.ino()))
            }
            None => None,
        };
        // Legacy files retain their recovered whole lines but get no new appends.
        if occupied == 0 {
            current = None;
        }
        Ok(FileSink {
            dir: dir.to_owned(),
            max_bytes,
            occupied,
            current,
            failed: false,
        })
    }

    /// Appends and fsyncs a whole batch. `max_bytes` is a soft threshold:
    /// a batch (even one oversized line) stays whole; the next batch rolls.
    /// A failed append is overwritten from its last acknowledged offset.
    pub fn append(&mut self, body: &[u8]) -> Result<(), FileError> {
        if self.failed {
            return Err(FileError::poisoned());
        }
        let result = self.append_inner(body);
        if result.as_ref().is_err_and(FileError::fatal) {
            self.failed = true;
        }
        result
    }

    fn append_inner(&mut self, body: &[u8]) -> Result<(), FileError> {
        if !body.is_empty() && !body.ends_with(b"\n") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit batches must end with a newline",
            )
            .into());
        }
        let handle = directory(&self.dir, true)?;
        let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let open = match &self.current {
            Some((name, len, dev, ino)) if *len < self.max_bytes => {
                match rustix::fs::openat(&handle, name, flags, Mode::empty()) {
                    Ok(fd) => {
                        let f = std::fs::File::from(fd);
                        let m = regular_file(&f)?;
                        (m.dev() == *dev && m.ino() == *ino && m.len() >= *len)
                            .then(|| (f, name.clone(), *len, *dev, *ino))
                    }
                    Err(rustix::io::Errno::NOENT) => None,
                    Err(e) => return Err(e.into()),
                }
            }
            _ => None,
        };
        let (mut f, name, len, dev, ino) = match open {
            Some(open) => open,
            None => loop {
                let n = self
                    .occupied
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("audit file sequences exhausted"))?;
                let name = PathBuf::from(file_name(n));
                match rustix::fs::openat(
                    &handle,
                    &name,
                    flags | OFlags::CREATE | OFlags::EXCL,
                    Mode::from_raw_mode(0o640),
                ) {
                    Ok(fd) => {
                        let f = std::fs::File::from(fd);
                        let m = regular_file(&f)?;
                        self.occupied = n;
                        self.current = Some((name.clone(), 0, m.dev(), m.ino()));
                        sync_file(&handle, false)?;
                        break (f, name, 0, m.dev(), m.ino());
                    }
                    Err(rustix::io::Errno::EXIST) => {
                        let m = rustix::fs::statat(&handle, &name, AtFlags::SYMLINK_NOFOLLOW)?;
                        if rustix::fs::FileType::from_raw_mode(m.st_mode)
                            != rustix::fs::FileType::RegularFile
                            || m.st_nlink != 1
                        {
                            return Err(std::io::Error::other("unsafe audit file name").into());
                        }
                        self.occupied = n;
                    }
                    Err(e) => return Err(e.into()),
                }
            },
        };
        let end = len
            .checked_add(body.len() as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or_else(|| std::io::Error::other("audit file size exceeds platform limit"))?;
        f.seek(SeekFrom::Start(len))?;
        f.write_all(body)?;
        f.set_len(end)?;
        sync_file(&f, true)?;
        self.current = Some((name, end, dev, ino));
        Ok(())
    }
}

/// A lazy file writer remains poisoned even when its initial open failed.
struct FileWriter {
    dir: PathBuf,
    max_bytes: u64,
    sink: Option<FileSink>,
    failed: bool,
}

impl FileWriter {
    fn append(&mut self, body: &[u8]) -> Result<(), FileError> {
        if self.failed {
            return Err(FileError::poisoned());
        }
        let result = (|| {
            let sink = match &mut self.sink {
                Some(sink) => sink,
                None => self.sink.insert(FileSink::open(&self.dir, self.max_bytes)?),
            };
            sink.append(body)
        })();
        if result.as_ref().is_err_and(FileError::fatal) {
            self.failed = true;
        }
        result
    }
}

/// Where the lines go.
enum Target {
    File(Arc<Mutex<FileWriter>>),
    Webhook {
        url: String,
        headers: Vec<(String, String)>,
    },
    S3 {
        remote: kronik_ship::Remote,
        /// Highest confirmed occupied slot, loaded once without collecting names.
        occupied: Option<u64>,
    },
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
#[derive(PartialEq, Eq)]
pub struct Batch {
    /// The record range it covers.
    first: Lsn,
    last: Lsn,
    /// Durable delivery identity, unchanged across retries.
    generation: Generation,
    /// Lines, each ending in `\n`.
    body: Bytes,
}

/// The audit stream's [`follow::Sink`].
pub struct AuditExport {
    node: Arc<Node>,
    mapper: Arc<Mapper>,
    target: Target,
    /// Valid retained source ranges and this writer's covered highwaters.
    gap_coverage: Option<Vec<(Lsn, Lsn)>>,
}

/// Keeps only merged intervals; disjoint notices cannot prove the hole between them.
fn cover_gap(coverage: &mut Vec<(Lsn, Lsn)>, mut from: Lsn, mut to: Lsn) {
    let start = coverage.partition_point(|&(_, end)| end < from.saturating_sub(1));
    let mut end = start;
    while end < coverage.len() && coverage[end].0 <= to.saturating_add(1) {
        from = from.min(coverage[end].0);
        to = to.max(coverage[end].1);
        end += 1;
    }
    drop(coverage.splice(start..end, [(from, to)]));
}

impl AuditExport {
    async fn put(
        &mut self,
        batch: &Batch,
        original: AuthLease,
    ) -> Result<(), (String, Option<Duration>)> {
        let env = self.node.env();
        match &mut self.target {
            Target::File(writer) => {
                if follow_lock(writer).failed {
                    return Err(("storage_sync".into(), None));
                }
                let (writer, body) = (writer.clone(), batch.body.clone());
                let env = env.clone();
                let retained = original.clone();
                let done = self
                    .node
                    .authorized_effect(original, move || async move {
                        Ok(env
                            .blocking("audit-file", move || {
                                let _retained = retained;
                                follow_lock(&writer).append(&body)
                            })
                            .await)
                    })
                    .await
                    .map_err(|e| (e.code.as_str().to_owned(), None))?;
                match done {
                    Some(Ok(())) => Ok(()),
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "audit sink: appending to the file failed");
                        Err((e.code().into(), None))
                    }
                    None => Err(("io".into(), None)),
                }
            }
            Target::Webhook { url, headers } => {
                let range = format!("{}-{}", batch.first, batch.last);
                // Replays need a new ACK even when the range and bytes repeat.
                let key = format!(
                    "{:032x}-{range}-{}",
                    u128::from_be_bytes(batch.generation),
                    &blake3::hash(&batch.body).to_hex()[..32],
                );
                let mut h = headers.clone();
                h.push(("kronik-audit-range".into(), range));
                h.push(("idempotency-key".into(), key));
                match http::post(
                    &self.node,
                    url.clone(),
                    h,
                    "application/x-ndjson",
                    batch.body.clone(),
                    original,
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
            Target::S3 { remote, occupied } => {
                let error = |e: kronik_ship::ShipError| {
                    tracing::warn!(code = e.code(), "audit sink: storing the batch failed");
                    (e.code().into(), None)
                };
                if occupied.is_none() {
                    let remote = remote.clone();
                    let prefix = OBJECT_PREFIX.to_owned();
                    let last = self
                        .node
                        .authorized_effect(original.clone(), move || async move {
                            let mut last = 0;
                            let listed = remote
                                .list_each(&prefix, |name| {
                                    let sequence = object_sequence(name).ok_or_else(|| {
                                        kronik_ship::ShipError::Config(
                                            "invalid audit/v2 object name".into(),
                                        )
                                    })?;
                                    last = last.max(sequence);
                                    Ok(())
                                })
                                .await;
                            Ok(listed.map(|()| last))
                        })
                        .await
                        .map_err(|e| (e.code.as_str().to_owned(), None))?
                        .map_err(error)?;
                    *occupied = Some(last);
                }
                let sequence = occupied
                    .and_then(|last| last.checked_add(1))
                    .ok_or_else(|| ("s3_order_exhausted".into(), None))?;
                let remote = remote.clone();
                let name = object_name(sequence);
                let body = batch.body.clone();
                let created = self
                    .node
                    .authorized_effect(original, move || async move {
                        Ok(remote.put_create(&name, body.into()).await)
                    })
                    .await
                    .map_err(|e| (e.code.as_str().to_owned(), None))?
                    .map_err(error)?;
                // Both results prove the slot exists. An unknown write error does not.
                *occupied = Some(sequence);
                if created {
                    Ok(())
                } else {
                    Err(("s3_conflict".into(), Some(Duration::ZERO)))
                }
            }
        }
    }
}

fn follow_lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl follow::Sink for AuditExport {
    type Batch = Batch;

    async fn prepare(
        &mut self,
        records: &[(pb::ActorSource, Committed)],
        generation: Generation,
        _reader: &kronik_sched::ShardReader,
        snapshot: &CertifiedSecretSnapshot,
        original: AuthLease,
    ) -> Result<Batch, String> {
        original.check().map_err(|e| e.code.as_str().to_owned())?;
        let first = records.first().map_or(0, |(_, record)| record.lsn);
        let last = records.last().map_or(0, |(_, record)| record.lsn);
        let secrets = kronik_sched::effects::secret_patterns(&snapshot.values);
        let mut body = Vec::new();
        let mut restored = false;
        for (source, c) in records {
            if source.lsn != c.lsn || source.shard.is_some() {
                return Err("STORAGE_CORRUPT".into());
            }
            restored |=
                matches!(&c.record, kronik_proto::Record::AuditEvent(e) if e.action == "restore");
            for l in self
                .mapper
                .lines_actor_at(source, &c.record, &secrets)
                .map_err(|error| error.code.as_str().to_owned())?
            {
                body.extend_from_slice(l.to_json().as_bytes());
                body.push(b'\n');
            }
        }
        if restored {
            self.gap_coverage = None;
        }
        Ok(Batch {
            first,
            last,
            generation,
            body: body.into(),
        })
    }

    async fn deliver(&mut self, batch: &Batch, original: AuthLease) -> Delivery {
        if let Target::File(writer) = &self.target
            && follow_lock(writer).failed
        {
            return Delivery::Retry {
                code: "storage_sync".into(),
                after: None,
            };
        }
        if !batch.body.is_empty()
            && let Err((code, after)) = self.put(batch, original).await
        {
            return Delivery::Retry { code, after };
        }
        Delivery::Delivered
    }

    fn committed(&mut self, lsn: Lsn, generation: Generation, rewind_pending: bool) {
        let hold = self.node.retention_hold();
        let now = self.node.env().clock.wall_ms();
        if rewind_pending {
            hold.set(lsn, now);
        } else {
            hold.complete_rewind(generation, lsn, now);
        }
    }

    async fn rewind(
        &mut self,
        to: Lsn,
        generation: Generation,
        _reader: &kronik_sched::ShardReader,
    ) -> Result<(), String> {
        self.node
            .retention_hold()
            .rewind(generation, to, self.node.env().clock.wall_ms());
        Ok(())
    }

    /// Records the gap as an `audit.gap` event. A failure is returned, so
    /// that the follower keeps its cursor before the gap and tries again
    /// (review M2).
    async fn gap(&mut self, from: Lsn, to: Lsn, original: AuthLease) -> Result<(), String> {
        if self.gap_coverage.is_none() {
            let mut coverage = Vec::new();
            self.node
                .reader()
                .read(1, self.node.applied_lsn(), |c| {
                    if let kronik_proto::Record::AuditEvent(event) = &c.record {
                        match kronik_sched::scrub::AuditPositions::parse(
                            &event.action,
                            &event.details,
                        ) {
                            Ok(Some(kronik_sched::scrub::AuditPositions::Restore { .. })) => {
                                coverage.clear()
                            }
                            Ok(Some(kronik_sched::scrub::AuditPositions::Gap { from, to }))
                                if to < c.lsn =>
                            {
                                cover_gap(&mut coverage, from, to)
                            }
                            _ => {}
                        }
                    }
                    Ok(())
                })
                .await
                .map_err(|_| "log_read".to_owned())?;
            self.gap_coverage = Some(coverage);
        }
        if self.gap_coverage.as_ref().is_some_and(|coverage| {
            coverage
                .iter()
                .any(|&(start, end)| start <= from && to <= end)
        }) {
            return Ok(());
        }
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
            .record_system_audit_event(
                kronik_sched::SystemAudit::RetentionGap,
                STREAM,
                details,
                audit,
                original,
            )
            .await
        {
            tracing::error!(from, to, error = %e.message, "audit export: recording the gap failed");
            return Err("audit_gap".into());
        }
        cover_gap(self.gap_coverage.get_or_insert_with(Vec::new), from, to);
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

/// Starts the audit stream and holds retention at its cursor. File I/O is
/// retried by delivery; invalid configuration still fails startup.
pub async fn start(
    node: Arc<Node>,
    cursors: Arc<Cursors>,
    settings: Settings,
    mapper: Arc<Mapper>,
    original: AuthLease,
) -> Result<Arc<Stream>, String> {
    if matches!(&settings.sink, Sink::File(_)) {
        validate_file_max_bytes(settings.file_max_bytes).map_err(|e| e.to_string())?;
    }
    let storage = node
        .storage_config()
        .ok_or("the audit export needs a data directory")?
        .clone();
    let log_first = node.log_first(&storage).map_err(|e| e.message)?;
    let saved_entry = cursors.get(STREAM);
    let saved = saved_entry.as_ref().map(|entry| entry.lsn);
    let cursor = start_cursor(saved, settings.from_now, log_first, node.applied_lsn());
    if Some(cursor) != saved {
        let cursors = cursors.clone();
        let entry = crate::cursor::Entry {
            lsn: cursor,
            state: serde_json::Value::Null,
            ..Default::default()
        };
        node.authorized_effect(original.clone(), move || async move {
            Ok(cursors.save(STREAM, entry).await)
        })
        .await
        .map_err(|e| e.code.as_str().to_owned())?
        .map_err(|_| "cursor_save".to_owned())?;
    }
    let hold = node.retention_hold();
    hold.configure(settings.hold_release, settings.max_hold);
    let now = node.env().clock.wall_ms();
    if let Some(rewind) = saved_entry
        .as_ref()
        .and_then(|entry| entry.pending_rewind())
    {
        hold.rewind(rewind.generation, rewind.to, now);
    }
    hold.set(cursor, now);
    let target = match &settings.sink {
        Sink::File(dir) => Target::File(Arc::new(Mutex::new(FileWriter {
            dir: dir.clone(),
            max_bytes: settings.file_max_bytes,
            sink: None,
            failed: false,
        }))),
        Sink::Webhook(url) => Target::Webhook {
            url: url.clone(),
            headers: http::env_headers(settings.headers_env.as_deref())?,
        },
        Sink::S3 { url, endpoint } => Target::S3 {
            remote: kronik_ship::Remote::open(url, endpoint.as_deref())
                .map_err(|e| format!("opening the audit bucket: {}", e.code()))?,
            occupied: None,
        },
    };
    let stream = Stream::new_audit(STREAM, true, settings.sink.shown(), cursor, cursors.clone());
    let export = AuditExport {
        node: node.clone(),
        mapper,
        target,
        gap_coverage: None,
    };
    let opts = follow::Options {
        batch: settings.batch_records.max(1),
        interval: settings.interval,
    };
    stream.own_task(node.env().spawn(
        "audit-export",
        follow::follow(node.clone(), stream.clone(), opts, export, original),
    ));
    tracing::info!(sink = %settings.sink.shown(), cursor, "exporting the audit log");
    Ok(stream)
}

#[cfg(test)]
mod tests {
    // The fixtures race real time around admitted work: the direct calls
    // are the harness, not daemon paths.
    #![allow(clippy::disallowed_methods)]

    use super::*;

    #[test]
    fn gap_coverage_merges_only_proven_ranges() {
        let mut coverage = Vec::new();
        cover_gap(&mut coverage, 10, 20);
        cover_gap(&mut coverage, 30, 40);
        cover_gap(&mut coverage, 12, 18);
        assert_eq!(coverage, [(10, 20), (30, 40)]);
        cover_gap(&mut coverage, 21, 29);
        assert_eq!(coverage, [(10, 40)]);
        cover_gap(&mut coverage, u64::MAX - 1, u64::MAX);
        cover_gap(&mut coverage, u64::MAX, u64::MAX);
        assert_eq!(coverage, [(10, 40), (u64::MAX - 1, u64::MAX)]);
    }

    #[test]
    fn object_name_v2_fixture_rejects_aliases_paths_zero_and_overflow() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/golden/audit-object-names-v2.json"))
                .unwrap();
        for case in fixture["accepted"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let sequence = case["sequence"].as_u64().unwrap();
            assert_eq!(object_sequence(name), Some(sequence));
            assert_eq!(
                object_name(sequence),
                format!("{}/{name}", fixture["namespace"].as_str().unwrap())
            );
        }
        for name in fixture["rejected"].as_array().unwrap() {
            assert_eq!(object_sequence(name.as_str().unwrap()), None);
        }
    }

    #[test]
    fn object_publication_survives_collision_reopen_clock_rollback_and_rewind() {
        use crate::audit::Keys;
        use kronik_core::env::{BoxFuture, Clock, Env};
        use kronik_sched::{NodeConfig, start_local};
        use std::sync::atomic::{AtomicU64, Ordering};

        struct Wall {
            value: AtomicU64,
            timers: Arc<dyn Clock>,
        }
        impl Clock for Wall {
            fn wall_ms(&self) -> u64 {
                self.value.load(Ordering::SeqCst)
            }
            fn monotonic(&self) -> Duration {
                self.timers.monotonic()
            }
            fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
                self.timers.sleep(duration)
            }
        }
        fn batch(
            rt: &tokio::runtime::Runtime,
            node: &Arc<Node>,
            export: &mut AuditExport,
            generation: Generation,
            original: AuthLease,
        ) -> (Batch, AuthLease) {
            let from = node.applied_lsn() + 1;
            rt.block_on(node.record_audit_event_authorized(
                "keys.rewrap",
                "",
                Default::default(),
                pb::Audit {
                    token_id: "system".into(),
                    reason: String::new(),
                    wall_time_ms: node.env().clock.wall_ms(),
                },
                original.clone(),
            ))
            .unwrap();
            let (snapshot, publication) = node.native_secret_snapshot_with_publication().unwrap();
            let reader = Arc::new(rt.block_on(node.capture_system_export_reader()).unwrap());
            let retained = follow::RetainedDisclosure::native(
                reader.clone(),
                snapshot.clone(),
                publication,
                original,
            );
            let records = rt
                .block_on(reader.local_export_page(from - 1, 256, follow::BATCH_BYTES))
                .unwrap()
                .records;
            let prepared = rt
                .block_on(follow::Sink::prepare(
                    export,
                    &records,
                    generation,
                    &reader,
                    &snapshot,
                    retained.clone(),
                ))
                .unwrap();
            (prepared, retained)
        }
        let data = tempfile::tempdir().unwrap();
        let objects = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut env = Env::real(rt.handle().clone());
        let wall = Arc::new(Wall {
            value: AtomicU64::new(1_000),
            timers: env.clock.clone(),
        });
        env.clock = wall.clone();
        let node = rt
            .block_on(start_local(env, data.path(), NodeConfig::default()))
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        settled(&rt, &node);
        let remote =
            kronik_ship::Remote::open(&format!("file://{}", objects.path().display()), None)
                .unwrap();
        let mapper = Arc::new(Mapper {
            keys: Keys::Plain,
            sealer: node.sealer().clone(),
            branch: "main".into(),
        });
        let make_export = |occupied| AuditExport {
            node: node.clone(),
            mapper: mapper.clone(),
            target: Target::S3 {
                remote: remote.clone(),
                occupied,
            },
            gap_coverage: None,
        };
        assert!(
            rt.block_on(remote.put_create(
                &object_name(1),
                Bytes::from_static(b"earlier publication\n").into(),
            ))
            .unwrap()
        );
        // A stale listing cannot acknowledge somebody else's occupied slot.
        let mut export = make_export(Some(0));
        let (first, first_guard) = batch(&rt, &node, &mut export, [1; 16], original.clone());
        node.retention_hold().set(0, node.env().clock.wall_ms());
        assert!(matches!(
            rt.block_on(follow::Sink::deliver(&mut export, &first, first_guard.clone())),
            Delivery::Retry { code, .. } if code == "s3_conflict"
        ));
        assert_eq!(node.retention_hold().floor(), Some(0));
        assert_eq!(
            std::fs::read(objects.path().join(object_name(1))).unwrap(),
            b"earlier publication\n"
        );
        assert_eq!(
            rt.block_on(follow::Sink::deliver(
                &mut export,
                &first,
                first_guard.clone()
            )),
            Delivery::Delivered
        );
        assert_eq!(node.retention_hold().floor(), Some(0));
        follow::Sink::committed(&mut export, first.last, [1; 16], false);
        assert_eq!(node.retention_hold().floor(), Some(first.last));

        wall.value.store(1, Ordering::SeqCst);
        export = make_export(None);
        let (mut second, second_guard) = batch(&rt, &node, &mut export, [2; 16], original.clone());
        assert_eq!(
            rt.block_on(follow::Sink::deliver(
                &mut export,
                &second,
                second_guard.clone()
            )),
            Delivery::Delivered
        );
        let line = |sequence| {
            let body = std::fs::read(objects.path().join(object_name(sequence))).unwrap();
            serde_json::from_slice::<crate::audit::Line>(&body).unwrap()
        };
        assert!(line(2).lsn < line(3).lsn);
        assert_eq!(line(2).at_wall_ms, 1_000);
        assert_eq!(line(3).at_wall_ms, 1);
        second.generation = [3; 16];
        assert_eq!(
            rt.block_on(follow::Sink::deliver(
                &mut export,
                &second,
                second_guard.clone()
            )),
            Delivery::Delivered
        );
        assert_eq!(line(3), line(4));
        assert_eq!(
            std::fs::read_dir(objects.path().join(OBJECT_PREFIX))
                .unwrap()
                .count(),
            4
        );

        let namespace = objects.path().join(OBJECT_PREFIX);
        let saved = objects.path().join("saved-v2");
        std::fs::rename(&namespace, &saved).unwrap();
        std::fs::write(&namespace, b"temporarily blocked").unwrap();
        assert!(matches!(
            rt.block_on(follow::Sink::deliver(
                &mut export,
                &second,
                second_guard.clone()
            )),
            Delivery::Retry { .. }
        ));
        std::fs::remove_file(&namespace).unwrap();
        std::fs::rename(&saved, &namespace).unwrap();
        assert_eq!(
            rt.block_on(follow::Sink::deliver(
                &mut export,
                &second,
                second_guard.clone()
            )),
            Delivery::Delivered
        );
        assert!(objects.path().join(object_name(5)).is_file());
        assert!(!objects.path().join(object_name(6)).exists());
        assert_eq!(node.retention_hold().floor(), Some(first.last));

        assert!(
            rt.block_on(remote.put_create(
                &object_name(u64::MAX),
                Bytes::from_static(b"last representable slot\n").into(),
            ))
            .unwrap()
        );
        export = make_export(None);
        assert!(matches!(
            rt.block_on(follow::Sink::deliver(&mut export, &second, second_guard.clone())),
            Delivery::Retry { code, .. } if code == "s3_order_exhausted"
        ));
        assert_eq!(node.retention_hold().floor(), Some(first.last));
        node.stop_native_execution().unwrap();
        for occupied in [None, Some(5)] {
            let mut stopped = make_export(occupied);
            assert!(matches!(
                rt.block_on(follow::Sink::deliver(
                    &mut stopped,
                    &second,
                    second_guard.clone()
                )),
                Delivery::Retry { .. }
            ));
            let Target::S3 {
                occupied: after, ..
            } = stopped.target
            else {
                unreachable!()
            };
            assert_eq!(after, occupied);
        }
        assert!(!objects.path().join(object_name(6)).exists());
        let dir = objects.path().join("denied-file");
        let mut stopped = AuditExport {
            node: node.clone(),
            mapper: mapper.clone(),
            target: Target::File(Arc::new(Mutex::new(FileWriter {
                dir: dir.clone(),
                max_bytes: 1024,
                sink: None,
                failed: false,
            }))),
            gap_coverage: None,
        };
        assert!(matches!(
            rt.block_on(follow::Sink::deliver(
                &mut stopped,
                &second,
                second_guard.clone()
            )),
            Delivery::Retry { .. }
        ));
        assert!(!dir.exists());
        let before = node.applied_lsn();
        assert!(
            rt.block_on(follow::Sink::gap(&mut stopped, 1, 1, original))
                .is_err()
        );
        assert_eq!(node.applied_lsn(), before);
    }

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
    fn sync_failures_poison_initial_open_recovery_and_append_without_further_io() {
        for phase in 0..4 {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("audit");
            let mut writer = FileWriter {
                dir: dir.clone(),
                max_bytes: 1024,
                sink: None,
                failed: false,
            };
            match phase {
                0 => {} // The first newly created directory's barrier.
                1 => {
                    // Recovery's truncation barrier.
                    std::fs::create_dir(&dir).unwrap();
                    std::fs::write(dir.join(file_name(1)), b"whole\ntorn").unwrap();
                }
                2 => {
                    // A new file's directory-entry barrier.
                    std::fs::create_dir(&dir).unwrap();
                }
                _ => {
                    // Data durability on an already acknowledged file.
                    writer.append(b"whole\n").unwrap();
                }
            }
            FAIL_SYNC_AFTER.with(|fault| fault.set(Some(0)));
            let error = writer.append(b"next\n").unwrap_err();
            assert!(error.fatal(), "phase {phase}: {error}");
            // The injected errno is not EIO: every failed sync is fatal.
            assert!(error.sync);
            assert!(writer.failed);
            let attempts = DIRECTORY_ATTEMPTS.with(|attempts| attempts.get());
            for _ in 0..3 {
                assert!(writer.append(b"next\n").unwrap_err().fatal());
            }
            assert_eq!(DIRECTORY_ATTEMPTS.with(|attempts| attempts.get()), attempts);
        }
    }

    #[test]
    fn initial_eio_is_latched_while_recoverable_open_errors_retry() {
        for errno in [rustix::io::Errno::IO, rustix::io::Errno::ACCESS] {
            let root = tempfile::tempdir().unwrap();
            let mut writer = FileWriter {
                dir: root.path().join("audit"),
                max_bytes: 1024,
                sink: None,
                failed: false,
            };
            FAIL_DIRECTORY.with(|fault| fault.set(Some(errno)));
            let error = writer.append(b"whole\n").unwrap_err();
            assert_eq!(error.fatal(), errno == rustix::io::Errno::IO);
            let attempts = DIRECTORY_ATTEMPTS.with(|attempts| attempts.get());
            if error.fatal() {
                assert!(writer.append(b"whole\n").unwrap_err().fatal());
                assert_eq!(DIRECTORY_ATTEMPTS.with(|attempts| attempts.get()), attempts);
                assert!(!writer.dir.exists());
            } else {
                writer.append(b"whole\n").unwrap();
                assert!(DIRECTORY_ATTEMPTS.with(|attempts| attempts.get()) > attempts);
                assert_eq!(
                    std::fs::read(writer.dir.join(file_name(1))).unwrap(),
                    b"whole\n"
                );
            }
        }
    }

    #[test]
    fn direct_file_sink_is_poisoned_after_a_failed_durability_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = FileSink::open(dir.path(), 1024).unwrap();
        sink.append(b"whole\n").unwrap();
        FAIL_SYNC_AFTER.with(|fault| fault.set(Some(0)));
        assert!(sink.append(b"next\n").unwrap_err().fatal());
        let attempts = DIRECTORY_ATTEMPTS.with(|attempts| attempts.get());
        assert!(sink.append(b"next\n").unwrap_err().fatal());
        assert_eq!(DIRECTORY_ATTEMPTS.with(|attempts| attempts.get()), attempts);
        for errno in [rustix::io::Errno::IO, rustix::io::Errno::NOSPC] {
            let error = FileError::from(errno);
            assert_eq!(error.fatal(), errno == rustix::io::Errno::IO);
        }
    }

    #[test]
    fn a_poisoned_export_writer_never_acknowledges_but_node_turns_continue() {
        use crate::audit::Keys;
        use kronik_core::env::Env;
        use kronik_core::ids::ActorRef;
        use kronik_sched::{NodeConfig, start_local};
        let data = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let node = rt.block_on(async {
            start_local(
                Env::real(tokio::runtime::Handle::current()),
                data.path(),
                NodeConfig::default(),
            )
            .await
            .unwrap()
        });
        let original = node.local_operator_authority().unwrap();
        let audit = || pb::Audit {
            token_id: "token:test".into(),
            reason: "durability failure".into(),
            wall_time_ms: 1,
        };
        let wasm = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/guests/counter.wasm",
        ))
        .unwrap();
        rt.block_on(node.deploy(&wasm, audit(), false, original.clone()))
            .unwrap();
        let mut writer = FileWriter {
            dir: out.path().join("audit"),
            max_bytes: 1024,
            sink: None,
            failed: false,
        };
        FAIL_SYNC_AFTER.with(|fault| fault.set(Some(0)));
        assert!(writer.append(b"pending\n").unwrap_err().fatal());
        let writer = Arc::new(Mutex::new(writer));
        let cursors = Arc::new(
            rt.block_on(Cursors::load(node.env().clone(), data.path()))
                .unwrap(),
        );
        rt.block_on(cursors.save(
            STREAM,
            crate::cursor::Entry {
                lsn: 0,
                state: serde_json::Value::Null,
                ..Default::default()
            },
        ))
        .unwrap();
        let stream = Stream::new_audit(STREAM, true, "file://".into(), 0, cursors.clone());
        let mut export = AuditExport {
            node: node.clone(),
            mapper: Arc::new(Mapper {
                keys: Keys::Plain,
                sealer: node.sealer().clone(),
                branch: "main".into(),
            }),
            target: Target::File(writer),
            gap_coverage: None,
        };
        let reader = rt.block_on(node.capture_system_export_reader()).unwrap();
        rt.block_on(follow::Sink::rewind(&mut export, 0, [1; 16], &reader))
            .unwrap();
        let empty = Batch {
            first: 1,
            last: 1,
            generation: [0; 16],
            body: Bytes::new(),
        };
        assert!(matches!(
            rt.block_on(follow::Sink::deliver(&mut export, &empty, original.clone())),
            Delivery::Retry { .. },
        ));
        stream.own_task(node.env().spawn(
            "poisoned-export-test",
            follow::follow(
                node.clone(),
                stream.clone(),
                follow::Options {
                    batch: 1,
                    interval: Duration::from_millis(10),
                },
                export,
                original.clone(),
            ),
        ));
        for _ in 0..200 {
            if stream.progress().last_error.as_deref() == Some("storage_sync") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            stream.progress().last_error.as_deref(),
            Some("storage_sync")
        );
        let before = node.applied_lsn();
        rt.block_on(node.send(
            ActorRef::parse("counter/a").unwrap(),
            pb::Message {
                name: "increment".into(),
                content_type: "text/plain".into(),
                ..Default::default()
            },
            audit(),
            false,
            original.clone(),
        ))
        .unwrap()
        .unwrap();
        assert!(node.applied_lsn() > before);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(stream.progress().cursor, 0);
        assert_eq!(cursors.get(STREAM).unwrap().lsn, 0);
        // Even a vanished target must not be recreated by a poisoned delivery.
        std::fs::remove_dir_all(out.path().join("audit")).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert!(!out.path().join("audit").exists());
        assert_eq!(stream.progress().cursor, 0);
    }

    #[test]
    fn a_new_cursor_starts_per_from() {
        // Saved wins; else the record before the first retained, or applied.
        assert_eq!(start_cursor(Some(40), false, 10, 90), 40);
        assert_eq!(start_cursor(None, false, 10, 90), 9);
        assert_eq!(start_cursor(None, true, 10, 90), 90);
    }

    #[test]
    fn file_v2_fixture_seals_legacy_and_ignores_mtime_for_current_files() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/golden/audit-file-names-v2.json")).unwrap();
        let legacy = fixture["legacy"].as_array().unwrap();
        let current = fixture["current"].as_array().unwrap();
        let dir = tempfile::tempdir().unwrap();
        for case in legacy {
            std::fs::write(dir.path().join(case["name"].as_str().unwrap()), b"legacy\n").unwrap();
        }
        let last_legacy = dir
            .path()
            .join(legacy.last().unwrap()["name"].as_str().unwrap());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&last_legacy)
            .unwrap()
            .write_all(b"torn")
            .unwrap();
        for case in legacy {
            std::fs::File::open(dir.path().join(case["name"].as_str().unwrap()))
                .unwrap()
                .set_modified(
                    std::time::UNIX_EPOCH
                        + Duration::from_secs(case["mtime_seconds"].as_u64().unwrap()),
                )
                .unwrap();
        }
        let mut writer = FileSink::open(dir.path(), 1024).unwrap();
        writer.append(b"new\n").unwrap();
        assert_eq!(std::fs::read(&last_legacy).unwrap(), b"legacy\n");
        for case in current.iter().skip(1) {
            std::fs::write(dir.path().join(case["name"].as_str().unwrap()), b"stored\n").unwrap();
        }
        for case in legacy.iter().chain(current) {
            std::fs::File::open(dir.path().join(case["name"].as_str().unwrap()))
                .unwrap()
                .set_modified(
                    std::time::UNIX_EPOCH
                        + Duration::from_secs(case["mtime_seconds"].as_u64().unwrap()),
                )
                .unwrap();
        }
        let expected: Vec<_> = legacy
            .iter()
            .chain(current)
            .map(|case| dir.path().join(case["name"].as_str().unwrap()))
            .collect();
        assert_eq!(files(dir.path()).unwrap(), expected);
        assert_eq!(std::fs::read(&expected[2]).unwrap(), b"new\n");
        let mut writer = FileSink::open(dir.path(), 1).unwrap();
        assert!(writer.append(b"no representable next slot\n").is_err());
        assert_eq!(files(dir.path()).unwrap(), expected);
        for name in fixture["rejected"].as_array().unwrap() {
            let path = dir.path().join(name.as_str().unwrap());
            std::fs::write(&path, b"invalid namespace\n").unwrap();
            assert_eq!(
                files(dir.path()).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            std::fs::remove_file(path).unwrap();
        }
    }

    /// Review M7: a torn last line is cut at start; whole lines stay, and
    /// the next batch starts on a line of its own. Files roll at the cap.
    #[test]
    fn a_rotated_away_file_sink_starts_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FileSink::open(dir.path(), 1 << 20).unwrap();
        s.append(b"{\"lsn\":1}\n").unwrap();
        std::fs::rename(dir.path().join(file_name(1)), dir.path().join("old")).unwrap();
        s.append(b"{\"lsn\":2}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(file_name(2))).unwrap(),
            "{\"lsn\":2}\n"
        );
    }

    /// A deterministic keyed sealer for line identity outside a node.
    fn test_sealer() -> &'static kronik_privacy::sealer::Sealer {
        static SEALER: std::sync::OnceLock<kronik_privacy::sealer::Sealer> =
            std::sync::OnceLock::new();
        SEALER.get_or_init(|| {
            let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
            let owner = kronik_privacy::key_source::lock_data(dir.path()).unwrap();
            let (master, _) = kronik_privacy::MasterKey::open(
                &dir.path().join("master.key"),
                dir.path(),
                Some([7; 32]),
            )
            .unwrap();
            let keystore = kronik_privacy::keystore::Keystore::open_owned(&owner, &master).unwrap();
            let pseudonyms = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
            kronik_privacy::sealer::Sealer::new(keystore).with_pseudonyms(pseudonyms)
        })
    }

    /// The node's detached initial secret refresh retires a certificate
    /// captured before it settles; wait until a fresh one stays current.
    fn settled(rt: &tokio::runtime::Runtime, node: &kronik_sched::Node) {
        rt.block_on(async {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Ok((_, publication)) = node.native_secret_snapshot_with_publication() {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    if publication.check_current().is_ok()
                        && publication.data_is_current_under_publication()
                    {
                        return;
                    }
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the initial secret refresh did not settle"
                );
            }
        });
    }

    /// Review R5: logrotate's `create` (the file renamed away, an empty one
    /// made under its name) and `copytruncate` (the file cut to 0) leave a
    /// file shorter than the sink recorded. The next batch starts a new
    /// file instead of writing at the old offset after NUL bytes, and what
    /// stays in the directory verifies.
    #[test]
    fn a_logrotated_file_is_not_written_at_the_old_offset() {
        use crate::audit::{Ctx, expected, lines, verify};
        use crate::spans::ActorKeys;
        let record = |lsn: u64| {
            let r = kronik_proto::Record::PrivacyMode(pb::PrivacyMode {
                epoch: lsn,
                mode: pb::PrivacyState::Off as i32,
                reseal_requested: false,
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
                sealer: test_sealer(),
                secrets: &[],
            };
            (
                lines(lsn, &r, &ctx).unwrap(),
                expected(lsn, &r, &ctx).unwrap(),
            )
        };
        let body = |lsn: u64| {
            record(lsn)
                .0
                .iter()
                .map(|l| format!("{}\n", l.to_json()))
                .collect::<String>()
        };
        for copytruncate in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut s = FileSink::open(dir.path(), 1 << 20).unwrap();
            s.append(body(1).as_bytes()).unwrap();
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
            s.append(body(2).as_bytes()).unwrap();
            let mut got = Vec::new();
            for f in files(dir.path()).unwrap() {
                let bytes = std::fs::read(&f).unwrap();
                assert!(!bytes.contains(&0), "NUL bytes in {}", f.display());
                for l in String::from_utf8(bytes).unwrap().lines() {
                    got.push(serde_json::from_str(l).unwrap());
                }
            }
            let report = verify(&[record(1).1, record(2).1].concat(), &got, 1, 2);
            assert!(report.complete, "{report:?}");
        }
    }

    #[test]
    fn the_file_sink_truncates_a_torn_line_and_rolls() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("audit");
        let mut s = FileSink::open(&dir, 20).unwrap();
        s.append(b"{\"lsn\":1}\n").unwrap();
        drop(s);
        let first = dir.join(file_name(1));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&first)
            .unwrap()
            .write_all(b"{\"lsn\":2,\"ki")
            .unwrap();
        let mut s = FileSink::open(&dir, 20).unwrap();
        s.append(b"{\"lsn\":2}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&first).unwrap(),
            "{\"lsn\":1}\n{\"lsn\":2}\n"
        );
        s.append(b"{\"lsn\":3}\n").unwrap();
        let written = files(&dir).unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(written[0], first);
        assert_eq!(std::fs::read(&written[1]).unwrap(), b"{\"lsn\":3}\n");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&written[1]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[test]
    fn large_files_and_oversized_torn_tails_preserve_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file_name(1));
        let mut file = std::fs::File::create(&path).unwrap();
        // Sparse large files must not require an allocation proportional to length.
        let whole_len = 128 << 20;
        file.set_len(whole_len).unwrap();
        file.seek(SeekFrom::Start(whole_len - 1)).unwrap();
        file.write_all(b"\n").unwrap();
        let chunk = [b'x'; 64 << 10];
        for _ in 0..80 {
            file.write_all(&chunk).unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        let mut sink = FileSink::open(dir.path(), MAX_FILE_BYTES).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), whole_len);
        sink.append(b"next\n").unwrap();
        let mut file = std::fs::File::open(path).unwrap();
        file.seek(SeekFrom::Start(whole_len - 1)).unwrap();
        let mut tail = Vec::new();
        file.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, b"\nnext\n");
    }

    #[test]
    fn rotation_is_a_soft_batch_threshold_and_rejects_invalid_limits() {
        let dir = tempfile::tempdir().unwrap();
        for max in [0, MAX_FILE_BYTES + 1, u64::MAX] {
            assert!(!FileSink::open(dir.path(), max).unwrap_err().fatal());
        }
        let mut sink = FileSink::open(dir.path(), 4).unwrap();
        let oversized = [vec![b'x'; 128 << 10], b"\n".to_vec()].concat();
        sink.append(&oversized).unwrap();
        sink.append(b"a\nb\n").unwrap();
        sink.append(b"c\n").unwrap();
        assert_eq!(
            std::fs::read(dir.path().join(file_name(1))).unwrap(),
            oversized
        );
        assert_eq!(
            std::fs::read(dir.path().join(file_name(2))).unwrap(),
            b"a\nb\n"
        );
        assert_eq!(
            std::fs::read(dir.path().join(file_name(3))).unwrap(),
            b"c\n"
        );
        assert!(!sink.append(b"partial").unwrap_err().fatal());
        assert_eq!(files(dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn removed_directories_are_recreated_on_append_retry() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/audit");
        let mut sink = FileSink::open(&dir, 100).unwrap();
        sink.append(b"old\n").unwrap();
        std::fs::remove_dir_all(root.path().join("a")).unwrap();
        std::fs::write(root.path().join("a"), b"blocked").unwrap();
        assert!(sink.append(b"new\n").is_err());
        assert_eq!(std::fs::read(root.path().join("a")).unwrap(), b"blocked");
        std::fs::remove_file(root.path().join("a")).unwrap();
        sink.append(b"new\n").unwrap();
        assert_eq!(std::fs::read(dir.join(file_name(2))).unwrap(), b"new\n");
    }

    #[test]
    fn symlinks_cannot_redirect_recovery_creation_or_retry() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep me without a newline").unwrap();
        let dir = root.path().join("audit");
        std::fs::create_dir(&dir).unwrap();
        let name = dir.join(file_name(1));
        symlink(&victim, &name).unwrap();
        assert!(files(&dir).is_err());
        assert!(FileSink::open(&dir, 100).is_err());
        std::fs::remove_file(&name).unwrap();
        let mut sink = FileSink::open(&dir, 100).unwrap();
        symlink(&victim, &name).unwrap();
        assert!(sink.append(b"replace\n").is_err());
        std::fs::remove_file(&name).unwrap();
        sink.append(b"old\n").unwrap();
        std::fs::remove_file(&name).unwrap();
        symlink(&victim, &name).unwrap();
        assert!(sink.append(b"replace\n").is_err());
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep me without a newline"
        );

        let real = root.path().join("real");
        std::fs::rename(&dir, &real).unwrap();
        symlink(&real, &dir).unwrap();
        assert!(sink.append(b"replace\n").is_err());
        assert!(FileSink::open(&dir, 100).is_err());
        assert!(FileSink::open(&dir.join("nested"), 100).is_err());
        assert!(!real.join("nested").exists());
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"keep me without a newline"
        );
    }

    #[test]
    fn a_retry_overwrites_only_the_unacknowledged_append_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = FileSink::open(dir.path(), 100).unwrap();
        sink.append(b"acknowledged\n").unwrap();
        let path = dir.path().join(file_name(1));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"unacknowledged whole line\nand a torn tail")
            .unwrap();
        sink.append(b"retry\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"acknowledged\nretry\n");
        drop(sink);
        let mut sink = FileSink::open(dir.path(), 100).unwrap();
        sink.append(b"after restart\n").unwrap();
        assert_eq!(
            std::fs::read(path).unwrap(),
            b"acknowledged\nretry\nafter restart\n"
        );
    }

    /// Review H-B: a rollover to a first LSN that has a file already (a
    /// restore or a rewind repeats it) starts a file of its own, and the
    /// old one keeps its lines.
    #[test]
    fn a_rollover_never_reuses_a_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path().join("a/b/audit");
        let mut s = FileSink::open(&dir, 1).unwrap();
        s.append(b"{\"lsn\":10,\"v\":\"old\"}\n").unwrap();
        s.append(b"{\"lsn\":20,\"v\":\"old\"}\n").unwrap();
        let mut s = FileSink::open(&dir, 1).unwrap();
        s.append(b"{\"lsn\":10,\"v\":\"new\"}\n").unwrap();
        let written = files(&dir).unwrap();
        assert_eq!(written.len(), 3);
        assert_eq!(
            std::fs::read(&written[0]).unwrap(),
            b"{\"lsn\":10,\"v\":\"old\"}\n"
        );
        assert_eq!(
            std::fs::read(&written[1]).unwrap(),
            b"{\"lsn\":20,\"v\":\"old\"}\n"
        );
        assert_eq!(
            std::fs::read(&written[2]).unwrap(),
            b"{\"lsn\":10,\"v\":\"new\"}\n"
        );
        std::fs::File::open(&written[2])
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        let mut s = FileSink::open(&dir, 1 << 20).unwrap();
        s.append(b"{\"lsn\":30,\"v\":\"restart\"}\n").unwrap();
        assert_eq!(files(&dir).unwrap(), written);
        assert_eq!(
            std::fs::read(&written[2]).unwrap(),
            b"{\"lsn\":10,\"v\":\"new\"}\n{\"lsn\":30,\"v\":\"restart\"}\n"
        );
    }
}
