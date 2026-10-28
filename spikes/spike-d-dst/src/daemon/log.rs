//! Append-only log: segment header, `[u32 len][u32 crc32c][u64 lsn][u8 kind]
//! [payload]` envelopes, group commit with fsync, and recovery scanning.
//!
//! The payload encoding is a stand-in for the Protobuf schema of M1.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use super::Mutation;
use crate::env::{Env, File, OpenMode};

pub const MAGIC: &[u8; 4] = b"KRNK";
pub const HEADER_LEN: u64 = 16;
const ENVELOPE_LEN: usize = 17;
const MAX_RECORD: u32 = 16 << 20;
pub const GROUP_COMMIT_WINDOW: Duration = Duration::from_millis(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectOutcome {
    Response {
        status: u16,
        body: Vec<u8>,
    },
    /// Definitely not sent.
    NotSent(String),
    /// May have been delivered.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok { status: u16, body: Vec<u8> },
    Failed { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnBegin {
    pub exec_id: String,
    pub actor: String,
    pub causal_key: String,
    pub ingress_key: String,
    pub time_ms: u64,
    pub seed: [u8; 32],
    pub input: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectResult {
    pub exec_id: String,
    pub ordinal: u32,
    pub outcome: EffectOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRecord {
    pub begin: TurnBegin,
    pub effects: Vec<(u32, EffectOutcome)>,
    pub writes: Vec<(String, Option<Vec<u8>>)>,
    pub outcome: Outcome,
    pub fuel: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    TurnBegin(TurnBegin),
    EffectResult(EffectResult),
    TurnRecord(TurnRecord),
}

impl Record {
    fn kind(&self) -> u8 {
        match self {
            Record::TurnBegin(_) => 1,
            Record::EffectResult(_) => 2,
            Record::TurnRecord(_) => 3,
        }
    }
}

// ---------------------------------------------------------------- encoding

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
    }
    fn str(&mut self, v: &str) {
        self.bytes(v.as_bytes());
    }
    fn begin(&mut self, b: &TurnBegin) {
        self.str(&b.exec_id);
        self.str(&b.actor);
        self.str(&b.causal_key);
        self.str(&b.ingress_key);
        self.u64(b.time_ms);
        self.0.extend_from_slice(&b.seed);
        self.bytes(&b.input);
    }
    fn effect(&mut self, e: &EffectOutcome) {
        match e {
            EffectOutcome::Response { status, body } => {
                self.u8(1);
                self.u16(*status);
                self.bytes(body);
            }
            EffectOutcome::NotSent(m) => {
                self.u8(2);
                self.str(m);
            }
            EffectOutcome::Unknown(m) => {
                self.u8(3);
                self.str(m);
            }
        }
    }
}

/// A record that passed its CRC but cannot be decoded, or carries kind 0 or
/// an unknown kind: `STORAGE_CORRUPT`, never a default value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corrupt(pub String);

struct Dec<'a>(&'a [u8]);

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Corrupt> {
        if self.0.len() < n {
            return Err(Corrupt("truncated payload".into()));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, Corrupt> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Corrupt> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| Corrupt("u16".into()))?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Corrupt> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| Corrupt("u32".into()))?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Corrupt> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| Corrupt("u64".into()))?,
        ))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, Corrupt> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Result<String, Corrupt> {
        String::from_utf8(self.bytes()?).map_err(|_| Corrupt("utf8".into()))
    }
    fn begin(&mut self) -> Result<TurnBegin, Corrupt> {
        Ok(TurnBegin {
            exec_id: self.str()?,
            actor: self.str()?,
            causal_key: self.str()?,
            ingress_key: self.str()?,
            time_ms: self.u64()?,
            seed: self
                .take(32)?
                .try_into()
                .map_err(|_| Corrupt("seed".into()))?,
            input: self.bytes()?,
        })
    }
    fn effect(&mut self) -> Result<EffectOutcome, Corrupt> {
        match self.u8()? {
            1 => Ok(EffectOutcome::Response {
                status: self.u16()?,
                body: self.bytes()?,
            }),
            2 => Ok(EffectOutcome::NotSent(self.str()?)),
            3 => Ok(EffectOutcome::Unknown(self.str()?)),
            k => Err(Corrupt(format!("effect outcome kind {k}"))),
        }
    }
}

pub fn encode_payload(r: &Record) -> Vec<u8> {
    let mut e = Enc::default();
    match r {
        Record::TurnBegin(b) => e.begin(b),
        Record::EffectResult(x) => {
            e.str(&x.exec_id);
            e.u32(x.ordinal);
            e.effect(&x.outcome);
        }
        Record::TurnRecord(t) => {
            e.begin(&t.begin);
            e.u32(t.effects.len() as u32);
            for (o, x) in &t.effects {
                e.u32(*o);
                e.effect(x);
            }
            e.u32(t.writes.len() as u32);
            for (k, v) in &t.writes {
                e.str(k);
                match v {
                    Some(v) => {
                        e.u8(1);
                        e.bytes(v);
                    }
                    None => e.u8(2),
                }
            }
            match &t.outcome {
                Outcome::Ok { status, body } => {
                    e.u8(1);
                    e.u16(*status);
                    e.bytes(body);
                }
                Outcome::Failed { code, message } => {
                    e.u8(2);
                    e.str(code);
                    e.str(message);
                }
            }
            e.u64(t.fuel);
        }
    }
    e.0
}

pub fn decode_payload(kind: u8, payload: &[u8]) -> Result<Record, Corrupt> {
    let mut d = Dec(payload);
    let r = match kind {
        1 => Record::TurnBegin(d.begin()?),
        2 => Record::EffectResult(EffectResult {
            exec_id: d.str()?,
            ordinal: d.u32()?,
            outcome: d.effect()?,
        }),
        3 => {
            let begin = d.begin()?;
            let n = d.u32()?;
            let mut effects = Vec::new();
            for _ in 0..n {
                effects.push((d.u32()?, d.effect()?));
            }
            let n = d.u32()?;
            let mut writes = Vec::new();
            for _ in 0..n {
                let k = d.str()?;
                let v = match d.u8()? {
                    1 => Some(d.bytes()?),
                    2 => None,
                    t => return Err(Corrupt(format!("write tag {t}"))),
                };
                writes.push((k, v));
            }
            let outcome = match d.u8()? {
                1 => Outcome::Ok {
                    status: d.u16()?,
                    body: d.bytes()?,
                },
                2 => Outcome::Failed {
                    code: d.str()?,
                    message: d.str()?,
                },
                t => return Err(Corrupt(format!("outcome tag {t}"))),
            };
            Record::TurnRecord(TurnRecord {
                begin,
                effects,
                writes,
                outcome,
                fuel: d.u64()?,
            })
        }
        k => return Err(Corrupt(format!("record kind {k}"))),
    };
    if !d.0.is_empty() {
        return Err(Corrupt("trailing bytes".into()));
    }
    Ok(r)
}

fn envelope(lsn: u64, r: &Record, out: &mut Vec<u8>) {
    let payload = encode_payload(r);
    let mut body = Vec::with_capacity(9 + payload.len());
    body.extend_from_slice(&lsn.to_le_bytes());
    body.push(r.kind());
    body.extend_from_slice(&payload);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    out.extend_from_slice(&body);
}

fn header(start_lsn: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN as usize);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&1u32.to_le_bytes());
    h.extend_from_slice(&start_lsn.to_le_bytes());
    h
}

// ---------------------------------------------------------------- scanning

#[derive(Debug, Default, Clone)]
pub struct Scan {
    pub records: Vec<(u64, Record)>,
    /// Offset just past the last valid record.
    pub valid_end: u64,
    /// Bytes after `valid_end` (a torn or partially persisted tail).
    pub tail_bytes: u64,
    /// Valid envelopes found *after* the first invalid one: only possible
    /// when unsynced writes were persisted out of order.
    pub valid_after_tear: u32,
}

/// Parses a whole segment image. CRC failures, short reads and LSN gaps end
/// the valid prefix (torn tail of the active segment); a record that passes
/// its CRC but does not decode is `STORAGE_CORRUPT`.
pub fn scan(image: &[u8]) -> Result<Scan, Corrupt> {
    let mut s = Scan {
        valid_end: HEADER_LEN,
        ..Scan::default()
    };
    if image.len() < HEADER_LEN as usize || &image[..4] != MAGIC {
        s.valid_end = 0;
        s.tail_bytes = image.len() as u64;
        return Ok(s);
    }
    let mut lsn_expected = u64::from_le_bytes(image[8..16].try_into().unwrap_or([0; 8]));
    let mut off = HEADER_LEN as usize;
    while let Some((rec_lsn, kind, payload, next)) = parse_at(image, off, lsn_expected) {
        s.records.push((rec_lsn, decode_payload(kind, payload)?));
        lsn_expected = rec_lsn + 1;
        off = next;
    }
    s.valid_end = off as u64;
    s.tail_bytes = (image.len() - off) as u64;
    // Diagnostics only: look for well-formed envelopes beyond the tear.
    let mut probe = off + 1;
    while probe + ENVELOPE_LEN <= image.len() {
        if let Some((_, _, _, next)) = parse_any(image, probe) {
            s.valid_after_tear += 1;
            probe = next;
        } else {
            probe += 1;
        }
    }
    Ok(s)
}

/// Parses consecutive valid records at the start of `bytes` (a suffix of a
/// segment starting at a record boundary). Returns the records and the
/// number of bytes consumed; stops at the first incomplete or invalid one.
pub fn parse_records(bytes: &[u8], mut expected_lsn: u64) -> (Vec<(u64, Record)>, usize) {
    let mut out = Vec::new();
    let mut off = 0;
    while let Some((lsn, kind, payload, next)) = parse_at(bytes, off, expected_lsn) {
        let Ok(r) = decode_payload(kind, payload) else {
            break;
        };
        out.push((lsn, r));
        expected_lsn = lsn + 1;
        off = next;
    }
    (out, off)
}

fn parse_any(image: &[u8], off: usize) -> Option<(u64, u8, &[u8], usize)> {
    let hdr = image.get(off..off + ENVELOPE_LEN)?;
    let len = u32::from_le_bytes(hdr[0..4].try_into().ok()?);
    if len > MAX_RECORD {
        return None;
    }
    let crc = u32::from_le_bytes(hdr[4..8].try_into().ok()?);
    let body = image.get(off + 8..off + ENVELOPE_LEN + len as usize)?;
    if crc32c::crc32c(body) != crc {
        return None;
    }
    let lsn = u64::from_le_bytes(body[0..8].try_into().ok()?);
    Some((lsn, body[8], &body[9..], off + ENVELOPE_LEN + len as usize))
}

fn parse_at(image: &[u8], off: usize, lsn_expected: u64) -> Option<(u64, u8, &[u8], usize)> {
    let r = parse_any(image, off)?;
    (r.0 == lsn_expected).then_some(r)
}

// ---------------------------------------------------------------- writer

pub struct Append {
    record: Record,
    done: oneshot::Sender<Result<u64, String>>,
}

/// Handle to the group-commit writer task.
#[derive(Clone)]
pub struct Log {
    tx: mpsc::UnboundedSender<Append>,
}

#[derive(Debug)]
pub struct Opened {
    pub scan: Scan,
    pub truncated_bytes: u64,
    pub recreated: bool,
}

pub fn segment_path(dir: &std::path::Path) -> PathBuf {
    dir.join("00000000000000000001.seg")
}

impl Log {
    /// Opens (or creates) the active segment, truncates a torn tail durably,
    /// and starts the writer. Committed records are forwarded to `committed`
    /// in LSN order after their fsync; `fatal` fires if the writer dies.
    pub async fn open(
        env: &Env,
        dir: PathBuf,
        committed: mpsc::UnboundedSender<(u64, Record)>,
        fatal: oneshot::Sender<String>,
        mutation: Option<Mutation>,
    ) -> io::Result<(Log, Opened)> {
        let dir_sync = mutation != Some(Mutation::NoDirSync);
        env.fs.create_dir_all(dir.clone()).await?;
        let path = segment_path(&dir);
        let existed = env.fs.exists(path.clone()).await?;
        let file = env.fs.open(path.clone(), OpenMode::ReadWriteCreate).await?;
        let len = file.len().await?;
        let image = file.read_at(0, len as usize).await?;
        let scan =
            scan(&image).map_err(|c| io::Error::other(format!("STORAGE_CORRUPT: {}", c.0)))?;
        let mut recreated = false;
        let mut truncated = 0;
        if scan.valid_end == 0 {
            // Missing or torn header: no record can have been acknowledged.
            file.set_len(0).await?;
            file.write_at(0, Bytes::from(header(1))).await?;
            file.sync_data().await?;
            if dir_sync {
                env.fs.sync_dir(dir.clone()).await?;
            }
            recreated = true;
        } else {
            if scan.tail_bytes > 0 && mutation != Some(Mutation::NoTruncateTail) {
                file.set_len(scan.valid_end).await?;
                file.sync_data().await?;
                truncated = scan.tail_bytes;
            }
            if !existed && dir_sync {
                env.fs.sync_dir(dir.clone()).await?;
            }
        }
        let next_lsn = scan.records.last().map(|(l, _)| l + 1).unwrap_or(1);
        let offset = if recreated {
            HEADER_LEN
        } else if mutation == Some(Mutation::NoTruncateTail) {
            len
        } else {
            scan.valid_end
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let ack_early = mutation == Some(Mutation::AckBeforeFsync);
        env.spawn(
            "log-writer",
            writer(
                env.clone(),
                file,
                rx,
                offset,
                next_lsn,
                committed,
                fatal,
                ack_early,
            ),
        );
        Ok((
            Log { tx },
            Opened {
                scan,
                truncated_bytes: truncated,
                recreated,
            },
        ))
    }

    /// Appends a record and resolves once it is fsynced, with its LSN.
    pub async fn append(&self, record: Record) -> Result<u64, String> {
        let (done, rx) = oneshot::channel();
        self.tx
            .send(Append { record, done })
            .map_err(|_| "log writer stopped".to_string())?;
        rx.await.map_err(|_| "log writer stopped".to_string())?
    }
}

#[allow(clippy::too_many_arguments)]
async fn writer(
    env: Env,
    file: Arc<dyn File>,
    mut rx: mpsc::UnboundedReceiver<Append>,
    mut offset: u64,
    mut next_lsn: u64,
    committed: mpsc::UnboundedSender<(u64, Record)>,
    fatal: oneshot::Sender<String>,
    ack_early: bool,
) {
    while let Some(first) = rx.recv().await {
        // Group commit: collect everything that arrives within the window.
        env.clock.sleep(GROUP_COMMIT_WINDOW).await;
        let mut batch = vec![first];
        while let Ok(a) = rx.try_recv() {
            batch.push(a);
        }
        let mut buf = Vec::new();
        let first_lsn = next_lsn;
        for a in &batch {
            envelope(next_lsn, &a.record, &mut buf);
            next_lsn += 1;
        }
        let len = buf.len() as u64;
        let mut res = file.write_at(offset, Bytes::from(buf)).await;
        if ack_early && res.is_ok() {
            // MUTATION: acknowledge before the fsync.
            for (i, a) in batch.drain(..).enumerate() {
                let lsn = first_lsn + i as u64;
                let _ = committed.send((lsn, a.record));
                let _ = a.done.send(Ok(lsn));
            }
        }
        if res.is_ok() {
            res = file.sync_data().await;
        }
        if let Err(e) = res {
            // Never retry a failed fsync: fail every waiter and stop. The
            // daemon treats this as fatal and restarts through recovery.
            let msg = format!("log write/fsync failed: {e}");
            for a in batch {
                let _ = a.done.send(Err(msg.clone()));
            }
            let _ = fatal.send(msg);
            return;
        }
        offset += len;
        for (i, a) in batch.into_iter().enumerate() {
            let lsn = first_lsn + i as u64;
            let _ = committed.send((lsn, a.record));
            let _ = a.done.send(Ok(lsn));
        }
    }
}
