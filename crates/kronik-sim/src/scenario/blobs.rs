//! The blob workload (M25, M26 §14; `--scenario blobs`): clients ask the
//! `media` guest to write blobs, to fetch bodies above the kind's threshold
//! from the simulated service and read them back, to post the blobs they
//! write (a request body streamed from the store), and to leave blobs loose
//! (written and discarded, written by a turn that then fails, a writer never
//! finished). The node runs its collector every virtual second, and the
//! workload adds passes of its own (`immediate` on half the seeds), so
//! sweeps run while turns hold blobs they have not committed yet. The disk
//! drops below `[blobs] disk_reserve` for a while on some seeds, so turns
//! that write blobs wait and run again. Besides the counter workload's
//! random crashes, a seed arms targeted crashes ([`CrashPoint`]): after a
//! blob's rename into place (before the record that references it), after a
//! log fsync (before its record is applied), after a blob directory's sync,
//! and between two deletions of a sweep.
//!
//! Invariants, after every start, after every pass of the workload's and at
//! the end ([`World::check_blob_refs`]):
//!
//! - every blob a committed record references, and every blob a pin of the
//!   index names, has its file, which reads back with its digest: a record
//!   never precedes its blob, and the collector never deletes what a record
//!   or a pin keeps (M26 B1, B2). Loose bytes may stay until a pass;
//!   missing committed bytes never;
//! - after a start, the index equals a rebuild from the log
//!   (`check_recovery`, with the `blobs` and `blob_pins` rows, B3);
//! - every blob a guest wrote or fetched has the bytes it was given, and
//!   every body the service received is the blob the guest wrote (B5);
//! - at the end, after two passes, no blob file is without a root and no
//!   part file is left (B6).
//!
//! The mutations ([`BlobMutation`]) break the store on purpose; each must
//! make some seed fail.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kronik_blob::{BlobMeta, BlobStore, NoKeys, Space, StoreConfig, SweepOptions};
use kronik_core::authority::AuthLease;
use kronik_core::ids::{ActorRef, Lsn};
use kronik_proto::log::v1 as pb;
use kronik_sched::{BlobsConfig, Ingress, Node, TurnResult};

use super::World;
use crate::SimRng;
use crate::fs::{CrashOp, CrashPoint};
use crate::service::{ServiceFaults, content};

/// The media guest (tests/guests/media.wasm).
pub const MEDIA: &[u8] = include_bytes!("../../../../tests/guests/media.wasm");
/// The data directory of the simulated node, which holds `blobs/`.
const DATA: &str = super::DATA_DIR;
/// `[blobs] disk_reserve`. The simulated disk reports no limit, except in a
/// full-store window, where it reports half of this.
const RESERVE: u64 = 1 << 30;
/// The actors' kind.
const KIND: &str = "media";

/// A deliberate bug in the blob store (mutation testing of the harness, as
/// `ack-before-fsync` for the log): each must make some seed fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobMutation {
    /// `ensure_durable` does not sync: a record can reference a blob whose
    /// name a crash loses.
    SkipEnsureDurable,
    /// A sweep deletes what a lease keeps: a blob a turn finished before
    /// the pass began, whose record is not applied yet.
    SweepIgnoresLeases,
    /// A sweep deletes what was named or claimed after it began: a blob a
    /// turn deduplicated onto during the pass.
    SweepIgnoresTouches,
    /// An erasure deletes none of its subject's blob files (E1).
    ErasureKeepsFiles,
}

impl BlobMutation {
    pub fn parse(name: &str) -> Option<BlobMutation> {
        match name {
            "blob-skip-ensure-durable" => Some(BlobMutation::SkipEnsureDurable),
            "blob-sweep-ignores-leases" => Some(BlobMutation::SweepIgnoresLeases),
            "blob-sweep-ignores-touches" => Some(BlobMutation::SweepIgnoresTouches),
            "blob-erasure-keeps-files" => Some(BlobMutation::ErasureKeepsFiles),
            _ => None,
        }
    }
}

/// The blob workload's knobs.
#[derive(Debug, Clone)]
pub struct BlobWorkload {
    /// The kind's `blob_threshold_bytes`.
    pub threshold: u64,
    /// The sizes of the blobs the guest writes: a few, so that writes land
    /// on each other's files (a loose one included) and deduplicate.
    pub sizes: Vec<u64>,
    /// The sizes of the bodies the service answers, around the threshold.
    pub fetched: Vec<u64>,
    /// How often the workload runs a collector pass of its own.
    pub sweep_every: Duration,
    /// Whether its passes delete at once, without the grace of a pass.
    pub immediate: bool,
    /// How many times the disk drops below the blob reserve for a while.
    pub full_windows: u32,
    /// Targeted crashes.
    pub crash_points: Vec<CrashPoint>,
    /// The most an open of a blob file takes longer ([`crate::fs::Disk::slow_open`]).
    pub slow_open: Duration,
    /// Data subjects (`user:0`, ...) whose blobs the workload writes and
    /// holds (M26 §9); 0 runs without a keystore, as M25 did.
    pub subjects: u32,
    /// Whether privacy mode is on: subjects' blobs are sealed, not only
    /// keyed.
    pub privacy_on: bool,
    /// How many of the subjects are erased while the clients run.
    pub erasures: u32,
    pub mutation: Option<BlobMutation>,
    pub faults: ServiceFaults,
}

impl BlobWorkload {
    pub fn for_seed(seed: u64) -> BlobWorkload {
        let r = SimRng::new(seed, b"blobs-config");
        let threshold = [256, 1024, 4096][r.below(3) as usize];
        let pick = |from: &[u64], n: usize| -> Vec<u64> {
            (0..n)
                .map(|_| from[r.below(from.len() as u64) as usize])
                .collect()
        };
        let sizes = pick(
            &[
                0, 1, 255, 256, 257, 4096, 65_535, 65_536, 65_537, 100_000, 200_000,
            ],
            2 + r.below(3) as usize,
        );
        let fetched = pick(
            &[0, 100, threshold, threshold + 1, 70_000, 200_000],
            2 + r.below(2) as usize,
        );
        let objects = PathBuf::from(DATA).join("blobs").join("objects");
        let log = PathBuf::from(DATA)
            .join("branches")
            .join("main")
            .join("log");
        let mut crash_points = Vec::new();
        for _ in 0..r.below(3) {
            let point = match r.below(4) {
                // After a blob's rename into place, before its record.
                0 => CrashPoint {
                    op: CrashOp::Rename,
                    under: objects.clone(),
                    nth: 1 + r.below(8),
                },
                // After a record's fsync, before its apply.
                1 => CrashPoint {
                    op: CrashOp::SyncData,
                    under: log.clone(),
                    nth: 5 + r.below(100),
                },
                // After a blob name is durable, before the record. A start's
                // preparation syncs the 256 shard directories and their
                // parent first.
                2 => CrashPoint {
                    op: CrashOp::SyncDir,
                    under: objects.clone(),
                    nth: 258 + r.below(8),
                },
                // Between two deletions of a sweep.
                _ => CrashPoint {
                    op: CrashOp::RemoveFile,
                    under: objects.clone(),
                    nth: 1 + r.below(4),
                },
            };
            crash_points.push(point);
        }
        // Drawn after the knobs above, which keep their values.
        let subjects = if r.chance(0.7) {
            1 + r.below(3) as u32
        } else {
            0
        };
        let privacy_on = r.chance(0.5);
        let erasures = if subjects > 0 {
            1 + r.below(u64::from(subjects.min(2))) as u32
        } else {
            0
        };
        BlobWorkload {
            threshold,
            sizes,
            fetched,
            sweep_every: Duration::from_millis(5 + r.below(200)),
            immediate: r.chance(0.5),
            full_windows: r.below(3) as u32,
            crash_points,
            slow_open: Duration::from_micros([0, 500, 3_000][r.below(3) as usize]),
            subjects,
            privacy_on,
            erasures,
            mutation: None,
            faults: ServiceFaults {
                connect_fail: [0.0, 0.05][r.below(2) as usize],
                lose_response: [0.0, 0.05][r.below(2) as usize],
                cut_body: [0.0, 0.05][r.below(2) as usize],
            },
        }
    }

    /// The directory the slow opens apply to.
    pub(super) fn objects() -> PathBuf {
        PathBuf::from(DATA).join("blobs").join("objects")
    }

    /// The store the node gets.
    pub(super) fn store_config(&self) -> StoreConfig {
        StoreConfig {
            reserve: RESERVE,
            lease_ttl: Duration::from_secs(30),
            mutation_skip_ensure_durable: self.mutation == Some(BlobMutation::SkipEnsureDurable),
            mutation_sweep_ignores_leases: self.mutation == Some(BlobMutation::SweepIgnoresLeases),
            mutation_sweep_ignores_touches: self.mutation
                == Some(BlobMutation::SweepIgnoresTouches),
            mutation_erasure_keeps_files: self.mutation == Some(BlobMutation::ErasureKeepsFiles),
        }
    }

    /// The node's `[blobs]` settings: its own pass every virtual second.
    pub(super) fn blobs_config(&self) -> BlobsConfig {
        BlobsConfig {
            disk_reserve: RESERVE,
            lease_ttl: Duration::from_secs(30),
            gc_interval: Duration::from_secs(1),
        }
    }
}

/// One request of the workload, and what its answer must be.
#[derive(Debug, Clone)]
enum Op {
    /// The answer is the blob of `size` bytes of the guest's pattern.
    Write { size: u64, chunk: u64 },
    /// GET `/bytes/<n>`, read the body back: `inline|blob ... <fnv>`.
    FetchSum { n: u64 },
    /// Write `size` bytes and POST them to `/sink`.
    WritePost { size: u64 },
    /// GET `/bytes/<n>`, then write `size` bytes: the answer is the blob.
    FetchWrite { n: u64, size: u64 },
    /// Write `size` bytes and discard them: loose bytes.
    WriteDiscard { size: u64 },
    /// Write 1000 bytes, then fail the turn: loose bytes.
    FailAfterWrite,
    /// Write into a writer never finished: a part file to discard.
    OpenWriter,
    /// Put `size` bytes (at most 1 MiB): the actor holds the blob and
    /// stores its reference (M26).
    Put { size: u64 },
    /// Read the stored reference whole: `<size> <fnv>`, or the error.
    HeldSum,
    /// Store `text` as the reference, in a turn without a subject: a copy
    /// of a subject's reference that the subject's erasure does not delete.
    RememberText { text: String },
}

/// Which actors a request goes to (M26 §9, the erasure part).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    /// `k<n>`: blobs without a subject.
    Plain,
    /// `s<i>`: subject `i`'s actor whose writes stop before its erasure, so
    /// a read of its held blob after the erasure must not see the bytes
    /// (E2).
    Strict(u32),
    /// `r<i>`: subject `i`'s actor whose writes may run across its erasure.
    Racy(u32),
}

fn subject_name(i: u32) -> String {
    format!("user:{i}")
}

impl Op {
    fn input(&self, actor: &ActorRef) -> pb::HttpInput {
        let (op, query, body) = match self {
            Op::Write { size, chunk } => ("write", format!("size={size}&chunk={chunk}"), None),
            Op::FetchSum { n } => ("fetch-sum", String::new(), Some(bytes_url(*n))),
            Op::WritePost { size } => (
                "write-post",
                format!("size={size}&url=http://payments/sink"),
                None,
            ),
            Op::FetchWrite { n, size } => {
                ("fetch-write", format!("size={size}"), Some(bytes_url(*n)))
            }
            Op::WriteDiscard { size } => ("write-discard", format!("size={size}"), None),
            Op::FailAfterWrite => ("fail-after-write", String::new(), None),
            Op::OpenWriter => ("open-writer", String::new(), None),
            Op::Put { size } => ("put", format!("size={size}"), None),
            Op::HeldSum => ("held-sum", String::new(), None),
            Op::RememberText { text } => ("remember-text", String::new(), Some(text.clone())),
        };
        pb::HttpInput {
            method: "POST".into(),
            path: format!("/{KIND}/{}/{op}", actor.key),
            query,
            body: Some(pb::Body {
                value: Some(pb::body::Value::Inline(pb::Sealable {
                    subject: None,
                    value: Some(pb::sealable::Value::Plain(
                        body.unwrap_or_default().into_bytes(),
                    )),
                })),
            }),
            ..Default::default()
        }
    }
}

fn bytes_url(n: u64) -> String {
    format!("http://payments/bytes/{n}")
}

/// Byte `i` of what the guest writes (`media`'s `pattern`).
fn pattern(i: u64) -> u8 {
    ((i.wrapping_mul(31) + 7) % 251) as u8
}

fn written(size: u64) -> Vec<u8> {
    (0..size).map(pattern).collect()
}

/// The guest's FNV-1a 64 of `bytes`, as it answers it.
fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn plain_hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

/// The request hash an ingress key is saved under (`INGRESS_HASH_VERSION`
/// and 32 bytes), the same for every retry of a request.
fn request_hash(input: &pb::HttpInput) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(input.method.as_bytes());
    h.update(b"\0");
    h.update(input.path.as_bytes());
    h.update(b"\0");
    h.update(input.query.as_bytes());
    h.update(b"\0");
    if let Some(pb::body::Value::Inline(s)) = input.body.as_ref().and_then(|b| b.value.as_ref())
        && let Some(pb::sealable::Value::Plain(b)) = &s.value
    {
        h.update(b);
    }
    [
        &[kronik_sched::INGRESS_HASH_VERSION][..],
        h.finalize().as_bytes(),
    ]
    .concat()
}

/// A committed answer as text: the blob's `blob <hash> <size>`, or the
/// inline body.
fn answer_text(r: &TurnResult) -> Result<String, String> {
    if !r.committed() {
        return Err(format!("{} {}", r.outcome.error_code, r.outcome.message));
    }
    match &r.outcome.output {
        Some(pb::outcome::Output::Http(h)) => {
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Blob(blob)) => {
                    Ok(format!("blob {} {}", blob.hash, blob.size))
                }
                Some(pb::body::Value::Inline(s)) => match &s.value {
                    Some(pb::sealable::Value::Plain(b)) => {
                        Ok(String::from_utf8_lossy(b).into_owned())
                    }
                    other => Err(format!("an inline body {other:?}")),
                },
                other => Err(format!("a body {other:?}")),
            }
        }
        other => Err(format!("an output {other:?}")),
    }
}

/// The blob workload's state.
#[derive(Default)]
pub(super) struct BlobState {
    /// The blob store of the node that runs now.
    pub(super) store: Option<Arc<BlobStore>>,
    /// The first answer to each request.
    answers: BTreeMap<String, String>,
    /// The workload's collector passes, and the checks after them.
    sweeps: u64,
    /// Full-store windows so far.
    full: u32,
    /// Subjects whose erasure has begun: their strict actors write no more.
    erasing: BTreeSet<u32>,
    /// Subjects whose erasure is done (its call returned, or a start
    /// recovered it).
    erased: BTreeSet<u32>,
    /// The writes of each subject's strict actor in flight.
    inflight: BTreeMap<u32, u32>,
    /// Reads of a held blob after its subject's erasure (E2), and how many
    /// of them reached the blob (`erased`) rather than a deleted reference.
    erased_reads: (u32, u32),
}

/// What an attempt at a request came to.
enum Attempt {
    Answer(Box<TurnResult>),
    /// No node, a crash, a refusal: try again.
    Again,
}

impl World {
    fn blobs(&self) -> Option<&BlobWorkload> {
        self.cfg.blobs.as_ref()
    }

    /// Opens the node's blob store on its disk (once per start): main's
    /// store under the data directory's `blobs/`, which deletes the part
    /// files a crash left.
    pub(super) async fn open_blob_store(
        &self,
        env: &kronik_core::env::Env,
    ) -> Result<Option<Arc<BlobStore>>, String> {
        let Some(workload) = self.blobs() else {
            return Ok(None);
        };
        let store = BlobStore::open(env.clone(), Path::new(DATA), workload.store_config())
            .await
            .map_err(|e| e.to_string())?;
        self.st().blobs.store = Some(store.clone());
        Ok(Some(store))
    }

    /// Deploys `media`, sets its threshold and grants it the service (each
    /// once: they are history after a restart).
    pub(super) async fn setup_blobs(
        &self,
        node: &Node,
        authority: &AuthLease,
    ) -> Result<(), String> {
        let Some(workload) = self.blobs() else {
            return Ok(());
        };
        let audit = || pb::Audit {
            token_id: "sim".into(),
            reason: "dst".into(),
            wall_time_ms: 0,
        };
        if !node.kind_exists(KIND) {
            node.deploy(MEDIA, audit(), false, authority.clone())
                .await
                .map_err(|e| format!("deploy: {}", e.code))?;
            self.event("deployed media");
        }
        let config = node.config_now();
        if config.limits(KIND).blob_threshold_bytes != workload.threshold {
            node.set_limits(
                pb::Limits {
                    kind: KIND.into(),
                    blob_threshold_bytes: Some(workload.threshold),
                    ..Default::default()
                },
                audit(),
                false,
                authority.clone(),
            )
            .await
            .map_err(|e| format!("limits: {}", e.code))?;
        }
        if workload.privacy_on && node.privacy_mode().0 != pb::PrivacyState::On {
            node.set_privacy_mode(pb::PrivacyState::On, audit(), false, authority.clone())
                .await
                .map_err(|e| format!("privacy mode: {}", e.code))?;
            self.event("privacy mode on");
        }
        if config.http_grant(KIND, "payments").is_none() {
            node.grant(
                KIND,
                "http:payments",
                Some(kronik_effects::Delivery::IdempotencyKeyed),
                None,
                kronik_effects::InForks::Recorded,
                audit(),
                false,
                authority.clone(),
            )
            .await
            .map_err(|e| format!("grant: {}", e.code))?;
        }
        Ok(())
    }

    /// A failed turn the workload asked for: `fail-after-write`, and a
    /// read of a held reference that is not there or whose subject was
    /// erased.
    pub(super) fn expected_blob_failure(&self, turn: &pb::TurnRecord) -> bool {
        let Some(pb::input::Kind::Http(h)) = turn.input.as_ref().and_then(|i| i.kind.as_ref())
        else {
            return false;
        };
        let message = turn.outcome.as_ref().map_or("", |o| o.message.as_str());
        self.blobs().is_some()
            && (h.path.ends_with("/fail-after-write")
                || (h.path.ends_with("/held-sum")
                    && (message == "no ref" || message == "get: erased"))
                // A write of a subject's blob in a turn that ran across the
                // subject's erasure (its path is sealed with the subject).
                || message == "write: erased")
    }

    fn draw_op(&self) -> Op {
        let Some(workload) = self.blobs() else {
            return Op::OpenWriter;
        };
        let size = || workload.sizes[self.work.below(workload.sizes.len() as u64) as usize];
        let n = || workload.fetched[self.work.below(workload.fetched.len() as u64) as usize];
        match self.work.below(100) {
            0..35 => Op::Write {
                size: size(),
                chunk: [1_000, 65_536, 1 << 20][self.work.below(3) as usize],
            },
            35..55 => Op::FetchSum { n: n() },
            55..70 => Op::WritePost { size: size() },
            70..80 => Op::FetchWrite {
                n: n(),
                size: size(),
            },
            80..90 => Op::WriteDiscard { size: size() },
            90..95 => Op::FailAfterWrite,
            _ => Op::OpenWriter,
        }
    }

    fn draw_size(&self) -> u64 {
        self.blobs().map_or(0, |w| {
            w.sizes[self.work.below(w.sizes.len() as u64) as usize]
        })
    }

    /// The next request: its actor's key, its operation and its group. A
    /// strict write is counted in flight here, in the same step as the check
    /// that its subject's erasure has not begun.
    fn draw_request(&self) -> (String, Op, Group) {
        let subjects = self.blobs().map_or(0, |w| w.subjects);
        if subjects == 0 || self.work.below(100) < 40 {
            let key = format!("k{}", self.work.below(self.cfg.actors as u64));
            return (key, self.draw_op(), Group::Plain);
        }
        let i = self.work.below(u64::from(subjects)) as u32;
        let size = self.draw_size().min(1 << 20);
        let pick = self.work.below(100);
        if self.work.chance(0.6) {
            let op = match pick {
                0..55 => Op::Put { size },
                55..80 => Op::HeldSum,
                _ => Op::Write {
                    size,
                    chunk: 65_536,
                },
            };
            let mut st = self.st();
            if matches!(op, Op::HeldSum) || st.blobs.erasing.contains(&i) {
                return (format!("s{i}"), Op::HeldSum, Group::Strict(i));
            }
            *st.blobs.inflight.entry(i).or_default() += 1;
            return (format!("s{i}"), op, Group::Strict(i));
        }
        let op = match pick {
            0..50 => Op::Write {
                size,
                chunk: 65_536,
            },
            50..80 => Op::Put { size },
            _ => Op::WriteDiscard { size },
        };
        (format!("r{i}"), op, Group::Racy(i))
    }

    /// Asks the node that runs now; waits for the answer while that node
    /// runs.
    async fn ask_media(
        &self,
        actor: &ActorRef,
        input: &pb::HttpInput,
        subject: Option<&str>,
    ) -> Attempt {
        let (node, node_id) = {
            let st = self.st();
            (st.node.clone(), st.node_id)
        };
        let Some(node) = node else {
            return Attempt::Again;
        };
        let waiter = match node.ingress(actor.clone(), input.clone(), subject.map(str::to_owned)) {
            Ok(Ingress::Done(r)) => return Attempt::Answer(r),
            Ok(Ingress::Started(w) | Ingress::Joined(w)) => w,
            Err(e) => {
                self.event(format!("ingress {}: {}", input.idempotency_key, e.code));
                return Attempt::Again;
            }
        };
        drop(node);
        let mut wait = Box::pin(async move { waiter.wait().await });
        loop {
            let tick = self.sleep(Duration::from_millis(50));
            tokio::select! {
                biased;
                r = &mut wait => {
                    return match r {
                        Ok(r) => Attempt::Answer(Box::new(r)),
                        Err(e) => {
                            self.event(format!(
                                "{}: {} {}",
                                input.idempotency_key, e.code, e.message
                            ));
                            Attempt::Again
                        }
                    };
                }
                () = tick => {}
            }
            // A crash dropped the turn: its waiter never answers.
            if self.st().node_id != node_id {
                return Attempt::Again;
            }
        }
    }

    /// Sends `op` to `actor` under the Idempotency-Key `idem` until it is
    /// answered.
    async fn request(
        &self,
        actor: &ActorRef,
        op: &Op,
        idem: &str,
        subject: Option<&str>,
    ) -> Option<Box<TurnResult>> {
        let mut input = op.input(actor);
        input.idempotency_key = idem.to_owned();
        input.request_hash = request_hash(&input);
        self.st().requests += 1;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if attempt > 2_000 {
                self.violation(format!("{idem} {op:?} never answered"));
                return None;
            }
            match self.ask_media(actor, &input, subject).await {
                Attempt::Answer(result) => return Some(result),
                Attempt::Again => {
                    let backoff = self
                        .work
                        .duration(Duration::from_millis(5), Duration::from_millis(60));
                    self.sleep(backoff).await;
                }
            }
        }
    }

    pub(super) async fn blob_client(self: Arc<Self>, client: usize) {
        for r in 0..self.cfg.requests_per_client {
            let (key, op, group) = self.draw_request();
            let actor = match ActorRef::parse(&format!("{KIND}/{key}")) {
                Ok(actor) => actor,
                Err(e) => return self.violation(format!("actor: {e}")),
            };
            let subject = match (group, &op) {
                (Group::Plain, _) | (_, Op::HeldSum) => None,
                (Group::Strict(i) | Group::Racy(i), _) => Some(subject_name(i)),
            };
            // A read is held to E2 when its subject's erasure was done before
            // it was asked.
            let erased_before = match group {
                Group::Strict(i) => self.st().blobs.erased.contains(&i),
                _ => false,
            };
            let idem = format!("b{client}-{r}");
            let Some(result) = self.request(&actor, &op, &idem, subject.as_deref()).await else {
                return;
            };
            let text = self
                .check_answer(&idem, &op, group, erased_before, &result)
                .await;
            // A strict put's reference is copied into state by a turn
            // without a subject: the erasure deletes the subject's own copy,
            // not this one, so a later read reaches the erased blob.
            if let (Group::Strict(_), Op::Put { .. }, Some(text)) = (group, &op, &text)
                && let Some(reference) = text.strip_prefix("blob ")
            {
                let remember = Op::RememberText {
                    text: reference.to_owned(),
                };
                let idem = format!("{idem}-remember");
                if let Some(result) = self.request(&actor, &remember, &idem, None).await {
                    self.check_answer(&idem, &remember, group, false, &result)
                        .await;
                }
            }
            if let Group::Strict(i) = group
                && !matches!(op, Op::HeldSum)
                && let Some(n) = self.st().blobs.inflight.get_mut(&i)
            {
                *n = n.saturating_sub(1);
            }
        }
        self.st().clients_done += 1;
    }

    /// Whether subject `i`'s erasure has begun.
    fn erasure_began(&self, i: u32) -> bool {
        let st = self.st();
        st.blobs.erasing.contains(&i) || st.blobs.erased.contains(&i)
    }

    /// The answer to a request is the one its operation must give, the same
    /// on every retry; a blob it names has its bytes (B5); a read of a held
    /// blob after its subject's erasure never sees the bytes (E2). Returns
    /// the answer's text when it was what the operation must give.
    async fn check_answer(
        &self,
        idem: &str,
        op: &Op,
        group: Group,
        erased_before: bool,
        result: &TurnResult,
    ) -> Option<String> {
        // A racy request that ran across its subject's erasure: the turn may
        // be refused new blobs of the subject (`erased`, a failed write), its
        // saved response may be the erasure's tombstone, and a retry after
        // the erasure runs again (the erasure deleted the saved response).
        // E1 is what holds for it.
        if let Group::Racy(i) = group
            && self.erasure_began(i)
        {
            let what = match answer_text(result) {
                Ok(text) => text,
                Err(e) => e,
            };
            self.event(format!(
                "{idem} {op:?} {group:?} across the erasure -> {what}"
            ));
            return None;
        }
        let text = match (op, answer_text(result)) {
            (Op::FailAfterWrite, Err(e)) if e.starts_with("TURN_FAILED") => e,
            (Op::HeldSum, Err(e))
                if e == "TURN_FAILED no ref" || e == "TURN_FAILED get: erased" =>
            {
                e
            }
            (_, Ok(text)) => text,
            (_, Err(e)) => {
                self.violation(format!("{idem} {op:?}: {e}"));
                return None;
            }
        };
        self.event(format!("{idem} {op:?} {group:?} -> {text}"));
        {
            let mut st = self.st();
            match st.blobs.answers.get(idem) {
                Some(first) if *first != text => {
                    let v = format!("{idem}: answered {text:?}, first {first:?}");
                    drop(st);
                    self.violation(v);
                    return None;
                }
                Some(_) => {}
                None => {
                    st.blobs.answers.insert(idem.to_owned(), text.clone());
                }
            }
        }
        let subject = match group {
            Group::Plain => None,
            Group::Strict(i) | Group::Racy(i) => Some(i),
        };
        // A fetch the service failed or cut answers its error: nothing to
        // check of the bytes.
        let network = text.starts_with("network")
            || text.starts_with("timeout")
            || text.starts_with("outcome-unknown")
            || text.starts_with("too-large");
        // A subject's blob is keyed (`b3s:`), so only its size is known
        // here; its bytes are checked below.
        let expected_blob = |size: u64| match subject {
            None => text == format!("blob {} {size}", plain_hash(&written(size))),
            Some(_) => text.starts_with("blob b3s:") && text.ends_with(&format!(" {size}")),
        };
        let ok = match op {
            Op::Write { size, .. } | Op::Put { size } => expected_blob(*size),
            Op::FetchWrite { size, .. } => network || expected_blob(*size),
            Op::FetchSum { n } => {
                let body = content(*n);
                let what = if *n > self.blobs().map_or(0, |w| w.threshold) {
                    format!("blob {} {n}", plain_hash(&body))
                } else {
                    format!("inline {n}")
                };
                network || text == format!("{what} {n} {}", fnv(&body))
            }
            Op::WritePost { .. } => network || text == "status 201",
            Op::WriteDiscard { .. } => text == "discarded",
            Op::OpenWriter => text == "left open",
            Op::FailAfterWrite => text.starts_with("TURN_FAILED"),
            Op::RememberText { .. } => text == "remembered",
            Op::HeldSum => match text.split_once(' ') {
                // The bytes of a blob the actor holds: never after its
                // subject's erasure (E2).
                Some((size, sum)) if !text.starts_with("TURN_FAILED") => {
                    // An empty blob is read without a call: no bytes to see.
                    if erased_before && size != "0" {
                        let i = subject.unwrap_or_default();
                        self.violation(format!(
                            "{idem}: a read of {}'s held blob after its erasure got its bytes: \
                             {text}",
                            subject_name(i)
                        ));
                        return None;
                    }
                    size.parse::<u64>()
                        .is_ok_and(|size| sum == fnv(&written(size)))
                }
                _ if text == "TURN_FAILED get: erased" => {
                    if erased_before {
                        self.st().blobs.erased_reads.1 += 1;
                    }
                    // Erased only once its erasure has begun.
                    subject.is_some_and(|i| self.erasure_began(i))
                }
                _ => true,
            },
        };
        if erased_before && matches!(op, Op::HeldSum) {
            self.st().blobs.erased_reads.0 += 1;
        }
        if !ok {
            self.violation(format!("{idem} {op:?}: unexpected answer {text}"));
            return None;
        }
        if let Some(blob) = text.strip_prefix("blob ") {
            // Its bytes are in the store now (B1 for a blob just answered).
            let mut words = blob.split(' ');
            if let (Some(hash), Some(size)) = (words.next(), words.next())
                && let Ok(size) = size.parse::<u64>()
            {
                match self.answered_ref(result, hash).await {
                    Some(blob) => {
                        if let Err(e) = self.read_blob(None, &blob).await
                            && !subject.is_some_and(|i| self.erasure_began(i))
                        {
                            self.violation(format!("{idem}: the blob it answered: {e}"));
                        }
                    }
                    // Its subject's erasure, and a pass, took its row.
                    None if subject.is_some_and(|i| self.erasure_began(i)) => {}
                    None => self.violation(format!(
                        "{idem}: neither the record of its turn nor the index knows {hash} \
                         ({size} bytes)"
                    )),
                }
            }
        }
        Some(text)
    }

    /// The complete reference of `hash`, from the index once the record of
    /// the turn that answered `result` is applied (a put of a blob the
    /// actor held already records no reference, but its row is there).
    /// Waits with the state store only: a supervisor task that kept the node
    /// past a crash would keep its custody of the keystore from the next
    /// node. `None` when the store went with a crash, or the row with the
    /// subject's erasure.
    async fn answered_ref(&self, result: &TurnResult, hash: &str) -> Option<pb::BlobRef> {
        let store = self.st().node.as_ref()?.store().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let applied = store.clone();
        let lsn = result.turn_id.lsn;
        self.exec.spawn(
            crate::exec::SUPERVISOR,
            "applied",
            Box::pin(async move {
                applied.applied.wait(lsn).await;
                let _ = tx.send(());
            }),
        );
        self.clock_timeout(Duration::from_secs(5), rx).await?.ok()?;
        let row = store.db().blob(hash).ok()??;
        Some(pb::BlobRef {
            hash: row.hash,
            size: row.size,
            subject: row.subject,
            key_version: row.key_version,
        })
    }

    /// Reads and verifies a blob with the store of the node that runs now
    /// (or the last one), with the node's keys for a subject's blob.
    async fn read_blob(&self, node: Option<&Node>, blob: &pb::BlobRef) -> Result<(), String> {
        // The keys are taken now, from the keystore of `node`, else of the
        // node that runs now: the read below holds no part of the node (see
        // `answered_ref`).
        let (store, keys) = {
            let st = self.st();
            let keys = match (&blob.subject, node.or(st.node.as_deref())) {
                (Some(subject), Some(node)) => {
                    use kronik_blob::KeyAccess as _;
                    let access = node.sealer().blob_key_access();
                    Some(FixedKeys {
                        subject: subject.clone(),
                        version: blob.key_version,
                        seal: access.seal_key(subject, blob.key_version),
                        identity: access.identity_key(subject, blob.key_version),
                    })
                }
                _ => None,
            };
            (st.blobs.store.clone(), keys)
        };
        let store = store.ok_or_else(|| "no blob store".to_string())?;
        // Its subject's keys are erased: its erasure is under way, and E1
        // checks its file once the erasure is done.
        if keys.as_ref().is_some_and(|k| {
            matches!(k.identity, kronik_blob::KeyAnswer::Erased)
                || matches!(k.seal, kronik_blob::KeyAnswer::Erased)
        }) {
            return Ok(());
        }
        let meta = BlobMeta::from_pb(blob).map_err(|e| format!("{}: {e}", blob.hash))?;
        let failed = |e: kronik_blob::BlobError| format!("{}: {e}", blob.hash);
        match &keys {
            Some(keys) => {
                let reader = store
                    .reader(&Space::Main, &meta, keys)
                    .await
                    .map_err(failed)?;
                reader
                    .verify(keys)
                    .await
                    .map_err(|e| format!("{} does not verify: {e}", blob.hash))
            }
            None => {
                let reader = store
                    .reader(&Space::Main, &meta, &NoKeys)
                    .await
                    .map_err(failed)?;
                reader
                    .verify(&NoKeys)
                    .await
                    .map_err(|e| format!("{} does not verify: {e}", blob.hash))
            }
        }
    }

    /// E1: no erased row of the index has a file in main's store. The node
    /// deletes them once an erasure's record is applied and at every start
    /// (M26 §9.3).
    pub(super) async fn check_erased_files(&self, node: &Node, when: &str) {
        if self.blobs().is_none_or(|w| w.subjects == 0) {
            return;
        }
        let Some(store) = self.st().blobs.store.clone() else {
            return;
        };
        let mut erased: BTreeSet<String> = match node.store().db().erased_blobs() {
            Ok(erased) => erased.into_iter().collect(),
            Err(e) => return self.violation(format!("{when}: reading the erased blobs: {e}")),
        };
        // And the erased blobs whose rows the collector already forgot.
        let erasures = erased_versions(node);
        if !erasures.is_empty() {
            let read = node
                .reader()
                .read(1, node.applied_lsn(), |c| {
                    for blob in kronik_proto::blobs::refs(&c.record) {
                        if is_erased(&erasures, blob) {
                            erased.insert(blob.hash.clone());
                        }
                    }
                    Ok(())
                })
                .await;
            if let Err(e) = read {
                return self.violation(format!("{when}: reading the log: {e}"));
            }
        }
        let left: Vec<String> = {
            let disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
            erased
                .into_iter()
                .filter(|hash| {
                    kronik_blob::BlobId::parse(hash)
                        .is_ok_and(|id| disk.exists(&store.object_path(&Space::Main, &id)))
                })
                .collect()
        };
        for hash in left {
            let row = node.store().db().blob(&hash).ok().flatten();
            self.violation(format!(
                "{when}: the erased blob {hash} still has its file (index row {row:?})"
            ));
        }
    }

    /// E1 after `subject`'s erasure (its record at `lsn`, through
    /// `key_version`) returned.
    ///
    /// At once: no erased blob of the subject that a record referenced
    /// before the erasure has a file. The erasure deleted those files after
    /// its record was applied, and no turn installs a blob of the subject
    /// once its erasure marks are set (M26 §9.3, B15 part 6).
    ///
    /// Later, in privacy mode on: once `privacy status` reports nothing
    /// pending, no erased blob has a file at all. A turn that ran across the
    /// erasure may commit a blob of the subject after the erasure returned
    /// (ADR 0123); applying its record deletes the file, and the erasure is
    /// pending until then. In mode off the subject's plain values in the log
    /// keep it pending until a reseal, so only the first check and the
    /// checks after every start and at the end apply.
    async fn after_erasure(&self, node: &Node, subject: &str, lsn: Lsn, key_version: u32) {
        let when = format!("{subject}'s erasure (lsn {lsn})");
        self.check_erased_at_return(node, subject, lsn, key_version, &when);
        if self.blobs().is_none_or(|w| !w.privacy_on) {
            return;
        }
        let mut waited = Duration::ZERO;
        loop {
            match node.pending_erasures().await {
                Ok(0) => break,
                // Bounded: the run ends, or the node with it, before long.
                Ok(_) if waited < Duration::from_secs(5) => {}
                Ok(n) => {
                    return self.violation(format!(
                        "{when}: privacy status still reports {n} pending erasure(s) after \
                         {waited:?}"
                    ));
                }
                Err(e) => return self.event(format!("{when}: privacy status: {}", e.code)),
            }
            self.sleep(Duration::from_millis(50)).await;
            waited += Duration::from_millis(50);
        }
        if !waited.is_zero() {
            self.event(format!("{when}: pending for {waited:?}"));
        }
        self.check_erased_files(node, &format!("{when}, once nothing was pending"))
            .await;
    }

    /// The first check of [`World::after_erasure`].
    fn check_erased_at_return(
        &self,
        node: &Node,
        subject: &str,
        lsn: Lsn,
        key_version: u32,
        when: &str,
    ) {
        let Some(store) = self.st().blobs.store.clone() else {
            return;
        };
        let rows = match node.store().db().erased_subject_blobs() {
            Ok(rows) => rows,
            Err(e) => return self.violation(format!("{when}: reading the erased blobs: {e}")),
        };
        let mut left = Vec::new();
        for (hash, of) in rows {
            if of != subject {
                continue;
            }
            let Ok(Some(row)) = node.store().db().blob(&hash) else {
                continue;
            };
            if row.key_version > key_version || row.first_lsn >= lsn {
                continue;
            }
            let Ok(id) = kronik_blob::BlobId::parse(&hash) else {
                continue;
            };
            let path = store.object_path(&Space::Main, &id);
            if self
                .disk
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .exists(&path)
            {
                left.push(row);
            }
        }
        for row in left {
            self.violation(format!(
                "{when} returned, but the erased blob {} (first referenced at lsn {}) still has \
                 its file",
                row.hash, row.first_lsn
            ));
        }
    }

    /// Erases the seed's subjects while the clients run, each once its
    /// strict actor's writes are done, and checks E1 after each.
    pub(super) async fn blob_eraser(self: Arc<Self>) {
        let Some(workload) = self.blobs().cloned() else {
            return;
        };
        for i in 0..workload.erasures {
            let wait = self
                .work
                .duration(Duration::from_millis(50), Duration::from_millis(1500));
            self.sleep(wait).await;
            if self.st().clients_done == self.cfg.clients {
                return;
            }
            let subject = subject_name(i);
            self.st().blobs.erasing.insert(i);
            self.event(format!(
                "erasing {subject}: its strict actor writes no more"
            ));
            while self.st().blobs.inflight.get(&i).copied().unwrap_or(0) > 0 {
                self.sleep(Duration::from_millis(5)).await;
            }
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                if attempts > 1_000 {
                    return self.violation(format!("{subject} was never erased"));
                }
                let (node, node_id) = {
                    let st = self.st();
                    (st.node.clone(), st.node_id)
                };
                let Some(node) = node else {
                    self.sleep(Duration::from_millis(10)).await;
                    continue;
                };
                // A start recovers an erasure whose keys went before a crash
                // took its record (`recover_erasures`).
                if attempts > 1
                    && node
                        .store()
                        .db()
                        .erasures()
                        .is_ok_and(|e| e.iter().any(|(s, _)| *s == subject))
                {
                    self.event(format!("{subject}'s erasure was done by a start"));
                    break;
                }
                let authority = match node.local_operator_authority() {
                    Ok(authority) => authority,
                    Err(_) => {
                        self.sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let (tx, rx) = tokio::sync::oneshot::channel();
                let eraser = node.clone();
                let erased = subject.clone();
                // E1 runs in the node's task too: what holds the node ends
                // with it.
                let world = self.clone();
                self.exec.spawn(
                    node_id,
                    "erase",
                    Box::pin(async move {
                        let audit = pb::Audit {
                            token_id: "sim".into(),
                            reason: "dst erasure".into(),
                            wall_time_ms: 0,
                        };
                        let result = eraser.erase_subject(&erased, audit, false, authority).await;
                        if let Ok(done) = &result
                            && let Some(lsn) = done.lsn
                        {
                            world
                                .after_erasure(&eraser, &erased, lsn, done.key_version)
                                .await;
                        }
                        let _ = tx.send(result);
                    }),
                );
                drop(node);
                match self.clock_timeout(Duration::from_secs(60), rx).await {
                    Some(Ok(Ok(done))) => {
                        self.event(format!(
                            "erased {subject}: lsn {:?}, {} blob files deleted",
                            done.lsn, done.blobs
                        ));
                        break;
                    }
                    Some(Ok(Err(e))) => self.event(format!("erasing {subject}: {}", e.code)),
                    _ => self.event(format!("erasing {subject}: ended with its node")),
                }
                self.sleep(Duration::from_millis(20)).await;
            }
            self.st().blobs.erased.insert(i);
        }
    }

    /// Opens the seed's full-store windows at random times while the clients
    /// run.
    pub(super) async fn blob_disk(self: Arc<Self>) {
        let Some(workload) = self.blobs().cloned() else {
            return;
        };
        for _ in 0..workload.full_windows {
            let wait = self
                .work
                .duration(Duration::from_millis(10), Duration::from_millis(800));
            self.sleep(wait).await;
            if self.st().clients_done == self.cfg.clients {
                return;
            }
            self.full_window().await;
        }
    }

    /// Runs collector passes of the workload's own while the clients run,
    /// and checks the references after every pass.
    pub(super) async fn blob_director(self: Arc<Self>) {
        let Some(workload) = self.blobs().cloned() else {
            return;
        };
        let mut pass = 0u64;
        loop {
            if self.st().clients_done == self.cfg.clients {
                return;
            }
            self.sleep(workload.sweep_every).await;
            pass += 1;
            let (node, node_id) = {
                let st = self.st();
                (st.node.clone(), st.node_id)
            };
            let Some(node) = node else {
                continue;
            };
            let options = SweepOptions {
                immediate: workload.immediate,
                ..SweepOptions::default()
            };
            // A task of the node, as an operator's `kronik blobs gc`: a crash
            // in the middle of the pass ends it with the node.
            let (tx, rx) = tokio::sync::oneshot::channel();
            let gc_node = node.clone();
            drop(node);
            // The check runs in the node's task too: what holds the node
            // ends with it.
            let world = self.clone();
            self.exec.spawn(
                node_id,
                "blob-gc",
                Box::pin(async move {
                    let result = gc_node.blob_gc(options).await;
                    if matches!(result, Ok(Some(_))) {
                        world.check_blob_refs(&gc_node, "a pass").await;
                    }
                    let _ = tx.send(result);
                }),
            );
            let Some(Ok(result)) = self.clock_timeout(Duration::from_secs(60), rx).await else {
                self.event(format!("pass {pass}: ended with its node"));
                continue;
            };
            match result {
                Ok(Some(gc)) => {
                    self.event(format!(
                        "pass {pass}: deleted {} of {} files, {} candidates",
                        gc.report.deleted,
                        gc.report.objects + gc.report.deleted,
                        gc.report.candidates
                    ));
                    self.st().blobs.sweeps += 1;
                }
                Ok(None) => self.violation("blob_gc: no blob store"),
                Err(e) => self.event(format!("pass {pass}: {}", e.code)),
            }
        }
    }

    /// The disk drops below the reserve for 100 ms to 2 s: turns that write
    /// blobs wait for room and run again.
    async fn full_window(&self) {
        let d = self
            .work
            .duration(Duration::from_millis(100), Duration::from_secs(2));
        self.event(format!("the disk is full for {d:?}"));
        self.disk.lock().unwrap_or_else(|e| e.into_inner()).free = Some(RESERVE / 2);
        self.st().blobs.full += 1;
        self.sleep(d).await;
        self.disk.lock().unwrap_or_else(|e| e.into_inner()).free = None;
        self.event("the disk has room again");
    }

    /// B1/B2: every blob a committed record references, and every blob a
    /// pin names, has its file and reads back with its digest.
    pub(super) async fn check_blob_refs(&self, node: &Node, when: &str) {
        // The pins first, then the log up to what is applied after them: a
        // pin is written with its record, which is then in what is read.
        let pinned: Vec<String> = match node
            .store()
            .db()
            .conn()
            .prepare("SELECT DISTINCT hash FROM blob_pins ORDER BY hash")
            .and_then(|mut st| {
                st.query_map([], |r| r.get::<_, String>(0))
                    .and_then(|rows| rows.collect())
            }) {
            Ok(pinned) => pinned,
            Err(e) => return self.violation(format!("{when}: reading the pins: {e}")),
        };
        let applied = node.applied_lsn();
        let mut referenced: BTreeMap<String, (pb::BlobRef, u64)> = BTreeMap::new();
        if let Err(e) = node
            .reader()
            .read(1, applied, |c| {
                for blob in kronik_proto::blobs::refs(&c.record) {
                    referenced
                        .entry(blob.hash.clone())
                        .or_insert_with(|| (blob.clone(), c.lsn));
                }
                Ok(())
            })
            .await
        {
            return self.violation(format!("{when}: reading the log: {e}"));
        }
        let erasures = erased_versions(node);
        for (hash, (blob, lsn)) in &referenced {
            // An erased subject's blob has no file (E1 checks that), and the
            // collector may have forgotten its row.
            if is_erased(&erasures, blob) {
                continue;
            }
            if let Err(e) = self.read_blob(Some(node), blob).await {
                self.violation(format!(
                    "{when}: the record at lsn {lsn} references {hash}, which is not whole: {e}"
                ));
            }
        }
        for hash in pinned {
            if !referenced.contains_key(&hash) {
                self.violation(format!(
                    "{when}: a pin names {hash}, which no record references"
                ));
            }
        }
    }

    /// The end of the run (B6): after two passes, every blob file is one a
    /// record references, no part file is left, and every body the service
    /// received is the blob the guest wrote.
    pub(super) async fn check_blobs_end(&self, node: &Node) {
        if self.blobs().is_none() {
            return;
        }
        self.check_blob_refs(node, "the end").await;
        for _ in 0..2 {
            if let Err(e) = node.blob_gc(SweepOptions::default()).await {
                return self.violation(format!("the last passes: {}", e.code));
            }
        }
        self.check_erased_files(node, "the end").await;
        let mut referenced = BTreeSet::new();
        if let Err(e) = node
            .reader()
            .read(1, node.applied_lsn(), |c| {
                for blob in kronik_proto::blobs::refs(&c.record) {
                    referenced.insert(blob.hash.clone());
                }
                Ok(())
            })
            .await
        {
            return self.violation(format!("the end: reading the log: {e}"));
        }
        let blobs = PathBuf::from(DATA).join("blobs");
        let (objects, parts) = {
            let disk = self.disk.lock().unwrap_or_else(|e| e.into_inner());
            (
                disk.files_under(&blobs.join("objects")),
                disk.files_under(&blobs.join("tmp")),
            )
        };
        let mut left = 0;
        for path in &objects {
            let Some(id) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(kronik_blob::BlobId::from_file_name)
            else {
                continue;
            };
            if !referenced.contains(&id.to_string()) {
                left += 1;
                let size = self
                    .disk
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .durable_contents(path)
                    .map(|bytes| bytes.len());
                let leased = self
                    .st()
                    .blobs
                    .store
                    .as_ref()
                    .map(|store| store.leases().is_leased(&id));
                let row = node.store().db().blob(&id.to_string()).ok().flatten();
                let dry = node
                    .blob_gc(SweepOptions {
                        dry_run: true,
                        ..SweepOptions::default()
                    })
                    .await
                    .ok()
                    .flatten()
                    .map(|gc| {
                        gc.unrooted
                            .iter()
                            .find(|u| u.hash == id.to_string())
                            .map(|u| format!("{} candidate={}", u.reason.as_str(), u.candidate))
                    });
                self.violation(format!(
                    "the end: {id} has no root after two passes ({}, {size:?} durable \
                     bytes, leased {leased:?}, index row {row:?}, a dry run says {dry:?})",
                    path.display()
                ));
            }
        }
        if !parts.is_empty() {
            self.violation(format!("the end: part files left: {parts:?}"));
        }
        if let Some(service) = &self.service {
            for sink in service.sinks() {
                if sink.body != written(sink.body.len() as u64) {
                    self.violation(format!(
                        "the service got {} bytes for {} that are not the blob the guest wrote",
                        sink.body.len(),
                        sink.key
                    ));
                }
            }
        }
        let (sweeps, full) = {
            let st = self.st();
            (st.blobs.sweeps, st.blobs.full)
        };
        let crashed: Vec<String> = self
            .disk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .crashed_at
            .iter()
            .map(|p| format!("{:?}#{}", p.op, p.nth))
            .collect();
        let (erased, reads) = {
            let st = self.st();
            (st.blobs.erased.len(), st.blobs.erased_reads)
        };
        self.st().notes = format!(
            " blobs={} files={} unrooted={left} passes={sweeps} full={full} erased={erased} \
             erased-reads={}/{} crash-points={crashed:?}",
            referenced.len(),
            objects.len(),
            reads.1,
            reads.0,
        );
    }
}

/// The erased key versions by subject: a subject's blob keyed with one of
/// them, or an older one, is erased (M26 §9.3).
fn erased_versions(node: &Node) -> BTreeMap<String, u32> {
    let mut out: BTreeMap<String, u32> = BTreeMap::new();
    for (subject, version) in node.store().db().erasures().unwrap_or_default() {
        let max = out.entry(subject).or_default();
        *max = (*max).max(version);
    }
    out
}

fn is_erased(erasures: &BTreeMap<String, u32>, blob: &pb::BlobRef) -> bool {
    blob.subject
        .as_ref()
        .and_then(|subject| erasures.get(subject))
        .is_some_and(|version| blob.key_version <= *version)
}

/// One subject's blob keys, taken from the node's keystore before a read
/// ([`World::read_blob`]).
struct FixedKeys {
    subject: String,
    version: u32,
    seal: kronik_blob::KeyAnswer,
    identity: kronik_blob::KeyAnswer,
}

fn copy(answer: &kronik_blob::KeyAnswer) -> kronik_blob::KeyAnswer {
    use kronik_blob::KeyAnswer;
    match answer {
        KeyAnswer::Found(key) => KeyAnswer::Found(key.clone()),
        KeyAnswer::Erased => KeyAnswer::Erased,
        KeyAnswer::Missing => KeyAnswer::Missing,
        KeyAnswer::Unavailable(why) => KeyAnswer::Unavailable(why.clone()),
    }
}

impl kronik_blob::KeyAccess for FixedKeys {
    fn seal_key(&self, subject: &str, version: u32) -> kronik_blob::KeyAnswer {
        if subject == self.subject && version == self.version {
            copy(&self.seal)
        } else {
            kronik_blob::KeyAnswer::Missing
        }
    }

    fn identity_key(&self, subject: &str, version: u32) -> kronik_blob::KeyAnswer {
        if subject == self.subject && version == self.version {
            copy(&self.identity)
        } else {
            kronik_blob::KeyAnswer::Missing
        }
    }
}
