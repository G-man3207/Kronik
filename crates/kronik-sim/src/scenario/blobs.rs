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
use kronik_core::ids::ActorRef;
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
}

impl BlobMutation {
    pub fn parse(name: &str) -> Option<BlobMutation> {
        match name {
            "blob-skip-ensure-durable" => Some(BlobMutation::SkipEnsureDurable),
            "blob-sweep-ignores-leases" => Some(BlobMutation::SweepIgnoresLeases),
            "blob-sweep-ignores-touches" => Some(BlobMutation::SweepIgnoresTouches),
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
        BlobWorkload {
            threshold,
            sizes,
            fetched,
            sweep_every: Duration::from_millis(5 + r.below(200)),
            immediate: r.chance(0.5),
            full_windows: r.below(3) as u32,
            crash_points,
            slow_open: Duration::from_micros([0, 500, 3_000][r.below(3) as usize]),
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

    /// A failed turn the workload asked for: `fail-after-write`.
    pub(super) fn expected_blob_failure(&self, turn: &pb::TurnRecord) -> bool {
        self.blobs().is_some()
            && matches!(
                turn.input.as_ref().and_then(|i| i.kind.as_ref()),
                Some(pb::input::Kind::Http(h)) if h.path.ends_with("/fail-after-write")
            )
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

    /// Asks the node that runs now; waits for the answer while that node
    /// runs.
    async fn ask_media(&self, actor: &ActorRef, input: &pb::HttpInput) -> Attempt {
        let (node, node_id) = {
            let st = self.st();
            (st.node.clone(), st.node_id)
        };
        let Some(node) = node else {
            return Attempt::Again;
        };
        let waiter = match node.ingress(actor.clone(), input.clone(), None) {
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

    pub(super) async fn blob_client(self: Arc<Self>, client: usize) {
        for r in 0..self.cfg.requests_per_client {
            let actor = match ActorRef::parse(&format!(
                "{KIND}/k{}",
                self.work.below(self.cfg.actors as u64)
            )) {
                Ok(actor) => actor,
                Err(e) => return self.violation(format!("actor: {e}")),
            };
            let op = self.draw_op();
            let idem = format!("b{client}-{r}");
            let mut input = op.input(&actor);
            input.idempotency_key = idem.clone();
            input.request_hash = request_hash(&input);
            self.st().requests += 1;
            let mut attempt = 0u32;
            let result = loop {
                attempt += 1;
                if attempt > 2_000 {
                    return self.violation(format!("{idem} {op:?} never answered"));
                }
                match self.ask_media(&actor, &input).await {
                    Attempt::Answer(result) => break result,
                    Attempt::Again => {
                        let backoff = self
                            .work
                            .duration(Duration::from_millis(5), Duration::from_millis(60));
                        self.sleep(backoff).await;
                    }
                }
            };
            self.check_answer(&idem, &op, &result).await;
        }
        self.st().clients_done += 1;
    }

    /// The answer to a request is the one its operation must give, the same
    /// on every retry; a blob it names has its bytes (B5).
    async fn check_answer(&self, idem: &str, op: &Op, result: &TurnResult) {
        let text = match (op, answer_text(result)) {
            (Op::FailAfterWrite, Err(e)) if e.starts_with("TURN_FAILED") => e,
            (_, Ok(text)) => text,
            (_, Err(e)) => return self.violation(format!("{idem} {op:?}: {e}")),
        };
        self.event(format!("{idem} {op:?} -> {text}"));
        {
            let mut st = self.st();
            match st.blobs.answers.get(idem) {
                Some(first) if *first != text => {
                    let v = format!("{idem}: answered {text:?}, first {first:?}");
                    drop(st);
                    return self.violation(v);
                }
                Some(_) => {}
                None => {
                    st.blobs.answers.insert(idem.to_owned(), text.clone());
                }
            }
        }
        // A fetch the service failed or cut answers its error: nothing to
        // check of the bytes.
        let network = text.starts_with("network")
            || text.starts_with("timeout")
            || text.starts_with("outcome-unknown")
            || text.starts_with("too-large");
        let expected_blob = |size: u64| {
            let bytes = written(size);
            format!("blob {} {size}", plain_hash(&bytes))
        };
        let ok = match op {
            Op::Write { size, .. } => text == expected_blob(*size),
            Op::FetchWrite { size, .. } => network || text == expected_blob(*size),
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
        };
        if !ok {
            return self.violation(format!("{idem} {op:?}: unexpected answer {text}"));
        }
        if let Some(blob) = text.strip_prefix("blob ") {
            // Its bytes are in the store now (B1 for a blob just answered).
            let mut words = blob.split(' ');
            if let (Some(hash), Some(size)) = (words.next(), words.next())
                && let Ok(size) = size.parse()
            {
                let r = pb::BlobRef {
                    hash: hash.to_owned(),
                    size,
                    subject: None,
                    key_version: 0,
                };
                if let Err(e) = self.read_blob(&r).await {
                    self.violation(format!("{idem}: the blob it answered: {e}"));
                }
            }
        }
    }

    /// Reads and verifies a blob with the store of the node that runs now
    /// (or the last one).
    async fn read_blob(&self, blob: &pb::BlobRef) -> Result<(), String> {
        let store = self
            .st()
            .blobs
            .store
            .clone()
            .ok_or_else(|| "no blob store".to_string())?;
        let meta = BlobMeta::from_pb(blob).map_err(|e| format!("{}: {e}", blob.hash))?;
        let reader = store
            .reader(&Space::Main, &meta, &NoKeys)
            .await
            .map_err(|e| format!("{}: {e}", blob.hash))?;
        reader
            .verify(&NoKeys)
            .await
            .map_err(|e| format!("{} does not verify: {e}", blob.hash))
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
            self.exec.spawn(
                node_id,
                "blob-gc",
                Box::pin(async move {
                    let _ = tx.send(gc_node.blob_gc(options).await);
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
                    self.check_blob_refs(&node, "a pass").await;
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
        for (hash, (blob, lsn)) in &referenced {
            if let Err(e) = self.read_blob(blob).await {
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
        self.st().notes = format!(
            " blobs={} files={} unrooted={left} passes={sweeps} full={full} crash-points={crashed:?}",
            referenced.len(),
            objects.len(),
        );
    }
}
