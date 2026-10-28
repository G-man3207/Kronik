//! Proposals (docs/design/m3-fork.md §8): propose new code, replay it over
//! the recent window, evaluate the policy; approve; promote with catch-up;
//! roll back a deployment.
//!
//! A proposal is a fork named `p-<12 hex>`. Its record and diff live in
//! `branches/<id>/` (`proposal.json`, `diff.json`) and are read back at
//! startup; the replay state needed for catch-up is kept in memory and
//! rebuilt by replaying again after a restart.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{CodeHash, Lsn, random_id};
use kronik_policy::RuleSet;
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::{CodeSwitch, Node};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::diff::{self, DiffOptions};
use crate::index::ProductionIndex;
use crate::replay::{self, Continuous, ForkKind, ReplaySetup, TreeResult};
use crate::{CodeEntry, fork_kinds, markdown, sample};

pub mod preview;

/// Catch-up converges when the newest root input is at most this far (in
/// logical time) ahead of the verified one (`[promote] max_gap`).
pub const MAX_GAP: Duration = Duration::from_secs(2);
/// Catch-up gives up after this long: `PROPOSAL_STALE`
/// (`[promote] catch_up_timeout`).
pub const CATCH_UP_TIMEOUT: Duration = Duration::from_secs(300);

/// An approval as the proposal remembers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Approved {
    pub lsn: Lsn,
    pub diff_hash: String,
    pub outcome: String,
    /// Targets with approximate or synthetic effects, or changed effects,
    /// when approved.
    pub targets: Vec<String>,
}

/// A promotion as the proposal remembers it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Promoted {
    pub epoch: u64,
    pub lsn: Lsn,
}

/// The persisted proposal (`branches/<id>/proposal.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub fork: String,
    /// `running` (the replay is under way, M10), `evaluated`, `approved`,
    /// `promoted`, `rejected`, `stale` or `failed` (the run ended with
    /// [`Proposal::error`]).
    pub status: String,
    pub fork_lsn: Lsn,
    pub created_lsn: Lsn,
    pub verified_through_lsn: Lsn,
    pub diff_hash: String,
    /// The policy evaluation (§7 JSON).
    pub policy: Value,
    /// The diff's summary (§5.1).
    pub summary: Value,
    pub options: DiffOptions,
    /// The proposed code, as `pb::KindVersion` (base64 protobuf).
    pub kinds: Vec<String>,
    pub reason: String,
    pub approved: Option<Approved>,
    pub promoted: Option<Promoted>,
    /// A plain fork (`kronik fork create`) rather than a proposal: no policy,
    /// never promoted.
    #[serde(default)]
    pub plain_fork: bool,
    /// Components of the request whose code main ran at the fork point and
    /// still runs: skipped, not part of the fork's code, and pinned at
    /// promote (M9). As `pb::KindVersion` (base64 protobuf), like `kinds`.
    #[serde(default)]
    pub unchanged: Vec<String>,
    /// Set when retention cut the window short (the diff's
    /// `base.window_cut`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_cut: Option<diff::WindowCut>,
    /// Why a `failed` proposal failed (M10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    /// Set on a preview fork (M11): a plain fork with status `preview`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<preview::Preview>,
}

/// The error for an operation that needs a finished proposal.
fn unfinished(meta: &Proposal) -> Option<ApiError> {
    match meta.status.as_str() {
        "running" => Some(
            ApiError::new(
                ErrorCode::ProposalRunning,
                format!("proposal {} is still running its replay", meta.id),
            )
            .with_hint(format!("kronik proposal wait {}", meta.id)),
        ),
        "failed" => Some(
            ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "proposal {} failed: {}",
                    meta.id,
                    meta.error.as_ref().map_or("", |e| e.message.as_str())
                ),
            )
            .with_hint("Propose again: kronik propose <wasm>... --reason \"...\""),
        ),
        _ => None,
    }
}

fn encode_kind(k: &pb::KindVersion) -> String {
    base64::engine::general_purpose::STANDARD.encode(k.encode_to_vec())
}

/// `b3:` and 12 hex characters of a code hash.
fn short(code_hash: &[u8]) -> String {
    CodeHash::from_slice(code_hash).map_or_else(|| "b3:?".to_owned(), |h| h.short())
}

impl Proposal {
    fn decode(&self, list: &[String]) -> Result<Vec<pb::KindVersion>, ApiError> {
        list.iter()
            .map(|k| {
                base64::engine::general_purpose::STANDARD
                    .decode(k)
                    .ok()
                    .and_then(|b| pb::KindVersion::decode(b.as_slice()).ok())
                    .ok_or_else(|| internal(format!("proposal {}: bad kind record", self.id)))
            })
            .collect()
    }

    pub fn kind_versions(&self) -> Result<Vec<pb::KindVersion>, ApiError> {
        self.decode(&self.kinds)
    }

    /// The skipped components ([`Proposal::unchanged`]).
    pub fn unchanged_versions(&self) -> Result<Vec<pb::KindVersion>, ApiError> {
        self.decode(&self.unchanged)
    }

    /// What the proposal's reader must know about how it was verified.
    pub fn warnings(&self) -> Vec<String> {
        self.window_cut
            .iter()
            .map(|c| {
                format!(
                    "retention cut the window: {} back from the newest root input reaches \
                     before lsn {}, the oldest point the log and snapshots still hold, so \
                     only the root inputs after it were replayed",
                    duration_text(c.window_ms),
                    c.kept_from_lsn
                )
            })
            .collect()
    }
}

/// `3600000` -> `1h`.
fn duration_text(ms: u64) -> String {
    crate::history_text(Duration::from_millis(ms))
}

/// What `propose` needs besides the code.
#[derive(Debug, Clone)]
pub struct ProposeRequest {
    pub wasm: Vec<Vec<u8>>,
    /// A name per component (the CLI's file names) for error messages;
    /// may be empty.
    pub names: Vec<String>,
    /// Logical time back from HEAD's newest root input (default 1 h).
    pub window_ms: Option<u64>,
    /// An explicit fork point instead of the window.
    pub at: Option<Lsn>,
    pub options: DiffOptions,
    /// Isolated replay workers (default: available cores, at most 16).
    pub workers: Option<usize>,
    pub audit: pb::Audit,
    pub dry_run: bool,
}

/// The replay state kept for catch-up.
struct Live {
    index: Arc<ProductionIndex>,
    kinds: BTreeMap<String, ForkKind>,
    before: Vec<CodeEntry>,
    after: Vec<CodeEntry>,
    trees: Vec<TreeResult>,
    continuous: Option<Continuous>,
    /// The fork's leading records (BranchCreated, Deployment).
    head: Vec<Record>,
    /// The last LSN written to the fork's log (0: nothing yet).
    logged_to: Lsn,
    /// Set when retention cut the proposal's window short.
    window_cut: Option<diff::WindowCut>,
    /// The fork log's LSN the saved diff covers (previews rebuild it on
    /// read).
    diffed_to: Lsn,
    /// Preview requests no longer held in memory (P-F3): the diff counts
    /// them on top of the ones it sees.
    preview_dropped: u64,
    /// Preview requests this state took (N1): capped at
    /// [`preview::MAX_PREVIEW_REQUESTS`], since each leaves rows in memory.
    preview_requests: u64,
    /// The erasure count this state was built at (N4): a preview drops it
    /// when an erasure happened since.
    erasure: u64,
}

struct Entry {
    meta: Proposal,
    live: Option<Live>,
}

/// Every proposal of the node.
pub struct Proposals {
    node: Arc<Node>,
    data: PathBuf,
    workers: usize,
    /// `[fork] live_allowlist`.
    live_allowlist: Vec<String>,
    max_gap: Duration,
    catch_up_timeout: Duration,
    /// `[fork] preview_ttl` (M11).
    preview_ttl: Duration,
    entries: tokio::sync::Mutex<BTreeMap<String, Entry>>,
    /// Erasures so far (N4): previews compare it with their state's.
    erasures: std::sync::atomic::AtomicU64,
    /// Requests a preview's state takes ([`preview::MAX_PREVIEW_REQUESTS`]).
    max_preview_requests: u64,
    /// Live previews' serving state (M11), outside `entries` (P-F4).
    previews: std::sync::Mutex<BTreeMap<String, Arc<preview::Served>>>,
    /// Proposals whose replay runs as a job (M10), by id.
    jobs: std::sync::Mutex<BTreeMap<String, Job>>,
    /// Test hook: each isolated root input of a job's replay takes a permit.
    gate: Option<Arc<tokio::sync::Semaphore>>,
}

/// A proposal's replay running on its own task: it outlives the request
/// that started it (M10, ADR 0022).
struct Job {
    progress: Arc<replay::Progress>,
}

/// What `propose` checked and chose before the replay.
struct Prepared {
    id: String,
    fork_lsn: Lsn,
    head: Lsn,
    kinds: Vec<pb::KindVersion>,
    unchanged: Vec<pb::KindVersion>,
    options: DiffOptions,
    workers: usize,
    reason: String,
    window_cut: Option<diff::WindowCut>,
}

/// How far a running proposal's replay has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JobProgress {
    pub isolated_done: u64,
    pub isolated_total: u64,
    pub continuous_done: u64,
    pub continuous_total: u64,
}

fn internal(m: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, m.to_string())
}

/// A replay's error: a sealed value without its key has its own code.
fn replay_error(e: replay::ReplayError) -> ApiError {
    match e {
        replay::ReplayError::KeyMissing(run) => {
            ApiError::new(ErrorCode::KeystoreIncomplete, run.to_string()).with_hint(
                "The node's privacy keystore lacks a subject's key; `kronik integrity` lists \
                 the subjects. Restore it from a keystore backup that holds the key.",
            )
        }
        e => internal(e),
    }
}

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn not_found(id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::ProposalNotFound,
        format!("no proposal {id:?}; run: kronik proposals list"),
    )
}

fn changed_targets(d: &diff::Diff) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = d
        .grounding
        .iter()
        .filter(|g| g.approximate + g.synthetic > 0)
        .map(|g| format!("{} {} {}{}", g.kind, g.method, g.host, g.route))
        .collect();
    out.extend(
        d.effects
            .items
            .iter()
            .map(|e| format!("{} {} {}{}", e.kind, e.method, e.host, e.route)),
    );
    out
}

fn outcome_rank(o: &str) -> u8 {
    match o {
        "allow" => 0,
        "require_approval" => 1,
        _ => 2,
    }
}

impl Proposals {
    /// Loads the proposals and forks recorded under `data/branches/*`.
    pub fn open(node: Arc<Node>, data: PathBuf) -> Result<Proposals, ApiError> {
        let mut entries = BTreeMap::new();
        let branches = data.join("branches");
        if let Ok(dir) = std::fs::read_dir(&branches) {
            for e in dir.flatten() {
                // Proposals and plain forks: every branch but main with a
                // proposal.json.
                let name = e.file_name().to_string_lossy().into_owned();
                if name == "main" {
                    continue;
                }
                let path = e.path().join("proposal.json");
                let Ok(bytes) = std::fs::read(&path) else {
                    // A preview whose creation stopped before its record
                    // was written (P-F7).
                    if name.starts_with(preview::ID_PREFIX)
                        && let Err(err) = std::fs::remove_dir_all(e.path())
                    {
                        tracing::warn!(preview = %name, error = %err, "deleting an unfinished preview");
                    }
                    continue;
                };
                let mut meta: Proposal = serde_json::from_slice(&bytes)
                    .map_err(|err| internal(format!("{}: {err}", path.display())))?;
                // A job does not survive the daemon: its proposal failed.
                if meta.status == "running" {
                    meta.status = "failed".into();
                    meta.error = Some(
                        ApiError::new(
                            ErrorCode::Unavailable,
                            "the daemon restarted while the proposal's replay was running",
                        )
                        .with_hint("Propose again: kronik propose <wasm>... --reason \"...\""),
                    );
                    let bytes = serde_json::to_vec_pretty(&meta).map_err(internal)?;
                    write_atomic(&path, &bytes)?;
                }
                entries.insert(meta.id.clone(), Entry { meta, live: None });
            }
        }
        let workers = std::thread::available_parallelism()
            .map_or(2, |n| n.get())
            .clamp(1, 16);
        let previews = entries
            .values()
            .filter(|e| e.meta.preview.is_some())
            .map(|e| {
                (
                    e.meta.id.clone(),
                    preview::Served::new(e.meta.clone(), None),
                )
            })
            .collect();
        Ok(Proposals {
            node,
            data,
            workers,
            live_allowlist: Vec::new(),
            max_gap: MAX_GAP,
            catch_up_timeout: CATCH_UP_TIMEOUT,
            preview_ttl: preview::PREVIEW_TTL,
            entries: tokio::sync::Mutex::new(entries),
            previews: std::sync::Mutex::new(previews),
            jobs: std::sync::Mutex::new(BTreeMap::new()),
            erasures: std::sync::atomic::AtomicU64::new(0),
            max_preview_requests: preview::MAX_PREVIEW_REQUESTS,
            gate: None,
        })
    }

    /// Test hook: each isolated root input of a proposal job's replay waits
    /// for a permit of `gate`, so a test can hold a job at a known point.
    #[doc(hidden)]
    pub fn with_test_gate(mut self, gate: Arc<tokio::sync::Semaphore>) -> Proposals {
        self.gate = Some(gate);
        self
    }

    /// `[fork] live_allowlist`: hosts whose unrecorded GETs (without
    /// secret headers) may go out live from forks; empty by default.
    pub fn with_live_allowlist(mut self, hosts: Vec<String>) -> Proposals {
        self.live_allowlist = hosts;
        self
    }

    /// `[promote] max_gap` and `catch_up_timeout`.
    pub fn with_promote(mut self, max_gap: Duration, catch_up_timeout: Duration) -> Proposals {
        self.max_gap = max_gap;
        self.catch_up_timeout = catch_up_timeout;
        self
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.data.join("branches").join(id)
    }

    fn save(&self, meta: &Proposal, diff: Option<&[u8]>) -> Result<(), ApiError> {
        let dir = self.dir(&meta.id);
        std::fs::create_dir_all(&dir).map_err(internal)?;
        if let Some(d) = diff {
            write_atomic(&dir.join("diff.json"), d)?;
        }
        let bytes = serde_json::to_vec_pretty(meta).map_err(internal)?;
        write_atomic(&dir.join("proposal.json"), &bytes)
    }

    /// Persists the isolated trees the diff names (samples, causes, changed
    /// responses, effects, errors) to `branches/<id>/isolated.jsonl`, so
    /// `kronik trace` finds `<fork>:r<root>.<n>` turns after a restart.
    fn save_samples(&self, id: &str, live: &Live, d: &diff::Diff) -> Result<(), ApiError> {
        let roots: BTreeSet<Lsn> = sample_ids(d)
            .iter()
            .filter_map(|t| isolated_id(t).map(|(fork, root, _)| (fork.to_owned(), root)))
            .filter(|(fork, _)| fork == id)
            .map(|(_, root)| root)
            .collect();
        let mut out = Vec::new();
        for tree in live.trees.iter().filter(|t| roots.contains(&t.root_lsn)) {
            for t in &tree.turns {
                // Sealed like production's log: the fork's turns hold the
                // values it revealed (m8-privacy §5).
                let mut record = Record::TurnRecord(shown_record(t));
                self.node.seal(&mut record)?;
                let line = serde_json::json!({
                    "id": t.id,
                    "root_lsn": tree.root_lsn,
                    "record": base64::engine::general_purpose::STANDARD.encode(match &record {
                        Record::TurnRecord(r) => r.encode_to_vec(),
                        _ => Vec::new(),
                    }),
                });
                out.extend(line.to_string().into_bytes());
                out.push(b'\n');
            }
        }
        write_atomic(&self.dir(id).join("isolated.jsonl"), &out)
    }

    /// A fork turn by id (`<fork>:<lsn>` from the fork's log,
    /// `<fork>:r<root>.<n>` from the persisted isolated trees) with every
    /// turn of its causal tree as (id, lsn, record); lsn is 0 for isolated
    /// turns.
    pub async fn fork_tree(&self, turn_id: &str) -> Result<Option<ForkTree>, ApiError> {
        let Some((fork, rest)) = turn_id.split_once(':') else {
            return Ok(None);
        };
        if self.get_any(fork).await.is_err() {
            return Ok(None);
        }
        if let Some((_, root, _)) = isolated_id(turn_id) {
            let path = self.dir(fork).join("isolated.jsonl");
            let Ok(text) = std::fs::read_to_string(path) else {
                return Ok(None);
            };
            let mut turns = Vec::new();
            for line in text.lines() {
                let v: Value = serde_json::from_str(line).map_err(internal)?;
                if v["root_lsn"].as_u64() != Some(root) {
                    continue;
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(v["record"].as_str().unwrap_or_default())
                    .map_err(internal)?;
                let record = pb::TurnRecord::decode(bytes.as_slice()).map_err(internal)?;
                turns.push((v["id"].as_str().unwrap_or_default().to_owned(), 0, record));
            }
            let Some(target) = turns
                .iter()
                .find(|(i, _, _)| i == turn_id)
                .map(|t| t.2.clone())
            else {
                return Ok(None);
            };
            return Ok(Some(ForkTree { target, turns }));
        }
        let Ok(lsn) = rest.parse::<Lsn>() else {
            return Ok(None);
        };
        let Some(target) = self.fork_turn(fork, lsn).await? else {
            return Ok(None);
        };
        let root = target
            .causal_key
            .as_ref()
            .map(|k| k.root.clone())
            .unwrap_or_default();
        let dir = self.dir(fork).join("log");
        let reader = kronik_log::LogReader::new(self.node.env().clone(), dir, fork);
        let mut turns = Vec::new();
        reader
            .read(1, Lsn::MAX, |c| {
                if let Record::TurnRecord(t) = c.record
                    && t.causal_key.as_ref().is_some_and(|k| k.root == root)
                {
                    turns.push((format!("{fork}:{}", c.lsn), c.lsn, t));
                }
                Ok(())
            })
            .await
            .map_err(internal)?;
        Ok(Some(ForkTree { target, turns }))
    }

    /// The rules in force: the latest `Policy` record, else the defaults.
    pub fn rules(&self) -> Result<(RuleSet, Option<pb::Policy>), ApiError> {
        match self.node.store().db().policy().map_err(internal)? {
            Some((_, p)) => {
                let rules = RuleSet::parse_toml(&p.rules_toml)
                    .map_err(|e| internal(format!("the recorded policy no longer parses: {e}")))?;
                Ok((rules, Some(p)))
            }
            None => Ok((RuleSet::defaults(), None)),
        }
    }

    fn evaluate(&self, diff_bytes: &[u8]) -> Result<Value, ApiError> {
        let (rules, _) = self.rules()?;
        let v: Value = serde_json::from_slice(diff_bytes).map_err(internal)?;
        serde_json::to_value(rules.evaluate(&v)).map_err(internal)
    }

    /// Main's index over `(fork_lsn, to]`, read from the newest usable
    /// snapshot at or below `fork_lsn` (m6-storage §3); `BAD_REQUEST` when
    /// the window starts before what the log and snapshots still hold.
    async fn index(
        &self,
        fork_lsn: Lsn,
        to: Lsn,
        no_pii: bool,
    ) -> Result<ProductionIndex, ApiError> {
        let base = crate::pick_base(&self.data, self.node.branch(), fork_lsn, false)
            .map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let mut index = ProductionIndex::load_from(self.node.reader(), base, fork_lsn, to)
            .await
            .map_err(internal)?;
        index.reveal(&self.privacy(no_pii));
        Ok(index)
    }

    /// What a fork sees of production's user data (M8 §5, §9).
    fn privacy(&self, no_pii: bool) -> crate::privacy::ForkPrivacy {
        crate::privacy::ForkPrivacy {
            sealer: self.node.sealer().clone(),
            no_pii,
        }
    }

    /// The fork point for a window: right before the first root input whose
    /// logical time is within `window_ms` of the newest one. Also says when
    /// the window reaches back before what the log and snapshots still
    /// hold, so the fork starts later than asked.
    async fn fork_point(
        &self,
        head: Lsn,
        window_ms: u64,
    ) -> Result<(Lsn, Option<diff::WindowCut>), ApiError> {
        // Every root input the log (or its oldest usable snapshot) holds.
        let base = crate::pick_base(&self.data, self.node.branch(), head, true)
            .map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let from = base.as_ref().map_or(0, |b| b.lsn);
        // The logical time of the base: its snapshot's turn-time mark.
        let base_time = base.as_ref().and_then(|b| {
            kronik_sched::snapshots::list(&self.data, self.node.branch())
                .into_iter()
                .find(|(_, m)| m.lsn == b.lsn)
                .map(|(_, m)| m.logical_time_ms)
        });
        let index = ProductionIndex::load_from(self.node.reader(), base, from, head)
            .await
            .map_err(internal)?;
        let Some(newest) = index.roots.last() else {
            return Ok((head, None));
        };
        let start = newest.logical_time_ms.saturating_sub(window_ms);
        let fork_lsn = index
            .roots
            .iter()
            .find(|r| r.logical_time_ms >= start)
            .map_or(head, |r| r.start_lsn - 1);
        // Turns before the base, inside the window, cannot be replayed.
        let cut = base_time.filter(|t| *t >= start).map(|_| diff::WindowCut {
            window_ms,
            kept_from_lsn: from,
        });
        Ok((fork_lsn, cut))
    }

    /// Each kind's code hash on main at `lsn`, from the `Deployment` records
    /// (the code the fork runs for a kind outside its set).
    fn code_at(&self, lsn: Lsn) -> Result<BTreeMap<String, Vec<u8>>, ApiError> {
        let mut out = BTreeMap::new();
        for (at, d) in self.node.store().db().deployments().map_err(internal)? {
            if at <= lsn {
                for k in d.kinds {
                    out.insert(k.kind, k.code_hash);
                }
            }
        }
        Ok(out)
    }

    fn setup(
        &self,
        id: &str,
        index: Arc<ProductionIndex>,
        kinds: BTreeMap<String, ForkKind>,
        options: &DiffOptions,
        progress: Option<Arc<replay::Progress>>,
    ) -> Arc<ReplaySetup> {
        let config = crate::config_at_with(&index, index.fork_lsn, self.node.sql_bytes_per_actor());
        // A preview answers whoever has its URL: no production key computes
        // for it, so its HMACs and signatures are `no recording` (P-F10).
        let secrets = if id.starts_with(preview::ID_PREFIX) {
            None
        } else {
            self.node.secrets().cloned()
        };
        let mut setup = ReplaySetup::new(id.to_owned(), index, kinds, config, secrets);
        setup.stubs = options.stubs.clone();
        setup.privacy = self.privacy(options.no_pii);
        setup.live = (!options.live_allowlist.is_empty()).then(|| crate::LiveAccess {
            hosts: options.live_allowlist.clone(),
            env: self.node.env().clone(),
        });
        setup.progress = progress;
        Arc::new(setup)
    }

    /// Request options with the operator's live allowlist in force.
    fn with_allowlist(&self, options: &DiffOptions) -> DiffOptions {
        DiffOptions {
            live_allowlist: self.live_allowlist.clone(),
            ..options.clone()
        }
    }

    fn build(
        &self,
        id: &str,
        live: &Live,
        options: &DiffOptions,
    ) -> Result<(diff::Diff, Vec<u8>, String), ApiError> {
        let prod = match &live.continuous {
            Some(_) => Some(replay::production_store(&live.index).map_err(internal)?),
            None => None,
        };
        let turns = live
            .continuous
            .as_ref()
            .map(Continuous::turns)
            .unwrap_or_default();
        let view = match (&live.continuous, &prod) {
            (Some(c), Some(p)) => Some(diff::ContinuousView {
                turns: &turns,
                fork: &c.store,
                prod: p,
            }),
            _ => None,
        };
        let d = diff::build(diff::DiffInput {
            fork: id,
            proposal_id: Some(id),
            index: &live.index,
            before: live.before.clone(),
            after: live.after.clone(),
            options,
            isolated: options.mode.isolated().then_some(live.trees.as_slice()),
            continuous: view,
        })
        .map_err(internal)?;
        let mut d = d;
        d.base.window_cut = live.window_cut.clone();
        d.summary.preview_inputs += live.preview_dropped;
        let bytes = d.to_bytes();
        let hash = diff::diff_hash(&bytes);
        Ok((d, bytes, hash))
    }

    /// Replays `(fork_lsn, to]` for a proposal.
    #[allow(clippy::too_many_arguments)]
    async fn replay(
        &self,
        id: &str,
        fork_lsn: Lsn,
        to: Lsn,
        kinds: &[pb::KindVersion],
        options: &DiffOptions,
        workers: usize,
        progress: Option<Arc<replay::Progress>>,
    ) -> Result<Live, ApiError> {
        crate::ensure_fork_retained(&self.node, &self.data, fork_lsn).await?;
        let index = Arc::new(self.index(fork_lsn, to, options.no_pii).await?);
        let code = self.node.code().clone();
        let mut new = Vec::with_capacity(kinds.len());
        for v in kinds {
            let hash = CodeHash::from_slice(&v.code_hash)
                .ok_or_else(|| internal(format!("kind {:?}: bad code hash", v.kind)))?;
            let program = code.get(&hash).map_err(internal)?;
            new.push((
                v.kind.clone(),
                ForkKind {
                    hash,
                    program,
                    schema_version: v.schema_version,
                },
            ));
        }
        let fc = fork_kinds(
            &index,
            fork_lsn,
            |h| code.get(h).map_err(|e| e.to_string()),
            &new,
        )
        .map_err(internal)?;
        let setup = self.setup(id, index.clone(), fc.kinds.clone(), options, progress);
        let head = [
            Record::BranchCreated(pb::BranchCreated {
                branch: id.to_owned(),
                parent_branch: "main".into(),
                fork_lsn,
                no_pii: options.no_pii,
                proposal_id: id.to_owned(),
                audit: None,
            }),
            Record::Deployment(pb::Deployment {
                epoch: setup.epoch + 1,
                kinds: kinds.to_vec(),
                cause: pb::DeploymentCause::Deploy as i32,
                proposal_id: id.to_owned(),
                ..Default::default()
            }),
        ];
        let (trees, continuous) =
            replay::both(self.node.env(), setup, options, workers, Some(id), &head)
                .await
                .map_err(replay_error)?;
        let trees = trees.unwrap_or_default();
        Ok(Live {
            index,
            kinds: fc.kinds,
            before: fc.before,
            after: fc.after,
            trees,
            continuous,
            head: head.to_vec(),
            logged_to: 0,
            window_cut: None,
            diffed_to: 0,
            preview_dropped: 0,
            preview_requests: 0,
            erasure: 0,
        })
    }

    /// Writes the fork's continuous history to `branches/<id>/log/`: its
    /// leading records at `fork_lsn + 1..`, then every turn not logged yet.
    /// A live state that has logged nothing replaces any older log.
    async fn write_log(&self, id: &str, live: &mut Live) -> Result<(), ApiError> {
        let Some(c) = &live.continuous else {
            return Ok(());
        };
        let dir = self.dir(id).join("log");
        let mut records = Vec::new();
        if live.logged_to == 0 {
            if dir.exists() {
                std::fs::remove_dir_all(&dir).map_err(internal)?;
            }
            records.extend(live.head.iter().cloned());
        }
        let turns = c.turns();
        records.extend(
            turns
                .iter()
                .filter(|t| t.lsn > live.logged_to)
                .map(|t| Record::TurnRecord(shown_record(t))),
        );
        // Sealed like production's log: the fork holds revealed values.
        for r in &mut records {
            self.node.seal(r)?;
        }
        if records.is_empty() {
            return Ok(());
        }
        let mut cfg = kronik_log::LogConfig::new(dir, id);
        cfg.group_commit_window = self.node.group_commit_window();
        cfg.first_lsn = live.index.fork_lsn + 1;
        let (committed, _) = tokio::sync::mpsc::unbounded_channel();
        let (fatal, _) = tokio::sync::oneshot::channel();
        let (log, opened) = kronik_log::Log::open(self.node.env(), cfg, committed, fatal)
            .await
            .map_err(internal)?;
        let expect = if live.logged_to == 0 {
            live.index.fork_lsn + 1
        } else {
            live.logged_to + 1
        };
        if opened.next_lsn != expect {
            return Err(internal(format!(
                "fork log of {id} continues at {} instead of {expect}",
                opened.next_lsn
            )));
        }
        if let Some(last) = log.append_all(records).await.map_err(internal)? {
            live.logged_to = last;
        }
        Ok(())
    }

    /// A turn of a fork's log (continuous replay and messages into the
    /// fork), for `GET /v1/turns/<fork>:<lsn>`.
    pub async fn fork_turn(
        &self,
        fork: &str,
        lsn: Lsn,
    ) -> Result<Option<pb::TurnRecord>, ApiError> {
        self.get_any(fork).await?;
        let dir = self.dir(fork).join("log");
        if !dir.exists() {
            return Ok(None);
        }
        let reader = kronik_log::LogReader::new(self.node.env().clone(), dir, fork);
        let mut out = None;
        reader
            .read(lsn, lsn, |c| {
                if let Record::TurnRecord(t) = c.record {
                    out = Some(t);
                }
                Ok(())
            })
            .await
            .map_err(internal)?;
        Ok(out)
    }

    /// `kronik propose` that returns the finished proposal: the job of
    /// [`Proposals::propose_job`], waited for.
    pub async fn propose(
        self: &Arc<Self>,
        req: ProposeRequest,
    ) -> Result<(Proposal, bool), ApiError> {
        self.propose_job(req, true).await
    }

    /// `kronik propose` as a job (M10, ADR 0022): the checks run now, the
    /// replay on a task of its own that outlives the caller. With `wait`,
    /// returns when the job is done (the finished proposal, or its error);
    /// without, at once with the `running` proposal. A dry run keeps
    /// nothing, so it always waits.
    pub async fn propose_job(
        self: &Arc<Self>,
        req: ProposeRequest,
        wait: bool,
    ) -> Result<(Proposal, bool), ApiError> {
        let dry_run = req.dry_run;
        let p = self.prepare(req).await?;
        if dry_run {
            let this = self.clone();
            let meta = self
                .node
                .env()
                .spawn("propose-dry-run", async move {
                    this.execute(&p, None, true).await
                })
                .await
                .ok_or_else(|| internal("the dry run was dropped"))??;
            return Ok((meta, true));
        }
        let running = Proposal {
            id: p.id.clone(),
            fork: p.id.clone(),
            status: "running".into(),
            fork_lsn: p.fork_lsn,
            created_lsn: p.head,
            verified_through_lsn: p.fork_lsn,
            diff_hash: String::new(),
            policy: Value::Null,
            summary: Value::Null,
            options: p.options.clone(),
            kinds: p.kinds.iter().map(encode_kind).collect(),
            reason: p.reason.clone(),
            approved: None,
            promoted: None,
            plain_fork: false,
            unchanged: p.unchanged.iter().map(encode_kind).collect(),
            window_cut: p.window_cut.clone(),
            error: None,
            preview: None,
        };
        // Save, insert and spawn under the entries lock with no await in
        // between: a caller dropped while queued on the lock leaves nothing.
        let mut entries = self.entries.lock().await;
        self.save(&running, None)?;
        entries.insert(
            p.id.clone(),
            Entry {
                meta: running.clone(),
                live: None,
            },
        );
        let progress = Arc::new(replay::Progress {
            gate: self.gate.clone(),
            ..Default::default()
        });
        let done = Arc::new(tokio::sync::Semaphore::new(0));
        lock(&self.jobs).insert(
            p.id.clone(),
            Job {
                progress: progress.clone(),
            },
        );
        let this = self.clone();
        let id = p.id.clone();
        let finished = done.clone();
        // The handle is dropped: the job runs to its end whoever waits.
        drop(self.node.env().spawn("propose-job", async move {
            let job = this.clone();
            let id = p.id.clone();
            // An inner task, so a panic in the replay fails the proposal
            // instead of leaving it `running` and its waiters waiting.
            let result = this
                .node
                .env()
                .spawn("propose-replay", async move {
                    job.execute(&p, Some(progress), false).await
                })
                .await
                .unwrap_or_else(|| {
                    Err(internal(
                        "the proposal's replay stopped unexpectedly; see the daemon log",
                    ))
                });
            if let Err(e) = result {
                tracing::warn!(proposal = %id, error = %e, "proposal failed");
                let mut entries = this.entries.lock().await;
                if let Some(entry) = entries.get_mut(&id) {
                    entry.meta.status = "failed".into();
                    entry.meta.error = Some(e);
                    if let Err(e) = this.save(&entry.meta, None) {
                        tracing::error!(proposal = %id, error = %e, "saving the failed proposal");
                    }
                }
            }
            lock(&this.jobs).remove(&id);
            finished.close();
        }));
        drop(entries);
        if !wait {
            return Ok((running, false));
        }
        let _ = done.acquire().await;
        let meta = self.get(&id).await?;
        match (meta.status.as_str(), &meta.error) {
            ("failed", Some(e)) => Err(e.clone()),
            _ => Ok((meta, false)),
        }
    }

    /// How far a running proposal's replay has come; `None` when it is not
    /// running.
    pub fn progress(&self, id: &str) -> Option<JobProgress> {
        use std::sync::atomic::Ordering::Relaxed;
        lock(&self.jobs).get(id).map(|j| JobProgress {
            isolated_done: j.progress.isolated_done.load(Relaxed),
            isolated_total: j.progress.isolated_total.load(Relaxed),
            continuous_done: j.progress.continuous_done.load(Relaxed),
            continuous_total: j.progress.continuous_total.load(Relaxed),
        })
    }

    /// The checks of `propose` and its choices: the fork point, the set,
    /// the proposal id.
    async fn prepare(&self, req: ProposeRequest) -> Result<Prepared, ApiError> {
        diff::check_options(&req.options).map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let options = self.with_allowlist(&req.options);
        if req.wasm.is_empty() {
            return Err(ApiError::new(ErrorCode::BadRequest, "no components given"));
        }
        let head = self.node.applied_lsn();
        let (fork_lsn, window_cut) = match req.at {
            Some(at) if at > head => {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!("at {at} is after HEAD ({head})"),
                ));
            }
            Some(at) => (at, None),
            None => {
                self.fork_point(head, req.window_ms.unwrap_or(3_600_000))
                    .await?
            }
        };
        crate::ensure_fork_retained(&self.node, &self.data, fork_lsn).await?;
        // One fork for every changed component. A component is skipped only
        // when main runs its code now and ran it at the fork point too (M9,
        // ADR 0012): the fork runs a kind outside the set with its code at
        // the fork point.
        let at_fork = self.code_at(fork_lsn)?;
        let mut kinds = Vec::with_capacity(req.wasm.len());
        let mut unchanged = Vec::new();
        let mut seen: Vec<(String, usize)> = Vec::new();
        for (i, bytes) in req.wasm.iter().enumerate() {
            let (hash, _, manifest) = self.node.prepare_code(bytes).await?;
            if let Some((_, first)) = seen.iter().find(|(k, _)| *k == manifest.kind) {
                let name = |n: usize| {
                    req.names
                        .get(n)
                        .map_or_else(|| format!("component {}", n + 1), |s| s.clone())
                };
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!(
                        "two components for kind {:?}: {} and {}",
                        manifest.kind,
                        name(*first),
                        name(i)
                    ),
                )
                .with_hint("Propose one component per actor kind; leave out the other build."));
            }
            seen.push((manifest.kind.clone(), i));
            let same = |code: Option<&[u8]>| code == Some(hash.0.as_slice());
            let version = pb::KindVersion {
                kind: manifest.kind.clone(),
                code_hash: hash.0.to_vec(),
                schema_version: manifest.schema_version,
                manifest: Some(manifest),
                code_size: bytes.len() as u64,
            };
            let running = self.node.deployed(&version.kind);
            if same(running.as_ref().map(|d| d.code_hash.as_slice()))
                && same(at_fork.get(&version.kind).map(Vec::as_slice))
            {
                unchanged.push(version);
            } else {
                kinds.push(version);
            }
        }
        if kinds.is_empty() {
            let names: Vec<String> = unchanged
                .iter()
                .map(|u| format!("{} {}", u.kind, short(&u.code_hash)))
                .collect();
            return Err(ApiError::new(
                ErrorCode::NothingToPropose,
                format!(
                    "nothing to propose: main already runs every component ({})",
                    names.join(", ")
                ),
            )
            .with_hint(
                "Change a component and build it again. To replay the running code, run: \
                 kronik fork create --reason \"...\" then kronik replay <fork> --reason \"...\"",
            ));
        }
        self.node.check_set_routes(&kinds)?;
        let id = format!("p-{}", &random_id(self.node.env())[..12]);
        let workers = req.workers.unwrap_or(self.workers).clamp(1, 64);
        Ok(Prepared {
            id,
            fork_lsn,
            head,
            kinds,
            unchanged,
            options,
            workers,
            reason: req.audit.reason,
            window_cut,
        })
    }

    /// Replays, builds the diff, evaluates the policy and (unless a dry
    /// run) keeps the proposal.
    async fn execute(
        &self,
        p: &Prepared,
        progress: Option<Arc<replay::Progress>>,
        dry_run: bool,
    ) -> Result<Proposal, ApiError> {
        let id = &p.id;
        let mut live = self
            .replay(
                id, p.fork_lsn, p.head, &p.kinds, &p.options, p.workers, progress,
            )
            .await?;
        live.window_cut = p.window_cut.clone();
        let (d, bytes, hash) = self.build(id, &live, &p.options)?;
        let policy = self.evaluate(&bytes)?;
        let denied = policy["outcome"] == "deny";
        let meta = Proposal {
            id: id.clone(),
            fork: id.clone(),
            status: if denied { "rejected" } else { "evaluated" }.into(),
            fork_lsn: p.fork_lsn,
            created_lsn: p.head,
            verified_through_lsn: d.summary.verified_through_lsn,
            diff_hash: hash,
            policy,
            summary: serde_json::to_value(&d.summary).map_err(internal)?,
            options: p.options.clone(),
            kinds: p.kinds.iter().map(encode_kind).collect(),
            reason: p.reason.clone(),
            approved: None,
            promoted: None,
            plain_fork: false,
            unchanged: p.unchanged.iter().map(encode_kind).collect(),
            window_cut: p.window_cut.clone(),
            error: None,
            preview: None,
        };
        if dry_run {
            return Ok(meta);
        }
        self.write_log(id, &mut live).await?;
        self.save(&meta, Some(&bytes))?;
        self.save_samples(id, &live, &d)?;
        self.entries.lock().await.insert(
            id.clone(),
            Entry {
                meta: meta.clone(),
                live: Some(live),
            },
        );
        Ok(meta)
    }

    pub async fn list(&self) -> Vec<Proposal> {
        self.entries
            .lock()
            .await
            .values()
            .map(|e| e.meta.clone())
            .collect()
    }

    pub async fn get(&self, id: &str) -> Result<Proposal, ApiError> {
        let mut entries = self.entries.lock().await;
        match entries.get_mut(id) {
            Some(e) if !e.meta.plain_fork => {
                self.reconcile(&mut e.meta)?;
                Ok(e.meta.clone())
            }
            _ => Err(not_found(id)),
        }
    }

    /// A promote or an approval whose caller went away after its record
    /// was committed (the switch and the approval record finish on their
    /// own) left the proposal's metadata behind: it is brought up to date
    /// from main's deployments and approvals, so a proposal is never
    /// promoted twice and its approval counts.
    fn reconcile(&self, meta: &mut Proposal) -> Result<(), ApiError> {
        if meta.plain_fork || meta.status == "promoted" {
            return Ok(());
        }
        let db = self.node.store().db();
        let promoted = db
            .deployments()
            .map_err(internal)?
            .into_iter()
            .find(|(_, d)| {
                d.proposal_id == meta.id && d.cause == pb::DeploymentCause::Promote as i32
            });
        let mut changed = false;
        if let Some((lsn, d)) = promoted {
            meta.status = "promoted".into();
            meta.promoted = Some(Promoted {
                epoch: d.epoch,
                lsn,
            });
            changed = true;
        } else if meta.approved.is_none()
            && let Ok(bytes) = std::fs::read(self.dir(&meta.id).join("diff.json"))
        {
            let hash = blake3::hash(&bytes).as_bytes().to_vec();
            let approval = db
                .approvals(&meta.id)
                .map_err(internal)?
                .into_iter()
                .rev()
                .find(|(_, a)| !a.request && a.diff_hash == hash);
            if let Some((lsn, _)) = approval {
                let d: Value = serde_json::from_slice(&bytes).map_err(internal)?;
                meta.approved = Some(Approved {
                    lsn,
                    diff_hash: meta.diff_hash.clone(),
                    outcome: meta.policy["outcome"].as_str().unwrap_or("deny").to_owned(),
                    targets: targets_of_value(&d),
                });
                if meta.status == "evaluated" {
                    meta.status = "approved".into();
                }
                changed = true;
            }
        }
        drop(db);
        if changed {
            self.save(meta, None)?;
        }
        Ok(())
    }

    /// A fork or a proposal by name.
    pub async fn get_any(&self, name: &str) -> Result<Proposal, ApiError> {
        self.entries
            .lock()
            .await
            .get(name)
            .map(|e| e.meta.clone())
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::ForkNotFound,
                    format!("no fork {name:?}; run: kronik fork list"),
                )
            })
    }

    /// The diff of a fork or proposal as JSON bytes, or rendered as
    /// Markdown; with `hide_credentials` (a caller without `pii:read`),
    /// through [`diff::Diff::redact_credentials`].
    pub async fn diff(
        &self,
        id: &str,
        markdown_format: bool,
        hide_credentials: bool,
    ) -> Result<Vec<u8>, ApiError> {
        let (meta, bytes) = self.diff_bytes(id).await?;
        if !markdown_format && !hide_credentials {
            return Ok(bytes);
        }
        let mut d: diff::Diff = serde_json::from_slice(&bytes).map_err(internal)?;
        if hide_credentials {
            d.redact_credentials();
        }
        if !markdown_format {
            return Ok(d.to_bytes());
        }
        let policy = (!meta.policy.is_null()).then_some(&meta.policy);
        Ok(markdown::render(&d, policy).into_bytes())
    }

    /// The short Markdown summary of a fork's or proposal's diff, without
    /// bodies, state values or URL paths ([`markdown::summary`], M10); hosts
    /// show as the current `http:` grant patterns that match them.
    pub async fn diff_summary(&self, id: &str) -> Result<Vec<u8>, ApiError> {
        let (meta, bytes) = self.diff_bytes(id).await?;
        let d: diff::Diff = serde_json::from_slice(&bytes).map_err(internal)?;
        let policy = (!meta.policy.is_null()).then_some(&meta.policy);
        let config = self.node.config_now();
        let grants: Vec<&str> = config
            .grants()
            .filter_map(|g| g.capability.strip_prefix("http:"))
            .collect();
        Ok(markdown::summary(&d, policy, &grants).into_bytes())
    }

    async fn diff_bytes(&self, id: &str) -> Result<(Proposal, Vec<u8>), ApiError> {
        self.refresh_preview_diff(id).await?;
        let meta = self.get_any(id).await?;
        if let Some(e) = unfinished(&meta) {
            return Err(e);
        }
        let path = self.dir(id).join("diff.json");
        if !path.exists() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("{id} has no diff yet; run: kronik replay {id}"),
            ));
        }
        let bytes = std::fs::read(path).map_err(internal)?;
        Ok((meta, bytes))
    }

    /// `kronik approve`: an `Approval` for the current diff.
    pub async fn approve(
        &self,
        id: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(Approved, Lsn), ApiError> {
        let mut entries = self.entries.lock().await;
        let entry = entries
            .get_mut(id)
            .filter(|e| !e.meta.plain_fork)
            .ok_or_else(|| not_found(id))?;
        let meta = &mut entry.meta;
        if let Some(e) = unfinished(meta) {
            return Err(e);
        }
        self.reconcile(meta)?;
        if meta.status == "promoted" {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("proposal {id} is already promoted"),
            ));
        }
        let bytes = std::fs::read(self.dir(id).join("diff.json")).map_err(internal)?;
        let d: Value = serde_json::from_slice(&bytes).map_err(internal)?;
        let targets = targets_of_value(&d);
        let hash_bytes = blake3::hash(&bytes).as_bytes().to_vec();
        let mut approved = Approved {
            lsn: 0,
            diff_hash: meta.diff_hash.clone(),
            outcome: meta.policy["outcome"].as_str().unwrap_or("deny").to_owned(),
            targets,
        };
        if dry_run {
            return Ok((approved, meta.verified_through_lsn));
        }
        let lsn = self
            .node
            .record_approval(pb::Approval {
                proposal_id: id.to_owned(),
                diff_hash: hash_bytes,
                verified_through_lsn: meta.verified_through_lsn,
                audit: Some(audit),
                request: false,
                command: String::new(),
            })
            .await?;
        approved.lsn = lsn;
        meta.approved = Some(approved.clone());
        if meta.status == "evaluated" {
            meta.status = "approved".into();
        }
        self.save(meta, None)?;
        Ok((approved, meta.verified_through_lsn))
    }

    /// `kronik promote`: catch-up, the policy again, then the switch.
    pub async fn promote(
        &self,
        id: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<PromoteResult, ApiError> {
        let mut entries = self.entries.lock().await;
        let entry = entries
            .get_mut(id)
            .filter(|e| !e.meta.plain_fork)
            .ok_or_else(|| not_found(id))?;
        if let Some(e) = unfinished(&entry.meta) {
            return Err(e);
        }
        self.reconcile(&mut entry.meta)?;
        if entry.meta.status == "promoted" {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("proposal {id} is already promoted"),
            ));
        }
        let fork_lsn = entry.meta.fork_lsn;
        if let Err(e) = crate::ensure_fork_retained(&self.node, &self.data, fork_lsn).await {
            if e.code != ErrorCode::BadRequest {
                return Err(e);
            }
            if !dry_run {
                entry.meta.status = "stale".into();
                self.save(&entry.meta, None)?;
            }
            let cutoff = self.node.retention_cutoff().ok().flatten();
            let message = match cutoff {
                Some(c) => {
                    format!("fork point {fork_lsn} is outside retention (cutoff logical time {c})")
                }
                None => format!("fork point {fork_lsn} is outside retention: {}", e.message),
            };
            return Err(ApiError::new(ErrorCode::ProposalStale, message)
                .with_hint("kronik propose <wasm> --window 1h --reason \"...\""));
        }
        let kinds = entry.meta.kind_versions()?;
        let options = entry.meta.options.clone();
        if entry.live.is_none() {
            let mut live = self
                .replay(
                    id,
                    entry.meta.fork_lsn,
                    entry.meta.verified_through_lsn,
                    &kinds,
                    &options,
                    self.workers,
                    None,
                )
                .await?;
            live.window_cut = entry.meta.window_cut.clone();
            entry.live = Some(live);
        }
        let Some(live) = entry.live.as_mut() else {
            return Err(internal("replay state missing"));
        };
        // Skipped kinds keep their code; changed kinds must still run the code
        // main ran when the proposal was made (`created_lsn`; an empty hash:
        // absent then), or another promote replaced it since and this one
        // would overwrite that change. Not the fork point: a window often
        // reaches back before a promote the proposal was made after. Not the
        // verified point either: catch-up moves it, outside the deploy lock,
        // past a promote that would then pass the check. A kind main already
        // runs the proposed code for is pinned to that.
        let mut pinned = entry.meta.unchanged_versions()?;
        let at_fork = live.index.kinds_at(entry.meta.created_lsn);
        pinned.extend(kinds.iter().map(|k| {
            if self
                .node
                .deployed(&k.kind)
                .is_some_and(|d| d.code_hash == k.code_hash)
            {
                return k.clone();
            }
            at_fork
                .get(&k.kind)
                .cloned()
                .unwrap_or_else(|| pb::KindVersion {
                    kind: k.kind.clone(),
                    ..Default::default()
                })
        }));
        // The same check as the switch's, once before catch-up: a stale
        // proposal fails before it replays (the switch's check, under the
        // deploy lock, stays authoritative).
        if let Err(e) = self.node.check_pins(&pinned) {
            if !dry_run {
                entry.meta.status = "stale".into();
                self.save(&entry.meta, None)?;
            }
            return Err(e);
        }
        // 1. Catch-up.
        let env = self.node.env().clone();
        let started = env.clock.monotonic();
        loop {
            let head = self.node.applied_lsn();
            if head > live.index.to_lsn {
                self.catch_up(id, live, head, &options).await?;
            }
            let now = self.node.applied_lsn();
            let pending = self.index(live.index.to_lsn, now, true).await?;
            let verified_time = live.index.roots.last().map_or(0, |r| r.logical_time_ms);
            let gap = pending
                .roots
                .last()
                .map_or(0, |r| r.logical_time_ms.saturating_sub(verified_time));
            if gap <= self.max_gap.as_millis() as u64 {
                break;
            }
            if env.clock.monotonic().saturating_sub(started) > self.catch_up_timeout {
                entry.meta.status = "stale".into();
                self.save(&entry.meta, None)?;
                return Err(ApiError::new(
                    ErrorCode::ProposalStale,
                    format!(
                        "catch-up did not converge within {:?}",
                        self.catch_up_timeout
                    ),
                ));
            }
        }
        self.write_log(id, live).await?;
        // 2. The policy on the whole diff.
        let (d, bytes, hash) = self.build(id, live, &options)?;
        let policy = self.evaluate(&bytes)?;
        let outcome = policy["outcome"].as_str().unwrap_or("deny").to_owned();
        let meta = &mut entry.meta;
        meta.verified_through_lsn = live.index.to_lsn;
        meta.diff_hash = hash.clone();
        meta.policy = policy.clone();
        meta.summary = serde_json::to_value(&d.summary).map_err(internal)?;
        if outcome == "deny" {
            if !dry_run {
                meta.status = "rejected".into();
                self.save(meta, Some(&bytes))?;
                self.save_samples(id, live, &d)?;
            }
            return Err(ApiError::new(
                ErrorCode::PolicyDenied,
                format!("the policy denies proposal {id}: {}", fired_names(&policy)),
            ));
        }
        if outcome == "require_approval" {
            let ok = meta.approved.as_ref().is_some_and(|a| {
                a.diff_hash == hash
                    || (outcome_rank(&outcome) <= outcome_rank(&a.outcome)
                        && changed_targets(&d).iter().all(|t| a.targets.contains(t)))
            });
            if !ok {
                if !dry_run {
                    self.save(meta, Some(&bytes))?;
                    self.save_samples(id, live, &d)?;
                }
                return Err(ApiError::new(
                    ErrorCode::ApprovalRequired,
                    format!(
                        "proposal {id} needs an approval for this diff ({}); run: kronik approve {id} --reason '...'",
                        fired_names(&policy)
                    ),
                ));
            }
        }
        // 3. The switch.
        let verified = live.index.to_lsn;
        let unverified = self
            .index(verified, self.node.applied_lsn(), true)
            .await?
            .roots
            .len() as u64;
        let switched = self
            .node
            .switch_code(
                CodeSwitch {
                    kinds: kinds.clone(),
                    pinned,
                    cause: pb::DeploymentCause::Promote,
                    verified_through_lsn: verified,
                    unverified_inputs: unverified,
                    proposal_id: id.to_owned(),
                    rollback_of_epoch: 0,
                },
                audit,
                dry_run,
            )
            .await;
        let (epoch, lsn) = match switched {
            Ok(s) => s,
            Err(e) => {
                if e.code == ErrorCode::ProposalStale && !dry_run {
                    meta.status = "stale".into();
                    self.save(meta, Some(&bytes))?;
                }
                return Err(e);
            }
        };
        if !dry_run {
            meta.status = "promoted".into();
            meta.promoted = Some(Promoted { epoch, lsn });
            self.save(meta, Some(&bytes))?;
            self.save_samples(id, live, &d)?;
            entry.live = None;
        }
        Ok(PromoteResult {
            epoch,
            lsn,
            verified_through_lsn: verified,
            unverified_inputs: unverified,
            kinds,
            policy,
        })
    }

    /// One catch-up round: replay the root inputs in `(to_lsn, head]`.
    async fn catch_up(
        &self,
        id: &str,
        live: &mut Live,
        head: Lsn,
        options: &DiffOptions,
    ) -> Result<(), ApiError> {
        let old_to = live.index.to_lsn;
        let mut index = ProductionIndex::load_from(
            self.node.reader(),
            live.index.base.clone(),
            live.index.fork_lsn,
            head,
        )
        .await
        .map_err(internal)?;
        index.reveal(&self.privacy(options.no_pii));
        let index = Arc::new(index);
        let setup = self.setup(id, index.clone(), live.kinds.clone(), options, None);
        if options.mode.isolated() {
            let fresh: Vec<_> = index
                .roots
                .iter()
                .filter(|r| r.lsn > old_to)
                .cloned()
                .collect();
            let roots = sample::sample(&fresh, id, options.sample);
            let trees = replay::isolated(self.node.env(), setup.clone(), roots, self.workers)
                .await
                .map_err(internal)?;
            live.trees.extend(trees);
        }
        if let Some(c) = live.continuous.as_mut() {
            c.extend(setup).await.map_err(internal)?;
        }
        live.index = index;
        Ok(())
    }

    /// `kronik fork create`: a fork at `fork_lsn` (at most HEAD) without
    /// code changes yet.
    pub async fn create_fork(
        &self,
        name: Option<String>,
        fork_lsn: Lsn,
        no_pii: bool,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(Proposal, bool), ApiError> {
        let head = self.node.applied_lsn();
        if fork_lsn > head {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("fork point {fork_lsn} is after HEAD ({head})"),
            ));
        }
        // Before a name is allocated or a directory is written, including
        // dry-run: a point outside the window must write nothing.
        crate::ensure_fork_retained(&self.node, &self.data, fork_lsn).await?;
        let name = match name {
            Some(n) => {
                let ok = n.len() <= 63
                    && n.starts_with(|c: char| c.is_ascii_lowercase())
                    && n.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !n.starts_with("p-")
                    && !n.starts_with(preview::ID_PREFIX)
                    && n != "main";
                if !ok {
                    return Err(ApiError::new(
                        ErrorCode::BadRequest,
                        format!(
                            "{n:?} is not a valid fork name ([a-z][a-z0-9-]*, not main, p-... or v-...)"
                        ),
                    ));
                }
                n
            }
            None => format!("f-{}", &random_id(self.node.env())[..12]),
        };
        let mut entries = self.entries.lock().await;
        if entries.contains_key(&name) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("fork {name} exists"),
            ));
        }
        let meta = Proposal {
            id: name.clone(),
            fork: name.clone(),
            status: "fork".into(),
            fork_lsn,
            created_lsn: head,
            verified_through_lsn: fork_lsn,
            diff_hash: String::new(),
            policy: Value::Null,
            summary: Value::Null,
            options: DiffOptions {
                no_pii,
                ..DiffOptions::default()
            },
            kinds: Vec::new(),
            reason: audit.reason,
            approved: None,
            promoted: None,
            plain_fork: true,
            error: None,
            preview: None,
            unchanged: Vec::new(),
            window_cut: None,
        };
        if dry_run {
            return Ok((meta, true));
        }
        self.save(&meta, None)?;
        entries.insert(
            name,
            Entry {
                meta: meta.clone(),
                live: None,
            },
        );
        Ok((meta, false))
    }

    /// A plain fork that is not a preview (P-F9: a preview's code, options
    /// and log are its proposal's for its whole life).
    fn fork_entry<'a>(
        entries: &'a mut BTreeMap<String, Entry>,
        name: &str,
    ) -> Result<&'a mut Entry, ApiError> {
        let entry = entries
            .get_mut(name)
            .filter(|e| e.meta.plain_fork)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::ForkNotFound,
                    format!("no fork {name:?}; run: kronik fork list"),
                )
            })?;
        if entry.meta.preview.is_some() {
            return Err(preview::not_a_fork(name));
        }
        Ok(entry)
    }

    /// `kronik deploy --fork`: code for one kind in the fork (allowed over
    /// history: forks never touch main).
    pub async fn fork_deploy(
        &self,
        name: &str,
        wasm: &[u8],
        dry_run: bool,
    ) -> Result<pb::KindVersion, ApiError> {
        let (hash, _, manifest) = self.node.prepare_code(wasm).await?;
        let version = pb::KindVersion {
            kind: manifest.kind.clone(),
            code_hash: hash.0.to_vec(),
            schema_version: manifest.schema_version,
            manifest: Some(manifest),
            code_size: wasm.len() as u64,
        };
        let mut entries = self.entries.lock().await;
        let entry = Self::fork_entry(&mut entries, name)?;
        if dry_run {
            return Ok(version);
        }
        let mut kinds = entry.meta.kind_versions()?;
        kinds.retain(|k| k.kind != version.kind);
        kinds.push(version.clone());
        entry.meta.kinds = kinds
            .iter()
            .map(|k| base64::engine::general_purpose::STANDARD.encode(k.encode_to_vec()))
            .collect();
        entry.live = None;
        self.save(&entry.meta, None)?;
        Ok(version)
    }

    /// `kronik replay`: replays the fork's code over `(fork_lsn, to]`.
    pub async fn fork_replay(
        &self,
        name: &str,
        to: Option<Lsn>,
        options: DiffOptions,
        workers: Option<usize>,
    ) -> Result<Proposal, ApiError> {
        diff::check_options(&options).map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
        let mut options = self.with_allowlist(&options);
        let head = self.node.applied_lsn();
        let mut entries = self.entries.lock().await;
        let entry = Self::fork_entry(&mut entries, name)?;
        options.no_pii = entry.meta.options.no_pii;
        let to = to.unwrap_or(head);
        if to > head || to < entry.meta.fork_lsn {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("to_lsn must be within {}..={head}", entry.meta.fork_lsn),
            ));
        }
        let kinds = entry.meta.kind_versions()?;
        let workers = workers.unwrap_or(self.workers).clamp(1, 64);
        let mut live = self
            .replay(
                name,
                entry.meta.fork_lsn,
                to,
                &kinds,
                &options,
                workers,
                None,
            )
            .await?;
        self.write_log(name, &mut live).await?;
        let (d, bytes, hash) = self.build(name, &live, &options)?;
        entry.meta.verified_through_lsn = d.summary.verified_through_lsn;
        entry.meta.diff_hash = hash;
        entry.meta.summary = serde_json::to_value(&d.summary).map_err(internal)?;
        entry.meta.options = options;
        self.save(&entry.meta, Some(&bytes))?;
        self.save_samples(name, &live, &d)?;
        entry.live = Some(live);
        Ok(entry.meta.clone())
    }

    /// A message into an actor of a fork (MCP `send_to_fork`): run under
    /// the fork's code on its continuous store, with no live effects (I7).
    /// Starts the fork's continuous state at the fork point when it has none.
    pub async fn fork_send(
        &self,
        name: &str,
        actor: kronik_core::ids::ActorRef,
        msg: pb::Message,
    ) -> Result<crate::ForkTurn, ApiError> {
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(name).ok_or_else(|| {
            ApiError::new(
                ErrorCode::ForkNotFound,
                format!("no fork {name:?}; run: kronik fork list"),
            )
        })?;
        if let Some(e) = unfinished(&entry.meta) {
            return Err(e);
        }
        // Its state is the preview's, behind the preview's own lock.
        if entry.meta.preview.is_some() {
            return Err(preview::not_a_fork(name));
        }
        let env = self.node.env();
        let root = random_id(env);
        let time = env.clock.wall_ms();
        let live = self.continuous_for(name, entry, &actor.kind).await?;
        let Some(c) = live.continuous.as_mut() else {
            return Err(internal("fork state missing"));
        };
        let mut turn = c.send(actor, msg, root, time).await.map_err(internal)?;
        // The reply leaves the fork: no real SQL rows in it (M5).
        turn.record = shown_record(&turn);
        self.write_log(name, live).await?;
        Ok(turn)
    }

    /// The fork's live state with its continuous store, started at the fork
    /// point when it has none; `ACTOR_NOT_FOUND` when the fork has no code
    /// for `kind`.
    async fn continuous_for<'e>(
        &self,
        name: &str,
        entry: &'e mut Entry,
        kind: &str,
    ) -> Result<&'e mut Live, ApiError> {
        if entry.live.as_ref().is_none_or(|l| l.continuous.is_none()) {
            let kinds = entry.meta.kind_versions()?;
            let options = DiffOptions {
                mode: diff::Mode::Continuous,
                stubs: entry.meta.options.stubs.clone(),
                live_allowlist: self.live_allowlist.clone(),
                no_pii: entry.meta.options.no_pii,
                ..DiffOptions::default()
            };
            let fork_lsn = entry.meta.fork_lsn;
            let live = self
                .replay(name, fork_lsn, fork_lsn, &kinds, &options, 1, None)
                .await?;
            entry.live = Some(live);
        }
        let live = entry
            .live
            .as_mut()
            .ok_or_else(|| internal("fork state missing"))?;
        if !live.continuous.as_ref().is_some_and(|c| c.has_kind(kind)) {
            return Err(ApiError::new(
                ErrorCode::ActorNotFound,
                format!("kind {kind:?} is not deployed in fork {name}"),
            ));
        }
        Ok(live)
    }

    /// MCP `request_approval`: an `Approval` record with `request` set and
    /// the exact command for the human. Returns (lsn, command).
    pub async fn request_approval(
        &self,
        id: &str,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(Lsn, String, Proposal), ApiError> {
        let meta = self.get(id).await?;
        if let Some(e) = unfinished(&meta) {
            return Err(e);
        }
        if meta.status == "promoted" {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("proposal {id} is already promoted"),
            ));
        }
        let mut command = format!("kronik approve {id} --reason '...'");
        let masked = ["pii_masked", "pii_unverified"]
            .iter()
            .map(|k| meta.summary[*k].as_u64().unwrap_or(0))
            .sum::<u64>();
        if masked > 0 {
            // A shell comment: the command still runs as given.
            command.push_str(&format!(
                "  # {masked} pii-masked turns were not verified: re-run the proposal with a pii:read token first"
            ));
        }
        if dry_run {
            return Ok((0, command, meta));
        }
        let bytes = std::fs::read(self.dir(id).join("diff.json")).map_err(internal)?;
        let lsn = self
            .node
            .record_approval(pb::Approval {
                proposal_id: id.to_owned(),
                diff_hash: blake3::hash(&bytes).as_bytes().to_vec(),
                verified_through_lsn: meta.verified_through_lsn,
                audit: Some(audit),
                request: true,
                command: command.clone(),
            })
            .await?;
        Ok((lsn, command, meta))
    }

    /// The approval requests of a proposal, in log order.
    pub fn approval_requests(&self, id: &str) -> Result<Vec<ApprovalRequestRow>, ApiError> {
        let all = self.node.store().db().approvals(id).map_err(internal)?;
        let last_approval = all
            .iter()
            .filter(|(_, a)| !a.request)
            .map(|(l, _)| *l)
            .max()
            .unwrap_or(0);
        Ok(all
            .into_iter()
            .filter(|(_, a)| a.request)
            .map(|(lsn, a)| {
                let audit = a.audit.unwrap_or_default();
                ApprovalRequestRow {
                    lsn,
                    command: a.command,
                    token_id: audit.token_id,
                    reason: audit.reason,
                    pending: lsn > last_approval,
                }
            })
            .collect())
    }

    /// `kronik fork delete`.
    pub async fn delete_fork(&self, name: &str, dry_run: bool) -> Result<(), ApiError> {
        let mut entries = self.entries.lock().await;
        Self::fork_entry(&mut entries, name)?;
        if dry_run {
            return Ok(());
        }
        entries.remove(name);
        std::fs::remove_dir_all(self.dir(name)).map_err(internal)
    }

    /// `kronik rollback <epoch>`: the kinds in force before `epoch` again.
    pub async fn rollback(
        &self,
        epoch: u64,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn, Vec<pb::KindVersion>), ApiError> {
        self.switch_back(epoch, false, audit, dry_run).await
    }

    /// A watch's rollback of `epoch` (M11): pins the deployment's kinds at
    /// its code, which the switch checks under the deploy lock, so the
    /// rollback never undoes a later deployment of them: `PROPOSAL_STALE`
    /// then. The plan read outside the lock holds while the pins do.
    pub async fn rollback_watched(
        &self,
        epoch: u64,
        audit: pb::Audit,
    ) -> Result<(u64, Lsn, Vec<pb::KindVersion>), ApiError> {
        self.switch_back(epoch, true, audit, false).await
    }

    async fn switch_back(
        &self,
        epoch: u64,
        pin: bool,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(u64, Lsn, Vec<pb::KindVersion>), ApiError> {
        let (target, kinds) = self.plan_rollback(epoch)?;
        let (new_epoch, lsn) = self
            .node
            .switch_code(
                CodeSwitch {
                    kinds: kinds.clone(),
                    pinned: if pin { target } else { Vec::new() },
                    cause: pb::DeploymentCause::Rollback,
                    verified_through_lsn: 0,
                    unverified_inputs: 0,
                    proposal_id: String::new(),
                    rollback_of_epoch: epoch,
                },
                audit,
                dry_run,
            )
            .await?;
        Ok((new_epoch, lsn, kinds))
    }

    /// The kinds a rollback of `epoch` would deploy, from the deployments
    /// in the log; `ROLLBACK_SCHEMA_CHANGED` when one of them would move a
    /// schema version back.
    pub fn rollback_plan(&self, epoch: u64) -> Result<Vec<pb::KindVersion>, ApiError> {
        Ok(self.plan_rollback(epoch)?.1)
    }

    /// The deployment `epoch`'s kinds, and [`Proposals::rollback_plan`].
    fn plan_rollback(
        &self,
        epoch: u64,
    ) -> Result<(Vec<pb::KindVersion>, Vec<pb::KindVersion>), ApiError> {
        let deployments = self.node.store().db().deployments().map_err(internal)?;
        let Some((_, target)) = deployments.iter().find(|(_, d)| d.epoch == epoch) else {
            return Err(ApiError::new(
                ErrorCode::DeploymentNotFound,
                format!("no deployment with epoch {epoch}; run: kronik deployments list"),
            ));
        };
        let mut before: BTreeMap<String, pb::KindVersion> = BTreeMap::new();
        let mut now: BTreeMap<String, pb::KindVersion> = BTreeMap::new();
        for (_, d) in &deployments {
            for k in &d.kinds {
                if d.epoch < epoch {
                    before.insert(k.kind.clone(), k.clone());
                }
                now.insert(k.kind.clone(), k.clone());
            }
        }
        let mut kinds = Vec::new();
        for k in &target.kinds {
            let Some(prev) = before.get(&k.kind) else {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    format!(
                        "kind {:?} did not exist before epoch {epoch}; nothing to roll back to, \
                         so no kind of the deployment is rolled back",
                        k.kind
                    ),
                )
                .with_hint(
                    "A deployment cannot remove a kind. Propose the earlier components of the \
                     other kinds together: kronik propose <earlier components> --reason \"...\"",
                ));
            };
            let current = now.get(&k.kind).map_or(0, |c| c.schema_version);
            if prev.schema_version < current {
                return Err(ApiError::new(
                    ErrorCode::RollbackSchemaChanged,
                    format!(
                        "kind {:?} would go from schema version {current} back to {}",
                        k.kind, prev.schema_version
                    ),
                ));
            }
            kinds.push(prev.clone());
        }
        Ok((target.kinds.clone(), kinds))
    }
}

/// A request for approval (an `Approval` record with `request` set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequestRow {
    pub lsn: Lsn,
    pub command: String,
    pub token_id: String,
    pub reason: String,
    /// No approval followed it yet.
    pub pending: bool,
}

/// A fork turn and its causal tree, for `kronik trace`.
#[derive(Debug, Clone)]
pub struct ForkTree {
    pub target: pb::TurnRecord,
    /// (turn id, lsn or 0 for isolated turns, record), in run order.
    pub turns: Vec<(String, Lsn, pb::TurnRecord)>,
}

/// A fork turn's record as it leaves the fork's memory (files, replies):
/// concealed when it may hold real SQL rows (`--no-pii`, M5).
fn shown_record(t: &crate::ForkTurn) -> pb::TurnRecord {
    let mut r = t.record.clone();
    if t.sql {
        crate::privacy::conceal_turn(&mut r);
    }
    r
}

/// `<fork>:r<root>.<n>` -> (fork, root lsn, n).
pub fn isolated_id(id: &str) -> Option<(&str, Lsn, u64)> {
    let (fork, rest) = id.split_once(':')?;
    let (root, n) = rest.strip_prefix('r')?.split_once('.')?;
    Some((fork, root.parse().ok()?, n.parse().ok()?))
}

/// Every fork turn id the diff names.
fn sample_ids(d: &diff::Diff) -> BTreeSet<String> {
    let s = &d.samples;
    let mut ids: BTreeSet<String> = [
        &s.origins,
        &s.consequences,
        &s.responses_changed,
        &s.effects_changed,
        &s.errors_introduced,
        &s.synthetic,
        &s.pii_masked,
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect();
    for c in &d.causes {
        ids.extend(c.samples.iter().cloned());
    }
    ids.extend(d.responses.items.iter().filter_map(|r| r.turn_fork.clone()));
    ids.extend(d.effects.items.iter().filter_map(|e| e.turn_fork.clone()));
    ids.extend(d.errors.items.iter().filter_map(|e| e.turn_fork.clone()));
    ids
}

/// The result of a promotion.
#[derive(Debug, Clone)]
pub struct PromoteResult {
    pub epoch: u64,
    pub lsn: Lsn,
    pub verified_through_lsn: Lsn,
    pub unverified_inputs: u64,
    pub kinds: Vec<pb::KindVersion>,
    pub policy: Value,
}

fn fired_names(policy: &Value) -> String {
    let names: Vec<&str> = policy["fired"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f["name"].as_str())
        .collect();
    if names.is_empty() {
        "no rule fired".into()
    } else {
        format!("fired: {}", names.join(", "))
    }
}

fn targets_of_value(d: &Value) -> Vec<String> {
    let mut out = BTreeSet::new();
    for g in d["grounding"].as_array().into_iter().flatten() {
        if g["approximate"].as_u64().unwrap_or(0) + g["synthetic"].as_u64().unwrap_or(0) > 0 {
            out.insert(format!(
                "{} {} {}{}",
                g["kind"].as_str().unwrap_or(""),
                g["method"].as_str().unwrap_or(""),
                g["host"].as_str().unwrap_or(""),
                g["route"].as_str().unwrap_or("")
            ));
        }
    }
    for e in d["effects"]["items"].as_array().into_iter().flatten() {
        out.insert(format!(
            "{} {} {}{}",
            e["kind"].as_str().unwrap_or(""),
            e["method"].as_str().unwrap_or(""),
            e["host"].as_str().unwrap_or(""),
            e["route"].as_str().unwrap_or("")
        ));
    }
    out.into_iter().collect()
}

pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), ApiError> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(internal)?;
    f.write_all(bytes).map_err(internal)?;
    f.sync_all().map_err(internal)?;
    std::fs::rename(&tmp, path).map_err(internal)?;
    Ok(())
}
