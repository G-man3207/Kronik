//! The M3 endpoints: forks, replay, diffs, proposals, approval, promote,
//! rollback and policy (docs/design/m3-fork.md §9).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_fork::diff::{DiffOptions, Mode};
use kronik_fork::proposal::{Proposal, Proposals, ProposeRequest as Propose};
use kronik_fork::watch::{Watch, Watches};
use kronik_policy::{DEFAULT_RULES_TOML, RuleSet};
use kronik_proto::log::v1 as pb;
use prost::Message as _;

use crate::auth::{Caller, Scope};
use crate::types::*;
use crate::{Api, ApiRequest, ApiResponse, Query, Result, bad, internal, json, ok, reason};

/// Whether a fork is made without personal data: when asked, and always for
/// a caller without `pii:read` (brief: "Forks without PII").
fn no_pii(requested: bool, caller: &Caller) -> bool {
    requested || !caller.has(Scope::PiiRead)
}

fn mode(m: &str) -> Result<Mode> {
    match m {
        "isolated" => Ok(Mode::Isolated),
        "continuous" => Ok(Mode::Continuous),
        "both" => Ok(Mode::Both),
        other => Err(bad(format!(
            "mode must be isolated, continuous or both, not {other:?}"
        ))),
    }
}

fn diff_options(o: &ReplayOptions) -> Result<DiffOptions> {
    Ok(DiffOptions {
        mode: mode(&o.mode)?,
        sample: o.sample,
        ignore_headers: o.ignore_headers.clone(),
        ignore_json_paths: o.ignore_json_paths.clone(),
        fuel_threshold: 0.02,
        stubs: o.stubs.clone(),
        live_allowlist: Vec::new(),
        no_pii: o.no_pii,
        // Filled from the log when the diff is built (M12).
        simulators: Vec::new(),
        simulator_overrides: o.simulator_overrides.clone(),
        foreign: Vec::new(),
    })
}

fn kind_json(k: &pb::KindVersion) -> DeploymentKind {
    DeploymentKind {
        kind: k.kind.clone(),
        code_hash: kronik_core::ids::CodeHash::from_slice(&k.code_hash)
            .map_or_else(String::new, |h| h.short()),
        schema_version: k.schema_version,
    }
}

fn kinds_json(list: &[String]) -> Vec<DeploymentKind> {
    list.iter()
        .filter_map(|k| STANDARD.decode(k).ok())
        .filter_map(|b| pb::KindVersion::decode(b.as_slice()).ok())
        .map(|k| kind_json(&k))
        .collect()
}

fn proposal_info(p: &Proposal, props: &Proposals) -> ProposalInfo {
    ProposalInfo {
        approval_requests: Vec::new(),
        id: p.id.clone(),
        fork: p.fork.clone(),
        status: p.status.clone(),
        fork_lsn: p.fork_lsn,
        verified_through_lsn: p.verified_through_lsn,
        diff_hash: p.diff_hash.clone(),
        policy: p.policy.clone(),
        summary: p.summary.clone(),
        kinds: kinds_json(&p.kinds),
        unchanged: kinds_json(&p.unchanged),
        warnings: p.warnings(),
        progress: props.progress(&p.id).map(|g| ProposalProgress {
            isolated_done: g.isolated_done,
            isolated_total: g.isolated_total,
            continuous_done: g.continuous_done,
            continuous_total: g.continuous_total,
        }),
        error: p.error.as_ref().map(ApiError::to_json),
        rebase: p.rebase.as_ref().map(|r| RebaseView {
            rolled_back_epoch: r.rolled_back_epoch,
            base_lsn: r.base_lsn,
            irreversible_effects: r.irreversible_effects,
            switch_lsn: r.switch_lsn,
        }),
    }
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The API's view of a watch: the same JSON as `watches/<id>.json`.
fn watch_info(w: &Watch) -> Result<WatchInfo> {
    serde_json::to_value(w)
        .and_then(serde_json::from_value)
        .map_err(internal)
}

/// `2026-10-25T10:00:00Z`, with optional fraction and `±hh:mm` offset, as
/// Unix milliseconds.
pub(crate) fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !(b[10] == b'T' || b[10] == b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut ms = 0i64;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits: String = frac.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let padded = format!("{digits:0<3}");
        ms = padded[..3].parse().ok()?;
        rest = &frac[digits.len()..];
    }
    let offset_min = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (oh, om) = rest[1..].split_once(':')?;
            sign * (oh.parse::<i64>().ok()? * 60 + om.parse::<i64>().ok()?)
        }
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset_min * 60;
    u64::try_from(secs * 1000 + ms).ok()
}

impl Api {
    pub(crate) fn proposals(&self) -> Result<&std::sync::Arc<Proposals>> {
        self.proposals.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "forks and proposals are not available in this process",
            )
        })
    }

    pub(crate) async fn route_m3(
        &self,
        req: &ApiRequest,
        segs: &[&str],
        q: &Query,
        caller: &Caller,
    ) -> Option<Result<ApiResponse>> {
        // Forks and proposals write their own logs, databases and diffs, and
        // an approval request appends to the log: new work, refused below
        // `[log] disk_reserve` like production's. (Approve and promote are
        // what an operator needs in an incident and stay allowed.)
        let writes = matches!(
            (req.method.as_str(), segs),
            ("POST", ["v1", "forks"])
                | ("POST", ["v1", "forks", _, "deployments" | "replay"])
                | ("POST", ["v1", "forks", _, "actors", _, _, "messages"])
                | ("POST", ["v1", "proposals"])
                | ("POST", ["v1", "proposals", _, "request-approval"])
                // A rollback via replay replays a window and writes its own
                // log, diff and samples (M13).
                | ("POST", ["v1", "deployments", _, "rebase"])
        );
        if writes && let Err(e) = self.node.check_running() {
            return Some(Err(e));
        }
        Some(match (req.method.as_str(), segs) {
            ("POST", ["v1", "forks"]) => self.fork_create(req, caller).await,
            ("GET", ["v1", "forks"]) => self.forks().await,
            ("DELETE", ["v1", "forks", name]) => self.fork_delete(req, name).await,
            ("POST", ["v1", "forks", name, "deployments"]) => self.fork_deploy(req, name).await,
            ("POST", ["v1", "forks", name, "replay"]) => self.fork_replay(req, name).await,
            ("POST", ["v1", "forks", name, "actors", kind, key, "messages"]) => {
                self.fork_send(req, name, kind, key, caller).await
            }
            ("GET", ["v1", "turns", id, "trace"]) => self.trace(id, caller).await,
            ("POST", ["v1", "proposals", id, "request-approval"]) => {
                self.request_approval(req, id).await
            }
            ("GET", ["v1", "forks", name, "diff"]) => self.diff(name, q, caller).await,
            ("POST", ["v1", "proposals"]) => self.propose(req, caller).await,
            ("GET", ["v1", "proposals"]) => self.proposals_list().await,
            ("GET", ["v1", "proposals", id]) => self.proposal(id).await,
            ("GET", ["v1", "proposals", id, "diff"]) => self.proposal_diff(id, q, caller).await,
            ("POST", ["v1", "proposals", id, "approve"]) => self.approve(req, id).await,
            ("POST", ["v1", "proposals", id, "promote"]) => self.promote(req, id).await,
            ("POST", ["v1", "deployments", epoch, "rollback"]) => self.rollback(req, epoch).await,
            ("POST", ["v1", "deployments", epoch, "watch"]) => self.watch(req, epoch).await,
            ("GET", ["v1", "watches"]) => self.watches_list(),
            ("GET", ["v1", "watches", id]) => self.watch_get(id),
            ("POST", ["v1", "watches", id, "stop"]) => self.watch_stop(req, id).await,
            ("POST", ["v1", "deployments", epoch, "rebase"]) => {
                self.rebase(req, epoch, caller).await
            }
            ("GET", ["v1", "policy"]) => self.policy(),
            ("PUT", ["v1", "policy"]) => self.policy_set(req).await,
            ("POST", ["v1", "policy", "test"]) => self.policy_test(req, caller).await,
            _ => return None,
        })
    }

    async fn fork_point(&self, at: &ForkPoint) -> Result<u64> {
        let head = self.node.applied_lsn();
        match at {
            ForkPoint::Lsn(l) => Ok(*l),
            ForkPoint::Text(t) if t == "now" => Ok(head),
            ForkPoint::Text(t) => {
                let ms = parse_rfc3339(t).ok_or_else(|| {
                    bad(format!(
                        "at must be an LSN, \"now\" or an RFC 3339 time, not {t:?}"
                    ))
                })?;
                // The last LSN whose turn ran at or before that logical time.
                let mut last = 0;
                self.node
                    .reader()
                    .read(1, head, |c| {
                        if let kronik_proto::Record::TurnRecord(r) = &c.record
                            && r.logical_time_ms <= ms
                        {
                            last = c.lsn;
                        }
                        Ok(())
                    })
                    .await
                    .map_err(internal)?;
                Ok(last)
            }
        }
    }

    async fn fork_create(&self, req: &ApiRequest, caller: &Caller) -> Result<ApiResponse> {
        let r: ForkCreateRequest = json(&req.body)?;
        reason(&r.reason)?;
        let lsn = self.fork_point(&r.at).await?;
        // Until privacy mode (M8) nothing is sealed, so a no-PII fork sees
        // the same values; the flag is recorded.
        let (p, dry_run) = self
            .proposals()?
            .create_fork(
                r.name.clone(),
                lsn,
                no_pii(r.no_pii, caller),
                self.audit(req, r.reason.clone()),
                r.dry_run,
            )
            .await?;
        ok(&ForkCreateResponse {
            dry_run,
            fork: ForkInfo {
                name: p.id,
                fork_lsn: p.fork_lsn,
                no_pii: p.options.no_pii,
                proposal_id: None,
            },
        })
    }

    async fn forks(&self) -> Result<ApiResponse> {
        let head = self.node.applied_lsn();
        let forks = self
            .proposals()?
            .list()
            .await
            .into_iter()
            .map(|p| ForkEntry {
                name: p.fork.clone(),
                fork_lsn: p.fork_lsn,
                head_lsn: head,
                proposal_id: (!p.plain_fork).then(|| p.id.clone()),
                verified_through_lsn: p.verified_through_lsn,
            })
            .collect();
        ok(&ForksResponse { forks })
    }

    async fn fork_delete(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        self.proposals()?.delete_fork(name, r.dry_run).await?;
        ok(&ForkDeleteResponse {
            dry_run: r.dry_run,
            deleted: name.to_owned(),
        })
    }

    async fn fork_deploy(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: DeployRequest = json(&req.body)?;
        reason(&r.reason)?;
        let wasm = STANDARD
            .decode(r.wasm_base64.trim())
            .map_err(|e| bad(format!("wasm_base64 is not valid base64: {e}")))?;
        let k = self
            .proposals()?
            .fork_deploy(name, &wasm, r.dry_run)
            .await?;
        ok(&ForkDeployResponse {
            dry_run: r.dry_run,
            fork: name.to_owned(),
            deployment: kind_json(&k),
        })
    }

    async fn fork_replay(&self, req: &ApiRequest, name: &str) -> Result<ApiResponse> {
        let r: ReplayRequest = json(&req.body)?;
        reason(&r.reason)?;
        let options = diff_options(&r.options)?;
        let p = self
            .proposals()?
            .fork_replay(name, r.to_lsn, options, r.options.threads)
            .await?;
        ok(&ReplayResponse {
            fork: p.id,
            summary: p.summary,
            diff_hash: p.diff_hash,
        })
    }

    async fn diff(&self, name: &str, q: &Query, caller: &Caller) -> Result<ApiResponse> {
        let props = self.proposals()?;
        let hide_credentials = !caller.has(Scope::PiiRead);
        let (body, md) = match q.get("format") {
            None | Some("json") => (props.diff(name, false, hide_credentials).await?, false),
            Some("md") => (props.diff(name, true, hide_credentials).await?, true),
            Some("summary") => (props.diff_summary(name).await?, true),
            Some(other) => {
                return Err(bad(format!(
                    "format must be json, md or summary, not {other:?}"
                )));
            }
        };
        Ok(ApiResponse {
            status: 200,
            content_type: if md {
                "text/markdown; charset=utf-8"
            } else {
                "application/json"
            },
            body,
        })
    }

    async fn proposal_diff(&self, id: &str, q: &Query, caller: &Caller) -> Result<ApiResponse> {
        self.proposals()?.get(id).await?;
        self.diff(id, q, caller).await
    }

    async fn propose(&self, req: &ApiRequest, caller: &Caller) -> Result<ApiResponse> {
        let r: ProposeRequest = json(&req.body)?;
        reason(&r.reason)?;
        let mut options = diff_options(&r.options)?;
        options.no_pii = no_pii(options.no_pii, caller);
        let wasm = r
            .wasm_base64
            .iter()
            .map(|w| {
                STANDARD
                    .decode(w.trim())
                    .map_err(|e| bad(format!("wasm_base64 is not valid base64: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        if r.run_async && r.dry_run {
            return Err(bad(
                "async and dry_run do not go together: a dry run keeps nothing to follow",
            )
            .with_hint("Leave out --async for a dry run."));
        }
        let props = self.proposals()?;
        let (p, dry_run) = props
            .propose_job(
                Propose {
                    wasm,
                    names: r.names,
                    window_ms: r.window_ms,
                    at: r.at,
                    options,
                    workers: r.options.threads,
                    audit: self.audit(req, r.reason.clone()),
                    dry_run: r.dry_run,
                },
                !r.run_async,
            )
            .await?;
        ok(&ProposeResponse {
            dry_run,
            proposal: proposal_info(&p, props),
        })
    }

    async fn proposals_list(&self) -> Result<ApiResponse> {
        let props = self.proposals()?;
        let proposals = props
            .list()
            .await
            .iter()
            .filter(|p| !p.plain_fork)
            .map(|p| proposal_info(p, props))
            .collect();
        ok(&ProposalsResponse { proposals })
    }

    async fn proposal(&self, id: &str) -> Result<ApiResponse> {
        let props = self.proposals()?;
        let mut info = proposal_info(&props.get(id).await?, props);
        info.approval_requests = props
            .approval_requests(id)?
            .into_iter()
            .map(|r| ApprovalRequestInfo {
                lsn: r.lsn,
                command: r.command,
                token_id: r.token_id,
                reason: r.reason,
                pending: r.pending,
            })
            .collect();
        ok(&info)
    }

    async fn request_approval(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let (lsn, command, p) = self
            .proposals()?
            .request_approval(id, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&RequestApprovalResponse {
            dry_run: r.dry_run,
            request: ApprovalRequest {
                proposal_id: id.to_owned(),
                diff_hash: p.diff_hash,
                verified_through_lsn: p.verified_through_lsn,
                lsn,
                command,
            },
        })
    }

    /// H7: an ordinary fork holds production's values in plain, so only a
    /// caller with `pii:read` may send into it or read its turns; a
    /// `--no-pii` fork is open to every caller with the route's scope. An
    /// unknown fork passes: the route answers not found.
    async fn require_fork_pii(&self, fork: &str, caller: &Caller) -> Result<()> {
        if caller.has(Scope::PiiRead) {
            return Ok(());
        }
        match self.proposals()?.get_any(fork).await {
            Ok(p) if !p.options.no_pii => caller.require(Scope::PiiRead),
            _ => Ok(()),
        }
    }

    async fn fork_send(
        &self,
        req: &ApiRequest,
        name: &str,
        kind: &str,
        key: &str,
        caller: &Caller,
    ) -> Result<ApiResponse> {
        self.require_fork_pii(name, caller).await?;
        let actor = Self::actor_ref(kind, key)?;
        let r: SendRequest = json(&req.body)?;
        reason(&r.reason)?;
        if r.name.is_empty() {
            return Err(bad("the message needs a name"));
        }
        if r.dry_run {
            return Err(bad(
                "dry_run is not supported for fork messages (forks have no live effects)",
            ));
        }
        let body = r.body.to_bytes().map_err(bad)?;
        let msg = pb::Message {
            name: r.name,
            content_type: if r.content_type.is_empty() {
                "application/octet-stream".into()
            } else {
                r.content_type
            },
            body: Some(pb::Sealable {
                subject: r.subject,
                value: Some(pb::sealable::Value::Plain(body)),
            }),
            blobs: Vec::new(),
        };
        let t = self.proposals()?.fork_send(name, actor, msg).await?;
        let o = t.record.outcome.clone().unwrap_or_default();
        let tr = crate::turn_response(Some(kronik_sched::TurnResult {
            turn_id: kronik_core::ids::TurnId {
                branch: name.to_owned(),
                lsn: t.lsn,
            },
            outcome: o.clone(),
        }));
        self.ok_scrubbed(&ForkTurnResponse {
            fork: name.to_owned(),
            turn_id: t.id,
            outcome: crate::outcome(&o),
            reply: tr.reply,
            effects: crate::effect_summaries(&t.record),
        })
    }

    /// A fork turn (`<fork>:<lsn>` or `<fork>:r<root>.<n>`) as turn JSON,
    /// redacted for the caller like a production turn; an ordinary fork's
    /// turns need `pii:read` (H7).
    pub(crate) async fn fork_turn_json(
        &self,
        id: &str,
        caller: &Caller,
    ) -> Result<Option<ApiResponse>> {
        let Some(props) = &self.proposals else {
            return Ok(None);
        };
        let Some(branch) = id.split_once(':').map(|(b, _)| b) else {
            return Ok(None);
        };
        if branch == self.node.branch() {
            return Ok(None);
        }
        let not_found = || ApiError::new(ErrorCode::TurnNotFound, format!("no turn {id}"));
        let mut tree = props.fork_tree(id).await?.ok_or_else(not_found)?;
        self.require_fork_pii(branch, caller).await?;
        let pii = caller.has(Scope::PiiRead);
        let hide = !pii && crate::input_has_sealed(tree.target.input.as_ref());
        crate::redact::redact_turn(&mut tree.target, self.node.sealer(), pii);
        crate::redact_credentials(&mut tree.target, pii);
        let lsn = tree
            .turns
            .iter()
            .find(|(i, _, _)| i == id)
            .map_or(0, |t| t.1);
        let mut v = crate::turn_json(branch, lsn, &tree.target);
        if hide {
            crate::hide_http_identity(&mut v);
        }
        v["turn_id"] = serde_json::Value::String(id.to_owned());
        Ok(Some(self.ok_scrubbed(&v)?))
    }

    async fn trace(&self, id: &str, caller: &Caller) -> Result<ApiResponse> {
        use std::collections::BTreeMap;
        let pii = caller.has(Scope::PiiRead);
        let not_found = || ApiError::new(ErrorCode::TurnNotFound, format!("no turn {id}"));
        let branch = id.split_once(':').map_or("", |(b, _)| b).to_owned();
        // (turn id, lsn, record) of the target's causal tree.
        let (target, turns): (pb::TurnRecord, Vec<(String, u64, pb::TurnRecord)>) =
            if branch != self.node.branch() && self.proposals.is_some() {
                self.require_fork_pii(&branch, caller).await?;
                let tree = self
                    .proposals()?
                    .fork_tree(id)
                    .await?
                    .ok_or_else(not_found)?;
                (tree.target, tree.turns)
            } else {
                let lsn = self.turn_id(id)?;
                let c = match self.node.read_record(lsn).await? {
                    Some(c) => c,
                    None => return Err(self.missing_turn(id, lsn).await),
                };
                let kronik_proto::Record::TurnRecord(target) = c.record else {
                    return Err(not_found());
                };
                let root = target
                    .causal_key
                    .as_ref()
                    .map(|k| k.root.clone())
                    .ok_or_else(|| internal("turn without causal key"))?;
                let refs = self.node.store().db().tree(&root).map_err(internal)?;
                let mut turns = Vec::with_capacity(refs.len());
                for r in refs {
                    if let Some(c) = self.node.read_record(r.lsn).await?
                        && let kronik_proto::Record::TurnRecord(t) = c.record
                    {
                        turns.push((format!("{branch}:{}", c.lsn), c.lsn, t));
                    }
                }
                (target, turns)
            };
        let (mut target, mut turns) = (target, turns);
        // Summaries show a sealed request's route pattern, not its path, to
        // a caller without pii:read (decided before redaction drops the
        // seal; also for records from before path became sealable).
        for t in std::iter::once(&mut target).chain(turns.iter_mut().map(|(_, _, t)| t)) {
            if !pii && crate::input_has_sealed(t.input.as_ref()) {
                crate::hide_request_line(t);
            }
            crate::redact::redact_turn(t, self.node.sealer(), pii);
        }
        let key = target
            .causal_key
            .clone()
            .ok_or_else(|| internal("turn without causal key"))?;
        let enc = |k: &pb::CausalKey| kronik_core::causal::encode(k);
        let parent = |k: &pb::CausalKey| {
            (!k.path.is_empty()).then(|| {
                enc(&pb::CausalKey {
                    root: k.root.clone(),
                    path: k.path[..k.path.len() - 1].to_vec(),
                })
            })
        };
        let mut by_key: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        let mut children: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        for (i, (_, _, t)) in turns.iter().enumerate() {
            let Some(k) = &t.causal_key else { continue };
            by_key.insert(enc(k), i);
            if let Some(p) = parent(k) {
                children.entry(p).or_default().push(i);
            }
        }
        let actor = |t: &pb::TurnRecord| {
            t.actor
                .as_ref()
                .map(|a| format!("{}/{}", a.kind, a.key))
                .unwrap_or_default()
        };
        let summary = |id: &str, lsn: u64, t: &pb::TurnRecord| {
            let mut s = crate::turn_summary(&branch, lsn, t, pii);
            s.turn_id = id.to_owned();
            s
        };
        let mut ancestors = Vec::new();
        let mut cur = parent(&key);
        while let Some(p) = cur {
            let Some(&i) = by_key.get(&p) else { break };
            let (tid, l, t) = &turns[i];
            ancestors.push(summary(tid, *l, t));
            cur = t.causal_key.as_ref().and_then(parent);
        }
        ancestors.reverse();
        let root = turns
            .iter()
            .find(|(_, _, t)| t.causal_key.as_ref().is_some_and(|k| k.path.is_empty()))
            .map(|(_, l, t)| TraceRoot {
                lsn: *l,
                root_id: key.root.clone(),
                input: crate::input_summary(t.input.as_ref(), pii),
            });
        const MAX: usize = 1000;
        let mut budget = MAX;
        let mut truncated = false;
        fn build(
            k: &[u8],
            turns: &[(String, u64, pb::TurnRecord)],
            children: &BTreeMap<Vec<u8>, Vec<usize>>,
            budget: &mut usize,
            truncated: &mut bool,
        ) -> Vec<TraceNode> {
            let mut out = Vec::new();
            for &i in children.get(k).map(Vec::as_slice).unwrap_or_default() {
                if *budget == 0 {
                    *truncated = true;
                    break;
                }
                *budget -= 1;
                let (tid, _, t) = &turns[i];
                let ck = t
                    .causal_key
                    .as_ref()
                    .map(kronik_core::causal::encode)
                    .unwrap_or_default();
                out.push(TraceNode {
                    turn_id: tid.clone(),
                    actor: t
                        .actor
                        .as_ref()
                        .map(|a| format!("{}/{}", a.kind, a.key))
                        .unwrap_or_default(),
                    // The turns were prepared for the caller above.
                    input: crate::input_summary(t.input.as_ref(), true),
                    outcome: crate::outcome(&t.outcome.clone().unwrap_or_default()),
                    children: build(&ck, turns, children, budget, truncated),
                });
            }
            out
        }
        let descendants = build(&enc(&key), &turns, &children, &mut budget, &mut truncated);
        let lsn = turns.iter().find(|(i, _, _)| i == id).map_or(0, |t| t.1);
        self.ok_scrubbed(&TraceResponse {
            turn: summary(id, lsn, &target),
            actor: actor(&target),
            root,
            ancestors,
            descendants,
            truncated,
        })
    }

    async fn approve(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let (a, verified) = self
            .proposals()?
            .approve(id, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&ApproveResponse {
            dry_run: r.dry_run,
            approval: ApprovalInfo {
                proposal_id: id.to_owned(),
                diff_hash: a.diff_hash,
                verified_through_lsn: verified,
                lsn: a.lsn,
            },
        })
    }

    async fn promote(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let p = self
            .proposals()?
            .promote(id, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&PromoteResponse {
            dry_run: r.dry_run,
            deployment: SwitchInfo {
                epoch: p.epoch,
                lsn: p.lsn,
                effective_lsn: 0,
                verified_through_lsn: p.verified_through_lsn,
                unverified_inputs: p.unverified_inputs,
                kinds: p.kinds.iter().map(kind_json).collect(),
            },
            policy: p.policy,
            rebase: p.rebase.map(|r| RebaseSwitchInfo {
                lsn: r.lsn,
                base_lsn: r.base_lsn,
                turns: r.turns,
                irreversible_effects: r.irreversible_effects,
            }),
        })
    }

    /// `kronik rollback <epoch> --by-replay` (M13): a rebase proposal.
    async fn rebase(&self, req: &ApiRequest, epoch: &str, caller: &Caller) -> Result<ApiResponse> {
        // A rebase runs on full data (its turns become main's state), so it
        // cannot be the --no-pii fork a token without pii:read gets: such a
        // token may not create one (ADR 0018).
        caller.require(Scope::PiiRead)?;
        let r: RebaseRequest = json(&req.body)?;
        reason(&r.reason)?;
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| bad(format!("{epoch:?} is not an epoch")))?;
        let options = DiffOptions {
            mode: mode(r.mode.as_deref().unwrap_or("continuous"))?,
            ..DiffOptions::default()
        };
        let props = self.proposals()?;
        let (p, dry_run) = props
            .rebase(kronik_fork::proposal::RebaseRequest {
                epoch,
                options,
                workers: r.threads,
                audit: self.audit(req, r.reason.clone()),
                dry_run: r.dry_run,
            })
            .await?;
        ok(&ProposeResponse {
            dry_run,
            proposal: proposal_info(&p, props),
        })
    }

    async fn rollback(&self, req: &ApiRequest, epoch: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| bad(format!("{epoch:?} is not an epoch")))?;
        let (new_epoch, lsn, kinds) = self
            .proposals()?
            .rollback(epoch, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&RollbackResponse {
            dry_run: r.dry_run,
            deployment: SwitchInfo {
                epoch: new_epoch,
                lsn,
                effective_lsn: 0,
                verified_through_lsn: 0,
                unverified_inputs: 0,
                kinds: kinds.iter().map(kind_json).collect(),
            },
        })
    }

    fn watches(&self) -> Result<&std::sync::Arc<Watches>> {
        self.watches.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "watches are not available in this process",
            )
        })
    }

    async fn watch(&self, req: &ApiRequest, epoch: &str) -> Result<ApiResponse> {
        let r: WatchRequest = json(&req.body)?;
        reason(&r.reason)?;
        let epoch: u64 = epoch
            .parse()
            .map_err(|_| bad(format!("{epoch:?} is not an epoch")))?;
        if r.run_async && r.dry_run {
            return Err(bad(
                "async and dry_run do not go together: a dry run keeps nothing to follow",
            )
            .with_hint("Leave out --async for a dry run."));
        }
        let w = self
            .watches()?
            .watch(
                epoch,
                r.for_ms,
                self.audit(req, r.reason.clone()),
                r.dry_run,
                !r.run_async,
            )
            .await?;
        ok(&WatchResponse {
            dry_run: r.dry_run,
            watch: watch_info(&w)?,
        })
    }

    fn watches_list(&self) -> Result<ApiResponse> {
        let watches = self
            .watches()?
            .list()
            .iter()
            .map(watch_info)
            .collect::<Result<_>>()?;
        ok(&WatchesResponse { watches })
    }

    fn watch_get(&self, id: &str) -> Result<ApiResponse> {
        ok(&watch_info(&self.watches()?.get(id)?)?)
    }

    async fn watch_stop(&self, req: &ApiRequest, id: &str) -> Result<ApiResponse> {
        let r: ResendRequest = json(&req.body)?;
        reason(&r.reason)?;
        let w = self
            .watches()?
            .stop(id, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&WatchResponse {
            dry_run: r.dry_run,
            watch: watch_info(&w)?,
        })
    }

    fn policy(&self) -> Result<ApiResponse> {
        let policy = self.node.store().db().policy().map_err(internal)?;
        let (rules_toml, epoch, default) = match policy {
            Some((_, p)) => (p.rules_toml, p.epoch, false),
            None => (DEFAULT_RULES_TOML.to_owned(), 0, true),
        };
        let rules = if default {
            RuleSet::defaults()
        } else {
            RuleSet::parse_toml(&rules_toml)
                .map_err(|e| internal(format!("the recorded policy no longer parses: {e}")))?
        };
        let guards = rules
            .effective_guards()
            .iter()
            .map(|g| PolicyGuard {
                name: g.name.clone(),
                when: g.when.clone(),
                action: g.action.as_str().to_owned(),
            })
            .collect();
        ok(&PolicyResponse {
            rules_toml,
            epoch,
            default,
            guards,
            default_guards: !rules.has_guard_key,
        })
    }

    async fn policy_set(&self, req: &ApiRequest) -> Result<ApiResponse> {
        let r: PolicySetRequest = json(&req.body)?;
        reason(&r.reason)?;
        RuleSet::parse_toml(&r.rules_toml).map_err(|e| bad(e.to_string()))?;
        let (epoch, lsn) = self
            .node
            .set_policy(&r.rules_toml, self.audit(req, r.reason.clone()), r.dry_run)
            .await?;
        ok(&PolicySetResponse {
            dry_run: r.dry_run,
            epoch,
            lsn,
        })
    }

    async fn policy_test(&self, req: &ApiRequest, caller: &Caller) -> Result<ApiResponse> {
        let r: PolicyTestRequest = json(&req.body)?;
        let rules = match &r.rules_toml {
            Some(t) => RuleSet::parse_toml(t).map_err(|e| bad(e.to_string()))?,
            None => self.proposals()?.rules()?.0,
        };
        // The diff the caller may read: rules of its own would otherwise
        // guess hidden credentials value by value.
        let hide_credentials = !caller.has(Scope::PiiRead);
        let bytes = self
            .proposals()?
            .diff(&r.proposal, false, hide_credentials)
            .await?;
        let diff: serde_json::Value = serde_json::from_slice(&bytes).map_err(internal)?;
        ok(&rules.evaluate(&diff))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339("2023-11-14T22:13:20Z"),
            Some(1_700_000_000_000)
        );
        assert_eq!(
            parse_rfc3339("2023-11-14T23:13:20.5+01:00"),
            Some(1_700_000_000_500)
        );
        assert_eq!(parse_rfc3339("2023-11-14 22:13:20Z"), None);
        assert_eq!(parse_rfc3339("yesterday"), None);
    }
}
