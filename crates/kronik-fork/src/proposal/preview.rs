//! Preview forks (M11, docs/design/m11-preview.md, ADR 0025): a plain fork
//! of main's HEAD with a proposal's code that takes new requests from the
//! gateway (`<id>.<preview_domain>`, or `/__preview/<id>/...` without a
//! preview domain). Each request is a new root input of the fork's
//! continuous state, with the fork's effect host: no live effects but
//! `[fork] live_allowlist` GETs (I7). The fork expires after its time to
//! live and the daemon deletes it.
//!
//! A preview's serving state is a [`Served`], outside the proposals'
//! `entries` lock: a request waits only for requests to the same preview,
//! and route lookup waits for no lock held across an await (P-F4). Its
//! requests' turns leave memory once logged, but for the few the diff lists
//! (P-F3).

use std::sync::Arc;
use std::time::Duration;

use kronik_core::causal;
use kronik_core::env::BoxFuture;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, TurnId, random_id};
use kronik_proto::log::v1 as pb;
use kronik_sched::{RouteEntry, TurnResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    Entry, Live, Proposal, Proposals, encode_kind, internal, lock, shown_record, unfinished,
};
use crate::diff::{self, DiffOptions, MAX_SAMPLES, PREVIEW_ROOT};

/// How long a preview lives unless asked otherwise (`[fork] preview_ttl`).
pub const PREVIEW_TTL: Duration = Duration::from_secs(24 * 3600);

/// At most this many previews live at once (P-F3): each one holds a copy of
/// production's state in memory for its time to live.
/// shortcut: a constant, not a setting; make it `[fork] max_previews` when
/// an installation needs more.
pub const MAX_PREVIEWS: usize = 16;

/// A preview's state takes at most this many requests (N1): each leaves
/// rows in its in-memory store (turn index, trees, the guest's writes),
/// which only main compacts. The next one answers `PREVIEW_FULL`.
/// shortcut: a count, not a byte size; cap the store's size if guests
/// write large values per request.
pub const MAX_PREVIEW_REQUESTS: u64 = 10_000;

/// A preview's id starts with this; no other fork's may (`create_fork`).
pub(super) const ID_PREFIX: &str = "v-";

/// What makes a fork a preview (in its `proposal.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Preview {
    /// The proposal whose code it runs.
    pub proposal: String,
    /// Wall-clock Unix milliseconds after which it is gone.
    pub expires_ms: u64,
    /// The routes of its code: main's at the fork point, with the
    /// proposal's kinds' routes instead of theirs.
    pub routes: Vec<PreviewRoute>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreviewRoute {
    pub kind: String,
    pub method: String,
    pub pattern: String,
}

/// A preview's serving state (P-F4): its expiry and routes, read under no
/// lock held across an await, and its record and live state behind its own
/// lock. `meta.preview` is `None` once it is deleted, for a request that
/// was already waiting for that lock.
pub(super) struct Served {
    expires_ms: u64,
    routes: Vec<RouteEntry>,
    state: tokio::sync::Mutex<Entry>,
}

impl Served {
    pub(super) fn new(meta: Proposal, live: Option<Live>) -> Arc<Served> {
        let (expires_ms, routes) = meta.preview.as_ref().map_or((0, Vec::new()), |p| {
            let routes = p
                .routes
                .iter()
                .map(|r| RouteEntry {
                    kind: r.kind.clone(),
                    method: r.method.clone(),
                    pattern: r.pattern.clone(),
                })
                .collect();
            (p.expires_ms, routes)
        });
        Arc::new(Served {
            expires_ms,
            routes,
            state: tokio::sync::Mutex::new(Entry { meta, live }),
        })
    }
}

fn not_found(id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::PreviewNotFound,
        format!("no preview {id:?}, or it expired"),
    )
}

/// The error for a fork command on a preview (P-F9): its code, options and
/// log are its proposal's for its whole life.
pub(super) fn not_a_fork(id: &str) -> ApiError {
    ApiError::new(
        ErrorCode::BadRequest,
        format!("{id} is a preview: it runs its proposal's code at its URL until it expires"),
    )
    .with_hint(
        "Send it requests at its URL (kronik preview list) and delete it with kronik preview \
         delete <id>; to change code or replay, create a fork: kronik fork create --at now \
         --reason \"...\"",
    )
}

/// Keeps of a preview's root turn what the diff's preview samples read:
/// its causal key, HTTP method and route, outcome kind and status (P-F3).
fn slim(r: &mut pb::TurnRecord) {
    let (method, route) = match r.input.as_ref().and_then(|i| i.kind.as_ref()) {
        Some(pb::input::Kind::Http(h)) => (h.method.clone(), h.route.clone()),
        _ => (String::new(), String::new()),
    };
    let kind = r.outcome.as_ref().map_or(0, |o| o.kind);
    let status = match r.outcome.as_ref().and_then(|o| o.output.as_ref()) {
        Some(pb::outcome::Output::Http(h)) => Some(h.status),
        _ => None,
    };
    *r = pb::TurnRecord {
        causal_key: r.causal_key.take(),
        input: Some(pb::Input {
            kind: Some(pb::input::Kind::Http(pb::HttpInput {
                method,
                route,
                ..Default::default()
            })),
        }),
        outcome: Some(pb::Outcome {
            kind,
            output: status.map(|status| {
                pb::outcome::Output::Http(pb::HttpResponse {
                    status,
                    ..Default::default()
                })
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
}

/// Once logged, a preview's request turns leave memory (P-F3), but its
/// first [`MAX_SAMPLES`] root turns, slimmed, which the diff lists; the
/// others only count (`preview_dropped`).
fn forget_logged(live: &mut Live) {
    let Some(c) = &live.continuous else {
        return;
    };
    let (mut kept, mut dropped) = (0, 0);
    c.retain_turns(|t| {
        let Some(k) = t
            .record
            .causal_key
            .as_ref()
            .filter(|k| k.root.starts_with(PREVIEW_ROOT))
        else {
            return true;
        };
        if !k.path.is_empty() {
            return false;
        }
        if kept < MAX_SAMPLES {
            kept += 1;
            slim(&mut t.record);
            return true;
        }
        dropped += 1;
        false
    });
    live.preview_dropped += dropped;
}

impl Proposals {
    /// `[fork] preview_ttl`: how long a preview lives unless asked
    /// otherwise.
    pub fn with_preview_ttl(mut self, ttl: Duration) -> Proposals {
        self.preview_ttl = ttl;
        self
    }

    /// Test hook: a lower [`MAX_PREVIEW_REQUESTS`].
    #[doc(hidden)]
    pub fn with_max_preview_requests(mut self, n: u64) -> Proposals {
        self.max_preview_requests = n;
        self
    }

    fn erasures(&self) -> u64 {
        self.erasures.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drops a preview's state built before the last erasure (N4).
    fn drop_erased(&self, entry: &mut Entry) {
        let now = self.erasures();
        if entry.live.as_ref().is_some_and(|l| l.erasure != now) {
            entry.live = None;
        }
    }

    fn now(&self) -> u64 {
        self.node.env().clock.wall_ms()
    }

    /// A preview that has not expired.
    fn served(&self, id: &str) -> Result<Arc<Served>, ApiError> {
        let now = self.now();
        lock(&self.previews)
            .get(id)
            .filter(|s| s.expires_ms > now)
            .cloned()
            .ok_or_else(|| not_found(id))
    }

    /// `PREVIEW_LIMIT` when [`MAX_PREVIEWS`] previews have not expired.
    fn preview_room(&self) -> Result<(), ApiError> {
        let now = self.now();
        let live = lock(&self.previews)
            .values()
            .filter(|s| s.expires_ms > now)
            .count();
        if live < MAX_PREVIEWS {
            return Ok(());
        }
        Err(ApiError::new(
            ErrorCode::PreviewLimit,
            format!("{live} previews are live; a daemon keeps at most {MAX_PREVIEWS}"),
        ))
    }

    /// `kronik preview create`: a fork `v-<12 hex>` of main's HEAD running
    /// the proposal's code (its changed kinds and the ones it pins), with
    /// the proposal's stubs and `no_pii` (or `no_pii` when asked), that
    /// expires after `ttl` (default `[fork] preview_ttl`).
    pub async fn create_preview(
        &self,
        proposal: &str,
        ttl: Option<Duration>,
        no_pii: bool,
        audit: pb::Audit,
        dry_run: bool,
    ) -> Result<(Proposal, bool), ApiError> {
        let p = self.get(proposal).await?;
        if let Some(e) = unfinished(&p) {
            return Err(e);
        }
        let ttl = ttl.unwrap_or(self.preview_ttl);
        if ttl.is_zero() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "the time to live must be more than zero",
            ));
        }
        self.preview_room()?;
        let mut kinds = p.kind_versions()?;
        kinds.extend(p.unchanged_versions()?);
        let (_, mut routes) = self.node.routes();
        routes.retain(|r| !kinds.iter().any(|k| k.kind == r.kind));
        for k in &kinds {
            for r in k.manifest.iter().flat_map(|m| &m.routes) {
                routes.push(RouteEntry {
                    kind: k.kind.clone(),
                    method: r.method.clone(),
                    pattern: r.pattern.clone(),
                });
            }
        }
        let head = self.node.applied_lsn();
        let id = format!("{ID_PREFIX}{}", &random_id(self.node.env())[..12]);
        let options = DiffOptions {
            mode: diff::Mode::Continuous,
            stubs: p.options.stubs.clone(),
            simulator_overrides: p.options.simulator_overrides.clone(),
            live_allowlist: self.live_allowlist.clone(),
            no_pii: no_pii || p.options.no_pii,
            ..DiffOptions::default()
        };
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let meta = Proposal {
            id: id.clone(),
            fork: id.clone(),
            status: "preview".into(),
            fork_lsn: head,
            created_lsn: head,
            verified_through_lsn: head,
            diff_hash: String::new(),
            policy: Value::Null,
            summary: Value::Null,
            options,
            kinds: kinds.iter().map(encode_kind).collect(),
            reason: audit.reason,
            approved: None,
            promoted: None,
            plain_fork: true,
            unchanged: Vec::new(),
            window_cut: None,
            error: None,
            rebase: None,
            preview: Some(Preview {
                proposal: proposal.to_owned(),
                expires_ms: self.now().saturating_add(ttl_ms),
                routes: routes
                    .into_iter()
                    .map(|r| PreviewRoute {
                        kind: r.kind,
                        method: r.method,
                        pattern: r.pattern,
                    })
                    .collect(),
            }),
        };
        if dry_run {
            return Ok((meta, true));
        }
        // Read before the replay: an erasure from now on makes this state
        // stale, and its first request rebuilds it (N4).
        let erasure = self.erasures();
        let mut live = self
            .replay(
                &id,
                head,
                head,
                &kinds,
                &meta.options,
                1,
                None,
                false,
                false,
                // Copies would outlive the request that made them (M14).
                Some(super::copies::PREVIEW),
            )
            .await?;
        live.erasure = erasure;
        // Recorded and listed before its log is written, with no await in
        // between (P-F7): whatever stops this later leaves a preview that
        // answers and expires, never a directory nothing deletes.
        let served = {
            let mut entries = self.entries.lock().await;
            self.preview_room()?;
            self.save(&meta, None)?;
            entries.insert(
                id.clone(),
                Entry {
                    meta: meta.clone(),
                    live: None,
                },
            );
            let served = Served::new(meta, Some(live));
            lock(&self.previews).insert(id.clone(), served.clone());
            served
        };
        let mut state = served.state.lock().await;
        let Entry { meta, live } = &mut *state;
        if meta.preview.is_some()
            && let Some(live) = live.as_mut()
        {
            self.write_log(&id, live).await?;
            self.save_preview_diff(meta, live)?;
        }
        let meta = meta.clone();
        drop(state);
        if let Some(e) = self.entries.lock().await.get_mut(&id) {
            e.meta = meta.clone();
        }
        Ok((meta, false))
    }

    /// Builds the preview's diff and saves it with its record.
    fn save_preview_diff(&self, meta: &mut Proposal, live: &mut Live) -> Result<(), ApiError> {
        let (d, bytes, hash) = self.build(&meta.id, live, &meta.options)?;
        meta.verified_through_lsn = d.summary.verified_through_lsn;
        meta.diff_hash = hash;
        meta.summary = serde_json::to_value(&d.summary).map_err(internal)?;
        self.save(meta, Some(&bytes))?;
        live.diffed_to = live.logged_to;
        Ok(())
    }

    /// Rebuilds a preview's diff when requests arrived since it was built
    /// (on read, not per request: the diff loads production's state).
    pub(super) async fn refresh_preview_diff(&self, id: &str) -> Result<(), ApiError> {
        let served = lock(&self.previews).get(id).cloned();
        let Some(served) = served else {
            return Ok(());
        };
        let mut state = served.state.lock().await;
        self.drop_erased(&mut state);
        let Entry {
            meta,
            live: Some(live),
        } = &mut *state
        else {
            return Ok(());
        };
        if meta.preview.is_none() || live.diffed_to == live.logged_to {
            return Ok(());
        }
        self.save_preview_diff(meta, live)?;
        let meta = meta.clone();
        drop(state);
        if let Some(e) = self.entries.lock().await.get_mut(id) {
            e.meta = meta;
        }
        Ok(())
    }

    /// `kronik preview list`: the previews that have not expired.
    pub async fn previews(&self) -> Vec<Proposal> {
        let now = self.now();
        self.entries
            .lock()
            .await
            .values()
            .filter(|e| e.meta.preview.as_ref().is_some_and(|p| p.expires_ms > now))
            .map(|e| e.meta.clone())
            .collect()
    }

    /// `kronik preview delete`: the fork, its directory and its routes.
    pub async fn delete_preview(&self, id: &str, dry_run: bool) -> Result<Proposal, ApiError> {
        let served = self.served(id)?;
        // After the request in flight, if any.
        let mut state = served.state.lock().await;
        if state.meta.preview.is_none() {
            return Err(not_found(id));
        }
        let meta = state.meta.clone();
        if dry_run {
            return Ok(meta);
        }
        // Gone for every request, also one already waiting for the lock.
        state.meta.preview = None;
        state.live = None;
        lock(&self.previews).remove(id);
        drop(state);
        self.entries.lock().await.remove(id);
        std::fs::remove_dir_all(self.dir(id)).map_err(internal)?;
        Ok(meta)
    }

    /// Deletes every expired preview: entry and directory. Returns how
    /// many.
    pub async fn expire_previews(&self) -> usize {
        let now = self.now();
        let expired: Vec<(String, Arc<Served>)> = {
            let mut map = lock(&self.previews);
            let ids: Vec<String> = map
                .iter()
                .filter(|(_, s)| s.expires_ms <= now)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| map.remove(&id).map(|s| (id, s)))
                .collect()
        };
        for (id, served) in &expired {
            let mut state = served.state.lock().await;
            state.meta.preview = None;
            state.live = None;
            drop(state);
            self.entries.lock().await.remove(id);
            match std::fs::remove_dir_all(self.dir(id)) {
                Ok(()) => tracing::info!(preview = %id, "expired preview deleted"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(preview = %id, error = %e, "deleting an expired preview"),
            }
        }
        expired.len()
    }

    /// After an erasure (P-F11, N4): every preview's in-memory state, with
    /// the values it revealed, goes before its next use; the next request
    /// starts it again from its fork point, with what production still
    /// reveals. Waits for no preview: a running request finishes on the
    /// old state.
    pub fn forget_preview_states(&self) {
        self.erasures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Test hook: how many turns preview `id` holds in memory.
    #[doc(hidden)]
    pub async fn preview_turns_held(&self, id: &str) -> Option<usize> {
        let served = self.served(id).ok()?;
        let state = served.state.lock().await;
        state
            .live
            .as_ref()?
            .continuous
            .as_ref()
            .map(|c| c.turn_count())
    }

    /// One request into a preview: a new root input whose causal root
    /// starts with [`PREVIEW_ROOT`], on the fork's continuous state (started
    /// at its fork point when it has none, e.g. after a restart), written
    /// sealed to the fork's log.
    async fn preview_send(
        &self,
        id: &str,
        actor: ActorRef,
        http: pb::HttpInput,
        subject: Option<String>,
    ) -> Result<TurnResult, ApiError> {
        let served = self.served(id)?;
        let env = self.node.env();
        let key = causal::root(format!("{PREVIEW_ROOT}{}", random_id(env)));
        // shortcut: one request at a time per preview (its own lock); turns
        // in parallel on one fork's state if a preview takes real traffic.
        let mut entry = served.state.lock().await;
        // Deleted or expired while this request waited: its directory may
        // be gone already.
        let now = env.clock.wall_ms();
        if entry
            .meta
            .preview
            .as_ref()
            .is_none_or(|p| p.expires_ms <= now)
        {
            return Err(not_found(id));
        }
        // Read before a rebuild, as in create_preview.
        let erasure = self.erasures();
        self.drop_erased(&mut entry);
        let max = self.max_preview_requests;
        let live = self.continuous_for(id, &mut entry, &actor.kind).await?;
        if live.preview_requests >= max {
            return Err(ApiError::new(
                ErrorCode::PreviewFull,
                format!("preview {id} took {max} requests, as many as it holds"),
            ));
        }
        if live.preview_requests == 0 {
            live.erasure = erasure;
        }
        live.preview_requests += 1;
        let Some(c) = live.continuous.as_mut() else {
            return Err(internal("fork state missing"));
        };
        let input = pb::Input {
            kind: Some(pb::input::Kind::Http(http)),
        };
        let turn = c
            .send_input(actor, input, key, now, subject)
            .await
            .map_err(internal)?;
        self.write_log(id, live).await?;
        forget_logged(live);
        // The reply leaves the fork: no real SQL rows in it (M5), as
        // fork_send's, and no secret value (I8), as any answer.
        let mut outcome = shown_record(&turn).outcome.unwrap_or_default();
        let secrets = self.node.secret_values();
        if !secrets.is_empty() {
            kronik_sched::scrub::outcome_output(&mut outcome.output, &secrets);
            outcome.message = kronik_effects::http::scrub_str(&outcome.message, &secrets);
        }
        Ok(TurnResult {
            turn_id: TurnId {
                branch: id.to_owned(),
                lsn: turn.lsn,
            },
            outcome,
        })
    }
}

/// Deletes expired previews every `every`, starting now (so a restart
/// deletes the ones that expired while the daemon was down).
pub async fn expire_loop(proposals: Arc<Proposals>, every: Duration) {
    loop {
        proposals.expire_previews().await;
        proposals.node.env().clock.sleep(every).await;
    }
}

impl kronik_gateway::PreviewRouter for Proposals {
    fn routes(&self, id: &str) -> BoxFuture<'_, Result<Vec<RouteEntry>, ApiError>> {
        let routes = self.served(id).map(|s| s.routes.clone());
        Box::pin(std::future::ready(routes))
    }

    fn send(
        self: Arc<Self>,
        id: String,
        actor: ActorRef,
        http: pb::HttpInput,
        subject: Option<String>,
    ) -> BoxFuture<'static, Result<TurnResult, ApiError>> {
        let env = self.node.env().clone();
        // Its own task: a client that stops waiting does not cut the turn
        // short between the fork's store and its log.
        let turn = env.spawn("preview-send", async move {
            self.preview_send(&id, actor, http, subject).await
        });
        Box::pin(async move {
            turn.await.unwrap_or_else(|| {
                Err(internal(
                    "the preview request stopped unexpectedly; see the daemon log",
                ))
            })
        })
    }
}
