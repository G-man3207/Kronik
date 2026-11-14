//! The secret workloads (M23, docs/design/m23-secret-backends.md section 9):
//! secret names linked to the simulated OpenBao of `bao.rs`, which the daemon
//! reaches with its real `openbao` secret backend.
//!
//! - **allocator** ("one allocator", criterion 3, step 8): clients make
//!   counters HMAC their payloads with the linked name `stripe` while the
//!   backend rotates it; an operator runs `secret refresh` now and then; the
//!   background refresher runs every few hundred milliseconds; and the node
//!   crashes as in the counter workload. So a new `source_version` is often
//!   seen by two first uses at once, by the refresher and by an explicit
//!   refresh. Every Kronik version number of the name is reserved once, the
//!   numbers are dense, every reservation ends active or failed, every
//!   `source_version` has exactly one active number, and every HMAC a turn
//!   recorded was made with the value of the version its `SecretRef` names.
//! - **secret-outage** (I10, section 9, "Outages"): the backend hangs.
//!   Turns that need no secret commit at their normal rate, turns whose secret
//!   is cached use it, turns whose secret is not cached fail with, or handle,
//!   SECRET_UNAVAILABLE within `[secrets] fetch_timeout`, and no TurnBegin is
//!   left open. Once the backend answers again, the uncached secret works.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_gateway::HttpRequest;
use kronik_privacy::secret_backend::config::{Definition, Settings};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;
use prost::Message as _;

use super::{World, hex};
use crate::bao::{self, Mode, SimBao};

/// The token file the daemon's backend reads, on the simulated disk.
pub(super) const TOKEN_FILE: &str = "/etc/kronik/credentials/bao.token";
const BACKEND: &str = "bao";

/// One of the secret workloads, with its knobs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecretWorkload {
    /// "One allocator": a rotating backend observed by first uses, the
    /// refresher (70% to 90% of `refresh` after each certificate) and
    /// explicit refreshes, under crashes.
    Allocator { refresh: Duration, rotations: u32 },
    /// "secret-outage": the backend hangs for `outage` after a `baseline`.
    Outage {
        refresh: Duration,
        fetch_timeout: Duration,
        baseline: Duration,
        outage: Duration,
    },
}

impl SecretWorkload {
    fn names(self) -> &'static [&'static str] {
        match self {
            SecretWorkload::Allocator { .. } => &["stripe"],
            SecretWorkload::Outage { .. } => &["warm", "cold"],
        }
    }

    /// The node's `[secrets]`: the backend `bao` and the workload's timings.
    pub(super) fn settings(self) -> Settings {
        let (refresh, fetch_timeout) = match self {
            SecretWorkload::Allocator { refresh, .. } => (refresh, Duration::from_secs(2)),
            SecretWorkload::Outage {
                refresh,
                fetch_timeout,
                ..
            } => (refresh, fetch_timeout),
        };
        Settings {
            backends: BTreeMap::from([(
                BACKEND.to_owned(),
                Definition::Openbao {
                    address: bao::ADDRESS.into(),
                    allowed_refs: vec!["secret/payments/".into()],
                    auth: "token".into(),
                    token_file: Some(TOKEN_FILE.into()),
                    role_id_file: None,
                    secret_id_file: None,
                    cert_file: None,
                    key_file: None,
                    ca_file: None,
                    auth_mount: None,
                    role: None,
                },
            )]),
            refresh,
            fetch_timeout,
            ..Settings::default()
        }
    }

    /// The backend's state before the run: the first version of each name;
    /// in the outage workload `cold` answers once (the link's check) and then
    /// hangs, so that it is never cached.
    pub(super) fn prepare(self, bao: &SimBao) {
        for name in self.names() {
            bao.put(&path(name), &value(name, 1));
        }
        if let SecretWorkload::Outage { .. } = self {
            bao.hang_after(&path("cold"), 1);
        }
    }
}

fn humantime(d: Duration) -> String {
    format!("{} ms", d.as_millis())
}

fn path(name: &str) -> String {
    format!("payments/{name}")
}

fn reference(name: &str) -> String {
    format!("secret/payments/{name}#key")
}

fn value(name: &str, version: u64) -> String {
    format!("{name}-value-{version}")
}

fn mac(key: &str, payload: &str) -> String {
    hex(&kronik_effects::crypto::hmac_sha256(
        key.as_bytes(),
        payload.as_bytes(),
    ))
}

/// The phases of the outage workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(super) enum Phase {
    #[default]
    Setup,
    Baseline,
    Outage,
    Recovered,
    Done,
}

/// One request of a secret workload and what came back.
#[derive(Debug, Clone)]
pub(super) struct Observed {
    client: usize,
    idem: String,
    op: &'static str,
    secret: Option<&'static str>,
    payload: String,
    phase: Phase,
    /// The phase when the answer came: a request that began in one phase
    /// and ended in another met both and is not held to either.
    phase_end: Phase,
    latency: Duration,
    /// None: the connection broke or the client timed out.
    status: Option<u16>,
    body: String,
}

/// What the secret workloads keep between the tasks of a run.
#[derive(Default)]
pub(super) struct SecretState {
    /// The names are granted and linked.
    ready: bool,
    /// A turn has used `warm` (outage): its value is cached.
    warmed: bool,
    phase: Phase,
    observed: Vec<Observed>,
    rotations: u32,
    /// Pairs of first uses the director made at once after a rotation.
    concurrent: u32,
    /// The director is between a rotation and the end of its pair of first
    /// uses: the run does not end meanwhile.
    director_busy: bool,
    refreshes: BTreeMap<String, u64>,
}

impl World {
    fn workload(&self) -> Option<SecretWorkload> {
        self.cfg.secrets
    }

    /// Grants the names to the counter kind and links them to the backend,
    /// each once: they are history after a restart.
    pub(super) async fn setup_secrets(
        &self,
        node: &Node,
        authority: &AuthLease,
    ) -> Result<(), String> {
        let Some(workload) = self.workload() else {
            return Ok(());
        };
        let audit = || pb::Audit {
            token_id: "sim".into(),
            reason: "dst".into(),
            wall_time_ms: 0,
        };
        for name in workload.names() {
            let capability = format!("secret:{name}");
            if node.config_now().grant("counter", &capability).is_none() {
                node.grant(
                    "counter",
                    &capability,
                    None,
                    None,
                    kronik_effects::InForks::Recorded,
                    audit(),
                    false,
                    authority.clone(),
                )
                .await
                .map_err(|e| format!("grant {capability}: {}", e.code))?;
            }
            if node.config_now().secret_link(name).is_none() {
                let linked = node
                    .secret_link(
                        name,
                        BACKEND,
                        &reference(name),
                        &audit(),
                        false,
                        authority.clone(),
                    )
                    .await;
                // A link answers SECRET_UNAVAILABLE when it is committed but
                // the inventory was not published again in time.
                if let Err(e) = linked
                    && node.config_now().secret_link(name).is_none()
                {
                    return Err(format!("link {name}: {} {}", e.code, e.message));
                }
                self.event(format!("linked {name}"));
            }
        }
        self.st().secrets.ready = true;
        Ok(())
    }

    fn secret_phase(&self) -> Phase {
        self.st().secrets.phase
    }

    fn set_secret_phase(&self, phase: Phase) {
        self.st().secrets.phase = phase;
        self.event(format!("secret phase {phase:?}"));
    }

    /// One request through the gateway, once; the status and the body, or
    /// `None` when there was no answer.
    async fn ask(&self, path: String, idem: &str, body: Vec<u8>) -> Option<(u16, String)> {
        let conn = self.st().conn.clone()?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let req = HttpRequest {
            method: "POST".into(),
            path,
            query: String::new(),
            headers: vec![("Idempotency-Key".into(), idem.to_owned())],
            body,
            peer: None,
        };
        conn.send((req, tx)).ok()?;
        match self.clock_timeout(Duration::from_secs(60), rx).await {
            Some(Ok(resp)) => Some((
                resp.status,
                String::from_utf8_lossy(&resp.body).into_owned(),
            )),
            _ => None,
        }
    }

    pub(super) async fn secret_client(self: Arc<Self>, client: usize) {
        while !self.st().secrets.ready {
            self.sleep(Duration::from_millis(10)).await;
        }
        match self.workload() {
            Some(SecretWorkload::Allocator { .. }) => self.allocator_client(client).await,
            Some(SecretWorkload::Outage { .. }) => self.outage_client(client).await,
            None => {}
        }
        // No await between the last check and the count: the director cannot
        // start a rotation in between.
        while self.st().secrets.director_busy {
            self.sleep(Duration::from_millis(10)).await;
        }
        self.st().clients_done += 1;
    }

    /// One HMAC of `stripe` by `actor` under `idem`, retried (same key)
    /// until it is answered; the answer, or `None` after a violation.
    async fn hmac_until_answered(&self, client: usize, actor: &str, idem: &str) -> Option<String> {
        self.st().requests += 1;
        let started = self.exec.now();
        let mut attempt = 0u32;
        let (status, body) = loop {
            attempt += 1;
            if attempt > 2_000 {
                self.violation(format!("{idem} never succeeded"));
                return None;
            }
            match self
                .ask(
                    format!("/counter/{actor}/hmac"),
                    idem,
                    format!("stripe\n{idem}").into_bytes(),
                )
                .await
            {
                Some((200, body)) => break (200, body),
                Some((status, body)) => {
                    self.event(format!("{idem} -> {status} {body}"));
                    if body.contains("TURN_FAILED") || body.contains("IDEMPOTENCY_KEY_REUSED") {
                        self.violation(format!("{idem}: {status} {body}"));
                        return None;
                    }
                }
                None => self.event(format!("{idem} -> no answer")),
            }
            let backoff = self
                .work
                .duration(Duration::from_millis(5), Duration::from_millis(60));
            self.sleep(backoff).await;
        };
        self.event(format!(
            "{idem} hmac {actor} -> {status} (attempt {attempt})"
        ));
        let mut st = self.st();
        if let Some(prev) = st.responses.get(idem)
            && *prev != body.as_bytes()
        {
            let v = format!("{idem}: retry got {body:?}");
            drop(st);
            self.violation(v);
            return None;
        }
        st.responses
            .insert(idem.to_owned(), body.clone().into_bytes());
        st.secrets.observed.push(Observed {
            client,
            idem: idem.to_owned(),
            op: "hmac",
            secret: Some("stripe"),
            payload: idem.to_owned(),
            phase: Phase::Setup,
            phase_end: Phase::Setup,
            latency: self.exec.now().saturating_sub(started),
            status: Some(status),
            body: body.clone(),
        });
        Some(body)
    }

    /// HMACs with `stripe`, each request retried until it is answered.
    async fn allocator_client(&self, client: usize) {
        for r in 0..self.cfg.requests_per_client {
            let actor = format!("k{}", self.work.below(self.cfg.actors as u64));
            if self
                .hmac_until_answered(client, &actor, &format!("c{client}-r{r}"))
                .await
                .is_none()
            {
                return;
            }
            // Bursts: often no pause at all, so that first uses meet.
            if self.work.chance(0.5) {
                let pause = self
                    .work
                    .duration(Duration::from_millis(1), Duration::from_millis(40));
                self.sleep(pause).await;
            }
        }
    }

    /// Client 0 increments (no secret), client 1 HMACs with `warm` (cached),
    /// client 2 uses `cold` (never cached) while the backend hangs, by an
    /// HMAC whose error fails the turn and by `exfiltrate`, which handles it,
    /// and once more after the backend is back.
    async fn outage_client(&self, client: usize) {
        let mut r = 0u32;
        let mut recovered = false;
        loop {
            let phase = self.secret_phase();
            if phase == Phase::Done {
                return;
            }
            r += 1;
            let idem = format!("c{client}-r{r}");
            let (op, secret, body, pause) = match client {
                0 => ("increment", None, Vec::new(), (20, 60)),
                1 => (
                    "hmac",
                    Some("warm"),
                    format!("warm\n{idem}").into_bytes(),
                    (50, 200),
                ),
                _ if phase == Phase::Outage => {
                    if r.is_multiple_of(2) {
                        (
                            "hmac",
                            Some("cold"),
                            format!("cold\n{idem}").into_bytes(),
                            (100, 300),
                        )
                    } else {
                        (
                            "exfiltrate",
                            Some("cold"),
                            b"cold http://invalid/".to_vec(),
                            (100, 300),
                        )
                    }
                }
                // After the outage and the 5 s for which a failure is
                // remembered: the uncached name works again.
                _ if phase == Phase::Recovered && !recovered => {
                    self.sleep(Duration::from_secs(6)).await;
                    recovered = true;
                    (
                        "hmac",
                        Some("cold"),
                        format!("cold\n{idem}").into_bytes(),
                        (10, 20),
                    )
                }
                _ => {
                    self.sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let actor = format!("k{client}");
            self.st().requests += 1;
            let started = self.exec.now();
            let answer = self
                .ask(format!("/counter/{actor}/{op}"), &idem, body)
                .await;
            let latency = self.exec.now().saturating_sub(started);
            let phase_end = self.secret_phase();
            let (status, text) = match answer {
                Some((status, text)) => (Some(status), text),
                None => (None, String::new()),
            };
            self.event(format!(
                "{idem} {op} {} [{phase:?}] -> {status:?} in {} ms",
                secret.unwrap_or("-"),
                latency.as_millis()
            ));
            if client == 1 && status == Some(200) {
                self.st().secrets.warmed = true;
            }
            self.st().secrets.observed.push(Observed {
                client,
                idem: idem.clone(),
                op,
                secret,
                payload: idem,
                phase,
                phase_end,
                latency,
                status,
                body: text,
            });
            let pause = self.work.duration(
                Duration::from_millis(pause.0),
                Duration::from_millis(pause.1),
            );
            self.sleep(pause).await;
        }
    }

    /// Drives the backend: rotations and explicit refreshes (allocator), or
    /// the phases of the outage.
    pub(super) async fn secret_director(self: Arc<Self>) {
        let Some(bao) = self.bao.clone() else {
            return;
        };
        match self.workload() {
            Some(SecretWorkload::Allocator { rotations, .. }) => {
                let mut left = rotations;
                while self.st().clients_done < self.cfg.clients {
                    let pause = self
                        .faults
                        .duration(Duration::from_millis(30), Duration::from_millis(400));
                    self.sleep(pause).await;
                    // The clients may have finished during the pause: the run
                    // is ending, and nothing new may begin.
                    if self.st().clients_done == self.cfg.clients {
                        break;
                    }
                    if left > 0 && self.faults.chance(0.5) {
                        self.st().secrets.director_busy = true;
                        let next = bao.current(&path("stripe")) + 1;
                        bao.put(&path("stripe"), &value("stripe", next));
                        left -= 1;
                        self.st().secrets.rotations += 1;
                        self.event(format!("backend rotates stripe to version {next}"));
                        // Two first uses at once: once the cached value is
                        // older than `refresh`, two turns of two actors need
                        // it in the same instant, while the refresher may
                        // observe the new version too. A value is as old as
                        // its last check, and a fetch that began before the
                        // rotation may check the old version a little after
                        // it: 100 ms is more than such a fetch takes here.
                        if let Some(SecretWorkload::Allocator { refresh, .. }) = self.workload() {
                            let wait = refresh + Duration::from_millis(100);
                            self.sleep(wait).await;
                            let n = self.st().secrets.rotations;
                            let (first, second) = (format!("d{n}-a"), format!("d{n}-b"));
                            let (a, b) = tokio::join!(
                                self.hmac_until_answered(9, "k0", &first),
                                self.hmac_until_answered(9, "k1", &second),
                            );
                            self.st().secrets.director_busy = false;
                            let (Some(a), Some(b)) = (a, b) else {
                                return;
                            };
                            // A rotation reaches new effects within `refresh`
                            // (ADR 0091): both first uses use the new version.
                            let key = value("stripe", next);
                            for (idem, body) in [(&first, &a), (&second, &b)] {
                                if *body != mac(&key, idem) {
                                    self.violation(format!(
                                        "{idem}: a first use {} after rotating to version {next} \
                                         did not use it",
                                        humantime(wait)
                                    ));
                                }
                            }
                            self.st().secrets.concurrent += 1;
                        }
                        self.st().secrets.director_busy = false;
                        continue;
                    }
                    // An operator's `secret refresh`, run as a task of the node:
                    // a crash ends it with the node, as it ends a request. A
                    // future of the supervisor that held the node across a
                    // crash would keep the crashed node, and its hold on the
                    // data directory, alive.
                    let (node, node_id) = {
                        let st = self.st();
                        (st.node.clone(), st.node_id)
                    };
                    let Some(node) = node else {
                        continue;
                    };
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    self.exec.spawn(
                        node_id,
                        "secret-refresh",
                        Box::pin(async move {
                            let outcome = match node.local_operator_authority() {
                                Ok(authority) => {
                                    let audit = pb::Audit {
                                        token_id: "sim".into(),
                                        reason: "dst refresh".into(),
                                        wall_time_ms: 0,
                                    };
                                    match node
                                        .secret_refresh("stripe", &audit, false, authority)
                                        .await
                                    {
                                        Ok(meta) => format!("v{}", meta.map_or(0, |m| m.version)),
                                        Err(e) => e.code.as_str().to_owned(),
                                    }
                                }
                                Err(e) => e.code.as_str().to_owned(),
                            };
                            let _ = tx.send(outcome);
                        }),
                    );
                    let outcome = rx.await.unwrap_or_else(|_| "crashed".to_owned());
                    self.event(format!("secret refresh stripe -> {outcome}"));
                    *self.st().secrets.refreshes.entry(outcome).or_default() += 1;
                }
            }
            Some(SecretWorkload::Outage {
                baseline, outage, ..
            }) => {
                while !self.st().secrets.ready {
                    self.sleep(Duration::from_millis(10)).await;
                }
                self.set_secret_phase(Phase::Baseline);
                // The baseline lasts until `warm` is cached, and `baseline`.
                while !self.st().secrets.warmed {
                    self.sleep(Duration::from_millis(10)).await;
                }
                self.sleep(baseline).await;
                bao.set_mode(Mode::Hang);
                self.set_secret_phase(Phase::Outage);
                self.sleep(outage).await;
                bao.set_mode(Mode::Up);
                bao.hang_after(&path("cold"), u64::MAX);
                self.set_secret_phase(Phase::Recovered);
                // The last client request waits 6 s, then is answered.
                self.sleep(Duration::from_secs(8)).await;
                self.set_secret_phase(Phase::Done);
            }
            None => {}
        }
    }

    /// Whether a failed turn is one the workload expects: in the outage
    /// workload, a turn whose effect could not get `cold`.
    pub(super) fn expected_failure(&self, turn: &pb::TurnRecord) -> bool {
        matches!(self.workload(), Some(SecretWorkload::Outage { .. }))
            && turn
                .effects
                .iter()
                .any(|e| e.error == "SECRET_UNAVAILABLE: cold")
    }

    /// The secret invariants of the workload, from the log.
    pub(super) async fn check_secrets(&self, node: &Node) {
        let Some(workload) = self.workload() else {
            return;
        };
        // The refresher may be between the reservation of a version it has
        // just observed and its end when the clients finish: give it the
        // time a fetch and a publication take. Nothing rotates any more, so
        // it observes nothing new meanwhile.
        if let SecretWorkload::Allocator { refresh, .. } = workload {
            self.sleep(refresh + Duration::from_secs(3)).await;
        }
        let mut records = Vec::new();
        if let Err(e) = node
            .reader()
            .read(1, node.applied_lsn(), |c| {
                records.push(c.record);
                Ok(())
            })
            .await
        {
            return self.violation(format!("reading the log: {e}"));
        }
        match workload {
            SecretWorkload::Allocator { .. } => self.check_allocator(&records),
            SecretWorkload::Outage { fetch_timeout, .. } => {
                self.check_outage(&records, fetch_timeout)
            }
        }
    }

    fn check_allocator(&self, records: &[Record]) {
        let Some(bao) = &self.bao else {
            return;
        };
        // Every SecretVersion record of `stripe`, by Kronik version, and the
        // format fence: numbers start after it. A node whose first start
        // crashed after it created the secret store, before its fence was
        // durable, finds an existing store at the next start and fences the
        // legacy range (u32::MAX), as for a store from before M23.
        let fence = pb::secret_version::Phase::Fence as i32;
        let mut floor = None;
        let mut allocated: BTreeMap<u64, Vec<&pb::SecretVersion>> = BTreeMap::new();
        for r in records {
            match r {
                Record::SecretVersion(v) if v.name.is_empty() && v.phase == fence => {
                    if floor.is_some() {
                        self.violation("two secret format fences in the log".to_owned());
                    }
                    floor = Some(v.version);
                }
                Record::SecretVersion(v) if v.name == "stripe" => {
                    allocated.entry(v.version).or_default().push(v);
                }
                _ => {}
            }
        }
        let floor = floor.unwrap_or_else(|| {
            self.violation("no secret format fence in the log".to_owned());
            0
        });
        let reserved = pb::secret_version::Phase::Reserved as i32;
        let active = pb::secret_version::Phase::Active as i32;
        let failed = pb::secret_version::Phase::Failed as i32;
        let numbers: Vec<u64> = allocated.keys().copied().collect();
        let dense: Vec<u64> = (floor + 1..=floor + numbers.len() as u64).collect();
        if numbers != dense {
            self.violation(format!(
                "stripe's versions are not dense after the fence at {floor}: {numbers:?}"
            ));
        }
        let mut by_source: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
        let mut observers: BTreeMap<String, u64> = BTreeMap::new();
        let mut failures = 0;
        for (version, rows) in &allocated {
            let phases: Vec<i32> = rows.iter().map(|r| r.phase).collect();
            let reservations = phases.iter().filter(|p| **p == reserved).count();
            let terminal = phases
                .iter()
                .filter(|p| **p == active || **p == failed)
                .count();
            if reservations != 1 || terminal != 1 || phases.len() != 2 {
                self.violation(format!(
                    "stripe v{version} has the phases {phases:?}: not one reservation and one end"
                ));
            }
            let sources: BTreeSet<&str> = rows.iter().map(|r| r.source_version.as_str()).collect();
            if sources.len() != 1 {
                self.violation(format!(
                    "stripe v{version} names several source versions: {sources:?}"
                ));
            }
            for row in rows.iter().filter(|r| r.phase == active) {
                by_source
                    .entry(row.source_version.as_str())
                    .or_default()
                    .insert(*version);
                let reason = row.audit.as_ref().map_or("", |a| a.reason.as_str());
                *observers.entry(reason.to_owned()).or_default() += 1;
            }
            failures += phases.iter().filter(|p| **p == failed).count();
        }
        for (source, versions) in &by_source {
            if versions.len() != 1 {
                self.violation(format!(
                    "source version {source} of stripe has the active versions {versions:?}"
                ));
            }
        }
        // Every HMAC a turn recorded was made with the value of the version
        // its SecretRef names, and the client got that HMAC.
        let active_rows: BTreeMap<u64, &pb::SecretVersion> = allocated
            .iter()
            .filter_map(|(v, rows)| rows.iter().find(|r| r.phase == active).map(|r| (*v, *r)))
            .collect();
        let answered: BTreeMap<String, String> = self
            .st()
            .secrets
            .observed
            .iter()
            .map(|o| (o.idem.clone(), o.body.clone()))
            .collect();
        let mut used = 0;
        for r in records {
            let Record::TurnRecord(t) = r else {
                continue;
            };
            let Some(pb::input::Kind::Http(h)) = t.input.as_ref().and_then(|i| i.kind.as_ref())
            else {
                continue;
            };
            for e in t.effects.iter().filter(|e| e.kind == "crypto.hmac-sha256") {
                let Some(pb::sealable::Value::Plain(bytes)) =
                    e.request.as_ref().and_then(|r| r.value.as_ref())
                else {
                    self.violation(format!(
                        "{}: an HMAC without a plain request",
                        h.idempotency_key
                    ));
                    continue;
                };
                let reference = pb::CryptoEffectRequest::decode(bytes.as_slice())
                    .ok()
                    .and_then(|request| request.secret);
                let Some(reference) = reference else {
                    self.violation(format!(
                        "{}: an HMAC without a SecretRef",
                        h.idempotency_key
                    ));
                    continue;
                };
                let version = reference.resolved_version().unwrap_or(0);
                let Some(row) = active_rows.get(&version) else {
                    self.violation(format!(
                        "{}: the HMAC names stripe v{version}, which is not active",
                        h.idempotency_key
                    ));
                    continue;
                };
                if row.version_hash != reference.version_hash {
                    self.violation(format!(
                        "{}: the SecretRef hash of v{version} is not the recorded one",
                        h.idempotency_key
                    ));
                }
                let source: u64 = row.source_version.parse().unwrap_or(0);
                let Some(key) = bao.value(&path("stripe"), source) else {
                    self.violation(format!("stripe source version {source} has no value"));
                    continue;
                };
                let want = mac(&key, &h.idempotency_key);
                let recorded = match e.response.as_ref().and_then(|r| r.value.as_ref()) {
                    Some(pb::sealable::Value::Plain(bytes)) => hex(bytes),
                    _ => String::new(),
                };
                if recorded != want {
                    self.violation(format!(
                        "{}: the recorded HMAC was not made with v{version} (source {source})",
                        h.idempotency_key
                    ));
                }
                if answered
                    .get(&h.idempotency_key)
                    .is_some_and(|body| *body != want)
                {
                    self.violation(format!(
                        "{}: the client got another HMAC than the turn recorded",
                        h.idempotency_key
                    ));
                }
                used += 1;
            }
        }
        if used == 0 {
            self.violation("no HMAC turn used the linked secret".to_owned());
        }
        let st = self.st();
        let refreshes: Vec<String> = st
            .secrets
            .refreshes
            .iter()
            .map(|(k, n)| format!("{k}x{n}"))
            .collect();
        let observed: Vec<String> = observers
            .iter()
            .map(|(reason, n)| format!("{}:{n}", reason.split_whitespace().next().unwrap_or("?")))
            .collect();
        let notes = format!(
            " versions={} failed={failures} rotations={} concurrent={} hmacs={used} observed=[{}] refresh=[{}]",
            numbers.len(),
            st.secrets.rotations,
            st.secrets.concurrent,
            observed.join(","),
            refreshes.join(",")
        );
        drop(st);
        self.st().notes = notes;
    }

    fn check_outage(&self, records: &[Record], fetch_timeout: Duration) {
        let observed = self.st().secrets.observed.clone();
        // A turn of the node takes milliseconds of virtual time; one that
        // waited for the backend takes about `fetch_timeout`.
        let normal = Duration::from_millis(250);
        let bounded = fetch_timeout + normal;
        let turns: BTreeMap<String, &pb::TurnRecord> = records
            .iter()
            .filter_map(|r| match r {
                Record::TurnRecord(t) => match t.input.as_ref().and_then(|i| i.kind.as_ref()) {
                    Some(pb::input::Kind::Http(h)) => Some((h.idempotency_key.clone(), t)),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut worst: BTreeMap<String, Duration> = BTreeMap::new();
        for o in &observed {
            if o.phase != o.phase_end {
                // It began before the backend hung or recovered and ended
                // after: either outcome is right. It was answered, and its
                // turn is in the log (no open TurnBegin is checked anyway).
                *counts.entry("transition".into()).or_default() += 1;
                if o.status.is_none() || !turns.contains_key(&o.idem) {
                    self.violation(format!(
                        "{} across a phase change: no answer or no turn",
                        o.idem
                    ));
                }
                continue;
            }
            let label = format!("{:?}-{}-{}", o.phase, o.op, o.secret.unwrap_or("none"));
            *counts.entry(label.clone()).or_default() += 1;
            let w = worst.entry(label).or_default();
            *w = (*w).max(o.latency);
            let what = format!(
                "client {} {} {} {:?} [{:?}]",
                o.client, o.idem, o.op, o.secret, o.phase
            );
            let Some(status) = o.status else {
                self.violation(format!("{what}: no answer"));
                continue;
            };
            let turn = turns.get(&o.idem);
            match (o.op, o.secret, o.phase) {
                ("increment", _, _) => {
                    if status != 200 || o.latency > normal {
                        self.violation(format!(
                            "{what}: a turn without a secret answered {status} in {} ms",
                            o.latency.as_millis()
                        ));
                    }
                }
                ("hmac", Some(name @ ("warm" | "cold")), phase)
                    if name == "warm" || phase == Phase::Recovered =>
                {
                    let want = self
                        .bao
                        .as_ref()
                        .and_then(|b| b.value(&path(name), 1))
                        .map(|key| mac(&key, &o.payload));
                    if status != 200 || Some(&o.body) != want.as_ref() {
                        self.violation(format!(
                            "{what}: {status} {:?}: a {} secret was not used",
                            o.body,
                            if name == "warm" {
                                "cached"
                            } else {
                                "recovered"
                            }
                        ));
                    }
                    if name == "warm" && o.latency > bounded {
                        self.violation(format!(
                            "{what}: the cached secret took {} ms",
                            o.latency.as_millis()
                        ));
                    }
                }
                ("hmac", Some("cold"), Phase::Outage) => {
                    // The guest's error fails the turn: the request is told
                    // TURN_FAILED, and the turn names SECRET_UNAVAILABLE.
                    if status == 200 || !o.body.contains("TURN_FAILED") {
                        self.violation(format!("{what}: {status} {}", o.body));
                    }
                    self.check_unavailable(&what, turn.copied(), false);
                    if o.latency > bounded {
                        self.violation(format!(
                            "{what}: ended after {} ms, not within fetch_timeout",
                            o.latency.as_millis()
                        ));
                    }
                }
                ("exfiltrate", Some("cold"), Phase::Outage) => {
                    // The guest handles the error: the turn commits.
                    if status != 200 {
                        self.violation(format!("{what}: {status} {}", o.body));
                    }
                    self.check_unavailable(&what, turn.copied(), true);
                    if o.latency > bounded {
                        self.violation(format!(
                            "{what}: ended after {} ms, not within fetch_timeout",
                            o.latency.as_millis()
                        ));
                    }
                }
                _ => self.violation(format!("{what}: not a request of the workload")),
            }
        }
        for needed in [
            "Outage-increment-none",
            "Outage-hmac-warm",
            "Outage-hmac-cold",
            "Outage-exfiltrate-cold",
            "Recovered-hmac-cold",
        ] {
            if !counts.contains_key(needed) {
                self.violation(format!("the workload made no request {needed}"));
            }
        }
        let summary: Vec<String> = counts
            .iter()
            .map(|(label, n)| {
                format!(
                    "{label}={n}/{}ms",
                    worst.get(label).map_or(0, |d| d.as_millis())
                )
            })
            .collect();
        self.st().notes = format!(" {}", summary.join(" "));
    }

    /// The turn of a request that met the outage: it recorded
    /// SECRET_UNAVAILABLE as its effect's result, and committed when the
    /// guest handled it, failed when it did not.
    fn check_unavailable(&self, what: &str, turn: Option<&pb::TurnRecord>, handled: bool) {
        let Some(turn) = turn else {
            return self.violation(format!("{what}: no turn in the log"));
        };
        if !turn
            .effects
            .iter()
            .any(|e| e.kind == "crypto.hmac-sha256" && e.error == "SECRET_UNAVAILABLE: cold")
        {
            self.violation(format!(
                "{what}: no HMAC effect recorded SECRET_UNAVAILABLE: {:?}",
                turn.effects
                    .iter()
                    .map(|e| (&e.kind, &e.error))
                    .collect::<Vec<_>>()
            ));
        }
        let committed =
            turn.outcome.as_ref().map(|o| o.kind) == Some(pb::OutcomeKind::Committed as i32);
        if committed != handled {
            self.violation(format!("{what}: outcome {:?}", turn.outcome));
        }
    }
}
