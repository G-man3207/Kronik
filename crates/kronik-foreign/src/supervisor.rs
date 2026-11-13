//! One foreign actor's sandbox: start, readiness, exit, restart with
//! backoff and stop (docs/design/m7-foreign.md §5).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::{Env, Process};
use kronik_effects::foreign::SecretLinks;
use kronik_privacy::SecretStore;
use kronik_proto::log::v1 as pb;
use tokio::sync::Notify;

use crate::blobs::BlobStore;
use crate::bridge::{self, Dialer, Pool};
use crate::fetch::FetchOptions;
use crate::image::ImageRef;
use crate::oci;
use crate::runtime::{Runtime, container_id, run_quick};

/// Bump when the bundle layout Kronik writes changes, so old bundles are
/// rebuilt.
const BUNDLE_FORMAT: u32 = 1;
/// The pids limit of every sandbox (not in the record in v0.1).
pub(crate) const PIDS_LIMIT: i64 = 1024;
/// Short runtime commands (kill, delete, list).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Timings of supervision; the defaults are the design's.
#[derive(Debug, Clone)]
pub(crate) struct Timings {
    pub start_timeout: Duration,
    pub ready_poll: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    pub healthy_after: Duration,
    pub stop_grace: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Timings {
            start_timeout: Duration::from_secs(30),
            ready_poll: Duration::from_millis(50),
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(60),
            healthy_after: Duration::from_secs(60),
            stop_grace: Duration::from_secs(10),
        }
    }
}

/// The delay before start number `failures + 1`.
pub(crate) fn backoff(t: &Timings, failures: u32) -> Duration {
    let exp = failures.saturating_sub(1).min(20);
    t.backoff_base
        .saturating_mul(1u32 << exp)
        .min(t.backoff_max)
}

/// Where an actor's files are (docs/design/m7-foreign.md §3).
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    /// `<data>/foreign`
    pub data: PathBuf,
    /// `[foreign] run_dir`
    pub run: PathBuf,
}

impl Paths {
    /// `<data>/foreign/actors`: one directory per actor, apart from the
    /// blob store, so no actor name can share a directory with it.
    pub fn actors(&self) -> PathBuf {
        self.data.join("actors")
    }
    pub fn actor(&self, name: &str) -> PathBuf {
        self.actors().join(name)
    }
    pub fn bundle(&self, name: &str) -> PathBuf {
        self.actor(name).join("bundle")
    }
    pub fn data_dir(&self, name: &str) -> PathBuf {
        self.actor(name).join("data")
    }
    pub fn log(&self, name: &str) -> PathBuf {
        self.actor(name).join("output.log")
    }
    pub fn netns_dir(&self) -> PathBuf {
        self.run.join("netns")
    }
    pub fn netns(&self, name: &str) -> PathBuf {
        self.netns_dir().join(name)
    }
    pub fn sock_root(&self) -> PathBuf {
        self.run.join("sock")
    }
    pub fn sock(&self, name: &str) -> PathBuf {
        self.sock_root().join(name)
    }
    pub fn blobs(&self) -> PathBuf {
        self.data.join("blobs")
    }
}

/// What every actor of one manager shares.
pub(crate) struct Ctx {
    pub env: Env,
    pub paths: Paths,
    pub blobs: BlobStore,
    pub fetch: FetchOptions,
    pub microvm_dir: PathBuf,
    pub disk_reserve: u64,
    /// `[foreign] pull_timeout`.
    pub pull_timeout: Duration,
    pub timings: Timings,
    /// `/kronik/<instance>`: the cgroup parent of this daemon's sandboxes.
    pub cgroup_parent: String,
    /// Secret values injected per actor name since the daemon started, for
    /// scrubbing logs (§9).
    pub injected: Mutex<Injected>,
    /// Fetches (pulls, layout imports) hold it shared, blob garbage
    /// collection exclusively: no blob is collected while it is being
    /// fetched or reused.
    pub fetching: tokio::sync::RwLock<()>,
    /// A garbage collection round was skipped during a fetch: the fetch
    /// that ends last wakes `gc_wake` ([`FetchGuard`]).
    pub gc_pending: AtomicBool,
    pub gc_wake: Arc<Notify>,
    /// Manifest digests of adds that fetched their image and have not
    /// finished yet (written or abandoned): garbage collection keeps them.
    pub adding: Mutex<std::collections::BTreeMap<String, usize>>,
}

/// Actor name -> (secret name, value) pairs it was given.
pub(crate) type Injected = std::collections::BTreeMap<String, Vec<(String, Vec<u8>)>>;

/// `fetching` held shared by a fetch; once released, a garbage collection
/// round skipped meanwhile is woken.
pub(crate) struct FetchGuard<'a> {
    guard: Option<tokio::sync::RwLockReadGuard<'a, ()>>,
    ctx: &'a Ctx,
}

impl Drop for FetchGuard<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        if self.ctx.gc_pending.load(Ordering::SeqCst) {
            self.ctx.gc_wake.notify_one();
        }
    }
}

impl Ctx {
    /// Holds `fetching` shared for a pull or a layout import.
    pub async fn fetch_shared(&self) -> FetchGuard<'_> {
        FetchGuard {
            guard: Some(self.fetching.read().await),
            ctx: self,
        }
    }

    pub fn cgroup_path(&self, name: &str) -> String {
        format!("{}/{}", self.cgroup_parent, container_id(name))
    }

    /// [`crate::fetch::pull`], given up after `pull_timeout` (a registry
    /// that stops answering must not hang an add or a start). `budget`:
    /// [`crate::fetch::FetchOptions::max_new_bytes`]. The caller holds
    /// `fetching` shared (until the image is held or declared).
    pub async fn pull(
        &self,
        registry: &str,
        repository: &str,
        digest: &str,
        budget: Option<u64>,
    ) -> Result<crate::fetch::Resolved, crate::image::ImageError> {
        let options = crate::fetch::FetchOptions {
            max_new_bytes: budget,
            ..self.fetch.clone()
        };
        let pull = crate::fetch::pull(&self.blobs, registry, repository, digest, &options);
        match self.env.timeout(self.pull_timeout, pull).await {
            Ok(r) => r,
            Err(_) => Err(crate::image::ImageError::TimedOut(format!(
                "pulling {registry}/{repository}@{digest} took longer than {} s \
                 ([foreign] pull_timeout)",
                self.pull_timeout.as_secs()
            ))),
        }
    }

    /// [`crate::fetch::import_layout_limited`] on a blocking thread, given
    /// up after `pull_timeout` (a hung network file system must not hang an
    /// add, a start or the shutdown waiting for it). The abandoned thread
    /// stops at its next read or blob and removes its temporary file; one
    /// stuck in a read stays until the read returns. The caller holds
    /// `fetching` shared.
    pub async fn import_layout(
        &self,
        dir: PathBuf,
        digest: Option<String>,
        reference: Option<String>,
        budget: Option<u64>,
    ) -> Result<crate::fetch::Resolved, crate::image::ImageError> {
        let blobs = self.blobs.clone();
        let shown = dir.display().to_string();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = cancel.clone();
        let import = self.env.blocking("foreign-image", move || {
            let limits = crate::fetch::ImportLimits {
                max_new_bytes: budget,
                cancel: Some(&flag),
            };
            crate::fetch::import_layout_limited(
                &blobs,
                &dir,
                digest.as_deref(),
                reference.as_deref(),
                &limits,
            )
        });
        match self.env.timeout(self.pull_timeout, import).await {
            Ok(Some(r)) => r,
            Ok(None) => Err(crate::image::ImageError::Io(
                "the import task was dropped".into(),
            )),
            Err(_) => {
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                Err(crate::image::ImageError::TimedOut(format!(
                    "importing oci-layout:{shown} took longer than {} s ([foreign] pull_timeout)",
                    self.pull_timeout.as_secs()
                )))
            }
        }
    }
}

/// Where an actor is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Starting,
    Running,
    Backoff,
    Stopping,
    Stopped,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Running => "running",
            State::Backoff => "backoff",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
        }
    }
}

/// How the last run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastExit {
    /// The container's exit status; `None` when the runtime was killed by
    /// a signal.
    pub code: Option<i32>,
    /// The sandbox exceeded its memory limit (`memory.events`).
    pub oom: bool,
    pub at_ms: u64,
}

/// An actor's supervision state, for `foreign list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub since_ms: u64,
    pub starts: u64,
    pub restarts: u64,
    pub last_exit: Option<LastExit>,
    pub next_start_ms: Option<u64>,
    pub error: Option<String>,
}

/// One declared foreign actor and its supervisor's shared state.
pub(crate) struct Actor {
    pub decl: pb::ForeignActor,
    pub runtime: Runtime,
    pub cgroup: String,
    pub dialer: Dialer,
    pub pool: Pool,
    status: Mutex<Status>,
    /// Woken on every state change.
    pub changed: Notify,
    stop: Notify,
    stopping: AtomicBool,
    finished: Notify,
    done: AtomicBool,
    pub secrets: Mutex<Option<Arc<SecretStore>>>,
    /// Whether a secret name is linked to an external backend now. The node
    /// replaces it at every reconcile; it answers from the node's current
    /// configuration, so a link made after this actor was declared counts.
    pub links: Mutex<SecretLinks>,
    /// Calls hold it shared; a checkpoint holds it exclusively, so main's
    /// calls wait in the daemon, not inside the paused sandbox (M14).
    pub calls: tokio::sync::RwLock<()>,
    /// The running sandbox's runtime spec, for its checkpoints (M14): the
    /// bundle's `config.json` is deleted once the sandbox runs (it holds
    /// the injected secret values).
    pub spec: Mutex<Vec<u8>>,
    pub vm: Mutex<Option<Arc<crate::microvm::Vm>>>,
}

impl Actor {
    pub fn new(
        ctx: &Ctx,
        decl: pb::ForeignActor,
        mut runtime: Runtime,
        secrets: Option<Arc<SecretStore>>,
        links: SecretLinks,
    ) -> Arc<Actor> {
        let name = decl.name.clone();
        let port = u16::try_from(decl.port).unwrap_or(0);
        // An old checkpoint/stop must never address a removed-and-readded VM.
        let cgroup = if runtime.engine == crate::runtime::Engine::Firecracker {
            let id = format!(
                "kronik-foreign-{:032x}",
                u128::from_le_bytes(ctx.env.random_bytes())
            );
            runtime.root.push(&id);
            format!("{}/{}", ctx.cgroup_parent, id)
        } else {
            ctx.cgroup_path(&name)
        };
        let dialer = match runtime.engine {
            crate::runtime::Engine::Runsc { .. } => Dialer::PortForward {
                runtime: runtime.clone(),
                id: container_id(&name),
                port,
                sock_dir: ctx.paths.sock(&name),
                log: ctx.paths.log(&name),
            },
            crate::runtime::Engine::Runc => Dialer::Netns {
                netns: ctx.paths.netns(&name),
                port,
            },
            crate::runtime::Engine::Firecracker => Dialer::Vsock {
                socket: runtime.root.join("jail/vsock.sock"),
                cgroup: cgroup.clone(),
            },
        };
        Arc::new(Actor {
            decl,
            runtime,
            cgroup,
            dialer,
            pool: Pool::default(),
            status: Mutex::new(Status {
                state: State::Starting,
                since_ms: ctx.env.clock.wall_ms(),
                starts: 0,
                restarts: 0,
                last_exit: None,
                next_start_ms: None,
                error: None,
            }),
            changed: Notify::new(),
            stop: Notify::new(),
            stopping: AtomicBool::new(false),
            finished: Notify::new(),
            done: AtomicBool::new(false),
            spec: Mutex::new(Vec::new()),
            vm: Mutex::new(None),
            secrets: Mutex::new(secrets),
            links: Mutex::new(links),
            calls: tokio::sync::RwLock::new(()),
        })
    }

    pub fn name(&self) -> &str {
        &self.decl.name
    }

    pub fn status(&self) -> Status {
        lock(&self.status).clone()
    }

    fn update(&self, env: &Env, f: impl FnOnce(&mut Status)) {
        {
            let mut s = lock(&self.status);
            let before = s.state;
            f(&mut s);
            if s.state != before {
                s.since_ms = env.clock.wall_ms();
            }
        }
        self.changed.notify_waiters();
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    /// Asks the supervisor to stop the sandbox and waits until it has.
    pub async fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.stop.notify_one();
        self.changed.notify_waiters();
        loop {
            let finished = self.finished.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            finished.await;
        }
    }

    /// Waits until the actor has left `starting` (or `timeout`).
    pub async fn settled(&self, env: &Env, timeout: Duration) {
        let _ = env
            .timeout(timeout, async {
                loop {
                    let changed = self.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if self.status().state != State::Starting || self.done.load(Ordering::Acquire) {
                        return;
                    }
                    changed.await;
                }
            })
            .await;
    }

    /// Waits until the actor is running, for at most `timeout`. The error
    /// says why it is not.
    pub async fn running(&self, env: &Env, timeout: Duration) -> Result<(), String> {
        let wait = async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let s = self.status();
                match s.state {
                    State::Running => return Ok(()),
                    State::Stopping | State::Stopped => return Err(why(&s, env)),
                    State::Starting | State::Backoff => {}
                }
                changed.await;
            }
        };
        match env.timeout(timeout, wait).await {
            Ok(r) => r,
            Err(_) => Err(why(&self.status(), env)),
        }
    }
}

/// A sentence on why an actor cannot answer, for `FOREIGN_UNAVAILABLE`.
fn why(s: &Status, env: &Env) -> String {
    let mut out = format!("it is {}", s.state.as_str());
    if let Some(e) = &s.last_exit {
        match (e.oom, e.code) {
            (true, _) => out.push_str(" after running out of memory"),
            (false, Some(c)) => out.push_str(&format!(" after exit status {c}")),
            (false, None) => out.push_str(" after being killed"),
        }
    }
    if let Some(next) = s.next_start_ms {
        let now = env.clock.wall_ms();
        let secs = next.saturating_sub(now).div_ceil(1000);
        out.push_str(&format!("; next start in {secs} s"));
    }
    if let Some(err) = &s.error {
        out.push_str(&format!(" ({err})"));
    }
    out
}

/// The supervisor task of one actor: runs until the actor is stopped.
pub(crate) async fn supervise(ctx: Arc<Ctx>, a: Arc<Actor>) {
    let env = ctx.env.clone();
    let mut failures: u32 = 0;
    loop {
        if a.stopping() {
            break;
        }
        a.update(&env, |s| {
            s.state = State::Starting;
            s.starts += 1;
            s.next_start_ms = None;
        });
        let started = env.clock.monotonic();
        match start(&ctx, &a).await {
            Err(e) => {
                tracing::warn!(foreign = a.name(), error = %e, "foreign actor failed to start");
                a.update(&env, |s| s.error = Some(e));
                failures += 1;
            }
            Ok(child) => {
                tracing::info!(foreign = a.name(), "foreign actor running");
                a.update(&env, |s| {
                    s.state = State::Running;
                    s.error = None;
                });
                match watch(&a, &child).await {
                    Watch::Stop => {
                        a.update(&env, |s| s.state = State::Stopping);
                        stop_running(&ctx, &a, child).await;
                        break;
                    }
                    Watch::Exited(code) => {
                        let oom = cleanup(&ctx, &a, Some(child)).await;
                        tracing::warn!(
                            foreign = a.name(),
                            code = ?code,
                            oom,
                            "foreign actor exited"
                        );
                        a.update(&env, |s| {
                            s.last_exit = Some(LastExit {
                                code,
                                oom,
                                at_ms: env.clock.wall_ms(),
                            });
                            s.error = oom.then(|| "out of memory".to_owned());
                        });
                        let ran = env.clock.monotonic().saturating_sub(started);
                        failures = if ran >= ctx.timings.healthy_after {
                            1
                        } else {
                            failures + 1
                        };
                    }
                }
            }
        }
        if a.stopping() {
            break;
        }
        let delay = backoff(&ctx.timings, failures);
        a.update(&env, |s| {
            s.state = State::Backoff;
            s.next_start_ms = Some(env.clock.wall_ms() + delay.as_millis() as u64);
        });
        tokio::select! {
            biased;
            () = a.stop.notified() => break,
            () = env.clock.sleep(delay) => {}
        }
        a.update(&env, |s| s.restarts += 1);
    }
    a.update(&env, |s| {
        s.state = State::Stopped;
        s.next_start_ms = None;
    });
    a.done.store(true, Ordering::Release);
    a.finished.notify_waiters();
}

enum Watch {
    Stop,
    Exited(Option<i32>),
}

/// Waits for the child to exit or for a stop request. The child's output
/// is capped as it is written (`Stdio::Log`), so nothing rotates here.
async fn watch(a: &Actor, child: &Arc<dyn Process>) -> Watch {
    tokio::select! {
        biased;
        () = a.stop.notified() => Watch::Stop,
        r = child.wait() => Watch::Exited(r.ok().flatten()),
    }
}

/// `TERM`, `KILL` after the grace period, then clean up. A microVM is asked to
/// stop over its control port instead (ADR 0096), and how its stop went is
/// logged: whether the guest acknowledged `STOP`, how long after that the VMM
/// exited, and whether it had to be killed.
async fn stop_running(ctx: &Ctx, a: &Actor, child: Arc<dyn Process>) {
    let id = container_id(a.name());
    let log = ctx.paths.log(a.name());
    let vm = lock(&a.vm).clone();
    let acknowledged = match &vm {
        Some(vm) => match vm.shutdown(&ctx.env).await {
            Ok(()) => Some(ctx.env.clock.monotonic()),
            Err(error) => {
                tracing::warn!(foreign = a.name(), %error, "the microVM did not acknowledge STOP");
                None
            }
        },
        None => {
            let _ = run_quick(&ctx.env, a.runtime.kill(&id, "TERM", &log), COMMAND_TIMEOUT).await;
            None
        }
    };
    let exited = ctx
        .env
        .timeout(ctx.timings.stop_grace, child.wait())
        .await
        .is_ok();
    if !exited {
        if vm.is_some() {
            let _ = child.kill().await;
        } else {
            let _ = run_quick(&ctx.env, a.runtime.kill(&id, "KILL", &log), COMMAND_TIMEOUT).await;
        }
    }
    if vm.is_some() {
        match acknowledged {
            Some(at) => tracing::info!(
                foreign = a.name(),
                acknowledged = true,
                exit_ms = ctx.env.clock.monotonic().saturating_sub(at).as_millis() as u64,
                forced = !exited,
                "microVM stopped"
            ),
            None => tracing::warn!(
                foreign = a.name(),
                acknowledged = false,
                forced = !exited,
                "microVM stopped"
            ),
        }
    }
    cleanup(ctx, a, Some(child)).await;
}

/// Deletes the container and the namespace, empties the pool. Returns
/// whether the sandbox was OOM-killed.
async fn cleanup(ctx: &Ctx, a: &Actor, child: Option<Arc<dyn Process>>) -> bool {
    let name = a.name().to_owned();
    let id = container_id(&name);
    let log = ctx.paths.log(&name);
    let events = PathBuf::from("/sys/fs/cgroup")
        .join(a.cgroup.trim_start_matches('/'))
        .join("memory.events");
    let oom = std::fs::read_to_string(&events)
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("oom_kill ").map(|v| v.trim().parse::<u64>()))
        })
        .and_then(Result::ok)
        .is_some_and(|n| n > 0);
    let vm = lock(&a.vm).take();
    if vm.is_none()
        && a.runtime.engine != crate::runtime::Engine::Firecracker
        && let Err(e) = run_quick(&ctx.env, a.runtime.delete(&id, &log), COMMAND_TIMEOUT).await
    {
        tracing::warn!(foreign = %name, error = %e, "deleting the container failed");
    }
    if let Some(child) = child
        && ctx
            .env
            .timeout(COMMAND_TIMEOUT, child.wait())
            .await
            .is_err()
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    if let Some(vm) = vm {
        let _ = ctx
            .env
            .blocking("foreign-vm-cleanup", move || {
                if let Err(e) = vm.remove_files() {
                    tracing::warn!(error = %e, "deleting the microVM jail failed");
                }
            })
            .await;
    }
    a.pool.clear();
    let netns = ctx.paths.netns(&name);
    let config = ctx.paths.bundle(&name).join("config.json");
    let _ = ctx
        .env
        .blocking("foreign-cleanup", move || {
            if let Err(e) = crate::sys::delete_netns(&netns) {
                tracing::warn!(path = %netns.display(), error = %e, "deleting the network namespace failed");
            }
            let _ = std::fs::remove_file(config);
        })
        .await;
    oom
}

/// The environment variable and the secret of one `--secret` entry.
pub(crate) fn secret_binding(entry: &str) -> Result<(String, String), String> {
    let (var, secret) = match entry.split_once('=') {
        Some((v, s)) => (v.to_owned(), s.to_owned()),
        None => (
            entry.to_ascii_uppercase().replace(['-', '.'], "_"),
            entry.to_owned(),
        ),
    };
    let var_ok = var
        .bytes()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && var.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    if !var_ok {
        return Err(format!(
            "{var:?} is not an environment variable name ([A-Za-z_][A-Za-z0-9_]*)"
        ));
    }
    if !kronik_privacy::valid_name(&secret) {
        return Err(format!("{secret:?} is not a secret name"));
    }
    Ok((var, secret))
}

/// The built-in secret store, as a start reads it.
pub(crate) trait BuiltinSecrets {
    /// The current value of `name`, or `None` when it has none.
    fn current_value(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
}

impl BuiltinSecrets for SecretStore {
    fn current_value(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        self.current(name)
            .map(|found| found.map(|secret| secret.value))
            .map_err(|e| e.to_string())
    }
}

/// Why a start or an add refuses a secret that is linked to an external
/// backend: a foreign actor reads the built-in store, which holds an older
/// value of such a name or none.
pub(crate) fn linked_secret_message(secret: &str) -> String {
    format!(
        "{secret} is linked to an external secret manager, and a foreign actor reads the \
         built-in store only"
    )
}

/// The environment variables (name, text) and the injected values (secret,
/// bytes) of an actor's secrets.
type StartSecrets = (Vec<(String, String)>, Vec<(String, Vec<u8>)>);

/// The environment variables and the injected values of the `--secret`
/// entries of an actor, each at its current version (§9). A name that is
/// linked to an external backend is refused first, before the built-in store
/// is asked for it; the other names behave as they always did.
pub(crate) fn injected_secrets(
    entries: &[String],
    linked: &dyn Fn(&str) -> bool,
    store: Option<&dyn BuiltinSecrets>,
) -> Result<StartSecrets, String> {
    let mut env_vars = Vec::new();
    let mut injected = Vec::new();
    for entry in entries {
        let (var, secret) = secret_binding(entry)?;
        if linked(&secret) {
            return Err(format!(
                "SECRET_EXTERNAL: {}",
                linked_secret_message(&secret)
            ));
        }
        let value = store
            .ok_or("SECRET_NOT_FOUND: the secret store is not configured")?
            .current_value(&secret)
            .map_err(|e| format!("reading secret {secret}: {e}"))?
            .ok_or_else(|| format!("SECRET_NOT_FOUND: {secret}"))?;
        let text = String::from_utf8(value.clone())
            .map_err(|_| format!("secret {secret} is not UTF-8 text"))?;
        env_vars.push((var, text));
        injected.push((secret, value));
    }
    Ok((env_vars, injected))
}

/// Starts the sandbox and waits until a bridge connection succeeds.
async fn start(ctx: &Arc<Ctx>, a: &Arc<Actor>) -> Result<Arc<dyn Process>, String> {
    // A production restart waits for any checkpoint of this instance to finish.
    let _start_gate = a.calls.read().await;
    let env = &ctx.env;
    if !crate::runtime::is_executable(&a.runtime.program) {
        let code = match a.runtime.engine {
            crate::runtime::Engine::Runsc { .. } => "RUNSC_MISSING",
            crate::runtime::Engine::Runc => "RUNC_MISSING",
            crate::runtime::Engine::Firecracker => "FOREIGN_UNAVAILABLE",
        };
        return Err(format!(
            "{code}: {} is not an executable file",
            a.runtime.program.display()
        ));
    }
    let name = a.name().to_owned();
    // Secrets at their current version (§9).
    let store = lock(&a.secrets).clone();
    let links = lock(&a.links).clone();
    let (env_vars, injected) = injected_secrets(
        &a.decl.secrets,
        &*links,
        store.as_deref().map(|s| s as &dyn BuiltinSecrets),
    )?;
    {
        // Every value an actor of this name got since the daemon started,
        // not only the current ones: its log can still hold a rotated or
        // deleted secret's old value, also after a remove and a new add.
        let mut all = lock(&ctx.injected);
        let all = all.entry(name.clone()).or_default();
        for v in injected {
            if !all.contains(&v) {
                all.push(v);
            }
        }
    }
    ensure_image(ctx, &a.decl).await?;
    {
        let ctx = ctx.clone();
        let decl = a.decl.clone();
        let cgroup = a.cgroup.clone();
        let spec = env
            .blocking("foreign-prepare", move || {
                prepare(&ctx, &decl, env_vars, cgroup)
            })
            .await
            .ok_or("the prepare task was dropped")??;
        *lock(&a.spec) = spec;
    }
    let spawned = if a.runtime.engine == crate::runtime::Engine::Firecracker {
        start_microvm(ctx, a).await
    } else {
        env.procs
            .spawn(a.runtime.run(
                &ctx.paths.bundle(&name),
                &container_id(&name),
                &ctx.paths.log(&name),
            ))
            .await
            .map_err(|e| e.to_string())
    };
    let child = match spawned {
        Ok(child) => child,
        Err(e) => {
            // No runtime read config.json: its secret values go now.
            let config = ctx.paths.bundle(&name).join("config.json");
            let _ = env
                .blocking("foreign-config", move || std::fs::remove_file(config))
                .await;
            return Err(format!("starting {}: {e}", a.runtime.program.display()));
        }
    };
    match ready(ctx, a, &child).await {
        Ok(()) => {
            // The runtime read config.json when it created the container;
            // the copy with the secret values goes now, not at the stop
            // (runsc keeps its own in its state file under run_dir, §9).
            let config = ctx.paths.bundle(&name).join("config.json");
            let _ = env
                .blocking("foreign-config", move || std::fs::remove_file(config))
                .await;
            Ok(child)
        }
        Err(e) => {
            cleanup(ctx, a, Some(child)).await;
            Err(e)
        }
    }
}

async fn start_microvm(ctx: &Arc<Ctx>, a: &Arc<Actor>) -> Result<Arc<dyn Process>, String> {
    let env = &ctx.env;
    let directory = ctx.microvm_dir.clone();
    let assets = env
        .blocking("foreign-vm-assets", move || {
            let assets = crate::microvm_assets::Assets::load(&directory)?;
            assets.require_exec_mount()?;
            Ok::<_, String>(assets)
        })
        .await
        .ok_or("microVM asset task was dropped")??;
    let config = crate::microvm::guest_config(&lock(&a.spec), a.decl.port as u16, a.name())?;
    let bundle = ctx.paths.bundle(a.name());
    let rootfs = bundle.join("root.ext4");
    let manifest = a
        .decl
        .image
        .rsplit_once('@')
        .ok_or("microVM image is not pinned")?
        .1;
    crate::microvm_assets::rootfs(
        env,
        &assets,
        &bundle.join("rootfs"),
        &rootfs,
        manifest,
        ctx.disk_reserve,
    )
    .await?;
    let data = ctx.paths.actor(a.name()).join("data.ext4");
    crate::microvm_assets::data(
        env,
        &assets,
        &ctx.paths.data_dir(a.name()),
        &data,
        config.uid,
        config.gid,
        ctx.disk_reserve,
    )
    .await?;
    let root = a.runtime.root.join("jail");
    let instance = a
        .runtime
        .root
        .file_name()
        .ok_or("microVM runtime has no instance identity")?;
    let output = ctx.paths.actor(a.name()).join(".microvm").join(instance);
    let vm = crate::microvm::Vm::spawn(
        env,
        crate::microvm::Start {
            assets: &assets,
            root: &root,
            output: &output,
            rootfs: &rootfs,
            data: &data,
            config: &config,
            cgroup: &a.cgroup,
            cpu_millis: a.decl.cpu_millis,
            memory_bytes: a.decl.memory_bytes,
            log: &ctx.paths.log(a.name()),
            restore: false,
        },
    )
    .await?;
    let child = vm.child.clone();
    *lock(&a.vm) = Some(vm.clone());
    if let Err(error) = vm.boot(env).await {
        let _ = child.kill().await;
        cleanup(ctx, a, Some(child)).await;
        return Err(format!("{error}; see `kronik foreign logs {}`", a.name()));
    }
    Ok(child)
}

async fn ready(ctx: &Ctx, a: &Actor, child: &Arc<dyn Process>) -> Result<(), String> {
    let env = &ctx.env;
    let deadline = env.clock.monotonic() + ctx.timings.start_timeout;
    let mut last: String;
    loop {
        if a.stopping() {
            return Err("stopped while starting".into());
        }
        let attempt = tokio::select! {
            biased;
            r = child.wait() => Err(r),
            r = bridge::dial(env, &a.pool, &a.dialer) => Ok(r),
        };
        match attempt {
            Err(status) => {
                return Err(format!(
                    "the sandbox exited while starting ({}); see `kronik foreign logs {}`",
                    describe(status),
                    a.name()
                ));
            }
            Ok(Ok(sender)) => {
                a.pool.put(sender);
                return Ok(());
            }
            Ok(Err(e)) => last = e,
        }
        if env.clock.monotonic() >= deadline {
            return Err(format!(
                "not ready within {} s: {last}",
                ctx.timings.start_timeout.as_secs()
            ));
        }
        tokio::select! {
            biased;
            r = child.wait() => {
                return Err(format!(
                    "the sandbox exited while starting ({}); see `kronik foreign logs {}`",
                    describe(r),
                    a.name()
                ));
            }
            () = env.clock.sleep(ctx.timings.ready_poll) => {}
        }
    }
}

fn describe(status: std::io::Result<Option<i32>>) -> String {
    match status {
        Ok(Some(c)) => format!("exit status {c}"),
        Ok(None) => "killed by a signal".into(),
        Err(e) => format!("wait failed: {e}"),
    }
}

/// Makes sure every blob of the image is in the blob store (fetching again
/// from the recorded source if the store lost it).
async fn ensure_image(ctx: &Arc<Ctx>, decl: &pb::ForeignActor) -> Result<(), String> {
    let image = ImageRef::parse(&decl.image).map_err(|e| e.to_string())?;
    let digest = match &image {
        ImageRef::Registry { digest, .. } => digest.clone(),
        ImageRef::Layout { digest, .. } => digest
            .clone()
            .ok_or_else(|| format!("the record's image {} has no digest", decl.image))?,
    };
    let present = {
        let ctx = ctx.clone();
        let digest = digest.clone();
        ctx.env
            .clone()
            .blocking("foreign-image", move || {
                oci::Image::open(&ctx.blobs, &digest)
                    .map(|img| img.layers.iter().all(|l| ctx.blobs.has(l)))
                    .unwrap_or(false)
            })
            .await
            .unwrap_or(false)
    };
    if present {
        return Ok(());
    }
    tracing::info!(image = %decl.image, "fetching the image of a foreign actor");
    // The image is declared, so garbage collection keeps it once fetched.
    let _fetching = ctx.fetch_shared().await;
    let resolved = match image {
        ImageRef::Registry {
            registry,
            repository,
            digest,
        } => ctx
            .pull(&registry, &repository, &digest, None)
            .await
            .map_err(|e| e.to_string())?,
        ImageRef::Layout { dir, digest, .. } => ctx
            .import_layout(dir, digest, None, None)
            .await
            .map_err(|e| e.to_string())?,
    };
    if resolved.manifest_digest != digest {
        return Err(format!(
            "the image resolved to {}, the record says {digest}",
            resolved.manifest_digest
        ));
    }
    Ok(())
}

/// Blocking: bundle (rebuilt if its marker differs), data directory, network
/// namespace and `config.json`.
fn prepare(
    ctx: &Ctx,
    decl: &pb::ForeignActor,
    env_vars: Vec<(String, String)>,
    cgroup: String,
) -> Result<Vec<u8>, String> {
    let name = &decl.name;
    let p = &ctx.paths;
    let io = |what: &str, path: &Path, e: std::io::Error| format!("{what} {}: {e}", path.display());
    create_dirs(p, name)?;
    let sock = p.sock(name);
    let _ = std::fs::remove_dir_all(&sock);
    std::fs::create_dir_all(&sock).map_err(|e| io("creating", &sock, e))?;
    set_mode(&sock, 0o700)?;
    let log = p.log(name);
    crate::logs::rotate(&log, crate::logs::ROTATE_BYTES).map_err(|e| io("rotating", &log, e))?;

    let image = ImageRef::parse(&decl.image).map_err(|e| e.to_string())?;
    let digest = match image {
        ImageRef::Registry { digest, .. } => digest,
        ImageRef::Layout { digest, .. } => digest.unwrap_or_default(),
    };
    let bundle = p.bundle(name);
    let rootfs = bundle.join("rootfs");
    let marker_path = bundle.join(".kronik-bundle");
    let marker = format!("format {BUNDLE_FORMAT}\nimage {digest}\n");
    let img = oci::Image::open(&ctx.blobs, &digest).map_err(|e| e.to_string())?;
    if std::fs::read_to_string(&marker_path).ok().as_deref() != Some(marker.as_str()) {
        if bundle.exists() {
            std::fs::remove_dir_all(&bundle).map_err(|e| io("removing", &bundle, e))?;
        }
        std::fs::create_dir_all(&bundle).map_err(|e| io("creating", &bundle, e))?;
        let limits = oci::UnpackLimits {
            preserve_owners: crate::sys::is_root(),
            ..oci::UnpackLimits::default()
        };
        let stats = oci::unpack(&ctx.blobs, &img, &rootfs, &limits).map_err(|e| e.to_string())?;
        tracing::info!(foreign = %name, ?stats, "unpacked the image");
        std::fs::write(&marker_path, &marker).map_err(|e| io("writing", &marker_path, e))?;
    }
    set_mode(&bundle, 0o700)?;

    let microvm = decl.isolation == pb::Isolation::Microvm as i32;
    if !microvm && p.actor(name).join("data.ext4").exists() {
        return Err("persistent data belongs to a microVM; refusing to start a different backend with stale directory data".into());
    }
    let netns = p.netns(name);
    if !microvm {
        crate::sys::delete_netns(&netns).map_err(|e| io("removing", &netns, e))?;
        crate::sys::create_netns(&netns)
            .map_err(|e| io("creating the network namespace", &netns, e))?;
    }

    let overrides = oci::Overrides {
        cpu_millis: decl.cpu_millis,
        memory_bytes: decl.memory_bytes,
        pids: PIDS_LIMIT,
        env: env_vars,
        binds: vec![oci::Bind {
            source: p.data_dir(name),
            destination: "/data".into(),
            read_only: false,
        }],
        cgroups_path: Some(cgroup),
        netns: (!microvm).then_some(netns),
        hostname: name.clone(),
        syscall_filter: decl.isolation == pb::Isolation::Trusted as i32,
    };
    let spec = oci::runtime_spec(&img, &rootfs, &overrides).map_err(|e| e.to_string())?;
    let data = p.data_dir(name);
    if crate::sys::is_root() {
        std::os::unix::fs::chown(&data, Some(spec.uid), Some(spec.gid))
            .map_err(|e| io("chowning", &data, e))?;
    }
    let config = bundle.join("config.json");
    let bytes = serde_json::to_vec_pretty(&spec.json).map_err(|e| e.to_string())?;
    write_private(&config, &bytes).map_err(|e| io("writing", &config, e))?;
    Ok(bytes)
}

/// Only root may enter an actor's directory: its bundle holds the image and
/// config.json, its data directory the program's own files
/// (docs/design/m7-foreign.md §3). The data directory itself stays 0755,
/// so a program that drops to another user inside the sandbox (Postgres's
/// entrypoint) can still reach what it created under `/data`.
fn create_dirs(p: &Paths, name: &str) -> Result<(), String> {
    for (dir, mode) in [
        (p.data.clone(), 0o700),
        (p.actors(), 0o700),
        (p.actor(name), 0o700),
        (p.data_dir(name), 0o755),
        (p.netns_dir(), 0o700),
        (p.sock_root(), 0o700),
    ] {
        std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        set_mode(&dir, mode)?;
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// Writes a file only root can read (`config.json` holds secret values).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    if written.is_err() {
        // A partial copy of the secret values must not stay either.
        let _ = std::fs::remove_file(path);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_actor_directory_is_private_and_its_data_directory_traversable() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let p = Paths {
            data: tmp.path().join("foreign"),
            run: tmp.path().join("run"),
        };
        create_dirs(&p, "pg").unwrap();
        let mode = |d: PathBuf| std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(p.actor("pg")), mode(p.data_dir("pg"))),
            (0o700, 0o755)
        );
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let t = Timings::default();
        let ms = |n| backoff(&t, n).as_millis();
        assert_eq!(
            [ms(0), ms(1), ms(2), ms(3), ms(4)],
            [500, 500, 1000, 2000, 4000]
        );
        assert_eq!(ms(8), 60_000);
        assert_eq!(ms(1000), 60_000);
    }

    #[test]
    fn secret_entries_name_their_variable() {
        assert_eq!(
            secret_binding("stripe-key").unwrap(),
            ("STRIPE_KEY".into(), "stripe-key".into())
        );
        assert_eq!(
            secret_binding("payments.api-key").unwrap(),
            ("PAYMENTS_API_KEY".into(), "payments.api-key".into())
        );
        assert_eq!(
            secret_binding("API_KEY=stripe-key").unwrap(),
            ("API_KEY".into(), "stripe-key".into())
        );
        assert!(secret_binding("1X=stripe-key").is_err());
        assert!(secret_binding("A-B=stripe-key").is_err());
        assert!(secret_binding("X=Bad Name").is_err());
    }

    /// A built-in store that counts what a start asks of it. The values are
    /// older than anything a backend serves for the same name.
    struct Store {
        values: Vec<(&'static str, &'static str)>,
        asked: Mutex<Vec<String>>,
    }

    impl BuiltinSecrets for Store {
        fn current_value(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            lock(&self.asked).push(name.to_owned());
            Ok(self
                .values
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.as_bytes().to_vec()))
        }
    }

    fn store() -> Store {
        Store {
            values: vec![("stripe", "stale-built-in-value"), ("plain", "plain-value")],
            asked: Mutex::new(Vec::new()),
        }
    }

    fn entries(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// A name linked to an external backend is refused with `SECRET_EXTERNAL`
    /// before the built-in store is asked for it, whatever the store holds:
    /// the value of the store (stale, here) is neither injected nor in the
    /// error, and the entries before it inject nothing. A store that is not
    /// configured does not change the answer.
    #[test]
    fn a_start_refuses_a_linked_name_before_it_reads_the_store() {
        let s = store();
        let linked = |name: &str| name == "stripe";
        let e = injected_secrets(&entries(&["plain", "stripe"]), &linked, Some(&s)).unwrap_err();
        assert!(e.starts_with("SECRET_EXTERNAL: stripe is linked"), "{e}");
        assert!(!e.contains("stale-built-in-value"), "{e}");
        assert_eq!(*lock(&s.asked), ["plain"], "the store was asked for stripe");
        let e = injected_secrets(&entries(&["stripe"]), &linked, None).unwrap_err();
        assert!(e.starts_with("SECRET_EXTERNAL: "), "{e}");
    }

    /// A name that is not linked is injected as it always was, with the same
    /// errors for a missing name or no store.
    #[test]
    fn a_start_injects_names_that_are_not_linked_as_before() {
        let s = store();
        let (vars, values) =
            injected_secrets(&entries(&["TOKEN=plain"]), &|_| false, Some(&s)).unwrap();
        assert_eq!(vars, [("TOKEN".to_owned(), "plain-value".to_owned())]);
        assert_eq!(values, [("plain".to_owned(), b"plain-value".to_vec())]);
        let e = injected_secrets(&entries(&["missing"]), &|_| false, Some(&s)).unwrap_err();
        assert_eq!(e, "SECRET_NOT_FOUND: missing");
        let e = injected_secrets(&entries(&["plain"]), &|_| false, None).unwrap_err();
        assert_eq!(e, "SECRET_NOT_FOUND: the secret store is not configured");
    }

    /// The question is asked at every start: a name linked after the actor
    /// was declared (or after it last started) is refused by its next start,
    /// and the start after an unlink gets the built-in value again.
    #[test]
    fn the_next_start_follows_a_link_made_and_removed_later() {
        let s = store();
        let linked = std::sync::atomic::AtomicBool::new(false);
        let view = |name: &str| name == "stripe" && linked.load(Ordering::SeqCst);
        let start = || injected_secrets(&entries(&["stripe"]), &view, Some(&s));
        assert_eq!(start().unwrap().1[0].1, b"stale-built-in-value");
        linked.store(true, Ordering::SeqCst);
        assert!(start().unwrap_err().starts_with("SECRET_EXTERNAL: "));
        linked.store(false, Ordering::SeqCst);
        assert_eq!(start().unwrap().1[0].1, b"stale-built-in-value");
    }
}
