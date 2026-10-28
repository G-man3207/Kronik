//! [`Foreign`]: the daemon's foreign actors (docs/design/m7-foreign.md).
//! The node calls it as a [`ForeignHost`] (reconcile at start and after
//! every add or remove, and the bridge for `foreign://`); the API calls it
//! to validate an add, to show status and to read logs.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::env::{BoxFuture, Env, HttpRequest, HttpResponse, NetError};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_effects::foreign::{ForeignHost, unavailable, valid_name};
use kronik_privacy::SecretStore;
use kronik_proto::log::v1 as pb;

use crate::blobs::BlobStore;
use crate::fetch::{FetchOptions, Resolved};
use crate::image::{ImageError, ImageRef};
use crate::runtime::{Engine, Runtime, container_id, find_runc, is_executable, run_quick};
use crate::supervisor::{Actor, Ctx, Paths, State, Status, Timings, secret_binding, supervise};

/// The tested gVisor release (ADR 0003).
pub const TESTED_RUNSC: &str = "release-20261019.0";
/// How long reconcile waits for newly started actors in total.
const RECONCILE_WAIT: Duration = Duration::from_secs(30);
/// How long a call waits for a starting or restarting actor.
const CALL_WAIT: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `[foreign] platform`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `systrap`, as the brief says; `kvm` only when chosen.
    Auto,
    Systrap,
    Kvm,
}

/// An actor's isolation level (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    Gvisor,
    Trusted,
    Microvm,
}

impl Isolation {
    pub fn parse(s: &str) -> Option<Isolation> {
        match s {
            "gvisor" => Some(Isolation::Gvisor),
            "trusted" => Some(Isolation::Trusted),
            "microvm" => Some(Isolation::Microvm),
            _ => None,
        }
    }

    pub fn from_pb(v: i32) -> Option<Isolation> {
        match pb::Isolation::try_from(v).ok()? {
            pb::Isolation::Gvisor => Some(Isolation::Gvisor),
            pb::Isolation::Trusted => Some(Isolation::Trusted),
            pb::Isolation::Microvm => Some(Isolation::Microvm),
            pb::Isolation::Unspecified => None,
        }
    }

    pub fn to_pb(self) -> i32 {
        (match self {
            Isolation::Gvisor => pb::Isolation::Gvisor,
            Isolation::Trusted => pb::Isolation::Trusted,
            Isolation::Microvm => pb::Isolation::Microvm,
        }) as i32
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Isolation::Gvisor => "gvisor",
            Isolation::Trusted => "trusted",
            Isolation::Microvm => "microvm",
        }
    }
}

/// The warning every `trusted` add carries.
pub const TRUSTED_WARNING: &str = "isolation trusted runs the image with plain runc and the host kernel: only use it for images you trust";

/// The daemon's settings for foreign actors.
#[derive(Debug, Clone)]
pub struct ForeignConfig {
    /// Kronik's data directory; foreign actors live under `foreign/`.
    pub data_dir: PathBuf,
    /// `[foreign] run_dir` (default `/run/kronik`).
    pub run_dir: PathBuf,
    /// `[foreign] runsc_path`.
    pub runsc_path: PathBuf,
    pub platform: Platform,
    /// Registries (`host:port`) pulled over plain HTTP. Tests only; not in
    /// `kronik.toml`.
    pub insecure_registries: Vec<String>,
    /// `[foreign] layout_dirs`: directories whose `oci-layout:` images an
    /// `operate` token may add; any other directory needs `admin` (§4).
    pub layout_dirs: Vec<PathBuf>,
    /// `[foreign] pull_timeout`: the longest one image fetch may take.
    pub pull_timeout: Duration,
}

/// `kronik foreign add` as the API received it.
#[derive(Debug, Clone, Default)]
pub struct AddRequest {
    pub name: String,
    pub image: String,
    pub port: u32,
    pub cpu_millis: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub isolation: Option<String>,
    pub secrets: Vec<String>,
    /// The caller may read an `oci-layout:` directory outside
    /// `layout_dirs` (the `admin` scope).
    pub any_layout_dir: bool,
    /// The free bytes above `[log] disk_reserve`: an image whose new layers
    /// need more is refused before it is fetched (None: no reserve).
    pub max_new_bytes: Option<u64>,
}

/// `dir` resolved, when it is inside one of `allowed`: first by its
/// components (no `..`), then after resolving symbolic links, so a link
/// inside an allowed directory cannot lead out of it. Only the second step
/// touches the file system.
// shortcut: checked once, then the import opens paths under the resolved
// directory again; a link swapped into the layout's directory chain after
// the check is followed (O_NOFOLLOW covers each file, not its parents).
// Blobs are digest-checked, read as regular files and bounded, so this
// reads at most a planted image; use openat2(RESOLVE_BENEATH) if the
// layout directories are writable by others.
fn allowed_layout_dir(dir: &std::path::Path, allowed: &[PathBuf]) -> Option<PathBuf> {
    use std::path::Component;
    if dir
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    if !allowed.iter().any(|a| dir.starts_with(a)) {
        return None;
    }
    let real = dir.canonicalize().ok()?;
    allowed
        .iter()
        .filter_map(|a| a.canonicalize().ok())
        .any(|a| real.starts_with(a))
        .then_some(real)
}

/// A validated add: the record to write (without epoch and audit) and the
/// warnings to show. Its image is kept from garbage collection until the
/// plan is passed to [`Foreign::finish_add`] (or dropped).
#[derive(Debug, Clone)]
pub struct AddPlan {
    pub record: pb::ForeignActor,
    pub warnings: Vec<String>,
    pub hold: Arc<AddHold>,
}

/// Keeps an add's image (manifest digest) out of garbage collection while
/// the add is between its fetch and its record.
pub struct AddHold {
    ctx: Arc<Ctx>,
    digest: String,
}

impl std::fmt::Debug for AddHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddHold")
            .field("digest", &self.digest)
            .finish()
    }
}

impl AddHold {
    fn new(ctx: &Arc<Ctx>, digest: String) -> Arc<AddHold> {
        *lock(&ctx.adding).entry(digest.clone()).or_insert(0) += 1;
        Arc::new(AddHold {
            ctx: ctx.clone(),
            digest,
        })
    }
}

impl Drop for AddHold {
    fn drop(&mut self) {
        let mut adding = lock(&self.ctx.adding);
        if let Some(n) = adding.get_mut(&self.digest) {
            *n -= 1;
            if *n == 0 {
                adding.remove(&self.digest);
            }
        }
    }
}

/// The last lines of an actor's log.
#[derive(Debug, Clone)]
pub struct LogTail {
    pub lines: Vec<String>,
    pub truncated: bool,
}

/// What [`Foreign::cleanup`] removed, and how many it could not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cleaned {
    pub sandboxes: u64,
    pub namespaces: u64,
    /// `bundle/config.json` files, which hold injected secret values.
    pub configs: u64,
    /// Sandboxes, namespaces or runtime listings that could not be removed
    /// or read (each logged as a warning).
    pub failed: u64,
}

/// The foreign actors of one daemon.
pub struct Foreign {
    ctx: Arc<Ctx>,
    cfg: ForeignConfig,
    actors: Mutex<BTreeMap<String, Arc<Actor>>>,
    /// Serializes reconciles; true once leftovers were cleaned up.
    reconcile: tokio::sync::Mutex<bool>,
    /// The lock on `run_dir` (held for the daemon's life), or why this
    /// daemon runs no foreign actors: another daemon holds it (§3).
    run_lock: Result<std::fs::File, String>,
    /// Why `foreign/` could not be prepared (the move to `actors/`): no
    /// actor starts and adds are refused, so none runs on an empty `/data`.
    layout: Result<(), String>,
}

/// `<run_dir>/foreign.lock`: one daemon per run directory, because start
/// deletes every sandbox and namespace under it.
pub const RUN_LOCK: &str = "foreign.lock";

/// Takes the lock on `run` (exclusive, released when the process exits).
fn lock_run_dir(run: &std::path::Path) -> Result<std::fs::File, String> {
    let path = run.join(RUN_LOCK);
    std::fs::create_dir_all(run).map_err(|e| format!("creating {}: {e}", run.display()))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| format!("opening {}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(format!(
            "another kronik serve uses [foreign] run_dir {}; give each daemon its own run_dir",
            run.display()
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("locking {}: {e}", path.display())),
    }
}

fn image_error(e: ImageError) -> ApiError {
    match e {
        ImageError::Invalid(m) => ApiError::new(ErrorCode::ImageInvalid, m),
        ImageError::Io(m) => ApiError::new(ErrorCode::Internal, m),
        ImageError::NoSpace(m) => ApiError::new(ErrorCode::Unavailable, m).with_hint(
            "Free disk space on the data directory's file system, or lower [log] \
             disk_reserve, then add the actor again.",
        ),
        ImageError::TimedOut(m) => ApiError::new(ErrorCode::ForeignUnavailable, m).with_hint(
            "The registry (or layout directory) did not answer within [foreign] pull_timeout: \
             check that it is reachable, or raise pull_timeout, then add the actor again.",
        ),
    }
}

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, m)
}

impl Drop for Foreign {
    fn drop(&mut self) {
        // Ends the garbage collection task.
        self.ctx.gc_wake.notify_one();
    }
}

impl Foreign {
    pub fn new(env: Env, cfg: ForeignConfig) -> Arc<Foreign> {
        Foreign::with_timings(env, cfg, Timings::default())
    }

    pub(crate) fn with_timings(env: Env, cfg: ForeignConfig, timings: Timings) -> Arc<Foreign> {
        let paths = Paths {
            data: cfg.data_dir.join("foreign"),
            run: cfg.run_dir.clone(),
        };
        let root = paths.run.join("runsc");
        let instance = blake3::hash(root.as_os_str().as_encoded_bytes()).to_hex();
        let ctx = Ctx {
            env,
            blobs: BlobStore::new(paths.blobs()),
            paths,
            fetch: FetchOptions {
                insecure_registries: cfg.insecure_registries.clone(),
                max_new_bytes: None,
            },
            pull_timeout: cfg.pull_timeout,
            timings,
            cgroup_parent: format!("/kronik/{}", &instance.as_str()[..8]),
            injected: Mutex::new(BTreeMap::new()),
            fetching: tokio::sync::RwLock::new(()),
            gc_pending: std::sync::atomic::AtomicBool::new(false),
            gc_wake: Arc::new(tokio::sync::Notify::new()),
            adding: Mutex::new(BTreeMap::new()),
        };
        let run_lock = lock_run_dir(&ctx.paths.run);
        // Under the run lock: no other daemon moves or starts actors from
        // here meanwhile.
        let layout = match &run_lock {
            Err(_) => Ok(()),
            Ok(_) => crate::layout::migrate(&ctx.paths.data)
                // Before any runtime call (cleanup at start included).
                .and_then(|()| crate::layout::private_runtime_roots(&ctx.paths.run))
                .map_err(|e| {
                    format!(
                        "preparing {} failed: {e}; foreign actors stay stopped until it is fixed",
                        ctx.paths.data.display()
                    )
                }),
        };
        if run_lock.is_ok() && layout.is_ok() {
            // Partial blobs of fetches a stopped or killed daemon left.
            let n = ctx.blobs.remove_temps();
            if n > 0 {
                tracing::info!(files = n, "deleted partial image blobs");
            }
        }
        let foreign = Foreign {
            ctx: Arc::new(ctx),
            cfg,
            actors: Mutex::new(BTreeMap::new()),
            reconcile: tokio::sync::Mutex::new(false),
            run_lock,
            layout,
        };
        if let Some(why) = foreign.off() {
            tracing::error!(why, "foreign actors are off in this daemon");
        }
        let foreign = Arc::new(foreign);
        // Runs a garbage collection round that a fetch made skip, once the
        // fetch is over; ends with the manager (its `Drop` wakes it).
        let (weak, wake) = (Arc::downgrade(&foreign), foreign.ctx.gc_wake.clone());
        drop(foreign.ctx.env.spawn("foreign-gc", async move {
            loop {
                wake.notified().await;
                let Some(f) = weak.upgrade() else { break };
                if f.ctx
                    .gc_pending
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    f.collect_unused().await;
                }
            }
        }));
        foreign
    }

    /// Why this daemon runs no foreign actors, if it does not.
    pub fn off(&self) -> Option<String> {
        let lock = self.run_lock.as_ref().err();
        lock.or(self.layout.as_ref().err()).cloned()
    }

    fn runsc(&self, platform: &str) -> Runtime {
        Runtime {
            engine: Engine::Runsc {
                platform: platform.to_owned(),
            },
            program: self.cfg.runsc_path.clone(),
            root: self.ctx.paths.run.join("runsc"),
        }
    }

    fn runc(&self) -> Runtime {
        Runtime {
            engine: Engine::Runc,
            program: find_runc().unwrap_or_else(|| PathBuf::from("/usr/bin/runc")),
            root: self.ctx.paths.run.join("runc"),
        }
    }

    fn runtime_for(&self, decl: &pb::ForeignActor) -> Runtime {
        match Isolation::from_pb(decl.isolation) {
            Some(Isolation::Trusted) => self.runc(),
            _ => self.runsc(if decl.platform.is_empty() {
                "systrap"
            } else {
                &decl.platform
            }),
        }
    }

    /// Validates an add and resolves its image into the blob store
    /// (digests verified). Nothing is written to the log.
    pub async fn prepare_add(
        &self,
        req: AddRequest,
        secrets: Option<&SecretStore>,
    ) -> Result<AddPlan, ApiError> {
        if let Some(why) = self.off() {
            return Err(ApiError::new(ErrorCode::ForeignUnavailable, why).with_hint(
                "Another daemon uses [foreign] run_dir (give each daemon its own), or the \
                 foreign actors' directory could not be prepared: the message says which.",
            ));
        }
        if !valid_name(&req.name) {
            return Err(bad(format!(
                "{:?} is not a foreign actor name (DNS-style labels of a-z, 0-9 and -, joined \
                 by dots, at most 63 characters)",
                req.name
            )));
        }
        if req.port == 0 || req.port > 65535 {
            return Err(bad(format!("port {} is not between 1 and 65535", req.port)));
        }
        let cpu_millis = req.cpu_millis.unwrap_or(1000);
        if !(10..=1_000_000).contains(&cpu_millis) {
            return Err(bad("cpu must be between 0.01 and 1000 CPUs"));
        }
        let memory_bytes = req.memory_bytes.unwrap_or(512 << 20);
        if memory_bytes < 16 << 20 {
            return Err(bad("memory must be at least 16Mi"));
        }
        let isolation = match req.isolation.as_deref() {
            None => Isolation::Gvisor,
            Some(s) => Isolation::parse(s).ok_or_else(|| {
                bad(format!(
                    "isolation {s:?} is not one of gvisor, trusted, microvm"
                ))
            })?,
        };
        let mut warnings = Vec::new();
        let platform = match isolation {
            Isolation::Microvm => {
                return Err(ApiError::new(
                    ErrorCode::NotImplemented,
                    "isolation microvm (Firecracker) is reserved and not implemented in v0.1; \
                     use gvisor",
                ));
            }
            Isolation::Trusted => {
                if find_runc().is_none() {
                    return Err(ApiError::new(
                        ErrorCode::RuncMissing,
                        "no runc in /usr/local/sbin, /usr/local/bin, /usr/sbin or /usr/bin",
                    ));
                }
                warnings.push(TRUSTED_WARNING.to_owned());
                String::new()
            }
            Isolation::Gvisor => {
                if !is_executable(&self.cfg.runsc_path) {
                    return Err(ApiError::new(
                        ErrorCode::RunscMissing,
                        format!(
                            "{} is not an executable file",
                            self.cfg.runsc_path.display()
                        ),
                    ));
                }
                match self.cfg.platform {
                    Platform::Auto | Platform::Systrap => "systrap".to_owned(),
                    Platform::Kvm => {
                        if let Err(e) = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open("/dev/kvm")
                        {
                            return Err(ApiError::new(
                                ErrorCode::KvmUnavailable,
                                format!("[foreign] platform is kvm, but /dev/kvm: {e}"),
                            ));
                        }
                        "kvm".to_owned()
                    }
                }
            }
        };
        let mut bindings: Vec<String> = Vec::new();
        let mut vars = std::collections::BTreeSet::new();
        for entry in &req.secrets {
            let (var, secret) = secret_binding(entry).map_err(bad)?;
            if !vars.insert(var.clone()) {
                return Err(bad(format!("two secrets set the variable {var}")));
            }
            let exists = secrets
                .map(|s| s.current(&secret))
                .transpose()
                .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
                .flatten()
                .is_some();
            if !exists {
                return Err(ApiError::new(
                    ErrorCode::SecretNotFound,
                    format!("no secret {secret}; set it with `kronik secret set {secret}`"),
                ));
            }
            bindings.push(format!("{var}={secret}"));
        }
        let image = ImageRef::parse(&req.image).map_err(image_error)?;
        // The daemon reads a layout as root: outside the operator's
        // allowlist only an admin may make it read a host directory.
        let image = match image {
            ImageRef::Layout {
                dir,
                digest,
                reference,
            } if !req.any_layout_dir => {
                let Some(real) = self.allowed_layout_dir(dir.clone()).await? else {
                    return Err(ApiError::new(
                        ErrorCode::ScopeMissing,
                        format!(
                            "oci-layout:{} is outside [foreign] layout_dirs; images from other \
                             directories need the admin scope",
                            dir.display()
                        ),
                    )
                    .with_hint(
                        "Put the layout under a directory of [foreign] layout_dirs in \
                         kronik.toml, or add it with an admin token.",
                    ));
                };
                ImageRef::Layout {
                    dir: real,
                    digest,
                    reference,
                }
            }
            other => other,
        };
        let (resolved, hold) = match self.resolve(image, req.max_new_bytes).await {
            Ok(done) => done,
            Err(e) => {
                // What the failed fetch stored is no actor's: it goes now.
                self.collect_unused().await;
                return Err(e);
            }
        };
        Ok(AddPlan {
            record: pb::ForeignActor {
                name: req.name,
                image: resolved.pinned,
                port: req.port,
                cpu_millis,
                memory_bytes,
                isolation: isolation.to_pb(),
                secrets: bindings,
                platform,
                ..Default::default()
            },
            warnings,
            hold,
        })
    }

    /// Ends an add: its image is no longer held for it. When the record was
    /// not written (`kept` false: a dry run, a refused or failed write), the
    /// blobs no declared actor needs are deleted now.
    pub async fn finish_add(&self, plan: AddPlan, kept: bool) {
        drop(plan);
        if !kept {
            self.collect_unused().await;
        }
    }

    /// The declarations of the actors this daemon supervises.
    fn declared(&self) -> Vec<pb::ForeignActor> {
        lock(&self.actors)
            .values()
            .map(|a| a.decl.clone())
            .collect()
    }

    /// [`allowed_layout_dir`] on a blocking thread, given up after
    /// `pull_timeout` (resolving a path on a hung network mount blocks).
    async fn allowed_layout_dir(&self, dir: PathBuf) -> Result<Option<PathBuf>, ApiError> {
        let allowed = self.cfg.layout_dirs.clone();
        let check = self.ctx.env.blocking("foreign-layout-dir", move || {
            allowed_layout_dir(&dir, &allowed)
        });
        match self.ctx.env.timeout(self.ctx.pull_timeout, check).await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(ApiError::new(
                ErrorCode::Internal,
                "the check task was dropped",
            )),
            Err(_) => Err(ApiError::new(
                ErrorCode::ImageInvalid,
                format!(
                    "resolving the layout directory took longer than {} s ([foreign] pull_timeout)",
                    self.ctx.pull_timeout.as_secs()
                ),
            )),
        }
    }

    /// Fetches and verifies an image into the blob store, within `budget`
    /// new bytes, and holds it from garbage collection for the add.
    async fn resolve(
        &self,
        image: ImageRef,
        budget: Option<u64>,
    ) -> Result<(Resolved, Arc<AddHold>), ApiError> {
        let ctx = self.ctx.clone();
        // Shared with other fetches, exclusive with garbage collection,
        // until the image is held.
        let _fetching = ctx.fetch_shared().await;
        let resolved = match image {
            ImageRef::Registry {
                registry,
                repository,
                digest,
            } => ctx
                .pull(&registry, &repository, &digest, budget)
                .await
                .map_err(image_error)?,
            ImageRef::Layout {
                dir,
                digest,
                reference,
            } => {
                if !dir.is_absolute() {
                    return Err(ApiError::new(
                        ErrorCode::ImageInvalid,
                        format!(
                            "oci-layout:{} must be an absolute directory (the CLI makes it absolute)",
                            dir.display()
                        ),
                    ));
                }
                ctx.import_layout(dir, digest, reference, budget)
                    .await
                    .map_err(image_error)?
            }
        };
        // The image must open (platform, config) before it is declared.
        let c = ctx.clone();
        let digest = resolved.manifest_digest.clone();
        ctx.env
            .blocking("foreign-image", move || {
                crate::oci::Image::open(&c.blobs, &digest).map(|_| ())
            })
            .await
            .ok_or_else(|| ApiError::new(ErrorCode::Internal, "the image task was dropped"))?
            .map_err(image_error)?;
        let hold = AddHold::new(&ctx, resolved.manifest_digest.clone());
        Ok((resolved, hold))
    }

    /// The supervision state of a running actor (`None`: not supervised
    /// here, e.g. removed).
    pub fn status(&self, name: &str) -> Option<Status> {
        lock(&self.actors).get(name).map(|a| a.status())
    }

    /// Waits until `name` has left `starting`, at most `timeout`.
    pub async fn settled(&self, name: &str, timeout: Duration) {
        let actor = lock(&self.actors).get(name).cloned();
        if let Some(a) = actor {
            a.settled(&self.ctx.env, timeout).await;
        }
    }

    /// The last `tail` lines of `name`'s log, with exact occurrences of
    /// `secrets` (and of the values injected into the actor) scrubbed.
    /// `None` when the actor never had a log.
    pub async fn logs(
        &self,
        name: &str,
        tail: usize,
        secrets: Vec<(String, Vec<u8>)>,
    ) -> Result<Option<LogTail>, ApiError> {
        if !valid_name(name) {
            return Ok(None);
        }
        let mut secrets = secrets;
        if let Some(values) = lock(&self.ctx.injected).get(name) {
            secrets.extend(values.iter().cloned());
        }
        let log = self.ctx.paths.log(name);
        let log2 = log.clone();
        let r = self
            .ctx
            .env
            .blocking("foreign-logs", move || {
                if !log2.exists() && !crate::logs::rotated(&log2).exists() {
                    return Ok(None);
                }
                crate::logs::tail(&log2, tail, &secrets).map(Some)
            })
            .await
            .ok_or_else(|| ApiError::new(ErrorCode::Internal, "the log task was dropped"))?
            .map_err(|e| {
                ApiError::new(
                    ErrorCode::ForeignUnavailable,
                    format!("reading {}: {e}", log.display()),
                )
            })?;
        Ok(r.map(|(lines, truncated)| LogTail { lines, truncated }))
    }

    /// Stops every sandbox (daemon shutdown) and removes this daemon's
    /// cgroup parent once it is empty.
    pub async fn shutdown(&self) {
        let actors: Vec<Arc<Actor>> = std::mem::take(&mut *lock(&self.actors))
            .into_values()
            .collect();
        for a in actors {
            tracing::info!(foreign = a.name(), "stopping foreign actor");
            a.stop().await;
        }
        if self.run_lock.is_ok() {
            self.remove_cgroup_parent();
        }
    }

    /// Deletes the blobs no declared actor's image needs (after a remove, a
    /// failed or a dry-run add), so images do not pile up on the data disk.
    /// Exclusive with every fetch; the images of adds in progress are kept.
    /// While a fetch runs, this round is skipped rather than waited for (a
    /// stalled registry would hang the caller until `pull_timeout`): it runs
    /// when the last fetch ends, and every start collects once at its first
    /// reconcile.
    async fn collect_garbage(&self, declared: Vec<pb::ForeignActor>) {
        if self.off().is_some() {
            return;
        }
        let ctx = self.ctx.clone();
        use std::sync::atomic::Ordering::SeqCst;
        let _gc = match ctx.fetching.try_write() {
            Ok(gc) => gc,
            Err(_) => {
                // Pending first, then look again: a fetch ending in between
                // either sees the flag or leaves the lock free here.
                ctx.gc_pending.store(true, SeqCst);
                match ctx.fetching.try_write() {
                    Ok(gc) => {
                        ctx.gc_pending.store(false, SeqCst);
                        gc
                    }
                    Err(_) => {
                        tracing::debug!(
                            "image garbage collection deferred: a fetch is in progress"
                        );
                        return;
                    }
                }
            }
        };
        let mut digests: Vec<String> = declared
            .iter()
            .filter_map(|d| match ImageRef::parse(&d.image) {
                Ok(ImageRef::Registry { digest, .. }) => Some(digest),
                Ok(ImageRef::Layout {
                    digest: Some(digest),
                    ..
                }) => Some(digest),
                _ => None,
            })
            .collect();
        digests.extend(lock(&ctx.adding).keys().cloned());
        let c = ctx.clone();
        let deleted = ctx
            .env
            .clone()
            .blocking("foreign-gc", move || {
                let mut keep = std::collections::HashSet::new();
                for digest in &digests {
                    match crate::oci::Image::open(&c.blobs, digest) {
                        Ok(img) => keep.extend(img.blobs().map(str::to_owned)),
                        // Not complete: keep everything, the next start
                        // fetches the rest.
                        Err(_) => return 0,
                    }
                }
                c.blobs.collect_garbage(&keep)
            })
            .await
            .unwrap_or(0);
        if deleted > 0 {
            tracing::info!(blobs = deleted, "deleted image blobs no foreign actor uses");
        }
    }

    /// [`Foreign::collect_garbage`] outside a reconcile: serialized with
    /// reconciles (the supervised actors are the declared ones), and not
    /// before the first one.
    async fn collect_unused(&self) {
        let reconciled = self.reconcile.lock().await;
        if *reconciled {
            self.collect_garbage(self.declared()).await;
        }
    }

    /// `kronik foreign cleanup` (the unit's `ExecStopPost=`): after the
    /// daemon stopped, crashed or was killed, deletes what its sandboxes
    /// left: containers, network namespaces, bridge sockets, every
    /// `config.json` (which holds secret values) and the cgroup parent.
    /// Refused while a daemon holds `run_dir`; works when the layout of
    /// `foreign/` could not be prepared (it touches no actor's data).
    pub async fn cleanup(&self) -> Result<Cleaned, String> {
        if let Err(why) = &self.run_lock {
            return Err(why.clone());
        }
        let cleaned = self.cleanup_leftovers().await;
        self.remove_cgroup_parent();
        Ok(cleaned)
    }

    /// `rmdir` of `/sys/fs/cgroup/kronik/<instance>`: it fails, harmlessly,
    /// while a sandbox's cgroup is still in it.
    fn remove_cgroup_parent(&self) {
        let dir = std::path::Path::new("/sys/fs/cgroup")
            .join(self.ctx.cgroup_parent.trim_start_matches('/'));
        let _ = std::fs::remove_dir(dir);
    }

    /// Kills and deletes every container under Kronik's runtime roots and
    /// removes leftover namespaces, sockets and `config.json` files (§5).
    async fn cleanup_leftovers(&self) -> Cleaned {
        let env = &self.ctx.env;
        let mut cleaned = Cleaned::default();
        for rt in [self.runsc("systrap"), self.runc()] {
            if !is_executable(&rt.program) || !rt.root.exists() {
                continue;
            }
            let out = self
                .ctx
                .paths
                .run
                .join(format!("list-{}.out", std::process::id()));
            let _ = std::fs::remove_file(&out);
            let listed = run_quick(env, rt.list(&out), Duration::from_secs(10)).await;
            if !matches!(listed, Ok(Some(0))) {
                tracing::warn!(runtime = %rt.program.display(), result = ?listed, "listing leftover containers failed");
                cleaned.failed += 1;
                continue;
            }
            let ids = std::fs::read_to_string(&out).unwrap_or_default();
            let _ = std::fs::remove_file(&out);
            let mut ids: Vec<&str> = ids
                .lines()
                .map(str::trim)
                .filter(|i| i.starts_with("kronik-foreign-"))
                .collect();
            // Longest first: runsc refuses an id that is a prefix of another
            // still there, as `kronik-foreign-<name>` ids from before they
            // had one length can be.
            ids.sort_by_key(|i| std::cmp::Reverse(i.len()));
            for id in ids {
                tracing::warn!(id, "deleting a leftover foreign sandbox");
                let log = self.ctx.paths.run.join("leftovers.log");
                let _ = run_quick(env, rt.kill(id, "KILL", &log), Duration::from_secs(10)).await;
                match run_quick(env, rt.delete(id, &log), Duration::from_secs(10)).await {
                    Ok(Some(0)) => cleaned.sandboxes += 1,
                    other => {
                        tracing::warn!(id, result = ?other, "deleting a leftover foreign sandbox failed");
                        cleaned.failed += 1;
                    }
                }
            }
        }
        let netns = self.ctx.paths.netns_dir();
        let sock = self.ctx.paths.sock_root();
        let actors = self.ctx.paths.actors();
        // runsc binds a namespace here for its sandboxes and leaves it
        // mounted after the last one; no sandbox of this run_dir is left.
        let null_netns = self.ctx.paths.run.join("runsc").join("null-netns");
        let files = env
            .blocking("foreign-cleanup", move || {
                let (mut namespaces, mut failed) = (0, 0);
                if let Ok(entries) = std::fs::read_dir(&netns) {
                    for e in entries.flatten() {
                        match crate::sys::delete_netns(&e.path()) {
                            Ok(()) => namespaces += 1,
                            Err(err) => {
                                failed += 1;
                                tracing::warn!(path = %e.path().display(), error = %err, "removing a leftover network namespace failed");
                            }
                        }
                    }
                }
                if null_netns.exists()
                    && let Err(err) = crate::sys::delete_netns(&null_netns)
                {
                    failed += 1;
                    tracing::warn!(path = %null_netns.display(), error = %err, "removing runsc's null network namespace failed");
                }
                let _ = std::fs::remove_dir_all(&sock);
                // A config.json outlives its sandbox only when the daemon
                // did not stop it; it holds the injected secret values.
                let mut configs = 0;
                if let Ok(entries) = std::fs::read_dir(&actors) {
                    for e in entries.flatten() {
                        if std::fs::remove_file(e.path().join("bundle/config.json")).is_ok() {
                            configs += 1;
                        }
                    }
                }
                (namespaces, configs, failed)
            })
            .await;
        if let Some((namespaces, configs, failed)) = files {
            cleaned.namespaces = namespaces;
            cleaned.configs = configs;
            cleaned.failed += failed;
        }
        cleaned
    }

    async fn reconcile_now(
        self: Arc<Self>,
        declared: Vec<pb::ForeignActor>,
        secrets: Option<Arc<SecretStore>>,
    ) {
        let mut cleaned = self.reconcile.lock().await;
        if self.run_lock.is_err() {
            // Another daemon owns run_dir: touch none of its sandboxes.
            return;
        }
        let first = !*cleaned;
        if first {
            // Also when the layout move failed: a killed daemon's
            // sandboxes go even if no actor of this one may start.
            self.cleanup_leftovers().await;
            *cleaned = true;
        }
        if let Err(why) = &self.layout {
            tracing::error!(why, "no foreign actor starts");
            return;
        }
        let wanted: BTreeMap<String, pb::ForeignActor> =
            declared.into_iter().map(|d| (d.name.clone(), d)).collect();
        let stale: Vec<Arc<Actor>> = {
            let mut actors = lock(&self.actors);
            let names: Vec<String> = actors
                .iter()
                .filter(|(n, a)| wanted.get(*n) != Some(&a.decl))
                .map(|(n, _)| n.clone())
                .collect();
            names.iter().filter_map(|n| actors.remove(n)).collect()
        };
        let mut removed = false;
        for a in stale {
            tracing::info!(foreign = a.name(), "stopping foreign actor");
            a.stop().await;
            if !wanted.contains_key(a.name()) {
                removed = true;
                let bundle = self.ctx.paths.bundle(a.name());
                let _ = self
                    .ctx
                    .env
                    .blocking("foreign-cleanup", move || std::fs::remove_dir_all(bundle))
                    .await;
            }
        }
        // The first reconcile also collects what the last run left (a round
        // deferred by a fetch when it stopped).
        if removed || first {
            self.collect_garbage(wanted.values().cloned().collect())
                .await;
        }
        let mut started = Vec::new();
        {
            let mut actors = lock(&self.actors);
            for (name, decl) in wanted {
                if let Some(a) = actors.get(&name) {
                    *lock(&a.secrets) = secrets.clone();
                    continue;
                }
                let runtime = self.runtime_for(&decl);
                let a = Actor::new(&self.ctx, decl, runtime, secrets.clone());
                actors.insert(name, a.clone());
                self.ctx
                    .env
                    .spawn("foreign-supervisor", supervise(self.ctx.clone(), a.clone()));
                started.push(a);
            }
        }
        let env = &self.ctx.env;
        let deadline = env.clock.monotonic() + RECONCILE_WAIT;
        for a in started {
            let left = deadline.saturating_sub(env.clock.monotonic());
            a.settled(env, left).await;
            let s = a.status();
            if s.state != State::Running {
                tracing::warn!(foreign = a.name(), state = s.state.as_str(), error = ?s.error, "foreign actor is not running after start");
            }
        }
        drop(cleaned);
    }

    /// The container id of `name` (tests and diagnostics).
    pub fn container_id(name: &str) -> String {
        container_id(name)
    }

    /// The cgroup of `name` under the cgroup v2 root (tests and doctor).
    pub fn cgroup_path(&self, name: &str) -> String {
        self.ctx.cgroup_path(name)
    }

    /// The network namespace file of `name` (tests).
    pub fn netns_path(&self, name: &str) -> PathBuf {
        self.ctx.paths.netns(name)
    }
}

/// The node's view: reconcile and the bridge.
pub struct Host(pub Arc<Foreign>);

impl ForeignHost for Host {
    fn reconcile(
        &self,
        declared: Vec<pb::ForeignActor>,
        secrets: Option<Arc<SecretStore>>,
    ) -> BoxFuture<'static, ()> {
        Box::pin(self.0.clone().reconcile_now(declared, secrets))
    }

    fn http(
        &self,
        name: &str,
        req: HttpRequest,
    ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let me = self.0.clone();
        let name = name.to_owned();
        Box::pin(async move {
            let actor = lock(&me.actors).get(&name).cloned();
            let Some(a) = actor else {
                let why = me
                    .off()
                    .unwrap_or_else(|| "it is not running in this daemon".to_owned());
                return Err(unavailable(&name, &why));
            };
            let env = &me.ctx.env;
            a.running(env, CALL_WAIT)
                .await
                .map_err(|why| unavailable(&name, &why))?;
            crate::bridge::send(env, &a.pool, &a.dialer, &name, req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_dirs_are_checked_by_path_and_after_links() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("images");
        std::fs::create_dir_all(allowed.join("echo")).unwrap();
        std::fs::create_dir_all(tmp.path().join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("elsewhere"), allowed.join("link")).unwrap();
        let ok = |p: PathBuf| allowed_layout_dir(&p, std::slice::from_ref(&allowed)).is_some();
        assert_eq!(
            allowed_layout_dir(&allowed.join("echo"), std::slice::from_ref(&allowed)),
            Some(allowed.join("echo").canonicalize().unwrap()),
            "the import reads the resolved path"
        );
        assert!(!ok(tmp.path().join("elsewhere")));
        assert!(
            !ok(allowed.join("link")),
            "a link out of the allowed directory"
        );
        assert!(!ok(allowed.join("../elsewhere")));
        assert!(!ok(allowed.join("missing")));
        assert!(allowed_layout_dir(&allowed.join("echo"), &[]).is_none());
    }

    #[test]
    fn one_daemon_per_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let first = lock_run_dir(tmp.path()).unwrap();
        let second = lock_run_dir(tmp.path()).unwrap_err();
        assert!(second.contains("another kronik serve"), "{second}");
        drop(first);
        lock_run_dir(tmp.path()).unwrap();
    }

    fn config(data: &std::path::Path) -> ForeignConfig {
        ForeignConfig {
            data_dir: data.join("data"),
            run_dir: data.join("run"),
            runsc_path: "/nonexistent/runsc".into(),
            platform: Platform::Auto,
            insecure_registries: Vec::new(),
            layout_dirs: Vec::new(),
            pull_timeout: Duration::from_secs(5),
        }
    }

    /// A runtime's state file holds the spec with resolved secret values,
    /// and the unit's run directory is 0750 for the kronik group: the
    /// runtimes' roots are 0700 when the daemon starts, also when a runtime
    /// made them first (runsc made its root 0710 under the unit).
    #[tokio::test]
    async fn runtime_state_directories_are_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        let runsc = cfg.run_dir.join("runsc");
        std::fs::create_dir_all(&runsc).unwrap();
        std::fs::set_permissions(&runsc, std::fs::Permissions::from_mode(0o711)).unwrap();
        let run = cfg.run_dir.clone();
        let f = Foreign::new(Env::real(tokio::runtime::Handle::current()), cfg);
        assert!(f.off().is_none(), "{:?}", f.off());
        for name in ["runsc", "runc"] {
            let mode = std::fs::metadata(run.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o700, "{name}");
        }
    }

    /// An old layout that cannot be moved to `actors/` (here `foreign` is
    /// a file) turns foreign actors off instead of starting them on an
    /// empty `/data`; `kronik foreign cleanup` still works.
    #[tokio::test]
    async fn a_failed_layout_move_starts_no_actor() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        std::fs::create_dir_all(&cfg.data_dir).unwrap();
        std::fs::write(cfg.data_dir.join("foreign"), b"not a directory").unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let f = Foreign::new(env, cfg);
        let why = f.off().expect("foreign actors are off");
        assert!(why.contains("preparing"), "{why}");
        let add = f
            .prepare_add(
                AddRequest {
                    name: "echo".into(),
                    image: "oci-layout:/x".into(),
                    port: 8080,
                    ..AddRequest::default()
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(add.code, ErrorCode::ForeignUnavailable, "{add}");
        assert!(f.cleanup().await.is_ok());
    }

    /// A foreign manager whose "runsc" is any executable (adds only check
    /// that it is one) and a packed layout image of `bytes` in one layer.
    async fn manager_and_image(tmp: &std::path::Path, bytes: usize) -> (Arc<Foreign>, String) {
        let mut cfg = config(tmp);
        cfg.runsc_path = "/bin/true".into();
        let src = tmp.join("src");
        std::fs::create_dir_all(&src).unwrap();
        // Pseudo-random (xorshift), so gzip keeps the layer about `bytes`.
        let mut x = 0x9e37_79b9_7f4a_7c15_u64;
        let content: Vec<u8> = (0..bytes)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        std::fs::write(src.join("big"), content).unwrap();
        let layout = tmp.join("layout");
        crate::oci::pack(
            &layout,
            &[crate::oci::LayerSource {
                dir: src,
                gzip: true,
            }],
            &crate::oci::ImageSpec {
                reference: "big".into(),
                cmd: vec!["/big".into()],
                ..crate::oci::ImageSpec::default()
            },
        )
        .unwrap();
        let f = Foreign::new(Env::real(tokio::runtime::Handle::current()), cfg);
        // The first reconcile (no actor declared) allows garbage collection.
        f.clone().reconcile_now(Vec::new(), None).await;
        (f, format!("oci-layout:{}", layout.display()))
    }

    fn add(image: &str, max_new_bytes: Option<u64>) -> AddRequest {
        AddRequest {
            name: "big".into(),
            image: image.into(),
            port: 8080,
            any_layout_dir: true,
            max_new_bytes,
            ..AddRequest::default()
        }
    }

    fn blobs(f: &Foreign) -> Vec<String> {
        std::fs::read_dir(f.ctx.blobs.dir())
            .map(|d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// R1: an image whose new layers do not fit in the free space above the
    /// reserve is refused before its layers are fetched, and what was
    /// fetched before the check goes; a dry run (or a refused write) keeps
    /// no blob either.
    #[tokio::test]
    async fn an_add_is_bounded_by_the_space_above_the_reserve_and_a_dry_run_keeps_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (f, image) = manager_and_image(tmp.path(), 256 << 10).await;
        let e = f
            .prepare_add(add(&image, Some(64 << 10)), None)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unavailable, "{e}");
        assert!(e.message.contains("disk_reserve"), "{e}");
        assert!(blobs(&f).is_empty(), "{:?}", blobs(&f));
        // Enough room: the image is fetched, held while the add runs, and
        // gone after a dry run.
        let plan = f
            .prepare_add(add(&image, Some(1 << 30)), None)
            .await
            .unwrap();
        assert_eq!(blobs(&f).len(), 3, "manifest, config, layer");
        f.finish_add(plan, false).await;
        assert!(blobs(&f).is_empty(), "{:?}", blobs(&f));
    }

    #[test]
    fn a_fetch_timeout_is_unavailable_not_an_invalid_image() {
        let e = image_error(ImageError::TimedOut(
            "pulling r/x@sha256:1 took longer than 600 s".into(),
        ));
        assert_eq!(e.code, ErrorCode::ForeignUnavailable);
        assert!(
            e.hint.as_deref().unwrap_or("").contains("pull_timeout"),
            "{e:?}"
        );
    }

    /// A stalled fetch (a registry that stopped answering holds `fetching`
    /// shared until `pull_timeout`) delays no add, dry run or remove: their
    /// garbage collection skips the round, and a later one collects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_fetch_delays_no_add_and_a_later_collection_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let (f, image) = manager_and_image(tmp.path(), 16 << 10).await;
        let stalled = f.ctx.fetch_shared().await;
        let quick = std::time::Duration::from_secs(5);
        let plan = f
            .ctx
            .env
            .timeout(quick, f.prepare_add(add(&image, None), None))
            .await
            .expect("the add waited for the stalled fetch")
            .unwrap();
        f.ctx
            .env
            .timeout(quick, f.finish_add(plan, false))
            .await
            .expect("the dry run's collection waited for the stalled fetch");
        assert_eq!(blobs(&f).len(), 3, "deferred while the fetch runs");
        // The round runs once the fetch is over, with nothing else to cause it.
        drop(stalled);
        for _ in 0..500 {
            if blobs(&f).is_empty() {
                break;
            }
            f.ctx
                .env
                .clock
                .sleep(std::time::Duration::from_millis(10))
                .await;
        }
        assert!(blobs(&f).is_empty(), "{:?}", blobs(&f));
    }

    /// A start collects what the last run left, without a remove.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_reconcile_collects_unused_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let (f, image) = manager_and_image(tmp.path(), 16 << 10).await;
        let stalled = f.ctx.fetch_shared().await;
        let plan = f.prepare_add(add(&image, None), None).await.unwrap();
        f.finish_add(plan, false).await;
        assert_eq!(blobs(&f).len(), 3);
        // Stopped (or killed) before the fetch ended: the round never ran.
        std::mem::forget(stalled);
        let dir = f.ctx.blobs.dir();
        drop(f);
        let mut cfg = config(tmp.path());
        cfg.runsc_path = "/bin/true".into();
        let f = Foreign::new(Env::real(tokio::runtime::Handle::current()), cfg);
        assert_eq!(f.ctx.blobs.dir(), dir);
        f.clone().reconcile_now(Vec::new(), None).await;
        assert!(blobs(&f).is_empty(), "{:?}", blobs(&f));
    }
}
