//! `kronik serve`: opens the data directory, recovers from the log, and
//! serves the gateway on TCP and the API on the Unix socket. Settings come
//! from `kronik.toml` ([`crate::config`]); the flags override it.

use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use kronik_api::Api;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_gateway::{Gateway, GatewayConfig};
use kronik_sched::{NodeConfig, start_local};

use crate::config::{Config, Overrides};

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// The configuration file [default: /etc/kronik/kronik.toml if it
    /// exists]. The flags below override it.
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    /// Data directory (code, logs, materialized state) [file: server.data_dir].
    #[arg(long, env = "KRONIK_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// Address of the HTTP gateway [file: server.http_listen].
    #[arg(long, env = "KRONIK_HTTP_LISTEN")]
    http_listen: Option<SocketAddr>,
    /// Address of embedded UI, /metrics and /healthz [file: server.admin_listen].
    #[arg(long, env = "KRONIK_ADMIN_LISTEN")]
    admin_listen: Option<SocketAddr>,
    /// Unix socket of the JSON API, mode 0660 [file: server.api_socket].
    #[arg(long, env = "KRONIK_API_SOCKET")]
    api_socket: Option<PathBuf>,
    /// Address of the JSON API and MCP over TCP, where every request needs a
    /// bearer token; off when absent. Without TLS only a loopback address
    /// [file: server.api_listen].
    #[arg(long, env = "KRONIK_API_LISTEN")]
    api_listen: Option<SocketAddr>,
    /// Gateway timeout in milliseconds; a slower turn gives 504 and still
    /// completes [file: gateway.timeout].
    #[arg(long)]
    gateway_timeout_ms: Option<u64>,
    /// Turns running at once.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// Master key of the secret store, created with mode 0600 if missing
    /// [file: keys.master_key_file]. `KRONIK_MASTER_KEY`, when set, holds
    /// the key itself (64 hex characters) and no file is read or created;
    /// setting both is an error.
    #[arg(long, env = "KRONIK_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
    /// Run as the nonroot service (M21): bind every listener and take the
    /// data directory's lock, empty all capability sets, hand the API socket
    /// to a capability-free acceptor that reads the callers' true uids, and
    /// enter the pinned Kronik user namespace. The unit that
    /// `serve --init --rootless` writes sets it, and the daemon refuses to
    /// start where it cannot keep its promises (as root, or in a rootless
    /// container or a nested user namespace). Without it `serve` starts as it
    /// did before M21, as root or as an ordinary user. With `--init`: install
    /// the nonroot service rather than the root one (the default).
    #[arg(long)]
    rootless: bool,
    /// Below this much free space on the log's file system, new inputs and
    /// changes are refused, e.g. `512MiB`; `0B` turns it off [file:
    /// log.disk_reserve].
    #[arg(long, value_name = "SIZE", env = "KRONIK_DISK_RESERVE")]
    disk_reserve: Option<crate::config::Size>,
    /// OTLP/HTTP collector for spans and metrics, e.g.
    /// `http://127.0.0.1:4318` [file: otel.endpoint].
    #[arg(long, value_name = "URL", env = "KRONIK_OTEL_ENDPOINT")]
    otel_endpoint: Option<String>,
    /// Test hook: callers stop after the callee answered and before the
    /// result is recorded, so a crash test can kill the daemon there.
    #[arg(long, hide = true)]
    test_hold_after_call: bool,
    /// Test hook: each isolated root input of a proposal job's replay waits
    /// for a permit; the file holds how many have been given so far.
    #[arg(long, hide = true, value_name = "FILE")]
    test_replay_permits: Option<PathBuf>,
    /// Test hook: delete expired previews this often (milliseconds)
    /// instead of every minute.
    #[arg(long, hide = true, value_name = "MS")]
    test_preview_sweep_ms: Option<u64>,
    /// Test hook: a registry (`host:port`) that foreign images are pulled
    /// from over plain HTTP. Repeatable.
    #[arg(long, hide = true, value_name = "HOST:PORT")]
    test_insecure_registry: Vec<String>,
    /// Test hook: after a `kronik restore`, exit once the `restore` event is
    /// committed, before the export cursors are clamped and the marker is
    /// removed, as a crash there would.
    #[arg(long, hide = true)]
    test_stop_after_restore_event: bool,
    /// Log lines as text or as JSON objects (one per line).
    #[arg(long, value_enum, default_value_t = LogFormat::Text, env = "KRONIK_LOG_FORMAT")]
    log_format: LogFormat,
    #[command(flatten)]
    init: crate::init::InitArgs,
}

impl ServeArgs {
    /// `--init` and what it needs, for main: host setup is a flag mode of
    /// `serve` that binds nothing, so it runs before the daemon starts.
    pub(crate) fn init_args(
        &self,
    ) -> Option<(crate::init::InitArgs, Option<&Path>, Option<&Path>)> {
        self.init.init.then(|| {
            let mut init = self.init.clone();
            init.rootless = self.rootless;
            init.overrides = Box::new(self.init_overrides());
            (
                init,
                self.config.as_deref(),
                // The key the host is set up with, not the one the file
                // records: a key given only by the environment still has to
                // reach init, which reads it once instead of re-reading it.
                self.master_key_file.as_deref(),
            )
        })
    }

    /// Whether this process's command line spells `name` (`--name VALUE` or
    /// `--name=VALUE`): what `--init` persists is what the operator wrote, not
    /// what an `env =` attribute supplied.
    fn flag_given(name: &str) -> bool {
        std::env::args().skip(1).any(|argument| {
            argument == name
                || argument
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with('='))
        })
    }

    /// The flags that override the configuration file: the daemon's, and, for
    /// `--init`, the ones a generated file is written from.
    fn overrides(&self) -> Overrides {
        Overrides {
            data_dir: self.data_dir.clone(),
            api_socket: self.api_socket.clone(),
            http_listen: self.http_listen,
            admin_listen: self.admin_listen,
            api_listen: self.api_listen,
            gateway_timeout: self.gateway_timeout_ms.map(Duration::from_millis),
            master_key_file: self.master_key_file.clone(),
            disk_reserve: self.disk_reserve,
            otel_endpoint: self.otel_endpoint.clone(),
        }
    }

    /// [`Self::overrides`], but only the flags this command line spells: the
    /// installed unit does not inherit the installer's environment, so a
    /// value that came only from there is not the service's to keep.
    fn init_overrides(&self) -> Overrides {
        let all = self.overrides();
        Overrides {
            data_dir: Self::flag_given("--data-dir")
                .then_some(all.data_dir)
                .flatten(),
            api_socket: Self::flag_given("--api-socket")
                .then_some(all.api_socket)
                .flatten(),
            http_listen: Self::flag_given("--http-listen")
                .then_some(all.http_listen)
                .flatten(),
            admin_listen: Self::flag_given("--admin-listen")
                .then_some(all.admin_listen)
                .flatten(),
            api_listen: Self::flag_given("--api-listen")
                .then_some(all.api_listen)
                .flatten(),
            gateway_timeout: Self::flag_given("--gateway-timeout-ms")
                .then_some(all.gateway_timeout)
                .flatten(),
            master_key_file: Self::flag_given("--master-key-file")
                .then_some(all.master_key_file)
                .flatten(),
            disk_reserve: Self::flag_given("--disk-reserve")
                .then_some(all.disk_reserve)
                .flatten(),
            otel_endpoint: Self::flag_given("--otel-endpoint")
                .then_some(all.otel_endpoint)
                .flatten(),
        }
    }

    /// The configuration file, if any, with the flags in place.
    fn config(&self) -> anyhow::Result<Config> {
        let (config, _file) = Config::find(self.config.as_deref())?;
        let config = config.with(self.overrides());
        // The overrides are checked as the file's values are.
        config.otel.check().map_err(anyhow::Error::msg)?;
        config.check_audit_hold().map_err(anyhow::Error::msg)?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

/// The `--test-replay-permits` file's count, polled: the permits it adds
/// go to `gate`.
async fn replay_permits(env: Env, path: PathBuf, gate: Arc<tokio::sync::Semaphore>) {
    let mut given = 0usize;
    loop {
        let total = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if total > given {
            gate.add_permits(total - given);
            given = total;
        }
        env.clock.sleep(Duration::from_millis(20)).await;
    }
}

/// KRONIK_LOG's filter, `info` without one.
fn log_filter(spec: Option<&str>) -> tracing_subscriber::EnvFilter {
    spec.and_then(|s| tracing_subscriber::EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"))
}

/// `rmcp` at info at most, whatever KRONIK_LOG says: it logs MCP arguments
/// and results at debug, unsealed values for a `pii:read` caller included.
/// A layer of its own, so that no KRONIK_LOG directive can override it.
fn rmcp_at_info(meta: &tracing::Metadata<'_>) -> bool {
    !(meta.target().starts_with("rmcp") && *meta.level() > tracing::Level::INFO)
}

/// Whether the log may carry ANSI colours: only when standard error is a
/// terminal, and not when `NO_COLOR` says so (<https://no-color.org>).
///
/// The daemon's log is routinely kept rather than watched - systemd's journal,
/// a redirected file, a test's pipe - and the escapes are then part of the
/// text: they break a search for a field and they end up in a bug report.
fn ansi_enabled() -> bool {
    std::io::stderr().is_terminal()
        && std::env::var("NO_COLOR").map_or(true, |value| value.is_empty())
}

/// The subscriber `kronik serve` logs through: KRONIK_LOG's filter (`spec`),
/// then [`rmcp_at_info`] over it.
fn log_subscriber(
    format: LogFormat,
    spec: Option<&str>,
) -> Box<dyn tracing::Subscriber + Send + Sync> {
    use tracing_subscriber::layer::SubscriberExt as _;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(log_filter(spec))
        .with_ansi(ansi_enabled())
        .with_writer(std::io::stderr);
    let cap = tracing_subscriber::filter::filter_fn(rmcp_at_info);
    match format {
        LogFormat::Text => Box::new(builder.finish().with(cap)),
        LogFormat::Json => Box::new(builder.json().finish().with(cap)),
    }
}

fn init_tracing(format: LogFormat) {
    use tracing_subscriber::util::SubscriberInitExt as _;
    log_subscriber(format, std::env::var("KRONIK_LOG").ok().as_deref()).init();
}

impl ServeArgs {
    /// The hidden `--test-*` flags that are set; each weakens the daemon, so
    /// `run` warns about them. Every test hook belongs here.
    fn test_flags(&self) -> Vec<&'static str> {
        let set = [
            (self.test_hold_after_call, "--test-hold-after-call"),
            (self.test_replay_permits.is_some(), "--test-replay-permits"),
            (
                !self.test_insecure_registry.is_empty(),
                "--test-insecure-registry",
            ),
            (
                self.test_preview_sweep_ms.is_some(),
                "--test-preview-sweep-ms",
            ),
        ];
        set.into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, f)| f)
            .collect()
    }
}

pub fn run(args: ServeArgs) -> anyhow::Result<()> {
    // `serve --rootless`, the nonroot service, binds its listeners, takes the
    // data directory's lock and gives up its host authority while it still
    // has one thread, before the logger and the runtime start. Plain `serve`,
    // as root or as an ordinary user, does what it did before M21.
    let started = args.rootless.then(|| {
        args.config()
            .and_then(|config| Early::start(&config).map(|early| (config, early)))
    });
    // When the early start fails there is no logger yet: install it to report why.
    init_tracing(args.log_format);
    let test_flags = args.test_flags();
    if !test_flags.is_empty() {
        tracing::warn!(flags = ?test_flags, "test-only flags are set; never use them in production");
    }
    let (config, early) = match started {
        Some(started) => started?,
        None => (args.config()?, Early::default()),
    };
    if let Some(kronik_foreign::Privilege::Unavailable(why)) = &early.privilege {
        tracing::warn!(why, "foreign actors are unavailable");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kronik")
        .build()
        .context("starting the tokio runtime")?;
    rt.block_on(serve(args, config, early))
}

/// What `kronik serve --rootless` sets up while the process has one thread
/// (ADR 0060): the TCP listeners, bound while the service still holds the
/// unit's `CAP_NET_BIND_SERVICE` for ports 80 and 443; the data directory's
/// lock; the API socket's acceptor, the cgroup leaf and the Kronik user
/// namespace, after the capabilities are gone. Plain `serve` has none of it:
/// every field is `None` and `serve` binds and locks where it always did.
#[derive(Default)]
struct Early {
    gateway: Option<std::net::TcpListener>,
    api_tcp: Option<std::net::TcpListener>,
    /// /metrics and /healthz are auxiliary: without the port Kronik serves
    /// anyway and says why.
    admin: Option<std::io::Result<std::net::TcpListener>>,
    /// The API socket's connections, read in the initial user namespace.
    acceptor: Option<kronik_foreign::sys::Acceptor>,
    privilege: Option<kronik_foreign::Privilege>,
    /// The data directory's lock, held from before the first bind until the
    /// node takes it over; it is never released and taken again.
    ownership: Option<kronik_privacy::key_source::DataOwnership>,
}

/// A TCP listener as tokio's own `bind` makes it (backlog 1024), ready for
/// `from_std`.
fn tcp_listen(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    rustix::net::listen(&listener, 1024)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// The checks of the configuration that stop `serve` before it does
/// anything; the API's TCP address, if any.
fn preflight(config: &Config) -> anyhow::Result<Option<SocketAddr>> {
    // A flag can set it too, so the file's check is not enough.
    let api_listen = config.api_listen().map_err(anyhow::Error::msg)?;
    config.check().map_err(anyhow::Error::msg)?;
    // The master key is the KRONIK_MASTER_KEY material, or a key file (the
    // flag, KRONIK_MASTER_KEY_FILE or [keys] master_key_file). Both set is
    // ambiguous, so refuse to start rather than silently pick one.
    if config.keys.master_key_file.is_some()
        && std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some()
    {
        anyhow::bail!(
            "KRONIK_MASTER_KEY and a master key file (--master-key-file, \
             KRONIK_MASTER_KEY_FILE or [keys] master_key_file) are both \
             set; remove one of them"
        );
    }
    Ok(api_listen)
}

impl Early {
    fn start(config: &Config) -> anyhow::Result<Early> {
        // Before anything is created, locked or bound: a nonroot service that
        // cannot keep its promises does not start at all.
        kronik_foreign::sys::acceptor_view().map_err(refusal)?;
        let api_listen = preflight(config)?;
        restrict_data_dir(&config.server.data_dir, &config.server.api_socket)?;
        let ownership = kronik_privacy::key_source::lock_data(&config.server.data_dir)?;
        let http_listen = config.http_listen();
        let gateway = tcp_listen(http_listen)
            .with_context(|| format!("binding the gateway on {http_listen}"))?;
        let api_tcp = api_listen
            .map(|addr| tcp_listen(addr).with_context(|| format!("binding the API on {addr}")))
            .transpose()?;
        let admin = tcp_listen(config.server.admin_listen);
        let (acceptor, privilege) = nonroot_boundary(config)?;
        Ok(Early {
            gateway: Some(gateway),
            api_tcp,
            admin: Some(admin),
            acceptor: Some(acceptor),
            privilege: Some(privilege),
            ownership: Some(ownership),
        })
    }
}

/// The refusal of the nonroot service, as the stable `ROOTLESS_UNAVAILABLE`
/// error: its message says what to change, and `kronik doctor --rootless`
/// reports the same condition before the service is started.
fn refusal(why: kronik_foreign::sys::AcceptorRefusal) -> anyhow::Error {
    ApiError::new(ErrorCode::RootlessUnavailable, why.to_string())
        .with_hint("Run `kronik doctor --rootless` as the service user to see this check before starting the service.")
        .into()
}

/// The non-root daemon's start (ADR 0060): the API
/// socket and its acceptor, which keeps reading the callers' host uids in
/// the initial namespace; the cgroup leaf; then the Kronik user namespace.
/// Without the namespace or a delegated cgroup the daemon still serves,
/// and foreign actors answer FOREIGN_UNAVAILABLE with the reason.
fn nonroot_boundary(
    config: &Config,
) -> anyhow::Result<(kronik_foreign::sys::Acceptor, kronik_foreign::Privilege)> {
    use kronik_foreign::Privilege::{Unavailable, Userns};
    use kronik_foreign::subid::USERNS_PIN;
    use kronik_foreign::sys;
    let api_socket = &config.server.api_socket;
    let unix = kronik_api::server::bind_std(api_socket)
        .with_context(|| format!("binding the API on {}", api_socket.display()))?;
    sys::clear_capabilities().context("dropping all host capabilities after listener binding")?;
    // Before the acceptor forks, so that it starts in the leaf too: the
    // delegated cgroup may hold no process once it has controllers on.
    let leaf = sys::cgroup_leaf();
    let acceptor = sys::Acceptor::spawn(std::os::fd::OwnedFd::from(unix))
        .context("starting the API socket's acceptor")?;
    let pin = Path::new(USERNS_PIN);
    let privilege = if !pin.exists() {
        Unavailable(format!(
            "the daemon is not root, and no Kronik user namespace is pinned at {USERNS_PIN}: \
             start kronik-userns.service (`kronik userns pin`)"
        ))
    } else {
        let uid = rustix::process::geteuid().as_raw();
        let entered = crate::cli::userns::kronik_user("", Some(uid))
            .and_then(|user| sys::enter_userns(pin, &user.maps()).map_err(|e| e.to_string()));
        match (entered, leaf) {
            (Err(why), _) => Unavailable(format!(
                "the daemon is not root, and it cannot enter the Kronik user namespace: {why}"
            )),
            (Ok(()), Ok(Some(cgroup))) if sys::cgroup_delegated(&cgroup) => Userns { cgroup },
            (Ok(()), Ok(Some(cgroup))) => Unavailable(format!(
                "the cgroup {cgroup} is not writable inside the Kronik user namespace"
            )),
            (Ok(()), Ok(None)) => Unavailable(format!(
                "no delegated cgroup: the daemon's cgroup {:?} is not writable for it; run it \
                 in kronik.service (Delegate=yes)",
                sys::own_cgroup().unwrap_or_default()
            )),
            (Ok(()), Err(e)) => Unavailable(format!("no cgroup leaf: {e}")),
        }
    };
    Ok((acceptor, privilege))
}

/// Hands the acceptor's connections to the runtime from a thread of its
/// own (its `recv` blocks).
fn accept_channel(
    acceptor: kronik_foreign::sys::Acceptor,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<(std::os::unix::net::UnixStream, u32)>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    std::thread::Builder::new()
        .name("kronik-api-accept".into())
        .spawn(move || {
            loop {
                match acceptor.recv() {
                    Ok((fd, uid)) => {
                        if tx.blocking_send((fd.into(), uid)).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "the API socket's acceptor stopped");
                        return;
                    }
                }
            }
        })
        .context("starting the API socket's accept thread")?;
    Ok(rx)
}

/// The API's Unix socket: bound by a root daemon, or fed by the acceptor.
enum UnixApi {
    Listener(tokio::net::UnixListener),
    Accepted(tokio::sync::mpsc::Receiver<(std::os::unix::net::UnixStream, u32)>),
}

/// The foreign actors' settings of `config` (serve and `foreign cleanup`).
pub(crate) fn foreign_config(
    config: &Config,
    data_dir: PathBuf,
    insecure_registries: Vec<String>,
) -> kronik_foreign::ForeignConfig {
    kronik_foreign::ForeignConfig {
        data_dir,
        run_dir: config.foreign.run_dir.clone(),
        runsc_path: config.foreign.runsc_path.clone(),
        platform: match config.foreign.platform {
            crate::config::Platform::Auto => kronik_foreign::Platform::Auto,
            crate::config::Platform::Systrap => kronik_foreign::Platform::Systrap,
            crate::config::Platform::Kvm => kronik_foreign::Platform::Kvm,
        },
        insecure_registries,
        layout_dirs: config.foreign.layout_dirs.clone(),
        pull_timeout: config.foreign.pull_timeout.0,
        start_timeout: config.foreign.start_timeout.0,
        checkpoints_kept: config.foreign.checkpoints_kept,
        privilege: kronik_foreign::Privilege::Root,
        microvm_dir: config.foreign.microvm_dir.clone(),
        disk_reserve: config.log.disk_reserve.0,
    }
}

/// The data directory is the daemon's alone (0700). With the API socket
/// inside it, the group may pass through to the socket (0710), whose own
/// mode (0660) then decides.
fn restrict_data_dir(data_dir: &Path, api_socket: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    // The socket's directory may not exist yet: then its absolute path, so
    // that a relative --api-socket still compares with the data directory.
    let canonical = |p: &Path| {
        std::fs::canonicalize(p)
            .or_else(|_| std::path::absolute(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let inside = api_socket
        .parent()
        .is_some_and(|dir| canonical(dir).starts_with(canonical(data_dir)));
    let mode = if inside { 0o710 } else { 0o700 };
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", data_dir.display()))
}

/// Raises the soft limit on open files to the hard one, and returns the
/// limit in force.
fn raise_open_files() -> usize {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    if let Rlimit {
        current: Some(soft),
        maximum: Some(hard),
    } = getrlimit(Resource::Nofile)
        && soft < hard
    {
        let raised = Rlimit {
            current: Some(hard),
            maximum: Some(hard),
        };
        if let Err(e) = setrlimit(Resource::Nofile, raised) {
            tracing::warn!(error = %e, soft, hard, "could not raise the limit on open files");
        }
    }
    let limit = getrlimit(Resource::Nofile).current.unwrap_or(u64::MAX);
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// The gateway's and the TCP API's connection caps under a limit of
/// `open_files`. Half the limit, at most 1 024, stays with the node: log
/// segments, `state.db`, open actor databases with their WAL files, the
/// key stores, snapshots and foreign actors. Of the rest the gateway gets
/// three quarters, at most 1 024, and the TCP API a quarter, at most 256;
/// at least 16 and 4. Connections then cannot take the descriptors the log
/// needs to roll a segment.
fn connection_caps(open_files: usize) -> (usize, usize) {
    let reserved = (open_files / 2).min(1024);
    let spare = open_files.saturating_sub(reserved) / 4;
    ((spare * 3).clamp(16, 1024), spare.clamp(4, 256))
}

async fn serve(args: ServeArgs, config: Config, early: Early) -> anyhow::Result<()> {
    // No core dumps or ptrace by other users: the process holds the master
    // key, secrets and plain subject data (PR_SET_DUMPABLE 0).
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        tracing::warn!(error = %e, "could not make the process non-dumpable");
    }
    let open_files = raise_open_files();
    let (gateway_connections, api_connections) = connection_caps(open_files);
    let api_listen = preflight(&config)?;
    let env = Env::real(tokio::runtime::Handle::current());
    let data_dir = config.server.data_dir.clone();
    // `--rootless` did this before it took the lock.
    if early.ownership.is_none() {
        restrict_data_dir(&data_dir, &config.server.api_socket)?;
    }
    // Foreign actors (M7): the node starts them after recovering the log and
    // before re-running open turns; they stop when the daemon stops.
    let mut foreign_config = foreign_config(
        &config,
        data_dir.clone(),
        args.test_insecure_registry.clone(),
    );
    if let Some(privilege) = early.privilege {
        foreign_config.privilege = privilege;
    }
    let foreign = kronik_foreign::Foreign::new(env.clone(), foreign_config);
    let node_config = NodeConfig {
        foreign: kronik_effects::foreign::ForeignSlot(Some(Arc::new(kronik_foreign::Host(
            foreign.clone(),
        )))),
        concurrency: args.concurrency.max(1),
        keys: config.keys.clone(),
        secret_settings: config.secrets.clone(),
        storage: Some(kronik_sched::snapshots::StorageConfig {
            data_dir: data_dir.clone(),
            snapshot_interval: config.retention.snapshot_interval.0,
            snapshots_kept: config.retention.snapshots_kept as usize,
            history: config.retention.history.0,
        }),
        ingress_ttl: config.gateway.idempotency_ttl.0,
        segment_max_bytes: Some(config.log.segment_max_mb * 1024 * 1024),
        segment_max_age: Some(Duration::from_secs(config.log.segment_max_age_s)),
        group_commit_window: Some(Duration::from_millis(config.log.group_commit_ms)),
        test_hold_after_call: args.test_hold_after_call,
        keystore_backup_retention: config.privacy.keystore_backup_retention.0,
        sql_bytes_per_actor: config.sql.max_size_per_actor.0,
        disk_reserve: config.log.disk_reserve.0,
        ..NodeConfig::default()
    };
    let node = match early.ownership {
        Some(ownership) => {
            kronik_sched::start_local_locked(env.clone(), &data_dir, node_config, ownership).await
        }
        None => start_local(env.clone(), &data_dir, node_config).await,
    }
    .with_context(|| format!("recovering {}", data_dir.display()))?;
    struct NativeExecutionGuard(Option<Arc<kronik_sched::Node>>);
    impl Drop for NativeExecutionGuard {
        fn drop(&mut self) {
            if let Some(node) = &self.0
                && let Err(error) = node.stop_native_execution()
            {
                tracing::error!(error = %error.message, "stopping native execution failed");
            }
        }
    }
    let mut native_execution = NativeExecutionGuard(Some(node.clone()));
    let configured_original = node.local_operator_authority()?;
    record_key_source(&node, &data_dir, configured_original.clone()).await?;
    let installation = crate::fleet::installation(
        &node,
        config
            .fleet
            .as_ref()
            .map(|fleet| fleet.installation.as_str()),
    )
    .await
    .map_err(|error| anyhow::anyhow!("installation identity: {}", error.message))?;
    // Export streams (M28): each follows the log from its cursor.
    let exports_on = config.audit.sink().is_some()
        || (config.otel.endpoint().is_some() && config.otel.traces)
        || !config.events.webhook.is_empty();
    let restore_pending = data_dir
        .join("branches/main")
        .join(kronik_ship::RESTORE_MARKER)
        .try_exists()?;
    let mut cursors = Arc::new(
        match kronik_otel::cursor::Cursors::load(env.clone(), &data_dir).await {
            Ok(cursors) => cursors,
            Err(_) if !exports_on && !restore_pending => {
                tracing::warn!(
                    code = "export_state",
                    "disabled exporters left unreadable export state untouched"
                );
                kronik_otel::cursor::Cursors::inactive(env.clone(), &data_dir)
            }
            Err(error) => return Err(error).context("reading the export cursors"),
        },
    );
    record_restore(
        &node,
        &data_dir.join("branches/main"),
        &cursors,
        args.test_stop_after_restore_event,
        configured_original.clone(),
    )
    .await?;
    if let Err(error) =
        crate::otel::migrate_trace_state(&node, &cursors, &data_dir, configured_original.clone())
            .await
    {
        if exports_on {
            return Err(error);
        }
        tracing::warn!(
            code = "state_read",
            "disabled exporters left unmigrated trace state untouched"
        );
        cursors = Arc::new(kronik_otel::cursor::Cursors::inactive(
            env.clone(),
            &data_dir,
        ));
    }
    let (audit_mapper, audit) = crate::otel::start_audit(
        &config,
        &node,
        &cursors,
        &data_dir,
        configured_original.clone(),
    )
    .await?;
    let mut exports = vec![
        crate::otel::start(
            &config,
            &node,
            &cursors,
            &data_dir,
            configured_original.clone(),
        )
        .await?,
        audit,
    ];
    // Shipping to object storage (m6-storage §4), when enabled.
    if config.ship.enabled {
        let url = config
            .ship
            .url
            .as_deref()
            .context("[ship] enabled needs url = \"s3://bucket/prefix\"")?;
        let remote = kronik_ship::Remote::open(url, config.ship.endpoint.as_deref())?;
        tracing::info!(url, "shipping to object storage");
        drop(
            env.spawn(
                "ship",
                kronik_ship::ship_loop(
                    env.clone(),
                    remote,
                    data_dir.clone(),
                    "main".into(),
                    kronik_ship::SHIP_INTERVAL,
                    node.key_source()
                        .cloned()
                        .context("the node has no loaded key source")?,
                    node.sealer()
                        .keystore()
                        .cloned()
                        .context("the node has no keystore")?,
                ),
            ),
        );
    }
    let mut proposals = kronik_fork::proposal::Proposals::open(node.clone(), data_dir.clone())
        .map_err(|e| anyhow::anyhow!("loading proposals: {}", e.message))?
        .with_live_allowlist(config.fork.live_allowlist.clone())
        .with_model(
            config
                .simulators
                .model
                .as_ref()
                .map(crate::config::SimulatorModel::resolve)
                .transpose()
                .map_err(anyhow::Error::msg)?,
        )
        .with_promote(config.promote.max_gap.0, config.promote.catch_up_timeout.0)
        .with_preview_ttl(config.fork.preview_ttl.0)
        .with_rebase(config.rebase.max_pause.0);
    if let Some(path) = args.test_replay_permits.clone() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        proposals = proposals.with_test_gate(gate.clone());
        drop(env.spawn(
            "test-replay-permits",
            replay_permits(env.clone(), path, gate),
        ));
    }
    let proposals = Arc::new(proposals);
    // Preview forks (M11): expired ones go, also those that expired while
    // the daemon was down.
    drop(
        env.spawn(
            "preview-expiry",
            kronik_fork::proposal::preview::expire_loop(
                proposals.clone(),
                args.test_preview_sweep_ms
                    .map_or(Duration::from_secs(60), Duration::from_millis),
            ),
        ),
    );
    let gateway = Arc::new(
        Gateway::new(
            node.clone(),
            GatewayConfig {
                timeout: config.gateway.timeout.0,
                subject_from: config.subject_from(),
                idempotency_header: config.gateway.idempotency_header.clone(),
                preview_domain: config.gateway.preview_domain.clone(),
                // Checked when the configuration was read.
                trusted_proxies: config
                    .gateway
                    .trusted_proxies
                    .iter()
                    .filter_map(|p| kronik_gateway::IpNet::parse(p).ok())
                    .collect(),
                ..GatewayConfig::default()
            },
        )
        .with_preview(proposals.clone()),
    );
    let tls = config
        .certificates()
        .map(kronik_gateway::tls::start)
        .transpose()
        .map_err(|e| anyhow::anyhow!("gateway TLS: {e}"))?;
    let http_listen = config.http_listen();
    let tcp = match early.gateway {
        Some(listener) => tokio::net::TcpListener::from_std(listener),
        None => tokio::net::TcpListener::bind(http_listen).await,
    }
    .with_context(|| format!("binding the gateway on {http_listen}"))?;
    let bound = tcp.local_addr().unwrap_or(http_listen);
    let tokens_db = data_dir.join("keys").join("tokens.db");
    let mut tokens =
        kronik_api::tokens::TokenStore::open_file(&tokens_db).map_err(anyhow::Error::msg)?;
    let publication = node.publication_domain();
    tokens
        .bind_before_any_issuer(publication.clone())
        .map_err(|error| anyhow::anyhow!(error.message))?;
    tokens
        .bind_execution_before_any_issuer(&publication, configured_original.clone())
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let tokens = Arc::new(tokens);
    // The same captured ACTIVE startup operation owns recovery and initial grants.
    let fleet = crate::fleet::open(
        node.clone(),
        tokens.clone(),
        &config,
        configured_original.clone(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("fleet startup: {}", error.message))?;
    let (event_feed, event_streams) = crate::events::start_native(
        node.clone(),
        &installation,
        &config.events,
        cursors.clone(),
        configured_original.clone(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("event startup: {}", error.message))?;
    exports.extend(event_streams);
    let admission = kronik_api::oidc::BrowserAuth::existing_admission(&node)
        .map_err(|error| anyhow::anyhow!("OIDC admission: {}", error.message))?;
    let browser = kronik_api::oidc::BrowserAuth::open(
        env.clone(),
        tokens.clone(),
        config.oidc.clone(),
        admission,
        node.sealer().clone(),
        tls.is_some(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("OIDC configuration: {}", error.message))?;
    // Unfinished watches resume here (M11).
    let watches =
        kronik_fork::watch::Watches::open(node.clone(), proposals.clone(), data_dir.clone())
            .map_err(|e| anyhow::anyhow!("loading watches: {}", e.message))?
            .start();
    let mut api = Api::new(node.clone())
        .with_http_listen(bound.to_string())
        .with_preview_urls(
            config.gateway.preview_domain.clone(),
            tls.is_some(),
            config.public_host(bound),
        )
        .with_proposals(proposals)
        .with_watches(watches)
        .with_tokens(tokens.clone())?
        .with_browser(browser.clone())
        .with_foreign(foreign.clone())
        .with_exports(exports)
        .with_audit_mapper(audit_mapper);
    if let Some(controller) = &fleet {
        api = api.with_fleet(controller.clone());
    }
    let api = Arc::new(api.with_event_feed(event_feed));
    let api_socket = &config.server.api_socket;
    let unix = match early.acceptor {
        Some(acceptor) => UnixApi::Accepted(accept_channel(acceptor)?),
        None => UnixApi::Listener(
            kronik_api::server::bind(api_socket)
                .with_context(|| format!("binding the API on {}", api_socket.display()))?,
        ),
    };
    let api_tcp = match (early.api_tcp, api_listen) {
        (Some(listener), _) => Some(
            tokio::net::TcpListener::from_std(listener)
                .context("binding the API from its early listener")?,
        ),
        (None, Some(addr)) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding the API on {addr}"))?,
        ),
        (None, None) => None,
    };
    let api_tcp_bound = api_tcp
        .as_ref()
        .and_then(|listener| listener.local_addr().ok());
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    tracing::info!(
        http = %bound,
        api = %api_socket.display(),
        api_tcp = ?api_tcp_bound,
        data = %data_dir.display(),
        engine = kronik_runtime::ENGINE_VERSION,
        applied_lsn = node.applied_lsn(),
        open_files,
        gateway_connections,
        api_connections,
        "kronik is serving"
    );
    let mcp = kronik_mcp::mount(api.clone());
    if let Some(controller) = fleet {
        crate::fleet::start(
            &node,
            controller,
            &api,
            Some(kronik_mcp::mount_for_tcp(api.clone())),
        );
    }
    let api_tcp = {
        let (api, mcp, tls) = (
            api.clone(),
            kronik_mcp::mount_for_tcp(api.clone()),
            tls.clone(),
        );
        async move {
            match api_tcp {
                Some(listener) => {
                    kronik_api::server::serve_tcp(listener, api, Some(mcp), tls, api_connections)
                        .await
                }
                None => std::future::pending().await,
            }
        }
    };
    // Without configured OIDC, an unavailable auxiliary admin port is nonfatal.
    let admin_listen = config.server.admin_listen;
    let admin = match early.admin {
        Some(early_admin) => early_admin.and_then(tokio::net::TcpListener::from_std),
        None => tokio::net::TcpListener::bind(admin_listen).await,
    };
    let admin = match admin {
        Ok(listener) => Some(listener),
        Err(error) if config.oidc.is_some() => {
            return Err(error).context("binding the configured OIDC admin listener");
        }
        Err(e) => {
            tracing::warn!(admin = %admin_listen, error = %e, "no admin UI, /metrics or /healthz: cannot bind the admin listener");
            None
        }
    };
    let admin = {
        let (node, api, browser, tls) = (node.clone(), api.clone(), browser.clone(), tls.clone());
        async move {
            match admin {
                Some(listener) => {
                    crate::admin::serve(listener, node, api, browser, tls, api_connections).await
                }
                None => std::future::pending().await,
            }
        }
    };
    let unix_api = async move {
        match unix {
            UnixApi::Listener(listener) => {
                kronik_api::server::serve_with(listener, api, Some(mcp)).await
            }
            UnixApi::Accepted(conns) => {
                kronik_api::server::serve_accepted(conns, api, Some(mcp)).await
            }
        }
    };
    let mut stopping = false;
    let served = tokio::select! {
        biased;
        msg = node.wait_fatal() => Err(anyhow::anyhow!("storage failure: {msg}")),
        r = kronik_gateway::server::serve_with_tls(tcp, gateway, tls, gateway_connections) => r.context("gateway listener failed"),
        r = unix_api => r.context("API listener failed"),
        r = api_tcp => r.context("TCP API listener failed"),
        r = admin => r.context("admin listener failed"),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; stopping");
            stopping = true;
            Ok(())
        }
        _ = term.recv() => {
            tracing::info!("SIGTERM; stopping");
            stopping = true;
            Ok(())
        }
    };
    // A controlled shutdown leaves a snapshot when something happened since
    // the newest one (the listeners are closed: their futures were dropped
    // with the select).
    if stopping {
        match node.shutdown_snapshot().await {
            Ok(Some(m)) => tracing::info!(lsn = m.lsn, "shutdown snapshot taken"),
            Ok(None) => tracing::info!("no shutdown snapshot: nothing new since the newest one"),
            Err(e) => tracing::warn!(error = %e.message, "shutdown snapshot failed"),
        }
    }
    let stopped = node
        .stop_native_execution()
        .map_err(|error| anyhow::anyhow!(error.message));
    native_execution.0 = None;
    // Sandboxes never outlive the daemon (docs/design/m7-foreign.md §5).
    foreign.shutdown().await;
    served?;
    stopped
}

/// After a `kronik restore`, records the system `AuditEvent` `restore`,
/// clamps every export cursor to the restored log and then deletes the
/// marker (M28 reviews H4, H-A). The clamp does not depend on an export
/// being on: a later start with `[audit]` on resumes at the restore point,
/// so it exports the `restore` line and everything after it. Each step is
/// durable before the next, so a crash leaves the marker and the next start
/// finishes the job: the event is recorded once (the log after the restore
/// point holds it then), and the clamp is idempotent.
async fn record_restore(
    node: &kronik_sched::Node,
    branch_dir: &Path,
    cursors: &Arc<kronik_otel::cursor::Cursors>,
    stop_after_event: bool,
    original: kronik_core::authority::AuthLease,
) -> anyhow::Result<()> {
    let marker = branch_dir.join(kronik_ship::RESTORE_MARKER);
    let body = match std::fs::read(&marker) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", marker.display())),
    };
    let v: serde_json::Value = serde_json::from_slice(&body)
        .with_context(|| format!("{} is not JSON", marker.display()))?;
    let through = v["through_lsn"]
        .as_u64()
        .filter(|through| *through <= node.applied_lsn())
        .context("the restore marker requires a valid through_lsn within the recovered log")?;
    let shown = through.to_string();
    let mut recorded = false;
    if node.applied_lsn() > through {
        node.reader()
            .read(through + 1, node.applied_lsn(), |c| {
                recorded |= matches!(&c.record, kronik_proto::Record::AuditEvent(e)
                    if e.action == "restore" && e.details.get("through_lsn") == Some(&shown));
                Ok(())
            })
            .await
            .context("reading the log after the restore point")?;
    }
    if !recorded {
        let audit = kronik_proto::log::v1::Audit {
            token_id: "system".into(),
            reason: "kronik restore".into(),
            wall_time_ms: node.env().clock.wall_ms(),
        };
        let details = [("through_lsn".to_owned(), shown)].into();
        node.record_system_audit_event(
            kronik_sched::SystemAudit::Restore,
            "",
            details,
            audit,
            original.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("recording the restore: {}", e.message))?;
    }
    if stop_after_event {
        anyhow::bail!("stopped after the restore event (--test-stop-after-restore-event)");
    }
    for stream in [crate::otel::TRACES, kronik_otel::sink::STREAM] {
        let saved = cursors.get(stream);
        let missing = saved.is_none();
        let old = saved.unwrap_or_default();
        let generation = loop {
            let generation = node.env().random_bytes();
            if generation != [0; 16]
                && generation != old.generation()
                && old
                    .pending_rewind()
                    .is_none_or(|r| r.generation != generation)
            {
                break generation;
            }
        };
        let mut control = kronik_otel::cursor::Control::new(generation);
        control.rewind = old.pending_rewind().map(|r| kronik_otel::cursor::Rewind {
            to: r.to.min(through),
            through: r.through.min(through),
            ..r
        });
        let entry = kronik_otel::cursor::Entry {
            lsn: old.lsn.min(through),
            state: if old.lsn > through {
                serde_json::Value::Null
            } else {
                old.state
            },
            control: Some(control),
        };
        // A fresh destination starts before the restore event even with
        // from="now"; an existing exporter keeps its older undelivered backlog.
        let entry = if missing {
            kronik_otel::cursor::Entry {
                lsn: through,
                ..entry
            }
        } else {
            entry
        };
        let owned = cursors.clone();
        node.authorized_effect(original.clone(), move || async move {
            Ok(owned.save(stream, entry).await)
        })
        .await
        .context("admitting restored export cursor")?
        .context("saving the export cursors")?;
    }
    if cursors
        .get(crate::otel::AUDIT_CONFIG)
        .is_some_and(|e| e.lsn > through)
    {
        let owned = cursors.clone();
        let entry = kronik_otel::cursor::Entry {
            lsn: through,
            ..Default::default()
        };
        node.authorized_effect(original.clone(), move || async move {
            Ok(owned.save(crate::otel::AUDIT_CONFIG, entry).await)
        })
        .await
        .context("admitting restored audit configuration cursor")?
        .context("resetting the restored audit configuration cache")?;
    }
    let fs = node.env().fs.clone();
    let branch_dir = branch_dir.to_path_buf();
    node.authorized_effect(original, move || async move {
        let removed = async {
            fs.remove_file(marker).await?;
            fs.sync_dir(branch_dir).await
        }
        .await;
        Ok(removed)
    })
    .await
    .context("admitting completed restore marker removal")?
    .context("syncing the restored branch after removing its marker")?;
    tracing::info!(through_lsn = through, "recorded the restore in the log");
    Ok(())
}

/// An offline source migration is audited once on its next successful start.
async fn record_key_source(
    node: &kronik_sched::Node,
    data: &Path,
    original: kronik_core::authority::AuthLease,
) -> anyhow::Result<()> {
    let marker = data
        .join("keys")
        .join(kronik_privacy::key_source::SOURCE_MARKER);
    let bytes = match kronik_privacy::key_source::read_envelope(&marker) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let id = value["id"]
        .as_str()
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .context("invalid key-source audit marker")?;
    let mut recorded = false;
    let first = node.reader().starts().await?.first().copied().unwrap_or(1);
    node.reader()
        .read(first, node.applied_lsn(), |c| {
            recorded |= matches!(&c.record, kronik_proto::Record::AuditEvent(e)
            if e.action == "keys.source" && e.details.get("id").is_some_and(|v| v == id));
            Ok(())
        })
        .await?;
    if !recorded {
        let secrets = node.secret_values().ok();
        let patterns = secrets
            .as_ref()
            .map(|values| kronik_sched::effects::secret_patterns(values));
        let scrub = |s| kronik_sched::scrub::for_log(s, patterns.as_deref());
        let details = [
            ("id".into(), id.into()),
            (
                "source".into(),
                scrub(value["source"].as_str().unwrap_or("")),
            ),
            ("key".into(), scrub(value["key"].as_str().unwrap_or(""))),
        ]
        .into();
        let audit = kronik_proto::log::v1::Audit {
            token_id: "system".into(),
            reason: scrub(value["reason"].as_str().unwrap_or("key source migration")),
            wall_time_ms: value["wall_ms"]
                .as_u64()
                .unwrap_or(node.env().clock.wall_ms()),
        };
        node.record_system_audit_event(
            kronik_sched::SystemAudit::KeySource,
            "",
            details,
            audit,
            original.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("recording key source: {}", e.message))?;
    }
    let fs = node.env().fs.clone();
    let directory = data.join("keys");
    node.authorized_effect(original, move || async move {
        let removed = async {
            fs.remove_file(marker).await?;
            fs.sync_dir(directory).await
        }
        .await;
        Ok(removed)
    })
    .await
    .context("admitting completed key-source marker removal")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use tracing::Level;

    #[derive(clap::Parser)]
    struct Serve {
        #[command(flatten)]
        args: super::ServeArgs,
    }

    #[test]
    fn init_forwards_the_selected_file_key_without_reloading_it() {
        let args = Serve::parse_from([
            "kronik",
            "--init",
            "--config",
            "/fixture/kronik.toml",
            "--master-key-file",
            "/fixture/selected-master.key",
        ])
        .args;
        let (_, config, selected_key) = args.init_args().unwrap();
        assert_eq!(config, Some(std::path::Path::new("/fixture/kronik.toml")));
        assert_eq!(
            selected_key,
            Some(std::path::Path::new("/fixture/selected-master.key"))
        );
    }

    #[test]
    fn test_flags_lists_the_set_test_hooks() {
        let flags = |argv: &[&str]| {
            Serve::parse_from([&["kronik"], argv].concat())
                .args
                .test_flags()
        };
        assert!(flags(&[]).is_empty());
        assert_eq!(
            flags(&[
                "--test-hold-after-call",
                "--test-replay-permits",
                "f",
                "--test-insecure-registry",
                "h:1",
                "--test-preview-sweep-ms",
                "50"
            ]),
            [
                "--test-hold-after-call",
                "--test-replay-permits",
                "--test-insecure-registry",
                "--test-preview-sweep-ms"
            ]
        );
        assert_eq!(
            flags(&["--test-replay-permits", "f"]),
            ["--test-replay-permits"]
        );
    }

    /// Runs `f` with each subscriber `kronik serve` can make for
    /// KRONIK_LOG=`spec`.
    fn with_filter(spec: &str, f: impl Fn()) {
        for format in [super::LogFormat::Text, super::LogFormat::Json] {
            tracing::subscriber::with_default(super::log_subscriber(format, Some(spec)), &f);
        }
    }

    #[test]
    fn rootless_is_a_flag_of_serve_and_conflicts_with_root_of_init() {
        let parse = |argv: &[&str]| Serve::try_parse_from([&["kronik"], argv].concat());
        assert!(!parse(&[]).unwrap().args.rootless);
        assert!(parse(&["--rootless"]).unwrap().args.rootless);
        let init = parse(&["--init", "--rootless"]).unwrap().args;
        let (init_args, _, _) = init.init_args().unwrap();
        assert!(init_args.rootless && !init_args.root);
        assert!(parse(&["--init", "--root", "--rootless"]).is_err());
        // --root without --init stays refused, as before.
        assert!(parse(&["--root"]).is_err());
    }

    #[test]
    fn rmcp_logs_at_info_at_most_whatever_kronik_log_says() {
        for spec in [
            "debug",
            "trace",
            "info",
            "debug,rmcp::service=debug",
            "rmcp=trace",
        ] {
            with_filter(spec, || {
                assert!(
                    !tracing::enabled!(target: "rmcp::service", Level::DEBUG),
                    "{spec}"
                );
                assert!(
                    tracing::enabled!(target: "rmcp::service", Level::INFO),
                    "{spec}"
                );
            });
        }
        with_filter("debug", || {
            assert!(tracing::enabled!(target: "kronik_api::server", Level::DEBUG));
        });
    }

    #[test]
    fn connections_leave_the_node_its_descriptors() {
        assert_eq!(super::connection_caps(65_536), (1024, 256));
        assert_eq!(super::connection_caps(2048), (768, 256));
        assert_eq!(super::connection_caps(1024), (384, 128));
        assert_eq!(super::connection_caps(256), (96, 32));
        assert_eq!(super::connection_caps(32), (16, 4));
    }
}
