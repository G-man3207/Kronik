//! `kronik serve`: opens the data directory, recovers from the log, and
//! serves the gateway on TCP and the API on the Unix socket. Settings come
//! from `kronik.toml` ([`crate::config`]); the flags override it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use kronik_api::Api;
use kronik_core::env::Env;
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
    /// Address of /metrics and /healthz [file: server.admin_listen].
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
    /// The configuration file, if any, with the flags in place.
    fn config(&self) -> anyhow::Result<Config> {
        let (config, _file) = Config::find(self.config.as_deref())?;
        let config = config.with(Overrides {
            data_dir: self.data_dir.clone(),
            api_socket: self.api_socket.clone(),
            http_listen: self.http_listen,
            admin_listen: self.admin_listen,
            api_listen: self.api_listen,
            gateway_timeout: self.gateway_timeout_ms.map(Duration::from_millis),
            master_key_file: self.master_key_file.clone(),
            disk_reserve: self.disk_reserve,
            otel_endpoint: self.otel_endpoint.clone(),
        });
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

/// The subscriber `kronik serve` logs through: KRONIK_LOG's filter (`spec`),
/// then [`rmcp_at_info`] over it.
fn log_subscriber(
    format: LogFormat,
    spec: Option<&str>,
) -> Box<dyn tracing::Subscriber + Send + Sync> {
    use tracing_subscriber::layer::SubscriberExt as _;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(log_filter(spec))
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
    init_tracing(args.log_format);
    let test_flags = args.test_flags();
    if !test_flags.is_empty() {
        tracing::warn!(flags = ?test_flags, "test-only flags are set; never use them in production");
    }
    if args.init.init {
        return crate::init::run_init(&args.init, args.config.as_deref());
    }
    let config = args.config()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kronik")
        .build()
        .context("starting the tokio runtime")?;
    rt.block_on(serve(args, config))
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
        checkpoints_kept: config.foreign.checkpoints_kept,
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

async fn serve(args: ServeArgs, config: Config) -> anyhow::Result<()> {
    // No core dumps or ptrace by other users: the process holds the master
    // key, secrets and plain subject data (PR_SET_DUMPABLE 0).
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        tracing::warn!(error = %e, "could not make the process non-dumpable");
    }
    let open_files = raise_open_files();
    let (gateway_connections, api_connections) = connection_caps(open_files);
    // A flag can set it too, so the file's check is not enough.
    let api_listen = config.api_listen().map_err(anyhow::Error::msg)?;
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
    let env = Env::real(tokio::runtime::Handle::current());
    let data_dir = config.server.data_dir.clone();
    restrict_data_dir(&data_dir, &config.server.api_socket)?;
    // Foreign actors (M7): the node starts them after recovering the log and
    // before re-running open turns; they stop when the daemon stops.
    let foreign = kronik_foreign::Foreign::new(
        env.clone(),
        foreign_config(
            &config,
            data_dir.clone(),
            args.test_insecure_registry.clone(),
        ),
    );
    let node_config = NodeConfig {
        foreign: kronik_effects::foreign::ForeignSlot(Some(Arc::new(kronik_foreign::Host(
            foreign.clone(),
        )))),
        concurrency: args.concurrency.max(1),
        master_key_file: Some(config.master_key_file()),
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
    let node = start_local(env.clone(), &data_dir, node_config)
        .await
        .with_context(|| format!("recovering {}", data_dir.display()))?;
    // Export streams (M28): each follows the log from its cursor.
    let cursors = Arc::new(
        kronik_otel::cursor::Cursors::load(env.clone(), &data_dir)
            .await
            .context("reading the export cursors")?,
    );
    record_restore(
        &node,
        &data_dir.join("branches/main"),
        &cursors,
        args.test_stop_after_restore_event,
    )
    .await?;
    let (audit_mapper, audit) =
        crate::otel::start_audit(&config, &node, &cursors, &data_dir).await?;
    let exports = vec![
        crate::otel::start(&config, &node, &cursors, &data_dir)?,
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
        drop(env.spawn(
            "ship",
            kronik_ship::ship_loop(
                env.clone(),
                remote,
                data_dir.clone(),
                "main".into(),
                kronik_ship::SHIP_INTERVAL,
                config.master_key_file(),
            ),
        ));
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
    let tcp = tokio::net::TcpListener::bind(http_listen)
        .await
        .with_context(|| format!("binding the gateway on {http_listen}"))?;
    let bound = tcp.local_addr().unwrap_or(http_listen);
    let tokens_db = data_dir.join("keys").join("tokens.db");
    let tokens =
        kronik_api::tokens::TokenStore::open_file(&tokens_db).map_err(anyhow::Error::msg)?;
    // Unfinished watches resume here (M11).
    let watches =
        kronik_fork::watch::Watches::open(node.clone(), proposals.clone(), data_dir.clone())
            .map_err(|e| anyhow::anyhow!("loading watches: {}", e.message))?
            .start();
    let api = Arc::new(
        Api::new(node.clone())
            .with_http_listen(bound.to_string())
            .with_preview_urls(
                config.gateway.preview_domain.clone(),
                tls.is_some(),
                config.public_host(bound),
            )
            .with_proposals(proposals)
            .with_watches(watches)
            .with_tokens(Arc::new(tokens))
            .with_foreign(foreign.clone())
            .with_exports(exports)
            .with_audit_mapper(audit_mapper),
    );
    let api_socket = &config.server.api_socket;
    let unix = kronik_api::server::bind(api_socket)
        .with_context(|| format!("binding the API on {}", api_socket.display()))?;
    let api_tcp = match api_listen {
        Some(addr) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding the API on {addr}"))?,
        ),
        None => None,
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
    // /metrics and /healthz are auxiliary: without the port, Kronik serves
    // anyway and says why.
    let admin_listen = config.server.admin_listen;
    let admin = match tokio::net::TcpListener::bind(admin_listen).await {
        Ok(listener) => Some(listener),
        Err(e) => {
            tracing::warn!(admin = %admin_listen, error = %e, "no /metrics and /healthz: cannot bind the admin listener");
            None
        }
    };
    let admin = async {
        match admin {
            Some(listener) => crate::admin::serve(listener, node.clone()).await,
            None => std::future::pending().await,
        }
    };
    let mut stopping = false;
    let served = tokio::select! {
        biased;
        msg = node.wait_fatal() => Err(anyhow::anyhow!("storage failure: {msg}")),
        r = kronik_gateway::server::serve_with_tls(tcp, gateway, tls, gateway_connections) => r.context("gateway listener failed"),
        r = kronik_api::server::serve_with(unix, api, Some(mcp)) => r.context("API listener failed"),
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
    // Sandboxes never outlive the daemon (docs/design/m7-foreign.md §5).
    foreign.shutdown().await;
    served
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
    cursors: &kronik_otel::cursor::Cursors,
    stop_after_event: bool,
) -> anyhow::Result<()> {
    let marker = branch_dir.join(kronik_ship::RESTORE_MARKER);
    let body = match std::fs::read(&marker) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", marker.display())),
    };
    let v: serde_json::Value = serde_json::from_slice(&body)
        .with_context(|| format!("{} is not JSON", marker.display()))?;
    let through = v["through_lsn"].as_u64().unwrap_or(0);
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
        node.record_audit_event("restore", "", details, audit)
            .await
            .map_err(|e| anyhow::anyhow!("recording the restore: {}", e.message))?;
    }
    if stop_after_event {
        anyhow::bail!("stopped after the restore event (--test-stop-after-restore-event)");
    }
    for stream in [crate::otel::TRACES, kronik_otel::sink::STREAM] {
        if let Some(e) = cursors.get(stream).filter(|e| e.lsn > through) {
            // The trace stream's open turns are the lost tail's.
            let state = if stream == crate::otel::TRACES {
                serde_json::Value::Null
            } else {
                e.state
            };
            let entry = kronik_otel::cursor::Entry {
                lsn: through,
                state,
            };
            cursors
                .save(stream, entry)
                .await
                .context("saving the export cursors")?;
        }
    }
    std::fs::remove_file(&marker).with_context(|| format!("removing {}", marker.display()))?;
    tracing::info!(through_lsn = through, "recorded the restore in the log");
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
