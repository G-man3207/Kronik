//! `kronik foreign add|list|logs|remove` (M7): foreign actors, Linux
//! programs from OCI images in gVisor behind a recorded boundary
//! (docs/design/m7-foreign.md §12 and §13).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use kronik_api::m7::{
    ForeignAddRequest, ForeignAddResponse, ForeignListResponse, ForeignLogsResponse,
    ForeignRemoveRequest, ForeignRemoveResponse, ForeignView,
};
use kronik_core::error::{ApiError, ErrorCode};

use super::render::{field, next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, reason, units};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Isolation {
    /// gVisor's runsc (the default).
    Gvisor,
    /// Plain runc on the host kernel: only for images you trust.
    Trusted,
    /// Firecracker: reserved, not implemented in v0.1.
    Microvm,
}

impl Isolation {
    fn as_str(self) -> &'static str {
        match self {
            Isolation::Gvisor => "gvisor",
            Isolation::Trusted => "trusted",
            Isolation::Microvm => "microvm",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ForeignCommand {
    /// Declare a foreign actor and start it: a Linux program from an OCI
    /// image, pinned by digest, that actors reach with foreign://<name>/...
    Add {
        /// The name actors use in foreign://<name>/... (DNS-style, e.g.
        /// payments.internal).
        name: String,
        /// `<registry>/<repo>@sha256:<digest>`, or a local OCI layout:
        /// `oci-layout:<dir>` (made absolute; the digest is optional when
        /// the layout holds one image).
        #[arg(long)]
        image: String,
        /// The TCP port the program listens on inside the sandbox.
        #[arg(long)]
        port: u32,
        /// CPUs, e.g. 1 or 0.5 [default: 1].
        #[arg(long)]
        cpu: Option<String>,
        /// Memory limit, e.g. 512Mi [default: 512Mi].
        #[arg(long)]
        memory: Option<String>,
        /// The sandbox [default: gvisor].
        #[arg(long, value_enum)]
        isolation: Option<Isolation>,
        /// A secret passed as an environment variable at start: `<name>`
        /// (variable NAME in upper case, `-` and `.` as `_`) or
        /// `<VAR>=<name>`. Repeat for more. The program sees the value.
        #[arg(long = "secret", value_name = "[VAR=]NAME")]
        secrets: Vec<String>,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// List the declared foreign actors and whether they are running.
    List,
    /// The last lines a foreign actor (and its runtime) wrote.
    Logs {
        name: String,
        /// How many lines [default: 200, at most 10000].
        #[arg(long)]
        tail: Option<u32>,
    },
    /// Stop a foreign actor and remove its declaration; its data directory
    /// (foreign/actors/<name>/data) is kept.
    Remove {
        name: String,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// With the daemon stopped (crashed or killed): delete what its
    /// sandboxes left behind, such as containers, network namespaces,
    /// bridge sockets and config.json files with secret values. The
    /// systemd unit runs it as ExecStopPost=. Local, as root; refused while
    /// a daemon holds [foreign] run_dir.
    Cleanup {
        /// The configuration file [default: /etc/kronik/kronik.toml if it
        /// exists].
        #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
        config: Option<PathBuf>,
        /// The data directory, as `kronik serve --data-dir` [file:
        /// server.data_dir].
        #[arg(long, value_name = "PATH", env = "KRONIK_DATA_DIR")]
        data_dir: Option<PathBuf>,
    },
}

pub(super) fn foreign(ctx: &Ctx, command: ForeignCommand) -> Result<ExitCode, Error> {
    match command {
        ForeignCommand::Add {
            name,
            image,
            port,
            cpu,
            memory,
            isolation,
            secrets,
            mutation,
        } => add(
            ctx,
            AddArgs {
                name,
                image,
                port,
                cpu,
                memory,
                isolation,
                secrets,
            },
            &mutation,
        ),
        ForeignCommand::List => list(ctx),
        ForeignCommand::Logs { name, tail } => logs(ctx, &name, tail),
        ForeignCommand::Remove { name, mutation } => remove(ctx, &name, &mutation),
        ForeignCommand::Cleanup { config, data_dir } => cleanup(ctx, config, data_dir),
    }
}

/// The JSON schema of `kronik foreign cleanup --json`.
#[cfg(test)]
pub fn cleanup_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<CleanupOutput>()
}

/// What `kronik foreign cleanup --json` prints: how many leftovers it
/// removed, and how many it could not (then it exits 1).
#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct CleanupOutput {
    sandboxes: u64,
    namespaces: u64,
    configs: u64,
    failed: u64,
}

fn cleanup(
    ctx: &Ctx,
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
) -> Result<ExitCode, Error> {
    let (config, _) = crate::config::Config::find(config.as_deref()).map_err(|e| {
        local(
            ErrorCode::BadRequest,
            e.to_string(),
            "Fix the file, or name another one with --config.",
        )
    })?;
    let data_dir = data_dir.unwrap_or_else(|| config.server.data_dir.clone());
    if !kronik_foreign::sys::is_root() {
        return Err(local(
            ErrorCode::Unavailable,
            "kronik foreign cleanup needs root, like the daemon's sandboxes".into(),
            "Run it as root (systemd's ExecStopPost= does).",
        ));
    }
    // What could not be removed is logged as a warning: show it.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::WARN)
        .try_init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            local(
                ErrorCode::Internal,
                format!("starting the runtime: {e}"),
                "",
            )
        })?;
    let cleaned = rt.block_on(async {
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let foreign = kronik_foreign::Foreign::new(
            env,
            crate::serve::foreign_config(&config, data_dir, Vec::new()),
        );
        foreign.cleanup().await
    });
    let cleaned = cleaned.map_err(|why| {
        local(
            ErrorCode::Unavailable,
            format!("not cleaning up: {why}"),
            "Stop the daemon first (systemctl stop kronik); it cleans up after itself when it stops.",
        )
    })?;
    let out = CleanupOutput {
        sandboxes: cleaned.sandboxes,
        namespaces: cleaned.namespaces,
        configs: cleaned.configs,
        failed: cleaned.failed,
    };
    if ctx.json {
        super::print_json(ctx, &out)?;
    } else {
        ctx.print(&format!(
            "Removed {} sandboxes, {} network namespaces and {} config.json files.\n",
            out.sandboxes, out.namespaces, out.configs
        ));
        if out.failed > 0 {
            ctx.print(&format!(
                "{} could not be removed or listed; the warnings above say which.\n",
                out.failed
            ));
        }
    }
    Ok(if out.failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

struct AddArgs {
    name: String,
    image: String,
    port: u32,
    cpu: Option<String>,
    memory: Option<String>,
    isolation: Option<Isolation>,
    secrets: Vec<String>,
}

fn local(code: ErrorCode, msg: String, hint: &str) -> Error {
    Error::from(ApiError::new(code, msg).with_hint(hint))
}

/// `--cpu 1`, `0.5`, `1.25` as thousandths of a CPU.
fn cpu_millis(s: &str) -> Result<u32, String> {
    let v: f64 = s
        .trim()
        .parse()
        .map_err(|_| format!("--cpu {s:?} is not a number of CPUs, e.g. 1 or 0.5"))?;
    let millis = (v * 1000.0).round();
    if !(1.0..=1_000_000.0).contains(&millis) {
        return Err(format!("--cpu {s:?} is out of range"));
    }
    Ok(millis as u32)
}

fn cpu_text(millis: u32) -> String {
    if millis.is_multiple_of(1000) {
        (millis / 1000).to_string()
    } else {
        format!("{}", f64::from(millis) / 1000.0)
    }
}

/// Makes the directory of `oci-layout:<dir>[@sha256:…]` absolute: the
/// daemon resolves it, from another working directory.
fn absolute_image(image: &str) -> Result<String, Error> {
    let Some(rest) = image.strip_prefix("oci-layout:") else {
        return Ok(image.to_owned());
    };
    let (path, digest) = match rest.rsplit_once("@sha256:") {
        Some((d, h)) => (d, Some(h)),
        None => (rest, None),
    };
    // `<dir>:<ref name>`, split at the first `:` as skopeo's `oci:` does.
    let (dir, reference) = match path.split_once(':') {
        Some((d, r)) => (d, Some(r)),
        None => (path, None),
    };
    let abs = std::fs::canonicalize(Path::new(dir)).map_err(|e| {
        local(
            ErrorCode::ImageInvalid,
            format!("the OCI layout directory {dir:?}: {e}"),
            "Give the directory of an OCI image layout (it holds oci-layout and index.json).",
        )
    })?;
    let mut out = format!("oci-layout:{}", abs.display());
    if let Some(r) = reference {
        let _ = write!(out, ":{r}");
    }
    if let Some(h) = digest {
        let _ = write!(out, "@sha256:{h}");
    }
    Ok(out)
}

fn add(ctx: &Ctx, a: AddArgs, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let cpu = a.cpu.as_deref().map(cpu_millis).transpose().map_err(|m| {
        local(
            ErrorCode::BadRequest,
            m,
            "For example --cpu 1 or --cpu 0.5.",
        )
    })?;
    let memory = a
        .memory
        .as_deref()
        .map(units::parse_size)
        .transpose()
        .map_err(|m| local(ErrorCode::BadRequest, m, "For example --memory 512Mi."))?;
    let image = absolute_image(&a.image)?;
    let mut rerun = format!(
        "kronik foreign add {} --image {} --port {}",
        shell_quote(&a.name),
        shell_quote(&image),
        a.port
    );
    if let Some(c) = cpu {
        let _ = write!(rerun, " --cpu {}", cpu_text(c));
    }
    if let Some(m) = memory {
        let _ = write!(rerun, " --memory {}", units::size_flag(m));
    }
    if let Some(i) = a.isolation {
        let _ = write!(rerun, " --isolation {}", i.as_str());
    }
    for s in &a.secrets {
        let _ = write!(rerun, " --secret {}", shell_quote(s));
    }
    let _ = write!(rerun, " --reason {}", shell_quote(reason));
    let body = ctx.post(
        "/v1/foreign",
        &ForeignAddRequest {
            name: a.name.clone(),
            image,
            port: a.port,
            cpu_millis: cpu,
            memory_bytes: memory,
            isolation: a.isolation.map(|i| i.as_str().to_owned()),
            secrets: a.secrets.clone(),
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ForeignAddResponse = ctx.decode(&body)?;
    ctx.print(&render_added(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn state(f: &ForeignView) -> String {
    let Some(s) = &f.status else {
        return "-".to_owned();
    };
    let mut out = s.state.clone();
    if let Some(e) = &s.last_exit {
        match (e.oom, e.code) {
            (true, _) => out.push_str(" (out of memory)"),
            (false, Some(c)) => {
                let _ = write!(out, " (exit {c})");
            }
            (false, None) => out.push_str(" (killed)"),
        }
    }
    out
}

fn describe(out: &mut String, f: &ForeignView) {
    field(out, "Image", std::slice::from_ref(&f.image), "");
    let isolation = if f.platform.is_empty() {
        f.isolation.clone()
    } else {
        format!("{} ({})", f.isolation, f.platform)
    };
    field(
        out,
        "Sandbox",
        &[format!(
            "port {}, {} CPU, {} memory, isolation {isolation}",
            f.port,
            cpu_text(f.cpu_millis),
            units::size(f.memory_bytes)
        )],
        "",
    );
    field(out, "Secrets", &f.secrets, "none");
    if let Some(e) = f.status.as_ref().and_then(|s| s.error.as_ref()) {
        field(out, "Error", std::slice::from_ref(e), "");
    }
}

fn render_added(r: &ForeignAddResponse, rerun: &str) -> String {
    let f = &r.foreign;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: foreign actor {} can be added at epoch {}; the image is verified, nothing was written",
            f.name, f.epoch
        );
        describe(&mut out, f);
        for w in &r.warnings {
            let _ = writeln!(out, "Warning: {w}");
        }
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    let _ = writeln!(
        out,
        "Added foreign actor {} (epoch {}, main:{}): {}",
        f.name,
        f.epoch,
        f.lsn,
        state(f)
    );
    describe(&mut out, f);
    for w in &r.warnings {
        let _ = writeln!(out, "Warning: {w}");
    }
    out.push_str(&next(&[
        format!(
            "kronik grant <kind> foreign:{} --reason \"...\"   (then call foreign://{}/... from the kind)",
            f.name, f.name
        ),
        format!("kronik foreign logs {}", shell_quote(&f.name)),
    ]));
    out
}

fn list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/foreign")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ForeignListResponse = ctx.decode(&body)?;
    ctx.print(&render_list(&r));
    Ok(ExitCode::SUCCESS)
}

fn render_list(r: &ForeignListResponse) -> String {
    let off = r
        .unavailable
        .as_ref()
        .map(|why| format!("Foreign actors are off in this daemon: {why}\n"))
        .unwrap_or_default();
    if r.foreign.is_empty() {
        let mut out = off;
        out.push_str("No foreign actors.\n");
        out.push_str(&next(&[
            "kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason \"...\""
                .to_owned(),
        ]));
        return out;
    }
    let rows = r
        .foreign
        .iter()
        .map(|f| {
            vec![
                f.name.clone(),
                state(f),
                f.status
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |s| s.restarts.to_string()),
                f.port.to_string(),
                cpu_text(f.cpu_millis),
                units::size_flag(f.memory_bytes),
                f.isolation.clone(),
                f.image.clone(),
            ]
        })
        .collect();
    let mut out = table(
        &[
            "NAME",
            "STATE",
            "RESTARTS",
            "PORT",
            "CPU",
            "MEMORY",
            "ISOLATION",
            "IMAGE",
        ],
        rows,
    );
    out.push_str(&off);
    for f in &r.foreign {
        if let Some(e) = f.status.as_ref().and_then(|s| s.error.as_ref()) {
            let _ = writeln!(out, "{}: {e}", f.name);
        }
    }
    out.push_str(&next(&[
        "kronik foreign logs <name>".to_owned(),
        "kronik foreign remove <name> --reason \"...\"".to_owned(),
    ]));
    out
}

fn logs(ctx: &Ctx, name: &str, tail: Option<u32>) -> Result<ExitCode, Error> {
    let mut target = format!("/v1/foreign/{}/logs", http::encode(name));
    if let Some(t) = tail {
        let _ = write!(target, "?tail={t}");
    }
    let body = ctx.get(&target)?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ForeignLogsResponse = ctx.decode(&body)?;
    let mut out = String::new();
    if r.truncated {
        out.push_str("(earlier lines omitted)\n");
    }
    for l in &r.lines {
        out.push_str(l);
        out.push('\n');
    }
    if r.lines.is_empty() {
        let _ = writeln!(out, "{} has written nothing yet.", r.name);
    }
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn remove(ctx: &Ctx, name: &str, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let body = ctx.send_json(
        "DELETE",
        &format!("/v1/foreign/{}", http::encode(name)),
        &ForeignRemoveRequest {
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ForeignRemoveResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik foreign remove {} --reason {}",
        shell_quote(name),
        shell_quote(reason)
    );
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: foreign actor {} can be removed at epoch {}; nothing was written",
            r.removed.name, r.removed.epoch
        );
        out.push_str(&next(&[rerun]));
        return Ok({
            ctx.print(&out);
            ExitCode::SUCCESS
        });
    }
    let _ = writeln!(
        out,
        "Removed foreign actor {} (epoch {}, main:{}); its sandbox is stopped and foreign/actors/{}/data is kept",
        r.removed.name, r.removed.epoch, r.removed.lsn, r.removed.name
    );
    out.push_str(&next(&["kronik foreign list".to_owned()]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpus_are_thousandths() {
        assert_eq!(cpu_millis("1").unwrap(), 1000);
        assert_eq!(cpu_millis("0.5").unwrap(), 500);
        assert_eq!(cpu_millis("1.25").unwrap(), 1250);
        assert!(cpu_millis("0").is_err());
        assert!(cpu_millis("x").is_err());
        assert_eq!(cpu_text(1000), "1");
        assert_eq!(cpu_text(500), "0.5");
    }

    #[test]
    fn layout_directories_become_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let rel = pathdiff(dir.path(), &cwd);
        let img = absolute_image(&format!("oci-layout:{rel}@sha256:ab"))
            .ok()
            .unwrap();
        assert_eq!(
            img,
            format!(
                "oci-layout:{}@sha256:ab",
                std::fs::canonicalize(dir.path()).unwrap().display()
            )
        );
        assert_eq!(
            absolute_image("ghcr.io/org/x@sha256:ab").ok().unwrap(),
            "ghcr.io/org/x@sha256:ab"
        );
        assert!(absolute_image("oci-layout:/nonexistent/dir").is_err());
        let named = absolute_image(&format!("oci-layout:{rel}:echo:dev"))
            .ok()
            .unwrap();
        assert!(named.ends_with(":echo:dev"), "{named}");
    }

    /// `path` relative to `base` through the root (`../../tmp/x`).
    fn pathdiff(path: &Path, base: &Path) -> String {
        let ups = base.components().count().saturating_sub(1);
        let mut s = "../".repeat(ups);
        s.push_str(path.to_string_lossy().trim_start_matches('/'));
        s
    }
}
