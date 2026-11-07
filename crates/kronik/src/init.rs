//! Idempotent systemd setup. The root service of v0.1 to v0.4 is the default
//! (`DEFAULT_MODE`) and `--rootless` selects the stable nonroot service. Both
//! support a read-only dry-run plan and JSON output. An installation of the
//! other kind is refused, never converted in place: the numeric owner of the
//! data decides (ADR 0063).
#[path = "init/setup.rs"]
mod setup;
use setup::*;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, bail};
use clap::Args;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_privacy::owned_tree::{Ancestors, Dir, Kind};

use crate::config::{Config, DEFAULT_PATH};

/// The unit, with `@KRONIK@` standing for the binary's path.
const UNIT: &str = include_str!("../../../deploy/systemd/kronik.service");
const MASTER_KEY: &str = "/etc/kronik/master.key";
const USERNS_UNIT: &str = include_str!("../../../deploy/systemd/kronik-userns.service");
const ROOT_UNIT: &str = include_str!("../../../deploy/systemd/kronik-root.service");

/// The one place that decides which service `--init` installs when neither
/// `--root` nor `--rootless` says. It is `Mode::Root`, the service of v0.1 to
/// v0.4, until the nonroot service has been run on the platforms that matter
/// (Ubuntu 24.04 with systemd 255). Set it to `Mode::Rootless` to make the
/// nonroot service the default and the root one the explicit `--root` choice;
/// nothing else in the code changes (the documentation does).
const DEFAULT_MODE: Mode = Mode::Root;

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Install and start the systemd service: the root service by default,
    /// the stable nonroot one with `--rootless`. Run as root; safe to run
    /// again.
    #[arg(long)]
    pub init: bool,
    /// With --init: the name to get a TLS certificate for with ACME
    /// (repeatable). Without it, the gateway serves plain HTTP on port 80.
    #[arg(long, requires = "init", requires = "acme_email", value_name = "NAME")]
    pub domain: Vec<String>,
    /// With --init and --domain: where the CA sends expiry notices.
    #[arg(long, requires = "domain", value_name = "EMAIL")]
    pub acme_email: Option<String>,
    /// With --init: install the root service (the v0.1 unit). This is the
    /// default; the flag names it explicitly. Also how an existing root
    /// installation is rerun.
    #[arg(long, requires = "init", conflicts_with = "rootless")]
    pub root: bool,
    /// `serve --rootless`, which with --init asks for the nonroot service
    /// explicitly. Copied in by `ServeArgs::init_args`; not an argument of
    /// its own.
    #[arg(skip)]
    pub rootless: bool,
    /// With --init: print what would be done, and change nothing.
    #[arg(long, requires = "init")]
    pub dry_run: bool,
}

impl InitArgs {
    /// The service this run installs.
    fn mode(&self) -> Mode {
        if self.root {
            Mode::Root
        } else if self.rootless {
            Mode::Rootless
        } else {
            DEFAULT_MODE
        }
    }
}

/// One thing `--init` sees to.
enum Step {
    /// A file written only if it is missing.
    Create {
        path: PathBuf,
        contents: String,
        mode: u32,
    },
    /// A file kept equal to `contents`.
    Install {
        path: PathBuf,
        contents: String,
        mode: u32,
    },
    Dir {
        path: PathBuf,
        mode: u32,
    },
    MasterKey {
        keys: Box<kronik_privacy::key_source::Keys>,
        data: PathBuf,
    },
    Group,
    User(PathBuf),
    SubIds,
    Remove(PathBuf),
}

impl Step {
    /// What the step is, for the plan.
    fn describe(&self) -> String {
        match self {
            Step::Create { path, mode, .. }
            | Step::Install { path, mode, .. }
            | Step::Dir { path, mode } => {
                format!("{} (mode {mode:04o})", path.display())
            }
            Step::MasterKey { keys, .. }
                if keys.source == kronik_privacy::key_source::Source::Env
                    || (keys.source == kronik_privacy::key_source::Source::File
                        && std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some()) =>
            {
                "env master key from KRONIK_MASTER_KEY (no key file)".into()
            }
            Step::MasterKey { keys, data } => format!(
                "{} master key at {}",
                keys.source.as_str(),
                if keys.source.is_kms() {
                    data.join(&keys.wrapped_file)
                } else {
                    keys.key_path(data)
                }
                .display(),
            ),
            Step::Group => "group kronik (groupadd --system kronik)".into(),
            Step::User(home) => format!("system user kronik (home {})", home.display()),
            Step::SubIds => {
                "shadow usermod subordinate UID/GID allocation (locked by shadow tools)".into()
            }
            Step::Remove(path) => format!("remove {}", path.display()),
        }
    }

    /// `None` when the step has nothing to do, else the verb of the plan.
    fn needed(&self) -> anyhow::Result<Option<&'static str>> {
        Ok(match self {
            Step::Create { path, .. } => (!path.exists()).then_some("create"),
            Step::MasterKey { .. } => Some("check"),
            Step::Dir { path, .. } => (!path.is_dir()).then_some("create"),
            Step::Install { path, contents, .. } => match std::fs::read_to_string(path) {
                Ok(current) if current == *contents => None,
                Ok(_) => Some("update"),
                Err(_) => Some("create"),
            },
            Step::Group => (!group_exists()?).then_some("create"),
            Step::User(_) => user_ids()?.is_none().then_some("create"),
            Step::SubIds => Some("check"),
            Step::Remove(path) => path.exists().then_some("delete"),
        })
    }

    fn apply(
        &self,
        held: Option<&kronik_privacy::key_source::DataOwnership>,
    ) -> anyhow::Result<()> {
        match self {
            Step::Create {
                path,
                contents,
                mode,
            }
            | Step::Install {
                path,
                contents,
                mode,
            } => durable_write(path, contents.as_bytes(), *mode),
            Step::Dir { path, mode } => {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("creating {}", path.display()))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                    .with_context(|| format!("setting the mode of {}", path.display()))
            }
            Step::MasterKey { keys, data } => {
                let existing = if keys.source.is_kms() {
                    keys.envelope_path(data)?.try_exists()?
                } else {
                    keys.source == kronik_privacy::key_source::Source::Env
                        || std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some()
                        || keys.key_path(data).try_exists()?
                };
                if let Some(held) = held {
                    // The lock is held for as long as this value exists; the
                    // directory it holds must still be the one `data` names.
                    let named = std::fs::metadata(data)?;
                    let locked = held.directory_resource().metadata()?;
                    anyhow::ensure!(
                        (named.dev(), named.ino()) == (locked.dev(), locked.ino()),
                        "key setup destination changed while locked"
                    );
                }
                // A rerun may read an active key; only first creation owns
                // the directory exclusively. Read-only loading uses staging.
                let _ownership = if existing || held.is_some() {
                    None
                } else {
                    Some(kronik_privacy::key_source::lock_data(data)?)
                };
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime
                    .block_on(async {
                        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
                        kronik_privacy::key_source::KeySource::load(
                            env,
                            keys.as_ref().clone(),
                            data,
                            !existing,
                        )
                        .await
                    })
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            }
            Step::Group => sh(&["groupadd", "--system", "kronik"]),
            Step::User(home) => sh(&[
                "useradd",
                "--system",
                "--gid",
                "kronik",
                "--home-dir",
                &home.to_string_lossy(),
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "kronik",
            ]),
            Step::SubIds => allocate_ranges(),
            Step::Remove(path) => durable_remove(path),
        }
    }
}

fn sh(argv: &[&str]) -> anyhow::Result<()> {
    use std::os::fd::AsFd as _;
    let stderr = std::io::stderr().as_fd().try_clone_to_owned()?;
    let status = Command::new(argv[0])
        .args(&argv[1..])
        .stdout(stderr)
        .status()
        .with_context(|| format!("running {}", argv.join(" ")))?;
    if !status.success() {
        bail!("{} failed ({status})", argv.join(" "));
    }
    Ok(())
}

fn group_exists() -> anyhow::Result<bool> {
    let status = Command::new("getent")
        .args(["group", "kronik"])
        .stdout(std::process::Stdio::null())
        .status()
        .context("running getent group kronik")?;
    Ok(status.success())
}

/// The configuration `--init` writes: the brief's file, with TLS by ACME for
/// the given names, or plain HTTP on port 80 without them.
fn config_file(domains: &[String], acme_email: Option<&str>) -> String {
    let quote = |s: &str| serde_json::Value::from(s).to_string();
    let tls = if domains.is_empty() {
        "mode = \"off\"                          # acme, files or off\n".to_owned()
    } else {
        format!(
            "mode = \"acme\"                         # acme, files or off\ndomains = [{}]\nacme_email = {}\n",
            domains
                .iter()
                .map(|d| quote(d))
                .collect::<Vec<_>>()
                .join(", "),
            quote(acme_email.unwrap_or_default()),
        )
    };
    let listen = if domains.is_empty() {
        "0.0.0.0:80"
    } else {
        "0.0.0.0:443"
    };
    format!(
        r#"# Kronik's server settings, written by `kronik serve --init`. Only the
# server's basics live here: grants, limits, policy, privacy mode and foreign
# actors are history, set with the CLI or the API. `kronik serve` reads this
# file at start; its flags override it.

[server]
data_dir = "/var/lib/kronik"
api_socket = "/run/kronik/api.sock"
http_listen = "{listen}"
admin_listen = "127.0.0.1:9464"      # /metrics and /healthz

[tls]
{tls}
[gateway]
timeout = "30s"
idempotency_header = "Idempotency-Key"
idempotency_ttl = "24h"
trusted_proxies = []                 # a reverse proxy here has no per-client connection cap
# preview_domain = "example-preview.com"   # previews only at https://<id>.<domain>/; acme needs dns01_hook

[log]
group_commit_ms = 2
segment_max_mb = 64
segment_max_age_s = 60
disk_reserve = "512MiB"              # below this much free space, new inputs wait

[retention]
history = "7d"                        # how far back the log reaches
snapshot_interval = "60m"
snapshots_kept = 48

[sql]
max_size_per_actor = "1GiB"

[ship]
enabled = false
# url = "s3://bucket/kronik"
# endpoint = "https://s3.example.com"

[keys]
master_key_file = "{MASTER_KEY}"   # secret store and privacy keystore

[privacy]
keystore_backup_retention = "30d"
# subject_from = "header:x-user-id"

[replay]
default_mode = "both"                 # isolated, continuous or both
sample = "100%"                       # isolated mode, stratified per route and actor type

[fork]
live_allowlist = []
preview_ttl = "24h"                   # how long a preview fork lives

# The model simulator for forks (M12): off unless configured, and only for
# targets that allow it (`kronik stubs set`). It never sees personal data.
# [simulators.model]
# endpoint = "http://127.0.0.1:11434/v1/chat/completions"  # OpenAI-compatible
# model = "llama3.1"
# api_key_env = "KRONIK_MODEL_API_KEY"
# timeout = "20s"
# max_examples = 5

[promote]
max_gap = "2s"
catch_up_timeout = "5m"

[rebase]
max_pause = "2s"                      # rollback --by-replay: the longest the switch holds requests

[foreign]
runsc_path = "/usr/local/bin/runsc"
platform = "auto"                     # auto, systrap or kvm
run_dir = "/run/kronik"               # runsc state, namespaces, bridge sockets
layout_dirs = []                      # oci-layout: images an operate token may add
pull_timeout = "10m"
checkpoints_kept = 3                  # per fork_mode = "sandbox" actor, one per snapshot
"#
    )
}

#[derive(serde::Serialize, schemars::JsonSchema)]
pub(crate) struct InitOutput {
    dry_run: bool,
    mode: Mode,
    steps: Vec<StepOutput>,
    /// What `kronik doctor` warned about once the service was running
    /// (absent: nothing, or a dry run). A warning is not a failure: the install
    /// succeeded, but nothing here proves that sandboxes work.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<DoctorWarning>,
}
/// A warning of `kronik doctor`, as `serve --init` saw it.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub(crate) struct DoctorWarning {
    /// The check: `delegate`, `sandbox`, `caps`, ...
    check: String,
    message: String,
    hint: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct StepOutput {
    action: String,
    what: String,
}

/// Fixed production setup inputs; only the standalone owned-fixture driver constructs alternatives.
pub(crate) struct InitHost {
    exe: PathBuf,
    unit_name: String,
    pin_unit_name: String,
    unit_dir: PathBuf,
    fixture_etc: Option<PathBuf>,
    fixture_helper: Option<PathBuf>,
    selected_key: Option<PathBuf>,
}
impl InitHost {
    fn production(selected_key: Option<&Path>) -> anyhow::Result<Self> {
        Ok(Self {
            exe: std::env::current_exe()?.canonicalize()?,
            unit_name: "kronik.service".into(),
            pin_unit_name: "kronik-userns.service".into(),
            unit_dir: "/etc/systemd/system".into(),
            fixture_etc: None,
            fixture_helper: None,
            selected_key: selected_key.map(Path::to_owned),
        })
    }
    fn unit(&self) -> PathBuf {
        self.unit_dir.join(&self.unit_name)
    }
    fn pin_unit(&self) -> PathBuf {
        self.unit_dir.join(&self.pin_unit_name)
    }
    fn dropin(&self, name: &str) -> PathBuf {
        self.unit_dir
            .join(format!("{}.d", self.unit_name))
            .join(name)
    }
    fn control_output(&self, args: &[&str]) -> anyhow::Result<std::process::Output> {
        let mut command = if let Some(etc) = &self.fixture_etc {
            let mut command = Command::new(
                self.fixture_helper
                    .as_ref()
                    .context("fixture helper missing")?,
            );
            command
                .arg("control")
                .arg(etc.parent().context("fixture root missing")?);
            command
        } else {
            Command::new("systemctl")
        };
        let output = command.args(args).output()?;
        anyhow::ensure!(
            output.status.success(),
            "service-manager command {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }
    fn control(&self, args: &[&str]) -> anyhow::Result<()> {
        if self.fixture_etc.is_none() {
            use std::os::fd::AsFd as _;
            let stderr = std::io::stderr().as_fd().try_clone_to_owned()?;
            let status = Command::new("systemctl")
                .args(args)
                .stdout(stderr)
                .status()?;
            anyhow::ensure!(status.success(), "systemctl {args:?} failed ({status})");
            return Ok(());
        }
        let output = self.control_output(args)?;
        use std::io::Write as _;
        std::io::stderr().write_all(&output.stdout)?;
        std::io::stderr().write_all(&output.stderr)?;
        Ok(())
    }
    /// Stops an owned fixture unit (or the pin unit): only the two units this
    /// host installs, and an already absent or inactive unit is quiescent.
    #[cfg(test)]
    pub(crate) fn stop(&self, unit: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            unit == self.unit_name || unit == self.pin_unit_name,
            "unowned setup stop target"
        );
        let output = self.control_output(&[
            "show",
            unit,
            "--property=LoadState,ActiveState,MainPID",
            "--no-pager",
        ])?;
        let state = std::str::from_utf8(&output.stdout)?;
        // An absent service is already quiescent; every other manager error stays fatal.
        if ["LoadState=not-found", "ActiveState=inactive", "MainPID=0"]
            .iter()
            .all(|expected| state.lines().any(|line| line == *expected))
        {
            return Ok(());
        }
        self.control(&["stop", unit])
    }
    #[cfg(test)]
    pub(crate) fn owned_fixture(
        exe: PathBuf,
        root: &Path,
        unit_name: String,
        helper: PathBuf,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            unit_name.starts_with("kronik-proof-")
                && unit_name.ends_with(".service")
                && unit_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "fixture requires an exact allocated kronik-proof unit"
        );
        let metadata = std::fs::symlink_metadata(root)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
            "fixture root must be private and root-owned"
        );
        let pin_unit_name = format!("{}-pin.service", unit_name.trim_end_matches(".service"));
        let marker = format!("# Kronik owned fixture {}\n", root.display());
        for name in [&unit_name, &pin_unit_name] {
            let path = root.join("units").join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(meta) => {
                    anyhow::ensure!(
                        meta.is_file()
                            && meta.uid() == 0
                            && meta.nlink() == 1
                            && meta.mode() & 0o022 == 0,
                        "fixture unit is not a protected owned file"
                    );
                    anyhow::ensure!(
                        std::fs::read_to_string(&path)?.starts_with(&marker),
                        "refusing to overwrite another fixture's unit"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Self {
            exe,
            unit_name,
            pin_unit_name,
            unit_dir: root.join("units"),
            fixture_etc: Some(root.join("etc")),
            fixture_helper: Some(helper),
            selected_key: None,
        })
    }
}

#[cfg(test)]
pub fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<InitOutput>()
}

fn unit(
    template: &str,
    host: &InitHost,
    config_path: &Path,
    config: &Config,
    systemd: u32,
) -> anyhow::Result<String> {
    use kronik_privacy::key_source::Source;
    let file = config.keys.source == Source::File;
    let credential = if file {
        format!(
            "LoadCredential=master-key:{}",
            config.keys.key_path(&config.server.data_dir).display()
        )
    } else {
        String::new()
    };
    let mut text = template
        .replace("@KRONIK@", &host.exe.to_string_lossy())
        .replace("@CONFIG@", &config_path.to_string_lossy())
        .replace("@KEY_CREDENTIAL@", &credential)
        .replace(
            "@KEY_ARGUMENT@",
            if file {
                " --master-key-file %d/master-key"
            } else {
                ""
            },
        )
        .replace(
            "ReadWritePaths=/var/lib/kronik",
            &format!("ReadWritePaths={}", config.server.data_dir.display()),
        );
    text = text
        .replace("kronik-userns.service", &host.pin_unit_name)
        .replace("kronik.service", &host.unit_name);
    if let Some(etc) = &host.fixture_etc {
        let root = etc.parent().context("fixture etc has no parent")?;
        if template == USERNS_UNIT {
            let helper = host
                .fixture_helper
                .as_ref()
                .context("fixture pin helper is missing")?;
            return Ok(format!(
                "# Kronik owned fixture {}\n[Unit]\nDescription=Kronik owned proof namespace\nBefore={}\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={} pin {}\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_DAC_OVERRIDE\nCPUQuota=200%\nMemoryMax=2G\nTasksMax=512\nTimeoutStartSec=90\nTimeoutStopSec=30\nStandardOutput=append:{0}/pin.log\nStandardError=append:{0}/pin.log\n",
                root.display(),
                host.unit_name,
                helper.display(),
                root.display()
            ));
        }
        // /etc is already private; credential sources beneath PrivateTmp disappear in the unit.
        text = text
            .replace(
                &config_path.to_string_lossy().to_string(),
                "/etc/kronik/kronik.toml",
            )
            .replace(
                "RuntimeDirectory=kronik\n",
                &format!(
                    "RuntimeDirectory={}\n",
                    host.unit_name.trim_end_matches(".service")
                ),
            )
            .replace("LogsDirectory=kronik\n", "")
            .replace("LogsDirectoryMode=0750\n", "");
        text = text.replace(
            &host.exe.to_string_lossy().to_string(),
            "/usr/local/bin/kronik",
        );
        if template == ROOT_UNIT {
            // Root reversal controls need namespace-local NET_ADMIN, never host NET_ADMIN.
            text = text.replace("ExecStart=/usr/local/bin/kronik ",
                "ExecStart=/usr/bin/unshare --user --mount --propagation private --keep-caps --map-users=0:0:65536 --map-groups=0:0:65536 /usr/local/bin/kronik ");
        }
        text = text.replace("[Service]\n", &format!("[Service]\nBindReadOnlyPaths=/usr/local/bin/kronik\nBindReadOnlyPaths={}/kronik/kronik.toml:/etc/kronik/kronik.toml\nBindReadOnlyPaths=-{}/run/kronik-userns/user:/run/kronik-userns/user\nBindPaths={}/data:{}\nBindPaths={}/run/kronik:{}\nBindPaths={}/ship:/var/lib/kronik-ship\nReadWritePaths=/var/lib/kronik-ship\nCPUQuota=200%\nMemoryMax=2G\nTasksMax=512\nRuntimeMaxSec=1800\nTimeoutStartSec=90\nTimeoutStopSec=30\nStandardOutput=append:{}/serve.log\nStandardError=append:{}/serve.log\n", etc.display(), root.display(), root.display(), config.server.data_dir.display(), root.display(), config.foreign.run_dir.display(), root.display(), root.display(), root.display()));
        text = text.replace(
            "[Service]\n",
            &format!(
                "[Service]\nReadWritePaths={}\n",
                config.foreign.run_dir.display()
            ),
        );
        if root.join("microvm").is_dir() {
            text = text.replace(
                "[Service]\n",
                &format!(
                    "[Service]\nBindReadOnlyPaths={}/microvm:/usr/local/lib/kronik/microvm\n",
                    root.display()
                ),
            );
        }
        if root.join("directory-tools").is_dir() {
            text = text.replace("[Service]\n", &format!("[Service]\nBindReadOnlyPaths={}/directory-tools:/usr/local/lib/kronik/directory-tools\n", root.display()));
        }
        let (uid, gid) =
            user_ids()?.context("fixture's private numeric service identity is missing")?;
        text = text
            .replace("User=kronik", &format!("User={uid}"))
            .replace("Group=kronik", &format!("Group={gid}"));
        let bindings = ["passwd", "group", "subuid", "subgid"]
            .iter()
            .map(|name| {
                format!(
                    "BindReadOnlyPaths={}/{}:/etc/{}\n",
                    etc.display(),
                    name,
                    name
                )
            })
            .collect::<String>();
        text = text.replace("[Service]\n", &format!("[Service]\n{bindings}"));
        text.insert_str(0, &format!("# Kronik owned fixture {}\n", root.display()));
    }
    Ok(if systemd < 257 {
        text.replace("ProtectControlGroups=private\n", "")
    } else {
        text
    })
}

fn plan(
    args: &InitArgs,
    config_path: &Path,
    host: &InitHost,
) -> anyhow::Result<(Config, Vec<Step>)> {
    let mut steps = Vec::new();
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        let text = config_file(&args.domain, args.acme_email.as_deref());
        let config = Config::parse(&text, config_path)?;
        steps.push(Step::Create {
            path: config_path.to_owned(),
            contents: text,
            mode: 0o644,
        });
        config
    };
    // What the configuration says, before a flag overrides it: the root unit
    // starts the daemon with the configuration alone.
    let configured_key = config.keys.key_path(&config.server.data_dir);
    let mut config = config.with(crate::config::Overrides {
        master_key_file: host.selected_key.clone(),
        ..Default::default()
    });
    config
        .keys
        .check_environment()
        .map_err(|error| error.api_error())?;
    if args.mode() == Mode::Root
        && let Some(selected) = &host.selected_key
        && *selected != configured_key
    {
        // The unit of v0.4.0 passes the daemon no key file, so the key step
        // would create or load one key and the daemon use another.
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            format!(
                "--master-key-file {} would not reach the root service: its unit starts the daemon with the configuration alone, and the configuration names {}",
                selected.display(),
                configured_key.display()
            ),
        )
        .with_hint("Set `[keys] master_key_file` in the configuration to that file and run `serve --init --root` again, or use `--rootless`, whose unit hands the file to the daemon as a credential.")
        .into());
    }
    if config.keys.source == kronik_privacy::key_source::Source::File
        && std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some()
    {
        if !args.dry_run {
            let mut established = false;
            for name in ["secrets.db", "keystore.db"] {
                match std::fs::metadata(config.server.data_dir.join("keys").join(name)) {
                    Ok(metadata) => established |= metadata.len() > 0,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !established {
                return Err(ApiError::new(ErrorCode::BadRequest, "the installer's transient KRONIK_MASTER_KEY cannot select a persistent systemd source")
                    .with_hint("Set [keys] source = \"env\" and provision KRONIK_MASTER_KEY in the service's native environment. Initialization never writes an environment seed into a unit or silently switches to a generated file seed.").into());
            }
        }
        // This is the loader's effective selection, not a persisted configuration rewrite.
        config.keys.source = kronik_privacy::key_source::Source::Env;
    }
    let rootless = args.mode() == Mode::Rootless;
    if rootless && config.keys.source == kronik_privacy::key_source::Source::File {
        reject_key_in_data_directory(&config)?;
        reject_key_in_writable_place(&config)?;
    }
    let systemd = if rootless { rootless_checks()? } else { 0 };
    steps.push(Step::Group);
    if rootless {
        steps.push(Step::User(config.server.data_dir.clone()));
        steps.push(Step::SubIds);
    }
    steps.push(Step::Dir {
        path: config.server.data_dir.clone(),
        mode: 0o700,
    });
    // Keys are initialized only after the destination layout is owned.
    steps.push(Step::MasterKey {
        keys: Box::new(config.keys.clone()),
        data: config.server.data_dir.clone(),
    });
    if rootless {
        steps.push(Step::Install {
            path: host.pin_unit(),
            contents: unit(USERNS_UNIT, host, config_path, &config, systemd)?,
            mode: 0o644,
        });
    }
    steps.push(Step::Install {
        path: host.unit(),
        contents: unit(
            if rootless { UNIT } else { ROOT_UNIT },
            host,
            config_path,
            &config,
            systemd,
        )?,
        mode: 0o644,
    });
    let microvm = config
        .foreign
        .microvm_dir
        .join("manifest.json")
        .try_exists()?;
    if microvm {
        kronik_foreign::microvm::validate_tools(&config.foreign.microvm_dir)
            .map_err(|why| ApiError::new(ErrorCode::RootlessUnavailable, why))?;
    }
    let kvm = rootless && (config.foreign.platform == crate::config::Platform::Kvm || microvm);
    let kvm_path = host.dropin("kvm.conf");
    let current_kvm = match std::fs::read_to_string(&kvm_path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let managed_kvm = current_kvm.as_deref().is_some_and(|text| {
        text.starts_with("# Written by kronik serve --init\n")
            || text.starts_with("# Written by `kronik serve --init` for ")
    });
    if kvm {
        anyhow::ensure!(
            current_kvm.is_none() || managed_kvm,
            "the managed KVM drop-in path contains custom rules; move those rules to another drop-in before enabling managed KVM"
        );
        use std::os::unix::fs::FileTypeExt as _;
        let supplementary = match std::fs::metadata("/dev/kvm") {
            Ok(device) => {
                anyhow::ensure!(
                    device.file_type().is_char_device(),
                    "/dev/kvm is not a character device"
                );
                anyhow::ensure!(
                    device.gid() != 0,
                    "KVM needs a dedicated nonroot device group; refusing a supplementary gid 0 grant"
                );
                format!("SupplementaryGroups={}\n", device.gid())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        steps.push(Step::Install { path: kvm_path, contents: format!("# Written by kronik serve --init\n[Service]\nDeviceAllow=/dev/kvm rw\nBindPaths=-/dev/kvm\n{supplementary}"), mode: 0o644 });
    } else if managed_kvm {
        steps.push(Step::Remove(kvm_path));
    }
    if !rootless && host.pin_unit().exists() {
        steps.push(Step::Remove(host.pin_unit()));
    }
    Ok((config, steps))
}

pub fn run(
    args: &InitArgs,
    config_path: Option<&Path>,
    selected_key: Option<&Path>,
    json: bool,
) -> std::process::ExitCode {
    match InitHost::production(selected_key)
        .and_then(|host| execute_on(args, config_path.unwrap_or(Path::new(DEFAULT_PATH)), &host))
    {
        Ok(out) => {
            if json {
                match serde_json::to_string(&out) {
                    Ok(body) => println!("{body}"),
                    Err(error) => {
                        return crate::cli::report_error(
                            true,
                            &ApiError::new(
                                ErrorCode::Internal,
                                format!("encoding init result failed: {error}"),
                            ),
                        );
                    }
                }
            } else {
                if out.dry_run {
                    println!("kronik serve --init would do this (dry run, nothing changed):");
                }
                for step in out.steps {
                    println!("  {:<7} {}", step.action, step.what);
                }
                if !out.dry_run {
                    println!(
                        "Kronik runs as kronik.service. Next:\n  kronik doctor\n  journalctl -u kronik -f"
                    );
                    print_warnings(&out.warnings);
                    if !args.domain.is_empty() {
                        println!(
                            "  point {} at this host: the gateway gets its certificate when it starts",
                            args.domain.join(", ")
                        );
                    }
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            let api = error.downcast::<ApiError>().unwrap_or_else(|error| {
                match error.downcast::<kronik_privacy::key_source::KeySourceError>() {
                    Ok(error) => error.api_error(),
                    Err(error) => ApiError::new(ErrorCode::RootlessUnavailable, format!("{error:#}"))
                        .with_hint("Fix the cause and rerun the same `kronik serve --init` command: every step checks before it acts. `--dry-run --json` shows the plan."),
                }
            });
            crate::cli::report_error(json, &api)
        }
    }
}

/// What `serve --init` says at the end about the warnings of `kronik doctor`:
/// the install succeeded and the service answers, but a warning means that
/// something is not proven, and the first foreign actor is the real proof.
fn print_warnings(warnings: &[DoctorWarning]) {
    if warnings.is_empty() {
        return;
    }
    println!("`kronik doctor` warns about:");
    for warning in warnings {
        println!("  {:<8} {}", warning.check, warning.message);
        if let Some(hint) = &warning.hint {
            println!("  {:<8} hint: {hint}", "");
        }
    }
    println!(
        "A warning is not a failure, and the install succeeded; but nothing here proves that\nsandboxes work. The first foreign actor you add, in gVisor or in a microVM, is the real proof."
    );
}

/// The refusal that names both ways forward: keep the root installation, or
/// re-initialize with the data shipped and restored.
const ROOT_INSTALLATION: &str =
    "an existing root installation is not converted to the nonroot service in place";
const NONROOT_INSTALLATION: &str =
    "an existing nonroot installation is not converted to the root service in place";

/// What `--init` asks of a data directory that exists, before it changes
/// anything.
///
/// The root service behaves as v0.4.0 did: a link to the directory, a mounted
/// volume say, is followed (`create_dir_all` and the permission change did),
/// and whoever owns a directory that holds a root installation is not asked
/// about. The one refusal is the series' own: a directory that belongs to the
/// nonroot service's user is another installation, empty or not, and is not
/// converted in place (ADR 0063): the root service would write into it as
/// root, by path, in a tree that user controls. The nonroot service never follows a link into the tree it
/// hands over, and wants the directory to be root's or the service user's.
fn check_existing_data_directory(
    data: &Path,
    mode: Mode,
    service: &dyn Fn() -> anyhow::Result<Option<u32>>,
) -> anyhow::Result<()> {
    let found = match mode {
        Mode::Root => std::fs::metadata(data),
        Mode::Rootless => std::fs::symlink_metadata(data),
    };
    let metadata = match found {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if mode == Mode::Rootless && metadata.file_type().is_symlink() {
        bail!("{} is a symbolic link: {PATH_RULE}", data.display());
    }
    anyhow::ensure!(metadata.is_dir(), "{} is not a directory", data.display());
    let owner = metadata.uid();
    if mode == Mode::Root && owner == 0 {
        // v0.4.0's own installation: nothing to ask, nothing to read.
        return Ok(());
    }
    admit_data_directory(
        mode,
        owner,
        data_directory_is_unused(data, mode)?,
        service()?,
    )
}

/// Whether `--init` of `mode` may use a data directory that is `empty` or
/// owned by `owner`, given the nonroot service user (`service`).
fn admit_data_directory(
    mode: Mode,
    owner: u32,
    empty: bool,
    service: Option<u32>,
) -> anyhow::Result<()> {
    // A directory that belongs to the nonroot service's user is its
    // installation whether or not it holds anything yet: the root service
    // would write into it as root, by path, in a tree that user controls.
    if mode == Mode::Root && owner != 0 && service == Some(owner) {
        return Err(refused_conversion(NONROOT_INSTALLATION));
    }
    // A directory without content is not an installation: a first run that
    // stopped early leaves one, and the next run adopts it.
    if empty {
        return Ok(());
    }
    let reversal = match mode {
        Mode::Rootless if owner == 0 => Some(ROOT_INSTALLATION),
        Mode::Root if Some(owner) == service && owner != 0 => Some(NONROOT_INSTALLATION),
        Mode::Rootless if Some(owner) == service => None,
        // v0.4.0 asked nothing of the owner of a root installation's
        // directory: an operator may own it, and a repair run must work.
        Mode::Root => None,
        Mode::Rootless => bail!("data directory belongs to an unexpected user {owner}"),
    };
    match reversal {
        None => Ok(()),
        Some(reason) => Err(refused_conversion(reason)),
    }
}

/// The refusal of an installation of the other kind (ADR 0063).
fn refused_conversion(reason: &str) -> anyhow::Error {
    ApiError::new(ErrorCode::RootlessUnavailable, format!("{reason}: the data's numeric owners would change under a running history"))
        .with_hint("Keep the installation (`kronik serve --init --root` reruns a root one, `kronik serve --init --rootless` a nonroot one), or re-initialize: ship the data (or take a snapshot), run `kronik serve --init --root` or `--init --rootless` against an empty data directory, then `kronik restore` into it. See the operations guide.")
        .into()
}

/// Who is who when `--init --rootless` works on the data directory.
#[derive(Clone, Copy)]
struct DataOwners {
    /// The user the installer runs as (root).
    root: u32,
    /// The service user's uid and gid.
    service: (u32, u32),
    /// Which directories the path to the data directory may pass through.
    ancestors: Ancestors,
}

impl DataOwners {
    fn production() -> anyhow::Result<DataOwners> {
        let root = rustix::process::geteuid().as_raw();
        Ok(DataOwners {
            root,
            service: user_ids()?.context("kronik user missing")?,
            ancestors: Ancestors::ControlledBy(root),
        })
    }
}

/// Why the installer refuses some paths to the nonroot service's data
/// directory: root changes the owner of what is below it, and a link or a
/// directory that others can write on the way to it could be redirected.
const PATH_RULE: &str = "with --rootless no component of the path may be a symbolic link, and every directory above it must be owned by root and closed to others; use a bind mount instead of a link, or set server.data_dir to the real path";

/// What the installer finds in the nonroot service's data directory.
#[derive(Debug, PartialEq, Eq)]
enum DataDirectory {
    /// Root's own: new, or left by a first run that stopped before the hand-
    /// over. Root writes the key material into it while nobody else can
    /// enter it, then hands it over (see [`hand_over_data_directory`]).
    Fresh,
    /// Already the service user's, from an earlier run. Root reads nothing in
    /// it and changes nothing in it: it belongs to the user that a
    /// compromised service runs as.
    Owned,
}

/// Whether the directory holds nothing but, at most, the `keys` directory that
/// a first run leaves: an installation that has not started yet.
fn data_directory_is_unused(path: &Path, mode: Mode) -> anyhow::Result<bool> {
    let entries = Dir::open(path)?.entries()?;
    Ok(match mode {
        Mode::Root => entries.is_empty(),
        Mode::Rootless => entries
            .iter()
            .all(|(name, kind)| name == "keys" && *kind == Kind::Dir),
    })
}

/// Makes the data directory ready for the nonroot service and says what it
/// found. The directory is reached from `/` without following a symbolic link
/// and through directories only root can write (the path of a root-side
/// `chown` must not be one the service user can redirect). A new directory,
/// or a root-owned one that holds nothing but `keys`, stays root's and private
/// (mode `mode`), gets its `keys` directory, and is handed over only after the
/// key step has written into it. One that belongs to the service user is left
/// alone.
fn prepare_data_directory(
    path: &Path,
    mode: u32,
    who: DataOwners,
) -> anyhow::Result<DataDirectory> {
    anyhow::ensure!(
        path.is_absolute(),
        "the data directory {} must be an absolute path: the service does not run in this directory",
        path.display()
    );
    let data = Dir::open_absolute(path, who.ancestors, Some(mode)).with_context(|| {
        format!(
            "preparing the data directory {}: {PATH_RULE}",
            path.display()
        )
    })?;
    let meta = data.stat()?;
    if meta.uid == who.service.0 {
        return Ok(DataDirectory::Owned);
    }
    anyhow::ensure!(
        meta.uid == who.root,
        "{} belongs to uid {}, neither the installer nor the service user",
        path.display(),
        meta.uid
    );
    let entries = data.entries()?;
    anyhow::ensure!(
        entries
            .iter()
            .all(|(name, kind)| name == "keys" && *kind == Kind::Dir),
        "{} is not empty: it is neither new nor left by a first run that stopped early",
        path.display()
    );
    // A directory from an unfinished first run may have another mode; only a
    // private one can be handed over.
    data.set_mode(mode)?;
    if entries.is_empty() {
        data.create_dir(std::ffi::OsStr::new("keys"), 0o700)?;
    }
    Ok(DataDirectory::Fresh)
}

/// Hands a [`DataDirectory::Fresh`] data directory to the service user, the
/// files in it before the directories that hold them and the data directory
/// itself last, all by descriptor and without following links. Nothing is
/// handed over if anything in it is not a plain directory or a regular file
/// with one link. After this root does not touch the tree again.
fn hand_over_data_directory(path: &Path, who: DataOwners) -> anyhow::Result<()> {
    let data = Dir::open_absolute(path, who.ancestors, None).with_context(|| {
        format!(
            "handing over the data directory {}: {PATH_RULE}",
            path.display()
        )
    })?;
    data.hand_over_tree(who.service.0, who.service.1)
        .with_context(|| format!("handing over the data directory {}", path.display()))
}

/// The key step of a rerun, when the data directory already belongs to the
/// service user: check that the key source still yields the key, reading
/// nothing in the service user's tree but the KMS envelope, by descriptor.
/// The stores are not read: the service checks them itself when it starts, and
/// a root process that opened a database the service user wrote would parse
/// attacker-chosen bytes with root's authority.
fn check_key_of_owned_directory(
    keys: &kronik_privacy::key_source::Keys,
    data: &Path,
) -> anyhow::Result<()> {
    kronik_privacy::key_source::protect_process()
        .map_err(|e| anyhow::anyhow!("{}", e.api_error()))?;
    if keys.source.is_kms() {
        let envelope = kronik_privacy::key_source::read_envelope_in(
            data,
            &keys.envelope_path(data).map_err(anyhow::Error::from)?,
        )
        .context("reading the wrapped master key")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime
            .block_on(async {
                let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
                kronik_privacy::key_source::unwrap_envelope(&env, keys, &envelope).await
            })
            .map(|_| ())
            .map_err(anyhow::Error::from)
    } else {
        // The key file is outside the data directory (see
        // `reject_key_in_data_directory`). The directory passed as the second
        // argument is only looked at, for stores, to word the error when the
        // file is missing: it is the key's own, not the service's tree.
        let key = keys.key_path(data);
        let beside = key.parent().unwrap_or(Path::new("/")).to_owned();
        kronik_privacy::MasterKey::open(&key, &beside, None)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// In the nonroot installation systemd hands the master key file to the
/// service as a credential, and the data directory belongs to the service
/// user: a key file inside it would be a path the service user controls
/// (a link planted there would be read with the privilege of the service
/// manager), and would not be root-only. The key stays outside.
fn reject_key_in_data_directory(config: &Config) -> anyhow::Result<()> {
    let data = &config.server.data_dir;
    let key = config.keys.key_path(data);
    let absolute = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_owned());
    // The path as the file system sees it, whether or not the file exists yet.
    let resolved = |p: &Path| {
        std::fs::canonicalize(p)
            .ok()
            .or_else(|| {
                let parent = std::fs::canonicalize(p.parent()?).ok()?;
                Some(parent.join(p.file_name()?))
            })
            .unwrap_or_else(|| absolute(p))
    };
    if absolute(&key).starts_with(absolute(data)) || resolved(&key).starts_with(resolved(data)) {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            format!(
                "the master key file {} is inside the data directory {}, which the nonroot service owns",
                key.display(),
                data.display()
            ),
        )
        .with_hint("Keep the key outside the data directory, for example `[keys] master_key_file = \"/etc/kronik/master.key\"` (root-only, mode 0600): systemd hands the file to the service as a credential, so the path must be one that only root controls. Or install the root service with `--root`.")
        .into());
    }
    Ok(())
}

/// The key file is not to be reached through a place that others can change
/// either, not only through the data directory. The service manager reads it as
/// root, before it drops to the service user, so no directory on the way to it
/// may be one that anyone but root (or the installer) can change: a link or a
/// swapped directory there would be read with root's authority. Every directory
/// from `/` to the one that holds the key must belong to root with no write
/// access for the group or others, and none may be a symbolic link. A sticky
/// directory such as `/tmp` is acceptable on the way, where only the owner of
/// an entry can swap it, but not as the last one: the part of the path that
/// does not exist yet is made by this installer, as root, in the nearest
/// directory that does, and the key goes there, so that directory must be
/// closed to the group and others whether or not it is sticky.
fn reject_key_in_writable_place(config: &Config) -> anyhow::Result<()> {
    use kronik_privacy::owned_tree::Dir;
    let key = std::path::absolute(config.keys.key_path(&config.server.data_dir))
        .context("resolving the master key path")?;
    let mut nearest = key.parent().unwrap_or(Path::new("/")).to_owned();
    while std::fs::symlink_metadata(&nearest).is_err() {
        match nearest.parent() {
            Some(parent) => nearest = parent.to_owned(),
            None => break,
        }
    }
    let installer = rustix::process::geteuid().as_raw();
    let refused = |why: String| {
        anyhow::Error::from(
            ApiError::new(
                ErrorCode::BadRequest,
                format!(
                    "the master key file {} is reached through a place that is not root's alone: {why}",
                    key.display()
                ),
            )
            .with_hint("systemd reads the key file as root before it drops to the service user, so every directory on the way to it must belong to root with no write access for anyone else, and none may be a symbolic link. Keep the key under a directory such as /etc/kronik, or install the root service with `--root`."),
        )
    };
    let directory =
        Dir::open_controlled(&nearest, installer, None).map_err(|e| refused(e.to_string()))?;
    // The walk judges the directories above the last one, and a sticky one is fine
    // among them (the next component is checked in its own turn, and only the owner
    // of an entry can swap it). The last is the directory in which the installer, as
    // root, creates the missing part of the path and then the key: no one else may be
    // able to write in it, sticky or not (in /tmp another user can make the entry first
    // and swap it for a link after).
    let meta = directory.stat().map_err(|e| refused(e.to_string()))?;
    if (meta.uid != 0 && meta.uid != installer) || meta.mode & 0o022 != 0 {
        return Err(refused(format!(
            "{} is owned by uid {} with mode {:04o}",
            nearest.display(),
            meta.uid,
            meta.mode & 0o7777
        )));
    }
    Ok(())
}

/// What a step reports once it has run, as in v0.4.0: `created`, `updated`,
/// `deleted`, `checked`, or `kept` when nothing was needed.
fn done(needed: Option<&str>) -> &'static str {
    match needed {
        None => "kept",
        Some("create") => "created",
        Some("update") => "updated",
        Some("delete") => "deleted",
        Some("check") => "checked",
        Some(_) => "ran",
    }
}

pub(crate) fn execute_on(
    args: &InitArgs,
    config_path: &Path,
    host: &InitHost,
) -> anyhow::Result<InitOutput> {
    if !args.dry_run && !kronik_foreign::sys::is_root() {
        return Err(ApiError::new(
            ErrorCode::Unavailable,
            "serve --init changes /etc and systemd, so it must run as root",
        )
        .with_hint("sudo kronik serve --init (see the plan with --dry-run)")
        .into());
    }
    let (config, steps) = plan(args, config_path, host)?;
    let mode = args.mode();
    let data = &config.server.data_dir;
    check_existing_data_directory(data, mode, &|| Ok(user_ids()?.map(|ids| ids.0)))?;
    let mut out = InitOutput {
        dry_run: args.dry_run,
        mode,
        steps: Vec::new(),
        warnings: Vec::new(),
    };
    // The nonroot installation's data directory, as the Dir step found it.
    let mut found = None;
    for step in steps {
        let needed = step.needed()?;
        out.steps.push(StepOutput {
            action: if args.dry_run {
                needed.unwrap_or("keep")
            } else {
                done(needed)
            }
            .into(),
            what: step.describe(),
        });
        if args.dry_run {
            continue;
        }
        match (&step, mode) {
            // The nonroot service's data directory is made and looked at by
            // descriptor (it is not created by `Step::apply`), the key step
            // writes into it while it is still root's, and it is handed over
            // afterwards, so that root never re-walks a tree the service user
            // can modify.
            (
                Step::Dir {
                    path,
                    mode: dir_mode,
                },
                Mode::Rootless,
            ) => {
                found = Some(prepare_data_directory(
                    path,
                    *dir_mode,
                    DataOwners::production()?,
                )?);
            }
            (Step::MasterKey { keys, data }, Mode::Rootless) => match found {
                Some(DataDirectory::Owned) => {
                    check_key_of_owned_directory(keys, data)?;
                }
                Some(DataDirectory::Fresh) => {
                    // A key step that fails, half way or not, leaves the
                    // directory root's and private, with whatever it wrote:
                    // nothing is handed over, because a directory owned by the
                    // service user is only ever checked and never given a key.
                    // The error of the step is the operator's message, and the
                    // next run starts from "new or left by an early stop" again.
                    step.apply(None)?;
                    hand_over_data_directory(data, DataOwners::production()?)?;
                }
                None => anyhow::bail!("the data directory was not prepared before the key step"),
            },
            _ => {
                if needed.is_some() {
                    step.apply(None)?;
                }
            }
        }
    }
    if args.dry_run {
        out.steps.push(StepOutput { action: "run".into(), what: "systemctl daemon-reload; enable and start kronik.service; verify identity and health".into() });
        return Ok(out);
    }
    host.control(&["daemon-reload"])?;
    if host.fixture_etc.is_some() {
        host.control(&["enable", "--runtime", "--now", &host.unit_name])
    } else {
        host.control(&["enable", "--now", &host.unit_name])
    }?;
    out.warnings = verify(mode, host, config_path)?;
    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn owned_setup_refuses_an_unrelated_unit_without_mutation() {
        use super::*;
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("units")).unwrap();
        let name = "kronik-proof-admission.service";
        let unit = root.path().join("units").join(name);
        std::fs::write(&unit, b"retained unrelated unit").unwrap();
        let before = unit.metadata().unwrap();
        let exe = std::env::current_exe().unwrap();
        assert!(InitHost::owned_fixture(exe.clone(), root.path(), name.into(), exe).is_err());
        let host = InitHost::production(None).unwrap();
        assert!(host.stop(name).is_err());
        assert_eq!(std::fs::read(&unit).unwrap(), b"retained unrelated unit");
        assert_eq!(unit.metadata().unwrap().ino(), before.ino());
    }

    #[test]
    fn an_installation_of_the_other_kind_is_refused_with_both_ways_forward() {
        use super::*;
        const SERVICE: Option<u32> = Some(998);
        // Fresh and interrupted first runs are not installations: an empty
        // directory is adopted, whoever owns it, except that the root service
        // does not take over one that belongs to the nonroot service's user.
        for mode in [Mode::Root, Mode::Rootless] {
            for owner in [0, 1234] {
                admit_data_directory(mode, owner, true, SERVICE).unwrap();
            }
        }
        admit_data_directory(Mode::Rootless, 998, true, SERVICE).unwrap();
        let error = admit_data_directory(Mode::Root, 998, true, SERVICE).unwrap_err();
        let error = error.downcast::<ApiError>().unwrap();
        assert!(
            error.message.starts_with(NONROOT_INSTALLATION),
            "{}",
            error.message
        );
        // Reruns of the same kind are kept.
        admit_data_directory(Mode::Root, 0, false, SERVICE).unwrap();
        admit_data_directory(Mode::Rootless, 998, false, SERVICE).unwrap();
        // The other kind is refused, whichever way it points.
        for (mode, owner, reason) in [
            (Mode::Rootless, 0, ROOT_INSTALLATION),
            (Mode::Root, 998, NONROOT_INSTALLATION),
        ] {
            let error = admit_data_directory(mode, owner, false, SERVICE).unwrap_err();
            let error = error.downcast::<ApiError>().unwrap();
            assert_eq!(error.code, ErrorCode::RootlessUnavailable);
            assert!(error.message.starts_with(reason), "{}", error.message);
            let hint = error.hint.as_deref().unwrap_or_default();
            assert!(hint.contains("--init --root"), "{hint}");
            assert!(hint.contains("--init --rootless"), "{hint}");
            assert!(hint.contains("kronik restore"), "{hint}");
        }
        // For the nonroot service an owner that is neither root nor the
        // service is not guessed at; the root service never asked (v0.4.0).
        let error = admit_data_directory(Mode::Rootless, 1234, false, SERVICE).unwrap_err();
        assert!(error.to_string().contains("unexpected user 1234"));
        admit_data_directory(Mode::Root, 1234, false, SERVICE).unwrap();
        admit_data_directory(Mode::Root, 1234, false, None).unwrap();
        assert!(admit_data_directory(Mode::Rootless, 998, false, None).is_err());
    }

    #[test]
    fn rerunning_key_init_reads_an_owned_source_but_never_creates_one() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let keys = kronik_privacy::key_source::Keys::default();
        let path = keys.key_path(dir.path());
        kronik_privacy::MasterKey::open(&path, &dir.path().join("keys"), Some([7; 32])).unwrap();
        let before = std::fs::read(&path).unwrap();
        let _owner = kronik_privacy::key_source::lock_data(dir.path()).unwrap();
        let step = Step::MasterKey {
            keys: Box::new(keys),
            data: dir.path().to_owned(),
        };
        step.apply(None).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).unwrap();
        let error = step.apply(None).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<kronik_privacy::key_source::KeySourceError>(),
            Some(kronik_privacy::key_source::KeySourceError::DataInUse)
        ));
        assert!(!path.exists());
        step.apply(Some(&_owner)).unwrap();
        assert!(
            path.is_file(),
            "an existing same-description data lock permits first creation"
        );
    }

    /// `git show v0.4.0:deploy/systemd/kronik.service | sha256sum`
    const V040_UNIT_SHA256: &str =
        "4e846315f2850cee90a68e10ebd0a3bbf96f5d8158f2bfa02074261284af8c6c";

    fn host(units: &std::path::Path, selected_key: Option<std::path::PathBuf>) -> super::InitHost {
        super::InitHost {
            exe: std::env::current_exe().unwrap(),
            unit_name: "kronik.service".into(),
            pin_unit_name: "kronik-userns.service".into(),
            unit_dir: units.to_owned(),
            fixture_etc: None,
            fixture_helper: None,
            selected_key,
        }
    }

    fn root_args() -> super::InitArgs {
        super::InitArgs {
            init: true,
            domain: Vec::new(),
            acme_email: None,
            root: true,
            rootless: false,
            dry_run: true,
        }
    }

    /// The root service's unit is the one of v0.4.0 and nothing else: no
    /// delegated cgroup (it would move where an existing installation's
    /// sandboxes get theirs), no key credential, no placeholder but the
    /// binary's path.
    #[test]
    fn the_root_template_is_the_v040_unit_byte_for_byte() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(super::ROOT_UNIT.as_bytes());
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, V040_UNIT_SHA256);
        for absent in ["Delegate", "LoadCredential", "@CONFIG@", "@KEY_"] {
            assert!(!super::ROOT_UNIT.contains(absent), "{absent}");
        }
        assert_eq!(super::ROOT_UNIT.matches("@KRONIK@").count(), 2);
        assert_eq!(
            super::ROOT_UNIT.matches('@').count(),
            4,
            "no placeholder but the binary's path"
        );
    }

    #[test]
    fn init_root_changes_nothing_on_a_host_that_v040_set_up() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let units = dir.path().join("units");
        std::fs::create_dir(&units).unwrap();
        let config = dir.path().join("kronik.toml");
        std::fs::write(
            &config,
            format!("[server]\ndata_dir = {:?}\n", dir.path().join("data")),
        )
        .unwrap();
        let host = host(&units, None);
        // What v0.4.0's `serve --init` wrote: its template with the binary's path.
        let written = ROOT_UNIT.replace("@KRONIK@", &host.exe.to_string_lossy());
        std::fs::write(host.unit(), &written).unwrap();
        let (_, steps) = plan(&root_args(), &config, &host).unwrap();
        let unit = steps
            .iter()
            .find(|step| matches!(step, Step::Install { path, .. } if *path == host.unit()))
            .expect("the plan installs the unit");
        assert_eq!(unit.needed().unwrap(), None, "the unit is kept as it is");
        // And it is a comparison, not a constant: any other byte is an update.
        std::fs::write(
            host.unit(),
            written.replace("Restart=on-failure", "Restart=always"),
        )
        .unwrap();
        let (_, steps) = plan(&root_args(), &config, &host).unwrap();
        let unit = steps
            .iter()
            .find(|step| matches!(step, Step::Install { path, .. } if *path == host.unit()))
            .unwrap();
        assert_eq!(unit.needed().unwrap(), Some("update"));
        // A rootless unit is never planned for the root service.
        assert!(
            !steps
                .iter()
                .any(|step| matches!(step, Step::Install { path, .. } if *path == host.pin_unit()))
        );
    }

    #[test]
    fn the_operations_guide_shows_the_microvm_drop_in_verbatim() {
        let guide = include_str!("../../../docs/guides/operations.md");
        assert!(
            guide.contains(kronik_foreign::microvm::ROOT_LEAF_DROPIN),
            "the guide must show the drop-in verbatim"
        );
        assert!(guide.contains(kronik_foreign::microvm::ROOT_LEAF_DROPIN_PATH));
        assert!(guide.contains("MicroVM actors on the root service"));
    }

    #[test]
    fn a_key_file_the_root_unit_could_not_pass_on_is_refused() {
        use super::*;
        let dir = tempfile::tempdir().unwrap();
        let units = dir.path().join("units");
        std::fs::create_dir(&units).unwrap();
        let config = dir.path().join("kronik.toml");
        let configured = dir.path().join("etc-master.key");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n[keys]\nmaster_key_file = {:?}\n",
                dir.path().join("data"),
                configured
            ),
        )
        .unwrap();
        // The file the configuration already names: fine.
        plan(
            &root_args(),
            &config,
            &host(&units, Some(configured.clone())),
        )
        .unwrap();
        plan(&root_args(), &config, &host(&units, None)).unwrap();
        // Another one: the key step and the daemon would use two keys.
        let other = dir.path().join("other.key");
        let error = plan(&root_args(), &config, &host(&units, Some(other)))
            .err()
            .unwrap();
        let api = error.downcast::<ApiError>().unwrap();
        assert_eq!(api.code, ErrorCode::BadRequest);
        assert!(
            api.message.contains("would not reach the root service"),
            "{}",
            api.message
        );
        let hint = api.hint.unwrap_or_default();
        assert!(
            hint.contains("[keys] master_key_file") && hint.contains("--rootless"),
            "{hint}"
        );
    }

    #[test]
    fn steps_report_what_was_done_in_the_past_tense() {
        use super::done;
        let said: Vec<_> = [
            None,
            Some("create"),
            Some("update"),
            Some("delete"),
            Some("check"),
            Some("run"),
        ]
        .into_iter()
        .map(done)
        .collect();
        assert_eq!(
            said,
            ["kept", "created", "updated", "deleted", "checked", "ran"]
        );
    }

    /// Which service `--init` installs by default is `DEFAULT_MODE` and
    /// nothing else; the flags override it either way. Until the nonroot
    /// service has been run on Ubuntu 24.04 the default is the root service
    /// of v0.4.0: flipping the constant also means editing the sentences that
    /// name the default (the operations, security, CLI and quickstart guides
    /// and ADRs 0062 and 0063) and the test of the default plan in ops.rs.
    #[test]
    fn the_default_service_is_one_switch_and_the_flags_override_it() {
        use super::*;
        let args = |root, rootless| InitArgs {
            init: true,
            domain: Vec::new(),
            acme_email: None,
            root,
            rootless,
            dry_run: true,
        };
        assert_eq!(args(false, false).mode(), DEFAULT_MODE);
        assert_eq!(DEFAULT_MODE, Mode::Root, "see the comment above");
        assert_eq!(args(true, false).mode(), Mode::Root);
        assert_eq!(args(false, true).mode(), Mode::Rootless);
    }

    #[test]
    fn the_written_configuration_parses_to_what_was_asked() {
        use super::*;
        let path = Path::new("kronik.toml");
        let acme = Config::parse(
            &config_file(&["app.example.com".into()], Some("ops@example.com")),
            path,
        )
        .unwrap();
        assert_eq!(acme.tls.mode, crate::config::TlsMode::Acme);
        assert_eq!(acme.tls.domains, ["app.example.com"]);
        assert_eq!(acme.tls.acme_email.as_deref(), Some("ops@example.com"));
        assert_eq!(acme.http_listen(), "0.0.0.0:443".parse().unwrap());
        assert_eq!(
            acme.keys.key_path(&acme.server.data_dir),
            PathBuf::from(MASTER_KEY)
        );
        let plain = Config::parse(&config_file(&[], None), path).unwrap();
        assert_eq!(plain.tls.mode, crate::config::TlsMode::Off);
        assert_eq!(plain.http_listen(), "0.0.0.0:80".parse().unwrap());
        // Apart from TLS and the listen address, the file is the brief's.
        let defaults = Config::default();
        assert_eq!(plain.gateway, defaults.gateway);
        assert_eq!(plain.retention, defaults.retention);
        assert_eq!(plain.promote, defaults.promote);
    }

    #[test]
    fn disabling_kvm_removes_only_our_managed_dropin() {
        use super::*;
        let tmp = tempfile::tempdir().unwrap();
        let mut host = InitHost::production(None).unwrap();
        host.unit_dir = tmp.path().join("units");
        let file = host.dropin("kvm.conf");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let config = tmp.path().join("kronik.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\ndata_dir = {:?}\n[foreign]\nmicrovm_dir = {:?}\n",
                tmp.path().join("data"),
                tmp.path().join("no-tools")
            ),
        )
        .unwrap();
        let args = InitArgs {
            init: true,
            domain: Vec::new(),
            acme_email: None,
            root: true,
            rootless: false,
            dry_run: true,
        };
        std::fs::write(&file, "# Written by another owner\n[Service]\n").unwrap();
        let (_, steps) = plan(&args, &config, &host).unwrap();
        assert!(
            !steps
                .iter()
                .any(|step| matches!(step, Step::Remove(path) if path == &file))
        );
        std::fs::write(
            &file,
            "# Written by `kronik serve --init` for [foreign] platform = \"kvm\"\n[Service]\n",
        )
        .unwrap();
        let (_, steps) = plan(&args, &config, &host).unwrap();
        let removal = steps
            .iter()
            .find(|step| matches!(step, Step::Remove(path) if path == &file))
            .unwrap();
        removal.apply(None).unwrap();
        assert!(!file.exists());
    }
}

/// The nonroot service's data directory, prepared and handed over by
/// descriptor: what root does in a tree the service user owns.
#[cfg(test)]
mod data_directory_tests {
    use super::*;
    use std::time::Duration;

    /// A test that needs a privilege this run does not have is skipped with a
    /// message, as the foreign tests are, unless `KRONIK_FOREIGN_TESTS=require`
    /// (CI, which runs it as root): then the skip is a failure, so that the
    /// test cannot be absent from every run without anyone noticing.
    fn require_or_skip(why: &str) {
        assert!(
            std::env::var("KRONIK_FOREIGN_TESTS").as_deref() != Ok("require"),
            "KRONIK_FOREIGN_TESTS=require, but this test cannot run: {why}"
        );
        eprintln!("skipped: {why}");
    }

    fn ids() -> (u32, u32) {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    /// The test's own user plays root, so a directory the test makes is
    /// "root's" and the service is another uid.
    fn root_is_me() -> DataOwners {
        let (uid, gid) = ids();
        DataOwners {
            root: uid,
            service: (uid.wrapping_add(1), gid.wrapping_add(1)),
            ancestors: Ancestors::Any,
        }
    }

    /// The test's own user plays the service, so a directory the test makes
    /// already belongs to it.
    fn service_is_me() -> DataOwners {
        let (uid, gid) = ids();
        DataOwners {
            root: uid.wrapping_add(1),
            service: (uid, gid),
            ancestors: Ancestors::Any,
        }
    }

    fn ctime(path: &Path) -> (i64, i64) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        (meta.ctime(), meta.ctime_nsec())
    }

    /// Change times tick coarsely; let the clock move before a comparison.
    fn tick() {
        std::thread::sleep(Duration::from_millis(40));
    }

    fn victim(base: &Path) -> PathBuf {
        let victim = base.join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("a.conf"), b"config").unwrap();
        victim
    }

    #[test]
    fn a_new_data_directory_is_private_has_keys_and_stays_roots() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("var/lib/kronik");
        let found = prepare_data_directory(&data, 0o700, root_is_me()).unwrap();
        assert_eq!(found, DataDirectory::Fresh);
        assert_eq!(std::fs::metadata(&data).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(data.join("keys")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(std::fs::metadata(&data).unwrap().uid(), ids().0);
        // Run again before the hand-over (a rerun of an unfinished first run).
        std::fs::write(data.join("keys/master.wrapped"), b"envelope").unwrap();
        assert_eq!(
            prepare_data_directory(&data, 0o700, root_is_me()).unwrap(),
            DataDirectory::Fresh
        );
        assert!(data_directory_is_unused(&data, Mode::Rootless).unwrap());
        assert!(!data_directory_is_unused(&data, Mode::Root).unwrap());
    }

    /// A directory that belongs to the nonroot service's user is its
    /// installation even when it is empty: the root service would write into
    /// it as root, by path, in a tree that user controls. Anything else is
    /// as in v0.4.0.
    #[test]
    fn the_root_service_does_not_take_over_an_empty_directory_of_the_service_user() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir(&data).unwrap();
        if rustix::process::geteuid().is_root() {
            std::os::unix::fs::chown(&data, Some(65_534), Some(65_534)).unwrap();
        }
        use std::os::unix::fs::MetadataExt as _;
        let owner = std::fs::metadata(&data).unwrap().uid();
        let service = move || Ok(Some(owner));
        let someone_else = move || Ok(Some(owner.wrapping_add(1)));
        let none = || Ok(None);
        let refused = |mode, who: &dyn Fn() -> anyhow::Result<Option<u32>>| {
            check_existing_data_directory(&data, mode, who)
        };
        // Empty and service-owned: refused for the root service, adopted by
        // the nonroot one.
        let error = refused(Mode::Root, &service).unwrap_err();
        let api = error.downcast::<ApiError>().unwrap();
        assert!(
            api.message.starts_with(NONROOT_INSTALLATION),
            "{}",
            api.message
        );
        refused(Mode::Rootless, &service).unwrap();
        // The same, with content.
        std::fs::create_dir(data.join("branches")).unwrap();
        assert!(refused(Mode::Root, &service).is_err());
        // Owned by somebody else than the service (an operator, as in v0.4.0)
        // or by no service user at all: accepted by the root service, empty or not.
        refused(Mode::Root, &someone_else).unwrap();
        refused(Mode::Root, &none).unwrap();
        std::fs::remove_dir(data.join("branches")).unwrap();
        refused(Mode::Root, &someone_else).unwrap();
        refused(Mode::Root, &none).unwrap();
        // And the service user is not looked up for a directory root owns.
        let base2 = tempfile::tempdir().unwrap();
        if rustix::process::geteuid().is_root() {
            let lookup = || -> anyhow::Result<Option<u32>> { panic!("looked up the service user") };
            check_existing_data_directory(base2.path(), Mode::Root, &lookup).unwrap();
        }
    }

    #[test]
    fn the_root_service_follows_a_link_to_its_data_directory_as_v040_did() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("volume");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(real.join("branches")).unwrap();
        std::fs::write(real.join("somefile"), b"installed").unwrap();
        let link = base.path().join("var-lib-kronik");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // A mounted volume behind a link is a root installation like another.
        check_existing_data_directory(&link, Mode::Root, &|| Ok(None)).unwrap();
        // The nonroot service says what to do instead.
        let error = check_existing_data_directory(&link, Mode::Rootless, &|| Ok(None)).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("symbolic link") && text.contains("bind mount"),
            "{text}"
        );
        // A link to nothing is not a directory in either mode, and a missing
        // directory is simply to be made.
        let dangling = base.path().join("dangling");
        std::os::unix::fs::symlink(base.path().join("nowhere"), &dangling).unwrap();
        check_existing_data_directory(&dangling, Mode::Root, &|| Ok(None)).unwrap();
        check_existing_data_directory(&base.path().join("absent"), Mode::Root, &|| Ok(None))
            .unwrap();
        check_existing_data_directory(&base.path().join("absent"), Mode::Rootless, &|| Ok(None))
            .unwrap();
        // A file is not a data directory.
        std::fs::write(base.path().join("file"), b"x").unwrap();
        assert!(
            check_existing_data_directory(&base.path().join("file"), Mode::Root, &|| Ok(None))
                .is_err()
        );
    }

    /// A repair run: `serve --init --root` over an existing root installation
    /// whose directory an operator owns proceeds, as in v0.4.0. Needs root to
    /// give a directory to another user.
    #[test]
    fn the_root_service_is_rerun_over_a_directory_another_user_owns() {
        let (uid, _) = ids();
        if uid != 0 {
            require_or_skip("changing the owner of a directory needs root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir_all(data.join("branches")).unwrap();
        std::os::unix::fs::chown(&data, Some(65_534), Some(65_534)).unwrap();
        check_existing_data_directory(&data, Mode::Root, &|| Ok(None)).unwrap();
        // The nonroot service wants root's or its own user's.
        let error = check_existing_data_directory(&data, Mode::Rootless, &|| Ok(None));
        assert!(error.is_err());
    }

    #[test]
    fn a_first_run_that_stopped_early_is_adopted_whatever_its_mode() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            prepare_data_directory(&data, 0o700, root_is_me()).unwrap(),
            DataDirectory::Fresh
        );
        assert_eq!(std::fs::metadata(&data).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_data_directory_with_anything_else_in_it_is_not_adopted() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir_all(data.join("branches")).unwrap();
        let error = prepare_data_directory(&data, 0o700, root_is_me()).unwrap_err();
        assert!(error.to_string().contains("not empty"), "{error:#}");
        assert!(!data_directory_is_unused(&data, Mode::Rootless).unwrap());
        // `keys` that is not a directory is something else too.
        let other = base.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("keys"), b"x").unwrap();
        assert!(prepare_data_directory(&other, 0o700, root_is_me()).is_err());
    }

    #[test]
    fn a_relative_data_directory_is_refused() {
        let error = prepare_data_directory(Path::new("data"), 0o700, root_is_me()).unwrap_err();
        assert!(error.to_string().contains("absolute"), "{error:#}");
    }

    #[test]
    fn a_symbolic_link_on_the_way_to_the_data_directory_is_not_followed() {
        let base = tempfile::tempdir().unwrap();
        let victim = victim(base.path());
        std::os::unix::fs::symlink(&victim, base.path().join("link")).unwrap();
        let before = ctime(&victim);
        tick();
        let error = prepare_data_directory(&base.path().join("link/data"), 0o700, root_is_me())
            .unwrap_err();
        assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
        assert!(!victim.join("data").exists());
        assert_eq!(ctime(&victim), before);
        // A data directory that is itself a link is refused too.
        std::os::unix::fs::symlink(&victim, base.path().join("data")).unwrap();
        assert!(prepare_data_directory(&base.path().join("data"), 0o700, root_is_me()).is_err());
        assert_eq!(ctime(&victim), before);
    }

    #[test]
    fn a_directory_that_others_can_write_on_the_way_is_refused_for_root() {
        let base = tempfile::tempdir().unwrap();
        let open = base.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let strict = DataOwners {
            ancestors: Ancestors::ControlledBy(ids().0),
            ..root_is_me()
        };
        let error = prepare_data_directory(&open.join("data"), 0o700, strict).unwrap_err();
        assert!(format!("{error:#}").contains("not controlled"), "{error:#}");
        assert!(!open.join("data").exists());
    }

    #[test]
    fn the_service_users_data_directory_is_left_alone() {
        let base = tempfile::tempdir().unwrap();
        let victim = victim(base.path());
        let data = base.path().join("data");
        std::fs::create_dir(&data).unwrap();
        // The service user's directory: whatever is in it, root changes and
        // reads nothing. Here `keys` is a planted link.
        std::os::unix::fs::symlink(&victim, data.join("keys")).unwrap();
        let (data_before, victim_before, file_before) =
            (ctime(&data), ctime(&victim), ctime(&victim.join("a.conf")));
        tick();
        assert_eq!(
            prepare_data_directory(&data, 0o700, service_is_me()).unwrap(),
            DataDirectory::Owned
        );
        assert_eq!(ctime(&data), data_before);
        assert_eq!(ctime(&victim), victim_before);
        assert_eq!(ctime(&victim.join("a.conf")), file_before);
        // The rerun's key check reads the key where it is, outside the tree.
        let key = base.path().join("master.key");
        std::fs::write(&key, "42".repeat(32)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let keys = kronik_privacy::key_source::Keys {
            master_key_file: Some(key),
            ..Default::default()
        };
        check_key_of_owned_directory(&keys, &data).unwrap();
        assert_eq!(ctime(&victim), victim_before);
        assert_eq!(ctime(&victim.join("a.conf")), file_before);
        // A missing key is an error, not a creation.
        let missing = kronik_privacy::key_source::Keys {
            master_key_file: Some(base.path().join("absent.key")),
            ..Default::default()
        };
        assert!(check_key_of_owned_directory(&missing, &data).is_err());
        assert!(!base.path().join("absent.key").exists());
    }

    #[test]
    fn a_missing_key_is_reported_without_looking_into_the_service_tree() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        // The service tree holds an encrypted store; the key outside is gone.
        std::fs::write(data.join("keys/secrets.db"), b"not a database").unwrap();
        let before = ctime(&data.join("keys/secrets.db"));
        tick();
        let missing = kronik_privacy::key_source::Keys {
            master_key_file: Some(base.path().join("etc/absent.key")),
            ..Default::default()
        };
        let error = check_key_of_owned_directory(&missing, &data).unwrap_err();
        // The message does not know about the store: it was not looked at.
        assert!(!error.to_string().contains("holds stores"), "{error}");
        assert_eq!(ctime(&data.join("keys/secrets.db")), before);
    }

    #[test]
    fn a_failed_key_step_leaves_the_directory_roots_and_the_next_run_fresh() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        let who = root_is_me();
        assert_eq!(
            prepare_data_directory(&data, 0o700, who).unwrap(),
            DataDirectory::Fresh
        );
        // The key step wrote part of its output and stopped. Nothing hands the
        // tree over; the directory is still private and root's.
        std::fs::write(data.join("keys/.wrapped-half"), b"half").unwrap();
        let meta = std::fs::metadata(&data).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(meta.uid(), ids().0);
        // The next run sees the same: new or left by an early stop.
        assert_eq!(
            prepare_data_directory(&data, 0o700, who).unwrap(),
            DataDirectory::Fresh
        );
        assert!(data_directory_is_unused(&data, Mode::Rootless).unwrap());
    }

    #[test]
    fn a_link_in_the_path_of_the_data_directory_says_what_to_do() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, base.path().join("var-lib")).unwrap();
        let error =
            prepare_data_directory(&base.path().join("var-lib/kronik"), 0o700, root_is_me())
                .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("symbolic link"), "{text}");
        assert!(text.contains("bind mount"), "{text}");
        assert!(!real.join("kronik").exists());
    }

    #[test]
    fn a_link_planted_as_keys_stops_the_hand_over() {
        let base = tempfile::tempdir().unwrap();
        let victim = victim(base.path());
        let data = base.path().join("data");
        let who = root_is_me();
        assert_eq!(
            prepare_data_directory(&data, 0o700, who).unwrap(),
            DataDirectory::Fresh
        );
        // Between the key step and the hand-over nothing can swap `keys`: the
        // directory is private. If it were swapped anyway, the hand-over
        // refuses it and changes nothing.
        std::fs::rename(data.join("keys"), data.join("keys.old")).unwrap();
        std::os::unix::fs::symlink(&victim, data.join("keys")).unwrap();
        let before = (ctime(&victim), ctime(&victim.join("a.conf")), ctime(&data));
        tick();
        let error = hand_over_data_directory(&data, who).unwrap_err();
        assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
        assert_eq!(
            (ctime(&victim), ctime(&victim.join("a.conf")), ctime(&data)),
            before
        );
    }

    /// With the privilege to chown, the real thing: the key step's files, the
    /// `keys` directory and the data directory end up the service user's.
    #[test]
    fn the_real_hand_over_gives_the_service_user_everything_and_nothing_else() {
        let (uid, gid) = ids();
        if uid != 0 {
            require_or_skip("handing a tree to another user needs root");
            return;
        }
        let base = tempfile::tempdir().unwrap();
        let victim = victim(base.path());
        let data = base.path().join("data");
        let who = DataOwners {
            root: 0,
            service: (65_534, 65_534),
            ancestors: Ancestors::Any,
        };
        assert_eq!(
            prepare_data_directory(&data, 0o700, who).unwrap(),
            DataDirectory::Fresh
        );
        std::fs::write(data.join("keys/master.wrapped"), b"envelope").unwrap();
        let victim_before = (ctime(&victim), ctime(&victim.join("a.conf")));
        tick();
        hand_over_data_directory(&data, who).unwrap();
        for path in [
            data.clone(),
            data.join("keys"),
            data.join("keys/master.wrapped"),
        ] {
            let meta = std::fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (meta.uid(), meta.gid()),
                (65_534, 65_534),
                "{}",
                path.display()
            );
        }
        assert_eq!(std::fs::metadata(&victim).unwrap().uid(), uid);
        assert_eq!(std::fs::metadata(&victim).unwrap().gid(), gid);
        assert_eq!(
            (ctime(&victim), ctime(&victim.join("a.conf"))),
            victim_before
        );
        // And now it is the service user's: the next run leaves it alone.
        assert_eq!(
            prepare_data_directory(&data, 0o700, who).unwrap(),
            DataDirectory::Owned
        );
    }

    fn config(text: &str) -> Config {
        Config::parse(text, Path::new("kronik.toml")).unwrap()
    }

    #[test]
    fn a_master_key_file_in_the_data_directory_is_refused_for_the_nonroot_service() {
        let inside = |key: &str| {
            reject_key_in_data_directory(&config(&format!(
                "[server]\ndata_dir = \"/var/lib/kronik\"\n[keys]\nmaster_key_file = \"{key}\"\n"
            )))
        };
        for key in [
            "/var/lib/kronik/keys/master.key",
            "/var/lib/kronik/master.key",
            "/var/lib/kronik/../kronik/keys/master.key",
        ] {
            let error = inside(key).unwrap_err();
            let api = error.downcast::<ApiError>().unwrap();
            assert_eq!(api.code, ErrorCode::BadRequest);
            assert!(
                api.message.contains("inside the data directory"),
                "{}",
                api.message
            );
        }
        inside("/etc/kronik/master.key").unwrap();
        inside("/var/lib/kronik-keys/master.key").unwrap();
        // Without a configured file the key is looked for under the data
        // directory: refused too.
        assert!(
            reject_key_in_data_directory(&config("[server]\ndata_dir = \"/var/lib/kronik\"\n"))
                .is_err()
        );
    }

    #[test]
    fn a_master_key_under_a_directory_that_others_can_change_is_refused_for_the_nonroot_service() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = tempfile::tempdir().unwrap();
        let make = |name: &str, mode: u32| {
            let dir = base.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir
        };
        let check = |key: &Path| {
            reject_key_in_writable_place(&config(&format!(
                "[server]\ndata_dir = \"/var/lib/kronik\"\n[keys]\nmaster_key_file = {key:?}\n"
            )))
        };
        // The base directory is the installer's own (or root's) and closed.
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let closed = make("etc", 0o755);
        check(&closed.join("master.key")).unwrap();
        // The part of the path that does not exist yet is made by the installer.
        check(&closed.join("kronik/new/master.key")).unwrap();
        // Writable by the group or others: refused, with the directory named.
        for (name, mode) in [("shared", 0o777), ("group", 0o775), ("other", 0o757)] {
            let dir = make(name, mode);
            for key in [dir.join("master.key"), dir.join("kronik/master.key")] {
                let error = check(&key).unwrap_err();
                let api = error.downcast::<ApiError>().unwrap();
                assert_eq!(api.code, ErrorCode::BadRequest);
                assert!(api.message.contains("not root's alone"), "{}", api.message);
                assert!(api.message.contains(name), "{}", api.message);
                assert!(
                    api.hint
                        .as_deref()
                        .is_some_and(|h| h.contains("/etc/kronik")),
                    "{:?}",
                    api.hint
                );
            }
        }
        // A sticky directory is no better where the installer creates the key and the
        // missing directories: another user can make the entry first (/tmp, /var/tmp,
        // /dev/shm), so it is refused as the last directory ...
        let sticky = make("sticky", 0o1777);
        assert!(check(&sticky.join("master.key")).is_err());
        assert!(check(&sticky.join("kronik/master.key")).is_err());
        // ... and fine as an ancestor of a closed directory, as /tmp is on the way to /tmp/x.
        let below = sticky.join("closed");
        std::fs::create_dir(&below).unwrap();
        std::fs::set_permissions(&below, std::fs::Permissions::from_mode(0o755)).unwrap();
        check(&below.join("master.key")).unwrap();
        check(&below.join("new/master.key")).unwrap();
        // A directory of another user than root or the installer: refused (root only).
        if rustix::process::geteuid().is_root() {
            let theirs = make("theirs", 0o755);
            std::os::unix::fs::chown(&theirs, Some(65_534), Some(65_534)).unwrap();
            assert!(check(&theirs.join("master.key")).is_err());
        }
        // A closed directory below one that others can write is no better.
        let inner = base.path().join("shared/inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check(&inner.join("master.key")).is_err());
        // A symbolic link on the way is refused, even to a closed directory.
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&closed, &link).unwrap();
        assert!(check(&link.join("master.key")).is_err());
    }

    #[test]
    fn a_key_file_that_is_a_link_into_the_data_directory_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        std::fs::write(data.join("keys/master.key"), [0x42u8; 32]).unwrap();
        let outside = base.path().join("etc-kronik");
        std::os::unix::fs::symlink(data.join("keys/master.key"), &outside).unwrap();
        let text = format!(
            "[server]\ndata_dir = {:?}\n[keys]\nmaster_key_file = {:?}\n",
            data, outside
        );
        let error = reject_key_in_data_directory(&config(&text)).unwrap_err();
        assert!(
            error.to_string().contains("inside the data directory"),
            "{error:#}"
        );
    }
}
