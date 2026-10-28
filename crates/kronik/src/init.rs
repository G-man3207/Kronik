//! `kronik serve --init`: sets a host up to run Kronik under systemd (SPEC.md,
//! "The finished product", step 2): the configuration file, the data
//! directory, the master key, the `kronik` group (which may use the API
//! socket) and the systemd unit, which it enables and starts. Every step
//! checks what is there first, so running it again changes nothing that is
//! already right; `--dry-run` prints the plan and changes nothing (I12).

use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, bail};
use clap::Args;

use crate::config::{Config, DEFAULT_PATH};

/// The unit, with `@KRONIK@` standing for the binary's path.
const UNIT: &str = include_str!("../../../deploy/systemd/kronik.service");
const UNIT_PATH: &str = "/etc/systemd/system/kronik.service";
const MASTER_KEY: &str = "/etc/kronik/master.key";

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Set this host up and start Kronik under systemd: the configuration,
    /// the data directory, the master key, the `kronik` group and the
    /// systemd unit. Run as root; safe to run again.
    #[arg(long)]
    pub init: bool,
    /// With --init: the name to get a TLS certificate for with ACME
    /// (repeatable). Without it, the gateway serves plain HTTP on port 80.
    #[arg(long, requires = "init", requires = "acme_email", value_name = "NAME")]
    pub domain: Vec<String>,
    /// With --init and --domain: where the CA sends expiry notices.
    #[arg(long, requires = "domain", value_name = "EMAIL")]
    pub acme_email: Option<String>,
    /// With --init: print what would be done, and change nothing.
    #[arg(long, requires = "init")]
    pub dry_run: bool,
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
    MasterKey(PathBuf),
    Group,
    Run(&'static [&'static str]),
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
            Step::MasterKey(path) => format!("{} (mode 0600, 32 random bytes)", path.display()),
            Step::Group => "group kronik (groupadd --system kronik)".into(),
            Step::Run(argv) => argv.join(" "),
        }
    }

    /// `None` when the step has nothing to do, else the verb of the plan.
    fn needed(&self) -> anyhow::Result<Option<&'static str>> {
        Ok(match self {
            Step::Create { path, .. } | Step::MasterKey(path) => {
                (!path.exists()).then_some("create")
            }
            Step::Dir { path, .. } => (!path.is_dir()).then_some("create"),
            Step::Install { path, contents, .. } => match std::fs::read_to_string(path) {
                Ok(current) if current == *contents => None,
                Ok(_) => Some("update"),
                Err(_) => Some("create"),
            },
            Step::Group => (!group_exists()?).then_some("create"),
            Step::Run(_) => Some("run"),
        })
    }

    fn apply(&self) -> anyhow::Result<()> {
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
            } => {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                std::fs::write(path, contents)
                    .with_context(|| format!("writing {}", path.display()))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                    .with_context(|| format!("setting the mode of {}", path.display()))
            }
            Step::Dir { path, mode } => {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("creating {}", path.display()))?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))
                    .with_context(|| format!("setting the mode of {}", path.display()))
            }
            Step::MasterKey(path) => {
                let mut fresh = [0u8; 32];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| f.read_exact(&mut fresh))
                    .context("reading /dev/urandom")?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                kronik_privacy::MasterKey::load_or_create(path, fresh)
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("{e}"))
            }
            Step::Group => run(&["groupadd", "--system", "kronik"]),
            Step::Run(argv) => run(argv),
        }
    }
}

fn run(argv: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(argv[0])
        .args(&argv[1..])
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

[promote]
max_gap = "2s"
catch_up_timeout = "5m"

[foreign]
runsc_path = "/usr/local/bin/runsc"
platform = "auto"                     # auto, systrap or kvm
run_dir = "/run/kronik"               # runsc state, namespaces, bridge sockets
layout_dirs = []                      # oci-layout: images an operate token may add
pull_timeout = "10m"
"#
    )
}

/// The plan for this host: what `--init` checks and, where needed, does.
fn plan(args: &InitArgs, config_path: &Path) -> anyhow::Result<Vec<Step>> {
    let exe = std::env::current_exe().context("finding the kronik binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    // An existing file is kept, and decides where the rest goes.
    let config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        let text = config_file(&args.domain, args.acme_email.as_deref());
        let config = Config::parse(&text, config_path)?;
        let mut steps = vec![Step::Create {
            path: config_path.to_owned(),
            contents: text,
            mode: 0o644,
        }];
        steps.extend(rest(&config, &exe));
        return Ok(steps);
    };
    Ok(rest(&config, &exe).collect())
}

fn rest(config: &Config, exe: &Path) -> impl Iterator<Item = Step> {
    let unit = UNIT.replace("@KRONIK@", &exe.to_string_lossy());
    [
        Step::Dir {
            path: config.server.data_dir.clone(),
            mode: 0o700,
        },
        Step::MasterKey(config.master_key_file()),
        Step::Group,
        Step::Install {
            path: UNIT_PATH.into(),
            contents: unit,
            mode: 0o644,
        },
        Step::Run(&["systemctl", "daemon-reload"]),
        Step::Run(&["systemctl", "enable", "--now", "kronik.service"]),
    ]
    .into_iter()
}

pub fn run_init(args: &InitArgs, config_path: Option<&Path>) -> anyhow::Result<()> {
    let config_path = config_path.unwrap_or(Path::new(DEFAULT_PATH));
    let steps = plan(args, config_path)?;
    if args.dry_run {
        println!("kronik serve --init would do this (dry run, nothing changed):");
    } else if std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
        != 0
    {
        bail!(
            "serve --init changes /etc and systemd, so it must run as root: \
             sudo kronik serve --init (see the plan with --dry-run)"
        );
    }
    for step in &steps {
        let needed = step.needed()?;
        if args.dry_run {
            println!("  {:<7} {}", needed.unwrap_or("keep"), step.describe());
            continue;
        }
        match needed {
            None => println!("  {:<7} {}", "kept", step.describe()),
            Some(verb) => {
                step.apply()?;
                let done = match verb {
                    "create" => "created",
                    "update" => "updated",
                    _ => "ran",
                };
                println!("  {done:<7} {}", step.describe());
            }
        }
    }
    if !args.dry_run {
        println!("Kronik runs as kronik.service. Next:");
        println!("  kronik doctor");
        println!("  journalctl -u kronik -f");
        if !args.domain.is_empty() {
            println!(
                "  point {} at this host: the gateway gets its certificate when it starts",
                args.domain.join(", ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_written_configuration_parses_to_what_was_asked() {
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
        assert_eq!(acme.master_key_file(), PathBuf::from(MASTER_KEY));
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
    fn the_unit_names_the_binary_and_the_configuration() {
        let unit = UNIT.replace("@KRONIK@", "/usr/local/bin/kronik");
        assert!(
            unit.contains("ExecStart=/usr/local/bin/kronik serve --config /etc/kronik/kronik.toml")
        );
        assert!(unit.contains(
            "ExecStopPost=-/usr/local/bin/kronik foreign cleanup --config /etc/kronik/kronik.toml"
        ));
        assert!(unit.contains("Group=kronik"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(!unit.contains("MemoryDenyWriteExecute=true"));
        // ADR 0027: an explicit User= costs runsc CAP_SETUID under the
        // seccomp settings. RestrictSUIDSGID stays in v0.1, which never runs
        // `runsc restore` (the one runsc step it breaks).
        let set = |key: &str| unit.lines().any(|l| l.starts_with(key));
        assert!(!set("User="));
        assert!(set("RestrictSUIDSGID=true"));
        assert!(set("NoNewPrivileges=true"));
    }
}
