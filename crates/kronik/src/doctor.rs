//! `kronik doctor`: what this host can run (the build brief, "The finished product",
//! step 1; ADR 0003 for gVisor). Needs no daemon: it reads the configuration
//! and looks at the host. Each check passes, warns or fails. A failure has a
//! catalog code and a hint (I12); a pass or a warning may omit a hint.
//! Foreign actors are optional (I10), so the checks of what only they need
//! (`runsc`, `kvm`, `cgroup`, `runc`, `netns`, `run_dir`, `sandbox`) warn
//! unless the configuration asks for what is missing: with `[foreign]
//! platform = "kvm"`, `kvm` and `sandbox` fail. A new network namespace with
//! more than `lo` fails too: foreign actors would run without their network
//! isolation. Where a microVM tool bundle is installed and the root service runs
//! (the nonroot one has its own delegation check), `microvm` says whether the
//! daemon has the delegated cgroup leaf a microVM needs, and gives the drop-in
//! that adds it when it has not.
//
// A client command, not daemon code: it compares certificate expiry with the
// wall clock directly (ADR 0004 §3 concerns the daemon).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime};

use clap::Args;
use schemars::JsonSchema;
use serde::Serialize;

use kronik_core::error::ErrorCode;

use crate::config::{Config, Platform, TlsMode};

/// The gVisor release Kronik is tested with (ADR 0003).
const TESTED_RUNSC: &str = "release-20261019.0";

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// The configuration file [default: /etc/kronik/kronik.toml if it exists].
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    /// Also check what the nonroot service (M21) needs, and run the smoke under
    /// its identity, also when invoked as root.
    #[arg(long)]
    rootless: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Serialize, JsonSchema)]
struct Check {
    /// Stable: config, kernel, runsc, kvm, cgroup, root, runc, netns,
    /// run_dir, caps, sandbox, disk, clock, tls, dns01_hook, wildcard, ship,
    /// export, key_source, secrets; with `--rootless` also userns, uid_view,
    /// subid, pin and delegate, and service_identity when a root invocation
    /// becomes the service user; microvm where a microVM tool bundle is
    /// installed and the root service runs; retention, connections.
    name: &'static str,
    status: Status,
    /// An error code from the catalog. Set on every failure, and on a
    /// warning when one applies.
    code: Option<&'static str>,
    message: String,
    /// What to do next. Set on every failure; a pass or a warning may omit it.
    hint: Option<String>,
}

fn check(name: &'static str, status: Status, message: impl Into<String>) -> Check {
    Check {
        name,
        status,
        code: None,
        message: message.into(),
        hint: None,
    }
}

impl Check {
    fn code(mut self, code: &'static str) -> Check {
        self.code = Some(code);
        self
    }

    fn hint(mut self, hint: impl Into<String>) -> Check {
        self.hint = Some(hint.into());
        self
    }
}

/// A failed check. I12: every failure has a catalog code and a non-empty hint.
fn failed(
    name: &'static str,
    message: impl Into<String>,
    code: ErrorCode,
    hint: impl Into<String>,
) -> Check {
    let hint = hint.into();
    debug_assert!(
        !hint.is_empty() && !hint.chars().any(char::is_control),
        "{name}: a failure hint must be one non-empty line"
    );
    check(name, Status::Fail, message)
        .code(code.as_str())
        .hint(hint)
}

/// One check as `kronik doctor` prints it. A failure includes its code and hint.
fn format_check(c: &Check) -> String {
    let status = match c.status {
        Status::Pass => "pass",
        Status::Warn => "warn",
        Status::Fail => "FAIL",
    };
    let code = c.code.map(|code| format!(" ({code})")).unwrap_or_default();
    let mut text = format!("  {status}  {:<7} {}{code}", c.name, c.message);
    if let Some(hint) = &c.hint {
        text.push('\n');
        text.push_str(&format!("        {:<7} hint: {hint}", ""));
    }
    text
}

/// What `kronik doctor --json` prints.
#[derive(Debug, Serialize, JsonSchema)]
struct Report {
    checks: Vec<Check>,
    pass: usize,
    warn: usize,
    fail: usize,
}

/// The schema of `kronik doctor --json` (docs/reference/json.md).
#[cfg(test)]
pub fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<Report>()
}

pub fn run(args: DoctorArgs, json: bool) -> ExitCode {
    let mut checks = Vec::new();
    let config = match Config::find(args.config.as_deref()) {
        Ok((config, Some(path))) => {
            checks.push(check(
                "config",
                Status::Pass,
                format!("{} is valid", path.display()),
            ));
            config
        }
        Ok((config, None)) => {
            checks.push(
                check(
                    "config",
                    Status::Pass,
                    "no configuration file: the defaults apply",
                )
                .hint("kronik serve --init writes /etc/kronik/kronik.toml"),
            );
            config
        }
        Err(e) => {
            checks.push(failed(
                "config",
                e.to_string(),
                ErrorCode::BadRequest,
                "fix the file; the other checks use the defaults",
            ));
            Config::default()
        }
    };
    // The nonroot service's checks are asked for, never added on their own: a
    // plain `kronik doctor` reports what it always did.
    let rootless_mode = args.rootless;
    let mut service_identity = !kronik_foreign::sys::is_root();
    // The nonroot unit's key reaches the daemon as a systemd credential, which
    // the service manager reads as root: the service user cannot read the
    // root-only key file itself. So root checks the key source here, before
    // it becomes that user below, the way the unit gets it.
    let key_before_drop = (args.rootless && !service_identity).then(|| key_source_as_root(&config));
    if args.rootless && !service_identity {
        match crate::cli::userns::kronik_user(crate::cli::userns::USER, None) {
            Ok(user) => match kronik_foreign::sys::become_user_with_groups(
                user.uid,
                user.gid,
                &service_groups(&user.name, user.gid),
            ) {
                Ok(()) => {
                    service_identity = true;
                    let groups = rustix::process::getgroups()
                        .map(|groups| groups.iter().map(|g| g.as_raw()).collect::<Vec<_>>())
                        .unwrap_or_default();
                    checks.push(check(
                        "service_identity",
                        Status::Pass,
                        format!(
                            "smoke runs as {} (host uid {}, gid {}, supplementary groups {groups:?}), \
                             as the service manager starts the unit",
                            user.name, user.uid, user.gid
                        ),
                    ));
                }
                Err(e) => {
                    checks.push(failed(
                        "service_identity",
                        format!("cannot become daemon user: {e}"),
                        ErrorCode::RootlessUnavailable,
                        "run doctor as root with CAP_SETUID and CAP_SETGID, or as the daemon's \
                         user: sudo -u kronik kronik doctor --rootless",
                    ));
                }
            },
            Err(e) => checks.push(check(
                "service_identity",
                Status::Warn,
                format!("cannot prove daemon identity: {e}"),
            )),
        }
    }
    let original_identity = root(rootless_mode);
    if rootless_mode {
        checks.extend(rootless());
    }
    checks.push(kernel());
    checks.push(runsc(&config.foreign.runsc_path));
    let dev_kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm");
    checks.push(kvm(config.foreign.platform, dev_kvm.map(drop)));
    checks.push(cgroup());
    checks.extend(microvm_leaf(
        config
            .foreign
            .microvm_dir
            .join("manifest.json")
            .try_exists()
            .unwrap_or(false),
        root_unit(),
    ));
    checks.push(original_identity);
    checks.push(runc());
    checks.push(if rootless_mode && !service_identity {
        check(
            "netns",
            Status::Warn,
            "not proven: daemon identity unavailable",
        )
    } else {
        netns()
    });
    checks.push(run_dir(&config.foreign.run_dir));
    checks.push(caps(&config.foreign.runsc_path, rootless_mode));
    checks.push(if rootless_mode && !service_identity {
        check(
            "sandbox",
            Status::Warn,
            "not proven: daemon identity unavailable",
        )
    } else {
        sandbox(&config.foreign.runsc_path, config.foreign.platform)
    });
    checks.push(disk(&config.server.data_dir));
    checks.push(clock());
    checks.push(tls(&config));
    checks.extend(dns01_hook(&config));
    checks.extend(wildcard_certificate(&config));
    checks.push(ship(&config));
    checks.push(export(&config));
    checks.push(key_before_drop.unwrap_or_else(|| key_source(&config)));
    checks.push(secrets(&config));
    checks.push(retention(&config));
    let hard = rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum;
    checks.push(connections(
        &config,
        hard.map_or(usize::MAX, |h| usize::try_from(h).unwrap_or(usize::MAX)),
    ));
    let count = |s| checks.iter().filter(|c| c.status == s).count();
    let report = Report {
        pass: count(Status::Pass),
        warn: count(Status::Warn),
        fail: count(Status::Fail),
        checks,
    };
    if json {
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        for c in &report.checks {
            println!("{}", format_check(c));
        }
        println!(
            "{} passed, {} warnings, {} failed",
            report.pass, report.warn, report.fail
        );
    }
    if report.fail > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Whether the open-file limit leaves room for `[connections] max_open`
/// (M24 §5.11): `kronik serve` raises its limit to the hard limit `hard`
/// and caps `max_open` to what the node, the gateway and the API leave.
fn connections(config: &Config, hard: usize) -> Check {
    let budget = crate::serve::connection_budget(hard);
    let max_open = config.connections.max_open;
    if budget >= max_open {
        return check(
            "connections",
            Status::Pass,
            format!("room for [connections] max_open = {max_open} under {hard} open files"),
        );
    }
    check(
        "connections",
        Status::Warn,
        format!(
            "{hard} open files leave room for {budget} WebSocket and SSE connections, \
             fewer than [connections] max_open = {max_open}"
        ),
    )
    .code(ErrorCode::ConnectionLimit.as_str())
    .hint("raise the daemon's open-file limit (LimitNOFILE=65536 in the shipped unit)")
}

/// `major.minor` of a kernel release such as `6.12.38+deb13-amd64`.
fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn kernel() -> Check {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = release.trim();
    match kernel_version(release) {
        Some(v) if v >= (5, 6) => check("kernel", Status::Pass, format!("Linux {release}")),
        Some(_) => check(
            "kernel",
            Status::Warn,
            format!("Linux {release} is older than 5.6"),
        )
        .hint("foreign actors (gVisor) need Linux 5.6 or newer"),
        None => check("kernel", Status::Warn, "cannot read the kernel version"),
    }
}

/// `release-YYYYMMDD.N` from `runsc --version`.
fn runsc_release(output: &str) -> Option<&str> {
    output
        .split_whitespace()
        .find(|word| word.starts_with("release-") && word.len() > "release-".len())
}

fn runsc(path: &Path) -> Check {
    let missing = |message: String| {
        check("runsc", Status::Warn, message)
            .code("RUNSC_MISSING")
            .hint("only foreign actors need it: install gVisor with install.sh, see https://gvisor.dev/docs/user_guide/install/")
    };
    if !is_executable(path) {
        return missing(format!("{} is not an executable file", path.display()));
    }
    let sentry = path.with_file_name("gvisor-bin").join("gvisor_sentry");
    if !sentry.is_file() {
        return missing(format!("{} is missing next to runsc", sentry.display()));
    }
    let version = Command::new(path).arg("--version").output();
    let text = version
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    match runsc_release(&text) {
        Some(release) if release >= TESTED_RUNSC => check(
            "runsc",
            Status::Pass,
            format!("{} {release}", path.display()),
        ),
        Some(release) => check(
            "runsc",
            Status::Warn,
            format!(
                "{} {release} is older than {TESTED_RUNSC}, the tested release",
                path.display()
            ),
        )
        .hint("upgrade gVisor with install.sh"),
        None => missing(format!(
            "{} --version does not report a release",
            path.display()
        )),
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `usable`: opening `/dev/kvm` read-write, as runsc's kvm platform does.
/// It exists but can't be opened on hosts where only the kvm group may
/// (CI runners): that is reported as such, not as a missing device.
fn kvm(platform: Platform, usable: std::io::Result<()>) -> Check {
    match (usable, platform) {
        (Ok(()), _) => check(
            "kvm",
            Status::Pass,
            "/dev/kvm is usable: gVisor's platforms kvm and systrap, and isolation microvm",
        ),
        (Err(e), Platform::Kvm) => {
            let mut hint =
                "[foreign] platform = \"kvm\" needs /dev/kvm; set platform = \"auto\" or \"systrap\"".to_owned();
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                hint.push_str(", or give this user access to /dev/kvm (the kvm group)");
            }
            failed(
                "kvm",
                format!("/dev/kvm: {e}"),
                ErrorCode::KvmUnavailable,
                hint,
            )
        }
        (Err(e), _) => check(
            "kvm",
            Status::Warn,
            format!("/dev/kvm: {e}; gVisor's platform systrap only, and no isolation microvm"),
        )
        .code("KVM_UNAVAILABLE")
        .hint(
            "fine for most hosts: foreign actors use gVisor with systrap without KVM; only \
             isolation microvm needs it",
        ),
    }
}

fn cgroup() -> Check {
    match std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
        Ok(controllers) => {
            let missing: Vec<&str> = ["cpu", "memory", "pids"]
                .into_iter()
                .filter(|c| !controllers.split_whitespace().any(|have| have == *c))
                .collect();
            if missing.is_empty() {
                check(
                    "cgroup",
                    Status::Pass,
                    "cgroup v2 with cpu, memory and pids",
                )
            } else {
                check(
                    "cgroup",
                    Status::Warn,
                    format!("cgroup v2 lacks the {} controllers", missing.join(", ")),
                )
                .hint("foreign actors' resource limits need them")
            }
        }
        Err(_) => check(
            "cgroup",
            Status::Warn,
            "cgroup v2 is not mounted at /sys/fs/cgroup",
        )
        .hint("foreign actors' resource limits need cgroup v2"),
    }
}

/// What the doctor can see of the root service's cgroup.
#[derive(Debug, PartialEq, Eq)]
enum RootUnit {
    /// Running: its main process is in this cgroup of the unified hierarchy.
    Running { pid: u32, cgroup: String },
    /// Loaded, not running: whether it asks systemd for the daemon's leaf.
    Stopped { leaf: bool },
}

/// The root service, from `systemctl show` of `kronik.service`: `None` when
/// the unit is not loaded, runs as a user (the nonroot service, which
/// `delegate` checks under `--rootless`), or systemd cannot be asked.
fn root_unit() -> Option<RootUnit> {
    let output = Command::new("systemctl")
        .args([
            "show",
            "--property=LoadState,User,MainPID,DelegateSubgroup",
            "kronik.service",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let text = String::from_utf8(output.stdout).ok()?;
    let pid = main_pid(&text);
    let cgroup = pid
        .filter(|&pid| pid != 0)
        .and_then(|pid| std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok())
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("0::"))
                .map(str::to_owned)
        });
    root_unit_from(&text, pid.zip(cgroup))
}

fn main_pid(show: &str) -> Option<u32> {
    show.lines()
        .find_map(|l| l.strip_prefix("MainPID="))?
        .parse()
        .ok()
}

/// `show` is the output of `systemctl show` for the properties above;
/// `running` the main process and its cgroup, if there is one.
fn root_unit_from(show: &str, running: Option<(u32, String)>) -> Option<RootUnit> {
    let property = |name: &str| {
        show.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
    };
    if property("LoadState") != Some("loaded") || property("User").is_none_or(|u| !u.is_empty()) {
        return None;
    }
    Some(match running {
        Some((pid, cgroup)) => RootUnit::Running { pid, cgroup },
        None => RootUnit::Stopped {
            leaf: property("DelegateSubgroup") == Some("daemon"),
        },
    })
}

/// A microVM needs the daemon in a delegated cgroup leaf. The root service's
/// unit is v0.4.0's and has none; the drop-in in the operations guide gives it
/// one. Silent where no tool bundle is installed or no root service is seen.
fn microvm_leaf(bundle: bool, unit: Option<RootUnit>) -> Option<Check> {
    use kronik_foreign::microvm::{ROOT_LEAF_NEED, root_leaf_advice};
    if !bundle {
        return None;
    }
    let (ok, where_) = match unit? {
        RootUnit::Running { pid, cgroup } => (
            cgroup.ends_with("/daemon"),
            format!("kronik.service (pid {pid}) runs in {cgroup}"),
        ),
        RootUnit::Stopped { leaf } => (
            leaf,
            format!(
                "kronik.service is not running and {} DelegateSubgroup=daemon",
                if leaf { "sets" } else { "does not set" }
            ),
        ),
    };
    Some(if ok {
        check(
            "microvm",
            Status::Pass,
            format!("{where_}: the daemon has the delegated leaf that microVM actors need"),
        )
    } else {
        check(
            "microvm",
            Status::Warn,
            format!("{ROOT_LEAF_NEED}: {where_}"),
        )
        .code("FOREIGN_UNAVAILABLE")
        .hint(root_leaf_advice())
    })
}

/// The supplementary groups the service manager gives the nonroot unit: the
/// user's memberships in /etc/group, as `initgroups` finds them for `User=`,
/// and the unit's `SupplementaryGroups=` (the managed KVM drop-in grants the
/// group of /dev/kvm that way). `sudo kronik doctor --rootless` takes them
/// when it becomes the user, so that its kvm, netns and sandbox checks see
/// the devices the service can open.
fn service_groups(user: &str, gid: u32) -> Vec<u32> {
    let group_file = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let unit = Command::new("systemctl")
        .args([
            "show",
            "--property=SupplementaryGroups",
            "--value",
            "kronik.service",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .unwrap_or_default();
    groups_of(&group_file, user, gid, &unit)
}

/// [`service_groups`] from the text of /etc/group and the unit's
/// `SupplementaryGroups=` value (names or numbers, separated by spaces).
/// Group 0, the invalid id and the user's own group are left out, and so is a
/// name that /etc/group does not know.
fn groups_of(group_file: &str, user: &str, gid: u32, supplementary: &str) -> Vec<u32> {
    let mut by_name = std::collections::BTreeMap::new();
    let mut groups = std::collections::BTreeSet::new();
    for line in group_file.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let [name, _, id, members] = fields[..] else {
            continue;
        };
        let Ok(id) = id.parse::<u32>() else {
            continue;
        };
        by_name.insert(name, id);
        if members.split(',').any(|member| member == user) {
            groups.insert(id);
        }
    }
    for word in supplementary.split_whitespace() {
        if let Some(id) = word
            .parse::<u32>()
            .ok()
            .or_else(|| by_name.get(word).copied())
        {
            groups.insert(id);
        }
    }
    groups.retain(|&id| id != 0 && id != u32::MAX && id != gid);
    groups.into_iter().collect()
}

/// Whether the process runs as root. Without `--rootless` this says what it
/// said before M21; with it, the identity the checks ran as.
fn root(rootless: bool) -> Check {
    // The effective uid itself: the owner of /proc/self is root for a process
    // that is not dumpable, which `--rootless` makes the doctor before it
    // becomes the service user.
    let initial_namespace = std::fs::read_to_string("/proc/self/uid_map")
        .is_ok_and(|map| kronik_foreign::sys::parse_map(&map) == [[0, 0, u32::MAX]]);
    root_identity(kronik_foreign::sys::euid(), initial_namespace, rootless)
}

/// [`root`] for an effective uid, and whether the process is in the initial
/// user namespace.
fn root_identity(euid: u32, initial_namespace: bool, rootless: bool) -> Check {
    match (euid, rootless) {
        (0, false) => check(
            "root",
            Status::Pass,
            "running as root, as the daemon does in v0.1",
        ),
        (_, false) => check(
            "root",
            Status::Warn,
            "not running as root: some checks see less than the daemon will",
        )
        .hint("sudo kronik doctor"),
        (0, true) if initial_namespace => check(
            "root",
            Status::Warn,
            "running as host root, not as the nonroot service's user: the checks below see more \
             than the service will",
        )
        .hint(
            "let `sudo kronik doctor --rootless` become the kronik user \
             (`sudo kronik serve --init --rootless` creates it), or run doctor as that user",
        ),
        (0, true) => check(
            "root",
            Status::Pass,
            "running as root of a user namespace: namespace-local authority only",
        ),
        (uid, true) => check(
            "root",
            Status::Pass,
            format!(
                "running as host uid {uid}, as the nonroot service does; its namespace is \
                 checked by `pin`"
            ),
        ),
    }
}

/// Checks namespace setup before service-identity smoke probes.
fn rootless() -> Vec<Check> {
    use kronik_foreign::subid::USERNS_PIN;
    use kronik_foreign::sys;
    let code = "ROOTLESS_UNAVAILABLE";
    let mut checks = Vec::new();
    checks.push(match crate::cli::userns::userns_allowed() {
        Ok(()) => check("userns", Status::Pass, "user namespaces are allowed"),
        Err(why) => check("userns", Status::Warn, why).code(code).hint(
            "set user.max_user_namespaces above 0 (and kernel.unprivileged_userns_clone = 1 on \
             Debian), or keep the root daemon: sudo kronik serve --init --root",
        ),
    });
    let root = sys::is_root();
    // The check the service makes before it starts; it refuses to start
    // where it fails (ADR 0065), so a failure here is a failure to start.
    checks.push(if root {
        check(
            "uid_view",
            Status::Warn,
            "skipped as root: run doctor as the service user, or `sudo kronik doctor --rootless`, which becomes that user",
        )
    } else {
        match sys::acceptor_view() {
            Ok(()) => check(
                "uid_view",
                Status::Pass,
                "the uid map is the host's identity map and the real, effective and saved \
                 uids agree: API callers keep their host uids",
            ),
            Err(why) => failed(
                "uid_view",
                why.to_string(),
                ErrorCode::RootlessUnavailable,
                "the nonroot service refuses to start here; use the root service on this \
                 host: sudo kronik serve --init --root",
            ),
        }
    });
    // As root, the `kronik` user; otherwise this user, as whom the daemon
    // would run.
    let uid = rustix::process::geteuid().as_raw();
    let user = if root {
        crate::cli::userns::kronik_user(crate::cli::userns::USER, None)
    } else {
        crate::cli::userns::kronik_user("", Some(uid))
    };
    checks.push(match &user {
        Ok(u) => check(
            "subid",
            Status::Pass,
            format!(
                "user {} (uid {}) has the ranges {}+{} (uids) and {}+{} (gids)",
                u.name, u.uid, u.subuid[0], u.subuid[1], u.subgid[0], u.subgid[1]
            ),
        ),
        Err(why) => check("subid", Status::Warn, why.clone())
            .code(code)
            .hint("sudo kronik serve --init --rootless creates the kronik user and its ranges"),
    });
    if !root && let Err(e) = sys::clear_capabilities() {
        checks.push(failed(
            "caps",
            format!("cannot clear host capabilities: {e}"),
            ErrorCode::RootlessUnavailable,
            "the nonroot service clears its capabilities and sets no-new-privileges before it \
             starts; check the seccomp and LSM policy that confines this process",
        ));
        return checks;
    }
    let pinned = sys::inspect_userns(std::path::Path::new(USERNS_PIN));
    let pin = match (&pinned, &user) {
        (Err(e), _) => check("pin", Status::Warn, format!("reading {USERNS_PIN}: {e}")).code(code),
        (Ok(None), _) => check(
            "pin",
            Status::Warn,
            format!("nothing is pinned at {USERNS_PIN}"),
        )
        .code(code)
        .hint("sudo systemctl start kronik-userns (it runs `kronik userns pin`)"),
        (Ok(Some(p)), _) if p.maps.is_err() => check(
            "pin",
            Status::Warn,
            format!(
                "{USERNS_PIN} is owned by uid {}; its maps are unreadable here: {}",
                p.owner,
                p.maps.as_ref().err().map_or("", String::as_str)
            ),
        )
        .code(code)
        .hint("run doctor as root or as the daemon's user"),
        (Ok(Some(p)), Ok(u))
            if p.owner == u.uid
                && p.maps.as_ref().ok() == Some(&u.maps())
                && !p.denies_setgroups() =>
        {
            failed(
                "pin",
                format!(
                    "{USERNS_PIN} has the right owner and maps, but {}",
                    sys::SETGROUPS_ALLOWED
                ),
                ErrorCode::RootlessUnavailable,
                "stop kronik.service, then sudo kronik userns unpin and sudo systemctl restart \
                 kronik-userns, which pins a namespace that denies setgroups",
            )
        }
        (Ok(Some(p)), Ok(u)) if p.owner == u.uid && p.maps.as_ref().ok() == Some(&u.maps()) => {
            check(
                "pin",
                Status::Pass,
                format!(
                    "{USERNS_PIN} is owned by {}, maps 0 to it and 1-65535 to its ranges, and denies setgroups",
                    u.name
                ),
            )
        }
        (Ok(Some(p)), _) => failed(
            "pin",
            format!(
                "{USERNS_PIN} is owned by uid {} with maps {:?}: not what the user's ranges give, \
                 so the daemon refuses it",
                p.owner, p.maps
            ),
            ErrorCode::RootlessUnavailable,
            "stop kronik.service, then sudo kronik userns unpin and sudo systemctl restart \
             kronik-userns, which pins the namespace the user's ranges give",
        ),
    };
    let pin_ok = pin.status == Status::Pass;
    let pin_index = checks.len();
    checks.push(pin);
    checks.push(if root {
        check(
            "delegate",
            Status::Warn,
            "skipped as root: only the daemon's unit has the delegated cgroup",
        )
        .hint("run `kronik doctor` as the daemon's user inside a unit like kronik.service to check it")
    } else {
        let cgroup = sys::own_cgroup().unwrap_or_default();
        if sys::cgroup_delegated(&cgroup) {
            check(
                "delegate",
                Status::Pass,
                format!("cgroup {cgroup} is delegated to this user"),
            )
        } else {
            check(
                "delegate",
                Status::Warn,
                format!("cgroup {cgroup} is not delegated to this user"),
            )
            .code(code)
            .hint("the daemon gets one in kronik.service (Delegate=yes); outside it foreign actors are unavailable")
        }
    });
    if !root
        && pin_ok
        && let Ok(u) = &user
        && let Err(e) = sys::enter_userns(std::path::Path::new(USERNS_PIN), &u.maps())
    {
        checks[pin_index] = failed(
            "pin",
            format!("cannot enter {USERNS_PIN}: {e}"),
            ErrorCode::RootlessUnavailable,
            "the nonroot service enters this namespace when it starts and refuses to start \
             without it; check the kernel's user-namespace policy (AppArmor on Ubuntu) or use \
             the root service: sudo kronik serve --init --root",
        );
    }
    checks
}

/// runc, for `--isolation trusted` (docs/design/m7-foreign.md §15).
fn runc() -> Check {
    let found = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin"]
        .iter()
        .map(|d| Path::new(d).join("runc"))
        .find(|p| is_executable(p));
    match found {
        Some(p) => check(
            "runc",
            Status::Pass,
            format!("{}: isolation trusted is available", p.display()),
        ),
        None => check(
            "runc",
            Status::Warn,
            "no runc: isolation trusted is unavailable (gvisor does not need it)",
        )
        .code("RUNC_MISSING")
        .hint("only for --isolation trusted: apt install runc"),
    }
}

/// A network namespace with only `lo` can be made (each foreign actor
/// gets one).
fn netns() -> Check {
    if !kronik_foreign::sys::is_root() {
        return check("netns", Status::Warn, "skipped: needs root").hint("sudo kronik doctor");
    }
    let made = tempfile::Builder::new()
        .prefix("kronik-doctor-")
        .tempdir()
        .map_err(|e| e.to_string())
        .and_then(|dir| {
            let ns = dir.path().join("ns");
            kronik_foreign::sys::create_netns(&ns).map_err(|e| e.to_string())?;
            let ifaces = kronik_foreign::sys::netns_interfaces(&ns).map_err(|e| e.to_string());
            let _ = kronik_foreign::sys::delete_netns(&ns);
            ifaces
        });
    match made {
        Ok(ifaces) if ifaces == ["lo"] => check(
            "netns",
            Status::Pass,
            "network namespaces with only lo can be created",
        ),
        Ok(ifaces) => failed(
            "netns",
            format!("a new namespace has {ifaces:?}, not only lo"),
            ErrorCode::ForeignUnavailable,
            "foreign actors would run without network isolation; check the kernel and any container runtime around the host",
        ),
        Err(e) => check(
            "netns",
            Status::Warn,
            format!("cannot create a network namespace: {e}"),
        )
        .code("FOREIGN_UNAVAILABLE")
        .hint(
            "foreign actors need CAP_SYS_ADMIN and unprivileged mounts of /proc/thread-self/ns/net",
        ),
    }
}

/// Whether `/proc/<pid>/status` text has `CAP_SETUID` (bit 7) in `CapPrm`.
fn has_cap_setuid(status: &str) -> Option<bool> {
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapPrm:"))?
        .trim();
    Some(u64::from_str_radix(hex, 16).ok()? & (1 << 7) != 0)
}

/// What `caps` examines.
#[derive(Debug, PartialEq, Eq)]
enum CapsSubject {
    /// The running root `kronik.service` (its pid): the trap of ADR 0027 is a
    /// root unit that lost `CAP_SETUID`.
    RootUnit(u32),
    /// This process, the identity of the smoke.
    Process,
}

/// The unit's main process is examined only while it runs as root. The
/// nonroot unit holds no host capability by design (it empties them after
/// binding its ports and works with namespace-local authority), so its
/// status says nothing about whether `runsc` can start.
fn caps_subject(unit: Option<(u32, &str)>) -> CapsSubject {
    match unit {
        Some((pid, status)) if effective_uid(status) == Some(0) => CapsSubject::RootUnit(pid),
        _ => CapsSubject::Process,
    }
}

/// Whether lacking `CAP_SETUID` is the trap of ADR 0027, a failure: it is for
/// a root unit and, as in v0.4.0, for the doctor process itself. Only with
/// `--rootless`, and only for a process that is not root (it entered the
/// service's namespace, or could not), is it a warning about namespace-local
/// authority.
fn caps_is_trap(subject: &CapsSubject, root: bool, rootless: bool) -> bool {
    match subject {
        CapsSubject::RootUnit(_) => true,
        CapsSubject::Process => root || !rootless,
    }
}

/// The effective uid of a `/proc/<pid>/status` text.
fn effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// runsc's gofer needs `CAP_SETUID`. systemd drops it from a root unit with
/// an explicit `User=` and a seccomp-based setting, and `NoNewPrivileges`
/// keeps runsc from getting it back (ADR 0027). Looks at the running root
/// kronik.service's process if there is one, else at this process. A nonroot
/// unit is not examined: it holds no host capability by design. With
/// `--rootless`, a doctor process that is not root checks namespace-local
/// authority, and lacking it is a warning: Wasm actors still run.
fn caps(runsc: &Path, rootless: bool) -> Check {
    if !is_executable(runsc) {
        return check("caps", Status::Warn, "skipped: no runsc").code("RUNSC_MISSING");
    }
    let unit = Command::new("systemctl")
        .args(["show", "--property=MainPID", "--value", "kronik.service"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&pid| pid != 0)
        .and_then(|pid| {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            Some((pid, status))
        });
    let subject = caps_subject(unit.as_ref().map(|(pid, s)| (*pid, s.as_str())));
    let trap = caps_is_trap(&subject, kronik_foreign::sys::is_root(), rootless);
    let (who, path) = match subject {
        CapsSubject::RootUnit(pid) => (
            format!("kronik.service (pid {pid})"),
            format!("/proc/{pid}/status"),
        ),
        CapsSubject::Process if trap => ("this process".to_owned(), "/proc/self/status".to_owned()),
        CapsSubject::Process => (
            "this doctor process (the identity used by its smoke)".to_owned(),
            "/proc/self/status".to_owned(),
        ),
    };
    match std::fs::read_to_string(&path)
        .ok()
        .as_deref()
        .and_then(has_cap_setuid)
    {
        Some(true) => check(
            "caps",
            Status::Pass,
            format!("{who} has CAP_SETUID, which runsc needs"),
        ),
        Some(false) if trap => failed(
            "caps",
            format!(
                "{who} lacks CAP_SETUID: no foreign actor can start (runsc's gofer fails with EPERM)"
            ),
            ErrorCode::ForeignUnavailable,
            "remove User= from kronik.service and its drop-ins; with it, systemd drops CAP_SETUID \
             under the unit's seccomp settings (docs/adr/0027-systemd-unit-hardening.md)",
        ),
        Some(false) => check(
            "caps",
            Status::Warn,
            format!("{who} lacks namespace-local CAP_SETUID: foreign sandboxes are unavailable"),
        )
        .hint(
            "check the pinned namespace and delegated unit with `kronik doctor --rootless`; \
             `kronik serve --init --root` installs the root service instead",
        ),
        None => check("caps", Status::Warn, format!("could not read {path}")),
    }
}

/// `[foreign] run_dir` exists or can be created.
fn run_dir(dir: &Path) -> Check {
    let usable = if dir.is_dir() {
        tempfile::tempfile_in(dir).is_ok()
    } else {
        dir.ancestors()
            .skip(1)
            .find(|p| p.exists())
            .is_some_and(|p| tempfile::tempfile_in(p).is_ok())
    };
    if usable {
        check(
            "run_dir",
            Status::Pass,
            format!("{} is usable for sandbox state", dir.display()),
        )
    } else {
        check(
            "run_dir",
            Status::Warn,
            format!("{} cannot be written", dir.display()),
        )
        .hint("set [foreign] run_dir to a writable directory, ideally on a tmpfs")
    }
}

/// Smoke test: a minimal sandbox with the chosen platform runs `true`. It
/// catches seccomp, AppArmor and systrap problems on unusual hosts.
fn sandbox(runsc: &Path, platform: Platform) -> Check {
    if !is_executable(runsc) {
        return check("sandbox", Status::Warn, "skipped: no runsc").code("RUNSC_MISSING");
    }
    if !kronik_foreign::sys::is_root() {
        return check("sandbox", Status::Warn, "skipped: needs root").hint("sudo kronik doctor");
    }
    // A failure only when the configuration asks for KVM.
    let failed = if matches!(platform, Platform::Kvm) {
        Status::Fail
    } else {
        Status::Warn
    };
    let platform = match platform {
        Platform::Kvm => "kvm",
        Platform::Auto | Platform::Systrap => "systrap",
    };
    let Ok(root) = tempfile::Builder::new()
        .prefix("kronik-doctor-runsc-")
        .tempdir()
    else {
        return check(
            "sandbox",
            Status::Warn,
            "cannot create a temporary runsc root",
        );
    };
    let out = Command::new("timeout")
        .current_dir("/")
        .arg("30")
        .arg(runsc)
        .arg("--root")
        .arg(root.path())
        .arg(format!("--platform={platform}"))
        .args(["--network=none", "do", "/bin/true"])
        .output();
    match out {
        Ok(o) if o.status.success() => check(
            "sandbox",
            Status::Pass,
            format!("runsc --platform={platform} runs a sandbox"),
        ),
        Ok(o) => check(
            "sandbox",
            failed,
            format!(
                "runsc --platform={platform} do /bin/true failed ({}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        )
        .code("FOREIGN_UNAVAILABLE")
        .hint("see https://gvisor.dev/docs/user_guide/compatibility/ and the daemon's seccomp/AppArmor setup"),
        Err(e) => check("sandbox", Status::Warn, format!("cannot run runsc: {e}")),
    }
}

/// Free bytes on the filesystem of `dir`, or of its nearest existing parent.
fn free_bytes(dir: &Path) -> Option<u64> {
    let existing = dir.ancestors().find(|p| p.exists())?;
    let out = Command::new("df")
        .args(["-P", "-B1"])
        .arg(existing)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().nth(1)?.split_whitespace().nth(3)?.parse().ok()
}

fn disk(data_dir: &Path) -> Check {
    const GIB: u64 = 1 << 30;
    match free_bytes(data_dir) {
        Some(free) if free < GIB => failed(
            "disk",
            format!(
                "{:.1} GiB free for {}",
                free as f64 / GIB as f64,
                data_dir.display()
            ),
            ErrorCode::Unavailable,
            "the log and snapshots need room: free space or move server.data_dir",
        ),
        Some(free) if free < 5 * GIB => check(
            "disk",
            Status::Warn,
            format!(
                "{:.1} GiB free for {}",
                free as f64 / GIB as f64,
                data_dir.display()
            ),
        )
        .hint("history and snapshots grow with traffic; see [retention]"),
        Some(free) => check(
            "disk",
            Status::Pass,
            format!(
                "{:.1} GiB free for {}",
                free as f64 / GIB as f64,
                data_dir.display()
            ),
        ),
        None => check(
            "disk",
            Status::Warn,
            format!("cannot tell the free space for {}", data_dir.display()),
        ),
    }
}

fn clock() -> Check {
    let synced = Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .output();
    match synced.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()) {
        Ok(v) if v == "yes" => check("clock", Status::Pass, "synchronized by NTP"),
        Ok(v) if v == "no" => check("clock", Status::Warn, "not synchronized by NTP")
            .hint("timestamps and ACME need a correct clock: timedatectl set-ntp true"),
        _ => check(
            "clock",
            Status::Warn,
            "cannot tell whether the clock is synchronized (no timedatectl)",
        ),
    }
}

/// Days until `expiry`, negative when it has passed.
fn days_left(expiry: SystemTime) -> i64 {
    match expiry.duration_since(SystemTime::now()) {
        Ok(left) => (left.as_secs() / 86_400) as i64,
        Err(past) => -((past.duration().as_secs() / 86_400) as i64) - 1,
    }
}

fn certificate_check(source: &str, chain: &[u8], key: &[u8]) -> Check {
    match kronik_gateway::tls::parse_pem(chain, key) {
        Ok((_, expiry)) => match days_left(expiry) {
            d if d < 0 => failed(
                "tls",
                format!("{source}: the certificate has expired"),
                ErrorCode::CertificateInvalid,
                "renew the certificate; for files, replace the PEM, and for ACME read the daemon log",
            ),
            d if d < 30 => check(
                "tls",
                Status::Warn,
                format!("{source}: the certificate expires in {d} days"),
            ),
            d => check(
                "tls",
                Status::Pass,
                format!("{source}: the certificate is valid for {d} more days"),
            ),
        },
        Err(e) => failed(
            "tls",
            format!("{source}: {e}"),
            ErrorCode::CertificateInvalid,
            "replace the PEM files; the message names what could not be parsed",
        ),
    }
}

fn tls(config: &Config) -> Check {
    match config.tls.mode {
        TlsMode::Off => check(
            "tls",
            Status::Pass,
            "TLS is off: the gateway serves plain HTTP",
        ),
        TlsMode::Files => {
            let (cert, key) = (
                config.tls.cert_file.clone().unwrap_or_default(),
                config.tls.key_file.clone().unwrap_or_default(),
            );
            match (std::fs::read(&cert), std::fs::read(&key)) {
                (Ok(chain), Ok(key_pem)) => {
                    certificate_check(&cert.display().to_string(), &chain, &key_pem)
                }
                (Err(e), _) => failed(
                    "tls",
                    format!("{}: {e}", cert.display()),
                    ErrorCode::CertificateInvalid,
                    "fix the path and permissions; [tls] mode = \"files\" needs readable cert_file and key_file",
                ),
                (_, Err(e)) => failed(
                    "tls",
                    format!("{}: {e}", key.display()),
                    ErrorCode::CertificateInvalid,
                    "fix the path and permissions; [tls] mode = \"files\" needs readable cert_file and key_file",
                ),
            }
        }
        TlsMode::Acme => {
            let cached = std::fs::read_dir(config.server.data_dir.join("tls/acme"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path().join("certificate.pem"))
                .find_map(|path| std::fs::read(&path).ok().map(|pem| (path, pem)));
            match cached {
                Some((path, pem)) => certificate_check(&path.display().to_string(), &pem, &pem),
                None => check(
                    "tls",
                    Status::Warn,
                    format!("no ACME certificate yet for {}", config.tls.domains.join(", ")),
                )
                .hint("the gateway gets one when it starts: the names must point at this host, port 443 open"),
            }
        }
    }
}

/// The DNS-01 hook, when `[tls] dns01_hook` is set: an executable file.
fn dns01_hook(config: &Config) -> Option<Check> {
    use std::os::unix::fs::PermissionsExt as _;
    let hook = config.tls.dns01_hook.as_ref()?;
    let hint = "the hook publishes the wildcard certificate's TXT records: chmod +x it, \
                and see docs/guides/operations.md, TLS";
    Some(match std::fs::metadata(hook) {
        Ok(m) if m.is_file() && m.permissions().mode() & 0o111 != 0 => check(
            "dns01_hook",
            Status::Pass,
            format!("{} is the DNS-01 hook", hook.display()),
        ),
        Ok(_) => failed(
            "dns01_hook",
            format!(
                "{}: the DNS-01 hook is not an executable file",
                hook.display()
            ),
            ErrorCode::BadRequest,
            hint,
        ),
        Err(e) => failed(
            "dns01_hook",
            format!("{}: {e}", hook.display()),
            ErrorCode::BadRequest,
            hint,
        ),
    })
}

/// The cached `*.<preview_domain>` certificate, when `[tls] dns01_hook` is
/// set: renewal by DNS-01 fails quietly (an expired API token) while the
/// hook itself stays executable.
fn wildcard_certificate(config: &Config) -> Option<Check> {
    config.tls.dns01_hook.as_ref()?;
    let domain = config.gateway.preview_domain.as_deref()?;
    let name = format!("wildcard.{domain}.pem");
    let cached = std::fs::read_dir(config.server.data_dir.join("tls/acme"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path().join(&name))
        .find_map(|path| std::fs::read(&path).ok().map(|pem| (path, pem)));
    let mut c = match cached {
        Some((path, pem)) => certificate_check(&path.display().to_string(), &pem, &pem),
        None => check(
            "dns01_hook",
            Status::Warn,
            format!("no wildcard certificate yet for *.{domain}"),
        )
        .hint("the gateway orders one when it starts; see the DNS-01 hook's output in the log"),
    };
    c.name = "dns01_hook";
    Some(c)
}

/// `host:port` of an `https://` or `http://` endpoint. Anything else is not
/// an http(s) URL, including a bare host and `s3://`.
fn endpoint_authority(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let authority = rest.split('/').next()?;
    if authority.contains(':') {
        Some(authority.to_owned())
    } else {
        Some(format!(
            "{authority}:{}",
            if scheme == "http" { 80 } else { 443 }
        ))
    }
}

fn ship(config: &Config) -> Check {
    if !config.ship.enabled {
        return check("ship", Status::Pass, "shipping is off");
    }
    let Some(endpoint) = config.ship.endpoint.as_deref().filter(|e| !e.is_empty()) else {
        return check(
            "ship",
            Status::Warn,
            "[ship] has no endpoint to check: the provider's default applies",
        );
    };
    let Some(authority) = endpoint_authority(endpoint) else {
        return failed(
            "ship",
            format!("[ship] endpoint {endpoint:?} is not an http(s) URL"),
            ErrorCode::BadRequest,
            "set [ship] endpoint to an http:// or https:// URL",
        );
    };
    use std::net::ToSocketAddrs as _;
    let reachable = authority.to_socket_addrs().ok().and_then(|mut addrs| {
        addrs
            .find(|addr| std::net::TcpStream::connect_timeout(addr, Duration::from_secs(5)).is_ok())
    });
    match reachable {
        Some(addr) => check(
            "ship",
            Status::Pass,
            format!("{endpoint} is reachable ({addr})"),
        ),
        None => failed(
            "ship",
            format!("{endpoint} is not reachable"),
            ErrorCode::Unavailable,
            "check the endpoint, DNS and the firewall; snapshots cannot ship until it answers",
        ),
    }
}

/// The export streams of a running daemon (m28-otel §5, §6.2): its `GET
/// /v1/export` on the configured API socket.
fn export(config: &Config) -> Check {
    let socket = &config.server.api_socket;
    let token = match crate::cli::client_token_from(None) {
        Ok(token) => token,
        Err(_) => {
            return check("export", Status::Warn, "cannot load the API token")
                .hint("check KRONIK_TOKEN and its token file");
        }
    };
    let endpoint = crate::cli::http::Endpoint::Unix(socket.clone());
    match crate::cli::http::request(
        &endpoint,
        "GET",
        "/v1/export",
        None,
        token.as_deref(),
        None,
        std::time::Duration::from_secs(5),
    ) {
        Ok(r) if r.status == 200 => {
            match serde_json::from_slice::<kronik_api::types::ExportStatusResponse>(&r.body) {
                Ok(s) => export_streams(config, &s.streams),
                Err(_) => check(
                    "export",
                    Status::Warn,
                    "the API returned invalid export status",
                )
                .hint("check the selected API socket and daemon version"),
            }
        }
        Ok(r) => check(
            "export",
            Status::Warn,
            format!("cannot read the export status: HTTP {}", r.status),
        )
        .hint("set KRONIK_TOKEN to a token with the read scope"),
        Err(crate::cli::http::Failure::Connect(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            check(
                "export",
                Status::Pass,
                format!(
                    "no daemon on {}: the export streams are not checked",
                    socket.display()
                ),
            )
        }
        Err(e) => check(
            "export",
            Status::Warn,
            match e {
                crate::cli::http::Failure::Connect(_) => "cannot connect to the API socket",
                crate::cli::http::Failure::Tls(_) => "the API TLS handshake failed",
                crate::cli::http::Failure::Io(_) => "the API connection broke",
                crate::cli::http::Failure::Timeout => "the API request timed out",
                crate::cli::http::Failure::Malformed(_) => "the API returned malformed HTTP",
            },
        )
        .hint("check the API socket and daemon; the export streams are not checked"),
    }
}

/// [`key_source`] for `sudo kronik doctor --rootless`, run as root before the
/// doctor becomes the service user. Over a data directory that another user
/// owns, root reads the key and nothing else (ADR 0062): the stores in that
/// directory are the service's, and it checks them against the key when it
/// starts. A root-owned directory gets the full check, as without
/// `--rootless`.
fn key_source_as_root(config: &Config) -> Check {
    use std::os::unix::fs::MetadataExt as _;
    let another_users = std::fs::metadata(&config.server.data_dir).is_ok_and(|m| m.uid() != 0);
    if another_users {
        key_source_checked(config, KeyCheck::MasterOnly)
    } else {
        key_source(config)
    }
}

/// How much of the key source `key_source_checked` loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCheck {
    /// The key, and the data directory's stores against it.
    Full,
    /// The key alone; nothing in the data directory but a KMS envelope.
    MasterOnly,
}

fn key_source(config: &Config) -> Check {
    key_source_checked(config, KeyCheck::Full)
}

fn key_source_checked(config: &Config, scope: KeyCheck) -> Check {
    use kronik_privacy::key_source::KeySource;
    let source = config.keys.source.as_str();
    let data = &config.server.data_dir;
    let mut credentials = Vec::new();
    if let Some(c) = &config.keys.openbao {
        credentials.extend([
            &c.token_file,
            &c.role_id_file,
            &c.secret_id_file,
            &c.key_file,
        ]);
    }
    if let Some(c) = &config.keys.gcp {
        credentials.push(&c.service_account_file);
    }
    if let Some(c) = &config.keys.azure {
        credentials.push(&c.client_secret_file);
    }
    let canonical_data = std::fs::canonicalize(data).unwrap_or_else(|_| data.clone());
    for file in credentials.into_iter().flatten() {
        let file = if file.is_absolute() {
            file.clone()
        } else {
            std::env::var_os("CREDENTIALS_DIRECTORY")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(file)
        };
        let file = std::fs::canonicalize(&file).unwrap_or(file);
        if file.starts_with(&canonical_data) {
            return check("key_source", Status::Warn, format!("{source}: bootstrap credential is under the data directory"))
                .hint("keep bootstrap credentials out of the data directory and its backups; prefer instance identity");
        }
    }
    if !config.keys.source.is_kms()
        && !data.join("keys/secrets.db").exists()
        && !config.keys.key_path(data).exists()
        && std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_none()
    {
        return check(
            "key_source",
            Status::Pass,
            format!("{source}: not initialized yet"),
        );
    }
    let endpoint = crate::cli::http::Endpoint::Unix(config.server.api_socket.clone());
    let token = crate::cli::client_token_from(None).ok().flatten();
    if let Ok(r) = crate::cli::http::request(
        &endpoint,
        "GET",
        "/v1/keys",
        None,
        token.as_deref(),
        None,
        Duration::from_secs(5),
    ) && r.status == 200
        && let Ok(status) = serde_json::from_slice::<kronik_privacy::key_source::KeyStatus>(&r.body)
    {
        return check(
            "key_source",
            Status::Pass,
            format!("{}: loaded; key checks match", status.source),
        );
    }
    let result = crate::restore::runtime()
        .map_err(|e| e.code)
        .and_then(|runtime| {
            runtime.block_on(async {
                let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
                match scope {
                    KeyCheck::Full => KeySource::load(env, config.keys.clone(), data, false)
                        .await
                        .map(|loaded| {
                            let status = loaded.status();
                            format!(
                                "{} {} {}; key checks match",
                                status.source,
                                status.key.unwrap_or_default(),
                                status.key_version.unwrap_or_default()
                            )
                        }),
                    KeyCheck::MasterOnly => KeySource::load_master(&env, config.keys.clone(), data)
                        .await
                        .map(|_| {
                            format!(
                                "{source}: the master key loads as root, as the unit's \
                                     credential does; the service checks its stores against it \
                                     when it starts"
                            )
                        }),
                }
                .map_err(|e| e.api_error().code)
            })
        });
    match result {
        Ok(message) => check("key_source", Status::Pass, message),
        Err(code) => failed(
            "key_source",
            format!("{source}: {code}"),
            code,
            "check the configured provider, credentials, key version and memory-lock limit",
        ),
    }
}

/// The external secret backends of a running daemon (m23 §6): its `GET
/// /v1/secrets/backends` on the configured API socket. Each backend's last
/// answer, and the linked names an effect would have to fetch.
fn secrets(config: &Config) -> Check {
    let socket = &config.server.api_socket;
    let token = match crate::cli::client_token_from(None) {
        Ok(token) => token,
        Err(_) => {
            return check("secrets", Status::Warn, "cannot load the API token")
                .hint("check KRONIK_TOKEN and its token file");
        }
    };
    let endpoint = crate::cli::http::Endpoint::Unix(socket.clone());
    match crate::cli::http::request(
        &endpoint,
        "GET",
        "/v1/secrets/backends",
        None,
        token.as_deref(),
        None,
        Duration::from_secs(5),
    ) {
        Ok(r) if r.status == 200 => {
            match serde_json::from_slice::<kronik_api::types::SecretBackendsResponse>(&r.body) {
                Ok(s) => secret_backends(&s.backends, now_ms()),
                Err(_) => check(
                    "secrets",
                    Status::Warn,
                    "the API returned an invalid list of secret backends",
                )
                .hint("check the selected API socket and daemon version"),
            }
        }
        Ok(r) => check(
            "secrets",
            Status::Warn,
            format!("cannot read the secret backends: HTTP {}", r.status),
        )
        .hint("set KRONIK_TOKEN to a token with the read scope"),
        Err(crate::cli::http::Failure::Connect(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            check(
                "secrets",
                Status::Pass,
                format!(
                    "no daemon on {}: the secret backends are not checked",
                    socket.display()
                ),
            )
        }
        Err(_) => check(
            "secrets",
            Status::Warn,
            "cannot reach the API socket: the secret backends are not checked",
        )
        .hint("check the API socket and the daemon"),
    }
}

/// Whether an open turn keeps the log of a running daemon from retention:
/// its `GET /v1/health` on the configured API socket, which carries what the
/// last retention pass kept for one.
fn retention(config: &Config) -> Check {
    let socket = &config.server.api_socket;
    let token = match crate::cli::client_token_from(None) {
        Ok(token) => token,
        Err(_) => {
            return check("retention", Status::Warn, "cannot load the API token")
                .hint("check KRONIK_TOKEN and its token file");
        }
    };
    let endpoint = crate::cli::http::Endpoint::Unix(socket.clone());
    match crate::cli::http::request(
        &endpoint,
        "GET",
        "/v1/health",
        None,
        token.as_deref(),
        None,
        Duration::from_secs(5),
    ) {
        Ok(r) if r.status == 200 => {
            match serde_json::from_slice::<kronik_api::types::HealthResponse>(&r.body) {
                Ok(health) => retention_pin(health.retention_pin.as_ref(), now_ms()),
                Err(_) => check(
                    "retention",
                    Status::Warn,
                    "the API returned an invalid health answer",
                )
                .hint("check the selected API socket and daemon version"),
            }
        }
        Ok(r) => check(
            "retention",
            Status::Warn,
            format!("cannot read the daemon's health: HTTP {}", r.status),
        )
        .hint("set KRONIK_TOKEN to a token with the read scope"),
        Err(crate::cli::http::Failure::Connect(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            check(
                "retention",
                Status::Pass,
                format!(
                    "no daemon on {}: retention is not checked",
                    socket.display()
                ),
            )
        }
        Err(_) => check(
            "retention",
            Status::Warn,
            "cannot reach the API socket: retention is not checked",
        )
        .hint("check the API socket and the daemon"),
    }
}

/// Warns when the last retention pass kept log segments for an open turn,
/// which it would have deleted otherwise: the log grows past `[retention]
/// history` until the turn ends (or, for a turn a kept snapshot holds open,
/// until that snapshot is deleted).
fn retention_pin(pin: Option<&kronik_api::types::RetentionPinView>, now: u64) -> Check {
    let Some(pin) = pin else {
        return check(
            "retention",
            Status::Pass,
            "no open turn keeps the log from retention",
        );
    };
    let held = format!("{:.1} MiB", pin.held_bytes as f64 / f64::from(1u32 << 20));
    let since = crate::cli::units::duration(now.saturating_sub(pin.since_ms) / 1000 * 1000);
    let message = match (&pin.snapshot, &pin.actor) {
        (Some(snapshot), _) => format!(
            "snapshot {snapshot} holds turn {} open: retention keeps {} log segments ({held}) \
             past [retention] history for it, for {since} now, until that snapshot is deleted",
            pin.execution_id, pin.held_segments
        ),
        (None, actor) => format!(
            "turn {} of {} is open since lsn {}: retention keeps {} log segments ({held}) past \
             [retention] history for it, for {since} now",
            pin.execution_id,
            actor.as_deref().unwrap_or("an actor"),
            pin.begin_lsn.unwrap_or(pin.segment),
            pin.held_segments
        ),
    };
    check("retention", Status::Warn, message).hint(
        "find out why the turn does not end; see the operations guide, An open turn that keeps the log",
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Warns for each external backend whose last request failed (it has not
/// answered since), and for each linked name without a value an effect could
/// use: while its backend does not answer, an effect that needs it fails
/// with SECRET_UNAVAILABLE.
fn secret_backends(backends: &[kronik_api::types::SecretBackendView], now: u64) -> Check {
    let external: Vec<_> = backends.iter().filter(|b| b.kind != "file").collect();
    if external.is_empty() {
        return check(
            "secrets",
            Status::Pass,
            "no external secret backend is configured",
        );
    }
    let ago = |at: u64| crate::cli::units::duration(now.saturating_sub(at) / 1000 * 1000);
    let mut warnings = Vec::new();
    for b in &external {
        if let (Some(error), Some(at)) = (&b.last_error, b.last_error_ms)
            && b.last_success_ms.is_none_or(|ok| ok < at)
        {
            let since = b.last_success_ms.map_or_else(
                || "it has not answered since the daemon started".to_owned(),
                |ok| format!("its last answer was {} ago", ago(ok)),
            );
            warnings.push(format!(
                "{}: the last request failed ({error}) {} ago; {since}",
                b.id,
                ago(at)
            ));
        }
        if !b.uncached.is_empty() {
            warnings.push(format!(
                "{}: no cached value of {}",
                b.id,
                b.uncached.join(", ")
            ));
        }
    }
    if warnings.is_empty() {
        let answered = external
            .iter()
            .filter(|b| b.last_success_ms.is_some())
            .count();
        return check(
            "secrets",
            Status::Pass,
            format!(
                "{} external backends, {answered} answered; every linked name has a cached value",
                external.len()
            ),
        );
    }
    check("secrets", Status::Warn, warnings.join("; "))
        .code(ErrorCode::SecretUnavailable.as_str())
        .hint(
            "check the backend and this node's credentials for it; `kronik secret backends` shows each backend's last answer, and the log's `secret fetch failed` lines say why",
        )
}

/// Warns when a stream with lag has not delivered for 10 × its interval,
/// and when the audit export has held retention for longer than
/// `[retention] history` (the hold's age is the time since its last
/// delivery).
fn export_streams(config: &Config, streams: &[kronik_api::types::ExportStream]) -> Check {
    let history = config.retention.history.0;
    let mut warnings = Vec::new();
    for s in streams.iter().filter(|s| s.enabled) {
        let Some(stalled) = s.stalled_ms.map(Duration::from_millis) else {
            continue;
        };
        let interval = if s.name == "audit" {
            config.audit.interval.0
        } else {
            config.otel.interval.0
        };
        let shown = crate::cli::units::duration(stalled.as_millis() as u64);
        if s.name == "audit" && stalled > history {
            warnings.push(format!(
                "the audit export has held retention for {shown}, longer than [retention] history, with {} records to export",
                s.lag
            ));
        } else if stalled > interval * 10 {
            warnings.push(format!(
                "the {} export has not delivered for {shown}, with {} records to export",
                s.name, s.lag
            ));
        }
    }
    if warnings.is_empty() {
        return check("export", Status::Pass, "the export streams are delivering");
    }
    check("export", Status::Warn, warnings.join("; ")).hint(
        "`kronik export status` shows each sink's last error; the audit hold gives way below [audit] hold_release free disk and records a gap",
    )
}

#[cfg(test)]
mod tests {
    /// M24 §5.11: the open-file limit against `[connections] max_open`.
    #[test]
    fn connections_room() {
        let config = Config::default();
        let ok = super::connections(&config, 65_536);
        assert!(matches!(ok.status, Status::Pass), "{ok:?}");
        let low = super::connections(&config, 1024);
        assert!(matches!(low.status, Status::Warn), "{low:?}");
        assert_eq!(low.code, Some("CONNECTION_LIMIT"));
        assert!(low.hint.is_some());
    }

    use super::*;

    #[test]
    fn an_inaccessible_dev_kvm_fails_only_when_the_configuration_asks_for_kvm() {
        let denied = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        for platform in [Platform::Auto, Platform::Systrap] {
            let c = kvm(platform, denied());
            assert_eq!((c.status, c.code), (Status::Warn, Some("KVM_UNAVAILABLE")));
        }
        let c = kvm(Platform::Kvm, denied());
        assert_eq!((c.status, c.code), (Status::Fail, Some("KVM_UNAVAILABLE")));
        assert!(c.hint.unwrap().contains("kvm group"));
        let missing = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(
            !kvm(Platform::Kvm, missing)
                .hint
                .unwrap()
                .contains("kvm group")
        );
        assert_eq!(kvm(Platform::Kvm, Ok(())).status, Status::Pass);
    }

    fn show(state: &str, user: &str, pid: u32, subgroup: &str) -> String {
        format!("MainPID={pid}\nLoadState={state}\nUser={user}\nDelegateSubgroup={subgroup}\n")
    }

    #[test]
    fn only_a_loaded_root_unit_is_looked_at() {
        let running = Some((7, "/system.slice/kronik.service".to_owned()));
        // The nonroot unit has User=; a unit that is not installed is not there.
        assert_eq!(
            root_unit_from(&show("loaded", "kronik", 7, ""), running.clone()),
            None
        );
        assert_eq!(root_unit_from(&show("not-found", "", 0, ""), None), None);
        assert_eq!(
            root_unit_from(&show("loaded", "", 7, ""), running.clone()),
            Some(RootUnit::Running {
                pid: 7,
                cgroup: "/system.slice/kronik.service".into()
            })
        );
        // Not running: the property tells; systemd before 254 has none.
        assert_eq!(
            root_unit_from(&show("loaded", "", 0, "daemon"), None),
            Some(RootUnit::Stopped { leaf: true })
        );
        assert_eq!(
            root_unit_from(&show("loaded", "", 0, ""), None),
            Some(RootUnit::Stopped { leaf: false })
        );
        assert_eq!(root_unit_from("LoadState=loaded\nMainPID=0\n", None), None);
        assert_eq!(main_pid("MainPID=4242\nUser=\n"), Some(4242));
    }

    #[test]
    fn microvm_actors_need_the_leaf_and_the_doctor_says_how_to_add_it() {
        let running = |cgroup: &str| RootUnit::Running {
            pid: 9,
            cgroup: cgroup.into(),
        };
        // Nothing to say without a tool bundle or without a root service.
        assert!(microvm_leaf(false, Some(running("/x"))).is_none());
        assert!(microvm_leaf(true, None).is_none());
        let c = microvm_leaf(true, Some(running("/system.slice/kronik.service/daemon"))).unwrap();
        assert_eq!((c.name, c.status), ("microvm", Status::Pass));
        for unit in [
            running("/system.slice/kronik.service"),
            RootUnit::Stopped { leaf: false },
        ] {
            let c = microvm_leaf(true, Some(unit)).unwrap();
            assert_eq!(
                (c.name, c.status, c.code),
                ("microvm", Status::Warn, Some("FOREIGN_UNAVAILABLE"))
            );
            assert!(
                c.message.starts_with("microVM actors need"),
                "{}",
                c.message
            );
            let hint = c.hint.unwrap();
            assert!(
                hint.contains("DelegateSubgroup=daemon") && hint.contains("254"),
                "{hint}"
            );
        }
        let c = microvm_leaf(true, Some(RootUnit::Stopped { leaf: true })).unwrap();
        assert_eq!(c.status, Status::Pass);
    }

    #[test]
    fn parses_what_the_host_reports() {
        assert_eq!(kernel_version("6.12.38+deb13-amd64"), Some((6, 12)));
        assert_eq!(kernel_version("5.4.0-150-generic"), Some((5, 4)));
        assert_eq!(kernel_version(""), None);
        assert_eq!(
            runsc_release("runsc version release-20261019.0\nspec: 1.2.1"),
            Some("release-20261019.0")
        );
        assert_eq!(runsc_release("runsc version dev"), None);
        assert!("release-20261019.0" >= TESTED_RUNSC && "release-20250101.0" < TESTED_RUNSC);
        assert_eq!(
            endpoint_authority("https://s3.example.com"),
            Some("s3.example.com:443".into())
        );
        assert_eq!(
            endpoint_authority("http://minio:9000/bucket"),
            Some("minio:9000".into())
        );
        assert_eq!(endpoint_authority("s3.example.com"), None);
        assert_eq!(endpoint_authority("s3://bucket/kronik"), None);
        assert_eq!(endpoint_authority("ftp://files.example"), None);
    }

    #[test]
    fn the_dns01_hook_must_be_an_executable_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        assert!(dns01_hook(&config).is_none());
        let hook = dir.path().join("hook");
        config.tls.dns01_hook = Some(hook.clone());
        assert_i12(&dns01_hook(&config).unwrap(), "BAD_REQUEST");
        std::fs::write(&hook, "#!/bin/sh\n").unwrap();
        assert_i12(&dns01_hook(&config).unwrap(), "BAD_REQUEST");
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(dns01_hook(&config).unwrap().status, Status::Pass);
    }

    #[test]
    fn doctor_checks_the_wildcard_certificate_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.data_dir = dir.path().to_path_buf();
        config.gateway.preview_domain = Some("p.example".into());
        assert!(wildcard_certificate(&config).is_none());
        config.tls.dns01_hook = Some(dir.path().join("hook"));
        assert_eq!(wildcard_certificate(&config).unwrap().status, Status::Warn);
        let ca = dir.path().join("tls/acme/ca");
        std::fs::create_dir_all(&ca).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut expired = rcgen::CertificateParams::new(vec!["*.p.example".into()]).unwrap();
        expired.not_before = rcgen::date_time_ymd(2019, 1, 1);
        expired.not_after = rcgen::date_time_ymd(2020, 1, 1);
        let pem = expired.self_signed(&key).unwrap().pem() + &key.serialize_pem();
        std::fs::write(ca.join("wildcard.p.example.pem"), pem).unwrap();
        let c = wildcard_certificate(&config).unwrap();
        assert_eq!(
            (c.name, c.status, c.code),
            ("dns01_hook", Status::Fail, Some("CERTIFICATE_INVALID")),
            "{}",
            c.message
        );
        assert_i12(&c, "CERTIFICATE_INVALID");
    }

    /// I12: a failure the printer and `--json` both show has a catalog code
    /// and a non-empty hint. Passing rows may still omit a hint.
    #[test]
    fn failed_checks_carry_a_code_and_a_hint() {
        let (chain, key) = expired_pem();
        let expired = certificate_check("cert.pem", chain.as_bytes(), key.as_bytes());
        assert!(expired.message.contains("expired"), "{}", expired.message);
        assert_i12(&expired, "CERTIFICATE_INVALID");

        let garbage = certificate_check("cert.pem", b"not-pem", b"not-pem");
        assert_i12(&garbage, "CERTIFICATE_INVALID");

        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.tls.mode = TlsMode::Files;
        config.tls.cert_file = Some(dir.path().join("missing.pem"));
        config.tls.key_file = Some(dir.path().join("missing-key.pem"));
        let unread_cert = tls(&config);
        assert!(
            unread_cert.message.contains("missing.pem"),
            "{}",
            unread_cert.message
        );
        assert_i12(&unread_cert, "CERTIFICATE_INVALID");
        std::fs::write(dir.path().join("cert.pem"), &chain).unwrap();
        config.tls.cert_file = Some(dir.path().join("cert.pem"));
        let unread_key = tls(&config);
        assert!(
            unread_key.message.contains("missing-key.pem"),
            "{}",
            unread_key.message
        );
        assert_i12(&unread_key, "CERTIFICATE_INVALID");

        config.tls.mode = TlsMode::Off;
        config.ship.enabled = true;
        config.ship.endpoint = Some("s3.example.com".into());
        let bad_endpoint = ship(&config);
        assert!(
            bad_endpoint.message.contains("http(s)"),
            "{}",
            bad_endpoint.message
        );
        assert_i12(&bad_endpoint, "BAD_REQUEST");
        config.ship.endpoint = Some("s3://bucket/kronik".into());
        assert_i12(&ship(&config), "BAD_REQUEST");

        // A pass may omit the hint. The printed sample does the same.
        let passed = check("kernel", Status::Pass, "Linux 6.12");
        assert!(passed.hint.is_none());
        assert!(!format_check(&passed).contains("hint:"));
    }

    /// `sudo kronik doctor --rootless` becomes the service user with the groups
    /// the service manager would give the unit: the user's memberships and the
    /// unit's SupplementaryGroups=, by name or by number, never group 0.
    #[test]
    fn the_service_identity_takes_the_units_groups() {
        let group_file = "root:x:0:\nkvm:x:993:\nkronik:x:998:\ndocker:x:990:kronik,alice\n\
                          video:x:44:alice\nwheel:x:10:kronik\nbroken\nodd:x:nan:kronik\n";
        assert_eq!(groups_of(group_file, "kronik", 998, ""), [10, 990]);
        // The managed KVM drop-in's numeric group, a name, an unknown name and root.
        assert_eq!(
            groups_of(group_file, "kronik", 998, "993 video nosuch 0\n"),
            [10, 44, 990, 993]
        );
        // The user's own group is the primary one, not a supplementary one.
        assert_eq!(
            groups_of(group_file, "kronik", 998, "kronik 998"),
            [10, 990]
        );
        assert!(groups_of("", "kronik", 998, "").is_empty());
        assert!(groups_of(group_file, "nobody", 998, "").is_empty());
    }

    /// The `root` row names the identity the checks ran as. With `--rootless`
    /// that is the service's host user, root of a user namespace, or host root,
    /// which only warns: the checks then see more than the service will.
    #[test]
    fn the_root_row_names_the_identity_the_checks_ran_as() {
        let row = |euid, initial, rootless| {
            let c = root_identity(euid, initial, rootless);
            (c.status, c.message)
        };
        assert_eq!(row(0, true, false).0, Status::Pass);
        assert_eq!(row(1000, true, false).0, Status::Warn);
        let (status, message) = row(0, true, true);
        assert_eq!(status, Status::Warn);
        assert!(message.contains("host root"), "{message}");
        let (status, message) = row(0, false, true);
        assert_eq!(status, Status::Pass);
        assert!(message.contains("user namespace"), "{message}");
        let (status, message) = row(998, true, true);
        assert_eq!(status, Status::Pass);
        assert!(message.contains("host uid 998"), "{message}");
    }

    /// `sudo kronik doctor --rootless` checks the key source as root, before
    /// it becomes the service user, and over a data directory that another
    /// user owns it reads the key alone: stores that the key would not open
    /// are the service's to check when it starts, and are not opened here.
    #[test]
    fn the_key_check_before_the_drop_reads_the_key_and_no_store() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(data.join("keys")).unwrap();
        // Not a database: the full check, which opens the stores, fails on it.
        std::fs::write(data.join("keys/secrets.db"), b"not a database").unwrap();
        let key = dir.path().join("master.key");
        std::fs::write(&key, "11".repeat(32)).unwrap();
        let mut config = Config::default();
        config.server.data_dir = data;
        config.server.api_socket = dir.path().join("no-daemon.sock");
        config.keys.master_key_file = Some(key);
        let only = key_source_checked(&config, KeyCheck::MasterOnly);
        assert_eq!(only.status, Status::Pass, "{}", only.message);
        assert!(
            only.message.contains("checks its stores"),
            "{}",
            only.message
        );
        let full = key_source_checked(&config, KeyCheck::Full);
        assert_eq!(full.status, Status::Fail, "{}", full.message);
        assert!(full.code.is_some() && full.hint.is_some(), "{full:?}");
    }

    fn expired_pem() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut expired = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        expired.not_before = rcgen::date_time_ymd(2019, 1, 1);
        expired.not_after = rcgen::date_time_ymd(2020, 1, 1);
        (
            expired.self_signed(&key).unwrap().pem(),
            key.serialize_pem(),
        )
    }

    /// Human output and `--json` both include the code and the hint.
    fn assert_i12(c: &Check, code: &str) {
        assert_eq!(c.status, Status::Fail, "{}", c.message);
        assert_eq!(c.code, Some(code), "{}", c.message);
        assert!(
            ErrorCode::parse(code).is_some(),
            "{code} is not a catalog code"
        );
        let hint = c
            .hint
            .as_deref()
            .unwrap_or_else(|| panic!("no hint: {c:?}"));
        assert!(!hint.is_empty() && !hint.contains('\n'), "{hint}");
        let text = format_check(c);
        assert!(
            text.starts_with("  FAIL  ") && text.contains(&format!("({code})")),
            "{text}"
        );
        assert!(
            text.contains(&format!("\n                hint: {hint}")),
            "{text}"
        );
        let json = serde_json::to_value(c).unwrap();
        assert_eq!(json["code"], code, "{json}");
        assert_eq!(json["hint"], hint, "{json}");
    }

    /// ADR 0027's measured values: the shipped unit with `User=root`
    /// (`CapPrm` without bit 7) and the unit without `User=`.
    #[test]
    fn cap_setuid_comes_from_cap_prm() {
        let status =
            |prm: &str| format!("Name:\tkronik\nCapInh:\t0000000000000000\nCapPrm:\t{prm}\n");
        assert_eq!(has_cap_setuid(&status("000001f3fdfeffff")), Some(true));
        assert_eq!(has_cap_setuid(&status("000001f3fdfeff7f")), Some(false));
        assert_eq!(has_cap_setuid("Name:\tkronik\n"), None);
        assert_eq!(has_cap_setuid(&status("zz")), None);
    }

    /// The ADR 0027 trap is looked for in a root unit only: a nonroot unit
    /// has no host capability by design, and no unit means this process.
    #[test]
    fn caps_looks_at_a_root_unit_and_ignores_a_nonroot_one() {
        let status = |uid: u32, prm: &str| {
            format!("Name:\tkronik\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nCapPrm:\t{prm}\n")
        };
        // The root unit that lost CAP_SETUID (User=root with a seccomp setting).
        let lost = status(0, "000001f3fdfeff7f");
        assert_eq!(caps_subject(Some((42, &lost))), CapsSubject::RootUnit(42));
        assert_eq!(has_cap_setuid(&lost), Some(false));
        let root = status(0, "000001f3fdfeffff");
        assert_eq!(caps_subject(Some((7, &root))), CapsSubject::RootUnit(7));
        // The nonroot unit holds no host capability, whatever its CapPrm says.
        let nonroot = status(998, "0000000000000000");
        assert_eq!(caps_subject(Some((9, &nonroot))), CapsSubject::Process);
        assert_eq!(effective_uid(&nonroot), Some(998));
        // Only the effective uid counts: a unit that is root in real uid only.
        let mixed = "Uid:\t0\t998\t998\t998\n";
        assert_eq!(effective_uid(mixed), Some(998));
        assert_eq!(caps_subject(Some((9, mixed))), CapsSubject::Process);
        // The doctor process itself is the trap too, as in v0.4.0, unless
        // `--rootless` runs it as an ordinary user in the service's namespace.
        for (root, rootless, trap) in [
            (true, false, true),
            (false, false, true),
            (true, true, true),
            (false, true, false),
        ] {
            assert_eq!(caps_is_trap(&CapsSubject::Process, root, rootless), trap);
        }
        assert!(caps_is_trap(&CapsSubject::RootUnit(1), false, true));
        // No unit, or a status that cannot be read as one.
        assert_eq!(caps_subject(None), CapsSubject::Process);
        assert_eq!(
            caps_subject(Some((1, "Name:\tkronik\n"))),
            CapsSubject::Process
        );
    }

    #[test]
    fn an_open_turn_that_keeps_the_log_warns() {
        use kronik_api::types::RetentionPinView;
        let now = 10_000_000;
        let c = retention_pin(None, now);
        assert_eq!(c.status, Status::Pass, "{}", c.message);
        let mut pin = RetentionPinView {
            execution_id: "e1".into(),
            source: "live".into(),
            actor: Some("billing/acme".into()),
            begin_lsn: Some(1482),
            snapshot: None,
            segment: 1400,
            held_segments: 3,
            held_bytes: 3 << 20,
            since_ms: now - 2 * 3_600_000,
        };
        let c = retention_pin(Some(&pin), now);
        assert_eq!(c.status, Status::Warn);
        assert!(
            c.message
                .contains("turn e1 of billing/acme is open since lsn 1482")
                && c.message.contains("keeps 3 log segments")
                && c.message.contains("for 2h now"),
            "{}",
            c.message
        );
        pin.source = "snapshot".into();
        pin.actor = None;
        pin.begin_lsn = None;
        pin.snapshot = Some("main-00000000000000001500".into());
        let c = retention_pin(Some(&pin), now);
        assert_eq!(c.status, Status::Warn);
        assert!(
            c.message
                .contains("snapshot main-00000000000000001500 holds turn e1 open"),
            "{}",
            c.message
        );
    }

    #[test]
    fn a_failing_backend_and_an_uncached_name_warn() {
        use kronik_api::types::SecretBackendView;
        let view = |id: &str, kind: &str| SecretBackendView {
            id: id.into(),
            kind: kind.into(),
            binding: "b".into(),
            configured: true,
            inventory_complete: true,
            last_success_ms: None,
            last_error_ms: None,
            last_error: None,
            uncached: Vec::new(),
        };
        let now = 10_000_000;
        let c = secret_backends(&[view("file", "file")], now);
        assert_eq!((c.status, c.code), (Status::Pass, None));
        let mut bao = view("bao", "openbao");
        bao.last_success_ms = Some(now - 60_000);
        let c = secret_backends(&[view("file", "file"), bao.clone()], now);
        assert_eq!(c.status, Status::Pass, "{}", c.message);
        // An error after the last success, and a name with no cached value.
        bao.last_error_ms = Some(now - 5_000);
        bao.last_error = Some("unavailable".into());
        bao.uncached = vec!["stripe".into()];
        let c = secret_backends(&[bao.clone()], now);
        assert_eq!(
            (c.status, c.code),
            (Status::Warn, Some("SECRET_UNAVAILABLE"))
        );
        assert!(
            c.message
                .contains("bao: the last request failed (unavailable) 5s ago"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("its last answer was 1m ago"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("no cached value of stripe"),
            "{}",
            c.message
        );
        assert!(c.hint.is_some());
        // An error that a later answer superseded is history.
        bao.last_success_ms = Some(now - 1_000);
        bao.uncached.clear();
        assert_eq!(secret_backends(&[bao], now).status, Status::Pass);
    }

    #[test]
    fn a_stalled_export_and_an_old_audit_hold_warn() {
        let stream = |name: &str, stalled_ms: Option<u64>| kronik_api::types::ExportStream {
            name: name.into(),
            enabled: true,
            sink: "file://".into(),
            cursor: 1,
            applied_lsn: 9,
            lag: 8,
            last_success_wall_ms: None,
            stalled_ms,
            last_error: None,
            gaps: 0,
        };
        let config = Config::default();
        let ok = export_streams(
            &config,
            &[stream("traces", Some(1_000)), stream("audit", None)],
        );
        assert_eq!(ok.status, Status::Pass, "{}", ok.message);
        // traces: 10 × 5 s.
        let stale = export_streams(&config, &[stream("traces", Some(51_000))]);
        assert_eq!(stale.status, Status::Warn);
        assert!(
            stale.message.contains("traces export has not delivered"),
            "{}",
            stale.message
        );
        // audit: 10 × 1 s, then past the 7-day history.
        let stale = export_streams(&config, &[stream("audit", Some(11_000))]);
        assert!(
            stale.message.contains("audit export has not delivered"),
            "{}",
            stale.message
        );
        let held = export_streams(&config, &[stream("audit", Some(8 * 86_400_000))]);
        assert_eq!(held.status, Status::Warn);
        assert!(held.message.contains("held retention"), "{}", held.message);
    }
}
