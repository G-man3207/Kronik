//! `kronik doctor`: what this host can run (SPEC.md, "The finished product",
//! step 1; ADR 0003 for gVisor). Needs no daemon: it reads the configuration
//! and looks at the host. Each check passes, warns or fails, with a hint.
//! Foreign actors are optional (I10), so the checks of what only they need
//! (`runsc`, `kvm`, `cgroup`, `runc`, `netns`, `run_dir`, `sandbox`) warn
//! unless the configuration asks for what is missing: with `[foreign]
//! platform = "kvm"`, `kvm` and `sandbox` fail. A new network namespace with
//! more than `lo` fails too: foreign actors would run without their network
//! isolation.
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

use crate::config::{Config, Platform, TlsMode};

/// The gVisor release Kronik is tested with (ADR 0003).
const TESTED_RUNSC: &str = "release-20261019.0";

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// The configuration file [default: /etc/kronik/kronik.toml if it exists].
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
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
    /// Stable: config, kernel, runsc, kvm, cgroup, root, disk, clock, tls,
    /// dns01_hook, ship.
    name: &'static str,
    status: Status,
    /// An error code from the catalog, when one applies.
    code: Option<&'static str>,
    message: String,
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
            checks.push(
                check("config", Status::Fail, e.to_string())
                    .code("BAD_REQUEST")
                    .hint("fix the file; the other checks use the defaults"),
            );
            Config::default()
        }
    };
    checks.push(kernel());
    checks.push(runsc(&config.foreign.runsc_path));
    let dev_kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm");
    checks.push(kvm(config.foreign.platform, dev_kvm.map(drop)));
    checks.push(cgroup());
    checks.push(root());
    checks.push(runc());
    checks.push(netns());
    checks.push(run_dir(&config.foreign.run_dir));
    checks.push(caps(&config.foreign.runsc_path));
    checks.push(sandbox(&config.foreign.runsc_path, config.foreign.platform));
    checks.push(disk(&config.server.data_dir));
    checks.push(clock());
    checks.push(tls(&config));
    checks.extend(dns01_hook(&config));
    checks.extend(wildcard_certificate(&config));
    checks.push(ship(&config));
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
            let status = match c.status {
                Status::Pass => "pass",
                Status::Warn => "warn",
                Status::Fail => "FAIL",
            };
            let code = c.code.map(|code| format!(" ({code})")).unwrap_or_default();
            println!("  {status}  {:<7} {}{code}", c.name, c.message);
            if let Some(hint) = &c.hint {
                println!("        {:<7} hint: {hint}", "");
            }
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
            "/dev/kvm is usable: platforms kvm and systrap",
        ),
        (Err(e), Platform::Kvm) => {
            let mut hint =
                "[foreign] platform = \"kvm\" needs /dev/kvm; set platform = \"auto\" or \"systrap\"".to_owned();
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                hint.push_str(", or give this user access to /dev/kvm (the kvm group)");
            }
            check("kvm", Status::Fail, format!("/dev/kvm: {e}"))
                .code("KVM_UNAVAILABLE")
                .hint(hint)
        }
        (Err(e), _) => check(
            "kvm",
            Status::Warn,
            format!("/dev/kvm: {e}; platform systrap only"),
        )
        .code("KVM_UNAVAILABLE")
        .hint("fine for most hosts: foreign actors use systrap without KVM"),
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

fn root() -> Check {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::metadata("/proc/self").map(|m| m.uid()) {
        Ok(0) => check(
            "root",
            Status::Pass,
            "running as root, as the daemon does in v0.1",
        ),
        _ => check(
            "root",
            Status::Warn,
            "not running as root: some checks see less than the daemon will",
        )
        .hint("sudo kronik doctor"),
    }
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
        Ok(ifaces) => check(
            "netns",
            Status::Fail,
            format!("a new namespace has {ifaces:?}, not only lo"),
        )
        .code("FOREIGN_UNAVAILABLE"),
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

/// runsc's gofer needs `CAP_SETUID`. systemd drops it from a unit with an
/// explicit `User=` and a seccomp-based setting, and `NoNewPrivileges`
/// keeps runsc from getting it back (ADR 0027). Looks at the running
/// kronik.service's process if there is one, else at this process.
fn caps(runsc: &Path) -> Check {
    if !is_executable(runsc) {
        return check("caps", Status::Warn, "skipped: no runsc").code("RUNSC_MISSING");
    }
    let pid = Command::new("systemctl")
        .args(["show", "--property=MainPID", "--value", "kronik.service"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&pid| pid != 0);
    let (who, path) = match pid {
        Some(pid) => (
            format!("kronik.service (pid {pid})"),
            format!("/proc/{pid}/status"),
        ),
        None => ("this process".to_owned(), "/proc/self/status".to_owned()),
    };
    match std::fs::read_to_string(&path).ok().as_deref().and_then(has_cap_setuid) {
        Some(true) => check(
            "caps",
            Status::Pass,
            format!("{who} has CAP_SETUID, which runsc needs"),
        ),
        Some(false) => check(
            "caps",
            Status::Fail,
            format!("{who} lacks CAP_SETUID: no foreign actor can start (runsc's gofer fails with EPERM)"),
        )
        .hint(
            "remove User= from kronik.service and its drop-ins; with it, systemd drops CAP_SETUID \
             under the unit's seccomp settings (docs/adr/0027-systemd-unit-hardening.md)",
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
        Some(free) if free < GIB => check(
            "disk",
            Status::Fail,
            format!(
                "{:.1} GiB free for {}",
                free as f64 / GIB as f64,
                data_dir.display()
            ),
        )
        .hint("the log and snapshots need room: free space or move server.data_dir"),
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
            d if d < 0 => check(
                "tls",
                Status::Fail,
                format!("{source}: the certificate has expired"),
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
        Err(e) => check("tls", Status::Fail, format!("{source}: {e}")),
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
                (Err(e), _) => check("tls", Status::Fail, format!("{}: {e}", cert.display())),
                (_, Err(e)) => check("tls", Status::Fail, format!("{}: {e}", key.display())),
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
        Ok(_) => check(
            "dns01_hook",
            Status::Fail,
            format!(
                "{}: the DNS-01 hook is not an executable file",
                hook.display()
            ),
        )
        .hint(hint),
        Err(e) => check(
            "dns01_hook",
            Status::Fail,
            format!("{}: {e}", hook.display()),
        )
        .hint(hint),
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

/// `host:port` of an `https://` or `http://` endpoint.
fn endpoint_authority(endpoint: &str) -> Option<String> {
    let (scheme, rest) = endpoint.split_once("://")?;
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
        return check(
            "ship",
            Status::Fail,
            format!("[ship] endpoint {endpoint:?} is not an http(s) URL"),
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
        None => check("ship", Status::Fail, format!("{endpoint} is not reachable")).hint(
            "check the endpoint, DNS and the firewall; snapshots cannot ship until it answers",
        ),
    }
}

#[cfg(test)]
mod tests {
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
    }

    #[test]
    fn the_dns01_hook_must_be_an_executable_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        assert!(dns01_hook(&config).is_none());
        let hook = dir.path().join("hook");
        config.tls.dns01_hook = Some(hook.clone());
        assert_eq!(dns01_hook(&config).unwrap().status, Status::Fail);
        std::fs::write(&hook, "#!/bin/sh\n").unwrap();
        assert_eq!(dns01_hook(&config).unwrap().status, Status::Fail);
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
            (c.name, c.status),
            ("dns01_hook", Status::Fail),
            "{}",
            c.message
        );
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
}
