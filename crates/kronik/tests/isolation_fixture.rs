//! Explicit non-shipped, one-thread installed product proof. No generic path/env bypass.
//! create PARENT PRODUCT PROBE_LAYOUT PG_LAYOUT PAYMENTS_LAYOUT UID GID SUBID OPERATOR_UID
//! init ROOT [root|rootless|dry-run]; cleanup ROOT.
//! Init contains the real unit-consuming PID1 manager in one exact transient parent.
//! control ROOT accepts only owned unit operations; manager/host-pid are fixed fixture seams.
#![allow(
    dead_code,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used
)]

#[path = "../src/cli/http.rs"]
pub(crate) mod cli_http;
#[path = "../src/config.rs"]
mod config;
#[path = "../src/init.rs"]
mod init;
mod cli {
    pub(crate) use crate::cli_http as http;
    pub fn report_error(_: bool, error: &kronik_core::error::ApiError) -> std::process::ExitCode {
        eprintln!("{error:?}");
        std::process::ExitCode::FAILURE
    }
}

use anyhow::{Context as _, bail, ensure};
use kronik_foreign::{
    subid::{COUNT, Range},
    sys,
};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, chown};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

type Result<T, E = anyhow::Error> = std::result::Result<T, E>;

const FIXTURE_HELPER: &str = "/usr/local/bin/kronik-isolation-fixture";

fn command(argv: &[&str]) -> Result<String> {
    let mut output = tempfile::tempfile().context("opening owned command stdout capture")?;
    let mut errors = tempfile::tempfile().context("opening owned command stderr capture")?;
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .stdout(output.try_clone()?)
        .stderr(errors.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.try_wait()? {
            use std::io::{Seek as _, SeekFrom};
            output.seek(SeekFrom::Start(0))?;
            errors.seek(SeekFrom::Start(0))?;
            let mut out = String::new();
            let mut err = String::new();
            output.take(8 * 1024 * 1024).read_to_string(&mut out)?;
            errors.take(8 * 1024 * 1024).read_to_string(&mut err)?;
            ensure!(status.success(), "{argv:?}: {err}");
            return Ok(out);
        }
        if Instant::now() >= deadline
            || output.metadata()?.len() + errors.metadata()?.len() > 8 * 1024 * 1024
        {
            child.kill()?;
            child.wait()?;
            bail!("command deadline/output limit: {argv:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn save(path: &Path, value: &Value) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(serde_json::to_string_pretty(value)?.as_bytes())?;
    file.sync_all()?;
    fs::File::open(path.parent().context("parent")?)?.sync_all()?;
    Ok(())
}

fn context(root: &Path) -> Result<Value> {
    ensure!(sys::is_root(), "owned setup authority is required");
    let md = fs::symlink_metadata(root)?;
    ensure!(
        md.is_dir() && md.uid() == 0 && md.mode() & 0o777 == 0o700,
        "private root-owned fixture required: {} uid={} mode={:o}",
        root.display(),
        md.uid(),
        md.mode() & 0o7777
    );
    let manifest = root.join("fixture.json");
    let record = fs::symlink_metadata(&manifest)?;
    ensure!(
        record.is_file() && record.uid() == 0 && record.mode() & 0o777 == 0o600,
        "invalid fixture manifest ownership"
    );
    let cfg: Value = serde_json::from_slice(&fs::read(manifest)?)?;
    ensure!(
        cfg["version"] == "kronik.isolation-fixture/v1"
            && cfg["root_identity"] == json!([md.dev(), md.ino()]),
        "fixture identity mismatch"
    );
    let token = cfg["token"].as_str().context("token")?;
    ensure!(
        token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid fixture token"
    );
    ensure!(
        cfg["unit"] == format!("kronik-proof-{token}.service"),
        "unowned unit target"
    );
    ensure!(
        cfg["manager_unit"] == format!("kronik-proof-{token}-manager.service"),
        "unowned manager target"
    );
    for key in ["data", "run", "etc", "socket"] {
        ensure!(
            Path::new(cfg[key].as_str().context("fixture path")?).starts_with(root),
            "fixture path escapes root"
        );
    }
    Ok(cfg)
}

fn number(cfg: &Value, field: &str) -> Result<u32> {
    u32::try_from(cfg[field].as_u64().context("numeric field")?)
        .context("numeric identity overflow")
}
fn text<'a>(cfg: &'a Value, key: &str) -> Result<&'a str> {
    cfg[key].as_str().context("string field")
}

fn process_start(pid: u32) -> Result<u64> {
    fs::read_to_string(format!("/proc/{pid}/stat"))?
        .rsplit_once(')')
        .and_then(|(_, words)| words.split_whitespace().nth(19))
        .context("process start time")?
        .parse()
        .context("invalid process start time")
}

fn parent_gone(state: &str) -> bool {
    [
        "MainPID=0",
        "InvocationID=",
        "LoadState=not-found",
        "ActiveState=inactive",
        "ControlGroup=",
    ]
    .iter()
    .all(|property| state.lines().any(|line| line == *property))
}

fn host_parent(root: &Path, cfg: &Value, args: &[&str]) -> Result<String> {
    let parent = text(cfg, "manager_unit")?;
    ensure!(
        (args.first() == Some(&"show") || args.first() == Some(&"stop")) && args.contains(&parent),
        "host manager control is restricted to the exact owned parent"
    );
    if args[0] == "stop" {
        let receipt: Value = serde_json::from_slice(&fs::read(root.join("parent.json"))?)?;
        let raw = command(&[
            "nsenter",
            "--target",
            "1",
            "--mount",
            "--pid",
            "systemctl",
            "show",
            parent,
            "--property=MainPID,InvocationID,ActiveState,LoadState,ControlGroup",
            "--no-pager",
        ])?;
        let pid: u32 = raw
            .lines()
            .find_map(|s| s.strip_prefix("MainPID="))
            .context("parent PID")?
            .parse()?;
        let invocation = raw
            .lines()
            .find_map(|s| s.strip_prefix("InvocationID="))
            .context("parent invocation")?;
        if parent_gone(&raw) {
            return Ok(String::new());
        }
        ensure!(
            receipt["pid"] == pid
                && receipt["start_time"] == process_start(pid)?
                && receipt["invocation"] == invocation,
            "parent was replaced; refusing stop"
        );
    }
    let mut argv = vec!["nsenter", "--target", "1", "--mount", "--pid", "systemctl"];
    argv.extend_from_slice(args);
    command(&argv)
}

fn manager_process(root: &Path, cfg: &Value) -> Result<(u32, String)> {
    let record: Value = serde_json::from_slice(&fs::read(root.join("manager.json"))?)?;
    let raw = host_parent(
        root,
        cfg,
        &[
            "show",
            text(cfg, "manager_unit")?,
            "--property=ActiveState,ControlGroup,InvocationID",
            "--no-pager",
        ],
    )?;
    ensure!(
        raw.lines().any(|s| s == "ActiveState=active"),
        "owned manager parent is not active"
    );
    let receipt: Value = serde_json::from_slice(&fs::read(root.join("parent.json"))?)?;
    ensure!(
        raw.lines()
            .find_map(|s| s.strip_prefix("InvocationID="))
            .is_some_and(|id| receipt["invocation"] == id),
        "parent invocation changed"
    );
    let group = raw
        .lines()
        .find_map(|s| s.strip_prefix("ControlGroup="))
        .context("parent cgroup")?
        .to_string();
    let parent = text(cfg, "manager_unit")?;
    ensure!(
        Path::new(&group)
            .components()
            .any(|p| p.as_os_str() == parent),
        "unowned parent cgroup"
    );
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(ns) = fs::metadata(entry.path().join("ns/pid")) else {
            continue;
        };
        if record["pid_namespace"] != json!([ns.dev(), ns.ino()]) {
            continue;
        }
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if !status
            .lines()
            .find_map(|s| s.strip_prefix("NSpid:"))
            .is_some_and(|s| s.split_whitespace().last() == Some("1"))
        {
            continue;
        }
        ensure!(
            record["start_time"] == process_start(pid)?,
            "private manager PID was replaced"
        );
        let cg = fs::read_to_string(entry.path().join("cgroup"))?;
        let actual = cg
            .trim()
            .strip_prefix("0::")
            .context("unified manager cgroup")?;
        ensure!(
            actual == group || actual.starts_with(&format!("{group}/")),
            "manager escaped owned parent"
        );
        found.push(pid);
    }
    ensure!(found.len() == 1, "owned private PID1 is not unique");
    Ok((found[0], group))
}

/// The host id of the process of the private manager's PID namespace whose id
/// in that namespace is `inside`. Only the processes of that namespace are
/// translated: a process in a namespace of its own below it, such as a microVM's
/// VMM (init of the namespace its launcher made), is not found by its last
/// `NSpid` entry, which is its id in its own namespace. The VMM's launcher is.
fn host_pid(root: &Path, cfg: &Value, inside: u32) -> Result<u32> {
    if inside == 0 {
        return Ok(0);
    }
    let (manager, parent) = manager_process(root, cfg)?;
    let namespace = fs::metadata(format!("/proc/{manager}/ns/pid"))?;
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(ns) = fs::metadata(entry.path().join("ns/pid")) else {
            continue;
        };
        if (ns.dev(), ns.ino()) != (namespace.dev(), namespace.ino()) {
            continue;
        }
        let Ok(start) = process_start(pid) else {
            continue;
        };
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        if status
            .lines()
            .find_map(|s| s.strip_prefix("NSpid:"))
            .and_then(|s| s.split_whitespace().last())
            .and_then(|s| s.parse::<u32>().ok())
            != Some(inside)
        {
            continue;
        }
        let cg = fs::read_to_string(entry.path().join("cgroup"))?;
        let group = cg
            .trim()
            .strip_prefix("0::")
            .context("unified child cgroup")?;
        ensure!(
            group == parent || group.starts_with(&format!("{parent}/")),
            "translated process escaped parent"
        );
        ensure!(
            process_start(pid)? == start,
            "process changed during PID translation"
        );
        save(
            &root.join(format!("pid-{pid}.json")),
            &json!({"host":pid,"inside":inside,"start_time":start,
            "pid_namespace":[ns.dev(),ns.ino()],"parent_cgroup":parent}),
        )?;
        found.push(pid);
    }
    ensure!(
        found.len() == 1,
        "private-manager process PID is not unique"
    );
    Ok(found[0])
}

fn control(root: &Path, cfg: &Value, args: &[String]) -> Result<String> {
    ensure!(!args.is_empty(), "private manager operation required");
    let unit = text(cfg, "unit")?;
    let pin = format!("{}-pin.service", unit.trim_end_matches(".service"));
    let owned = |s: &str| s == unit || s == pin;
    let valid = match args[0].as_str() {
        "daemon-reload" => args.len() == 1,
        "start" | "stop" | "restart" => args.len() > 1 && args[1..].iter().all(|s| owned(s)),
        "enable" => {
            args.len() == 4 && args[1] == "--runtime" && args[2] == "--now" && args[3] == unit
        }
        "show" => {
            args[1..].iter().any(|s| owned(s))
                && args[1..].iter().all(|s| {
                    owned(s)
                        || [
                            "--property",
                            "MainPID",
                            "--property=MainPID",
                            "--property=ActiveState",
                            "--property=MainPID,ControlGroup,ActiveState",
                            "--property=LoadState,ActiveState,MainPID",
                            "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,StatusErrno,StatusText,LoadCredential",
                            "--value",
                            "--no-pager",
                        ]
                        .contains(&s.as_str())
                })
        }
        _ => false,
    };
    ensure!(valid, "unowned private-manager operation");
    let (manager, parent) = manager_process(root, cfg)?;
    let id = manager.to_string();
    let mut argv = vec![
        "nsenter",
        "--target",
        id.as_str(),
        "--mount",
        "--pid",
        "systemctl",
    ];
    argv.extend(args.iter().map(String::as_str));
    let output = command(&argv)?;
    if args[0] != "show" {
        return Ok(output);
    }
    if args.iter().any(|s| s == "--value") {
        if args
            .iter()
            .any(|s| s == "MainPID" || s == "--property=MainPID")
        {
            return Ok(format!(
                "{}\n",
                host_pid(root, cfg, output.trim().parse()?)?
            ));
        }
        return Ok(output);
    }
    let mut translated = String::new();
    for line in output.lines() {
        if let Some(pid) = line.strip_prefix("MainPID=") {
            translated.push_str(&format!("MainPID={}\n", host_pid(root, cfg, pid.parse()?)?));
        } else if let Some(path) = line.strip_prefix("ControlGroup=") {
            translated.push_str(&format!(
                "ControlGroup={}{}\n",
                parent.trim_end_matches('/'),
                path
            ));
        } else {
            translated.push_str(line);
            translated.push('\n');
        }
    }
    Ok(translated)
}

fn ensure_manager(root: &Path, cfg: &Value) -> Result<()> {
    if root.join("manager.json").try_exists()? {
        manager_process(root, cfg)?;
        return Ok(());
    }
    let parent = text(cfg, "manager_unit")?;
    let write = format!("ReadWritePaths={}", root.display());
    let out = format!("StandardOutput=append:{}/manager.log", root.display());
    let err = format!("StandardError=append:{}/manager.log", root.display());
    let binds = format!(
        "BindPaths={}{}",
        root.display(),
        if root.join("microvm").is_dir() {
            " /dev/kvm"
        } else {
            ""
        }
    );
    // The owned /run bind survives the child's /tmp rebind; the original root pathname does not.
    let scratch = "TMPDIR=/run/kronik";
    let helper = text(cfg, "helper")?;
    let owned = root.to_str().context("fixture path")?;
    let mut argv = vec![
        "systemd-run",
        "--quiet",
        "--collect",
        "--service-type=exec",
        "--unit",
        parent,
        "--setenv",
        scratch,
        "--property=Delegate=yes",
        "--property=CPUQuota=200%",
        "--property=MemoryMax=2G",
        "--property=TasksMax=1024",
        "--property=RuntimeMaxSec=1800",
        "--property=TimeoutStopSec=10s",
        "--property=KillMode=control-group",
        "--property=ProtectSystem=strict",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=PrivateDevices=yes",
        "--property=ProtectHome=read-only",
        "--property=CapabilityBoundingSet=~CAP_SYS_TIME CAP_SYS_BOOT CAP_SYS_MODULE CAP_SYS_RAWIO CAP_MKNOD CAP_MAC_ADMIN CAP_MAC_OVERRIDE CAP_AUDIT_CONTROL CAP_NET_ADMIN",
        "--property",
        &write,
        "--property",
        &out,
        "--property",
        &err,
        "--property",
        &binds,
    ];
    if root.join("microvm").is_dir() {
        argv.push("--property=DeviceAllow=/dev/kvm rw");
    }
    argv.extend([
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "--pid",
        "--fork",
        "--mount-proc",
        "--kill-child=SIGKILL",
        "--uts",
        "--ipc",
        "--cgroup",
        helper,
        "manager",
        owned,
    ]);
    command(&argv)?;
    let raw = host_parent(
        root,
        cfg,
        &[
            "show",
            parent,
            "--property=MainPID,InvocationID,ControlGroup",
            "--no-pager",
        ],
    )?;
    let pid: u32 = raw
        .lines()
        .find_map(|s| s.strip_prefix("MainPID="))
        .context("parent PID")?
        .parse()?;
    let invocation = raw
        .lines()
        .find_map(|s| s.strip_prefix("InvocationID="))
        .context("parent invocation")?;
    let group = raw
        .lines()
        .find_map(|s| s.strip_prefix("ControlGroup="))
        .context("parent cgroup")?;
    ensure!(
        Path::new(group)
            .components()
            .any(|p| p.as_os_str() == parent),
        "parent cgroup escaped allocation"
    );
    let started = process_start(pid)?;
    save(
        &root.join("parent.json"),
        &json!({"pid":pid,"start_time":started,"invocation":invocation,"cgroup":group}),
    )?;
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{group}"),
        "manager launcher is not in the exact allocated parent"
    );
    // Keep the waiting unshare supervisor out of the domain root before PID1 delegates controllers.
    let supervisor = Path::new("/sys/fs/cgroup")
        .join(group.trim_start_matches('/'))
        .join("launcher.scope");
    fs::create_dir(&supervisor)?;
    fs::write(supervisor.join("cgroup.procs"), pid.to_string())?;
    ensure!(
        process_start(pid)? == started,
        "launcher changed during cgroup handoff"
    );
    save(
        &root.join("manager-continue.json"),
        &json!({"parent":parent,"supervisor":supervisor}),
    )?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !root.join("run/systemd/private").try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "private manager socket readiness timed out"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    manager_process(root, cfg)?;
    Ok(())
}

fn manager(root: &Path) -> Result<()> {
    ensure!(
        std::process::id() == 1,
        "private system manager requires child PID1"
    );
    private_setup(root)?;
    // Private scratch mounts must not hide the retained proof tree beneath /var/tmp.
    use std::os::fd::AsRawFd as _;
    let retained = fs::File::open(root)?;
    let source = format!("/proc/1/fd/{}", retained.as_raw_fd());
    for path in ["/tmp", "/var/tmp", "/dev/shm"] {
        command(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "size=64m,mode=1777",
            "tmpfs",
            path,
        ])?;
    }
    fs::create_dir_all(root)?;
    command(&[
        "mount",
        // libmount canonicalization loses the retained inode beneath private scratch.
        "--no-canonicalize",
        "--bind",
        &source,
        root.to_str().context("root path")?,
    ])?;
    // Fresh cgroup2 is rooted at the delegated parent by the new cgroup namespace.
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == "0::/",
        "manager cgroup namespace is not rooted"
    );
    command(&["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])?;
    for path in [
        "/proc/sys",
        "/proc/sysrq-trigger",
        "/proc/irq",
        "/proc/bus",
        "/proc/fs",
    ] {
        command(&["mount", "--bind", path, path])?;
        command(&["mount", "-o", "remount,bind,ro", path])?;
    }
    let cfg = context(root)?;
    let mut namespaces = serde_json::Map::new();
    for name in ["mnt", "pid", "user", "cgroup", "uts", "ipc", "net"] {
        let md = fs::metadata(format!("/proc/self/ns/{name}"))?;
        let identity = json!([md.dev(), md.ino()]);
        ensure!(
            (identity == cfg["host_namespaces"][name]) == ["user", "net"].contains(&name),
            "manager's {name} namespace has the wrong authority boundary"
        );
        namespaces.insert(name.into(), identity);
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let bound = u64::from_str_radix(
        status
            .lines()
            .find_map(|s| s.strip_prefix("CapBnd:"))
            .context("manager capability bound")?
            .trim(),
        16,
    )?;
    for bit in [12, 16, 17, 22, 25, 27, 30, 32, 33] {
        ensure!(
            bound & (1u64 << bit) == 0,
            "manager retains forbidden host capability {bit}"
        );
    }
    ensure!(
        fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .any(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(4) == Some(&"/")
                    && fields
                        .get(5)
                        .is_some_and(|flags| flags.split(',').any(|flag| flag == "ro"))
            }),
        "manager host root is not a read-only mount view"
    );
    let namespace = fs::metadata("/proc/self/ns/pid")?;
    save(
        &root.join("manager.json"),
        &json!({"pid_namespace":[namespace.dev(),namespace.ino()],
        "start_time":process_start(1)?,"namespaces":namespaces,"capability_bound":format!("{bound:016x}")}),
    )?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !root.join("manager-continue.json").try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "owned supervisor cgroup handoff timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    use std::os::unix::process::CommandExt as _;
    let error = Command::new("/usr/lib/systemd/systemd")
        .args([
            "--system",
            "--unit=kronik-proof.target",
            "--log-target=console",
        ])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LANG", "C.UTF-8")
        .env("container", "kronik-proof")
        .env(
            "SYSTEMD_UNIT_PATH",
            format!("{}:/run/systemd/system", root.join("units").display()),
        )
        .env("SYSTEMD_GENERATOR_PATH", root.join("manager-empty"))
        .env(
            "SYSTEMD_ENVIRONMENT_GENERATOR_PATH",
            root.join("manager-empty"),
        )
        .exec();
    Err(error.into())
}

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    let md = fs::symlink_metadata(source)?;
    ensure!(
        !md.file_type().is_symlink(),
        "artifact tree must not contain symlinks"
    );
    if md.is_dir() {
        fs::create_dir(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        }
    } else {
        ensure!(md.is_file(), "artifact must contain regular files only");
        fs::copy(source, target)?;
    }
    Ok(())
}

fn validate_ids(uid: u32, gid: u32, start: u32, operator: u32) -> Result<()> {
    ensure!(
        uid > 0
            && gid > 0
            && operator > 0
            && operator != uid
            && start >= 100000
            && uid < start
            && gid < start,
        "unique nonroot IDs below the exact subordinate range required"
    );
    let end = start.checked_add(COUNT).context("subid overflow")?;
    ensure!(
        !(start..end).contains(&uid)
            && !(start..end).contains(&gid)
            && !(start..end).contains(&operator),
        "identity overlaps mapped range"
    );
    for (file, ids) in [
        ("/etc/passwd", vec![uid, operator]),
        ("/etc/group", vec![gid]),
    ] {
        for line in fs::read_to_string(file)?.lines() {
            if let Some(n) = line.split(':').nth(2).and_then(|n| n.parse::<u32>().ok()) {
                ensure!(
                    !ids.contains(&n) && !(start..end).contains(&n),
                    "identity already used in {file}"
                );
            }
        }
    }
    for file in ["/etc/subuid", "/etc/subgid"] {
        match fs::read_to_string(file) {
            Ok(contents) => {
                for line in contents.lines() {
                    let p: Vec<_> = line.split(':').collect();
                    if p.len() != 3 || line.trim().is_empty() {
                        continue;
                    }
                    let lo: u32 = p[1].parse()?;
                    let hi = lo
                        .checked_add(p[2].parse()?)
                        .context("existing subid overflow")?;
                    ensure!(
                        end <= lo || start >= hi,
                        "range already allocated in {file}"
                    );
                    ensure!(
                        ![uid, gid, operator].iter().any(|id| (lo..hi).contains(id)),
                        "identity lies in another account's range"
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn create(args: &[String]) -> Result<()> {
    let directory_only = args.len() == 11 && args[9] == "--directory-tools";
    ensure!(
        (9..=10).contains(&args.len()) || directory_only,
        "create PARENT PRODUCT PROBE_LAYOUT PG_LAYOUT PAYMENTS_LAYOUT UID GID SUBID OPERATOR_UID [MICROVM_DIR | --directory-tools TOOLS_DIR]"
    );
    ensure!(sys::is_root(), "setup requires root");
    let uid = args[5].parse()?;
    let gid = args[6].parse()?;
    let start = args[7].parse()?;
    let operator = args[8].parse()?;
    validate_ids(uid, gid, start, operator)?;
    let parent = Path::new(&args[0]).canonicalize()?;
    let root = tempfile::Builder::new()
        .prefix("kronik-proof-")
        .tempdir_in(parent)?
        .keep();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    eprintln!("retained owned proof: {}", root.display());
    let mut random = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let product = Path::new(&args[1]).canonicalize()?;
    let helper = std::env::current_exe()?.canonicalize()?;
    let product_metadata = product.metadata()?;
    ensure!(
        product_metadata.is_file() && product_metadata.mode() & 0o005 == 0o005,
        "fixture product must have ordinary installed read/execute permissions (0755)"
    );
    for dir in [
        "etc",
        "etc/kronik",
        "data",
        "run",
        "run/kronik",
        "run/kronik-userns",
        "run/systemd",
        "run/systemd/system",
        "ship",
        "units",
        "manager-empty",
    ] {
        fs::create_dir(root.join(dir))?;
        fs::set_permissions(root.join(dir), fs::Permissions::from_mode(0o755))?;
    }
    fs::write(root.join("etc/machine-id"), format!("{token}\n"))?;
    fs::write(root.join("run/systemd/container"), "kronik-proof\n")?;
    for name in [
        "kronik-proof.target",
        "basic.target",
        "sysinit.target",
        "sockets.target",
        "timers.target",
        "paths.target",
        "network-online.target",
        "multi-user.target",
        "shutdown.target",
    ] {
        fs::write(
            root.join("units").join(name),
            "[Unit]\nDescription=Owned fixture target\nDefaultDependencies=no\n",
        )?;
    }
    fs::write(
        root.join("etc/passwd"),
        format!(
            "root:x:0:0:root:/root:/bin/false\nkronik:x:{uid}:{gid}:proof:/var/lib/kronik:/bin/false\n"
        ),
    )?;
    fs::write(
        root.join("etc/group"),
        format!("root:x:0:\nkronik:x:{gid}:\n"),
    )?;
    fs::write(root.join("etc/subuid"), "")?;
    fs::write(root.join("etc/subgid"), "")?;
    // Production usermod performs real shadow locking, solely in this private /etc.
    let last = start.checked_add(COUNT - 1).context("subid overflow")?;
    fs::write(
        root.join("etc/login.defs"),
        format!(
            "SUB_UID_MIN {start}\nSUB_UID_MAX {last}\nSUB_UID_COUNT {COUNT}\nSUB_GID_MIN {start}\nSUB_GID_MAX {last}\nSUB_GID_COUNT {COUNT}\n"
        ),
    )?;
    fs::write(
        root.join("etc/nsswitch.conf"),
        "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n",
    )?;
    fs::write(root.join("data/.kronik-proof-owner"), &token)?;
    fs::write(root.join("data/.kronik-check-rootless"), &token)?;
    fs::create_dir(root.join("data/layouts"))?;
    for (arg, name) in [
        (&args[2], "probe"),
        (&args[3], "pg"),
        (&args[4], "payments"),
    ] {
        let source = Path::new(arg).canonicalize()?;
        ensure!(
            source.join("index.json").is_file(),
            "prebuilt OCI layout missing: {}",
            source.display()
        );
        copy_tree(&source, &root.join(format!("data/layouts/{name}.oci")))?;
    }
    for path in [root.join("run/kronik"), root.join("ship")] {
        chown(path, Some(uid), Some(gid))?;
    }
    if args.len() > 9 {
        let source = Path::new(args.last().context("tool directory")?).canonicalize()?;
        let target = root.join(if directory_only {
            "directory-tools"
        } else {
            "microvm"
        });
        fs::create_dir(&target)?;
        chown(&target, Some(0), Some(0))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        let names: &[&str] = if directory_only {
            &[
                "manifest.json",
                "provenance.json",
                "mke2fs",
                "debugfs",
                "e2fsck",
            ]
        } else {
            &[
                "manifest.json",
                "provenance.json",
                "firecracker",
                "vmlinux",
                "guest-init",
                "mke2fs",
                "debugfs",
                "e2fsck",
            ]
        };
        for &name in names {
            let path = source.join(name);
            ensure!(
                path.symlink_metadata()?.is_file() && path.metadata()?.len() <= 256 * 1024 * 1024,
                "unbounded microvm artifact"
            );
            copy_tree(&path, &target.join(name))?;
            chown(target.join(name), Some(0), Some(0))?;
            let mode =
                if ["firecracker", "guest-init", "mke2fs", "debugfs", "e2fsck"].contains(&name) {
                    0o555
                } else {
                    0o444
                };
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(mode))?;
        }
        if !directory_only {
            use std::os::unix::fs::FileTypeExt as _;
            ensure!(
                Path::new("/dev/kvm")
                    .metadata()?
                    .file_type()
                    .is_char_device(),
                "required real KVM device missing"
            );
        }
    }
    // The service has its own mount view; no globally fixed data/run path is written.
    fs::write(
        root.join("etc/kronik/kronik.toml"),
        "[server]\ndata_dir='/var/lib/kronik'\napi_socket='/run/kronik/api.sock'\nhttp_listen='127.0.0.1:0'\nadmin_listen='127.0.0.1:0'\n[foreign]\nrun_dir='/run/kronik'\nplatform='systrap'\nlayout_dirs=['/var/lib/kronik/layouts']\n[keys]\nsource='file'\nmaster_key_file='/etc/kronik/master.key'\n[ship]\nenabled=true\nurl='file:///var/lib/kronik-ship/main'\n[log]\ndisk_reserve='64MiB'\nsegment_max_age_s=1\n[gateway]\ntimeout='120s'\n",
    )?;
    for name in [
        "passwd",
        "group",
        "subuid",
        "subgid",
        "login.defs",
        "nsswitch.conf",
        "machine-id",
        "kronik/kronik.toml",
    ] {
        fs::set_permissions(
            root.join("etc").join(name),
            fs::Permissions::from_mode(0o644),
        )?;
    }
    let md = root.metadata()?;
    let unit = format!("kronik-proof-{token}.service");
    let manager_unit = format!("kronik-proof-{token}-manager.service");
    let mut host_namespaces = serde_json::Map::new();
    for name in ["mnt", "pid", "user", "cgroup", "uts", "ipc", "net"] {
        let md = fs::metadata(format!("/proc/self/ns/{name}"))?;
        host_namespaces.insert(name.into(), json!([md.dev(), md.ino()]));
    }
    let cfg = json!({"version":"kronik.isolation-fixture/v1","root_identity":[md.dev(),md.ino()],
        "token":token,"unit":unit,"manager_unit":manager_unit,"uid":uid,"gid":gid,"subid":start,"operator_uid":operator,
        "host_namespaces":host_namespaces,
        "expected_mode":"rootless","binary":product,"helper":helper,"data":root.join("data"),
        "data_roots":[root.join("data")],"run":root.join("run/kronik"),"etc":root.join("etc"),
        "socket":root.join("run/kronik/api.sock"),"probe_layout":root.join("data/layouts/probe.oci"),
        "probe_image":"oci-layout:/var/lib/kronik/layouts/probe.oci",
        "pg_image":"oci-layout:/var/lib/kronik/layouts/pg.oci",
        "payments_image":"oci-layout:/var/lib/kronik/layouts/payments.oci"});
    save(&root.join("fixture.json"), &cfg)?;
    println!("{}", root.display());
    Ok(())
}

fn private_setup(root: &Path) -> Result<()> {
    let cfg = context(root)?;
    sys::bootstrap_owned_rootless_fixture(&root.join("etc"), &root.join("run"))?;
    // Credential helper mounts propagate only inside this already-private owned /run bind.
    command(&["mount", "--make-rshared", "/run"])?;
    if root.join("manager.json").try_exists()? && std::process::id() != 1 {
        let (manager, _) = manager_process(root, &cfg)?;
        let source = format!(
            "/proc/{manager}/root{}/run/kronik-userns/user",
            root.display()
        );
        match Path::new(&source).metadata() {
            Ok(md) if md.dev() != root.metadata()?.dev() => {
                command(&[
                    "mount",
                    "--no-canonicalize",
                    "--bind",
                    &source,
                    "/run/kronik-userns/user",
                ])?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "size=16m,mode=755",
        "tmpfs",
        "/var/lib",
    ])?;
    for (name, source) in [
        ("kronik", root.join("data")),
        ("kronik-ship", root.join("ship")),
    ] {
        let target = Path::new("/var/lib").join(name);
        fs::create_dir(&target)?;
        command(&[
            "mount",
            "--bind",
            source.to_str().context("source path")?,
            target.to_str().context("target path")?,
        ])?;
    }
    // Fixed private executable destinations must exist without writing the read-only host.
    use std::os::fd::AsRawFd as _;
    let binaries = [
        ("kronik", fs::File::open(text(&cfg, "binary")?)?),
        // Use this mount view, not /proc/self/exe's retained executable mount.
        (
            "kronik-isolation-fixture",
            fs::File::open(text(&cfg, "helper")?)?,
        ),
        ("runsc", fs::File::open("/usr/local/bin/runsc")?),
    ];
    let sidecar_target = Path::new("/usr/local/bin/gvisor-bin");
    let sidecars = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(sidecar_target)
    {
        Ok(directory) => Some(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    command(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "size=16m,mode=755",
        "tmpfs",
        "/usr/local/bin",
    ])?;
    for (name, binary) in binaries {
        let target = Path::new("/usr/local/bin").join(name);
        fs::File::create(&target)?;
        let source = format!("/proc/{}/fd/{}", std::process::id(), binary.as_raw_fd());
        command(&[
            "mount",
            "--no-canonicalize",
            "--bind",
            &source,
            target.to_str().context("binary target")?,
        ])?;
        command(&[
            "mount",
            "-o",
            "remount,bind,ro",
            target.to_str().context("binary target")?,
        ])?;
    }
    if let Some(sidecars) = sidecars {
        fs::create_dir(sidecar_target)?;
        let source = format!("/proc/{}/fd/{}", std::process::id(), sidecars.as_raw_fd());
        command(&[
            "mount",
            "--no-canonicalize",
            "--bind",
            &source,
            sidecar_target.to_str().context("sidecar target")?,
        ])?;
        command(&[
            "mount",
            "-o",
            "remount,bind,ro",
            sidecar_target.to_str().context("sidecar target")?,
        ])?;
    }
    for name in ["microvm", "directory-tools"] {
        let source = root.join(name);
        if !source.try_exists()? {
            continue;
        }
        command(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "size=16m,mode=755",
            "tmpfs",
            "/usr/local/lib",
        ])?;
        let target = Path::new("/usr/local/lib/kronik").join(name);
        fs::create_dir_all(&target)?;
        command(&[
            "mount",
            "--bind",
            source.to_str().context("artifact path")?,
            target.to_str().context("artifact target")?,
        ])?;
        command(&[
            "mount",
            "-o",
            "remount,bind,ro",
            target.to_str().context("artifact target")?,
        ])?;
    }
    Ok(())
}

fn require_manager_namespace(root: &Path) -> Result<()> {
    let record: Value = serde_json::from_slice(&fs::read(root.join("manager.json"))?)?;
    let actual = fs::metadata("/proc/self/ns/pid")?;
    ensure!(
        record["pid_namespace"] == json!([actual.dev(), actual.ino()]),
        "pin mutation requires the owned private manager namespace"
    );
    Ok(())
}

fn pin(root: &Path, cfg: &Value) -> Result<()> {
    require_manager_namespace(root)?;
    let path = root.join("run/kronik-userns/user");
    let uid = number(cfg, "uid")?;
    let gid = number(cfg, "gid")?;
    let range = Range {
        start: number(cfg, "subid")?,
        count: COUNT,
    };
    match sys::pin_userns(uid, gid, range, range, &path)? {
        sys::Pin::Created => {
            let md = path.metadata()?;
            save(
                &root.join("created-pin.json"),
                &json!({"identity":[md.dev(),md.ino()],"owner":uid}),
            )?;
        }
        sys::Pin::Kept => {
            // Keeping a namespace NEVER grants this runner cleanup ownership.
            let record = root.join("created-pin.json");
            if !record.try_exists()? {
                let md = path.metadata()?;
                save(
                    &root.join("kept-pin.json"),
                    &json!({"identity":[md.dev(),md.ino()],"owner":uid}),
                )?;
                return Ok(());
            }
            let previous: Value = serde_json::from_slice(&fs::read(record)?)?;
            let md = path.metadata()?;
            ensure!(
                previous["identity"] == json!([md.dev(), md.ino()]),
                "owned pin identity changed"
            );
        }
    }
    Ok(())
}
fn unpin(root: &Path) -> Result<()> {
    let record = root.join("created-pin.json");
    if !record.try_exists()? {
        return Ok(());
    }
    require_manager_namespace(root)?;
    let previous: Value = serde_json::from_slice(&fs::read(&record)?)?;
    let path = root.join("run/kronik-userns/user");
    let md = path.metadata()?;
    ensure!(
        previous["identity"] == json!([md.dev(), md.ino()]),
        "pin replaced; refusing cleanup"
    );
    ensure!(sys::unpin_userns(&path)?, "owned pin unexpectedly absent");
    fs::remove_file(record)?;
    Ok(())
}

fn capture_units(root: &Path, cfg: &Value) -> Result<()> {
    let unit = text(cfg, "unit")?;
    let pin = format!("{}-pin.service", unit.trim_end_matches(".service"));
    let mut rows = Vec::new();
    for name in [unit, &pin] {
        let path = root.join("units").join(name);
        if path.try_exists()? {
            let md = path.symlink_metadata()?;
            ensure!(md.is_file() && md.uid() == 0, "unowned unit artifact");
            rows.push(json!({"path":path,"identity":[md.dev(),md.ino()],
                "contents":fs::read_to_string(path)?}));
        }
        for dir in ["multi-user.target.wants", "default.target.wants"] {
            let path = root.join("run/systemd/system").join(dir).join(name);
            if path.try_exists()? {
                let md = path.symlink_metadata()?;
                ensure!(
                    md.file_type().is_symlink(),
                    "enable artifact is not a symlink"
                );
                rows.push(json!({"path":path,"identity":[md.dev(),md.ino()],"target":fs::read_link(path)?}));
            }
        }
    }
    let path = root.join("units").join(format!("{unit}.d/kvm.conf"));
    if path.try_exists()? {
        let md = path.symlink_metadata()?;
        ensure!(
            md.is_file() && md.uid() == 0 && md.nlink() == 1,
            "unowned unit drop-in"
        );
        let contents = fs::read_to_string(&path)?;
        ensure!(
            contents.starts_with("# Written by kronik "),
            "unrecognized owned unit drop-in"
        );
        rows.push(json!({"path":path,"identity":[md.dev(),md.ino()],"contents":contents}));
    }
    save(&root.join("created-units.json"), &json!(rows))
}

fn setup(root: &Path, cfg: &Value, mode: &str) -> Result<()> {
    ensure!(
        ["root", "rootless", "dry-run"].contains(&mode),
        "unknown explicit init mode"
    );
    if mode != "dry-run" {
        ensure_manager(root, cfg)?;
    }
    let unit = text(cfg, "unit")?.to_string();
    let host = init::InitHost::owned_fixture(
        PathBuf::from(text(cfg, "binary")?),
        root,
        unit,
        PathBuf::from(FIXTURE_HELPER),
    )?;
    private_setup(root)?;
    let args = init::InitArgs {
        init: true,
        domain: Vec::new(),
        acme_email: None,
        root: mode == "root",
        rootless: mode != "root",
        dry_run: mode == "dry-run",
    };
    let output = init::execute_on(&args, &root.join("etc/kronik/kronik.toml"), &host);
    if let Err(error) = &output {
        let unit = text(cfg, "unit")?;
        let pin = format!("{}-pin.service", unit.trim_end_matches(".service"));
        let state = control(root, cfg, &[
            "show".into(), unit.into(), pin,
            "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,StatusErrno,StatusText,LoadCredential".into(),
            "--no-pager".into(),
        ]).unwrap_or_else(|failure| format!("collecting owned service state: {failure:#}"));
        save(
            &root.join("init-failure.json"),
            &json!({
                "status":"ERROR", "error":format!("{error:#}"), "manager_state":state,
            }),
        )
        .with_context(|| format!("preserving init failure: {error:#}"))?;
    }
    capture_units(root, cfg)?;
    save(
        &root.join(format!("init-{mode}.json")),
        &serde_json::to_value(output?)?,
    )?;
    Ok(())
}

fn cleanup(root: &Path, cfg: &Value) -> Result<()> {
    let unit = text(cfg, "unit")?;
    let pin = format!("{}-pin.service", unit.trim_end_matches(".service"));
    if root.join("parent.json").try_exists()? {
        let state = host_parent(
            root,
            cfg,
            &[
                "show",
                text(cfg, "manager_unit")?,
                "--property=MainPID,InvocationID,ActiveState,LoadState,ControlGroup",
                "--no-pager",
            ],
        )?;
        if parent_gone(&state) {
            return Ok(());
        }
    }
    if !root.join("manager.json").try_exists()? {
        if root.join("parent.json").try_exists()? {
            host_parent(root, cfg, &["stop", text(cfg, "manager_unit")?])?;
            save(
                &root.join("cleanup.json"),
                &json!({"parent":cfg["manager_unit"],
                "retained_evidence":root,"status":"OWNED_PARENT_GONE"}),
            )?;
        }
        return Ok(());
    }
    let private = (|| -> Result<()> {
        let rows: Value = match fs::read(root.join("created-units.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!([]),
            Err(error) => return Err(error.into()),
        };
        // Refuse every replaced artifact BEFORE sending a manager mutation.
        for row in rows.as_array().context("unit rows")? {
            let path = Path::new(text(row, "path")?);
            ensure!(path.starts_with(root), "unit cleanup escaped owned root");
            let md = path.symlink_metadata()?;
            ensure!(
                row["identity"] == json!([md.dev(), md.ino()]),
                "unit replaced; refusing cleanup"
            );
            if row.get("contents").is_some() {
                ensure!(
                    row["contents"] == fs::read_to_string(path)?,
                    "unit contents changed"
                );
            } else {
                ensure!(
                    row["target"] == json!(fs::read_link(path)?),
                    "unit link changed"
                );
            }
        }
        let host = init::InitHost::owned_fixture(
            PathBuf::from(text(cfg, "binary")?),
            root,
            unit.into(),
            PathBuf::from(text(cfg, "helper")?),
        )?;
        host.stop(unit)?;
        host.stop(&pin)?;
        for row in rows.as_array().context("rows")? {
            fs::remove_file(text(row, "path")?)?;
        }
        let dropins = root.join("units").join(format!("{unit}.d"));
        if dropins.try_exists()? {
            fs::remove_dir(dropins)?;
        }
        control(root, cfg, &["daemon-reload".into()])?;
        let (manager, _) = manager_process(root, cfg)?;
        command(&[
            "nsenter",
            "--target",
            &manager.to_string(),
            "--mount",
            "--pid",
            FIXTURE_HELPER,
            "unpin",
            root.to_str().context("root")?,
        ])?;
        Ok(())
    })();
    let stopped = host_parent(root, cfg, &["stop", text(cfg, "manager_unit")?]);
    if let Err(error) = private {
        if let Err(stop) = stopped {
            bail!("{error:#}; stopping owned parent: {stop:#}");
        }
        return Err(error);
    }
    stopped?;
    save(
        &root.join("cleanup.json"),
        &json!({"units":[unit,pin],"retained_evidence":root,"status":"PASS"}),
    )?;
    Ok(())
}

fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let md = path.symlink_metadata()?;
    ensure!(!md.file_type().is_symlink(), "fixture artifact symlink");
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            chown_tree(&entry?.path(), uid, gid)?;
        }
    }
    chown(path, Some(uid), Some(gid))?;
    Ok(())
}

fn reset(root: &Path, cfg: &Value) -> Result<()> {
    control(root, cfg, &["stop".into(), text(cfg, "unit")?.into()])?;
    let data = root.join("data");
    let generation = tempfile::Builder::new()
        .prefix("retained-data-")
        .tempdir_in(root)?
        .keep();
    fs::remove_dir(&generation)?;
    fs::rename(&data, &generation)?;
    // A fresh LSN history must not restore segments from a prior owned generation.
    let ship = root.join("ship");
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &ship,
        rustix::fs::CWD,
        generation.join(".owned-object-store"),
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    fs::create_dir(&ship)?;
    fs::set_permissions(&ship, fs::Permissions::from_mode(0o700))?;
    chown(&ship, Some(number(cfg, "uid")?), Some(number(cfg, "gid")?))?;
    fs::create_dir(&data)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
    fs::write(data.join(".kronik-proof-owner"), text(cfg, "token")?)?;
    fs::write(data.join(".kronik-check-rootless"), text(cfg, "token")?)?;
    copy_tree(&generation.join("layouts"), &data.join("layouts"))?;
    chown_tree(&data, number(cfg, "uid")?, number(cfg, "gid")?)?;
    setup(root, cfg, "rootless")
}

fn restore(root: &Path, cfg: &Value) -> Result<()> {
    let data = root.join("data");
    let before = tempfile::Builder::new()
        .prefix("before-restore-")
        .tempdir_in(root)?
        .keep();
    fs::remove_dir(&before)?;
    fs::rename(&data, &before)?;
    fs::create_dir(&data)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
    chown(&data, Some(number(cfg, "uid")?), Some(number(cfg, "gid")?))?;
    private_setup(root)?;
    let output = command(&[
        text(cfg, "binary")?,
        "--json",
        "restore",
        "--from",
        "file:///var/lib/kronik-ship/main",
        "--config",
        "/etc/kronik/kronik.toml",
    ])?;
    let result: Value = serde_json::from_str(&output)?;
    ensure!(
        result["keystore"] == "installed",
        "restore did not authenticate/install privacy keys"
    );
    save(&root.join("restore.json"), &result)?;
    copy_tree(&before.join("layouts"), &data.join("layouts"))?;
    for name in [".kronik-proof-owner", ".kronik-check-rootless"] {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(data.join(name))
        {
            Ok(mut file) => {
                file.write_all(text(cfg, "token")?.as_bytes())?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure!(
                    fs::read(data.join(name))? == text(cfg, "token")?.as_bytes(),
                    "restored fixture marker changed"
                );
            }
            Err(error) => return Err(error.into()),
        }
        chown(
            data.join(name),
            Some(number(cfg, "uid")?),
            Some(number(cfg, "gid")?),
        )?;
    }
    chown_tree(
        &data.join("layouts"),
        number(cfg, "uid")?,
        number(cfg, "gid")?,
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(!args.is_empty(), "explicit fixture command required");
    if args[0] == "create" {
        return create(&args[1..]);
    }
    ensure!(args.len() >= 2, "owned fixture root required");
    let root = Path::new(&args[1]).canonicalize()?;
    let cfg = context(&root)?;
    match args[0].as_str() {
        "manager" => manager(&root),
        "manager-pid" => {
            println!("{}", manager_process(&root, &cfg)?.0);
            Ok(())
        }
        "manager-info" => {
            let (pid, cgroup) = manager_process(&root, &cfg)?;
            let namespace = fs::metadata(format!("/proc/{pid}/ns/pid"))?;
            println!(
                "{}",
                json!({"pid":pid,"start_time":process_start(pid)?,"cgroup":cgroup,
                "pid_namespace":[namespace.dev(),namespace.ino()]})
            );
            Ok(())
        }
        "host-pid" => {
            println!(
                "{}",
                host_pid(&root, &cfg, args.get(2).context("namespace PID")?.parse()?)?
            );
            Ok(())
        }
        "control" => {
            print!("{}", control(&root, &cfg, &args[2..])?);
            Ok(())
        }
        "pin" => pin(&root, &cfg),
        "pin-identity" => {
            require_manager_namespace(&root)?;
            let path = root.join("run/kronik-userns/user");
            ensure!(sys::validate_owned_userns(&path)?, "owned pin missing");
            let metadata = path.metadata()?;
            println!("{}", json!([metadata.dev(), metadata.ino()]));
            Ok(())
        }
        "unpin" => unpin(&root),
        "init" => setup(&root, &cfg, args.get(2).map_or("rootless", String::as_str)),
        "cleanup" => cleanup(&root, &cfg),
        "reset" => reset(&root, &cfg),
        "restore" => restore(&root, &cfg),
        _ => bail!("unknown explicit fixture command"),
    }
}
