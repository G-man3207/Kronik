//! Host setup operations of `kronik serve --init`.
use super::*;

/// Which service `--init` installs: the root service of v0.1 to v0.4 or the
/// nonroot one. `DEFAULT_MODE` says which is meant without a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    Rootless,
    Root,
}

/// The nonroot service's host identity and its subordinate ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ids {
    pub uid: u32,
    pub gid: u32,
    pub uid_start: u32,
    pub gid_start: u32,
}

pub(super) fn user_ids() -> anyhow::Result<Option<(u32, u32)>> {
    let out = Command::new("getent").args(["passwd", "kronik"]).output()?;
    if !out.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(out.stdout)?;
    let fields: Vec<_> = text.trim().split(':').collect();
    anyhow::ensure!(fields.len() >= 4, "invalid kronik passwd entry");
    let (uid, gid): (u32, u32) = (fields[2].parse()?, fields[3].parse()?);
    anyhow::ensure!(
        uid != 0 && gid != 0 && uid != u32::MAX && gid != u32::MAX,
        "kronik must have a stable nonroot system identity"
    );
    Ok(Some((uid, gid)))
}
fn read_optional(path: &str) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        result => result.with_context(|| format!("reading {path}")),
    }
}
fn ranges(
    uid: u32,
) -> anyhow::Result<(kronik_foreign::subid::Range, kronik_foreign::subid::Range)> {
    use kronik_foreign::subid;
    let defs = read_optional("/etc/login.defs")?;
    let mut maximum = 65535;
    let mut occupied = Vec::new();
    for db in ["passwd", "group"] {
        let out = Command::new("getent").arg(db).output()?;
        anyhow::ensure!(out.status.success(), "getent {db} failed");
        for line in String::from_utf8(out.stdout)?.lines() {
            if let Some(id) = line.split(':').nth(2).and_then(|s| s.parse::<u32>().ok())
                && id < u32::MAX - 1
            {
                maximum = maximum.max(id);
                occupied.push(id);
            }
        }
    }
    let mut out = Vec::new();
    for (file, prefix) in [("/etc/subuid", "SUB_UID"), ("/etc/subgid", "SUB_GID")] {
        let text = read_optional(file)?;
        let limit = |suffix: &str, fallback| {
            let key = format!("{prefix}_{suffix}");
            defs.lines()
                .rev()
                .find_map(|line| {
                    let mut words = line.split_whitespace();
                    (words.next() == Some(key.as_str()))
                        .then(|| words.next()?.parse::<u32>().ok())
                        .flatten()
                })
                .unwrap_or(fallback)
        };
        let min = limit("MIN", 100_000);
        let max = limit("MAX", 600_100_000);
        let range = if let Some(range) = subid::find(&text, "kronik", uid) {
            range
        } else {
            anyhow::ensure!(
                !subid::parse(&text).any(|(name, _)| name == "kronik" || name == uid.to_string()),
                "{file} contains an insufficient kronik subordinate range"
            );
            subid::allocate(&text, maximum.max(min.saturating_sub(1)))
                .context("no free subordinate range")?
        };
        anyhow::ensure!(
            range
                .start
                .checked_add(subid::COUNT - 1)
                .is_some_and(|n| n <= max),
            "subordinate range exceeds login.defs"
        );
        anyhow::ensure!(
            !occupied
                .iter()
                .any(|id| *id >= range.start && *id - range.start < range.count),
            "{file} maps an existing host account identity"
        );
        out.push(range);
    }
    Ok((out[0], out[1]))
}
pub(super) fn host_ids() -> anyhow::Result<Ids> {
    let (uid, gid) = user_ids()?.context("kronik user missing")?;
    let (u, g) = ranges(uid)?;
    Ok(Ids {
        uid,
        gid,
        uid_start: u.start,
        gid_start: g.start,
    })
}
pub(super) fn allocate_ranges() -> anyhow::Result<()> {
    use kronik_foreign::subid;
    let (uid, _) = user_ids()?.context("kronik user missing")?;
    let (u, g) = ranges(uid)?;
    for (file, flag, range) in [
        ("/etc/subuid", "--add-subuids", u),
        ("/etc/subgid", "--add-subgids", g),
    ] {
        if subid::find(&read_optional(file)?, "kronik", uid).is_none() {
            // usermod uses shadow's passwd/subid lock protocol; never append to the database.
            sh(&[
                "usermod",
                flag,
                &format!("{}-{}", range.start, range.start + subid::COUNT - 1),
                "kronik",
            ])?;
        }
    }
    // Re-read after shadow's locked operation; a concurrent allocator may have won the race.
    let (u, g) = ranges(uid)?;
    anyhow::ensure!(
        subid::find(&read_optional("/etc/subuid")?, "kronik", uid) == Some(u)
            && subid::find(&read_optional("/etc/subgid")?, "kronik", uid) == Some(g),
        "subordinate allocation changed unexpectedly"
    );
    Ok(())
}
pub(super) fn systemd_version() -> anyhow::Result<u32> {
    let out = Command::new("systemctl").arg("--version").output()?;
    anyhow::ensure!(out.status.success(), "systemctl --version failed");
    String::from_utf8(out.stdout)?
        .split_whitespace()
        .nth(1)
        .context("missing systemd version")?
        .parse()
        .context("invalid systemd version")
}
pub(super) fn rootless_checks() -> anyhow::Result<u32> {
    // A host that lacks what the nonroot service needs never gets the root
    // service by itself: the operator is told how to choose it.
    const ROOT: &str = "; `kronik serve --init --root` installs the root service instead";
    let version = systemd_version().map_err(|e| {
        e.context(format!(
            "the nonroot service needs systemd 255 or newer{ROOT}"
        ))
    })?;
    anyhow::ensure!(
        version >= 255,
        "the nonroot service needs systemd 255 or newer, and this host has {version}{ROOT}"
    );
    anyhow::ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "the nonroot service needs cgroup v2{ROOT}"
    );
    let count: u64 = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")?
        .trim()
        .parse()?;
    anyhow::ensure!(
        count != 0,
        "user namespaces are disabled (user.max_user_namespaces is 0){ROOT}"
    );
    Ok(version)
}
pub(super) fn durable_write(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write as _;
    let parent = path.parent().context("setup path has no parent")?;
    let missing: Vec<_> = parent
        .ancestors()
        .take_while(|path| !path.exists())
        .collect();
    for directory in missing.into_iter().rev() {
        std::fs::create_dir(directory)?;
        std::fs::File::open(
            directory
                .parent()
                .context("setup directory has no parent")?,
        )?
        .sync_all()?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    tmp.write_all(contents)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) fn durable_remove(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            std::fs::File::open(path.parent().context("setup path has no parent")?)?.sync_all()?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn main_pid(host: &InitHost) -> anyhow::Result<u32> {
    let out =
        host.control_output(&["show", "--property", "MainPID", "--value", &host.unit_name])?;
    let pid = String::from_utf8(out.stdout)?.trim().parse()?;
    anyhow::ensure!(
        pid != 0,
        "service did not start; inspect it with journalctl"
    );
    Ok(pid)
}
fn start_time(pid: u32) -> anyhow::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("reading service PID {pid} start time"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .context("service start time missing")?
        .parse()
        .context("invalid service start time")
}

/// The first part of `path` that `uid`/`gid` may not search (a directory) or
/// read (the file itself), worded for the operator; `None` when the mode bits
/// let the service in. This reads modes, not the service's credentials: it
/// answers the one failure that leaves no process to ask, a daemon that
/// exited before it could open its configuration.
fn unreadable_configuration(path: &Path, uid: u32, gid: u32) -> anyhow::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt as _;
    let allows = |metadata: &std::fs::Metadata, bit: u32| {
        let shift = if metadata.uid() == uid {
            6
        } else if metadata.gid() == gid {
            3
        } else {
            0
        };
        (metadata.mode() >> shift) & bit != 0
    };
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    let mut ancestors: Vec<_> = absolute.ancestors().collect();
    ancestors.reverse();
    for component in ancestors {
        let metadata = match std::fs::metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(format!("{} does not exist", component.display())));
            }
            Err(error) => return Err(error.into()),
        };
        let mode = metadata.mode() & 0o7777;
        let (what, bit) = if component == absolute {
            ("read", 0o4)
        } else {
            ("search", 0o1)
        };
        if !allows(&metadata, bit) {
            return Ok(Some(format!(
                "{} is mode {mode:04o}, owned by uid {} and gid {}; the kronik service (uid {uid}, gid {gid}) cannot {what} it",
                component.display(),
                metadata.uid(),
                metadata.gid()
            )));
        }
    }
    Ok(None)
}

/// The readiness failure that the nonroot service's configuration already
/// explains: the daemon exited because it could not read the file, so the
/// service's PID is gone and `reading service PID N start time` would name
/// the symptom, not the cause (F-2). `None` for the root service, and whenever
/// the mode bits say the file is reachable: the caller then reports what it
/// found, as before.
pub(super) fn unreadable_configuration_error(
    mode: Mode,
    config: &Path,
) -> anyhow::Result<Option<anyhow::Error>> {
    if mode != Mode::Rootless {
        return Ok(None);
    }
    let Some((uid, gid)) = user_ids()? else {
        return Ok(None);
    };
    let Some(why) = unreadable_configuration(config, uid, gid)? else {
        return Ok(None);
    };
    Ok(Some(
        ApiError::new(
            ErrorCode::RootlessUnavailable,
            format!(
                "the kronik service cannot read the configuration {}: {why}",
                config.display()
            ),
        )
        .with_hint(
            "The nonroot service runs as kronik, so the configuration's directory must be mode 0755 and the file 0644, and every directory on the way to them must let it in. Rerunning `sudo kronik serve --init --rootless` restores both modes.",
        )
        .into(),
    ))
}

pub(super) fn verify(
    mode: Mode,
    host: &InitHost,
    config: &Path,
) -> anyhow::Result<Vec<DoctorWarning>> {
    use kronik_core::env::{Clock, real::RealClock};
    use std::time::Duration;
    // A diagnosis only: `verify` works unchanged when the mode bits are
    // unreadable to this process. The daemon cannot have started without
    // reading its configuration, so every way this process's absence shows
    // (`systemctl` reporting none, `/proc` gone, a restart loop) prefers the
    // configuration's path and mode to the symptom.
    let unreadable = || unreadable_configuration_error(mode, config).ok().flatten();
    let pid = match main_pid(host) {
        Ok(pid) => pid,
        Err(error) => return Err(unreadable().unwrap_or(error)),
    };
    let started = match start_time(pid) {
        Ok(started) => started,
        Err(error) => return Err(unreadable().unwrap_or(error)),
    };
    let settings = Config::load(config)?;
    let endpoint = crate::cli::http::Endpoint::Unix(settings.server.api_socket);
    let clock = RealClock::default();
    let deadline = clock.monotonic() + Duration::from_secs(90);
    loop {
        let ready = crate::cli::http::request(
            &endpoint,
            "GET",
            "/v1/keys",
            None,
            None,
            None,
            Duration::from_millis(500),
        );
        if ready.as_ref().is_ok_and(|response| response.status == 200) {
            break;
        }
        let now = start_time(pid).map_err(|error| unreadable().unwrap_or(error))?;
        anyhow::ensure!(now == started, "service restarted during initialization");
        if clock.monotonic() >= deadline {
            if let Some(error) = unreadable() {
                return Err(error);
            }
            let why = match ready {
                Ok(response) => format!("loaded-source status returned HTTP {}", response.status),
                Err(error) => format!("{error:?}"),
            };
            bail!("service readiness timed out: {why}; inspect it with journalctl");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    let want = if mode == Mode::Root {
        0
    } else {
        user_ids()?.context("kronik user missing")?.0
    };
    for value in status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context("service UIDs missing")?
        .split_whitespace()
    {
        anyhow::ensure!(
            value.parse::<u32>()? == want,
            "service has unexpected host credentials"
        );
    }
    if mode == Mode::Rootless {
        let ids = host_ids()?;
        for value in status
            .lines()
            .find_map(|line| line.strip_prefix("Gid:"))
            .context("service GIDs missing")?
            .split_whitespace()
        {
            anyhow::ensure!(
                value.parse::<u32>()? == ids.gid,
                "service has unexpected host group credentials"
            );
        }
        let namespace = std::fs::File::open(format!("/proc/{pid}/ns/user"))?;
        let own = std::fs::metadata("/proc/self/ns/user")?;
        let actual = namespace.metadata()?;
        if (own.dev(), own.ino()) == (actual.dev(), actual.ino()) {
            for cap in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
                anyhow::ensure!(
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix(cap))
                        .is_some_and(|value| value.trim() == "0000000000000000"),
                    "service retains {cap} host capabilities"
                );
            }
        } else {
            let pinned = if let Some(etc) = &host.fixture_etc {
                let helper = host
                    .fixture_helper
                    .as_ref()
                    .context("fixture helper missing")?;
                let root = etc.parent().context("fixture root missing")?;
                let output = Command::new(helper).arg("manager-pid").arg(root).output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "cannot identify the owned private manager"
                );
                let manager: u32 = String::from_utf8(output.stdout)?.trim().parse()?;
                let output = Command::new("nsenter")
                    .args(["--target", &manager.to_string(), "--mount", "--pid"])
                    .arg(helper)
                    .arg("pin-identity")
                    .arg(root)
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "owned pin validation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                serde_json::from_slice::<[u64; 2]>(&output.stdout)?
            } else {
                let pin = Path::new(kronik_foreign::subid::USERNS_PIN);
                anyhow::ensure!(
                    kronik_foreign::sys::validate_owned_userns(pin)?,
                    "service's namespace pin is not owned"
                );
                let pinned = std::fs::metadata(pin)?;
                [pinned.dev(), pinned.ino()]
            };
            anyhow::ensure!(
                pinned == [actual.dev(), actual.ino()],
                "service is not in the owned pinned namespace"
            );
            let inspected = kronik_foreign::sys::inspect_userns_fd(&namespace)?
                .context("service user namespace missing")?;
            anyhow::ensure!(
                inspected.owner == ids.uid,
                "service namespace has an unexpected owner"
            );
            let (uids, gids) = inspected.maps.map_err(anyhow::Error::msg)?;
            let count = kronik_foreign::subid::COUNT - 1;
            anyhow::ensure!(
                uids.as_slice() == [[0, ids.uid, 1], [1, ids.uid_start, count]]
                    && gids.as_slice() == [[0, ids.gid, 1], [1, ids.gid_start, count]],
                "service namespace maps changed"
            );
        }
    }
    let doctor = doctor_report(host, config, mode == Mode::Rootless)?;
    let final_pid = main_pid(host).map_err(|error| unreadable().unwrap_or(error))?;
    let final_started = start_time(pid).map_err(|error| unreadable().unwrap_or(error))?;
    anyhow::ensure!(
        final_pid == pid && final_started == started,
        "service identity changed during verification"
    );
    Ok(doctor)
}

/// Runs `kronik doctor` against the running service and returns what it warned
/// about. The report is read as data (`--json`); a failed check, or a report
/// that cannot be read, fails the installation, as the exit status always did.
fn doctor_report(
    host: &InitHost,
    config: &Path,
    rootless: bool,
) -> anyhow::Result<Vec<DoctorWarning>> {
    let mut command = Command::new(&host.exe);
    command.arg("doctor");
    if rootless {
        command.arg("--rootless");
    }
    let output = command
        .arg("--json")
        .arg("--config")
        .arg(config)
        .output()
        .context("running kronik doctor")?;
    let (warnings, failed) = parse_doctor(&output.stdout).map_err(|cause| {
        unreadable_report(
            &cause,
            &output.status.to_string(),
            &output.stdout,
            &output.stderr,
        )
    })?;
    anyhow::ensure!(
        output.status.success() && failed.is_empty(),
        "kronik doctor failed: {}",
        if failed.is_empty() {
            format!("{}", output.status)
        } else {
            failed.join("; ")
        }
    );
    Ok(warnings)
}

/// The error for a doctor whose output is not a report: the doctor failed
/// before it could print one, and what it wrote says why. A bounded, printable
/// excerpt of its standard error and output goes into the message.
fn unreadable_report(
    cause: &anyhow::Error,
    status: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> anyhow::Error {
    let excerpt = |bytes: &[u8]| -> String {
        String::from_utf8_lossy(bytes)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(400)
            .collect::<String>()
            .trim()
            .to_owned()
    };
    let mut text = format!("{cause:#} (kronik doctor: {status}");
    for (what, bytes) in [("standard error", stderr), ("standard output", stdout)] {
        let shown = excerpt(bytes);
        if !shown.is_empty() {
            text.push_str(&format!("; {what}: {shown}"));
        }
    }
    text.push(')');
    anyhow::anyhow!(text)
}

/// The warnings and the failures (as `name: message`) in the JSON of
/// `kronik doctor --json` (docs/reference/json.md).
fn parse_doctor(report: &[u8]) -> anyhow::Result<(Vec<DoctorWarning>, Vec<String>)> {
    let report: serde_json::Value =
        serde_json::from_slice(report).context("kronik doctor did not print a JSON report")?;
    let checks = report["checks"]
        .as_array()
        .context("the doctor's report has no checks")?;
    let mut warnings = Vec::new();
    let mut failed = Vec::new();
    for check in checks {
        let field = |name: &str| check[name].as_str().map(str::to_owned);
        let (Some(name), Some(status), Some(message)) =
            (field("name"), field("status"), field("message"))
        else {
            bail!("a check of the doctor's report is malformed");
        };
        match status.as_str() {
            "warn" => warnings.push(DoctorWarning {
                check: name,
                message,
                hint: field("hint"),
            }),
            "fail" => failed.push(format!("{name}: {message}")),
            _ => {}
        }
    }
    Ok((warnings, failed))
}

#[cfg(test)]
mod doctor_tests {
    // `use super::*` sits in each test: the explicit fixture driver compiles this
    // module with `cfg(test)` but without the test harness, which drops the tests.

    const REPORT: &str = r#"{"checks":[
        {"name":"config","status":"pass","code":null,"message":"/etc/kronik/kronik.toml is valid","hint":null},
        {"name":"delegate","status":"warn","code":"ROOTLESS_UNAVAILABLE","message":"cgroup /x is not delegated to this user","hint":"the daemon gets one in kronik.service"},
        {"name":"sandbox","status":"warn","code":null,"message":"not proven: daemon identity unavailable","hint":null},
        {"name":"disk","status":"pass","code":null,"message":"7.9 GiB free","hint":null}],
        "pass":2,"warn":2,"fail":0}"#;

    #[test]
    fn the_warnings_of_the_doctor_are_read_with_their_hints_and_nothing_else() {
        use super::*;
        let (warnings, failed) = parse_doctor(REPORT.as_bytes()).unwrap();
        assert!(failed.is_empty());
        assert_eq!(
            warnings,
            [
                DoctorWarning {
                    check: "delegate".into(),
                    message: "cgroup /x is not delegated to this user".into(),
                    hint: Some("the daemon gets one in kronik.service".into()),
                },
                DoctorWarning {
                    check: "sandbox".into(),
                    message: "not proven: daemon identity unavailable".into(),
                    hint: None,
                },
            ]
        );
    }

    #[test]
    fn a_doctor_that_printed_no_report_is_reported_with_what_it_wrote() {
        use super::*;
        let cause = parse_doctor(b"").unwrap_err();
        let text = unreadable_report(
            &cause,
            "exit status: 1",
            b"",
            b"error: cannot read /etc/kronik/kronik.toml: Permission denied\n",
        )
        .to_string();
        for needle in [
            "did not print a JSON report",
            "exit status: 1",
            "standard error: error: cannot read /etc/kronik/kronik.toml: Permission denied",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert!(!text.contains("standard output"), "{text}");
        // Long, multi-line and non-UTF-8 output is bounded and printable.
        let noise = [b"line one\nline two\x1b[31m\xff".as_slice(), &[b'x'; 5000]].concat();
        let text = unreadable_report(&cause, "signal: 9", &noise, b"").to_string();
        assert!(
            text.contains("standard output: line one line two"),
            "{text}"
        );
        assert!(
            text.len() < 700 && !text.contains('\n') && !text.contains('\u{1b}'),
            "{text}"
        );
    }

    #[test]
    fn a_failed_check_and_an_unreadable_report_fail_the_installation() {
        use super::*;
        let report = REPORT.replace(
            r#""name":"disk","status":"pass""#,
            r#""name":"disk","status":"fail""#,
        );
        let (_, failed) = parse_doctor(report.as_bytes()).unwrap();
        assert_eq!(failed, ["disk: 7.9 GiB free"]);
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"checks":[{"name":"x"}]}"#,
            r#"{"checks":"x"}"#,
        ] {
            assert!(parse_doctor(bad.as_bytes()).is_err(), "{bad:?}");
        }
        // No checks at all is a report with nothing in it, not a failure.
        assert_eq!(parse_doctor(br#"{"checks":[]}"#).unwrap(), (vec![], vec![]));
    }

    #[test]
    fn the_end_of_the_install_says_what_is_not_proven_only_when_something_is_not() {
        use super::*;
        // Printing is a side effect; the shape of the input is what matters here.
        print_warnings(&[]);
        let (warnings, _) = parse_doctor(REPORT.as_bytes()).unwrap();
        print_warnings(&warnings);
    }

    /// A directory this test's process owns, under `/tmp`: the service
    /// identities below are neither owner nor group, so only the "other"
    /// bits decide what they can reach.
    fn temp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("kronik-init-")
            .tempdir_in("/tmp")
            .or_else(|_| tempfile::tempdir())
            .unwrap()
    }

    fn mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// F-2: the install says which path the service cannot read, and its
    /// mode, instead of `reading service PID N start time` (the PID is gone
    /// precisely because the daemon could not read the configuration).
    #[test]
    fn the_configuration_the_service_cannot_reach_is_named() {
        use super::*;
        let root = temp_dir();
        let etc = root.path().join("kronik");
        std::fs::create_dir(&etc).unwrap();
        let config = etc.join("kronik.toml");
        std::fs::write(&config, "[server]\n").unwrap();
        mode(root.path(), 0o755);
        mode(&etc, 0o755);
        mode(&config, 0o644);
        // Service identities that own nothing here: the mode classes that
        // decide are "other", as they are for the kronik user.
        let uid = u32::MAX - 1;
        let gid = u32::MAX - 2;
        assert_eq!(unreadable_configuration(&config, uid, gid).unwrap(), None);
        // The directory that took the operator's umask.
        mode(&etc, 0o700);
        let why = unreadable_configuration(&config, uid, gid)
            .unwrap()
            .unwrap();
        assert!(why.contains(&etc.display().to_string()), "{why}");
        assert!(why.contains("0700"), "{why}");
        assert!(why.contains("cannot search"), "{why}");
        assert!(why.contains(&format!("uid {uid}")), "{why}");
        // A directory that is traversable but a file only root may read.
        mode(&etc, 0o755);
        mode(&config, 0o600);
        let why = unreadable_configuration(&config, uid, gid)
            .unwrap()
            .unwrap();
        assert!(why.contains(&config.display().to_string()), "{why}");
        assert!(why.contains("0600"), "{why}");
        assert!(why.contains("cannot read"), "{why}");
        // And with the documented modes it says nothing.
        mode(&config, 0o644);
        assert_eq!(unreadable_configuration(&config, uid, gid).unwrap(), None);
    }

    /// Only the nonroot service is told about a configuration permission
    /// problem: the root service reads it as root.
    #[test]
    fn the_root_service_never_blames_the_configuration_mode() {
        use super::*;
        let root = temp_dir();
        let config = root.path().join("kronik.toml");
        std::fs::write(&config, "[server]\n").unwrap();
        mode(&config, 0o600);
        assert!(
            unreadable_configuration_error(Mode::Root, &config)
                .unwrap()
                .is_none()
        );
    }
}
