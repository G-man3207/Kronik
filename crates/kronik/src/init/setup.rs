//! Host setup operations of `kronik serve --init`.
use super::*;

/// Which service `--init` installs: the nonroot default or the explicit root
/// fallback.
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
pub(super) fn verify(mode: Mode, host: &InitHost, config: &Path) -> anyhow::Result<()> {
    use kronik_core::env::{Clock, real::RealClock};
    use std::time::Duration;
    let pid = main_pid(host)?;
    let started = start_time(pid)?;
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
        anyhow::ensure!(
            start_time(pid)? == started,
            "service restarted during initialization"
        );
        if clock.monotonic() >= deadline {
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
    if mode == Mode::Rootless {
        sh(&[
            &host.exe.to_string_lossy(),
            "doctor",
            "--rootless",
            "--config",
            &config.to_string_lossy(),
        ])?;
    } else {
        sh(&[
            &host.exe.to_string_lossy(),
            "doctor",
            "--config",
            &config.to_string_lossy(),
        ])?;
    }
    anyhow::ensure!(
        main_pid(host)? == pid && start_time(pid)? == started,
        "service identity changed during verification"
    );
    Ok(())
}
