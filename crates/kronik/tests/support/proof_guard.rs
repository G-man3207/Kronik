//! The guards of the bring-up helper (`isolation_fixture create`). The helper is
//! privileged: it starts a transient service of the host's manager that keeps
//! most of root's capabilities in the host's user and network namespaces, opens
//! listeners on the host's addresses, and retains a tree of copies. These
//! checks keep it from running on a machine nobody meant it for, with an id
//! that is already someone's, or into a directory that cannot hold it.
//!
//! The helper includes this file, and `tests/proof_guard.rs` tests it: the
//! helper itself has no test harness.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};

/// The file the operator writes once, on the throwaway machine.
pub const MARKER: &str = "/etc/kronik-proof-host";
pub const MACHINE_ID: &str = "/etc/machine-id";
/// What must stay free on the parent directory after the copies are made.
pub const RESERVE_BYTES: u64 = 1 << 30;
/// How long the transient manager (and so the whole proof) may run, by default.
pub const DEFAULT_MAX_RUNTIME_SECS: u32 = 3600;

/// G1. The operator has said that this machine is disposable: a root-owned
/// regular file, not writable by others, holds this machine's own machine id.
/// A marker bound to the machine id cannot be copied to another host by
/// accident, and the check does not ask for a virtual machine: the proof with
/// KVM may well run on bare metal or nested. `owner` is root's uid.
pub fn require_proof_host(marker: &Path, machine_id: &Path, owner: u32) -> Result<()> {
    let say = format!(
        "this proof changes the host: it starts a transient service of the host's service manager that keeps most of root's capabilities in the host's user and network namespaces, and it opens listeners on the host's real addresses. Run it only on a machine that holds nothing worth protecting, and say so once, as root, on that machine: cat {MACHINE_ID} > {MARKER}"
    );
    let id = fs::read_to_string(machine_id)
        .with_context(|| format!("reading {}", machine_id.display()))?;
    let id = id.trim();
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "{} does not hold an initialized machine id, so the host cannot be told from another: {say}",
        machine_id.display()
    );
    let metadata = match fs::symlink_metadata(marker) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("{} does not exist: {say}", marker.display())
        }
        Err(e) => return Err(e).with_context(|| format!("looking at {}", marker.display())),
    };
    ensure!(
        metadata.is_file() && metadata.uid() == owner && metadata.mode() & 0o022 == 0,
        "{} must be a regular file owned by root that nobody else can write: {say}",
        marker.display()
    );
    ensure!(
        metadata.len() <= 256,
        "{} is not a machine id: {say}",
        marker.display()
    );
    let held =
        fs::read_to_string(marker).with_context(|| format!("reading {}", marker.display()))?;
    ensure!(
        held.trim() == id,
        "{} holds another machine's id, so it was not written on this host: {say}",
        marker.display()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdKind {
    User,
    Group,
}

/// G2. The chosen ids must belong to nobody: no account in any database the
/// host's name service reads (LDAP, SSSD and homed accounts are not in
/// `/etc/passwd`), and no process of the host running as one of them.
/// `known` answers whether the name service knows an id; an answer that cannot
/// be had refuses, because the fixture would otherwise own files that someone
/// else's id may already own. `proc` is the directory of process entries.
pub fn require_unused_ids(
    ids: &[(IdKind, u32)],
    known: &dyn Fn(IdKind, u32) -> Result<bool>,
    proc: &Path,
) -> Result<()> {
    for &(kind, id) in ids {
        let name = match kind {
            IdKind::User => "user",
            IdKind::Group => "group",
        };
        ensure!(
            !known(kind, id).with_context(|| format!(
                "asking the name service about {name} id {id} (getent) failed, so the id cannot be shown to be unused"
            ))?,
            "{name} id {id} belongs to an account the name service knows (getent): choose another"
        );
    }
    let entries = fs::read_dir(proc).with_context(|| format!("reading {}", proc.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        // A process that ends while the directory is scanned is not a finding.
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        for line in status.lines() {
            let (kind, rest) = if let Some(rest) = line.strip_prefix("Uid:") {
                (IdKind::User, rest)
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                (IdKind::Group, rest)
            } else {
                continue;
            };
            for field in rest.split_whitespace() {
                let Ok(value) = field.parse::<u32>() else {
                    continue;
                };
                if ids.iter().any(|&(k, id)| k == kind && id == value) {
                    bail!(
                        "process {pid} runs as {} id {value}, one of the ids chosen for the fixture: choose ids that nothing uses",
                        if kind == IdKind::User {
                            "user"
                        } else {
                            "group"
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

/// The ids G2 asks about: the chosen user, operator and group ids, and both ends
/// of the subordinate range (as users and as groups). The flat files are checked
/// for the whole range by the helper; the name service and the running processes
/// cannot be asked about all of its `count` ids, so the ends stand for it.
pub fn fixture_ids(
    uid: u32,
    gid: u32,
    operator: u32,
    start: u32,
    count: u32,
) -> Result<Vec<(IdKind, u32)>> {
    let last = count
        .checked_sub(1)
        .and_then(|span| start.checked_add(span))
        .context("the subordinate range is empty or overflows")?;
    Ok(vec![
        (IdKind::User, uid),
        (IdKind::User, operator),
        (IdKind::Group, gid),
        (IdKind::User, start),
        (IdKind::User, last),
        (IdKind::Group, start),
        (IdKind::Group, last),
    ])
}

/// G2, on this host: `getent passwd <uid>` and `getent group <gid>` answer 0
/// when the id is known and 2 when it is not; anything else is an error.
pub fn getent_knows(kind: IdKind, id: u32) -> Result<bool> {
    let database = match kind {
        IdKind::User => "passwd",
        IdKind::Group => "group",
    };
    // By absolute path: the helper runs as root, and PATH is the caller's.
    let getent = ["/usr/bin/getent", "/bin/getent"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .context("getent is not installed at /usr/bin/getent or /bin/getent")?;
    let status = std::process::Command::new(getent)
        .args([database, &id.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("running getent")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        other => bail!("getent {database} {id} ended with {other:?}"),
    }
}

/// The bytes of the regular files below `path` (a file is its own length). A
/// link is not followed and counts for nothing; the tree is bounded.
pub fn tree_size(path: &Path) -> Result<u64> {
    fn walk(path: &Path, depth: usize, seen: &mut usize) -> Result<u64> {
        ensure!(depth <= 64, "{} is nested too deeply", path.display());
        *seen += 1;
        ensure!(
            *seen <= 5_000_000,
            "too many entries below the fixture's inputs"
        );
        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_file() {
            return Ok(metadata.len());
        }
        if !metadata.is_dir() {
            return Ok(0);
        }
        let mut total = 0u64;
        for entry in fs::read_dir(path)? {
            total = total.saturating_add(walk(&entry?.path(), depth + 1, seen)?);
        }
        Ok(total)
    }
    walk(path, 0, &mut 0)
}

/// The bytes available to an unprivileged writer on the file system of `path`.
pub fn available_bytes(path: &Path) -> Result<u64> {
    let stat = rustix::fs::statvfs(path).with_context(|| format!("statvfs {}", path.display()))?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// G4. The copies `create` is about to make, and the reserve, must fit.
pub fn require_space(parent: &Path, needed: u64, available: u64) -> Result<()> {
    // A size that overflows with the reserve does not fit anywhere.
    ensure!(
        needed
            .checked_add(RESERVE_BYTES)
            .is_some_and(|total| total <= available),
        "{} has {} MiB free; the fixture's copies need about {} MiB and {} MiB must stay free after them. Every run retains its tree (rm -r it once its evidence is read), so free the space or choose another parent directory",
        parent.display(),
        available >> 20,
        needed >> 20,
        RESERVE_BYTES >> 20
    );
    Ok(())
}

/// G6. The limit of the transient manager's life is an argument, `--max-runtime
/// SECONDS`, at the end of the arguments of `create`: the whole proof runs inside
/// it, and systemd kills the manager when it ends, in the middle of whatever is
/// running. Returns the other arguments and the limit.
pub fn take_max_runtime(args: &[String]) -> Result<(&[String], u32)> {
    let [rest @ .., flag, value] = args else {
        return Ok((args, DEFAULT_MAX_RUNTIME_SECS));
    };
    if flag != "--max-runtime" {
        return Ok((args, DEFAULT_MAX_RUNTIME_SECS));
    }
    let seconds: u32 = value
        .parse()
        .with_context(|| format!("--max-runtime {value:?} is not a number of seconds"))?;
    ensure!(
        (600..=86_400).contains(&seconds),
        "--max-runtime {seconds} must be between 600 and 86400 seconds"
    );
    Ok((rest, seconds))
}
