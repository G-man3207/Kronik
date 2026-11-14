//! `kronik userns pin|unpin|status` (M21, ADR 0060): the Kronik user
//! namespace that the non-root daemon enters. `kronik-userns.service` runs
//! `pin` as root before the daemon starts; stopping that unit leaves the pin
//! alone, and `unpin` is an explicit step for a stopped installation. Host
//! setup, like `foreign cleanup`: no daemon, no reason, nothing in the
//! history.
//!
//! Also the host facts that `serve`, `doctor` and the offline commands
//! share: the `kronik` user, its subordinate ranges, whether user
//! namespaces are allowed, and dropping root for a data directory that
//! belongs to the non-root daemon.

use std::path::Path;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_foreign::subid::{self, Range, USERNS_PIN};
use kronik_foreign::sys::{self, IdMap, Pin};
use schemars::JsonSchema;
use serde::Serialize;

use super::{Ctx, Error};

/// The system user of the non-root daemon.
pub const USER: &str = "kronik";

#[derive(Debug, Subcommand)]
pub enum UsernsCommand {
    /// As root: create the Kronik user namespace (owned by the `kronik`
    /// user, 0 mapped to it and 1-65535 to its range in /etc/subuid and
    /// /etc/subgid) and pin it at /run/kronik-userns/user. A namespace
    /// already pinned with those maps is kept. kronik-userns.service runs
    /// it before kronik.service.
    Pin(HostArgs),
    /// As root: unmount and remove the pinned namespace.
    Unpin(HostArgs),
    /// Whether the namespace is pinned, its owner and maps, and whether
    /// they are what the `kronik` user's ranges give. Any user.
    Status {
        /// The daemon's user.
        #[arg(long, value_name = "NAME", default_value = USER)]
        user: String,
    },
}

#[derive(Debug, Args)]
pub struct HostArgs {
    /// The daemon's user, who owns the namespace.
    #[arg(long, value_name = "NAME", default_value = USER)]
    user: String,
    /// Show what would be done; change nothing.
    #[arg(long)]
    dry_run: bool,
}

/// What a command did, or with `--dry-run` would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Action {
    /// A namespace was pinned where there was none.
    Created,
    /// The pinned namespace had the right owner and maps.
    Kept,
    /// The pinned namespace was removed.
    Removed,
    /// Nothing was pinned.
    Absent,
}

/// The `kronik` user and its subordinate ranges.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct KronikUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// `[start, count]` of its /etc/subuid range.
    pub subuid: [u32; 2],
    /// `[start, count]` of its /etc/subgid range.
    pub subgid: [u32; 2],
}

impl KronikUser {
    /// The maps the Kronik namespace must have for this user.
    pub fn maps(&self) -> (IdMap, IdMap) {
        let range = |[start, count]: [u32; 2]| Range { start, count };
        (
            sys::kronik_map(self.uid, range(self.subuid)),
            sys::kronik_map(self.gid, range(self.subgid)),
        )
    }
}

/// What `kronik userns pin|unpin|status --json` prints.
#[derive(Debug, Serialize, JsonSchema)]
struct UsernsReport {
    /// Where the namespace is pinned: /run/kronik-userns/user.
    path: String,
    /// What `pin` or `unpin` did (with `--dry-run`: would do); absent for
    /// `status`.
    action: Option<Action>,
    dry_run: bool,
    /// Whether a user namespace is pinned there now (with `--dry-run`:
    /// before the command).
    pinned: bool,
    /// The uid that owns the pinned namespace.
    owner: Option<u32>,
    /// Its maps as `[inside, outside, count]` lines.
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    /// Why the maps could not be read: only the owner and root may.
    maps_error: Option<String>,
    /// The namespace's `setgroups` state, `deny` or `allow`: Kronik's
    /// denies `setgroups(2)`, so that its uid 0 cannot drop the service's
    /// supplementary groups (absent when it could not be read).
    setgroups: Option<String>,
    /// The `kronik` user and its ranges, when they are set up.
    user: Option<KronikUser>,
    /// Why the `kronik` user or its ranges are missing.
    user_error: Option<String>,
    /// Whether the owner and maps are what `user` gives and `setgroups` is
    /// denied (absent when either is unknown).
    matches: Option<bool>,
}

/// The JSON schema of `kronik userns pin|unpin|status --json`.
#[cfg(test)]
pub fn schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<UsernsReport>()
}

fn rootless(msg: String, hint: &str) -> ApiError {
    ApiError::new(ErrorCode::RootlessUnavailable, msg).with_hint(hint)
}

const SETUP_HINT: &str = "`sudo kronik serve --init --rootless` creates the kronik user and its ranges; \
     `sudo kronik serve --init --root` keeps the root daemon instead.";

/// One `/etc/passwd` entry that `pick` accepts: name, uid, gid.
// shortcut: reads /etc/passwd only, not NSS (LDAP and the like); the
// kronik system user is local. Upgrade to getpwnam_r if that changes.
fn passwd(path: &Path, pick: impl Fn(&str, u32) -> bool) -> Option<(String, u32, u32)> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        let (name, _, uid, gid) = (f.next()?, f.next()?, f.next()?, f.next()?);
        let (uid, gid) = (uid.parse().ok()?, gid.parse().ok()?);
        pick(name, uid).then(|| (name.to_owned(), uid, gid))
    })
}

/// The user `name` (or, with `uid`, the user with that uid) and its
/// subordinate ranges, or why they are not usable.
pub(crate) fn kronik_user(name: &str, uid: Option<u32>) -> Result<KronikUser, String> {
    // Privileged setup never follows a daemon-owned identity-file symlink.
    for (path, directory) in [
        ("/etc", true),
        ("/etc/passwd", false),
        ("/etc/subuid", false),
        ("/etc/subgid", false),
    ] {
        trusted_identity(Path::new(path), directory)?;
    }
    kronik_user_from(
        name,
        uid,
        Path::new("/etc/passwd"),
        Path::new("/etc/subuid"),
        Path::new("/etc/subgid"),
    )
}

fn trusted_identity(path: &Path, directory: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || (if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        })
    {
        return Err(format!(
            "{} is not a root-controlled nonsymlink identity {}",
            path.display(),
            if directory { "directory" } else { "file" }
        ));
    }
    Ok(())
}

/// Trusted setup/test seam: private identity files, never daemon configuration or environment.
pub(crate) fn kronik_user_from(
    name: &str,
    uid: Option<u32>,
    passwd_file: &Path,
    subuid: &Path,
    subgid: &Path,
) -> Result<KronikUser, String> {
    let (name, uid, gid) = match uid {
        Some(uid) => passwd(passwd_file, |_, u| u == uid)
            .ok_or_else(|| format!("no user with uid {uid} in {}", passwd_file.display()))?,
        None => passwd(passwd_file, |n, _| n == name)
            .ok_or_else(|| format!("no user {name} in {}", passwd_file.display()))?,
    };
    if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
        return Err(format!(
            "user {name} has uid {uid} and gid {gid}: the namespace never maps host root"
        ));
    }
    let range = |file: &Path, id: u32| {
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("reading {}: {e}", file.display()))?;
        match subid::find(&text, &name, uid) {
            Some(r) if r.start > 0 && !(r.start..r.end().unwrap_or(0)).contains(&id) => {
                Ok([r.start, r.count])
            }
            _ => Err(format!(
                "no safe range of {} ids for {name} in {}",
                subid::COUNT,
                file.display()
            )),
        }
    };
    Ok(KronikUser {
        subuid: range(subuid, uid)?,
        subgid: range(subgid, gid)?,
        name,
        uid,
        gid,
    })
}

/// Whether the kernel allows user namespaces as the Kronik namespace and
/// runsc's own below it need them, or why not.
pub(crate) fn userns_allowed() -> Result<(), String> {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    match read("/proc/sys/user/max_user_namespaces") {
        Some(0) => {
            return Err("user namespaces are off: user.max_user_namespaces is 0".into());
        }
        None => return Err("this kernel has no user namespaces".into()),
        Some(_) => {}
    }
    // Debian's switch; runsc's sandboxes create namespaces below Kronik's
    // without host capabilities.
    if read("/proc/sys/kernel/unprivileged_userns_clone") == Some(0) {
        return Err("kernel.unprivileged_userns_clone is 0".into());
    }
    Ok(())
}

pub(super) fn userns(ctx: &Ctx, command: UsernsCommand) -> Result<ExitCode, Error> {
    let path = Path::new(USERNS_PIN);
    let (action, dry_run, name) = match command {
        UsernsCommand::Pin(a) => (Some(pin(path, &a.user, a.dry_run)?), a.dry_run, a.user),
        UsernsCommand::Unpin(a) => (Some(unpin(path, a.dry_run)?), a.dry_run, a.user),
        UsernsCommand::Status { user, .. } => (None, false, user),
    };
    let user = kronik_user(&name, None);
    let pinned = sys::inspect_userns(path)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("reading {USERNS_PIN}: {e}")))?;
    let (uid_map, gid_map, maps_error) = match pinned.as_ref().map(|p| &p.maps) {
        Some(Ok((u, g))) => (Some(u.clone()), Some(g.clone()), None),
        Some(Err(e)) => (None, None, Some(e.clone())),
        None => (None, None, None),
    };
    let matches = match (&pinned, &user) {
        (Some(p), Ok(u)) => p
            .maps
            .as_ref()
            .ok()
            .map(|m| p.owner == u.uid && *m == u.maps() && p.denies_setgroups()),
        _ => None,
    };
    let report = UsernsReport {
        path: USERNS_PIN.to_owned(),
        action,
        dry_run,
        pinned: pinned.is_some(),
        owner: pinned.as_ref().map(|p| p.owner),
        uid_map,
        gid_map,
        maps_error,
        setgroups: pinned.as_ref().and_then(|p| p.setgroups.clone().ok()),
        user_error: user.as_ref().err().cloned(),
        user: user.ok(),
        matches,
    };
    if ctx.json {
        super::print_json(ctx, &report)?;
    } else {
        ctx.print(&render(&report));
    }
    Ok(ExitCode::SUCCESS)
}

fn render(r: &UsernsReport) -> String {
    let (done, would) = (!r.dry_run, r.dry_run);
    let mut out = match r.action {
        Some(Action::Created) if done => format!("Pinned a new namespace at {}.\n", r.path),
        Some(Action::Created) => format!("Would pin a new namespace at {}.\n", r.path),
        Some(Action::Kept) => format!("{} is pinned with the right maps: kept.\n", r.path),
        Some(Action::Removed) if would => format!("Would remove the namespace at {}.\n", r.path),
        Some(Action::Removed) => format!("Removed the namespace at {}.\n", r.path),
        Some(Action::Absent) => format!("Nothing is pinned at {}.\n", r.path),
        None if r.pinned => format!("{} is pinned.\n", r.path),
        None => format!("Nothing is pinned at {}.\n", r.path),
    };
    let show = |m: &IdMap| {
        m.iter()
            .map(|[a, b, c]| format!("{a} {b} {c}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(owner) = r.owner {
        out.push_str(&format!("Owner    uid {owner}\n"));
    }
    if let (Some(u), Some(g)) = (&r.uid_map, &r.gid_map) {
        out.push_str(&format!("Uid map  {}\nGid map  {}\n", show(u), show(g)));
    }
    if let Some(e) = &r.maps_error {
        out.push_str(&format!("Maps     unreadable: {e}\n"));
    }
    match r.setgroups.as_deref() {
        Some("deny") => out.push_str("Groups   setgroups(2) is denied\n"),
        Some(other) => out.push_str(&format!(
            "Groups   setgroups(2): {other}: uid 0 there could drop the service's groups; pin it again\n"
        )),
        None => {}
    }
    match (&r.user, &r.user_error) {
        (Some(u), _) => out.push_str(&format!(
            "User     {} (uid {}, gid {}), ranges {}+{} and {}+{}\n",
            u.name, u.uid, u.gid, u.subuid[0], u.subuid[1], u.subgid[0], u.subgid[1]
        )),
        (None, Some(e)) => out.push_str(&format!("User     {e}\n")),
        (None, None) => {}
    }
    match r.matches {
        Some(true) => out.push_str("Matches  yes: the daemon can enter it\n"),
        Some(false) => out.push_str(
            "Matches  no: stop the daemon, unpin its owned namespace, then pin the new identity\n",
        ),
        None => {}
    }
    out
}

fn needs_root(what: &str) -> Result<(), Error> {
    if sys::is_root() {
        return Ok(());
    }
    Err(ApiError::new(
        ErrorCode::Unavailable,
        format!("kronik userns {what} needs root"),
    )
    .with_hint("Run it as root (kronik-userns.service does), or add --dry-run to see the plan.")
    .into())
}

fn pin(path: &Path, name: &str, dry_run: bool) -> Result<Action, Error> {
    userns_allowed().map_err(|why| rootless(why, "Allow user namespaces (sysctl user.max_user_namespaces, kernel.unprivileged_userns_clone), or keep the root daemon with `sudo kronik serve --init --root`."))?;
    let user = kronik_user(name, None).map_err(|why| rootless(why, SETUP_HINT))?;
    let want = user.maps();
    if dry_run {
        let now = sys::inspect_userns(path).map_err(|e| {
            ApiError::new(ErrorCode::Internal, format!("reading {USERNS_PIN}: {e}"))
        })?;
        return Ok(match now {
            Some(p)
                if p.owner == user.uid
                    && p.maps.as_ref().is_ok_and(|m| *m == want)
                    && !p.denies_setgroups() =>
            {
                return Err(rootless(
                    format!("refusing to keep {USERNS_PIN}: {}", sys::SETGROUPS_ALLOWED),
                    "Stop consumers, then remove only the owned pin with `sudo kronik userns unpin`.",
                )
                .into());
            }
            Some(p) if p.owner == user.uid && p.maps.as_ref().is_ok_and(|m| *m == want) => {
                sys::validate_owned_userns(path).map_err(|e| {
                    ApiError::new(
                        ErrorCode::RootlessUnavailable,
                        format!("validating pin creation token: {e}"),
                    )
                })?;
                Action::Kept
            }
            Some(_) => return Err(rootless(
                "refusing to replace an existing namespace".into(),
                "Stop consumers, then remove only the owned pin with `sudo kronik userns unpin`.",
            )
            .into()),
            None => Action::Created,
        });
    }
    needs_root("pin")?;
    let range = |[start, count]: [u32; 2]| Range { start, count };
    let done = sys::pin_userns(
        user.uid,
        user.gid,
        range(user.subuid),
        range(user.subgid),
        path,
    )
    .map_err(|e| {
        rootless(
            format!("pinning the Kronik user namespace at {USERNS_PIN}: {e}"),
            "Run `kronik doctor` for the failing check; `sudo kronik serve --init --root` keeps the root daemon.",
        )
    })?;
    Ok(match done {
        Pin::Created => Action::Created,
        Pin::Kept => Action::Kept,
    })
}

fn unpin(path: &Path, dry_run: bool) -> Result<Action, Error> {
    if dry_run {
        let there = sys::validate_owned_userns(path).map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("validating owned pin {USERNS_PIN}: {e}"),
            )
        })?;
        return Ok(if there {
            Action::Removed
        } else {
            Action::Absent
        });
    }
    needs_root("unpin")?;
    let removed = sys::unpin_userns(path)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("unpinning {USERNS_PIN}: {e}")))?;
    Ok(if removed {
        Action::Removed
    } else {
        Action::Absent
    })
}

/// For a command that runs without the daemon and writes its data
/// directory (`restore`, `upgrade check`, `foreign cleanup`): run as root
/// against the non-root daemon's directory, it becomes that directory's
/// owner first, so that it leaves no file owned by root there (M21). Root
/// installs (a directory owned by root) are unchanged. Call it while the
/// process has one thread.
pub(crate) fn data_dir_owner(data_dir: &Path) -> Result<Option<(u32, u32)>, ApiError> {
    use std::os::unix::fs::MetadataExt as _;
    if !sys::is_root() {
        return Ok(None);
    }
    let meta = match std::fs::metadata(data_dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if Path::new(USERNS_PIN).exists() {
                return Err(rootless(
                    format!(
                        "{} does not exist, and this host runs the non-root daemon: as root this would create it owned by root",
                        data_dir.display()
                    ),
                    &format!(
                        "Create it for the kronik user first: `install -d -o {USER} -g {USER} -m 0700 {}`, then run the command again.",
                        data_dir.display()
                    ),
                ));
            }
            return Ok(None);
        }
        Err(e) => {
            return Err(ApiError::new(
                ErrorCode::Internal,
                format!("reading {}: {e}", data_dir.display()),
            ));
        }
    };
    if meta.uid() == 0 {
        return Ok(None);
    }
    let user = kronik_user(USER, None).map_err(|why| rootless(why, SETUP_HINT))?;
    if (meta.uid(), meta.gid()) != (user.uid, user.gid) || !meta.is_dir() {
        return Err(rootless(
            format!(
                "{} is not owned by the configured stable daemon identity {}:{}",
                data_dir.display(),
                user.uid,
                user.gid
            ),
            "Refusing a privileged data handover to an arbitrary owner; fix the stopped installation's ownership first.",
        ));
    }
    Ok(Some((user.uid, user.gid)))
}

pub(crate) fn as_data_dir_owner(data_dir: &Path) -> Result<(), ApiError> {
    let Some((uid, gid)) = data_dir_owner(data_dir)? else {
        return Ok(());
    };
    become_owner(uid, gid)
}

/// Gives up root for good: the user and group of the data directory's owner,
/// no supplementary group, no capability, no core dump, and nothing to go back
/// to. It needs the process to have one thread, and says so if it has more.
pub(crate) fn become_owner(uid: u32, gid: u32) -> Result<(), ApiError> {
    sys::become_user(uid, gid).map_err(|e| {
        ApiError::new(
            ErrorCode::Internal,
            format!("becoming the stable data owner {uid}:{gid}: {e}"),
        )
    })?;
    if rustix::process::geteuid().as_raw() != uid || rustix::process::getegid().as_raw() != gid {
        return Err(ApiError::new(
            ErrorCode::RootlessUnavailable,
            "the identity of the data directory's owner was not taken",
        ));
    }
    Ok(())
}

/// For a non-root command that works on the foreign actors' files (`foreign
/// cleanup`): enters the pinned Kronik namespace, as the daemon does, when
/// one is pinned for this user. Returns this process's cgroup when it
/// entered. Call it while the process has one thread.
pub(crate) fn enter_if_pinned() -> Result<Option<String>, String> {
    if sys::is_root() || !Path::new(USERNS_PIN).exists() {
        return Ok(None);
    }
    let uid = rustix::process::geteuid().as_raw();
    let user = kronik_user("", Some(uid))?;
    sys::enter_userns(Path::new(USERNS_PIN), &user.maps()).map_err(|e| e.to_string())?;
    sys::own_cgroup().map(Some).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_identity_files_validate_both_ranges_and_numeric_subgid_owner() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        let subuid = dir.path().join("subuid");
        let subgid = dir.path().join("subgid");
        std::fs::write(&passwd, "kronik:x:1001:1010::/:/bin/false\n").unwrap();
        std::fs::write(&subuid, "kronik:200000:65536\n").unwrap();
        std::fs::write(&subgid, "1001:300000:65536\n").unwrap();
        let user = kronik_user_from(USER, None, &passwd, &subuid, &subgid).unwrap();
        assert_eq!((user.uid, user.gid), (1001, 1010));
        assert_eq!(
            user.maps(),
            (
                vec![[0, 1001, 1], [1, 200000, 65535]],
                vec![[0, 1010, 1], [1, 300000, 65535]]
            )
        );
        std::fs::write(&subuid, "kronik:200000:65536\nother:210000:65536\n").unwrap();
        assert!(kronik_user_from(USER, None, &passwd, &subuid, &subgid).is_err());
        std::fs::write(&subuid, "kronik:1:65536\n").unwrap();
        assert!(kronik_user_from(USER, None, &passwd, &subuid, &subgid).is_err());
        std::fs::write(&passwd, "kronik:x:1001:0::/:/bin/false\n").unwrap();
        assert!(kronik_user_from(USER, None, &passwd, &subuid, &subgid).is_err());
    }

    #[test]
    fn the_user_never_maps_host_root() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        let subid = dir.path().join("subid");
        std::fs::write(&passwd, "root:x:0:0::/:/bin/false\n").unwrap();
        std::fs::write(&subid, "").unwrap();
        let e = kronik_user_from("", Some(0), &passwd, &subid, &subid).unwrap_err();
        assert!(e.contains("never maps host root"), "{e}");
        assert!(kronik_user("no-such-user-kronik-test", None).is_err());
    }

    #[test]
    fn privileged_identity_inputs_reject_writable_files_and_links() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("passwd");
        std::fs::write(&file, "kronik:x:1001:1001::/:/bin/false\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(trusted_identity(&file, false).is_err());
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(trusted_identity(&link, false).is_err());
    }

    #[test]
    fn the_report_says_what_was_done() {
        let r = UsernsReport {
            path: USERNS_PIN.into(),
            action: Some(Action::Created),
            dry_run: true,
            pinned: false,
            owner: None,
            uid_map: None,
            gid_map: None,
            maps_error: None,
            setgroups: None,
            user: None,
            user_error: Some("no user kronik in /etc/passwd".into()),
            matches: None,
        };
        let text = render(&r);
        assert!(text.starts_with("Would pin"), "{text}");
        assert!(text.contains("no user kronik"), "{text}");
        assert!(!text.contains("setgroups"), "{text}");
        // A pinned namespace says whether it denies setgroups(2).
        let denied = UsernsReport {
            pinned: true,
            owner: Some(1001),
            setgroups: Some("deny".into()),
            ..r
        };
        assert!(render(&denied).contains("setgroups(2) is denied"));
        let allowed = UsernsReport {
            setgroups: Some("allow".into()),
            ..denied
        };
        assert!(render(&allowed).contains("pin it again"));
    }
}
