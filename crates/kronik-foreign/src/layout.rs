//! The layout of `<data>/foreign` (docs/design/m7-foreign.md §3): the blob
//! store in `blobs/` and every actor in `actors/<name>/`, all mode 0700.
//!
//! Before this layout, actors lived in `foreign/<name>/`, where an actor
//! named `blobs` shared its directory with the blob store. [`migrate`]
//! moves such directories once, through a staging directory, so a crash
//! in the middle resumes on the next start.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use kronik_effects::foreign::valid_name;

/// Written into `actors/` when it is complete.
const MARKER: &str = ".layout";
/// Where old actor directories are gathered before `actors/` appears.
const STAGING: &str = ".actors-new";
/// What an actor named `blobs` kept next to the blob store.
const ACTOR_FILES: [&str; 4] = ["bundle", "data", "output.log", "output.log.1"];

fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path).map_err(|e| at("creating", path, e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| at("setting the mode of", path, e))
}

/// runsc's and runc's state directories under `run`, mode 0700 whatever
/// made them (runsc made its root 0710 under the unit): a state file holds the
/// container's spec, the resolved secret values in its environment
/// included, and under the unit `run` is /run/kronik, 0750 for the kronik
/// group that may use the API socket.
pub(crate) fn private_runtime_roots(run: &Path) -> io::Result<()> {
    private_dir(&run.join("runsc"))?;
    private_dir(&run.join("runc"))
}

/// An error that names the path it is about (the daemon logs it and
/// `foreign list` shows it).
fn at(what: &str, path: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what} {}: {e}", path.display()))
}

fn rename(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("moving {} to {}: {e}", from.display(), to.display()),
        )
    })
}

/// Moves an old actor directory into `staging`. A symbolic link moves as a
/// link (an operator may have put an actor's directory on another disk); a
/// relative target is made absolute, since the link moves one level down.
fn move_actor(from: &Path, to: &Path, link: bool) -> io::Result<()> {
    if link {
        let target = fs::read_link(from).map_err(|e| at("reading the link", from, e))?;
        if target.is_relative()
            && let Some(parent) = from.parent()
        {
            std::os::unix::fs::symlink(parent.join(&target), to)
                .map_err(|e| at("creating the link", to, e))?;
            return fs::remove_file(from).map_err(|e| at("removing the link", from, e));
        }
    }
    match fs::rename(from, to) {
        // A mount point cannot move (EBUSY; EXDEV across file systems): it
        // stays, and the new path links to it, as an operator's link would.
        Err(e) if matches!(e.raw_os_error(), Some(16 | 18)) => {
            let target = std::path::absolute(from).map_err(|e| at("resolving", from, e))?;
            if fs::read_link(to).is_ok_and(|t| t == target) {
                return Ok(()); // linked by an interrupted earlier run
            }
            std::os::unix::fs::symlink(&target, to).map_err(|e| at("creating the link", to, e))?;
            tracing::info!(
                from = %from.display(),
                "a foreign actor directory is a mount point: it stays, linked from foreign/actors"
            );
            Ok(())
        }
        r => r.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("moving {} to {}: {e}", from.display(), to.display()),
            )
        }),
    }
}

/// Creates `foreign/`, `foreign/blobs/` and `foreign/actors/` (mode 0700),
/// moving actor directories of the old layout into `actors/`.
pub(crate) fn migrate(foreign: &Path) -> io::Result<()> {
    private_dir(foreign)?;
    private_dir(&foreign.join("blobs"))?;
    let actors = foreign.join("actors");
    if actors.join(MARKER).exists() {
        return fs::set_permissions(&actors, fs::Permissions::from_mode(0o700))
            .map_err(|e| at("setting the mode of", &actors, e));
    }
    let staging = foreign.join(STAGING);
    private_dir(&staging)?;
    for entry in fs::read_dir(foreign).map_err(|e| at("reading", foreign, e))? {
        let entry = entry.map_err(|e| at("reading", foreign, e))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let kind = entry
            .file_type()
            .map_err(|e| at("reading", &entry.path(), e))?;
        if !(kind.is_dir() || kind.is_symlink()) || !valid_name(&name) {
            continue;
        }
        if name == "blobs" {
            // The blob store stays; an actor named `blobs` moves out of it.
            for file in ACTOR_FILES {
                let from = entry.path().join(file);
                if from.symlink_metadata().is_ok() {
                    private_dir(&staging.join("blobs"))?;
                    rename(&from, &staging.join("blobs").join(file))?;
                }
            }
            continue;
        }
        // Without the marker, `actors/` is the old directory of an actor
        // named `actors`.
        move_actor(&entry.path(), &staging.join(&name), kind.is_symlink())?;
    }
    let marker = staging.join(MARKER);
    fs::write(&marker, b"actors under foreign/actors/<name>\n")
        .map_err(|e| at("writing", &marker, e))?;
    rename(&staging, &actors)?;
    let moved = fs::read_dir(&actors)
        .map_err(|e| at("reading", &actors, e))?
        .count()
        - 1;
    if moved > 0 {
        tracing::info!(
            actors = moved,
            "moved foreign actor directories to foreign/actors"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for e in walk(dir) {
            out.push(e.strip_prefix(dir).unwrap().display().to_string());
        }
        out.sort();
        out
    }

    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            out.push(p.clone());
            if p.is_dir() {
                out.extend(walk(&p));
            }
        }
        out
    }

    #[test]
    fn old_actor_directories_move_under_actors() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        for d in [
            "echo/data",
            "echo/bundle",
            "actors/data",
            "blobs/sha256",
            "blobs/data",
        ] {
            fs::create_dir_all(f.join(d)).unwrap();
        }
        fs::write(f.join("blobs/sha256/ab"), b"blob").unwrap();
        fs::write(f.join("blobs/output.log"), b"log").unwrap();
        fs::write(f.join("echo/data/x"), b"x").unwrap();
        migrate(&f).unwrap();
        assert_eq!(
            tree(&f),
            [
                "actors",
                "actors/.layout",
                "actors/actors",
                "actors/actors/data",
                "actors/blobs",
                "actors/blobs/data",
                "actors/blobs/output.log",
                "actors/echo",
                "actors/echo/bundle",
                "actors/echo/data",
                "actors/echo/data/x",
                "blobs",
                "blobs/sha256",
                "blobs/sha256/ab",
            ]
        );
        let mode = |p: &str| fs::metadata(f.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            (mode(""), mode("blobs"), mode("actors")),
            (0o700, 0o700, 0o700)
        );
        // A second start changes nothing.
        migrate(&f).unwrap();
        assert_eq!(tree(&f).len(), 14);
    }

    #[test]
    fn an_interrupted_migration_resumes() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        fs::create_dir_all(f.join(".actors-new/echo/data")).unwrap();
        fs::create_dir_all(f.join("pay/data")).unwrap();
        migrate(&f).unwrap();
        assert!(f.join("actors/echo/data").is_dir());
        assert!(f.join("actors/pay/data").is_dir());
        assert!(!f.join(".actors-new").exists());
    }

    /// An old actor directory that is a link (to another disk) moves as a
    /// link: the actor keeps its data instead of starting on an empty one.
    #[test]
    fn a_linked_actor_directory_moves_as_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        let disk = tmp.path().join("disk/echo");
        fs::create_dir_all(disk.join("data")).unwrap();
        fs::write(disk.join("data/x"), b"x").unwrap();
        fs::create_dir_all(&f).unwrap();
        std::os::unix::fs::symlink(&disk, f.join("echo")).unwrap();
        // A relative link (`foreign/pay -> ../disk/pay`) still resolves
        // one level down.
        fs::create_dir_all(tmp.path().join("disk/pay/data")).unwrap();
        std::os::unix::fs::symlink("../disk/pay", f.join("pay")).unwrap();
        migrate(&f).unwrap();
        let moved = f.join("actors/echo");
        assert!(moved.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read(moved.join("data/x")).unwrap(), b"x");
        assert!(!f.join("echo").exists());
        assert!(
            f.join("actors/pay/data").is_dir(),
            "the relative link resolves"
        );
    }

    /// An old actor directory that is a mount point cannot be moved: it
    /// stays, and `actors/<name>` links to it. Needs root (a tmpfs mount);
    /// skipped otherwise.
    #[test]
    fn a_mounted_actor_directory_stays_and_is_linked() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        let echo = f.join("echo");
        fs::create_dir_all(&echo).unwrap();
        let mounted = std::process::Command::new("mount")
            .args(["-t", "tmpfs", "-o", "size=1m", "tmpfs"])
            .arg(&echo)
            .status()
            .is_ok_and(|s| s.success());
        if !mounted {
            eprintln!("skipped: mounting a tmpfs needs root");
            return;
        }
        fs::create_dir_all(echo.join("data")).unwrap();
        fs::write(echo.join("data/x"), b"x").unwrap();
        let r = migrate(&f);
        let moved = f.join("actors/echo");
        let linked = moved.symlink_metadata().map(|m| m.file_type().is_symlink());
        let read = fs::read(moved.join("data/x"));
        let _ = std::process::Command::new("umount").arg(&echo).status();
        r.unwrap();
        assert!(linked.unwrap(), "actors/echo is a link");
        assert_eq!(read.unwrap(), b"x");
        assert_eq!(
            fs::read_link(&moved).unwrap(),
            std::path::absolute(&echo).unwrap()
        );
    }

    /// A move that fails names its paths (the daemon shows the message).
    #[test]
    fn a_failed_move_names_its_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        fs::create_dir_all(&f).unwrap();
        // `.actors-new` cannot be created: a file is in the way.
        fs::write(f.join(".actors-new"), b"").unwrap();
        let e = migrate(&f).unwrap_err().to_string();
        assert!(e.contains(".actors-new"), "{e}");
    }

    #[test]
    fn a_fresh_data_directory_gets_the_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("foreign");
        migrate(&f).unwrap();
        assert_eq!(tree(&f), ["actors", "actors/.layout", "blobs"]);
    }
}
