//! Command lines of the container runtimes (docs/design/m7-foreign.md §5,
//! ADR 0003 §1): `runsc` for `gvisor`, plain `runc` for `trusted`. Every
//! command runs through `Env::procs`.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kronik_core::env::{Env, ProcessSpec, Stdio};

/// Which runtime runs an actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Engine {
    /// gVisor with `--platform=<platform>` (`systrap` or `kvm`).
    Runsc { platform: String },
    /// Plain runc (`trusted`).
    Runc,
}

/// One runtime binary with its state directory (`--root`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Runtime {
    pub engine: Engine,
    pub program: PathBuf,
    pub root: PathBuf,
}

/// The container id of a foreign actor: `kronik-foreign-` and 16 hex
/// digits of the name's BLAKE3 hash. runsc resolves ids by prefix, so ids
/// must not be prefixes of each other, as `kronik-foreign-pay` was of
/// `kronik-foreign-payments` (docs/design/m7-foreign.md §3).
pub(crate) fn container_id(name: &str) -> String {
    format!(
        "kronik-foreign-{}",
        &blake3::hash(name.as_bytes()).to_hex()[..16]
    )
}

impl Runtime {
    fn spec(&self, args: Vec<String>, out: Stdio) -> ProcessSpec {
        let mut all = vec!["--root".to_owned(), self.root.display().to_string()];
        all.extend(args);
        ProcessSpec {
            program: self.program.clone(),
            args: all,
            env: Vec::new(),
            cwd: None,
            stdout: out.clone(),
            stderr: out,
        }
    }

    /// `run` in the foreground: the child's exit status is the container's.
    /// Its output goes through the daemon into `log`, capped (§12). Under
    /// gVisor the rootfs overlay lives in the sandbox's memory, so writes
    /// outside `/data` count against the memory limit instead of filling
    /// the host's disk (`runsc`'s default `root:self` keeps them in a file
    /// next to the rootfs).
    pub fn run(&self, bundle: &Path, id: &str, log: &Path) -> ProcessSpec {
        let mut args = Vec::new();
        if let Engine::Runsc { platform } = &self.engine {
            args.push(format!("--platform={platform}"));
            args.push("--network=sandbox".to_owned());
            args.push("--overlay2=root:memory".to_owned());
        }
        args.extend([
            "run".to_owned(),
            "--bundle".to_owned(),
            bundle.display().to_string(),
            id.to_owned(),
        ]);
        self.spec(
            args,
            Stdio::Log {
                path: log.to_path_buf(),
                max_bytes: crate::logs::ROTATE_BYTES,
            },
        )
    }

    pub fn kill(&self, id: &str, signal: &str, log: &Path) -> ProcessSpec {
        self.spec(
            vec!["kill".into(), id.into(), signal.into()],
            Stdio::Append(log.to_path_buf()),
        )
    }

    pub fn delete(&self, id: &str, log: &Path) -> ProcessSpec {
        self.spec(
            vec!["delete".into(), "--force".into(), id.into()],
            Stdio::Append(log.to_path_buf()),
        )
    }

    /// Lists the ids under the root, one per line, into `out`.
    pub fn list(&self, out: &Path) -> ProcessSpec {
        let quiet = match self.engine {
            Engine::Runsc { .. } => "-quiet",
            Engine::Runc => "-q",
        };
        let mut spec = self.spec(
            vec!["list".into(), quiet.into()],
            Stdio::Append(out.to_path_buf()),
        );
        spec.stderr = Stdio::Null;
        spec
    }

    /// `runsc --version` into `out` (a checkpoint's `meta.json`).
    pub fn version(&self, out: &Path) -> ProcessSpec {
        self.spec(vec!["--version".into()], Stdio::Append(out.to_path_buf()))
    }

    /// `runsc pause` / `runsc resume` (a checkpoint, ADR 0019).
    pub fn pause(&self, id: &str, resume: bool, log: &Path) -> ProcessSpec {
        let verb = if resume { "resume" } else { "pause" };
        self.spec(
            vec![verb.into(), id.into()],
            Stdio::Append(log.to_path_buf()),
        )
    }

    /// `runsc checkpoint --leave-running`: the sandbox's memory and overlay
    /// into `image`; the container keeps running.
    pub fn checkpoint(&self, id: &str, image: &Path, log: &Path) -> ProcessSpec {
        self.spec(
            vec![
                "checkpoint".into(),
                format!("--image-path={}", image.display()),
                "--leave-running".into(),
                id.into(),
            ],
            Stdio::Append(log.to_path_buf()),
        )
    }

    /// `runsc restore --detach`: a new container `id` from the checkpoint
    /// `image` with the bundle `bundle` (a fork's copy, ADR 0019). The
    /// rootfs is production's: the copy's writes to it go to an overlay in
    /// the copy's memory, as production's do (`run`; a restore needs the
    /// overlay medium of the checkpointed sandbox), never into production's
    /// rootfs directory.
    pub fn restore(&self, bundle: &Path, id: &str, image: &Path, log: &Path) -> ProcessSpec {
        let mut args = Vec::new();
        if let Engine::Runsc { platform } = &self.engine {
            args.push(format!("--platform={platform}"));
            args.push("--network=sandbox".to_owned());
            args.push("--overlay2=root:memory".to_owned());
        }
        args.extend([
            "restore".to_owned(),
            "--detach".to_owned(),
            format!("--image-path={}", image.display()),
            "--bundle".to_owned(),
            bundle.display().to_string(),
            id.to_owned(),
        ]);
        self.spec(args, Stdio::Append(log.to_path_buf()))
    }

    /// `runsc port-forward --stream`: connects the Unix socket `sock` to
    /// `port` inside the sandbox, then exits (0 once the connection is
    /// handed over, non-zero when nothing listens on the port).
    pub fn port_forward(&self, sock: &Path, id: &str, port: u16, log: &Path) -> ProcessSpec {
        self.spec(
            vec![
                "port-forward".into(),
                "--stream".into(),
                sock.display().to_string(),
                id.into(),
                port.to_string(),
            ],
            Stdio::Append(log.to_path_buf()),
        )
    }
}

/// Runs a short command to its end; kills it after `timeout`. Returns the
/// exit code (`None` for a signal).
pub(crate) async fn run_quick(
    env: &Env,
    spec: ProcessSpec,
    timeout: Duration,
) -> io::Result<Option<i32>> {
    let what = spec
        .args
        .iter()
        .find(|a| !a.starts_with('-') && !a.starts_with('/'))
        .cloned()
        .unwrap_or_default();
    let child = env.procs.spawn(spec).await?;
    match env.timeout(timeout, child.wait()).await {
        Ok(r) => r,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{what} did not finish within {} ms", timeout.as_millis()),
            ))
        }
    }
}

/// Finds `runc` in the usual places.
pub(crate) fn find_runc() -> Option<PathBuf> {
    ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin"]
        .iter()
        .map(|d| Path::new(d).join("runc"))
        .find(|p| is_executable(p))
}

pub(crate) fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_ids_have_one_length_so_none_is_a_prefix_of_another() {
        let pay = container_id("pay");
        let payments = container_id("payments");
        assert_eq!(pay, container_id("pay"));
        assert_eq!((pay.len(), payments.len()), (31, 31));
        assert!(pay.starts_with("kronik-foreign-"));
        assert!(!payments.starts_with(&pay) && !pay.starts_with(&payments));
    }

    #[test]
    fn command_lines_follow_adr_0003() {
        let rt = Runtime {
            engine: Engine::Runsc {
                platform: "systrap".into(),
            },
            program: "/usr/local/bin/runsc".into(),
            root: "/run/kronik/runsc".into(),
        };
        let log = Path::new("/d/out.log");
        assert_eq!(
            rt.run(Path::new("/d/bundle"), "kronik-foreign-echo", log)
                .args,
            [
                "--root",
                "/run/kronik/runsc",
                "--platform=systrap",
                "--network=sandbox",
                "--overlay2=root:memory",
                "run",
                "--bundle",
                "/d/bundle",
                "kronik-foreign-echo"
            ]
        );
        assert_eq!(
            rt.run(Path::new("/d/bundle"), "kronik-foreign-echo", log)
                .stdout,
            Stdio::Log {
                path: log.to_path_buf(),
                max_bytes: crate::logs::ROTATE_BYTES
            }
        );
        assert_eq!(
            rt.port_forward(Path::new("/s/c1.sock"), "kronik-foreign-echo", 8080, log)
                .args,
            [
                "--root",
                "/run/kronik/runsc",
                "port-forward",
                "--stream",
                "/s/c1.sock",
                "kronik-foreign-echo",
                "8080"
            ]
        );
        let runc = Runtime {
            engine: Engine::Runc,
            program: "/usr/bin/runc".into(),
            root: "/run/kronik/runc".into(),
        };
        assert_eq!(
            runc.run(Path::new("/d/bundle"), "kronik-foreign-x", log)
                .args,
            [
                "--root",
                "/run/kronik/runc",
                "run",
                "--bundle",
                "/d/bundle",
                "kronik-foreign-x"
            ]
        );
        assert_eq!(runc.list(log).args.last().map(String::as_str), Some("-q"));
        assert_eq!(runc.list(log).stderr, Stdio::Null);
    }
}
