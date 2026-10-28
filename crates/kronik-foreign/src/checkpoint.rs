//! Checkpoints of foreign actors and the copies forks start from them
//! (docs/design/m14-foreign-forks.md, ADR 0019).
//!
//! A checkpoint is `<data>/foreign/actors/<name>/checkpoints/<lsn:020>/` with
//! `image/` (`runsc checkpoint`), `data/` (the data directory, copied while
//! the sandbox is paused), `config.json` (the sandbox's runtime spec) and
//! `meta.json`. A copy is a new container restored from it, with its own
//! data copy, network namespace (only `lo`), cgroup and bridge.

use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kronik_core::env::{BoxFuture, Env, HttpRequest, HttpResponse, NetError};
use kronik_effects::foreign::{Checkpoint, CopySpec, ForeignCopy};
use serde::{Deserialize, Serialize};

use crate::bridge::{Dialer, Pool};
use crate::manager::Foreign;
use crate::runtime::{Engine, Runtime, container_id, run_quick};
use crate::supervisor::State;

const QUICK: Duration = Duration::from_secs(30);
/// How long a restored copy may take to answer its first connection.
const COPY_READY: Duration = Duration::from_secs(20);

/// `meta.json` of a checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    name: String,
    lsn: u64,
    image: String,
    platform: String,
    /// The runsc release that took it (design §3); empty in older ones.
    #[serde(default)]
    runsc: String,
    port: u32,
    at_ms: u64,
    bytes: u64,
}

fn dir_name(lsn: u64) -> String {
    format!("{lsn:020}")
}

/// Resumes the paused sandbox `id`, retrying. One that stays paused is
/// killed, so its supervisor restarts it: production never stays paused.
pub(crate) async fn resume(env: &Env, rt: &Runtime, id: &str, log: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..3 {
        match run_quick(env, rt.pause(id, true, log), QUICK).await {
            Ok(Some(0)) => return Ok(()),
            r => last = format!("runsc resume: {r:?}"),
        }
    }
    let _ = run_quick(env, rt.kill(id, "KILL", log), QUICK).await;
    tracing::error!(id, error = %last, "a foreign actor did not resume; killed it, it restarts");
    Err(format!("{last}; the sandbox was killed and restarts"))
}

/// The bytes of the files under `dir` (0 when it cannot be read).
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// Copies `from` to `to` (which must not exist) with modes, owners,
/// symlinks and file times; sockets, FIFOs and devices are skipped. Setuid
/// and setgid are cleared, as when images are unpacked (oci.rs): a setid
/// file a guest made in `/data` never reaches a checkpoint or a copy
/// (ADR 0027), and std::fs::copy would copy them.
pub(crate) fn copy_tree(from: &Path, to: &Path) -> io::Result<u64> {
    let meta = std::fs::symlink_metadata(from)?;
    std::fs::create_dir(to)?;
    let mut bytes = 0;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let src = e.path();
        let dst = to.join(e.file_name());
        let m = std::fs::symlink_metadata(&src)?;
        let ft = m.file_type();
        if ft.is_dir() {
            bytes += copy_tree(&src, &dst)?;
        } else if ft.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&src)?, &dst)?;
            std::os::unix::fs::lchown(&dst, Some(m.uid()), Some(m.gid()))?;
        } else if ft.is_file() {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&dst)?;
            bytes += io::copy(&mut std::fs::File::open(&src)?, &mut out)?;
            out.set_permissions(std::fs::Permissions::from_mode(m.mode() & 0o1777))?;
            std::os::unix::fs::chown(&dst, Some(m.uid()), Some(m.gid()))?;
            let f = std::fs::File::options().write(true).open(&dst)?;
            f.set_modified(m.modified()?)?;
        }
    }
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(meta.mode() & 0o1777))?;
    std::os::unix::fs::chown(to, Some(meta.uid()), Some(meta.gid()))?;
    Ok(bytes)
}

fn private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn err(what: &str, e: impl std::fmt::Display) -> String {
    format!("{what}: {e}")
}

/// The copy's container id: fixed length, so no id is a prefix of another
/// (runsc resolves ids by prefix), and new per start, so a copy being
/// stopped never takes a newer copy's id, namespace or disk with it.
fn copy_key(fork: &str, name: &str) -> String {
    static STARTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = STARTS.fetch_add(1, Ordering::Relaxed);
    let h = blake3::hash(format!("{fork}\0{name}\0{n}").as_bytes()).to_hex();
    h[..16].to_owned()
}

impl Foreign {
    fn checkpoints_dir(&self, name: &str) -> PathBuf {
        self.ctx.paths.actor(name).join("checkpoints")
    }

    /// The checkpoints of `name`, oldest first.
    pub fn checkpoints(&self, name: &str) -> Vec<Checkpoint> {
        let Ok(entries) = std::fs::read_dir(self.checkpoints_dir(name)) else {
            return Vec::new();
        };
        let mut out: Vec<Checkpoint> = entries
            .flatten()
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .filter_map(|e| {
                let m: Meta =
                    serde_json::from_slice(&std::fs::read(e.path().join("meta.json")).ok()?)
                        .ok()?;
                Some(Checkpoint {
                    name: m.name,
                    lsn: m.lsn,
                    dir: e.path(),
                    at_ms: m.at_ms,
                    bytes: m.bytes,
                })
            })
            .collect();
        out.sort_by_key(|c| c.lsn);
        out
    }

    /// Checkpoints the running gVisor actor `name` at main's LSN `lsn`
    /// (§3): pause, copy the data directory, `runsc checkpoint
    /// --leave-running`, resume. `hold` keeps main's turns drained; it is
    /// dropped once main's calls to `name` wait in the daemon (the actor's
    /// call gate), so main runs on during the copy. `budget`: the room
    /// above `[log] disk_reserve`; a data directory bigger than it is not
    /// copied (no checkpoint, never a full disk).
    pub async fn checkpoint(
        &self,
        name: &str,
        lsn: u64,
        hold: Box<dyn std::any::Any + Send>,
        budget: Option<u64>,
    ) -> Result<Checkpoint, String> {
        let actor = crate::manager::lock(&self.actors).get(name).cloned();
        let a = actor.ok_or_else(|| format!("{name} is not running in this daemon"))?;
        if !matches!(a.runtime.engine, Engine::Runsc { .. }) {
            return Err(format!("{name} runs under runc, which has no checkpoints"));
        }
        if a.status().state != State::Running {
            return Err(format!("{name} is {}", a.status().state.as_str()));
        }
        if let Some(c) = self.checkpoints(name).into_iter().find(|c| c.lsn == lsn) {
            return Ok(c);
        }
        // No call is in flight (main is drained); from here main's calls to
        // `name` wait for the checkpoint, and main's other turns run. Not
        // waited for: only an earlier checkpoint still running (its snapshot
        // request gone, H1) holds the gate now, and waiting would keep main
        // drained for the rest of it (review M14 P1).
        let Ok(_calls) = a.calls.try_write() else {
            return Err(format!(
                "an earlier checkpoint of {name} is still running: none at lsn {lsn}"
            ));
        };
        drop(hold);
        // Measured with main running again (review M14 M1). The checkpoint
        // holds the data and the sandbox's memory, which its limit bounds
        // (review M14 M2).
        if let Some(room) = budget {
            let data = self.ctx.paths.data_dir(name);
            let bytes = self
                .ctx
                .env
                .blocking("foreign-checkpoint-size", move || dir_bytes(&data))
                .await
                .unwrap_or(0)
                .saturating_add(a.decl.memory_bytes);
            if bytes > room {
                return Err(format!(
                    "{name}'s data and memory take up to {bytes} bytes, more than the {room} \
                     bytes free above [log] disk_reserve: no checkpoint"
                ));
            }
        }
        let env = &self.ctx.env;
        let root = self.checkpoints_dir(name);
        let tmp = root.join(format!(".tmp-{}", dir_name(lsn)));
        let r = self.checkpoint_into(&a, name, lsn, &tmp).await;
        if r.is_err() {
            let tmp = tmp.clone();
            let _ = env
                .blocking("foreign-checkpoint-clean", move || {
                    std::fs::remove_dir_all(tmp)
                })
                .await;
        }
        r
    }

    async fn checkpoint_into(
        &self,
        a: &crate::supervisor::Actor,
        name: &str,
        lsn: u64,
        tmp: &Path,
    ) -> Result<Checkpoint, String> {
        let env = &self.ctx.env;
        let root = self.checkpoints_dir(name);
        let final_dir = root.join(dir_name(lsn));
        let data = self.ctx.paths.data_dir(name);
        let log = self.ctx.paths.log(name);
        let id = container_id(name);
        {
            let (root, tmp) = (root.clone(), tmp.to_path_buf());
            env.blocking("foreign-checkpoint-dir", move || {
                // Leftovers of failed or interrupted checkpoints (memory
                // images, which hold secrets).
                for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
                    if e.file_name().to_string_lossy().starts_with(".tmp-") {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
                private_dir(&tmp.join("image"))
            })
            .await
            .ok_or("checkpoint directory task dropped")?
            .map_err(|e| err("checkpoint directory", e))?;
        }
        // No connection may hang across the checkpoint.
        a.pool.clear();
        let started = env.clock.monotonic();
        let rt = &a.runtime;
        let ok = |r: io::Result<Option<i32>>, what: &str| match r {
            Ok(Some(0)) => Ok(()),
            Ok(code) => Err(format!("runsc {what} exited with {code:?}")),
            Err(e) => Err(err(&format!("runsc {what}"), e)),
        };
        let version = tmp.join("runsc-version");
        let _ = run_quick(env, rt.version(&version), QUICK).await;
        ok(
            run_quick(env, rt.pause(&id, false, &log), QUICK).await,
            "pause",
        )?;
        let copied = {
            let (data, to) = (data.clone(), tmp.join("data"));
            env.blocking("foreign-checkpoint-copy", move || copy_tree(&data, &to))
                .await
                .ok_or_else(|| "copy task dropped".to_owned())
                .and_then(|r| r.map_err(|e| err("copying the data directory", e)))
        };
        let saved = match &copied {
            Ok(_) => ok(
                run_quick(env, rt.checkpoint(&id, &tmp.join("image"), &log), QUICK).await,
                "checkpoint",
            ),
            Err(e) => Err(e.clone()),
        };
        // Always resume, whatever failed.
        let resumed = resume(env, rt, &id, &log).await;
        resumed?;
        saved?;
        let bytes = copied?;
        let paused_ms = env.clock.monotonic().saturating_sub(started).as_millis();
        let meta = Meta {
            name: name.to_owned(),
            lsn,
            image: a.decl.image.clone(),
            platform: match &a.runtime.engine {
                Engine::Runsc { platform } => platform.clone(),
                Engine::Runc => String::new(),
            },
            runsc: String::new(),
            port: a.decl.port,
            at_ms: env.clock.wall_ms(),
            bytes,
        };
        let keep = self.cfg.checkpoints_kept.max(1);
        let (root2, tmp) = (root.clone(), tmp.to_path_buf());
        let spec = crate::manager::lock(&a.spec).clone();
        if spec.is_empty() {
            return Err(format!("{name} has no runtime spec: it is not running"));
        }
        let done = env
            .blocking("foreign-checkpoint-finish", move || -> io::Result<()> {
                let mut meta = meta;
                meta.runsc = std::fs::read_to_string(&version)
                    .unwrap_or_default()
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim_start_matches("runsc version ")
                    .to_owned();
                let _ = std::fs::remove_file(&version);
                write_private(&tmp.join("config.json"), &spec)?;
                let meta = serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?;
                write_private(&tmp.join("meta.json"), &meta)?;
                let _ = std::fs::remove_dir_all(&final_dir);
                std::fs::rename(&tmp, &final_dir)?;
                prune(&root2, keep);
                Ok(())
            })
            .await
            .ok_or("checkpoint task dropped")?;
        done.map_err(|e| err("writing the checkpoint", e))?;
        tracing::info!(name, lsn, bytes, paused_ms, "checkpointed a foreign actor");
        self.checkpoints(name)
            .into_iter()
            .find(|c| c.lsn == lsn)
            .ok_or_else(|| format!("checkpoint {lsn} of {name} is missing"))
    }

    /// Starts a fork's copy of `spec.name` from `spec.checkpoint` (§4):
    /// its own data copy in a new directory under `spec.dir`, network
    /// namespace and cgroup, `runsc restore`, and a bridge connection that
    /// proves it answers.
    pub async fn start_copy(&self, spec: CopySpec) -> Result<Arc<Copy>, String> {
        let env = self.ctx.env.clone();
        let ck = spec.checkpoint.dir.clone();
        let meta: Meta = serde_json::from_slice(
            &std::fs::read(ck.join("meta.json")).map_err(|e| err("checkpoint meta.json", e))?,
        )
        .map_err(|e| err("checkpoint meta.json", e))?;
        let key = copy_key(&spec.fork, &spec.name);
        let id = format!("kronik-copy-{key}");
        let netns = self.ctx.paths.netns_dir().join(format!("copy-{key}"));
        let sock_dir = self.ctx.paths.sock_root().join(format!("copy-{key}"));
        let cgroup = format!("{}/copy-{key}", self.ctx.cgroup_parent);
        let dir = spec.dir.join(&key);
        let bundle = dir.join("bundle");
        let log = dir.join("output.log");
        let runtime = Runtime {
            engine: Engine::Runsc {
                platform: if meta.platform.is_empty() {
                    "systrap".into()
                } else {
                    meta.platform.clone()
                },
            },
            program: self.cfg.runsc_path.clone(),
            root: self.ctx.paths.run.join("runsc"),
        };
        {
            let (dir, bundle, netns, sock_dir) =
                (dir.clone(), bundle.clone(), netns.clone(), sock_dir.clone());
            let ck = ck.clone();
            let cgroup = cgroup.clone();
            env.blocking("foreign-copy-prepare", move || -> io::Result<()> {
                let _ = std::fs::remove_dir_all(&dir);
                private_dir(&dir)?;
                copy_tree(&ck.join("data"), &dir.join("data"))?;
                let mut spec: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(ck.join("config.json"))?)
                        .map_err(io::Error::other)?;
                copy_spec(&mut spec, &dir.join("data"), &netns, &cgroup);
                private_dir(&bundle)?;
                write_private(
                    &bundle.join("config.json"),
                    &serde_json::to_vec_pretty(&spec).map_err(io::Error::other)?,
                )?;
                let _ = crate::sys::delete_netns(&netns);
                std::fs::create_dir_all(netns.parent().unwrap_or(Path::new("/")))?;
                crate::sys::create_netns(&netns)?;
                let _ = std::fs::remove_dir_all(&sock_dir);
                private_dir(&sock_dir)
            })
            .await
            .ok_or("copy preparation task dropped")?
            .map_err(|e| err("preparing the copy", e))?;
        }
        let copy = Arc::new(CopyInner {
            env: env.clone(),
            name: spec.name.clone(),
            id: id.clone(),
            runtime: runtime.clone(),
            dialer: Dialer::PortForward {
                runtime: runtime.clone(),
                id: id.clone(),
                port: u16::try_from(meta.port).unwrap_or(0),
                sock_dir: sock_dir.clone(),
                log: log.clone(),
            },
            pool: Pool::default(),
            netns,
            sock_dir,
            dir,
            log: log.clone(),
            stopped: AtomicBool::new(false),
        });
        {
            let mut all = crate::manager::lock(&self.copies);
            all.retain(|c| c.strong_count() > 0);
            all.push(Arc::downgrade(&copy));
        }
        let restored = run_quick(
            &env,
            runtime.restore(&bundle, &id, &ck.join("image"), &log),
            QUICK,
        )
        .await;
        if !matches!(restored, Ok(Some(0))) {
            copy.stop_now().await;
            return Err(format!(
                "runsc restore of {} failed ({restored:?}); see {}",
                spec.name,
                log.display()
            ));
        }
        // runsc read the spec when it restored the container; the copy with
        // the secret values goes now, as production's does once it runs.
        {
            let config = bundle.join("config.json");
            let _ = env
                .blocking("foreign-copy-config", move || std::fs::remove_file(config))
                .await;
        }
        let started = env.clock.monotonic();
        loop {
            match crate::bridge::dial(&env, &copy.pool, &copy.dialer).await {
                Ok(sender) => {
                    copy.pool.put(sender);
                    break;
                }
                Err(e) if env.clock.monotonic().saturating_sub(started) > COPY_READY => {
                    copy.stop_now().await;
                    return Err(format!("the copy of {} does not answer: {e}", spec.name));
                }
                Err(_) => env.clock.sleep(Duration::from_millis(50)).await,
            }
        }
        tracing::info!(fork = %spec.fork, name = %spec.name, lsn = spec.checkpoint.lsn, id, "started a fork copy of a foreign actor");
        Ok(Arc::new(Copy(copy)))
    }
}

/// The checkpoint's runtime spec for a copy: its data directory, network
/// namespace and cgroup.
fn copy_spec(spec: &mut serde_json::Value, data: &Path, netns: &Path, cgroup: &str) {
    if let Some(mounts) = spec["mounts"].as_array_mut() {
        for m in mounts {
            if m["destination"] == "/data" {
                m["source"] = data.display().to_string().into();
            }
        }
    }
    if let Some(nss) = spec["linux"]["namespaces"].as_array_mut() {
        for n in nss {
            if n["type"] == "network" {
                n["path"] = netns.display().to_string().into();
            }
        }
    }
    spec["linux"]["cgroupsPath"] = cgroup.into();
}

/// Deletes the oldest checkpoints beyond `keep`.
fn prune(root: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    let excess = dirs.len().saturating_sub(keep);
    for d in dirs.into_iter().take(excess) {
        if let Err(e) = std::fs::remove_dir_all(&d) {
            tracing::warn!(path = %d.display(), error = %e, "could not delete an old checkpoint");
        }
    }
}

/// A fork's copy of a foreign actor.
pub struct Copy(Arc<CopyInner>);

pub(crate) struct CopyInner {
    env: Env,
    name: String,
    id: String,
    runtime: Runtime,
    dialer: Dialer,
    pool: Pool,
    netns: PathBuf,
    sock_dir: PathBuf,
    dir: PathBuf,
    log: PathBuf,
    stopped: AtomicBool,
}

impl CopyInner {
    /// Kills and deletes the container, its namespace, sockets and disk.
    pub(crate) async fn stop_now(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        self.pool.clear();
        self.removal().await;
    }

    /// What stopping does once the copy is unreachable, as an owned future.
    fn removal(&self) -> impl Future<Output = ()> + Send + 'static {
        let (env, runtime, id, log) = (
            self.env.clone(),
            self.runtime.clone(),
            self.id.clone(),
            self.log.clone(),
        );
        let (name, netns, sock, dir) = (
            self.name.clone(),
            self.netns.clone(),
            self.sock_dir.clone(),
            self.dir.clone(),
        );
        async move {
            let _ = run_quick(&env, runtime.kill(&id, "KILL", &log), QUICK).await;
            let _ = run_quick(&env, runtime.delete(&id, &log), QUICK).await;
            let _ = env
                .blocking("foreign-copy-cleanup", move || {
                    let _ = crate::sys::delete_netns(&netns);
                    let _ = std::fs::remove_dir_all(&sock);
                    let _ = std::fs::remove_dir_all(&dir);
                })
                .await;
            tracing::info!(name = %name, id = %id, "stopped a fork copy of a foreign actor");
        }
    }
}

impl Drop for CopyInner {
    /// A copy nobody stopped, because the replay or proposal that started
    /// it was cancelled (review M14 M3), holds production data and secret
    /// values in its memory: stopped now.
    fn drop(&mut self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            self.env.spawn("fork-copy-stop", self.removal());
        }
    }
}

impl ForeignCopy for Copy {
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
        let c = self.0.clone();
        Box::pin(async move { crate::bridge::send(&c.env, &c.pool, &c.dialer, &c.name, req).await })
    }

    fn stop(&self) -> BoxFuture<'static, ()> {
        let c = self.0.clone();
        Box::pin(async move { c.stop_now().await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As images are unpacked (oci.rs): a checkpoint's or a copy's data keeps
    /// modes and the sticky bit, never setuid or setgid.
    #[test]
    fn copied_data_keeps_modes_but_not_setid_bits() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        for (dir, mode) in [("shared", 0o2777), ("sticky", 0o1777)] {
            std::fs::create_dir_all(from.join(dir)).unwrap();
            std::fs::set_permissions(from.join(dir), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        std::fs::write(from.join("suid"), b"x").unwrap();
        std::fs::set_permissions(from.join("suid"), std::fs::Permissions::from_mode(0o4755))
            .unwrap();
        let to = tmp.path().join("to");
        assert_eq!(copy_tree(&from, &to).unwrap(), 1);
        let mode = |p: &str| std::fs::metadata(to.join(p)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode("shared"), 0o777);
        assert_eq!(mode("sticky"), 0o1777);
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(std::fs::read(to.join("suid")).unwrap(), b"x");
    }

    #[test]
    fn a_copy_spec_gets_its_own_disk_namespace_and_cgroup() {
        let mut spec = serde_json::json!({
            "root": {"path": "/srv/foreign/pg/rootfs", "readonly": true},
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/data", "type": "bind", "source": "/srv/foreign/pg/data"}
            ],
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "network", "path": "/run/kronik/netns/pg"}],
                "cgroupsPath": "kronik/pg"
            }
        });
        copy_spec(
            &mut spec,
            Path::new("/srv/branches/f-1/foreign/pg/data"),
            Path::new("/run/kronik/netns/copy-k"),
            "kronik/copy-k",
        );
        assert_eq!(spec["mounts"][0]["source"], "proc");
        assert_eq!(
            spec["mounts"][1]["source"],
            "/srv/branches/f-1/foreign/pg/data"
        );
        assert_eq!(
            spec["linux"]["namespaces"][0],
            serde_json::json!({"type": "pid"})
        );
        assert_eq!(
            spec["linux"]["namespaces"][1]["path"],
            "/run/kronik/netns/copy-k"
        );
        assert_eq!(spec["linux"]["cgroupsPath"], "kronik/copy-k");
        // The image's root filesystem is shared, read-only.
        assert_eq!(spec["root"]["path"], "/srv/foreign/pg/rootfs");
    }

    #[test]
    fn copy_ids_have_one_length_and_are_new_per_start() {
        let a = copy_key("f-1", "pg");
        assert_eq!(a.len(), 16);
        assert_ne!(a, copy_key("f-1", "pg"));
    }

    /// A sandbox that does not resume is retried, then killed so its
    /// supervisor restarts it (review M12).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sandbox_that_does_not_resume_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let program = dir.path().join("runsc");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"$3 $4\" >> {}\n[ \"$3\" = resume ] && exit 1\nexit 0\n",
                calls.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rt = Runtime {
            engine: Engine::Runsc {
                platform: "systrap".into(),
            },
            program,
            root: dir.path().join("root"),
        };
        let env = Env::real(tokio::runtime::Handle::current());
        let r = resume(&env, &rt, "x", &dir.path().join("log")).await;
        assert!(r.is_err());
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap(),
            "resume x\nresume x\nresume x\nkill x\n"
        );
    }

    #[test]
    fn prune_keeps_the_newest_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        for lsn in [5, 40, 300, 7] {
            std::fs::create_dir(dir.path().join(dir_name(lsn))).unwrap();
        }
        std::fs::create_dir(dir.path().join(".tmp-x")).unwrap();
        prune(dir.path(), 2);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, [".tmp-x", &dir_name(40), &dir_name(300)]);
    }
}
