//! Full Firecracker snapshots use the same main-drain/actor-call gates as M14.
//! Disks and restored memory backing are owned by the checkpoint/copy lifetime.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use kronik_effects::foreign::{Checkpoint, CopySpec};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::bridge::{Dialer, Pool};
use crate::checkpoint::{Copy, CopyInner, Meta, copy_key, private_dir, prune, write_private};
use crate::manager::{Foreign, lock};
use crate::microvm::{DATA_BYTES, Resources, Start, Vm};
use crate::microvm_assets::{Assets, Identity};
use crate::runtime::{Engine, Runtime};
use crate::supervisor::Actor;

const SCHEMA: &str = "kronik.microvm-checkpoint/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MicrovmMeta {
    pub schema: String,
    pub tools: Identity,
    pub host: String,
    pub root_sha256: String,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub resources: Resources,
}

/// The conservative restore contract is the same host-kernel build and CPU
/// model/features, not a promise that snapshots migrate between CPU models.
fn host_identity() -> Result<String, String> {
    let kernel = fs::read("/proc/version").map_err(|e| e.to_string())?;
    let cpu = fs::read_to_string("/proc/cpuinfo").map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    hash.update(std::env::consts::ARCH.as_bytes());
    hash.update(&kernel);
    let first = cpu
        .split("\n\n")
        .next()
        .ok_or("empty host CPU information")?;
    let mut fields = 0;
    for line in first.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(
            name.trim(),
            "vendor_id"
                | "cpu family"
                | "model"
                | "stepping"
                | "flags"
                | "Features"
                | "CPU implementer"
                | "CPU architecture"
                | "CPU variant"
                | "CPU part"
                | "CPU revision"
        ) {
            hash.update(name.trim().as_bytes());
            hash.update([0]);
            hash.update(value.trim().as_bytes());
            hash.update([0]);
            fields += 1;
        }
    }
    if fields < 2 {
        return Err("host CPU identity is unavailable".into());
    }
    Ok(crate::blobs::hex(&hash.finalize()))
}

/// Copies the snapshot Firecracker wrote into `output` to `image/memory` and
/// `image/state`, empties the VMM's files and returns the memory file's
/// length. The copies are new files private to the daemon's user (0600),
/// whatever mode the VMM wrote with.
///
/// The files stay where they are: the VMM's jail binds each of them, and a
/// rename or an unlink would leave the jail writing to a file the daemon no
/// longer sees. `output` is the VMM's directory, so each file is opened
/// without following a link or blocking on a FIFO and must be a regular file
/// with one link (see `microvm::snapshot_file`); a snapshot that is anything
/// else, or empty, fails the checkpoint, which is discarded.
fn copy_snapshot(output: &Path, image: &Path) -> io::Result<u64> {
    use crate::microvm::{SNAPSHOT_MEMORY, SNAPSHOT_STATE, snapshot_file};
    let mut memory = 0;
    for (from, to) in [(SNAPSHOT_MEMORY, "memory"), (SNAPSHOT_STATE, "state")] {
        let file = snapshot_file(output, from, false)?;
        let bytes = crate::microvm_sys::copy_from(file, &image.join(to))?;
        if bytes == 0 {
            return Err(io::Error::other(format!("the VMM wrote no {from}")));
        }
        if to == "memory" {
            memory = bytes;
        }
    }
    crate::microvm::empty_snapshot(output)?;
    Ok(memory)
}

fn sync_tree(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            sync_tree(&entry.path())?;
        } else if metadata.is_file() {
            File::open(entry.path())?.sync_all()?;
        } else {
            return Err(io::Error::other("unexpected checkpoint entry type"));
        }
    }
    File::open(path)?.sync_all()
}

struct PendingCopy(PathBuf);
impl PendingCopy {
    fn create(path: PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for PendingCopy {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

impl Foreign {
    pub(crate) async fn checkpoint_microvm(
        &self,
        actor: &Actor,
        name: &str,
        lsn: u64,
        tmp: &Path,
    ) -> Result<Checkpoint, String> {
        let env = &self.ctx.env;
        let vm = lock(&actor.vm)
            .clone()
            .ok_or("microVM is no longer running")?;
        let asset_dir = self.ctx.microvm_dir.clone();
        let rootfs = self.ctx.paths.bundle(name).join("root.ext4");
        let root_copy = rootfs.clone();
        let (assets, host, root_sha256, root_bytes) = env
            .blocking("foreign-vm-checkpoint-identity", move || {
                let bytes = fs::metadata(&root_copy).map_err(|e| e.to_string())?.len();
                Ok::<_, String>((
                    Assets::load(&asset_dir)?,
                    host_identity()?,
                    crate::microvm_assets::digest(&root_copy)?,
                    bytes,
                ))
            })
            .await
            .ok_or("microVM identity task dropped")??;
        let resources = Resources::new(actor.decl.cpu_millis, actor.decl.memory_bytes)?;
        // The snapshot's memory is on the disk twice until the VMM's file is
        // emptied: as the VMM wrote it and as the checkpoint's copy.
        let required = DATA_BYTES
            .saturating_add(u64::from(resources.guest_mib) << 21)
            .saturating_add(root_bytes)
            .saturating_add(1 << 20)
            .saturating_add(self.ctx.disk_reserve);
        let room = env
            .fs
            .available(self.ctx.paths.actor(name))
            .await
            .map_err(|e| e.to_string())?;
        if room < required {
            return Err("not enough space on the actor filesystem above disk_reserve for a full microVM checkpoint".into());
        }
        let root = self.checkpoints_dir(name);
        let temporary = tmp.to_path_buf();
        let output = vm.output.clone();
        env.blocking(
            "foreign-vm-checkpoint-prepare",
            move || -> io::Result<()> {
                if temporary.exists() {
                    fs::remove_dir_all(&temporary)?;
                }
                private_dir(&temporary.join("image"))?;
                crate::microvm::empty_snapshot(&output)
            },
        )
        .await
        .ok_or("microVM checkpoint preparation dropped")?
        .map_err(|e| e.to_string())?;
        actor.pool.clear();
        let started = env.clock.monotonic();
        let copied = async {
            vm.pause(env, true).await?;
            vm.snapshot(env).await?;
            let source_data = self.ctx.paths.actor(name).join("data.ext4");
            let output = vm.output.clone();
            let temporary = tmp.to_path_buf();
            env.blocking(
                "foreign-vm-checkpoint-disks",
                move || -> Result<u64, String> {
                    File::open(&source_data)
                        .and_then(|f| f.sync_all())
                        .map_err(|e| e.to_string())?;
                    let data = crate::microvm_sys::copy_reserved(
                        &source_data,
                        &temporary.join("data.ext4"),
                    )
                    .map_err(|e| e.to_string())?;
                    let root =
                        crate::microvm_sys::copy(&rootfs, &temporary.join("image/root.ext4"))
                            .map_err(|e| e.to_string())?;
                    let memory = copy_snapshot(&output, &temporary.join("image"))
                        .map_err(|e| e.to_string())?;
                    Ok(data.saturating_add(root).saturating_add(memory))
                },
            )
            .await
            .ok_or("microVM disk copy task dropped")?
        }
        .await;
        // Always resume, including ENOSPC/API/copy errors. A VM that will not
        // resume is killed and its existing supervisor restarts production.
        let mut resumed = false;
        for _ in 0..3 {
            if vm.pause(env, false).await.is_ok() {
                resumed = true;
                break;
            }
        }
        let killed = if !resumed { vm.kill(env).await } else { Ok(()) };
        if copied.is_err() || !resumed {
            let vm = vm.clone();
            env.blocking("foreign-vm-snapshot-discard", move || vm.discard_snapshot())
                .await
                .ok_or("snapshot cleanup task dropped")?
                .map_err(|e| e.to_string())?;
        }
        killed?;
        if !resumed {
            return Err(
                "microVM did not resume after checkpoint; killed for supervisor restart".into(),
            );
        }
        let bytes = copied?;
        let paused_ms = env.clock.monotonic().saturating_sub(started).as_millis();
        let meta = Meta {
            name: name.into(),
            lsn,
            image: actor.decl.image.clone(),
            platform: "firecracker".into(),
            runsc: String::new(),
            port: actor.decl.port,
            at_ms: env.clock.wall_ms(),
            bytes,
            microvm: Some(MicrovmMeta {
                schema: SCHEMA.into(),
                tools: assets.identity,
                host,
                root_sha256,
                cpu_millis: actor.decl.cpu_millis,
                memory_bytes: actor.decl.memory_bytes,
                resources,
            }),
        };
        let spec = lock(&actor.spec).clone();
        if spec.is_empty() {
            return Err("running microVM has no resolved process configuration".into());
        }
        let keep = self.cfg.checkpoints_kept.max(1);
        let temporary = tmp.to_path_buf();
        let final_dir = root.join(format!("{lsn:020}"));
        env.blocking(
            "foreign-vm-checkpoint-publish",
            move || -> io::Result<()> {
                write_private(&temporary.join("config.json"), &spec)?;
                write_private(
                    &temporary.join("meta.json"),
                    &serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?,
                )?;
                sync_tree(&temporary)?;
                crate::microvm_sys::publish(&temporary, &final_dir)?;
                File::open(&root)?.sync_all()?;
                prune(&root, keep);
                Ok(())
            },
        )
        .await
        .ok_or("microVM checkpoint publication dropped")?
        .map_err(|e| e.to_string())?;
        tracing::info!(
            name,
            lsn,
            bytes,
            paused_ms,
            "checkpointed a microVM foreign actor"
        );
        self.checkpoints(name)
            .into_iter()
            .find(|c| c.lsn == lsn)
            .ok_or("published microVM checkpoint is missing".into())
    }

    pub(crate) async fn start_microvm_copy(
        &self,
        spec: CopySpec,
        meta: Meta,
    ) -> Result<Arc<Copy>, String> {
        let env = &self.ctx.env;
        let expected = meta.microvm.ok_or("checkpoint has no microVM identity")?;
        if expected.schema != SCHEMA
            || expected.resources != Resources::new(expected.cpu_millis, expected.memory_bytes)?
        {
            return Err("unsupported or inconsistent microVM checkpoint resource format".into());
        }
        let asset_dir = self.ctx.microvm_dir.clone();
        let checkpoint = spec.checkpoint.dir.clone();
        let root_source = checkpoint.join("image/root.ext4");
        let (assets, host, root_sha256) = env
            .blocking("foreign-vm-restore-identity", move || {
                Ok::<_, String>((
                    Assets::load(&asset_dir)?,
                    host_identity()?,
                    crate::microvm_assets::digest(&root_source)?,
                ))
            })
            .await
            .ok_or("microVM restore identity task dropped")??;
        if assets.identity != expected.tools
            || host != expected.host
            || root_sha256 != expected.root_sha256
        {
            return Err("microVM checkpoint tools, host kernel/CPU or immutable root do not match; use its recorded fork mode on a different host".into());
        }
        let parent = spec.dir.clone();
        env.blocking("foreign-vm-copy-root", move || private_dir(&parent))
            .await
            .ok_or("copy root task dropped")?
            .map_err(|e| e.to_string())?;
        let room = env
            .fs
            .available(spec.dir.clone())
            .await
            .map_err(|e| e.to_string())?;
        let memory = fs::metadata(checkpoint.join("image/memory"))
            .map_err(|e| e.to_string())?
            .len();
        let root_bytes = fs::metadata(checkpoint.join("image/root.ext4"))
            .map_err(|e| e.to_string())?
            .len();
        let needed = DATA_BYTES
            .saturating_add(memory)
            .saturating_add(root_bytes)
            .saturating_add(self.ctx.disk_reserve);
        if room < needed {
            return Err(
                "not enough disk space above disk_reserve for a complete microVM fork copy".into(),
            );
        }
        let key = copy_key(&spec.fork, &spec.name);
        let id = format!("kronik-copy-{key}");
        let directory = spec.dir.join(&key);
        let pending = directory.clone();
        let mut pending = env
            .blocking("foreign-vm-copy-private", move || {
                PendingCopy::create(pending)
            })
            .await
            .ok_or("private copy task dropped")?
            .map_err(|e| e.to_string())?;
        let destination = directory.clone();
        let source = checkpoint.clone();
        env.blocking("foreign-vm-copy-backing", move || -> io::Result<()> {
            private_dir(&destination.join("out"))?;
            crate::microvm_sys::copy_reserved(
                &source.join("data.ext4"),
                &destination.join("data.ext4"),
            )?;
            crate::microvm_sys::copy(
                &source.join("image/root.ext4"),
                &destination.join("root.ext4"),
            )?;
            crate::microvm_sys::copy(
                &source.join("image/memory"),
                &destination.join("out/restore.mem"),
            )?;
            crate::microvm_sys::copy(
                &source.join("image/state"),
                &destination.join("out/restore.state"),
            )?;
            Ok(())
        })
        .await
        .ok_or("microVM copy backing task dropped")?
        .map_err(|e| e.to_string())?;
        let config_bytes = fs::read(checkpoint.join("config.json")).map_err(|e| e.to_string())?;
        let config = crate::microvm::guest_config(&config_bytes, meta.port as u16, &spec.name)?;
        let root = self.ctx.paths.run.join("microvm").join(&id).join("jail");
        let output = directory.join("out");
        let cgroup = format!("{}/copy-{key}", self.ctx.cgroup_parent);
        let log = directory.join("output.log");
        let vm = Vm::spawn(
            env,
            Start {
                assets: &assets,
                root: &root,
                output: &output,
                rootfs: &directory.join("root.ext4"),
                data: &directory.join("data.ext4"),
                config: &config,
                cgroup: &cgroup,
                cpu_millis: expected.cpu_millis,
                memory_bytes: expected.memory_bytes,
                log: &log,
                restore: true,
            },
        )
        .await?;
        let dialer = Dialer::Vsock {
            socket: root.join("vsock.sock"),
            cgroup: cgroup.clone(),
        };
        let copy = Arc::new(CopyInner {
            env: env.clone(),
            name: spec.name.clone(),
            id,
            runtime: Runtime {
                engine: Engine::Firecracker,
                program: assets.firecracker,
                root: self.ctx.paths.run.join("microvm"),
            },
            dialer,
            pool: Pool::default(),
            netns: PathBuf::new(),
            sock_dir: PathBuf::new(),
            dir: directory,
            log,
            stopped: AtomicBool::new(false),
            vm: Some(vm.clone()),
        });
        pending.0.clear();
        {
            let mut copies = lock(&self.copies);
            copies.retain(|c| c.strong_count() > 0);
            copies.push(Arc::downgrade(&copy));
        }
        if let Err(error) = vm.boot(env).await {
            copy.stop_now().await;
            return Err(error);
        }
        let started = env.clock.monotonic();
        loop {
            match crate::bridge::dial(env, &copy.pool, &copy.dialer).await {
                Ok(sender) => {
                    copy.pool.put(sender);
                    break;
                }
                Err(error)
                    if env.clock.monotonic().saturating_sub(started) >= Duration::from_secs(20) =>
                {
                    copy.stop_now().await;
                    return Err(format!("restored microVM copy did not answer: {error}"));
                }
                Err(_) => env.clock.sleep(Duration::from_millis(50)).await,
            }
        }
        tracing::info!(fork=%spec.fork, name=%spec.name, lsn=spec.checkpoint.lsn, "started a microVM fork copy");
        Ok(Arc::new(Copy(copy)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_copy_preparation_removes_only_its_new_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("production");
        fs::write(&source, b"unchanged").unwrap();
        let target = root.path().join("copy");
        {
            let pending = PendingCopy::create(target.clone()).unwrap();
            fs::write(pending.0.join("memory"), b"guest-secret").unwrap();
            assert_eq!(
                fs::metadata(&pending.0).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(!target.exists());
        assert_eq!(fs::read(&source).unwrap(), b"unchanged");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("existing"), b"keep").unwrap();
        assert!(PendingCopy::create(target.clone()).is_err());
        assert_eq!(fs::read(target.join("existing")).unwrap(), b"keep");
    }

    #[test]
    fn a_snapshot_is_copied_into_the_image_private_to_the_daemon_and_the_vmms_files_emptied() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let (output, image) = (dir.path().join("out"), dir.path().join("image"));
        fs::create_dir_all(&output).unwrap();
        fs::create_dir_all(&image).unwrap();
        // Firecracker writes with the VMM's umask: readable by others here.
        fs::write(output.join("checkpoint.mem"), vec![7u8; 4096]).unwrap();
        fs::write(output.join("checkpoint.state"), b"state").unwrap();
        for name in ["checkpoint.mem", "checkpoint.state"] {
            fs::set_permissions(output.join(name), fs::Permissions::from_mode(0o666)).unwrap();
        }
        assert_eq!(copy_snapshot(&output, &image).unwrap(), 4096);
        for name in ["memory", "state"] {
            let mode = fs::metadata(image.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
        assert_eq!(fs::read(image.join("memory")).unwrap(), vec![7u8; 4096]);
        assert_eq!(fs::read(image.join("state")).unwrap(), b"state");
        // The VMM's files stay, empty, for the jail's binds of them.
        for name in ["checkpoint.mem", "checkpoint.state"] {
            assert_eq!(fs::metadata(output.join(name)).unwrap().len(), 0, "{name}");
        }
        // An empty snapshot, one the VMM did not write, is no checkpoint.
        let again = dir.path().join("again");
        fs::create_dir_all(&again).unwrap();
        assert!(copy_snapshot(&output, &again).is_err());
        // Nor is one whose files are missing.
        fs::remove_file(output.join("checkpoint.state")).unwrap();
        assert!(crate::microvm::empty_snapshot(&output).is_err());
    }

    /// Were the VMM able to leave something else as `checkpoint.mem` (its
    /// `out` is read-only, so it is not): a link, a second name for a file of
    /// the host, a FIFO. None of them is followed, read, emptied or changed,
    /// and the checkpoint fails.
    #[test]
    fn a_snapshot_that_is_not_a_plain_file_is_refused_and_nothing_it_names_is_changed() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("setuid-tool");
        fs::write(&victim, b"host file").unwrap();
        let setuid = fs::Permissions::from_mode(0o4755);
        fs::set_permissions(&victim, setuid).unwrap();
        let before = fs::metadata(&victim).unwrap();
        for case in ["link", "hard link", "fifo", "directory"] {
            let (output, image) = (
                dir.path().join(case),
                dir.path().join(format!("image-{case}")),
            );
            fs::create_dir_all(&output).unwrap();
            fs::create_dir_all(&image).unwrap();
            fs::write(output.join("checkpoint.state"), b"state").unwrap();
            let mem = output.join("checkpoint.mem");
            match case {
                "link" => symlink(&victim, &mem).unwrap(),
                "hard link" => fs::hard_link(&victim, &mem).unwrap(),
                "fifo" => {
                    // No safe binding in this crate: the command makes it.
                    let made = std::process::Command::new("mkfifo").arg(&mem).status();
                    if !matches!(made, Ok(status) if status.success()) {
                        eprintln!("skipped the FIFO case: mkfifo is not available");
                        continue;
                    }
                }
                _ => fs::create_dir(&mem).unwrap(),
            }
            let error = copy_snapshot(&output, &image).unwrap_err();
            assert!(!error.to_string().is_empty(), "{case}");
            // Emptying (a discarded checkpoint) refuses it too.
            assert!(crate::microvm::empty_snapshot(&output).is_err(), "{case}");
            let after = fs::metadata(&victim).unwrap();
            assert_eq!(
                after.mode() & 0o7777,
                0o4755,
                "{case}: the host file's mode changed"
            );
            assert_eq!(
                (after.dev(), after.ino(), after.len()),
                (before.dev(), before.ino(), before.len())
            );
            assert_eq!(fs::read(&victim).unwrap(), b"host file");
        }
    }

    #[test]
    fn snapshot_metadata_rejects_wrong_schema_fields_and_resource_rounding() {
        assert!(
            serde_json::from_value::<MicrovmMeta>(
                serde_json::json!({"schema":SCHEMA,"unexpected":true})
            )
            .is_err()
        );
        assert_ne!(Resources::new(2001, 512 << 20).unwrap().vcpus, 3);
    }
}
