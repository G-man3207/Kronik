//! Fixed Firecracker backend. The daemon never downloads tools or grants a VMM
//! the daemon's filesystem/network namespace. The launcher runs before threads.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::{Env, Process, ProcessSpec, Stdio};
use kronik_guest_init::GuestConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::microvm_assets::Assets;

pub(crate) const DATA_BYTES: u64 = 1 << 30;
/// Guest RAM is separate from VMM threads, device state and mapped metadata.
/// Calibration is a required real-KVM conformance result, not a guest quota.
pub(crate) const VMM_OVERHEAD: u64 = 128 << 20;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const LAUNCH_SCHEMA: &str = "kronik.microvm-launch/v1";
const MAX_LAUNCH: u64 = 32 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Resources {
    pub vcpus: u8,
    pub guest_mib: u32,
    pub host_bytes: u64,
}

impl Resources {
    pub fn new(cpu_millis: u32, memory_bytes: u64) -> Result<Self, String> {
        if !(10..=32_000).contains(&cpu_millis) {
            return Err("microvm CPU must be between 0.01 and 32 CPUs".into());
        }
        let requested = cpu_millis.div_ceil(1000);
        // Firecracker accepts one vCPU, or an even number. The cgroup still
        // enforces the caller's exact milliCPU quota, not the rounded topology.
        let vcpus = if requested == 1 {
            1
        } else {
            requested.next_multiple_of(2)
        };
        let guest_mib = u32::try_from(memory_bytes >> 20)
            .map_err(|_| "microvm RAM exceeds Firecracker's MiB range")?;
        if guest_mib < 128 {
            return Err("microvm memory must be at least 128Mi of guest RAM".into());
        }
        let host_bytes = (u64::from(guest_mib) << 20)
            .checked_add(VMM_OVERHEAD)
            .ok_or("microvm RAM plus VMM overhead overflows")?;
        Ok(Self {
            vcpus: vcpus as u8,
            guest_mib,
            host_bytes,
        })
    }
}

/// Typed inputs to the single-purpose, single-threaded child launcher. No shell,
/// ambient environment, arbitrary bind list or arbitrary executable is accepted.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Launch {
    schema: String,
    root: PathBuf,
    cgroup: String,
    cpu_millis: u32,
    memory_bytes: u64,
    firecracker: PathBuf,
    kernel: PathBuf,
    initrd: PathBuf,
    rootfs: PathBuf,
    data: PathBuf,
    output: PathBuf,
    parent_pid: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    cgroup: String,
}

struct Unspawned(PathBuf);
impl Drop for Unspawned {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// The drop-in that gives the root service's daemon the cgroup leaf a microVM
/// needs. The root unit is the one of v0.4.0 and delegates no cgroup (a
/// delegation would move where an existing installation's gVisor sandboxes
/// get their cgroups), so a host that runs microVMs adds this itself. The
/// nonroot service has the same by design. `DelegateSubgroup=` is new in
/// systemd 254; older versions ignore it with a warning and leave the daemon
/// in the unit's own cgroup, which `kronik doctor` then reports. The
/// operations guide shows the same text (a test keeps them equal).
pub const ROOT_LEAF_DROPIN: &str = "[Service]\nDelegate=yes\nDelegateSubgroup=daemon\n";
/// Where the guide puts the drop-in.
pub const ROOT_LEAF_DROPIN_PATH: &str = "/etc/systemd/system/kronik.service.d/microvm.conf";
/// The first sentence of the refusal and of the warning.
pub const ROOT_LEAF_NEED: &str = "microVM actors need the daemon in a delegated cgroup leaf, which the root service's unit does not give it";

/// What to do about [`ROOT_LEAF_NEED`].
pub fn root_leaf_advice() -> String {
    format!(
        "Add `Delegate=yes` and `DelegateSubgroup=daemon` under [Service] in a drop-in such as \
         {ROOT_LEAF_DROPIN_PATH} (systemd 254 or newer; the operations guide has the whole \
         file), run `systemctl daemon-reload` and restart kronik.service. Or use isolation gvisor."
    )
}

/// Whether the daemon is where a microVM's cgroup goes: the root service must
/// run in the leaf of its delegated cgroup (a direct root `serve` never makes
/// one: it could be an unrelated shell's cgroup), the nonroot service moved
/// itself into one before it could start foreign actors.
pub fn require_leaf(
    privilege: &crate::manager::Privilege,
    own_cgroup: io::Result<String>,
) -> Result<(), String> {
    use crate::manager::Privilege;
    match privilege {
        Privilege::Root => match own_cgroup {
            Ok(cgroup) if cgroup.ends_with("/daemon") => Ok(()),
            Ok(cgroup) => Err(format!("{ROOT_LEAF_NEED} (the daemon runs in {cgroup})")),
            Err(e) => Err(format!(
                "{ROOT_LEAF_NEED} (the daemon's cgroup is unreadable: {e})"
            )),
        },
        Privilege::Userns { .. } | Privilege::Unavailable(_) => Ok(()),
    }
}

/// How a process that was waited for ended, for a message.
fn describe_exit(status: io::Result<Option<i32>>) -> String {
    match status {
        Ok(Some(code)) => format!("exit status {code}"),
        Ok(None) => "killed by a signal".into(),
        Err(e) => format!("wait failed: {e}"),
    }
}

/// The reason in a Firecracker error response (`{"fault_message": "..."}`),
/// printable and short: it is written into an error that the operator reads.
fn fault_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let text = value.get("fault_message")?.as_str()?;
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_owned())
}

/// Setup validates an installed tool bundle before granting the service KVM.
pub fn validate_tools(directory: &Path) -> Result<(), String> {
    let assets = Assets::load(directory)?;
    assets.require_exec_mount()
}

fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "microVM directory is not a real directory",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// The guest kernel's command line. Every word is the kernel's own parameter
/// (`Documentation/admin-guide/kernel-parameters.txt`): `console=ttyS0` is the
/// serial console, `reboot=k` and `panic=1` end the VM on a reboot request or
/// a panic (as in Firecracker's `DEFAULT_KERNEL_CMDLINE`), `pci=off` because
/// the machine has no PCI bus, `nomodule` disables module loading (spelt
/// `nomodule`, as in Firecracker's default: the kernel has no `nomodules`),
/// and `init=/init` is the guest init of the initramfs. It stays last: the
/// kernel hands a word it does not know, and that has no `=`, to init as an
/// argument (`unknown_bootoption` in `init/main.c`), but the handler of
/// `init=` drops the ones that came before it (`init_setup`), so a stray word
/// is harmless before `init=` and would reach init after it. Firecracker
/// appends only parameters that the kernel consumes (`root=`, `ro`,
/// `virtio_mmio.device=`).
pub(crate) const BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off nomodule init=/init";

/// Internal CLI entry point. The executable has not started a runtime or logger.
/// A failed jail is fatal: there is no unjailed Firecracker fallback.
#[allow(clippy::disallowed_methods)] // Only the already jailed, threadless child execs.
pub fn launch(manifest: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(manifest)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_LAUNCH || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid private microVM launch manifest",
        ));
    }
    let launch: Launch = serde_json::from_reader(file.take(MAX_LAUNCH + 1)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid microVM launch manifest",
        )
    })?;
    if launch.schema != LAUNCH_SCHEMA
        || launch.parent_pid == 0
        || launch.cpu_millis == 0
        || launch.memory_bytes < VMM_OVERHEAD
        || [
            &launch.root,
            &launch.firecracker,
            &launch.kernel,
            &launch.initrd,
            &launch.rootfs,
            &launch.data,
            &launch.output,
        ]
        .iter()
        .any(|p| !p.is_absolute())
        || manifest.parent() != launch.root.parent()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid microVM launch inputs",
        ));
    }
    let root = fs::symlink_metadata(&launch.root)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || root.uid() != metadata.uid()
        || root.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "microVM jail ownership changed",
        ));
    }
    crate::sys::jail_microvm(&crate::sys::MicrovmJail {
        root: &launch.root,
        cgroup: &launch.cgroup,
        cpu_millis: launch.cpu_millis,
        memory_bytes: launch.memory_bytes,
        firecracker: &launch.firecracker,
        kernel: &launch.kernel,
        initrd: &launch.initrd,
        rootfs: &launch.rootfs,
        data: &launch.data,
        output: &launch.output,
        parent_pid: launch.parent_pid,
    })?;
    // Exec is intentionally confined to this already jailed, threadless child.
    Err(std::process::Command::new("/firecracker")
        .args(["--api-sock", "/api.sock"])
        .env_clear()
        .exec())
}

/// Live API endpoint and its independently supervised process. Drop never
/// pretends to stop the process; the actor/copy cleanup path kills and reaps it.
pub(crate) struct Vm {
    pub child: Arc<dyn Process>,
    pub root: PathBuf,
    pub output: PathBuf,
    pub cgroup: String,
    api: PathBuf,
    resources: Resources,
    restore: bool,
}

/// Resolve the same OCI process already validated for the other backends.
pub(crate) fn guest_config(spec: &[u8], port: u16, name: &str) -> Result<GuestConfig, String> {
    #[derive(Deserialize)]
    struct Spec {
        process: GuestProcess,
    }
    #[derive(Deserialize)]
    struct GuestProcess {
        args: Vec<String>,
        env: Vec<String>,
        cwd: String,
        user: User,
        capabilities: Capabilities,
    }
    #[derive(Deserialize)]
    struct User {
        uid: u32,
        gid: u32,
    }
    #[derive(Deserialize)]
    struct Capabilities {
        bounding: Vec<String>,
    }
    let spec: Spec = serde_json::from_slice(spec).map_err(|_| "invalid resolved OCI process")?;
    let process = spec.process;
    let config = GuestConfig {
        schema: kronik_guest_init::SCHEMA.into(),
        args: process.args,
        env: process.env,
        cwd: process.cwd,
        uid: process.user.uid,
        gid: process.user.gid,
        port,
        hostname: name.into(),
        capabilities: process.capabilities.bounding,
    };
    config.validate().map_err(|e| e.to_string())?;
    Ok(config)
}

pub(crate) struct Start<'a> {
    pub assets: &'a Assets,
    pub root: &'a Path,
    pub output: &'a Path,
    pub rootfs: &'a Path,
    pub data: &'a Path,
    pub config: &'a GuestConfig,
    pub cgroup: &'a str,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub log: &'a Path,
    /// Restored backing files are private copies retained in `output` for the
    /// VM's full lifetime; pruning the original checkpoint cannot remove them.
    pub restore: bool,
}

impl Vm {
    pub async fn spawn(env: &Env, start: Start<'_>) -> Result<Arc<Self>, String> {
        let resources = Resources::new(start.cpu_millis, start.memory_bytes)?;
        start.config.validate().map_err(|e| e.to_string())?;
        crate::microvm_sys::kvm()
            .map_err(|e| format!("KVM_UNAVAILABLE: {e}; use isolation gvisor on this host"))?;
        let parent = start.root.parent().ok_or("microVM jail has no parent")?;
        private_dir(
            parent
                .parent()
                .ok_or("microVM launcher has no runtime root")?,
        )
        .map_err(|e| e.to_string())?;
        fs::create_dir(parent)
            .map_err(|e| format!("creating a new private microVM launcher directory: {e}"))?;
        let mut unspawned = Unspawned(parent.to_path_buf());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        private_file(
            &parent.join(".state.tmp"),
            &serde_json::to_vec(&State {
                cgroup: start.cgroup.into(),
            })
            .map_err(|_| "encoding microVM ownership state")?,
        )
        .map_err(|e| e.to_string())?;
        fs::rename(parent.join(".state.tmp"), parent.join("state.json"))
            .map_err(|e| e.to_string())?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        if start.root.exists() {
            return Err("stale microVM jail must be cleaned after its process exits".into());
        }
        private_dir(start.root).map_err(|e| e.to_string())?;
        private_dir(&start.root.join("dev")).map_err(|e| e.to_string())?;
        private_dir(&start.root.join("out")).map_err(|e| e.to_string())?;
        private_dir(start.output).map_err(|e| e.to_string())?;
        for name in [
            "firecracker",
            "vmlinux",
            "initrd",
            "root.ext4",
            "data.ext4",
            "dev/kvm",
        ] {
            private_file(&start.root.join(name), &[]).map_err(|e| e.to_string())?;
        }
        let initrd = parent.join("initrd.cpio");
        let manifest = parent.join("launch.json");
        write_initrd(&initrd, &start.assets.guest_init, start.config).map_err(|e| e.to_string())?;
        let launch = Launch {
            schema: LAUNCH_SCHEMA.into(),
            root: start.root.to_path_buf(),
            cgroup: start.cgroup.into(),
            cpu_millis: start.cpu_millis,
            memory_bytes: resources.host_bytes,
            firecracker: start.assets.firecracker.clone(),
            kernel: start.assets.kernel.clone(),
            initrd: initrd.clone(),
            rootfs: start.rootfs.to_path_buf(),
            data: start.data.to_path_buf(),
            output: start.output.to_path_buf(),
            parent_pid: std::process::id(),
        };
        let bytes = serde_json::to_vec(&launch).map_err(|e| e.to_string())?;
        private_file(&manifest, &bytes).map_err(|e| e.to_string())?;
        let output = Stdio::Log {
            path: start.log.to_path_buf(),
            max_bytes: crate::logs::ROTATE_BYTES,
        };
        let child = env
            .procs
            .spawn(ProcessSpec {
                // The running image, even if the file was replaced by an
                // upgrade or deleted since the daemon started.
                program: PathBuf::from("/proc/self/exe"),
                args: vec![
                    "foreign".into(),
                    "launch-microvm".into(),
                    manifest.display().to_string(),
                ],
                env: vec![],
                cwd: None,
                stdout: output.clone(),
                stderr: output,
            })
            .await
            .map_err(|e| format!("starting microVM launcher: {e}"))?;
        let vm = Arc::new(Self {
            child,
            root: start.root.to_path_buf(),
            output: start.output.to_path_buf(),
            cgroup: start.cgroup.into(),
            api: start.root.join("api.sock"),
            resources,
            restore: start.restore,
        });
        unspawned.0.clear();
        Ok(vm)
    }

    /// The actor/copy owns cleanup before the first boot-protocol await.
    pub async fn boot(&self, env: &Env) -> Result<(), String> {
        let vm = self;
        let resources = self.resources;
        let parent = self.root.parent().ok_or("microVM jail has no parent")?;
        let initrd = parent.join("initrd.cpio");
        let manifest = parent.join("launch.json");
        let booted = env
            .timeout(Duration::from_secs(15), async {
                // The launcher exits at once when its jail cannot be built, and
                // the API socket then never appears: say so, with how it
                // exited, instead of waiting out the 15 seconds.
                loop {
                    tokio::select! {
                        biased;
                        status = self.child.wait() => {
                            return Err(format!(
                                "the microVM launcher exited before the VMM's API was ready ({})",
                                describe_exit(status)
                            ));
                        }
                        connected = tokio::net::UnixStream::connect(&vm.api) => {
                            if connected.is_ok() {
                                break;
                            }
                        }
                    }
                    env.clock.sleep(Duration::from_millis(20)).await;
                }
                if self.restore {
                    vm.put(
                        env,
                        "/snapshot/load",
                        json!({
                            "snapshot_path":"/out/restore.state",
                            "mem_backend":{"backend_type":"File","backend_path":"/out/restore.mem"},
                            "resume_vm":true
                        }),
                    )
                    .await
                } else {
                    vm.put(
                        env,
                        "/machine-config",
                        json!({"vcpu_count":resources.vcpus,"mem_size_mib":resources.guest_mib}),
                    )
                    .await?;
                    vm.put(
                        env,
                        "/boot-source",
                        json!({"kernel_image_path":"/vmlinux","initrd_path":"/initrd",
                    "boot_args":BOOT_ARGS}),
                    )
                    .await?;
                    vm.put(
                        env,
                        "/drives/root",
                        json!({"drive_id":"root","path_on_host":"/root.ext4","is_root_device":true,
                    "is_read_only":true,"cache_type":"Writeback","io_engine":"Sync"}),
                    )
                    .await?;
                    vm.put(
                        env,
                        "/drives/data",
                        json!({"drive_id":"data","path_on_host":"/data.ext4","is_root_device":false,
                    "is_read_only":false,"cache_type":"Writeback","io_engine":"Sync"}),
                    )
                    .await?;
                    vm.put(
                        env,
                        "/vsock",
                        json!({"guest_cid":3,"uds_path":"/vsock.sock"}),
                    )
                    .await?;
                    vm.put(env, "/actions", json!({"action_type":"InstanceStart"}))
                        .await
                }
            })
            .await;
        // No unencrypted environment remains in a host bootstrap file.
        let _ = fs::remove_file(&initrd);
        let _ = fs::remove_file(&manifest);
        match booted {
            Ok(result) => result,
            Err(_) => Err("microVM boot exceeded 15 seconds".into()),
        }
    }

    async fn request(
        env: &Env,
        api: &Path,
        method: &str,
        path: &str,
        value: Value,
    ) -> Result<(), String> {
        use bytes::Bytes;
        use http_body_util::{BodyExt as _, Full, Limited};
        let body = serde_json::to_vec(&value).map_err(|_| "encoding microVM control request")?;
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| "invalid microVM control request")?;
        env.timeout(CONTROL_TIMEOUT, async {
            let socket = tokio::net::UnixStream::connect(api)
                .await
                .map_err(|e| e.to_string())?;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(8192)
                .handshake(hyper_util::rt::TokioIo::new(socket))
                .await
                .map_err(|e| e.to_string())?;
            let deadline = env.clone();
            env.spawn("foreign-vm-control", async move {
                let _ = deadline.timeout(CONTROL_TIMEOUT, connection).await;
            });
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            // Firecracker always keeps HTTP connections alive. Hyper finishes
            // the 204/body framing without waiting for transport EOF.
            let body = Limited::new(response.into_body(), 8192)
                .collect()
                .await
                .map_err(|_| "microVM control response was invalid or exceeded 8KiB")?
                .to_bytes();
            if status == 204 || status == 200 {
                Ok(())
            } else {
                // An error response is `{"fault_message": "..."}`: the reason
                // is what a first bring-up needs to see.
                let why = fault_message(&body)
                    .map(|why| format!(": {why}"))
                    .unwrap_or_default();
                Err(format!(
                    "Firecracker {method} {path} failed (status {status}){why}"
                ))
            }
        })
        .await
        .map_err(|_| "microVM control request timed out".to_owned())?
    }

    async fn put(&self, env: &Env, path: &str, value: Value) -> Result<(), String> {
        Self::request(env, &self.api, "PUT", path, value).await
    }

    pub async fn pause(&self, env: &Env, paused: bool) -> Result<(), String> {
        Self::request(
            env,
            &self.api,
            "PATCH",
            "/vm",
            json!({"state":if paused {"Paused"} else {"Resumed"}}),
        )
        .await
    }

    pub async fn snapshot(&self, env: &Env) -> Result<(), String> {
        self.put(
            env,
            "/snapshot/create",
            json!({"snapshot_type":"Full","snapshot_path":"/out/checkpoint.state",
            "mem_file_path":"/out/checkpoint.mem","sync_snapshot_files":true}),
        )
        .await
    }

    pub async fn shutdown(&self, env: &Env) -> Result<(), String> {
        env.timeout(CONTROL_TIMEOUT, async {
            let mut socket = crate::bridge::vsock(
                env,
                &self.root.join("vsock.sock"),
                kronik_guest_init::CONTROL_PORT,
            )
            .await?;
            socket
                .write_all(kronik_guest_init::STOP)
                .await
                .map_err(|e| e.to_string())?;
            let mut reply = [0; kronik_guest_init::STOP_OK.len()];
            socket
                .read_exact(&mut reply)
                .await
                .map_err(|e| e.to_string())?;
            if reply.as_slice() != kronik_guest_init::STOP_OK {
                return Err("invalid guest stop acknowledgement".into());
            }
            Ok(())
        })
        .await
        .map_err(|_| "guest stop request timed out")?
    }

    /// Signaling the owned cgroup does not contend with the supervisor's
    /// pending Process::wait mutex. A missing group has already been reaped.
    pub async fn kill(&self, env: &Env) -> Result<(), String> {
        let group = crate::sys::cgroup_dir(&self.cgroup);
        let target = group.clone();
        env.blocking("foreign-vm-kill", move || {
            match fs::write(target.join("cgroup.kill"), "1") {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        })
        .await
        .ok_or("microVM kill task dropped")?
        .map_err(|e| e.to_string())?;
        let deadline = env.clock.monotonic() + CONTROL_TIMEOUT;
        loop {
            let target = group.clone();
            let exited = env
                .blocking("foreign-vm-reap-group", move || {
                    match fs::read_to_string(target.join("cgroup.procs")) {
                        Ok(pids) => Ok(pids.trim().is_empty()),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
                        Err(e) => Err(e),
                    }
                })
                .await
                .ok_or("microVM group wait task dropped")?
                .map_err(|e| e.to_string())?;
            if exited {
                return Ok(());
            }
            if env.clock.monotonic() >= deadline {
                return Err("microVM cgroup did not exit; backing files retained".into());
            }
            env.clock.sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn discard_snapshot(&self) -> io::Result<()> {
        for name in ["checkpoint.mem", "checkpoint.state"] {
            match fs::remove_file(self.output.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Called only after reap: namespace mounts and guest writes have ended.
    pub fn remove_files(&self) -> io::Result<()> {
        let group = crate::sys::cgroup_dir(&self.cgroup);
        match fs::read_to_string(group.join("cgroup.procs")) {
            Ok(pids) if !pids.trim().is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "microVM still has live processes",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if let Some(parent) = self.root.parent()
            && parent.exists()
        {
            fs::remove_dir_all(parent)?;
        }
        if self.output.exists() {
            fs::remove_dir_all(&self.output)?;
        }
        let group = Path::new("/sys/fs/cgroup").join(self.cgroup.trim_start_matches('/'));
        match fs::remove_dir(group) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Recover only this daemon's fixed VMM roots after its run-directory lock is
/// acquired. Killing a cgroup avoids PID reuse and never needs a runtime binary.
pub(crate) async fn cleanup_stale(
    env: &Env,
    runtime: &Path,
    parent: &str,
) -> Result<usize, String> {
    let mut removed = 0;
    let entries = match fs::read_dir(runtime) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let directory = entry.path();
        // An entry that is not one of ours is left alone and reported: the
        // run directory is the operator's too, and one stray file must not
        // keep every other sandbox from being cleaned up and started.
        let Some((name, suffix)) = entry
            .file_name()
            .to_str()
            .and_then(|name| {
                let (kind, length) = if name.starts_with("kronik-foreign-") {
                    ("kronik-foreign-", 32)
                } else {
                    ("kronik-copy-", 16)
                };
                let suffix = name.strip_prefix(kind)?;
                (suffix.len() == length && suffix.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| (name.to_owned(), suffix.to_owned()))
            })
            .filter(|_| {
                fs::symlink_metadata(&directory)
                    .map(|m| m.is_dir())
                    .unwrap_or(false)
            })
        else {
            tracing::warn!(
                path = %directory.display(),
                "leaving an entry that is not a Kronik microVM runtime directory"
            );
            continue;
        };
        let (name, suffix) = (name.as_str(), suffix.as_str());
        let state = directory.join("state.json");
        let state = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state)
        {
            Ok(file) => {
                let metadata = file.metadata().map_err(|e| e.to_string())?;
                if !metadata.is_file() || metadata.len() > 1024 {
                    return Err("invalid VMM ownership state type or size".into());
                }
                serde_json::from_reader::<_, State>(file.take(1025))
                    .map_err(|_| "invalid VMM ownership state")?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // The durable state precedes child creation. Only its private
                // staging file can exist when publication was interrupted.
                if fs::read_dir(&directory)
                    .map_err(|e| e.to_string())?
                    .any(|e| match e {
                        Ok(e) => e.file_name() != ".state.tmp",
                        Err(_) => true,
                    })
                {
                    return Err(
                        "VMM runtime has no durable ownership state; retained for diagnosis".into(),
                    );
                }
                fs::remove_dir_all(directory).map_err(|e| e.to_string())?;
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let child = state
            .cgroup
            .strip_prefix(parent)
            .and_then(|p| p.strip_prefix('/'))
            .filter(|p| !p.is_empty() && !p.contains('/') && *p != "." && *p != "..")
            .ok_or("VMM ownership cgroup escapes this daemon")?;
        let expected = if name.starts_with("kronik-foreign-") {
            name.to_owned()
        } else {
            format!("copy-{suffix}")
        };
        if child != expected {
            return Err("VMM ownership state names another sandbox's cgroup".into());
        }
        let group = crate::sys::cgroup_dir(&state.cgroup);
        if group.exists() {
            let members =
                fs::read_to_string(group.join("cgroup.procs")).map_err(|e| e.to_string())?;
            if !members.trim().is_empty() {
                fs::write(group.join("cgroup.kill"), "1").map_err(|e| e.to_string())?;
            }
            let deadline = env.clock.monotonic() + Duration::from_secs(10);
            loop {
                let members =
                    fs::read_to_string(group.join("cgroup.procs")).map_err(|e| e.to_string())?;
                if members.trim().is_empty() {
                    break;
                }
                if env.clock.monotonic() >= deadline {
                    return Err(
                        "owned VMM did not exit; retaining its jail and backing files".into(),
                    );
                }
                env.clock.sleep(Duration::from_millis(20)).await;
            }
            fs::remove_dir(group).map_err(|e| e.to_string())?;
        }
        fs::remove_dir_all(directory).map_err(|e| e.to_string())?;
        removed += 1;
    }
    Ok(removed)
}

/// Minimal uncompressed newc archive: no host device creation and no guest
/// image mutation. Byte values from the guest environment are never formatted
/// into errors or process arguments.
fn write_initrd(path: &Path, init: &Path, config: &GuestConfig) -> io::Result<()> {
    config.validate()?;
    let manifest =
        serde_json::to_vec(config).map_err(|_| io::Error::other("encoding guest manifest"))?;
    if manifest.len() > kronik_guest_init::MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest manifest exceeds 128KiB",
        ));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(init)?;
    let length = input.metadata()?.len();
    if length > 32 << 20 || !input.metadata()?.is_file() {
        return Err(io::Error::other("invalid static guest init size or type"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    input.read_to_end(&mut bytes)?;
    cpio_entry(&mut output, "init", 0o100755, &bytes, 0, 0)?;
    cpio_entry(&mut output, "config.json", 0o100600, &manifest, 0, 0)?;
    cpio_entry(&mut output, "dev", 0o040755, &[], 0, 0)?;
    cpio_entry(&mut output, "dev/console", 0o020600, &[], 5, 1)?;
    cpio_entry(&mut output, "TRAILER!!!", 0, &[], 0, 0)?;
    output.sync_all()
}

fn cpio_entry(
    out: &mut File,
    name: &str,
    mode: u32,
    bytes: &[u8],
    major: u32,
    minor: u32,
) -> io::Result<()> {
    let size =
        u32::try_from(bytes.len()).map_err(|_| io::Error::other("initramfs entry too large"))?;
    let header = format!(
        "070701{:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{size:08x}{:08x}{:08x}{major:08x}{minor:08x}{:08x}{:08x}",
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        name.len() + 1,
        0
    );
    out.write_all(header.as_bytes())?;
    out.write_all(name.as_bytes())?;
    out.write_all(&[0])?;
    for _ in 0..((4 - (110 + name.len() + 1) % 4) % 4) {
        out.write_all(&[0])?;
    }
    out.write_all(bytes)?;
    for _ in 0..((4 - bytes.len() % 4) % 4) {
        out.write_all(&[0])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_root_service_needs_the_drop_in_for_microvms_and_the_nonroot_one_has_its_leaf() {
        use crate::manager::Privilege;
        let ok = |cgroup: &str| Ok(cgroup.to_owned());
        let root = Privilege::Root;
        assert!(super::require_leaf(&root, ok("/system.slice/kronik.service/daemon")).is_ok());
        // `/` in a private cgroup namespace is a leaf only when it says so.
        assert!(super::require_leaf(&root, ok("/daemon")).is_ok());
        for cgroup in [
            "/system.slice/kronik.service",
            "/",
            "/user.slice/session-3.scope",
        ] {
            let why = super::require_leaf(&root, ok(cgroup)).unwrap_err();
            assert!(why.starts_with("microVM actors need"), "{why}");
            assert!(why.contains(cgroup), "{why}");
        }
        let unreadable = super::require_leaf(&root, Err(std::io::Error::other("no cgroup")));
        assert!(unreadable.unwrap_err().contains("unreadable"));
        // The nonroot daemon made its leaf before it got a privilege.
        let userns = Privilege::Userns {
            cgroup: "/system.slice/kronik.service".into(),
        };
        assert!(super::require_leaf(&userns, ok("/system.slice/kronik.service/daemon")).is_ok());
        assert!(super::require_leaf(&Privilege::Unavailable("x".into()), ok("/")).is_ok());
    }

    #[test]
    fn the_advice_names_the_file_and_the_two_directives() {
        let advice = super::root_leaf_advice();
        for needle in [
            super::ROOT_LEAF_DROPIN_PATH,
            "Delegate=yes",
            "DelegateSubgroup=daemon",
            "254",
        ] {
            assert!(advice.contains(needle), "{advice}");
        }
        assert!(super::ROOT_LEAF_DROPIN.starts_with("[Service]\n"));
        assert!(super::ROOT_LEAF_DROPIN.ends_with('\n'));
    }

    use super::*;

    /// Pins the command line to the exact text, so that an edit is noticed.
    /// The module switch is `nomodule`: it is how the kernel documents it
    /// (`kernel-parameters.txt`: "nomodule  Disable module load", defined by
    /// `core_param(nomodule, ...)` in `kernel/module/main.c`) and how
    /// Firecracker v1.17.0's `DEFAULT_KERNEL_CMDLINE` spells it
    /// (`src/vmm/src/vmm_config/boot_source.rs`).
    #[test]
    fn the_kernel_command_line_is_pinned() {
        assert_eq!(
            BOOT_ARGS,
            "console=ttyS0 reboot=k panic=1 pci=off nomodule init=/init"
        );
        // A word without `=` that the kernel does not know reaches init as an
        // argument unless `init=` follows it; `nomodule` is the one boolean
        // parameter used. `init=` must stay the last word.
        for word in BOOT_ARGS.split(' ') {
            assert!(word.contains('=') || word == "nomodule", "{word}");
        }
        assert_eq!(BOOT_ARGS.split(' ').next_back(), Some("init=/init"));
        assert!(!BOOT_ARGS.contains("nomodules"));
    }

    #[test]
    fn resources_keep_quota_separate_from_supported_guest_topology() {
        let low = Resources::new(10, (128 << 20) + 17).unwrap();
        assert_eq!(
            low,
            Resources {
                vcpus: 1,
                guest_mib: 128,
                host_bytes: (128 << 20) + VMM_OVERHEAD
            }
        );
        assert_eq!(Resources::new(2001, 512 << 20).unwrap().vcpus, 4);
        assert_eq!(Resources::new(32000, 512 << 20).unwrap().vcpus, 32);
        assert!(Resources::new(32001, 512 << 20).is_err());
        assert!(Resources::new(1000, (128 << 20) - 1).is_err());
        assert!(Resources::new(1000, u64::MAX).is_err());
    }

    #[tokio::test]
    async fn a_keepalive_204_completes_without_waiting_for_eof() {
        let directory = tempfile::tempdir().unwrap();
        let api = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&api).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let server = env.spawn("test-vm-control", async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(socket.read_u8().await.unwrap());
                assert!(headers.len() <= 8192);
            }
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
                .await
                .unwrap();
            let _ = held.await;
        });
        let result = env
            .timeout(
                Duration::from_millis(500),
                Vm::request(&env, &api, "PUT", "/machine-config", json!({})),
            )
            .await;
        let _ = release.send(());
        assert!(matches!(result, Ok(Ok(()))), "{result:?}");
        assert_eq!(server.await, Some(()));
    }

    #[test]
    fn firecrackers_fault_message_is_extracted_printable_and_short() {
        let body = br#"{"fault_message":"Invalid request: The kernel file cannot be opened: No such file or directory (os error 2)"}"#;
        assert_eq!(
            fault_message(body).unwrap(),
            "Invalid request: The kernel file cannot be opened: No such file or directory (os error 2)"
        );
        // Control characters do not reach the log or the terminal.
        assert_eq!(
            fault_message(br#"{"fault_message":"a\u001b[31m\nred\tb"}"#).unwrap(),
            "a [31m red b"
        );
        // Long messages are cut, and anything else is no message at all.
        let long = format!(r#"{{"fault_message":"{}"}}"#, "x".repeat(1000));
        assert_eq!(fault_message(long.as_bytes()).unwrap().len(), 300);
        for none in [
            &b""[..],
            b"not json",
            br#"{"other":"x"}"#,
            br#"{"fault_message":7}"#,
            br#"{"fault_message":"  \n "}"#,
            br#"["fault_message"]"#,
        ] {
            assert_eq!(fault_message(none), None, "{none:?}");
        }
    }

    async fn serve_one(listener: tokio::net::UnixListener, reply: Vec<u8>) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.unwrap());
        }
        // The request has a body: read what the headers promise.
        let text = String::from_utf8_lossy(&headers).to_ascii_lowercase();
        let length: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        socket.write_all(&reply).await.unwrap();
        socket.flush().await.unwrap();
        let _ = socket.shutdown().await;
    }

    #[tokio::test]
    async fn a_refused_request_says_why_firecracker_refused_it() {
        let directory = tempfile::tempdir().unwrap();
        let api = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&api).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let body = r#"{"fault_message":"Invalid request: the root drive is read-only"}"#;
        let reply = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let server = env.spawn("test-vm-control", serve_one(listener, reply));
        let error = Vm::request(&env, &api, "PUT", "/drives/rootfs", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            "Firecracker PUT /drives/rootfs failed (status 400): Invalid request: the root drive is read-only"
        );
        assert_eq!(server.await, Some(()));
    }

    #[tokio::test]
    async fn a_refusal_without_a_body_still_reports_the_status() {
        let directory = tempfile::tempdir().unwrap();
        let api = directory.path().join("api.sock");
        let listener = tokio::net::UnixListener::bind(&api).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let reply = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_vec();
        let server = env.spawn("test-vm-control", serve_one(listener, reply));
        let error = Vm::request(&env, &api, "PATCH", "/vm", json!({}))
            .await
            .unwrap_err();
        assert_eq!(error, "Firecracker PATCH /vm failed (status 500)");
        assert_eq!(server.await, Some(()));
    }

    struct Exited(Option<i32>);
    impl Process for Exited {
        fn id(&self) -> Option<u32> {
            None
        }
        fn wait(&self) -> kronik_core::env::BoxFuture<'static, io::Result<Option<i32>>> {
            let status = self.0;
            Box::pin(async move { Ok(status) })
        }
        fn kill(&self) -> kronik_core::env::BoxFuture<'static, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn a_launcher_that_exits_at_once_is_reported_without_waiting_for_the_api() {
        let directory = tempfile::tempdir().unwrap();
        let jail = directory.path().join("jail");
        fs::create_dir(&jail).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        for (status, said) in [(Some(1), "exit status 1"), (None, "killed by a signal")] {
            let vm = Vm {
                child: Arc::new(Exited(status)),
                root: jail.clone(),
                output: directory.path().join("out"),
                cgroup: "/x/vm".into(),
                api: jail.join("api.sock"),
                resources: Resources::new(1000, 256 << 20).unwrap(),
                restore: false,
            };
            let started = env.clock.monotonic();
            let error = vm.boot(&env).await.unwrap_err();
            assert!(
                env.clock.monotonic() - started < Duration::from_secs(5),
                "{error}"
            );
            assert_eq!(
                error,
                format!("the microVM launcher exited before the VMM's API was ready ({said})")
            );
        }
    }

    #[tokio::test]
    async fn entries_that_are_not_ours_are_left_alone_and_do_not_stop_the_cleanup() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let run = directory.path();
        fs::write(run.join("stray-file"), b"x").unwrap();
        fs::create_dir(run.join("somebody-elses-directory")).unwrap();
        fs::create_dir(run.join("kronik-foreign-not-hex")).unwrap();
        fs::create_dir(run.join(format!("kronik-copy-{}", "a".repeat(15)))).unwrap();
        // Ours by name, but a link and a file: not real directories.
        symlink(
            directory.path(),
            run.join(format!("kronik-foreign-{}", "b".repeat(32))),
        )
        .unwrap();
        fs::write(run.join(format!("kronik-copy-{}", "c".repeat(16))), b"x").unwrap();
        // A real stale runtime directory with nothing durable in it.
        let stale = run.join(format!("kronik-copy-{}", "d".repeat(16)));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join(".state.tmp"), b"half").unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        cleanup_stale(&env, run, "").await.unwrap();
        assert!(!stale.exists(), "the stale runtime directory is removed");
        for kept in [
            "stray-file",
            "somebody-elses-directory",
            "kronik-foreign-not-hex",
        ] {
            assert!(run.join(kept).symlink_metadata().is_ok(), "{kept}");
        }
        assert!(
            run.join(format!("kronik-foreign-{}", "b".repeat(32)))
                .symlink_metadata()
                .is_ok()
        );
        // The link's target was not entered or removed.
        assert!(run.is_dir());
    }

    #[tokio::test]
    async fn stale_ownership_state_cannot_target_the_daemon_cgroup() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory
            .path()
            .join(format!("kronik-foreign-{}", "a".repeat(32)));
        fs::create_dir(&root).unwrap();
        private_file(&root.join("state.json"), b"{\"cgroup\":\"/daemon\"}").unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let error = cleanup_stale(&env, directory.path(), "").await.unwrap_err();
        assert!(error.contains("another sandbox"));
        assert!(root.join("state.json").is_file());
    }

    #[test]
    fn initramfs_has_private_config_and_real_console_without_image_injection() {
        let dir = tempfile::tempdir().unwrap();
        let init = dir.path().join("guest-init");
        fs::write(&init, b"static-init").unwrap();
        let config = GuestConfig {
            schema: kronik_guest_init::SCHEMA.into(),
            args: vec!["/echo".into()],
            env: vec!["SECRET=never-log".into()],
            cwd: "/".into(),
            uid: 0,
            gid: 0,
            port: 8080,
            hostname: "echo".into(),
            capabilities: vec![],
        };
        let path = dir.path().join("initrd");
        write_initrd(&path, &init, &config).unwrap();
        let bytes = fs::read(&path).unwrap();
        let mut offset = 0;
        let mut names = Vec::new();
        while offset < bytes.len() {
            let header = &bytes[offset..offset + 110];
            assert_eq!(&header[..6], b"070701");
            let number = |field: usize| {
                u32::from_str_radix(
                    std::str::from_utf8(&header[6 + field * 8..14 + field * 8]).unwrap(),
                    16,
                )
                .unwrap()
            };
            let size = number(6) as usize;
            let length = number(11) as usize;
            let start = offset + 110;
            let name = std::str::from_utf8(&bytes[start..start + length - 1]).unwrap();
            if name == "config.json" {
                assert_eq!(number(1), 0o100600);
            }
            if name == "dev/console" {
                assert_eq!((number(1), number(9), number(10)), (0o020600, 5, 1));
            }
            names.push(name.to_string());
            offset = (start + length).next_multiple_of(4);
            if name == "config.json" {
                GuestConfig::parse(&bytes[offset..offset + size]).unwrap();
            }
            offset = (offset + size).next_multiple_of(4);
        }
        assert_eq!(
            names,
            ["init", "config.json", "dev", "dev/console", "TRAILER!!!"]
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(write_initrd(&path, &init, &config).is_err());
    }
}
