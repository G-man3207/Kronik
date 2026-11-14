//! Static Linux PID1 for Kronik's microVMs. The host supplies `/config.json`
//! in the initramfs, a read-only ext4 `/dev/vda`, and a writable ext4 `/dev/vdb`.
//! No program or configuration file is installed into the image root.

#[cfg(not(target_os = "linux"))]
compile_error!("kronik-guest-init requires Linux");

mod sys;

use serde::{Deserialize, Serialize};
use std::io::{self, Read};

pub const SCHEMA: &str = "kronik.guest/v1";
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
pub const MAX_PROCESS_BYTES: usize = 96 * 1024;
pub const MAX_PROCESS_ENTRIES: usize = 4096;
pub const VSOCK_PORT: u32 = 10000;
pub const MAX_CONNECTIONS: usize = 64;
/// Emitted on the data stream only after the fixed loopback TCP target connects.
pub const READY: &[u8] = b"KRONIK/1 READY\n";
pub const CONTROL_PORT: u32 = 10001;
pub const STOP: &[u8] = b"STOP\n";
pub const STOP_OK: &[u8] = b"OK\n";

/// Resolved OCI process settings, not host paths. `env` contains `KEY=VALUE`
/// entries, including the image's resolved PATH. Secrets must never be logged.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestConfig {
    pub schema: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub uid: u32,
    pub gid: u32,
    pub port: u16,
    pub hostname: String,
    pub capabilities: Vec<String>,
}

// The existing OCI root capability intent, deliberately without NET_RAW.
const CAPABILITIES: [(&str, u32); 13] = [
    ("CAP_CHOWN", 0),
    ("CAP_DAC_OVERRIDE", 1),
    ("CAP_FOWNER", 3),
    ("CAP_FSETID", 4),
    ("CAP_KILL", 5),
    ("CAP_SETGID", 6),
    ("CAP_SETUID", 7),
    ("CAP_SETPCAP", 8),
    ("CAP_NET_BIND_SERVICE", 10),
    ("CAP_SYS_CHROOT", 18),
    ("CAP_MKNOD", 27),
    ("CAP_AUDIT_WRITE", 29),
    ("CAP_SETFCAP", 31),
];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl GuestConfig {
    /// Rejects malformed or unbounded process settings before any guest setup.
    pub fn validate(&self) -> io::Result<()> {
        if self.schema != SCHEMA {
            return Err(invalid("unsupported guest configuration schema"));
        }
        if self.args.is_empty() || self.args[0].is_empty() {
            return Err(invalid("guest process needs an executable"));
        }
        if self.args.len().saturating_add(self.env.len()) > MAX_PROCESS_ENTRIES {
            return Err(invalid("too many guest process entries"));
        }
        let mut bytes = 0usize;
        for value in self.args.iter().chain(&self.env) {
            if value.as_bytes().contains(&0) || value.len() > 32 * 1024 {
                return Err(invalid("invalid or oversized guest process entry"));
            }
            bytes = bytes.saturating_add(value.len() + 1);
        }
        if bytes > MAX_PROCESS_BYTES {
            return Err(invalid("guest process settings exceed byte limit"));
        }
        for entry in &self.env {
            if !entry
                .split_once('=')
                .is_some_and(|(key, _)| !key.is_empty())
            {
                return Err(invalid("guest environment requires KEY=VALUE entries"));
            }
        }
        if !self.cwd.starts_with('/') || self.cwd.as_bytes().contains(&0) || self.cwd.len() > 4096 {
            return Err(invalid("guest working directory must be an absolute path"));
        }
        if self.port == 0 {
            return Err(invalid("guest service port must be nonzero"));
        }
        if self.hostname.is_empty()
            || self.hostname.len() > 64
            || !self
                .hostname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(invalid("invalid guest hostname"));
        }
        if self.uid == u32::MAX || self.gid == u32::MAX {
            return Err(invalid("invalid guest process identity"));
        }
        if self.capabilities.len() > CAPABILITIES.len()
            || (self.uid != 0 && !self.capabilities.is_empty())
        {
            return Err(invalid("invalid guest capability intent"));
        }
        let mut seen = 0u64;
        for name in &self.capabilities {
            let bit = capability(name).ok_or_else(|| invalid("unsupported guest capability"))?;
            if seen & (1u64 << bit) != 0 {
                return Err(invalid("duplicate guest capability"));
            }
            seen |= 1u64 << bit;
        }
        Ok(())
    }

    /// Reads at most 128 KiB plus one sentinel byte, including JSON overhead.
    /// Parser errors intentionally omit source snippets, which can hold secrets.
    pub fn parse(reader: impl Read) -> io::Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_MANIFEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(invalid("guest manifest exceeds 128 KiB"));
        }
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid guest configuration JSON"))?;
        config.validate()?;
        Ok(config)
    }
}

fn capability(name: &str) -> Option<u32> {
    CAPABILITIES
        .iter()
        .find_map(|(known, number)| (*known == name).then_some(*number))
}

/// Notes the arguments the kernel handed to init beyond its own name. The
/// kernel passes the words of its command line that it does not recognise
/// and that have no `=` to init as arguments, and a boot loader may add
/// others (such as `BOOT_IMAGE`). The host chooses the command line, so they
/// are no question of trust: the text is logged once and the arguments are
/// ignored. A word that reaches init after `init=` (the kernel passes on the
/// ones it does not know) must not stop the guest.
pub fn ignored_arguments(args: impl IntoIterator<Item = std::ffi::OsString>) -> Option<String> {
    let extra: Vec<String> = args
        .into_iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    if extra.is_empty() {
        return None;
    }
    let shown: String = extra.join(" ").chars().take(200).collect();
    Some(format!(
        "ignoring {} unexpected kernel argument(s): {shown}",
        extra.len()
    ))
}

/// Runs only as Linux PID1. All mounts, the application and the fixed-target
/// host-to-guest bridge share the VM lifetime; no host service is contacted.
pub fn run_guest(config: GuestConfig) -> io::Result<()> {
    config.validate()?;
    sys::run_guest(config)
}

/// Used by the PID1 binary on both normal termination and fatal setup failure
/// to end the VM. It restarts the machine, because Firecracker has no guest
/// power management and exits on a restart (see `sys::END_VM`). A failure is
/// returned instead of pretending the VM stopped.
pub fn power_off() -> io::Result<()> {
    sys::power_off()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> GuestConfig {
        GuestConfig {
            schema: SCHEMA.into(),
            args: vec!["/echo".into()],
            env: vec!["PATH=/bin".into(), "SECRET=private".into()],
            cwd: "/".into(),
            uid: 0,
            gid: 0,
            port: 8080,
            hostname: "echo".into(),
            capabilities: vec!["CAP_CHOWN".into()],
        }
    }

    #[test]
    fn parses_contract_and_rejects_unknown_fields_without_leaking_values() {
        let bytes = serde_json::to_vec(&config()).unwrap();
        assert_eq!(GuestConfig::parse(bytes.as_slice()).unwrap().port, 8080);
        let mut value = serde_json::to_value(config()).unwrap();
        value["SECRET=private"] = serde_json::json!(true);
        let error = GuestConfig::parse(serde_json::to_vec(&value).unwrap().as_slice())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("private"));
    }

    #[test]
    fn extra_kernel_arguments_are_noted_once_and_ignored() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        let args = |list: &[&str]| list.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(ignored_arguments(args(&[])), None);
        assert_eq!(ignored_arguments(args(&["/init"])), None);
        assert_eq!(
            ignored_arguments(args(&["/init", "stray"])).as_deref(),
            Some("ignoring 1 unexpected kernel argument(s): stray")
        );
        assert_eq!(
            ignored_arguments(args(&["/init", "quiet", "BOOT_IMAGE"])).as_deref(),
            Some("ignoring 2 unexpected kernel argument(s): quiet BOOT_IMAGE")
        );
        // Bounded, and not a panic for bytes that are not UTF-8.
        let long = "x".repeat(10_000);
        assert!(ignored_arguments(args(&["/init", &long])).unwrap().len() < 300);
        let odd = vec![
            OsString::from("/init"),
            OsString::from_vec(vec![0xff, 0xfe]),
        ];
        assert!(ignored_arguments(odd).unwrap().starts_with("ignoring 1 "));
    }

    #[test]
    fn enforces_manifest_entry_and_process_byte_bounds() {
        assert!(GuestConfig::parse(vec![b' '; MAX_MANIFEST_BYTES + 1].as_slice()).is_err());
        let mut c = config();
        c.env = vec!["K=V".into(); MAX_PROCESS_ENTRIES];
        assert!(c.validate().is_err());
        c.env = vec![format!("K={}", "x".repeat(32 * 1024)); 4];
        assert!(c.validate().is_err());
        c.env = vec!["K=V".into(); MAX_PROCESS_ENTRIES - 1];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_identity_path_port_environment_and_capability_boundary_errors() {
        let mutations: [fn(&mut GuestConfig); 11] = [
            |c: &mut GuestConfig| c.cwd = "relative".into(),
            |c: &mut GuestConfig| c.cwd = "/bad\0path".into(),
            |c: &mut GuestConfig| c.port = 0,
            |c: &mut GuestConfig| c.env = vec!["NO_EQUALS".into()],
            |c: &mut GuestConfig| c.env = vec!["=value".into()],
            |c: &mut GuestConfig| c.args[0] = "bad\0arg".into(),
            |c: &mut GuestConfig| c.capabilities = vec!["CAP_SYS_ADMIN".into()],
            |c: &mut GuestConfig| c.capabilities.push("CAP_CHOWN".into()),
            |c: &mut GuestConfig| c.uid = 1000,
            |c: &mut GuestConfig| c.gid = u32::MAX,
            |c: &mut GuestConfig| c.hostname = "bad/name".into(),
        ];
        for mutate in mutations {
            let mut c = config();
            mutate(&mut c);
            assert!(c.validate().is_err());
        }
    }
}
