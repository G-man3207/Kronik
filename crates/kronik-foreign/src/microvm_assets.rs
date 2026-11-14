//! Offline, digest-verified tools and immutable ext4 publication. No host mount or downloader.
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kronik_core::env::{Env, ProcessSpec, Stdio};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::microvm::DATA_BYTES;
const MAX_BYTES: u64 = 8 << 30;
const MAX_ENTRIES: u64 = 1_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub schema: String,
    pub firecracker_version: String,
    pub kernel_version: String,
    pub firecracker_sha256: String,
    pub kernel_sha256: String,
    pub guest_init_sha256: String,
    pub mke2fs_sha256: String,
    pub mke2fs_version: String,
    pub provenance_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Assets {
    pub dir: PathBuf,
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub guest_init: PathBuf,
    pub mke2fs: PathBuf,
    pub identity: Identity,
}

fn error(e: impl std::fmt::Display) -> String {
    format!("MICROVM_ASSETS: {e}")
}

/// The bundle is checked, then bound into a jail and executed: whoever can
/// write it or the directories above it in between decides what runs with the
/// daemon's authority (`mke2fs`) and with `/dev/kvm` (the VMM). So it, its
/// directory and every ancestor must belong to root or to the user the daemon
/// runs as, and nobody else may write to them. A sticky ancestor such as
/// `/tmp` is the one exception, as for the namespace pin's directory.
fn trusted(owner: u32, euid: u32) -> bool {
    owner == 0 || owner == euid
}

/// The tool directory as the nonroot daemon checked it before it entered
/// the Kronik user namespace (see [`check_from_host`]), and the uid that an
/// owner the namespace does not map shows as there.
static HOST_CHECKED: std::sync::OnceLock<(PathBuf, u32)> = std::sync::OnceLock::new();

/// Checks the tool directory `dir` as [`Assets::load`] does, from the host's
/// view: the nonroot daemon calls it before it enters the Kronik user
/// namespace. Inside, root's files show as the overflow uid, the uid of every
/// owner the namespace does not map, so ownership cannot be judged there; a
/// file of `dir` (and `dir` and its ancestors) that shows as that uid is then
/// taken as the owner this check saw. Only root or the daemon's user can
/// change what it checked: the directory and every one above it are theirs
/// alone. A bundle installed after the daemon started is not checked, and
/// adding a microVM then says that it is not root's.
pub fn check_from_host(dir: &Path) -> Result<(), String> {
    Assets::load(dir)?;
    let overflow = fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(65_534);
    let _ = HOST_CHECKED.set((dir.to_path_buf(), overflow));
    Ok(())
}

/// The overflow uid, when `dir` is the directory [`check_from_host`] checked.
fn host_checked_overflow(dir: &Path) -> Option<u32> {
    HOST_CHECKED
        .get()
        .filter(|(checked, _)| checked == dir)
        .map(|(_, overflow)| *overflow)
}

fn check_bundle_path(dir: &Path, euid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    if !dir.is_absolute() {
        return Err(error("tool directory must be an absolute path"));
    }
    let checked = host_checked_overflow(dir);
    let trusted = |owner: u32| trusted(owner, euid) || checked == Some(owner);
    for (index, ancestor) in dir.ancestors().enumerate() {
        let md = fs::symlink_metadata(ancestor).map_err(error)?;
        let sticky = md.mode() & 0o1000 != 0 && index > 0;
        if !md.is_dir() || !trusted(md.uid()) || (md.mode() & 0o022 != 0 && !sticky) {
            return Err(error(format!(
                "{} is {}: the tool directory and the directories above it must be real directories \
                 owned by root or by the daemon's user, with no write access for anyone else",
                ancestor.display(),
                if !md.is_dir() {
                    "not a real directory".to_owned()
                } else if !trusted(md.uid()) {
                    format!("owned by uid {}", md.uid())
                } else {
                    format!(
                        "writable by group or others (mode {:04o})",
                        md.mode() & 0o7777
                    )
                }
            )));
        }
    }
    Ok(())
}

fn euid() -> u32 {
    crate::sys::euid()
}
fn regular(path: &Path, max: u64, private: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(error)?;
    let md = file.metadata().map_err(error)?;
    let checked = path.parent().and_then(host_checked_overflow);
    if !md.is_file()
        || !(trusted(md.uid(), euid()) || checked == Some(md.uid()))
        || md.len() > max
        || (private && md.nlink() != 1)
        || md.mode() & (if private { 0o077 } else { 0o022 }) != 0
    {
        return Err(error(format!(
            "{} is not a bounded, protected regular file",
            path.display()
        )));
    }
    Ok(file)
}
/// Fails, with the way out, when `path` is on a `noexec` mount.
fn executable_here(path: &Path) -> Result<(), String> {
    let file = File::open(path).map_err(error)?;
    let flags = crate::sys::mount_flags(&file).map_err(error)?;
    if flags & crate::sys::ST_NOEXEC != 0 {
        return Err(error(format!(
            "the microVM tool directory is on a noexec mount ({} cannot be executed there); \
             put [foreign] microvm_dir on a file system that allows execution",
            path.display()
        )));
    }
    Ok(())
}
fn sha256(file: &mut File) -> Result<String, String> {
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let bound = file.metadata().map_err(error)?.len();
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(error)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or_else(|| error("digest size overflow"))?;
        if count > bound {
            return Err(error("file grew while hashing"));
        }
        hash.update(&buffer[..n]);
    }
    if count != bound {
        return Err(error("file changed while hashing"));
    }
    Ok(crate::blobs::hex(&hash.finalize()))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn verify(path: &Path, expected: &str, max: u64, executable: bool) -> Result<(), String> {
    if !valid_digest(expected) {
        return Err(error("digest must be 64 lowercase hexadecimal characters"));
    }
    let mut file = regular(path, max, false)?;
    if executable && file.metadata().map_err(error)?.mode() & 0o111 == 0 {
        return Err(error(format!("{} is not executable", path.display())));
    }
    if sha256(&mut file)? != expected {
        return Err(error(format!("{} digest mismatch", path.display())));
    }
    Ok(())
}
pub(crate) fn digest(path: &Path) -> Result<String, String> {
    sha256(&mut regular(path, 32 << 30, false)?)
}
impl Assets {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let md = fs::symlink_metadata(dir).map_err(error)?;
        if !md.is_dir() || md.mode() & 0o022 != 0 {
            return Err(error("tool directory is not protected"));
        }
        check_bundle_path(dir, euid())?;
        let file = regular(&dir.join("manifest.json"), 65536, false)?;
        if file.metadata().map_err(error)?.nlink() != 1 {
            return Err(error("tool manifest must have exactly one link"));
        }
        let identity: Identity = serde_json::from_reader(file.take(65537)).map_err(error)?;
        if identity.schema != "kronik.microvm-tools/v1"
            || identity.firecracker_version != "1.17.0"
            || identity.kernel_version != "6.18.25"
            || !valid_digest(&identity.provenance_sha256)
            || identity.mke2fs_version != "1.47.2"
        {
            return Err(error("unsupported tool manifest identity"));
        }
        let assets = Self {
            dir: dir.to_path_buf(),
            firecracker: dir.join("firecracker"),
            kernel: dir.join("vmlinux"),
            guest_init: dir.join("guest-init"),
            mke2fs: dir.join("mke2fs"),
            identity,
        };
        assets.verify()?;
        Ok(assets)
    }
    /// The files that are executed on this host, the VMM in its jail and the
    /// filesystem tool, must not be on a `noexec` mount: the jail keeps the
    /// source mount's `noexec`, and the exec would fail with a bare `EACCES`.
    pub fn require_exec_mount(&self) -> Result<(), String> {
        [&self.firecracker, &self.mke2fs]
            .into_iter()
            .try_for_each(|path| executable_here(path))
    }
    pub fn verify(&self) -> Result<(), String> {
        verify(
            &self.firecracker,
            &self.identity.firecracker_sha256,
            128 << 20,
            true,
        )?;
        verify(&self.kernel, &self.identity.kernel_sha256, 256 << 20, false)?;
        verify(
            &self.guest_init,
            &self.identity.guest_init_sha256,
            64 << 20,
            true,
        )?;
        verify(&self.mke2fs, &self.identity.mke2fs_sha256, 32 << 20, true)?;
        verify(
            &self.dir.join("provenance.json"),
            &self.identity.provenance_sha256,
            1 << 20,
            false,
        )
    }
}

struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn stage(env: &Env, out: &Path) -> Result<Stage, String> {
    let parent = out
        .parent()
        .ok_or_else(|| error("disk has no parent directory"))?;
    let token = env.random_bytes::<16>();
    let path = parent.join(format!(".microvm-{:032x}", u128::from_le_bytes(token)));
    fs::create_dir(&path).map_err(error)?;
    fs::set_permissions(&path, Permissions::from_mode(0o700)).map_err(error)?;
    Ok(Stage(path))
}

#[derive(Default)]
struct Tree {
    entries: u64,
    inodes: u64,
    bytes: u64,
    owner: (u32, u32),
    mode: u32,
}
fn scan(root: &Path) -> Result<Tree, String> {
    let md = fs::symlink_metadata(root).map_err(error)?;
    if !md.is_dir() {
        return Err(error("root tree is not a directory"));
    }
    let mut tree = Tree {
        entries: 1,
        inodes: 1,
        owner: (md.uid(), md.gid()),
        mode: md.mode() & 0o7777,
        ..Tree::default()
    };
    let mut seen = HashSet::from([(md.dev(), md.ino())]);
    let mut pending = vec![fs::read_dir(root).map_err(error)?];
    while let Some(directory) = pending.last_mut() {
        let Some(entry) = directory.next() else {
            pending.pop();
            continue;
        };
        let entry = entry.map_err(error)?;
        let md = entry.metadata().map_err(error)?;
        if !md.is_dir() && !md.is_file() && !md.file_type().is_symlink() {
            return Err(error(format!(
                "unsupported rootfs entry {}",
                entry.path().display()
            )));
        }
        tree.entries += 1;
        if seen.insert((md.dev(), md.ino())) {
            tree.inodes += 1;
            tree.bytes = tree
                .bytes
                .checked_add(if md.is_file() { md.len() } else { 0 })
                .ok_or_else(|| error("rootfs size overflow"))?;
        }
        if tree.entries > MAX_ENTRIES || tree.bytes > MAX_BYTES {
            return Err(error("rootfs exceeds OCI size/inode limit"));
        }
        if md.is_dir() {
            pending.push(fs::read_dir(entry.path()).map_err(error)?);
        }
    }
    Ok(tree)
}
async fn reserve(env: &Env, parent: &Path, bytes: u64, reserve: u64) -> Result<(), String> {
    let required = bytes
        .checked_add(reserve)
        .ok_or_else(|| error("disk reserve overflow"))?;
    if env
        .fs
        .available(parent.to_path_buf())
        .await
        .map_err(error)?
        < required
    {
        return Err("DISK_FULL: insufficient free space for microvm disk and reserve".into());
    }
    Ok(())
}
fn existing_data(out: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(out) {
        Ok(md) => {
            if !md.is_file() || md.len() != DATA_BYTES {
                return Err(error(
                    "existing data drive must be a regular file of exactly 1 GiB",
                ));
            }
            let file = regular(out, DATA_BYTES, true)?;
            let actual = file.metadata().map_err(error)?;
            if actual.len() != DATA_BYTES || actual.blocks() * 512 < DATA_BYTES {
                return Err(error(
                    "existing data drive must have its full 1 GiB capacity allocated",
                ));
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(error(e)),
    }
}
async fn image(
    env: &Env,
    assets: &Assets,
    root: &Path,
    out: &Path,
    reserve_bytes: u64,
    owner: Option<(u32, u32)>,
    uuid: u128,
) -> Result<(), String> {
    assets.verify()?;
    let root = root.to_path_buf();
    let root_scan = root.clone();
    let tree = env
        .blocking("microvm disk inventory", move || scan(&root_scan))
        .await
        .ok_or_else(|| error("disk inventory cancelled"))??;
    let bytes = if owner.is_some() {
        DATA_BYTES
    } else {
        let needed = tree.bytes + tree.inodes * 8192 + (64 << 20);
        needed.div_ceil(1 << 20) * (1 << 20)
    };
    if owner.is_some() && tree.bytes + tree.inodes * 8192 + (32 << 20) > DATA_BYTES {
        return Err(error("source data does not fit the fixed 1 GiB drive"));
    }
    let parent = out.parent().ok_or_else(|| error("disk has no parent"))?;
    reserve(env, parent, bytes + (1 << 20), reserve_bytes).await?;
    let stage = stage(env, out)?;
    let disk = stage.0.join("disk.ext4");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&disk)
        .map_err(error)?;
    let allocation = file.try_clone().map_err(error)?;
    env.blocking("microvm disk allocation", move || {
        crate::microvm_sys::allocate(&allocation, bytes)
    })
    .await
    .ok_or_else(|| error("disk allocation cancelled"))?
    .map_err(error)?;
    let inodes = if owner.is_some() {
        (bytes / 16384).max(tree.inodes + 256)
    } else {
        tree.inodes + 256
    };
    let uuid = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (uuid >> 96) as u32,
        (uuid >> 80) as u16,
        (uuid >> 64) as u16,
        (uuid >> 48) as u16,
        uuid & 0xffff_ffff_ffff
    );
    let (uid, gid) = owner.unwrap_or(tree.owner);
    let log = stage.0.join("mke2fs.log");
    let status = crate::runtime::run_quick(env, ProcessSpec {
        program: assets.mke2fs.clone(),
        args: vec!["-q".into(), "-F".into(), "-t".into(), "ext4".into(), "-b".into(), "4096".into(),
            "-I".into(), "256".into(), "-m".into(), "0".into(), "-N".into(), inodes.to_string(),
            "-U".into(), uuid.clone(), "-O".into(), "none,has_journal,ext_attr,resize_inode,dir_index,filetype,extent,64bit,sparse_super,large_file,huge_file,dir_nlink,extra_isize,metadata_csum".into(),
            "-E".into(), format!("lazy_itable_init=0,lazy_journal_init=0,nodiscard,hash_seed={uuid},root_owner={uid}:{gid},root_perms={:o}", tree.mode),
            "-d".into(), root.into_os_string().into_string().map_err(|_| error("non-UTF8 root path"))?,
            disk.to_str().ok_or_else(|| error("non-UTF8 disk path"))?.into()],
        // The pinned patch preserves original mtimes; only construction timestamps use this epoch.
        // Native zeroout falls back to hole punching; explicit zero writes retain the reservation.
        env: vec![("SOURCE_DATE_EPOCH".into(), "1".into()), ("E2FSPROGS_FAKE_TIME".into(), "1".into()), ("MKE2FS_CONFIG".into(), "/dev/null".into()), ("UNIX_IO_NOZEROOUT".into(), "1".into()), ("LC_ALL".into(), "C".into())],
        cwd: None, stdout: Stdio::Append(log.clone()), stderr: Stdio::Append(log),
    }, Duration::from_secs(180)).await.map_err(error)?;
    if status != Some(0) {
        let mut detail = crate::logs::tail(&stage.0.join("mke2fs.log"), 8, &[])
            .map(|(lines, _)| lines.join("\n"))
            .unwrap_or_else(|e| format!("reading formatter diagnostics: {e:?}"));
        detail.truncate(detail.floor_char_boundary(4096));
        return Err(error(format!(
            "mke2fs directory population exited {status:?}: {detail}"
        )));
    }
    let formatted = file.metadata().map_err(error)?;
    if formatted.len() != bytes || (owner.is_some() && formatted.blocks() * 512 < bytes) {
        return Err(error(
            "mke2fs changed disk capacity or discarded reserved data blocks",
        ));
    }
    if owner.is_none() {
        file.set_permissions(Permissions::from_mode(0o400))
            .map_err(error)?;
    }
    file.sync_all().map_err(error)?;
    File::open(&stage.0)
        .map_err(error)?
        .sync_all()
        .map_err(error)?;
    crate::microvm_sys::publish(&disk, out).map_err(error)?;
    env.fs.sync_dir(parent.to_path_buf()).await.map_err(error)
}

pub(crate) async fn rootfs(
    env: &Env,
    assets: &Assets,
    root: &Path,
    out: &Path,
    manifest_digest: &str,
    reserve: u64,
) -> Result<(), String> {
    let hex = manifest_digest
        .strip_prefix("sha256:")
        .filter(|hex| valid_digest(hex))
        .ok_or_else(|| error("root image must have a verified SHA256 manifest digest"))?;
    let uuid = u128::from_str_radix(&hex[..32], 16).map_err(error)?;
    // The caller has already verified the bundle's image marker before reaching this cache.
    match fs::symlink_metadata(out) {
        Ok(_) => {
            let file = regular(out, 32 << 30, true)?;
            let md = file.metadata().map_err(error)?;
            if md.len() == 0 || md.len() % 4096 != 0 || md.mode() & 0o777 != 0o400 {
                return Err(error(
                    "cached root disk must be a private read-only block-aligned regular file",
                ));
            }
            return Ok(());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(error(e)),
    }
    image(env, assets, root, out, reserve, None, uuid).await
}
pub(crate) async fn data(
    env: &Env,
    assets: &Assets,
    source_dir: &Path,
    out: &Path,
    uid: u32,
    gid: u32,
    reserve: u64,
) -> Result<(), String> {
    if existing_data(out)? {
        return Ok(());
    }
    image(
        env,
        assets,
        source_dir,
        out,
        reserve,
        Some((uid, gid)),
        u128::from_be_bytes(env.random_bytes()),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The overflow uid is an owner like any other except for the very tool
    /// directory that the daemon checked from the host's view.
    #[test]
    fn only_the_directory_checked_from_the_host_takes_an_unmapped_owner_as_seen() {
        let (dir, _) = fixture();
        assert!(host_checked_overflow(dir.path()).is_none());
        check_from_host(dir.path()).unwrap();
        let overflow = fs::read_to_string("/proc/sys/kernel/overflowuid")
            .map(|text| text.trim().parse().unwrap())
            .unwrap_or(65_534);
        assert_eq!(host_checked_overflow(dir.path()), Some(overflow));
        for other in [dir.path().join("x"), PathBuf::from("/usr")] {
            assert!(
                host_checked_overflow(&other).is_none(),
                "{}",
                other.display()
            );
        }
        // A file of another directory is judged as before.
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(host_checked_overflow(elsewhere.path()).is_none());
    }

    #[test]
    fn a_bundle_that_someone_else_could_replace_is_refused_up_front() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = tempfile::tempdir().unwrap();
        let bundle = base.path().join("a/microvm");
        fs::create_dir_all(&bundle).unwrap();
        let me = euid();
        // The daemon's own user owns it all: fine, and so is a root-owned system path.
        check_bundle_path(&bundle, me).unwrap();
        check_bundle_path(Path::new("/usr"), me).unwrap();
        // Another user's directory anywhere on the path is refused.
        let stranger = if me == 0 {
            std::os::unix::fs::chown(base.path().join("a"), Some(65_534), None).unwrap();
            0
        } else {
            me.wrapping_add(1)
        };
        let why = check_bundle_path(&bundle, stranger).unwrap_err();
        assert!(why.contains("must be real directories"), "{why}");
        assert!(
            why.contains(base.path().join("a").to_str().unwrap()),
            "{why}"
        );
        if me == 0 {
            // Back to root's, for the checks that follow.
            std::os::unix::fs::chown(base.path().join("a"), Some(0), None).unwrap();
        }
        // Write access for others is refused, owner or not; so is a relative path.
        fs::set_permissions(base.path().join("a"), fs::Permissions::from_mode(0o775)).unwrap();
        let why = check_bundle_path(&bundle, me).unwrap_err();
        assert!(why.contains("writable by group or others"), "{why}");
        assert!(check_bundle_path(Path::new("relative/microvm"), me).is_err());
        // A link on the way is refused: it can be repointed.
        fs::set_permissions(base.path().join("a"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(base.path().join("a"), base.path().join("link")).unwrap();
        let why = check_bundle_path(&base.path().join("link/microvm"), me).unwrap_err();
        assert!(why.contains("not a real directory"), "{why}");
        // A sticky directory above is the exception (like /tmp), not the bundle's own.
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o1777)).unwrap();
        check_bundle_path(&bundle, me).unwrap();
        fs::set_permissions(&bundle, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(check_bundle_path(&bundle, me).is_err());
    }

    /// A tool on a `noexec` mount is refused with the way out. `/proc` is
    /// `noexec` on common hosts; where it is not, there is nothing to refuse.
    #[test]
    fn a_tool_on_a_noexec_mount_is_refused_with_the_way_out() {
        let here = std::env::current_exe().unwrap();
        assert!(
            executable_here(&here).is_ok(),
            "the test binary runs from here"
        );
        let proc = Path::new("/proc/self/stat");
        let noexec = File::open(proc)
            .and_then(|f| crate::sys::mount_flags(&f))
            .is_ok_and(|flags| flags & crate::sys::ST_NOEXEC != 0);
        if noexec {
            let message = executable_here(proc).unwrap_err();
            assert!(message.contains("noexec mount"), "{message}");
            assert!(message.contains("microvm_dir"), "{message}");
        }
    }
    use kronik_core::env::{BoxFuture, Fs, OpenMode};
    use std::sync::Arc;

    const IMAGE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (tempfile::TempDir, Assets) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        for name in [
            "firecracker",
            "vmlinux",
            "guest-init",
            "mke2fs",
            "provenance.json",
        ] {
            fs::write(dir.path().join(name), name).unwrap();
            fs::set_permissions(dir.path().join(name), Permissions::from_mode(0o500)).unwrap();
        }
        let hash = |name| sha256(&mut File::open(dir.path().join(name)).unwrap()).unwrap();
        let identity = Identity {
            schema: "kronik.microvm-tools/v1".into(),
            firecracker_version: "1.17.0".into(),
            kernel_version: "6.18.25".into(),
            firecracker_sha256: hash("firecracker"),
            kernel_sha256: hash("vmlinux"),
            guest_init_sha256: hash("guest-init"),
            mke2fs_sha256: hash("mke2fs"),
            mke2fs_version: "1.47.2".into(),
            provenance_sha256: hash("provenance.json"),
        };
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            dir.path().join("manifest.json"),
            Permissions::from_mode(0o600),
        )
        .unwrap();
        let assets = Assets::load(dir.path()).unwrap();
        (dir, assets)
    }
    #[test]
    fn rejects_corrupt_manifest_digest_and_symlink_without_following() {
        let (dir, assets) = fixture();
        let manifest = dir.path().join("manifest.json");
        let mut bad = assets.identity.clone();
        bad.kernel_sha256 = "A".repeat(64);
        fs::write(&manifest, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(Assets::load(dir.path()).is_err());
        fs::write(&manifest, b"{").unwrap();
        assert!(Assets::load(dir.path()).is_err());
        let mut unknown = serde_json::to_value(&assets.identity).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        fs::write(&manifest, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(Assets::load(dir.path()).is_err());
        fs::write(&manifest, serde_json::to_vec(&assets.identity).unwrap()).unwrap();
        for mode in [0o644, 0o444] {
            fs::set_permissions(&manifest, Permissions::from_mode(mode)).unwrap();
            assert!(Assets::load(dir.path()).is_ok());
        }
        for mode in [0o660, 0o664] {
            fs::set_permissions(&manifest, Permissions::from_mode(mode)).unwrap();
            assert!(Assets::load(dir.path()).is_err());
        }
        fs::set_permissions(&manifest, Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&assets.kernel, Permissions::from_mode(0o600)).unwrap();
        fs::write(&assets.kernel, b"corrupt").unwrap();
        assert!(Assets::load(dir.path()).is_err());
        fs::remove_file(&assets.kernel).unwrap();
        std::os::unix::fs::symlink("firecracker", &assets.kernel).unwrap();
        assert!(Assets::load(dir.path()).is_err());
        assert_eq!(fs::read(&assets.firecracker).unwrap(), b"firecracker");
        fs::remove_file(&manifest).unwrap();
        std::os::unix::fs::symlink("firecracker", &manifest).unwrap();
        assert!(Assets::load(dir.path()).is_err());
    }
    #[test]
    fn public_readonly_installed_tools_are_verified_but_linked_manifests_are_rejected() {
        let (dir, assets) = fixture();
        fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        for name in ["firecracker", "guest-init", "mke2fs"] {
            fs::set_permissions(dir.path().join(name), Permissions::from_mode(0o555)).unwrap();
        }
        for name in ["vmlinux", "manifest.json", "provenance.json"] {
            fs::set_permissions(dir.path().join(name), Permissions::from_mode(0o444)).unwrap();
        }
        assert_eq!(Assets::load(dir.path()).unwrap().identity, assets.identity);
        let alias = dir.path().join("manifest-alias");
        fs::hard_link(dir.path().join("manifest.json"), &alias).unwrap();
        assert!(Assets::load(dir.path()).is_err());
        fs::remove_file(alias).unwrap();
        assert!(Assets::load(dir.path()).is_ok());
    }
    #[test]
    fn manifest_identity_ignores_json_whitespace_and_binds_all_fields() {
        let (dir, assets) = fixture();
        let mut value = serde_json::to_value(&assets.identity).unwrap();
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
        assert_eq!(Assets::load(dir.path()).unwrap().identity, assets.identity);
        assert_eq!(
            digest(&assets.kernel).unwrap(),
            assets.identity.kernel_sha256
        );
        for (key, field) in value.as_object().unwrap() {
            let mut changed = value.clone();
            changed[key] = serde_json::json!(format!("{}-changed", field.as_str().unwrap()));
            fs::write(
                dir.path().join("manifest.json"),
                serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();
            assert!(
                Assets::load(dir.path()).is_err(),
                "manifest field {key} was not bound"
            );
        }
        value["schema"] = serde_json::json!("kronik.microvm-tools/v2");
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(Assets::load(dir.path()).is_err());
        fs::write(dir.path().join("manifest.json"), vec![b' '; 65537]).unwrap();
        assert!(Assets::load(dir.path()).is_err());
    }
    #[test]
    fn existing_drive_is_exact_regular_private_and_never_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("data.ext4");
        assert!(!existing_data(&out).unwrap());
        fs::write(&out, b"production").unwrap();
        fs::set_permissions(&out, Permissions::from_mode(0o600)).unwrap();
        assert!(existing_data(&out).is_err());
        assert_eq!(fs::read(&out).unwrap(), b"production");
        OpenOptions::new()
            .write(true)
            .open(&out)
            .unwrap()
            .set_len(DATA_BYTES)
            .unwrap();
        assert!(
            existing_data(&out).is_err(),
            "a sparse 1 GiB file is not a reserved drive"
        );
        let mut start = [0; 10];
        File::open(&out).unwrap().read_exact(&mut start).unwrap();
        assert_eq!(&start, b"production");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&out, &link).unwrap();
        assert!(existing_data(&link).is_err());
    }
    fn tree(root: &Path) {
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::write(root.join("dir/file"), b"actual contents\n").unwrap();
        fs::set_permissions(root.join("dir/file"), Permissions::from_mode(0o640)).unwrap();
        std::os::unix::fs::symlink("file", root.join("dir/link")).unwrap();
        fs::hard_link(root.join("dir/file"), root.join("dir/hard")).unwrap();
        for path in [
            root.to_path_buf(),
            root.join("dir"),
            root.join("dir/file"),
            root.join("dir/link"),
        ] {
            crate::microvm_sys::set_mtime(&path, 1234567890).unwrap();
        }
    }
    #[test]
    fn inventory_counts_hardlinks_once_and_requires_a_directory_root() {
        let root = tempfile::tempdir().unwrap();
        tree(root.path());
        let inventory = scan(root.path()).unwrap();
        assert_eq!(
            (inventory.entries, inventory.inodes, inventory.bytes),
            (5, 4, b"actual contents\n".len() as u64)
        );
        let md = fs::metadata(root.path()).unwrap();
        assert_eq!(inventory.owner, (md.uid(), md.gid()));
        assert_eq!(inventory.mode, md.mode() & 0o7777);
        assert!(scan(&root.path().join("dir/file")).is_err());
    }

    #[test]
    fn bounds_sparse_sources_and_rejects_live_socket_entries() {
        let root = tempfile::tempdir().unwrap();
        let file = File::create(root.path().join("oversized")).unwrap();
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(scan(root.path()).is_err());
        fs::remove_file(root.path().join("oversized")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(root.path().join("socket")).unwrap();
        assert!(scan(root.path()).is_err());
    }

    struct NoSpace(Arc<dyn Fs>);
    impl Fs for NoSpace {
        fn create_dir_all(&self, p: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.0.create_dir_all(p)
        }
        fn open(
            &self,
            p: PathBuf,
            m: OpenMode,
        ) -> BoxFuture<'static, io::Result<Arc<dyn kronik_core::env::File>>> {
            self.0.open(p, m)
        }
        fn exists(&self, p: PathBuf) -> BoxFuture<'static, io::Result<bool>> {
            self.0.exists(p)
        }
        fn read_dir(&self, p: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>> {
            self.0.read_dir(p)
        }
        fn rename(&self, p: PathBuf, q: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.0.rename(p, q)
        }
        fn remove_file(&self, p: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.0.remove_file(p)
        }
        fn sync_dir(&self, p: PathBuf) -> BoxFuture<'static, io::Result<()>> {
            self.0.sync_dir(p)
        }
        fn available(&self, _: PathBuf) -> BoxFuture<'static, io::Result<u64>> {
            Box::pin(async { Err(io::Error::from_raw_os_error(libc::ENOSPC)) })
        }
    }
    #[tokio::test]
    async fn enospc_and_sparse_existing_data_never_modify_source_or_reformat() {
        let (_tools, assets) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        tree(&source);
        let mut env = Env::real(tokio::runtime::Handle::current());
        env.fs = Arc::new(NoSpace(env.fs.clone()));
        let out = dir.path().join("data.ext4");
        assert!(
            data(&env, &assets, &source, &out, 123, 456, 0)
                .await
                .is_err()
        );
        assert!(!out.exists());
        assert_eq!(
            fs::read(source.join("dir/file")).unwrap(),
            b"actual contents\n"
        );
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&out)
            .unwrap();
        file.set_len(DATA_BYTES).unwrap();
        fs::remove_file(&assets.mke2fs).unwrap();
        assert!(
            data(&env, &assets, &source, &out, 123, 456, u64::MAX)
                .await
                .is_err()
        );
        assert_eq!(fs::metadata(out).unwrap().len(), DATA_BYTES);
    }
    #[tokio::test]
    async fn matching_bundle_root_is_reused_without_writes_and_unsafe_roots_are_rejected() {
        let (_tools, assets) = fixture();
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("root.ext4");
        fs::write(&out, vec![0u8; 4096]).unwrap();
        fs::set_permissions(&out, Permissions::from_mode(0o400)).unwrap();
        let before = fs::metadata(&out).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        assert!(
            rootfs(&env, &assets, dir.path(), &out, "sha256:bad", 0)
                .await
                .is_err()
        );
        rootfs(
            &env,
            &assets,
            &dir.path().join("unneeded-unpacked-tree"),
            &out,
            IMAGE_DIGEST,
            u64::MAX,
        )
        .await
        .unwrap();
        assert_eq!(fs::metadata(&out).unwrap().ino(), before.ino());
        assert_eq!(fs::read(&out).unwrap(), vec![0u8; 4096]);
        fs::set_permissions(&out, Permissions::from_mode(0o600)).unwrap();
        assert!(
            rootfs(&env, &assets, dir.path(), &out, IMAGE_DIGEST, 0)
                .await
                .is_err()
        );
        fs::set_permissions(&out, Permissions::from_mode(0o400)).unwrap();
        let alias = dir.path().join("alias");
        fs::hard_link(&out, &alias).unwrap();
        assert!(
            rootfs(&env, &assets, dir.path(), &out, IMAGE_DIGEST, 0)
                .await
                .is_err()
        );
        fs::remove_file(alias).unwrap();
        fs::remove_file(&out).unwrap();
        fs::write(dir.path().join("canary"), b"outside").unwrap();
        std::os::unix::fs::symlink("canary", &out).unwrap();
        assert!(
            rootfs(&env, &assets, dir.path(), &out, IMAGE_DIGEST, 0)
                .await
                .is_err()
        );
        assert_eq!(fs::read(dir.path().join("canary")).unwrap(), b"outside");
    }
    async fn tool(env: &Env, program: PathBuf, args: Vec<String>, log: &Path) -> String {
        let status = crate::runtime::run_quick(
            env,
            ProcessSpec {
                program,
                args,
                env: Vec::new(),
                cwd: None,
                stdout: Stdio::Append(log.to_path_buf()),
                stderr: Stdio::Append(log.to_path_buf()),
            },
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(
            status,
            Some(0),
            "{}",
            fs::read_to_string(log).unwrap_or_default()
        );
        fs::read_to_string(log).unwrap()
    }
    /// Explicit required offline gate: the source builder runs this before publication.
    #[tokio::test]
    #[ignore = "requires the explicitly built pinned tools; absence is a gate failure, not a skip"]
    async fn real_ext4_metadata_and_two_location_reproducibility() {
        let assets = Assets::load(Path::new(
            &std::env::var("KRONIK_MICROVM_ASSETS").expect("required built asset directory"),
        ))
        .unwrap();
        ext4_roundtrip(assets).await;
    }
    #[tokio::test]
    #[ignore = "explicit local ext4 proof requires caller-selected installed e2fsprogs 1.47.2 tools"]
    async fn real_ext4_with_installed_tools() {
        let source = PathBuf::from(
            std::env::var_os("KRONIK_MICROVM_EXT4_TOOLS")
                .expect("required installed e2fsprogs directory"),
        );
        assert!(source.is_absolute());
        let (_fixture, mut assets) = fixture();
        // Only filesystem tools execute here; the full pinned-asset/KVM gate stays separate.
        for name in ["mke2fs", "debugfs", "e2fsck"] {
            // The fixture's placeholder is read-only (0500): a copy over it is
            // refused to anyone but root, and the builder runs unprivileged.
            match fs::remove_file(assets.dir.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("removing the placeholder {name}: {error}"),
            }
            fs::copy(source.join(name), assets.dir.join(name)).unwrap();
            fs::set_permissions(assets.dir.join(name), Permissions::from_mode(0o500)).unwrap();
        }
        assets.identity.mke2fs_sha256 = sha256(&mut File::open(&assets.mke2fs).unwrap()).unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        for name in ["mke2fs", "debugfs", "e2fsck"] {
            let version = tool(
                &env,
                assets.dir.join(name),
                vec!["-V".into()],
                &assets.dir.join(format!("{name}-version.log")),
            )
            .await;
            assert_eq!(
                version.split_whitespace().nth(1),
                Some("1.47.2"),
                "{version}"
            );
        }
        ext4_roundtrip(assets).await;
    }
    fn assert_mtime(stat: &str, source: &fs::Metadata) {
        let time = stat
            .lines()
            .find(|line| line.trim_start().starts_with("mtime:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let (low, extra) = time.split_once(':').unwrap();
        let low = u32::from_str_radix(low.trim_start_matches("0x"), 16).unwrap();
        let extra = u32::from_str_radix(extra, 16).unwrap();
        assert_eq!(
            i64::from(low as i32) + (i64::from(extra & 3) << 32),
            source.mtime(),
            "{stat}"
        );
        assert_eq!(i64::from(extra >> 2), source.mtime_nsec(), "{stat}");
    }
    async fn ext4_roundtrip(assets: Assets) {
        let env = Env::real(tokio::runtime::Handle::current());
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let root_a = first.path().join("tree");
        let root_b = second.path().join("tree");
        let payload = first.path().join("payload");
        fs::create_dir(&payload).unwrap();
        tree(&payload);
        let layout = first.path().join("layout");
        let image_digest = crate::oci::pack(
            &layout,
            &[crate::oci::LayerSource {
                dir: payload,
                gzip: false,
            }],
            &crate::oci::ImageSpec {
                entrypoint: vec!["/dir/file".into()],
                workdir: "/dir/missing/nested".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let store = crate::blobs::BlobStore::new(layout.join("blobs"));
        let image = crate::oci::Image::open(&store, &image_digest).unwrap();
        let limits = crate::oci::UnpackLimits {
            preserve_owners: false,
            ..Default::default()
        };
        crate::oci::unpack(&store, &image, &root_a, &limits).unwrap();
        crate::oci::runtime_spec(&image, &root_a, &crate::oci::Overrides::default()).unwrap();
        env.clock.sleep(Duration::from_millis(1100)).await;
        crate::oci::unpack(&store, &image, &root_b, &limits).unwrap();
        crate::oci::runtime_spec(&image, &root_b, &crate::oci::Overrides::default()).unwrap();
        assert_eq!(
            fs::metadata(root_a.join("dir/missing/nested"))
                .unwrap()
                .mtime(),
            0
        );
        assert_eq!(
            fs::metadata(root_b.join("dir/missing/nested"))
                .unwrap()
                .mtime(),
            0
        );
        for root in [&root_a, &root_b] {
            fs::remove_file(root.join("dir/hard")).unwrap();
            fs::hard_link(root.join("dir/file"), root.join("dir/hard")).unwrap();
            let future = root.join("dir/future");
            fs::write(&future, b"future timestamp\n").unwrap();
            File::open(&future)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + Duration::new(2_200_000_000, 123_456_789),
                ))
                .unwrap();
            crate::microvm_sys::set_mtime(&root.join("dir"), 1234567890).unwrap();
            fs::set_permissions(root, Permissions::from_mode(0o750)).unwrap();
            File::open(root)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + Duration::new(0, 777_888_999)),
                )
                .unwrap();
        }
        let a = first.path().join("root.ext4");
        let b = second.path().join("root.ext4");
        rootfs(&env, &assets, &root_a, &a, &image_digest, 0)
            .await
            .unwrap();
        rootfs(&env, &assets, &root_b, &b, &image_digest, 0)
            .await
            .unwrap();
        assert_eq!(
            sha256(&mut File::open(&a).unwrap()).unwrap(),
            sha256(&mut File::open(&b).unwrap()).unwrap()
        );
        assert_eq!(fs::metadata(&a).unwrap().mode() & 0o777, 0o400);
        tool(
            &env,
            assets.dir.join("e2fsck"),
            vec!["-fn".into(), a.display().to_string()],
            &first.path().join("fsck.log"),
        )
        .await;
        let stat = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /dir/file".into(),
                a.display().to_string(),
            ],
            &first.path().join("stat.log"),
        )
        .await;
        let md = fs::metadata(root_a.join("dir/file")).unwrap();
        assert!(stat.contains("0640"), "{stat}");
        assert_mtime(&stat, &md);
        let fields = stat.split_whitespace().collect::<Vec<_>>();
        for (label, value) in [("User:", md.uid()), ("Group:", md.gid())] {
            let index = fields.iter().position(|x| *x == label).unwrap();
            assert_eq!(fields[index + 1].parse::<u32>().unwrap(), value);
        }
        let hard = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /dir/hard".into(),
                a.display().to_string(),
            ],
            &first.path().join("hard.log"),
        )
        .await;
        let inode = |text: &str| {
            text.split("Inode: ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        assert_eq!(inode(&stat), inode(&hard));
        let future = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /dir/future".into(),
                a.display().to_string(),
            ],
            &first.path().join("future.log"),
        )
        .await;
        assert_mtime(&future, &fs::metadata(root_a.join("dir/future")).unwrap());
        let root_stat = tool(
            &env,
            assets.dir.join("debugfs"),
            vec!["-R".into(), "stat /".into(), a.display().to_string()],
            &first.path().join("root.log"),
        )
        .await;
        assert_mtime(&root_stat, &fs::metadata(&root_a).unwrap());
        assert_eq!(
            root_stat
                .split("Mode:")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next(),
            Some("0750"),
            "{root_stat}"
        );
        let dump = first.path().join("dump");
        tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                format!("dump /dir/file {}", dump.display()),
                a.display().to_string(),
            ],
            &first.path().join("dump.log"),
        )
        .await;
        assert_eq!(fs::read(&dump).unwrap(), b"actual contents\n");
        let link = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /dir/link".into(),
                a.display().to_string(),
            ],
            &first.path().join("link.log"),
        )
        .await;
        assert!(link.contains("Fast link dest: \"file\""), "{link}");
        let before = fs::metadata(&a).unwrap();
        rootfs(&env, &assets, &root_a, &a, &image_digest, u64::MAX)
            .await
            .unwrap();
        assert_eq!(fs::metadata(&a).unwrap().ino(), before.ino());
        let historical = root_a.join("historical");
        fs::write(&historical, b"historical timestamp\n").unwrap();
        File::open(&historical)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH - Duration::new(1, 0)),
            )
            .unwrap();
        File::open(&root_a)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + Duration::new(0, 777_888_999)),
            )
            .unwrap();
        let retained = first.path().join("retained-data.ext4");
        fs::write(&retained, b"irreplaceable data").unwrap();
        fs::set_permissions(&retained, Permissions::from_mode(0o600)).unwrap();
        let retained_inode = fs::metadata(&retained).unwrap().ino();
        assert!(
            data(&env, &assets, &root_a, &retained, 12345, 23456, 0)
                .await
                .is_err()
        );
        assert_eq!(fs::read(&retained).unwrap(), b"irreplaceable data");
        assert_eq!(fs::metadata(&retained).unwrap().ino(), retained_inode);
        let data_disk = first.path().join("data.ext4");
        data(&env, &assets, &root_a, &data_disk, 12345, 23456, 0)
            .await
            .unwrap();
        assert_eq!(fs::metadata(&data_disk).unwrap().len(), DATA_BYTES);
        assert!(fs::metadata(&data_disk).unwrap().blocks() * 512 >= DATA_BYTES);
        let root_stat = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /".into(),
                data_disk.display().to_string(),
            ],
            &first.path().join("data-stat.log"),
        )
        .await;
        let fields = root_stat.split_whitespace().collect::<Vec<_>>();
        for (label, value) in [("User:", 12345u32), ("Group:", 23456u32)] {
            let index = fields.iter().position(|x| *x == label).unwrap();
            assert_eq!(fields[index + 1].parse::<u32>().unwrap(), value);
        }
        assert_mtime(&root_stat, &fs::metadata(&root_a).unwrap());
        assert_eq!(
            root_stat
                .split("Mode:")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next(),
            Some("0750"),
            "{root_stat}"
        );
        let historical_stat = tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                "stat /historical".into(),
                data_disk.display().to_string(),
            ],
            &first.path().join("historical.log"),
        )
        .await;
        assert_mtime(&historical_stat, &fs::metadata(&historical).unwrap());
        let byte = first.path().join("byte");
        fs::write(&byte, b"x").unwrap();
        let batch = first.path().join("writes.debugfs");
        let commands = (0..1000)
            .map(|n| format!("write {} /new-{n}\n", byte.display()))
            .collect::<String>();
        fs::write(&batch, commands).unwrap();
        tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-w".into(),
                "-f".into(),
                batch.display().to_string(),
                data_disk.display().to_string(),
            ],
            &first.path().join("inodes.log"),
        )
        .await;
        let mut unavailable_tools = assets.clone();
        unavailable_tools.mke2fs = first.path().join("missing-mke2fs");
        data(
            &env,
            &unavailable_tools,
            &root_a,
            &data_disk,
            12345,
            23456,
            u64::MAX,
        )
        .await
        .unwrap();
        let inode_dump = first.path().join("inode-dump");
        tool(
            &env,
            assets.dir.join("debugfs"),
            vec![
                "-R".into(),
                format!("dump /new-999 {}", inode_dump.display()),
                data_disk.display().to_string(),
            ],
            &first.path().join("inode-dump.log"),
        )
        .await;
        assert_eq!(fs::read(inode_dump).unwrap(), b"x");
        tool(
            &env,
            assets.dir.join("e2fsck"),
            vec!["-fn".into(), data_disk.display().to_string()],
            &first.path().join("data-fsck.log"),
        )
        .await;
    }
}
