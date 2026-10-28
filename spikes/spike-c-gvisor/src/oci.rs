//! OCI image layouts: packing a test image, opening and verifying an image,
//! unpacking its layers into a rootfs and generating the runtime spec
//! (`config.json`) for runsc.
//!
//! Unpacking follows the OCI image spec (layer.md): layers are applied in
//! order, `.wh.<name>` removes `<name>` from lower layers, `.wh..wh..opq`
//! hides every lower-layer entry of its directory, and entries of one layer
//! are never hidden by whiteouts in the same layer. Paths are resolved as if
//! the rootfs were `/`: symlinks (including absolute ones) never lead outside
//! it, and entries containing `..` are rejected.

use std::collections::{HashSet, VecDeque};
use std::ffi::OsString;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown, lchown, symlink};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub type Result<T, E = String> = std::result::Result<T, E>;

pub trait Context<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: Display> Context<T> for std::result::Result<T, E> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| format!("{}: {e}", what()))
    }
}

pub const MEDIA_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const MEDIA_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const MEDIA_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub const MEDIA_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
pub const MEDIA_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const MEDIA_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const DOCKER_LAYER_TAR: &str = "application/vnd.docker.image.rootfs.diff.tar";
const REF_NAME: &str = "org.opencontainers.image.ref.name";
const OPAQUE: &str = ".wh..wh..opq";
const WHITEOUT_PREFIX: &str = ".wh.";

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

impl Descriptor {
    fn from_json(v: &Value) -> Result<Self> {
        Ok(Self {
            media_type: v["mediaType"].as_str().unwrap_or_default().to_string(),
            digest: v["digest"]
                .as_str()
                .ok_or("descriptor without digest")?
                .to_string(),
            size: v["size"].as_u64().ok_or("descriptor without size")?,
        })
    }

    fn to_json(&self) -> Value {
        json!({ "mediaType": self.media_type, "digest": self.digest, "size": self.size })
    }
}

fn blob_path(layout: &Path, digest: &str) -> Result<PathBuf> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("unsupported digest {digest}"))?;
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("malformed digest {digest}"));
    }
    Ok(layout.join("blobs").join("sha256").join(hex))
}

/// Reads a small blob (index, manifest, config) and checks size and digest.
fn read_verified(layout: &Path, desc: &Descriptor) -> Result<Vec<u8>> {
    let path = blob_path(layout, &desc.digest)?;
    let bytes = fs::read(&path).ctx(|| format!("read blob {}", path.display()))?;
    if bytes.len() as u64 != desc.size {
        return Err(format!(
            "blob {} has {} bytes, descriptor says {}",
            desc.digest,
            bytes.len(),
            desc.size
        ));
    }
    let actual = format!("sha256:{}", sha256_hex(&bytes));
    if actual != desc.digest {
        return Err(format!("blob {} has digest {actual}", desc.digest));
    }
    Ok(bytes)
}

/// Streams a (possibly large) blob through SHA-256 and checks size and digest.
fn verify_blob_file(layout: &Path, desc: &Descriptor) -> Result<()> {
    let path = blob_path(layout, &desc.digest)?;
    let file = File::open(&path).ctx(|| format!("open blob {}", path.display()))?;
    let mut reader = HashingReader::new(BufReader::new(file));
    let n = io::copy(&mut reader, &mut io::sink()).ctx(|| format!("read {}", path.display()))?;
    let actual = format!("sha256:{}", reader.hex());
    if n != desc.size || actual != desc.digest {
        return Err(format!(
            "layer blob {} failed verification: {n} bytes, {actual}",
            desc.digest
        ));
    }
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn hex(self) -> String {
        hex(&self.hasher.finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

fn parse_json(bytes: &[u8], what: &str) -> Result<Value> {
    serde_json::from_slice(bytes).ctx(|| format!("parse {what}"))
}

pub struct Image {
    pub manifest_digest: String,
    pub config_digest: String,
    pub config: Value,
    pub layers: Vec<Descriptor>,
    pub diff_ids: Vec<String>,
}

/// Opens an image in an OCI layout. `reference` is a manifest digest
/// (`sha256:...`) or a ref name annotation; without it, the layout must
/// contain exactly one image. Index, manifest and config are verified
/// against their digests.
pub fn open_image(layout: &Path, reference: Option<&str>) -> Result<Image> {
    let marker = parse_json(
        &fs::read(layout.join("oci-layout"))
            .ctx(|| format!("{} is not an OCI layout", layout.display()))?,
        "oci-layout",
    )?;
    if marker["imageLayoutVersion"] != "1.0.0" {
        return Err(format!(
            "unsupported layout version {}",
            marker["imageLayoutVersion"]
        ));
    }
    let index = parse_json(
        &fs::read(layout.join("index.json")).ctx(|| "read index.json".to_string())?,
        "index.json",
    )?;
    let manifests = index["manifests"]
        .as_array()
        .ok_or("index.json without manifests")?;
    let chosen: Vec<&Value> = manifests
        .iter()
        .filter(|m| match reference {
            Some(r) if r.starts_with("sha256:") => m["digest"] == r,
            Some(r) => {
                m["annotations"][REF_NAME] == r || m["annotations"]["io.containerd.image.name"] == r
            }
            None => true,
        })
        .collect();
    let [top] = chosen.as_slice() else {
        return Err(format!(
            "{} images match {reference:?} in {}",
            chosen.len(),
            layout.display()
        ));
    };
    let mut desc = Descriptor::from_json(top)?;
    // An index may point at a nested index (multi-platform); pick linux/amd64.
    while desc.media_type == MEDIA_INDEX || desc.media_type == DOCKER_LIST {
        let nested = parse_json(&read_verified(layout, &desc)?, "nested index")?;
        let entry = nested["manifests"]
            .as_array()
            .and_then(|ms| {
                ms.iter().find(|m| {
                    m["platform"]["os"] == "linux" && m["platform"]["architecture"] == "amd64"
                })
            })
            .ok_or("no linux/amd64 manifest in nested index")?;
        desc = Descriptor::from_json(entry)?;
    }
    if desc.media_type != MEDIA_MANIFEST && desc.media_type != DOCKER_MANIFEST {
        return Err(format!(
            "unsupported manifest media type {}",
            desc.media_type
        ));
    }
    let manifest = parse_json(&read_verified(layout, &desc)?, "manifest")?;
    let config_desc = Descriptor::from_json(&manifest["config"])?;
    let config = parse_json(&read_verified(layout, &config_desc)?, "image config")?;
    if config["os"] != "linux" || config["architecture"] != "amd64" {
        return Err(format!(
            "image is {}/{}, not linux/amd64",
            config["os"], config["architecture"]
        ));
    }
    let layers = manifest["layers"]
        .as_array()
        .ok_or("manifest without layers")?
        .iter()
        .map(Descriptor::from_json)
        .collect::<Result<Vec<_>>>()?;
    let diff_ids: Vec<String> = config["rootfs"]["diff_ids"]
        .as_array()
        .ok_or("config without rootfs.diff_ids")?
        .iter()
        .map(|d| d.as_str().unwrap_or_default().to_string())
        .collect();
    if diff_ids.len() != layers.len() {
        return Err(format!(
            "{} layers but {} diff_ids",
            layers.len(),
            diff_ids.len()
        ));
    }
    Ok(Image {
        manifest_digest: desc.digest,
        config_digest: config_desc.digest,
        config,
        layers,
        diff_ids,
    })
}

#[derive(Debug, Default)]
pub struct UnpackStats {
    pub layers: usize,
    pub entries: usize,
    pub whiteouts: usize,
    pub opaque_dirs: usize,
    pub skipped: usize,
}

/// Unpacks all layers of `image` into `rootfs`, which must not exist yet.
/// Each layer blob is verified before anything from it is applied, and its
/// uncompressed digest is checked against the config's diff_id.
pub fn unpack(layout: &Path, image: &Image, rootfs: &Path) -> Result<UnpackStats> {
    fs::create_dir(rootfs).ctx(|| format!("create {}", rootfs.display()))?;
    fs::set_permissions(rootfs, Permissions::from_mode(0o755))
        .ctx(|| "chmod rootfs".to_string())?;
    let mut stats = UnpackStats::default();
    for (i, layer) in image.layers.iter().enumerate() {
        verify_blob_file(layout, layer)?;
        let path = blob_path(layout, &layer.digest)?;
        let file = BufReader::new(File::open(&path).ctx(|| format!("open {}", path.display()))?);
        let decoded: Box<dyn Read> = match layer.media_type.as_str() {
            MEDIA_LAYER_TAR | DOCKER_LAYER_TAR => Box::new(file),
            MEDIA_LAYER_GZIP | DOCKER_LAYER_GZIP => {
                Box::new(flate2::read::MultiGzDecoder::new(file))
            }
            MEDIA_LAYER_ZSTD => return Err("zstd layers are not supported by this spike".into()),
            other => return Err(format!("unsupported layer media type {other}")),
        };
        let mut hashing = HashingReader::new(decoded);
        apply_layer(rootfs, &mut hashing, &mut stats)
            .ctx(|| format!("layer {i} ({})", layer.digest))?;
        // Trailing tar padding after the end-of-archive marker is part of the diff_id.
        io::copy(&mut hashing, &mut io::sink()).ctx(|| "drain layer".to_string())?;
        let diff_id = format!("sha256:{}", hashing.hex());
        if diff_id != image.diff_ids[i] {
            return Err(format!(
                "layer {i}: uncompressed digest {diff_id} does not match diff_id {}",
                image.diff_ids[i]
            ));
        }
        stats.layers += 1;
    }
    Ok(stats)
}

/// Normalizes a tar entry path to a relative path. Rejects `..`.
fn sanitize(path: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(format!("entry {} escapes the rootfs", path.display()));
            }
        }
    }
    Ok(out)
}

/// Resolves the relative path `rel` inside `root` like a lookup in
/// `chroot(root)`: symlinks are followed, absolute targets restart at `root`
/// and `..` stops at `root`. Returns the resolved path relative to `root`.
/// Missing directories are created (and recorded in `created`) when `create`
/// is set; otherwise the unresolved rest is appended as is.
fn resolve(
    root: &Path,
    rel: &Path,
    create: bool,
    created: &mut HashSet<PathBuf>,
) -> Result<PathBuf> {
    let mut resolved = PathBuf::new();
    let mut pending: VecDeque<OsString> = rel
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        if part == "." || part == "/" {
            continue;
        }
        let candidate = resolved.join(&part);
        let full = root.join(&candidate);
        match fs::symlink_metadata(&full) {
            Ok(md) if md.file_type().is_symlink() => {
                links += 1;
                if links > 40 {
                    return Err(format!("too many symlinks resolving {}", rel.display()));
                }
                let target = fs::read_link(&full).ctx(|| format!("readlink {}", full.display()))?;
                if target.is_absolute() {
                    resolved = PathBuf::new();
                }
                for component in target.components().rev() {
                    match component {
                        Component::Normal(p) => pending.push_front(p.to_os_string()),
                        Component::ParentDir => pending.push_front("..".into()),
                        _ => {}
                    }
                }
            }
            Ok(md) if md.is_dir() => resolved = candidate,
            Ok(_) if pending.is_empty() => resolved = candidate,
            Ok(_) => return Err(format!("{} is not a directory", candidate.display())),
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                fs::create_dir(&full).ctx(|| format!("mkdir {}", full.display()))?;
                fs::set_permissions(&full, Permissions::from_mode(0o755))
                    .ctx(|| format!("chmod {}", full.display()))?;
                created.insert(candidate.clone());
                resolved = candidate;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                resolved = candidate;
                for rest in pending.drain(..) {
                    if rest == ".." {
                        resolved.pop();
                    } else {
                        resolved.push(rest);
                    }
                }
            }
            Err(e) => return Err(format!("lstat {}: {e}", full.display())),
        }
    }
    Ok(resolved)
}

/// Removes a file, symlink or directory tree without following symlinks.
fn remove_any(path: &Path) -> Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    result.ctx(|| format!("remove {}", path.display()))
}

/// Applies one uncompressed layer tarball to `root`.
pub fn apply_layer(root: &Path, reader: impl Read, stats: &mut UnpackStats) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    // Entries created by this layer, as resolved paths relative to root.
    // Whiteouts only hide entries from lower layers.
    let mut created: HashSet<PathBuf> = HashSet::new();
    for entry in archive.entries().ctx(|| "read tar".to_string())? {
        let mut entry = entry.ctx(|| "read tar entry".to_string())?;
        let raw = entry.path().ctx(|| "entry path".to_string())?.into_owned();
        let rel = sanitize(&raw)?;
        stats.entries += 1;
        let Some(name) = rel.file_name().map(|n| n.to_os_string()) else {
            continue; // the root directory itself
        };
        let parent_rel = rel.parent().unwrap_or(Path::new("")).to_path_buf();
        let name_str = name.to_string_lossy();

        if name_str == OPAQUE {
            let dir = resolve(root, &parent_rel, false, &mut created)?;
            match fs::read_dir(root.join(&dir)) {
                Ok(children) => {
                    for child in children {
                        let child = child.ctx(|| "read dir".to_string())?;
                        let child_rel = dir.join(child.file_name());
                        if !created.contains(&child_rel) {
                            remove_any(&root.join(&child_rel))?;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("read {}: {e}", dir.display())),
            }
            stats.opaque_dirs += 1;
            continue;
        }
        if let Some(hidden) = name_str.strip_prefix(WHITEOUT_PREFIX) {
            let dir = resolve(root, &parent_rel, false, &mut created)?;
            let target = dir.join(hidden);
            if !created.contains(&target) {
                remove_any(&root.join(&target))?;
            }
            stats.whiteouts += 1;
            continue;
        }

        let dir = resolve(root, &parent_rel, true, &mut created)?;
        let dest_rel = dir.join(&name);
        let dest = root.join(&dest_rel);
        let header = entry.header();
        let mode = header.mode().ctx(|| "mode".to_string())? & 0o7777;
        let uid =
            u32::try_from(header.uid().ctx(|| "uid".to_string())?).map_err(|e| e.to_string())?;
        let gid =
            u32::try_from(header.gid().ctx(|| "gid".to_string())?).map_err(|e| e.to_string())?;
        let ctx = || format!("{}", dest_rel.display());
        match header.entry_type() {
            tar::EntryType::Directory => {
                match fs::symlink_metadata(&dest) {
                    Ok(md) if md.is_dir() => {}
                    Ok(_) => {
                        remove_any(&dest)?;
                        fs::create_dir(&dest).ctx(ctx)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&dest).ctx(ctx)?
                    }
                    Err(e) => return Err(format!("{}: {e}", ctx())),
                }
                chown(&dest, Some(uid), Some(gid)).ctx(ctx)?;
                fs::set_permissions(&dest, Permissions::from_mode(mode)).ctx(ctx)?;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                remove_any(&dest)?;
                // create_new is O_CREAT|O_EXCL: it never follows a symlink.
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&dest)
                    .ctx(ctx)?;
                io::copy(&mut entry, &mut file).ctx(ctx)?;
                // chown before chmod: chown clears setuid and setgid bits.
                chown(&dest, Some(uid), Some(gid)).ctx(ctx)?;
                file.set_permissions(Permissions::from_mode(mode))
                    .ctx(ctx)?;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .ctx(ctx)?
                    .ok_or_else(|| format!("{}: symlink without target", ctx()))?
                    .into_owned();
                remove_any(&dest)?;
                symlink(&target, &dest).ctx(ctx)?;
                lchown(&dest, Some(uid), Some(gid)).ctx(ctx)?;
            }
            tar::EntryType::Link => {
                let target_raw = entry
                    .link_name()
                    .ctx(ctx)?
                    .ok_or_else(|| format!("{}: hard link without target", ctx()))?
                    .into_owned();
                let target_rel = sanitize(&target_raw)?;
                let target_name = target_rel
                    .file_name()
                    .ok_or_else(|| format!("{}: bad hard link target", ctx()))?;
                let target_dir = resolve(
                    root,
                    target_rel.parent().unwrap_or(Path::new("")),
                    false,
                    &mut created,
                )?;
                let target = root.join(target_dir.join(target_name));
                remove_any(&dest)?;
                // linkat(2) without AT_SYMLINK_FOLLOW: links the entry itself.
                fs::hard_link(&target, &dest).ctx(ctx)?;
            }
            // Device nodes and FIFOs are not created; the runtime provides /dev.
            _ => {
                stats.skipped += 1;
                continue;
            }
        }
        created.insert(dest_rel);
    }
    Ok(())
}

/// Reads a file inside the rootfs, resolving symlinks within it.
fn read_in_root(rootfs: &Path, rel: &str) -> Option<String> {
    let path = resolve(rootfs, Path::new(rel), false, &mut HashSet::new()).ok()?;
    fs::read_to_string(rootfs.join(path)).ok()
}

fn lookup_id(db: &str, name: &str) -> Option<(u32, u32)> {
    db.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&name) && fields.len() > 3 {
            Some((fields[2].parse().ok()?, fields[3].parse().ok()?))
        } else {
            None
        }
    })
}

/// Resolves the image's `User` ("uid", "uid:gid", "name" or "name:group").
fn resolve_user(rootfs: &Path, user: &str) -> Result<(u32, u32)> {
    if user.is_empty() {
        return Ok((0, 0));
    }
    let passwd = read_in_root(rootfs, "etc/passwd").unwrap_or_default();
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let (uid, primary_gid) = match user_part.parse::<u32>() {
        Ok(uid) => {
            let gid = passwd
                .lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .find(|f| f.len() > 3 && f[2] == user_part)
                .and_then(|f| f[3].parse().ok())
                .unwrap_or(0);
            (uid, gid)
        }
        Err(_) => lookup_id(&passwd, user_part)
            .ok_or_else(|| format!("user {user_part} not found in /etc/passwd"))?,
    };
    let gid = match group_part {
        None => primary_gid,
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => {
                let group = read_in_root(rootfs, "etc/group").unwrap_or_default();
                group
                    .lines()
                    .map(|l| l.split(':').collect::<Vec<_>>())
                    .find(|f| f.len() > 2 && f[0] == g)
                    .and_then(|f| f[2].parse().ok())
                    .ok_or_else(|| format!("group {g} not found in /etc/group"))?
            }
        },
    };
    Ok((uid, gid))
}

/// Parses sizes such as `512Mi`, `1Gi`, `64M` or `1048576` into bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let units: [(&str, u64); 6] = [
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("K", 1000),
        ("M", 1000 * 1000),
        ("G", 1000 * 1000 * 1000),
    ];
    for (suffix, factor) in units {
        if let Some(n) = s.strip_suffix(suffix) {
            return n
                .parse::<u64>()
                .map(|n| n * factor)
                .map_err(|e| format!("bad size {s}: {e}"));
        }
    }
    s.parse().map_err(|e| format!("bad size {s}: {e}"))
}

pub struct Bind {
    pub source: PathBuf,
    pub destination: String,
    pub read_only: bool,
}

#[derive(Default)]
pub struct Overrides {
    /// CPUs, e.g. 1.0 for `--cpu 1`.
    pub cpu: Option<f64>,
    /// Bytes, e.g. 512Mi for `--memory 512Mi`.
    pub memory: Option<u64>,
    pub pids: Option<i64>,
    /// `KEY=VALUE` entries that replace image entries with the same key.
    pub env: Vec<String>,
    pub binds: Vec<Bind>,
    pub cgroups_path: Option<String>,
    /// Path of an existing network namespace to join, e.g.
    /// `/var/run/netns/<name>`; without it runsc creates an empty one.
    pub netns: Option<String>,
    pub hostname: String,
    /// Replaces the image's `Cmd`; the `Entrypoint` stays.
    pub cmd: Option<Vec<String>>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Generates the OCI runtime spec (`config.json`) for runsc from the image
/// config and the operator's overrides.
pub fn runtime_spec(image_config: &Value, rootfs: &Path, o: &Overrides) -> Result<Value> {
    let cfg = &image_config["config"];
    let mut args = strings(&cfg["Entrypoint"]);
    args.extend(o.cmd.clone().unwrap_or_else(|| strings(&cfg["Cmd"])));
    if args.is_empty() {
        return Err("image has neither Entrypoint nor Cmd".into());
    }

    let mut env: Vec<String> = strings(&cfg["Env"]);
    for entry in &o.env {
        let key = entry.split('=').next().unwrap_or_default();
        env.retain(|e| e.split('=').next() != Some(key));
        env.push(entry.clone());
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    let (uid, gid) = resolve_user(rootfs, cfg["User"].as_str().unwrap_or_default())?;

    let cwd = cfg["WorkingDir"]
        .as_str()
        .filter(|w| !w.is_empty())
        .unwrap_or("/");
    // Like Docker, create a missing working directory.
    resolve(
        rootfs,
        &sanitize(Path::new(cwd))?,
        true,
        &mut HashSet::new(),
    )?;

    // Docker's default capabilities minus CAP_NET_RAW.
    let caps: Vec<&str> = vec![
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE",
    ];
    let caps = if uid == 0 { caps } else { Vec::new() };

    let mut mounts = vec![
        json!({"destination": "/proc", "type": "proc", "source": "proc"}),
        json!({"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
               "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}),
        json!({"destination": "/dev/pts", "type": "devpts", "source": "devpts",
               "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]}),
        json!({"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
               "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"]}),
        json!({"destination": "/sys", "type": "sysfs", "source": "sysfs",
               "options": ["nosuid", "noexec", "nodev", "ro"]}),
    ];
    for bind in &o.binds {
        mounts.push(json!({
            "destination": bind.destination,
            "type": "bind",
            "source": bind.source,
            "options": ["rbind", if bind.read_only { "ro" } else { "rw" }, "nosuid", "nodev"],
        }));
    }

    let mut resources = Map::new();
    if let Some(cpu) = o.cpu {
        let period: u64 = 100_000;
        resources.insert(
            "cpu".into(),
            json!({ "quota": (cpu * period as f64).round() as i64, "period": period }),
        );
    }
    if let Some(memory) = o.memory {
        // swap equal to the limit means no swap on top of it.
        resources.insert("memory".into(), json!({ "limit": memory, "swap": memory }));
    }
    if let Some(pids) = o.pids {
        resources.insert("pids".into(), json!({ "limit": pids }));
    }

    let mut linux = json!({
        "namespaces": [
            {"type": "pid"}, {"type": "network"}, {"type": "ipc"},
            {"type": "uts"}, {"type": "mount"},
        ],
        "resources": resources,
        "maskedPaths": [
            "/proc/acpi", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
            "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
            "/sys/firmware", "/proc/scsi",
        ],
        "readonlyPaths": [
            "/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
            "/proc/sysrq-trigger",
        ],
    });
    if let Some(path) = &o.cgroups_path {
        linux["cgroupsPath"] = json!(path);
    }
    if let Some(path) = &o.netns {
        linux["namespaces"][1]["path"] = json!(path);
    }

    Ok(json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": uid, "gid": gid },
            "args": args,
            "env": env,
            "cwd": cwd,
            "capabilities": {
                "bounding": caps, "effective": caps, "permitted": caps,
            },
            "rlimits": [{ "type": "RLIMIT_NOFILE", "hard": 65536, "soft": 65536 }],
            "noNewPrivileges": true,
        },
        "root": { "path": "rootfs", "readonly": false },
        "hostname": o.hostname,
        "mounts": mounts,
        "linux": linux,
    }))
}

pub struct LayerSource {
    pub dir: PathBuf,
    pub gzip: bool,
}

pub struct ImageSpec {
    pub reference: String,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    pub user: String,
    pub exposed_ports: Vec<String>,
}

fn write_blob(layout: &Path, bytes: &[u8], media_type: &str) -> Result<Descriptor> {
    let digest = format!("sha256:{}", sha256_hex(bytes));
    let path = blob_path(layout, &digest)?;
    fs::write(&path, bytes).ctx(|| format!("write {}", path.display()))?;
    Ok(Descriptor {
        media_type: media_type.into(),
        digest,
        size: bytes.len() as u64,
    })
}

/// Tars a directory tree deterministically: sorted entries, owner 0:0,
/// mtime 0. Files named `.wh.*` are packed as is, which is how whiteouts
/// are represented in layers.
pub fn tar_dir(dir: &Path) -> Result<Vec<u8>> {
    fn walk(base: &Path, rel: &Path, builder: &mut tar::Builder<Vec<u8>>) -> Result<()> {
        let full = base.join(rel);
        let mut names: Vec<OsString> = fs::read_dir(&full)
            .ctx(|| format!("read {}", full.display()))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<io::Result<_>>()
            .ctx(|| format!("read {}", full.display()))?;
        names.sort();
        for name in names {
            let child_rel = rel.join(&name);
            let child = base.join(&child_rel);
            let md = fs::symlink_metadata(&child).ctx(|| format!("lstat {}", child.display()))?;
            let mut header = tar::Header::new_gnu();
            header.set_mode(md.mode() & 0o7777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            let ctx = || format!("tar {}", child.display());
            if md.file_type().is_symlink() {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                let target = fs::read_link(&child).ctx(ctx)?;
                builder
                    .append_link(&mut header, &child_rel, &target)
                    .ctx(ctx)?;
            } else if md.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                builder
                    .append_data(&mut header, &child_rel, io::empty())
                    .ctx(ctx)?;
                walk(base, &child_rel, builder)?;
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(md.len());
                builder
                    .append_data(&mut header, &child_rel, File::open(&child).ctx(ctx)?)
                    .ctx(ctx)?;
            }
        }
        Ok(())
    }
    let mut builder = tar::Builder::new(Vec::new());
    walk(dir, Path::new(""), &mut builder)?;
    builder.into_inner().ctx(|| "finish tar".to_string())
}

/// Writes an OCI image layout with one image and returns its manifest digest.
pub fn pack(out: &Path, layers: &[LayerSource], spec: &ImageSpec) -> Result<String> {
    fs::create_dir_all(out.join("blobs").join("sha256"))
        .ctx(|| format!("create {}", out.display()))?;
    fs::write(out.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)
        .ctx(|| "write oci-layout".to_string())?;
    let mut layer_descs = Vec::new();
    let mut diff_ids = Vec::new();
    for layer in layers {
        let tar = tar_dir(&layer.dir)?;
        diff_ids.push(format!("sha256:{}", sha256_hex(&tar)));
        let desc = if layer.gzip {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(&tar).ctx(|| "gzip".to_string())?;
            write_blob(
                out,
                &gz.finish().ctx(|| "gzip".to_string())?,
                MEDIA_LAYER_GZIP,
            )?
        } else {
            write_blob(out, &tar, MEDIA_LAYER_TAR)?
        };
        layer_descs.push(desc);
    }
    let exposed: Map<String, Value> = spec
        .exposed_ports
        .iter()
        .map(|p| (p.clone(), json!({})))
        .collect();
    let config = json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Entrypoint": spec.entrypoint,
            "Cmd": spec.cmd,
            "Env": spec.env,
            "WorkingDir": spec.workdir,
            "User": spec.user,
            "ExposedPorts": exposed,
        },
        "rootfs": { "type": "layers", "diff_ids": diff_ids },
    });
    let config_desc = write_blob(
        out,
        &serde_json::to_vec(&config).ctx(|| "config".to_string())?,
        MEDIA_CONFIG,
    )?;
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_MANIFEST,
        "config": config_desc.to_json(),
        "layers": layer_descs.iter().map(Descriptor::to_json).collect::<Vec<_>>(),
    });
    let manifest_desc = write_blob(
        out,
        &serde_json::to_vec(&manifest).ctx(|| "manifest".to_string())?,
        MEDIA_MANIFEST,
    )?;
    let mut entry = manifest_desc.to_json();
    entry["annotations"] = json!({ REF_NAME: spec.reference });
    let index = json!({ "schemaVersion": 2, "mediaType": MEDIA_INDEX, "manifests": [entry] });
    fs::write(
        out.join("index.json"),
        serde_json::to_vec_pretty(&index).ctx(|| "index".to_string())?,
    )
    .ctx(|| "write index.json".to_string())?;
    Ok(manifest_desc.digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh rootfs directory under the system temp dir.
    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spike-c-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    enum E<'a> {
        Dir(&'a str),
        File(&'a str, &'a str),
        Link(&'a str, &'a str),
        Hard(&'a str, &'a str),
        /// A regular file whose raw header name is written verbatim.
        Raw(&'a str),
    }

    fn layer(entries: &[E]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for e in entries {
            let mut h = tar::Header::new_gnu();
            h.set_mode(0o755);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(0);
            match e {
                E::Dir(p) => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_size(0);
                    b.append_data(&mut h, p, io::empty()).unwrap();
                }
                E::File(p, content) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(content.len() as u64);
                    b.append_data(&mut h, p, content.as_bytes()).unwrap();
                }
                E::Link(p, target) => {
                    h.set_entry_type(tar::EntryType::Symlink);
                    h.set_size(0);
                    b.append_link(&mut h, p, target).unwrap();
                }
                E::Hard(p, target) => {
                    h.set_entry_type(tar::EntryType::Link);
                    h.set_size(0);
                    b.append_link(&mut h, p, target).unwrap();
                }
                E::Raw(name) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(0);
                    h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
                    h.set_cksum();
                    b.append(&h, io::empty()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn apply(root: &Path, entries: &[E]) -> Result<()> {
        apply_layer(root, layer(entries).as_slice(), &mut UnpackStats::default())
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn whiteout_hides_lower_layer_entries_only() {
        let root = temp_root("whiteout");
        apply(
            &root,
            &[
                E::Dir("etc/"),
                E::File("etc/stale", "x"),
                E::Dir("etc/d/"),
                E::File("etc/d/f", "y"),
            ],
        )
        .unwrap();
        apply(
            &root,
            &[
                E::File("etc/new", "n"),
                E::File("etc/.wh.new", ""),
                E::File("etc/.wh.stale", ""),
                E::File("etc/.wh.d", ""),
            ],
        )
        .unwrap();
        assert_eq!(listing(&root.join("etc")), ["new"]);
    }

    #[test]
    fn opaque_dir_hides_lower_children_but_keeps_its_own_layer() {
        let root = temp_root("opaque");
        apply(
            &root,
            &[
                E::Dir("srv/old/"),
                E::File("srv/old/a", "a"),
                E::Dir("srv/old/sub/"),
                E::File("srv/old/sub/b", "b"),
            ],
        )
        .unwrap();
        // The new entry comes before the marker in the stream on purpose.
        apply(
            &root,
            &[
                E::File("srv/old/c", "c"),
                E::File("srv/old/.wh..wh..opq", ""),
            ],
        )
        .unwrap();
        assert_eq!(listing(&root.join("srv/old")), ["c"]);
    }

    #[test]
    fn absolute_symlinks_resolve_inside_the_rootfs() {
        let root = temp_root("abslink");
        apply(
            &root,
            &[E::Dir("srv/"), E::Dir("opt/"), E::Link("opt/link", "/srv")],
        )
        .unwrap();
        // No directory entry for opt/link: the parent is the symlink.
        apply(&root, &[E::File("opt/link/via-link.txt", "v")]).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("srv/via-link.txt")).unwrap(),
            "v"
        );
        assert!(
            fs::symlink_metadata(root.join("opt/link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn hostile_symlinks_cannot_write_outside_the_rootfs() {
        let root = temp_root("hostile");
        let marker = format!("spike-c-escape-{}", std::process::id());
        let host_tmp = std::env::temp_dir();
        apply(
            &root,
            &[
                E::Link("evil", host_tmp.to_str().unwrap()),
                E::Link("up", "../../../../../.."),
            ],
        )
        .unwrap();
        apply(
            &root,
            &[
                E::File(&format!("evil/{marker}"), "pwned"),
                E::File(&format!("up/{marker}-2"), "pwned"),
            ],
        )
        .unwrap();
        assert!(!host_tmp.join(&marker).exists());
        assert!(!Path::new("/").join(format!("{marker}-2")).exists());
        assert!(
            root.join(host_tmp.strip_prefix("/").unwrap())
                .join(&marker)
                .exists()
        );
        assert!(root.join(format!("{marker}-2")).exists());
    }

    #[test]
    fn parent_dir_entries_are_rejected() {
        let root = temp_root("dotdot");
        let err = apply(&root, &[E::Raw("../escape.txt")]).unwrap_err();
        assert!(err.contains("escapes the rootfs"), "{err}");
    }

    #[test]
    fn symlink_loops_are_rejected() {
        let root = temp_root("loop");
        apply(&root, &[E::Link("a", "b"), E::Link("b", "a")]).unwrap();
        let err = apply(&root, &[E::File("a/x", "x")]).unwrap_err();
        assert!(err.contains("too many symlinks"), "{err}");
    }

    #[test]
    fn entries_replace_entries_of_another_type() {
        let root = temp_root("replace");
        apply(
            &root,
            &[E::Dir("x/"), E::File("x/inner", "i"), E::File("y", "file")],
        )
        .unwrap();
        apply(&root, &[E::File("x", "now a file"), E::Dir("y/")]).unwrap();
        assert_eq!(fs::read_to_string(root.join("x")).unwrap(), "now a file");
        assert!(root.join("y").is_dir());
    }

    #[test]
    fn hard_links_point_inside_the_rootfs() {
        let root = temp_root("hardlink");
        apply(
            &root,
            &[
                E::Dir("bin/"),
                E::File("bin/busybox", "bb"),
                E::Hard("bin/sh", "bin/busybox"),
            ],
        )
        .unwrap();
        let a = fs::metadata(root.join("bin/busybox")).unwrap();
        let b = fs::metadata(root.join("bin/sh")).unwrap();
        assert_eq!(a.ino(), b.ino());
    }

    #[test]
    fn user_names_resolve_through_the_image_passwd() {
        let root = temp_root("user");
        apply(
            &root,
            &[
                E::Dir("etc/"),
                E::File(
                    "etc/passwd",
                    "root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\n",
                ),
                E::File("etc/group", "root:x:0:\nnogroup:x:65534:\nstaff:x:50:\n"),
            ],
        )
        .unwrap();
        assert_eq!(resolve_user(&root, "nobody").unwrap(), (65534, 65534));
        assert_eq!(resolve_user(&root, "65534:50").unwrap(), (65534, 50));
        assert_eq!(resolve_user(&root, "nobody:staff").unwrap(), (65534, 50));
        assert_eq!(resolve_user(&root, "1000").unwrap(), (1000, 0));
        assert!(resolve_user(&root, "ghost").is_err());
    }
}
