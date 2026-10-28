//! OCI images from the blob store to a runtime bundle (m7-foreign §4, ADR
//! 0003 §4): opening and verifying an image, unpacking its layers into a
//! rootfs, generating the runtime spec (`config.json`) for runsc or runc,
//! and packing deterministic test images.
//!
//! Unpacking follows the OCI image spec (layer.md): layers are applied in
//! order, `.wh.<name>` removes `<name>` from lower layers, `.wh..wh..opq`
//! hides every lower-layer entry of its directory, and entries of one layer
//! are never hidden by whiteouts in the same layer, whatever their order in
//! the stream. Paths are resolved as if the rootfs were `/`: symlinks
//! (including absolute ones) never lead outside it, and entries containing
//! `..` are rejected. Setuid and setgid bits are cleared. Lifted from spike
//! C's `oci-tool` and hardened.

use std::collections::{HashSet, VecDeque};
use std::error::Error as _;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown, lchown, symlink};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::blobs::{BlobStore, Descriptor, HashingReader, io_error, sha256_digest};
use crate::image::{ImageError, validate_digest};

/// OCI image index.
pub const MEDIA_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// OCI image manifest.
pub const MEDIA_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// OCI image config.
pub const MEDIA_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
/// OCI uncompressed layer.
pub const MEDIA_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
/// OCI gzip layer.
pub const MEDIA_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// OCI zstd layer.
pub const MEDIA_LAYER_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
/// Docker manifest list (multi-platform).
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker image manifest, schema 2.
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker image config.
pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const DOCKER_LAYER_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const DOCKER_LAYER_TAR: &str = "application/vnd.docker.image.rootfs.diff.tar";
const DOCKER_FOREIGN_GZIP: &str = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";
const OCI_NONDIST_TAR: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar";
const OCI_NONDIST_GZIP: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";
const OCI_NONDIST_ZSTD: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";
/// The annotation holding an image's name in a layout's `index.json`.
pub const REF_NAME: &str = "org.opencontainers.image.ref.name";
const OPAQUE: &str = ".wh..wh..opq";
const META_PREFIX: &str = ".wh..wh.";
const WHITEOUT_PREFIX: &str = ".wh.";

/// The largest index, manifest or image config Kronik reads.
pub const MAX_JSON_BYTES: u64 = 8 << 20;
/// How deep indexes may nest before a manifest must appear.
const MAX_INDEX_DEPTH: usize = 4;
/// The largest `/etc/passwd` or `/etc/group` read for user resolution.
const MAX_ID_DB_BYTES: u64 = 4 << 20;

fn invalid(msg: impl Into<String>) -> ImageError {
    ImageError::Invalid(msg.into())
}

/// An io::Error with its source chain (tar puts the cause in the source).
fn chain(e: &io::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        let s_text = s.to_string();
        if !out.ends_with(&s_text) {
            out.push_str(": ");
            out.push_str(&s_text);
        }
        source = s.source();
    }
    out
}

/// The OCI name of the host architecture (`amd64`, `arm64`).
pub fn host_arch() -> Result<&'static str, ImageError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        other => Err(invalid(format!(
            "foreign actors are not supported on {other}"
        ))),
    }
}

/// How a layer blob is compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Codec {
    Tar,
    Gzip,
    Zstd,
}

/// The codec of a supported layer media type. Nondistributable (foreign)
/// layers are treated like their distributable twins; Kronik fetches them
/// from the registry by digest like any other layer, never from their URLs.
pub(crate) fn layer_codec(media_type: &str) -> Result<Codec, ImageError> {
    match media_type {
        MEDIA_LAYER_TAR | DOCKER_LAYER_TAR | OCI_NONDIST_TAR => Ok(Codec::Tar),
        MEDIA_LAYER_GZIP | DOCKER_LAYER_GZIP | OCI_NONDIST_GZIP | DOCKER_FOREIGN_GZIP => {
            Ok(Codec::Gzip)
        }
        MEDIA_LAYER_ZSTD | OCI_NONDIST_ZSTD => Ok(Codec::Zstd),
        other => Err(invalid(format!("unsupported layer media type {other:?}"))),
    }
}

/// An index or manifest blob, parsed far enough to follow it.
pub(crate) enum Parsed {
    /// The `manifests` entries of an index.
    Index(Vec<Value>),
    /// An image manifest: its config and layers, media types checked.
    Manifest {
        config: Descriptor,
        layers: Vec<Descriptor>,
    },
}

/// Parses an index or image manifest (OCI or Docker schema 2). The media
/// type comes from the document itself (OCI makes it optional, so the
/// structure decides when it is missing).
pub(crate) fn parse_manifest(bytes: &[u8], digest: &str) -> Result<Parsed, ImageError> {
    let v = parse_json(bytes, &format!("manifest {digest}"))?;
    if v["schemaVersion"] != 2 {
        return Err(invalid(format!(
            "manifest {digest} has schemaVersion {}, expected 2",
            v["schemaVersion"]
        )));
    }
    let media_type = v["mediaType"].as_str().unwrap_or_default();
    let is_index = match media_type {
        MEDIA_INDEX | DOCKER_LIST => true,
        MEDIA_MANIFEST | DOCKER_MANIFEST => false,
        "" if v["manifests"].is_array() => true,
        "" if v["config"].is_object() => false,
        other => {
            return Err(invalid(format!(
                "{digest} is not an image (media type {other:?})"
            )));
        }
    };
    if is_index {
        let entries = v["manifests"]
            .as_array()
            .ok_or_else(|| invalid(format!("index {digest} without manifests")))?;
        return Ok(Parsed::Index(entries.clone()));
    }
    let config = Descriptor::from_json(&v["config"])?;
    if config.media_type != MEDIA_CONFIG && config.media_type != DOCKER_CONFIG {
        return Err(invalid(format!(
            "{digest} is not a container image (config media type {:?})",
            config.media_type
        )));
    }
    let layers = v["layers"]
        .as_array()
        .ok_or_else(|| invalid(format!("manifest {digest} without layers")))?
        .iter()
        .map(|l| {
            let d = Descriptor::from_json(l)?;
            layer_codec(&d.media_type)?;
            Ok(d)
        })
        .collect::<Result<Vec<_>, ImageError>>()?;
    Ok(Parsed::Manifest { config, layers })
}

/// Picks the entry for `linux` and the host architecture from an index.
pub(crate) fn select_platform(entries: &[Value], digest: &str) -> Result<Descriptor, ImageError> {
    let arch = host_arch()?;
    let entry = entries
        .iter()
        .find(|m| m["platform"]["os"] == "linux" && m["platform"]["architecture"] == arch)
        .ok_or_else(|| invalid(format!("index {digest} has no image for linux/{arch}")))?;
    Descriptor::from_json(entry)
}

fn parse_json(bytes: &[u8], what: &str) -> Result<Value, ImageError> {
    serde_json::from_slice(bytes).map_err(|e| invalid(format!("parse {what}: {e}")))
}

/// An image opened from the blob store: its platform manifest, verified
/// config and layer list.
#[derive(Clone, Debug)]
pub struct Image {
    /// Digest of the platform manifest (not of an index above it).
    pub manifest_digest: String,
    /// Digest of the image config.
    pub config_digest: String,
    /// The image config document.
    pub config: Value,
    /// Layer descriptors, lowest first.
    pub layers: Vec<Descriptor>,
    /// Uncompressed digests of the layers (`rootfs.diff_ids`).
    pub diff_ids: Vec<String>,
    /// The digests read to reach the platform manifest: the one opened,
    /// any indexes, the manifest itself.
    pub chain: Vec<String>,
}

impl Image {
    /// Every blob of the image: the chain to its manifest, its config and
    /// its layers (what the blob store must keep for it).
    pub fn blobs(&self) -> impl Iterator<Item = &str> {
        self.chain
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(self.config_digest.as_str()))
            .chain(self.layers.iter().map(|l| l.digest.as_str()))
    }
}

/// Parses an image config and checks that it is for `linux` and the host
/// architecture.
pub(crate) fn parse_config(bytes: &[u8]) -> Result<Value, ImageError> {
    let config = parse_json(bytes, "image config")?;
    let arch = host_arch()?;
    if config["os"] != "linux" || config["architecture"] != arch {
        return Err(invalid(format!(
            "image is {}/{}, not linux/{arch}",
            config["os"], config["architecture"]
        )));
    }
    Ok(config)
}

impl Image {
    /// Opens the image with `manifest_digest` (a manifest, or an index that
    /// is followed to its linux entry for the host architecture). Every blob
    /// read is verified against its digest; the config must be for
    /// `linux` and the host architecture.
    pub fn open(store: &BlobStore, manifest_digest: &str) -> Result<Image, ImageError> {
        let mut digest = manifest_digest.to_string();
        let mut chain = vec![digest.clone()];
        let mut bytes = store.read_digest(&digest, MAX_JSON_BYTES)?;
        let mut depth = 0;
        let (config_desc, layers) = loop {
            match parse_manifest(&bytes, &digest)? {
                Parsed::Manifest { config, layers } => break (config, layers),
                Parsed::Index(entries) => {
                    depth += 1;
                    if depth > MAX_INDEX_DEPTH {
                        return Err(invalid(format!("indexes nest too deeply at {digest}")));
                    }
                    let desc = select_platform(&entries, &digest)?;
                    bytes = store.read_small(&desc, MAX_JSON_BYTES)?;
                    digest = desc.digest;
                    chain.push(digest.clone());
                }
            }
        };
        let config = parse_config(&store.read_small(&config_desc, MAX_JSON_BYTES)?)?;
        let diff_ids = config["rootfs"]["diff_ids"]
            .as_array()
            .ok_or_else(|| invalid("image config without rootfs.diff_ids"))?
            .iter()
            .map(|d| {
                let d = d.as_str().unwrap_or_default();
                validate_digest(d)?;
                Ok(d.to_string())
            })
            .collect::<Result<Vec<_>, ImageError>>()?;
        if diff_ids.len() != layers.len() {
            return Err(invalid(format!(
                "{} layers but {} diff_ids",
                layers.len(),
                diff_ids.len()
            )));
        }
        Ok(Image {
            manifest_digest: digest,
            config_digest: config_desc.digest,
            config,
            layers,
            diff_ids,
            chain,
        })
    }
}

/// Limits and options of [`unpack`].
#[derive(Clone, Debug)]
pub struct UnpackLimits {
    /// Uncompressed bytes over all layers (default 8 GiB).
    pub max_bytes: u64,
    /// Tar entries over all layers (default 1 000 000).
    pub max_entries: u64,
    /// Apply owners from the tar headers (needs root; true in production).
    pub preserve_owners: bool,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 << 30,
            max_entries: 1_000_000,
            preserve_owners: true,
        }
    }
}

/// What [`unpack`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnpackStats {
    /// Layers applied.
    pub layers: u64,
    /// Tar entries read (including whiteouts and skipped ones).
    pub entries: u64,
    /// Uncompressed layer bytes read.
    pub bytes: u64,
    /// `.wh.<name>` entries.
    pub whiteouts: u64,
    /// `.wh..wh..opq` entries.
    pub opaque_dirs: u64,
    /// Device nodes, FIFOs, `.wh..wh.*` meta entries and pax global
    /// headers, which are not created.
    pub skipped: u64,
    /// Directories and files whose setuid or setgid bit was cleared.
    pub setid_cleared: u64,
}

/// Counts bytes through the decoder and fails once the budget is spent.
struct Budget<R> {
    inner: R,
    remaining: u64,
    exceeded: bool,
}

impl<R: Read> Read for Budget<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("the image exceeds the unpack byte limit"));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Decodes all zstd frames of a stream (skippable frames are skipped).
/// `ruzstd::decoding::StreamingDecoder` stops after the first frame.
struct ZstdFrames<R> {
    source: R,
    decoder: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> ZstdFrames<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            decoder: ruzstd::decoding::FrameDecoder::new(),
            in_frame: false,
        }
    }
}

impl<R: BufRead> Read for ZstdFrames<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::errors::{FrameDecoderError, ReadFrameHeaderError};
        loop {
            if !self.in_frame {
                if self.source.fill_buf()?.is_empty() {
                    return Ok(0);
                }
                match self.decoder.reset(&mut self.source) {
                    Ok(()) => self.in_frame = true,
                    Err(FrameDecoderError::ReadFrameHeaderError(
                        ReadFrameHeaderError::SkipFrame { length, .. },
                    )) => {
                        let skipped =
                            io::copy(&mut (&mut self.source).take(length.into()), &mut io::sink())?;
                        if skipped != u64::from(length) {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated zstd skippable frame",
                            ));
                        }
                        continue;
                    }
                    Err(e) => return Err(io::Error::other(e)),
                }
            }
            while self.decoder.can_collect() == 0 && !self.decoder.is_finished() {
                self.decoder
                    .decode_blocks(
                        &mut self.source,
                        ruzstd::decoding::BlockDecodingStrategy::UptoBlocks(1),
                    )
                    .map_err(io::Error::other)?;
            }
            let n = self.decoder.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.decoder.is_finished() && self.decoder.can_collect() == 0 {
                self.in_frame = false;
            }
        }
    }
}

/// Unpacks all layers of `image` into `rootfs`, which must not exist yet.
/// Each layer blob is verified against its digest and size before anything
/// from it is applied, and its uncompressed digest against the config's
/// `diff_id` after it was applied.
pub fn unpack(
    store: &BlobStore,
    image: &Image,
    rootfs: &Path,
    limits: &UnpackLimits,
) -> Result<UnpackStats, ImageError> {
    fs::create_dir(rootfs).map_err(|e| io_error(format!("create {}", rootfs.display()), e))?;
    fs::set_permissions(rootfs, Permissions::from_mode(0o755))
        .map_err(|e| io_error(format!("chmod {}", rootfs.display()), e))?;
    let mut stats = UnpackStats::default();
    for (i, (layer, diff_id)) in image.layers.iter().zip(&image.diff_ids).enumerate() {
        let what = || format!("layer {i} ({})", layer.digest);
        let codec = layer_codec(&layer.media_type)?;
        store.verify(layer)?;
        let file = BufReader::new(store.open(layer)?);
        let decoded: Box<dyn Read> = match codec {
            Codec::Tar => Box::new(file),
            Codec::Gzip => Box::new(flate2::read::MultiGzDecoder::new(file)),
            Codec::Zstd => Box::new(ZstdFrames::new(file)),
        };
        let mut reader = Budget {
            inner: HashingReader::new(decoded),
            remaining: limits.max_bytes - stats.bytes.min(limits.max_bytes),
            exceeded: false,
        };
        let mut result = apply_layer(rootfs, &mut reader, &mut stats, limits);
        if result.is_ok() {
            // Trailing padding after the end-of-archive marker is part of
            // the diff_id.
            result = io::copy(&mut reader, &mut io::sink())
                .map(|_| ())
                .map_err(|e| invalid(format!("read layer: {}", chain(&e))));
        }
        stats.bytes += reader.inner.count();
        if reader.exceeded {
            return Err(invalid(format!(
                "{}: the image unpacks to more than {} bytes",
                what(),
                limits.max_bytes
            )));
        }
        result.map_err(|e| match e {
            ImageError::Invalid(m) => invalid(format!("{}: {m}", what())),
            ImageError::Io(m) => ImageError::Io(format!("{}: {m}", what())),
            ImageError::NoSpace(m) => ImageError::NoSpace(format!("{}: {m}", what())),
            ImageError::TimedOut(m) => ImageError::TimedOut(format!("{}: {m}", what())),
        })?;
        let actual = reader.inner.digest();
        if &actual != diff_id {
            return Err(invalid(format!(
                "{}: uncompressed digest {actual} does not match diff_id {diff_id}",
                what()
            )));
        }
        stats.layers += 1;
    }
    Ok(stats)
}

/// Normalizes a tar entry path to a relative path. Rejects `..`.
fn sanitize(path: &Path) -> Result<PathBuf, ImageError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid(format!(
                    "entry {} escapes the rootfs",
                    path.display()
                )));
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
) -> Result<PathBuf, ImageError> {
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
                    return Err(invalid(format!(
                        "too many symlinks resolving {}",
                        rel.display()
                    )));
                }
                let target = fs::read_link(&full)
                    .map_err(|e| io_error(format!("readlink {}", full.display()), e))?;
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
            Ok(_) => {
                return Err(invalid(format!(
                    "{} is not a directory",
                    candidate.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                fs::create_dir(&full)
                    .map_err(|e| io_error(format!("mkdir {}", full.display()), e))?;
                fs::set_permissions(&full, Permissions::from_mode(0o755))
                    .map_err(|e| io_error(format!("chmod {}", full.display()), e))?;
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
            Err(e) => return Err(io_error(format!("lstat {}", full.display()), e)),
        }
    }
    Ok(resolved)
}

/// Removes a file, symlink or directory tree without following symlinks.
fn remove_any(path: &Path) -> Result<(), ImageError> {
    let result = match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    result.map_err(|e| io_error(format!("remove {}", path.display()), e))
}

/// Copies an entry's content into `file`, telling layer read errors
/// (invalid image) from write errors (local disk).
fn copy_entry(entry: &mut impl Read, file: &mut File, what: &str) -> Result<(), ImageError> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match entry.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(invalid(format!("read {what}: {}", chain(&e)))),
        };
        file.write_all(&buf[..n])
            .map_err(|e| io_error(format!("write {what}"), e))?;
    }
}

/// Applies one uncompressed layer tarball to `root`.
fn apply_layer(
    root: &Path,
    reader: impl Read,
    stats: &mut UnpackStats,
    limits: &UnpackLimits,
) -> Result<(), ImageError> {
    let tar_err = |e: io::Error| invalid(format!("read tar: {}", chain(&e)));
    let mut archive = tar::Archive::new(reader);
    // Entries created by this layer, as resolved paths relative to root.
    // Whiteouts only hide entries from lower layers.
    let mut created: HashSet<PathBuf> = HashSet::new();
    for entry in archive.entries().map_err(tar_err)? {
        let mut entry = entry.map_err(tar_err)?;
        stats.entries += 1;
        if stats.entries > limits.max_entries {
            return Err(invalid(format!(
                "the image has more than {} entries",
                limits.max_entries
            )));
        }
        let entry_type = entry.header().entry_type();
        if entry_type == tar::EntryType::XGlobalHeader {
            stats.skipped += 1;
            continue;
        }
        let raw = entry.path().map_err(tar_err)?.into_owned();
        let rel = sanitize(&raw)?;
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
                        let child = child.map_err(|e| io_error("read dir", e))?;
                        let child_rel = dir.join(child.file_name());
                        if !created.contains(&child_rel) {
                            remove_any(&root.join(&child_rel))?;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(format!("read {}", dir.display()), e)),
            }
            stats.opaque_dirs += 1;
            continue;
        }
        if name_str.starts_with(META_PREFIX) {
            // Other AUFS meta entries (`.wh..wh.plnk`, `.wh..wh.aufs`).
            stats.skipped += 1;
            continue;
        }
        if let Some(hidden) = name_str.strip_prefix(WHITEOUT_PREFIX) {
            if hidden.is_empty() || hidden == "." || hidden == ".." {
                return Err(invalid(format!(
                    "whiteout {} hides no valid name",
                    raw.display()
                )));
            }
            let dir = resolve(root, &parent_rel, false, &mut created)?;
            let target = dir.join(hidden);
            if !created.contains(&target) {
                remove_any(&root.join(&target))?;
            }
            stats.whiteouts += 1;
            continue;
        }

        let header = entry.header();
        // Setuid and setgid are never set, the sticky bit is: a foreign actor
        // needs neither, and no setid file comes from an image (ADR 0027).
        let header_mode = header.mode().map_err(tar_err)?;
        let mode = header_mode & 0o1777;
        let setid = u64::from(header_mode & 0o6000 != 0);
        let uid = u32::try_from(header.uid().map_err(tar_err)?)
            .map_err(|_| invalid(format!("{}: uid out of range", raw.display())))?;
        let gid = u32::try_from(header.gid().map_err(tar_err)?)
            .map_err(|_| invalid(format!("{}: gid out of range", raw.display())))?;
        match entry_type {
            tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
                // The runtime provides /dev; device nodes and FIFOs are not
                // created.
                stats.skipped += 1;
                continue;
            }
            tar::EntryType::Directory
            | tar::EntryType::Regular
            | tar::EntryType::Continuous
            | tar::EntryType::GNUSparse
            | tar::EntryType::Symlink
            | tar::EntryType::Link => {}
            other => {
                return Err(invalid(format!(
                    "{}: unsupported tar entry type {other:?}",
                    raw.display()
                )));
            }
        }

        let dir = resolve(root, &parent_rel, true, &mut created)?;
        let dest_rel = dir.join(&name);
        let dest = root.join(&dest_rel);
        let what = dest_rel.display().to_string();
        let io_ctx = |e: io::Error| io_error(&what, e);
        let owners = limits.preserve_owners.then_some((uid, gid));
        match entry_type {
            tar::EntryType::Directory => {
                match fs::symlink_metadata(&dest) {
                    Ok(md) if md.is_dir() => {}
                    Ok(_) => {
                        remove_any(&dest)?;
                        fs::create_dir(&dest).map_err(io_ctx)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&dest).map_err(io_ctx)?
                    }
                    Err(e) => return Err(io_ctx(e)),
                }
                // O_NOFOLLOW|O_DIRECTORY: owner and mode are set on this
                // directory through its descriptor, never through a symlink.
                let handle = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                    .open(&dest)
                    .map_err(io_ctx)?;
                if let Some((uid, gid)) = owners {
                    fchown(&handle, Some(uid), Some(gid)).map_err(io_ctx)?;
                }
                handle
                    .set_permissions(Permissions::from_mode(mode))
                    .map_err(io_ctx)?;
                stats.setid_cleared += setid;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse => {
                remove_any(&dest)?;
                // create_new is O_CREAT|O_EXCL: it never follows a symlink.
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&dest)
                    .map_err(io_ctx)?;
                copy_entry(&mut entry, &mut file, &what)?;
                if let Some((uid, gid)) = owners {
                    fchown(&file, Some(uid), Some(gid)).map_err(io_ctx)?;
                }
                file.set_permissions(Permissions::from_mode(mode))
                    .map_err(io_ctx)?;
                stats.setid_cleared += setid;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(tar_err)?
                    .ok_or_else(|| invalid(format!("{what}: symlink without target")))?
                    .into_owned();
                remove_any(&dest)?;
                symlink(&target, &dest).map_err(io_ctx)?;
                if let Some((uid, gid)) = owners {
                    lchown(&dest, Some(uid), Some(gid)).map_err(io_ctx)?;
                }
            }
            tar::EntryType::Link => {
                let target_raw = entry
                    .link_name()
                    .map_err(tar_err)?
                    .ok_or_else(|| invalid(format!("{what}: hard link without target")))?
                    .into_owned();
                let target_rel = sanitize(&target_raw)?;
                let target_name = target_rel
                    .file_name()
                    .ok_or_else(|| invalid(format!("{what}: bad hard link target")))?;
                let target_dir = resolve(
                    root,
                    target_rel.parent().unwrap_or(Path::new("")),
                    false,
                    &mut created,
                )?;
                let target = root.join(target_dir.join(target_name));
                match fs::symlink_metadata(&target) {
                    Ok(md) if md.is_dir() => {
                        return Err(invalid(format!(
                            "{what}: hard link to the directory {}",
                            target_raw.display()
                        )));
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Err(invalid(format!(
                            "{what}: hard link to the missing {}",
                            target_raw.display()
                        )));
                    }
                    Err(e) => return Err(io_ctx(e)),
                }
                if target == dest {
                    continue;
                }
                remove_any(&dest)?;
                // linkat(2) without AT_SYMLINK_FOLLOW: links the entry itself.
                fs::hard_link(&target, &dest).map_err(io_ctx)?;
            }
            _ => {}
        }
        created.insert(dest_rel);
    }
    Ok(())
}

/// Reads a regular file inside the rootfs, resolving symlinks within it.
fn read_in_root(rootfs: &Path, rel: &str) -> Option<String> {
    let path = resolve(rootfs, Path::new(rel), false, &mut HashSet::new()).ok()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(rootfs.join(path))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_ID_DB_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
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

/// Resolves the image's `User` ("uid", "uid:gid", "name" or "name:group")
/// through the image's own `/etc/passwd` and `/etc/group`.
fn resolve_user(rootfs: &Path, user: &str) -> Result<(u32, u32), ImageError> {
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
            .ok_or_else(|| invalid(format!("image user {user_part} not found in /etc/passwd")))?,
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
                    .ok_or_else(|| invalid(format!("image group {g} not found in /etc/group")))?
            }
        },
    };
    Ok((uid, gid))
}

/// A bind mount into the sandbox.
#[derive(Clone, Debug)]
pub struct Bind {
    /// Host path.
    pub source: PathBuf,
    /// Absolute path inside the sandbox.
    pub destination: String,
    /// Mount read-only.
    pub read_only: bool,
}

/// What the record and the daemon add to the image config.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// CPU quota in thousandths of a CPU over a 100 ms period; 0 means no
    /// quota.
    pub cpu_millis: u32,
    /// Memory limit in bytes (no swap on top); 0 means no limit.
    pub memory_bytes: u64,
    /// Process limit; 0 or less means no limit.
    pub pids: i64,
    /// Variables that replace image variables with the same name.
    pub env: Vec<(String, String)>,
    /// Extra bind mounts (the data directory).
    pub binds: Vec<Bind>,
    /// `linux.cgroupsPath`.
    pub cgroups_path: Option<String>,
    /// Path of an existing network namespace to join (`<run>/netns/<name>`);
    /// without it the runtime creates an empty one.
    pub netns: Option<PathBuf>,
    /// The sandbox's hostname (the actor name).
    pub hostname: String,
    /// A seccomp filter for the host kernel (`trusted`, plain runc): the
    /// syscalls Docker's default profile also refuses that let a process
    /// reach past its container (namespaces, mounts, keyrings, BPF, kernel
    /// modules, tracing). gVisor has its own kernel and needs none.
    pub syscall_filter: bool,
}

/// Syscalls refused under `trusted` (EPERM).
const DENIED_SYSCALLS: &[&str] = &[
    "unshare",
    "setns",
    "mount",
    "umount2",
    "pivot_root",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "keyctl",
    "add_key",
    "request_key",
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "open_by_handle_at",
    "name_to_handle_at",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "syslog",
    "swapon",
    "swapoff",
    "reboot",
    "acct",
    "quotactl",
    "lookup_dcookie",
    // Docker 25+ refuses io_uring: a large, often exploited kernel surface.
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// `clone` flags that create namespaces (refused, like `unshare`).
const NAMESPACE_FLAGS: [u64; 7] = [
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

/// The OCI `linux.seccomp` of `trusted`: everything allowed but
/// [`DENIED_SYSCALLS`] and namespace flags of `clone`; `clone3`, whose flags
/// a filter cannot see, answers ENOSYS so libc falls back to `clone`.
fn syscall_filter() -> Value {
    let mut syscalls = vec![
        json!({"names": DENIED_SYSCALLS, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}),
        json!({"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}),
    ];
    for flag in NAMESPACE_FLAGS {
        syscalls.push(json!({
            "names": ["clone"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "args": [{"index": 0, "value": flag, "valueTwo": flag, "op": "SCMP_CMP_MASKED_EQ"}],
        }));
    }
    json!({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": syscalls})
}

/// A generated runtime spec and the user the program runs as.
#[derive(Clone, Debug)]
pub struct RuntimeSpec {
    /// The `config.json` document.
    pub json: Value,
    /// The resolved uid of the image user.
    pub uid: u32,
    /// The resolved gid of the image user.
    pub gid: u32,
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

fn utf8_path<'a>(path: &'a Path, what: &str) -> Result<&'a str, ImageError> {
    path.to_str()
        .ok_or_else(|| invalid(format!("{what} {} is not UTF-8", path.display())))
}

/// Docker's default capabilities minus `CAP_NET_RAW`.
const ROOT_CAPS: [&str; 13] = [
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

/// Generates the OCI runtime spec (`config.json`) for runsc and runc from
/// the image config and the overrides. Resolves the image user inside
/// `rootfs` and creates a missing working directory there, like Docker.
pub fn runtime_spec(
    image: &Image,
    rootfs: &Path,
    o: &Overrides,
) -> Result<RuntimeSpec, ImageError> {
    let cfg = &image.config["config"];
    let mut args = strings(&cfg["Entrypoint"]);
    args.extend(strings(&cfg["Cmd"]));
    if args.is_empty() {
        return Err(invalid("the image has neither Entrypoint nor Cmd"));
    }

    let mut env: Vec<String> = strings(&cfg["Env"]);
    for (key, value) in &o.env {
        env.retain(|e| e.split('=').next() != Some(key.as_str()));
        env.push(format!("{key}={value}"));
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    let (uid, gid) = resolve_user(rootfs, cfg["User"].as_str().unwrap_or_default())?;

    let workdir = sanitize(Path::new(cfg["WorkingDir"].as_str().unwrap_or_default()))?;
    resolve(rootfs, &workdir, true, &mut HashSet::new())?;
    let cwd = format!("/{}", utf8_path(&workdir, "working directory")?);

    let caps: Vec<&str> = if uid == 0 {
        ROOT_CAPS.to_vec()
    } else {
        Vec::new()
    };

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
            "source": utf8_path(&bind.source, "bind source")?,
            "options": ["rbind", if bind.read_only { "ro" } else { "rw" }, "nosuid", "nodev"],
        }));
    }

    let mut resources = Map::new();
    if o.cpu_millis > 0 {
        resources.insert(
            "cpu".into(),
            json!({ "quota": i64::from(o.cpu_millis) * 100, "period": 100_000u64 }),
        );
    }
    if o.memory_bytes > 0 {
        // swap equal to the limit means no swap on top of it.
        resources.insert(
            "memory".into(),
            json!({ "limit": o.memory_bytes, "swap": o.memory_bytes }),
        );
    }
    if o.pids > 0 {
        resources.insert("pids".into(), json!({ "limit": o.pids }));
    }

    let mut network = json!({"type": "network"});
    if let Some(path) = &o.netns {
        network["path"] = json!(utf8_path(path, "network namespace")?);
    }
    let mut linux = json!({
        "namespaces": [
            {"type": "pid"}, network, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
        ],
        "resources": resources,
        // Docker's masks, with the RAPL energy counters (a side channel)
        // and the interrupt counts.
        "maskedPaths": [
            "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
            "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
            "/sys/firmware", "/proc/scsi", "/proc/interrupts", "/sys/devices/virtual/powercap",
        ],
        "readonlyPaths": [
            "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
        ],
    });
    if let Some(path) = &o.cgroups_path {
        linux["cgroupsPath"] = json!(path);
    }
    if o.syscall_filter {
        linux["seccomp"] = syscall_filter();
    }

    let json = json!({
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
        "root": { "path": utf8_path(rootfs, "rootfs")?, "readonly": false },
        "hostname": o.hostname,
        "mounts": mounts,
        "linux": linux,
    });
    Ok(RuntimeSpec { json, uid, gid })
}

/// One layer of a packed image: a directory tree, gzip-compressed or not.
#[derive(Clone, Debug)]
pub struct LayerSource {
    /// The directory whose contents become the layer.
    pub dir: PathBuf,
    /// Compress the layer with gzip.
    pub gzip: bool,
}

/// The image config of a packed image.
#[derive(Clone, Debug, Default)]
pub struct ImageSpec {
    /// The `org.opencontainers.image.ref.name` annotation in `index.json`.
    pub reference: String,
    /// `Entrypoint`.
    pub entrypoint: Vec<String>,
    /// `Cmd`.
    pub cmd: Vec<String>,
    /// `Env`, as `KEY=VALUE`.
    pub env: Vec<String>,
    /// `WorkingDir`.
    pub workdir: String,
    /// `User`.
    pub user: String,
    /// `ExposedPorts` keys, e.g. `8080/tcp`.
    pub exposed_ports: Vec<String>,
}

fn write_blob(out: &Path, bytes: &[u8], media_type: &str) -> Result<Descriptor, ImageError> {
    let digest = sha256_digest(bytes);
    let path = out.join("blobs/sha256").join(&digest["sha256:".len()..]);
    fs::write(&path, bytes).map_err(|e| io_error(format!("write {}", path.display()), e))?;
    Ok(Descriptor {
        media_type: media_type.into(),
        digest,
        size: bytes.len() as u64,
    })
}

/// Tars a directory tree deterministically: entries sorted by name, depth
/// first, owner 0:0, mtime 0, modes from the files. Files named `.wh.*` are
/// packed as is, which is how whiteouts are represented in layers. Only
/// directories, regular files and symlinks are supported. The tarball is
/// built in memory: this is for small test and example images.
pub fn tar_dir(dir: &Path) -> Result<Vec<u8>, ImageError> {
    fn walk(
        base: &Path,
        rel: &Path,
        builder: &mut tar::Builder<Vec<u8>>,
    ) -> Result<(), ImageError> {
        let full = base.join(rel);
        let mut names: Vec<OsString> = fs::read_dir(&full)
            .and_then(|entries| entries.map(|e| e.map(|e| e.file_name())).collect())
            .map_err(|e| io_error(format!("read {}", full.display()), e))?;
        names.sort();
        for name in names {
            let child_rel = rel.join(&name);
            let child = base.join(&child_rel);
            let what = || format!("tar {}", child.display());
            let md = fs::symlink_metadata(&child).map_err(|e| io_error(what(), e))?;
            let mut header = tar::Header::new_gnu();
            // As unpacking does: no setuid or setgid, the sticky bit kept.
            header.set_mode(md.mode() & 0o1777);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            if md.file_type().is_symlink() {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                let target = fs::read_link(&child).map_err(|e| io_error(what(), e))?;
                builder
                    .append_link(&mut header, &child_rel, &target)
                    .map_err(|e| io_error(what(), e))?;
            } else if md.is_dir() {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                builder
                    .append_data(&mut header, &child_rel, io::empty())
                    .map_err(|e| io_error(what(), e))?;
                walk(base, &child_rel, builder)?;
            } else if md.is_file() {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(md.len());
                let file = File::open(&child).map_err(|e| io_error(what(), e))?;
                builder
                    .append_data(&mut header, &child_rel, file)
                    .map_err(|e| io_error(what(), e))?;
            } else {
                return Err(invalid(format!(
                    "{}: only directories, regular files and symlinks can be packed",
                    child.display()
                )));
            }
        }
        Ok(())
    }
    let mut builder = tar::Builder::new(Vec::new());
    walk(dir, Path::new(""), &mut builder)?;
    builder.into_inner().map_err(|e| io_error("finish tar", e))
}

/// gzip with a fixed header (mtime 0, OS "unknown"), so equal input gives
/// equal output.
fn gzip(bytes: &[u8]) -> Result<Vec<u8>, ImageError> {
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), flate2::Compression::default());
    gz.write_all(bytes).map_err(|e| io_error("gzip", e))?;
    gz.finish().map_err(|e| io_error("gzip", e))
}

fn to_json(v: &Value) -> Result<Vec<u8>, ImageError> {
    serde_json::to_vec(v).map_err(|e| invalid(format!("serialize JSON: {e}")))
}

/// Writes a deterministic OCI image layout with one image for linux and the
/// host architecture into `out`, which must not exist, and returns the
/// manifest digest. The same inputs always give the same bytes: tar entries
/// are sorted with owner 0:0 and mtime 0, gzip headers are fixed and the
/// JSON documents are compact with a fixed key order.
pub fn pack(out: &Path, layers: &[LayerSource], spec: &ImageSpec) -> Result<String, ImageError> {
    let arch = host_arch()?;
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| io_error(format!("create {}", parent.display()), e))?;
    }
    fs::create_dir(out).map_err(|e| io_error(format!("create {}", out.display()), e))?;
    fs::create_dir_all(out.join("blobs/sha256"))
        .map_err(|e| io_error(format!("create {}/blobs", out.display()), e))?;
    fs::write(out.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)
        .map_err(|e| io_error("write oci-layout", e))?;
    let mut layer_descs = Vec::new();
    let mut diff_ids = Vec::new();
    for layer in layers {
        let tar = tar_dir(&layer.dir)?;
        diff_ids.push(sha256_digest(&tar));
        let desc = if layer.gzip {
            write_blob(out, &gzip(&tar)?, MEDIA_LAYER_GZIP)?
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
        "architecture": arch,
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
    let config_desc = write_blob(out, &to_json(&config)?, MEDIA_CONFIG)?;
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MEDIA_MANIFEST,
        "config": config_desc.to_json(),
        "layers": layer_descs.iter().map(Descriptor::to_json).collect::<Vec<_>>(),
    });
    let manifest_desc = write_blob(out, &to_json(&manifest)?, MEDIA_MANIFEST)?;
    let mut entry = manifest_desc.to_json();
    entry["annotations"] = json!({ REF_NAME: spec.reference });
    let index = json!({ "schemaVersion": 2, "mediaType": MEDIA_INDEX, "manifests": [entry] });
    fs::write(out.join("index.json"), to_json(&index)?)
        .map_err(|e| io_error("write index.json", e))?;
    Ok(manifest_desc.digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::import_layout;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("km7-oci-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    fn is_root() -> bool {
        fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().next().map(|u| u == "0"))
            .unwrap_or(false)
    }

    fn no_owners() -> UnpackLimits {
        UnpackLimits {
            preserve_owners: false,
            ..UnpackLimits::default()
        }
    }

    enum E<'a> {
        Dir(&'a str),
        File(&'a str, &'a str),
        Link(&'a str, &'a str),
        Hard(&'a str, &'a str),
        Fifo(&'a str),
        /// A regular file whose raw header name is written verbatim.
        Raw(&'a str),
        /// A regular file with mode and owner.
        Owned(&'a str, u32, u64, u64),
        /// A directory with a mode.
        DirMode(&'a str, u32),
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
                E::Fifo(p) => {
                    h.set_entry_type(tar::EntryType::Fifo);
                    h.set_size(0);
                    b.append_data(&mut h, p, io::empty()).unwrap();
                }
                E::Raw(name) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_size(0);
                    h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
                    h.set_cksum();
                    b.append(&h, io::empty()).unwrap();
                }
                E::Owned(p, mode, uid, gid) => {
                    h.set_entry_type(tar::EntryType::Regular);
                    h.set_mode(*mode);
                    h.set_uid(*uid);
                    h.set_gid(*gid);
                    h.set_size(1);
                    b.append_data(&mut h, p, &b"x"[..]).unwrap();
                }
                E::DirMode(p, mode) => {
                    h.set_entry_type(tar::EntryType::Directory);
                    h.set_mode(*mode);
                    h.set_size(0);
                    b.append_data(&mut h, p, io::empty()).unwrap();
                }
            }
        }
        b.into_inner().unwrap()
    }

    fn apply(root: &Path, entries: &[E]) -> Result<(), ImageError> {
        apply_layer(
            root,
            layer(entries).as_slice(),
            &mut UnpackStats::default(),
            &no_owners(),
        )
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
        let tmp = temp_dir();
        let root = tmp.path();
        apply(
            root,
            &[
                E::Dir("etc/"),
                E::File("etc/stale", "x"),
                E::Dir("etc/d/"),
                E::File("etc/d/f", "y"),
            ],
        )
        .unwrap();
        apply(
            root,
            &[
                E::File("etc/new", "n"),
                E::File("etc/.wh.new", ""),
                E::File("etc/.wh.stale", ""),
                E::File("etc/.wh.d", ""),
                E::File("etc/.wh..wh.plnk", ""),
            ],
        )
        .unwrap();
        assert_eq!(listing(&root.join("etc")), ["new"]);
    }

    #[test]
    fn empty_and_dot_whiteouts_are_rejected() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(root, &[E::Dir("etc/"), E::File("etc/keep", "k")]).unwrap();
        // `.wh.` hides nothing, `.wh..` hides `.`, `.wh...` hides `..`.
        for bad in ["etc/.wh.", "etc/.wh..", "etc/.wh..."] {
            let err = apply(root, &[E::Raw(bad)]).unwrap_err().to_string();
            assert!(err.contains("hides no valid name"), "{bad}: {err}");
        }
        assert_eq!(listing(&root.join("etc")), ["keep"]);
    }

    #[test]
    fn opaque_dir_hides_lower_children_but_keeps_its_own_layer() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(
            root,
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
            root,
            &[
                E::File("srv/old/c", "c"),
                E::File("srv/old/.wh..wh..opq", ""),
                E::File("srv/old/d", "d"),
            ],
        )
        .unwrap();
        assert_eq!(listing(&root.join("srv/old")), ["c", "d"]);
    }

    #[test]
    fn absolute_symlinks_resolve_inside_the_rootfs() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(
            root,
            &[E::Dir("srv/"), E::Dir("opt/"), E::Link("opt/link", "/srv")],
        )
        .unwrap();
        // No directory entry for opt/link: the parent is the symlink.
        apply(root, &[E::File("opt/link/via-link.txt", "v")]).unwrap();
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
        let tmp = temp_dir();
        let root = &tmp.path().join("root");
        fs::create_dir(root).unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        apply(
            root,
            &[
                E::Link("evil", outside.to_str().unwrap()),
                E::Link("up", "../../../../../.."),
                E::Link("file-link", outside.join("target").to_str().unwrap()),
            ],
        )
        .unwrap();
        apply(
            root,
            &[
                E::File("evil/marker", "pwned"),
                E::File("up/marker-2", "pwned"),
                // Replacing the symlink itself must not write through it.
                E::File("file-link", "pwned"),
                E::Dir("evil/"),
            ],
        )
        .unwrap();
        assert!(listing(&outside).is_empty());
        assert!(!tmp.path().join("marker-2").exists());
        assert!(
            root.join(outside.strip_prefix("/").unwrap())
                .join("marker")
                .exists()
        );
        assert!(root.join("marker-2").exists());
        assert!(root.join("file-link").is_file());
        assert!(root.join("evil").is_dir());
    }

    #[test]
    fn parent_dir_entries_are_rejected() {
        let tmp = temp_dir();
        let err = apply(tmp.path(), &[E::Raw("../escape.txt")]).unwrap_err();
        assert!(err.to_string().contains("escapes the rootfs"), "{err}");
        let err = apply(tmp.path(), &[E::Hard("x", "../../etc/passwd")]).unwrap_err();
        assert!(err.to_string().contains("escapes the rootfs"), "{err}");
    }

    #[test]
    fn symlink_loops_are_rejected() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(root, &[E::Link("a", "b"), E::Link("b", "a")]).unwrap();
        let err = apply(root, &[E::File("a/x", "x")]).unwrap_err();
        assert!(err.to_string().contains("too many symlinks"), "{err}");
    }

    #[test]
    fn entries_replace_entries_of_another_type() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(
            root,
            &[E::Dir("x/"), E::File("x/inner", "i"), E::File("y", "file")],
        )
        .unwrap();
        apply(root, &[E::File("x", "now a file"), E::Dir("y/")]).unwrap();
        assert_eq!(fs::read_to_string(root.join("x")).unwrap(), "now a file");
        assert!(root.join("y").is_dir());
    }

    #[test]
    fn hard_links_point_inside_the_rootfs() {
        let tmp = temp_dir();
        let root = &tmp.path().join("root");
        fs::create_dir(root).unwrap();
        fs::write(tmp.path().join("secret"), "s").unwrap();
        apply(
            root,
            &[
                E::Dir("bin/"),
                E::File("bin/busybox", "bb"),
                E::Hard("bin/sh", "bin/busybox"),
                E::Link("out", tmp.path().to_str().unwrap()),
            ],
        )
        .unwrap();
        let a = fs::metadata(root.join("bin/busybox")).unwrap();
        let b = fs::metadata(root.join("bin/sh")).unwrap();
        assert_eq!(a.ino(), b.ino());
        // Through a symlink, the target re-roots: out/secret is not the host file.
        let err = apply(root, &[E::Hard("stolen", "out/secret")]).unwrap_err();
        assert!(err.to_string().contains("missing"), "{err}");
        let err = apply(root, &[E::Hard("dirlink", "bin")]).unwrap_err();
        assert!(err.to_string().contains("directory"), "{err}");
    }

    #[test]
    fn fifos_are_skipped_and_counted() {
        let tmp = temp_dir();
        let mut stats = UnpackStats::default();
        apply_layer(
            tmp.path(),
            layer(&[E::Fifo("pipe"), E::File("f", "x")]).as_slice(),
            &mut stats,
            &no_owners(),
        )
        .unwrap();
        assert_eq!(stats.skipped, 1);
        assert_eq!(listing(tmp.path()), ["f"]);
    }

    #[test]
    fn owners_come_from_the_headers_but_setid_bits_do_not() {
        if !is_root() {
            eprintln!("skipped: chown needs root");
            return;
        }
        let tmp = temp_dir();
        apply_layer(
            tmp.path(),
            layer(&[E::Owned("suid", 0o4755, 1000, 50)]).as_slice(),
            &mut UnpackStats::default(),
            &UnpackLimits::default(),
        )
        .unwrap();
        let md = fs::metadata(tmp.path().join("suid")).unwrap();
        assert_eq!((md.uid(), md.gid()), (1000, 50));
        assert_eq!(md.mode() & 0o7777, 0o755);
    }

    /// No setid bit comes from an image (ADR 0027), also not
    /// postgres:17-alpine's `run/postgresql` (2777): the bits are cleared,
    /// and sticky bits kept.
    #[test]
    fn setid_bits_are_cleared_and_counted_and_sticky_bits_kept() {
        let tmp = temp_dir();
        let mut stats = UnpackStats::default();
        apply_layer(
            tmp.path(),
            layer(&[
                E::DirMode("shared/", 0o2777),
                E::DirMode("sticky/", 0o1777),
                E::Owned("suid", 0o4755, 0, 0),
                E::File("plain", "x"),
            ])
            .as_slice(),
            &mut stats,
            &no_owners(),
        )
        .unwrap();
        let mode = |name: &str| fs::metadata(tmp.path().join(name)).unwrap().mode() & 0o7777;
        assert_eq!(mode("shared"), 0o777);
        assert_eq!(mode("sticky"), 0o1777);
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(mode("plain"), 0o755);
        assert_eq!(stats.setid_cleared, 2);
    }

    /// The image builder writes the modes unpacking would apply: setuid and
    /// setgid cleared, the sticky bit kept.
    #[test]
    fn tar_dir_clears_setid_bits() {
        let src = temp_dir();
        fs::write(src.path().join("suid"), b"x").unwrap();
        fs::set_permissions(src.path().join("suid"), Permissions::from_mode(0o4755)).unwrap();
        fs::create_dir(src.path().join("sticky")).unwrap();
        fs::set_permissions(src.path().join("sticky"), Permissions::from_mode(0o1777)).unwrap();
        let tarball = tar_dir(src.path()).unwrap();
        let mut modes: Vec<(String, u32)> = tar::Archive::new(tarball.as_slice())
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let path = e.path().unwrap().display().to_string();
                (
                    path.trim_end_matches('/').to_owned(),
                    e.header().mode().unwrap(),
                )
            })
            .collect();
        modes.sort();
        assert_eq!(
            modes,
            [("sticky".to_owned(), 0o1777), ("suid".to_owned(), 0o755)]
        );
    }

    #[test]
    fn user_names_resolve_through_the_image_passwd() {
        let tmp = temp_dir();
        let root = tmp.path();
        apply(
            root,
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
        assert_eq!(resolve_user(root, "").unwrap(), (0, 0));
        assert_eq!(resolve_user(root, "nobody").unwrap(), (65534, 65534));
        assert_eq!(resolve_user(root, "65534:50").unwrap(), (65534, 50));
        assert_eq!(resolve_user(root, "nobody:staff").unwrap(), (65534, 50));
        assert_eq!(resolve_user(root, "1000").unwrap(), (1000, 0));
        assert!(resolve_user(root, "ghost").is_err());
        assert!(resolve_user(root, "nobody:ghosts").is_err());
    }

    // ---- whole images through the blob store ----

    struct TestLayer {
        media_type: &'static str,
        tar: Vec<u8>,
    }

    fn compress(media_type: &str, tar: &[u8]) -> Vec<u8> {
        match layer_codec(media_type).unwrap() {
            Codec::Tar => tar.to_vec(),
            Codec::Gzip => gzip(tar).unwrap(),
            Codec::Zstd => {
                ruzstd::encoding::compress_to_vec(tar, ruzstd::encoding::CompressionLevel::Fastest)
            }
        }
    }

    fn put(store: &BlobStore, bytes: &[u8], media_type: &str) -> Descriptor {
        let d = Descriptor {
            media_type: media_type.into(),
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
        };
        store.put(&d, bytes).unwrap();
        d
    }

    /// Stores an image and returns its manifest digest. `diff_ids` default
    /// to the right ones.
    fn store_image(
        store: &BlobStore,
        layers: &[TestLayer],
        diff_ids: Option<Vec<String>>,
    ) -> String {
        let descs: Vec<Descriptor> = layers
            .iter()
            .map(|l| put(store, &compress(l.media_type, &l.tar), l.media_type))
            .collect();
        let diff_ids =
            diff_ids.unwrap_or_else(|| layers.iter().map(|l| sha256_digest(&l.tar)).collect());
        let config = json!({
            "architecture": host_arch().unwrap(), "os": "linux",
            "config": {"Entrypoint": ["/bin/echo"], "Cmd": ["hi"], "Env": ["A=1", "PATH=/bin"],
                       "User": "app", "WorkingDir": "/work"},
            "rootfs": {"type": "layers", "diff_ids": diff_ids},
        });
        let config = put(store, &to_json(&config).unwrap(), MEDIA_CONFIG);
        let manifest = json!({
            "schemaVersion": 2, "mediaType": MEDIA_MANIFEST, "config": config.to_json(),
            "layers": descs.iter().map(Descriptor::to_json).collect::<Vec<_>>(),
        });
        put(store, &to_json(&manifest).unwrap(), MEDIA_MANIFEST).digest
    }

    fn new_store(tmp: &tempfile::TempDir) -> BlobStore {
        BlobStore::new(tmp.path().join("blobs"))
    }

    #[test]
    fn gzip_zstd_and_plain_layers_unpack() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let digest = store_image(
            &store,
            &[
                TestLayer {
                    media_type: MEDIA_LAYER_GZIP,
                    tar: layer(&[E::Dir("a/"), E::File("a/gz", "g")]),
                },
                TestLayer {
                    media_type: MEDIA_LAYER_ZSTD,
                    tar: layer(&[E::File("a/zst", "z")]),
                },
                TestLayer {
                    media_type: MEDIA_LAYER_TAR,
                    tar: layer(&[E::File("a/tar", "t")]),
                },
                TestLayer {
                    media_type: DOCKER_LAYER_GZIP,
                    tar: layer(&[E::File("a/docker", "d")]),
                },
                TestLayer {
                    media_type: OCI_NONDIST_ZSTD,
                    tar: layer(&[E::File("a/nondist", "n")]),
                },
            ],
            None,
        );
        let image = Image::open(&store, &digest).unwrap();
        assert_eq!(image.manifest_digest, digest);
        let rootfs = tmp.path().join("rootfs");
        let stats = unpack(&store, &image, &rootfs, &no_owners()).unwrap();
        assert_eq!(stats.layers, 5);
        assert_eq!(
            listing(&rootfs.join("a")),
            ["docker", "gz", "nondist", "tar", "zst"]
        );
        assert_eq!(fs::read_to_string(rootfs.join("a/zst")).unwrap(), "z");
        // The rootfs must not exist yet.
        assert!(unpack(&store, &image, &rootfs, &no_owners()).is_err());
    }

    #[test]
    fn multi_frame_zstd_layers_unpack() {
        let tar = layer(&[E::File("big", &"x".repeat(5000))]);
        let (a, b) = tar.split_at(1000);
        let mut blob =
            ruzstd::encoding::compress_to_vec(a, ruzstd::encoding::CompressionLevel::Fastest);
        // A skippable frame between the two data frames.
        blob.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(b"abc");
        blob.extend(ruzstd::encoding::compress_to_vec(
            b,
            ruzstd::encoding::CompressionLevel::Fastest,
        ));
        let mut out = Vec::new();
        ZstdFrames::new(blob.as_slice())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, tar);
    }

    #[test]
    fn diff_id_mismatch_is_rejected() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let tar = layer(&[E::File("f", "x")]);
        let wrong = sha256_digest(b"something else");
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_GZIP,
                tar,
            }],
            Some(vec![wrong]),
        );
        let image = Image::open(&store, &digest).unwrap();
        let err = unpack(&store, &image, &tmp.path().join("rootfs"), &no_owners()).unwrap_err();
        assert!(err.to_string().contains("does not match diff_id"), "{err}");
    }

    #[test]
    fn tampered_layer_blob_is_rejected() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_TAR,
                tar: layer(&[E::File("f", "x")]),
            }],
            None,
        );
        let image = Image::open(&store, &digest).unwrap();
        let path = store.path(&image.layers[0].digest).unwrap();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"!").unwrap();
        drop(f);
        let rootfs = tmp.path().join("rootfs");
        let err = unpack(&store, &image, &rootfs, &no_owners()).unwrap_err();
        assert!(matches!(err, ImageError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("descriptor says"), "{err}");
        // Nothing from the layer was applied.
        assert!(listing(&rootfs).is_empty());
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_TAR,
                tar: layer(&[E::File("f", "x")]),
            }],
            None,
        );
        let path = store.path(&digest).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b' ');
        fs::write(&path, bytes).unwrap();
        let err = Image::open(&store, &digest).unwrap_err();
        assert!(err.to_string().contains("failed verification"), "{err}");
    }

    #[test]
    fn byte_and_entry_limits_are_enforced() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_GZIP,
                tar: layer(&[
                    E::File("a", &"x".repeat(10_000)),
                    E::File("b", "y"),
                    E::File("c", "z"),
                ]),
            }],
            None,
        );
        let image = Image::open(&store, &digest).unwrap();
        let limits = UnpackLimits {
            max_bytes: 4096,
            ..no_owners()
        };
        let err = unpack(&store, &image, &tmp.path().join("r1"), &limits).unwrap_err();
        assert!(err.to_string().contains("more than 4096 bytes"), "{err}");
        let limits = UnpackLimits {
            max_entries: 2,
            ..no_owners()
        };
        let err = unpack(&store, &image, &tmp.path().join("r2"), &limits).unwrap_err();
        assert!(err.to_string().contains("more than 2 entries"), "{err}");
        let stats = unpack(&store, &image, &tmp.path().join("r3"), &no_owners()).unwrap();
        assert_eq!(stats.entries, 3);
        assert!(stats.bytes > 10_000);
    }

    #[test]
    fn indexes_resolve_to_the_host_platform() {
        let tmp = temp_dir();
        let store = new_store(&tmp);
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_TAR,
                tar: layer(&[E::File("f", "x")]),
            }],
            None,
        );
        let size = fs::metadata(store.path(&digest).unwrap()).unwrap().len();
        let other = if host_arch().unwrap() == "amd64" {
            "arm64"
        } else {
            "amd64"
        };
        let index = json!({"schemaVersion": 2, "mediaType": DOCKER_LIST, "manifests": [
            {"mediaType": MEDIA_MANIFEST, "digest": sha256_digest(b"nope"), "size": 4,
             "platform": {"os": "linux", "architecture": other}},
            {"mediaType": MEDIA_MANIFEST, "digest": digest, "size": size,
             "platform": {"os": "linux", "architecture": host_arch().unwrap()}},
        ]});
        let index = put(&store, &to_json(&index).unwrap(), DOCKER_LIST);
        let image = Image::open(&store, &index.digest).unwrap();
        assert_eq!(image.manifest_digest, digest);

        let only_other = json!({"schemaVersion": 2, "manifests": [
            {"mediaType": MEDIA_MANIFEST, "digest": digest, "size": size,
             "platform": {"os": "linux", "architecture": other}},
        ]});
        let only_other = put(&store, &to_json(&only_other).unwrap(), MEDIA_INDEX);
        let err = Image::open(&store, &only_other.digest).unwrap_err();
        assert!(err.to_string().contains("no image for linux"), "{err}");
    }

    fn spec_image(tmp: &tempfile::TempDir) -> (Image, PathBuf) {
        let store = new_store(tmp);
        let digest = store_image(
            &store,
            &[TestLayer {
                media_type: MEDIA_LAYER_GZIP,
                tar: layer(&[
                    E::Dir("etc/"),
                    E::File(
                        "etc/passwd",
                        "root:x:0:0::/:/bin/sh\napp:x:1000:1000::/:/bin/sh\n",
                    ),
                ]),
            }],
            None,
        );
        let image = Image::open(&store, &digest).unwrap();
        let rootfs = tmp.path().join("bundle/rootfs");
        fs::create_dir(tmp.path().join("bundle")).unwrap();
        unpack(&store, &image, &rootfs, &no_owners()).unwrap();
        (image, rootfs)
    }

    #[test]
    fn runtime_spec_applies_the_overrides() {
        let tmp = temp_dir();
        let (image, rootfs) = spec_image(&tmp);
        let o = Overrides {
            cpu_millis: 500,
            memory_bytes: 64 << 20,
            pids: 1024,
            env: vec![("A".into(), "2".into()), ("SECRET".into(), "s".into())],
            binds: vec![Bind {
                source: "/var/lib/kronik/foreign/echo/data".into(),
                destination: "/data".into(),
                read_only: false,
            }],
            cgroups_path: Some("/kronik/0123abcd/echo".into()),
            netns: Some("/run/kronik/netns/echo".into()),
            hostname: "echo".into(),
            syscall_filter: false,
        };
        let spec = runtime_spec(&image, &rootfs, &o).unwrap();
        let j = &spec.json;
        assert_eq!((spec.uid, spec.gid), (1000, 1000));
        assert_eq!(j["ociVersion"], "1.0.2");
        assert_eq!(j["process"]["user"], json!({"uid": 1000, "gid": 1000}));
        assert_eq!(j["process"]["args"], json!(["/bin/echo", "hi"]));
        assert_eq!(j["process"]["env"], json!(["PATH=/bin", "A=2", "SECRET=s"]));
        assert_eq!(j["process"]["cwd"], "/work");
        assert!(rootfs.join("work").is_dir());
        assert_eq!(j["process"]["noNewPrivileges"], true);
        assert_eq!(j["process"]["capabilities"]["bounding"], json!([]));
        assert_eq!(j["process"]["rlimits"][0]["hard"], 65536);
        assert_eq!(j["root"]["path"], rootfs.to_str().unwrap());
        assert_eq!(j["hostname"], "echo");
        let r = &j["linux"]["resources"];
        assert_eq!(r["cpu"], json!({"quota": 50_000, "period": 100_000}));
        assert_eq!(r["memory"], json!({"limit": 64 << 20, "swap": 64 << 20}));
        assert_eq!(r["pids"], json!({"limit": 1024}));
        assert_eq!(j["linux"]["cgroupsPath"], "/kronik/0123abcd/echo");
        assert_eq!(
            j["linux"]["namespaces"],
            json!([{"type": "pid"}, {"type": "network", "path": "/run/kronik/netns/echo"},
                   {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}])
        );
        let mounts = j["mounts"].as_array().unwrap();
        let dests: Vec<&str> = mounts
            .iter()
            .map(|m| m["destination"].as_str().unwrap())
            .collect();
        assert_eq!(
            dests,
            ["/proc", "/dev", "/dev/pts", "/dev/shm", "/sys", "/data"]
        );
        assert_eq!(mounts[4]["options"][3], "ro");
        assert_eq!(mounts[5]["source"], "/var/lib/kronik/foreign/echo/data");
        assert_eq!(mounts[5]["options"][1], "rw");
        let masked = j["linux"]["maskedPaths"].as_array().unwrap();
        assert!(masked.contains(&json!("/sys/devices/virtual/powercap")));
        assert!(j["linux"]["seccomp"].is_null(), "gVisor needs no filter");
        let trusted = runtime_spec(
            &image,
            &rootfs,
            &Overrides {
                syscall_filter: true,
                ..o
            },
        )
        .unwrap();
        let filter = &trusted.json["linux"]["seccomp"];
        assert_eq!(filter["defaultAction"], "SCMP_ACT_ALLOW");
        let names = filter["syscalls"][0]["names"].as_array().unwrap();
        assert!(names.contains(&json!("unshare")) && names.contains(&json!("bpf")));
        assert!(names.contains(&json!("io_uring_setup")));
        assert_eq!(filter["syscalls"][1]["errnoRet"], 38);
        assert_eq!(filter["syscalls"].as_array().unwrap().len(), 9);
    }

    #[test]
    fn runtime_spec_gives_root_the_default_capabilities() {
        let tmp = temp_dir();
        let (mut image, rootfs) = spec_image(&tmp);
        image.config["config"]["User"] = json!("");
        let spec = runtime_spec(&image, &rootfs, &Overrides::default()).unwrap();
        let caps = spec.json["process"]["capabilities"]["effective"]
            .as_array()
            .unwrap();
        assert_eq!(caps.len(), 13);
        assert!(!caps.contains(&json!("CAP_NET_RAW")));
        assert_eq!(spec.json["linux"]["resources"], json!({}));
        assert_eq!(
            spec.json["linux"]["namespaces"][1],
            json!({"type": "network"})
        );
        assert!(spec.json["linux"].get("cgroupsPath").is_none());
    }

    #[test]
    fn pack_is_deterministic_and_imports() {
        let tmp = temp_dir();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("bin")).unwrap();
        fs::write(src.join("bin/app"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(src.join("bin/app"), Permissions::from_mode(0o755)).unwrap();
        symlink("app", src.join("bin/alias")).unwrap();
        let spec = ImageSpec {
            reference: "echo".into(),
            entrypoint: vec!["/bin/app".into()],
            exposed_ports: vec!["8080/tcp".into()],
            ..ImageSpec::default()
        };
        let layers = [
            LayerSource {
                dir: src.clone(),
                gzip: true,
            },
            LayerSource {
                dir: src.clone(),
                gzip: false,
            },
        ];
        let a = pack(&tmp.path().join("a"), &layers, &spec).unwrap();
        let b = pack(&tmp.path().join("b"), &layers, &spec).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            fs::read(tmp.path().join("a/index.json")).unwrap(),
            fs::read(tmp.path().join("b/index.json")).unwrap()
        );
        assert!(pack(&tmp.path().join("a"), &layers, &spec).is_err());

        let store = new_store(&tmp);
        let resolved = import_layout(&store, &tmp.path().join("a"), None).unwrap();
        assert_eq!(resolved.manifest_digest, a);
        let image = Image::open(&store, &a).unwrap();
        let rootfs = tmp.path().join("rootfs");
        unpack(&store, &image, &rootfs, &no_owners()).unwrap();
        assert_eq!(
            fs::read_link(rootfs.join("bin/alias")).unwrap(),
            Path::new("app")
        );
        assert_eq!(
            fs::metadata(rootfs.join("bin/app")).unwrap().mode() & 0o777,
            0o755
        );
    }
}
