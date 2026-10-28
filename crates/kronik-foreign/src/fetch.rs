//! Getting an image into the blob store (m7-foreign §4): from a local OCI
//! image layout or, anonymously, from a registry with `oci-client`.
//!
//! Both paths verify everything themselves. The top-level manifest (or
//! index) must hash to the pinned digest, an index resolves to its entry for
//! `linux` and the host architecture, and the config and every layer blob
//! must match their descriptors' digest and size before they are kept.
//! Kronik never trusts a digest a registry reports.

use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference, RegistryOperation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWrite};

use crate::blobs::{BlobStore, Descriptor, TempFile, check, hex, io_error, sha256_digest};
use crate::image::{ImageError, ImageRef, validate_digest};
use crate::oci::{
    DOCKER_LIST, DOCKER_MANIFEST, MAX_JSON_BYTES, MEDIA_INDEX, MEDIA_MANIFEST, Parsed,
    parse_config, parse_manifest, select_platform,
};

/// How deep indexes may nest before a manifest must appear.
const MAX_INDEX_DEPTH: usize = 4;

/// An image that is complete in the blob store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The digest the reference resolved to (the top-level manifest or
    /// index); [`crate::oci::Image::open`] takes it.
    pub manifest_digest: String,
    /// The canonical record string, see [`ImageRef::pinned`].
    pub pinned: String,
}

fn invalid(msg: impl Into<String>) -> ImageError {
    ImageError::Invalid(msg.into())
}

/// Opens a file of a layout: never through a symbolic link (the daemon
/// reads as root, and a link could point anywhere on the host), never a
/// FIFO or device (`O_NONBLOCK`, then a regular-file check).
fn open_in_layout(path: &Path) -> Result<fs::File, ImageError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                invalid(format!(
                    "{} is missing: not an OCI image layout",
                    path.display()
                ))
            } else if e.raw_os_error() == Some(libc::ELOOP) {
                invalid(format!(
                    "{} is a symbolic link; the files of a layout must be regular files",
                    path.display()
                ))
            } else {
                io_error(format!("open {}", path.display()), e)
            }
        })?;
    let regular = file
        .metadata()
        .map_err(|e| io_error(format!("stat {}", path.display()), e))?
        .is_file();
    if !regular {
        return Err(invalid(format!("{} is not a regular file", path.display())));
    }
    Ok(file)
}

/// Reads a small file of the layout, at most `max` bytes.
fn read_layout_file(path: &Path, max: u64) -> Result<Vec<u8>, ImageError> {
    let file = open_in_layout(path)?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(format!("read {}", path.display()), e))?;
    if bytes.len() as u64 > max {
        return Err(invalid(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Copies one blob from the layout into the store (verified by `put`).
fn copy_blob(
    store: &BlobStore,
    dir: &Path,
    desc: &Descriptor,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<(), ImageError> {
    let abandoned = || cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed));
    if abandoned() {
        return Err(invalid(
            "the layout import was abandoned ([foreign] pull_timeout)",
        ));
    }
    if store.has_verified(desc) {
        return Ok(());
    }
    validate_digest(&desc.digest)?;
    let path = dir
        .join("blobs/sha256")
        .join(&desc.digest["sha256:".len()..]);
    let file = open_in_layout(&path).map_err(|e| match e {
        ImageError::Invalid(m) if m.ends_with("not an OCI image layout") => invalid(format!(
            "blob {} is missing from {}",
            desc.digest,
            dir.display()
        )),
        other => other,
    })?;
    // A read error ends `put`, which then removes its temporary file.
    let reader = CancelReader {
        inner: io::BufReader::new(file),
        cancel,
    };
    store.put(desc, reader)
}

/// Fails reads once `cancel` is set: an abandoned import stops at the next
/// read instead of copying the rest of a large blob.
struct CancelReader<'a, R> {
    inner: R,
    cancel: Option<&'a std::sync::atomic::AtomicBool>,
}

impl<R: io::Read> io::Read for CancelReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self
            .cancel
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        {
            return Err(io::Error::other("the layout import was abandoned"));
        }
        self.inner.read(buf)
    }
}

/// `blobs/sha256` must be inside the layout itself, not a link elsewhere.
fn check_blob_dir(dir: &Path) -> Result<(), ImageError> {
    let canonical = |p: &Path| {
        p.canonicalize()
            .map_err(|e| io_error(format!("resolve {}", p.display()), e))
    };
    let blobs = dir.join("blobs/sha256");
    if blobs.symlink_metadata().is_err() {
        return Ok(()); // the missing blobs are reported one by one
    }
    if !canonical(&blobs)?.starts_with(canonical(dir)?) {
        return Err(invalid(format!(
            "{} leads out of the layout",
            blobs.display()
        )));
    }
    Ok(())
}

/// Imports an image from the OCI image layout in `dir` into the store
/// (blocking). `digest` selects an image listed in `index.json`; without it
/// the layout must list exactly one. Indexes resolve to their entry for
/// `linux` and the host architecture; index, manifest, config and layers are
/// verified and copied, so the image no longer depends on the directory.
pub fn import_layout(
    store: &BlobStore,
    dir: &Path,
    digest: Option<&str>,
) -> Result<Resolved, ImageError> {
    import_layout_named(store, dir, digest, None)
}

/// [`import_layout`], choosing the image by its
/// `org.opencontainers.image.ref.name` annotation when `reference` is given
/// (`oci-layout:<dir>:<ref name>`).
pub fn import_layout_named(
    store: &BlobStore,
    dir: &Path,
    digest: Option<&str>,
    reference: Option<&str>,
) -> Result<Resolved, ImageError> {
    import_layout_limited(store, dir, digest, reference, &ImportLimits::default())
}

/// [`import_layout_named`] with an add's space budget and a cancel flag.
pub fn import_layout_limited(
    store: &BlobStore,
    dir: &Path,
    digest: Option<&str>,
    reference: Option<&str>,
    limits: &ImportLimits<'_>,
) -> Result<Resolved, ImageError> {
    let copy = |desc: &Descriptor| copy_blob(store, dir, desc, limits.cancel);
    let marker: Value = serde_json::from_slice(&read_layout_file(&dir.join("oci-layout"), 4096)?)
        .map_err(|e| invalid(format!("parse {}/oci-layout: {e}", dir.display())))?;
    if marker["imageLayoutVersion"] != "1.0.0" {
        return Err(invalid(format!(
            "unsupported image layout version {} in {}",
            marker["imageLayoutVersion"],
            dir.display()
        )));
    }
    check_blob_dir(dir)?;
    let index: Value =
        serde_json::from_slice(&read_layout_file(&dir.join("index.json"), MAX_JSON_BYTES)?)
            .map_err(|e| invalid(format!("parse {}/index.json: {e}", dir.display())))?;
    let entries = index["manifests"]
        .as_array()
        .ok_or_else(|| invalid(format!("{}/index.json lists no images", dir.display())))?;
    if let Some(d) = digest {
        validate_digest(d)?;
    }
    let chosen: Vec<&Value> = entries
        .iter()
        .filter(|m| digest.is_none_or(|d| m["digest"] == d))
        .filter(|m| reference.is_none_or(|r| m["annotations"][crate::oci::REF_NAME] == r))
        .collect();
    let top = match (chosen.as_slice(), digest) {
        ([one], _) => Descriptor::from_json(one)?,
        ([], None) if reference.is_some() => {
            return Err(invalid(format!(
                "{}/index.json has no image named {:?}",
                dir.display(),
                reference.unwrap_or_default()
            )));
        }
        ([], Some(d)) => {
            return Err(invalid(format!(
                "{}/index.json does not list {d}",
                dir.display()
            )));
        }
        (many, Some(d)) => {
            return Err(invalid(format!(
                "{}/index.json lists {d} {} times",
                dir.display(),
                many.len()
            )));
        }
        (many, None) => {
            return Err(invalid(format!(
                "{} holds {} images: pick one with oci-layout:{}@sha256:<digest>",
                dir.display(),
                many.len(),
                dir.display()
            )));
        }
    };

    let mut desc = top.clone();
    for _ in 0..=MAX_INDEX_DEPTH {
        if desc.size > MAX_JSON_BYTES {
            return Err(invalid(format!("manifest {} is too large", desc.digest)));
        }
        copy(&desc)?;
        let bytes = store.read_small(&desc, MAX_JSON_BYTES)?;
        match parse_manifest(&bytes, &desc.digest)? {
            Parsed::Index(entries) => desc = select_platform(&entries, &desc.digest)?,
            Parsed::Manifest { config, layers } => {
                if config.size > MAX_JSON_BYTES {
                    return Err(invalid(format!(
                        "image config {} is too large",
                        config.digest
                    )));
                }
                copy(&config)?;
                parse_config(&store.read_small(&config, MAX_JSON_BYTES)?)?;
                check_image_size(
                    store,
                    &layers,
                    &format!("oci-layout:{}", dir.display()),
                    limits.max_new_bytes,
                )?;
                for layer in &layers {
                    copy(layer)?;
                }
                let pinned = ImageRef::Layout {
                    dir: dir.to_path_buf(),
                    digest: None,
                    reference: None,
                }
                .pinned(&top.digest);
                return Ok(Resolved {
                    manifest_digest: top.digest,
                    pinned,
                });
            }
        }
    }
    Err(invalid(format!(
        "indexes nest too deeply in {}",
        dir.display()
    )))
}

/// Options of [`pull`].
#[derive(Clone, Debug, Default)]
pub struct FetchOptions {
    /// Registries (`host:port`) pulled over plain HTTP. Tests only.
    pub insecure_registries: Vec<String>,
    /// At most this many bytes of layers the store does not hold yet (an
    /// add below `[log] disk_reserve`'s margin is refused before it fetches).
    pub max_new_bytes: Option<u64>,
}

/// Limits of a layout import ([`import_layout_limited`]).
#[derive(Debug, Default)]
pub struct ImportLimits<'a> {
    /// As [`FetchOptions::max_new_bytes`].
    pub max_new_bytes: Option<u64>,
    /// Set when the import is abandoned (`pull_timeout`): it stops at the
    /// next blob boundary or read, and removes its temporary file.
    pub cancel: Option<&'a std::sync::atomic::AtomicBool>,
}

const ACCEPTED_MANIFESTS: [&str; 4] = [MEDIA_MANIFEST, MEDIA_INDEX, DOCKER_MANIFEST, DOCKER_LIST];

fn registry_error(what: &str, e: impl std::fmt::Display) -> ImageError {
    invalid(format!("{what}: {e}"))
}

/// Pulls `registry/repository@digest` anonymously into the store. The
/// manifest (or index) is fetched by digest and must hash to `digest`; an
/// index resolves to its entry for `linux` and the host architecture,
/// fetched and verified by its own digest. Config and layer blobs stream
/// into the store through SHA-256 and are kept only if they match their
/// descriptors. Blobs already in the store (and intact) are not fetched
/// again.
pub async fn pull(
    store: &BlobStore,
    registry: &str,
    repository: &str,
    digest: &str,
    options: &FetchOptions,
) -> Result<Resolved, ImageError> {
    validate_digest(digest)?;
    // reqwest uses rustls without a bundled provider; Kronik uses ring
    // everywhere. Installing fails harmlessly when a provider is set.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let protocol = if options.insecure_registries.is_empty() {
        ClientProtocol::Https
    } else {
        ClientProtocol::HttpsExcept(options.insecure_registries.clone())
    };
    let client = Client::new(ClientConfig {
        protocol,
        platform_resolver: None,
        ..ClientConfig::default()
    });
    let reference = |d: &str| Reference::with_digest(registry.into(), repository.into(), d.into());
    let image = format!("{registry}/{repository}@{digest}");
    client
        .auth(
            &reference(digest),
            &RegistryAuth::Anonymous,
            RegistryOperation::Pull,
        )
        .await
        .map_err(|e| registry_error(&format!("authenticate to {registry}"), e))?;

    let mut current = digest.to_string();
    let mut expected_size: Option<u64> = None;
    for _ in 0..=MAX_INDEX_DEPTH {
        let bytes = manifest(
            &client,
            store,
            &reference(&current),
            &current,
            expected_size,
        )
        .await?;
        match parse_manifest(&bytes, &current)? {
            Parsed::Index(entries) => {
                let desc = select_platform(&entries, &current)?;
                if desc.size > MAX_JSON_BYTES {
                    return Err(invalid(format!("manifest {} is too large", desc.digest)));
                }
                current = desc.digest;
                expected_size = Some(desc.size);
            }
            Parsed::Manifest { config, layers } => {
                if config.size > MAX_JSON_BYTES {
                    return Err(invalid(format!(
                        "image config {} is too large",
                        config.digest
                    )));
                }
                let r = reference(&current);
                blob(&client, store, &r, &config).await?;
                let path = store.path(&config.digest)?;
                let config_bytes = tokio::fs::read(&path)
                    .await
                    .map_err(|e| io_error(format!("read {}", path.display()), e))?;
                check(
                    &config,
                    config_bytes.len() as u64,
                    &sha256_digest(&config_bytes),
                )?;
                parse_config(&config_bytes)?;
                check_image_size(store, &layers, &image, options.max_new_bytes)?;
                for layer in &layers {
                    blob(&client, store, &r, layer).await?;
                }
                tracing::info!(image = %image, manifest = %current, layers = layers.len(), "image pulled");
                let pinned = ImageRef::Registry {
                    registry: registry.to_string(),
                    repository: repository.to_string(),
                    digest: digest.to_string(),
                }
                .pinned(digest);
                return Ok(Resolved {
                    manifest_digest: digest.to_string(),
                    pinned,
                });
            }
        }
    }
    Err(invalid(format!("indexes nest too deeply in {image}")))
}

/// The most an image's layers may take compressed, the same bound as the
/// uncompressed rootfs (`UnpackLimits::max_bytes`): checked against the
/// manifest before any layer is fetched, so a huge image never fills the
/// blob store's disk first.
pub const MAX_IMAGE_BYTES: u64 = 8 << 30;

/// Checks an image's layers against [`MAX_IMAGE_BYTES`], and the layers the
/// store does not hold yet against `max_new_bytes` (the free space above
/// `[log] disk_reserve`, for an add), before any layer is fetched.
fn check_image_size(
    store: &BlobStore,
    layers: &[Descriptor],
    image: &str,
    max_new_bytes: Option<u64>,
) -> Result<(), ImageError> {
    let total = layers
        .iter()
        .fold(0u64, |sum, l| sum.saturating_add(l.size));
    if total > MAX_IMAGE_BYTES {
        return Err(invalid(format!(
            "{image} has {total} bytes of layers, more than the {MAX_IMAGE_BYTES} allowed"
        )));
    }
    if let Some(budget) = max_new_bytes {
        let new = layers
            .iter()
            .filter(|l| !store.has(l))
            .fold(0u64, |sum, l| sum.saturating_add(l.size));
        if new > budget {
            return Err(ImageError::NoSpace(format!(
                "{image} needs {} MiB of new layers, but only {} MiB are free above \
                 [log] disk_reserve",
                new.div_ceil(1 << 20),
                budget >> 20
            )));
        }
    }
    Ok(())
}

/// Returns the verified manifest or index `digest`, from the store when it
/// is there, else from the registry (then it is stored).
async fn manifest(
    client: &Client,
    store: &BlobStore,
    reference: &Reference,
    digest: &str,
    expected_size: Option<u64>,
) -> Result<Vec<u8>, ImageError> {
    let path = store.path(digest)?;
    if let Ok(bytes) = tokio::fs::read(&path).await
        && sha256_digest(&bytes) == digest
        && expected_size.is_none_or(|s| s == bytes.len() as u64)
    {
        return Ok(bytes);
    }
    let (bytes, _registry_digest) = client
        .pull_manifest_raw(reference, &RegistryAuth::Anonymous, &ACCEPTED_MANIFESTS)
        .await
        .map_err(|e| registry_error(&format!("fetch manifest {reference}"), e))?;
    let size = bytes.len() as u64;
    if size > MAX_JSON_BYTES {
        return Err(invalid(format!("manifest {digest} is too large")));
    }
    let desc = Descriptor {
        media_type: String::new(),
        digest: digest.to_string(),
        size: expected_size.unwrap_or(size),
    };
    check(&desc, size, &sha256_digest(&bytes))?;
    write_verified(store, &desc, &bytes).await?;
    Ok(bytes.to_vec())
}

/// Writes bytes that were verified against `desc` into the store.
async fn write_verified(
    store: &BlobStore,
    desc: &Descriptor,
    bytes: &[u8],
) -> Result<(), ImageError> {
    let guard = TempFile(store.temp_name());
    let temp = &guard.0;
    let mut file = create_temp(store, temp).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes)
        .await
        .map_err(|e| io_error(format!("write {}", temp.display()), e))?;
    commit(store, file, temp, &desc.digest).await
}

async fn create_temp(store: &BlobStore, temp: &Path) -> Result<tokio::fs::File, ImageError> {
    let dir = store.dir();
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| io_error(format!("create {}", dir.display()), e))?;
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(temp)
        .await
        .map_err(|e| io_error(format!("create {}", temp.display()), e))
}

/// fsyncs `file`, renames it to the blob's final name and makes the rename
/// durable.
async fn commit(
    store: &BlobStore,
    file: tokio::fs::File,
    temp: &Path,
    digest: &str,
) -> Result<(), ImageError> {
    file.sync_all()
        .await
        .map_err(|e| io_error(format!("fsync {}", temp.display()), e))?;
    drop(file);
    let path = store.path(digest)?;
    tokio::fs::rename(temp, &path)
        .await
        .map_err(|e| io_error(format!("rename {}", path.display()), e))?;
    let dir = store.dir();
    let handle = tokio::fs::File::open(&dir)
        .await
        .map_err(|e| io_error(format!("open {}", dir.display()), e))?;
    handle
        .sync_all()
        .await
        .map_err(|e| io_error(format!("fsync {}", dir.display()), e))
}

/// Whether the blob is in the store and intact, hashing it asynchronously.
/// A corrupt blob is removed so it is fetched again.
async fn has_verified(store: &BlobStore, desc: &Descriptor) -> bool {
    if !store.has(desc) {
        return false;
    }
    let Ok(path) = store.path(&desc.digest) else {
        return false;
    };
    let Ok(mut file) = tokio::fs::File::open(&path).await else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut size = 0u64;
    loop {
        match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                size += n as u64;
            }
            Err(_) => return false,
        }
    }
    let actual = format!("sha256:{}", hex(&hasher.finalize()));
    if size == desc.size && actual == desc.digest {
        return true;
    }
    tracing::warn!(digest = %desc.digest, "removing a corrupt blob from the store");
    let _ = tokio::fs::remove_file(&path).await;
    false
}

/// Streams a config or layer blob from the registry into the store.
async fn blob(
    client: &Client,
    store: &BlobStore,
    reference: &Reference,
    desc: &Descriptor,
) -> Result<(), ImageError> {
    validate_digest(&desc.digest)?;
    if has_verified(store, desc).await {
        return Ok(());
    }
    let guard = TempFile(store.temp_name());
    let temp = &guard.0;
    let file = create_temp(store, temp).await?;
    let mut out = HashingFile {
        file,
        hasher: Sha256::new(),
        written: 0,
        limit: desc.size,
        oversize: false,
        disk_error: None,
    };
    // The descriptor is passed as a bare digest: Kronik fetches every
    // blob from the registry, never from a layer's `urls`.
    let pulled = client
        .pull_blob(reference, desc.digest.as_str(), &mut out)
        .await;
    if let Some(e) = out.disk_error.take() {
        return Err(ImageError::Io(format!("write {}: {e}", temp.display())));
    }
    if out.oversize {
        return Err(invalid(format!(
            "blob {} has more than the {} bytes its descriptor says",
            desc.digest, desc.size
        )));
    }
    pulled.map_err(|e| registry_error(&format!("fetch blob {}", desc.digest), e))?;
    let actual = format!("sha256:{}", hex(&out.hasher.finalize()));
    check(desc, out.written, &actual)?;
    commit(store, out.file, temp, &desc.digest).await
}

/// A temporary blob file that hashes and counts what is written and refuses
/// to grow beyond the descriptor's size.
struct HashingFile {
    file: tokio::fs::File,
    hasher: Sha256,
    written: u64,
    limit: u64,
    oversize: bool,
    disk_error: Option<String>,
}

impl AsyncWrite for HashingFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.written + buf.len() as u64 > this.limit {
            this.oversize = true;
            return Poll::Ready(Err(io::Error::other("blob larger than its descriptor")));
        }
        match Pin::new(&mut this.file).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.hasher.update(&buf[..n]);
                this.written += n as u64;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                this.disk_error = Some(e.to_string());
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{Image, ImageSpec, LayerSource, pack};

    fn temp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("km7-fetch-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    fn packed(tmp: &tempfile::TempDir, name: &str, content: &str) -> (std::path::PathBuf, String) {
        let src = tmp.path().join(format!("src-{name}"));
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file"), content).unwrap();
        let out = tmp.path().join(name);
        let digest = pack(
            &out,
            &[LayerSource {
                dir: src,
                gzip: true,
            }],
            &ImageSpec {
                reference: name.into(),
                cmd: vec!["/file".into()],
                ..ImageSpec::default()
            },
        )
        .unwrap();
        (out, digest)
    }

    #[test]
    fn single_image_layouts_import_without_a_digest() {
        let tmp = temp_dir();
        let (layout, digest) = packed(&tmp, "one", "1");
        let store = BlobStore::new(tmp.path().join("blobs"));
        let resolved = import_layout(&store, &layout, None).unwrap();
        assert_eq!(resolved.manifest_digest, digest);
        assert_eq!(
            resolved.pinned,
            format!("oci-layout:{}@{digest}", layout.display())
        );
        let image = Image::open(&store, &digest).unwrap();
        assert_eq!(image.layers.len(), 1);
        // The store no longer needs the layout.
        fs::remove_dir_all(&layout).unwrap();
        Image::open(&store, &digest).unwrap();
        assert!(store.has(&image.layers[0]));
    }

    /// Merges the `index.json` of `b` into `a`, and copies b's blobs.
    fn merge_layouts(a: &Path, b: &Path) {
        for e in fs::read_dir(b.join("blobs/sha256")).unwrap() {
            let e = e.unwrap();
            fs::copy(e.path(), a.join("blobs/sha256").join(e.file_name())).unwrap();
        }
        let mut ia: Value =
            serde_json::from_slice(&fs::read(a.join("index.json")).unwrap()).unwrap();
        let ib: Value = serde_json::from_slice(&fs::read(b.join("index.json")).unwrap()).unwrap();
        ia["manifests"]
            .as_array_mut()
            .unwrap()
            .push(ib["manifests"][0].clone());
        fs::write(a.join("index.json"), serde_json::to_vec(&ia).unwrap()).unwrap();
    }

    #[test]
    fn multi_image_layouts_import_by_digest() {
        let tmp = temp_dir();
        let (a, da) = packed(&tmp, "a", "A");
        let (b, db) = packed(&tmp, "b", "B");
        merge_layouts(&a, &b);
        let store = BlobStore::new(tmp.path().join("blobs"));
        let err = import_layout(&store, &a, None).unwrap_err();
        assert!(err.to_string().contains("holds 2 images"), "{err}");
        let resolved = import_layout(&store, &a, Some(&db)).unwrap();
        assert_eq!(resolved.manifest_digest, db);
        assert_eq!(Image::open(&store, &db).unwrap().manifest_digest, db);
        assert!(Image::open(&store, &da).is_err());
        let missing = sha256_digest(b"missing");
        let err = import_layout(&store, &a, Some(&missing)).unwrap_err();
        assert!(err.to_string().contains("does not list"), "{err}");
        // oci-layout:<dir>:<ref name> picks by the ref name annotation.
        let resolved = import_layout_named(&store, &a, None, Some("a")).unwrap();
        assert_eq!(resolved.manifest_digest, da);
        assert!(
            resolved.pinned.ends_with(&format!("@{da}")),
            "{}",
            resolved.pinned
        );
        let err = import_layout_named(&store, &a, None, Some("c")).unwrap_err();
        assert!(err.to_string().contains("no image named"), "{err}");
    }

    #[test]
    fn tampered_layout_blobs_are_not_imported() {
        let tmp = temp_dir();
        let (layout, digest) = packed(&tmp, "t", "content");
        let store = BlobStore::new(tmp.path().join("blobs"));
        // Tamper with the layer: the largest blob is the gzip layer here,
        // so find it through the manifest.
        let manifest: Value = serde_json::from_slice(
            &fs::read(layout.join("blobs/sha256").join(&digest[7..])).unwrap(),
        )
        .unwrap();
        let layer = manifest["layers"][0]["digest"].as_str().unwrap();
        let path = layout.join("blobs/sha256").join(&layer[7..]);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0);
        fs::write(&path, bytes).unwrap();
        let err = import_layout(&store, &layout, None).unwrap_err();
        assert!(matches!(err, ImageError::Invalid(_)), "{err}");
        assert!(!store.has(&Descriptor {
            media_type: String::new(),
            digest: layer.to_string(),
            size: 0,
        }));
        let left: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// A blob fetch whose future is dropped (`pull_timeout`, an add whose
    /// request went away) leaves no temporary file behind.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // a test without an Env: tokio's timer
    async fn a_dropped_blob_fetch_leaves_no_temporary_file() {
        let tmp = temp_dir();
        let store = BlobStore::new(tmp.path().join("blobs"));
        // A registry that accepts connections and never answers.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let registry = listener.local_addr().unwrap().to_string();
        std::thread::Builder::new()
            .spawn(move || {
                let held: Vec<_> = listener.incoming().collect();
                drop(held);
            })
            .unwrap();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![registry.clone()]),
            platform_resolver: None,
            ..ClientConfig::default()
        });
        let digest = sha256_digest(b"never sent");
        let desc = Descriptor {
            media_type: String::new(),
            digest: digest.clone(),
            size: 10,
        };
        let reference = Reference::with_digest(registry, "x".into(), digest);
        let fetch = blob(&client, &store, &reference, &desc);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), fetch)
                .await
                .is_err(),
            "the registry never answers"
        );
        let left: Vec<_> = fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn tampered_layout_manifests_are_rejected() {
        let tmp = temp_dir();
        let (layout, digest) = packed(&tmp, "m", "content");
        let path = layout.join("blobs/sha256").join(&digest[7..]);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let store = BlobStore::new(tmp.path().join("blobs"));
        let err = import_layout(&store, &layout, None).unwrap_err();
        assert!(err.to_string().contains("descriptor says"), "{err}");
    }

    /// Manual smoke test against a registry, e.g. a local `registry:2`:
    /// `KM7_PULL=127.0.0.1:5000/echo@sha256:... KM7_INSECURE=127.0.0.1:5000
    /// cargo test -p kronik-foreign pull_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs network and a registry; see the doc comment"]
    fn pull_smoke() {
        let reference = std::env::var("KM7_PULL").unwrap();
        let insecure: Vec<String> = std::env::var("KM7_INSECURE")
            .map(|s| s.split(',').map(String::from).collect())
            .unwrap_or_default();
        let ImageRef::Registry {
            registry,
            repository,
            digest,
        } = ImageRef::parse(&reference).unwrap()
        else {
            panic!("not a registry reference");
        };
        let tmp = temp_dir();
        let store = BlobStore::new(tmp.path().join("blobs"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let options = FetchOptions {
            insecure_registries: insecure,
            max_new_bytes: None,
        };
        let resolved = rt
            .block_on(pull(&store, &registry, &repository, &digest, &options))
            .unwrap();
        eprintln!("resolved: {resolved:?}");
        assert_eq!(resolved.manifest_digest, digest);
        let image = Image::open(&store, &digest).unwrap();
        eprintln!(
            "platform manifest {} with {} layers",
            image.manifest_digest,
            image.layers.len()
        );
        // A second pull is served from the store.
        let again = rt
            .block_on(pull(&store, &registry, &repository, &digest, &options))
            .unwrap();
        assert_eq!(again, resolved);
        let rootfs = tmp.path().join("rootfs");
        let stats = crate::oci::unpack(
            &store,
            &image,
            &rootfs,
            &crate::oci::UnpackLimits {
                preserve_owners: false,
                ..Default::default()
            },
        )
        .unwrap();
        eprintln!("unpacked: {stats:?}");
    }
}
