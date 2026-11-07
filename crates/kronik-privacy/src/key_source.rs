//! M23 B1: one key source for runtime and offline readers. Only ciphertext
//! is persisted for KMS sources; the loaded key is shared with shipping.

pub mod config;
mod ownership;
mod pkcs11;
pub(crate) mod providers;
pub use ownership::DataOwnership;

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use kronik_core::env::Env;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::owned_tree::{self, Ancestors, Dir};
use crate::{MasterKey, PrivacyError, encrypted_stores};
pub use config::{Keys, Source};

const SCHEMA: &str = "kronik.wrapped-key/v1";
const PURPOSE: &str = "kronik master v1";
/// The largest wrapped-key envelope that is read.
pub const MAX_ENVELOPE: u64 = 65_536;
pub const SOURCE_MARKER: &str = "key-source.json";

#[derive(Debug, thiserror::Error)]
pub enum KeySourceError {
    #[error("invalid key source configuration: {0}")]
    Config(String),
    #[error("KEY_SOURCE_UNAVAILABLE: the configured key source did not answer successfully")]
    Unavailable,
    #[error("KEY_HELPER_FAILED: PKCS#11 helper returned {0}")]
    Pkcs11(String),
    #[error(
        "UNAVAILABLE: the data directory is owned by serve, restore or keys wrap; stop the owning process or choose a different --data-dir"
    )]
    DataInUse,
    #[error(
        "invalid wrapped master key: source, key, purpose or format differs from configuration"
    )]
    InvalidEnvelope,
    #[error(transparent)]
    Key(#[from] PrivacyError),
    #[error("key source I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl KeySourceError {
    pub fn api_error(self) -> kronik_core::error::ApiError {
        use kronik_core::error::{ApiError, ErrorCode};
        let code = match &self {
            Self::Config(_) => ErrorCode::BadRequest,
            Self::Unavailable => ErrorCode::KeySourceUnavailable,
            Self::Pkcs11(_) => ErrorCode::KeyHelperFailed,
            Self::InvalidEnvelope => ErrorCode::MasterKeyMismatch,
            Self::Key(PrivacyError::KeyMissing(_)) => ErrorCode::MasterKeyMissing,
            Self::Key(PrivacyError::KeyMismatch(_)) => ErrorCode::MasterKeyMismatch,
            Self::Key(PrivacyError::KeyProtection) => ErrorCode::KeyProtectionUnavailable,
            Self::Key(_) => ErrorCode::StorageCorrupt,
            Self::DataInUse => ErrorCode::Unavailable,
            Self::Io(_) => ErrorCode::Internal,
        };
        let error = ApiError::new(code, self.to_string());
        if matches!(self, Self::DataInUse) {
            error.with_hint(
                "Stop the owning daemon or offline operation, or choose a different --data-dir.",
            )
        } else {
            error
        }
    }
}

/// No endpoint or credential is read from this untrusted document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrapped {
    pub schema: String,
    pub source: String,
    pub key: String,
    pub key_version: String,
    pub ciphertext: String,
    pub aad: String,
    pub created_wall_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeyStatus {
    pub source: String,
    pub key: Option<String>,
    pub key_version: Option<String>,
    pub check_ok: bool,
}

pub struct KeySource {
    env: Env,
    config: Keys,
    data: PathBuf,
    master: MasterKey,
    wrapped: RwLock<Option<Wrapped>>,
    change: tokio::sync::Mutex<()>,
}

/// No key-loading command may write a core dump. This also covers offline
/// restore, audit verification, upgrade check, wrap and init.
pub fn protect_process() -> Result<(), KeySourceError> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| PrivacyError::KeyProtection)?;
    Ok(())
}

impl Keys {
    pub fn key_path(&self, data: &Path) -> PathBuf {
        self.master_key_file
            .clone()
            .unwrap_or_else(|| data.join("keys/master.key"))
    }

    pub fn envelope_path(&self, data: &Path) -> Result<PathBuf, KeySourceError> {
        if self.wrapped_file.as_os_str().is_empty()
            || self
                .wrapped_file
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(KeySourceError::Config(
                "wrapped_file must be a relative path without . or ..".into(),
            ));
        }
        Ok(data.join(&self.wrapped_file))
    }

    pub fn check_environment(&self) -> Result<(), KeySourceError> {
        self.check().map_err(KeySourceError::Config)?;
        let material = std::env::var_os(crate::MASTER_KEY_ENV).is_some();
        if material && (self.master_key_file.is_some() || self.source.is_kms()) {
            return Err(KeySourceError::Config(
                "KRONIK_MASTER_KEY conflicts with the configured key file or KMS source".into(),
            ));
        }
        if self.source == Source::Env && !material {
            return Err(KeySourceError::Key(PrivacyError::KeyMissing(
                "KRONIK_MASTER_KEY is not set for source env".into(),
            )));
        }
        Ok(())
    }
}

impl Wrapped {
    pub fn parse(bytes: &[u8], config: &Keys) -> Result<Self, KeySourceError> {
        if bytes.len() as u64 > MAX_ENVELOPE {
            return Err(KeySourceError::InvalidEnvelope);
        }
        let w: Wrapped =
            serde_json::from_slice(bytes).map_err(|_| KeySourceError::InvalidEnvelope)?;
        if w.schema != SCHEMA
            || w.source != config.source.as_str()
            || w.key != config.key_ref().map_err(KeySourceError::Config)?
            || w.aad != PURPOSE
            || w.ciphertext.is_empty()
            || w.key_version.is_empty()
        {
            return Err(KeySourceError::InvalidEnvelope);
        }
        providers::validate_wrapped(config, &w).map_err(|_| KeySourceError::InvalidEnvelope)?;
        Ok(w)
    }

    pub fn bytes(&self) -> Result<Vec<u8>, KeySourceError> {
        serde_json::to_vec(self).map_err(|_| KeySourceError::InvalidEnvelope)
    }
}

impl KeySource {
    pub async fn load(
        env: Env,
        mut config: Keys,
        data: &Path,
        create: bool,
    ) -> Result<Arc<Self>, KeySourceError> {
        protect_process()?;
        config.check_environment()?;
        let deadline = operation_deadline(&env, &config)?;
        if config.source == Source::File && std::env::var_os(crate::MASTER_KEY_ENV).is_some() {
            config.source = Source::Env;
        }
        let keys = data.join("keys");
        let (master, wrapped) = if config.source.is_kms() {
            let path = config.envelope_path(data)?;
            match read_envelope_in(data, &path) {
                Ok(bytes) => {
                    let wrapped = Wrapped::parse(&bytes, &config)?;
                    let master = unwrap_retry(&env, &config, &wrapped, deadline).await?;
                    if create {
                        master.validate_stores(&keys)?;
                    } else {
                        validate_staged_stores(&master, &keys)?;
                    }
                    (master, Some(wrapped))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !create || encrypted_stores(&keys)? {
                        return Err(PrivacyError::KeyMissing("the wrapped master key is missing; no key is generated over encrypted stores".into()).into());
                    }
                    let master = MasterKey::from_bytes(env.random_bytes::<32>())?;
                    let wrapped = encrypt_retry(&env, &config, &master, deadline).await?;
                    let check = unwrap_retry(&env, &config, &wrapped, deadline).await?;
                    if !master.same_key(&check) {
                        return Err(KeySourceError::InvalidEnvelope);
                    }
                    let bytes = wrapped.bytes()?;
                    // Creation never replaces a file that appeared meanwhile.
                    write_envelope_in(&env, data, &path, &bytes, false)?;
                    (master, Some(wrapped))
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            let fresh = create.then(|| env.random_bytes::<32>());
            let (master, _) = MasterKey::open(&config.key_path(data), &keys, fresh)?;
            if create {
                master.validate_stores(&keys)?;
            } else {
                validate_staged_stores(&master, &keys)?;
            }
            (master, None)
        };
        Ok(Arc::new(Self {
            env,
            config,
            data: data.to_path_buf(),
            master,
            wrapped: RwLock::new(wrapped),
            change: tokio::sync::Mutex::new(()),
        }))
    }

    pub fn master(&self) -> &MasterKey {
        &self.master
    }
    pub fn config(&self) -> &Keys {
        &self.config
    }

    pub fn status(&self) -> KeyStatus {
        let w = self.wrapped.read().unwrap_or_else(|e| e.into_inner());
        KeyStatus {
            source: self.config.source.as_str().into(),
            key: w.as_ref().map(|w| w.key.clone()),
            key_version: w.as_ref().map(|w| w.key_version.clone()),
            check_ok: true,
        }
    }

    /// Ciphertext only; shipping requires no provider access after startup.
    pub fn wrapped_bytes(&self) -> Result<Option<Vec<u8>>, KeySourceError> {
        self.wrapped
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Wrapped::bytes)
            .transpose()
    }

    /// The API writes the audited intent before calling this mutation.
    pub async fn rewrap(&self, dry_run: bool) -> Result<KeyStatus, KeySourceError> {
        if !self.config.source.is_kms() {
            return Err(KeySourceError::Config(
                "rewrap requires a KMS source; migrate with keys wrap first".into(),
            ));
        }
        let _guard = self.change.lock().await;
        let deadline = operation_deadline(&self.env, &self.config)?;
        // A changed/replaced envelope cannot be overwritten under another seed.
        let bytes = read_envelope(&self.config.envelope_path(&self.data)?)?;
        let prior = Wrapped::parse(&bytes, &self.config)?;
        let check = unwrap_retry(&self.env, &self.config, &prior, deadline).await?;
        if !check.same_key(&self.master) {
            return Err(PrivacyError::KeyMismatch(
                "the wrapped key differs from the running node's master key".into(),
            )
            .into());
        }
        self.master.validate_stores(&self.data.join("keys"))?;
        let next = encrypt_retry(&self.env, &self.config, &self.master, deadline).await?;
        // Verify the provider's answer before replacing the only local envelope.
        let check = unwrap_retry(&self.env, &self.config, &next, deadline).await?;
        if !check.same_key(&self.master) {
            return Err(KeySourceError::InvalidEnvelope);
        }
        let status = KeyStatus {
            source: next.source.clone(),
            key: Some(next.key.clone()),
            key_version: Some(next.key_version.clone()),
            check_ok: true,
        };
        if !dry_run {
            write_envelope(
                &self.env,
                &self.config.envelope_path(&self.data)?,
                &next.bytes()?,
                true,
            )?;
            *self.wrapped.write().unwrap_or_else(|e| e.into_inner()) = Some(next);
        }
        Ok(status)
    }
}

/// Produce a non-secret key-possession probe without loading or changing a seed.
pub async fn enroll_pkcs11(env: &Env, config: &Keys) -> Result<config::Probe, KeySourceError> {
    protect_process()?;
    config
        .check_pkcs11_enrollment()
        .map_err(KeySourceError::Config)?;
    if !cfg!(target_os = "linux") {
        return Err(KeySourceError::Config("PKCS11_UNSUPPORTED_PLATFORM".into()));
    }
    pkcs11::enroll(
        env,
        config
            .pkcs11
            .as_ref()
            .ok_or_else(|| KeySourceError::Config("PKCS11_CONFIG".into()))?,
    )
    .await
    .map_err(KeySourceError::Pkcs11)
}

pub async fn unwrap_envelope(
    env: &Env,
    config: &Keys,
    bytes: &[u8],
) -> Result<MasterKey, KeySourceError> {
    protect_process()?;
    config.check_environment()?;
    let wrapped = Wrapped::parse(bytes, config)?;
    unwrap_retry(env, config, &wrapped, operation_deadline(env, config)?).await
}

/// Offline migration: target configuration is already set to the chosen KMS.
/// Old file/env material is read separately and never deleted by default.
pub async fn wrap_existing(
    env: &Env,
    config: &Keys,
    data: &Path,
    old_file: &Path,
    remove_file: bool,
    reason: impl FnOnce(&MasterKey, &Path) -> String,
    dry_run: bool,
) -> Result<KeyStatus, KeySourceError> {
    wrap_existing_as(
        Caller::this_process(),
        env,
        config,
        data,
        old_file,
        remove_file,
        reason,
        dry_run,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn wrap_existing_as(
    who: Caller,
    env: &Env,
    config: &Keys,
    data: &Path,
    old_file: &Path,
    remove_file: bool,
    reason: impl FnOnce(&MasterKey, &Path) -> String,
    dry_run: bool,
) -> Result<KeyStatus, KeySourceError> {
    let _ownership = lock_data(data)?;
    protect_process()?;
    config.check().map_err(KeySourceError::Config)?;
    if !config.source.is_kms() {
        return Err(KeySourceError::Config("wrap needs a KMS source".into()));
    }
    let path = config.envelope_path(data)?;
    match exists_as(data, &path, who) {
        Ok(true) => {
            return Err(KeySourceError::Config(
                "a wrapped key already exists; use keys rewrap".into(),
            ));
        }
        Ok(false) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // An old key file inside the service's tree is not read through a link or
    // a special file that the service user put in its place.
    let master = read_old_key_as(data, old_file, who)?;
    let stage = stage_stores_as(&data.join("keys"), who)?;
    master.validate_stores(stage.path())?;
    let deadline = operation_deadline(env, config)?;
    let wrapped = encrypt_retry(env, config, &master, deadline).await?;
    let check = unwrap_retry(env, config, &wrapped, deadline).await?;
    if !master.same_key(&check) {
        return Err(KeySourceError::InvalidEnvelope);
    }
    let status = KeyStatus {
        source: wrapped.source.clone(),
        key: Some(wrapped.key.clone()),
        key_version: Some(wrapped.key_version.clone()),
        check_ok: true,
    };
    if !dry_run {
        // Marker first: a crash can over-report an attempted source change but
        // cannot hide one. No seed or credential enters this document.
        let bytes = wrapped.bytes()?;
        let marker = serde_json::json!({"source":wrapped.source,"key":wrapped.key,
            "id":blake3::hash(&bytes).to_hex().to_string(),
            "reason":reason(&master, stage.path()),"wall_ms":env.clock.wall_ms()});
        write_envelope_as(
            env,
            data,
            &data.join("keys").join(SOURCE_MARKER),
            &serde_json::to_vec(&marker).map_err(|_| KeySourceError::InvalidEnvelope)?,
            true,
            who,
        )?;
        write_envelope_as(env, data, &path, &bytes, false, who)?;
        if remove_file && std::env::var_os(crate::MASTER_KEY_ENV).is_none() {
            remove_key_file(data, old_file, who).map_err(|e| removal_failed(old_file, &e))?;
        }
    }
    Ok(status)
}

/// The old key of `keys wrap`. A file in the tree of another user is read by
/// name through descriptors: it must be a regular file with one link, and a
/// link planted for it (or for `keys`) is an error and never followed. A file
/// outside the data directory is the operator's and is read by path, as is
/// everything in the caller's own tree. `KRONIK_MASTER_KEY` wins over a file,
/// as it does for [`MasterKey::open`].
fn read_old_key_as(data: &Path, old_file: &Path, who: Caller) -> Result<MasterKey, KeySourceError> {
    let keys = data.join("keys");
    if std::env::var_os(crate::MASTER_KEY_ENV).is_some() {
        return Ok(MasterKey::open(old_file, &keys, None)?.0);
    }
    match reach(data, old_file, who)? {
        Reach::Path => Ok(MasterKey::open(old_file, &keys, None)?.0),
        Reach::Name(dir, name) => {
            let bytes = match dir.read_regular(&name, 4096) {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(PrivacyError::KeyMissing(format!(
                        "no master key: {} does not exist and KRONIK_MASTER_KEY is not set",
                        old_file.display()
                    ))
                    .into());
                }
                Err(e) => return Err(e.into()),
            };
            let source = format!("file {}", old_file.display());
            let text =
                std::str::from_utf8(&bytes).map_err(|_| PrivacyError::BadKey(source.clone()))?;
            Ok(MasterKey::from_hex(text, source)?)
        }
    }
}

/// The old key file is removed last, after the wrapped key and the source marker
/// are written, so a failure to remove it is a failure of a wrap that is done: say
/// so, because running the command again would only answer that a wrapped key
/// exists.
fn removal_failed(old_file: &Path, why: &std::io::Error) -> KeySourceError {
    KeySourceError::Config(format!(
        "the master key is wrapped (the wrapped key and the source marker are written), but the old key file {} could not be removed: {why}. Check the wrapped key (`kronik keys status` once the service runs), then remove the old file by hand; running `keys wrap` again would only say that a wrapped key exists",
        old_file.display()
    ))
}

/// Removes the old key file (and flushes its directory): by name when it lies
/// in the tree of another user, where a link in its place is removed and not
/// followed; by path when it is the operator's file outside the data
/// directory. Whether it is one or the other is decided by [`reach`], and a
/// failure to reach it is a failure to remove it: with `keys` swapped for a link
/// to another directory, this must not delete the `master.key` that lies there.
fn remove_key_file(data: &Path, old_file: &Path, who: Caller) -> std::io::Result<()> {
    match reach(data, old_file, who)? {
        Reach::Name(dir, name) => {
            dir.unlink(&name)?;
            dir.sync()
        }
        Reach::Path => {
            std::fs::remove_file(old_file)?;
            if let Some(parent) = old_file.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
    }
}

/// Offline validation must not create SQLite WAL sidecars in the source.
pub fn validate_staged_stores(master: &MasterKey, keys: &Path) -> Result<(), KeySourceError> {
    let stage = stage_stores(keys)?;
    master.validate_stores(stage.path())?;
    Ok(())
}

/// The largest store file that is staged.
const MAX_STORE: u64 = 1 << 36;

/// How a process reaches a file below a data directory. A privileged process
/// that works in the tree of the nonroot service must not follow what is in
/// it: the service user can swap any entry for a symbolic link, a FIFO, a
/// socket or a hard link, and `keys` is the entry that matters. So when the
/// data directory belongs to another user than the one the process runs as,
/// every file below it is reached by name through descriptors
/// ([`owned_tree`]); in the process's own tree (the daemon's, or a root
/// installation's, where only root can have made a link) paths work as they
/// always did.
enum Reach {
    Path,
    Name(Dir, OsString),
}

/// Who reaches into a data directory, and what the directories on the way to
/// it must be. In production it is this process, and the directories must
/// belong to root or to it with no write access for anyone else; the tests
/// play other users with other numbers.
#[derive(Clone, Copy)]
struct Caller {
    euid: u32,
    ancestors: Ancestors,
}

impl Caller {
    fn this_process() -> Caller {
        let euid = rustix::process::geteuid().as_raw();
        Caller {
            euid,
            ancestors: Ancestors::ControlledBy(euid),
        }
    }
}

/// How `path` is reached. A path that is not below `data` is the operator's own
/// file (the old key of `keys wrap` from `--master-key-file`) and is reached by
/// path: that is decided by its spelling alone, before anything is opened, so
/// that nothing the service user can change decides which way a file is
/// reached. (A spelling with `..` cannot be told apart from one below `data`
/// without following links, so in another user's tree it is refused.) A path
/// below `data` is reached by name when the tree belongs to another user, and
/// every failure on the way, a refused link first of all, is an error: no
/// caller may go on by path after one.
fn reach(data: &Path, path: &Path, who: Caller) -> std::io::Result<Reach> {
    let Ok(relative) = path.strip_prefix(data) else {
        if path.components().any(|c| matches!(c, Component::ParentDir))
            && Dir::open(data)?.belongs_to_another_than(who.euid)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{} has a `..` in it; name the file without it, so that it is not mistaken for one outside {}",
                    path.display(),
                    data.display()
                ),
            ));
        }
        return Ok(Reach::Path);
    };
    if !Dir::open(data)?.belongs_to_another_than(who.euid)? {
        return Ok(Reach::Path);
    }
    // Another user's tree. The open above followed the links of the data
    // directory's own path; this one starts at `/`, follows none, and passes
    // only directories that root and the caller can change.
    let anchor = Dir::open_absolute(data, who.ancestors, None).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "{e}. This data directory belongs to another user, and root reaches into such a directory only through directories that root alone can change: run the command as the user who owns it, or give the data directory a path that root controls"
            ),
        )
    })?;
    let name = relative
        .file_name()
        .ok_or_else(|| {
            std::io::Error::other(format!("{} is the data directory itself", path.display()))
        })?
        .to_owned();
    let parent = anchor.open_below(
        relative.parent().unwrap_or(Path::new("")),
        Ancestors::Any,
        None,
    )?;
    Ok(Reach::Name(parent, name))
}

/// [`read_envelope`] of a file below `data`, safe in the nonroot service's tree.
pub fn read_envelope_in(data: &Path, path: &Path) -> std::io::Result<Vec<u8>> {
    read_envelope_as(data, path, Caller::this_process())
}

fn read_envelope_as(data: &Path, path: &Path, who: Caller) -> std::io::Result<Vec<u8>> {
    match reach(data, path, who)? {
        Reach::Path => read_envelope(path),
        Reach::Name(dir, name) => dir.read_regular(&name, MAX_ENVELOPE),
    }
}

/// Whether `path` below `data` exists (a link counts as existing), safe in the
/// nonroot service's tree.
pub fn exists_in(data: &Path, path: &Path) -> std::io::Result<bool> {
    exists_as(data, path, Caller::this_process())
}

fn exists_as(data: &Path, path: &Path, who: Caller) -> std::io::Result<bool> {
    match reach(data, path, who)? {
        Reach::Path => path.try_exists(),
        Reach::Name(dir, name) => Ok(dir.entry(&name)?.is_some()),
    }
}

/// [`write_envelope`] for a file below `data`. In the nonroot service's tree
/// the file is made by name in the directory that holds it (which must exist),
/// given to that directory's owner before it appears, and never written
/// through a link.
pub fn write_envelope_in(
    env: &Env,
    data: &Path,
    path: &Path,
    bytes: &[u8],
    replace: bool,
) -> std::io::Result<()> {
    write_envelope_as(env, data, path, bytes, replace, Caller::this_process())
}

fn write_envelope_as(
    env: &Env,
    data: &Path,
    path: &Path,
    bytes: &[u8],
    replace: bool,
    who: Caller,
) -> std::io::Result<()> {
    let (dir, name) = match reach(data, path, who)? {
        Reach::Path => return write_envelope(env, path, bytes, replace),
        Reach::Name(dir, name) => (dir, name),
    };
    let owner = dir.stat()?;
    let temp = OsString::from(format!(
        ".wrapped-{}",
        crate::hex(&env.random_bytes::<16>())
    ));
    let result = (|| {
        let mut file = dir.create_file(&temp, 0o600)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        owned_tree::chown_file(&file, owner.uid, owner.gid)?;
        if replace {
            dir.rename(&temp, &name)?;
        } else {
            dir.link(&temp, &name)?;
            dir.unlink(&temp)?;
        }
        dir.sync()
    })();
    let _ = dir.unlink(&temp);
    result
}

fn stage_stores(keys: &Path) -> Result<tempfile::TempDir, KeySourceError> {
    stage_stores_as(keys, Caller::this_process())
}

fn stage_stores_as(keys: &Path, who: Caller) -> Result<tempfile::TempDir, KeySourceError> {
    // Copies of a service's databases, kept private to the caller.
    let stage = tempfile::Builder::new()
        .prefix("kronik-stores-")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()?;
    let data = keys.parent().unwrap_or(Path::new("/"));
    for file in [
        "secrets.db",
        "secrets.db-wal",
        "keystore.db",
        "keystore.db-wal",
    ] {
        // A data directory or `keys` that is not there holds no stores.
        let copied = reach(data, &keys.join(file), who).and_then(|reached| match reached {
            Reach::Path => std::fs::copy(keys.join(file), stage.path().join(file)).map(drop),
            Reach::Name(dir, name) => std::fs::File::create_new(stage.path().join(file))
                .and_then(|mut to| dir.copy_regular(&name, &mut to, MAX_STORE))
                .map(drop),
        });
        match copied {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A store that is not there is not staged; a copy that was
                // begun for it is not left behind.
                let _ = std::fs::remove_file(stage.path().join(file));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(stage)
}

pub fn read_envelope(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_ENVELOPE {
        return Err(std::io::Error::other("wrapped key exceeds size limit"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ENVELOPE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ENVELOPE {
        return Err(std::io::Error::other("wrapped key exceeds size limit"));
    }
    Ok(bytes)
}
/// Lock the data directory itself, not a sibling (systemd only permits
/// writes inside it). Directory descriptors keep the same lock inode.
pub fn lock_data(data: &Path) -> Result<DataOwnership, KeySourceError> {
    use std::os::unix::fs::MetadataExt as _;
    let file = std::fs::File::open(data)?;
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => KeySourceError::DataInUse,
        std::fs::TryLockError::Error(e) => KeySourceError::Io(e),
    })?;
    let held = file.metadata()?;
    let named = std::fs::metadata(data)?;
    if !held.is_dir() || (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(std::io::Error::other(
            "the data directory changed while its lock was acquired",
        )
        .into());
    }
    Ok(DataOwnership::locked(file, data.to_owned()))
}

/// Durable private ciphertext/marker installation. Creation uses a hard link
/// to avoid replacing another process's concurrent first key.
pub fn write_envelope(env: &Env, path: &Path, bytes: &[u8], replace: bool) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("wrapped key has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let suffix = crate::hex(&env.random_bytes::<16>());
    let temp = parent.join(format!(".wrapped-{suffix}"));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            std::fs::rename(&temp, path)?;
        } else {
            std::fs::hard_link(&temp, path)?;
            std::fs::remove_file(&temp)?;
        }
        std::fs::File::open(parent)?.sync_all()
    })();
    let _ = std::fs::remove_file(temp);
    result
}

fn operation_deadline(env: &Env, config: &Keys) -> Result<Duration, KeySourceError> {
    Ok(env
        .clock
        .monotonic()
        .saturating_add(config.start_timeout().map_err(KeySourceError::Config)?))
}

async fn encrypt_retry(
    env: &Env,
    config: &Keys,
    master: &MasterKey,
    deadline: Duration,
) -> Result<Wrapped, KeySourceError> {
    let left = deadline.saturating_sub(env.clock.monotonic());
    if left.is_zero() {
        return Err(KeySourceError::Unavailable);
    }
    env.timeout(left, providers::preflight(env, config))
        .await
        .map_err(|_| KeySourceError::Unavailable)?
        .map_err(KeySourceError::Config)?;
    let mut delay = Duration::from_millis(100);
    loop {
        let left = deadline.saturating_sub(env.clock.monotonic());
        if left.is_zero() {
            return Err(KeySourceError::Unavailable);
        }
        match env
            .timeout(
                left,
                providers::encrypt(env, config, master.bytes(), PURPOSE.as_bytes()),
            )
            .await
        {
            Ok(Ok(w)) => {
                Wrapped::parse(&w.bytes()?, config)?;
                return Ok(w);
            }
            Ok(Err(code)) if config.source == Source::Pkcs11 => {
                return Err(KeySourceError::Pkcs11(code));
            }
            _ if config.source == Source::Pkcs11 => return Err(KeySourceError::Unavailable),
            _ if env.clock.monotonic() < deadline => {
                env.clock
                    .sleep(delay.min(deadline.saturating_sub(env.clock.monotonic())))
                    .await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            _ => return Err(KeySourceError::Unavailable),
        }
    }
}

async fn unwrap_retry(
    env: &Env,
    config: &Keys,
    wrapped: &Wrapped,
    deadline: Duration,
) -> Result<MasterKey, KeySourceError> {
    let left = deadline.saturating_sub(env.clock.monotonic());
    if left.is_zero() {
        return Err(KeySourceError::Unavailable);
    }
    env.timeout(left, providers::preflight(env, config))
        .await
        .map_err(|_| KeySourceError::Unavailable)?
        .map_err(KeySourceError::Config)?;
    let mut delay = Duration::from_millis(100);
    loop {
        let left = deadline.saturating_sub(env.clock.monotonic());
        if left.is_zero() {
            return Err(KeySourceError::Unavailable);
        }
        match env
            .timeout(left, providers::decrypt(env, config, wrapped))
            .await
        {
            Ok(Ok(mut bytes)) => {
                let mut seed = Zeroizing::new([0u8; 32]);
                if bytes.len() != seed.len() {
                    return Err(KeySourceError::InvalidEnvelope);
                }
                seed.copy_from_slice(&bytes);
                bytes.zeroize();
                return MasterKey::from_bytes(*seed).map_err(Into::into);
            }
            Ok(Err(code)) if config.source == Source::Pkcs11 => {
                return Err(KeySourceError::Pkcs11(code));
            }
            _ if config.source == Source::Pkcs11 => return Err(KeySourceError::Unavailable),
            _ if env.clock.monotonic() < deadline => {
                env.clock
                    .sleep(delay.min(deadline.saturating_sub(env.clock.monotonic())))
                    .await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            _ => return Err(KeySourceError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests;
