//! Shipping to and restoring from S3-compatible object storage via
//! `object_store` (docs/design/m6-storage.md §4, §6). Every object but a
//! snapshot's manifest is compressed with zstd.
//!
//! ```text
//! <prefix>/<branch>/segments/<start-lsn>.seg.zst
//! <prefix>/<branch>/snapshots/<lsn>/manifest.json
//! <prefix>/<branch>/snapshots/<lsn>/<file>.zst
//! <prefix>/code/<blake3>.wasm.zst
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::Env;
use kronik_core::ids::Lsn;
use kronik_sched::snapshots::{self, Manifest};
use object_store::path::Path as Key;
use object_store::{ObjectStore, ObjectStoreExt, PutPayload};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ShipError {
    #[error("ship: {0}")]
    Config(String),
    #[error("object storage: {0}")]
    Store(#[from] object_store::Error),
    #[error("ship I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("restore: {0}")]
    Restore(String),
    /// The master key is missing or another key than the keystore
    /// backup's.
    #[error(transparent)]
    Key(kronik_privacy::PrivacyError),
    /// A sealed value in the restored data has no key in the keystore the
    /// bucket can provide.
    #[error("KEYSTORE_INCOMPLETE: {0}")]
    KeystoreIncomplete(String),
}

impl ShipError {
    /// A stable code for logs and statuses. Never the error's text: a store's
    /// error carries its URL and the provider's response body, which can echo
    /// credentials or personal data (m28 review M9).
    pub fn code(&self) -> &'static str {
        use object_store::Error as E;
        match self {
            ShipError::Config(_) => "s3_config",
            ShipError::Io(_) => "io",
            ShipError::Restore(_) => "restore",
            ShipError::Key(_) => "master_key",
            ShipError::KeystoreIncomplete(_) => "keystore_incomplete",
            ShipError::Store(e) => match e {
                E::NotFound { .. } => "s3_not_found",
                E::PermissionDenied { .. } => "s3_forbidden",
                E::Unauthenticated { .. } => "s3_unauthenticated",
                E::Precondition { .. } | E::NotModified { .. } => "s3_precondition",
                E::AlreadyExists { .. } => "s3_conflict",
                _ => "s3",
            },
        }
    }
}

/// zstd level for shipped objects.
const LEVEL: i32 = 3;

/// How often `kronik serve` ships (m6-storage §4).
pub const SHIP_INTERVAL: Duration = Duration::from_secs(10);

/// A bucket (or a local directory, for tests) with a key prefix.
#[derive(Clone)]
pub struct Remote {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl Remote {
    /// `s3://bucket/prefix` (credentials and region from the standard
    /// `AWS_*` environment; `endpoint` for S3-compatible servers, where
    /// `http://` is allowed) or `file:///dir/prefix`.
    pub fn open(url: &str, endpoint: Option<&str>) -> Result<Remote, ShipError> {
        // reqwest's rustls has no bundled provider; ring is the process's
        // (an error means one is installed already).
        let _ = rustls::crypto::ring::default_provider().install_default();
        if let Some(rest) = url.strip_prefix("s3://") {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if bucket.is_empty() {
                return Err(ShipError::Config(format!("no bucket in {url}")));
            }
            let mut b = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(bucket);
            if std::env::var_os("AWS_REGION").is_none()
                && std::env::var_os("AWS_DEFAULT_REGION").is_none()
            {
                b = b.with_region("us-east-1");
            }
            if let Some(e) = endpoint {
                b = b.with_endpoint(e).with_allow_http(e.starts_with("http://"));
            }
            return Ok(Remote {
                store: Arc::new(b.build()?),
                prefix: prefix.trim_matches('/').to_owned(),
            });
        }
        if let Some(path) = url.strip_prefix("file://") {
            std::fs::create_dir_all(path)?;
            let fs = object_store::local::LocalFileSystem::new_with_prefix(path)?;
            return Ok(Remote {
                store: Arc::new(fs),
                prefix: String::new(),
            });
        }
        Err(ShipError::Config(format!(
            "{url}: expected s3://bucket/prefix or file:///path"
        )))
    }

    fn key(&self, rel: &str) -> Key {
        if self.prefix.is_empty() {
            Key::from(rel)
        } else {
            Key::from(format!("{}/{rel}", self.prefix))
        }
    }

    /// Stores `bytes` under `rel` (below the prefix).
    pub async fn put(&self, rel: &str, bytes: Vec<u8>) -> Result<(), ShipError> {
        self.store
            .put(&self.key(rel), PutPayload::from(bytes))
            .await?;
        Ok(())
    }

    /// The object under `rel`.
    pub async fn get(&self, rel: &str) -> Result<Vec<u8>, ShipError> {
        Ok(self
            .store
            .get(&self.key(rel))
            .await?
            .bytes()
            .await?
            .to_vec())
    }

    async fn delete(&self, rel: &str) -> Result<(), ShipError> {
        self.store.delete(&self.key(rel)).await?;
        Ok(())
    }

    /// Object names directly under `rel/` and sub-directory names.
    pub async fn list(&self, rel: &str) -> Result<(Vec<String>, Vec<String>), ShipError> {
        let prefix = self.key(rel);
        let r = self.store.list_with_delimiter(Some(&prefix)).await?;
        let name = |p: &Key| p.filename().unwrap_or_default().to_owned();
        Ok((
            r.objects.iter().map(|o| name(&o.location)).collect(),
            r.common_prefixes.iter().map(name).collect(),
        ))
    }

    /// A cheap check that the bucket is reachable and the credentials work
    /// (`kronik doctor`).
    pub async fn check(&self) -> Result<(), ShipError> {
        self.list("").await.map(|_| ())
    }
}

fn compress(bytes: &[u8]) -> Result<Vec<u8>, ShipError> {
    Ok(zstd::stream::encode_all(bytes, LEVEL)?)
}

fn decompress(bytes: &[u8]) -> Result<Vec<u8>, ShipError> {
    Ok(zstd::stream::decode_all(bytes)?)
}

/// What has been uploaded (`<data>/ship.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShipState {
    /// Closed segments uploaded, by start LSN.
    pub segments: BTreeSet<Lsn>,
    /// The active segment's start and the size last uploaded.
    pub active: Option<(Lsn, u64)>,
    pub snapshots: BTreeSet<Lsn>,
    pub code: BTreeSet<String>,
    /// Wall time of the last uploaded keystore backup.
    #[serde(default)]
    pub keystore_backup_ms: Option<u64>,
    /// mtime/size stamp of `keys/keystore.db` at that backup.
    #[serde(default)]
    pub keystore_stamp: Option<u64>,
}

impl ShipState {
    fn path(data: &Path) -> PathBuf {
        data.join("ship.json")
    }

    pub fn load(data: &Path) -> ShipState {
        std::fs::read(Self::path(data))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, data: &Path) -> Result<(), ShipError> {
        let tmp = Self::path(data).with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap_or_default())?;
        std::fs::rename(tmp, Self::path(data))?;
        Ok(())
    }
}

/// One round's work.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ShipReport {
    pub objects: u64,
    pub bytes: u64,
    pub deleted: u64,
}

/// Uploads what is missing remotely: closed segments (once), the active
/// segment when it grew (so an idle node's last records leave within one
/// round), snapshots (files, then the manifest), components; deletes
/// remote segments and snapshots that retention removed locally.
pub async fn ship_once(
    remote: &Remote,
    data: &Path,
    branch: &str,
    state: &mut ShipState,
) -> Result<ShipReport, ShipError> {
    let mut report = ShipReport::default();
    let log_dir = data.join("branches").join(branch).join("log");
    let starts = kronik_log::segment_starts(&log_dir)?;
    let seg_rel = |s: Lsn| format!("{branch}/segments/{}.zst", kronik_log::segment_name(s));
    for (i, &start) in starts.iter().enumerate() {
        let closed = i + 1 < starts.len();
        let path = log_dir.join(kronik_log::segment_name(start));
        let bytes = std::fs::read(&path)?;
        let dirty = closed && kronik_sched::reupload_ready(data, start, &bytes);
        if closed {
            if state.segments.contains(&start) && !dirty {
                continue;
            }
        } else {
            let size = bytes.len() as u64;
            if state.active == Some((start, size)) {
                continue;
            }
        }
        let size = bytes.len() as u64;
        let z = compress(&bytes)?;
        report.bytes += z.len() as u64;
        report.objects += 1;
        remote.put(&seg_rel(start), z).await?;
        if dirty {
            kronik_sched::clear_reupload(data, start)?;
        }
        if closed {
            state.segments.insert(start);
            if state.active.is_some_and(|(s, _)| s == start) {
                state.active = None;
            }
        } else {
            state.active = Some((start, size));
        }
        state.save(data)?;
    }
    // Retention: segments gone locally go remotely too.
    let first = starts.first().copied().unwrap_or(1);
    let gone: Vec<Lsn> = state
        .segments
        .iter()
        .copied()
        .filter(|s| *s < first)
        .collect();
    for s in gone {
        remote.delete(&seg_rel(s)).await?;
        state.segments.remove(&s);
        report.deleted += 1;
        state.save(data)?;
    }
    // Snapshots: files first, the manifest last.
    let local = snapshots::list(data, branch);
    for (dir, m) in &local {
        if state.snapshots.contains(&m.lsn) {
            continue;
        }
        let base = format!("{branch}/snapshots/{:020}", m.lsn);
        for f in &m.files {
            let bytes = std::fs::read(dir.join(&f.path))?;
            let z = compress(&bytes)?;
            report.bytes += z.len() as u64;
            report.objects += 1;
            remote.put(&format!("{base}/{}.zst", f.path), z).await?;
        }
        let manifest = std::fs::read(dir.join("manifest.json"))?;
        report.bytes += manifest.len() as u64;
        report.objects += 1;
        remote
            .put(&format!("{base}/manifest.json"), manifest)
            .await?;
        state.snapshots.insert(m.lsn);
        state.save(data)?;
    }
    let kept: BTreeSet<Lsn> = local.iter().map(|(_, m)| m.lsn).collect();
    let pruned: Vec<Lsn> = state.snapshots.difference(&kept).copied().collect();
    for lsn in pruned {
        // Manifest first, so a half-deleted snapshot is never complete.
        let base = format!("{branch}/snapshots/{lsn:020}");
        remote.delete(&format!("{base}/manifest.json")).await?;
        let (files, _) = remote.list(&base).await?;
        for f in files {
            remote.delete(&format!("{base}/{f}")).await?;
        }
        state.snapshots.remove(&lsn);
        report.deleted += 1;
        state.save(data)?;
    }
    // Components.
    if let Ok(entries) = std::fs::read_dir(data.join("code")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".wasm") || state.code.contains(&name) {
                continue;
            }
            let z = compress(&std::fs::read(e.path())?)?;
            report.bytes += z.len() as u64;
            report.objects += 1;
            remote.put(&format!("code/{name}.zst"), z).await?;
            state.code.insert(name);
            state.save(data)?;
        }
    }
    Ok(report)
}
/// At most one backup a minute after a keystore change, and one a day
/// even when nothing changed (docs/design/m8-privacy.md §10).
pub const KEYSTORE_BACKUP_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// The daily backup, independent of changes.
pub const KEYSTORE_BACKUP_DAILY: Duration = Duration::from_secs(86_400);

/// A change stamp of the keystore: its file and its WAL, where SQLite
/// writes a new key until the next checkpoint (so the file alone can look
/// unchanged for long after a key was added).
fn keystore_stamp(path: &Path) -> Option<u64> {
    let one = |p: &Path| -> Option<u64> {
        let meta = std::fs::metadata(p).ok()?;
        let nanos = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos() as u64;
        Some(nanos.wrapping_mul(0x9E37_79B9).wrapping_add(meta.len()))
    };
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    let wal = one(Path::new(&wal)).unwrap_or(0);
    Some(one(path)?.wrapping_mul(31).wrapping_add(wal))
}

/// Uploads `keystore/<wall_ms>.bin` (the export bytes, not zstd) and deletes
/// backups older than `retention`. The newest is always kept. The master
/// key is never uploaded.
pub async fn ship_keystore(
    remote: &Remote,
    data: &Path,
    state: &mut ShipState,
    wall_ms: u64,
    retention: Duration,
    nonce: [u8; 24],
    key_path: &Path,
) -> Result<ShipReport, ShipError> {
    let mut report = ShipReport::default();
    let path = data.join("keys").join("keystore.db");
    let stamp = keystore_stamp(&path);
    let since = state.keystore_backup_ms.map(|t| wall_ms.saturating_sub(t));
    let changed = stamp.is_some() && stamp != state.keystore_stamp;
    let interval_ok = since.is_none_or(|s| s >= KEYSTORE_BACKUP_MIN_INTERVAL.as_millis() as u64);
    let daily_due = since.is_some_and(|s| s >= KEYSTORE_BACKUP_DAILY.as_millis() as u64);
    if stamp.is_some() && ((changed && interval_ok) || daily_due) {
        // The daemon's own key, wherever it is configured (never shipped).
        let (master, _) = kronik_privacy::MasterKey::open(key_path, &data.join("keys"), None)
            .map_err(|e| ShipError::Config(e.to_string()))?;
        let ks = kronik_privacy::keystore::Keystore::open_file(&path, &master)
            .map_err(|e| ShipError::Config(e.to_string()))?;
        let blob = ks
            .export_backup(nonce)
            .map_err(|e| ShipError::Config(e.to_string()))?;
        report.bytes += blob.len() as u64;
        report.objects += 1;
        remote.put(&format!("keystore/{wall_ms}.bin"), blob).await?;
        state.keystore_backup_ms = Some(wall_ms);
        state.keystore_stamp = stamp;
        state.save(data)?;
        tracing::info!(wall_ms, "shipped a keystore backup");
    }
    let (names, _) = match remote.list("keystore").await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "could not list keystore backups");
            return Ok(report);
        }
    };
    let mut walls: Vec<u64> = names
        .iter()
        .filter_map(|n| n.strip_suffix(".bin")?.parse().ok())
        .collect();
    walls.sort_unstable();
    let Some(&newest) = walls.last() else {
        return Ok(report);
    };
    let cutoff = wall_ms.saturating_sub(retention.as_millis() as u64);
    for w in walls {
        if w < cutoff && w != newest {
            remote.delete(&format!("keystore/{w}.bin")).await?;
            report.deleted += 1;
        }
    }
    Ok(report)
}

/// Ships every `interval` until the node stops (a task of `kronik serve`
/// when `[ship] enabled`).
pub async fn ship_loop(
    env: Env,
    remote: Remote,
    data: PathBuf,
    branch: String,
    interval: Duration,
    key_path: PathBuf,
) {
    let mut state = ShipState::load(&data);
    loop {
        match ship_once(&remote, &data, &branch, &mut state).await {
            Ok(r) if r.objects + r.deleted > 0 => {
                tracing::info!(
                    objects = r.objects,
                    bytes = r.bytes,
                    deleted = r.deleted,
                    "shipped"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "shipping failed; retrying next round"),
        }
        let mut nonce = [0u8; 24];
        env.entropy.fill(&mut nonce);
        let retention = Duration::from_millis(kronik_sched::keystore_retention_ms(&data));
        match ship_keystore(
            &remote,
            &data,
            &mut state,
            env.clock.wall_ms(),
            retention,
            nonce,
            &key_path,
        )
        .await
        {
            Ok(r) if r.objects + r.deleted > 0 => {
                tracing::info!(
                    objects = r.objects,
                    deleted = r.deleted,
                    "keystore backup round"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "keystore backup failed; retrying next round"),
        }
        env.clock.sleep(interval).await;
    }
}

/// What a restore installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RestoreReport {
    pub snapshot_lsn: Lsn,
    pub snapshot_id: String,
    pub state_hash: String,
    pub segments: usize,
    pub log_first_lsn: Lsn,
    pub components: usize,
    /// Wall time of the keystore backup installed into `keys/keystore.db`.
    /// `None` when the bucket had no backup, or with `--without-keystore`. A backup that is there but can't be
    /// installed fails the restore.
    #[serde(default)]
    pub keystore_backup_ms: Option<u64>,
    /// `installed`, `none_in_bucket`, or `skipped` (`--without-keystore`).
    pub keystore: &'static str,
    /// With `--allow-missing-keys`: the subjects whose sealed values have
    /// no key in the installed keystore and stay unreadable.
    pub keys_missing: Vec<String>,
}

/// `kronik restore` (m6-storage §6): the newest remote snapshot, every
/// remote segment and component into `data`, then the snapshot installed
/// as the branch's state. The daemon must not run on `data`; an existing
/// `state.db` is refused unless `force`.
/// What a restore does with the bucket's privacy keystore backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreMode {
    /// Install the newest backup; refuse when a sealed value's key is
    /// missing from it (`KEYSTORE_INCOMPLETE`).
    Require,
    /// Install the newest backup even when it lacks some keys
    /// (`--allow-missing-keys`): those subjects' sealed values stay
    /// unreadable and are listed; every other subject's stay readable.
    AllowMissingKeys,
    /// Install no backup (`--without-keystore`): every sealed value of
    /// every subject stays unreadable.
    Without,
}

pub async fn restore(
    remote: &Remote,
    data: &Path,
    branch: &str,
    force: bool,
    key_path: &Path,
    mode: KeystoreMode,
) -> Result<RestoreReport, ShipError> {
    restore_with_fault(remote, data, branch, force, key_path, mode, &|_| Ok(())).await
}

/// The file a restore leaves in the branch directory, with the last LSN of
/// the restored log (`through_lsn`): the next `kronik serve` records a
/// system `AuditEvent` `restore` from it, then deletes it (M28 review H4:
/// a restore is a mutation, and LSNs after it repeat ones an audit sink
/// has already seen).
pub const RESTORE_MARKER: &str = "restored.json";

/// [`restore`] that calls `fault` before each step of moving the staged
/// restore into place, and once after (`committed`), so tests can
/// interrupt it there.
#[doc(hidden)]
pub async fn restore_with_fault(
    remote: &Remote,
    data: &Path,
    branch: &str,
    force: bool,
    key_path: &Path,
    mode: KeystoreMode,
    fault: &dyn Fn(&str) -> std::io::Result<()>,
) -> Result<RestoreReport, ShipError> {
    let branch_dir = data.join("branches").join(branch);
    if branch_dir.join("state.db").exists() && !force {
        return Err(ShipError::Restore(format!(
            "{} already holds state; restore into an empty data directory or pass --force",
            data.display()
        )));
    }
    // Everything is downloaded, checked and written in a staging directory
    // first: a restore that fails there leaves the data directory as it was,
    // and moving the result into place is only renames (install_staged).
    let stage = data.join(".restore");
    if stage.exists() {
        std::fs::remove_dir_all(&stage)?;
    }
    // The directories this restore may create, innermost first: a refusal
    // removes them again, so "nothing was written" holds for a destination
    // that did not exist.
    let created: Vec<PathBuf> = std::iter::once(data.join("keys"))
        .chain(data.ancestors().map(Path::to_path_buf))
        .take_while(|d| !d.exists())
        .collect();
    let staged = stage_restore(remote, data, &stage, branch, key_path, mode).await;
    let result = match staged {
        Ok(s) => install_staged(data, &stage, branch, &branch_dir, s, fault),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&stage);
            // Empty only: never anything else that appeared meanwhile.
            for d in &created {
                let _ = std::fs::remove_dir(d);
            }
            Err(e)
        }
    };
    let _ = std::fs::remove_dir_all(&stage);
    result
}

/// What [`stage_restore`] downloaded and checked.
struct Staged {
    m: Manifest,
    segments: Vec<String>,
    components: Vec<String>,
    keystore: &'static str,
    keystore_backup_ms: Option<u64>,
    keys_missing: Vec<String>,
    /// The snapshot at or before a later rebase switch's base (M13).
    older: Option<Manifest>,
    /// The last LSN of the staged log (the snapshot's without a segment).
    through_lsn: Lsn,
}

async fn stage_restore(
    remote: &Remote,
    data: &Path,
    stage: &Path,
    branch: &str,
    key_path: &Path,
    mode: KeystoreMode,
) -> Result<Staged, ShipError> {
    // 1. The newest complete remote snapshot.
    let (_, lsns) = remote.list(&format!("{branch}/snapshots")).await?;
    let mut newest: Option<Manifest> = None;
    let mut all: Vec<Manifest> = Vec::new();
    for l in lsns {
        let Ok(bytes) = remote
            .get(&format!("{branch}/snapshots/{l}/manifest.json"))
            .await
        else {
            continue;
        };
        let Ok(m) = serde_json::from_slice::<Manifest>(&bytes) else {
            continue;
        };
        if newest.as_ref().is_none_or(|n| m.lsn > n.lsn) {
            newest = Some(m.clone());
        }
        all.push(m);
    }
    let m = newest.ok_or_else(|| ShipError::Restore("no snapshot in the bucket".into()))?;
    // The keystore backup is checked before anything is downloaded, so a
    // missing or wrong key fails fast (m8-privacy §10).
    let keystore =
        check_keystore_backup(remote, data, key_path, mode == KeystoreMode::Without).await?;
    let snap = stage.join("snapshot");
    download_snapshot(remote, &snap, branch, &m).await?;
    // 2. Every remote segment, and the subject keys its sealed values need.
    let mut needed = kronik_store::db::SubjectKeys::new();
    let mut erasures: Vec<(String, u32, u64)> = Vec::new();
    let log = stage.join("log");
    std::fs::create_dir_all(&log)?;
    let (names, _) = remote.list(&format!("{branch}/segments")).await?;
    let mut segments = Vec::new();
    let mut through_lsn = m.lsn;
    for n in &names {
        let Some(seg) = n.strip_suffix(".zst") else {
            continue;
        };
        let bytes = decompress(&remote.get(&format!("{branch}/segments/{n}")).await?)?;
        let start: Lsn = seg
            .strip_suffix(".seg")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ShipError::Restore(format!("{n} is not a segment name")))?;
        kronik_log::scan_segment_image(&bytes, branch, start, 0, Lsn::MAX, true, |mut c| {
            through_lsn = through_lsn.max(c.lsn);
            if let kronik_proto::Record::Erasure(e) = &c.record {
                let wall = e.audit.as_ref().map_or(0, |a| a.wall_time_ms);
                erasures.push((e.subject.clone(), e.key_version, wall));
            }
            kronik_proto::sealables::record_mut(
                &mut c.record,
                &mut kronik_store::db::note_sealed(&mut needed),
            );
            Ok::<_, kronik_log::LogError>(())
        })
        .map_err(|e| ShipError::Restore(format!("segment {seg}: {e}")))?;
        std::fs::write(log.join(seg), bytes)?;
        segments.push(seg.to_owned());
    }
    let local = kronik_log::segment_starts(&log)?;
    let first = local.first().copied().unwrap_or(m.lsn + 1);
    if first > m.lsn + 1 {
        return Err(ShipError::Restore(format!(
            "the bucket's log starts at lsn {first}, after the snapshot at {}",
            m.lsn
        )));
    }
    // The snapshot's state: sealed values whose records retention deleted.
    for ((subject, _), sample) in kronik_store::snapshot::sealed_keys(&snap)
        .map_err(|e| ShipError::Restore(format!("the snapshot's state.db: {e}")))?
    {
        kronik_store::db::note_key(&mut needed, &subject, &sample);
    }
    // 3. The keystore: the backup, with the log's erasures applied again,
    //    must hold every key a sealed value needs.
    let allow = mode == KeystoreMode::AllowMissingKeys;
    let subjects_of = |pairs: &[(String, u32)]| {
        let mut s: Vec<String> = pairs.iter().map(|(s, _)| s.clone()).collect();
        s.dedup();
        s
    };
    let (keystore, keystore_backup_ms, keys_missing) = match keystore {
        Ok(k) => {
            let ks = kronik_privacy::keystore::Keystore::import_backup_file(
                &stage.join("keystore.db"),
                &k.master,
                &k.blob,
            )
            .map_err(ShipError::Key)?;
            for (subject, version, wall) in &erasures {
                ks.erase_through(subject, *version, *wall)
                    .map_err(ShipError::Key)?;
            }
            let mut missing = Vec::new();
            for ((subject, version), sample) in &needed {
                if !ks
                    .covers(subject, *version, sample)
                    .map_err(ShipError::Key)?
                {
                    missing.push((subject.clone(), *version));
                }
            }
            if !missing.is_empty() && !allow {
                let shown: Vec<String> = missing
                    .iter()
                    .map(|(s, v)| format!("{s} (key {v})"))
                    .collect();
                return Err(ShipError::KeystoreIncomplete(format!(
                    "the bucket's newest keystore backup ({}) lacks the keys of {}: their sealed \
                     values would be unreadable",
                    k.wall,
                    list_some(&shown)
                )));
            }
            ("installed", Some(k.wall), subjects_of(&missing))
        }
        Err("none_in_bucket") if !needed.is_empty() => {
            let pairs: Vec<(String, u32)> = needed.keys().cloned().collect();
            if !allow {
                let shown: Vec<String> = pairs
                    .iter()
                    .map(|(s, v)| format!("{s} (key {v})"))
                    .collect();
                return Err(ShipError::KeystoreIncomplete(format!(
                    "the restored data holds sealed values of {}, and the bucket has no keystore \
                     backup",
                    list_some(&shown)
                )));
            }
            ("none_in_bucket", None, subjects_of(&pairs))
        }
        Err(status) => (status, None, Vec::new()),
    };
    // A rebase switch after the snapshot whose base is before it: the first
    // start rebuilds the shadow from a snapshot at or before that base
    // (docs/design/m13-rebase.md section 6).
    let older = match rebase_base_after(&log, branch, &local, m.lsn)? {
        Some(base) => all
            .iter()
            .filter(|o| o.lsn <= base)
            .max_by_key(|o| o.lsn)
            .cloned(),
        None => None,
    };
    if let Some(o) = &older {
        download_snapshot(remote, &stage.join("older-snapshot"), branch, o).await?;
    }
    // 4. Components.
    let code = stage.join("code");
    std::fs::create_dir_all(&code)?;
    let (comps, _) = remote.list("code").await?;
    let mut components = Vec::new();
    for c in &comps {
        let Some(name) = c.strip_suffix(".zst") else {
            continue;
        };
        let bytes = decompress(&remote.get(&format!("code/{c}")).await?)?;
        std::fs::write(code.join(name), bytes)?;
        components.push(name.to_owned());
    }
    // 5. The state and actor databases, copied now so that moving the
    //    restore into place is only renames.
    let state = stage.join("branch");
    std::fs::create_dir_all(state.join("sql"))?;
    std::fs::copy(snap.join("state.db"), state.join("state.db"))?;
    copy_tree(&snap.join("sql"), &state.join("sql"))?;
    if snap.join("secrets.db").exists() {
        std::fs::copy(snap.join("secrets.db"), stage.join("secrets.db"))?;
    }
    Ok(Staged {
        m,
        segments,
        components,
        keystore,
        keystore_backup_ms,
        keys_missing,
        older,
        through_lsn,
    })
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    if !from.exists() {
        return Ok(());
    }
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let dest = to.join(e.file_name());
        if e.file_type()?.is_dir() {
            std::fs::create_dir_all(&dest)?;
            copy_tree(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), dest)?;
        }
    }
    Ok(())
}

/// "a, b, c and 4 more".
fn list_some(items: &[String]) -> String {
    let shown = items.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    match items.len() {
        n if n > 5 => format!("{shown} and {} more", n - 5),
        _ => shown,
    }
}

/// Moves a checked staging directory into place, with renames only. The
/// old `state.db` goes first and the new one comes last: an interrupted
/// install leaves no `state.db`, never the old state with the new log, and
/// `kronik restore` can run again without `--force` (m6-storage §6).
fn install_staged(
    data: &Path,
    stage: &Path,
    branch: &str,
    branch_dir: &Path,
    s: Staged,
    fault: &dyn Fn(&str) -> std::io::Result<()>,
) -> Result<RestoreReport, ShipError> {
    let replace_dir = |from: &Path, to: &Path| -> std::io::Result<()> {
        if to.exists() {
            std::fs::remove_dir_all(to)?;
        }
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::rename(from, to)
    };
    let replace_file = |from: &Path, to: &Path| -> std::io::Result<()> {
        if let Some(p) = to.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::rename(from, to)
    };
    std::fs::create_dir_all(branch_dir)?;
    fault("state")?;
    for f in ["state.db", "state.db-wal", "state.db-shm"] {
        let p = branch_dir.join(f);
        if p.exists() {
            std::fs::remove_file(&p)?;
        }
    }
    fault("log")?;
    let log_dir = branch_dir.join("log");
    replace_dir(&stage.join("log"), &log_dir)?;
    fault("sql")?;
    replace_dir(&stage.join("branch").join("sql"), &branch_dir.join("sql"))?;
    fault("snapshot")?;
    let snap_dir = snapshots::snapshots_dir(data, branch).join(format!("{:020}", s.m.lsn));
    replace_dir(&stage.join("snapshot"), &snap_dir)?;
    if let Some(o) = &s.older {
        let dir = snapshots::snapshots_dir(data, branch).join(format!("{:020}", o.lsn));
        replace_dir(&stage.join("older-snapshot"), &dir)?;
    }
    fault("code")?;
    let code = data.join("code");
    std::fs::create_dir_all(&code)?;
    for c in &s.components {
        std::fs::rename(stage.join("code").join(c), code.join(c))?;
    }
    fault("keys")?;
    let keys = data.join("keys");
    if stage.join("secrets.db").exists() {
        replace_file(&stage.join("secrets.db"), &keys.join("secrets.db"))?;
    }
    if s.keystore == "installed" {
        for suffix in ["", "-wal", "-shm"] {
            let from = stage.join(format!("keystore.db{suffix}"));
            let to = keys.join(format!("keystore.db{suffix}"));
            if from.exists() {
                replace_file(&from, &to)?;
            } else if to.exists() {
                std::fs::remove_file(to)?;
            }
        }
        tracing::info!(wall = ?s.keystore_backup_ms, "restore: installed a keystore backup");
    }
    if !s.keys_missing.is_empty() {
        tracing::warn!(
            subjects = ?s.keys_missing,
            "restore: --allow-missing-keys: these subjects' sealed values stay unreadable"
        );
    }
    // Nothing was shipped from here yet.
    let _ = std::fs::remove_file(ShipState::path(data));
    // The marker is durable before the new state is in place (perf review
    // R4): restored state without it would let an audit cursor past the
    // restored log skip the new history.
    let marker = serde_json::json!({ "through_lsn": s.through_lsn }).to_string();
    snapshots::write_synced(&branch_dir.join(RESTORE_MARKER), marker.as_bytes())?;
    fault("commit")?;
    std::fs::rename(
        stage.join("branch").join("state.db"),
        branch_dir.join("state.db"),
    )?;
    fault("committed")?;
    let first = kronik_log::segment_starts(&log_dir)?
        .first()
        .copied()
        .unwrap_or(s.m.lsn + 1);
    Ok(RestoreReport {
        snapshot_lsn: s.m.lsn,
        snapshot_id: s.m.id,
        state_hash: s.m.state_hash,
        segments: s.segments.len(),
        log_first_lsn: first,
        components: s.components.len(),
        keystore_backup_ms: s.keystore_backup_ms,
        keystore: s.keystore,
        keys_missing: s.keys_missing,
    })
}
/// Downloads and checks one remote snapshot into `snap_dir`.
async fn download_snapshot(
    remote: &Remote,
    snap_dir: &Path,
    branch: &str,
    m: &Manifest,
) -> Result<(), ShipError> {
    let base = format!("{branch}/snapshots/{:020}", m.lsn);
    for f in &m.files {
        let bytes = decompress(&remote.get(&format!("{base}/{}.zst", f.path)).await?)?;
        let hash = blake3::hash(&bytes).to_hex().to_string();
        if bytes.len() as u64 != f.size || hash != f.blake3 {
            return Err(ShipError::Restore(format!(
                "{} does not match the manifest",
                f.path
            )));
        }
        let dest = snap_dir.join(&f.path);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(dest, bytes)?;
    }
    std::fs::write(
        snap_dir.join("manifest.json"),
        serde_json::to_vec_pretty(m).unwrap_or_default(),
    )?;
    Ok(())
}

/// The lowest `base_lsn` of a `StateRebase` switch after `after` whose base
/// is before `after`, in the restored log.
fn rebase_base_after(
    log_dir: &Path,
    branch: &str,
    starts: &[u64],
    after: u64,
) -> Result<Option<u64>, ShipError> {
    let mut lowest: Option<u64> = None;
    for (i, &start) in starts.iter().enumerate() {
        if starts.get(i + 1).is_some_and(|n| *n <= after) {
            continue;
        }
        let image = std::fs::read(log_dir.join(kronik_log::segment_name(start)))?;
        let last = i + 1 == starts.len();
        kronik_log::scan_segment_image(&image, branch, start, after + 1, u64::MAX, last, |c| {
            if let Some((_, sw)) = c.record.rebase_switch()
                && sw.base_lsn < after
            {
                lowest = Some(lowest.map_or(sw.base_lsn, |l| l.min(sw.base_lsn)));
            }
            Ok::<_, kronik_log::LogError>(())
        })
        .map_err(|e| ShipError::Restore(e.to_string()))?;
    }
    Ok(lowest)
}

/// A keystore backup that decrypted under the node's key, ready to install.
struct KeystoreBackup {
    wall: u64,
    blob: Vec<u8>,
    master: kronik_privacy::MasterKey,
}

/// The newest `keystore/<wall>.bin`, checked against
/// the master key before restore writes anything: a backup that is there
/// but can't be installed fails the restore, unless `without` (then the
/// restored node starts without the subjects' keys, and sealed values stay
/// unreadable). Otherwise the status: `none_in_bucket` or `skipped`.
async fn check_keystore_backup(
    remote: &Remote,
    data: &Path,
    key_path: &Path,
    without: bool,
) -> Result<Result<KeystoreBackup, &'static str>, ShipError> {
    let (names, _) = match remote.list("keystore").await {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(error = %e, "restore: no keystore backups");
            return Ok(Err("none_in_bucket"));
        }
    };
    // The newest backup, not the newest before the snapshot: keys are only
    // ever added, a backup shipped after the snapshot holds the keys of its
    // values too, and erasures after it are applied again from the log.
    let best = names
        .iter()
        .filter_map(|n| n.strip_suffix(".bin")?.parse::<u64>().ok())
        .max();
    let Some(wall) = best else {
        tracing::info!("restore: no keystore backup in the bucket");
        return Ok(Err("none_in_bucket"));
    };
    if without {
        tracing::warn!(
            wall,
            "restore: --without-keystore: keystore backup {wall} not installed"
        );
        return Ok(Err("skipped"));
    }
    let (master, _) = kronik_privacy::MasterKey::open(key_path, &data.join("keys"), None)
        .map_err(ShipError::Key)?;
    let blob = remote.get(&format!("keystore/{wall}.bin")).await?;
    match kronik_privacy::keystore::Keystore::read_backup(&master, &blob) {
        Ok(_) => Ok(Ok(KeystoreBackup { wall, blob, master })),
        Err(kronik_privacy::PrivacyError::Decrypt(_)) => Err(ShipError::Key(
            kronik_privacy::PrivacyError::KeyMismatch(format!(
                "the keystore backup {wall} does not decrypt with this master key \
                 (another key, or a damaged backup)"
            )),
        )),
        Err(e) => Err(ShipError::Key(e)),
    }
}
