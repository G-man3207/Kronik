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

    async fn put(&self, rel: &str, bytes: Vec<u8>) -> Result<(), ShipError> {
        self.store
            .put(&self.key(rel), PutPayload::from(bytes))
            .await?;
        Ok(())
    }

    async fn get(&self, rel: &str) -> Result<Vec<u8>, ShipError> {
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
    async fn list(&self, rel: &str) -> Result<(Vec<String>, Vec<String>), ShipError> {
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

fn keystore_stamp(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let secs = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(secs.wrapping_mul(0x9E37_79B9).wrapping_add(meta.len()))
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
    /// `None` when the bucket had no backup at or before the restore point,
    /// or with `--without-keystore`. A backup that is there but can't be
    /// installed fails the restore.
    #[serde(default)]
    pub keystore_backup_ms: Option<u64>,
    /// `installed`, `none_in_bucket`, or `skipped` (`--without-keystore`).
    pub keystore: &'static str,
}

/// `kronik restore` (m6-storage §6): the newest remote snapshot, every
/// remote segment and component into `data`, then the snapshot installed
/// as the branch's state. The daemon must not run on `data`; an existing
/// `state.db` is refused unless `force`.
pub async fn restore(
    remote: &Remote,
    data: &Path,
    branch: &str,
    force: bool,
    key_path: &Path,
    without_keystore: bool,
) -> Result<RestoreReport, ShipError> {
    let branch_dir = data.join("branches").join(branch);
    if branch_dir.join("state.db").exists() && !force {
        return Err(ShipError::Restore(format!(
            "{} already holds state; restore into an empty data directory or pass --force",
            data.display()
        )));
    }
    // 1. The newest complete remote snapshot.
    let (_, lsns) = remote.list(&format!("{branch}/snapshots")).await?;
    let mut newest: Option<Manifest> = None;
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
            newest = Some(m);
        }
    }
    let m = newest.ok_or_else(|| ShipError::Restore("no snapshot in the bucket".into()))?;
    // The keystore backup is checked before anything is written, so a
    // missing or wrong key leaves the directory as it was (m8-privacy §10).
    let keystore =
        check_keystore_backup(remote, data, m.created_wall_ms, key_path, without_keystore).await?;
    let snap_dir = snapshots::snapshots_dir(data, branch).join(format!("{:020}", m.lsn));
    if snap_dir.exists() {
        std::fs::remove_dir_all(&snap_dir)?;
    }
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
        serde_json::to_vec_pretty(&m).unwrap_or_default(),
    )?;
    // 2. Every remote segment.
    let log_dir = branch_dir.join("log");
    if log_dir.exists() {
        std::fs::remove_dir_all(&log_dir)?;
    }
    std::fs::create_dir_all(&log_dir)?;
    let (names, _) = remote.list(&format!("{branch}/segments")).await?;
    let mut starts = Vec::new();
    for n in &names {
        let Some(seg) = n.strip_suffix(".zst") else {
            continue;
        };
        let bytes = decompress(&remote.get(&format!("{branch}/segments/{n}")).await?)?;
        std::fs::write(log_dir.join(seg), bytes)?;
        starts.push(seg.to_owned());
    }
    let local = kronik_log::segment_starts(&log_dir)?;
    let first = local.first().copied().unwrap_or(m.lsn + 1);
    if first > m.lsn + 1 {
        return Err(ShipError::Restore(format!(
            "the bucket's log starts at lsn {first}, after the snapshot at {}",
            m.lsn
        )));
    }
    // 3. Components.
    let code = data.join("code");
    std::fs::create_dir_all(&code)?;
    let (comps, _) = remote.list("code").await?;
    for c in &comps {
        let Some(name) = c.strip_suffix(".zst") else {
            continue;
        };
        let bytes = decompress(&remote.get(&format!("code/{c}")).await?)?;
        std::fs::write(code.join(name), bytes)?;
    }
    // 4. Install the snapshot (state.db, actor databases, secrets.db).
    kronik_store::snapshot::install(&snap_dir, &branch_dir)
        .map_err(|e| ShipError::Restore(e.to_string()))?;
    let secrets = snap_dir.join("secrets.db");
    if secrets.exists() {
        std::fs::create_dir_all(data.join("keys"))?;
        std::fs::copy(&secrets, data.join("keys").join("secrets.db"))?;
    }
    // 5. The keystore backup checked in step 1.
    let (keystore, keystore_backup_ms) = match keystore {
        Ok(k) => {
            kronik_privacy::keystore::Keystore::import_backup_file(
                &data.join("keys").join("keystore.db"),
                &k.master,
                &k.blob,
            )
            .map_err(ShipError::Key)?;
            tracing::info!(wall = k.wall, "restore: installed a keystore backup");
            ("installed", Some(k.wall))
        }
        Err(status) => (status, None),
    };
    // Nothing was shipped from here yet.
    let _ = std::fs::remove_file(ShipState::path(data));
    Ok(RestoreReport {
        snapshot_lsn: m.lsn,
        snapshot_id: m.id,
        state_hash: m.state_hash,
        segments: starts.len(),
        log_first_lsn: first,
        components: comps.len(),
        keystore_backup_ms,
        keystore,
    })
}
/// A keystore backup that decrypted under the node's key, ready to install.
struct KeystoreBackup {
    wall: u64,
    blob: Vec<u8>,
    master: kronik_privacy::MasterKey,
}

/// The newest `keystore/<wall>.bin` with `wall <= point`, checked against
/// the master key before restore writes anything: a backup that is there
/// but can't be installed fails the restore, unless `without` (then the
/// restored node starts without the subjects' keys, and sealed values stay
/// unreadable). Otherwise the status: `none_in_bucket` or `skipped`.
async fn check_keystore_backup(
    remote: &Remote,
    data: &Path,
    point: u64,
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
    let best = names
        .iter()
        .filter_map(|n| n.strip_suffix(".bin")?.parse::<u64>().ok())
        .filter(|w| *w <= point)
        .max();
    let Some(wall) = best else {
        tracing::info!("restore: no keystore backup at or before the restore point");
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
