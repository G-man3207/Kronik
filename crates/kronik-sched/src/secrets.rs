//! Log-derived secret publication and memory-only provider values.
//!
//! A caller admitting a live turn must persist TurnBegin before calling
//! `resolve_secret`; inventory and explicit management are separate I/O work.
pub(crate) mod coverage;
mod file_data;
mod native_current;
pub(crate) mod recovery;
mod scan;
pub use file_data::SecretCacheData;
use file_data::{ReadStamp, StampedFetched};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::env::Env;

use kronik_core::error::{ApiError, ErrorCode};
use kronik_effects::Config;
use kronik_privacy::secret_backend::config::{Backends, Settings};
use kronik_privacy::secret_backend::{BackendError, Fetched, SecretBackend, file::FileBackend};
use kronik_privacy::{SecretMeta, SecretRowMeta, SecretStore, SecretValue};
use kronik_proto::secret::{LEGACY_SECRET_VERSION_MAX, MAX_SECRET_VERSION};
use kronik_proto::{Record, log::v1 as pb};
use pb::secret_version::Phase;
use prost::Message;
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;
use zeroize::Zeroizing;

use crate::Node;

const NEGATIVE_TTL: Duration = Duration::from_secs(5);
const MAX_CATALOGUE_PAGES: usize = 1024;
const MAX_INVENTORY_VALUES: usize = 65_536;
pub(crate) const MAX_INVENTORY_BYTES: usize = 64 * 1024 * 1024;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::SecretUnavailable,
        "The retained secret identity or value is unavailable",
    )
}
fn committed_inventory_unavailable() -> ApiError {
    ApiError::new(ErrorCode::SecretUnavailable, "The secret mutation is already committed, but its inventory publication is unavailable")
        .with_hint("The committed mutation may finish publishing. Once inventory is available, inspect its history before explicitly submitting another mutation; do not automatically retry it.")
}
fn gone() -> ApiError {
    ApiError::new(
        ErrorCode::SecretVersionGone,
        "The recorded immutable secret version is gone or no longer authorized",
    )
}
fn invalid_name(name: &str) -> Result<(), ApiError> {
    if kronik_privacy::valid_name(name) {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::BadRequest,
            "Secret names must match [a-z0-9][a-z0-9_.-]{0,63}",
        ))
    }
}
fn backend_error(error: BackendError) -> ApiError {
    match error {
        BackendError::Unavailable => unavailable(),
        BackendError::NotFound => {
            ApiError::new(ErrorCode::SecretNotFound, "The secret was not found")
        }
        BackendError::Unauthorized => ApiError::new(
            ErrorCode::Unauthenticated,
            "The original request authority ended",
        ),
        BackendError::VersionGone | BackendError::Denied | BackendError::Invalid => gone(),
    }
}
fn system_audit(env: &Env, reason: &str) -> pb::Audit {
    pb::Audit {
        token_id: "system".into(),
        reason: reason.into(),
        wall_time_ms: env.clock.wall_ms(),
    }
}
fn active(row: &pb::SecretVersion) -> bool {
    row.phase == Phase::Active as i32
}
fn revision(version: u64) -> u32 {
    if version <= LEGACY_SECRET_VERSION_MAX {
        1
    } else {
        2
    }
}
fn meta(row: &pb::SecretVersion) -> SecretMeta {
    SecretMeta {
        name: row.name.clone(),
        version: row.version,
        version_hash: row.version_hash.clone(),
        created_wall_ms: row.audit.as_ref().map_or(0, |audit| audit.wall_time_ms),
    }
}
fn same_identity(left: &pb::SecretVersion, right: &pb::SecretVersion) -> bool {
    left.name == right.name
        && left.version == right.version
        && left.version_hash == right.version_hash
        && left.backend == right.backend
        && left.source_version == right.source_version
        && left.deleted == right.deleted
        && left.r#ref == right.r#ref
        && left.binding == right.binding
        && left.link_generation == right.link_generation
        && left.canonical_ref == right.canonical_ref
        && left.phase == right.phase
        && left.hash_revision == right.hash_revision
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Scope {
    name: String,
    backend: String,
    binding: String,
    reference: String,
    canonical: String,
    generation: u64,
}
impl Scope {
    fn file(name: &str, generation: u64) -> Self {
        Self {
            name: name.into(),
            backend: "file".into(),
            binding: "file".into(),
            reference: name.into(),
            canonical: name.into(),
            generation,
        }
    }
    fn link(link: &pb::SecretLink) -> Self {
        if link.backend.is_empty() {
            Self::file(&link.name, link.generation)
        } else {
            Self {
                name: link.name.clone(),
                backend: link.backend.clone(),
                binding: link.binding.clone(),
                reference: link.r#ref.clone(),
                canonical: link.canonical_ref.clone(),
                generation: link.generation,
            }
        }
    }
    fn config(name: &str, config: &Config) -> Self {
        config
            .secret_link(name)
            .map(Self::link)
            .unwrap_or_else(|| Self::file(name, 0))
    }
    fn row(row: &pb::SecretVersion) -> Self {
        Self {
            name: row.name.clone(),
            backend: row.backend.clone(),
            binding: row.binding.clone(),
            reference: row.r#ref.clone(),
            canonical: row.canonical_ref.clone(),
            generation: row.link_generation,
        }
    }
}
struct Authority {
    binding: String,
    allowed_refs: Vec<String>,
}
struct Held {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    checked: Duration,
    operational: bool,
}
/// The certificate covers every retained secret's committed state through
/// `base_lsn`: a PREFIX of the applied log, not a moment. Mutations after
/// the base dirty only the names they touch; untouched names keep serving
/// under this certificate while a rebuild builds the next one.
#[derive(Clone)]
struct NativeCoverage {
    revision: u64,
    epoch: u64,
    captured_at: Duration,
    fingerprint: [u8; 32],
    references: Option<Arc<[pb::SecretRef]>>,
    base_lsn: u64,
}
struct SnapshotLiveness {
    current: AtomicBool,
    changed: tokio::sync::Notify,
}
#[derive(Default)]
struct RetiredNativeCoverage {
    _coverage: Option<NativeCoverage>,
    live: Option<Arc<SnapshotLiveness>>,
}
impl Drop for RetiredNativeCoverage {
    fn drop(&mut self) {
        if let Some(live) = &self.live {
            live.changed.notify_waiters();
        }
    }
}

/// Data only; the existing cache mutex is its concrete publication fence.
#[derive(Clone)]
pub struct SecretSnapshotPublication {
    node: std::sync::Weak<Node>,
    env: Env,
    execution: Arc<crate::native_execution::NativeExecution>,
    recovery: AuthLease,
    cache: Arc<SecretCache>,
    live: Arc<SnapshotLiveness>,
    epoch: u64,
    until: Duration,
}
impl SecretSnapshotPublication {
    pub fn data_is_current_under_publication(&self) -> bool {
        self.live.current.load(Ordering::Acquire)
            && self.execution.source_is_live_under_publication()
            && self.env.clock.monotonic() <= self.until
    }
    pub fn check_current(&self) -> Result<(), ApiError> {
        let node = self.node.upgrade().ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "the original native node was dropped",
            )
        })?;
        node.check_alive()?;
        self.recovery.check()?;
        if node.epoch() != self.epoch || !self.data_is_current_under_publication() {
            return Err(unavailable());
        }
        Ok(())
    }
    /// Only a concrete final enqueue/cache swap, inside the SAME original admission.
    /// Lock order: original admission -> cache; never call a getter, authority or I/O here.
    pub fn with_current_publication<T>(
        &self,
        denied: &mut ApiError,
        publish: impl FnOnce() -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let publication = match self.cache.state.try_lock() {
            Ok(publication) => publication,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(ApiError {
                    code: denied.code,
                    message: std::mem::take(&mut denied.message),
                    hint: denied.hint.take(),
                });
            }
        };
        if publication.native_current.is_pending()
            || !self.data_is_current_under_publication()
            || publication.coverage.as_ref().is_none_or(|coverage| {
                coverage.revision != publication.revision
                    || coverage.epoch != self.epoch
                    || coverage
                        .captured_at
                        .saturating_add(self.cache.settings.refresh)
                        != self.until
            })
            || publication
                .native_certificate_live
                .as_ref()
                .is_none_or(|live| !Arc::ptr_eq(live, &self.live))
        {
            return Err(ApiError {
                code: denied.code,
                message: std::mem::take(&mut denied.message),
                hint: denied.hint.take(),
            });
        }
        publish()
    }
    pub fn cancelled(&self) -> kronik_core::env::BoxFuture<'static, ()> {
        let held = self.clone();
        Box::pin(async move {
            let stopped = held.recovery.cancelled();
            tokio::pin!(stopped);
            loop {
                let changed = held.live.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !held.data_is_current_under_publication() {
                    return;
                }
                let remaining = held.until.saturating_sub(held.env.clock.monotonic());
                tokio::select! {
                    biased;
                    () = changed => {},
                    () = held.env.clock.sleep(remaining) => return,
                    () = &mut stopped => return,
                }
            }
        })
    }
}

struct NativeCatalogueCapture {
    at: Duration,
    scopes: BTreeSet<Scope>,
    file_rows: Vec<SecretRowMeta>,
}
struct CurrentName {
    live: Arc<AtomicBool>,
    binding: Option<(Scope, Option<(u64, String)>)>,
}
#[derive(Default)]
struct SecretName {
    lock: Arc<AsyncMutex<()>>,
    current: Option<CurrentName>,
    file_mutation: Option<file_data::FileMutation>,
}
#[derive(Default)]
struct CacheState {
    registry: BTreeMap<(String, u64), pb::SecretVersion>,
    values: BTreeMap<(String, u64), Held>,
    scrub_file: BTreeMap<(String, u64), Arc<Zeroizing<Vec<u8>>>>,
    current: BTreeMap<Scope, (String, u64)>,
    names: BTreeMap<String, SecretName>,
    negative: BTreeMap<(Scope, Option<String>), (Duration, BackendError)>,
    revision: u64,
    /// Per name: the applied LSN of the last record touching it. A name is
    /// certified through a coverage whose base_lsn is at or after this.
    dirty: BTreeMap<String, u64>,
    /// The highest dirty LSN: the whole-inventory gate (all names certified
    /// only when the coverage's base reaches it).
    dirty_max: u64,
    coverage: Option<NativeCoverage>,
    native_certificate_live: Option<Arc<SnapshotLiveness>>,
    native_catalogue_capture: Option<Arc<NativeCatalogueCapture>>,
    bytes: usize,
    native_current: native_current::NativeCurrentState,
    physical: Option<std::sync::Weak<crate::native_execution::Lifecycle>>,
    bound_runtime: std::sync::Weak<SecretRuntime>,
    bound_cache: std::sync::Weak<SecretCache>,
    native_owner: Option<std::sync::Weak<crate::native_execution::NativeExecution>>,
}
fn pattern_reference(row: &pb::SecretVersion) -> Option<pb::SecretRef> {
    if !active(row)
        || row.deleted
        || !kronik_privacy::valid_name(&row.name)
        || row.version_hash.len() != 16
    {
        return None;
    }
    let mut reference = pb::SecretRef {
        name: row.name.clone(),
        version_hash: row.version_hash.clone(),
        ..Default::default()
    };
    reference.set_resolved_version(row.version).ok()?;
    Some(reference)
}

// Privacy provenance only: these identities do not grant operational use of retained bytes.
fn pattern_references(state: &CacheState) -> Option<Vec<pb::SecretRef>> {
    let mut references = Vec::with_capacity(state.values.len() + state.scrub_file.len());
    for key in state.values.keys() {
        references.push(pattern_reference(state.registry.get(key)?)?);
    }
    if !state.scrub_file.is_empty() {
        let mut physical = BTreeMap::new();
        for row in state
            .registry
            .values()
            .filter(|row| active(row) && !row.deleted && row.backend == "file")
        {
            let version = kronik_privacy::secret_backend::file::source_highwater(
                &row.name,
                std::slice::from_ref(row),
                None,
            )
            .ok()?;
            physical.entry((row.name.as_str(), version)).or_insert(row);
        }
        for key in state.scrub_file.keys() {
            references.push(pattern_reference(physical.get(&(key.0.as_str(), key.1))?)?);
        }
    }
    Some(references)
}
// Only a successfully admitted reservation can be completed without reacquiring
// ordinary authority; terminal publication can change its phase, nothing else.
struct AdmittedSecret(pb::SecretVersion);

/// Forks can read already-authorized identities, never initiate provider I/O.
/// Scrub-only retained bytes are deliberately not an operational fallback.
pub struct SecretCache {
    env: Env,
    settings: Settings,
    authorities: BTreeMap<String, Authority>,
    publication: Arc<Mutex<()>>,
    state: Arc<Mutex<CacheState>>,
    revision_changed: Arc<tokio::sync::Notify>,
}
impl SecretCache {
    fn new(
        env: Env,
        settings: Settings,
        backends: &Backends,
        publication: Arc<Mutex<()>>,
        data: &SecretCacheData,
    ) -> Self {
        let authorities = backends
            .ids()
            .filter_map(|id| {
                backends.get(id).map(|source| {
                    (
                        id.to_owned(),
                        Authority {
                            binding: source.binding.clone(),
                            allowed_refs: source.allowed_refs.clone(),
                        },
                    )
                })
            })
            .collect();
        Self {
            env,
            settings,
            authorities,
            publication,
            state: data.state.clone(),
            revision_changed: data.changed.clone(),
        }
    }
    fn retire_certificate(state: &mut CacheState) -> RetiredNativeCoverage {
        let live = state.native_certificate_live.take();
        if let Some(live) = &live {
            live.current.store(false, Ordering::Release);
        }
        RetiredNativeCoverage {
            _coverage: state.coverage.take(),
            live,
        }
    }
    fn clear_coverage(&self) {
        let retired = {
            let mut state = lock(&self.state);
            Self::retire_certificate(&mut state)
        };
        drop(retired);
    }
    fn trusted(&self, scope: &Scope) -> bool {
        scope.backend == "file"
            || self.authorities.get(&scope.backend).is_some_and(|source| {
                source.binding == scope.binding
                    && source
                        .allowed_refs
                        .iter()
                        .any(|prefix| scope.reference.starts_with(prefix))
            })
    }
    fn register(&self, row: pb::SecretVersion) {
        let key = (row.name.clone(), row.version);
        let mut retired = RetiredNativeCoverage::default();
        let mut state = lock(&self.state);
        if state.registry.get(&key).is_some_and(|old| {
            old.phase != Phase::Reserved as i32 && row.phase == Phase::Reserved as i32
        }) {
            return;
        }
        if state.registry.get(&key) != Some(&row) {
            state.registry.insert(key, row.clone());
            state.revision = state.revision.wrapping_add(1);
            retired = Self::retire_certificate(&mut state);
            self.revision_changed.notify_one();
        }
        drop(state);
        drop(retired);
    }
    // Unused since the certified-snapshot rework; kept for the M23 track.
    #[allow(dead_code)]
    fn invalidate(&self) {
        let mut state = lock(&self.state);
        state.revision = state.revision.wrapping_add(1);
        let retired = Self::retire_certificate(&mut state);
        self.revision_changed.notify_one();
        drop(state);
        drop(retired);
    }
    fn invalidate_file_operational(&self, name: &str, through: u64) {
        let retired;
        let mut state = lock(&self.state);
        retired = Self::retire_certificate(&mut state);
        let CacheState {
            registry, values, ..
        } = &mut *state;
        for (key, held) in values {
            if key.0 == name
                && registry.get(key).is_some_and(|row| {
                    row.backend == "file"
                        && row
                            .source_version
                            .parse::<u64>()
                            .is_ok_and(|physical| physical <= through)
                })
            {
                held.operational = false;
            }
        }
        drop(state);
        drop(retired);
    }
    fn row(&self, scope: &Scope, version: Option<u64>) -> Option<pb::SecretVersion> {
        let state = lock(&self.state);
        match version {
            Some(version) => state
                .registry
                .get(&(scope.name.clone(), version))
                .filter(|row| Scope::row(row) == *scope)
                .cloned(),
            None if scope.backend != "file" => state
                .current
                .get(scope)
                .and_then(|key| state.registry.get(key))
                .cloned(),
            None => state
                .registry
                .range((scope.name.clone(), 0)..=(scope.name.clone(), MAX_SECRET_VERSION))
                .rev()
                .map(|(_, row)| row)
                .find(|row| active(row) && Scope::row(row) == *scope)
                .cloned(),
        }
    }
    fn held(&self, row: &pb::SecretVersion, allow_stale: bool) -> Option<Arc<Zeroizing<Vec<u8>>>> {
        let state = lock(&self.state);
        let held = state.values.get(&(row.name.clone(), row.version))?;
        let age = self.env.clock.monotonic().saturating_sub(held.checked);
        (held.operational
            && age
                <= if allow_stale {
                    self.settings.max_stale
                } else {
                    self.settings.refresh
                })
        .then(|| held.bytes.clone())
    }
    fn insert(
        &self,
        row: &pb::SecretVersion,
        bytes: Arc<Zeroizing<Vec<u8>>>,
        operational: bool,
        stamp: Option<&ReadStamp>,
    ) -> Result<(), ApiError> {
        let mut retired = RetiredNativeCoverage::default();
        let mut state = lock(&self.state);
        if operational
            && stamp.is_none_or(|stamp| {
                !self.read_matches(&state, &row.backend, &row.canonical_ref, stamp)
            })
        {
            return Err(ApiError {
                code: ErrorCode::SecretUnavailable,
                message: String::new(),
                hint: None,
            });
        }
        let key = (row.name.clone(), row.version);
        let previous = state.values.get(&key).map_or(0, |held| held.bytes.len());
        let total = state
            .bytes
            .saturating_sub(previous)
            .checked_add(bytes.len())
            .ok_or_else(unavailable)?;
        if total > MAX_INVENTORY_BYTES
            || (!state.values.contains_key(&key)
                && state.values.len().saturating_add(state.scrub_file.len())
                    >= MAX_INVENTORY_VALUES)
        {
            drop(Self::retire_certificate(&mut state));
            return Err(unavailable());
        }
        let (bytes, checked, operational) = match state.values.get(&key) {
            Some(held) => (
                held.bytes.clone(),
                if operational {
                    self.env.clock.monotonic()
                } else {
                    held.checked
                },
                operational || held.operational,
            ),
            None => {
                retired = Self::retire_certificate(&mut state);
                (bytes, self.env.clock.monotonic(), operational)
            }
        };
        state.bytes = total;
        state.values.insert(
            key,
            Held {
                bytes,
                checked,
                operational,
            },
        );
        // A linked row is selected for its link scope through the CURRENT
        // map: the unversioned resolve of a non-file scope reads it. Only an
        // OPERATIONAL value chooses the pointer (a catalogue observation is
        // not the current value), and the newest version wins; a deleted row
        // releases a pointer that names it.
        if row.backend != "file" {
            let scope = Scope::row(row);
            if operational && !row.deleted && active(row) {
                let superseded = state
                    .current
                    .get(&scope)
                    .is_some_and(|(name, version)| *name == row.name && *version >= row.version);
                if !superseded {
                    state.current.insert(scope, (row.name.clone(), row.version));
                }
            } else if state
                .current
                .get(&scope)
                .is_some_and(|(name, version)| *name == row.name && *version == row.version)
            {
                state.current.remove(&scope);
            }
        }
        drop(state);
        drop(retired);
        Ok(())
    }
    fn insert_scrub_file(
        &self,
        metadata: &SecretMeta,
        bytes: Arc<Zeroizing<Vec<u8>>>,
    ) -> Result<(), ApiError> {
        let mut state = lock(&self.state);
        let key = (metadata.name.clone(), metadata.version);
        if state.scrub_file.contains_key(&key) {
            return Ok(());
        }
        let total = state
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(unavailable)?;
        if total > MAX_INVENTORY_BYTES
            || state.values.len().saturating_add(state.scrub_file.len()) >= MAX_INVENTORY_VALUES
        {
            drop(Self::retire_certificate(&mut state));
            return Err(unavailable());
        }
        state.bytes = total;
        let retired = Self::retire_certificate(&mut state);
        state.scrub_file.insert(key, bytes);
        drop(state);
        drop(retired);
        Ok(())
    }
    fn failure(&self, scope: &Scope, error: BackendError) {
        self.failure_version(scope, None, error);
    }
    fn failure_version(&self, scope: &Scope, version: Option<&str>, error: BackendError) {
        // A caller's lease ending says nothing about the backend or the version:
        // never cache it as a negative observation.
        if error == BackendError::Unauthorized {
            return;
        }
        let mut state = lock(&self.state);
        state.negative.insert(
            (scope.clone(), version.map(str::to_owned)),
            (self.env.clock.monotonic(), error),
        );
        state.revision = state.revision.wrapping_add(1);
        let retired = Self::retire_certificate(&mut state);
        if error != BackendError::Unavailable {
            let CacheState {
                registry, values, ..
            } = &mut *state;
            for (key, held) in values {
                if registry.get(key).is_some_and(|row| {
                    Scope::row(row) == *scope
                        && (version.is_none()
                            || matches!(error, BackendError::Denied | BackendError::Invalid)
                            || version == Some(row.source_version.as_str()))
                }) {
                    held.operational = false;
                }
            }
        }
        drop(state);
        drop(retired);
    }
    fn negative(&self, scope: &Scope) -> Option<BackendError> {
        self.negative_version(scope, None)
    }
    fn negative_version(&self, scope: &Scope, version: Option<&str>) -> Option<BackendError> {
        let state = lock(&self.state);
        state
            .negative
            .get(&(scope.clone(), version.map(str::to_owned)))
            .or_else(|| version.and_then(|_| state.negative.get(&(scope.clone(), None))))
            .and_then(|(at, error)| {
                (self.env.clock.monotonic().saturating_sub(*at) < NEGATIVE_TTL).then_some(*error)
            })
    }
    fn clear_negative(&self, scope: &Scope) {
        self.clear_negative_version(scope, None);
    }
    fn clear_negative_version(&self, scope: &Scope, version: Option<&str>) {
        lock(&self.state)
            .negative
            .remove(&(scope.clone(), version.map(str::to_owned)));
    }

    pub fn cached(
        &self,
        name: &str,
        version: Option<u64>,
        config: &Config,
    ) -> Result<Option<SecretValue>, ApiError> {
        invalid_name(name)?;
        let scope = Scope::config(name, config);
        if !self.trusted(&scope) {
            return Err(gone());
        }
        let Some(row) = self.row(&scope, version) else {
            return if version.is_some() {
                Err(gone())
            } else {
                Ok(None)
            };
        };
        if !active(&row) || row.deleted {
            return if version.is_some() {
                Err(gone())
            } else {
                Ok(None)
            };
        }
        if version.is_none() && Self::file_current_pending(&lock(&self.state), &row) {
            return Err(unavailable());
        }
        let stale = match if version.is_some() {
            self.negative_version(&scope, Some(&row.source_version))
        } else {
            self.negative(&scope)
        } {
            Some(BackendError::Unavailable) => true,
            Some(error) => return Err(backend_error(error)),
            None => false,
        };
        let bytes = self.held(&row, stale).ok_or_else(unavailable)?;
        Ok(Some(SecretValue {
            meta: meta(&row),
            value: bytes.to_vec(),
        }))
    }
    /// Native fingerprint/privacy verification only. Retained bytes never
    /// authorize a reveal, a resend, a fork or an operational provider fallback.
    pub(crate) fn scrub_reference(
        &self,
        reference: &pb::SecretRef,
    ) -> Result<Arc<Zeroizing<Vec<u8>>>, ApiError> {
        let corrupt = || {
            ApiError::new(
                ErrorCode::StorageCorrupt,
                "Invalid recorded secret scrub identity",
            )
        };
        invalid_name(&reference.name).map_err(|_| corrupt())?;
        let version = reference.resolved_version().map_err(|_| corrupt())?;
        let key = (reference.name.clone(), version);
        let state = lock(&self.state);
        let row = state.registry.get(&key).ok_or_else(unavailable)?;
        if !active(row) || row.version_hash != reference.version_hash {
            return Err(corrupt());
        }
        state
            .values
            .get(&key)
            .map(|held| held.bytes.clone())
            .ok_or_else(unavailable)
    }

    fn complete(&self, epoch: u64) -> bool {
        let state = lock(&self.state);
        !state.native_current.is_pending()
            && state.coverage.as_ref().is_some_and(|coverage| {
                epoch == coverage.epoch && coverage.base_lsn >= state.dirty_max
            })
    }

    /// Certified scrub inventory shares the existing controlled buffers; it grants no operational access.
    // The certified snapshot's value list: name plus zeroizing bytes.
    #[allow(clippy::type_complexity)]
    pub fn values(&self, epoch: u64) -> Result<Vec<(String, Arc<Zeroizing<Vec<u8>>>)>, ApiError> {
        Ok(self.native_snapshot(epoch)?.values)
    }
    fn native_snapshot(&self, epoch: u64) -> Result<CertifiedSecretSnapshot, ApiError> {
        let state = lock(&self.state);
        self.native_snapshot_locked(&state, epoch)
    }
    fn native_snapshot_locked(
        &self,
        state: &CacheState,
        epoch: u64,
    ) -> Result<CertifiedSecretSnapshot, ApiError> {
        let NativeCoverage {
            revision,
            epoch: at_epoch,
            captured_at: _,
            fingerprint,
            references,
            base_lsn,
        } = state.coverage.clone().ok_or_else(unavailable)?;
        if state.native_current.is_pending() {
            return Err(unavailable());
        }
        if state.dirty_max > base_lsn {
            return Err(unavailable());
        }
        if epoch != at_epoch {
            return Err(unavailable());
        }
        let _ = revision;
        let values = state
            .values
            .iter()
            .map(|((name, _), held)| (name.clone(), held.bytes.clone()))
            .chain(
                state
                    .scrub_file
                    .iter()
                    .map(|((name, _), bytes)| (name.clone(), bytes.clone())),
            )
            .collect::<Vec<_>>();
        if references.as_ref().is_some_and(|references| {
            references.len() != values.len()
                || references
                    .iter()
                    .zip(&values)
                    .any(|(reference, (name, _))| &reference.name != name)
        }) {
            return Err(unavailable());
        }
        Ok(CertifiedSecretSnapshot {
            values,
            fingerprint,
            references,
        })
    }
}

/// Certified values and their immutable native coverage identity travel together.
pub struct CertifiedSecretSnapshot {
    pub values: Vec<(String, Arc<Zeroizing<Vec<u8>>>)>,
    pub fingerprint: [u8; 32],
    /// Privacy pattern provenance only; None means an actual needle lacks a proven identity.
    pub references: Option<Arc<[pb::SecretRef]>>,
}

pub struct SecretRuntime {
    env: Env,
    file: Arc<SecretStore>,
    file_source: FileBackend,
    backends: Backends,
    settings: Settings,
    cache: Arc<SecretCache>,
    inventory: AsyncMutex<()>,
    /// Serializes the writers of the coverage watermark file.
    watermark_io: AsyncMutex<()>,
    /// What certification has cost since the node started.
    stats: CertificationStats,
    initialized: AtomicBool,
    background: AtomicBool,
    // The ADR-0004-compliant replacement ripples through the wait/notify
    // design of every reader and the background cycle; tracked under the
    // M23 track with the other secret-catalogue defects.
    #[allow(clippy::disallowed_types)]
    // The ADR-0004-compliant replacement ripples through the wait/notify
    // design of every reader and the background cycle; tracked under the
    // M23 track with the other secret-catalogue defects.
    #[allow(clippy::disallowed_types)]
    certified: tokio::sync::watch::Sender<(u64, bool)>,
}
/// What certifying the inventory has cost since the node started: the
/// builds it ran and the log records they read. The numbers are in the
/// "secret inventory certified" log line, and what the tests of the watermark
/// read.
#[derive(Default)]
struct CertificationStats {
    builds: std::sync::atomic::AtomicU64,
    records: std::sync::atomic::AtomicU64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecretBackendStatus {
    pub id: String,
    pub kind: String,
    pub binding: String,
    pub configured: bool,
    pub inventory_complete: bool,
}
impl SecretRuntime {
    /// Registers applied secret rows into the certification cache as the
    /// applier applies them: the registry is the applied projection, fed by
    /// the applier rather than by later store queries racing its lag.
    pub(crate) fn register_applied(&self, row: pb::SecretVersion) {
        // The durable format fence is a `SecretVersion` record with no name
        // and version zero; it initializes the store's format floor, it is
        // not a secret, and it must not enter the certificate's registry or
        // dirty tracking.
        if row.name.is_empty() || row.version == 0 {
            return;
        }
        self.cache.register(row);
    }

    /// Abandons an in-flight native-current apply's bookkeeping after an
    /// availability-class publish failure (see NativeCurrentState::abandon).
    pub(crate) fn abandon_in_flight_apply(&self, cut: u64) {
        lock(&self.cache.state).native_current.abandon(cut);
    }

    /// Wakes the background rebuild after an availability-class degrade:
    /// the certified catalogue stays retired and the cycle retries promptly.
    pub(crate) fn schedule_rebuild(&self) {
        self.cache.revision_changed.notify_one();
    }

    pub(crate) fn new(
        env: Env,
        file: Arc<SecretStore>,
        backends: Backends,
        settings: Settings,
        publication: Arc<Mutex<()>>,
        physical: &Arc<crate::native_execution::Lifecycle>,
    ) -> Result<Arc<Self>, kronik_privacy::PrivacyError> {
        let data = file
            .data()
            .ok_or(kronik_privacy::PrivacyError::SecretStoreUnowned)?;
        let actual: &dyn std::any::Any = data.as_ref();
        let data = actual
            .downcast_ref::<SecretCacheData>()
            .ok_or(kronik_privacy::PrivacyError::SecretStoreUnowned)?;
        let cache = Arc::new(SecretCache::new(
            env.clone(),
            settings.clone(),
            &backends,
            publication,
            data,
        ));
        let file_source = FileBackend::new(env.clone(), file.clone());
        let runtime = Arc::new(Self {
            env,
            file,
            file_source,
            backends,
            settings,
            cache,
            inventory: AsyncMutex::new(()),
            watermark_io: AsyncMutex::new(()),
            stats: CertificationStats::default(),
            initialized: AtomicBool::new(false),
            background: AtomicBool::new(false),
            certified: tokio::sync::watch::channel((0, false)).0,
        });
        runtime.cache.bind_physical(physical, &runtime)?;
        Ok(runtime)
    }
    fn name_lock(&self, name: &str) -> Arc<AsyncMutex<()>> {
        let mut state = lock(&self.cache.state);
        if let Some(slot) = state.names.get(name) {
            return slot.lock.clone();
        }
        let slot = SecretName::default();
        let held = slot.lock.clone();
        state.names.insert(name.to_owned(), slot);
        held
    }
    fn ready(&self) -> Result<(), ApiError> {
        if self.initialized.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    fn source(
        &self,
        scope: &Scope,
    ) -> Result<&kronik_privacy::secret_backend::config::Source, ApiError> {
        let source = self.backends.get(&scope.backend).ok_or_else(gone)?;
        if source.binding != scope.binding {
            return Err(gone());
        }
        if !source.allows(&scope.reference) {
            return Err(ApiError::new(
                ErrorCode::SecretRefNotAllowed,
                "The reference is not allowed by trusted backend configuration",
            ));
        }
        Ok(source)
    }
    async fn fetched(
        &self,
        scope: &Scope,
        version: Option<&str>,
        original: AuthLease,
    ) -> Result<StampedFetched, BackendError> {
        original.check().map_err(|_| BackendError::Unauthorized)?;
        let stamp = self.cache.read_stamp(scope)?;
        let result = if scope.backend == "file" {
            self.file_source
                .version(
                    &scope.reference,
                    version.ok_or(BackendError::Invalid)?,
                    original.clone(),
                )
                .await
        } else {
            let source = self.source(scope).map_err(|_| BackendError::Invalid)?;
            self.env
                .timeout(self.settings.fetch_timeout, async {
                    match version {
                        Some(version) => {
                            source
                                .client
                                .version(&scope.reference, version, original.clone())
                                .await
                        }
                        None => {
                            source
                                .client
                                .current(&scope.reference, original.clone())
                                .await
                        }
                    }
                })
                .await
                .unwrap_or(Err(BackendError::Unavailable))
        };
        original.check().map_err(|_| BackendError::Unauthorized)?;
        let Fetched {
            value,
            source_version,
            canonical_ref,
        } = result?;
        if !self.cache.read_matches(
            &lock(&self.cache.state),
            &scope.backend,
            &scope.canonical,
            &stamp,
        ) {
            return Err(BackendError::Unavailable);
        }
        Ok(StampedFetched {
            value,
            source_version,
            canonical_ref,
            stamp,
        })
    }
    async fn fetched_pinned(
        &self,
        expected: &pb::SecretVersion,
        original: AuthLease,
    ) -> Result<StampedFetched, BackendError> {
        let scope = Scope::row(expected);
        let version = Some(expected.source_version.as_str());
        let fetched = self.fetched(&scope, version, original).await?;
        self.validate(&scope, &fetched, version)?;
        if self
            .file
            .version_hash(&expected.name, expected.version, &fetched.value)
            .map_err(|_| BackendError::Invalid)?
            != expected.version_hash
        {
            return Err(BackendError::Invalid);
        }
        Ok(fetched)
    }
    fn validate(
        &self,
        scope: &Scope,
        fetched: &StampedFetched,
        version: Option<&str>,
    ) -> Result<(), BackendError> {
        if fetched.canonical_ref != scope.canonical
            || fetched.source_version.is_empty()
            || fetched.source_version.len() > 4096
            || fetched.source_version.chars().any(char::is_control)
            || version.is_some_and(|version| fetched.source_version != version)
        {
            Err(BackendError::Invalid)
        } else {
            Ok(())
        }
    }
    async fn retained_file_bytes(
        &self,
        name: &str,
        physical: u64,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let file = self.file.clone();
        let name = name.to_owned();
        self.env
            .blocking("secret-file-scrub", move || {
                let value = file
                    .retained_version_for_scrub(&name, physical)
                    .map_err(|_| unavailable())?
                    .ok_or_else(unavailable)?;
                Ok(Zeroizing::new(value.value))
            })
            .await
            .ok_or_else(unavailable)?
    }
    async fn file_rows(&self) -> Result<Vec<SecretRowMeta>, ApiError> {
        let file = self.file.clone();
        self.env
            .blocking("secret-file-metadata", move || {
                let mut result = Vec::new();
                let mut cursor: Option<(String, u64)> = None;
                loop {
                    let page = file
                        .metadata_page(
                            cursor
                                .as_ref()
                                .map(|(name, version)| (name.as_str(), *version)),
                            true,
                        )
                        .map_err(|_| unavailable())?;
                    if page.is_empty() {
                        return Ok(result);
                    }
                    if result.len().saturating_add(page.len()) > MAX_INVENTORY_VALUES {
                        return Err(unavailable());
                    }
                    let last = page
                        .last()
                        .map(|row| (row.meta.name.clone(), row.meta.version))
                        .ok_or_else(unavailable)?;
                    if cursor.as_ref().is_some_and(|cursor| *cursor >= last) {
                        return Err(unavailable());
                    }
                    let full = page.len() == 256;
                    result.extend(page);
                    cursor = Some(last);
                    if !full {
                        return Ok(result);
                    }
                }
            })
            .await
            .ok_or_else(unavailable)?
    }
}

async fn owned<T, F, Fut>(node: &Node, run: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(Arc<Node>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, ApiError>> + Send + 'static,
{
    let me = node.me().ok_or_else(unavailable)?;
    node.env
        .spawn("secret-intent", run(me))
        .await
        .ok_or_else(unavailable)?
}

impl Node {
    fn runtime(&self) -> Result<&Arc<SecretRuntime>, ApiError> {
        self.secret_runtime.as_ref().ok_or_else(unavailable)
    }
    pub(crate) fn publish_secret_config_epoch(&self, publish_epoch: impl FnOnce()) {
        let Some(runtime) = &self.secret_runtime else {
            publish_epoch();
            return;
        };
        let retired = {
            let mut state = lock(&runtime.cache.state);
            state.revision = state.revision.wrapping_add(1);
            let retired = SecretCache::retire_certificate(&mut state);
            publish_epoch();
            state.native_current.configured(self.epoch());
            retired
        };
        drop(retired);
        runtime.cache.revision_changed.notify_one();
    }
    pub fn secret_cache(&self) -> Option<Arc<SecretCache>> {
        self.secret_runtime
            .as_ref()
            .map(|runtime| runtime.cache.clone())
    }
    /// Native-only: member factories bind their physical global certificate instead.
    pub fn native_secret_snapshot(&self) -> Result<CertifiedSecretSnapshot, ApiError> {
        self.check_alive()?;
        let epoch = self.epoch();
        let snapshot = match self.runtime()?.cache.native_snapshot(epoch) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                // A reader that finds the catalogue uncertified wakes the
                // rebuild. The exporter and the CLI retry the documented
                // window, and a cycle parked on its periodic tick must not
                // make a read-only workload wait the whole tick for a
                // certificate its own demand needs.
                self.runtime()?.cache.revision_changed.notify_one();
                return Err(error);
            }
        };
        if self.epoch() != epoch {
            return Err(unavailable());
        }
        self.check_alive()?;
        if let Err(error) = self.probe_store_identity() {
            self.runtime()?.cache.revision_changed.notify_one();
            return Err(error);
        }
        Ok(snapshot)
    }

    /// The certificate must cover the retained bytes' physical readability:
    /// on every certified read, every active native ledger row's retained
    /// bytes must still load from the store. A replaced, damaged or
    /// unloadable store retires the certificate, so scrubbed reads stall
    /// instead of answering from a snapshot whose backing bytes are gone.
    /// The probe is one row load per active secret — it keeps the whole-log
    /// rescan out of the read path, not the values themselves.
    fn probe_store_identity(&self) -> Result<(), ApiError> {
        let runtime = self.runtime()?;
        let rows = {
            let state = lock(&runtime.cache.state);
            state
                .registry
                .values()
                .filter(|row| active(row) && row.backend == "file")
                .cloned()
                .collect::<Vec<_>>()
        };
        for row in rows {
            let physical: u64 = row.source_version.parse().map_err(|_| unavailable())?;
            // The retained load covers live values and deleted rows (they
            // stay scrub needles) alike, and decrypts under the store's
            // keyed identity, which fails on any ciphertext damage or store
            // replacement.
            let readable = runtime
                .file
                .retained_version_for_scrub(&row.name, physical)
                .map_err(|_| unavailable())?
                .is_some();
            if !readable {
                runtime.cache.clear_coverage();
                return Err(unavailable());
            }
        }
        Ok(())
    }
    /// Snapshot and its held generation are captured under ONE registry/value lock.
    pub fn native_secret_snapshot_with_publication(
        &self,
    ) -> Result<(Arc<CertifiedSecretSnapshot>, SecretSnapshotPublication), ApiError> {
        // Demand wakes the rebuild: the exporter polls this gate, and a
        // cycle parked on its periodic tick must not make a read-only
        // workload wait the whole tick for a certificate its own demand
        // needs.
        if let Some(runtime) = &self.secret_runtime
            && !runtime.cache.complete(self.epoch())
        {
            runtime.cache.revision_changed.notify_one();
        }
        self.check_alive()?;
        let node = Arc::downgrade(&self.me().ok_or_else(unavailable)?);
        let execution = self.native_snapshot_execution();
        let recovery = self.native_recovery_authority()?;
        let cache = self.runtime()?.cache.clone();
        let epoch = self.epoch();
        let (snapshot, live, at) = {
            let state = lock(&cache.state);
            let snapshot = match cache.native_snapshot_locked(&state, epoch) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(step = "snapshot", code = %error.code, "publication snapshot failed");
                    return Err(error);
                }
            };
            let live = match state.native_certificate_live.clone() {
                Some(live) => live,
                None => {
                    tracing::warn!(step = "live", "publication live token missing");
                    return Err(unavailable());
                }
            };
            let at = state
                .coverage
                .as_ref()
                .map_or(self.env.clock.monotonic(), |coverage| coverage.captured_at);
            (snapshot, live, at)
        };
        let publication = SecretSnapshotPublication {
            node,
            env: self.env.clone(),
            execution,
            recovery,
            cache,
            live,
            epoch,
            until: at.saturating_add(self.runtime()?.settings.refresh),
        };
        if let Err(error) = publication.check_current() {
            tracing::warn!(
                step = "current",
                code = %error.code,
                message = %error.message,
                "publication check_current failed"
            );
            return Err(error);
        }
        if let Err(error) = self.probe_store_identity() {
            tracing::warn!(step = "probe", code = %error.code, "publication probe failed");
            return Err(error);
        }
        Ok((Arc::new(snapshot), publication))
    }
    // As SecretCache::values: the scrub inventory's shape is the API.
    #[allow(clippy::type_complexity)]
    pub fn secret_values(&self) -> Result<Vec<(String, Arc<Zeroizing<Vec<u8>>>)>, ApiError> {
        Ok(self.native_secret_snapshot()?.values)
    }
    fn secret_audit(&self, audit: &pb::Audit) -> Result<pb::Audit, ApiError> {
        if audit.reason.trim().is_empty() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "An audit reason is required",
            ));
        }
        let mut audit = audit.clone();
        let inventory = self.secret_values().ok();
        let patterns = inventory
            .as_ref()
            .map(|values| crate::effects::secret_patterns(values));
        audit.reason = crate::scrub::for_log(&audit.reason, patterns.as_deref());
        Ok(audit)
    }
    async fn secret_rows(&self, name: Option<&str>) -> Result<Vec<pb::SecretVersion>, ApiError> {
        let store = self.store().clone();
        let name = name.map(str::to_owned);
        self.env
            .blocking("secret-ledger-metadata", move || {
                store
                    .db()
                    .secret_versions(name.as_deref())
                    .map_err(crate::node::store_err)
            })
            .await
            .ok_or_else(unavailable)?
    }
    async fn secret_config_records(&self) -> Result<Vec<Record>, ApiError> {
        let store = self.store().clone();
        self.env
            .blocking("secret-config-history", move || {
                store.db().config_records().map_err(crate::node::store_err)
            })
            .await
            .ok_or_else(unavailable)?
    }
    async fn secret_format_floor(&self) -> Result<Option<u64>, ApiError> {
        let store = self.store().clone();
        self.env
            .blocking("secret-format-floor", move || {
                store
                    .db()
                    .secret_format_floor()
                    .map_err(crate::node::store_err)
            })
            .await
            .ok_or_else(unavailable)?
    }
    async fn secret_publish(&self, row: pb::SecretVersion) -> Result<(), ApiError> {
        self.commit(Record::SecretVersion(row.clone())).await?;
        self.runtime()?.cache.register(row);
        Ok(())
    }
    async fn next_secret_version(&self, name: &str) -> Result<u64, ApiError> {
        let store = self.store().clone();
        let name = name.to_owned();
        let high = self
            .env
            .blocking("secret-version-highwater", move || {
                store
                    .db()
                    .secret_highwater(&name)
                    .map_err(crate::node::store_err)
            })
            .await
            .ok_or_else(unavailable)??;
        high.checked_add(1)
            .filter(|version| *version <= MAX_SECRET_VERSION)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::SecretVersionExhausted,
                    "The secret version domain is exhausted",
                )
            })
    }
    fn secret_record(
        &self,
        scope: &Scope,
        version: u64,
        source_version: String,
        hash: Vec<u8>,
        deleted: bool,
        audit: pb::Audit,
    ) -> pb::SecretVersion {
        pb::SecretVersion {
            name: scope.name.clone(),
            version,
            version_hash: hash,
            backend: scope.backend.clone(),
            source_version,
            deleted,
            audit: Some(audit),
            r#ref: scope.reference.clone(),
            binding: scope.binding.clone(),
            link_generation: scope.generation,
            canonical_ref: scope.canonical.clone(),
            phase: Phase::Reserved as i32,
            hash_revision: revision(version),
        }
    }
    async fn admit_secret(
        &self,
        row: pb::SecretVersion,
        auth: AuthLease,
    ) -> Result<AdmittedSecret, ApiError> {
        self.commit_authorized(Record::SecretVersion(row.clone()), auth)
            .await?;
        self.runtime()?.cache.register(row.clone());
        Ok(AdmittedSecret(row))
    }
    async fn finish_secret(
        &self,
        admitted: AdmittedSecret,
        success: bool,
    ) -> Result<pb::SecretVersion, ApiError> {
        let mut row = admitted.0;
        row.phase = if success {
            Phase::Active as i32
        } else {
            Phase::Failed as i32
        };
        self.secret_publish(row.clone()).await?;
        Ok(row)
    }

    /// Local-only format migration and reconciliation; never contacts a provider.
    pub async fn initialize_secret_versions(
        &self,
        fresh_log_at_open: bool,
        original: AuthLease,
    ) -> Result<(), ApiError> {
        original.check()?;
        let Some(runtime) = &self.secret_runtime else {
            return Ok(());
        };
        let _guard = runtime.inventory.lock().await;
        let file_rows = runtime.file_rows().await?;
        let existing = self.secret_rows(None).await?;
        let floor = self.secret_format_floor().await?;
        let importing = floor.is_none() || floor == Some(LEGACY_SECRET_VERSION_MAX);
        if floor.is_none() {
            let fresh = fresh_log_at_open
                && runtime.file.fresh_at_open()
                && file_rows.is_empty()
                && existing.is_empty();
            self.commit(Record::SecretVersion(pb::SecretVersion {
                version: if fresh { 0 } else { LEGACY_SECRET_VERSION_MAX },
                phase: Phase::Fence as i32,
                audit: Some(system_audit(&self.env, "secret format initialization")),
                ..Default::default()
            }))
            .await?;
        }
        for row in existing {
            runtime.cache.register(row);
        }
        for stored in &file_rows {
            if runtime
                .cache
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .registry
                .contains_key(&(stored.meta.name.clone(), stored.meta.version))
            {
                continue;
            }
            // A wide orphan can only be an interrupted modern write, not legacy data.
            if !importing || stored.meta.version > LEGACY_SECRET_VERSION_MAX {
                continue;
            }
            let scope = Scope::file(&stored.meta.name, 0);
            let mut row = self.secret_record(
                &scope,
                stored.meta.version,
                stored.meta.version.to_string(),
                stored.meta.version_hash.clone(),
                stored.deletion_applied_wall_ms.is_some(),
                pb::Audit {
                    wall_time_ms: stored.meta.created_wall_ms,
                    ..system_audit(&self.env, "legacy secret import")
                },
            );
            row.phase = Phase::Active as i32;
            self.secret_publish(row).await?;
        }
        for mut pending in self
            .secret_rows(None)
            .await?
            .into_iter()
            .filter(|row| row.phase == Phase::Reserved as i32)
        {
            let matching = if pending.backend != "file" {
                false
            } else if pending.deleted {
                let through = pending
                    .source_version
                    .parse::<u64>()
                    .map_err(|_| unavailable())?;
                if through == 0 || through.to_string() != pending.source_version {
                    return Err(unavailable());
                }
                let file = runtime.file.clone();
                let name = pending.name.clone();
                self.env
                    .blocking("native-pending-deletion-floor", move || {
                        let matched = file
                            .stored_deletion_floor(&name)
                            .map_err(|_| unavailable())?
                            .is_some_and(|floor| floor.through_version >= through);
                        if matched {
                            file.sync_parent_directory().map_err(|_| unavailable())?;
                        }
                        Ok::<_, ApiError>(matched)
                    })
                    .await
                    .ok_or_else(unavailable)??
            } else {
                match runtime
                    .fetched(
                        &Scope::row(&pending),
                        Some(&pending.source_version),
                        original.clone(),
                    )
                    .await
                {
                    Ok(fetched) => runtime
                        .file
                        .version_hash(&pending.name, pending.version, &fetched.value)
                        .is_ok_and(|hash| hash == pending.version_hash),
                    Err(_) => false,
                }
            };
            pending.phase = if matching {
                Phase::Active as i32
            } else {
                Phase::Failed as i32
            };
            self.secret_publish(pending).await?;
        }
        runtime.initialized.store(true, Ordering::Release);
        // A file-only inventory can be made complete without startup network I/O.
        if runtime.backends.ids().next().is_none() {
            // Preload operational file bytes; closure certification below also
            // checks retained log references and snapshot metadata.
            for row in self
                .secret_rows(None)
                .await?
                .into_iter()
                .filter(|row| active(row) && !row.deleted)
            {
                match runtime
                    .fetched(
                        &Scope::row(&row),
                        Some(&row.source_version),
                        original.clone(),
                    )
                    .await
                {
                    Ok(fetched)
                        if runtime
                            .file
                            .version_hash(&row.name, row.version, &fetched.value)
                            .is_ok_and(|hash| hash == row.version_hash) =>
                    {
                        let _ = runtime.cache.insert(
                            &row,
                            Arc::new(fetched.value),
                            true,
                            Some(&fetched.stamp),
                        );
                    }
                    _ => {}
                }
            }
        }
        drop(_guard);
        if runtime.backends.ids().next().is_none() {
            // The startup records that follow (the installation identity, the
            // audit configuration, early grants) are scrubbed against the
            // certified inventory when they are written. A transient applier
            // lag at startup must not leave their reasons permanently
            // withheld, so certify before returning: the mode exits fast
            // while the applier is still pending, and a few bounded retries
            // outlast that window.
            for attempt in 0..50 {
                match self.refresh_secret_inventory(original.clone()).await {
                    Ok(()) => break,
                    Err(error) => {
                        tracing::warn!(
                            attempt,
                            code = %error.code,
                            message = %error.message,
                            "startup secret inventory certification retry"
                        );
                        self.env.clock.sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn secret_set(
        &self,
        name: &str,
        value: Vec<u8>,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<Option<SecretMeta>, ApiError> {
        let value = Zeroizing::new(value);
        auth.check()?;
        invalid_name(name)?;
        self.runtime()?.ready()?;
        let mut audit = audit.clone();
        if audit.reason.trim().is_empty() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "An audit reason is required",
            ));
        }
        let name = name.to_owned();
        owned(self, move |node| async move {
            let runtime = node.runtime()?;
            let _guard = runtime.name_lock(&name).lock_owned().await;
            auth.check()?;
            let config = node.config_now();
            if config
                .secret_link(&name)
                .is_some_and(|link| !link.backend.is_empty())
            {
                return Err(ApiError::new(
                    ErrorCode::SecretExternal,
                    "Unlink the secret before writing the built-in source",
                ));
            }
            let scope = Scope::config(&name, &config);
            // Match source text once: a new value must not rescrub a marker
            // generated by redaction against an older retained value.
            match node.secret_values() {
                Ok(values) => {
                    let mut patterns = crate::effects::secret_patterns(&values);
                    patterns.push((name.as_str(), value.as_slice()));
                    audit.reason = crate::scrub::for_log(&audit.reason, Some(&patterns));
                }
                Err(_) => audit.reason = crate::scrub::for_log(&audit.reason, None),
            }
            if dry_run {
                auth.check()?;
                return Ok(None);
            }
            let version = node.next_secret_version(&name).await?;
            let claims = node.secret_rows(Some(&name)).await?;
            let file = runtime.file.clone();
            let source_name = name.clone();
            let stored = node
                .env
                .blocking("native-secret-set-source-highwater", move || {
                    file.physical_highwater(&source_name)
                        .map_err(|_| unavailable())
                })
                .await
                .ok_or_else(unavailable)??;
            let physical =
                kronik_privacy::secret_backend::file::source_highwater(&name, &claims, None)
                    .map_err(backend_error)?
                    .max(stored)
                    .checked_add(1)
                    .filter(|physical| *physical <= MAX_SECRET_VERSION)
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::SecretVersionExhausted,
                            "The FILE source version domain is exhausted",
                        )
                    })?
                    .max(version);
            let hash = runtime
                .file
                .version_hash(&name, version, &value)
                .map_err(|_| unavailable())?;
            let row = node.secret_record(
                &scope,
                version,
                physical.to_string(),
                hash,
                false,
                audit.clone(),
            );
            let wait_auth = auth.clone();
            let admitted = node.admit_secret(row, auth).await?;
            let file = runtime.file.clone();
            let write_name = name.clone();
            let nonce = node.env.random_bytes::<24>();
            let wall = audit.wall_time_ms;
            let written = node
                .env
                .blocking("secret-file-set", move || {
                    file.set_at(
                        &write_name,
                        physical,
                        &value,
                        nonce,
                        wall,
                        &audit.token_id,
                        &audit.reason,
                    )
                    .map_err(|_| unavailable())?;
                    file.sync_parent_directory().map_err(|_| unavailable())?;
                    Ok::<_, ApiError>(value)
                })
                .await
                .ok_or_else(unavailable)?;
            let value = match written {
                Ok(value) => value,
                Err(error) => {
                    node.finish_secret(admitted, false).await?;
                    return Err(error);
                }
            };
            let row = node.finish_secret(admitted, true).await?;
            let stamp = runtime.finish_owned_file_change(&row).await?;
            runtime.cache.clear_negative(&scope);
            runtime
                .cache
                .insert(&row, Arc::new(value), true, Some(&stamp))
                .map_err(|_| committed_inventory_unavailable())?;
            drop(_guard);
            node.wait_secret_inventory(wait_auth)
                .await
                .map_err(|_| committed_inventory_unavailable())?;
            Ok(Some(meta(&row)))
        })
        .await
    }

    pub async fn secret_delete(
        &self,
        name: &str,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<u32, ApiError> {
        auth.check()?;
        invalid_name(name)?;
        self.runtime()?.ready()?;
        let audit = audit.clone();
        let name = name.to_owned();
        owned(self, move |node| async move {
            let runtime = node.runtime()?;
            let _guard = runtime.name_lock(&name).lock_owned().await;
            auth.check()?;
            let config = node.config_now();
            if config
                .secret_link(&name)
                .is_some_and(|link| !link.backend.is_empty())
            {
                return Err(ApiError::new(
                    ErrorCode::SecretExternal,
                    "Unlink the secret before deleting a built-in value",
                ));
            }
            let scope = Scope::config(&name, &config);
            let audit = node.secret_audit(&audit)?;
            let rows = node.secret_rows(Some(&name)).await?;
            let current = rows
                .iter()
                .rev()
                .find(|row| active(row) && row.backend == "file");
            if current.is_none_or(|row| row.deleted) {
                return Err(ApiError::new(
                    ErrorCode::SecretNotFound,
                    "The secret was not found",
                ));
            }
            if dry_run {
                auth.check()?;
                return Ok(0);
            }
            let mut key = (name.clone(), 0);
            for row in rows
                .iter()
                .filter(|row| active(row) && row.backend == "file" && !row.version_hash.is_empty())
            {
                key.1 = row.version;
                if !lock(&runtime.cache.state).values.contains_key(&key) {
                    let physical = kronik_privacy::secret_backend::file::source_highwater(
                        &name,
                        std::slice::from_ref(row),
                        None,
                    )
                    .map_err(backend_error)?;
                    let bytes = runtime.retained_file_bytes(&name, physical).await?;
                    if runtime
                        .file
                        .version_hash(&name, row.version, &bytes)
                        .map_err(|_| gone())?
                        != row.version_hash
                    {
                        return Err(gone());
                    }
                    runtime.cache.insert(row, Arc::new(bytes), false, None)?;
                }
            }
            let version = node.next_secret_version(&name).await?;
            let file = runtime.file.clone();
            let source_name = name.clone();
            let stored = node
                .env
                .blocking("native-secret-delete-source-highwater", move || {
                    file.physical_highwater(&source_name)
                        .map_err(|_| unavailable())
                })
                .await
                .ok_or_else(unavailable)??;
            let through =
                kronik_privacy::secret_backend::file::source_highwater(&name, &rows, None)
                    .map_err(backend_error)?
                    .max(stored);
            if through == 0 {
                return Err(unavailable());
            }
            let row = node.secret_record(
                &scope,
                version,
                through.to_string(),
                Vec::new(),
                true,
                audit.clone(),
            );
            let wait_auth = auth.clone();
            let admitted = node.admit_secret(row, auth).await?;
            Record::SecretVersion(admitted.0.clone())
                .validate()
                .map_err(|_| unavailable())?;
            let through_version = admitted
                .0
                .source_version
                .parse::<u64>()
                .map_err(|_| unavailable())?;
            if through_version.to_string() != admitted.0.source_version {
                return Err(unavailable());
            }
            runtime
                .cache
                .invalidate_file_operational(&name, through_version);
            let file = runtime.file.clone();
            let delete_name = name.clone();
            let worker_env = node.env.clone();
            let deleted = node
                .env
                .blocking("secret-file-delete", move || {
                    let applied_wall_ms = file
                        .stored_deletion_floor(&delete_name)
                        .map_err(|_| unavailable())?
                        .filter(|floor| floor.through_version >= through_version)
                        .map_or_else(|| worker_env.clock.wall_ms(), |floor| floor.applied_wall_ms);
                    let count = file
                        .delete(&delete_name, through_version, applied_wall_ms)
                        .map_err(|_| unavailable())?;
                    file.sync_parent_directory().map_err(|_| unavailable())?;
                    Ok::<u32, ApiError>(count)
                })
                .await
                .ok_or_else(unavailable)?;
            // A failed dirsync does not prove that the physical DELETE never committed.
            let count = deleted?;
            let row = node.finish_secret(admitted, true).await?;
            runtime.finish_owned_file_change(&row).await?;
            drop(_guard);
            node.wait_secret_inventory(wait_auth)
                .await
                .map_err(|_| committed_inventory_unavailable())?;
            Ok(count)
        })
        .await
    }

    pub async fn secret_link(
        &self,
        name: &str,
        backend: &str,
        reference: &str,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<(pb::SecretLink, Option<u64>), ApiError> {
        self.secret_change_link(name, Some((backend, reference)), audit, dry_run, auth)
            .await
    }
    pub async fn secret_unlink(
        &self,
        name: &str,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<(pb::SecretLink, Option<u64>), ApiError> {
        self.secret_change_link(name, None, audit, dry_run, auth)
            .await
    }
    async fn secret_change_link(
        &self,
        name: &str,
        destination: Option<(&str, &str)>,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<(pb::SecretLink, Option<u64>), ApiError> {
        auth.check()?;
        invalid_name(name)?;
        self.runtime()?.ready()?;
        let audit = audit.clone();
        let name = name.to_owned();
        let destination =
            destination.map(|(backend, reference)| (backend.to_owned(), reference.to_owned()));
        owned(self, move |node| async move {
            let runtime = node.runtime()?;
            // Configuration first in the lock order, as for other epoch changes.
            let deploy = node.lock_deploy_authorized(&auth).await?;
            let _guard = runtime.name_lock(&name).lock_owned().await;
            auth.check()?;
            let mut audit = node.secret_audit(&audit)?;
            if destination.is_some() {
                audit.reason = crate::scrub::for_log(&audit.reason, None);
            }
            let config = node.config_now();
            let old = config.secret_link(&name);
            let generation = old
                .as_ref()
                .map_or(Some(1), |old| old.generation.checked_add(1))
                .filter(|generation| *generation <= i64::MAX as u64)
                .ok_or_else(unavailable)?;
            let epoch = node
                .epoch()
                .checked_add(1)
                .filter(|epoch| *epoch <= i64::MAX as u64)
                .ok_or_else(unavailable)?;
            let mut link = pb::SecretLink {
                name: name.clone(),
                generation,
                epoch,
                audit: Some(audit),
                ..Default::default()
            };
            if let Some((backend, reference)) = destination {
                let source = runtime.backends.get(&backend).ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::SecretBackendUnknown,
                        "The secret backend is not configured",
                    )
                })?;
                if !source.allows(&reference) {
                    return Err(ApiError::new(
                        ErrorCode::SecretRefNotAllowed,
                        "The reference is not allowed by trusted backend configuration",
                    ));
                }
                let fetched = node
                    .env
                    .timeout(
                        runtime.settings.fetch_timeout,
                        source.client.current(&reference, auth.clone()),
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(backend_error)?;
                if fetched.canonical_ref.is_empty() || fetched.source_version.is_empty() {
                    return Err(gone());
                }
                link.backend = backend;
                link.r#ref = reference;
                link.binding = source.binding.clone();
                link.canonical_ref = fetched.canonical_ref;
            } else if old.as_ref().is_none_or(|old| old.backend.is_empty()) {
                return Err(ApiError::new(
                    ErrorCode::SecretNotFound,
                    "The secret has no external link",
                ));
            }
            if dry_run {
                auth.check()?;
                return Ok((link, None));
            }
            let wait_auth = auth.clone();
            let lsn = node
                .commit_config_authorized(deploy, epoch, Record::SecretLink(link.clone()), auth)
                .await?;
            drop(_guard);
            node.wait_secret_inventory(wait_auth)
                .await
                .map_err(|_| committed_inventory_unavailable())?;
            Ok((link, Some(lsn)))
        })
        .await
    }

    pub async fn secret_refresh(
        &self,
        name: &str,
        audit: &pb::Audit,
        dry_run: bool,
        auth: AuthLease,
    ) -> Result<Option<SecretMeta>, ApiError> {
        auth.check()?;
        invalid_name(name)?;
        self.runtime()?.ready()?;
        let audit = audit.clone();
        let name = name.to_owned();
        owned(self, move |node| async move {
            let runtime = node.runtime()?;
            let _guard = runtime.name_lock(&name).lock_owned().await;
            let mut audit = node.secret_audit(&audit)?;
            let scope = Scope::config(&name, &node.config_now());
            if scope.backend != "file" {
                audit.reason = crate::scrub::for_log(&audit.reason, None);
            }
            let source_version = node.file_current_source(&scope).await?;
            if dry_run {
                auth.check()?;
                let fetched = runtime
                    .fetched(&scope, source_version.as_deref(), auth.clone())
                    .await
                    .map_err(backend_error)?;
                runtime
                    .validate(&scope, &fetched, source_version.as_deref())
                    .map_err(backend_error)?;
                auth.check()?;
                return Ok(None);
            }
            node.await_secret_inventory().await;
            let intent =
                node.audit_event_record("secret.refresh", &name, Default::default(), audit)?;
            let Record::AuditEvent(mut failed) = intent.clone() else {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "Invalid secret refresh intent",
                ));
            };
            node.commit_authorized(intent, auth.clone()).await?;
            let wait_auth = auth.clone();
            let refreshed = async {
                let fetched = runtime
                    .fetched(&scope, source_version.as_deref(), auth.clone())
                    .await
                    .map_err(|error| {
                        runtime.cache.failure(&scope, error);
                        backend_error(error)
                    })?;
                if let Err(error) = runtime.validate(&scope, &fetched, source_version.as_deref()) {
                    runtime.cache.failure(&scope, error);
                    return Err(backend_error(error));
                }
                node.observe_secret_authorized(&scope, fetched, auth)
                    .await
                    .map(|row| Some(meta(&row)))
            }
            .await;
            if let Err(error) = &refreshed {
                failed.action = "secret.refresh.failed".into();
                failed
                    .details
                    .insert("code".into(), error.code.as_str().into());
                node.commit(Record::AuditEvent(failed)).await?;
            }
            drop(_guard);
            if refreshed.is_ok() {
                node.wait_secret_inventory(wait_auth)
                    .await
                    .map_err(|_| committed_inventory_unavailable())?;
            }
            refreshed
        })
        .await
    }
    pub async fn secret_history(&self, name: &str) -> Result<Vec<pb::SecretVersion>, ApiError> {
        invalid_name(name)?;
        self.secret_rows(Some(name)).await
    }
    /// Committed observations for one captured configuration; this never fetches values.
    pub async fn secret_list(&self) -> Result<(Vec<SecretMeta>, Vec<pb::SecretLink>), ApiError> {
        self.runtime()?.ready()?;
        let config = self.config_now();
        let rows = self.secret_rows(None).await?;
        let mut current: BTreeMap<&str, &pb::SecretVersion> = BTreeMap::new();
        for row in &rows {
            if !active(row) {
                continue;
            }
            let link = config.secret_link(&row.name);
            let matches = match link.filter(|link| !link.backend.is_empty()) {
                Some(link) => {
                    row.backend == link.backend
                        && row.binding == link.binding
                        && row.r#ref == link.r#ref
                        && row.canonical_ref == link.canonical_ref
                        && row.link_generation == link.generation
                }
                None => {
                    row.backend == "file"
                        && row.binding == "file"
                        && row.r#ref == row.name
                        && row.canonical_ref == row.name
                        && row.link_generation == link.map_or(0, |link| link.generation)
                }
            };
            if matches
                && current
                    .get(row.name.as_str())
                    .is_none_or(|previous| previous.version < row.version)
            {
                current.insert(&row.name, row);
            }
        }
        let values = current
            .into_values()
            .filter(|row| !row.deleted)
            .map(meta)
            .collect();
        Ok((values, config.secret_links().cloned().collect()))
    }
    pub fn secret_backends(&self) -> Vec<SecretBackendStatus> {
        let Some(runtime) = &self.secret_runtime else {
            return Vec::new();
        };
        let complete = runtime.cache.complete(self.epoch());
        let mut result = vec![SecretBackendStatus {
            id: "file".into(),
            kind: "file".into(),
            binding: "file".into(),
            configured: true,
            inventory_complete: complete,
        }];
        for id in runtime.backends.ids() {
            if let Some(source) = runtime.backends.get(id) {
                result.push(SecretBackendStatus {
                    id: id.into(),
                    kind: source.kind.into(),
                    binding: source.binding.clone(),
                    configured: true,
                    inventory_complete: complete,
                });
            }
        }
        result
    }

    async fn file_current_source(&self, scope: &Scope) -> Result<Option<String>, ApiError> {
        if scope.backend != "file" {
            return Ok(None);
        }
        let row = self
            .secret_rows(Some(&scope.name))
            .await?
            .into_iter()
            .rev()
            .find(|row| active(row) && row.backend == "file");
        match row {
            Some(row) if !row.deleted => Ok(Some(row.source_version)),
            _ => Err(ApiError::new(
                ErrorCode::SecretNotFound,
                "The secret was not found",
            )),
        }
    }
    async fn known_secret_observation(
        &self,
        scope: &Scope,
        fetched: &StampedFetched,
    ) -> Result<Option<pb::SecretVersion>, ApiError> {
        let runtime = self.runtime()?;
        runtime
            .validate(scope, fetched, None)
            .map_err(backend_error)?;
        let existing = self
            .secret_rows(Some(&scope.name))
            .await?
            .into_iter()
            .find(|row| {
                active(row)
                    && !row.deleted
                    && Scope::row(row) == *scope
                    && row.source_version == fetched.source_version
            });
        if let Some(row) = &existing
            && runtime
                .file
                .version_hash(&row.name, row.version, &fetched.value)
                .map_err(|_| gone())?
                != row.version_hash
        {
            runtime.cache.failure(scope, BackendError::Invalid);
            return Err(gone());
        }
        Ok(existing)
    }
    fn hold_secret_observation(
        &self,
        scope: &Scope,
        row: &pb::SecretVersion,
        bytes: Arc<Zeroizing<Vec<u8>>>,
        operational: bool,
        stamp: &ReadStamp,
    ) -> Result<(), ApiError> {
        let runtime = self.runtime()?;
        runtime.cache.register(row.clone());
        runtime.cache.clear_negative_version(
            scope,
            if operational {
                None
            } else {
                Some(row.source_version.as_str())
            },
        );
        runtime.cache.insert(row, bytes, operational, Some(stamp))?;
        if operational {
            lock(&runtime.cache.state)
                .current
                .insert(scope.clone(), (row.name.clone(), row.version));
        }
        Ok(())
    }
    async fn observe_secret(
        &self,
        scope: &Scope,
        fetched: StampedFetched,
        audit: pb::Audit,
        operational: bool,
        original: AuthLease,
    ) -> Result<pb::SecretVersion, ApiError> {
        let runtime = self.runtime()?;
        if let Some(row) = self.known_secret_observation(scope, &fetched).await? {
            let mut bytes = Some(Arc::new(fetched.value));
            original.admit(&mut || {
                self.hold_secret_observation(
                    scope,
                    &row,
                    bytes.take().ok_or_else(unavailable)?,
                    operational,
                    &fetched.stamp,
                )
            })?;
            if bytes.is_some() {
                return Err(unavailable());
            }
            return Ok(row);
        }
        let version = self.next_secret_version(&scope.name).await?;
        let hash = runtime
            .file
            .version_hash(&scope.name, version, &fetched.value)
            .map_err(|_| unavailable())?;
        let row = self.secret_record(
            scope,
            version,
            fetched.source_version.clone(),
            hash,
            false,
            audit,
        );
        let admitted = self.admit_secret(row, original).await?;
        let row = self.finish_secret(admitted, true).await?;
        self.hold_secret_observation(
            scope,
            &row,
            Arc::new(fetched.value),
            operational,
            &fetched.stamp,
        )?;
        Ok(row)
    }

    async fn observe_secret_authorized(
        &self,
        scope: &Scope,
        fetched: StampedFetched,
        auth: AuthLease,
    ) -> Result<pb::SecretVersion, ApiError> {
        if let Some(row) = self.known_secret_observation(scope, &fetched).await? {
            let node = self.me().ok_or_else(unavailable)?;
            let scope = scope.clone();
            return self
                .authorized_effect(auth, move || async move {
                    node.hold_secret_observation(
                        &scope,
                        &row,
                        Arc::new(fetched.value),
                        true,
                        &fetched.stamp,
                    )?;
                    Ok(row)
                })
                .await;
        }
        let runtime = self.runtime()?;
        let version = self.next_secret_version(&scope.name).await?;
        let hash = runtime
            .file
            .version_hash(&scope.name, version, &fetched.value)
            .map_err(|_| unavailable())?;
        let row = self.secret_record(
            scope,
            version,
            fetched.source_version.clone(),
            hash,
            false,
            system_audit(&self.env, "explicit secret refresh observation"),
        );
        let admitted = self.admit_secret(row, auth).await?;
        let row = self.finish_secret(admitted, true).await?;
        self.hold_secret_observation(scope, &row, Arc::new(fetched.value), true, &fetched.stamp)?;
        Ok(row)
    }

    /// Exact replay uses the recorded ledger identity and the admitted epoch;
    /// no metadata field ever chooses a provider client or endpoint.
    pub async fn resolve_secret(
        &self,
        name: &str,
        version: Option<u64>,
        config: &Config,
        original: AuthLease,
    ) -> Result<Option<SecretValue>, ApiError> {
        original.check()?;
        invalid_name(name)?;
        let Some(runtime) = &self.secret_runtime else {
            return Ok(None);
        };
        runtime.ready()?;
        let scope = Scope::config(name, config);
        if !runtime.cache.trusted(&scope) {
            runtime.cache.failure(&scope, BackendError::Invalid);
            return Err(gone());
        }
        if let Ok(Some(value)) = runtime.cache.cached(name, version, config) {
            return Ok(Some(value));
        }
        let exact_source = version.and_then(|_| {
            runtime
                .cache
                .row(&scope, version)
                .map(|row| row.source_version)
        });
        let started = self.env.clock.monotonic();
        let node = self.me().ok_or_else(unavailable)?;
        let work_scope = scope.clone();
        // The task retains the name lock through durable publication even when
        // the turn's deadline fires or its waiting request is disconnected.
        let work = self.env.spawn("secret-resolve", async move {
            node.resolve_secret_cold(work_scope, version, started, original)
                .await
        });
        match self.env.timeout(runtime.settings.fetch_timeout, work).await {
            Ok(Some(result)) => result,
            Ok(None) => Err(unavailable()),
            Err(_) => {
                runtime.cache.failure_version(
                    &scope,
                    exact_source.as_deref(),
                    BackendError::Unavailable,
                );
                Err(unavailable())
            }
        }
    }

    async fn resolve_secret_cold(
        &self,
        scope: Scope,
        version: Option<u64>,
        started: Duration,
        original: AuthLease,
    ) -> Result<Option<SecretValue>, ApiError> {
        let runtime = self.runtime()?;
        let remaining = || {
            runtime
                .settings
                .fetch_timeout
                .saturating_sub(self.env.clock.monotonic().saturating_sub(started))
        };
        if remaining().is_zero() {
            return Err(unavailable());
        }
        let _guard = self
            .env
            .timeout(remaining(), runtime.name_lock(&scope.name).lock_owned())
            .await
            .map_err(|_| unavailable())?;
        original.check()?;
        let name = &scope.name;
        let row = runtime.cache.row(&scope, version);
        if version.is_some() && row.as_ref().is_none_or(|row| !active(row) || row.deleted) {
            return Err(gone());
        }
        let exact_source =
            version.and_then(|_| row.as_ref().map(|row| row.source_version.as_str()));
        if let Some(error) = runtime.cache.negative_version(&scope, exact_source) {
            if error == BackendError::Unavailable
                && let Some(row) = &row
                && let Some(bytes) = runtime.cache.held(row, true)
            {
                return Ok(Some(SecretValue {
                    meta: meta(row),
                    value: bytes.to_vec(),
                }));
            }
            if error == BackendError::NotFound && version.is_none() {
                return Ok(None);
            }
            return Err(backend_error(error));
        }
        if row.as_ref().is_some_and(|row| row.deleted) {
            return Ok(None);
        }
        if let Some(row) = &row
            && let Some(bytes) = runtime.cache.held(row, false)
        {
            return Ok(Some(SecretValue {
                meta: meta(row),
                value: bytes.to_vec(),
            }));
        }
        let source_version = match &row {
            Some(row) if version.is_some() => Some(row.source_version.clone()),
            _ => match self.file_current_source(&scope).await {
                Ok(source) => source,
                Err(error) if error.code == ErrorCode::SecretNotFound && version.is_none() => {
                    return Ok(None);
                }
                Err(error) => {
                    return Err(error);
                }
            },
        };
        if remaining().is_zero() {
            return Err(unavailable());
        }
        let result = self
            .env
            .timeout(
                remaining(),
                runtime.fetched(&scope, source_version.as_deref(), original.clone()),
            )
            .await
            .unwrap_or(Err(BackendError::Unavailable));
        original.check()?;
        let fetched = match result {
            Ok(fetched) => fetched,
            Err(error) => {
                runtime.cache.failure_version(&scope, exact_source, error);
                if error == BackendError::Unavailable
                    && let Some(row) = &row
                    && let Some(bytes) = runtime.cache.held(row, true)
                {
                    return Ok(Some(SecretValue {
                        meta: meta(row),
                        value: bytes.to_vec(),
                    }));
                }
                if error == BackendError::NotFound && version.is_none() {
                    return Ok(None);
                }
                return Err(
                    if version.is_some()
                        && !matches!(
                            error,
                            BackendError::Unavailable | BackendError::Unauthorized
                        )
                    {
                        gone()
                    } else {
                        backend_error(error)
                    },
                );
            }
        };
        if let Err(error) = runtime.validate(&scope, &fetched, source_version.as_deref()) {
            runtime.cache.failure_version(&scope, exact_source, error);
            return Err(gone());
        }
        let resolved = if let Some(row) = row.filter(|_| version.is_some()) {
            if runtime
                .file
                .version_hash(name, row.version, &fetched.value)
                .map_err(|_| gone())?
                != row.version_hash
            {
                runtime.cache.failure(&scope, BackendError::Invalid);
                return Err(gone());
            }
            let mut bytes = Some(Arc::new(fetched.value));
            original.admit(&mut || {
                runtime
                    .cache
                    .clear_negative_version(&scope, Some(&row.source_version));
                runtime.cache.insert(
                    &row,
                    bytes.take().ok_or_else(unavailable)?,
                    true,
                    Some(&fetched.stamp),
                )
            })?;
            if bytes.is_some() {
                return Err(unavailable());
            }
            row
        } else {
            self.observe_secret(
                &scope,
                fetched,
                system_audit(&self.env, "secret source observation"),
                true,
                original,
            )
            .await?
        };
        let bytes = runtime
            .cache
            .held(&resolved, false)
            .ok_or_else(unavailable)?;
        Ok(Some(SecretValue {
            meta: meta(&resolved),
            value: bytes.to_vec(),
        }))
    }

    pub async fn secret_identity(
        &self,
        branch: &str,
        name: &str,
        version: u64,
    ) -> Result<pb::SecretVersion, ApiError> {
        if branch != self.branch() {
            return Err(gone());
        }
        invalid_name(name)?;
        self.secret_rows(Some(name))
            .await?
            .into_iter()
            .find(|row| row.version == version && active(row) && !row.deleted)
            .ok_or_else(gone)
    }
    pub async fn secret_hmac(
        &self,
        branch: &str,
        expected: &pb::SecretVersion,
        message: &[u8],
        original: AuthLease,
    ) -> Result<[u8; 32], ApiError> {
        original.check()?;
        let committed = self
            .secret_identity(branch, &expected.name, expected.version)
            .await?;
        if !same_identity(&committed, expected) {
            return Err(gone());
        }
        let records = self.secret_config_records().await?;
        let link = records.iter().find_map(|record| match record {
            Record::SecretLink(link)
                if link.name == committed.name && link.generation == committed.link_generation =>
            {
                Some(link)
            }
            _ => None,
        });
        let mut config = Config::default();
        if committed.link_generation != 0 {
            config.apply(&Record::SecretLink(link.ok_or_else(gone)?.clone()));
        }
        let runtime = self.runtime()?;
        runtime.ready()?;
        let scope = Scope::config(&committed.name, &config);
        if scope != Scope::row(&committed) || !runtime.cache.trusted(&scope) {
            return Err(gone());
        }
        let stale = match runtime
            .cache
            .negative_version(&scope, Some(&committed.source_version))
        {
            Some(BackendError::Unavailable) => true,
            Some(error) => return Err(backend_error(error)),
            None => false,
        };
        let held = runtime.cache.held(&committed, stale);
        // A pinned MAC must not publish operational cache values inside its caller's data fence.
        let fetched = if held.is_none() && !stale {
            let fetched = self
                .env
                .timeout(
                    runtime.settings.fetch_timeout,
                    runtime.fetched_pinned(&committed, original.clone()),
                )
                .await
                .unwrap_or(Err(BackendError::Unavailable));
            original.check()?;
            match fetched {
                Ok(fetched) => Some(fetched),
                Err(BackendError::Unavailable) => None,
                Err(error) => {
                    runtime
                        .cache
                        .failure_version(&scope, Some(&committed.source_version), error);
                    return Err(gone());
                }
            }
        } else {
            None
        };
        let fallback = if !stale && held.is_none() && fetched.is_none() {
            runtime.cache.held(&committed, true)
        } else {
            None
        };
        let bytes = held
            .as_ref()
            .or(fallback.as_ref())
            .map(|bytes| bytes.as_slice())
            .or_else(|| fetched.as_ref().map(|fetched| fetched.value.as_slice()))
            .ok_or_else(unavailable)?;
        let result = Zeroizing::new(kronik_effects::crypto::hmac_sha256(bytes, message));
        let current = self
            .secret_identity(branch, &expected.name, expected.version)
            .await?;
        if !same_identity(&current, expected) {
            return Err(gone());
        }
        let mut prepared: Option<[u8; 32]> =
            Some(result.as_slice().try_into().map_err(|_| unavailable())?);
        let mut output = None;
        original.admit(&mut || {
            output = Some(prepared.take().ok_or_else(unavailable)?);
            Ok(())
        })?;
        output.ok_or_else(unavailable)
    }

    /// Collect the retained ledger/state/snapshot closure and every retained
    /// provider catalogue for a name that has ever had reveal authority.
    pub async fn refresh_secret_inventory(&self, original: AuthLease) -> Result<(), ApiError> {
        let through = self
            .refresh_secret_inventory_mode(original.clone(), false)
            .await?;
        self.persist_coverage_watermark(through).await;
        Ok(())
    }

    /// Wakes the background rebuild from a reader's demand.
    pub(crate) fn wake_rebuild(&self) {
        if let Some(runtime) = &self.secret_runtime {
            runtime.cache.revision_changed.notify_one();
        }
    }

    /// The fetch budget for transient secret-coverage windows.
    pub(crate) fn fetch_timeout_for_coverage(&self) -> Duration {
        self.secret_runtime
            .as_ref()
            .map_or(Duration::from_secs(2), |runtime| {
                runtime.settings.fetch_timeout
            })
    }

    /// Best-effort bounded wait for a certified secret inventory before an
    /// audit reason is scrubbed. A transient rebuild window must not
    /// permanently lose an operator's reason, and a read-only demand wakes
    /// the rebuild; when the budget expires the caller proceeds with the
    /// fail-closed withholding, never with a plaintext reason.
    pub(crate) async fn await_secret_inventory(&self) {
        let Some(runtime) = &self.secret_runtime else {
            return;
        };
        let deadline = self
            .env
            .clock
            .monotonic()
            .saturating_add(runtime.settings.fetch_timeout);
        // No extra wake here: the retire itself notifies the rebuild, and a
        // per-poll notify would churn the cycle while a whole scan runs.
        while !runtime.cache.complete(self.epoch()) {
            if self.env.clock.monotonic() >= deadline {
                return;
            }
            self.env.clock.sleep(Duration::from_millis(10)).await;
        }
    }

    /// Persists the coverage watermark after a fully successful refresh: a
    /// restart then certifies the prefix from it and re-scans only the log
    /// that came after. `through` is the last record the refresh's scan read
    /// (or an earlier scan had), never the applied LSN of the moment: records
    /// applied while the refresh ran are for the next one to read. Never
    /// propagated — a failed persist only costs the next restart its delta
    /// (the manifest is a daemon-local cache).
    async fn persist_coverage_watermark(&self, through: u64) {
        let Some(storage) = self.storage_config() else {
            return;
        };
        // An empty log has nothing to resume after.
        if through == 0 {
            return;
        }
        let Some(runtime) = &self.secret_runtime else {
            return;
        };
        // One writer at a time: two refreshes finish apart from the
        // inventory lock, and both write through the same temporary file.
        let _writing = runtime.watermark_io.lock().await;
        let Ok(snapshot) = self.native_secret_snapshot() else {
            return;
        };
        let store_generation = runtime
            .file
            .generation()
            .map(|generation| kronik_core::ids::hex(&generation))
            .unwrap_or_default();
        coverage::persist(
            &self.env,
            &storage.data_dir.clone(),
            &coverage::CoverageWatermark {
                schema: coverage::SCHEMA.into(),
                branch: self.branch().to_owned(),
                certified_through_lsn: through,
                coverage_epoch: self.epoch(),
                coverage_fingerprint: kronik_core::ids::hex(&snapshot.fingerprint),
                store_generation,
            },
        )
        .await;
    }

    pub(crate) async fn recertify_cached_secret_inventory(&self) -> Result<bool, ApiError> {
        if self.secret_runtime.is_none() {
            return Ok(false);
        }
        let original = self.native_recovery_authority()?;
        match self.refresh_secret_inventory_mode(original, true).await {
            Ok(_) => Ok(true),
            Err(error) if error.code == ErrorCode::SecretUnavailable => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Certifies the inventory. Returns the last LSN the log has been read
    /// through for it: the scan's bound, 0 when there is no inventory.
    async fn refresh_secret_inventory_mode(
        &self,
        original: AuthLease,
        cached_only: bool,
    ) -> Result<u64, ApiError> {
        original.check()?;
        let Some(runtime) = &self.secret_runtime else {
            return Ok(0);
        };
        runtime.ready()?;
        let _guard = if cached_only {
            None
        } else {
            Some(runtime.inventory.lock().await)
        };
        let started = self.env.clock.monotonic();
        runtime
            .stats
            .builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let file_changes = runtime.cache.capture_file_changes()?;
        let native_revision = lock(&runtime.cache.state)
            .native_current
            .capture_revision()
            .ok_or_else(unavailable)?;
        let prior = if cached_only {
            Some(
                lock(&runtime.cache.state)
                    .native_catalogue_capture
                    .clone()
                    .ok_or_else(unavailable)?,
            )
        } else {
            None
        };
        let captured_at = prior
            .as_ref()
            .map_or_else(|| self.env.clock.monotonic(), |capture| capture.at);
        if self.env.clock.monotonic().saturating_sub(captured_at) > runtime.settings.refresh {
            return Err(unavailable());
        }
        if !cached_only {
            runtime.cache.clear_coverage();
        }
        let epoch = self.epoch();
        let floor = self.secret_format_floor().await?.ok_or_else(unavailable)?;
        let mut records = self.secret_config_records().await?;
        let mut required = BTreeMap::new();
        for row in self.secret_rows(None).await? {
            required.insert((row.name.clone(), row.version), row);
        }
        self.retained_snapshot_secrets(&mut required, &mut records)
            .await?;
        // Modern values cannot enter state or snapshots without this durable ledger.
        // Legacy effect references supply missing-row evidence before any disclosure.
        let first = self
            .reader()
            .starts()
            .await
            .map_err(|_| unavailable())?
            .into_iter()
            .next();
        // The log is read up to `scanned`. Without a storage config there
        // is no watermark location and the refresh falls back to the full
        // scan instead of failing; a watermark that is ahead of the applied
        // log, or belongs to another store, covers nothing this log holds.
        let scanned = self.applied_lsn();
        let watermark = match self.storage_config() {
            Some(storage) => coverage::load(&self.env, &storage.data_dir.clone(), self.branch())
                .await
                .filter(|watermark| {
                    watermark.certified_through_lsn <= scanned
                        && watermark.store_generation
                            == runtime
                                .file
                                .generation()
                                .map(|generation| kronik_core::ids::hex(&generation))
                                .unwrap_or_default()
                }),
            None => None,
        };
        let scan_from = first.map(|first| match &watermark {
            Some(watermark) => {
                let through = watermark.certified_through_lsn;
                // The watermark must stay inside the retained log and cover
                // only what this branch's log can still re-read.
                if through.saturating_add(1) > first {
                    through.saturating_add(1)
                } else {
                    first
                }
            }
            None => first,
        });
        // The records the watermark does not cover, once: their references
        // must be ones the ledger knows (the references of the covered
        // prefix were checked when it was certified), and their names are
        // the ones the new certificate vouches for.
        let mut references = BTreeMap::new();
        let mut touched_names = BTreeSet::new();
        let mut records_read = 0;
        if let Some(scan_from) = scan_from {
            let scan = self.scan_secret_use(scan_from, scanned).await?;
            references = scan.references;
            touched_names = scan.touched;
            records_read = scan.records;
        }
        for (key, hash) in &references {
            if !required
                .get(key)
                .is_some_and(|row| active(row) && row.version_hash == *hash)
            {
                return Err(unavailable());
            }
        }
        if required.len() > MAX_INVENTORY_VALUES {
            return Err(unavailable());
        }
        for row in required.values() {
            runtime.cache.register(row.clone());
        }
        let mut reveal_names = BTreeSet::new();
        let mut catalogues = BTreeSet::new();
        for record in &records {
            match record {
                Record::Grant(grant) => {
                    if let Some(name) = grant.capability.strip_prefix("secret-reveal:") {
                        reveal_names.insert(name.to_owned());
                    }
                }
                Record::ForeignActor(actor) => {
                    reveal_names.extend(actor.secrets.iter().cloned());
                }
                _ => {}
            }
        }
        if !reveal_names.is_empty()
            && self.secret_format_floor().await? == Some(LEGACY_SECRET_VERSION_MAX)
            && first != Some(1)
        {
            return Err(unavailable());
        }
        for record in &records {
            if let Record::SecretLink(link) = record
                && !link.backend.is_empty()
                && reveal_names.contains(&link.name)
            {
                catalogues.insert(Scope::link(link));
            }
        }
        if let Some(prior) = &prior
            && !catalogues.is_subset(&prior.scopes)
        {
            return Err(unavailable());
        }
        for scope in &catalogues {
            if cached_only {
                continue;
            }
            let _name = runtime.name_lock(&scope.name).lock_owned().await;
            let source = runtime.source(scope)?;
            let mut cursor = None;
            let mut cursors = BTreeSet::new();
            let mut ids = BTreeSet::new();
            let mut complete = false;
            for _ in 0..MAX_CATALOGUE_PAGES {
                let page = match self
                    .env
                    .timeout(
                        runtime.settings.fetch_timeout,
                        source.client.versions(
                            &scope.reference,
                            cursor.as_deref(),
                            original.clone(),
                        ),
                    )
                    .await
                {
                    Ok(Ok(page)) => page,
                    result => {
                        let error = match result {
                            Ok(Err(error)) => error,
                            _ => BackendError::Unavailable,
                        };
                        runtime.cache.failure(scope, error);
                        return Err(unavailable());
                    }
                };
                if page.canonical_ref != scope.canonical {
                    runtime.cache.failure(scope, BackendError::Invalid);
                    return Err(unavailable());
                }
                for id in page.ids {
                    if id.is_empty()
                        || id.len() > 4096
                        || id.chars().any(char::is_control)
                        || !ids.insert(id.clone())
                    {
                        return Err(unavailable());
                    }
                    if ids.len() > MAX_INVENTORY_VALUES {
                        return Err(unavailable());
                    }
                    let fetched = runtime
                        .fetched(scope, Some(&id), original.clone())
                        .await
                        .map_err(|error| {
                            runtime.cache.failure_version(scope, Some(&id), error);
                            unavailable()
                        })?;
                    runtime
                        .validate(scope, &fetched, Some(&id))
                        .map_err(|_| unavailable())?;
                    let row = self
                        .observe_secret(
                            scope,
                            fetched,
                            system_audit(&self.env, "retained secret catalogue observation"),
                            false,
                            original.clone(),
                        )
                        .await?;
                    required.insert((row.name.clone(), row.version), row);
                }
                match page.next {
                    None => {
                        complete = true;
                        break;
                    }
                    Some(next)
                        if !next.is_empty()
                            && next.len() <= 8192
                            && cursors.insert(next.clone()) =>
                    {
                        cursor = Some(next);
                    }
                    _ => return Err(unavailable()),
                }
            }
            if !complete {
                return Err(unavailable());
            }
        }
        // Merge observations that raced the first registry snapshot before
        // capturing the revision that will authorize publication.
        for row in self.secret_rows(None).await? {
            required.insert((row.name.clone(), row.version), row.clone());
            runtime.cache.register(row);
        }
        let revision = lock(&runtime.cache.state).revision;
        for row in required.values().filter(|row| active(row)) {
            if row.deleted && row.version_hash.is_empty() {
                continue;
            }
            let key = (row.name.clone(), row.version);
            if lock(&runtime.cache.state).values.contains_key(&key) {
                continue;
            }
            if cached_only {
                return Err(unavailable());
            }
            let scope = Scope::row(row);
            if !runtime.cache.trusted(&scope) {
                return Err(unavailable());
            }
            let bytes = if row.backend == "file" {
                let physical = row
                    .source_version
                    .parse::<u64>()
                    .map_err(|_| unavailable())?;
                if physical.to_string() != row.source_version {
                    return Err(unavailable());
                }
                runtime.retained_file_bytes(&row.name, physical).await?
            } else {
                let fetched = runtime
                    .fetched(&scope, Some(&row.source_version), original.clone())
                    .await
                    .map_err(|error| {
                        runtime
                            .cache
                            .failure_version(&scope, Some(&row.source_version), error);
                        unavailable()
                    })?;
                runtime
                    .validate(&scope, &fetched, Some(&row.source_version))
                    .map_err(|_| unavailable())?;
                fetched.value
            };
            if runtime
                .file
                .version_hash(&row.name, row.version, &bytes)
                .map_err(|_| unavailable())?
                != row.version_hash
            {
                return Err(unavailable());
            }
            runtime.cache.insert(row, Arc::new(bytes), false, None)?;
        }
        let file_rows = runtime.file_rows().await?;
        if let Some(prior) = &prior
            && (file_rows.len() != prior.file_rows.len()
                || file_rows
                    .iter()
                    .zip(&prior.file_rows)
                    .any(|(current, prior)| {
                        current.meta.name != prior.meta.name
                            || current.meta.version != prior.meta.version
                            || current.meta.version_hash != prior.meta.version_hash
                            || current.deletion_applied_wall_ms.is_some()
                                != prior.deletion_applied_wall_ms.is_some()
                    }))
        {
            return Err(unavailable());
        }
        for stored in &file_rows {
            let cached = {
                let state = lock(&runtime.cache.state);
                state
                    .scrub_file
                    .get(&(stored.meta.name.clone(), stored.meta.version))
                    .cloned()
                    .or_else(|| {
                        state
                            .registry
                            .iter()
                            .filter(|(_, row)| {
                                row.backend == "file"
                                    && row.name == stored.meta.name
                                    && row.source_version == stored.meta.version.to_string()
                            })
                            .find_map(|(key, _)| {
                                state.values.get(key).map(|held| held.bytes.clone())
                            })
                    })
            };
            let covered = cached.is_some();
            if cached_only {
                if !covered {
                    return Err(unavailable());
                }
                continue;
            }
            let bytes = match cached {
                Some(bytes) => bytes,
                None => Arc::new(
                    runtime
                        .retained_file_bytes(&stored.meta.name, stored.meta.version)
                        .await?,
                ),
            };
            if runtime
                .file
                .version_hash(&stored.meta.name, stored.meta.version, &bytes)
                .map_err(|_| unavailable())?
                != stored.meta.version_hash
            {
                return Err(unavailable());
            }
            if !covered {
                runtime.cache.insert_scrub_file(&stored.meta, bytes)?;
            }
        }
        runtime
            .reconcile_native_file_changes(&file_changes, &required)
            .await?;
        let fingerprint =
            native_coverage_fingerprint(epoch, floor, &required, &records, &file_rows);
        let catalogue_capture = prior.unwrap_or_else(|| {
            Arc::new(NativeCatalogueCapture {
                at: captured_at,
                scopes: catalogues,
                file_rows,
            })
        });
        let live = Arc::new(SnapshotLiveness {
            current: AtomicBool::new(true),
            changed: tokio::sync::Notify::new(),
        });
        // Every record this refresh committed (its observations included)
        // retires the catalogue when the applier applies it; the drain waits
        // for the applier to reach the log's fsynced head BEFORE the tail
        // publishes coverage. Bounded by the fetch timeout; expiry fails the
        // refresh instead of publishing stale coverage.
        self.wait_for_applier_drain(runtime.settings.fetch_timeout)
            .await?;
        // The CAS base: the applier's drained head this build built against.
        let head = self.committed_head();
        if self.applied_lsn() != head {
            // The applier moved during the build: the strict CAS fails, the
            // shadow is discarded, and the still-serving coverage stays; the
            // cycle's next iteration rebuilds the delta from the new head.
            return Err(unavailable());
        }

        self.wait_for_applier_drain(runtime.settings.fetch_timeout)
            .await?;

        let mut state = lock(&runtime.cache.state);
        if !state.bound_runtime.ptr_eq(&Arc::downgrade(runtime))
            || state.revision != revision
            || self.epoch() != epoch
            || state.native_current.capture_revision() != Some(native_revision)
            || self.env.clock.monotonic().saturating_sub(captured_at) > runtime.settings.refresh
            || state.registry.iter().any(|(key, row)| {
                active(row)
                    && (!row.deleted || !row.version_hash.is_empty())
                    && !state.values.contains_key(key)
            })
        {
            return Err(unavailable());
        }
        if !SecretCache::finish_file_corpus(&mut state, &file_changes) {
            return Err(unavailable());
        }
        let references = pattern_references(&state).map(Arc::from);
        state.coverage = Some(NativeCoverage {
            revision,
            epoch,
            captured_at,
            fingerprint,
            references,
            base_lsn: head,
        });
        state.native_certificate_live = Some(live);
        // The delta's names are certified through the new base.
        for name in &touched_names {
            state.dirty.insert(name.clone(), head);
            state.dirty_max = state.dirty_max.max(head);
        }
        let retired_catalogue = state.native_catalogue_capture.replace(catalogue_capture);
        drop(state);
        drop(retired_catalogue);
        runtime
            .stats
            .records
            .fetch_add(records_read, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "kronik::secrets",
            from = scan_from.unwrap_or(0),
            through = scanned,
            records = records_read,
            elapsed_ms = u64::try_from(self.env.clock.monotonic().saturating_sub(started).as_millis())
                .unwrap_or(u64::MAX),
            "secret inventory certified"
        );
        Ok(scanned)
    }

    async fn retained_snapshot_secrets(
        &self,
        required: &mut BTreeMap<(String, u64), pb::SecretVersion>,
        records: &mut Vec<Record>,
    ) -> Result<(), ApiError> {
        let Some(storage) = self.storage_config() else {
            return Ok(());
        };
        let root = crate::snapshots::snapshots_dir(&storage.data_dir, self.branch());
        if !self
            .env
            .fs
            .exists(root.clone())
            .await
            .map_err(|_| unavailable())?
        {
            return Ok(());
        }
        let entries = self
            .env
            .fs
            .read_dir(root.clone())
            .await
            .map_err(|_| unavailable())?;
        if entries.len() > MAX_INVENTORY_VALUES {
            return Err(unavailable());
        }
        for entry in entries {
            if entry.starts_with('.') {
                continue;
            }
            if entry.len() != 20 || !entry.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(unavailable());
            }
            let path = root.join(entry).join("state.db");
            let (rows, config) = self.env.blocking("secret-snapshot-inventory", move || -> Result<_, ApiError> {
                let connection = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|_| unavailable())?;
                let modern: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='secret_versions')", [], |row| row.get(0)).map_err(|_| unavailable())?;
                // A legacy snapshot can contain revealed bytes whose metadata has
                // been lost. It cannot be certified by a current-only inventory.
                if !modern { return Err(unavailable()); }
                let mut statement = connection.prepare("SELECT record FROM secret_versions ORDER BY name, version").map_err(|_| unavailable())?;
                let mut cursor = statement.query([]).map_err(|_| unavailable())?;
                let mut rows = Vec::new();
                while let Some(row) = cursor.next().map_err(|_| unavailable())? {
                    if rows.len() >= MAX_INVENTORY_VALUES { return Err(unavailable()); }
                    let bytes: Vec<u8> = row.get(0).map_err(|_| unavailable())?;
                    let record = pb::SecretVersion::decode(bytes.as_slice()).map_err(|_| unavailable())?;
                    Record::SecretVersion(record.clone()).validate().map_err(|_| unavailable())?;
                    rows.push(record);
                }
                let mut statement = connection.prepare("SELECT kind, record FROM config_records ORDER BY lsn").map_err(|_| unavailable())?;
                let mut cursor = statement.query([]).map_err(|_| unavailable())?;
                let mut config = Vec::new();
                while let Some(row) = cursor.next().map_err(|_| unavailable())? {
                    if config.len() >= MAX_INVENTORY_VALUES { return Err(unavailable()); }
                    let kind: u8 = row.get(0).map_err(|_| unavailable())?;
                    let bytes: Vec<u8> = row.get(1).map_err(|_| unavailable())?;
                    config.push(Record::decode(kind, &bytes).map_err(|_| unavailable())?);
                }
                Ok((rows, config))
            }).await.ok_or_else(unavailable)??;
            for row in rows {
                let key = (row.name.clone(), row.version);
                if let Some(current) = required.get(&key) {
                    // An older pending snapshot is not an identity conflict.
                    let mut old = row.clone();
                    old.phase = current.phase;
                    old.audit = current.audit.clone();
                    if !same_identity(current, &old) {
                        return Err(unavailable());
                    }
                } else {
                    required.insert(key, row);
                }
            }
            records.extend(config);
        }
        Ok(())
    }

    /// Waits (bounded) until the applier has applied through the log's
    /// fsynced head. Publishing coverage earlier would publish coverage its
    /// own records just retired; expiry fails the refresh instead.
    async fn wait_for_applier_drain(&self, budget: std::time::Duration) -> Result<(), ApiError> {
        let deadline = self.env.clock.monotonic().saturating_add(budget);
        while self.applied_lsn() < self.committed_head()
            || self
                .secret_runtime
                .as_ref()
                .is_some_and(|runtime| lock(&runtime.cache.state).native_current.apply_in_flight())
        {
            if self.env.clock.monotonic() >= deadline {
                return Err(unavailable());
            }
            self.env
                .clock
                .sleep(std::time::Duration::from_millis(10))
                .await;
        }
        Ok(())
    }

    /// The write path waits for the catalogue to republish after its own
    /// records retire it: when a recertification already completed and
    /// failed for this revision, drive the identical procedure INLINE
    /// (bounded by the same fetch timeout) instead of waiting for the
    /// background cycle's next tick. Genuine failures still answer 503.
    async fn wait_secret_inventory(&self, original: AuthLease) -> Result<(), ApiError> {
        let runtime = self.runtime()?;
        let mut completed = runtime.certified.subscribe();
        let wanted = lock(&runtime.cache.state).revision;
        if runtime.cache.complete(self.epoch()) {
            return Ok(());
        }
        if !runtime.background.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        runtime.cache.revision_changed.notify_one();
        self.env
            .timeout(runtime.settings.fetch_timeout, async {
                loop {
                    let result = *completed.borrow_and_update();
                    if runtime.cache.complete(self.epoch()) {
                        return Ok(());
                    }
                    if result.0 >= wanted && !result.1 {
                        let refreshed = self.refresh_secret_inventory(original.clone()).await;
                        if refreshed.is_ok() && runtime.cache.complete(self.epoch()) {
                            return Ok(());
                        }
                        return Err(unavailable());
                    }
                    completed.changed().await.map_err(|_| unavailable())?;
                }
            })
            .await
            .map_err(|_| unavailable())?
    }

    pub fn start_secret_refresh(&self, original: AuthLease) {
        let Some(runtime) = &self.secret_runtime else {
            return;
        };
        if runtime.background.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(node) = self.me() else {
            return;
        };
        let weak = Arc::downgrade(&node);
        let env = self.env.clone();
        self.env.spawn("secret-refresh", async move {
            let mut registry_wake = false;
            let mut deadline = env.clock.monotonic();
            // A file-only inventory is certified before the node starts
            // (`initialize_secret_versions`). The first cycle still
            // observes every name's current version, but it does not
            // rebuild that certificate moments after it was made: the
            // rebuild retires the certificate, and every scrubbed read
            // waits for a rebuild nothing asked for.
            let mut certified_at_start = weak.upgrade().is_some_and(|node| {
                node.secret_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.cache.complete(node.epoch()))
            });
            // A failed cycle (or a cleared catalogue it could not rebuild)
            // retries promptly with bounded backoff instead of waiting the
            // whole refresh tick; after the budget is spent the loop falls
            // back to the periodic tick.
            let mut rebuild_failures = 0u32;
            loop {
                let Some(node) = weak.upgrade() else {
                    return;
                };
                if original.check().is_err() {
                    return;
                }
                let Some(runtime) = &node.secret_runtime else {
                    return;
                };
                if !registry_wake || !runtime.cache.complete(node.epoch()) {
                    let attempt = lock(&runtime.cache.state).revision;
                    let config = node.config_now();
                    let mut names: BTreeSet<_> = match node.secret_rows(None).await {
                        Ok(rows) => rows.into_iter().map(|row| row.name).collect(),
                        Err(_) => BTreeSet::new(),
                    };
                    names.extend(config.secret_links().map(|link| link.name.clone()));
                    for name in names {
                        let _guard = runtime.name_lock(&name).lock_owned().await;
                        let scope = Scope::config(&name, &config);
                        let source_version = match node.file_current_source(&scope).await {
                            Ok(version) => version,
                            Err(_) => continue,
                        };
                        match runtime
                            .fetched(&scope, source_version.as_deref(), original.clone())
                            .await
                        {
                            Ok(fetched) => {
                                if runtime
                                    .validate(&scope, &fetched, source_version.as_deref())
                                    .is_err()
                                {
                                    runtime.cache.failure(&scope, BackendError::Invalid);
                                    continue;
                                }
                                let _ = node
                                    .observe_secret(
                                        &scope,
                                        fetched,
                                        system_audit(&env, "background secret refresh"),
                                        true,
                                        original.clone(),
                                    )
                                    .await;
                            }
                            Err(error) => runtime.cache.failure(&scope, error),
                        }
                    }
                    // Kept as it is only when no observation above retired it.
                    let kept = std::mem::take(&mut certified_at_start)
                        && runtime.cache.complete(node.epoch())
                        && lock(&runtime.cache.state).revision == attempt;
                    let refreshed = if kept {
                        Ok(())
                    } else {
                        node.refresh_secret_inventory(original.clone()).await
                    };
                    let completed = if refreshed.is_ok() {
                        lock(&runtime.cache.state).revision
                    } else {
                        attempt
                    };
                    runtime
                        .certified
                        .send_replace((completed, refreshed.is_ok()));
                    match &refreshed {
                        Ok(()) => {
                            rebuild_failures = 0;
                            let jitter = u64::from_le_bytes(env.random_bytes::<8>()) % 21;
                            deadline = env.clock.monotonic().saturating_add(
                                runtime
                                    .settings
                                    .refresh
                                    .mul_f64(0.9 + jitter as f64 / 100.0),
                            );
                        }
                        Err(error) => {
                            // A failed cycle must not leave the catalogue
                            // uncertified for the whole refresh tick: retry
                            // promptly with bounded backoff (the fetch-timeout
                            // family), then fall back to the periodic tick.
                            tracing::warn!(
                                code = %error.code,
                                message = %error.message,
                                failures = rebuild_failures,
                                "secret rebuild failed"
                            );
                            rebuild_failures = rebuild_failures.saturating_add(1);
                            if rebuild_failures > 20 {
                                tracing::warn!(
                                    error = %error.message,
                                    "secret rebuild kept failing; falling back to the periodic tick"
                                );
                                rebuild_failures = 0;
                                deadline = env
                                    .clock
                                    .monotonic()
                                    .saturating_add(runtime.settings.refresh);
                            } else {
                                // Recovery windows (restore replay, applier
                                // catch-up) close in seconds; a retry must
                                // not back off for longer than one fetch
                                // window squared, or the whole stream waits
                                // on an otherwise transient state.
                                let backoff = runtime
                                    .settings
                                    .fetch_timeout
                                    .saturating_mul(1u32 << rebuild_failures.min(2));
                                deadline = env.clock.monotonic().saturating_add(backoff);
                            }
                        }
                    }
                }
                let delay = deadline.saturating_sub(env.clock.monotonic());
                let changed = runtime.cache.revision_changed.clone();
                drop(node);
                registry_wake = tokio::select! {
                    biased;
                    () = changed.notified() => true,
                    () = env.clock.sleep(delay) => false,
                    () = original.cancelled() => {
                        tracing::warn!("secret refresh cycle cancelled");
                        return;
                    }
                };
            }
        });
    }
}

// Only typed coordinates and already-keyed immutable value hashes enter this cache stamp.
// It identifies the inventory a certificate vouches for, not the part of the log a build
// re-read: the references a scan met are not an input, because a build that starts at
// the coverage watermark meets only the newest ones and would otherwise stamp the same
// inventory differently from one build to the next.
fn native_coverage_fingerprint(
    epoch: u64,
    floor: u64,
    required: &BTreeMap<(String, u64), pb::SecretVersion>,
    records: &[Record],
    file_rows: &[SecretRowMeta],
) -> [u8; 32] {
    fn bytes(hash: &mut blake3::Hasher, value: &[u8]) {
        hash.update(&(value.len() as u64).to_le_bytes());
        hash.update(value);
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"kronik native secret coverage v2\0");
    hash.update(&epoch.to_le_bytes());
    hash.update(&floor.to_le_bytes());
    hash.update(&(required.len() as u64).to_le_bytes());
    for row in required.values() {
        hash.update(&row.version.to_le_bytes());
        bytes(&mut hash, &row.version_hash);
        hash.update(&row.phase.to_le_bytes());
        hash.update(&[u8::from(row.deleted), u8::from(row.backend == "file")]);
        hash.update(&row.hash_revision.to_le_bytes());
        hash.update(&row.link_generation.to_le_bytes());
    }
    let links: BTreeSet<_> = records
        .iter()
        .filter_map(|record| match record {
            Record::SecretLink(link) => {
                Some((link.epoch, link.generation, link.backend.is_empty()))
            }
            _ => None,
        })
        .collect();
    hash.update(&(links.len() as u64).to_le_bytes());
    for (epoch, generation, unlinked) in links {
        hash.update(&epoch.to_le_bytes());
        hash.update(&generation.to_le_bytes());
        hash.update(&[u8::from(unlinked)]);
    }
    hash.update(&(file_rows.len() as u64).to_le_bytes());
    for row in file_rows {
        hash.update(&row.meta.version.to_le_bytes());
        bytes(&mut hash, &row.meta.version_hash);
        hash.update(&[u8::from(row.deletion_applied_wall_ms.is_some())]);
    }
    *hash.finalize().as_bytes()
}

fn collect_secret_references(
    record: &Record,
    sealer: &kronik_privacy::sealer::Sealer,
    result: &mut BTreeMap<(String, u64), Vec<u8>>,
) -> Result<(), ApiError> {
    fn effect(
        effect: &pb::EffectRecord,
        sealer: &kronik_privacy::sealer::Sealer,
        result: &mut BTreeMap<(String, u64), Vec<u8>>,
    ) -> Result<(), ApiError> {
        if !matches!(
            effect.kind.as_str(),
            "http.fetch"
                | "foreign.http"
                | "crypto.hmac-sha256"
                | "crypto.sign-ed25519"
                | "secret.reveal"
        ) {
            return Ok(());
        }
        let Some(request) = &effect.request else {
            return Ok(());
        };
        let decrypted;
        let bytes: &[u8] = match &request.value {
            Some(pb::sealable::Value::Plain(bytes)) => bytes,
            Some(pb::sealable::Value::Sealed(_)) => {
                decrypted =
                    Zeroizing::new(sealer.open(request).into_owned().ok_or_else(unavailable)?);
                &decrypted
            }
            None => return Ok(()),
        };
        let references: Vec<pb::SecretRef> = match effect.kind.as_str() {
            "http.fetch" | "foreign.http" => pb::HttpEffectRequest::decode(bytes)
                .map_err(|_| unavailable())?
                .headers
                .into_iter()
                .filter_map(|header| match header.value {
                    Some(pb::http_effect_header::Value::Secret(reference)) => Some(reference),
                    _ => None,
                })
                .collect(),
            "crypto.hmac-sha256" | "crypto.sign-ed25519" => pb::CryptoEffectRequest::decode(bytes)
                .map_err(|_| unavailable())?
                .secret
                .into_iter()
                .collect(),
            "secret.reveal" => pb::RevealEffectRequest::decode(bytes)
                .map_err(|_| unavailable())?
                .secret
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        for reference in references {
            if effect.status != pb::EffectStatus::Ok as i32
                && reference.version == 0
                && reference.wide_version == 0
                && reference.version_hash.is_empty()
            {
                continue;
            }
            let version = reference.resolved_version().map_err(|_| unavailable())?;
            let key = (reference.name, version);
            if result
                .get(&key)
                .is_some_and(|hash| *hash != reference.version_hash)
            {
                return Err(unavailable());
            }
            result.insert(key, reference.version_hash);
            if result.len() > MAX_INVENTORY_VALUES {
                return Err(unavailable());
            }
        }
        Ok(())
    }
    match record {
        Record::EffectResult(result_record) => {
            if let Some(record) = &result_record.effect {
                effect(record, sealer, result)?;
            }
        }
        _ if record.turn().is_some() => {
            for record in &record.turn().ok_or_else(unavailable)?.effects {
                effect(record, sealer, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
#[path = "secrets/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "secrets/certification_tests.rs"]
mod certification_tests;
