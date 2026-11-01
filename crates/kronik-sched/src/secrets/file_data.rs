//! The existing cache's physical-write interval, never caller authority.
use super::*;
use kronik_privacy::{PrivacyError, SecretStoreData};

pub(super) struct FileMutation {
    pub ticket: u64,
    pub physical: u64,
    pub running: bool,
    pub sql_committed: bool,
    pub current_unknown: bool,
    pub corpus_unknown: bool,
}

pub(super) struct ReadStamp {
    publisher: std::sync::Weak<SecretCache>,
    file_ticket: Option<u64>,
}
pub(super) struct StampedFetched {
    pub value: Zeroizing<Vec<u8>>,
    pub source_version: String,
    pub canonical_ref: String,
    pub stamp: ReadStamp,
}

impl SecretCache {
    pub(super) fn is_current_view(&self, state: &CacheState) -> bool {
        std::ptr::eq(state.bound_cache.as_ptr(), self)
    }
    pub(super) fn read_stamp(&self, scope: &Scope) -> Result<ReadStamp, BackendError> {
        let state = lock(&self.state);
        if !self.is_current_view(&state) { return Err(BackendError::Unavailable); }
        let pending = (scope.backend == "file").then(|| state.names.get(&scope.canonical)
            .and_then(|slot| slot.file_mutation.as_ref())).flatten();
        if pending.is_some_and(|pending| pending.running || !pending.sql_committed
           ) {
            return Err(BackendError::Unavailable);
        }
        Ok(ReadStamp { publisher: state.bound_cache.clone(), file_ticket: pending.map(|pending| pending.ticket) })
    }
    pub(super) fn read_matches(&self, state: &CacheState, backend: &str, physical: &str, stamp: &ReadStamp) -> bool {
        if !self.is_current_view(state) || !stamp.publisher.ptr_eq(&state.bound_cache) { return false; }
        if backend != "file" { return true; }
        let pending = state.names.get(physical).and_then(|slot| slot.file_mutation.as_ref());
        pending.is_none_or(|pending| !pending.running && pending.sql_committed
)
            && pending.map(|pending| pending.ticket) == stamp.file_ticket
    }
}

/// Construct before exposing a mutable Store; each runtime reuses these SAME facts.
pub struct SecretCacheData {
    pub(super) state: Arc<Mutex<CacheState>>,
    pub(super) changed: Arc<tokio::sync::Notify>,
}
impl SecretCacheData {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { state: Arc::new(Mutex::new(CacheState::default())),
            changed: Arc::new(tokio::sync::Notify::new()) })
    }
}
impl SecretStoreData for SecretCacheData {
    fn begin(&self, name: &str, physical: u64) -> Result<u64, PrivacyError> {
        let mut state = self.state.lock().map_err(|_| PrivacyError::SecretStoreUnknown)?;
        if state.names.get(name).and_then(|slot| slot.file_mutation.as_ref()).is_some_and(|pending| pending.running) {
            return Err(PrivacyError::SecretStoreBusy);
        }
        let ticket = state.revision.checked_add(1).ok_or(PrivacyError::SecretStoreUnknown)?;
        let mutation = FileMutation {
            ticket, physical, running: true, sql_committed: false, current_unknown: true, corpus_unknown: true,
        };
        match state.names.get_mut(name) {
            Some(slot) => slot.file_mutation = Some(mutation),
            None => {
                state.names.insert(name.to_owned(), SecretName { file_mutation: Some(mutation), ..Default::default() });
            },
        }
        for slot in state.names.values() {
            if let Some(current) = &slot.current
                && current.binding.as_ref().is_some_and(|(scope, _)| scope.backend == "file" && scope.canonical == name) {
                current.live.store(false, Ordering::Release);
            }
        }
        let CacheState { registry, values, .. } = &mut *state;
        for (key, held) in values {
            if registry.get(key).is_some_and(|row| row.backend == "file" && row.canonical_ref == name) {
                held.operational = false;
            }
        }
        state.revision = ticket;
        let retired = (SecretCache::retire_certificate(&mut state), state.native_catalogue_capture.take());
        drop(state);
        drop(retired);
        self.changed.notify_waiters();
        Ok(ticket)
    }
    fn sql_committed(&self, name: &str, physical: u64, ticket: u64) -> Result<(), PrivacyError> {
        let mut state = self.state.lock().map_err(|_| PrivacyError::SecretStoreUnknown)?;
        let pending = state.names.get_mut(name).and_then(|slot| slot.file_mutation.as_mut())
            .filter(|pending| pending.ticket == ticket && pending.physical == physical && pending.running)
            .ok_or(PrivacyError::SecretStoreUnknown)?;
        pending.running = false;
        pending.sql_committed = true;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    fn sql_aborted(&self, name: &str, physical: u64, ticket: u64) {
        let mut state = lock(&self.state);
        if let Some(pending) = state.names.get_mut(name).and_then(|slot| slot.file_mutation.as_mut())
            && pending.ticket == ticket && pending.physical == physical {
            pending.running = false;
        }
        drop(state);
        self.changed.notify_waiters();
    }
}

impl SecretCache {
    pub(super) fn bind_physical(&self, physical: &Arc<crate::native_execution::Lifecycle>,
        runtime: &Arc<SecretRuntime>) -> Result<(), PrivacyError> {
        match (runtime.file.data_ownership(), physical.data_ownership()) {
            (Ok(file), Some(owner)) if Arc::ptr_eq(file.directory_resource(), owner.directory_resource()) => {},
            // Runtime construction already excluded read-only and fixture custody via its actual DATA adapter.
            (Err(PrivacyError::SecretStoreUnowned), None) => {},
            (Err(error), _) => return Err(error),
            _ => return Err(PrivacyError::SecretStoreUnowned),
        }
        let (previous, previous_runtime, native) = {
            let state = lock(&self.state);
            (state.physical.clone(), state.bound_runtime.clone(), state.native_owner.clone())
        };
        let native_live = native.as_ref().map_or(previous_runtime.strong_count() != 0, |native|
            native.upgrade().is_some_and(|native| native.source_is_live_under_publication()));
        let live = previous.as_ref().and_then(std::sync::Weak::upgrade).is_some_and(|previous|
            previous.data_is_alive_under_publication()
                && if previous.data_is_native_under_publication() { native_live } else { previous_runtime.strong_count() != 0 });
        let next = Arc::downgrade(physical);
        let mut state = lock(&self.state);
        let unchanged = match (&state.physical, &previous) {
            (Some(current), Some(previous)) => current.ptr_eq(previous),
            (None, None) => true,
            _ => false,
        };
        if !unchanged || !state.bound_runtime.ptr_eq(&previous_runtime) || live
            || state.names.values().any(|slot| slot.file_mutation.as_ref().is_some_and(|pending| pending.running)) {
            return Err(PrivacyError::SecretStoreBusy);
        }
        for slot in state.names.values() {
            if let Some(current) = &slot.current { current.live.store(false, Ordering::Release); }
        }
        for held in state.values.values_mut() { held.operational = false; }
        let retired = (SecretCache::retire_certificate(&mut state), state.native_catalogue_capture.take());
        state.physical = Some(next);
        state.bound_runtime = Arc::downgrade(runtime);
        state.bound_cache = Arc::downgrade(&runtime.cache);
        state.native_owner = None;
        drop(state);
        drop(retired);
        self.revision_changed.notify_waiters();
        Ok(())
    }
    pub(super) fn file_current_pending(state: &CacheState, row: &pb::SecretVersion) -> bool {
        row.backend == "file" && state.names.get(&row.canonical_ref).and_then(|slot| slot.file_mutation.as_ref())
            .is_some_and(|pending| pending.running || pending.current_unknown)
    }
}

impl SecretRuntime {
    pub(super) fn owns_data_state(&self, state: &CacheState) -> bool {
        std::ptr::eq(state.bound_runtime.as_ptr(), self)
    }
    pub(crate) async fn bind_native_current_execution(self: &Arc<Self>,
        native: &Arc<crate::native_execution::NativeExecution>, store: &kronik_store::Store,
        reader: &kronik_log::LogReader, initial_epoch: u64) -> Result<(), PrivacyError> {
        {
            let mut state = lock(&self.cache.state);
            if !self.owns_data_state(&state) { return Err(PrivacyError::SecretStoreUnowned); }
            state.native_owner = Some(Arc::downgrade(native));
        }
        self.verify_native_current_source(reader).await.map_err(|_| PrivacyError::SecretStoreUnknown)?;
        let mut state = lock(&self.cache.state);
        if !self.owns_data_state(&state) || state.native_owner.as_ref()
            .is_none_or(|owner| !owner.ptr_eq(&Arc::downgrade(native))) { return Err(PrivacyError::SecretStoreUnowned); }
        state.native_current.bind_epoch(initial_epoch);
        if !state.native_current.complete_replay(&self.cache, store.applied.get(), initial_epoch) {
            return Err(PrivacyError::SecretStoreUnknown);
        }
        Ok(())
    }
}

impl SecretCache {
    pub(super) fn capture_file_changes(&self) -> Result<Vec<(String, u64)>, ApiError> {
        let state = lock(&self.state);
        if state.names.values().any(|slot| slot.file_mutation.as_ref()
            .is_some_and(|pending| pending.running || !pending.sql_committed)) { return Err(unavailable()); }
        Ok(state.names.iter().filter_map(|(name, slot)| slot.file_mutation.as_ref()
            .filter(|pending| pending.current_unknown || pending.corpus_unknown)
            .map(|pending| (name.clone(), pending.ticket))).collect())
    }
    pub(super) fn finish_file_corpus(state: &mut CacheState, captured: &[(String, u64)]) -> bool {
        if !state.names.iter().filter_map(|(name, slot)| slot.file_mutation.as_ref()
            .filter(|pending| pending.current_unknown || pending.corpus_unknown)
            .map(|pending| (name.as_str(), pending.ticket,
                !pending.running && pending.sql_committed && !pending.current_unknown)))
            .eq(captured.iter().map(|(name, ticket)| (name.as_str(), *ticket, true))) {
            return false;
        }
        for slot in state.names.values_mut() {
            if let Some(pending) = &mut slot.file_mutation { pending.corpus_unknown = false; }
        }
        true
    }
}

impl SecretRuntime {
    /// Only the actual admitted owned mutation calls this after its ACTIVE acknowledgement.
    pub(super) async fn finish_owned_file_change(&self, row: &pb::SecretVersion) -> Result<ReadStamp, ApiError> {
        let physical = row.source_version.parse::<u64>().map_err(|_| unavailable())?;
        let ticket = {
            let state = lock(&self.cache.state);
            state.names.get(&row.canonical_ref).and_then(|slot| slot.file_mutation.as_ref())
                .filter(|pending| pending.physical == physical && !pending.running && pending.sql_committed)
                .map(|pending| pending.ticket).ok_or_else(unavailable)?
        };
        self.finish_current_file_change(row, ticket).await
    }
    async fn finish_current_file_change(&self, row: &pb::SecretVersion, ticket: u64) -> Result<ReadStamp, ApiError> {
        if !active(row) || row.backend != "file" || row.binding != "file" || row.r#ref != row.canonical_ref {
            return Err(unavailable());
        }
        let physical = row.source_version.parse::<u64>().map_err(|_| unavailable())?;
        if physical.to_string() != row.source_version { return Err(unavailable()); }
        {
            let state = lock(&self.cache.state);
            if !self.owns_data_state(&state) || !state.names.get(&row.canonical_ref).and_then(|slot| slot.file_mutation.as_ref())
                .is_some_and(|pending| pending.ticket == ticket && !pending.running && pending.sql_committed) {
                return Err(unavailable());
            }
        }
        let file = self.file.clone();
        let expected = row.clone();
        let matches = self.env.blocking("reconcile-owned-current-secret", move || {
            match file.data_ownership() {
                Ok(_) => file.sync_parent_directory().map_err(|_| unavailable())?,
                Err(PrivacyError::SecretStoreUnowned) => {},
                Err(_) => return Err(unavailable()),
            }
            let current = file.current(&expected.canonical_ref).map_err(|_| unavailable())?
                .map(|current| (current.meta, Zeroizing::new(current.value)));
            let floor = file.stored_deletion_floor(&expected.canonical_ref).map_err(|_| unavailable())?;
            if expected.deleted {
                return Ok::<_, ApiError>(floor.is_some_and(|floor| floor.through_version >= physical)
                    && current.is_none_or(|(meta, _)| meta.version > physical));
            }
            let Some((meta, value)) = current else { return Ok(false); };
            Ok(meta.version == physical && floor.is_none_or(|floor| physical > floor.through_version)
                && file.version_hash(&expected.name, expected.version, &value).map_err(|_| unavailable())?
                    == expected.version_hash)
        }).await.ok_or_else(unavailable)??;
        if !matches { return Err(unavailable()); }
        let mut state = lock(&self.cache.state);
        if !self.owns_data_state(&state) { return Err(unavailable()); }
        let pending = state.names.get_mut(&row.canonical_ref).and_then(|slot| slot.file_mutation.as_mut())
            .filter(|pending| pending.ticket == ticket && !pending.running && pending.sql_committed)
            .ok_or_else(unavailable)?;
        pending.current_unknown = false;
        let stamp = ReadStamp { publisher: state.bound_cache.clone(), file_ticket: Some(ticket) };
        drop(state);
        self.cache.revision_changed.notify_waiters();
        Ok(stamp)
    }
    /// Standalone native WAL plus the SAME actual current store; never a member COPY qualifier.
    pub(super) async fn reconcile_native_file_changes(&self, captured: &[(String, u64)],
        required: &BTreeMap<(String, u64), pb::SecretVersion>) -> Result<(), ApiError> {
        for (name, ticket) in captured {
            let file = self.file.clone();
            let physical_name = name.clone();
            let current = self.env.blocking("native-file-current-source", move || file.current_meta(&physical_name))
                .await.ok_or_else(unavailable)?.map_err(|_| unavailable())?;
            let Some(current) = current else { continue; };
            let row = required.values().find(|row| active(row) && !row.deleted && row.backend == "file"
                && row.canonical_ref == *name && row.source_version.parse::<u64>().ok() == Some(current.version))
                .ok_or_else(unavailable)?;
            self.finish_current_file_change(row, *ticket).await?;
        }
        Ok(())
    }
}