//! Native apply/config DATA only; no historical or Member source constructor.
use super::*;
use std::sync::atomic::AtomicU64;
use std::sync::Weak;
use kronik_log::Committed;
use kronik_store::Store;

#[derive(Default)]
pub(super) struct NativeCurrentState {
    revision: Arc<AtomicU64>,
    applying: Option<u64>,
    awaiting_config: Option<(u64, u64)>,
    config_epoch: u64,
    apply_owner: Weak<SecretCache>,
    source: Option<Arc<(std::path::PathBuf, String, Committed)>>,
}
impl NativeCurrentState {
    fn finish(&mut self, cut: u64, config_epoch: u64, applied: u64) {
        self.applying = None;
        let (cut, required) = self.awaiting_config.map_or((cut, config_epoch),
            |(prior, epoch)| (prior.max(cut), epoch.max(config_epoch)));
        if applied >= cut { self.revision.store(cut, Ordering::Release); }
        if applied >= cut && self.config_epoch >= required {
            self.awaiting_config = None;
        } else {
            self.awaiting_config = Some((cut, required));
        }
    }
    pub(super) fn configured(&mut self, epoch: u64) {
        self.config_epoch = self.config_epoch.max(epoch);
        if self.applying.is_none() && let Some((cut, required)) = self.awaiting_config
            && self.config_epoch >= required && self.revision.load(Ordering::Acquire) != u64::MAX
            && self.revision.load(Ordering::Acquire) >= cut {
            self.awaiting_config = None;
        }
    }
    pub(super) fn bind_epoch(&mut self, epoch: u64) { self.config_epoch = epoch; }
    pub(super) fn is_pending(&self) -> bool {
        self.applying.is_some() || self.awaiting_config.is_some()
    }
    pub(super) fn capture_revision(&self) -> Option<u64> {
        let revision = self.revision.load(Ordering::Acquire);
        (!self.is_pending() && revision != u64::MAX).then_some(revision)
    }
    pub(super) fn complete_replay(&mut self, cache: &Arc<SecretCache>, applied: u64, epoch: u64) -> bool {
        if !self.is_pending() { return true; }
        if self.apply_owner.ptr_eq(&Arc::downgrade(cache)) { return false; }
        let cut = self.applying.unwrap_or(0).max(self.awaiting_config.map_or(0, |(cut, _)| cut));
        let required = self.awaiting_config.map_or(0, |(_, epoch)| epoch);
        if applied < cut || epoch < required { return false; }
        self.config_epoch = epoch;
        self.finish(cut, required, applied);
        !self.is_pending()
    }
}

/// An actual apply cut, not permission to run, read a source, or allocate an identity.
pub(crate) struct NativeCurrentApply {
    cache: Weak<SecretCache>,
    store: Weak<Store>,
    cut: u64,
    config_epoch: u64,
}
fn same_current_source(left: &Committed, right: &Committed) -> bool {
    left.lsn == right.lsn && left.pos == right.pos && match (&left.record, &right.record) {
        (Record::SecretVersion(left), Record::SecretVersion(right)) => left == right,
        (Record::SecretLink(left), Record::SecretLink(right)) => left == right,
        _ => false,
    }
}

impl SecretRuntime {
    async fn native_current_source_directory(&self, reader: &kronik_log::LogReader)
        -> Result<std::path::PathBuf, ApiError> {
        let directory = reader.dir().to_path_buf();
        match self.file.data_ownership() {
            Ok(_) => self.env.blocking("native-current-log-directory", move || std::fs::canonicalize(directory))
                .await.ok_or_else(unavailable)?.map_err(|_| unavailable()),
            Err(kronik_privacy::PrivacyError::SecretStoreUnowned) => Ok(directory),
            Err(_) => Err(unavailable()),
        }
    }
    pub(super) async fn verify_native_current_source(&self, reader: &kronik_log::LogReader) -> Result<(), ApiError> {
        let (source, pending) = {
            let state = lock(&self.cache.state);
            if !self.owns_data_state(&state) { return Err(unavailable()); }
            let pending = state.native_current.is_pending();
            match &state.native_current.source {
                Some(source) => (source.clone(), pending),
                None if pending => return Err(unavailable()),
                None => return Ok(()),
            }
        };
        if self.native_current_source_directory(reader).await? != source.0 { return Err(unavailable()); }
        if pending {
            let (namespace, actual) = reader.read_at_with_namespace(source.2.pos).await.map_err(|_| unavailable())?;
            if namespace != source.1 || !same_current_source(&actual, &source.2) { return Err(unavailable()); }
        }
        Ok(())
    }
    pub(crate) async fn begin_native_current_apply(&self, batch: &[Committed], store: &Arc<Store>,
        reader: &kronik_log::LogReader) -> Result<Option<NativeCurrentApply>, ApiError> {
        let Some(last) = batch.iter().filter(|committed| matches!(&committed.record,
            Record::SecretVersion(_) | Record::SecretLink(_))).max_by_key(|committed| committed.lsn)
            else { return Ok(None); };
        let cut = last.lsn;
        if cut == 0 || cut == u64::MAX { return Err(unavailable()); }
        let config_epoch = batch.iter().filter_map(|committed| match &committed.record {
            Record::SecretLink(link) => Some(link.epoch), _ => None,
        }).max().unwrap_or(0);
        let (namespace, source) = reader.read_at_with_namespace(last.pos).await.map_err(|_| unavailable())?;
        if !same_current_source(last, &source) { return Err(unavailable()); }
        let source = Arc::new((self.native_current_source_directory(reader).await?, namespace, source));
        let denial = unavailable();
        let retired = {
            let _publication = lock(&self.cache.publication);
            let mut state = lock(&self.cache.state);
            if !self.owns_data_state(&state) || state.native_current.applying.is_some() { return Err(denial); }
            let Some(revision) = state.revision.checked_add(1) else { return Err(denial); };
            let prior_cut = state.native_current.awaiting_config.map_or(0, |(cut, _)| cut);
            let prior_epoch = state.native_current.awaiting_config.map_or(0, |(_, epoch)| epoch);
            state.native_current.awaiting_config = Some((cut.max(prior_cut), config_epoch.max(prior_epoch)));
            state.native_current.apply_owner = Arc::downgrade(&self.cache);
            state.native_current.applying = Some(cut);
            state.native_current.revision.store(u64::MAX, Ordering::Release);
            state.revision = revision;
            for committed in batch {
                let name = match &committed.record {
                    Record::SecretVersion(row) if active(row) => row.name.as_str(),
                    Record::SecretLink(link) => link.name.as_str(),
                    _ => continue,
                };
                if let Some(current) = state.names.get(name).and_then(|name| name.current.as_ref()) {
                    current.live.store(false, Ordering::Release);
                }
            }
            (SecretCache::retire_certificate(&mut state), state.native_catalogue_capture.take(),
                state.native_current.source.replace(source))
        };
        drop(retired);
        self.cache.revision_changed.notify_waiters();
        Ok(Some(NativeCurrentApply { cache: Arc::downgrade(&self.cache), store: Arc::downgrade(store), cut, config_epoch }))
    }
    pub(crate) fn finish_native_current_apply(&self, ticket: NativeCurrentApply, store: &Store) -> Result<(), ApiError> {
        if !Weak::ptr_eq(&ticket.cache, &Arc::downgrade(&self.cache))
            || !std::ptr::eq(ticket.store.as_ptr(), store) || store.applied.get() < ticket.cut {
            return Err(unavailable());
        }
        let denial = unavailable();
        {
            let _publication = lock(&self.cache.publication);
            let mut state = lock(&self.cache.state);
            if !self.owns_data_state(&state) || state.native_current.applying != Some(ticket.cut) {
                return Err(denial);
            }
            state.native_current.finish(ticket.cut, ticket.config_epoch, store.applied.get());
        }
        self.cache.revision_changed.notify_waiters();
        Ok(())
    }
    /// The actual config publisher already holds its original publication domain.
    pub(crate) fn publish_native_current_config_under_publication(&self, epoch: u64) {
        lock(&self.cache.state).native_current.configured(epoch);
    }
}
