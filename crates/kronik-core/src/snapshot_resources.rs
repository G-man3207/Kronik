//! Physical source reader retention and deletion exclusion, not authority.
//! The existing source inventory must register and match every overlapping
//! path. Durable WAL/manifest/preparation roots independently retain unknown
//! commands through cancellation and restart.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak, atomic::{AtomicBool, AtomicUsize, Ordering}};

pub struct SnapshotRootRegistration {
    paths: Box<[PathBuf]>,
    readers: AtomicUsize,
    deleting: AtomicBool,
    retired: AtomicBool,
}

fn absolute_path(path: &Path) -> bool {
    path.is_absolute() && path.components().all(|component|
        matches!(component, Component::RootDir | Component::Normal(_)))
}

fn normalized_paths(mut paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, String> {
    if paths.is_empty() || paths.iter().any(|path| !absolute_path(path)) {
        return Err("snapshot retention requires its actual canonical physical paths".into());
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(paths)
}

impl SnapshotRootRegistration {
    /// The caller registers these exact canonical physical paths in the SAME
    /// existing source registry before opening files. This creates no read or
    /// key permission, and does not claim that the paths contain a valid source.
    pub fn new(paths: Vec<PathBuf>) -> Result<Arc<Self>, String> {
        Ok(Self::from_normalized_paths(normalized_paths(paths)?))
    }

    fn from_normalized_paths(paths: Vec<PathBuf>) -> Arc<Self> {
        Arc::new(Self { paths: paths.into_boxed_slice(), readers: AtomicUsize::new(0),
            deleting: AtomicBool::new(false), retired: AtomicBool::new(false) })
    }

    pub fn paths(&self) -> &[PathBuf] { &self.paths }
    /// A parent-directory deletion conflicts with a descendant read as well.
    pub fn overlaps(&self, path: &Path) -> bool {
        self.paths.iter().any(|root| root.starts_with(path) || path.starts_with(root))
    }
    pub fn is_retired(&self) -> bool { self.retired.load(Ordering::Acquire) }
    pub fn is_deleting(&self) -> bool { self.deleting.load(Ordering::Acquire) }
    pub fn is_pinned(&self) -> bool { self.readers.load(Ordering::Acquire) != 0 }

    /// Must be selected through the original registry, not reconstructed from a
    /// descriptor, path or Arc count. Atomics also close the late-pin/delete race.
    pub fn try_pin(self: &Arc<Self>) -> Option<SnapshotRootPin> {
        if self.is_deleting() || self.is_retired() { return None; }
        self.readers.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |readers| readers.checked_add(1)).ok()?;
        if self.is_deleting() || self.is_retired() {
            self.release_reader();
            return None;
        }
        Some(SnapshotRootPin { registration: self.clone() })
    }

    /// The registry must reserve ALL overlapping registrations before any FS
    /// mutation. No registry, physical, Store or depot mutex follows this token.
    pub fn try_begin_delete(self: &Arc<Self>) -> Option<SnapshotRootDeletion> {
        if self.is_retired() || self.deleting.compare_exchange(false, true,
            Ordering::AcqRel, Ordering::Acquire).is_err() { return None; }
        if self.is_pinned() {
            self.deleting.store(false, Ordering::Release);
            return None;
        }
        Some(SnapshotRootDeletion { registration: self.clone() })
    }

    fn release_reader(&self) {
        // Accounting failure is sticky negative DATA; never wrap to zero and
        // permit physical deletion after an overflow or unmatched release.
        let _ = self.readers.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |readers| Some(if readers == usize::MAX { usize::MAX }
                else { readers.checked_sub(1).unwrap_or(usize::MAX) }));
    }
}

pub struct SnapshotRootPin { registration: Arc<SnapshotRootRegistration> }
impl SnapshotRootPin {
    pub fn registration(&self) -> &Arc<SnapshotRootRegistration> { &self.registration }
    pub fn paths(&self) -> &[PathBuf] { self.registration.paths() }
    pub fn covers(&self, path: &Path) -> bool {
        self.paths().iter().any(|root| path.starts_with(root))
    }
    /// DATA only; the operation separately retains its original role/key scope.
    pub fn data_is_live_under_publication(&self) -> bool {
        !self.registration.is_deleting() && !self.registration.is_retired()
            && self.registration.readers.load(Ordering::Acquire) != usize::MAX
    }
}
impl Clone for SnapshotRootPin {
    fn clone(&self) -> Self {
        let _ = self.registration.readers.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |readers| Some(readers.saturating_add(1)));
        Self { registration: self.registration.clone() }
    }
}
impl Drop for SnapshotRootPin {
    fn drop(&mut self) { self.registration.release_reader(); }
}

/// Owned physical deletion reservation. Dropping it is deliberately NOT an
/// abort/terminal receipt: an admitted IO job may still have changed the files.
#[must_use]
pub struct SnapshotRootDeletion { registration: Arc<SnapshotRootRegistration> }
impl SnapshotRootDeletion {
    pub fn registration(&self) -> &Arc<SnapshotRootRegistration> { &self.registration }
    /// Only before any FS mutation has been admitted. The existing controller
    /// retains unresolved reservations and reconciles its real durable intent.
    pub fn abort_before_mutation(self) {
        if !self.registration.is_retired() {
            self.registration.deleting.store(false, Ordering::Release);
        }
    }
    /// Only after actual removal and parent-directory fsync completed.
    pub fn finish_deleted(self) { self.registration.retired.store(true, Ordering::Release); }
}

/// The existing physical reader-root state, shared by its original lifecycle.
/// Empty means no active reader resources, never complete durable-source cover.
/// Original authority, source namespaces and source revisions stay in the
/// actual outer producer; this state changes only its resource generation.
#[derive(Default)]
pub struct SnapshotRootRegistry {
    retained_roots: BTreeMap<u64, Arc<SnapshotRootRegistration>>,
    retention_revision: u64,
}

/// The SAME registry's actual overlap plan, prepared before final admission.
pub struct SnapshotRootDeletionPlan {
    registry: Weak<Mutex<SnapshotRootRegistry>>,
    retention_revision: u64,
    reservation: Arc<SnapshotRootRegistration>,
    registered: Vec<Arc<SnapshotRootRegistration>>,
    held: Vec<SnapshotRootDeletion>,
}

/// An actual admitted set of deletion exclusions. Drop is deliberately NOT a
/// terminal receipt. The owned IO/controller must explicitly reconcile it.
#[must_use]
pub struct SnapshotRootDeletionBatch {
    registry: Weak<Mutex<SnapshotRootRegistry>>,
    reservation: u64,
    held: Vec<SnapshotRootDeletion>,
}

fn lock_root_state(registry: &Mutex<SnapshotRootRegistry>) -> MutexGuard<'_, SnapshotRootRegistry> {
    registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn unavailable_root_state() -> String {
    "the original physical source roots are changing or retained".into()
}
impl SnapshotRootRegistry {
    fn next_revision(&self) -> Result<u64, String> {
        self.retention_revision.checked_add(1)
            .filter(|revision| *revision != u64::MAX).ok_or_else(unavailable_root_state)
    }

    fn has_pending_deletion(&self) -> bool {
        self.retention_revision == u64::MAX
            || self.retained_roots.values().any(|root| root.is_deleting() && !root.is_retired())
    }

    pub fn retain(registry: &Arc<Mutex<Self>>, paths: Vec<PathBuf>) -> Result<SnapshotRootPin, String> {
        let paths = normalized_paths(paths)?;
        let mut state = lock_root_state(registry);
        if state.retention_revision == u64::MAX
            || state.retained_roots.values().any(|root| root.is_deleting() && !root.is_retired()
                && paths.iter().any(|path| root.overlaps(path))) {
            return Err(unavailable_root_state());
        }
        if let Some(existing) = state.retained_roots.values().find(|root|
            !root.is_retired() && root.paths() == paths.as_slice()) {
            return existing.try_pin().ok_or_else(unavailable_root_state);
        }
        let revision = state.next_revision()?;
        let candidate = SnapshotRootRegistration::from_normalized_paths(paths);
        let pin = candidate.try_pin().ok_or_else(unavailable_root_state)?;
        state.retained_roots.insert(revision, candidate);
        state.retention_revision = revision;
        Ok(pin)
    }

    pub fn prepare_deletion(registry: &Arc<Mutex<Self>>, paths: Vec<PathBuf>)
        -> Result<SnapshotRootDeletionPlan, String>
    {
        let reservation = SnapshotRootRegistration::new(paths)?;
        let state = lock_root_state(registry);
        state.next_revision()?;
        let registered = state.retained_roots.values().filter(|root| !root.is_retired()
            && reservation.paths().iter().any(|path| root.overlaps(path)))
            .cloned().collect::<Vec<_>>();
        let held = Vec::with_capacity(registered.len() + 1);
        Ok(SnapshotRootDeletionPlan { registry: Arc::downgrade(registry),
            retention_revision: state.retention_revision, reservation, registered, held })
    }

    pub fn begin_deletion(registry: &Arc<Mutex<Self>>, mut plan: SnapshotRootDeletionPlan)
        -> Result<SnapshotRootDeletionBatch, String>
    {
        if !Weak::ptr_eq(&plan.registry, &Arc::downgrade(registry)) {
            return Err(unavailable_root_state());
        }
        let mut state = lock_root_state(registry);
        if state.retention_revision != plan.retention_revision { return Err(unavailable_root_state()); }
        let revision = state.next_revision()?;
        for root in plan.registered.iter().chain(std::iter::once(&plan.reservation)) {
            let Some(deletion) = root.try_begin_delete() else {
                for previous in plan.held.drain(..) { previous.abort_before_mutation(); }
                return Err(unavailable_root_state());
            };
            plan.held.push(deletion);
        }
        state.retained_roots.insert(revision, plan.reservation);
        state.retention_revision = revision;
        Ok(SnapshotRootDeletionBatch { registry: plan.registry, reservation: revision, held: plan.held })
    }

    pub fn capture_pins(registry: &Arc<Mutex<Self>>) -> Result<Vec<SnapshotRootPin>, String> {
        let state = lock_root_state(registry);
        if state.has_pending_deletion() { return Err(unavailable_root_state()); }
        let mut pins = Vec::with_capacity(state.retained_roots.len());
        for root in state.retained_roots.values().filter(|root| !root.is_retired() && root.is_pinned()) {
            pins.push(root.try_pin().ok_or_else(unavailable_root_state)?);
        }
        Ok(pins)
    }

    pub fn contains(registry: &Arc<Mutex<Self>>, pin: &SnapshotRootPin) -> bool {
        if !pin.data_is_live_under_publication() { return false; }
        let state = lock_root_state(registry);
        state.retention_revision != u64::MAX
            && state.retained_roots.values().any(|root| Arc::ptr_eq(root, pin.registration()))
    }

    pub fn deletion_pending(registry: &Arc<Mutex<Self>>) -> bool {
        lock_root_state(registry).has_pending_deletion()
    }

    pub fn generation(registry: &Arc<Mutex<Self>>) -> u64 {
        lock_root_state(registry).retention_revision
    }
}

impl SnapshotRootDeletionBatch {
    /// Only before any filesystem mutation was admitted by the original job.
    pub fn abort_before_mutation(self) -> Result<(), String> { self.resolve(false) }

    /// Only after actual deletion AND parent-directory fsync completed.
    pub fn finish_deleted(self) -> Result<(), String> { self.resolve(true) }

    fn resolve(mut self, deleted: bool) -> Result<(), String> {
        let registry = self.registry.upgrade().ok_or_else(unavailable_root_state)?;
        let mut state = lock_root_state(&registry);
        let selected = self.held.last().ok_or_else(unavailable_root_state)?.registration();
        if !state.retained_roots.get(&self.reservation).is_some_and(|actual|
            Arc::ptr_eq(actual, selected) && actual.is_deleting() && !actual.is_retired()) {
            return Err(unavailable_root_state());
        }
        if deleted {
            for root in self.held.drain(..) { root.finish_deleted(); }
            state.retained_roots.retain(|_, root| !root.is_retired());
        } else {
            for root in self.held.drain(..) { root.abort_before_mutation(); }
            state.retained_roots.remove(&self.reservation);
        }
        // Exhaustion is permanent negative data, never an old complete cut.
        state.retention_revision = state.retention_revision.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_reader_and_parent_delete_are_mutually_exclusive() {
        let registered = SnapshotRootRegistration::new(vec![PathBuf::from("/data/snapshots/H")]).unwrap();
        assert!(registered.overlaps(Path::new("/data")));
        assert!(registered.overlaps(Path::new("/data/snapshots/H/state.db")));
        assert!(!registered.overlaps(Path::new("/data/snapshots/H-other")));
        let first = registered.try_pin().unwrap();
        let second = first.clone();
        assert!(registered.try_begin_delete().is_none());
        drop(first);
        assert!(registered.try_begin_delete().is_none());
        drop(second);
        let deleting = registered.try_begin_delete().unwrap();
        assert!(registered.try_pin().is_none());
        deleting.abort_before_mutation();
        assert!(registered.try_pin().is_some());
        let deleting = registered.try_begin_delete().unwrap();
        deleting.finish_deleted();
        assert!(registered.is_retired());
        assert!(registered.try_pin().is_none());
        assert!(registered.try_begin_delete().is_none());
    }

    #[test]
    fn unknown_deletion_and_reader_accounting_failure_never_release_the_root() {
        let registered = SnapshotRootRegistration::new(vec![PathBuf::from("/data/snapshots/H")]).unwrap();
        drop(registered.try_begin_delete().unwrap());
        assert!(registered.is_deleting());
        assert!(registered.try_pin().is_none());
        assert!(registered.try_begin_delete().is_none());
        let saturated = SnapshotRootRegistration::new(vec![PathBuf::from("/data/snapshots/other")]).unwrap();
        saturated.readers.store(usize::MAX, Ordering::Release);
        assert!(saturated.try_pin().is_none());
        assert!(saturated.try_begin_delete().is_none());
    }

    #[test]
    fn registry_reserves_all_overlaps_or_releases_every_unsubmitted_reservation() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let first = SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/log")]).unwrap();
        let first_registration = first.registration().clone();
        let second = SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/state")]).unwrap();
        let second_registration = second.registration().clone();
        drop(first);
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/H")]).unwrap();
        assert!(SnapshotRootRegistry::begin_deletion(&registry, plan).is_err());
        assert!(!first_registration.is_deleting());
        assert!(!second_registration.is_deleting());
        drop(second);
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/H")]).unwrap();
        let deleting = SnapshotRootRegistry::begin_deletion(&registry, plan).unwrap();
        assert!(first_registration.try_pin().is_none());
        assert!(second_registration.try_pin().is_none());
        drop(deleting);
        assert!(first_registration.is_deleting());
        assert!(second_registration.is_deleting());
        assert!(SnapshotRootRegistry::capture_pins(&registry).is_err());
    }

    #[test]
    fn registry_rejects_foreign_and_stale_plans_without_mutation() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let foreign = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/A")]).unwrap();
        assert!(SnapshotRootRegistry::begin_deletion(&foreign, plan).is_err());
        assert_eq!(SnapshotRootRegistry::generation(&registry), 0);
        assert_eq!(SnapshotRootRegistry::generation(&foreign), 0);
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/A")]).unwrap();
        let reader = SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/B")]).unwrap();
        let revision = SnapshotRootRegistry::generation(&registry);
        assert!(SnapshotRootRegistry::begin_deletion(&registry, plan).is_err());
        assert_eq!(SnapshotRootRegistry::generation(&registry), revision);
        assert!(SnapshotRootRegistry::contains(&registry, &reader));
    }

    #[test]
    fn registry_resolves_only_explicit_scoped_deletions() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let reader = SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/A")]).unwrap();
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/B")]).unwrap();
        let deleting = SnapshotRootRegistry::begin_deletion(&registry, plan).unwrap();
        assert!(SnapshotRootRegistry::contains(&registry, &reader));
        assert!(SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/B/child")]).is_err());
        deleting.abort_before_mutation().unwrap();
        let another = SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/B")]).unwrap();
        assert!(SnapshotRootRegistry::contains(&registry, &another));
        let registration = another.registration().clone();
        drop(another);
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/B")]).unwrap();
        SnapshotRootRegistry::begin_deletion(&registry, plan).unwrap().finish_deleted().unwrap();
        assert!(registration.is_retired());
        assert!(SnapshotRootRegistry::contains(&registry, &reader));
        assert!(!SnapshotRootRegistry::deletion_pending(&registry));
    }

    #[test]
    fn registry_owner_loss_and_generation_exhaustion_never_complete_unknown_work() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/A")]).unwrap();
        let deleting = SnapshotRootRegistry::begin_deletion(&registry, plan).unwrap();
        let registration = deleting.held.last().unwrap().registration().clone();
        drop(registry);
        assert!(deleting.abort_before_mutation().is_err());
        assert!(registration.is_deleting());

        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        lock_root_state(&registry).retention_revision = u64::MAX - 2;
        let plan = SnapshotRootRegistry::prepare_deletion(&registry, vec![PathBuf::from("/data/A")]).unwrap();
        SnapshotRootRegistry::begin_deletion(&registry, plan).unwrap().abort_before_mutation().unwrap();
        assert_eq!(SnapshotRootRegistry::generation(&registry), u64::MAX);
        assert!(SnapshotRootRegistry::deletion_pending(&registry));
        assert!(SnapshotRootRegistry::capture_pins(&registry).is_err());
        assert!(SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/B")]).is_err());
    }
}
