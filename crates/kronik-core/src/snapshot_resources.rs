//! Physical source reader retention, not authority. Durable WAL, manifest and
//! preparation roots independently retain unknown commands through
//! cancellation and restart.
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::sync::lock;

/// The existing physical reader-root state, shared by its original lifecycle.
/// Empty means no active reader resources, never complete durable-source cover.
/// Original authority, source namespaces and source revisions stay in the
/// actual outer producer; this state changes only its resource generation.
#[derive(Default)]
pub struct SnapshotRootRegistry {
    retained_roots: BTreeMap<Vec<PathBuf>, Arc<SnapshotRootRegistration>>,
}

struct SnapshotRootRegistration {
    readers: AtomicUsize,
}

fn absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
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
    /// Must be selected through the original registry, not reconstructed from a
    /// descriptor, path or Arc count.
    fn try_pin(self: &Arc<Self>) -> Option<SnapshotRootPin> {
        self.readers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |readers| {
                readers.checked_add(1)
            })
            .ok()?;
        Some(SnapshotRootPin {
            registration: self.clone(),
        })
    }

    fn release_reader(&self) {
        // Accounting failure is sticky negative DATA; never wrap to zero and
        // report a live source after an overflow or unmatched release.
        let _ = self
            .readers
            .try_update(Ordering::AcqRel, Ordering::Acquire, |readers| {
                Some(if readers == usize::MAX {
                    usize::MAX
                } else {
                    readers.checked_sub(1).unwrap_or(usize::MAX)
                })
            });
    }
}

pub struct SnapshotRootPin {
    registration: Arc<SnapshotRootRegistration>,
}
impl SnapshotRootPin {
    /// DATA only; the operation separately retains its original role/key scope.
    pub fn data_is_live_under_publication(&self) -> bool {
        self.registration.readers.load(Ordering::Acquire) != usize::MAX
    }
}
impl Clone for SnapshotRootPin {
    fn clone(&self) -> Self {
        let _ =
            self.registration
                .readers
                .try_update(Ordering::AcqRel, Ordering::Acquire, |readers| {
                    Some(readers.saturating_add(1))
                });
        Self {
            registration: self.registration.clone(),
        }
    }
}
impl Drop for SnapshotRootPin {
    fn drop(&mut self) {
        self.registration.release_reader();
    }
}

fn unavailable_root_state() -> String {
    "the original physical source roots are unavailable for retention".into()
}
impl SnapshotRootRegistry {
    /// The caller registers these exact canonical physical paths in the SAME
    /// existing source registry before opening files. This creates no read or
    /// key permission, and does not claim that the paths contain a valid source.
    pub fn retain(
        registry: &Arc<Mutex<Self>>,
        paths: Vec<PathBuf>,
    ) -> Result<SnapshotRootPin, String> {
        let paths = normalized_paths(paths)?;
        let mut state = lock(registry);
        if let Some(existing) = state.retained_roots.get(&paths) {
            return existing.try_pin().ok_or_else(unavailable_root_state);
        }
        let candidate = Arc::new(SnapshotRootRegistration {
            readers: AtomicUsize::new(0),
        });
        let pin = candidate.try_pin().ok_or_else(unavailable_root_state)?;
        state.retained_roots.insert(paths, candidate);
        Ok(pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_requires_actual_canonical_physical_paths() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        assert!(SnapshotRootRegistry::retain(&registry, vec![]).is_err());
        assert!(SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("relative")]).is_err());
        assert!(
            SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/../escape")])
                .is_err()
        );
    }

    #[test]
    fn the_same_canonical_paths_share_one_pinned_registration() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let first =
            SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/log")]).unwrap();
        let again =
            SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/log")]).unwrap();
        assert!(Arc::ptr_eq(&first.registration, &again.registration));
        assert!(first.data_is_live_under_publication());
        let reordered = SnapshotRootRegistry::retain(
            &registry,
            vec![PathBuf::from("/data/H/state"), PathBuf::from("/data/H/log")],
        )
        .unwrap();
        let sorted = SnapshotRootRegistry::retain(
            &registry,
            vec![PathBuf::from("/data/H/log"), PathBuf::from("/data/H/state")],
        )
        .unwrap();
        assert!(Arc::ptr_eq(&reordered.registration, &sorted.registration));
        let other =
            SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/state")]).unwrap();
        assert!(!Arc::ptr_eq(&first.registration, &other.registration));
    }

    #[test]
    fn saturated_reader_accounting_is_sticky_unavailable_data() {
        let registry = Arc::new(Mutex::new(SnapshotRootRegistry::default()));
        let pin =
            SnapshotRootRegistry::retain(&registry, vec![PathBuf::from("/data/H/log")]).unwrap();
        let registration = pin.registration.clone();
        drop(pin);
        registration.readers.store(usize::MAX, Ordering::Release);
        assert!(registration.try_pin().is_none());
    }
}
