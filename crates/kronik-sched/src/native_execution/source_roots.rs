//! Ordinary native reader resources; SAME original lifecycle, not authority.
use super::*;

impl NativeExecution {
    pub(crate) fn source_roots(
        &self,
    ) -> Arc<Mutex<kronik_core::snapshot_resources::SnapshotRootRegistry>> {
        self.physical.source_roots().clone()
    }
    pub(crate) fn ownership(&self) -> Option<Arc<std::fs::File>> {
        self.physical.ownership()
    }
}
