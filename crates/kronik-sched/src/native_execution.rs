//! A native capability is issued only by an actually-started node and its real WAL lifetime.
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use kronik_core::authority::Authority;
use kronik_core::env::BoxFuture;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_log::NativeWriterState;
use tokio::sync::Notify;

mod source_roots;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn stopped() -> ApiError { ApiError::new(ErrorCode::Unavailable, "the original native execution lifetime ended") }

pub(crate) struct Lifecycle {
    alive: AtomicBool,
    native_mode: AtomicBool,
    changed: Notify,
    // Capabilities and admitted workers retain the SAME original root owner/File.
    // No File::try_clone and no lock reacquisition occurs.
    ownership: Option<kronik_privacy::key_source::DataOwnership>,
    source_roots: Arc<Mutex<kronik_core::snapshot_resources::SnapshotRootRegistry>>,
}
impl Default for Lifecycle { fn default() -> Self { Self::new(None) } }
impl Lifecycle {
    pub(crate) fn new(ownership: Option<kronik_privacy::key_source::DataOwnership>) -> Self {
        Self { alive: AtomicBool::new(true), native_mode: AtomicBool::new(true), changed: Notify::new(),
            ownership,
            source_roots: Arc::new(Mutex::new(kronik_core::snapshot_resources::SnapshotRootRegistry::default())) }
    }
    pub(crate) fn ownership(&self) -> Option<Arc<std::fs::File>> {
        self.ownership.as_ref().map(|owner| owner.directory_resource().clone())
    }
    pub(crate) fn data_ownership(&self) -> Option<&kronik_privacy::key_source::DataOwnership> {
        self.ownership.as_ref()
    }
    pub(crate) fn source_roots(&self) -> &Arc<Mutex<kronik_core::snapshot_resources::SnapshotRootRegistry>> {
        &self.source_roots
    }
    pub(crate) fn data_is_alive_under_publication(&self) -> bool { self.alive.load(Ordering::Acquire) }
    pub(crate) fn data_is_native_under_publication(&self) -> bool {
        self.alive.load(Ordering::Acquire) && self.native_mode.load(Ordering::Acquire)
    }
    pub(crate) fn stop_under_publication(&self) {
        self.alive.store(false, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(crate) fn check(&self) -> Result<(), ApiError> {
        if self.alive.load(Ordering::Acquire) { Ok(()) } else { Err(stopped()) }
    }
    pub(crate) fn declare_member_under_publication(&self) {
        self.native_mode.store(false, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(crate) fn check_native(&self) -> Result<(), ApiError> {
        self.check()?;
        if self.native_mode.load(Ordering::Acquire) { Ok(()) } else { Err(stopped()) }
    }
    pub(crate) async fn native_stopped(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.check_native().is_err() { return; }
            changed.await;
        }
    }
    pub(crate) async fn stopped(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.check().is_err() { return; }
            changed.await;
        }
    }
}

const PENDING: u8 = 0;
const ACTIVE: u8 = 1;
const STOPPED: u8 = 2;

pub(crate) struct NativeExecution {
    publication: Arc<Mutex<()>>,
    physical: Arc<Lifecycle>,
    writer: Arc<NativeWriterState>,
    source_first_lsn: u64,
    phase: AtomicU8,
    recovery_issued: AtomicBool,
    changed: Notify,
    me: Weak<Self>,
    node: OnceLock<Weak<crate::Node>>,
}
impl NativeExecution {
    /// Original configured ordinary readers require ACTIVE, never recovery.
    /// DATA only for the existing source publication fence.
    pub(crate) fn active_source_is_live_under_publication(&self) -> bool {
        self.phase.load(Ordering::Acquire) == ACTIVE && self.source_is_live_under_publication()
    }
    pub(crate) fn source_is_live_under_publication(&self) -> bool {
        self.physical.alive.load(Ordering::Acquire)
            && self.physical.native_mode.load(Ordering::Acquire)
            && matches!(self.phase.load(Ordering::Acquire), PENDING | ACTIVE)
            && self.writer.is_open()
            && self.node.get().is_some_and(|node| node.strong_count() != 0)
    }
    pub(crate) fn new(publication: Arc<Mutex<()>>, physical: Arc<Lifecycle>, writer: Arc<NativeWriterState>, source_first_lsn: u64) -> Arc<Self> {
        Arc::new_cyclic(|me| Self { publication, physical, writer, source_first_lsn, phase: AtomicU8::new(PENDING), recovery_issued: AtomicBool::new(false), changed: Notify::new(), me: me.clone(), node: OnceLock::new() })
    }
    pub(crate) fn bind_node(&self, node: Weak<crate::Node>) -> Result<(), ApiError> {
        self.node.set(node).map_err(|_| ApiError::new(ErrorCode::Unavailable, "native execution is already bound to its original node"))
    }
    /// Positive provenance of the native Node constructor and its actual bound
    /// WAL writer. This is a historical source fact, never an execution grant:
    /// stopped execution may still read its original history.
    pub(crate) fn native_source_start(&self, node: &crate::Node, log: &kronik_log::Log) -> Result<u64, ApiError> {
        if self.source_first_lsn == 0 || self.source_first_lsn > i64::MAX as u64
            || self.node.get().is_none_or(|original| !std::ptr::eq(original.as_ptr(), node))
            || !log.has_native_writer(&self.writer)
            || !self.physical.native_mode.load(Ordering::Acquire) {
            return Err(ApiError::new(ErrorCode::Unavailable, "the original native source profile is unavailable"));
        }
        Ok(self.source_first_lsn)
    }
    pub(crate) fn activate(&self) -> Result<(), ApiError> {
        let _publication = lock(&self.publication);
        self.physical.check_native()?;
        if self.node.get().is_none_or(|node| node.strong_count() == 0) { return Err(stopped()); }
        if !self.writer.is_open() { return Err(stopped()); }
        self.phase.compare_exchange(PENDING, ACTIVE, Ordering::AcqRel, Ordering::Acquire).map_err(|_| stopped())?;
        Ok(())
    }
    pub(crate) fn recovery_authority(self: &Arc<Self>) -> Result<kronik_core::authority::AuthLease, ApiError> {
        let _publication = lock(&self.publication);
        self.physical.check_native()?;
        if self.phase.load(Ordering::Acquire) != PENDING || !self.writer.is_open() { return Err(stopped()); }
        self.recovery_issued.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ApiError::new(ErrorCode::Unavailable, "native recovery authority was already issued"))?;
        Ok(Arc::new(NativeRecovery { execution: self.clone() }))
    }

    fn check_recovery(&self) -> Result<(), ApiError> {
        self.physical.check_native()?;
        // Checking custody must not upgrade/drop the last Node Arc under a publisher.
        if self.node.get().is_none_or(|node| node.strong_count() == 0) { return Err(stopped()); }
        if matches!(self.phase.load(Ordering::Acquire), PENDING | ACTIVE) && self.writer.is_open() {
            Ok(())
        } else {
            Err(stopped())
        }
    }
    pub(crate) fn stop(&self) {
        let _publication = lock(&self.publication);
        self.phase.store(STOPPED, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub(crate) fn stop_physical(&self) -> Result<(), ApiError> {
        let _publication = lock(&self.publication);
        self.check_recovery()?;
        self.phase.store(STOPPED, Ordering::Release);
        self.changed.notify_waiters();
        self.physical.stop_under_publication();
        Ok(())
    }
}
impl Authority for NativeExecution {
    fn check(&self) -> Result<(), ApiError> {
        self.check_recovery()?;
        if self.phase.load(Ordering::Acquire) == ACTIVE { Ok(()) } else { Err(stopped()) }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let Some(original) = self.me.upgrade() else { return Box::pin(std::future::ready(())); };
        Box::pin(async move {
            let native = async {
                loop {
                    let changed = original.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if original.phase.load(Ordering::Acquire) != ACTIVE { return; }
                    changed.await;
                }
            };
            tokio::select! { biased; () = native => {}, () = original.physical.native_stopped() => {}, () = original.writer.closed() => {} }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let _publication = lock(&self.publication);
        self.check()?;
        effect()
    }
}

/// Only startup can mint this original recovery capability, before public readiness.
struct NativeRecovery {
    execution: Arc<NativeExecution>,
}

impl Authority for NativeRecovery {
    fn check(&self) -> Result<(), ApiError> {
        self.execution.check_recovery()
    }

    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let original = self.execution.clone();
        Box::pin(async move {
            let recovery = async {
                loop {
                    let changed = original.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if original.check_recovery().is_err() { return; }
                    changed.await;
                }
            };
            tokio::select! { biased; () = recovery => {}, () = original.physical.native_stopped() => {}, () = original.writer.closed() => {} }
        })
    }

    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let _publication = lock(&self.execution.publication);
        self.check()?;
        effect()
    }
}
