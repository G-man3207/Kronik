//! Native writer liveness is published synchronously in the physical admission domain.
use super::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

struct Binding {
    publication: Arc<Mutex<()>>,
    // The SAME original ownership File, never a duplicated descriptor.
    _ownership: Option<Arc<std::fs::File>>,
}

pub struct NativeWriterState {
    open: AtomicBool,
    changed: Notify,
    binding: Mutex<Option<Binding>>,
}

impl NativeWriterState {
    pub(super) fn new() -> Self {
        Self { open: AtomicBool::new(true), changed: Notify::new(), binding: Mutex::new(None) }
    }
    pub fn is_open(&self) -> bool { self.open.load(Ordering::Acquire) }
    pub async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.is_open() { return; }
            changed.await;
        }
    }
}

impl Log {
    /// Bind before any native execution capability is activated. The binding mutex
    /// serializes with an UNBOUND writer close, so no close publisher can escape
    /// into an unfenced store after binding and activation.
    pub fn bind_native_execution(
        &self, publication: Arc<Mutex<()>>, ownership: Option<Arc<std::fs::File>>,
    ) -> Result<Arc<NativeWriterState>, LogError> {
        let mut binding = self.native_writer.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.native_writer.is_open() { return Err(LogError::Stopped("native writer already ended".into())); }
        match binding.as_mut() {
            Some(bound) if !Arc::ptr_eq(&bound.publication, &publication) =>
                return Err(LogError::Stopped("native writer has a different physical publication domain".into())),
            Some(bound) => match (&bound._ownership, ownership) {
                (Some(original), Some(owner)) if !Arc::ptr_eq(original, &owner) =>
                    return Err(LogError::Stopped("native writer has a different ownership file".into())),
                (None, owner) => bound._ownership = owner,
                _ => {},
            },
            None => *binding = Some(Binding { publication, _ownership: ownership }),
        }
        Ok(self.native_writer.clone())
    }

    /// Identity of the original WAL writer, not a live execution permission.
    pub fn has_native_writer(&self, original: &Arc<NativeWriterState>) -> bool {
        Arc::ptr_eq(&self.native_writer, original)
    }
}

/// This owns the receiver BEFORE the Env task is spawned. Cancellation before
/// its first poll still runs Drop, publishing closure BEFORE receiver destruction.
pub(super) struct NativeInbox<T> {
    receiver: mpsc::UnboundedReceiver<T>,
    life: Arc<NativeWriterState>,
    closed: bool,
}

impl<T> NativeInbox<T> {
    pub(super) fn new(receiver: mpsc::UnboundedReceiver<T>, life: Arc<NativeWriterState>) -> Self {
        Self { receiver, life, closed: false }
    }
    pub(super) async fn recv(&mut self) -> Option<T> { self.receiver.recv().await }
    pub(super) fn try_recv(&mut self) -> Result<T, mpsc::error::TryRecvError> { self.receiver.try_recv() }
    pub(super) fn close(&mut self) {
        if self.closed { return; }
        let binding = self.life.binding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut publish = || {
            self.life.open.store(false, Ordering::Release);
            self.receiver.close();
            self.life.changed.notify_waiters();
        };
        if let Some(bound) = binding.as_ref() {
            let _publication = bound.publication.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            publish();
        } else {
            // Keep the binding mutex through this store. A later binder observes
            // CLOSED, never activates, and cannot race an unfenced close.
            publish();
        }
        self.closed = true;
    }
}

impl<T> Drop for NativeInbox<T> {
    fn drop(&mut self) { self.close(); }
}
