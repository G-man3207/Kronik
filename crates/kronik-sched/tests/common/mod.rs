#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use kronik_core::authority::{AuthLease, Authority};
use kronik_core::env::BoxFuture;
use kronik_core::error::{ApiError, ErrorCode};

#[derive(Clone)]
pub struct Revocable {
    live: Arc<Mutex<bool>>,
    changed: Arc<tokio::sync::Notify>,
}
impl Revocable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { live: Arc::new(Mutex::new(true)), changed: Arc::new(tokio::sync::Notify::new()) })
    }
    pub fn revoke(&self) {
        *self.live.lock().unwrap() = false;
        self.changed.notify_waiters();
    }
    pub fn lease(self: &Arc<Self>) -> AuthLease { self.clone() }
}
impl Authority for Revocable {
    fn check(&self) -> Result<(), ApiError> {
        if *self.live.lock().unwrap() { Ok(()) } else {
            Err(ApiError::new(ErrorCode::Unauthenticated, "test request revoked"))
        }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let this = self.clone();
        Box::pin(async move {
            loop {
                let changed = this.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if this.check().is_err() { return; }
                changed.await;
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        let live = self.live.lock().unwrap();
        if !*live { return Err(ApiError::new(ErrorCode::Unauthenticated, "test request revoked")); }
        effect()
    }
}
pub fn lease() -> AuthLease { Revocable::new().lease() }
