//! Helpers the unit-test modules of this crate share.

use std::future::Future;

use kronik_core::env::Env;
use kronik_proto::log::v1 as pb;

/// The counter test guest.
pub(crate) const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

/// An operator audit for test operations.
pub(crate) fn audit() -> pb::Audit {
    pb::Audit {
        token_id: "test".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    }
}

/// The real environment on the current runtime.
pub(crate) fn env() -> Env {
    Env::real(tokio::runtime::Handle::current())
}

/// Runs `future` on a runtime of its own, then drops the runtime with
/// everything the node spawned on it: the node is gone as a `kill -9` leaves it.
pub(crate) fn run<T>(future: impl Future<Output = T>) -> T {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let output = runtime.block_on(future);
    drop(runtime);
    output
}
