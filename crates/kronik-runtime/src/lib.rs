//! Wasmtime configuration, the code store per hash, host implementations of
//! the WIT interfaces, and fuel and memory limits.
//!
//! This crate also defines the engine version: the exact Kronik and Wasmtime
//! versions that execute turns. The engine version is recorded with every
//! turn and is part of replay identity.

pub mod allowlist;
pub mod engine;
pub mod host;
pub mod turn;

pub use engine::{CodeError, CodeStore, PoolSize, build_engine};
pub use host::blobs::{
    BLOB_BYTES_PER_FUEL, BLOB_FRAME_BYTES, BlobHost, BlobHostError, MAX_BLOB_CALL_BYTES,
    MAX_OPEN_WRITERS, read_charge,
};
pub use host::{
    CallOutcome, ConnectionView, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchBody,
    FetchHeader, FetchOutcome, FetchRequest, FetchResponse, FetchResponseBody, GateError, LogEvent,
    SendNowOutcome, SendNowRequest, SqlError, SqlHost, SqlHostError, SqlRows, SqlValue, StateView,
    TurnLimits, timer_id,
};
pub use turn::{Program, RunError, TurnOutput, TurnRequest};

/// Kronik's version. All crates in the workspace share it.
pub const KRONIK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the Wasmtime engine linked into this build.
///
/// `wasmtime` does not export its own version. This literal is the version the
/// workspace pins; a test checks it against the Wasmtime packages in
/// `Cargo.lock`, including the transitive `wasmtime-environ`.
pub const WASMTIME_VERSION: &str = "50.0.3";

/// The engine version, `kronik-<Kronik version>+wasmtime-<Wasmtime version>`.
///
/// The Wasmtime part repeats [`WASMTIME_VERSION`] because `concat!` cannot
/// read a constant. A test checks that the two agree.
pub const ENGINE_VERSION: &str =
    concat!("kronik-", env!("CARGO_PKG_VERSION"), "+wasmtime-", "50.0.3",);

#[cfg(test)]
mod tests {
    use super::{ENGINE_VERSION, KRONIK_VERSION, WASMTIME_VERSION};

    #[test]
    fn engine_version_names_the_kronik_and_wasmtime_versions() {
        assert_eq!(
            ENGINE_VERSION,
            format!("kronik-{KRONIK_VERSION}+wasmtime-{WASMTIME_VERSION}")
        );
    }

    #[test]
    fn wasmtime_version_is_the_locked_wasmtime_version() {
        let lockfile =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
                .unwrap();
        for name in [
            "wasmtime",
            "wasmtime-environ",
            "wasmtime-wasi",
            "wasmtime-wasi-io",
            "wasmtime-wasi-http",
        ] {
            assert_eq!(
                locked_versions(&lockfile, name),
                [WASMTIME_VERSION],
                "{name}"
            );
        }
    }

    /// Returns the versions of every package called `name` in a Cargo.lock.
    fn locked_versions(lockfile: &str, name: &str) -> Vec<String> {
        let name_line = format!("name = \"{name}\"");
        lockfile
            .split("[[package]]")
            .filter(|package| package.lines().any(|line| line == name_line))
            .filter_map(|package| {
                package
                    .lines()
                    .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
            })
            .map(str::to_owned)
            .collect()
    }
}
