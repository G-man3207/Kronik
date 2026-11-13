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
pub use host::{
    CallOutcome, ConnectionView, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader,
    FetchOutcome, FetchRequest, FetchResponse, GateError, LogEvent, SqlError, SqlHost,
    SqlHostError, SqlRows, SqlValue, StateView, TurnLimits, timer_id,
};
pub use turn::{Program, RunError, TurnOutput, TurnRequest};

/// Kronik's version. All crates in the workspace share it.
pub const KRONIK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of the Wasmtime engine linked into this build.
///
/// `wasmtime` does not export its own version, so it is read from
/// `wasmtime-environ`, which every `wasmtime` release requires at exactly its
/// own version. A test checks that both resolve to this version.
pub const WASMTIME_VERSION: &str = wasmtime_environ::VERSION;

/// The engine version, `kronik-<Kronik version>+wasmtime-<Wasmtime version>`.
pub const ENGINE_VERSION: &str = match core::str::from_utf8(&ENGINE_VERSION_BYTES) {
    Ok(version) => version,
    Err(_) => panic!("the engine version is not valid UTF-8"),
};

const ENGINE_VERSION_PARTS: [&str; 4] = ["kronik-", KRONIK_VERSION, "+wasmtime-", WASMTIME_VERSION];

const ENGINE_VERSION_BYTES: [u8; total_len(&ENGINE_VERSION_PARTS)] =
    concat_bytes(&ENGINE_VERSION_PARTS);

/// Sums the byte lengths of `parts` at compile time.
const fn total_len(parts: &[&str]) -> usize {
    let mut len = 0;
    let mut i = 0;
    while i < parts.len() {
        len += parts[i].len();
        i += 1;
    }
    len
}

/// Concatenates `parts` at compile time. `N` must equal `total_len(parts)`.
const fn concat_bytes<const N: usize>(parts: &[&str]) -> [u8; N] {
    let mut out = [0; N];
    let mut pos = 0;
    let mut i = 0;
    while i < parts.len() {
        let bytes = parts[i].as_bytes();
        let mut j = 0;
        while j < bytes.len() {
            out[pos] = bytes[j];
            pos += 1;
            j += 1;
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::WASMTIME_VERSION;

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
