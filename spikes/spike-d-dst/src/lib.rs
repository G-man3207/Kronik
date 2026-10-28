//! Kronik M0 spike D: deterministic simulation testing of a mini daemon.
//! See `docs/adr/0004-deterministic-simulation.md`.

pub mod daemon;
pub mod env;
pub mod env_real;
#[cfg(madsim)]
pub mod madsim_backend;
pub mod scenario;
pub mod sim;
pub mod wasm;
