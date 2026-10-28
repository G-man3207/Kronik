//! The effect registry, capabilities, secret handles, host-side
//! cryptography, recording, matching, divergence policy and effect
//! simulators (docs/design/m2-effects.md).

pub mod config;
pub mod contract;
pub mod crypto;
pub mod foreign;
pub mod http;
pub mod rate;
pub mod simulator;

pub use config::{Capability, Config, ConfigHistory, Delivery, Grant, KindLimits, Rate};
