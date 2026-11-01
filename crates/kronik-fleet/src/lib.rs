//! Outbound fleet control and operational events over the ordinary API.
//!
//! Controller authority never exceeds the installation's ordinary scopes,
//! policy and durable local revocation epoch. The control panel is external.

pub mod enrollment;
pub mod events;
pub mod transport;
pub mod webhook;
