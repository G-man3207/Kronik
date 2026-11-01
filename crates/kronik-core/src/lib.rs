//! Identifiers, causal keys, error codes, logical time and the I/O boundary
//! (`env`) shared by every Kronik crate.
//!
//! The stable error codes live in this crate ([`error`]), with the built-in
//! documentation that `kronik explain` prints ([`explain`]).

pub mod authority;
pub mod causal;
pub mod env;
pub mod error;
pub mod explain;
pub mod http;
#[cfg(feature = "host-identity")]
pub mod identity;
pub mod ids;
pub mod snapshot_resources;
pub mod time;
