//! Foreign actors (docs/design/m7-foreign.md, ADR 0003): OCI images pinned
//! by digest, bundles for `runsc` (and plain `runc` for `trusted`), the
//! sandbox lifecycle, and the bridge that carries `foreign://<name>/...`
//! calls into the sandbox.
//!
//! - [`image`], [`blobs`], [`fetch`] and [`oci`]: image references, the
//!   content-addressed blob store, fetching from registries and local OCI
//!   layouts with digest verification, unpacking layers into a rootfs and
//!   generating `config.json`.
//! - [`sys`]: network namespaces and the other syscalls without a safe
//!   binding (the crate's only `unsafe`).
//! - [`Foreign`]: the manager the daemon holds. [`Host`] wraps it as the
//!   node's [`kronik_effects::foreign::ForeignHost`] (reconcile and the
//!   bridge); the API calls it to validate an add, for status and logs.
//!
//! This crate is the real sandbox boundary, outside DST (ADR 0004 §5). It
//! still takes time, tasks, blocking work and child processes from the
//! daemon's [`kronik_core::env::Env`].

pub mod blobs;
pub mod fetch;
pub mod image;
pub mod oci;
pub mod sys;

mod bridge;
mod layout;
mod logs;
mod manager;
mod runtime;
mod supervisor;

pub use image::{ImageError, ImageRef};
pub use manager::{
    AddPlan, AddRequest, Cleaned, Foreign, ForeignConfig, Host, Isolation, LogTail, Platform,
    RUN_LOCK, TESTED_RUNSC, TRUSTED_WARNING,
};
pub use supervisor::{LastExit, State, Status};
