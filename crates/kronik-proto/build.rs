//! Generates the log schema types from `proto/kronik/log/v1/*.proto`.
//!
//! `protox` compiles the files in pure Rust, so building Kronik does not need
//! `protoc` on the machine.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let files = ["common", "input", "turn", "config", "branch", "effects"]
        .map(|name| root.join(format!("kronik/log/v1/{name}.proto")));
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let descriptors = protox::compile(&files, [&root])?;
    // BTreeMap so that a record's bytes (and so its hash) are deterministic.
    prost_build::Config::new()
        .btree_map([".kronik.log.v1.AuditEvent.details"])
        .compile_fds(descriptors)?;
    Ok(())
}
