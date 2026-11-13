//! Generates the log schema types from `proto/kronik/log/v1/*.proto`.
//!
//! `protox` compiles the files in pure Rust, so building Kronik does not need
//! `protoc` on the machine.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let files = [
        "common", "input", "turn", "config", "branch", "effects", "control",
    ]
    .map(|name| root.join(format!("kronik/log/v1/{name}.proto")));
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let descriptors = protox::compile(&files, [&root])?;
    // BTreeMap so that a record's bytes (and so its hash) are deterministic.
    // prost derives Eq and Hash only for messages without a repeated message
    // field; EffectRecord had them before its `blobs` (M25) and every field
    // it holds still has them.
    prost_build::Config::new()
        .btree_map([".kronik.log.v1.AuditEvent.details"])
        .type_attribute(".kronik.log.v1.EffectRecord", "#[derive(Eq, Hash)]")
        .compile_fds(descriptors)?;
    Ok(())
}
