//! Generates the OTLP message types from the vendored
//! `proto/opentelemetry/` files (opentelemetry-proto v1.7.0, ADR 0081), as
//! `kronik-proto` does for the log schema: protox compiles them in pure Rust.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let files = [
        "common/v1/common",
        "resource/v1/resource",
        "trace/v1/trace",
        "metrics/v1/metrics",
        "collector/trace/v1/trace_service",
        "collector/metrics/v1/metrics_service",
    ]
    .map(|name| root.join(format!("opentelemetry/proto/{name}.proto")));
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let descriptors = protox::compile(&files, [&root])?;
    // The upstream comments hold JSON examples that rustdoc would run as
    // doctests; the vendored .proto files keep them.
    prost_build::Config::new()
        .disable_comments(["."])
        .compile_fds(descriptors)?;
    Ok(())
}
