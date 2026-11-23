//! Writes `linear_memory_keep_resident.rs` for issue #78 perf sweeps.

const DEFAULT: usize = 2 << 20;

fn allowed_bytes() -> Option<usize> {
    let raw = std::env::var("KRONIK_PERF_LINEAR_MEMORY_KEEP_RESIDENT").ok()?;
    match raw.as_str() {
        "0" => Some(0),
        "262144" => Some(256 << 10),
        "524288" => Some(512 << 10),
        "1048576" => Some(1 << 20),
        "2097152" => Some(2 << 20),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = allowed_bytes().unwrap_or(DEFAULT);
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let src = format!(
        "/// Bytes of reused linear memory the pooling allocator keeps resident \
         (Wasmtime's `linear_memory_keep_resident`). Default 2 MiB (docs/perf.md). \
         Set at build time with `KRONIK_PERF_LINEAR_MEMORY_KEEP_RESIDENT` for issue #78 sweeps only.\n\
         pub const LINEAR_MEMORY_KEEP_RESIDENT_BYTES: usize = {bytes};\n"
    );
    std::fs::write(out.join("linear_memory_keep_resident.rs"), src)?;
    println!("cargo:rerun-if-env-changed=KRONIK_PERF_LINEAR_MEMORY_KEEP_RESIDENT");
    Ok(())
}
