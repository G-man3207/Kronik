//! Engine configuration for deterministic execution, the engine-version
//! string, and the precompiled-code cache keyed by (component hash, engine
//! version).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use wasmtime::component::Component;
use wasmtime::{Config, Engine, InstanceAllocationStrategy, OptLevel, PoolingAllocationConfig};

/// Kronik's version as it would be reported by the `kronik` binary.
pub const KRONIK_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The exact linked Wasmtime version. `wasmtime` exports no version constant;
/// `wasmtime-environ` does and is always required at exactly the same version
/// (same approach as `crates/kronik-runtime`).
pub const WASMTIME_VERSION: &str = wasmtime_environ::VERSION;

/// Default per-turn fuel budget from the brief.
pub const DEFAULT_FUEL: u64 = 50_000_000;

/// Default per-instance memory limit from the brief (64 MiB).
pub const DEFAULT_MEMORY_BYTES: usize = 64 << 20;

/// Hard ceiling for a single linear memory in the pooling allocator. Per-kind
/// limits (enforced by the `ResourceLimiter`) may be raised up to this value.
pub const POOL_MAX_MEMORY_BYTES: usize = 1 << 30;

/// Fuel consumed between cooperative yields of the async turn future. This
/// keeps one CPU-heavy turn from starving a single-threaded executor (the DST
/// executor in particular) and is deterministic because fuel is.
pub const FUEL_YIELD_INTERVAL: u64 = 1_000_000;

/// The engine version that is written into every `TurnBegin` and turn record
/// and is part of the replay identity: `kronik-<kronik semver>+wasmtime-<wasmtime semver>`.
pub fn engine_version() -> String {
    format!("kronik-{KRONIK_VERSION}+wasmtime-{WASMTIME_VERSION}")
}

/// Builds the deterministic engine.
///
/// Determinism-relevant settings:
/// - NaN canonicalization on: every float op that can produce a NaN produces
///   the canonical NaN, so NaN bit patterns cannot differ between hosts.
/// - Relaxed SIMD stays enabled (ComponentizeJS/StarlingMonkey builds may use
///   it) but is forced to its deterministic semantics on every architecture.
/// - Threads: the `threads` Cargo feature of `wasmtime` is not compiled in, so
///   the threads proposal (shared memories, atomics wait/notify) cannot be
///   enabled; shared-everything-threads is explicitly off.
/// - Fuel instead of epochs: fuel is a deterministic function of the executed
///   code, epochs depend on wall-clock time.
/// - Pooling allocator: instance slots are reset between uses, so a fresh
///   instance never sees a previous instance's memory (I3).
pub fn build_engine() -> wasmtime::Result<Engine> {
    build_engine_with(true)
}

/// `pooling = false` exists only to benchmark the on-demand allocator.
pub fn build_engine_with(pooling: bool) -> wasmtime::Result<Engine> {
    let mut cfg = Config::new();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(false);
    cfg.cranelift_nan_canonicalization(true);
    cfg.wasm_relaxed_simd(true);
    cfg.relaxed_simd_deterministic(true);
    cfg.wasm_shared_everything_threads(false);
    cfg.cranelift_opt_level(OptLevel::Speed);
    cfg.parallel_compilation(true);
    if !pooling {
        return Engine::new(&cfg);
    }

    let mut pool = PoolingAllocationConfig::new();
    // Sized for a spike; the daemon derives these from its worker-pool size.
    pool.total_component_instances(64);
    pool.total_core_instances(512);
    pool.total_memories(128);
    pool.total_tables(512);
    pool.total_stacks(64);
    pool.max_core_instances_per_component(32);
    pool.max_memories_per_component(8);
    pool.max_tables_per_component(32);
    pool.max_memories_per_module(2);
    pool.max_tables_per_module(8);
    pool.table_elements(100_000);
    pool.max_memory_size(POOL_MAX_MEMORY_BYTES);
    pool.max_core_instance_size(4 << 20);
    pool.max_component_instance_size(4 << 20);
    cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));

    Engine::new(&cfg)
}

/// Where a component's code came from when it was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSource {
    /// Compiled in-process from the component bytes (no cache configured).
    Compiled,
    /// Compiled, written to the cache, and loaded back from it.
    CompiledAndCached,
    /// Loaded from an existing precompiled cache file.
    CacheHit,
}

pub struct LoadedCode {
    pub component: Component,
    /// `b3:` + full hex BLAKE3 of the component bytes (the code identity).
    pub code_hash: String,
    pub source: CodeSource,
    pub compile_time: Option<Duration>,
    pub load_time: Duration,
    pub cache_file: Option<PathBuf>,
}

/// Short display form from the brief: `b3:` plus 12 hex characters.
pub fn short_hash(code_hash: &str) -> &str {
    &code_hash[..code_hash.len().min(3 + 12)]
}

pub fn code_hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

/// Path of the precompiled artifact: `<dir>/<blake3>.<engine-version>.cwasm`,
/// matching the brief's `code/<blake3>.<engine>.cwasm` layout.
pub fn cache_path(dir: &Path, code_hash: &str) -> PathBuf {
    let hex = code_hash.trim_start_matches("b3:");
    dir.join(format!("{hex}.{}.cwasm", engine_version()))
}

/// Loads a component, going through the precompiled cache when `cache_dir` is
/// set. The cache key contains the engine version, and Wasmtime additionally
/// refuses artifacts whose embedded engine/config fingerprint differs; such a
/// file is treated as a miss and overwritten.
pub fn load_component(
    engine: &Engine,
    bytes: &[u8],
    cache_dir: Option<&Path>,
) -> wasmtime::Result<LoadedCode> {
    let hash = code_hash(bytes);
    let Some(dir) = cache_dir else {
        let start = Instant::now();
        let component = Component::new(engine, bytes)?;
        let t = start.elapsed();
        return Ok(LoadedCode {
            component,
            code_hash: hash,
            source: CodeSource::Compiled,
            compile_time: Some(t),
            load_time: t,
            cache_file: None,
        });
    };

    std::fs::create_dir_all(dir)?;
    let path = cache_path(dir, &hash);
    if path.exists() {
        let start = Instant::now();
        // SAFETY: the file lives in Kronik's own data directory and was
        // produced by `Engine::precompile_component` of this exact engine
        // version (encoded in the file name). Wasmtime validates the artifact
        // header and engine fingerprint before using it.
        match unsafe { Component::deserialize_file(engine, &path) } {
            Ok(component) => {
                return Ok(LoadedCode {
                    component,
                    code_hash: hash,
                    source: CodeSource::CacheHit,
                    compile_time: None,
                    load_time: start.elapsed(),
                    cache_file: Some(path),
                });
            }
            Err(e) => {
                eprintln!(
                    "note: ignoring incompatible cache file {}: {e}",
                    path.display()
                );
            }
        }
    }

    let start = Instant::now();
    let artifact = engine.precompile_component(bytes)?;
    let compile_time = start.elapsed();
    let tmp = path.with_extension("cwasm.tmp");
    std::fs::write(&tmp, &artifact)?;
    std::fs::rename(&tmp, &path)?;
    let start = Instant::now();
    // SAFETY: see above; the file was written by this process just now.
    let component = unsafe { Component::deserialize_file(engine, &path)? };
    Ok(LoadedCode {
        component,
        code_hash: hash,
        source: CodeSource::CompiledAndCached,
        compile_time: Some(compile_time),
        load_time: start.elapsed(),
        cache_file: Some(path),
    })
}
