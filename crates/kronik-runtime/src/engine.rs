//! The deterministic Wasmtime engine (ADR 0001) and the code store:
//! `code/<blake3>.wasm` plus the precompiled `code/<blake3>.<engine>.cwasm`.
//
// This module calls `Component::deserialize_file`, which is `unsafe`.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kronik_core::ids::CodeHash;
use wasmtime::component::Component;
use wasmtime::{Config, Engine, InstanceAllocationStrategy, OptLevel, PoolingAllocationConfig};

use crate::ENGINE_VERSION;
use crate::turn::Program;

/// Default per-turn fuel budget (brief: 50 million).
pub const DEFAULT_FUEL: u64 = 50_000_000;
/// Default per-instance memory limit (brief: 64 MiB).
pub const DEFAULT_MEMORY_BYTES: usize = 64 << 20;
/// Hard ceiling for one linear memory in the pooling allocator; per-kind
/// limits can be raised up to this.
pub const POOL_MAX_MEMORY_BYTES: usize = 1 << 30;
/// Fuel between cooperative yields of a running turn, so one CPU-heavy turn
/// cannot starve an executor thread. Deterministic because fuel is.
pub const FUEL_YIELD_INTERVAL: u64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum CodeError {
    #[error("IMPORT_NOT_ALLOWED: {0:?}")]
    ImportNotAllowed(Vec<String>),
    #[error("invalid component: {0}")]
    Invalid(String),
    #[error("code store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("component {0:?} is not in the code store")]
    Missing(CodeHash),
    #[error("wasmtime: {0}")]
    Wasmtime(String),
}

fn wt(e: wasmtime::Error) -> CodeError {
    CodeError::Wasmtime(format!("{e:#}"))
}

/// Sizing of the instance pool; `concurrency` is the number of turns that can
/// run at once (the scheduler's worker permits).
#[derive(Debug, Clone, Copy)]
pub struct PoolSize {
    pub concurrency: u32,
}

impl Default for PoolSize {
    fn default() -> Self {
        PoolSize { concurrency: 128 }
    }
}

/// Builds the deterministic engine: NaN canonicalization, deterministic
/// relaxed SIMD, no threads, fuel instead of epochs, pooling allocator (a
/// fresh instance never sees a previous instance's memory, I3).
pub fn build_engine(pool: PoolSize) -> Result<Engine, CodeError> {
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
    let n = pool.concurrency.max(1);
    let mut p = PoolingAllocationConfig::new();
    p.total_component_instances(n);
    p.total_core_instances(n * 8);
    p.total_memories(n * 2);
    p.total_tables(n * 8);
    p.total_stacks(n);
    p.max_core_instances_per_component(32);
    p.max_memories_per_component(8);
    p.max_tables_per_component(32);
    p.max_memories_per_module(2);
    p.max_tables_per_module(8);
    p.table_elements(100_000);
    p.max_memory_size(POOL_MAX_MEMORY_BYTES);
    p.max_core_instance_size(4 << 20);
    p.max_component_instance_size(4 << 20);
    // Up to 2 MiB of a reused memory slot is zeroed with memset instead of
    // madvise, so a replay that instantiates the same component thousands
    // of times does not fault the pages back in: a guest's 1 MiB stack plus
    // heap took about a fifth of isolated replay on dev, more on a VM
    // (docs/perf.md). A slot keeps resident only what its instances used,
    // at most this. Memory is still cleared (I3).
    p.linear_memory_keep_resident(2 << 20);
    p.table_keep_resident(64 << 10);
    cfg.allocation_strategy(InstanceAllocationStrategy::Pooling(p));
    Engine::new(&cfg).map_err(wt)
}

/// Content-addressed component storage plus the loaded programs. `dir`
/// `None` keeps everything in memory (simulation, tests).
pub struct CodeStore {
    engine: Engine,
    dir: Option<PathBuf>,
    programs: Mutex<HashMap<CodeHash, Arc<Program>>>,
    bytes: Mutex<HashMap<CodeHash, Arc<Vec<u8>>>>,
}

impl CodeStore {
    pub fn new(engine: Engine, dir: Option<PathBuf>) -> Result<CodeStore, CodeError> {
        if let Some(d) = &dir {
            std::fs::create_dir_all(d)?;
        }
        Ok(CodeStore {
            engine,
            dir,
            programs: Mutex::new(HashMap::new()),
            bytes: Mutex::new(HashMap::new()),
        })
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    fn wasm_path(&self, hash: &CodeHash) -> Option<PathBuf> {
        Some(self.dir.as_ref()?.join(format!("{}.wasm", hash.hex())))
    }

    fn cwasm_path(&self, hash: &CodeHash) -> Option<PathBuf> {
        Some(
            self.dir
                .as_ref()?
                .join(format!("{}.{ENGINE_VERSION}.cwasm", hash.hex())),
        )
    }

    /// Checks imports, stores the bytes durably (write, fsync, rename, fsync
    /// dir) and loads the program. Idempotent.
    pub fn add(&self, bytes: &[u8]) -> Result<(CodeHash, Arc<Program>), CodeError> {
        let bad = crate::allowlist::disallowed_imports(bytes)
            .map_err(|e| CodeError::Invalid(e.to_string()))?;
        if !bad.is_empty() {
            return Err(CodeError::ImportNotAllowed(bad));
        }
        let hash = CodeHash::of(bytes);
        if let Some(path) = self.wasm_path(&hash)
            && !path.exists()
        {
            write_durable(&path, bytes)?;
        }
        lock(&self.bytes).insert(hash, Arc::new(bytes.to_vec()));
        let program = self.load_bytes(hash, bytes)?;
        Ok((hash, program))
    }

    /// The program for `hash`, loading it from disk on first use.
    pub fn get(&self, hash: &CodeHash) -> Result<Arc<Program>, CodeError> {
        if let Some(p) = lock(&self.programs).get(hash) {
            return Ok(p.clone());
        }
        let bytes = self.bytes(hash)?;
        self.load_bytes(*hash, &bytes)
    }

    /// The component bytes for `hash`.
    pub fn bytes(&self, hash: &CodeHash) -> Result<Arc<Vec<u8>>, CodeError> {
        if let Some(b) = lock(&self.bytes).get(hash) {
            return Ok(b.clone());
        }
        let path = self.wasm_path(hash).ok_or(CodeError::Missing(*hash))?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CodeError::Missing(*hash));
            }
            Err(e) => return Err(e.into()),
        };
        if CodeHash::of(&bytes) != *hash {
            return Err(CodeError::Invalid(format!(
                "{} does not match its hash",
                path.display()
            )));
        }
        let bytes = Arc::new(bytes);
        lock(&self.bytes).insert(*hash, bytes.clone());
        Ok(bytes)
    }

    fn load_bytes(&self, hash: CodeHash, bytes: &[u8]) -> Result<Arc<Program>, CodeError> {
        if let Some(p) = lock(&self.programs).get(&hash) {
            return Ok(p.clone());
        }
        let component = self.component(&hash, bytes)?;
        let program = Arc::new(Program::new(&self.engine, &component, hash).map_err(wt)?);
        lock(&self.programs).insert(hash, program.clone());
        Ok(program)
    }

    /// Loads through the precompiled cache. Wasmtime refuses artifacts of
    /// another engine version or configuration; such a file is a cache miss.
    fn component(&self, hash: &CodeHash, bytes: &[u8]) -> Result<Component, CodeError> {
        let Some(path) = self.cwasm_path(hash) else {
            return Component::new(&self.engine, bytes).map_err(wt);
        };
        if path.exists() {
            // SAFETY: the file lives in Kronik's own code directory, was
            // written by `precompile_component` of this engine version (the
            // version is in the file name), and Wasmtime validates the
            // artifact header and engine fingerprint before using it.
            match unsafe { Component::deserialize_file(&self.engine, &path) } {
                Ok(c) => return Ok(c),
                Err(e) => tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "ignoring incompatible precompiled code"
                ),
            }
        }
        let artifact = self.engine.precompile_component(bytes).map_err(wt)?;
        write_durable(&path, &artifact)?;
        // SAFETY: as above; the file was just written by this process.
        unsafe { Component::deserialize_file(&self.engine, &path) }.map_err(wt)
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Write to a temporary file, fsync, rename, fsync the directory.
fn write_durable(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}
