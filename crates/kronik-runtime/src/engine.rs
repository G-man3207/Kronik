//! The deterministic Wasmtime engine (ADR 0001) and the code store:
//! `code/<blake3>.wasm` plus the precompiled `code/<blake3>.<engine>.cwasm`.
//
// This module calls `Component::deserialize_file`, which is `unsafe`.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use kronik_core::ids::CodeHash;
use kronik_core::sync::lock;
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
/// Bytes of each linear memory that the pooling allocator keeps resident for
/// reuse (Wasmtime's `linear_memory_keep_resident`, ADR 0140, `docs/perf.md`).
pub const LINEAR_MEMORY_KEEP_RESIDENT_BYTES: usize = 2 << 20;
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

/// Sizing of the instance pool: `concurrency` component instances can be
/// live at once, each with up to two linear memories. A turn holds one for
/// as long as it runs, and a turn that waits for its `call` keeps it while
/// the callee's turn holds another.
#[derive(Debug, Clone, Copy)]
pub struct PoolSize {
    pub concurrency: u32,
}

impl PoolSize {
    /// A pool of `instances` instances, at least one.
    pub fn instances(instances: usize) -> PoolSize {
        PoolSize {
            concurrency: u32::try_from(instances.max(1)).unwrap_or(u32::MAX),
        }
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
    p.total_core_instances(n * 48);
    p.total_memories(n * 2);
    p.total_tables(n * 8);
    p.total_stacks(n);
    p.max_core_instances_per_component(64);
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
    p.linear_memory_keep_resident(LINEAR_MEMORY_KEEP_RESIDENT_BYTES);
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
        self.add_inner(bytes, true)
    }

    /// Checks imports and loads the program without writing to the code
    /// directory. A loaded program stays in memory, so a dry run's replay can
    /// run it; nothing here survives a restart.
    pub fn check(&self, bytes: &[u8]) -> Result<(CodeHash, Arc<Program>), CodeError> {
        self.add_inner(bytes, false)
    }

    fn add_inner(
        &self,
        bytes: &[u8],
        persist: bool,
    ) -> Result<(CodeHash, Arc<Program>), CodeError> {
        let bad = crate::allowlist::disallowed_imports(bytes)
            .map_err(|e| CodeError::Invalid(e.to_string()))?;
        if !bad.is_empty() {
            return Err(CodeError::ImportNotAllowed(bad));
        }
        let hash = CodeHash::of(bytes);
        if persist {
            if let Some(path) = self.wasm_path(&hash)
                && !path.exists()
            {
                write_durable(&path, bytes)?;
            }
            self.precompile(&hash, bytes)?;
        }
        let program = if !persist {
            // `load_bytes` would write the .cwasm cache through `component`;
            // a dry run must leave the code directory as it is.
            if let Some(p) = lock(&self.programs).get(&hash) {
                p.clone()
            } else {
                let component = Component::new(&self.engine, bytes).map_err(wt)?;
                let program = Arc::new(Program::new(&self.engine, &component, hash).map_err(wt)?);
                lock(&self.programs).insert(hash, program.clone());
                program
            }
        } else {
            // A dry run may already have loaded this program; make sure the
            // files a later restart reads are there even then.
            self.load_bytes(hash, bytes)?
        };
        lock(&self.bytes).insert(hash, Arc::new(bytes.to_vec()));
        Ok((hash, program))
    }

    /// Writes the precompiled cache for `hash` if it is not there. `component`
    /// would, but it is skipped for a program a dry run already loaded.
    fn precompile(&self, hash: &CodeHash, bytes: &[u8]) -> Result<(), CodeError> {
        let Some(path) = self.cwasm_path(hash) else {
            return Ok(());
        };
        if path.exists() {
            return Ok(());
        }
        let artifact = self.engine.precompile_component(bytes).map_err(wt)?;
        write_durable(&path, &artifact)?;
        Ok(())
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

    /// Drops the cached program and bytes of every hash that is not in
    /// `live` and is durably in the code directory: such a hash reloads
    /// from disk on the next `get`, so dropping it only costs a re-read.
    /// Dry-run code (`check`) exists only in memory and stays cached, as
    /// does everything in a store without a directory. A switch calls
    /// this once its code is installed, so the caches stay bounded by
    /// the live kinds instead of the deploy history (issue #274).
    pub fn sweep(&self, live: &[CodeHash]) {
        let droppable =
            |h: &CodeHash| !live.contains(h) && self.wasm_path(h).is_some_and(|p| p.exists());
        lock(&self.programs).retain(|h, _| !droppable(h));
        lock(&self.bytes).retain(|h, _| !droppable(h));
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

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/guests/counter.wasm"
    ));

    fn store(dir: &std::path::Path) -> CodeStore {
        CodeStore::new(
            build_engine(PoolSize { concurrency: 1 }).unwrap(),
            Some(dir.to_path_buf()),
        )
        .unwrap()
    }

    /// `base` plus a custom section holding `i`: a distinct valid component.
    fn variant(base: &[u8], i: u32) -> Vec<u8> {
        let name = b"kronik-test";
        let payload = i.to_le_bytes();
        let mut out = base.to_vec();
        out.push(0x00); // custom section: id, size, name, payload
        out.push((name.len() + 1 + payload.len()) as u8);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn sweep_drops_persisted_code_and_reloads_it_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let code = store(dir.path());
        let (hash, _) = code.add(COUNTER).unwrap();

        code.sweep(&[]);
        assert!(
            !lock(&code.programs).contains_key(&hash) && !lock(&code.bytes).contains_key(&hash),
            "switched-away code leaves the cache"
        );

        // It is still on disk: a rerun of an old turn reloads it.
        code.get(&hash).unwrap();
        assert!(lock(&code.programs).contains_key(&hash));
    }

    #[test]
    fn sweep_keeps_live_and_dry_run_code() {
        let dir = tempfile::tempdir().unwrap();
        let code = store(dir.path());
        let (deployed, _) = code.add(COUNTER).unwrap();
        // A dry run's code exists only in memory; the sweep must keep it.
        let (dry, _) = code.check(&variant(COUNTER, 7)).unwrap();

        code.sweep(&[deployed]);
        assert!(lock(&code.programs).contains_key(&deployed));
        assert!(
            lock(&code.programs).contains_key(&dry) && lock(&code.bytes).contains_key(&dry),
            "dry-run code is not on disk, so it stays cached"
        );
    }

    #[test]
    fn sweep_keeps_everything_without_a_directory() {
        let code =
            CodeStore::new(build_engine(PoolSize { concurrency: 1 }).unwrap(), None).unwrap();
        let (hash, _) = code.add(COUNTER).unwrap();
        code.sweep(&[]);
        assert!(
            lock(&code.programs).contains_key(&hash) && lock(&code.bytes).contains_key(&hash),
            "an in-memory store has no disk to reload from"
        );
    }

    /// The acceptance soak of issue #274, sized for CI: after any number of
    /// deploys, the cache holds the live code, not the deploy history.
    #[test]
    fn the_cache_stays_bounded_across_deploys() {
        let dir = tempfile::tempdir().unwrap();
        let code = store(dir.path());
        let mut hash = None;
        for i in 0..8u32 {
            hash = Some(code.add(&variant(COUNTER, i)).unwrap().0);
            // Each deploy switches the kind away from the previous code.
            code.sweep(&[hash.unwrap()]);
        }
        assert_eq!(lock(&code.programs).len(), 1);
        assert_eq!(lock(&code.bytes).len(), 1);
        assert!(lock(&code.programs).contains_key(&hash.unwrap()));
    }

    fn names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn check_writes_nothing_and_add_stores_the_component() {
        let dir = tempfile::tempdir().unwrap();
        let code = store(dir.path());

        let (hash, _) = code.check(COUNTER).unwrap();
        assert_eq!(hash, CodeHash::of(COUNTER));
        assert!(code.get(&hash).is_ok(), "a dry run can run what it checked");
        assert_eq!(names(dir.path()), Vec::<String>::new());

        code.add(COUNTER).unwrap();
        let files = names(dir.path());
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(files[0].ends_with(".cwasm"), "{files:?}");
        assert!(files[1].ends_with(".wasm"), "{files:?}");
        assert!(
            files.iter().all(|n| n.starts_with(&hash.hex())),
            "{files:?}"
        );
    }
}
