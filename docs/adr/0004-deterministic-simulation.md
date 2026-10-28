# 0004. Deterministic simulation testing on our own executor

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

The brief ("Teststrategi", "DST-design", M0 spike D) requires `kronik-sim`
to run the *whole daemon* in a simulated world. That world has a virtual
clock, a disk that loses unsynced writes and tears the last one, simulated
external services with latency and faults, and crashes and restarts at
random points. Everything runs on a single-threaded deterministic executor.
The test volume is 200 seeds per PR, 10,000 seeds nightly, and at least one
run of 1M steps. A failing seed must be reproducible with
`cargo test -p kronik-sim -- --seed 12345`. All I/O goes through `Clock`,
`Fs`, `Net`, `Spawner`, `EntropySource` and `ProcessRunner`, each with a real
and a simulated implementation. The question was `madsim` or our own
executor. ADR 0001 already decided that host functions are async, so a turn
is a future that a simulator can drive.

Spike D (`spikes/spike-d-dst/`) built a mini daemon that contains the hard
parts and ran it on both executors:

- **Log:** segment header, envelopes of `[u32 len][u32 crc32c][u64 lsn][u8
  kind][payload]`, a group-commit writer (2 ms window), `fdatasync` through
  `Fs`, torn-tail truncation on recovery, and an fsync error treated as fatal
  (never retried).
- **Turns:** each turn runs the Rust guest on a fresh Wasmtime instance (ADR
  0001: async host functions, fuel yields every 20k fuel). The guest makes
  one external effect (`POST https://payments.sim/charge`) through `Net`. A
  `TurnBegin` is fsynced before the effect (I14), an `EffectResult` before
  the guest sees the result, and a `TurnRecord` before the reply.
- **State and recovery:** materialized state lives in real SQLite
  (`rusqlite`). A single applier applies records in LSN order, writing
  `applied_lsn` and the logical-time high-water mark in the same
  transaction. Recovery re-applies the log tail and re-runs every
  `TurnBegin` that has no `TurnRecord`. Recorded effect results are
  replayed; for an effect without a result, an `idempotency-keyed` target
  gets the request again with the same key and an `unsafe` target gives the
  guest `outcome-unknown` (I17).
- **Ingress:** `Idempotency-Key` dedup across crashes, including requests
  that arrive while the original is still in flight.
- **Faults:** crashes at random times (the node's tasks are dropped);
  unsynced writes lost or torn, in two models: prefix-with-torn-last, and
  per-sector reordering; unsynced directory entries lost; a stale `state.db`
  after a crash (WAL `synchronous=NORMAL`); injected fsync EIO; connect
  failures, lost responses and hung requests; wall-clock jumps of up to
  5 s backwards.
- **Invariants checked:**
  - No acknowledged turn is lost, and every acknowledgement matches its
    `TurnRecord`.
  - Each ingress key commits exactly once.
  - The counter value `n` runs exactly 1..N per actor and equals the state.
  - The state after incremental recovery equals a rebuild from the durable
    log, and identity replay of every committed turn through Wasm gives the
    same writes, outcome, effects and fuel.
  - No external effect is received before its `TurnBegin` is durable (data
    and directory entry). The external service checks this at the moment it
    receives the request.
  - An `unsafe` effect is never delivered twice.
  - Logical time handed out is always above every durable logical time and
    above the previous assignment (I15).
  - Every request gets a definite answer.
  - Same seed gives the same event-trace hash.

## Decision

### 1. Our own executor in `kronik-sim`, not madsim

Both executors ran the identical daemon and scenario code, and both were
deterministic and found no violations (see Measurements). We choose our own
executor for these reasons:

- **madsim does not provide what DST needs most.** In madsim 0.2.34,
  `FsSim::power_fail` is an empty `TODO`, and `madsim-tokio` re-exports the
  *real* `tokio::fs`. Crash semantics (lost or torn unsynced writes, lost
  directory entries) need our own `SimFs` either way. madsim's network is
  socket-level, and we inject at the HTTP effect boundary and at the
  gateway's service function (see 5).
- **Crash semantics.** Our `kill_node` drops every future of the node at
  once, as a real crash does. madsim's `kill`/`restart` drops a killed
  task's future only when that task is next scheduled. A task that is never
  woken again keeps its destructors from running (for example, oneshot
  senders stay alive), which a real crash never does.
- **The selling point does not apply.** madsim's value is that code written
  against tokio, and dependencies using tokio, become simulated when
  rebuilt with `--cfg madsim`. Our boundary is `Env` (section 2). Hyper,
  axum, rustls and object_store sit outside the simulated core, so there is
  nothing for madsim to transparently intercept. Making those crates run
  under madsim would require `[patch.crates-io]` forks for the whole graph,
  which is what RisingWave maintains.
- **Build and maintenance cost.** madsim needs `RUSTFLAGS="--cfg madsim"`
  for the entire dependency graph and therefore a second target directory.
  The spike's madsim build took 103 s on top of the normal build;
  `wasmtime`, `cranelift` and `rusqlite` compiled unchanged under the cfg.
  madsim also works by overriding libc symbols (`clock_gettime`,
  `getrandom`, `sysconf`, `pthread_attr_init`). As a result
  `std::time::Instant::now()` silently returns simulated time inside the
  runtime: the spike's first wall-time measurement read 0 ms because of
  this. Creating an OS thread inside the simulation fails, so Wasmtime's
  parallel compilation has to happen outside it. The last `madsim-tokio`
  release was 2024-10 and the last `madsim` release 2025-10.
- **Control.** Our executor is about 300 lines (`sim/exec.rs`), has no libc tricks, runs as
  an ordinary `cargo test` target, and we own the scheduling policy and the
  fault hooks (for example, crashing a node at an exact step).

Throughput is not the deciding factor. madsim's raw executor is faster (5.0M
vs 2.6–2.9M polls/s), but both are about 50x faster than the daemon needs,
and whole-scenario throughput was the same on both (30.2 vs 29.9 seeds/s).

Because the daemon only sees `Env`, switching to madsim later stays cheap:
the spike runs the same scenario on madsim with a 170-line backend (`madsim_backend.rs`).

### 2. The trait set: `kronik-core::env`

Lift `spikes/spike-d-dst/src/env.rs` verbatim into `kronik-core::env`. It
depends only on `bytes` and `tokio` with the `sync` and `macros` features
(for `oneshot` and a biased `select!`).

- **Explicit context.** Every component receives an `Env` (a cheap-to-clone
  bundle of `Arc<dyn _>`). There are no globals and no thread-locals, so
  several simulated nodes (clusters in v0.4) can share one process.
- **Object-safe traits with boxed futures** (`BoxFuture<'static, T>`, which
  is `Send`). One allocation per I/O operation is negligible next to the I/O
  itself. A generic `E: Env` parameter would infect every type of every
  crate and compile the daemon twice.
- **Sync vs async.** Methods that only read a value are synchronous; methods
  that wait are async. All futures are `Send + 'static`, so the same code
  runs on tokio's multi-threaded runtime.

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Clock: Send + Sync + 'static {
    fn wall_ms(&self) -> u64;              // may jump either way; one input to I15
    fn monotonic(&self) -> Duration;       // never decreases
    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>;
}
pub trait Spawner: Send + Sync + 'static {
    fn spawn(&self, name: &'static str, fut: BoxFuture<'static, ()>);
    fn spawn_blocking(&self, name: &'static str, f: Box<dyn FnOnce() + Send + 'static>);
}
pub trait EntropySource: Send + Sync + 'static { fn fill(&self, buf: &mut [u8]); }
pub trait Fs: Send + Sync + 'static {        // creation/rename/removal durable after sync_dir
    fn create_dir_all(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    fn open(&self, path: PathBuf, mode: OpenMode) -> BoxFuture<'static, io::Result<Arc<dyn File>>>;
    fn exists(&self, path: PathBuf) -> BoxFuture<'static, io::Result<bool>>;
    fn read_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<Vec<String>>>;
    fn rename(&self, from: PathBuf, to: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    fn remove_file(&self, path: PathBuf) -> BoxFuture<'static, io::Result<()>>;
    fn sync_dir(&self, dir: PathBuf) -> BoxFuture<'static, io::Result<()>>;
}
pub trait File: Send + Sync + 'static {      // owned buffers: hand-off to blocking threads
    fn len(&self) -> BoxFuture<'static, io::Result<u64>>;
    fn read_at(&self, offset: u64, len: usize) -> BoxFuture<'static, io::Result<Vec<u8>>>;
    fn write_at(&self, offset: u64, data: Bytes) -> BoxFuture<'static, io::Result<()>>;
    fn set_len(&self, len: u64) -> BoxFuture<'static, io::Result<()>>;
    fn sync_data(&self) -> BoxFuture<'static, io::Result<()>>;   // error = fatal, never retry
}
pub trait Net: Send + Sync + 'static {       // outbound HTTP at the effect boundary
    fn http(&self, req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>>;
}
pub enum NetError { Connect(String) /* definitely not sent */, Io(String) /* outcome unknown */ }
pub trait ProcessRunner: Send + Sync + 'static {
    fn spawn(&self, spec: ProcessSpec) -> BoxFuture<'static, io::Result<Arc<dyn Process>>>;
}
pub trait Process: Send + Sync + 'static {
    fn id(&self) -> Option<u32>;
    fn wait(&self) -> BoxFuture<'static, io::Result<Option<i32>>>;
    fn kill(&self) -> BoxFuture<'static, io::Result<()>>;
}
#[derive(Clone)]
pub struct Env { clock, spawner, entropy, fs, net, procs }   // all Arc<dyn _>
impl Env {
    fn spawn<T>(&self, name, fut) -> JoinHandle<T>;          // via oneshot; drop = detach
    fn blocking<T>(&self, name, f) -> JoinHandle<T>;
    async fn timeout<T>(&self, d, fut) -> Result<T, Elapsed>; // biased: the future wins ties
    fn random_bytes<const N: usize>(&self) -> [u8; N];
}
```

- **Where the implementations live.** The real implementations go in
  `kronik-core::env::real` behind a cargo feature `real`, enabled only by the
  `kronik` binary and integration tests (source:
  `spikes/spike-d-dst/src/env_real.rs`). The simulated ones go in
  `kronik-sim` (source: `spikes/spike-d-dst/src/sim/`).
- **Inbound HTTP is not part of `Net`** (see 5). A real `Net` (a hyper
  client) comes in M2; the spike's real mode used an in-process loopback.

### 3. One daemon, two runtimes

- **Production:** a tokio multi-threaded runtime.
  - `RealSpawner` wraps a `tokio::runtime::Handle`.
  - `RealClock` is `SystemTime` plus `tokio::time`.
  - `RealFs` runs every blocking syscall (`write_at`, `fdatasync`, the
    directory fsync) on tokio's blocking pool through `spawn_blocking`, so an
    fsync never stalls an async worker.
  - The log writer is one task, so its writes and fsyncs are serialized
    without locks.
  - SQLite calls go through `Env::blocking`. The applier owns the write
    connection and commits one transaction per group-commit batch.
  - Wasm turns run as ordinary tasks; fuel yields (ADR 0001) keep them
    cooperative.
- **Simulation:** the deterministic executor, with `SimClock`, `SimSpawner`
  (spawns onto a node; `spawn_blocking` runs inline as one step), `SimFs`,
  `SimNet`, `SimEntropy` and `SimProcs`.
- **Proof:** the spike's `real` mode runs the same daemon code on tokio (4
  workers) with real files and a WAL `state.db`. It served 400 concurrent
  requests, restarted through recovery with identical state, and passed
  identity replay of the real log file.

**What daemon code may use from tokio:** only `tokio::sync` (`mpsc`,
`oneshot`, `Mutex`, `RwLock`, `Semaphore`, `Notify`) and `tokio::select!`
with `biased;`.

- **Not allowed:** `tokio::spawn`, `tokio::task::spawn_blocking`,
  `tokio::time`, `tokio::net`, `tokio::fs`, `tokio::process`, `tokio::signal`
  and `tokio::runtime`. They exist only in `kronik-core::env::real`, the
  gateway/API servers and the `kronik` binary.
- **`tokio::sync::watch` is banned.** The DST determinism check found this:
  watch receivers register on one of eight `Notify` shards chosen by tokio's
  thread-local RNG (`BigNotify`, seeded from the OS), so the wake order
  differed between runs of the same seed (14 of 40 seeds). It was replaced by
  an `AtomicU64` plus `Notify` (`AppliedLsn` in the spike).
- **`select!` without `biased;` is banned** for the same reason (it uses the
  same RNG).
- **Enforcement:**
  - Daemon crates enable only tokio's `sync` and `macros` features.
  - `clippy.toml` gets `disallowed-methods` / `disallowed-types` for the
    items above and for the hygiene rules in 6.
  - A CI check runs `cargo tree -e features` and rejects tokio's `rt`,
    `time`, `net`, `fs` and `process` in any crate other than `kronik`,
    `kronik-gateway`, `kronik-api` and `kronik-core` with feature `real`.

### 4. SQLite (`state.db`, per-actor SQL)

SQLite is not behind `Fs`.

- **Production** opens files: WAL with `synchronous=NORMAL` for `state.db`.
  The per-actor layout follows ADR 0005.
- **Simulation** opens in-memory databases with the same `rusqlite` code, so
  statement behaviour and the session extension are identical. It models a
  crash by keeping serialized images (`sqlite3_serialize`). Each commit
  appends an image; a random subset become "checkpoints". On a crash, the
  database comes back as any commit at or after the last checkpoint, which
  is the `synchronous=NORMAL` guarantee. Snapshotting costs O(database size)
  per commit, so long runs snapshot only every 64th commit.
- **What DST checks** is everything Kronik relies on: atomic
  `applied_lsn` + changes, recovery from a stale `state.db`, and rebuild
  equality.
- **What DST does not check** is SQLite's own file durability. The nightly
  real `kill -9` crash test covers that.
- **Seam in M1:** `kronik-store` takes a `SqliteOpener` (`fn open(&self,
  name) -> rusqlite::Result<Connection>` plus an optional commit hook)
  instead of paths.

### 5. HTTP layers and the boundary of DST

- **The gateway and API are split** into a service function and a server.
  The service function (`async fn handle(&self, req) -> Response` over
  `Env`) is what the simulator calls, and it sits behind the routing,
  ingress idempotency and auth logic. The server binds that function to
  hyper/axum, TLS, ACME and the Unix socket. The CLI and MCP are clients of
  the API service and can be driven the same way.
- **Outside DST:** the hyper/axum/rustls/ACME servers, real sockets, real
  `runsc`, SQLite's file durability and `object_store`. Those are covered by
  integration tests, the nightly `kill -9` loop on a real disk, and the VPS
  test.

### 6. Determinism hygiene for daemon code

1. No ambient time: no `SystemTime::now` or `Instant::now`; use
   `env.clock`.
2. No ambient randomness: no `rand::thread_rng`, `getrandom` or `uuid` v4;
   use `env.entropy`.
3. No OS threads (`std::thread::spawn`); use `env.spawn` and
   `env.blocking`.
4. No iteration over `HashMap`/`HashSet` with `RandomState` where the order
   can leak (scheduling, log order, output). Use `BTreeMap`/`BTreeSet`, or
   a fixed hasher where iteration never matters. The `HashMapRerunOrder`
   mutation (below) shows the determinism check catching exactly this.
5. `select!` only with `biased;`; no `tokio::sync::watch`; no tokio
   primitive that uses its internal RNG.
6. No std `Mutex` guard held across an `.await`. On the single-threaded
   simulator that deadlocks the whole run; it happened once in the spike,
   via a guard kept alive through a `let … else` block.
   `clippy::await_holding_lock` must stay denied.
7. Never wake wakers while holding an executor or primitive lock (this was
   an executor bug found in the spike).
8. Order of work must come from data (LSN, causal keys), never from task
   completion order. For example, recovery re-runs pending turns in the log
   order of their `TurnBegin`.
9. No pointer-address-dependent logic, and no reading environment variables
   or files outside `Env`/config at runtime.
10. Every wait has a `Clock`-based timeout, so no seed can hang forever.

### 7. Harness, seeds and reproduction

- **Custom harness.** `kronik-sim` has a `[[test]] harness = false` target
  that parses `--seed N` and `--seeds A..B`, because libtest rejects unknown
  flags. `cargo test --release --test dst -- --seed 12345` works in the
  spike.
- **Seed-derived variation.** The fault mix comes from the seed (crash model
  and delivery class alternate), so a seed range covers all models.
- **Failure output.** A failure prints the violations, the last 64 events
  and the exact reproduce command. `DST_TRACE=1` streams every event.
- **Determinism check.** Each event (with its virtual time) is hashed with
  BLAKE3. CI runs a slice of seeds twice and requires identical hashes. The
  spike's seed 12345 gave hash `0842addb3798aa9d` on both the AMD dev
  machine and the Intel VPS.
- **Mutation tests.** The harness's checks must keep catching seeded bugs.
  The `mutants` command runs each deliberate bug against a seed range and
  requires that at least one seed catches it.

### 8. Findings that shape M1

- **Log recovery rule.**
  - In the *active* segment, everything from the first record that fails
    its CRC or LSN check is a torn tail: truncate it and fsync.
  - Once unsynced pages can persist out of order, valid records can appear
    *after* a tear. This happened 26 times in the 1M-step run. Those records
    were never acknowledged, because acknowledgement waits for the fsync of
    everything before them, so dropping them is correct.
  - "Corrupt record in the middle → `STORAGE_CORRUPT`" therefore applies to
    *closed* segments (immutable, fully synced). In the active segment it
    applies only to a record that passes its CRC but does not decode.
- **The applier is fed by the log writer** in LSN order after each fsync,
  never by the turns themselves. Turns wait for "applied ≥ my LSN" before
  replying and releasing the actor lock. Otherwise `applied_lsn` can skip a
  record.
- **The logical-time high-water mark** after recovery is the maximum over
  *all* records, `TurnBegin` included, not only applied `TurnRecord`s.
- **The precise I15 property** for tests: every newly assigned time is
  above every logical time already durable, and above the previous
  assignment in this process. Commit order in the log is *not* monotonic in
  time, because concurrent actors commit out of start order.
- **Ingress idempotency** must check the saved response *and* the in-flight
  table under one lock, and a turn leaves the in-flight table only after it
  is applied.
- **Cost of one effect.** A turn with one effect needs three sequential
  durable appends (`TurnBegin`, `EffectResult`, `TurnRecord`). With the 2 ms
  group-commit window, a single actor serializes on about 3 × (window +
  fsync). Group commit amortizes this only across actors. In real mode this
  measured 297–314 turns/s with 4 busy actors.
- **Crash recovery must be O(tail).** In the spike, recovery reads and
  decodes the whole single segment on every crash, which made the 1M-step
  run cost 224 s instead of about 81 s without crashes. M1 needs segment
  rolling, the `applied_lsn` skip, and the footer index from the start. The
  simulator's own invariant checks must be incremental too (the spike's
  `DurableView` is).
- **SQLite cost.** Use `prepare_cached` for every hot statement; per-turn
  statement preparation is a visible cost in the simulator.

## Alternatives

- **madsim:** see 1. It is kept as a possible backend, since the `Env`
  boundary makes it cheap to swap in.
- **turmoil:** a network and host simulator on top of tokio, with
  simulated TCP and partitions. It has no disk or crash model and relies on
  tokio's scheduler, which is not seed-controlled. It suits network
  protocols (useful for the v0.4 cluster), not single-node crash
  correctness.
- **tokio `current_thread` with `start_paused`:** a virtual clock comes for
  free, but tokio's internal RNG (`select!`, `watch`) and scheduler order are
  not seed-controlled, and there is no node or crash model.
- **loom or shuttle:** model checkers for concurrency primitives. They are
  complementary for small lock-free structures and unsuitable for a whole
  daemon.
- **A generic `E: Env` instead of `Arc<dyn _>`:** this avoids one box per
  I/O operation but monomorphizes every crate and leaks the parameter into
  every type. Rejected.

## Consequences

- **Every M1 crate takes an `Env`.** No crate other than the binary, the
  servers and `env::real` touches tokio's runtime, time, network, file
  system or process APIs. This is enforced by features, clippy and a CI
  check.
- **`kronik-sim` owns** the executor, `SimFs`, `SimNet`, the external
  service fakes, the crash models, the invariant catalogue, the harness and
  the mutation suite. New invariants (messages, timers, `call` dedup,
  compensations, forks without live effects) are added as checks in the
  same style.
- **CI cost** at today's prototype rates:
  - 200 seeds per PR: 2–6 s with 8 threads.
  - 10,000 seeds nightly: about 7 min single-threaded or about 5 min with 8
    threads on the dev machine; about 5.6 min on the 2-vCPU VPS.
  - The 1M-step run: about 4 min.
  These grow with daemon scope; keep recovery O(tail) and checks
  incremental.
- **Revisit** if madsim gains a power-failure file system and eager kill, or
  if we need socket-level simulation of third-party protocols (then
  consider turmoil or madsim for that layer only).

### Measurements

Dev machine: AMD EPYC 9354P, 8 vCPUs, shared, load average about 3. VPS:
Intel Skylake, 2 vCPUs, Debian 13, idle. Release builds. A "poll" is one
executor poll of one task (the brief's "step"). Every DST seed runs 4 clients
× 12 requests against 3 actors with crashes about every 150 ms, followed by
the full end-of-run checks including identity replay.

| Measurement | Result |
| --- | --- |
| Executor overhead only (100 tasks × 10k random sleeps + `tokio::sync::Mutex`) | own: 2.6–2.9M polls/s (dev), 1.44M polls/s (VPS); madsim: 5.0M polls/s (dev) |
| DST seeds, single thread | own: 30.2 seeds/s; madsim: 29.9 seeds/s (dev, 100 seeds); own: 18.4 seeds/s (VPS) |
| DST seeds, parallel | 1,000 seeds in 28.1 s with 8 threads (dev, 0 failures); 200 seeds in 6.8 s with 2 threads (VPS) |
| Determinism, same seed twice | 50/50 identical, 50/50 distinct across seeds (own); identical under madsim; seed 12345 identical on AMD and Intel |
| ≥1M-step run (8 clients × 5,000 requests, 16 actors) | 1,199,684 polls, 39,912 turns, 911 crashes, 138 fsync-error restarts, 106 torn tails, 26 valid-records-after-tear, 0 violations, 224 s wall, 613 s simulated |
| Same, crashes off and replay off | 1,118,378 polls in 81 s |
| Real mode (tokio, 4 workers, real files, WAL `state.db`) | 400 turns, 297 turns/s (dev), 314 turns/s (VPS); recovered state identical; identity replay 0 mismatches |
| Faults over 200 seeds (dev) | 1,095 crashes, 51 torn tails, 45 fsync-error restarts, 1,596 recovery re-runs, 577 stale-`state.db` restarts, 453 clock jumps |

Mutation suite: every seeded bug is caught (`mutants 0..100`).

| Mutation | Seeds catching it | Caught by |
| --- | --- | --- |
| Effect sent before the durable `TurnBegin` | 100/100 | I14 check at the external service |
| Acknowledge before `fdatasync` | 100/100 | `state.db` ahead of the log / lost acknowledgement |
| No torn-tail truncation | 36/100 | Recovery ≠ rebuild |
| No directory fsync for a new segment | 98/100 | I14 (durable name) |
| Logical time = wall clock only | 95/100 | I15 |
| No re-run of pending `TurnBegin`s | 50/100 | Unsafe effect delivered twice (only `unsafe` seeds can see it) |
| Pending re-runs in `HashMap` order | 77/100 | Trace hash differs for the same seed |

### Verification

```sh
cd spikes/spike-d-dst
(cd guest && cargo build --release --target wasm32-wasip2)
cargo build --release
target/release/spike-d-dst determinism 0..50
target/release/spike-d-dst seeds 0..1000 -j 8
target/release/spike-d-dst mutants 0..100 -j 8
target/release/spike-d-dst long --requests 5000
target/release/spike-d-dst real
target/release/spike-d-dst exec-bench
cargo test --release --test dst -- --seed 12345
RUSTFLAGS="--cfg madsim" cargo build --release --target-dir target/madsim
target/madsim/release/spike-d-dst madsim-seeds 0..100
target/madsim/release/spike-d-dst exec-bench
```
