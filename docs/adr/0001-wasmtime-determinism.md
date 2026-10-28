# 0001. Wasmtime configuration for deterministic, fresh-instance turns

- **Status:** Accepted
- **Date:** 2026-10-24

## Context

Every turn must be a deterministic function of code hash, engine version,
input, recorded effect results, logical time, seed and starting state (I1).
All non-determinism must reach the guest through host calls (I2), and the
guest's linear memory must never be state: every turn runs in a new instance
(I3). The brief ("Aktörs-ABI (WIT)", "Turn-semantik", milestone M0) asks for:
NaN canonicalization, deterministic or disabled relaxed SIMD, no threads, fuel
instead of epochs, a `ResourceLimiter` for memory, `InstancePre`, the pooling
allocator, precompiled code per hash and engine version, and a deterministic
WASI allowlist (`wasi:clocks`, `wasi:random`, `wasi:cli`, `wasi:io`), with
everything else rejected at deploy with `IMPORT_NOT_ALLOWED`.

Spike A tested this in `spikes/spike-a-wasmtime/`:

- `wit/kronik-actor.wit`: the brief's WIT draft, `package kronik:actor@0.1.0`.
- `spikes/spike-a-wasmtime/`: a host harness CLI (`imports`, `describe`,
  `handle`, `demo`, `bench`) that can load any component targeting the
  `kronik:actor` world. It implements every import and prints the result plus
  an ordered trace of host calls, including WASI clock, random and stdio
  calls.
- `spikes/spike-a-wasmtime/guest/`: a Rust guest built for `wasm32-wasip2` with
  `wit-bindgen` 0.63. It uses Kronik state, `now-ms` and `random-bytes`, and it
  also uses std-level WASI: `SystemTime::now`, `Instant::now`, a `HashMap` with
  `RandomState`, `println!`/`eprintln!`, NaN arithmetic and a `static` counter.
  It has extra modes that spin forever (fuel), allocate N MiB (memory), panic
  (trap), call the denied effects, and `messaging.call` another actor (nested
  turn).

Toolchain: Rust 1.99.1 (from `rust-toolchain.toml`), wasm-tools 1.262.0,
Wasmtime 50.0.0 (the latest stable release on crates.io on 2026-10-24).

## Decision

### 1. Wasmtime version and features

`wasmtime`, `wasmtime-environ`, `wasmtime-wasi` and `wasmtime-wasi-io` are all
pinned at exactly `=50.0.0`. `wasmtime` uses `default-features = false` with
these features: `runtime`, `cranelift`, `component-model`, `async`,
`pooling-allocator`, `parallel-compilation` and `std` (`addr2line` and
`demangle` are only for diagnostics). The `threads`, `component-model-async`
and `gc` features are **not** compiled in. Without the `threads` feature the
threads proposal (shared memories, `memory.atomic.wait`/`notify`) cannot be
turned on at all.

### 2. Engine configuration

| Setting | Value | Why |
| --- | --- | --- |
| `cranelift_nan_canonicalization` | `true` | NaN bit patterns are identical on every host. The guest observed `nan_bits=7ff8000000000000` on AMD and on Intel. |
| `wasm_relaxed_simd` + `relaxed_simd_deterministic` | `true` + `true` | Toolchains such as StarlingMonkey may emit relaxed SIMD. Deterministic mode picks the same semantics on every architecture, so we accept it instead of rejecting those modules. |
| `wasm_shared_everything_threads` | `false` | Threads off. The base threads proposal is excluded at compile time (see 1). |
| `consume_fuel` | `true` | CPU limit. Fuel is a deterministic function of the executed code. |
| `epoch_interruption` | `false` | Epochs depend on wall-clock time. |
| `fuel_async_yield_interval` (per store) | 1,000,000 | A CPU-heavy turn yields to the executor every 1M fuel, so one turn cannot starve a single-threaded executor (the DST executor in particular). The yield points depend only on fuel. |
| Allocation strategy | Pooling | Slots are reset before reuse. 2-3x faster instantiation than on-demand (see measurements). |
| Pool limits (spike values) | 64 component instances, 512 core instances, 128 memories, 512 tables, 64 stacks, 32 core instances / 8 memories / 32 tables per component, 100,000 table elements, 1 GiB max per linear memory | Generous enough for wasip2 and JS components. The daemon derives these from worker count × maximum call depth. Since M15 (ADR 0030) the per-component limit is 64 core instances and the pool holds 48 per turn slot: a Python component instantiates 38. |
| `cranelift_opt_level` | `Speed` | |

### 3. Engine version

The format is `kronik-<kronik semver>+wasmtime-<wasmtime semver>`, for example
`kronik-0.1.0-dev+wasmtime-50.0.0`. `crates/kronik-runtime` already defines
`ENGINE_VERSION` in exactly this format and reads the Wasmtime version from
`wasmtime_environ::VERSION`. The spike now uses the same source, and the two
agree. The engine configuration above is code inside the Kronik binary, so any
change to it ships as a new Kronik version and therefore as a new engine
version.

### 4. Code store and precompiled cache

- Code identity: `b3:` + BLAKE3 of the component bytes, shown as 12 hex
  characters.
- Precompiled artifact: `code/<blake3-hex>.<engine-version>.cwasm`, produced by
  `Engine::precompile_component` and loaded with `Component::deserialize_file`.
  Loading is `unsafe` in Wasmtime: the file must come from Kronik's own data
  directory, never from user input or object storage.
- Wasmtime embeds an engine and target fingerprint (including host CPU
  features) in the artifact and refuses mismatches. Observed: a `.cwasm` built
  on the AMD EPYC dev machine was refused on the Intel Skylake VPS ("failed to
  load code"). Kronik treats a refused file as a cache miss, recompiles and
  overwrites it. The cache is derived data (I4) and specific to one machine.
  Snapshots and shipping never include `.cwasm` files, and `restore`
  recompiles.

### 5. Fresh instance per turn

The `Linker` is built once per engine. For each code hash, `InstancePre` (the
bindgen `ActorPre`) is created once at deploy or load. Each turn creates a new
`Store` with new per-turn host data and instantiates from the `InstancePre`, so
no import resolution happens per turn. Nothing guest-side survives a turn: the
guest's `static` counter read 1 in every turn, and state carried over only
through the host's buffered writes.

### 6. Limits and outcome classification

- **Fuel:** 50M per turn by default. `Trap::OutOfFuel` → `FUEL_EXHAUSTED`.
  `fuel_used` (budget minus remaining) is deterministic and is part of the
  canonical outcome.
- **Memory:** a `ResourceLimiter` caps the *sum* of all linear memories of the
  instance (64 MiB by default; up to the 1 GiB pool ceiling per kind). The
  limiter is also consulted when memories are created. It refuses growth with
  `Ok(false)`, so `memory.grow` returns -1 as the spec requires and a guest
  allocator may recover. The limiter records the refusal, and a trap that
  follows is classified as a memory-limit failure (`TURN_FAILED` with that
  detail). Tables are capped at 1M elements.
- **Values:** state values and message bodies over 1 MiB, and random requests
  over 1 MiB, trap in the host.
- **Canonical outcome:** a trap is recorded by its Wasmtime trap code, and a
  host-raised error by its root-cause message. Backtraces, addresses and
  timings are never part of the outcome.
- **Observed:** Wasmtime 50 charges bulk-memory instructions (`memory.fill`,
  `memory.copy`) fuel proportional to their length (`pre_translate_bulk_op` in
  `wasmtime-internal-cranelift`). Zeroing 100 MiB cost about 106M fuel and 40
  MiB about 42M. With the defaults (50M fuel, 64 MiB memory), a turn runs out
  of fuel before it can touch all of its memory. This is deterministic and
  acceptable, but the per-kind limits docs must say it.

### 7. Deterministic WASI

The linker contains *only* the allowlisted interfaces. A component that
somehow bypassed the deploy check still cannot instantiate.

| Interface | Implementation |
| --- | --- |
| `wasi:clocks/wall-clock` | Kronik host code. `now` = the turn's logical time, resolution 1 ms. |
| `wasi:clocks/monotonic-clock` | Kronik host code. `now` = logical time in ns, constant within the turn. `subscribe-instant` and `subscribe-duration` return an always-ready pollable: a guest sleep returns immediately, and no real time passes inside a turn. |
| `wasi:random/random`, `insecure`, `insecure-seed` | Kronik host code. ChaCha20 seeded with the 32-byte turn seed, using domain-separated ChaCha20 stream ids: 0 = `context.random-bytes`, 1 = `wasi:random/random`, 2 = `wasi:random/insecure`, 3 = `insecure-seed`. |
| `wasi:cli/*` | `wasmtime-wasi` with an empty environment, no arguments, no cwd and empty stdin. stdout and stderr are custom streams that turn every write into a log event (an ordered trace entry). `exit` becomes a trap. |
| `wasi:io/error`, `poll`, `streams` | `wasmtime-wasi-io`. |

The streams are separated so that a language runtime drawing randomness at
startup (hash map seeds, `Math.random` state) does not shift the bytes the
actor gets from `context.random-bytes`. All four streams still come from the
single recorded seed.

### 8. Import allowlist (`IMPORT_NOT_ALLOWED`)

`allowlist::disallowed_imports(bytes: &[u8]) -> Result<Vec<String>, _>` reads
the top-level import section of the outer component with `wasmparser`, before
compilation, and returns every import that is not allowed. Imports of nested
core modules and components are satisfied inside the component and are not
host imports. An import is allowed when it is:

- `kronik:actor/{types,state,sql,context,messaging,timers,http-client,crypto,secrets,log,privacy}@0.1.x`;
- `wasi:io/{error,poll,streams}@0.2.x`;
- `wasi:clocks/{wall-clock,monotonic-clock}@0.2.x`;
- `wasi:random/{random,insecure,insecure-seed}@0.2.x`;
- `wasi:cli/{environment,exit,stdin,stdout,stderr,terminal-input,terminal-output,terminal-stdin,terminal-stdout,terminal-stderr}@0.2.x`.

Everything else is rejected: `wasi:filesystem`, `wasi:sockets`, `wasi:http`,
`wasi:clocks/timezone`, WASI 0.3, other packages, unversioned names and bare
function imports. Error text:
`IMPORT_NOT_ALLOWED: the component imports interfaces outside the allowlist: <list>`.

### 9. Rust guests: what `wasm32-wasip2` actually imports, and the SDK target

A Rust 1.99.1 `wasm32-wasip2` `cdylib` built with `wit-bindgen` 0.63, which
uses `println!`, `SystemTime`, `Instant`, `HashMap`/`RandomState` and panics,
imports exactly this (release and debug builds alike):

```text
kronik:actor/{state,sql,types,context,http-client,crypto,secrets,log,messaging}@0.1.0   (only the ones used)
wasi:io/{poll,error,streams}@0.2.12
wasi:clocks/{monotonic-clock,wall-clock}@0.2.12
wasi:cli/{stdout,stderr,stdin,environment,exit}@0.2.12
wasi:cli/{terminal-input,terminal-output,terminal-stdin,terminal-stdout,terminal-stderr}@0.2.12
wasi:random/insecure-seed@0.2.12
```

There is no `wasi:filesystem` and no `wasi:sockets`. `HashMap`'s
`RandomState` takes its keys from `wasi:random/insecure-seed`, not from
`wasi:random/random`. Only using `std::fs` (the `fs-probe` build) adds
`wasi:filesystem/types` and `wasi:filesystem/preopens`, and that component is
rejected with `IMPORT_NOT_ALLOWED`. Using `std::net` would add `wasi:sockets`
in the same way.

**Decision:** the Rust SDK targets `wasm32-wasip2` with `wit-bindgen`, as the
brief says. No `wasm32-unknown-unknown` build, trimmed adapter or WASI
virtualization is needed. Implication for the SDK: `kronik build` (and the CI
test from the brief) runs the same allowlist check after building, so that use
of `std::fs` or `std::net` fails at build time with the list of offending
imports instead of at deploy.

### 10. Host functions are async

All `kronik:actor` imports are generated with `imports: { default: async |
trappable }`, and exports with `exports: { default: async }`. The guest still
sees synchronous functions: Wasmtime runs the guest on a fiber and suspends it
while a host future is pending.

- `messaging.call` must run the callee's whole turn before returning. With
  async host functions the caller's host call simply awaits the callee's turn,
  which runs on its own fresh instance and store while the caller's fiber is
  suspended. The spike does this (`nested-call/async-host`), and the result is
  deterministic.
- `http.fetch` does network I/O. As a future it runs on the daemon's executor
  instead of blocking a worker thread.
- Spike D needs to drive the whole daemon on a single-threaded deterministic
  executor. With async host functions, every place where a turn waits (a
  callee's turn, a simulated network reply with simulated latency, a log
  fsync for `TurnBegin`) is an await point that the simulator controls. A
  synchronous host function would have to block the only thread, so the
  simulator could neither run the callee nor advance virtual time.
- What the guest observes does not depend on when a future completes, only on
  its value. Async scheduling therefore cannot break I1. Fuel-based yields keep
  long turns cooperative.

The cost of fibers is included in the measurements below. The spike harness
uses a tokio current-thread runtime, which has the same shape as the DST
executor.

## Alternatives

- **Epoch interruption for CPU limits.** Wall-clock based, so where a turn
  stops would differ between production and replay. Rejected (the brief also
  says fuel).
- **Disable relaxed SIMD.** Would reject components that use it.
  `relaxed_simd_deterministic` gives the same determinism without that cost.
- **`wasmtime-wasi` clocks with custom `HostWallClock`/`HostMonotonicClock`.**
  The values would be deterministic, but `subscribe-*` would still sleep in
  real time on tokio. That sleep has nondeterministic length and cannot be
  driven by a simulator, so we implement the clock interfaces ourselves.
- **One ChaCha20 stream for all randomness.** Simpler, but then a language
  runtime's start-up draws would shift `context.random-bytes`. Rejected in
  favour of stream ids from the same seed.
- **`ResourceLimiter` returning `Err` (immediate trap) on growth past the
  limit.** It gives a crisper error but violates the spec's `memory.grow`
  failure semantics and prevents allocator recovery (JS engines GC and retry).
  Rejected.
- **`wasm32-unknown-unknown` + `wasm-tools component new`, a trimmed
  wasip1 adapter, or wasi-virt.** Unnecessary, because `wasm32-wasip2` already
  stays inside the allowlist. `wasm32-unknown-unknown` would also lose
  `println!` and std time.
- **Synchronous host functions.** About one fiber switch cheaper per call, but
  `call` and `fetch` would block threads and the daemon could not run under a
  single-threaded deterministic simulator (see 10).
- **On-demand instance allocator.** 2.5-3.5x slower instantiation on both
  machines.

## Consequences

- `crates/kronik-runtime` takes over the spike's engine builder, code cache,
  allowlist check, deterministic WASI and turn runner in M1. Its `wasmtime`
  dependency (currently `default-features = false` with no features) must
  enable the features listed in 1, and must never enable `threads`.
- Every host function is async. Production drives turns on tokio, and
  `kronik-sim` drives the same futures on its deterministic executor. `Store`
  is `Send`, so turns can run on a worker pool.
- Each nested `call` holds an extra instance slot, so pool sizes must cover
  workers × maximum call depth. Exhausting the pool is a host error, not a turn
  outcome.
- Guests cannot measure time or sleep inside a turn: `Instant` never advances
  and sleeps return immediately. The SDK docs must say this, and timers are the
  way to wait.
- Precompiled code is per machine. A restore or a move to a different CPU
  recompiles once per hash: 83 ms (dev) to 175 ms (VPS) for the 110 KB Rust
  guest.
- The defaults for fuel and memory interact through the per-byte fuel cost of
  bulk memory operations (6).
- Open for spike B: how much memory, fuel and how many table elements
  ComponentizeJS/StarlingMonkey components need. The harness's `--memory-mib`
  and `--fuel` flags exist for that.
- Revisit on any Wasmtime upgrade (through `kronik upgrade check`) and for WASI
  0.3 (M22).

### WIT deviations

None. `wasm-tools component wit wit/kronik-actor.wit` parses the brief's draft
unchanged, and its encoded form validates (`wasm-tools validate --features
all`). Both the guest (`wit-bindgen` 0.63) and the host (`wasmtime` bindgen)
generate bindings from it without changes.

### Measurements

Dev machine: AMD EPYC 9354P (8 vCPUs visible, shared with other workloads,
load average about 14 during the run, so the numbers are noisy). Testbench VPS
(`travelfiesta`): Intel Xeon Skylake (IBRS, no TSX), 2 vCPUs, 4 GB, KVM guest
without `/dev/kvm`, Debian 13, idle. The guest is the 110-116 KB Rust
component. "Whole turn" includes creating the store and the per-turn WASI
context, instantiating, calling `handle`, and reading fuel.

| Measurement | Dev (EPYC 9354P) | VPS (Skylake, 2 vCPU) |
| --- | --- | --- |
| Compile (Cranelift, parallel), p50 | 83 ms | 175 ms |
| Deserialize `.cwasm` (cache hit), p50 | 155 µs | 333 µs |
| Instantiate, pooling + `InstancePre`, p50 / p99 | 11.2 / 26.4 µs | 14.8 / 35.3 µs |
| Instantiate, on-demand, p50 / p99 | 36.7 / 91.8 µs | 52.5 / 93.8 µs |
| `handle` call, trivial (`noop`, 1,875 fuel), p50 / p99 | 11.5 / 27.2 µs | 12.8 / 27.3 µs |
| Whole trivial turn, pooling, p50 / p99 | 38.1 / 103.9 µs (~23k turns/s per thread) | 45.6 / 96.6 µs (~19.6k turns/s per thread) |
| Whole `probe` turn (14 host calls, 176k fuel), pooling, p50 / p99 | 87.9 µs / 1.0 ms | 129.3 / 244.5 µs |

The brief's target of 1,000 committed turns per second for the Rust counter on
the VPS leaves Wasm execution well under 10% of the budget; logging and fsync
will dominate.

### Verification

```sh
spikes/spike-a-wasmtime/run.sh demo    # builds guest + harness, prints imports, runs 22 checks
spikes/spike-a-wasmtime/run.sh bench   # the measurements above
wasm-tools component wit wit/kronik-actor.wit
cd spikes/spike-a-wasmtime && cargo test --release   # allowlist unit tests
```

Observed on both machines: `0 check(s) failed`. The checks cover the
allowlist, `IMPORT_NOT_ALLOWED` for synthetic and `std::fs` components, the
code cache, `describe`, byte-identical outcomes over four fresh instances (two
engines, compiled and deserialized code), std clocks equal to logical time,
`Instant` constant, the seed and the logical time driving the values, the
static counter reset (I3), `FUEL_EXHAUSTED`, the memory limit, a per-kind
memory limit, trap classification with stderr capture, denied effects, pool
slot reuse, and nested `call`. Cross-machine: `handle --msg probe` gave the
digest
`b3:0cef2655a32d2d62a9b35c9af917d712682bf65f743a959a058bab5e841e571e` on the
AMD dev machine and on the Intel VPS, and `handle --msg call` gave
`b3:2e3fd2b69e2a24b8f3454e37026f8f2861a545396f96e02c11c9ca10adb0ef41` on both.
