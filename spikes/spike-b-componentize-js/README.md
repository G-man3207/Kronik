# Spike B: a TypeScript actor built with jco and ComponentizeJS

Milestone M0, spike B: a TypeScript component built with jco and
ComponentizeJS runs in the same `kronik:actor` world as spike A's Rust guest,
and its imports are listed and checked against the deploy allowlist. The
decision, the findings and the numbers are in
[ADR 0002](../../docs/adr/0002-typescript-components.md). This README explains
how to reproduce the results in `results/`.

## What is here

| Path | What it is |
| --- | --- |
| `package.json`, `package-lock.json` | The pinned toolchain: `@bytecodealliance/jco` 1.39.0, `@bytecodealliance/componentize-js` 0.23.0 and `typescript` 7.0.2, exact versions. |
| `tsconfig.json` | Type checking only (`noEmit`); jco bundles the TypeScript itself. |
| `src/actor.ts` | The probe actor. The message name, or the last segment of an HTTP path, selects a mode: `noop`, `counter`, `probe` (state, context, clocks and every JavaScript random source, reported as JSON), `math`, `json`, `spin`, `alloc`, `throw`, `reject`. |
| `src/counter.ts` | The brief's TypeScript counter, written against the raw bindings that the M4 SDK will wrap. |
| `src/build-time-random.ts` | Must fail to build: `Math.random()` in module scope. |
| `scripts/` | Build and experiment scripts; see below. |
| `results/` | Output of the experiments, committed as evidence. `*-dev.txt` reports measurements from the dev machine (AMD EPYC 9354P, 8 vCPU, shared with other work), `*-travelfiesta.txt` from the testbench VPS (Debian 13, 2 vCPU Intel Xeon Skylake, no `/dev/kvm`). |

The components run in the spike A harness, `spikes/spike-a-wasmtime`, which
is used unmodified. Two experiments need things Kronik must never do in
production, so `scripts/build-harness.sh` builds a copy of the harness under
`out/harness/` with `scripts/harness-experiments.patch` applied: a `reuse`
subcommand that calls `handle` repeatedly on one instance, and the
`SPIKE_B_KEEP_RESIDENT_MIB` variable, which sets the pooling allocator's
`linear_memory_keep_resident` and `table_keep_resident`.

The spike uses `wit/kronik-actor.wit` as of commit `5a8d400`, which is what
the harness implements; the scripts take it from git (`WIT_REV` in
`scripts/lib.sh`). The amendments in `b8a3b39` add functions to existing
interfaces and do not change the findings, but since then the harness no
longer compiles in the working tree (it lacks `state.set-for` and
`privacy.current-subject`), so build it from commit `ca784bf`.

## Reproduce

On the development machine, with Node.js 22.12 or later and npm (Node.js
26.10.0 and npm 11.19.1 were used), Rust, `wasm-tools` (1.262.0 was used),
`rsync` and `ssh` to the test host:

```sh
git worktree add /tmp/kronik-ca784bf ca784bf
(cd /tmp/kronik-ca784bf/spikes/spike-a-wasmtime && cargo build --release)
export HARNESS=/tmp/kronik-ca784bf/spikes/spike-a-wasmtime/target/release/spike-a-wasmtime

scripts/build.sh                 # npm ci if needed, then the components under out/
scripts/build-harness.sh         # the patched harness copy
scripts/imports.sh
scripts/determinism.sh
scripts/bench.sh                 # about 4 minutes
scripts/reuse-wasmtime.sh
scripts/keep-resident.sh         # about 7 minutes
scripts/quickjs-check.sh
scripts/no-wasi-check.sh
scripts/deploy.sh travelfiesta   # determinism, bench, reuse and keep-resident on the test host
```

`scripts/deploy.sh` copies both harness binaries (stripped), `wasm-tools`,
the components and `scripts/` to `/root/kronik-spike-b` on the test host,
runs the steps there and fetches `results/`. Node.js is not needed on the
test host. The steps take about 45 minutes there, mostly because each
benchmark compiles its component five times at 14 seconds each.

| Script | Result file | What it shows |
| --- | --- | --- |
| `build.sh` | `build.txt` | Step timings of the pipeline, the expected build failure, whether two builds of the same source are byte-identical, component sizes. Full tool output goes to `out/build-log.txt`. |
| `imports.sh` | `imports.txt` | The imports of every build variant (`wasm-tools component wit`) and the allowlist verdict (`spike-a-wasmtime imports`), the WebAssembly features the components need, their tables and memories, and the producers metadata. |
| `determinism.sh` | `determinism-<host>.txt` | Traces of the probe turn; digests across fresh instances, processes, seeds and logical times; how `Math.random()` reaches the host; the fuel of JSON work; the outcomes of errors and limits; two builds of the same source. |
| `bench.sh` | `bench-<host>.txt` | Declared memory, fuel and peak memory per turn, compile and deserialize times, and instantiation and whole-turn latency with the pooling and on-demand allocators. |
| `reuse-wasmtime.sh` | `reuse-<host>.txt` | Fuel and time of the fresh instance per turn against repeated calls on one instance. |
| `keep-resident.sh` | `keep-resident-<host>.txt` | Digests and latency with pool slots kept resident at 0 (Wasmtime's default), 2, 4 and 16 MiB. |
| `quickjs-check.sh` | `quickjs.txt` | For comparison: the imports of the counter built with jco's QuickJS backend. |
| `no-wasi-check.sh` | `no-wasi.txt` | For comparison: the actor built with `--disable all`, its imports, and which turns still work. |
| `build-harness.sh` | | Builds the patched harness copy. |
| `deploy.sh` | | Runs `determinism.sh`, `bench.sh`, `reuse-wasmtime.sh` and `keep-resident.sh` on the test host. |

`build.sh` builds these variants into `out/`:

| Component | jco componentize flags |
| --- | --- |
| `actor.wasm`, `counter.wasm` | `--disable http fetch-event stdio` (the chosen flags) |
| `actor-aot.wasm`, `counter-aot.wasm` | the same plus `--aot` (weval) |
| `actor-no-http.wasm` | `--disable http fetch-event` |
| `actor-default.wasm` | none |
| `counter-rebuild.wasm` | a second build of `counter.wasm`, to check reproducibility |

Two builds of the same source differ (see ADR 0002), so a rebuild gives new
code hashes, fuel and digests. Apart from `quickjs.txt` and `no-wasi.txt`,
which build their own components, all committed results come from one build:
`out/actor.wasm` is `b3:7194b807a941` and `out/counter.wasm` is
`b3:3ed342e6bc41`.
