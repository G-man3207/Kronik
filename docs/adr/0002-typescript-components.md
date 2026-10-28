# 0002. TypeScript components: jco and ComponentizeJS without `http`, `fetch-event` and `stdio`

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

TypeScript actors are built with jco and ComponentizeJS via `kronik build`
(brief: "SDK:er och exempelappar", `@kronik/sdk` in M4). They run in the same
`kronik:actor` world as Rust actors and under the same rules: the deploy
allowlist and the deterministic WASI host of ADR 0001 (I1, I2), and a fresh
instance per turn (I3). M0 spike B asks for a TypeScript component built that
way to run in that world with its imports listed. The brief also leaves an
open question to an ADR: how fast is a fresh instance per turn for JavaScript
components on the testbench VPS, and what pre-initialization is needed? ADR
0001 left spike B to find out how much memory, fuel and how many table
elements such components need.

ComponentizeJS puts a JavaScript engine, StarlingMonkey (SpiderMonkey compiled
to WebAssembly), into every component. At build time it runs the engine's
initialization and evaluates the bundled module under Wizer, and the resulting
linear memory becomes the component's data segments; every instance starts
from that snapshot. So the questions were what this engine imports, whether
its clocks and randomness go through Kronik's host, what restoring the
snapshot costs per turn, and what the build must do.

Spike B (`spikes/spike-b-componentize-js/`, see its README) has:

- `src/actor.ts`, a probe actor with modes for a no-op turn, the counter,
  state/context/clock/randomness reporting, `Math.random()` counting, JSON
  work, an endless loop, allocation, a thrown `Error` and a thrown
  `handler-error`; `src/counter.ts`, the brief's counter written against the
  raw bindings; and `src/build-time-random.ts`, which must fail to build.
- Scripts that build the components with the pinned toolchain the way
  `kronik build` would, list their imports, and run them in spike A's harness
  (unmodified) for determinism checks and benchmarks. Two experiments use a
  patched copy of the harness, because they do what Kronik must not: calling
  `handle` repeatedly on one instance, and changing the pooling allocator's
  slot reset.
- Results from the development machine (AMD EPYC 9354P, 8 vCPU, shared with
  other work, so its timings are noisy) and from the testbench VPS (Debian 13,
  2 vCPU Intel Xeon Skylake, no `/dev/kvm`, 3.7 GiB), in `results/`.

The spike used `wit/kronik-actor.wit` as of `5a8d400`. The amendments in
`b8a3b39` (`state.set-for`, `privacy.current-subject`) add functions to
existing interfaces and change nothing below.

**Versions.** Node.js 26.10.0 and npm 11.19.1; `@bytecodealliance/jco` 1.39.0
(it bundles TypeScript with rolldown 1.2.15); `@bytecodealliance/componentize-js`
0.23.0, which brings Wizer 10.0.0 and, for `--aot`, weval 0.5.1; `typescript`
7.0.2. The components report `ComponentizeJS [0.23.0]` and `wit-component
[0.259.0]`; the engine module inside was built with clang 21.1.4 (wasi-sdk)
and rustc 1.88.0. Runtime: Wasmtime 50.0.0 configured as in ADR 0001.

## Decision

### 1. Toolchain

`@kronik/sdk` pins exact versions of `@bytecodealliance/jco`,
`@bytecodealliance/componentize-js` and `typescript` (the spike's are above),
and `kronik build --lang ts` uses the project's installed copies. A new
ComponentizeJS version replaces the engine inside every component, so an
upgrade is deliberate and reruns this spike's checks: imports, determinism and
the numbers below. The build machine needs Node.js 22.12 or later (rolldown's
`engines`); the server never runs Node.js.

The build goes through `jco componentize`. The `componentize-js` command of
0.23.0 cannot read the WIT file: its splicer runs on preview2-shim 0.30.0
without preopens and fails with `No such file or directory (os error 44)`.
The engine is StarlingMonkey, the default; jco's QuickJS backend is not used
(see Alternatives).

### 2. The build pipeline of `kronik build --lang ts`

1. The SDK ships `kronik-actor.wit` and the TypeScript declarations generated
   from it with `jco guest-types <wit> --world-name actor` (0.5 s in the
   spike).
2. `tsc --noEmit` type-checks the project (0.7 s for the spike with
   TypeScript 7). jco strips types without checking them.
3. `jco componentize <entry>.ts --wit <wit> --world-name actor --disable http
   fetch-event stdio -o dist/<kind>.wasm` bundles, splices the bindings into
   the engine and pre-initializes it (3.7 s for each spike component on the
   development machine).
4. The import check that deploy uses runs on the result and fails the build
   with `IMPORT_NOT_ALLOWED`. The brief's CI test for the TypeScript examples
   is the same check.

Pre-initialization is part of step 3 and is all that a component needs at
build time. ComponentizeJS always runs it.

### 3. Imports

With `--disable http fetch-event stdio` a component imports 18 interfaces and
passes the allowlist (`results/imports.txt`):

- all 11 `kronik:actor/*@0.1.0` interfaces, in every build: ComponentizeJS
  imports every interface of the world, whether the code uses it or not (the
  counter uses only `state`). The import list says nothing about what a
  JavaScript actor does;
- `wasi:io/poll`, `wasi:io/error`, `wasi:io/streams`,
  `wasi:clocks/monotonic-clock`, `wasi:clocks/wall-clock`, `wasi:cli/stderr`
  and `wasi:random/random`, all `@0.2.12`.

It exports `kronik:actor/handler@0.1.0`. With fewer features disabled, the
allowlist rejects the component:

| `jco componentize` flags | Imports | Rejected imports |
| --- | --- | --- |
| none | 29 | `wasi:http/types@0.2.10`, `wasi:http/outgoing-handler@0.2.10`, `wasi:filesystem/types@0.2.12`, `wasi:filesystem/preopens@0.2.12` |
| `--disable http fetch-event` | 27 | `wasi:filesystem/types@0.2.12`, `wasi:filesystem/preopens@0.2.12` |
| `--disable http fetch-event stdio` | 18 | none |

The filesystem imports come with `stdio`; disabling it also drops
`wasi:cli/stdin`, `stdout` and the `terminal-*` interfaces. `random` and
`clocks` stay enabled, because the host makes them deterministic (section 5).
No virtualization or composition step (such as WASI-Virt) is needed.

The components use no SIMD, relaxed SIMD or threads: they validate with those
features disabled, the `--aot` builds too. The engine module declares one
linear memory of 145 pages (9.06 MiB) and a `funcref` table of 7,708
elements; the small adapter modules add an empty memory and two tables of 28
elements. That fits ADR 0001's pool limits (100,000 table elements, 1 GiB per
memory).

### 4. What the flags and the engine mean for actor code

These are SDK obligations for M4, observed with the raw bindings:

- **`console.*` output is dropped.** The probe's `console.log` makes no host
  call at all. The SDK routes `console.*` to `kronik:actor/log`.
- **An uncaught exception loses its message.** A thrown `Error` ends the turn
  with `TURN_FAILED` and an `unreachable` trap, with nothing on stderr. The
  SDK catches everything in `handle` and returns `handler-error::failed` with
  the message.
- **Throwing the WIT error works.** `throw { tag: 'rejected', val: 'not
  today' }` gives `handler-error::rejected("not today")`.
- **No `fetch`.** The `http` and `fetch-event` features are off; outgoing
  HTTP is `kronik:actor/http-client` through the SDK's `http.fetch`. (Standard
  `fetch` through the effect layer is a later item in the brief.)
- **Module scope runs at build time,** under Wizer: whatever it computes is
  part of the snapshot (section 5).
- **Module-level variables do not survive a turn** (I3): the probe's turn
  counter is 1 in every turn.

### 5. Determinism

Every check gave the same digests, fuel and outcomes on the AMD development
machine and the Intel VPS (`results/determinism-*.txt` differ only in
timestamps and timings):

- **Fresh instances and processes.** Three fresh instances and two more
  processes give identical digests for the same input, seed and time.
- **`Math.random()` draws from the host on every call.** 1, 10, 100 and 1,000
  calls make exactly as many `wasi:random/random.get-random-u64` calls, about
  2,000 fuel each. StarlingMonkey keeps no generator state in the snapshot,
  so the values come from the turn's seed (stream 1 of ADR 0001). Another
  seed changes them and the same seed reproduces them. No seeding work is
  needed in Kronik or the SDK.
- **`crypto`.** `crypto.getRandomValues` on 8 bytes is one
  `get-random-bytes(8)` call, `crypto.randomUUID()` one `get-random-bytes(16)`
  call. Both follow the seed, like `context.random-bytes`.
- **Time.** `Date.now()` and `new Date()` read `wasi:clocks/wall-clock`, which
  is the turn's logical time; `performance.now()` is 0, because the monotonic
  clock stands still during a turn. The engine also reads the monotonic clock
  itself: twice before the handler and six times after it, and eight times
  in `describe`. Those calls are in the trace and are deterministic.
- **Module scope.** `Math.random()` in module scope fails the build
  (`attempted to call an unknown imported function: 'wasi:random/random@0.2.10'
  'get-random-u64'`), so no random value can be baked into a component.
  `Date.now()` in module scope is the build time (the probe's `buildTime` is
  1792891469823, the moment of the build). That is deterministic per
  component but surprising, and the SDK docs say so.
- **Errors and limits are deterministic outcomes:** an endless loop is
  `FUEL_EXHAUSTED` at 50,000,000; allocating 100 MiB under the 64 MiB limit is
  `TURN_FAILED` with the memory limit recorded; allocating 16 MiB succeeds
  with a peak of 25,664 KiB.
- **Builds are not reproducible.** Wizer runs with real WASI
  (`--allow-wasi`, `--inherit-env=true` in ComponentizeJS), so the snapshot
  differs between builds. Two builds of the unchanged counter differ in
  2,401,514 bytes, have different hashes and use different fuel per turn
  (1,587,545 and 1,587,590), so their turn digests differ. One build behaves
  identically everywhere.

### 6. Fresh instance per turn: cost and pre-initialization

This answers the brief's open question. Measured on the testbench VPS with
the pooling allocator, `InstancePre` and code loaded from the `.cwasm` cache
(`results/bench-travelfiesta.txt`, `results/reuse-travelfiesta.txt`):

| | `noop` | counter | JSON, 64 KB |
| --- | --- | --- | --- |
| Fuel per turn | 954,692 | 1,587,545 | 28,779,575 |
| Instantiate, p50 / p99 | 35.0 / 74.2 µs | 35.1 / 75.5 µs | 63.2 / 111.7 µs |
| Whole turn, p50 / p99 | 1.3 / 2.1 ms | 1.7 / 2.5 ms | 7.1 / 11.3 ms |
| Turns per second, one core | ~714 | ~565 | ~135 |
| `handle` again on a warm instance, p50 (forbidden by I3) | 37 µs | 130 µs | 4.8 ms |

Peak memory is 9,280 KiB for all three. For comparison, ADR 0001's trivial
Rust turn takes 45.6 µs on the same VPS.

- **Instantiation is cheap,** 35 µs: Wasmtime maps the 9 MiB snapshot
  copy-on-write instead of copying it.
- **The first call on a fresh instance is not.** The first `handle` call on
  an instance costs the full 954,662 fuel for `noop` and 1,587,515 for the
  counter; later calls on the same instance cost 145,919 to 1,041,596 and
  479,906 to 2,689,186 fuel and take 37 µs and 130 µs at p50. On the VPS a
  fresh-instance turn takes 1.3 to 2.1 ms longer than a warm call. That is
  the price of I3 for StarlingMonkey: most of a small TypeScript turn is the
  engine warming up from the snapshot, not the actor's code. On larger turns
  it matters less (JSON: 6.9 ms fresh, 4.8 ms warm).
- **Keeping pool slots resident does not help on the VPS.** With Wasmtime's
  `linear_memory_keep_resident` and `table_keep_resident` at 2, 4 and 16 MiB,
  the call gets faster (at 16 MiB, `noop` takes 0.46 ms instead of 1.2 ms),
  but the time moves to freeing the slot, where the resident memory is reset:
  the whole `noop` turn takes 1.7, 1.9 and 2.4 ms instead of 1.3 ms, the
  counter 2.0, 2.3 and 2.5 ms instead of 1.7 ms
  (`results/keep-resident-travelfiesta.txt`). On the development machine
  16 MiB does pay off (counter 0.82 ms instead of 1.3 ms), so the outcome
  depends on the machine; Kronik keeps Wasmtime's default. The probe's
  digests and fuel were the same at every size, so no state leaked between
  turns.
- **`--aot` (weval) does not help either.** The counter turn takes 1.8 ms
  instead of 1.7 ms, the JSON turn 6.7 ms instead of 7.1 ms with 10% less
  fuel, but the component grows from 12.8 to 19.0 MB, its compile time from
  14 to 20 s and its `.cwasm` from 40 to 54 MB.

**Pre-initialization needed:** none beyond what ComponentizeJS already does
(the Wizer snapshot of the engine and the module) and what ADR 0001 already
requires: precompiled code per hash and engine version, and an `InstancePre`
per kind. The precompiled code is not optional for JavaScript: compiling one
12.8 MB component takes 14 s on the VPS (2.8 s on the development machine),
while loading its 40 MB `.cwasm` takes 1.8 ms. So `kronik deploy` compiles
before it switches, and restore and engine upgrades recompile before turns
run; a turn never compiles.

### 7. Limits for JavaScript kinds

The brief's defaults stay as they are for TypeScript kinds: 50 million fuel
and 64 MiB. Memory is ample: the snapshot is 9.06 MiB and building, writing
and parsing 669 KB of JSON peaks at 15,424 KiB. Fuel is what TypeScript
actors will hit first, so the SDK docs and `kronik explain FUEL_EXHAUSTED`
state the cost model and point to `kronik limits set <kind> --fuel`:

- about 1 million fuel per turn before the handler does anything;
- about 2,000 fuel per `Math.random()` call;
- building, stringifying and parsing JSON: 4.3 million fuel for 6 KB, 28.8
  million for 64 KB and 295 million for 669 KB, so a 1 MiB message cannot be
  handled as JSON under the default;
- on the VPS, 50 million fuel is about 12 ms of compute-bound JavaScript (the
  JSON turn runs about 4.2 million fuel per millisecond).

## Alternatives

- **Default features, or only `--disable http fetch-event`.** Rejected by the
  allowlist (section 3). Allowing `wasi:http` or `wasi:filesystem` is out of
  the question in v0.1.
- **Keeping `stdio` and removing the filesystem imports by composition**
  (WASI-Virt or a deny-all filesystem component). More moving parts for
  nothing: console output goes to `log` anyway, and without `stdio` there is
  nothing to remove.
- **Also disabling `random` and `clocks`** (`--disable all`). The component
  then imports only the 11 `kronik:actor` interfaces, and the `noop` and
  counter turns work, but the probe, which uses `crypto`, `Date` and
  `Math.random()`, traps (`results/no-wasi.txt`). The SDK would have to
  replace those APIs, while the host already makes them deterministic.
- **`--aot` (weval).** Measured in section 6: no gain for small turns, 6%
  for JSON, at about 48% more size and 40% more compile time. It could become
  an opt-in for CPU-heavy kinds.
- **QuickJS (`jco componentize --backend quickjs`, componentize-qjs).** The
  counter is 2.35 MB and builds in 1.4 s, but jco adds a
  `jco:node/console@0.1.0` import and writes it into the WIT file it is given,
  and the component imports `wasi:filesystem`. With `--backend-qjs-stub-wasi`
  only `jco:node/console` is left, which the allowlist still rejects
  (`results/quickjs.txt`). Not measured at runtime. The brief names
  ComponentizeJS; QuickJS is worth a second look if the size and per-turn
  cost of StarlingMonkey become a problem.
- **The `componentize-js` command instead of jco.** Fails to read the WIT
  file (section 1).
- **Reusing instances for JavaScript kinds.** Section 6 shows what it would
  save, but I3 forbids it.

## Consequences

- **M4 SDK.** `actor({...})` builds the `handler` export (`describe` from
  kind, schema version and routes; `handle` dispatches HTTP, messages, timers
  and `migrate`), catches every exception into `handler-error::failed`, sends
  `console.*` to `log`, and documents that module scope runs at build time.
  The SDK ships the WIT and its generated declarations, and pins the
  toolchain.
- **Size and compile time.** Every TypeScript component carries the engine:
  12.8 MB per component plus a 40 MB `.cwasm` per engine version, against
  about 115 KB and a 175 ms compile for spike A's Rust guest (ADR 0001). The
  code store and cache need about 53 MB per deployed TypeScript version, and
  a deploy or restore spends 14 s per new TypeScript hash compiling on the
  VPS.
- **Throughput.** On the VPS, Wasm execution alone limits a TypeScript
  counter to about 565 turns per second per core (the brief's target of 1,000
  per second is for the Rust counter). Replay runs at the same per-turn cost,
  so replaying TypeScript kinds 20 times faster than real time works only up
  to about 28 recorded turns per second per core.
- **Rebuilds change the hash.** Because builds are not reproducible, a
  rebuild of unchanged source gives a new hash and slightly different fuel,
  so `kronik propose dist/` would replay unchanged TypeScript kinds instead of
  skipping them, and fuel diffs show noise. In M4, `kronik build` keeps the
  previous component when its inputs (bundled source, WIT, toolchain versions,
  flags) are unchanged, and records the input hash in the component.
  Deterministic pre-initialization (Wizer with fixed clocks and randomness)
  would need upstream work or Kronik's own pre-initialization step.
- **ADR 0001.** It keeps relaxed SIMD in deterministic mode because
  StarlingMonkey might emit it. ComponentizeJS 0.23.0 uses no SIMD at all, so
  JavaScript components are no reason to keep it. Its pool limits are enough
  for them.
- **Revisit** when ComponentizeJS or StarlingMonkey changes (a faster restore
  would change section 6), when WASI 0.3 arrives (M22), or if TypeScript turn
  cost dominates a real workload.
