# 0030. Python and Go components: componentize-py, TinyGo and a WASI deny adapter

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M15 (brief: "Python- och Go-SDK"): Python is built with componentize-py,
Go with TinyGo and wit-bindgen-go, and both SDKs expose the same API as
the Rust and TypeScript ones. Their components run in the same
`kronik:actor` world under the same rules: the deploy allowlist, the
deterministic WASI host of ADR 0001, a fresh instance per turn (I3). ADR
0002 answered these questions for TypeScript. The M15 spike
(`spikes/spike-m15-python-go/`, reproduced by its `run.sh`) asked them again: do the
two toolchains produce components for `wit/kronik-actor.wit` whose imports
stay inside the allowlist, what does a turn cost in fuel, do they run
deterministically, and are the builds reproducible.

Versions: componentize-py 0.25.1 (CPython 3.14 inside, wasi-sdk);
TinyGo 0.43.0 (LLVM 22.1.4) on Go 1.27.2; wit-bindgen-go v0.7.0 with
`go.bytecodealliance.org/cm` v0.3.0; WASI-Virt at `bca61c27`; Wasmtime
50.0.0 configured as in ADR 0001.

## Findings

**Imports.** Neither toolchain alone stays inside the allowlist:

| Build | Rejected imports |
| --- | --- |
| componentize-py | `wasi:filesystem/types`, `preopens`, all seven `wasi:sockets/*` (`@0.2.9`) |
| componentize-py `--stub-wasi` | none, but every WASI call traps: `time.time()` ends the turn |
| TinyGo `-target=wasip2`, a world without `wasi:filesystem` | does not link: the runtime's start calls `initial-cwd` and the preopens |
| TinyGo `-target=wasip2`, world including `wasi:cli/imports` | `wasi:filesystem/types`, `preopens` (`@0.2.0`) |

CPython's libc and TinyGo's runtime import the filesystem (and CPython the
sockets) whether the code uses them or not. Composing the component with a
WASI-Virt adapter (`--allow-clocks --allow-random --allow-stdio
--allow-exit --allow-env`, no filesystem passthrough, no sockets) replaces
those imports with an empty virtual filesystem and sockets that fail; what
is left goes to the host, whose clocks, randomness, environment and stdio
are Kronik's deterministic ones. Both results pass the allowlist. WASI-Virt
must pass the environment through (`--allow-env`): its own environment
traps on `initial-cwd`, which TinyGo's start calls. Kronik's host answers
with an empty environment and no working directory.

componentize-py imports every interface of the world; TinyGo (through
wit-component) only the ones the program calls, so a Go counter imports
`state`, `types` and `context` and nothing else.

**Pool limits.** A Python component instantiates 38 core module instances
(CPython, wasi-libc, the adapters, the virtual adapter); ADR 0001's pool
allowed 32 per component and 8 per turn slot in total. The pool now allows
64 per component and 48 per slot (`kronik-runtime/src/engine.rs`). These
are reservations, not memory: unused slots cost address space only.

**Fuel per turn** (counter actors from the spike, dev machine):

| | Python | Go | TypeScript (ADR 0002) |
| --- | --- | --- | --- |
| no-op message | 0.14 to 0.17 M | 0.77 M | 0.95 M |
| counter increment | 0.37 to 0.42 M | 0.89 to 0.91 M | 1.59 M |
| component size | 18.7 MB | 2.75 MB | 12.8 MB |
| build | 10 s | 70 s (contended dev) | 3.7 s |

componentize-py pre-initializes CPython at build time (as ComponentizeJS
does with Wizer), so a turn starts from an initialized interpreter; most of
a Go turn is TinyGo's runtime start (`_initialize`), which runs in every
fresh instance.

**Determinism.** Same seed, logical time and input give byte-identical
outcomes, fuel and logs on fresh instances, for both languages (the
determinism test runs the examples, see Decision 4). `time.time()`,
`time.Now()` and `datetime.now()` read the turn's logical time; Python's
`random` and Go's `math/rand` draw from the turn's seed through
`wasi:random`, so they differ between turns and repeat in replay. A
Python exception and a Go panic end the turn as a trap without a message
unless the SDK catches them.

**Reproducibility.** TinyGo builds are reproducible (the same source gives
the same bytes). componentize-py builds are not: the pre-initialized heap
differs between builds (12.7 M bytes differ between two builds of the same
counter), like ComponentizeJS's (ADR 0002 §5).

## Decision

1. **Toolchains, pinned.** `scripts/install-sdk-tools.sh` installs
   componentize-py 0.25.1 (wheel by SHA-256), Go 1.27.2 and TinyGo 0.43.0
   (archives by SHA-256), wit-bindgen-go v0.7.0 (Go's checksum database),
   wasm-tools 1.262.0 (which TinyGo runs; crates.io, `--locked`) and
   WASI-Virt at `bca61c27` (built with `--locked`, Rust 1.99.1, without
   the optional C++ `wasm-opt`) into `$KRONIK_SDK_TOOLS` (default
   `~/.cache/kronik/sdk-tools`), for Linux x86_64. `kronik build` takes its
   tools from there and checks their versions; an upgrade changes the
   script and the versions in `kronik build` together and reruns the
   spike's checks.
2. **One pipeline in `kronik build`** for both languages: compile (for
   Python `componentize-py componentize` with the SDK and the project on
   its path; for Go `tinygo build -target=wasip2` against the SDK's world),
   compose with the WASI-Virt deny adapter, check the imports against the
   allowlist (`IMPORT_NOT_ALLOWED` fails the build), and keep the previous
   component when the inputs (sources, SDK, tool versions, flags) are
   unchanged, recorded in a custom section as for TypeScript. That last
   step is what makes non-reproducible Python builds harmless for
   `kronik propose`.
3. **`kronik init --lang python|go`** creates projects with the SDK
   vendored, as for TypeScript and Rust. The brief requires only SDKs and
   examples; `init` and `build` are added because the deny adapter, the
   import check and the input cache are steps every Python and Go project
   needs identically, and the guide can then say `kronik build` for every
   language.
4. **Determinism test** for the new languages: `crates/kronik-sched`'s
   `sdk_determinism` test runs the components named in
   `KRONIK_DETERMINISM_COMPONENTS` (a sequence of inputs with real ids,
   SQL, effects and timers, twice, each in a fresh world), and CI's `sdks`
   step runs it on the six new examples.
5. **Limits unchanged** for Python and Go kinds: 50 M fuel and 64 MiB
   leave room; the SDK guide states the per-turn costs above.

## Alternatives

- **`componentize-py --stub-wasi`.** Passes the allowlist without a
  composition step, but bakes the build's random seed into `random` and
  traps on every clock read; the SDK would have to replace `time`,
  `datetime` and `random`, which the host already makes deterministic.
- **Allowing `wasi:filesystem` and `wasi:sockets`.** Out of the question in
  v0.1 (brief, "Aktörs-ABI").
- **Linking WASI-Virt into `kronik`.** It is not on crates.io in a current
  version (git dependencies are denied) and pulls in `wasm-opt` (C++) by
  default.
- **Kronik's own deny adapter.** A Rust component exporting every
  filesystem and sockets function as an error is possible but is a second
  WASI-Virt to maintain; revisit if the external tool becomes a burden.
- **Go's own compiler (`GOOS=wasip1`) instead of TinyGo.** It cannot
  produce components or export functions for the component model yet; the
  brief names TinyGo.

## Consequences

- Python and Go projects need the pinned tools on the build machine
  (and cargo once, for WASI-Virt). The server never runs them.
- A Python component carries CPython: 18.7 MB and a longer compile at
  deploy; a Go component is 2.75 MB.
- Python rebuilds change the hash unless `kronik build` keeps the previous
  component (Decision 2).
- Revisit when componentize-py or TinyGo change their WASI imports, when
  WASI 0.3 arrives (M22), or when Go's own compiler can build components.
