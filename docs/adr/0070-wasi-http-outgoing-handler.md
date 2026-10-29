# 0070. Standard `fetch` through `wasi:http/outgoing-handler` as an `http.fetch` effect

- **Status:** Accepted (spike `spikes/spike-m22-wasi-http` proved §2 and §3's secret mapping for TypeScript `fetch`; §5 blocked on Wasmtime)
- **Date:** 2026-10-27

## Context

M22 (brief "M22 WASI 0.3 och wasi:http") wants standard `fetch` in guest code
recorded and matched like other effects, secrets in `wasi:http` headers as
`{{secret:NAME}}` inserted by the host, and WASI 0.3 components "when Wasmtime
supports them stably". Today `wasi:http` is denied (`IMPORT_NOT_ALLOWED`,
`crates/kronik-runtime/src/allowlist.rs`), TypeScript builds use `--disable http
fetch-event stdio` (`crates/kronik/src/project/build.rs:32`, ADR 0002 §3), and
the TS SDK's `ctx.http.fetch` calls `kronik:actor/http-client.fetch`
(`sdk/ts/src/ctx.ts:8,139`). That path ends in `EffectGate::fetch`
(`crates/kronik-runtime/src/host.rs:155`), which the scheduler implements with
capability checks, secret rendering, recording, replay, limits, delivery
classes and scrubbing (`crates/kronik-sched/src/effects.rs:236-512`).

Findings (registry sources under `~/.cargo/registry/src/index.crates.io-*/`):

**1. `wasmtime-wasi-http` 50.0.0 exists and implements `wasi:http@0.2.12`**
(`wit/deps/http.wit:1`; `src/p2/mod.rs:9-13` lists `outgoing-handler`, `types`,
`incoming-handler`).

- Hook: `WasiHttpHooks::send_request(&mut self, http::Request<WasiBody>,
  Option<RequestOptions>, fut) -> Box<dyn Future<Output = Result<(Response<WasiBody>,
  io)>> + Send>` (`src/ctx.rs:251-322`); without `default-send-request` it has
  no default, so no request can bypass Kronik. Also `forbidden_header_filter`,
  `is_supported_scheme`, `set_host_header`, `default_scheme` and the p2 body
  buffer sizes (`src/ctx.rs:215-337`), reached through `WasiHttpCtxView.hooks`.
- `outgoing-handler.handle` is sync: it builds the request, calls
  `send_request` and spawns the future with `wasmtime_wasi::runtime::spawn`
  (tokio, else a global runtime; `wasmtime-wasi-50.0.0/src/runtime.rs`)
  (`src/p2/http_impl.rs:20-119`).
- Features: `default = [default-send-request, p2, p3]`; only
  `default-send-request` pulls `rustls`+`ring`, `tokio-rustls`, `webpki-roots`;
  `hyper` (`full`) and `tokio` are unconditional. `cargo tree --offline` on a
  scratch crate with `default-features = false, features = ["p2"]` adds one
  crate to Kronik's `Cargo.lock`, `wasmtime-wasi-http` itself (`hyper`, `h2`,
  `tokio`, `rustix` are already there); no C dependency. MSRV 1.97 ≤ 1.99.1.
- Bodies: the outgoing body is an `mpsc` channel with `buffer_chunks + 1`
  slots; `check-write` returns 0 when the channel is full, so its answer
  depends on how fast the host drains (`src/p2/body.rs:417,588-603`). The
  incoming body stream reads frames with a no-op waker; a fully buffered
  `Full<Bytes>` body is readable at once (`src/p2/body.rs:173-219`).
  `future-incoming-response.get` returns `none` until a pollable on it has
  observed readiness (`src/p2/types.rs:229-259`, `types_impl.rs:609-614`).
- Non-determinism: `wasi:io/poll.poll` returns every pollable that is ready
  *at that moment* (`wasmtime-wasi-io-50.0.0/src/impls.rs:15-67`), and
  StarlingMonkey runs the ready task with the lowest index (below). Two
  in-flight fetches can therefore resolve in different orders live and in
  replay. `request-options` timeouts are only used by `default_send_request`.
  Kronik's clock pollables are already always ready (`host.rs:880-900`).

**2. WASI 0.3 is not stable in Wasmtime 50.** WASI 0.3.0 was ratified on
2026-06-11 ([WASI v0.3.0](https://github.com/WebAssembly/WASI/releases/tag/v0.3.0)),
and [wasi.dev/releases](https://wasi.dev/releases) says Wasmtime 46+ runs 0.3
components by default. The component-model `async` ABI is on by default when
the `component-model-async` Cargo feature is compiled in
(`wasmtime-50.0.0/src/config.rs:2629-2635`) and is listed with all boxes ticked
except the C API in [stability-wasm-proposals.md@release-50.0.0](https://github.com/bytecodealliance/wasmtime/blob/release-50.0.0/docs/stability-wasm-proposals.md).
But: the host side is explicitly unstable. `wasmtime_wasi::p3` and
`wasmtime_wasi_http::p3` (which implements `wasi:http@0.3.0`) say "Experimental,
unstable and incomplete … not compliant with semver … not ready for production
use … Bug and security fixes limited to wasip3 will not be given patch
releases" (`wasmtime-wasi-50.0.0/src/p3/mod.rs:1-9`,
`wasmtime-wasi-http-50.0.0/src/p3/mod.rs:1-9`); `Config::wasm_component_model_async`
still says "very incomplete" (`config.rs:1301-1314`); neither
`component-model-async` nor WASIp3 appears in any tier of
[stability-tiers.md@release-50.0.0](https://github.com/bytecodealliance/wasmtime/blob/release-50.0.0/docs/stability-tiers.md)
(`wasi-http` there is the 0.2 implementation). ADR 0001 keeps
`component-model-async` out of the build. **Verdict: M22's third bullet is not
met by Wasmtime 50.**

**3. TypeScript `fetch` needs only two `wasi:http` imports.** The pinned
toolchain is `@bytecodealliance/jco` 1.39.0 → `componentize-js` 0.23.0
(`sdk/ts/package-lock.json`). Its features are `stdio random clocks http
fetch-event`; `http` is "outbound HTTP via the `fetch` global"
(`node_modules/@bytecodealliance/componentize-js/src/componentize.js:64`,
`README.md:185`). ADR 0002's measured imports: with `http` enabled the
component adds `wasi:http/types@0.2.10` and `wasi:http/outgoing-handler@0.2.10`
(the rest: `wasi:io/{poll,error,streams}`, `wasi:clocks/*`, `wasi:random`,
`wasi:cli/stderr`); `wasi:filesystem` only comes with `stdio`. Wasmtime's linker
resolves `@0.2.10` to a `@0.2.12` definition (`wasmtime-50.0.0/src/runtime/component/linker.rs:26-49`).
In [StarlingMonkey](https://github.com/bytecodealliance/StarlingMonkey) `main`
(read on 2026-10-27; that the engine in componentize-js 0.23 behaves the same
is [INFERENCE]), every body, even a string, becomes a `ReadableStream`
(`builtins/web/fetch/request-response.cpp`, `extract_body`), so `fetch` calls
`outgoing-handler.handle` *before* writing the body
(`builtins/web/fetch/fetch-api.cpp:105-131`); the event loop polls all pending
tasks and runs the lowest ready index (`host-apis/wasi-0.2.0/host_api.cpp`,
`AsyncTask::select`). It sets `content-length` and, for text, `content-type`.
componentize-js 0.23 has no WASI 0.3 target [INFERENCE from its feature list].

## Decision

### 1. Dependency

Add `wasmtime-wasi-http = { version = "=50.0.0", default-features = false,
features = ["p2"] }` to `kronik-runtime`. Never `default-send-request`, `p3`
or `component-model-async`. `kronik-runtime` keeps no network code.

### 2. Interception: queue in the hook, drive in `wasi:io`

- `TurnHost` gets a `WasiHttpCtx` and a `KronikHttpHooks`. `send_request`
  never touches the network: it hands the request back to the host and
  returns a future that never resolves. `set_host_header` → `false`;
  `is_supported_scheme` → `http`/`https` only; `forbidden_header_filter` =
  default list.
- Kronik links `wasi:http/outgoing-handler.handle` by hand (`func_wrap`; the
  generated `add_to_linker` needs all of `wasi:http/types` on the store type,
  through `types::Host`'s supertraits). The wrapper calls wasmtime-wasi-http's
  `outgoing_handler::Host::handle` and queues the request with the returned
  `future-incoming-response`'s table index, in `handle` order. A new handle
  that reuses a queued index means the guest dropped the old future: that
  request is never sent.
- Kronik implements `wasi:io/poll.poll`, `pollable.block` and the
  `blocking-*` stream calls itself, as wrappers around wasmtime-wasi-io that
  first run **drive**: for each queued request in `handle` order, take the
  body frames that are already there (no-op waker); when the body is
  finished (≤ limit), take the next operation ordinal, run the effect via
  `EffectGate::fetch` on the turn's executor and replace the future's table
  entry with `Ready(response)`. The task `handle` spawned is aborted with
  it: no answer goes through tokio, so readiness never depends on when a
  task runs. Effects of one turn run one at a time, in ordinal order, like
  `http-client.fetch` today.
- The ordinal is taken when the effect runs, not in `handle`: StarlingMonkey
  calls `handle` before it writes a body, so bodies complete in another
  order than `handle` (spike: a `GET` started second runs first). Ordinals
  stay in the order effects happen, and that order depends only on where
  the guest blocks.
- Result: host-side `wasi:http` progress happens only while the guest is
  blocked in a `wasi:io` wait, and every wait returns a ready set that depends
  only on guest actions and recorded results. `check-write` capacity changes
  only during drive, so write loops (and fuel) are deterministic too.
- A blocking wait that finds nothing ready and nothing left to drive cannot
  ever finish. An example is a guest that waits for the response to a
  request whose body it never closed. The turn then traps at once with
  `TURN_FAILED` ("wasi:http: ... waits for something that can never be
  ready"), instead of hanging until the effect timeout. The trap depends
  only on what the guest did.
- A turn may have 32 requests it has not waited for (each holds up to a
  request body in host memory); the 33rd `handle` returns
  `connection-limit-reached`.

### 3. Mapping onto the `http.fetch` effect

- **Kind and target:** `http.fetch`, capability `http:<host>`, the same
  `FetchRequest` → `HttpEffectRequest`, fingerprint, `EffectRecord`, delivery
  class (default by method), idempotency key, rate limit and `kronik-sim`
  simulators. No second kind and no second HTTP stack.
- **Request:** method, absolute URI as `url`, every header value as one
  `(name, FetchHeader)` entry, body collected up to the kind's
  `message_bytes` (1 MiB by default), the limit `http-client.fetch` applies
  to request bodies. `request-options` timeouts are ignored; the effect
  timeout applies. Request trailers are refused (`HTTP-request-denied`).
- **Secrets:** a header value containing exactly one
  `{{secret:NAME}}` (NAME matching `[a-z0-9][a-z0-9_.-]{0,63}`) becomes
  `FetchHeader::Secret { name: NAME, template: value with the placeholder
  replaced by "{}" }`. From there the existing gate applies unchanged:
  capability `secret:NAME` (else `CAPABILITY_NOT_GRANTED: secret:NAME`), value
  lookup (else `SECRET_NOT_FOUND: NAME`), `SecretRef` (name, version, version
  hash) in the record, value only in wire headers, response headers, body and
  network errors scrubbed of every secret known to the turn
  (`effects.rs:281-333,456-491`). The guest only ever holds the placeholder.
  Two placeholders in one value, or a literal `{}` beside one, are rejected as
  `HTTP-request-denied` with a turn log event (`wasi:http: ... not sent`).
- **Response:** `status`, scrubbed headers, body as one `Full<Bytes>`, no
  trailers.
- **Errors** (`FetchOutcome` → `wasi:http/types.error-code`): `Denied` →
  `HTTP-request-denied`; `Timeout` → `HTTP-response-timeout`; `TooLarge` →
  `HTTP-response-body-size(some(limit))`; `Network(msg)` →
  `internal-error(some(msg))`; `OutcomeUnknown` →
  `internal-error(some("outcome-unknown"))`, and the turn fails with
  `EFFECT_OUTCOME_UNKNOWN` exactly as for `http-client.fetch`
  (`node.rs:1281`). A request body over the limit →
  `HTTP-request-body-size(some(limit))` without an effect (deterministic from
  guest input). No new error codes. StarlingMonkey turns every error code
  into the same `TypeError: NetworkError when attempting to fetch resource`,
  so a TypeScript actor that must tell a denial from a network error uses
  `ctx.http.fetch` (`webhook-relay-ts` does; `uptime-ts` uses `fetch`).

### 4. Imports and build

- Allow `wasi:http/types` and `wasi:http/outgoing-handler` at `0.2.x`. Keep
  denied: `wasi:http/incoming-handler` (the gateway owns inbound HTTP),
  `wasi:sockets`, `wasi:filesystem`, every `0.3.x` package.
- `kronik build --lang ts` drops `http` from `DISABLED_FEATURES` (keeps
  `fetch-event stdio`). `globals.d.ts` gains `fetch`, `Headers`, `Response`
  and `ReadableStream`; `ctx.http.fetch` stays (the path to `foreign://`
  and to error kinds). Every TypeScript component now imports the two
  `wasi:http` interfaces, whether or not it calls `fetch`.
- The TS SDK's handlers may be `async`: `handle` returns the handler's
  promise, ComponentizeJS runs the event loop until it settles, and a
  rejection becomes the handler error as a throw does.
- The example `uptime-ts` fetches its targets with `Promise.all` and a
  `Bearer {{secret:NAME}}` header; its tests run in the test host and
  `scripts/identity-examples.sh` replays it.

### 5. WASI 0.3

Not in M22 on Wasmtime 50. Gate to revisit: a Wasmtime release where the
`p3` modules of `wasmtime-wasi`/`wasmtime-wasi-http` lose the "experimental,
no patch releases" banner and WASIp3 / `component-model-async` is listed at
tier 1 (or tier 2) in `stability-tiers.md`, plus a componentize-js release
that targets `wasi:http@0.3`. Then: compile `component-model-async`, add `p3`,
re-run ADR 0001's determinism suite with the async scheduler, and route the
0.3 `wasi:http/client.send` import (`src/p3/wit/deps/http.wit:454`) through
the same `send_request` hook, queue and gate.

### 6. Spike results (`spikes/spike-m22-wasi-http`, 2026-10-27)

A standalone harness (Kronik's engine from `kronik_runtime::build_engine`,
the real `EffectGate`/`FetchRequest`/`FetchHeader` types, a stand-in gate
that renders and scrubs secrets as `effects.rs` does, 0 to 4 ms of random
real latency per effect) runs a guest built with the pinned jco 1.39.0 /
componentize-js 0.23.0 with only `fetch-event stdio` disabled. Its imports
are exactly `wasi:http/{types,outgoing-handler}@0.2.10` beside the
allowlisted `wasi:io`, `wasi:clocks`, `wasi:random` and `wasi:cli/stderr`.
100 runs per mode (`results/run.txt`):

| Mode | Transcripts (output, effects, every `poll` ready list, fuel) |
| --- | --- |
| `Promise.all` of a `POST` with a string body and a `GET` with `authorization: Bearer {{secret:api}}` | 1 of 100, fuel 2 345 224 |
| a `POST` whose body is a `ReadableStream` of 64 one-byte chunks (more than the body buffer) | 1 of 100 (64 waits on the body stream), fuel 3 616 482 |
| a denied request | 1 of 100; the guest sees `TypeError: NetworkError when attempting to fetch resource` (StarlingMonkey drops the error code) |
| the first mode with the effect inside `send_request`'s future (the first alternative below) | 8 of 100: completion order, effect order and fuel vary |

The secret header reached the gate as `FetchHeader::Secret { name: "api",
template: "Bearer {}" }`; the guest saw `Bearer [secret:api]` in the echo,
never the value. StarlingMonkey adds `content-length` and, for text,
`content-type`, and waits with `poll` and `blocking-flush`. Not covered by
the spike: the real gate (capability, records, replay), `kronik-sim`'s
executor (`handle` still calls `wasmtime_wasi::runtime::spawn`, which needs
a tokio runtime), forks and simulators. Those are M22's implementation.

## Alternatives

- **Effect inside `send_request`'s future.** Simplest, but it runs on a tokio
  task outside the turn executor (breaks `kronik-sim`) and completes at a
  wall-clock time the guest observes through `poll` (spike: 8 different
  transcripts in 100 runs).
- **Block in `handle` until the response exists.** StarlingMonkey writes the
  body after `handle`: deadlock for every `fetch` with a body.
- **Own bindings for all of `wasi:http/types`.** ~2,000 lines of resource
  plumbing duplicated from `wasmtime-wasi-http`.
- **`default-send-request` or a separate `wasi.http` kind.** A second network
  stack (own TLS roots) or a second record format for the same effect.
- **SDK polyfill of `globalThis.fetch` over `http-client`.** TS only; kept as
  fallback if the drive design fails its determinism test.

## Consequences

- One new crate, no new C code, no new error codes; the effect layer, record
  format, fork matching and simulators are unchanged.
- Parallel `fetch` calls in a turn run sequentially (as with the SDK today),
  in the order their bodies complete at the guest's waits.
- Responses are fully buffered within the limit; streaming waits for M25
  blobs. `fetch` and `ctx.http.fetch` fingerprints can differ (headers added
  by StarlingMonkey), so switching an actor between them breaks matching.
- No response goes through a tokio task: drive writes it into the table
  (§2). `handle` itself still spawns one (aborted unanswered), so a turn
  needs a tokio runtime context, also under `kronik-sim` [to check in the
  implementation].
- A guest that never finishes a request body fails its turn at its first
  blocking wait (§2), deterministically.
- **Verification (M22 acceptance):** a TS actor with `fetch` (string body,
  1-byte chunked stream body, `Promise.all` of two fetches) against a
  simulated server with jittered latency: identical turn records and fuel
  over 100 runs, identity replay without network, a fork matching the
  recording; a `{{secret:API}}` header whose value is grepped for in the data
  directory, the log and guest-visible responses (also echoed by the server)
  and never found; ungranted and unknown secrets give `HTTP-request-denied`
  with `CAPABILITY_NOT_GRANTED`/`SECRET_NOT_FOUND` records; the allowlist
  accepts the new imports and still rejects `incoming-handler` and `@0.3`.
- Revisit if Wasmtime adds a hook that exposes the response pollable (drive
  could then drop the `handle` wrapper), or when the WASI 0.3 gate in §5 opens.
