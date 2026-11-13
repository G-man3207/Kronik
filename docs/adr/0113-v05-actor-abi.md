# 0113. The v0.5 actor ABI: additive 0.1.1 with an optional connection export

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

M24 (long-lived connections) has to deliver three new kinds of input to an
actor (a connection opens, a frame arrives, the connection closes). It also
has to let the actor answer an open with accept or refuse, and send frames.
M25 and M26 (streaming bodies and blob storage) add blob reads, blob
creation and reference operations. Their design is ADRs 0117 to 0122, and
this ADR is the ABI story the two designs share.

What constrains the choice:

- **The brief.** The WIT was "finalized in M1 and then versioned". Its rule
  is "one entry point, `handle`". It put `blob-ref`, `message.blobs` and
  `http-body::blob` into v0.1 "so that WIT does not need to change in a
  breaking way when blobs arrive". M24 got no such placeholder.
- **The freeze.** `docs/design/m1-core.md` §5 and `docs/reference/wit.md`:
  the WIT is frozen for v0.1, and it changes only by additions that existing
  components keep linking against. The project status lists M24's choice as
  open: "a new minor ABI or a second export within the current one".
- **The next breaking change is already known.** `handler.handle` is a
  synchronous export. A WASI 0.3 guest that awaits would trap, so the async
  component model needs an `async func` export: a breaking ABI generation.
  ADR 0070 (amendment, blocker 1) says that M24 and M25 face it too. Its gate
  is closed on the pinned Wasmtime.
- **Wasmtime 50.0.1 resolves semver-compatible names in both directions.**
  This holds for linker imports (`wasmtime` `src/runtime/component/linker.rs`,
  "Names and Semver"; `wasmtime-environ` `alternate_lookup_key`: for 0.x the
  compatible track is `0.<minor>`) and for `Component::get_export`
  (`component.rs`, its test of `@0.1.1` finding `@0.1.0`). A host bound to
  `kronik:actor@0.1.1` therefore links and calls a component built for
  `0.1.0`, as long as every interface they share has the same types and the
  host offers at least the guest's functions. A local prototype on the pinned
  Wasmtime confirmed it, as described in Consequences. `wasm-tools component
  targets` compares names exactly and is not a model of what Wasmtime
  accepts.
- **What breaks a component.** A new case in `input` or `output`, or a new
  field in `manifest`, changes the type of `handle` or `describe`. Every
  existing 0.1.0 component would then fail the typed export check, and the
  host would need a second binding generation to keep them running. They
  must keep running: deployed history replays (`kronik upgrade check`, the
  compatibility corpus), and I16 keeps old logs readable.
- **The host today.** `crates/kronik-runtime/src/host.rs` runs one
  `bindgen!` for the world `actor`, and `Program` holds an `ActorPre`. The
  import allowlist (`allowlist.rs`) names every `kronik:actor` interface and
  accepts the versions `0.1.x`.

## Decision

1. **v0.5 ships `package kronik:actor@0.1.1`; there is no 0.2.0.** The ABI
   grows on the 0.1 track by additions only. The next breaking generation is
   whichever comes first of the async handler (WASI 0.3) and `1.0.0` (M33).
   It gets its own ADR.
2. **The rules of the 0.1 track, from 0.1.1 on:**
   1. Existing interfaces, types, functions and worlds never change. No
      function is added to an existing interface, and no case or field to an
      existing type.
   2. New functionality comes as **new interfaces**, marked `@since(version =
      0.1.1)` (or the version that adds them). Each one is **complete when it
      first appears**. Functions whose milestone has not landed trap with
      `NOT_IMPLEMENTED`, and no release ships an interface that later grows.
      The reason: an import of an extended interface from a newer guest would
      pass an older host's allowlist and then fail at instantiation with an
      opaque type error, not with `IMPORT_NOT_ALLOWED`.
   3. **A new export is optional.** The host looks it up per component and
      never requires it, so a component without it runs exactly as before.
   4. The allowlist keeps naming every interface, so an older host refuses a
      newer interface with `IMPORT_NOT_ALLOWED` and the list of imports.
   5. One package version per release line. v0.5 is `0.1.1` for M24, M25
      and M26; whichever slice lands first bumps it, and no release ships in
      between.
3. **M24's surface** (the whole interface lands in M24's first slice):
   - an import interface `connections` (the connection id, frame and close
     types, `send`, `broadcast`, `close` and `send-now`);
   - an export interface `connection-handler` with three functions, `open`,
     `frame` and `close`, one turn each;
   - a world `actor-connections`, which is `include actor; import
     connections; export connection-handler;`.

   The world `actor` keeps its 0.1.0 shape. M25/M26 add their `blobs`
   import to it. The full WIT is in `docs/design/m24-connections.md` §2.
4. **One input in the log.** Connection events are `Input.connection` in the
   log. The scheduler, the recording, replay and the diff see one input
   type. Only the runtime chooses which export to call: `handle` for HTTP,
   messages, timers and migrations, `connection-handler` for connection
   inputs.
5. **Routes stay in the manifest.** A WebSocket or SSE route is a manifest
   route with the pseudo-method `WEBSOCKET` or `SSE`, so the `manifest` type
   does not change. A kind with such a route must export
   `connection-handler`, or deploy refuses it with `BAD_REQUEST`. Older
   hosts refuse these routes too, because their manifest validation does
   not know the method.
6. **One binding generation in the host.** A second `bindgen!` for
   `actor-connections` reuses the `actor` world's generated modules with
   `with:`. `Program` keeps the `ActorPre`, plus the connection
   pre-instance when the component exports `connection-handler`.
7. **SDKs** (Rust, TypeScript, Python, Go) build against
   `actor-connections` and always export `connection-handler`. When an actor
   defines no connection handlers, the SDK's default refuses an open with
   404. That code never runs, because the kind has no connection routes.

## Alternatives

- **A new minor version, `kronik:actor@0.2.0`,** with
  `input::connection(..)` and an accept case in `output`, and 0.1.0 frozen
  as it is. This keeps the brief's single entry point in the WIT. But the
  host would carry two binding generations until M33: every import trait
  twice (or a macro), conversions between two sets of generated types, and
  every host-function test twice. Every SDK and example would move at once.
  And 0.2 would itself be superseded by the async generation or by 1.0.0,
  so at v1.0 the host would carry 0.1, 0.2 and 1.0. Rejected for v0.5. The
  next breaking generation can move the connection events into `input` if
  the maintainers want the single entry point back.
- **No ABI change at all.** Connection events would arrive as
  `input::message` with reserved names, with typed accessors and
  accept/refuse calls in `connections`. This is stringly typed. It collides
  with operator and actor messages of the same name, so every path that
  creates a message would need a reserved-prefix check. `sender: none`
  already means "the operator". And the open's answer becomes a side
  channel. Rejected.
- **Adding functions to existing interfaces under 0.1.1,** as M1 did before
  the freeze. After a release this fails on older hosts with an opaque link
  error. Rejected.
- **Exporting `connection-handler` from the world `actor` itself.**
  Generated bindings would then require the export, and every 0.1.0
  component would fail to instantiate. Rejected.

## Consequences

- Components built for 0.1.0 are untouched: the compatibility corpus,
  `kronik upgrade check` and every deployed kind keep running.
- A component built with a v0.5 SDK imports
  `kronik:actor/connections@0.1.1` (a TypeScript component always does), so
  a v0.4 host refuses it with `IMPORT_NOT_ALLOWED`. That is expected: new
  components need a new host.
- The brief's "one entry point" holds for the log, the scheduler and replay,
  but not for the WIT, where a component has two exports. The WIT reference
  says so. The next breaking generation revisits it.
- M25/M26 follow the same rules: `blobs` lands whole in its first slice, and
  host-produced `http-body::blob` values reach only components that import
  `blobs` (ADR 0117 and the following ones).
- **Prototype.** On the pinned Wasmtime 50.0.1 (an uncommitted example in
  `kronik-runtime`), with the component's imports stubbed by
  `define_unknown_imports_as_traps`:
  - `get_export_index` found `kronik:actor/handler@0.1.0` under the name
    `@0.1.1`.
  - Bindings generated from the 0.1.1 WIT instantiated
    `tests/guests/counter.wasm`, which is built for 0.1.0, and its
    `describe` returned the counter's manifest.
  - The `actor-connections` pre-instance refused the same component ("no
    exported instance named `kronik:actor/connection-handler@0.1.1`").
  - The second `bindgen!` compiled with `with:` reusing the first world's
    modules.

  That import names resolve across 0.1.0 and 0.1.1 is Wasmtime's
  documented linker behavior. The first slice's tests check it with real
  host definitions.
- **Verification, in M24's first slice:** the committed corpus components
  link and replay under the 0.1.1 bindings; a component with and one without
  the export both run; the allowlist accepts `connections` and still refuses
  unknown interfaces; deploy refuses a `WEBSOCKET` route without the export.
- Revisit when the WASI 0.3 gate of ADR 0070 §5 opens, or at M33.
