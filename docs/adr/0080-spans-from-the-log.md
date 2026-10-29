# 0080. Spans are built from committed turn records

- **Status:** Proposed
- **Date:** 2026-10-27

## Context

M28: "Varje turn blir ett span. Meddelanden och anrop blir länkar, och
effekter blir underspan". Acceptance: "Ett anrop genom tre aktörer syns som
en sammanhängande trace i en vanlig OpenTelemetry-backend."

Kronik has no `tracing` spans; it has a log. The log already holds what a
span needs:
- every turn's `TurnRecord`, with its causal key, logical time, input,
  effects and outcome;
- a causal tree that `GET /v1/turns/{id}/trace` builds from the keys
  alone.

A turn may run more than once before it commits (crash recovery replays, I1
and I4). DST requires determinism in everything the scheduler does.

## Decision

- **Source.** The trace exporter in `kronik-otel` reads committed
  `TurnRecord`s from the log, after commit, and turns each into one span.
  Each of its `EffectRecord`s becomes a child span. Nothing in the turn path
  creates spans.
- **Ids.** Every id is a deterministic function of the record and the
  node's id key:
  - Trace id: the causal root, which is 16 random bytes as hex (blake3 of
    the root if it is not 32 hex characters), always. An incoming W3C
    `traceparent` is a link on the root span (`traceparent`), with only its
    two ids: adopting its trace id would split the trace, because a callee
    derives its trace id from its own record and a CALL input carries no
    trace context.
  - A trace is one root and its synchronous calls. A timer turn and a
    message's receiver start a new trace, its id derived from their own
    causal key (keyed, as below), with a `timer` or `message` link to the
    cause. Their keys are children of the turn that caused them, so
    otherwise a self-rescheduling timer, or two actors messaging each
    other, would make one unbounded trace. A callee takes its caller's
    trace, which the
    exporter keeps for every open turn (calls are synchronous, so the
    caller is open). It also keeps a committed callee's trace while its
    messages, timers or compensation are still to come, so that their
    links name the span that exists, and a caller's trace while a callee
    whose call timed out has not run (M28 code review M7). A rewind
    rebuilds this set at the rewind point from the retained log (M8).
  - Turn span id: 8 bytes of `blake3_keyed(id key, "kronik span v1" ‖
    encode(causal_key))`; a migrate turn also hashes
    `u32_le(to_schema_version)` (into its trace id too), as one input can
    migrate twice under one key.
  - Effect span id: 8 bytes of `blake3_keyed(id key, "kronik effect span v1"
    ‖ encode(causal_key) ‖ ordinal)` (with the same migrate suffix).
  - The id key is `Sealer::keyed_hash("kronik otel ids v1", [])`, or the same
    construction with the node-local `otel.key` on a node without a master
    key (ADR 0082). The causal key holds every step's actor key in plain,
    so unkeyed ids would let a backend confirm a guessed actor key (M28 perf
    review P1). Only the root's trace id, which is random, is not keyed.
- **Parent and link.** Every non-root turn within a trace gets both, so the
  trace is connected and the causal relation is still explicit:
  - a call: parent = the caller's `actor.call` effect span, link `call`;
  - a compensation: parent = the turn its key path names, link
    `compensation`;
  - a timer or a send (new trace) and a migrate (it runs before its input
    turn): no parent, a `timer`, `message` or `migrate` link;
  - a resend starts a new trace, with a `resend` link to the dead-lettered
    turn.
- **Times.**
  - A turn starts at `logical_time_ms`. Its duration is
    `TurnRecord.duration_us` (field 23, from M11) where present.
  - An effect starts at the turn's start plus the new
    `EffectRecord.offset_us` (field 80). Its duration is
    `EffectRecord.duration_us`, which the scheduler now sets for every kind
    of effect, not only fetch.
  - Records without these fields fall back as described in m28-otel §3.3.
  - Children are clamped into their parents where the parent's record is in
    the same batch: `logical_time_ms` is in milliseconds and can run ahead
    of the wall clock. So a callee's times depend on the batching: a
    re-export cut differently can move them (m28-otel §3.3).

## Alternatives

- **Live instrumentation in the scheduler** (`tracing` spans plus
  `tracing-opentelemetry`).
  - It would emit spans for runs that never commit, and twice for a
    recovered turn.
  - It would put work on the hot path, and its timing would be
    nondeterministic inside code that DST simulates.
  - It cannot re-export after a collector outage.
- **Calls as links only, with no parent.** Backends show such spans as
  separate roots ("orphans"), and the acceptance asks for a call through
  three actors to be one connected trace. Messages, which are asynchronous,
  do become links: in a new trace, not an orphan inside the old one.
- **Messages inside the sender's trace** (the first draft). Unbounded
  traces for actors that message each other (design review M1).
- **Trace context carried in the call input.** It would let a callee know
  its trace without the exporter's open-turn set, but adds a recorded field
  on every call for what the log already implies.
- **Random span ids** recorded in the log. That needs a record change and
  makes a re-export produce new spans. Derived ids need neither.

## Consequences

- Exporting a span twice sends the same span. Any reader of the log
  (another node, a later run) computes the same trace.
- Spans appear once their turn commits, so a slow turn's span is late, not
  missing. A crash before commit leaves no span, which matches the log.
- Callees commit before their callers, so a trace fills in from the leaves.
  Backends join spans by id, whatever order they arrive in.
- Verified by `crates/kronik/tests/otel.rs` (an in-process OTLP receiver,
  three actors, connectivity checks) and by `demo/vps-otel.sh` against
  Jaeger (m28-otel §8).
- Revisit if a backend needs spans while a turn is still running. That
  would need live spans in addition to these.
