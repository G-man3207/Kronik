# 0116. Connections in replay and the behavior diff

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-13

## Context

The brief: "In replay, incoming frames are root inputs, and outgoing frames
are compared as responses." M24's second acceptance criterion asks two
things. Identity replay of a recorded WebSocket session must give an empty
diff. And a changed formatting of messages must show up as changed outgoing
frames.

The rest of the context:

- **I7.** Forks never reach the outside world.
- **Replay today** (`docs/design/m3-fork.md`):
  - the root inputs are the turn records of the window with an empty causal
    path;
  - isolated replay runs each against production's state at its LSN;
  - continuous replay evolves its own state;
  - turns differ when their outcome, output, writes, messages, timers,
    effects or SQL differ;
  - external effects are matched exact, approximate or synthetic, and
    counted in `grounding` and `summary.confidence`, which the default
    policy reads (`low-grounding-needs-approval` below 0.9).
- **The diff format.** `kronik.diff/v1` has grown by optional fields before
  without a new version: `kinds` (M9), `preview_inputs` (M11),
  `synthetic_by` (M12) and `forked` (M14). Its JSON Schema
  (`docs/reference/diff-v1.schema.json`) closes every object
  (`additionalProperties: false`), so additions go into the schema.
- **`send-now` is an `unsafe` effect** (ADR 0115). Its "answer" is `ok`,
  `closed` or `outcome-unknown`, and it comes from Kronik's own gateway, not
  from a system outside.

## Decision

1. **Root inputs.** Connection inputs (open, frame, close) are root inputs
   like HTTP requests. They replay in both modes, are sampled per stratum,
   and are grouped in `causes` under the labels
   `connection open|frame|close <WEBSOCKET|SSE> <route>`.
2. **Comparison.** A turn's outgoing connection operations are part of what
   §4 of the fork design compares. That is the ordered list of
   (connections, frame kind, data, SSE event and id) and closes
   (connection, code, reason), and the open turn's answer (accept with
   subprotocol, headers and subject, or the refusal's HTTP response). The
   `seq` is not compared, because an earlier change shifts it. The noise
   filters (`ignore_json_paths`) apply to JSON frame data as they apply to
   bodies.
3. **The diff.**
   - A new optional top-level `frames` section, after `responses`, built
     like `responses` from isolated replay. Each changed item has the root
     input, its route, its turns, the open answer when it changed, and the
     changed frames with JSON body operations.
   - Optional `summary.frames_changed`, `kinds[].frames` and
     `samples.frames_changed`.
   - A "Frames" section in the Markdown.
   - `--summary` shows counts only, never frame data.
   - All of it is absent when the window has no connection input and no
     frame. The schema stays `kronik.diff/v1`, as for M9, M11, M12 and M14.
4. **`send-now` in a fork writes nothing anywhere (I7).** The fork answers
   it from the recording, matched by causal key, ordinal and kind:
   - same connection and identical frame: the recorded result (exact);
   - same connection, different frame: the recorded result (approximate),
     with the frame difference in `frames`;
   - otherwise the **connection model** answers `ok` when the connection is
     open in the fork's state at that turn, and `closed` when it is not.

   `send-now` is **not counted in `grounding` or `summary.confidence`**: its
   answer says nothing about a system outside. `frames.send_now` reports how
   many answers were recorded and how many modeled.
   `fork.live_allowlist` never applies to connections.
5. **Connections the fork does not hold.** In continuous replay, a frame or
   close input for a connection that the fork's actor did not accept (the
   fork refused the open) is not run. It is counted in `frames.skipped` with
   samples, and its production turn is reported as missing in the fork.
   Isolated replay always runs such inputs, because production's state at
   their LSN holds the connection.
6. **Identity replay of a recorded session is empty.** Everything that
   drives a connection turn is recorded or derived from the recorded state:
   the connection ids, the seqs (from the `connections` table at the turn's
   start), the `send-now` results, the close facts (`frames_written`, cause,
   code).
7. **Previews do not take connections in M24.** A WebSocket or SSE request
   to a preview answers `501 NOT_IMPLEMENTED`. Ordinary forks and replays
   have no gateway at all.
8. **A rollback via replay (M13)** closes the live connections of the
   rebased kinds (host reason `rebase`). The connections that the rebased
   state holds open then get host closes, as after a restart.

## Alternatives

- **Counting `send-now` in `grounding` like `http.fetch`.** A change to how
  a stream is cut into frames would lower the confidence and trigger
  `low-grounding-needs-approval`, though nothing outside was guessed. The
  confidence would stop meaning "how well the fork's answers rest on
  recordings". Rejected. The frame difference is reported where a reviewer
  reads behavior: in `frames`.
- **`FailClosed` (denied) for an unmatched `send-now`,** as for an
  unmatched fetch. Code that streams differently would then fail in replay
  and show as introduced errors that production would never have.
  Rejected.
- **Reporting frames under `responses`.** Frames have no status or headers,
  a turn sends to many connections, and one root input can send frames
  without being a connection input (an HTTP POST that broadcasts). A
  section of its own with per-kind counts is clearer. Rejected.
- **`kronik.diff/v2`.** Optional additions have kept v1 four times, old
  diffs still validate, and policies keep working. A new version would
  force every policy and tool to change for no gain. Rejected.
- **Running the frames of connections the fork refused** in continuous
  replay. The fork's actor would get frames for connections it never
  accepted, which would show as false origins. Rejected.

## Consequences

- A reviewer sees a changed message format as changed frames, with JSON
  pointer operations, and a changed open policy as changed open answers.
- Policies can read `diff.frames.changed` (for example to require approval
  for a chat change). The defaults do not change.
- The diff builder, its Markdown renderer, the schema and its fixtures get
  a `frames` part (`docs/design/fixtures/diff-connections.json`).
- Verified by identity replay of a recorded chat session (`chat-ts`, and a
  Rust test guest in `cargo test`) being empty in both modes and
  byte-identical with 1, 4 and 16 workers, and by a formatting variant
  whose diff shows changed frames and nothing else.
- Revisit when previews take connections, or when a cluster delivers
  frames from several gateway nodes.
