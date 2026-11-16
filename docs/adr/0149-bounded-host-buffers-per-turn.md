# 0149. Host-side turn buffers share the memory limit

- **Status:** Accepted (2026-11-16)
- **Date:** 2026-11-16

## Context

The turn host copies guest-supplied data into buffers that live on the
daemon's heap: guest log events (`log.emit`, and stdout/stderr through the
WASI streams), buffered state writes (`state.set`), outbound messages
(`messaging.send` and `messaging.call`) and scheduled timers
(`timers.schedule`). The resource limiter counted linear memories only,
and fuel charges instructions, not bytes. Each of those buffers had a
per-item limit (1 MiB for a message or a state value, 10,000 operations for
connections), but no per-turn total, so a deployed actor could make one
turn buffer far past the documented 64 MiB memory limit. Issue #121 found
that about 130 `log.emit` calls with 60 MiB messages make the daemon
allocate about 8 GiB; the node's API socket, every other turn and every
actor share that process, so it is a denial of service by a single
deployed component.

Connections already bounded their buffered operation, target and payload
bytes, and effects have their own per-turn cap (ADR 0145). The missing
bound is on the buffers a turn fills directly. Those buffers must be
deterministic: a replay and a fork's re-run must decide from the same
input and state as production (I1), and the recorded turn must not depend
on the host's remaining memory.

## Decision

- **One shared budget per turn.** `TurnLimits::host_bytes` is the bytes a
  turn may hold in its guest logs and stdout/stderr, state writes, messages
  and timers together. The scheduler and a fork's replay set it to the
  kind's `memory_bytes`, the same per-kind limit as its linear memories;
  the default is 64 MiB and the runtime caps it at 1 GiB. There is no new
  `Limits` field, log record or API parameter: `kronik limits set <kind>
  --memory <size>` raises it, and a replay uses the recorded epoch's value
  as it does for `memory_bytes`.
- **Charged as data is copied.** Each buffered entry costs 128 bytes of
  bookkeeping plus its payload: a log event's message and each field name
  and value; a state write's key, value and subject; a message's name,
  content type, body and blob references; a timer's message. State writes
  are charged when they are copied, not when the map replaces an earlier
  value, so a loop that keeps overwriting one key still stops. Logs
  written by the host itself for the guest (`wasi:http` warnings) are not
  allowed to fail a turn: they are dropped once the budget is spent.
- **Over the budget, the turn traps.** The next charge that would pass the
  budget raises the existing `TURN_TOO_LARGE` host trap, before the host
  stores the entry. The turn fails with that code as its outcome; its
  buffered state writes, messages and timers are discarded, as for a
  record that does not fit. Log entries copied before the trap stay with
  the failed turn for diagnosis, up to the budget. An HTTP client gets
  `TURN_FAILED`, as for any failed turn.
- **Reusing `TURN_TOO_LARGE`.** The code already means the turn produced
  more output than one turn may hold; its hint (split the work or write
  less) and its HTTP shape fit this bound. No new code, WIT change or
  status is needed. The catalog entry, the security model and the WIT
  reference state both limits and how to raise the host one.
- **Connections keep their own caps.** Their operation, target and payload
  limits are stricter than this budget for small frames and already
  deterministic; they are not double-charged.

## Alternatives

- **A new per-kind `host_bytes_per_turn` limit.** It would add a
  `Limits` field, CLI flag, API field and compatibility fixture for a
  second memory knob that operators would have to raise with `memory_bytes`
  anyway. Revisit if a kind needs much more linear memory than host
  buffering, or the reverse; today the two are the same resource decision.
- **Separate log and writes/messages/timers budgets.** Four limits whose
  sum is still unbounded per turn is worse than one; splitting one budget
  into two would need a rationale for the split, and the issue permits
  either.
- **Item counts only.** A small count of 64 MiB messages still exhausts
  memory; bytes have to be counted.
- **Charging the bytes as fuel.** Fuel is deterministic and recorded, but
  changing its arithmetic changes every turn's `fuel_used` and the
  identity of replays and upgrade checks. The budget is a host limit, not
  work the guest did.
- **A process-wide cap.** It would make one actor's failure another's
  `UNAVAILABLE`, and the same turn could pass or fail depending on
  concurrency, breaking replay identity.

## Consequences

- A default turn may buffer at most 64 MiB of these outputs on the host; a
  kind with a larger memory limit may buffer up to 1 GiB. This bounds the
  attack in issue #121 independently of the turn's record size.
- A turn that legitimately logged or wrote more than its memory limit in
  one turn now fails instead of growing the daemon. Operators raise the
  kind's memory limit, which also raises its guest linear memory, or split
  the work; the failure names the budget and is in dead letters for a
  message or timer input.
- The budget is deterministic and identical in production, a re-run and a
  fork's replay, because it comes from the turn's recorded configuration
  epoch and charges only guest actions that replay repeats.
- Verified by `kronik-runtime` unit tests for the cap and accumulation, a
  regression guest (`tests/guests/counter-budget.wasm`) that loops
  `log.emit`, stdout, `state.set`, `messaging.send` and `timers.schedule`
  and traps at a small budget while committing below it, and a scheduler
  unit test that the per-kind memory limit is the limit mapped into
  `TurnLimits`.
