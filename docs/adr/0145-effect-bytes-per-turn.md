# 0145. A per-turn cap on the effect bytes a turn records

- **Status:** Accepted (2026-11-14)
- **Date:** 2026-11-14

## Context

ADR 0130 made every turn's record fit in one log record, but effects are
recorded as they happen, each in its own `EffectResult` record, and effects
are not charged fuel. One turn could still write about twice the record
limit to the log: its effect results (up to 128 MiB, bounded only by the
turn's record budget) and then its turn record. Issue #74 asked for a
per-kind limit on what one turn's effects record, set like the other limits
and recorded in the log (I5). It needed a maintainer decision on the
default; the decision (2026-11-14) is 32 MiB.

The invariants that shape it: every effect is recorded before the guest
sees its result (I14), a re-run and a fork's replay must make the same
decisions as production (I1), a fork never reaches the outside world (I7),
and the log stays readable across releases (I16).

## Decision

- **A new limit, `effect_bytes_per_turn`** (`Limits` field 18, per actor
  type, default 32 MiB), set with `kronik limits set <kind>
  --effect-bytes-per-turn <SIZE>` and `POST /v1/limits`, shown by `limits
  show` and `GET /v1/limits`, and audited like the other limits. A turn uses
  the value of its configuration epoch.
- **What counts:** what each of the turn's effect results holds inline, its
  request and its response as recorded (`record_budget::effect_bytes`, the
  encoded `Sealable`s): an HTTP body with its headers, a `call`'s message and
  reply, a frame sent now, the small records of crypto calls and secret
  reveals. A body stored as a blob (an M25 blob request body, a response
  above the blob threshold) is only its reference there, so it counts no
  more than that; the blob quota bounds it. Denials and refusals record no
  request and count nothing.
- **When an effect would pass it, the effect fails** with the new code
  `EFFECT_BYTES_EXCEEDED`, recorded as that effect's result; the turn goes
  on and its code decides what to do:
  - a request that alone does not fit in what is left is not sent (for a
    `call`: its request and the largest reply the callee may send, its
    type's message size, plus 4 KiB; for a crypto call or a reveal, 4 KiB).
    The refusal is deterministic, so it is recorded without an fsync, as a
    denial is;
  - an HTTP response is read at most up to what is left after its request;
    one that would pass it, with its headers, is sent and not recorded.
  The guest gets the failure of its effect's kind: `too-large` for a fetch,
  `failed` for a `call`, `denied` for `send-now` and crypto, an error for a
  reveal, each with the code in its text where the kind carries one. The
  result's status is the one whose outcome the guest sees (`TOO_LARGE`,
  `FAILED`, `DENIED`); no new status and no WIT change.
- **Recorded results are charged, never refused.** A re-run's results from
  its earlier execution and a fork's copies of production's results count
  what they hold, as the record budget charges them: they happened. A fork
  applies the limit, at the same points, to the effects it performs or
  answers itself (live GETs, foreign copies, stubs, simulators, calls into
  its own callees), so an identity replay decides as production did.
- **`EFFECT_BYTES_EXCEEDED`** (413, M1): the catalog's hint is to raise the
  kind's limit, move large bodies into blobs (streaming), or split the work.

## Alternatives

- **Fuel for effect bytes.** Fuel bounds computation; charging bytes to it
  would change every recorded turn's fuel and the identity of replays.
- **Trapping the turn, as `TURN_TOO_LARGE` does.** The record budget traps
  because a record that does not fit cannot be written at all. Here the
  turn's record is fine; the guest can handle a failed effect and carry on
  (fetch the rest in the next turn), so the effect fails, not the turn.
- **A new `EffectStatus` or WIT error case.** A new fetch error case would
  change the actor ABI; the existing `too-large`, `failed` and `denied`
  carry the meaning, and the code is in the recorded error.
- **Applying the limit to recorded results in forks.** It would make an
  identity replay or an upgrade check of turns that an earlier release
  recorded past 32 MiB diverge, though nothing changed.

## Consequences

- One turn writes at most about `effect_bytes_per_turn` plus one record
  limit to the log (its turn record), instead of about twice the record
  limit. The record budget (ADR 0130) still applies within it.
- Large exchanges move to blobs or several turns; the limit is per actor
  type, so an operator can raise it where a kind needs more.
- A `call` near the end of the effect bytes is refused when what is left is
  less than its request plus the callee's message size, even when its reply
  would have been small: the reply is not known before the callee runs.
- A fork's own calls are subject to it, so an identity replay of a turn an
  earlier release recorded with more than the limit's worth of effects
  before a `call` may differ; fetches served from the recording do not.
- Verified by unit tests of the count and the limit, scheduler tests (a
  response past it is sent and not recorded, a request past it is not
  sent, earlier effects count, the boundary is exact, the failure survives
  a restart), and an identity replay over such turns in both modes.
