# 0130. A turn's record fits in one log record

- **Status:** Accepted (2026-11-13), amended 2026-11-14 and 2026-11-15
- **Date:** 2026-11-13

## Context

The log format's contract is that no record body exceeds `MAX_RECORD`
(128 MiB), and readers refused larger entries. Nothing enforced it on the
write side: a turn's scrubbed output alone could reach the limit, and its
effects, SQL changesets and schema changes and compensations came on top,
as did each `EffectResult`. A committed record over the limit made
`history` answer `STORAGE_CORRUPT`, and after an unclean stop the start
cut the acknowledged, applied record off as a torn tail and then could not
start (issue #26). Effects are not charged fuel, so one turn could write
hundreds of MiB.

The brief requires a turn's outputs to be committed together with one
record (atomic local commit), every effect to be recorded before the guest
sees it, the log to stay readable across releases (I16) and turns to be
deterministic (I1), so the same limit must be decided the same way in a
re-run and in a fork's replay.

## Decision

- **One budget per turn** (`kronik_sched::record_budget`): the record
  limit less a 4 KiB reserve, which holds what differs between a run and
  its replay (execution id, engine version, durations), a failed outcome
  and a `StateRebase` wrapper. Everything a turn records is charged: its
  input (plaintext form), each effect as the gate records it, its
  compensations, writes, messages, timers, SQL changes and schema, and its
  outcome. Every value counts 64 bytes more for sealing, whether or not
  privacy is on.
- **Effects are refused before they happen.** A new effect whose request
  and a result without a body (4 KiB) do not fit traps the turn with the
  new code `TURN_TOO_LARGE`. An HTTP response is read only up to what is
  left (`too-large` for the guest, as over `effect_response_bytes`); a
  `call` reply over it is withheld, as one over `effect_response_bytes` is.
- **The end of the turn** turns a record over the budget into a failed
  `TURN_TOO_LARGE` turn: input, effects and compensations stay, the rest
  goes. The gate kept the effects within the budget, so it fits and closes
  the turn's `TurnBegin`. (A record a release before 0.5 began is the one
  exception: see the amendment of 2026-11-15.)
- **`TURN_TOO_LARGE`** (500, a host trap like `FUEL_EXHAUSTED`, so an HTTP
  client gets `TURN_FAILED`) is a new code: `PAYLOAD_TOO_LARGE` is defined
  as a refusal before any turn ran, and the turn here did run.
- **The log refuses** a body over the limit (`LogError::TooLarge`): nothing
  written, no LSN used, the writer goes on. Readers accept a complete entry
  with a valid CRC whatever its length (records earlier releases wrote);
  a length never sizes a read past the file. The start passes `state.db`'s
  applied LSN to the log, which never truncates an entry at or below it:
  a damaged acknowledged record is `STORAGE_CORRUPT`.

## Alternatives

- **Only a check before the append.** It would turn data loss into a lost
  turn with an open `TurnBegin`, and effects would already have happened
  that no record could hold.
- **A per-turn cap on effect bytes.** It would bound log growth per turn
  below twice the record limit, but needs a new `Limits` field, CLI and API
  surface: a separate maintainer decision.
- **A larger `MAX_RECORD` or a new format.** Records would still have no
  bound, and older readers would refuse them.
- **Reusing `PAYLOAD_TOO_LARGE`.** Its catalog meaning is a request refused
  before any turn ran.

## Consequences

- No record over the limit is written again; one already written reads
  again, and a start never cuts off what `state.db` applied.
- A turn writes at most about twice the record limit to the log.
- A fork applies the same budget at the same points, so identity replays
  stay empty; a turn of a release before 0.5 that went over the limit may
  replay as `TURN_TOO_LARGE`.
- Verified by `kronik-log` unit tests (refusal, reading and not truncating a
  complete over-limit record, the acknowledged-record rule), scheduler tests
  with a small test-only limit, and an identity replay over such turns.
- Revisit with the per-turn effect cap, or when blobs (M26) move large
  bodies out of the record.

## Amendment (2026-11-14): the per-turn effect cap

The alternative "a per-turn cap on effect bytes" was decided (issue #74):
[ADR 0145](0145-effect-bytes-per-turn.md) adds the per-kind limit
`effect_bytes_per_turn` (32 MiB by default). An effect that would pass it
fails with `EFFECT_BYTES_EXCEEDED`, recorded as its result. One turn now
writes at most about that limit plus one record limit to the log.

## Amendment (2026-11-15): a legacy compensation goes before the effects

The Decision above says the failed record "fits and closes the turn's
`TurnBegin`". That is true for a record this release assembled, because the
gate charged every effect and compensation while it filled the budget. It
was not true for the re-run of a `TurnBegin` an earlier release wrote
(issue #87). A pre-0.5 turn could record one compensation message per
successful `call`, and nothing charged them; on a re-run `fail` copied every
recorded compensation into `record.compensations`, after which `strip`
cleared only the effects' requests and responses and then the effects. If
the compensations alone were over the budget, the failed record stayed over
`MAX_RECORD`, the log refused it (`LogError::TooLarge`), no `TurnRecord`
closed the begin, `open_turns` kept the row, and every start ran the turn
again. `open_turn_pin` then kept its segment from retention for ever, so
compaction stopped and the log grew until the disk reserve refused writes.
The `Fit::Over` doc comment's premise — that the overrun is within the 4 KiB
`TURN_RESERVE` — had the same provenance: nothing bounded a legacy
compensation, or a legacy input.

The maintainer decision recorded here:

- **The input stays.** Every failed record keeps its input. It is the
  request that caused the turn, the log format and its validator require
  it, and the applier reads it for dead letters and connection inputs. A
  closing record without an input, or with a reference to the begin's, is a
  format change and is not part of this amendment.
- **The last-resort order** in `strip`, after each step is re-measured:
  first the requests and responses of the effects; then the compensations;
  then the effects themselves. Only the input is never left out.
- **A compensation left out makes its call's committed change an orphan.**
  Its `EffectResult` record stays in the log, so the call and the callee's
  committed change remain visible, but no compensation is delivered for it,
  in the record or from the node's in-memory list; a callee that never
  committed leaves nothing to compensate. When the effects stay in the
  closing record (the common case, where the input fits the turn budget), the
  applier lists the call as an `orphans` row with no compensation id — the
  design's existing fallback for a successful call with no compensation.
  When only the input fits, the effects go too and there is no closing effect
  for the applier to list: the call's `EffectResult` stays in the log and the
  callee's change stands, but `kronik history --orphans` does not name it.
  The outcome message says `; its N compensations are not recorded: their
  calls are orphans`, and, if that rung was also reached, the existing effects
  note follows it.
- **`Fit::Over` means the input alone.** After the ladder, `Over` is
  returned only when the record without its effects and compensations is
  still over the turn budget. The caller may append it only if it is within
  the log's own record limit (`MAX_RECORD`, `TURN_RESERVE` more than the
  budget); `close_open_turn` says so, and whether the turn can be closed,
  in its log line. A 0.5 release never writes such an input: a new input
  over the budget is refused before the turn runs (`PAYLOAD_TOO_LARGE`),
  and a re-run of an earlier one is closed before its guest runs. Only a
  pre-0.5 data directory whose ingress accepted an input over 128 MiB can
  hold one. Such a turn still cannot be closed by this format — there is no
  closing record without the input — and the amendment does not pretend
  otherwise; a future format change would have to make the input optional
  on a failed record, or cite the `TurnBegin`.

Verified by
`record_budget/tests.rs::an_earlier_releases_compensations_are_left_out_last`
(2 effects, 2 compensations of 40 KiB against a 60 KiB limit: `Stripped`,
the compensations gone, the effects kept, each step noted in the outcome)
and `record_limit.rs::an_open_turn_whose_compensations_no_longer_fit_is_closed_not_rerun_for_ever`
(an open turn with a recorded 100 KiB compensation and a limit that holds
only its input: the closing `TURN_TOO_LARGE` record fits, `open_turns` is
empty, a second start runs nothing, no compensation is delivered, and a
retention pass deletes the begin's segment). The input-over-the-budget case
is still covered by `an_open_turn_whose_input_no_longer_fits_is_closed_not_rerun_for_ever`.
