# 0130. A turn's record fits in one log record

- **Status:** Proposed
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
  the turn's `TurnBegin`.
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
