# 0123. An erasure stops the plaintext already in flight

- **Status:** Accepted (2026-11-14)
- **Date:** 2026-11-13

## Context

`kronik privacy erase` deletes a subject's keys, commits an `Erasure` record,
and applying it deletes or tombstones the subject's rows in `state.db` and its
SQL rows (docs/design/m8-privacy.md §6). That covered what the log and
`state.db` hold, but not what the node holds in memory, or what it reads
back without looking at the erasure:

- A message a turn sent is delivered as an in-memory job that carries the
  plaintext the turn produced; the mailbox row is only read at a start. The
  same holds for the callee input of a call, a compensation and a request
  waiting in a queue.
- A turn that runs when the keys are deleted keeps running with the
  plaintext it read.
- In privacy mode `off`, the recorded effects of an open turn
  (`open_effects`) are plain and a re-run hands them to the guest; neither
  the erasure nor reseal touched them.

The input check before a turn only refused sealed values whose key is gone,
so all of these reached the guest after the erasure. When the turn committed,
sealing found no key for the subject and created a new one, "numbered after
any erased versions" (the keystore's rule for a subject that comes back), so
the erased data was sealed again under a readable key, while
`privacy status` reported the erasure complete (#72).

## Decision

Once `kronik privacy erase` returns, no plaintext of the subject from before
the erasure reaches a guest or is sealed under a new key version, and
`privacy status` counts what is still pending. An erasure does not wait for
running turns: it must not depend on how long other work takes.

1. **Provenance.** Every queued input and every running turn carries where
   its values came from: the node's erasure generation for what it holds in
   memory, the LSN that recorded it for what it reads back (a re-run's begin
   and recorded effects, a mailbox row, a timer). The generation increases
   when an erasure begins; each erased subject keeps the generation and the
   LSN of its erasure. A value of a subject erased after its provenance
   *predates* the erasure. A turn takes its provenance before its input is
   checked. Until an erasure's record is applied, the subject's rows are
   still in `state.db` and the actor databases, so what the node takes in
   meanwhile counts as born before that erasure.
2. **Check at hand-over.** Before guest code runs, an input with a value
   that predates its subject's erasure fails the turn with
   `SUBJECT_ERASED`, plain or sealed; a re-run's recorded effects count as
   its input. The turn's record holds the erasure's tombstone in place of
   each such value (an empty-nonce `Sealed` naming the erased version, which
   opens as erased whatever the keystore holds), and an open turn is closed
   under its own execution id.
3. **Seal with provenance.** Every record a turn writes - its `TurnBegin`,
   its effect results and its `TurnRecord` (or the record that closes it) -
   is sealed against the turn's provenance: a value that predates its
   subject's erasure becomes the tombstone instead of being sealed under a
   key version newer than the erased ones. Sealing and appending a turn's
   record take a fence shared; an erasure takes it exclusively from before
   its keys go until its record is applied. A turn's record is therefore in
   the log before the `Erasure` record, sealed under the version it erases,
   or sealed knowing of the erasure. A turn that runs across an erasure
   finishes, but nothing it records brings the subject back, and the
   messages, calls and compensations it sends carry the tombstones too.
4. **Scrub.** Applying the record tombstones the subject's values in the
   inputs still queued, and in `state.db` the erasure tombstones its values in
   `open_effects` as it does in timers and the mailbox; reseal rewrites
   `open_effects` with the effect results it rewrites.
5. **Count.** `privacy status` counts an erasure as pending while the log,
   `state.db`, or an input queued in this process holds a plain value of it,
   and while a turn that began before it was applied still runs.
6. **Forks.** A fork seals what it writes without creating a key version
   for an erased subject - its log, its samples, and the turns a rebase
   stages into main's log: such a value becomes the erasure's tombstone. A
   rebase that resumes compares its fresh replay with its log with those
   values as tombstones on both sides.
7. **SQL of a running turn.** A turn runs its SQL inside a savepoint, and
   its end rolls the savepoint back (its changeset is applied from its
   record). An erasure applied to an actor database while one of the
   actor's turns has its savepoint open ran its deletes inside it, so the
   turn's end rolled them back, and its session recorded them as the
   turn's own changes. The deletes now wait for the turn to end and run
   right after its savepoint is rolled back; until then the database's
   applied LSN stays below the erasure's, so a stop in between replays it.

A value that arrives after the erasure began (a new request of the subject)
is new data: it is sealed under a new key version, as before.

## Alternatives

- **Pause main's turns while the keys go** (as a privacy-mode change does).
  Simpler to reason about, but an erasure would fail whenever a turn runs
  longer than the pause allows, for example one waiting on a slow effect: a
  data subject's erasure must not depend on unrelated work. With provenance,
  the running turn finishes and its records carry tombstones.
- **Re-read the mailbox row when a job starts.** It covers delivered
  messages only, not calls, compensations, requests or running turns, and
  costs a read per turn.
- **Refuse new key versions for an erased subject altogether.** A subject
  may come back after its erasure (the keystore numbers its new keys after
  the erased ones); only plaintext from before the erasure must not be
  sealed again.

## Consequences

- A queued input that held a value of the subject from before the erasure
  becomes a `SUBJECT_ERASED` dead letter instead of running. So does a
  request of the subject that arrives while its erasure is being recorded
  (between the key deletion and the record's apply, milliseconds).
- An erasure waits for the turns that are appending a record (an fsync)
  before it deletes the keys, and turns that append meanwhile wait for its
  record to be applied.
- A turn that runs across the erasure has already seen the value: what it
  sends out in an effect before it ends, and its reply to the request that
  ran it, are not undone. What it records, and what it sends to other
  actors, holds tombstones.
- What a guest copies into a value of another subject, or of none, still
  survives the erasure (m8-privacy, "What erasure does not do").
- Verified by `crates/kronik-sched/src/erasure/node_tests.rs` (a turn running
  across an erasure and a message queued behind it; an open turn's recorded
  value in `off` mode across a restart), the store tests of `open_effects`
  and of an erasure during a turn's SQL, and the sealer test of a fork's
  record.
