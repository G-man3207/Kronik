# 0109. Erased recorded input is unverifiable, not divergence

- **Status:** Accepted (2026-11-13)
- **Date:** 2026-11-08, amended 2026-11-13 (points 1, 3, 5, 7 and 8,
  issues #27-#29 and #49; points 1, 5, 7 and 9, #73)

## Context

`kronik privacy erase <subject>` destroys the subject's keys on purpose: the
values sealed for it cannot be read again, by anyone, ever (M8; ADR 0108's
amendment on sealed requests of erased subjects). The log is append-only, so
the turn that wrote those values keeps its record; only the sealed plaintext
text is gone.

An identity replay runs production's recorded code on production's recorded
inputs and compares the result with the recording. That comparison is only
meaningful when the guest and the replay can read the same input. After an
erasure they cannot: the recording holds ciphertext whose key is gone, the
replay sees the sentinel `[erased]`, and the guest computes something else
from it. S-16 (v0.4.1) made this a gate failure. In the observed case a turn
with an `http.fetch` whose request was sealed for `user:1` replayed the
sentinel as a URL, could not decode the recorded request, fell through to a
synthetic `Denied(replay: no recording)`, so the guest failed a turn that
production had committed, the diff counted the recorded effect as removed,
`upgrade.rs` computed `passed = !summary.changed` and
`ENGINE_UPGRADE_DIVERGED` refused the upgrade. `serve` then refuses the data
directory as well, because it reads the same report. The v0.4.1 workaround -
one new turn, then a check with a window shorter than the gap to the erased
turn - only moves the fork point past the erased turn; the trap returns for
the default six-hour window, for a restore, or for any operator who does not
know the workaround, and the erased turn is silently *not verified* rather
than reported.

Two properties make the erased case decidable. The erasure is deliberate,
audited and operator-requested, never a corrupt-key surprise. And what
remains is a recording of the outcome: the guest's input, effect request and
effect response are gone, but the recorded effect result (status, response
bytes, error) is retained under whatever subject it has, usually none. For
the turn that met an erased value, "the recording is the truth" is the only
truth left.

## Decision

An erased recorded value makes the turn that met it **unverifiable**, not
divergent. Identity replay and `kronik upgrade check` treat it that way:

1. **Carry the bit.** `ForkPrivacy` exposes whether a `Sealable` opens
   `Erased`; `ProductionIndex::reveal` records, before replacing the value
   with `[erased]`, the turn LSNs whose guest read an erased value - in its
   recorded input or in an effect's request or response - and the effect
   ordinals whose recorded request is erased. A turn whose erased values
   are all among its own outputs is point 9's. An erased state value is not
   replaced: it stays sealed, so the fork's store holds it unreadable, as
   production's did until its erasure. `ForkState` reads it as absent and
   records the read, also for a value written inside the replayed log
   (issue #49). The replay marks such a turn (`ForkTurn::erased`).
2. **Serve the recording.** At the marked effect ordinal of such a turn the
   effect gate does not decode or re-derive the recorded request and does not
   compare fingerprints; it pushes the recorded effect and returns the
   recorded outcome, grounding `exact`. Only `http.fetch` and `foreign.http`
   are served this way: at an erased ordinal of another effect kind the guest
   asked for something else and the difference is real.
3. **Do not count it.** A turn that met erased data is classified
   `unverifiable`, and its differences - effects, response, errors, outcome,
   the state and SQL rows it wrote, its fuel - are not counted as changes. A
   production turn missing below it (a message, call or timer the erased
   value decided) is `unverifiable` too: neither a divergent turn nor an
   origin or a consequence, and its effects and writes are not changes
   either (issue #28). Every other difference keeps the existing fail-closed
   treatment.
4. **Only pii-masked exclusion is wider.** `DiffSummary.changed` no longer
   includes `pii_masked`: a proposal whose only differences are turns that
   read pseudonyms also does not change observable behaviour. ADR 0031's
   approval floor still reads `pii_masked` (and `pii_unverified`), so such a
   proposal still needs an approval; `changed` is not the floor.
5. **Report it.** `DiffSummary.unverifiable` and the upgrade report's
   `unverifiable` count the turns of points 1, 3 and 7, each causal key
   once, whether they differ or not. `kronik upgrade check` shows the
   count right under its verdict, also when it is 0 (`Unverifiable  N turns
   met erased data and were not verified`), and `--json` always carries it
   (the upgrade report schema stays `kronik.upgrade-check/v1`; the field is
   additive and defaults to 0 for reports written by older binaries). A
   check passes when the only differences are unverifiable turns, and still
   exits 1 with `ENGINE_UPGRADE_DIVERGED` when any verified difference
   remains.
6. **Fail closed when the outcome is gone.** Serving a recording needs a
   readable recording. An erased request whose recorded outcome is also
   unreadable is not silently accepted: the check reports the error and
   does not pass. The erasure excuses the input, not the evidence.
7. **Follow what the erased data shaped** (issue #29). A turn meets erased
   data not only through its own recording. It is `unverifiable` as well
   when, at its production position:
   - an unverifiable turn sent its message, call or timer, and its input
     differs from what production's counterpart received, or production has
     none;
   - it reads a state key, lists keys or asks whether a timer is pending
     where an unverifiable turn left the state different from its production
     counterpart's, or where a production turn missing below one wrote. Such
     a mark lasts until a verified turn writes that key again, or, when only
     one subject's values are involved on both sides, until that subject's
     erasure deletes them on both sides. A turn that reads a marked key is
     unverifiable itself, so its write marks the key again instead of ending
     the mark: a key that turns read and write back (a counter, any
     read-modify-write chain) stays marked to the end of the window, and
     every turn that reads it is unverifiable, unless a verified turn writes
     it without reading it first or, with one subject's values only, that
     subject's erasure comes. A mark that involves a value of no subject or
     of several ends only with such a write;
   - it uses the SQL database of an actor that an unverifiable turn (or a
     production turn missing below one) left different, or whose replay
     skipped an erased subject's changeset while production still had those
     rows, before that subject's `Erasure`. A database is the unit: any SQL
     use counts, whatever table it touches. Only a changeset recorded by an
     engine before Kronik 0.5.0 can hold rows of a table without `_subject`
     (from 0.5.0 on a subject's turn cannot write one, ADR 0005 §6 option B),
     and an erasure does not delete those: when the database has such a
     table, a gap or mark from such a changeset lasts to the end of the
     window. From any later engine's changeset, the erasure ends it;
   - it calls a turn that is unverifiable.
   These marks only classify: they never change what a guest reads. The
   price is the same as point 3's: a real change in such a turn is reported
   as unverifiable, not as a difference.
8. **Follow the erasure.** Continuous replay applies production's `Erasure`
   records at their place in the window, as isolated replay's production
   cursor does: the fork's state loses what production's lost there, so a
   later turn reads what production's read and the final states compare
   (state written before the window and erased inside it is no difference).
9. **Outputs alone.** A turn whose guest read no erased value - its input and
   its effects are intact - but whose own outputs (state writes, messages,
   timers, its reply, SQL changes) hold values of a subject erased since is
   replayed and compared like any other turn. Only that subject's values
   are left out: they are masked as `[erased]` on both sides, because
   production's cannot be read again. A real change elsewhere in the turn -
   its reply, its other values, its effects, its outcome - is a difference.
   Its writes leave no mark of point 7: the replay computed them from intact
   inputs, so a reader that then differs shows a real change. A change
   confined to the erased subject's values is not seen; there is nothing
   left to compare it with.

**Ruling.** The maintainers ruled on 2026-11-13: the upgrade gate passes when
the only differences are unverifiable turns (point 5), with the unverifiable
class narrowed to what an erasure explains (points 7 and 9, #73), and the
count shown prominently in the human and the `--json` output.

## Alternatives

- **Keep the v0.4.1 hint and workaround.** No code change, but the default
  six-hour check keeps failing on exactly the directories the erase feature
  is for, `serve` keeps refusing them, and the passing short-window check is
  a pass that never looked at the erased turn - worse than the explicit
  "unverifiable" count.
- **Treat `[erased]` as the request.** The sentinel is not the request; two
  different erased requests are indistinguishable, and any guest that
  branches on the value can match by accident. Unsound as verification, and
  it keeps the synthetic denial.
- **Count `pii_masked` as changed and only exempt erased turns.** A masked
  turn is already defined as one the fork did not run on real data; keeping
  it in `changed` would still fail a no-PII proposal's identity check for no
  observable change.
- **Keep the decoy key (or the sealed value) on erase.** Erases the privacy
  guarantee: the point is that the plaintext is gone for everyone, including
  future binaries.
- **Skip erased turns entirely (do not replay them).** Cheaper, but hides
  how the rest of the window behaves around their effects and consequences;
  replaying them from the recording is what makes the turn's children and
  responses comparable.
- **Serve the recording for state too** (apply an unverifiable turn's
  recorded writes to the fork's store instead of the guest's). Later turns
  would read production's values, but the fork's state would no longer be
  what its code computed (a proposal's or a rollback's), production turns
  missing below the erased turn would still leave gaps, and an erased
  subject's skipped rows still could not be rebuilt. The marks of point 7
  classify instead and leave execution as it was.

## Consequences

A v0.4.0 (or older) directory on which a subject was erased can be upgraded
to v0.5.0 with the default check, and then served: the passing report still
records how many turns it could not verify, and the operator can see them
(`--json`, `unverifiable`). A check that fails after v0.5.0 has found a real
difference or an unreadable recording, not an erasure: the turns an erasure
reaches are the ones points 1, 3, 7 and 8 classify - the turn that met an
erased value, everything below it that production ran and the replay did
not, and every turn that read what those left different or what the replay
could not rebuild without the erased rows. A turn that only wrote an erased
subject's values is compared except for those values (point 9). The old
workaround paragraph stays
in the operations guide for v0.4.1 and older binaries.

The erased turn's *behaviour* is not verified, only the recording is trusted:
if the guest's change makes it take a different path on `[erased]` and the
recording still answers, the check reports the turn unverifiable instead of
diffing it. The same holds for every turn point 7 reaches, which can be many
when a shared actor's state or database is involved: an SQL database stays
unverified for the rest of the window once an unverifiable turn changed rows
of no subject (or of one that is not erased) in it, and so does a state key
that turns read and write back (point 7). That is the price of passing, and
it is reported, not hidden. Erasure also no longer voids the
upgrade gate, so an operator can erase before upgrading without knowing the
workaround.

No format, WIT, engine-id or public-API break: the diff summary and upgrade
report gain an additive field (`#[serde(default)]`), the CLI's `--json` gains
the same optional field and its human output a line only when it is non-zero.
ADR 0108's rules 8-11 are unchanged; this decision reads the same erasure
signal one layer up.

Revisit if per-turn erasure metadata is ever recorded (the index scan could
then be skipped), or if a real change is ever found hiding inside a turn
reported unverifiable - the count's usages then grow a per-turn diff.
