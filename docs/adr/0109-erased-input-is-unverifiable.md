# 0109. Erased recorded input is unverifiable, not divergence

- **Status:** Proposed
- **Date:** 2026-11-08, amended 2026-11-13 (points 1, 3, 5, 7 and 8,
  issues #27-#29 and #49)

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
   with `[erased]`, the turn LSNs whose recorded input, effects, writes,
   messages, timers or outcome contain an erased value, and the effect
   ordinals whose recorded request is erased. An erased state value is not
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
   once, whether they differ or not, and `kronik upgrade check`
   prints `N turns unverifiable: erased` (the upgrade report schema stays
   `kronik.upgrade-check/v1`; the field is additive and defaults to 0 for
   reports written by older binaries). A check passes when the only
   differences are unverifiable turns, and still exits 1 with
   `ENGINE_UPGRADE_DIVERGED` when any verified difference remains.
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
     erasure deletes them on both sides;
   - it uses the SQL database of an actor that an unverifiable turn (or a
     production turn missing below one) left different, or whose replay
     skipped an erased subject's changeset while production still had those
     rows: before that subject's `Erasure`, or at any time when the database
     has a table without `_subject`, whose rows an erasure does not delete (a
     subject's turn could write one before ADR 0005 §6 option B);
   - it calls a turn that is unverifiable.
   These marks only classify: they never change what a guest reads. The
   price is the same as point 3's: a real change in such a turn is reported
   as unverifiable, not as a difference.
8. **Follow the erasure.** Continuous replay applies production's `Erasure`
   records at their place in the window, as isolated replay's production
   cursor does: the fork's state loses what production's lost there, so a
   later turn reads what production's read and the final states compare
   (state written before the window and erased inside it is no difference).

**Status note.** The ruling on replay semantics that this decision depends on
was left open when the v0.4.1 release was decided; the recommendation there is
this text, and the implementation above is in place and gated. The ADR stays
Proposed, and the record that ships it (the v0.5.0 release notes) says the
behaviour is new rather than settled, until the maintainers record the ruling.

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
could not rebuild without the erased rows. The old workaround paragraph stays
in the operations guide for v0.4.1 and older binaries.

The erased turn's *behaviour* is not verified, only the recording is trusted:
if the guest's change makes it take a different path on `[erased]` and the
recording still answers, the check reports the turn unverifiable instead of
diffing it. The same holds for every turn point 7 reaches, which can be many
when a shared actor's state or database is involved: an SQL database stays
unverified for the rest of the window once an unverifiable turn changed rows
of no subject (or of one that is not erased) in it. That is the price of
passing, and it is reported, not hidden. Erasure also no longer voids the
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
