# 0109. Erased recorded input is unverifiable, not divergence

- **Status:** Proposed
- **Date:** 2026-11-08, amended 2026-11-13 (points 3 and 5, issues #27
  and #28)

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
   ordinals whose recorded request is erased. `ForkState` records an erased
   state read. The replay marks such a turn (`ForkTurn::erased`).
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
   `unverifiable` count the turns of points 1 and 3, each causal key once,
   whether they differ or not, and `kronik upgrade check`
   prints `N turns unverifiable: erased` (the upgrade report schema stays
   `kronik.upgrade-check/v1`; the field is additive and defaults to 0 for
   reports written by older binaries). A check passes when the only
   differences are unverifiable turns, and still exits 1 with
   `ENGINE_UPGRADE_DIVERGED` when any verified difference remains.
6. **Fail closed when the outcome is gone.** Serving a recording needs a
   readable recording. An erased request whose recorded outcome is also
   unreadable is not silently accepted: the check reports the error and
   does not pass. The erasure excuses the input, not the evidence.

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

## Consequences

A v0.4.0 (or older) directory on which a subject was erased can be upgraded
to v0.5.0 with the default check, and then served: the passing report still
records how many turns it could not verify, and the operator can see them
(`--json`, `unverifiable`). A check that fails after v0.5.0 has found a real
difference or an unreadable recording, not an erasure; the old workaround
paragraph stays in the operations guide for v0.4.1 and older binaries.

The erased turn's *behaviour* is not verified, only the recording is trusted:
if the guest's change makes it take a different path on `[erased]` and the
recording still answers, the check reports the turn unverifiable instead of
diffing it. That is the price of passing, and it is reported, not hidden.
Erasure also no longer voids the upgrade gate, so an operator can erase
before upgrading without knowing the workaround.

No format, WIT, engine-id or public-API break: the diff summary and upgrade
report gain an additive field (`#[serde(default)]`), the CLI's `--json` gains
the same optional field and its human output a line only when it is non-zero.
ADR 0108's rules 8-11 are unchanged; this decision reads the same erasure
signal one layer up.

Revisit if per-turn erasure metadata is ever recorded (the index scan could
then be skipped), or if a real change is ever found hiding inside a turn
reported unverifiable - the count's usages then grow a per-turn diff.
