# 0020. Grounding `forked`: answers from a copy of a foreign actor

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M14: "Svar från en kopia märks `forked` i förankringen, en egen nivå mellan
exakt och syntetisk." The diff grades every effect of a fork (m3-fork §5.3):
`exact` (production's recorded answer to the same request), `approximate`
(production's answer to another request of the same target), `synthetic`
(a simulator or fail-closed) and `live` (an allowlisted GET). An answer
from a copy is real, from the actor's own code and state, but from a state
that may differ from production's (time, background work, calls with an
unknown outcome) and not deterministic. `kronik.diff/v1` is a published
format with `additionalProperties: false`; policies read it.

## Decision

- `Grounding` gains `GROUNDING_FORKED = 5` (`proto/kronik/log/v1/turn.proto`).
  Old records never hold it; old readers are not required to read new logs
  (I16).
- In the diff, grounding rows and the summary gain `forked` (always written;
  not required by the schema, so diffs written before M14 validate and read
  as 0); effect items can say `forked`; `confidence` stays exact over all.
  `options.foreign` records, per `sandbox` actor, the checkpoint used and
  the replayed calls, or why the actor stayed `recorded`.
- The order of trust is exact, then approximate and forked, then synthetic.
  An actor with a copy gets no approximate answers: a changed request is
  answered by the copy, because production's answer to another request is
  the wrong data for a changed query. In `both` mode the diff therefore
  takes the effects to such an actor, and the responses of the root inputs
  that call it, from the continuous view, where the copy answered.
- Policies see `t.forked`. The default rules are the brief's and stay as
  they are: forked answers lower `confidence` (exact over all), so
  `low-grounding-needs-approval` sees them; an operator who wants copies of
  a target reviewed adds a rule on `t.forked` (`has(t.forked)` keeps such a
  rule working on diffs from before M14).
- `trace`, `history` and the turn JSON label such effects `forked`.
- Compatibility fixtures: an `EffectRecord` with `GROUNDING_FORKED` and a
  `ForeignActor` with `fork_mode`, and a policy fixture with `forked`.

## Alternatives

- **Reuse `approximate`.** It means production's answer to another request;
  a copy's answer is a different kind of evidence, and policies need to
  tell them apart.
- **Reuse `live`.** Live answers come from the real target; a copy never is.
- **A `simulator` label on synthetic** (M12). A copy is not a simulation of
  the target from recordings or contracts; grading it synthetic would put
  real answers next to fail-closed denials.

## Consequences

- Policies written for M3 to M13 keep their meaning; a rule that should
  cover copies names `forked`.
- A diff with `forked` answers may change between replays of the same fork
  where a copy's answer depends on time or background work: the
  `kronik.diff/v1` promise "the same fork, code and options give the same
  bytes" excludes them, and the schema says so.
