# 0132. A fork's computation with a held linked secret is synthetic

- **Status:** Proposed
- **Date:** 2026-11-13

## Context

ADR 0112 lets an unmatched `crypto.*` of a fork compute on the host when
the grant's mode is `compute`. For a name linked to an external backend at
the fork point, the M23 design (§6) and ADR 0090/0091 allow only a value
that this process already holds for the fork point's link and that is still
authorized: a fork never fetches (I7). As implemented in 0.5.0-dev, the
fork read that value through the production cache's ordinary read path and
graded the computation `exact`, like a computation with a built-in name.

A review of the integration branch found two problems:

- The ordinary read path is not read-only. A fork's read of a value older
  than `[secrets] refresh` marked the name stale in production's cache, set
  `kronik_secret_stale{name}` to 1 and logged `secret used stale` (and later
  `secret fresh again`), although no production effect used the value.
- The computation is not reproducible. Whether the process holds the value
  depends on its memory: after a restart it holds none, and the same fork
  or proposal is then denied with `SECRET_UNAVAILABLE` and graded
  `synthetic`. A value held after a rotation is a later version than the one
  current at the fork point. An `exact` grade claims a grounding that the
  log does not give.

## Decision

1. A fork reads a held value through a separate, read-only lookup
   (`SecretCache::fork_value`): the value held for the current version of
   the fork point's link (backend, binding, reference and generation), only
   while it is operational, younger than `[secrets] max_stale` and not
   revoked by a definitive failure. It never marks a value stale, never
   changes `kronik_secret_stale` and logs nothing; it never reads the
   built-in store or retained scrub-only bytes, and never fetches.
2. A computation with such a value is graded `synthetic`, as a fork grades
   every answer that is not grounded in production's recording or in
   durable state. The guest still gets the computed result, so the turn
   behaves as it would with the key. The denial when nothing is held stays
   `synthetic` too, so the grounding counts and the confidence of a diff are
   the same whether the process held the value or not.
3. Nothing else changes: a fingerprint match returns production's recording
   (`exact`); a `recorded` grant denies an unmatched call with `replay: no
   recording`; a built-in name under `compute` is computed with the built-in
   store's current value and graded `exact` (ADR 0112); a preview computes
   nothing.

## Alternatives

- **Serve only the version current at the fork point, or the version that
  production's effect at the same ordinal recorded.** This matches ADR
  0090's "exact provenance" more closely, and avoids computing with a later
  version after a rotation. It does not make the diff reproducible on its
  own: the process may or may not hold that version (after a restart it holds
  none), so the grade would still have to differ from `exact`. The fork's
  index does not track which version was current at the fork point (version
  rows carry no LSN), so it also needs new plumbing. It can be added later,
  on top of this decision, without changing the grade.
- **Grade it `approximate`.** Approximate means that production's recording
  was matched with a tolerance; here no recording was matched.
- **Keep `exact` and document the dependency.** A grade that changes
  between two runs of the same diff is not a grade.

## Consequences

A proposal whose turns compute with a linked name has a lower confidence
than one whose turns are all matched or computed with built-in names, which
is what the operator should see. The value used is still the one the cache
holds now for the fork point's link: a later version after a rotation
without a relink (the gap the M23 design §6 documents, accepted for 0.5).
Production's stale tracking, metric and log describe production's effects
only. Verified by `a_fork_reads_a_held_value_without_marking_it_stale`
(kronik-sched) and by the daemon test
`a_fork_computes_a_linked_name_with_the_value_held_for_its_link_and_never_fetches`,
which checks the `synthetic` grade.
