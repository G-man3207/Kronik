# 0161. A forked grounding row is a changed target for approvals

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

`kronik approve` lets a later diff after catch-up use an approval only if
every changed target of that diff was changed when the approval was given
([m3-fork](../design/m3-fork.md) §10). A non-exact grounding row is such a
target, and so is every changed effect item.

A forked row is an answer from a copy of a foreign actor (ADR 0020): real
code and real state, but not production, and not necessarily the same
answer on the next replay. Before this ADR, `approve` and `reconcile`
recorded forked rows in the approval's `targets`, but `promote`'s
`changed_targets` counted only `approximate + synthetic`. A later diff
whose only new change was a forked row therefore used an approval that had
never seen that target. The same `kronik.diff/v1` document was read twice:
as untyped JSON when approving and as `diff::Diff` when promoting, with two
different rules.

ADR 0020 ranks forked with approximate, below exact, and the approval floor
exists so a human reviews every target whose evidence is below exact.

## Decision

An approval's targets are the diff's grounding rows with
`approximate + synthetic + forked > 0`, plus every changed effect item.
`approve`, `reconcile` and `promote` all compute this with
`changed_targets(&diff::Diff)`; `targets_of_value` is gone.

A later diff with a new forked-only target therefore needs a new approval.
Existing approvals already recorded forked rows in their `targets`, so no
record is rewritten.

## Alternatives

- **Keep forked out of changed targets.** That is fail-open: a copy's answer
  can change with time or background work between replays (ADR 0020), and
  an approval would vouch for an answer it never saw. It also records a
  target in `Approved.targets` that `promote` then ignores.
- **Keep both functions and change both rules.** The untyped walk and the
  typed one read the same document; one function cannot drift from the
  other.

## Consequences

Promote is stricter than before for a diff whose catch-up adds a forked
row, which is the intended review. Nothing else changes: exact rows are
still not targets, changed effects are still counted, and the approval's
diff hash is unchanged. The rule is pinned by
`a_forked_grounding_row_is_a_changed_target` on
`docs/design/fixtures/diff-forked-postgres.json`.

Revisit if forked answers become deterministic, or if they are reviewed
somewhere that already covers every later forked row.
