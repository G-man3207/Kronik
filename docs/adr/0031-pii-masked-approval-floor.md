# 0031. A diff with pii-masked turns needs an approval: a floor in code

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

The brief (Privacy mode, "Forks utan PII") says that a fork for a token
without `pii:read` runs on pseudonyms, and that turns whose logic depends
on real values may diverge and are marked `pii-masked` in the diff. Since
the v0.1 re-review, such a turn no longer counts as an introduced error,
an origin or a consequence, so pseudonyms alone don't make the default
`no-new-errors` rule deny unchanged code.

That made masking hide real regressions. In privacy mode, every handler
whose input has a subject runs on pseudonyms in an agent's proposal. A
proposal whose `get` was broken showed `errors.introduced 0`,
`divergent_turns 0` and `pii_masked 8`, and the policy outcome was
`allow`. The operator promoted it without an approval, and real GETs then
failed. The same code proposed with `pii:read` was denied (introduced 4).
A run on pseudonyms cannot tell broken code from correct code, so its diff
is not evidence that the code works.

## Decision

- `RuleSet::evaluate` ends with a floor. When `summary.pii_masked > 0`, it
  adds the fired entry `pii-masked-needs-approval` with action
  `require_approval` and a `reason`: "N turns could not be verified
  without personal data; re-run the proposal with a pii:read token to see
  their real behaviour". The outcome is therefore at least
  `require_approval`, and a rule's `deny` stays `deny`.
- The floor is code, not a CEL rule in `DEFAULT_RULES_TOML`. A `policy set`
  replaces the rules, and it must not be able to drop the floor. The
  brief's six default rules stay as written; the floor sits next to them.
- Every evaluation goes through it: the proposal's own evaluation,
  promote's re-evaluation after catch-up, and `policy test`.
- `Fired.reason` is optional and additive: rules have none, and older
  evaluations parse.
- The floor also counts `summary.pii_unverified`: turns of a kind whose
  code changed that read a pseudonym and came out identical to
  production. A regression that fails only on the real value could hide
  in such a turn (a timer or message turn with no output). It fires on
  `pii_masked + pii_unverified > 0`. An identity replay changes no kind,
  so it has no such turns.
- `summary.pii_masked` and `summary.pii_unverified` are always written,
  0 when there are none, so a custom rule can read them without `has()`.
- The outcome is shown wherever a human or an agent reads it:
  - the CLI's policy lines show the reason and a `PII-masked` line;
  - the Markdown diff has a summary row;
  - MCP tools return the summary, and their `next` approval command
    carries a shell comment;
  - an approval request's command carries the same comment.

## Consequences

- An agent's proposal in privacy mode needs a human's approval whenever a
  subject's traffic was replayed. The human can check the real behaviour
  by proposing the same code with a `pii:read` token.
- A proposal without masked turns is evaluated as before.
- A rule set can't relax the floor; only the code can.
- An approval keeps holding when promote's catch-up grows the masked
  count without a stricter outcome. This is the existing approval rule: a
  new approval is needed only for a stricter outcome or new changed
  targets. So whoever approves should know that the count can grow
  before the switch.
