A policy rule with the action `deny` matched the proposal's behavior diff. Policies are CEL rules against the diff (`kronik.diff/v1`), the strictest outcome wins, and a denied proposal goes back to its author.

Typical causes, with the default rules: the change introduces new errors (`no-new-errors`), fuel at p99 regresses (`fuel-regression`), or payments are covered only by a sample (`payments-full-coverage`).

To fix it, read the diff, change the code and propose again. To see the rules and test them against the proposal:

    kronik diff show p-7h3k --md
    kronik policy show
    kronik policy test rules.toml --proposal p-7h3k

See also: `proposal`, `behavior-diff`.
