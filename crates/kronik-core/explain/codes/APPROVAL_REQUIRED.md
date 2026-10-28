The policy outcome for the proposal is `require_approval`, and no approval covers its current diff. Policies are CEL rules against the behavior diff, and the strictest outcome wins.

Typical causes:

- A rule such as `payments-must-be-exact` matched, for example because payment effects changed.
- The proposal was approved, but catch-up at promote made the outcome stricter or changed new targets. An approval applies only to the diff it was given for, so a new approval is required.

To fix it, a human reads the diff and approves the proposal (from M5 this needs the `approve` scope), and then it is promoted:

    kronik diff show p-7h3k --md
    kronik approve p-7h3k --reason "reviewed the VAT change"
    kronik promote p-7h3k --reason "Apply EU VAT"

See also: `proposal`, `behavior-diff`, `grounding`.
