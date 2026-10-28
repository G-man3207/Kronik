A proposal is the result of `kronik propose`: a fork, a replay of real root inputs through the new code, a behavior diff and a policy outcome. It carries `verified_through_lsn`, the last LSN in main whose root inputs have run through its code. The policy lets it through, requires an approval (`kronik approve`) or denies it. `kronik promote` first runs catch-up on the traffic since the proposal, evaluates the policy again on the whole diff, and then switches the code. A proposal is a fork with a diff.

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"
    kronik diff show p-7h3k --md
    kronik approve p-7h3k --reason "..."
    kronik promote p-7h3k --reason "..."

See also: `behavior-diff`, `grounding`, `fork`.
