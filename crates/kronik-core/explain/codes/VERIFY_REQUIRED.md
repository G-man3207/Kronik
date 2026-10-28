A direct deploy is allowed only for a new actor type without history. This actor type has history, so new code goes the golden path (M3): propose, review the behavior diff and promote. `--skip-verify`, which deploys without verification if the policy allows it, does not exist yet.

To fix it, propose the new code and promote it after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"
    kronik promote p-7h3k --reason "Apply EU VAT"

See also: `proposal`, `deployment`.
