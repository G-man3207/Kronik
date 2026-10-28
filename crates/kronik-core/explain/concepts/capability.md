A capability is permission for an actor type to use an effect against a target, for example `http:api.stripe.com`, `http:*.example.com`, `foreign:payments` (M7), `secret:<name>` or `secret-reveal:<name>`. Every external effect is denied until the operator grants a capability (default deny, I6); without one, the guest gets `denied`. Grants are log records, apply per actor type rather than per hash, and give the target a delivery class and optionally a rate.

    kronik grant billing http:payments.internal --reason "billing charges invoices"

See also: `delivery-class`, `effect`, `CAPABILITY_NOT_GRANTED`.
