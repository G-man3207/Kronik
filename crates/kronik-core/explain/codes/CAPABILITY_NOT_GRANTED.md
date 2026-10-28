The actor type tried to use an effect against a target that has not been granted. Every external effect is denied until the operator grants a capability for that target (default deny, I6). The guest gets `denied`, and the attempt is recorded in the turn. Deploy also warns about requested capabilities that are not granted.

Typical causes:

- The capability was never granted, or it was revoked.
- The request goes to another target than the granted one, for example a different host.

To fix it, grant the capability to the actor type. Grants apply per actor type, not per hash, so they carry over to new code. `--delivery` sets the target's delivery class and `--rate` limits the call rate:

    kronik grant billing http:payments.internal --reason "billing charges invoices"

See also: `capability`, `delivery-class`, `effect`.
