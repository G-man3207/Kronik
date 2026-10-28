The delivery class says how a target tolerates retries, and it is set when the target is granted: `replay-safe` (the call can be redone without consequences), `idempotency-keyed` (the target respects `Idempotency-Key`) or `unsafe`. After a crash without a recorded result, the first two are redone with the same idempotency key, and an `unsafe` effect is not: the guest gets `outcome-unknown` (I17). The default is `replay-safe` for GET, HEAD and OPTIONS and `unsafe` for everything else. The class is the operator's claim about the target; Kronik cannot check that a target really respects idempotency keys.

    kronik grant billing http:payments.internal --delivery idempotency-keyed --reason "..."

See also: `capability`, `EFFECT_OUTCOME_UNKNOWN`.
