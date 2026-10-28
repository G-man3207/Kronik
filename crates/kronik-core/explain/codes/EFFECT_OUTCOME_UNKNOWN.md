The turn made an external effect against an `unsafe` target, and Kronik crashed before the result was recorded. Kronik never promises exactly-once towards the outside world (I17) and does not redo an `unsafe` effect, so it cannot know whether the effect happened. The guest got `outcome-unknown` for the effect and did not handle it, so the turn failed. The input is in dead letters together with the request, and an HTTP client gets 500 with this code and the turn id.

To fix it, check in the target system whether the effect happened, for example whether the charge exists. Resend the input only if it did not:

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "the charge was not created"

If the target honors `Idempotency-Key`, grant it with the delivery class `idempotency-keyed`: Kronik then redoes such effects after a crash with the same key. Kronik cannot check that a target really honors the key.

    kronik grant billing http:payments.internal --delivery idempotency-keyed --reason "the API honors Idempotency-Key"

See also: `delivery-class`, `dead-letters`.
