The `Idempotency-Key` was already used for this actor with a different request. Keys apply per actor and are stored with the response for 24 hours by default, so one key stands for exactly one request.

Typical causes: a client that reuses keys, or a retry that differs from the original, for example a new timestamp in the body.

To fix it, send a retry that is identical to the original request, and use a new key for every new request.

See also: `IDEMPOTENCY_IN_FLIGHT`.
