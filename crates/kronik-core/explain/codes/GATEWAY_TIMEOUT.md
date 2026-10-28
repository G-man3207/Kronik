The gateway answers only after the turn commits. This turn took longer than the gateway timeout (30 seconds by default, `timeout` under `[gateway]`), so the client got 504, but the turn still completes. This code exists because a slow turn has neither failed nor been lost: the client must know that the request may still take effect.

To fix it, repeat the request with the same `Idempotency-Key`, if the original carried one: after commit the repeat gets the stored response, and while the original still runs the repeat waits for it. Without a key, check the actor's history before sending again, or the request may run twice:

    kronik history billing/acme

See also: `IDEMPOTENCY_IN_FLIGHT`, `turn`.
