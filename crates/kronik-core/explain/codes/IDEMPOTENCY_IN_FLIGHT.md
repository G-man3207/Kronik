A request repeated an `Idempotency-Key` while the original request with that key was still running. The repeat waited for the original until the gateway timeout and then got this code. The original still completes.

To fix it, retry later with the same key and the same request. Once the original has committed, the repeat gets the stored response and creates no new turn. Keys are stored per actor, for 24 hours by default.

See also: `GATEWAY_TIMEOUT`, `IDEMPOTENCY_KEY_REUSED`.
