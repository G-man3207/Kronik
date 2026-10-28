A root input is an input from outside: HTTP, an operator message or a timer (from M2) that existed before the fork point. From M3, replay runs main's root inputs through new code; internal messages are never taken from the recording but arise from the fork's code. Resending a dead letter creates a new root input, and a repeated HTTP request with the same `Idempotency-Key` for the same actor creates none.

See also: `causal-key`, `isolated-replay`, `dead-letters`.
