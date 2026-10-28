A message is data to an actor: `name`, `content-type` and `body`, plus a `blobs` list that stays empty until M26. It comes from another actor, the operator, a timer or HTTP. `send` is buffered and delivered exactly once, but only if the sending turn commits. `call` (from M2) happens immediately: the callee runs and commits a turn of its own, and its response is recorded in the caller's turn. `call` is not atomic with the caller's turn, so it can carry a compensation message. Docs recommend `send` for changes and `call` for queries. Message is one of Kronik's five concepts.

Once tokens arrive (M5), an operator message to main needs the `operate` scope:

    kronik send billing/acme <message> --reason "..."

See also: `turn`, `orphaned-change`, `dead-letters`.
