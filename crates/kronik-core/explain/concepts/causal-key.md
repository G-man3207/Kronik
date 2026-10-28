A causal key is the root input's id plus the path of actor and outgoing ordinal up to a turn. From M3 it pairs up turns in production and in a fork: a fork turn matches a production turn when their causal keys are equal, and a matched turn reuses the recorded logical time and seed. The causal id, message ids and, from M2, the idempotency keys of effects are derived from it.

See also: `causal-id`, `root-input`, `grounding`.
