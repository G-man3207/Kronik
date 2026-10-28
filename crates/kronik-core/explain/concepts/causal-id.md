The causal id is derived from the causal key. It is the same in production and replay, and it is the id that guest code gets from `causal-id` when it needs a correlation id. The host adds it, together with the execution id, to every log event.

See also: `causal-key`, `execution-id`.
