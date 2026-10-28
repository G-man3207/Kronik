The execution id is the host's internal id for one execution of a turn. It ties together the turn's `TurnBegin` and `EffectResult` records (written from M2) and its turn record, which the log interleaves with records of other actors. Guest code never sees it; it uses the causal id instead.

See also: `causal-id`, `turn`.
