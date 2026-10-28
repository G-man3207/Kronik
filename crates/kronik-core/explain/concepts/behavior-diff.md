The behavior diff is the difference in responses, effects, state, errors and resources between production and a fork for the same root inputs. It is written as JSON (`kronik.diff/v1`) and rendered as Markdown, origins first: an origin is the first turn in a causal tree that differs despite identical input, and differences further down the tree are its consequences. Identity replay, the same code through the same history, must always give an empty diff.

    kronik diff show p-7h3k --md

See also: `grounding`, `isolated-replay`, `continuous-replay`, `proposal`.
