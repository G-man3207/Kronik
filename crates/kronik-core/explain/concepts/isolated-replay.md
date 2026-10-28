Isolated replay runs each root input against production's state at its own LSN, in an overlay that is discarded afterwards, so that a difference cannot contaminate the next root input. It is the default for the main part of the diff. Root inputs run in parallel, and the results are merged in LSN order. For large windows it can run on a deterministic sample, for example `--sample 10%`, and the coverage shows in the diff.

See also: `continuous-replay`, `behavior-diff`.
