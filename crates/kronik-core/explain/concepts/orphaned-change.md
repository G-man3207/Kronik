An orphaned change is a change that a called actor committed in a `call` whose caller then failed without compensation. `call` is not atomic: the callee's turn stands. If the call carried a compensation message, Kronik delivers it exactly once to the callee; a compensation that itself fails ends up in dead letters, and the change counts as orphaned until a compensation succeeds. Orphaned changes show up in `kronik history --orphans` and, from M3, in the diff.

See also: `message`, `dead-letters`.
