The data belongs to a subject that was erased with `kronik privacy erase`. Erasure deletes the subject's key, so its sealed values are unreadable everywhere: in the log, state, snapshots and shipped copies. Diffs and history show such values as `[erased]`.

This is permanent by design. Do not retry: the data cannot be recovered, and code that needs it must handle its absence.

See also: `subject`, `sealed-value`, `privacy-mode`.
