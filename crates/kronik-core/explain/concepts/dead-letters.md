Dead letters are inputs whose turn failed. Failed messages end up there, and from M2 so do timers, uncertain effect outcomes and compensations that fail. They show up in `history` and in `kronik dead-letters list`. There is no automatic retry, because the outcome would then depend on time; `kronik dead-letters resend` creates a new root input instead.

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: `turn`, `root-input`, `TURN_FAILED`, `EFFECT_OUTCOME_UNKNOWN`.
