The turn trapped, ran out of fuel or returned a `handler-error`, and a failed turn record was written with the input, the effects that already happened and the error. Its buffered state writes, SQL changes, messages and timers were discarded, but compensation messages for successful calls (M2) are delivered, and external effects that already happened stand. There is no automatic retry, since the outcome would then depend on time. An HTTP client gets 500 with this code and the turn id (also in the `Kronik-Turn-Id` header), and a failed message or timer ends up in dead letters. Deploy gives this code when `describe` traps.

To fix it, find the cause in the turn's error, fix the code (for a kind with history, through propose and promote from M3), and resend the failed input:

    kronik history billing/acme
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: `turn`, `dead-letters`, `FUEL_EXHAUSTED`.
