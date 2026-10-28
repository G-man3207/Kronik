The turn used up its fuel, the deterministic CPU budget per turn (50 million by default). The turn failed: nothing it buffered was committed, and a failed message or timer is in dead letters. This code is the error code of the failed turn in `history` and in dead letters; an HTTP client gets `TURN_FAILED`. Fuel is deterministic, so the same input fails the same way again.

Typical causes: an endless or very long loop, or work that is too large for one turn.

To fix it, make the handler cheaper or split the work over several turns, or raise the actor type's fuel limit (M2):

    kronik limits set billing --fuel 100000000 --reason "invoices with many lines"

See also: `turn`, `dead-letters`.
