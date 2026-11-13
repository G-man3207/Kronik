Everything a turn records must fit in one log record of at most 128 MiB: its input, the request and result of every external effect and `call`, its state writes, messages, timers, SQL changes and schema changes, compensations and its output. This turn would have needed more, so it failed instead of writing a record that later reads could not accept. Nothing it buffered was committed (state writes, SQL changes, messages, timers), compensation messages for successful calls are delivered, and external effects that already happened stand and are recorded. A failed message or timer is in dead letters. This code is the error code of the failed turn in `history` and in dead letters; an HTTP client gets `TURN_FAILED`, as for `FUEL_EXHAUSTED`. When the turn also had an effect whose outcome is unknown, its code is `EFFECT_OUTCOME_UNKNOWN` instead and its message says that the record was too large. The limit is the same on every node, so the same input fails the same way again.

A turn that an earlier release began and that was still open when this release started can have an input that this release's budget does not hold. It is not run again: its re-run closes it with this code, under its own execution id, so that it does not stay open.

The turn fails at the effect that no longer fits, before that effect happens, or when it ends and its state writes, messages, SQL changes and output do not fit. An HTTP response that is larger than what is left of the turn's record is cut off like one over the actor type's `effect_response_bytes`: the guest gets `too-large` and may go on.

Typical causes: many large HTTP responses in one turn, a loop that writes many large state values or sends many large messages, or one SQL transaction that changes a great many rows.

To fix it, split the work over several turns, for example one message per page of a large download, and keep large data out of a single turn:

    kronik history billing/acme

See also: `turn`, `dead-letters`, `FUEL_EXHAUSTED`, `PAYLOAD_TOO_LARGE`.
