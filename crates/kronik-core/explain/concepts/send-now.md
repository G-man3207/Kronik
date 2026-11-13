`connections.send-now` sends a frame during the turn instead of after it commits (M24), for intermediate results such as the tokens of a streamed answer. It is an effect with the delivery class `unsafe`: it needs the capability `connection:send-now`, its turn's `TurnBegin` is durable before the frame goes out, and its result is recorded before the guest sees it. `ok` means the frame was handed to the connection in order, not that the client received it; `closed` means it was not sent. After a crash a re-run never sends it again: the guest gets `outcome-unknown`, and a turn that does not handle it fails with `EFFECT_OUTCOME_UNKNOWN`. A stream can reach the client before its turn fails: that is the price of streaming. Use `send` for final notices, such as "payment complete".

    kronik grant chat connection:send-now --reason "stream the bot's answers"

See also: `connections`, `effect`, `delivery-class`, `EFFECT_OUTCOME_UNKNOWN`.
