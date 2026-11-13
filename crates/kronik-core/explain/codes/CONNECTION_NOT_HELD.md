A turn used a connection that its actor does not hold: `connections.send`, `broadcast`, `close` or `send-now` named a connection id that another actor accepted, or one that no actor accepted. Only the actor whose open turn accepted a connection (its owner) may send on it or close it, and an id is data, not a capability: storing it or sending it in a message grants nothing (ADR 0114). The turn failed with this code; an HTTP client gets `TURN_FAILED`, and a failed message, timer or frame input is a dead letter.

To reach clients whose connections another actor holds, send that actor a message and let it forward the frame on its own connection, or let one actor (such as a room) accept all the connections it broadcasts to.

    kronik history chat/lobby --limit 10

See also: `connections`, `dead-letters`, `TURN_FAILED`.
