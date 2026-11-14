A long-lived connection is a WebSocket or a server-sent-events (SSE) stream between a client and the gateway (M24). A route with the method `WEBSOCKET` or `SSE` names one actor, and that actor's `connection-handler` decides in its open turn whether to accept or refuse. The client gets its `101 Switching Protocols` or the `200` event stream only after that turn's record is durable. The actor that accepted a connection is its owner for its whole life: only the owner's turns send on it or close it. A frame or a close to any other id, one that closed, one that was never accepted, or one that another actor holds, is recorded as dropped and goes nowhere, so a turn depends only on its own actor's connections and replays the same; to reach another actor's client, send that actor a message. The open, every incoming frame and the close are inputs of the owner, each a root input with its own turn.

`connections.send`, `broadcast` and `close` are buffered like `send`: the frames are recorded with the turn and handed to the connection after it commits, in order; a failed turn sends nothing. An acknowledged turn means that its frames are recorded and were handed over, not that the client received them; frames to a closed connection are recorded and dropped, and `history` shows each frame as written, dropped, queued or unknown. Every accepted connection gets exactly one close input, also after a crash: a restart closes every connection the last process held with the reason `restart` (code 1012), and clients reconnect. The gateway holds the connection, not the actor, so a connection lives on while the actor sleeps between its inputs.

In replay, connection inputs are root inputs like HTTP requests, and outgoing frames are compared as responses: a changed message format shows as changed frames in the diff.

`kronik connections list` shows the open connections, `kronik connections inspect` one with its frame counts, and `kronik history --connection` its turns; an operator closes one with `kronik connections close`.

    kronik connections list --actor chat/lobby
    kronik history chat/lobby --connection c-0123456789abcdef0123456789abcdef

See also: `frame`, `send-now`, `root-input`, `CONNECTION_NOT_FOUND`, `CONNECTION_LIMIT`.
