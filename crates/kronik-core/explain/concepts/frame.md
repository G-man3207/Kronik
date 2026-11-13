A frame is one message on a long-lived connection (M24): a WebSocket text or binary message, or an SSE event with its `event`, `id` and data. Frames go both ways. An incoming frame (WebSocket only) is a root input of the connection's owner, numbered 0, 1, 2, ... in the order the client sent them. An outgoing frame has its own sequence number per connection, in the order the frames go out. Frame data is the subject's data like a message body: it can be sealed and erased. An SSE event's `event` and `id` are recorded in plain text, so keep personal data out of them.

    kronik history chat/lobby --limit 20

See also: `connections`, `send-now`, `message`.
