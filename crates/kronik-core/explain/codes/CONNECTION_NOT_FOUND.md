No WebSocket or SSE connection has this id, or the operation needs an open one and this one is closed. Connection ids are `c-` and 32 lowercase hex characters. A closed connection stays listed until retention passes its close; after that it is gone, like its turns. Closing works only on a connection that is open on this node.

List the connections, open ones by default, and look one up by its id:

    kronik connections list --state all
    kronik connections inspect c-0123456789abcdef0123456789abcdef

See also: `connections`.
