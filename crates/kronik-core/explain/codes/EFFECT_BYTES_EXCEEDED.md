An effect of a turn would have made the turn's effects record more than the actor type's `effect_bytes_per_turn` (32 MiB by default) in the log. The bytes counted are what the turn's effect results hold inline: the request and the response of every effect as recorded (an HTTP body with its headers, a `call`'s message and reply, a frame sent now, the small records of crypto and secret reveals). A body stored as a blob counts only its reference: the blob quota bounds it.

The effect fails; the turn goes on and its code decides what to do. When the request alone does not fit in what is left, the effect does not happen: nothing is sent. When the response would not fit, the request was sent and the response is not recorded: an `http.fetch` gets `too-large`, a `call` gets `failed` with this code in its text, a `send-now` gets `denied`, a crypto call `denied` and a secret reveal an error, each with this code. The failure is recorded as the effect's result, so a re-run and a fork's replay get the same answer.

The limit is per actor type, set in the log like every limit, so every node and every replay decides the same way:

    kronik limits set billing --effect-bytes-per-turn 64Mi --reason "monthly export fetches large pages"

Typical causes: a loop that fetches many pages in one turn, or responses that should be streamed into blobs. Prefer streaming large bodies into blobs (a kind whose code reads blobs keeps bodies above its blob threshold out of the log), or splitting the work over several turns, to a larger limit.

See also: `effect`, `TURN_TOO_LARGE`, `blob`.
