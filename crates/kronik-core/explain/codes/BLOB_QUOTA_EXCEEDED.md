An actor would keep more blob bytes alive than `blob_bytes_per_actor`
allows for its kind (1 GiB by default), or a turn would write more bytes
into blobs than that. The quota counts each blob once, across what the
actor holds and what its turns left in rows: its timers, the messages and
compensations it sent that still wait, and the dead letters of its
messages and timers. A blob counts against the actor that sent it, never
the receiver, and stops counting at the actor's first turn after its row
goes (the message taken, the timer fired or cancelled, the dead letter
resent). A blob several actors keep counts for each.

`blobs.put`, `blobs.retain` and a writer's `write` answer `quota-exceeded`
to the guest; nothing was held or written by that call, and the turn goes
on. The SDKs turn the answer into an error with this code; a turn that does
not handle it fails with it. A `send`, `schedule` or `call` that would pass
the quota with its blobs fails the turn with this code, because those calls
have no error to answer with; nothing of the turn is kept.

Release the blobs the actor no longer needs, cancel timers that carry
blobs, or raise the quota with
`kronik limits set <kind> --blob-size-per-actor <size> --reason "..."`.

See also: `blob`.
