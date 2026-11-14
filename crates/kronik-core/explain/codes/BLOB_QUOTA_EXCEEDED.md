An actor would hold more blob bytes than `blob_bytes_per_actor` allows for
its kind (1 GiB by default), or a turn would write more bytes into blobs
than that. The quota counts the distinct blobs the actor holds after the
call: those it held when the turn started plus what the turn retained and
put, minus what it released. A blob several actors hold counts for each.

`blobs.put`, `blobs.retain` and a writer's `write` answer `quota-exceeded`
to the guest; nothing was held or written by that call, and the turn goes on.
The SDKs turn the answer into an error with this code; a turn that does not
handle it fails with it.

Release the blobs the actor no longer needs, or raise the quota with
`kronik limits set <kind> --blob-size-per-actor <size> --reason "..."`.

See also: `blob`.
