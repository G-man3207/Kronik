A hold is an actor's own reference to a blob (M26). A turn may use the blobs
its actor holds, the ones its input carries (an upload, a message's or a
timer's `blobs`) and the ones it got during the turn (a `fetch` response, a
call's reply, a blob it wrote); only the held ones last beyond the turn, and
the others are borrowed, readable until the turn ends. `blobs.retain` holds
a blob the turn may use, `blobs.put` stores bytes and holds the new blob,
and `blobs.release` ends the actor's own hold and no one else's. Like state,
holds change only when the turn commits, recorded as `RETAIN` and `RELEASE`
in the turn record: a turn that fails holds nothing new and releases
nothing.

A reference is a hash and a size, an identity and not a permission. A hash
kept in state, SQL or a message body is data: it keeps nothing alive and
grants nothing, and using it without a hold gives `BLOB_NOT_HELD`. To give a
blob to another actor, send it in the message's `blobs`; the receiving turn
may read it, and holds it only if it retains it. An actor's holds count
against its kind's blob quota (1 GiB by default), with the blobs of its
timers, of the messages it sent that still wait, and of the dead letters of
its messages and timers.

    kronik blobs list --actor media/trip
    kronik limits set media --blob-size-per-actor 4Gi --reason "media keeps originals"

See also: `blob`, `collector`, `BLOB_NOT_HELD`, `BLOB_QUOTA_EXCEEDED`.
