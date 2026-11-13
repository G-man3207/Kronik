A turn used a blob reference that it may not use. A `blob-ref` names a blob
(its hash and size); it is not a permission. A turn may use exactly the
references it holds, the ones its input carries (an HTTP body, a message's or
timer's blobs), and the ones it obtained during the turn (a fetch response, a
blob it wrote, a call's reply). Any other reference gives `BLOB_NOT_HELD`,
even when its hash is right: a hash that was stored in state, SQL or a
message body is data, not a reference.

In a turn, `blobs.get` and the other blob functions return `not-held`; a
fetch with such a request body is denied with `BLOB_NOT_HELD`; and returning
or sending such a reference fails the turn with this code. The check is the
same in production and in replay.

To keep a blob across turns, retain it (`blobs.retain`, M26) in the turn that
received it, and send it to another actor in the message's `blobs`, never in
its body.

See also: `blob`.
