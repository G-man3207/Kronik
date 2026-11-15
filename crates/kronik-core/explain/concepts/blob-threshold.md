The blob threshold is the size above which a body is stored as a blob
instead of in the log (M25). It is a limit of each actor type, 1 MiB by
default, and never above the type's message size. It applies to a kind whose
code imports `kronik:actor/blobs` (the SDKs' blob API): an HTTP request
body or a `fetch` response (standard `fetch` too) above it reaches the turn
as a blob, streamed into the blob store as it arrives, and the record holds
only its hash and size. A body at or below it stays inline, in the record.
A kind whose code does not import blobs gets no blobs and works as before.

The largest request body of a kind that reads blobs is its upload size,
64 MiB by default; above it the gateway answers `413 PAYLOAD_TOO_LARGE`. A
response is a blob only when the guest writes one (`blobs.put` or a writer)
and answers with it. Both limits are set in the log, like every limit, so
every node and every replay decides the same way:

    kronik limits set media --blob-threshold 256Ki --upload-size 1Gi --reason "smaller records, camera originals"

See also: `blob`, `hold`, `EFFECT_BYTES_EXCEEDED`.
