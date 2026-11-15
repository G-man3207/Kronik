The API was asked about a blob (`kronik blobs inspect`, `kronik blobs get`,
`GET /v1/blobs/{hash}`) that this node does not know: no record within
retention or row of the state references it, and, for `inspect`, no file of
that identity is in the blob store. The hash may be mistyped, or name a
blob of another node; or the blob was kept by nothing any more, and the
collector deleted it (`kronik blobs gc --dry-run` lists what the next pass
deletes, and why). `get` serves only blobs a record or the state
references; a loose file has no metadata to serve it with.

Nothing changed. Check the hash: `kronik blobs list --actor <kind/key>`
lists the blobs an actor holds, and `kronik blobs inspect` one blob's
state. History does not show a turn's blobs.

See also: `blob`, `collector`.
