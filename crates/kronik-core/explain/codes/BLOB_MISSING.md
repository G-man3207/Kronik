A committed record refers to a blob whose bytes are not in the blob store.
Kronik writes and syncs a blob before any record refers to it and keeps it
while a record within retention refers to it, so this is never expected. It
can follow a restore that was told to go on without some blobs
(`--allow-missing-blobs`), or files removed from the data directory by hand.

The turn that needed the blob is not recorded; an HTTP client gets `500
BLOB_MISSING`. Nothing else is affected. Restore the blob store from the
backup the data directory came from.

See also: `blob`.
