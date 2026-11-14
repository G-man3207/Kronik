The blob store's file system has less free space than `[blobs]
disk_reserve` (twice `[log] disk_reserve` by default), so no new blob is
written: an upload or response that would become a blob is refused with
`503 BLOB_STORE_FULL`. The reserve keeps room for the log, so a full disk
never stops turns that write no blobs.

A turn whose blob write meets the reserve is not recorded and does not fail:
it runs again from the start, with backoff (from 100 ms up to 30 s), until
there is room, and the metric `kronik_blob_turn_retries_total` counts the
attempts. A turn that had already written its `TurnBegin` runs again as a
re-run, with its recorded effects.

Free disk space, or lower `[blobs] disk_reserve`.

See also: `blob`.
