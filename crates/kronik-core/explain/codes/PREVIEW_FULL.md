A preview keeps every request's effect on its state in memory (an in-memory copy of production's state, plus each request's rows), and anyone with its URL can send it requests. So a preview takes at most 10,000 requests; the next one answers this code and changes nothing. The count starts again when the preview's state is rebuilt from its fork point (after a daemon restart or an erasure).

Its blobs have a cap too. A preview's uploads, and the blobs its turns write, go to its own blob space, which no collector sweeps while the preview lives. The space holds at most `[fork] preview_blob_bytes` (256 MiB). An upload past it answers this code, and a turn's write past it answers `quota-exceeded` to the guest. The space is deleted with the preview, when it is deleted or expires.

Delete the preview and create a new one:

    kronik preview delete <id> --reason "..."
    kronik preview create <proposal>

See also: `PREVIEW_LIMIT`, `PREVIEW_NOT_FOUND`.
