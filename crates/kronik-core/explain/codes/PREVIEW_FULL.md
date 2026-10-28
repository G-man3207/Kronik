A preview keeps every request's effect on its state in memory (an in-memory copy of production's state, plus each request's rows), and anyone with its URL can send it requests. So a preview takes at most 10,000 requests; the next one answers this code and changes nothing. The count starts again when the preview's state is rebuilt from its fork point (after a daemon restart or an erasure).

Delete the preview and create a new one:

    kronik preview delete <id> --reason "..."
    kronik preview create <proposal>

See also: `PREVIEW_LIMIT`, `PREVIEW_NOT_FOUND`.
