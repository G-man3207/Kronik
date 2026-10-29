The export stream named in the request is off: `audit` has no `[audit] sink`, or `traces` has no `[otel] endpoint`. A stream that is off has no cursor to move, so `kronik export rewind` refuses it.

To fix it, check which streams are on, then set the sink or endpoint in `kronik.toml` (or `KRONIK_AUDIT_SINK`, `KRONIK_OTEL_ENDPOINT`) and restart `kronik serve`:

    kronik export status

See also: `lsn`.
