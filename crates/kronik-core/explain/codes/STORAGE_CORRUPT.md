Kronik found data on disk that it cannot trust, such as a log record with a bad checksum in the middle of a segment, or a record with the enum value 0 or an unknown enum value. Kronik never applies such a record or reads it as a default value, and a corrupt record in the middle of a segment stops the startup. A torn last record after a crash is not corruption: it is truncated at startup.

Typical causes: disk or file system errors, or files in the data directory that something other than Kronik changed.

To fix it, stop the daemon and keep the data directory as it is; do not delete or edit log segments. If shipping to object storage is enabled (M6), restore into a fresh data directory:

    kronik restore --from s3://bucket/kronik

See also: `segment`, `snapshot`.
