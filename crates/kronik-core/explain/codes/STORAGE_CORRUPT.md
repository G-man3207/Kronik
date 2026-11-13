Kronik found data on disk that it cannot trust, such as a log record with a bad checksum in the middle of a segment, or a record with the enum value 0 or an unknown enum value. Kronik never applies such a record or reads it as a default value, and a corrupt record in the middle of a segment stops the startup. A torn last record after a crash is not corruption: it is truncated at startup.

Typical causes: disk or file system errors, or files in the data directory that something other than Kronik changed.

To fix it, stop the daemon and keep the data directory as it is; do not delete or edit log segments. If shipping to object storage is enabled (M6), restore into a fresh data directory:

    kronik restore --from s3://bucket/kronik

The message "state is at lsn N, but the log starts at M (compacted)" is a different case and does not mean corruption: an actor database that has not changed for longer than `[retention] history` is behind the log that retention kept. Releases up to v0.4.0 can stop at the start for this; the fix raises those databases before it deletes log, and repairs such a directory at the next start from the newest snapshot. `kronik upgrade check` reports it before the restart, including for an actor database a running daemon holds: that applied LSN is read without taking the daemon's lock. If the database cannot be read, the check does not pass. See "A start that stops at the log's start" in the operations guide.

See also: `segment`, `snapshot`.
