Kronik found data on disk that it cannot trust, such as a log record with a bad checksum in the middle of a segment, or a record with the enum value 0 or an unknown enum value. Kronik never applies such a record or reads it as a default value, and a corrupt record in the middle of a segment stops the startup. A torn last record after a crash is not corruption: it is truncated at startup. A record that `state.db` has already applied was written and acknowledged before, so it is never truncated: if it is damaged, the start stops with this code and changes nothing.

Typical causes: disk or file system errors, or files in the data directory that something other than Kronik changed.

To fix it, stop the daemon and keep the data directory as it is; do not delete or edit log segments. If shipping to object storage is enabled (M6), restore into a fresh data directory:

    kronik restore --from s3://bucket/kronik

The message "state is at lsn N, but the log starts at M (compacted)" is a different case and does not mean corruption: an actor database that has not changed for longer than `[retention] history` is behind the log that retention kept. Releases up to v0.4.0 can stop at the start for this; the fix raises those databases before it deletes log, and repairs such a directory at the next start from the newest snapshot. `kronik upgrade check` reports it before the restart, including for an actor database a running daemon holds: that applied LSN is read without taking the daemon's lock. If the database cannot be read, the check does not pass. See "A start that stops at the log's start" in the operations guide.

The message "state.db has applied lsn N, but the log ends at M" means the log lost records that were acknowledged. Releases up to v0.4.1 could cause it themselves: a turn could write a record over 128 MiB, which their start then cut off as if it were a torn write. Do not delete segments; restore from a shipped copy taken before the crash into a new data directory. The message "the open turn ... began ... in log segment ..., which is gone" means retention of a release before v0.5 deleted the log of a turn that was still open, so the turn cannot run again; restore a snapshot taken after the turn ended, or a copy of that segment.

See also: `segment`, `snapshot`, `TURN_TOO_LARGE`.
