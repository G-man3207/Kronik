A snapshot is a consistent copy of materialized state at a known LSN, made with SQLite's backup API, with a `manifest.json` that lists the lsn, branch, segments, engine version and time. Snapshots are made every 60 minutes by default and at a controlled shutdown. Forks build their state from the nearest snapshot, and with shipping enabled snapshots are uploaded to object storage, from where `kronik restore` fetches the latest one and the segments after it. Like all state, snapshots are derived from the log (I4).

    kronik snapshot list
    kronik restore --from s3://bucket/kronik

See also: `segment`, `branch`.
