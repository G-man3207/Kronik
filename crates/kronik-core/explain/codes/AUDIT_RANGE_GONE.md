The requested range starts before the first record the log still holds. Retention deletes closed segments once a snapshot covers them and they are older than `[retention] history`, so `kronik audit show --from` and `kronik export rewind --to` can only reach back to the first retained record. The message names that LSN.

To fix it, start at the first retained LSN:

    kronik audit show --from <first retained LSN>

Records before it are gone from this node. If the audit sink lost lines from that range, a shipped copy of the log (`kronik restore` into a scratch data directory) still has them.

See also: `lsn`, `segment`, `snapshot`.
