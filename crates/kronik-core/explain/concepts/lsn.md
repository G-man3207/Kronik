An LSN, log sequence number, numbers every log record, not only turn records; it is in each record's envelope. LSNs are strictly increasing per branch, and from v0.4 per branch and shard. A deployment takes effect at an LSN; from M3, a fork starts at an LSN and a proposal is verified through an LSN.

See also: `turn-id`, `segment`, `branch`.
