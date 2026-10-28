A turn id is `<branch>:<lsn>` of the turn's turn record, for example `main:1482331`. Other log records are identified the same way. From v0.4, with shards, the format becomes `<branch>:<shard>:<lsn>`, and old ids stay valid. The gateway returns the turn id of every request in the `Kronik-Turn-Id` header, and from M3 `kronik trace` shows a turn's causal tree.

    kronik history billing/acme
    kronik trace main:1482331

See also: `lsn`, `branch`, `turn`.
