The configuration epoch is a sequence number for system-wide configuration changes. Configuration records carry it: `Deployment`, from M2 `Grant` and `Limits`, and from M3 `Policy`. In v0.1 an epoch corresponds to an LSN; from v0.4 it corresponds to one LSN per shard, so that a change of several actor types still switches atomically.

See also: `deployment`, `lsn`.
