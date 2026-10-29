# M6 storage: snapshots, shipping, restore, retention, upgrades

Status: design for M6's storage half (the brief's "Snapshots, shipping to
S3-compatible storage, `restore`, retention and compaction", the startup
target, `demo/vps-restore.sh` and `kronik upgrade check`). The operations
half (config file, `serve --init`, systemd, TLS/ACME, doctor, metrics,
logs, install) is fast-policy's. Builds on ADR 0005 (per-actor SQL files),
m1-core (log, store, startup) and m3-fork (replay).

## 1. Crates

| Crate | M6 adds |
| --- | --- |
| `kronik-log` | segment listing with ranges, `Log::roll` (close the active segment), deleting closed segments |
| `kronik-store` | the apply lock, `Store::snapshot`, snapshot install, the `segments` table, compaction of `turn_index`/`trees` |
| `kronik-sched` | the snapshot schedule and the controlled-shutdown snapshot, startup from a snapshot, retention, `EngineUpgrade` at startup |
| `kronik-ship` (new) | `object_store` (S3) + zstd: the shipper and `restore` |
| `kronik-fork` | production cursors from the nearest snapshot; the retention bound; `upgrade check` |
| `kronik-api` | `/v1/snapshots`, `/v1/integrity` |
| `kronik` | `snapshot create/list`, `restore`, `upgrade check` (CLI by fast-docs) |

## 2. Snapshots

A **snapshot** is a consistent copy of a branch's materialized state at one
LSN `L` (I4: derived, rebuildable from the log):

```text
snapshots/main/<L>/state.db          VACUUM INTO copy of branches/main/state.db
snapshots/main/<L>/sql/<file>        VACUUM INTO copy of every actor database
snapshots/main/<L>/secrets.db        backup of keys/secrets.db (encrypted under the master key)
snapshots/main/<L>/manifest.json     written last: the snapshot exists iff it does
```

`manifest.json`:

```json
{"format": 1, "id": "main-0000000000012345", "branch": "main", "lsn": 12345,
 "engine_version": "kronik-…+wasmtime-…", "created_wall_ms": 1761400000000,
 "logical_time_ms": 1761399999123,
 "segments": ["00000000000000012001.seg", "…"],
 "files": [{"path": "state.db", "size": 123, "blake3": "…"}, …],
 "state_hash": "b3:…"}
```

- `segments`: the closed and active segments holding LSNs after `L` when
  the snapshot was taken (what a restore needs next).
- `state_hash`: §8, so a restore can be checked against it.
- **Consistency.** The store gets an apply lock that `Store::apply` holds
  for a whole batch (actor databases first, then `state.db`); the snapshot
  takes it, so `state.db` and every actor database are at exactly `L =
  applied_lsn`. `state.db` and the actor databases are copied with `VACUUM
  INTO` (live rows only, so pages freed by an erasure never reach a
  snapshot; M8), `secrets.db` with SQLite's online backup API, into a
  temporary directory that is renamed into place, then the manifest is
  written and fsynced. Applies wait meanwhile (turns keep running; their
  records queue).
- **History.** After the manifest, a `SnapshotMarker {snapshot_id, lsn,
  manifest_hash, engine_version}` record is appended to the branch's log,
  so the log says which snapshots existed (I5 for operations).
- **When.** Every `retention.snapshot_interval` (60 min) of wall time,
  measured by `Env::clock`; on controlled shutdown (`SIGTERM`/`SIGINT`, after
  the gateway stops accepting and before exit); and on `kronik snapshot
  create` (`POST /v1/snapshots`, scope `operate`). The interval and the
  shutdown snapshots are not taken when nothing was applied since the
  newest snapshot but its own marker, so an idle node writes no copy of
  the state and appends no marker.
- **Kept.** The newest `retention.snapshots_kept` (48), plus always the
  newest snapshot at or below the oldest retained LSN (§5), which cursors
  and startup need.
- `kronik snapshot list` (`GET /v1/snapshots`): `{"snapshots": [{"id",
  "lsn", "created_wall_ms", "engine_version", "bytes", "shipped"}]}`.

## 3. Starting from a snapshot

**Startup.** As today, `state.db` is reopened and the log is applied from
its `applied_lsn + 1`. New: when `branches/main/state.db` is missing (a
restore, a lost disk) or the log no longer holds the records after
`applied_lsn` (compacted), the newest snapshot whose LSN is within the log
(first retained LSN - 1 ≤ L) is installed (copied into `branches/main/`),
then the log is applied from `L + 1`. Without one: `STORAGE_CORRUPT`
naming the gap.

**Replay cursors** (m3-fork §3.3) start from the nearest snapshot at or
below the LSN they need instead of LSN 1: the snapshot's databases are
loaded into memory (SQLite backup from file into an in-memory connection,
per actor database into the cursor's in-memory pool), then records after
`L` are applied. The production index reads the log from `L + 1`;
configuration and kinds at the fork point come from the snapshot's
`state.db` (`config_records`, `deployments`) plus the records after `L`.
Fork state likewise starts from the nearest snapshot at or below the fork
point plus main's records up to it.

**The brief's `kv_versions`** (production's state at any LSN in the window)
is served by these cursors: state at LSN `x` = nearest snapshot ≤ `x` +
records up to `x`. No per-key version table is kept; snapshots every
60 min bound the records a cursor applies (§9 measures it).

## 4. Shipping (`kronik-ship`)

Optional (`[ship] enabled`, `url = "s3://bucket/prefix"`, `endpoint` for
S3-compatible servers such as MinIO). Credentials and region come from the
standard environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_REGION`, default `us-east-1`); an `http://`
endpoint is allowed (local MinIO). Uploads use `object_store`'s S3 client,
each object compressed with zstd (level 3):

```text
<prefix>/main/segments/<start-lsn>.seg.zst
<prefix>/main/snapshots/<L>/manifest.json            (uncompressed, uploaded last)
<prefix>/main/snapshots/<L>/<file>.zst
<prefix>/code/<blake3>.wasm.zst                      components (restore needs them)
```

- **The shipper** (a task of `kronik serve`, real environment only): every
  10 s it uploads closed segments, snapshots (files first, manifest last)
  and components not uploaded yet, and records what is uploaded in
  `ship.json` next to the data. The active segment is uploaded again
  whenever it grew since the last round (the object is replaced; a torn
  tail at its end is cut off on open like a local one), so an idle node's
  last records leave within one round without rolling the log: data loss
  on total machine loss is at most one round (10 s) plus the upload. A
  failed round is retried at the next; uploads never block turns. Remote
  segments and snapshots are deleted with the local ones by retention
  (§5; a snapshot's manifest goes first, so a half-deleted snapshot is
  never complete).
- The master key is never shipped. `secrets.db` travels inside snapshots,
  encrypted under it; the operator restores the key from their own backup
  (`keys.master_key_file`). The privacy keystore backup joins in M8.

## 5. Retention and compaction

- **The window**: `retention.history` (7 d) back from the newest record's
  logical time. Forks, replay and proposals may only start within it: a
  fork point outside it is `BAD_REQUEST` ("outside retention") at fork
  create and propose, and `PROPOSAL_STALE` at promote (m3-fork §8).
  As built, that check runs on fork create, propose, replay and promote,
  before any write; a point the log no longer covers is refused at create
  as well. A point with no turn at or before it uses the earliest later
  turn: that turn older than the cutoff is outside retention; no later
  turn, or one still inside the window, is allowed. A dry-run promote
  returns `PROPOSAL_STALE` without changing the proposal.
  `GET /v1/integrity` reports the window (`retention_history_ms`,
  `newest_logical_time_ms`, `retention_cutoff_ms`; all zero when the node
  has no storage config).
- **Segments.** `state.db` keeps `segments (start, last_lsn,
  last_time_ms)` from the applier; `last_time_ms` is the turn-time
  high-water mark at the segment's last record. That mark says nothing
  about records after the segment's last turn: a configuration record
  (the first `Deployment` of a young node) has no logical time and gets an
  older turn's mark, or 0. Such a record is at most as old as the next
  turn, so as built a closed segment is deleted (locally, then remotely
  when shipped) only when its `last_lsn` is at most the LSN of a kept
  snapshot and the first later segment with a higher `last_time_ms` (the
  one holding the next turn) is older than the window too. Without a later
  turn the segment is kept. Compaction runs after each snapshot.
- **A window cut short.** A proposal's `--window` can reach back before
  what the log and snapshots still hold. The fork then starts at the
  oldest usable snapshot and the proposal says so: `warnings` in its JSON,
  a `Warning:` line in the CLI, and `base.window_cut` (`window_ms`,
  `kept_from_lsn`) in the diff (additive in `kronik.diff/v1`).
- **Index compaction.** Rows of `turn_index` and `trees` for deleted LSNs
  are deleted; `history` and `trace` end at the oldest retained LSN.
  Dead letters keep their input (they don't need the segment); ingress
  keys past their TTL are deleted in the same pass.
- Reseal for privacy mode rides on compaction in M8.

## 6. Restore

`kronik restore --from s3://bucket/prefix [--endpoint URL] [--data-dir
DIR]` (offline: the daemon must not run on `DIR`; an existing `state.db`
is refused unless `--force`):

1. List `<prefix>/main/snapshots/`, take the newest manifest; download and
   decompress its files into `DIR/snapshots/main/<L>/` and check sizes and
   BLAKE3 against the manifest.
2. Download every remote segment of the branch (the remote keeps the
   retention window, so history within it comes back) into
   `DIR/branches/main/log/`; segments must be contiguous and reach past `L`.
3. Download every component the snapshot's deployments and the segments'
   deployments name into `DIR/code/`.
4. Install the snapshot (§3: `state.db`, `sql/`, `keys/secrets.db`).
5. Print the snapshot LSN, the last LSN in the restored log and the state
   hash at `L`; `kronik serve` then applies the log from `L + 1`.

`kronik restore` needs the master key file in place (or `--master-key-file`)
only for the secrets to be usable; restore itself does not decrypt.

## 7. Upgrades (`kronik upgrade check`)

The new binary checks itself against the data directory before it replaces
the old one (the old daemon keeps running; the check only reads):

1. `kronik upgrade check --window 6h [--data-dir DIR]` opens the log,
   snapshots and code read-only, picks the fork point 6 h of logical time
   back from the newest root input, and runs an identity replay (both
   modes) of `(fork point, HEAD]` with the same code hashes and this
   binary's engine. Fuel is not compared (`fuel_threshold` infinite).
2. An empty diff writes `DIR/upgrade/<to-engine>.json` with `{from_engine,
   to_engine, window, fork_lsn, checked_through_lsn, diff_hash,
   report_hash}` and exits 0. A non-empty diff exits with
   `ENGINE_UPGRADE_DIVERGED`, writes the diff next to it and prints a
   summary.
3. When the new binary starts and the engine version recorded in `state.db`
   (`meta.engine_version`, written by the applier from the newest
   `TurnBegin`/`TurnRecord`/`EngineUpgrade`) differs from its own, it
   requires a passing report for exactly that pair and appends
   `EngineUpgrade {epoch (the current one: not a configuration change),
   from_engine_version, to_engine_version, effective_lsn: 0,
   check_report_hash (BLAKE3 of the report file), checked_through_lsn,
   audit}` after the log is replayed and before open turns re-run or
   anything is served. Without one it refuses to start with
   `ENGINE_VERSION_MISMATCH` and the exact `upgrade check` command.
   (`kronik_fork::upgrade::check` and `kronik_sched::upgrade` hold the two
   halves; the report's fuel threshold is a finite 10^12, since JSON has no
   infinity.)

## 8. State hash and integrity

`GET /v1/integrity` (scope `read`): `{"applied_lsn", "state_hash",
"log_first_lsn", "log_hash", "through_lsn", "retention_history_ms",
"newest_logical_time_ms", "retention_cutoff_ms"}`; `?through=<lsn>` hashes
the log only through that LSN (M28: a restored node's first start appends
its `restore` audit event after the source's last record). The three retention
fields are 0 when the node has no storage config.

- `state_hash` = BLAKE3 over, in key order: `actors` (kind, key, schema
  version), `kv` (kind, key, k, value, subject), `timers`, `mailbox`,
  `dead_letters` (lsn, input, error), `orphans`, `kinds`, and each actor
  database's canonical SQL hash (ADR 0005). Positions and other derived
  index columns are excluded, so a restored node built from a snapshot plus
  segments hashes the same as the original. An actor database hashes its
  committed rows: while a turn has its savepoint open, the hash comes from
  a copy of the committed state (`SqlActor::committed_hash`, a
  `.hash-copy-<file>.tmp` file deleted after and swept at start; a
  snapshot hashes its copies), so `state_hash` is always the applied
  LSN's.
- `log_hash` = BLAKE3 over the encoded records `log_first_lsn..=through_lsn`
  (`applied_lsn` unless `through` is given).
- `demo/vps-restore.sh` compares the state hash, the log hash through the
  source's applied LSN, and the history of sample actors, between the
  source and the restored node; after that LSN the restored node holds
  exactly one record, its `restore` audit event.

## 9. Startup target

"Start with 1 GB of log after the latest snapshot: under 30 seconds."
Measured by `crates/kronik-sched/examples/startup_speed.rs`: write a
snapshot, then about 1 GB of counter turn records after it, delete
`state.db`, start the node and time until it serves (`docs/perf.md`).
The applier reads segments sequentially and applies in batches; the
measurement decides the batch size and whether reading and applying
overlap.

## 10. Tests

- Snapshot consistency under concurrent turns (state hash of the snapshot
  = state hash of a store rebuilt from the log up to `L`); snapshot list,
  pruning to `snapshots_kept`, the shutdown snapshot.
- Startup without `state.db` from the newest snapshot plus the log; a
  compacted log without a usable snapshot is `STORAGE_CORRUPT`.
- Replay from a snapshot: identity and +2 diffs equal those from LSN 1.
- Retention: old segments deleted only when covered by a kept snapshot;
  forks outside the window refused; history/trace end at the window.
- Shipping and restore against MinIO in Docker (unique container name,
  random port, removed afterwards): restored state hash and log hash equal
  the source's; the idle-roll bound.
- `upgrade check`: an identity replay passes; a deliberately different
  engine behaviour (a test hook) diverges with `ENGINE_UPGRADE_DIVERGED`;
  startup with a changed engine needs the report and writes
  `EngineUpgrade`.
- DST: snapshots taken at random points survive crashes (a crash during a
  snapshot leaves no manifest and no harm).
