# M6 storage: snapshots, shipping, restore, retention, upgrades

Status: design for M6's storage half (the brief's "Snapshots, shipping to
S3-compatible storage, `restore`, retention and compaction", the startup
target, `demo/vps-restore.sh` and `kronik upgrade check`).
`demo/vps-restore.sh` does not destroy a host or restore onto a second
one, so it is not a pass of the destroyed-VPS criterion. The operations
half (config file, `serve --init`, systemd, TLS/ACME, doctor, metrics,
logs, install) is covered by the operations guide. Builds on ADR 0005
(per-actor SQL files), m1-core (log, store, startup) and m3-fork (replay).

## 1. Crates

| Crate | M6 adds |
| --- | --- |
| `kronik-log` | segment listing with ranges, `Log::roll` (close the active segment), deleting closed segments |
| `kronik-store` | the apply lock, `Store::snapshot`, snapshot install, the `segments` table, compaction of `turn_index`/`trees` |
| `kronik-sched` | the snapshot schedule and the controlled-shutdown snapshot, startup from a snapshot, retention, `EngineUpgrade` at startup |
| `kronik-ship` (new) | `object_store` (S3) + zstd: the shipper and `restore` |
| `kronik-fork` | production cursors from the nearest snapshot; the retention bound; `upgrade check` |
| `kronik-api` | `/v1/snapshots`, `/v1/integrity` |
| `kronik` | `snapshot create/list`, `restore`, `upgrade check` |

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

- `segments`: the closed and active segments a start from the snapshot
  reads, when it was taken: those holding LSNs after `L`, and from the one
  holding the `TurnBegin` of a turn open at `L` on (§5, "Open turns").
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
- **Kept.** The newest `retention.snapshots_kept` (48); the window's
  **base**, the newest snapshot whose state is older than the start of
  the history window (§5: its `logical_time_ms` is strictly before the
  cutoff), from which every fork point in the window can start; and,
  between the base and the newest `snapshots_kept`, one snapshot per seventh
  of `history` (a day with the defaults; at least `snapshot_interval`
  apart). As the window moves, the base moves to the next of them, so the
  log reaches back at most that step (and an interval) further than
  `history`. Before a snapshot is old enough to be the base (a young node
  for its first `history`, or for up to one `history` after an upgrade from
  0.4.1 or older), the oldest usable one is kept in its place and nothing
  is deleted. With the defaults that is 48 hourly
  snapshots and about six more. A snapshot at or before a rebase switch's
  base is kept until a snapshot after the switch exists (ADR 0017). After an
  erasure deleted the snapshots before it (m8 §6.6) and none after it is
  old enough yet, the oldest one after it is the base: a fork point before
  the erasure that the log alone cannot reach is outside retention anyway.
  Before 0.5 this kept the newest `snapshots_kept` and the oldest snapshot
  the log continued, while compaction deleted by the newest snapshot, so
  up to all but the newest `snapshots_kept` intervals of the window could
  not be forked (#66).
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

*Which `applied_lsn`.* The start replays from the lowest applied LSN of
`state.db` and of every actor database (`Store::replay_from`), because the
files commit independently. An actor database's applied LSN is where its
**last change** was (idempotence for `apply`, and the point the log is
needed from), not "complete through n": an actor that has not changed for
longer than `history` says an LSN that retention has long deleted. So the
question above is asked of the lowest of them (`plan_state`, which
`prepare_state`, the start, and `kronik upgrade check` all call). The check
may run beside the old daemon, which holds actor databases exclusively. It
reads those applied LSNs from a private copy of the file and its WAL, without
taking the lock, waiting, or writing the data directory. A database it still
cannot read is not treated as current: the check fails rather than reporting
a pass the start would refuse. An installed snapshot carries its cut
to every database it installs: a
snapshot is a consistent cut, complete through its LSN for each of them
(`install` stamps the copies; the snapshot's own files are untouched, its
manifest hashes them). Compaction does the same before it deletes (§5).
No stored shape changes: the stamp is the row `stamp_applied` already
writes for a rebase switch.

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
records up to `x`; the base (§2) is at or before every LSN in the window,
so every one has a snapshot. No per-key version table is kept. The records a
cursor applies are at most `snapshot_interval` of them for an `x` within the
newest `snapshots_kept` intervals (48 h with the defaults), and at most a
seventh of `history` (a day) plus an interval for an older `x`. §9 measures
the start, not a cursor.

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
  when shipped) only when its `last_lsn` is at most the LSN of the window's
  base (§2) and the first later segment with a higher `last_time_ms` (the
  one holding the next turn) is older than the window too. Without a later
  turn the segment is kept, and without a base nothing is deleted. A segment
  that holds an LSN inside the window is never deleted, and the base the
  log then starts from is at or before every LSN in the window, so a fork,
  a replay or a cursor can start at any of them. Compaction runs after each
  snapshot.
- **Open turns.** The start re-runs a turn whose `TurnBegin` has no turn
  record, and reads that `TurnBegin` from the log at the position
  `open_turns` holds (its effect results are copied into `open_effects`).
  A snapshot taken while a turn is open holds that row, so a segment that
  holds the `TurnBegin` of a turn open in the live state or in any snapshot
  is not deleted, nor any later one: a snapshot does not cover a segment it
  still needs. That keeps the log the one copy of the turn's input. The
  alternative, a copy of each open `TurnBegin` in `state.db`, would be a
  second copy of turn inputs that reseal and erasure must also cover, and
  it would not help a snapshot an older release took; the cost here is
  that a turn open for longer than `history` holds back retention until it
  ends and no kept snapshot holds it open. A start that still misses the
  segment (a directory an older release compacted) is `STORAGE_CORRUPT`
  naming the turn's execution id, not a bare I/O error (#35).
- **Order of a pass.** Decide which segments go; raise the applied LSN of
  every actor database below the horizon to the applied LSN, under the
  apply lock (in batches of 64 databases, never the whole pass: turns wait
  for a batch) and checkpoint it, so that the raise is in the database file
  and not only in its WAL (`synchronous=NORMAL` syncs a WAL when it is
  checkpointed); only then delete. An error stops the pass before any
  delete. Under the apply lock every database is complete through what is
  applied (a record's SQL is applied before `state.db` takes it), which is
  what makes the raise true; only databases idle for longer than `history`
  are written, one row each. A crash before the delete loses nothing; a crash
  after a delete leaves a log that every database reaches. A database a turn
  has open (its savepoint would roll the stamp back) is retried briefly and
  then stops the pass, as does a missing file.
- **A window cut short.** A proposal's `--window` can reach back before
  what the log and snapshots still hold, or before the history window. The
  fork then starts at the oldest point it may take: the oldest usable
  snapshot, or the first turn inside the history window when the window's
  base is older than that, and the proposal says so: `warnings` in its
  JSON, a `Warning:` line in the CLI, and `base.window_cut` (`window_ms`,
  `kept_from_lsn`, the fork point it starts from) in the diff (additive in
  `kronik.diff/v1`).
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

Run as root against the data directory of the nonroot installation (a
directory that another user owns), `restore` is split at a change of identity.
As root it does only what needs root: it reads the master key and, for an
`s3://` remote, the credentials (held in memory), and decrypts the keystore
backup to check it against the key. Nothing is written, and the only things
read in the directory are the key file and the envelope of a KMS source, by
name. Then it gives up root for good, and the owner of the
directory does the rest: the downloads into `DIR/.restore` (removed when the
restore ends, and by the next restore if it was killed), the check of the
directory's own stores against the key, and the install. A `file://` remote is
read by the owner, so it must be readable by that user. The credentials of an
`s3://` remote cannot be refreshed after the change, so temporary ones must
last as long as the restore takes. The operations guide has the steps.

## 7. Upgrades (`kronik upgrade check`)

The new binary checks itself against the data directory before it replaces
the old one (the old daemon keeps running; the check does not write the
data directory). An actor database the daemon holds is read from a private
copy of that file and its WAL, which is deleted after the applied LSN is
read:

1. `kronik upgrade check --window 6h [--data-dir DIR]` opens the log,
   snapshots and code read-only, picks the fork point 6 h of logical time
   back from the newest root input, and runs an identity replay (both
   modes) of `(fork point, HEAD]` with the same code hashes and this
   binary's engine. Fuel is not compared (`fuel_threshold` infinite).
   Each matched turn uses its recorded code hash and configuration epoch:
   production deployments, grants, revocations and limits inside the window
   are history to reproduce, not engine differences. This upgrade-only
   policy must not replace ordinary forks' fixed fork-point/candidate
   configuration and code overrides.
2. A diff with no verified difference writes `DIR/upgrade/<to-engine>.json`
   with `{from_engine, to_engine, window, fork_lsn, checked_through_lsn,
   diff_hash, report_hash}` and exits 0. Differences of turns that met
   erased data (their recorded input, a state value they read, or an input
   or state that erased data shaped) are unverifiable, not a behavior change
   (ADR 0109). A verified difference exits with `ENGINE_UPGRADE_DIVERGED`,
   writes the diff next to it and prints a summary.
3. When the new binary starts and the engine version recorded in `state.db`
   (`meta.engine_version`, written by the applier from the newest
   `TurnBegin`/`TurnRecord`/`EngineUpgrade`) differs from its own, it
   requires a passing report for exactly that pair and appends
   `EngineUpgrade {epoch (the current one: not a configuration change),
   from_engine_version, to_engine_version, effective_lsn: 0,
   check_report_hash (BLAKE3 of the report file), checked_through_lsn,
   audit}` after the log is replayed and before open turns re-run or
   anything is served. The record's audit reason names the report relative
   to the data directory (`engine upgrade checked by the upgrade report
   upgrade/<to-engine>.json`), never by its path on this machine: the log
   is append-only and every audit export carries the reason. Without a
   report it refuses to start with `ENGINE_VERSION_MISMATCH` and the exact
   `upgrade check` command.
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
  exactly one record, its `restore` audit event. The script does not
  destroy a host or restore onto a second one, so it is not a pass of the
  destroyed-VPS criterion.

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
- An actor database that has not changed since before the log start:
  the restart after a compaction works; a directory an older binary
  compacted is repaired by the start (install stamps), and `kronik upgrade
  check` says so (or refuses with the start's words); the order of a pass is
  pinned by hooks (a crash after the raise deletes nothing, a crash after a
  delete leaves a log every database reaches).
- Replay from a snapshot: identity and +2 diffs equal those from LSN 1.
- Retention: old segments deleted only when covered by the window's base;
  forks outside the window refused; history/trace end at the window; a
  fork at the oldest point of the window works after the base has moved
  (and the plan keeps a base for every point over weeks of hourly
  snapshots); a snapshot taken while a turn is open stays a start point
  through retention.
- Shipping and restore against MinIO in Docker (unique container name,
  random port, removed afterwards): restored state hash and log hash equal
  the source's; the idle-roll bound.
- `upgrade check`: an identity replay passes; a deliberately different
  engine behaviour (a test hook) diverges with `ENGINE_UPGRADE_DIVERGED`;
  startup with a changed engine needs the report and writes
  `EngineUpgrade`.
- DST: snapshots taken at random points survive crashes (a crash during a
  snapshot leaves no manifest and no harm).
