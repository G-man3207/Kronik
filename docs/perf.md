# Performance

Measurements of the daemon against the build brief's targets. Every number here
comes from a script in the repository; rerun it before quoting a number.

## Method

- `scripts/perf-m1.sh [WORKDIR] [PORT] [SECONDS]` starts the release
  binary on a fresh data directory on a real disk (`/var/tmp`, not tmpfs),
  deploys the counter test guest (`tests/guests/counter.wasm`, a WIT-level
  stand-in for `counter-rs`), and runs `tools/loadgen` once per row below:
  2 s warm-up, then 10 s measured.
- `tools/loadgen` is a dependency-free HTTP/1.1 client with one keep-alive
  connection per worker. Each request is `POST /counter/k<key>/increment`
  and counts only when it returns 2xx, that is, after its `TurnRecord` is
  fsynced and applied. With `--keys >= --concurrency` no two workers share
  an actor. Closed-loop rows send back to back; the 200 req/s row is
  open-loop and measures latency from the scheduled send time (no
  coordinated omission).
- The load generator runs on the same machine as the daemon and competes
  for its CPUs.
- Fsync cost per write, for reference: `dd if=/dev/zero of=/var/tmp/f
  bs=4k count=500 oflag=dsync`.

## Machines

| | development machine | test VPS |
| --- | --- | --- |
| CPU | AMD EPYC 9354P, 8 vCPU | Intel Xeon Skylake, 2 vCPU |
| Memory | 31 GB | 4 GB |
| OS | Debian 13 | Debian 13, no `/dev/kvm` |
| 4 KiB `O_DSYNC` write | 1.08 ms | 0.85 ms |

## Results (M1, 2026-10-25, commit 560d350)

Committed turns per second, and request latency in ms:

| Workload | development turns/s | development p50 / p99 | VPS turns/s | VPS p50 / p99 |
| --- | ---: | --- | ---: | --- |
| 1 actor, 1 client | 181 | 4.9 / 12.8 | 174 | 5.2 / 12.7 |
| 1 actor, 16 clients | 206 | 76.9 / 97.2 | 190 | 82.7 / 114.3 |
| 64 actors, 64 clients | 7 842 | 7.6 / 17.6 | 2 769 | 21.9 / 49.6 |
| 256 actors, 256 clients | 7 995 | 29.8 / 72.0 | 2 774 | 91.6 / 167.9 |
| 256 actors, open loop 200 req/s | 200 | 5.1 / 11.8 | 200 | 5.7 / 22.9 |

`scripts/acceptance-m1.sh` (10 000 sequential-per-actor increments from 16
clients to one actor) took 45.9 s on the development machine and 58.4 s on the VPS.

## Against the build brief's targets

- **At least 1 000 committed turns/s for the Rust counter with group
  commit.** Met across actors: about 7 900/s on the development machine
  and 2 770/s on the 2-vCPU VPS, with no errors. **Not met for a single actor**, which commits
  about 180 to 210 turns/s, five times below the target, if the target is
  meant per actor.
  - Why: an actor runs one turn at a time, and its next turn starts only
    after the previous turn record is fsynced and applied (the turn must
    read its own committed state). Each turn therefore waits for the group
    commit window (2 ms, which tokio's millisecond timer rounds up to 2 to
    3 ms), one fsync (about 1 ms on both machines), and the apply. That is
    4 to 5 ms per turn, matching the measured p50 of 4.9 to 5.2 ms with one
    client. More clients on the same actor only queue (p50 77 to 83 ms).
  - Across actors, one fsync covers every turn in the window, so
    throughput scales until the CPU is the limit: the 64- and 256-actor rows
    give the same rate, and on the VPS the load generator and daemon share
    two vCPUs.
  - Not tuned yet. Options, to be decided against measurements: a shorter
    or adaptive window (commit immediately when the writer is idle), and
    pipelining an actor's next turn on top of its uncommitted state while
    still answering only after fsync.
- **Gateway p99 below 25 ms at 200 req/s.** Met: 11.8 ms on the development
  machine and 22.9 ms on the VPS, where the margin is small (the load
  generator runs on the same two vCPUs).

## Replay speed (M3)

The build brief's target: replay of the reference workload at 20x real time or
more on the test VPS, measured as the production wall time of the window
divided by the replay wall time (docs/design/m3-fork.md §10).

### Method

- `cargo run --release -p kronik-fork --example replay_speed --
  [--requests N] [--rate R] [--actors A] [--workers W]` starts a node on a
  fresh data directory under `/var/tmp`, deploys the counter test guest,
  and records the reference workload open loop: N `POST
  /counter/k<i mod A>/increment` root inputs at R per second through
  `Node::ingress`, each acknowledged after its `TurnRecord` is fsynced
  (production wall time = first send to last acknowledgement). The
  reference is the open-loop row above: 200 req/s over 256 actors, here for
  60 s (12 000 requests).
- It then replays the window with the same code (an identity replay; it
  checks the diff is empty) and times, each from reading the log: isolated
  replay of every root input on W workers (default: all cores), continuous
  replay, and both (continuous on its own task next to W-1 isolated
  workers), each including the diff build. It also reports isolated
  replay without the diff and the diff build alone.
- `scripts/acceptance-m3.sh` runs it with 12 000 requests at 200 req/s.

### Results (development machine, 2026-10-25, commit 0047670)

The numbers move by a factor of up to two between runs.

| Mode, 12 000 inputs at 200 req/s (60 s window) | Replay | Speed |
| --- | --- | --- |
| Isolated, 8 workers | 1.3 to 2.4 s | 25x to 47x |
| Continuous | 1.4 to 2.6 s | 23x to 42x |
| Both | 1.9 to 3.0 s | 20x to 31x |

- Per input, one thread replays about 7 000 to 9 000 root inputs/s:
  each is a full turn (the guest runs again) plus its apply into an
  in-memory store.
- Isolated replay scales to about 1.6x on 2 workers and 1.85x on 4, and
  not beyond: 1.5 s, 0.95 s, 0.83 s and 1.03 s for 1, 2, 4 and 8 workers
  (12 000 inputs). The workers share no locks in Kronik; the likely limit is
  instance allocation and teardown in the Wasm runtime under concurrency
  (the same as production turns across actors). Not investigated yet.

### Results (VPS, 2026-10-25)

test VPS, 2 vCPU, release, `replay_speed --workers 2`. 12 000 requests
at 200 req/s, 60.01 s production window. Identity diff empty. The continuous
diff reads production's live `state.db` after its actor and kv rows match a
rebuilt store. Index time is building the root and causal maps.

| Run | Isolated | Continuous | Both | Index |
| --- | --- | --- | --- | --- |
| 1 | 1.70 s, 35.3x | 2.09 s, 28.8x | 3.14 s, 19.1x | 0.06 s |
| 2 | 1.71 s, 35.1x | 2.00 s, 30.0x | 3.09 s, 19.4x | 0.05 s |

Isolated and continuous meet 20x. Both does not. The target is not lowered.
An earlier bulk `turn_index` catch-up (1.73 s / 2.26 s / 3.26 s) is not this code.

### Results (VPS, 2026-10-26, commit 970cb81)

test VPS, release, `replay_speed --workers 2`, 12 000 requests at
200 req/s, 60.01 s production window, identity diff empty in every run.
The load average is the 1-minute value from `uptime` before each run.

| Run | Binary | Load | Isolated | Continuous | Both |
| --- | --- | --- | --- | --- | --- |
| before | 7e50134 | 1.49 | 1.87 s, 32.0x | 2.30 s, 26.1x | 3.43 s, 17.5x |
| before | 7e50134 | 1.45 | 1.99 s, 30.2x | 2.34 s, 25.6x | 3.33 s, 18.0x |
| 1 | 970cb81 | 2.22 | 1.47 s, 40.9x | 2.20 s, 27.2x | 2.54 s, 23.6x |
| 2 | 970cb81 | 1.55 | 1.49 s, 40.4x | 2.10 s, 28.6x | 2.68 s, 22.4x |
| 3 | 970cb81 | 1.45 | 1.72 s, 34.8x | 2.22 s, 27.1x | 2.47 s, 24.3x |

**Both meets 20x** in three consecutive runs; isolated and continuous got
faster too.

What the profile showed:

- **Both modes were already balanced on two cores.** An instrumented run
  had the continuous task finish after 2.86 s and the one isolated worker
  after 2.88 s (running alone, continuous takes 2.2 s: the two slow each
  other down). So there was little idle core to give back; the two cores
  were simply busy for about 5.7 s.
- **Per turn, the kernel took a fifth** (perf on the development machine,
  isolated replay on one core): page faults and `madvise` from the Wasm
  pooling allocator, which zeroed 64 KiB of a reused memory slot and
  returned the rest, so every
  instance faulted its stack and heap (about 1 MiB for the counter) back
  in. SQLite took another quarter, malloc and memcpy a fifth.

What changed:

- The pooling allocator keeps up to 2 MiB of a reused linear memory
  resident and zeroes it with memset (38a47ee). The kernel's share fell to
  3%; isolated replay on the VPS went from 1.9 s to 1.4 to 1.7 s. Production
  turns gain the same; a slot keeps at most what its instances used
  resident.
- Each applied turn no longer writes the never-read `turn_actor` table,
  and a batch no longer rewrites an unchanged `config_epoch` (8c3f83e).
- Isolated replay splits ranges for idle workers, and in both modes the
  continuous task joins once it is done (970cb81). On this workload the
  two halves finish close together, so the split rarely triggers; it pays
  when continuous replay is much shorter than isolated replay.
- Measured and not kept: caching the overlay's `SAVEPOINT` and
  `ROLLBACK TO` statements made isolated replay 2.3 times slower (5.0 to
  5.6 s on the VPS); the split alone, without the memory change, left both
  at 3.38 and 3.40 s.

### Memory cost of the resident Wasm memories (38a47ee)

The pool has `2 × concurrency` linear memory slots per engine (one engine
per daemon; forks and replays share it, `kronik upgrade check` builds its
own of `2 × workers`). Each reused slot now keeps up to 2 MiB resident
instead of 64 KiB, so the worst case on top of running instances is
128 × 2 MiB = 256 MiB at the default `--concurrency 64` (512 MiB at 128),
248 MiB more than before.

Measured on the test VPS (4 GB): `kronik serve` from the same tree with
64 KiB (before) and 2 MiB (after), the guest deployed, 20 s of 64 clients
on 64 actors, then 30 s of 256 clients on 256 actors (`tools/loadgen`, as
`scripts/perf-m1.sh`), VmRSS / VmHWM of the daemon:

| Guest | Before | After |
| --- | --- | --- |
| Rust counter, after deploy | 41 / 42 MiB | 43 / 43 MiB |
| Rust counter, after the 256-actor load and 10 s idle | 64 / 64 MiB | 66 / 68 MiB |
| TypeScript counter, after deploy | 334 / 479 MiB | 337 / 477 MiB |
| TypeScript counter, after the 256-actor load and 10 s idle | 428 / 600 MiB | 563 / 708 MiB |

The Rust counter's memory is about 1 MiB and few instances run at once, so
little stays resident. The TypeScript counter's turns are slower (458 and
436 req/s), more slots get used, and each keeps the full 2 MiB: 135 MiB
more. The worst case fits a 4 GB VPS; `docs/guides/operations.md` has it
for operators.



## Startup after a crash (M6)

The build brief: "start with 1 GB of log after the latest snapshot: under 30
seconds" (docs/design/m6-storage.md §9).

Since v0.4.0 a start also certifies the secret inventory before it serves
([ADR 0108](adr/0108-durable-secret-coverage-watermark.md)); the results
below were measured before that. The certification runs after the replay,
not alongside it, and reads the log appended since the coverage watermark,
or the whole retained log when there is none: on the first start after an
upgrade from v0.4.0, after a restore, or when retention cut the log below
the watermark. Measured on 135 996 records in 5 segments (68 MB in the
first) without a watermark: 1.8 to 3.0 s, 1.05 to 1.93 s of CPU for the
whole start, and a peak resident set of 91 MiB against 26 MiB with a
watermark, at a load average of 41 to 44. That is about 10 us of CPU per
record, the decode speed of the results below. It decodes up to 4 segments
at a time, so its transient memory is at most 4 segments (256 MiB at the
default 64 MiB). It has not been measured with 1 GiB of log, and
`startup_speed` does not report it. At 3 million records and the same speed
it is 24 to 43 s of CPU, or 6 to 11 s on four free cores, to be added to
the replay times below on a cold start only.

### Method

`cargo run --release -p kronik-sched --example startup_speed -- [--gib 1.0]
[--apply-batch N] [--reuse] [--read-only]`:

1. It deploys the counter, takes a snapshot, copies `state.db` as it was
   at the snapshot, then writes counter turns (HTTP root inputs over 4 096
   actors, 64 concurrent turns) until the log after the snapshot holds 1 GiB,
   and drops the runtime, as a crash would.
2. It times `start_local` until it returns, which is after replay, when
   the node serves. This runs twice: without `state.db` and `sql/` (the
   start installs the snapshot, then replays everything after it), and with
   `state.db` as it was at the snapshot (a crash with 1 GiB unapplied).
3. `--read-only` times reading and decoding the same records without
   applying them. `--reuse` measures an existing directory again, for
   example with another `--apply-batch`, the size of the batches that
   startup replay applies in one transaction (`NodeConfig.apply_batch`).

### Results (development machine, 2026-10-26, commit c4d1904)

The log after the snapshot: 3 072 001 records, 1.00 GiB, about 350 bytes
per counter turn record. Absolute times are pessimistic; the ratios between
rows hold.

| | 0.1 GiB | 1 GiB |
| --- | --- | --- |
| Reading and decoding only | 3.6 s (87 000 records/s) | 30.6 s (100 000 records/s) |
| Start, `apply_batch` 512 (default), without `state.db` | 19.3 s | 445.5 s |
| Start, `apply_batch` 512, `state.db` at the snapshot | 19.1 s | 361.1 s |
| Start, `apply_batch` 8 192 | 9.1 to 9.7 s | |
| Start, `apply_batch` 65 536, without `state.db` | 7.2 s | 140.4 s |
| Start, `apply_batch` 65 536, `state.db` at the snapshot | 6.8 s | 145.9 s |

**The target is not met: 140 s at best against 30 s.** What the numbers
show:

- **Reading alone takes the whole budget.** At 100 000 records/s, decoding
  1 GiB of records (protobuf, one allocation per field) takes about 30 s.
  CRC checking and reading the 64 MiB segments are a small part of it.
  Reading and applying run one after the other: the reader decodes a
  segment, then the batch is applied inside its callback.
- **Applying gets slower as the state grows**: about 23 µs per record at
  0.1 GiB and 36 µs at 1 GiB with batches of 65 536. Every record inserts
  into two indexes at scattered places, `trees` (keyed by the random root
  id of the causal tree) and `turn_index_actor` (one hot spot per actor),
  so each commit writes many separate pages to the WAL. A 256 MiB SQLite
  page cache made no difference, since the OS page cache already holds the
  file.
- **Batch size is the cheap lever**: 512 records per transaction is right
  for the live applier (latency) but costs startup 2.5 to 3 times more
  than 65 536.

Changes that would close the gap, for the store and the scheduler (all
four are in the code now; the VPS results below say how):

1. Startup replay applies in batches of about 65 536 records (or 32 MiB),
   separately from the live applier's `apply_batch`: 361 s to 146 s
   measured.
2. Reading the next segment overlaps applying the previous batch, so a
   start takes about the longer of the two, not their sum: about 30 s
   less.
3. Segments are decoded in parallel (a segment's entries split over the
   blocking pool), so reading no longer takes the whole budget on 8 vCPUs.
4. The derived indexes are built in bulk during long replays, for example
   by inserting each batch's `trees` rows in sorted order, or by
   rebuilding the indexes after replay, instead of scattered inserts per
   record.

### Results (VPS, 2026-10-25, prepared-insert catch-up)

test VPS, release, `startup_speed --reuse`, 1.00 GiB log, `state.db`
removed. File catch-up inserts each `turn_index` row with a prepared
statement and builds the `(kind, key, lsn)` index when the replay finishes.

| Run | Without `state.db` |
| --- | --- |
| best | 30.8 s |
| typical | 31–32 s |
| confirmation | 32.81 s |

**The 30 s target is not met.**

Buffering `turn_index` and loading it in one transaction was slower
(37.33 s, 33.48 s, 33.30 s) and is not this code.

### Results (VPS, 2026-10-26, commit c852dae, streamed catch-up)

test VPS, release, `startup_speed --gib 1.0 --reuse` on a log this
tool wrote the same day (3 002 369 records, 1.00 GiB after the snapshot).
Three consecutive runs; the load average is the 1-minute value from
`uptime` right before each run.

| Run | Load | Without `state.db` | `state.db` at the snapshot |
| --- | --- | --- | --- |
| before (dd16701) | 1.54 | 32.73 s | 30.66 s |
| before (dd16701) | 2.03 | 32.95 s | 33.82 s |
| 1 | 0.07 | 19.71 s | 17.19 s |
| 2 | 1.18 | 18.84 s | 16.85 s |
| 3 | 1.61 | 19.43 s | 16.94 s |
| 1 (7e50134) | 0.00 | 20.09 s | 16.76 s |
| 2 (7e50134) | 1.13 | 18.76 s | 16.70 s |
| 3 (7e50134) | 1.75 | 19.01 s | 16.92 s |

**The 30 s target is met.** (The load average before runs 2 and 3 is the
previous run's own work.) The 7e50134 rows include the crash marker, the
actor index on every node and the default page size (below); later commits
do not change startup replay.

What the profile showed (perf on the development machine pinned to two
cores, then timers in an instrumented VPS build):

- **The apply thread set the pace, not decoding.** In a 20.4 s replay it
  spent 9.7 s applying, 4.4 s freeing the decoded records (allocated on
  the decode thread, freed on the apply thread) and about 1.3 s moving
  them (a `Committed` is 1 KiB) into batches, and waited 5 s for decode.
  Applying ran three prepared-statement cache lookups per record (two
  DELETEs on the empty `open_turns` and `open_effects`, the `turn_index`
  insert) and cloned keys into hash maps.
- **Decoding a segment into a vector touched fresh memory every time.** A
  segment decoded into 190 000 records holds about 200 MiB; on the
  development machine a quarter of decode time was the kernel faulting pages
  in, and on the VPS a cold segment decoded in 1.1 s against 0.7 s warm.
- **The rebuild after replay took 8.5 to 10 s**: `CREATE INDEX
  turn_index_actor` sorted in memory on one thread (5.6 to 9.2 s), and the
  `trees` build sorted 3 million strings through pointers (3 to 4 s),
  inserted them into a scratch table and copied them with a decoding
  `INSERT ... SELECT` (1.2 to 2.6 s).

What changed:

- A decode task streams its segment's records into `CatchupRows`
  (kronik-store) and drops each record as soon as it is added, so the heap
  stays small and warm and nothing is freed on the apply thread. The apply
  thread only writes the prepared rows, one transaction per segment, with
  `applied_lsn` and `time_hwm` in it. A segment with any record that is
  not a simple HTTP turn (or turn begin) is applied record by record as
  before. Every core decodes: two segments are in flight on two cores.
- `trees` rows are sorted by an 8-byte prefix, the scratch table has the
  final shape (so the copy is SQLite's row transfer) and lives beside
  `state.db` instead of `/dev/shm`, and `CREATE INDEX` runs with
  `temp_store = FILE` so its sorter spills runs and sorts them on worker
  threads (4.6 to 5.0 s against 6.4 to 7.3 s in memory, A/B on the VPS).

With these, a 1 GiB start on the VPS is about 11.5 s of replay (the apply
thread busy about 7 s) plus 6 to 7 s of rebuild.

**`state.db` keeps SQLite's default page size.** The bulk replay used to
rebuild `state.db` with 64 KiB pages first (a `VACUUM`), which stayed for
the node's life and would have changed what the live applier writes per
commit. Measured on the VPS at 2110c8c, `KRONIK_STARTUP_ONCE=1
startup_speed --reuse`, alternating binaries: 20.65, 21.00 and 19.88 s with
64 KiB pages, 20.53, 20.70 and 19.41 s without (load average 0.1 to 1.8).
The larger page bought nothing once `trees` is copied with SQLite's row
transfer, so the replay no longer changes the page size.

**A crash during the replay** (journaling is off) cannot leave a torn or
double-counted `state.db` behind: the replay keeps a marker file beside it,
fsynced before journaling goes off and removed after `state.db` is fsynced
at the end; a start that finds the marker discards `state.db` and rebuilds
it from the snapshot and the log. The final fsync is part of the times
above (about 1 s more than at c852dae).


## Privacy mode overhead (M8)

The build brief: "The `off` mode has no measurable overhead compared to M6.
Measure and document" (docs/design/m8-privacy.md §13).

### Method

`NICE=-10 scripts/bench-privacy.sh BASE NEW [RUNS] [SECONDS]` builds both
commits in release mode and measures them alternately: per run, BASE, then
NEW in `off` mode, then NEW in `on` mode, each on a fresh data directory
with `privacy.subject_from = "header:x-user-id"`. Three workloads, 2 s
warm-up and 10 s measured each, through `tools/loadgen`:

- **counter**: the gateway, `POST /counter/k<key>/increment`, 64 keys, 16
  clients; requests for even keys carry the header, so half the turns have
  a subject.
- **send**: the API over TCP with a bearer token, `POST
  /v1/actors/counter/s<key>/messages` with a `subject`, 64 keys, 16 clients.
- **notes**: the gateway, `POST /notes/n<key>` with a body, 16 keys, 16
  clients, all with the header: every turn writes an SQL row with
  `_subject`, so the log holds one changeset per subject.

Besides throughput and latency the script reports the daemon's CPU time
(user + system from `/proc`) per log record and the log bytes per record.
"No measurable overhead" means that for throughput, p99 and CPU per record
the difference is under 2 standard deviations or under 3 %.

### Results (development machine, 2026-10-25)

BASE is `28aac17`, the parent of the sealing commit. NEW is `28aac17` with
only the M8 commits on top (`c99061f`, the API fix `ed47360`, `c90a633`,
`eaf56b8`). 5 runs, niceness -10, on a loaded development machine:

| Workload | Build | turns/s | p50 ms | p99 ms | CPU µs/record | log B/record |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| counter | base | 1 717 ± 185 | 8.0 ± 0.7 | 29.5 ± 8.6 | 627 ± 224 | 425 |
| counter | off | 1 782 ± 139 | 7.7 ± 0.9 | 27.5 ± 4.2 | 479 ± 174 | 425 |
| counter | on | 1 831 ± 342 | 7.7 ± 1.4 | 27.1 ± 11.1 | 532 ± 94 | 562 |
| send | base | 1 805 ± 418 | 7.8 ± 1.3 | 29.0 ± 9.5 | 520 ± 103 | 407 |
| send | off | 1 842 ± 337 | 7.5 ± 1.1 | 28.6 ± 9.4 | 525 ± 146 | 407 |
| send | on | 1 688 ± 176 | 7.9 ± 0.6 | 30.6 ± 7.3 | 612 ± 158 | 547 |
| notes | base | 1 018 ± 211 | 14.2 ± 2.9 | 45.8 ± 10.7 | 971 ± 84 | 484 |
| notes | off | 1 217 ± 176 | 11.8 ± 1.6 | 37.8 ± 10.9 | 1 097 ± 188 | 484 |
| notes | on | 1 150 ± 311 | 12.6 ± 2.7 | 46.5 ± 34.3 | 1 374 ± 334 | 759 |

- **`off` against M6: no measurable overhead.** Every difference is within
  the run-to-run noise: throughput +2 % to +20 %, p99 -18 % to -2 %, CPU per
  record -24 % to +13 %, against standard deviations of 8 % to 36 %. The
  log is byte for byte the same size. On a machine this busy the bound is
  loose; the quiet test VPS should narrow it (owed).
- **Why off costs nothing, by construction.** `off` adds no encryption, no
  key lookup, no copy and no allocation per turn: one relaxed atomic load
  per appended record (`Node::seal`), a walk over the input's few values
  looking for a sealed one, an integer column written and read with each
  state value (`kv.sealed`), and the subject tag on fetch and call effect
  records. A guest's state read moves the stored bytes out as before M8,
  and plain SQL changesets are applied as before (`eaf56b8`).
- **`on` costs log size more than time.** Each sealed value carries a key
  version, a 24-byte nonce and a 16-byte tag: +32 % log bytes per record
  for counter, +34 % for send, +57 % for notes (every tagged value of a turn
  is sealed: the header, the body and the changeset). Throughput stayed
  within the noise; CPU per record rose by up to 42 %, for notes (1 374 ±
  334 µs against 971 ± 84).

## Nightly checks (Definition of done)

The Definition of done asks for a crash test of 1 000 `kill -9` cycles and
for DST over 10 000 seeds plus a long run of at least 1 000 000 steps,
all without violations. `.github/workflows/nightly.yml` runs these every
night with the commands below, once the repository is on GitHub.

### Method

- **Crash test:** `scripts/chaos.sh [CYCLES] [WORKDIR]`. The defaults are
  1 000 cycles in `/var/tmp/kronik-chaos`, on a real disk.
  - Each cycle, 12 clients send 40 to 200 HTTP requests with an
    `Idempotency-Key`, and retry them until acknowledged. The requests go to
    four counters and four `notes` actors (SQL).
  - It also sends one to four pairs of `fetch` messages to a local target:
    one to an unsafe grant and one to an idempotency-keyed grant. 30% of the
    target's answers are slow.
  - The daemon is killed at a random moment and restarted.
  - After every restart it checks:
    - no acknowledged turn is lost or applied twice;
    - a retry with the same `Idempotency-Key` gets the same turn;
    - the first turn after the restart is later in logical time than every
      turn in the recovered log;
    - no unsafe request is sent twice;
    - an unsafe request the kill cut off ends `EFFECT_OUTCOME_UNKNOWN` with
      a dead letter;
    - keyed retries carry the same key and body.
  - Every 50 cycles and at the end, the recovered state (`state.db` and every
    SQL database) must equal the state rebuilt from the log alone.
  - At the end, an identity replay of everything since the setup must give
    an empty diff.
  - The details are in `scripts/chaos.py`.
- **DST:** `scripts/dst.sh [SEEDS] [JOBS] [harness options]` runs
  kronik-sim's harness over a range of seeds, split across processes.
  - `--twice` runs every seed twice and compares the traces.
  - With `--scenario webhook` and
    `KRONIK_DST_RELAY=examples/dist/webhook-relay-ts.wasm`, the webhook
    workload uses the TypeScript relay.
- **DST long run:**
  `cargo test --release -p kronik-sim --test dst -- --long 1000000 --twice`.
  This runs the counter workload as one run of at least 1 000 000 executor
  steps, with a crash about every 0.3 to 1 s of virtual time.

### Results (development machine, 2026-10-25, commit 2e3740f)

The development machine was loaded during these runs, and the runs
overlapped. Wall times are therefore upper bounds.

| Check | Result | Wall time |
| --- | --- | --- |
| Crash test, 1 000 cycles | No violations. Details below the table. | 49 min |
| DST, seeds 0 to 9 999, counter, effects and webhook, each twice | 30 000 runs: no violation, no nondeterminism | 735 s, 8 processes |
| DST, seeds 0 to 9 999, webhook with webhook-relay-ts, each twice | 10 000 runs: no violation, no nondeterminism | 1 253 s, 8 processes |
| DST long run, seed 0, twice | 1 003 063 steps: no violation, the same trace both times | 362 s per run |

Crash test details:

- 118 915 acknowledged requests, and 20 000 of them sent again with their
  key.
- 20 rebuild comparisons, all equal.
- 2 451 unsafe effects, none sent twice. 469 of them were cut off by the
  kill and ended in the dead letters as outcome unknown.
- 477 keyed effects were redone after a restart.
- The final identity replay of 124 782 root inputs was empty.
- The daemon was healthy again after a median of 0.22 s, p99 0.71 s, at
  most 1.52 s.

DST long run details: 68 147 requests, 109 582 turns, 273 crashes and
188.8 s of virtual time.

### Restart time in the crash test since v0.4.0

The 0.22 s median above predates v0.4.0, whose start also certifies the
secret inventory before the daemon serves
([ADR 0108](adr/0108-durable-secret-coverage-watermark.md)). The nightly of
2026-11-06 (hosted runner, v0.4.0, seed 1) shows what that cost when the
certification read the log again at every start: the time from `kill -9` to a
healthy daemon rose in steps of about 1 800 acknowledged requests (2 048
records), and the run ended after cycle 326 on a history read that answered
503 `SECRET_UNAVAILABLE` for longer than the harness retried.

| Cycle | Acknowledged so far | Healthy again after |
| --- | --- | --- |
| 1 | 74 | 0.04 s |
| 50 | 6 015 | 1.28 s |
| 100 | 12 307 | 3.20 s |
| 150 | 18 141 | 5.94 s |
| 200 | 23 839 | 10.53 s |
| 250 | 30 123 | 15.32 s |
| 300 | 36 184 | 20.57 s |
| 326 | 39 499 | 24.42 s |

Three things made the step: a second scan from the first retained record at
every certification, in windows of 2 048 records; a read of a segment that
checks every record before the first one asked for, with two blocking-pool
round trips per record, so each window cost time in proportion to the
segment; and a checkpoint after each window that replaced the last valid
watermark. The secret cycle that follows a start then did the same again with
the certificate cleared, which is the 503. The fix reads only the records
after the watermark, from whole segment images, and keeps the certificate the
start made.

The same run, 150 cycles with seed 1, with the v0.4.0 binary and the fixed
binary side by side on one machine (8 vCPUs, load average 15 to 35). The
cells are the median and, in brackets, the maximum of the seconds until
healthy:

| Cycles | v0.4.0 | Fixed |
| --- | --- | --- |
| 1 to 10 | 0.15 (0.47) | 0.07 (0.19) |
| 11 to 25 | 0.52 (1.65) | 0.07 (0.24) |
| 26 to 50 | 1.98 (5.05) | 0.15 (0.58) |
| 51 to 75 | 5.44 (11.58) | 0.15 (0.40) |
| 76 to 100 | 8.96 (14.10) | 0.16 (0.31) |
| 101 to 125 | 10.93 (17.41) | 0.18 (0.34) |
| 126 to 150 | 17.42 (21.08) | 0.23 (0.54) |

The run took 2 319 s with v0.4.0 and 315 s with the fix. v0.4.0 repeated a
history read 4 538 times after a 503; the fix never did.

The fixed binary then ran all 1 000 cycles in 75.5 minutes, on a machine at a
load average of 15 to 56: no violation, 20 rebuild comparisons equal, an empty
identity replay of 126 145 root inputs, and no history read answered 503. The
median restart rose from 0.13 s (cycles 1 to 100) to 1.12 s (cycles 801 to
900, 108 000 acknowledged requests); the last 100 cycles ran while other work
kept the load average at 35 to 56 (median 2.37 s, maximum 9.10 s).

What is left grows with the active log segment, which rolled at 68 MB after
132 643 records. A start does three things with it. `Log::open` reads it,
checks every CRC and decodes every turn record to rebuild the footer index
(`crates/kronik-log/src/lib.rs`); the replay reads the whole image to reach
its unapplied tail; and the certification reads it to reach the records after
the watermark. In a traced start of a segment of 40 321 records on the loaded
machine, the first took about 0.8 s from the read to its next system call, the
second about 0.5 s for 28 records, and a certification of all the records
0.6 s; the index decode is most of the first. A certification of about 125
new records took a median of 6 ms while the segment held fewer than 20 000
records, 25 ms up to 60 000, 67 ms up to 100 000 and 123 ms beyond (load
average 15 to 40).

A start from a copy of the data directory of cycle 104 (14 056 records, with
the invalid manifest v0.4.0 had left), measured on the same machine:

| | v0.4.0 (two starts) | Fixed (four starts) |
| --- | --- | --- |
| Healthy after | 7.3 and 9.6 s | 0.13 to 0.27 s |
| A scrubbed read answers 200 after | 12.0 and 19.2 s (88 and 178 retries) | 0.01 s after healthy (no retry) |
| Read system calls (process) | 261 865 (one start) | 5 132 to 5 162 |
| CPU time of the daemon | 6.6 and 7.0 s | 0.10 to 0.14 s |
| Certification | 7.2 s (one logged start) | 71 and 167 ms (two logged starts) |
| Restart with a valid watermark | | 0.15 to 0.26 s, no record read |

The absolute times depend on the machine, the counts and the ratios much
less. `scripts/chaos.py` now fails a restart that takes more than
`--max-recovery` (10 s), a run whose last 50 restarts have a median
`--max-recovery-growth` (5 s) above that of the first 50, and a history read
that answers 503 after a restart. Every certification logs `secret inventory
certified` with the LSN range, the number of records read and the time it
took.

## M32 benchmark and regression contract

The M32 targets are unchanged:

| Scenario | Required physical test environment and target |
| --- | --- |
| Counter | Three separate nodes, each 4 vCPU and 8 GB: at least 20,000 committed turns/s |
| Gateway | 5,000 requests/s with p99 below 50 ms |
| Distributed replay | At least 50 times the recorded production window's real duration |
| Leader replacement | A replacement leader within 10 s of node loss |
| State | 100 GB per node, including working snapshots and compaction |

Three processes on one host are not three machines or failure zones. The
historical single-node results above and the runner below do not close these
targets. No target is adjusted without an ADR and actual measurements.

### Reproducible public single-node control

`scripts/benchmark-single-node.py` exercises an already-built real daemon via
its public CLI/API and HTTP gateway. It starts only its own fresh fixture
directory and process group; it never installs a service, deletes an existing
data directory or loads an unrelated application. It measures committed
counter throughput, open-loop gateway p99, an identity replay in both modes,
and snapshot creation. Replay timing includes the public CLI round trip and
diff construction, and its production window is the fixed open-loop row,
not a faster release's variable-throughput row. This is **single-node
replay**, not distributed replay, and no leader-replacement or 100-GB result
is synthesized from it.

Example after building the binary and dependency-free load generator:

```sh
python3 scripts/benchmark-single-node.py \
  --binary target/release/kronik \
  --loadgen tools/loadgen/target/release/kronik-loadgen \
  --guest tests/guests/counter.wasm \
  --revision <exact-40-hex-source-commit> --rig-id <stable-test-rig-id> \
  --workdir /var/tmp/kronik-benchmark --port 47813
```

Run it in an isolated test environment with explicit resource limits. The
offline sandbox supplies a read-only source/toolchain container with 3 CPUs,
8 GiB memory, 128 processes, 6 GiB bounded scratch and a 900-s wall deadline;
its scratch is **tmpfs**. That setup is suitable for a functional smoke, not
disk/fsync or physical M32 acceptance. It only uses an already-local image
and cached dependencies; it never pulls an image or fetches a tool. Source,
toolchain and local image are explicit arguments. It runs with all
capabilities dropped and no host home, socket or host process/network
namespace.

The emitted `benchmark.json` is `kronik.benchmark/v1`. It records the exact
binary and guest SHA-256, source revision, rig id, placement, kernel,
architecture, filesystem, CPU/memory limits, generator and harness SHA-256, and
workload settings. Raw command results remain in the run directory. Repeated samples
use their median; errors, a missing result, a changed identity diff or omitted
root input fail the run. Preserve the binary, revision and raw results when
publishing a measurement. Do not publish a partial/failed run as a benchmark.

The maintained load generator keeps a fixed histogram instead of every
request's latency. Its path/header/body templates are parsed once per worker;
constant values remain borrowed and key substitutions reuse preallocated
buffers rather than allocating on every request. Quantiles conservatively
round upward by no more than 3.125%, with an exact maximum; response bodies are
drained through a bounded buffer. Numeric loopback/IP endpoints avoid unbounded DNS time. A complete
request has a five-second deadline. Unsupported framing, capped responses,
network failures, worker failures and unsent open-loop slots are errors, not
successful requests omitted from the denominator. `elapsed_seconds` is actual
measurement time including in-flight drain, and throughput uses that value,
not an invented duration.

### Between-release regression enforcement

```sh
python3 scripts/check-performance.py baseline/benchmark.json candidate/benchmark.json
```

The comparator fails a decrease greater than 10% for a higher-is-better
measurement or an increase greater than 10% for a lower-is-better measurement.
Exactly 10% is allowed. It refuses invalid/nonfinite numbers, duplicate or
missing scenarios, error-bearing measurements, incompatible units/directions,
changed guests, and changed rig/profile/workload configuration. A smoke
artifact cannot be compared to a physical-cluster artifact. Source/binary
provenance may differ between releases; the workload and generator must not.
It does not download, invent or silently skip a missing release baseline.

The comparator's synthetic tests are checks of enforcement, not performance
measurements. Current proof: the bounded offline sandbox invocation of
`python3 -B -m unittest discover -s scripts/tests -p test_check_performance.py`
passed 25 tests on 2026-10-31. This is not a physical benchmark result.
The comparator and its required test hook are on `main` at `425cc3fd`.
The broader Python suite now runs in the same existing CI step; the existing
examples step tests the standalone generator, and the existing SDK/product
step gates actual documentation and compatibility.
Comparing real release artifacts still requires the actual baseline/candidate
measurements from the same provisioned rig and workload.

The full public cluster benchmark depends on the cluster's actual startup,
join, routing, distributed replay and lifecycle consumers, which the cluster
track (M16–M19) will provide; a private RawNode fixture is not substituted.
Provisioning the three physical nodes and space for 100-GB state plus
snapshots/compaction remains necessary. The runner and comparator above
preserve that distinction rather than reducing M32's scope.

### Exercised local control, 2026-10-31

The real public-binary runner completed with exit 0 in the bounded offline
sandbox. This is a **debug-build functional smoke on tmpfs**, not an M32
hardware measurement or release-regression baseline. Source was commit
`d9b946f29e3152fe94f34da32a40ef35983ed302`; the exact executing binary digest
is retained rather than calling it a release build.

| Actual smoke setting/result | Observed |
| --- | --- |
| Resources | 3 CPU quota, 8 GiB memory, one process/node, tmpfs |
| Rows | 0.5 s requested, 0.1 s warmup, 4 clients, 8 keys, one repetition |
| Counter acknowledged throughput | 726.298 turns/s |
| Gateway | 20 requests/s; p99 8.912895 ms |
| Single-node identity replay, both modes | 5.378978928170382x; complete and unchanged |
| Snapshot creation through public CLI | 32.470348989591 ms |
| Load-generator boundary tests | 5 passed, 0 failed, 0 ignored |

The recorded result is summarized on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence) page. Binary SHA-256:
`149fe62fe088267992a1eec40853947c89daab9c38b58acb44cf0bf6a1fc5408`;
load generator:
`d5694ef72b0dc6158eea937af9c9aa2fda5e615c06de33010135f895095cfb25`;
counter guest:
`747c8630dfe34766b8b29f81787145b0c5061acef875be5c2c04c8da4ea70fb5`.

The exercised inner commands were:

```sh
cargo test --locked --offline --manifest-path tools/loadgen/Cargo.toml
cargo build --locked --offline --manifest-path tools/loadgen/Cargo.toml
cargo build --locked --offline -p kronik
python3 -B scripts/benchmark-single-node.py \
  --binary target/debug/kronik \
  --loadgen target/debug/kronik-loadgen \
  --guest tests/guests/counter.wasm \
  --revision d9b946f29e3152fe94f34da32a40ef35983ed302 \
  --rig-id docker-3cpu-8g-tmpfs \
  --workdir /var/tmp/kronik-benchmark --port 47813 \
  --seconds 0.5 --warmup 0.1 --gateway-rate 20 \
  --repetitions 1 --concurrency 4 --keys 8
```

The build took 2 min 52 s and the complete group 237.34 s. These are
resource and proof-command timings, **not** substituted production/replay durations. The
runner measured those scenarios with actual monotonic clocks.

### Request-buffer and caller regression proof, 2026-10-31

The later bounded run used the actual published v0.3.0 musl binary
`1681833ad84da60622a6c196b8084bbe52a2deb8f6860a26c81dc9ea4f4a3947`
and the optimized, updated generator
`e9cebaee012ee0b000ef5c3c7055326ba62a2b4a6b0d4ae65dc6a69b2ce378b4`.
All seven generator boundary tests passed, including borrowed constant
templates and stable buffers across multiple key substitutions. The actual
public single-node smoke recorded 1002.206 committed turns/s, gateway p99
4.718591 ms at 20 requests/s, complete unchanged replay at
18.446705178995746x, and a snapshot in 16.251779161393642 ms. Its exact
result is summarized on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence) page.
Different binary/build and generator provenance make it **not comparable**
to the earlier debug smoke as a between-release regression baseline, and
neither is physical M32 acceptance.

The same run reproduced the existing shell caller's failure masking using
its actual committed `d9b946f2` source, SHA-256
`7a5ff7ed8c8956ff49cea7cf65f852e04bcc6717e93adbaf6f49d0dafd6d3d19`.
With the real daemon and generator under the configured process limit, it printed
HTTP 503 and worker-spawn failures but returned **0** after all five rows.
The changed caller printed its first failing 64-client row, returned **1**,
and did not run the later rows. This is observed failing-before/passing-after
error propagation, not a fabricated success or a throughput result. Retained
raw measurements and statuses are summarized on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence)
page.

That combined group's outer exit was 1: 60 of 61 Python tests passed and the
new source-dispatch inventory exposed six missing comma-less block arms in
its parser; its book command also selected the wrong directory, and the
historical v0.3 binary lacks the modern bounded-integrity candidate API.
Those separate failures were not hidden by the successful generator, caller
and benchmark checks. The dispatch parser was corrected with a permanent
block-arm regression case; book invocation and candidate prerequisites were
corrected without weakening the checks or regenerating the old corpus.

### Actual historical between-release gate, 2026-10-31

The final generator formats only the first recorded failure cause, rather
than allocating another diagnostic for every subsequent failed request.
All **eight** generator boundary tests passed, with no failed/ignored tests.
Its optimized binary SHA-256 is
`04ef44c2d970eaf9232ffa6f4ff43a92fd8174bc473a406ec94cbf8a6d878ef9`.

The real v0.1.0 and v0.3.0 published musl binaries then ran the same public
harness, guest, generator and isolated rig: 3 CPUs, 8 GiB, tmpfs, four clients,
eight keys, 2 s per measured row, 0.25 s warmup, 100 gateway requests/s, three
repetitions. Both completed with zero request errors. The actual comparator
returned **1**, correctly refusing the greater-than-10% gateway regression:

| Measured control | v0.1.0 | v0.3.0 | Gate |
| --- | ---: | ---: | --- |
| Committed counter turns/s | 996.503 | 926.867 | -6.98804%, pass |
| Gateway p99, ms | 5.111807 | 6.160383 | +20.5128%, **regression** |
| Single-node replay ratio | 19.80287999354438 | 19.604726621660145 | -1.00063%, pass |
| Snapshot creation, ms | 16.411247896030545 | 16.480289865285158 | +0.420699%, pass |

The comparator scans a baseline and a candidate report with
`python3 scripts/check-performance.py BASELINE CANDIDATE`; the recorded
reports for this comparison are summarized on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence)
page and are not part of the repository.

This is an exercised historical release comparison, **not a causal diagnosis,
latest-product regression baseline or physical M32 acceptance**. The short
same-host control does not explain the latency difference. It was not rerun
until green, and neither the threshold nor workload was relaxed. The
recorded gate report on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence)
page records `comparator_status: 1` and `gate_passed: false`; the combined
outer group also returned 1 rather than hiding that failure.

The retained `d9b946f2`-based debug binary separately completed the final
generator smoke: 701.484 committed turns/s, p99 8.257535 ms at 20 requests/s,
complete unchanged single-node replay at 5.350388559264805x, and a snapshot in
32.40831685252488 ms. Its exact result on the
[performance evidence](https://github.com/G-man3207/Kronik/wiki/Performance-evidence)
page has different workload settings and is not compared to the historical
pair.


### Adoption boundary and latest semantic tests

These reports preserve observations made on `d9b946f2`-based and historical
release builds, not on the current integrated binary.
The immutable follow-up `d6759bc28a0724eb4a8ed1bd09eeb2685966ff30` removes
implementation-only pointer/borrow/call-count assertions. Its seven tests check
rendered bytes across all slots and shrinking substitutions, failure totals and
first cause, histogram bounds, HTTP framing, invalid settings and missed slots.
The older eight-test receipt remains unchanged. Current-product compatibility,
documentation generation and real release-regression results must use the
final coherent built product; physical M32 targets remain open.
