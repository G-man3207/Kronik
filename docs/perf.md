# Performance

Measurements of the daemon against the brief's targets. Every number here
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

| | dev | test VPS (`travelfiesta`) |
| --- | --- | --- |
| CPU | AMD EPYC 9354P, 8 vCPU, shared with other work (load average 5 to 10 during the run) | Intel Xeon Skylake, 2 vCPU |
| Memory | 31 GB | 4 GB |
| OS | Debian 13 | Debian 13, no `/dev/kvm` |
| 4 KiB `O_DSYNC` write | 1.08 ms | 0.85 ms |

## Results (M1, 2026-10-25, commit 560d350)

Committed turns per second, and request latency in ms:

| Workload | dev turns/s | dev p50 / p99 | VPS turns/s | VPS p50 / p99 |
| --- | ---: | --- | ---: | --- |
| 1 actor, 1 client | 181 | 4.9 / 12.8 | 174 | 5.2 / 12.7 |
| 1 actor, 16 clients | 206 | 76.9 / 97.2 | 190 | 82.7 / 114.3 |
| 64 actors, 64 clients | 7 842 | 7.6 / 17.6 | 2 769 | 21.9 / 49.6 |
| 256 actors, 256 clients | 7 995 | 29.8 / 72.0 | 2 774 | 91.6 / 167.9 |
| 256 actors, open loop 200 req/s | 200 | 5.1 / 11.8 | 200 | 5.7 / 22.9 |

`scripts/acceptance-m1.sh` (10 000 sequential-per-actor increments from 16
clients to one actor) took 45.9 s on dev and 58.4 s on the VPS.

## Against the brief's targets

- **At least 1 000 committed turns/s for the Rust counter with group
  commit.** Met across actors: about 7 900/s on dev and 2 770/s on the
  2-vCPU VPS, with no errors. **Not met for a single actor**, which commits
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
- **Gateway p99 below 25 ms at 200 req/s.** Met: 11.8 ms on dev and
  22.9 ms on the VPS, where the margin is small (the load generator runs on
  the same two vCPUs).

## Replay speed (M3)

The brief's target: replay of the reference workload at 20x real time or
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

### Results (dev, 2026-10-25, commit 0047670)

Dev is shared: load average 6 to 11 during these runs, so the numbers move
by a factor of up to two between runs.

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

travelfiesta, 2 vCPU, release, `replay_speed --workers 2`. 12 000 requests
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

travelfiesta, release, `replay_speed --workers 2`, 12 000 requests at
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
- **Per turn, the kernel took a fifth** (perf, dev, isolated replay on one
  core): page faults and `madvise` from the Wasm pooling allocator, which
  zeroed 64 KiB of a reused memory slot and returned the rest, so every
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

Measured on travelfiesta (4 GB): `kronik serve` from the same tree with
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

The brief: "start with 1 GB of log after the latest snapshot: under 30
seconds" (docs/design/m6-storage.md §9).

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

### Results (dev, 2026-10-26, commit c4d1904)

The log after the snapshot: 3 072 001 records, 1.00 GiB, about 350 bytes
per counter turn record. Load average 9 to 17 on the 8 vCPUs during these
runs (other work on the machine), so absolute times are pessimistic; the
ratios between rows hold.

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

travelfiesta, release, `startup_speed --reuse`, 1.00 GiB log, `state.db`
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

travelfiesta, release, `startup_speed --gib 1.0 --reuse` on a log this
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

What the profile showed (perf on dev pinned to two cores, then timers in
an instrumented VPS build; not committed):

- **The apply thread set the pace, not decoding.** In a 20.4 s replay it
  spent 9.7 s applying, 4.4 s freeing the decoded records (allocated on
  the decode thread, freed on the apply thread) and about 1.3 s moving
  them (a `Committed` is 1 KiB) into batches, and waited 5 s for decode.
  Applying ran three prepared-statement cache lookups per record (two
  DELETEs on the empty `open_turns` and `open_effects`, the `turn_index`
  insert) and cloned keys into hash maps.
- **Decoding a segment into a vector touched fresh memory every time.** A
  segment decoded into 190 000 records holds about 200 MiB; on dev a
  quarter of decode time was the kernel faulting pages in, and on the VPS a
  cold segment decoded in 1.1 s against 0.7 s warm.
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

The brief: "The `off` mode has no measurable overhead compared to M6.
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

### Results (dev, 2026-10-25)

BASE is `28aac17`, the parent of the sealing commit. NEW is `28aac17` with
only the M8 commits on top (`c99061f`, the API fix `ed47360`, `c90a633`,
`eaf56b8`). 5 runs, niceness -10, while other agents' builds and tests
kept the load average between 6 and 23 on the 8 vCPUs:

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

### Results (dev, 2026-10-25, commit 2e3740f)

Dev was shared during these runs (load average around 20 on 8 vCPUs), and
the runs overlapped. Wall times are therefore upper bounds.

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
