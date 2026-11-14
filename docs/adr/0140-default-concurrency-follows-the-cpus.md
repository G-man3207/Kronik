# 0140. The default turn concurrency follows the CPUs

- **Status:** Proposed
- **Date:** 2026-11-14

## Context

`kronik serve --concurrency` is how many turns run at once: the scheduler's
worker permits. Its default was 64 on every machine. The Wasm instance pool
is sized from it: `2 × concurrency` linear-memory slots, and a slot that an
instance used keeps up to 2 MiB resident afterwards, so that the next
instance does not fault those pages back in
([`docs/perf.md`](../perf.md), "Memory cost of the resident Wasm memories").
At 64 the pool may keep 256 MiB warm.

M24's load acceptance ([the design](../design/m24-connections.md),
criterion 1: 1,000 WebSocket clients in 50 rooms, one message per client
every 10 s, the daemon confined to 2 CPUs and 4 GiB like the 2-vCPU VPS)
ran on the shipped static musl build of main 3c29fa42:

| `--concurrency` | Steady phase | Heap growth (RssAnon) | p99 | Max |
| --- | --- | --- | --- | --- |
| 64 | 10 min | +95 MiB | 247 ms | 2.85 s |
| 64 | 30 min | +119 MiB | 319 ms | 2.8 s |
| 8 | 10 min | +6.7 MiB | 168 ms | 0.54 s |
| 8 | 30 min | +25.7 MiB | 172 ms | 1.24 s |

On 2 CPUs, 64 turns at once do no more work than 8 or 16: they wait for the
same two CPUs. Each new peak of turns in flight touches pool slots that no
turn used before, and those slots stay warm. At 64 the heap grew in such
steps; at 8 the pool was warm within 5 minutes. The slower growth from about
17 minutes on, at both settings, is attributed to the room actors' SQLite
page caches (512 KiB per actor database, at most 25 MiB for 50 rooms), which
this decision does not touch.

The throughput target ([ADR 0111](0111-cross-actor-throughput.md))
is 1 000 committed turns/s across actors; it measured 2 770 turns/s on the
2-vCPU VPS at the old default.

## Decision

Without `--concurrency`, `kronik serve` runs 8 turns at once per CPU it may
use, at least 8 and at most 64: `clamp(8 × available_parallelism(), 8,
64)`. Rust's `std::thread::available_parallelism` counts the process's CPU
affinity and a cgroup v2 CPU quota, so a daemon on a 2-vCPU machine, in a
systemd unit with `AllowedCPUs=` or `CPUQuota=`, or in a container limited
to 2 CPUs runs 16; from 8 CPUs the default stays 64. An explicit
`--concurrency` is used as given. The `kronik is serving` log line shows the
value.

## Measurements

On kronik-test (4 vCPU, 7 GiB; the static musl build of this change), with
[`docs/perf.md`](../perf.md)'s method (`scripts/perf-m1.sh`, the counter,
10 s per row, no errors in any row), turns/s across actors:

| CPUs | `--concurrency` | 64 actors | 256 actors | 200 req/s p99 |
| --- | --- | --- | --- | --- |
| 2 (daemon confined, load generator on the other 2) | 16 (new default) | 2 656 | 2 644 | 28.8 ms |
| 2 | 64 | 2 612 | 2 624 | 31.5 ms |
| 4 (shared with the load generator) | 32 (new default) | 3 016 | 2 782 | 31.5 ms |
| 4 | 64 | 3 022 | 2 797 | 30.4 ms |

The new default is as fast as 64 within the noise, and ADR 0111's 1 000
turns/s across actors holds. From 8 CPUs the default is 64, so the
development machine's results in `docs/perf.md` stand. At the defaults (16
on 2 CPUs) M24's criterion 1 passes every check (heap +12.4 MiB over the
steady 10 minutes, p99 151 ms, all 1 199 600 deliveries) and criterion 4
passes (reconnects within 3.1 s).

## Alternatives

- **Keep 64 and change M24's memory criterion to the pool's bound.** The
  pool is bounded, but on a small machine the extra permits buy nothing and
  cost memory and tail latency. Rejected.
- **Keep less resident per slot.** `linear_memory_keep_resident` is 2 MiB
  because a replay instantiates the same component thousands of times and
  faulting the pages back in cost about a fifth of isolated replay. Lowering
  it slows replay on every machine. Rejected.
- **Bound the warm slots instead** (wasmtime's `max_unused_warm_slots`).
  This would keep 64 permits on 2 CPUs and their tail latency. Not chosen; it
  can still be added later.
- **A fixed smaller default, such as 16.** This would cap throughput on large
  machines. Rejected.

## Consequences

- On 2 CPUs the pool keeps at most 64 MiB warm instead of 256 MiB, and the
  tail latency of a busy small machine drops.
- From 8 CPUs nothing changes.
- An operator who wants the old behaviour on a small machine sets
  `--concurrency 64`.
- The M24 load acceptance runs at the defaults.
- Revisit if a measurement at the new default falls below the 1 000
  turns/s target, or if a machine with many CPUs needs more than 64 turns at
  once.
