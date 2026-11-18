# 0156. The SQL pool grows with the actors opened

- **Status:** Accepted
- **Date:** 2026-11-18

## Context

ADR 0005 keeps one SQLite file per actor and an LRU of connections. The
prototype sized that LRU at 256. The live node still hardcoded 256.
`SqlPool::get` opened a miss while holding the pool mutex, and turn apply
called `get` while holding the apply lock.

Past 256 SQL actors, almost every distinct actor missed, dropped a 512 KiB
page cache, and paid a SQLite open on the apply path. That open stalled
every turn waiting on the applied LSN, and it stalled other actors' applies
on the pool mutex. File descriptors are the real bound: two per actor (the
database and its WAL), and `kronik serve` already raises the soft open-file
limit to the hard one. Issue #195.

Opening under the apply lock is not required for the invariant that a
record's SQL is applied before `state.db` takes it. The open can happen
before the lock. The apply itself stays under the lock.

## Decision

- A miss opens outside the pool mutex. One thread opens a given actor;
  another `get` of that actor waits on it, and a `get` of a different actor
  does not.
- `Store::apply`, a rebase copy and `erase_again` pin the actor databases
  they will write before taking the apply lock. A cold open does not run
  under that lock.
- The live pool starts at 256 and grows with the actors it opens, up to the
  point where two descriptors per actor would leave fewer than 1024 for the
  log, `state.db` and the listeners. It does not preallocate that cap.
  Pools constructed with an explicit capacity still evict past it.

## Alternatives

- **A `[sql] pool_size` knob, still defaulting to 256.** An operator can set
  it, and an operator who does not still pays an open on every turn past
  256. The file-descriptor limit is already the knob (`LimitNOFILE`).
- **Never evict.** A node with more actors than descriptors fails the next
  open, including the log's. The cap is that limit, not an unbounded cache.
- **Keep 256 and only move the open outside the lock.** Other actors' applies
  are no longer stalled on the mutex, and the applier still pays the open
  before the applied LSN advances. That is the cost the 256 cap causes.

## Consequences

A deployment whose working set fits in the cap does not reopen an actor
database on the apply path. One that does not still opens outside the apply
lock and outside the pool mutex. Each retained connection may hold a 512 KiB
page cache; 1 000 actors are about 512 MiB of cache, allocated as pages are
used, plus two descriptors each. Raising `LimitNOFILE` raises the cap.
Revisit if actor counts reach the 100k the page-store VFS in ADR 0005 was
deferred for, or if the 1024 left for the rest of the process is no longer
enough for the log.
