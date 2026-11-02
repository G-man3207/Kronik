# 0108. Durable secret-coverage watermark

- **Status:** Proposed
- **Date:** 2026-11-02

## Context

The certified secret catalogue is memory-only: every restart starts
uncertified, and the only recertification is a whole-log reference scan whose
cost grows with the log while consumers wait `secret refresh/fetch_timeout`
(2 s). On any real restart with a grown log this made scrubbed reads and
secret writes answer 503 `SECRET_UNAVAILABLE` for a long window — v0.3's
green DST webhook run and 1000-cycle chaos test became deterministic
failures on the current tree (DST webhook seeds 0, 2, 3 never certified;
chaos cycle 1's history check hit the 503). Fail-closed during the window is
a recorded design decision; the defect is that the window is long and grows.

Two companion fixes land with this decision and bound it from the other
side: committed mutations answer success with their reason fields withheld
(the one field `audit()`'s own scrub path already withholds) instead of
stalling, and every certified read probes the retained bytes' loadability —
a replaced or damaged store retires the certificate instead of a warm
in-memory snapshot answering over bytes that are gone.

## Decision

Persist a coverage watermark in `<data>/secret-coverage.json`, written after
each fully successful refresh: schema, branch, certified-through LSN,
coverage epoch and fingerprint, and the secret store's random generation
(minted by `randomblob(16)` in the store's own `store_identity` table). The
next restart validates it — same branch, same store generation, LSN within
the retained log — and certifies the prefix from the watermark, re-scanning
only the log appended after it. Anything that can invalidate it forces the
full scan: a restored or replaced store (generation mismatch), an erasure or
reseal (coverage retirement, next cycle writes a fresh watermark), retention
or compaction cutting the log below the watermark, or any unreadable
manifest. The watermark is written only after in-memory coverage is fully
set, so a crash mid-write costs a bigger scan, never a wrong certificate.

Error semantics are deliberately the opposite of the export cursors', whose
style (temp file + atomic rename, byte budget) the manifest reuses: a
missing, corrupt, unparseable or failed-validation watermark is discarded
with a warning and the next refresh falls back to the full scan. A cache
artifact may cost re-scan time; it may never cost availability or
correctness, and it must never block startup. The file is a daemon-local
cache: it is never shipped, and restore always voids it (a restored store
carries another generation, and the file itself is not part of any shipped
or restored set).

The per-read store probe stays: the watermark bounds how much log a restart
must re-scan; it does not weaken the read path's physical-readability check.

## Alternatives

- A state.db metadata row: rejected to keep certification state out of the
  log-schema path and to mirror the existing durable-cache mechanism
  (M28 export cursors) rather than add a store schema surface.
- Retrying the window in clients (chaos, DST harness): rejected as the fix —
  the window was unbounded and deterministic on grown logs; retrying would
  paper over a regression. Harnesses keep the CLI's bounded retry (30 s,
  100 ms backoff) as hygiene for the documented brief transient.
- Trusting a warm snapshot across store damage without a probe: rejected —
  that was the fail-open gap (audit reads answered 200 over unloadable
  retained bytes).

## Consequences

Post-restart certification is O(append) instead of O(log): DST webhook seeds
0-3 pass deterministically and chaos restarts no longer observe the window
at all. A stale or voided watermark costs only re-scan time. New trust
surface: the manifest must never become authoritative on its own — its
validation is generation- and branch-pinned, its failure mode is fallback,
and erasure/reseal semantics must keep re-verified against the delta rule
(per-record, monotone union) as the suite grows. Revisit if a restore path
ever ships or preserves the manifest.
