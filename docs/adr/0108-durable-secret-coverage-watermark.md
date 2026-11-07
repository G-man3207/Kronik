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

## Amendment (2026-11-07): what a refresh may read and write

The consequences above promise a cost, and v0.4.0 did not keep it: in
the crash test the time from `kill -9` to a healthy daemon grew from
0.04 s at the first cycle to 24 s at the 326th, and scrubbed reads
answered 503 for as long again after every restart. The causes were in
the implementation, so the decision stands, and these rules bind it:

1. A refresh reads the records after the watermark, once, up to the
   applied LSN it started at; what is applied while it runs is for the
   next refresh or restart to read. It reads from the first retained
   record only when no valid watermark exists. (v0.4.0 ran a second scan
   from the log start after the one that resumes at the watermark.)
2. Only a finished certification writes the manifest, and always with
   its certified LSN: the last record its scan read, not the applied LSN
   of the moment it writes, so that a restart never skips a record that
   no scan read. The manifest never records the progress of a scan under
   way. (v0.4.0 stored a checkpoint after every 2,048 records with
   certified LSN 0, which `load()` refuses, so every start that was
   killed left no watermark.) A manifest that still has the old
   `scan_frontier` field is read as before.
3. A watermark ahead of the applied log covers nothing this log holds
   and is ignored.
4. The log is read in whole segment images decoded on the blocking
   pool, not with `LogReader::read_while`. Its first read in a segment
   validates every record before the requested one with two blocking-pool
   round trips per record, so one scan that starts late in a segment is
   linear in the segment, and a scan made of short windows is quadratic.
5. A node that certified the inventory when it started keeps that
   certificate: the first pass of the secret cycle still observes the
   current versions, but does not rebuild a certificate that is moments
   old, because a rebuild clears the certificate for as long as it runs.
6. The coverage fingerprint identifies the inventory (ledger rows, links
   and file rows), not the part of the log that a build read, so the
   references a scan meets are not hashed. The manifest schema is v2 for
   that reason.
7. A v1 manifest (v0.4.0) is not trusted. v0.4.0 stored the applied LSN
   of the moment it wrote the file, which can lie ahead of the last
   record its scan read by every record applied while that refresh ran
   (the refresh took seconds on a grown log). Skipping up to it could
   skip records that no scan read, so a v1 manifest is
   treated like a missing one: one info line, a scan from the first
   retained record, and a v2 manifest written by that certification. The
   first start after an upgrade from v0.4.0 therefore reads the whole
   retained log once.

Every build logs `secret inventory certified` with the LSN range it
read, the number of records and the time it took, which is where to look
when a start is slow.

The crash test enforces the cost: it fails a restart that takes more
than `--max-recovery`, a run whose last 50 restarts have a median
`--max-recovery-growth` above the first 50, and a history read that
answers 503 after a restart (`scripts/chaos.py`).

Not changed, and still open: a rebuild clears the certificate when it
starts, so a forced or periodic rebuild is a window of 503 for reads
that scrub their output, as long as the rebuild; and a start waits for
its first certification however long that takes.

## Amendment (2026-11-07): sealed requests of erased subjects

The scan opens every sealed request of an effect that can carry a secret
(`http.fetch`, `foreign.http`, `crypto.hmac-sha256`, `crypto.sign-ed25519`,
`secret.reveal`), because only the plaintext tells whether it cites a
version. v0.4.0 read a request it could not open as a loss of coverage.
Erasing a subject (`kronik privacy erase`) destroys its key on purpose, so
the sealed `http.fetch` of any of its turns could never be opened again:
every output that scrubs answered 503 `SECRET_UNAVAILABLE`, with no secret
in the store, for as long as a refresh had that request to read. The
watermark of the first amendment hides it while the request lies before
the watermark; any scan from the first record brings it back (a v1
manifest, a restore, a lost manifest, retention cutting the log below the
watermark). The sealer already tells the two ways a sealed value fails to
open apart, and the scan now follows it:

8. An erased request cites nothing. Its subject's key was destroyed on
   purpose, or a reseal left a tombstone for it: the content is gone for
   everyone, this node included. The scan counts it and goes on
   (`erased_requests` in the `secret inventory certified` line counts the
   effects it skipped; the effect of a finished turn is met twice, in its
   own record and in its turn's).
9. A request that is unreadable and not erased refuses coverage. A request
   the sealer cannot open and has not erased (no key store, no such key
   version, a value that fails to unseal) is not gone: a restored key store
   may hold its key, and nothing says what it cites. The refresh fails with
   `SECRET_UNAVAILABLE`, as before, until the key is back.
10. Skipping loses no scrub value. A certificate scrubs against the ledger
   rows, the retained snapshots and the provider catalogues; the references
   a scan finds are checked against them and never added to them, so a
   skipped request removes nothing from what is scrubbed. Nothing releases a
   version because the requests that cited it were erased (there is no
   collector of retained versions). What the skip gives up is the check that
   such a request cited a version the ledger knows.
11. An erasure does not void the watermark. The Decision lists an erasure
   among the events that force a full scan; no code does that. An erasure is
   a configuration epoch: it retires the certificate, and the next refresh
   reads the records after the watermark, as after a deployment. A scan from
   the first record reads the same sealed requests and now passes the erased
   ones.

A scan of a log with many erased subjects costs one key store lookup per
erased request: the sealer caches the keys that exist, not the erasures.
