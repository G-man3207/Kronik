# 0005. Per-actor SQL state: sessions, changesets and one file per actor

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

The brief ("SQL-tillstånd per aktör", M0 spike E) gives every actor its own
SQLite database, owned by the host.

- **Turn mechanism:** a turn's statements run in a savepoint; the session
  extension captures them as a changeset; the savepoint is rolled back; the
  changeset is applied. Production, recovery and replay therefore build the
  database the same way.
- **DDL** is recorded separately and allowed only in `migrate`, before the
  first DML.
- **Determinism:** `random()`, `datetime('now')` and similar follow the
  turn's seed and logical time.
- **Denied:** extensions, `ATTACH`, `VACUUM`, `ANALYZE` and pragmas that
  affect storage.
- **Subjects:** changesets are split per subject via `_subject`.
- **Size:** capped per actor (1 GiB).
- **Open questions:** whether tables without `PRIMARY KEY` can be tracked
  safely, and how the databases are stored.
- **M3 and M6 needs:** forks need every actor's SQL state at the fork LSN;
  isolated replay needs an actor's production state at any LSN in the
  retention window, with a throw-away overlay; snapshots must be consistent;
  privacy-mode erasure must delete a subject's rows physically; the
  simulator opens SQLite in memory (ADR 0004, the `SqliteOpener` seam).

Spike E (`spikes/spike-e-sql/`) is the prototype. It uses `rusqlite =0.41.0`
with bundled SQLite 3.54.0 (`libsqlite3-sys =0.39.0`).

- **`SqlActor`** wraps one actor database.
- **`ffi.rs`** is the only module with `unsafe` code.
- **`check`** runs 30 checks. All pass on the dev machine (AMD EPYC 9354P)
  and on the testbench VPS (Intel Skylake, 2 vCPUs).
- **`bench`** does the measurements, on real disk (`/var/tmp`, not tmpfs).

## Decision

### 1. The turn mechanism

1. **`begin_turn`** sets the turn's logical time and seed and resets
   `last_insert_rowid()`. It then opens `SAVEPOINT kronik_turn` and a
   session on all tables except `_kronik*`. Rowid tables are tracked (see 3).
2. **Each guest statement:**
   - It is authorized (section 5).
   - It runs inside `SAVEPOINT kronik_stmt`, so a statement that a
     post-check rejects can be undone alone.
   - Its VM steps are added to the turn's SQL fuel.
3. **`end_turn`:**
   - Capture the changeset and split it per subject (section 6).
   - Then `ROLLBACK TO kronik_turn; RELEASE kronik_turn`.
   - If SQLite rolled the whole transaction back itself (`SQLITE_FULL`,
     `INSERT OR ROLLBACK`, `RAISE(ROLLBACK)`), the turn is *poisoned*: later
     SQL calls fail and the turn fails.
4. **The turn record** stores `sql_schema` (the DDL text, in order) and
   `sql_changes` (one `Sealable` changeset per subject).
5. **Apply** happens after the record is durable, in the single LSN-ordered
   applier (ADR 0004). In one savepoint it does three things:
   - replays the DDL;
   - applies the changeset with `sqlite3changeset_apply_v2(...,
     SQLITE_CHANGESETAPPLY_FKNOACTION)`, aborting on any conflict;
   - sets `_kronik_meta.applied_lsn`.

   Details:
   - The live apply uses the unsplit changeset in one call. Rebuilds,
     forks and replay apply the per-subject changesets from the log.
   - Triggers are disabled during apply (their effects are already in the
     changeset), but only when the schema has triggers, because toggling the
     flag expires every prepared statement.
   - A conflict during apply means the database is not in the state the log
     says it is: `STORAGE_CORRUPT` on recovery, `REPLAY_DIVERGED` in replay.

**Verified** (`changesets/memory`, `changesets/file`): 60 mixed turns, with
118 inserts, 1,059 updates and 15 deletes in 56 KB of changesets. The
canonical hash (schema plus every row in key order, type-tagged, BLAKE3) of
the savepoint/changeset database equals that of a database built by direct
execution, and equals a clean copy rebuilt from the log. The memory and file
openers give identical hashes. Trigger effects and `ON DELETE CASCADE`
effects rebuild exactly (`apply/triggers-and-cascades`).

### 2. DDL: only in `migrate`, only before the first DML

A changeset is a per-row *net* result at the end of the turn, not an ordered
log. The recorded DDL is replayed as a separate list *before* it. Measured
with DML, then DDL, then DML in one session (`ddl/mid-turn-breaks-rebuild`):

| Mid-turn DDL | Result |
| --- | --- |
| DDL first (`ADD COLUMN`, then `INSERT`) | rebuild == direct |
| `INSERT`, `ADD COLUMN`, `UPDATE` | rebuild == direct (works in 3.54) |
| `INSERT`, `RENAME COLUMN`, `UPDATE` | rebuild == direct (works in 3.54) |
| `UPDATE`, `DROP COLUMN` | `sqlite3session_changeset` fails (`SQLITE_SCHEMA`) |
| `INSERT`, `RENAME TO`, `UPDATE` | `sqlite3session_changeset` fails |
| `INSERT`, `DROP TABLE` + `CREATE TABLE`, `INSERT` | `sqlite3session_changeset` fails |

The rule ensures capture can never fail, and it does not depend on which
`ALTER` variants a given SQLite version can handle. It is enforced through
the authorizer:

- A statement is DDL if it writes to the schema table or uses a
  CREATE/DROP/ALTER action.
- DDL outside `migrate` is denied with `denied("DDL is only allowed in
  migrate")`.
- DDL after the first DML of the `migrate` turn is denied with
  `denied("DDL must come before the first DML statement of the migrate
  turn")`.
- A statement that is both DDL and DML is denied, which covers `CREATE TABLE
  … AS SELECT`.
- DDL text is recorded exactly as executed and replayed before the turn's
  changesets (`ddl/recorded-and-replayed`: `ALTER TABLE … ADD COLUMN … NOT
  NULL DEFAULT`, then `CREATE INDEX`, then DML; the rebuild matches).

### 3. Tables without `PRIMARY KEY`: allowed

`SQLITE_SESSION_OBJCONFIG_ROWID` (SQLite ≥ 3.45) tracks tables without a
primary key as if they had a leading `_rowid_ INTEGER PRIMARY KEY`.

- **With it:** duplicate rows, `INSERT … SELECT`, and `UPDATE`/`DELETE` by
  rowid all rebuild exactly (`rowid/tracked-with-objconfig-rowid`).
- **Without it** (the default), sessions record nothing for such tables,
  and the turn's writes are silently lost (`rowid/ignored-without-it`).

What makes this safe:

- Applies carry explicit rowids.
- `VACUUM`, which could renumber rowids, is denied.
- The canonical hash includes the rowid for tables without a primary key.
- SQLite picks a *random* rowid once `max(rowid)` is `i64::MAX`. Storing
  rowid 9223372036854775807 is therefore denied (detected by an update hook,
  then the statement is undone), which makes that random path unreachable
  (`rowid/max-denied`).

So the brief's condition is met, and `PRIMARY KEY` is not required.

### 4. Determinism of time and randomness

- **`'now'` everywhere.** Each connection gets a clone of the default VFS
  (same I/O, locking and `pAppData`) whose `xCurrentTimeInt64` returns the
  turn's logical time. This covers `datetime/date/time/julianday/strftime`,
  `unixepoch()`, `CURRENT_TIMESTAMP/DATE/TIME` and `DEFAULT
  CURRENT_TIMESTAMP`. SQLite caches the value per statement, and Kronik's
  time is constant per turn anyway. It works for `:memory:` databases too,
  which the simulator needs.
- **`localtime` and `utc` modifiers.** A process-wide alternative
  `localtime()` that calls `gmtime_r`, installed with
  `SQLITE_TESTCTRL_LOCALTIME_FAULT`. Child processes with `TZ=UTC`,
  `Pacific/Kiritimati` and `America/Los_Angeles` produce identical output
  (`determinism/localtime-is-utc`). This is a test-control interface; it is
  acceptable because SQLite is bundled and pinned, and a check runs on every
  SQLite upgrade.
- **`random()` and `randomblob(N)`** are overridden per connection
  (`SQLITE_INNOCUOUS`, so they still work in schema defaults under
  `trusted_schema=OFF`). They draw from ChaCha20 stream 4 of the turn seed;
  streams 0-3 are ADR 0001's. `randomblob` above the length limit gives
  `too-large`.
- **SQLite's global PRNG.** I went through every use of
  `sqlite3_randomness` in 3.54.0 and made each guest-visible one
  unreachable:
  - the random-rowid fallback (section 3);
  - random column-name suffixes once a select has six or more columns with
    the same name. This really is random (two prepares gave `a:3610558715`
    and `a:1169484310`). The statement is prepared a second time whenever a
    result column name ends in `:digits`, and denied if the names differ.
    `CREATE TABLE AS` is denied.
  - FTS5's locale header: virtual tables are denied.
  - temp, vacuum and super-journal file names: `temp_store=MEMORY`, and
    `VACUUM` and `ATTACH` are denied.

  We do *not* seed the PRNG per turn: it is process-global, so seeding it
  would mean a global lock around all guest SQL.
- **Connection history.** `changes()` and `total_changes()` are denied.
  `last_insert_rowid()` is reset at turn start
  (`determinism/last-insert-rowid-turn-local`). `sqlite_offset()` is not
  compiled in. TEMP objects are denied, because they would outlive the turn
  on the connection.
- **Query plans.** `ANALYZE` is denied, `sqlite_stat*` cannot be written,
  and pragmas that affect plans are denied. SQLite is pinned (it is part of
  the engine version, like Wasmtime).
- **Proof:** re-executing the probe turn gives identical results and
  identical changeset bytes; a different seed changes only the random
  values, and a different logical time changes only the time values
  (`determinism/*`).
- **`unsafe`** lives only in `ffi.rs` (about 500 lines; each block has a
  `SAFETY` comment): the time VFS, the localtime override, sessions with
  `OBJCONFIG_ROWID`, `changegroup_add_change`, `changeset_apply_v2`, invert,
  and the `last_insert_rowid` reset. It is allowlisted in M1 as
  `kronik-store::sql::ffi`.

### 5. Deny list, allow list and limits

All checks go through the authorizer unless noted. Every denial returns
`sql-error::denied(reason)`. The 31 denied statements (`deny/list`):

- **Extensions:** `load_extension()` (also disabled at runtime and removed
  from the VFS).
- **Attach:** `ATTACH`/`DETACH`; `SQLITE_LIMIT_ATTACHED` is 0.
- **Storage and plan maintenance:** `VACUUM` and `VACUUM INTO` (detected by
  first keyword, because `VACUUM` is not visible to the authorizer),
  `ANALYZE`, and a standalone `REINDEX`. The `REINDEX` that `CREATE INDEX`
  authorizes internally is allowed.
- **Transactions:** `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` and
  `RELEASE`, so a guest cannot end the host's savepoints.
- **Objects:** TEMP tables, views, triggers and indexes; `CREATE VIRTUAL
  TABLE` (FTS and R-tree are a later decision).
- **Functions and tables:** `changes()`, `total_changes()`, the `dbstat`
  table, and `_kronik*` tables.
- **Subjects:** `UPDATE … SET _subject`.
- **Pragmas:** every pragma except a read-only allowlist. The table-valued
  `pragma_*` forms go through the same check.
  - Allowed: `table_info`, `table_xinfo`, `table_list`, `index_list`,
    `index_info`, `index_xinfo`, `foreign_key_list`, `foreign_key_check`,
    `collation_list`, `function_list`, `pragma_list` and `compile_options`.
  - Read only (no value): `user_version`, `schema_version`,
    `application_id` and `encoding`.
  - Denied: everything else, including `journal_mode`, `synchronous`,
    `foreign_keys`, `cache_size`, `writable_schema`, `user_version = N` (a
    header field the session cannot capture), `reverse_unordered_selects`,
    `automatic_index` and `page_count`.

Host-fixed connection settings:

- `DEFENSIVE` on, `TRUSTED_SCHEMA` off, `DQS_DML`/`DQS_DDL` off.
- `foreign_keys=ON` (the bundled default), `recursive_triggers=OFF`,
  `temp_store=MEMORY`.
- `SQLITE_LIMIT_WORKER_THREADS=0`, `SQL_LENGTH=1 MiB`, `TRIGGER_DEPTH=32`.

Limits:

- **Size per actor:** `max_page_count` = 1 GiB / page size. Exceeding it
  gives `too-large`, the turn is discarded, and the state is unchanged
  (`limits/size-cap`).
- **Value size:** `SQLITE_LIMIT_LENGTH` = 1 MiB, giving `too-large`
  (`limits/value-size`).
- **CPU:** guest SQL runs in the host, outside Wasm fuel.
  `sqlite3_stmt_status(VM_STEP)` per statement is charged to the turn,
  and a progress handler interrupts a statement once the turn's SQL budget
  is spent, giving `FUEL_EXHAUSTED`. An infinite recursive CTE stopped
  after 2,001,006 VM steps in two runs (`limits/sql-fuel`). VM step counts
  are deterministic for the same SQLite version, data and plan.
- **Memory per statement** has no per-connection limit in SQLite; the VM
  step budget bounds sort and CTE growth indirectly. This remains an open
  item for M31 hardening.

### 6. Per-subject changesets and erasure

- **Splitting.** The row's subject is its `_subject` value (new value for
  INSERT, old value for DELETE). For an UPDATE, whose record carries only
  changed columns, the subject is looked up by key. Tables without
  `_subject` use the turn's default subject. Changes are grouped into one
  changeset per subject with `sqlite3changegroup_add_change`, preserving
  their order. If no changed table has `_subject`, the split is skipped.
- **Moving a row between subjects is not allowed.** An `UPDATE` of
  `_subject` is denied. A `REPLACE` or upsert that moves a row is detected
  at the end of the turn, and the turn fails (`subjects/move-detected`).
  Otherwise the moved row's old values (one subject's data) would sit in
  the other subject's changeset.
- **Verified** (`subjects/split`, `subjects/row-subject-wins`): one turn
  with default subject `user:1` wrote rows for `user:2` and `user:3` plus a
  table without `_subject`, giving three changesets, each applicable on its
  own. An update of `user:2`'s row in a turn whose default subject is
  `user:3` goes to `user:2`.
- **Erasure** is a recorded erasure operation in the log, not a changeset,
  because a changeset's old values would be the erased data. The host runs
  `DELETE FROM t WHERE _subject = ?` on every table that has a `_subject`
  column. On rebuild, the erased subject's changesets are unreadable and
  skipped, and the erasure operation is replayed. The result equals the
  live database (`subjects/erasure`).
- **A gap in the brief (needs an owner decision before M8).** "Saknas
  kolumnen gäller turnens standardsubjekt" decides how such changesets are
  *sealed*, but those rows can never be *erased*: they carry no subject in
  the database. After erasure the rebuild also diverges. A row inserted
  under subject A and updated under subject B, with A erased, gives a
  rebuild error `NOTFOUND on prefs Update`, while the live row survives
  (`subjects/gap-without-column`).

  Recommendation: a turn that has a default subject may only write to
  tables that have a `_subject` column. The SDK's migration helper declares
  `_subject TEXT DEFAULT (kronik_subject())`, where `kronik_subject()` is a
  host function returning the turn's default subject, so rows carry the
  default subject explicitly. Other alternatives would be a host-maintained
  row-owner table (invisible to guests, but more machinery) or forced
  snapshots at erasure (rejected: the rows would still be readable).

  Status after M1: open. The owner has been asked; M1 implements the brief
  as written (tables without `_subject` use the turn's default subject) and
  ships `kronik_subject()`. The question is tracked in `STATUS.md`.

### 7. Storage: one SQLite file per actor

- **Path:** `branches/<b>/sql/<first 2 hex of blake3(actor)>/<actor>-<8
  hex>.db`. Shard directories keep directory sizes bounded.
- **Pragmas:** `journal_mode=WAL`, `locking_mode=EXCLUSIVE` (no `-shm`
  file), `synchronous=NORMAL`, `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`.
  - The SQL databases are derived (I4). They must stay *consistent* after
    power loss, which WAL commits are, but not *durable*:
    `_kronik_meta.applied_lsn` sits in the same transaction as the changes,
    and recovery re-applies the log from there.
  - Without `NO_CKPT_ON_CLOSE`, every LRU eviction checkpointed and
    fsynced. An LRU miss then cost 4.7 ms at p50 (187 turns/s over 10k
    actors on the dev machine), against 0.94 ms with it (1,052 turns/s).
- **Connections** sit in an LRU, sized by file descriptors (2 per open
  actor, db + wal) and memory (`cache_size=-512`). 256 in the prototype;
  thousands are realistic with a raised `LimitNOFILE`.
- **Footprint:** 24 KiB per actor for the database file, 68 KiB including
  the WAL that stays when there is no checkpoint on close. A periodic
  `wal_checkpoint(TRUNCATE)` of idle actors reclaims the WAL part. 10,000
  actors take 668 MiB and 20,000 files.
- **Rejected: a shared store with renamed tables.** It would mean
  rewriting guest SQL; parsing every statement and isolating actors by name
  is fragile.
- **Deferred: a page-store VFS** that keeps actor pages in a shared store,
  like Durable Objects. It would make snapshots atomic and could version
  pages for forks, but it is a large build. Revisit if actor counts reach
  100k+ or snapshots of many changed actors dominate.

Measured (warm page cache, real disk; the dev numbers are from a shared
machine):

| | Dev (EPYC 9354P) | VPS (Skylake, 2 vCPU) |
| --- | --- | --- |
| Direct execution of a turn (BEGIN; INSERT, UPSERT, DELETE/5; COMMIT), file WAL, p50 | 19 µs | 24 µs |
| Kronik turn, file WAL, p50 (p99) | 220 µs (430 µs) | 326 µs (4.6 ms) |
| - execute in savepoint + session | 32 µs | 48 µs |
| - changeset + split + rollback | 47 µs | 65 µs |
| - apply (DDL, changeset, `applied_lsn`) | 139 µs | 202 µs |
| Kronik turn, in memory, p50 | 170 µs | 280 µs |
| Open + configure an existing actor, p50 | 386 µs | 442 µs |
| First read turn after open | 19 µs | 26 µs |
| Close (no checkpoint) | 35 µs | 46 µs |
| Create a new actor database | 4.8–6.2 ms | 7.0 ms |
| 20,000 turns over 256 actors, LRU 256 (98.7% hits) | 3,346 turns/s | 1,991 turns/s |
| 20,000 turns over 10,000 actors, LRU 256 (2.6% hits) | 1,052 turns/s, p50 0.94 ms | 392 turns/s, p50 2.0 ms |

- **Cost of the brief's approach.** The savepoint/changeset approach costs
  about 10x direct execution per turn (about 200 µs). Most of that is
  `sqlite3changeset_apply`, which re-reads table info and prepares its
  statements on every call. At 3,000 turns/s per core this is well inside
  the brief's targets. If it ever matters, the optimization is our own
  applier that decodes the changeset and runs cached INSERT/UPDATE/DELETE
  statements with old-value checks.
- **Where file-per-actor starts to hurt.** Throughput holds while the
  working set fits in the LRU. It drops to about the cost of one open per
  turn once the working set is much larger: about 1 ms per cold actor on
  the dev machine, 2 ms on the VPS. The real limits are file descriptors
  for the LRU and around 70 KiB of disk per actor; the number of actors
  itself is not a limit. Creating 10k actors took 62–70 s, dominated by
  the fsyncs during creation.

### 8. SQL state at an LSN (M3) and snapshots (M6)

- **The building block** is to copy a database, then apply that actor's
  changesets from the log in LSN order. Each database carries its own
  `applied_lsn`, so a copy is self-describing. A per-actor index
  `sql_changes(actor, lsn)` in `state.db` (derived) or the segment footer
  index (actor → offsets) finds the changesets.
- **(a) Fork at L:** take the nearest snapshot S ≤ L. A fork's actor
  database is materialized lazily on first access as a copy of S's file
  plus the actor's changesets in (S, L]. The prototype's fork at 150 =
  snapshot@100 + 50 changesets, equal to production@150
  (`at-lsn/fork-roll-forward`). The cost is linear in the number of
  changesets (110 µs each on the dev machine, 241 µs on the VPS, for this
  workload).
- **(b) Isolated replay:**
  - Per actor, keep a *production cursor*: a copy rolled forward
    monotonically through the window. Each production changeset is applied
    once per actor, not once per root input.
  - For a root input at L, roll the cursor to L−1, open `SAVEPOINT
    kronik_overlay`, and run the fork's turn (its own savepoint, session and
    apply nest inside). Diff, then `ROLLBACK TO kronik_overlay`.
  - Verified over 10 root inputs: the fork's state differed as intended,
    and after each rollback the cursor equalled production at L−1
    (`at-lsn/isolated-replay-overlay`). Parallel workers each own a cursor
    for a contiguous LSN range.
- **Near HEAD** (catch-up, short windows): copy HEAD and apply the inverted
  changesets (`sqlite3changeset_invert`; the changesets keep full old
  values) of (L, HEAD] in reverse. 50 inverted changesets from HEAD@200
  gave production@150 (`at-lsn/inverted-from-head`), at 76 µs each on the
  dev machine. Inversion cannot cross a `migrate` with DDL; such ranges use
  the snapshot path.
- **(c) Consistent snapshots without pausing the applier.**
  - Copy `state.db` and every SQL database changed since the previous
    snapshot with the backup API (205 µs for a 104 KiB database in memory).
    Unchanged files are hard-linked from the previous snapshot, since
    snapshot files are immutable.
  - The manifest records the snapshot LSN L. Each copy may sit at its own
    `applied_lsn` ≤ L, a "fuzzy" snapshot. Restore rolls each database
    forward from its own `applied_lsn` to L.
  - Verified with copies at 120 and 130 rolled forward to 200: both equal
    the live databases (`at-lsn/fuzzy-snapshot`). Shipping packs the
    changed files into the snapshot archive.
- **(d) Erasure:** see 6. Snapshots taken after an erasure no longer
  contain the rows. Older snapshots and segments become unreadable for the
  subject through key deletion and are resealed by compaction, as the brief
  describes for the rest of state.
- **(e) Simulator:** `MemOpener` opens `:memory:` with the same time VFS.
  The identical code passes the same checks in memory and on files with
  identical hashes. Crash modelling of in-memory SQL databases follows ADR
  0004 (`sqlite3_serialize` images).

### 9. Build: no libclang

rusqlite's `session` feature turns on `libsqlite3-sys/buildtime_bindgen`,
which needs libclang on every build machine (the first build failed with
"Unable to find libclang"). The pre-generated bundled bindings already
declare the session API. So the bundled SQLite is compiled with
`LIBSQLITE3_FLAGS = "-DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_PREUPDATE_HOOK"`
from `[env]` in `.cargo/config.toml`, and sessions are called through
`ffi.rs`. M1 moves that `[env]` entry to the workspace root.

## Alternatives

- **Executing the statements directly and recording statements instead of
  changesets.** Cheaper per turn (19 µs vs 220 µs), but rebuild would then
  depend on re-executing SQL, including plans and functions. The brief
  chose changesets precisely to remove that dependency. Rejected.
- **Seeding SQLite's PRNG per statement** (`SQLITE_TESTCTRL_PRNG_SEED`)
  under a global lock. It would make every PRNG use deterministic, but it
  serializes all guest SQL in the process. Rejected; the guest-visible uses
  are unreachable instead (4).
- **Overriding the date functions** instead of the VFS clock. That means
  reimplementing every modifier. Rejected.
- **Requiring `PRIMARY KEY` or `WITHOUT ROWID`.** Unnecessary given
  `OBJCONFIG_ROWID` (3). `WITHOUT ROWID` would also break the common
  `INTEGER PRIMARY KEY` auto-id pattern.
- **A shared store** (7): table renaming was rejected; a page-store VFS is
  deferred.
- **rusqlite's `session` feature:** see 9.

## Consequences

- **`kronik-store`** gets a `sql` module modelled on `SqlActor`, with
  `ffi.rs` allowlisted for `unsafe`. Its API: `open(opener, actor,
  limits)`, `begin_turn`, `query`/`execute`, `end_turn -> TurnSql { ddl,
  changesets, vm_steps }`, `apply(turn_sql, lsn, erased)`,
  `erase_subject`, `canonical_hash`.
- **`kronik-proto`:**
  - `SqlChangeset` stays one `Sealable` per subject.
  - `SqlSchemaChange` stays the DDL text.
  - Add an erasure operation for SQL, a recorded `DELETE … WHERE _subject =
    ?` without a changeset.
- **WIT / SDK:** `sql-error::too-large` also covers values over 1 MiB, and
  SQL CPU exhaustion fails the turn with `FUEL_EXHAUSTED`. The SDK should
  document that DDL belongs in `migrate`, that `_subject` cannot be changed,
  and that `changes()` is unavailable (use `execute`'s return value or
  `RETURNING`).
- **M1:**
  - The applier applies SQL changesets in the same LSN-ordered stream as KV
    writes.
  - Per-actor `applied_lsn` lets recovery skip already-applied work.
  - The SQL-fuel conversion (VM steps to fuel units) is chosen together
    with Wasm fuel.
  - `max_page_count` should get a small margin during apply, so an apply
    can never fail where the turn passed.
- **M3:** needs the per-actor changeset index, production cursors and
  overlays as in 8.
- **M6:** fuzzy snapshots and hard links for unchanged actors, as in 8.
- **M8:** needs the owner's decision on the `_subject` gap (6).
- **SQLite upgrades** go through `kronik upgrade check`, plus re-running the
  spike's determinism checks: `localtime` test-control, column-name
  randomness, `OBJCONFIG_ROWID`, the authorizer action list.

### Verification

```sh
cd spikes/spike-e-sql
./run.sh check     # 30 checks, "0 check(s) failed" (dev and VPS)
./run.sh bench     # the measurements above (writes to /var/tmp)
```
