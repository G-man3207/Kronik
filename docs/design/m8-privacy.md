# M8 privacy mode: design

Status: groundwork. The seams in §12 are agreed with good-core (log, store,
sched, fork), which also reviewed §6 and §8. This document covers SPEC.md
"Privacy mode (the GDPR switch)", I8/I9, the M8 acceptance list, and ADR 0005
§6. The table in §14 says who builds what: **now** is fast-policy's
groundwork; **later** is the deep integration, by good-foreign (sealing,
redaction, erasure, forks, measurement) and good-core (reseal compaction and
shipping, on its M6 storage); **CLI** is fast-docs.

## 1. What the format already has

M1 made every user-data field a `Sealable { optional subject, oneof { plain,
sealed } }` with `Sealed { key_version, nonce, ciphertext }` (I9), recorded
in both modes. These fields are the turn input (HTTP headers and body,
message bodies), outgoing message bodies, `STATE_OP_SET` values, the SQL
changesets (one per subject, ADR 0005 §6), and effect requests and responses.
The log also has `PrivacyMode { epoch, mode, audit }` and `Erasure { epoch,
subject, key_version, audit }`. Subjects come from `ctx.subject(..)` (default
for later writes, changeable mid-turn), `set_for(subject, ..)` per write, the
root input's default subject, and the SQL `_subject` column.

A subject is 1 to 256 bytes of printable ASCII without spaces, such as
`user:123` (`kronik_privacy::keystore::valid_subject`). A value has at most
one subject.

## 2. Keystore (now: done in 895ff28)

`<data_dir>/keys/keystore.db`, `kronik_privacy::keystore::Keystore`:

- `subject_keys (subject, version, nonce, wrapped, created_wall_ms)`. Every
  key is 32 random bytes, wrapped with XChaCha20-Poly1305 under
  `derive_key("kronik keystore v1", master)` with `subject \0 version` as
  associated data, so a wrapped key can't be moved to another subject.
- `erasures (subject, last_version, erased_wall_ms)`. `erase` deletes every
  key of the subject in one transaction and records the last version. Values
  sealed with any version up to it read as `Erased` forever, even if the same
  subject id later gets a new key (numbered after the erased ones).
- `key_for_sealing(subject, fresh, nonce, wall)` returns the newest key,
  creating version 1 on first use. `key(subject, version)` returns `Found`,
  `Erased` or `Missing`. `rotate` adds a version, and older ones still unseal.
- `seal(subject, key, nonce, plaintext)` / `unseal(..)` handle one value:
  XChaCha20-Poly1305, associated data `"kronik sealed v1" \0 subject \0
  version`, so a sealed value can't be replayed under another subject or
  version.
- Randomness: callers pass key material and nonces from `Env::random_bytes`
  (ADR 0004). The simulator therefore stays deterministic, and the keystore
  never reads ambient randomness or time.
- Nothing in the module logs, and `Debug` hides keys. Subject ids are personal
  data too: metrics never carry them as labels, and log lines carry them only
  at debug level.
- The master key is the existing `[keys] master_key_file` (M2). It is never
  shipped. Operators back it up separately (docs/operations must say so):
  without it, the keystore and its backups are useless.

## 3. Modes and the `PrivacyMode` record (now)

`kronik privacy mode on|off --reason R [--dry-run]` → `POST /v1/privacy/mode`
→ `Node::set_privacy_mode`, which commits a `PrivacyMode` record with the
next configuration epoch. The store keeps it in `config_records`; the node
reads the latest at start and caches the state in an atomic that the sealing
points read. Asking for the current mode commits nothing and answers
`changed: false`.

- **The mode applies by time of writing.** A value is sealed when its record
  is assembled while the mode is `on`. Turning the mode `off` stops sealing
  new values; sealed values stay sealed. Replay never looks at the mode,
  because it reads what was recorded.
- **`off` costs nothing measurable:** a sealing point is one relaxed atomic
  load and a branch. There is no allocation, no keystore access and no
  encryption; the subject tags are written as in M1.
- `kronik privacy status` → `GET /v1/privacy`: the mode, the epoch of its
  record, keystore counts (`subjects`, `keys`, `erased`; `null` without a
  keystore), and (later) pending erasures and reseal progress.

## 4. Sealing points (later: good-foreign)

The rule: **every `Sealable` with a subject is sealed when its record is
assembled while the mode is `on`.** Values without a subject stay `plain`.
Concretely:

| Value | Where it's sealed |
|---|---|
| Root input (HTTP headers, body; API `send` body) | when the node admits the input and builds the `TurnRecord`'s `Input` |
| Message bodies (outgoing, then the receiver's input) | in the sender's record; the receiver's input refers to it and is not re-sealed |
| `STATE_OP_SET` values | in the turn record; `state.db` stores the `Sealable` as recorded |
| SQL changesets | per subject after ADR 0005's split, one `Sealed` per subject |
| Effect requests and responses | in the `EffectRecord` (requests at the gate, responses at completion) |
| Replies (HTTP response body) | when the turn's output is recorded |

- **Keys:** `key_for_sealing(subject, ..)` behind an in-memory cache of
  unwrapped keys per subject (bounded, LRU). Erase and rotate invalidate it.
  The nonce is 24 bytes from `Env::random_bytes` per value.
- **SQL actor databases keep plaintext rows**, because SQLite must query
  them. Their protection is the erasure turn (§6), which deletes the rows,
  and the sealed changesets in the log.
- **Guest log lines are not sealed.** They go to the daemon's log, not to
  Kronik's log. Docs must tell guest authors not to log personal data; the
  `execution_id`/`causal_id` fields identify the turn without it.

## 5. Unsealing and redaction (later: good-foreign; CLI rendering: fast-docs)

- **Inside turns:** the host unseals before the guest sees a value (state
  reads, delivered message bodies, recorded effect responses on re-run). An
  erased state value reads as absent. Any other erased input (a queued
  message body, a recorded response) fails the turn with `SUBJECT_ERASED`
  as a dead letter: the turn can't run on data that no longer exists.
- **API output** (`actors inspect`, `history`, diffs, MCP): with `pii:read`,
  sealed values are unsealed. Without it they show as `[sealed]` (as built:
  no subject id either, see §15), and erased ones as `[erased]` for every
  caller. An API call that reads an
  erased value directly (`GET` of one state key, an effect body) gets
  `SUBJECT_ERASED` (410). Plain values written in `off` mode are shown as
  they are: `off` protects nothing, which docs must say.
- Redaction happens where the API renders a `Sealable`: one helper,
  `render_sealable(&Sealable, &Caller) -> Rendered`, in kronik-api, so the
  JSON API, MCP and diffs agree.

## 6. Erasure (later: good-foreign; snapshots: good-core; the open question in §7)

`kronik privacy erase user:123 --reason R [--dry-run]` →
`POST /v1/privacy/erase {subject, reason, dry_run}` → `Node::erase_subject`:

1. `keystore.erase(subject, wall)` deletes the keys (durable: WAL with
   `synchronous = FULL`) and returns `last_version`. Doing this first means a
   crash before step 2 already leaves the data unreadable, and recovery sees
   an erasure row without a record and commits the record.
2. Commit `Erasure { epoch, subject, key_version: last_version, audit }`.
3. **The erasure operation** runs when the record is applied, once in
   production and again on every rebuild. It is recorded as this record, not
   as a changeset, because a changeset's old values would be the erased data
   (ADR 0005 §6). For every actor with SQL state it runs `DELETE FROM t WHERE
   _subject = ?` on each table with a `_subject` column, and it deletes the
   subject's KV rows from `state.db`. On rebuild the subject's changesets
   can't be unsealed and are skipped; the operation is then replayed, and
   the result equals the live database.
4. **Other subjects are unaffected:** their values in the same turns are
   separate `Sealable`s under other keys, their SQL changesets are separate,
   and `DELETE … WHERE _subject = ?` touches only the erased subject's rows.
5. **Plain values** that the subject wrote in `off` mode and that were never
   resealed are still readable in old segments. Erasure counts them,
   reports them as `plain_values`, and schedules a compaction of the
   affected segments that replaces them with tombstones (§8). Until then the
   erasure is `pending`.
6. **Snapshots** hold the actors' SQL files in plaintext. After an erasure,
   a new snapshot is taken, and the local and shipped snapshots older than
   the erasure are deleted once a newer one exists, from shipping storage
   too. As a consequence, `pick_base` and restore can't go back past an
   erasure. That is intended: going back would bring the subject's rows back.
7. **Completion:** shipped keystore backups (§10) still hold the keys until
   they expire. The command prints `erasure of user:123 is complete on
   <erased_at + privacy.keystore_backup_retention>` (30 days by default),
   provided steps 5 and 6 are done by then; `privacy status` lists pending
   erasures without naming subjects unless the caller has `pii:read`.

Erasing a subject that has no key still records the erasure and runs the SQL
deletion, and it works in `off` mode too (there are no keys, version 0).

## 7. The open owner question: rows in tables without `_subject`

ADR 0005 §6: a turn with a default subject can write to a table that has no
`_subject` column. Its changeset is sealed under the turn's default subject,
but the row can never be found by `DELETE … WHERE _subject = ?`. After that
subject's erasure, the rebuild also diverges (`subjects/gap-without-column`).
The owner has been asked. Both options are designed here, and neither is
implemented until the answer comes.

**Option A, the brief as written: such rows belong to the turn's default
subject.**

- Sealing: as M1 does today, the changeset goes to the default subject.
- Erasure can't delete the rows (they carry no subject), so they survive in
  the live database while their changesets in the log become unreadable.
- To keep rebuilds equal to the live database, the store would have to keep
  a host-side row-owner table `_kronik_row_subjects (table, rowid/pk,
  subject)`, maintained from the changesets at apply. Erasure would then
  delete the rows it lists. This is invisible to guests, but it costs a
  write per changed row in every turn with a subject, in `off` mode too,
  which conflicts with "off costs nothing". The alternative, a forced
  snapshot at erasure, was rejected in ADR 0005 (the rows would stay
  readable).
- Docs would say that rows in tables without `_subject` survive erasure.

**Option B, ADR 0005's recommendation: a turn with a default subject may
only write tables that have `_subject`.**

- The SDK's migration helper declares `_subject TEXT DEFAULT
  (kronik_subject())`, where the host function `kronik_subject()` (shipped
  in M1) returns the turn's default subject, so rows carry their subject
  explicitly.
- A write to a table without `_subject` in a turn that has a default subject
  fails the turn with `subjects/table-without-subject`, a clear error naming
  the table. Turns without a subject (system work) may still write
  anywhere, so configuration tables stay possible.
- Erasure then finds every row, and rebuilds stay equal. There is no extra
  cost at write time.
- Migration: an existing table gets the column with `ALTER TABLE … ADD
  COLUMN _subject TEXT DEFAULT (kronik_subject())`. Old rows have NULL, belong
  to nobody, and docs explain this.

Recommendation: B, for the same reasons as ADR 0005: it is correct by
construction and costs nothing in `off` mode.

## 8. Reseal via compaction (later: good-core)

`kronik privacy reseal --reason R [--dry-run]` → `POST /v1/privacy/reseal`
starts a background compaction that requires the mode to be `on`:

- It rewrites log segments with the same LSNs, records and order. Only
  `Sealable` values change: a tagged `plain` becomes `sealed` with the
  subject's current key, and a value of an erased subject becomes a
  tombstone `Sealed { key_version: <erased version>, nonce: zeros,
  ciphertext: empty }`, which can never unseal. Record checksums are
  recomputed. A replay with the keys gives exactly the results of the
  unrewritten log.
- It works on closed segments only. Each rewritten segment is written next
  to the old one, fsynced and renamed over it. Because record sizes change
  (tombstones are shorter), the segment's `turn_index` and `open_turns`
  offsets are then fixed in one `state.db` transaction. Snapshot manifests
  name segments by start LSN only, so they stay valid.
- The shipper treats closed segments as immutable and uploads each once,
  so reseal marks every rewritten segment for re-upload, and the shipped
  copy is replaced. Until it is, the shipped copy still holds the plain
  values, and `privacy status` counts such segments as pending.
- It does the same for `state.db` values and takes a snapshot afterwards.
- Progress (segments done/total, values sealed, tombstones) appears in
  `privacy status`. Docs recommend running reseal right after turning the
  mode on, before the first erasure.

## 9. Forks without PII (later: good-foreign)

`kronik fork create --no-pii`; tokens without `pii:read` always get it
(`no_pii = request.no_pii || !caller.has(PiiRead)`):

- The fork's host never hands a real value to the fork's guests. Every
  tagged value a turn reads, sealed or plain, is replaced by
  `Pseudonyms::of(subject, plaintext)` = `pii:` + 12 hex of a keyed BLAKE3
  (key `derive_key("kronik pseudonym v1", master)`, done in 895ff28). The
  host unseals transiently to compute it, so equal values get equal
  pseudonyms and equality checks in guest logic still hold. Without the key,
  a pseudonym can't be checked against a guessed value. Erased values become
  `[erased]`.
- The replay runner marks a turn that read at least one pseudonym. If such a
  turn's result differs from production, the diff calls it `pii-masked`
  instead of `diverged`.
- Diffs of a `--no-pii` fork show the pseudonyms, never real values.

## 10. Keystore backup (now: export/import; later: shipping by good-core)

`Keystore::export_backup(nonce)` produces one blob: `KRKSTOR1`, a 24-byte
nonce, and XChaCha20-Poly1305 under `derive_key("kronik keystore backup v1",
master)` of every key row and erasure row. Subject ids are therefore hidden
too. `Keystore::import_backup(conn, master, blob)` restores it.

The M6 shipper uploads a backup after keystore changes (debounced, at most
once a minute) and daily, as `keystore/<wall_ms>.bin`. It deletes backups
older than `privacy.keystore_backup_retention` and always keeps the newest.
A restore takes the **newest** backup, not the newest before the snapshot:
keys are only ever added, so a backup shipped after the snapshot holds every
key its values need, while one from before the snapshot can lack the keys of
the newest subjects (v0.1 quickstart walk 4). The erasures the restored log
records after that backup are applied again to it, through their key
version, and every sealed value in the restored state and log must then
have its key or be erased, or the restore fails with `KEYSTORE_INCOMPLETE`
before it writes. The shipper's change stamp covers the keystore's WAL, so
a new key ships within a minute rather than after the next checkpoint. This
retention is what makes erasure complete (§6.7).

## 11. Gateway subject (now)

`privacy.subject_from = "header:<name>"` or `"jwt:<claim>"` (normally
`jwt:sub`), in `kronik_gateway::subject::SubjectFrom`:

- The header's trimmed value, or the claim of the `Authorization: Bearer`
  JWT, becomes the root input's default subject (`node.ingress(.., subject)`)
  and the subject tag of every header and body value of the input.
- A missing header, token or claim means no subject. A present but unusable
  one (not a JWT, bad base64url or JSON, a claim that is neither a string
  nor an integer, not a valid subject) is `400 BAD_REQUEST` with the reason.
- **Kronik v0.1 does not verify the JWT, it only reads the claim.** Whoever
  can reach the gateway can choose the subject. The subject tags data; it
  does not authenticate. Put an authenticating proxy in front, or derive the
  subject in the actor. Docs must say this (SPEC.md).

## 12. API and CLI

| Endpoint | Scope | Request | Response | Who |
|---|---|---|---|---|
| `GET /v1/privacy` | `read` | — | `{mode, epoch, keystore: {subjects, keys, erased} \| null}` | now |
| `POST /v1/privacy/mode` | `operate` | `{mode: "on"\|"off", reason, dry_run}` | `{dry_run, changed, mode, previous, epoch, lsn}` | now |
| `POST /v1/privacy/erase` | `operate` | `{subject, reason, dry_run}` | `{dry_run, subject, key_version, lsn, plain_values, complete_after_ms}` | later |
| `POST /v1/privacy/reseal` | `operate` | `{reason, dry_run}` | `{dry_run, started, segments}` | later |

`mode` is `"off"` or `"on"`. `epoch` is `null` before the first `PrivacyMode`
record. `lsn` is `null` for a dry run or when nothing changed. Errors:
`BAD_REQUEST` (a bad mode or subject), `REASON_REQUIRED`, `SUBJECT_ERASED`,
and the usual auth errors.

CLI (fast-docs, in `cli/privacy.rs`): `kronik privacy mode on|off --reason R
[--dry-run]`, `kronik privacy status`, and later `kronik privacy erase
<subject> --reason R` and `kronik privacy reseal --reason R`, all with
`--json`.

Seams in good-core's crates, agreed:

1. kronik-store: apply `PrivacyMode` via `config_insert`, so that it is in
   `config_records`, from which the node rebuilds `kronik_effects::Config`
   at start. `Config` folds the record and answers `privacy()`.
2. kronik-sched: `src/privacy.rs` with `Node::{privacy_mode,
   set_privacy_mode, keystore_stats}`, and `start_local` opening
   `keys/keystore.db` next to `secrets.db`.
3. kronik-api: `src/privacy.rs` routes and `required_scope` entries.
4. kronik-gateway: `GatewayConfig.subject_from` (done).

## 13. Measuring the overhead

Acceptance: "`off` has no measurable overhead compared to M6. Measure and
document."

- **Builds:** the last commit before any sealing code (baseline) against M8
  in `off` mode, same machine, release builds, nothing else running.
- **Workloads:**
  - (a) the gateway with `subject_from = "header:x-user-id"`: 20,000 `POST
    /counter/<key>/increment` over 64 keys from 16 concurrent clients, half
    with the header;
  - (b) the same through the API's `send` with a `subject`;
  - (c) an SQL actor writing a `_subject` row per turn (per-subject
    changeset split).
- **Measured:** throughput (turns/s); p50/p99 client latency;
  `kronik_turn_duration_seconds` and `kronik_log_fsync_duration_seconds`
  from `/metrics`; log bytes per turn.
- **Method:** 5 alternating runs per build. Report mean ± standard
  deviation. "No measurable overhead" means the difference in throughput and
  p99 is within run-to-run noise: under 2 standard deviations and under 3%.
- The same workloads in `on` mode give the documented cost of sealing.
- `scripts/bench-privacy.sh` (later, with the sealing code) prints a
  results table for `docs/operations/privacy.md`.

## 14. Who builds what

| Part | Owner | When |
|---|---|---|
| Keystore, seal/unseal, pseudonyms, backup export/import | fast-policy | now (895ff28) |
| Gateway `subject_from` (header, unverified JWT) | fast-policy | now |
| `PrivacyMode` record path: store seam, `Node::set_privacy_mode`, `/v1/privacy` | fast-policy | now, after good-core's M6 commit |
| CLI `privacy mode`, `privacy status` | fast-docs | now, after the API |
| Opening the keystore in `start_local` | fast-policy | now, after good-core's M6 commit |
| Sealing points, key cache, unsealing in turns | good-foreign | later |
| Redaction helper and its use in API, MCP, diffs | good-foreign, with fast-docs for the CLI | later |
| Erasure operation and `/v1/privacy/erase` | good-foreign | later |
| Snapshot handling after erasure (§6.6) | good-core | later |
| Reseal compaction, `/v1/privacy/reseal` | good-core | later |
| `--no-pii` forks and `pii-masked` | good-foreign | later |
| Keystore backup shipping and retention | good-core (M6 shipper) | later |
| Option A or B for tables without `_subject` | owner decides; then good-foreign | after the answer |
| Overhead measurement (`docs/perf.md`) | good-foreign | done on dev |

## 15. As built (good-foreign: §4, §5, §6.1-6.4, §9)

Commits `da0ad03` (the `Sealer`), `c99061f` (sealing, unsealing, erasure,
`--no-pii` forks), `ed47360` (the erase route in the OpenAPI document),
`c90a633` (erasure recovery), `eaf56b8` (no copy in `off` mode) and
`22a8bca` (`history` marks erased writes). Where the code differs from the
sections above:

- **One seal point.** `Node::commit` and `Node::append` seal the record in
  place (`kronik-sched/src/sealing.rs`); the walk over a record's
  `Sealable`s is `kronik_proto::sealables::record_mut`. In `off` mode that
  is one relaxed atomic load; the guest's input was cloned before M8 as
  well, so unsealing it adds no allocation, and a guest's state read and
  the apply of a plain SQL changeset are what they were before M8. Values the guest and API callers
  see come from in-memory copies or are unsealed on the way in. Fetch
  effects carry the guest's subject (`FetchRequest.subject`), call effects
  the message's.
- **The request line (v0.1 fix, review H10).** A gateway request with a
  subject puts its path, query and route parameter values into
  `HttpInput.sealed_path`, `sealed_query` and `Param.sealed_value` (an
  additive change to the v1 format; the plain `path`, `query` and
  `Param.value` stay empty), tagged like its headers and body, so they are
  sealed, resealed, counted and erased with the rest. Readers go through
  `HttpInput::path_text`/`query_text`/`param_values` (`kronik-proto`
  `http.rs`), which fall back to the plain fields of older records
  (fixture `crates/kronik-proto/tests/fixtures/http-input-v1.hex`). The
  method and the route pattern stay plain; actor keys are identities and
  stay plain everywhere. Turn details hide a sealed request's path, query,
  parameters and `Idempotency-Key` from callers without `pii:read`, and
  history, dead-letter and trace summaries show such a caller the route
  pattern instead of the path (re-review R4: others see the path). A
  `--no-pii` fork pseudonymizes the request line like every tagged value
  (re-review R2, redone: revealing it handed real paths and queries to
  code an agent can write). A turn that read a pseudonym
  (`ForkTurn::pseudonyms`) and differs from production, failing included,
  is `pii-masked` (`diff::Acc::turn_errors` and the causal grouping skip
  it): no introduced error, origin or consequence, so `no-new-errors` does
  not deny on masking alone (an SQL turn ran on real rows: its errors
  count). A production turn missing below such a turn is `pii-masked` too.
  Masked runs can't tell broken code from correct code, so while
  `summary.pii_masked + summary.pii_unverified > 0` (the latter: turns of
  changed code identical on pseudonyms, `Acc::pii_same`) the evaluation
  has the floor
  `pii-masked-needs-approval` (require_approval, in `RuleSet::evaluate`,
  ADR 0031); a `pii:read` reviewer re-runs on real data to see such a
  turn's real behaviour before approving. Validation (`kronik_proto` `input()`) requires a value in
  each present sealable field.
- **Idempotent replays stay with their requester (v0.1 fix, H8, M6, M7,
  re-review R3).** `HttpInput.request_hash` is a version byte
  (`INGRESS_HASH_VERSION` = 3) and a hash of the method, path, query, body
  and the requester: the subject when there is one, else the value of
  `Authorization` (never `Cookie`), keyed with `Sealer::keyed_hash` (a
  master-derived key, purpose `kronik.ingress.v3`; plain BLAKE3 with that
  domain without a key). `Node::ingress` treats saved rows of other
  versions as expired (v1: no requester; v2: credential headers too, which
  turned retries with a rotated cookie into 422). A subject
  header (or `Authorization` for `jwt:`) that appears twice or holds a list
  is `400`. Effect fingerprints of a subject's `http.fetch` and
  `actor.call` requests are `0x02` and a keyed hash of the plain
  fingerprint (`Sealer::effect_fingerprint`); a re-run and a fork's exact
  match also accept the plain fingerprint of records written before
  (`fingerprint_matches`). Turn-failure messages for unreadable values no
  longer name the subject.
- **`kv.sealed`.** `state.db` stores a state value as recorded; a column
  `sealed` (added to older databases on open) tells a sealed value's
  encoded `Sealed` from plain bytes. An erased state value reads as absent
  in turns.
- **The store opens SQL changesets** at apply with the node's sealer: an
  erased subject's changeset is skipped, any other that can't be opened is
  `STORAGE_CORRUPT`. The `Erasure` record deletes the subject's `kv` rows
  and its rows in every table with `_subject` of every actor database,
  including databases created earlier in the same apply batch; the same
  runs on rebuild, so a rebuild equals the live databases (tested by
  deleting `state.db` and `sql/`).
- **Saved responses and dead letters (v0.1 fix).** `ingress_keys`,
  `dead_letters` and `deliveries` have a `subject` column (added to older
  databases on open, filled from the stored blobs, and rows of subjects
  erased before are then erased too). A saved ingress response has the
  subject of its response, or of the request when the response has none; a
  dead letter that of its message or timer body; a saved call response that
  of the reply. The `Erasure` record deletes the subject's `ingress_keys`
  rows (a repeated `Idempotency-Key` runs anew) and dead letters. A saved
  call response becomes a tombstone outcome (`SUBJECT_ERASED`, no output)
  and the row stays, so the message stays delivered and a repeated call
  gets that failure instead of a second run. Dead letters a subject's
  turns produce after its erasure stay (their input is sealed under the
  erased key); resending one fails with `SUBJECT_ERASED`.
- **Nothing left in the files (v0.1 fix).** `state.db`, every actor
  database and `keys/keystore.db` run with `PRAGMA secure_delete = ON`, so
  deleted rows are zeroed in their pages. `Keystore::erase` runs
  `wal_checkpoint(TRUNCATE)` after its commit, before the `Erasure` record
  is written; applying the record checkpoints every actor database it
  touched and then `state.db` the same way (skipped inside an overlay and
  in a bulk replay, whose journal is off). A checkpoint a reader blocks is
  logged as a warning. Snapshots copy `state.db` and the actor databases
  with `VACUUM INTO` (the actor database's attach limit is raised to 1 for
  it), so no free page reaches a snapshot; the state hash is computed from
  the logical content and is unchanged. `secrets.db` is still copied with
  the backup API.
- **Recovery (§6.1)** is built: `state.db` keeps the applied erasures
  (`erasures (subject, key_version, lsn)`), and at start the node commits
  an `Erasure` record (audit token `kronik`) for every keystore erasure
  without one, before anything runs.
- **`POST /v1/privacy/erase`** answers `{dry_run, subject, key_version,
  epoch, lsn, plain_values, complete_after_ms}`. `complete_after_ms` is
  the erase's wall time plus `privacy.keystore_backup_retention` (the
  default 30 days, or the value `serve` passes from the configuration
  file).
- **Reseal (§8)** is `Node::reseal` and `POST /v1/privacy/reseal`
  `{reason, dry_run}` → `{dry_run, started, segments}` (scope `operate`).
  The mode must be `on` (`BAD_REQUEST` otherwise, hint
  `kronik privacy mode on --reason '...'`). It rewrites closed segments
  only: same LSNs and order, tagged plain values sealed with the current
  key, erased subjects replaced by a tombstone `Sealed` (erased version,
  zero nonce, empty ciphertext), checksums recomputed, written beside the
  old file, fsynced and renamed. `turn_index` and `open_turns` offsets,
  and the rows the rewritten turns still own (`kv` values, saved ingress
  and call responses, dead-letter inputs; a row a later turn replaced is
  left), are fixed in one `state.db` transaction, followed by a WAL
  checkpoint. Rows of an erased subject are already gone or tombstoned by
  its `Erasure`; a value of it in a row that remains becomes a tombstone.
  The active segment is left for the next roll. A snapshot
  follows. Rewritten segments are marked for re-upload
  (`privacy/reupload/<start>`); `GET /v1/privacy` counts them in
  `reseal.pending_segments` until the shipper replaces the object. Status
  also reports `pending_erasures` and `reseal.{segments_done,
  segments_total, values_sealed, tombstones}`. A dry run writes nothing.
  A second reseal with nothing plain left rewrites nothing. No guest code
  runs. `kronik privacy reseal [--dry-run] --reason '...'` is the CLI
  wrapper.
- **Snapshots after erasure (§6.6).** Applying an `Erasure` record takes
  a snapshot (`reason: erasure`) and deletes local snapshots older than
  that LSN once the new one exists. `pick_base` will not use a snapshot
  from before an erasure. A fork the log itself still holds (the log
  starts at LSN 1) replays that log and is not outside retention. A fork
  the log no longer reaches, with no snapshot at or after the erasure,
  fails with the existing "outside retention" error (`BAD_REQUEST` at
  the API). The shipper's next round deletes the matching remote
  snapshots, manifest first, because they are no longer local.
- **Keystore backup shipping (§10).** `ship_loop` uploads
  `keystore/<wall_ms>.bin` (the `export_backup` bytes, not zstd) after a
  keystore change, at most once a minute, and once a day. Backups older
  than the published retention are deleted; the newest is kept. The
  master key is never uploaded. `restore` installs the newest backup into
  `keys/keystore.db`, with the log's later erasures applied again, after
  checking it holds every key the restored data needs; a backup it can't
  install, or a missing key, fails the restore before it writes (see the
  operations guide; `--allow-missing-keys` installs it anyway and lists
  the subjects left without a key, `--without-keystore` installs none). `serve` passes `[privacy] keystore_backup_retention` to
  `NodeConfig.keystore_backup_retention`, so a configured window is what
  both erasure completion and the shipper use.
- **Redaction.** `kronik_api::redact::render_sealable` renders state values
  (`GET /v1/actors/{kind}/{key}`) and turns (`GET /v1/turns/{id}`), which
  MCP and the CLI use. `history` shows no values, so its write summaries
  carry `erased: true` for a value sealed for an erased subject, and
  `kronik history` prints `set s [erased]`. No route reads a single state value or effect body,
  so nothing answers `SUBJECT_ERASED` (410) yet. Diffs never show a
  subject's values, in any fork: state values and bodies appear as
  `{redacted, subject, hash}` (as before M8), and since `c99061f` so do the
  values of a subject's SQL rows. Since the v0.1 fix, so do the url,
  header and body fields of an effect request recorded under a subject,
  response header values with a subject, and the final-state rows with a
  `_subject` in continuous replay; the Markdown diff shows such a value as
  `[sealed:<subject> <hash>]`. Fork turns (`GET /v1/turns/<fork>:…`) and
  `trace` are redacted per caller like production turns.
- **Who sees subjects (v0.1 review M3, H7, H12).** A caller without
  `pii:read` sees `[sealed]` (`kronik_proto::http::SEALED`) and no subject
  id: `redact::redact` drops the subject of every value for it, `inspect`
  and `history` null theirs. A diff is built once and served to every
  `read` caller, so it carries `s:` + 12 hex of
  `Sealer::keyed_hash("kronik diff subject v1", [subject])` instead of the
  id, and its hashes are `k:` + 16 hex of
  `keyed_hash("kronik diff redaction v1", [subject, value])` (was an
  unkeyed BLAKE3 a guess could be checked against); both are `-` without
  the master key (`Sealer::plain`, the offline upgrade check). Diffs
  stored before keep their old form until replayed. Sending into a fork
  made without `--no-pii`, and reading its turns or their trace, needs
  `pii:read` (`SCOPE_MISSING`, `m3.rs` `require_fork_pii`).
- **Forks.** The production index is revealed for the fork in place
  (`kronik-fork/src/privacy.rs`): plaintext, or pseudonyms for `--no-pii`.
  SQL changesets are unsealed but never pseudonymized, so a `--no-pii`
  fork's SQL state holds real rows (a v0.1 gap). So a `--no-pii` turn that
  used SQL (`SqlTurn::end` returned something), called a turn that did, or
  was sent a message or timer by one is `ForkTurn::sql` (and masked): its
  record leaves the fork only through `privacy::conceal_turn` (every value
  and the outcome message read `[sql]`: the `send_to_fork` reply, the fork
  log, `isolated.jsonl`), and the diff tags its produced values with the
  subject `[sql]` (`diff::sql_tagged`), so they are redacted. State that
  such a turn writes and a later turn reads is not tracked (documented in
  the privacy guide).
  State reads go through `ForkState`, which pseudonymizes tagged values.
  A `--no-pii` turn is masked when its input or a recorded (non-live)
  effect response is tagged or it read a masked state value; if it differs,
  it counts in `summary.pii_masked` and `samples.pii_masked`, not as
  divergent, an error or a cause. HTTP root inputs keep the gateway's
  subject in forks (taken from the body's or a header's tag). A fork
  records its effects with the
  guest's subject as production does, and seals what it writes to disk (its
  log and `isolated.jsonl`) with the node's sealer, so no plain value of a
  subject reaches a fork's files in `on` mode. Forks written before that
  fix keep their plain files until deleted.
- **The open owner question (§7)** is one seam,
  `kronik_store::sql::actor::rows_without_subject_column`: a no-op that
  returns 0, documented with both options. Option B's turn-time refusal is
  not built.
- **Tests:** `crates/kronik/tests/privacy_mode.rs` (a real `kronik serve`)
  covers tags per value from the gateway and the SDK including a mid-turn
  subject switch in `off` mode, sealing in `on` mode, `[sealed]`
  without `pii:read`, an identity replay over sealed history with an empty
  diff, erasure (`[erased]`, state value and SQL rows gone, user:2's values
  from the same turns intact, a rebuild equal to the live databases) and a
  `--no-pii` fork (`pii_masked`, no real value in its diff).
  `kronik-sched/tests/node.rs` covers recovery.
  `an_erasure_leaves_nothing_in_the_data_directory` in `privacy_mode.rs` scans
  every file of the data directory after an erasure and after a rebuild
  for the subject's plain values and wrapped key, and checks its saved
  idempotent response and dead letter are gone;
  `kronik-api/tests/reseal.rs` checks a resealed dead letter, and
  `kronik-store/src/db.rs` the erasure of these rows and the migration.
- **Overhead (§13):** `scripts/bench-privacy.sh` with the three workloads
  (the gateway with half the requests carrying a subject, the API's send
  with a subject, an SQL actor with `_subject`); results in
  `docs/perf.md`: `off` is within run-to-run noise of the commit before
  sealing, `on` adds 32 % to 57 % log bytes per record.
