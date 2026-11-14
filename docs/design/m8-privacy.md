# M8 privacy mode: design

Status: design. The seams in §12 are agreed with the log, store, sched and
fork crates, which also reviewed §6 and §8. This document covers the build
brief's "Privacy mode (the GDPR switch)", I8/I9, the M8 acceptance list, and
ADR 0005 §6.

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

## 2. Keystore

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
  Subject-key versions remain positive `u32`; an exhausted version or erased
  floor refuses creation/rotation without wrapping to zero or changing rows.
- The keystore exposes a persistent, checked integer `revision()` for semantic
  change detection, independently of database/WAL timestamps or lengths. Key and erasure
  writes advance it in their SQLite transaction, including backup installation.
  Sealer caches also observe SQLite's connection-local `data_version`; a loaded
  key and its revision come from the same read snapshot. A failed revision read
  clears cached keys and fails closed. Replacing a loaded database's device/inode
  requires reopening it; arbitrary raw in-place writes outside SQLite are not a
  supported concurrent update path. These revisions are housekeeping metadata:
  `KRKSTOR1` backups and master-keyed audit identity remain unchanged.
- `Sealer::seal_value_at(value, version, fill)` protects a tagged plaintext
  snapshot value under its required positive original subject-key version,
  independently of the current mode. It refuses missing or erased versions and
  never creates a key or promotes a value to a newer version; callers must first
  validate the original row's source and erasure provenance.
  `require_key_version(subject, version)` is the noncreating read-only admission
  check: snapshot callers must check every original positive reference across
  all actors before minting any first-protection key.
- `Sealer::key_availability(subject, version)` reports `Found`, `Missing`, or
  `Erased` for an exact positive original reference through the same opening
  cache and revision/floor checks. It exposes no key material, creates no key,
  and never selects the newest version. Database and wrapped-key MAC failures
  remain errors. `Found` still requires payload/source/schema authentication;
  a missing outer key leaves nested references unknown, not proved complete.
- `Sealer::erasure_floor(subject)` is a noncreating point read through the same
  revision-bound cache. `Some(0)` is actual erasure history; `None` only observes
  no local row and is not a complete-history or OriginalSourcePos proof. Missing
  storage or a revision/read failure returns an error, never fabricated absence.
  Generic historical plaintext after any erasure needs the caller's actual
  source-position/floor proof or remains incomplete; a current A2 key is not
  that proof. `seal_plain_source` compares the proved floor expectation
  atomically with key selection at protection.
- `Sealer::seal_plain_source(value, expected_erasure_floor, fill, wall)`
  protects plaintext only after its caller verifies the current ready proof:
  matching erasure receipt and namespace, source/materialized coverage, and no
  old plaintext across cells, schema and sequence data. The required argument
  is an expectation, not that proof: `None` means proved never-erased;
  `Some(0)` is a real receipt. A mismatch fails before any key creation or
  plaintext replacement. It bypasses newest-cache selection, and original
  sealed versions still use `seal_value_at(original_version)`, never promotion.
  Ordinary privacy-off handling does not mint a key. Missing source proof
  leaves the operation incomplete while preserving keys and data.
- Internal shard bootstrap can export one original wrapped subject-key version
  and its observed erasure floor from one SQLite read snapshot. It exports
  neither a master nor a plaintext data key and never creates a fallback key.
  The receiver asserts the separately committed expected subject/version,
  verifies the existing wrap/AAD under the already shared protected master,
  and preserves an existing equivalent raw key's original envelope and times.
  Only a separately proved, subject-bound global floor can advance local state;
  physical shared-key deletion requires the actual GLOBAL epoch/all-required-
  replica barrier and LOCAL hosted-shard cuts, not one shard's erasure/intent.
  The method's floor tuple is an expectation/projection, not that proof. A
  floor that has not been proved cannot authorize deletion, and absence is not
  floor zero.
  The already-admitted receiving host supplies its actual clock only to stamp
  a newly applied local floor; unchanged/lower floors preserve their old time,
  and the capsule's erasure time is diagnostic, not authority. Floor advancement
  and noncovered envelope insertion share one transaction/revision; conflicts
  and failures leave both unchanged.
  The cluster caller owns authoritative SourcePos/epoch/barrier, current member
  and registered install assignment, and final term/principal admission after
  all waits/body/capacity. These primitives do not bootstrap the shared master,
  prove a complete source cut, or grant production access while recovering.
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

## 3. Modes and the `PrivacyMode` record

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

## 4. Sealing points

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

## 5. Unsealing and redaction

- **Inside turns:** the host unseals before the guest sees a value (state
  reads, delivered message bodies, recorded effect responses on re-run). An
  erased state value reads as absent. Any other erased input (a queued
  message body, a recorded response) fails the turn with `SUBJECT_ERASED`
  as a dead letter: the turn can't run on data that no longer exists. A
  queued timer or message body of an erased subject is a tombstone (§6.3),
  also one written in `off` mode, so that holds for plain bodies too.
- **API output** (`actors inspect`, `history`, diffs, MCP): with `pii:read`,
  sealed values are unsealed. Without it they show as `[sealed]` (as built:
  no subject id either, see §14), and erased ones as `[erased]` for every
  caller. An API call that reads an
  erased value directly (`GET` of one state key, an effect body) gets
  `SUBJECT_ERASED` (410). Plain values written in `off` mode are shown as
  they are: `off` protects nothing, which docs must say.
- Redaction happens where the API renders a `Sealable`: one helper,
  `render_sealable(&Sealable, &Caller) -> Rendered`, in kronik-api, so the
  JSON API, MCP and diffs agree.

## 6. Erasure

`kronik privacy erase user:123 --reason R [--dry-run]` →
`POST /v1/privacy/erase {subject, reason, dry_run}` → `Node::erase_subject`:

1. `keystore.erase(subject, wall)` deletes the keys (durable: WAL with
   `synchronous = FULL`) and returns `last_version`. Doing this first means a
   crash before step 2 already leaves the data unreadable, and recovery sees
   an erasure row without a record and commits the record. From the
   deletion until the record is applied, no turn seals and appends a record
   (§6.8).
2. Commit `Erasure { epoch, subject, key_version: last_version, audit }`.
3. **The erasure operation** runs when the record is applied, once in
   production and again on every rebuild. It is recorded as this record, not
   as a changeset, because a changeset's old values would be the erased data
   (ADR 0005 §6). For every actor with SQL state it runs `DELETE FROM t WHERE
   _subject = ?` on each table with a `_subject` column, and it deletes the
   subject's KV rows from `state.db`. The bodies of the subject's pending
   timers and undelivered messages, and its values in the recorded effects
   of turns still open, become tombstones of its erased key version: the
   rows stay, so their turns still run and fail with `SUBJECT_ERASED`
   instead of handing the value to a guest, which would seal it again under
   a new key version. On rebuild the subject's
   changesets can't be unsealed and are skipped; the operation is then
   replayed, and the result equals the live database.
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
8. **What was in flight** (ADR 0123). Plaintext of the subject that the node
   already held is never handed to a guest after the erasure, nor sealed
   again under a key version newer than the erased ones:
   - Every queued input and every running turn carries where its values
     came from: the node's erasure generation for what it holds in memory (a
     request, a message or a call a turn sent, a compensation), the LSN that
     recorded it for what it read back (a re-run, a mailbox row, a timer). A
     value of a subject erased after that point predates the erasure.
   - An input with such a value fails its turn with `SUBJECT_ERASED` before
     guest code runs, a re-run's recorded effects included, and its record
     holds the erasure's tombstone in place of the value (an open turn is
     closed under its own execution id). Applying the record also tombstones
     such values in the inputs still queued.
   - A turn that runs across the erasure finishes, but every record it
     writes (`TurnBegin`, effect results, `TurnRecord`) is sealed against its
     provenance: a value that predates the erasure becomes the tombstone, and
     so do the values of the messages it sends. A turn takes its provenance
     before its input is checked; until the record is applied, what the node
     takes in counts as born before the erasure (the subject's rows are still
     there to read). Sealing and appending a turn's record take a fence
     shared, the erasure takes it from before the key deletion until its
     record is applied: a record lands before the `Erasure` record, sealed
     under the erased version, or is sealed knowing of it, never under a
     newer key.
   - The deletes in an actor database wait for a turn of the actor that has
     its savepoint open, and run right after the turn's end rolls it back:
     run inside it, they were rolled back with it (and recorded by its
     session as the turn's own changes). The database's applied LSN stays
     below the erasure's until then, so a stop in between replays it.
   - In `state.db` the bodies of pending timers and undelivered messages, and
     the recorded effects of turns still open (`open_effects`, which a re-run
     hands to its guest), become tombstones (step 3); reseal rewrites
     `open_effects` with the effect results it rewrites (§8).
   - `privacy status` counts an erasure as pending while the log, `state.db`,
     or an input still queued in this process holds a plain value of it, and
     while a turn that began before its record was applied still runs.
   - A fork never creates a key version for an erased subject: what it
     writes of one (its log, its samples, the turns a rebase stages into
     main's log) is the erasure's tombstone.
   A subject can come back after its erasure: a value that arrives after the
   erasure began is new data, sealed under a new key version (§2).

Erasing a subject that has no key still records the erasure and runs the SQL
deletion, and it works in `off` mode too (there are no keys, version 0).

## 7. Rows in tables without `_subject`

Decided: option B (ADR 0005 §6). Option A, a host-side row-owner table, is
not implemented. A turn that has a default subject may only write tables
that have a `_subject` column. A write to a table without that column fails
the turn with `subjects/table-without-subject` and names the table. Turns
without a subject may still write anywhere, so configuration tables stay
possible.

`rows_without_subject_column` stays a no-op because new writes are refused.
Erasure of rows that already have a `_subject` value is unchanged
(`DELETE FROM t WHERE _subject = ?`). Existing rows written before this
decision are not rewritten. Old rows in tables without `_subject`, or with
a NULL `_subject`, belong to nobody and survive erasure. An existing table
gets the column with `ALTER TABLE … ADD COLUMN _subject TEXT DEFAULT
(kronik_subject())`; rows already in it stay NULL until rewritten by the
application.

## 8. Reseal via compaction

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
- It does the same for the `state.db` rows the rewritten records still own
  (state values, the bodies of pending timers and undelivered messages,
  saved responses, dead-letter inputs) and takes a snapshot afterwards.
- Progress (segments done/total, values sealed, tombstones) appears in
  `privacy status`. Docs recommend running reseal right after turning the
  mode on, before the first erasure.

## 9. Forks without PII

`kronik fork create --no-pii`; tokens without `pii:read` always get it
(`no_pii = request.no_pii || !caller.has(PiiRead)`):

- The fork's host never hands a real value to the fork's guests. Every
  tagged value a turn reads, sealed or plain, is replaced by
  `Pseudonyms::of(subject, plaintext)` = `pii:` + 12 hex of a keyed BLAKE3
  (key `derive_key("kronik pseudonym v1", master)`, in
  `crates/kronik-privacy/src/keystore.rs`). The
  host unseals transiently to compute it, so equal values get equal
  pseudonyms and equality checks in guest logic still hold. Without the key,
  a pseudonym can't be checked against a guessed value. A production value
  that already has the shape of a pseudonym is replaced too; only a value
  the fork itself wrote (a revealed record's, or a guest's) is read back as
  it is, so a pseudonym stays equal to itself (issue #69). Erased values
  become `[erased]`, except an erased state value, which reads as absent.
- Subject-tagged SQL changesets are pseudonymized before they are applied
  to the fork's actor database. Text and blob cell values become
  `Pseudonyms::of(subject, bytes)`; old and new images are rewritten the
  same way, so a later UPDATE still matches. Integer and real values,
  including primary keys, stay so apply can find the row. The `_subject`
  column stays the subject id, so erasure still finds the row. A snapshot
  the fork continues is rewritten the same way before later changesets are
  applied. Changesets with no subject are not rewritten. Erased subjects
  stay skipped and unreadable.
- **Carve-out: numeric cells (#70).** Integer and real cells are applied as
  production recorded them, key columns or not: a `--no-pii` guest that
  selects a subject's age, amount or account number stored as `INTEGER` or
  `REAL` reads production's number. So "a `--no-pii` guest cannot `SELECT`
  plaintext that production stored for a subject" holds for text and blob
  cells only. Store numeric personal data as `TEXT` (or a `BLOB`) where a
  `--no-pii` fork must not see it. Pseudonymizing non-key numeric cells (a
  deterministic per-subject value, keys left real) is left to a later ADR.
- The replay runner marks a turn that read at least one pseudonym. If such a
  turn's result differs from production, the diff calls it `pii-masked`
  instead of `diverged`.
- Diffs of a `--no-pii` fork show the pseudonyms, never real values.

## 10. Keystore backup

`Keystore::export_backup(nonce)` produces one blob: `KRKSTOR1`, a 24-byte
nonce, and XChaCha20-Poly1305 under `derive_key("kronik keystore backup v1",
master)` of every key row and erasure row. Subject ids are therefore hidden
too. `Keystore::restore_owned(original_owner, master, blob)` restores it using
the same exclusive data-directory owner and shared negative publication as all
other mutable handles. `reopen_owned()` shares that owner; private memory and
actual read-only connections are distinct modes, not file-owner substitutes.

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

## 11. Gateway subject

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
  subject in the actor. The documentation must say this.

## 12. API and CLI

| Endpoint | Scope | Request | Response | Phase |
|---|---|---|---|---|
| `GET /v1/privacy` | `read` | — | `{mode, epoch, keystore: {subjects, keys, erased} \| null}` | M8 |
| `POST /v1/privacy/mode` | `operate` | `{mode: "on"\|"off", reason, dry_run}` | `{dry_run, changed, mode, previous, epoch, lsn}` | M8 |
| `POST /v1/privacy/erase` | `operate` | `{subject, reason, dry_run}` | `{dry_run, subject, key_version, lsn, plain_values, complete_after_ms}` | planned |
| `POST /v1/privacy/reseal` | `operate` | `{reason, dry_run}` | `{dry_run, started, segments}` | planned |

`mode` is `"off"` or `"on"`. `epoch` is `null` before the first `PrivacyMode`
record. `lsn` is `null` for a dry run or when nothing changed. Errors:
`BAD_REQUEST` (a bad mode or subject), `REASON_REQUIRED`, `SUBJECT_ERASED`,
and the usual auth errors.

CLI (in `cli/privacy.rs`): `kronik privacy mode on|off --reason R
[--dry-run]`, `kronik privacy status`, and the planned `kronik privacy erase
<subject> --reason R` and `kronik privacy reseal --reason R`, all with
`--json`.

Seams in the core crates, agreed:

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

- **Builds:** the pre-M8 baseline against M8 in `off` mode, same machine,
  release builds, nothing else running.
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
- `scripts/bench-privacy.sh` prints a results table for
  `docs/guides/privacy.md`.

## 14. Implementation notes

Where the code differs from the sections above:

- **One seal point.** `Node::commit` and `Node::append` seal the record in
  place (`kronik-sched/src/sealing.rs`); the walk over a record's
  `Sealable`s is `kronik_proto::sealables::record_mut`. In `off` mode that
  is one relaxed atomic load; the guest's input was cloned before M8 as
  well, so unsealing it adds no allocation, and a guest's state read and
  the apply of a plain SQL changeset are what they were before M8. Values the guest and API callers
  see come from in-memory copies or are unsealed on the way in. Fetch
  effects carry the guest's subject (`FetchRequest.subject`), call effects
  the message's.
- **The request line (v0.1).** A gateway request with a
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
  pattern instead of the path (others see the path). A
  `--no-pii` fork pseudonymizes the request line like every tagged value
  (revealing it would hand real paths and queries to code an agent can
  write). A turn that read a pseudonym
  (`ForkTurn::pseudonyms`) and differs from production, failing included,
  is `pii-masked` (`diff::Acc::turn_errors` and the causal grouping skip
  it): no introduced error, origin or consequence, so `no-new-errors` does
  not deny on masking alone (an SQL turn's output is still concealed;
  `turn_errors` still counts its errors). A production turn missing below such a turn is `pii-masked` too.
  Masked runs can't tell broken code from correct code, so while
  `summary.pii_masked + summary.pii_unverified > 0` (the latter: turns of
  changed code identical on pseudonyms, `Acc::pii_same`) the evaluation
  has the floor
  `pii-masked-needs-approval` (require_approval, in `RuleSet::evaluate`,
  ADR 0031); a `pii:read` reviewer re-runs on real data to see such a
  turn's real behaviour before approving. Validation (`kronik_proto` `input()`) requires a value in
  each present sealable field.
- **Idempotent replays stay with their requester (v0.1).**
  `HttpInput.request_hash` is a version byte
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
  gets that failure instead of a second run. The bodies of its pending
  timers and undelivered messages become tombstones (§6.3). Dead letters a
  subject's turns produce after its erasure stay (their input is sealed
  under the erased key); resending one fails with `SUBJECT_ERASED`.
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
  and the rows the rewritten turns (a rebased turn of a `StateRebase`
  record too) still own (`kv` values, the bodies of their pending timers
  and undelivered messages, saved ingress and call responses, dead-letter
  inputs; a row a later turn replaced is left), are fixed in one
  `state.db` transaction, followed by a WAL checkpoint (issue #31: a timer
  scheduled in `off` mode kept its plain body after a reseal and was
  handed to its guest after the subject's erasure). Rows of an erased
  subject are already gone or tombstoned by its `Erasure`; a value of it
  in a row that remains becomes a tombstone. The active segment is left for the next roll. A snapshot
  follows. Rewritten segments are marked for re-upload
  (`privacy/reupload/<start>`); `GET /v1/privacy` counts them in
  `reseal.pending_segments` until the shipper replaces the object. Status
  also reports `pending_erasures` and `reseal.{segments_done,
  segments_total, values_sealed, tombstones}`. `pending_erasures` counts
  the erased subjects that still have a plain value in the log or in
  `state.db` (state values, queued timer and message bodies, saved
  responses, dead letters, the recorded effects of open turns). A dry run
  writes nothing.
  A second reseal with nothing plain left rewrites nothing. No guest code
  runs. `kronik privacy reseal [--dry-run] --reason '...'` is the CLI
  wrapper.

  An explicit request now records `PrivacyMode.reseal_requested = true`
  (field 4) with mode `on` before rewriting. Ordinary mode changes and
  historical records leave it false; being in `on` mode does not request a
  reseal. This record is the request, **not completion**. The native worker
  keeps the deploy lock through request publication and rewriting, without
  draining open turns for an unchanged mode. The `privacy.reseal` audit is
  still emitted only after successful work. A dry run records neither.
  A requested reseal with no eligible closed segments rewrites nothing.
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
  `{redacted, subject, hash}` (as before M8), and so do the
  values of a subject's SQL rows. Since the v0.1 fix, so do the url,
  header and body fields of an effect request recorded under a subject,
  response header values with a subject, and the final-state rows with a
  `_subject` in continuous replay; the Markdown diff shows such a value as
  `[sealed:<subject> <hash>]`. Fork turns (`GET /v1/turns/<fork>:…`) and
  `trace` are redacted per caller like production turns.
- **Who sees subjects (v0.1).** A caller without
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
  Subject-tagged SQL changesets are unsealed and, for `--no-pii`, have
  their text and blob cells pseudonymized before the fork store applies
  them (`sql::pseudonymize_changeset`); a snapshot the cursor loads is
  rewritten the same way. Integer and real values and the `_subject`
  column stay. Changesets with no subject are applied as recorded. So a
  `--no-pii` turn that
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
  divergent, an error or a cause. A state value the base snapshot holds is
  production's and is replaced like a recorded one; a value the replay wrote
  that already is a pseudonym is read back as it is (issue #69). An erased
  subject's state value stays sealed in the fork's store, reads as absent
  and marks the reading turn as one that met erased data (ADR 0109), as do
  reads of state that erased data shaped there. HTTP root inputs keep the gateway's
  subject in forks (taken from the body's or a header's tag). A fork
  records its effects with the
  guest's subject as production does, and seals what it writes to disk (its
  log and `isolated.jsonl`) with the node's sealer, so no plain value of a
  subject reaches a fork's files in `on` mode. Forks written before that
  fix keep their plain files until deleted.
- **Tables without `_subject` (§7)** are decided: option B. A turn with
  a default subject that writes such a table fails with
  `subjects/table-without-subject`. `rows_without_subject_column` stays
  a no-op because those writes are refused. Old rows without a subject
  still survive erasure.
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
  `docs/perf.md`: `off` is within run-to-run noise of the pre-M8 baseline,
  `on` adds 32 % to 57 % log bytes per record.
