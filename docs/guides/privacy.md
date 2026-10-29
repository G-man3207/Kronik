# Privacy mode

Privacy mode is the switch that lets Kronik keep personal data in a form
that can be erased: every value carries the subject it belongs to, and with
the mode on, values are encrypted with one key per subject, so deleting
the key makes them unreadable everywhere. This guide is for operators, who
decide whether to use the mode, and for actor authors, whose code decides
which subject each value belongs to. The design is in
[M8 privacy design](../design/m8-privacy.md).

**Responsibility.** The operator decides whether the mode is used and is
responsible for the legal basis, agreements with processors, and retention
periods. Kronik provides the mechanism described here and states exactly
what it does and does not do; it does not make a system compliant by
itself.

## Subjects

A subject names whose data a value is: a string of 1 to 256 printable
ASCII characters without spaces, such as `user:123`. A value has at most
one subject. Data that belongs to several people is modeled as separate
values.

Every value in the log carries its subject tag, also when the mode is off.
That is what lets erasure, redaction and the mode work per value instead of
per turn. A value gets its subject in four ways:

- **In actor code, the turn's default subject**, for every value written
  after it is set. It can change in the middle of a turn:

  ```rust
  ctx.subject("user:123");             // Rust; ctx.subject(None) clears it
  ```

  ```ts
  ctx.subject("user:123");             // TypeScript; ctx.subject(null) clears it
  ```

- **For one write**, whatever the default is:

  ```rust
  ctx.state().set_for(Some("user:456"), "email", b"bob@example.com");
  ```

  ```ts
  ctx.state.setFor("user:456", "email", "bob@example.com");
  ```

- **From the gateway**, for HTTP requests:
  `privacy.subject_from = "header:x-user-id"` takes the subject from a
  header, and `"jwt:sub"` takes it from the `sub` claim of the bearer JWT
  in `Authorization`. The subject becomes the request's default subject and
  the tag of its path, query, route parameters, headers and body. A missing
  header, token or claim means no subject; one that is present but unusable
  gets `400 BAD_REQUEST`, and so does a subject header (or `Authorization`
  for `jwt:`) that appears more than once or holds a comma-separated list.

  **Kronik does not verify the JWT's signature in v0.1; it only reads the
  claim.** Whoever can reach the gateway can choose the subject. The subject
  tags data; it is not authentication. Put an authenticating proxy in front
  of the gateway, or check the token in the actor. The proxy must *replace*
  the subject header a client sent, not append to it. With
  `[gateway] trusted_proxies` set, only a connection from a listed proxy may
  carry the subject: a request with the subject header (or, for `jwt:`, a
  bearer token with the claim) from any other peer gets `400 BAD_REQUEST`
  ("the subject header is accepted only from [gateway] trusted_proxies"),
  rather than running without a subject, which would store its data
  unsealed and beyond erasure. Requests without one run as usual. List the
  proxy's address as it connects (IPv4 or IPv6). With `trusted_proxies`
  empty, every peer's header counts.

  The method and the route pattern (`/notes/{key}`) are configuration and
  stay plain. **Actor keys are identities, not values:** the key in
  `/notes/carol@example.com` is the actor's name, plain in the log, in
  `GET /v1/actors`, in history and in the daemon's log, for every caller and
  after an erasure. Use opaque keys (a random id, a keyed hash of the e-mail
  address) and keep the personal data in the actor's state.

- **From the API**: a message sent with `POST
  /v1/actors/<kind>/<key>/messages` can carry a `subject`, which becomes its
  turn's default subject.

The input's subject (from the gateway or the message) is the turn's default
subject until the code changes it. In Rust, `ctx.current_subject()` returns
the one in force.

### SQL state

An actor's SQL rows get their subject from a `_subject` column, and the log
keeps one changeset per subject ([ADR 0005](../adr/0005-sql-state.md) §6).
Declare it with the turn's default subject as the default:

```sql
CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  item TEXT NOT NULL,
  _subject TEXT DEFAULT (kronik_subject())
);
```

- `kronik_subject()` returns the turn's default subject, so rows written
  under `ctx.subject("user:123")` carry `user:123`.
- A row's subject can't change: `UPDATE … SET _subject` is refused (delete
  the row and insert it again), and a turn whose writes would move a row to
  another subject fails.
- Erasure deletes the subject's rows from every table that has `_subject`.
- **Rows in tables without `_subject` are not deleted by erasure.** Their
  changesets are sealed under the turn's default subject, but the rows
  themselves carry no subject. Give every table that holds personal data a
  `_subject` column. How such rows should be handled is an open question
  for the project's owner (ADR 0005 §6).

## The modes

**`off`**, the default, records the subject tags and nothing else: no
encryption and no cost. Values are stored in plain text in the log, the
state and the actors' databases, and any caller with the `read` scope sees
them. `off` protects nothing; it keeps the format ready for the mode.

**`on`** seals every tagged value written from then on: inputs, message
bodies, state values, SQL changesets, effect requests and responses, and
saved responses. Sealing is XChaCha20-Poly1305 with the subject's own key,
bound to the subject and key version. The keys are in
`<data_dir>/keys/keystore.db`, each encrypted under the master key (see
[the master key](operations.md#the-master-key)). Values without a subject
stay plain.

**Every new subject id creates a key**, the first time a value of it is
sealed. The keystore, and each of its backups, grows with the number of
distinct subjects; `privacy status` counts them (`keystore.subjects`). Who
picks the subject ids decides how many keys there are, so take them from an
authenticating proxy (a header it sets after login, or a token it has
verified), not from whatever clients send: a client that sends a new id
per request makes a new key per request.

The mode is a recorded change with a reason, like a deployment
([`kronik privacy mode`](../reference/cli.md#kronik-privacy-mode),
[`kronik privacy status`](../reference/cli.md#kronik-privacy-status)):

```sh
kronik privacy mode on --reason "GDPR: production starts"
kronik privacy status
```

`privacy status` shows the mode, the epoch of its record, the keystore's
counts (subjects, keys, erased subjects), how many erasures still have a
plain value in the log, and reseal progress (segments done and total,
values sealed, tombstones, segments waiting to be re-uploaded). Asking for
the mode already in effect records nothing. The API is `GET /v1/privacy`
and `POST /v1/privacy/mode`.

- Only values written **after** the mode is turned on are sealed. History
  written in `off` mode stays plain in the log until a reseal (below).
- Turning the mode off stops sealing new values. Sealed values stay sealed.
- Actor code never sees the difference: the host unseals values before a
  turn reads them.

## Who sees what

Reading sealed values needs the `pii:read` scope. Without it, `actors
inspect`, turn details and `trace` show a sealed value as `[sealed]`, and
never a subject id: the `subject` fields of state values, writes and turn
values are null. An erased value shows as `[erased]` for everyone. Plain
values (written in `off` mode, or without a subject) are shown as they are.

A fork made without `--no-pii` holds production's values in plain, so
sending a message into it, and reading its turns (`GET /v1/turns/<fork>:…`,
`kronik trace`), needs `pii:read` too (`SCOPE_MISSING` otherwise); MCP's
`send_to_fork` and `trace_turn` go through the same checks.

Callers on the Unix socket without a token (root, or members of the
`kronik` group) have every scope. Tokens (`kronik token create --scopes
...`) get `pii:read` only when it is given explicitly; the default scopes
are `read`, `fork` and `propose`.

For an HTTP request with a sealed value, a caller without `pii:read` also
sees its path, query, route parameter values and `Idempotency-Key` as
`[sealed]` in turn details, including records written before path and
query became sealable. History, dead letters and `trace` summarize such an
HTTP input by method and route pattern for that caller; callers with
`pii:read`, and requests without a sealed value (privacy mode off, or no
subject), get the method and path.

A saved response to a request with an `Idempotency-Key` is replayed only to
the same requester. With a subject, the requester is the subject alone: a
rotated cookie (a load balancer's sticky cookie) or a refreshed token in a
client's own retry still gets the saved response. Without a subject, the
requester is the `Authorization` header's value (none: anonymous);
`Cookie` never counts. The same key from another requester is
`422 IDEMPOTENCY_KEY_REUSED`, never the saved response. So without a
subject, two cookie-only sessions that send the same `Idempotency-Key`
share its saved response; set `subject_from` where sessions are cookies.
Responses saved with an older hash (v0.1 candidates) count as expired, so
such a key is used anew. Hashes that sit next to sealed values (the
request hash, effect fingerprints of a subject's requests, the diff's
`redacted` hashes) are
keyed with a key derived from the master key, so nobody holding the data
directory or a shipped copy without the master key can confirm a guessed
value with them.

## Erasure

Erasing a subject deletes its keys and records an `Erasure` record
([`kronik privacy erase`](../reference/cli.md#kronik-privacy-erase), or
`POST /v1/privacy/erase`):

```sh
kronik privacy erase user:123 --reason "erasure request #4711" --dry-run
kronik privacy erase user:123 --reason "erasure request #4711"
```

The erasure itself:

1. The subject's keys are deleted first, durably, so a crash right after
   already leaves its sealed values unreadable. If the daemon stops before
   step 2, its next start writes the missing `Erasure` record (audited as
   `kronik`) before anything else runs.
2. The `Erasure` record is written. Applying it deletes the subject's state
   values, its rows in every table with `_subject` of every actor, its
   saved responses to requests with an `Idempotency-Key` (a repeated
   request runs anew) and its dead letters. A saved response of a call to
   an actor becomes an erased marker: a repeated call fails with
   `SUBJECT_ERASED` instead of running again. The same happens when the
   state is rebuilt from the log, so a rebuild equals the live databases.
   The databases zero deleted rows (`secure_delete`) and their write-ahead
   logs are emptied right after (the keystore's before the record is
   written), so no copy of a deleted row or key stays in the data
   directory's files.
3. From then on, the subject's sealed values in the log are unreadable for
   everyone, the API shows them as `[erased]`, and its state values read as
   absent in turns. A queued input of the subject fails its turn with
   `SUBJECT_ERASED` (a dead letter): the turn can't run on data that no
   longer exists.

Other subjects are unaffected, also their values written in the same turn:
each has its own key, its own changesets and its own rows.

`plain_values` counts the subject's values written in `off` mode that are
still in plain text in the log. Erasure does not rewrite those segments;
`POST /v1/privacy/reseal` does (below). Until then the erasure is pending,
and `privacy status` counts such erasures without naming subjects.

Applying the erasure also takes a new snapshot and deletes local snapshots
older than it, so a restore or a fork cannot go back to a copy that still
holds the subject's rows. Snapshots are compact copies of the databases'
live rows, without the free space deleted rows occupied. A fork of a point
before the erasure fails with the usual "outside retention" error. Shipped
copies of those snapshots are deleted on the next shipping round (the
manifest first).

**Reseal.** `POST /v1/privacy/reseal` with `{reason, dry_run}` rewrites
closed log segments. The mode must already be `on`. A tagged plain value
becomes sealed with the subject's current key; a value of an erased
subject becomes a tombstone that can never be unsealed. LSNs and record
order stay the same. The state values, saved responses and dead letters
that the rewritten records hold in `state.db` are sealed the same way. The
segment still being written is left until the next roll. A dry run reports
how many closed segments would change and writes nothing. Run it after
turning the mode on, before the first erasure. The command is `kronik
privacy reseal --reason "..."`; `--dry-run` writes nothing.

**When erasure is complete.** Inside the data directory, the keys are gone
at once. The shipper uploads an encrypted backup of the keystore (not the
master key) after a change, at most once a minute, and once a day, and
deletes backups older than `privacy.keystore_backup_retention` (30 days
by default; `kronik serve` applies the file's value), always keeping the newest. `complete_after_ms` on the erase
response is the erase's wall time plus that window. Count the erasure as
complete when that time has passed and reseal and the snapshot replacement
are done.

## Forks without personal data

`kronik fork create --no-pii` gives a fork whose actors never see real
personal data, in every privacy mode (values are tagged in `off` too):
every tagged value they read is replaced with a pseudonym, `pii:` and 12
hex characters. Pseudonyms are a keyed hash of the subject
and the value, so equal values get equal pseudonyms (equality checks in the
code still hold), and without the installation's key a pseudonym can't be
checked against a guessed value. Erased values read as `[erased]`. That
includes an HTTP request's path, query and route parameters, so code that
dispatches on a route parameter can take another branch or fail.

A turn whose result depends on the real value can diverge from production.
If such a turn read a pseudonym or an erased value and differs from
production, failing where production committed included, its diff marks
it `pii-masked` (`summary.pii_masked`, `samples.pii_masked`) instead of
diverged: it is no introduced error, origin or consequence. So is a
production turn missing below it. The default `no-new-errors` rule does
not fire on masking alone, but a masked run can't tell broken code from
correct code either. A turn of changed code that read a pseudonym and
came out identical did not run on the real value either
(`summary.pii_unverified`). While `pii_masked + pii_unverified` is above
0, the policy outcome is at least `require_approval`
(`pii-masked-needs-approval`, a floor in code that no `policy set` drops;
ADR 0031). An approval holds when promote's catch-up adds such turns. What such a turn
really does is not shown: a reviewer with `pii:read` sees it by
re-running the proposal or fork on real data (a fork without `--no-pii`),
before approving.

Tokens without `pii:read` always get such forks, whatever they ask for. A rollback via replay
(`kronik rollback --by-replay`) is the exception: it runs on full data,
because its turns become main's state, so creating one needs `pii:read`
(`SCOPE_MISSING` otherwise).

Diffs never show a subject's values, in any fork and to any caller: state
values, bodies, response header values and the url, headers and body of an
effect request made for a subject appear as `{"redacted": true, "subject":
"s:…", "hash": "k:…"}` (`[sealed:s:… k:…]` in the Markdown diff), and the
values of a subject's SQL rows as `[redacted:s:…:k:…]`. A diff is stored
once and shown to every caller with `read`, so it never names the subject
either: `s:` and 12 hex characters is a keyed hash of the subject id (equal
subjects get equal ones), and the `k:` hash (16 hex characters) is keyed
over the subject and the value, so neither can be checked against a guess
without the installation's master key. The offline `kronik upgrade check`
has no key and shows `-` for both. A `--no-pii` fork's actors ran on
pseudonyms, but its diff shows these hashes. A fork's turns (`kronik trace
<fork>:…`) are shown like production's: sealed without `pii:read`. In `on`
mode a fork seals what it writes to disk, as the main log does.

SQL rows are not pseudonymized: SQL changesets are applied to a fork's
actor databases unsealed, so even a `--no-pii` fork's SQL state holds real
rows (in memory, while the fork replays). A `--no-pii` fork therefore
treats a turn that used SQL, called a turn that did, or was sent a message
or timer by one as personal data: its values (reply, writes, messages,
effects, outcome message) read `[sql]` in the reply to `send_to_fork`, in
its turn and trace and in the fork's files, and its diff shows them
redacted under the subject `[sql]`; its differences count as
`pii-masked`. This covers what such a turn produces, not everything code
can do with what it read: a value it writes to state and a later turn
reads, or data it puts into names, keys or URLs, is not tracked. A
`--no-pii` fork limits what reaches its callers; it is not a sandbox
against code written to move rows out.

## Logs and other output

- **Actors' log lines are not sealed.** They go to the daemon's log
  (target `kronik::guest`), not to Kronik's log. Don't log personal data;
  `execution_id` and `causal_id` identify the turn without it.
- Metrics never carry subjects.
- **OpenTelemetry export** (`[otel]`, [operations
  guide](operations.md#opentelemetry)) carries no sealable value, in any
  mode: spans have actor kinds, route patterns and methods, status codes,
  outcome kinds, error codes, effect kinds, target hosts and secret names,
  never a body, header, path, query, reply, state, guest-written error
  text, subject id or secret. Actor keys, which are plain everywhere else,
  leave hashed by default (`actor_keys = "hashed"`: `kh:` and 12 hex of a
  keyed hash, stable but not reversible without the node's key), because a
  key can be an e-mail address and the backend is outside the node.
  `"plain"` sends them as they are, `"none"` leaves them out. An incoming
  `traceparent` contributes only its two ids, and none once its subject is
  erased.
- **Audit lines** (`[audit]`; ADR 0082) carry no sealable value, no body
  and no subject id. An erasure's subject leaves as
  `s:` plus 12 hex of its keyed hash, also inside its reason; actor keys
  are hashed by default (`[otel] actor_keys`). The audit line's
  `record_hash` covers each sealed value as its subject tag only, so a
  reseal or an erasure changes no exported line. Other reasons leave the
  node as written: keep personal data out of `--reason`.
- Code that has seen a value can always leak it, for example in a log line
  or an outgoing request. Sealing protects what Kronik stores, not what
  actors do.
- **Erasure only reaches values tagged with the subject.** A guest that
  copies several subjects' data into one output makes a value erasure
  can't find. For example, a `list` handler that answers with every row:

  ```rust
  // Reply: "alice@example.com [user:1]\nbob@example.com [user:2]"
  let rows = ctx.sql().query("SELECT body, _subject FROM notes", &[])?;
  ```

  The reply carries the turn's subject, the caller's (or none, so it is
  plain), not `user:1` and `user:2`. Erasing `user:1` deletes its rows but
  not the copy in that reply: in the log, in a saved response to an
  `Idempotency-Key` request, or in whatever the caller stored it in. Return
  only the caller's own rows, or one subject's rows per reply under
  `ctx.subject(...)`.

## Limitations

- The gateway reads the JWT's claim without verifying the token (above).
- The segment still being written is not resealed until it rolls. History
  in that segment stays plain until the next reseal.
- Rows in SQL tables without `_subject` survive erasure.
- Requests recorded before path, query and route parameters became
  sealable fields hold them plain in the log; they are hidden from callers
  without `pii:read` but survive erasure and reseal. Actor keys are always
  plain (above).
- SQL rows are stored in plain text in the actors' databases, also in `on`
  mode; their protection is that erasure deletes them.
- A value has one subject. Data a guest copies into a value of another
  subject, or of none, survives the erasure of its own (above).
- Losing the master key loses every sealed value and every keystore
  backup. There is no master-key rotation in v0.1. The master key is
  never shipped; back it up separately.
