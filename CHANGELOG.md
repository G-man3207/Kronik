# Changelog

All notable changes to Kronik are recorded here. The project is pre-alpha; the
formats, the API, the WIT interface and the CLI may change between releases
until the v1.0 compatibility promise takes effect.

## Unreleased

- After a restart, the views that remove secret values (`history`,
  `actors inspect`, turns, traces, dead letters, the audit log and others)
  answered 503 `SECRET_UNAVAILABLE` for good once the external backend of a
  linked secret no longer served a version the node had recorded (destroyed,
  removed by a version limit, a changed `env` variable): a known defect of
  0.5.0-dev. The node now keeps an encrypted, scrub-only copy of each external
  version it records in `keys/secrets.db` (XChaCha20-Poly1305 under a key
  derived from the master seed, bound to the version's identity; ADR 0142),
  and a restart scrubs with it. The copies never answer an effect, a re-run,
  a fork, a reveal or a foreign actor; they travel inside snapshots with
  `secrets.db` and stay valid across `keys rewrap`. Versions recorded by an
  earlier release get their copy at the first start while the backend still
  serves them. **External secret values are now at rest, encrypted, in the
  data directory, its snapshots and the bucket.**
- The actor WIT is now `kronik:actor@0.1.1` (M24, ADR 0113). It adds the
  `connections` interface (WebSocket and SSE frames: `send`, `broadcast`,
  `close`, `send-now`) and the world `actor-connections`, whose components
  also export `connection-handler` (`open`, `frame`, `close`); nothing that
  existed changes, and components built for `0.1.0` link and run as before.
  Routes may declare the pseudo-methods `WEBSOCKET` and `SSE`; deploy and
  propose refuse such a kind with `BAD_REQUEST` when its component lacks the
  `connection-handler` export, and an `SSE` route conflicts with a `GET`
  route on the same pattern (`ROUTE_CONFLICT`). The SDKs build against the
  new version; until the rest of M24 lands, the `connections` functions
  trap with `NOT_IMPLEMENTED` and the gateway opens no connections.
- A turn could commit a log record over the 128 MiB record limit (for
  example many large HTTP responses or state writes in one turn), which
  `history` then refused with `STORAGE_CORRUPT: entry length ...`, and after
  an unclean stop the start cut the acknowledged record off as a torn tail
  and stopped with `state.db has applied lsn N, but the log ends at M`
  (#26). Everything a turn records now counts against one budget: an effect
  that no longer fits does not happen, a response is read only as far as
  fits, and a turn whose record would not fit fails with the new code
  `TURN_TOO_LARGE` (an HTTP client gets `TURN_FAILED`; a message becomes a
  dead letter). The log refuses any record over the limit without writing
  it. Readers accept a complete over-limit record that an earlier release
  wrote, and a start never truncates a record `state.db` has applied: a
  damaged one is `STORAGE_CORRUPT` with nothing cut off. No log-format
  change. A turn that fails after an effect whose outcome is unknown keeps
  the code `EFFECT_OUTCOME_UNKNOWN` also when its record was too large. A
  turn that an earlier release left open with an input this budget does not
  hold is closed as failed (`TURN_TOO_LARGE`) at the next start instead of
  being refused at every start. A fork denies a call to an undeclared
  foreign actor with production's text and fits the answers it makes up
  (stub rules, contract fakes, neighbors, the model) to the record as it
  fits live ones.
- Forks, replays and proposals now work at every point of the
  `[retention] history` window, as the brief requires (#66). Retention kept
  the log for the window but only the newest `snapshots_kept` snapshots and
  the oldest one the log continued, so a point older than that snapshot
  (between 2 and 7 days back with the defaults) had no snapshot to start
  from and was refused as outside retention. Retention now keeps the
  window's base (the newest snapshot from before the window) and about one
  snapshot a day between it and the newest 48, and deletes only log that
  the base covers. **After the upgrade an installation keeps more on disk:
  about six more snapshots (each a full copy of the state), up to a day
  more log than `history`, and right after the upgrade, while no kept
  snapshot is older than the window yet, no log is deleted until one is (up
  to about 5 days with the defaults, at most one `history`), so the log can
  then reach back up to about twice `history`.** A proposal whose
  `--window` reaches back before the history window starts at its oldest
  point and says so (`window_cut`). Data from v0.3.0 or older: a v0.3.0
  snapshot that is the base is kept until a newer one is old enough, and so
  are the 503 answers described in the operations guide's "Upgrading from
  v0.3.0 or older".
- A snapshot taken while a turn was open could stop the next start that
  used it with a bare `log I/O failed: No such file or directory`:
  retention deleted the segment holding the open turn's begin, which the
  start reads to run the turn again (#35). Retention now keeps that segment
  while a turn is open in the state or in a kept snapshot, the snapshot's
  manifest names it, and a directory that already lost it fails with
  `STORAGE_CORRUPT` naming the turn's execution id. When that keeps a
  segment past `[retention] history`, the daemon says so: a log line naming
  the turn (a warning for a turn open in the running state), the gauge
  `kronik_retention_open_turn_segments`, `retention_pin` in `/v1/health`,
  and the new `kronik doctor` check `retention`.
- `kronik privacy erase` no longer lets the subject's plaintext that was
  already in flight reach an actor or be sealed again under a new key
  version: a message or call a turn had sent, a request waiting in a queue,
  a turn running across the erasure, or (privacy mode `off`) the recorded
  effects of a turn still open. Before, such a value reached the actor after
  the erasure, the turn's record was sealed under a new key version of the
  erased subject, and `privacy status` reported the erasure complete. Now
  an input that held a value of the subject from before the erasure fails
  with `SUBJECT_ERASED` before the actor sees it, a turn running across the
  erasure records and sends the erased marker in place of the subject's
  values, the erasure tombstones the subject's values in open turns'
  recorded effects (reseal seals them), and `privacy status` counts inputs
  still queued and turns still running from before the erasure
  ([ADR 0123](docs/adr/0123-erasure-stops-plaintext-in-flight.md)).
- An erasure applied while a turn of an actor had its SQL savepoint open
  left the subject's rows in that actor's live database: the deletes ran
  inside the savepoint, the turn's end rolled them back, and a rebuild
  from the log deleted them. The deletes now run right after the turn
  ends.
- `kronik upgrade check` (and every fork diff) no longer excuses more than
  an erasure explains. A turn whose input and effects are intact but which
  wrote a value of a subject erased later is compared like any other turn,
  without that subject's values, instead of counting as unverifiable. Once a
  subject's erasure in the window deleted its SQL rows, the actor's later
  SQL turns are verified again even when its database has a table without
  `_subject`: only an engine before 0.5.0 let a subject's turn write such a
  table. Before, a real change in those turns passed the check as
  unverifiable ([ADR 0109](docs/adr/0109-erased-input-is-unverifiable.md)
  points 7 and 9, now accepted). The check shows the count of unverifiable
  turns right under its verdict, also when it is 0.
- The privacy guide and the design now state a limit of `--no-pii` forks:
  they pseudonymize the text and blob cells of a subject's SQL rows only;
  integer and real cells reach their actors as production stored them.
  Store numeric personal data as `TEXT` where a `--no-pii` fork must not see
  it (#70).
- A fork (a proposal, a preview, a rebase) never creates a key version for
  an erased subject: what it writes of one - its log, and the turns a rebase
  stages into main's log - is the erasure's tombstone. A replay that
  meets a sealed value of an erased subject fails with `SUBJECT_ERASED`
  instead of `KEYSTORE_INCOMPLETE` ("its key is not in this node's privacy
  keystore").
- An open turn whose re-run after a restart met an input of an erased
  subject, or a kind that is no longer deployed, is closed once: its failed
  record now carries the turn's own execution id and its recorded effects.
  Before, the turn stayed open, every start added another dead letter for
  it, and retention kept the log from its begin on for good.
- `kronik upgrade check` passes after an erasure whose turns wrote state or
  SQL rows: those writes, and every other difference of a turn that met
  erased data (effects, response, errors, fuel), are no longer counted as
  changes. Before, `ENGINE_UPGRADE_DIVERGED` failed the check and `serve`
  refused the directory (issues #16, #27). A verified difference still fails.
- An erasure no longer makes other turns verified divergences
  ([ADR 0109](docs/adr/0109-erased-input-is-unverifiable.md), amended):
  production turns missing below a turn that met erased data are
  unverifiable, not divergent, origins or consequences (#28); a turn that
  reads state or SQL rows an erasure removed or shaped, whose input an
  unverifiable turn shaped, or that calls one, is unverifiable too (#29);
  the continuous replay applies production's erasures in its window, so a
  value written before the window and erased inside it is no difference;
  and `unverifiable` counts each turn once.
- In a fork, an erased state value reads as absent and marks the turn that
  read it, also when the value was written inside the replayed log; before,
  the guest read the bytes `[erased]` as the value (#49).
- `kronik privacy reseal` also seals the bodies of pending timers and
  undelivered messages in `state.db`, and an erasure turns its subject's
  queued bodies into tombstones, plain ones too: a timer scheduled in `off`
  mode no longer hands an erased subject's value to its actor, or seals it
  again under a new key version, after the erasure. Its turn fails with
  `SUBJECT_ERASED` as a dead letter. `privacy status` counts an erasure as
  pending while its subject has a plain value in `state.db`, not only in the
  log (#31).
- A replay hands the guest a pending timer's or an undelivered message's
  body the way it hands it any recorded value: opened, pseudonymized in a
  `--no-pii` fork, and `[erased]` for an erased subject, whose turn is then
  unverifiable. Before, the body went to the guest as the fork's store held
  it, sealed when a base snapshot held it.
- A `--no-pii` fork replaces a production value that already looks like a
  pseudonym (`pii:` and 12 hex characters) like any other tagged value; only
  a value the fork itself wrote is read back as it is (#69).
M23, key and secret backends:

- Foreign actors get a secret linked to an external backend through the
  node's secret cache, as the effects of turns do: `foreign add --secret` and
  every start read it from the cache or its backend (`SECRET_UNAVAILABLE`
  while the backend does not answer and nothing is cached; the next start
  retries) instead of refusing the name with `SECRET_EXTERNAL`.
- An unmatched `crypto.*` of a fork under a `compute` grant computes a name
  linked at the fork point with the value the node already holds for that
  link, and is denied with `SECRET_UNAVAILABLE` when it holds none, instead of
  `SECRET_EXTERNAL` for every linked name. Both are graded synthetic (ADR
  0132): what the node holds is not in the log, so the diff of a proposal
  grades them the same after a restart. The fork reads the value without
  touching production's stale tracking, `kronik_secret_stale` or its log. A
  fork still never asks a backend.
- After a restart, the crash re-run of a turn that used an older version of a
  linked secret made new effects use that version too, until `[secrets]
  refresh` passed, although a newer one had been recorded. Found against a
  real OpenBao.
- An effect whose backend did not answer in time could fail with
  `SECRET_UNAVAILABLE` although a value younger than `[secrets] max_stale` was
  held. Found by the new DST scenario `secret-outage`.
- The AWS Secrets Manager client takes an empty `NextToken` as the last page
  (moto sends one), and the Azure Key Vault client reads a secret whose
  `attributes` has no `enabled` (the emulator omits it).
- The reads that remove secret values from what they show (the
  OpenTelemetry and audit exports and event streams among them) could answer
  503 `SECRET_UNAVAILABLE` for up to about a tenth of `[secrets] refresh`
  (30 s with the default) in about half of the refresh windows. The
  inventory of secret values stays valid for `refresh` after its rebuild
  began, but the node began the next rebuild 90% to 110% of `refresh` after
  the last one ended, and an inventory that expired woke nothing. The next
  rebuild now begins 70% to 90% of `refresh` after the last one began, so
  the new inventory is in place before the old one expires; the node reads
  its secrets' sources about a quarter more often.
- New metrics `kronik_secret_fetch_total`, `kronik_secret_fetch_seconds`,
  `kronik_secret_stale` and `kronik_secret_versions_total`, and
  `kronik_key_source_up` is exported at last: it was set on every scrape and
  dropped, as it was missing from the catalog (#38). A test now fails when the
  daemon records a metric that the catalog lacks.
- `kronik secret backends` (and its API) shows each backend's last success,
  last error and the linked names without a cached value; the new `kronik
  doctor` check `secrets` warns about them.
- DST scenarios `--scenario allocator` (one allocator of secret versions under
  concurrent first uses, refreshes and crashes) and `--scenario
  secret-outage`; `scripts/dst.sh` runs them.
- `scripts/e2e-secrets.sh` runs the external-secret criteria against OpenBao
  (token and AppRole), moto's Secrets Manager and the GCP and Azure
  emulators, pinned by digest; `scripts/e2e-cloud-secrets.sh` runs them
  against the real clouds with an operator's credentials (not run by the
  project); `scripts/e2e-pkcs11.sh` runs the `kronik-keyhelper` flow against
  SoftHSM2.
- The gateway sent an actor's status of 600 to 999 to the client as it was,
  although an actor answers with 200 to 599; like an informational status, it
  is now answered with `TURN_FAILED` (#68).
- The API read a `+` in a path segment as a space, so an actor whose key
  holds a `+` (which the gateway creates and serves) answered `BAD_REQUEST`
  at `/v1/actors/<kind>/<key>` unless the client wrote `%2B`. A `+` in a path
  is now literal; in a query it still means a space (#47).
- An answer that is not the API's (a proxy's error page, an empty body) made
  the human CLI print an uncoded `error: the daemon answered HTTP 502: ...`
  while `--json` printed `UNAVAILABLE` with a hint. Both now print the same
  `UNAVAILABLE` error, with its hint, `docs:` line and the start of the page
  (#41).
- `kronik mcp` ignored `--json` when it could not start (no daemon on the
  socket, a refused `--url`, a bad configuration), so an agent host decoding
  stdout got nothing, and the unreachable-daemon error had no `docs:` line. A
  failure to start is now the error JSON on stdout with `--json` and a full
  error (code, hint, `docs:`) otherwise, and a token the daemon refuses is
  `UNAUTHENTICATED` instead of `UNAVAILABLE` (#42).
- `GET /v1/actors/{kind}/{key}/timers` returned pending timers' message names
  unscrubbed, and answered 200 while the secret inventory was unavailable,
  where every other view of a turn's data scrubs them or answers 503. It now
  scrubs names like a turn's `timers[].name` and fails closed with
  `SECRET_UNAVAILABLE` (#44).
- `demo/verify-change.sh` with `GUESTS=test` stopped with a Python traceback
  after a successful promote: the test guests answer the decimal n, and the
  script parsed JSON. It reads both now, and the M3 acceptance script runs
  that mode too (#50).
- A revealed secret written into a SQL `BLOB` cell was not scrubbed: the
  scrub covered text cells only, so its bytes reached the turn's SQL
  changeset in the log and the actor database, also in privacy mode `on`.
  Blob cells are scrubbed byte for byte now and stay blobs, and a secret
  that is not UTF-8 is scrubbed from them too (#37).
- A `call` that timed out while its callee was busy still committed at the
  callee, but when the caller's turn then failed the change was neither an
  orphan (`history --orphans`, `GET /v1/orphans`) nor compensated, and a
  compensation attached to the call was dropped (#30). Such a call now
  becomes an orphan, and its compensation is delivered exactly once, as soon
  as the callee's turn commits, whether that is before or after the caller's
  failure; a callee turn that fails leaves neither. A successful call whose
  reply was withheld (`HOST_REDACTION_FAILURE`) is now an orphan too, as its
  compensation already was delivered. The behavior diff counts orphans the
  same way, so `errors.new_orphans` no longer reports production's orphan of
  a timed-out call as new in the fork.
- A fork could not replay a turn whose call reply production had withheld
  as over the caller's response limit (`HOST_REDACTION_FAILURE`): the fork's
  call record named no callee source, so the replay stopped with
  `UNAVAILABLE`. The fork's record now names the fork's callee turn, and the
  fork withholds the reply, fails the turn and delivers the call's
  compensation as production did.
- After the host clock stepped back (an NTP correction, a VM resume, an
  operator fixing a clock that ran ahead), every timer waited until the wall
  clock had climbed back by the step, minutes late for webhook retries,
  leases and holds, although ADR 0006 said timers are due against logical
  time (#40). A timer now fires when logical time reaches its due time or
  when its delay has passed on the monotonic clock, whichever comes first;
  nothing recorded changes. DST's webhook workload steps its clock back 5 to
  10 minutes and no longer corrects it before draining, and every run checks
  that a timer turn runs at or after its due time.
- An actor type can leave more headers and query parameters out of its HTTP
  fingerprints than the six default headers (#39, ADR 0134): `kronik limits
  set <kind> --fingerprint-exclude-header x-api-key
  --fingerprint-exclude-query ts,nonce` (and `fingerprint_exclude_headers` /
  `fingerprint_exclude_query` in `POST /v1/limits`), so a rotating key or a
  timestamp no longer makes a re-run diverge or a fork's match approximate.
  The rules are part of the log: a request with rules is recorded as
  fingerprint version 3 with the names it left out, and every recording is
  matched under its own rules. Requests without rules stay version 2, byte
  for byte; a binary from before this release refuses a log with version 3
  requests.
- A fork replayed a call that had timed out in production by running its
  callee at once (a fork's calls never time out), so the caller got an answer
  where production's got `timeout`, and an identity replay of that turn
  showed a change. The fork now serves the recorded timeout to the caller, as
  it serves other recorded effects, and runs the callee's turn where
  production ran it; a compensation the call carried goes out once that turn
  committed, as in production.
- A timed-out call whose callee had not run it when the daemon stopped was
  lost with the process, and its held compensation and bookkeeping row stayed
  in `state.db` for good. The next start now closes such a call as a failed
  turn of its callee with `UNAVAILABLE` ("the call never ran"): its
  compensation is dropped and nothing is orphaned, in a rebuild of the log
  too.

## v0.4.1 — 2026-11-07

Fixes to v0.4.0; no log-format, WIT or breaking API/CLI change.

- A node whose retention had deleted the log past the last SQL change of an idle
  SQL actor could not restart (`STORAGE_CORRUPT: state is at lsn N, but the log
  starts at M (compacted)`). Releases v0.1.0 to v0.4.0 were affected once an
  actor database instance had been idle for longer than `[retention] history`
  (7 days by default) and the node restarted. Retention now raises such
  databases before deleting, the next start repairs an already affected
  directory by installing its newest snapshot, a restore from a bucket in that
  state starts, and `kronik upgrade check` reports the directory that the start
  would refuse.
- Restart time no longer grows with the log: a start certifies the secret
  inventory from the coverage watermark instead of reading the log twice (24 s
  at the 326th cycle of the nightly crash test before). A first start also no
  longer logs `watermark write: rename: No such file or directory`.
- Erasing a data subject no longer leaves `history`, `actors inspect` and the
  other reads that scrub their output at 503 `SECRET_UNAVAILABLE`, neither after
  the erase nor after a restart.
- An operator's `--reason` is no longer replaced for good by `[withheld: secrets
  could not be loaded]` when a mutation begins while a configuration change
  rebuilds the secret inventory.
- The audit exporter no longer stays unavailable for up to five minutes after a
  secret-inventory rebuild: the certificate a new one displaces is retired, and
  a batch refused at admission is prepared again. No line is lost or exported
  twice.
- An audit export, trace or event-webhook follower that a configuration commit
  overtakes captures a new reader at once instead of pausing for a minute;
  nothing is lost or exported twice.
- A held resend whose dead letter a rollback removed answers
  `DEAD_LETTER_NOT_FOUND` instead of running.
- `kronik upgrade check` no longer writes the data directory's path into the
  `engine.upgrade` audit record, and neither does an upgrade.
- An `upgrade check` that diverges because a subject was erased after the last
  snapshot now names the reason and the way out: the check forks from the root
  inputs, not from snapshots, so make one new turn and rerun it with a window
  shorter than the time since the erasure. A snapshot alone does not move the
  fork point. (v0.5.0 will report the erased turn as unverifiable rather than as
  a change.)
- `kronik restore` validates manifest paths and names before installing
  anything, installs a `code/` object only when it is named `<64 hex>.wasm`
  and its bytes hash to that name, and refuses unsafe entries. (v0.4.1 still
  installed every such object, named by a deployment or not; from v0.5.0 a
  restore installs only the components the snapshot's and the segments'
  deployments name, as the design says.)
- The daemon's log carries ANSI colours only when standard error is a terminal:
  a redirected, piped or journaled log no longer holds escape sequences between
  a field's name, its `=`, and its value (`NO_COLOR` is still honoured on one).
- The `watch` test no longer races its first evaluation against the directory
  change (test-only).

The engine is now `kronik-0.4.1+wasmtime-50.0.1` (was
`kronik-0.4.0+wasmtime-50.0.1`). Data written by any earlier release needs a
passing `kronik upgrade check` with this binary before the first start; without
one the start stops with `ENGINE_VERSION_MISMATCH`, and a passing start appends
one `engine.upgrade` record. Going back needs the reverse check. The first start
reads the retained log once (1.8 to 3.0 s for a 136,000-record log in testing).

## v0.4.0 — 2026-11-03

- Standard `fetch` through `wasi:http` (M22): `http.fetch` effects are recorded,
  replayed and matched in forks, and the TypeScript SDK handlers may use
  ordinary `fetch` with `{{secret:NAME}}` header templates.
- OpenTelemetry and audit export (M28): traces built from committed turn
  records, Prometheus and OTLP metrics, and a verifiable audit export to files,
  webhooks and object storage, with durable export cursors.
- KMS-backed master key (M23 B1): OpenBao transit, AWS KMS, GCP Cloud KMS and
  Azure Key Vault can wrap the master seed, with `kronik keys
  wrap|rewrap|status` and the optional `kronik-keyhelper` distribution.
- Engine updated to Wasmtime 50.0.1 (RUSTSEC-2026-0420 through 0424), with the
  upgrade procedure unchanged.
- Crash-path hardening: atomic secret-catalogue publication, paced rate
  windows, resumable cold scans, restart-safe custody and a bounded applier.
- Static musl binaries for x86_64 and aarch64, with Sigstore attestations,
  checksums, CycloneDX SBOMs and two-build reproducibility evidence.
- The build brief and project status are now maintained in the project wiki.

## v0.3.0 — 2026-10-29

- Python and Go SDKs (M15).
- The CLI against a remote API (M10, except the criterion that requires a run
  in a public repository), watch after promote (M11) and preview forks.
- Effect simulators (M12) and rollback via replay (M13).
- Foreign actors copied into forks (M14).
- `kronik upgrade check` opens sealed values with the data directory's keystore
  and master key.
- New engine: `kronik-0.3.0+wasmtime-50.0.0`; upgrade check required before the
  first start on existing data.

## v0.1.0 — 2026-10-29

- Durable turns on one node (M0 to M3): a single binary runtime, Wasm actors
  with key-value state and per-actor SQLite, deterministic replay, fork, replay
  and behavior diff.
- The TypeScript and Rust SDKs (M4).
- Policy, the JSON API and the MCP server (M5).
- Operations on a VPS (M6): TLS and ACME, systemd, snapshots, shipping,
  restore and `upgrade check`.
- Foreign actors in gVisor (M7).
- Privacy mode (M8): sealing, erasure, resealing and forks without personal
  data.
- System proposals (M9).
- Static musl binaries; these binaries report `0.1.0-dev`.
