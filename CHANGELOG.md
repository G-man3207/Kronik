# Changelog

All notable changes to Kronik are recorded here. The project is pre-alpha; the
formats, the API, the WIT interface and the CLI may change between releases
until the v1.0 compatibility promise takes effect.

## Unreleased

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
