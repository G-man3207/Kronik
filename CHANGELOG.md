# Changelog

All notable changes to Kronik are recorded here. The project is pre-alpha; the
formats, the API, the WIT interface and the CLI may change between releases
until the v1.0 compatibility promise takes effect.

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
- `kronik restore` validates manifest paths and names before installing
  anything, installs only the components the manifest names, and refuses unsafe
  entries.
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
