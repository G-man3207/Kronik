# Changelog

All notable changes to Kronik are recorded here. The project is pre-alpha; the
formats, the API, the WIT interface and the CLI may change between releases
until the v1.0 compatibility promise takes effect.

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
