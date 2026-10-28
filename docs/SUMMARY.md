# Summary

[Introduction](introduction.md)

# Concepts

- [Concepts](concepts/glossary.md)
- [Architecture](concepts/architecture.md)

# Reference

- [CLI](reference/cli.md)
- [JSON output](reference/json.md)
- [WIT](reference/wit.md)
- [Error codes](errors.md)

# Guides

- [Quickstart](guides/quickstart.md)
- [Installing Kronik](guides/install.md)
- [Operating Kronik](guides/operations.md)
- [Privacy mode](guides/privacy.md)
- [Writing actors](guides/actors.md)
- [Agent guide](guides/agent.md)
- [GitHub Action](guides/github-action.md)
- [Security model](guides/security.md)

# Design

- [M1 core design](design/m1-core.md)
- [M2 effects design](design/m2-effects.md)
- [M3 fork design](design/m3-fork.md)
- [M6 storage design](design/m6-storage.md)
- [M7 foreign actors design](design/m7-foreign.md)
- [M8 privacy design](design/m8-privacy.md)
- [M9 system proposals design](design/m9-system-proposals.md)
- [M10 remote control design](design/m10-remote.md)
- [M11 watch design](design/m11-watch.md)
- [M11 preview forks design](design/m11-preview.md)
- [M11 preview wildcard certificate design](design/m11-dns01.md)
- [Performance](perf.md)

# Decisions

- [ADR 0001: Wasmtime for deterministic turns](adr/0001-wasmtime-determinism.md)
- [ADR 0002: TypeScript components](adr/0002-typescript-components.md)
- [ADR 0003: Foreign actors in gVisor](adr/0003-gvisor-bridge.md)
- [ADR 0004: Deterministic simulation testing](adr/0004-deterministic-simulation.md)
- [ADR 0005: Per-actor SQL state](adr/0005-sql-state.md)
- [ADR 0006: Logical time](adr/0006-logical-time.md)
- [ADR 0007: Policy rules in CEL](adr/0007-policy-cel.md)
- [ADR 0008: The MCP server](adr/0008-mcp-server.md)
- [ADR 0009: Gateway TLS and ACME](adr/0009-acme-instant-acme.md)
- [ADR 0010: OpenAPI from the API's types](adr/0010-openapi-schemars.md)
- [ADR 0011: Closed-segment footer index](adr/0011-segment-footer-index.md)
- [ADR 0012: System proposals and the per-kind diff](adr/0012-system-proposal-diff.md)
- [ADR 0013: One switch for a set of kinds](adr/0013-set-switch-gate.md)
- [ADR 0021: The CLI against a remote API](adr/0021-remote-cli.md)
- [ADR 0022: Proposals run as daemon jobs](adr/0022-proposal-jobs.md)
- [ADR 0023: The public diff summary](adr/0023-diff-summary.md)
- [ADR 0024: Watch after promote: guards from the log](adr/0024-watch-guards.md)
- [ADR 0025: Preview forks](adr/0025-preview-forks.md)
- [ADR 0026: DNS-01 for the preview wildcard: an exec hook](adr/0026-dns01-exec-hook.md)
- [ADR 0027: systemd unit hardening and runsc](adr/0027-systemd-unit-hardening.md)
- [ADR 0031: A diff with pii-masked turns needs an approval](adr/0031-pii-masked-approval-floor.md)
