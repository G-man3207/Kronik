# 0154. Exceptions for unmaintained chrono and humantime

- **Status:** Accepted
- **Date:** 2026-11-17

## Context

`deny.toml` sets `unmaintained = "all"`. RustSec marks every version of
`chrono` ([RUSTSEC-2026-0543](https://rustsec.org/advisories/RUSTSEC-2026-0543))
and `humantime`
([RUSTSEC-2026-0542](https://rustsec.org/advisories/RUSTSEC-2026-0542))
unmaintained. There is no patched release. The advisories are maintenance
status, not a demonstrated memory-safety defect.

The locked graph still resolves both. `object_store` 0.14 (S3 shipping)
depends on both. `oci-client` 0.18 (registry pulls) and `rmcp` 3.10 (the MCP
client, pinned exactly) depend on `chrono`. `rmcp`'s `schemars` feature
enables `schemars`'s `chrono04` feature, so `schemars` resolves `chrono` too.
The latest releases of those crates still depend on them. Replacing
`object_store`, `oci-client` or `rmcp` would replace S3 shipping, image pull
or the MCP protocol implementation. That is not a way to turn this gate green.

## Decision

`deny.toml` records a reasoned exception for `RUSTSEC-2026-0542` and
`RUSTSEC-2026-0543`. `unmaintained` stays `"all"`. An exception for only one
of the two still fails `cargo deny`. The deny step also runs the same graph
with an empty ignore list and requires both advisories to fail it.

Drop an exception when the resolved graph no longer contains that crate. Do
not add an exception for a vulnerability or unsoundness advisory.

cargo-deny 0.20.2, the version CI installs, accepts only `id` and `reason` on
an ignore entry, so the exception is not limited to the current parent crates.
A new direct dependency on either crate still needs a review of this ADR
before it is treated as covered.

## Alternatives

- **Drop the crates from the graph.** No current release of `object_store`,
  `oci-client` or `rmcp` does. Replacing them is a separate design.
- **Set `unmaintained` to `workspace` or `none`.** That would also hide a
  future unmaintained crate. The gate stays fail-closed for every other
  advisory.
- **Upgrade cargo-deny so an ignore entry can name allowed parents.** CI pins
  0.20.2. A newer deny can add that later; it is not required to name both
  IDs.

## Consequences

- `scripts/ci.sh deny` passes against the current RustSec database.
- Removing either exception, or reintroducing either crate without it, fails
  that step.
- Vulnerability and unsoundness advisories are still not ignored.
