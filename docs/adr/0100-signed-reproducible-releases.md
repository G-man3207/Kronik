# 0100. Keyless signed and reproducible releases

- **Status:** Accepted; public Kronik signing and independent-build evidence remain release gates.
- **Date:** 2026-10-30

## Context

M31 requires signed, reproducible releases and refusal of unsigned downloads.
A checksum served beside an archive authenticates neither its publisher nor its
source. Deterministic gzip/tar headers do not establish reproducible compilation.
The standalone installer must work on Ubuntu 24.04 without an account, modern
system `gh`, a checkout, or an unverified product used to verify itself.

## Decision

The existing manual Release workflow must run from the exact `v<package-version>`
tag in repository **1432583300**, `G-man3207/Kronik`. It builds the same committed
source in two independent source/target directories, sharing only pinned build
tools and source inputs. `SOURCE_DATE_EPOCH` comes from that commit; the pinned
cargo-cyclonedx already uses it for timestamps and omits its random serial number.
Compiled ELF bytes, embedded notices/SBOMs and unsigned distribution bytes must
match before `actions/attest` signs the archives and release metadata.
`reproducibility.json` records the actual comparison, not a packaging-only claim.
Only newly generated SBOM graph references remap their opaque Cargo workspace IDs
to the same `/kronik` virtual source root as compiler paths; package URLs, licenses
and document text are not rewritten. Historical supplied SBOM bytes stay untouched.
This is a bijection over component identifiers and every dependency reference;
duplicate/colliding identifiers and dangling graph references fail closed.
Nightly builds remain unsigned candidates, not installable signed releases.
Before upload or draft creation, that same job must install its actual attested
x86_64 archive through both the standalone installer and Action. A public
upstream fixture is not a substitute for this real Kronik gate.

The installer and Action use the standard GitHub CLI/Sigstore verifier, with:

- the exact certificate identity
  `https://github.com/G-man3207/Kronik/.github/workflows/release.yml@refs/tags/v<VERSION>`;
- the same exact source ref, and issuer
  `https://token.actions.githubusercontent.com`;
- GitHub-hosted runners and the default SLSA provenance predicate;
- numeric `sourceRepositoryIdentifier == "1432583300"` from the **verified
  certificate**, not an untrusted bundle or workflow-controlled predicate.

`gh --cert-identity` and `--signer-workflow` are mutually exclusive. The exact
certificate identity already binds the workflow path; it is combined with
`--source-ref`, issuer and numeric-ID enforcement. Each archive carries the
standard `.tar.gz.sigstore.json` bundle. `gh` checks the artifact digest; the
consumer does not repeat an unauthenticated sidecar check as signature proof.
Archive members and ELF architecture are checked before any downloaded product
runs. Existing destination-private staging and same-filesystem rename remain.

Both Linux architectures bootstrap official **gh 2.103.3** from fixed official
URLs and SHA-256 values embedded in the trusted source. Actual official amd64 and
arm64 ELFs are static (no ELF interpreter or dynamic segment); only amd64 has
been executed by this slice. The upstream MIT `LICENSE` stays beside the private
verifier, whose upstream build also embeds dependency notices. The verifier is
not installed globally or bundled into Kronik. Its private HOME/config/cache and
empty credential environment prevent reading the operator's GitHub credentials.
Maintained Sigstore TUF roots are bootstrapped by standard `gh`, not our own PKI.
Fresh installation needs HTTPS access to official verifier and TUF endpoints;
`file://` artifact mirrors do not imply air-gapped bootstrap support.

Source policy cannot be overridden at runtime: no alternate verifier digest,
repository/workflow/issuer/root, or allow-unsigned switch. Version is an explicit
release selector, not a trust-root override. Obtain the installer/Action itself
from an authenticated, reviewed source; executing a bootstrap script cannot
retroactively authenticate that script.

The shared pinned gVisor setup lives in `scripts/install-runsc.sh`. Trusted
checkout CI calls it directly. Release rendering embeds that one source in the
standalone installer; it never needs a runtime checkout/helper and never uses a
fabricated unsigned release to install gVisor.

## Alternatives

An project-held Ed25519 key and OpenSSL would make the consumer smaller, but adds
unavailable long-lived key custody and rotation. It was not selected. Requiring
a modern system `gh` is not a fresh-Ubuntu contract: Noble supplies an older CLI.
Downloading a verifier and trusting its adjacent checksum, handwritten Sigstore
PKI, executing Kronik to verify its own download, and unsigned fallbacks are not
acceptable alternatives.

## Consequences

Current consumers intentionally refuse historical unsigned v0.3.0 downloads.
Its original and supplementary assets, old installer/Action and Wasmtime 50.0.0
bytes remain unchanged: they are not re-signed, replaced or relabeled as a
security patch. An actual signed Kronik tag/run must be proven before claiming
public signed availability. No workflow event is implied by this source change.

The genuine `cli/cli` 2.103.3 fixture proves standard no-account verification and
identity/digest rejection. Its actual signer ref is `refs/heads/trunk`; private
fixture SOURCE constants describe that fact without weakening production tag
policy or inventing a certificate. Tests distinguish that fixture from a future
real Kronik release, and distinguish two-build evidence from cross-host/toolchain
reproducibility, fuzzing, an external audit or a blanket security claim.
