# 0094. Secret and key providers without SDKs

- **Status:** Accepted for B1 KMS clients; external secret clients remain planned.
- **Date:** 2026-10-28; B1 re-reviewed 2026-10-30

## Context

M23 needs these providers:
- OpenBao (Vault KV v2 and transit);
- AWS Secrets Manager and KMS;
- GCP Secret Manager and Cloud KMS;
- Azure Key Vault (secrets and keys).

Each needs two to four REST calls plus its authentication. The constraints:
- ring only, never aws-lc-rs;
- no tokio runtime features in library crates (hygiene);
- I/O through `Env`, so DST can drive it;
- every dependency justified;
- cargo-deny.

The providers' SDKs are not in the offline cache. They bring large trees,
their own HTTP stacks, and (AWS) aws-lc-rs by default.

## Decision

The B1 KMS clients are small REST clients in `kronik-privacy` over
`Env::net()`, with JSON through `serde_json`. The same provider names for
external secret retrieval remain B4 work, not implemented by this slice.

- **OpenBao and Vault:**
  - `X-Vault-Token`, with AppRole and TLS-certificate login;
  - transit `encrypt` and `decrypt`;
  - external KV v2 reads and token renewal remain B4 work.
- **AWS:** SigV4 over the existing ring implementation, with time from
  `env.clock` and published fixed-path vectors (headers and session tokens).
  Credentials come from `AWS_*` env or IMDSv2. B1 implements KMS `Encrypt`
  and `Decrypt`; Secrets Manager reads remain B4 work.
- **GCP:**
  - a service-account JWT signed RS256 through `Env::entropy`, exchanged at
    `oauth2.googleapis.com/token`, or a token from the metadata server;
    ring's internal RSA blinding stays in the production Env, not providers;
  - Secret Manager reads remain B4 work;
  - KMS `encrypt` and `decrypt`.
- **Azure:**
  - Entra ID client credentials (form POST), or the IMDS managed-identity
    token;
  - Key Vault secret reads remain B4 work;
  - `keys/K/{version}/wrapkey` and `unwrapkey`.

No new third-party dependency enters the graph: B1 reuses locked dependencies.
PKCS#11 dependencies and the separate helper artifact remain maintainer-gated.

**No-paid-cloud acceptance targets** (observed outcomes belong in STATUS.md):

| Provider | Run against |
|---|---|
| OpenBao (MPL-2.0) | the OpenBao server image |
| AWS | moto (Apache-2.0) |
| GCP Cloud KMS | Blackwell Systems third-party REST KMS emulator (Apache-2.0) |
| Azure Key Vault | rokeller emulator (Apache-2.0) |

The acceptance services run in isolated containers. Real-cloud/IAM checks
remain opt-in owner work; emulator evidence does not claim those checks.

## Alternatives

- **aws-sdk-secretsmanager and aws-sdk-kms with aws-config:** dozens of
  crates, an aws-lc-rs default, their own clock and runtime use, not cached.
- **The google-cloud-* and azure_* crates:** the same problems, plus a
  gRPC stack (tonic) for the Google crates.
- **`vaultrs`:** reqwest-based, with a large surface for two endpoints.
- **`object_store`'s `AwsAuthorizer`** (public, reusable for non-S3
  services): it reads `Utc::now()` itself, which keeps AWS out of DST, and
  it needs object_store's request type. Our SigV4 is short, and the AWS
  test suite pins it.
- **`jsonwebtoken`:** ring already provides RS256.
- **LocalStack** for AWS: since March 2026 its image needs an account
  token under proprietary terms. Moto covers Secrets Manager and KMS.
- **HashiCorp Vault** as the test server: BUSL-1.1. OpenBao implements the
  same API under MPL-2.0.

## Consequences

- We own provider protocol code:
  - SigV4;
  - the JWT assertion;
  - authentication for key loading and rewrap (not background secret refresh);
  - the provider error shapes.

  B1 requires published signing vectors and real emulator acceptance;
  permanent tests focus on uncertain integrity/security boundaries, not
  mock-echo round trips. STATUS.md records actual commands and outcomes.
- Emulators prove protocol and cryptographic operation, not real IAM. Paid
  cloud checks remain the maintainers' choice. The original no-GCP-KMS-emulator
  assumption is historical; the B1 verification work evaluates the available
  third-party REST emulator without claiming cloud validation.
- Network, clock and signing stay behind Env. Custom CA/client identity
  produce a separate provider-scoped client, never the guest effect client.
  Loopback-only authentication overrides support isolated acceptance without
  sending credentials to a configurable remote token service.
