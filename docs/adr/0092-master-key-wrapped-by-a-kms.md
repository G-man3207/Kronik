# 0092. The master key is a seed wrapped by a KMS or HSM

- **Status:** Accepted for B1 KMS lifecycle; PKCS#11 remains maintainer-gated.
- **Date:** 2026-10-28; B1 re-reviewed 2026-10-30

## Context

M23: "Huvudnyckeln kan ligga i en KMS eller i en HSM via PKCS#11 och skrivs
då aldrig till disk." Criterion: "Kronik startar med huvudnyckeln i en KMS
utan att nyckeln skrivs till disk."

Before B1 the master key was a 32-byte seed in a hex file or in
`KRONIK_MASTER_KEY`. Six local keys are derived from it with keyed BLAKE3:
- secret encryption;
- secret version hashes;
- the keystore KEK;
- keystore backups;
- pseudonyms;
- keyed hashes.

A KMS or HSM key is non-exportable and offers only operations such as
encrypt/decrypt and wrap/unwrap. It cannot stand in for those derivations.

The original design found hard-coded key readers and new-key creation over
encrypted stores. Those were already fixed on main before B1; this work
reuses their single loader and `MASTER_KEY_MISSING`/`MASTER_KEY_MISMATCH`
guards. Upgrade check and offline audit verification are additional current
readers and must use the provider-aware source too.

## Decision

- **Envelope.** The seed stays Kronik's master key. With `[keys] source`
  set to `openbao`, `aws`, `gcp` or `azure` (B1):
  - **Init:** the seed is generated in memory, encrypted by the provider's
    key, and only the ciphertext is written, to `<data>/keys/master.wrapped`
    (JSON: source, key reference and version, ciphertext, AAD).
  - **Start:** the file is decrypted by the provider; the seed is retained
    in a shared, stable protected mapping and zeroized on final drop.
    Linux requires mlock and MADV_DONTDUMP and disables process dumps.
    macOS uses mlock and disabled standard core dumps, not Linux's mapping
    exclusion or a debugger exclusion guarantee. Offline loaders protect
    keys too; transient cipher state is not separately locked.
  - **Shipping:** `master.wrapped` is ciphertext. It is shipped with each
    keystore backup and after a rewrap, and `kronik restore` installs it.
    A restore onto an empty machine therefore unwraps through the KMS. The
    provider key version that wrapped a kept backup must stay enabled.

  The providers:

  | Source | Operation |
  |---|---|
  | `openbao` | transit encrypt/decrypt with a derived key, so the AAD goes in as `context` |
  | `aws` | KMS Encrypt/Decrypt with an encryption context |
  | `gcp` | Cloud KMS encrypt/decrypt with AAD |
  | `azure` | Key Vault wrapkey/unwrapkey, RSA-OAEP-256 |
  | `pkcs11` (planned, maintainer-gated) | proposed AES-256-GCM through `kronik-keyhelper`, ADR 0093 |

- **The provider is needed at start only.** Start retries for `[keys]
  start_timeout` (default 60 s), then stops with `KEY_SOURCE_UNAVAILABLE`.
- **One loader.** `KeySource::load` selects the configured provider or the
  retained file/env primitive `MasterKey::open`.
  The guards come from that fix too: `MASTER_KEY_MISSING` and
  `MASTER_KEY_MISMATCH`, through a `key_check` row in each store.
- **Migration and rewrap.**
  - `kronik keys wrap --source S` (offline, dry run) moves an existing key
    into a KMS. The guide states that such a seed was on disk once.
  - `kronik keys rewrap` (online, admin, reason, dry run) re-encrypts the
    seed under the provider key's current version.
  - Both are audited: `rewrap` writes an M28 `AuditEvent`, and the start
    after `keys wrap` writes a system one.
- **Credentials.** Credentials for the provider come from files (relative
  paths resolve in `$CREDENTIALS_DIRECTORY`), env names, or instance
  identity, and never from `kronik.toml`.
  - Unsupported sources are refused by name: AWS web identity, SSO and
    profiles; Azure certificates; GCP workload identity federation.
  - A credential that sits on the same disk or in the same backup as
    `master.wrapped` defeats the envelope. The security guide says so, and
    doctor warns when a credential file is under the data directory.

## Alternatives

- **Derive the seed inside the HSM or KMS with an HMAC**, e.g.
  `HMAC(kms_key, "kronik master seed v1")`. That needs no wrapped file.
  But Azure Key Vault (standard) has no HMAC, and it would make the seed
  depend on a KMS key that may rotate. The envelope works with every
  provider through one operation pair.
- **Move every derivation into the KMS** (per-value KMS calls). This would
  mean a KMS round trip for every secret read, every sealed value and every
  keyed hash: a KMS outage would stop turns (against I10), and a cloud KMS
  bill would grow per request.
- **`KRONIK_MASTER_KEY` from a secret manager.** That exists today, but the
  daemon still receives the raw key, often through files or unit
  environments that end up on disk. It stays as a source; it is not the
  KMS answer.
- **Rotate the seed itself.** That means re-keying every store: re-encrypt
  secrets, re-wrap subject DEKs, and new pseudonyms (which would change
  pseudonyms in forks). It is not in the brief and is left for later.

## Consequences

- A copy of the data directory with `master.wrapped` is useless without
  the KMS key. Losing the KMS key loses every secret and sealed value. The
  operations guide puts this next to today's "losing the key" text.
- The seed is in daemon memory, as today. The process is non-dumpable, and
  the seed is zeroed on drop.
- File and environment sources retain their existing behavior. Shipping uses
  the loaded key and never unwraps again per backup. Rewrap publishes one
  atomic `wrapped/current.wrapped` object independently of keystore changes;
  per-backup `.wrapped` is published before the `.bin` commit marker.
- Restore validates source/key/purpose/version, unwraps and validates staged
  stores before installation. It syncs the installed envelope's parent
  before committing restored state. A missing current object may use the
  newest complete backup pair; other current-object failures do not fall back.
- Offline migration shares the data-directory descriptor lock held by serve
  before recovery and by restore. No sibling lock requires broader systemd
  permissions. The seed is verified before any envelope is persisted.
- `start_timeout` bounds the whole key-loading operation, including fresh
  encrypt and verification decrypt. No retry begins after that deadline.
- Proof commands and observed outcomes are recorded in STATUS.md. SoftHSM2,
  PKCS#11 and external secret version/history criteria are not part of B1
  and are not claimed as verified here.
- The durable envelope schema is `kronik.wrapped-key/v1`. Its repository
  compatibility fixture is
  `crates/kronik-privacy/tests/fixtures/wrapped-key-v1.json`; the privacy
  boundary test preserves its metadata and rejects wrong source/key and
  unknown schema versions. Opaque fixture ciphertext is not a cloud-crypto
  round-trip claim.

## Observed B1 evidence (2026-10-30)

- The static x86-64 musl binary passed the OpenBao, AWS/moto, GCP KMS
  emulator and Azure Key Vault emulator lifecycle matrix. Each run checked
  real crypto, restore state/log identity, outage behavior, atomic pair
  publication, migration, exact-secret scrubbing and owned-resource cleanup.
- Each daemon's actual master mapping was locked and dump-excluded; seven
  retained key pages were observed, not a blanket no-swap inference.
- A current musl binary passed an actual non-root systemd unit with
  `DynamicUser`, `ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`,
  an 8 MiB memlock limit and disabled core dumps. Parent-directory writes
  were denied; file-to-KMS migration, restart, typed contention, effective
  environment/socket commands and cleanup passed without wider permissions.
- `scoped_provider_tls_does_not_change_guest_trust_or_identity` exercises
  actual TLS/mTLS, including non-inheritance by the guest client. The
  provider matrix independently verifies a real RS256 service-account JWT.
- Exact commands, binary hashes, pinned emulator images and reports are in
  STATUS.md. These are emulator and Linux-host results, not real-cloud IAM,
  macOS runtime, SoftHSM or PKCS#11 verification.

