# M23: Key and secret backends (design)

Status: B1 KMS lifecycle is implemented for OpenBao, AWS, GCP and Azure. B2
to B6 are in the code, and each has run as the table below says; whether M23
is accepted is the maintainers' decision, and the project status page on the
wiki has it. Sections 1–13 contain the design proposal, including its
historical loader inventory and the acceptance plan: where a sentence there
says "planned", the table below decides. The B1 design gate at the end records
the design that was implemented first. Implementation evidence is tracked with
the code; a plan is not a pass.

| Slice | In the code | Has run | Not done |
| --- | --- | --- | --- |
| B1 master key in a KMS | OpenBao, AWS, GCP and Azure wrapping; `file` and `env` seeds; `keys wrap`, `rewrap`, `status` | `scripts/e2e-keys.sh` on pinned service images (the status page has the runs) | |
| B2 trait, links, versions | `SecretBackend`; `SecretVersion` (kind 45) and `SecretLink` (kind 46); `secret link`, `unlink`, `refresh`, `history`, `backends`; effects resolve through links; re-runs fetch by `source_version`; `secrets` in the effects of `history` | `crates/kronik/tests/secret_backends.rs` (§9, criteria 2 and 3, steps 1 to 7, against a stand-in for OpenBao's KV v2); the DST scenario `allocator` ("one allocator", step 8): `scripts/dst.sh 0..10000 6 --scenario allocator` passes (release), and seeds 0..300 give the same trace twice | |
| B3 cache and outages | the cache and the refresher; `fetch_timeout`; `max_stale`; the failure cache of 5 s; an error result for an effect that cannot get its secret; scrubbing that fails closed; foreign actors through the cache; forks that use only a held value and never fetch; the four metrics and `kronik doctor`'s `secrets` check (§6) | the same file (outage, refusal, restart and crash re-run cases, a fork and `foreign add` with a linked name); the DST scenario `secret-outage`: `scripts/dst.sh 0..2000 6 --scenario secret-outage` passes (release), seeds 0..100 give the same trace twice, and 4 of seeds 0..16 fail without the stale fallback of this release; `scripts/e2e-secrets.sh` with each real service paused, and OpenBao also stopped | a foreign actor's start with a linked name has run only in unit tests and through `foreign add` (a start needs a sandbox) |
| B4 providers | clients for `env`, `openbao` (KV v2, token, AppRole, certificate), `aws` (Secrets Manager), `gcp` and `azure` | unit tests for each; `scripts/e2e-secrets.sh` against the real services below, all passing on one run | OpenBao's certificate login and token renewal, and the cloud metadata/IMDS logins, against a real service; any real cloud |
| B5 proof and docs | `secret_backends.rs`; `scripts/e2e-secrets.sh`; `scripts/e2e-cloud-secrets.sh`; the `[secrets]` table and the troubleshooting sections of the operations guide; the CLI, JSON, OpenAPI and error references | `scripts/e2e-secrets.sh`, see below | `scripts/e2e-cloud-secrets.sh` has **not been run**: the project has no AWS, GCP or Azure account for it |
| B6 PKCS#11 | the `kronik-keyhelper` crate and its default-off release asset (ADR 0093); `[keys] source = "pkcs11"`; `keys enroll` | `scripts/e2e-pkcs11.sh` against SoftHSM2 2.6.1 with a **development build** of `kronik` and `kronik-keyhelper --features pkcs11`, see below | the release artifacts (musl daemon, glibc helper asset); a physical HSM; the rest of ADR 0093's acceptance list (staged restore, migration with `keys wrap`, helper crash/timeout/overflow drills) |

**`scripts/e2e-secrets.sh`, 2026-11-13** (a development build of `kronik`,
0.5.0-dev, SHA-256 `55fe5dd7…cb38514`; images by digest, ports on loopback):

| Service | Image | Outcome |
| --- | --- | --- |
| OpenBao, KV v2 behind TLS, token auth | `openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f` (the B1 pin) | pass |
| OpenBao, AppRole auth | the same | pass |
| AWS Secrets Manager | `motoserver/moto@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a` (moto 5.2.5, the B1 pin) | pass, with a loopback shim: moto answers ListSecretVersionIds with the secret's name in `ARN`, and the shim puts back the ARN that DescribeSecret gives (10 answers corrected in a run of this service alone) |
| GCP Secret Manager | `ghcr.io/blackwell-systems/gcp-secret-manager-emulator-dual@sha256:2c9d3bb0453fdff102b29af00b4abd9b2c6fa466031a9d8e6d93a270ba22a6e2` (1.9.0) | pass; the token from a loopback fixture that verifies the service-account RS256 JWT |
| Azure Key Vault | `ghcr.io/rokeller/azure-keyvault-emulator@sha256:126d8433d11f4983dba5337352311bcf9278a566b415b0cbfd5eea2b7d8e9d88` (the B1 pin) | pass; client credentials through a loopback authority (the emulator checks the token's syntax only) |

Each passed criterion 2 (the `SecretVersion` in the log, read from the
segment files, has the hash a `file` node computes for the same value under
the same master key and the service's own version id, and the effect's
`SecretRef` names it; no value in a file, the daemon's output, or an answer of
the API, the CLI or MCP) and criterion 3 steps 1 to 6 (§9: rotation, `secret
history`, `@v1`/`@v2` in `history`, a fork from before the rotation replayed
with 2 exact turns, no divergence and no synthetic or live effect while the
service was paused; the crash re-run of a recorded reveal got the recorded
version's value; a destroyed version made the re-run fail with
`SECRET_VERSION_GONE`). With the service paused, turns without a secret that
arrived through the gateway took at most 50 ms, also right after a restart,
and a turn with an uncached secret failed in 1.8–1.9 s (`fetch_timeout` 2 s)
with `SECRET_UNAVAILABLE` recorded; with OpenBao stopped or sealed, in under
70 ms, as the connection is refused. Observed, not asserted: the first
`kronik send` after a restart waited about 2 s while the service was paused,
as an operator's mutation waits for the inventory before its reason is
scrubbed (`[secrets] fetch_timeout`); and after a destroyed version and a
restart, the reads that scrub answered 503 `SECRET_UNAVAILABLE` on all five
(the known defect of the operations guide). The run found and this release
fixes three defects: a re-run's older version became the current value after
a restart, moto's empty `NextToken` was refused, and a Key Vault answer
without `attributes.enabled` was refused.

**`scripts/e2e-pkcs11.sh`, 2026-11-13** (development builds: `kronik`
`55fe5dd7…cb38514`, `kronik-keyhelper` `e7b8a3eb…3ef99781`; Debian
`softhsm2` 2.6.1-3 and `opensc` 0.26.1-2, module SHA-256 `f2c19104…2f753fd`):
pass. `keys enroll` refused an extractable, modifiable key; a start with
`source = "pkcs11"` wrote only `master.wrapped`; a secret survived a restart
(unwrap through the helper) and a `keys rewrap`; the seed, learned by running
the helper on the envelope, opened a copy of the data directory as an `env`
key; neither the seed (raw, hex, base64), the PIN nor the secret's value was
in the data directory, the configuration directory (the PIN file excepted),
the daemon's output or SoftHSM's token directory; a wrong PIN stopped the
start with `KEY_HELPER_FAILED` and wrote nothing.

## The brief

English translation of the build brief (the authoritative Swedish original is
unchanged):

> **M23 Key and secret backends.** The master key and the secrets can live outside the server. Touches `kronik-privacy`.
>
> - The `SecretBackend` trait with backends for file (default), environment variables, Vault-compatible APIs such as OpenBao, and the cloud providers' secret services.
> - The master key can live in a KMS or in an HSM via PKCS#11 and is then never written to disk.
>
> * [ ] Kronik starts with the master key in a KMS without the key being written to disk.
> * [ ] Secrets from an external backend get a version hash in the log, just as with the built-in store.
> * [ ] Rotation of a secret shows up as a new version in `history`, and replay of old turns is not affected.

Invariants that bind it:
- **I8:** a secret is a handle. Its value never reaches the log, diffs,
  `history` or MCP.
- **I10:** the core needs no external service. A secret backend or KMS is
  opt-in, and a backend that is down must not stop turns that don't use it.
- **I2:** secrets reach guest code only through recorded host calls.
- **I5:** configuration that changes behaviour goes through the log.

## 1. Historical baseline (2026-10-28, before v0.1.0)

**The master key.**
- `MasterKey([u8; 32])` (`kronik-privacy/src/lib.rs:43`) is a seed. Six
  keys are derived from it with `blake3::derive_key`:
  - the secret store's XChaCha20-Poly1305 key;
  - the secret version-hash key;
  - the keystore KEK, which wraps per-subject DEKs;
  - the keystore backup key;
  - the pseudonym key;
  - the shared keyed-hash key.
- Its source is a hex file (`[keys] master_key_file`, default
  `<data>/keys/master.key`) or `KRONIK_MASTER_KEY` (the material itself).
- There are four load sites:
  - init (`init.rs:133`);
  - node start (`kronik-sched/src/lib.rs:204`);
  - keystore ship and keystore restore (`kronik-ship/src/lib.rs:343,609`).
    Both of these hard-coded `<data>/keys/master.key`, so they ignored the
    configured file and `KRONIK_MASTER_KEY`.
- A start with no key file and no env material **created a new key**, even
  when encrypted stores already existed.
- Both are fixed: one loader (`MasterKey::open`),
  `MASTER_KEY_MISSING`, and a `key_check` row per store
  (`MASTER_KEY_MISMATCH`).
- There is no master-key versioning and no rotation.

**The secret store.**
- `<data>/keys/secrets.db` is a concrete `SecretStore`:
  - values are encrypted per version under the derived key, with AAD
    `name|version`;
  - versions are `max+1`, starting at 1;
  - `version_hash` = 16 bytes of keyed BLAKE3 over `name ‖ 0 ‖ version_le ‖
    0 ‖ value`.
- `secret set/list/delete` change only SQLite. **No log record is written**:
  `list` shows the latest version, and there is no per-name version history.

**Effects.**
- HTTP secret headers, `crypto.hmac-sha256`, `crypto.sign-ed25519` and
  `secret.reveal` record a `SecretRef {name, template, version,
  version_hash}` (`effects.proto:11`) and never the value.
- `history` does not show the version (`EffectSummary` has no secret
  fields).
- Matched recorded effects never need the value:
  - recorded HTTP and crypto results are returned as recorded;
  - fork reveal returns a placeholder.
- The exceptions:
  - **production crash recovery of a reveal** reloads the recorded version;
  - an HTTP effect that must be re-sent loads its recorded version;
  - **unmatched fork crypto** of a built-in name uses its *current*
    production value only under a `compute` grant; a `recorded` grant, the
    default for a new grant since ADR 0112, denies it (`replay: no
    recording`) and uses no value. A grant written before the mode existed
    is `compute`, so the gap remains for such grants. Under `compute`, a
    name linked to an external backend at the fork point uses the value
    this process holds for that link, never a fetch (see §6).

**Scrubbing.** `Node::secret_values()` decrypts every non-deleted version of
every secret for each scrubbed API response and for foreign logs.

**Foreign actors** read the current values at each start and get them as
environment variables.

**What is missing:** no trait, no remote backend, no KMS or HSM code. The
dependency tree has no provider SDK and no PKCS#11 crate.

## 2. Overall shape

```text
                 kronik-privacy
 ┌───────────────────────────────────────────────────────────┐
 │ KeySource ── file | env | openbao | aws | gcp | azure      │
 │   │           | pkcs11                                     │
 │   └─> MasterKey (32-byte seed, memory only when wrapped)   │
 │                                                           │
 │ Secrets (resolver + cache) ── name ─> link ─> backend      │
 │   ├─ file      (the built-in store, default)              │
 │   ├─ env       (the daemon's environment)                 │
 │   ├─ openbao   (Vault-compatible KV v2)                   │
 │   ├─ aws       (Secrets Manager)                          │
 │   ├─ gcp       (Secret Manager)                           │
 │   └─ azure     (Key Vault secrets)                        │
 └───────────────────────────────────────────────────────────┘
 log: SecretVersion (kind 45), SecretLink (kind 46)
```

Two independent features share one crate:

1. **Where the master key lives** (§3). A KMS or HSM key wraps the seed. The
   plain seed exists only in memory.
2. **Where secrets live** (§4–§7). Every secret name resolves through a
   link, to the built-in store or an external backend. Every version Kronik
   uses is recorded in the log with the built-in version hash.

## 3. The master key in a KMS or HSM (ADR 0092, ADR 0093)

### 3.1 Envelope: the KMS wraps the seed

The KMS key never leaves the KMS, so it cannot *be* the master key: the six
local derivations need key bytes (keyed BLAKE3, XChaCha). So the master key
stays the 32-byte seed, and the KMS or HSM key **wraps** it:

- **New node:**
  1. `kronik serve --init` (or the first start) generates the seed in
     memory.
  2. It calls the provider's encrypt.
  3. It writes only the result, `<data>/keys/master.wrapped`.
  4. The plain seed is never written: no file, no temp file, no log line.
- **Every start:**
  1. Read `master.wrapped`.
  2. Call the provider's decrypt.
  3. Keep the seed in memory, in a `Zeroizing<[u8; 32]>` (`zeroize` is
     already in the tree).

  The process is already non-dumpable (`serve.rs:224`). Everything
  downstream is unchanged.
- **Memory, not swap**: the seed and the six derived keys
  are `mlock`ed and marked `MADV_DONTDUMP`, and the derived keys are
  zeroized on drop too. Offline commands that load the seed (`restore`,
  `keys wrap`, `keys rewrap`) also set `PR_SET_DUMPABLE 0`.

`master.wrapped` (JSON, mode 0600):

```json
{"schema":"kronik.wrapped-key/v1","source":"openbao",
 "key":"transit/keys/kronik","key_version":"1",
 "ciphertext":"vault:v1:…","aad":"kronik master v1","created_wall_ms":…}
```

- `aad` binds the blob to its purpose: AWS `EncryptionContext`, GCP
  `additionalAuthenticatedData`, PKCS#11 AES-GCM AAD, and OpenBao transit
  with a **derived** key (`derived=true`) and `context` = base64 of the AAD;
  the guide says to create a dedicated derived transit key.
  Azure RSA-OAEP has no AAD; the blob names its purpose in its own
  `schema` field only.
- **`master.wrapped` is shipped**: it is ciphertext, so it goes
  to the bucket with each keystore backup (`keystore/<wall>.wrapped`) and
  again after `rewrap`. `kronik restore` installs the newest one at or
  before the restore point when the node's `[keys] source` is a KMS, so a
  restore onto an empty VPS unwraps through the KMS and reads everything.
  The provider key *version* that wrapped a shipped blob must stay enabled
  for as long as the backup is kept (GCP and Azure can disable old
  versions); the guide says so.
- A copy of the data directory plus `master.wrapped` is useless without the
  KMS. Losing the KMS key loses the data. That is the operator's backup
  decision, documented next to the existing "losing the key" text.

### 3.2 Providers

| `[keys] source` | Encrypt / decrypt | Auth |
|---|---|---|
| `file` (default) | none: the hex file, as today | — |
| `env` | none: `KRONIK_MASTER_KEY`, as today | — |
| `openbao` | transit `POST /v1/{mount}/encrypt/{key}` and `/decrypt/{key}` | token file, AppRole (`role_id_file`, `secret_id_file`) or TLS client certificate |
| `aws` | KMS `Encrypt`/`Decrypt` (`X-Amz-Target: TrentService.*`) with `EncryptionContext` | SigV4 with credentials from `AWS_*` env or IMDSv2 instance role |
| `gcp` | Cloud KMS `cryptoKeys:encrypt` / `:decrypt` | service-account JSON key (RS256 JWT, signed with ring) or the metadata server |
| `azure` | Key Vault keys `wrapkey`/`unwrapkey`, RSA-OAEP-256 | client credentials (secret file) or managed identity (IMDS) |
| `pkcs11` (B6, accepted design; integration/release acceptance separately gated) | optional `kronik-keyhelper` process (§3.4): `CKM_AES_GCM` on a non-extractable AES-256 key | private PIN file; not a B1 source |

Credentials are never in `kronik.toml`, only paths to files (or env names).
Systemd's `LoadCredential=` fits: `$CREDENTIALS_DIRECTORY` is read where a
path is relative (`pin_file = "kronik-hsm-pin"`). The bootstrap credential
has to live somewhere. The clean answers are instance identity (AWS role,
GCP metadata, Azure managed identity), a TLS client certificate, or an HSM
PIN in a credential. The operations guide says so plainly.

**What the envelope protects**: a copy of the data directory or
of the bucket without the bootstrap credential reveals no seed. A copy that
includes it (an AppRole `secret_id`, a TLS client key, a PIN file or AWS
keys on the same disk or in the same backup) can unwrap through a reachable
KMS. The security guide's at-rest map says this, recommends instance
identity, and `kronik doctor` warns when a credential file lies under the
data directory.

**Credential sources Kronik does not support** are refused at config check
with their name: AWS web identity, SSO and profiles; Azure
certificate credentials; GCP workload identity federation. Tokens have a
redacting `Debug`, and the shared `Env::net` client never logs headers.

### 3.3 Start, outages, migration and rewrap

- **The KMS is needed at start only.** After start the seed is in memory,
  so a KMS outage affects no turn (I10). At start, `kronik serve` retries
  the provider with backoff (Env clock) for `[keys] start_timeout` (default
  60 s). It then stops with `KEY_SOURCE_UNAVAILABLE`, and systemd restarts
  it.
- **Never a silent new key, never another key:** a missing key over existing stores is
  `MASTER_KEY_MISSING`; a wrong one is `MASTER_KEY_MISMATCH`, from the
  `key_check` row each store holds, written only after the key has
  decrypted one of the store's values (so a mis-copied key is never
  blessed). A missing `master.wrapped` over existing stores is
  `MASTER_KEY_MISSING` too.
- **One loader.** `MasterKey::open` becomes `KeySource::load(config)`
  with the KMS sources added; start, shipping, restore and init all use it.
- **A KMS outage during a restart is a full outage**: it is
  inherent to keeping the key elsewhere, and only at start. Doctor and the
  `kronik_key_source_up` gauge make it visible; the guide recommends an
  alert. Keeping the seed in the kernel keyring across daemon restarts is
  not done: it would outlive the process, which the envelope tries to avoid.
- **Migration** `kronik keys wrap --source openbao [--dry-run]`, run
  offline with the daemon stopped:
  1. load the current file or env key;
  2. wrap it;
  3. write `master.wrapped`;
  4. remove the old key file. A configured file is not touched unless
     `--remove-file` is given.

  The guide is explicit: that seed *was* on disk once. A seed that was never
  on disk needs a new node (or a future master-key rotation, which re-keys
  every store; not in M23).
- **Rewrap** `kronik keys rewrap [--dry-run]`, online: decrypt with the
  recorded key version, encrypt with the current one, and replace
  `master.wrapped` atomically (`write_synced`). This is for GCP and Azure,
  whose new key versions don't decrypt old ciphertext on their own, and for
  OpenBao `min_decryption_version`. AWS rotates transparently.
- **Doctor** shows the source, the key reference and version, and whether
  the stores' key checks match.
- **Key-source changes are audited**: `rewrap` writes an
  `AuditEvent` `keys.rewrap` with its reason; `keys wrap` runs offline and
  leaves a marker that the next start turns into a system `AuditEvent`
  `keys.source` (M28's restore-marker pattern). Both need M28's kind 40, so
  M23 Phase B follows M28.

### 3.4 Optional PKCS#11 helper (B6, accepted ADR 0093)

PKCS#11 is a C ABI: the vendor's module (`libsofthsm2.so`, a YubiHSM or
Luna library) must be `dlopen`ed. **The release `kronik` is a static musl
binary, which cannot `dlopen` at all** (probed: "Dynamic loading
not supported"), and the vendor modules are glibc-linked. So the daemon
never loads one:

- **`kronik-keyhelper`**, a separate x86_64 GNU binary with exact
  `cryptoki = 0.12.1`. Its default-off `pkcs11` feature never enters the
  daemon's normal dependency closure. `KRONIK_RELEASE_KEYHELPER=yes` adds
  `kronik-keyhelper-x86_64-unknown-linux-gnu.tar.gz`, its own SBOM, original
  normal-root/Rust notices, LICENSE/NOTICE and checksum. The manual release
  workflow reproduces it before the same keyless attestation as the daemon.
  `KRONIK_INSTALL_KEYHELPER=yes` selects only a correctly attested archive;
  see the [installation guide](../guides/install.md#optional-gnu-pkcs11-helper).
- **Run only for explicit PKCS#11 operations:** startup, `keys wrap`,
  `keys rewrap` and `keys enroll`. The helper disables dumps before sensitive
  input, uses private stdin/stdout and the trusted PIN-file descriptor at fd3,
  then finalizes and exits. The module, its dependencies and the token/key
  configuration are unbundled operator prerequisites.
- **One bounded existing protocol:** `kronik.pkcs11/v1`, defined by
  `crates/kronik-keyhelper/src/protocol.rs`, with a 4-KiB request/response
  boundary and kill-and-reap on failure. Actual token manufacturer/model/serial,
  enrolled key ID/version and a non-secret possession probe replace the old
  label/slot assumptions; use the real `kronik keys enroll --config ...` path.
  No seed/PIN in argv, environment or an invented protocol file.
- **Why a process even if a glibc build existed:** vendor C runs for one
  call in a process that exits right after; memory corruption, threads left
  after `C_Finalize`, signal or atfork handlers and a second libcrypto never
  reach the daemon or its `runsc` spawns.
- This is ADR 0093's accepted narrow process exception, not a promise about a
  vendor's C implementation or full B6 acceptance.
- Proof must name the actual extracted artifact, source, profile and platform.
  A GNU helper/software-token exercise with a matching GNU debug CLI is
  local evidence, not the final musl-daemon/helper release lifecycle, supported
  glibc floor, Ubuntu/ARM execution or physical-HSM acceptance.
- M21's unit has `PrivateDevices=yes`, which hides USB HSMs: the guide
  ships a `DeviceAllow=` drop-in for them.

## 4. `SecretBackend` and links (B2–B4, ADR 0090)

In the code since v0.4.0 (`crates/kronik-privacy/src/secret_backend.rs`,
`crates/kronik-sched/src/secrets.rs`). The sketches in 4.1 and 4.3 are the
first proposal; the notes under them say what the types carry as built.

### 4.1 The trait

```rust
/// Where the values of linked secrets come from. Implementations do I/O
/// through `Env` only, so DST and tests can drive them.
pub trait SecretBackend: Send + Sync + 'static {
    /// The value the backend calls current, with its own version id.
    fn current(&self, path: &BackendPath) -> BoxFuture<'_, Result<Fetched, BackendError>>;
    /// One earlier version by the backend's own id, for crash recovery and
    /// re-sent effects.
    fn version(&self, path: &BackendPath, id: &str) -> BoxFuture<'_, Result<Fetched, BackendError>>;
}

pub struct Fetched { pub value: Zeroizing<Vec<u8>>, pub source_version: String }
pub enum BackendError { Unavailable(String), NotFound, VersionGone, Denied(String), Invalid(String) }
```

As built, the trait has a third method, `versions` (the retained catalogue of a
path, one page at a time), every method takes the caller's original lease, and
`Fetched` also returns the canonical reference of what it read. `BackendError`
carries no message and has one more variant, `Unauthorized` (the original
authority ended).

The built-in store is the `file` backend. It keeps its own write path
(`secret set`, `secret delete`), which no other backend has: Kronik never
writes to an external secret manager. Rotation happens there, with that
system's tools and audit.

### 4.2 Backends

| `type` | `--ref` | `source_version` | Earlier versions |
|---|---|---|---|
| `file` | (the name) | Kronik's version number | until `secret delete` |
| `env` | variable name | `k:` + 16 hex of the master-keyed hash (`"kronik env secret v1"`, name, value): the env has no ids | current only; a changed value is seen at the next start |
| `openbao` (Vault KV v2 API) | `<mount>/<path>#<field>` | KV `version` | as the mount keeps them (default 10) |
| `aws` (Secrets Manager) | secret id or ARN, optional `#json-field` | `VersionId` | until AWS removes them (100 recent, plus 24 h) |
| `gcp` (Secret Manager) | `projects/P/secrets/S` | numeric version | until destroyed |
| `azure` (Key Vault) | `https://V.vault.azure.net/secrets/S` | version id | until purged |

Backends are configured per node, because they hold credentials. Several of
the same type are allowed:

```toml
[secrets.backends.bao]
type = "openbao"
address = "https://bao.internal:8200"
auth = "approle"                # token | approle | cert
role_id_file = "bao-role-id"    # relative: $CREDENTIALS_DIRECTORY
secret_id_file = "bao-secret-id"
ca_file = "/etc/kronik/bao-ca.pem"

[secrets.backends.aws]
type = "aws"
region = "eu-north-1"
# endpoint = "http://127.0.0.1:5000"   # moto, tests only
```

### 4.3 Links are log records

Which backend serves a name changes what turns see, so it goes through the
log (I5), like grants. Record kind **46, `SecretLink`**:

```proto
message SecretLink {
  string name = 1;      // the Kronik secret name actors are granted
  string backend = 2;   // a [secrets.backends.<id>]; empty = unlink (back to file)
  string ref = 3;       // the backend path, e.g. "secret/payments#stripe"
  Audit audit = 4;
}
```

As built, `SecretLink` also carries `binding`, `generation`, `epoch` and
`canonical_ref` (`proto/kronik/log/v1/config.proto`); ADR 0090 says why.

- `kronik secret link <name> --backend bao --ref secret/payments#stripe
  --reason R [--dry-run]` checks that the backend exists on this node and
  that `ref` lies under one of the backend's `allowed_refs` prefixes, then
  fetches the current value once, so a bad ref fails now with the backend's
  error rather than at the first turn. The dry run fetches but appends
  nothing and does not fill the cache.
- **Scope `admin`, and an allowlist**: the backend sees only
  the node's identity, so its own policy cannot tell which Kronik caller
  asked. Without a limit, `link` (with `secret-reveal` and an `http.fetch`
  grant) could read and send out anything that identity can read. So
  `[secrets.backends.<id>] allowed_refs = ["secret/payments/", …]` is
  required for every external backend (an empty list refuses every link),
  a ref outside it is `SECRET_REF_NOT_ALLOWED` (403), and `link`/`unlink`
  need scope `admin`.
- `kronik secret unlink <name> --reason R [--dry-run]`.
- An **active link**, including `backend = "file"` and a same-name file link,
  has no owned built-in value. Both `secret set` and `secret delete` return
  `SECRET_EXTERNAL` (409) before allocating a version or changing any physical
  row, floor, provider or audit history. Unlink first; a subsequent built-in
  mutation affects that logical name's own file row only, never the old target
  or another alias. An unlink record may remain in configuration with an empty
  backend; that is not an active link. Grants stay `secret:<name>` and
  `secret-reveal:<name>`, so guest code does not know or care where a value lives.
  Logical revocation is not physical deletion: the target's original encrypted
  history and qualified host-only scrub custody remain independent of aliases.
- `SecretLink` is applied to a `secret_links` table in `state.db`, so it is
  rebuilt from the log.

## 5. Versions and hashes in the log (B2, ADR 0090)

### 5.1 `SecretVersion`, kind 45

Every version Kronik uses, from any backend including the built-in one, is
first recorded:

```proto
message SecretVersion {
  string name = 1;
  uint32 version = 2;          // Kronik's number: 1, 2, … per name
  bytes version_hash = 3;      // 16 bytes, exactly the built-in hash
  string backend = 4;          // "file", or the backend id
  string source_version = 5;   // the backend's id (KV version, VersionId, …)
  bool deleted = 6;            // `secret delete` of the built-in store
  Audit audit = 7;             // the caller for set/delete; "system" when observed
}
```

As built, `version` is a `uint64`, and the record also carries `ref`,
`binding`, `link_generation`, `canonical_ref`, a `phase` (reserved, active,
failed, or the format fence) and `hash_revision`.

- **The hash** is the built-in one: `version_hash = BLAKE3_keyed(k,
  name ‖ 0 ‖ version_le ‖ 0 ‖ value)[..16]`, with k derived from the master
  key. So an external secret's hash is computed, stored and shown exactly
  as the built-in store's: in `SecretRef.version_hash` on every effect, in
  `secret list`, and in `SecretVersion`. That is the second criterion,
  literally.
- **Kronik's version number has one allocator per name**. A
  new `source_version` can be seen by the refresher (§6), by `secret
  refresh <name>`, or by an effect whose fetch found a version not yet
  recorded, in parallel. All of them go through
  `Secrets::record(name, fetched)`, which, under a per-name lock in the
  resolver:
  1. returns the recorded number if this `source_version` is already in
     `secret_versions`;
  2. otherwise takes `max(version) + 1`, appends the `SecretVersion` and
     **waits for its commit**;
  3. only then hands the number to the caller.

  So one `source_version` gets exactly one number, numbers are dense, and a
  `SecretRef` always names a committed version. An effect records the
  version *before* the value is used (an HTTP header leaving the node, a
  MAC, a reveal), as `TurnBegin` is committed before the turn runs, so the
  log says which version actually left.
- **On an M16 cluster** the metadata leader is the allocator: `record`
  forwards to it, and the record lives in the metadata log. M16's design
  names a metadata entry `SecretVersion` too; they are to be the same
  record, with M23's fields, reconciled when M16's metadata log is built
  (M16 §9/§12).
- **The built-in store writes it too, as the intent** (with
  M28): `secret set` allocates the number, appends `SecretVersion` with the
  caller's audit, then writes `secrets.db`; a failed write appends M28's
  `secret.set.failed` `AuditEvent`. `secret delete` appends one with
  `deleted = true` and its reason, then deletes. This replaces M28's
  `secret.set`/`secret.delete` intent events for these two routes, so each
  change has one record, and M28's classifier exports kinds 45 and 46 (both
  carry `Audit`; its proto-walking test enforces it).
- **Versions from before M23** have no record: the first M23
  start appends one system `SecretVersion` per existing built-in version,
  in version order, so `secret history` is complete.
- **Applied** into `secret_versions(name, version, version_hash, backend,
  source_version, deleted, lsn, wall_ms)` in `state.db`. Crash recovery
  finds the backend's id for a recorded version there.
- **Never the value.** The record holds no value and nothing derived from
  it except keyed hashes: the version hash, and an `env` backend's
  `source_version`, which is keyed too, so a short value cannot be guessed
  from the log.

### 5.2 Rotation in `history`

The third criterion: "Rotation of a secret shows up as a new version in
`history`, and replay of old turns is not affected."

- **Actor history** (`kronik history <kind/key>`, `GET …/history`, MCP):
  each effect that used a secret shows it as `secret:<name>@v<N>` with the
  first 8 hex of its hash. These come from the `SecretRef`s that are
  already recorded; `EffectSummary` gains a `secrets: [{name, version,
  version_hash}]` field, additive in JSON. A turn before a rotation shows
  `@v3`, a turn after it `@v4`. As built:
  - `version` is the legacy `uint32` or the wide version (at most 2^53 - 1,
    exact in a JSON number); `version_hash` is the first 8 hex characters
    of the recorded 16 bytes. Never a value.
  - Every effect kind that records a `SecretRef` has it: the secret headers
    of `http.fetch` and `foreign.http`, `crypto.*` and `secret.reveal`. A
    secret version is listed once per effect, in the order of first use. A
    reference that never resolved, as in a denied effect, is not a use.
  - The field is omitted when it is empty and, like `request`, when the
    request is sealed for a data subject or erased with it: it is read from
    a plain request only, and a caller who may open a sealed request (the
    turn JSON and the trace unseal it for `pii:read`) sees it.
  - It is on the effects of `GET …/history`, of the turn JSON (`GET
    /v1/turns/{id}`, `turn.schema.json`), of a trace and of a message into a
    fork. The CLI adds a `SECRETS` column to the effects table of `history`
    and of `send --fork` when an effect used a secret.
- **`kronik secret history <name>`** (`GET /v1/secrets/{name}/history`,
  scope `read`) lists the `SecretVersion`s: version, hash, backend,
  `source_version`, when, who and reason. A deletion is a row.
- **`kronik secret list`** shows the backend and ref next to the latest
  version.

### 5.3 Replay of old turns is unaffected

- **Recorded effects match without the value.**
  - Production crash recovery and fork replay return the recorded HTTP and
    crypto results.
  - Fork reveal is a placeholder.
  - The crypto fingerprint excludes the version, so a rotation never turns
    a match into a mismatch.

  This is true today; M23 adds a test that pins it (§9).
- **Where the old value is needed**, it is fetched by the recorded version,
  never the current one: crash recovery of a reveal, and an effect that must
  be re-sent.
  1. `secret_versions` gives the `source_version`.
  2. `SecretBackend::version` fetches that version.
  3. The hash is checked against the recorded `version_hash`; a mismatch is
     `VersionGone`.
- **A recorded outcome is never changed** (I1). A reveal (or a
  re-send) whose `EffectResult` was recorded `Ok` must give the guest that
  value again:
  - **`Unavailable`:** the rerun retries with backoff (Env clock) and holds
    only that actor's turn; other actors run (I10). The gauge
    `kronik_secret_recovery_stalled` and a warning that names the actor and
    the turn show it; `kronik doctor` does not yet.
  - **`VersionGone`** (destroyed version, changed `env` value): the turn
    fails with `SECRET_VERSION_GONE` before the guest sees anything, and
    goes to dead letters with that code. The guest never takes a path the
    log does not record.
  - An effect *without* a recorded result is a new effect. In a live turn it
    gets an error result as in §6. In a re-run it waits like the recorded
    ones while the backend does not answer (the worker retries with backoff),
    so that a re-run sees what the first run would have seen as soon as the
    backend answers. A refusal does not pass while a turn waits, and a wait
    for ever holds the actor: a re-run gets the error result of §6 for it.
- **Identity replay** (`kronik fork replay`, the identity check) needs no
  secret value for recorded effects, so it gives the same outcomes before
  and after a rotation.

## 6. Caching, outages and timeouts (B3, ADR 0091)

Built: the cache and the refresher, `fetch_timeout`, `max_stale`, the failure
cache, scrubbing that fails closed, the error result of an effect that cannot
get its secret, the resolver for foreign actors and forks, the four metrics,
the doctor section and the DST scenario `secret-outage`. `secret_backends.rs`
exercises the outage, refusal and restart cases against the stand-in,
`scripts/e2e-secrets.sh` against the real services (§9), and unit tests the
stale-use bounds.

The rule (I10): a backend that is down affects only effects that need its
secrets, and only once Kronik has no usable value.

- **Lazy, then warm.**
  - At start, nothing blocks on a backend. Not even linked names are
    fetched synchronously.
  - A background refresher (`env.spawn`) fetches every linked name that a
    current grant uses, then refetches each every `[secrets] refresh`
    (default 5 min, with jitter from `env.random`).
  - A refetch that finds a new `source_version` records it (§5.1). Later
    effects use it; earlier turns keep theirs.
- **The cache** is in memory only: `name → {version, source_version, value,
  fetched_at}`, values in `Zeroizing`. It is never written to disk, which
  would put external secrets at rest in a second place.
- **An effect that needs a secret:**
  - **fresh cache:** uses it, with no I/O;
  - **stale cache** (refresh failed): uses it until `[secrets] max_stale`
    (default 24 h). The gauge `kronik_secret_stale{name}` is 1 and the log
    warns (`secret used stale`) while effects use a value older than
    `refresh`; a fresh value sets it back to 0. A value is used stale also
    when the fetch of a cold effect gives up at `fetch_timeout` (the
    resolver's own deadline): the DST scenario `secret-outage` found a turn
    that failed with `SECRET_UNAVAILABLE` there although a usable value was
    held;
  - **no cache:** fetches with `[secrets] fetch_timeout` (default 2 s, Env
    timer).
    - On failure, the effect gets an error result, `SECRET_UNAVAILABLE`.
      Failure is no answer in time, an answer of `Denied` or `Invalid`, and a
      backend binding that the node does not trust; a name that does not exist
      is `SECRET_NOT_FOUND`. This is like a network error, and the guest sees
      an error it can handle, the same one in each case: a guest should not
      learn the state of the node's credentials. The log has the reason
      (`secret fetch failed`, with the secret, the backend and a category).
      The result is recorded before the guest sees it, like every effect
      result: status `network` for `http.fetch`, `denied` for `crypto.*` and
      `secret.reveal`, with the error in `error`. Nothing is sent. Replay and
      forks return the recorded error, and a crash re-run of the turn does not
      ask the backend again.
    - The turn is not failed by Kronik, and nothing else waits. The guest
      decides: a handler that fails with the error ends the turn as failed
      (`TURN_FAILED`; a message or timer becomes a dead letter), one that
      handles it commits. The caller is not answered with a 503, and no
      `TurnBegin` is left open for the next start to run for want of a
      secret: a `TurnBegin` without a record that a secret caused exists only
      after a crash. (Other aborts after a `TurnBegin`, such as a call whose
      callee's outcome cannot be handed to the caller, are not about secrets
      and are not covered here.)
    - Only a failure is cached: for 5 s, so a burst of turns does not
      queue on a dead backend.
- **Turns that use no linked secret never touch the cache or a backend.**
  The DST scenario `secret-outage` asserts this with a backend that hangs:
  such turns commit at their normal rate. `secret_backends.rs` shows it in a
  daemon with a hanging stand-in, and `scripts/e2e-secrets.sh` with real
  services stopped or paused.
- **Retries:** the refresher backs off from 1 s up to `refresh`. A refused
  fetch (bad credentials) is logged as `secret fetch failed`, once for each 5 s
  that the failure is remembered, and every request to a backend is counted
  in `kronik_secret_fetch_total{backend,result}`.
- **Token lifetimes:** OpenBao tokens are renewed with `renew-self` at half
  their TTL. AppRole logs in again when renewal fails. Cloud access tokens
  are refreshed before `expires_in`.
- **Foreign actors:**
  - They get their values from the same cache at start, through the node's
    resolver with the configuration of that moment: a name that is not
    linked is read from the built-in store, a linked one is the cache's value
    of its link, fetched within `fetch_timeout` when none is held (and
    recorded as a `SecretVersion` when that version is new). A backend that
    is down stops only a foreign start that has no cached value: the start
    fails with `SECRET_UNAVAILABLE` and the supervisor's existing retry
    applies. `foreign add --secret` checks each name the same way. A link or
    an unlink made after an actor was declared is seen by its next start.
    (Until this release a stopgap refused a linked name with
    `SECRET_EXTERNAL`.)
  - A rotation does not restart a running foreign actor. Its next start
    (after a crash or a daemon restart), or removing and adding it again,
    picks the new version; no command restarts one actor.
- **Scrubbing survives restarts** (I8). `ok_scrubbed` keeps
  revealed values that a guest stored or logged out of `history`, `actors
  inspect` and MCP. It must cover every value that may sit in retained data:
  - at start the refresher fetches, by `source_version`, every version a
    recorded `secret.reveal` within retention references, and every version
    of a name with a `secret-reveal` grant that is still within the
    backend's retention;
  - until those are held, responses that need scrubbing **fail closed**
    with `SECRET_UNAVAILABLE` (503) rather than go out unscrubbed;
  - a decrypt or fetch error in `secret_values()` also fails closed (today
    it returns an empty list, which fails open);
  - foreign logs keep their documented limit.
- **Revocation beats staleness**: `NotFound`, `Denied`,
  `VersionGone` from a refresh, and `unlink`, drop the cached value at
  once; only `Unavailable` (timeouts, 5xx) uses `max_stale`. A rotation
  reaches new effects within `refresh` (5 min) or at once with `secret
  refresh`.
- **Forks never fetch** (I7): an unmatched effect in a fork that
  needs an external secret uses a value this process already holds for the
  fork point's link (its backend, binding, reference and generation);
  otherwise it is denied in the fork and the diff marks it unverifiable. No
  provider audit log or bill sees a fork. Today that is an unmatched
  `crypto.*` under a `compute` grant (ADR 0112): with a value held for the
  link it is computed on the host, as for a built-in name, and the value is
  the one the cache holds now for that link (a later version after a
  rotation without a relink, as the built-in store's current value is for a
  built-in name); without one it is denied with `SECRET_UNAVAILABLE` and
  graded synthetic, and the built-in store is not asked. A preview computes
  nothing. The fork point's configuration includes the links of its window,
  so a fork from before the link, or after an unlink, uses the built-in store
  as before. (Until this release a stopgap denied every such effect with
  `SECRET_EXTERNAL`.)
- **Metrics:**
  - `kronik_secret_fetch_total{backend,result}`: every request to a backend
    (current value, a version by its id, a page of the version list, a
    link's check), with `result` `ok`, `unavailable`, `denied`,
    `not_found`, `version_gone`, `invalid` or `cancelled`;
  - `kronik_secret_fetch_seconds{backend}`;
  - `kronik_secret_stale{name}`;
  - `kronik_secret_versions_total{backend}`: versions this node recorded
    (`file` for the built-in store);
  - and, outside the family, `kronik_secret_recovery_stalled` and
    `kronik_key_source_up`. Every name the daemon records is in the
    catalog of `kronik-metrics`, which `/metrics` and OTLP walk; a test reads
    the sources and fails when one is not (`crates/kronik-metrics/tests/catalog.rs`).
- **Doctor:** the `secrets` check reads `GET /v1/secrets/backends` from a
  running daemon: each backend's last success and last error, and the linked
  names with no value an effect could use. It warns (`SECRET_UNAVAILABLE`)
  when a backend's last request failed after its last answer, or a linked
  name has no cached value. `kronik secret backends` shows the same
  columns.

### 6.1 Configured immutable host MACs

A configured native signer validates the committed logical identity, selected
link and trusted backend before reading its exact immutable `source_version`.
It uses only an already operational held value or the verified provider/FILE
version; retained scrub-only inventory is not operational permission. This
read neither observes a new version nor inserts or promotes a cache value.
Only `Unavailable` can use the existing bounded operational last-good value;
other provider failures invalidate operational use outside admission.

Provider/file reads, identity checks and HMAC calculation finish before the
caller's original final admission. Its callback only moves one prepared MAC.
An exporter retains its actual inventory publication separately through that
same original admission; the data publication is not a new authority. Avoiding
cache publication here prevents re-entering the exporter's held cache fence.

### 6.2 Private native execution versus public readiness

The original native execution is activated once after unchanged erasure
recovery and secret-version initialization/refresh setup, before Foreign
reconciliation and open-turn rerun enqueue. This preserves Foreign-before-rerun
ordering. Public readiness remains the final successful `Node::start` return;
private ACTIVE is not a new listener, issuer, recovery permission or proof
that an operational current-name selection is available.

The native constructor arms its private startup guard immediately after the
real Node/writer binding, before spawning work. An error or cancelled startup
invokes the existing physical stop even if background work still retains a
Node Arc; final-Arc `Node::drop` alone cannot cover that case. The guard is
disarmed only immediately before the successful return. If the writer has
already closed, its existing liveness predicate denies use even when cleanup
cannot report a successful stop; no fallback authority is created.
After the actual Foreign await, the same retained native execution is checked
again before any rerun is enqueued or readiness can be returned. A physical
stop during reconciliation therefore fails startup rather than returning a
stopped Node. The startup observer used by the error/cancellation consumer
fixtures is private, task-scoped and compiled out of production.

The ordinary Native Foreign courier must retain that same ACTIVE execution
and actual committed configuration Arc/epoch/declarations. Its operational
current-name DATA publication is separate from historical scrub inventory.
Final start/send handoff must fence current configuration and all required
selections under one original admission; provider/file work, capacity waits
and destruction stay outside that fence. Even a declaration with no secret
bindings must check/watch the actual committed configuration and use the same
configuration-DATA callback at final start or call enqueue. An old retained
configuration Arc or an ACTIVE execution alone cannot authorize a removed run.
The common manager/ForeignHost/Node courier adoption is not final: its mandatory
actual Cluster dependency eagerly includes the native-import producer, not just
an independently readable origin codec. Root keeps its existing Host
ABI and callers; it does not add that producer, a Member facade, optional
authority, a feature gate or an unused replacement courier. Native operational
Foreign hot-rebind acceptance, as well as Member historical closure, is not
established. The private startup guard and ordinary storage DATA work are separate.

The shared `CurrentSecretSelection` primitive retains the actual active logical
row, zeroizing value, original expiry and original publisher notification. A
retired selection never revives. Its final DATA callback checks all selections
under one actual publisher with a denial prepared before original admission;
it is not an authority or historical inventory certificate. Retiring one
logical alias must not retire another binding to the same still-live physical
row or extend its expiry. The global scrub-corpus certificate stays global.

FILE row verification uses the canonical physical reference and physical
`source_version` for SQLite, AEAD and the original physical keyed hash. The
logical name/version has its own independently checked M23 keyed identity,
even when the version numbers are equal. Cipher custody descriptors keep the
unchanged raw-ciphertext BLAKE3 domain. These crypto checks do not qualify a
source, authorize an import or prove absence of deletion: physical floors still
require a real closed physical-name/cut/purpose/source proof. No logical alias
tombstone or a missing floor becomes shared physical deletion permission.

The borrowed Record45 validator uses that same logical/physical split; an
explicit FILE link, including a self-link, is still an external definition.
Its immutable physical reference must match its canonical FILE reference and
the existing physical-name grammar. LINK and retained UNLINK remain distinct.
`SecretStore::current_meta` shares `current`'s single-row selector but reads only
version/hash/creation metadata, never nonce or ciphertext. It can detect that a
retained immutable version is no longer physical CURRENT without decrypting it;
it is not a custody, complete-history, no-deletion or logical-permission proof.
The candidate-value regression inspects both actual Reserved/Active WAL audit
facts and encrypted-row operator facts, then reopens the real store and checks
the redacted history and unchanged encrypted row. It does not pin marker wording.

### 6.3 Original-owner mutable stores and private readers

Live file-backed secret and subject-key stores retain the original
`DataOwnership` directory-lock resource. Independent connections use
`reopen_owned`, sharing that same owner and DATA publisher; neither a new path
lookup nor a second directory lock creates currentness. The keystore publisher
selects only `keystore.db`. Secret-file mutations use the existing cache's
separate physical-name mutation interval, installed before the store is exposed.
Memory and actual read-only connections are distinct modes, not live owners.
Raw mutable-connection constructors/imports and the arbitrary public secret
backup destination have been removed from production callers.

A secret mutation invalidates affected operational bindings and the global
scrub certificate before SQL. Its non-clone stack guard spans SQL and reports
commit or ended-but-unknown failure; SQL commit alone does not certify CURRENT.
The owning native mutation joins its real ACTIVE record to physical metadata,
floor and keyed value identity before acknowledging inventory publication.
Concurrent mutations of the same physical name refuse before SQL rather than
minting a new selection from an independent connection's older WAL view.
Inventory capture and its final cache publication compare the same mutation
tickets, native apply cut, actual epoch and cache revision. Apply/config
incompleteness cannot be hidden by reusing an old scrub certificate.

Before any kind-45/46 application, native DATA retires the global certificate;
only actual ACTIVE/link changes retire current-name bindings. A failed apply or
unpublished configuration remains negative across reuse of the owned store.
After real startup replay, clearing that pending state requires the original
log directory, exact record/header namespace and the actual applied/configuration
cuts—not merely larger counters from another source. A healthy completed source
does not require reopening an already compacted metadata frame.

The physical SQLite identity is obtained with public FILESTAT through the live
connection: borrow its reported Unix descriptor only for `fstat`, and retain
the same Connection/owner. Never duplicate, separately open or close a database
descriptor for this check: that can release process-wide POSIX locks.
The paired FILESTAT/WALSTAT build flags do not expose either diagnostic SQL
function to guests. The observed bounded C-only ABI/locking proof is separate
from the Rust FFI, owned-store and daemon integration regressions.

A live secret reader stages the existing Connection's completed encrypted
SQLite backup and consumes that private stage into `open_readonly`; it does
not byte-copy a live database or its WAL. The stage remains owned by the reader.
An already closed private destination can instead supply its actual read-only
Connection directly. Offline key wrapping and ship restore acquire fresh
exclusive original ownership before validating their private inputs.

The public `validate_staged_stores` → `KeySource::load(false)` path still
copies main/WAL files. Its path-only offline-sealer/M19, audit-verifier,
doctor-fallback and existing-key init-rerun callers are not thereby frozen
or qualified; the latter three are separate ordinary source-contract gaps.
Source DB/WAL preservation and absent source SHM remain required. These
callers retain their old behavior pending a genuine compatible source boundary.

Compliant file writers must retain the original exclusive owner. This is not a
process-local claim to fence arbitrary external raw SQL; existing identity,
master, floor and corruption checks remain necessary. The Root source cutover
and its regressions are not implemented, and do not establish the Foreign,
historical-source or complete M23 acceptance criteria.

## 7. Providers without SDKs (ADR 0094)

Every provider is a small REST client over `Env::net()` (hyper and rustls
with ring, the effects client), with JSON through `serde_json`:

| Need | How | New crate? |
|---|---|---|
| OpenBao / Vault | B1 transit + token/AppRole/cert login; KV v2 reads and token renewal (B4, in the code since v0.4.0, tested with a fake network and the stand-in only) | no |
| AWS SigV4 | B1 KMS over ring HMAC/SHA256 and `env.clock`, with published signing vectors; Secrets Manager (B4, in the code since v0.4.0, tested with a fake network only) | no |
| GCP OAuth2 service-account JWT | RS256 with `ring::signature::RsaKeyPair::from_pkcs8` + `RSA_PKCS1_SHA256`; token from `oauth2.googleapis.com/token`; or the metadata server | no |
| Azure AD client credentials | form POST to `login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, or IMDS managed identity | no |
| PKCS#11 (B6 proposed; maintainer-gated) | proposed `cryptoki` helper dependency tree, not added by B1 | maintainer decision; no B1 dependency |
| Zeroizing seed and values | `zeroize` 1.9 (already in the lock file) | no |

Rejected:
- **The AWS, GCP and Azure SDKs.** Each is dozens of crates with its own
  HTTP stack; the AWS SDK defaults to aws-lc-rs; and they are not in the
  offline cache. We need about four calls per provider.
- **`vaultrs`:** reqwest/rustls, and a large API surface for two endpoints.
- **`object_store`'s `AwsAuthorizer`:** it is public, but it reads
  `Utc::now()` itself, which keeps the AWS backend out of DST, and it ties
  us to object_store's request type.
- **`jsonwebtoken`:** ring already signs RS256.

B1 adds no provider SDK or PKCS#11 dependency. The proposed B6 helper would
need a separate cargo-deny review of its `cryptoki` dependency tree; this
design does not claim that the proposed tree or any SoftHSM check passed.

## 8. Configuration, CLI and API

The CLI, JSON and OpenAPI references are the contract; this section keeps the
original combined proposal. Differences that matter: `kronik secret backends`
lists the id, kind, binding, whether the backend is configured and whether the
inventory is complete, and shows no last success or error; PKCS#11 follows
§3.4, not the sketch.

```toml
[keys]
source = "openbao"            # file (default) | env | openbao | aws | gcp | azure | pkcs11
wrapped_file = "keys/master.wrapped"   # relative to the data dir
start_timeout = "60s"

[keys.openbao]
address = "https://bao.internal:8200"
mount = "transit"
key = "kronik"
auth = "cert"                 # token | approle | cert
cert_file = "bao-client.pem"  # relative: $CREDENTIALS_DIRECTORY
key_file = "bao-client.key"

# Optional PKCS#11 uses [keys.pkcs11] with helper_path, module and its SHA-256,
# private pin_file, actual manufacturer/model/serial, key_id/key_version and
# the real CLI-returned possession probe. See §3.4 and accepted ADR 0093;
# the former helper/token_label/key_label prototype is not this contract.

[secrets]
refresh = "5m"
max_stale = "24h"
fetch_timeout = "2s"
```

`refresh` also limits how old the catalogue behind an inventory certificate
may be: a rebuild installs its certificate only if the catalogue it was built
from is younger than `refresh`. A rebuild that takes longer never installs
one, and the reads that scrub answer 503 `SECRET_UNAVAILABLE` until one does,
so `refresh` has to stay well above the `elapsed_ms` of the `secret
inventory certified` log line. The daemon logs a warning when a certificate
was not installed for that reason (see [`[secrets]` in Operating
Kronik](../guides/operations.md#secrets)).

`Config::check` refuses:
- inline credentials (keys named `token`, `secret_id`, `client_secret` or
  `pin`); only `*_file` and env names are accepted;
- `http://` to a non-loopback address;
- `[keys.<x>]` that does not match `source`;
- an unknown backend `type`.

| CLI | API | Scope | Notes |
|---|---|---|---|
| `kronik secret link <name> --backend ID --ref REF` | PUT `/v1/secrets/{name}/link` | admin | reason, dry run; `allowed_refs`; `SecretLink` |
| `kronik secret unlink <name>` | DELETE `/v1/secrets/{name}/link` | admin | reason, dry run |
| `kronik secret refresh <name>` | POST `/v1/secrets/{name}/refresh` | operate | reason, dry run; records a new version if there is one |
| `kronik secret history <name>` | GET `/v1/secrets/{name}/history` | read | the `SecretVersion`s |
| `kronik secret backends` | GET `/v1/secrets/backends` | read | id, kind, binding, configured, inventory complete; contacts no provider |
| `kronik keys status` | GET `/v1/keys` | read | source, key ref and version, check ok; never key bytes |
| `kronik keys wrap --source S` | (offline) | — | dry run; migration (§3.3) |
| `kronik keys rewrap` | POST `/v1/keys/rewrap` | admin | reason, dry run |

**Error codes:**
- `SECRET_UNAVAILABLE` (503);
- `SECRET_EXTERNAL` (409);
- `SECRET_VERSION_GONE` (410);
- `SECRET_BACKEND_UNKNOWN` (400): a link to a backend this node lacks;
- `SECRET_REF_NOT_ALLOWED` (403): a ref outside the backend's
  `allowed_refs`;
- `SECRET_VERSION_EXHAUSTED` (409): the next version would pass 2^53 - 1;
- `KEY_SOURCE_UNAVAILABLE` (503): at start and in doctor;
- `KEY_HELPER_FAILED` (503): `kronik-keyhelper` missing, crashed, timed out
  or answered an error.

`MASTER_KEY_MISSING` and `MASTER_KEY_MISMATCH` exist already.

Milestone "M23".

## 9. Acceptance plan and what has run

The original full-M23 plan uses the following free services. The B1 KMS
lifecycle has run against them. The external-secret criteria run against a
stand-in for OpenBao's KV v2 shape (`secret_backends.rs`) and, with
`scripts/e2e-secrets.sh`, against OpenBao itself, moto's Secrets Manager and
the GCP and Azure emulators (the table at the top has the images and the
outcomes). They have not run against the real clouds. The PKCS#11 flow runs
against SoftHSM2 with `scripts/e2e-pkcs11.sh`; no physical HSM was used.

| What | With | Licence |
|---|---|---|
| Vault-compatible backend and the KMS path | `openbao/openbao` (KV v2 + transit), dev mode | MPL-2.0 (a separately run server, not linked) |
| AWS KMS, and Secrets Manager | `motoserver/moto` | Apache-2.0 |
| GCP Secret Manager | Blackwell Systems REST emulator (`gcp-secret-manager-emulator-dual`) | Apache-2.0, third party |
| Azure Key Vault RSA wrap/unwrap, and secrets | rokeller emulator, the pinned B1 digest | Apache-2.0, third party |
| PKCS#11 | SoftHSM2 2.6.1 (Debian package), with OpenSC 0.26.1 | BSD-2-Clause |
| GCP Cloud KMS | Blackwell Systems dual REST KMS emulator, pinned B1 digest | Apache-2.0, third party |

Not used:
- **LocalStack:** since March 2026 its image needs an account token under
  proprietary terms.
- **HashiCorp Vault:** BUSL-1.1. OpenBao proves the same API.

B1's actual pinned service images, proper TLS leaf fixtures and observed
outcomes are recorded in the project status page; this table is not a proof of
unrun work.

**B1 criterion 1: "Kronik starts with the master key in a KMS without the key
being written to disk"** (`scripts/e2e-keys.sh`; observed runs are in the project status page):
1. Start OpenBao. Enable transit and create key `kronik`.
2. `kronik serve --init`-style start with `[keys] source = "openbao"`.
3. Set a secret, send a turn, stop, and start again: the secret still
   decrypts and the turn history reads.
4. The test learns the seed from outside Kronik: it decrypts
   `master.wrapped`'s ciphertext with OpenBao's own API. It then searches
   every file under the data directory, the config directory, the test's
   temp root, `$CREDENTIALS_DIRECTORY` and the daemon's journald output
   for the seed as raw bytes, hex and base64. None may match.
5. With OpenBao stopped, `kronik serve` stops with `KEY_SOURCE_UNAVAILABLE`
   after `start_timeout` and writes no key. With the wrapped file deleted
   but stores present, it stops with `MASTER_KEY_MISSING`.
6. **Restore onto an empty directory**: ship, then `kronik
   restore` into a new directory whose only key source is the KMS
   configuration. The restored node installs the shipped `master.wrapped`,
   unwraps through OpenBao, and its secrets and sealed values decrypt.

The same flow runs for `aws` (moto KMS) and `azure` (emulator wrapkey), on
the **release artifacts**. For `pkcs11`, `scripts/e2e-pkcs11.sh` runs it
against SoftHSM2: `softhsm2-util --init-token`, then an AES-256 key made
through PKCS#11 itself (`C_GenerateKey`; `pkcs11-tool --keygen` cannot set
`CKA_MODIFIABLE`, which the helper requires to be false), `kronik keys
enroll`, a fresh start, a secret, a restart, `keys rewrap` and a wrong PIN;
it learns the seed by running the helper on the envelope and proves it by
opening a copy of the data directory with it. Its needle search also covers
SoftHSM's token directory, which holds its own encrypted key store. It ran on
a **development build** of `kronik` and of `kronik-keyhelper --features
pkcs11` (the table at the top); a run of the release artifacts, and of a
physical HSM, is not claimed.

**B2–B4 criterion 2: "Secrets from an external backend get a version
hash in the log, just as with the built-in store"**
(`crates/kronik/tests/secret_backends.rs` runs steps 1 to 4 below, and the
steps of criterion 3, against a real `kronik serve` and a local fake that
speaks the KV v2 shape of the OpenBao client; `scripts/e2e-secrets.sh` runs
the same steps against each real service, reading the `SecretVersion` and
the effect's `SecretRef` from the log's segment files itself):
1. Link `stripe` to `secret/payments#key`. A turn uses it in an HMAC.
2. The log has a `SecretVersion {stripe, 1, hash, backend "bao",
   source_version "1"}`. The effect's `SecretRef` has version 1 and the
   same hash.
3. The hash is checked against the built-in computation: the test also
   `secret set`s the same value under the same name on a second node with
   the same master key (file source, from `KRONIK_MASTER_KEY`), and the two
   hashes are equal.
4. Needle: the value appears in no file, no `history`, no MCP answer and no
   `GET` response.

**B2–B5 criterion 3: "Rotation of a secret shows up as a new version
in `history`, and replay of old turns is not affected":**
1. Write a new KV version in OpenBao, then `kronik secret refresh stripe`.
2. `SecretVersion` 2 appears, and `secret history stripe` shows v1 and v2.
3. A new turn's history shows `secret:stripe@v2`; the old turn still shows
   `@v1`.
4. A fork at an LSN before the rotation replays the old turns identically
   (the identity check: same outcomes, same effects matched).
5. Crash recovery of a `secret.reveal` recorded at v1, injected with the
   existing crash hook after the rotation, gets v1's value (by KV version
   1), not v2's.
6. After destroying KV version 1, the same recovery fails the turn with
   `SECRET_VERSION_GONE`, never v2's value and never a different effect
   outcome. With OpenBao stopped instead, the rerun waits and
   the guest never sees `SECRET_UNAVAILABLE` for a recorded reveal.
7. **Scrubbing after a restart**: reveal v1 and store it in
   state, rotate, restart; `actors inspect` and `history` never show v1,
   and while v1 is not yet fetched again they answer `SECRET_UNAVAILABLE`.
8. **One allocator**: a DST scenario with two concurrent first
   uses and the refresher on a rotated backend gives exactly one record per
   `source_version`, with dense numbers.

Steps 1 to 7 of criterion 3 run in `secret_backends.rs`, and steps 1 to 6
in `scripts/e2e-secrets.sh` against each service: there the fork of step 4
runs while the service is paused, so it cannot have asked it, and the
destroyed version of step 6 is the service's own (OpenBao `kv destroy`, GCP
`DestroySecretVersion`; Secrets Manager destroys no single version, so the
script deletes the secret without recovery, and Key Vault disables the
version). Step 8 is the DST scenario `allocator` (`scripts/dst.sh 0..N 8
--scenario allocator`): two to four clients HMAC with the linked name in
bursts, the simulated OpenBao rotates it, an operator refreshes it, the
refresher runs every 100 to 600 ms, the node crashes, and after each rotation
two turns of two actors need the new version in the same instant. Every
version number of the name is reserved once and ends active or failed, the
numbers are dense after the format fence, each `source_version` has exactly
one active number, each recorded HMAC was made with the value of the version
its `SecretRef` names, and both first uses after a rotation use the new
version.

**Outages (I10):**
- DST scenario `secret-outage` (`--scenario secret-outage`): the simulated
  OpenBao hangs for four fetch timeouts and up to 3 s more. Turns without
  secrets commit at their normal rate (within 250 ms of virtual time). Turns
  with a cached secret use it. Turns with an uncached secret fail with, or
  handle, `SECRET_UNAVAILABLE` within `fetch_timeout`, the error recorded as
  the effect's result, and leave no open `TurnBegin`. After the outage and
  the 5 s for which a failure is remembered, the uncached secret works.
- `secret_backends.rs` makes the fake hang and checks the same in a real
  daemon: turns without secrets commit at once, and a turn with an uncached
  secret ends within `fetch_timeout` as a failed turn that names
  `SECRET_UNAVAILABLE`, with nothing sent to the target, no open `TurnBegin`
  (also for a timer's turn and after a restart) and no second request for one
  `Idempotency-Key`. Every scenario of that file ends by checking that no
  `TurnBegin` is open once the daemon is quiet.
- `scripts/e2e-secrets.sh` does the same with each real service paused
  (`docker pause`: every request hangs), and OpenBao also stopped and started
  again (it comes back sealed, and requests are refused until it is
  unsealed): turns without a secret that arrive through the gateway commit
  within milliseconds, also right after a restart; a cached secret is used; a
  turn with an uncached secret fails within `fetch_timeout` with
  `SECRET_UNAVAILABLE: <name>` as its effect's recorded error and no open
  `TurnBegin`; the crash re-run of a recorded reveal waits while the service
  is down and then gets the recorded version's value.

**Cloud providers for real:** `scripts/e2e-cloud-secrets.sh` runs the
checks of `scripts/e2e-secrets.sh` against the real AWS Secrets Manager, GCP
Secret Manager and Azure Key Vault with the operator's own credentials (the
cloud CLIs for the test's own writes; environment variables and credential
files for the daemon), except the outages, as a test cannot stop a real
service. It makes one secret per cloud and deletes it. It is not in CI and
**has not been run**: the project has no cloud accounts for it. Running it
once before a release is the maintainers' call (§13).

## 10. Determinism and invariants

- **I2 / DST:**
  - Backends and key sources do I/O only through `Env` (net, clock,
    random, spawn), so DST drives them with fakes.
  - The version a turn sees is whatever the cache holds when its effect
    runs, recorded in the effect's `SecretRef`. Replay never consults the
    cache for recorded effects.
- **I5:**
  - Links (`SecretLink`) and versions (`SecretVersion`) are log records,
    applied into `state.db`, so they are rebuilt from the log.
  - Backend connection settings and credentials are node-local config, as
    `[ship]` is.
- **I8:**
  - No record holds a value.
  - The cache is memory only and `Zeroizing`.
  - Scrubbing covers every retained external version, fetched again after
    a restart, and fails closed until it does (§6).
- **I1:** a rerun never gives a recorded effect another outcome (§5.3).
- **I4 / I14 (open turns):** a `TurnBegin` without a `TurnRecord` is what a
  crash leaves, and the next start runs it. A turn that cannot get a secret
  records an error result for the effect instead of abandoning its `TurnBegin`
  (§6). Two checks guard the invariant in general: every daemon scenario of
  `secret_backends.rs` ends by checking that no `TurnBegin` is open once the
  daemon is quiet, and DST checks the same after every drain, also in the
  scenario `secret-outage`, where a backend hangs while turns need its
  secrets.
- **I10:** both features are opt-in. `file` stays the default for both,
  with no behaviour change for existing nodes apart from the new
  `SecretVersion` records.
- **I16:** both new record kinds are additive, with compat fixtures. A
  pre-M23 binary refuses a log with them, as for every new kind.
- **Forks:**
  - A fork reads the links and versions of its fork point from the log.
  - A fork never fetches from a backend (§6); under a `compute` grant an
    unmatched `crypto.*` of a name linked at the fork point uses the value
    this process holds for that link or is denied. With the built-in store,
    unmatched fork crypto uses the current value only under a `compute`
    grant; `recorded`, the default for a new grant since ADR 0112, denies
    it. A grant from before the mode stays `compute` (the known gap, now
    opt-in).
  - A fork never records new `SecretVersion`s in main's log.
- **Cluster (M16):** each node fetches independently; the metadata leader
  allocates version numbers (§5.1).

## 11. Numbering

- **ADRs:**
  - 0090: `SecretBackend`, links and versions in the log;
  - 0091: caching, outages and complete retained-value coverage;
  - 0092: the master key wrapped by a KMS or HSM (B1);
  - 0093: PKCS#11 through an optional helper process;
  - 0094: secret and key providers without SDKs (B1 KMS clients).
- **Record kinds:** 45 `SecretVersion`, 46 `SecretLink`. 47–49 are not used.
- **Proto fields 90–99:** none needed. `SecretRef` already carries
  `version` and `version_hash`, and the new messages are new kinds.
  `EffectSummary.secrets` is API JSON, not proto.
- **Error codes:** the eight in §8, milestone "M23".

## 12. Phase B plan

Each slice carries its tests, which fail without the change, and its docs.
Gates run through the CI harness. The status of each slice is in the table at
the top of this page.

0. **Spike** (a day):
   - a glibc `kronik-keyhelper` with `cryptoki` against SoftHSM2, called
     from the **musl release build** of `kronik`: AES-GCM wrap/unwrap of 32
     bytes by key label;
   - OpenBao transit encrypt/decrypt from a 60-line client over `Env::net`;
   - SigV4 against the AWS test vectors;
   - check `cryptoki`'s dependency tree with `cargo deny`.
1. **B1 key sources:**
   - `KeySource::load`, growing `MasterKey::open`;
   - `master.wrapped`, shipped with keystore backups and installed by
     restore;
   - mlock / `MADV_DONTDUMP` / zeroize of the seed and derived keys;
     non-dumpable offline commands;
   - providers openbao and aws first, then gcp and azure;
   - `keys status`, `keys wrap`, `keys rewrap`, with their audit events;
   - `scripts/e2e-keys.sh` (criterion 1, and restore onto an empty
     directory).
2. **B2 trait and log:**
   - `SecretBackend`;
   - the built-in store as `file`;
   - `SecretVersion` and `SecretLink` with compat fixtures and their
     `state.db` tables;
   - the per-name allocator; `secret set` and `secret delete` write
     `SecretVersion` as the intent; records for pre-M23 versions;
   - `link` (admin, `allowed_refs`), `unlink`, `refresh`, `history`;
   - `EffectSummary.secrets` in history;
   - effects resolve through links;
   - reruns fetch by `source_version` and never change a recorded outcome;
   - an in-test fake backend.
3. **B3 cache and outages:**
   - the resolver cache;
   - the refresher;
   - timeouts, stale use and failure caching;
   - foreign actors through the cache;
   - scrubbing of every retained version, failing closed;
   - revocation drops the cache; forks never fetch;
   - metrics and doctor;
   - the DST scenario `secret-outage`.
4. **B4 providers:**
   - `env`;
   - `openbao` (KV v2, token, AppRole, cert, renewal);
   - `aws` (SigV4);
   - `gcp` (JWT and metadata);
   - `azure` (client credentials and IMDS).
5. **B5 proof and docs:**
   - `crates/kronik/tests/secret_backends.rs` (criteria 2 and 3);
   - the e2e suite with OpenBao, moto, the emulators and SoftHSM2;
   - the operations guide (backends, the master key in a KMS, bootstrap
     credentials, migration, rewrap, losing the KMS key);
   - the security guide's at-rest map;
   - cli.md, json.md, openapi.json, errors.md.

6. **B6 PKCS#11, last and separable:** the default-off GNU helper archive,
   its own original normal-root/Rust notices and SBOM, two actual compilations
   and strict keyless consumer authentication. Exercise extracted helper
   enrollment/probe with owned SoftHSM; retain exact scope separately from the
   complete matching musl release lifecycle and device/vendor acceptance.

B1 and B2 are independent. B3 and B4 need B2's trait. M23 follows M28
(kind 40 for the key-source audit events, and M28's classifier for kinds 45
and 46).

## 13. Open questions

- **ADR 0093:** the release `kronik` is static musl and cannot load a
  PKCS#11 module at all. Proposed: a separate glibc `kronik-keyhelper`
  artifact that loads it for one call at start (the only C beyond SQLite,
  and outside the daemon). The alternative is PKCS#11 as a documented gap.
- **Release check:** run the real-cloud check before release (a few dollars
  a month while keys exist), or rely on the emulators.
- **Master-key rotation** (re-keying every store under a new seed): not in
  the brief, not in M23. `keys wrap` covers moving an existing key into a
  KMS.


## B1 design gate (2026-10-30)

This section records the gate of 2026-10-30: B1 was the implemented scope,
B2–B5 were pending, and B6 and ADR 0093 were maintainer-gated. B2 to B4 have
been built since (the table at the top of this page). The revised B1 design
was reviewed before implementation.
The earlier loader inventory is historical: the current code already fixes
missing/wrong keys, shipping and restore; offline upgrade and audit verify are
additional callers.

- All source readers use one provider-aware loader, including init, upgrade
  check and offline audit verify. Runtime shipping uses the loaded key, never
  a new KMS call. No fallback seed is created on a provider failure.
- Provider endpoints and key references come only from checked configuration.
  A wrapped envelope must match its configured source, key and purpose; its
  version is validated under that key, never used as an arbitrary URL.
- Provider TLS credentials and custom roots pass through the Env network
  boundary; certificate authentication must not bypass deterministic I/O.
- Publish the wrapped ciphertext before its matching keystore backup, which
  commits the pair. Advance ship state only after both uploads succeed. A
  rewrap is shipped independently even when the keystore has not changed.
  Rewrap replaces the single atomic `wrapped/current.wrapped` object, so
  wall-clock rollback cannot select an older wrapping version. Restore
  falls back to a paired wrapper only when current is genuinely absent.
- Restore selects a complete backup pair, unwraps and validates it and the
  snapshot secret store in staging before installing anything. The newest
  keystore rule remains: snapshot time does not restrict backup selection.
  No rejected restore replaces the target envelope or creates a fresh seed.
- Native snapshots reuse the existing private encrypted staging backup. Its
  SQLite destination is closed and has no WAL, SHM or journal before a
  non-overwriting hard link installs it in the snapshot's already-owned new
  directory. The stage is discarded before hashing and publishing the manifest;
  live secret rows and the existing snapshot cut, lock and retention stay intact.
- Wrap preserves the old key file unless explicit --remove-file is given.
  Rewrap checks the loaded seed and existing stores before replacing the
  envelope; the seed itself is never rotated.
- Offline wrap holds the data-directory FD lock shared with serve/restore;
  it needs no writable parent or lock file outside systemd's ReadWritePaths.
  Validation and reason scrubbing use private encrypted database/WAL copies.
  The binary shell applies the existing fail-closed audit scrubber before
  the source-change marker is persisted.
- Linux protects dedicated long-lived master/derived-key mappings with
  mandatory mlock and MADV_DONTDUMP, plus process dump exclusion. macOS keeps
  local file/env operation with mlock and disabled core dumps; this is not
  a debugger/inspection exclusion guarantee. Transient cipher working state
  and per-subject DEKs are zeroized but are not separately locked mappings.
- The configured start timeout is one total load budget, including fresh
  encryption and verification unwrap; no envelope is installed if either
  fails or the deadline expires. No retry starts after the deadline.

Before B2, revise version identity to include backend, ref and link generation
(not source_version alone), retain that identity for old-version recovery,
and prevent a failed built-in set intent colliding with the next store
max+1 allocation. None of those B2 changes are implemented by B1.
