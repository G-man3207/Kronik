# M23: Key and secret backends (design)

Status: B1 KMS lifecycle is implemented for OpenBao, AWS, GCP and Azure
after design re-review and the non-B6 spike. B2–B5 remain planned; B6 and
ADR 0093 remain maintainer-gated.
Sections 1–13 preserve the revised parked `m23-design` proposal from main
6c04dea, including its historical loader inventory and future acceptance
plan. The resumed B1 gate below supersedes stale B1 details. Observed
implementation evidence is recorded in STATUS.md; a plan is not a pass.

## The brief

English translation from the build brief (the authoritative Swedish brief is unchanged):

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

## 1. Historical baseline (main 6c04dea)

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
- Both are fixed by `fix-v01-master-key`: one loader (`MasterKey::open`),
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
  - **unmatched fork crypto** uses the *current* production value (a known
    gap, unchanged here).

**Scrubbing.** `Node::secret_values()` decrypts every non-deleted version of
every secret for each scrubbed API response and for foreign logs.

**Foreign actors** read the current values at each start and get them as
environment variables.

**What is missing:** no trait, no remote backend, no KMS or HSM code. The
dependency tree has no provider SDK and no PKCS#11 crate.

## 2. Overall proposal shape (B1 scope and planned B2–B6)

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
- **Memory, not swap** (review, Low): the seed and the six derived keys
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
  the guide says to create a dedicated derived transit key (review, Low).
  Azure RSA-OAEP has no AAD; the blob names its purpose in its own
  `schema` field only.
- **`master.wrapped` is shipped** (review H1): it is ciphertext, so it goes
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
| `pkcs11` (B6 proposed; maintainer-gated) | proposed `kronik-keyhelper` process (§3.4): `CKM_AES_GCM` on a non-extractable AES-256 key | proposed PIN file; not a B1 source |

Credentials are never in `kronik.toml`, only paths to files (or env names).
Systemd's `LoadCredential=` fits: `$CREDENTIALS_DIRECTORY` is read where a
path is relative (`pin_file = "kronik-hsm-pin"`). The bootstrap credential
has to live somewhere. The clean answers are instance identity (AWS role,
GCP metadata, Azure managed identity), a TLS client certificate, or an HSM
PIN in a credential. The operations guide says so plainly.

**What the envelope protects** (review M3): a copy of the data directory or
of the bucket without the bootstrap credential reveals no seed. A copy that
includes it (an AppRole `secret_id`, a TLS client key, a PIN file or AWS
keys on the same disk or in the same backup) can unwrap through a reachable
KMS. The security guide's at-rest map says this, recommends instance
identity, and `kronik doctor` warns when a credential file lies under the
data directory.

**Credential sources Kronik does not support** are refused at config check
with their name (review): AWS web identity, SSO and profiles; Azure
certificate credentials; GCP workload identity federation. Tokens have a
redacting `Debug`, and the shared `Env::net` client never logs headers.

### 3.3 Start, outages, migration and rewrap

- **The KMS is needed at start only.** After start the seed is in memory,
  so a KMS outage affects no turn (I10). At start, `kronik serve` retries
  the provider with backoff (Env clock) for `[keys] start_timeout` (default
  60 s). It then stops with `KEY_SOURCE_UNAVAILABLE`, and systemd restarts
  it.
- **Never a silent new key, never another key:** on main since
  `fix-v01-master-key`. A missing key over existing stores is
  `MASTER_KEY_MISSING`; a wrong one is `MASTER_KEY_MISMATCH`, from the
  `key_check` row each store holds, written only after the key has
  decrypted one of the store's values (so a mis-copied key is never
  blessed; review M5). A missing `master.wrapped` over existing stores is
  `MASTER_KEY_MISSING` too.
- **One loader.** `MasterKey::open` (main) becomes `KeySource::load(config)`
  with the KMS sources added; start, shipping, restore and init all use it.
- **A KMS outage during a restart is a full outage** (review, Low): it is
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
- **Key-source changes are audited** (review M6): `rewrap` writes an
  `AuditEvent` `keys.rewrap` with its reason; `keys wrap` runs offline and
  leaves a marker that the next start turns into a system `AuditEvent`
  `keys.source` (M28's restore-marker pattern). Both need M28's kind 40, so
  M23 Phase B merges after M28.

### 3.4 PKCS#11 helper proposal (B6, ADR 0093 maintainer-gated)

PKCS#11 is a C ABI: the vendor's module (`libsofthsm2.so`, a YubiHSM or
Luna library) must be `dlopen`ed. **The release `kronik` is a static musl
binary, which cannot `dlopen` at all** (review B1, probed: "Dynamic loading
not supported"), and the vendor modules are glibc-linked. So the daemon
never loads one:

- **`kronik-keyhelper`**, a second, small binary: dynamically linked
  against glibc, built for `x86_64-unknown-linux-gnu`, containing only
  `cryptoki` and the protocol. It is a separate release artifact
  (`kronik-keyhelper-<version>-x86_64-linux-gnu`), installed only by
  operators who use an HSM.
- **Run only when `[keys] source = "pkcs11"`**: at start, and by
  `keys wrap` and `keys rewrap`. The daemon spawns it with a cleared
  environment, `PR_SET_DUMPABLE 0` set by the helper first thing, stdin
  and stdout as pipes, and the PIN file's descriptor passed as fd 3 (the
  helper never reads config or paths of its own choosing).
- **Protocol:** one request line of JSON, one answer line, then exit:
  `{"op":"unwrap","module":"/usr/lib/softhsm/libsofthsm2.so",
  "token_label":"kronik","key_label":"kronik-master","iv":"…","aad":"…",
  "ciphertext":"…"}` → `{"ok":"<base64 seed>"}` or `{"error":{"code":…,
  "message":…}}`; `wrap` is the mirror. The daemon reads at most 4 KiB with
  a timeout and kills the helper on overrun.
- **Why a process even if a glibc build existed:** vendor C runs for one
  call in a process that exits right after; memory corruption, threads left
  after `C_Finalize`, signal or atfork handlers and a second libcrypto never
  reach the daemon or its `runsc` spawns.
- The daemon keeps the rule "no C beyond bundled SQLite". The helper is the
  narrow exception ADR 0093 asks the maintainers to confirm; the alternative is
  PKCS#11 as a documented gap.
- **Proof** runs against the daemon and helper extracted from release archives
  (`dist/release/*.tar.gz`), never a dev build: SoftHSM2 in `e2e-keys.sh`.
- M21's unit has `PrivateDevices=yes`, which hides USB HSMs: the guide
  ships a `DeviceAllow=` drop-in for them (review, Low).

## 4. Planned B2–B4: `SecretBackend` and links (parked ADR 0090)

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

- `kronik secret link <name> --backend bao --ref secret/payments#stripe
  --reason R [--dry-run]` checks that the backend exists on this node and
  that `ref` lies under one of the backend's `allowed_refs` prefixes, then
  fetches the current value once, so a bad ref fails now with the backend's
  error rather than at the first turn. The dry run fetches but appends
  nothing and does not fill the cache.
- **Scope `admin`, and an allowlist** (review M2): the backend sees only
  the node's identity, so its own policy cannot tell which Kronik caller
  asked. Without a limit, `link` (with `secret-reveal` and an `http.fetch`
  grant) could read and send out anything that identity can read. So
  `[secrets.backends.<id>] allowed_refs = ["secret/payments/", …]` is
  required for every external backend (an empty list refuses every link),
  a ref outside it is `SECRET_REF_NOT_ALLOWED` (403), and `link`/`unlink`
  need scope `admin`.
- `kronik secret unlink <name> --reason R [--dry-run]`.
- A linked name has no built-in value. `secret set` on it answers
  `SECRET_EXTERNAL` (409), with the hint "set it in the backend, then `kronik
  secret refresh <name>`". Grants stay `secret:<name>` and
  `secret-reveal:<name>`, so guest code does not know or care where a value
  lives.
- `SecretLink` is applied to a `secret_links` table in `state.db`, so it is
  rebuilt from the log.

## 5. Planned B2: versions and hashes in the log (parked ADR 0090)

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

- **The hash** is the built-in one: `version_hash = BLAKE3_keyed(k,
  name ‖ 0 ‖ version_le ‖ 0 ‖ value)[..16]`, with k derived from the master
  key. So an external secret's hash is computed, stored and shown exactly
  as the built-in store's: in `SecretRef.version_hash` on every effect, in
  `secret list`, and in `SecretVersion`. That is the second criterion,
  literally.
- **Kronik's version number has one allocator per name** (review H4). A
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
  MAC, a reveal), as `TurnBegin` is committed before the turn runs (review,
  Low), so the log says which version actually left.
- **On an M16 cluster** the metadata leader is the allocator: `record`
  forwards to it, and the record lives in the metadata log. M16's design
  names a metadata entry `SecretVersion` too; they are to be the same
  record, with M23's fields, reconciled when M16's metadata log is built
  (M16 §9/§12).
- **The built-in store writes it too, as the intent** (review M7, with
  M28): `secret set` allocates the number, appends `SecretVersion` with the
  caller's audit, then writes `secrets.db`; a failed write appends M28's
  `secret.set.failed` `AuditEvent`. `secret delete` appends one with
  `deleted = true` and its reason, then deletes. This replaces M28's
  `secret.set`/`secret.delete` intent events for these two routes, so each
  change has one record, and M28's classifier exports kinds 45 and 46 (both
  carry `Audit`; its proto-walking test enforces it).
- **Versions from before M23** have no record (review, Low): the first M23
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
  `@v3`, a turn after it `@v4`.
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
- **A recorded outcome is never changed** (review H2, I1). A reveal (or a
  re-send) whose `EffectResult` was recorded `Ok` must give the guest that
  value again:
  - **`Unavailable`:** the rerun retries with backoff (Env clock) and holds
    only that actor's turn; other actors run (I10). Doctor and
    `kronik_secret_stalled_reruns` show it.
  - **`VersionGone`** (destroyed version, changed `env` value): the turn
    fails with `SECRET_VERSION_GONE` before the guest sees anything, and
    goes to dead letters with that code. The guest never takes a path the
    log does not record.
  - An effect *without* a recorded result is a new effect and may get an
    error result as in §6.
- **Identity replay** (`kronik fork replay`, the identity check) needs no
  secret value for recorded effects, so it gives the same outcomes before
  and after a rotation.

## 6. Planned B2–B5: caching, outages and timeouts (parked ADR 0091)

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
    (default 24 h), with `kronik_secret_stale{name}` set and a warning;
  - **no cache:** fetches with `[secrets] fetch_timeout` (default 2 s, Env
    timer).
    - On failure, the effect gets an error result, `SECRET_UNAVAILABLE`.
      This is like a network error: status `error`, and the guest sees an
      error it can handle.
    - The turn is not failed by Kronik, and nothing else waits.
    - Only a failure is cached: for 5 s, so a burst of turns does not
      queue on a dead backend.
- **Turns that use no linked secret never touch the cache or a backend.**
  The DST scenario `secret-outage` asserts this with a backend that hangs
  forever: such turns commit at their normal rate.
- **Retries:** the refresher backs off from 1 s up to `refresh`. A
  `Denied` error (bad credentials) is logged once per change and counted.
- **Token lifetimes:** OpenBao tokens are renewed with `renew-self` at half
  their TTL. AppRole logs in again when renewal fails. Cloud access tokens
  are refreshed before `expires_in`.
- **Foreign actors:**
  - They get their values from the same cache at start. A backend that is
    down stops only a foreign start that has no cached value; the
    supervisor's existing retry applies.
  - A rotation does not restart a running foreign actor. `kronik foreign
    restart` or the next start picks the new version.
- **Scrubbing survives restarts** (review H3, I8). `ok_scrubbed` keeps
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
- **Revocation beats staleness** (review M1): `NotFound`, `Denied`,
  `VersionGone` from a refresh, and `unlink`, drop the cached value at
  once; only `Unavailable` (timeouts, 5xx) uses `max_stale`. A rotation
  reaches new effects within `refresh` (5 min) or at once with `secret
  refresh`.
- **Forks never fetch** (review M4, I7): an unmatched effect in a fork that
  needs an external secret uses a value this process already holds for the
  fork point's link and version; otherwise it is denied in the fork and the
  diff marks it unverifiable. No provider audit log or bill sees a fork.
- **Metrics:**
  - `kronik_secret_fetch_total{backend,result}`;
  - `kronik_secret_fetch_seconds{backend}`;
  - `kronik_secret_stale{name}`;
  - `kronik_secret_versions_total{backend}`.
- **Doctor:** each backend's last success and error, and linked names with
  no cached value.

## 7. Providers without SDKs (ADR 0094)

Every provider is a small REST client over `Env::net()` (hyper and rustls
with ring, the effects client), with JSON through `serde_json`:

| Need | How | New crate? |
|---|---|---|
| OpenBao / Vault | B1 transit + token/AppRole/cert login; KV v2 and token renewal remain planned B4 | no |
| AWS SigV4 | B1 KMS over ring HMAC/SHA256 and `env.clock`, with published signing vectors; Secrets Manager remains planned B4 | no |
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
design does not claim that unlanded tree or any SoftHSM check passed.

## 8. Proposed configuration, CLI and API (B2–B6 not implemented)

B1's shipped interfaces are documented in the current CLI, JSON and OpenAPI
references. This original combined proposal also contains planned external
secret and PKCS#11 interfaces; those are not available in B1.

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

[keys.pkcs11]
helper = "/usr/local/libexec/kronik-keyhelper"   # the glibc helper (§3.4)
module = "/usr/lib/softhsm/libsofthsm2.so"
token_label = "kronik"
key_label = "kronik-master"
pin_file = "kronik-hsm-pin"

[secrets]
refresh = "5m"
max_stale = "24h"
fetch_timeout = "2s"
```

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
| `kronik secret backends` | GET `/v1/secrets/backends` | read | id, type, address host only, last success/error |
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
- `KEY_SOURCE_UNAVAILABLE` (503): at start and in doctor;
- `KEY_HELPER_FAILED` (503): `kronik-keyhelper` missing, crashed, timed out
  or answered an error.

`MASTER_KEY_MISSING` and `MASTER_KEY_MISMATCH` exist already
(`fix-v01-master-key`).

Milestone "M23".

## 9. Acceptance plan (B1 evidence in STATUS.md; B2–B6 planned)

The original full-M23 plan uses the following free services. Only the B1
KMS lifecycle is implemented; external-secret and PKCS#11 runs remain planned.

| What | With | Licence |
|---|---|---|
| Vault-compatible backend and the KMS path | `openbao/openbao` (KV v2 + transit), dev mode | MPL-2.0 (a separately run server, not linked) |
| AWS Secrets Manager + KMS | `motoserver/moto` | Apache-2.0 |
| GCP Secret Manager (planned B4) | Blackwell Systems REST emulator | Apache-2.0, third party |
| Azure Key Vault RSA wrap/unwrap (secrets planned B4) | rokeller emulator, pinned B1 version/digest in STATUS.md | Apache-2.0, third party |
| PKCS#11 (maintainer-gated B6 proposal) | proposed SoftHSM2 run, not exercised by B1 | BSD-2-Clause |
| GCP Cloud KMS | Blackwell Systems dual REST KMS emulator, pinned B1 digest in STATUS.md | Apache-2.0, third party |

Not used:
- **LocalStack:** since March 2026 its image needs an account token under
  proprietary terms.
- **HashiCorp Vault:** BUSL-1.1. OpenBao proves the same API.

B1's actual pinned service images, proper TLS leaf fixtures and observed
outcomes are recorded in STATUS.md; this table is not a proof of unrun work.

**B1 criterion 1: "Kronik starts with the master key in a KMS without the key
being written to disk"** (`scripts/e2e-keys.sh`; observed runs in STATUS.md):
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
6. **Restore onto an empty directory** (review H1): ship, then `kronik
   restore` into a new directory whose only key source is the KMS
   configuration. The restored node installs the shipped `master.wrapped`,
   unwraps through OpenBao, and its secrets and sealed values decrypt.

The same flow runs for `aws` (moto KMS), `azure` (emulator wrapkey) and
`pkcs11` (SoftHSM2: `softhsm2-util --init-token`, then an AES key created
with `pkcs11-tool --keygen` as non-extractable). For `pkcs11` the needle
search also covers SoftHSM's token directory, which holds its own encrypted
key store. All of these run the **release artifacts** (`kronik-*-musl` and
`kronik-keyhelper`), never a dev build (review B1).

**Planned B2–B4 criterion 2: "Secrets from an external backend get a version
hash in the log, just as with the built-in store"**
(`crates/kronik/tests/secret_backends.rs` is still planned):
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

**Planned B2–B5 criterion 3: "Rotation of a secret shows up as a new version
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
   outcome (review H2). With OpenBao stopped instead, the rerun waits and
   the guest never sees `SECRET_UNAVAILABLE` for a recorded reveal.
7. **Scrubbing after a restart** (review H3): reveal v1 and store it in
   state, rotate, restart; `actors inspect` and `history` never show v1,
   and while v1 is not yet fetched again they answer `SECRET_UNAVAILABLE`.
8. **One allocator** (review H4): a DST scenario with two concurrent first
   uses and the refresher on a rotated backend gives exactly one record per
   `source_version`, with dense numbers.

**Outages (I10):**
- DST scenario `secret-outage`: a fake backend that hangs. Turns without
  secrets commit at their normal rate. Turns with a cached secret use it.
  Turns with an uncached secret get `SECRET_UNAVAILABLE` within
  `fetch_timeout`.
- An e2e test stops OpenBao mid-run and checks the same in a real daemon.

**Cloud providers for real:** `scripts/e2e-cloud-secrets.sh` runs against
real AWS, GCP and Azure only with the operator's own credentials. It is
not in CI or the batch: about $1 a month per KMS key, plus API calls.
Running it once before release is the maintainers' call (§12).

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
- **I10:** both features are opt-in. `file` stays the default for both,
  with no behaviour change for existing nodes apart from the new
  `SecretVersion` records.
- **I16:** both new record kinds are additive, with compat fixtures. A
  pre-M23 binary refuses a log with them, as for every new kind.
- **Forks:**
  - A fork reads the links and versions of its fork point from the log.
  - A fork never fetches from a backend (§6); with the built-in store,
    unmatched fork crypto keeps today's behaviour (a known gap).
  - A fork never records new `SecretVersion`s in main's log.
- **Cluster (M16):** each node fetches independently; the metadata leader
  allocates version numbers (§5.1).

## 11. Numbering

- **ADR reservations/status:**
  - 0090: parked proposal for `SecretBackend`, links and versions;
  - 0091: parked proposal for caching, outages and timeouts;
  - 0092: restored and accepted for B1 KMS only;
  - 0093: unlanded helper proposal, requiring maintainer approval;
  - 0094: restored and accepted for B1 KMS clients only.
- **Record kinds:** 45 `SecretVersion`, 46 `SecretLink`. 47–49 are not used.
- **Proto fields 90–99:** none needed. `SecretRef` already carries
  `version` and `version_hash`, and the new messages are new kinds.
  `EffectSummary.secrets` is API JSON, not proto.
- **Error codes:** the seven in §8, milestone "M23".

## 12. Phase B plan

Each slice carries its tests, which fail without the change, and its docs.
Gates run through `kronik-slot`.

0. **Spike** (a day):
   - a glibc `kronik-keyhelper` with `cryptoki` against SoftHSM2, called
     from the **musl release build** of `kronik`: AES-GCM wrap/unwrap of 32
     bytes by key label;
   - OpenBao transit encrypt/decrypt from a 60-line client over `Env::net`;
   - SigV4 against the AWS test vectors;
   - check `cryptoki`'s dependency tree with `cargo deny`.
1. **B1 key sources:**
   - `KeySource::load`, growing main's `MasterKey::open`;
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
   - the e2e and batch rows with OpenBao, moto, the emulators and SoftHSM2;
   - the operations guide (backends, the master key in a KMS, bootstrap
     credentials, migration, rewrap, losing the KMS key);
   - the security guide's at-rest map;
   - cli.md, json.md, openapi.json, errors.md.

6. **B6 PKCS#11, last and separable:** `kronik-keyhelper` (glibc, its own
   release artifact), the daemon side of its protocol, the SoftHSM2 e2e
   run against the release artifacts, and the `DeviceAllow=` drop-in. It
   can be dropped to a documented gap without touching B1–B5.

B1 and B2 are independent. B3 and B4 need B2's trait. M23 merges after M28
(kind 40 for the key-source audit events, and M28's classifier for kinds 45
and 46).

## 13. Open questions for the maintainers

- **ADR 0093:** the release `kronik` is static musl and cannot load a
  PKCS#11 module at all. Proposed: a separate glibc `kronik-keyhelper`
  artifact that loads it for one call at start (the only C beyond SQLite,
  and outside the daemon). The alternative is PKCS#11 as a documented gap.
- **Release check:** run the real-cloud check before release (a few dollars
  a month while keys exist), or rely on the emulators.
- **Master-key rotation** (re-keying every store under a new seed): not in
  the brief, not in M23. `keys wrap` covers moving an existing key into a
  KMS.


## B1 resumed design gate (2026-10-30)

Only B1 is resumed. B2–B5 remain pending; B6 and ADR 0093 remain maintainer-gated.
The revised B1 design was re-reviewed before implementation. The earlier
loader inventory is historical: current main already fixes missing/wrong keys,
shipping and restore; offline upgrade and audit verify are additional callers.

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
