# Security model

Kronik assumes that actor code, foreign images and agents can be wrong or
hostile, and limits what each of them can do. This page lists the threats,
the protections that the brief requires against each, and which of them the
code has today; the others are marked with the milestone that brings them.

Kronik is pre-alpha: do not run it in production yet. `SECURITY.md` in the
repository root says how to report a vulnerability.

## Threats and protections

| Threat | Protection | In the code today |
| --- | --- | --- |
| Untrusted actor code | Wasm sandbox, fresh instance per turn, capabilities with default deny, limits for fuel and memory | All of them: the sandbox, fresh instances and limits since M1, default deny since M2 |
| Untrusted images | gVisor, no external network, images pinned by digest, resource limits | All of them since M7: gVisor sandboxes with no outbound network, images pinned by digest, CPU and memory limits ([M7 design](../design/m7-foreign.md)); `isolation = "trusted"` runs runc with a seccomp filter instead |
| Agents with too much power | Tokens with scopes, policy and approvals, forks without personal data by default, a reason on every mutation | A reason on every mutation. Policy and approvals: M3. Tokens and scopes: M5. Forks without personal data: M8 |
| Leaked secrets | Handles by default: the value is inserted at the effect boundary and never reaches the guest or the log. Revealing a value requires its own capability, and the value is scrubbed | All of them, since M2 |
| Theft of the data directory | Sealed subject values and encrypted secrets, with their master seed held separately; encrypt the disk for plaintext log data | Privacy mode since M8; M23 B1 adds KMS-wrapped master seeds. This does not encrypt ordinary log inputs/metadata or protect a compromised live host |
| Unauthorized API access | Unix socket with file permissions, TCP only with a token, TLS for external traffic | The Unix socket; TCP only with a bearer token and, off loopback, only with TLS (M5); scopes per token (M5); TLS for the gateway and the TCP API since M6 |
| The supply chain | cargo-deny, SBOM and release builds that are as reproducible as possible | cargo-deny in CI. Static release binaries arrive with M6, and the SBOM with the v0.1.0 release |

## Actor code

- **Sandbox.** An actor is a Wasm component. It reaches nothing outside
  its own memory except through the imports in the
  [WIT reference](../reference/wit.md). Deploy rejects a component that
  imports anything else, such as `wasi:filesystem` or `wasi:sockets`, with
  `IMPORT_NOT_ALLOWED`, and the engine links only the allowed interfaces, so
  such a component could not even be instantiated
  ([ADR 0001](../adr/0001-wasmtime-determinism.md)).
- **Fresh instance per turn (I3).** Nothing in guest memory survives to the
  next turn, so one input cannot leave state behind for the next except
  through the actor's recorded state.
- **Limits.** Fuel bounds a turn's CPU, a resource limiter its memory (64
  MiB by default), and the host the size of messages, state values, SQL
  values and each actor's database. SQL runs in the host, but its VM steps
  count against the turn's fuel limit. Limits can be set per kind from M2.
- **Default deny (I6, M2).** An actor can do nothing beyond its own state,
  its messages and its timers until the operator grants a capability:
  `http:<host>` or `http:*.<suffix>` for outgoing HTTP, `secret:<name>` to
  use a secret in a header or in `crypto`, `secret-reveal:<name>` to read
  its value, `connection:send-now` to send on a connection before the turn
  commits (M24). Without a grant the guest gets `denied` and the denied effect
  is recorded. The capabilities that a component asks for in its manifest
  grant nothing. Grants are records in the log, apply per kind (so new code
  of a kind keeps them), carry a delivery class and an optional rate, and
  are checked against the configuration of the turn's epoch.
- **Host code.** `unsafe` Rust is denied in the whole workspace except two
  allowlisted modules: loading precompiled code in `kronik-runtime` and the
  SQLite bindings in `kronik-store`. Precompiled code is read only from
  Kronik's own data directory, never from user input.

Known gaps: SQLite has no memory limit per statement, so the VM step budget
bounds sorts and recursive queries only indirectly (ADR 0005 leaves this for
the hardening milestone, M31).

## Secrets

Secrets arrive with M2.

- **Storage.** The file source loads `<data>/keys/master.key`
  (`--master-key-file`), or creates 32 random bytes in hex, mode 0600.
  `KRONIK_MASTER_KEY` supplies that seed from the environment without a key
  file. M23 B1 also supports OpenBao transit, AWS KMS, GCP Cloud KMS and
  Azure Key Vault: the provider wraps the same 32-byte seed, and only its
  ciphertext envelope lives at `<data>/keys/master.wrapped`. A fresh
  KMS-backed node never writes a plaintext seed file. Secret values remain
  in `<data>/keys/secrets.db`, sealed with XChaCha20-Poly1305 under a derived
  key, one row per version. These key sources change custody of the master
  seed, not the built-in secret store into an external secret backend.
- **Copies of external values.** A value fetched from an external secret
  backend is held in memory for effects, never on disk. For each version of
  it that the node records, `secrets.db` also keeps one scrub-only copy
  (table `external_scrub_copies`), sealed with XChaCha20-Poly1305 under its
  own key derived from the master seed and bound to that version's identity
  ([ADR 0142](../adr/0142-scrub-only-copies-of-external-secret-versions.md)).
  It exists so that the views can still remove the value from what they show
  after a restart when the backend no longer serves the version. It never
  answers an effect, a re-run, a fork, a reveal or a foreign actor, and no
  API shows it. It travels inside snapshots and the bucket with
  `secrets.db`, stays valid across `keys rewrap`, and is kept as long as the
  version's record, like the built-in store's deleted versions; a copy of a
  version that never became active is deleted at the next start. So a
  backend's revocation ends every use of a value at once, but not every
  encrypted trace of it in the data directory and its backups.
- **Handles.** Guest code names a secret in an HTTP header template such as
  `Bearer {}` (with standard `fetch`, M22, the header value `Bearer
  {{secret:NAME}}`) or in a `crypto` call, and the host inserts the value at
  the effect boundary or computes with it. The value never enters guest memory,
  and the log records only the secret's name and a keyed hash of its
  version, which reveals nothing even about short values. `kronik history`
  and the turn JSON show that identity for each effect that used a secret,
  as `secret:<name>@v<N>` with the first 8 hex characters of the hash, so
  a rotation shows up as a new version in the turns after it. A request
  sealed for a data subject shows none of it to a caller who may not read
  the request, nor once the subject is erased.
- **Operations.** `kronik secret set` reads the value from stdin, never
  from the command line, and does not echo it on a terminal;
  `kronik secret list` shows names, versions and version hashes but never
  values; `kronik secret delete` marks every version deleted. Every
  operation needs a reason.
- **A secret that cannot be fetched.** A secret from an external backend
  that is not cached and cannot be fetched within `[secrets] fetch_timeout`,
  or that the backend refuses, fails the effect that asked for it with
  `SECRET_UNAVAILABLE`, as a network
  error does: `http.fetch` answers `network` with that text, `crypto.*` and
  `secrets.reveal` a denial with it. Nothing is sent. The error is recorded
  in the turn before the guest sees it, and the guest decides: a handler
  that fails ends the turn as failed (a message or timer becomes a dead
  letter), one that handles the error commits. The caller is not answered
  with a 503, and no turn is left open to run at the next start. A client
  that repeats the request with the same `Idempotency-Key` gets the recorded
  answer back until `[gateway] idempotency_ttl` has passed; use a new key to
  try again. A fork replays the recorded error and never asks the backend. See
  [A turn whose effect cannot get its secret](operations.md#a-turn-whose-effect-cannot-get-its-secret).
- **Reveal.** `secrets.reveal` returns a raw value only with the capability
  `secret-reveal:<name>`. In a fork it returns the placeholder
  `[secret:<name>]`, never the value. `crypto.*` in a fork returns a
  matching recording when one exists. Otherwise the grant's in-forks mode
  decides ([ADR 0112](../adr/0112-fork-crypto-grant-mode.md)): `recorded`,
  the default for a new grant, denies the call (`replay: no recording`) and
  does not compute; `compute` signs on the host with the production key.
  The key stays on the host either way: it is not in the guest, the log, or
  the diff. A `compute` grant still lets code in a fork (scope `fork`)
  obtain HMACs and signatures under production keys over data it chooses,
  which is as good as the key for webhooks and tokens signed with it. Each
  such computation is a log line and a `kronik_fork_crypto_computations_total`
  sample. Grant `fork`, and `compute`, only to callers you would trust with
  that. An older grant with no mode stays `compute`; re-granting without
  `--in-forks compute` writes `recorded`. A name that is linked to an
  external backend at the fork point is computed with the value the node
  already holds for that link, and denied (`SECRET_UNAVAILABLE`) when it
  holds none: a fork never asks the backend. Both are graded synthetic
  (ADR 0132). A preview (M11) answers whoever
  has its URL, so it gets no production key at all: its `crypto.*` calls
  answer `no recording`.
- **Scrubbing.** When a turn used or revealed a secret, exact occurrences of
  the value are replaced by `[secret:<name>]` in the turn's state writes,
  SQL text and blob values (a blob stays a blob), messages, timers,
  compensations, output, effect requests and responses (each
  `EffectResult` before it is appended) and log events before anything is
  written, so the value reaches neither the log nor a state file. Fork turns are scrubbed the same way. Responses from HTTP targets are scrubbed of the inserted
  values before the guest sees them, and the API's views of actors,
  history, turns, timers and dead letters replace the values of all live
  secrets.

Scrubbing matches exact bytes, and only values of at least 4 bytes other
than `true`, `false` and `null` (which would break JSON). An
encoded, split or otherwise transformed value is not caught, and code that
has seen a value can always leak it, for example to a host it may call
(I8). A value handed to another actor in a `call` is the callee's input:
the callee did not use or reveal the secret, so its turn record, its state
and its reply hold the value as it got it (messages sent with `send` and
compensations are scrubbed in the sender's turn before delivery, so their
receivers get the placeholder). Grant `secret-reveal` as rarely as
possible.

**Secrets linked to an external backend.** The views that remove secret
values (`history`, `actors inspect`, turns, traces, dead letters and the
audit log, among others) need the value of every secret version that the node
recorded. After a restart a node takes them from its scrub-only copies (see
above), so a version that the provider no longer serves is still removed. A
recorded version without a copy (one an earlier release recorded, or one
recorded after the newest snapshot of a restored node) that the provider no
longer serves makes the views answer 503 `SECRET_UNAVAILABLE` instead of
showing data they cannot scrub; the log and the state are intact and turns
keep running. See [Secrets that an external backend no longer
serves](operations.md#secrets-that-an-external-backend-no-longer-serves).

### Master-key custody

Keep file keys and KMS bootstrap credentials apart from the data directory
and its backups. Relative provider credential/CA paths resolve beneath
`CREDENTIALS_DIRECTORY`; absolute paths are also accepted. Each provider's
custom CA and OpenBao client identity are scoped to that provider, not
guest HTTP effects. There is no insecure TLS or unprotected-memory fallback.

The long-lived master seed and its derived storage/hash keys occupy locked
pages. Linux marks those mappings `MADV_DONTDUMP` and the key-loading process
non-dumpable; macOS disables core dumps and locks the mappings. Failure to
establish required protection is `KEY_PROTECTION_UNAVAILABLE`, not a warning.
Controlled KMS payload and credential buffers are zeroized on drop, but
HTTP headers and libraries can make ordinary transient copies that are not
all controlled or wiped. This is not a blanket guarantee against sensitive
data reaching swap. The protections do not defend against a privileged
attacker on the running host or make arbitrary application state secret.

A running node keeps its loaded seed: an unavailable KMS does not stop
turns or force the shipper to unwrap again. Start, offline verification and
rewrap do need the provider and fail with `KEY_SOURCE_UNAVAILABLE` within
the configured total operation budget. Missing ciphertext over existing
encrypted stores is `MASTER_KEY_MISSING`; Kronik must not regenerate a
replacement seed there.

`keys wrap` migrates an existing file/environment seed offline; stop the
daemon first. Older v0.3 daemons do not participate in the new cooperative
directory lock. The old file is preserved unless `--remove-file` is explicit,
and removing it does not erase copies in filesystem snapshots or backups.
Migration is therefore not proof that a seed was never on disk.

Online `keys rewrap` needs `admin` and a reason, retains the seed, verifies
the new ciphertext and records the change. It is not seed rotation. Keep
old provider key versions decryptable for retained backups. Shipping stores
the current encrypted envelope independently and pairs keystore backups
with ciphertext; restore validates these and the restored stores before
installing them. Neither plaintext seeds nor bootstrap credentials belong
in the bucket. Theft of the envelope **and** credentials authorized to unwrap
it can still expose the seed; use least-privilege provider policy.

See [the operations guide](operations.md#the-master-key) for provider
configuration, migration, outages and restore.


## The log is sensitive

The log holds the whole history of the system: every input, state value, SQL
change, message, and effect request and response. Until privacy mode (M8)
seals values under their subject's key, all of it is plaintext. It also
holds every turn's random seed, so anyone with the log can recreate a token
that a turn generated from `random-bytes`.

- Treat the data directory as a secret, and from M6 also its snapshots and
  the copies shipped to object storage.
- Put the data directory on an encrypted disk.
- HTTP inputs are kept as they came, credentials included: an end user's
  `Authorization`, `Cookie` and API-key or token headers, and the
  `Set-Cookie` an actor answers with. The API shows those headers as
  `[redacted]` to a caller without `pii:read`, in turns and in fork and
  proposal diffs (JSON, Markdown and MCP `get_diff`), and `policy test`
  evaluates such a caller's rules on that redacted diff: any header whose
  name contains `authorization`, `x-auth`, `cookie`, `api-key`, `apikey`,
  `api_key`, `access-key`, `session`, `jwt` or `password`, or ends in
  `token` or `secret`. So a redacted diff does not hash to the proposal's
  `diff_hash`, which is that of the stored diff.
- At every start `kronik serve` gives the data directory mode 0700 (0710
  when the API socket is inside it, so that the socket's group can reach
  it), `keys/` mode 0700, and the key stores in it (`master.key`,
  `secrets.db`, `keystore.db`, `tokens.db`, with their SQLite `-wal` and
  `-shm` files) mode 0600. New or replaced KMS ciphertext envelopes are
  mode 0600; loading an existing or custom `wrapped_file` does not
  universally reset its permissions. The API socket has mode 0660. Other
  files get the process's default permissions; the directory's mode keeps
  them private. The systemd unit that `kronik serve --init` installs creates
  the data directory with mode 0700 too.

## API access

- **Unix socket.** The JSON API listens on a Unix socket,
  `/run/kronik/api.sock` unless `--api-socket` says otherwise, with mode
  0660: the socket file's owner and group can use the API, nobody else.
  A caller without a token has every scope there, so whoever can connect
  has full control; a caller that sends a token gets that token's scopes.
- **Tokens and scopes (M5).** `kronik token create` makes a bearer token
  with scopes: `read`, `fork`, `propose`, `approve`, `promote`, `operate`
  (grants, limits, secrets, messages and resends on main), `pii:read` and
  `admin` (every scope, and tokens). An agent's token has `read`, `fork`
  and `propose` by default: it can read, fork, propose and ask for an
  approval, and a human with `approve` and `promote` takes it from there.
  The token is shown once; `<data dir>/keys/tokens.db` (mode 0600) keeps
  its BLAKE3 hash, never the token, and `kronik token revoke` stops it at
  once, on every listener. Every request is checked against the scope its
  route needs (`SCOPE_MISSING` otherwise), MCP tool calls included.
- **The API over TCP (M5)** is off unless `server.api_listen` or
  `--api-listen` sets an address. There, every request needs
  `Authorization: Bearer <token>` (`UNAUTHENTICATED` otherwise), checked
  before the body is read. Without `[tls]` only a loopback address is
  accepted; with it, the TCP API uses the gateway's certificate, so tokens
  never cross a network in the clear. A client has 10 s to send a request
  head and 120 s for its body; how many connections may be open at once
  follows from the limit on open files (below).
- **Audit.** Every mutation needs a non-empty reason (`REASON_REQUIRED`
  otherwise) and can run as a dry run first. It is recorded with the reason,
  the wall-clock time and the caller's token id: `token:<name>` for a token,
  else `unix:uid=<n>`, the uid of the connecting process from the socket's
  peer credentials. Token names are never reused, so the id stays
  unambiguous in the log.
  Secret/token changes record intent before changing their stores and
  record a `.failed` event if the change fails; intent is not proof of
  success. Audit export emits `kronik.audit/v3` only. Free text, names and
  spans are scrubbed for secret values and token spellings. A line's
  `record_hash` covers the scrubbed free text and is keyed with the master
  key, so it does not confirm a guess of private text, and checking it
  (`kronik audit verify`) needs the master key. Subject masking handles
  case, percent encoding and identifier boundaries.
  If the inventory cannot be loaded, privacy-sensitive API projections
  return 503 `SECRET_UNAVAILABLE` and both exporters stall preparation
  without cursor advance. A mutation waits for a rebuild in flight (at
  most `[secrets] fetch_timeout` plus 5 s) and records its reason; only a
  wait that runs out withholds the audit text, and a mutation does not
  wait while the rebuilds fail. Unrelated
  node work remains usable. Complete retained external/deleted-version
  coverage across restart remains M23 work; current local inventory is
  not evidence that this is closed.
  Export rewind also records intent before its effect; intent is not a
  success claim. An owned task preserves the durable replay request after
  caller cancellation. Configuration observations remain source-audited
  even if the export cursor cache is unavailable.
- **The gateway** serves plain HTTP, on `127.0.0.1:8080` unless
  `--http-listen` says otherwise, or HTTPS when `[tls]` in `kronik.toml`
  sets `mode = "files"` (a certificate and key, reloaded every 12 hours) or
  `mode = "acme"` (a certificate for `domains` by ACME TLS-ALPN-01 on the
  gateway's own port, renewed 30 days before expiry), since M6
  ([ADR 0009](../adr/0009-acme-instant-acme.md)). It does not authenticate
  requests: every deployed route is open to whoever can reach the port. It
  accepts request bodies up to 1 MiB. A client has 10 s to send a request
  head and 30 s for its body. How many connections may be open at once
  follows from the limit on open files (below). One client address may
  hold a quarter of them; a connection over that share gets
  `503 UNAVAILABLE` with `connection: close`. A reverse proxy carries many
  users' traffic from one address: list it in `[gateway] trusted_proxies`,
  which exempts it from the share. An actor's response cannot set
  `Content-Length`, `Connection`, `Transfer-Encoding` or another hop-by-hop
  header, nor `kronik-turn-id`, so it cannot spill into the next response
  on a connection; a status outside 200 to 599, an informational one (1xx)
  or one of 600 and above, is answered with `TURN_FAILED`. A failure inside
  Kronik is answered with a generic
  `INTERNAL`, and the daemon's log has the details. Without TLS, keep the
  gateway on a private address or behind a proxy that terminates TLS.
- **File descriptors.** `kronik serve` raises its soft limit on open files
  to the hard one at start (the systemd unit sets `LimitNOFILE=65536`) and
  keeps half of them, at most 1 024, for the log, the actor databases and
  the key stores. Of the rest, the gateway may hold three quarters as
  connections (between 16 and 1 024) and the TCP API a quarter (between 4
  and 256): 1 024 and 256 under the unit's limit, 384 and 128 under a hard
  limit of 1 024. The start-up log line `kronik is serving` names the
  numbers. A failed `accept()` is logged and tried again after a pause of
  up to a second. The admin listener gives a client 10 s for a request
  head.

The MCP server is served at `/mcp` on the Unix socket and, with
`--api-listen`, on TCP. It makes every tool call as an API request with the
caller's token, so an agent has exactly its token's scopes. A token without
`pii:read` always gets forks without personal data: the API records
`no_pii` on every fork and proposal it makes, and in every privacy mode the
fork's actors read each value tagged with a subject as a pseudonym (see
[forks without personal data](privacy.md#forks-without-personal-data)).
Policy and approvals for proposals exist since M3.

**Previews (M11)** run unapproved proposal code for anyone who reaches the
gateway, with only the `fork` scope behind them. With `[gateway]
preview_domain` they answer only at `<id>.<preview_domain>`; the domain
must not be, or be a parent of, a `[tls] domains` name (refused at start).
Make it a separate registrable domain (`example-preview.com`, not
`preview.example.com`): a subdomain of the production site shares its
site, so cookies set for `Domain=example.com` reach preview code, and
SameSite defences treat the two as one. Without a preview domain previews
answer under `/__preview/<id>/` on the production origin; there Kronik
drops the request's `Cookie`, `Authorization` and `Proxy-Authorization` headers before the
preview's code and log see them, keeps only an allowlist of response
headers (no `Set-Cookie`, HSTS, `Clear-Site-Data`, NEL/Report-To or
`Location`), and adds `Content-Security-Policy: sandbox`, so a preview
page runs in an opaque origin and cannot read or use the production
site's cookies.
Prefer a preview domain wherever previews take traffic from browsers.

## WebSocket and SSE connections

Long-lived connections ([Connections](connections.md), M24):

- **Owner-only sending.** Only the actor that accepted a connection may
  send on it or close it while it is live. Another actor's use fails its
  turn with `CONNECTION_NOT_HELD`
  ([ADR 0114](../adr/0114-only-the-accepting-actor-sends.md)). A
  connection's id is 128 random bits, so an actor cannot find another
  actor's connections by guessing ids; a frame to an id that no live
  connection has is recorded as dropped.
- **Check `Origin` in `open`.** Browsers send cookies and an `Origin`
  header with a WebSocket handshake, and the gateway does not check
  `Origin` (cross-site WebSocket hijacking). An actor that authenticates
  by cookie must check it in its open handler, as the chat example does.
  The gateway strips Kronik's own admin cookies from every upgrade, as it
  does from HTTP requests.
- **Tokens in `Sec-WebSocket-Protocol`.** Browsers cannot set
  `Authorization` on a WebSocket, so apps pass bearer tokens in this
  header. Kronik records it like `Authorization`: as a header of the open's
  request, sealed when the request has a subject (`privacy.subject_from`),
  and shown by the API only to callers with `pii:read`. An open without a
  subject, the usual browser case, is recorded in plain text, so the log,
  snapshots, backups and forks hold the token: prefer short-lived tokens,
  or set a subject for the request. The accept records only the selected
  subprotocol's position, never its value.
- **Subjects.** As for HTTP, only `[gateway] trusted_proxies` may set the
  subject of an open. An actor that learns its user from a token sets the
  connection's subject in its accept; the API shows a connection's subject
  only with `pii:read`.
- **Caps and memory.** Connections are capped in total, per actor and per
  client (the forwarded client behind a trusted proxy, an IPv6 /64), and
  their buffers per connection and node-wide (`[connections]`). A client
  that stops reading is closed as a slow consumer within `ping_timeout`.
- **`connection:send-now`** sends during a turn, before it commits, and
  needs its grant (always delivery class `unsafe`); buffered `send`,
  `broadcast` and `close` on the actor's own connections need none.
- **Closing a client.** An operator closes any open connection, such as an
  abusive client's, with `kronik connections close` (scope `operate`); the
  reason is audited.

## Root

`kronik serve --init` installs the root service of v0.1 to v0.4. Its opt-in
alternative, `kronik serve --init --rootless` (M21), uses root only for setup
and installs the nonroot `kronik` service. Its design is accepted
([ADR 0060](../adr/0060-non-root-daemon-user-namespace.md),
[ADR 0061](../adr/0061-runsc-in-the-kronik-user-namespace.md),
[ADR 0062](../adr/0062-non-root-systemd-units.md) and
[ADR 0065](../adr/0065-api-peer-identity-acceptor.md)), but the installed
proofs of [ADR 0064](../adr/0064-foreign-isolation-conformance.md) have not
been run on this revision, and the service is untested on Ubuntu 24.04:
Kronik checks `user.max_user_namespaces` and
`kernel.unprivileged_userns_clone` and does not handle that distribution's
AppArmor restriction on unprivileged user namespaces.

The daemon runs as `kronik` with the group `kronik` and the umask 0007. Its
API acceptor stays in the initial user namespace with that host uid and no
capability, so Unix peer uids remain real host identities in the audit trail
and for token attribution. Before the logger and the runtime start, the
daemon binds its ports and then empties all capability sets, including when
foreign isolation is unavailable and only Wasm actors can run.

The sandboxes need root inside a namespace, not on the host. A short-lived,
root-controlled setup (`kronik userns pin`, run by `kronik-userns.service`)
pins a user namespace owned by `kronik`, with namespace root mapped to that
user and ids 1 to 65535 to its subordinate range. At start the daemon checks
the namespace's type, owner and exact maps through one open descriptor and
enters that descriptor; namespace root is the nonzero host uid, never host
root. `runsc` and `runc` then run as namespace root inside it. The brief's M21
says "`runsc` runs in rootless mode where the kernel allows it"; Kronik does
not use `runsc --rootless`, whose limits ADR 0061 describes. The maintainers
ratified that deviation from the brief's wording on 2026-11-13. A missing pin
or delegation gives typed foreign unavailability (`FOREIGN_UNAVAILABLE` with
the reason), never an automatic trusted runtime or a root fallback. The pinned
namespace denies `setgroups(2)`: namespace root could otherwise drop the
supplementary groups the unit runs with (`kvm`, the service user's groups) and
so reach a file whose mode denies one of those groups, such as `0604
root:kvm`. Every namespace made inside it inherits the denial.

`serve --init` (or `serve --init --root`) installs the separate root service,
which keeps the hardening decisions of
[ADR 0027](../adr/0027-systemd-unit-hardening.md). Both
modes keep strict host file system protection, no-new-privileges and private
runtime storage. `RestrictSUIDSGID` stays out because M14's `runsc restore`
needs `openat2`.

Image unpacking clears setuid and setgid bits, as do gVisor directory
checkpoints and copies. A sandbox can still set them in its own persistent
directory: in the nonroot installation namespace-root ownership maps to the
service uid, and a root installation can leave root-owned files. Keep those
private trees private and never copy their modes into a public or executable
location. A microVM's guest inode modes stay inside its opaque drive; they
are not host setid files.

A microVM's VMM (M20, experimental) that escaped its guest can change three
files of the host's data file system and nothing else there: its data drive
and the two files of a snapshot, which the daemon makes before the VMM starts.
Its output directory is read-only, so it creates, renames and removes nothing
in it. Each file it writes is limited to the larger of the data drive (1 GiB)
and the VM's memory (`RLIMIT_FSIZE`; a write past it ends the VMM), and a data
drive that grew past its size is refused at the next start or checkpoint.
`/dev/kvm` is bound read-only: the VMM opens and uses the device, but on a root
installation, where the VMM is uid 0 and owns the device node, it cannot
change the node's mode, owner or ACLs. Its jail directory is under
`[foreign] run_dir`, by default on the `/run` tmpfs, where what it writes
counts against the VM's memory limit: keep `run_dir` there, as on a disk it
would not be bounded. Its disk I/O bandwidth is not limited
([ADR 0095](../adr/0095-pinned-firecracker-guest.md)).

A command that root runs against a nonroot installation (`sudo kronik ...`,
`sudo kronik doctor`, the readiness check of `serve --init`) does not connect
to the API socket by path: `/run/kronik` belongs to the service user, who could
put a link to another of the host's sockets, a FIFO or a listener of its own in
place of the daemon's socket, and root would connect with its own authority
and send its token. Root reaches the socket's directory from `/` through
directories that root controls and links that root made only, opens the socket
without following a link, requires a socket that the directory's owner made,
connects to exactly that inode and requires the same owner at the other end
(`SO_PEERCRED`); anything else is refused with the reason. The service user can
still answer root's requests, as the daemon does; it cannot redirect them. A
socket in a directory that only root controls (the root service's) is used as
before.

`sudo kronik restore` into a nonroot installation works in two phases: as root
it reads the key source and checks the newest keystore backup, then it gives up
root and reads the rest of the bucket as the data directory's owner. A
`file://` bucket may belong to the service user (the daemon ships to
`/var/lib/kronik-ship`), so in the root phase it is read by descriptor: reached
from `/` without following a link and through directories that only root
controls, never created, and below it only real directories on its file system
and regular files with one link. A link to a file that only root may read, a
FIFO that would hang the restore, or a linked directory in the bucket fails
the restore instead.

`/run/kronik` is mode 0750 with group `kronik`: whoever may use the API socket
can list it. The runtime state of the sandboxes beneath it (`runsc/`, `runc/`)
is mode 0700, because a runtime's state file holds the container's
environment, resolved secret values included. Only the service user and host
root can read it, not every member of the API group.

The nonroot service is `kronik serve --rootless` (M21,
[ADR 0060](../adr/0060-non-root-daemon-user-namespace.md)); the unit that
`serve --init --rootless` writes passes the flag. The daemon needs write access to the
data directory and to the socket's directory (by default `/var/lib/kronik` and
`/run/kronik`). While it still has one thread it takes the data directory's
lock and binds its listeners, then empties all its capability sets and sets
`no_new_privs`, moves into a `daemon` leaf of its cgroup when that cgroup is
delegated to it, and starts a small acceptor process that stays in the initial
user namespace without any capability and hands each API connection over
together with its caller's host uid, so the audit trail and token attribution
keep real uids. Last it enters the pinned Kronik user namespace if one exists.
Foreign actors need both the namespace and the delegated cgroup. Without them
it still serves Wasm actors, and foreign actors answer `FOREIGN_UNAVAILABLE`
with the reason; it never falls back to a weaker backend or to unbounded
resources. `kronik userns
status` shows the namespace.

`--rootless` fails closed. It stops with `ROOTLESS_UNAVAILABLE`, before it
creates or binds anything, where it cannot keep the promise above: as root;
when the real, effective and saved user ids are not one and the same; and in a
user namespace whose uid map is not the host's identity map, such as a
rootless container or a nested user namespace. There the kernel would
translate every API caller's uid, and the audit trail and token attribution
would name the wrong users. Rootless containers and nested user namespaces are
not supported for the nonroot unit: use the root service (`serve --init
--root`). `kronik doctor --rootless` reports the same condition as `uid_view`
before the service is started.

Plain `kronik serve`, without `--rootless`, starts as it did before M21, as
root or as an ordinary user: it takes no early lock, forks no acceptor, empties
no capability set, does not set `no_new_privs` and does not enter a namespace.
