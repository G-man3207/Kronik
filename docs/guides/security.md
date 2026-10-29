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
| Theft of the data directory | Privacy mode with sealed values; without it the log is plaintext, so use an encrypted disk | Privacy mode arrives with M8; until then the log is plaintext |
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
  its value. Without a grant the guest gets `denied` and the denied effect
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

- **Storage.** `kronik serve` loads the master key from
  `<data>/keys/master.key` (`--master-key-file`), or creates it on first
  start: 32 random bytes in hex, mode 0600. The values live in
  `<data>/keys/secrets.db`, sealed with XChaCha20-Poly1305 under a key
  derived from the master key, one row per version. Without the master key
  the stored values cannot be decrypted, so back the key up apart from the
  data directory.
- **Handles.** Guest code names a secret in an HTTP header template such as
  `Bearer {}` (with standard `fetch`, M22, the header value `Bearer
  {{secret:NAME}}`) or in a `crypto` call, and the host inserts the value at
  the effect boundary or computes with it. The value never enters guest memory,
  and the log records only the secret's name and a keyed hash of its
  version, which reveals nothing even about short values.
- **Operations.** `kronik secret set` reads the value from stdin, never
  from the command line, and does not echo it on a terminal;
  `kronik secret list` shows names, versions and version hashes but never
  values; `kronik secret delete` marks every version deleted. Every
  operation needs a reason.
- **Reveal.** `secrets.reveal` returns a raw value only with the capability
  `secret-reveal:<name>`. In a fork it returns the placeholder
  `[secret:<name>]`, never the value. `crypto.*` in a fork, when no
  recording matches, is still computed on the host with the production key
  (brief): the key stays on the host, but code deployed into a fork (scope
  `fork`) can obtain HMACs and signatures under production keys over data it
  chooses, which is as good as the key for webhooks and tokens signed with
  it. Grant `fork` only to callers you would trust with that. A preview
  (M11) answers whoever has its URL, so it gets no production key at all:
  its `crypto.*` calls answer `no recording`.
- **Scrubbing.** When a turn used or revealed a secret, exact occurrences of
  the value are replaced by `[secret:<name>]` in the turn's state writes,
  SQL text values, messages, timers, compensations, output, effect
  requests and responses (each `EffectResult` before it is appended) and
  log events before anything is written, so the value reaches neither the
  log nor a state file. Fork turns are scrubbed the same way. Responses from HTTP targets are scrubbed of the inserted
  values before the guest sees them, and the API's views of actors,
  history, turns and dead letters replace the values of all live secrets.

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
  `-shm` files) mode 0600. The API socket has mode 0660. Other files get
  the process's default permissions; the directory's mode keeps them
  private. The systemd unit that `kronik serve --init` installs creates the
  data directory with mode 0700 too.

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
  on a connection; an informational status (1xx) is answered with
  `TURN_FAILED`. A failure inside Kronik is answered with a generic
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

## Root

In v0.1 the daemon and `runsc` run as root under systemd, with the
hardening that systemd allows. `kronik serve --init` (M6) installs the unit
`deploy/systemd/kronik.service`: it runs the daemon as root with the group
`kronik` and the umask 0007, keeps the data directory `/var/lib/kronik` at
mode 0700 and the socket directory `/run/kronik` at mode 0750, and sets
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`,
`ProtectClock`, `ProtectKernelModules`, `ProtectKernelLogs`,
`RestrictRealtime`, `LockPersonality` and `SystemCallArchitectures=native`.
[ADR 0027](../adr/0027-systemd-unit-hardening.md) gives the evidence for
each setting.

The unit names no `User=` on purpose: root is the default, and with an
explicit `User=` systemd drops `CAP_SETUID` from the daemon, which `runsc`
needs to start a sandbox (`kronik doctor`'s `caps` check finds this).
It also leaves out `RestrictSUIDSGID`, which makes `openat2` fail, and
`runsc restore` needs it for the sandbox copies forks talk to (M14). Image
unpacking clears setuid and setgid bits, so no setid file comes from an
image, and checkpoints and copies of an actor's data clear them too. The
risk that remains: a program in a sandbox that runs as root can set them
on files in its own `/data`, which leaves root-owned setid files in the
data directory. Only root can reach them there (mode 0700 parents), and
executing one inside the service gains nothing under `NoNewPrivileges`.

`/run/kronik` is mode 0750 with group `kronik`: whoever may use the API
socket can list it. The runtime state of the sandboxes beneath it
(`runsc/`, `runc/`) is mode 0700, because a runtime's state file holds the
container's environment, resolved secret values included. Only root can
read it.

Rootless operation comes after v0.1, with M21. Started by hand,
`kronik serve` runs as the user that starts it, and
that user needs write access to the data directory and to the socket's
directory (by default `/var/lib/kronik` and `/run/kronik`).
