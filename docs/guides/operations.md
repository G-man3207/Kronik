# Operating Kronik

This guide is for whoever runs `kronik serve` on a server: a single Linux
host, normally a small VPS. It covers the first start, every setting in
`kronik.toml`, the systemd unit, TLS, `kronik doctor`, metrics and logs, the
master key, foreign actors, and what to do about each error. Installing the
binary is in [Installing Kronik](install.md). The commands are in the
[CLI reference](../reference/cli.md), and the trust boundaries are in the
[security model](security.md).

Kronik is one process. It keeps its state in one data directory
(`/var/lib/kronik` by default), answers clients on a Unix socket, serves
HTTP to the world through the gateway, and serves `/metrics` and `/healthz`
on a local admin port.

## The first start

As root, on a host with systemd:

```sh
kronik serve --init --dry-run                                  # print the plan, change nothing
kronik serve --init --domain api.example.com --acme-email ops@example.com
kronik doctor
```

`kronik serve --init` sets up a host in six steps:

1. It writes `/etc/kronik/kronik.toml` (mode 0644). With `--domain` (which
   can be repeated) the gateway listens on `0.0.0.0:443` with a certificate
   from Let's Encrypt. Without it, the gateway listens on `0.0.0.0:80`
   without TLS.
2. It creates the data directory `/var/lib/kronik` (mode 0700).
3. It creates or loads the master key through `[keys] source`. The default
   is `/etc/kronik/master.key` (mode 0600); a KMS source stores only a
   wrapped key. See [the master key](#the-master-key).
4. It creates the system group `kronik`.
5. It installs `/etc/systemd/system/kronik.service`, whose `ExecStart`
   points at the binary you ran.
6. It runs `systemctl daemon-reload` and `systemctl enable --now
   kronik.service`.

Every step checks before it acts, so running `--init` again changes nothing
that is already in place, and it never overwrites an existing config file
or key. Edit `/etc/kronik/kronik.toml` afterwards and run `systemctl restart
kronik`.

Clients (`kronik deploy`, `kronik actors`, `kronik mcp` and the rest) talk to
the daemon over `/run/kronik/api.sock`. The socket's mode is 0660 for group
`kronik`, so to let a user run them:

```sh
usermod -aG kronik alice        # takes effect at alice's next login
```

## kronik.toml

`kronik serve` reads `/etc/kronik/kronik.toml`, or the file named by
`--config` or `KRONIK_CONFIG`. Without a file it uses the defaults below.
Flags (and their environment variables) override the file, and the file
overrides the defaults. An unknown key or a bad value stops the start with
the file, the line and the reason, for example `kronik.toml:3: unknown field
"http_lisen"`. `kronik doctor` checks the file the same way.

Durations are written like `"30s"`, `"5m"`, `"24h"` or `"7d"` (also `ms`).
Sizes are written like `"512MiB"` or `"1GiB"` (`B`, `KiB`, `MiB`, `GiB`,
`TiB`), and percentages like `"10%"`.

The file holds only the server's basics. Grants, limits, policy, privacy
mode and foreign actors are part of the recorded history and are set with
the CLI or the API, not here.

Every key in the tables below is applied. A file written for a later
release still parses; unknown keys are errors.

### [server]

| Key | Default | Meaning | Flag |
|---|---|---|---|
| `data_dir` | `"/var/lib/kronik"` | The data directory: the log, the materialized state, actor databases, code, keys and the ACME cache | `--data-dir`, `KRONIK_DATA_DIR` |
| `api_socket` | `"/run/kronik/api.sock"` | The Unix socket of the JSON API, for the CLI and `kronik mcp` | `--api-socket`, `KRONIK_API_SOCKET` |
| `http_listen` | `"0.0.0.0:443"` with TLS, `"127.0.0.1:8080"` without | The gateway's address | `--http-listen`, `KRONIK_HTTP_LISTEN` |
| `admin_listen` | `"127.0.0.1:9464"` | With TLS: embedded `/ui/`, same-origin public `/v1`, `/metrics` and `/healthz`, using the gateway certificate. Plain loopback HTTP serves only metrics/health. A bind failure is fatal when OIDC is configured; otherwise the daemon warns and runs without this listener | `--admin-listen`, `KRONIK_ADMIN_LISTEN` |
| `api_listen` | none (off) | The JSON API and MCP over TCP, where every request needs a bearer token (`kronik token`). Without TLS only a loopback address is accepted, so tokens never cross a network in the clear; with TLS the API uses the gateway's certificate. A remote CLI (CI, the [GitHub Action](github-action.md)) reaches it with `--url https://<name>:<port>` or `KRONIK_URL`, and `KRONIK_TOKEN` | `--api-listen`, `KRONIK_API_LISTEN` |

### [tls]

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"off"` | `"off"`, `"files"` or `"acme"`; see [TLS](#tls) |
| `domains` | `[]` | The names to get a certificate for (`acme`) |
| `acme_email` | none | The ACME account's contact address (`acme`) |
| `acme_directory` | Let's Encrypt's production directory | The ACME server's directory URL, for example Let's Encrypt's staging directory while testing |
| `acme_ca_file` | none | A PEM CA certificate to trust for the ACME server, besides the system's roots (a private ACME server) |
| `cert_file` | none | The certificate chain, PEM (`files`) |
| `key_file` | none | The private key, PEM (`files`) |
| `dns01_hook` | none | The executable that publishes DNS-01 TXT records for the `*.<preview_domain>` certificate (`acme`); see [Preview forks: a wildcard certificate by DNS-01](#preview-forks-a-wildcard-certificate-by-dns-01) |
| `dns01_propagation` | `"60s"` | How long to wait after the hook publishes a record before the CA checks it |

`acme` needs `domains` and `acme_email`, and `files` needs `cert_file` and
`key_file`. `dns01_hook` needs `acme` and `[gateway] preview_domain`.

### [oidc] and the embedded UI

Open `/ui/` on the TLS `server.admin_listen`, never on the application gateway.
There is no frontend build/install or additional UI service. The embedded app
uses the same published API, scopes, PII projection and policy as CLI and MCP.
It shows actor history, turn details/causal trees, proposal response, effect and
state differences, grounding per target, approvals, dead letters, deployments
and cluster observations. A native node reports `member: false`; an installed
member status producer's error is never replaced with a healthy native result.

Register an OIDC **public authorization-code + S256 PKCE client**, with one
exact redirect URI. The admin certificate must cover its hostname. Provision
an ordinary scoped token, then map the provider's stable subject, not an email
or display name, to that token name:

```sh
kronik token create --name ui-reviewer --scopes read,approve,promote \
  --reason "Allow the explicitly bound reviewer to inspect and approve changes"
```

The raw token is not put in the browser or OIDC configuration:

```toml
[oidc]
issuer = "https://login.example.com"
client_id = "kronik-ui"
redirect_uri = "https://admin.example.com:9464/v1/auth/callback"
# ca_file = "/etc/kronik/issuer-ca.pem"  # Optional private CA for this provider only.

[[oidc.bindings]]
subject = "the-provider-assigned-stable-subject"
token = "ui-reviewer"
```

No binding, missing token or revoked token means no access. Provider `scope`,
email, groups and roles grant nothing. Sessions use the mapped token's live
scopes; revoking that token revokes its sessions. Add `pii:read` only when
required; neither UI nor OIDC grants it implicitly. Without an installed
active Fleet authority, managed Fleet credentials remain denied.

Issuer authority and bindings require ordinary durable configuration admission.
Typed `AuthConfig` stores protected principal hashes, not raw subjects or
serialized private configuration. Startup reads its durable admission and
never replaces it merely because a file changed. Ordinary admin-scoped
`GET /v1/auth/config` and `PUT /v1/auth/config` inspect/admit it. PUT accepts
`{"config":{...the private OIDC profile...},"reason":"...","dry_run":true}`;
`config: null` disables OIDC. Dry-run does not contact the provider or publish
an epoch change. A real change preflights under the original administrator,
then uses the sole typed publisher and actual committed source. Member
publication requires its real metadata authority and barrier.

An unreachable provider, wrong exclusive CA or valid startup-profile mismatch
leaves OIDC inactive with a sanitized status reason and login 503. Ordinary
bearer and verified Unix administration remain available to admit a corrected
profile through the same PUT; an explicit unchanged-profile PUT can reinitialize
a recovered provider. There is no repair endpoint, anonymous fallback or
automatic file-based replacement. Pending callbacks and sessions retain their
original source/epoch and cannot upgrade to a new one. Corrupt durable
authority, missing required master keys and invalid global configuration remain
fatal as appropriate.

Discovery must return the exact configured issuer and HTTPS authorization,
token and JWKS URLs on its authority. Redirects and token-directed key URLs
are not followed. The public-client profile requires RS256, S256 PKCE and nonce.
Another endpoint authority is rejected instead of silently widening trust.

Cookies are host-only, Secure, HttpOnly and SameSite=Lax. Login state is
single-use and browser-bound. Sessions expire by the verified ID token or one
hour and disappear on restart/logout. Cookie-authenticated writes require
exact Origin and `X-Kronik-CSRF` from `GET /v1/auth/session`; the UI sends both.
Do not copy raw tokens or authorization codes into logs; proxies must not log
the callback query. Responses are no-store/no-referrer. Logout clears the UI.

Cookies are scoped to a hostname, **not a port**. Use a dedicated trusted admin
hostname; do not share it with untrusted services on another port. Gateway
ingress removes `__Host-kronik-session` and `__Host-kronik-login` before guest
input/WAL, and response delivery filters guest attempts to set these names.
Ordinary application cookies and Authorization remain intact. This does not
isolate unrelated processes sharing the admin hostname.

Ordinary OIDC caller/approval IDs are opaque `oidc:<protected binding HMAC hex>`,
never Base64 issuer/subject. An approval additionally stores the exact original
verified pair in optional `Approval.verified_identity` field 7, authenticated
and encrypted under that principal's existing subject key even with Actor
privacy off. Only `pii:read` reveals the stored historical pair; no-read responses
omit it, erased keys produce `ERASED`, and unknown/unreadable keys fail closed.
A current session is not historical proof. Native approvals keep this field absent.

Bearer tokens keep working. The optional password field holds a bearer only in
memory and sends Authorization without cookies; clearing it does not revoke it.
No credential is stored in localStorage, sessionStorage or offline caches.
Mutations retain reason/dry-run, proposal hashes, catch-up and required approvals.

`scripts/e2e-ui-oidc.py` runs the finite owned TLS/code/JWT fixture. Its browser
observes actual network operations against generated OpenAPI, axe-core WCAG 2.2 AA
and keyboard/focus semantics. Run it only in its documented OS-enforced sandbox.
Dummy subjects and automated clicks are not real-human review, public M10 flow
or healthy-cluster acceptance. See ADRs [0103](../adr/0103-oidc-principals-and-browser-sessions.md)
and [0104](../adr/0104-admin-ui-as-a-public-api-client.md).

### [gateway]

| Key | Default | Meaning | Flag |
|---|---|---|---|
| `timeout` | `"30s"` | After this, the client gets `504 GATEWAY_TIMEOUT` while the turn still completes | `--gateway-timeout-ms` |
| `idempotency_header` | `"Idempotency-Key"` | The header the gateway reads as the idempotency key, compared without regard to case. An empty name is `BAD_REQUEST` at start | |
| `idempotency_ttl` | `"24h"` | How long the gateway keeps a response for retries with the same `Idempotency-Key` | |
| `trusted_proxies` | `[]` | Reverse proxies, as addresses or CIDR blocks (`["127.0.0.1", "10.0.0.0/8"]`). One client address may hold a quarter of the gateway's connections; a trusted proxy, which carries many users' traffic, may hold all of them. A connection over its client's share gets `503 UNAVAILABLE` with `connection: close`. When set, only these peers may set the request's subject (`privacy.subject_from`): a subject header or `jwt:` claim from any other peer gets `400 BAD_REQUEST`; IPv4-mapped entries (`::ffff:10.0.0.0/104`) mean their IPv4 block | |
| `preview_domain` | none | The domain whose subdomains serve preview forks (`<id>.<domain>`), best a separate registrable domain; see [previews](#previews). With it, previews answer only there, not under `/__preview/`. With `[tls] mode = "acme"` it needs `dns01_hook` (the `*.<domain>` certificate); with `mode = "files"` the certificate must cover `*.<domain>`. It must not be, or be a parent of, a `[tls] domains` name. Lowercase, without scheme or port | |

### [log]

| Key | Default | Meaning |
|---|---|---|
| `group_commit_ms` | `2` | How long the log writer gathers records into one fsync |
| `segment_max_mb` | `64` | The size at which a log segment is closed |
| `segment_max_age_s` | `60` | The age at which a log segment is closed |
| `disk_reserve` | `"512MiB"` | Below this much free space on the data directory's file system, new inputs, deployments, grants, `foreign add`, forks, proposals, approval requests and replays are refused with `UNAVAILABLE`, so new work does not drive the disk full. `foreign add` also refuses an image whose new layers would not fit above the reserve, before it fetches them. Turns already running finish, and timers, queued messages, foreign actors and the catch-up of a promote keep writing, so on a shared file system a log write can still fail: give `<data_dir>/foreign` its own file system. Idempotent retries still get their saved response; rollback, promote, approvals, `foreign remove`, revoke, `limits set` and erasure still work. No snapshot is taken (`kronik snapshot create` fails with `UNAVAILABLE`), but retention still deletes old segments, snapshots beyond `snapshots_kept` and partial copies. `/v1/health` and `/healthz` add `"low_disk": true`, and `kronik_disk_below_reserve` is 1. `"0B"` turns it off; `--disk-reserve` (`KRONIK_DISK_RESERVE`) overrides it |

### [retention]

| Key | Default | Meaning |
|---|---|---|
| `history` | `"7d"` | How far back the log reaches: closed segments older than this are deleted once a kept snapshot covers them. See [snapshots and retention](#snapshots-and-retention) |
| `snapshot_interval` | `"60m"` | How often a snapshot is taken, when something changed since the last one |
| `snapshots_kept` | `48` | How many snapshots are kept |

### [sql]

| Key | Default | Meaning |
|---|---|---|
| `max_size_per_actor` | `"1GiB"` | The SQL size limit for a kind that has no `sql_bytes_per_actor` in a `Limits` record. `kronik limits set --sql-size` still wins for that kind |

### [ship]

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Ship the log, snapshots and code to object storage; see [shipping](#shipping-to-object-storage) |
| `url` | none | `"s3://bucket/prefix"`, or `"file:///dir"` for a directory on this machine (a demo, not a backup); `enabled = true` requires it |
| `endpoint` | none | An S3-compatible server instead of AWS, such as `"http://127.0.0.1:9000"` for MinIO |

### [keys]

| Key | Default | Meaning | Flag |
|---|---|---|---|
| `master_key_file` | `<data_dir>/keys/master.key` (`--init` writes `/etc/kronik/master.key`) | The file source's 64 hex characters. Conflicts with `KRONIK_MASTER_KEY` and with KMS sources | `--master-key-file`, `KRONIK_MASTER_KEY_FILE` |
| `source` | `"file"` | `"file"`, `"env"`, `"openbao"`, `"aws"`, `"gcp"` or `"azure"`; see [the master key](#the-master-key) | |
| `wrapped_file` | `"keys/master.wrapped"` | KMS ciphertext, relative to `data_dir`; absolute paths, `.` and `..` are refused | |
| `start_timeout` | `"60s"` | Total retry/timeout budget for one high-level KMS load, wrap or rewrap, including encrypt and verification decrypt; a positive duration in `ms`, `s` or `m` | |

### [secrets]

| Key | Default | Meaning |
|---|---|---|
| `refresh` | `"5m"` | About how often the node reads every secret's current version from its source and rebuilds the inventory of secret values that the views remove from what they show; a value read from a backend is also used for this long without another request. **Keep `refresh` well above the `elapsed_ms` of the `secret inventory certified` log line:** a rebuild that takes longer than `refresh` never installs its certificate, and the reads that remove secret values answer 503 `SECRET_UNAVAILABLE` for as long as that holds. The daemon logs a warning, `the catalogue the secret inventory was built from is older than [secrets] refresh`, when that is the cause |
| `max_stale` | `"24h"` | How long a value that was authorized stays in use while its backend is unavailable (a timeout or a 5xx answer). A definitive refusal, a missing version or a binding that no longer matches ends its use at once |
| `fetch_timeout` | `"2s"` | The longest a request to a backend, or a secret change waiting for the inventory to be published again, takes; at most `"60s"`. When the wait for the inventory runs out, `kronik secret set`, `delete`, `link`, `unlink` and `refresh` answer 503 `SECRET_UNAVAILABLE` saying that the change is already committed: it is made, so do not repeat it. A mutation that begins while the inventory is being rebuilt waits for it for this long plus 5 s before its reason is recorded |

External backends are defined in `[secrets.backends.<id>]` tables; see the
[M23 design](../design/m23-secret-backends.md).

### [privacy]

| Key | Default | Meaning |
|---|---|---|
| `subject_from` | none | Where HTTP root inputs get their subject: `"header:<name>"` or `"jwt:<claim>"` (normally `"jwt:sub"`). **The JWT's signature is not verified**; the claim is only read. See [Privacy mode](privacy.md) |
| `keystore_backup_retention` | `"30d"` | How long shipped keystore backups of an erasure are kept. `kronik serve` applies the file's value |

### [replay]

| Key | Default | Meaning |
|---|---|---|
| `default_mode` | `"both"` | Replay mode when `kronik propose` or `kronik replay` omits `--mode`: `isolated`, `continuous` or `both`. An explicit `--mode` wins |
| `sample` | `"100%"` | Isolated-replay sample when those commands omit `--sample`. An explicit `--sample` wins |

### [fork]

| Key | Default | Meaning |
|---|---|---|
| `live_allowlist` | `[]` | Hosts that forks may call live: an effect with no recording that is a `GET` without secret headers to a listed host goes out for real. Anything else never leaves a fork |
| `preview_ttl` | `"24h"` | How long a preview fork lives unless `kronik preview create --ttl` says otherwise; see [previews](#previews) |

### [simulators.model]

The model simulator (M12, [ADR 0015](../adr/0015-model-simulator.md)): off
when the table is absent, and even then it answers only for targets whose
`kronik stubs set` file has `model = true`. It never sees personal data: a
turn that touched a subject's data fails closed instead. Answers are cached
per proposal (`branches/<id>/simulator-cache.json`), so a proposal's diff
stays the same when it is replayed again.

| Key | Default | Meaning |
|---|---|---|
| `endpoint` | required | An OpenAI-compatible chat completions URL, e.g. `"http://127.0.0.1:11434/v1/chat/completions"` |
| `model` | required | The model name sent with each request |
| `api_key_env` | none | The environment variable holding the API key (sent as a bearer token); the key never appears in the file or the log. `kronik serve` refuses to start when the variable is unset |
| `timeout` | `"20s"` | How long one call may take; a timeout is a refusal (the effect fails closed) |
| `max_examples` | `5` | Recorded exchanges with the target (without personal data or secrets) sent as examples |
| `examples_under_privacy` | `false` | Send recorded examples even while privacy mode is or was on in the replayed window. Off: no examples then, because a turn's state reads are not recorded and it may have copied personal data into an untagged request |

### [promote]

| Key | Default | Meaning |
|---|---|---|
| `max_gap` | `"2s"` | Promotion first lets the fork's continuous replay catch up with production until it is at most this far behind, in logical time |
| `catch_up_timeout` | `"300s"` | If it hasn't caught up by then, promotion fails with `PROPOSAL_STALE` |

### [rebase]

| Key | Default | Meaning |
|---|---|---|
| `max_pause` | `"2s"` | `kronik rollback --by-replay` ([M13](../design/m13-rebase.md)): the longest the switch holds new requests, messages and timers while it waits for running turns and replays the last root inputs. If that does not fit, nothing is switched and promote fails with `PROPOSAL_STALE` (run it again). The last round reloads the index of the whole window, so long windows may need more |

### [foreign]

| Key | Default | Meaning |
|---|---|---|
| `runsc_path` | `"/usr/local/bin/runsc"` | gVisor's `runsc` |
| `platform` | `"auto"` | `"auto"`, `"systrap"` or `"kvm"`: gVisor's platform. `auto` is systrap; `kvm` needs a `/dev/kvm` the daemon can open |
| `run_dir` | `"/run/kronik"` | Runtime state of the sandboxes: runsc's root, network namespaces and bridge sockets. Best on a tmpfs; nothing in it survives a reboot. One daemon per directory: a second daemon runs without foreign actors |
| `layout_dirs` | `[]` | Absolute directories whose `oci-layout:` images an `operate` token may add; any other directory needs `admin` |
| `pull_timeout` | `"10m"` | How long an image pull or layout import may take |
| `checkpoints_kept` | `3` | Checkpoints kept per `fork_mode = "sandbox"` actor ([M14](../design/m14-foreign-forks.md)); one is taken with every snapshot, and a fork's copy starts from the newest at or before its fork point |

### [otel]

| Key | Default | Meaning | Flag |
|---|---|---|---|
| `endpoint` | none (off) | An OTLP/HTTP collector, `"http://127.0.0.1:4318"` or `"https://…"`; spans and metrics go to `<endpoint>/v1/traces` and `/v1/metrics`. See [OpenTelemetry](#opentelemetry) | `--otel-endpoint`, `KRONIK_OTEL_ENDPOINT` |
| `traces` | `true` | Export a span per committed turn and its effects | |
| `metrics` | `true` | Push the metrics of `/metrics` | |
| `service_name` | `"kronik"` | The `service.name` backends group by | |
| `actor_keys` | `"hashed"` | How actor keys leave the node: `"hashed"` (`kh:` + 12 hex of a keyed hash), `"plain"` or `"none"` | |
| `interval` | `"5s"` | A batch smaller than `batch_spans` waits this long for more | |
| `metrics_interval` | `"60s"` | How often metrics are pushed | |
| `batch_spans` | `512` | At most this many log records per request (and at most 4 MiB of them; a larger record goes alone) | |
| `headers_env` | none | The environment variable holding extra headers, `key=value,…` (as `OTEL_EXPORTER_OTLP_HEADERS`); with it, `http://` is refused unless the host is loopback | |

### [audit]

| Key | Default | Meaning | Flag |
|---|---|---|---|
| `sink` | none (off) | Where the audit lines go: `"file:///var/log/kronik/audit/"`, `"https://…"` (a webhook; `http://` only to loopback) or `"s3://bucket/prefix"`. See [the audit log](#the-audit-log) | `KRONIK_AUDIT_SINK` |
| `endpoint` | none | An S3-compatible server, as `[ship] endpoint`; `s3://` only | |
| `batch_records` | `500` | At most this many log records per delivery (and at most 4 MiB of them; a larger record goes alone) | |
| `interval` | `"1s"` | A smaller batch waits this long for more | |
| `file_max_bytes` | `"64MiB"` | A directory sink starts a new file at this size | |
| `headers_env` | none | The environment variable holding a webhook's extra headers, `key=value,…` | |
| `from` | `"start"` | Where a first export starts: `"start"` (the first retained record) or `"now"` | |
| `max_hold` | `"0s"` | Retention ignores the audit hold once it is older (`"0s"`: no cap) | |
| `hold_release` | `"2x"` | Retention ignores the hold below this much free disk: a multiple of `[log] disk_reserve`, or a size. With a sink it must be above `disk_reserve` unless `max_hold` is set (so `disk_reserve = "0B"` needs a size here) | |

### Other settings of kronik serve

| Flag | Default | Meaning |
|---|---|---|
| `--concurrency` | `64` | Turns that run at the same time |
| `--log-format` (`KRONIK_LOG_FORMAT`) | `text` | `text` or `json`; see [logs](#logs) |
| `KRONIK_LOG` | `info` | The log filter: a level, or per target like `info,kronik::guest=debug` |
| `--disk-reserve` (`KRONIK_DISK_RESERVE`) | `[log] disk_reserve` | Overrides `[log] disk_reserve`, e.g. `0B` for a test machine with little free space |

### Memory

One daemon has one Wasm instance pool, sized by `--concurrency`: room for
`2 × concurrency` linear memories. Forks, replays and promote catch-up run
on the same pool; `kronik upgrade check` is its own process with a pool of
`2 × workers` memories. After an instance ends, its memory slot keeps up to
2 MiB resident (zeroed), so the next instance does not fault those pages
back in. That bounds what the pool holds on top of running instances:

| `--concurrency` | Memory slots | Kept resident, worst case |
|---|---|---|
| 64 (default) | 128 | 256 MiB |
| 128 | 256 | 512 MiB |

A slot keeps only what its instances used, so a small Rust guest (about
1 MiB of linear memory) holds little; large guests such as TypeScript ones
reach the 2 MiB per slot. Measured on a 2 vCPU, 4 GB VPS after 30 s of 256
clients on 256 actors (`docs/perf.md`): the daemon used 66 MiB with the Rust
counter and 563 MiB with the TypeScript counter, which needs about 330 MiB
for its compiled code alone. On a 4 GB machine the default leaves room;
raise `--concurrency` only with the worst case above in mind.

## systemd

`kronik serve --init` installs this unit (`deploy/systemd/kronik.service` in
the source):

- `ExecStart=<binary> serve --config /etc/kronik/kronik.toml`,
  `Restart=on-failure` after 2 s, `LimitNOFILE=65536`, and `LimitCORE=0`:
  no core dumps, since the process holds the master key, secrets and
  unsealed subject data. `kronik serve` also marks itself non-dumpable
  (`PR_SET_DUMPABLE` 0), which keeps it from dumping core and from being
  traced by other users outside systemd too.
- `Group=kronik`, `UMask=0007`, and no `User=`: v0.1 runs the daemon as
  root, the default, because gVisor needs it for foreign actors (rootless
  is a later milestone; see the security model). The group owns the API
  socket. The unit leaves out an explicit `User=root` on purpose: together
  with the seccomp-based settings below, systemd then drops `CAP_SETUID`
  from the daemon, `NoNewPrivileges` keeps `runsc` from getting it back,
  and no sandbox starts ([ADR 0027](../adr/0027-systemd-unit-hardening.md)).
- `RuntimeDirectory=kronik` (`/run/kronik`, mode 0750 with group `kronik`,
  kept across restarts) holds the socket and the sandboxes' runtime state.
  The daemon keeps the runtimes' state directories in it (`runsc/`,
  `runc/`) at mode 0700: their state files hold resolved secret values.
  `ExecStopPost=` runs `kronik foreign cleanup`, so sandboxes and their
  `config.json` (secret values) are removed even when the daemon was
  killed.
  `StateDirectory=kronik` (`/var/lib/kronik`, mode 0700) is the data
  directory. `LogsDirectory=kronik` (`/var/log/kronik`, mode 0750) makes
  the default audit sink, `file:///var/log/kronik/audit/`, writable.
- Hardening: `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `NoNewPrivileges`, `ProtectClock`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `RestrictRealtime`, `LockPersonality`,
  `SystemCallArchitectures=native`.
- Left out on purpose: `MemoryDenyWriteExecute`, because Wasmtime compiles
  code at run time; `ProtectHostname`, `ProtectKernelTunables`,
  `ProtectControlGroups` and a `CapabilityBoundingSet`, because `runsc`
  creates namespaces and cgroups for foreign actors; and
  `RestrictSUIDSGID`, because it also makes `openat2` fail, which
  `runsc restore` needs for sandbox copies in forks
  ([ADR 0027](../adr/0027-systemd-unit-hardening.md)).

`ProtectSystem=strict` makes the whole file system read-only for the daemon
except its runtime and state directories. If `server.data_dir` is somewhere
else, add that directory to the unit with `ReadWritePaths=` (in a drop-in:
`systemctl edit kronik`).

Day-to-day:

```sh
systemctl status kronik
journalctl -u kronik -f                     # the daemon's log
systemctl restart kronik                    # after editing kronik.toml
systemd-analyze security kronik.service     # what the sandboxing covers
```

## TLS

The gateway serves HTTPS in two ways, or plain HTTP when `mode = "off"`.

**`mode = "files"`** loads `cert_file` and `key_file` at start: a missing or
bad file stops the start. It reloads them every 12 hours, so a renewal by
another tool (certbot, say) is picked up without a restart.

**`mode = "acme"`** gets and renews a certificate by itself, with the
TLS-ALPN-01 challenge on the gateway's own port (no port 80 needed; see
[ADR 0009](../adr/0009-acme-instant-acme.md)). A real domain needs:

- a DNS `A` (and `AAAA`, if the host has IPv6) record for every name in
  `domains`, pointing at this host;
- the gateway listening on port 443 (`http_listen = "0.0.0.0:443"`) and
  reachable from the internet: open the firewall and the provider's
  security group;
- `acme_email`, and a correct clock (`kronik doctor` checks NTP).

Try it first against Let's Encrypt's staging directory, whose rate limits
are generous. Its certificates are not trusted by browsers:

```toml
[tls]
mode = "acme"
domains = ["api.example.com"]
acme_email = "ops@example.com"
acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
```

The account and the certificate are cached in
`<data_dir>/tls/acme/<one directory per ACME server>/`, so a restart serves
the cached certificate without a new order. The certificate is renewed 30
days before it expires. After a failure the gateway keeps serving the
certificate it has and retries after 1 minute, doubling up to 1 hour. Until
the first certificate arrives, TLS handshakes fail; the daemon log says why
the order failed.

`kronik doctor` fails when the certificate (from the files or the cache)
has expired and warns 30 days before.

### Preview forks: a wildcard certificate by DNS-01

Preview forks answer at `<id>.<preview_domain>`. One certificate,
`*.<preview_domain>`, covers them all, and ACME issues wildcards only by
DNS-01: the CA looks up a TXT record at `_acme-challenge.<preview_domain>`.
Kronik has no DNS provider built in. The operator provides a hook, a program
that writes and deletes that TXT record through the DNS host's API (see
[ADR 0026](../adr/0026-dns01-exec-hook.md)). Without a hook there is no
wildcard certificate, so `mode = "acme"` with `preview_domain` and no hook
is refused at start; leave `preview_domain` unset and preview forks use the
path prefix `/__preview/<id>` on the main name.

The operator provides:

- a DNS zone they can write to through an API, with a wildcard record
  `*.preview.example.com` (`A`, and `AAAA` with IPv6) pointing at this
  host;
- the hook, executable by the daemon's user, with its API credentials
  wherever it reads them (not in `kronik.toml`);
- `[tls] mode = "acme"` with the main certificate's `domains` as above.

```toml
[gateway]
preview_domain = "preview.example.com"

[tls]
mode = "acme"
domains = ["api.example.com"]
acme_email = "ops@example.com"
dns01_hook = "/usr/local/bin/kronik-dns01"
dns01_propagation = "60s"
```

The gateway runs the hook as:

```
/usr/local/bin/kronik-dns01 present _acme-challenge.preview.example.com. <value>
/usr/local/bin/kronik-dns01 cleanup _acme-challenge.preview.example.com. <value>
```

The name ends with a dot, and `value` is the TXT record's text. Exit 0 is
success; a non-zero exit, or no exit within two minutes, is a failure. A
failed `present` fails the order, which is retried like any ACME failure
(after 1 minute, doubling up to 1 hour); a failed `cleanup` is a warning
in the log. The hook's output goes to the daemon log. It runs in its own
process group, and on timeout the whole group is killed, so whatever it
started dies with it. It inherits the daemon's environment except
`KRONIK_MASTER_KEY` and `KRONIK_TOKEN`. After a successful
`present` the gateway waits `dns01_propagation` before the CA looks; a hook
that waits for propagation itself can set `"0s"`. These are the arguments
of lego's `exec` provider, so a lego script works with little or no change.

A hook for Cloudflare's API, for example (it needs `curl` and `jq`), with a
token allowed to edit the zone's DNS in `/etc/kronik/cloudflare.env`
(`CF_API_TOKEN=...` and `CF_ZONE_ID=...`, mode 0600):

```sh
#!/bin/sh
# /usr/local/bin/kronik-dns01 present|cleanup <fqdn> <value>
set -eu
. /etc/kronik/cloudflare.env
api="https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records"
auth="Authorization: Bearer $CF_API_TOKEN"
name="${2%.}"
case "$1" in
present)
    curl -fsS -X POST "$api" -H "$auth" -H "Content-Type: application/json" \
        --data "{\"type\":\"TXT\",\"name\":\"$name\",\"content\":\"$3\",\"ttl\":60}" ;;
cleanup)
    # Every TXT record at the challenge name: only ACME challenges live there.
    for id in $(curl -fsS -G "$api" -H "$auth" --data-urlencode "type=TXT" \
        --data-urlencode "name=$name" | jq -r '.result[].id'); do
        curl -fsS -X DELETE "$api/$id" -H "$auth"
    done ;;
*) echo "usage: $0 present|cleanup <fqdn> <value>" >&2; exit 2 ;;
esac
```

The wildcard certificate is cached as `wildcard.<preview_domain>.pem` next
to the main one and renewed the same way. The gateway serves it for every
name exactly one label below `preview_domain`, and the main certificate for
everything else. `kronik doctor`'s `dns01_hook` check fails when the hook is
missing or not executable, and checks the cached wildcard certificate's
expiry like `tls` does for the main one.

## kronik doctor

`kronik doctor` checks what this host can run. It needs no running daemon
and reads the same `kronik.toml`. It exits 1 if any check fails, and `--json`
gives `{checks: [{name, status, code, message, hint}], pass, warn, fail}`.
Some checks need root (`sudo kronik doctor`) and are skipped otherwise.
Foreign actors are optional, so the checks of what only they need warn
rather than fail, unless `kronik.toml` asks for what is missing
(`platform = "kvm"`).

| Check | Fails or warns when | What to do |
|---|---|---|
| `config` | The file has an unknown key or a bad value (`BAD_REQUEST`). Without a file it passes and says that the defaults apply | Fix the line it names; `kronik serve --init` writes a file |
| `kernel` | Linux older than 5.6 (warning) | Only foreign actors need 5.6 |
| `runsc` | `runsc` is missing, not executable, lacks gVisor's `gvisor-bin`/`gvisor_sentry` next to it, or is older than the tested `release-20261019.0` (`RUNSC_MISSING`, warning) | Install or upgrade gVisor with `install.sh`; only foreign actors need it |
| `kvm` | `/dev/kvm` is missing or can't be opened read-write (`KVM_UNAVAILABLE`): a warning, or a failure with `platform = "kvm"` | Most hosts are fine with systrap: set `platform = "auto"`. For `kvm` when it exists but is denied, give the daemon's user access (the `kvm` group) |
| `cgroup` | cgroup v2 or its `cpu`, `memory` or `pids` controllers are missing (warning) | Foreign actors' resource limits need them |
| `root` | Not running as root (warning) | The daemon runs as root under systemd; run doctor with `sudo` for the root-only checks |
| `runc` | `runc` is missing (`RUNC_MISSING`, warning) | Only foreign actors with `--isolation trusted` need it: `apt install runc` |
| `netns` | A network namespace can't be created (`FOREIGN_UNAVAILABLE`, warning), or a new one has more than `lo` (failure); skipped without root | Check the kernel and any container runtime around the host; only foreign actors need it |
| `run_dir` | `[foreign] run_dir` can't be created or written (warning) | Point it at a writable directory, ideally on a tmpfs |
| `caps` | The running `kronik.service` (or, without one, `kronik doctor` itself) lacks `CAP_SETUID`, which `runsc` needs: no foreign actor can start (failure); skipped without runsc | Remove `User=` from the unit and its drop-ins ([ADR 0027](../adr/0027-systemd-unit-hardening.md)) |
| `sandbox` | `runsc ... do /bin/true` fails (`FOREIGN_UNAVAILABLE`): a warning, or a failure with `platform = "kvm"`; skipped without runsc or root | See gVisor's compatibility notes and the host's seccomp/AppArmor setup |
| `disk` | Under 1 GiB free in the data directory (failure) or under 5 GiB (warning) | Free space or move `server.data_dir` |
| `clock` | The clock is not synchronized by NTP (warning) | `timedatectl set-ntp true` |
| `tls` | The certificate has expired or can't be read (failure), or expires within 30 days (warning). With `acme` and no certificate cached yet, it warns | Renew the files; for ACME see [TLS](#tls): the gateway orders a certificate when it starts |
| `dns01_hook` | `[tls] dns01_hook` is set and is not an executable file (failure); the cached `*.<preview_domain>` certificate has expired (failure), expires within 30 days or isn't cached yet (warning) | `chmod +x` the hook, or fix the path; for the certificate, read the hook's output in the daemon log; see [Preview forks](#preview-forks-a-wildcard-certificate-by-dns-01) |
| `ship` | `[ship] endpoint` is not reachable over TCP (failure); passes when shipping is off | Check the address and the network |
| `export` | With `[otel]` or `[audit]` on and the daemon answering on `server.api_socket`: a stream with lag has not delivered for 10 × its `interval`, or the audit export has held retention for longer than `[retention] history` (warnings); passes without a daemon | `kronik export status` shows the sink's last error code; fix the sink, or see [the audit log](#the-audit-log) |

## Metrics and logs

### /metrics and /healthz

On `admin_listen` (`127.0.0.1:9464` by default; keep it local or restrict
operator access). With TLS, scrape HTTPS using the certificate hostname;
with OIDC, Host must match the configured admin origin:

- `GET /healthz` answers `200 {"status": "ok", "applied_lsn": N}` while the
  node runs (with `"low_disk": true` below `[log] disk_reserve`), and `503`
  with the error JSON after a storage failure, when the daemon must be
  restarted (systemd does this).
- `GET /metrics` answers in Prometheus' text format:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `kronik_build_info` | gauge | `version`, `engine` | Always 1; the build |
| `kronik_applied_lsn` | gauge | | The newest log record applied to the state |
| `kronik_disk_free_bytes` | gauge | | Free bytes on the log's file system, when `[log] disk_reserve` is set |
| `kronik_disk_below_reserve` | gauge | | 1 while free space is below `[log] disk_reserve` (also `"low_disk": true` in `/v1/health` and `/healthz`) |
| `kronik_turns_total` | counter | `kind`, `outcome` | Turns by actor type and outcome: `committed`, `rejected` or `failed` |
| `kronik_turn_duration_seconds` | histogram | `kind` | Turn duration |
| `kronik_log_records_appended_total` | counter | | Records written to the log |
| `kronik_log_fsync_duration_seconds` | histogram | | Duration of the log's fsyncs (group commit) |
| `kronik_effects_total` | counter | `kind`, `status` | Effects by kind and status |
| `kronik_gateway_requests_total` | counter | `status` | Gateway requests by HTTP status |
| `kronik_gateway_request_duration_seconds` | histogram | `status` | Gateway request duration |
| `kronik_replay_runs_total` | counter | `mode` | Fork replays by mode |
| `kronik_guard_triggered_total` | counter | `action`, `outcome` | Guards of `kronik watch` that fired |
| `kronik_export_records_total` | counter | `stream` | Log records an export stream (`traces`, `audit`) delivered or skipped |
| `kronik_export_lag_records` | gauge | `stream` | Committed records the stream has not delivered yet |
| `kronik_export_errors_total` | counter | `stream` | Failed attempts, retried with backoff |
| `kronik_export_dropped_total` | counter | `stream` | Records in batches the sink refused for good (OTLP 400) |
| `kronik_export_gaps_total` | counter | `stream` | Ranges retention deleted before the stream read them |

A Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: kronik
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

### OpenTelemetry

With `[otel] endpoint` set, `kronik serve` sends every committed turn as a
span, and each of its effects as a child span, to an OpenTelemetry
collector over OTLP/HTTP with protobuf (no gRPC), and pushes the metrics
above every `metrics_interval` (counters as cumulative sums, histograms
with their bounds). Spans are built from the log after commit, off the turn
path: a slow or absent collector never slows a turn. Delivery is at least
once, in log order, from a cursor in `<data_dir>/export.json`, so a restart
or a collector outage resumes where it stopped (spans of a turn are the
same spans when sent twice). A first start exports from the current end of
the log, not the history. Retention does not wait for the collector: spans
of deleted segments are skipped and counted in
`kronik_export_gaps_total{stream="traces"}`. `kronik export status` shows
the cursor, the lag, the last success and the last error's code;
`kronik_export_lag_records` also counts up while the collector is down. An
exporter that died (a bug) is started again from its saved cursor after a
backoff, with last error `panic`. `kronik export rewind traces --to <lsn>`
resends the spans after `<lsn>` as they were first sent: the exporter
first rebuilds which turns were open there from the retained log.

A trace is one root input (an HTTP request, an operator send, a resend)
and the calls it makes: a call through three actors is one connected
trace. A message sent to another actor and a timer start traces of their
own, with a link (`kronik.link = "message"` or `"timer"`) to the turn that
caused them, so two actors messaging each other do not make one endless
trace. The trace id is the turn's causal root. An incoming W3C
`traceparent` header becomes a link on the root span (`kronik.link =
"traceparent"`), not its parent, so a callee always computes the same
trace. A message, timer or compensation sent by a callee links to that
callee's span in its caller's trace; a callee whose call timed out still
joins its caller's trace when it runs.

- **A collector:** point `endpoint` at the OpenTelemetry Collector's
  `otlp` receiver (`http` protocol, port 4318) and forward from there.
- **Jaeger** (v2) takes OTLP/HTTP on 4318 itself:
  `docker run --rm -p 127.0.0.1:4318:4318 -p 127.0.0.1:16686:16686
  jaegertracing/jaeger`, then `endpoint = "http://127.0.0.1:4318"` and the
  UI on port 16686.
- **Grafana Tempo** takes OTLP/HTTP on its distributor (4318 when the
  `otlp` receiver's `http` protocol is on); metrics go to a collector or
  Mimir's OTLP endpoint.
- **A vendor:** `endpoint = "https://otlp.vendor.example"` and
  `headers_env = "KRONIK_OTEL_HEADERS"`, with
  `KRONIK_OTEL_HEADERS=authorization=Bearer …` in the unit's environment
  (`systemctl edit kronik`), so the credential stays out of the file.

**Try it with Jaeger.** From a checkout, `scripts/jaeger.sh COMMAND` runs a
throwaway Jaeger v2 in docker (pinned by digest, in-memory, removed
afterwards) on free loopback ports and gives COMMAND
`KRONIK_TEST_OTLP_ENDPOINT` (for `[otel] endpoint`) and
`KRONIK_TEST_JAEGER_QUERY` (the UI). `scripts/jaeger.sh demo/vps-otel.sh`
serves with that endpoint, calls through three actors, with and without a
`traceparent`, and checks in Jaeger's API that each call is one connected
trace (`KRONIK_BIN` picks the binary). To look around yourself,
`scripts/jaeger.sh bash` and start `kronik serve` from that shell.

**What leaves the node** (ADR 0082): actor kinds, keys (hashed by
default), route patterns and methods, status codes, outcome kinds and error
codes, effect kinds, statuses and target hosts, secret names, code hashes,
epochs and turn ids. Never a request or message body, a header, a path or
query string, a reply, state, `Outcome.message`, an effect's error text, a
subject id or a secret. With `actor_keys = "hashed"` a key such as
`counter/carol@example.com` leaves as `kh:` plus 12 hex of a keyed hash:
the same key always gives the same label, and without the node's key it
cannot be reversed. The hash key derives from the master key, or on a node
without one from `<data_dir>/otel.key` (created at first use, mode 0600).
`"plain"` exports keys as they are (test data); `"none"` leaves them out.

### The audit log

The log is the audit trail: every mutation writes a log record with its
token and reason (`kronik history` and the diff read them). With
`[audit] sink` set, `kronik serve` also writes one JSON line
(`kronik.audit/v2`) per audited record to the sink, in log order, at least
once, from the `audit` cursor in `<data_dir>/export.json`: configuration
changes, operator sends and resends, each `secret.reveal`, guards that
fired (`watch.guard`), the switch of a rollback via replay
(`rollback.rebase`), and the mutations recorded as `AuditEvent`s
(secrets, tokens, forks, proposals, a rollback via replay's proposal
(`rebase.create`), watch start and stop, preview create and delete,
snapshots, reseal, export rewinds, and the node's own `restore`,
`audit.gap` and `audit.config`). `kronik audit show` prints the same lines
from the log, also when no sink is set (scope `admin`). A consumer
deduplicates by `lsn`, `effect` and `record_hash`; after `kronik restore`
from an older ship point, new records reuse the lost tail's LSNs, and a
`restore` line marks the point. The first start after restore durably
clamps or initializes both export cursors (including absent/from-now
entries), drops lost-tail trace resume state, resets the lost-tail
audit-configuration hash, preserves/clamps pending replay and assigns a
new applied generation. Only then is the restore marker removed and its
parent synced, with exports on or off.

- **A directory** (`file:///var/log/kronik/audit/`): lines go to
  `audit-v2-<sequence:020>.jsonl` files (mode 0640), fsynced before the cursor
  moves; `file_max_bytes` (1 B–1 GiB, default 64 MiB) is a soft
  whole-batch rotation threshold, not an oversized-record drop limit.
  Exclusive-create names use an increasing sequence, independent of LSNs
  and file mtimes. Recovery and verification read numbered files by sequence,
  after historical LSN-named files; historical ordering is not repaired.
  A fixed-buffer tail scan truncates a crash's partial line at start.
  Files must be no-follow, regular and uniquely linked. Kronik never deletes
  them. Rotate sealed older files to cold storage, keeping the newest
  numbered file across writer restarts; do not renumber the archive.
  When the newest file is moved away, replaced by another (logrotate's `create`) or
  truncated (`copytruncate`), the next batch starts a new file. Keep what
  `kronik audit verify` should still check. The unit's
  `LogsDirectory=kronik` makes `/var/log/kronik` writable; another
  directory needs `ReadWritePaths=`.
  Removed directories are recreated and recoverable open/write errors
  retry. Any sync failure or EIO latches that writer as `storage_sync`:
  no later filesystem attempts or cursor acknowledgements occur, but the
  node remains usable. Repair or quarantine the storage, create a new
  writer and safely rewind from retained records. Restart alone is not
  proof that durability was repaired; no automatic COW repair is promised.
- **A webhook** (`https://…`): one POST per batch,
  `application/x-ndjson`, with `kronik-audit-range: <first>-<last>` and
  `idempotency-key: <generation>-<first>-<last>-<body hash>` headers.
  Retries retain the key; intentional replay changes generation and cannot
  reuse the receiver's old ACK. Credentials come through `headers_env`.
  Anything but
  a 2xx is retried with backoff (a 4xx other than 408 and 429 also logs a
  warning): audit lines are never dropped on the sink's say-so.
- **Object storage** (`s3://bucket/prefix`, with `endpoint` and the
  `AWS_*` variables as for shipping): one create-only object per successful
  delivery at `<prefix>/audit/v2/<sequence:020>.jsonl`. Recovery streams the
  tail once, not once per batch. Collisions prove occupation but never ACK
  this delivery; unknown failures do not advance the candidate, and lost
  ACKs may yield duplicates. Legacy top-level objects are read first, then
  numbered v2 objects. Keep the v2 namespace append-only: disable bucket
  lifecycle deletion there and do not remove/renumber objects during
  publication or recovery. Ordering assumes the backend's conditional
  create is atomic and its ACK durable; arbitrary deletion plus stale
  listing is not safe. Historical ordering is not retroactively repaired.
  A backend without conditional create stalls with `s3_unsupported` and no
  cursor advance; fix the backend/configuration rather than bypass it.

**Retention waits for the audit export, production does not.** Retention
keeps every segment the export has not delivered, until free disk falls
below `hold_release` (or the hold is older than `max_hold`): then it
deletes as before, and the export writes an `audit.gap` event naming the
lost range and counts `kronik_export_gaps_total{stream="audit"}`. Free
disk is measured for this with `[log] disk_reserve = "0B"` too. A sink
that stays down shows in `kronik export status`, in
`kronik_export_lag_records{stream="audit"}`, and in `kronik doctor`.

**Checking a sink.** `kronik audit verify` (no daemon needed; it reads the
data directory and the master key, which an erasure's `record_hash` is
keyed with) compares a `file://` or `s3://` sink with the log: every
audited record must have its line, with no extra or conflicting line. It
checks up to the audit cursor by default, prints what is missing, extra or
conflicting, and exits 1 unless the sink is complete. A webhook cannot be
read back; verify the store behind it. After a sink lost data,
`kronik export rewind audit --to <lsn> --reason …` sends the records after
`<lsn>` again (scope `operate`); retention keeps them from the moment you
ask.

Replay requests are durable and processed by an owned task, so cancelling
the API call does not lose the request. Audit intent precedes the effect;
failures leave an event and stable code. A newer request survives older
in-flight acknowledgements: its generation first checkpoints the earliest
cut and clears pending replay only on reaching that generation's head.
The retention hold is restored before export starts and moves only after
durable checkpoints. Requests wake retry loops; webhook keys bind generation
and S3 replay creates new ordered objects. Authoritative source gaps are
recorded during remote retries,
deduplicated across checkpoint failure/restart, and the skipped range is
durably saved before preparing later data.

Trace resume metadata is a small checksummed `kronik.trace-state/v1`
reference into two fixed snapshot/delta files plus scratch. Legacy
open-pair/`{open,kept}` state migrates once; corrupt selected modern state
stalls trace export rather than silently resetting it. Oversized metadata
reports `trace_state_limit`, not truncated state. Entry-count limits alone
are not a heap bound. With both cursor exporters off, unreadable
`export.json` is left untouched; configuration changes remain
source-audited even if the cache is unavailable.

The current exporter integration suite and actual binary restore/S3 checks
exercise these control/checkpoint contracts. Physical fsync repair and
complete retained external/deleted-version secret coverage are not implied.

**What leaves the node** (ADR 0082): the line's action, token id, reason,
wall time, epoch, record hash and plain facts (kinds and code hashes,
capabilities, limits, policy rule names and hash, secret and token names,
fork and proposal ids, a foreign image's digest). Never a secret value, a
token, a message body, a subject id or a sealed value: a subject is `s:`
plus 12 hex of its keyed hash, actor keys follow `[otel] actor_keys`.
Free text, names and spans are scrubbed for secret values and token
spellings; canonical audit hashing withholds free text. Subject masking
handles case, percent encoding and identifier boundaries. Never put
personal data in `--reason`. If secret inventory is unavailable,
privacy-sensitive API projections return 503 `SECRET_UNAVAILABLE` and
both exporters stall preparation without cursor advance. A mutation that
begins while the inventory is being rebuilt waits for it, for `[secrets]
fetch_timeout` plus 5 s at most, and records its reason; only a wait that
runs out records `[withheld: secrets could not be loaded]` in its place.
While a backend is down and the rebuilds fail, a mutation does not wait:
it records the placeholder at once. Unrelated node work remains usable. Complete
retained external/deleted-version coverage across restart remains M23
work, not a guarantee of the current local inventory.

Verification accepts exact source-derived legacy v1 lines alongside v2,
validates known schema/hash/identity, and counts mixed retries as one
logical item. Only trusted source restores authorize superseding cuts,
never sink-provided lines. `restore.through_lsn` and `audit.gap.from`/`to`
are validated action-specific `u64` positions: v2 JSON numbers, legacy
v1 decimal strings; other text gets no key-name exemption.

### Logs

The daemon logs to stderr, which systemd sends to the journal. With
`--log-format json` (or `KRONIK_LOG_FORMAT=json`), every line is one JSON
object with `timestamp`, `level`, `target` and `fields`, ready for a log
shipper. `KRONIK_LOG` filters by level and target, for example
`KRONIK_LOG=warn` or `KRONIK_LOG=info,kronik::guest=debug`. The MCP
library's targets (`rmcp`) stay at `info` whatever it says: at `debug` they
log tool arguments and results. To set it under systemd, use
`systemctl edit kronik` and add `Environment=` lines.

Actors' own log lines come out with target `kronik::guest`, carrying
`execution_id` and `causal_id` fields that tie them to a turn
(`kronik trace`, `kronik history`). Kronik doesn't filter what actors log:
actors should not log personal data or secrets. Exact occurrences of
revealed secret values are replaced with `[secret:<name>]`.

## Watching a deployment

After `kronik promote`, watch the new code against the traffic before it:

```sh
kronik watch <epoch> --for 10m --reason "after promote"
```

The watch compares the error rate (turns the code or the host failed, and
committed HTTP 5xx responses; not `REJECTED`, which is the client's bad
input) and the p50 and p99 turn latency of the deployment's actor kinds
in the `--for` window after it (at most 24h) with an equally long window
before it, every 5 seconds. It runs in the daemon: the CLI can go away
(`--async`), and a restart resumes it from the log
(`<data_dir>/watches/<id>.json`). `kronik watches list` and
`kronik watches show <id>` follow it; `kronik watches stop <id> --reason
"..."` ends it without further alerts or rollbacks. `kronik watch
--dry-run` shows the metrics now and which guards would fire.

Only the latest deployment of its kinds can be watched. A later promote,
deploy or rollback of any of them ends the watch `superseded`: nothing
acts on code that no longer runs, so a hotfix is never rolled back by an
older watch.

The policy's guards decide what a breach does. Add `[[guard]]` tables to
the rules file (`kronik policy set`):

```toml
[[guard]]
name = "error-rate-up"
when = "guard.after.turns >= 20 && guard.after.failed >= 3 && guard.after.error_rate > guard.before.error_rate + 0.05"
action = "rollback"

[[guard]]
name = "slow"
when = "guard.after.turns >= 50 && guard.after.latency_p99_ms > 500.0"
action = "alert"
```

Without a `guard` key, two defaults apply: `error-rate-up` as above
(rollback) and `latency-p99-up` (alert when p99 more than doubles and
rises by over 50 ms, with at least 10 turns on both sides and a measured
p99 before). `guard = []` means no guards: the watch only measures.
`kronik policy show` prints the guards in force. Guards are evaluated once
a turn ran after the deployment. A guard that fires writes a
`GuardTriggered` record with the metrics, logs an error (`a guard fired
after a deployment`) and counts in `kronik_guard_triggered_total`. A
`rollback` guard rolls back like `kronik rollback` does, with audit token
`kronik`; when the deployment raised a schema version it alerts instead
(`rollback_refused_schema`). Each guard fires at most once per watch; a
guard that cannot be evaluated alerts once (`the guard could not be
evaluated: ...`) and is tried again. `kronik watch` exits 1 when a
rollback guard fired but the rollback did not happen. Alert on the
metric, or on the log line, to page someone.

## The master key

The master key is a 32-byte seed. It protects the secret store
(`<data_dir>/keys/secrets.db`), the privacy keystore
(`<data_dir>/keys/keystore.db`) and their derived keys. Init, start,
shipping, restore, upgrade checks and audit verification use the same
checked `[keys]` configuration.

### File and environment sources

`source = "file"` is the default. `[keys] master_key_file` holds 64 hex
characters, mode 0600: `/etc/kronik/master.key` after `serve --init`, or
`<data_dir>/keys/master.key` otherwise. A first start creates it only when
there are no encrypted stores.

With `source = "env"`, `KRONIK_MASTER_KEY` must hold the 64 hex characters
themselves, not a filename. For existing configurations, the default file
source also accepts that variable when no key file was explicitly
configured. No key file is then read or created. Setting the material
together with `master_key_file`, `--master-key-file` or a KMS source is an
error; unset the variable before starting a KMS-backed node. Child
processes, including the DNS-01 hook, do not inherit it.

Back a file/env key up separately, offline, not beside the data directory's
backup. Losing it loses every secret and sealed value. A missing key over
existing stores is `MASTER_KEY_MISSING`, never permission to generate a
replacement; a key that does not match the stores is
`MASTER_KEY_MISMATCH`.

### KMS sources

`source = "openbao"`, `"aws"`, `"gcp"` or `"azure"` keeps the provider's
key outside Kronik. Kronik generates a seed in memory and asks that key to
wrap it. Only the ciphertext envelope is written, mode 0600, at
`<data_dir>/<wrapped_file>`. At start the provider unwraps it; no plaintext
master-key file or temporary key file is created. The envelope's source,
key, version, format and purpose are checked against the node's
configuration. An envelope cannot choose an endpoint or a credential.

Configure exactly the table matching `source`. Credentials are file paths
or the supported environment/instance identity, never inline TOML values.
Relative credential and CA paths resolve under systemd's
`$CREDENTIALS_DIRECTORY`; otherwise use absolute paths. A provider's
`ca_file` adds a private PEM CA to its own TLS client, not to guest HTTP
effects. OpenBao certificate authentication uses that provider's client
certificate and key. Plain HTTP is accepted only on loopback.

**OpenBao transit** (Vault-compatible API):

```toml
[keys]
source = "openbao"
wrapped_file = "keys/master.wrapped"
start_timeout = "60s"

[keys.openbao]
address = "https://bao.internal:8200"
mount = "transit"
key = "kronik"
auth = "token"
token_file = "/etc/kronik/bao-token"
ca_file = "/etc/kronik/bao-ca.pem"
```

Create a dedicated derived transit key in OpenBao, for example
`bao secrets enable transit` then
`bao write transit/keys/kronik derived=true type=aes256-gcm96`. Kronik
binds the purpose `kronik master v1` through the transit `context`.
`mount` defaults to `transit`. Authentication is exactly one of:

- `auth = "token"` with `token_file`;
- `auth = "approle"` with `role_id_file` and `secret_id_file`, optionally
  `auth_mount`;
- `auth = "cert"` with `cert_file` and `key_file`, optionally `auth_mount`
  and `role`.

**AWS KMS:**

```toml
[keys]
source = "aws"

[keys.aws]
region = "eu-north-1"
key_id = "arn:aws:kms:eu-north-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
auth = "auto"
```

`key_id` must be the full immutable key ARN in `region`, not an alias or
bare id. `auth` is `auto` (environment, then IMDSv2), `env` or `imds`.
Environment credentials are `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
and, for temporary credentials, `AWS_SESSION_TOKEN`. Profiles, SSO and web
identity are not credential providers. `endpoint` selects a KMS-compatible
endpoint, such as loopback moto for tests; `ca_file` is optional. The
provider's encryption context binds the purpose.

**Google Cloud KMS:**

```toml
[keys]
source = "gcp"

[keys.gcp]
key = "projects/my-project/locations/global/keyRings/kronik/cryptoKeys/master"
# service_account_file = "/etc/kronik/service-account.json"
```

`key` is the full unversioned `cryptoKeys` resource. A
`service_account_file` supplies an RSA service-account key for an RS256 JWT
exchanged for an OAuth token; without it, the provider uses the instance
metadata service. Workload identity federation is not supported. `endpoint`
and `ca_file` are optional. Authenticated additional data binds the purpose.

**Azure Key Vault:**

```toml
[keys]
source = "azure"

[keys.azure]
key = "https://my-vault.vault.azure.net/keys/kronik"
# tenant_id = "00000000-0000-0000-0000-000000000000"
# client_id = "11111111-1111-1111-1111-111111111111"
# client_secret_file = "/etc/kronik/azure-client-secret"
```

`key` is an unversioned Key Vault key URL. Set all three client-credential
fields together, or omit `tenant_id` and `client_secret_file` to use
managed identity; `client_id` may select a managed identity. `ca_file` is
optional. Kronik resolves the current version and uses RSA-OAEP-256
wrap/unwrap. Unlike the other providers, this operation has no AAD; the
envelope's format and checked key reference identify its purpose.

For isolated tests, AWS `imds_endpoint` and Azure `authority_endpoint` may
override a loopback origin; GCP `token_endpoint`/`metadata_endpoint` and
Azure `metadata_endpoint` may name a full loopback URL. These overrides
are never read from the envelope, cannot target a non-loopback host and
contain no inline credentials. Normal deployments leave them unset.

PKCS#11 is not implemented by this slice. Neither an HSM module nor a
keyhelper is loaded.

### Migration and rewrap

`kronik keys status` (scope `read`) shows the source, key reference,
provider version and store-check result; never seed bytes.

To move an existing file/env seed into a KMS:

1. Stop the daemon on this data directory.
2. Write the target configuration with the chosen KMS `source` and its
   provider table, without `master_key_file`.
3. Run a dry run with the old file explicitly named:

   ```sh
   kronik keys wrap --source openbao --config /etc/kronik/kronik-kms.toml \
     --data-dir /var/lib/kronik --master-key-file /etc/kronik/master.key \
     --reason "move the existing seed into OpenBao" --dry-run
   ```

4. Repeat without `--dry-run`, then start using the target configuration.
   Keep any old `KRONIK_MASTER_KEY` or `KRONIK_MASTER_KEY_FILE` only for the
   migration command and unset both before KMS start. The printed start
   command does this explicitly.

The old file is preserved unless `--remove-file` is explicit; it is not
securely erased from disk snapshots or backups. A migrated seed therefore
*was* on disk once. A seed that has never been persisted requires a new
KMS-backed node. `keys wrap` does not rotate the seed or re-encrypt stores.
New daemons and `keys wrap` use a cooperative lock on the directory itself;
no writable sibling or parent lock file is needed. Released v0.3 daemons
do not hold this lock: stop an older daemon explicitly before migration.

After rotating the provider's wrapping-key version, run:

```sh
kronik keys rewrap --reason "use the current wrapping-key version" --dry-run
kronik keys rewrap --reason "use the current wrapping-key version"
```

This is online, requires `admin`, checks that old and new envelopes unwrap
to the node's existing seed, and atomically replaces only the ciphertext.
The API records `keys.rewrap`; offline migration leaves a marker which the
next start records as `keys.source`. Neither operation records key bytes
or credentials. Rewrap is not master-seed rotation.

### Outages, backup and restore

The running node shares its loaded key with the shipper. A KMS outage
does not stop turns or require another unwrap for a keystore backup.
Start and commands that load or rewrap a key do need the provider:
unavailability is `KEY_SOURCE_UNAVAILABLE` after retries within
`start_timeout`. A missing envelope over encrypted stores is
`MASTER_KEY_MISSING`, not a new seed.

For KMS sources, shipping publishes the ciphertext with the keystore
backup, before marking the pair complete, and publishes a changed
envelope after rewrap even when the keystore has not changed. On a fresh
machine, restore with the same KMS configuration:

```sh
kronik restore --from s3://my-bucket/kronik/prod \
  --config /etc/kronik/kronik-kms.toml --data-dir /var/lib/kronik
kronik serve --config /etc/kronik/kronik-kms.toml
```

Restore stages the shipped envelope and encrypted stores, unwraps and
checks them before installation, and never replaces an existing target
key on failed validation. File/env restores still need their original
key supplied separately. `--allow-missing-keys` and `--without-keystore`
keep their explicitly destructive meanings for subject keys.

Keep every provider key version needed by a retained backup enabled for
that backup's lifetime. Losing the KMS key loses the encrypted data.
The envelope protects a stolen data directory or bucket only when its
bootstrap credential is not stolen too: prefer instance identity, or keep
credential files outside the data/backup tree. `doctor` warns about
credential files under the data directory.

The seed and long-lived derived keys live in locked mappings, shared by
reference rather than copied when cloned. On Linux those mappings are
also excluded from core dumps (`MADV_DONTDUMP`), and key-loading processes
are non-dumpable. macOS locks the mappings and disables standard core
dumps with `RLIMIT_CORE=0`; it has no per-mapping `MADV_DONTDUMP`. Failure
to protect a key is `KEY_PROTECTION_UNAVAILABLE`, never an unprotected
fallback. Give the process enough `LimitMEMLOCK` for its key mappings.

### Free emulator acceptance

`scripts/e2e-keys.sh` exercises an already-built Linux binary against pinned
OpenBao, Moto KMS, GCP KMS and Azure Key Vault emulator images. It builds and
installs nothing, uses dummy credentials, and needs Linux root, Python 3.12+
(`os.setns`), Docker, OpenSSL and the host public CA bundle at
`/etc/ssl/certs/ca-certificates.crt` (the Debian test VPS path). The checked-in
counter component supplies the secret-HMAC and sealed-value workload.

```sh
KRONIK_BIN=target/x86_64-unknown-linux-musl/release/kronik \
  flock -w 20 /var/tmp/kronik-vps.lock scripts/e2e-keys.sh
```

The VPS lock is the existing convention on the shared test VPS: do not run
another suite concurrently. Each run creates a fresh private directory beneath
`/var/tmp`, prints its `results.json` path and retains logs/test data there.
On exit the driver removes only its owned containers, reports removal
failures and records a filtered post-cleanup observation. Existing services
and data are not touched. Containers have read-only root filesystems,
explicit resource limits and no external network. Only the trusted driver
enters their private network namespace for loopback API/OAuth calls.

`--probe-only` checks emulator capabilities without claiming product
acceptance; `--only openbao,gcp` selects a subset while iterating. A full B1
proof needs all four providers and a release-musl run, not a probe-only or
subset success. The fixtures verify actual OpenBao HTTPS client-certificate
authentication and GCP RS256 JWT signatures/claims; they do not prove real
cloud IAM. Moto does not enforce SigV4; the separate published AWS signing
vectors cover the signer. Azure's emulator validates JWT form, not live
Entra authorization. Do not use these emulator credentials or certificates
outside the disposable tests.


## Snapshots and retention

A snapshot is a consistent copy of the materialized state as of one log
position: `state.db`, every actor's SQL database, and the secret store
(`keys/secrets.db`, still encrypted under the master key). It lives in
`<data_dir>/snapshots/main/<lsn>/`, with a `manifest.json` listing every
file's size and BLAKE3 hash. The daemon takes one:

- every `[retention] snapshot_interval` (60 minutes by default), when
  something changed since the last one;
- when it stops on SIGTERM or Ctrl-C (`systemctl stop` and `restart`
  included), unless nothing happened since the newest snapshot;
- when you ask: `kronik snapshot create --reason "..."`.

`kronik snapshot list` shows them, newest first. `kronik integrity` prints
the applied LSN, the state hash and a hash of the log, which is how a
restore is compared with the node it came from. The restored node's first
start records one `restore` audit event after the source's last record, so
on it run `kronik integrity --through <the source's applied LSN>`: the state
hash and log hash then equal the source's, and `kronik audit show --from
<that LSN + 1>` shows the `restore` line.

After each snapshot the daemon applies retention. It keeps the newest
`snapshots_kept` snapshots (48 by default) plus the oldest one the log
still continues from. It deletes closed log segments older than
`[retention] history` (7 days by default) whose records a kept snapshot
already covers. A record without a logical time of its own, such as a
deployment, counts as old as the next turn after it, so a segment is kept
until a later turn has aged out of the window too. Before it deletes, it
records on every actor database that has not changed for longer than the
window that the database is complete through the snapshot, so that the
next start does not look for a log that has been deleted. After an upgrade
from v0.3.0 or older, `snapshots_kept` also decides how long some reads
answer 503: see [Upgrading from v0.3.0 or older](#upgrading-from-v030-or-older).

When a proposal's `--window` reaches back before the oldest point still
kept, the fork starts at the oldest usable snapshot and the proposal says
so: `Warning: retention cut the window ...` in `kronik propose`, `warnings`
in its JSON and `base.window_cut` in the diff.

The same window is how far back a fork, a replay or a proposal may start:
`history` of logical time back from the newest record. A fork point older
than that is `BAD_REQUEST` ("outside retention") from `kronik fork create`,
`kronik propose` and `kronik replay`, and `PROPOSAL_STALE` from `kronik
promote`. `kronik integrity` prints the window, the newest logical time
and the cutoff. A turn whose LSN is below the log's first LSN is
`TURN_NOT_FOUND`; the message says the turn is outside retention and
names `log_first_lsn`.

`kronik snapshot list` shows whether each snapshot has been shipped
(`shipped` in the JSON; yes or no in the table). Shipping off, or a
snapshot not yet in `<data_dir>/ship.json`, is no.

At start, when `state.db` is missing, or older than the first record the
log still holds, the daemon installs the newest snapshot that the log
continues and replays the log from there. A data directory therefore
recovers from a lost or deleted `state.db`.

The privacy keystore (`keys/keystore.db`) is not part of snapshots. The
shipper uploads it separately, encrypted, within a minute of a change. A
restore installs the newest of those backups and refuses
(`KEYSTORE_INCOMPLETE`) when it lacks the key of a sealed value in the
restored data, for example a restore made within a minute of a new
subject's first value. If the source still runs, let it ship again and
restore again. If it is gone, `kronik restore --allow-missing-keys`
installs the backup anyway and names the subjects whose sealed values stay
unreadable; every other subject stays readable. (`--without-keystore`
drops every key, so use it only without the master key.) `kronik integrity`
lists subjects whose sealed values have no key, and exits 1.

## Shipping to object storage

With shipping on, the daemon copies the log, its snapshots and the deployed
code to an S3 bucket every 10 seconds:

```toml
[ship]
enabled = true
url = "s3://my-bucket/kronik/prod"
# endpoint = "http://127.0.0.1:9000"   # S3-compatible servers, such as MinIO
```

`url` may also be `file:///dir`: the daemon then ships to a directory on
the same machine, and `kronik restore --from file:///dir` reads it back.
That runs the whole flow without a bucket, as the
[quickstart](quickstart.md)'s step 9 does, but it is not a backup: the
copy does not leave the machine.

- **Credentials and region** come from the standard variables
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optionally
  `AWS_SESSION_TOKEN`, and `AWS_REGION` (default `us-east-1`). Under
  systemd, put them in a root-only file and point the unit at it with
  `systemctl edit kronik`:

  ```ini
  [Service]
  EnvironmentFile=/etc/kronik/ship.env
  ```

- **What is uploaded:** each closed log segment once, the active segment
  again whenever it has grown (so the last records of an idle node leave
  within one round), each snapshot (its files, then its manifest), and the
  code. Everything but manifests is compressed with zstd. Segments and
  snapshots that retention deletes locally are deleted from the bucket
  too. `<data_dir>/ship.json` records what is already up.
- **What is never uploaded:** the plaintext master key or its bootstrap
  credentials. File/env keys need a separate backup; KMS sources ship
  their ciphertext envelope with the encrypted keystore backup (see
  [the master key](#the-master-key)). Forks and proposals, with their
  diffs (`<data_dir>/branches/<name>/`), stay in the old data directory.
- `kronik doctor`'s `ship` check tells whether the endpoint is reachable.

Restoring onto a new machine (the daemon must not be running on the
directory):

```sh
kronik restore --from s3://my-bucket/kronik/prod --data-dir /var/lib/kronik
kronik serve --data-dir /var/lib/kronik
```

`--endpoint` is the same URL as `[ship] endpoint` when the bucket is not
AWS. An existing `state.db` is refused unless `--force`. `--dry-run` prints
the plan and writes nothing. Restore writes no log record, so it takes no
`--reason`. It does not bring back forks, proposals or their diffs: on the
restored node, `kronik proposals list` shows only proposals made after the
restore, and an earlier one answers `PROPOSAL_NOT_FOUND`. Deployments and
approvals are log records and are restored, each approval with the hash of
the diff it was given for (`diff_hash`). File/env sources need the
original master key before restore; KMS sources install the shipped
wrapped key and unwrap it using the supplied configuration. In a checkout,
`demo/vps-restore.sh` does this with two data directories and one bucket
(`scripts/minio.sh demo/vps-restore.sh` uses a local MinIO in Docker).

**Starts that replay a long stretch of the log, up to v0.0.8.** A start
that replays 8,192 or more records in one
go uses a bulk replay: after a restore, after `state.db` was moved away or
lost, or when `state.db` is that far behind the log. Up to v0.0.8, such a
start could re-run turns that had already finished, when a turn's first
and last records fell in different segments or replay batches. The re-run
sent an idempotency-keyed or replay-safe request again, recorded an unsafe
one as `EFFECT_OUTCOME_UNKNOWN` (a dead letter), and applied the turn's
writes and messages a second time. If you restored or rebuilt `state.db`
with such a binary, look in that start's daemon log for `re-running an
unfinished turn` lines; each names an actor and an execution id. For each,
`kronik history <actor>` shows whether that turn ended twice, and
`kronik dead-letters list` shows outcome-unknown dead letters from that
start.

## Upgrading to a new release

Each release has its own engine version, `kronik-<version>+wasmtime-<version>`
(`kronik --version` prints it). Data written by another engine starts
only after this binary has checked itself against it: a start without a
passing check stops with `ENGINE_VERSION_MISMATCH` before it serves
anything, and loses nothing (on data from v0.3.0 or older it has by then
changed the tables of the databases, see [Upgrading from v0.3.0 or
older](#upgrading-from-v030-or-older)). So an upgrade, for example from a
0.1.0-dev build to 0.3.0, is three steps:

1. Install the new binary (`install.sh` replaces `/usr/local/bin/kronik`;
   the running daemon keeps the old one).
2. Check it against the data directory, with the old daemon still running:

   ```sh
   sudo kronik upgrade check --window 6h --config /etc/kronik/kronik.toml
   ```

3. Restart: `sudo systemctl restart kronik`. The first start records the
   upgrade (an `EngineUpgrade` record in the log) and compiles every
   deployed component again for the new engine, so it takes longer than
   usual. The compiled code of the old engine stays in `<data-dir>/code/`
   (`*.<old engine>.cwasm`); delete those files once the new binary runs.

The check replays the last `--window` of logical time with the new engine
and the same code. It reads the data directory, its privacy keystore and
the same key-source configuration as `kronik serve`. A KMS-backed check
needs the provider and its credentials, even while the old daemon keeps
running. An empty diff writes `<data-dir>/upgrade/<engine>.json`
and exits 0. A diff that is not empty writes that report and the diff next
to it (`<engine>.diff.json`) and exits 1 with `ENGINE_UPGRADE_DIVERGED`:
keep the current binary. `--dry-run` prints the result and writes neither
file. A bad window or a directory with no log is `BAD_REQUEST`.

The check also asks the question the start asks of the data directory: the
databases (`state.db` and the actor databases) must be reached by the log
that retention kept. It prints a note when the start will repair that by
installing a snapshot, and stops with `STORAGE_CORRUPT` and the start's own
message when it cannot ([A start that stops at the log's
start](#a-start-that-stops-at-the-logs-start)). Run it before every restart
after an upgrade.

After the restart the data is the new engine's. Going back to the old
binary is the same procedure the other way: its own `kronik upgrade check`
first. That works between builds that write the same kinds of record; v0.3.0
could not start on data that a newer build had served (see [Upgrading from
v0.3.0 or older](#upgrading-from-v030-or-older)). A restore from a bucket that
an older binary shipped also needs the check before the restored directory's
first start.

### Upgrading from v0.3.0 or older

This is a known defect, not intended behavior. A code change for it is being
considered, and it may change this section. It concerns data directories that
v0.3.0 or older wrote. It was checked with the data directories of v0.3.0 and
v0.1.0 under `tests/compatibility/` and, for a log that had been compacted, with
a data directory that the published v0.3.0 binary wrote for the purpose, using a
build of `kronik 0.4.1-dev` and the published v0.4.0 binary, which behaves the
same. The data directory of v0.4.0 upgraded without it. Each point says what was
checked.

**Before you upgrade.** Make the backup that [the upgrade
runbook](../runbooks/upgrade.md) asks for, and keep it for as long as you may
want to go back:

- Once a newer binary has served the data, the older one cannot start on it.
  The published v0.3.0 binary stopped on a copy that a build of `kronik
  0.4.1-dev` had served, with `STORAGE_CORRUPT: record at lsn 19: unknown record
  kind 45`. Nothing was corrupt: the log holds records of kinds that v0.3.0 does
  not know. Going back to v0.3.0 means restoring the backup.
- Between binaries that write the same kinds of record, going back is the
  procedure above. The published v0.4.0 binary refused data that a build of
  `kronik 0.4.1-dev` had served with `ENGINE_VERSION_MISMATCH`, passed its own
  `kronik upgrade check`, started, and recorded a second `engine upgrade`. Only
  that pair was tried.

**The check.** Run it with the new binary before its first start, as above, with
`--config` or with `--data-dir` and `--master-key-file`. On the data of v0.3.0
and v0.1.0 it exited 0 with an empty diff (9 root inputs and 10 turns in the
compatibility data) and wrote `<data-dir>/upgrade/<engine>.json`, here
`kronik-0.4.1-dev+wasmtime-50.0.1.json` for the engines
`kronik-0.3.0+wasmtime-50.0.0` and `kronik-0.1.0-dev+wasmtime-50.0.0`. These
errors exited 1, and none of them wrote a report:

- `MASTER_KEY_MISSING`: no key where the node looks (`--master-key-file`,
  `[keys] master_key_file`, else `<data-dir>/keys/master.key`) and no
  `KRONIK_MASTER_KEY`, while `keys/` holds encrypted stores;
- `MASTER_KEY_MISMATCH`: a key was found, but `keys/secrets.db` was encrypted
  under another one;
- `BAD_REQUEST`: `KRONIK_MASTER_KEY` is set and a key file is configured as well
  (the message says that they conflict). A `--window` that is not a duration and
  a directory with no log gave `BAD_REQUEST` too.

The key, given in each of four ways (the environment variable, `[keys]
master_key_file`, `--master-key-file`, the default path), gave the same report
on v0.4.0 data; the first two were also tried on v0.3.0 and v0.1.0. The check
changed no file that existed. It added SQLite `-shm` and `-wal` files, a
compiled-code cache named for the new engine in `code/`, and the report.

**A start without a passing check.** The new binary stopped with exit 1 and
`ENGINE_VERSION_MISMATCH: the data was last written by engine … and this binary
is …; check the upgrade first with this binary: kronik upgrade check …`, before
it served anything and without creating `upgrade/`. On the data of v0.3.0 and
v0.1.0 it had by then already changed the databases: it added tables to
`keys/secrets.db`, `keys/keystore.db` and `branches/main/state.db`, rewrote
`state.db` and created `foreign/actors/.layout`. (On v0.4.0 data only an SQLite
`-shm` file changed.) The published v0.3.0 binary still started on one such copy
and answered `history` and a send. That was tried once; it is not a promise that
going back after a refused start is safe. Start the new binary only after the
check has passed.

**What happens.** After a passing check the start succeeds and records the
upgrade. From then on, for as long as it was watched (two minutes at a time, and
across one restart):

- The start is slower. The node tries to certify the secret inventory 50 times,
  about 13 ms apart, and logs each try as `startup secret inventory
  certification retry … SECRET_UNAVAILABLE`. Health answered after 0.8 s instead
  of 0.1 s in the debug build that was used.
- `kronik history`, `actors inspect`, `grants list`, `dead-letters list`, `token
  list`, `audit show`, `trace`, `proposals list`, `foreign list` and `secret
  history` answer 503 `SECRET_UNAVAILABLE`. Those ten were run. Reading a turn
  by id, which [the section on external
  backends](#secrets-that-an-external-backend-no-longer-serves) also lists, was
  not.
- `kronik deployments list` answers, but every REASON reads `[withheld: secrets
  could not be loaded]`.
- Sending messages and running turns work, and so do `actors list`, `secret
  list`, `secret backends`, `limits show`, `keys status`, `policy show`,
  `snapshot list`, `integrity` and the health check. `kronik upgrade check` run
  against the running node still passes.
- `kronik secret backends` shows `false` in the INVENTORY COMPLETE column.
- `kronik snapshot create`, `token create`, `fork create` and `replay` each took
  about 7 s (7.0 to 7.1 s) and wrote between 560 and 660 `secret rebuild failed`
  lines to the log. What makes them wait was not examined. Each of ten reads
  that answered 503, one a second, wrote one such line, and a node that nobody
  asked anything wrote one about every 8 s. The log never shows `secret
  inventory certified`.
- A restart changed nothing. Neither did the way the key was given (the
  environment variable and a key file were both tried).

The error is the generic one. Its hint, "Check `kronik doctor`, the secret
backend and access to retained versions", does not point at this cause: no
external backend is involved.

**How it arises.** The views remove secret values from what they show, so the
node certifies the inventory of the secret versions it retains before it answers
a read that needs scrubbing. For that it reads every retained snapshot. A
snapshot that v0.3.0 or older wrote has no `secret_versions` table, the version
ledger (the snapshots in the v0.3.0 and v0.1.0 data lack it; those in the v0.4.0
data and the ones the new binary wrote have it). The node cannot certify an
inventory with such a snapshot in it, so it fails closed. `kronik --json
snapshot list` shows which engine wrote each snapshot (`engine_version`).

**What ends it.** The node certifies, and the reads answer 200 without a
restart, as soon as retention has deleted the last snapshot that v0.3.0 or older
wrote. Retention runs after each snapshot. It keeps the newest `snapshots_kept`
(48 by default) and, when the log no longer starts at LSN 1, also the oldest
snapshot that the log still continues from, because a replay of the log begins
there; see [Snapshots and retention](#snapshots-and-retention). So the start of
the log decides which of two cases a node is in. `kronik integrity` prints it as
`Log first LSN` (`log_first_lsn` in `--json`), for example `Log first LSN 1` on
the v0.3.0 and v0.1.0 data of the compatibility tests and `Log first LSN 57` on
the compacted copy described below.

*The log starts at LSN 1.* This is a young node, or one whose log is younger
than `[retention] history`. Nothing is kept beyond the newest `snapshots_kept`,
so the wait is 48 snapshots of activity, not 48 hours. A snapshot is taken only
when something was applied since the last one: at most every `snapshot_interval`
(60 minutes), at a shutdown, or on request. A node that changes every hour needs
about 48 hours, one that changes once a day needs 48 days, and one that never
changes does not get there.

Two ways to end it earlier were run on copies of the v0.3.0 and v0.1.0 data.
Both use only documented settings and commands. Neither is a recommendation, and
both delete restore points.

1. Keep one snapshot. Set, in `kronik.toml`,

   ```toml
   [retention]
   snapshots_kept = 1
   ```

   restart the daemon, and run `kronik snapshot create --reason "..."` once.
   After the restart the reads still answered 503. The create returned in 0.06 s
   on the v0.3.0 data and in 0.4 s on the v0.1.0 data. Retention then deleted
   every older snapshot, so that the copy held only the one just taken; the log
   showed `secret inventory certified` (`from=1 through=24 records=24`,
   `elapsed_ms=2` and `20`) 6 ms and 56 ms after the `snapshot taken` line, and
   the first read after the command answered 200. Then put the setting back
   (remove the two lines) and restart. While it is 1, every later snapshot, the
   one at each shutdown included, deletes all but the newest. After that restart
   the node certified at start and the reads answered 200.

   Consequence: every older snapshot is gone, and with it every restore point
   and every base for a fork, replay or proposal before the newest snapshot.
   With `[ship]` on, snapshots that retention deletes locally are deleted from
   the bucket too, as [the section on shipping](#shipping-to-object-storage)
   says; that was not tried here. On the compatibility data, whose log starts at
   LSN 1, `kronik fork create --at 22` still worked afterwards.

2. Make 48 snapshots. A round was one `kronik send` to an actor (an `increment`
   of the counter actor in the compatibility data, so that something had
   changed) and one `kronik snapshot create --reason "..."`. 47 rounds were
   followed by 503 on `history` and the 48th by 200. That snapshot made
   retention delete the old one: the copy then held 48 snapshots, the oldest
   from round 1, and the log showed `secret inventory certified from=1
   through=165 records=165` (`elapsed_ms=39`). The 48 rounds took 352 s on the
   v0.3.0 data with the build used for this section, and about 354 s on the
   v0.3.0 and on the v0.1.0 data with the build before it, most of it the 7 s
   that each `snapshot create` waited in this state.

   Consequence: 48 more turns in the history of the actor you send to, 48
   snapshots on disk (each a copy of the whole state, about 172 KiB here), and
   whatever retention deletes beyond the newest 48, the old snapshot included.
   Do not run it on data whose history must not change.

*The log starts later.* This is a node whose log has been compacted, which with
the default `[retention] history = "7d"` is any node that has served for longer
than that. **Neither way above helps.** Both were run on a copy of a data
directory that the published v0.3.0 binary had written and compacted itself,
with small log segments and a very short history: `Log first LSN 57`, ten
snapshots from v0.3.0. `kronik upgrade check` passed (23 root
inputs, 23 turns) and the first start answered 503. With `snapshots_kept = 1`
and one `snapshot create`, retention deleted every snapshot but two, the new one
and the v0.3.0 snapshot at LSN 64, the oldest that the log continues from; the
reads still answered 503, also after the restart that put the setting back.
After 52 rounds of `kronik send` and `snapshot create` (48 are enough where the
log starts at LSN 1) every read still answered 503: the copy held 49 snapshots,
the newest 48 and the one at LSN 64, and the log still started at LSN 57. The 52
rounds took 385 s and the log got 32,596 `secret rebuild failed` lines.

What ends it there is the log itself: retention deletes the old snapshot when
compaction has moved the start of the log past the newest snapshot that v0.3.0
or older wrote, and 48 newer snapshots exist. Compaction deletes only closed
segments that are older than `[retention] history` and covered by a newer
snapshot, and the age is measured in logical time, so it needs new turns. On a
node that keeps working that is about one retention window after the node
stopped under v0.3.0 (7 days with the defaults); on a node that does nothing it
does not happen. This follows from the retention rule above and from the code;
no node was observed for a whole retention window. Waiting costs nothing beyond
what retention deletes anyway.

**What was not tried.** KMS key sources, sealed (privacy-mode) values, secrets
linked to an external backend, `[ship]`, and a check that finds a behavior
change (`ENGINE_UPGRADE_DIVERGED`). Waiting out a real retention window. A node
that has run v0.3.0 for days with its default snapshots, and states larger than
a few hundred KiB; every timing here comes from a debug build on small states.
Other values of `snapshots_kept`, deleting snapshot directories by hand, v0.2.0
(never published) and development builds.

## Foreign actors

Foreign actors are ordinary programs (OCI images) that run in gVisor
sandboxes next to the daemon. Kronik reaches them only through its bridge,
and they record their calls like other effects
([M7 design](../design/m7-foreign.md), [ADR 0003](../adr/0003-gvisor-bridge.md)).
They need:

- root (the systemd unit runs the daemon as root);
- `runsc` at `[foreign] runsc_path`, from `install.sh` or gVisor's
  instructions; `kronik doctor`'s `runsc`, `kvm`, `cgroup`, `netns`,
  `run_dir` and `sandbox` checks tell whether the host can run them;
- Linux 5.6 or newer with cgroup v2;
- `runc`, only for `--isolation trusted`.

They are managed with `kronik foreign add`, `list`, `logs` and `remove`
(see the [CLI reference](../reference/cli.md)). Declaring and removing them
is recorded history, like deployments. Without systemd, run `kronik
foreign cleanup` after the daemon crashed or was killed.

Where things are:

| Path | |
|---|---|
| `<data_dir>/foreign/blobs/` | Verified image layers, shared by all actors |
| `<data_dir>/foreign/actors/<name>/data/` | The actor's persistent `/data`, never replayed |
| `<data_dir>/foreign/actors/<name>/output.log` | The program's and runsc's stdout and stderr (`kronik foreign logs <name>`); the previous 8 MiB are in `output.log.1` |
| `<data_dir>/foreign/actors/<name>/checkpoints/<lsn>/` | `fork_mode = "sandbox"`: the gVisor checkpoint and a copy of `/data` at a snapshot's LSN (0700; local, never shipped). It holds the secret values the actor was given (its memory and `config.json`); rotating a secret does not change kept checkpoints |
| `<data_dir>/branches/<fork>/foreign/<name>/` | A fork's copy of the actor: its disk and runtime spec, deleted with the fork and at daemon start |
| `<run_dir>/runsc/`, `<run_dir>/netns/`, `<run_dir>/sock/` | runsc's state, the network namespaces and the bridge sockets |

The daemon starts every declared actor before it serves, and waits up to 30
seconds for them. An actor counts as running once its port accepts a
connection through the bridge. After an exit it restarts with a backoff of
0.5 s, doubling up to 60 s. An actor killed for exceeding its memory limit
shows as `oom` in `kronik foreign list` and in the daemon log. Sandboxes
never outlive the daemon: at start, the daemon removes whatever an earlier
run left behind.

Limits to know: no outbound network at all, inbound only through Kronik's
bridge; some syscalls and `/proc` files are missing in gVisor; file I/O is
slower than native; registry pulls are anonymous, so private images must be
copied into a local layout first (`skopeo copy` into `oci-layout:`). A
program can fill the disk through `/data`, which has no quota: put
`<data_dir>/foreign` on its own file system (or give it a quota) so the log
keeps its room. `[log] disk_reserve` refuses new work before the log's disk
is full, but sandboxes and running work keep writing, so on a shared file
system it only narrows the risk; `kronik foreign remove` still works below
it. `--isolation trusted` is not a security boundary. An image's setuid and
setgid bits are cleared when it is unpacked (the sticky bit stays): a
program that needs another user's rights through them won't get them.
A program in a sandbox that runs as root can still set them on files in
its `/data`, which lands them in `<data_dir>/foreign/actors/<name>/data`
(owned by root, beneath mode 0700 directories). Checkpoints and fork
copies clear them; the actor's own data keeps them, so don't copy that
tree with modes kept (`cp -a`, `tar -p`) to where others can reach it
([ADR 0027](../adr/0027-systemd-unit-hardening.md)). The
[M7 design](../design/m7-foreign.md) lists the rest.

## Previews

`kronik preview create <proposal>` starts a preview fork: main's HEAD with
the proposal's code, taking new requests at its own URL
([M11 design](../design/m11-preview.md),
[ADR 0025](../adr/0025-preview-forks.md)). The gateway sends a request to
a preview one way or the other, never both:

- **Host**, with `[gateway] preview_domain = "example-preview.com"`:
  `https://<id>.example-preview.com/<path>`, and only there. Point a
  wildcard DNS record (`*.example-preview.com`) at the gateway and give it
  a wildcard certificate for that name (ACME with `dns01_hook`, or a
  `files` certificate that covers it). The paths are the app's own, so
  absolute links in its pages work. Use a registrable domain of its own,
  not a subdomain of the production site: a sibling such as
  `preview.example.com` is the same site as `app.example.com`, so cookies
  for `Domain=example.com` reach the preview's code (see the
  [security model](security.md#api-access)). Host names match in any case,
  with or without a trailing dot; any host under the domain that is not a
  live preview answers `404 PREVIEW_NOT_FOUND`, never main.
- **Path prefix**, only without `preview_domain`:
  `<gateway>/__preview/<id>/<path>` goes to `<path>` of preview `<id>`.
  Nothing to set up; the prefix shadows any route of the actors that
  starts with `/__preview/`. The preview answers on the production origin,
  so Kronik drops the request's `Cookie`, `Authorization` and `Proxy-Authorization` headers
  (main's credentials) before the preview sees them, keeps only safe
  response headers (content type and length, caching, the turn id; no
  `Set-Cookie`, HSTS, `Clear-Site-Data`, NEL/Report-To or `Location`, so
  no redirects), and adds `Content-Security-Policy: sandbox`, which also
  blocks scripts and forms: single-page apps need a preview domain. Its
  pages' absolute links point at main. The URL names the
  first `[tls] domains` name, else the gateway's address (`0.0.0.0` as
  `127.0.0.1`).

An unknown or expired id answers `404 PREVIEW_NOT_FOUND`. A preview makes
no live effects but one: a fetch without a stub is denied, except a `GET`
without secret headers to a `[fork] live_allowlist` host, which goes out
live. Its `crypto.*` calls answer `no recording` (it gets no production
key), and `secrets.reveal` the placeholder. Its requests are not
deduplicated by `Idempotency-Key`. Timers its requests set never fire, and
neither do the timers pending at its fork point. The URL is reachable by
whoever reaches the gateway, so a preview that may read personal data (the
proposal's fork reads it, and the creator holds `pii:read`) shows the new
code's answers on real data to them; use `--no-pii` when that matters.
`kronik privacy erase` makes every preview start again from its fork
point at its next request, without the erased values.

Every request is a turn in `<data_dir>/branches/<id>/log/`, sealed like
main's, and shows as a preview input in `kronik diff show <id>`. A preview
takes one request at a time; requests to other previews and most operator
commands do not wait for it, but `kronik diff show <id>` and `kronik
preview delete <id>` wait for its request in flight. Once logged, a request's turns leave memory
(the diff keeps its count and its first 20 samples). A preview takes at
most 10,000 requests, then answers `409 PREVIEW_FULL` until it is deleted
(or restarted from its fork point after a restart or an erasure). At most 16 previews
live at once: the next `kronik preview create` answers `PREVIEW_LIMIT`.
Preview create and requests are refused below `[log] disk_reserve`, like
any new input. A preview is not a fork to change: `deploy --fork`,
`replay`, `send --fork` and `fork delete` refuse it. The daemon deletes a
preview (directory and routes) within a minute after `[fork] preview_ttl`
or `--ttl`, also after a restart, and deletes at start the directory of a
preview whose creation stopped half-way; `kronik preview delete` does it
at once. After a restart a preview's state starts again from its fork
point, and its next request replaces the log of the requests before the
restart.

## Troubleshooting

Every error names a code, and `kronik explain <CODE>` prints what it means
and what to do; the [error codes](../errors.md) list them all. The ones an
operator meets:

| Code | When | What to do |
|---|---|---|
| `BAD_REQUEST` at start | `kronik.toml` has an unknown key or a bad value | Fix the line the message names (`kronik doctor` checks the file too) |
| `STORAGE_CORRUPT` | The data directory is inconsistent: `state.db` is ahead of the log, or a log record can't be read. "state is at lsn N, but the log starts at M (compacted)": see [A start that stops at the log's start](#a-start-that-stops-at-the-logs-start) | Keep a copy of the data directory and look at the message. `state.db` is materialized from the log and can be rebuilt by moving it away and starting again; the log itself must not be edited |
| `UNAVAILABLE` | The node stopped after a storage failure (also `/healthz` 503) | The daemon exits and systemd restarts it; check the disk (`kronik doctor`'s `disk` check) and the journal |
| `GATEWAY_TIMEOUT` | A turn took longer than `[gateway] timeout` | The turn still completes; clients that retry with the same `Idempotency-Key` get its response |
| `PAYLOAD_TOO_LARGE` | A request body over 1 MiB | v0.1's limit |
| `REASON_REQUIRED` | A change without `--reason` | Every mutation is audited and needs a reason. `restore` and `upgrade check` write no log record, so they take no `--reason` |
| `ENGINE_UPGRADE_DIVERGED` | `kronik upgrade check` found a behavior change | Keep the current binary. The diff is next to the report in `<data-dir>/upgrade/` |
| `ENGINE_VERSION_MISMATCH` | A new binary started against data written by another engine, without a passing check | Run `kronik upgrade check --window 6h`, or start the recorded engine version. For data from v0.3.0 or older read [Upgrading from v0.3.0 or older](#upgrading-from-v030-or-older) first |
| `UNAUTHENTICATED`, `SCOPE_MISSING`, `TOKEN_NOT_FOUND` | A bearer token is missing, lacks the scope, or was revoked | `kronik token list`, `kronik token create --name <name> --scopes <scope>,... --reason ...`, on the socket as root or a member of `kronik` |
| `SECRET_NOT_FOUND` | An effect uses a secret that isn't set, or was deleted | `kronik secret set <name> --reason ...` |
| `SECRET_UNAVAILABLE` | A read answered 503 while the secret inventory was needed, or an effect failed inside a turn because its secret could not be fetched | For a read after a restart: the provider no longer serves a version that Kronik recorded, [a known defect](#secrets-that-an-external-backend-no-longer-serves). For a read after an upgrade of data written by v0.3.0 or older: a snapshot from those versions is still retained, [a known defect](#upgrading-from-v030-or-older). Or the rebuild of the inventory takes longer than `[secrets] refresh` and the daemon logs that it did not install its certificate: raise `refresh` above the `elapsed_ms` of the `secret inventory certified` line ([`[secrets]`](#secrets)). For an effect: the backend did not answer in time or refused, see [A turn whose effect cannot get its secret](#a-turn-whose-effect-cannot-get-its-secret) |
| `SECRET_VERSION_GONE` | A turn needed a secret version that its provider no longer serves, for example the re-run of a `secret.reveal` after the version was destroyed | The turn is recorded as failed before the guest runs, and no other version's value is used. See [the same section](#secrets-that-an-external-backend-no-longer-serves) for what else the lost version does |
| `RUNSC_MISSING`, `KVM_UNAVAILABLE`, `RUNC_MISSING`, `FOREIGN_UNAVAILABLE` | Foreign actors can't run | `kronik doctor` names the cause; see [Foreign actors](#foreign-actors) |
| `IMAGE_INVALID` | `kronik foreign add` got an image it can't verify or unpack | Check the reference; private images need a local layout |

If the daemon won't start, `journalctl -u kronik` shows why: the config
error with its line, a port already in use (another process on 443 or 80),
or `STORAGE_CORRUPT`. If `/metrics` is missing, the admin port was taken
(the log has a warning); set `admin_listen` to a free port.

### A start that stops at the log's start

`kronik serve` stops with `STORAGE_CORRUPT: state is at lsn N, but the log
starts at M (compacted); install a snapshot that reaches it or restore one`.
Nothing is lost: the data directory is as it was.

**What it means.** The start replays the log from the lowest applied LSN of
`state.db` and of every actor database, and an actor database's applied LSN
is where that actor's last change was. Retention deletes log older than
`[retention] history` (7 days by default). An actor with an SQL database that
has not changed for longer than that, for example one actor instance per
customer key that is idle for a week, is behind the log that is left, and the
start refuses. Releases up to and including v0.4.0 do this; a release with the
fix raises those databases before it deletes, and repairs a directory an older
release compacted, at the next start, from the newest snapshot (it logs
`installed a snapshot as the branch's state`).

**What to do on a release without the fix.**
- `kronik upgrade check` passes on such a directory; do not read it as a
  promise that the start works.
- A full restore from a backup or a shipped bucket that still has the
  records ([Restore](../runbooks/restore.md)), or the release with the fix.
- Before it happens: an actor with a single instance and an SQL database can
  be kept current by a heartbeat, a turn that changes its SQL more often than
  `history`. That does not scale to one instance per key.
- `snapshots_kept` does not help: more snapshots do not change what the actor
  databases say.
- Do not edit the databases or the log by hand: a wrong edit discards
  changes without a message. Keep a copy of the data directory and ask for
  help.

### Secrets that an external backend no longer serves

This is a known defect, not intended behavior. It concerns names linked to an
external backend with `kronik secret link`; secrets set with `kronik secret
set` were not part of these checks.

Kronik records each version of a linked secret that it observes, with the
provider's own id for it (`kronik secret history NAME`, column SOURCE
VERSION). The views remove secret values from what they show, so after a
restart the node fetches every recorded version again by that id. If the
provider no longer serves one of them, the node cannot complete that inventory
and fails closed: it answers 503 instead of showing data it cannot scrub.

**What happens.** From the first start after the version was lost, and for as
long as it was watched (minutes):

- `kronik history`, `actors inspect`, `trace`, `dead-letters list`,
  `grants list`, `audit show`, `proposals list`, `foreign list` and
  `secret history` answer 503 `SECRET_UNAVAILABLE`, and so does reading a turn
  by id;
- sending messages and running turns still work, and so do `actors list`,
  `secret list`, `secret backends`, `limits show`, `keys status`,
  `policy show` and the health check;
- `kronik secret refresh` and `kronik secret unlink` commit and then answer
  503 "already committed": do not repeat them;
- `kronik secret backends` shows `false` in the INVENTORY COMPLETE column;
- the daemon log repeats `secret rebuild failed code=SECRET_UNAVAILABLE`; its
  `failed_version` names the first retained version that the rebuild could not
  get, as `NAME@vN on BACKEND: reason` (others may follow once it is served
  again). The error that clients get does not name it.

A running node is not affected until it restarts: it still holds the value in
memory, so the loss can go unnoticed until the next start.

**How it arises.**

- An `env` secret whose variable was changed. The `env` backend reads its
  variables when the daemon starts, so a change is seen at the next start. The
  node then records the new value as the next version, and the old value,
  which the provider cannot serve any more, keeps the inventory incomplete.
- A KV version that the provider removed: destroyed by hand, or removed by the
  mount's version limit when newer versions were written. This was checked
  only against a local test server that answers 404 for such a version, as the
  client expects. A real OpenBao, its default version limit, soft deletion and
  undelete, and AWS, GCP and Azure were not tried.

**What ends it.** If the provider serves the version again, the reads come
back without a restart. This was checked four times with the test server,
from 15 seconds to two minutes after the start: the first read after the
version was served again still answered 503, and a read about a second later
was served. With no read in between, nothing changed in the 12 seconds
watched. An `env` variable holds one value, so it cannot serve an old value
together with the new one. These do not help (tried with the `env` backend and
with the test server):

- unlinking the name before changing the variable;
- putting the variable back after the node has started once with the new
  value, because that start recorded the new value as a version too;
- removing the backend from `kronik.toml`;
- `kronik secret refresh` and `kronik secret unlink` on the affected node.

No other repair is known.

**Preventing it.**

- Keep every version with PHASE `active` in `kronik secret history NAME`
  readable at the provider. Do not destroy such a version, and check how many
  versions the mount keeps against how often the secret changes.
- Never change the value of an `env` variable that a linked name has used. To
  rotate such a secret, add a variable next to the old one: define the new
  variable in the daemon's environment (its name must start with one of the
  backend's `allowed_refs`), keep the old variable unchanged, restart the
  daemon, then link the name to the new variable with `kronik secret link NAME
  --backend ID --ref NEW_VARIABLE --reason "..."`. The old variable has to stay
  defined with its old value: unsetting it brings the 503 back (checked).

### A turn whose effect cannot get its secret

This is intended behavior. An effect that needs a secret from an external
backend fails with `SECRET_UNAVAILABLE` inside its turn when the node holds no
value for it and cannot get one: the backend does not answer within
`[secrets] fetch_timeout` (default 2 s), or it refuses (bad credentials, an
answer that Kronik cannot use), or the configuration no longer has the backend
that the link names. The guest is told the same in every case; the log says
which.

- The error is recorded in the turn before the guest sees it, as for a network
  error: the turn is in `kronik history ACTOR`, and its effect carries the
  status (`network` for `http.fetch`, `denied` for `crypto.*` and
  `secrets.reveal`) and the error. Nothing was sent to the target.
- The guest decides. A handler that fails ends the turn as failed: an HTTP
  client gets 500 `TURN_FAILED`, `kronik send` reports the failed outcome, and
  a failed message or timer is a dead letter. A handler that handles the error
  commits and answers as it chooses. The request is not answered 503, and the
  secret no longer leaves a turn open to run again at the next start.
- A client that repeats the request with the same `Idempotency-Key` gets the
  recorded answer until `[gateway] idempotency_ttl` has passed, and nothing is
  sent. To try again, use a new key. For a dead letter, wait until the backend
  answers, then `kronik dead-letters resend ID --reason "..."`.
- The log has one warning, `secret fetch failed`, with the name of the secret,
  the id of the backend, the version asked for (`current`, or the provider's
  own id of a recorded one) and a reason: `unavailable` (no answer in time),
  `denied` (the backend refused: check the credentials and the policy),
  `invalid` (an answer that Kronik cannot use) or `binding` (the configuration
  no longer has the backend, or not the same). It comes once for each 5 s in
  which the failure is remembered, whoever asked, a turn or the background
  refresh, and never has a body, a credential or a value. Fix the cause, then
  resend the dead letters.
- Turns that need no external secret, or whose secret the node holds, run as
  usual during the outage. After a crash, a turn that had not yet got its
  secret waits for an outage to end and then runs, except an effect of an
  `unsafe` grant, which a re-run ends as outcome unknown whatever the secret
  does; one that had recorded the error ends with it. A refusal does not pass
  while a turn waits, so a turn that met one after a crash records it like a
  live turn does.
- A failure is remembered for 5 s, so that a burst of turns does not queue on
  a dead backend. Right after the backend is back, effects can still fail for
  up to 5 s. A dead letter that is resent in that window can fail again and
  then makes one more dead letter; nothing is lost, resend that one.
- A failed timer's turn is a failed turn like any other: what it buffered is
  discarded, the next timer it set included. A timer that sets its next timer
  stops after such a failure until the dead letter is resent; a handler that
  handles the error and commits keeps the chain going.
