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
3. It creates the master key `/etc/kronik/master.key` (32 random bytes from
   `/dev/urandom`, mode 0600). See [the master key](#the-master-key).
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
| `admin_listen` | `"127.0.0.1:9464"` | `/metrics` and `/healthz`. If the port can't be bound, the daemon logs a warning and runs without them | `--admin-listen`, `KRONIK_ADMIN_LISTEN` |
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
| `master_key_file` | `<data_dir>/keys/master.key` (`--init` writes `/etc/kronik/master.key`) | The master key of the secret store and the privacy keystore. Not read when `KRONIK_MASTER_KEY` is set | `--master-key-file`, `KRONIK_MASTER_KEY_FILE` |

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
Kronik has no DNS provider built in. The owner provides a hook, a program
that writes and deletes that TXT record through the DNS host's API (see
[ADR 0026](../adr/0026-dns01-exec-hook.md)). Without a hook there is no
wildcard certificate, so `mode = "acme"` with `preview_domain` and no hook
is refused at start; leave `preview_domain` unset and preview forks use the
path prefix `/__preview/<id>` on the main name.

The owner provides:

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

On `admin_listen` (`127.0.0.1:9464` by default; keep it local or behind a
firewall):

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
(`kronik.audit/v1`) per audited record to the sink, in log order, at least
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
`restore` line marks the point. The first start after a restore moves
every export cursor in `export.json` back to the restored log (with the
export on or off), so the `restore` line and everything after it are
exported; no sink overwrites the lines it got before.

- **A directory** (`file:///var/log/kronik/audit/`): lines go to
  `audit-<first lsn>.jsonl` files (mode 0640), fsynced before the cursor
  moves; a new file starts at `file_max_bytes`, as
  `audit-<first lsn>.<n>.jsonl` when that name is taken (LSNs repeat after
  a restore or a rewind). A start truncates a line a
  crash left half written. Kronik never deletes these files: rotation is
  yours: compress, move or copy to cold storage what you like. When the
  newest file is moved away, replaced by another (logrotate's `create`) or
  truncated (`copytruncate`), the next batch starts a new file. Keep what
  `kronik audit verify` should still check. The unit's
  `LogsDirectory=kronik` makes `/var/log/kronik` writable; another
  directory needs `ReadWritePaths=`.
- **A webhook** (`https://…`): one POST per batch,
  `application/x-ndjson`, with `kronik-audit-range: <first>-<last>` and
  `idempotency-key: <first>-<last>-<hash of the body>` headers, so a batch
  with other lines over the same range is never answered from the
  receiver's cache; credentials through `headers_env`. Anything but
  a 2xx is retried with backoff (a 4xx other than 408 and 429 also logs a
  warning): audit lines are never dropped on the sink's say-so.
- **Object storage** (`s3://bucket/prefix`, with `endpoint` and the
  `AWS_*` variables as for shipping): one object per batch,
  `<prefix>/audit/<prepared ms>-<first>-<last>.jsonl`, the wall time the
  batch was prepared first, so names sort in write order; a retried batch
  overwrites itself.

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

**What leaves the node** (ADR 0082): the line's action, token id, reason,
wall time, epoch, record hash and plain facts (kinds and code hashes,
capabilities, limits, policy rule names and hash, secret and token names,
fork and proposal ids, a foreign image's digest). Never a secret value, a
token, a message body, a subject id or a sealed value: a subject is `s:`
plus 12 hex of its keyed hash, actor keys follow `[otel] actor_keys`.
**Reasons leave the node as written**, minus exact secret values (removed
when the reason is written, so a secret deleted later stays out too) and
an erasure's subject id: do not put personal data in a `--reason`.

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

The master key encrypts the secret store (`<data_dir>/keys/secrets.db`) and
the privacy keystore (`<data_dir>/keys/keystore.db`). It is 32 random bytes
in hex, in `[keys] master_key_file`, mode 0600: `/etc/kronik/master.key`
when `kronik serve --init` set up the host, or `<data_dir>/keys/master.key`,
which `kronik serve` creates at the first start if it is missing (and logs
a warning saying so).

The key can also come from the environment: `KRONIK_MASTER_KEY` holds the 64
hex characters themselves, the way a secret manager hands the key to the
daemon (a systemd `Environment=` line, a container's environment). When it is
set, it is the key: no key file is read or created, not even at the first
start. The value is never logged. Material that is not 64 hex characters
stops `kronik serve` with an error. Setting `KRONIK_MASTER_KEY` together with
a key file (`--master-key-file`, `KRONIK_MASTER_KEY_FILE` or
`[keys] master_key_file`) also stops the start, so a stale file can never
silently win over the material; remove one of the two.

- **Back it up separately**, somewhere offline, and not next to backups of
  the data directory. A copy of the data directory without the key reveals
  no secret values or sealed personal data, and that is the point.
- **It is never shipped** or copied anywhere by Kronik: child processes,
  the DNS-01 hook included, don't inherit `KRONIK_MASTER_KEY`.
- **Losing it** loses every secret value and every sealed value: the stores
  can't be decrypted without it. There is no recovery.
- **No new key over existing stores.** `kronik serve` makes a key only for a
  data directory without stores. When the key is missing and
  `keys/secrets.db` or `keys/keystore.db` exists, it stops with
  `MASTER_KEY_MISSING`; with another key than theirs, with
  `MASTER_KEY_MISMATCH` (each store records which key it belongs to). Put
  the right key back, or, if it is lost for good, move both files aside to
  start over without those secrets and sealed values.
- **Shipping and restore use the same key source** as `kronik serve`: the
  configured file or `KRONIK_MASTER_KEY`. `kronik restore` takes
  `--master-key-file` (or the configuration file's `[keys]`) and needs the
  key in place *before* it runs: with a privacy keystore backup in the
  bucket and no key (or another key), it fails without writing anything,
  unless `--without-keystore`.
- v0.1 has no command that rotates the master key.

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
until a later turn has aged out of the window too.

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
- **What is never uploaded:** the master key. Snapshots carry the secret
  store encrypted under it, so keep the key's own backup separate (see
  [the master key](#the-master-key)). Forks and proposals, with their
  diffs (`<data_dir>/branches/<name>/`), are not uploaded either: they stay
  in the old data directory.
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
the diff it was given for (`diff_hash`). Copy the master key into place
before serving if secrets must be readable; it is not in the bucket. In a
checkout of the repository, `demo/vps-restore.sh` does this with two data
directories and one bucket (`scripts/minio.sh demo/vps-restore.sh` runs it
against a local MinIO in Docker).

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
anything, and loses nothing. So an upgrade, for example from a 0.1.0-dev
build to 0.3.0, is three steps:

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
the master key that `kronik serve` uses (`--config`, `--master-key-file`,
`KRONIK_MASTER_KEY` or `<data-dir>/keys/master.key`), so sealed values in
the window replay too. An empty diff writes `<data-dir>/upgrade/<engine>.json`
and exits 0. A diff that is not empty writes that report and the diff next
to it (`<engine>.diff.json`) and exits 1 with `ENGINE_UPGRADE_DIVERGED`:
keep the current binary. `--dry-run` prints the result and writes neither
file. A bad window or a directory with no log is `BAD_REQUEST`.

After the restart the data is the new engine's. Going back to the old
binary is the same procedure the other way: its own `kronik upgrade check`
first. A restore from a bucket that an older binary shipped also needs the
check before the restored directory's first start.

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
| `STORAGE_CORRUPT` | The data directory is inconsistent: `state.db` is ahead of the log, or a log record can't be read | Keep a copy of the data directory and look at the message. `state.db` is materialized from the log and can be rebuilt by moving it away and starting again; the log itself must not be edited |
| `UNAVAILABLE` | The node stopped after a storage failure (also `/healthz` 503) | The daemon exits and systemd restarts it; check the disk (`kronik doctor`'s `disk` check) and the journal |
| `GATEWAY_TIMEOUT` | A turn took longer than `[gateway] timeout` | The turn still completes; clients that retry with the same `Idempotency-Key` get its response |
| `PAYLOAD_TOO_LARGE` | A request body over 1 MiB | v0.1's limit |
| `REASON_REQUIRED` | A change without `--reason` | Every mutation is audited and needs a reason. `restore` and `upgrade check` write no log record, so they take no `--reason` |
| `ENGINE_UPGRADE_DIVERGED` | `kronik upgrade check` found a behavior change | Keep the current binary. The diff is next to the report in `<data-dir>/upgrade/` |
| `ENGINE_VERSION_MISMATCH` | A new binary started against data written by another engine, without a passing check | Run `kronik upgrade check --window 6h`, or start the recorded engine version |
| `UNAUTHENTICATED`, `SCOPE_MISSING`, `TOKEN_NOT_FOUND` | A bearer token is missing, lacks the scope, or was revoked | `kronik token list`, `kronik token create --name <name> --scopes <scope>,... --reason ...`, on the socket as root or a member of `kronik` |
| `SECRET_NOT_FOUND` | An effect uses a secret that isn't set, or was deleted | `kronik secret set <name> --reason ...` |
| `RUNSC_MISSING`, `KVM_UNAVAILABLE`, `RUNC_MISSING`, `FOREIGN_UNAVAILABLE` | Foreign actors can't run | `kronik doctor` names the cause; see [Foreign actors](#foreign-actors) |
| `IMAGE_INVALID` | `kronik foreign add` got an image it can't verify or unpack | Check the reference; private images need a local layout |

If the daemon won't start, `journalctl -u kronik` shows why: the config
error with its line, a port already in use (another process on 443 or 80),
or `STORAGE_CORRUPT`. If `/metrics` is missing, the admin port was taken
(the log has a warning); set `admin_listen` to a free port.
