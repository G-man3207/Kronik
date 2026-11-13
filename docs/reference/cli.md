# CLI reference

The `kronik` binary runs the daemon (`kronik serve`) and the client commands
that talk to it. Client commands call the JSON API on the daemon's Unix
socket (`/v1`, see [M1 core design](../design/m1-core.md) §4 and
[M2 effects design](../design/m2-effects.md) §8). `kronik explain`,
`kronik doctor`, `kronik keys wrap`, `kronik restore` and
`kronik upgrade check` work without a daemon.

Commands have the brief's form `kronik <noun> <verb>`, such as
`kronik actors list` and `kronik secret set`; the golden path's verbs
(`deploy`, `send`, `grant`, `revoke`) stand on their own. Human output is
short, in English, and ends with the exact next commands under `Next`.
Placeholders such as `<key>` and `"..."` are yours to fill in. The examples
on this page come from a daemon whose gateway listens on `127.0.0.1:8080`,
except where a sample names another address.

## Global options

| Option | Meaning |
| --- | --- |
| `--socket <PATH>` | The daemon's API socket. Default: `$KRONIK_API_SOCKET`, else `server.api_socket` in `/etc/kronik/kronik.toml` when that file exists, else `/run/kronik/api.sock` (the same as `kronik serve`). Not with `--url`. |
| `--url <URL>` | A remote API (M10): `https://host:port`, the daemon's `server.api_listen` with TLS on. The port is required: 443 or 80 is usually the gateway, which would record the token with the request. Default: `$KRONIK_URL`. Plain `http://` is accepted only to `localhost` or a loopback address; anything else is refused before a connection is made, so a token never crosses a network in the clear. `localhost` is never looked up: the CLI dials `[::1]`, then `127.0.0.1` (RFC 6761), and over plain HTTP it dials only loopback addresses. The scheme is lower case. An error about the URL names only its scheme, host and port, never user info, a path or a query. |
| `--token <TOKEN>` | The ordinary API bearer. Default: `$KRONIK_TOKEN`, preferred because flags appear in shell history and process listings. A blank explicit bearer is refused. Within `fleet`, use `--api-token` for this bearer; `fleet enroll --token` is the distinct one-time enrollment credential. `kronik mcp` also accepts the ordinary bearer. |
| `--json` | Print the unchanged API response or local result, and stable error JSON on failure. `events tail` instead writes NDJSON event envelopes and a final typed resume checkpoint. Other commands print one object; non-API error responses become `UNAVAILABLE`. [JSON output](json.md) gives the schemas and [openapi.json](openapi.json) the API. A command that reports an outcome that is not an error with exit 1, such as `upgrade check`, `doctor`, `send` or `integrity`, prints its own object, not the error JSON; [JSON output](json.md) lists them. |

They can go before or after the command: `kronik --json actors list` and
`kronik actors list --json` are the same. `kronik serve` takes none of
them and refuses them; it has `--api-socket`. `init`, `build`, `doctor`,
`keys wrap`, `restore` and `upgrade` do not talk to the API: they refuse
`--url` and `--token` (exit 2) rather than ignore them. `kronik mcp` takes `--socket`
and `--token` and refuses `--url`, and `$KRONIK_URL` without `--socket`
(see [kronik mcp](#kronik-mcp)).

The CLI talks to `--url`, else `--socket`, else `$KRONIK_URL`, else the
socket. Over TLS it trusts the system's root certificates; for a private
CA, point `SSL_CERT_FILE` at its bundle. A certificate the CLI does not
trust, or one for another name, fails with `UNAVAILABLE` ("TLS to … failed")
before anything is sent ([ADR 0021](../adr/0021-remote-cli.md)). Plain
HTTP to a loopback port authenticates nothing: on a host shared with other
users, one of them can bind that port while the daemon is down and collect
the tokens sent to it; prefer the socket or TLS there.

Every request has timeouts: the connection must be made within 30
seconds, and the daemon may stay silent for at most one hour (the longest
a sync replay or a promote's catch-up may take), so a dead connection fails
with `UNAVAILABLE` instead of hanging. [kronik proposal
wait](#kronik-proposal-wait) bounds every poll by its `--timeout`.

When a command was given `--url`, the commands under `Next` are printed
without it, followed by one reminder line: `(each with --url <url>, or
export KRONIK_URL=<url>)`. An error whose hint names a command gets the
same reminder after it: `(the hint's command with --url <url>, or export
KRONIK_URL=<url>)` (not with `--json`).

```text
$ export KRONIK_URL=https://kronik.example.com:7443 KRONIK_TOKEN=<token>
$ kronik actors list
```

A token (`--token` or `$KRONIK_TOKEN`) is sent as `Authorization: Bearer
<token>` with every request (M5): the command acts as that token, with its
scopes, and the history records `token:<name>` with each change (see
[kronik token create](#kronik-token-create)). The remote API needs one;
without one, the socket's caller has every scope and is recorded as
`unix:uid=<n>`. A value with spaces, control characters or non-ASCII bytes
is refused before anything is sent. Prefer `$KRONIK_TOKEN` (or a CI secret
in the environment) to `--token`.

Every mutation (`deploy`, `send`, `dead-letters resend`, `grant`, `revoke`,
`limits set`, `secret set`, `secret delete`, `secret link`, `secret unlink`,
`secret refresh`, `fork create`, `fork deploy`, `fork delete`, `propose`,
`approve`, `promote`, `rollback`, `watch`, `watches stop`, `policy set`,
`preview create`, `preview delete`, `foreign add`, `foreign remove`,
`stubs set`, `privacy mode`, `privacy erase`, `privacy reseal`, `keys wrap`,
`keys rewrap`, `token create`, `token revoke`, `snapshot create`,
`export rewind`, `fleet enroll`, `fleet revoke`,
`events webhooks replay`) requires `--reason`,
which the history records with the change, and supports `--dry-run`, which
checks the request and writes nothing (I12). `replay` writes only in its
fork, and `send --fork` only in the fork; both require `--reason` and have
no dry run. A missing or blank reason fails with `REASON_REQUIRED` before
anything is sent. `restore` and `upgrade check` are offline: they write no
log record, so they take no `--reason`. Both support `--dry-run`, which
prints the plan or the result and writes nothing.

## Exit codes and errors

| Exit code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | An error, a turn that did not commit (`send`, `dead-letters resend`), or `upgrade check` finding a behavior change (`ENGINE_UPGRADE_DIVERGED`). |
| 2 | Invalid arguments (printed by the argument parser). |

An error prints its code, message, hint and documentation command on
stderr; with `--json` it prints the standard error JSON on stdout instead
(see `docs/errors.md`):

```text
$ kronik actors inspect counter/zzz
error: ACTOR_NOT_FOUND: actor counter/zzz has no turns
hint:  Check the kind and key with `kronik actors list`.
docs:  kronik explain ACTOR_NOT_FOUND

$ kronik --json actors inspect counter/zzz
{"error":{"code":"ACTOR_NOT_FOUND","docs":"kronik explain ACTOR_NOT_FOUND","hint":"Check the kind and key with `kronik actors list`.","message":"actor counter/zzz has no turns"}}
```

When no daemon listens on the socket, client commands fail with
`UNAVAILABLE` and say how to start one:

```text
$ kronik actors list
error: UNAVAILABLE: no Kronik daemon is listening on /run/kronik/api.sock
hint:  Start the daemon with `kronik serve --api-socket /run/kronik/api.sock`, or pass its socket with `--socket <path>`.
docs:  kronik explain UNAVAILABLE
```

## kronik serve

Runs the daemon: it recovers from the log in the data directory, serves the
gateway (HTTP), the JSON API (Unix socket, mode 0660, and optionally TCP)
and `/metrics` and `/healthz`, and stops on SIGTERM or Ctrl-C. It reads the
configuration file `/etc/kronik/kronik.toml` when that exists, or the file
named by `--config` (`$KRONIK_CONFIG`); an unknown key or an invalid value
stops it with the file and the line. The flags override the file, and
without a file the defaults below apply.

| Option | Key in the file | Default |
| --- | --- | --- |
| `--config <PATH>` | | `/etc/kronik/kronik.toml` if it exists; `$KRONIK_CONFIG` |
| `--data-dir <DIR>` | `server.data_dir` | `/var/lib/kronik`; `$KRONIK_DATA_DIR` |
| `--http-listen <ADDR>` | `server.http_listen` | `127.0.0.1:8080`; `$KRONIK_HTTP_LISTEN` |
| `--api-socket <PATH>` | `server.api_socket` | `/run/kronik/api.sock`; `$KRONIK_API_SOCKET` |
| `--api-listen <ADDR>` | `server.api_listen` | off; `$KRONIK_API_LISTEN` (the JSON API and MCP over TCP, every request with a bearer token) |
| `--admin-listen <ADDR>` | `server.admin_listen` | `127.0.0.1:9464`; `$KRONIK_ADMIN_LISTEN` (`/metrics` and `/healthz`) |
| `--gateway-timeout-ms <MS>` | `gateway.timeout` | 30 seconds |
| `--master-key-file <PATH>` | `keys.master_key_file` | For the file source: `<data dir>/keys/master.key`; `$KRONIK_MASTER_KEY_FILE`. `$KRONIK_MASTER_KEY`, when set, is the key itself (64 hex characters) and no file is read or created. File flags and the variable conflict; KMS sources refuse both. Configure KMS with `[keys] source` and its provider table, not this flag |
| `--disk-reserve <SIZE>` | `log.disk_reserve` | `512MiB`; `$KRONIK_DISK_RESERVE`. Below this much free space new inputs and changes are refused; `0B` turns it off |
| `--otel-endpoint <URL>` | `otel.endpoint` | off; `$KRONIK_OTEL_ENDPOINT` (an OTLP/HTTP collector for spans and metrics, M28) |
| `--concurrency <N>` | | `64` |
| `--log-format text\|json` | | `text`; `$KRONIK_LOG_FORMAT` (`json`: one JSON object per line) |

`kronik serve --help` lists every option.

```text
$ kronik serve --data-dir /var/lib/kronik
```

**The API over TCP (M5).** With `--api-listen`, the JSON API and the MCP
endpoint `/mcp` also listen on TCP, where every request needs
`Authorization: Bearer <token>`; without one, or with an unknown or revoked
token, the answer is 401 `UNAUTHENTICATED`. Tokens come from
[`kronik token create`](#kronik-token-create) and live as hashes in
`<data dir>/keys/tokens.db` (mode 0600). With `[tls]` in the file the TCP
API uses the gateway's certificate; without TLS only a loopback address is
accepted, so that tokens never cross a network in the clear:

```text
$ kronik serve --api-listen 0.0.0.0:7443
2026-10-25T05:51:41.350726Z ERROR kronik: kronik serve stopped error="server.api_listen = \"0.0.0.0:7443\" is not a loopback address and [tls] is off: bearer tokens would cross the network in the clear; turn TLS on or listen on 127.0.0.1"
```

**Metrics and health (M6).** `GET /healthz` on the admin address answers
200 with `{"applied_lsn","status":"ok"}` while the node runs (plus
`"low_disk":true` below `[log] disk_reserve`), and 503 after a storage
failure. `GET /metrics` gives the Prometheus text format. When the admin
port is taken, Kronik serves anyway and logs a warning.

```text
$ curl -s http://127.0.0.1:9464/healthz
{"applied_lsn":1,"status":"ok"}
```

| Metric | Type | What it counts |
| --- | --- | --- |
| `kronik_build_info` | gauge | Always 1; the labels name the Kronik version and the engine. |
| `kronik_applied_lsn` | gauge | The last log sequence number applied to the materialized state. |
| `kronik_disk_free_bytes` | gauge | Free bytes on the log's file system (when [log] disk_reserve is set). |
| `kronik_disk_below_reserve` | gauge | 1 while the log's file system is below [log] disk_reserve: new inputs and changes are refused. |
| `kronik_key_source_up` | gauge | 1 when the daemon loaded its master key through its key source ([keys] source); 0 without a secret store. |
| `kronik_secret_recovery_stalled` | gauge | Re-runs of open turns waiting for a recorded secret value or for an unavailable prerequisite. |
| `kronik_retention_open_turn_segments` | gauge | Closed log segments that the last retention pass kept only for an open turn, by source (live: open in the running state; snapshot: held open by a kept snapshot). |
| `kronik_secret_fetch_total` | counter | Requests to external secret backends, by backend and result (ok, unavailable, denied, not_found, version_gone, invalid, cancelled). |
| `kronik_secret_fetch_seconds` | histogram | Time an external secret backend took to answer, or until the request gave up, by backend. |
| `kronik_secret_stale` | gauge | 1 while effects use a secret's cached value past [secrets] refresh because its backend does not answer, by secret name. |
| `kronik_secret_versions_total` | counter | Secret versions this node recorded, by backend (file for the built-in store). |
| `kronik_turns_total` | counter | Turns recorded, by actor kind and outcome. |
| `kronik_turn_duration_seconds` | histogram | Time from the start of a turn to its record, by actor kind. |
| `kronik_log_records_appended_total` | counter | Records written to the log. |
| `kronik_log_fsync_duration_seconds` | histogram | Time to fsync a group commit of the log. |
| `kronik_effects_total` | counter | Effect results recorded, by effect kind and status. |
| `kronik_gateway_requests_total` | counter | HTTP requests answered by the gateway, by status code. |
| `kronik_gateway_request_duration_seconds` | histogram | Time to answer an HTTP request at the gateway, by status code. |
| `kronik_replay_runs_total` | counter | Replays run for forks and proposals, by mode. |
| `kronik_fork_crypto_computations_total` | counter | Unmatched crypto effects a fork computed on the host, by algorithm. The key is not a label. |
| `kronik_guard_triggered_total` | counter | Guards of `kronik watch` that fired, by action and outcome. |
| `kronik_export_records_total` | counter | Log records an export stream delivered (or skipped), by stream. |
| `kronik_export_lag_records` | gauge | Committed records an export stream has not delivered yet, by stream. |
| `kronik_export_errors_total` | counter | Failed export attempts (retried), by stream. |
| `kronik_export_dropped_total` | counter | Records in batches the sink refused for good and the export skipped, by stream. |
| `kronik_export_gaps_total` | counter | Log ranges retention deleted before an export stream read them, by stream. |

`kronik serve --init [--domain <NAME>]... [--acme-email <EMAIL>] [--dry-run]`
sets a host up, as root (M6): it writes the configuration file, creates the
data directory, the master key (mode 0600) and the `kronik` group, and
installs, enables and starts the systemd unit `deploy/systemd/kronik.service`,
which runs the daemon with the group `kronik`, so the API socket is open to
that group. With `--domain` the file asks for a TLS certificate by ACME for
those names (`--acme-email` receives the CA's notices); without it the
gateway serves plain HTTP on port 80. Each step checks the host first, so
running it again changes nothing, and `--dry-run` prints the plan.

## kronik doctor

`kronik doctor [--config <PATH>]`

Checks what this host can run (M6): the configuration file, the kernel,
gVisor's `runsc`, KVM, cgroups, whether it runs as root, and for foreign
actors `runc`, network namespaces, the run directory and a sandbox; then
free disk for the data directory, clock synchronization, the TLS
certificate, shipping and the master key's source; and, from a daemon that
answers on the API socket, its export streams, its secret backends and
whether an open turn keeps the log past `[retention] history` (`retention`).
Each check passes, warns or fails. A failure
includes a catalog code and a hint; a pass or a warning may omit a hint.
The checks of what only foreign actors need warn rather than fail, unless
the configuration asks for what is missing (`platform = "kvm"`); the
[operations guide](../guides/operations.md#kronik-doctor) lists them all.
The exit code is 1 when a check fails, so a provisioning script can stop on
it; `--json` gives the report as data.

```text
$ kronik doctor
  pass  config  no configuration file: the defaults apply
                hint: kronik serve --init writes /etc/kronik/kronik.toml
  pass  kernel  Linux 6.12.111+deb13-cloud-amd64
  pass  runsc   /usr/local/bin/runsc release-20261019.0
  warn  kvm     /dev/kvm: No such file or directory (os error 2); platform systrap only (KVM_UNAVAILABLE)
                hint: fine for most hosts: foreign actors use systrap without KVM
  pass  cgroup  cgroup v2 with cpu, memory and pids
  pass  root    running as root, as the daemon does in v0.1
  pass  runc    /usr/bin/runc: isolation trusted is available
  pass  netns   network namespaces with only lo can be created
  pass  run_dir /run/kronik is usable for sandbox state
  pass  sandbox runsc --platform=systrap runs a sandbox
  pass  disk    7.9 GiB free for /var/lib/kronik
  pass  clock   synchronized by NTP
  pass  tls     TLS is off: the gateway serves plain HTTP
  pass  ship    shipping is off
13 passed, 1 warnings, 0 failed
```

## kronik restore

`kronik restore --from <URL> [--endpoint <URL>] [--data-dir <DIR>] [--config <PATH>] [--master-key-file <PATH>] [--allow-missing-keys | --without-keystore] [--branch main] [--force] [--dry-run]`

Restores a data directory from object storage (M6). Offline: the daemon
must not be running on the directory, and the command does not talk to
one. It downloads the newest snapshot of the branch, every remote segment
and the deployed components, checks the snapshot against its manifest, and
installs it. `kronik serve` then applies the log from the snapshot's LSN.

It writes no log record, so it takes no `--reason`. The master key is never
in the bucket. Put it in place before restoring, where `kronik serve` will
look for it: `--master-key-file` (or `KRONIK_MASTER_KEY_FILE`), else
`[keys] master_key_file` in the configuration file, else
`<data-dir>/keys/master.key`; or set `KRONIK_MASTER_KEY`. Restore uses it
to install the bucket's newest privacy keystore backup, applies the
erasures the log records after it, and checks that the keystore holds the
key of every sealed value in the restored state and log. Everything is
downloaded, checked and written in `<data-dir>/.restore` first, so a check
that fails leaves the directory as it was:
- a backup in the bucket and the key missing or another one:
  `MASTER_KEY_MISSING` or `MASTER_KEY_MISMATCH`;
- a sealed value whose key no backup provides (or sealed values and no
  backup at all): `KEYSTORE_INCOMPLETE`.

Then the result is moved into place with renames: the old `state.db` is
removed first and the new one put in place last. A restore interrupted
there (a crash, a full disk) leaves no `state.db`, never the old state with
the new log; run the restore again, without `--force`.

When the source node is gone and its newest backup lacks a subject's key
(it ships within a minute of a new subject's first value),
`--allow-missing-keys` installs that backup anyway: only the listed
subjects' sealed values stay unreadable, and the JSON's `keys_missing`
names them. `--without-keystore` installs no backup at all, which drops
**every** subject's key: every sealed value stays unreadable. After
either, `kronik integrity` lists the subjects and exits 1. The JSON's
`keystore` says `installed`, `none_in_bucket` or `skipped`.

`--from` is `s3://bucket/prefix` or `file:///path`. Credentials and region
come from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN` and `AWS_REGION` (default `us-east-1`). `--endpoint` is
an S3-compatible server, such as MinIO. The data directory is `--data-dir`,
else `server.data_dir` in the configuration file, else `/var/lib/kronik`.
An existing `state.db` is refused unless `--force`. `--dry-run` checks the
URL and that the bucket answers, prints the plan, and writes nothing to
the data directory. It does not download the snapshot, so it does not name
the snapshot's LSN.

```text
$ kronik restore --from s3://my-bucket/kronik --endpoint http://127.0.0.1:9000 --data-dir /var/lib/kronik
Restored snapshot main-00000000000000000012 at lsn 12 into /var/lib/kronik
  State hash    b3:9f2c1a0e4b7d8c6a5e3f1d0c9b8a7061524332415069788a7b6c5d4e3f2a1b0
  Segments      2
  Log first LSN 1
  Components    1
  Keystore      installed with the master key, which serve will use too
Next     kronik serve --data-dir /var/lib/kronik
```

## kronik upgrade check

`kronik upgrade check [--window 6h] [--data-dir <DIR>] [--config <PATH>] [--master-key-file <PATH>] [--workers <N>] [--dry-run]`

Checks this binary against a data directory before it replaces the one
that is running (M6). Offline and read-only apart from the report: the
old daemon may keep running. It replays the last `--window` of logical
time (default `6h`) with this binary's engine and the same code hashes.
Fuel is not compared. Sealed values open with the directory's privacy
keystore and the same `[keys]` configuration as `serve`. Select the matching
configuration with `--config` (or `KRONIK_CONFIG`). File/env sources use
`--master-key-file`, `[keys] master_key_file`, `KRONIK_MASTER_KEY`, or
`<data-dir>/keys/master.key` as configured; a KMS source needs its matching
`master.wrapped`, provider key and credentials. Missing/mismatched material
is refused; KMS never falls back to an environment seed or raw key file.

A diff with no verified difference writes `<data-dir>/upgrade/<engine>.json`
and exits 0; differences of turns that met erased data do not count as
changes. A diff with a verified difference writes that report and
the diff next to it
(`<data-dir>/upgrade/<engine>.diff.json`) and exits 1 with
`ENGINE_UPGRADE_DIVERGED`. `--dry-run` runs the check and prints the
result, and writes neither file. A bad window or a data directory with no
log is `BAD_REQUEST`. `--json` prints the report, and the diff path when
one was written, even when the command exits 1.

A turn whose recorded input was **erased** (`kronik privacy erase`, M8)
is unverifiable, not divergent, and so is every turn the erased data
reached: one whose input or state it shaped, one that read a state value
or SQL rows the erasure removed before production's own erasure did, and
a production turn missing below an unverifiable one (ADR 0109). The
replay serves their effects from the recording, reports `N turns
unverifiable: erased` (the report's `unverifiable` field, also in
`--json`), and passes when nothing else differs. Any other difference
still exits 1, so a check that fails after an erasure has found a real
change or a recording that cannot be read.
Reports written by older binaries lack the field; the report schema stays
`kronik.upgrade-check/v1`.

The check also asks the question `kronik serve` asks of the data directory
before it opens anything: whether the log that retention kept reaches
`state.db` and every actor database (an actor database says where that
actor's last change was, so an idle SQL actor can be behind a log that was
compacted past it). When a snapshot repairs that, the check passes and prints
a note on stderr, also with `--json`, that the first start installs that
snapshot. When none does, it exits 1 with `STORAGE_CORRUPT` and the message
`kronik serve` would stop with. An actor database a running daemon holds is
read without taking that lock or waiting for it, and counts in the same way.
If it cannot be read, the check does not pass: it exits 1 with
`STORAGE_CORRUPT` rather than treating the database as current.

A Wasmtime patch also changes the recorded engine identity: 50.0.0 to
50.0.1 still requires this check, with no verified difference in both
replay modes. The new daemon refuses the old directory until the exact
pair has a passing report, then writes one `EngineUpgrade` before serving.
Do not rewrite recorded engine metadata or relabel precompiled caches.

Historical v0.3.0 output (the recorded versions and hashes are unchanged):

```text
$ kronik upgrade check --window 6h --data-dir /var/lib/kronik
Upgrade check passed: kronik-0.1.0-dev+wasmtime-50.0.0 -> kronik-0.3.0+wasmtime-50.0.0, window 6h, fork lsn 7 through 95
  Root inputs   62
  Turns         63
  Diff          b3:6aff290d69f92f2a99a3236ce9d5a5285bbd527b1321dca03e212ffddc5adf6c
  Report        /var/lib/kronik/upgrade/kronik-0.3.0+wasmtime-50.0.0.json
Next     kronik serve --data-dir /var/lib/kronik
```

## kronik init

`kronik init [--lang ts|rust|python|go] <NAME>`

Creates the directory `<NAME>` with an actor project in TypeScript (the
default), Rust, Python or Go: one actor type named `<NAME>`, with the route
`POST /<NAME>/{key}/increment`, and a test (`test/actor.test.ts`,
`tests/actor.rs`, `tests/test_actor.py` or `test/actor_test.go`). The SDK
and the WIT are copied from the binary into `vendor/kronik-sdk`, for Go into
`kronik-sdk` (Go reserves `vendor/` for its own vendoring; `go.mod` replaces
`kronik.dev/sdk` with it). A Python project is tested with `python3 -m
unittest discover -s tests`, a Go project with `go test ./test`; both test
and build with the pinned tools of `scripts/install-sdk-tools.sh` (from a
Kronik checkout), which the next steps name first. The name may have lowercase letters, digits and dashes
and starts with a letter; an existing directory must be empty. See
[Writing actors](../guides/actors.md).

```text
$ kronik init --lang ts billing
created billing/ with the actor type billing and the SDK in vendor/kronik-sdk
next:
  cd billing
  npm install
  npm test
  kronik build
  kronik deploy dist/billing.wasm --reason 'first deploy'
```

## kronik build

`kronik build [--dir <DIR>] [--force] [--entry <ENTRY>]`

Builds the project in `<DIR>` (default `.`) into `dist/<name>.wasm` and checks
the component's imports against the allowlist, failing with
`IMPORT_NOT_ALLOWED` as `kronik deploy` would. A TypeScript project (it has a
`package.json`; run `npm install` first) is type-checked with `tsc --noEmit`
and built with `jco componentize`; when no input changed since the last
build, the component is kept, unless `--force`. `--entry` builds another
entry than `package.json`'s `kronik.entry` as a variant:
`--entry src/step2.ts` gives `dist/<name>-step2.wasm`. A Rust project (it has
a `Cargo.toml`) is built with `cargo build --release --target wasm32-wasip2`,
and the same sources give the same component wherever they are. A Python
project (`pyproject.toml`) is built with componentize-py from the module in
`[tool.kronik] entry` (default `actor`, in `src/`), a Go project (`go.mod`)
with TinyGo from the package `.`; both are then composed with WASI-Virt's
adapter, which keeps the filesystem and sockets out of the component, and
keep the previous component when no input changed (ADR 0030). `--entry
step2` (Python) or `--entry ./step2` (Go) builds a variant
`dist/<name>-step2.wasm`. Their tools come from `$KRONIK_SDK_TOOLS/bin`
(default `~/.cache/kronik/sdk-tools/bin`, `scripts/install-sdk-tools.sh`)
and must be the pinned versions. Progress goes to stderr. A TypeScript
build needs Node.js 22.20 or later on `PATH`, and checks for it before it
runs the toolchain.

```text
$ kronik build
building billing (TypeScript, @bytecodealliance/jco@1.39.0, @bytecodealliance/componentize-js@0.23.0, typescript@7.0.2)
  tsc --noEmit                                     0.1 s
  jco componentize                                 3.6 s
  imports: 18, all within the allowlist
dist/billing.wasm  b3:7ca3c84a00b3  13119624 bytes

$ kronik build
building billing (TypeScript, @bytecodealliance/jco@1.39.0, @bytecodealliance/componentize-js@0.23.0, typescript@7.0.2)
  inputs unchanged since the last build (input b3:f20db4c60316), kept the component
  imports: 18, all within the allowlist
dist/billing.wasm  b3:7ca3c84a00b3  13119624 bytes
```

## kronik deploy

`kronik deploy <WASM> --reason <REASON> [--dry-run]`

Deploys a component as a new actor type. A kind that already has history
needs `kronik propose` instead (`VERIFY_REQUIRED`). Deploying the code a kind
already runs changes nothing. After a deploy, the `curl` line shows the first
route on the gateway's address, which the daemon reports, else
`$KRONIK_HTTP_LISTEN` or `127.0.0.1:8080`. For every capability that the
manifest asks for and that has no grant yet, the daemon warns, and `Next`
starts with the exact `kronik grant` command; asking for a capability grants
nothing.

```text
$ kronik deploy counter.wasm --reason "first deploy" --dry-run
Dry run: counter b3:73c790c0997e (schema 0) can be deployed; nothing was written
  Routes        POST /counter/{key}/{op}
                GET /counter/{key}
  Capabilities  none
Next     kronik deploy counter.wasm --reason 'first deploy'

$ kronik deploy counter.wasm --reason "first deploy"
Deployed counter b3:73c790c0997e (schema 0) at lsn 1, epoch 1
  Routes        POST /counter/{key}/{op}
                GET /counter/{key}
  Capabilities  none
Next     curl -X POST 'http://127.0.0.1:8080/counter/<key>/<op>'
         kronik send counter/<key> <name> --reason "..."
         kronik history counter/<key>
```

With requested capabilities (a daemon on `127.0.0.1:18080`):

```text
$ kronik deploy webhook-relay.wasm --reason "relay webhooks"
Deployed webhook-relay b3:b38bc360a255 (schema 0) at lsn 12, epoch 6
  Routes        POST /hooks/{key}
                GET /hooks/{key}/{id}
  Capabilities  http:webhooks.example.com
                secret:relay-signing-key
  Warnings      capability http:webhooks.example.com is not granted
                capability secret:relay-signing-key is not granted
Next     kronik grant webhook-relay http:webhooks.example.com --reason '...'
         kronik grant webhook-relay secret:relay-signing-key --reason '...'
         curl -X POST 'http://127.0.0.1:18080/hooks/<key>'
         kronik send webhook-relay/<key> <name> --reason "..."
         kronik history webhook-relay/<key>
```

## kronik deployments list

`kronik deployments list`

Lists every deployment, oldest first: the epoch that names it, its LSN, its
cause (`deploy`, `promote` or `rollback`), the code it switches to, who made
it (`token:<name>`, or `unix:uid=<n>` on the socket without a token) and its
reason. `Next` offers to roll back the newest one.

```text
$ kronik deployments list
EPOCH  LSN  CAUSE   CODE                     BY             REASON
1      1    deploy  counter b3:bf34162595e6  token:release  first deploy
Next     kronik actors list
```

## kronik send

`kronik send <KIND/KEY> <NAME> [--text <TEXT> | --file <PATH>] [--content-type <TYPE>] [--fork <FORK>] --reason <REASON> [--dry-run]`

Sends an operator message to an actor and waits for its turn. The body is
`--text`, the bytes of `--file`, or empty. The content type defaults to
`text/plain` with `--text`, else the daemon's `application/octet-stream`. A
turn that fails exits with 1; its message is then a dead letter.

```text
$ kronik send counter/a increment --reason "try it"
Turn main:3 committed on counter/a
  Reply         1
Next     kronik history counter/a
         kronik actors inspect counter/a

$ kronik send counter/a fail --reason "see a failure"
Turn main:6 failed on counter/a
  Error         TURN_FAILED: deliberate failure
  Dead letter   main:6: fix the cause, then resend it
Next     kronik dead-letters resend main:6 --reason "..."
         kronik explain TURN_FAILED
         kronik history counter/a
```

With `--fork`, the message goes to the actor in a fork instead (M3): it
runs under the fork's code, on the fork's state from the fork point on,
without live effects, and the output lists the turn's effects, with the
version of each secret they used in a `SECRETS` column when there is one
(as in `kronik history`). A message into a fork has no dry run.

```text
$ kronik send counter/a increment --fork try --reason "try it"
Turn try:7 committed on counter/a in fork try
  Reply         3
Next     kronik diff show try
         kronik fork list

$ kronik send counter/a fetch-ok --text "GET https://api.example.com/x" --fork try --reason "effects in a fork"
Turn try:8 committed on counter/a in fork try
  Reply         error FetchError::Denied("CAPABILITY_NOT_GRANTED: http:api.example.com")

EFFECT      TARGET                DELIVERY  STATUS  ERROR
http.fetch  http:api.example.com  -         denied  CAPABILITY_NOT_GRANTED: http:api.example.com
Next     kronik diff show try
         kronik fork list
```

## kronik actors list

`kronik actors list [--kind <KIND>] [--after <KIND/KEY>] [--limit <N>]`

Lists actors by kind and key, 100 per page by default. When a page is full,
the last `Next` line fetches the next one.

```text
$ kronik actors list
ACTOR      SCHEMA  TURNS  LAST TURN  SQL
counter/a  0       2      main:6     no
notes/n    1       2      main:5     yes
Next     kronik actors inspect counter/a
         kronik history counter/a
```

## kronik actors inspect

`kronik actors inspect <KIND/KEY>`

Shows an actor's key-value state, with the LSN and subject of each value,
and the row counts of its SQL tables.

```text
$ kronik actors inspect notes/n
Actor    notes/n (schema 1, 2 turns, last turn main:5)
State    (none)
SQL      notes: 1 row
Next     kronik history notes/n
         kronik actors timers notes/n
```

## kronik actors timers

`kronik actors timers <KIND/KEY>`

Lists an actor's pending timers, by due time: the timer id that
`timers.schedule` returned, the logical time it is due (UTC), and the name
of its message. A timer leaves the list when its turn has run. `--json`
gives the id as a decimal string, because a 64-bit id does not fit a JSON
number exactly.

```text
$ kronik actors timers counter/t
ID                    DUE                   MESSAGE
12684291335336720919  2026-10-25T05:02:04Z  increment
Next     kronik history counter/t
```

## kronik history

`kronik history <KIND/KEY> [--limit <N>] [--before <LSN>]`

Shows an actor's turns, newest first, 100 per page by default: the input,
the outcome, what the turn changed and the hash of the code that ran it
(`CODE`). `--json` gives each turn's logical time and fuel too.

```text
$ kronik history counter/a
TURN    TYPE     INPUT                       OUTCOME                                   CHANGES  CODE
main:8  message  increment from operator     committed                                 set n    b3:d440473283f4
main:7  message  fail from resend of main:6  failed (TURN_FAILED: deliberate failure)  -        b3:d440473283f4
main:6  message  fail from operator          failed (TURN_FAILED: deliberate failure)  -        b3:d440473283f4
main:3  message  increment from operator     committed                                 set n    b3:d440473283f4
Next     kronik dead-letters list

$ kronik history counter/a --limit 1
TURN    TYPE     INPUT                    OUTCOME    CHANGES  CODE
main:8  message  increment from operator  committed  set n    b3:d440473283f4
Next     kronik history counter/a --before 8 --limit 1
```

The turns' effects (M2) follow in a second table: the effect, its target,
the delivery class, the status (`ok`, `denied`, `network`, `timeout`,
`too_large`, `outcome_unknown`, and for `call` also `not_found`,
`rejected`, `failed` and `reentrant`) and the error the guest got. The
target of an HTTP effect is its request's method, host and path, such as
`POST api.example.com/hooks` (`request` in the JSON); a denied one, which
sent nothing, shows the capability it lacked. Without a grant the guest
gets `denied` with `CAPABILITY_NOT_GRANTED`, and `Next` starts with the
exact command that grants the capability:

```text
$ kronik send counter/a fetch-ok --text "GET https://api.example.com/v1/rates" --reason "try a fetch"
Turn main:2 committed on counter/a
  Reply         error FetchError::Denied("CAPABILITY_NOT_GRANTED: http:api.example.com")
Next     kronik history counter/a
         kronik actors inspect counter/a

$ kronik history counter/a
TURN    TYPE     INPUT                   OUTCOME    CHANGES   CODE
main:2  message  fetch-ok from operator  committed  1 effect  b3:d440473283f4

TURN    EFFECT      TARGET                DELIVERY  STATUS  ERROR
main:2  http.fetch  http:api.example.com  -         denied  CAPABILITY_NOT_GRANTED: http:api.example.com
Next     kronik grant counter http:api.example.com --reason '...'
```

An effect that used a secret (M23) says which version in a last column,
`SECRETS`, as `secret:<name>@v<N> (<hash>)`: the hash is the first 8 hex
characters of the version hash that `kronik secret list` shows in full, and
several secrets are separated by a comma. The column is there only when an
effect on the page used a secret. When a secret is rotated, with
`kronik secret set` and a new value, the turns after it show the new version
while the turns before it keep the one they used. The value is never shown.
`--json` gives the effect a `secrets` list of `name`, `version` and
`version_hash`; it is absent when the effect used no secret, and, like
`request`, when the request is sealed for a data subject.

```text
$ kronik history billing/acme
TURN    TYPE     INPUT                 OUTCOME    CHANGES   CODE
main:9  message  charge from operator  committed  1 effect  b3:d440473283f4
main:5  message  charge from operator  committed  1 effect  b3:d440473283f4

TURN    EFFECT      TARGET                           DELIVERY           STATUS  ERROR  SECRETS
main:9  http.fetch  POST api.example.com/v1/charges  idempotency-keyed  ok      -      secret:stripe-key@v2 (3fa9c1d2)
main:5  http.fetch  POST api.example.com/v1/charges  idempotency-keyed  ok      -      secret:stripe-key@v1 (8b705664)
Next     kronik actors inspect billing/acme
```

## kronik history --operations

`kronik history --operations [--limit <N>]`

Shows the durable operator audit through the existing `GET /v1/audit` consumer,
with the same `admin` scope as `kronik audit show`. This is not actor-turn or
orphan history: it takes no actor, `--before`, `--orphans` or `--all`.
The limit is 1–1000, default 100. Native pages retain their original LSNs;
Member pages retain the actual metadata source/cut rather than inventing an
actor LSN. JSON preserves the server response after validating the page's
domain; mixed native/metadata fields are rejected.

The principal, reason, time and immutable audit identity come from the recorded
mutation. Reading this history neither appends an audit nor retries a mutation.
Current read-time privacy can withhold a historical flat reason without changing
the durable original. Pagination uses the existing `kronik audit show --from`
hint. This read command does not enable maintenance drain or a metadata reader
capability.

## kronik history --orphans

`kronik history --orphans [--all]`

Lists orphaned changes (M2): a change that a called actor committed in a
`call` whose caller then failed. Each row names the callee (`ACTOR`) and its
turn, the caller and its failed turn, and the compensation's state (`none`,
`pending`, `dead letter` or `done`). A change stays orphaned until a
compensation for it succeeds; `--all` includes the resolved ones, with the
turn that resolved them. `--orphans` takes no actor.

```text
$ kronik send counter/c call-fail --text "counter/d increment" --reason "see an orphan"
Turn main:9 failed on counter/c
  Error         TURN_FAILED: failing after call: reply 1
  Dead letter   main:9: fix the cause, then resend it
Next     kronik dead-letters resend main:9 --reason "..."
         kronik explain TURN_FAILED
         kronik history counter/c

$ kronik history --orphans
ACTOR      TURN    CALLER     CALLER TURN  COMPENSATION  RESOLVED BY
counter/d  main:7  counter/c  main:9       none          -
Next     kronik history counter/d
```

## kronik trace

`kronik trace <TURN-ID>`

Shows a turn's causal tree (M3): the root input, the turns from it down to
this one, and everything this turn caused, as a tree of at most 1000
turns. Turn ids are on main (`main:<lsn>`); fork turns follow once forks
keep logs. `--json` also has the traced turn's effects, with the secret
versions each used (`secrets`).

```text
$ kronik trace main:2
Trace of main:2 on counter/a
Root     message fanout from operator at lsn 2 (root id 4c3568017ff1…)

main:2  counter/a  message fanout from operator  committed   <- this turn
├─ main:3  counter/f1  message note from counter/a  committed
└─ main:4  counter/f0  message note from counter/a  committed
Next     kronik history counter/a

$ kronik trace main:3
Trace of main:3 on counter/f1
Root     message fanout from operator at lsn 2 (root id 4c3568017ff1…)

main:2  message fanout from operator  committed
└─ main:3  counter/f1  message note from counter/a  committed   <- this turn
Next     kronik history counter/f1
```

## kronik dead-letters list

`kronik dead-letters list [--after <ID>] [--limit <N>]`

Lists dead letters, oldest first: inputs whose turn failed. A dead letter's
id is the turn id of the failed turn; `RESENT AS` is the turn that resent it.

```text
$ kronik dead-letters list
ID      ACTOR      INPUT                               ERROR                            RESENT AS
main:6  counter/a  message fail from operator          TURN_FAILED: deliberate failure  main:7
main:7  counter/a  message fail from resend of main:6  TURN_FAILED: deliberate failure  -
Next     kronik dead-letters resend main:7 --reason "..."
         kronik explain TURN_FAILED
```

## kronik dead-letters resend

`kronik dead-letters resend <ID> --reason <REASON> [--dry-run]`

Runs a dead letter's input again as a new root input and waits for its
turn. A dead letter can be resent once (`DEAD_LETTER_ALREADY_RESENT`); if the
new turn fails too, it is a dead letter of its own, and the command exits
with 1.

```text
$ kronik dead-letters resend main:6 --reason "retry after the fix"
Resent main:6 as turn main:7, which failed
  Error         TURN_FAILED: deliberate failure
  Dead letter   main:7: fix the cause, then resend it
Next     kronik explain TURN_FAILED
         kronik dead-letters list
```

## kronik grant

`kronik grant <KIND> <CAPABILITY> [--delivery replay-safe|idempotency-keyed|unsafe] [--rate <N/s|N/m|N/h>] [--in-forks compute|recorded] --reason <REASON> [--dry-run]`

Grants an actor type a capability (M2). Every external effect is denied
until it is granted (I6). Capabilities are `http:<host>`, `http:*.<domain>`
(the most specific match wins, and a wildcard never matches the domain
itself), `secret:<name>` (use the secret in a header template or in
`crypto`) and `secret-reveal:<name>` (read its value). Grants apply per
actor type, not per code hash, and take effect at a new configuration
epoch.

`--in-forks` chooses what a fork does with an unmatched
`crypto.hmac-sha256` or `crypto.sign-ed25519` of a `secret:` grant
([ADR 0112](../adr/0112-fork-crypto-grant-mode.md)). `recorded`, the
default for a new grant, returns a matching recording or denies the call.
`compute` signs on the host; the key does not enter the guest, the log, or
the diff. A grant written before the field existed stays `compute` until it
is granted again. Re-granting without `--in-forks compute` writes
`recorded`. Under `compute`, a name linked to an external backend at the
fork point is computed with the value the node holds for that link, and is
denied with `SECRET_UNAVAILABLE` when it holds none: a fork never fetches.
Either way the effect is graded synthetic (ADR 0132), as what the node
holds is not part of the log.

For `http:` capabilities, `--delivery` says how the target tolerates
retries after a crash: `replay-safe` and `idempotency-keyed` requests are
sent again with the same `Idempotency-Key`, `unsafe` ones are not, and the
guest gets `outcome-unknown` (I17). Without it the method decides:
`replay-safe` for GET, HEAD and OPTIONS, `unsafe` otherwise. `--rate`
limits the requests per target host.

```text
$ kronik grant counter http:api.example.com --delivery idempotency-keyed --rate 5/s --reason "rates API" --dry-run
Dry run: counter can be granted http:api.example.com at epoch 2; nothing was written
  Delivery      idempotency-keyed
  Rate          5/s
Next     kronik grant counter http:api.example.com --delivery idempotency-keyed --rate 5/s --reason 'rates API'

$ kronik grant counter http:api.example.com --delivery idempotency-keyed --rate 5/s --reason "rates API"
Granted http:api.example.com to counter at lsn 3, epoch 2
  Delivery      idempotency-keyed
  Rate          5/s
Next     kronik grants list --kind counter
         kronik revoke counter http:api.example.com --reason "..."

$ kronik grant counter secret:signing-key --in-forks compute --reason "forks may sign"
Granted secret:signing-key to counter at lsn 5, epoch 4
  In forks      compute
Next     kronik grants list --kind counter
```

## kronik revoke

`kronik revoke <KIND> <CAPABILITY> --reason <REASON> [--dry-run]`

Revokes a granted capability. A capability that is not granted gives
`CAPABILITY_NOT_GRANTED`.

```text
$ kronik revoke counter http:api.example.com --reason "rates come from elsewhere now"
Revoked http:api.example.com from counter at lsn 4, epoch 3
Next     kronik grants list --kind counter
```

## kronik grants list

`kronik grants list [--kind <KIND>]`

Lists the grants in force. `DELIVERY` is `by method` for an `http:` grant
without a delivery class. `IN-FORKS` is `compute` or `recorded`.

```text
$ kronik grants list
KIND     CAPABILITY            DELIVERY           RATE  IN-FORKS  EPOCH  REASON
counter  http:api.example.com  idempotency-keyed  5/s   recorded  2      rates API
Next     kronik revoke counter http:api.example.com --reason "..."
```

## kronik limits set

`kronik limits set <KIND> [--fuel <N>] [--memory <SIZE>] [--message-size <SIZE>] [--state-value-size <SIZE>] [--sql-size <SIZE>] [--effect-timeout <DURATION>] [--effect-response-size <SIZE>] --reason <REASON> [--dry-run]`

Changes an actor type's limits (M2); limits that are not named keep their
value, and at least one must be named. Turns use the limits of their
configuration epoch. The output shows every limit in force afterwards.

- `<N>` is a number, optionally with `k`, `M` or `G` (powers of 1000), e.g.
  `100M`.
- `<SIZE>` is bytes, optionally with `Ki`, `Mi`, `Gi` or `Ti` (powers of
  1024) or `k`, `M`, `G` or `T` (powers of 1000), e.g. `128Mi`.
- `<DURATION>` is a number with `ms`, `s`, `m` or `h`, e.g. `10s`.

| Option | Limit | Default |
| --- | --- | --- |
| `--fuel` | Fuel per turn | 50000000 |
| `--memory` | Memory per instance | 64 MiB |
| `--message-size` | Largest message body | 1 MiB |
| `--state-value-size` | Largest state value | 1 MiB |
| `--sql-size` | Largest SQL database per actor | 1 GiB |
| `--effect-timeout` | How long an effect may take | 10s |
| `--effect-response-size` | Largest effect response | 10 MiB |

```text
$ kronik limits set counter --fuel 100M --memory 128Mi --effect-timeout 2s --reason "invoices with many lines"
Set the limits of counter at lsn 5, epoch 4
  Fuel              100000000
  Memory            128 MiB
  Message size      1 MiB
  State value size  1 MiB
  SQL size          1 GiB
  Effect timeout    2s
  Effect response   10 MiB
Next     kronik limits show --kind counter
```

## kronik limits show

`kronik limits show [--kind <KIND>]`

Shows the limits in force for every deployed actor type, or for `--kind`,
deployed or not.

```text
$ kronik limits show
KIND     FUEL       MEMORY   MESSAGE  STATE VALUE  SQL    EFFECT TIMEOUT  EFFECT RESPONSE
counter  100000000  128 MiB  1 MiB    1 MiB        1 GiB  2s              10 MiB
Next     kronik limits set counter --fuel <n> --reason "..."
```

## kronik secret set

`kronik secret set <NAME> --reason <REASON> [--dry-run]`

Stores a secret (M2), or a new version of it, in the daemon's secret store,
encrypted under the master key. The value is read from stdin, never from
the command line: from a terminal, one line that is not echoed; otherwise
everything up to the end of input. One trailing newline is removed from a
value that is text, so `echo "$VALUE" |` works too; other bytes are kept
exactly. Names are up to 64 of `a-z`, `0-9`, `_`, `.` and `-`, starting
with a letter or a digit. The value is never shown, by this command or any
other; the log and the API know a secret by its name and a keyed hash of
each version.

```text
$ printf %s "$VALUE" | kronik secret set stripe-key --reason "payments"
Stored secret stripe-key, version 1
  Version hash  8b705664281cdfcde70f57adae0396f7
Next     kronik grant <kind> secret:stripe-key --reason "..."
         kronik secret list
```

## kronik secret list

`kronik secret list`

Lists the secrets: name, current version, version hash and when that
version was stored (UTC). Never values.

```text
$ kronik secret list
NAME        VERSION  VERSION HASH                      CREATED
stripe-key  1        8b705664281cdfcde70f57adae0396f7  2026-10-25T04:02:15Z
Next     kronik grant <kind> secret:stripe-key --reason "..."
```

## kronik secret delete

`kronik secret delete <NAME> --reason <REASON> [--dry-run]`

Deletes every version of a secret; an unknown name gives
`SECRET_NOT_FOUND`. An effect that needs a deleted secret, also when a turn
runs again after a crash, is denied.

```text
$ kronik secret delete stripe-key --reason "rotated out" --dry-run
Dry run: secret stripe-key can be deleted; nothing was written
Next     kronik secret delete stripe-key --reason 'rotated out'

$ kronik secret delete stripe-key --reason "rotated out"
Deleted secret stripe-key: 1 version
Next     kronik secret list
```

## M23 external-secret CLI additions: source contract

The following five commands match the current M23 source declarations, not
availability in the `d9b946f2` proof binary or published v0.3.0. The final
integrated binary must pass the real help/surface check before availability is
claimed. See the [API examples](api-examples.md) for the owned `demo-env`
backend configuration, permitted dummy environment reference and startup
snapshot semantics. The link, unlink and refresh mutations require a nonblank
reason; a dry run does not commit them.

## kronik secret backends

`kronik secret backends`

List configured backend identities without contacting providers. Inspect
`configured` and `inventory_complete` separately; neither the command's
presence nor an identity listing proves an external service is healthy.
LAST SUCCESS and LAST ERROR (`last_success_ms`, `last_error_ms` and
`last_error` in JSON: `unavailable`, `denied`, `not_found`, `version_gone` or
`invalid`, never a provider's words) are what this node last heard from each
external backend since it started; UNCACHED (`uncached`) lists the linked
names that have no value an effect could use now, so the next effect that
needs one asks the backend. `kronik doctor` warns about both.

```sh
kronik --socket /owned/fixture/api.sock secret backends
```

## kronik secret link

`kronik secret link <NAME> --backend <ID> --ref <REFERENCE> --reason <REASON> [--dry-run]`

Binds a name to an explicitly configured backend and an allowed reference.
A run without `--dry-run` commits a `SecretLink` record. `--dry-run` only
previews that binding and does not commit it. The command does not set the
remote provider's value. Use only the fixture's allowed dummy environment
reference.

```sh
kronik --socket /owned/fixture/api.sock secret link demo-api-key \
  --backend demo-env --ref KRONIK_DEMO_API_KEY \
  --reason "preview owned fixture binding" --dry-run
```

## kronik secret refresh

`kronik secret refresh <NAME> --reason <REASON> [--dry-run]`

For a separately approved, committed fixture link, preview observing its
current external version without replacing recorded historical identities.
The preceding dry-run link alone does not establish that prerequisite.

```sh
kronik --socket /owned/fixture/api.sock secret refresh demo-api-key \
  --reason "preview owned fixture refresh" --dry-run
```

## kronik secret history

`kronik secret history <NAME>`

Read committed immutable version identities and provenance, not secret values.
Inspect recorded phases and deletion markers; a reserved or failed row is not
proof of an activated version. Never rewrite the ledger to make it fit a
provider's current value.

```sh
kronik --socket /owned/fixture/api.sock secret history demo-api-key
```

## kronik secret unlink

`kronik secret unlink <NAME> --reason <REASON> [--dry-run]`

Preview the admin change that returns future turns to the built-in store.
This does not delete the provider's value, erase recorded version identities
or permit historical replay to substitute a different source version.

```sh
kronik --socket /owned/fixture/api.sock secret unlink demo-api-key \
  --reason "preview owned fixture unlink" --dry-run
```

## kronik keys status

`kronik keys status`

Shows the loaded master-key source, the wrapping key and version when there
are any, and whether the seed passed the local store checks. Needs `read`;
calls `GET /v1/keys`. It never returns key bytes, ciphertext or credentials.
`check_ok` describes the loaded key, not current provider reachability:
the running node does not unwrap again for this command.

```sh
kronik keys status
```

## kronik keys wrap

`kronik keys wrap --source <openbao|aws|gcp|azure|pkcs11> [--config <PATH>] [--data-dir <DIR>] [--master-key-file <PATH>] --reason <REASON> [--dry-run] [--remove-file]`

Offline migration of an existing file or environment master seed.
`--source` is `openbao|aws|gcp|azure|pkcs11`. `openbao`, `aws`, `gcp` and
`azure` are cloud KMS providers; `pkcs11` is the PKCS#11 helper, not a
cloud KMS. Stop the daemon first. The target configuration must already
select the same `source` as `--source` and contain that source's settings;
this command does not rewrite the configuration. See
[master-key configuration](../guides/operations.md#the-master-key) for the
four cloud provider tables and bootstrap credentials.

`--data-dir` overrides `server.data_dir`. The old file comes from
`--master-key-file`, else `KRONIK_MASTER_KEY_FILE`, else
`<data-dir>/keys/master.key`; alternatively give the old 64-character hex
seed with `KRONIK_MASTER_KEY`, not both. Unset both old-key environment
variables before starting with the target KMS configuration; the printed
start command does so. A relative `wrapped_file` selects the encrypted
envelope; its default is `keys/master.wrapped` under the data directory.

The command validates the existing encrypted stores, wraps the same seed,
unwraps it to check the result, then atomically persists the envelope.
It does not rotate the seed or re-encrypt the stores. A private marker
becomes a `keys.source` audit event at the next start. Never put key bytes
or credentials in `--reason`; reasons are history.

`--dry-run` contacts the provider and checks the wrapping operation but
writes neither envelope nor marker and removes no file. The old file is
preserved by default; `--remove-file` explicitly removes it only after a
successful non-dry migration. Deletion is not secure erasure of disk
snapshots or backups. A migrated file seed therefore was on disk before
migration.

New daemons and this command cooperate through a lock on the data directory
itself, with no writable parent or sibling required. A running daemon with
that lock is refused. Released v0.3 daemons did not hold it: explicitly stop
an older daemon rather than relying on lock detection.

```sh
kronik keys wrap --source openbao --config /etc/kronik/kronik-kms.toml \
  --master-key-file /etc/kronik/master.key \
  --reason "move the existing seed into OpenBao" --dry-run
```

## kronik keys rewrap

`kronik keys rewrap --reason <REASON> [--dry-run]`

Online re-encryption of the already loaded seed with the configured KMS's
current wrapping-key version. Needs `admin`; calls `POST /v1/keys/rewrap`.
Read and operate tokens cannot rewrap, including a dry run. The file and
environment sources must be migrated with offline `keys wrap` first.

The command checks that old and new ciphertext unwrap to the existing
seed, validates the stores and atomically replaces only the envelope.
It records `keys.rewrap` (and `keys.rewrap.failed` if the operation fails).
The daemon keeps its loaded key; turns and shipping do not need another
unwrap. A dry run still performs the provider checks but leaves the
envelope and audit log unchanged.

Keep older provider key versions decryptable while any backup still
depends on them. Shipping publishes the current envelope independently of
keystore changes and pairs each encrypted keystore backup with an envelope;
restore checks the chosen material before installing it. Rewrap is not
master-seed rotation.

On an already configured KMS-backed installation, validate the new wrapping
operation without publishing it:

```sh
kronik keys rewrap --reason "validate the provider key rotation" --dry-run
```

## kronik keys enroll

`kronik keys enroll [--config <PATH>] [--json]`

Verifies a configured PKCS#11 key through the isolated helper and prints the
non-secret possession probe. This is an offline operator command: it reads the
`[keys]` configuration from `--config` (default `/etc/kronik/kronik.toml`),
drives the configured module through the helper, and prints the probe to save
under `[keys.pkcs11.probe]` in that same file. It does not load or change the
master seed, and it never prints key bytes, the private PIN or other module
credentials. Normal startup, wrap, rewrap and restore require the enrolled
probe. A helper, module, token or credential failure is
[`KEY_HELPER_FAILED`](../errors.md#key_helper_failed). After a verified
enrollment, the probe's own output names the next step:
`kronik keys wrap --source pkcs11`. `--source` accepts
`openbao|aws|gcp|azure|pkcs11`, the same set as the wrap synopsis.
`pkcs11` is the PKCS#11 helper, not a cloud KMS. See the installation guide's
[PKCS#11 helper](../guides/install.md#optional-gnu-pkcs11-helper) section and
the operations guide's master-key tables.

```sh
kronik keys enroll --config /etc/kronik/kronik.toml --json
```

## kronik fork create

`kronik fork create --at <LSN|now|TIME> [--name <NAME>] [--no-pii] --reason <REASON> [--dry-run]`

Creates a fork (M3): a branch of the history from an LSN, with main's state
at that point and a log of its own from there on. A fork makes no live
effects. `--at` is an LSN, `now`, or a logical time in RFC 3339, which
means the last turn at or before it. The name is generated without
`--name`. `--no-pii` makes a fork without access to personal data, and a
token without `pii:read` always gets one: the flag is recorded on the
fork, and in every privacy mode its actors read each value tagged with a
subject as a pseudonym (see
[forks without personal data](../guides/privacy.md#forks-without-personal-data)).

```text
$ kronik fork create --at 1 --name try --reason "try step 2"
Forked main at lsn 1 -> fork try
Next     kronik fork deploy try <wasm> --reason "..."
         kronik replay try --reason "..."
```

## kronik fork deploy

`kronik fork deploy <FORK> <WASM> --reason <REASON> [--dry-run]`

Deploys a component in a fork, also for a kind that has history: the code
that the fork's replay runs.

```text
$ kronik fork deploy try counter-step2.wasm --reason "step 2"
Deployed counter b3:9ae922b13c24 (schema 0) in fork try
Next     kronik replay try --reason "..."
```

## kronik fork list

`kronik fork list`

Lists the forks, those of proposals included (their name is the proposal
id): where each starts and how far its replay has verified main.

```text
$ kronik fork list
Main is at lsn 4.
FORK  FORK LSN  VERIFIED THROUGH  PROPOSAL
try   1         4                 -
Next     kronik diff show try --md
```

## kronik fork delete

`kronik fork delete <FORK> --reason <REASON> [--dry-run]`

Deletes a fork and its state.

```text
$ kronik fork delete try --reason "done"
Deleted fork try
Next     kronik fork list
```

## kronik replay

`kronik replay <FORK> [--to <LSN>] [--mode isolated|continuous|both] [--sample <SHARE>] [--ignore-header <NAME>]... [--ignore-json-path <PATH>]... [--threads <N>] [--stub <FILE>]... [--simulators <TARGET=FILE>]... --reason <REASON>`

Runs main's root inputs after the fork point, up to `--to` or HEAD, through
the fork's code, and writes the fork's behavior diff. Isolated replay runs
each root input on production's state at its own LSN; continuous replay
lets the fork's state evolve under the new code; `--mode` picks one. When
`--mode` is omitted, the value is `[replay] default_mode` in the
configuration file (`$KRONIK_CONFIG`, else `/etc/kronik/kronik.toml` if it
exists), and `both` when that file is absent or leaves the key at its
default. `--sample` replays a share of the root inputs in isolated
mode, as a percentage (`10%`) or a fraction (`0.1`), the same share every
time for the same fork. An omitted `--sample` is `[replay] sample` from
that file, `100%` by default. `--ignore-header` and `--ignore-json-path`
(JSONPath such as `$.a.b[*].c`) leave noise out of the comparison. The
output is the diff in short, the same as `kronik diff show`.

`--stub` gives canned answers to effects that have no recording, which
otherwise fail closed. The file is TOML with `[[stub]]` tables, or a JSON
array, of rules: `method` (any when absent), `url_prefix`, and either a
response (`status`, 200 by default; `headers`, as `[name, value]` pairs;
`body`) or an `error`: `network`, `timeout`, `too-large` or `denied`. The
first rule whose method and URL prefix match answers. A stubbed effect
counts as synthetic grounding, and the diff records the rules in
`options.stubs`. The flag repeats, and its rules apply in order.

`--simulators TARGET=FILE` gives one target the simulator configuration in
FILE (the rules file of `kronik stubs set`: stub rules, a contract,
`neighbor`, `model`) for this replay only. It replaces main's configuration
of TARGET as of the fork point, which is what a fork uses otherwise (I5),
and the diff records it in `options.simulator_overrides`. The flag repeats,
one per target.

```text
$ kronik replay try --reason "see the diff"
Replayed 3 of 3 root inputs in fork try (isolated and continuous), verified through lsn 4
  Causes        3 origins, 0 consequences
                counter on message increment: 3 origins (3 roots)
  Responses     no HTTP root inputs
  Effects       0 changed, 0 added, 0 removed
  State         1 actor changed
                1 actor drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 0.0%, memory p99 0.0%
  Grounding     0 exact, 0 approximate, 0 synthetic (confidence 1.00)
Next     kronik diff show try --md
         kronik policy test try

$ cat stubs.toml
[[stub]]
method = "GET"
url_prefix = "http://127.0.0.1:28191/items/"
headers = [["content-type", "text/plain"]]
body = "stubbed"

$ kronik replay extra --stub stubs.toml --reason "the extra GET, stubbed"
Replayed 2 of 2 root inputs in fork extra (isolated and continuous), verified through lsn 8
  Causes        2 origins, 0 consequences
                counter on POST /counter/{key}/{op}: 2 origins (2 roots)
  Responses     2 replayed, 0 identical, 2 changed
  Effects       0 changed, 2 added, 0 removed
                http.fetch GET 127.0.0.1/items/{}/extra: 2 changes
  State         0 actors changed
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 +55.4%, memory p99 0.0%
  Grounding     2 exact, 0 approximate, 2 synthetic (confidence 0.50)
                127.0.0.1 GET /items/{}/extra: 0 exact, 0 approximate, 2 synthetic
  Stubs         GET http://127.0.0.1:28191/items/ -> 200
Next     kronik diff show extra --md
         kronik policy test extra
```

## kronik diff show

`kronik diff show <FORK|PROPOSAL> [--md | --summary]`

Shows a fork's or a proposal's behavior diff (`kronik.diff/v1`, see
[M3 fork design](../design/m3-fork.md) §5): by default in short, with
`--md` as Markdown for a review, with `--json` as the JSON diff, whose
JSON Schema is [diff-v1.schema.json](diff-v1.schema.json). `--summary`
(M10) prints a short Markdown summary for public pull requests: counts
from the diff's totals, the code per kind, the policy, causes by declared
input pattern, error codes, and grounding per effect kind, method and host
(at most 10 targets, then "… N more"), where an `http.fetch` host shows as
the `http:` grant that matches it (`*.example.com` for a wildcard grant,
`(no grant)` without one), a method no route may declare as `(other)` and a
kind with no code as `(undeployed kind)`. It never shows a URL path or an effect's route,
a body, a header, a state key or value, an SQL row, an effect's fields, an
error message or an actor's key, whatever the privacy mode, and every
interpolated name is inline code ([ADR 0023](../adr/0023-diff-summary.md)).
`--md` and `--summary` exclude each other and `--json`.

- **Causes**: the origins, the first turns whose outcome differs although
  their input is the same as production's, and their consequences further
  down the same causal trees.
- **Responses**: the HTTP root inputs whose response changed.
- **Effects**: external effects added, removed or changed, per target.
- **State**: the actors whose state changed, and those whose state drifts
  only over the window, in continuous replay.
- **Errors**: errors introduced and fixed, and new orphaned calls.
- **Resources**: the change in fuel and memory at p99.
- **Grounding**: how many of the fork's effects rest on exact or
  approximate recordings, or on a synthetic answer, with the confidence and
  the targets that are not exact.

```text
$ kronik diff show try
Diff of fork try: main lsn 2 to 4
  counter   b3:d440473283f4 -> b3:9ae922b13c24
  Causes        3 origins, 0 consequences
                counter on message increment: 3 origins (3 roots)
  Responses     no HTTP root inputs
  Effects       0 changed, 0 added, 0 removed
  State         1 actor changed
                1 actor drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 0.0%, memory p99 0.0%
  Grounding     0 exact, 0 approximate, 0 synthetic (confidence 1.00)
Next     kronik diff show try --md

$ kronik diff show p-d8e829aa6c7a --md
# Behavior diff: p-d8e829aa6c7a

- Base: main at LSN 1, window 2..=6
- Code: counter b3:d440473283f4 → b3:9ae922b13c24 (schema 0 → 0)
- Policy: **require_approval**: any-change (require_approval)

## Summary
…
```

## kronik propose

`kronik propose <WASM_OR_DIR>... [--window <DURATION> | --at <LSN>] [replay options] [--async] --reason <REASON> [--dry-run]`

Proposes new code (M3), one component per changed actor type: Kronik forks
main, deploys the code in the fork, replays the root inputs of the window
(1 hour of logical time back from the newest root input by default, or
from `--at`) in the replay mode from the configuration file (`both` by
default; see `kronik replay`), writes the behavior diff and evaluates the
policy. The replay options are those of `kronik replay`, `--stub` rule
files included (stubbed effects count as synthetic). A denied
proposal gets the status `rejected`. With `--dry-run` the replay runs and
the policy is evaluated, but nothing is kept. When the window reaches
back before the oldest point the log and snapshots still hold (see
[snapshots and retention](../guides/operations.md#snapshots-and-retention)),
the replay starts at the oldest usable snapshot and the output says so in a
`Warning: retention cut the window ...` line (`warnings` in the JSON,
`base.window_cut` in the diff).

The checks run at once; the replay runs as a job in the daemon (M10,
[ADR 0022](../adr/0022-proposal-jobs.md)), so a long replay survives the
CLI going away. The CLI always starts the job (`"async": true`) and then
follows it as [kronik proposal wait](#kronik-proposal-wait) does, printing
the progress to stderr, until the proposal is done; the output is then
the same as a sync propose's (`ProposeResponse` with `--json`). If
following it fails (a broken connection, a proxy's timeout), the error
names the proposal and the hint is `kronik proposal wait <id>`; the job
goes on. With `--async` the command returns as soon as the job has
started, with the proposal's id and the status `running`. `--async` does
not go with `--dry-run`, which keeps nothing to follow; a dry run is
answered in the request.

```text
$ kronik propose dist/ --async --reason "notes learn tally"
Proposal p-3c1f0e8a9b27 is running: its replay of main from lsn 1200 runs in the daemon
Next     kronik proposal wait p-3c1f0e8a9b27
         kronik proposal status p-3c1f0e8a9b27
```

Several components make a system proposal (M9,
[design](../design/m9-system-proposals.md)): all of them go into one fork,
one replay runs them together, so a kind that starts calling a new message
of another is verified with that kind's new code, and the diff reports each
actor kind on its own (`Kinds`, and `kinds` in the JSON). A directory
stands for every `.wasm` file directly in it. A component is skipped, and
listed as `Skipped`, when main runs its code now and ran it at the fork
point; promote then checks that its kind still runs it
(`PROPOSAL_STALE` otherwise). When every component is skipped, nothing is
proposed (`NOTHING_TO_PROPOSE`). Two components for one kind are refused with
both file names (a TypeScript project's `dist/` can hold `<name>.wasm`
and `<name>-<entry>.wasm` builds of one kind: name the ones to propose),
and so is a set in which two kinds would serve one route
(`ROUTE_CONFLICT`).

The examples from here to `kronik promote` run with the one-rule policy of
[kronik policy set](#kronik-policy-set) in force: `any-change`, an approval
for every change. Under the default rules this proposal is allowed
(`Policy   ALLOW`).

```text
$ kronik propose counter-step2.wasm --reason "count in steps of 2"
Forked main at lsn 1 -> fork p-d8e829aa6c7a
Replayed 3 of 3 root inputs (isolated and continuous), verified through lsn 5

Proposal p-d8e829aa6c7a   counter   b3:d440473283f4 -> b3:9ae922b13c24   (evaluated)
  Causes        3 origins, 0 consequences
                counter on message increment: 3 origins (3 roots)
  Responses     no HTTP root inputs
  Effects       0 changed, 0 added, 0 removed
  State         1 actor changed
                1 actor drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 0.0%, memory p99 0.0%
  Grounding     0 exact, 0 approximate, 0 synthetic (confidence 1.00)

Policy   any-change -> APPROVAL REQUIRED
Next     kronik diff show p-d8e829aa6c7a --md
         kronik approve p-d8e829aa6c7a --reason "..."
         kronik promote p-d8e829aa6c7a --reason "..."   (catches up to HEAD first)
```

Here `dist/` holds a counter that now calls `tally` on notes, the notes
actor that serves `tally`, and an unchanged webhook relay; this sample and
the next run under the default rules:

```text
$ kronik propose dist/ --reason "notes learn tally; counter tallies"
Forked main at lsn 3 -> fork p-697d0d1911d4
Replayed 5 of 5 root inputs (isolated and continuous), verified through lsn 9

Proposal p-697d0d1911d4   counter   b3:bf34162595e6 -> b3:06d907243ec0   (evaluated)
                          notes   b3:5a268f14727f -> b3:98e7a1ef194c
Skipped webhook-relay   b3:b38bc360a255: main already runs this code
  Kinds         counter (changed code): 4 divergent turns, 0 errors introduced
                notes (changed code): 8 divergent turns, 0 errors introduced
  Causes        4 origins, 8 consequences
                counter on POST /counter/{key}/{op}: 4 origins (4 roots)
  Responses     4 replayed, 4 identical, 0 changed
  Effects       0 changed, 0 added, 0 removed
  State         1 actor changed
                1 actor drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 +47.7%, memory p99 0.0%
  Grounding     0 exact, 0 approximate, 0 synthetic (confidence 1.00)

Policy   ALLOW
Next     kronik diff show p-697d0d1911d4 --md
         kronik promote p-697d0d1911d4 --reason "..."   (catches up to HEAD first)
```

The counter alone would call a message the running notes code does not
serve:

```text
$ kronik propose dist/counter.wasm --reason "counter alone"
...
Proposal p-998bf4826ae5   counter   b3:bf34162595e6 -> b3:06d907243ec0   (rejected)
  Kinds         counter (changed code): 4 divergent turns, 4 errors introduced
                notes (unchanged code): 8 divergent turns, 4 errors introduced
...
  Errors        8 introduced, 0 fixed, 0 new orphaned calls
```

## kronik proposals list

`kronik proposals list`

Lists the proposals with their status (`running`, `failed`, `evaluated`,
`approved`, `promoted`, `rejected` or `stale`), the policy outcome and the
code. `running` and `failed` come from `kronik propose --async` (M10).

```text
$ kronik proposals list
PROPOSAL        STATUS     POLICY            VERIFIED THROUGH  CODE
p-d8e829aa6c7a  evaluated  require_approval  5                 counter b3:9ae922b13c24
Next     kronik proposals show p-d8e829aa6c7a
```

## kronik proposals show

`kronik proposals show <PROPOSAL>`

Shows a proposal as `kronik propose` did, with its current status; a
`running` proposal's progress and a `failed` one's error (exit 1), as
[kronik proposal status](#kronik-proposal-status) does: the two are the
same.

```text
$ kronik proposals show p-d8e829aa6c7a
Proposal p-d8e829aa6c7a   counter   b3:d440473283f4 -> b3:9ae922b13c24   (promoted)
  Causes        3 origins, 0 consequences
                counter on message increment: 3 origins (3 roots)
  Responses     no HTTP root inputs
  Effects       0 changed, 0 added, 0 removed
  State         1 actor changed
                1 actor drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 0.0%, memory p99 0.0%
  Grounding     0 exact, 0 approximate, 0 synthetic (confidence 1.00)

Policy   any-change -> APPROVAL REQUIRED
Next     kronik diff show p-d8e829aa6c7a --md
         kronik rollback <epoch> --reason "..."
```

A request for approval (`request_approval` over MCP) follows the policy,
with its requester and its reason in full: the evidence the human reads
before deciding.

```text
Approval requested at lsn 7 by token:agent-1 (pending):
  step 2 doubles the increment: every replayed response is n+2 instead of n+1,
  and no effect, error or other actor changed
```

## kronik proposal status

`kronik proposal status <PROPOSAL>`

Shows where a proposal is (M10). A proposal's replay runs as a job in the
daemon ([ADR 0022](../adr/0022-proposal-jobs.md)): while it is `running`,
this shows the root inputs replayed so far, per replay mode; afterwards the
proposal as `kronik proposals show` does; for a `failed` one its error
(exit 1). With `--json` it prints the proposal object in every case, and
exits 1 for a `failed` one too.

```text
$ kronik proposal status p-3c1f0e8a9b27
Proposal p-3c1f0e8a9b27 is running: its replay of main from lsn 1200 runs in the daemon
  Progress      isolated 5 of 20, continuous 12 of 20 root inputs
Next     kronik proposal wait p-3c1f0e8a9b27
```

## kronik proposal wait

`kronik proposal wait <PROPOSAL> [--timeout <DURATION>]`

Waits until a proposal's replay is done (M10), printing a progress line to
stderr whenever it moves (also with `--json`: stdout stays one JSON
object), then shows the proposal (with `--json`, the proposal object). It
polls every half second. A poll that cannot reach the daemon, that the
daemon leaves unanswered or cuts short, or that a proxy answers with 502,
503 or 504 is retried with backoff (up to 5 seconds apart; one stderr line
when the trouble starts); a TLS failure (a certificate not trusted or for
another name) is not. `--timeout` (1 hour by default) bounds everything, a
single stalled poll included. It exits 1 with the proposal's error when
the job failed; with `PROPOSAL_RUNNING` when `--timeout` runs out after
the proposal was seen running; and with the transport's error
(`UNAVAILABLE`) when the daemon was never reached. The job goes on either
way. CI runs `kronik propose --async` and then this.

```text
$ kronik proposal wait p-3c1f0e8a9b27 --timeout 45m
p-3c1f0e8a9b27: isolated 5 of 20 root inputs
p-3c1f0e8a9b27: isolated 12 of 20 root inputs
Proposal p-3c1f0e8a9b27   counter   b3:d440473283f4 -> b3:9ae922b13c24   (evaluated)
  ...
```

## kronik approve

`kronik approve <PROPOSAL> --reason <REASON> [--dry-run]`

Approves a proposal's diff when the policy requires an approval. The
approval holds for that diff: if catch-up at promote changes the diff to a
stricter outcome or to new changed targets, promote asks for a new one.

```text
$ kronik promote p-d8e829aa6c7a --reason "ship it"
error: APPROVAL_REQUIRED: proposal p-d8e829aa6c7a needs an approval for this diff (fired: any-change); run: kronik approve p-d8e829aa6c7a --reason '...'
hint:  Read the diff, then run `kronik approve <proposal> --reason '...'`.
docs:  kronik explain APPROVAL_REQUIRED

$ kronik approve p-d8e829aa6c7a --reason "reviewed the diff"
Approved proposal p-d8e829aa6c7a at lsn 6, for its diff b3:a1930a6fc…
  Verified      through lsn 5
Next     kronik promote p-d8e829aa6c7a --reason "..."   (catches up to HEAD first)
```

## kronik promote

`kronik promote <PROPOSAL> --reason <REASON> [--dry-run]`

Switches to a proposal's code. It first catches up: the root inputs that
arrived since the proposal run through the new code too, until the gap is
at most 2 seconds of logical time (`PROPOSAL_STALE` after 5 minutes). Then
the policy is evaluated again on the whole diff (`POLICY_DENIED`,
`APPROVAL_REQUIRED`), and one deployment switches the code of every kind
in the proposal, with one epoch and one LSN; turns that start after it run
the new code of every kind, and turns that arrive while it is being
written wait for it. `Verified` says how many root inputs arrived after
the verified point and ran on the old code only. Every kind in the
proposal, skipped or changed, must still run on main the code main ran
for it when the proposal was made (or still not exist), else promote refuses with
`PROPOSAL_STALE` naming the deployment that changed it: another promote
or a rollback came first, and promoting would overwrite it. This is
checked before catch-up and again at the switch.

Turns already running when the switch lands finish with the old code, and
such a turn can still call a kind the switch changed: old caller, new
callee, a pair no replay ran. When a change stops serving a message or
changes its meaning, keep the old message working for one release. An HTTP
request routed just before the switch runs on the new code of the kind it
was routed to.

```text
$ kronik promote p-d8e829aa6c7a --reason "ship it"
Promoted proposal p-d8e829aa6c7a at lsn 7, epoch 3
  Code          counter b3:9ae922b13c24 (schema 0)
  Verified      through lsn 6; 0 root inputs after it ran on the old code only
Policy   any-change -> APPROVAL REQUIRED (approved)
Next     kronik rollback 3 --reason "..."
         kronik actors list
```

## kronik rollback

`kronik rollback <EPOCH> [--by-replay [--mode continuous|both] [--threads <N>]] --reason <REASON> [--dry-run]`

Writes a new deployment with the code that was in force before the
deployment with this epoch (`kronik deployments list` shows the epochs).
When that deployment switched several kinds (a system proposal), the
rollback restores all of them in one deployment, at one LSN, or none of
them. A rollback that would lower a kind's schema version is refused with
`ROLLBACK_SCHEMA_CHANGED`; an unknown epoch gives `DEPLOYMENT_NOT_FOUND`.

A deployment cannot remove a kind, so rolling back a deployment that
added one (a system proposal with a new actor kind) is refused with
`BAD_REQUEST`, and none of its kinds is rolled back. To undo the other
kinds, propose their earlier components together, `kronik propose
<earlier components> --reason "..."`, and promote that; the added kind
keeps running, and a later proposal can change its code.
`--by-replay` (M13, [design](../design/m13-rebase.md)) rolls back also
after a schema change, without losing data: it creates a rebase proposal
`r-<12 hex>` whose fork starts just before the deployment (before any
migration) and replays every root input since then through the old code.
Its diff shows the state the old code would have produced
(`state.continuous`) and, under `Irreversible`, the external effects the
rolled-back code made that the old code would not have made, which no
rollback can undo. Nothing changes on main yet: `kronik approve` (always
required) and `kronik promote` switch main to that state and the old code
in one `StateRebase` record, holding new requests for at most `[rebase]
max_pause`. Main's history stays. Creating it needs `propose` and `pii:read` (the
rebase replays on full data), and below `[log] disk_reserve` neither the
creation nor its promote is allowed (use plain `kronik rollback`). Only
main's newest deployment can be
rolled back this way, and only when every kind of it existed before;
`--mode isolated` alone is refused. Needs `propose`; the promote needs
`promote`.

```text
$ kronik rollback 4 --by-replay --reason "undo the schema change"
Rebase proposal r-470545e1b8f2 rolls back epoch 4: replayed main since lsn 8 through the old code, verified through lsn 16

  Causes        1 origin, 2 consequences
                counter on message fetch-ok: 1 origin (1 roots)
                counter on message increment: 0 origins (1 roots)
  Responses     no HTTP root inputs
  Effects       0 changed, 0 added, 1 removed
                http.fetch GET 127.0.0.1/v1/charges/{}/extra: 1 change
  State         2 actors changed
                2 actors drifting over the window (cumulative)
  Errors        0 introduced, 0 fixed, 0 new orphaned calls
  Resources     fuel p99 -52.1%, memory p99 +0.0%
  Grounding     1 exact, 0 approximate, 0 synthetic (confidence 1.00)
  Irreversible  1 external effect of the rolled-back code the old code would not have made (cannot be undone)
                http.fetch GET 127.0.0.1/v1/charges/{}/extra (ok, replay-safe) in main:16

Policy   ALLOW
Next     kronik diff show r-470545e1b8f2 --md
         kronik approve r-470545e1b8f2 --reason "..."
         kronik promote r-470545e1b8f2 --reason "..."   (switches main's state and code)

$ kronik approve r-470545e1b8f2 --reason "read the diff"
...
$ kronik promote r-470545e1b8f2 --reason "undo the schema change"
Rebased main at lsn 20, epoch 5: the state is the old code's from lsn 8 on, and the old code runs
  Code          counter b3:e06fea7099d7 (schema 0)
  Rebased       2 replayed turns, verified through lsn 19; 1 irreversible effect
Next     kronik diff show r-470545e1b8f2 --md
         kronik actors list
```

```text
$ kronik rollback 3 --reason "back to steps of 1"
Rolled back epoch 3 at lsn 8, epoch 4: the code before it runs again
  Code          counter b3:d440473283f4 (schema 0)
Next     kronik actors list
```

## kronik watch

`kronik watch <EPOCH> --for <DURATION> --reason <REASON> [--async] [--dry-run]`

Watches a deployment (M11): compares the error rate and latency of its
kinds' turns after it with the equally long window before it, and
evaluates the policy's guards every 5 seconds, once a turn ran after the
deployment, until `--for` (at most 24h) has passed. A `rollback` guard that
fires rolls the deployment back (audit token `kronik`); a deployment that
changed a schema version alerts instead. Each guard that fires is a
`GuardTriggered` record in the log with the metrics it saw. Without a
`guard` key in the policy the default guards apply (see
[M11 watch design](../design/m11-watch.md) §2).

Only the latest deployment of its kinds can be watched (`BAD_REQUEST`
otherwise). A later deployment of any of them ends the watch `superseded`
without any action, so a watch never rolls back newer code.

The watch runs in the daemon and survives the CLI and a restart. Without
`--async`, `kronik watch` follows it, prints the metrics and each guard
that fires to stderr, and ends with the watch; it exits 1 when the watch
rolled back or failed, or when a rollback guard fired and the rollback was
refused or failed. With `--async` it prints the watch's id at once. With
`--dry-run` it shows the metrics now and the guards that would fire. An
unknown epoch gives `DEPLOYMENT_NOT_FOUND`.

```text
$ kronik watch 3 --for 10m --reason "after promote"
w-3k9x2a7b1c0d: watching epoch 3 for 10m
w-3k9x2a7b1c0d: after 25 turns, 25 failed (100.0%), p99 2.1 ms; before 20 turns, 0 failed (0.0%), p99 1.9 ms
Watch w-3k9x2a7b1c0d of epoch 3: rolled_back
  For           10m
  Reason        after promote
  Metrics       after 25 turns, 25 failed (100.0%), p99 2.1 ms; before 20 turns, 0 failed (0.0%), p99 1.9 ms
  Fired         error-rate-up (rollback): rolled_back at lsn 61, epoch 4
Next     kronik deployments list
```

## kronik watches list

`kronik watches list`

Lists the watches with their status (`watching`, `done`, `rolled_back`,
`superseded`, `stopped`, `failed`) and the guards that fired.

```text
$ kronik watches list
ID              EPOCH  FOR  STATUS       FIRED
w-3k9x2a7b1c0d  3      10m  rolled_back  error-rate-up (rolled_back)
```

## kronik watches show

`kronik watches show <ID>`

Shows a watch: its status, the last metrics and the guards that fired. An
unknown id gives `WATCH_NOT_FOUND`. Exits 1 when the watch rolled back or
failed, or a rollback guard's rollback did not happen, also with `--json`.

```sh
kronik watches show w-3k9x2a7b1c0d
```

## kronik watches stop

`kronik watches stop <ID> --reason <REASON> [--dry-run]`

Stops a watch that is `watching`: it ends `stopped` and from then on
writes no record and rolls nothing back. Needs the `promote` scope. A
watch that is over gives `BAD_REQUEST`.

```text
$ kronik watches stop w-3k9x2a7b1c0d --reason "known slow migration"
Stopped watch w-3k9x2a7b1c0d of epoch 3: it alerts and rolls back no more
Next     kronik watches list
```

## kronik policy show

`kronik policy show`

Shows the policy rules in force as TOML: the rules last set, or the
default rules (see [M3 fork design](../design/m3-fork.md) §7 and
[ADR 0007](../adr/0007-policy-cel.md)). Then the guards of `kronik watch`
when they are not in the file: the default guards while the policy has no
`guard` key, or a note that there are none (`guard = []`). The JSON has
them in `guards`, with `default_guards`.

```text
$ kronik policy show
The policy rules set at epoch 2:

guard = []

[[rule]]
name = "any-change"
when = "diff.summary.changed"
action = "require_approval"

No guards: `kronik watch` measures and does not act.

Next     kronik policy test <proposal> --rules <rules.toml>
         kronik policy set <rules.toml> --reason "..."
```

The same file may hold `[[guard]]` tables for `kronik watch`; `policy
show` prints them with the rules. A guard may not refer to `diff`.

## kronik policy set

`kronik policy set <RULES.TOML> --reason <REASON> [--dry-run]`

Replaces the policy rules with the rules in a TOML file. Rules that do not
parse are refused with `BAD_REQUEST`. It replaces every rule: `strict.toml`
below has only `any-change`, so the default rules no longer apply.

```text
$ cat strict.toml
[[rule]]
name = "any-change"
when = "diff.summary.changed"
action = "require_approval"

$ kronik policy set strict.toml --reason "review every change"
Set the policy at lsn 5, epoch 2
Next     kronik policy show
```

## kronik policy test

`kronik policy test <PROPOSAL|FORK> [--rules <RULES.TOML>]`

Evaluates the rules in force, or the rules in a file, against a proposal's
or a fork's diff, and changes nothing. A rule that fails to evaluate counts
as firing.

```text
$ kronik policy test try --rules strict.toml
The rules in strict.toml for try
Policy   any-change -> APPROVAL REQUIRED
Next     kronik policy set strict.toml --reason "..."
```

## kronik preview create

`kronik preview create <PROPOSAL> [--ttl <DURATION>] [--no-pii] --reason <REASON> [--dry-run]`

Creates a preview of a proposal (M11): a fork of main's HEAD, named
`v-<12 hex>`, that runs the proposal's code (its changed kinds and the ones
it pins) on HEAD's state and takes new requests at its own URL. With
`[gateway] preview_domain` the URL is `<scheme>://<id>.<preview_domain>/`
and only that host reaches the preview; without it, the gateway's path
prefix `<scheme>://<host>/__preview/<id>/`, where `<host>` is the first
`[tls] domains` name, else the gateway's address (`0.0.0.0` shown as
`127.0.0.1`). The scheme is `https` when the gateway serves TLS, else
`http`. Each request is a root input of the fork, its turns go to the
fork's log, and its diff lists them as preview inputs. A preview makes no
live effects (I7) but one: a fetch without a stub is denied, except a GET
without secret headers to a host in `[fork] live_allowlist`, which goes
out live. A preview runs without personal data when the proposal does,
with `--no-pii`, or for a token without `pii:read`. It is deleted after
`--ttl` (default `[fork] preview_ttl`, 24 h). Creating one needs the
`fork` scope; at most 16 previews live at once (`PREVIEW_LIMIT`).

```text
$ kronik preview create p-1a2b3c4d5e6f --reason "show the new checkout"
Preview v-9f8e7d6c5b4a of proposal p-1a2b3c4d5e6f at lsn 12
  URL           http://127.0.0.1:8080/__preview/v-9f8e7d6c5b4a/
  Expires       2026-10-28T12:00:00Z
  Effects       only allowlisted GETs go live ([fork] live_allowlist)
Next     curl http://127.0.0.1:8080/__preview/v-9f8e7d6c5b4a/
         kronik diff show v-9f8e7d6c5b4a --md
         kronik preview delete v-9f8e7d6c5b4a --reason "..."
```

## kronik preview list

`kronik preview list`

Lists the previews that have not expired, with their URLs.

```text
$ kronik preview list
PREVIEW         PROPOSAL        EXPIRES               URL
v-9f8e7d6c5b4a  p-1a2b3c4d5e6f  2026-10-28T12:00:00Z  http://127.0.0.1:8080/__preview/v-9f8e7d6c5b4a/
Next     kronik diff show v-9f8e7d6c5b4a --md
```

## kronik preview delete

`kronik preview delete <ID> --reason <REASON> [--dry-run]`

Deletes a preview before it expires: its state and directory go, and its
URL answers `PREVIEW_NOT_FOUND`.

```text
$ kronik preview delete v-9f8e7d6c5b4a --reason "reviewed"
Deleted preview v-9f8e7d6c5b4a
Next     kronik preview list
```

## kronik foreign add

`kronik foreign add <NAME> --image <REF> --port <PORT> [--cpu <CPUS>] [--memory <SIZE>] [--isolation gvisor|trusted|microvm] [--secret [VAR=]<SECRET>]... [--fork-mode recorded|sandbox] --reason <REASON> [--dry-run]`

Declares a foreign actor (M7) and starts it: a Linux program from an OCI
image, pinned by digest (`<registry>/<repo>@sha256:<digest>`, or a local
layout `oci-layout:<dir>`, made absolute), in gVisor with no outbound
network. Actors call it with `http.fetch` on `foreign://<NAME>/...` once
granted `foreign:<NAME>`. Writes a `ForeignActor` record; needs `operate`.
A layout outside `[foreign] layout_dirs` needs `admin` (the daemon reads it
as root); symbolic links inside a layout are refused. Pulls stop after
`[foreign] pull_timeout` (default 10 minutes) and above 8 GiB.
`--secret` passes a secret as an environment variable at every start (the
program sees the value), read as the effects of turns read it: from the
built-in store, or, for a name linked to an external secret manager, from the
node's cache or the backend (`SECRET_UNAVAILABLE` while the backend does not
answer and nothing is cached; the next start retries). A link made later is
seen by the next start. `trusted` runs plain runc with a warning, a
seccomp filter and no user namespace: it is not a security boundary;
`microvm` is `NOT_IMPLEMENTED`. `--fork-mode` (M14) says how forks answer
calls to it: `recorded` (the default) matches production's recordings;
`sandbox` (gVisor only) checkpoints the actor with every snapshot, and each
continuous fork gets a copy from the nearest checkpoint, with no network
and its own disk, deleted with the fork; its answers are graded `forked`.
To change the mode, remove and add the actor again. Errors:
`FOREIGN_EXISTS`, `IMAGE_INVALID`, `RUNSC_MISSING`, `RUNC_MISSING`,
`SECRET_NOT_FOUND`, `SECRET_UNAVAILABLE`, `SCOPE_MISSING`, `UNAVAILABLE` when the image's new
layers do not fit above `[log] disk_reserve`, and `FOREIGN_UNAVAILABLE`
when another daemon holds `[foreign] run_dir` or the registry (or layout
directory) did not answer within `[foreign] pull_timeout`. See
[the M7 design](../design/m7-foreign.md) and
[the M14 design](../design/m14-foreign-forks.md).

```text
$ kronik foreign add echo --image oci-layout:examples/dist/foreign-echo.oci --port 8080 --reason "echo for tests"
Added foreign actor echo (epoch 3, main:3): running
Image    oci-layout:/srv/kronik/examples/dist/foreign-echo.oci@sha256:eef33d7c…
Sandbox  port 8080, 1 CPU, 512 MiB memory, isolation gvisor (systrap)
Secrets  none
Next     kronik grant <kind> foreign:echo --reason "..."   (then call foreign://echo/... from the kind)
         kronik foreign logs echo
```

## kronik foreign list

`kronik foreign list`

The declared foreign actors with their state (`starting`, `running`,
`backoff`, `stopping`), restarts, the last exit, limits and fork mode
(`FORKS`: `recorded`, `sandbox`, or `sandbox (lsn N)` with the newest
checkpoint).

```sh
kronik foreign list
```

## kronik foreign cleanup

`kronik foreign cleanup [--config <PATH>] [--data-dir <PATH>] [--json]`

Run on the host while the daemon is stopped (the systemd unit's
`ExecStopPost=`): deletes what the sandboxes of a daemon that stopped,
crashed or was killed left behind: runsc containers, network namespaces,
bridge sockets, every `bundle/config.json` (they hold secret values),
including those of fork copies (M14), partial checkpoints, and the cgroup
parent, and unmounts runsc's `null-netns`. Refused with
`UNAVAILABLE` while a daemon holds `[foreign] run_dir`, and without root.
The data directory comes from `--data-dir`, `KRONIK_DATA_DIR` or the
configuration, as for `serve`. What it could not remove or list is printed
as a warning on stderr, counted in `failed` (`--json`), and makes the exit
code 1 (the unit's `ExecStopPost=-` ignores it).

For a stopped, allocated fixture only (never a shared runtime directory):

```sh
kronik foreign cleanup --config /owned/fixture/kronik.toml --data-dir /owned/fixture/data --json
```

## kronik foreign logs

`kronik foreign logs <NAME> [--tail <N>]`

The last lines (default 200) the program and its runtime wrote; values of
secrets are replaced by `[secret:<name>]`. Needs `operate`.

```sh
kronik foreign logs echo --tail 20
```

## kronik foreign remove

`kronik foreign remove <NAME> --reason <REASON> [--dry-run]`

Stops the sandbox and writes a `ForeignActor` remove record; the data
directory `foreign/actors/<NAME>/data` is kept, its checkpoints are
deleted. Needs `operate`.

```sh
kronik foreign remove echo --reason "retire the owned echo fixture" --dry-run
```

## kronik stubs set

`kronik stubs set <TARGET> <RULES.toml> --reason <REASON> [--dry-run]`

Replaces how forks answer effects to `TARGET` (`http:<host>` or
`foreign:<name>`) that have no recording (M12): writes one
`SimulatorConfig` record, so the configuration is history, and every
replay uses the one in force at its fork point (I5), plus the overrides its
request carries (`--simulators`; an override can turn the model off for a
target, never on). Needs `operate`. The
file holds `[[stub]]` rules (as for `kronik replay --stub`; each
`url_prefix` must be on the target), `contract = "<file>.json"` (an OpenAPI
3 document in JSON, at most 1 MiB, path relative to the rules file),
`neighbor = true` (reuse the most similar recorded request to the same
route) and `model = true` (allow the model simulator, see
`[simulators.model]` in [operations](../guides/operations.md)). Unknown keys
are an error; an empty file clears the target. See
[the M12 design](../design/m12-simulators.md).

```text
$ cat charges.toml
contract = "charges.openapi.json"
neighbor = true

[[stub]]
method = "GET"
url_prefix = "https://api.example.com/v1/health"
body = "ok"

$ kronik stubs set http:api.example.com charges.toml --reason "fake the charges API in forks"
http:api.example.com now has 1 stub rule, a contract, neighbor (epoch 5, LSN 42).
Next     kronik simulators list
```

A fork effect without a recording tries, in order: request stub rules
(`--stub`), the target's stub rules, the `[fork] live_allowlist`, the
contract, the neighbor, the model, and else fails closed. Every answer
except a live one is synthetic and labeled with its simulator: the diff's
effect items say `grounding: synthetic` with `simulator` `stub`,
`contract`, `neighbor`, `model` or `fail-closed`,
`grounding[*].synthetic_by` and `summary.synthetic_by` count them, and
`kronik trace` shows the label on fork turns. A fork uses the target's
configuration as of its fork point (I5): configuration set later applies to
forks and proposals created after it, or to a replay that carries it with
`--simulators TARGET=FILE` (the same rules file). A policy rule can forbid
synthetic answers per target, for example:

```toml
[[rule]]
name = "no-model-for-payments"
when = "diff.grounding.exists(t, t.host.endsWith('payments.internal') && has(t.synthetic_by) && has(t.synthetic_by.model))"
action = "deny"
```

## kronik simulators list

`kronik simulators list`

The simulators in the order they are tried, whether the model simulator is
configured (endpoint host and model, never the key), and each target's
configuration: stub rules, contract title, neighbor, model, epoch and
reason.

```sh
kronik simulators list
```

## kronik privacy mode

`kronik privacy mode on|off --reason <REASON> [--dry-run]`

Turns privacy mode on or off (M8). With it on, values with a subject that
are written from then on are sealed with their subject's key. Values
written before stay as they are. With it off, new values are stored in the
clear, and sealed values stay sealed. Asking for the mode that is already
in force records nothing. Needs `operate`.

A value gets its subject from the message's `subject`, from the SDK's
`subject`, or, for HTTP root inputs, from `privacy.subject_from` in
`kronik.toml`. That setting is `header:<name>` (the value of a request
header) or `jwt:<claim>`, usually `jwt:sub`: that claim of a bearer JWT.
The gateway does not verify the JWT's signature; it only reads the claim.
So whoever reaches the gateway chooses the subject: it tags data for
sealing and erasure and authenticates nothing. A missing header, token or
claim gives no subject; one that can't be used gives 400 `BAD_REQUEST`.

```text
$ kronik privacy mode on --reason "GDPR: seal personal data" --dry-run
Dry run: privacy mode would turn on (epoch 1); nothing was written
Next     kronik privacy mode on --reason 'GDPR: seal personal data'

$ kronik privacy mode on --reason "GDPR: seal personal data"
Privacy mode is on (epoch 1, lsn 1)
Values with a subject written from now on are sealed with their subject's key;
values written before stay as they are.
Next     kronik privacy status

$ kronik privacy mode on --reason "again"
Privacy mode was already on; nothing was recorded
Next     kronik privacy status
```

## kronik privacy status

`kronik privacy status`

Shows privacy mode, the configuration epoch it was last set in (`none yet`
before the first change), the keystore's counts, how many erasures still
have a plain value in the log or in `state.db` (a state value, a queued
timer or message body, a saved response, a dead letter), and reseal
progress. If a rewritten segment has not been replaced in object storage
yet, it says the shipped copy still holds the old bytes. Needs `read`.

```text
$ kronik privacy status
  Mode          on (epoch 1)
  Keystore      0 subjects, 0 keys, 0 erased
  Erasures      0 still have a plain value in the log or state.db
  Reseal        0 of 0 segments, 0 values sealed, 0 tombstones
Next     kronik privacy mode off --reason "..."
```

## kronik privacy erase

`kronik privacy erase <SUBJECT> --reason <REASON> [--dry-run]`

Erases a subject (M8), such as `user:42`, for a request under GDPR article
17. It deletes the subject's keys, so its sealed values can't be read again
anywhere: in the log, in the state, in replays and in forks. It also
deletes the subject's SQL rows. An `Erasure` record keeps the reason and
the caller. `key version 0` means the subject had no key: none of its
values was sealed. Values that were written with privacy mode off are
still plain in the log until they are resealed, and the command warns with
their count. When `complete_after_ms` is set, the command prints that wall
time: the erasure counts as complete after it, once reseal and snapshot
replacement have run. Needs `operate`.

```text
$ kronik privacy erase user:42 --reason "GDPR art. 17 request #1182" --dry-run
Dry run: subject user:42 can be erased (epoch 2); nothing was written
Next     kronik privacy erase user:42 --reason 'GDPR art. 17 request #1182'

$ kronik privacy erase user:42 --reason "GDPR art. 17 request #1182"
Erased subject user:42: its sealed values can't be read again (key version 0, epoch 2, lsn 3)
Next     kronik privacy status

$ kronik --json privacy erase user:43 --reason "GDPR art. 17 request #1183"
{"dry_run":false,"subject":"user:43","key_version":0,"epoch":3,"lsn":4,"plain_values":0}
```

## kronik privacy reseal

`kronik privacy reseal --reason <REASON> [--dry-run]`

Rewrites closed log segments (M8). Privacy mode must already be on
(`BAD_REQUEST` otherwise). A tagged plain value becomes sealed with the
subject's current key; a value of an erased subject becomes a tombstone.
The rows the rewritten records hold in `state.db` follow: state values, the
bodies of pending timers and undelivered messages, saved responses and dead
letters. The segment still being written is left until it rolls.
`--dry-run` reports how many closed segments would change and writes
nothing. Needs `operate`.

```text
$ kronik privacy reseal --reason "seal history written before privacy mode" --dry-run
Dry run: reseal would rewrite 2 closed segments; nothing was written
Next     kronik privacy reseal --reason 'seal history written before privacy mode'

$ kronik privacy reseal --reason "seal history written before privacy mode"
Resealed 2 closed segments
Next     kronik privacy status
```


## kronik snapshot list

`kronik snapshot list`

Lists snapshots of main, newest first (M6). Needs `read`. A snapshot is a
consistent copy of the materialized state at one LSN: `state.db`, every
actor database and the secret store. The daemon also takes one on a
schedule and on a controlled shutdown.

```text
$ kronik snapshot list
id                         lsn  state hash                                                            bytes    reason  shipped  created
main-00000000000000000012  12   b3:9f2c1a0e4b7d8c6a5e3f1d0c9b8a7061524332415069788a7b6c5d4e3f2a1b0  1.2 MiB  manual  no       2026-10-25T10:00:00Z
Next     kronik snapshot create --reason "..."
```

`shipped` is yes when that snapshot's LSN is recorded in `<data_dir>/ship.json`,
and no when shipping is off or the snapshot has not been uploaded.

## kronik snapshot create

`kronik snapshot create --reason <REASON> [--dry-run]`

Takes a snapshot now (`POST /v1/snapshots`, scope `operate`). The reason is
required, as for every mutation; the snapshot record itself is marked
`manual`. `--dry-run` reports the LSN it would capture and writes nothing.
Nothing is taken when nothing has been applied since the last snapshot.
Every snapshot also checkpoints the `--fork-mode sandbox` foreign actors
(M14); `kronik foreign list` shows the newest checkpoint.

```text
$ kronik snapshot create --reason "before the deploy" --dry-run
Dry run: a snapshot of main at lsn 12 would be taken; nothing was written
Next     kronik snapshot create --reason 'before the deploy'

$ kronik snapshot create --reason "before the deploy"
Snapshot main-00000000000000000012 at lsn 12
  State hash    b3:9f2c1a0e4b7d8c6a5e3f1d0c9b8a7061524332415069788a7b6c5d4e3f2a1b0
  Bytes         1.2 MiB
Next     kronik snapshot list
```

## kronik integrity

`kronik integrity [--through <LSN>]`

Prints the applied LSN, the state hash, a hash of the log still on disk,
and the retention window (`GET /v1/integrity`, scope `read`). A restore is
checked by comparing the hashes with the source node. A restored node's
first start appends one `restore` audit event after the source's last
record (M28), so compare its log through the source's applied LSN:
`kronik integrity --through <the source's applied LSN>` on the restored
node gives the source's log hash, its state hash is the source's, and
`kronik audit show --from <that LSN + 1>` shows the one `restore` line.
`--through` hashes the log only through that LSN (1 to the applied LSN;
`through_lsn` in the JSON). Log first LSN is the oldest
record retention has kept. The window is `[retention] history` back from
the newest logical time; a fork point before the cutoff is refused.

```text
$ kronik integrity
Applied LSN   13
State hash    b3:9f2c1a0e4b7d8c6a5e3f1d0c9b8a7061524332415069788a7b6c5d4e3f2a1b0
Log hash      b3:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80
Log first LSN 1
Window        7 days back from logical time 1761400000000 (cutoff 1760795200000)
Next     kronik snapshot list
```

## kronik export status

`kronik export status`

Shows every export stream of the daemon (M28): `traces` (spans over OTLP,
`[otel]`) and `audit` (`GET /v1/export`, scope `read`). For each: whether
it is on, the sink's scheme and host only (never a path, query or
credentials), the cursor (the last LSN the sink acknowledged), the lag
behind the applied LSN, the last success, the last error's code (such as
`http_503`, `connect` or `timeout`; never its text) and the gaps retention
made since the start. With `--json`, `stalled_ms` is, while there is lag,
the time since the last delivery (or since the start without one);
`kronik doctor` warns on it. A configuration change (a grant, a deployment, a
policy) that lands while a stream is reading a batch makes that read fail once
with `UNAVAILABLE`; the stream reads the batch again about a second later, so
the last error can read `UNAVAILABLE` for that moment without a sink being
down. Nothing is lost or sent twice.
`storage_sync` means any sync failure or EIO latched the file writer:
it makes no later filesystem attempts or cursor acknowledgements.
The node remains usable. Repair/quarantine storage, create a new writer
and safely rewind; restart alone does not prove durability repaired.
`s3_unsupported` means the audit backend cannot perform the required atomic
create; no cursor advances. Configure a supporting backend, not an overwrite
fallback. Current archive names are monotonic, independent of clock rollback:
`audit-v2-<sequence>.jsonl` locally and `audit/v2/<sequence>.jsonl` remotely.
The `v2` names the numbering scheme; the lines in them are
`kronik.audit/v3`.
Keep the remote namespace append-only; see the operations guide for rotation
and backend-consistency requirements.

```text
$ kronik export status
stream  enabled  sink                   cursor  lag  last success          last error  gaps
traces  yes      http://127.0.0.1:4318  41      0    2026-10-27T09:12:04Z  -           0
audit   yes      file://                41      0    2026-10-27T09:12:04Z  -           0
```

## kronik export rewind

`kronik export rewind <STREAM> --to <LSN> --reason <REASON> [--dry-run]`

Moves a stream's cursor back, so that the records after `--to` are sent
again, after a sink lost them (`POST /v1/export/{stream}/rewind`, scope
`operate`). `--to` is at most the cursor, and not before the record before
the first retained one (`AUDIT_RANGE_GONE`). For `audit`, retention is held
from `--to` at once. A stream that is off answers `EXPORT_NOT_CONFIGURED`.
The rewind writes audit intent before its effect; failure records an event
and stable code. An owned task preserves the request if the caller
cancels. New requests wake retries, survive older acknowledgements, and
begin a new generation with a checkpoint exactly at its earliest cut.
Pending replay clears only when that generation reaches its replay head.
For traces, causal state is rebuilt at `--to` from retained source records.
The hold is restored before exporter startup and moves only after durable
checkpoints. Current control/checkpoint and restore behavior is exercised
by the exporter integration and actual binary audit tests.

```text
$ kronik export rewind audit --to 1200 --reason "the bucket lost a day"
audit resends from LSN 1201 (its cursor was 1342)
Next     kronik export status
```

## kronik audit show

`kronik audit show [--from <LSN>] [--limit <N>]`

Prints the audit lines (`kronik.audit/v3`) of main's log from `--from` (the
first retained record by default), as an audit sink receives them, also
when no sink is set (`GET /v1/audit`, scope `admin`: the lines name tokens
and callers). `--limit` is 1 to 1000 lines, 100 by default; a page ends
between records. `--json` prints the lines in full.
Unavailable secret inventory returns HTTP 503 `SECRET_UNAVAILABLE`
rather than an unscrubbed projection.

```text
$ kronik audit show --limit 3
lsn  action         at                    token       reason
1    deploy         2026-10-27T09:10:00Z  unix:uid=0  first version
3    send           2026-10-27T09:10:02Z  unix:uid=0  check the key
3#1  secret.reveal  2026-10-27T09:10:02Z  unix:uid=0  check the key
Next     kronik audit show --from 4
```

## kronik audit verify

`kronik audit verify [--sink <URL>] [--from <LSN>] [--to <LSN>] [--config <PATH>] [--data-dir <DIR>]`

Compares an audit sink with main's log (m28-otel §4.5): every audited
record in (`--from`, `--to`] must have its line, deduplicated by `lsn`,
`effect` and `record_hash`, and equal in kind, action, token and time;
no line may be extra or conflict with the log's record. Known schema,
source-derived hash and identity fields are validated. New emissions are
`kronik.audit/v3`, whose `record_hash` (`b3k:v3:`) is keyed with the master
key, so verification loads the master key as the daemon does. Legacy v2 and
v1 lines are read too, and retries in mixed formats count as one logical
source item. Only trusted source restore records authorize superseding a
tail, never a sink's own restore claim. Restore/gap positions are
validated action-specific `u64`: JSON numbers in v3 and v2, decimal
strings in v1.
Needs no daemon: it reads the data directory (`--data-dir`, else `server.data_dir`)
and the sink, `--sink` or `[audit] sink`: a `file://` directory or an
`s3://` bucket (with `[audit] endpoint` and the `AWS_*` variables). A
webhook cannot be read back. `--from` defaults to the record before the
first retained one, `--to` to the audit cursor in `export.json`. It prints
the report, and exits 1 unless the sink is complete.

```text
$ kronik audit verify --sink file:///var/log/kronik/audit/
Complete: file://: 1342 audited items in (0, 1342], 1342 distinct lines
```

## kronik token create

`kronik token create --name <NAME> [--scopes <SCOPE>,...] --reason <REASON> [--dry-run]`

Creates an API token (M5): a bearer credential with scopes, for an agent,
a script or a person. The scopes are `read`, `fork`, `propose`, `approve`,
`promote`, `operate` (grants, limits, secrets, messages and resends on
main), `pii:read` and `admin` (every scope, and tokens); without
`--scopes` a token gets an agent's `read,fork,propose`. Every change the
token makes is recorded as `token:<name>` with its reason, so a name is
never reused, even after a revoke. Creating tokens needs `admin`. The token
is printed once; Kronik stores only its hash, in `keys/tokens.db`.

```text
$ kronik token create --name agent-1 --reason "the CI agent"
Created token agent-1, recorded as token:agent-1
  Scopes        read, fork, propose
  Token         kronik_EXAMPLEexampleEXAMPLEexampleEXAMPLEexampleE
This is the only time the token is shown; Kronik keeps only its hash.
Give it to its holder through a secret store, not a chat or a ticket.
Next     KRONIK_TOKEN=<token> kronik <command>   (the CLI as this token)
         KRONIK_TOKEN=<token> kronik mcp   (an agent's MCP server, as this token)
         kronik token revoke agent-1 --reason "..."
```

A request outside the token's scopes fails with `SCOPE_MISSING`, and the
hint names the scope:

```text
$ KRONIK_TOKEN=$AGENT_TOKEN kronik grant counter http:api.example.com --reason "try"
error: SCOPE_MISSING: token token:agent-1 lacks scope operate
hint:  Use a token with the operate scope; an operator creates one with `kronik token create --name <name> --scopes operate --reason "..."`.
docs:  kronik explain SCOPE_MISSING
```

A token without `pii:read` always gets forks without personal data:
`fork create` and `propose` record `no_pii` for it whether or not it asked.

## kronik token list

`kronik token list`

Lists the tokens, live and revoked: name, scopes, when and by whom each was
created, and whether it is live. Never the tokens themselves. Needs `admin`.

```text
$ kronik token list
NAME     SCOPES                CREATED               BY          STATE
agent-1  read,fork,propose     2026-10-25T05:51:52Z  unix:uid=0  live
alice    read,approve,promote  2026-10-25T05:51:52Z  unix:uid=0  live
Next     kronik token revoke <name> --reason "..."
```

## kronik token revoke

`kronik token revoke <NAME> --reason <REASON> [--dry-run]`

Revokes a token: from then on it authenticates nobody, on the socket or
over TCP, also in the middle of an MCP session. The record stays, with who
revoked it and why. An unknown name gives `TOKEN_NOT_FOUND`. Needs `admin`.

```text
$ kronik token revoke agent-1 --reason "rotated"
Revoked token agent-1: it authenticates nobody from now on
  Scopes        read, fork, propose
Next     kronik token list

$ KRONIK_TOKEN=$AGENT_TOKEN kronik actors list
error: UNAUTHENTICATED: the bearer token is unknown or revoked
hint:  Send a live token as `Authorization: Bearer <token>` (KRONIK_TOKEN for the CLI). `kronik token list` shows the tokens and `kronik token create` makes one.
docs:  kronik explain UNAUTHENTICATED
```

## kronik fleet enroll

`kronik fleet enroll <URL> [--token <ONE_TIME> | --token-file <PATH> | --token-stdin] --reason <REASON> [--dry-run]`

Asks the local daemon to enroll with a fleet controller, through the ordinary
authenticated `POST /v1/fleet/enroll` API. Local operator configuration pins the
controller's server trust, canonical origin, installation identity and exact
ordinary scopes. Before the first request the daemon durably creates its owned
private leaf key and CSR; normal bootstrap does not require a manually supplied
client certificate. The trusted issuer's returned certificate must match that
exact request and CSR. No private key is sent to the controller or generated
production root introduced. Dry-run creates no key, certificate, durable grant or
remote enrollment and consumes no one-time credential.

Initial enrollment requires exactly one explicit credential source; the daemon
rejects a missing credential with `BAD_REQUEST`. Prefer `--token-file` or
`--token-stdin`: a literal `--token` appears in process listings and shell history.
File and stdin input are bounded to 4096 bytes; surrounding whitespace is
removed, and the remaining credential must be nonempty printable ASCII without
spaces. Neither input errors nor normal output print the credential.

Omit all credential flags only for a dry-run preview, or to recover the exact
existing durable requested enrollment after a lost controller reply. The CLI
sends `token: null`, never reuses the API bearer or invents an empty credential.
The daemon decides whether recovery matches its existing durable request;
omission cannot create a new grant, consume another credential or fall back to
permissive enrollment.

Within `fleet enroll`, `--token` is the **one-time enrollment credential**, not
the ordinary API bearer. Supply the API bearer in `$KRONIK_TOKEN`, in
`kronik --token <API_BEARER> fleet ...` before `fleet`, or as
`kronik fleet --api-token <API_BEARER> ...`. Outside the `fleet` command tree,
the global `--token` keeps its ordinary meaning and placement.

```sh
kronik fleet enroll https://controller.example.com:7443 \
  --token-file /run/secrets/fleet-enrollment --reason "join this installation"
```

## kronik fleet status

`kronik fleet status`

Reads `GET /v1/fleet`, showing the daemon's actual enrollment status. This is
an ordinary API request, not an offline configuration inspection. `--socket`
still selects a reachable local Unix API when the controller is unavailable.
Human output renders the API response as indented JSON; `--json` prints the
response unchanged, without inventing an installation identity.

```sh
kronik fleet status
```

## kronik fleet revoke

`kronik fleet revoke --reason <REASON> [--dry-run]`

Revokes enrollment using the ordinary `POST /v1/fleet/revoke` API. It remains
available through the daemon's Unix socket and has no alternate privileged
offline path. The daemon checks the API caller's authorization, records the
reason and enforces dry-run semantics.

```sh
kronik fleet revoke --reason "revoke the owned fixture's enrollment" --dry-run
```

## kronik events list

`kronik events list [--source actor-native|actor-N|metadata] [--cursor <CURSOR>] [--limit <N>]`

Reads a bounded page from `GET /v1/events`; the limit is 1–256 (default 100).
Pass the returned opaque cursor unchanged to continue. Cursors track installation,
branch and typed source positions, never a fabricated global LSN: actor positions
use the actual native/sharded actor-log LSN; metadata positions use the actual
consensus index. Cursor keys are canonical `actor-native`, `actor-<u32>` or
`metadata`, not arbitrary shard labels.
`--source` selects only an actual configured source. An unavailable source fails;
it is never substituted with actor zero, a native node or an empty metadata feed.
The response exposes history gaps rather than claiming uninterrupted delivery.
Both `events list` and `events tail` send `--cursor` in the standard
`Last-Event-ID` header, never in the URL. This preserves the complete bounded
cursor across all source streams without exceeding HTTP URI-length limits.
Small cursors can be literal JSON values. For a full cursor, use `--cursor -`
to read bounded JSON from stdin, including a file redirected by the shell:
`kronik events list --cursor - < checkpoint.json`. The CLI checks the published
cursor schema, source domains and 525568-byte bound locally before any HTTP
request. Invalid input errors never echo the input. There is no `@file` syntax,
extra cursor-file option or automatic disk cache.

```sh
kronik events list --source actor-native --limit 100
```

## kronik events tail

`kronik events tail [--source actor-native|actor-N|metadata] [--cursor <CURSOR>] [--limit <N>] [--json]`

Opens the actual long-lived `GET /v1/events/stream` SSE response over the same
Unix socket or verified TLS transport as every other API command. It does not
poll JSON pages. With no limit it follows until Ctrl-C, which exits normally;
a positive `--limit` exits successfully only after that many complete operational
events. Heartbeats and cursor-only frames do not count. EOF before completion,
malformed or oversized frames, disconnects and explicit gaps fail visibly.
Startup API failures retain their stable error codes.
Omitting `--source` follows all configured sources without inventing an order
between them. Selecting a source preserves the original full typed cursor.

Each SSE `id` is an opaque resume cursor **after** its event. It is not the
event envelope's replay-stable `id`. Cursor-only frames may advance past records
that emit no event. A checkpoint advances only after a complete valid frame and
successful event output, never when an `id` line precedes incomplete or invalid
data. Finite completion, Ctrl-C and disconnects publish the last acknowledged
checkpoint when available; a failed write still exits with an error. No reconnect
is automatic, and gaps are reported rather than silently skipped.

`--json` writes one published `kronik.event/v1` envelope per line (NDJSON),
then a final published `kronik.events-cursor/v1` checkpoint. Its per-line schema
is `Event | ResumeCursor`; failures may additionally print the stable error JSON.
Save the cursor footer bytes unchanged and resume through stdin, not a potentially
oversized shell argument. A line filter preserves the cursor's full integer
coordinates without reserializing them:

```sh
kronik events tail --json --limit 100 |
  grep '^{"schema":"kronik.events-cursor/v1",' > checkpoint.json
kronik events tail --cursor - --json --limit 100 < checkpoint.json |
  grep '^{"schema":"kronik.events-cursor/v1",' > next-checkpoint.json
```

Human output labels the complete JSON checkpoint and gives the same feasible
`--cursor - < checkpoint.json` hint. Event lines show stable event identity,
the actual actor branch when applicable, typed actor-log or metadata-consensus
position and record kind, not raw
operational metadata. `source` in JSON is a tagged `kind: actor` (optional numeric
shard and LSN) or `kind: metadata` (consensus index), with no legacy top-level LSN
or shard aliases.
Actor events carry their actual `branch`; metadata events omit `branch` entirely,
never claiming `main` or an empty synthetic branch. The cursor identity's branch
selects the actor feed only and does not assign branch provenance to metadata.
Imported native-history events include `data.adoption`. Human output explicitly
marks `adoption=archive (imported history)` or
`adoption=current-projection (imported history)`. The latter means a captured
current projection, not a newly created installation or grant; neither marker
changes the original action or invents an original issuer.
Resume IDs use the shared 525568-byte cursor budget. Complete frames permit two
full cursors plus a 1 MiB event page and 8192 bytes of envelope/framing overhead;
individual lines permit one cursor plus a 1 MiB page and 4096 bytes of overhead.
Oversized or invalid header values fail instead of truncating or dropping streams.
The consumer writes each event before reading more, so slow stdout applies
backpressure.

## kronik events schemas

`kronik events schemas`

Reads `GET /v1/events/schemas`, the daemon's published schema registry.
See also [JSON output](json.md).

```sh
kronik events schemas
```

## kronik events webhooks status

`kronik events webhooks status`

Reads `GET /v1/events/webhooks`, showing delivery status for configured webhook
names. It does not expose webhook signing secrets.

```sh
kronik events webhooks status
```

## kronik events webhooks replay

`kronik events webhooks replay <NAME> --cursor <CURSOR> --reason <REASON> [--dry-run]`

```sh
kronik events webhooks replay owned-native --cursor "$CHECKPOINT_CURSOR" \
  --reason "replay the retained boundary" --dry-run
```

As with list and tail, `--cursor -` reads and validates the bounded cursor JSON
from stdin; file input uses shell redirection.
The CLI sends the validated cursor as the API's typed JSON object, not a quoted
JSON string. List and tail still encode that same cursor in `Last-Event-ID`.

Calls `POST /v1/events/webhooks/<name>/replay` with the opaque cursor, reason and
dry-run flag. The destination and signing key remain daemon configuration;
the command cannot choose a new destination or supply a signing secret.
Replay is an ordinary authenticated and audited mutation, not a direct sender.

The current Root integration is source-only. Its actual Native producers and
ordinary API/CLI adapters are separate from the genuine Member/registered-source
factories; no absent factory is a working empty source or a native fallback.
Historical native scenario receipts do not establish this newer source cohort.


## kronik mcp

`kronik mcp [--socket <PATH>] [--token <TOKEN>]`

Serves the Model Context Protocol on stdin and stdout for an agent's MCP
client, and forwards each request to the daemon's MCP endpoint, `/mcp` on
the API socket (`--socket` and `$KRONIK_API_SOCKET` apply; `--json` does
not). With `--token` or `$KRONIK_TOKEN`, the agent acts as that token,
with its scopes; an agent's token has `read`, `fork` and `propose`.
Without a token, it acts as the socket's caller, with every scope. The same
endpoint answers over TCP with `--api-listen` and a bearer token, so
`kronik mcp --url` is refused (`BAD_REQUEST`, exit 1), as is a set
`$KRONIK_URL` unless `--socket` is given, with the hint to
point the agent's MCP client at `https://<host>:<port>/mcp` (Streamable
HTTP) with `Authorization: Bearer <token>`. See
[ADR 0008](../adr/0008-mcp-server.md) and the
[agent guide](../guides/agent.md).

A request may be up to 64 MiB over stdio, as over the endpoint: a
TypeScript component in base64 (about 17.5 MB) fits. A longer one is
answered with a JSON-RPC error whose message starts with
`PAYLOAD_TOO_LARGE`.

The tools are thin layers over the JSON API, each with the scope its API
route needs:

| Tool | Scope | Does |
| --- | --- | --- |
| `list_actors`, `inspect_actor` | `read` | Actors and their state |
| `query_history`, `trace_turn` | `read` | History and causal trees |
| `list_dead_letters` | `read` | Failed inputs and uncertain effects |
| `create_fork`, `send_to_fork` | `fork` | Forks, without personal data for a token without `pii:read`, and messages into them |
| `propose_change` | `propose` | Replays recent traffic through new code; the proposal, its diff summary and the next commands |
| `get_diff` | `read` | The whole behavior diff of a proposal or a fork |
| `request_approval` | `propose` | A pending request, with the exact `kronik approve` command for a human |
| `promote`, `rollback` | `promote` | Switch code; promote runs catch-up first |
| `explain` | `read` | `kronik explain`: concepts, error codes and the agent guide |

Tools that change something require `reason`. All of them but
`send_to_fork` also accept `dry_run`. A failed call returns the API's error
JSON, `SCOPE_MISSING` included. The resources, which need `read`, are
`kronik://agent-guide` (`AGENT_GUIDE.md`), `kronik://concepts`,
`kronik://errors`, `kronik://wit/kronik-actor.wit` and `kronik://config`.
Stdout carries only JSON-RPC; when no daemon answers, the command exits
with 1 and an `UNAVAILABLE` error on stderr.

With `KRONIK_TOKEN` already set to the allocated agent's scoped token, connect
the MCP client to the owned fixture socket:

```sh
kronik mcp --socket /owned/fixture/api.sock
```

## kronik explain

`kronik explain <TOPIC>` or `kronik explain --list`

Prints the built-in documentation for a concept, an error code or the agent
guide (`kronik explain agent` prints `AGENT_GUIDE.md`), without a daemon.
Topics ignore case, so `kronik explain actor_not_found` works.
`--list` lists every topic; `--json` gives a topic as
`{"name","kind","title","http_status","milestone","text"}` (`kind` is
`concept`, `guide` or `error_code`; `http_status` only for error codes) and
the list as `{"topics":[…]}`. `milestone` is the roadmap milestone that
introduces the topic.

```text
$ kronik explain dead-letters
dead-letters: Inputs whose turn failed, kept for inspection and resend

Dead letters are inputs whose turn failed. Failed messages end up there, and from M2 so do timers, uncertain effect outcomes and compensations that fail. They show up in `history` and in `kronik dead-letters list`. There is no automatic retry, because the outcome would then depend on time; `kronik dead-letters resend` creates a new root input instead.

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: `turn`, `root-input`, `TURN_FAILED`, `EFFECT_OUTCOME_UNKNOWN`.

Milestone: M1
```

## kronik test-host

`kronik test-host [--dir <PROJECT>] [--entry <ENTRY>]... [--wasm <COMPONENT>]... [--seed <N>] [--start-ms <MS>]`

This hidden command is the SDK testkits' real in-memory host, not a production
deployment command. `--dir` builds/deploys the project; `--entry` requires it.
`--wasm` deploys an existing component and can be repeated. The host prints a
ready JSON line, then consumes one request per stdin line and returns one JSON
line per request. Progress/errors go to stderr. The clock and randomness are
seeded; the host settles work caused by a request before responding.

From a source checkout with the maintained counter component:

```sh
printf '%s\n' '{"op":"http","method":"POST","path":"/counter/a/increment","body":""}' | \
  kronik test-host --wasm tests/guests/counter.wasm --seed 0
```

The JSON-lines operations are `http`, `api`, `advance`, `stub`, `requests` and
`settle`; their actual request/response contract is
`crates/kronik-testhost/src/protocol.rs`. An `http` request uses the gateway;
an `api` request uses the management API; `advance` drives due timers;
`stub` supplies recorded fixture responses, and `requests` inspects them.
This protocol is not MCP, a network deployment, or evidence that a new app has
been deployed by a fresh agent. IO protocol changes must update the actual
consumer examples and documentation-surface check together.
