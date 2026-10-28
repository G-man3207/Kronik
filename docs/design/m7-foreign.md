# M7 foreign actors in gVisor

Status: binding for M7. Builds on `m1-core.md`, `m2-effects.md` and
`m3-fork.md`; brief sections "Främmande aktörer med gVisor" (SPEC: "Foreign
actors with gVisor"), "Effekter och capabilities" and invariants I5, I6, I7,
I8, I10, I11, I14 and I17. The bridge and the sandbox setup follow ADR 0003;
this document fixes everything ADR 0003 left to M7.

A foreign actor is an ordinary Linux program from an OCI image that runs in a
sandbox. Only its boundary is recorded: every call an actor makes to it is an
effect, and nothing inside the sandbox is deterministic or replayable.

## 1. Crates

| Crate | M7 adds |
| --- | --- |
| `kronik-foreign` | Image references, the blob store, OCI fetch (registries with `oci-client`, local OCI layouts), digest verification, layer unpacking, `config.json`, network namespaces, the `runsc`/`runc` lifecycle through `ProcessRunner`, supervision, the `port-forward --stream` bridge with a connection pool, logs, and `Foreign`, the manager the daemon and the API hold. |
| `kronik-effects` | `foreign::ForeignHost` (the transport trait, next to the capability code), and foreign actors in `Config` (declared actors per epoch). |
| `kronik-store` | `ForeignActor` records go into `config_records` like grants and limits. |
| `kronik-sched` | `NodeParts.foreign`; reconcile at start; `Node::foreign_add` and `foreign_remove`; the `foreign.http` effect in the gate; grants for `foreign:` take a delivery class and a rate. |
| `kronik-fork` | `foreign.http` in the replay gate (matching only, never live) and in the diff's grounding. |
| `kronik-api` | The endpoints in §11 (module `m7`). |
| `kronik` | `kronik foreign add|list|logs|remove` (`cli/foreign.rs`); `serve` builds `Foreign` and stops the sandboxes on shutdown. |

`kronik-foreign` is outside DST like the gateway server (ADR 0004 §5): it
talks to real `runsc`, real sockets and the real kernel. It still takes the
daemon's `Env` for time, tasks, blocking work and child processes, and the
CI hygiene step allows it tokio's `net` feature (Unix sockets) like
`kronik-api`. DST and forks never get a `ForeignHost`.

## 2. Declaration (I5)

`kronik foreign add` and `kronik foreign remove` write `ForeignActor` records
(`proto/kronik/log/v1/config.proto`) at the next configuration epoch, with an
`Audit` (token id, reason, wall time), through the same path as grants
(`Node::commit_config`, under the deploy lock). A fork sees the foreign
actors as at its fork point, and `kronik history` shows every change.

| Field | Meaning and validation |
| --- | --- |
| `name` | DNS-style: labels `[a-z0-9]([a-z0-9-]*[a-z0-9])?` joined by dots, at most 63 characters (`echo`, `payments.internal`). Unique among declared actors: adding a declared name is `FOREIGN_EXISTS`; to change an actor, remove it and add it again. |
| `image` | Always pinned by digest after resolution: `<registry>/<repo>@sha256:<hex>` or `oci-layout:<absolute dir>@sha256:<hex>`. A registry reference without a digest (only a tag) is `IMAGE_INVALID`. A local layout may be given without a digest when its `index.json` holds exactly one image (or as `oci-layout:<dir>:<ref name>`); the record stores the digest it resolved to. The CLI makes the directory absolute. |
| `port` | The TCP port the program listens on inside the sandbox, 1 to 65535. Required. |
| `cpu_millis` | `--cpu` in thousandths of a CPU (default 1000). `cpu.max` quota over a 100 ms period. |
| `memory_bytes` | `--memory` (default 512Mi, at least 16Mi). `memory.max`, and no swap. |
| `isolation` | `gvisor` (default), `trusted` (plain `runc`; the response carries a warning), `microvm` (`NOT_IMPLEMENTED`, nothing is written). |
| `secrets` | `--secret <name>` or `--secret <ENV>=<name>`, stored as `ENV=name`. Without `ENV=`, the variable is the name in upper case with `-` and `.` replaced by `_` (`stripe-key` → `STRIPE_KEY`). Each secret must exist (`SECRET_NOT_FOUND`). §9. |
| `platform` | `systrap` or `kvm`: `[foreign] platform` at add time (`auto` means `systrap`, as the brief says; `kvm` only when the operator chooses it). Empty for `trusted`. |

Not in the record, fixed in v0.1: a pids limit of 1024; the data directory
mounted at `/data` (§10); no outbound network (§6).

`--dry-run` validates the request and resolves and verifies the image (the
blob store is a cache, not history), but writes no record and starts
nothing. Removing an undeclared name is `FOREIGN_NOT_FOUND`.

Remove stops the sandbox (§5) and deletes its bundle; the data directory is
kept.

## 3. Files

```text
<data>/foreign/blobs/sha256/<hex>              verified blobs, content-addressed, shared by all actors
<data>/foreign/actors/<name>/bundle/           config.json (only while starting) and rootfs/ (rebuilt when the image changes)
<data>/foreign/actors/<name>/data/             persistent, bind-mounted at /data; never replayed (§10)
<data>/foreign/actors/<name>/output.log       stdout and stderr of the program and of runsc
<data>/foreign/actors/<name>/output.log.1     the previous 8 MiB
<run>/foreign.lock                             held by the daemon that runs the sandboxes
<run>/runsc/                                   runsc --root (runc: <run>/runc/)
<run>/netns/<name>                             the actor's network namespace (bind mount)
<run>/sock/<name>/                             port-forward sockets
```

Every directory Kronik creates here is mode 0700, whatever the umask, so
secrets in `config.json` and program output stay root's. The one exception
is `data/` itself (0755, owned by the image's user, inside the 0700 actor
directory): a program that drops to another user in the sandbox, as
Postgres's entrypoint does, must still reach what it created under `/data`. Actors live under
`actors/` so no name can collide with `blobs` (before v0.1.1 they were
`foreign/<name>`; the first start moves them, once, marked by
`foreign/actors/.layout`). The move runs under the run lock (below); an
old actor directory that is a symbolic link moves as the link (a relative
target is made absolute); one that is a mount point (it cannot be renamed)
stays where it is, and `actors/<name>` becomes an absolute link to it, as
an operator's link would be. When the move fails (no space), the daemon logs why, with the paths, and runs no
foreign actor: adds answer `FOREIGN_UNAVAILABLE`, `foreign list` shows the
reason, and leftovers of an earlier daemon are still cleaned up, so none
starts on an empty `/data`. Fix the cause and restart.

`<run>` is `[foreign] run_dir`, default `/run/kronik` (a tmpfs, so nothing
survives a reboot). One daemon per `<run>`: the daemon takes an exclusive
lock on `<run>/foreign.lock` at start. A second daemon that finds it held
logs an error and runs without foreign actors (adds answer
`FOREIGN_UNAVAILABLE`; it never touches the other daemon's sandboxes).
Under the lock, before any runtime call, the daemon makes `<run>/runsc`
and `<run>/runc` (the runtimes' `--root`) mode 0700, also when a runtime
created them first: their state files hold the container spec, resolved
secret values included, and the unit's `/run/kronik` is 0750 for the
`kronik` group.
The sandbox id `<id>` is `kronik-foreign-` and 16 hex
characters of BLAKE3 of the name. All ids have one length because runsc
resolves an id by prefix: with `kronik-foreign-<name>`, actor `pay`'s id was a
prefix of `payments`', so runsc refused it while both ran and acted on
`payments` once `pay`'s was gone. At start the daemon deletes every leftover
`kronik-foreign-*` sandbox, longest id first, so ids named the old way go too.
Its cgroup is
`/kronik/<instance>/<name>` under the cgroup v2 root, where `<instance>` is 8
hex characters of BLAKE3 of the runsc root path, so two daemons on one host
never share a cgroup. Shutdown and `kronik foreign cleanup` remove the empty
`/kronik/<instance>`.

## 4. Image to bundle

- **Registry fetch** with `oci-client` (anonymous pull over HTTPS; private
  registries are a known gap): the manifest is fetched by digest and its
  SHA-256 must equal the pinned digest. An index (multi-platform) resolves
  to the entry for `linux` and the host architecture, which is fetched and
  verified by its own digest. Config and layer blobs stream into the blob
  store through SHA-256 and are kept only if digest and size match their
  descriptors. Kronik never trusts a digest a registry reports.
- **Local layout** (`oci-layout:<dir>`): index, manifest, config and layers
  are read from the layout, verified the same way and copied into the blob
  store, so the actor no longer depends on the directory. The daemon reads
  the layout as root, so a directory outside `[foreign] layout_dirs`
  (absolute paths, default none) needs the `admin` scope; the check is on
  the path and again after resolving links (on a blocking thread, given up
  after `pull_timeout`), and the import reads the resolved path. Files are
  opened with `O_NOFOLLOW` and must be regular files, and `blobs/sha256`
  must resolve inside the layout: a symbolic link in a layout is refused.
  The check is not atomic with the import: a link swapped into the
  directory chain afterwards is followed. Blobs are still digest-checked,
  so that reads at most a planted image; keep layout directories writable
  by root only.
- **Bounds.** An image whose layers add up to more than 8 GiB is refused
  before any layer is fetched, and so is one whose layers not yet in the
  store would not fit in the free space above `[log] disk_reserve`
  (`UNAVAILABLE`). A pull or layout import is abandoned after `[foreign]
  pull_timeout` (default 10 minutes); an abandoned layout import stops at
  its next read. A blob being written lives in a `.tmp-*` file that goes
  when its fetch fails or is abandoned; the ones a killed daemon left go at
  the next start. `foreign add` is refused below `[log] disk_reserve`
  before it fetches anything.
- **Garbage collection.** After a remove, a failed add and an add that
  wrote no record (a dry run, a refused write), every blob that no declared
  actor's image and no add in progress needs is deleted, with every
  `.tmp-*`. Fetches hold a lock shared and the collection needs it
  exclusively, so nothing is collected while it is fetched or reused. The
  collection never waits for a fetch (a stalled registry would hold the
  remove or add until `pull_timeout`): while one runs, the round is
  deferred and runs when the last fetch ends; every start also collects
  once, at its first reconcile.
- **Unpack** (lifted from spike C's `oci-tool`, hardened): layers apply in
  order; each layer blob is verified before anything from it is applied and
  its `diff_id` after decompression. Media types: OCI and Docker `tar`,
  `tar+gzip`, and OCI `tar+zstd` (pure-Rust decoder). `.wh.<name>` removes
  `<name>` from lower layers and `.wh..wh..opq` hides every lower-layer
  entry of its directory, whatever their order in the stream; other
  `.wh..wh.*` entries are ignored and an empty whiteout name is an error.
  Paths resolve as in `chroot(rootfs)`: absolute symlinks restart at the
  rootfs, `..` never leaves it, entries containing `..` are rejected, files
  are created with `O_CREAT|O_EXCL`, hard links must point inside the
  rootfs. Device nodes and FIFOs are skipped. An image that unpacks to more
  than 8 GiB or 1 000 000 entries is rejected. Owners and modes come from
  the tar headers, without setuid and setgid (the sticky bit stays): a
  foreign actor needs neither, and the unit's `RestrictSUIDSGID` makes the
  kernel refuse them (ADR 0027).
- **`config.json`** from the image config plus the record: `Entrypoint` +
  `Cmd`, `Env` (secrets override image variables of the same name; a
  default `PATH` if missing), `WorkingDir` (created if missing), `User`
  resolved through the image's own `/etc/passwd` and `/etc/group`, hostname
  = the actor name. `noNewPrivileges`; capabilities are Docker's default set
  minus `CAP_NET_RAW` for uid 0 and none otherwise; `RLIMIT_NOFILE` 65536;
  mounts `/proc`, `/dev`, `/dev/pts`, `/dev/shm`, read-only `/sys` and
  `/data`; `linux.resources` with the CPU quota, memory limit (`swap` =
  limit) and pids limit; `linux.cgroupsPath` (§3); the network namespace path
  (§6). The data directory is chowned to the image user.
- The bundle is rebuilt only when its marker (`bundle/.kronik-bundle`, the
  manifest digest and the bundle format version) differs; `config.json` is
  written at every start and deleted as soon as the sandbox is running (the
  runtime has read it), so secret values do not stay on disk.

## 5. Lifecycle and supervision

**Start order.** `Node::start` recovers the log and loads the configuration,
then calls `ForeignHost::reconcile` with the declared actors and waits for
it, then re-runs open turns (which may redo foreign effects, m2-effects §4),
then re-queues the mailbox; `serve` starts the gateway and the API only
after `Node::start` returns. Reconcile waits until every actor is running or
has failed its first start, at most 30 s in total.

**Leftovers.** The first reconcile after the daemon starts kills and deletes
every container `runsc list` (and `runc list`) shows under Kronik's roots,
unmounts every namespace under `<run>/netns/` and runsc's own
`<run>/runsc/null-netns`, empties `<run>/sock/` and deletes every
`config.json`: sandboxes never survive the daemon that started them. A
daemon killed with SIGKILL cannot do that itself, so the systemd unit runs
`kronik foreign cleanup` as `ExecStopPost=`; it does the same while no
daemon holds `<run>`, needs root, takes the data directory from
`--data-dir`, `KRONIK_DATA_DIR` or the configuration like `serve`, and
prints what it could not remove. Without systemd, run it after a crash.
runsc's own state file (`<run>/runsc/<id>_sandbox:<id>.state`, mode 0640,
which holds the spec) goes with `runsc delete`. A `config.json` also goes
when the runtime cannot be spawned.

**Start** (per actor, one supervisor task): build the bundle if needed,
create the network namespace (§6), write `config.json`, then spawn through
`Env::procs`, with stdout and stderr through a pipe the daemon copies to
`output.log` (capped, §12) and stdin from `/dev/null`:

```text
runsc --root <run>/runsc --platform=<systrap|kvm> --network=sandbox --overlay2=root:memory run --bundle <bundle> <id>
runc  --root <run>/runc run --bundle <bundle> <id>          (trusted)
```

The actor is `running` once the readiness check passes: a bridge connection
(§7) is accepted inside the sandbox, tried every 50 ms for at most 30 s.
For gVisor that is `runsc port-forward --stream` exiting 0 (it exits 128
when nothing listens on the port; measured on dev), for `trusted` a TCP
connect inside the namespace. No HTTP request is sent to the program. That
connection goes into the pool.

**Exit.** The child's exit status is the container's (ADR 0003 §6). Before
`runsc delete --force`, the supervisor reads `memory.events` of the
sandbox's cgroup: a higher `oom_kill` count means the sandbox exceeded its
memory limit, reported as `oom` in the status and the daemon log. Then it
deletes the container and the namespace and drops pooled connections.

**Restart with backoff.** After an exit the actor is in `backoff` and starts
again after 0.5 s × 2^(n−1), at most 60 s, where n counts consecutive
failures; n resets when a run lasted 60 s. A failed start (bundle, missing
`runsc`, readiness timeout) counts as a failure too.

**Stop** (remove, shutdown): `runsc kill <id> TERM`, `KILL` after 10 s,
wait for the child, `runsc delete --force <id>`, delete the namespace.
`kronik serve` stops every sandbox on SIGTERM and Ctrl-C before it exits.

**Status** (`foreign list`): `state` is `starting`, `running`, `backoff` or
`stopping` (and `stopped` while it shuts down); plus `since_ms`, `starts`,
`restarts`, `last_exit` (`{"code", "oom", "at_ms"}`; `code` is null when the
runtime was killed by a signal), `next_start_ms` and `error`.

## 6. Isolation and network

| Level | Runtime | v0.1 |
| --- | --- | --- |
| `gvisor` | `runsc` with `--platform=systrap` (or `kvm`), `--network=sandbox` | yes, the default |
| `trusted` | plain `runc` with the same bundle and a seccomp filter | yes; every add answers with the warning "isolation trusted runs the image with plain runc and the host kernel: only use it for images you trust" |
| `microvm` | Firecracker | `NOT_IMPLEMENTED` |

**Network namespace with only `lo`** (ADR 0003 §2). Before each start,
Kronik creates a namespace by `unshare(CLONE_NEWNET)` on a short-lived
dedicated thread (never a pool thread: the thread's namespace changes), bind
mounts that thread's `/proc/thread-self/ns/net` onto `<run>/netns/<name>`,
and sets `lo` up with `SIOCSIFFLAGS` from a socket inside the namespace.
Deleting is `umount2(MNT_DETACH)` and removing the file. These syscalls have
no safe binding in the dependencies the workspace already has, so they live
in one allowlisted module, `kronik-foreign/src/sys.rs`, on `libc`. With
`--network=sandbox` runsc copies the namespace's interfaces into its
netstack, so the sandbox has a loopback NIC and no route out. runc puts the
container directly in that namespace: also only `lo`.

**Outbound network is blocked** for both levels: there is no interface but
`lo`. The M7 test proves it from inside the sandbox (§14). `--host-uds`
stays `none`.

**`trusted` is not a security boundary.** It shares the host kernel, has no
user namespace and no AppArmor or SELinux profile. Kronik adds what it can
without them: a seccomp filter that refuses (EPERM) the syscalls Docker's
default profile refuses for escapes (`unshare`, `setns`, namespace flags of
`clone`, `mount` and the new mount API, `keyctl`, `bpf`, `perf_event_open`,
`userfaultfd`, `ptrace`, `io_uring_*`, module and kexec calls and the like;
`clone3` answers ENOSYS so libc falls back to `clone`), on top of the empty
capability set for non-root users. Its root file system is the bundle's
`rootfs/` on the host disk.

**Masked paths** (both levels): Docker's list plus `/proc/interrupts` and
`/sys/devices/virtual/powercap` (RAPL energy counters, a side channel).

**Limits.** `cpu.max` (quota/100 ms), `memory.max` with `memory.swap.max`
0, `pids.max` 1024, created by the runtime under `linux.cgroupsPath` and
removed by `delete`. Apps see at least 2 CPUs under gVisor (ADR 0003).
With `--overlay2=root:memory` writes outside `/data` live in the sandbox's
memory and count against `memory.max`; `/data` has no quota of its own
(§16).

## 7. The bridge

- **gvisor:** one `runsc port-forward --stream` per connection (ADR 0003
  §3): Kronik binds a fresh Unix socket in `<run>/sock/<name>/` (mode 0700),
  spawns `runsc --root <run>/runsc port-forward --stream <socket> <id>
  <port>`, accepts the one connection runsc makes
  (within 5 s), removes the socket file and reaps the helper in the
  background.
- **trusted:** a TCP connection to `127.0.0.1:<port>` created inside the
  container's namespace (a short-lived thread does `setns` on the namespace
  file, connects, and exits; the socket keeps its namespace).
- **Pool.** HTTP/1.1 (hyper's client connection) over each stream, kept
  alive; up to 8 idle connections per actor, more are opened on demand. A
  request first tries an idle connection; if hyper reports that the request
  was not sent (`try_send_request` hands it back), it is retried on a fresh
  connection. A restart empties the pool.
- **Requests.** `foreign://<name>/<path>?<query>` becomes `<METHOD>
  /<path>?<query>` with `Host: <name>`, the guest's headers (secret headers
  rendered by the gate), `Idempotency-Key` (§8) and the body. The response
  body is read up to the effect's response limit.
- **Errors (I17).** The actor is not declared at the turn's epoch: denied,
  §8. Not running: the call waits for `running` for at most the rest of the
  effect timeout, else `NetError::Connect("FOREIGN_UNAVAILABLE: <name> is in
  backoff after exit status 3; next start in 4 s")`; a failed bridge
  connection is `Connect` as well, since the request never left the host.
  Anything after the request was handed to a connection is `NetError::Io`:
  the outcome is unknown and the target's delivery class decides what a
  re-run does.

## 8. The `foreign.http` effect

Actors reach a foreign actor with `http.fetch` on `foreign://<name>/...`.

| | |
| --- | --- |
| Capability | `foreign:<name>` (exact; no wildcards), `kronik grant billing foreign:payments.internal --delivery idempotency-keyed --reason "..."`. Without it: `denied("CAPABILITY_NOT_GRANTED: foreign:<name>")`, recorded `DENIED` in the turn (no fsync), and the history hint is the exact grant command. |
| Declared | The actor must be declared in the configuration of the turn's epoch; otherwise `denied("FOREIGN_NOT_FOUND: no foreign actor <name>")`, also deterministic from the configuration. |
| `EffectRecord` | `kind = "foreign.http"`, `target = "foreign:<name>"`, request `HttpEffectRequest` with the `foreign://` URL, response `HttpEffectResponse`, idempotency key, delivery, status, duration, grounding `LIVE`. |
| Fingerprint | The HTTP fingerprint (m2-effects §3) of the request: scheme `foreign`, host = the name. |
| Delivery class | The grant's `--delivery`, else `replay-safe` for GET, HEAD and OPTIONS and `unsafe` otherwise. Re-runs after a crash follow m2-effects §4 unchanged. |
| Idempotency key | `Idempotency-Key: hex(blake3(causal key + ordinal))` on every request, as for `http.fetch`. |
| Rate | `--rate` on the grant, as for `http:`. |
| Limits | The kind's effect timeout (10 s) and response limit (10 MiB). |
| Secrets in headers | As for `http.fetch`: `secret:<name>` needed; the value is inserted at the boundary and scrubbed from the response. |
| Order | `TurnBegin` is fsynced before the first live foreign call (I14); the `EffectResult` is fsynced before the guest sees it. |

**`FOREIGN_UNAVAILABLE`** is what the guest sees (as `network("FOREIGN_UNAVAILABLE:
...")`) when the actor is declared but cannot answer: starting past the
timeout, in backoff, `runsc` missing, or no `ForeignHost` in this process.
The API answers `FOREIGN_UNAVAILABLE` (503) only for `foreign logs` of an
actor whose log cannot be read.

## 9. Secrets for foreign actors

Secrets named with `--secret` are read from the secret store at every
(re)start, at their current version, and passed as environment variables in
`config.json`. Kronik never logs them and never returns them: `foreign
list` shows only `ENV=name`, and `foreign logs` replaces exact occurrences
of every value the program was given since the daemon started and of every
stored version of the secret with `[secret:<name>]`, so a rotation does not
unmask what the old value printed. A version deleted from the store has its
ciphertext wiped and cannot be scrubbed after a daemon restart. The
program in the sandbox sees the values, which is the same trust as
`secret-reveal:<name>` (I8): it can leak them over the boundary.
`config.json` holds the values only until the sandbox is running (§4); it
is written with mode 0600 in a 0700 directory. A secret deleted from the
store makes the next start fail (status `backoff`, error
`SECRET_NOT_FOUND: <name>`).

## 10. The data directory

`foreign/actors/<name>/data` is bind-mounted read-write at `/data` and survives
restarts, removal and daemon upgrades. **It is not replayable**: Kronik
records only the calls across the boundary, never what the program keeps.
A fork does not see it, a restore from a snapshot does not roll it back,
and replay cannot reproduce what the program would have answered from a
different state. Everything outside `/data` is gVisor's overlay, kept in
the sandbox's memory, and is lost when the sandbox stops (ADR 0003).

## 11. Replay and forks

- In a fork (isolated and continuous replay, messages into forks) a
  `foreign.http` effect is matched against production's recordings exactly
  like `http.fetch` (m3-fork §3.5): exact by fingerprint, approximate by
  (method, name, route pattern), else a stub rule or `FailClosed`
  (synthetic). The capability and the declaration are checked against the
  fork's configuration first.
- **The foreign actor is never started in a fork, and no fork sends it
  anything** (I7): the replay gate has no transport, and `[fork]
  live_allowlist` never applies to `foreign://`. Forks get no `ForeignHost`.
- The diff counts `foreign.http` as an external effect; its grounding entry
  has `kind = "foreign.http"`, `host` = the name, `route` = the route
  pattern, so `t.host.endsWith('payments.internal')` works in policies.

## 12. API (`/v1`, conventions as in m1-core §4)

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/foreign` | `{"name","image","port","cpu_millis":1000,"memory_bytes":536870912,"isolation":"gvisor"\|"trusted"\|"microvm","secrets":["stripe-key","API_KEY=stripe-key"],"reason","dry_run"}` (cpu, memory, isolation and secrets optional) | `{"dry_run","foreign":<foreign>,"warnings":[…]}` |
| `GET /v1/foreign` | | `{"foreign":[<foreign>…]}` sorted by name |
| `GET /v1/foreign/{name}` | | `{"foreign":<foreign>}`; `FOREIGN_NOT_FOUND` |
| `GET /v1/foreign/{name}/logs?tail=200` | `tail` 1 to 10 000 | `{"name","lines":["…"],"truncated":bool}` |
| `DELETE /v1/foreign/{name}` | `{"reason","dry_run"}` | `{"dry_run","removed":{"name","epoch","lsn"}}`; `FOREIGN_NOT_FOUND` |

`<foreign>` is `{"name","image","port","cpu_millis","memory_bytes",
"isolation","platform","secrets":["ENV=name"],"epoch","lsn","reason",
"status":{"state","since_ms","starts","restarts","last_exit":{"code",
"oom","at_ms"}|null,"next_start_ms","error"}}`; for a dry run
`epoch` is the epoch it would get, `lsn` is 0 and `status` is null. `add`
waits up to 10 s for the actor to leave `starting` so the response shows
`running` or the start error.

Scopes (`kronik-api::auth`): add and remove need `operate`; list and show
need `read`; logs need `operate`, because a program's output can carry
values Kronik cannot scrub.

Errors: `BAD_REQUEST` (name, port, cpu, memory), `IMAGE_INVALID` (400: not
pinned, unreachable, not an image for this platform, digest or size
mismatch, bad layer), `FOREIGN_EXISTS` (409), `FOREIGN_NOT_FOUND` (404),
`SECRET_NOT_FOUND`, `RUNSC_MISSING` and `RUNC_MISSING` (503: the runtime
binary is missing; nothing is written), `KVM_UNAVAILABLE`,
`NOT_IMPLEMENTED` (`microvm`), `REASON_REQUIRED`.

**Logs.** `output.log` holds what the program and runsc write, through a
pipe the daemon reads: past 8 MiB the file moves to `output.log.1` and a
new one starts, so at most 16 MiB are kept per actor however fast the
program writes. When the daemon is gone the pipe is closed, so a sandbox
never writes to the disk unsupervised.

## 13. CLI

```text
kronik foreign add <name> --image <ref> --port <port> [--cpu 1] [--memory 512Mi]
                   [--isolation gvisor|trusted|microvm] [--secret [ENV=]name]...
                   --reason "..." [--dry-run] [--json]
kronik foreign list [--json]
kronik foreign logs <name> [--tail 200] [--json]
kronik foreign remove <name> --reason "..." [--dry-run] [--json]
kronik foreign cleanup [--config <path>] [--data-dir <path>] [--json]   (daemon stopped)
```

`--image oci-layout:./dir` is made absolute by the CLI. `--cpu` takes
decimals (`0.5`). `--json` prints the response body unchanged.

## 14. Testing

- **Unit** (`kronik-foreign`, no root needed): image references; layout
  resolution and digest checks (a tampered blob, a wrong size, a wrong
  `diff_id`); unpacking (whiteouts, opaque directories, hostile symlinks,
  `..`, hard links, entry types, limits); `config.json` (user resolution,
  env merge, limits, mounts, namespaces); secret env names; log rotation
  and tail; backoff.
- **Integration** (`crates/kronik/tests/foreign.rs`, needs root and runsc;
  skipped with a message otherwise; `scripts/ci.sh foreign` runs it with
  `KRONIK_FOREIGN_TESTS=require`, which turns a skip into a failure; GitHub
  CI installs gVisor with `scripts/install.sh` and runs it under `sudo`): a
  daemon with the `foreign-echo` layout (`examples/foreign-echo`,
  `scripts/build-foreign-examples.sh`) where a test actor calls
  `foreign://echo/...`; the calls are in the log as `foreign.http`; a fork
  replay matches them exactly while the sandbox is stopped and no sandbox
  starts; `GET /egress` inside the sandbox (TCP and UDP to public, private
  and host addresses, DNS) fails every attempt; `remove` stops the sandbox
  and deletes its namespace and cgroup; `POST /exit` restarts it with
  backoff; a secret reaches the program's environment and never the log.
- **Registry fetch**: `kronik-foreign`'s ignored `pull_smoke` test against a
  local `registry:2` container (skopeo pushes the layout); `kronik serve
  --test-insecure-registry <host:port>` (hidden) lets a daemon test pull
  over plain HTTP.

## 18. As built

- Local images: `oci-layout:<absolute dir>`, `oci-layout:<dir>@sha256:<hex>`
  and `oci-layout:<dir>:<ref name>` (split at the first `:`, as skopeo's
  `oci:` transport does; a directory with `:` in its path needs the digest
  form). The CLI makes the directory absolute; the record stores the digest.
- `crates/kronik/tests/foreign.rs` also adds a foreign actor from a local
  `registry:2` container by digest (`--test-insecure-registry`), skipped
  without Docker and skopeo.
- `kronik doctor` adds the checks `runc`, `netns`, `run_dir`, `caps` (the
  daemon has `CAP_SETUID`, ADR 0027) and `sandbox` (§15) after `root`.
- runsc keeps a `null-netns` mount in its `--root` directory; cleanup
  unmounts it, and whoever deletes a run directory (tests) unmounts it first.
- `demo/billing.sh` runs billing-ts with fake-payments as
  `payments.internal` end to end, including the approval the default policy
  requires for the EU VAT change.

## 15. `kronik doctor` (fast-policy)

ADR 0003's list, with what M7 fixes:

- `runsc` at `[foreign] runsc_path`, executable, with `gvisor-bin/gvisor_sentry`
  next to it; else `RUNSC_MISSING`. `runsc --version` parses as
  `release-YYYYMMDD.N`; warn when older than `release-20261019.0`, the
  version M7 is tested with.
- `runc` on `PATH` (`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`,
  `/usr/bin`): information only, needed for `isolation = trusted`
  (`RUNC_MISSING`).
- Kernel 5.6 or newer; `/dev/kvm` openable or not (`platform = "kvm"`
  without it: `KVM_UNAVAILABLE`).
- cgroup v2 with `cpu`, `memory` and `pids` in `cgroup.controllers` of the
  root and writable `/sys/fs/cgroup` (sandboxes go under `/kronik/`).
- Running as root and able to create a network namespace (`unshare -n
  true` or Kronik's own `kronik_foreign::sys` check).
- `[foreign] run_dir` (default `/run/kronik`) exists or can be created.
- Smoke test: `runsc --root <tmp> --platform=<platform> --network=none do
  /bin/true` exits 0 (about 0.3 s on dev); it catches seccomp, AppArmor and
  systrap problems.

## 16. Known limitations

- gVisor implements most, not all, of the Linux syscall ABI; some
  syscalls, ioctls and `/proc` and `/sys` files are missing or partial, and
  some programs fail because of it.
- File I/O goes through the sentry and the gofer and is slower than native;
  I/O-heavy programs suffer most. New connections cost a process spawn
  (13 ms median on the testbench), so the pool matters.
- Under a CPU quota, bursts are throttled per 100 ms period, which shows up
  as latency tails.
- No outbound network at all, no raw sockets, and no inbound network except
  through Kronik's bridge. A foreign actor cannot call actors or other
  foreign actors.
- Registry pulls are anonymous; private registries need a local layout
  (`skopeo copy` into `oci-layout:`).
- The data directory is not replayable (§10), and has no quota: a program
  can fill its file system. Put `<data>/foreign` on its own file system or
  give it a project quota. `[log] disk_reserve` refuses new inputs and
  changes before the log's file system is full, but running turns, timers,
  queued messages and the sandboxes keep writing, so on a shared file
  system it narrows the risk and does not remove it.
- `trusted` is not a security boundary (§6), and its root file system
  writes go to the host disk without a limit.
- v0.1 runs the daemon and the sandboxes as root (rootless is M21).

## 17. Seams in other crates

| File | Change |
| --- | --- |
| `kronik-effects/src/config.rs` | `Config` keeps declared foreign actors (`foreign(name)`, `foreign_actors()`); `ConfigHistory::at` folds `ForeignActor`. |
| `kronik-store/src/db.rs` | `ForeignActor` → `config_records`. |
| `kronik-fork/src/index.rs` | `config_records` includes `ForeignActor`. |
| `kronik-sched` | `NodeParts.foreign: Option<Arc<dyn ForeignHost>>`, reconcile in `Node::start` before re-runs, `foreign_add`/`foreign_remove`, the gate's `foreign.http`, `grant` accepts `--delivery`/`--rate` for `foreign:`. |
| `kronik-fork/src/replay.rs`, `diff.rs` | `foreign.http` matching; `external()` and `target()` know the kind. |
| `kronik-core/src/env.rs` | `ProcessSpec` gains `stdout`/`stderr` (`Stdio::Null` or `Stdio::Append(path)`); the default is null, never the daemon's own stdio. |
| `kronik-core/src/error.rs` | `FOREIGN_NOT_FOUND`, `FOREIGN_EXISTS`, `IMAGE_INVALID`, `RUNC_MISSING`. |
| `kronik-api/src/auth.rs` | `GET /v1/foreign/{name}/logs` needs `operate`. |
| `kronik/src/config.rs` | `[foreign] run_dir`. |
| `scripts/ci.sh` | Hygiene allows `kronik-foreign`; a `foreign` step. |
