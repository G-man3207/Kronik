# 0003. Foreign actors in gVisor: runsc without KVM, bridged with `runsc port-forward --stream`

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

A foreign actor is an ordinary Linux program from an OCI image that runs in
gVisor; only the boundary to it is recorded (brief: "Främmande aktörer med
gVisor", M7). Actors reach it with `http.fetch` on `foreign://<name>/...`,
recorded as `foreign.http`. The sandbox gets no external network, and egress
is disabled in v0.1. `runsc` must use the `systrap` platform, which works on
the testbench VPS without `/dev/kvm` (I11). The brief leaves the bridge from
Kronik into the sandbox to this spike: a bind-mounted Unix socket with
gVisor's `--host-uds`, or `runsc port-forward`.

Spike C (`spikes/spike-c-gvisor/`) built what Kronik will need and measured
both bridges on the testbench:

- `oci-tool bundle` turns an image in a local OCI layout into a runsc bundle:
  it verifies the digests of index, manifest, config and every layer (each
  layer blob before anything from it is applied, the uncompressed `diff_id`
  after), applies the layers in order with whiteouts and opaque directories,
  resolves every path inside the rootfs, and generates `config.json` from the
  image config plus operator overrides.
- A static echo server is the foreign actor; `netprobe`, `bridge-bench` and a
  Unix-socket-to-TCP shim do the rest.
- The scripts and their raw output are in `scripts/` and `results/`.

**Testbench.** Debian 13 (trixie), kernel 6.12.111+deb13-cloud-amd64, 2 vCPU
Intel Xeon (Skylake) under KVM without nested virtualization (no `vmx` or
`svm` flag, no `/dev/kvm`), 3.7 GiB RAM, cgroup v2, systemd 257. The brief
assumes Ubuntu 24.04; nothing here depends on the distribution, but the
numbers should be rechecked on Ubuntu 24.04 when such a testbench exists.

**gVisor packaging.** The pinned release is `release-20261019.0` (OCI spec
1.2.1). Since 2026-07, gVisor releases are a tarball (`gvisor.tar.zstd` or
`.bz2` with a `.sha512`) containing `runsc`, `containerd-shim-runsc-v1` and a
`gvisor-bin/` directory of sidecar binaries (`gvisor_sentry`, `checkpointgofer`
and others) that runsc runs at runtime and looks up next to its own binary. A
single `runsc` binary is no longer a complete install.

## Decision

### 1. Running a foreign actor

Kronik runs each foreign actor in its own sandbox, as a child process, without
`--detach`:

```text
runsc --root /run/kronik/runsc --platform=systrap --network=sandbox \
      run --bundle /var/lib/kronik/foreign/<name>/bundle kronik-foreign-<name>
```

- `--platform=kvm` replaces `systrap` only when `[foreign] platform` asks for
  it and `/dev/kvm` exists.
- `--host-uds` keeps its default, `none`.
- The container's stdout and stderr go to files under
  `/var/lib/kronik/foreign/<name>/` for `kronik foreign logs`. runsc passes
  its own stdio to the container (seen even with `--detach`), so the daemon
  gives the child files or pipes, never its own stdio.

### 2. Network: a namespace with only `lo`

Before each start, Kronik creates a fresh network namespace that contains only
the loopback interface, set up, and puts its path in `config.json`
(`linux.namespaces`, type `network`). With `--network=sandbox`, runsc copies
the namespace's interfaces into its netstack, so the sandbox gets a loopback
NIC and nothing else: no route out. Kronik deletes the namespace after
`runsc delete`; runsc does not.

`--network=none` is not an option: `runsc port-forward` rejects it
(`unsupported network type "none"`). A namespace that runsc creates itself has
`lo` down, and then port-forward fails with `network is unreachable`. Both are
in `13-alternatives.txt`.

### 3. Bridge: one `runsc port-forward --stream` per connection

To open a connection, Kronik listens on a new Unix socket in a directory only
it can access (mode 0700), runs

```text
runsc --root /run/kronik/runsc port-forward --stream <socket> kronik-foreign-<name> <port>
```

accepts the one connection runsc makes to that socket, and removes the socket
file. runsc hands the connection to the sandbox, which connects it to `<port>`
on the sandbox's loopback, and then exits (within a second, status 0); the
connection keeps working. The effect layer keeps a pool of kept-alive
HTTP/1.1 connections per foreign actor and opens the first one at start,
which doubles as the readiness check.

### 4. Bundles

Kronik builds bundles as `oci-tool bundle` does:

- Every blob is checked against its digest and size; layer blobs before they
  are applied, `diff_id`s after decompression. A mismatch fails the bundle.
- Layers apply in order. `.wh.<name>` removes `<name>`, and `.wh..wh..opq`
  hides every entry of its directory, but only entries from lower layers,
  whatever their order in the tar stream.
- Paths resolve as in `chroot(rootfs)`: absolute symlinks restart at the
  rootfs, `..` never leaves it, entries containing `..` are rejected, and
  files are created with `O_CREAT|O_EXCL`. Device nodes and FIFOs are
  skipped. Layer media types in the spike: OCI and Docker tar and tar+gzip;
  zstd layers still need a decoder in M7.
- `config.json` comes from the image config (`Entrypoint` + `Cmd`, `Env`,
  `WorkingDir`, `User` resolved through the image's own `/etc/passwd` and
  `/etc/group`) plus operator overrides. `noNewPrivileges` is set,
  capabilities are Docker's default set minus `CAP_NET_RAW` for root and none
  for other users, and the mounts are `/proc`, `/dev`, `/dev/pts`,
  `/dev/shm`, a read-only `/sys` and the actor's data directory
  (`foreign/<name>/data`).

### 5. Limits

`--cpu`, `--memory` and a pids limit go into `linux.resources`, with
`linux.cgroupsPath` set to Kronik's own cgroup subtree. runsc creates the
cgroup v2 directory with `cpu.max` (quota and 100 ms period), `memory.max`,
`memory.swap.max` 0 (`swap` equal to `limit`) and `pids.max`, puts the
sandbox processes in it, and removes it on `runsc delete`.

### 6. Supervision

- The child's exit status is the container's exit status: 3 when the app
  exits with 3, 137 after `runsc kill KILL` and 137 when the sandbox process
  is killed on the host (30 of 30 in `12-wait-race.txt`). `runsc wait` on a
  detached sandbox is not reliable. It reported the app's own exit when it
  was waiting in time (10 of 10), but it got the status in only 1 of 10 runs
  after `runsc kill` and in 0 of 10 after `kill -9`; it then fails with
  `sandbox no longer running and its exit status is unavailable`.
- Kronik restarts a foreign actor with exponential backoff. Before
  `runsc delete`, it reads `memory.events` in the sandbox cgroup: exceeding
  `memory.max` makes the host OOM killer kill the sentry, and with it the whole
  sandbox.
- Stop: `runsc kill <id> TERM`, `KILL` after a grace period, then
  `runsc delete --force`, then delete the network namespace.
- At daemon start, Kronik deletes every container that `runsc list` shows
  under its root and every leftover network namespace, then starts the
  foreign actors fresh.
- `runsc events --stats <id>` gives CPU, memory and pids for `/metrics`.

### 7. Installation

`install.sh` installs a pinned gVisor release tarball into `/usr/local/bin`
(`runsc` plus `gvisor-bin/`) after checking its SHA-512, or uses gVisor's
signed apt repository on Debian and Ubuntu. `scripts/install-runsc.sh` in the
spike does the former.

## Measurements

Testbench as above; all numbers in `spikes/spike-c-gvisor/results/`. Requests
are sequential `POST /echo` with a 64-byte body, 3 rounds of 1000 after 100
warmup requests; the table shows the median of the three rounds. The sandbox
runs at `--cpu 1 --memory 512Mi` (`04-bridges-cpu-on.txt`); without the CPU
quota the numbers are similar except for the tails
(`04-bridges-cpu-off.txt`).

| Bridge | Kept-alive p50 / p99 / p99.9 | New connection p50 / p99 |
| --- | --- | --- |
| Host process over TCP, no sandbox | 0.11 / 0.28 / 0.43 ms | 0.36 / 0.87 ms |
| Host process over a Unix socket, no sandbox | 0.05 / 0.15 / 0.20 ms | 0.22 / 0.77 ms |
| **`port-forward --stream` (chosen)** | **0.36 / 1.2 / 19 ms** | **13 / 26 ms** |
| `port-forward` local mode | 0.57 / 1.7 / 4.6 ms | 4.9 / 19 ms |
| `--host-uds=create` + shim | 0.57 / 3.0 / 24 ms | 6.5 / 51 ms |
| `--host-uds=create`, app listens on the socket | 0.18 / 0.81 / 16 ms | 2.8 / 37 ms |

- **CPU.** Over the same 6600 requests without the quota, the sandbox cgroup
  used 25 s of CPU with `--stream`, 18 s with local port-forward and 34 s with
  the shim (`04-bridges-cpu-off.txt`). Under the 1-CPU quota the shim run was
  throttled in 364 of 381 periods, the `--stream` run in 14 of 470
  (`04-bridges-cpu-on.txt`). With `--stream`, a kept-alive request costs
  about 0.6 ms of sandbox CPU and a new connection about 7 ms, plus the
  short-lived runsc helper on the host (`09-systrap.txt`).
- **Cold start** (10 starts, `05-coldstart.txt`): `runsc run --detach`
  including the namespace takes 104 ms (median); the first answered request
  through `--stream` comes 123 ms after the start (108–150 ms). Teardown with
  `runsc delete --force` takes 17 ms.
- **Idle cost** (`09-systrap.txt`, `11-overhead.txt`): 3 ms of CPU per 5 s;
  18 MiB `memory.current` in the cgroup; RSS 34 MiB for the sentry and 16 MiB
  for the gofer. Each `--stream` helper uses about 15 MiB while it lives.
  Disabling the systrap fast path made no measurable difference.
- **Egress** (`06-egress-pf.txt`): TCP to 1.1.1.1:443, 8.8.8.8:53,
  [2606:4700:4700::1111]:443 and to the host's own public, Docker and
  Tailscale addresses, UDP DNS to 8.8.8.8, 1.1.1.1 and 100.100.100.100, and
  busybox `nslookup` and `wget` all fail with `Network unreachable`; name
  resolution fails; inside there is only `lo`; the sandbox host processes sit
  in a namespace with only `lo`.
- **Limits** (`07-limits.txt`): two busy threads get 1.00 CPU with
  `cpu.max 100000 100000` and 1.97 CPU with the quota lifted. 300 MiB fits
  (`memory.peak` 323 MiB); touching 700 MiB gets `gvisor_sentry` killed by the
  cgroup OOM killer (`oom_kill 1`) and the sandbox stops. The app sees 2 CPUs
  (runsc's `--cpu-num-from-quota` rounds the quota up but never below 2) and
  `MemTotal` 524288 kB.
- **Bundles** (`02-bundle.txt`): a 1.7 MB gzip layer plus a 6.9 MB tar layer
  verify and unpack in 0.22 s; a layer blob with one appended byte is
  rejected. BuildKit layers with real whiteouts unpack correctly
  (`10-buildkit-check.txt`).

## Alternatives

- **`--host-uds=create` with a shim in the sandbox** (`--network=none`). It
  works and was measured in full. The sandbox needs `create` (with `none` or
  `open` the socket exists only inside the sandbox), and the shim needs root
  inside the sandbox to bind in Kronik's 0700 directory (`13-alternatives.txt`).
  With `create`, the sandbox still cannot connect to host sockets in its
  mounts (`06-egress-uds.txt`). Its advantages are `--network=none`, so no
  namespace to manage, and new connections without a process spawn (6.5 ms
  instead of 13 ms). Apps that can listen on a Unix socket themselves answer
  in 0.18 ms. It was not chosen because:
  - Kronik code would run inside every sandbox: a static shim per
    architecture, bind-mounted, started with `runsc exec` and supervised.
  - When the shim dies, its socket stays connectable but nobody answers, so
    clients hang until their timeout (10 s in `08-supervise.txt`), until
    Kronik removes the file and starts the shim again.
  - `runsc checkpoint` fails with `Cannot save endpoint with bound host
    socket`, and the failed checkpoint leaves the container stopped. That
    conflicts with M14, which checkpoints foreign actors. A sandbox that has
    served port-forward connections checkpoints fine (`13-alternatives.txt`).
  - It burns more CPU: 34 s instead of 25 s for the same requests, and heavy
    throttling under `--cpu 1` (`04-bridges-cpu-*.txt`).
  - It needs an extra sandbox permission, `--host-uds=create`.
- **`runsc port-forward` in local mode** (`runsc port-forward <id>
  <host-port>:<port>`). It listens on all host interfaces (`*:18080`), and
  there is no option to bind only to localhost, so the foreign actor would be
  reachable from the internet unless a firewall blocks the port. It is also
  one more long-lived process per actor. Rejected.
- **Passing a listening host socket into the sandbox** (`runsc exec
  --pass-fd`). `accept` on the passed socket fails with `EINVAL` inside gVisor
  (`13-alternatives.txt`). Rejected.
- **A veth pair between Kronik and the sandbox** (`--network=sandbox` with real
  addressing). It would need IP configuration and firewall rules to keep
  egress closed, which is more host state and more ways to get it wrong.
  Rejected for v0.1.
- **Calling runsc's control socket directly** (the `PortForward` RPC with file
  descriptor passing) instead of starting a helper per connection. It would
  remove the 13 ms spawn, but the protocol is internal to runsc. Kept as an
  optimization if connection setup ever matters.

## Consequences

- Kronik owns one network namespace per foreign actor: create it with `lo` up
  before `runsc run`, delete it after `runsc delete`, and clean up leftovers
  at start. In Rust this is `unshare(CLONE_NEWNET)` on a dedicated thread,
  bind-mounting that thread's `ns/net` to a file under `/run/kronik/netns/`, and
  setting `lo` up with netlink or `SIOCSIFFLAGS`. The crate choice, and any
  `unsafe`, needs its own decision in M7.
- New connections cost a process spawn (13 ms median), so the effect layer
  must pool connections. A broken connection mid-request is an uncertain
  effect outcome and follows the target's delivery class (I17).
- The M7 test "outgoing network from the sandbox is blocked" can reuse
  `netprobe`: run it in the sandbox and require that every attempt fails.
- Exceeding the memory limit kills the whole sandbox, not only the app.
  Kronik reports it as out of memory (from `memory.events`) and restarts with
  backoff.
- Apps see at least 2 CPUs even with `--cpu 1`, and `MemTotal` equals the
  memory limit. Thread pools sized from the CPU count get 2 threads.
- The spike's test image, a static echo server packed into a local OCI layout
  by `oci-tool pack`, is a starting point for `examples/foreign-echo`.
- The daemon and runsc run as root in v0.1, as the brief says. Rootless
  runsc (M21) must recheck the namespace setup and port-forward.
- **Known limitations to document** for foreign actors:
  - gVisor implements most, not all, of the Linux syscall ABI; some syscalls,
    ioctls and `/proc` and `/sys` files are missing or partial, and some
    programs fail because of it.
  - File I/O goes through the sentry and gofer and is slower than native; the
    brief expects this, and the spike did not measure it. The rootfs is an
    overlay (runsc's default `--overlay2=root:self`, with its filestore in the
    rootfs directory): writes there never reach the bundle and do not survive
    the sandbox. Only bind mounts such as `foreign/<name>/data` persist
    (`13-alternatives.txt`), and they cannot be replayed.
  - Thread creation and new connections are slow in the sandbox: a new
    connection costs about 7 ms of sandbox CPU on the testbench, so clients
    should keep connections alive.
  - Under a CPU quota, bursts of work are throttled per 100 ms period, which
    shows up as latency tails (p99.9 of 19 ms at `--cpu 1`).
  - Raw sockets are off, and there is no network at all except loopback.
- **`kronik doctor`** checks, all with `--json`:
  - `[foreign] runsc_path` exists and is executable, and `gvisor-bin/` with
    `gvisor_sentry` sits next to it. Otherwise `RUNSC_MISSING`, with a hint to
    `install.sh` and the gVisor install guide.
  - `runsc --version` parses as `release-YYYYMMDD.N`. Report the version, and
    warn when it is older than the version Kronik was tested with.
  - The kernel is 5.6 or newer, which gVisor requires.
  - `/dev/kvm` exists and can be opened. Report which platforms are
    available; `platform = "kvm"` without it is `KVM_UNAVAILABLE`.
  - cgroup v2 is mounted and the `cpu`, `memory` and `pids` controllers are
    available to Kronik's subtree.
  - The daemon runs as root (v0.1) and can create network namespaces.
  - A smoke test starts a minimal sandbox with the chosen flags, connects
    through `port-forward --stream` and deletes it. It takes about 0.15 s and
    catches seccomp, AppArmor and systrap problems on unusual hosts.
