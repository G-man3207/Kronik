# Spike C: runsc without KVM, and a bridge into the sandbox

Milestone M0, spike C: `runsc` runs an unpacked OCI bundle on a VPS without
KVM, and a bridge from the host into the sandbox works. The decision is
recorded in [ADR 0003](../../docs/adr/0003-gvisor-bridge.md). This README
explains how to reproduce the results in `results/`.

## What is here

| Path | What it is |
| --- | --- |
| `src/oci.rs` | OCI image layout handling, done the way Kronik will do it in M7: verifies index, manifest, config and layer digests (each layer blob before it is applied, its `diff_id` after), applies layers in order with whiteouts (`.wh.<name>`) and opaque directories (`.wh..wh..opq`), resolves every path inside the rootfs (absolute symlinks are re-rooted, `..` entries are rejected), skips device nodes, and generates `config.json` from the image config plus overrides. Also packs the test image. Unit tests cover the tricky cases. |
| `src/http.rs` | Minimal HTTP/1.1 codec shared by the binaries. |
| `src/bin/echo-server.rs` | The foreign actor: a std-only HTTP server with `/healthz`, `/echo`, `/info`, `/exit`, `/burn` and `/alloc`. |
| `src/bin/uds-shim.rs` | Unix socket to TCP forwarder for the `--host-uds` bridge. |
| `src/bin/netprobe.rs` | Tries to reach the outside from inside the sandbox. |
| `src/bin/bridge-bench.rs` | Latency benchmark and readiness probe over TCP, a Unix socket or `runsc port-forward --stream`. |
| `src/bin/oci-tool.rs` | `pack` (build the test layout) and `bundle` (layout to runsc bundle). |
| `scripts/` | Build, deploy and experiment scripts; see below. |
| `results/` | Output of the experiments on the test host, committed as evidence. |

All binaries are built as static musl executables (`rust-toolchain.toml`
adds the `x86_64-unknown-linux-musl` target), so they run in a scratch image
and on any x86_64 Linux host.

## The test image

`scripts/build.sh` packs `foreign-echo:spike` into `out/foreign-echo-layout`
with `oci-tool pack`:

- layer 1 (gzip): `/bin/echo-server`, `/etc/passwd`, `/etc/group`,
  `/etc/stale.conf`, `/srv/old/a.txt`, `/srv/old/sub/b.txt`, `/tmp` (1777);
- layer 2 (uncompressed tar): `/bin/netprobe`, a static `/bin/busybox` from
  Debian's `busybox-static` package, a whiteout for `/etc/stale.conf`, and an
  opaque marker plus `c.txt` in `/srv/old`;
- config: `Entrypoint ["/bin/echo-server"]`, `Cmd ["--listen","0.0.0.0:8080"]`,
  `Env`, `WorkingDir /srv`, `User nobody` (resolved through the image's own
  `/etc/passwd` to 65534:65534).

skopeo 1.18.0 accepts the layout (`skopeo inspect` and `skopeo copy`, which
verifies the digests). `scripts/10-buildkit-check.sh` also unpacks a
multi-layer image built by BuildKit, whose layers contain real per-file
whiteouts; see `results/10-buildkit-check.txt`.

## Reproduce

On the development machine (Debian or Ubuntu with rustup, apt and ssh):

```sh
cargo test --release            # unpacker tests; run as root (they chown to 0:0)
scripts/build.sh                # binaries and the OCI layout under out/
scripts/deploy.sh travelfiesta  # copies bin/, the layout and scripts/
```

On the test host, as root (the experiments use `/var/lib/kronik-spike-c`,
`/run/kronik-spike-c` and port 18080):

```sh
/root/kronik-spike-c/scripts/install-runsc.sh 20261019.0
/root/kronik-spike-c/scripts/run-all.sh       # about 6 minutes
```

Back on the development machine:

```sh
scripts/fetch-results.sh travelfiesta  # also replaces the host's public and Tailscale addresses
scripts/10-buildkit-check.sh           # optional; needs docker buildx
```

| Script | Result file | What it shows |
| --- | --- | --- |
| `install-runsc.sh` | | Installs a pinned gVisor release tarball after checking its SHA-512. |
| `01-survey.sh` | `01-survey.txt` | Host: OS, kernel, CPU, memory, disk, `/dev/kvm`, cgroups, gVisor. |
| `02-bundle.sh` | `02-bundle.txt` | Layout to bundle, rootfs checks, `config.json`, a tampered layer is rejected. |
| `03-start.sh` | `03-start.txt` | `--platform=kvm` fails without `/dev/kvm`; systrap starts with `--network=none` and with the chosen configuration. |
| `04-bridges.sh` | `04-bridges-cpu-on.txt`, `04-bridges-cpu-off.txt` | Latency of every bridge and a host baseline, with and without the CPU quota. |
| `05-coldstart.sh` | `05-coldstart.txt` | From `runsc run` to the first HTTP 200, per bridge. |
| `06-egress.sh` | `06-egress-pf.txt`, `06-egress-uds.txt` | Egress is blocked; which interfaces exist inside. |
| `07-limits.sh` | `07-limits.txt` | `--cpu 1 --memory 512Mi` take effect. |
| `08-supervise.sh` | `08-supervise.txt` | Exit detection, a dead shim, teardown. |
| `09-systrap.sh` | `09-systrap.txt` | Idle CPU and the systrap fast path. |
| `11-overhead.sh` | `11-overhead.txt` | Host memory per sandbox; lifetime of the port-forward helper. |
| `12-wait-race.sh` | `12-wait-race.txt` | Foreground `runsc run` versus detached `runsc wait`, 10 runs each. |
| `13-alternatives.sh` | `13-alternatives.txt` | What port-forward needs, the `--host-uds` modes, `--pass-fd`, checkpointing with each bridge, where writes inside the sandbox go. |

## Results in short

Test host: Debian 13, kernel 6.12.111, 2 vCPU (Skylake under KVM, no
`vmx`/`svm`, no `/dev/kvm`), 3.7 GiB RAM, cgroup v2; gVisor release-20261019.0.

- **Start without KVM.** `--platform=kvm` fails with `error opening /dev/kvm:
  no such file or directory`; `--platform=systrap` starts the sandbox in about
  100 ms (`runsc run --detach`), and the first request through the bridge is
  answered about 0.12–0.14 s after `runsc run` starts.
- **Bridges** (median of 3 × 1000 sequential requests, sandbox at `--cpu 1`):

  | Bridge | Kept-alive p50 / p99 | New connection p50 / p99 |
  | --- | --- | --- |
  | Host process, TCP (baseline) | 0.11 / 0.28 ms | 0.36 / 0.87 ms |
  | `runsc port-forward --stream` (chosen) | 0.36 / 1.2 ms | 13 / 26 ms |
  | `runsc port-forward` local mode | 0.57 / 1.7 ms | 4.9 / 19 ms |
  | `--host-uds=create` + shim | 0.57 / 3.0 ms | 6.5 / 51 ms |
  | `--host-uds=create`, app listens on the socket | 0.18 / 0.8 ms | 2.8 / 37 ms |

- **Egress is blocked** in both configurations: TCP and UDP to external
  addresses, DNS servers and the host's own addresses all fail with
  `Network unreachable`; the sandbox has only `lo`.
- **Limits work:** two busy threads get 1.00 CPU under `cpu.max 100000
  100000` and 1.97 CPU without it; 300 MiB fits under `memory.max` 512 MiB,
  700 MiB gets the sandbox killed by the cgroup OOM killer.
- **Supervision:** `runsc run` without `--detach` returns the container's exit
  status every time (30 of 30); `runsc wait` on a detached sandbox loses the
  status when the sandbox goes down (1 of 10 after `runsc kill`, 0 of 10 after
  `kill -9` on the host).
