# 0064. Required real foreign-isolation conformance

- **Status:** Proposed. The scripts and drivers exist; none of them has been run on this revision. Awaits maintainer ratification.
- **Date:** 2026-11-07

## Decision

M21 acceptance is the actual v0.1 programs running without host root, plus a deliberately malicious UID0 image that cannot reach host files, network, processes or neighbouring sandboxes. The probe uses real system calls and positive own-resource controls. It does not turn unexpected errno into “absent,” infer nonroot mode from a root target, delete failed diagnostics, or call source-text/wiring assertions a security result. Guest namespace inode numbers cannot be compared across separate kernels as evidence of isolation.

The static `foreign-probe` is packed with OCI User0, not merely an unprivileged image user. It tests owned filesystem markers, IPv4/IPv6 TCP/UDP/DNS, Unix/abstract sockets, processes, SysV IPC and device boundaries. Initial host controls establish reachable listeners/resources and drain control traffic before actor attempts; host observations must then show no actor receipts or outside writes. Writes use exclusive unpredictable filenames and cleanup checks the identity of only resources actually created. Mount probes run in disposable child mount namespaces, never by remounting the live daemon's namespace. For microVMs, the guest's own root/data devices are not falsely labelled host escapes; their read-only/finite-drive semantics have explicit controls.

## Owned installed fixture

`isolation_fixture` and `rootless_boundary` are non-shipped, explicit proof binaries. They use the narrow trusted internal setup seam, private passwd/group/subid/config views and actual shadow-tool locking. They never add real host accounts or sub-ID allocations. Runtime units have exact unpredictable allocated names, numeric service identities, bounded delegated cgroups and owned roots. Cleanup targets only those names/resources, retains the private evidence tree, and must not unpin somebody else's namespace. Existing applications, units, global clock, firewall, network or AppArmor policy are not changed.

The installed fixture's host manager controls only its exact allocated `kronik-proof-TOKEN-manager.service` transient containment parent. The real product and pin units are read from an owned-only unit search path by a separate systemd **system** manager running as PID1 in child PID/mount/cgroup/UTS/IPC namespaces. Its `/run`, identity files, temporary filesystems, machine ID and generator directories are private. Generators are disabled and its initial target has no application dependencies. The host filesystem is a read-only mount view except owned proof storage and the delegated cgroup. The parent has minimal private devices and excludes time, reboot, module, raw-I/O, mknod, MAC/audit-control and host network-administration capabilities; only explicit microVM mode binds the approved KVM device. Namespace identities, the actual read-only root mount and capability bound are asserted before systemd starts.

Every fixture reload/enable/start/stop/show targets that private manager; no host `daemon-reload` or host manager socket bind is used. The parent is created by `systemd-run`, not by writing or reloading host unit files. Its supervisor moves into an owned cgroup leaf before private PID1 enables controllers, avoiding cgroupv2's no-internal-process constraint. Cleanup validates the parent's invocation ID/PID/start time before stopping only that parent, including after private cleanup failure. Production installer manager operations are unchanged.

The parent never hides an owned `/tmp` proof root behind a premature scratch mount. Its trusted launcher uses `TMPDIR` inside that writable owned root while the host view remains read-only; private PID1 retains the root descriptor before creating/rebinding its own temporary filesystems. An already-collected owned parent is an idempotent cleanup no-op only when the exact name is not found, inactive, with empty invocation/cgroup and PID0. A live or replaced parent still requires its recorded invocation/PID/start time.

Only after bootstrap has recursively made the child's mount tree private does
the child's own `/run` bind become shared. This lets its systemd credential
helper publish the actual `LoadCredential` mount into that private manager view;
host `/run` propagation is unchanged. The normal sole source load remains after
the existing startup transition in the final runtime. No temporary runtime,
preloaded source argument, retained-Env rewrite or second loader is needed.

The private manager consumes the actual generated product units, including their UID/capability, credential, hardening and delegation directives; transient-parent properties are containment, not a substitute product unit. A root `--user` manager is unsuitable here: systemd257's [implicit private-user setup](https://github.com/systemd/systemd/blob/v257/src/core/exec-invoke.c) for filesystem sandboxing would prevent entering the separately owned pin. A child PID1 system manager preserves production namespace semantics. Host audits translate private-manager PIDs/cgroup paths and require matching PID namespace, NSpid, start time and owned parent membership before inspection or signalling. They access the pin through the validated manager's mount view, never mistake the host's ordinary backing file for the namespace mount.

The private `/usr/local/bin` view retains the actual installed runsc closure:
an optional installed `gvisor-bin` sidecar directory is opened without following
symlinks, bound through its retained directory FD and remounted read-only.
It is not replaced by a copied or monolithic-runtime fallback.

The helper is reopened through its validated installation path in this mount
view, then FD-bound read-only at `/usr/local/bin/kronik-isolation-fixture`
before private scratch mounts. Generated pin units and in-manager unpin use this fixed
private view, not an original installation path later hidden beneath `/var/tmp`.
The outer host driver retains the original installed path for identity and
control. No real host binary or global mount is changed to make an installed
package fixture work.

Only the explicitly selected ROOT fixture unit enters a child user namespace
with identity UID/GID maps0..65535 and a child private mount namespace before the
real product starts. Its network-administration capability is namespace-local;
the containment parent still excludes host `CAP_NET_ADMIN`. The oracle preopens
the initial host network namespace and requires real `setns` refusal with EPERM
after entering that child user namespace. No host network policy is changed.

The namespace diagnostic still requires nine real positive reads. The exact
gVisor `/proc/self/ns/cgroup` ENOENT is retained as a diagnostic, not a denied
boundary: [the installed release's immutable source](https://github.com/google/gvisor/blob/760b80785dc53311d4c87bd2de167525a99709c1/pkg/sentry/fsimpl/proc/task.go#L63-L73)
creates that link only after its virtual cgroup2 filesystem was ever mounted.
All actual host-cgroup access denials and delegated resource-limit controls
remain mandatory; this calibration does not apply to microVMs or other errno.


The rootless-boundary driver checks actual namespace entry/replacement refusal, true initial-namespace caller UIDs, capability loss before threads including degradation, acceptor death and privileged-port denial with positive controls. Wrong-user/root execution is a failure of the required nonroot oracle.

The program proof runs the actual verify-change and billing demos against fresh owned external-daemon generations, without overwriting existing kinds or stopping/removing an arbitrary external daemon. It checks Postgres data ownership under the nonroot service, real checkpoint-backed fork divergence with `forked` grounding, shipping/restore with the already loaded protected key, destination ownership, durable UID audit and owned cleanup. File-backed and loaded-provider semantics remain the B1 implementation; there is no second key-loading stack.

Each demo generation resets only after stopping its exact owned unit. Its data
and complete object-store directory are retained together using NOREPLACE;
the replacement ship root is new0700/service-owned. Reusing old high-LSN remote
segments with a fresh low-LSN data directory would test an invalid mixed history,
not restore correctness. The real two-generation consumer proof preserves every
old object's bytes/inode and restores the fresh lower snapshot. No runtime
contiguity check is weakened, remote object pruned or failed tree removed.
Ownership checks lstat ordinary image symlinks as leaves; only the existing
structural linked actor roots are explicitly resolved as participating roots.

Installed consumption is observed through the running process's resolved credential argument, byte-identical root-only selected source and systemd credential, loaded-key API, numeric host identities/capabilities, actual cgroup namespace and usable delegated controllers. Systemd 255 must retain its private manager's cgroup namespace; systemd 257 or newer must consume the unit's additional private cgroup protection. Init invokes `doctor --rootless` for the stable service identity rather than treating a root doctor's smoke as nonroot proof. During shipping the original source is unavailable, and calibrated inotify watches on both the source inode and consumed credential must observe zero plaintext key opens or reads while snapshot/keystore publication succeeds. This is runtime evidence, not a generated-unit wording assertion.


## Required runner contract

Build the product, the explicit helper targets and probe/PG/payments OCI layouts beforehand. Select free numeric UID/GID/operator IDs and subordinate ranges; the helper validates them rather than mutating host identity databases. Then run:

```sh
timeout --signal=TERM --kill-after=10s 1800s bash scripts/proof-rootless.sh \
  HELPER PRODUCT PROBE_LAYOUT PG_LAYOUT PAYMENTS_LAYOUT OUTPUT_PARENT \
  UID GID SUBID OPERATOR_UID
```

Appending `--microvm TOOLS_DIR` selects the required real-KVM boundary and Postgres full-snapshot/fork proof. It records the actual Firecracker machine configuration, VMM process/cgroup limits and memory peaks, checks resource rounding, and exhausts the fixed guest data drive to actual ENOSPC without losing the existing marker. Cold-booting copied data is not a snapshot oracle: the Postgres postmaster start time must survive restore, in addition to independent fork SQL writes.

Before any VM actor boot, that same service's owned user/mount namespace runs the produced `mke2fs -d DIRECTORY`, `debugfs` and `e2fsck` tools. The mandatory oracle checks logical UID12345/GID23456 against real mapped host owners, file capability and binary user-xattr bytes, hardlink inode identity, file content/mode, source-root mode/owner/xattr/mtime, future mtimes beyond2038, byte-identical images despite different host construction times, and the explicit data-root owner override. It never mounts an ext4 image, changes host IDs/policy, or substitutes tar/libarchive population. Tool hashes and inode observations are retained.


The owned containment parent is bounded to 2 CPUs, 2 GiB, 1,024 tasks and 1,800 seconds; the generated product unit retains its own limits. Every required prerequisite/error/FAIL is nonzero. Missing KVM does not become a skipped or negative-only successful microVM job.

`scripts/proof-rootless.sh` is written for an Ubuntu 24.04 host with systemd 255 and the kernel's AppArmor restriction on unprivileged user namespaces active, because that is the brief's install target. Kronik does not handle that restriction and has not been tested there, so the wrapper is a test of whether it works, not a claim that it does. It is not wired into CI: adding a CI step for it (and for the microVM job) is a separate decision.

On another host, use the same prebuilt artifacts and allocated IDs but invoke the non-shipped helper and conformance entry point explicitly. The result then says nothing about Ubuntu 24.04:

```sh
timeout --signal=TERM --kill-after=120s 1800s \
  bash -s -- "$HELPER" "$OUTPUT_PARENT" "$PRODUCT" "$PROBE_LAYOUT" \
  "$PG_LAYOUT" "$PAYMENTS_LAYOUT" "$UID_NUMBER" "$GID_NUMBER" \
  "$SUBID" "$OPERATOR_UID" <<'SH'
set -euo pipefail
umask 077
helper=$1
proof=$("$helper" create "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}")
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  "$helper" cleanup "$proof" >>"$proof/cleanup.log" 2>&1 || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=20s 180s \
  "$helper" init "$proof" rootless >"$proof/initial-init.log" 2>&1
bash scripts/conformance-rootless.sh --fixture "$proof" \
  --isolation gvisor --program-proof
SH
```

The standalone mapped DIRECTORY oracle does not require or probe KVM and starts no foreign actors. Add `--directory-tools "$TOOLS_DIR"` to the helper's `create` arguments above, initialize the basic rootless service, then run:

```sh
timeout --signal=TERM --kill-after=10s 300s \
  python3 scripts/isolation-conformance.py directory --fixture "$proof"
```

This uses a separate fixed read-only tool bind, containing only manifest/provenance/mke2fs/debugfs/e2fsck. It can run before the gVisor full-program proof on that fixture, under the same cleanup trap. Actual VM acceptance remains the separate KVM run.

For the separate KVM/mapped-directory oracle, create a fresh fixture with the final positional `"$TOOLS_DIR"` argument, then use `--isolation microvm --microvm-proof` instead. The tool directory must already contain the pinned manifest/provenance, Firecracker, kernel, static guest init, patched directory-populating mke2fs1.47.2, debugfs and e2fsck; no missing-tool skip is allowed. Root setup authority, active systemd255+, cgroupv2 delegation, mount/user namespaces, shadow tools, runsc, Python3, nsenter/unshare/setpriv, setcap/getcap, adequate owned disk space and all prebuilt example/test Wasm components are prerequisites. The Ubuntu wrapper adds mandatory Ubuntu kernel and AppArmor-policy checks that this invocation does not make.


## Evidence boundary

Parser/socket/filesystem regressions and static review support implementation but cannot close these runtime criteria. The installed program proof (real malicious-actor controls, the demos, Postgres checkpoint and fork, the UID audit, source-unavailable loaded-key ship/restore), the pinned tool build and the KVM boot, call, resource calibration, ENOSPC, full snapshot, fork and stop checks have not been run on this revision. They remain unexercised criteria, never optional skips. No independent security audit, Ubuntu 24.04 result or cross-version snapshot compatibility is claimed.
