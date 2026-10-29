# 0027. systemd unit hardening and runsc

- **Status:** Accepted (owner confirmed 2026-10-29). Amended 2026-10-28 for
  v0.1: `RestrictSUIDSGID` stayed while nothing ran `runsc restore`.
  Amended for v0.3: M14's sandbox copies run `runsc restore`, so the unit
  drops it (see "Without `RestrictSUIDSGID` (M14)").
- **Date:** 2026-10-27, amended 2026-10-28 (v0.1 and v0.3); v0.3's evidence
  under the installed unit 2026-10-29

## Context

`kronik serve --init` installs `deploy/systemd/kronik.service`. In v0.1 the
daemon runs as root, with the hardening that systemd allows (brief:
"Säkerhetsmodell", SPEC: "Security model"). Every foreign-actor test runs
the daemon outside systemd. When the unit was tested on travelfiesta it
failed in two ways.

1. **No sandbox starts.** Under the unit shipped with 927c80a, every
   foreign actor fails with "creating container: cannot create gofer
   process: gofer: fork/exec /proc/self/exe: operation not permitted".
   Turning off one setting at a time, only `NoNewPrivileges=no` cures it.
2. **`runsc restore` fails.** With `RestrictSUIDSGID=yes` it stops at
   "opening state file …/checkpoint.img failed: function not implemented".
   M14's sandbox copies (v0.3) need restore; v0.1 never called it.

Both were measured on travelfiesta (Debian 13.7, kernel
6.12.111+deb13-cloud-amd64, systemd 257.13-1~deb13u1, runsc
release-20261019.0, systrap, no KVM) on 2026-10-27.

**Root cause of 1.** No LSM is involved: AppArmor has no runsc profile, the
kernel log shows no denial, and runsc has no file capabilities.

- The daemon's capability sets differ with the unit's settings:

  | Unit settings | Daemon's `CapInh` / `CapPrm` |
  | --- | --- |
  | Shipped unit (`User=root`) | `0x200100` (`CAP_SETPCAP`, `CAP_SYS_ADMIN`) / `0x1f3fdfeff7f` (no `CAP_SETUID`) |
  | Without `User=` | `0` / `0x1f3fdfeffff` |

- A matrix of transient units with one `-p` setting each shows the
  condition: an explicit `User=`, plus at least one seccomp-based setting.
  - Seccomp-based settings that trigger it: `ProtectClock`,
    `ProtectKernelModules`, `ProtectKernelLogs`, `RestrictSUIDSGID`,
    `RestrictRealtime`, `LockPersonality`, `SystemCallArchitectures`.
  - These do not: `ProtectSystem`, `PrivateTmp`, `CapabilityBoundingSet`
    alone, `Group=` alone, and `User=root` alone.
- The code is systemd's `exec-invoke.c` (v257), `keep_seccomp_privileges`:
  - When a unit sets a user and has a seccomp filter, systemd keeps
    `CAP_SYS_ADMIN` and `CAP_SETPCAP` (through keep-caps) to install the
    filter after it switches user.
  - After the switch it drops `CAP_SETUID`, unless `CAP_SETUID` is in
    `AmbientCapabilities`.
  - For `User=root` that leaves a root daemon without `CAP_SETUID` in its
    permitted set.
- `NoNewPrivileges` then stops `runsc`, executed as root, from getting the
  capability back:
  - The kernel caps the new permitted set at the old one.
  - runsc's gofer start needs `CAP_SETUID`, so it fails with EPERM.
  - Without `NoNewPrivileges`, an exec as root gets the full bounding set
    again, which is why only that toggle helped.

**Root cause of 2.** `RestrictSUIDSGID` makes `openat2` fail with ENOSYS for
every caller, because seccomp cannot inspect the struct that carries
openat2's flags. This is systemd's `src/shared/seccomp-util.c`: "Let's block
it entirely … we return ENOSYS". runsc's restore opens the checkpoint image
with `openat2` and has no fallback. Every child of the unit inherits the
filter, so Kronik cannot work around it.

## Decision

- **No `User=` line.** Root is the default for a system unit. The unit
  keeps `Group=kronik` for the API socket. `NoNewPrivileges=true` stays.
  `kronik doctor`'s `caps` check reports a running `kronik.service` (or,
  without one, itself) without `CAP_SETUID`, with this ADR as the hint, so
  a drop-in that brings `User=` back is named instead of surfacing as the
  gofer's EPERM.
- **No `RestrictSUIDSGID` from v0.3 (M14).** Its one cost, `openat2`
  failing, hits `runsc restore`, which M14's sandbox copies run; `runsc run`
  and `runsc checkpoint` pass with it (Evidence). v0.1, which never
  restored a sandbox, kept it. Without it a sandbox's host side applies a
  setuid or setgid bit a guest sets: the residual risk below.
  - Image unpacking clears setuid and setgid bits (`mode & 0o1777`, the
    sticky bit kept; 2858e0b), so no setid file comes from an image, and
    images with such entries, such as postgres:17-alpine's
    `run/postgresql` (2777), start under any unit. The image builder
    (`tar_dir`) masks modes the same way, and so does `copy_tree`, which
    makes M14's checkpoints and copies of an actor's `/data`.
- **The runtimes' state directories are private.** Under the run lock and
  before any runtime call, the daemon makes `<run_dir>/runsc` and
  `<run_dir>/runc` mode 0700, also when a runtime made them (under the unit
  runsc made its root 0710, which the group can pass through; Evidence).
  A runtime's state file holds the container spec, resolved
  secret values in its environment included, and `/run/kronik` is mode 0750
  for the `kronik` group, which may use the API socket but must not read
  secret values.
- Every other setting stays as it was, with the same reasons for what is
  left out: `MemoryDenyWriteExecute`, `ProtectHostname`,
  `ProtectKernelTunables`, `ProtectControlGroups` and a
  `CapabilityBoundingSet`.
- A unit test (`init.rs`) fails if the unit gains a `User=` or
  `RestrictSUIDSGID=` line, or loses `NoNewPrivileges=true`.

## Without `RestrictSUIDSGID` (M14)

M14 needs `runsc restore` for its sandbox copies: with the setting, every
restore fails with ENOSYS from `openat2` (root cause 2; the transient-unit
toggle test under Evidence). The unit therefore leaves it out, and this is
the residual risk, which is wider than a compromised process:

- **Guest code, not only a compromise.** Without the setting, ordinary
  code in an untrusted image that runs as root in its sandbox can
  `chmod u+s` or `g+s` a file under `/data`, and the sandbox's host side
  applies it. That leaves root-owned setid files in
  `/var/lib/kronik/foreign/actors/<name>/data` (mode 0755, beneath 0700
  parents). A compromised daemon or runsc can do the same anywhere it
  writes.
- **Reachability.** Only the 0700 ancestors keep such files out of other
  users' reach. Copying the data tree with modes kept (`cp -a`, `tar -p`, a
  backup restored elsewhere) or loosening a parent's mode exposes them.
  `/run/kronik` is not root-only: it is mode 0750 for the `kronik` group.
- **What remains.** `NoNewPrivileges` means executing such a file inside
  the service gains nothing. Unpacking clears setid bits, and so does
  `copy_tree`, which makes every checkpoint and copy of `/data`: a setid
  file a guest made never reaches a checkpoint or a fork's copy. The
  actor's own `/data` keeps it; the operations guide tells operators not
  to copy that tree with modes kept.

## Evidence

- **On travelfiesta, 2026-10-27, 20:09 UTC, under the VPS lock.**
  - Setup:
    - The 927c80a release, installed by `install.sh` and
      `kronik serve --init`.
    - Then the installed unit replaced by this branch's
      `deploy/systemd/kronik.service` (only `@KRONIK@` substituted;
      `diff` against the file: identical), `daemon-reload`, restart.
  - With the new unit:
    - The daemon has `CapInh 0`, `CapPrm 0x1f3fdfeffff`, `NoNewPrivs 1`.
    - `kronik deploy counter.wasm`.
    - `kronik foreign add plain --image oci-layout:…/echo-plain.oci --port 8080`: running.
    - `kronik grant counter foreign:plain`.
    - `kronik send counter/c1 fetch-ok --text 'GET foreign://plain/healthz'`: reply `200 ok`.
    - `kronik foreign remove plain`: removed.
  - Control: a drop-in with only `User=root` puts the daemon back at
    `CapInh 0x200100`, `CapPrm 0x1f3fdfeff7f`. `foreign add plain2` ends in
    `backoff` with "gofer: fork/exec /proc/self/exe: operation not
    permitted".
  - Afterwards: unit, user group, data, configuration and binary removed;
    no runsc processes and no network namespaces left.
- **Restore, plain runsc as root** in transient units with the new unit's
  settings (`Group=kronik`, `UMask=0007`, `NoNewPrivileges`,
  `ProtectSystem=strict` with `ReadWritePaths` of the scratch directory,
  `ProtectHome`, `PrivateTmp`, `ProtectClock`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `RestrictRealtime`, `LockPersonality`,
  `SystemCallArchitectures=native`). The steps were `run --detach`, then
  `checkpoint --leave-running`, then `restore --detach` of a copy:
  - **New unit:** 0, 0, 0; both containers run.
  - **The same plus `RestrictSUIDSGID=yes`:** 0, 0, 128 with "function not
    implemented".
  - The same result came earlier as a non-root user in a user namespace
    (the M21 setting), toggling each setting alone: only
    `RestrictSUIDSGID` breaks restore.
- **The v0.1 amendment, on travelfiesta, 2026-10-28, 09:32 UTC, under the
  VPS lock.** Each binary was installed through `kronik serve --init` from
  `/opt` (no `install.sh`). Each run deployed counter.wasm, added
  foreign-echo as `echo`, granted it, sent `GET foreign://echo/healthz` from
  `counter/c1`, listed the modes, and removed everything again.
  - **Before** (main's unit, without `RestrictSUIDSGID`): `CapPrm
    000001f3fdfeffff`, `NoNewPrivs 1`, reply `200 ok`. `/run/kronik` was
    `750 root:kronik`, and runsc's root `/run/kronik/runsc` was
    `710 root:kronik`: the group could pass through it. The sandbox's
    `.state` file, 3 410 bytes with the spec, was `640 root:kronik`, and its
    name derives from the actor's name. So any member of `kronik` could read
    a foreign actor's resolved environment.
  - **After** (this change, `RestrictSUIDSGID=yes`): the same capabilities,
    the actor `running`, reply `200 ok`. `/run/kronik/runsc` was
    `700 root:kronik`. `kronik doctor`: `caps` passes for the unit's
    process, and `sandbox` passes.
  - Afterwards: no unit, configuration, data, group or runsc process left.
    `/run/kronik` holds only its `foreign.lock` again.
- **The v0.3 unit with M14's copies, on travelfiesta, 2026-10-29, 01:20:36
  to 01:20:41 UTC, under the VPS lock** (the batch's `M14/unit`). The
  94d20ac release, installed by `install.sh` and `kronik serve --init`; the
  installed unit is `deploy/systemd/kronik.service` with only `@KRONIK@`
  substituted (`cmp`: identical).
  - `systemctl show`: `User=` empty, `Group=kronik`,
    `NoNewPrivileges=yes`, `RestrictSUIDSGID=no`. The daemon has `CapInh 0`,
    `CapPrm 000001f3fdfeffff`, `NoNewPrivs 1`.
  - `kronik foreign add echo --fork-mode sandbox` with foreign-echo:
    `running`. `counter/c1` sent `GET foreign://echo/healthz`: `200 ok`.
  - `kronik snapshot create` at lsn 6 checkpointed echo: paused 86 ms, a
    runsc image of 242 453 bytes (its `/data` is empty); `foreign list`
    shows `sandbox (lsn 6)`.
  - Calls at lsn 10, the fork point, and at 13 and 16. A fork at lsn 10
    with counter-body-v2, replayed continuously: `forked` 2, `exact` 0. Its
    copy, `kronik-copy-fafc41352e586d2b`, ran under `/run/kronik/runsc` in
    its own network namespace, started by `runsc restore` from the
    checkpoint (journal: "started a fork copy of a foreign actor … lsn=6").
  - `kronik fork delete` removed the copy; `kronik foreign remove echo`
    left no container and no namespace.
  - Afterwards: unit, group, data, configuration, binary and image copy
    removed; no runsc process left.

To repeat the toggle test on a host with runsc (as root, under the lock;
`$B` is a bundle whose `config.json` has `"terminal": false`):

```sh
U="-p Group=nogroup -p NoNewPrivileges=yes -p ProtectSystem=strict -p ReadWritePaths=$B \
   -p ProtectHome=yes -p PrivateTmp=yes -p ProtectClock=yes -p ProtectKernelModules=yes \
   -p ProtectKernelLogs=yes -p RestrictRealtime=yes -p LockPersonality=yes \
   -p SystemCallArchitectures=native"
F="--root $B/runsc --platform=systrap --network=none --overlay2=root:memory"
for extra in "" "-p RestrictSUIDSGID=yes" "-p User=root"; do
  systemd-run --quiet --wait --pipe --collect $U $extra sh -c "
    grep -E '^Cap(Inh|Prm)' /proc/self/status
    runsc $F run --detach --bundle $B a; echo run=\$?
    runsc $F checkpoint --image-path $B/ck --leave-running a; echo checkpoint=\$?
    runsc $F restore --detach --image-path $B/ck --bundle $B b; echo restore=\$?
    for c in a b; do runsc $F kill \$c KILL; runsc $F delete --force \$c; done; rm -rf $B/ck"
done
```

Expected results (the snippet was run as written on travelfiesta on
2026-10-27, with `postgres:17-alpine` as the bundle's rootfs, and gave
exactly these):
- Without an extra setting, all three steps exit 0.
- With `RestrictSUIDSGID=yes`, restore exits 128.
- With `User=root`, `CapPrm` lacks bit 7 (`CAP_SETUID`) and `run` fails
  with the gofer EPERM.

## Alternatives

- **`NoNewPrivileges=no`.** It fixes problem 1, but then any setuid binary
  the daemon or a sandbox's host process executes can gain privileges. The
  root cause is systemd's capability drop, not runsc. Rejected.
- **`AmbientCapabilities=CAP_SETUID` with `User=root`.** It keeps
  `CAP_SETUID` through systemd's path. It works around a setting the unit
  does not need, and it reads as if the daemon wanted an extra capability.
  Rejected for leaving out `User=`.
- **Keep `RestrictSUIDSGID` and give up M14's sandbox copies under
  systemd.** That loses a v0.3 feature on the target platform. Rejected
  for v0.3; v0.1, which had no copies, kept the setting.
- **Ask gVisor to fall back to `openat` on ENOSYS.** Worth reporting
  upstream. It does not help the pinned release, and it would leave the
  unit depending on a future runsc.

## Consequences

- Foreign actors work under the installed unit, which they never did in a
  release.
- The batch should run the foreign suites under the installed unit, not
  only outside systemd. Both problems stayed hidden because no test did.
- M21 replaces this unit with a non-root one (`User=kronik`, a user
  namespace for the sandboxes). The `User=` trap does not apply there: a
  non-root daemon gets its capabilities inside its own user namespace, not
  from systemd. `RestrictSUIDSGID` stays out while `runsc restore` needs
  `openat2`.
- To revisit: a systemd that keeps `CAP_SETUID` for `User=root`, or a runsc
  whose restore falls back from `openat2`. Either would let a setting come
  back, after the toggle test above passes.
