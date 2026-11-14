# 0060. Stable-user namespace setup and irreversible startup boundary

- **Status:** Accepted (2026-11-13). Implemented; the proofs that need root, systemd 255 or newer and free numeric ids have not been run on this revision (see Consequences and proof).
- **Date:** 2026-11-07
- **Relates to:** ADR 0003 (gVisor bridge), ADR 0027 (unit hardening) and the data-directory descriptor lock of the key-source boundary (ADR 0092).

## Context

The build brief's M21 says "`runsc` runs in rootless mode where the kernel allows it". This ADR and ADR 0061 do not do that: `runsc` runs as root **inside** a user namespace that the service user owns, because the measurements behind ADR 0061 show that `runsc --rootless` cannot run the sandbox network, `create` or `restore` that Kronik needs. That is a deviation from the brief's wording, which the maintainer ratified on 2026-11-13; the rest of M21 follows the brief.

The long-running daemon must not have root authority in the host user namespace. Foreign runtimes still need namespace-local ownership, mounts and capabilities. An unprivileged namespace creator alone is insufficient on hosts whose user-namespace policy restricts creation.

## Decision

A short-lived root setup command pins a namespace owned by the stable `kronik` user. UID/GID 0 map to that user's nonzero host UID/GID; 1–65535 map to the allocated subordinate ranges, starting at or above 100000. Host UID/GID 0, invalid sentinel IDs, overlapping service identities/allocations, low/short ranges and overflowing ranges are refused. Production identity and pin locations are fixed; root-owned nonsymlink, non-writable-by-others identity files are required before privileged setup or data handover. `userns` has no unused configuration/path override.

The pin parent and ancestors are validated before privileged mutation. A matching pin is kept only when its root-owned creation record also matches, with namespace identity unchanged. A mismatch or preexisting file is not replaced or adopted. Creation records the namespace's owner/device/inode in a root-only sidecar. Explicit unpin and its dry-run validate that record and the unchanged namespace identity; they never detach a replacement or an unrelated preexisting file. Fixture cleanup additionally acts only on `Pin::Created`, never `Pin::Kept`. Ordinary helper-unit stop/restart leaves the pin intact. Changing identity requires stopped, serialized setup.

Startup holds the data directory's existing file-descriptor lock **before** replacing an API socket or forking a helper. That same lock (the `DataOwnership` that `lock_data` returned, one open descriptor) is handed to `start_local_locked`; it is not unlocked or reopened, and the held and named inodes are compared again. No new lock file or second key loader is introduced.

This is `kronik serve --rootless`, the mode the nonroot unit starts; plain `kronik serve`, as root or as an ordinary user, is unchanged and does none of it, so development and CI runs are not affected. Before loading secrets or starting logger/runtime threads, `--rootless` startup binds all TCP/Unix listeners, clears ambient/inheritable/permitted/effective host capabilities and sets no-new-privileges. Clearing is mandatory even when the pin/delegation is absent and only Wasm remains available. The API acceptor stays in the initial user namespace as the nonroot service user with no possessed capabilities. The daemon validates namespace type, owner and exact maps using **one open namespace FD**, then enters that same FD and installs a private mount namespace with recursively slave propagation. Successful entry grants only namespace-local authority. An initial-namespace capability bounding ceiling is not possessed authority and is not advertised as zero.

`--rootless` fails closed: it refuses to start, with `ROOTLESS_UNAVAILABLE` and a message that says what to change, as root, with differing real, effective and saved user ids, and in a user namespace whose uid map is not the host's identity map (ADR 0065). Rootless containers and nested user namespaces are not supported for the nonroot unit. The explicit root installation is a separate operator-selected fallback, not automatic degradation. Missing rootless foreign prerequisites yield typed unavailability, not a trusted-runtime fallback or removed resource limits.

## Trusted executable fixtures

`sys::bootstrap_owned_rootless_fixture(etc, run)` accepts only root-owned non-writable-by-others directories in a one-thread setup process. It makes mount propagation private before binding those directories at the fixed `/etc` and `/run` locations. It does not edit host accounts/subid files or expose a daemon environment bypass. It does **not** isolate PID 1: installed-init proofs additionally need their own service manager or exact owned transient-unit control seam. Numeric identities, pin ownership and delegated subtrees are allocated by the integration fixture, not inferred from an existing customer installation.

## Consequences and proof

The root setup command is trusted, bounded setup authority, not a privileged daemon/helper service. Pin restart must not strand a live daemon in a new namespace. Offline root handover validates the stable destination owner before dropping privilege; loaded keys and the data lock remain held across that transition.

Behavioral regressions cover strict map parsing, symlink/FD identity, owned unpin refusal, startup capabilities on successful and degraded paths, and real peer UIDs. The explicit `rootless_boundary` driver requires allocated numeric identities and real namespace authority; it fails on missing prerequisites and retains diagnostics.

Nothing in this ADR has been run on this revision: the unit tests run anywhere, but the `rootless_boundary` driver, the installed fixture and the program proof need root, systemd 255 or newer and free numeric ids, and have not been run. The design is untested on Ubuntu 24.04: it checks `user.max_user_namespaces` and `kernel.unprivileged_userns_clone` only and does not handle Ubuntu's AppArmor restriction on unprivileged user namespaces. It has had no independent security review.
