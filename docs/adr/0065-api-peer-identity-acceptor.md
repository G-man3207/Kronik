# 0065. Initial-namespace Unix API attribution

- **Status:** Accepted (2026-11-13). Implemented; the boundary driver has not been run on this revision.
- **Date:** 2026-11-07

## Context

`SO_PEERCRED` translates a caller's UID into the reader's user namespace. After entering the mapped daemon namespace, host root and unmapped operators would collapse to overflow UID 65534, while the service owner appears as UID 0. Persisting those values would produce incorrect security attribution.

## Decision

Before entering the user namespace or loading secrets, the single-threaded nonroot daemon forks one acceptor in the initial user namespace. The child clears ambient/inheritable/permitted/effective capabilities, enables no-new-privileges, becomes nondumpable, closes unrelated descriptors, and acknowledges completed setup before startup may create threads. It remains the same stable nonroot host UID, never a root or capability-bearing accept thread.

Before forking, acceptance requires the complete identity UID-map view (`0 0 4294967295`). A limited outer user namespace is refused rather than labeling its translated/enclosing UIDs as physical-host operator identities: `kronik serve --rootless` stops with `ROOTLESS_UNAVAILABLE`, before it creates or binds anything, and says that rootless containers and nested user namespaces are not supported for the nonroot unit; a root service is the alternative. `kronik doctor --rootless` reports the same condition as `uid_view` before the service is started. The same refusal covers real, effective and saved user ids that differ, and root. The safe numeric-service fixture therefore keeps the acceptor in the host UID view and isolates its identity/config/runtime files with private mounts; it does not claim an outer user namespace proves host UID attribution.

For each connection the acceptor reads `SO_PEERCRED` in that initial namespace and transfers the connected FD and host UID together over a private close-on-exec sequenced-packet channel. The daemon does not recompute credentials after namespace entry. The existing API server handles the transferred connection through its ordinary request, MCP, bearer-token and audit paths; token attribution still overrides the Unix peer identity when a valid bearer token is presented. TCP token authentication is unchanged.

Forwarding is bounded to 64 pending connections. Channel EOF/protocol failure stops the API serving future and therefore fails the daemon's listener select, rather than leaving a healthy-looking daemon with a dead local API. Parent death terminates the acceptor; controlled drop kills/reaps only the owned child. No process-name kill or reconnect/retry path is introduced.

## Consequences and proof

The acceptor is a small initial-namespace trust boundary, not a second API/authentication stack. Its setup uses syscall-only post-fork code before protected keys exist. The data-directory lock remains in the daemon and unrelated child descriptors are closed.

The standalone boundary regression exchanges real Unix connections from host UID 0, a distinct allocated operator and the service user, checks acceptor host UID/capabilities/namespace from outside, and asserts bounded failure after terminating the owned acceptor. Full integration additionally checks those identities and bearer-token override in durable operations/audit state after daemon restart. No execution result is claimed for these new tests.
