# 0062. Stable-user systemd units and source-aware credentials

- **Status:** Proposed. Implemented, not yet run on this revision; awaits maintainer ratification.
- **Date:** 2026-11-07
- **Amends:** ADR 0027 for the default stable-user installation, if accepted; the explicit root fallback keeps its separate template and ADR 0027's constraints.

## Decision

The default daemon unit runs `kronik serve --rootless` (ADR 0060) and uses `User=kronik`, `Group=kronik`, `Delegate=yes`, no-new-privileges, strict filesystem protection, private tmp/devices/IPC, kernel/clock protections and the existing compatible seccomp denylist. Only `CAP_NET_BIND_SERVICE` is available for early listener binding. Startup explicitly clears every possessed host capability before logger/runtime threads, including Wasm-only degradation; entering the owned namespace subsequently grants only namespace-local authority.

`Wants=kronik-userns.service`, **not Requires**, orders the root setup unit without making Wasm availability depend on namespace creation. The setup unit exits after pinning. It does not unpin on ordinary stop/restart: matching pins must survive a live daemon/helper restart. Explicit unpin is ownership-token checked and reserved for stopped setup.

`ProtectControlGroups=private` is rendered only for systemd 257 or newer. The same source supports 255 using its discovered delegated cgroup path, without silently dropping actor limits. Data access uses explicit `ReadWritePaths`; recursive `StateDirectory` ownership repair is not used over mapped foreign data. Existing audit `LogsDirectory` support remains in both templates.

Do not add MemoryDenyWriteExecute, RestrictSUIDSGID, proc restrictions, private gateway networking, or an incompatible syscall allowlist merely to make the unit look stricter: Wasmtime, runsc, checkpoint restore and recorded network effects must still work. A required KVM device exception is explicit and installation removes its owned drop-in when disabled.

## Credential rendering interface

Templates use `@KRONIK@`, `@CONFIG@`, `@KEY_CREDENTIAL@` and `@KEY_ARGUMENT@`. Init renders the last two only for the selected **file** custody source:

- `LoadCredential=master-key:<selected source file>`;
- an ExecStart suffix ` --master-key-file %d/master-key`.

In the nonroot installation the key file stays outside the data directory, which the service user owns: systemd hands the file to the service as a credential, and a path inside a directory the service user controls is one it could redirect. `serve --init --rootless` refuses a file key under the data directory and says to keep it elsewhere (`/etc/kronik/master.key`, root-only, is the default) or to use `--root`.

The installer treats the data directory the same way. Everything it writes there (the `keys` directory and the KMS envelope of a first run) it writes while the directory is still root's and private (mode 0700), then hands the tree over to the service user by descriptor, files first and the data directory itself last, without following a link and only if it holds nothing but directories and regular files with one link. Once the directory belongs to the service user, a rerun reads nothing in it but the KMS envelope, through a descriptor with no symbolic link followed, and changes nothing in it: a process with the service user's uid can swap anything in that tree for a link, a FIFO or a socket. The databases are not opened by the installer; the service checks them when it starts. A directory left by a first run that stopped early (nothing but `keys`) is adopted.

Environment/KMS sources get neither file credential directive nor file flag. Native `CREDENTIALS_DIRECTORY` provider paths and DynamicUser behavior are not replaced by a second provider stack or a TOML precedence override. Missing required source credentials fail closed. The daemon/shipper use the already loaded protected source; offline restore loads privileged source material before dropping authority, then writes as the validated destination owner under the same data lock.

## Doctor and proof

Doctor runs the nonroot checks (`userns`, `uid_view`, `subid`, `pin`, `delegate`) only with `--rootless`; without it `doctor` reports what it did before M21. Root `--rootless` changes to the actual stable service identity before namespace and sandbox smoke. If that identity cannot be established, it reports the limitation and cannot count a root-run smoke as success. The CAP_SETUID check keeps the detection of ADR 0027's trap, a root unit (or the doctor process) that lost `CAP_SETUID`, which is a failure. A nonroot unit is not examined: it holds no host capability by design, so the check looks at the doctor process instead, and with `--rootless` an ordinary-user doctor process checks its namespace-local authority and only warns. Being the service UID outside a delegated unit is not proof of effective installed-unit delegation/hardening.

Tests assert the check sets with and without `--rootless`, what the CAP_SETUID check examines, and explicit rootless identity behavior. The installed fixture is designed to check the service identity and capabilities, the selected `LoadCredential` bytes and argument, read-only controls, usable delegated controllers, real writes and malicious-actor boundaries, and loaded-key shipping with the original source unavailable followed by an authenticated destination-owned restore. None of that has been run on this revision. The unit is untested on Ubuntu 24.04 (systemd 255) and does not handle its AppArmor restriction on unprivileged user namespaces.

An existing root installation is not converted in place (ADR 0063): `kronik serve --init` refuses it and names the two ways forward, keeping it with `--init --root`, or re-initializing and restoring the data with `kronik restore`.
