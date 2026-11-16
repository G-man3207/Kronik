# 0150. The root unit renders the configuration path `--init` was given

- **Status:** Accepted (2026-11-16)
- **Date:** 2026-11-16
- **Amends:** ADR 0062's rendering interface for the root service

## Context

`kronik serve --init --root --config PATH` writes the configuration to `PATH`,
and its readiness check reads back the file at that same path. The root
systemd template, however, had `/etc/kronik/kronik.toml` hard-coded in
`ExecStart` and `ExecStopPost`. With any other `PATH` the install therefore
wrote a configuration the service never read, and the readiness check then
polled the `api_socket` of a daemon that had either failed to start or was
running from another installation's file. The flag was accepted and planned,
but could not produce a healthy install.

The default path is covered by the v0.4.1 compatibility promise: running
`serve --init` again on a host that v0.4.1 set up must leave its unit byte for
byte unchanged. A fix must not trade that promise for the custom path.

## Decision

The root template names the configuration path with `@CONFIG@` in both
`ExecStart` and `ExecStopPost`, as the nonroot template already does. Init
renders the path it was given into both commands. The default
`/etc/kronik/kronik.toml` renders byte for byte the unit of v0.4.1, so a
v0.4.1 host is still left alone; a custom `--config` now reaches the service.

The root template still carries no key path or credential. `--init --root`
keeps refusing a `--master-key-file` that names a file other than the one in
the configuration, because the daemon reads that file itself.

The test that pinned the template's digest now pins the default-rendered
unit's digest, and a plan test asserts that a custom configuration path
appears in both `ExecStart` and `ExecStopPost` of the written unit. The
configuration must still be readable inside the unit's sandbox; a path that
`PrivateTmp=true` or `ProtectHome=true` hides, such as one under `/tmp` or
`/root`, names the same file for the installer but not for the service. The
standard location, `/etc/kronik`, is outside both.

## Alternatives

- **Refuse a non-default `--config` with `BAD_REQUEST`.** It leaves the
  accepted flag broken by design, and the root install is the default one:
  an operator would have to choose the nonroot service to keep a custom
  configuration path. Rendering is the same change the nonroot unit already
  needed, and it preserves the documented directory step for `--config`.
- **Render a fixed path only into `ExecStart`.** `ExecStopPost` runs
  `foreign cleanup`, which must clean up the installation the daemon serves;
  leaving it on `/etc/kronik/kronik.toml` would clean up another installation.
- **Drop the byte-for-byte promise.** The template already has placeholders;
  rendering the default path keeps the installed bytes and the idempotent
  rerun intact, so existing root installations do not gain a gratuitous unit
  update.

## Consequences

A custom `--config` now produces a working root service, and a dry run names
the same configuration path the real run installs. Existing default
installations are untouched: the digest test and the "keeps what it wrote"
test still compare the installed unit, not the template's raw bytes.
Changing the configuration path on a rerun updates the unit, as changing the
binary already did. The sandbox limitation above remains for paths under
`/tmp`, `/var/tmp`, `/home` and `/root`; none of them is the documented
location, and `serve --init` still writes the file it was asked to write.
