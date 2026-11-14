# 0063. An existing installation is not converted in place

- **Status:** Accepted (2026-11-13). Implemented as the behavior of `kronik serve --init`. An in-place migration is the alternative; it is kept out of this decision as a separate, optional patch.
- **Date:** 2026-11-07

## Context

Until M21 every installation is a root installation: the daemon, the data directory and the foreign actors' files are owned by host root. The nonroot installation of ADR 0062 runs as the stable `kronik` user, and the foreign actors' files are owned by that user's subordinate id range (ADR 0061). Moving an existing installation from one kind to the other therefore changes the numeric owner, mode bits, capabilities and extended attributes of every file under the data directory, while the daemon is stopped, with foreign actors' trees that mix ids from the whole range.

A conversion in place needs a journal that survives a crash and a restart fence that keeps systemd from starting the old unit on a half-converted tree. That is a substantial feature (the prototype's version is about 1,300 lines of unsafe-allowlisted code), and nothing in the brief asks for it.

## Decision

`kronik serve --init` looks at the owner of the data directory before it changes anything, in `--dry-run` as well:

- A missing directory is not an installation, and neither is a root-owned one that is empty or holds only `keys` (a first run of `--rootless` that stopped early): the nonroot service adopts it, installs what it needs while the directory is still root's and private, and hands it over to the service user.
- The same kind as the requested one (root-owned with `--root` or by default, service-owned with `--rootless`) is rerun as before; every step checks first and changes nothing that is already right.
- The other kind is refused with `ROOTLESS_UNAVAILABLE` (503) before anything is written or stopped. The message names the kind that was found, and the hint names both ways forward: keep the installation by running `kronik serve --init` with `--root` (for a root one) or `--rootless` (for a nonroot one), or re-initialize it. A directory that belongs to the nonroot service's user is its installation even when it is empty: the root service would write into it as root, by path, in a tree that user controls.
- Beyond that the root service behaves as v0.4.0 did, so that no existing installation becomes impossible to repair: it follows a symbolic link to the data directory (a mounted volume) and asks nothing about the owner of a directory that is not the service user's. The nonroot service accepts only a directory that root owns or the service user owns, reached without a symbolic link in its path (root changes the owner of what is below it; use a bind mount), and refuses any other owner.

Re-initializing is documented in the operations guide: ship the data (or take a snapshot to a `file://` target that the `kronik` user can read), stop and remove the old unit, run `kronik serve --init` with an empty data directory, and `kronik restore` into it. Restore as root into the nonroot service's directory does the work that needs root first, then gives up root and finishes as the directory's owner (ADR 0062), so no file is left owned by root; the owner reads the remote after that, so a `file://` target has to be readable by the `kronik` user, or the remote is `s3://`. What is not shipped is not restored: foreign actors' data directories and checkpoints are local. Their records are in the log, so the actors are declared again; their persistent data has to be copied by the operator, with the ids of the other kind, or is lost.

## Alternatives

- **Convert in place.** Journal every inode's original owner, mode, capabilities and extended attributes before the first change, fence the old unit, change owners epoch by epoch and be able to reverse. It keeps foreign actors' data. It is the optional patch that accompanies this series; whether the project wants that much privileged, crash-sensitive code for a one-time move is the maintainer's call.
- **`chown -R` in the documentation.** Unsafe: it follows no policy for the subordinate ranges, drops capabilities and misses extended attributes.
- **Quietly keep the installation of the other kind.** Hides that `--init` did not install what was asked.

## Consequences

- No privileged code walks the data directory; the unsafe-allowlisted surface is smaller by the migration module.
- Moving an installation takes a restore, and foreign actors' persistent data does not move with it automatically.
- Nothing here has been run on a host with systemd; the decision logic is a pure function with unit tests.
- Revisit if operators need to keep foreign actors' data across the change: that is the case for the in-place migration.
