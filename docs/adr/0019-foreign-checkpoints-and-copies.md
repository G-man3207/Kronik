# 0019. Foreign actors in forks: gVisor checkpoints at snapshots, restored copies per fork

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M14: "Främmande aktörer checkpointas med gVisors checkpoint och restore, i
takt med snapshots. Med `fork_mode = "sandbox"` startar en fork en kopia
från närmaste checkpoint och spelar upp de inspelade gränsanropen fram till
forkpunkten." In v0.1 a fork never starts a foreign actor (m7-foreign §11):
a changed call gets an approximate or synthetic answer. A foreign actor's
state is not in the log (its data directory is not replayable,
m7-foreign §10), so a fork can only get a real answer from a process that
starts from a saved state of the actor. The first target is a VPS without
KVM (I11 for v0.1; every milestone's demo runs on one). The spike on the
dev machine (`docs/design/m14-foreign-forks.md` §1: runsc
release-20261019.0, systrap, Postgres 16.4) measured about 200 ms from pause
to resume for a checkpoint and about 100 ms for a restore, with no KVM.

## Decision

- **`fork_mode` on the declaration** (`ForeignActor.fork_mode`, field 12,
  `recorded` default, `sandbox`): configuration is history (I5), and a fork
  sees the mode as at its fork point. `sandbox` requires gVisor isolation.
- **Checkpoints with every snapshot.** Main's turns are paused (the turn
  gate's drain, ADR 0018), so no foreign call is in flight and every call's
  `EffectResult` is at or before the applied LSN: the checkpoint's LSN is
  an exact cut of the boundary. Per actor (each at its own LSN): close the
  actor's call gate, so main's calls to it wait in the daemon, and let main
  run again; pause the sandbox, copy its data directory, `runsc checkpoint
  --leave-running`, resume (retried; a sandbox that does not resume is
  killed and restarts); plus the sandbox's `config.json` and a `meta.json`.
  If turns do not pause within 2 s, that checkpoint is skipped and the
  snapshot goes on. Checkpoints are local
  files (`foreign/actors/<name>/checkpoints/<lsn>/`), the newest
  `checkpoints_kept` (3) per actor, not in the log and not shipped.
- **A copy per fork and actor**, started when the fork's continuous replay
  begins: the newest checkpoint at or before the fork point, its data copied
  under `branches/<fork>/foreign/<name>/<key>/`, the checkpoint's
  `config.json` with that data, an own network namespace with only `lo`, an
  own cgroup, and a fixed-length id `kronik-copy-<key>`, new per start;
  `runsc restore --detach` with the rootfs overlay in the copy's memory
  (`--overlay2=root:memory`, as production's sandbox runs);
  then every recorded `foreign.http` call of main to the actor in
  `(checkpoint, fork point]` is sent to it in log order, except calls of
  turns the fork runs again.
- **No copies** for a fork without personal data (a copy holds raw
  production data), a dry run, or a rollback via replay (recordings only):
  the actor is `recorded` there, with the reason in `options.foreign`.
- **The copy answers in continuous replay only**, in fork order; an exact
  match keeps production's recorded answer (and is still sent to the copy,
  so its state follows the fork). Isolated replay keeps v0.1's matching.
- **Lifetime with the fork's live state**: a new replay or a deployment
  into the fork stops the copy before a new one starts from the
  checkpoint; deleting the fork, promoting the proposal, its rejection by
  the policy or going stale, or stopping the daemon stops it and deletes
  its directory; leftovers are removed at start.

## Alternatives

- **Replay the actor from scratch** (an empty sandbox, every recorded call
  since the actor was added). Unbounded and impossible after retention, and
  the data directory's history is not in the log.
- **Copy the data directory only** (start a fresh process on a copy of
  `/data`). Works for some databases after crash recovery, but loses what
  the process holds in memory and its exact point; gVisor's checkpoint keeps
  both, at the cost of a short pause.
- **Checkpoint without pausing turns.** Calls in flight would be in the
  checkpoint but recorded after its LSN, and would be replayed into the
  copy a second time.
- **Checkpoints in the snapshot directory, shipped.** They are host-specific
  (runsc version, platform) and large, and the foreign data directory is
  not shipped either; a restored host takes new ones.
- **Use the copy in isolated replay** with one copy per root input.
  Restoring and replaying the boundary per root input costs seconds each;
  isolated replay keeps recordings and the continuous fork gets the copy.
- **`trusted` (runc) copies.** runc has no checkpoint without CRIU, which
  the project does not depend on.

## Consequences

- A snapshot pauses main's turns only until each `sandbox` actor's call
  gate is closed; main's calls to that actor wait for its checkpoint, about
  200 ms (more for a large data directory, which is copied).
- Answers from a copy are not deterministic: replaying a fork again can
  give a different diff where a copy answered. They are labeled (ADR 0020).
- The checkpoint holds the program's memory and its runtime spec, so it is
  as sensitive as the secrets the program was given: 0700 directories, 0600
  files. Secret rotation does not reach kept checkpoints; they age out
  (`checkpoints_kept`) or go with the actor.
- Copies share the production bundle's root file system; their writes go
  to a gVisor overlay in the copy's memory (`--overlay2=root:memory`, the
  medium production's sandbox runs with, which a restore must match),
  never into production's; a new image of the actor while a
  fork runs leaves that fork's copy on the old one until its next replay.
- A host restored from the bucket has no checkpoints until its first
  snapshot; forks fall back to `recorded` and the diff says why.
