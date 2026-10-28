# M14 foreign actors in forks

Status: binding for M14. Builds on `m7-foreign.md` (sandboxes, the bridge,
§11 replay and forks), `m3-fork.md` (§3 replay, §3.5 matching), `m6-storage.md`
(snapshots) and ADR 0003; brief section "v0.3: Rikare replay", M14, and the
invariants I5, I7, I11, I17. ADR 0019 records the checkpoints and copies,
ADR 0020 the `forked` grounding.

In v0.1 a fork never starts a foreign actor: a changed call to a database
gets an approximate (production's answer to another request) or synthetic
answer. With `fork_mode = "sandbox"` a fork instead starts a **copy** of the
foreign actor from its nearest checkpoint, brings it to the fork point by
replaying the recorded boundary calls, and lets it answer the fork's calls.
Answers from a copy are graded `forked`.

## 1. Spike (dev machine: root, runsc release-20261019.0, no KVM, systrap)

`postgres:16.4-alpine3.20`, pinned
`sha256:5660c2cbfea50c7a9127d17dc4e48543eedd3d7a41a595a2dfa572471e37e64c`
(pulled from Docker Hub, converted to an OCI layout with skopeo), run by
runsc with `--network=sandbox` in a namespace with only `lo` and `/data` a
host bind mount (`PGDATA=/data/pg`), 1 000 rows:

| Step | Time |
| --- | --- |
| `runsc pause` | 10 ms |
| copy `/data` (39 MB) | 120 ms |
| `runsc checkpoint --leave-running` (16 MB image) | 61 ms |
| `runsc resume` | 12 ms |
| pause to resume, in all | about 200 ms |
| `runsc restore --detach` of a copy (own bundle, data copy, namespace) | 100–115 ms |
| first query in the copy | 93 ms |

The production sandbox keeps running across the checkpoint. Two copies
restored from one checkpoint (each with its own copy of `/data`) are
independent: a row inserted in one is in neither the other nor production,
and a row inserted in production afterwards is in no copy. From inside a
copy, `wget http://1.1.1.1/` fails with "Network unreachable". Checkpoint
and restore need no KVM: they work with systrap, so M14 holds on the
testbench VPS. I11 binds v0.1; the brief's test strategy runs every
milestone's demo on a VPS without KVM, and M14 meets that too.

Findings for the design: `/data` is not in the checkpoint (a host bind
mount), so the checkpoint copies it while the sandbox is paused, and each
copy gets its own copy of that; runsc resolves container ids by prefix, so
copy ids have a fixed length.

## 2. Configuration (I5)

`ForeignActor` gains `string fork_mode = 12`: `recorded` (the default; an
empty value from an older record means the same) or `sandbox`. `kronik
foreign add <name> ... --fork-mode sandbox`; the API's `ForeignAddRequest`
and `ForeignView` carry `fork_mode`. `sandbox` needs `isolation = gvisor`
(runc has no checkpoint): `trusted` with `sandbox` is `BAD_REQUEST`. To
change the mode, remove and add the actor again (its data directory stays).
`[foreign] checkpoints_kept` (default 3) bounds the checkpoints per actor.

## 3. Checkpoints, in step with snapshots

Every snapshot of main (interval, `kronik snapshot create`, shutdown, ...)
also checkpoints every running `sandbox` actor, one after the other, each
at its own LSN:

1. Main's turns are paused (the turn gate's drain, ADR 0018: no turn
   starts but callee turns of calls, and it waits until no turn runs), at
   most 2 s, after any other drain (a rebase switch); it takes no deploy
   lock. If that does not happen, this actor gets no checkpoint this time
   (a warning) and the snapshot goes on.
2. `lsn` = main's applied LSN. With no turn running, every foreign call of
   main has its `EffectResult` at or before `lsn`, and no call after it has
   started: the checkpoint is an exact cut of the boundary.
3. The actor's call gate is closed: from now on main's calls to it wait in
   the daemon (not inside the paused sandbox), and main's turns resume.
   Main is held only for this, not for the copy and the runsc steps.
4. The bridge's idle connections are closed, `runsc pause`, the data
   directory is copied to `foreign/actors/<name>/checkpoints/<lsn:020>/data`,
   `runsc checkpoint --leave-running --image-path .../image`, `runsc
   resume`, and `meta.json` (`lsn`, image digest, platform, `runsc` release,
   bytes, time) and the sandbox's `config.json` are written. A failure is
   logged and leaves no partial checkpoint (written to `.tmp-<lsn>`, renamed
   at the end; leftover `.tmp-*` directories of failed or interrupted
   checkpoints are deleted before the next one). A resume that fails is
   retried twice; a sandbox that still does not resume is killed, so its
   supervisor restarts it: production never stays paused.
5. The call gate opens. Checkpoints beyond `checkpoints_kept` are deleted,
   oldest first; removing the actor deletes its checkpoints.

Checkpoints are local, like the foreign data directory: they are neither in
the log nor shipped (a restored host has none until its next snapshot).
They hold the program's memory and `config.json`, which contain the secret
values the program was given (m7-foreign §9): directories are 0700, files
0600. The copied data keeps modes and owners but, as unpacked images
(m7-foreign), never setuid or setgid bits. A rotated or deleted secret's old value stays in the checkpoints kept
(`checkpoints_kept`) until they age out; remove and add the actor again to
drop them at once. A copy deletes its bundle's `config.json` once it runs,
as production's sandbox does, and `kronik foreign cleanup` removes copy
bundles' `config.json` and partial (`.tmp-`) checkpoints a stopped daemon
left. A checkpoint is not written while the disk is below `[log]
disk_reserve` or when its data would not fit above it, and a fork gets no
copy that would not fit (the actor is `recorded`, with the reason).

## 4. Copies in forks

**Where.** Continuous replay of a fork (propose, `kronik replay`, catch-up,
messages into the fork) uses copies; isolated replay keeps v0.1's matching,
because its root inputs run in parallel on discarded overlays that one
running process cannot follow. In `both` mode (the default) the diff takes
the effects to an actor with a copy, and the responses of the root inputs
that call it, from the continuous view.

**No copies** (the actor is `recorded`, and `options.foreign[].why` says
why): a fork without personal data (`--no-pii`, every caller without
`pii:read`) gets none, since a copy holds production's raw data; a dry run
(`--dry-run`) starts none (I12); a rollback via replay starts none, as it
answers from production's recordings only (m13-rebase §8).

**Start** (when a fork's continuous replay begins, for every actor of the
fork's configuration with `fork_mode = "sandbox"`):

1. The nearest checkpoint: the newest with `lsn` at most the fork point. If
   there is none (or the actor runs no checkpointable sandbox), the actor
   stays `recorded` for this fork and the diff says why.
2. `branches/<fork>/foreign/<name>/<key>/data` is a copy of the
   checkpoint's data directory; `config.json` is the checkpoint's with that
   data directory, the copy's own network namespace (only `lo`), cgroup and
   id (`kronik-copy-<key>`, `key` = 16 hex of blake3(fork, name, a counter
   per start): fixed length, and new for every start, so stopping an old
   copy never touches a new one).
3. `runsc restore --detach --overlay2=root:memory --image-path
   <checkpoint>/image --bundle <copy>`: the copy's writes to the shared
   rootfs go to an overlay in its own memory, as production's sandbox
   runs (a restore must match the checkpointed overlay medium). Then a
   bridge connection
   (`runsc port-forward`) proves it answers.
4. **Up to the fork point**: every `foreign.http` call of main to the actor
   whose `EffectResult` is in `(checkpoint lsn, fork point]` is sent to the
   copy in log order (status `denied` never left and is skipped; other
   failures may have reached the actor and are sent), except calls of
   turns whose root input the fork runs again (a turn across the fork
   point), which reach the copy from the fork's run. Answers are dropped.
   If this fails, every copy already started for the fork is stopped.

**Answers.** In continuous replay a `foreign.http` call to an actor with a
copy is sent to the copy in fork order, so the copy follows the fork's
history. If production made the same call (exact match), the fork keeps
production's recorded answer (grounding `exact`); otherwise the copy's
answer is the result, with grounding `forked` (ADR 0020). Approximate
matching does not apply to such an actor: a changed query gets a real
answer, not production's answer to another query. A copy that cannot be
reached gives the guest `network("FOREIGN_UNAVAILABLE: ...")`, graded
`forked` as well.

Secret headers of recorded calls cannot be replayed (the log holds no
values) and are dropped when sent to a copy. A call with an unknown outcome
in production is sent to the copy once; the copy may differ from production
there. The copy's clock and background work are its own: answers that
depend on time can differ.

**Isolation (I7).** A copy runs with runsc's `--network=sandbox` in a
namespace with only `lo`: no route out, as for production sandboxes. It is
reached only through the bridge, from the fork's replay.

**Lifetime.** A copy belongs to the fork's live replay state: it is stopped
and its directory deleted when that state is replaced (a new replay of the
fork or a deployment into it; the old copy is stopped before a new one
starts), when the fork is deleted (`kronik fork delete`), when a proposal
is promoted, rejected by the policy or goes stale, or when the daemon stops
(`Foreign::shutdown` stops every copy). An evaluated proposal keeps its
copies until one of these, for its catch-up at promote.
Copies never survive the daemon: at start, leftover copy containers are
killed with the production leftovers (id prefix `kronik-copy-`) and
`branches/*/foreign/` is removed.

## 5. The diff and the policy (ADR 0020)

- Grounding rows and the summary get `forked` (additive in
  `kronik.diff/v1`; old diffs read as 0); effect items can say `forked`;
  `confidence` is exact over all, as before.
- `options.foreign`: one entry per `sandbox` actor of the fork:
  `{"name", "mode": "sandbox" | "recorded", "checkpoint_lsn", "replayed_calls",
  "why"}` (`why` when it fell back to recorded).
- Policy rules see `t.forked` per target, e.g. `t.host == 'pg' && t.forked >
  0` to require approval when a database answered from a copy. The default
  rules (the brief's) are unchanged; forked answers lower `confidence`, which
  `low-grounding-needs-approval` judges.

## 6. API and CLI

- `POST /v1/foreign`: `fork_mode` (`recorded` default). `GET /v1/foreign`:
  each actor's `fork_mode` and `checkpoints: [{"lsn", "at_ms", "bytes"}]`.
- `kronik foreign add ... --fork-mode sandbox`; `kronik foreign list`
  shows the mode and the newest checkpoint.
- `kronik snapshot create` (like every snapshot) checkpoints the `sandbox`
  actors; `kronik foreign list` shows the newest checkpoint.

## 7. Tests (root, runsc and the `foreign-pg` image; skipped otherwise)

`foreign-pg` (`examples/foreign-pg`, built by
`scripts/build-foreign-examples.sh --only foreign-pg`, which needs docker for
the pinned Postgres base) is Postgres 16.4 plus a small HTTP shim on 8080:
`POST /sql` runs the body with `psql` and answers its output.

| Criterion | Test |
| --- | --- |
| A fork with `fork_mode = "sandbox"` starts a copy of a Postgres actor from the nearest checkpoint | `crates/kronik/tests/foreign.rs` `postgres_fork_answers_from_a_copy`: rows before a snapshot, rows after it, a fork after them; the diff's `options.foreign` names the checkpoint and the replayed calls; the copy runs. |
| A changed SQL query gets a real answer from the copy, labeled `forked` | same test: the fork's code changes every query; counts come back equal to production's from the copy, graded `forked`; a message into the fork reads a row only the fork inserted. |
| The copy cannot reach the network and is deleted with the fork | same test: the copy's sandbox runs in its own namespace, which has only `lo` (the positive control), and egress from inside the copy fails (meaningful only on a host that itself reaches 1.1.1.1:443; the namespace check holds everywhere); a second replay replaces the copy; after `kronik fork delete` the copy's container and directory are gone. |

Plus `crates/kronik-fork/tests/foreign.rs` with an in-memory host (a
second replay stops the old copy first; `both` mode grades the copy's
answers `forked`; `--no-pii`, dry runs and rollbacks via replay start no
copies; a rejected proposal stops its copies; a turn across the fork point
reaches the copy once; main runs during a checkpoint), unit tests for the
recorded-call extraction, the copy specification, the resume-or-kill step
and the gate's `forked` grading, `kronik-proto` compatibility fixtures
(`ForeignActor.fork_mode`, an effect with `GROUNDING_FORKED`), and a
policy fixture with `forked`.
