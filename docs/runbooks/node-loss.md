# Node loss

Goal: preserve acknowledged history and authority when one member is lost,
measure actual replacement time, and recover the member without split-brain
or duplicate external effects.

## Cluster prerequisite

This procedure requires the real public member startup/join/router/lifecycle
integration. At the committed single-node baseline those cluster consumers are
not available. A private RawNode fixture, three processes on one machine, or
a single-node restart does **not** exercise the M32 replacement target or close
this runbook's three-node test environment criterion. Do not invent a `cluster` CLI
command to conceal that prerequisite. Reconcile the final public member
commands and authority/status surface with the cluster implementation
before executing a cluster drill.

## Operational procedure

1. Record all actual member identities, voter/learner roles, current leader,
   epoch, committed/applied positions, routes and in-flight owned fixture
   requests. Ensure quorum remains before stopping any member. Retain the
   exact member lifecycle handles; never select a process merely by its name.
2. Send a bounded fixture workload with unique idempotency keys and record each
   successful acknowledgement. Record the monotonic failure-injection time,
   then terminate **only the allocated member fixture** using its exact
   recorded process/container handle. Do not change host firewalls, clocks,
   shared services or customer deployments.
3. Observe the actual public status/forwarding boundary until a replacement is
   authoritative. Measure first proven replacement minus failure-injection
   time; polling intervals bound measurement precision. Sleeping ten seconds
   and asserting success is not measurement. The unchanged target is <10 s.
4. Verify every acknowledged fixture operation exists exactly once, stale
   leaders cannot publish state/effects, revoked/stale forwarded authority
   cannot enqueue work, and effect receipts/outbox ownership remain correct.
   A read-only status response alone does not prove these transitions.
5. Rejoin the lost member with the implementation's real persisted identity
   and join/recovery process. Do not manufacture a new identity over its old
   log or bypass fencing. Catch it up and compare committed history/state.
6. Clean only the owned fixtures and preserve the exact binary/source hashes,
   topology, failure timing, acknowledgements, replacement proof and integrity
   results. Report any invariant violation without narrowing the workload.

## Single-node recovery control

For a single-node fixture, SIGKILL/restart and comparison of acknowledged
counter/SQL state against the recovered log is a useful **crash-recovery
control**, not cluster leader replacement. The existing `scripts/chaos.sh` and
[snapshot/retention documentation](../guides/operations.md#snapshots-and-retention)
cover that path. A 30-day physical three-node chaos history cannot be replaced
by a short local control or fabricated elapsed time.
