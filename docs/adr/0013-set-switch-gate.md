# 0013. One switch for a set of kinds: the turn-start gate

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M9: "A `Deployment` can cover several actor types with the same
configuration epoch and `effective_lsn`", and "after `effective_lsn`, no
turn starts with old code for any type in the set". Promote and rollback
already wrote one `Deployment` for every kind through `Node::switch_code`,
with `effective_lsn = 0` meaning the record's own LSN (m3-fork §8). But the
switch was three steps: commit the `Deployment` (append, fsync, apply),
swap every kind's code, then store the new epoch. A turn took its code in
`run_job` and its epoch later in `run_turn`, and a migrate turn and the
input's turn each read the epoch again. So a turn could start while the
`Deployment` was being committed, or after it was applied and before the
swap, with the old code; or take the old code and the new epoch. With a
group commit window that is milliseconds by default and configurable, that
window is real. Running turns finishing with the old code is intended and
stays.

## Decision

- The node's turn gate (`kronik-sched` `gate.rs`, `TurnGate`) holds the
  switch gate, an `Arc<tokio::sync::RwLock<()>>` (shared, so a switch's own
  task can hold an owned write guard). A turn takes its
  kind's code and the configuration epoch together under a read guard and
  passes the epoch into `run_turn` (and into the record of an input that
  could not run). After a job's migrate turn commits, it takes them again;
  if a switch swapped the code meanwhile, the input's turn runs the new
  code, migrating first again if that code's schema version is ahead. A
  re-run after a crash uses its recorded epoch and code, and the schema
  version of that code's `Deployment`, not the current kind's.
- Deploy, promote and rollback take the write guard right before they
  append their `Deployment` and hold it until every kind of the set and the
  epoch are swapped. Compiling, route checks and dry runs happen before,
  without it. The append and the swap run on a task of their own that owns
  the deploy lock and the write guard, so a caller that goes away (a client
  disconnect) cannot leave a `Deployment` committed with the old code
  running (`a_cancelled_set_switch_still_installs_its_code`).
- So every turn starts either before the switch, with the old code of every
  kind and an epoch below the new one, or after the `Deployment` is
  applied, with the new code of every kind. Turns that arrive during the
  switch wait for it: the `Deployment`'s group commit, fsync and apply, and
  the swap.
- The set's routes are checked as a whole (`check_set_routes`): against the
  kinds outside the set and between the kinds of the set. Kinds a proposal
  skipped are pinned: under the deploy lock, each must still run the code
  it was verified with, else `PROPOSAL_STALE`.

## Alternatives

- **Swap the code before the commit.** Turns could start with code whose
  `Deployment` is not durable; after a failed commit their records would
  name an epoch that never existed.
- **One lock for code and epoch, no gate across the commit.** Makes
  code and epoch consistent, but turns can still start with the old code
  after the `Deployment` is in the log.
- **A non-zero `effective_lsn` in the future.** Needs every turn to compare
  LSNs it does not know when it starts; the brief's `effective_lsn` is
  already satisfied by the record's own LSN once the gate closes the window.
- **Pause the whole node (stop ingress) during a switch.** Also stops
  turns of kinds outside the set and messages already in flight; the gate
  only delays turn starts, briefly.

## Consequences

- Every turn start takes an uncontended read lock: one atomic operation in
  the common case. During a switch, new turns wait for its commit and
  apply; running turns, calls already made and other writers are not
  blocked.
- Not closed by the gate: a turn that took the old code before the switch
  and is still running can `call` a kind of the set after the swap (old
  caller, new callee; no replay ran that pair). Keep serving the messages
  the old code sends for one release after changing them. And an HTTP
  request routed by the old route table just before the switch runs on the
  new code of the kind it was routed to.
- Deadlock-free by construction: the read guard is held only for two loads
  and never across an await, and the commit path takes no turn.
- Verified by `no_turn_starts_with_old_code_after_a_set_switch`
  (`crates/kronik-fork/tests/system.rs`): the hidden test hook
  `NodeConfig::test_hold_switch` parks a rollback after its `Deployment` is
  applied and before the swap, the test sends turns of both kinds, waits
  until both have come for their code, and releases the switch. Without
  the gate it fails with a turn after the rollback's LSN running the code
  it replaced; nothing in it depends on timing.
- In a cluster (M16) the epoch becomes an LSN per shard; the gate is per
  node, so that milestone has to keep the same rule per shard.
- M13's rebase switch goes through the same gate and install path; the
  pause it needs is the gate's drain (ADR 0018).
