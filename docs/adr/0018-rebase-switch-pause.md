# 0018. The rebase switch: stage first, then a bounded pause in which no turn runs

- **Status:** Accepted
- **Date:** 2026-10-27

## Context

M13: "Under själva bytet håller gatewayn nya requests i högst
`rebase.max_pause`, 2 sekunder som standard", and no root input may be lost
or duplicated during the switch. The state after a `StateRebase` is the
fork's, built from main's root inputs up to the switch (ADR 0017). A root
input that commits on main after the fork's last catch-up and before the
switch would be in main's history but not in the rebased state (lost); a
turn that runs across the switch would apply new-code writes on top of the
rebased state. Promote's switch (m3-fork §8) lets running turns finish
with the old code; that is not enough here.

## Decision

- **Stage before pausing.** Promote of a rebase catches up as promote does,
  then appends the fork's turns (`RebasedTurn`) to main's log while main
  runs, and the node keeps an in-memory shadow (state at the fork point plus
  the staged turns) up to date. Only the last root inputs remain for the
  pause. Each turn is in the fork's own log before it is staged. A replay
  state that a failed or cancelled round may have left half-way is
  dropped; the replay that replaces it (also after a restart) must give
  exactly the turns already staged (fork LSN and record hash against the
  fork's log), else promote refuses with `PROPOSAL_STALE` and a hint to
  create the rebase again: the staged turns stay inert.
- **Main's newest code change only.** Before staging and again at the
  switch (under the deploy lock), a deployment or rebase switch after the
  rolled-back one makes promote `PROPOSAL_STALE`; so does a fork point
  before main's newest rebase switch for any proposal.
- **Consequences main has not run stay main's.** The rebase fork runs a
  message, compensation or timer only when main's history has its turn
  (with recordings); one main had not run when its round was indexed (in
  flight at the pause, or new under the old code) stays pending in the
  fork's store, so in the shadow, and main runs it after the switch with
  real effects. A later round queues it once main has run it.
- **The pause is in the node, not only in the gateway.** `Node` stops
  starting turns: every actor worker leaves its queued jobs (HTTP root
  inputs from the gateway, API messages, resends, messages, timers) where
  they are, except the callee turns of `call`s whose caller still waits,
  which run so that a running turn can finish (one whose caller gave up
  waits for the pause to end). The switch waits until no turn runs, and
  checks it again under the switch gate. Held HTTP requests
  wait in the gateway for their turn, so the gateway holds them without
  code of its own.
- **Bounded.** From the moment turns are held, the wait for running turns,
  the last catch-up round (it reads only main's records since the previous
  round) and its staging run under one deadline, `rebase.max_pause`
  (`[rebase] max_pause`, default 2 s). At the deadline the round is
  abandoned, nothing more is written, the node resumes and promote fails
  with `PROPOSAL_STALE`; the staged turns stay and a retry continues from
  them.
- **Then one record.** Erasures since the fork point are applied to the
  shadow at their place and again after the last staged turn (a replayed
  input from before an erasure must not bring the subject back), the
  `StateRebase` switch is committed, the applier transplants the shadow in
  the record's `state.db` transaction, the node switches its code, reloads
  its timer wheel, replaces queued messages and timers with the rebased
  mailbox, answers held resends of dead letters the rebased state no longer
  has with `DEAD_LETTER_NOT_FOUND`, takes a snapshot at the switch (storage
  configured), and resumes.
- **Cancel-safe.** From the commit on, the switch (commit, code, reload,
  end of the pause) runs on a task of its own that holds the deploy lock,
  the drain and the switch gate; a caller that goes away (a client
  disconnect) cannot leave it half done. A reload that fails after the
  commit makes the node fatal; a restart applies the switch from the log.
  Set switches (deploy, promote, rollback) run the same way.

- **One gate with set switches (ADR 0013).** The pause is the *drain* of
  the node's turn gate (`kronik-sched` `gate.rs`); the switch gate of ADR
  0013 is the other half. Promote of a rebase takes the deploy lock before
  it drains and keeps it through the last round and the switch, so a
  deploy, promote or rollback waits for the rebase switch instead of
  landing inside it. The switch commits its record under the switch gate's
  write lock and installs its code through the same path as a set switch.
  Lock order everywhere: deploy lock, drain, write lock. Foreign
  checkpoints (M14) drain without the deploy lock; a drain waits for
  another to end, within its own bound. Only the rebase pause fails with
  `PROPOSAL_STALE` naming `rebase.max_pause`; a plain drain fails with
  `UNAVAILABLE`.

## Alternatives

- **Gateway-only hold.** API messages, resends, timers and messages already
  queued would still start turns during the switch.
- **Hold a read lock for each whole turn and take it for writing.** A turn
  that `call`s an actor whose queue holds a job waiting for the lock never
  finishes: a deadlock. The worker skipping to queued callee turns avoids
  it.
- **Don't wait for running turns; let them finish later.** Their writes
  would land on the rebased state, and a root input among them would be
  committed after the fork's last round: lost from the rebased state.
- **Copy everything inside the pause.** The copy grows with the window;
  2 s would only fit small windows.

## Consequences

- Creating a rollback via replay needs the `pii:read` scope as well as
  `propose`: its fork runs on full data, because its turns become main's
  state, so it cannot be the fork without personal data that a token
  without `pii:read` gets (privacy guide, AGENT_GUIDE.md). The brief's M13
  does not have agents propose rollbacks via replay; the MCP `rollback` tool
  with `by_replay` therefore answers `SCOPE_MISSING` for an agent token
  without `pii:read`, and a human (or an operator token) creates it.

- During a switch, actors run at most the callee turns of calls already in
  flight; everything else waits up to `rebase.max_pause`.
- A turn blocked on a slow external effect makes the switch time out
  instead of stretching the pause; the operator retries.
- The transplant runs after the record and is not bounded by the pause: its
  cost is the affected actors' state.
- The last round reads main's records since the previous round only; its
  replay of those root inputs must fit in `rebase.max_pause`.
- Verified by `the_pause_holds_requests_at_most_max_pause`,
  `consequences_in_flight_at_the_pause_run_on_main_after_the_switch`,
  `a_resume_that_cannot_prove_its_staged_turns_is_refused` and
  `a_deployment_after_the_rebase_makes_its_promote_stale`.
- A cluster (M16) needs the same pause per shard.
- Verified with the set-switch hook `test_hold_switch`, which also parks
  the rebase switch after its record is applied:
  `no_turn_starts_with_old_code_after_a_rebase_switch`,
  `a_set_switch_waits_for_a_rebase_switch` and
  `a_rerun_after_a_rebase_keeps_the_rebased_code_and_schema`
  (`crates/kronik-fork/tests/rebase.rs`).
