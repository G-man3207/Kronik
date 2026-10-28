# 0022. Proposals run as daemon jobs

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M10: "`propose --async` returns immediately, and `kronik proposal status`
and `kronik proposal wait` follow the progress", and "a 30-minute replay
survives the CLI client disconnecting". A proposal's replay ran inside the
`POST /v1/proposals` request: when the client went away, hyper dropped the
request's future and the replay with it, half done and unrecorded. A CI
runner, a laptop going to sleep or a proxy timeout would lose every long
replay.

## Decision

- **A job per proposal.** `POST /v1/proposals` does the checks (components,
  fork point, retention, skip rule, routes) in the request, so a bad
  request still fails at once, then writes the proposal with status
  `running` (`branches/<id>/proposal.json`) and runs the replay, the diff
  and the policy on a task of its own (`Env::spawn`). The proposal file,
  its entry and the job are created under the proposals lock with no await
  in between, so a request dropped while it waits for the lock leaves no
  orphan `running` proposal. The job runs the replay on an inner task: if
  it panics, the proposal becomes `failed` with `INTERNAL`, and its waiters
  are released. Without `async` the request waits for the job and answers
  as before (`Proposals::propose` is that wait, so tests run the job path);
  if the client goes away, only the wait ends. With `"async": true` it
  answers at once with the running proposal. A dry run keeps nothing to
  follow, so it always waits (and `async` with `dry_run` is
  `BAD_REQUEST`); it also runs on its own task.
- **Statuses.** `running` and `failed` join the existing ones. A failed job
  keeps its error (`error`, the error JSON) in the proposal. Approve,
  promote, request-approval, the diff and `send --fork` into the
  proposal's fork (MCP `send_to_fork`) of a running proposal answer the
  new stable code `PROPOSAL_RUNNING` (409, "wait and repeat"), so nothing
  writes the fork's log while the job does; of a failed
  one `BAD_REQUEST` with "propose again". A job does not survive the daemon:
  at startup a proposal still `running` becomes `failed` ("the daemon
  restarted"), never a half-written success.
- **Progress.** The replay counts root inputs done and to do, per mode
  (`replay::Progress`, relaxed atomics read by `GET /v1/proposals/{id}` as
  `progress`); counters never change a result or the diff. `kronik proposal
  status` shows them; `kronik proposal wait` polls every half second,
  prints a progress line to stderr when it changes, and ends with the
  proposal (exit 0), its error (exit 1), or `PROPOSAL_RUNNING` when
  `--timeout` (default 1 h) runs out.
- **Testing without the clock.** A hidden hook (`--test-replay-permits`,
  `Proposals::with_test_gate`) makes each isolated root input of a job wait
  for a permit, so a test holds a job at a known point, disconnects its
  client and releases it step by step.

## Alternatives

- **Keep the replay in the request and ask clients to keep the connection
  open.** The criterion is exactly that a disconnect must not matter.
- **A job queue with persistence and resume after a restart.** Replay is
  deterministic and cheap to start again; resuming half a replay would
  need its in-memory trees on disk. Failing the proposal clearly is enough.
- **Server-sent events or a streaming endpoint for progress.** Polling a
  small JSON object every half second is simple, works over every proxy and
  needs no new transport.
- **Reuse `PROPOSAL_STALE` or `BAD_REQUEST` for "still running".** The
  request is right and only early; a client must be able to tell that it
  can wait and repeat it unchanged.

## Consequences

- Long replays no longer depend on the client; several jobs can run at
  once (each with its own workers).
- The proposal JSON (`ProposalInfo`) gains `progress` and `error`;
  `policy` and `summary` are null while running. Additive.
- A daemon restart fails running proposals; CI then proposes again.
- Tested by `crates/kronik/tests/remote.rs`
  (`a_proposal_outlives_its_client_and_wait_shows_progress`) and
  `crates/kronik-fork/tests/proposals.rs`
  (`a_running_proposal_refuses_send_approve_request_approval_and_diff`,
  `a_proposal_running_at_a_restart_is_failed_and_refused`).
