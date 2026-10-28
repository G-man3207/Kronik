# M9 system proposals

Status: binding for M9. Builds on `m3-fork.md` (§5 the diff, §8 proposals,
promote and rollback, §9 API); brief section "v0.2: Hela system i CI", M9.

Several actor kinds are verified and switched as one unit: `kronik propose
a.wasm b.wasm` or `kronik propose dist/` puts every new hash in one fork,
one replay runs them together, one diff reports each kind on its own, and
one `Deployment` switches (and a rollback restores) the whole set. A
proposal is still a fork with a diff and a deployment still points to
hashes: no new concept (I13).

## 1. What already existed (M3)

- `POST /v1/proposals` took `wasm_base64` as a list, `Proposals::propose`
  prepared every component, refused two for one kind, and `fork_kinds`
  replaced or added each kind in the fork's code. Isolated and continuous
  replay already ran every kind of the fork, and a fork turn's `call` to
  another kind ran as a fork turn under the fork's code for that kind.
- `Deployment.kinds` is a list; promote and rollback wrote one
  `Deployment` through `Node::switch_code` for every kind of the proposal
  (rollback: every kind of the target deployment, each back to its code
  before that epoch, refused as a whole when one kind would lower its
  schema version).
- `kronik propose` took several files, MCP `propose_change` a string or a
  list.

## 2. What M9 changes

| Area | Change |
| --- | --- |
| CLI | `kronik propose <WASM_OR_DIR>...`: a directory stands for the `.wasm` files directly in it, in name order (not recursive; none is `BAD_REQUEST`). The CLI sends the file names (`names`), so an error names the files: two builds of one kind (a TypeScript project's `dist/<name>.wasm` and `dist/<name>-<entry>.wasm`) are refused with both names. Human output lists `Skipped <kind> <hash>` lines and a `Kinds` block. |
| Propose | The fork point is chosen first. A component is skipped only when its code hash equals the code main runs for its kind now and the code main ran at the fork point (the code the fork would run for it); it is listed in the proposal's `unchanged` with its full hash, and pinned: promote refuses with `PROPOSAL_STALE` when such a kind no longer runs that code. A changed kind is pinned too, to main's code for it when the proposal was made (or to its absence), so a promote never overwrites a newer deployment of a kind it changes. Any other component stays in the set, also when main runs it now (promote then swaps to the same code). When every component is skipped: `BAD_REQUEST` "nothing to propose", with a hint for an identity replay (`kronik fork create`, `kronik replay`). The set's routes are checked before replay (`ROUTE_CONFLICT`, §4). |
| Diff | `kinds`: one entry per actor kind (ADR 0012), additive to `kronik.diff/v1`. Markdown gets an "Actor kinds" table. |
| API | `ProposalInfo.unchanged: [{kind, code_hash, schema_version}]` (default `[]`); `ProposeRequest.names` (optional, one per component, for error messages). |
| MCP | `propose_change` describes the list form, skipping and `proposal.unchanged`. |
| Switch | Turns read their code and epoch under a gate that a switch holds from its `Deployment`'s commit to the swap of every kind (ADR 0013). Routes are checked for the set as a whole. |
| Policy | Nothing new to evaluate: rules see `diff.kinds` like any field, e.g. `diff.kinds.exists(k, k.kind == 'payments' && k.errors.introduced > 0)`. |

## 3. `kinds` in the diff

Sorted by kind; one entry for every kind of the fork's code (`code.after`
and `code.before`) and every kind a replayed turn ran as:

```json
{"kind": "notes", "code": "changed" | "unchanged" | "new" | "absent",
 "root_inputs": 1, "turns_prod": 1, "turns_fork": 5,
 "divergent_turns": 4, "origins": 0, "consequences": 4,
 "responses": {"unchanged": 0, "changed": 0},
 "effects": {"added": 0, "removed": 0, "changed": 0},
 "actors_changed": 1,
 "errors": {"introduced": 0, "fixed": 0, "new_orphans": 0, "outcome_unknown": 0}}
```

Each count is the top-level count restricted to the kind: root inputs by
the actor they address, turns, divergence, origins, consequences and errors
by the turn's actor, responses by the HTTP root input's actor, effects by
the turn that made them, and `actors_changed` by the actors in
`state.isolated` and `state.continuous` (uncapped). A divergent turn
belongs to one kind, so the kinds' `divergent_turns` add up to
`summary.divergent_turns`. `code` compares the kind's entry in
`code.before` (production at the fork point) with `code.after`; `absent`
means neither has one (a kind only turns that found no deployed kind ran
as, `ACTOR_NOT_FOUND`).

## 4. Routes of a set

`Node::check_set_routes` checks the routes the set would serve against the
deployed kinds outside the set and against the other kinds of the set. So
a set may move a route from one of its kinds to another, and two kinds of a
set cannot both take a new route. Single-kind deploy uses the same check.

## 5. The switch (criterion 3)

`effective_lsn` stays 0, "the `Deployment`'s own LSN" (m3-fork §8). A turn
starts when it takes its kind's code and the configuration epoch; it does
so under `switch_gate` for reading. Deploy, promote and rollback take it
for writing from right before their `Deployment` is appended until every
kind of the set and the epoch are swapped. So a turn starts either before
the switch, with the old code of every kind and an epoch below the new
one, or after the `Deployment` is applied, with the new code of every kind.
Turns that arrive during the switch wait for it: the `Deployment`'s group
commit, fsync and apply, then the swap. Running turns finish with the old
code, as before. After a job's migrate turn the code is taken again: if a
switch swapped it meanwhile, the input's turn runs the new code (migrating
again first if the new code's schema version is ahead).

Known limits, documented rather than closed in M9:

- A turn that took the old code before a switch and is still running can
  `call` a kind of the set after the swap: old caller, new callee, a
  combination no replay ran. Keep serving the messages the old code sends
  for one release after changing them.
- An HTTP request is routed by the route table when it arrives; if a switch
  lands between routing and the turn's start, the turn runs the new code of
  the kind it was routed to, even when the new code no longer declares that
  route.
- A kind that a proposal does not list runs its code at the fork point for
  the whole window, also where main deployed other code for it inside the
  window (this predates M9). Propose with a window that starts after the
  last deployment of the kinds involved, or list those kinds' current
  components too.

For tests, `NodeConfig::test_hold_switch` (hidden, like
`test_hold_after_call`) parks a promote or rollback right after its
`Deployment` is applied and before the swap, and counts the turns that come
to take their code, so a test can send turns into exactly that window.

## 5a. Rollback of a set

A rollback restores every kind of the target deployment to its code before
that epoch, in one `Deployment`, or refuses as a whole. A deployment cannot
remove a kind, so rolling back a set that added a kind is refused
(`BAD_REQUEST`, nothing written). The operator proposes the earlier
components of the other kinds together (`kronik propose <earlier
components>`), which verifies and switches them as one; the added kind
keeps running, and a later proposal can change its code. Removing a kind
is out of scope for M9.

## 6. Compatibility

- Log: no format change; `Deployment` already had `repeated kinds`.
- `kronik.diff/v1`: `kinds` is added, not required by the schema (diffs
  written before M9, kept in `branches/*/diff.json`, still validate and
  load with `kinds: []`). No version bump (ADR 0012); fixture
  `docs/design/fixtures/diff-system-caller-alone.json`. A diff's bytes, and
  so its hash, now include `kinds`: a proposal from before M9 that is
  promoted after an upgrade gets a new diff hash at catch-up, and an
  approval then holds through the existing changed-targets rule.
- API and CLI JSON: `unchanged` is an added field with a default.
- Behavior: a proposal of code main already runs, which used to give an
  empty diff, is now refused; identity replay is a fork replay.

## 7. Tests

- `crates/kronik-fork/tests/system.rs`:
  `a_caller_and_its_new_callee_verify_together_and_fail_apart` (criteria 1,
  2; under an explicit `no-new-errors` policy, with the default rules
  checked on the same diffs),
  `unchanged_components_are_skipped_and_nothing_changed_is_refused`,
  `no_turn_starts_with_old_code_after_a_set_switch` (3, with the switch
  hold), `rolling_back_a_set_restores_every_kind_at_one_lsn` (4),
  `rolling_back_a_set_that_added_a_kind_is_refused`,
  `a_component_promoted_inside_the_window_is_not_skipped` (the skip rule),
  `promote_refuses_when_a_skipped_kind_changed_code` (pins),
  `a_rerun_across_a_schema_raising_switch_keeps_its_code_version`,
  `two_kinds_of_a_set_cannot_claim_one_route` and
  `a_set_can_move_a_route_from_one_kind_to_another` (§4). Test guests:
  `counter-calls-tally` (every increment calls `tally` on notes/tally),
  `notes-tally` (serves `tally`), and `counter-route-tally` and
  `notes-route-tally` (each also claims `GET /tally/{key}`), built by
  `scripts/build-test-guests.sh`.
- `crates/kronik/tests/schemas.rs`: a two-kind proposal's diff validates
  against `diff-v1.schema.json`, and so does every policy fixture
  (`docs/design/fixtures/diff-*.json`; `diff-system-caller-alone.json` is
  a real diff of the counter-calls-tally proposal alone).
- `crates/kronik-policy/tests/policy.rs`: the new fixture's default
  outcome, and a per-kind rule.
- `crates/kronik/tests/cli.rs`: `kronik propose <dir>`, human and JSON.
