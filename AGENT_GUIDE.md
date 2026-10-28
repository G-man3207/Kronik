# Kronik for agents

This page is all an agent needs to change a Kronik system safely: read what
production did, propose new code, read what the change would do to real
traffic, and ask a human to approve it. You get the same text from
`kronik explain agent` and from the MCP resource `kronik://agent-guide`.

Kronik runs **actors**: small programs, each with its own state, identified
as `kind/key` (for example `webhook-relay/payments`). Every input and every
effect (an HTTP call, a timer, a message) is recorded in a log. A change is
never deployed blind. You **propose** a new component. Kronik **forks**
history, replays recent real inputs through the new code with the recorded
effects, and writes a **behavior diff**. A **policy** then decides whether
the change may go live, needs a human's approval, or is denied.

## Connect

Kronik speaks MCP. Use one of these:

- **stdio:** run `kronik mcp` with `KRONIK_TOKEN=<token>` in its environment.
- **Streamable HTTP:** `POST /mcp` on the daemon's API, either on its Unix
  socket or over TCP with `Authorization: Bearer <token>`.

Your token decides what you may do. An agent's token has the scopes `read`,
`fork` and `propose`: you can read everything, make forks, and propose
changes. You cannot approve, promote or change grants and limits. Those
belong to humans, and you hand them over with `request_approval`. A call
outside your scopes fails with `SCOPE_MISSING`. Your forks never contain
personal data unless your token has `pii:read`.

## Rules for every call

- A tool that changes something requires `reason`: one sentence on why,
  recorded with your token's name. Most such tools also accept
  `dry_run: true`, which checks the call and changes nothing.
- A failed call returns `{"error": {"code", "message", "hint", "docs"}}`. The
  `code` is stable. Read the `hint` first: it usually holds the exact next
  step. `explain` with the code as `topic` gives the full explanation.
- Forks make no live effects. An effect in a fork is answered from the
  recordings, or denied. The one exception is a GET without secrets to a
  host the operator allowlisted. So nothing you do in a fork charges a card
  or sends a mail.

## The golden path

### 1. See what runs

- `list_actors` lists actors as `kind/key`, with their number of turns and
  their last turn id.
- `inspect_actor` with `{"actor": "kind/key"}` gives an actor's state:
  key-value entries and SQL tables.
- The resource `kronik://config` shows the deployments (which code runs for
  each kind), the grants (which effects each kind may make, against which
  targets), the limits and the policy rules in force.

### 2. Read the history

- `query_history` with `{"actor": "kind/key", "limit": 20}` gives turns,
  newest first. Each turn has its input (HTTP request, message or timer),
  its outcome (`committed` or `failed`, with an error code), the state it
  wrote, the messages it sent, and its effects: kind, target, status and
  delivery. Pass a result's `next` as `before` for older turns.
- `trace_turn` with `{"turn_id": "main:42"}` gives the causal tree around a
  turn. You get the root input that started it, the turns from the root down
  to it, and every turn it caused. Use it to see why something happened.
- `list_dead_letters` lists inputs that failed and effects with an uncertain
  outcome, with their error codes.

### 3. Make the change

Write the new code and build it into a component. In a Kronik project,
`kronik build` writes `dist/<name>.wasm`. Keep the actor kind and its routes.
Pass the component's bytes as base64. A request may be up to 64 MiB, over
stdio as over HTTP: a TypeScript component, about 17.5 MB in base64, fits.

### 4. Propose it

Call `propose_change` with `{"wasm_base64": "<base64>", "reason": "..."}`.
When the change spans several actor kinds (one starts calling a new message
of another), pass every changed component in one call as a list,
`{"wasm_base64": ["<a>", "<b>"], ...}`: they are verified together in one
fork, and promoted and rolled back together. Proposed one at a time, the
caller's proposal fails against the running callee. A component whose code
already runs, and ran at the fork point, is skipped and listed in
`proposal.unchanged`; if every one is, the call fails with `BAD_REQUEST`.
If such a kind changes code before you promote, promote answers
`PROPOSAL_STALE`: propose again.
Optionally add `window_ms`, how much recent traffic to replay (one hour by
default). Kronik forks, replays every root input of the window through your
code, evaluates the policy, and returns:

- `proposal.id`, such as `p-7h3k2a9c1d0e`. You need it for everything that
  follows.
- `proposal.status`: one of
  - `evaluated`: waiting for a decision;
  - `approved`;
  - `promoted`: live;
  - `rejected`: the policy denied it.
- `proposal.policy.outcome`: one of
  - `allow`: it may go live;
  - `require_approval`: a human must approve first;
  - `deny`: it may not go live.

  `proposal.policy.fired` names the rules behind the outcome.
- `proposal.summary`, the diff in numbers:

  | Field | Meaning |
  | --- | --- |
  | `root_inputs` | root inputs in the window |
  | `replayed` | how many were replayed |
  | `divergent_turns` | turns that behave differently |
  | `exact`, `approximate`, `synthetic` | how the fork's effects were answered: by an identical recording, by a similar one, or with no recording at all |
  | `confidence` | `exact / (exact + approximate + synthetic)` |
  | `changed` | whether anything differs |
  | `pii_masked` | in a fork without personal data (yours, unless your token has `pii:read`): turns that read pseudonyms instead of real values and came out differently, so they may differ for that reason alone; not counted as divergent or as errors. Always present, 0 when none |
  | `pii_unverified` | in such a fork: turns of changed code that read pseudonyms and came out identical, so they did not run on the real values either. Always present, 0 when none |

  While `pii_masked + pii_unverified` is above 0, the outcome is at least
  `require_approval`, and `policy.fired` lists `pii-masked-needs-approval`:
  a floor in code that no rule set removes, since a run on pseudonyms can't
  tell broken code from correct code. Its `reason` asks for a re-run with a
  `pii:read` token, which yours can't do: call `request_approval` (step 6).
  A human with `pii:read` re-runs the proposal to see the real behaviour
  before approving.

- `proposal.warnings`, when present: what you must know about how it was
  verified. "retention cut the window" means less history was replayed
  than `window_ms` asked for; say so when you ask for approval.
- `next`: the exact commands that follow, in order.

### 5. Read the diff

Call `get_diff` with `{"proposal": "<id>"}` for the whole diff
(`kronik.diff/v1`). Read it in this order:

- `errors.introduced`: turns that fail in the fork but committed in
  production. Anything above 0 is a regression, and the default policy
  denies it.
- `responses`: HTTP answers that changed, as JSON diffs of status, headers
  and body.
- `effects`: calls to the outside world that were added, removed or
  changed, with the changed fields (`url`, `method`, `header:<name>`,
  `body`).
- `grounding`: one entry per target (`host` and `route`), with its own
  `exact`, `approximate` and `synthetic` counts. Payments must be exact: the
  rule `payments-must-be-exact` asks for approval whenever a
  `payments.internal` target has a single approximate or synthetic effect,
  however high the total confidence.
- `state`: values written differently, per root input and per actor.
- `kinds`: each actor kind on its own, with whether its code changed and its
  share of the divergent turns, responses, effects, changed actors and
  errors. In a system proposal, read it to see which kind a regression is in.
- `resources`: fuel and memory, production against fork.
- `samples`: fork turn ids per category. Pass them to `trace_turn`.
  `samples.pii_masked` lists the pseudonym-affected turns, when there are
  any.
- `options.no_pii`: `true` when the fork ran without personal data, as
  yours do unless your token has `pii:read`.

To try one input by hand, call `create_fork` with
`{"at": "now", "reason": "..."}`. Then call `send_to_fork` with
`{"fork": "<name>", "actor": "kind/key", "name": "<message>", "text": "...",
"reason": "..."}`. This runs one message against the fork's code and state
and returns its outcome, reply and effects. `get_diff` with
`{"fork": "<name>"}` shows a fork's diff.

### 6. Ask for approval

If the outcome is `require_approval`, call `request_approval` with
`{"proposal": "<id>", "reason": "..."}`. Put your evidence in `reason`: what
changed, why, and what you checked in the diff. Kronik records a pending
request with your token's name; a human sees it with
`kronik proposals show <id>`. The result's `request.command` is the exact
command a human runs to approve. After the approval, promote puts the
change live:

```text
kronik approve p-7h3k2a9c1d0e --reason '...'
kronik promote p-7h3k2a9c1d0e --reason '...'
```

Give both commands to the human, with the proposal id and a summary of the
diff. Promote first replays the traffic that arrived since your proposal
(catch-up) and evaluates the policy again; an approval applies to the diff
it was given for.

If the outcome is `allow`, the proposal can be promoted without an approval.
`promote` needs the `promote` scope, which a person normally holds, so hand
over the command in `next` the same way. If the outcome is `deny`, fix the
code and propose again; `policy.fired` and `errors.items` say what to fix.

### 7. Afterwards

`list_actors`, `query_history` and `kronik://config` show what runs now. A
promoted change can be undone with `rollback` and the deployment's epoch,
which also needs the `promote` scope.

## Tools

| Tool | Scope | Does |
| --- | --- | --- |
| `list_actors`, `inspect_actor` | `read` | Actors and their state |
| `query_history`, `trace_turn` | `read` | History and causal trees |
| `list_dead_letters` | `read` | Failed inputs and uncertain effects |
| `create_fork`, `send_to_fork` | `fork` | Forks and messages into them; never live effects |
| `propose_change` | `propose` | Replays recent traffic through new code; returns the proposal and its diff summary |
| `get_diff` | `read` | The whole behavior diff of a proposal or a fork |
| `request_approval` | `propose` | A pending request with the exact command for a human |
| `promote`, `rollback` | `promote` | Switch code; promote runs catch-up first |
| `explain` | `read` | Concepts and error codes |

Resources: `kronik://agent-guide` (this page), `kronik://concepts`,
`kronik://errors`, `kronik://wit/kronik-actor.wit` (the interface every
component implements) and `kronik://config`.

## Errors you will meet

| Code | What it means for you |
| --- | --- |
| `SCOPE_MISSING` | Your token cannot do this. Hand it to a human with `request_approval` or the command from `next`. |
| `REASON_REQUIRED` | Add a `reason`. |
| `APPROVAL_REQUIRED` | The policy wants a human's approval first: `request_approval`. |
| `POLICY_DENIED` | The policy denies the change. Read `policy.fired`, fix the code and propose again. |
| `PROPOSAL_STALE` | Production changed since the proposal. Propose again. |
| `VERIFY_REQUIRED` | A kind with history only changes through `propose_change`. |
| `CAPABILITY_NOT_GRANTED` | The code calls a target it has no grant for. In a fork that call is denied; in production a human grants it. |
| `ACTOR_NOT_FOUND`, `FORK_NOT_FOUND`, `PROPOSAL_NOT_FOUND`, `TURN_NOT_FOUND` | Check the id: list again. |
| `UNAUTHENTICATED` | Your token is missing, unknown or revoked. |

Call `explain` with `{"topic": "<CODE or concept>"}` for anything else.
