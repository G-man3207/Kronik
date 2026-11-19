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
- Forks make no live effects but one. An effect in a fork is answered from
  the recordings, or denied. The exception is a GET without secret headers
  to a host in `[fork] live_allowlist` whose grant's effective delivery
  class is `replay-safe`, which goes out live. So nothing you do in a fork
  charges a card or sends a mail.

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
  newest first. Each turn has its input (HTTP request, message, timer, or a
  connection's open, incoming frame or close),
  its outcome (`committed` or `failed`, with an error code), the state it
  wrote, the messages it sent, and its effects: kind, target, status and
  delivery. An effect that used a secret also lists it in `secrets`, with
  the secret's name, its version and the first 8 hex characters of its
  version hash, never a value: when an operator rotates a secret, the turns
  after it show a higher version and the turns before it keep theirs. Pass a
  result's `next` as `before` for older turns.
- `trace_turn` with `{"turn_id": "main:42"}` gives the causal tree around a
  turn. You get the root input that started it, the turns from the root down
  to it, and every turn it caused. Use it to see why something happened.
- `list_dead_letters` lists inputs that failed and effects with an uncertain
  outcome, with their error codes.
- `list_connections` lists an app's WebSocket and SSE connections: owner,
  route, state, close and frame counts. `query_history` with `connection`
  gives one connection's turns, with what each sent and whether the frames
  were written.
- A body larger than its kind's blob threshold (an upload, a large `fetch`
  response, a blob an actor wrote) is a blob, outside the log. History and
  trace show a turn's blob references (`blobs` in their JSON, a `BLOBS`
  column or a trailing `blob …` in text): each is the hash and size an
  `inspect_blob` call takes. The API's turn JSON shows a body that is a blob
  as its reference too. "Large bodies and blobs" below says what you must
  know about them.

### 3. Make the change

Write the new code and build it into a component. In a Kronik project,
`kronik build` writes `dist/<name>.wasm`. Keep the actor kind and its routes.
If its routes include `WEBSOCKET` or `SSE`, the component must still export
`kronik:actor/connection-handler`, or propose refuses it with `BAD_REQUEST`.
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
`proposal.unchanged`; if every one is, the call fails with
`NOTHING_TO_PROPOSE`.
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
  and body. A blob body is compared by reference and shown as
  `{"blob": "b3:…", "size": N}`, never its bytes.
- `frames`, when present: what the root inputs sent to WebSocket and SSE
  connections. `frames.changed` counts the inputs whose outgoing frames or
  whose open answers differ. Each item shows the changed frames as JSON
  diffs of their data. `frames.skipped` counts the inputs of connections
  that the fork's code never accepted, which continuous replay does not run.
- `effects`: calls to the outside world that were added, removed or
  changed, with the changed fields (`url`, `method`, `header:<name>`,
  `body`). They are paired with production by the turn's operation ordinal,
  so a call inserted or removed before another in the same turn shows as
  changed pairs plus a tail `added` or `removed`, not as one insertion at its
  position. The item list is capped at 200; the counts are not.
- `grounding`: one entry per target (`host` and `route`), with its own
  `exact`, `approximate` and `synthetic` counts. Payments must be exact: the
  rule `payments-must-be-exact` asks for approval whenever a
  `payments.internal` target has a single approximate or synthetic effect,
  however high the total confidence. It counts the fork's effects only: a
  payment call the fork no longer makes has no row and does not lower
  confidence (a payment effect that takes its ordinal is graded on its
  own). Gate that absence with a rule on `diff.effects` (the uncapped
  counts, or the capped per-target items), not on grounding (ADR 0147).
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
and returns its outcome, reply and effects. A fork has a diff only once
recorded traffic has been replayed through it, which `kronik replay <name>`
does and no tool of yours does: then `get_diff` with `{"fork": "<name>"}`
shows it. Before that, `get_diff` answers `BAD_REQUEST`. A proposal's diff
exists as soon as `propose_change` returns.

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
which also needs the `promote` scope. When that deployment migrated state,
`rollback` with `by_replay` creates a rollback via replay instead (`propose`
and `pii:read` scopes: it replays on full data, so a token without `pii:read`
gets `SCOPE_MISSING` and a human creates it): a rebase proposal `r-...` whose diff shows the old code's state and
the effects that cannot be undone; it needs a human's approval, then
`promote`.

## Large bodies and blobs

A body larger than its kind's blob threshold (1 MiB by default) is a
**blob**: an upload, a `fetch` response, or bytes a turn writes. The record
keeps only a reference, `b3:` and the BLAKE3 hash of the bytes (`b3s:` and
a hash keyed per subject for a subject's blob) with the size; the bytes
stay in the node's blob store. This holds for code that imports the blob
interface, `kronik:actor/blobs` (`ctx.blobs` in the SDKs); other code gets
no blobs. When you write or review such code:

- **A hash is not a reference.** A turn may use exactly the blobs its actor
  holds, the ones its input carries (an upload, a message's or timer's
  `blobs`) and the ones it got during the turn (a `fetch` response, a
  call's reply, a blob it wrote). Any other reference fails with
  `BLOB_NOT_HELD`, even with the right hash: a hash kept in state, SQL or a
  message body is data. Production and every replay check the same way.
- **Holds keep blobs.** A blob a turn got is borrowed, readable until the
  turn ends. To use it in later turns, the actor holds it: `retain(b)`, or
  `put(bytes)` to store new bytes and hold them; `release(b)` ends the
  actor's own hold. Holds change when the turn commits, like state. Keep
  the hold, and store the hash and size to rebuild the reference later.
- **Blobs travel in `blobs`.** A message, a timer or a call's reply carries
  blobs in its `blobs` field, never in its body. The receiving turn may read
  them, and holds one only if it retains it.
- **Subjects.** A blob gets the subject in effect when it is written (the
  turn's default; `putFor` names another), and in privacy mode it is sealed
  with that subject's key, so erasing the subject makes it unreadable
  (`SUBJECT_ERASED`). Keep its reference in a value or row of the same
  subject, and send it under that subject.
- **Quota.** An actor keeps at most its kind's blob quota alive (1 GiB by
  default): its holds and the blobs of its timers, waiting messages and
  dead letters. Past it, `put` and `retain` raise `BLOB_QUOTA_EXCEEDED`,
  which the code can handle; a `send`, timer or `call` past it fails the
  turn.
- **Forks** read production's blobs, and the blobs a fork's turns write go
  to the fork's own space.

History shows a turn's input, writes and effects, not its blobs. A hash
shows in an app's own answers and state (`inspect_actor`, which also counts
the blobs an actor holds), in a diff's bodies, in `blob_gc_plan`, and in the
API's turn JSON (`GET /v1/turns/{id}`: a blob body as its reference, its
subject only with `pii:read`).
`inspect_blob` with a hash gives the blob's state, size and what keeps it:
`held` by an actor, a `pin` (a queued message, a timer, a dead letter, a
saved response, a running turn), a `log` record within retention, a
`snapshot`, a `fork` or a `lease`. `blob_gc_plan` lists the files nothing
keeps, with why. Neither returns bytes or deletes anything: the collector
deletes what nothing keeps, and the bytes are for an operator
(`kronik blobs get`).

## Tools

| Tool | Scope | Does |
| --- | --- | --- |
| `list_actors`, `inspect_actor` | `read` | Actors and their state |
| `query_history`, `trace_turn` | `read` | History and causal trees |
| `list_dead_letters` | `read` | Failed inputs and uncertain effects |
| `inspect_blob` | `read` | A blob's state, size and what keeps it, by its hash; never its bytes |
| `list_connections` | `read` | WebSocket and SSE connections, or one by `id`; closing one is an operator's command |
| `blob_gc_plan` | `read` | The blob files nothing keeps, with why (`loose`, `released`, `out-of-retention`, `erased`); deletes nothing |
| `create_fork`, `send_to_fork` | `fork` | Forks and messages into them; only a secretless `GET` whose grant is `replay-safe`, to an allowlisted host, leaves |
| `propose_change` | `propose` | Replays recent traffic through new code; returns the proposal and its diff summary |
| `get_diff` | `read` | The whole behavior diff of a proposal or a fork |
| `request_approval` | `propose` | A pending request with the exact command for a human |
| `promote`, `rollback` | `promote` | Switch code; promote runs catch-up first; `rollback` with `by_replay` creates a rebase proposal (`propose` and `pii:read`) |
| `explain` | `read` | Concepts and error codes |

Resources: `kronik://agent-guide` (this page), `kronik://concepts`,
`kronik://errors`, `kronik://wit/kronik-actor.wit` (the interface every
component implements) and `kronik://config`.

Master-key custody is an operator concern. `kronik keys status` (or
`GET /v1/keys`, scope `read`) reports the loaded source, wrapping-key
identity/version and local key-check result, never key bytes. Rewrap is an
audited `admin` operation; file/environment migration is offline
`kronik keys wrap` after the operator stops the daemon. Do not copy keys,
provider credentials or ciphertext into a chat or a reason. If a key source
is unavailable, hand off its configuration/reachability to the operator;
never “fix” missing key material by making a new seed over existing data.

## Errors you will meet

| Code | What it means for you |
| --- | --- |
| `SCOPE_MISSING` | Your token cannot do this. Hand it to a human with `request_approval` or the command from `next`. |
| `REASON_REQUIRED` | Add a `reason`. |
| `APPROVAL_REQUIRED` | The policy wants a human's approval first: `request_approval`. |
| `POLICY_DENIED` | The policy denies the change. Read `policy.fired`, fix the code and propose again. |
| `PROPOSAL_STALE` | Production changed since the proposal. Propose again. |
| `NOTHING_TO_PROPOSE` | Main already runs every component you passed. Nothing changed: stop proposing, or change the code and build it again. |
| `VERIFY_REQUIRED` | A kind with history only changes through `propose_change`. |
| `CAPABILITY_NOT_GRANTED` | The code calls a target it has no grant for. In a fork that call is denied; in production a human grants it. |
| `SECRET_UNAVAILABLE` | A secret's value cannot be read now, often a linked secret whose backend is down. A fork never fetches one: it uses only a value the node already holds for the fork point. Ask the operator; do not retry in a loop. |
| `BLOB_NOT_HELD` | The code used a blob reference its turn neither holds nor received, such as one rebuilt from a stored hash without a hold. Use the reference the turn got, or retain the blob in the turn that got it. |
| `BLOB_QUOTA_EXCEEDED` | The actor would keep more blob bytes alive than its kind's quota. Release what it no longer needs, or handle the error in the code; raising the quota (`kronik limits set`) is the operator's. |
| `BLOB_STORE_FULL` | The node's disk is below the blob store's reserve: uploads that would become blobs are refused, and turns that write blobs wait and run again. Ask the operator; do not retry in a loop. |
| `BLOB_MISSING` | A committed blob's bytes are not in the store, which is never expected (a restore without them, or files removed by hand). Hand it to the operator. |
| `BLOB_NOT_FOUND` | This node knows no such blob: a mistyped hash, another node's, or one nothing kept and the collector deleted. Check the hash. |
| `UPLOAD_TOO_SLOW` | An upload arrived slower than the gateway's minimum rate (8 KiB/s, after 30 s), so nothing of it was kept. Send it faster. |
| `PREVIEW_FULL` | A preview took as many requests, or as many blob bytes (256 MiB), as it can hold. It needs a new preview. |
| `EFFECT_BYTES_EXCEEDED` | A turn's effects would record more inline bytes than its kind allows (32 MiB by default). Let large responses become blobs (code that reads blobs keeps them out of the log), or split the work over several turns. |
| `SUBJECT_ERASED` | The data's subject was erased, a blob's too: it cannot be read. Do not retry; code that needs it must handle its absence. |
| `ACTOR_NOT_FOUND`, `FORK_NOT_FOUND`, `PROPOSAL_NOT_FOUND`, `TURN_NOT_FOUND` | Check the id: list again. |
| `UNAUTHENTICATED` | Your token is missing, unknown or revoked. |
| `KEY_SOURCE_UNAVAILABLE` | A KMS operation could not complete within its total budget. Ask the operator to check provider reachability, credentials and key versions; the running node may still have its loaded key. |
| `KEY_PROTECTION_UNAVAILABLE` | Required memory/dump protection failed. Ask the operator to fix host limits/protection; do not disable it. |
| `MASTER_KEY_MISSING`, `MASTER_KEY_MISMATCH` | Existing encrypted stores need the original seed/correct wrapping material. Stop and hand off recovery; do not regenerate or overwrite the key. |

Call `explain` with `{"topic": "<CODE or concept>"}` for anything else.
