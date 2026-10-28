# M3 fork, replay and behavior diff

Status: binding for M3. Builds on `m1-core.md` and `m2-effects.md`; brief
sections "Forks, replay och beteendediff", "Deploy, propose, promote och
rollback", policy, invariants I1, I4, I5, I7, I13. §7 (the policy interface)
is self-contained for the `kronik-policy` implementer.

## 1. Crates

| Crate | M3 adds |
| --- | --- |
| `kronik-fork` | `Fork` (branch metadata and state at the fork point), `ProductionIndex` (root inputs, production turns by causal key, effects by causal key and ordinal), `Replayer` (isolated and continuous replay, the deterministic scheduler, the replay effect gate), `Diff` (builder, `kronik.diff/v1` JSON, Markdown), `Sampler`. Pure except for reading logs and opening in-memory stores. |
| `kronik-policy` | Rules in TOML, CEL evaluation against the diff JSON, default rules (§7). Implemented by a second worker against §7. |
| `kronik-store` | Overlays (`Store::overlay_begin/rollback`: savepoints on `state.db` and on every actor database touched), `StateDb::apply` inside a savepoint so it nests in an overlay, in-memory stores for production cursors. |
| `kronik-sched` | Branch-aware code lookup for replay, `propose`, `approve`, `promote` with catch-up, `rollback`, policy records; `Deployment` with `PROMOTE`/`ROLLBACK`. |
| `kronik-api` | The endpoints in §9. |

## 2. Branches and forks

- **A fork is a branch** named `f-<12 hex>` (or `--name`), created at a
  fork point `fork_lsn` on `main` (`--at <lsn>`, `--at <RFC 3339 time>`: the
  last LSN whose logical time is ≤ the time, or `now`: the applied LSN).
- **Storage.** `branches/<fork>/log/` holds the fork's own records; its
  first record is `BranchCreated {branch, parent_branch: "main", fork_lsn,
  no_pii, proposal_id, audit}` at LSN `fork_lsn + 1`. Fork LSNs continue
  main's numbering from the fork point, so turn ids `<fork>:<lsn>` never
  collide with main's. `branches/<fork>/diff.json` holds the latest diff.
  Main knows its forks by scanning `branches/` at startup.
- **State at the fork point** is main's state after `fork_lsn`: built by
  applying main's log `1..=fork_lsn` into an in-memory store (snapshots from
  M6 will start from the nearest snapshot instead). A fork's own state is
  that plus its own records.
- **Configuration (I5).** Deployments, grants, limits and policy as of the
  fork point (main's configuration records with LSN ≤ `fork_lsn`), plus the
  fork's own configuration records (a proposal deploys its code in the fork
  with a `Deployment` in the fork's log; a direct deploy over history is
  allowed in a fork).
- **No live effects (I7).** The replay gate never calls `Net`. An effect is
  answered from production's recording (§3.5), or by a stub rule, or
  `FailClosed`. `[fork] live_allowlist` (hosts) may allow replay-safe GETs to
  listed hosts; empty by default, and nothing else ever leaves.
- **`--no-pii`**: the fork reads no subject keys (privacy mode, M8);
  until then the flag is recorded and values with a subject are redacted
  in the diff anyway (§5.4).

## 3. Replay

### 3.1 Root inputs

The input of replay is every **root input** in main within the window
`(fork_lsn, to_lsn]`: each main `TurnRecord` whose causal key has an empty
path and whose input is not `migrate` (HTTP requests, operator messages,
dead-letter resends). Inner messages, calls, timers and migrations are never
taken from the recording; they arise from the fork's code. A root input is
identified by its production LSN and its root id.

### 3.2 Production index

Built once per replay from main's log over the window (plus the records
needed for state, §3.3): production turns by causal key (`TurnRecord` with
outcome, writes, messages, timers, effects, SQL change sizes, fuel, memory,
logical time, seed), production effects by `(causal key, ordinal)`, and the
causal tree of each root input (production turns whose causal key starts with
the root id).

### 3.3 Isolated replay (default for the diff's main part)

- Each root input runs against **production's state at its own LSN** in an
  overlay that is discarded afterwards: a production cursor (an in-memory
  store) applies main's records in LSN order up to the record before the
  tree's first one: the root turn's `TurnBegin` when it wrote one (a turn
  that calls commits its callees' turns before its own record, and those
  belong to its tree), else its `TurnRecord`; the
  root input's whole causal tree then runs under the fork's code inside an
  overlay (savepoints on `state.db` and on each actor database touched);
  the overlay is rolled back. A difference therefore cannot infect a later
  root input.
- Migrations: if the fork's code has a higher schema version than an actor
  touched by the tree, `migrate(from)` runs first, inside the overlay.
- Timers set inside an isolated tree fire only where production fired the
  same timer in the window: the fork's timer turn gets the production timer
  turn's causal key exactly when the fork set the same timer, and it runs
  at that turn's place. Before that turn (and any other matched consequence
  committed after the root), the overlay applies the production records in
  between that are not part of this tree, so the turn reads the state
  production had there. A later root's write of the same key is not a
  difference of this tree. Other timers do not fire (continuous replay shows
  them); a production timer turn the fork did not schedule counts as
  missing, caused by the scheduling turn's difference.
- **Parallelism.** Root inputs are partitioned into contiguous chunks, one
  per worker; each worker builds its own cursor (state at the fork point,
  then main's records up to its chunk) and runs its chunk in order of the
  trees' first records.
  Results are merged in LSN order. Each root input's result depends only
  on (state at its LSN, its input, the fork's code, the recordings), so the
  diff is byte-identical with 1, 4 or 16 workers.

### 3.4 Continuous replay

- One fork store starts at the fork point and evolves under the fork's code
  in production order over **all** root inputs of the window (never
  sampled). It shows cumulative effects, writes the fork's log, and is the
  fork that catch-up continues.
- Single-threaded, deterministic.

### 3.5 The deterministic scheduler and matching

- **Turn matching.** A fork turn matches a production turn with the same
  causal key. A matched turn reuses the recorded logical time and seed. An
  unmatched (new) turn gets the logical time of its causal parent (or of the
  timer's due time) and the seed `blake3("kronik.fork.seed.v1" + fork name
  + causal key encoding)`.
- **Order.** Each pending fork turn has an order key, a sequence of u64
  compared lexicographically: a matched turn has `[production LSN]`; a new
  turn has its causal parent's key followed by `ordinal + 1`. The scheduler
  always runs the pending turn with the smallest key; per actor, turns are
  serialized in that order. So matched turns run in production order and
  new turns run right after their causal parent.
- **Calls** run the callee's turn in the fork (re-executed, not taken from
  the recording); its result is internal.
- **Fork-only timers** (continuous): a timer due at `d` fires at the first
  production position whose logical time is ≥ `d`, before that root input:
  its order key is `[that root input's LSN - 1, u64::MAX, seq]`, which sorts
  after everything at the previous LSN and before the root input. Timers
  still pending at the end of the window stay pending.
- **Effect matching**, per external effect of a fork turn (`http.fetch`,
  `crypto.*`, `secret.reveal`):
  1. **Exact**: a production effect with the same causal key, ordinal, kind
     and fingerprint: its recorded result is returned (`GROUNDING_EXACT`).
  2. **Approximate**: same causal key, ordinal, kind and *target*, but a
     different request: the recorded result is reused, the effect is
     flagged approximate (`GROUNDING_APPROXIMATE`) and the request
     difference goes to the diff. The target of an HTTP effect is method,
     host and **route pattern**: the URL path with each segment that is a
     decimal number, a UUID, 8 or more hex characters, or a mix of letters
     and 6 or more digits replaced by `{}`; the query is ignored.
  3. **Synthetic**: no counterpart: a stub rule (from the proposal) if one
     matches, else `FailClosed`, which gives the guest
     `denied("replay: no recording")` (`GROUNDING_SYNTHETIC`); the turn is
     marked divergent.
  Crypto matches exactly by fingerprint (name and data hash) or is
  recomputed on the host with the production key (the key never leaves the
  host, but the fork gets a real HMAC or signature over data its code
  chose); it counts as exact either way. `secret.reveal` in a fork never
  gets the value: it answers the placeholder `[secret:<name>]` (exact when
  production revealed at that point, else synthetic). Production records
  HTTP and call requests, and fingerprints them, with the same placeholder
  in place of revealed values, so requests a fork builds from a value used
  verbatim match exactly. A value the guest transformed (Basic auth's
  base64 of `user:secret`, an HMAC or a JWT it computed from a revealed
  key) is not scrubbed in production and comes out differently from the
  placeholder in the fork, so such requests match approximately or not at
  all: a known gap of exact-only scrubbing.

## 4. Comparison

A fork turn and its production turn **differ** when any of these differ:
outcome kind and error code; output (status, headers, body); state writes
(key, operation, value); outgoing messages (target, name, body); timer
operations (op, due time relative to the turn's time, message); external
effects (kind, target, fingerprint); SQL changes (row-level, §5.4). Fuel and
memory are compared separately (§5.10); a fuel change under 2 % is not a
change. **Noise filters**: per proposal, `ignore_headers` (names) and
`ignore_json_paths` (JSONPath subset `$.a.b[*].c`) are removed from bodies
and headers before comparison.

**Causal grouping.** An **origin** is a differing turn whose input is
byte-identical to production's (the root turn of a tree, or a turn whose
message did not change). Every other difference in the same tree (a turn
with a changed input, a turn that is new in the fork, a production turn
missing in the fork) is a **consequence** of its nearest differing ancestor.

## 5. `kronik.diff/v1`

Canonical JSON: object keys in the order listed here, arrays in the stated
order, integers as JSON integers, ratios as JSON numbers with at most 6
decimals (rounded half-even), no timestamps from the host clock. The same
fork, code and options always give the same bytes (except `forked` answers
of copies of foreign actors, M14, ADR 0020); `diff_hash =
blake3(bytes)`. The JSON Schema is
[`docs/reference/diff-v1.schema.json`](../reference/diff-v1.schema.json),
and tests validate real diffs against it. It includes the fields added as
built: `live` (§11), `stubs`, `live_allowlist` and `no_pii` in `options`,
`pii_masked` (M8), `kinds`, each actor kind on its own, after `summary`
(M9, [m9-system-proposals.md](m9-system-proposals.md) §3, ADR 0012), and
`preview_inputs` and `samples.preview` (M11, §11).

```json
{
  "schema": "kronik.diff/v1",
  "fork": "p-7h3k2a9c1d0e",
  "proposal_id": "p-7h3k2a9c1d0e",
  "base": {"branch": "main", "fork_lsn": 1200, "from_lsn": 1201, "to_lsn": 9800},
  "code": {
    "before": [{"kind": "counter", "code_hash": "b3:…", "schema_version": 0}],
    "after":  [{"kind": "counter", "code_hash": "b3:…", "schema_version": 0}]
  },
  "options": {"mode": "both", "sample": 1.0, "ignore_headers": [], "ignore_json_paths": [], "fuel_threshold": 0.02, "stubs": [], "live_allowlist": [], "no_pii": false},
  "summary": { … §5.1 },
  "causes": [ … §5.2 ],
  "grounding": [ … §5.3 ],
  "responses": { … §5.4 },
  "effects": { … §5.5 },
  "state": { … §5.6 },
  "cumulative": { … §5.7 },
  "errors": { … §5.8 },
  "resources": { … §5.9 },
  "samples": { … §5.10 }
}
```

### 5.1 `summary`

| Field | Type | Meaning |
| --- | --- | --- |
| `root_inputs` | int | root inputs in the window |
| `replayed` | int | root inputs replayed in isolated mode |
| `sample` | number | `replayed / root_inputs` (1.0 when the window is empty) |
| `turns_prod` | int | production turns of the replayed trees |
| `turns_fork` | int | fork turns of the replayed trees |
| `divergent_turns` | int | turns that differ (§4), both modes deduplicated by causal key |
| `origins`, `consequences` | int | §4 |
| `exact`, `approximate`, `synthetic`, `live` | int | effect groundings over all fork effects (`live`: §11) |
| `confidence` | number | `exact / (exact + approximate + synthetic + live)`; 1.0 without effects |
| `verified_through_lsn` | int | the last main LSN whose root inputs ran through the fork's code |
| `changed` | bool | any difference anywhere in the diff |
| `pii_masked` | int | in a `--no-pii` fork, differing turns that read pseudonyms, not counted as divergent (M8); absent when 0 |
| `preview_inputs` | int | in a preview fork, the requests it took at its URL (M11, §11); absent when 0 |

### 5.2 `causes`

Sorted by origins descending, then kind, then input:
`[{"kind": "counter", "input": "POST /counter/{key}/{op}" | "message increment" | "timer increment", "origins": 3, "consequences": 10412, "root_inputs": 3, "samples": ["p-…:r1290.0"]}]`
(`input` is the method and route pattern for HTTP, `message <name>` or
`timer <name>` otherwise).

### 5.3 `grounding`

One entry per external target, sorted by kind, host, route:
`[{"kind": "http.fetch", "method": "POST", "host": "payments.internal", "route": "/v1/charges/{}", "exact": 120, "approximate": 4, "synthetic": 0, "live": 0, "confidence": 0.967742}]`.
For crypto and reveal: `method` is `""`, `host` is the secret name, `route`
is `""`.

### 5.4 `responses`

Per HTTP root input (isolated mode): `{"unchanged": N, "changed": N, "items": [{"root_lsn", "route", "turn_prod", "turn_fork", "status": {"prod", "fork"}, "headers": [{"name", "prod", "fork"}], "body": [ <json diff ops> ]}]}`, items in root LSN
order. Body diff: when both bodies are JSON, a list of `{"op": "add" |
"remove" | "replace", "path": "/a/0/b", "prod", "fork"}` (JSON Pointer
paths, sorted); otherwise `[{"op": "replace", "path": "", "prod": <text or
base64>, "fork": …}]`. Values with a subject tag are redacted:
`{"redacted": true, "subject": "user:1", "hash": "b3:…"}`.

### 5.5 `effects`

`{"added": N, "removed": N, "changed": N, "items": [{"change": "added" | "removed" | "changed", "kind", "method", "host", "route", "grounding", "turn_prod", "turn_fork", "fields": [{"field": "url" | "method" | "header:<name>" | "body", "prod", "fork"}]}]}`
grouped (sorted) by kind, host, route, then turn. Secret header values never
appear (name and version hash only).

### 5.6 `state`

`{"isolated": [{"root_lsn", "actor", "keys": [{"key", "op": "set" | "delete" | "unchanged-missing", "prod", "fork"}], "sql": [{"table", "op": "insert" | "update" | "delete", "pk": [...], "prod": {...}, "fork": {...}}]}], "continuous": [{"actor", "keys": [...], "sql": [...]}]}`.
Isolated entries compare the writes of each root input's tree; continuous
entries compare each actor's final state (fork store vs production cursor at
`to_lsn`). Values with a subject are redacted as in §5.4.

### 5.7 `cumulative`

Differences visible only in continuous replay: actors whose final state
differs although every isolated tree that touched them was unchanged, or
whose drift grows: `{"actors_changed": N, "items": [{"actor", "keys": [...], "sql": [...]}]}`.

### 5.8 `errors`

| Field | Meaning |
| --- | --- |
| `introduced` | fork turns that fail where production committed, plus new turns that fail |
| `fixed` | turns that committed in the fork but failed in production |
| `new_orphans` | orphans created in the fork that production did not create |
| `outcome_unknown` | fork effects matched to a production effect whose recorded status was outcome-unknown |
| `items` | `[{"kind": "introduced" | "fixed" | "new_orphan" | "outcome_unknown", "error_code", "message", "turn_prod", "turn_fork", "input"}]`, at most 20 per kind |

### 5.9 `resources`

`{"fuel": {"prod": {"p50", "p95", "p99"}, "fork": {...}}, "memory": {"prod": {...}, "fork": {...}}, "fuel_p99_change": number, "memory_p99_change": number}`,
over matched turns; `*_change = (fork - prod) / prod` (0.0 when prod is 0).

### 5.10 `samples`

Up to 20 fork turn ids per category, in order: `{"origins": [...], "consequences": [...], "responses_changed": [...], "effects_changed": [...], "errors_introduced": [...], "synthetic": [...]}`,
and `"pii_masked": [...]` when there are any (M8), and `"preview": [{"turn",
"method", "route", "status", "outcome"}]` for a preview's requests (M11,
§11).
Fork turn ids: continuous turns `<fork>:<lsn>`; isolated turns
`<fork>:r<root_lsn>.<n>` (n-th turn of that tree).

### 5.11 Markdown

`GET …/diff?format=md` renders: a header (fork, base, code, policy
outcome), a summary table, causes (origins first, "3 origins, 10 412
consequences"), grounding per target (approximate and synthetic rows
first), changed responses and effects with field diffs, errors, resources,
and samples with `kronik trace` hints. Deterministic like the JSON.

## 6. Sampling

`propose --sample 10%` replays a deterministic, stratified sample in
isolated mode. Strata: (actor kind, input) as in §5.2. In each stratum the
root inputs are ordered by `blake3(proposal_id + root id)` and the first
`ceil(p × n)` are taken (at least one per stratum). The same proposal always
samples the same inputs; `summary.sample` shows the coverage. Continuous
replay always covers all root inputs.

## 7. Policy interface (self-contained)

This section is the contract for `kronik-policy`.

- **Input**: the diff JSON of §5 as a `serde_json::Value`, bound to the
  variable `diff`. JSON integers are CEL `int`, other numbers `double`,
  strings `string`, booleans `bool`, arrays `list`, objects `map`. Integers
  and doubles must compare numerically with each other (`diff.summary.sample
  < 1` and `diff.errors.introduced > 0.0` both work).
- **Rules** (TOML, `kronik policy set rules.toml`):

  ```toml
  [[rule]]
  name = "payments-must-be-exact"      # unique, [a-z0-9-]+
  when = "diff.grounding.exists(t, t.host.endsWith('payments.internal') && t.approximate + t.synthetic > 0)"
  action = "require_approval"         # allow | require_approval | deny
  ```

  Unknown keys and duplicate names are parse errors.
- **CEL subset that must work**: literals, field selection, indexing,
  `== != < <= > >=`, `&& || !`, `+ - * /`, `in`, `size()`,
  `.exists(x, p)`, `.all(x, p)`, `.exists_one(x, p)`, `.filter(x, p)`,
  `.map(x, e)`, `.startsWith()`, `.endsWith()`, `.contains()`,
  `.matches()`, `has()`.
- **Outcome**: the strictest action among the rules whose expression is
  true (`allow < require_approval < deny`); `allow` when none fire. A rule
  whose expression fails to evaluate (missing field, type error) counts as
  firing with at least `require_approval` and is listed in `errors`.
- **API** (Rust):

  ```rust
  pub enum Action { Allow, RequireApproval, Deny }          // Ord: Allow < RequireApproval < Deny
  pub struct Rule { pub name: String, pub when: String, pub action: Action }
  pub struct RuleSet { pub rules: Vec<Rule> }
  pub struct Fired { pub name: String, pub action: Action }
  pub struct RuleError { pub name: String, pub message: String }
  pub struct Evaluation { pub outcome: Action, pub fired: Vec<Fired>, pub errors: Vec<RuleError> }
  impl RuleSet {
      pub fn parse_toml(text: &str) -> Result<RuleSet, PolicyError>;
      pub fn defaults() -> RuleSet;                          // the brief's six rules, verbatim
      pub fn evaluate(&self, diff: &serde_json::Value) -> Evaluation;  // pure; fired in rule order
  }
  ```

  `PolicyError` carries the rule name and a message (stable code
  `BAD_REQUEST` at the API).
- **Default rules** (when no `Policy` record exists): `no-new-errors`
  (deny), `no-new-orphans` (require_approval), `low-grounding-needs-approval`
  (require_approval), `payments-must-be-exact` (require_approval),
  `payments-full-coverage` (deny), `fuel-regression` (deny), exactly as in
  the brief. Next to any rule set, a floor in code: `pii-masked-needs-approval`
  (require_approval) fires when `summary.pii_masked + summary.pii_unverified
  > 0` (ADR 0031).
- **JSON rendering of an evaluation**: `{"outcome": "allow" |
  "require_approval" | "deny", "fired": [{"name", "action", "reason"?}],
  "errors": [{"name", "message"}]}`; only the floor has a `reason`.
- **Fields the default rules read**: `diff.errors.introduced` (int),
  `diff.errors.new_orphans` (int), `diff.summary.confidence` (double),
  `diff.summary.sample` (double), `diff.grounding[*].host` (string),
  `diff.grounding[*].approximate` and `.synthetic` (int),
  `diff.resources.fuel_p99_change` (double).
- **Test fixtures**: `docs/design/fixtures/diff-*.json` (identity,
  counter +2, approximate payments, sampled payments, introduced error)
  are committed with this design; for each, the expected default-rule
  outcome is in its `"expected_policy"` field (removed before evaluation).
- **As built (M11): guards.** A rules file may also hold `[[guard]]`
  tables (`name`, `when`, `action = "alert" | "rollback"`), evaluated by
  `kronik watch` with the variable `guard` instead of `diff`
  (`RuleSet::guards`, `RuleSet::evaluate_guards(&Value) -> GuardEvaluation
  { fired, errors }`; an erroring guard does not fire and is listed in
  `errors`; a guard naming `diff` is refused; a `guard` key, even
  `guard = []`, replaces the default guards). Rule evaluation ignores
  guards. Contract: `docs/design/m11-watch.md` §2.

## 8. Proposals, approval, promote, rollback

- **`propose`** (`wasm` per kind, `window` default 1 h of logical time
  back from HEAD or `at <lsn>`, `mode` default `both`, `sample` default
  100 %, noise filters, stub rules; components whose code main already runs
  are skipped, M9): creates the fork `p-<12 hex>` at the
  fork point, writes a `Deployment` (cause `DEPLOY`) with the new code in
  the fork's log, runs replay over `(fork_lsn, HEAD]`, writes the diff and
  evaluates the policy. Its state lives in the fork (BranchCreated with
  `proposal_id`, diff file) and in main's `state.db` table `proposals (id,
  fork, status, verified_through_lsn, diff_hash, policy, created_lsn)`
  rebuilt from the fork directories at startup.
- **`approve`** writes `Approval {proposal_id, diff_hash,
  verified_through_lsn, audit}` in main's log. An approval holds for the
  diff (hash) it was given for.
- **`promote`**:
  1. Catch-up: continuous replay continues from `verified_through_lsn` to
     HEAD in rounds until the gap is at most `promote.max_gap` (2 s of
     logical time between HEAD's last root input and
     `verified_through_lsn`'s). New root inputs keep arriving meanwhile;
     main is not paused. Not converged within `promote.catch_up_timeout`
     (5 min), or the fork point is outside retention: `PROPOSAL_STALE`.
  2. The policy is evaluated again on the whole diff (isolated part plus
     catch-up). If the outcome is `deny`: refused with `POLICY_DENIED`. If
     it is `require_approval` and there is no approval for this diff's
     hash, or the outcome is stricter than when approved, or targets changed
     that were unchanged when approved: refused with `APPROVAL_REQUIRED`.
  3. The switch: a `Deployment {epoch: next, kinds: the fork's code,
     effective_lsn: 0 (= its own LSN), verified_through_lsn,
     unverified_inputs: root inputs in (verified_through_lsn,
     effective_lsn), cause: PROMOTE, proposal_id, audit}`. Turns that start
     after it run the new code; running turns finish with the old. Under
     the deploy lock, each kind the proposal changes must still run on main
     the code main ran for it when the proposal was made (`created_lsn`,
     fixed: not the fork point, which a window often places before a
     promote the proposal was made after, and not the verified point, which
     catch-up moves outside the deploy lock; or main already runs the
     proposed code); else another promote or rollback changed it since, and promote
     refuses with `PROPOSAL_STALE` instead of overwriting it (also on
     `--dry-run`).
  4. Migrations run as each actor's first turn under the new code (as
     replayed in the fork).
- **`rollback <epoch>`**: a new `Deployment` (cause `ROLLBACK`,
  `rollback_of_epoch`) whose kinds are those in force *before* that epoch.
  If any kind's schema version would go down: `ROLLBACK_SCHEMA_CHANGED`.
  From M13, `rollback <epoch> --by-replay` rolls back across a schema
  change by replay instead ([m13-rebase.md](m13-rebase.md)).
- New error codes: `PROPOSAL_NOT_FOUND` (404), `POLICY_DENIED` and
  `APPROVAL_REQUIRED` (exist), `PROPOSAL_STALE` (exists),
  `ROLLBACK_SCHEMA_CHANGED` (exists), `FORK_NOT_FOUND` (exists),
  `DEPLOYMENT_NOT_FOUND` (404).

## 9. API (`/v1`, conventions as in m1-core §4)

| Method and path | Request | Response |
| --- | --- | --- |
| `POST /v1/forks` | `{"at": 1200 \| "now" \| "2026-10-25T10:00:00Z", "name": null, "no_pii": false, "reason", "dry_run"}` | `{"dry_run", "fork": {"name", "fork_lsn", "no_pii", "proposal_id": null}}` |
| `GET /v1/forks` | | `{"forks": [{"name", "fork_lsn", "head_lsn", "proposal_id", "verified_through_lsn"}]}` |
| `DELETE /v1/forks/{name}` | `{"reason", "dry_run"}` | `{"dry_run", "deleted": "<name>"}` |
| `POST /v1/forks/{name}/deployments` | `{"wasm_base64", "reason", "dry_run"}` | as `POST /v1/deployments`, in the fork (allowed over history) |
| `POST /v1/forks/{name}/replay` | `{"to_lsn": null, "mode": "both", "sample": 1.0, "ignore_headers": [], "ignore_json_paths": [], "threads": null, "reason"}` | `{"fork", "summary": {§5.1}, "diff_hash"}` |
| `GET /v1/forks/{name}/diff?format=json\|md` | | the diff (§5) or Markdown (`text/markdown`) |
| `POST /v1/proposals` | `{"wasm_base64": ["…"], "window_ms": 3600000, "at": null, "mode": "both", "sample": 1.0, "ignore_headers": [], "ignore_json_paths": [], "reason", "dry_run"}` | `{"dry_run", "proposal": {"id", "fork", "status", "verified_through_lsn", "diff_hash", "policy": {§7}, "summary": {§5.1}}}` |
| `GET /v1/proposals` | | `{"proposals": [{"id", "fork", "status", "verified_through_lsn", "policy": {"outcome"}}]}` |
| `GET /v1/proposals/{id}` | | the proposal object |
| `GET /v1/proposals/{id}/diff?format=json\|md` | | the diff or Markdown |
| `POST /v1/proposals/{id}/approve` | `{"reason", "dry_run"}` | `{"dry_run", "approval": {"proposal_id", "diff_hash", "verified_through_lsn", "lsn"}}` |
| `POST /v1/proposals/{id}/promote` | `{"reason", "dry_run"}` | `{"dry_run", "deployment": {"epoch", "lsn", "effective_lsn", "verified_through_lsn", "unverified_inputs", "kinds": [...]}, "policy": {§7}}` |
| `POST /v1/deployments/{epoch}/rollback` | `{"reason", "dry_run"}` | `{"dry_run", "deployment": {...}}` |
| `GET /v1/policy` | | `{"rules_toml", "epoch", "default": bool}` |
| `PUT /v1/policy` | `{"rules_toml", "reason", "dry_run"}` | `{"dry_run", "epoch", "lsn"}` |
| `POST /v1/policy/test` | `{"rules_toml", "proposal"}` | the evaluation (§7) |
| `GET /v1/turns/{id}/trace` | | `{"turn": {…}, "root": {"lsn", "root_id", "input"}, "ancestors": [{…}], "descendants": [{"turn_id", "actor", "input", "outcome", "children": [...]}]}` |
| `POST /v1/forks/{name}/actors/{kind}/{key}/messages` | as `POST /v1/actors/{kind}/{key}/messages` | `{"fork", "turn_id", "outcome", "reply", "effects": [{"kind", "target", "status", …}]}` |
| `POST /v1/proposals/{id}/request-approval` | `{"reason", "dry_run"}` | `{"dry_run", "request": {"proposal_id", "diff_hash", "verified_through_lsn", "lsn", "command"}}` |

Proposal `status`: `evaluated`, `approved`, `promoted`, `rejected`
(policy deny), `stale`.

- **Trace** (`kronik trace`, MCP `trace_turn`): the causal tree of a turn,
  up to its root input and down to everything it caused (at most 1000
  descendants). `state.db` keeps `trees (root, lsn)` from every applied
  `TurnRecord`, so a trace reads only the tree's records. Fork turns
  trace too: `<fork>:<lsn>` from the fork's log, `<fork>:r<root>.<n>` from
  `branches/<fork>/isolated.jsonl`, where every isolated tree the diff
  names (samples, causes, changed responses, effects, errors) is persisted
  with the diff, so the diff's turn ids survive a restart.
- **Send to a fork** (MCP `send_to_fork`): a message into an actor of a
  fork, run under the fork's code on the fork's continuous store with the
  replay gate: no recording matches, so every external effect is synthetic
  (`denied("replay: no recording")`, I7) and calls run in the fork. The
  root id is drawn from the entropy source like any root input. The turn
  becomes part of the fork's live state; a later replay of the fork starts
  again from the fork point.
- **Request approval** (MCP `request_approval`): an `Approval` record
  with `request: true` and `command` (additive fields) in main's log
  (history, I5): nothing is approved; `command` is the exact command for the
  human (`kronik approve <id> --reason '...'`). A request is pending until
  an `Approval` without `request` for the same proposal follows it.
  `GET /v1/proposals/{id}` lists `approval_requests` with `pending`.
- **Caller identity and scopes** (for M5 tokens and the MCP server):
  `Api::handle` resolves every request to a `Caller {token_id, scopes}`
  through an `Authenticator` (today the local socket's caller,
  `unix:uid=<n>`, has every scope) and checks `required_scope(method,
  path)` before routing (`SCOPE_MISSING`, 403). The table: `GET` and
  `POST /v1/policy/test` need `read`; forks (create, deploy, replay,
  messages, delete) `fork`; `POST /v1/proposals` and request-approval
  `propose`; approve `approve`; promote, rollback and deploy on main
  `promote`; `PUT /v1/policy` `admin`; everything else (grants, limits,
  secrets, messages and resends on main) `operate`. `admin` implies every
  scope. M5 adds a token store with `Api::with_authenticator` without
  touching handlers (`crates/kronik-api/src/auth.rs`).

## 10. Testing and performance

- Identity replay of 10 000 recorded requests: empty diff, isolated and
  continuous. Counter `+2`: changed responses and state for every touched
  actor, 0 synthetic. Approximate effects (changed request body to a granted
  target): approximate grounding, confidence < 1, per-target grounding.
  Isolation: an early change does not leak into later root inputs; diffs
  byte-identical at 1, 4 and 16 workers. Causal grouping: one origin with
  1 000 consequences. Continuous drift in `cumulative`. Sampling: same
  sample twice; `payments-full-coverage` stops promote under a sample.
  Same fork and code twice: identical bytes. Promote with catch-up, a
  catch-up that finds a new error stops promote, rollback restores
  behaviour. `demo/verify-change.sh` end to end.
- **Speed**: replay of the reference workload (the counter workload of
  `docs/perf.md`) at ≥ 20× real time on the test VPS, measured as
  production wall time of the window divided by replay wall time, recorded
  in `docs/perf.md`.

## 11. As built (M3 implementation notes)

Where the implementation settles details this design left open, or
differs from it:

- **Proposal state** lives in `branches/<id>/proposal.json` and
  `branches/<id>/diff.json`, read back at startup into memory (the planned
  `proposals` table in `state.db` would only duplicate them). Plain forks
  use the same files with `plain_fork: true`.
- **Fork logs** hold the fork's continuous history: `BranchCreated` and
  the fork's `Deployment` at `fork_lsn + 1` and `+ 2`, then every
  continuous turn (and messages sent into the fork) at the LSN it was
  applied at in the fork's store, so `<fork>:<lsn>` ids are the log's.
  Catch-up appends; a new replay of a fork rewrites its log. `GET
  /v1/turns/<fork>:<lsn>` reads them. Isolated turns
  (`<fork>:r<root>.<n>`) exist only in the diff's samples and in memory.
  Isolated trees the diff names are kept in `isolated.jsonl` (see Trace,
  §9). **Promote after a restart**: the catch-up state (every isolated
  tree and the continuous fork) is in memory only, so the first promote
  after a restart replays `(fork_lsn, verified_through_lsn]` again before
  catching up. Replay is deterministic, so this gives the same trees and
  diff as before the restart; it costs one replay of the window.
- **Lists in the diff are capped** at 200 items (responses, effects, state
  entries, cumulative), 20 per sample category and error kind, 5 samples
  per cause; the counts always cover everything. Body diff operations come
  in document order (object keys sorted, then array indices). Typed objects
  keep the key order listed in §5; free-form objects (state values, SQL
  rows) have sorted keys.
- **Failure** in errors and orphans means any outcome but committed
  (rejected, failed, trap, fuel, memory, outcome unknown).
- **`cumulative`** lists actors whose final state differs in continuous
  replay and whose isolated trees changed them in no root input or in two
  or more (drift across inputs); with continuous replay alone, every actor
  whose final state differs.
- **Approvals across catch-up**: an approval holds for the diff it was
  given for, and also for a later diff (after catch-up) whose outcome is
  not stricter and whose changed targets (approximate or synthetic
  grounding rows, changed effects) were all changed when approved.
- **Both modes**: continuous replay runs on its own task next to the
  isolated workers (one fewer isolated worker).
- **Stub rules** come with a replay or proposal (`stubs` in the request:
  `[{"method", "url_prefix", "status", "headers", "body"}]` or `{...,
  "error": "network" | "timeout" | "too-large" | "denied"}`), are checked
  in order for an effect without a recording, count as synthetic, and are
  recorded in the diff's `options.stubs`.
- **`[fork] live_allowlist`** (kronik.toml): an effect without a
  recording that is a `GET` without secret headers to a listed host goes
  out live from the fork (grounding `live`, a fourth count next to exact,
  approximate and synthetic in `summary` and `grounding`; `confidence =
  exact / (exact + approximate + synthetic + live)`). Anything else, POSTs
  and `foreign://` included, never leaves (stub or `FailClosed`). The hosts
  in force are recorded in `options.live_allowlist`.
- **`--no-pii`** is accepted on fork create and propose and recorded in
  `options.no_pii` and `BranchCreated.no_pii`; until privacy mode (M8)
  nothing is sealed, so it changes no value.
- **Codes**: unknown proposals answer `PROPOSAL_NOT_FOUND`, unknown epochs
  `DEPLOYMENT_NOT_FOUND`.
- **Preview inputs (M11)**: a preview fork's requests run under causal
  roots starting with `preview-`. The diff lifts their turns out of the
  comparison before §4 runs: they count in `summary.preview_inputs` and
  `samples.preview` (the root turns, with method, route pattern, HTTP
  status and outcome), never in `turns_fork`, divergence, causes, effects,
  grounding or errors; their writes show in `state.continuous` like any
  continuous turn's. The Markdown adds a "Preview inputs" summary row
  (counts only, also in `--summary`) and a section listing them. See
  [M11 previews](m11-preview.md).
