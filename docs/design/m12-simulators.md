# M12 effect simulators

Status: binding for M12. Builds on `m2-effects.md`, `m3-fork.md` (§3.5
matching, §5.3 grounding, §7 policy) and `m8-privacy.md`; brief sections
"v0.3: Rikare replay" → M12 (SPEC: "v0.3: Richer replay"), "Effekter och
capabilities" (the `EffectSimulator` trait), "Forks, replay och
beteendediff" (the three matching levels) and invariants I5, I7, I8 and I9.
ADRs 0014, 0015 and 0016 record the choices this document relies on.

Until M12, an effect a fork makes without a recorded counterpart is either
answered by a stub rule the replay request carried, sent live to a host in
`[fork] live_allowlist`, or denied by `FailClosed`. M12 adds three
simulators that give such an effect a plausible answer, labels every
synthetic answer with the simulator that gave it, and lets the policy refuse
them per target.

## 1. Crates

| Crate | M12 adds |
| --- | --- |
| `kronik-proto` | The `SimulatorConfig` record (kind 15) and `EffectRecord.simulator`. |
| `kronik-effects` | `ContractFake` (OpenAPI → schema-valid JSON, deterministic by fingerprint) and `RecordedNeighbor` (the most similar recorded request to the same route), both `EffectSimulator`s; simulator configuration per target in `Config`. |
| `kronik-store` | `SimulatorConfig` records go into `config_records` like grants. |
| `kronik-sched` | `Node::set_simulators` (under the deploy lock, through `commit_config`). |
| `kronik-fork` | The per-replay `Simulators` (configuration as of the fork point plus the request's overrides), the `ModelSimulator` (an HTTP client of an OpenAI-compatible endpoint, with the per-proposal cache), the new order in the replay gate, labels and per-simulator counts in the diff. |
| `kronik-api` | `GET /v1/simulators`, `PUT /v1/simulators/{target}`; `simulator_overrides` in replay options; `grounding` and `simulator` on the effect summaries of fork turns (`GET /v1/turns/<fork>:<lsn>`, `trace`). |
| `kronik` | `kronik stubs set <target> <rules.toml>`, `kronik simulators list`; `[simulators.model]` in `kronik.toml`. |

## 2. Configuration is history (I5, ADR 0014)

`kronik stubs set` writes one `SimulatorConfig` record for one target at the
next configuration epoch, with an `Audit` (token, reason, wall time):

| Field | Meaning |
| --- | --- |
| `target` | `http:<host>` or `foreign:<name>`: the capability target, exact host (no wildcards). |
| `stubs` | Stub rules for the target, in order: `method` (optional), `url_prefix` (must start with `http://<host>` or `https://<host>` of the target, or `foreign://<name>`), `status`, `headers`, `body`, or `error` (`network`, `timeout`, `too-large`, `denied`). |
| `contract` | An OpenAPI 3 document as JSON, or empty: the JSON value the API received, serialized compactly (not the file's bytes; at most 1 MiB). Its digest (`b3:` + hex) is BLAKE3 of those bytes, so it differs from a hash of the file. |
| `neighbor` | `RecordedNeighbor` on for the target. |
| `model` | `ModelSimulator` allowed for the target. |

A record replaces the target's whole configuration; a record with no stubs,
no contract, `neighbor` and `model` false clears it. `GET /v1/simulators`
shows each target's configuration in force with its record's LSN, epoch and
reason; earlier records stay in the log (`kronik history` is per actor and
does not list them).

**Which configuration a replay uses (I5).** A replay uses main's simulator
configuration as of its **fork point**, like grants and limits, plus the
`simulator_overrides` its request carries: a list of `{"target", "stubs",
"contract", "neighbor", "model"}` (the fields of `PUT
/v1/simulators/{target}`, validated the same way, one entry per target),
each replacing main's configuration of its target for that fork, except
that an override's `model` is ANDed with main's at the fork point: whether
a target's recorded exchanges may go to the model endpoint is the
operator's decision (ADR 0015), so a `fork` or `propose` caller can turn
the model off for a target, never on. `kronik
replay` and `kronik propose` take them as `--simulators TARGET=FILE` (the
rules file of `kronik stubs set`). The overrides are kept in the fork's
options (`proposal.json`), so catch-up (which extends the window) and the
replay after a restart use exactly the same configuration; configuration
main sets after the fork point never applies to the fork. To apply new
configuration to an existing window, replay or propose again with
overrides, or propose again after `kronik stubs set`. The diff records the
overrides in `options.simulator_overrides` and the configuration it used in
`options.simulators` (target, epoch, LSN, number of stubs, contract
digest, neighbor, model, and `request: true` with epoch and LSN 0 for an
override).

## 3. Where an effect's answer comes from

For an external effect of a fork turn (`http.fetch`, `foreign.http`), in
order; the first that answers wins:

1. **Exact** (recorded at the same causal key, ordinal, kind, fingerprint).
2. **Approximate** (same causal key, ordinal, kind, target).
3. **Stub rules of the replay request** (`stubs` in a replay or proposal,
   as in M3): label `stub`.
4. **Stub rules of the target** (`SimulatorConfig.stubs`): label `stub`.
5. **Live** (`[fork] live_allowlist`: a GET without secret headers to a
   listed host): grounding `live`, not synthetic.
6. **ContractFake** (target has a contract): label `contract`.
7. **RecordedNeighbor** (target has `neighbor`): label `neighbor`.
8. **ModelSimulator** (target has `model` and the server has
   `[simulators.model]`): label `model`.
9. **FailClosed**: the guest gets `denied("replay: no recording")`; label
   `fail-closed`.

Steps 3 to 9 are synthetic grounding (`GROUNDING_SYNTHETIC`), and the turn
is divergent as before. Crypto keeps its M3 behavior (exact by fingerprint
or recomputed on the host). `secret.reveal` in a fork answers the
placeholder `[secret:<name>]`, never the value (v0.1): exact where
production revealed at that point, else synthetic with the label
`placeholder`, so every synthetic answer has a label. `actor.call` is
re-executed. A simulator that cannot answer (no matching operation in the
contract, no neighbor, the model declines) passes to the next step.

`EffectRecord.simulator` carries the label of a synthetic answer; it is
empty for every other grounding. Fork turns are written to the fork's log
with it, so `trace` and `GET /v1/turns/<fork>:<lsn>` show it.

### 3.1 ContractFake (ADR 0016)

- The document is OpenAPI 3.0 or 3.1 JSON. `paths` keys are templates
  (`/v1/charges/{id}`); a request path matches a template when the segment
  counts are equal and every literal segment is equal; among several, the
  one with the most literal segments wins, then the lexicographically
  smallest template. A `servers[0].url` path prefix is stripped first.
- The operation is the path item's lower-case method. Its response is the
  lowest 2xx code with an `application/json` schema (else `default`); the
  status is that code (200 for `default` or `2XX`).
- The body is generated from the schema, resolving `$ref` to
  `#/components/schemas/...` (depth at most 16): `enum` and `const` pick a
  value; `type` `object` fills every property in name order (required ones
  and optional ones alike, except an optional property that refers back to
  a `$ref` being generated) and gives a `required` name without a property
  schema an empty object, `array` gives `minItems` items, or one when
  `minItems` is absent or 0 (none when `maxItems` is 0 or the items refer
  back to a `$ref` being generated), `string` honors `format` (`date-time`,
  `date`, `uuid`, `email`, `uri`) and `minLength`/`maxLength`,
  `integer`/`number` stay within `minimum`/`maximum` (0 to 1000 without
  either; up to 1000 below a negative `maximum` alone), `boolean`;
  `oneOf`/`anyOf` take the first branch, `allOf` merges object branches.
- Bounds: at most 10 000 values and 1 MiB per answer (strings, keys,
  scalars, and `const`/`enum` values at their serialized size, so a large
  `const` repeated by `minItems` cannot allocate more), and strings of at
  most 4096 characters. A schema that cannot be satisfied within them (required
  recursion past depth 16, a formatted string that does not fit its length
  bounds, `minimum` above `maximum`, `minLength` above `maxLength`) gives no
  answer rather than an invalid one. Choices come from a stream keyed
  by BLAKE3 of `"kronik.contract.v1"`, the target and the request
  fingerprint, so the same request always gets the same bytes.
- Headers: `content-type: application/json`.
- An operation without a usable response, or a path without a match, is no
  answer.

### 3.2 RecordedNeighbor

Candidates are the production effects of the replay's index (base snapshot
excluded: its effects are not indexed) with the same kind, method, host and
route pattern as the request, a plain request and a plain response, status
OK. The score of a candidate is the number of equal items between the two
requests' item sets: path segments by position, query parameters (name,
value), and the JSON body's leaves (path, value), or the body's hash when it
is not JSON. The highest score wins, then the highest LSN, then the lowest
ordinal. The answer is the candidate's recorded response.

### 3.3 ModelSimulator (ADR 0015)

Off by default. It answers only when the target's record has `model` and
`kronik.toml` has:

```toml
[simulators.model]
endpoint = "http://127.0.0.1:11434/v1/chat/completions"  # OpenAI-compatible
model = "llama3.1"
api_key_env = "KRONIK_MODEL_API_KEY"   # optional: the variable holding the key
timeout = "20s"
max_examples = 5
```

- **What it sends**: one chat completion request (`temperature` 0) with a
  system message describing the task and the reply format (a JSON object
  `{"status", "headers", "body"}`), and a user message with up to
  `max_examples` recorded exchanges with the target (the most recent first;
  of each response only its status, `content-type` and body) and the
  request: method, URL without credentials, text headers other than
  `authorization`, `cookie`, `proxy-authorization` and `x-api-key`, and the
  body as text.
- **What it never sends** (the M12 criterion, tested): a value with a
  subject, sealed or plain, and no secret. Recorded exchanges qualify only
  from production turns that show no subject or sealed value anywhere
  (input, effects, writes, messages, timers, reply) and ran no SQL, and
  only when their request and response are `plain` with no subject and the
  request has no secret header. A production turn's state reads are not
  recorded, so a turn without a subject may have copied personal data into
  an untagged request: while privacy mode is on now or was on in the
  replay's window, no recorded exchange is sent at all unless
  `[simulators.model] examples_under_privacy = true`. The request itself
  qualifies only when the turn has seen no subject and no secret: the
  effect's request has no subject (the guest's default subject is unset),
  the root input has none, the turn has read no state value, effect result
  or `actor.call` reply with a subject (the fork records call requests and
  replies with their subjects, as production does), has revealed or used no
  secret, and has run no SQL statement; and neither has any turn it took
  data from: a turn that saw personal data marks its messages, timers and
  call replies (`ForkTurn::personal`), so a callee's tagged state or SQL
  rows keep the caller's request away from the model too. Otherwise the
  simulator declines and the next step answers. Secret headers are never in
  a request the gate builds (I8: they are `SecretRef`s by name), and the
  model client refuses a request with one. Headers that
  `kronik_core::http::credential_header` names (authorization, cookies,
  api keys, session ids, `*-token`, `*-secret`, ...) are left out of the
  request and the examples. A request or example whose raw URL, text
  header values or body (before encoding or truncation) holds the value of
  any secret in the store is refused or left out, and secret values in an
  answer are replaced by `[secret:<name>]` before it is cached. Privacy
  mode counts when it is on now, was on at the fork point, or changed in
  the window.
- **Cache**: answers are cached per proposal (each proposal and plain fork
  has one) and per (target, fingerprint) in
  `branches/<id>/simulator-cache.json`; a failure or a refusal is cached as
  a refusal. Concurrent workers asking for the same key share one call.
  Replaying the same proposal again, and promote's catch-up, read the cache
  first, so the same proposal run twice gives byte-identical diffs. The
  cache is written durably (synced file, rename, directory sync) after each
  replay, catch-up round and message into the fork; a cache file that does
  not parse fails the replay. Deleting the fork deletes the cache.
- **Dry runs** (`propose --dry-run`, `promote --dry-run`) never call the
  model and write nothing (I12): the model answers from the saved cache
  only, and a miss is a refusal (the next step answers, often
  `fail-closed`). `promote --dry-run` replays and catches up on its own
  state and leaves the proposal, its fork log and its cache as they were.

## 4. The diff (`kronik.diff/v1`, additive)

- `effects.items[*].grounding` keeps its v0.1 values (`exact`,
  `approximate`, `synthetic`, `live`); a new field
  `effects.items[*].simulator` names the simulator of a `synthetic` item
  (`stub`, `contract`, `neighbor`, `model`, `fail-closed`, `placeholder`) and is absent
  otherwise. Diffs and rules written for v0.1 (`grounding == 'synthetic'`)
  keep working. The turn JSON's effects have the same pair: `grounding`
  (`exact`, `approximate`, `synthetic`; absent for production and live
  effects) and `simulator` (absent for a fork turn recorded before M12).
- `grounding[*].synthetic_by`: counts per simulator (`{"contract": 2,
  "fail-closed": 1}`), omitted when empty. `synthetic` stays the total.
- `summary.synthetic_by`: the same over all targets, omitted when empty.
- `options.simulators`: the configuration the replay used (§2), omitted when
  empty; `options.simulator_overrides`: the request's overrides, omitted
  when empty.

The Markdown rendering shows the per-simulator counts next to each target.

## 5. Policy per target

The policy reads the diff (m3-fork §7), so it can forbid synthetic answers
per target and per simulator:

```toml
[[rule]]
name = "payments-no-synthetic"
when = "diff.grounding.exists(t, t.host == 'payments.internal' && t.synthetic > 0)"
action = "deny"

[[rule]]
name = "no-model-for-ledger"
when = "diff.grounding.exists(t, t.host == 'ledger.internal' && has(t.synthetic_by) && has(t.synthetic_by.model))"
action = "deny"
```

The default rules are unchanged (`payments-must-be-exact` already counts
synthetic answers).

## 6. API and CLI

- `GET /v1/simulators` → `{"simulators": [{"name", "grounding": "recorded" |
  "synthetic", "description"}], "targets": [{"target", "stubs", "contract":
  {"title", "digest", "bytes"} | null, "neighbor", "model", "epoch", "lsn",
  "reason"}],
  "model": {"configured", "endpoint_host", "model"}}`.
- `PUT /v1/simulators/{target}` with `{"stubs": [...], "contract": <OpenAPI
  JSON object> | null, "neighbor", "model", "reason", "dry_run"}` →
  `{"target", "epoch", "lsn", "dry_run"}`. Validation errors are
  `BAD_REQUEST`. It needs the `operate` scope, as grants do.
- `kronik stubs set <target> <rules.toml> [--reason] [--dry-run] [--json]`:

  ```toml
  [[stub]]                       # zero or more, in order
  method = "GET"
  url_prefix = "https://payments.internal/v1/charges/"
  status = 200
  headers = [["content-type", "application/json"]]
  body = '{"id": "ch_1", "status": "succeeded"}'

  contract = "payments.openapi.json"   # relative to the rules file
  neighbor = true
  model = false
  ```

  An empty file clears the target. Unknown keys are errors.
- `kronik simulators list [--json]` prints the simulators and each target's
  configuration.

## 7. Tests (the M12 criteria)

| Criterion | Test |
| --- | --- |
| Every synthetic answer is labeled with its simulator in the diff and in `trace` | `kronik-fork` `simulators_label_every_synthetic_answer` (one fork replayed with fail-closed, contract, target stub and request stub answers: effect items keep `grounding: synthetic` with `simulator`, grounding rows, `summary.synthetic_by`, `options.simulators`, the fork log's records); `kronik-api` `trace_shows_simulator_labels` (trace of a fork turn; production turns carry no label; configuration set after the fork point does not apply). The neighbor is covered by the `kronik-effects` unit test. A v0.1 diff with a plain `synthetic` item (`docs/design/fixtures/diff-synthetic-v01.json`) still validates against the schema and gives its policy. |
| Configuration as of the fork point (I5) | `kronik-fork` `simulator_configuration_is_taken_at_the_fork_point` (a record after the fork point changes nothing, also over a longer window and after a restart; a fork after it sees it). |
| Contract fakes are schema-valid, and the same request always gets the same answer | `kronik-effects` contract tests (a validator for the subset, many requests, repeated generation); the replay test above checks the bytes of two runs. |
| The same proposal run twice with the model simulator gives a byte-identical diff | `kronik-fork` `model_answers_are_cached_per_proposal` (a local fake model server whose answers change on every call; a fork replayed again and after a restart; equal diff bytes; no second call). |
| The model simulator never sees sealed values | `kronik-fork` `model_never_sees_personal_data` (privacy on, turns on behalf of a subject and a plain turn with copied personal data: the subject's turns fail closed, the fake server's received bytes hold neither the subject's values, its id nor its requests, and the plain exchange is an example only with `examples_under_privacy`); `the_model_never_sees_or_caches_secret_values`; `fork_call_replies_keep_their_subject`; unit tests for turn-level taint and response headers. |
| A dry run calls no model and writes nothing | `kronik-fork` `a_dry_run_proposal_calls_no_model_and_writes_nothing`, `a_dry_run_promote_calls_no_model_and_writes_nothing`. |
| The policy can forbid synthetic answers per target | `kronik-fork` `policy_forbids_synthetic_answers_per_target`. |

Tests use a local fake model server, never a paid API.
