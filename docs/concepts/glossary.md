# Concepts

<!-- Generated from crates/kronik-core/src/explain.rs and
crates/kronik-core/explain/concepts/ by
`cargo run -p kronik-core --example concepts_md > docs/concepts/glossary.md`.
Edit those files, not this one; `scripts/ci.sh docs` checks it. -->

Kronik has five concepts of its own: [actor](#actor), [message](#message),
[effect](#effect), [hash](#hash) and [fork](#fork). The other terms on this
page are built from them. Code, docs and the CLI use every term exactly as it
is written here, and `kronik explain <term>` prints the same text in a
terminal.

Each term names the milestone that introduces it, and a definition marks
parts that come later with their own milestone, for example "(M3)". The
[introduction](../introduction.md#roadmap) lists the milestones.

| Term | Meaning | Milestone |
| --- | --- | --- |
| [`actor`](#actor) | An instance with its own state, identified by kind/key | M1 |
| [`kind`](#kind) | An actor type: the code for one sort of actor | M1 |
| [`message`](#message) | Data sent to an actor: name, content type and body | M1 |
| [`effect`](#effect) | A call from guest code to the outside world, via the host | M2 |
| [`hash`](#hash) | The BLAKE3 hash of a component: the identity of its code | M1 |
| [`fork`](#fork) | A branch of the system's history from an LSN | M3 |
| [`turn`](#turn) | One execution of an actor's handle for one input | M1 |
| [`turn-id`](#turn-id) | The branch and LSN of a turn's turn record | M1 |
| [`lsn`](#lsn) | The log sequence number of a log record | M1 |
| [`branch`](#branch) | main or a fork, each with its own log and state | M1 |
| [`root-input`](#root-input) | An input from outside: HTTP, an operator message or a timer | M1 |
| [`causal-key`](#causal-key) | The root input's id plus the path to a turn | M1 |
| [`causal-id`](#causal-id) | A correlation id that is the same in production and replay | M1 |
| [`execution-id`](#execution-id) | The host's internal id for one execution of a turn | M1 |
| [`logical-time`](#logical-time) | The turn's time: constant, monotonic and recorded | M1 |
| [`deployment`](#deployment) | A log record that points actor types at code hashes | M1 |
| [`configuration-epoch`](#configuration-epoch) | A sequence number for system-wide configuration changes | M1 |
| [`proposal`](#proposal) | A fork with a diff: the result of kronik propose | M3 |
| [`behavior-diff`](#behavior-diff) | What changes in responses, effects, state, errors and resources | M3 |
| [`grounding`](#grounding) | How well a fork's effects rest on recordings | M3 |
| [`isolated-replay`](#isolated-replay) | Each root input replayed on production's state at its own LSN | M3 |
| [`continuous-replay`](#continuous-replay) | The fork evolves its own state under the new code | M3 |
| [`capability`](#capability) | Permission for an actor type to use an effect against a target | M2 |
| [`delivery-class`](#delivery-class) | How a target tolerates retries | M2 |
| [`secret-handle`](#secret-handle) | A secret referred to by name; the value never reaches the guest | M2 |
| [`sql-state`](#sql-state) | A SQLite database per actor, owned by the host | M1 |
| [`dead-letters`](#dead-letters) | Inputs whose turn failed, kept for inspection and resend | M1 |
| [`orphaned-change`](#orphaned-change) | A callee's committed change whose caller then failed | M2 |
| [`privacy-mode`](#privacy-mode) | The operator's GDPR switch for sealing personal data | M8 |
| [`subject`](#subject) | The person a value belongs to, such as user:123 | M1 |
| [`sealed-value`](#sealed-value) | A value encrypted with its subject's key | M8 |
| [`foreign-actor`](#foreign-actor) | A Linux binary in gVisor behind a recorded boundary | M7 |
| [`isolation-level`](#isolation-level) | How code is sandboxed: wasm, gvisor, trusted or microvm | M7 |
| [`snapshot`](#snapshot) | A consistent copy of materialized state at an LSN | M6 |
| [`segment`](#segment) | A log file; closed segments are immutable | M1 |

## actor

An instance with its own state, identified by kind/key. Milestone M1.

An actor is an instance of an actor type, identified by `kind/key`, for example `billing/acme`. It has its own state and handles one input at a time: an HTTP request, a message, a timer (from M2) or a migration, each in its own turn. Actors are Wasm components, and every turn runs in a fresh instance, so nothing in guest memory survives to the next turn (I3). Actor is one of Kronik's five concepts.

    kronik actors list
    kronik actors inspect billing/acme
    kronik history billing/acme

See also: [`kind`](#kind), [`turn`](#turn), [`message`](#message), [`foreign-actor`](#foreign-actor).

## kind

An actor type: the code for one sort of actor. Milestone M1.

An actor type, called kind in code and in actor ids, is the code for one sort of actor, for example `billing` in `billing/acme`. A deployment points each kind at a code hash. Its `describe` export returns the manifest: kind, schema version, routes and requested capabilities. Grants and limits (from M2) apply per kind, not per hash, so they carry over when the code changes.

A new kind without history is deployed directly; from M3, a kind with history changes through propose and promote:

    kronik deploy ./dist/billing.wasm --reason "first deploy"
    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"

See also: [`actor`](#actor), [`hash`](#hash), [`deployment`](#deployment).

## message

Data sent to an actor: name, content type and body. Milestone M1.

A message is data to an actor: `name`, `content-type` and `body`, plus a `blobs` list that stays empty until M26. It comes from another actor, the operator, a timer or HTTP. `send` is buffered and delivered exactly once, but only if the sending turn commits. `call` (from M2) happens immediately: the callee runs and commits a turn of its own, and its response is recorded in the caller's turn. `call` is not atomic with the caller's turn, so it can carry a compensation message. Docs recommend `send` for changes and `call` for queries. Message is one of Kronik's five concepts.

Once tokens arrive (M5), an operator message to main needs the `operate` scope:

    kronik send billing/acme <message> --reason "..."

See also: [`turn`](#turn), [`orphaned-change`](#orphaned-change), [`dead-letters`](#dead-letters).

## effect

A call from guest code to the outside world, via the host. Milestone M2.

An effect is a call from guest code to the outside world via the host, for example `http.fetch`, a call to a foreign actor (M7) or host-side cryptography with a secret. External effects require a capability (default deny, I6); internal ones, such as `call`, `send` and timers, do not. Every effect is recorded. External effects can happen before the turn commits and are not rolled back. In a fork (M3), effects are matched against recordings and never reach the outside world (I7). Effect is one of Kronik's five concepts.

See also: [`capability`](#capability), [`delivery-class`](#delivery-class), [`grounding`](#grounding), [`secret-handle`](#secret-handle).

## hash

The BLAKE3 hash of a component: the identity of its code. Milestone M1.

A hash is the BLAKE3 hash of a component's bytes and the identity of its code. It is shown as `b3:` plus 12 hex characters, for example `b3:4f1c09ab77e9`. A deployment points an actor type at a hash, every turn record carries the code hash, and from M3 a rollback switches back to the previous hash. Hash is one of Kronik's five concepts.

See also: [`kind`](#kind), [`deployment`](#deployment), [`proposal`](#proposal).

## fork

A branch of the system's history from an LSN. Milestone M3.

A fork is a branch of the system's history from an LSN, with its own state and its own log from there on. Its state is built from the nearest snapshot plus the log up to the fork point, and its configuration (deployments, grants, limits and policy) is the one at the fork point plus what changes in the fork. A fork makes no live effects (I7), unless the operator has allowlisted a target for forks in `fork.live_allowlist`. With `--no-pii` (M8), a fork has no access to the keys of sealed values. Fork is one of Kronik's five concepts.

    kronik fork create --at now --name try-1 --reason "try a fix"
    kronik fork list

See also: [`branch`](#branch), [`proposal`](#proposal), [`isolated-replay`](#isolated-replay), [`continuous-replay`](#continuous-replay).

## turn

One execution of an actor's handle for one input. Milestone M1.

A turn is one execution of an actor's `handle` for one input. It has an atomic local commit: state writes, SQL changes, `send`, timers (from M2) and blob references (from M26) are committed together or discarded together. External effects and `call` (from M2) can happen before commit and are not rolled back. Each actor runs one turn at a time, and nothing is applied, delivered or answered until the turn record is fsynced. A turn that traps, runs out of fuel or returns a `handler-error` writes a failed turn record; there is no automatic retry.

See also: [`turn-id`](#turn-id), [`logical-time`](#logical-time), [`execution-id`](#execution-id), [`dead-letters`](#dead-letters).

## turn-id

The branch and LSN of a turn's turn record. Milestone M1.

A turn id is `<branch>:<lsn>` of the turn's turn record, for example `main:1482331`. Other log records are identified the same way. From v0.4, with shards, the format becomes `<branch>:<shard>:<lsn>`, and old ids stay valid. The gateway returns the turn id of every request in the `Kronik-Turn-Id` header, and from M3 `kronik trace` shows a turn's causal tree.

    kronik history billing/acme
    kronik trace main:1482331

See also: [`lsn`](#lsn), [`branch`](#branch), [`turn`](#turn).

## lsn

The log sequence number of a log record. Milestone M1.

An LSN, log sequence number, numbers every log record, not only turn records; it is in each record's envelope. LSNs are strictly increasing per branch, and from v0.4 per branch and shard. A deployment takes effect at an LSN; from M3, a fork starts at an LSN and a proposal is verified through an LSN.

See also: [`turn-id`](#turn-id), [`segment`](#segment), [`branch`](#branch).

## branch

main or a fork, each with its own log and state. Milestone M1.

A branch is `main` or a fork (forks arrive with M3). A fork has its own log from its fork point, and every branch has its own materialized state, which is derived from the log (I4) and can always be rebuilt from it. Deployments, grants and limits (M2) and policy (M3) are records on a branch, so a branch's configuration is part of its history (I5).

See also: [`fork`](#fork), [`lsn`](#lsn), [`snapshot`](#snapshot).

## root-input

An input from outside: HTTP, an operator message or a timer. Milestone M1.

A root input is an input from outside: HTTP, an operator message or a timer (from M2) that existed before the fork point. From M3, replay runs main's root inputs through new code; internal messages are never taken from the recording but arise from the fork's code. Resending a dead letter creates a new root input, and a repeated HTTP request with the same `Idempotency-Key` for the same actor creates none.

See also: [`causal-key`](#causal-key), [`isolated-replay`](#isolated-replay), [`dead-letters`](#dead-letters).

## causal-key

The root input's id plus the path to a turn. Milestone M1.

A causal key is the root input's id plus the path of actor and outgoing ordinal up to a turn. From M3 it pairs up turns in production and in a fork: a fork turn matches a production turn when their causal keys are equal, and a matched turn reuses the recorded logical time and seed. The causal id, message ids and, from M2, the idempotency keys of effects are derived from it.

See also: [`causal-id`](#causal-id), [`root-input`](#root-input), [`grounding`](#grounding).

## causal-id

A correlation id that is the same in production and replay. Milestone M1.

The causal id is derived from the causal key. It is the same in production and replay, and it is the id that guest code gets from `causal-id` when it needs a correlation id. The host adds it, together with the execution id, to every log event.

See also: [`causal-key`](#causal-key), [`execution-id`](#execution-id).

## execution-id

The host's internal id for one execution of a turn. Milestone M1.

The execution id is the host's internal id for one execution of a turn. It ties together the turn's `TurnBegin` and `EffectResult` records (written from M2) and its turn record, which the log interleaves with records of other actors. Guest code never sees it; it uses the causal id instead.

See also: [`causal-id`](#causal-id), [`turn`](#turn).

## logical-time

The turn's time: constant, monotonic and recorded. Milestone M1.

Logical time is the turn's time as the guest sees it via `now-ms`. It is constant within a turn, recorded, and never lower than the logical time of the message or timer that started the turn (I15). It is the largest of the host's clock at turn start, the largest logical time already handed out, and the logical time of the message or timer that started the turn. At startup the largest time in the log plus 1 ms seeds the second value, so neither a host clock that jumps backwards nor a restart moves time backwards (ADR 0006). Several turns may share a millisecond: unique ids come from the causal id or the turn id, not from `now-ms`. A matched turn in replay (M3) reuses the recorded logical time.

See also: [`turn`](#turn), [`causal-key`](#causal-key).

## deployment

A log record that points actor types at code hashes. Milestone M1.

A deployment is a log record saying that one or more actor types use certain hashes from a certain LSN, and it carries a configuration epoch, which names it. `kronik deploy` writes one for a new actor type without history. From M3, a kind with history goes the golden path of propose, review the diff and promote, and `kronik rollback` writes a new deployment that restores the code in force before a given one. Deployments are log records, so code changes are part of the history.

    kronik deployments list
    kronik rollback <epoch> --reason "..."

See also: [`hash`](#hash), [`configuration-epoch`](#configuration-epoch), [`proposal`](#proposal).

## configuration-epoch

A sequence number for system-wide configuration changes. Milestone M1.

The configuration epoch is a sequence number for system-wide configuration changes. Configuration records carry it: `Deployment`, from M2 `Grant` and `Limits`, and from M3 `Policy`. In v0.1 an epoch corresponds to an LSN; from v0.4 it corresponds to one LSN per shard, so that a change of several actor types still switches atomically.

See also: [`deployment`](#deployment), [`lsn`](#lsn).

## proposal

A fork with a diff: the result of kronik propose. Milestone M3.

A proposal is the result of `kronik propose`: a fork, a replay of real root inputs through the new code, a behavior diff and a policy outcome. It carries `verified_through_lsn`, the last LSN in main whose root inputs have run through its code. The policy lets it through, requires an approval (`kronik approve`) or denies it. `kronik promote` first runs catch-up on the traffic since the proposal, evaluates the policy again on the whole diff, and then switches the code. A proposal is a fork with a diff.

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"
    kronik diff show p-7h3k --md
    kronik approve p-7h3k --reason "..."
    kronik promote p-7h3k --reason "..."

See also: [`behavior-diff`](#behavior-diff), [`grounding`](#grounding), [`fork`](#fork).

## behavior-diff

What changes in responses, effects, state, errors and resources. Milestone M3.

The behavior diff is the difference in responses, effects, state, errors and resources between production and a fork for the same root inputs. It is written as JSON (`kronik.diff/v1`) and rendered as Markdown, origins first: an origin is the first turn in a causal tree that differs despite identical input, and differences further down the tree are its consequences. Identity replay, the same code through the same history, must always give an empty diff.

    kronik diff show p-7h3k --md

See also: [`grounding`](#grounding), [`isolated-replay`](#isolated-replay), [`continuous-replay`](#continuous-replay), [`proposal`](#proposal).

## grounding

How well a fork's effects rest on recordings. Milestone M3.

Grounding says how well a fork's effects rest on recordings. An effect is exact when causal key, ordinal, type and fingerprint match a recording; the recorded response is used. It is approximate when causal key, ordinal, type and target (method, host and route pattern) match but the request differs; the recorded response is reused, and the request difference is shown in the diff. It is synthetic when nothing matches: a stub rule answers, or `FailClosed` gives the guest `denied`, and the turn is marked divergent. Grounding is reported in total and per target, because thousands of exact calls can hide a few approximate payments, and policy judges it per target.

See also: [`behavior-diff`](#behavior-diff), [`effect`](#effect), [`proposal`](#proposal).

## isolated-replay

Each root input replayed on production's state at its own LSN. Milestone M3.

Isolated replay runs each root input against production's state at its own LSN, in an overlay that is discarded afterwards, so that a difference cannot contaminate the next root input. It is the default for the main part of the diff. Root inputs run in parallel, and the results are merged in LSN order. For large windows it can run on a deterministic sample, for example `--sample 10%`, and the coverage shows in the diff.

See also: [`continuous-replay`](#continuous-replay), [`behavior-diff`](#behavior-diff).

## continuous-replay

The fork evolves its own state under the new code. Milestone M3.

Continuous replay lets the fork evolve its own state under the new code, in production order, so that cumulative effects show up in the diff's `cumulative` part. It always runs on all root inputs, and it is the fork that catch-up continues at promote. `kronik propose --mode` selects `isolated`, `continuous` or `both`, the default.

See also: [`isolated-replay`](#isolated-replay), [`proposal`](#proposal).

## capability

Permission for an actor type to use an effect against a target. Milestone M2.

A capability is permission for an actor type to use an effect against a target, for example `http:api.stripe.com`, `http:*.example.com`, `foreign:payments` (M7), `secret:<name>` or `secret-reveal:<name>`. Every external effect is denied until the operator grants a capability (default deny, I6); without one, the guest gets `denied`. Grants are log records, apply per actor type rather than per hash, and give the target a delivery class and optionally a rate.

    kronik grant billing http:payments.internal --reason "billing charges invoices"

See also: [`delivery-class`](#delivery-class), [`effect`](#effect), [`CAPABILITY_NOT_GRANTED`](../errors.md#capability_not_granted).

## delivery-class

How a target tolerates retries. Milestone M2.

The delivery class says how a target tolerates retries, and it is set when the target is granted: `replay-safe` (the call can be redone without consequences), `idempotency-keyed` (the target respects `Idempotency-Key`) or `unsafe`. After a crash without a recorded result, the first two are redone with the same idempotency key, and an `unsafe` effect is not: the guest gets `outcome-unknown` (I17). The default is `replay-safe` for GET, HEAD and OPTIONS and `unsafe` for everything else. The class is the operator's claim about the target; Kronik cannot check that a target really respects idempotency keys.

    kronik grant billing http:payments.internal --delivery idempotency-keyed --reason "..."

See also: [`capability`](#capability), [`EFFECT_OUTCOME_UNKNOWN`](../errors.md#effect_outcome_unknown).

## secret-handle

A secret referred to by name; the value never reaches the guest. Milestone M2.

A secret handle refers to a secret by its name. The guest names the secret in a header template such as `Bearer {}` or in a `crypto` call, and the host inserts the value at the effect boundary or uses it in host-side cryptography. The value never enters guest memory, and Kronik never writes it to the log, diffs, `history` or MCP responses (I8); the log records the secret's name and version hash. Raw values require the capability `secret-reveal:<name>`, and exact occurrences are then scrubbed from logs and diffs.

`kronik secret set` reads the value from stdin and never shows it again:

    kronik secret set <name>
    kronik secret list

See also: [`capability`](#capability), [`effect`](#effect).

## sql-state

A SQLite database per actor, owned by the host. Milestone M1.

SQL state is one SQLite database per actor, owned by the host. A turn's statements run in a savepoint and are captured as a changeset, which the turn record carries and which is applied at commit, so the database is built the same way in production, at recovery and in replay. `random()`, `datetime('now')` and the like are deterministic. Extensions, `ATTACH`, `VACUUM`, `ANALYZE` and pragmas that affect storage are denied, and DDL is allowed only in `migrate`, before the first DML statement. The `_subject` column ties rows to a subject. The size is limited per actor, 1 GiB by default.

See also: [`subject`](#subject), [`turn`](#turn).

## dead-letters

Inputs whose turn failed, kept for inspection and resend. Milestone M1.

Dead letters are inputs whose turn failed. Failed messages end up there, and from M2 so do timers, uncertain effect outcomes and compensations that fail. They show up in `history` and in `kronik dead-letters list`. There is no automatic retry, because the outcome would then depend on time; `kronik dead-letters resend` creates a new root input instead.

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: [`turn`](#turn), [`root-input`](#root-input), [`TURN_FAILED`](../errors.md#turn_failed), [`EFFECT_OUTCOME_UNKNOWN`](../errors.md#effect_outcome_unknown).

## orphaned-change

A callee's committed change whose caller then failed. Milestone M2.

An orphaned change is a change that a called actor committed in a `call` whose caller then failed without compensation. `call` is not atomic: the callee's turn stands. If the call carried a compensation message, Kronik delivers it exactly once to the callee; a compensation that itself fails ends up in dead letters, and the change counts as orphaned until a compensation succeeds. Orphaned changes show up in `kronik history --orphans` and, from M3, in the diff.

See also: [`message`](#message), [`dead-letters`](#dead-letters).

## privacy-mode

The operator's GDPR switch for sealing personal data. Milestone M8.

Privacy mode is a switch that the operator controls; turning it on writes a `PrivacyMode` record. The format always supports it (I9): every value carries a subject tag even in the `off` mode, which is the default and costs nothing measurable. In the `on` mode, values written under a subject are sealed with that subject's key (XChaCha20-Poly1305). Erasing a subject deletes its key and makes its sealed values unreadable everywhere, and reseal seals history written while the mode was off. The operator decides whether the mode is used and is responsible for the legal basis, agreements and retention periods.

    kronik privacy mode on --reason "..."
    kronik privacy erase user:123 --reason "..."
    kronik privacy reseal

See also: [`subject`](#subject), [`sealed-value`](#sealed-value), [`SUBJECT_ERASED`](../errors.md#subject_erased).

## subject

The person a value belongs to, such as user:123. Milestone M1.

A subject is the person that data belongs to, for example `user:123`. Every value carries its own subject tag, recorded even when privacy mode is off, so that reseal, erasure and audit (M8) work per value instead of per turn. Guest code sets the default subject for the rest of the turn (`privacy.set-subject`) or a subject for a single write (`state.set-for`), and from M8 the gateway can take the subject of HTTP root inputs from a header or a JWT claim (`privacy.subject_from`). A value has at most one subject in v0.1, and the `_subject` column ties rows in SQL state to a subject.

See also: [`privacy-mode`](#privacy-mode), [`sealed-value`](#sealed-value), [`sql-state`](#sql-state).

## sealed-value

A value encrypted with its subject's key. Milestone M8.

A sealed value is a value encrypted with its subject's key. It is erased by erasing the key, after which it is unreadable in the log, state, snapshots and shipped copies. Without the `pii:read` scope, `actors inspect`, turns, `history` and MCP responses show sealed values as `[sealed]` and erased ones as `[erased]`, and never a subject id; diffs show a subject's values as redacted, with a keyed hash in place of the subject. A fork created with `--no-pii` sees deterministic pseudonyms instead, `pii:` plus 12 hex characters.

See also: [`subject`](#subject), [`privacy-mode`](#privacy-mode), [`SUBJECT_ERASED`](../errors.md#subject_erased).

## foreign-actor

A Linux binary in gVisor behind a recorded boundary. Milestone M7.

A foreign actor is an ordinary Linux binary from an OCI image, always pinned by digest, that runs in gVisor: `runsc` with the `systrap` platform by default, which works without KVM. Only the boundary to it is recorded. Actors call it with `http.fetch` on `foreign://<name>/...`, which requires the capability `foreign:<name>` and is recorded as `foreign.http`. In a fork, the calls are matched against recordings and the foreign actor is not started. The sandbox has no outgoing network in v0.1, and its persistent directory cannot be replayed.

    kronik foreign add payments --image ghcr.io/org/fake-payments@sha256:... --port 8080 --cpu 1 --memory 512Mi --reason "..."
    kronik foreign list

See also: [`isolation-level`](#isolation-level), [`RUNSC_MISSING`](../errors.md#runsc_missing), [`FOREIGN_UNAVAILABLE`](../errors.md#foreign_unavailable).

## isolation-level

How code is sandboxed: wasm, gvisor, trusted or microvm. Milestone M7.

The isolation level says how code is sandboxed: `wasm` for actors (the default), `gvisor` for foreign actors (their default, `runsc` with the systrap platform), `trusted` for what the operator chooses to trust (plain runc, with a warning), and `microvm` for Firecracker where KVM is available. `microvm` is reserved and gives `NOT_IMPLEMENTED` in v0.1.

See also: [`foreign-actor`](#foreign-actor), [`KVM_UNAVAILABLE`](../errors.md#kvm_unavailable).

## snapshot

A consistent copy of materialized state at an LSN. Milestone M6.

A snapshot is a consistent copy of materialized state at a known LSN, made with SQLite's backup API, with a `manifest.json` that lists the lsn, branch, segments, engine version and time. Snapshots are made every 60 minutes by default and at a controlled shutdown. Forks build their state from the nearest snapshot, and with shipping enabled snapshots are uploaded to object storage, from where `kronik restore` fetches the latest one and the segments after it. Like all state, snapshots are derived from the log (I4).

    kronik snapshot list
    kronik restore --from s3://bucket/kronik

See also: [`segment`](#segment), [`branch`](#branch).

## segment

A log file; closed segments are immutable. Milestone M1.

A segment is a log file. The active segment is written to. A segment is closed at 64 MiB or after 60 seconds; a closed segment is immutable, gets a footer index from actor to offset (M3) and can be shipped (M6). Every record in a segment sits in the envelope `[u32 len][u32 crc32c][u64 lsn][u8 kind][protobuf]`. A torn last record after a crash is truncated at startup; a corrupt record in the middle of a segment gives `STORAGE_CORRUPT`. Segments older than the retention window are deleted once a snapshot covers them (M6).

See also: [`lsn`](#lsn), [`snapshot`](#snapshot), [`STORAGE_CORRUPT`](../errors.md#storage_corrupt).
