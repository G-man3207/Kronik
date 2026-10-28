# Error codes

<!-- Generated from crates/kronik-core/src/error.rs and
crates/kronik-core/explain/codes/ by
`cargo run -p kronik-core --example errors_md > docs/errors.md`.
Edit those files, not this one; `scripts/ci.sh docs` checks it. -->

Every error from the JSON API, the gateway and the CLI has the same shape, and
its HTTP status follows from its code:

```json
{
  "error": {
    "code": "CAPABILITY_NOT_GRANTED",
    "message": "billing is not allowed to call payments.internal",
    "hint": "kronik grant billing http:payments.internal --reason '...'",
    "docs": "kronik explain CAPABILITY_NOT_GRANTED"
  }
}
```

- `code` is stable: a code is never renamed or reused.
- `message` says what happened, for this request.
- `hint` says what to do next, often as the exact next command. Unless the
  error has a more specific one, it is the code's default hint listed below.
  It is omitted when an error has no hint.
- `docs` is `kronik explain <CODE>`, which prints the code's entry below.
  The lookup ignores case.

Each code names the milestone that introduces it; the
[introduction](introduction.md#roadmap) lists the milestones. Terms in the
entries are defined in [Concepts](concepts/glossary.md).

| Code | HTTP status | Milestone | Meaning |
| --- | --- | --- | --- |
| [`ACTOR_NOT_FOUND`](#actor_not_found) | 404 | M1 | No such actor or actor type |
| [`APPROVAL_REQUIRED`](#approval_required) | 403 | M3 | The policy requires an approval first |
| [`BAD_REQUEST`](#bad_request) | 400 | M1 | The request is malformed |
| [`CAPABILITY_NOT_GRANTED`](#capability_not_granted) | 403 | M2 | The actor type lacks a capability for this effect |
| [`DEAD_LETTER_ALREADY_RESENT`](#dead_letter_already_resent) | 409 | M1 | The dead letter was already resent |
| [`DEAD_LETTER_NOT_FOUND`](#dead_letter_not_found) | 404 | M1 | No such dead letter |
| [`DEPLOYMENT_NOT_FOUND`](#deployment_not_found) | 404 | M3 | No such deployment |
| [`EFFECT_OUTCOME_UNKNOWN`](#effect_outcome_unknown) | 500 | M2 | An unsafe effect may or may not have happened |
| [`ENGINE_UPGRADE_DIVERGED`](#engine_upgrade_diverged) | 409 | M6 | The new engine version changes behavior |
| [`ENGINE_VERSION_MISMATCH`](#engine_version_mismatch) | 409 | M6 | The engine version differs from the recorded one |
| [`FOREIGN_EXISTS`](#foreign_exists) | 409 | M7 | A foreign actor with this name is already declared |
| [`FOREIGN_NOT_FOUND`](#foreign_not_found) | 404 | M7 | No foreign actor with this name is declared |
| [`FOREIGN_UNAVAILABLE`](#foreign_unavailable) | 503 | M7 | The foreign actor is not reachable |
| [`FORK_NOT_FOUND`](#fork_not_found) | 404 | M3 | No such fork |
| [`FUEL_EXHAUSTED`](#fuel_exhausted) | 500 | M1 | The turn ran out of fuel |
| [`GATEWAY_TIMEOUT`](#gateway_timeout) | 504 | M1 | The turn outlived the gateway timeout |
| [`IDEMPOTENCY_IN_FLIGHT`](#idempotency_in_flight) | 409 | M1 | The original request with this key is still running |
| [`IDEMPOTENCY_KEY_REUSED`](#idempotency_key_reused) | 422 | M1 | The key was already used for a different request |
| [`IMAGE_INVALID`](#image_invalid) | 400 | M7 | The image cannot be used |
| [`IMPORT_NOT_ALLOWED`](#import_not_allowed) | 400 | M1 | The component imports an interface outside the allowlist |
| [`INTERNAL`](#internal) | 500 | M1 | An internal error in Kronik |
| [`KEYSTORE_INCOMPLETE`](#keystore_incomplete) | 409 | M8 | A sealed value's subject key is not in the keystore |
| [`KVM_UNAVAILABLE`](#kvm_unavailable) | 503 | M7 | KVM is not available on this host |
| [`MASTER_KEY_MISMATCH`](#master_key_mismatch) | 409 | M2 | The master key is not the key the stores were encrypted under |
| [`MASTER_KEY_MISSING`](#master_key_missing) | 409 | M2 | The master key is missing, and the data directory holds encrypted stores |
| [`NOT_IMPLEMENTED`](#not_implemented) | 501 | M1 | Not available in this version |
| [`PAYLOAD_TOO_LARGE`](#payload_too_large) | 413 | M1 | The body or message is over the limit |
| [`POLICY_DENIED`](#policy_denied) | 403 | M3 | A policy rule denies the change |
| [`PROPOSAL_NOT_FOUND`](#proposal_not_found) | 404 | M3 | No such proposal |
| [`PROPOSAL_STALE`](#proposal_stale) | 409 | M3 | The proposal can no longer be promoted |
| [`REASON_REQUIRED`](#reason_required) | 400 | M1 | The mutation has no reason |
| [`REPLAY_DIVERGED`](#replay_diverged) | 500 | M2 | Replay did not reproduce the recorded history |
| [`ROLLBACK_SCHEMA_CHANGED`](#rollback_schema_changed) | 409 | M3 | The schema version changed since that deployment |
| [`ROUTE_CONFLICT`](#route_conflict) | 409 | M1 | Another actor type already serves this route |
| [`ROUTE_NOT_FOUND`](#route_not_found) | 404 | M1 | No deployed route matches the request |
| [`RUNC_MISSING`](#runc_missing) | 503 | M7 | runc is not installed |
| [`RUNSC_MISSING`](#runsc_missing) | 503 | M7 | gVisor's runsc is not installed |
| [`SCOPE_MISSING`](#scope_missing) | 403 | M5 | The token lacks the scope for this operation |
| [`SECRET_NOT_FOUND`](#secret_not_found) | 404 | M2 | No such secret |
| [`STORAGE_CORRUPT`](#storage_corrupt) | 500 | M1 | The log or state on disk is corrupt |
| [`SUBJECT_ERASED`](#subject_erased) | 410 | M8 | The subject's data was erased |
| [`TOKEN_NOT_FOUND`](#token_not_found) | 404 | M5 | No API token with that name |
| [`TURN_FAILED`](#turn_failed) | 500 | M1 | The turn failed |
| [`TURN_NOT_FOUND`](#turn_not_found) | 404 | M1 | No turn with that id |
| [`UNAUTHENTICATED`](#unauthenticated) | 401 | M5 | No valid token |
| [`UNAVAILABLE`](#unavailable) | 503 | M1 | The daemon is not accepting requests |
| [`VERIFY_REQUIRED`](#verify_required) | 409 | M1 | The actor type has history; verify the change first |

## ACTOR_NOT_FOUND

HTTP status 404, milestone M1. No such actor or actor type.

Default hint: Check the kind and key with `kronik actors list`.

The actor or its actor type does not exist. Actors are addressed as `kind/key`: the kind must be deployed, and an actor appears once it has run its first turn.

Typical causes:

- A typo in the kind or the key.
- A message to a kind that has not been deployed yet.
- Inspecting an actor that has never run a turn.

To fix it, list the actors that exist, or deploy the kind first:

    kronik actors list
    kronik deploy ./dist/billing.wasm --reason "first deploy"

See also: [`actor`](concepts/glossary.md#actor), [`kind`](concepts/glossary.md#kind).

## APPROVAL_REQUIRED

HTTP status 403, milestone M3. The policy requires an approval first.

Default hint: Read the diff, then run `kronik approve <proposal> --reason '...'`.

The policy outcome for the proposal is `require_approval`, and no approval covers its current diff. Policies are CEL rules against the behavior diff, and the strictest outcome wins.

Typical causes:

- A rule such as `payments-must-be-exact` matched, for example because payment effects changed.
- The proposal was approved, but catch-up at promote made the outcome stricter or changed new targets. An approval applies only to the diff it was given for, so a new approval is required.

To fix it, a human reads the diff and approves the proposal (from M5 this needs the `approve` scope), and then it is promoted:

    kronik diff show p-7h3k --md
    kronik approve p-7h3k --reason "reviewed the VAT change"
    kronik promote p-7h3k --reason "Apply EU VAT"

See also: [`proposal`](concepts/glossary.md#proposal), [`behavior-diff`](concepts/glossary.md#behavior-diff), [`grounding`](concepts/glossary.md#grounding).

## BAD_REQUEST

HTTP status 400, milestone M1. The request is malformed.

Default hint: Fix the field or value named in the message and send the request again.

The request could not be understood: invalid JSON, a missing or mistyped field, an invalid actor key or path segment, or a manifest from `describe` that breaks the naming rules. Kronik uses this generic code for malformed input that no more specific code covers, so that a client can tell a request it must fix from a failure on the server.

The message names the field or value that is wrong. Fix it and send the request again; the same request always gives the same error.

## CAPABILITY_NOT_GRANTED

HTTP status 403, milestone M2. The actor type lacks a capability for this effect.

Default hint: Grant it with `kronik grant <kind> <capability> --reason '...'`.

The actor type tried to use an effect against a target that has not been granted. Every external effect is denied until the operator grants a capability for that target (default deny, I6). The guest gets `denied`, and the attempt is recorded in the turn. Deploy also warns about requested capabilities that are not granted.

Typical causes:

- The capability was never granted, or it was revoked.
- The request goes to another target than the granted one, for example a different host.

To fix it, grant the capability to the actor type. Grants apply per actor type, not per hash, so they carry over to new code. `--delivery` sets the target's delivery class and `--rate` limits the call rate:

    kronik grant billing http:payments.internal --reason "billing charges invoices"

See also: [`capability`](concepts/glossary.md#capability), [`delivery-class`](concepts/glossary.md#delivery-class), [`effect`](concepts/glossary.md#effect).

## DEAD_LETTER_ALREADY_RESENT

HTTP status 409, milestone M1. The dead letter was already resent.

Default hint: See its `resent_as` turn in `kronik dead-letters list`.

The dead letter has already been resent, or a resend of it is in progress. Resending creates a new root input, so a dead letter can be resent only once; a second resend would run the input twice. This code is separate from `DEAD_LETTER_NOT_FOUND` because the dead letter exists: the conflict is with its state.

To fix it, look at the dead letter's `resent_as` turn. If that turn failed as well, it is a dead letter of its own; resend that one instead:

    kronik dead-letters list

See also: [`dead-letters`](concepts/glossary.md#dead-letters).

## DEAD_LETTER_NOT_FOUND

HTTP status 404, milestone M1. No such dead letter.

Default hint: List dead letters with `kronik dead-letters list`.

No dead letter has this id. A dead letter's id is the turn id of the failed turn, for example `main:1482331`. This code exists, apart from the other not-found codes, because the id names a failed turn rather than an actor, a turn in general or a route.

To fix it, list the dead letters and use an id from the list:

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: [`dead-letters`](concepts/glossary.md#dead-letters), [`turn-id`](concepts/glossary.md#turn-id).

## DEPLOYMENT_NOT_FOUND

HTTP status 404, milestone M3. No such deployment.

Default hint: List the deployments and their epochs with `kronik deployments list`.

No deployment has this epoch. A deployment is named by its configuration epoch, which `kronik deploy` and `kronik promote` print; a rollback names the deployment to undo this way.

Typical causes: a typo, or an epoch that belongs to another configuration change, such as a grant or a limits change, and not to a deployment.

    kronik deployments list

See also: [`deployment`](concepts/glossary.md#deployment), [`configuration-epoch`](concepts/glossary.md#configuration-epoch), [`ROLLBACK_SCHEMA_CHANGED`](#rollback_schema_changed).

## EFFECT_OUTCOME_UNKNOWN

HTTP status 500, milestone M2. An unsafe effect may or may not have happened.

Default hint: Check the target system; resend the dead letter only if the effect did not happen.

The turn made an external effect against an `unsafe` target, and Kronik crashed before the result was recorded. Kronik never promises exactly-once towards the outside world (I17) and does not redo an `unsafe` effect, so it cannot know whether the effect happened. The guest got `outcome-unknown` for the effect and did not handle it, so the turn failed. The input is in dead letters together with the request, and an HTTP client gets 500 with this code and the turn id.

To fix it, check in the target system whether the effect happened, for example whether the charge exists. Resend the input only if it did not:

    kronik dead-letters list
    kronik dead-letters resend main:1482331 --reason "the charge was not created"

If the target honors `Idempotency-Key`, grant it with the delivery class `idempotency-keyed`: Kronik then redoes such effects after a crash with the same key. Kronik cannot check that a target really honors the key.

    kronik grant billing http:payments.internal --delivery idempotency-keyed --reason "the API honors Idempotency-Key"

See also: [`delivery-class`](concepts/glossary.md#delivery-class), [`dead-letters`](concepts/glossary.md#dead-letters).

## ENGINE_UPGRADE_DIVERGED

HTTP status 409, milestone M6. The new engine version changes behavior.

Default hint: Keep the current binary and report the diff from `kronik upgrade check`.

`kronik upgrade check` ran an identity replay with the same code hashes under the new binary's engine version (Kronik plus Wasmtime), and the behavior diff is not empty. The diff must be empty before a new binary is swapped in; fuel is not compared between engine versions.

Typical cause: a change in Kronik or Wasmtime that alters what guests observe, so existing code would behave differently under the new version.

To fix it, keep running the current binary, and report the diff together with both versions. Check a newer build again before switching:

    kronik upgrade check --window 6h

See also: [`behavior-diff`](concepts/glossary.md#behavior-diff), [`ENGINE_VERSION_MISMATCH`](#engine_version_mismatch).

## ENGINE_VERSION_MISMATCH

HTTP status 409, milestone M6. The engine version differs from the recorded one.

Default hint: Run the recorded engine version, or verify the new one with `kronik upgrade check`.

The engine version, Kronik plus Wasmtime, is part of replay identity and is written in every `TurnBegin` and turn record. This binary's engine version does not match the one that the work at hand was recorded or verified with.

Typical causes:

- Re-executing or replaying turns that were recorded with another engine version.
- Running a new binary against a data directory before `kronik upgrade check` has verified the switch and recorded it as an `EngineUpgrade` record.

To fix it, run a binary with the recorded engine version (`kronik --version` prints a binary's Kronik and Wasmtime versions), or verify the new binary first:

    kronik upgrade check --window 6h

See also: [`ENGINE_UPGRADE_DIVERGED`](#engine_upgrade_diverged).

## FOREIGN_EXISTS

HTTP status 409, milestone M7. A foreign actor with this name is already declared.

Default hint: Remove it first with `kronik foreign remove <name> --reason '...'`, then add it again.

A foreign actor with this name is already declared. Names are unique, and a declaration is history (a `ForeignActor` record), so an existing foreign actor is never changed in place.

To change its image, port, limits or secrets, remove it and add it again; the data directory `foreign/actors/<name>/data` is kept:

    kronik foreign remove payments --reason "..."
    kronik foreign add payments --image ghcr.io/org/fake-payments@sha256:... --port 8080 --reason "..."

See also: [`foreign-actor`](concepts/glossary.md#foreign-actor).

## FOREIGN_NOT_FOUND

HTTP status 404, milestone M7. No foreign actor with this name is declared.

Default hint: List the foreign actors with `kronik foreign list`.

No foreign actor with this name is declared at the configuration that applies. For the API this means the name is unknown; inside a turn, an actor that calls `foreign://<name>/...` gets `denied` with this code when no foreign actor of that name is declared at the turn's configuration epoch.

Typical causes: a typo in the name, a foreign actor that was never added, or one that `kronik foreign remove` removed.

To fix it, list the declared foreign actors, or add the missing one:

    kronik foreign list
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..."

See also: [`foreign-actor`](concepts/glossary.md#foreign-actor), [`FOREIGN_UNAVAILABLE`](#foreign_unavailable).

## FOREIGN_UNAVAILABLE

HTTP status 503, milestone M7. The foreign actor is not reachable.

Default hint: Check it with `kronik foreign list` and `kronik foreign logs <name>`.

The foreign actor's sandbox is not running or does not answer. Kronik starts, monitors and restarts foreign actors with backoff, so this is often temporary.

Typical causes:

- The program in the sandbox crashed or is still starting.
- The image or its configuration is wrong, so the sandbox keeps failing to start.
- `foreign add`: the registry (or the layout directory) did not answer within `[foreign] pull_timeout`. Check that it is reachable, or raise `pull_timeout`, and add the actor again.
- Another daemon holds `[foreign] run_dir`, so this one runs no foreign actors.

To fix it, check the foreign actor's state and its logs:

    kronik foreign list
    kronik foreign logs payments

See also: [`foreign-actor`](concepts/glossary.md#foreign-actor).

## FORK_NOT_FOUND

HTTP status 404, milestone M3. No such fork.

Default hint: List forks with `kronik fork list`.

No fork has this name or id. Forks are branches of the history; proposals create them too.

To fix it, list the forks and use a name from the list:

    kronik fork list

See also: [`fork`](concepts/glossary.md#fork), [`branch`](concepts/glossary.md#branch).

## FUEL_EXHAUSTED

HTTP status 500, milestone M1. The turn ran out of fuel.

Default hint: Make the handler cheaper, or raise the fuel with `kronik limits set <kind> --fuel <n> --reason '...'`.

The turn used up its fuel, the deterministic CPU budget per turn (50 million by default). The turn failed: nothing it buffered was committed, and a failed message or timer is in dead letters. This code is the error code of the failed turn in `history` and in dead letters; an HTTP client gets `TURN_FAILED`. Fuel is deterministic, so the same input fails the same way again.

Typical causes: an endless or very long loop, or work that is too large for one turn.

To fix it, make the handler cheaper or split the work over several turns, or raise the actor type's fuel limit (M2):

    kronik limits set billing --fuel 100000000 --reason "invoices with many lines"

See also: [`turn`](concepts/glossary.md#turn), [`dead-letters`](concepts/glossary.md#dead-letters).

## GATEWAY_TIMEOUT

HTTP status 504, milestone M1. The turn outlived the gateway timeout.

Default hint: The turn still completes; repeat the request with the same Idempotency-Key to get its response.

The gateway answers only after the turn commits. This turn took longer than the gateway timeout (30 seconds by default, `timeout` under `[gateway]`), so the client got 504, but the turn still completes. This code exists because a slow turn has neither failed nor been lost: the client must know that the request may still take effect.

To fix it, repeat the request with the same `Idempotency-Key`, if the original carried one: after commit the repeat gets the stored response, and while the original still runs the repeat waits for it. Without a key, check the actor's history before sending again, or the request may run twice:

    kronik history billing/acme

See also: [`IDEMPOTENCY_IN_FLIGHT`](#idempotency_in_flight), [`turn`](concepts/glossary.md#turn).

## IDEMPOTENCY_IN_FLIGHT

HTTP status 409, milestone M1. The original request with this key is still running.

Default hint: Retry later with the same Idempotency-Key and the same request.

A request repeated an `Idempotency-Key` while the original request with that key was still running. The repeat waited for the original until the gateway timeout and then got this code. The original still completes.

To fix it, retry later with the same key and the same request. Once the original has committed, the repeat gets the stored response and creates no new turn. Keys are stored per actor, for 24 hours by default.

See also: [`GATEWAY_TIMEOUT`](#gateway_timeout), [`IDEMPOTENCY_KEY_REUSED`](#idempotency_key_reused).

## IDEMPOTENCY_KEY_REUSED

HTTP status 422, milestone M1. The key was already used for a different request.

Default hint: Use a new Idempotency-Key for a different request.

The `Idempotency-Key` was already used for this actor with a different request. Keys apply per actor and are stored with the response for 24 hours by default, so one key stands for exactly one request.

Typical causes: a client that reuses keys, or a retry that differs from the original, for example a new timestamp in the body.

To fix it, send a retry that is identical to the original request, and use a new key for every new request.

See also: [`IDEMPOTENCY_IN_FLIGHT`](#idempotency_in_flight).

## IMAGE_INVALID

HTTP status 400, milestone M7. The image cannot be used.

Default hint: Pin the image by digest (`<ref>@sha256:<digest>` or `oci-layout:<dir>`) and check that it is a linux image for this host.

Kronik cannot use the image of a foreign actor. Images are always pinned by digest, every blob is checked against its digest and size, and the layers must unpack safely into a root file system for this host's platform.

Typical causes:

- A registry reference without a digest: use `<registry>/<repo>@sha256:<digest>`. A local OCI layout, `oci-layout:<dir>`, may omit the digest when it holds exactly one image.
- The registry or the layout directory is unreachable, or the image is private (registry pulls are anonymous in v0.1; copy a private image into a local layout with `skopeo copy`).
- A blob does not match its digest or size, the image has no `linux` manifest for this architecture, or a layer has an unsupported media type, escapes the root file system or exceeds the unpack limits.

To fix it, check the reference and the image, then add the foreign actor again:

    skopeo inspect --raw docker://<registry>/<repo>@sha256:<digest>
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..." --dry-run

See also: [`foreign-actor`](concepts/glossary.md#foreign-actor).

## IMPORT_NOT_ALLOWED

HTTP status 400, milestone M1. The component imports an interface outside the allowlist.

Default hint: Remove the listed imports; only kronik:actor and deterministic WASI are allowed.

Deploy rejects a component that imports anything outside the allowlist, and the message lists the offending imports. Guest code may import only Kronik's interfaces (`kronik:actor`) and deterministic versions of a WASI allowlist: `wasi:clocks` (logical time), `wasi:random` (the turn's seed), `wasi:cli` (stdout and stderr become log events) and the `wasi:io` streams that are needed. `wasi:filesystem`, `wasi:sockets` and `wasi:http` are denied in v0.1.

Typical cause: a library that uses the file system, opens sockets or makes HTTP requests directly. Outgoing HTTP must go through Kronik's effect, `http.fetch`.

To fix it, remove or replace the code that pulls in the listed imports, rebuild the component and deploy it again (from M3, propose it instead for a kind with history):

    kronik deploy ./dist/billing.wasm --reason "remove file system access"

See also: [`effect`](concepts/glossary.md#effect).

## INTERNAL

HTTP status 500, milestone M1. An internal error in Kronik.

Default hint: This is a bug in Kronik; please report it with the daemon log.

Something failed inside Kronik that should not fail: this is a bug. Kronik uses this code instead of guessing a more specific one, so that clients do not act on a wrong diagnosis.

To fix it, report the bug with the message, the request and the daemon log. Retrying may or may not help.

## KEYSTORE_INCOMPLETE

HTTP status 409, milestone M8. A sealed value's subject key is not in the keystore.

Default hint: Let the source ship its keystore again and restore again; if it is gone, `kronik restore --allow-missing-keys` keeps every other subject readable.

A sealed value (privacy mode on, a value tagged with a subject) needs its subject's key from the privacy keystore, `keys/keystore.db`, and the keystore does not hold it. The subject was not erased either, so the value is not a tombstone: it is data that nobody can read on this node.

Where it shows:

- `kronik restore` checks every sealed value in the restored state and log against the keystore it would install (the bucket's newest keystore backup, with the log's later erasures applied again). If one has no key, the restore fails before it writes, and names the subjects.
- `kronik integrity` lists such subjects on a running node, for example one restored with `--allow-missing-keys` or `--without-keystore`, and exits 1.
- Replay (a proposal, a fork) that meets such a value fails with this code instead of running the turn without it.

Typical causes:

- The keystore backup in the bucket is older than the subject's first sealed value: the shipper uploads one within a minute of a keystore change, so restoring right after a new subject appeared can come too early.
- The restore ran with `--allow-missing-keys` (some keys) or `--without-keystore` (every key).
- `keys/keystore.db` was deleted or replaced on this node.

To fix it, let the source node ship again (or wait a minute while it runs) and restore again, or restore from another bucket that has a newer backup. If the source is gone, `kronik restore --allow-missing-keys` installs the newest backup anyway: the listed subjects' sealed values stay unreadable, every other subject's stay readable. `--without-keystore` is not the way out here: it installs no backup and drops every subject's key.

See also: [`MASTER_KEY_MISSING`](#master_key_missing), [`SUBJECT_ERASED`](#subject_erased).

## KVM_UNAVAILABLE

HTTP status 503, milestone M7. KVM is not available on this host.

Default hint: Set `platform = "auto"` or `"systrap"` under `[foreign]`, or enable `/dev/kvm`.

The configuration or the operation needs KVM, but `/dev/kvm` is missing or not usable. Everything in v0.1 works without KVM (I11): foreign actors run in gVisor with the `systrap` platform by default.

Typical cause: `platform = "kvm"` under `[foreign]` in `/etc/kronik/kronik.toml` on a VPS without KVM.

To fix it, set `platform = "auto"` or `platform = "systrap"` under `[foreign]`, or run on a host with `/dev/kvm`. `kronik doctor` shows whether the host has KVM:

    kronik doctor

See also: [`isolation-level`](concepts/glossary.md#isolation-level).

## MASTER_KEY_MISMATCH

HTTP status 409, milestone M2. The master key is not the key the stores were encrypted under.

Default hint: Start with the data directory's own master key: the file it was created with, or its KRONIK_MASTER_KEY.

The master key that `kronik serve` loaded is not the key the data directory's secret store or privacy keystore was encrypted under. Each store records a value derived from its key at its first start, and older stores are checked by decrypting one of their values. Kronik stops instead of serving secrets it cannot read.

Typical causes:

- The key of another node or installation: a copied configuration, or `KRONIK_MASTER_KEY` set for a different data directory.
- `kronik serve --init` made a new key file over a lost one.
- A store that holds values under two keys, left by older versions that
  made a new key when the old one was missing: the first value decides.
- A damaged store: a value that does not decrypt for another reason is
  reported here too. If the key is certainly right, treat it as
  `STORAGE_CORRUPT` and keep the directory.

To fix it, start with the key this data directory was created with. `kronik restore` checks the privacy keystore backup against the key before it writes anything, and fails with this code when they don't match.

See also: [`MASTER_KEY_MISSING`](#master_key_missing).

## MASTER_KEY_MISSING

HTTP status 409, milestone M2. The master key is missing, and the data directory holds encrypted stores.

Default hint: Put the key back where [keys] master_key_file points, or set KRONIK_MASTER_KEY; Kronik does not make a new key over existing stores.

`kronik serve` found no master key: the key file (`[keys] master_key_file`, `--master-key-file` or `KRONIK_MASTER_KEY_FILE`, else `<data_dir>/keys/master.key`) does not exist and `KRONIK_MASTER_KEY` is not set. The data directory already holds the secret store or the privacy keystore, which are encrypted under the key this directory was created with. A new key would make every secret and every sealed value unreadable, and would change the keyed hashes in the log, so Kronik refuses to make one. A new, empty data directory still gets a key at its first start.

Typical causes:

- A restored data directory: the key is never in the bucket, and must be put in place on the new machine.
- The configuration names another key file than before, or `KRONIK_MASTER_KEY` is not set in this environment (a unit file, a container) although the node was started with it.
- The key file was deleted.

To fix it, put the original key back where the configuration points, or set `KRONIK_MASTER_KEY` to it, and start again. If the key is lost, the stores cannot be decrypted by anyone: move `keys/secrets.db` and `keys/keystore.db` aside to start with a new key and without those secrets and sealed values.

See also: [`MASTER_KEY_MISMATCH`](#master_key_mismatch).

## NOT_IMPLEMENTED

HTTP status 501, milestone M1. Not available in this version.

Default hint: Use what this version supports; `kronik --version` shows the version.

The operation is part of Kronik's design but not available in this version, for example the `microvm` isolation level, which is reserved in v0.1, or an API endpoint that a later milestone adds.

To fix it, use what this version supports, for example the `gvisor` isolation level instead of `microvm`. `kronik --version` shows which version you run:

    kronik --version

See also: [`isolation-level`](concepts/glossary.md#isolation-level).

## PAYLOAD_TOO_LARGE

HTTP status 413, milestone M1. The body or message is over the limit.

Default hint: Send less data; messages are limited to 1 MiB by default.

The request body or the message is larger than the limit, so it was rejected before any turn ran. Messages and state values are limited to 1 MiB each by default, and the limits can be set per actor type; the gateway and the API also limit the size of requests. This code exists, rather than `BAD_REQUEST`, because the request is otherwise valid: only its size is the problem.

To fix it, send less data, or raise the actor type's limits with `kronik limits set` (M2) if larger messages are expected.

## POLICY_DENIED

HTTP status 403, milestone M3. A policy rule denies the change.

Default hint: Read the diff with `kronik diff show <proposal>`, change the code and propose again.

A policy rule with the action `deny` matched the proposal's behavior diff. Policies are CEL rules against the diff (`kronik.diff/v1`), the strictest outcome wins, and a denied proposal goes back to its author.

Typical causes, with the default rules: the change introduces new errors (`no-new-errors`), fuel at p99 regresses (`fuel-regression`), or payments are covered only by a sample (`payments-full-coverage`).

To fix it, read the diff, change the code and propose again. To see the rules and test them against the proposal:

    kronik diff show p-7h3k --md
    kronik policy show
    kronik policy test rules.toml --proposal p-7h3k

See also: [`proposal`](concepts/glossary.md#proposal), [`behavior-diff`](concepts/glossary.md#behavior-diff).

## PROPOSAL_NOT_FOUND

HTTP status 404, milestone M3. No such proposal.

Default hint: List the proposals with `kronik proposals list`.

No proposal has this id. A proposal id is `p-` followed by 12 hex characters; `kronik propose` prints it, and the proposal's fork has the same name.

Typical causes: a typo in the id, or an id from another data directory.

    kronik proposals list

See also: [`proposal`](concepts/glossary.md#proposal), [`FORK_NOT_FOUND`](#fork_not_found).

## PROPOSAL_STALE

HTTP status 409, milestone M3. The proposal can no longer be promoted.

Default hint: Propose again with `kronik propose <wasm> --reason '...'`.

Promote first runs catch-up: the fork runs the root inputs that arrived after the proposal, in rounds, until it is at most `promote.max_gap` (2 seconds by default) behind main. Promote was aborted because catch-up did not converge within `promote.catch_up_timeout` (5 minutes by default), because the fork point is now outside the retention window, or because main's code for a kind changed since the proposal forked: a kind the proposal changes or skipped no longer runs the code main ran for it when the proposal was made, so promoting would overwrite that newer code.

Typical causes: a proposal that waited too long, for example for an approval, heavy traffic during catch-up, or another proposal for the same kind promoted (or rolled back) first.

To fix it, propose the change again, so that it is verified against recent history, and promote the new proposal soon after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"

See also: [`proposal`](concepts/glossary.md#proposal).

## REASON_REQUIRED

HTTP status 400, milestone M1. The mutation has no reason.

Default hint: Add --reason with a short explanation.

Every mutation requires a reason (I12). Deploys, grants, messages, resends and every other change are recorded with the token id and the reason, so the log shows who did what and why. The reason was missing or empty.

To fix it, repeat the command with `--reason` and a short explanation, or set a non-empty `reason` in the API request body:

    kronik deploy ./dist/billing.wasm --reason "first deploy"

## REPLAY_DIVERGED

HTTP status 500, milestone M2. Replay did not reproduce the recorded history.

Default hint: This is a determinism bug; report it with the turn id and the daemon log.

A replay that must reproduce recorded history produced a different result. The same code hash, engine version, input, recorded effect results, logical time, random seed and starting state must give a byte-identical outcome (I1), so this is a determinism bug.

Typical causes: a bug in Kronik's host or engine configuration, or a value that reached the guest without going through a recorded host call (I2).

To fix it, do not promote or upgrade on top of the divergence. Report it with the turn id, the actor's history and the daemon log:

    kronik history billing/acme

See also: [`turn`](concepts/glossary.md#turn), [`behavior-diff`](concepts/glossary.md#behavior-diff).

## ROLLBACK_SCHEMA_CHANGED

HTTP status 409, milestone M3. The schema version changed since that deployment.

Default hint: Fix forward: propose a corrected version that keeps the current schema version.

`kronik rollback <deployment>` switches back to the previous hash, but the actor type's schema version has changed since then: the newer code has migrated the state with `migrate`. In v0.1 such a rollback is rejected. Rollback via replay, which handles schema changes, comes after v0.1 (M13).

To fix it, fix forward: propose a corrected version that keeps or raises the current schema version, and promote it after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "fix the invoice total"

See also: [`deployment`](concepts/glossary.md#deployment), [`proposal`](concepts/glossary.md#proposal).

## ROUTE_CONFLICT

HTTP status 409, milestone M1. Another actor type already serves this route.

Default hint: Change the method or pattern in the kind's describe, rebuild and deploy again.

Deploy found that another actor type already serves the same HTTP method and route pattern. Routes come from the manifest that `describe` returns, and each method and pattern belongs to at most one actor type. Patterns that differ only in parameter names count as the same route.

To fix it, change the method or the pattern in the component's manifest, rebuild the component and deploy it again:

    kronik deploy ./dist/billing.wasm --reason "move billing routes under /billing"

See also: [`kind`](concepts/glossary.md#kind), [`ROUTE_NOT_FOUND`](#route_not_found).

## ROUTE_NOT_FOUND

HTTP status 404, milestone M1. No deployed route matches the request.

Default hint: Check the method and path against the routes that `kronik deploy` printed.

The gateway found no route for the request's method and path. Routes come from the manifests of the current deployments, and a `{name}` segment in a pattern matches one path segment. This code exists, apart from `ACTOR_NOT_FOUND`, because the gateway routes on method and path before any actor is involved.

Typical causes: a wrong method or path, a kind that has not been deployed, or a route that the latest deployment removed.

To fix it, compare the request with the routes in the kind's manifest, which `kronik deploy` prints.

See also: [`ROUTE_CONFLICT`](#route_conflict), [`deployment`](concepts/glossary.md#deployment).

## RUNC_MISSING

HTTP status 503, milestone M7. runc is not installed.

Default hint: Install runc for `--isolation trusted`, or use the default `gvisor`.

The foreign actor asks for `--isolation trusted`, which runs the image with plain `runc` and the host kernel, and Kronik found no `runc` in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin` or `/usr/bin`. Nothing was written.

To fix it, install `runc` (on Debian and Ubuntu, `apt install runc`), or use the default isolation, gVisor, which only needs `runsc`:

    kronik doctor
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..."

See also: [`isolation-level`](concepts/glossary.md#isolation-level), [`RUNSC_MISSING`](#runsc_missing).

## RUNSC_MISSING

HTTP status 503, milestone M7. gVisor's runsc is not installed.

Default hint: Install gVisor's runsc, then check the host with `kronik doctor`.

Foreign actors run in gVisor, and Kronik could not find its `runsc` binary (`runsc_path` under `[foreign]`, `/usr/local/bin/runsc` by default). `runsc` is optional: Kronik itself needs no external services (I10), but foreign actors need it.

To fix it, install gVisor's `runsc` (the install script offers to), or point `runsc_path` to it, then check the host:

    kronik doctor

See also: [`foreign-actor`](concepts/glossary.md#foreign-actor), [`isolation-level`](concepts/glossary.md#isolation-level).

## SCOPE_MISSING

HTTP status 403, milestone M5. The token lacks the scope for this operation.

Default hint: Use a token with the required scope.

The caller's token does not have the scope that the operation needs. The scopes are `read`, `fork`, `propose`, `approve`, `promote`, `operate` (grants, limits, foreign actors, privacy), `pii:read` and `admin`. Agents get `read`, `fork` and `propose` by default, and an operator message to main needs `operate`.

To fix it, use a token that has the scope, or ask someone who has one. Tokens and their scopes are created with `kronik token create --scopes`, and `kronik token list` shows the existing ones.

See also: [`UNAUTHENTICATED`](#unauthenticated).

## SECRET_NOT_FOUND

HTTP status 404, milestone M2. No such secret.

Default hint: List secrets with `kronik secret list`.

No secret has this name, or it was deleted. Secrets live in the secret store, encrypted with the master key; they are referred to by name and their values are never shown.

Typical causes: a typo in the name, a secret that was never set, or one that `kronik secret delete` removed.

To fix it, list the secrets that exist, or set the secret; `kronik secret set` reads the value from stdin:

    kronik secret list
    kronik secret set <name> --reason "..."

See also: [`secret-handle`](concepts/glossary.md#secret-handle).

## STORAGE_CORRUPT

HTTP status 500, milestone M1. The log or state on disk is corrupt.

Default hint: Stop the daemon and keep the data directory; do not delete log segments.

Kronik found data on disk that it cannot trust, such as a log record with a bad checksum in the middle of a segment, or a record with the enum value 0 or an unknown enum value. Kronik never applies such a record or reads it as a default value, and a corrupt record in the middle of a segment stops the startup. A torn last record after a crash is not corruption: it is truncated at startup.

Typical causes: disk or file system errors, or files in the data directory that something other than Kronik changed.

To fix it, stop the daemon and keep the data directory as it is; do not delete or edit log segments. If shipping to object storage is enabled (M6), restore into a fresh data directory:

    kronik restore --from s3://bucket/kronik

See also: [`segment`](concepts/glossary.md#segment), [`snapshot`](concepts/glossary.md#snapshot).

## SUBJECT_ERASED

HTTP status 410, milestone M8. The subject's data was erased.

Default hint: The subject was erased; its data cannot be read.

The data belongs to a subject that was erased with `kronik privacy erase`. Erasure deletes the subject's key, so its sealed values are unreadable everywhere: in the log, state, snapshots and shipped copies. Diffs and history show such values as `[erased]`.

This is permanent by design. Do not retry: the data cannot be recovered, and code that needs it must handle its absence.

See also: [`subject`](concepts/glossary.md#subject), [`sealed-value`](concepts/glossary.md#sealed-value), [`privacy-mode`](concepts/glossary.md#privacy-mode).

## TOKEN_NOT_FOUND

HTTP status 404, milestone M5. No API token with that name.

Default hint: List the tokens with `kronik token list`.

No API token has this name. Tokens are referred to by the name they were created with, such as `agent-1`; the token itself is shown only once, when it is created, and is never stored.

Typical causes: a typo in the name, or a token that was never created on this daemon. A revoked token keeps its name and is still listed, and names are never reused.

To fix it, list the tokens, or create one:

    kronik token list
    kronik token create --name <name> --scopes read,fork,propose --reason "..."

See also: [`UNAUTHENTICATED`](#unauthenticated), [`SCOPE_MISSING`](#scope_missing).

## TURN_FAILED

HTTP status 500, milestone M1. The turn failed.

Default hint: Inspect the turn with `kronik history <kind/key>`; resend failed messages with `kronik dead-letters resend`.

The turn trapped, ran out of fuel or returned a `handler-error`, and a failed turn record was written with the input, the effects that already happened and the error. Its buffered state writes, SQL changes, messages and timers were discarded, but compensation messages for successful calls (M2) are delivered, and external effects that already happened stand. There is no automatic retry, since the outcome would then depend on time. An HTTP client gets 500 with this code and the turn id (also in the `Kronik-Turn-Id` header), and a failed message or timer ends up in dead letters. Deploy gives this code when `describe` traps.

To fix it, find the cause in the turn's error, fix the code (for a kind with history, through propose and promote from M3), and resend the failed input:

    kronik history billing/acme
    kronik dead-letters resend main:1482331 --reason "retry after the fix"

See also: [`turn`](concepts/glossary.md#turn), [`dead-letters`](concepts/glossary.md#dead-letters), [`FUEL_EXHAUSTED`](#fuel_exhausted).

## TURN_NOT_FOUND

HTTP status 404, milestone M1. No turn with that id.

Default hint: Check the turn id (`<branch>:<lsn>`) with `kronik history <kind/key>`.

No turn record has this id on the branch that the daemon serves. A turn id is `<branch>:<lsn>` of the turn's turn record, for example `main:1482331`; an LSN that holds another kind of record is not a turn. This code exists, apart from `ACTOR_NOT_FOUND`, because turn ids address positions in the log, not actors.

If the turn's LSN is below the first LSN the log still holds, retention has deleted that segment. The message says the turn is outside retention and names `log_first_lsn`.

To fix it, take the turn id from the actor's history, from a dead letter or from the `Kronik-Turn-Id` header:

    kronik history billing/acme

See also: [`turn-id`](concepts/glossary.md#turn-id), [`lsn`](concepts/glossary.md#lsn).

## UNAUTHENTICATED

HTTP status 401, milestone M5. No valid token.

Default hint: Send a valid token as `Authorization: Bearer <token>`.

The request has no valid token. The JSON API over TCP requires a bearer token, and this one is missing, malformed or revoked. Over the Unix socket a request without a token is the socket user's, identified by file permissions and the peer's user id; a token sent there must be live too. This code exists, apart from `SCOPE_MISSING`, because there a token is valid but lacks a scope, while here there is no valid token at all.

To fix it, send a live token as `Authorization: Bearer <token>`; the CLI and `kronik mcp` send `$KRONIK_TOKEN`. `kronik token list` shows the existing tokens, and `kronik token create` makes a new one:

    kronik token list
    kronik token create --name agent-1 --scopes read,fork,propose --reason "..."

See also: [`SCOPE_MISSING`](#scope_missing), [`TOKEN_NOT_FOUND`](#token_not_found).

## UNAVAILABLE

HTTP status 503, milestone M1. The daemon is not accepting requests.

Default hint: Retry shortly; if it persists, check the daemon log.

The daemon cannot serve the request right now: it is starting or shutting down, it stopped accepting turns after a fatal error such as a failed log write, or the data directory's file system is below `[log] disk_reserve`, where new inputs and changes are refused until there is room. This code exists so that clients can tell a temporary state of the daemon from an error in their request.

To fix it, retry shortly. If it persists, read the message and the daemon log. Below the reserve, free disk space (old snapshots, foreign actors' data; `kronik foreign remove` and rollback still work) or lower the reserve. After a fatal error, fix the cause, for example a full disk, and restart the daemon.

## VERIFY_REQUIRED

HTTP status 409, milestone M1. The actor type has history; verify the change first.

Default hint: A kind with history changes through `kronik propose` and `kronik promote`.

A direct deploy is allowed only for a new actor type without history. This actor type has history, so new code goes the golden path (M3): propose, review the behavior diff and promote. `--skip-verify`, which deploys without verification if the policy allows it, does not exist yet.

To fix it, propose the new code and promote it after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"
    kronik promote p-7h3k --reason "Apply EU VAT"

See also: [`proposal`](concepts/glossary.md#proposal), [`deployment`](concepts/glossary.md#deployment).
