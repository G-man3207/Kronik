# Compatibility, versions and deprecation

Kronik has **not reached the v0.9 compatibility freeze**. The actor package is
currently `kronik:actor@0.1.0` in the committed baseline; the IO workstream is
changing the actual ABI before that freeze. This page defines the required
compatibility policy, not a claim that unfinished interfaces are frozen or that
v0.9/v1.0 is ready. `STATUS.md` identifies accepted implementation and proof.

## What must remain compatible

The v0.9 freeze covers log format v1, `kronik:actor@1.0.0`, API `/v1`, the CLI's
machine-readable schemas, `kronik.diff/v1`, and the policy language. The frozen
contracts remain backward compatible until v2. A name in this list does not
rename today's WIT package or advertise an unimplemented adapter.

A change is breaking if a previously supported producer, component, client,
operator command or policy loses its documented meaning. This includes:

- refusing an old log, dropping a record or field needed to reconstruct state,
  changing causal identity, silently altering effect delivery, or replaying a
  committed result differently without an explicit engine upgrade;
- removing/retyping a WIT function, changing record/variant layout or resource
  ownership, or accepting an old component whose host semantics changed;
- removing an endpoint, request/response field, CLI command/option, JSON field,
  error code or enum case; changing its type, requiredness, scope requirement,
  status/exit behavior, default meaning or pagination semantics;
- changing diff classifications, grounding/confidence or PII semantics so that
  the same observed behavior yields a different decision without a versioned
  migration; changing policy syntax, evaluation or approval precedence;
- returning previously private data, granting authority where an old caller
  was denied, or treating an unrecognized security field as authorization.

Adding an optional field or endpoint can be compatible only if old consumers
continue to work. An added enum/variant is not automatically compatible: old
consumers may require exhaustive matching. Unknown Protobuf fields must not be
reused as evidence of authorization. Removed field numbers and enum values
remain reserved; never reuse their numbers for a different meaning.

## Version numbers

The binary and each published SDK use semantic versions. After 1.0:

- a patch fixes compatible behavior and security defects;
- a minor adds backward-compatible functionality;
- a major permits breaking changes, with the notice and migration rules below.

SDK versions describe each SDK's public API independently. A binary or SDK
version bump alone does not version a wire format: logs, WIT packages, API
namespaces and JSON/diff schemas retain their own explicit identifiers.
Changing one requires the matching versioned reader/adapter and compatibility
proof, not an alias that pretends two formats are identical.

Before the freeze, a `0.x` minor may introduce a documented breaking change.
Even then, repository rules require a format version change and a genuine old
producer fixture. Do not overwrite an old fixture with new encoder output or
regenerate every expected result to conceal a behavior change.

Wasmtime/engine changes are not replay-compatible by assumption, including
patch updates. Follow `kronik upgrade check` and
[ADR 0001](../adr/0001-wasmtime-determinism.md); preserve the recorded old engine
identity and code hash. Do not rewrite historical engine names to make a check
pass.

## At least twelve months before removal

A frozen supported interface is not removed until **at least twelve calendar
months after public deprecation notice**, and never in a backward-compatible
minor/patch release. Notice must identify the affected versions and interface,
replacement, migration commands/examples, first notice date and earliest
removal date. Publish it in release notes and the relevant reference/migration
guide; machine-readable warnings must not corrupt JSON stdout.

For example, a notice published on 2027-02-15 cannot permit removal before
2028-02-15, even if v2 ships sooner. The replacement must be usable throughout
the notice period. Deprecation is not permission to stop fixing supported
security defects. A severe unsafe operation may need immediate fail-closed
restriction: publish the actual security rationale and remediation through the
[security advisory process](https://github.com/G-man3207/Kronik/security/policy), rather than silently describing
it as compatible or fabricating a twelve-month history.

## Evidence required for a change

1. Keep the original release's immutable producer log/component bytes and their
   producer version, source revision, engine and SHA-256 provenance. Store only
   non-secret fixture data. A current encoder's hand-built record is useful as
   a wire unit test, but is not a released-producer compatibility fixture.
2. Read or explicitly migrate every actual released `0.x` producer corpus with
   the candidate. Reconstruct state and perform deterministic identity replay
   of the same recorded inputs/effects, checking the real behavior diff and
   state. A successful Protobuf decode alone does not prove compatibility.
3. Run old WIT components through the real adapter. If no adapter exists, reject
   before deployment with the unsupported package/version and the exact
   supported build/migration path; never partially link or silently substitute
   host behavior. Freeze the final WIT only after its actual consumers agree.
4. Exercise API/CLI/diff/policy consumers against their declared schemas and
   semantics, including precedence, error/exit and authorization behavior.
   Retain old and new fixtures for new versioned formats.
5. Record exact commands, revisions, fixture digests and pass/fail/ignored
   counts. Missing released producers, an unavailable runtime or unmerged
   feature consumers are explicit gaps, not green compatibility results.

The current fixture tests, example identity replay and engine-upgrade checks
remain useful evidence for their measured revisions. They do not by themselves
establish the complete M33 release corpus or all future interfaces. Consult
`STATUS.md` before relying on an acceptance claim.

## Replaying the actual released corpus

`tests/compatibility/releases.json` is the versioned
`kronik.compatibility-index/v2` inventory. Its separately declared
`published_releases` set must exactly match its covered cases. It pins the actual
published v0.1.0 and v0.3.0 producer binary digests, source commits, immutable
exported manifest digests, original root counts, genuine counter/SQL component
bytes, and original API, CLI JSON, diff and WIT source snapshots from those tags.
There was no published v0.2.0 artifact in the inspected release set; do not
invent one. The v0.1.0 artifact actually reports `kronik 0.1.0-dev` and records
Wasmtime 50.0.0; its real identity is retained rather than rewritten.

The saved logs were produced by those binaries running the maintained test
applications. Their embedded component bytes remain exactly as recorded.
Separately, the index's `components` entries preserve the genuine tagged old
SDK/WIT component bytes, including older counters that differ from today's
counter fixture. A newly compiled component with the same WIT package name
is not a substitute for those bytes.

Run the existing public-binary consumer from a clean candidate checkout:

```sh
cargo build -p kronik
python3 scripts/verify-compatibility.py \
  --index tests/compatibility/releases.json \
  --binary target/debug/kronik \
  --revision "$(git rev-parse HEAD)" \
  --workdir /var/tmp/kronik-compatibility-new \
  --port 47831
```

The work directory must not exist. The command copies, never upgrades in
place, each immutable corpus; runs real `upgrade check`; compares the original
state/log integrity hashes; requires **all nine original roots**, not merely a
positive root count, in the upgrade check and isolated/continuous identity
replays; and verifies the historical key-backed result. It also deploys each
release's genuine old counter and SQL components into a fresh fixture, checks
committed state transitions, replays their five real inputs in both modes,
consumes the public versioned diff, and runs the versioned public policy
semantic cases. Any mismatch exits nonzero. The existing CI caller uses the
already-built candidate; it must never regenerate producer output during CI.

An older WIT component may instead receive a real nonzero
`IMPORT_NOT_ALLOWED` response identifying its old package/interface version and
an explicit rebuild path naming the supported package and `kronik build`.
Generic link failures, missing JSON errors, successful exit codes with error
text, and hints added by this script do not qualify. The failed deployment must
leave the actual deployment inventory unchanged. The consumer then deploys
the maintained current component and still runs the real state, replay, diff
and policy checks. Its proof distinguishes executing original bytes from this
clear-migration alternative; rejecting a component never makes old-log replay
optional. Today's generic allowlist hint alone is not a migration receipt.

The candidate must support the current historical integrity query and confirm
the requested `through_lsn` in its response. Released v0.3.0 is a valid
producer, but its older integrity handler reads through the current applied
LSN and does not accept that position as an argument. Do not use it as a
modern candidate, drop the integrity comparison, or rewrite the frozen log
hash after an engine-upgrade record has been appended.

`compatibility-corpus.py produce` is an explicit maintainer operation requiring
the real release binary and its pinned SHA-256. Its `--emit-files` records may be
promoted by `promote-compatibility-corpus.py` only into a new owned directory.
Promotion verifies bounded payloads, exact inventory and digest/provenance
agreement, and refuses existing destinations. Only the public dummy master key
`44` repeated 32 times and owned test data occur in these fixtures.

The retained checkpoint proof reports under `docs/benchmarks/compatibility-*`
show nine original roots and ten turns per actual producer, successful engine
upgrade from Wasmtime 50.0.0 to 50.0.1, and complete unchanged replay in both
modes. Their candidate is the assurance branch's `0b84ab0f`-based development
binary, **not the subsequently integrated M23–M30 product**. The later IO
0.1-to-0.2 adapter, new wire formats, public API/CLI additions and their schemas
must pass again against that actual integrated binary before any M33 or v0.9
claim. The source revision label alone is not proof of a clean release build.


### Exercised tagged-component and public-contract consumer

The complete index consumer subsequently passed against that same owned
checkpoint binary, SHA-256
`149fe62fe088267992a1eec40853947c89daab9c38b58acb44cf0bf6a1fc5408`.
For **both** actual releases it read the frozen producer log, upgraded and
verified the original bounded integrity, then deployed the genuine tagged old
counter and SQL component bytes into a separate fresh daemon. Two committed
increments read back as `2`; the committed SQL insert read back as one row.
All five actual inputs replayed unchanged in each mode, with zero
approximate/synthetic inputs or divergent turns.

The real public `kronik.diff/v1` API agreed with the CLI replay's semantic
summary. Public policy evaluation kept `deny` stricter than later `allow`,
and a missing-field evaluation error required approval rather than allowing
promotion. The exact
[released-component and contract proof](../benchmarks/released-components-and-contracts-2026-10-31.json)
is retained; this was not a source-copy, default-value or decoder-only test.

The released v0.1.0/v0.3.0 WIT definitions and the committed `0b84ab0f`
definition also resolve to the same actual Git blob,
`86c3f0e739057aa08c460bda06f1a42c9679d87e`. That confirms the legacy definition's
lineage without substituting today's component binary for the older binaries.
The final IO 0.2 adapter and subsequently integrated product still require
the same frozen consumer to pass again; this checkpoint does not certify them.


## Source guards for all six contracts

The ordinary source tests cover these distinct boundaries:

| Contract | Compatibility guard | Required product evidence |
| --- | --- | --- |
| Log format v1 | Pinned complete released-producer catalog, unchanged manifests/inventory, and exact original-root assertions | The actual candidate reads or explicitly upgrades every published `0.x` corpus, preserves bounded state/log integrity, and identity-replays every original root |
| WIT `kronik:actor@1.0.0` | Selected-baseline ABI tokens, ignoring comments/layout but not field order, types, ownership or package identity; strict actual migration-error decoding | Genuine old components execute, or the product gives the clear migration response above and current components really execute; intended WIT 1.0 itself must first exist |
| API `/v1` | Every baseline method/path, authorization/scope, parameter serialization, required body, status/header/media type and request/response schema | Existing generated-schema and routed-API checks bind the source to the real binary; actual public consumers must pass against that same candidate |
| CLI JSON | Every baseline command's JSON availability/output variants and typed error response; transitive schema references, types, fields, requiredness, nullability, enums and defaults | The existing typed-schema/Clap inventory tests keep the generated page complete; real CLI consumers must pass against the coherent candidate |
| `kronik.diff/v1` | Full selected schema, including its real version constant and referenced definitions, plus API/CLI semantic-summary agreement | Existing real-diff schema tests and the released-component public diff consumer |
| Policy language | Versioned `tests/compatibility/policy-cases.json`: strictest-action precedence, no-match default, errors, short-circuiting, actual diff values, arithmetic, membership, collections, string methods and presence | Each case is evaluated by the actual public `/v1/policy/test` implementation; no second policy interpreter or source-copy assertion |

`scripts/compatibility-contracts.py` is a conservative **source comparison**:
requests must continue to accept old inputs, while new responses must still
satisfy old consumers. It follows internal schema references, including
transitive and recursive definitions. Descriptions, examples and layout are
not wire contracts; changed defaults, closed objects, enum variants and
unknown changed validation keywords cannot silently pass. Unsupported schema
constructs fail closed and need a concrete compatibility proof, not a bypass.
Newly named properties must also preserve the old `additionalProperties`
contract: an optional integer field can reject previously accepted string
requests, or violate an old string-valued response map. Optionality alone is
not compatibility; declaring the same previously accepted value type is.
Enum, constant and default values use JSON equality, including nested values:
`true`/`false` are not `1`/`0`, while equal JSON numbers such as `1` and `1.0`
remain equal.

An explicitly reviewed baseline can be compared with a source checkout:

```sh
python3 scripts/compatibility-contracts.py \
  --baseline tests/compatibility/v0.3.0/contracts \
  --candidate-root .
```

The historical directories are **lineage and comparison inputs**, not a claim
that all pre-v0.9 API/error-enum changes were forbidden. This command can reject
a deliberately documented pre-freeze change. It is not newly wired into
today's CI as a global freeze gate. The Swedish brief starts the interface
promise after v0.9; the separate old-log requirement already covers every
published `0.x`. No empty, future or invented v0.9 baseline is checked in.
Once a coherent product actually meets the acceptance criteria, retain its
reviewed source snapshots and provenance as the declared freeze baseline and
make this comparison against that exact baseline required. A successful
source comparison alone never proves the binary, old-WIT adapter or freeze.

For each newly published actual `0.x` release, update the declared catalog and
add its case together: pinned published binary/source identity, unchanged
producer data/manifest, the observed original root count, genuine tagged
components, and exact tagged contract source bytes with Git-blob and SHA-256
identities. Do not delete a published release to make the matrix green, rewrite
old bytes for a new engine, or replace a tagged component with a new build.
The currently retained v0.1.0/v0.3.0 snapshots were read directly from source
commits `4353863c275e1ddbe978c7701181cc7ac26f9db5` and
`86d5a4bb92432d1acaf2cf8bec3188f9963dff76`.

Ordinary Python behavior tests and explicit source-CLI comparisons do not run
the Kronik product, upgrade/replay an old log, or prove a production WIT
migration rejection. The historical checkpoint receipts above remain
historical. These source guards do **not** declare WIT 1.0, current coherent
product acceptance, the v0.9 freeze or a v1/v2 support window already in force.

### Narrow source-verification receipt

`<internal-evidence>` retains the exact lightweight observation,
raw outputs and read-only inputs. The tested source identities are:

| Source | SHA-256 |
| --- | --- |
| `scripts/compatibility-contracts.py` | `ddddce87b3b24d48ebc4179936b23f73a4d7bae7b686ab29839183b6cd8dc984` |
| `scripts/tests/test_compatibility_contracts.py` | `1f7d2b92b72d686747d5bcbbcaf6ecacde245d85cbf29eb43087e1864a9fdb3b` |
| `scripts/tests/test_compatibility.py` after the private-copy fix | `e73f41e1fef0b37b0210b638b8137f7e8a6cc6f2d2d5ff0ff59fb43fded40e00` |

There were 58 initial successful cases and three initial private-copy
permission errors; only those three were corrected and resumed successfully,
with zero skips and no fresh whole-suite rerun. The two real source-CLI
pass/fail pairs and total 2.140556-second outer observation are separate from
any production acceptance. The owned driver/control scaffolding was removed;
the raw failure/success outputs and exact read-only source evidence remain.
Mutable candidates existed only in the two finite `--rm` containers' tmpfs.
