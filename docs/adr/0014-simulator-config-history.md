# 0014. Simulator configuration is a log record, applied as of the fork point

- **Status:** Accepted (revised after the v0.3 review: the first version
  applied the configuration at the window's end, which deviated from I5
  without the owner's sign-off)
- **Date:** 2026-10-26

## Context

M12 adds per-target simulator configuration (stub rules, an OpenAPI
contract, `RecordedNeighbor`, the model simulator) set with `kronik stubs
set`. I5 says configuration that affects behavior is history: a log record,
seen by a fork as it was at its fork point. Invariants are not changed by
agents (AGENTS.md). An operator usually sets simulator configuration after
a proposal's diff shows `FailClosed` answers, at an LSN after the proposal's
fork point. Formats need a versioned schema and a compatibility fixture
(SPEC, "Format changes").

## Decision

- A new record `SimulatorConfig` (envelope kind 15) in
  `proto/kronik/log/v1/config.proto`, with an epoch and an `Audit`, one per
  target, replacing that target's configuration. It is written through
  `Node::commit_config` under the deploy lock like grants, kept in
  `config_records`, and folded into `Config`.
- `EffectRecord` gains `string simulator = 13`, the label of a synthetic
  answer. Old readers ignore it; old records read as empty.
- A replay uses main's simulator configuration as of its **fork point**
  (I5), like grants and limits, plus the per-target `simulator_overrides`
  the replay or proposal request itself carries (the fields of `PUT
  /v1/simulators/{target}`; each replaces main's configuration of its target
  for that fork). The overrides are kept in the fork's options
  (`proposal.json`), so catch-up and the replay after a restart use the same
  configuration; the diff records both the overrides and the configuration
  it used in `options.simulators` (`request: true` for an override).
- Compatibility fixtures: the protobuf bytes of a `SimulatorConfig` and of
  an `EffectRecord` with `simulator` are committed under
  `crates/kronik-proto/tests/fixtures/` with a test that decodes them and
  checks every field.

## Alternatives

- **As of the window's end.** The first M12 version. It lets configuration
  set after the fork point apply to an existing proposal, but a fork then
  sees configuration that did not exist at its fork point (an I5
  deviation), catch-up mixes two configurations within one proposal, and a
  replay after a restart can give different bytes.
- **Configuration in `kronik.toml`.** Not history: two replays of the same
  window on different days could differ silently, and a fork could not show
  what its diff rested on.
- **Per-proposal only (the M3 `stubs` request field).** Kept, and consulted
  first; but contracts and neighbor settings belong to a target and are
  reused by every proposal created after they are set.

## Consequences

- `GET /v1/simulators` shows each target's configuration in force with the
  LSN, epoch and reason of its record; earlier records stay in the log
  (`kronik history` is per actor and does not list them).
- A diff is reproducible from the log and the fork's options alone: fork
  point, window end, and the request's overrides.
- To apply new simulator configuration to an existing window, replay or
  propose again with `simulator_overrides` (`kronik replay --simulators
  TARGET=FILE`), or propose again after `kronik stubs set`.
- Kind 15 is taken; branches that add records must take later numbers.
