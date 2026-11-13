# 0110. Hosted workflows start only by hand

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

`.github/workflows/ci.yml` started on every push to `main` and every pull
request. `.github/workflows/nightly.yml` also started from a daily cron. Those
runs use GitHub-hosted runners, and hosted-runner minutes are finite. Starting
the full suite on every push, and the long checks every night, spends that
allowance whether or not anyone needs the run. The nightly jobs are allowed
hours each, and one night starts all of them.

The checks themselves are unchanged. `scripts/ci.sh` is still the local run of
the CI steps. The nightly commands (`scripts/chaos.sh`, `scripts/dst.sh`,
`scripts/release.sh`) still exist and still match the Definition of done
volumes in [ADR 0004](0004-deterministic-simulation.md): 200 seeds in an
ordinary CI run, 10,000 seeds and a million-step run in the long workflow, and
a 1,000-cycle crash test. What changes is only when GitHub starts them.

The Release workflow was already `workflow_dispatch` only
([ADR 0100](0100-signed-reproducible-releases.md)). The synthetic M10 workflow
(`.github/workflows/kronik.yml`) is not a general build. It starts only when
`examples/github-flow/proof/change.json` changes, on a real pull request or a
real push from a distinct App bot. A dispatch cannot stand in for those events,
and no manifest is committed, so that workflow does not spend minutes by being
installed.

## Decision

`ci.yml`, `nightly.yml` and `release.yml` start only from `workflow_dispatch`.
No `push`, `pull_request` or `schedule` trigger. A hosted run happens only when
someone starts it from the Actions tab or with `gh workflow run`.

One manual nightly run still starts every job in that workflow. Run the same
commands locally when a hosted run is not needed.

Do not convert `.github/workflows/kronik.yml` to `workflow_dispatch`. Its jobs
require a real pull request and a real bot push; a manual run would not be the
proof, and the workflow must not grow a dispatch path that pretends to be one.

## Alternatives

- **Keep the triggers and disable the workflows in the GitHub UI.** The
  allowance is safe only until someone re-enables them. The repository would
  still say that a push starts CI.
- **Path filters or a cheaper runner.** A push would still start work, and the
  nightly cron would still spend minutes every day.
- **Make the proof workflow manual too.** That would either no-op (its jobs
  refuse a dispatch) or weaken the rule that a dispatch is not an approval.

## Consequences

- A pull request is not checked on GitHub unless someone starts CI on that
  ref. `scripts/ci.sh` is the check to run before pushing.
- The WASI 0.3 gate job no longer reports every night. It still runs when the
  nightly workflow is started, and its unit tests still run in `scripts/ci.sh
  action`.
- Revisit this if hosted minutes stop being the constraint, or if a required
  status check has to follow every pull request again. Restoring a push or
  pull-request trigger on `ci.yml` must ignore
  `examples/github-flow/proof/change.json`, which remains the proof workflow's
  only path.
