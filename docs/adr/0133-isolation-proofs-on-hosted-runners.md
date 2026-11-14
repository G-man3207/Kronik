# 0133. The isolation proofs run on GitHub-hosted runners

- **Status:** Accepted (2026-11-14)
- **Date:** 2026-11-13
- **Relates to:** ADR 0064 (the conformance proof), ADR 0095 and 0096 (the
  microVM level), ADR 0110 (hosted workflows start only by hand)

## Context

M20 and M21 are accepted only on evidence that the code and its unit tests
cannot give (ADR 0064, "Evidence boundary"): the installed nonroot service
running the v0.1 demos, a hostile actor that fails to reach its host, a
Firecracker VM booted on real KVM, and Ubuntu 24.04 with AppArmor's
restriction on unprivileged user namespaces (R1), the brief's install
target. None of it had run.

The proofs change their host on purpose. The installed fixture starts a
transient unit of the host's service manager that keeps most of root's
capabilities in the host's user and network namespaces, opens listeners on
the host's own addresses, and keeps a tree of copies; the boundary driver pins
user namespaces; the jobs install runsc, give `/dev/kvm` to the `kvm` group
with a udev rule and set `kernel.apparmor_restrict_unprivileged_userns`. Their
`create` refuses a host whose operator has not declared it disposable. A
machine that also runs anything else - a production application in Docker,
say - is not such a host, however well the fixture contains itself: a defect in
the system under test, or a sandbox escape, would act with near-root authority
on it.

GitHub's standard Linux runners for public repositories are disposable
virtual machines with Ubuntu 24.04, systemd 255, passwordless sudo and, with a
udev rule, a usable `/dev/kvm`
([changelog, 2024-04-02](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/)).
Each job gets a fresh one and loses it at the end.

## Decision

The proofs run in `.github/workflows/isolation.yml`, started only by hand
(ADR 0110), through `scripts/isolation-ci.py`, whose host-changing steps refuse
to run outside a GitHub-hosted runner (`GITHUB_ACTIONS=true`,
`RUNNER_ENVIRONMENT=github-hosted`):

- **m21**, twice: the `rootless_boundary` driver, then the installed fixture
  with the hostile `foreign-probe` actor and the program proof (the demos,
  Postgres fork, UID audit, ship and restore). Once with Ubuntu's restriction
  active, through `scripts/proof-rootless.sh` (R1), and once with it lifted
  through ADR 0064's explicit commands, so that a failure caused by R1 can be
  told from one that is not. A run records the restriction's value on the
  image and whether the job changed it; one with the restriction lifted says
  that it did not exercise R1.
- **microvm-tools**: `scripts/build-microvm-tools.sh` on the runner, cached
  with `actions/cache` under a key made from the recipe's inputs, so that a
  rerun restores the bundle instead of compiling a kernel again.
- **m20**: the fixture with microVM actors on KVM, after the job has proved
  the KVM API (version 12, a VM created and closed), with the restriction
  active. The device is the `kvm` group's (0660), not everyone's as in the
  Android emulator's recipe: the nonroot unit opens it through its own grant
  (the `SupplementaryGroups=` that `serve --init` writes), so the proof shows
  that the grant works.

Each job marks its runner disposable, picks ids and a subordinate range that
nobody uses, collects its evidence (text only: no key, image, disk or
database) and uploads it, and then fails unless every proof it owes left its
record with a pass. A missing record is a failure, so a proof that was
skipped cannot pass.

CI's `foreign` step runs a bounded version of the hostile actor on every CI
run (M21's "the test lives in CI"): under the root daemon, in gVisor, the
probe tries the host's listeners, files, processes, devices and directories
and a neighbouring sandbox, in about ten seconds. The workflow is the full
proof.

## Alternatives

- **The remote test host.** It runs a production application in Docker; the
  proofs would run beside it with near-root authority. Refused.
- **A self-hosted runner or a rented KVM machine.** Equivalent proof, but a
  machine to maintain and to wipe between runs; the hosted runner is wiped by
  construction.
- **Lift Ubuntu's restriction for every run.** It would hide R1, which is the
  open question of the install target.

## Consequences

- The proofs cost hosted minutes only when someone starts the workflow. A run
  takes hours: the kernel build the first time, the release build and the
  TypeScript examples each time.
- The evidence is a public artifact of the run (30 days). It holds no key and
  no secret value; it does hold the runner's addresses and the run's random
  tokens.
- What a run proves is what its artifact records, on the runner image of the
  day. A result on a hosted runner says nothing about bare metal or another
  distribution, and a cached tool bundle was built on an earlier image of the
  same runner (its provenance says which).
- Nothing here has been run yet. The workflow is written against the runner as
  documented; the first runs are expected to need fixes, and those runs, not
  this ADR, are the evidence.
