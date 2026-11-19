# Security Policy

## Supported versions

Kronik is pre-alpha. The latest `v0.x` release and the latest commit on the
`main` branch receive security fixes. Do not run Kronik in production yet.

## Reporting a vulnerability

Do not report vulnerabilities in public issues, discussions or pull requests.

Report them privately through GitHub's private vulnerability reporting on the
project repository: open the repository's **Security** tab and choose
**Report a vulnerability**. Only you and the maintainers can see the report.

Please include:

- the affected component (crate, CLI command, API endpoint or SDK) and the
  commit or version;
- what an attacker can do, and what access they need, for example a deployed
  actor, an API token with certain scopes, a foreign actor image or network
  access;
- steps to reproduce, ideally with a minimal actor, configuration or script;
- whether the issue is public or known to others;
- whether and how you would like to be credited.

Do not send real secrets or personal data from a production system.

## What to expect

- We aim to acknowledge your report within 7 days and to share an initial
  assessment within 14 days.
- We keep you informed while we work on a fix and agree on a disclosure date
  with you. Please do not disclose the issue publicly before then.
- Once a fix is available, we publish a GitHub security advisory and credit
  you unless you prefer not to be named.

## Security model

Kronik assumes that actor code, foreign images and agents can be faulty or
hostile, and limits what each of them can do. Kronik is pre-alpha and its
interfaces may still change, but the controls below are implemented and in
the released versions. The
[project status page](https://github.com/G-man3207/Kronik/wiki/Project-status)
lists the tracks that are still absent or partial: the cluster (M16–M19), the
remaining WASI 0.3 work (M22), the UI, fleet and hardening tracks (M27 and
M29–M34), fuzzing and an independent external security review. Isolation is
not on that list: since v0.5.0 the nonroot service (M21) and the microVM level
(M20) are shipped, opt-in levels, and the root service remains the default.
The [security guide](docs/guides/security.md) covers each protection and its
known gaps.

- **Actors** run in a Wasm sandbox with a fresh instance per turn, default-deny
  capabilities, and fuel and memory limits.
- **Foreign actors** run in gVisor without external network access, with
  images pinned by digest and resource limits. An operator can choose
  `--isolation trusted` instead, which runs an image with plain `runc` on the
  host kernel and says so with a warning.
- **Agents and operators** use tokens with scopes. Policy and approvals gate
  changes. A caller without `pii:read` cannot receive personal data in a
  fork: the fork excludes it when the caller passes `--no-pii`, and always
  when the caller lacks that scope, so a token without `pii:read` always
  gets such a fork. A caller on the Unix socket without a token has every
  scope, including `pii:read`, so `kronik fork create` keeps production
  subject values unless `--no-pii`. That flag is how a local operator opts
  into a fork without personal data. Every mutation requires a reason and
  is recorded.
- **Secrets are handles.** The host inserts a secret value at the effect
  boundary, so it never reaches guest code or the log. Revealing a raw value
  requires the capability `secret-reveal:<name>`; exact occurrences are then
  scrubbed from logs and diffs, but code that has seen a value can always leak
  it.
- **The API** listens on a Unix socket protected by file permissions; TCP
  access requires a token, and external traffic uses TLS.
- **Root and isolation.** By default the daemon and `runsc` run as root under
  systemd, with the hardening that systemd allows
  ([ADR 0027](docs/adr/0027-systemd-unit-hardening.md)). The root service
  remains the default.
  `kronik serve --init --rootless` installs the opt-in nonroot service
  instead (M21; [ADR 0060](docs/adr/0060-non-root-daemon-user-namespace.md),
  [ADR 0062](docs/adr/0062-non-root-systemd-units.md)): the daemon runs as
  the `kronik` user, and `runsc`/`runc` run as namespace root inside a user
  namespace that user owns, not as host root
  ([ADR 0061](docs/adr/0061-runsc-in-the-kronik-user-namespace.md)). This is
  not `runsc --rootless`, which cannot run Kronik's sandbox network or
  checkpoints. The installed proofs passed on 2026-11-14 on GitHub-hosted
  Ubuntu 24.04 runners, once with the distribution's AppArmor restriction on
  unprivileged user namespaces active and once with it lifted; they have not
  run on other distributions or on hardware. The opt-in microVM level (M20)
  runs a foreign actor under a Firecracker VMM. The VMM runs as the daemon's
  host identity with every capability cleared and a PID namespace of its own
  ([ADR 0095](docs/adr/0095-pinned-firecracker-guest.md)). Both levels refuse
  an actor with a typed error when its host prerequisites are missing, instead
  of falling back to a weaker runtime.

**The data directory and the log are sensitive.** The log contains the whole
history of the system, including the random seeds that can recreate tokens
generated in a turn. Without privacy mode, the log is stored in plaintext; use
an encrypted disk. Treat the data directory, snapshots and shipped copies in
object storage as secrets.
