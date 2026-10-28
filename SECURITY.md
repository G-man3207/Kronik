# Security Policy

## Supported versions

Kronik is pre-alpha and has no releases. Only the latest commit on the `main`
branch receives security fixes. Do not run Kronik in production yet.

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
hostile, and limits what each of them can do. Kronik is pre-alpha, so most of
the design below is not implemented yet; `STATUS.md` shows what is.

- **Actors** run in a Wasm sandbox with a fresh instance per turn, default-deny
  capabilities, and fuel and memory limits.
- **Foreign actors** run in gVisor without external network access, with
  images pinned by digest and resource limits.
- **Agents and operators** use tokens with scopes. Policy and approvals gate
  changes, forks have no access to personal data by default, and every
  mutation requires a reason and is recorded.
- **Secrets are handles.** The host inserts a secret value at the effect
  boundary, so it never reaches guest code or the log. Revealing a raw value
  requires the capability `secret-reveal:<name>`; exact occurrences are then
  scrubbed from logs and diffs, but code that has seen a value can always leak
  it.
- **The API** listens on a Unix socket protected by file permissions; TCP
  access requires a token, and external traffic uses TLS.
- **Root.** In v0.1 the daemon and `runsc` run as root under systemd, with the
  hardening that systemd allows. Rootless operation comes after v0.1.

**The data directory and the log are sensitive.** The log contains the whole
history of the system, including the random seeds that can recreate tokens
generated in a turn. Without privacy mode, the log is stored in plaintext; use
an encrypted disk. Treat the data directory, snapshots and shipped copies in
object storage as secrets.
