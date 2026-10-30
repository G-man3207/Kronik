# The GitHub flow, as a repository

This directory is what goes in a repository that runs Kronik's
[GitHub Action](../../docs/guides/github-action.md):
- one Rust actor, `counter`, as `kronik init --lang rust counter` makes it;
- the reference workflow in `.github/workflows/kronik.yml`.

With it, pull requests are proposed with a comment and a check, and after a
merge to main the change is promoted once a reviewer approves.

> **Public GitHub acceptance is not yet complete.** The reusable workflow below
> still needs a reachable daemon and repository settings. Kronik's root workflow
> now has a real, locally exercised TLS/persisted-proposal fixture (below);
> local success is not evidence of a GitHub PR, check/comment or human gate approval.

The files are kept in step with Kronik itself:
- `kronik.yml` is `docs/examples/kronik-ci.yml`, byte for byte. A test in
  `action/tests` checks this.
- The actor is `kronik init`'s Rust template for the name `counter`. A test
  in `crates/kronik/src/project/init.rs` checks this.
- `vendor/kronik-sdk` (the SDK and the WIT) is not here. `kronik init`
  writes it from the binary (step 2).

## This repository's bounded proof

The root [proof workflow](../../.github/workflows/kronik.yml) uses
[`scripts/e2e-github-flow.py`](../../scripts/e2e-github-flow.py), not the external
daemon/secrets setup below. Its strict manifest path is
`examples/github-flow/proof/change.json`; the first actual proof PR will create:

```json
{"component":"counter-step2.wasm","reason":"M10 public proof, first head"}
```

A second PR head changes only the reason, after the first actual check/comment
exists, to prove that the same comment is updated for the new head/proposal.
The only other allowed component is the hash-pinned `counter.wasm` baseline.
No manifest is committed with this preparation, so installing the workflow
does not itself start a proof run.

Each job allocates a bounded, non-root daemon in an owned internal Docker
network, with no published host port or external route. The runner reaches
its private bridge address using a freshly issued certificate for that exact
address; wrong/missing trust and missing/wrong tokens fail. The public v0.3.0
binary is hash-pinned and remains the historical Wasmtime 50.0.0 binary,
not an engine security update. No Rust/guest build is added.

`verify` stops the real daemon cleanly and uploads only the synthetic state,
code, proposal/diff and correlation metadata. Plaintext bearer/bootstrap/master
credentials and all private CA/TLS keys are excluded; unknown-file bearer or
private-key material is refused. A digest binds both archive and metadata to
the repository, exact head, run, attempt and proposal. After the actual GitHub
gate, `promote` restores it without proposing again. It creates a fresh
`read,approve,promote` token through the existing real Unix-authenticated operator
CLI and verifies that proposal/code/diff bytes remain unchanged despite allowed
credential audit records. The final check inspects the actual Approval record,
deployment, integrity result and changed HTTPS response. The synthetic fixture's
public encryption seed is not a production key.

The configured `kronik-production` environment has only reviewer `G-man3207`
(user ID 113182292), prevents review, disallows administrator bypass and
allows only branch `main`; these properties were read back from GitHub.
The main event must be authored by a genuinely distinct installed App bot,
then actually approved by that human. No dispatch/PAT approval substitutes
for either step. Fork PRs are skipped; an actual prior-head promotion attempt
must fail without changing the evaluated proposal or deployments.

Local smoke, with the exact public binary already installed:

```sh
KRONIK_BIN=/absolute/path/to/kronik \
GITHUB_REPOSITORY=G-man3207/Kronik GITHUB_SHA=$(git rev-parse HEAD) \
GITHUB_RUN_ID=10001 GITHUB_RUN_ATTEMPT=1 \
python3 scripts/e2e-github-flow.py smoke
```

This performs real local product approval with an explicit **not GitHub approval**
reason. It cannot satisfy the still-pending public PR/updated comment/check,
App-authored merge, actual human environment approval and main promotion.
Publishing branches or triggering those runs is separately director-batched.


## 1. A daemon GitHub can reach

On the server, run `kronik serve` with TLS and the API on a public address.
In the config file:

```toml
[tls]
mode = "acme"
domains = ["kronik.example.com"]
acme_email = "ops@example.com"

[server]
api_listen = "0.0.0.0:7443"
```

Without TLS, `api_listen` refuses a non-loopback address. Then deploy the
first version of the actor from a checkout of the repository (step 2):

```sh
kronik build
kronik deploy dist/counter.wasm --reason 'first deploy'
```

Make two tokens, each with the least it needs:

```sh
kronik token create --name ci-propose --scopes read,propose --reason 'GitHub: propose and verify'
kronik token create --name ci-promote --scopes read,approve,promote --reason 'GitHub: promote after review'
```

## 2. The repository

```sh
gh repo create <owner>/kronik-github-flow --public --clone
cd kronik-github-flow
kronik init --lang rust counter    # with the kronik of the release you pin below
cp -r counter/. . && rm -r counter
mkdir -p .github/workflows
cp <kronik checkout>/examples/github-flow/.github/workflows/kronik.yml .github/workflows/
cargo test                         # the actor in a test host (kronik on PATH)
git add . && git commit -m 'counter' && git push -u origin main
```

In `kronik.yml`, replace the commit after every `G-man3207/Kronik/action@`
with the commit of the Kronik release whose files `KRONIK_BASE_URL` points
to. The `Build` steps run `kronik build`. On GitHub's Ubuntu runners rustup
installs the toolchain and the `wasm32-wasip2` target that
`rust-toolchain.toml` pins, on first use.

## 3. Settings

In the repository's settings:

| Where | Name | Value |
| --- | --- | --- |
| Variables → Actions | `KRONIK_BASE_URL` | Where one release's files are: `kronik-x86_64-unknown-linux-musl` and `SHA256SUMS` (a versioned URL, not a "latest" one) |
| Secrets → Actions | `KRONIK_URL` | `https://kronik.example.com:7443` |
| Secrets → Actions | `KRONIK_TOKEN` | The `ci-propose` token (`read`, `propose`) |
| Environments | `kronik-production` | Required reviewers, "Prevent review" on, administrators may not bypass, deployment branches: `main` only |
| Environment `kronik-production` → secrets | `KRONIK_URL` | As above |
| Environment `kronik-production` → secrets | `KRONIK_TOKEN` | The `ci-promote` token (`read`, `approve`, `promote`) |

The promote token lives only in the environment. So a job reaches it only
after a reviewer approves, and only on main.

This workflow retains its published Action pin and the original, available
`v0.3.0` raw-binary distribution. The current checkout's archive installer
instead needs `kronik-<arch>-unknown-linux-musl.tar.gz` and its `.sha256`
sidecar, including the real license/notice files. Both supplemental archives
are now public at the same `v0.3.0` release URL; no historical assets or Action
pins were replaced. They retain the exact Wasmtime 50.0.0 binaries, not the
current source's 50.0.1 security patch. See the
[installation guide](../../docs/guides/install.md) before changing the pin.

## 4. A change, end to end

On a branch, make the counter count by 2: in `src/lib.rs`, change
`.unwrap_or(0) + 1` to `.unwrap_or(0) + 2`. Push the branch and open a pull
request to main. Send a few requests first, so there is traffic to replay
(`curl -X POST https://kronik.example.com/counter/a/increment`).

A successful run shows:

1. **On the pull request**, the `propose` job:
   - a check run named `Kronik proposal`, whose conclusion follows the
     policy (`success` for `allow`, `neutral` with a note for
     `require_approval`, `failure` for `deny`);
   - one comment from `github-actions[bot]` with the proposal's summary
     (`kronik diff show --summary`). That summary has counts, routes and
     hosts, but no bodies and no state values.

   A later push updates the same comment.
2. **After the merge**, the `verify` job proposes main's components again and
   puts the summary in its job summary. Its output `proposal-id` is the
   proposal, `p-…`.
3. The `promote` job waits for a reviewer of `kronik-production`. The
   reviewer reads `verify`'s summary and approves the run in GitHub. On a
   re-run of the workflow (run attempt 2 or later), the approval's comment
   must name the proposal id.
4. `promote` then approves the proposal in Kronik when the policy asks for
   it, naming the GitHub reviewers, and promotes exactly that proposal.
   The job's summary says `Promoted: epoch …, lsn …`.
5. On the server, `kronik deployments list` shows the `promote` deployment.
   `POST /counter/a/increment` now counts by 2.

What does not happen:
- A pull request from a fork is not proposed. The job's `if:` skips it, and
  so does the action.
- A promote for a commit that is no longer main's head promotes nothing: it is
  skipped when a newer push run of the workflow exists to promote the new
  head, and fails otherwise.
- Without the reviewer's approval, nothing is approved or promoted.
