# The GitHub flow, as a repository

This directory is what goes in a repository that runs Kronik's
[GitHub Action](../../docs/guides/github-action.md):
- one Rust actor, `counter`, as `kronik init --lang rust counter` makes it;
- the reference workflow in `.github/workflows/kronik.yml`.

With it, pull requests are proposed with a comment and a check, and after a
merge to main the change is promoted once a reviewer approves.

> **Not yet run on GitHub.** The workflow and the action are tested against a
> fake `kronik` and a fake GitHub API (`scripts/ci.sh action`). Running this
> flow needs a repository and a Kronik daemon that GitHub's runners can
> reach, which are the owner's to set up. Nothing below has been run on
> GitHub yet.

The files are kept in step with Kronik itself:
- `kronik.yml` is `docs/examples/kronik-ci.yml`, byte for byte. A test in
  `action/tests` checks this.
- The actor is `kronik init`'s Rust template for the name `counter`. A test
  in `crates/kronik/src/project/init.rs` checks this.
- `vendor/kronik-sdk` (the SDK and the WIT) is not here. `kronik init`
  writes it from the binary (step 2).

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
| Environments | `kronik-production` | Required reviewers, "Prevent self-review" on, administrators may not bypass, deployment branches: `main` only |
| Environment `kronik-production` → secrets | `KRONIK_URL` | As above |
| Environment `kronik-production` → secrets | `KRONIK_TOKEN` | The `ci-promote` token (`read`, `approve`, `promote`) |

The promote token lives only in the environment. So a job reaches it only
after a reviewer approves, and only on main.

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
