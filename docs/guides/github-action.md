# The GitHub Action

The official GitHub Action, in `action/` of the Kronik repository, drives a
remote Kronik daemon from CI with `kronik`'s own commands:

- on a pull request it proposes the pull request's components, waits for the
  proposal, creates a check run whose conclusion follows the policy and
  comments the proposal's summary on the pull request;
- after the merge, a `verify` job proposes main's components the same way and
  puts the summary in its job summary; a `promote` job, in a protected GitHub
  environment, then promotes exactly that proposal.

The human approval is GitHub's: a required reviewer of the
`kronik-production` environment approves the `promote` job after reading the
`verify` job's summary. Before the action approves a proposal whose policy
outcome is `require_approval`, it checks with GitHub that a reviewer approved
this run for that environment, and records the reviewers in the Kronik
approval. Without such an approval it approves and promotes nothing.

> **Not yet run on GitHub.** The action and the reference workflow are tested
> against a fake `kronik` and a fake GitHub API (`scripts/ci.sh action`).
> Running them in a real GitHub repository, against a real daemon, is an owner
> action that has not been done yet.

## What it does

Each run first installs `kronik` when `base-url` is set: it downloads the
binary for the runner's architecture (`kronik-x86_64-unknown-linux-musl` or
`kronik-aarch64-unknown-linux-musl`) and the release's `SHA256SUMS`, checks
the binary's SHA-256 and refuses it when the sum differs or `SHA256SUMS` has
no line for it, as `install.sh` does. It puts `kronik` on `PATH` for the
job's later steps and prints `kronik --version`. Without `base-url` it uses
the `kronik` already on `PATH`. The action needs a Linux runner with
`python3` 3.9 or newer, which GitHub's Ubuntu runners have.

`base-url` must be `https://` or `file://`, or `http://` to a loopback IP
address (`127.0.0.1`, `[::1]`): the binary and `SHA256SUMS` come from the same
place, so the checksum guards against corruption, not against whoever serves
both. Point it at one release's files (a URL with the version in it, not a
"latest" one), and pin the action to that release's commit.

Then, by `command`:

| Command | What it runs |
| --- | --- |
| `install` | Nothing more. |
| `propose` | `kronik propose <components> --async`, `kronik proposal wait`, `kronik diff show --summary`; then a check run named `Kronik proposal` on the commit and, on a pull request, one comment (created, then updated by later runs). |
| `promote` | `kronik proposal wait` and `kronik diff show --summary` for the proposal in the input `proposal`; then, when the outcome is `require_approval`, the GitHub approval check and `kronik approve`; then `kronik promote`. It refuses to run for a pull request event. |

Every `kronik` call is bounded by the input `timeout` plus a margin (the
smaller of `timeout` and one minute), so a stalled connection fails the step
with `TIMEOUT` instead of holding the job until GitHub's six-hour limit. The
default `timeout`, `45m`, is longer than a 30-minute replay; raise it, and the
jobs' `timeout-minutes`, for longer ones.

The check run's conclusion and the step's result follow the policy outcome:

| Outcome | Check run | Step |
| --- | --- | --- |
| `allow` | `success` | passes |
| `require_approval` | `neutral` | passes |
| `deny` | `failure` | fails |
| nothing to propose (`NOTHING_TO_PROPOSE`) | `neutral` | passes, with a notice |
| the proposal failed or timed out | `failure` | fails |

`require_approval` is `neutral`, not `action_required`: the approval comes
later, from the production environment after the merge, and a required check
that is `action_required` would block the merge that leads there. The comment
and the check run say that an approval is needed.

Nothing to propose means main already runs every component, as on a pull
request that changes only documentation: the comment and the check run say
that nothing changed, the outputs are `proposal-id` empty, `outcome` `none`
and `status` `unchanged`, and the reference workflow skips `promote`.

### The comment

The comment starts with the hidden marker `<!-- kronik-proposal -->`. The
action updates only a comment that starts with the marker and was written by
`github-actions[bot]`, the author of comments made with the default
`GITHUB_TOKEN`; a comment by anyone else with the marker is left alone, and
the action adds its own. With another `github-token` (a personal or app
token), each run therefore adds a new comment. The check run is created
before the comment is touched.

The comment names the commit it reports on. When the pull request's head has
moved past that commit by the time the run finishes (a newer push), the action
leaves the comment to the newer run, with a notice; the check run is still
created on its own commit. The reference workflow also cancels the older
run (`concurrency` per pull request).

The summary is `kronik diff show --summary`: per component, the counts of
changed origins and effects; grounding per effect kind, HTTP method and host
(a host reached through a wildcard grant such as `http:*.example.com` is shown
as the grant's pattern, `*.example.com`, and a host without a grant as
`(no grant)`; a method other than a route method shows as `(other)`, and a
kind that is not deployed as `(undeployed kind)`, since the proposed code
chooses those strings), never a route or a path; and the
rules that fired. It has no request or response bodies, no state keys or
values and no error messages, so it is safe for a public pull request. The
same text goes to the job summary.

Errors are posted as their code and hint. The daemon's address is a secret
(`KRONIK_URL`), and GitHub masks secrets only in logs, not in comments or
check runs, and only as written (not with another case or without a trailing
slash), so the action replaces the address (its host in any case), any other
`host:port` and the names in a certificate error, in what it posts, in its
error line and in kronik's stderr.

### The approval check

When the outcome is `require_approval` and the proposal is not approved in
Kronik yet, `promote` asks GitHub for the run's approvals
(`GET /repos/{repo}/actions/runs/{run_id}/approvals`, which needs
`actions: read`) and requires one with the state `approved` for the input
`environment` (default `kronik-production`, the job's environment). It then
runs `kronik approve` with a reason that names the reviewers, their comments
and the run. On a re-run (`GITHUB_RUN_ATTEMPT` above 1) only an approval
whose comment names the proposal id counts, since the run's approvals can
include an earlier attempt's, given for another proposal: re-run the job and
approve the deployment with a comment such as `p-... looks right`. Without
such an approval (an environment without required
reviewers, an administrator who bypassed them, a job without
`environment:`), the step fails without approving or promoting, and prints
the command for a person who reviewed the proposal to run, such as:

```sh
kronik approve p-... --reason 'reviewed proposal p-... of owner/repo: https://github.com/owner/repo/actions/runs/...'
```

Re-run the job after that: a proposal already approved in Kronik is promoted
without the GitHub check. A proposal whose outcome is `allow` needs no
approval and is promoted directly; a proposal already promoted passes with a
notice.

Before it approves or promotes, `promote` checks that the commit it runs
for (`GITHUB_SHA`) is still the head of its branch (`GITHUB_REF`, through
`GET /repos/{repo}/git/ref/heads/...`, which needs `contents: read`). When
the branch moved on, it promotes nothing: an older commit's proposal would
put its code back over the newer commit's. It then looks for a newer push run
of the same workflow on the branch (`GET
/repos/{repo}/actions/workflows/{workflow}/runs`, `actions: read`): a run with
a higher id than this one, for another commit. If there is one, that run
promotes the newer commit, and this step passes with a notice and the status
`skipped`. If there is none, nothing would promote the branch's head, so the
step fails, telling to re-run the workflow for the new head or printing the
`kronik promote` command for a person. A GitHub API error fails the step.

Required reviewers are a GitHub plan feature: on Free, Pro and Team they work
only in public repositories; on Enterprise in any repository. Environment
secrets work without them, which is why the action checks for the approval
itself. In the environment's protection rules, turn on **Prevent
self-review** and turn off **Allow administrators to bypass configured
protection rules**.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `command` | (required) | `install`, `propose` or `promote`. |
| `base-url` | empty | Where one release's files are (`https://`, `file://`, or `http://` to a loopback IP). Empty: use the `kronik` on `PATH`. |
| `components` | `dist` | Whitespace-separated `.wasm` files, globs or directories, searched for `*.wasm`. |
| `proposal` | empty | `promote`: the proposal to promote, the `verify` job's `proposal-id`. Empty: nothing to promote, with a notice. |
| `environment` | `kronik-production` | `promote`: the job's environment, whose approval of the run is required for `require_approval`. |
| `reason` | the pull request or commit, the actor and the run URL | The reason recorded with the proposal and the promotion. |
| `window` | `kronik propose`'s | The replay window, such as `1h`. |
| `timeout` | `45m` | How long `kronik proposal wait` waits (`ms`, `s`, `m` or `h`); also bounds every `kronik` call. |
| `allow-forks` | `false` | Propose for pull requests from forks, and on the events below, too. |
| `github-token` | `${{ github.token }}` | The token for the check run, the comment and the run's approvals. |
| `comment` | `true` | Create or update the pull request comment. |

## Outputs

| Output | Meaning |
| --- | --- |
| `proposal-id` | The proposal's id, `p-...`; empty when there was nothing to propose. |
| `outcome` | `allow`, `require_approval` or `deny`; `none` when there was nothing to propose; `error` when the proposal failed. |
| `status` | The proposal's status, such as `evaluated`, `approved`, `rejected` or `promoted`; `unchanged` when there was nothing to propose; `skipped` when `promote` left the proposal to a newer run because the branch moved on; `failed` when it failed. |

## Connection and tokens

The action reads the daemon's address and token from the environment, as
`kronik` does: `KRONIK_URL` (`https://host:port`) and `KRONIK_TOKEN`. Pass
them to the step's `env` from secrets. The token never goes on a command
line: `kronik` reads `KRONIK_TOKEN` itself, so it stays out of process lists
and logs, which is why the environment is preferred to a `--token` flag. The
action also masks it with `::add-mask::`, and does not pass the GitHub token
to `kronik`.

Give each place the least it needs (see
[kronik token create](../reference/cli.md#kronik-token-create)):

- the repository secret `KRONIK_TOKEN`, used by `propose` and `verify`: the
  scopes `read` and `propose`;
- the `kronik-production` environment's secret `KRONIK_TOKEN`, which takes
  the place of the repository secret in jobs that run in that environment:
  `read`, `approve` and `promote`.

Give the environment required reviewers, and main as its only deployment
branch, so that a pull request that adds `environment: kronik-production` to
its own job cannot reach the promote token unreviewed.

## Forks and triggers

The supported triggers are `pull_request`, `push` to main and
`workflow_dispatch`. Pull requests from forks are skipped by default, with a
notice, and the step passes. A fork's code is untrusted: proposing it would
run its components on your daemon with your token, and GitHub does not give
secrets to `pull_request` runs from forks anyway. The reference workflow
skips forks with an `if:` on the job, and the action checks again by itself
(the pull request's head repository against its base repository), so a
workflow that forgets the `if:` still does not propose a fork's code.

`propose` refuses to run on `pull_request_target`, `workflow_run` and
`issue_comment` events: they run with the secrets, and their code can come
from a fork without a pull request in the event to check. `allow-forks: true`
turns both checks off, for a private repository that sends secrets to fork
pull requests on purpose.

## The reference workflow

`docs/examples/kronik-ci.yml`, below, proposes on every pull request to main
from the repository itself, and verifies and promotes on every push to main.
Copy it to `.github/workflows/kronik.yml` in the repository of your actors,
replace the `kronik build` placeholders with your build, replace the Kronik
action's commit SHA with the commit of the release `KRONIK_BASE_URL` points
to, and set the variable, secrets and environment its header names.
`examples/github-flow` in the Kronik repository is a whole
repository's content with this workflow and a Rust actor, and the steps to
run the flow on GitHub end to end.

```yaml
{{#include ../examples/kronik-ci.yml}}
```

It runs on `pull_request`, never `pull_request_target`, which would run a
fork's code with the secrets. Every action is pinned to a full commit SHA, and
`actions/checkout` keeps no credentials (`persist-credentials: false`). Each
job has only the permissions it needs: `propose` `contents: read`,
`pull-requests: write` and `checks: write`; `verify` `contents: read` and
`checks: write`; `promote` `actions: read`, to read the run's approvals and the workflow's newer runs, and
`contents: read`, to read the branch's head.
Each job has a `timeout-minutes`.

`propose` runs once per pull request at a time: a new push cancels the older
run. `promote` needs `verify` and runs only when `verify` proposed something;
the reviewers approve it after `verify`'s summary is there, and it promotes
exactly that proposal, so what they approve is what reaches production. Its
`concurrency` group runs one promotion at a time; GitHub keeps at most one
pending run in a group, so a newer pending promotion cancels an older pending
one. When another promotion lands between `verify` and `promote`, `promote`
fails with `PROPOSAL_STALE`. Do not re-run that run: its commit is no longer
the newest, and its proposal would undo newer code (the re-run promotes
nothing anyway: it skips when a newer run exists, and fails otherwise). Re-run
the newest run on the branch, or push a new commit.
