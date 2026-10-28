# M10 remote control from CI

Status: binding for M10. Builds on `m1-core.md` §4 (the API), M5 (tokens
and the TCP API listener) and `m3-fork.md` §8 (proposals); brief section
"v0.2: Hela system i CI", M10.

CI and operators reach Kronik without being on the server: the CLI talks to
the API over TLS, proposals run as jobs that outlive their client, a short
diff summary is safe for public pull requests, and an official GitHub
Action runs the flow. No new concept (I13): a proposal is still a fork with
a diff.

## 1. What already existed

- `server.api_listen` (M5): the JSON API and MCP on TCP, every request with
  a bearer token, HTTPS with the gateway's certificate when `[tls]` is on,
  loopback only without TLS. Tokens with scopes, recorded with mutations.
- `POST /v1/proposals` ran the replay inside the request.

## 2. What M10 adds

| Area | Change | ADR |
| --- | --- | --- |
| CLI | Global `--url` / `$KRONIK_URL` (`https://host:port`; `http://` only to a loopback host) and `--token` / `$KRONIK_TOKEN`; a rustls client with the system's roots (`SSL_CERT_FILE`). | 0021 |
| Proposals | A job per proposal (`Env::spawn`): statuses `running` and `failed`, `error`, `progress`; a restart fails running jobs. `POST /v1/proposals` takes `"async": true`. | 0022 |
| CLI | `kronik propose --async`; `kronik proposal status <id>`; `kronik proposal wait <id> [--timeout 1h]` (progress on stderr, exit 1 on failure or timeout). | 0022 |
| Errors | `PROPOSAL_RUNNING` (409): approve, promote, request-approval, diff, `send --fork` or `wait --timeout` on a running proposal. `NOTHING_TO_PROPOSE` (409): propose when main already runs every component (was `BAD_REQUEST`; ADR 0012 amendment). | 0022 |
| Diff | `format=summary` / `kronik diff show --summary`: an allow-listed short Markdown summary. | 0023 |
| CI | `action/` (composite GitHub Action, logic in `action/kronik_action.py`), the reference workflow `docs/examples/kronik-ci.yml`, the guide `docs/guides/github-action.md`, the CI step `scripts/ci.sh action`. | guide |

## 3. The job

`Proposals::propose_job` runs `prepare` (all checks, the fork point, the set,
the id) in the request, saves the `running` proposal, then spawns
`execute` (replay, diff, policy, save). A waiting request awaits the job's
done signal (a closed semaphore, not `watch`: ADR 0004's determinism
rules); a dropped request does not cancel it. `replay::Progress` holds
relaxed counters of isolated and continuous root inputs, done and to do.

## 4. The GitHub Action

`propose` on `pull_request` (never `pull_request_target`; `workflow_run`
and `issue_comment` refused too unless `allow-forks: true`): skipped for
pull requests from forks unless `allow-forks: true`, checked by the action
itself and by the reference workflow's `if:`; runs `propose --async`,
`proposal wait`, `diff show --summary`, then a check run (allow → success,
require_approval → neutral, `NOTHING_TO_PROPOSE` → neutral with a notice,
deny or failure → failure) and one PR comment: only a comment by
`github-actions[bot]` starting with the hidden marker is updated, it names
the head commit, and it is left alone when the head moved on. Errors are
posted as code and hint with the daemon's address redacted. Every `kronik`
call is bounded by `timeout` (default 45m, longer than a 30-minute replay)
plus a margin.

After the merge, a `verify` job (no environment, the `read,propose` token)
proposes main's components and outputs `proposal-id`; the reviewers of the
`kronik-production` environment approve the `promote` job (`needs: verify`)
with that summary in front of them, so the approval stands for that
proposal. `promote` promotes exactly that id: for `require_approval` it
first requires an `approved` entry for its environment in GitHub's
`GET /repos/{repo}/actions/runs/{run_id}/approvals` (`actions: read`) and
approves with a reason naming the reviewers (on a re-run, only an approval
whose comment names the proposal id counts); without one it fails and prints
the `kronik approve` command for a person. It promotes nothing when the branch's head is no longer the run's commit
(`contents: read`): with a notice (status `skipped`) when a newer push run of
the workflow exists to promote the head (`actions: read`), else it fails. `allow` is promoted without an
approval. `install` downloads the release binary and `SHA256SUMS` from
`https://`, `file://` or loopback `http://` and refuses a mismatch. Token:
`KRONIK_TOKEN` only in the environment, masked; `read,propose` for
`propose` and `verify`, `read,approve,promote` in the environment.

## 5. Compatibility

- API and CLI JSON: `ProposeRequest.async`, `ProposalInfo.progress` and
  `.error` are added; `policy` and `summary` may be null while `running`.
  A client that waited for `POST /v1/proposals` gets the same answer.
- No log or diff format change.

## 6. Tests

- `crates/kronik/tests/remote.rs`: the CLI over HTTPS with `$KRONIK_URL` /
  `$KRONIK_TOKEN` and with the flags; untrusted certificate; no token;
  plain HTTP to another host refused and to 127.0.0.1 accepted (criterion
  1); a proposal outlives its killed client, `status` and `wait` show
  progress at points held by the permits hook, `PROPOSAL_RUNNING` while
  running, `--async` (criterion 2).
- `crates/kronik-fork/src/markdown.rs` (unit) and
  `crates/kronik/tests/privacy_mode.rs::the_diff_summary_shows_no_bodies_or_values`
  and `::the_diff_summary_shows_no_url_paths`: the summary against a marker
  in every string field (only deployed kind names, hashes, codes, rule
  names, declared input patterns, route methods and grant patterns may
  show; any other method is `(other)`, any other kind `(undeployed kind)`), and
  against a real diff with privacy `on`, subjects, plain values and an
  e-mail address in an effect's URL path, through the API and the CLI
  (criterion 3).
- `action/tests/test_action.py` (`scripts/ci.sh action`): checksums and
  `base-url` schemes, fork pull requests and unsafe events refused by
  default (criterion 5), comment created then updated (only the bot's,
  not after the head moved), check conclusions, nothing to propose, the
  daemon's address redacted (also in the log and kronik's stderr), the
  `kronik` call timeout, the promote flow with and without a reviewer's
  approval (a re-run needs one naming the proposal; API errors fail), no
  promotion after the branch moved on (skipped with a newer run, failed
  without one or on an API error), the token never on a command line;
  the reference workflow's shape and pins (pinned to an ancestor) (criterion
  4 as far as it can be tested without GitHub).
- Owner action, not done: run the reference workflow in a real repository
  (criterion 4).
