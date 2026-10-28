#!/usr/bin/env python3
"""The Kronik GitHub Action (action.yml runs it; docs/guides/github-action.md).

Installs kronik from a release (checking its SHA-256), then:

- install: nothing more;
- propose: proposes the components (of a pull request, or of main in the
  verify job after a merge), waits for the proposal, creates a check run
  whose conclusion follows the policy outcome and, on a pull request,
  comments its summary (one comment, updated);
- promote: promotes the proposal the verify job made (input proposal),
  approving it first when the policy requires an approval and a reviewer
  of the job's GitHub environment approved this run; skipped when the
  branch moved on and a newer push run of this workflow exists to promote the
  new head; failed when the branch moved and no such run exists.

Standard library only. The inputs come as INPUT_* variables; KRONIK_URL and
KRONIK_TOKEN reach kronik through its environment, never its command line.
"""

import glob
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

MARKER = "<!-- kronik-proposal -->"
# The login of GITHUB_TOKEN's comments: only its comments are updated.
BOT = "github-actions[bot]"
# require_approval is neutral, not action_required: the approval is the
# production environment's after the merge, and a neutral check does not
# block the merge as a required check, which action_required would.
CONCLUSIONS = {"allow": "success", "require_approval": "neutral", "deny": "failure", "none": "neutral"}
TITLES = {"allow": "ALLOW", "require_approval": "APPROVAL REQUIRED", "deny": "DENY", "none": "NOTHING TO PROPOSE"}
PASSING = ("allow", "require_approval", "none")
SUMMARY_LIMIT = 65000  # the Checks API takes at most 65535 characters
# Events whose pull request code is_fork cannot judge: refused unless
# allow-forks (they can run a fork's code with the secrets).
UNSAFE_EVENTS = ("pull_request_target", "workflow_run", "issue_comment")


class Failure(Exception):
    """Ends the run with an error annotation and exit code 1."""


class KronikError(Failure):
    def __init__(self, code, message, hint=""):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.hint = code, message, hint


def inp(name, default=""):
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), "").strip() or default


def flag(name, default):
    value = inp(name, default)
    if value not in ("true", "false"):
        raise Failure(f"input {name} must be true or false, not {value!r}")
    return value == "true"


def env(name, default=""):
    return os.environ.get(name) or default


def annotate(kind, message):
    """A workflow command (::error:: or ::notice::), its message escaped."""
    message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{kind}::{message}", flush=True)


def run_url():
    server = env("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{env('GITHUB_REPOSITORY')}/actions/runs/{env('GITHUB_RUN_ID')}"


def is_fork(pr):
    head = (pr.get("head") or {}).get("repo")  # null when the fork was deleted
    base = (pr.get("base") or {}).get("repo") or {}
    return not head or head.get("full_name") != base.get("full_name")


# Install


def download(url):
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            return response.read()
    except (urllib.error.URLError, OSError) as e:
        raise Failure(f"could not download {url}: {e}") from e


def install(base_url):
    if platform.system() != "Linux":
        raise Failure(f"kronik runs on Linux runners, not {platform.system()}")
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(machine)
    if not arch:
        raise Failure(f"there is no kronik for {machine}; there is one for x86_64 and one for aarch64")
    check_base_url(base_url)
    base_url = base_url.rstrip("/")
    name = f"kronik-{arch}-unknown-linux-musl"
    binary = download(f"{base_url}/{name}")
    sums = download(f"{base_url}/SHA256SUMS").decode("utf-8", "replace")
    # sha256sum's format: "<hex>  <file>", or "<hex> *<file>" in binary mode.
    want = [f[0].lower() for f in map(str.split, sums.splitlines()) if len(f) == 2 and f[1].lstrip("*") == name]
    if not want:
        raise Failure(f"SHA256SUMS has no line for {name}; refusing to install it")
    got = hashlib.sha256(binary).hexdigest()
    if got != want[0]:
        raise Failure(f"the SHA-256 of {name} is {got}, but SHA256SUMS says {want[0]}; refusing to install it")
    bin_dir = os.path.join(env("RUNNER_TEMP", tempfile.gettempdir()), "kronik-bin")
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, "kronik")
    with open(path, "wb") as f:
        f.write(binary)
    os.chmod(path, 0o755)
    os.environ["PATH"] = bin_dir + os.pathsep + env("PATH")
    if env("GITHUB_PATH"):
        with open(env("GITHUB_PATH"), "a") as f:
            f.write(bin_dir + "\n")
    print(f"Installed {name} from {base_url}, SHA-256 {got}")


def check_base_url(base_url):
    """https:// or file://, or http:// to a loopback IP: the binary and its
    SHA256SUMS come from the same place, so plain HTTP elsewhere would let the
    network swap both."""
    url = urllib.parse.urlsplit(base_url)
    if url.scheme in ("https", "file"):
        return
    if url.scheme == "http":
        try:
            if ipaddress.ip_address(url.hostname or "").is_loopback:
                return
        except ValueError:
            pass
    raise Failure(f"base-url must be an https:// or file:// URL, or http:// to a loopback IP address, not {base_url!r}")


def timeout_seconds():
    """The input timeout (kronik's duration: a number with ms, s, m or h)."""
    m = re.fullmatch(r"(\d+)(ms|s|m|h)", inp("timeout", "45m"))
    if not m:
        raise Failure(f"input timeout must be a number with ms, s, m or h, such as 45m, not {inp('timeout')!r}")
    return int(m[1]) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[m[2]]


# kronik


def kronik(*args, as_json=True):
    """Runs kronik: the parsed JSON (or stdout without as_json) on success."""
    argv = ["kronik", *(["--json"] if as_json else []), *args]
    print("$ " + shlex.join(argv), flush=True)
    # kronik needs KRONIK_URL and KRONIK_TOKEN, not the GitHub token.
    child_env = {k: v for k, v in os.environ.items() if k != "INPUT_GITHUB_TOKEN"}
    # The wait itself is bounded by --timeout; this also bounds a stalled
    # connection, with a margin for kronik to report its own timeout first.
    limit = timeout_seconds() + min(timeout_seconds(), 60)
    # kronik's stderr (progress, retries) is relayed as it comes, redacted:
    # the runner masks only KRONIK_URL's exact text.
    read_end, write_end = os.pipe()
    relay = threading.Thread(target=relay_stderr, args=(read_end,), daemon=True)
    relay.start()
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=write_end, text=True, env=child_env, timeout=limit)
    except FileNotFoundError as e:
        raise Failure("kronik is not on PATH; set the input base-url, or install it in an earlier step") from e
    except subprocess.TimeoutExpired as e:
        raise KronikError(
            "TIMEOUT",
            f"`{shlex.join(argv)}` did not finish within {limit:g} s",
            "The daemon did not answer in time: check that it is reachable, or raise the input timeout.",
        ) from e
    finally:
        os.close(write_end)
        relay.join(5)
    if not as_json:
        if p.returncode:
            raise KronikError("EXIT", f"`{shlex.join(argv)}` exited with {p.returncode}")
        return p.stdout
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = None
    if p.returncode == 0 and isinstance(out, dict):
        return out
    err = out.get("error") if isinstance(out, dict) else None
    if isinstance(err, dict):
        raise KronikError(err.get("code", "ERROR"), err.get("message", ""), err.get("hint", ""))
    raise KronikError("EXIT", f"`{shlex.join(argv)}` exited with {p.returncode} without JSON: {p.stdout.strip()[:500]}")


def components():
    files = []
    for entry in inp("components", "dist").split():
        if os.path.isdir(entry):
            found = glob.glob(os.path.join(entry, "**", "*.wasm"), recursive=True)
        else:
            found = glob.glob(entry, recursive=True)
        if not found:
            raise Failure(f"components: {entry} matches no file")
        files += [f for f in sorted(found) if f not in files]
    return files


def blank(pid=""):
    return {"id": pid, "sha": "", "status": "failed", "outcome": "error", "fired": [], "summary": "", "error": None, "extra": ""}


def fetch(r):
    """Waits for proposal r["id"] and fills in its outcome and summary."""
    info = kronik("proposal", "wait", r["id"], "--timeout", inp("timeout", "45m"))
    policy = info.get("policy") or {}
    r["status"], r["outcome"] = info.get("status", ""), policy.get("outcome", "error")
    r["fired"] = policy.get("fired") or []
    r["summary"] = kronik("diff", "show", r["id"], "--summary", as_json=False)


def evaluate(reason):
    """Proposes the components and waits: the proposal's result."""
    r = blank()
    args = ["propose", *components(), "--async", "--reason", reason]
    if inp("window"):
        args += ["--window", inp("window")]
    try:
        started = kronik(*args)
        r["id"] = (started.get("proposal") or {}).get("id") or ""
        if not r["id"]:
            raise KronikError("EXIT", f"kronik propose printed no proposal id: {json.dumps(started)[:500]}")
        fetch(r)
    except KronikError as e:
        if e.code == "NOTHING_TO_PROPOSE":
            annotate("notice", f"Kronik: nothing to propose: {redact(e.message)}")
            r.update(status="unchanged", outcome="none", summary="Nothing changed: main already runs every component.")
        else:
            r.update(status="failed", outcome="error", error=e)
    return r


def passed(r):
    return r["error"] is None and r["outcome"] in PASSING


def redact(text):
    """text without the daemon's address: KRONIK_URL is a secret, and the log's
    masking (exact text only) does not reach comments and check runs. Host
    names match in any case; a certificate's names, which have no port, go
    too (rustls: "certificate is only valid for a or b")."""
    url = env("KRONIK_URL")
    if url:
        parts = urllib.parse.urlsplit(url)
        for s in (url, url.rstrip("/"), parts.netloc, parts.hostname):
            if s:
                text = re.sub(re.escape(s), "<KRONIK_URL>", text, flags=re.I)
    text = re.sub(r"(only valid for ).*", r"\1<names>", text)
    return re.sub(r"(\[[0-9A-Fa-f:.]+\]|localhost|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+):\d{1,5}\b", "<host:port>", text)


def relay_stderr(fd):
    with os.fdopen(fd, errors="replace") as f:
        for line in f:
            sys.stderr.write(redact(line))
            sys.stderr.flush()


def render(r):
    title = TITLES.get(r["outcome"], "FAILED") if r["error"] is None else "FAILED"
    lines = [f"### Kronik proposal `{r['id']}`: {title}" if r["id"] else f"### Kronik proposal: {title}", ""]
    if r["sha"]:
        lines += [f"Commit `{r['sha']}`", ""]
    if r["error"] is not None:
        e = r["error"]
        lines.append(f"`{e.code}`: {redact(e.message)}")
        if e.hint:
            lines += ["", f"Hint: {redact(e.hint)}"]
    else:
        fired = ", ".join(f"`{f.get('name')}` ({f.get('action')})" for f in r["fired"]) or "none"
        lines += [f"Status `{r['status']}`, policy outcome `{r['outcome']}`; rules fired: {fired}", ""]
        lines.append(r["summary"].strip())
    if r["extra"]:
        lines += ["", r["extra"]]
    lines += ["", f"[Workflow run]({run_url()})"]
    return title, "\n".join(lines) + "\n"


def report(r, body):
    """The step's outputs and job summary."""
    if env("GITHUB_OUTPUT"):
        with open(env("GITHUB_OUTPUT"), "a") as f:
            f.write(f"proposal-id={r['id']}\noutcome={r['outcome']}\nstatus={r['status']}\n")
    if env("GITHUB_STEP_SUMMARY"):
        with open(env("GITHUB_STEP_SUMMARY"), "a") as f:
            f.write(body)
    print(body)


# GitHub


def github(method, path, body=None):
    url = env("GITHUB_API_URL", "https://api.github.com").rstrip("/") + path
    request = urllib.request.Request(
        url,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {inp('github-token')}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "kronik-action",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise Failure(
            f"GitHub API {method} {path}: HTTP {e.code} {detail} (check the job's permissions: propose needs "
            "pull-requests: write and checks: write, promote actions: read and contents: read)"
        ) from e
    except (urllib.error.URLError, OSError) as e:
        raise Failure(f"GitHub API {method} {path}: {e}") from e
    return json.loads(data) if data else None


def upsert_comment(repo, number, body):
    """Updates the pull request's comment that BOT wrote and that starts with
    MARKER, or creates it: anyone can write the marker in a comment."""
    page = 1
    while True:
        comments = github("GET", f"/repos/{repo}/issues/{number}/comments?per_page=100&page={page}")
        for c in comments:
            if (c.get("user") or {}).get("login") == BOT and (c.get("body") or "").startswith(MARKER):
                github("PATCH", f"/repos/{repo}/issues/comments/{c['id']}", {"body": body})
                return
        if len(comments) < 100:
            break
        page += 1
    github("POST", f"/repos/{repo}/issues/{number}/comments", {"body": body})


# Commands


def propose(event):
    pr = event.get("pull_request")
    sha = ((pr or {}).get("head") or {}).get("sha") or env("GITHUB_SHA")
    if pr:
        default = f"GitHub pull request #{pr.get('number')} at {sha[:12]} by {env('GITHUB_ACTOR')}: {run_url()}"
    else:
        default = f"GitHub {env('GITHUB_EVENT_NAME')} at {sha[:12]} by {env('GITHUB_ACTOR')}: {run_url()}"
    r = evaluate(inp("reason", default))
    r["sha"] = sha
    title, body = render(r)
    report(r, body)
    repo = env("GITHUB_REPOSITORY")
    github(
        "POST",
        f"/repos/{repo}/check-runs",
        {
            "name": "Kronik proposal",
            "head_sha": sha,
            "status": "completed",
            "conclusion": CONCLUSIONS.get(r["outcome"], "failure") if r["error"] is None else "failure",
            "details_url": run_url(),
            "output": {"title": f"Kronik proposal: {title}", "summary": body[:SUMMARY_LIMIT]},
        },
    )
    if pr and flag("comment", "true"):
        # A run that finishes after a newer push's run must not overwrite it.
        head = ((github("GET", f"/repos/{repo}/pulls/{pr['number']}") or {}).get("head") or {}).get("sha")
        if head != sha:
            annotate("notice", f"Kronik: did not update the comment: the pull request's head moved from {sha[:12]} to {str(head)[:12]}")
        else:
            upsert_comment(repo, pr["number"], f"{MARKER}\n{body}")
    return r


def environment_approval(name, pid):
    """The approve reason naming the reviewers who approved this run for the
    environment name, or None when none did. After the run's first attempt
    only an approval whose comment names pid counts: the run's approvals may
    include an earlier attempt's, given for another proposal."""
    repo, run_id = env("GITHUB_REPOSITORY"), env("GITHUB_RUN_ID")
    approvals = github("GET", f"/repos/{repo}/actions/runs/{run_id}/approvals")
    if not isinstance(approvals, list):
        raise Failure(f"GitHub API GET /repos/{repo}/actions/runs/{run_id}/approvals: not a list: {json.dumps(approvals)[:300]}")
    first = env("GITHUB_RUN_ATTEMPT") == "1"
    names_pid = re.compile(rf"(?<![\w-]){re.escape(pid)}(?![\w-])")
    who = [
        (a.get("user") or {}).get("login", "?") + (f" ({a['comment']})" if a.get("comment") else "")
        for a in approvals
        if a.get("state") == "approved"
        and any(e.get("name") == name for e in a.get("environments") or [])
        and (first or names_pid.search(a.get("comment") or ""))
    ]
    if not who:
        return None
    return f"approved in the GitHub environment {name} of {repo} by {'; '.join(who)}: {run_url()}"


def head_of_ref():
    """The commit GITHUB_REF's branch points to now."""
    ref = env("GITHUB_REF")
    if not ref.startswith("refs/heads/"):
        raise Failure(f"promote runs on a push to a branch, not on {ref!r}")
    path = f"/repos/{env('GITHUB_REPOSITORY')}/git/ref/{urllib.parse.quote(ref.removeprefix('refs/'))}"
    head = ((github("GET", path) or {}).get("object") or {}).get("sha")
    if not head:
        raise Failure(f"GitHub API GET {path}: no commit sha in the answer")
    return head


def newer_push_run(sha):
    """Whether a push run of this workflow, newer than this run, exists for
    GITHUB_REF at another commit. API errors raise: fail closed."""
    repo, ref = env("GITHUB_REPOSITORY"), env("GITHUB_REF")
    workflow = env("GITHUB_WORKFLOW_REF").split("@", 1)[0].rsplit("/", 1)[-1]
    if not workflow:
        raise Failure("GITHUB_WORKFLOW_REF is not set: cannot look for a newer run of this workflow")
    branch = urllib.parse.quote(ref.removeprefix("refs/heads/"), safe="")
    path = f"/repos/{repo}/actions/workflows/{urllib.parse.quote(workflow)}/runs?branch={branch}&event=push&per_page=100"
    runs = (github("GET", path) or {}).get("workflow_runs")
    if not isinstance(runs, list):
        raise Failure(f"GitHub API GET {path}: no workflow_runs list in the answer")
    # Run ids grow with time; the newest runs come first.
    me = int(env("GITHUB_RUN_ID"))
    return any(int(run.get("id") or 0) > me and run.get("head_sha") != sha for run in runs)


def promote(event):
    pid = inp("proposal")
    if not pid:
        annotate("notice", "Kronik: nothing to promote: the input proposal is empty (the verify job proposed nothing)")
        return dict(blank(), status="unchanged", outcome="none")
    sha = env("GITHUB_SHA")
    reason = inp("reason", f"GitHub {env('GITHUB_EVENT_NAME')} of {sha[:12]} to {env('GITHUB_REF')} by {env('GITHUB_ACTOR')}: {run_url()}")
    r = blank(pid)
    try:
        fetch(r)
        if r["status"] == "promoted":
            annotate("notice", f"Kronik: proposal {pid} is already promoted")
        elif passed(r) and (head := head_of_ref()) != sha:
            # An older commit's proposal would put its code back over the
            # newer commit's; skip only if a newer run will promote the newer one.
            moved = f"{env('GITHUB_REF')} moved from {sha[:12]} to {head[:12]}"
            if not newer_push_run(sha):
                cmd = shlex.join(["kronik", "promote", pid, "--reason", reason])
                r["extra"] = f"Not promoted: {moved}, and no newer run of this workflow will promote it."
                report(r, render(r)[1])
                raise Failure(
                    f"Kronik did not promote {pid}: {moved}, and no newer push run of this workflow exists to promote it. "
                    f"Re-run the workflow for the new head, or, if {pid} is still wanted, run: {cmd}"
                )
            r["status"] = "skipped"
            r["extra"] = f"Not promoted: {moved}; a newer run of this workflow promotes the new head."
            annotate("notice", f"Kronik: did not promote {pid}: {moved}; a newer run of this workflow promotes it")
        elif passed(r):
            if r["outcome"] == "require_approval" and r["status"] != "approved":
                name = inp("environment", "kronik-production")
                approval = environment_approval(name, pid)
                if approval is None:
                    cmd = shlex.join(["kronik", "approve", pid, "--reason", f"reviewed proposal {pid} of {env('GITHUB_REPOSITORY')}: {run_url()}"])
                    why = f"no reviewer of the GitHub environment {name} approved this run"
                    retry = ""
                    attempt = env("GITHUB_RUN_ATTEMPT", "?")
                    if attempt != "1":
                        why += f" with a comment that names {pid}"
                        retry = (
                            f" This is attempt {attempt} of the run, and an approval of an earlier attempt may be for "
                            f"another proposal: re-run this job and approve the deployment with a comment that names {pid}."
                        )
                    r["extra"] = (
                        f"Kronik: {why[0].upper()}{why[1:]}, so the action neither approved nor promoted.{retry} "
                        f"Or a person who reviewed the proposal can approve it, then re-run this job:\n\n"
                        f"```\n{cmd}\n```"
                    )
                    report(r, render(r)[1])
                    raise Failure(f"Kronik proposal {pid} needs an approval, and {why}.{retry} Or run: {cmd}")
                kronik("approve", pid, "--reason", approval)
            deployment = kronik("promote", pid, "--reason", reason).get("deployment") or {}
            r["status"] = "promoted"
            r["extra"] = f"Promoted: epoch {deployment.get('epoch')}, lsn {deployment.get('lsn')}"
    except KronikError as e:
        r.update(status="failed", error=e)
    report(r, render(r)[1])
    return r


def main():
    command = inp("command")
    if command not in ("install", "propose", "promote"):
        raise Failure(f"input command must be install, propose or promote, not {command!r}")
    for name in ("KRONIK_TOKEN", "INPUT_GITHUB_TOKEN"):
        if env(name):
            print(f"::add-mask::{env(name)}", flush=True)
    event = {}
    if env("GITHUB_EVENT_PATH"):
        with open(env("GITHUB_EVENT_PATH")) as f:
            event = json.load(f)
    pr = event.get("pull_request")
    if command == "propose" and env("GITHUB_EVENT_NAME") in UNSAFE_EVENTS and not flag("allow-forks", "false"):
        raise Failure(
            f"propose does not run on {env('GITHUB_EVENT_NAME')} events, which can run a fork's code with this "
            "repository's secrets; run it on pull_request, push or workflow_dispatch (or set allow-forks: true)"
        )
    # A fork's code must not run with this repository's Kronik token, also
    # when the workflow's if: is missing.
    if command == "propose" and pr and is_fork(pr) and not flag("allow-forks", "false"):
        annotate(
            "notice",
            f"Kronik: skipped pull request #{pr.get('number')}: it comes from a fork, "
            "and forks do not get the Kronik token (set allow-forks: true to change that)",
        )
        return 0
    if command == "promote" and pr:
        raise Failure("promote runs on a push to the main branch, not on a pull request")
    flag("comment", "true")  # bad values fail before anything runs
    timeout_seconds()
    if inp("base-url"):
        install(inp("base-url"))
    version = kronik("--version", as_json=False).strip()
    print(f"Using {version}")
    if command == "install":
        return 0
    if not env("KRONIK_URL"):
        raise Failure("KRONIK_URL is not set; pass it (and KRONIK_TOKEN) to this step's env from secrets")
    r = (propose if command == "propose" else promote)(event)
    if r["error"] is not None:
        raise Failure(f"Kronik proposal {r['id'] or '(none)'} failed: {r['error']}")
    if not passed(r):
        raise Failure(f"Kronik proposal {r['id']}: the policy outcome is {r['outcome']} ({r['status']})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Failure as e:
        annotate("error", redact(str(e)))
        sys.exit(1)
