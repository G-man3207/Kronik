"""Tests of the Kronik GitHub Action (scripts/ci.sh action): kronik_action.py
runs as on a runner, against a fake kronik (fake_kronik.py on PATH) and a
fake GitHub API on 127.0.0.1, with fake GITHUB_* variables and events."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

ACTION = Path(__file__).resolve().parents[1]
ROOT = ACTION.parent
SCRIPT = ACTION / "kronik_action.py"
FAKE = Path(__file__).resolve().parent / "fake_kronik.py"
WORKFLOW = ROOT / "docs" / "examples" / "kronik-ci.yml"
REPO = "owner/actors"
HEAD_SHA = "a" * 40
MERGE_SHA = "b" * 40
KRONIK_TOKEN = "kronik-secret-token-1234"
GITHUB_TOKEN = "ghs_secret-github-token-5678"
RUN_URL = f"https://github.example/{REPO}/actions/runs/42"
BOT = "github-actions[bot]"
KRONIK_URL = "https://kronik.example:8443"


class FakeGitHub(BaseHTTPRequestHandler):
    """Comments, check runs, the head and the run's approvals of one pull
    request (#7), kept in the server."""

    def log_message(self, *args):
        pass

    def handle_any(self):
        s = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        s.requests.append({"method": self.command, "path": url.path, "auth": self.headers.get("Authorization"), "body": body})
        status, out = 404, {"message": "Not Found"}
        if s.deny:
            status, out = 403, {"message": "Resource not accessible by integration"}
        elif self.command == "GET" and url.path == f"/repos/{REPO}/issues/7/comments":
            per_page, page = int(query["per_page"][0]), int(query["page"][0])
            status, out = 200, s.comments[(page - 1) * per_page : page * per_page]
        elif self.command == "POST" and url.path == f"/repos/{REPO}/issues/7/comments":
            out = {"id": 1000 + len(s.comments), "body": body["body"], "user": {"login": BOT}}
            s.comments.append(out)
            status = 201
        elif self.command == "GET" and url.path == f"/repos/{REPO}/pulls/7":
            status, out = 200, {"number": 7, "head": {"sha": s.head}}
        elif self.command == "GET" and url.path == f"/repos/{REPO}/actions/runs/42/approvals":
            # An int is an error status; anything else the answer.
            status, out = (s.approvals, {"message": "nope"}) if isinstance(s.approvals, int) else (200, s.approvals)
        elif self.command == "GET" and url.path == f"/repos/{REPO}/actions/workflows/kronik.yml/runs":
            assert query["branch"] == ["main"] and query["event"] == ["push"], query
            status, out = (s.runs, {"message": "nope"}) if isinstance(s.runs, int) else (200, {"workflow_runs": s.runs})
        elif self.command == "GET" and url.path == f"/repos/{REPO}/git/ref/heads/main":
            status, out = 200, {"ref": "refs/heads/main", "object": {"type": "commit", "sha": s.main_head}}
        elif self.command == "PATCH" and url.path.startswith(f"/repos/{REPO}/issues/comments/"):
            cid = int(url.path.rsplit("/", 1)[1])
            for c in s.comments:
                if c["id"] == cid:
                    c["body"], status, out = body["body"], 200, c
        elif self.command == "POST" and url.path == f"/repos/{REPO}/check-runs":
            s.check_runs.append(body)
            status, out = 201, {"id": len(s.check_runs)}
        data = json.dumps(out).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = handle_any


def pr_event(head_repo=REPO):
    return {
        "pull_request": {
            "number": 7,
            "head": {"sha": HEAD_SHA, "repo": {"full_name": head_repo} if head_repo else None},
            "base": {"repo": {"full_name": REPO}},
        }
    }


def scenario(outcome="allow", status="evaluated", wait_error=None, promote_error=None, propose_error=None, error_message=None, error_hint="a hint"):
    def error(code):
        return {"exit": 1, "stdout": {"error": {"code": code, "message": error_message or f"{code} happened", "hint": error_hint}}}

    info = {
        "id": "p-1",
        "fork": "p-1",
        "status": status,
        "policy": {"outcome": outcome, "fired": [{"name": "any-change", "action": outcome}], "errors": []},
        "summary": {},
        "kinds": [],
        "unchanged": [],
    }
    return {
        "propose": error(propose_error) if propose_error else {"stdout": {"dry_run": False, "proposal": {"id": "p-1", "status": "running"}}},
        "wait": error(wait_error) if wait_error else {"stdout": info},
        "diff": {"stdout": "**counter**: 3 origins changed, 0 effects changed\n"},
        "approve": {"stdout": {"dry_run": False, "proposal": dict(info, status="approved")}},
        "promote": error(promote_error) if promote_error else {"stdout": {"dry_run": False, "deployment": {"epoch": 3, "lsn": 7}, "policy": info["policy"]}},
    }


class ActionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="kronik-action-test-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        shutil.copy(FAKE, self.bin / "kronik")
        (self.bin / "kronik").chmod(0o755)
        self.work = self.tmp / "work"
        (self.work / "dist" / "sub").mkdir(parents=True)
        (self.work / "dist" / "a.wasm").write_bytes(b"\0asm")
        (self.work / "dist" / "sub" / "b.wasm").write_bytes(b"\0asm")
        (self.work / "dist" / "notes.txt").write_text("not a component")
        self.gh = ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
        self.gh.requests, self.gh.comments, self.gh.check_runs, self.gh.deny = [], [], [], False
        self.gh.head, self.gh.approvals, self.gh.main_head, self.gh.runs = HEAD_SHA, [], MERGE_SHA, []
        threading.Thread(target=self.gh.serve_forever, daemon=True).start()
        self.addCleanup(self.gh.server_close)
        self.addCleanup(self.gh.shutdown)

    def run_action(self, command, scen=None, event=None, event_name="pull_request", path_bin=True, extra_env=None, **inputs):
        log = self.tmp / "kronik.log"
        log.unlink(missing_ok=True)
        (self.tmp / "scenario.json").write_text(json.dumps(scen or scenario()))
        (self.tmp / "event.json").write_text(json.dumps(pr_event() if event is None else event))
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "INPUT_", "KRONIK_", "RUNNER_"))}
        env.update(
            PATH=(str(self.bin) + os.pathsep if path_bin else "") + os.environ["PATH"],
            GITHUB_API_URL=f"http://127.0.0.1:{self.gh.server_port}",
            GITHUB_SERVER_URL="https://github.example",
            GITHUB_REPOSITORY=REPO,
            GITHUB_RUN_ID="42",
            GITHUB_WORKFLOW_REF=f"{REPO}/.github/workflows/kronik.yml@refs/heads/main",
            GITHUB_RUN_ATTEMPT="1",
            GITHUB_ACTOR="alice",
            GITHUB_SHA=MERGE_SHA,
            GITHUB_REF="refs/heads/main",
            GITHUB_EVENT_NAME=event_name,
            GITHUB_EVENT_PATH=str(self.tmp / "event.json"),
            GITHUB_OUTPUT=str(self.tmp / "output"),
            GITHUB_STEP_SUMMARY=str(self.tmp / "summary.md"),
            GITHUB_PATH=str(self.tmp / "path"),
            RUNNER_TEMP=str(self.tmp / "runner"),
            KRONIK_URL=KRONIK_URL,
            KRONIK_TOKEN=KRONIK_TOKEN,
            INPUT_GITHUB_TOKEN=GITHUB_TOKEN,
            INPUT_COMMAND=command,
            FAKE_KRONIK_LOG=str(log),
            FAKE_KRONIK_SCENARIO=str(self.tmp / "scenario.json"),
        )
        env.update({"INPUT_" + k.upper(): v for k, v in inputs.items()})
        env.update(extra_env or {})
        p = subprocess.run([sys.executable, str(SCRIPT)], cwd=self.work, env=env, capture_output=True, text=True, timeout=60)
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        self.assert_no_token_leak(p, calls)
        return p, calls

    def assert_no_token_leak(self, p, calls):
        for token in (KRONIK_TOKEN, GITHUB_TOKEN):
            for line in (p.stdout + p.stderr).splitlines():
                if token in line:
                    # The runner consumes the mask command; it is never logged.
                    self.assertEqual(line, f"::add-mask::{token}")
            for call in calls:
                self.assertNotIn(token, " ".join(call["argv"]))
        for call in calls:
            self.assertEqual(call["kronik_token"], KRONIK_TOKEN, "kronik gets its token from the environment")
            self.assertIsNone(call["github_token"], "kronik does not get the GitHub token")

    def outputs(self):
        return dict(line.split("=", 1) for line in (self.tmp / "output").read_text().splitlines())

    def subcommands(self, calls):
        return [[a for a in c["argv"] if a != "--json"][0] for c in calls]


class InstallTest(ActionTest):
    def release(self, sums=None):
        rel = self.tmp / "release"
        rel.mkdir(exist_ok=True)
        lines = []
        for arch in ("x86_64", "aarch64"):
            name = f"kronik-{arch}-unknown-linux-musl"
            shutil.copy(FAKE, rel / name)
            lines.append(f"{hashlib.sha256(FAKE.read_bytes()).hexdigest()}  {name}")
        (rel / "SHA256SUMS").write_text((sums if sums is not None else "\n".join(lines)) + "\n")
        return rel.as_uri()

    def installed(self):
        return self.tmp / "runner" / "kronik-bin" / "kronik"

    def test_checksum_verified(self):
        p, calls = self.run_action("install", base_url=self.release(), event={}, event_name="push", path_bin=False)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("Using kronik 0.0.0-fake", p.stdout)
        self.assertTrue(os.access(self.installed(), os.X_OK))
        self.assertEqual((self.tmp / "path").read_text(), f"{self.installed().parent}\n")
        self.assertEqual(calls[0]["argv"], ["--version"])

    def test_checksum_mismatch_refused(self):
        sums = "\n".join(f"{'0' * 64}  kronik-{a}-unknown-linux-musl" for a in ("x86_64", "aarch64"))
        p, calls = self.run_action("install", base_url=self.release(sums), event={}, event_name="push", path_bin=False)
        self.assertEqual(p.returncode, 1)
        self.assertIn("but SHA256SUMS says", p.stdout)
        self.assertFalse(self.installed().exists())
        self.assertEqual(calls, [])

    def test_missing_checksum_line_refused(self):
        p, calls = self.run_action("install", base_url=self.release(f"{'0' * 64}  other-file"), event={}, event_name="push", path_bin=False)
        self.assertEqual(p.returncode, 1)
        self.assertIn("SHA256SUMS has no line for kronik-", p.stdout)
        self.assertFalse(self.installed().exists())

    def test_install_then_propose(self):
        p, calls = self.run_action("propose", base_url=self.release(), path_bin=False)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "propose", "proposal", "diff"])

    def test_base_url_scheme(self):
        for url in ("http://releases.example/v1", "http://localhost:1/v1", "ftp://releases.example/v1", "releases.example/v1"):
            with self.subTest(url=url):
                p, calls = self.run_action("install", base_url=url, event={}, event_name="push", path_bin=False)
                self.assertEqual(p.returncode, 1)
                self.assertIn("base-url must be an https:// or file:// URL, or http:// to a loopback IP address", p.stdout)
                self.assertEqual(calls, [])
        # Allowed, and then fails only because nothing listens there.
        for url in ("http://127.0.0.1:1/v1", "http://[::1]:1/v1"):
            with self.subTest(url=url):
                p, _ = self.run_action("install", base_url=url, event={}, event_name="push", path_bin=False)
                self.assertEqual(p.returncode, 1)
                self.assertIn("could not download", p.stdout)


class ProposeTest(ActionTest):
    def test_argv(self):
        p, calls = self.run_action("propose", window="2h", timeout="45m")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        propose, wait, diff = calls[1]["argv"], calls[2]["argv"], calls[3]["argv"]
        reason = f"GitHub pull request #7 at {HEAD_SHA[:12]} by alice: {RUN_URL}"
        self.assertEqual(propose, ["--json", "propose", "dist/a.wasm", "dist/sub/b.wasm", "--async", "--reason", reason, "--window", "2h"])
        self.assertEqual(wait, ["--json", "proposal", "wait", "p-1", "--timeout", "45m"])
        self.assertEqual(diff, ["diff", "show", "p-1", "--summary"])

    def test_check_conclusion_per_outcome(self):
        cases = [
            (scenario("allow"), "success", 0, "allow", "evaluated"),
            (scenario("require_approval"), "neutral", 0, "require_approval", "evaluated"),
            (scenario("deny", "rejected"), "failure", 1, "deny", "rejected"),
            (scenario(wait_error="PROPOSAL_RUNNING"), "failure", 1, "error", "failed"),
        ]
        for scen, conclusion, code, outcome, status in cases:
            with self.subTest(outcome=outcome):
                p, _ = self.run_action("propose", scen)
                self.assertEqual(p.returncode, code, p.stdout + p.stderr)
                check = self.gh.check_runs[-1]
                self.assertEqual(check["conclusion"], conclusion)
                self.assertEqual(check["status"], "completed")
                self.assertEqual(check["head_sha"], HEAD_SHA, "the PR's head, not the merge commit")
                self.assertEqual(self.outputs(), {"proposal-id": "p-1", "outcome": outcome, "status": status})
        self.assertIn("PROPOSAL_RUNNING", self.gh.check_runs[-1]["output"]["summary"])
        self.assertIn("::error::", p.stdout)

    def test_comment_created_then_updated(self):
        self.run_action("propose", scenario("allow"))
        self.run_action("propose", scenario("deny", "rejected"))
        writes = [(r["method"], r["path"]) for r in self.gh.requests if r["method"] != "GET" and "comments" in r["path"]]
        self.assertEqual(writes, [("POST", f"/repos/{REPO}/issues/7/comments"), ("PATCH", f"/repos/{REPO}/issues/comments/1000")])
        self.assertEqual(len(self.gh.comments), 1)
        body = self.gh.comments[0]["body"]
        self.assertTrue(body.startswith("<!-- kronik-proposal -->\n"))
        self.assertIn("DENY", body)
        self.assertIn("3 origins changed", body)
        self.assertIn(RUN_URL, body)
        self.assertTrue(all(r["auth"] == f"Bearer {GITHUB_TOKEN}" for r in self.gh.requests))
        self.assertIn("3 origins changed", (self.tmp / "summary.md").read_text())

    def test_comment_found_on_a_later_page(self):
        self.gh.comments = [{"id": i, "body": "lgtm", "user": {"login": "bob"}} for i in range(150)]
        self.gh.comments[120] = {"id": 120, "body": "<!-- kronik-proposal -->\nold", "user": {"login": BOT}}
        p, _ = self.run_action("propose")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(len(self.gh.comments), 150)
        self.assertIn("ALLOW", self.gh.comments[120]["body"])

    def test_comment_of_someone_else_not_updated(self):
        planted = [
            {"id": 1, "body": "<!-- kronik-proposal -->\nALLOW", "user": {"login": "mallory"}},
            {"id": 2, "body": "quoting <!-- kronik-proposal -->", "user": {"login": BOT}},
        ]
        self.gh.comments = [dict(c) for c in planted]
        p, _ = self.run_action("propose", scenario("deny", "rejected"))
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.gh.comments[:2], planted)
        self.assertEqual(len(self.gh.comments), 3)
        self.assertIn("DENY", self.gh.comments[2]["body"])
        writes = [(r["method"], r["path"]) for r in self.gh.requests if r["method"] != "GET"]
        self.assertEqual(writes[0], ("POST", f"/repos/{REPO}/check-runs"), "the check run comes before any comment")
        self.assertNotIn("PATCH", [m for m, _ in writes])

    def test_comment_names_the_commit(self):
        p, _ = self.run_action("propose")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f"Commit `{HEAD_SHA}`", self.gh.comments[0]["body"])

    def test_comment_not_updated_when_the_head_moved(self):
        self.run_action("propose", scenario("allow"))
        self.gh.head = "c" * 40
        p, _ = self.run_action("propose", scenario("deny", "rejected"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("did not update the comment: the pull request's head moved", p.stdout)
        self.assertEqual(len(self.gh.comments), 1)
        self.assertIn("ALLOW", self.gh.comments[0]["body"])
        self.assertEqual(self.gh.check_runs[-1]["conclusion"], "failure", "the check run is still this commit's")

    def test_nothing_to_propose_passes(self):
        p, calls = self.run_action("propose", scenario(propose_error="NOTHING_TO_PROPOSE"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "propose"])
        self.assertIn("::notice::Kronik: nothing to propose", p.stdout)
        self.assertEqual(self.gh.check_runs[-1]["conclusion"], "neutral")
        self.assertIn("Nothing changed", self.gh.comments[0]["body"])
        self.assertEqual(self.outputs(), {"proposal-id": "", "outcome": "none", "status": "unchanged"})

    def test_daemon_address_not_posted(self):
        scen = scenario(
            wait_error="UNAVAILABLE",
            error_message=f"could not connect to {KRONIK_URL}: refused (kronik.example also at 10.0.0.5:8443)",
            error_hint="Check that kronik.example:8443 or [fd00::1]:8443 is reachable.",
        )
        p, _ = self.run_action("propose", scen)
        self.assertEqual(p.returncode, 1)
        for text in (self.gh.comments[0]["body"], self.gh.check_runs[0]["output"]["summary"], (self.tmp / "summary.md").read_text()):
            self.assertIn("UNAVAILABLE", text)
            for secret in ("kronik.example", "8443", "10.0.0.5", "fd00::1"):
                self.assertNotIn(secret, text)

    def test_daemon_address_not_logged(self):
        # M7: the runner masks only the secret's exact text, so the error
        # line and kronik's stderr are redacted too: here the secret has an
        # upper-case host and a trailing slash, and kronik prints it in lower
        # case; a certificate's names have no port.
        scen = scenario(
            wait_error="UNAVAILABLE",
            error_message='invalid peer certificate: certificate not valid for name "kronik.example"; '
            "certificate is only valid for kronik.corp.internal or *.corp.internal",
        )
        scen["wait"]["stderr"] = "GET https://kronik.example:8443/v1/proposals/p-1 failed: refused; retrying\n"
        p, _ = self.run_action("propose", scen, extra_env={"KRONIK_URL": "https://Kronik.Example:8443/"})
        self.assertEqual(p.returncode, 1)
        self.assertIn("::error::Kronik proposal p-1 failed: UNAVAILABLE", p.stdout)
        self.assertIn("retrying", p.stderr)
        for text in (p.stdout, p.stderr, self.gh.comments[0]["body"], self.gh.check_runs[0]["output"]["summary"]):
            for secret in ("kronik.example", "8443", "corp.internal"):
                self.assertNotIn(secret, text.lower())

    def test_stalled_kronik_times_out(self):
        scen = scenario()
        scen["wait"]["sleep"] = 30
        started = time.monotonic()
        p, _ = self.run_action("propose", scen, timeout="1s")
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(p.returncode, 1)
        self.assertIn("did not finish within 2 s", p.stdout)
        self.assertIn("TIMEOUT", self.gh.check_runs[0]["output"]["summary"])

    def test_bad_timeout_fails(self):
        p, calls = self.run_action("propose", timeout="45")
        self.assertEqual(p.returncode, 1)
        self.assertIn("input timeout must be a number with ms, s, m or h", p.stdout)
        self.assertEqual(calls, [])

    def test_unsafe_events_refused(self):
        for name in ("pull_request_target", "workflow_run", "issue_comment"):
            with self.subTest(event=name):
                p, calls = self.run_action("propose", event_name=name)
                self.assertEqual(p.returncode, 1)
                self.assertIn(f"propose does not run on {name} events", p.stdout)
                self.assertEqual(calls, [])
        p, calls = self.run_action("propose", event_name="workflow_run", allow_forks="true")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_no_comment(self):
        p, _ = self.run_action("propose", comment="false")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual([r["path"] for r in self.gh.requests], [f"/repos/{REPO}/check-runs"])

    def test_fork_skipped_by_default(self):
        for head in ("someone/actors", None):
            with self.subTest(head=head):
                p, calls = self.run_action("propose", event=pr_event(head))
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn("::notice::Kronik: skipped pull request #7: it comes from a fork", p.stdout)
                self.assertEqual(calls, [])
                self.assertEqual(self.gh.requests, [])

    def test_fork_runs_with_allow_forks(self):
        p, calls = self.run_action("propose", event=pr_event("someone/actors"), allow_forks="true")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "propose", "proposal", "diff"])
        self.assertEqual(len(self.gh.check_runs), 1)

    def test_push_event_checks_the_commit(self):
        p, _ = self.run_action("propose", event={}, event_name="push")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.gh.check_runs[0]["head_sha"], MERGE_SHA)
        self.assertFalse(any("comments" in r["path"] for r in self.gh.requests))

    def test_github_api_error_fails(self):
        self.gh.deny = True
        p, _ = self.run_action("propose")
        self.assertEqual(p.returncode, 1)
        self.assertIn("HTTP 403", p.stdout)

    def test_missing_kronik_url_fails(self):
        p, calls = self.run_action("propose", extra_env={"KRONIK_URL": ""})
        self.assertEqual(p.returncode, 1)
        self.assertIn("KRONIK_URL is not set", p.stdout)
        self.assertEqual(self.subcommands(calls), ["--version"])

    def test_bad_input_fails(self):
        p, _ = self.run_action("propose", allow_forks="yes", event=pr_event("someone/actors"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("allow-forks must be true or false", p.stdout)


class PromoteTest(ActionTest):
    APPROVALS = f"/repos/{REPO}/actions/runs/42/approvals"
    REF = f"/repos/{REPO}/git/ref/heads/main"

    def promote(self, scen, proposal="p-1", **inputs):
        return self.run_action("promote", scen, event={"ref": "refs/heads/main"}, event_name="push", proposal=proposal, **inputs)

    def approval(self, login, state="approved", environment="kronik-production", comment=""):
        return {"state": state, "comment": comment, "user": {"login": login}, "environments": [{"name": environment}]}

    def test_require_approval_needs_a_reviewer(self):
        cases = [
            [],
            [self.approval("bob", state="rejected")],
            [self.approval("bob", environment="staging")],
        ]
        for approvals in cases:
            with self.subTest(approvals=approvals):
                self.gh.approvals = approvals
                p, calls = self.promote(scenario("require_approval"))
                self.assertEqual(p.returncode, 1)
                self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"], "no approve, no promote")
                command = f"kronik approve p-1 --reason 'reviewed proposal p-1 of {REPO}: {RUN_URL}'"
                self.assertIn(command, p.stdout)
                self.assertIn("no reviewer of the GitHub environment kronik-production approved this run", p.stdout)
                self.assertEqual(self.gh.requests[-1]["path"], self.APPROVALS)

    def test_require_approval_approves_naming_the_reviewer(self):
        self.gh.approvals = [self.approval("mallory", state="rejected"), self.approval("bob", comment="diff looks right")]
        p, calls = self.promote(scenario("require_approval"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff", "approve", "promote"])
        self.assertEqual(calls[1]["argv"], ["--json", "proposal", "wait", "p-1", "--timeout", "45m"])
        approve = calls[3]["argv"]
        self.assertEqual(approve[:4], ["--json", "approve", "p-1", "--reason"])
        self.assertIn("bob (diff looks right)", approve[4])
        self.assertNotIn("mallory", approve[4])
        self.assertIn(RUN_URL, approve[4])
        self.assertEqual(calls[4]["argv"][:4], ["--json", "promote", "p-1", "--reason"])
        self.assertEqual(self.outputs(), {"proposal-id": "p-1", "outcome": "require_approval", "status": "promoted"})
        self.assertIn("epoch 3, lsn 7", (self.tmp / "summary.md").read_text())
        self.assertEqual([r["path"] for r in self.gh.requests], [self.REF, self.APPROVALS])

    def test_rerun_needs_an_approval_naming_the_proposal(self):
        # A2: on attempt 2 an approval may be attempt 1's, for another proposal.
        rerun = {"GITHUB_RUN_ATTEMPT": "2"}
        for comment in ("", "ok for p-0", "ok for p-10"):
            with self.subTest(comment=comment):
                self.gh.approvals = [self.approval("bob", comment=comment)]
                p, calls = self.promote(scenario("require_approval"), extra_env=rerun)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"], "no approve, no promote")
                self.assertIn("This is attempt 2 of the run", p.stdout)
                self.assertIn("re-run this job and approve the deployment with a comment that names p-1.", p.stdout)
        self.gh.approvals = [self.approval("bob", comment="p-1 looks right")]
        p, calls = self.promote(scenario("require_approval"), extra_env=rerun)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff", "approve", "promote"])
        self.assertIn("bob (p-1 looks right)", calls[3]["argv"][4])

    def test_approvals_api_errors_fail(self):
        # A3: no approval is read from an error or an answer that is not a list.
        for answer, want in ((403, "HTTP 403"), (404, "HTTP 404"), ({"total_count": 1}, "not a list")):
            with self.subTest(answer=answer):
                self.gh.approvals = answer
                p, calls = self.promote(scenario("require_approval"))
                self.assertEqual(p.returncode, 1)
                self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"], "no approve, no promote")
                self.assertIn(want, p.stdout)
                self.assertIn("::error::", p.stdout)
                self.assertNotIn("Traceback", p.stderr)

    RUNS = f"/repos/{REPO}/actions/workflows/kronik.yml/runs"

    def test_moved_branch_skips_when_a_newer_run_exists(self):
        # A1: an older commit's proposal would undo the newer commit's code.
        self.gh.main_head = "c" * 40
        self.gh.runs = [{"id": 43, "head_sha": "c" * 40}, {"id": 42, "head_sha": MERGE_SHA}]
        for scen in (scenario("allow"), scenario("require_approval")):
            with self.subTest(outcome=scen["wait"]["stdout"]["policy"]["outcome"]):
                p, calls = self.promote(scen)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"], "no approve, no promote")
                self.assertIn(f"::notice::Kronik: did not promote p-1: refs/heads/main moved from {MERGE_SHA[:12]} to cccccccccccc", p.stdout)
                self.assertEqual(self.outputs()["status"], "skipped")
                self.assertNotIn(self.APPROVALS, [r["path"] for r in self.gh.requests])

    def test_moved_branch_fails_without_a_newer_run(self):
        # R3: nothing would ever promote the new head; a silent skip hides it.
        self.gh.main_head = "c" * 40
        for runs in ([], [{"id": 42, "head_sha": MERGE_SHA}], [{"id": 41, "head_sha": "c" * 40}], [{"id": 43, "head_sha": MERGE_SHA}]):
            with self.subTest(runs=runs):
                self.gh.runs = runs
                p, calls = self.promote(scenario("allow"))
                self.assertEqual(p.returncode, 1, p.stdout)
                self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"], "no approve, no promote")
                self.assertIn("no newer push run of this workflow exists", p.stdout)
                self.assertIn("kronik promote p-1 --reason", p.stdout)
                self.assertIn(self.RUNS, [r["path"] for r in self.gh.requests])

    def test_moved_branch_runs_api_error_fails(self):
        self.gh.main_head = "c" * 40
        for runs in (403, 500):
            with self.subTest(runs=runs):
                self.gh.runs = runs
                p, calls = self.promote(scenario("allow"))
                self.assertEqual(p.returncode, 1, p.stdout)
                self.assertNotIn("promote", self.subcommands(calls)[1:])
                self.assertIn(f"HTTP {runs}", p.stdout)
                self.assertNotIn("Traceback", p.stderr)

    def test_head_check_error_fails(self):
        self.gh.deny = True
        p, calls = self.promote(scenario("allow"))
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("promote", self.subcommands(calls)[1:])
        self.assertIn("HTTP 403", p.stdout)

    def test_already_approved_in_kronik_promotes(self):
        p, calls = self.promote(scenario("require_approval", "approved"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff", "promote"])
        self.assertEqual([r["path"] for r in self.gh.requests], [self.REF])

    def test_allow_promotes_without_approval(self):
        # allow needs no approval, so no reviewer is required either.
        p, calls = self.promote(scenario("allow"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff", "promote"])
        self.assertEqual([r["path"] for r in self.gh.requests], [self.REF])

    def test_already_promoted_passes(self):
        p, calls = self.promote(scenario("allow", "promoted"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version", "proposal", "diff"])
        self.assertIn("is already promoted", p.stdout)

    def test_nothing_to_promote_passes(self):
        p, calls = self.promote(scenario(), proposal="")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.subcommands(calls), ["--version"])
        self.assertIn("::notice::Kronik: nothing to promote", p.stdout)

    def test_deny_fails(self):
        p, calls = self.promote(scenario("deny", "rejected"))
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("promote", self.subcommands(calls)[2:])
        self.assertNotIn("approve", self.subcommands(calls))
        self.assertIn("the policy outcome is deny", p.stdout)

    def test_promote_error_fails(self):
        p, _ = self.promote(scenario("allow", promote_error="PROPOSAL_STALE"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("PROPOSAL_STALE", p.stdout)
        self.assertEqual(self.outputs()["status"], "failed")

    def test_refused_on_pull_request(self):
        p, calls = self.run_action("promote")
        self.assertEqual(p.returncode, 1)
        self.assertIn("not on a pull request", p.stdout)
        self.assertEqual(calls, [])


def load(path):
    return yaml.safe_load(path.read_text())


class LintTest(unittest.TestCase):
    """action.yml and the reference workflow: actionlint when installed, and
    always (with PyYAML) the structure the guide promises."""

    @unittest.skipIf(shutil.which("actionlint") is None, "actionlint is not installed; skipping it")
    def test_actionlint(self):
        # The workflow with the action as a local one, so that actionlint
        # checks action.yml and the inputs the workflow gives it too.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".github" / "workflows").mkdir(parents=True)
            text = re.sub(r"G-man3207/Kronik/action@[0-9a-f]{40}", "./action", WORKFLOW.read_text())
            (Path(tmp) / ".github" / "workflows" / "kronik.yml").write_text(text)
            shutil.copytree(ACTION, Path(tmp) / "action")
            # actionlint looks for the project (and ./action) from a Git root.
            subprocess.run(["git", "init", "-q", tmp], check=True)
            p = subprocess.run(["actionlint"], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_workflow_pins_every_action(self):
        text = WORKFLOW.read_text()
        uses = re.findall(r"^\s*(?:- )?uses:\s*(\S+)", text, re.M)
        self.assertGreater(len(uses), 0)
        for ref in uses:
            self.assertRegex(ref, r"@[0-9a-f]{40}$", "pinned to a full commit SHA")
        checkouts = [u for u in uses if u.startswith("actions/checkout@")]
        settings = re.findall(r"uses: actions/checkout@\S+[^\n]*\n\s+with:\n\s+persist-credentials: false\n", text)
        self.assertEqual(len(settings), len(checkouts), "every checkout sets persist-credentials: false")

    def test_workflow_pins_an_ancestor(self):
        # A4: the pinned action commit must be in this branch's history (a
        # rebase drops the old commit). Needs a full Git checkout.
        def git(*args):
            return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)

        if shutil.which("git") is None or git("rev-parse", "--git-dir").returncode != 0:
            self.skipTest("not a Git checkout")
        if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
            self.skipTest("a shallow clone lacks the history")
        pins = set(re.findall(r"G-man3207/Kronik/action@([0-9a-f]{40})", WORKFLOW.read_text()))
        self.assertEqual(len(pins), 1, pins)
        for sha in pins:
            self.assertEqual(git("merge-base", "--is-ancestor", sha, "HEAD").returncode, 0, f"{sha} is not an ancestor of HEAD")

    @unittest.skipIf(yaml is None, "PyYAML is not installed; skipping the YAML structure checks")
    def test_action_yml(self):
        action = load(ACTION / "action.yml")
        self.assertEqual(action["runs"]["using"], "composite")
        inputs = action["inputs"]
        for name in ("command", "base-url", "components", "proposal", "environment", "reason", "window", "timeout", "allow-forks", "github-token", "comment"):
            self.assertIn("description", inputs[name])
        self.assertEqual(inputs["allow-forks"]["default"], "false")
        self.assertEqual(inputs["comment"]["default"], "true")
        self.assertEqual(inputs["github-token"]["default"], "${{ github.token }}")
        self.assertEqual(inputs["timeout"]["default"], "45m", "longer than the 30-minute replay")
        self.assertEqual(inputs["environment"]["default"], "kronik-production")
        (step,) = action["runs"]["steps"]
        self.assertEqual(step["shell"], "bash")
        for name in inputs:
            self.assertEqual(step["env"]["INPUT_" + name.upper().replace("-", "_")], "${{ inputs.%s }}" % name)
        for name in ("proposal-id", "outcome", "status"):
            self.assertEqual(action["outputs"][name]["value"], "${{ steps.kronik.outputs.%s }}" % name)
        self.assertNotIn("KRONIK_TOKEN", json.dumps(action))

    @unittest.skipIf(yaml is None, "PyYAML is not installed; skipping the YAML structure checks")
    def test_workflow(self):
        wf = load(WORKFLOW)
        on = wf.get("on", wf.get(True))  # YAML 1.1 reads a bare on as true
        self.assertIn("pull_request", on)
        self.assertNotIn("pull_request_target", on)
        self.assertEqual(on["push"]["branches"], ["main"])
        self.assertEqual(wf["permissions"], {"contents": "read"})
        propose, verify, promote = wf["jobs"]["propose"], wf["jobs"]["verify"], wf["jobs"]["promote"]
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", propose["if"])
        self.assertEqual(propose["permissions"], {"contents": "read", "pull-requests": "write", "checks": "write"})
        self.assertEqual(propose["concurrency"], {"group": "kronik-propose-${{ github.event.pull_request.number }}", "cancel-in-progress": True})
        self.assertEqual(verify["if"], "github.event_name == 'push'")
        self.assertEqual(verify["permissions"], {"contents": "read", "checks": "write"})
        self.assertEqual(verify["outputs"], {"proposal-id": "${{ steps.propose.outputs.proposal-id }}"})
        for job in (propose, verify):
            self.assertNotIn("environment", job)
        self.assertEqual(promote["needs"], "verify")
        self.assertEqual(promote["if"], "needs.verify.outputs.proposal-id != ''")
        self.assertEqual(promote["environment"], "kronik-production")
        self.assertEqual(promote["permissions"], {"actions": "read", "contents": "read"})
        for job in (propose, verify, promote):
            self.assertIn("timeout-minutes", job)
        for job, command in ((propose, "propose"), (verify, "propose"), (promote, "promote")):
            steps = [s for s in job["steps"] if s.get("with", {}).get("command") == command]
            self.assertEqual(len(steps), 1, command)
            self.assertEqual(steps[0]["env"], {"KRONIK_URL": "${{ secrets.KRONIK_URL }}", "KRONIK_TOKEN": "${{ secrets.KRONIK_TOKEN }}"})
            self.assertNotIn("TOKEN", json.dumps(steps[0]["with"]))
        (step,) = [s for s in promote["steps"] if s.get("with", {}).get("command") == "promote"]
        self.assertEqual(step["with"]["proposal"], "${{ needs.verify.outputs.proposal-id }}")
        self.assertEqual(step["with"]["environment"], promote["environment"])

    @unittest.skipIf(yaml is None, "PyYAML is not installed; skipping shellcheck of the run: blocks")
    @unittest.skipIf(shutil.which("shellcheck") is None, "shellcheck is not installed; skipping it")
    def test_shellcheck_run_blocks(self):
        steps = load(ACTION / "action.yml")["runs"]["steps"]
        steps += [s for job in load(WORKFLOW)["jobs"].values() for s in job["steps"]]
        for step in steps:
            if "run" in step:
                script = re.sub(r"\$\{\{.*?\}\}", "x", step["run"])
                p = subprocess.run(["shellcheck", "-s", "bash", "-"], input=script, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout)


class GuideTest(unittest.TestCase):
    def test_guide_includes_the_workflow(self):
        guide = (ROOT / "docs" / "guides" / "github-action.md").read_text()
        self.assertIn("{{#include ../examples/kronik-ci.yml}}", guide)

    def test_the_example_repository_has_the_reference_workflow(self):
        # examples/github-flow is what goes in a repository: its workflow is
        # the one the tests above check, byte for byte.
        example = ROOT / "examples" / "github-flow" / ".github" / "workflows" / "kronik.yml"
        self.assertEqual(example.read_text(), WORKFLOW.read_text())


if __name__ == "__main__":
    unittest.main()
