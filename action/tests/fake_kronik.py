#!/usr/bin/env python3
"""A stand-in for kronik in the action's tests: records its argv and the
tokens in its environment to $FAKE_KRONIK_LOG (JSON lines) and answers each
subcommand from the scenario in $FAKE_KRONIK_SCENARIO:
{"propose"|"wait"|"diff"|"approve"|"promote": {"stdout": ..., "exit": n,
"sleep": seconds, "stderr": text}}. An error is {"error": {"code", "message",
"hint"}} on stdout with exit 1, as kronik --json prints it."""

import json
import os
import sys
import time

argv = sys.argv[1:]
if os.environ.get("FAKE_KRONIK_LOG"):
    with open(os.environ["FAKE_KRONIK_LOG"], "a") as f:
        record = {
            "argv": argv,
            "kronik_token": os.environ.get("KRONIK_TOKEN"),
            "github_token": os.environ.get("INPUT_GITHUB_TOKEN"),
        }
        f.write(json.dumps(record) + "\n")
words = [a for a in argv if a != "--json"]
if words == ["--version"]:
    print("kronik 0.0.0-fake")
    sys.exit(0)
key = {"propose": "propose", "proposal": "wait", "diff": "diff", "approve": "approve", "promote": "promote"}[words[0]]
with open(os.environ["FAKE_KRONIK_SCENARIO"]) as f:
    reply = json.load(f)[key]
out = reply["stdout"]
time.sleep(reply.get("sleep", 0))
sys.stderr.write(reply.get("stderr", ""))
print(out if isinstance(out, str) else json.dumps(out))
sys.exit(reply.get("exit", 0))
