#!/usr/bin/env python3
"""Check that the workflow runs every default ci.sh step exactly once.

The steps may be spread over parallel jobs. Each job runs its steps in the
order ci.sh lists them, since a later step of a job can use what an earlier
one built. The workflow is read as text, so the check needs no YAML library.
"""

import pathlib
import re
import shlex
import sys


def jobs(workflow):
    """The text of each job under the top-level `jobs:` key, by job id. A text
    without that key is one job, named ``workflow``."""
    match = re.search(r"^jobs:[ \t]*(?:#.*)?$", workflow, re.M)
    if match is None:
        return {"workflow": workflow}
    found = {}
    indent = name = None
    for line in workflow[match.end():].splitlines():
        if line.strip() == "" or line.lstrip().startswith("#"):
            if name is not None:
                found[name] += line + "\n"
            continue
        if not line[0].isspace():
            break  # the next top-level key
        width = len(line) - len(line.lstrip())
        if indent is None:
            indent = width
        header = re.match(r"([A-Za-z0-9_-]+):[ \t]*(?:#.*)?$", line[width:])
        if width == indent and header:
            name = header.group(1)
            if name in found:
                raise ValueError(f"workflow defines job {name} twice")
            found[name] = ""
        elif name is not None:
            found[name] += line + "\n"
    return found


def calls(text, steps):
    """The ci.sh steps that the commands in `text` run, in order."""
    runs = []
    # The workflow uses literal shell commands; join shell continuations before
    # taking every argument up to a shell operator (foreign ends in || status=$?).
    for line in re.sub(r"\\\n[ \t]*", " ", text).splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = re.search(r"\bscripts/ci\.sh\b(.*)", line)
        if match is None:
            continue
        lexer = shlex.shlex(match.group(1), posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        args = []
        for arg in lexer:
            if arg and arg[0] in ";&|()<>":
                break
            args.append(arg)
        runs.extend(args or steps)  # ci.sh without arguments runs the defaults.
    return runs


def check(script, workflow):
    match = re.search(r"^\s*set -- ([a-z -]+)$", script, re.M)
    if match is None:
        raise ValueError("scripts/ci.sh has no default step inventory")
    steps = match.group(1).split()
    where = {}
    for job, text in jobs(workflow).items():
        runs = calls(text, steps)
        unknown = sorted(set(runs) - set(steps))
        if unknown:
            raise ValueError(f"workflow calls unknown ci.sh steps: {unknown}")
        if runs != sorted(runs, key=steps.index):
            raise ValueError(f"job {job} runs {runs}, not in the order of ci.sh's {steps}")
        for step in runs:
            where.setdefault(step, []).append(job)
    twice = {step: names for step, names in where.items() if len(names) > 1}
    if twice:
        raise ValueError(f"workflow runs ci.sh steps more than once: {twice}")
    missing = [step for step in steps if step not in where]
    if missing:
        raise ValueError(f"workflow does not run every ci.sh step {steps}; missing: {missing}")


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        check((root / "scripts/ci.sh").read_text(),
              (root / ".github/workflows/ci.yml").read_text())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
