#!/usr/bin/env python3
"""Check that the workflow runs every default ci.sh step, once and in order."""

import pathlib
import re
import shlex
import sys


def check(script, workflow):
    match = re.search(r"^\s*set -- ([a-z ]+)$", script, re.M)
    if match is None:
        raise ValueError("scripts/ci.sh has no default step inventory")
    steps = match.group(1).split()
    runs = []
    # The workflow uses literal shell commands; join shell continuations before
    # taking every argument up to a shell operator (foreign ends in || status=$?).
    for line in re.sub(r"\\\n[ \t]*", " ", workflow).splitlines():
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
    unknown = sorted(set(runs) - set(steps))
    if unknown:
        raise ValueError(f"workflow calls unknown ci.sh steps: {unknown}")
    if runs != steps:
        missing = [step for step in steps if step not in runs]
        raise ValueError(f"workflow runs {runs}, ci.sh expects {steps}; missing: {missing}")


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        check((root / "scripts/ci.sh").read_text(),
              (root / ".github/workflows/ci.yml").read_text())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
