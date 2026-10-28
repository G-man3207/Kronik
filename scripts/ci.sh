#!/usr/bin/env bash
# Runs the checks that CI runs (.github/workflows/ci.yml), with the same
# commands. Exits non-zero as soon as a step fails.
#
# Usage: scripts/ci.sh [STEP...]
# Steps: fmt, clippy, hygiene, test, docs, book, examples, ts, sdks, dst, deny,
# foreign (needs root and runsc; skipped with a message otherwise, a failure
# with KRONIK_FOREIGN_TESTS=require),
# identity (without libfaketime, todo-ts is skipped with a message too),
# action.
# Without arguments, all steps run in order.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

step_fmt() {
    cargo fmt --all --check
}

step_clippy() {
    cargo clippy --workspace --all-targets --locked -- -D warnings
}

# ADR 0004 §3: only the binary, the hyper servers (kronik-gateway,
# kronik-api), kronik-core's `real` Env and kronik-foreign (the real sandbox
# boundary, outside DST: docs/design/m7-foreign.md §1) may enable tokio's
# runtime, time, net, fs, process or signal features; daemon code uses only
# `sync` and `macros`. Every `select!` must be `biased;`. And the Definition
# of done's rules: `unsafe` code only in the files that
# scripts/unsafe-allowlist.txt lists with a reason (and no stale entries),
# and no `unwrap`/`expect` in the daemon's code paths: every crate inherits
# the workspace lints that deny them, and `allow`s of those lints appear
# only in test code (tests/, examples/, #[cfg(test)] modules).
step_hygiene() {
    cargo metadata --format-version 1 --no-deps --locked | python3 -c '
import json, sys
allowed = {"kronik", "kronik-gateway", "kronik-api", "kronik-core", "kronik-foreign"}
banned = {"rt", "rt-multi-thread", "time", "net", "fs", "process", "signal", "full"}
bad = []
for p in json.load(sys.stdin)["packages"]:
    if p["name"] in allowed:
        continue
    for d in p["dependencies"]:
        if d["name"] == "tokio" and d["kind"] is None:
            bad += [f"{p["name"]}: tokio feature {f}" for f in banned & set(d["features"])]
    for feature, items in p["features"].items():
        bad += [f"{p["name"]}[{feature}]: {i}" for i in items
                if i.split("/")[0] == "tokio" and i.split("/")[-1] in banned]
for b in bad:
    print("error: " + b, file=sys.stderr)
sys.exit(1 if bad else 0)
'
    python3 - <<'PY'
import pathlib, re, sys
bad = []
for f in pathlib.Path("crates").rglob("*.rs"):
    lines = f.read_text().splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bselect!\s*\{", line):
            nxt = next((l.strip() for l in lines[i + 1:] if l.strip()), "")
            if nxt != "biased;":
                bad.append(f"{f}:{i + 1}: select! without biased;")
for b in bad:
    print("error: " + b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
    python3 - <<'PY'
import pathlib, re, sys


def code(text):
    """The text without comments, strings and char literals."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif (m := re.match(r'b?r(#*)"', text[i:i + 300])) and not (i and (text[i - 1].isalnum() or text[i - 1] == "_")):
            j = text.find('"' + m.group(1), i + m.end())
            i = n if j < 0 else j + 1 + len(m.group(1))
            out.append('""')
        elif text[i] == '"' or text.startswith('b"', i):
            j = i + (2 if text[i] == "b" else 1)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            out.append('""')
        elif m := re.match(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^\\'\n])'", text[i:i + 12]):
            i += m.end()
            out.append("' '")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def line(text, pos):
    return text.count("\n", 0, pos) + 1


bad = []
allowed = {}
for entry in pathlib.Path("scripts/unsafe-allowlist.txt").read_text().splitlines():
    if entry.strip() and not entry.startswith("#"):
        path, _, why = entry.partition(" ")
        if not why.strip():
            bad.append(f"scripts/unsafe-allowlist.txt: {path} has no reason")
        allowed[path] = why.strip()
files = [f for root in ("crates", "sdk/rust/src") for f in pathlib.Path(root).rglob("*.rs") if "target" not in f.parts]
for f in sorted(files):
    src = code(f.read_text())
    uses = [m.start() for m in re.finditer(r"\bunsafe\s*(\{|fn\b|impl\b|extern\b|trait\b)|\ballow\s*\([^)]*\bunsafe_code\b", src)]
    if uses and str(f) not in allowed:
        bad.append(f"{f}:{line(src, uses[0])}: unsafe code in a file that scripts/unsafe-allowlist.txt does not list")
    if not uses and str(f) in allowed:
        bad.append(f"scripts/unsafe-allowlist.txt: {f} has no unsafe code any more; remove its entry")
    allowed.pop(str(f), None)
    if f.parts[0] == "crates" and not {"tests", "examples", "benches"} & set(f.parts):
        for m in re.finditer(r"allow\s*\([^)]*clippy::(unwrap_used|expect_used)", src):
            before = src[max(0, m.start() - 300):m.start()]
            if not re.search(r"#\[cfg\(test\)\]\s*(mod\s+\w+\s*\{\s*#!\[|#\[)\s*$", before):
                bad.append(f"{f}:{line(src, m.start())}: allow(clippy::{m.group(1)}) outside test code")
for path in allowed:
    bad.append(f"scripts/unsafe-allowlist.txt: {path} does not exist")
for manifest in sorted(pathlib.Path("crates").glob("*/Cargo.toml")):
    if not re.search(r"^\[lints\]\s*\nworkspace\s*=\s*true", manifest.read_text(), re.M):
        bad.append(f"{manifest}: no [lints] workspace = true, so unwrap/expect are not denied")
for b in bad:
    print("error: " + b, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
    # The GitHub workflow runs every step of this script, in this order
    # (review M15 N1: a step it lacks breaks the steps after it). A call may
    # sit inside a multi-line command (foreign runs under sudo); steps that
    # call no ci.sh step (Install gVisor) and comments don't count.
    python3 - <<'PY'
import pathlib, re, sys
script = pathlib.Path("scripts/ci.sh").read_text()
steps = re.search(r"set -- ([a-z ]+)\n", script).group(1).split()
workflow = pathlib.Path(".github/workflows/ci.yml").read_text()
runs = re.findall(r"^(?![ \t]*#)[^\n]*?\bscripts/ci\.sh (\w+)", workflow, re.M)
if runs != steps:
    print(f"error: .github/workflows/ci.yml runs {runs}, scripts/ci.sh has {steps}", file=sys.stderr)
    sys.exit(1)

PY
}

step_test() {
    cargo test --workspace --locked
}

# The error catalog (docs/errors.md) and the concepts page
# (docs/concepts/glossary.md) are generated from kronik-core and must match
# what their generators print.
step_docs() {
    local pair example file generated status=0
    generated="$(mktemp)"
    for pair in errors_md:docs/errors.md concepts_md:docs/concepts/glossary.md; do
        example="${pair%%:*}"
        file="${pair#*:}"
        if ! cargo run --quiet --locked -p kronik-core --example "$example" >"$generated"; then
            status=1
        elif ! diff -u "$file" "$generated"; then
            echo "error: $file is out of date; regenerate it with: cargo run -p kronik-core --example $example > $file" >&2
            status=1
        fi
    done
    rm -f "$generated"
    return "$status"
}

# The book (docs/book.toml), built into target/book with the mdBook version
# that scripts/install-mdbook.sh pins and verifies. mdBook reports problems
# such as a missing include or an unclosed HTML tag only as WARN or ERROR
# log lines and still exits 0, so any such line fails the step. Then every
# internal link and anchor of the built book must resolve.
step_book() {
    local mdbook log status=0
    mdbook="$(scripts/install-mdbook.sh)"
    log="$(mktemp)"
    "$mdbook" build docs 2>&1 | tee "$log" || status=$?
    if [ "$status" -eq 0 ] && grep -Eq '^ *(WARN|ERROR) ' "$log"; then
        echo "error: mdbook reported problems (WARN or ERROR lines above)" >&2
        status=1
    fi
    rm -f "$log"
    if [ "$status" -eq 0 ]; then
        python3 scripts/check-book-links.py target/book || status=$?
    fi
    return "$status"
}

# The example actors (examples/) are a workspace of their own, built for
# wasm32-wasip2, with the Rust SDK as a member (examples/kronik-sdk is a
# symlink to sdk/rust): formatting, lints and the SDK's unit tests, then the
# brief's check that builds the example actors, lists their imports and fails
# if one is outside the deploy allowlist (the same check kronik deploy runs).
step_examples() {
    cargo fmt --manifest-path examples/Cargo.toml --all --check
    cargo clippy --manifest-path examples/Cargo.toml --locked -p kronik-sdk --all-targets -- -D warnings
    cargo clippy --manifest-path examples/Cargo.toml --locked --workspace --target wasm32-wasip2 -- -D warnings
    cargo test --manifest-path examples/Cargo.toml --locked -p kronik-sdk
    scripts/build-examples.sh
    cargo run --quiet --locked -p kronik-runtime --example check_imports -- examples/dist/*.wasm
}

# The TypeScript SDK (sdk/ts): its types (the guest code and the Node.js
# testkit), its unit tests, and the types/ that `jco guest-types` generates
# from the WIT, which must be up to date. Then the TypeScript examples, built
# with kronik build, which type-checks them and fails on an import outside
# the deploy allowlist; their imports are listed with the same check as the
# Rust examples', and their tests run them in test hosts. Last, new projects
# from kronik init, in both languages, pass their own tests and build
# (scripts/e2e-init.sh). The binary is a release build: a debug build's
# Cranelift takes a minute to compile a JavaScript component for a test
# host, and the release dependencies are shared with the dst step. Needs
# Node.js 22.20 or later and network access.
step_ts() {
    local kronik
    npm ci --prefix sdk/ts --no-audit --no-fund
    (cd sdk/ts && npm run --silent check && node --test test/*.test.ts && npm run --silent types && git diff --exit-code -- types)
    cargo build --locked --release -p kronik
    # Where cargo put it, also with CARGO_TARGET_DIR set.
    kronik="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)/release/kronik"
    KRONIK_BIN="$kronik" scripts/build-examples-ts.sh
    cargo run --quiet --locked -p kronik-runtime --example check_imports -- examples/dist/*-ts*.wasm
    (cd examples && KRONIK_BIN="$kronik" npm test --workspaces)
    KRONIK_BIN="$kronik" E2E_INIT_LANGS="ts rust" scripts/e2e-init.sh
}

# M15: the Python and Go SDKs (ADR 0030, docs/design/m15-sdks.md). Installs
# the pinned toolchains (scripts/install-sdk-tools.sh, once per version),
# checks that both SDKs carry the actor WIT unchanged and that the Go
# bindings are generated from it, runs the SDKs' unit tests, builds the
# examples with kronik build, lists their imports against the allowlist,
# runs the examples' tests in test hosts and the determinism test on them,
# and new projects from kronik init in both languages (scripts/e2e-init.sh).
# Needs Linux x86_64, python3 with pip, and network access for the first
# install and Go's module downloads.
step_sdks() {
    local kronik tools
    tools="${KRONIK_SDK_TOOLS:-$HOME/.cache/kronik/sdk-tools}"
    scripts/install-sdk-tools.sh "$tools"
    export KRONIK_SDK_TOOLS="$tools"
    cmp wit/kronik-actor.wit sdk/python/wit/kronik-actor.wit
    cmp wit/kronik-actor.wit sdk/go/wit/deps/kronik-actor/kronik-actor.wit
    (cd sdk/go && PATH="$tools/bin:$PATH" ./generate.sh && git diff --exit-code -- internal/wit)
    python3 -m unittest discover -s sdk/python/tests
    # The SDK package's own tests (sdk_test.go, host_test.go) and testkit.
    (cd sdk/go && PATH="$tools/bin:$PATH" GOTOOLCHAIN=local go vet . ./testkit/... &&
        PATH="$tools/bin:$PATH" GOTOOLCHAIN=local go test . ./testkit/...)
    cargo build --locked --release -p kronik
    # Where cargo put it, also with CARGO_TARGET_DIR set.
    kronik="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)/release/kronik"
    KRONIK_BIN="$kronik" scripts/build-examples-py.sh
    KRONIK_BIN="$kronik" scripts/build-examples-go.sh
    cargo run --quiet --locked -p kronik-runtime --example check_imports -- examples/dist/*-py*.wasm examples/dist/*-go*.wasm
    local example
    for example in counter-py notes-py webhook-relay-py; do
        (cd "examples/$example" && KRONIK_BIN="$kronik" python3 -m unittest discover -s tests)
    done
    for example in counter-go notes-go webhook-relay-go; do
        (cd "examples/$example/test" && KRONIK_BIN="$kronik" PATH="$tools/bin:$PATH" GOTOOLCHAIN=local go test ./...)
    done
    # Absolute: cargo runs the test in the crate's directory.
    KRONIK_DETERMINISM_COMPONENTS="$(printf '%s:' "$PWD"/examples/dist/{counter,notes,webhook-relay}-{py,go}.wasm)" \
        cargo test --locked -p kronik-sched --test sdk_determinism
    KRONIK_BIN="$kronik" E2E_INIT_LANGS="python go" scripts/e2e-init.sh
}

# The simulator's acceptance run: 200 seeds of the counter workload (M1) and
# of the effects workload against a simulated external service (M2), with
# crashes, each run twice to check determinism; then 200 seeds of the
# rebuild workload (tiny bulk-replay thresholds; every start's recovered
# state against a rebuild from the log).
step_dst() {
    cargo test --locked --release -p kronik-sim --test dst -- --seeds 0..200 --twice
    cargo test --locked --release -p kronik-sim --test dst -- --seeds 0..200 --scenario rebuild --twice
}

step_deny() {
    if ! cargo deny --version >/dev/null 2>&1; then
        echo "error: cargo-deny is not installed; install it with: cargo install --locked cargo-deny" >&2
        return 1
    fi
    cargo deny --locked check
    # The examples (with the Rust SDK) have a lockfile of their own, and their
    # few dependencies use only some of the licenses deny.toml allows.
    cargo deny --manifest-path examples/Cargo.toml --locked check -A license-not-encountered
}

# M7: foreign actors in real gVisor sandboxes. Needs root and runsc
# (docs/design/m7-foreign.md §14); elsewhere it says why and skips, unless
# KRONIK_FOREIGN_TESTS=require (as in CI), which makes every skip, here and
# in the tests, a failure. M14's Postgres fork test also needs docker, for
# the foreign-pg image's base.
step_foreign() {
    local runsc="${KRONIK_RUNSC:-/usr/local/bin/runsc}"
    if [ "$(id -u)" != 0 ] || [ ! -x "$runsc" ]; then
        local why="the foreign step needs root and runsc at $runsc (scripts/install.sh installs gVisor)"
        if [ "${KRONIK_FOREIGN_TESTS:-}" = require ]; then
            echo "error: KRONIK_FOREIGN_TESTS=require, but $why" >&2
            return 1
        fi
        echo "skipped: $why"
        return 0
    fi
    scripts/build-foreign-examples.sh
    KRONIK_FOREIGN_TESTS=require cargo test --locked -p kronik --test foreign -- --test-threads=1
}

# Identity replay of every example app (the Definition of done: "Identity
# replay empty for all example apps"): each example runs on a fresh daemon,
# is driven, forked and replayed in both modes (scripts/identity-examples.sh),
# and both behavior diffs must be empty. The binary is a release build: a
# debug build takes minutes per example, and the release dependencies are
# shared with the dst step. todo-ts restarts its daemon under libfaketime
# for its day-later sweep; without the library the run covers the other
# examples and says why (as the foreign step does).
step_identity() {
    local faketime_lib="${FAKETIME_LIB:-}"
    if [ -z "$faketime_lib" ]; then
        # The same search scripts/identity-examples.sh does.
        local lib
        for lib in /usr/lib/*/faketime/libfaketimeMT.so.1 \
                /usr/lib/faketime/libfaketimeMT.so.1 \
                /usr/local/lib/faketime/libfaketimeMT.so.1; do
            if [ -f "$lib" ]; then
                faketime_lib="$lib"
                break
            fi
        done
    fi
    local only=()
    if [ -z "$faketime_lib" ]; then
        echo "skipped: todo-ts needs libfaketime for its sweep (Debian and Ubuntu: apt-get install faketime)"
        # Every example in scripts/identity-examples.py's EXAMPLES but todo-ts.
        only=(--only counter-rs,counter-ts,counter-py,counter-go,notes-rs,notes-ts,notes-py,notes-go,webhook-relay-rs,webhook-relay-ts,webhook-relay-py,webhook-relay-go,billing-ts)
    fi
    cargo build --locked --release -p kronik
    # Where cargo put it, also with CARGO_TARGET_DIR set.
    local kronik
    kronik="$(cd "${CARGO_TARGET_DIR:-target}" && pwd)/release/kronik"
    KRONIK_BIN="$kronik" scripts/identity-examples.sh "${only[@]}"
}

# The GitHub Action (action/, docs/guides/github-action.md): its unit tests
# run kronik_action.py against a fake kronik and a fake GitHub API, and lint
# action.yml and the reference workflow (docs/examples/kronik-ci.yml): their
# structure with PyYAML, their run: blocks with shellcheck, and both with
# actionlint when it is installed; each check that lacks its tool is skipped
# with a message.
step_action() {
    python3 -B -m unittest discover -v -s action/tests
}

if [ "$#" -eq 0 ]; then
    set -- fmt clippy hygiene test docs book examples ts sdks dst deny foreign identity action
fi

for step in "$@"; do
    case "$step" in
        fmt | clippy | hygiene | test | docs | book | examples | ts | sdks | dst | deny | foreign | identity | action) ;;
        *)
            echo "error: unknown step '$step'; expected fmt, clippy, hygiene, test, docs, book, examples, ts, sdks, dst, deny, foreign, identity or action" >&2
            exit 2
            ;;
    esac
    echo "==> $step"
    "step_$step"
done

echo "==> passed: $*"
