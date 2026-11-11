#!/usr/bin/env bash
# M15 acceptance: the Python and Go examples through the M1 to M3 commands
# in docs/design/m15-sdks.md section 5. Runnable on its own. scripts/ci.sh
# step_sdks calls it after installing the pinned tools.
#
#   M1  M1_GUESTS=py and M1_GUESTS=go on scripts/e2e-m1.sh and
#       scripts/acceptance-m1.sh (counter and notes)
#   M2  RELAY=examples/dist/webhook-relay-py.wasm and the Go twin on
#       scripts/e2e-webhook-relay.sh; DST with KRONIK_DST_RELAY set to
#       each (--scenario webhook --seeds 0..200 --twice)
#   M3  demo/verify-change.sh with COUNTER and COUNTER_NEW set to the
#       counter and its -step2 build
#
# Does not substitute M1_GUESTS=test. When the pinned SDK tools are absent
# it prints why and skips, as the other optional CI checks do. It does not
# skip when those tools are installed.
#
# Usage: [KRONIK_BIN=path] [KRONIK_SDK_TOOLS=dir] scripts/acceptance-m15.sh
# Needs curl and python3, and a release kronik (built here if it is
# missing). DST needs cargo. Each language's examples are built first when
# that language's tools are present.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# rustup may be installed without being added to PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "${CARGO_HOME:-$HOME/.cargo}/env" ]; then
    # shellcheck source=/dev/null
    . "${CARGO_HOME:-$HOME/.cargo}/env"
fi

# Same directory as scripts/install-sdk-tools.sh and step_sdks. Absence is
# a missing executable there, not a guess from PATH, so a host that has the
# pinned tools in that directory is not skipped.
tools="${KRONIK_SDK_TOOLS:-${HOME:-}/.cache/kronik/sdk-tools}"

tool_ok() {
    [ -n "$tools" ] && [ -x "$tools/bin/$1" ]
}

# Names in "$@" that are not executable in the SDK tools bin.
missing_tools() {
    local missing=() tool
    for tool in "$@"; do
        if ! tool_ok "$tool"; then
            missing+=("$tool")
        fi
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        return 0
    fi
    printf '%s\n' "${missing[*]}"
    return 1
}

python_missing=""
go_missing=""
python_ready=0
go_ready=0
if python_missing="$(missing_tools componentize-py wasi-virt)"; then
    python_ready=1
    python_missing=""
fi
if go_missing="$(missing_tools go tinygo wasm-tools wasi-virt)"; then
    go_ready=1
    go_missing=""
fi

skip_absent() {
    local names="$1" which="$2" platform why
    platform="$(uname -s)-$(uname -m)"
    why="the pinned ${which} SDK toolchain is absent (${names} not executable in the SDK tools bin; scripts/install-sdk-tools.sh installs it)"
    if [ "$platform" != "Linux-x86_64" ]; then
        why="the pinned SDK toolchains are for Linux x86_64, not ${platform}; ${why}"
    fi
    echo "skipped: ${why}"
}

if [ "$python_ready" -eq 0 ] && [ "$go_ready" -eq 0 ]; then
    # One message: both languages need the same install, and wasi-virt is shared.
    absent="$(missing_tools componentize-py go tinygo wasm-tools wasi-virt || true)"
    skip_absent "$absent" "Python and Go"
    exit 0
fi
if [ "$python_ready" -eq 0 ]; then
    skip_absent "$python_missing" "Python"
fi
if [ "$go_ready" -eq 0 ]; then
    skip_absent "$go_missing" "Go"
fi

export KRONIK_SDK_TOOLS="$tools"

if [ -z "${KRONIK_BIN:-}" ]; then
    KRONIK_BIN="${CARGO_TARGET_DIR:-target}/release/kronik"
fi
if [ ! -x "$KRONIK_BIN" ]; then
    cargo build --locked --release -p kronik
fi
if [ ! -x "$KRONIK_BIN" ]; then
    echo "error: no release kronik binary; build it with: cargo build --locked --release -p kronik" >&2
    exit 1
fi
export KRONIK_BIN

require_component() {
    if [ ! -s "$1" ]; then
        echo "error: missing $1; M15 acceptance does not substitute M1_GUESTS=test" >&2
        exit 1
    fi
}

run_lang() {
    local lang="$1" relay
    case "$lang" in
        py | go) ;;
        *)
            echo "error: M15 acceptance runs py and go, not '$lang'" >&2
            exit 2
            ;;
    esac

    echo "== build ${lang} examples"
    case "$lang" in
        py) scripts/build-examples-py.sh ;;
        go) scripts/build-examples-go.sh ;;
    esac
    require_component "examples/dist/counter-${lang}.wasm"
    require_component "examples/dist/notes-${lang}.wasm"
    require_component "examples/dist/webhook-relay-${lang}.wasm"
    require_component "examples/dist/counter-${lang}-step2.wasm"

    echo "== M1 ${lang}: M1_GUESTS=${lang} scripts/e2e-m1.sh"
    M1_GUESTS="$lang" scripts/e2e-m1.sh
    echo "== M1 ${lang}: M1_GUESTS=${lang} scripts/acceptance-m1.sh"
    M1_GUESTS="$lang" scripts/acceptance-m1.sh

    relay="examples/dist/webhook-relay-${lang}.wasm"
    echo "== M2 ${lang}: RELAY=${relay} scripts/e2e-webhook-relay.sh"
    RELAY="$relay" scripts/e2e-webhook-relay.sh

    # docs/design/m15-sdks.md section 5, full seed range. The harness does
    # not run with this checkout as its cwd, so the relay path is resolved
    # from here before it is passed.
    echo "== M2 ${lang}: DST KRONIK_DST_RELAY=${relay} --scenario webhook --seeds 0..200 --twice"
    KRONIK_DST_RELAY="$PWD/${relay}" \
        cargo test --locked --release -p kronik-sim --test dst -- \
        --scenario webhook --seeds 0..200 --twice

    echo "== M3 ${lang}: COUNTER=examples/dist/counter-${lang}.wasm COUNTER_NEW=examples/dist/counter-${lang}-step2.wasm demo/verify-change.sh"
    COUNTER="examples/dist/counter-${lang}.wasm" \
        COUNTER_NEW="examples/dist/counter-${lang}-step2.wasm" \
        demo/verify-change.sh
}

ran=()
if [ "$python_ready" -eq 1 ]; then
    run_lang py
    ran+=(py)
fi
if [ "$go_ready" -eq 1 ]; then
    run_lang go
    ran+=(go)
fi

echo "PASS: M15 acceptance for ${ran[*]}"
