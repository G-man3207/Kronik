#!/usr/bin/env bash
# The M3 flow end to end with the real binary (brief: demo/verify-change.sh):
# serve, deploy counter-rs, record traffic, fork + replay + diff, propose a
# change (counter +2), traffic while the proposal waits, promote with
# catch-up, check that the new code serves, roll back, check the old
# behaviour again. Prints the elapsed time; the brief's budget on a fresh
# VPS is 10 minutes.
#
# Usage: [KRONIK_BIN=path] [GUESTS=examples|test] [COUNTER=old.wasm]
#        [COUNTER_NEW=new.wasm] [REQUESTS=500] demo/verify-change.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-verify-change, port 47821, KRONIK_BIN
# target/release/kronik, GUESTS=examples (examples/dist/counter.wasm and
# counter-step2.wasm from scripts/build-examples.sh; `test` uses
# tests/guests/counter.wasm and counter-step2.wasm). COUNTER and COUNTER_NEW
# override the two components (e.g. the TypeScript counter and its +2
# build): any kind `counter` with POST /counter/{key}/increment answering
# JSON {"n": N}, as the examples do, or the decimal N, as the test guests
# do. Needs curl and python3.
# External owned mode: KRONIK_DEMO_{SOCKET,HTTP,DATA_DIR,RUN_DIR,OWNER_TOKEN,FIXTURE}.
# It audits the exact nonroot fixture, retains evidence, and never stops/removes it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-verify-change}"
port="${2:-47821}"
bin="${KRONIK_BIN:-target/release/kronik}"
requests="${REQUESTS:-500}"
case "${GUESTS:-examples}" in
    examples)
        old=examples/dist/counter.wasm
        new=examples/dist/counter-step2.wasm
        inc() { echo "/$kind/$1/increment"; }
        ;;
    test)
        old=tests/guests/counter.wasm
        new=tests/guests/counter-step2.wasm
        inc() { echo "/$kind/$1/increment"; }
        ;;
    *)
        echo "GUESTS must be examples or test" >&2
        exit 2
        ;;
esac
old="${COUNTER:-$old}"
new="${COUNTER_NEW:-$new}"
for f in "$bin" "$old" "$new"; do
    [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done
external=0
sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
if [ -n "${KRONIK_DEMO_SOCKET:-}" ]; then
    : "${KRONIK_DEMO_HTTP:?external daemon needs its HTTP URL}"
    : "${KRONIK_DEMO_DATA_DIR:?external daemon needs its owned data directory}"
    : "${KRONIK_DEMO_RUN_DIR:?external daemon needs its owned runtime directory}"
    : "${KRONIK_DEMO_OWNER_TOKEN:?external daemon needs its fixture ownership token}"
    : "${KRONIK_DEMO_FIXTURE:?external daemon needs its trusted fixture manifest}"
    bash scripts/check-rootless.sh --fixture "$KRONIK_DEMO_FIXTURE"
    [ "$(cat "$KRONIK_DEMO_DATA_DIR/.kronik-proof-owner")" = "$KRONIK_DEMO_OWNER_TOKEN" ] ||
        { echo "wrong external fixture owner" >&2; exit 2; }
    [ ! -e "$dir" ] || { echo "evidence directory already exists: $dir" >&2; exit 2; }
    external=1
    sock=$KRONIK_DEMO_SOCKET
    gw=$KRONIK_DEMO_HTTP
fi
pid=""

if [ "$external" = 0 ]; then rm -rf "$dir"; fi
umask 077
mkdir -p "$dir"
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; true' EXIT

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() { echo "FAIL: $*" >&2; tail -20 "$dir/serve.log" >&2 || true; exit 1; }

api() { # METHOD PATH [JSON] (the body goes through stdin: components are big)
    local out
    out=$(printf '%s' "${3:-}" | curl -s --unix-socket "$sock" -X "$1" \
        -H 'content-type: application/json' ${3:+--data-binary @-} "http://kronik$2") ||
        fail "API $1 $2"
    printf '%s' "$out"
}
field() { # JSON PYTHON-EXPR (on v)
    python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"
}
b64() { python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$1"; }
traffic() { # COUNT
    for i in $(seq 1 "$1"); do
        curl -sf -X POST "$gw$(inc "k$((i % 10))")" >/dev/null || fail "request $i"
    done
}
value() { # KEY -> n after one more increment: JSON {"n": N} or the decimal N
    curl -sf -X POST "$gw$(inc "$1")" |
        python3 -c 'import json,sys; v=json.load(sys.stdin); print(v["n"] if isinstance(v, dict) else int(v))'
}

step "serve"
if [ "$external" = 0 ]; then
    setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
        --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && break
        sleep 0.1
    done
fi
curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null || fail "daemon not healthy"

step "deploy counter"
r=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$old")\",\"dry_run\":true,\"reason\":\"demo manifest\"}")
kind=$(field "$r" 'v["deployment"]["kind"]')
[ -n "$kind" ] || fail "component has no actor kind"
if [ "$external" = 1 ]; then
    api GET /v1/deployments >"$dir/preexisting-deployments.json"
    python3 -c 'import json,sys; kind=sys.argv[2]; assert not any(k["kind"]==kind for d in json.load(open(sys.argv[1]))["deployments"] for k in d["kinds"]), "refusing to overwrite an existing kind"' \
        "$dir/preexisting-deployments.json" "$kind" || fail "external fixture already has kind $kind"
fi
r=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$old")\",\"reason\":\"demo\"}")
[ "$(field "$r" 'v["deployment"]["kind"]')" = "$kind" ] || fail "deploy: $r"
fork_lsn=$(field "$(api GET /v1/health)" 'v["applied_lsn"]')

step "record $requests requests"
traffic "$requests"

step "fork, deploy +2 in the fork, replay, diff"
r=$(api POST /v1/forks "{\"at\":$fork_lsn,\"name\":\"try-step2\",\"reason\":\"demo\"}")
[ "$(field "$r" 'v["fork"]["name"]')" = try-step2 ] || fail "fork create: $r"
r=$(api POST /v1/forks/try-step2/deployments "{\"wasm_base64\":\"$(b64 "$new")\",\"reason\":\"demo\"}")
r=$(api POST /v1/forks/try-step2/replay '{"reason":"demo"}')
[ "$(field "$r" 'v["summary"]["changed"]')" = True ] || fail "replay: $r"
echo "replay: $(field "$r" 'v["summary"]')"
curl -s --unix-socket "$sock" "http://kronik/v1/forks/try-step2/diff?format=md" >"$dir/fork-diff.md"
grep -q "Behavior diff" "$dir/fork-diff.md" || fail "markdown diff"
echo "diff: $dir/fork-diff.md ($(wc -l <"$dir/fork-diff.md") lines)"

step "propose counter +2"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$new")\"],\"reason\":\"demo: count by two\"}")
id=$(field "$r" 'v["proposal"]["id"]')
[ "$(field "$r" 'v["proposal"]["policy"]["outcome"]')" = allow ] || fail "propose: $r"
echo "proposal $id: $(field "$r" 'v["proposal"]["summary"]["root_inputs"]') root inputs, $(field "$r" 'v["proposal"]["summary"]["divergent_turns"]') divergent turns"
curl -s --unix-socket "$sock" "http://kronik/v1/proposals/$id/diff?format=md" >"$dir/proposal-diff.md"

step "traffic while the proposal waits"
traffic 50
before=$(field "$(api GET /v1/health)" 'v["applied_lsn"]')

step "promote (catch-up first)"
r=$(api POST "/v1/proposals/$id/promote" '{"reason":"demo"}')
epoch=$(field "$r" 'v["deployment"]["epoch"]')
verified=$(field "$r" 'v["deployment"]["verified_through_lsn"]')
[ "$verified" -ge "$before" ] || fail "catch-up stopped at $verified < $before: $r"
echo "deployment epoch $epoch, verified through $verified, unverified $(field "$r" 'v["deployment"]["unverified_inputs"]')"

step "the new code serves"
n1=$(value k1); n2=$(value k1)
[ $((n2 - n1)) -eq 2 ] || fail "after promote: $n1 then $n2"

step "rollback"
r=$(api POST "/v1/deployments/$epoch/rollback" '{"reason":"demo"}')
[ "$(field "$r" 'v["deployment"]["epoch"]')" -gt "$epoch" ] || fail "rollback: $r"
n3=$(value k1); n4=$(value k1)
[ $((n4 - n3)) -eq 1 ] || fail "after rollback: $n3 then $n4"

elapsed=$(( $(date +%s) - started ))
printf '\nPASS: verify-change in %ss (budget 600 s)\n' "$elapsed"
[ "$elapsed" -le 600 ] || fail "over the 10 minute budget"
