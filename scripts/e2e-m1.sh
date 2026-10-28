#!/usr/bin/env bash
# M1 end-to-end check with the real binary: serve, deploy over the API socket,
# HTTP turns through the gateway, Idempotency-Key, a failed turn, kill -9,
# recovery.
#
# M1_GUESTS picks the actors: `test` (default) runs the WIT-level test guest
# tests/guests/counter.wasm; `examples` runs the Rust SDK examples counter-rs
# and notes-rs from examples/dist (build them with scripts/build-examples.sh)
# and also checks notes-rs's routes and a failed message turn; `ts` does the
# same with their TypeScript twins counter-ts and notes-ts (build them with
# scripts/build-examples-ts.sh).
#
# Usage: [M1_GUESTS=test|examples|ts] [KRONIK_BIN=path] scripts/e2e-m1.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-e2e and port 47811, KRONIK_BIN
# target/release/kronik. Needs curl and python3, and a release build (cargo
# build --release -p kronik).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dir="${1:-/var/tmp/kronik-e2e}"
port="${2:-47811}"
bin="${KRONIK_BIN:-target/release/kronik}"
guests="${M1_GUESTS:-test}"
sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
pid=""

case "$guests" in
    test) ;;
    examples)
        counter=examples/dist/counter.wasm
        notes=examples/dist/notes.wasm
        ;;
    ts)
        counter=examples/dist/counter-ts.wasm
        notes=examples/dist/notes-ts.wasm
        ;;
    *)
        echo "M1_GUESTS must be test, examples or ts, not '$guests'" >&2
        exit 2
        ;;
esac

rm -rf "$dir"
mkdir -p "$dir"

start() {
    setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
        --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        if curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1; then
            return
        fi
        sleep 0.1
    done
    echo "FAIL: daemon did not become healthy" >&2
    cat "$dir/serve.log" >&2
    exit 1
}

stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}
trap stop EXIT

expect() { # expect <what> <want> <got>
    if [ "$2" != "$3" ]; then
        echo "FAIL: $1: want '$2', got '$3'" >&2
        exit 1
    fi
    echo "ok: $1 = $3"
}

api() { curl -s --unix-socket "$sock" "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
deploy() { # deploy <component>: prints the deployed kind
    python3 -c "import base64,json,sys; print(json.dumps({'wasm_base64': base64.b64encode(open(sys.argv[1],'rb').read()).decode(), 'reason': 'e2e deploy'}))" "$1" >"$dir/deploy.json"
    api -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments | json 'd["deployment"]["kind"]'
}
# The counter's value in a response body: the decimal n from the test guest,
# {"n": n} from the SDK examples.
counter_value() {
    if [ "$guests" != test ]; then
        json 'd["n"]'
    else
        cat
    fi
}
counter() { curl -s "$@" | counter_value; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

start
expect "health" "ok" "$(api http://kronik/v1/health | json 'd["status"]')"

if [ "$guests" != test ]; then
    expect "deploy kind" "counter" "$(deploy "$counter")"
    expect "deploy kind" "notes" "$(deploy "$notes")"
else
    expect "deploy kind" "counter" "$(deploy tests/guests/counter.wasm)"
fi

for i in 1 2 3; do
    expect "increment $i" "$i" "$(counter -X POST "$gw/counter/e2e/increment")"
done
expect "idempotent first" "4" "$(counter -X POST -H 'Idempotency-Key: abc' -d x "$gw/counter/e2e/increment")"
expect "idempotent repeat" "4" "$(counter -X POST -H 'Idempotency-Key: abc' -d x "$gw/counter/e2e/increment")"
expect "idempotent other body" "422 IDEMPOTENCY_KEY_REUSED" "$(curl -s -o "$dir/reused.json" -w '%{http_code}' -X POST -H 'Idempotency-Key: abc' -d y "$gw/counter/e2e/increment") $(json 'd["error"]["code"]' <"$dir/reused.json")"
if [ "$guests" != test ]; then
    # The notes examples do not handle messages, so this turn fails and the
    # message becomes a dead letter.
    expect "failed turn" "rejected TURN_FAILED" "$(api -X POST -d '{"name":"archive","reason":"e2e"}' http://kronik/v1/actors/notes/e2e/messages | json 'd["outcome"]["kind"] + " " + d["outcome"]["error_code"]')"
    expect "dead letter" "notes/e2e" "$(api http://kronik/v1/dead-letters | json '",".join(x["actor"] for x in d["dead_letters"])')"
else
    expect "failed turn" "500 TURN_FAILED" "$(curl -s -o "$dir/fail.json" -w '%{http_code}' -X POST "$gw/counter/e2e/fail") $(json 'd["error"]["code"]' <"$dir/fail.json")"
fi
expect "operator send" "5" "$(api -X POST -d '{"name":"increment","reason":"e2e"}' http://kronik/v1/actors/counter/e2e/messages | json 'd["reply"]["text"]' | counter_value)"

if [ "$guests" != test ]; then
    expect "create note" "201 1" "$(curl -s -o "$dir/note.json" -w '%{http_code}' -X POST -d '{"title":"first","body":"hello"}' "$gw/notes/e2e") $(json 'd["id"]' <"$dir/note.json")"
    expect "get note" "first hello" "$(curl -s "$gw/notes/e2e/1" | json 'd["title"] + " " + d["body"]')"
    expect "invalid note" "400" "$(status -X POST -d 'not json' "$gw/notes/e2e")"
    expect "create second note" "2" "$(curl -s -X POST -d '{"title":"second"}' "$gw/notes/e2e" | json 'd["id"]')"
    expect "delete note" "204" "$(status -X DELETE "$gw/notes/e2e/1")"
    expect "deleted note" "404" "$(status "$gw/notes/e2e/1")"
    expect "list notes" "[2]" "$(curl -s "$gw/notes/e2e" | json '[n["id"] for n in d["notes"]]')"
fi

echo "kill -9 $pid"
kill -9 "$pid"
wait "$pid" 2>/dev/null || true
pid=""

start
expect "state after kill -9" "5" "$(counter "$gw/counter/e2e")"
expect "idempotent after restart" "4" "$(counter -X POST -H 'Idempotency-Key: abc' -d x "$gw/counter/e2e/increment")"
expect "increment after restart" "6" "$(counter -X POST "$gw/counter/e2e/increment")"
expect "turns in history" "8" "$(api 'http://kronik/v1/actors/counter/e2e' | json 'd["actor"]["turns"]')"
if [ "$guests" != test ]; then
    expect "notes after kill -9" "[2]" "$(curl -s "$gw/notes/e2e" | json '[n["id"] for n in d["notes"]]')"
fi
echo "PASS: e2e M1 with the $guests guests (log: $dir/serve.log)"
