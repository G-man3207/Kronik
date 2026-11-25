#!/usr/bin/env bash
# The setup the payments-platform dogfood demos share (issue #302): sourced,
# never run. The sourcing demo (demo/payments-platform-*.sh) sets started,
# dir, port, bin, billing, ledger and its variant wasm path, then calls
# payments_preflight, payments_serve and payments_deploy in that order; the
# scenario-specific fork, replay and proposal steps follow as before.
#
# `demo/billing.sh` sources this file for its helpers only (`step`, `fail`,
# `api`, `field`, `b64`, `http`, `invoice`, `payments_cleanup`) and keeps its
# own preflight and serve steps because of its external owned mode.

. scripts/lib.sh

layout=examples/dist/fake-payments.oci
api_key="demo-key-$(date +%s%N | sha256sum | cut -c1-16)"

payments_preflight() { # VARIANT-WASM...: root, runsc, the binary and the wasms
    [ "$(id -u)" = 0 ] || { echo "$0 needs root (foreign actors run in gVisor)" >&2; exit 2; }
    [ -x /usr/local/bin/runsc ] || { echo "needs runsc: scripts/install.sh installs gVisor" >&2; exit 2; }
    local f
    for f in "$bin" "$billing" "$ledger" "$@"; do
        [ -e "$f" ] || { echo "missing $f (cargo build --release; scripts/build-examples-ts.sh)" >&2; exit 2; }
    done
    if [ ! -e "$layout/index.json" ]; then
        scripts/build-foreign-examples.sh --only fake-payments
    fi
}

pid=""
payments_cleanup() {
    if [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() { echo "FAIL: $*" >&2; tail -20 "$dir/serve.log" >&2 || true; exit 1; }
api() {
    printf '%s' "${3:-}" | curl -s --unix-socket "$sock" -X "$1" \
        -H 'content-type: application/json' ${3:+--data-binary @-} "http://kronik$2" ||
        fail "API $1 $2"
}
field() { python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(eval(sys.argv[2]))' "$1" "$2"; }
b64() { python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1],"rb").read()).decode())' "$1"; }
http() {
    curl -s -o "$dir/out" -w '%{http_code}' -X "$1" -H 'content-type: application/json' \
        ${3:+--data-binary "$3"} "$gw$2" >"$dir/code" || fail "$1 $2"
    printf '%s %s' "$(cat "$dir/code")" "$(cat "$dir/out")"
}
invoice() {
    local c="$1"
    [ "$(http PUT "/$billing_kind/$c" "{\"name\":\"$c\",\"country\":\"$2\",\"vat_id\":null}" | cut -d' ' -f1)" -lt 300 ] ||
        fail "customer $c"
    r=$(api POST "/v1/actors/$billing_kind/$c/messages" \
        "{\"name\":\"configure\",\"content_type\":\"application/json\",\"text\":\"{\\\"api_key_secret\\\":\\\"$secret\\\"}\",\"reason\":\"demo\"}")
    [ "$(field "$r" 'v["outcome"]["kind"]')" = committed ] || fail "configure $c: $r"
    [ "$(http POST "/$billing_kind/$c/invoices/$3" \
        '{"currency":"EUR","lines":[{"description":"widgets","quantity":4,"unit_price":2500}]}' | cut -d' ' -f1)" -lt 300 ] ||
        fail "invoice $c/$3"
    http POST "/$billing_kind/$c/invoices/$3/finalize"
}

payments_serve() { # [EXTRA-TOML]: reset the sandbox, serve, wait for health
    trap payments_cleanup EXIT
    if [ -d "$dir" ]; then
        umount "$dir/run/runsc/null-netns" 2>/dev/null || true
        rm -rf "$dir"
    fi
    umask 077
    mkdir -p "$dir"
    sock="$dir/api.sock"
    gw="http://127.0.0.1:$port"
    image="oci-layout:$(realpath "$layout")"
    step "serve"
    printf '[server]\ndata_dir = "%s/data"\n\n[foreign]\nrun_dir = "%s/run"\n%s' "$dir" "$dir" "${1:-}" >"$dir/kronik.toml"
    setsid "$bin" serve --config "$dir/kronik.toml" --http-listen "127.0.0.1:$port" \
        --admin-listen 127.0.0.1:0 --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
    pid=$!
    wait_healthy "$sock" "$dir/serve.log"
}

payments_deploy() { # [EXTRA-CAPABILITY]: manifests, foreign actor, billing and
    # ledger, grants, and the fork point's LSN. EXTRA-CAPABILITY (reorder's
    # http:payments.internal) is granted replay-safe between the foreign and
    # secret grants, before the fork.
    manifest=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$billing")\",\"dry_run\":true,\"reason\":\"dogfood manifest\"}")
    billing_kind=$(field "$manifest" 'v["deployment"]["kind"]')
    manifest=$(api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$ledger")\",\"dry_run\":true,\"reason\":\"dogfood manifest\"}")
    ledger_kind=$(field "$manifest" 'v["deployment"]["kind"]')
    secret="payments-key-standalone"

    step "fake-payments foreign actor"
    api PUT "/v1/secrets/$secret" "{\"text\":\"$api_key\",\"reason\":\"dogfood\"}" >/dev/null
    r=$(api POST /v1/foreign "{\"name\":\"payments.internal\",\"image\":\"$image\",\"port\":8080,\"cpu_millis\":1000,\"memory_bytes\":268435456,\"secrets\":[\"PAYMENTS_API_KEY=$secret\"],\"reason\":\"dogfood\"}")
    [ "$(field "$r" 'v["foreign"]["status"]["state"]')" = running ] || fail "foreign add: $r"

    step "deploy billing and ledger"
    local w
    for w in "$billing" "$ledger"; do
        api POST /v1/deployments "{\"wasm_base64\":\"$(b64 "$w")\",\"reason\":\"dogfood\"}" >/dev/null
    done
    api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"foreign:payments.internal\",\"delivery\":\"idempotency-keyed\",\"reason\":\"dogfood\"}" >/dev/null
    if [ -n "${1:-}" ]; then
        api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"$1\",\"delivery\":\"replay-safe\",\"reason\":\"dogfood\"}" >/dev/null
    fi
    api POST /v1/grants "{\"kind\":\"$billing_kind\",\"capability\":\"secret:$secret\",\"reason\":\"dogfood\"}" >/dev/null
    fork_lsn=$(field "$(api GET /v1/health)" 'v["applied_lsn"]')
}
