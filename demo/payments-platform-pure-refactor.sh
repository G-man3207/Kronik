#!/usr/bin/env bash
# Dogfood scenario 1 (issue #136 / #153): billing-ts with recorded traffic,
# then a refactor-only build that must replay with zero divergent turns and
# propose with policy allow.
#
# Usage: [KRONIK_BIN=path] demo/payments-platform-pure-refactor.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-payments-refactor, port 47841, target/release/kronik.
# Needs root, runsc, curl, python3, examples/dist/billing-ts*.wasm (including
# billing-ts-refactor.wasm), and fake-payments OCI (built if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-payments-refactor}"
port="${2:-47841}"
bin="${KRONIK_BIN:-target/release/kronik}"
billing=examples/dist/billing-ts.wasm
refactor=examples/dist/billing-ts-refactor.wasm
ledger=examples/dist/billing-ts-ledger.wasm
. demo/payments-lib.sh

payments_preflight "$refactor"
payments_serve
payments_deploy

step "fork before traffic"
r=$(api POST /v1/forks "{\"at\":$fork_lsn,\"name\":\"refactor\",\"reason\":\"dogfood scenario 1\"}")
[ "$(field "$r" 'v["fork"]["name"]')" = refactor ] || fail "fork: $r"

step "record billing traffic"
for c in se-1:SE de-1:DE us-1:US; do
    out=$(invoice "${c%%:*}" "${c##*:}" inv-1)
    [ "${out%% *}" = 200 ] || fail "finalize ${c%%:*}: $out"
done
out=$(invoice declined-1 SE inv-1)
[ "${out%% *}" = 500 ] || fail "declined card must fail the turn: $out"

step "deploy refactor build on fork, replay"
api POST /v1/forks/refactor/deployments "{\"wasm_base64\":\"$(b64 "$refactor")\",\"reason\":\"dogfood\"}" >/dev/null
r=$(api POST /v1/forks/refactor/replay '{"reason":"dogfood"}')
[ "$(field "$r" 'v["summary"]["divergent_turns"]')" = 0 ] || fail "refactor replay diverged: $r"
[ "$(field "$r" 'v["summary"]["changed"]')" = False ] || fail "refactor replay changed: $r"

step "propose refactor-only change"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$refactor")\"],\"reason\":\"dogfood: pure refactor\"}")
[ "$(field "$r" 'v["proposal"]["summary"]["divergent_turns"]')" = 0 ] || fail "proposal diverged: $r"
[ "$(field "$r" 'v["proposal"]["policy"]["outcome"]')" = allow ] || fail "refactor must allow: $r"

payments_cleanup
pid=""
echo
printf 'PASS: payments-platform pure refactor in %ss\n' "$(( $(date +%s) - started ))"
