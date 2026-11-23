#!/usr/bin/env bash
# Dogfood scenario 3 (issue #136): billing-ts with recorded traffic, then a
# build that inserts GET payments/healthz after charge (tail insertion, ADR
# 0147). The diff shows three added payment effects without shifting earlier
# ordinal pairs; propose needs approval for the new live GETs.
#
# Usage: [KRONIK_BIN=path] demo/payments-platform-reorder.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-payments-reorder, port 47843, target/release/kronik.
# Needs root, runsc, curl, python3, examples/dist/billing-ts*.wasm (including
# billing-ts-reorder.wasm), and fake-payments OCI (built if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

started=$(date +%s)
dir="${1:-/var/tmp/kronik-payments-reorder}"
port="${2:-47843}"
bin="${KRONIK_BIN:-target/release/kronik}"
billing=examples/dist/billing-ts.wasm
reorder=examples/dist/billing-ts-reorder.wasm
ledger=examples/dist/billing-ts-ledger.wasm
. demo/payments-lib.sh

payments_preflight "$reorder"
payments_serve '

[fork]
live_allowlist = ["payments.internal"]
'
payments_deploy http:payments.internal

step "fork before traffic"
r=$(api POST /v1/forks "{\"at\":$fork_lsn,\"name\":\"reorder\",\"reason\":\"dogfood scenario 3\"}")
[ "$(field "$r" 'v["fork"]["name"]')" = reorder ] || fail "fork: $r"

step "record billing traffic"
for c in se-1:SE de-1:DE us-1:US; do
    out=$(invoice "${c%%:*}" "${c##*:}" inv-1)
    [ "${out%% *}" = 200 ] || fail "finalize ${c%%:*}: $out"
done
out=$(invoice declined-1 SE inv-1)
[ "${out%% *}" = 500 ] || fail "declined card must fail the turn: $out"

step "deploy reorder on fork, replay"
api POST /v1/forks/reorder/deployments "{\"wasm_base64\":\"$(b64 "$reorder")\",\"reason\":\"dogfood\"}" >/dev/null
r=$(api POST /v1/forks/reorder/replay '{"reason":"dogfood"}')
divergent=$(field "$r" 'v["summary"]["divergent_turns"]')
live=$(field "$r" 'v["summary"]["live"]')
# Three paid finalizes each gain one live GET (billing + ledger diverge).
[ "$divergent" = 6 ] || fail "expected 6 divergent turns (3 billing + 3 ledger): $r"
[ "$live" = 3 ] || fail "expected 3 live payment health checks: $r"
[ "$(field "$r" 'v["summary"]["changed"]')" = True ] || fail "replay must report a change: $r"

step "diff shows tail insertions"
d=$(api GET "/v1/forks/reorder/diff")
added=$(field "$d" 'v["effects"]["added"]')
changed=$(field "$d" 'v["effects"]["changed"]')
[ "$added" = 3 ] || fail "expected 3 added payment effects: $d"
[ "$changed" = 0 ] || fail "earlier ordinal pairs must not cascade: $d"

step "propose inserted health check"
r=$(api POST /v1/proposals "{\"wasm_base64\":[\"$(b64 "$reorder")\"],\"reason\":\"dogfood: ping after charge\"}")
[ "$(field "$r" 'v["proposal"]["summary"]["live"]')" = 3 ] || fail "proposal live count: $r"
outcome=$(field "$r" 'v["proposal"]["policy"]["outcome"]')
[ "$outcome" = deny ] || [ "$outcome" = require_approval ] ||
    fail "live payment GETs must not allow promotion: $r"
echo "$r" | python3 -c 'import json,sys; fired=[r["name"] for r in json.load(sys.stdin)["proposal"]["policy"]["fired"]]; sys.exit(0 if "low-grounding-needs-approval" in fired else 1)' ||
    fail "low-grounding-needs-approval must fire: $r"

payments_cleanup
pid=""
echo
printf 'PASS: payments-platform reorder in %ss\n' "$(( $(date +%s) - started ))"
