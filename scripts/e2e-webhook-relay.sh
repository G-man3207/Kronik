#!/usr/bin/env bash
# End-to-end check of the webhook-relay example with the real binary: a local
# target server records what it receives; secrets and grants are set over the
# API; then a signed delivery with the authorization secret header, a retry
# by timer after a 500, a target whose host is not granted, and a webhook
# that does not exist.
#
# RELAY picks the component (default examples/dist/webhook-relay.wasm); with
# examples/dist/webhook-relay-body-v2.wasm the forwarded body must also have
# its "relay" field. examples/dist/webhook-relay-ts.wasm, the TypeScript twin
# (scripts/build-examples-ts.sh), passes the same checks.
#
# Usage: [KRONIK_BIN=path] [RELAY=path] scripts/e2e-webhook-relay.sh [WORKDIR] [PORT]
# Defaults: /var/tmp/kronik-e2e-relay, port 47821 (the target listens on
# PORT+1), KRONIK_BIN target/release/kronik. Needs curl and python3.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dir="${1:-/var/tmp/kronik-e2e-relay}"
port="${2:-47821}"
target_port=$((port + 1))
bin="${KRONIK_BIN:-target/release/kronik}"
relay="${RELAY:-examples/dist/webhook-relay.wasm}"
sock="$dir/api.sock"
gw="http://127.0.0.1:$port"
target="http://127.0.0.1:$target_port"
signing_key="relay-e2e-signing-key"
pid=""
target_pid=""

rm -rf "$dir"
mkdir -p "$dir"

stop() {
    for p in "$pid" "$target_pid"; do
        if [ -n "$p" ]; then
            kill "$p" 2>/dev/null || true
            wait "$p" 2>/dev/null || true
        fi
    done
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
post_api() { # post_api <path> <json>
    api -X "${3:-POST}" -H 'content-type: application/json' -d "$2" "http://kronik$1"
}
configure() { # configure <json>: the relay's configure message
    post_api /v1/actors/webhook-relay/acme/messages "$(python3 -c 'import json,sys; print(json.dumps({"name": "configure", "text": sys.argv[1], "reason": "e2e"}))' "$1")" |
        json 'd["outcome"]["kind"]'
}

# The target: answers 200 on /ok; on /flaky, 500 for the first request of each
# x-webhook-id and 200 after that. Every request is appended to target.jsonl.
python3 - "$target_port" "$dir/target.jsonl" <<'PY' &
import http.server, json, sys
port, log = int(sys.argv[1]), sys.argv[2]
seen = set()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        hook = self.headers.get("x-webhook-id")
        status = 200
        if self.path == "/flaky" and hook not in seen:
            status = 500
        seen.add(hook)
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "status": status,
                                "headers": {k.lower(): v for k, v in self.headers.items()},
                                "body": body.decode()}) + "\n")
        self.send_response(status)
        self.send_header("content-length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
target_pid=$!

setsid "$bin" serve --data-dir "$dir/data" --http-listen "127.0.0.1:$port" \
    --api-socket "$sock" >>"$dir/serve.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
    curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && break
    sleep 0.1
done

python3 -c "import base64,json,sys; print(json.dumps({'wasm_base64': base64.b64encode(open(sys.argv[1],'rb').read()).decode(), 'reason': 'e2e deploy'}))" "$relay" >"$dir/deploy.json"
expect "deploy" "webhook-relay http:webhooks.example.com,secret:relay-signing-key" "$(api -X POST -d @"$dir/deploy.json" http://kronik/v1/deployments | json 'd["deployment"]["kind"] + " " + ",".join(d["deployment"]["capabilities"])')"
expect "set signing key" "relay-signing-key" "$(post_api /v1/secrets/relay-signing-key "{\"text\":\"$signing_key\",\"reason\":\"e2e\"}" PUT | json 'd["secret"]["name"]')"
expect "set auth secret" "relay-auth" "$(post_api /v1/secrets/relay-auth '{"text":"tok-123","reason":"e2e"}' PUT | json 'd["secret"]["name"]')"
for cap in secret:relay-signing-key secret:relay-auth; do
    expect "grant $cap" "$cap" "$(post_api /v1/grants "{\"kind\":\"webhook-relay\",\"capability\":\"$cap\",\"reason\":\"e2e\"}" | json 'd["grant"]["capability"]')"
done
expect "grant http:127.0.0.1" "idempotency-keyed" "$(post_api /v1/grants '{"kind":"webhook-relay","capability":"http:127.0.0.1","delivery":"idempotency-keyed","reason":"e2e"}' | json 'd["grant"]["delivery"]')"

expect "configure" "committed" "$(configure "{\"target\":\"$target/ok\",\"auth_secret\":\"relay-auth\"}")"
curl -s -o "$dir/first.json" -w '%{http_code}' -X POST -d '{"event":"paid","amount":42}' "$gw/hooks/acme" >"$dir/first.status"
expect "delivered" "200 delivered 1" "$(cat "$dir/first.status") $(json 'd["status"] + " " + str(d["attempts"])' <"$dir/first.json")"
id=$(json 'd["id"]' <"$dir/first.json")
# What the target got: the forwarded body, signed with the signing key, with
# the secret inserted by the host and an Idempotency-Key.
expect "forwarded request" "ok" "$(python3 - "$dir/target.jsonl" "$id" "$signing_key" "$relay" <<'PY'
import hashlib, hmac, json, sys
log, hook, key, relay = sys.argv[1:]
req = json.loads(open(log).readline())
h, body = req["headers"], req["body"].encode()
want = {"webhook": hook, "source": "acme", "payload": {"event": "paid", "amount": 42}}
if "body-v2" in relay:
    want["relay"] = "kronik-webhook-relay/2"
checks = {
    "path": req["path"] == "/ok",
    "body": json.loads(body) == want,
    "x-webhook-id": h.get("x-webhook-id") == hook,
    "x-signature": h.get("x-signature") == "sha256=" + hmac.new(key.encode(), body, hashlib.sha256).hexdigest(),
    "authorization": h.get("authorization") == "Bearer tok-123",
    "idempotency-key": len(h.get("idempotency-key", "")) == 64,
    "content-type": h.get("content-type") == "application/json",
}
bad = [k for k, ok in checks.items() if not ok]
print("ok" if not bad else f"bad {bad}: {req}")
PY
)"

expect "configure flaky" "committed" "$(configure "{\"target\":\"$target/flaky\"}")"
curl -s -o "$dir/flaky.json" -w '%{http_code}' -X POST -d 'plain text' "$gw/hooks/acme" >"$dir/flaky.status"
expect "first attempt" "502 retrying 1" "$(cat "$dir/flaky.status") $(json 'd["status"] + " " + str(d["attempts"])' <"$dir/flaky.json")"
flaky=$(json 'd["id"]' <"$dir/flaky.json")
for _ in $(seq 1 50); do
    status=$(curl -s "$gw/hooks/acme/$flaky" | json 'd["status"] + " " + str(d["attempts"])')
    [ "$status" = "retrying 1" ] || break
    sleep 0.2
done
expect "retried by timer" "delivered 2" "$status"
expect "same request twice" "2 1" "$(python3 - "$dir/target.jsonl" "$flaky" <<'PY'
import json, sys
reqs = [json.loads(l) for l in open(sys.argv[1]) if json.loads(l)["headers"].get("x-webhook-id") == sys.argv[2]]
print(len(reqs), len({(r["body"], r["headers"]["x-signature"]) for r in reqs}))
PY
)"

expect "configure ungranted host" "committed" "$(configure "{\"target\":\"http://localhost:$target_port/ok\"}")"
curl -s -o "$dir/denied.json" -w '%{http_code}' -X POST -d '{}' "$gw/hooks/acme" >"$dir/denied.status"
expect "denied" "502 failed True" "$(cat "$dir/denied.status") $(json 'd["status"] + " " + str("CAPABILITY_NOT_GRANTED" in d["error"])' <"$dir/denied.json")"
expect "unknown webhook" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$gw/hooks/acme/nope")"
echo "PASS: webhook-relay e2e with $relay (log: $dir/serve.log)"
