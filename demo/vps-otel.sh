#!/usr/bin/env bash
# M28's acceptance against a real backend (docs/design/m28-otel.md §8): a call
# through three actors is one connected trace in Jaeger, also when the caller
# sends a W3C traceparent. Then, when an S3 bucket is given, the audit export
# to it is complete compared with the log (`kronik audit verify`).
#
# Usage: scripts/jaeger.sh demo/vps-otel.sh
#        scripts/minio.sh scripts/jaeger.sh demo/vps-otel.sh   (with the audit half)
#        [KRONIK_BIN=path] demo/vps-otel.sh [WORKDIR]
# Needs KRONIK_TEST_OTLP_ENDPOINT and KRONIK_TEST_JAEGER_QUERY (scripts/jaeger.sh
# exports them); the audit half also needs KRONIK_TEST_S3_URL,
# KRONIK_TEST_S3_ENDPOINT and the AWS_* variables (scripts/minio.sh). The
# counter is tests/guests/counter.wasm. Needs curl and python3.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -z "${KRONIK_TEST_OTLP_ENDPOINT:-}" ] || [ -z "${KRONIK_TEST_JAEGER_QUERY:-}" ]; then
    echo "KRONIK_TEST_OTLP_ENDPOINT and KRONIK_TEST_JAEGER_QUERY are unset." >&2
    echo "Run: scripts/jaeger.sh demo/vps-otel.sh" >&2
    exit 2
fi

started=$(date +%s)
dir="${1:-/var/tmp/kronik-vps-otel-$$}"
guest=tests/guests/counter.wasm
if [ -n "${KRONIK_BIN:-}" ]; then
    bin="$KRONIK_BIN"
elif [ -x target/release/kronik ]; then
    bin=target/release/kronik
elif [ -x target/debug/kronik ]; then
    bin=target/debug/kronik
else
    echo "missing kronik binary; set KRONIK_BIN or cargo build -p kronik" >&2
    exit 2
fi
for f in "$bin" "$guest"; do
    [ -e "$f" ] || { echo "missing $f" >&2; exit 2; }
done

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
gw="http://127.0.0.1:$port"
sock="$dir/api.sock"
cfg="$dir/kronik.toml"
log="$dir/serve.log"
pid=""
traceparent="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

rm -rf "$dir"
mkdir -p "$dir"
trap '[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; true' EXIT

step() { printf '\n== %s (%ss)\n' "$1" "$(( $(date +%s) - started ))"; }
fail() {
    echo "FAIL: $*" >&2
    echo "--- serve log ---" >&2
    tail -40 "$log" >&2 || true
    exit 1
}

write_config() { # EXTRA
    cat >"$cfg" <<EOF
[server]
data_dir = "$dir/data"
api_socket = "$sock"
http_listen = "127.0.0.1:$port"

[otel]
endpoint = "$KRONIK_TEST_OTLP_ENDPOINT"
# Test data only: real deployments keep the default, hashed.
actor_keys = "plain"
interval = "200ms"
# Jaeger takes traces only.
metrics = false
$1
EOF
}

start_serve() {
    setsid "$bin" serve --config "$cfg" >>"$log" 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        curl -sf --unix-socket "$sock" http://kronik/v1/health >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "daemon not healthy"
}

stop_serve() {
    if [ -n "$pid" ]; then
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        pid=""
    fi
}

# three_actors [HEADER]: POST /counter/a/call with body `counter/b call`:
# counter/a calls counter/b, which calls counter/x. Prints the root turn id.
three_actors() {
    local headers body
    headers=$(mktemp -p "$dir")
    body=$(curl -sf -D "$headers" -X POST -H 'content-type: text/plain' ${1:+-H "$1"} \
        --data-binary 'counter/b call' "$gw/counter/a/call") || fail "three-actor call"
    case $body in *"reply reply "*) ;; *) fail "unexpected reply: $body" ;; esac
    tr -d '\r' <"$headers" | awk -F': ' 'tolower($1) == "kronik-turn-id" { print $2 }'
}

causal_root() { # TURN
    curl -sf --unix-socket "$sock" "http://kronik/v1/turns/$1" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["causal_key"]["root"])'
}

# wait_exported STREAM: until the stream's cursor reaches the applied LSN.
wait_exported() {
    local s
    for _ in $(seq 1 300); do
        s=$("$bin" --socket "$sock" --json export status) || fail "export status"
        python3 - "$s" "$1" <<'PY' && return 0
import json, sys
s = next(x for x in json.loads(sys.argv[1])["streams"] if x["name"] == sys.argv[2])
sys.exit(0 if s["enabled"] and s["cursor"] == s["applied_lsn"] else 1)
PY
        sleep 0.1
    done
    fail "the $1 stream did not catch up: $s"
}

# jaeger_trace ID OUT: polls Jaeger's query API until it has the trace's five
# spans (ingestion is asynchronous), 30 s. OUT.json is the UI's view
# (/api/traces: CHILD_OF and FOLLOWS_FROM references, warnings), OUT.otlp.json
# the OTLP view (/api/v3/traces: parents and links with their attributes).
jaeger_trace() {
    for _ in $(seq 1 150); do
        if curl -sf "$KRONIK_TEST_JAEGER_QUERY/api/traces/$1" -o "$2.json" &&
            python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["data"]; sys.exit(0 if d and len(d[0]["spans"]) >= 5 else 1)' "$2.json"; then
            curl -sf "$KRONIK_TEST_JAEGER_QUERY/api/v3/traces/$1" -o "$2.otlp.json" ||
                fail "Jaeger's /api/v3/traces/$1"
            return 0
        fi
        sleep 0.2
    done
    fail "Jaeger has no complete trace $1 after 30s: $(cat "$2.json" 2>/dev/null)"
}

step "serve with [otel] endpoint = $KRONIK_TEST_OTLP_ENDPOINT"
write_config ""
start_serve

step "deploy the counter and call through three actors"
"$bin" --socket "$sock" deploy "$guest" --reason "vps-otel" >/dev/null
plain=$(three_actors "")
traced=$(three_actors "traceparent: $traceparent")
{ [ -n "$plain" ] && [ -n "$traced" ]; } || fail "no kronik-turn-id header"
root_plain=$(causal_root "$plain") || fail "turn $plain"
root_traced=$(causal_root "$traced") || fail "turn $traced"
echo "turn $plain: trace $root_plain"
echo "turn $traced (traceparent): trace $root_traced"

step "wait for the trace export"
wait_exported traces

step "read both traces back from Jaeger"
jaeger_trace "$root_plain" "$dir/plain"
jaeger_trace "$root_traced" "$dir/traced"

python3 - "$dir/plain" "$root_plain" "$plain" "" \
    "$dir/traced" "$root_traced" "$traced" "$traceparent" <<'PY' || fail "Jaeger's traces are not one connected trace each"
import json, sys

def tags(s):
    return {t["key"]: t["value"] for t in s.get("tags", [])}

def check(path, root_id, turn, traceparent):
    # The UI's view: what Jaeger draws, and its warnings.
    data = json.load(open(path + ".json"))
    assert not data.get("errors"), data["errors"]
    assert len(data["data"]) == 1, f"{len(data['data'])} traces"
    trace = data["data"][0]
    assert trace["traceID"] == root_id, (trace["traceID"], root_id)
    spans = trace["spans"]
    warnings = [w for s in spans for w in (s.get("warnings") or [])] + (trace.get("warnings") or [])
    assert not warnings, warnings
    assert len(spans) == 5, [s["operationName"] for s in spans]
    by_id = {s["spanID"]: s for s in spans}
    turns = sorted(f'{tags(s)["kronik.actor.kind"]}/{tags(s)["kronik.actor.key"]}'
                   for s in spans if "kronik.turn_id" in tags(s))
    assert turns == ["counter/a", "counter/b", "counter/x"], turns
    assert sum(s["operationName"] == "actor.call" for s in spans) == 2, [s["operationName"] for s in spans]

    def refs(s, kind):
        return [(r["traceID"], r["spanID"]) for r in s.get("references") or [] if r["refType"] == kind]

    # One root; every other span is CHILD_OF a span of this trace.
    roots = [s for s in spans if not refs(s, "CHILD_OF")]
    assert len(roots) == 1, [s["operationName"] for s in roots]
    root = roots[0]
    assert tags(root)["kronik.turn_id"] == turn, tags(root)
    for s in spans:
        if s is not root:
            ((t, p),) = refs(s, "CHILD_OF")
            assert t == root_id and p in by_id, (s["operationName"], s["references"])
    # Each callee is a child of its caller's actor.call span.
    callees = [s for s in spans if tags(s).get("kronik.message.source") == "call"]
    assert len(callees) == 2, len(callees)
    for c in callees:
        ((_, p),) = refs(c, "CHILD_OF")
        assert by_id[p]["operationName"] == "actor.call", c["references"]
    # An incoming traceparent is a link on the root, never the trace id.
    if traceparent:
        _, tid, sid, _ = traceparent.split("-")
        assert root_id != tid
        assert refs(root, "FOLLOWS_FROM") == [(tid, sid)], root["references"]
    else:
        assert not root.get("references"), root["references"]

    # The OTLP view: the links and their kronik.link names.
    otlp = json.load(open(path + ".otlp.json"))["result"]["resourceSpans"]
    ospans = {s["spanId"]: s for rs in otlp for ss in rs["scopeSpans"] for s in ss["spans"]}
    assert set(ospans) == set(by_id), (sorted(ospans), sorted(by_id))

    def links(s):
        return [(l["traceId"], l["spanId"], {a["key"]: a["value"]["stringValue"] for a in l.get("attributes", [])})
                for l in s.get("links") or []]

    for c in callees:
        s = ospans[c["spanID"]]
        assert links(s) == [(root_id, s["parentSpanId"],
                             {"kronik.link": "call", "opentracing.ref_type": "child_of"})], links(s)
    want = [(tid, sid, {"kronik.link": "traceparent"})] if traceparent else []
    assert links(ospans[root["spanID"]]) == want, links(ospans[root["spanID"]])
    print(f"trace {root_id}: 5 spans, counter/a -> counter/b -> counter/x, 2 actor.call, "
          "one root, every parent present, call links"
          + (", root linked to the incoming traceparent" if traceparent else ""))

a, b = sys.argv[1:5], sys.argv[5:9]
check(*a)
check(*b)
assert a[1] != b[1]
PY
echo "PASS: traces"

step "audit export to S3"
audit=skip
if [ -z "${KRONIK_TEST_S3_URL:-}" ] || [ -z "${KRONIK_TEST_S3_ENDPOINT:-}" ]; then
    echo "SKIP: audit: no bucket (KRONIK_TEST_S3_URL unset; run under scripts/minio.sh or with_garage)"
elif ! "$bin" audit verify --help >/dev/null 2>&1; then
    echo "SKIP: audit: this kronik has no 'kronik audit verify'"
else
    audit=run
fi
if [ "$audit" = run ]; then
    stop_serve
    write_config "$(printf '[audit]\nsink = "%s"\nendpoint = "%s"\ninterval = "200ms"' \
        "$KRONIK_TEST_S3_URL" "$KRONIK_TEST_S3_ENDPOINT")"
    start_serve
    # A mutation after the restart, so the bucket holds more than the backlog.
    "$bin" --socket "$sock" snapshot create --reason "vps-otel audit" >/dev/null
    three_actors "" >/dev/null
    wait_exported audit
    stop_serve
    KRONIK_CONFIG="$cfg" "$bin" audit verify --sink "$KRONIK_TEST_S3_URL" ||
        fail "the audit export in $KRONIK_TEST_S3_URL is not complete"
    echo "PASS: audit"
fi

stop_serve
printf '\nPASS: vps-otel%s in %ss\n' "$([ "$audit" = run ] || echo ' (audit skipped)')" \
    "$(( $(date +%s) - started ))"
