#!/usr/bin/env bash
# Runs COMMAND against a throwaway Jaeger v2 (an ordinary OpenTelemetry
# backend) in docker: a container with a unique name, OTLP/HTTP and the query
# API on free 127.0.0.1 ports, and in-memory storage. The container is
# removed afterwards, whatever COMMAND's result.
#
#   scripts/jaeger.sh demo/vps-otel.sh
#   scripts/minio.sh scripts/jaeger.sh demo/vps-otel.sh   (with the audit half)
#
# Exported to COMMAND:
#   KRONIK_TEST_OTLP_ENDPOINT   http://127.0.0.1:<port>   ([otel] endpoint)
#   KRONIK_TEST_JAEGER_QUERY    http://127.0.0.1:<port>   (UI and /api/traces)
#
# KRONIK_JAEGER_IMAGE picks the image (default: Jaeger 2.22.0, pinned by
# digest).
set -euo pipefail

if [ $# -eq 0 ]; then
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

image=${KRONIK_JAEGER_IMAGE:-jaegertracing/jaeger:2.22.0@sha256:836b967b5abcf1f7758066aa6b348619267a2f1459f72d472840570f9bd88a17}
name="kronik-jaeger-$$-$RANDOM"
free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
otlp_port=$(free_port)
query_port=$(free_port)

docker run -d --rm --name "$name" \
    -p "127.0.0.1:$otlp_port:4318" -p "127.0.0.1:$query_port:16686" \
    "$image" >/dev/null
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 143' TERM INT

otlp="http://127.0.0.1:$otlp_port"
query="http://127.0.0.1:$query_port"
for _ in $(seq 1 150); do
    curl -fsS "$query/api/v3/services" >/dev/null 2>&1 &&
        curl -sS -o /dev/null "$otlp/v1/traces" 2>/dev/null && break
    sleep 0.2
done
curl -fsS "$query/api/v3/services" >/dev/null

export KRONIK_TEST_OTLP_ENDPOINT="$otlp"
export KRONIK_TEST_JAEGER_QUERY="$query"
echo "jaeger: $name, OTLP $otlp, query $query" >&2
"$@"
