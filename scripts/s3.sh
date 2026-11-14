#!/usr/bin/env bash
# Runs COMMAND against a throwaway S3-compatible server in docker: moto's S3
# server, pinned by the digest scripts/e2e-secrets.py and scripts/e2e-keys.py
# pin for AWS, in a container with a unique name on a free 127.0.0.1 port,
# with a bucket and the environment shipping, restore and the S3 audit sink
# read. The container is removed afterwards, whatever COMMAND's result.
#
#   scripts/s3.sh cargo test -p kronik-ship --test ship
#   scripts/s3.sh demo/vps-restore.sh
#   scripts/s3.sh scripts/jaeger.sh demo/vps-otel.sh
#
# Exported to COMMAND:
#   KRONIK_TEST_S3_URL       s3://<bucket>/<prefix>
#   KRONIK_TEST_S3_ENDPOINT  http://127.0.0.1:<port>
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
#
# KRONIK_S3_IMAGE picks another image of moto's server. moto answers the
# operations Kronik uses: PUT (also multipart, and the conditional create of
# If-None-Match: *), GET with ranges, HEAD, DELETE and listing by prefix and
# delimiter. (MinIO's images and binaries, which this replaced, are no longer
# distributed.)
set -euo pipefail

if [ $# -eq 0 ]; then
    sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

image=${KRONIK_S3_IMAGE:-motoserver/moto@sha256:59a1965d845249b04def37a0e2565f9cc6c44543cb89b68e90f28f344b3b0d1a}
name="kronik-s3-$$-$RANDOM"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
user=kronik
secret="kronik-$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')"
bucket=kronik-test

docker run -d --rm --name "$name" -p "127.0.0.1:$port:5000" "$image" >/dev/null
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

endpoint="http://127.0.0.1:$port"
for _ in $(seq 1 100); do
    curl -fsS "$endpoint/" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -fsS "$endpoint/" >/dev/null
# Create the bucket with a SigV4-signed PUT (moto accepts any credentials).
curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user "$user:$secret" \
    -X PUT "$endpoint/$bucket" >/dev/null

export KRONIK_TEST_S3_URL="s3://$bucket/run-$$"
export KRONIK_TEST_S3_ENDPOINT="$endpoint"
export AWS_ACCESS_KEY_ID="$user"
export AWS_SECRET_ACCESS_KEY="$secret"
export AWS_REGION=us-east-1
echo "s3: $name ($image) at $endpoint, $KRONIK_TEST_S3_URL" >&2
"$@"
