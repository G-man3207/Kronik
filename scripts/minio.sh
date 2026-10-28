#!/usr/bin/env bash
# Runs COMMAND against a throwaway MinIO (S3-compatible) server in docker:
# a container with a unique name on a free 127.0.0.1 port, a bucket, and
# the environment shipping and restore read. The container is removed
# afterwards, whatever COMMAND's result.
#
#   scripts/minio.sh cargo test -p kronik-ship --test ship
#   scripts/minio.sh demo/vps-restore.sh
#
# Exported to COMMAND:
#   KRONIK_TEST_S3_URL       s3://<bucket>/<prefix>
#   KRONIK_TEST_S3_ENDPOINT  http://127.0.0.1:<port>
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
#
# KRONIK_MINIO_IMAGE picks the image (default: minio/minio, or a local
# MinIO image when one is present).
set -euo pipefail

if [ $# -eq 0 ]; then
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

image=${KRONIK_MINIO_IMAGE:-}
if [ -z "$image" ]; then
    image=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -m1 -E '(^|/)minio:' || true)
    image=${image:-minio/minio:latest}
fi
name="kronik-minio-$$-$RANDOM"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
user=kronik
secret="kronik-$(od -An -N8 -tx8 /dev/urandom | tr -d ' ')"
bucket=kronik-test

docker run -d --rm --name "$name" -p "127.0.0.1:$port:9000" \
    -e MINIO_ROOT_USER="$user" -e MINIO_ROOT_PASSWORD="$secret" \
    "$image" server /data >/dev/null
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

endpoint="http://127.0.0.1:$port"
for _ in $(seq 1 100); do
    curl -fsS "$endpoint/minio/health/ready" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -fsS "$endpoint/minio/health/ready" >/dev/null
# Create the bucket with a SigV4-signed PUT (no mc needed).
curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user "$user:$secret" \
    -X PUT "$endpoint/$bucket" >/dev/null

export KRONIK_TEST_S3_URL="s3://$bucket/run-$$"
export KRONIK_TEST_S3_ENDPOINT="$endpoint"
export AWS_ACCESS_KEY_ID="$user"
export AWS_SECRET_ACCESS_KEY="$secret"
export AWS_REGION=us-east-1
echo "minio: $name at $endpoint, $KRONIK_TEST_S3_URL" >&2
"$@"
