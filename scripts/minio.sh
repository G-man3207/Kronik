#!/usr/bin/env bash
# Deprecated: MinIO's images and binaries are no longer distributed, so this
# runs COMMAND under scripts/s3.sh (moto's S3 server in docker) instead, with
# the same environment. Use scripts/s3.sh.
set -euo pipefail
echo "scripts/minio.sh is deprecated: running scripts/s3.sh instead" >&2
exec "$(dirname "${BASH_SOURCE[0]}")/s3.sh" "$@"
