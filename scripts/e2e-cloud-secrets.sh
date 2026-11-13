#!/usr/bin/env bash
# M23 B5: the external-secret criteria (docs/design/m23-secret-backends.md
# section 9, criteria 2 and 3) against the real AWS Secrets Manager, GCP
# Secret Manager and Azure Key Vault, with the operator's own credentials.
# The same checks as scripts/e2e-secrets.sh, except the outages: a real
# service cannot be stopped by a test, so those run against the emulators.
#
# Not part of CI and never run by the project's automation: it costs money
# (each run makes and deletes one secret per cloud, plus API calls) and it
# needs accounts. Running it before a release is the maintainers' call.
#
# Usage: KRONIK_BIN=target/debug/kronik scripts/e2e-cloud-secrets.sh [--only aws,gcp,azure] [--dir DIR]
#
# Needs Python 3.11+, openssl, and per cloud:
#   aws    the `aws` CLI logged in with rights to create, write, read and
#          delete secrets under `kronik-e2e/`; KRONIK_E2E_AWS_REGION; the
#          daemon reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and
#          AWS_SESSION_TOKEN (`auth = "env"`).
#   gcp    `gcloud` logged in with rights on Secret Manager;
#          KRONIK_E2E_GCP_PROJECT_NUMBER (the number: Secret Manager answers
#          with it, whatever the request named); KRONIK_E2E_GCP_SERVICE_ACCOUNT_FILE,
#          a service-account key that may access the project's secrets.
#   azure  `az` logged in with secret set/delete rights on the vault;
#          KRONIK_E2E_AZURE_VAULT (https://<name>.vault.azure.net),
#          KRONIK_E2E_AZURE_TENANT_ID, KRONIK_E2E_AZURE_CLIENT_ID and
#          KRONIK_E2E_AZURE_CLIENT_SECRET_FILE for the daemon's app.
# The run uses loopback ports 47150-47171 for its fixtures and gateway.
# Writes its evidence to results.json in the run directory, which it prints.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 -B scripts/e2e-secrets.py --cloud \
    --bin "${KRONIK_BIN:-${CARGO_TARGET_DIR:-target}/debug/kronik}" "$@"
