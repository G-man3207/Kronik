Every mutation requires a reason (I12). Deploys, grants, messages, resends and every other change are recorded with the token id and the reason, so the log shows who did what and why. The reason was missing or empty.

To fix it, repeat the command with `--reason` and a short explanation, or set a non-empty `reason` in the API request body:

    kronik deploy ./dist/billing.wasm --reason "first deploy"
