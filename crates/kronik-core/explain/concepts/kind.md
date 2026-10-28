An actor type, called kind in code and in actor ids, is the code for one sort of actor, for example `billing` in `billing/acme`. A deployment points each kind at a code hash. Its `describe` export returns the manifest: kind, schema version, routes and requested capabilities. Grants and limits (from M2) apply per kind, not per hash, so they carry over when the code changes.

A new kind without history is deployed directly; from M3, a kind with history changes through propose and promote:

    kronik deploy ./dist/billing.wasm --reason "first deploy"
    kronik propose ./dist/billing.wasm --window 1h --reason "Apply EU VAT"

See also: `actor`, `hash`, `deployment`.
