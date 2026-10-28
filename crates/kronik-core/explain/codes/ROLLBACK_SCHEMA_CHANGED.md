`kronik rollback <deployment>` switches back to the previous hash, but the actor type's schema version has changed since then: the newer code has migrated the state with `migrate`. In v0.1 such a rollback is rejected. Rollback via replay, which handles schema changes, comes after v0.1 (M13).

To fix it, fix forward: propose a corrected version that keeps or raises the current schema version, and promote it after review:

    kronik propose ./dist/billing.wasm --window 1h --reason "fix the invoice total"

See also: `deployment`, `proposal`.
