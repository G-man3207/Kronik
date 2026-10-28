No preview has this id, or its time to live ran out and the daemon deleted it. A preview id is `v-` followed by 12 hex characters; `kronik preview create` prints it with the preview's URL, and the preview's fork has the same name.

A preview is a fork that takes new requests at its URL: any host under `[gateway] preview_domain` (`https://<id>.<preview_domain>/`), or, without a preview domain, `/__preview/<id>/...` on the gateway. Requests to an unknown or expired preview get this code instead of reaching main, so a stale preview link never runs against production.

    kronik preview list
    kronik preview create <proposal> --reason "..."

See also: `fork`, `proposal`, `FORK_NOT_FOUND`.