A deployment is a log record saying that one or more actor types use certain hashes from a certain LSN, and it carries a configuration epoch, which names it. `kronik deploy` writes one for a new actor type without history. From M3, a kind with history goes the golden path of propose, review the diff and promote, and `kronik rollback` writes a new deployment that restores the code in force before a given one. Deployments are log records, so code changes are part of the history.

    kronik deployments list
    kronik rollback <epoch> --reason "..."

See also: `hash`, `configuration-epoch`, `proposal`.
