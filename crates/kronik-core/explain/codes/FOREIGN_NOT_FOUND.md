No foreign actor with this name is declared at the configuration that applies. For the API this means the name is unknown; inside a turn, an actor that calls `foreign://<name>/...` gets `denied` with this code when no foreign actor of that name is declared at the turn's configuration epoch.

Typical causes: a typo in the name, a foreign actor that was never added, or one that `kronik foreign remove` removed.

To fix it, list the declared foreign actors, or add the missing one:

    kronik foreign list
    kronik foreign add <name> --image <ref>@sha256:<digest> --port <port> --reason "..."

See also: `foreign-actor`, `FOREIGN_UNAVAILABLE`.
