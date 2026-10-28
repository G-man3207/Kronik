No API token has this name. Tokens are referred to by the name they were created with, such as `agent-1`; the token itself is shown only once, when it is created, and is never stored.

Typical causes: a typo in the name, or a token that was never created on this daemon. A revoked token keeps its name and is still listed, and names are never reused.

To fix it, list the tokens, or create one:

    kronik token list
    kronik token create --name <name> --scopes read,fork,propose --reason "..."

See also: `UNAUTHENTICATED`, `SCOPE_MISSING`.
