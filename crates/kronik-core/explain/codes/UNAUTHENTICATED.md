The request has no valid token. The JSON API over TCP requires a bearer token, and this one is missing, malformed or revoked. Over the Unix socket a request without a token is the socket user's, identified by file permissions and the peer's user id; a token sent there must be live too. This code exists, apart from `SCOPE_MISSING`, because there a token is valid but lacks a scope, while here there is no valid token at all.

To fix it, send a live token as `Authorization: Bearer <token>`; the CLI and `kronik mcp` send `$KRONIK_TOKEN`. `kronik token list` shows the existing tokens, and `kronik token create` makes a new one:

    kronik token list
    kronik token create --name agent-1 --scopes read,fork,propose --reason "..."

See also: `SCOPE_MISSING`, `TOKEN_NOT_FOUND`.
