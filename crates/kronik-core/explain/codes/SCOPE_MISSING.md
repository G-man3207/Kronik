The caller's token does not have the scope that the operation needs. The scopes are `read`, `fork`, `propose`, `approve`, `promote`, `operate` (grants, limits, foreign actors, privacy), `pii:read` and `admin`. Agents get `read`, `fork` and `propose` by default, and an operator message to main needs `operate`.

To fix it, use a token that has the scope, or ask someone who has one. Tokens and their scopes are created with `kronik token create --scopes`, and `kronik token list` shows the existing ones.

See also: `UNAUTHENTICATED`.
