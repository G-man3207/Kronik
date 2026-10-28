No secret has this name, or it was deleted. Secrets live in the secret store, encrypted with the master key; they are referred to by name and their values are never shown.

Typical causes: a typo in the name, a secret that was never set, or one that `kronik secret delete` removed.

To fix it, list the secrets that exist, or set the secret; `kronik secret set` reads the value from stdin:

    kronik secret list
    kronik secret set <name> --reason "..."

See also: `secret-handle`.
