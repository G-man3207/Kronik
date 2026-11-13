The request could not be understood: invalid JSON, a missing or mistyped field, an invalid actor key or path segment, or a manifest from `describe` that breaks the naming rules. Kronik uses this generic code for malformed input that no more specific code covers, so that a client can tell a request it must fix from a failure on the server.

`kronik serve` also stops at start with this code when a `kronik.toml` setting is invalid, for example an empty `[gateway] idempotency_header`, or a `[secrets]` table with a zero `refresh` or a backend it cannot use.

The message names the field or value that is wrong. Fix it and send the request again, or start the daemon again; the same input always gives the same error.
