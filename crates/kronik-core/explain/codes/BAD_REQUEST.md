The request could not be understood: invalid JSON, a missing or mistyped field, an invalid actor key or path segment, or a manifest from `describe` that breaks the naming rules. Kronik uses this generic code for malformed input that no more specific code covers, so that a client can tell a request it must fix from a failure on the server.

The message names the field or value that is wrong. Fix it and send the request again; the same request always gives the same error.
