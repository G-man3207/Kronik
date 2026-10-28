A secret handle refers to a secret by its name. The guest names the secret in a header template such as `Bearer {}` or in a `crypto` call, and the host inserts the value at the effect boundary or uses it in host-side cryptography. The value never enters guest memory, and Kronik never writes it to the log, diffs, `history` or MCP responses (I8); the log records the secret's name and version hash. Raw values require the capability `secret-reveal:<name>`, and exact occurrences are then scrubbed from logs and diffs.

`kronik secret set` reads the value from stdin and never shows it again:

    kronik secret set <name>
    kronik secret list

See also: `capability`, `effect`.
