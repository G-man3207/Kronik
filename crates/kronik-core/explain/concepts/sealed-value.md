A sealed value is a value encrypted with its subject's key. It is erased by erasing the key, after which it is unreadable in the log, state, snapshots and shipped copies. Without the `pii:read` scope, `actors inspect`, turns, `history` and MCP responses show sealed values as `[sealed]` and erased ones as `[erased]`, and never a subject id; diffs show a subject's values as redacted, with a keyed hash in place of the subject. A fork created with `--no-pii` sees deterministic pseudonyms instead, `pii:` plus 12 hex characters.

See also: `subject`, `privacy-mode`, `SUBJECT_ERASED`.
