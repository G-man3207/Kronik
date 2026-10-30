Kronik could not load the existing master key. For `source = "file"` (the default), the configured key file does not exist and `KRONIK_MASTER_KEY` is not set. For `source = "env"`, that environment variable is missing. For a KMS source, the configured wrapped-key file is missing while encrypted stores already exist. Kronik never creates a replacement seed over existing encrypted data: that would make secrets and sealed values unreadable and change keyed hashes. A new, empty data directory can create its first key.

Typical causes:

- A restored data directory: a file/env seed is never in the bucket and must be supplied separately. KMS restores need the shipped wrapped ciphertext and access to the configured provider key.
- The configuration names another key file than before, or `KRONIK_MASTER_KEY` is not set in this environment (a unit file, a container) although the node was started with it.
- The key file was deleted.
- A KMS envelope was removed or `wrapped_file` points at a different path.

Restore the original file/env material, or restore the original KMS envelope with its matching provider configuration and credentials. Never generate another seed to bypass this error. If the seed or provider key is permanently lost, keep the existing data for investigation; those encrypted values cannot be recovered by changing configuration.

For KMS custody, restore the matching `[keys] wrapped_file` (default `<data_dir>/keys/master.wrapped`) together with the matching `[keys] source` and provider key reference. `KRONIK_MASTER_KEY` and a raw `master_key_file` are not fallbacks: they conflict with a KMS source and must not be substituted for its envelope.

See also: `MASTER_KEY_MISMATCH`, `KEY_SOURCE_UNAVAILABLE`, `KEY_PROTECTION_UNAVAILABLE`.
