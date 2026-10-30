The loaded master key does not match the data directory's encrypted stores, or a KMS envelope does not match its configured source, provider key, version or fixed purpose. Each store records a value derived from its key at first start; older stores are checked by decrypting an existing value. Kronik stops instead of replacing an envelope or serving secrets it cannot read.

Typical causes:

- The key of another node or installation: a copied configuration, or `KRONIK_MASTER_KEY` set for a different data directory.
- An older release generated a replacement seed after the original was lost.
- A store that holds values under two keys, left by older versions that
  made a new key when the old one was missing: the first value decides.
- A damaged store: a value that does not decrypt for another reason is
  reported here too. If the key is certainly right, treat it as
  `STORAGE_CORRUPT` and keep the directory.
- The wrapped ciphertext belongs to another provider/key, its recorded version is invalid for the configured key, or its metadata was changed.

Use the original seed or its matching KMS envelope and provider key. `kronik restore` unwraps and checks staged stores before installing the envelope or committing destination state; a mismatch preserves the existing destination. Do not repair this error by generating another seed or overwriting the wrapper.

For KMS custody, use the matching `[keys] wrapped_file` (default `<data_dir>/keys/master.wrapped`), `[keys] source` and provider key reference. Keep the original wrapping version available. Do not set `KRONIK_MASTER_KEY` or select a raw key file to bypass a mismatch: KMS custody rejects those fallbacks.

See also: `MASTER_KEY_MISSING`, `KEY_SOURCE_UNAVAILABLE`, `KEY_PROTECTION_UNAVAILABLE`.
