The master key that `kronik serve` loaded is not the key the data directory's secret store or privacy keystore was encrypted under. Each store records a value derived from its key at its first start, and older stores are checked by decrypting one of their values. Kronik stops instead of serving secrets it cannot read.

Typical causes:

- The key of another node or installation: a copied configuration, or `KRONIK_MASTER_KEY` set for a different data directory.
- `kronik serve --init` made a new key file over a lost one.
- A store that holds values under two keys, left by older versions that
  made a new key when the old one was missing: the first value decides.
- A damaged store: a value that does not decrypt for another reason is
  reported here too. If the key is certainly right, treat it as
  `STORAGE_CORRUPT` and keep the directory.

To fix it, start with the key this data directory was created with. `kronik restore` checks the privacy keystore backup against the key before it writes anything, and fails with this code when they don't match.

See also: `MASTER_KEY_MISSING`.
