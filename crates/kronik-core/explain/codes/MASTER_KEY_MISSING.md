`kronik serve` found no master key: the key file (`[keys] master_key_file`, `--master-key-file` or `KRONIK_MASTER_KEY_FILE`, else `<data_dir>/keys/master.key`) does not exist and `KRONIK_MASTER_KEY` is not set. The data directory already holds the secret store or the privacy keystore, which are encrypted under the key this directory was created with. A new key would make every secret and every sealed value unreadable, and would change the keyed hashes in the log, so Kronik refuses to make one. A new, empty data directory still gets a key at its first start.

Typical causes:

- A restored data directory: the key is never in the bucket, and must be put in place on the new machine.
- The configuration names another key file than before, or `KRONIK_MASTER_KEY` is not set in this environment (a unit file, a container) although the node was started with it.
- The key file was deleted.

To fix it, put the original key back where the configuration points, or set `KRONIK_MASTER_KEY` to it, and start again. If the key is lost, the stores cannot be decrypted by anyone: move `keys/secrets.db` and `keys/keystore.db` aside to start with a new key and without those secrets and sealed values.

See also: `MASTER_KEY_MISMATCH`.
