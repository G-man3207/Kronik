# Restore

Goal: recover a separately backed-up installation without overwriting live
state, substituting keys, or claiming the unshipped tail was recovered.

## Preconditions

Use a fresh owned recovery directory and the correct recorded engine or an
explicitly checked candidate engine. Have the original file/environment master
key, or the matching KMS configuration and provider authority, available from
the separate recovery channel. Never generate a replacement seed over an
existing encrypted store.

## Procedure

1. Keep the source and failed installation intact for investigation. Select the
   actual bucket/prefix and shipped recovery point, not a guessed LSN.
2. Review a dry run, then restore into the empty recovery directory:

   ```sh
   kronik restore --from s3://example-backups/installation \
     --config /owned/recovery/kronik.toml --data-dir /owned/recovery/data --dry-run
   kronik restore --from s3://example-backups/installation \
     --config /owned/recovery/kronik.toml --data-dir /owned/recovery/data
   ```

   The paths and bucket are examples to replace. Supply file/env key material
   through its documented separate key source, never argv or this runbook.
   KMS restore installs and validates the shipped ciphertext envelope before
   publishing encrypted stores. Do not use `--force` against live data.
3. Refuse `MASTER_KEY_MISSING`, `MASTER_KEY_MISMATCH`, `KEY_SOURCE_UNAVAILABLE`
   or `KEYSTORE_INCOMPLETE` until the actual source/key problem is resolved.
   `--allow-missing-keys` and `--without-keystore` explicitly accept unreadable
   or discarded subject keys; they are data-loss decisions, not routine fixes.
4. If the candidate engine differs, follow the [upgrade runbook](upgrade.md)
   before starting it. Start only this owned recovered instance using its own
   config, gateway port and API socket:

   ```sh
   kronik serve --config /owned/recovery/kronik.toml
   ```

5. Compare `kronik --json integrity --through <source-LSN>` against the recorded
   source state/log hashes. Check `keys_missing` is empty and read known
   fixture key-value and SQL values. Confirm the next audit records include
   the real restore marker; new mutations may legitimately increase the head.
   Forks/proposals/diffs not shipped by the format are not magically restored.
6. Perform an identity replay of the recovered fixture's recorded roots in
   isolated and continuous modes. Require complete roots, no behavioral
   changes and no synthetic/approximate effects before declaring recovery.
   Reopen external traffic only after the actual checks pass.

## Drill record

Record binary/engine and fixture hashes, the exact restore command, source and
restored LSNs, state/log comparisons, key inventory, replay counts and observed
errors. In a disposable fixture, separately check missing/wrong keys are
refused; never experiment with production keys. A same-host file target proves
format flow only, not off-host backup availability or an unobserved recovery
point/time objective.
