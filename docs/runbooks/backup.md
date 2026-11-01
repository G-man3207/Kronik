# Backup

Goal: retain a recoverable, off-host copy of committed history, components and
keys, with a recorded recovery point. A snapshot alone is not a backup.

## Preconditions

- Use the configuration and exact binary of the installation being backed up.
- Keep the original master-key recovery material separately from the data and
  bucket. With KMS custody, retain access to every wrapping-key version needed
  by retained backups; copying the envelope without that authority is not
  sufficient.
- Select an owned test fixture for a drill. Never point a drill at an existing
  deployment or change shared services, accounts, firewall or global clock.

## Procedure

1. Configure `[ship] enabled = true`, with the actual `s3://bucket/prefix` and
   optional S3-compatible endpoint, following the [operations guide](../guides/operations.md#shipping-to-object-storage).
   Protect bucket credentials and verify the retention/lifecycle policy.
2. Record the binary's `kronik --version`, configuration identity and current
   `kronik --json integrity`. Keep the state hash, log hash and applied LSN in
   the incident/drill record; do not dump private actor state into that record.
3. Create a snapshot and wait for shipping to complete:

   ```sh
   kronik snapshot create --reason 'recovery point before maintenance'
   kronik --json snapshot list
   ```

   Check the actual snapshot's shipped status, and that the uploaded manifest
   and referenced objects are available. Uploading files without the final
   manifest is not a completed snapshot. An active log tail can lag its latest
   acknowledgement by the ship interval: record the **actual shipped** point,
   not an assumed zero-loss recovery point.
4. Restore into a separate empty owned directory using the [restore runbook](restore.md).
   Compare integrity through the recorded source LSN and read the fixture's
   known SQL/key-value state. A successful upload or listing is not proof that
   a backup can be restored.
5. Keep recovery keys and provider versions for the backup's entire retained
   lifetime. Erasure and backup retention need their documented key lifecycle;
   do not resurrect erased data from an unreviewed older key copy.

## Owned local drill

A `file:///owned/fixture/shipped` ship target exercises the real ship/restore
format without credentials or an external service. It is **not off-host backup
or disaster-resilience proof**. Use known non-secret data, let the actual
shipper publish the recorded snapshot, then run restore and integrity checks
against another fixture directory. Record exact versions, commands, hashes,
source/shipped/restored LSNs, missing-key inventory and cleanup. Physical S3
availability/IAM and test VPS exercises are separate evidence, not inferred
from this local flow.
