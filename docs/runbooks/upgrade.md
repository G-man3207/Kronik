# Upgrade

Goal: change the executing binary only after the new engine has replayed the
actual retained history without a behavior change. A patch version is not an
engine-compatibility exemption.

## Procedure

1. Record old and candidate `kronik --version` output and binary SHA-256.
   Obtain the candidate through the release verification process; do not
   weaken signature verification for an upgrade. Make a recoverable backup
   using the [backup runbook](backup.md), including its independent key source.
2. With the **candidate binary**, check the actual data and configured keys:

   ```sh
   /owned/candidate/kronik --json upgrade check \
     --data-dir /owned/installation/data --config /owned/installation/kronik.toml \
     --workers 2 --dry-run
   /owned/candidate/kronik --json upgrade check \
     --data-dir /owned/installation/data --config /owned/installation/kronik.toml \
     --workers 2
   ```

   Select a retained traffic window that covers the application's important
   behavior. Check the actual old/new engine pair, root and turn counts and
   that the diff holds no verified difference. A zero-input check is not
   application evidence. Turns that met erased data (their own recorded
   input, or state and messages it shaped) are reported `N turns
   unverifiable` and pass; read that count, not only the exit code, because
   those turns were not verified. The
   check also asks the question the start asks of the data directory, whether
   the log that retention kept reaches `state.db` and every actor database: it
   prints a note on stderr, also with `--json`, when the start will repair that
   by installing a snapshot, and exits 1 with `STORAGE_CORRUPT` and the start's
   own message when it cannot ([A start that stops at the log's
   start](../guides/operations.md#a-start-that-stops-at-the-logs-start)).
   An actor database the old daemon holds is read without taking that lock.
   If it cannot be read, the check exits 1 with `STORAGE_CORRUPT` rather than
   treating the database as current.
3. If `ENGINE_UPGRADE_DIVERGED`, `STORAGE_CORRUPT`, missing keys or another
   prerequisite is reported, keep the current binary. Read the saved
   report/diff. Never edit historical engine strings, suppress divergence, or
   copy a report from another directory/pair. An unavailable prerequisite is
   not a passing check.
4. Stop only the owned old process/service using its recorded lifecycle handle,
   replace its binary through the normal verified installation mechanism, and
   start the candidate with the same owned data/config/key source. In a local
   fixture, do not install/reload/restart a global host service.
5. Check health, the real `engine.upgrade` audit event and integrity through
   the old recorded LSN. Read the fixture's known SQL/key-value state and
   repeat a key-backed effect. Restart the owned candidate once and ensure it
   does not append a second upgrade event for the same completed transition.
6. Identity replay in both modes must remain complete and unchanged. A rollback
   is an engine transition in the opposite direction and needs its own passing
   check; restoring the old binary over new data without a check is unsafe.

For data written by v0.3.0 or older, two things differ from the procedure
above: an older binary could not start on data that a newer one had served,
so the backup of step 1 is the way back, and some reads answer 503
`SECRET_UNAVAILABLE` after the upgrade until retention has deleted the old
snapshots. What was checked, and how to end it, is in [Upgrading from v0.3.0
or older](../guides/operations.md#upgrading-from-v030-or-older).

## Compatibility drill

`scripts/compatibility-corpus.py` preserves actual released producer data and
uses the candidate's real public upgrade check, integrity and isolated/continuous
identity replay. Its source alone is not a drill result. Keep the immutable
producer's release/revision/binary digest and exact candidate proof, including
failed/refused transitions. The actual v0.1.0 release reports `0.1.0-dev`;
retain that historical identity rather than relabeling it. The
[compatibility policy](../guides/compatibility.md) describes the broader corpus
and notice requirements.
