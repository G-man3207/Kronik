A sealed value (privacy mode on, a value tagged with a subject) needs its subject's key from the privacy keystore, `keys/keystore.db`, and the keystore does not hold it. The subject was not erased either, so the value is not a tombstone: it is data that nobody can read on this node.

Where it shows:

- `kronik restore` checks every sealed value in the restored state and log against the keystore it would install (the bucket's newest keystore backup, with the log's later erasures applied again). If one has no key, the restore fails before it writes, and names the subjects.
- `kronik integrity` lists such subjects on a running node, for example one restored with `--without-keystore`.
- Replay (a proposal, a fork) that meets such a value fails with this code instead of running the turn without it.

Typical causes:

- The keystore backup in the bucket is older than the subject's first sealed value: the shipper uploads one within a minute of a keystore change, so restoring right after a new subject appeared can come too early.
- The restore ran with `--without-keystore`.
- `keys/keystore.db` was deleted or replaced on this node.

To fix it, let the source node ship again (or wait a minute while it runs) and restore again, or restore from another bucket that has a newer backup. If the keys are lost, the values cannot be recovered; `--without-keystore` restores the rest.

See also: `MASTER_KEY_MISSING`, `SUBJECT_ERASED`.
