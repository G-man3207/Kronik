The collector deletes the blob files that nothing keeps any more (M26). No
actor or operator deletes a blob directly, except that erasing a subject
deletes its blobs at once. What keeps a blob is a root: a hold; a queued
message, a timer or a dead letter that carries it; a saved idempotent
response or `call` outcome; a running turn and its effects; a record within
retention; a snapshot; a fork; or a lease, which the daemon takes in memory
on what it is using right now (an upload, a streamed answer, a turn, a
replay) and renews while it does. A hash stored as data is no root.

A pass runs after every retention pass and every `[blobs] gc_interval` (an
hour), and deletes a file only if the previous pass also found it without a
root, so a file goes within two passes after its last root does.
`kronik blobs gc --dry-run` (MCP `blob_gc_plan`) lists the files without a
root and why: `loose` (no record ever referenced it), `released` (its last
holder let it go), `out-of-retention` or `erased`. `kronik blobs inspect`
lists one blob's roots, and `kronik blobs gc --reason "..."` runs a pass
now.

    kronik blobs gc --dry-run
    kronik blobs inspect b3:4f1c09ab77e9d0c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9

See also: `blob`, `hold`, `snapshot`, `fork`.
