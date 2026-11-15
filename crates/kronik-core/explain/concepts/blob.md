A blob holds a large HTTP body or an app's large object outside the log (M25,
M26). The log records only a reference: the blob's hash and size, and for a
subject's blob its subject and key version. The bytes live in the blob store
under `<data>/blobs`, written and synced before any record refers to them.

A blob is named by its content: `b3:` and the BLAKE3 hash of its bytes, or,
for a blob with a subject, `b3s:` and a hash keyed with the subject's key,
so the name says nothing about the content once the subject is erased.

A reference is an identity, not a permission. A turn may use the references
it holds, the ones its input carries (an upload, a message's blobs), and the
ones it obtained during the turn (a fetch response above the blob threshold,
a blob it wrote). Using any other reference gives `BLOB_NOT_HELD`. A
reference the turn received but does not hold is *borrowed*: readable during
the turn only. `blobs.retain` makes the actor hold it once the turn commits,
and `blobs.release` ends the hold (M26).

A component gets blob bodies only if it imports `kronik:actor/blobs`; it
reads them in ranges with `blobs.get` and writes them with a `writer`.
Replay reads the same blobs lazily, only the bytes the guest reads.

See also: `blob-threshold`, `hold`, `collector`, `BLOB_NOT_HELD`, `message`, `subject`, `sealed-value`.
