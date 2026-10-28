A hash is the BLAKE3 hash of a component's bytes and the identity of its code. It is shown as `b3:` plus 12 hex characters, for example `b3:4f1c09ab77e9`. A deployment points an actor type at a hash, every turn record carries the code hash, and from M3 a rollback switches back to the previous hash. Hash is one of Kronik's five concepts.

See also: `kind`, `deployment`, `proposal`.
