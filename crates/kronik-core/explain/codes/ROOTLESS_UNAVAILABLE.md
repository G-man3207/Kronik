The nonroot service cannot establish its owned user namespace, safely hand over its data directory or use a delegated cgroup. Typical causes are a missing or mismatched namespace pin, unavailable user namespaces, missing subordinate IDs, an unexpected data owner, or a unit without writable delegation.

No host capability is retained to make this work, no actor resource limit is removed, and no weaker backend or root service is selected automatically. A daemon whose foreign boundary is unavailable can still serve Wasm after clearing its startup capabilities. A rejected setup or offline handover must be repaired before retrying.

`kronik serve --rootless` also stops with this code, before it creates or binds anything, where it could not report its API callers' real uids: when it runs as root, when its real, effective and saved user ids differ, and in a user namespace whose uid map is not the host's identity map, as in a rootless container or a nested user namespace. The message says which. Those hosts are not supported for the nonroot unit: use the root service (`kronik serve --init --root`). `kronik doctor --rootless` shows the same condition as `uid_view` before the service is started.

Run the diagnosis under the actual service identity and its owned unit:

    kronik doctor --rootless
    kronik userns status --json

Repair the root-controlled stable-user/subordinate-ID setup and the unit's `Delegate=yes` configuration. A matching pin is kept. A mismatched pin is never replaced automatically: stop its consumers and use explicit, ownership-checked unpin/setup before changing identity. Never remove a replacement or preexisting pin belonging to another runner.

See also: `FOREIGN_UNAVAILABLE`, `isolation-level`.
