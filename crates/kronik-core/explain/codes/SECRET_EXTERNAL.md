# SECRET_EXTERNAL

This name is linked to an external secret manager. Kronik does not write or delete values in that service.

Change or rotate the value using the backend's own authorized tools, then run `kronik secret refresh <name> --reason '...'`. To return future turns to the built-in store, an administrator can explicitly unlink the name. Unlinking does not redirect historical versions or make an old recorded value equal to the current one.

A foreign actor does not read a linked name from its backend, and the built-in store holds an older value of that name or none, so it refuses it. `kronik foreign add --secret` refuses a linked name. An actor declared before the name was linked is not stopped and keeps the value it started with, as after a rotation; its next start fails with this code (`kronik foreign list` shows it, and the supervisor retries with its backoff) until the name is unlinked, or the actor is removed and added again with another secret.
