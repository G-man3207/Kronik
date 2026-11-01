# SECRET_EXTERNAL

This name is linked to an external secret manager. Kronik does not write or delete values in that service.

Change or rotate the value using the backend's own authorized tools, then run `kronik secret refresh <name> --reason '...'`. To return future turns to the built-in store, an administrator can explicitly unlink the name. Unlinking does not redirect historical versions or make an old recorded value equal to the current one.
