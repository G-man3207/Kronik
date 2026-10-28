A foreign actor with this name is already declared. Names are unique, and a declaration is history (a `ForeignActor` record), so an existing foreign actor is never changed in place.

To change its image, port, limits or secrets, remove it and add it again; the data directory `foreign/actors/<name>/data` is kept:

    kronik foreign remove payments --reason "..."
    kronik foreign add payments --image ghcr.io/org/fake-payments@sha256:... --port 8080 --reason "..."

See also: `foreign-actor`.
