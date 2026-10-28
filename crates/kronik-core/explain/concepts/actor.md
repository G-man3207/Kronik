An actor is an instance of an actor type, identified by `kind/key`, for example `billing/acme`. It has its own state and handles one input at a time: an HTTP request, a message, a timer (from M2) or a migration, each in its own turn. Actors are Wasm components, and every turn runs in a fresh instance, so nothing in guest memory survives to the next turn (I3). Actor is one of Kronik's five concepts.

    kronik actors list
    kronik actors inspect billing/acme
    kronik history billing/acme

See also: `kind`, `turn`, `message`, `foreign-actor`.
