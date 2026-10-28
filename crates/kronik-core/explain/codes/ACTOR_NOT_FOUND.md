The actor or its actor type does not exist. Actors are addressed as `kind/key`: the kind must be deployed, and an actor appears once it has run its first turn.

Typical causes:

- A typo in the kind or the key.
- A message to a kind that has not been deployed yet.
- Inspecting an actor that has never run a turn.

To fix it, list the actors that exist, or deploy the kind first:

    kronik actors list
    kronik deploy ./dist/billing.wasm --reason "first deploy"

See also: `actor`, `kind`.
