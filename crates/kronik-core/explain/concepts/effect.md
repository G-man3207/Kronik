An effect is a call from guest code to the outside world via the host, for example `http.fetch`, a call to a foreign actor (M7) or host-side cryptography with a secret. External effects require a capability (default deny, I6); internal ones, such as `call`, `send` and timers, do not. Every effect is recorded. External effects can happen before the turn commits and are not rolled back. In a fork (M3), effects are matched against recordings and never reach the outside world (I7). Effect is one of Kronik's five concepts.

See also: `capability`, `delivery-class`, `grounding`, `secret-handle`.
