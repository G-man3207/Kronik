A replay that must reproduce recorded history produced a different result. The same code hash, engine version, input, recorded effect results, logical time, random seed and starting state must give a byte-identical outcome (I1), so this is a determinism bug.

Typical causes: a bug in Kronik's host or engine configuration, or a value that reached the guest without going through a recorded host call (I2).

To fix it, do not promote or upgrade on top of the divergence. Report it with the turn id, the actor's history and the daemon log:

    kronik history billing/acme

See also: `turn`, `behavior-diff`.
