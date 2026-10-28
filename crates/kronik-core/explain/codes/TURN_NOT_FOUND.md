No turn record has this id on the branch that the daemon serves. A turn id is `<branch>:<lsn>` of the turn's turn record, for example `main:1482331`; an LSN that holds another kind of record is not a turn. This code exists, apart from `ACTOR_NOT_FOUND`, because turn ids address positions in the log, not actors.

If the turn's LSN is below the first LSN the log still holds, retention has deleted that segment. The message says the turn is outside retention and names `log_first_lsn`.

To fix it, take the turn id from the actor's history, from a dead letter or from the `Kronik-Turn-Id` header:

    kronik history billing/acme

See also: `turn-id`, `lsn`.
