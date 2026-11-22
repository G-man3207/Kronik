The fetch URL names an explicit port, for example `https://api.example.com:8443`. An `http:` capability names only a host — a grant that itself spells a port is refused, because ports are not part of it — so no grant can cover another port of that host: it may be a different service than the one the operator intended. The guest gets `denied`, and the attempt is recorded in the turn.

To fix it, fetch the scheme's default port by omitting `:port` from the URL. If the service really is on another port, it needs its own host name (a name that resolves to it), granted as usual.

See also: `CAPABILITY_NOT_GRANTED`, `capability`, `effect`.
