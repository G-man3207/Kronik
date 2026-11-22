The request carries a secret header (`{{secret:NAME}}`) and its URL is cleartext `http` to a host beyond loopback. The host inserts the value at the effect boundary and never shows it to the guest, but on cleartext it would transmit it unencrypted to that host, readable by anything on the path. The guest gets `denied`, and the attempt is recorded in the turn. Loopback hosts (`localhost`, `127.0.0.1`, `::1`) are the exception: their bytes never leave the machine, so local sidecars and test servers may take a secret over `http`.

To fix it, use an `https` URL for the request, or send the header without a secret.

See also: `CAPABILITY_NOT_GRANTED`, `SECRET_UNAVAILABLE`, `capability`, `effect`.
