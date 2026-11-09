The TLS certificate configured for the gateway cannot be used. It has expired, its PEM cannot be parsed, or the certificate or private-key file cannot be read. A TLS handshake with that material fails, so the gateway cannot serve HTTPS until it is replaced. `kronik doctor` reports this from the `tls` check (files or a cached ACME certificate) and from the `dns01_hook` check (a cached wildcard certificate).

Typical causes:

- `[tls] cert_file` or `key_file` is missing, unreadable, or not PEM.
- The certificate's not-after date has passed.
- ACME renewal failed, so the cache still holds an expired certificate.

To fix it, replace the files or let the gateway renew, then check again:

    kronik doctor
