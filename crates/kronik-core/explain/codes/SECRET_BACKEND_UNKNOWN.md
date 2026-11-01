# SECRET_BACKEND_UNKNOWN

The requested link names a backend that this installation has not configured. Backend identity, endpoints, credentials and reference allowlists come from trusted installation configuration, never a link or wrapped envelope supplied by a caller.

Use `kronik secret backends` to inspect configured bindings without contacting providers. Select the intended backend, or have an administrator configure it and restart the installation deliberately. Link and unlink require `admin`; refreshing a configured name requires `operate`.

An unknown backend publishes no link or secret version and does not fall back to the built-in store. Historical resolved references must retain the exact backend binding, canonical resource, link generation and immutable version; changing a name's current link does not rewrite those identities.
