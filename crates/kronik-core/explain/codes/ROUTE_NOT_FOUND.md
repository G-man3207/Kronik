The gateway found no route for the request's method and path. Routes come from the manifests of the current deployments, and a `{name}` segment in a pattern matches one path segment. This code exists, apart from `ACTOR_NOT_FOUND`, because the gateway routes on method and path before any actor is involved.

Typical causes: a wrong method or path, a kind that has not been deployed, or a route that the latest deployment removed.

To fix it, compare the request with the routes in the kind's manifest, which `kronik deploy` prints.

See also: `ROUTE_CONFLICT`, `deployment`.
