Deploy found that another actor type already serves the same HTTP method and route pattern. Routes come from the manifest that `describe` returns, and each method and pattern belongs to at most one actor type. Patterns that differ only in parameter names count as the same route.

To fix it, change the method or the pattern in the component's manifest, rebuild the component and deploy it again:

    kronik deploy ./dist/billing.wasm --reason "move billing routes under /billing"

See also: `kind`, `ROUTE_NOT_FOUND`.
