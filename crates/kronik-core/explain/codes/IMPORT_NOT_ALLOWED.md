Deploy rejects a component that imports anything outside the allowlist, and the message lists the offending imports. Guest code may import only Kronik's interfaces (`kronik:actor`) and deterministic versions of a WASI allowlist: `wasi:clocks` (logical time), `wasi:random` (the turn's seed), `wasi:cli` (stdout and stderr become log events) and the `wasi:io` streams that are needed. `wasi:filesystem`, `wasi:sockets` and `wasi:http` are denied in v0.1.

Typical cause: a library that uses the file system, opens sockets or makes HTTP requests directly. Outgoing HTTP must go through Kronik's effect, `http.fetch`.

To fix it, remove or replace the code that pulls in the listed imports, rebuild the component and deploy it again (from M3, propose it instead for a kind with history):

    kronik deploy ./dist/billing.wasm --reason "remove file system access"

See also: `effect`.
