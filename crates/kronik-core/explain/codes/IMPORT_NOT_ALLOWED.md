Deploy rejects a component that imports anything outside the allowlist, and the message lists the offending imports. Guest code may import Kronik's interfaces (`kronik:actor`) and deterministic versions of a WASI allowlist: `wasi:clocks` (logical time), `wasi:random` (the turn's seed), `wasi:cli` (stdout and stderr become log events), the `wasi:io` streams those need, and `wasi:http/types` and `wasi:http/outgoing-handler` at 0.2.x. Those two `wasi:http` imports are allowed: each outgoing request is an `http.fetch` effect, which is what a TypeScript `fetch` uses. `wasi:http/incoming-handler`, `wasi:filesystem` and `wasi:sockets` are denied, as is any other `wasi:http` interface and WASI 0.3.

Typical cause: a library that uses the file system or opens sockets. An import of `wasi:http/types` or `wasi:http/outgoing-handler` is not one to remove, and a standard `fetch` that uses those imports is supported.

To fix it, remove or replace the code that pulls in the imports the message lists, rebuild the component and deploy it again (from M3, propose it instead for a kind with history):

    kronik deploy ./dist/billing.wasm --reason "remove file system access"

See also: `effect`.
