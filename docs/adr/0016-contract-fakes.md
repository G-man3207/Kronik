# 0016. Contract fakes from OpenAPI JSON, deterministic by fingerprint

- **Status:** Accepted
- **Date:** 2026-10-26

## Context

M12's `ContractFake` gives schema-valid answers from an OpenAPI file for a
target, the same answer for the same request. Kronik has no YAML or JSON
Schema dependency, and adding a full JSON Schema implementation for one
simulator is heavy. Answers must not depend on time, randomness or worker
order (I1).

## Decision

- Documents are OpenAPI 3.0 or 3.1 in JSON, stored in the
  `SimulatorConfig` record (at most 1 MiB). YAML users convert first; the CLI
  says so.
- A generator in `kronik-effects` covers the schema keywords listed in
  `docs/design/m12-simulators.md` §3.1 (`$ref` to components, `type`,
  `properties`, `items`, `enum`, `const`, `format`, length and range bounds,
  `oneOf`/`anyOf` first branch, `allOf` merge). Unsupported keywords are
  ignored, which can only make a value less specific, not invalid for the
  keywords covered.
- Every choice draws from a BLAKE3 XOF keyed by `kronik.contract.v1`, the
  target and the request fingerprint, so the same request gets the same
  bytes, on any machine and with any number of workers.
- Generation is bounded: at most 10 000 values, 1 MiB (values counted at
  their serialized size, `const` and `enum` included) and nesting depth 16
  per answer, strings at most 4096 characters, an optional property or an array
  without `minItems` that refers back to a `$ref` being generated is left
  out or empty. A schema that cannot be satisfied within the bounds
  (required recursion, a format that does not fit its length bounds,
  `minimum` above `maximum`) gives no answer, never an invalid one; the next
  simulator answers. An `operate` token cannot make the daemon generate
  without bound.
- Validity is tested with an independent validator for the same subset in
  the test code, and the keyword edges with direct assertions.

## Alternatives

- **A JSON Schema crate** (`jsonschema`): a large dependency tree for
  validation only; the generator would still be ours.
- **Examples from the document** (`example`, `examples`): many documents
  have none; used would be fine but not sufficient.
- **Random answers per call**: breaks determinism and the criterion.

## Consequences

- Contract fakes are cheap and reproducible; a document that relies on
  keywords outside the subset gets plainer values.
- A later YAML dependency would only change parsing.
