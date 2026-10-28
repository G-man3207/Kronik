# 0007. Policy rules in CEL with the `cel` crate

- **Status:** Accepted
- **Date:** 2026-10-25

## Context

Policy is rules in CEL evaluated against the diff object `kronik.diff/v1`
(brief, "Operator configuration and policy"). The brief says to evaluate the
`cel-interpreter` crate in M5 and, if it is not sufficient, to build a simple
declarative matcher with the same TOML format. `docs/design/m3-fork.md` §7 is
the binding contract: the diff JSON bound to `diff`, ints and doubles that
compare numerically, the CEL subset that must work, error-as-firing, and the
Rust API. Policy is part of the functional core: evaluation must be pure and
deterministic, and nothing a rule says may crash the daemon.

`cel-interpreter` was renamed to `cel` (same repository,
`cel-rust/cel-rust`). Its last release under the old name, 0.10.0 (July 2025),
depends on `paste`, which RustSec lists as unmaintained (RUSTSEC-2024-0436),
so it fails `cargo deny`. The evaluation below is of `cel` 0.15.0 (October
2026), with `default-features = false, features = ["regex"]`. Its new
dependencies (`antlr4rust`, `nom`, `pastey`, `bit-set`, `murmur3`,
`typed-arena`, `uuid`, `parking_lot`, …) are all under licenses the allowlist
already has, and `cargo deny check` passes.

### Findings

Each item was checked by evaluation; the tests in
`crates/kronik-policy/tests/cel.rs` keep checking them.

| Feature | Result |
| --- | --- |
| Literals: int, uint, double, hex, string (quotes, triple quotes, raw, escapes), bytes, bool, null, lists | Work. |
| Field selection, indexing (`a.b`, `a['b']`, `l[0]`, `l[1u]`) | Work. A missing key or index is an error. |
| `== != < <= > >=`, int/double/uint mixed | Work numerically: `diff.summary.sample < 1` and `diff.errors.introduced > 0.0` hold as §7 requires. Arithmetic does not mix types (`1 + 1.0` is an error), as in the CEL spec. |
| `&& \|\| !` | Work, commutatively absorbing errors (`diff.nope \|\| true` is true), as in the spec. |
| `+ - * /` | Work; overflow and integer division by zero are errors. |
| `in`, `size()` | Work for lists, maps, strings (code points) and bytes. |
| `exists`, `all`, `exists_one`, `filter`, `map` (two and three arguments) | Work, absorbing errors an element that decides overrides. |
| `startsWith`, `endsWith`, `contains`, `matches` | Work; `matches` uses the `regex` crate (RE2 syntax, linear time). An invalid pattern is an evaluation error. |
| `has()` | Works on map keys; `has(diff)` is a parse error. |
| Clock and environment | Nothing reachable. Without the `chrono` feature there are no timestamp or duration types, so no function touches a clock; there is no `now`, `getenv` or extension library in the environment, and an unknown function is an evaluation error. |
| Side effects | None: evaluation reads its inputs only. |
| Determinism | **Gap.** CEL maps are `HashMap`s with a random seed, and the CEL spec leaves map iteration order unspecified. Measured: `diff.summary.map(k, k)[0]` gave 13 different keys over 50 evaluations, and the error a comprehension over a map reports varied between runs. |
| Stack use | **Gap.** Parsing and evaluation recurse over the expression, and nothing bounds it. Measured on a 2 MiB thread: a 2000-term `1 + 1 + …` overflows the stack in evaluation (release), 60 terms in debug builds. The ANTLR-generated parser takes ≈6.5 KiB of stack per level of nested parentheses in release builds and ≈160 KiB in debug builds; its recursion limit (96) caps this at ≈0.9 MiB release, ≈17 MiB debug. A stack overflow aborts the process. |
| Panics | **Gap.** `ParseError`'s `Display` panics when the column exceeds `u16::MAX`; a few `todo!()` and `expect()` remain on evaluation paths not used by the standard library. |
| JSON numbers | `cel::to_value` turns positive JSON integers into `uint`, so §7's mapping needs a binding of our own. |
| API stability | 0.x with breaking changes in most minor releases. |

## Decision

Rules are evaluated with `cel` 0.15.0, pinned exactly (`=0.15.0`): its
semantics decide policy outcomes, so an upgrade is a reviewed change that
reruns this evaluation. `kronik-policy` fills the gaps:

- **Binding.** The diff is bound through our own `Val` implementation over
  the `serde_json::Value` (`json.rs`), which borrows instead of copying: JSON
  integers are `int` (`uint` above `i64::MAX`), other numbers `double`,
  objects a map that iterates its keys in the JSON object's order. Lists are
  the crate's own lists, so they compare with list literals.
- **Determinism.** Map literals (`{…}`) are rejected at parse time, since
  CEL would iterate them in hash order. Every map a rule sees is the diff's,
  so every evaluation of a rule set against a diff gives the same
  `Evaluation`, messages included. Message construction (`T{…}`) is rejected,
  and the optional-value syntax (`a.?b`), an extension that cel-go also leaves
  off by default, is disabled. The `optional.*` functions stay callable; they
  are pure.
- **Limits** (checked at `policy set`):
  - a `when` is at most 1024 bytes (`MAX_WHEN_BYTES`), which bounds the
    chains the parser recurses over;
  - it nests parentheses, brackets, braces, call arguments and conditionals
    at most 8 levels below its top level (`MAX_WHEN_NESTING`, the parser's
    own recursion limit);
  - its expression tree is at most 32 levels deep, where a comprehension
    counts two (`MAX_WHEN_DEPTH`).

  Measured with these limits, the worst inputs need ≤ 231 KiB of stack to
  parse and ≤ 63 KiB to evaluate in release builds, and ≤ 1.6 MiB and
  ≤ 1.3 MiB in debug builds. So any rule, accepted or not, fits the 2 MiB
  stack of a tokio worker or test thread, in debug builds too. The tests run
  the deepest accepted shapes on a 2 MiB thread, and on a 512 KiB thread
  under `cargo test --release`. Realistic rules nest 3 to 5 levels; the
  default rules nest 3.
- **Panics.** Parse errors are formatted by `kronik-policy`, not by
  `ParseError`'s `Display`. Parsing and evaluation run under `catch_unwind`:
  a panic in the crate fails that rule (a parse error, or an evaluation error
  that fires with at least `require_approval`) rather than the daemon, as long
  as panics unwind.
- **Compile once.** `RuleSet::parse_toml` compiles every `when`, so syntax
  errors and limit violations surface at `policy set`. `evaluate` reuses the
  compiled trees, which takes a few microseconds per rule set. A rule
  changed through the public `rules` field after parsing is compiled again
  when it is evaluated.

## Alternatives

- **The declarative fallback** (the brief's matcher, or our own CEL subset
  over `serde_json::Value`): deterministic and bounded by construction, with
  no parser dependency. It is also a language implementation to own, and every
  CEL corner (error absorption, numeric equality, string escapes, regex
  syntax) would be ours to get right. The crate passed every functional check,
  and its gaps can be closed in `kronik-policy` with a few hundred lines. If
  an upgrade breaks the guarantees above, or the dependency becomes a burden,
  this is the fallback, with the same TOML format and API.
- **`cel-interpreter` 0.10**: unmaintained `paste`, older API; superseded by
  `cel`.
- **The crate's `parser_pratt` feature**: a hand-written parser that would
  avoid ANTLR's stack use, but it is `#[doc(hidden)]` and not what `Env`
  uses.
- **Evaluating on a thread with a large stack**: library code may not spawn
  threads (ADR 0004), and the limits are needed for a bounded parse anyway.
- **Sorting map literals**: would need rewriting the AST into calls of our
  own map constructor, against crate internals that change between releases.
  Lists cover the uses (`t.host in ['a', 'b']`).

## Consequences

- Rules are standard CEL, minus map literals, message construction and the
  optional syntax, within the three limits. `docs/design/m3-fork.md` §7
  holds; ints and doubles compare numerically.
- There is no type checker: an unknown variable or function in a `when` is an
  evaluation error, so the rule fires with at least `require_approval` and
  the message is in `errors`. `kronik policy test` shows it before
  `policy set`.
- Evaluation cost is not metered: nested comprehensions over large lists in
  the diff (for example `responses.items`) take time proportional to their
  product. Policy is set by operators with the policy scope; a cost limit is
  for when that is not enough.
- The `cel` version is part of how policies behave. Upgrading it means
  rerunning `crates/kronik-policy/tests` and the stack measurements behind
  the limits, and amending this ADR.
