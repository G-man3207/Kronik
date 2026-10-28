//! Prints `docs/errors.md`, the error catalog, from `kronik_core::error`:
//!
//! ```sh
//! cargo run -p kronik-core --example errors_md > docs/errors.md
//! ```
//!
//! `scripts/ci.sh docs` fails when the committed file differs from this
//! output.

use std::io::{self, Write};

use kronik_core::error::ErrorCode;

const INTRO: &str = r#"# Error codes

<!-- Generated from crates/kronik-core/src/error.rs and
crates/kronik-core/explain/codes/ by
`cargo run -p kronik-core --example errors_md > docs/errors.md`.
Edit those files, not this one; `scripts/ci.sh docs` checks it. -->

Every error from the JSON API, the gateway and the CLI has the same shape, and
its HTTP status follows from its code:

```json
{
  "error": {
    "code": "CAPABILITY_NOT_GRANTED",
    "message": "billing is not allowed to call payments.internal",
    "hint": "kronik grant billing http:payments.internal --reason '...'",
    "docs": "kronik explain CAPABILITY_NOT_GRANTED"
  }
}
```

- `code` is stable: a code is never renamed or reused.
- `message` says what happened, for this request.
- `hint` says what to do next, often as the exact next command. Unless the
  error has a more specific one, it is the code's default hint listed below.
  It is omitted when an error has no hint.
- `docs` is `kronik explain <CODE>`, which prints the code's entry below.
  The lookup ignores case.

Each code names the milestone that introduces it; the
[introduction](introduction.md#roadmap) lists the milestones. Terms in the
entries are defined in [Concepts](concepts/glossary.md).

"#;

fn main() -> io::Result<()> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    out.write_all(INTRO.as_bytes())?;
    writeln!(out, "| Code | HTTP status | Milestone | Meaning |")?;
    writeln!(out, "| --- | --- | --- | --- |")?;
    for &code in ErrorCode::ALL {
        writeln!(
            out,
            "| [`{code}`](#{anchor}) | {status} | {milestone} | {title} |",
            anchor = anchor(code),
            status = code.http_status(),
            milestone = code.milestone(),
            title = code.title(),
        )?;
    }
    for &code in ErrorCode::ALL {
        write!(
            out,
            "\n## {code}\n\nHTTP status {status}, milestone {milestone}. {title}.\n\nDefault hint: {hint}\n\n",
            status = code.http_status(),
            milestone = code.milestone(),
            title = code.title(),
            hint = code.hint(),
        )?;
        for line in code.explain().lines() {
            match see_also(line) {
                Some(links) => writeln!(out, "{links}")?,
                None => writeln!(out, "{line}")?,
            }
        }
    }
    out.flush()
}

/// The heading id of a code's entry.
fn anchor(code: ErrorCode) -> String {
    code.as_str().to_ascii_lowercase()
}

/// In the catalog, the topics of a `See also:` line become links: to the
/// code's entry, or to the concept on the concepts page.
fn see_also(line: &str) -> Option<String> {
    let refs = line.strip_prefix("See also: ")?;
    let refs = refs.strip_suffix('.').unwrap_or(refs);
    let links: Vec<String> = refs
        .split(", ")
        .map(|r| {
            let name = r.trim_matches('`');
            match ErrorCode::parse(name) {
                Some(code) => format!("[`{code}`](#{})", anchor(code)),
                None => format!("[`{name}`](concepts/glossary.md#{name})"),
            }
        })
        .collect();
    Some(format!("See also: {}.", links.join(", ")))
}
