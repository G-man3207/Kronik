//! Prints `docs/concepts/glossary.md`, the book's concepts page, from
//! `kronik_core::explain`:
//!
//! ```sh
//! cargo run -p kronik-core --example concepts_md > docs/concepts/glossary.md
//! ```
//!
//! `scripts/ci.sh docs` fails when the committed file differs from this
//! output.

use std::io::{self, Write};

use kronik_core::error::ErrorCode;
use kronik_core::explain::{self, TopicKind};

const INTRO: &str = r#"# Concepts

<!-- Generated from crates/kronik-core/src/explain.rs and
crates/kronik-core/explain/concepts/ by
`cargo run -p kronik-core --example concepts_md > docs/concepts/glossary.md`.
Edit those files, not this one; `scripts/ci.sh docs` checks it. -->

Kronik has five concepts of its own: [actor](#actor), [message](#message),
[effect](#effect), [hash](#hash) and [fork](#fork). The other terms on this
page are built from them. Code, docs and the CLI use every term exactly as it
is written here, and `kronik explain <term>` prints the same text in a
terminal.

Each term names the milestone that introduces it, and a definition marks
parts that come later with their own milestone, for example "(M3)". The
[introduction](../introduction.md#roadmap) lists the milestones.

"#;

fn main() -> io::Result<()> {
    let concepts: Vec<explain::Topic> = explain::list()
        .filter(|t| t.kind == TopicKind::Concept)
        .collect();
    let mut out = io::BufWriter::new(io::stdout().lock());
    out.write_all(INTRO.as_bytes())?;
    writeln!(out, "| Term | Meaning | Milestone |")?;
    writeln!(out, "| --- | --- | --- |")?;
    for t in &concepts {
        writeln!(
            out,
            "| [`{name}`](#{name}) | {title} | {milestone} |",
            name = t.name,
            title = t.title,
            milestone = t.milestone,
        )?;
    }
    for t in &concepts {
        write!(
            out,
            "\n## {name}\n\n{title}. Milestone {milestone}.\n\n",
            name = t.name,
            title = t.title,
            milestone = t.milestone,
        )?;
        for line in t.text.lines() {
            match see_also(line) {
                Some(links) => writeln!(out, "{links}")?,
                None => writeln!(out, "{line}")?,
            }
        }
    }
    out.flush()
}

/// On the concepts page, the topics of a `See also:` line become links: to
/// the concept's entry, or to the code's entry in the error catalog.
fn see_also(line: &str) -> Option<String> {
    let refs = line.strip_prefix("See also: ")?;
    let refs = refs.strip_suffix('.').unwrap_or(refs);
    let links: Vec<String> = refs
        .split(", ")
        .map(|r| {
            let name = r.trim_matches('`');
            match ErrorCode::parse(name) {
                Some(code) => format!(
                    "[`{code}`](../errors.md#{})",
                    code.as_str().to_ascii_lowercase()
                ),
                None => format!("[`{name}`](#{name})"),
            }
        })
        .collect();
    Some(format!("See also: {}.", links.join(", ")))
}
