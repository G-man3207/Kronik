//! Every metric that the daemon records is in the catalog, and every catalog
//! entry is recorded somewhere. `/metrics` and the OTLP push walk the catalog
//! ([`kronik_metrics::METRICS`]), so a series under a name that is not in it
//! is recorded and never exported, and nothing says so: that is how
//! `kronik_key_source_up` was dropped on every scrape (issue #38).
//!
//! The test reads the sources of the workspace's crates (`crates/*/src`) and
//! collects the names given to `kronik_metrics::{inc, add, set, observe,
//! timer}`, as a string literal or as a `const` of the same file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const RECORDERS: [&str; 5] = ["inc", "add", "set", "observe", "timer"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The value of `const <ident>: &str = "<value>";` in `text`.
fn constant(text: &str, ident: &str) -> Option<String> {
    let start = text.find(&format!("const {ident}: &str = \""))?;
    let rest = &text[start..];
    let open = rest.find('"')? + 1;
    let close = rest[open..].find('"')? + open;
    Some(rest[open..close].to_owned())
}

/// The metric names `text` records, and the calls whose name it could not
/// read (neither a literal nor a constant of the file).
fn recorded(text: &str) -> (BTreeSet<String>, Vec<String>) {
    let mut names = BTreeSet::new();
    let mut unread = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("kronik_metrics::") {
        rest = &rest[at + "kronik_metrics::".len()..];
        let Some(function) = RECORDERS.iter().find(|f| {
            rest.strip_prefix(**f)
                .is_some_and(|after| after.trim_start().starts_with('('))
        }) else {
            continue;
        };
        let argument = rest[function.len()..].trim_start()[1..].trim_start();
        if let Some(literal) = argument.strip_prefix('"') {
            match literal.find('"') {
                Some(end) => {
                    names.insert(literal[..end].to_owned());
                }
                None => unread.push(argument.chars().take(40).collect()),
            }
        } else {
            let ident: String = argument
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            match constant(text, &ident) {
                Some(name) => {
                    names.insert(name);
                }
                None => unread.push(argument.chars().take(40).collect()),
            }
        }
    }
    (names, unread)
}

#[test]
fn every_recorded_metric_is_in_the_catalog_and_every_entry_is_recorded() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap().flatten() {
        rust_files(&entry.path().join("src"), &mut files);
    }
    files.sort();
    let mut names = BTreeSet::new();
    let mut unread = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let (found, missed) = recorded(&text);
        names.extend(found);
        unread.extend(
            missed
                .into_iter()
                .map(|m| format!("{}: {m}", file.display())),
        );
    }
    assert!(
        unread.is_empty(),
        "metric names this test cannot read: {unread:?}"
    );
    // Not vacuous: the daemon records most of its catalog in plain sight.
    assert!(names.len() >= 20, "only {names:?} found");
    let catalog: BTreeSet<String> = kronik_metrics::METRICS
        .iter()
        .map(|def| def.name.to_owned())
        .collect();
    let missing: Vec<_> = names.difference(&catalog).collect();
    assert!(
        missing.is_empty(),
        "recorded but not in the catalog, so never exported: {missing:?}"
    );
    let unrecorded: Vec<_> = catalog.difference(&names).collect();
    assert!(
        unrecorded.is_empty(),
        "in the catalog but recorded nowhere: {unrecorded:?}"
    );
}

/// The scanner reads literals and constants, across line breaks, and does
/// not take another function of the crate for a recording.
#[test]
fn the_scanner_reads_literal_and_constant_names() {
    let text = r#"
        const STALL: &str = "kronik_a";
        fn f() {
            kronik_metrics::inc("kronik_b", &[]);
            kronik_metrics::set(
                STALL,
                &[],
                1.0,
            );
            kronik_metrics::observe(
                "kronik_c",
                &[],
                d,
            );
            let _ = kronik_metrics::render();
            kronik_metrics::enum_label("X", "Y");
        }
    "#;
    let (names, unread) = recorded(text);
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        ["kronik_a", "kronik_b", "kronik_c"]
    );
    assert!(unread.is_empty(), "{unread:?}");
    let (_, unread) = recorded("kronik_metrics::inc(name_of(x), &[]);");
    assert_eq!(unread.len(), 1);
}
