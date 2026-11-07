//! What a restore accepts as a name. A bucket does not decide where a file
//! goes: a snapshot manifest lists plain relative paths below the snapshot
//! directory, each once.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use kronik_sched::snapshots::SnapshotFile;

use crate::ShipError;

/// How many characters of a name an error message shows.
const SHOWN: usize = 80;

/// A name from the bucket as an error message shows it: quoted, escaped and
/// cut short.
fn shown(name: &str) -> String {
    let head: String = name.chars().take(SHOWN).collect();
    let cut = if head.len() < name.len() { "..." } else { "" };
    format!("{head:?}{cut}")
}

/// Why `path` is not a plain relative path, or `None` when it is one: not
/// empty, no NUL, no leading `/`, and every part between slashes is a normal
/// name (not empty, `.` or `..`).
fn path_fault(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("empty");
    }
    if path.contains('\0') {
        return Some("contains a NUL byte");
    }
    if path.starts_with('/') {
        return Some("absolute");
    }
    for part in path.split('/') {
        match part {
            "" => return Some("has an empty part"),
            "." | ".." => return Some("has a . or .. part"),
            _ => {}
        }
    }
    // The standard library must read the same parts.
    if Path::new(path)
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        None
    } else {
        Some("is not made of plain names")
    }
}

/// Where the files of a manifest go below `dir`, in the manifest's order.
///
/// Refuses the whole manifest unless every path is a plain relative path,
/// each is listed once, none is also a directory of another, and none is
/// `manifest.json`, which the restore writes itself. A path that passes is
/// its own normal form, so comparing the strings compares the files.
pub(crate) fn snapshot_destinations(
    dir: &Path,
    files: &[SnapshotFile],
) -> Result<Vec<PathBuf>, ShipError> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(files.len());
    let mut destinations = Vec::with_capacity(files.len());
    for file in files {
        let path = file.path.as_str();
        let fault = path_fault(path).or((path == "manifest.json").then_some("reserved"));
        if let Some(fault) = fault {
            return Err(ShipError::Restore(format!(
                "the snapshot manifest names a file {} that is not a plain relative path ({fault})",
                shown(path)
            )));
        }
        if !seen.insert(path) {
            return Err(ShipError::Restore(format!(
                "the snapshot manifest names the file {} more than once",
                shown(path)
            )));
        }
        let destination = dir.join(path);
        if !destination.starts_with(dir) {
            return Err(ShipError::Restore(format!(
                "the snapshot manifest names a file {} outside the snapshot directory",
                shown(path)
            )));
        }
        destinations.push(destination);
    }
    for file in files {
        for (slash, _) in file.path.match_indices('/') {
            if let Some(parent) = file.path.get(..slash)
                && seen.contains(parent)
            {
                return Err(ShipError::Restore(format!(
                    "the snapshot manifest names {} both as a file and as a directory",
                    shown(parent)
                )));
            }
        }
    }
    Ok(destinations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> SnapshotFile {
        SnapshotFile {
            path: path.into(),
            size: 0,
            blake3: String::new(),
        }
    }

    fn files(paths: &[&str]) -> Vec<SnapshotFile> {
        paths.iter().map(|p| file(p)).collect()
    }

    fn refused(paths: &[&str]) -> String {
        match snapshot_destinations(Path::new("/stage/snapshot"), &files(paths)) {
            Err(ShipError::Restore(message)) => message,
            other => panic!("{paths:?} was not refused: {other:?}"),
        }
    }

    #[test]
    fn the_paths_a_node_writes_are_accepted_in_order() {
        let dir = Path::new("/stage/snapshot");
        let paths = [
            "state.db",
            "secrets.db",
            "sql/ab/notes~n0-0123abcd.db",
            "sql/cd/counter-c1-89abcdef.db",
        ];
        let destinations = snapshot_destinations(dir, &files(&paths)).unwrap();
        let want: Vec<PathBuf> = paths.iter().map(|p| dir.join(p)).collect();
        assert_eq!(destinations, want);
        assert!(snapshot_destinations(dir, &[]).unwrap().is_empty());
        // Names that are only unusual are not refused.
        for odd in [
            "a b.db",
            "sql/ü/ñ.db",
            "x..y",
            "sql/..db",
            "a.b/c",
            "-x",
            "~",
        ] {
            snapshot_destinations(dir, &files(&[odd])).unwrap();
        }
    }

    #[test]
    fn a_path_that_is_not_a_plain_relative_path_is_refused() {
        for (bad, reason) in [
            ("", "empty"),
            ("/", "absolute"),
            ("/etc/passwd", "absolute"),
            ("//x", "absolute"),
            ("/a/", "absolute"),
            ("..", "has a . or .. part"),
            (".", "has a . or .. part"),
            ("../x", "has a . or .. part"),
            ("a/..", "has a . or .. part"),
            ("a/../b", "has a . or .. part"),
            ("../../../x", "has a . or .. part"),
            ("sql/../../x", "has a . or .. part"),
            ("./x", "has a . or .. part"),
            ("a/./b", "has a . or .. part"),
            ("a/.", "has a . or .. part"),
            ("a//b", "has an empty part"),
            ("a/", "has an empty part"),
            ("x\0y", "contains a NUL byte"),
            ("manifest.json", "reserved"),
        ] {
            let message = refused(&[bad]);
            assert!(
                message.ends_with(&format!("is not a plain relative path ({reason})")),
                "{bad:?}: {message}"
            );
        }
        // One bad path refuses the whole manifest, wherever it is.
        refused(&["state.db", "../x", "secrets.db"]);
        refused(&["../x", "state.db"]);
    }

    #[test]
    fn a_file_listed_twice_or_used_as_a_directory_is_refused() {
        assert!(refused(&["state.db", "secrets.db", "state.db"]).contains("more than once"));
        assert!(refused(&["sql", "sql/ab/x.db"]).contains("file and as a directory"));
        assert!(refused(&["sql/ab/x.db", "sql"]).contains("file and as a directory"));
        assert!(refused(&["sql/ab", "sql/ab/x.db"]).contains("file and as a directory"));
        // Siblings and prefixes of a name that are not a directory part are fine.
        let dir = Path::new("/stage/snapshot");
        snapshot_destinations(dir, &files(&["sql", "sql2/x.db", "sql.db"])).unwrap();
    }

    #[test]
    fn an_error_shows_a_name_quoted_and_cut() {
        let escaped = shown("\u{1b}[2J\n..");
        assert!(
            !escaped.contains('\u{1b}') && !escaped.contains('\n'),
            "{escaped:?}"
        );
        assert!(escaped.starts_with('"'), "{escaped}");
        let long = format!("../{}", "x".repeat(500));
        let message = refused(&[&long]);
        assert!(message.len() < 300, "{message}");
        assert!(message.contains("..."), "{message}");
    }
}
