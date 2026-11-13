//! Engine upgrades (docs/design/m6-storage.md §7): the report `kronik
//! upgrade check` writes, and the startup gate that turns a passing report
//! into an `EngineUpgrade` record.

use std::path::{Path, PathBuf};

use kronik_core::ids::Lsn;
use kronik_proto::log::v1 as pb;
use serde::{Deserialize, Serialize};

pub const REPORT_SCHEMA: &str = "kronik.upgrade-check/v1";

/// `DIR/upgrade/<to_engine>.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpgradeReport {
    pub schema: String,
    pub from_engine: String,
    pub to_engine: String,
    /// The window asked for, in milliseconds of logical time.
    pub window_ms: u64,
    pub fork_lsn: Lsn,
    pub checked_through_lsn: Lsn,
    pub root_inputs: u64,
    pub turns: u64,
    /// The identity replay's diff (`b3:<hex>`).
    pub diff_hash: String,
    /// Turns the diff could not verify because they met erased data: their
    /// recorded input, a state value they read, or an input or state that
    /// erased data shaped, and production turns missing below one (S-16,
    /// ADR 0109). They do not make `passed` false: the recorded outcome is
    /// the only truth there is, and the replay served it.
    #[serde(default)]
    pub unverifiable: u64,
    /// The diff found no verified difference.
    pub passed: bool,
    pub checked_wall_ms: u64,
}

impl UpgradeReport {
    pub fn path(data: &Path, to_engine: &str) -> PathBuf {
        data.join("upgrade").join(format!("{to_engine}.json"))
    }

    /// `upgrade/<to_engine>.json`: where [`UpgradeReport::path`] puts the
    /// report, relative to the data directory. This is the form the log may
    /// name it in: the log is append-only and exported, so it never carries
    /// the path of the machine it was written on.
    pub fn relative_path(to_engine: &str) -> String {
        format!("upgrade/{to_engine}.json")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).unwrap_or_default();
        v.push(b'\n');
        v
    }

    /// Writes the report (and, for a failing check, nothing else: the
    /// caller writes the diff next to it).
    pub fn write(&self, data: &Path) -> std::io::Result<PathBuf> {
        let path = Self::path(data, &self.to_engine);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, self.to_bytes())?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }
}

/// What startup does about the engine version that last wrote the data.
pub(crate) enum Gate {
    /// The same engine (or a fresh data directory).
    Same,
    /// A different engine with a passing report: append this record.
    Upgrade(pb::EngineUpgrade),
    /// A different engine without one: refuse to start.
    Refuse(String),
}

/// `recorded` is the engine version of the newest turn (or upgrade) in
/// the state; `running` this binary's.
pub(crate) fn gate(
    data: &Path,
    recorded: Option<&str>,
    running: &str,
    epoch: u64,
    wall_ms: u64,
) -> Gate {
    let Some(from) = recorded.filter(|r| *r != running) else {
        return Gate::Same;
    };
    let command = format!(
        "kronik upgrade check --window 6h --data-dir {}",
        data.display()
    );
    let path = UpgradeReport::path(data, running);
    let Ok(bytes) = std::fs::read(&path) else {
        return Gate::Refuse(format!(
            "the data was last written by engine {from} and this binary is {running}; \
             check the upgrade first with this binary: {command}"
        ));
    };
    let report = match serde_json::from_slice::<UpgradeReport>(&bytes) {
        Ok(r) => r,
        Err(e) => return Gate::Refuse(format!("{}: {e}; run {command} again", path.display())),
    };
    if report.schema != REPORT_SCHEMA || report.from_engine != from || report.to_engine != running {
        return Gate::Refuse(format!(
            "{} checks {} -> {}, but the data is at {from}; run {command} again",
            path.display(),
            report.from_engine,
            report.to_engine
        ));
    }
    if !report.passed {
        return Gate::Refuse(format!(
            "{} records a diverging identity replay (diff {}); the upgrade is not safe. \
             A turn that met erased data is unverifiable, not divergent, as of v0.5.0: run the \
             check again with this binary and read its count. If this report is from a v0.4.1 or \
             older binary it may name only the erasure; then make one new turn and run the \
             check with a window shorter than the time since the erasure - the check forks \
             from the root inputs, not from snapshots, so an erased request is replayed \
             again unless newer input and a shorter window put it behind the fork",
            path.display(),
            report.diff_hash
        ));
    }
    Gate::Upgrade(pb::EngineUpgrade {
        epoch,
        from_engine_version: from.to_owned(),
        to_engine_version: running.to_owned(),
        effective_lsn: 0,
        check_report_hash: blake3::hash(&bytes).as_bytes().to_vec(),
        checked_through_lsn: report.checked_through_lsn,
        audit: Some(pb::Audit {
            token_id: "system".into(),
            // Named relative to the data directory, not by `path`: that is
            // an absolute path of this machine, and this text is kept in
            // the log and in every audit export. The record's own
            // `check_report_hash` identifies the report's content.
            reason: format!(
                "engine upgrade checked by the upgrade report {}",
                UpgradeReport::relative_path(running)
            ),
            wall_time_ms: wall_ms,
        }),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn report(from: &str, to: &str, passed: bool) -> UpgradeReport {
        UpgradeReport {
            schema: REPORT_SCHEMA.into(),
            from_engine: from.into(),
            to_engine: to.into(),
            window_ms: 6 * 3_600_000,
            fork_lsn: 10,
            checked_through_lsn: 99,
            root_inputs: 5,
            turns: 7,
            diff_hash: "b3:00".into(),
            unverifiable: 0,
            passed,
            checked_wall_ms: 1,
        }
    }

    #[test]
    fn the_gate_needs_a_passing_report_for_exactly_the_pair() {
        // Unit tests have no CARGO_TARGET_TMPDIR: the workspace's target/.
        let tmp = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let dir = tempfile::Builder::new().tempdir_in(tmp).unwrap();
        let d = dir.path();
        assert!(matches!(gate(d, None, "new", 1, 0), Gate::Same));
        assert!(matches!(gate(d, Some("new"), "new", 1, 0), Gate::Same));
        let Gate::Refuse(m) = gate(d, Some("old"), "new", 1, 0) else {
            panic!()
        };
        assert!(m.contains("kronik upgrade check --window 6h"), "{m}");
        report("other", "new", true).write(d).unwrap();
        assert!(matches!(gate(d, Some("old"), "new", 1, 0), Gate::Refuse(_)));
        report("old", "new", false).write(d).unwrap();
        let Gate::Refuse(m) = gate(d, Some("old"), "new", 1, 0) else {
            panic!()
        };
        assert!(m.contains("not safe"), "{m}");
        let path = report("old", "new", true).write(d).unwrap();
        let Gate::Upgrade(u) = gate(d, Some("old"), "new", 3, 0) else {
            panic!()
        };
        assert_eq!((u.epoch, u.checked_through_lsn), (3, 99));
        assert_eq!(
            u.check_report_hash,
            blake3::hash(&std::fs::read(path).unwrap())
                .as_bytes()
                .to_vec()
        );
    }

    #[test]
    fn the_upgrade_record_names_the_report_relative_to_the_data_directory() {
        let tmp = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        let dir = tempfile::Builder::new().tempdir_in(tmp).unwrap();
        let d = dir.path();
        let path = report("old", "kronik-9.9.9+wasmtime-1.0.0", true)
            .write(d)
            .unwrap();
        let Gate::Upgrade(u) = gate(d, Some("old"), "kronik-9.9.9+wasmtime-1.0.0", 3, 0) else {
            panic!()
        };
        let reason = u.audit.unwrap().reason;
        // The log keeps this text for good and exports it: no local path.
        assert_eq!(
            reason,
            "engine upgrade checked by the upgrade report \
             upgrade/kronik-9.9.9+wasmtime-1.0.0.json"
        );
        assert!(!reason.contains(d.to_str().unwrap()), "{reason}");
        assert!(
            !reason
                .split_whitespace()
                .any(|word| Path::new(word).is_absolute()),
            "{reason}"
        );
        // The name is the report's place under the data directory.
        assert_eq!(
            path.strip_prefix(d).unwrap(),
            Path::new(&UpgradeReport::relative_path("kronik-9.9.9+wasmtime-1.0.0"))
        );
    }
}
