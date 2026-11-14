//! `kronik upgrade check`: an identity replay of recent history with this
//! binary, before it replaces the one that is running (docs/design/m6-storage.md
//! §7). Offline and read-only apart from the report it writes. It takes no
//! `--reason`: it does not write a log record.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use kronik_core::env::Env;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::upgrade::UpgradeReport;
use schemars::JsonSchema;
use serde::Serialize;

use crate::cli::{self, field, next, shell_quote};

#[derive(Debug, clap::Subcommand)]
pub enum UpgradeCommand {
    /// Replay recent history with this binary and refuse a behavior change.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// How far back to replay, of logical time.
    #[arg(long, default_value = "6h", value_name = "DURATION")]
    window: String,
    /// Data directory to read [default: server.data_dir in the configuration
    /// file, else /var/lib/kronik].
    #[arg(long, env = "KRONIK_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// The configuration file [default: /etc/kronik/kronik.toml if it exists].
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    /// The master key file `kronik serve` uses on this directory [default:
    /// keys.master_key_file in the configuration file, else
    /// <data-dir>/keys/master.key]. The check opens sealed values with it
    /// and the privacy keystore. `KRONIK_MASTER_KEY`, when set, is the key
    /// itself.
    #[arg(long, value_name = "PATH", env = "KRONIK_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
    /// Replay workers [default: the machine's cores, at most 16].
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    workers: Option<u16>,
    /// Run the check and print the result; write neither the report nor the diff.
    #[arg(long)]
    dry_run: bool,
}

/// What `kronik upgrade check --json` prints: the report, plus the diff
/// path when one was written. `code` is set when the process exits 1.
#[derive(Debug, Serialize, JsonSchema)]
struct UpgradeCheckOutput {
    schema: String,
    from_engine: String,
    to_engine: String,
    window_ms: u64,
    fork_lsn: u64,
    checked_through_lsn: u64,
    root_inputs: u64,
    turns: u64,
    /// Turns the identity replay could not verify because they met erased
    /// data: their recorded input, a state value they read, or an input or
    /// state that erased data shaped, and production turns missing below one
    /// (S-16, ADR 0109). Always present (0 when none): a passing check did
    /// not verify these turns.
    #[serde(default)]
    unverifiable: u64,
    diff_hash: String,
    passed: bool,
    checked_wall_ms: u64,
    dry_run: bool,
    /// Set when the report file was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    report_path: Option<String>,
    /// Set when a diverging diff was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_path: Option<String>,
    /// `ENGINE_UPGRADE_DIVERGED` when a verified difference remains.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

#[cfg(test)]
pub fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<UpgradeCheckOutput>()
}

struct Done {
    text: String,
    value: UpgradeCheckOutput,
    error: Option<ApiError>,
    /// For stderr, whatever the output format: what the first start will do.
    note: Option<String>,
}

pub fn check(args: CheckArgs, json: bool) -> ExitCode {
    match execute(args) {
        Ok(done) => {
            if let Some(note) = &done.note {
                eprintln!("{note}");
            }
            if json {
                match serde_json::to_string(&done.value) {
                    Ok(body) => println!("{body}"),
                    Err(e) => {
                        return cli::report_error(
                            true,
                            &ApiError::new(
                                ErrorCode::Internal,
                                format!("encoding JSON failed: {e}"),
                            ),
                        );
                    }
                }
            } else {
                print!("{}", done.text);
            }
            match done.error {
                Some(e) if !json => cli::report_error(false, &e),
                Some(_) => ExitCode::FAILURE,
                None => ExitCode::SUCCESS,
            }
        }
        Err(e) => cli::report_error(json, &e),
    }
}

fn execute(args: CheckArgs) -> Result<Done, ApiError> {
    let window_ms = crate::cli::parse_duration_ms(&args.window).map_err(|m| {
        ApiError::new(ErrorCode::BadRequest, format!("--window: {m}"))
            .with_hint("Give a duration with ms, s, m or h, e.g. 6h.")
    })?;
    let (configuration, selected_config) =
        crate::restore::key_config(args.config.as_deref(), args.master_key_file.clone())?;
    let data = args
        .data_dir
        .clone()
        .unwrap_or(configuration.server.data_dir);
    // The start refuses a data directory whose databases the log no longer
    // reaches, unless a snapshot repairs it: ask the question the start asks
    // (read-only, the old daemon may still run), so that the operator learns
    // before the restart and not at it.
    let plan = kronik_sched::snapshots::plan_state(&data, "main", true)
        .map_err(|text| ApiError::new(ErrorCode::StorageCorrupt, text))?;
    let note = state_note(&plan);
    let workers = args
        .workers
        .map(usize::from)
        .unwrap_or_else(default_workers);
    // Sealed values in the window open as they do for the daemon.
    let keys = configuration.keys;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kronik")
        .build()
        .map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("starting the runtime failed: {e}"),
            )
        })?;
    let checked = rt.block_on(async {
        let env = Env::real(tokio::runtime::Handle::current());
        let sealer = kronik_sched::offline_sealer(env.clone(), &data, keys)
            .await
            .map_err(|e| e.api_error())?;
        kronik_fork::upgrade::check(
            &env,
            &data,
            Duration::from_millis(window_ms),
            workers,
            sealer,
        )
        .await
        .map_err(check_error)
    })?;

    let report_file = UpgradeReport::path(&data, &checked.report.to_engine);
    let diff_file = report_file.with_extension("diff.json");
    let (report_path, diff_path) = if args.dry_run {
        (None, None)
    } else {
        checked.report.write(&data).map_err(|e| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("could not write the upgrade report: {e}"),
            )
            .with_hint(format!("Check that {} is writable.", data.display()))
        })?;
        if checked.report.passed {
            let _ = std::fs::remove_file(&diff_file);
            (Some(report_file.display().to_string()), None)
        } else {
            write_diff(&diff_file, &checked.diff_bytes).map_err(|e| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("could not write the diff: {e}"),
                )
            })?;
            (
                Some(report_file.display().to_string()),
                Some(diff_file.display().to_string()),
            )
        }
    };

    let value = UpgradeCheckOutput {
        schema: checked.report.schema.clone(),
        from_engine: checked.report.from_engine.clone(),
        to_engine: checked.report.to_engine.clone(),
        window_ms: checked.report.window_ms,
        fork_lsn: checked.report.fork_lsn,
        checked_through_lsn: checked.report.checked_through_lsn,
        root_inputs: checked.report.root_inputs,
        turns: checked.report.turns,
        unverifiable: checked.report.unverifiable,
        diff_hash: checked.report.diff_hash.clone(),
        passed: checked.report.passed,
        checked_wall_ms: checked.report.checked_wall_ms,
        dry_run: args.dry_run,
        report_path: report_path.clone(),
        diff_path: diff_path.clone(),
        code: (!checked.report.passed)
            .then(|| ErrorCode::EngineUpgradeDiverged.as_str().to_owned()),
    };
    let error = (!checked.report.passed).then(|| diverge_error(&value, &args.window));
    let text = render(&value, &args, &data, selected_config.as_deref());
    Ok(Done {
        text,
        value,
        error,
        note,
    })
}

/// What the first start does with the databases, when it is not nothing.
fn state_note(plan: &kronik_sched::snapshots::StatePlan) -> Option<String> {
    let mut parts = Vec::new();
    if let Some((_, manifest)) = &plan.install {
        let at = plan
            .state
            .map(|(state, lowest)| {
                format!(" (state at lsn {state}, an actor database at {lowest})")
            })
            .unwrap_or_default();
        parts.push(format!(
            "note: the first start installs the snapshot at lsn {} because the databases are \
             older than the log retention kept{at}; kronik explain STORAGE_CORRUPT",
            manifest.lsn
        ));
    }
    // A database that could not be read is an error from `plan_state`, not a
    // note on a passing check: ignoring it would report a pass the start may
    // refuse.
    (!parts.is_empty()).then(|| parts.join("\n"))
}

/// The report's count of turns an identity replay could not verify because
/// they met erased data (S-16, ADR 0109), shown right under the verdict
/// whatever it is: a passing check did not verify these turns.
fn unverifiable_text(turns: u64) -> String {
    match turns {
        0 => "0 turns (none met erased data)".to_owned(),
        1 => "1 turn met erased data and was not verified".to_owned(),
        n => format!("{n} turns met erased data and were not verified"),
    }
}

fn diverge_error(v: &UpgradeCheckOutput, window: &str) -> ApiError {
    let where_ = v
        .diff_path
        .as_deref()
        .map(|p| format!(" The diff is {p}."))
        .unwrap_or_else(|| " Re-run without --dry-run to write the diff.".to_owned());
    ApiError::new(
        ErrorCode::EngineUpgradeDiverged,
        format!(
            "identity replay of the last {window} has a verified difference ({} root inputs, \
             diff {})",
            v.root_inputs, v.diff_hash
        ),
    )
    .with_hint(format!(
        "Keep the current binary.{where_} Report the diff with both engine versions. \
         Turns that met erased data are unverifiable, not divergent, as of v0.5.0 (the \
         report counts them in `unverifiable`), so this diff records a real difference in \
         verified behaviour - or a recording that could not be read. The fork point \
         comes from the root inputs, not from snapshots."
    ))
}

fn render(
    v: &UpgradeCheckOutput,
    args: &CheckArgs,
    data: &Path,
    config_path: Option<&Path>,
) -> String {
    let window = &args.window;
    let mut out = String::new();
    let verb = if v.passed { "passed" } else { "diverged" };
    let dry = if v.dry_run { "Dry run: " } else { "" };
    let _ = writeln!(
        out,
        "{dry}Upgrade check {verb}: {} -> {}, window {window}, fork lsn {} through {}",
        v.from_engine, v.to_engine, v.fork_lsn, v.checked_through_lsn
    );
    field(
        &mut out,
        "Unverifiable",
        &[unverifiable_text(v.unverifiable)],
        "",
    );
    field(&mut out, "Root inputs", &[v.root_inputs.to_string()], "");
    field(&mut out, "Turns", &[v.turns.to_string()], "");
    field(&mut out, "Diff", std::slice::from_ref(&v.diff_hash), "");
    if let Some(path) = &v.report_path {
        field(&mut out, "Report", std::slice::from_ref(path), "");
    }
    if let Some(path) = &v.diff_path {
        field(&mut out, "Diff file", std::slice::from_ref(path), "");
    }
    if v.dry_run {
        let _ = writeln!(out, "Nothing was written.");
    }
    let dir = shell_quote(&data.display().to_string());
    let mut next_cmd = if v.passed && !v.dry_run {
        format!("kronik serve --data-dir {dir}")
    } else if v.dry_run {
        format!(
            "kronik upgrade check --window {} --data-dir {dir}",
            shell_quote(window)
        )
    } else {
        "kronik explain ENGINE_UPGRADE_DIVERGED".to_owned()
    };
    if v.passed || v.dry_run {
        if let Some(path) = config_path {
            let _ = write!(
                next_cmd,
                " --config {}",
                shell_quote(&path.display().to_string())
            );
        }
        if let Some(path) = &args.master_key_file {
            let _ = write!(
                next_cmd,
                " --master-key-file {}",
                shell_quote(&path.display().to_string())
            );
        }
    }
    out.push_str(&next(&[next_cmd]));
    out
}

fn write_diff(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .clamp(1, 16)
}

fn check_error(msg: String) -> ApiError {
    if msg.contains("holds no log") {
        ApiError::new(ErrorCode::BadRequest, msg).with_hint(
            "Point --data-dir at a data directory that has served, or start one with `kronik serve --data-dir <dir>`.",
        )
    } else if let Some(i) = msg.find("SUBJECT_ERASED: ") {
        ApiError::new(ErrorCode::SubjectErased, msg[i..].to_owned()).with_hint(
            "A sealed value of an erased subject reached a replayed turn; erased values cannot \
             be read again.",
        )
    } else if let Some(i) = msg.find("KEYSTORE_INCOMPLETE: ") {
        ApiError::new(ErrorCode::KeystoreIncomplete, msg[i..].to_owned()).with_hint(
            "The privacy keystore lacks a subject's key; `kronik integrity` lists the subjects.",
        )
    } else if msg.to_ascii_lowercase().contains("corrupt") {
        ApiError::new(ErrorCode::StorageCorrupt, msg)
    } else {
        ApiError::new(ErrorCode::Internal, msg)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{check_error, unverifiable_text};
    use kronik_core::error::ErrorCode;

    /// A replay that meets a sealed value of an erased subject says so: the
    /// key is not missing from the keystore, the subject was erased.
    #[test]
    fn a_replays_erased_value_is_subject_erased_not_a_missing_key() {
        let erased = check_error(
            "replay failed: SUBJECT_ERASED: a sealed value of an erased subject reached a fork \
             turn"
                .into(),
        );
        assert_eq!(erased.code, ErrorCode::SubjectErased);
        assert!(!erased.message.contains("keystore"), "{}", erased.message);
        let missing = check_error(
            "replay failed: KEYSTORE_INCOMPLETE: a sealed value of subject user:1 cannot be \
             opened: its key is not in this node's privacy keystore"
                .into(),
        );
        assert_eq!(missing.code, ErrorCode::KeystoreIncomplete);
    }

    /// The count is always shown, also when it is 0: a passing check did not
    /// verify the turns it counts (ADR 0109 point 5).
    #[test]
    fn the_unverifiable_count_is_always_shown() {
        assert_eq!(unverifiable_text(0), "0 turns (none met erased data)");
        assert_eq!(
            unverifiable_text(1),
            "1 turn met erased data and was not verified"
        );
        assert_eq!(
            unverifiable_text(7),
            "7 turns met erased data and were not verified"
        );
        let mut out = String::new();
        crate::cli::field(&mut out, "Unverifiable", &[unverifiable_text(7)], "");
        assert_eq!(
            out,
            "  Unverifiable  7 turns met erased data and were not verified\n"
        );
    }
}
