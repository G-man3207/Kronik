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
use crate::config;

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
    /// `ENGINE_UPGRADE_DIVERGED` when the diff is not empty.
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
}

pub fn check(args: CheckArgs, json: bool) -> ExitCode {
    match execute(args) {
        Ok(done) => {
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
    let data =
        config::resolve_data_dir(args.config.as_deref(), args.data_dir.clone()).map_err(|e| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("the configuration file is invalid: {e}"),
            )
            .with_hint("Fix the file, or pass --data-dir <dir>.")
        })?;
    let workers = args
        .workers
        .map(usize::from)
        .unwrap_or_else(default_workers);
    // Sealed values in the window open as they do for the daemon.
    let key_path = crate::restore::master_key_path(
        args.config.as_deref(),
        args.master_key_file.clone(),
        &data,
    )?;
    let sealer = kronik_sched::offline_sealer(&data, &key_path).map_err(key_error)?;
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
    let checked = rt
        .block_on(async {
            let env = Env::real(tokio::runtime::Handle::current());
            kronik_fork::upgrade::check(
                &env,
                &data,
                Duration::from_millis(window_ms),
                workers,
                sealer,
            )
            .await
        })
        .map_err(check_error)?;

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
    let text = render(&value, &data, &args.window);
    Ok(Done { text, value, error })
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
            "identity replay of the last {window} is not empty ({} root inputs, diff {})",
            v.root_inputs, v.diff_hash
        ),
    )
    .with_hint(format!(
        "Keep the current binary.{where_} Report the diff with both engine versions."
    ))
}

fn render(v: &UpgradeCheckOutput, data: &Path, window: &str) -> String {
    let mut out = String::new();
    let verb = if v.passed { "passed" } else { "diverged" };
    let dry = if v.dry_run { "Dry run: " } else { "" };
    let _ = writeln!(
        out,
        "{dry}Upgrade check {verb}: {} -> {}, window {window}, fork lsn {} through {}",
        v.from_engine, v.to_engine, v.fork_lsn, v.checked_through_lsn
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
    let next_cmd = if v.passed && !v.dry_run {
        format!("kronik serve --data-dir {dir}")
    } else if v.dry_run {
        format!("kronik upgrade check --window {window} --data-dir {dir}")
    } else {
        "kronik explain ENGINE_UPGRADE_DIVERGED".to_owned()
    };
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

/// The master key or the privacy keystore could not be opened.
fn key_error(e: kronik_privacy::PrivacyError) -> ApiError {
    let hint = "Use the master key `kronik serve` uses on this directory: --master-key-file, \
                [keys] master_key_file with --config, <data-dir>/keys/master.key, or \
                KRONIK_MASTER_KEY.";
    match e {
        kronik_privacy::PrivacyError::KeyMissing(_) => {
            ApiError::new(ErrorCode::MasterKeyMissing, format!("upgrade check: {e}"))
                .with_hint(hint)
        }
        kronik_privacy::PrivacyError::KeyMismatch(_) => {
            ApiError::new(ErrorCode::MasterKeyMismatch, format!("upgrade check: {e}"))
                .with_hint(hint)
        }
        e => ApiError::new(ErrorCode::StorageCorrupt, format!("upgrade check: {e}")),
    }
}
