//! `kronik restore`: install a data directory from object storage
//! (docs/design/m6-storage.md §6). Offline: it does not talk to a daemon,
//! and it writes no log record itself, so it takes no `--reason`; it leaves
//! a marker from which the next `kronik serve` records an `AuditEvent`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_ship::{Remote, ShipError};
use schemars::JsonSchema;
use serde::Serialize;

use crate::cli::{self, field, next, shell_quote};
use crate::config;

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The bucket: `s3://bucket/prefix` or `file:///path`.
    #[arg(long, value_name = "URL")]
    from: String,
    /// An S3-compatible endpoint, such as `http://127.0.0.1:9000` for MinIO.
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
    /// Data directory to restore into [default: server.data_dir in the
    /// configuration file, else /var/lib/kronik].
    #[arg(long, env = "KRONIK_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// The configuration file [default: /etc/kronik/kronik.toml if it exists].
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    /// The master key file that `kronik serve` will use on this directory
    /// [default: keys.master_key_file in the configuration file, else
    /// <data-dir>/keys/master.key]. It is never in the bucket; restore needs
    /// it to install the privacy keystore backup. `KRONIK_MASTER_KEY`, when
    /// set, is the key itself.
    #[arg(long, value_name = "PATH", env = "KRONIK_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
    /// Restore without the bucket's privacy keystore backup, when the
    /// master key it needs is not available. This drops every subject key:
    /// every sealed value of every subject stays unreadable.
    #[arg(long, conflicts_with = "allow_missing_keys")]
    without_keystore: bool,
    /// Install the bucket's newest keystore backup even when it lacks the
    /// keys of some sealed values (a node lost within a minute of a new
    /// subject's first value). Those subjects' values stay unreadable and
    /// are listed; everyone else's stay readable.
    #[arg(long)]
    allow_missing_keys: bool,
    /// The branch to restore.
    #[arg(long, default_value = "main")]
    branch: String,
    /// Replace an existing state.db. Without this, a directory that already
    /// holds state is refused.
    #[arg(long)]
    force: bool,
    /// Print the plan and write nothing.
    #[arg(long)]
    dry_run: bool,
}

/// What `kronik restore --json` prints.
#[derive(Debug, Serialize, JsonSchema)]
struct RestoreOutput {
    dry_run: bool,
    from: String,
    /// Absent when no endpoint was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    data_dir: String,
    branch: String,
    /// Set after a restore. A dry run does not download, so these are absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_lsn: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    segments: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_first_lsn: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<u64>,
    /// The privacy keystore backup: `installed`, `none_in_bucket`, or
    /// `skipped` (`--without-keystore`). Absent for a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    keystore: Option<String>,
    /// With `--allow-missing-keys`: subjects whose sealed values have no key
    /// and stay unreadable. Absent when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    keys_missing: Vec<String>,
}

#[cfg(test)]
pub fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<RestoreOutput>()
}

pub fn run(args: RestoreArgs, json: bool) -> ExitCode {
    match execute(args) {
        Ok((text, value)) => {
            if json {
                match serde_json::to_string(&value) {
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
                print!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => cli::report_error(json, &e),
    }
}

fn execute(args: RestoreArgs) -> Result<(String, RestoreOutput), ApiError> {
    if args.from.is_empty() {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "--from is empty: give s3://bucket/prefix or file:///path",
        ));
    }
    if args.branch.is_empty() || args.branch.contains('/') || args.branch.contains('\0') {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            format!("--branch {:?} is not a branch name", args.branch),
        ));
    }
    let data =
        config::resolve_data_dir(args.config.as_deref(), args.data_dir.clone()).map_err(|e| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("the configuration file is invalid: {e}"),
            )
            .with_hint("Fix the file, or pass --data-dir <dir>.")
        })?;
    let key_path = master_key_path(args.config.as_deref(), args.master_key_file.clone(), &data)?;
    // The same refusal `restore` makes, before anything is opened, so a dry
    // run and a real run fail the same way and neither writes.
    let state = data.join("branches").join(&args.branch).join("state.db");
    if state.exists() && !args.force {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            format!(
                "{} already holds state; restore into an empty data directory or pass --force",
                data.display()
            ),
        )
        .with_hint(format!(
            "Restore into an empty directory, or replace this one with `kronik restore --from {} --data-dir {} --force`.",
            shell_quote(&args.from),
            shell_quote(&data.display().to_string())
        )));
    }
    let rt = runtime()?;
    let endpoint = args.endpoint.clone();
    let from = args.from.clone();
    let branch = args.branch.clone();
    let force = args.force;
    let dry_run = args.dry_run;
    let mode = if args.without_keystore {
        kronik_ship::KeystoreMode::Without
    } else if args.allow_missing_keys {
        kronik_ship::KeystoreMode::AllowMissingKeys
    } else {
        kronik_ship::KeystoreMode::Require
    };
    let report = rt.block_on(async {
        let remote = Remote::open(&from, endpoint.as_deref()).map_err(ship_error)?;
        if dry_run {
            // Reachable credentials, and nothing written to the data directory.
            // The library has no list API, so the plan cannot name the snapshot.
            remote.check().await.map_err(ship_error)?;
            return Ok(None);
        }
        // The install writes the restore marker before its commit step.
        let report = kronik_ship::restore(&remote, &data, &branch, force, &key_path, mode)
            .await
            .map_err(ship_error)?;
        Ok::<_, ApiError>(Some(report))
    })?;
    let output = RestoreOutput {
        dry_run,
        from: from.clone(),
        endpoint: endpoint.clone(),
        data_dir: data.display().to_string(),
        branch: branch.clone(),
        snapshot_lsn: report.as_ref().map(|r| r.snapshot_lsn),
        snapshot_id: report.as_ref().map(|r| r.snapshot_id.clone()),
        state_hash: report.as_ref().map(|r| r.state_hash.clone()),
        segments: report.as_ref().map(|r| r.segments as u64),
        log_first_lsn: report.as_ref().map(|r| r.log_first_lsn),
        components: report.as_ref().map(|r| r.components as u64),
        keystore: report.as_ref().map(|r| r.keystore.to_owned()),
        keys_missing: report
            .as_ref()
            .map(|r| r.keys_missing.clone())
            .unwrap_or_default(),
    };
    Ok((
        render(&output, &from, endpoint.as_deref(), &data, force),
        output,
    ))
}

fn render(
    o: &RestoreOutput,
    from: &str,
    endpoint: Option<&str>,
    data: &Path,
    force: bool,
) -> String {
    let dir = shell_quote(&data.display().to_string());
    let mut out = String::new();
    if o.dry_run {
        let _ = writeln!(
            out,
            "Dry run: would restore branch {} from {from} into {}",
            o.branch,
            data.display()
        );
        if let Some(endpoint) = endpoint {
            field(&mut out, "Endpoint", &[endpoint.to_owned()], "");
        }
        if force {
            field(
                &mut out,
                "Existing",
                &["state.db would be replaced".to_owned()],
                "",
            );
        }
        let _ = writeln!(
            out,
            "The newest snapshot, its segments and the deployed code would be downloaded and installed. Nothing was written."
        );
        let _ = writeln!(
            out,
            "Restore does not write a log record, so it takes no --reason."
        );
        out.push_str(&next(&[rerun(from, endpoint, &dir, force, false)]));
        return out;
    }
    let _ = writeln!(
        out,
        "Restored snapshot {} at lsn {} into {}",
        o.snapshot_id.as_deref().unwrap_or("?"),
        o.snapshot_lsn.unwrap_or(0),
        data.display()
    );
    field(
        &mut out,
        "State hash",
        &[o.state_hash.clone().unwrap_or_default()],
        "",
    );
    field(
        &mut out,
        "Segments",
        &[o.segments.unwrap_or(0).to_string()],
        "",
    );
    field(
        &mut out,
        "Log first LSN",
        &[o.log_first_lsn.unwrap_or(0).to_string()],
        "",
    );
    field(
        &mut out,
        "Components",
        &[o.components.unwrap_or(0).to_string()],
        "",
    );
    let keystore = match o.keystore.as_deref() {
        Some("installed") => "installed with the master key, which serve will use too".to_owned(),
        Some("skipped") => {
            "not installed (--without-keystore): every sealed value stays unreadable".to_owned()
        }
        _ if !o.keys_missing.is_empty() => "none in the bucket".to_owned(),
        _ => "none in the bucket, and none needed".to_owned(),
    };
    field(&mut out, "Keystore", &[keystore], "");
    if !o.keys_missing.is_empty() {
        field(
            &mut out,
            "Unreadable",
            &[format!(
                "no key for the sealed values of {} (--allow-missing-keys; kronik integrity lists them)",
                o.keys_missing.join(", ")
            )],
            "",
        );
    }
    out.push_str(&next(&[format!("kronik serve --data-dir {dir}")]));
    out
}

fn rerun(from: &str, endpoint: Option<&str>, dir: &str, force: bool, dry_run: bool) -> String {
    let mut cmd = format!(
        "kronik restore --from {} --data-dir {dir}",
        shell_quote(from)
    );
    if let Some(endpoint) = endpoint {
        let _ = write!(cmd, " --endpoint {}", shell_quote(endpoint));
    }
    if force {
        cmd.push_str(" --force");
    }
    if dry_run {
        cmd.push_str(" --dry-run");
    }
    cmd
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime, ApiError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("kronik")
        .build()
        .map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("starting the runtime failed: {e}"),
            )
        })
}

/// The master key file `kronik serve` will use on `data`: `flag`
/// (--master-key-file, KRONIK_MASTER_KEY_FILE), else `[keys]
/// master_key_file` in the configuration file, else
/// `<data>/keys/master.key`. `KRONIK_MASTER_KEY` together with a file is
/// refused, as by serve.
pub(crate) fn master_key_path(
    config: Option<&Path>,
    flag: Option<PathBuf>,
    data: &Path,
) -> Result<PathBuf, ApiError> {
    let configured = match flag {
        Some(path) => Some(path),
        None => config::Config::find(config)
            .ok()
            .and_then(|(c, _)| c.keys.master_key_file),
    };
    if configured.is_some() && std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some() {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "KRONIK_MASTER_KEY and a master key file (--master-key-file, \
             KRONIK_MASTER_KEY_FILE or [keys] master_key_file) are both set",
        )
        .with_hint("Remove one of them, as for `kronik serve`."));
    }
    Ok(configured.unwrap_or_else(|| data.join("keys").join("master.key")))
}

fn ship_error(e: ShipError) -> ApiError {
    match e {
        ShipError::Config(m) => ApiError::new(ErrorCode::BadRequest, format!("ship: {m}")),
        ShipError::Restore(m) if m.contains("already holds state") => {
            ApiError::new(ErrorCode::BadRequest, format!("restore: {m}"))
                .with_hint("Restore into an empty data directory, or pass --force.")
        }
        ShipError::Restore(m) if m.contains("does not match") => {
            ApiError::new(ErrorCode::StorageCorrupt, format!("restore: {m}")).with_hint(
                "The bucket copy does not match its manifest. Do not serve this data directory.",
            )
        }
        ShipError::Restore(m) if m.contains("no snapshot") => {
            ApiError::new(ErrorCode::BadRequest, format!("restore: {m}"))
                .with_hint("Take a snapshot and wait for it to ship, then restore again.")
        }
        ShipError::Restore(m) => ApiError::new(ErrorCode::BadRequest, format!("restore: {m}")),
        ShipError::Store(e) => {
            ApiError::new(ErrorCode::Unavailable, format!("object storage: {e}"))
                .with_hint("Check the URL, the endpoint and the AWS_* credentials.")
        }
        ShipError::Key(e @ kronik_privacy::PrivacyError::KeyMissing(_)) => {
            ApiError::new(ErrorCode::MasterKeyMissing, format!("restore: {e}")).with_hint(
                "The bucket has a privacy keystore backup, which needs the master key. Put the key \
                 where `kronik serve` will look for it (--master-key-file, [keys] master_key_file, \
                 or <data-dir>/keys/master.key), or set KRONIK_MASTER_KEY, and restore again; \
                 --without-keystore restores without it, and sealed values stay unreadable.",
            )
        }
        ShipError::Key(e @ kronik_privacy::PrivacyError::KeyMismatch(_)) => {
            ApiError::new(ErrorCode::MasterKeyMismatch, format!("restore: {e}")).with_hint(
                "Use the key the shipping node ran with, and restore again; nothing was written.",
            )
        }
        ShipError::Key(e) => ApiError::new(ErrorCode::BadRequest, format!("restore: {e}")),
        ShipError::KeystoreIncomplete(m) => ApiError::new(
            ErrorCode::KeystoreIncomplete,
            format!("restore: KEYSTORE_INCOMPLETE: {m}"),
        )
        .with_hint(
            "If the source node still runs, let it ship again (it uploads a keystore backup \
             within a minute of a change) and restore again. If it is gone, \
             --allow-missing-keys installs the backup anyway: only the listed subjects' sealed \
             values stay unreadable. (--without-keystore drops every key.) Nothing was written.",
        ),
        ShipError::Io(e) => ApiError::new(ErrorCode::BadRequest, format!("restore I/O: {e}"))
            .with_hint("Check that the data directory is writable and the bucket is readable."),
    }
}
