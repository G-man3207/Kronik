//! `kronik restore`: install a data directory from object storage
//! (docs/design/m6-storage.md §6). Offline: it does not talk to a daemon,
//! and it writes no log record itself, so it takes no `--reason`; it leaves
//! a marker from which the next `kronik serve` records an `AuditEvent`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_ship::{Remote, RemoteCredentials, ShipError};
use schemars::JsonSchema;
use serde::Serialize;

use crate::cli::{self, field, next, shell_quote};
use crate::config;

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The bucket: `s3://bucket/prefix` or `file:///path`.
    #[arg(long, value_name = "URL")]
    from: String,
    /// An S3-compatible endpoint, such as `http://127.0.0.1:9000` for a
    /// self-hosted server.
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
    let (configuration, selected_config) =
        key_config(args.config.as_deref(), args.master_key_file.clone())?;
    let data = args
        .data_dir
        .clone()
        .unwrap_or(configuration.server.data_dir);
    let keys = configuration.keys;
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
            "Restore into an empty directory, or replace this one with `{}`.",
            rerun(&args, selected_config.as_deref(), &data, true)
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
    let destination = crate::cli::userns::data_dir_owner(&data)?;
    let report = if let Some((uid, gid)) = destination.filter(|_| !dry_run) {
        // The runtime that was made above is not used: the steps below make
        // and drop their own, on either side of the drop of privileges.
        drop(rt);
        let job = Job {
            from: &from,
            endpoint: endpoint.as_deref(),
            data: &data,
            branch: &branch,
            force,
            mode,
            keys: &keys,
        };
        let mut hooks = Hooks {
            drop_to: &crate::cli::userns::become_owner,
            seen: &mut |_| {},
            credentials: &remotes_credentials,
            threads: &process_threads,
            single: 1,
            thread_name: "kronik",
        };
        Some(restore_dropping(&job, (uid, gid), &mut hooks)?)
    } else {
        rt.block_on(async {
            let remote = Remote::open(&from, endpoint.as_deref()).map_err(ship_error)?;
            if dry_run {
                remote.check().await.map_err(ship_error)?;
                return Ok(None);
            }
            let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
            let report = kronik_ship::restore(&remote, &data, &branch, force, &env, &keys, mode)
                .await
                .map_err(ship_error)?;
            Ok::<_, ApiError>(Some(report))
        })?
    };
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
        render(&output, &args, &data, selected_config.as_deref()),
        output,
    ))
}

/// What a restore needs to know, apart from the process it runs in.
struct Job<'a> {
    from: &'a str,
    endpoint: Option<&'a str>,
    data: &'a Path,
    branch: &'a str,
    force: bool,
    mode: kronik_ship::KeystoreMode,
    keys: &'a kronik_privacy::key_source::Keys,
}

/// The steps of [`restore_dropping`], in the order they happen. The tests pin
/// that order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// The data directory is locked, and its owner read from what is locked.
    Locked,
    /// The remote's credentials are read, once, while the process may.
    CredentialsResolved,
    /// The key (and the destination's envelope, for a KMS source) is loaded, the
    /// keystore backup decrypted: everything that needs root. Nothing is written.
    RootPhase,
    /// The runtime, its threads and the remote of the root phase are gone.
    RuntimeJoined,
    /// Root is given up for good.
    Dropped,
    /// A new runtime, and the remote again, with the credentials of before.
    Reopened,
    /// The data directory's owner has downloaded, checked and installed.
    Installed,
}

/// The parts of [`restore_dropping`] that a test replaces. The drop itself
/// cannot be rehearsed in a test process, nor can a process with one thread;
/// what is checked there is the order, and the real drop is the subject of
/// `tests/restore_drop.rs`.
struct Hooks<'a> {
    /// Gives up root: `userns::become_owner`.
    drop_to: &'a dyn Fn(u32, u32) -> Result<(), ApiError>,
    /// A witness of the steps.
    seen: &'a mut dyn FnMut(Step),
    /// Reads the credentials of the remote while the process may.
    credentials:
        &'a dyn Fn(&tokio::runtime::Runtime, &Job<'_>) -> Result<RemoteCredentials, ApiError>,
    /// How many threads the process has once the runtime is gone, and how many
    /// it may have for the drop (one: the thread that drops).
    threads: &'a dyn Fn() -> Result<u64, ApiError>,
    single: u64,
    /// What the threads of the runtimes are called: `kronik`. A test that
    /// counts them gives its restore a name of its own, because a test process
    /// runs other tests side by side.
    thread_name: &'a str,
}

/// The names of the threads of this process, for the message that says there
/// are too many.
fn thread_names() -> Vec<String> {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    tasks
        .flatten()
        .map(|task| {
            std::fs::read_to_string(task.path().join("comm"))
                .map(|name| name.trim().to_owned())
                .unwrap_or_else(|_| "?".into())
        })
        .collect()
}

/// The credentials of the remote of the job, from its own provider: the
/// environment, a token file, the metadata of an instance or a pod. An `s3://`
/// remote needs them for every request, and the process cannot read most of
/// their sources once it has given up root.
fn remotes_credentials(
    runtime: &tokio::runtime::Runtime,
    job: &Job<'_>,
) -> Result<RemoteCredentials, ApiError> {
    runtime.block_on(async {
        Remote::open(job.from, job.endpoint)
            .map_err(ship_error)?
            .resolve_credentials()
            .await
            .map_err(ship_error)
    })
}

/// The number of threads of this process, once a runtime that was just dropped
/// has left the kernel's count.
fn process_threads() -> Result<u64, ApiError> {
    kronik_foreign::sys::threads_settled(1).map_err(|e| {
        ApiError::new(
            ErrorCode::Internal,
            format!("counting the threads of the process: {e}"),
        )
    })
}

/// A restore into a data directory that another user owns, as root.
///
/// The order is the whole point, and each step is a line below:
///
/// 1. lock the data directory, and take the owner from the locked
///    descriptor, not from a path;
/// 2. read the remote's credentials (a token file only root may read, an
///    instance's or a pod's endpoint) into memory;
/// 3. do everything that needs root: load the key, unwrap the envelopes of a
///    KMS source (the bucket's and the destination's), decrypt the keystore
///    backup. Nothing is written, and the data directory's stores are not read;
/// 4. drop the runtime, and with it every thread that might hold root;
/// 5. give up root for good (one thread, no supplementary group, no core
///    dump, no capability);
/// 6. open a new runtime and the remote again, signing with the credentials of
///    step 2 and reading no file;
/// 7. as the owner: check the stores against the key, download into
///    `.restore` inside the data directory, import the keystore and move it
///    all into place.
///
/// A failure at any step leaves the data directory as it was.
fn restore_dropping(
    job: &Job<'_>,
    expected: (u32, u32),
    hooks: &mut Hooks<'_>,
) -> Result<kronik_ship::RestoreReport, ApiError> {
    // Before any secret is read: no core dump, and nothing for another
    // process of the same user to attach to. (Taking another identity resets
    // this on some hosts, so the drop sets it again right after.)
    kronik_privacy::key_source::protect_process().map_err(|e| e.api_error())?;
    // 1.
    let ownership = kronik_privacy::key_source::lock_data(job.data).map_err(|e| e.api_error())?;
    let owner = locked_owner(&ownership)?;
    if owner != expected {
        return Err(ApiError::new(
            ErrorCode::RootlessUnavailable,
            format!(
                "{} changed owner to {}:{} while it was being locked, and is no longer the data directory of the stable daemon identity {}:{}",
                job.data.display(),
                owner.0,
                owner.1,
                expected.0,
                expected.1
            ),
        )
        .with_hint("Nothing was written. Fix the stopped installation's ownership and run the command again."));
    }
    (hooks.seen)(Step::Locked);
    // 2. and 3., in a runtime that step 4 drops.
    let root_runtime = runtime_named(hooks.thread_name)?;
    let credentials = (hooks.credentials)(&root_runtime, job)?;
    (hooks.seen)(Step::CredentialsResolved);
    let phase = root_runtime.block_on(async {
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        // A `file://` bucket, which the service user may own, is read by
        // descriptor: no link followed, no FIFO opened, nothing created (the
        // owner's phase below reads the rest of it as the owner).
        let remote;
        let bucket = match job.from.strip_prefix("file://") {
            Some(directory) => {
                kronik_ship::Bucket::local(Path::new(directory)).map_err(ship_error)?
            }
            None => {
                remote =
                    Remote::open_with(job.from, job.endpoint, &credentials).map_err(ship_error)?;
                kronik_ship::Bucket::Remote(&remote)
            }
        };
        kronik_ship::root_phase_from(&bucket, job.data, &env, job.keys, job.mode)
            .await
            .map_err(ship_error)
    })?;
    (hooks.seen)(Step::RootPhase);
    // 4. No runtime thread may retain root credentials across the irreversible
    //    drop: dropping the runtime joins its threads, and the count says so
    //    before anything is given up (the drop would refuse as well).
    drop(root_runtime);
    let threads = (hooks.threads)()?;
    if threads != hooks.single {
        return Err(ApiError::new(
            ErrorCode::Internal,
            format!(
                "the process still has {threads} threads after the runtime was dropped ({}), where {} is needed to give up root; nothing was written",
                thread_names().join(", "),
                hooks.single
            ),
        ));
    }
    (hooks.seen)(Step::RuntimeJoined);
    // 5.
    (hooks.drop_to)(owner.0, owner.1)?;
    (hooks.seen)(Step::Dropped);
    // 6.
    let owner_runtime = runtime_named(hooks.thread_name)?;
    let local_bucket = job.from.strip_prefix("file://");
    let remote =
        Remote::open_with(job.from, job.endpoint, &credentials).map_err(
            |e| match local_bucket {
                Some(directory) => unreadable_bucket(directory, owner, &e),
                None => ship_error(e),
            },
        )?;
    if let Some(directory) = local_bucket {
        // A bucket directory that only root can read is not readable now.
        owner_runtime
            .block_on(remote.check())
            .map_err(|e| unreadable_bucket(directory, owner, &e))?;
    }
    (hooks.seen)(Step::Reopened);
    // 7.
    let env = kronik_core::env::Env::real(owner_runtime.handle().clone());
    let report = owner_runtime
        .block_on(kronik_ship::restore_as_owner(
            &remote, job.data, job.branch, job.force, &env, phase, &ownership,
        ))
        .map_err(ship_error)?;
    (hooks.seen)(Step::Installed);
    Ok(report)
}

/// The owner of the directory that is locked, from the descriptor: a path
/// that was replaced after the lock names another directory.
fn locked_owner(
    ownership: &kronik_privacy::key_source::DataOwnership,
) -> Result<(u32, u32), ApiError> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = ownership.directory_resource().metadata().map_err(|e| {
        ApiError::new(
            ErrorCode::Internal,
            format!("reading the locked data directory: {e}"),
        )
    })?;
    if !meta.is_dir() {
        return Err(ApiError::new(
            ErrorCode::Internal,
            "the locked data directory is not a directory",
        ));
    }
    Ok((meta.uid(), meta.gid()))
}

fn unreadable_bucket(directory: &str, owner: (u32, u32), why: &ShipError) -> ApiError {
    ApiError::new(
        ErrorCode::BadRequest,
        format!(
            "the bucket directory {directory} cannot be read by user {}, the owner of the data directory, who reads it once root has been given up: {why}",
            owner.0
        ),
    )
    .with_hint(
        "Make the bucket directory readable by that user, or restore from an s3:// bucket, whose credentials are read before root is given up. Nothing was written.",
    )
}

fn render(
    o: &RestoreOutput,
    args: &RestoreArgs,
    data: &Path,
    config_path: Option<&Path>,
) -> String {
    let from = &o.from;
    let endpoint = o.endpoint.as_deref();
    let force = args.force;
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
        out.push_str(&next(&[rerun(args, config_path, data, force)]));
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
    let mut command = format!("kronik serve --data-dir {dir}");
    if let Some(path) = config_path {
        let _ = write!(
            command,
            " --config {}",
            shell_quote(&path.display().to_string())
        );
    }
    if let Some(path) = &args.master_key_file {
        let _ = write!(
            command,
            " --master-key-file {}",
            shell_quote(&path.display().to_string())
        );
    }
    out.push_str(&next(&[command]));
    out
}

fn rerun(args: &RestoreArgs, config_path: Option<&Path>, data: &Path, force: bool) -> String {
    let mut cmd = format!(
        "kronik restore --from {} --data-dir {}",
        shell_quote(&args.from),
        shell_quote(&data.display().to_string())
    );
    if let Some(endpoint) = &args.endpoint {
        let _ = write!(cmd, " --endpoint {}", shell_quote(endpoint));
    }
    if let Some(path) = config_path {
        let _ = write!(
            cmd,
            " --config {}",
            shell_quote(&path.display().to_string())
        );
    }
    if let Some(path) = &args.master_key_file {
        let _ = write!(
            cmd,
            " --master-key-file {}",
            shell_quote(&path.display().to_string())
        );
    }
    if args.branch != "main" {
        let _ = write!(cmd, " --branch {}", shell_quote(&args.branch));
    }
    if args.without_keystore {
        cmd.push_str(" --without-keystore");
    }
    if args.allow_missing_keys {
        cmd.push_str(" --allow-missing-keys");
    }
    if force {
        cmd.push_str(" --force");
    }
    cmd
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime, ApiError> {
    runtime_named("kronik")
}

/// A multi-thread runtime whose threads are called `name`.
fn runtime_named(name: &str) -> Result<tokio::runtime::Runtime, ApiError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name(name)
        .build()
        .map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("starting the runtime failed: {e}"),
            )
        })
}

/// Source configuration shared by restore, upgrade and the daemon.
pub(crate) fn key_config(
    config: Option<&Path>,
    flag: Option<PathBuf>,
) -> Result<(config::Config, Option<PathBuf>), ApiError> {
    let (mut config, path) = config::Config::find(config).map_err(|e| {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("the configuration file is invalid: {e}"),
        )
    })?;
    if let Some(path) = flag {
        config.keys.master_key_file = Some(path);
    }
    config.keys.check_environment().map_err(|e| e.api_error())?;
    Ok((config, path))
}

fn ship_error(e: ShipError) -> ApiError {
    match e {
        ShipError::KeySource(e) => e.api_error(),
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
        e @ ShipError::CredentialsExpired(_) => ApiError::new(ErrorCode::Unavailable, e.to_string())
            .with_hint(
                "Nothing was installed, and the work directory `.restore` was removed. A restore that is run as root against a nonroot installation reads the credentials once, before it gives up root, and cannot refresh them; use credentials that last as long as the restore takes.",
            ),
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
        ShipError::Key(e @ kronik_privacy::PrivacyError::KeyProtection) => {
            kronik_privacy::key_source::KeySourceError::Key(e).api_error()
        }
        ShipError::Key(e) => ApiError::new(ErrorCode::BadRequest, format!("restore: {e}")),
        ShipError::Keystore(_) => ApiError::new(
            ErrorCode::Unavailable,
            "The privacy keystore could not be read safely for shipping.",
        )
        .with_hint(
            "Check the privacy keystore and storage access before attempting the operation again.",
        ),
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

#[cfg(test)]
mod tests;
