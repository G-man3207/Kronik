//! Master-key sources, offline migration and online rewrap (M23 B1).
use std::path::PathBuf;
use std::process::ExitCode;

use super::{Ctx, Error, Mutation, next, reason, shell_quote};
use kronik_api::types::{KeysChangeResponse, KeysRewrapRequest};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_privacy::key_source::KeyStatus;

#[derive(Debug, clap::Subcommand)]
pub enum KeysCommand {
    /// Show the loaded source and provider version, never key bytes.
    Status,
    /// Wrap the same seed under the provider's current key version.
    Rewrap {
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Migrate an existing file/env seed into the configured KMS, offline.
    Wrap(WrapArgs),
    /// Verify a PKCS#11 key and print its non-secret enrollment probe.
    Enroll {
        #[arg(long, env = "KRONIK_CONFIG", default_value = crate::config::DEFAULT_PATH)]
        config: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct WrapArgs {
    #[arg(long, value_parser = ["openbao", "aws", "gcp", "azure", "pkcs11"])]
    source: String,
    #[arg(long, env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, env = "KRONIK_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// The OLD key file; defaults to <data-dir>/keys/master.key.
    /// KRONIK_MASTER_KEY may instead supply the old seed for this command.
    #[arg(long, env = "KRONIK_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
    /// Delete the old key file after durable wrap; NEVER the default.
    #[arg(long)]
    remove_file: bool,
    #[command(flatten)]
    mutation: Mutation,
}

#[cfg(test)]
pub fn wrap_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<KeysChangeResponse>()
}

#[cfg(test)]
pub fn enroll_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<kronik_privacy::key_source::config::Probe>()
}

pub(super) fn keys(ctx: &Ctx, command: KeysCommand) -> Result<ExitCode, Error> {
    match command {
        KeysCommand::Status => {
            let bytes = ctx.get("/v1/keys")?;
            if ctx.json {
                ctx.print_raw(&bytes);
            } else {
                show(
                    ctx,
                    &ctx.decode::<KeyStatus>(&bytes)?,
                    false,
                    &["kronik keys status".into()],
                );
            }
        }
        KeysCommand::Rewrap { mutation } => {
            let why = reason(&mutation)?;
            let bytes = ctx.post(
                "/v1/keys/rewrap",
                &KeysRewrapRequest {
                    reason: why.into(),
                    dry_run: mutation.dry_run,
                },
            )?;
            if ctx.json {
                ctx.print_raw(&bytes);
            } else {
                let r: KeysChangeResponse = ctx.decode(&bytes)?;
                show(ctx, &r.keys, r.dry_run, &["kronik keys status".into()]);
            }
        }
        KeysCommand::Wrap(args) => {
            let why = reason(&args.mutation)?;
            let (config, selected_config) = crate::config::Config::find(args.config.as_deref())
                .map_err(|e| ApiError::new(ErrorCode::BadRequest, e.to_string()))?;
            if config.keys.source.as_str() != args.source {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    "--source must match [keys] source in the target configuration",
                )
                .into());
            }
            let env_material = std::env::var_os(kronik_privacy::MASTER_KEY_ENV).is_some();
            let explicit_file = args.master_key_file.is_some();
            if explicit_file && env_material {
                return Err(ApiError::new(
                    ErrorCode::BadRequest,
                    "choose an old key file or KRONIK_MASTER_KEY, not both",
                )
                .into());
            }
            let data = args.data_dir.unwrap_or(config.server.data_dir);
            let file = args
                .master_key_file
                .unwrap_or_else(|| data.join("keys/master.key"));
            let runtime = crate::restore::runtime()?;
            let keys = runtime
                .block_on(async {
                    let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
                    kronik_privacy::key_source::wrap_existing(
                        &env,
                        &config.keys,
                        &data,
                        &file,
                        args.remove_file,
                        |master, stage| {
                            let secrets = rusqlite::Connection::open_with_flags(stage.join("secrets.db"),
                                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                                .map_err(kronik_privacy::PrivacyError::from)
                                .and_then(|conn| kronik_privacy::SecretStore::open_readonly(conn, master))
                                .and_then(|store| store.values())
                                .ok();
                            let patterns = secrets.as_ref().map(|values| values.iter()
                                .map(|(name, value)| (name.as_str(), value.as_slice())).collect::<Vec<_>>());
                            kronik_sched::scrub::for_log(why, patterns.as_deref())
                        },
                        args.mutation.dry_run,
                    )
                    .await
                })
                .map_err(|e| e.api_error())?;
            let response = KeysChangeResponse {
                dry_run: args.mutation.dry_run,
                keys,
            };
            if ctx.json {
                ctx.print(
                    &serde_json::to_string(&response)
                        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?,
                );
            } else {
                let mut commands = Vec::new();
                if response.dry_run {
                    let mut command = format!(
                        "kronik keys wrap --source {} --data-dir {}",
                        args.source,
                        shell_quote(&data.display().to_string())
                    );
                    if let Some(path) = &selected_config {
                        command.push_str(&format!(
                            " --config {}",
                            shell_quote(&path.display().to_string())
                        ));
                    }
                    if explicit_file {
                        command.push_str(&format!(
                            " --master-key-file {}",
                            shell_quote(&file.display().to_string())
                        ));
                    }
                    if args.remove_file {
                        command.push_str(" --remove-file");
                    }
                    command.push_str(" --reason \"...\"");
                    commands.push(command);
                }
                let mut start = format!(
                    "kronik serve --data-dir {}",
                    shell_quote(&data.display().to_string())
                );
                if let Some(path) = &selected_config {
                    start.push_str(&format!(
                        " --config {}",
                        shell_quote(&path.display().to_string())
                    ));
                }
                if env_material || explicit_file {
                    start.insert_str(0, "env -u KRONIK_MASTER_KEY -u KRONIK_MASTER_KEY_FILE ");
                }
                commands.push(start);
                let socket = std::env::var_os("KRONIK_API_SOCKET")
                    .map(PathBuf::from)
                    .unwrap_or(config.server.api_socket);
                commands.push(format!(
                    "kronik --socket {} keys status",
                    shell_quote(&socket.display().to_string())
                ));
                show(ctx, &response.keys, response.dry_run, &commands);
            }
        }
        KeysCommand::Enroll { config: path } => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| ApiError::new(ErrorCode::BadRequest, format!("{}: {e}", path.display())))?;
            let document: toml::Value = toml::from_str(&text)
                .map_err(|_| ApiError::new(ErrorCode::BadRequest, "Invalid enrollment configuration"))?;
            let keys: kronik_privacy::key_source::Keys = document.get("keys").cloned()
                .ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "Enrollment requires [keys] configuration"))?
                .try_into().map_err(|_| ApiError::new(ErrorCode::BadRequest, "Invalid [keys] enrollment configuration"))?;
            let runtime = crate::restore::runtime()?;
            let probe = runtime.block_on(async {
                let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
                kronik_privacy::key_source::enroll_pkcs11(&env, &keys).await
            }).map_err(|e| e.api_error())?;
            if ctx.json {
                ctx.print(&serde_json::to_string(&probe)
                    .map_err(|_| ApiError::new(ErrorCode::Internal, "Cannot encode enrollment probe"))?);
            } else {
                let probe = toml::to_string(&probe)
                    .map_err(|_| ApiError::new(ErrorCode::Internal, "Cannot encode enrollment probe"))?;
                ctx.print(&format!("Verified PKCS#11 key possession. Save this non-secret probe in {}:\n\n[keys.pkcs11.probe]\n{probe}", path.display()));
                ctx.print(&next(&[format!(
                    "kronik keys wrap --source pkcs11 --config {} --reason \"...\"",
                    shell_quote(&path.display().to_string())
                )]));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn show(ctx: &Ctx, s: &KeyStatus, dry_run: bool, commands: &[String]) {
    ctx.print(&format!(
        "{}Master key source {}{}{}; key check {}\n{}",
        if dry_run { "Dry run: " } else { "" },
        s.source,
        s.key.as_ref().map(|k| format!(" {k}")).unwrap_or_default(),
        s.key_version
            .as_ref()
            .map(|v| format!(" (version {v})"))
            .unwrap_or_default(),
        if s.check_ok { "ok" } else { "failed" },
        next(commands)
    ));
}
