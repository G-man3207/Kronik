//! Ordinary authenticated fleet API commands; enrollment credentials never become API bearers.

use std::io::{self, Read as _};
use std::path::PathBuf;
use std::process::ExitCode;

use kronik_core::error::{ApiError, ErrorCode};
use serde_json::json;

use super::{Ctx, Error, Mutation, reason};

#[derive(Debug, clap::Subcommand)]
pub enum FleetCommand {
    /// Enroll with a controller; a new request needs an explicit one-time credential.
    Enroll(EnrollArgs),
    /// Show this installation's fleet enrollment through its ordinary API.
    Status,
    /// Revoke this installation's enrollment through its ordinary API.
    Revoke {
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, clap::Args)]
#[command(group(clap::ArgGroup::new("enrollment_credential").args(["enrollment_token", "token_file", "token_stdin"])))]
pub struct EnrollArgs {
    /// The controller URL; trust and client credentials remain daemon configuration.
    #[arg(value_name = "URL")]
    controller_url: String,
    /// A one-time enrollment credential (prefer --token-file or --token-stdin).
    #[arg(long = "token", value_name = "ONE_TIME", hide_env_values = true)]
    enrollment_token: Option<String>,
    /// Read the one-time enrollment credential from this file.
    #[arg(long, value_name = "PATH")]
    token_file: Option<PathBuf>,
    /// Read the one-time enrollment credential from standard input.
    #[arg(long)]
    token_stdin: bool,
    #[command(flatten)]
    mutation: Mutation,
}

pub(super) fn fleet(ctx: &Ctx, command: FleetCommand) -> Result<ExitCode, Error> {
    let body = match command {
        FleetCommand::Status => ctx.get("/v1/fleet")?,
        FleetCommand::Revoke { mutation } => ctx.post(
            "/v1/fleet/revoke",
            &json!({"reason": reason(&mutation)?, "dry_run": mutation.dry_run}),
        )?,
        FleetCommand::Enroll(args) => {
            let why = reason(&args.mutation)?;
            let token = match (args.enrollment_token, args.token_file, args.token_stdin) {
                (Some(value), _, _) => Some(credential(value.into_bytes())?),
                (None, None, false) => None,
                (None, file, _) => {
                    let mut input: Box<dyn io::Read> = match file {
                        Some(path) => Box::new(
                            std::fs::File::open(path)
                                .map_err(|_| bad("cannot open the enrollment credential file"))?,
                        ),
                        None => Box::new(io::stdin()),
                    };
                    let mut bytes = Vec::new();
                    input
                        .by_ref()
                        .take(4097)
                        .read_to_end(&mut bytes)
                        .map_err(|_| bad("cannot read the enrollment credential"))?;
                    Some(credential(bytes)?)
                }
            };
            ctx.post("/v1/fleet/enroll", &json!({
                "url": args.controller_url, "token": token, "reason": why, "dry_run": args.mutation.dry_run
            }))?
        }
    };
    render(ctx, &body)?;
    Ok(ExitCode::SUCCESS)
}

fn bad(message: &str) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}

fn credential(bytes: Vec<u8>) -> Result<String, ApiError> {
    if bytes.len() > 4096 {
        return Err(bad("the enrollment credential exceeds 4096 bytes"));
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| bad("the enrollment credential must be printable ASCII"))?;
    let token = value.trim();
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(bad(
            "the enrollment credential must be nonempty printable ASCII without spaces",
        ));
    }
    Ok(token.to_owned())
}

pub(super) fn render(ctx: &Ctx, body: &[u8]) -> Result<(), Error> {
    if ctx.json {
        ctx.print_raw(body);
    } else {
        let value: serde_json::Value = ctx.decode(body)?;
        let text = serde_json::to_string_pretty(&value)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot render the API response"))?;
        ctx.print(&format!("{text}\n"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn enrollment_token_is_not_the_api_bearer() {
        let cli = crate::Cli::try_parse_from([
            "kronik",
            "--token",
            "api-secret",
            "fleet",
            "enroll",
            "https://controller:443",
            "--token",
            "one-time",
            "--reason",
            "join",
        ])
        .unwrap();
        assert_eq!(cli.client.token.as_deref(), Some("api-secret"));
        assert!(cli.client.url.is_none());
        let crate::Command::Client(super::super::Command::Fleet(FleetCommand::Enroll(args))) =
            cli.command
        else {
            panic!("expected enrollment");
        };
        assert_eq!(args.enrollment_token.as_deref(), Some("one-time"));
        assert_eq!(args.controller_url, "https://controller:443");
    }

    #[test]
    fn fleet_bearer_alias_and_ordinary_global_token_work() {
        let cli = crate::Cli::try_parse_from([
            "kronik",
            "fleet",
            "--api-token",
            "api-secret",
            "enroll",
            "https://controller:443",
            "--token-stdin",
            "--reason",
            "join",
        ])
        .unwrap();
        assert_eq!(cli.client.token.as_deref(), Some("api-secret"));
        let cli = crate::Cli::try_parse_from(["kronik", "actors", "list", "--token", "ordinary"])
            .unwrap();
        assert_eq!(cli.client.token.as_deref(), Some("ordinary"));
        assert!(
            crate::Cli::try_parse_from([
                "kronik",
                "fleet",
                "enroll",
                "https://controller:443",
                "--reason",
                "resume"
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "kronik",
                "fleet",
                "enroll",
                "https://controller:443",
                "--token",
                "one-time",
                "--token-stdin"
            ])
            .is_err()
        );
        let cli = crate::Cli::try_parse_from([
            "kronik",
            "--url",
            "https://daemon:7443",
            "fleet",
            "enroll",
            "https://controller:443",
            "--token",
            "one-time",
            "--reason",
            "join",
        ])
        .unwrap();
        assert_eq!(cli.client.url.as_deref(), Some("https://daemon:7443"));
        assert!(cli.client.token.is_none());
    }

    #[test]
    fn preview_and_durable_recovery_never_reuse_the_api_bearer_as_enrollment_token() {
        for dry_run in [false, true] {
            let mut argv = vec![
                "kronik",
                "--token",
                "api-only",
                "fleet",
                "enroll",
                "https://controller:443",
                "--reason",
                "recover",
            ];
            if dry_run {
                argv.push("--dry-run");
            }
            let cli = crate::Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.client.token.as_deref(), Some("api-only"));
            let crate::Command::Client(super::super::Command::Fleet(FleetCommand::Enroll(args))) =
                cli.command
            else {
                panic!("expected enrollment");
            };
            assert!(args.enrollment_token.is_none());
            assert!(args.token_file.is_none());
            assert!(!args.token_stdin);
            assert_eq!(args.mutation.dry_run, dry_run);
        }
    }

    #[test]
    fn credential_validation_never_echoes_secrets() {
        assert_eq!(credential(b"secret\n".to_vec()).unwrap(), "secret");
        for bytes in [
            vec![],
            b"private value".to_vec(),
            b"private\0value".to_vec(),
            vec![b'x'; 4097],
            vec![255],
        ] {
            let message = credential(bytes).unwrap_err().message;
            assert!(!message.contains("private"));
        }
    }
}
