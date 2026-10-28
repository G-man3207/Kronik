//! The client commands of the `kronik` binary. They talk to the daemon's
//! JSON API over its Unix socket (docs/design/m1-core.md §4 and
//! docs/design/m2-effects.md §8); `explain` works without a daemon. Human
//! output is short and ends with the exact next commands; `--json` prints
//! the API's response body unchanged. With `$KRONIK_TOKEN` set, every
//! request carries that token and acts as it, with its scopes.

mod foreign;
mod fork;
mod http;
mod privacy;
mod render;
#[cfg(test)]
mod schemas;
mod snapshot;
mod token;
mod units;

use std::io::{self, BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{ArgGroup, Args, Subcommand};
use kronik_api::types::{
    ActorsResponse, DeadLettersResponse, DeployRequest, DeployResponse, DeploymentsResponse,
    ForkTurnResponse, GrantRequest, GrantResponse, GrantsResponse, HistoryResponse,
    InspectResponse, LimitsListResponse, LimitsRequest, LimitsResponse, OrphansResponse, Payload,
    ResendRequest, RevokeRequest, RevokeResponse, SecretDeleteRequest, SecretDeleteResponse,
    SecretResponse, SecretSetRequest, SecretsResponse, SendRequest, TimersResponse, TraceResponse,
    TurnResponse,
};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::explain;
use kronik_core::ids::ActorRef;
use serde::Serialize;
use serde::de::DeserializeOwned;

use render::TurnContext;

/// Options of every client command.
#[derive(Debug, Args)]
pub struct Global {
    /// The daemon's API socket [default: $KRONIK_API_SOCKET, else
    /// server.api_socket in /etc/kronik/kronik.toml, else
    /// /run/kronik/api.sock]. Not for `serve`, which takes --api-socket.
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Print JSON: the API's response unchanged for a client command, the
    /// result of init, build, doctor, restore, upgrade check and explain,
    /// and the error JSON on failure (docs/reference/json.md has every
    /// schema). Not for `serve`.
    #[arg(long, global = true)]
    pub json: bool,
}

impl Global {
    /// Whether any client option was given, which `serve` does not take.
    pub fn given(&self) -> bool {
        self.socket.is_some() || self.json
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Deploy a component as a new actor type (a kind without history).
    Deploy(DeployArgs),
    /// List the deployments: the code switches, with their epochs.
    #[command(subcommand)]
    Deployments(DeploymentsCommand),
    /// Send an operator message to an actor and wait for its turn.
    Send(SendArgs),
    /// List actors, show one actor's state, or list its timers.
    #[command(subcommand)]
    Actors(ActorsCommand),
    /// Show an actor's turns, newest first, or the orphaned changes.
    History(HistoryArgs),
    /// Show a turn's causal tree: from its root input down to everything it
    /// caused.
    Trace {
        /// The turn id, e.g. main:12.
        turn_id: String,
    },
    /// List failed inputs, or resend one as a new root input.
    #[command(subcommand)]
    DeadLetters(DeadLettersCommand),
    /// Grant an actor type a capability: permission for an effect against a
    /// target.
    Grant(GrantArgs),
    /// Revoke a capability from an actor type.
    Revoke(RevokeArgs),
    /// List the capabilities granted to actor types.
    #[command(subcommand)]
    Grants(GrantsCommand),
    /// Set or show the limits of actor types.
    #[command(subcommand)]
    Limits(LimitsCommand),
    /// Store, list or delete secrets. Values are read from stdin and never
    /// shown.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Create, list, deploy to or delete forks: branches of the history.
    #[command(subcommand)]
    Fork(fork::ForkCommand),
    /// Replay root inputs through a fork's code and write its behavior diff.
    Replay(fork::ReplayArgs),
    /// Show the behavior diff of a fork or a proposal.
    #[command(subcommand)]
    Diff(fork::DiffCommand),
    /// Propose new code: fork, replay recent traffic through it, write the
    /// behavior diff and evaluate the policy.
    Propose(fork::ProposeArgs),
    /// List proposals, or show one.
    #[command(subcommand)]
    Proposals(fork::ProposalsCommand),
    /// Approve a proposal's diff when the policy requires an approval.
    Approve(fork::ProposalArgs),
    /// Switch to a proposal's code, after replaying the traffic since it.
    Promote(fork::ProposalArgs),
    /// Switch back to the code in force before a deployment.
    Rollback(fork::RollbackArgs),
    /// Show, set or test the policy rules.
    #[command(subcommand)]
    Policy(fork::PolicyCommand),
    /// Create, list or revoke API tokens: bearer credentials with scopes.
    #[command(subcommand)]
    Token(token::TokenCommand),
    /// Foreign actors: Linux programs from OCI images in gVisor, reached
    /// with foreign://<name>/... (add, list, logs, remove).
    #[command(subcommand)]
    Foreign(foreign::ForeignCommand),
    /// Privacy mode: turn sealing of personal data on or off, or show it.
    #[command(subcommand)]
    Privacy(privacy::PrivacyCommand),
    /// List snapshots of main, or take one now.
    #[command(subcommand)]
    Snapshot(snapshot::SnapshotCommand),
    /// The applied LSN, the state hash and a hash of the log, to compare
    /// after a restore.
    Integrity,
    /// Explain a concept or an error code. Needs no daemon.
    Explain(ExplainArgs),
}

/// `--reason` and `--dry-run`, which every mutation takes (I12).
#[derive(Debug, Args)]
pub struct Mutation {
    /// Why: recorded in the history with the change. Required.
    #[arg(long)]
    reason: Option<String>,
    /// Check the request and show what would happen; write nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// The component, a .wasm file.
    wasm: PathBuf,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// The actor, as kind/key.
    actor: String,
    /// The message name.
    name: String,
    /// The message body as text.
    #[arg(long, conflicts_with = "file")]
    text: Option<String>,
    /// Read the message body from a file.
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,
    /// The body's content type [default: text/plain with --text, otherwise
    /// application/octet-stream].
    #[arg(long)]
    content_type: Option<String>,
    /// Send the message to the actor in this fork instead of main: it runs
    /// under the fork's code, without live effects, and has no dry run.
    #[arg(long, conflicts_with = "dry_run")]
    fork: Option<String>,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Subcommand)]
pub enum ActorsCommand {
    /// List actors, ordered by kind and key.
    List(ListActorsArgs),
    /// Show an actor's state and SQL tables.
    Inspect {
        /// The actor, as kind/key.
        actor: String,
    },
    /// List an actor's pending timers, by due time.
    Timers {
        /// The actor, as kind/key.
        actor: String,
    },
}

#[derive(Debug, Args)]
pub struct ListActorsArgs {
    /// Only actors of this kind.
    #[arg(long)]
    kind: Option<String>,
    /// Start after this actor (kind/key), for the next page.
    #[arg(long, value_name = "KIND/KEY")]
    after: Option<String>,
    /// At most this many actors (1-1000) [default: 100].
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: Option<u32>,
}

#[derive(Debug, Args)]
pub struct HistoryArgs {
    /// The actor, as kind/key.
    #[arg(required_unless_present = "orphans")]
    actor: Option<String>,
    /// At most this many turns (1-1000) [default: 100].
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: Option<u32>,
    /// Only turns before this LSN, for the next page.
    #[arg(long, value_name = "LSN")]
    before: Option<u64>,
    /// List the orphaned changes instead: changes that a called actor
    /// committed in a `call` whose caller then failed, until a compensation
    /// succeeds.
    #[arg(long, conflicts_with_all = ["actor", "limit", "before"])]
    orphans: bool,
    /// With --orphans: also the resolved ones.
    #[arg(long, requires = "orphans")]
    all: bool,
}

#[derive(Debug, Subcommand)]
pub enum DeadLettersCommand {
    /// List dead letters, oldest first.
    List {
        /// Start after this dead letter id, for the next page.
        #[arg(long, value_name = "ID")]
        after: Option<String>,
        /// At most this many dead letters (1-1000) [default: 100].
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: Option<u32>,
    },
    /// Resend a dead letter's input as a new root input and wait for its
    /// turn.
    Resend {
        /// The dead letter id: the turn id of the failed turn, e.g. main:12.
        id: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("what").required(true).args(["topic", "list"])))]
pub struct ExplainArgs {
    /// A concept or an error code, e.g. fork or ACTOR_NOT_FOUND. Case does
    /// not matter.
    topic: Option<String>,
    /// List every topic.
    #[arg(long)]
    list: bool,
}

/// How a target tolerates retries: the delivery class of an `http:` grant.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Delivery {
    /// The request can be repeated without consequences.
    ReplaySafe,
    /// The target respects `Idempotency-Key`.
    IdempotencyKeyed,
    /// Neither: after a crash the request is not repeated.
    Unsafe,
}

impl Delivery {
    fn as_str(self) -> &'static str {
        match self {
            Delivery::ReplaySafe => "replay-safe",
            Delivery::IdempotencyKeyed => "idempotency-keyed",
            Delivery::Unsafe => "unsafe",
        }
    }
}

#[derive(Debug, Args)]
pub struct GrantArgs {
    /// The actor type, e.g. billing.
    kind: String,
    /// The capability: http:<host>, http:*.<domain>, secret:<name> or
    /// secret-reveal:<name>.
    capability: String,
    /// How the target tolerates retries, for http: capabilities [default:
    /// replay-safe for GET, HEAD and OPTIONS, unsafe otherwise].
    #[arg(long, value_enum)]
    delivery: Option<Delivery>,
    /// At most this many requests per second, minute or hour, for http:
    /// capabilities, e.g. 2/s.
    #[arg(long, value_name = "N/s|N/m|N/h")]
    rate: Option<String>,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    /// The actor type, e.g. billing.
    kind: String,
    /// The granted capability, e.g. http:api.example.com.
    capability: String,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Subcommand)]
pub enum GrantsCommand {
    /// List the grants in force, by actor type and capability.
    List {
        /// Only grants of this actor type.
        #[arg(long)]
        kind: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum LimitsCommand {
    /// Change an actor type's limits; limits not named keep their value.
    Set(LimitsSetArgs),
    /// Show the limits in force for every deployed actor type.
    Show {
        /// Only this actor type (deployed or not).
        #[arg(long)]
        kind: Option<String>,
    },
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("limit")
        .required(true)
        .multiple(true)
        .args([
            "fuel",
            "memory",
            "message_size",
            "state_value_size",
            "sql_size",
            "effect_timeout",
            "effect_response_size",
        ])
))]
pub struct LimitsSetArgs {
    /// The actor type, e.g. billing.
    kind: String,
    /// Fuel per turn, e.g. 100000000 or 100M.
    #[arg(long, value_name = "N", value_parser = units::parse_count)]
    fuel: Option<u64>,
    /// Memory per instance, e.g. 128Mi.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    memory: Option<u64>,
    /// Largest message body, e.g. 2Mi.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    message_size: Option<u64>,
    /// Largest state value, e.g. 2Mi.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    state_value_size: Option<u64>,
    /// Largest SQL database per actor, e.g. 2Gi.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    sql_size: Option<u64>,
    /// How long an effect may take, e.g. 10s or 500ms.
    #[arg(long, value_name = "DURATION", value_parser = units::parse_duration_ms)]
    effect_timeout: Option<u64>,
    /// Largest effect response, e.g. 10Mi.
    #[arg(long, value_name = "SIZE", value_parser = units::parse_size)]
    effect_response_size: Option<u64>,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// Store a secret, or a new version of it, from stdin: one hidden line
    /// from a terminal, otherwise everything up to the end of input.
    Set {
        /// The secret's name: up to 64 of a-z, 0-9, `_`, `.` and `-`,
        /// starting with a letter or a digit.
        name: String,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// List secrets: names, versions and version hashes, never values.
    List,
    /// Delete every version of a secret.
    Delete {
        /// The secret's name.
        name: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

/// Runs a client command and returns the process exit code: 0 on success,
/// 1 on an error or a failed turn.
pub fn run(command: Command, global: &Global) -> ExitCode {
    let ctx = Ctx {
        // A broken configuration file fails the commands that need the
        // daemon; `explain` still works.
        socket: crate::config::client_api_socket(global.socket.clone()).map_err(|e| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("the configuration file is invalid: {e}"),
            )
            .with_hint(
                "Fix the file, or name the socket with --socket <path> or $KRONIK_API_SOCKET.",
            )
        }),
        json: global.json,
        token: client_token(),
    };
    let result = match command {
        Command::Deploy(a) => deploy(&ctx, a),
        Command::Deployments(DeploymentsCommand::List) => deployments(&ctx),
        Command::Send(a) => send(&ctx, a),
        Command::Actors(ActorsCommand::List(a)) => actors(&ctx, a),
        Command::Actors(ActorsCommand::Inspect { actor }) => inspect(&ctx, &actor),
        Command::Actors(ActorsCommand::Timers { actor }) => timers(&ctx, &actor),
        Command::History(a) if a.orphans => orphans(&ctx, a.all),
        Command::History(a) => history(&ctx, a),
        Command::Trace { turn_id } => trace(&ctx, &turn_id),
        Command::DeadLetters(DeadLettersCommand::List { after, limit }) => {
            dead_letters(&ctx, after, limit)
        }
        Command::DeadLetters(DeadLettersCommand::Resend { id, mutation }) => {
            resend(&ctx, &id, mutation)
        }
        Command::Grant(a) => grant(&ctx, a),
        Command::Revoke(a) => revoke(&ctx, a),
        Command::Grants(GrantsCommand::List { kind }) => grants(&ctx, kind),
        Command::Limits(LimitsCommand::Set(a)) => limits_set(&ctx, a),
        Command::Limits(LimitsCommand::Show { kind }) => limits_show(&ctx, kind),
        Command::Secret(SecretCommand::Set { name, mutation }) => secret_set(&ctx, &name, mutation),
        Command::Secret(SecretCommand::List) => secrets(&ctx),
        Command::Secret(SecretCommand::Delete { name, mutation }) => {
            secret_delete(&ctx, &name, mutation)
        }
        Command::Fork(c) => fork::fork(&ctx, c),
        Command::Replay(a) => fork::replay(&ctx, a),
        Command::Diff(c) => fork::diff(&ctx, c),
        Command::Propose(a) => fork::propose(&ctx, a),
        Command::Proposals(c) => fork::proposals(&ctx, c),
        Command::Approve(a) => fork::approve(&ctx, a),
        Command::Promote(a) => fork::promote(&ctx, a),
        Command::Rollback(a) => fork::rollback(&ctx, a),
        Command::Policy(c) => fork::policy(&ctx, c),
        Command::Privacy(c) => privacy::privacy(&ctx, c),
        Command::Token(c) => token::token(&ctx, c),
        Command::Foreign(c) => foreign::foreign(&ctx, c),
        Command::Snapshot(c) => snapshot::snapshot(&ctx, c),
        Command::Integrity => snapshot::integrity(&ctx),
        Command::Explain(a) => explain_topic(&ctx, a),
    };
    result.unwrap_or_else(|e| {
        ctx.fail(&e);
        ExitCode::FAILURE
    })
}

/// Why a command failed.
enum Error {
    /// An error found by the CLI itself.
    Local(ApiError),
    /// The daemon's error response, as it was sent.
    Remote { status: u16, body: Vec<u8> },
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Error {
        Error::Local(e)
    }
}

struct Ctx {
    /// The API socket, or why the configuration does not give one.
    socket: Result<PathBuf, ApiError>,
    json: bool,
    /// `$KRONIK_TOKEN`, sent as `Authorization: Bearer`, or why it is not a
    /// token.
    token: Result<Option<String>, ApiError>,
}

/// `$KRONIK_TOKEN`: absent or empty means none; anything but printable
/// ASCII is refused rather than sent as a header.
pub(crate) fn client_token() -> Result<Option<String>, ApiError> {
    let Some(value) = std::env::var_os("KRONIK_TOKEN") else {
        return Ok(None);
    };
    let value = value.to_str().map(str::trim);
    match value {
        Some("") => Ok(None),
        Some(token) if token.bytes().all(|b| b.is_ascii_graphic()) => Ok(Some(token.to_owned())),
        _ => Err(ApiError::new(
            ErrorCode::BadRequest,
            "$KRONIK_TOKEN is not a token: it has spaces, control characters or non-ASCII bytes",
        )
        .with_hint(
            "Set KRONIK_TOKEN to the token that `kronik token create` printed, or unset it.",
        )),
    }
}

impl Ctx {
    fn get(&self, target: &str) -> Result<Vec<u8>, Error> {
        self.request("GET", target, None)
    }

    fn post<B: Serialize>(&self, target: &str, body: &B) -> Result<Vec<u8>, Error> {
        self.send_json("POST", target, body)
    }

    /// Sends a request with a JSON body.
    fn send_json<B: Serialize>(
        &self,
        method: &str,
        target: &str,
        body: &B,
    ) -> Result<Vec<u8>, Error> {
        let body = serde_json::to_vec(body).map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("encoding the request failed: {e}"),
            )
        })?;
        self.request(method, target, Some(&body))
    }

    /// Sends a request; a 2xx response gives its body, any other status an
    /// [`Error::Remote`].
    fn request(&self, method: &str, target: &str, body: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        let socket = self.socket.as_ref().map_err(|e| Error::Local(e.clone()))?;
        let token = self.token.as_ref().map_err(|e| Error::Local(e.clone()))?;
        let r =
            http::request(socket, method, target, body, token.as_deref()).map_err(|f| match f {
                http::Failure::Connect(e) => connect_error(socket, &e),
                http::Failure::Io(e) => ApiError::new(
                    ErrorCode::Unavailable,
                    format!(
                        "the connection to the daemon on {} broke: {e}",
                        socket.display()
                    ),
                ),
                http::Failure::Malformed(m) => ApiError::new(ErrorCode::Internal, m).with_hint(
                    format!("Check that {} is a Kronik API socket.", socket.display()),
                ),
            })?;
        if (200..300).contains(&r.status) {
            Ok(r.body)
        } else {
            Err(Error::Remote {
                status: r.status,
                body: r.body,
            })
        }
    }

    /// Parses a successful response for human output.
    fn decode<T: DeserializeOwned>(&self, body: &[u8]) -> Result<T, Error> {
        serde_json::from_slice(body).map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("unexpected response from the daemon: {e}"),
            )
            .with_hint(
                "Check that the CLI and the daemon are the same version (`kronik --version`).",
            )
            .into()
        })
    }

    /// Prints a response body unchanged, for `--json`.
    fn print_raw(&self, body: &[u8]) {
        let mut out = io::stdout().lock();
        let _ = out.write_all(body);
        if !body.ends_with(b"\n") {
            let _ = out.write_all(b"\n");
        }
        let _ = out.flush();
    }

    fn print(&self, text: &str) {
        let mut out = io::stdout().lock();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }

    /// Reports an error: the error JSON on stdout with `--json`, otherwise
    /// code, message, hint and docs on stderr.
    fn fail(&self, e: &Error) {
        if self.json {
            match e {
                Error::Local(e) => match serde_json::to_vec(e) {
                    Ok(body) => self.print_raw(&body),
                    Err(_) => self.print_raw(e.to_json().to_string().as_bytes()),
                },
                Error::Remote { body, .. } => self.print_raw(body),
            }
            return;
        }
        let text = match e {
            Error::Local(e) => render::error(e),
            Error::Remote { status, body } => match serde_json::from_slice::<ApiError>(body) {
                Ok(e) => render::error(&e),
                Err(_) => format!(
                    "error: the daemon answered HTTP {status}: {}\n",
                    String::from_utf8_lossy(body).trim()
                ),
            },
        };
        let mut err = io::stderr().lock();
        let _ = err.write_all(text.as_bytes());
        let _ = err.flush();
    }
}

/// The error for a socket that cannot be connected to.
fn connect_error(socket: &Path, e: &io::Error) -> ApiError {
    let shown = socket.display();
    let start = format!(
        "Start the daemon with `kronik serve --api-socket {}`, or pass its socket with `--socket <path>`.",
        shell_quote(&socket.to_string_lossy())
    );
    let (message, hint) = match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            (format!("no Kronik daemon is listening on {shown}"), start)
        }
        io::ErrorKind::PermissionDenied => (
            format!("permission denied on {shown}"),
            "Run as root or as a member of the socket's group, or pass another socket with `--socket <path>`."
                .to_owned(),
        ),
        _ => (format!("cannot connect to {shown}: {e}"), start),
    };
    ApiError::new(ErrorCode::Unavailable, message).with_hint(hint)
}

/// The reason of a mutation; a missing or blank one fails before anything
/// is sent.
fn reason(m: &Mutation) -> Result<&str, Error> {
    required_reason(m.reason.as_deref())
}

/// A required `--reason`, also for commands without `--dry-run`.
fn required_reason(reason: Option<&str>) -> Result<&str, Error> {
    match reason {
        Some(r) if !r.trim().is_empty() => Ok(r),
        _ => Err(ApiError::new(
            ErrorCode::ReasonRequired,
            "every mutation needs a reason, which the history records with it",
        )
        .with_hint("Add --reason with a short explanation, e.g. --reason \"first deploy\".")
        .into()),
    }
}

fn actor_ref(s: &str) -> Result<ActorRef, Error> {
    ActorRef::parse(s).map_err(|e| {
        ApiError::new(ErrorCode::BadRequest, e.to_string())
            .with_hint("Name the actor as kind/key, for example counter/a.")
            .into()
    })
}

fn read_file(path: &Path, what: &str) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|e| {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("cannot read {what} {}: {e}", path.display()),
        )
        .with_hint("Check the path.")
        .into()
    })
}

/// `?k=v&…` with the given values, encoded; empty without any.
fn query(pairs: &[(&str, Option<String>)]) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if let Some(v) = v {
            out.push(if out.is_empty() { '?' } else { '&' });
            out.push_str(k);
            out.push('=');
            out.push_str(&http::encode(v));
        }
    }
    out
}

fn actor_path(a: &ActorRef) -> String {
    format!(
        "/v1/actors/{}/{}",
        http::encode(&a.kind),
        http::encode(&a.key)
    )
}

/// The gateway address for the hints after a deploy: `http_listen` from
/// `GET /v1/health` where the daemon reports it, else `$KRONIK_HTTP_LISTEN`
/// (which serve reads too) or serve's default.
fn gateway(ctx: &Ctx) -> String {
    let reported = ctx
        .get("/v1/health")
        .ok()
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .and_then(|v| v.get("http_listen")?.as_str().map(str::to_owned));
    let addr = reported
        .or_else(|| std::env::var("KRONIK_HTTP_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    loopback(&addr)
}

/// A listen address as a client reaches it: an unspecified IP (0.0.0.0 or
/// ::) becomes loopback.
fn loopback(addr: &str) -> String {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(mut a) if a.ip().is_unspecified() => {
            a.set_ip(match a {
                std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
                std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
            });
            a.to_string()
        }
        _ => addr.to_owned(),
    }
}

/// The exit code for a turn: failure unless it committed (or was a dry run).
fn turn_exit(t: &TurnResponse) -> ExitCode {
    match &t.outcome {
        Some(o) if o.kind != "committed" => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
}

#[derive(Debug, Subcommand)]
pub enum DeploymentsCommand {
    /// List every deployment, oldest first: deploys, promotes and rollbacks.
    List,
}

fn deployments(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/deployments")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: DeploymentsResponse = ctx.decode(&body)?;
    ctx.print(&render::deployments(&r));
    Ok(ExitCode::SUCCESS)
}

fn deploy(ctx: &Ctx, a: DeployArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let wasm = read_file(&a.wasm, "the component")?;
    // Compiling a large component takes a while; say so on a terminal.
    if !ctx.json && io::stderr().is_terminal() {
        let _ = writeln!(
            io::stderr(),
            "Compiling {} ({} bytes) in the daemon; this can take a while...",
            a.wasm.display(),
            wasm.len()
        );
    }
    let body = ctx.post(
        "/v1/deployments",
        &DeployRequest {
            wasm_base64: STANDARD.encode(&wasm),
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: DeployResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik deploy {} --reason {}",
        shell_quote(&a.wasm.to_string_lossy()),
        shell_quote(reason)
    );
    ctx.print(&render::deploy(&r, &rerun, &gateway(ctx)));
    Ok(ExitCode::SUCCESS)
}

fn send(ctx: &Ctx, a: SendArgs) -> Result<ExitCode, Error> {
    let actor = actor_ref(&a.actor)?;
    let reason = reason(&a.mutation)?;
    let (body, default_type) = match (&a.text, &a.file) {
        (Some(t), _) => (
            Payload {
                text: Some(t.clone()),
                base64: None,
            },
            "text/plain",
        ),
        (None, Some(path)) => (
            Payload {
                text: None,
                base64: Some(STANDARD.encode(read_file(path, "the message body")?)),
            },
            "",
        ),
        (None, None) => (Payload::default(), ""),
    };
    let content_type = a
        .content_type
        .clone()
        .unwrap_or_else(|| default_type.to_owned());
    let request = SendRequest {
        name: a.name.clone(),
        content_type: content_type.clone(),
        body,
        subject: None,
        reason: reason.to_owned(),
        dry_run: a.mutation.dry_run,
    };
    if let Some(fork) = &a.fork {
        let raw = ctx.post(
            &format!(
                "/v1/forks/{}/actors/{}/{}/messages",
                http::encode(fork),
                http::encode(&actor.kind),
                http::encode(&actor.key)
            ),
            &request,
        )?;
        let parsed = serde_json::from_slice::<ForkTurnResponse>(&raw);
        let exit = |t: &ForkTurnResponse| match t.outcome.kind.as_str() {
            "committed" => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        };
        if ctx.json {
            ctx.print_raw(&raw);
            return Ok(parsed.map_or(ExitCode::SUCCESS, |t| exit(&t)));
        }
        let t: ForkTurnResponse = ctx.decode(&raw)?;
        ctx.print(&render::fork_turn(&t, &actor.to_string()));
        return Ok(exit(&t));
    }
    let raw = ctx.post(&format!("{}/messages", actor_path(&actor)), &request)?;
    let parsed = serde_json::from_slice::<TurnResponse>(&raw);
    if ctx.json {
        ctx.print_raw(&raw);
        return Ok(parsed.map_or(ExitCode::SUCCESS, |t| turn_exit(&t)));
    }
    let t: TurnResponse = ctx.decode(&raw)?;
    let mut rerun = format!("kronik send {actor} {}", shell_quote(&a.name));
    if let Some(text) = &a.text {
        rerun.push_str(&format!(" --text {}", shell_quote(text)));
    }
    if let Some(path) = &a.file {
        rerun.push_str(&format!(" --file {}", shell_quote(&path.to_string_lossy())));
    }
    if let Some(ct) = &a.content_type {
        rerun.push_str(&format!(" --content-type {}", shell_quote(ct)));
    }
    rerun.push_str(&format!(" --reason {}", shell_quote(reason)));
    ctx.print(&render::turn(
        &t,
        &TurnContext::Send {
            actor: actor.to_string(),
            rerun,
        },
    ));
    Ok(turn_exit(&t))
}

fn trace(ctx: &Ctx, turn_id: &str) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!("/v1/turns/{}/trace", http::encode(turn_id)))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: TraceResponse = ctx.decode(&body)?;
    ctx.print(&render::trace(&r));
    Ok(ExitCode::SUCCESS)
}

fn actors(ctx: &Ctx, a: ListActorsArgs) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!(
        "/v1/actors{}",
        query(&[
            ("kind", a.kind.clone()),
            ("after", a.after.clone()),
            ("limit", a.limit.map(|l| l.to_string())),
        ])
    ))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ActorsResponse = ctx.decode(&body)?;
    let mut more = String::from("kronik actors list");
    if let Some(k) = &a.kind {
        more.push_str(&format!(" --kind {}", shell_quote(k)));
    }
    if let Some(l) = a.limit {
        more.push_str(&format!(" --limit {l}"));
    }
    ctx.print(&render::actors(&r, &more));
    Ok(ExitCode::SUCCESS)
}

fn inspect(ctx: &Ctx, actor: &str) -> Result<ExitCode, Error> {
    let actor = actor_ref(actor)?;
    let body = ctx.get(&actor_path(&actor))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: InspectResponse = ctx.decode(&body)?;
    ctx.print(&render::inspect(&r));
    Ok(ExitCode::SUCCESS)
}

fn history(ctx: &Ctx, a: HistoryArgs) -> Result<ExitCode, Error> {
    let actor = actor_ref(a.actor.as_deref().unwrap_or_default())?;
    let body = ctx.get(&format!(
        "{}/history{}",
        actor_path(&actor),
        query(&[
            ("before", a.before.map(|b| b.to_string())),
            ("limit", a.limit.map(|l| l.to_string())),
        ])
    ))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: HistoryResponse = ctx.decode(&body)?;
    ctx.print(&render::history(&actor.to_string(), &r, a.limit));
    Ok(ExitCode::SUCCESS)
}

fn orphans(ctx: &Ctx, all: bool) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!(
        "/v1/orphans{}",
        query(&[("all", all.then(|| "true".to_owned()))])
    ))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: OrphansResponse = ctx.decode(&body)?;
    ctx.print(&render::orphans(&r, all));
    Ok(ExitCode::SUCCESS)
}

fn timers(ctx: &Ctx, actor: &str) -> Result<ExitCode, Error> {
    let actor = actor_ref(actor)?;
    let body = ctx.get(&format!("{}/timers", actor_path(&actor)))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: TimersResponse = ctx.decode(&body)?;
    ctx.print(&render::timers(&actor.to_string(), &r));
    Ok(ExitCode::SUCCESS)
}

fn dead_letters(ctx: &Ctx, after: Option<String>, limit: Option<u32>) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!(
        "/v1/dead-letters{}",
        query(&[("after", after), ("limit", limit.map(|l| l.to_string())),])
    ))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: DeadLettersResponse = ctx.decode(&body)?;
    // The API returns at most 100 by default; a full page may have more.
    let full = r.dead_letters.len() == limit.map_or(100, |l| l as usize);
    ctx.print(&render::dead_letters(&r, full.then_some(limit)));
    Ok(ExitCode::SUCCESS)
}

fn resend(ctx: &Ctx, id: &str, mutation: Mutation) -> Result<ExitCode, Error> {
    let reason = reason(&mutation)?;
    let raw = ctx.post(
        &format!("/v1/dead-letters/{}/resend", http::encode(id)),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    let parsed = serde_json::from_slice::<TurnResponse>(&raw);
    if ctx.json {
        ctx.print_raw(&raw);
        return Ok(parsed.map_or(ExitCode::SUCCESS, |t| turn_exit(&t)));
    }
    let t: TurnResponse = ctx.decode(&raw)?;
    ctx.print(&render::turn(
        &t,
        &TurnContext::Resend {
            id: id.to_owned(),
            rerun: format!(
                "kronik dead-letters resend {} --reason {}",
                shell_quote(id),
                shell_quote(reason)
            ),
        },
    ));
    Ok(turn_exit(&t))
}

fn grant(ctx: &Ctx, a: GrantArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        "/v1/grants",
        &GrantRequest {
            kind: a.kind.clone(),
            capability: a.capability.clone(),
            delivery: a.delivery.map(|d| d.as_str().to_owned()),
            rate: a.rate.clone(),
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: GrantResponse = ctx.decode(&body)?;
    let mut rerun = format!(
        "kronik grant {} {}",
        shell_quote(&a.kind),
        shell_quote(&a.capability)
    );
    if let Some(d) = a.delivery {
        rerun.push_str(&format!(" --delivery {}", d.as_str()));
    }
    if let Some(rate) = &a.rate {
        rerun.push_str(&format!(" --rate {}", shell_quote(rate)));
    }
    rerun.push_str(&format!(" --reason {}", shell_quote(reason)));
    ctx.print(&render::grant(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn revoke(ctx: &Ctx, a: RevokeArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        "/v1/grants/revoke",
        &RevokeRequest {
            kind: a.kind.clone(),
            capability: a.capability.clone(),
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: RevokeResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik revoke {} {} --reason {}",
        shell_quote(&a.kind),
        shell_quote(&a.capability),
        shell_quote(reason)
    );
    ctx.print(&render::revoke(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn grants(ctx: &Ctx, kind: Option<String>) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!("/v1/grants{}", query(&[("kind", kind)])))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: GrantsResponse = ctx.decode(&body)?;
    ctx.print(&render::grants(&r));
    Ok(ExitCode::SUCCESS)
}

fn limits_set(ctx: &Ctx, a: LimitsSetArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        "/v1/limits",
        &LimitsRequest {
            kind: a.kind.clone(),
            fuel: a.fuel,
            memory_bytes: a.memory,
            message_bytes: a.message_size,
            state_value_bytes: a.state_value_size,
            sql_bytes_per_actor: a.sql_size,
            effect_timeout_ms: a.effect_timeout,
            effect_response_bytes: a.effect_response_size,
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: LimitsResponse = ctx.decode(&body)?;
    let mut rerun = format!("kronik limits set {}", shell_quote(&a.kind));
    for (flag, value) in [
        ("--fuel", a.fuel.map(|n| n.to_string())),
        ("--memory", a.memory.map(units::size_flag)),
        ("--message-size", a.message_size.map(units::size_flag)),
        (
            "--state-value-size",
            a.state_value_size.map(units::size_flag),
        ),
        ("--sql-size", a.sql_size.map(units::size_flag)),
        ("--effect-timeout", a.effect_timeout.map(units::duration)),
        (
            "--effect-response-size",
            a.effect_response_size.map(units::size_flag),
        ),
    ] {
        if let Some(v) = value {
            rerun.push_str(&format!(" {flag} {v}"));
        }
    }
    rerun.push_str(&format!(" --reason {}", shell_quote(reason)));
    ctx.print(&render::limits_set(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn limits_show(ctx: &Ctx, kind: Option<String>) -> Result<ExitCode, Error> {
    let body = ctx.get(&format!("/v1/limits{}", query(&[("kind", kind)])))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: LimitsListResponse = ctx.decode(&body)?;
    ctx.print(&render::limits(&r));
    Ok(ExitCode::SUCCESS)
}

fn secret_path(name: &str) -> String {
    format!("/v1/secrets/{}", http::encode(name))
}

fn secret_set(ctx: &Ctx, name: &str, mutation: Mutation) -> Result<ExitCode, Error> {
    let reason = reason(&mutation)?;
    let value = read_secret(name)?;
    let body = ctx.send_json(
        "PUT",
        &secret_path(name),
        &SecretSetRequest {
            value: Payload {
                text: None,
                base64: Some(STANDARD.encode(&value)),
            },
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SecretResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik secret set {} --reason {}",
        shell_quote(name),
        shell_quote(reason)
    );
    ctx.print(&render::secret_set(name, &r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn secrets(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/secrets")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SecretsResponse = ctx.decode(&body)?;
    ctx.print(&render::secrets(&r));
    Ok(ExitCode::SUCCESS)
}

fn secret_delete(ctx: &Ctx, name: &str, mutation: Mutation) -> Result<ExitCode, Error> {
    let reason = reason(&mutation)?;
    let body = ctx.send_json(
        "DELETE",
        &secret_path(name),
        &SecretDeleteRequest {
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SecretDeleteResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik secret delete {} --reason {}",
        shell_quote(name),
        shell_quote(reason)
    );
    ctx.print(&render::secret_deleted(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

/// Reads a secret's value from stdin, never from the command line: one line
/// with echo off when stdin is a terminal, otherwise everything up to the
/// end of input. One trailing newline is removed from a value that is text,
/// so `echo "$VALUE" | kronik secret set …` stores the value without it;
/// other bytes are kept exactly.
fn read_secret(name: &str) -> Result<Vec<u8>, Error> {
    let failed = |e: io::Error| {
        Error::from(
            ApiError::new(
                ErrorCode::BadRequest,
                format!("reading the secret from stdin failed: {e}"),
            )
            .with_hint("Give the value on stdin, e.g. printf %s \"$VALUE\" | kronik secret set <name> --reason \"...\"."),
        )
    };
    let stdin = io::stdin();
    let mut value = Vec::new();
    if stdin.is_terminal() {
        prompt(&format!("Value of secret {name} (not shown): "));
        let echo = EchoOff::new()?;
        let read = stdin.lock().read_until(b'\n', &mut value);
        drop(echo);
        prompt("\n");
        read.map_err(failed)?;
    } else {
        stdin.lock().read_to_end(&mut value).map_err(failed)?;
    }
    if std::str::from_utf8(&value).is_ok() {
        if value.ends_with(b"\r\n") {
            value.truncate(value.len() - 2);
        } else if value.ends_with(b"\n") {
            value.truncate(value.len() - 1);
        }
    }
    if value.is_empty() {
        return Err(ApiError::new(ErrorCode::BadRequest, "the secret value is empty")
            .with_hint("Give the value on stdin, e.g. printf %s \"$VALUE\" | kronik secret set <name> --reason \"...\".")
            .into());
    }
    Ok(value)
}

/// Writes a prompt to stderr, so stdout stays the command's output.
fn prompt(text: &str) {
    let mut err = io::stderr().lock();
    let _ = err.write_all(text.as_bytes());
    let _ = err.flush();
}

/// Turns the terminal's echo off with `stty` while a secret is typed, and
/// restores the previous settings when dropped.
struct EchoOff {
    saved: String,
}

impl EchoOff {
    fn new() -> Result<EchoOff, Error> {
        let saved = stty(&["-g"])?;
        stty(&["-echo"])?;
        Ok(EchoOff {
            saved: saved.trim().to_owned(),
        })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = stty(&[&self.saved]);
    }
}

/// Runs `stty` on the terminal on stdin and returns what it printed.
fn stty(args: &[&str]) -> Result<String, Error> {
    let failed = |detail: String| {
        Error::from(
            ApiError::new(
                ErrorCode::BadRequest,
                format!("cannot turn off echo on the terminal: {detail}"),
            )
            .with_hint("Give the value on stdin instead, e.g. printf %s \"$VALUE\" | kronik secret set <name> --reason \"...\"."),
        )
    };
    let out = std::process::Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| failed(format!("stty: {e}")))?;
    if !out.status.success() {
        return Err(failed(format!(
            "stty {} exited with {}",
            args.join(" "),
            out.status
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `{"topics":[…]}` for `explain --list --json`.
#[derive(Serialize)]
struct Topics {
    topics: Vec<explain::Topic>,
}

fn explain_topic(ctx: &Ctx, a: ExplainArgs) -> Result<ExitCode, Error> {
    if a.list {
        let topics: Vec<explain::Topic> = explain::list().collect();
        if ctx.json {
            print_json(ctx, &Topics { topics })?;
        } else {
            ctx.print(&render::topics(&topics));
        }
        return Ok(ExitCode::SUCCESS);
    }
    let name = a.topic.unwrap_or_default();
    let Some(topic) = explain::lookup(&name) else {
        return Err(
            ApiError::new(ErrorCode::BadRequest, format!("no topic {name:?}"))
                .with_hint("List the topics with `kronik explain --list`.")
                .into(),
        );
    };
    if ctx.json {
        print_json(ctx, &topic)?;
    } else {
        ctx.print(&format!("{topic}\n"));
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints a value as JSON, for output that does not come from the API.
fn print_json<T: Serialize>(ctx: &Ctx, v: &T) -> Result<(), Error> {
    let body = serde_json::to_vec(v)
        .map_err(|e| ApiError::new(ErrorCode::Internal, format!("encoding JSON failed: {e}")))?;
    ctx.print_raw(&body);
    Ok(())
}

/// Prints a local error the way a client command does, for commands that
/// do not talk to the daemon.
pub(crate) fn report_error(json: bool, e: &kronik_core::error::ApiError) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string(e).unwrap_or_else(|_| e.to_json().to_string())
        );
    } else {
        eprint!("{}", render::error(e));
    }
    ExitCode::FAILURE
}

pub(crate) use render::{field, next, shell_quote};
pub(crate) use units::parse_duration_ms;
