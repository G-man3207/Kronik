//! The M3 commands: forks, replay, behavior diffs, proposals, approval,
//! promote, rollback and policy, against the endpoints of
//! docs/design/m3-fork.md §9.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{Args, Subcommand};
use kronik_api::types::{
    ApproveResponse, DeployRequest, DeploymentKind, ForkCreateRequest, ForkCreateResponse,
    ForkDeleteResponse, ForkDeployResponse, ForkPoint, ForksResponse, PolicyResponse,
    PolicySetRequest, PolicySetResponse, PolicyTestRequest, PromoteResponse, ProposalInfo,
    ProposalsResponse, ProposeRequest, ProposeResponse, ReplayOptions, ReplayRequest,
    ReplayResponse, ResendRequest, RollbackResponse, SwitchInfo,
};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_fork::stubs::StubRule;
use serde_json::Value;

use super::render::{clip, field, next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, read_file, reason, required_reason, units};

#[derive(Debug, Subcommand)]
pub enum ForkCommand {
    /// Create a fork: a branch of the history from an LSN, with its own
    /// state and log from there on.
    Create(ForkCreateArgs),
    /// List the forks, the forks of proposals included.
    List,
    /// Deploy a component in a fork, also over a kind's history.
    Deploy {
        /// The fork.
        fork: String,
        /// The component, a .wasm file.
        wasm: PathBuf,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Delete a fork and its state.
    Delete {
        /// The fork.
        fork: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, Args)]
pub struct ForkCreateArgs {
    /// Where the fork starts: an LSN, `now`, or a logical time in RFC 3339,
    /// e.g. 2026-10-25T10:00:00Z.
    #[arg(long, value_name = "LSN|now|TIME")]
    at: String,
    /// The fork's name [default: generated].
    #[arg(long)]
    name: Option<String>,
    /// A fork without access to personal data; always so for a token
    /// without pii:read. Until privacy mode (M8) nothing is sealed, so the
    /// flag is recorded and the fork sees the same values.
    #[arg(long)]
    no_pii: bool,
    #[command(flatten)]
    mutation: Mutation,
}

/// Which replay runs.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Mode {
    /// Each root input on production's state at its own LSN.
    Isolated,
    /// The fork evolves its own state under the new code.
    Continuous,
    /// Both.
    Both,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Isolated => "isolated",
            Mode::Continuous => "continuous",
            Mode::Both => "both",
        }
    }
}

/// The replay mode as words, e.g. "isolated and continuous".
fn mode_text(m: Option<Mode>) -> &'static str {
    mode_words(m.unwrap_or(Mode::Both).as_str())
}

fn mode_words(mode: &str) -> &'static str {
    match mode {
        "isolated" => "isolated",
        "continuous" => "continuous",
        _ => "isolated and continuous",
    }
}

/// The replay options of `replay` and `propose`.
#[derive(Debug, Args)]
pub struct ReplayOptionArgs {
    /// Which replay runs [default: [replay] default_mode in the config file, else both].
    #[arg(long, value_enum)]
    mode: Option<Mode>,
    /// The share of root inputs replayed in isolated mode, e.g. 10% or 0.1
    /// [default: [replay] sample in the config file, else 100%].
    #[arg(long, value_name = "SHARE", value_parser = units::parse_share)]
    sample: Option<f64>,
    /// A response header to leave out of the comparison; repeat for more.
    #[arg(long = "ignore-header", value_name = "NAME")]
    ignore_headers: Vec<String>,
    /// A part of JSON bodies to leave out of the comparison, as JSONPath
    /// ($.a.b[*].c); repeat for more.
    #[arg(long = "ignore-json-path", value_name = "PATH")]
    ignore_json_paths: Vec<String>,
    /// Isolated replay workers [default: the machine's cores, at most 16].
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    threads: Option<u16>,
    /// Canned answers for effects without a recording, which count as
    /// synthetic grounding: a TOML file of [[stub]] tables or a JSON array,
    /// each {method?, url_prefix, status?, headers?, body?} or {url_prefix,
    /// error: network|timeout|too-large|denied}. Repeatable; the first
    /// matching rule answers.
    #[arg(long = "stub", value_name = "FILE")]
    stubs: Vec<PathBuf>,
}

/// A `--stub` TOML file: `[[stub]]` tables.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StubFile {
    #[serde(default)]
    stub: Vec<StubRule>,
}

/// The rules of a `--stub` file: TOML when it ends in `.toml`, else JSON
/// (an array of rules, the API's shape).
fn read_stubs(path: &Path) -> Result<Vec<StubRule>, Error> {
    let text = read_file(path, "the stub rules file")?;
    let text = String::from_utf8(text).map_err(|_| {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("{} is not UTF-8 text", path.display()),
        )
    })?;
    let bad = |e: String| {
        Error::from(
            ApiError::new(
                ErrorCode::BadRequest,
                format!("{} is not a stub rules file: {e}", path.display()),
            )
            .with_hint(
                "Give [[stub]] tables in TOML, or a JSON array, of {method?, url_prefix, \
                 status?, headers?, body?} or {url_prefix, error}.",
            ),
        )
    };
    if path.extension().is_some_and(|e| e == "toml") {
        toml::from_str::<StubFile>(&text)
            .map(|f| f.stub)
            .map_err(|e| bad(e.to_string()))
    } else {
        serde_json::from_str::<Vec<StubRule>>(&text).map_err(|e| bad(e.to_string()))
    }
}

impl ReplayOptionArgs {
    fn api(&self) -> Result<ReplayOptions, Error> {
        let config = crate::config::client_config().map_err(|e| {
            Error::from(ApiError::new(
                ErrorCode::BadRequest,
                format!("the configuration file is invalid: {e}"),
            ))
        })?;
        self.options_from(&config)
    }

    /// Replay options for a request. An omitted `--mode` or `--sample`
    /// comes from `[replay]` in `config`; an explicit flag wins.
    pub(crate) fn options_from(
        &self,
        config: &crate::config::Config,
    ) -> Result<ReplayOptions, Error> {
        let mut stubs = Vec::new();
        for path in &self.stubs {
            stubs.extend(read_stubs(path)?);
        }
        Ok(ReplayOptions {
            mode: self
                .mode
                .map(|m| m.as_str().to_owned())
                .unwrap_or_else(|| config.replay.default_mode.as_str().to_owned()),
            sample: self.sample.unwrap_or(config.replay.sample.0 / 100.0),
            ignore_headers: self.ignore_headers.clone(),
            ignore_json_paths: self.ignore_json_paths.clone(),
            threads: self.threads.map(usize::from),
            stubs,
            no_pii: false,
        })
    }

    /// The options as flags, for a command that repeats them.
    fn flags(&self) -> String {
        let mut out = String::new();
        if let Some(m) = self.mode {
            let _ = write!(out, " --mode {}", m.as_str());
        }
        if let Some(s) = self.sample {
            let _ = write!(out, " --sample {s}");
        }
        for h in &self.ignore_headers {
            let _ = write!(out, " --ignore-header {}", shell_quote(h));
        }
        for p in &self.ignore_json_paths {
            let _ = write!(out, " --ignore-json-path {}", shell_quote(p));
        }
        if let Some(t) = self.threads {
            let _ = write!(out, " --threads {t}");
        }
        for s in &self.stubs {
            let _ = write!(out, " --stub {}", shell_quote(&s.display().to_string()));
        }
        out
    }
}

#[derive(Debug, Args)]
pub struct ReplayArgs {
    /// The fork.
    fork: String,
    /// Replay the root inputs up to this main LSN [default: HEAD].
    #[arg(long, value_name = "LSN")]
    to: Option<u64>,
    #[command(flatten)]
    options: ReplayOptionArgs,
    /// Why: recorded with the replay. Required.
    #[arg(long)]
    reason: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum DiffCommand {
    /// Show the behavior diff of a fork or a proposal.
    Show {
        /// The fork or the proposal, e.g. p-7h3k2a9c1d0e.
        name: String,
        /// Print the diff as Markdown, for a review.
        #[arg(long)]
        md: bool,
    },
}

#[derive(Debug, Args)]
pub struct ProposeArgs {
    /// The new components: .wasm files, or directories such as dist/ whose
    /// .wasm files are all proposed together. A component whose code main
    /// already runs (and ran at the fork point) is skipped.
    #[arg(required = true, value_name = "WASM_OR_DIR")]
    wasm: Vec<PathBuf>,
    /// How much recent traffic to replay, in logical time back from the
    /// newest root input [default: 1h].
    #[arg(long, value_name = "DURATION", value_parser = units::parse_duration_ms)]
    window: Option<u64>,
    /// Fork at this main LSN instead of a window back from HEAD.
    #[arg(long, value_name = "LSN", conflicts_with = "window")]
    at: Option<u64>,
    #[command(flatten)]
    options: ReplayOptionArgs,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Subcommand)]
pub enum ProposalsCommand {
    /// List the proposals.
    List,
    /// Show a proposal: its status, its code, the policy outcome and the
    /// behavior diff in short.
    Show {
        /// The proposal, e.g. p-7h3k2a9c1d0e.
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct ProposalArgs {
    /// The proposal, e.g. p-7h3k2a9c1d0e.
    proposal: String,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// The deployment to undo, by its epoch, which `kronik deploy` and
    /// `kronik promote` print.
    epoch: u64,
    #[command(flatten)]
    mutation: Mutation,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Show the policy rules in force, as TOML.
    Show,
    /// Replace the policy rules with the rules in a TOML file.
    Set {
        /// The rules file.
        file: PathBuf,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Evaluate rules against a proposal's or a fork's diff; changes
    /// nothing.
    Test {
        /// The proposal or the fork.
        proposal: String,
        /// Test the rules in this TOML file instead of the rules in force.
        #[arg(long, value_name = "FILE")]
        rules: Option<PathBuf>,
    },
}

pub fn fork(ctx: &Ctx, c: ForkCommand) -> Result<ExitCode, Error> {
    match c {
        ForkCommand::Create(a) => create(ctx, a),
        ForkCommand::List => list(ctx),
        ForkCommand::Deploy {
            fork,
            wasm,
            mutation,
        } => deploy(ctx, &fork, &wasm, &mutation),
        ForkCommand::Delete { fork, mutation } => delete(ctx, &fork, &mutation),
    }
}

fn fork_path(name: &str) -> String {
    format!("/v1/forks/{}", http::encode(name))
}

fn proposal_path(id: &str) -> String {
    format!("/v1/proposals/{}", http::encode(id))
}

/// Prints the API's body for `--json`, else parses it for `render`.
fn show<T: serde::de::DeserializeOwned>(
    ctx: &Ctx,
    body: &[u8],
    render: impl FnOnce(T) -> String,
) -> Result<ExitCode, Error> {
    if ctx.json {
        ctx.print_raw(body);
    } else {
        let r: T = ctx.decode(body)?;
        ctx.print(&render(r));
    }
    Ok(ExitCode::SUCCESS)
}

fn create(ctx: &Ctx, a: ForkCreateArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let at =
        a.at.parse::<u64>()
            .map_or_else(|_| ForkPoint::Text(a.at.clone()), ForkPoint::Lsn);
    let body = ctx.post(
        "/v1/forks",
        &ForkCreateRequest {
            at,
            name: a.name.clone(),
            no_pii: a.no_pii,
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    let mut rerun = format!("kronik fork create --at {}", shell_quote(&a.at));
    if let Some(n) = &a.name {
        let _ = write!(rerun, " --name {}", shell_quote(n));
    }
    if a.no_pii {
        rerun.push_str(" --no-pii");
    }
    let _ = write!(rerun, " --reason {}", shell_quote(reason));
    show(ctx, &body, |r: ForkCreateResponse| {
        let f = &r.fork;
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: main can be forked at lsn {} as {}; nothing was written",
                f.fork_lsn, f.name
            );
            out.push_str(&next(&[rerun]));
        } else {
            let _ = writeln!(out, "Forked main at lsn {} -> fork {}", f.fork_lsn, f.name);
            let name = shell_quote(&f.name);
            out.push_str(&next(&[
                format!("kronik fork deploy {name} <wasm> --reason \"...\""),
                format!("kronik replay {name} --reason \"...\""),
            ]));
        }
        out
    })
}

fn list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/forks")?;
    show(ctx, &body, |r: ForksResponse| {
        let Some(first) = r.forks.first() else {
            let mut out = String::from("No forks.\n");
            out.push_str(&next(&[
                "kronik fork create --at now --reason \"...\"".to_owned()
            ]));
            return out;
        };
        let rows = r
            .forks
            .iter()
            .map(|f| {
                vec![
                    f.name.clone(),
                    f.fork_lsn.to_string(),
                    f.verified_through_lsn.to_string(),
                    f.proposal_id.clone().unwrap_or_else(|| "-".to_owned()),
                ]
            })
            .collect();
        let mut out = format!("Main is at lsn {}.\n", first.head_lsn);
        out.push_str(&table(
            &["FORK", "FORK LSN", "VERIFIED THROUGH", "PROPOSAL"],
            rows,
        ));
        out.push_str(&next(&[format!(
            "kronik diff show {} --md",
            shell_quote(&first.name)
        )]));
        out
    })
}

fn deploy(ctx: &Ctx, fork: &str, wasm: &Path, m: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(m)?;
    let bytes = read_file(wasm, "the component")?;
    let body = ctx.post(
        &format!("{}/deployments", fork_path(fork)),
        &DeployRequest {
            wasm_base64: STANDARD.encode(&bytes),
            reason: reason.to_owned(),
            dry_run: m.dry_run,
        },
    )?;
    let rerun = format!(
        "kronik fork deploy {} {} --reason {}",
        shell_quote(fork),
        shell_quote(&wasm.to_string_lossy()),
        shell_quote(reason)
    );
    show(ctx, &body, |r: ForkDeployResponse| {
        let d = &r.deployment;
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: {} {} (schema {}) can be deployed in fork {}; nothing was written",
                d.kind, d.code_hash, d.schema_version, r.fork
            );
            out.push_str(&next(&[rerun]));
        } else {
            let _ = writeln!(
                out,
                "Deployed {} {} (schema {}) in fork {}",
                d.kind, d.code_hash, d.schema_version, r.fork
            );
            out.push_str(&next(&[format!(
                "kronik replay {} --reason \"...\"",
                shell_quote(&r.fork)
            )]));
        }
        out
    })
}

fn delete(ctx: &Ctx, fork: &str, m: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(m)?;
    let body = ctx.send_json(
        "DELETE",
        &fork_path(fork),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: m.dry_run,
        },
    )?;
    let rerun = format!(
        "kronik fork delete {} --reason {}",
        shell_quote(fork),
        shell_quote(reason)
    );
    show(ctx, &body, |r: ForkDeleteResponse| {
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: fork {} can be deleted; nothing was written",
                r.deleted
            );
            out.push_str(&next(&[rerun]));
        } else {
            let _ = writeln!(out, "Deleted fork {}", r.deleted);
            out.push_str(&next(&["kronik fork list".to_owned()]));
        }
        out
    })
}

/// The JSON diff of a fork or a proposal, for human output.
fn fetch_diff(ctx: &Ctx, name: &str) -> Result<Value, Error> {
    let body = ctx.get(&format!("{}/diff", fork_path(name)))?;
    ctx.decode(&body)
}

pub fn replay(ctx: &Ctx, a: ReplayArgs) -> Result<ExitCode, Error> {
    let reason = required_reason(a.reason.as_deref())?;
    let options = a.options.api()?;
    let mode = mode_words(&options.mode);
    let body = ctx.post(
        &format!("{}/replay", fork_path(&a.fork)),
        &ReplayRequest {
            to_lsn: a.to,
            options,
            reason: reason.to_owned(),
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ReplayResponse = ctx.decode(&body)?;
    let diff = fetch_diff(ctx, &r.fork)?;
    let s = &r.summary;
    let mut out = format!(
        "Replayed {} of {} root inputs in fork {} ({}), verified through lsn {}\n",
        int(&s["replayed"]),
        int(&s["root_inputs"]),
        r.fork,
        mode,
        int(&s["verified_through_lsn"])
    );
    out.push_str(&diff_block(&diff));
    let name = shell_quote(&r.fork);
    out.push_str(&next(&[
        format!("kronik diff show {name} --md"),
        format!("kronik policy test {name}"),
    ]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

pub fn diff(ctx: &Ctx, c: DiffCommand) -> Result<ExitCode, Error> {
    let DiffCommand::Show { name, md } = c;
    if md && ctx.json {
        return Err(
            ApiError::new(ErrorCode::BadRequest, "--md and --json exclude each other")
                .with_hint("Use --md for the Markdown diff or --json for the JSON diff.")
                .into(),
        );
    }
    if md {
        let body = ctx.get(&format!("{}/diff?format=md", fork_path(&name)))?;
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let body = ctx.get(&format!("{}/diff", fork_path(&name)))?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let d: Value = ctx.decode(&body)?;
    let mut out = diff_header(&d);
    out.push_str(&diff_block(&d));
    out.push_str(&next(&[format!(
        "kronik diff show {} --md",
        shell_quote(&name)
    )]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

/// The components to propose: each file as given, and the `.wasm` files
/// directly in each directory (not its subdirectories), in name order.
fn components(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Error> {
    let unreadable = |p: &Path, e: std::io::Error| -> Error {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("cannot read directory {}: {e}", p.display()),
        )
        .with_hint("Check the path.")
        .into()
    };
    let mut out = Vec::new();
    for p in paths {
        if !p.is_dir() {
            out.push(p.clone());
            continue;
        }
        let mut found = Vec::new();
        for entry in std::fs::read_dir(p).map_err(|e| unreadable(p, e))? {
            let f = entry.map_err(|e| unreadable(p, e))?.path();
            if f.is_file() && f.extension().is_some_and(|x| x == "wasm") {
                found.push(f);
            }
        }
        if found.is_empty() {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("no .wasm files in {}", p.display()),
            )
            .with_hint("Build the components first: kronik build")
            .into());
        }
        found.sort();
        out.extend(found);
    }
    Ok(out)
}

/// The components a proposal skipped because main already runs them.
fn unchanged_lines(out: &mut String, unchanged: &[DeploymentKind]) {
    for u in unchanged {
        let _ = writeln!(
            out,
            "Skipped {}   {}: main already runs this code",
            u.kind, u.code_hash
        );
    }
}

/// What the reader must know about how the proposal was verified.
fn warning_lines(out: &mut String, warnings: &[String]) {
    for w in warnings {
        let _ = writeln!(out, "Warning: {w}");
    }
}

pub fn propose(ctx: &Ctx, a: ProposeArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let files = components(&a.wasm)?;
    let wasm = files
        .iter()
        .map(|p| read_file(p, "the component").map(|b| STANDARD.encode(b)))
        .collect::<Result<Vec<_>, _>>()?;
    let body = ctx.post(
        "/v1/proposals",
        &ProposeRequest {
            wasm_base64: wasm,
            names: files
                .iter()
                .map(|f| f.to_string_lossy().into_owned())
                .collect(),
            window_ms: a.window,
            at: a.at,
            options: a.options.api()?,
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ProposeResponse = ctx.decode(&body)?;
    let p = &r.proposal;
    let mut out = String::new();
    if r.dry_run {
        let mut rerun = String::from("kronik propose");
        for w in &a.wasm {
            let _ = write!(rerun, " {}", shell_quote(&w.to_string_lossy()));
        }
        if let Some(w) = a.window {
            let _ = write!(rerun, " --window {}", units::duration(w));
        }
        if let Some(at) = a.at {
            let _ = write!(rerun, " --at {at}");
        }
        rerun.push_str(&a.options.flags());
        let _ = write!(rerun, " --reason {}", shell_quote(reason));
        let _ = writeln!(
            out,
            "Dry run: the code can be proposed from lsn {}; nothing was written",
            p.fork_lsn
        );
        summary_lines(&mut out, &p.summary);
        unchanged_lines(&mut out, &p.unchanged);
        warning_lines(&mut out, &p.warnings);
        policy_lines(&mut out, &p.policy);
        out.push_str(&next(&[rerun]));
        ctx.print(&out);
        return Ok(ExitCode::SUCCESS);
    }
    let diff = fetch_diff(ctx, &p.fork)?;
    let _ = writeln!(out, "Forked main at lsn {} -> fork {}", p.fork_lsn, p.fork);
    let s = &p.summary;
    let _ = writeln!(
        out,
        "Replayed {} of {} root inputs ({}), verified through lsn {}",
        int(&s["replayed"]),
        int(&s["root_inputs"]),
        mode_text(a.options.mode),
        p.verified_through_lsn
    );
    out.push('\n');
    out.push_str(&proposal_report(p, &diff));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

pub fn proposals(ctx: &Ctx, c: ProposalsCommand) -> Result<ExitCode, Error> {
    match c {
        ProposalsCommand::List => {
            let body = ctx.get("/v1/proposals")?;
            show(ctx, &body, |r: ProposalsResponse| {
                let Some(first) = r.proposals.first() else {
                    let mut out = String::from("No proposals.\n");
                    out.push_str(&next(
                        &["kronik propose <wasm> --reason \"...\"".to_owned()],
                    ));
                    return out;
                };
                let rows = r
                    .proposals
                    .iter()
                    .map(|p| {
                        vec![
                            p.id.clone(),
                            p.status.clone(),
                            text(&p.policy["outcome"]),
                            p.verified_through_lsn.to_string(),
                            kinds(&p.kinds),
                        ]
                    })
                    .collect();
                let mut out = table(
                    &["PROPOSAL", "STATUS", "POLICY", "VERIFIED THROUGH", "CODE"],
                    rows,
                );
                out.push_str(&next(&[format!(
                    "kronik proposals show {}",
                    shell_quote(&first.id)
                )]));
                out
            })
        }
        ProposalsCommand::Show { id } => {
            let body = ctx.get(&proposal_path(&id))?;
            if ctx.json {
                ctx.print_raw(&body);
                return Ok(ExitCode::SUCCESS);
            }
            let p: ProposalInfo = ctx.decode(&body)?;
            let diff = fetch_diff(ctx, &p.fork)?;
            ctx.print(&proposal_report(&p, &diff));
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// A proposal: its code, the diff in short, the policy and what to do
/// next, which depends on its status and the policy outcome.
fn proposal_report(p: &ProposalInfo, diff: &Value) -> String {
    let mut out = String::new();
    let changes = code_changes(diff);
    let first = changes.first().cloned().unwrap_or_default();
    let _ = writeln!(out, "Proposal {}   {}   ({})", p.id, first, p.status);
    for c in changes.iter().skip(1) {
        let _ = writeln!(out, "{:width$}{c}", "", width = p.id.len() + 12);
    }
    unchanged_lines(&mut out, &p.unchanged);
    warning_lines(&mut out, &p.warnings);
    out.push_str(&diff_block(diff));
    out.push('\n');
    policy_lines(&mut out, &p.policy);
    // The requester's reason is its evidence for the human who decides: in full.
    for a in &p.approval_requests {
        let _ = writeln!(
            out,
            "Approval requested at lsn {} by {} ({}):",
            a.lsn,
            a.token_id,
            if a.pending { "pending" } else { "answered" }
        );
        for line in a.reason.lines() {
            let _ = writeln!(out, "  {line}");
        }
    }
    let id = shell_quote(&p.id);
    let outcome = p.policy["outcome"].as_str().unwrap_or_default();
    let mut cmds = vec![format!("kronik diff show {id} --md")];
    match p.status.as_str() {
        "promoted" => cmds.push("kronik rollback <epoch> --reason \"...\"".to_owned()),
        "rejected" | "stale" => {
            cmds.push("kronik propose <wasm> --reason \"...\"".to_owned());
        }
        status => {
            if outcome == "require_approval" && status != "approved" {
                cmds.push(format!("kronik approve {id} --reason \"...\""));
            }
            cmds.push(format!(
                "kronik promote {id} --reason \"...\"   (catches up to HEAD first)"
            ));
        }
    }
    out.push_str(&next(&cmds));
    out
}

/// `kind  before -> after` per changed kind, from the diff's `code`.
fn code_changes(diff: &Value) -> Vec<String> {
    let before = diff["code"]["before"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let after = diff["code"]["after"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    after
        .iter()
        .filter_map(|a| {
            let kind = text(&a["kind"]);
            let old = match before.iter().find(|b| b["kind"] == a["kind"]) {
                Some(b) if b["code_hash"] == a["code_hash"] => return None,
                Some(b) => text(&b["code_hash"]),
                None => "(new)".to_owned(),
            };
            Some(format!("{kind}   {old} -> {}", text(&a["code_hash"])))
        })
        .collect()
}

/// The header of `diff show`: the fork, the window and the code.
fn diff_header(d: &Value) -> String {
    let mut out = format!(
        "Diff of fork {}: main lsn {} to {}\n",
        text(&d["fork"]),
        int(&d["base"]["from_lsn"]),
        int(&d["base"]["to_lsn"])
    );
    for c in code_changes(d) {
        let _ = writeln!(out, "  {c}");
    }
    out
}

/// The behavior diff in short, like the brief's `kronik propose` sample.
fn diff_block(d: &Value) -> String {
    let s = &d["summary"];
    let mut out = String::new();

    // Each actor kind on its own (M9): the kinds whose code or behavior
    // changed.
    let kinds: Vec<String> = array(&d["kinds"])
        .iter()
        .filter(|k| {
            k["code"] != "unchanged"
                || int(&k["divergent_turns"]) + int(&k["errors"]["introduced"]) > 0
        })
        .map(|k| {
            format!(
                "{} ({} code): {} divergent {}, {} {} introduced",
                text(&k["kind"]),
                text(&k["code"]),
                int(&k["divergent_turns"]),
                plural(int(&k["divergent_turns"]), "turn"),
                int(&k["errors"]["introduced"]),
                plural(int(&k["errors"]["introduced"]), "error")
            )
        })
        .collect();
    if !kinds.is_empty() {
        field(&mut out, "Kinds", &kinds, "");
    }

    let origins = int(&s["origins"]);
    let consequences = int(&s["consequences"]);
    let mut causes = vec![format!(
        "{origins} {}, {consequences} {}",
        plural(origins, "origin"),
        plural(consequences, "consequence")
    )];
    for c in array(&d["causes"]).iter().take(3) {
        causes.push(format!(
            "{} on {}: {} {} ({} roots)",
            text(&c["kind"]),
            text(&c["input"]),
            int(&c["origins"]),
            plural(int(&c["origins"]), "origin"),
            int(&c["root_inputs"])
        ));
    }
    field(&mut out, "Causes", &causes, "");

    let r = &d["responses"];
    let unchanged = int(&r["unchanged"]);
    let changed = int(&r["changed"]);
    let responses = if unchanged + changed == 0 {
        "no HTTP root inputs".to_owned()
    } else {
        format!(
            "{} replayed, {unchanged} identical, {changed} changed",
            unchanged + changed
        )
    };
    field(&mut out, "Responses", &[responses], "");

    let e = &d["effects"];
    let mut effects = vec![format!(
        "{} changed, {} added, {} removed",
        int(&e["changed"]),
        int(&e["added"]),
        int(&e["removed"])
    )];
    let mut targets: Vec<(String, u64)> = Vec::new();
    for item in array(&e["items"]) {
        let target = format!(
            "{} {} {}{}",
            text(&item["kind"]),
            text(&item["method"]),
            text(&item["host"]),
            text(&item["route"])
        );
        match targets.iter_mut().find(|(t, _)| *t == target) {
            Some((_, n)) => *n += 1,
            None => targets.push((target, 1)),
        }
    }
    effects.extend(
        targets
            .iter()
            .take(3)
            .map(|(t, n)| format!("{t}: {n} {}", plural(*n, "change"))),
    );
    field(&mut out, "Effects", &effects, "");

    let mut actors: Vec<String> = Vec::new();
    for entry in array(&d["state"]["isolated"])
        .iter()
        .chain(array(&d["state"]["continuous"]).iter())
    {
        let a = text(&entry["actor"]);
        if !actors.contains(&a) {
            actors.push(a);
        }
    }
    let mut state = vec![format!(
        "{} {} changed",
        actors.len(),
        plural(actors.len() as u64, "actor")
    )];
    let cumulative = int(&d["cumulative"]["actors_changed"]);
    if cumulative > 0 {
        state.push(format!(
            "{cumulative} {} drifting over the window (cumulative)",
            plural(cumulative, "actor")
        ));
    }
    field(&mut out, "State", &state, "");

    let er = &d["errors"];
    let mut errors = format!(
        "{} introduced, {} fixed, {} new orphaned calls",
        int(&er["introduced"]),
        int(&er["fixed"]),
        int(&er["new_orphans"])
    );
    if int(&er["outcome_unknown"]) > 0 {
        let _ = write!(errors, ", {} outcome unknown", int(&er["outcome_unknown"]));
    }
    field(&mut out, "Errors", &[errors], "");
    pii_masked_field(&mut out, s);

    let res = &d["resources"];
    field(
        &mut out,
        "Resources",
        &[format!(
            "fuel p99 {}, memory p99 {}",
            percent(&res["fuel_p99_change"]),
            percent(&res["memory_p99_change"])
        )],
        "",
    );

    let live = int(&s["live"]);
    let mut grounding = vec![format!(
        "{} exact, {} approximate, {} synthetic{} (confidence {})",
        int(&s["exact"]),
        int(&s["approximate"]),
        int(&s["synthetic"]),
        if live > 0 {
            format!(", {live} live")
        } else {
            String::new()
        },
        ratio(&s["confidence"])
    )];
    for g in array(&d["grounding"]) {
        if int(&g["approximate"]) + int(&g["synthetic"]) > 0 {
            grounding.push(format!(
                "{} {} {}: {} exact, {} approximate, {} synthetic",
                text(&g["host"]),
                text(&g["method"]),
                text(&g["route"]),
                int(&g["exact"]),
                int(&g["approximate"]),
                int(&g["synthetic"])
            ));
        }
    }
    field(&mut out, "Grounding", &grounding, "");
    // Stub rules answered effects without a recording (synthetic).
    let stubs: Vec<String> = array(&d["options"]["stubs"])
        .iter()
        .map(|r| {
            let answer = match r["error"].as_str() {
                Some(e) => e.to_owned(),
                None => r["status"].as_u64().unwrap_or(200).to_string(),
            };
            format!(
                "{} {} -> {answer}",
                r["method"].as_str().unwrap_or("any"),
                text(&r["url_prefix"])
            )
        })
        .collect();
    if !stubs.is_empty() {
        field(&mut out, "Stubs", &stubs, "");
    }
    if s["sample"].as_f64().is_some_and(|x| x < 1.0) {
        field(
            &mut out,
            "Sample",
            &[format!(
                "{} of {} root inputs replayed in isolated mode",
                int(&s["replayed"]),
                int(&s["root_inputs"])
            )],
            "",
        );
    }
    out
}

/// The summary lines of a dry-run proposal, which has no stored diff.
fn summary_lines(out: &mut String, s: &Value) {
    field(
        out,
        "Replayed",
        &[format!(
            "{} of {} root inputs, {} divergent turns ({} origins, {} consequences)",
            int(&s["replayed"]),
            int(&s["root_inputs"]),
            int(&s["divergent_turns"]),
            int(&s["origins"]),
            int(&s["consequences"])
        )],
        "",
    );
    field(
        out,
        "Grounding",
        &[format!(
            "{} exact, {} approximate, {} synthetic (confidence {})",
            int(&s["exact"]),
            int(&s["approximate"]),
            int(&s["synthetic"]),
            ratio(&s["confidence"])
        )],
        "",
    );
    pii_masked_field(out, s);
}

/// `PII-masked` when turns ran on pseudonyms (`summary.pii_masked`, and
/// `pii_unverified` for those identical to production): they could not be
/// verified, so the policy needs an approval (ADR 0031).
fn pii_masked_field(out: &mut String, s: &Value) {
    let identical = int(&s["pii_unverified"]);
    let masked = int(&s["pii_masked"]) + identical;
    if masked > 0 {
        let mut line = format!(
            "{masked} {} ran on pseudonyms and could not be verified",
            plural(masked, "turn")
        );
        if identical > 0 {
            let _ = write!(line, " ({identical} identical to production)");
        }
        line.push_str("; re-run with a pii:read token");
        field(out, "PII-masked", &[line], "");
    }
}

/// `Policy   <rule> -> <ACTION>` for every fired rule, on the one line as
/// the Markdown diff lists them (the floor in code with its reason), else
/// the outcome; then a line per rule that could not be evaluated.
fn policy_lines(out: &mut String, policy: &Value) {
    let fired: Vec<String> = array(&policy["fired"])
        .iter()
        .map(|f| {
            let mut line = format!("{} -> {}", text(&f["name"]), action(&text(&f["action"])));
            if let Some(reason) = f["reason"].as_str() {
                let _ = write!(line, ": {reason}");
            }
            line
        })
        .collect();
    let mut lines = vec![if fired.is_empty() {
        action(&text(&policy["outcome"]))
    } else {
        fired.join(", ")
    }];
    for e in array(&policy["errors"]) {
        lines.push(format!(
            "rule {} failed, which counts as firing: {}",
            text(&e["name"]),
            text(&e["message"])
        ));
    }
    for (i, l) in lines.iter().enumerate() {
        let label = if i == 0 { "Policy" } else { "" };
        let _ = writeln!(out, "{label:<8} {l}");
    }
}

/// A policy action as the brief prints it, e.g. APPROVAL REQUIRED.
fn action(a: &str) -> String {
    match a {
        "allow" => "ALLOW".to_owned(),
        "require_approval" => "APPROVAL REQUIRED".to_owned(),
        "deny" => "DENY".to_owned(),
        other => other.to_uppercase(),
    }
}

pub fn approve(ctx: &Ctx, a: ProposalArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        &format!("{}/approve", proposal_path(&a.proposal)),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    let id = shell_quote(&a.proposal);
    let rerun = format!("kronik approve {id} --reason {}", shell_quote(reason));
    show(ctx, &body, |r: ApproveResponse| {
        let ap = &r.approval;
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: proposal {} can be approved; nothing was written",
                ap.proposal_id
            );
            out.push_str(&next(&[rerun]));
        } else {
            let _ = writeln!(
                out,
                "Approved proposal {} at lsn {}, for its diff {}",
                ap.proposal_id,
                ap.lsn,
                clip(&ap.diff_hash, 13)
            );
            field(
                &mut out,
                "Verified",
                &[format!("through lsn {}", ap.verified_through_lsn)],
                "",
            );
            out.push_str(&next(&[format!(
                "kronik promote {id} --reason \"...\"   (catches up to HEAD first)"
            )]));
        }
        out
    })
}

pub fn promote(ctx: &Ctx, a: ProposalArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        &format!("{}/promote", proposal_path(&a.proposal)),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    let rerun = format!(
        "kronik promote {} --reason {}",
        shell_quote(&a.proposal),
        shell_quote(reason)
    );
    show(ctx, &body, |r: PromoteResponse| {
        let d = &r.deployment;
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: proposal {} can be promoted at epoch {}; nothing was written",
                a.proposal, d.epoch
            );
            policy_lines(&mut out, &r.policy);
            out.push_str(&next(&[rerun]));
            return out;
        }
        let _ = writeln!(
            out,
            "Promoted proposal {} at lsn {}, epoch {}",
            a.proposal, d.lsn, d.epoch
        );
        switch_fields(&mut out, d);
        field(
            &mut out,
            "Verified",
            &[format!(
                "through lsn {}; {} root {} after it ran on the old code only",
                d.verified_through_lsn,
                d.unverified_inputs,
                plural(d.unverified_inputs, "input")
            )],
            "",
        );
        // The switch happened, so an approval covered a require_approval.
        let mut policy = String::new();
        policy_lines(&mut policy, &r.policy);
        if r.policy["outcome"] == "require_approval" {
            policy = policy.replacen('\n', " (approved)\n", 1);
        }
        out.push_str(&policy);
        out.push_str(&next(&[
            format!("kronik rollback {} --reason \"...\"", d.epoch),
            "kronik actors list".to_owned(),
        ]));
        out
    })
}

pub fn rollback(ctx: &Ctx, a: RollbackArgs) -> Result<ExitCode, Error> {
    let reason = reason(&a.mutation)?;
    let body = ctx.post(
        &format!("/v1/deployments/{}/rollback", a.epoch),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    let rerun = format!(
        "kronik rollback {} --reason {}",
        a.epoch,
        shell_quote(reason)
    );
    show(ctx, &body, |r: RollbackResponse| {
        let d = &r.deployment;
        let mut out = String::new();
        if r.dry_run {
            let _ = writeln!(
                out,
                "Dry run: epoch {} can be rolled back at epoch {}; nothing was written",
                a.epoch, d.epoch
            );
            switch_fields(&mut out, d);
            out.push_str(&next(&[rerun]));
        } else {
            let _ = writeln!(
                out,
                "Rolled back epoch {} at lsn {}, epoch {}: the code before it runs again",
                a.epoch, d.lsn, d.epoch
            );
            switch_fields(&mut out, d);
            out.push_str(&next(&["kronik actors list".to_owned()]));
        }
        out
    })
}

/// The code a deployment switches to.
fn switch_fields(out: &mut String, d: &SwitchInfo) {
    let kinds: Vec<String> = d
        .kinds
        .iter()
        .map(|k| format!("{} {} (schema {})", k.kind, k.code_hash, k.schema_version))
        .collect();
    field(out, "Code", &kinds, "");
}

pub fn policy(ctx: &Ctx, c: PolicyCommand) -> Result<ExitCode, Error> {
    match c {
        PolicyCommand::Show => {
            let body = ctx.get("/v1/policy")?;
            show(ctx, &body, |r: PolicyResponse| {
                let mut out = if r.default {
                    String::from("The default policy rules (no policy has been set):\n\n")
                } else {
                    format!("The policy rules set at epoch {}:\n\n", r.epoch)
                };
                out.push_str(&r.rules_toml);
                if !r.rules_toml.ends_with('\n') {
                    out.push('\n');
                }
                out.push('\n');
                out.push_str(&next(&[
                    "kronik policy test <proposal> --rules <rules.toml>".to_owned(),
                    "kronik policy set <rules.toml> --reason \"...\"".to_owned(),
                ]));
                out
            })
        }
        PolicyCommand::Set { file, mutation } => {
            let reason = reason(&mutation)?;
            let rules = read_rules(&file)?;
            let body = ctx.send_json(
                "PUT",
                "/v1/policy",
                &PolicySetRequest {
                    rules_toml: rules,
                    reason: reason.to_owned(),
                    dry_run: mutation.dry_run,
                },
            )?;
            let rerun = format!(
                "kronik policy set {} --reason {}",
                shell_quote(&file.to_string_lossy()),
                shell_quote(reason)
            );
            show(ctx, &body, |r: PolicySetResponse| {
                let mut out = String::new();
                if r.dry_run {
                    let _ = writeln!(
                        out,
                        "Dry run: the rules are valid and would apply from epoch {}; nothing was written",
                        r.epoch
                    );
                    out.push_str(&next(&[rerun]));
                } else {
                    let _ = writeln!(out, "Set the policy at lsn {}, epoch {}", r.lsn, r.epoch);
                    out.push_str(&next(&["kronik policy show".to_owned()]));
                }
                out
            })
        }
        PolicyCommand::Test { proposal, rules } => {
            let rules_toml = rules.as_deref().map(read_rules).transpose()?;
            let body = ctx.post(
                "/v1/policy/test",
                &PolicyTestRequest {
                    rules_toml,
                    proposal: proposal.clone(),
                },
            )?;
            show(ctx, &body, |v: Value| {
                let mut out = String::new();
                let _ = writeln!(
                    out,
                    "{} for {proposal}",
                    match &rules {
                        Some(f) => format!("The rules in {}", f.display()),
                        None => "The rules in force".to_owned(),
                    }
                );
                policy_lines(&mut out, &v);
                out.push_str(&next(&[match &rules {
                    Some(f) => format!(
                        "kronik policy set {} --reason \"...\"",
                        shell_quote(&f.to_string_lossy())
                    ),
                    None => format!("kronik diff show {} --md", shell_quote(&proposal)),
                }]));
                out
            })
        }
    }
}

fn read_rules(path: &Path) -> Result<String, Error> {
    String::from_utf8(read_file(path, "the rules file")?).map_err(|_| {
        ApiError::new(
            ErrorCode::BadRequest,
            format!("{} is not UTF-8 text", path.display()),
        )
        .with_hint("Policy rules are a TOML file.")
        .into()
    })
}

/// Code hashes per kind, e.g. `counter b3:…`.
fn kinds(k: &[DeploymentKind]) -> String {
    k.iter()
        .map(|k| format!("{} {}", k.kind, k.code_hash))
        .collect::<Vec<_>>()
        .join(", ")
}

fn int(v: &Value) -> u64 {
    v.as_u64().unwrap_or_default()
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_owned()
}

fn array(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

/// A change as a signed percentage, e.g. `+3.1%`; one that rounds to zero
/// is `0.0%`, never `-0.0%`.
fn percent(v: &Value) -> String {
    match format!("{:+.1}", v.as_f64().unwrap_or_default() * 100.0).as_str() {
        "+0.0" | "-0.0" => "0.0%".to_owned(),
        s => format!("{s}%"),
    }
}

/// A ratio with two decimals, e.g. `0.99`.
fn ratio(v: &Value) -> String {
    format!("{:.2}", v.as_f64().unwrap_or(1.0))
}

fn plural(n: u64, word: &str) -> String {
    if n == 1 {
        word.to_owned()
    } else {
        format!("{word}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../docs/design/fixtures/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn diff_block_reads_like_the_brief() {
        let d = fixture("diff-approximate-payments");
        let shown = diff_block(&d);
        for want in [
            "  Causes        4 origins, 0 consequences\n",
            "  Responses     100 replayed, 100 identical, 0 changed\n",
            "  Effects       4 changed, 0 added, 0 removed\n",
            "                http.fetch POST payments.internal/v1/charges/{}: 1 change\n",
            "  Errors        0 introduced, 0 fixed, 0 new orphaned calls\n",
            "  Resources     fuel p99 0.0%, memory p99 0.0%\n",
            "  Grounding     120 exact, 4 approximate, 0 synthetic (confidence 0.97)\n",
            "                payments.internal POST /v1/charges/{}: 120 exact, 4 approximate, 0 synthetic\n",
        ] {
            assert!(shown.contains(want), "{want}: {shown}");
        }
        assert_eq!(
            code_changes(&d),
            ["billing   b3:aaaaaaaaaaaa -> b3:bbbbbbbbbbbb"]
        );
    }

    #[test]
    fn a_system_diff_shows_each_changed_kind() {
        let d = fixture("diff-system-caller-alone");
        let shown = diff_block(&d);
        for want in [
            "  Kinds         counter (changed code): 4 divergent turns, 4 errors introduced\n",
            "                notes (unchanged code): 8 divergent turns, 4 errors introduced\n",
        ] {
            assert!(shown.contains(want), "{want}: {shown}");
        }
        // Only the kinds whose code changes are listed as code changes.
        assert_eq!(
            code_changes(&d),
            ["counter   b3:bf34162595e6 -> b3:06d907243ec0"]
        );
    }

    #[test]
    fn policy_lines_name_the_fired_rules() {
        let mut out = String::new();
        policy_lines(
            &mut out,
            &json!({"outcome": "require_approval", "fired": [
                {"name": "payments-must-be-exact", "action": "require_approval"}
            ], "errors": []}),
        );
        assert_eq!(
            out,
            "Policy   payments-must-be-exact -> APPROVAL REQUIRED\n"
        );
        let mut out = String::new();
        policy_lines(
            &mut out,
            &json!({"outcome": "allow", "fired": [], "errors": []}),
        );
        assert_eq!(out, "Policy   ALLOW\n");
    }

    #[test]
    fn the_policy_line_lists_every_fired_rule_with_the_floor() {
        let mut out = String::new();
        policy_lines(
            &mut out,
            &json!({"outcome": "require_approval", "fired": [
                {"name": "any-change", "action": "require_approval"},
                {"name": "pii-masked-needs-approval", "action": "require_approval",
                 "reason": "8 turns could not be verified without personal data"}
            ], "errors": []}),
        );
        assert_eq!(
            out,
            "Policy   any-change -> APPROVAL REQUIRED, pii-masked-needs-approval -> \
             APPROVAL REQUIRED: 8 turns could not be verified without personal data\n"
        );
    }

    #[test]
    fn a_change_that_rounds_to_zero_has_no_sign() {
        // Walk 3: 2 420 074 fuel at p99 against 2 420 306 printed -0.0%.
        assert_eq!(percent(&json!(-232.0 / 2_420_306.0)), "0.0%");
        assert_eq!(percent(&json!(0.0)), "0.0%");
        assert_eq!(percent(&json!(0.0004)), "0.0%");
        assert_eq!(percent(&json!(0.554)), "+55.4%");
        assert_eq!(percent(&json!(-0.031)), "-3.1%");
    }

    #[test]
    fn omitted_replay_flags_come_from_the_file_and_explicit_flags_win() {
        let config = crate::config::Config::parse(
            "[replay]\ndefault_mode = \"isolated\"\nsample = \"10%\"\n",
            std::path::Path::new("kronik.toml"),
        )
        .unwrap();
        let omitted = ReplayOptionArgs {
            mode: None,
            sample: None,
            ignore_headers: vec![],
            ignore_json_paths: vec![],
            threads: None,
            stubs: vec![],
        }
        .options_from(&config);
        let omitted = must_options(omitted);
        assert_eq!(omitted.mode, "isolated");
        assert!((omitted.sample - 0.1).abs() < 1e-9, "{}", omitted.sample);
        let explicit = ReplayOptionArgs {
            mode: Some(Mode::Both),
            sample: Some(1.0),
            ignore_headers: vec![],
            ignore_json_paths: vec![],
            threads: None,
            stubs: vec![],
        }
        .options_from(&config);
        let explicit = must_options(explicit);
        assert_eq!(explicit.mode, "both");
        assert_eq!(explicit.sample, 1.0);
        let defaults = crate::config::Config::default();
        let from_defaults = ReplayOptionArgs {
            mode: None,
            sample: None,
            ignore_headers: vec![],
            ignore_json_paths: vec![],
            threads: None,
            stubs: vec![],
        }
        .options_from(&defaults);
        let from_defaults = must_options(from_defaults);
        assert_eq!(from_defaults.mode, "both");
        assert_eq!(from_defaults.sample, 1.0);
    }

    fn must_options(r: Result<ReplayOptions, Error>) -> ReplayOptions {
        match r {
            Ok(o) => o,
            Err(Error::Local(e)) => panic!("{e}"),
            Err(Error::Remote { status, .. }) => panic!("remote status {status}"),
        }
    }
}
