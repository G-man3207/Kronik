//! The `kronik` binary: the CLI and `serve`.

mod admin;
mod cli;
mod config;
mod doctor;
mod init;
mod mcp;
mod project;
mod restore;
mod serve;
mod upgrade;

use std::process::ExitCode;
use std::sync::LazyLock;

use clap::{Parser, Subcommand};
use kronik_runtime::{ENGINE_VERSION, KRONIK_VERSION, WASMTIME_VERSION};

/// Printed by `kronik --version`: the Kronik, Wasmtime and engine versions.
static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!("{KRONIK_VERSION}\nwasmtime {WASMTIME_VERSION}\nengine {ENGINE_VERSION}")
});

/// A runtime that verifies every change against real production traffic
/// before it goes live.
#[derive(Debug, Parser)]
#[command(
    version = KRONIK_VERSION,
    long_version = LONG_VERSION.as_str(),
    arg_required_else_help = true
)]
struct Cli {
    #[command(flatten)]
    client: cli::Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the daemon: the gateway (HTTP) and the API (Unix socket).
    Serve(serve::ServeArgs),
    /// Create an actor project (TypeScript or Rust) with the SDK vendored.
    Init(project::InitArgs),
    /// Build the actor project into dist/<name>.wasm and check its imports.
    Build(project::BuildArgs),
    /// Run a project in an in-memory node, driven by JSON lines on stdin:
    /// the host of the SDK testkits.
    #[command(hide = true)]
    TestHost(project::TestHostArgs),
    /// Serve MCP on stdio, forwarding to the daemon's MCP endpoint over the
    /// API socket.
    Mcp(mcp::McpArgs),
    /// Check what this host can run: gVisor, KVM, cgroups, disk, clock, TLS
    /// and object storage. Needs no daemon; --json for a report.
    Doctor(doctor::DoctorArgs),
    /// Restore a data directory from object storage. Needs no daemon, and
    /// writes no log record.
    Restore(restore::RestoreArgs),
    /// Check this binary against a data directory before switching to it.
    /// Needs no daemon.
    #[command(subcommand)]
    Upgrade(upgrade::UpgradeCommand),
    #[command(flatten)]
    Client(cli::Command),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let refused = match &cli.command {
        Command::Serve(_) | Command::Mcp(_) | Command::Client(_) => None,
        Command::Init(_) => cli.client.refuse_remote("init"),
        Command::Build(_) => cli.client.refuse_remote("build"),
        Command::TestHost(_) => cli.client.refuse_remote("test-host"),
        Command::Doctor(_) => cli.client.refuse_remote("doctor"),
        Command::Restore(_) => cli.client.refuse_remote("restore"),
        Command::Upgrade(_) => cli.client.refuse_remote("upgrade"),
    };
    if let Some(code) = refused {
        return code;
    }
    let args = match cli.command {
        Command::Serve(args) => args,
        Command::Init(args) => return project::init(args, cli.client.json),
        Command::Build(args) => return project::build(args, cli.client.json),
        Command::TestHost(args) => return project::test_host(args),
        Command::Mcp(args) => return mcp::run(args, &cli.client),
        Command::Doctor(args) => return doctor::run(args, cli.client.json),
        Command::Restore(args) => return restore::run(args, cli.client.json),
        Command::Upgrade(upgrade::UpgradeCommand::Check(args)) => {
            return upgrade::check(args, cli.client.json);
        }
        Command::Client(command) => return cli::run(command, &cli.client),
    };
    if cli.client.given() {
        eprintln!(
            "error: kronik serve takes none of --socket, --url, --token and --json, which are for the client commands; its own API socket is --api-socket (see kronik serve --help)"
        );
        return ExitCode::from(2);
    }
    let result = serve::run(args);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "kronik serve stopped");
            ExitCode::FAILURE
        }
    }
}
