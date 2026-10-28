//! `kronik init`, `kronik build` and `kronik test-host`: actor projects in
//! TypeScript and Rust.
//!
//! `init` writes a project with the SDK and the WIT vendored from sources
//! embedded in this binary, so nothing needs a package registry except the
//! public ones for the toolchain and the SDK's own dependencies. `build`
//! turns a project into `dist/<name>.wasm` and checks its imports against
//! the deploy allowlist, as `kronik deploy` would. `test-host` (hidden) runs
//! a project in an in-memory node for the SDKs' testkits.

mod build;
mod embed;
mod init;
mod testhost;

pub use testhost::TestHostArgs;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, ValueEnum};
use kronik_core::error::{ApiError, ErrorCode};
use serde::Serialize;

/// A project's language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Lang {
    /// TypeScript, built with jco and ComponentizeJS (ADR 0002).
    Ts,
    /// Rust, built for wasm32-wasip2.
    Rust,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// The project's name, also its directory and its actor type's name:
    /// lowercase letters, digits and dashes.
    name: String,
    /// The language.
    #[arg(long, value_enum, default_value = "ts")]
    lang: Lang,
}

#[derive(Debug, Args)]
pub struct BuildArgs {
    /// The project directory.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    /// Build even if the inputs are unchanged since the last build.
    #[arg(long)]
    force: bool,
    /// TypeScript: build this entry instead of package.json's
    /// `kronik.entry`, as the variant dist/<name>-<entry's file name>.wasm.
    #[arg(long)]
    entry: Option<String>,
}

/// An error with an optional next step, printed as `error:`/`hint:`, or
/// with `--json` as the stable error JSON on stdout.
#[derive(Debug)]
pub struct Failure {
    code: ErrorCode,
    message: String,
    hint: Option<String>,
    docs: Option<String>,
}

impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Failure {
            code: ErrorCode::BadRequest,
            message: message.into(),
            hint: None,
            docs: None,
        }
    }

    fn code(mut self, code: ErrorCode) -> Self {
        self.code = code;
        self
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    fn docs(mut self, docs: impl Into<String>) -> Self {
        self.docs = Some(docs.into());
        self
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Failure::new(e.to_string())
    }
}

/// Prints a result: `human` for a person, or with `json` one JSON object on
/// stdout, the error JSON on failure.
fn report<T: Serialize>(
    result: Result<T, Failure>,
    json: bool,
    human: impl FnOnce(&T),
) -> ExitCode {
    match result {
        Ok(out) => {
            if json {
                println!("{}", serde_json::to_string(&out).unwrap_or_default());
            } else {
                human(&out);
            }
            ExitCode::SUCCESS
        }
        Err(f) if json => {
            let mut e = ApiError::new(f.code, f.message);
            if let Some(hint) = f.hint {
                e = e.with_hint(hint);
            }
            println!("{}", e.to_json());
            ExitCode::FAILURE
        }
        Err(f) => {
            eprintln!("error: {}", f.message);
            if let Some(hint) = f.hint {
                eprintln!("hint:  {hint}");
            }
            if let Some(docs) = f.docs {
                eprintln!("docs:  {docs}");
            }
            ExitCode::FAILURE
        }
    }
}

/// `kronik init`.
pub fn init(args: InitArgs, json: bool) -> ExitCode {
    report(init::run(&args.name, args.lang), json, init::print)
}

/// `kronik build`.
pub fn build(args: BuildArgs, json: bool) -> ExitCode {
    let built = build::component(&args.dir, args.force, args.entry.as_deref())
        .and_then(|b| build::output(&b));
    // The human summary went to stderr while building.
    report(built, json, |_| {})
}

/// `kronik test-host`.
pub fn test_host(args: TestHostArgs) -> ExitCode {
    report(testhost::run(args), false, |()| {})
}

/// The schema of `kronik init --json` (docs/reference/json.md).
#[cfg(test)]
pub fn init_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<init::Created>()
}

/// The schema of `kronik build --json` (docs/reference/json.md).
#[cfg(test)]
pub fn build_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<build::BuildOutput>()
}
