//! `kronik init`, `kronik build` and `kronik test-host`: actor projects in
//! TypeScript, Rust, Python and Go.
//!
//! `init` writes a project with the SDK and the WIT vendored from sources
//! embedded in this binary, so nothing needs a package registry except the
//! public ones for the toolchain and the SDK's own dependencies. `build`
//! turns a project into `dist/<name>.wasm` and checks its imports against
//! the deploy allowlist, as `kronik deploy` would. `test-host` (hidden) runs
//! a project in an in-memory node for the SDKs' testkits.

mod build;
mod build_sdk;
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
    /// Python, built with componentize-py (ADR 0030).
    Python,
    /// Go, built with TinyGo (ADR 0030).
    Go,
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
    /// Build this entry instead of the project's default, as the variant
    /// dist/<name>-<entry's name>.wasm: a TypeScript file (package.json's
    /// `kronik.entry`), a Python module in src/ (`[tool.kronik] entry`) or
    /// a Go package directory (`.`). Rust variants are Cargo features.
    #[arg(long)]
    entry: Option<String>,
}

/// A local error from `init`, `build` and `test-host`.
///
/// Human output matches [`crate::cli::report_error`]: the stable code, the
/// message, a hint (the code's default when none was set) and the
/// documentation command. `--json` prints the standard error object, using
/// that same default hint.
#[derive(Debug)]
pub struct Failure {
    code: ErrorCode,
    message: String,
    hint: Option<String>,
}

impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Failure {
            code: ErrorCode::BadRequest,
            message: message.into(),
            hint: None,
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

    /// The error JSON. A missing hint becomes the code's default, as
    /// [`ApiError::new`] does.
    fn api_error(self) -> ApiError {
        self.into_error(false)
    }

    /// The human form. A message that already starts with its code (the
    /// import check keeps that prefix in JSON) is not printed twice.
    fn human_error(self) -> ApiError {
        self.into_error(true)
    }

    fn into_error(self, human: bool) -> ApiError {
        let code = self.code;
        let mut message = self.message;
        if human {
            let prefix = format!("{code}: ");
            if let Some(rest) = message.strip_prefix(&prefix) {
                message = rest.to_owned();
            }
        }
        let mut error = ApiError::new(code, message);
        if let Some(hint) = self.hint {
            error = error.with_hint(hint);
        }
        error
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
            println!("{}", f.api_error().to_json());
            ExitCode::FAILURE
        }
        Err(f) => crate::cli::report_error(false, &f.human_error()),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn nameless_package() -> Failure {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        match build::component(dir.path(), false, None) {
            Err(failure) => failure,
            Ok(_) => panic!("a package.json with no name must fail the build"),
        }
    }

    /// I12: a package.json with no name is a coded human error, and the
    /// JSON object keeps the message without a second copy of the code.
    #[test]
    fn a_nameless_package_json_names_its_code() {
        let human = crate::cli::render_error(&nameless_package().human_error());
        assert!(
            human.starts_with("error: BAD_REQUEST: package.json has no name\n"),
            "{human}"
        );
        assert!(human.contains("\nhint:  "), "{human}");
        assert!(
            human.ends_with("docs:  kronik explain BAD_REQUEST\n"),
            "{human}"
        );

        let json = nameless_package().api_error().to_json();
        assert_eq!(json["error"]["code"], "BAD_REQUEST");
        assert_eq!(json["error"]["message"], "package.json has no name");
        assert!(json["error"]["hint"].is_string());
        assert_eq!(json["error"]["docs"], "kronik explain BAD_REQUEST");
    }

    /// The import check's message already starts with its code, for JSON.
    /// The human line must not repeat it.
    #[test]
    fn a_coded_message_is_not_repeated_for_a_person() {
        let failure = Failure::new(format!(
            "{}: the component imports interfaces outside the allowlist: wasi:filesystem",
            ErrorCode::ImportNotAllowed
        ))
        .code(ErrorCode::ImportNotAllowed)
        .hint("remove the code that uses them");
        let json = failure.api_error();
        assert_eq!(
            json.message,
            "IMPORT_NOT_ALLOWED: the component imports interfaces outside the allowlist: wasi:filesystem"
        );
        let failure = Failure::new(format!(
            "{}: the component imports interfaces outside the allowlist: wasi:filesystem",
            ErrorCode::ImportNotAllowed
        ))
        .code(ErrorCode::ImportNotAllowed)
        .hint("remove the code that uses them");
        let human = crate::cli::render_error(&failure.human_error());
        assert!(
            human.starts_with(
                "error: IMPORT_NOT_ALLOWED: the component imports interfaces outside the allowlist: wasi:filesystem\n"
            ),
            "{human}"
        );
        assert!(
            !human.contains("IMPORT_NOT_ALLOWED: IMPORT_NOT_ALLOWED"),
            "{human}"
        );
    }
}
