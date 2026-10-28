//! `kronik stubs set` and `kronik simulators list` (M12): how a fork answers
//! effects without a recording (docs/design/m12-simulators.md §6).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use kronik_api::m12::{SimulatorsResponse, SimulatorsSetRequest, SimulatorsSetResponse};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_fork::stubs::StubRule;

use super::render::{next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, read_file, reason};

#[derive(Debug, Subcommand)]
pub enum StubsCommand {
    /// Replace a target's simulator configuration with a TOML file:
    /// [[stub]] tables {method?, url_prefix, status?, headers?, body?} or
    /// {url_prefix, error}, `contract = "openapi.json"` (relative to the
    /// file), `neighbor = true`, `model = true`. An empty file clears it.
    Set {
        /// `http:<host>` or `foreign:<name>`.
        target: String,
        /// The rules file.
        rules: PathBuf,
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, Subcommand)]
pub enum SimulatorsCommand {
    /// The simulators, in the order they are tried, and each target's
    /// configuration.
    List,
}

/// A `kronik stubs set` rules file.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    stub: Vec<StubRule>,
    #[serde(default)]
    contract: Option<PathBuf>,
    #[serde(default)]
    neighbor: bool,
    #[serde(default)]
    model: bool,
}

fn bad(path: &Path, e: impl std::fmt::Display) -> Error {
    ApiError::new(
        ErrorCode::BadRequest,
        format!("{} is not a simulator rules file: {e}", path.display()),
    )
    .with_hint(
        "Give [[stub]] tables {method?, url_prefix, status?, headers?, body?} or \
         {url_prefix, error}, and optionally contract = \"openapi.json\", neighbor = true, \
         model = true.",
    )
    .into()
}

/// The request a rules file stands for; the contract path is relative to
/// the file.
pub(super) fn read_rules(path: &Path) -> Result<SimulatorsSetRequest, Error> {
    let text = read_file(path, "the simulator rules file")?;
    let text = String::from_utf8(text).map_err(|_| bad(path, "not UTF-8 text"))?;
    let f: RulesFile = toml::from_str(&text).map_err(|e| bad(path, e))?;
    let contract = match f.contract {
        None => None,
        Some(c) => {
            let c = path.parent().map_or(c.clone(), |d| d.join(&c));
            let bytes = read_file(&c, "the contract")?;
            let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                Error::from(
                    ApiError::new(
                        ErrorCode::BadRequest,
                        format!("the contract {} is not JSON: {e}", c.display()),
                    )
                    .with_hint("Give an OpenAPI 3 document in JSON."),
                )
            })?;
            Some(doc)
        }
    };
    Ok(SimulatorsSetRequest {
        stubs: f.stub,
        contract,
        neighbor: f.neighbor,
        model: f.model,
        reason: String::new(),
        dry_run: false,
    })
}

pub(super) fn stubs(ctx: &Ctx, command: StubsCommand) -> Result<ExitCode, Error> {
    let StubsCommand::Set {
        target,
        rules,
        mutation,
    } = command;
    let reason = reason(&mutation)?;
    let mut body = read_rules(&rules)?;
    body.reason = reason.to_owned();
    body.dry_run = mutation.dry_run;
    let summary = describe(&body);
    let raw = ctx.send_json(
        "PUT",
        &format!("/v1/simulators/{}", http::encode(&target)),
        &body,
    )?;
    if ctx.json {
        ctx.print_raw(&raw);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SimulatorsSetResponse = ctx.decode(&raw)?;
    let mut out = if r.dry_run {
        format!(
            "Dry run: {} would get {summary} at epoch {}. Nothing was written.\n",
            r.target, r.epoch
        )
    } else {
        format!(
            "{} now has {summary} (epoch {}, LSN {}).\n",
            r.target, r.epoch, r.lsn
        )
    };
    let cmd = if r.dry_run {
        format!(
            "kronik stubs set {} {} --reason {}",
            shell_quote(&r.target),
            shell_quote(&rules.display().to_string()),
            shell_quote(reason)
        )
    } else {
        "kronik simulators list".to_owned()
    };
    out.push_str(&next(&[cmd]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

/// `2 stub rules, a contract, neighbor` or `no simulators`.
fn describe(r: &SimulatorsSetRequest) -> String {
    let mut parts = Vec::new();
    if !r.stubs.is_empty() {
        parts.push(format!(
            "{} stub rule{}",
            r.stubs.len(),
            if r.stubs.len() == 1 { "" } else { "s" }
        ));
    }
    if r.contract.is_some() {
        parts.push("a contract".to_owned());
    }
    if r.neighbor {
        parts.push("neighbor".to_owned());
    }
    if r.model {
        parts.push("model".to_owned());
    }
    if parts.is_empty() {
        "no simulators".to_owned()
    } else {
        parts.join(", ")
    }
}

pub(super) fn simulators(ctx: &Ctx, command: SimulatorsCommand) -> Result<ExitCode, Error> {
    let SimulatorsCommand::List = command;
    let body = ctx.get("/v1/simulators")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SimulatorsResponse = ctx.decode(&body)?;
    ctx.print(&render_list(&r));
    Ok(ExitCode::SUCCESS)
}

fn render_list(r: &SimulatorsResponse) -> String {
    let mut out = table(
        &["SIMULATOR", "GROUNDING", "DESCRIPTION"],
        r.simulators
            .iter()
            .map(|s| vec![s.name.clone(), s.grounding.clone(), s.description.clone()])
            .collect(),
    );
    let _ = writeln!(
        out,
        "\nModel: {}",
        match (&r.model.model, &r.model.endpoint_host) {
            (Some(m), Some(h)) => format!("{m} at {h}"),
            (Some(m), None) => m.clone(),
            _ => "not configured ([simulators.model] in kronik.toml)".to_owned(),
        }
    );
    out.push('\n');
    if r.targets.is_empty() {
        out.push_str("No target has simulators.\n");
        out.push_str(&next(&[
            "kronik stubs set http:<host> rules.toml --reason \"...\"".to_owned(),
        ]));
        return out;
    }
    let yes = |b: bool| if b { "yes" } else { "-" }.to_owned();
    out.push_str(&table(
        &[
            "TARGET", "STUBS", "CONTRACT", "NEIGHBOR", "MODEL", "EPOCH", "REASON",
        ],
        r.targets
            .iter()
            .map(|t| {
                vec![
                    t.target.clone(),
                    t.stubs.to_string(),
                    t.contract.as_ref().map_or_else(
                        || "-".to_owned(),
                        |c| c.title.clone().unwrap_or_else(|| c.digest.clone()),
                    ),
                    yes(t.neighbor),
                    yes(t.model),
                    t.epoch.to_string(),
                    t.reason.clone(),
                ]
            })
            .collect(),
    ));
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn rules_files_resolve_the_contract_and_reject_unknown_keys() {
        let dir = std::env::temp_dir().join(format!("kronik-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("api.json"), br#"{"openapi":"3.0.0","paths":{}}"#).unwrap();
        let rules = dir.join("rules.toml");
        std::fs::write(
            &rules,
            "contract = \"api.json\"\nneighbor = true\n[[stub]]\nurl_prefix = \"https://a.example/x\"\n",
        )
        .unwrap();
        let read = |p: &Path| read_rules(p).ok().unwrap();
        let r = read(&rules);
        assert_eq!(r.stubs.len(), 1);
        assert!(r.neighbor && !r.model);
        assert_eq!(r.contract.unwrap()["openapi"], "3.0.0");
        assert_eq!(describe(&read(&rules)), "1 stub rule, a contract, neighbor");
        std::fs::write(&rules, "").unwrap();
        assert_eq!(describe(&read(&rules)), "no simulators");
        std::fs::write(&rules, "modle = true\n").unwrap();
        assert!(read_rules(&rules).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
