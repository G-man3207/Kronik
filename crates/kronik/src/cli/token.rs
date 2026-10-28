//! `kronik token create|list|revoke` (M5): API tokens, bearer credentials
//! with scopes. A client sends one as `Authorization: Bearer`; the CLI and
//! `kronik mcp` send `$KRONIK_TOKEN`.

use std::fmt::Write as _;
use std::process::ExitCode;

use clap::Subcommand;
use kronik_api::types::{
    TokenCreateRequest, TokenCreateResponse, TokenRevokeRequest, TokenRevokeResponse, TokenView,
    TokensResponse,
};

use super::render::{field, next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, reason, units};

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a token. It is printed once and stored only as a hash.
    Create {
        /// The token's name, e.g. agent-1: a lowercase letter, then
        /// lowercase letters, digits and dashes. Recorded as
        /// `token:<name>` with everything the token does; never reused.
        #[arg(long)]
        name: String,
        /// Comma-separated scopes: read, fork, propose, approve, promote,
        /// operate, pii:read, admin [default: read,fork,propose, an agent's].
        #[arg(long, value_delimiter = ',')]
        scopes: Option<Vec<String>>,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// List the tokens, live and revoked: names, scopes and who created
    /// them, never the tokens.
    List,
    /// Revoke a token: from now on it authenticates nobody.
    Revoke {
        /// The token's name.
        name: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

pub(super) fn token(ctx: &Ctx, command: TokenCommand) -> Result<ExitCode, Error> {
    match command {
        TokenCommand::Create {
            name,
            scopes,
            mutation,
        } => create(ctx, &name, scopes, &mutation),
        TokenCommand::List => list(ctx),
        TokenCommand::Revoke { name, mutation } => revoke(ctx, &name, &mutation),
    }
}

fn create(
    ctx: &Ctx,
    name: &str,
    scopes: Option<Vec<String>>,
    mutation: &Mutation,
) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let rerun = {
        let mut cmd = format!("kronik token create --name {}", shell_quote(name));
        if let Some(scopes) = &scopes {
            let _ = write!(cmd, " --scopes {}", shell_quote(&scopes.join(",")));
        }
        let _ = write!(cmd, " --reason {}", shell_quote(reason));
        cmd
    };
    let body = ctx.post(
        "/v1/tokens",
        &TokenCreateRequest {
            name: name.to_owned(),
            scopes,
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: TokenCreateResponse = ctx.decode(&body)?;
    ctx.print(&render_created(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/tokens")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: TokensResponse = ctx.decode(&body)?;
    ctx.print(&render_list(&r));
    Ok(ExitCode::SUCCESS)
}

fn revoke(ctx: &Ctx, name: &str, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let body = ctx.post(
        &format!("/v1/tokens/{}/revoke", http::encode(name)),
        &TokenRevokeRequest {
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: TokenRevokeResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik token revoke {} --reason {}",
        shell_quote(name),
        shell_quote(reason)
    );
    ctx.print(&render_revoked(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn render_created(r: &TokenCreateResponse, rerun: &str) -> String {
    let t = &r.token;
    let mut out = String::new();
    let Some(secret) = &r.secret else {
        let _ = writeln!(
            out,
            "Dry run: token {} can be created with the scopes {}; nothing was written",
            t.name,
            t.scopes.join(", ")
        );
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    };
    let _ = writeln!(out, "Created token {}, recorded as {}", t.name, t.token_id);
    field(&mut out, "Scopes", &[t.scopes.join(", ")], "");
    field(&mut out, "Token", std::slice::from_ref(secret), "");
    out.push_str(
        "This is the only time the token is shown; Kronik keeps only its hash.\n\
         Give it to its holder through a secret store, not a chat or a ticket.\n",
    );
    out.push_str(&next(&[
        "KRONIK_TOKEN=<token> kronik <command>   (the CLI as this token)".to_owned(),
        "KRONIK_TOKEN=<token> kronik mcp   (an agent's MCP server, as this token)".to_owned(),
        format!(
            "kronik token revoke {} --reason \"...\"",
            shell_quote(&t.name)
        ),
    ]));
    out
}

fn state(t: &TokenView) -> String {
    match t.revoked_wall_ms {
        Some(ms) => format!("revoked {}", units::utc(ms)),
        None => "live".to_owned(),
    }
}

fn render_list(r: &TokensResponse) -> String {
    if r.tokens.is_empty() {
        let mut out = String::from("No tokens.\n");
        out.push_str(&next(&[
            "kronik token create --name <name> --scopes read,fork,propose --reason \"...\""
                .to_owned(),
        ]));
        return out;
    }
    let rows = r
        .tokens
        .iter()
        .map(|t| {
            vec![
                t.name.clone(),
                t.scopes.join(","),
                units::utc(t.created_wall_ms),
                t.created_by.clone(),
                state(t),
            ]
        })
        .collect();
    let mut out = table(&["NAME", "SCOPES", "CREATED", "BY", "STATE"], rows);
    out.push_str(&next(&[
        "kronik token revoke <name> --reason \"...\"".to_owned()
    ]));
    out
}

fn render_revoked(r: &TokenRevokeResponse, rerun: &str) -> String {
    let t = &r.token;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: token {} can be revoked; nothing was written",
            t.name
        );
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    let _ = writeln!(
        out,
        "Revoked token {}: it authenticates nobody from now on",
        t.name
    );
    field(&mut out, "Scopes", &[t.scopes.join(", ")], "");
    out.push_str(&next(&["kronik token list".to_owned()]));
    out
}
