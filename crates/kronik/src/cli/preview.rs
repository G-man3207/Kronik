//! `kronik preview create|list|delete` (M11): preview forks, a fork of
//! HEAD with a proposal's code that takes new requests at its own URL,
//! without live effects (docs/design/m11-preview.md).

use std::fmt::Write as _;
use std::process::ExitCode;

use clap::Subcommand;
use kronik_api::types::{
    PreviewCreateRequest, PreviewCreateResponse, PreviewDeleteResponse, PreviewInfo,
    PreviewsResponse, ResendRequest,
};

use super::render::{field, next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, reason, units};

#[derive(Debug, Subcommand)]
pub enum PreviewCommand {
    /// Create a preview of a proposal: a fork of HEAD with its code that
    /// takes new requests at its URL. No live effects but `[fork]
    /// live_allowlist` GETs.
    Create {
        /// The proposal, e.g. p-1a2b3c4d5e6f.
        proposal: String,
        /// How long it lives, e.g. 2h [default: [fork] preview_ttl, 24h].
        #[arg(long, value_name = "DURATION", value_parser = units::parse_duration_ms)]
        ttl: Option<u64>,
        /// A preview without access to personal data; always so for a
        /// token without pii:read, and when the proposal has it.
        #[arg(long)]
        no_pii: bool,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// List the previews that have not expired, with their URLs.
    List,
    /// Delete a preview and its state; its URL stops answering.
    Delete {
        /// The preview, e.g. v-1a2b3c4d5e6f.
        id: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

pub(super) fn preview(ctx: &Ctx, command: PreviewCommand) -> Result<ExitCode, Error> {
    match command {
        PreviewCommand::Create {
            proposal,
            ttl,
            no_pii,
            mutation,
        } => create(ctx, &proposal, ttl, no_pii, &mutation),
        PreviewCommand::List => list(ctx),
        PreviewCommand::Delete { id, mutation } => delete(ctx, &id, &mutation),
    }
}

fn create(
    ctx: &Ctx,
    proposal: &str,
    ttl: Option<u64>,
    no_pii: bool,
    mutation: &Mutation,
) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let body = ctx.post(
        "/v1/previews",
        &PreviewCreateRequest {
            proposal: proposal.to_owned(),
            ttl_ms: ttl,
            no_pii,
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: PreviewCreateResponse = ctx.decode(&body)?;
    let p = &r.preview;
    let mut out = String::new();
    if r.dry_run {
        let mut rerun = format!("kronik preview create {}", shell_quote(proposal));
        if let Some(ttl) = ttl {
            let _ = write!(rerun, " --ttl {}", units::duration(ttl));
        }
        if no_pii {
            rerun.push_str(" --no-pii");
        }
        let _ = write!(rerun, " --reason {}", shell_quote(reason));
        let _ = writeln!(
            out,
            "Dry run: proposal {} can be previewed at lsn {}; nothing was written",
            p.proposal, p.fork_lsn
        );
        out.push_str(&next(&[rerun]));
    } else {
        let _ = writeln!(
            out,
            "Preview {} of proposal {} at lsn {}",
            p.id, p.proposal, p.fork_lsn
        );
        details(&mut out, p);
        out.push_str(&next(&[
            format!("curl {}", shell_quote(&p.url)),
            format!("kronik diff show {} --md", shell_quote(&p.id)),
            format!(
                "kronik preview delete {} --reason \"...\"",
                shell_quote(&p.id)
            ),
        ]));
    }
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn details(out: &mut String, p: &PreviewInfo) {
    field(out, "URL", std::slice::from_ref(&p.url), "");
    field(out, "Expires", &[units::utc(p.expires_ms)], "");
    if p.no_pii {
        field(out, "Data", &["no personal data (--no-pii)".to_owned()], "");
    }
    field(
        out,
        "Effects",
        &["only allowlisted GETs go live ([fork] live_allowlist)".to_owned()],
        "",
    );
}

fn list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/previews")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: PreviewsResponse = ctx.decode(&body)?;
    let mut out = String::new();
    let Some(first) = r.previews.first() else {
        out.push_str("No previews.\n");
        out.push_str(&next(&[
            "kronik preview create <proposal> --reason \"...\"".to_owned(),
        ]));
        ctx.print(&out);
        return Ok(ExitCode::SUCCESS);
    };
    let rows = r
        .previews
        .iter()
        .map(|p| {
            vec![
                p.id.clone(),
                p.proposal.clone(),
                units::utc(p.expires_ms),
                p.url.clone(),
            ]
        })
        .collect();
    out.push_str(&table(&["PREVIEW", "PROPOSAL", "EXPIRES", "URL"], rows));
    out.push_str(&next(&[format!(
        "kronik diff show {} --md",
        shell_quote(&first.id)
    )]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn delete(ctx: &Ctx, id: &str, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let body = ctx.send_json(
        "DELETE",
        &format!("/v1/previews/{}", http::encode(id)),
        &ResendRequest {
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: PreviewDeleteResponse = ctx.decode(&body)?;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: preview {} can be deleted; nothing was written",
            r.deleted
        );
        out.push_str(&next(&[format!(
            "kronik preview delete {} --reason {}",
            shell_quote(id),
            shell_quote(reason)
        )]));
    } else {
        let _ = writeln!(out, "Deleted preview {}", r.deleted);
        out.push_str(&next(&["kronik preview list".to_owned()]));
    }
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}
