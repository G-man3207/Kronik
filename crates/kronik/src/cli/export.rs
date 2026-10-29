//! `kronik export status` and `kronik export rewind` (docs/design/m28-otel.md
//! §6.2): the daemon's export streams. Status needs `read`, rewind
//! `operate`.

use std::fmt::Write as _;
use std::process::ExitCode;

use kronik_api::types::{
    ExportRewindRequest, ExportRewindResponse, ExportStatusResponse, ExportStream,
};

use super::render::{next, shell_quote, table};
use super::{Ctx, Error, Mutation, reason, units};

#[derive(Debug, clap::Subcommand)]
pub enum ExportCommand {
    /// Every export stream (traces, audit): sink, cursor, lag, last
    /// success and error, gaps.
    Status,
    /// Move a stream's cursor back, so that the records after `--to` are
    /// sent again (after a sink lost them).
    Rewind {
        /// `traces` or `audit`.
        stream: String,
        /// Resend the records after this LSN.
        #[arg(long, value_name = "LSN")]
        to: u64,
        #[command(flatten)]
        mutation: Mutation,
    },
}

pub(super) fn export(ctx: &Ctx, command: ExportCommand) -> Result<ExitCode, Error> {
    match command {
        ExportCommand::Status => status(ctx),
        ExportCommand::Rewind {
            stream,
            to,
            mutation,
        } => rewind(ctx, &stream, to, mutation),
    }
}

fn rewind(ctx: &Ctx, stream: &str, to: u64, m: Mutation) -> Result<ExitCode, Error> {
    let why = reason(&m)?;
    let body = ctx.post(
        &format!("/v1/export/{stream}/rewind"),
        &ExportRewindRequest {
            to,
            reason: why.to_owned(),
            dry_run: m.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ExportRewindResponse = ctx.decode(&body)?;
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: {} would resend from LSN {} (its cursor is {}); nothing was written",
            r.stream,
            r.to + 1,
            r.from
        );
        out.push_str(&next(&[format!(
            "kronik export rewind {} --to {} --reason {}",
            shell_quote(&r.stream),
            r.to,
            shell_quote(why)
        )]));
    } else {
        let _ = writeln!(
            out,
            "{} resends from LSN {} (its cursor was {})",
            r.stream,
            r.to + 1,
            r.from
        );
        out.push_str(&next(&["kronik export status".to_owned()]));
    }
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn status(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/export")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ExportStatusResponse = ctx.decode(&body)?;
    ctx.print(&render(&r));
    Ok(ExitCode::SUCCESS)
}

fn render(r: &ExportStatusResponse) -> String {
    if r.streams.is_empty() {
        return "No export streams in this daemon.\n".to_owned();
    }
    table(
        &[
            "stream",
            "enabled",
            "sink",
            "cursor",
            "lag",
            "last success",
            "last error",
            "gaps",
        ],
        r.streams.iter().map(row).collect(),
    )
}

fn row(s: &ExportStream) -> Vec<String> {
    let dash = || "-".to_owned();
    vec![
        s.name.clone(),
        if s.enabled { "yes" } else { "no" }.to_owned(),
        if s.sink.is_empty() {
            dash()
        } else {
            s.sink.clone()
        },
        s.cursor.to_string(),
        s.lag.to_string(),
        s.last_success_wall_ms.map_or_else(dash, units::utc),
        s.last_error.clone().unwrap_or_else(dash),
        s.gaps.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_shows_every_stream() {
        let r = ExportStatusResponse {
            streams: vec![ExportStream {
                name: "traces".into(),
                enabled: true,
                sink: "http://127.0.0.1:4318".into(),
                cursor: 40,
                applied_lsn: 42,
                lag: 2,
                last_success_wall_ms: None,
                stalled_ms: Some(60_000),
                last_error: Some("http_503".into()),
                gaps: 1,
            }],
        };
        let text = render(&r);
        assert!(text.contains("traces"), "{text}");
        assert!(text.contains("http://127.0.0.1:4318"), "{text}");
        assert!(text.contains("http_503"), "{text}");
    }
}
