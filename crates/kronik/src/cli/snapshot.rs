//! `kronik snapshot list`, `kronik snapshot create` and `kronik integrity`
//! (docs/design/m6-storage.md §2, §8). They talk to the daemon: list and
//! integrity need `read`, create needs `operate`.

use std::fmt::Write as _;
use std::process::ExitCode;

use kronik_api::types::{
    IntegrityResponse, SnapshotCreateRequest, SnapshotCreateResponse, SnapshotEntry,
    SnapshotsResponse,
};

use super::render::{field, next, shell_quote, table};
use super::{Ctx, Error, Mutation, reason, units};

#[derive(Debug, clap::Subcommand)]
pub enum SnapshotCommand {
    /// List snapshots of main, newest first.
    List,
    /// Take a snapshot now: state, actor databases and secrets at one LSN.
    Create(CreateArgs),
}

#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    #[command(flatten)]
    mutation: Mutation,
}

pub(super) fn snapshot(ctx: &Ctx, command: SnapshotCommand) -> Result<ExitCode, Error> {
    match command {
        SnapshotCommand::List => list(ctx),
        SnapshotCommand::Create(a) => create(ctx, a),
    }
}

pub(super) fn integrity(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/integrity")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: IntegrityResponse = ctx.decode(&body)?;
    let mut out = String::new();
    let _ = writeln!(out, "Applied LSN   {}", r.applied_lsn);
    let _ = writeln!(out, "State hash    {}", r.state_hash);
    let _ = writeln!(out, "Log hash      {}", r.log_hash);
    let _ = writeln!(out, "Log first LSN {}", r.log_first_lsn);
    let _ = writeln!(
        out,
        "Window        {} back from logical time {} (cutoff {})",
        history_label(r.retention_history_ms),
        r.newest_logical_time_ms,
        r.retention_cutoff_ms
    );
    out.push_str(&next(&["kronik snapshot list".to_owned()]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn list(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/snapshots")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SnapshotsResponse = ctx.decode(&body)?;
    ctx.print(&render_list(&r));
    Ok(ExitCode::SUCCESS)
}

fn create(ctx: &Ctx, a: CreateArgs) -> Result<ExitCode, Error> {
    let why = reason(&a.mutation)?;
    let body = ctx.post(
        "/v1/snapshots",
        &SnapshotCreateRequest {
            reason: why.to_owned(),
            dry_run: a.mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: SnapshotCreateResponse = ctx.decode(&body)?;
    let rerun = format!("kronik snapshot create --reason {}", shell_quote(why));
    ctx.print(&render_create(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn render_list(r: &SnapshotsResponse) -> String {
    if r.snapshots.is_empty() {
        let mut out = String::from("No snapshots yet.\n");
        out.push_str(&next(&[
            "kronik snapshot create --reason \"...\"".to_owned()
        ]));
        return out;
    }
    let rows = r.snapshots.iter().map(row).collect();
    let mut out = table(
        &[
            "id",
            "lsn",
            "state hash",
            "bytes",
            "reason",
            "shipped",
            "created",
        ],
        rows,
    );
    out.push_str(&next(&[
        "kronik snapshot create --reason \"...\"".to_owned()
    ]));
    out
}

fn row(s: &SnapshotEntry) -> Vec<String> {
    vec![
        s.id.clone(),
        s.lsn.to_string(),
        s.state_hash.clone(),
        units::size(s.bytes),
        s.reason.clone(),
        if s.shipped { "yes" } else { "no" }.to_owned(),
        units::utc(s.created_wall_ms),
    ]
}

/// The retention window in English. Days when they divide evenly; otherwise
/// the shared duration helper (`168h`, `10s`, `0ms`).
fn history_label(ms: u64) -> String {
    const DAY: u64 = 86_400_000;
    if ms >= DAY && ms.is_multiple_of(DAY) {
        let n = ms / DAY;
        if n == 1 {
            "1 day".to_owned()
        } else {
            format!("{n} days")
        }
    } else {
        units::duration(ms)
    }
}

fn render_create(r: &SnapshotCreateResponse, rerun: &str) -> String {
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: a snapshot of main at lsn {} would be taken; nothing was written",
            r.lsn
        );
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    let Some(s) = &r.snapshot else {
        let _ = writeln!(
            out,
            "No snapshot was taken (nothing applied since the last one); applied lsn {}",
            r.lsn
        );
        out.push_str(&next(&["kronik snapshot list".to_owned()]));
        return out;
    };
    let _ = writeln!(out, "Snapshot {} at lsn {}", s.id, s.lsn);
    field(
        &mut out,
        "State hash",
        std::slice::from_ref(&s.state_hash),
        "",
    );
    field(&mut out, "Bytes", &[units::size(s.bytes)], "");
    out.push_str(&next(&["kronik snapshot list".to_owned()]));
    out
}
