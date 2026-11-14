//! `kronik blobs status`, `inspect`, `get` and `gc` (M25 §15, M26 §12):
//! the blob store and its collector. All talk to the daemon: status,
//! inspect, get and the dry run need `read` (and `get` of a subject's blob
//! `pii:read`), a pass needs `operate`.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kronik_api::types::{
    BlobGcPlanResponse, BlobGcRequest, BlobGcResponse, BlobInspectResponse, BlobsStatusResponse,
};
use kronik_core::error::{ApiError, ErrorCode};

use super::render::{next, shell_quote, table};
use super::{Ctx, Error, Mutation, http, units};

#[derive(Debug, clap::Subcommand)]
pub enum BlobsCommand {
    /// The blob store: the blobs its index keeps, the floor, leases, free
    /// disk and reserve, and the collector's last pass.
    Status,
    /// One blob: its size, subject, referencing LSNs, state and what keeps
    /// it.
    Inspect(InspectArgs),
    /// Write a blob's bytes, through the secret output matcher, to a file
    /// or standard output.
    Get(GetArgs),
    /// The collector: with --dry-run alone, list the blob files nothing
    /// keeps and why; with --reason, run a pass now.
    Gc(GcArgs),
}

#[derive(Debug, clap::Args)]
pub struct InspectArgs {
    /// The blob's hash: b3:<64 hex>, or b3s:<64 hex> for a subject's blob.
    hash: String,
    /// Also read and check the whole file.
    #[arg(long)]
    verify: bool,
}

#[derive(Debug, clap::Args)]
pub struct GetArgs {
    /// The blob's hash.
    hash: String,
    /// Write to this file (created or replaced) instead of standard output.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct GcArgs {
    /// Delete every file without a root now, without waiting a pass.
    #[arg(long)]
    immediate: bool,
    #[command(flatten)]
    mutation: Mutation,
}

pub(super) fn blobs(ctx: &Ctx, command: BlobsCommand) -> Result<ExitCode, Error> {
    match command {
        BlobsCommand::Status => status(ctx),
        BlobsCommand::Inspect(a) => inspect(ctx, a),
        BlobsCommand::Get(a) => get(ctx, a),
        BlobsCommand::Gc(a) => gc(ctx, a),
    }
}

/// A hash for a path segment: hex, `b3:` or `b3s:`; anything else is
/// percent-encoded, and the daemon refuses it.
fn segment(hash: &str) -> String {
    http::encode(hash)
}

fn status(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/blobs")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: BlobsStatusResponse = ctx.decode(&body)?;
    ctx.print(&render_status(&r));
    Ok(ExitCode::SUCCESS)
}

fn render_status(r: &BlobsStatusResponse) -> String {
    let mut out = String::new();
    if !r.enabled {
        out.push_str("Blobs are off in this daemon.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "Indexed      {} blobs, {}",
        r.indexed,
        units::size(r.indexed_bytes)
    );
    if let Some(floor) = r.floor {
        let _ = writeln!(out, "Floor        lsn {floor}");
    }
    let _ = writeln!(out, "Leases       {}", r.leases);
    let free = r.free_bytes.map_or("unknown".to_owned(), units::size);
    let _ = writeln!(
        out,
        "Disk         {free} free, reserve {}{}",
        units::size(r.reserve_bytes),
        if r.below_reserve {
            ": BELOW RESERVE, new blobs are refused"
        } else {
            ""
        }
    );
    match &r.last_gc {
        Some(g) => {
            let _ = writeln!(
                out,
                "Last pass    {} files ({}) left, {} deleted ({}), {} candidates, floor lsn {}",
                g.objects,
                units::size(g.bytes),
                g.deleted,
                units::size(g.deleted_bytes),
                g.candidates,
                g.floor
            );
        }
        None => out.push_str("Last pass    none since the daemon started\n"),
    }
    out.push_str(&next(&["kronik blobs gc --dry-run".to_owned()]));
    out
}

fn inspect(ctx: &Ctx, a: InspectArgs) -> Result<ExitCode, Error> {
    let mut path = format!("/v1/blobs/{}", segment(&a.hash));
    if a.verify {
        path.push_str("?verify=true");
    }
    let body = ctx.get(&path)?;
    let r: BlobInspectResponse = ctx.decode(&body)?;
    // A file that does not check out is a failed check, not a detail.
    let status = if r.verified == Some(false) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(status);
    }
    ctx.print(&render_inspect(&r));
    Ok(status)
}

fn render_inspect(r: &BlobInspectResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Blob         {}", r.hash);
    let _ = writeln!(out, "State        {}", r.state);
    if let Some(size) = r.size {
        let _ = writeln!(out, "Size         {}", units::size(size));
    }
    if let Some(subject) = &r.subject {
        let _ = writeln!(
            out,
            "Subject      {subject} (key version {})",
            r.key_version.unwrap_or(0)
        );
    }
    if let (Some(first), Some(last)) = (r.first_ref_lsn, r.last_ref_lsn) {
        let _ = writeln!(out, "Referenced   lsn {first} to lsn {last}");
    }
    if let Some(sealed) = r.sealed {
        let _ = writeln!(out, "Sealed       {}", if sealed { "yes" } else { "no" });
    }
    if let Some(bytes) = r.file_bytes {
        let _ = writeln!(out, "File         {}", units::size(bytes));
    }
    match (r.verified, &r.verify_error) {
        (Some(true), _) => out.push_str("Verified     the whole file checks out\n"),
        (Some(false), Some(e)) => {
            let _ = writeln!(out, "Verified     FAILED: {e}");
        }
        _ => {}
    }
    if r.roots.is_empty() {
        out.push_str("Kept by      nothing: the collector deletes it\n");
    } else {
        let rows = r
            .roots
            .iter()
            .map(|root| {
                let detail = match root.kind.as_str() {
                    "log" => format!(
                        "a record at lsn {} (floor lsn {})",
                        root.lsn.unwrap_or(0),
                        root.floor.unwrap_or(0)
                    ),
                    "pin" => format!(
                        "{} {} (lsn {})",
                        root.source.as_deref().unwrap_or(""),
                        root.owner.as_deref().unwrap_or(""),
                        root.lsn.unwrap_or(0)
                    ),
                    "snapshot" => format!("snapshot at lsn {}", root.lsn.unwrap_or(0)),
                    "fork" => format!("fork {}", root.fork.as_deref().unwrap_or("")),
                    _ => "a lease of the daemon (a turn, upload, stream or replay)".to_owned(),
                };
                vec![root.kind.clone(), detail]
            })
            .collect();
        out.push_str("Kept by\n");
        out.push_str(&table(&["root", "what"], rows));
    }
    out.push_str(&next(&[format!(
        "kronik blobs get {} -o FILE",
        shell_quote(&r.hash)
    )]));
    out
}

fn get(ctx: &Ctx, a: GetArgs) -> Result<ExitCode, Error> {
    let target = format!("/v1/blobs/{}/content", segment(&a.hash));
    let response = ctx.stream(&target)?;
    let mut body = response.body;
    if !(200..300).contains(&response.status) {
        let mut text = Vec::new();
        body.take(1 << 20)
            .read_to_end(&mut text)
            .map_err(|e| unavailable(format!("reading the daemon's error failed: {e}")))?;
        return Err(Error::Remote {
            status: response.status,
            body: text,
        });
    }
    let written = match &a.output {
        Some(path) => {
            // Into a temporary file next to the target, renamed when the
            // whole blob arrived: a cut stream leaves no partial file.
            let dir = path
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let mut tmp = tempfile::NamedTempFile::new_in(dir)
                .map_err(|e| local(format!("creating a file in {} failed: {e}", dir.display())))?;
            let n = std::io::copy(&mut body, &mut tmp)
                .map_err(|e| unavailable(format!("the download stopped: {e}")))?;
            tmp.as_file()
                .sync_all()
                .map_err(|e| local(format!("writing {} failed: {e}", path.display())))?;
            tmp.persist(path)
                .map_err(|e| local(format!("writing {} failed: {}", path.display(), e.error)))?;
            n
        }
        None => {
            let mut out = std::io::stdout().lock();
            let n = std::io::copy(&mut body, &mut out)
                .map_err(|e| unavailable(format!("the download stopped: {e}")))?;
            out.flush()
                .map_err(|e| local(format!("writing standard output failed: {e}")))?;
            n
        }
    };
    if let Some(path) = &a.output {
        if ctx.json {
            let v = serde_json::json!({"hash": a.hash, "path": path, "bytes": written});
            ctx.print_raw(v.to_string().as_bytes());
        } else {
            ctx.print(&format!(
                "Wrote {} ({}) to {}\n",
                a.hash,
                units::size(written),
                path.display()
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn gc(ctx: &Ctx, a: GcArgs) -> Result<ExitCode, Error> {
    // `--dry-run` alone reads the plan with `read`; a pass needs a reason.
    if a.mutation.dry_run && a.mutation.reason.is_none() {
        let body = ctx.get("/v1/blobs/gc")?;
        if ctx.json {
            ctx.print_raw(&body);
            return Ok(ExitCode::SUCCESS);
        }
        let r: BlobGcPlanResponse = ctx.decode(&body)?;
        ctx.print(&render_plan(&r));
        return Ok(ExitCode::SUCCESS);
    }
    let why = super::reason(&a.mutation)?;
    let body = ctx.post(
        "/v1/blobs/gc",
        &BlobGcRequest {
            reason: why.to_owned(),
            dry_run: a.mutation.dry_run,
            immediate: a.immediate,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: BlobGcResponse = ctx.decode(&body)?;
    let mut out = String::new();
    if !r.enabled {
        out.push_str("Blobs are off in this daemon: nothing to collect.\n");
    } else if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: a pass now would delete {} files ({}) and keep {} candidates for the next one.",
            r.deleted,
            units::size(r.bytes),
            r.candidates
        );
    } else {
        let _ = writeln!(
            out,
            "Deleted {} files ({}); {} candidates for the next pass; {} files left.",
            r.deleted,
            units::size(r.bytes),
            r.candidates,
            r.objects
        );
    }
    out.push_str(&next(&["kronik blobs status".to_owned()]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn render_plan(r: &BlobGcPlanResponse) -> String {
    let mut out = String::new();
    if !r.enabled {
        out.push_str("Blobs are off in this daemon.\n");
        return out;
    }
    if r.blobs.is_empty() {
        let _ = writeln!(out, "Nothing to collect: all {} files have a root.", r.kept);
        return out;
    }
    let rows = r
        .blobs
        .iter()
        .map(|b| {
            vec![
                b.hash.clone(),
                b.reason.clone(),
                units::size(b.bytes),
                b.last_ref_lsn.map_or("-".to_owned(), |l| l.to_string()),
                if b.candidate {
                    "next pass"
                } else {
                    "pass after"
                }
                .to_owned(),
            ]
        })
        .collect();
    out.push_str(&table(
        &["blob", "reason", "bytes", "last lsn", "deleted by"],
        rows,
    ));
    let _ = writeln!(
        out,
        "{} files ({}) without a root; {} kept; floor lsn {}.",
        r.count,
        units::size(r.bytes),
        r.kept,
        r.floor.unwrap_or(0)
    );
    out.push_str(&next(&[
        "kronik blobs gc --reason \"...\"".to_owned(),
        "kronik blobs gc --immediate --reason \"...\"".to_owned(),
    ]));
    out
}

fn local(message: String) -> Error {
    Error::Local(ApiError::new(ErrorCode::BadRequest, message))
}

fn unavailable(message: String) -> Error {
    Error::Local(ApiError::new(ErrorCode::Unavailable, message))
}
