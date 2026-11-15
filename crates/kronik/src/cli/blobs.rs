//! `kronik blobs status`, `inspect`, `get`, `list` and `gc` (M25 §15, M26
//! §12): the blob store, what actors hold, and the collector. All talk to
//! the daemon: status, inspect, get, list and the dry run need `read` (and
//! `get` of a subject's blob `pii:read`), a pass needs `operate`.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use kronik_api::types::{
    ActorBlobsResponse, BlobGcPlanResponse, BlobGcRequest, BlobGcResponse, BlobInspectResponse,
    BlobsStatusResponse,
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
    /// The blobs an actor holds, by hash.
    List(ListArgs),
    /// The collector: with --dry-run alone, list the blob files nothing
    /// keeps and why; with --reason, run a pass now.
    Gc(GcArgs),
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// The actor, as kind/key.
    #[arg(long, value_name = "KIND/KEY")]
    actor: String,
    /// Start after this hash (the `next` of the previous page).
    #[arg(long)]
    after: Option<String>,
    /// At most this many (1 to 1000; default 100).
    #[arg(long)]
    limit: Option<u32>,
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
    /// With --dry-run alone: also check the index's pins against the rows
    /// they mirror; any difference (drift) exits with 1.
    #[arg(long)]
    verify: bool,
    #[command(flatten)]
    mutation: Mutation,
}

pub(super) fn blobs(ctx: &Ctx, command: BlobsCommand) -> Result<ExitCode, Error> {
    match command {
        BlobsCommand::Status => status(ctx),
        BlobsCommand::Inspect(a) => inspect(ctx, a),
        BlobsCommand::Get(a) => get(ctx, a),
        BlobsCommand::List(a) => list(ctx, a),
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
        out.push_str("This node has no blob store.\n");
        return out;
    }
    let _ = writeln!(
        out,
        "Indexed      {} blobs, {}",
        r.indexed,
        units::rounded_size(r.indexed_bytes)
    );
    if let Some(floor) = r.floor {
        let _ = writeln!(out, "Floor        lsn {floor}");
    }
    let _ = writeln!(out, "Leases       {}", r.leases);
    let free = r
        .free_bytes
        .map_or("unknown".to_owned(), units::rounded_size);
    let _ = writeln!(
        out,
        "Disk         {free} free, reserve {}{}",
        units::rounded_size(r.reserve_bytes),
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
                units::rounded_size(g.bytes),
                g.deleted,
                units::rounded_size(g.deleted_bytes),
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
        let _ = writeln!(out, "Size         {}", units::rounded_size(size));
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
        let _ = writeln!(out, "File         {}", units::rounded_size(bytes));
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
                    "held" => format!(
                        "held by {} (lsn {})",
                        root.actor.as_deref().unwrap_or(""),
                        root.lsn.unwrap_or(0)
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
                units::rounded_size(written),
                path.display()
            ));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn list(ctx: &Ctx, a: ListArgs) -> Result<ExitCode, Error> {
    let Some((kind, key)) = a.actor.split_once('/') else {
        return Err(local(format!("--actor {:?} is not kind/key", a.actor)));
    };
    let mut query = Vec::new();
    if let Some(after) = &a.after {
        query.push(format!("after={}", http::encode(after)));
    }
    if let Some(limit) = a.limit {
        query.push(format!("limit={limit}"));
    }
    let mut path = format!(
        "/v1/actors/{}/{}/blobs",
        http::encode(kind),
        http::encode(key)
    );
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    let body = ctx.get(&path)?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ActorBlobsResponse = ctx.decode(&body)?;
    ctx.print(&render_list(&a.actor, &r));
    Ok(ExitCode::SUCCESS)
}

fn render_list(actor: &str, r: &ActorBlobsResponse) -> String {
    let mut out = String::new();
    if r.blobs.is_empty() {
        let _ = writeln!(out, "{actor} holds no blob.");
        return out;
    }
    let rows = r
        .blobs
        .iter()
        .map(|b| {
            vec![
                b.hash.clone(),
                units::rounded_size(b.size),
                b.subject.clone().unwrap_or_else(|| "-".to_owned()),
                b.lsn.to_string(),
            ]
        })
        .collect();
    out.push_str(&table(&["blob", "size", "subject", "held since lsn"], rows));
    let mut steps = Vec::new();
    if let Some(after) = &r.next {
        steps.push(format!(
            "kronik blobs list --actor {} --after {}",
            shell_quote(actor),
            shell_quote(after)
        ));
    }
    if let Some(first) = r.blobs.first() {
        steps.push(format!("kronik blobs inspect {}", shell_quote(&first.hash)));
    }
    out.push_str(&next(&steps));
    out
}

fn gc(ctx: &Ctx, a: GcArgs) -> Result<ExitCode, Error> {
    // `--dry-run` alone reads the plan with `read`; a pass needs a reason.
    if a.mutation.dry_run && a.mutation.reason.is_none() {
        let path = if a.verify {
            "/v1/blobs/gc?verify=true"
        } else {
            "/v1/blobs/gc"
        };
        let body = ctx.get(path)?;
        let r: BlobGcPlanResponse = ctx.decode(&body)?;
        // Drift is a failed check, not a detail.
        let status = if r.drift.as_ref().is_some_and(|d| !d.is_empty()) {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
        if ctx.json {
            ctx.print_raw(&body);
            return Ok(status);
        }
        ctx.print(&render_plan(&r));
        return Ok(status);
    }
    if a.verify {
        return Err(local(
            "--verify goes with --dry-run alone: kronik blobs gc --dry-run --verify".to_owned(),
        ));
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
        out.push_str("This node has no blob store: nothing to collect.\n");
    } else if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: a pass now would delete {} files ({}) and keep {} candidates for the next one.",
            r.deleted,
            units::rounded_size(r.bytes),
            r.candidates
        );
    } else {
        let _ = writeln!(
            out,
            "Deleted {} files ({}); {} candidates for the next pass; {} files left.",
            r.deleted,
            units::rounded_size(r.bytes),
            r.candidates,
            r.objects
        );
    }
    out.push_str(&next(&["kronik blobs status".to_owned()]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn render_drift(r: &BlobGcPlanResponse, out: &mut String) {
    match &r.drift {
        None => {}
        Some(d) if d.is_empty() => out.push_str("Pins         match the rows they mirror\n"),
        Some(d) => {
            let _ = writeln!(
                out,
                "Pins         DRIFT: {} differences from the rows they mirror",
                d.len()
            );
            let rows = d
                .iter()
                .map(|e| {
                    vec![
                        e.hash.clone(),
                        e.source.clone(),
                        e.owner.clone(),
                        e.problem.clone(),
                    ]
                })
                .collect();
            out.push_str(&table(&["blob", "row", "owner", "problem"], rows));
        }
    }
}

fn render_plan(r: &BlobGcPlanResponse) -> String {
    let mut out = String::new();
    if !r.enabled {
        out.push_str("This node has no blob store.\n");
        return out;
    }
    if r.blobs.is_empty() {
        let _ = writeln!(out, "Nothing to collect: all {} files have a root.", r.kept);
        render_drift(r, &mut out);
        return out;
    }
    let rows = r
        .blobs
        .iter()
        .map(|b| {
            vec![
                b.hash.clone(),
                match &b.released_by {
                    Some(actor) if b.reason == "released" => format!("released by {actor}"),
                    _ => b.reason.clone(),
                },
                units::rounded_size(b.bytes),
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
        units::rounded_size(r.bytes),
        r.kept,
        r.floor.unwrap_or(0)
    );
    render_drift(r, &mut out);
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

#[cfg(test)]
mod tests {
    use kronik_api::types::{ActorBlobEntry, BlobGcEntry, BlobGcSummary, BlobRootEntry};

    use super::*;

    const HASH: &str = "b3:4f1c09ab77e9d0c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9";
    const REFERENCE: &str = include_str!("../../../../docs/reference/cli.md");

    /// `$ kronik <command>` and its output, as the CLI reference shows it.
    fn documented(command: &str, output: &str) {
        let shown = format!("$ kronik {command}\n{output}");
        assert!(REFERENCE.contains(&shown), "not in cli.md:\n{shown}");
    }

    /// The sizes that `kronik blobs` measures are rounded, the exact counts
    /// are in `--json`; the reference's samples are the CLI's output.
    #[test]
    fn blob_commands_render_as_documented() {
        documented(
            "blobs status",
            &render_status(&BlobsStatusResponse {
                enabled: true,
                indexed: 12,
                indexed_bytes: 325_480_000,
                floor: Some(1190),
                leases: 2,
                free_bytes: Some(94_600_000_000),
                reserve_bytes: 4 << 30,
                below_reserve: false,
                last_gc: Some(BlobGcSummary {
                    objects: 14,
                    bytes: 326_110_000,
                    deleted: 3,
                    deleted_bytes: 42_160_000,
                    candidates: 1,
                    floor: 1190,
                }),
            }),
        );
        documented(
            &format!("blobs inspect {HASH}"),
            &render_inspect(&BlobInspectResponse {
                hash: HASH.into(),
                state: "live".into(),
                size: Some(31_457_000),
                subject: None,
                key_version: Some(0),
                first_ref_lsn: Some(1203),
                last_ref_lsn: Some(1203),
                sealed: Some(false),
                file_bytes: Some(31_459_436),
                roots: vec![BlobRootEntry {
                    kind: "log".into(),
                    actor: None,
                    lsn: Some(1203),
                    floor: Some(1190),
                    source: None,
                    owner: None,
                    fork: None,
                }],
                verified: None,
                verify_error: None,
            }),
        );
        documented(
            "blobs list --actor media/alice",
            &render_list(
                "media/alice",
                &ActorBlobsResponse {
                    blobs: vec![ActorBlobEntry {
                        hash: HASH.into(),
                        size: 31_457_000,
                        subject: None,
                        lsn: 1203,
                    }],
                    next: None,
                },
            ),
        );
        documented(
            "blobs gc --dry-run --verify",
            &render_plan(&BlobGcPlanResponse {
                enabled: true,
                blobs: vec![BlobGcEntry {
                    hash: HASH.into(),
                    reason: "out-of-retention".into(),
                    released_by: None,
                    size: Some(31_457_000),
                    bytes: 31_459_436,
                    subject: None,
                    last_ref_lsn: Some(1203),
                    candidate: true,
                }],
                count: 1,
                bytes: 31_459_436,
                floor: Some(1290),
                kept: 12,
                drift: Some(Vec::new()),
            }),
        );
    }

    /// What the store measures is rounded: a free disk of 98203944 KiB is
    /// 93.7 GiB.
    #[test]
    fn status_rounds_what_it_measures() {
        let shown = render_status(&BlobsStatusResponse {
            enabled: true,
            indexed: 1,
            indexed_bytes: 5_243_000,
            floor: None,
            leases: 0,
            free_bytes: Some(98_203_944 << 10),
            reserve_bytes: 1 << 30,
            below_reserve: false,
            last_gc: None,
        });
        assert!(shown.contains("Indexed      1 blobs, 5.0 MiB\n"), "{shown}");
        assert!(
            shown.contains("Disk         93.7 GiB free, reserve 1.0 GiB\n"),
            "{shown}"
        );
        let shown = render_status(&BlobsStatusResponse {
            enabled: true,
            reserve_bytes: 1 << 30,
            below_reserve: true,
            ..BlobsStatusResponse::default()
        });
        assert!(
            shown.contains(
                "Disk         unknown free, reserve 1.0 GiB: BELOW RESERVE, new blobs are refused\n"
            ),
            "{shown}"
        );
    }
}
