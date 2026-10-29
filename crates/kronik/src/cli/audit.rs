//! `kronik audit show` and `kronik audit verify` (docs/design/m28-otel.md
//! §4.5, §6.2). `show` asks the daemon (scope `admin`: the lines name
//! tokens and callers). `verify` needs no daemon: it reads the log and the
//! export cursor of the data directory and the sink's lines, and compares
//! them by §4.5's definition.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kronik_api::types::AuditResponse;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_otel::audit::{Ctx as LineCtx, Item, Line, Report};
use kronik_otel::sink::Sink;
use kronik_otel::spans::ActorKeys;

use super::render::{next, table};
use super::{Ctx, Error, units};

#[derive(Debug, clap::Subcommand)]
pub enum AuditCommand {
    /// The audit lines of main's log, as an audit sink receives them, also
    /// when the export is off. Needs `admin`.
    Show {
        /// Lines of records at this LSN and after [default: the first
        /// retained record].
        #[arg(long)]
        from: Option<u64>,
        /// At most this many lines (1–1000) [default: 100].
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Compare a sink's lines with the log: missing, extra and conflicting
    /// lines. Needs no daemon. Exits 1 unless the sink is complete.
    Verify(VerifyArgs),
}

#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// `file:///dir/` or `s3://bucket/prefix` [default: `[audit] sink`]. A
    /// webhook cannot be read back. For s3://, `[audit] endpoint` and the
    /// `AWS_*` variables apply.
    #[arg(long, value_name = "URL")]
    sink: Option<String>,
    /// Check records after this LSN [default: the one before the first
    /// retained record].
    #[arg(long, value_name = "LSN")]
    from: Option<u64>,
    /// Check records through this LSN [default: the audit export's cursor,
    /// else the end of the log].
    #[arg(long, value_name = "LSN")]
    to: Option<u64>,
    /// The configuration file [default: /etc/kronik/kronik.toml if it exists].
    #[arg(long, value_name = "PATH", env = "KRONIK_CONFIG")]
    config: Option<PathBuf>,
    /// The data directory [default: server.data_dir in the configuration
    /// file, else /var/lib/kronik].
    #[arg(long, env = "KRONIK_DATA_DIR")]
    data_dir: Option<PathBuf>,
}

/// The schema of `kronik audit verify --json` (docs/reference/json.md).
#[cfg(test)]
pub fn verify_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    g.subschema_for::<Report>()
}

pub(super) fn audit(ctx: &Ctx, command: AuditCommand) -> Result<ExitCode, Error> {
    match command {
        AuditCommand::Show { from, limit } => show(ctx, from, limit),
        AuditCommand::Verify(a) => verify(ctx, a),
    }
}

fn show(ctx: &Ctx, from: Option<u64>, limit: Option<u64>) -> Result<ExitCode, Error> {
    let mut query = Vec::new();
    if let Some(f) = from {
        query.push(format!("from={f}"));
    }
    if let Some(l) = limit {
        query.push(format!("limit={l}"));
    }
    let target = if query.is_empty() {
        "/v1/audit".to_owned()
    } else {
        format!("/v1/audit?{}", query.join("&"))
    };
    let body = ctx.get(&target)?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: AuditResponse = ctx.decode(&body)?;
    ctx.print(&render_show(&r));
    Ok(ExitCode::SUCCESS)
}

fn render_show(r: &AuditResponse) -> String {
    let mut out = if r.lines.is_empty() {
        "No audit lines.\n".to_owned()
    } else {
        table(
            &["lsn", "action", "at", "token", "reason"],
            r.lines
                .iter()
                .map(|l| {
                    vec![
                        match l.effect {
                            Some(e) => format!("{}#{e}", l.lsn),
                            None => l.lsn.to_string(),
                        },
                        l.action.clone(),
                        units::utc(l.at_wall_ms),
                        l.token_id.clone(),
                        l.reason.clone(),
                    ]
                })
                .collect(),
        )
    };
    if let Some(n) = r.next {
        out.push_str(&next(&[format!("kronik audit show --from {n}")]));
    }
    out
}

fn verify(ctx: &Ctx, a: VerifyArgs) -> Result<ExitCode, Error> {
    let bad = |m: String| ApiError::new(ErrorCode::BadRequest, m);
    let (config, _) = crate::config::Config::find(a.config.as_deref())
        .map_err(|e| bad(format!("the configuration file is invalid: {e}")))?;
    let data_dir = a.data_dir.unwrap_or(config.server.data_dir.clone());
    let key_file = config
        .keys
        .master_key_file
        .clone()
        .unwrap_or_else(|| data_dir.join("keys/master.key"));
    let url = a.sink.or_else(|| config.audit.sink()).ok_or_else(|| {
        bad("no sink to verify".into()).with_hint(
            "Pass --sink file:///dir/ or --sink s3://bucket/prefix, or set [audit] sink.",
        )
    })?;
    let endpoint = config
        .audit
        .endpoint
        .as_deref()
        .filter(|_| url.starts_with("s3://"));
    let sink = Sink::parse(&url, endpoint).map_err(bad)?;
    let report =
        crate::restore::runtime()?.block_on(compare(&data_dir, &key_file, &sink, a.from, a.to))?;
    if ctx.json {
        ctx.print(&format!(
            "{}\n",
            serde_json::to_string(&report).unwrap_or_default()
        ));
    } else {
        ctx.print(&render_verify(&report, &sink.shown()));
    }
    Ok(if report.complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Reads main's log in `(from, to]` and the sink's lines, and compares them.
async fn compare(
    data_dir: &Path,
    key_file: &Path,
    sink: &Sink,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<Report, ApiError> {
    let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
    let corrupt = |e: kronik_log::LogError| ApiError::new(ErrorCode::StorageCorrupt, e.to_string());
    let reader =
        kronik_log::LogReader::new(env.clone(), data_dir.join("branches/main/log"), "main");
    let starts = reader.starts().await.map_err(corrupt)?;
    let first = starts.first().copied().unwrap_or(1);
    let from = from.unwrap_or(first.saturating_sub(1));
    if from + 1 < first {
        return Err(ApiError::new(
            ErrorCode::AuditRangeGone,
            format!("LSN {from} is before the first retained record, LSN {first}"),
        )
        .with_hint(format!(
            "Pass --from {} or later; retention deleted what came before.",
            first - 1
        )));
    }
    let to = match to {
        Some(t) => t,
        None => {
            let cursors = kronik_otel::cursor::Cursors::load(env, data_dir)
                .await
                .map_err(|e| {
                    ApiError::new(ErrorCode::Internal, format!("reading export.json: {e}"))
                })?;
            match cursors.get(kronik_otel::sink::STREAM) {
                Some(e) => e.lsn,
                None => u64::MAX,
            }
        }
    };
    // Only what verify compares (kind, action, token, time, hash) matters:
    // no actor key hashing or secret scrub. An erasure's hash covers its
    // subject's keyed label (review M6), so the master key is needed.
    let master = kronik_privacy::MasterKey::open(key_file, &data_dir.join("keys"), None)
        .map(|(k, _)| k)
        .map_err(|e| {
            ApiError::new(
                ErrorCode::BadRequest,
                format!("reading the master key: {e}"),
            )
            .with_hint(
                "verify recomputes erasure records' hashes with the master key: run it as the \
             daemon's user, or set [keys] master_key_file or KRONIK_MASTER_KEY.",
            )
        })?;
    let sealer = kronik_privacy::sealer::Sealer::plain()
        .with_pseudonyms(kronik_privacy::keystore::Pseudonyms::new(&master));
    let keys = ActorKeys::Omit;
    let subject = |s: &str| kronik_otel::audit::subject_label(&sealer, s);
    let line_ctx = LineCtx {
        branch: "main",
        keys: &keys,
        subject: &subject,
        secrets: &[],
    };
    let mut expected = Vec::new();
    let mut last = from;
    if to > from {
        reader
            .read(from + 1, to, |c| {
                last = c.lsn;
                expected.extend(kronik_otel::audit::lines(c.lsn, &c.record, &line_ctx));
                Ok(())
            })
            .await
            .map_err(corrupt)?;
    }
    let lines = read_sink(sink).await?;
    Ok(kronik_otel::audit::verify(
        &expected,
        &lines,
        from,
        to.min(last.max(from)),
    ))
}

/// A sink's lines in the order they were written. A last line without its
/// `\n` is an append in progress, and skipped.
async fn read_sink(sink: &Sink) -> Result<Vec<Line>, ApiError> {
    let unavailable = |m: String| {
        ApiError::new(ErrorCode::Unavailable, m)
            .with_hint("Check the URL, the endpoint and the AWS_* credentials.")
    };
    let mut bodies = Vec::new();
    match sink {
        Sink::File(dir) => {
            let files = kronik_otel::sink::files(dir).map_err(|e| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("reading {}: {e}", dir.display()),
                )
            })?;
            for f in files {
                let body = std::fs::read(&f).map_err(|e| {
                    ApiError::new(
                        ErrorCode::BadRequest,
                        format!("reading {}: {e}", f.display()),
                    )
                })?;
                bodies.push((f.display().to_string(), body));
            }
        }
        Sink::S3 { url, endpoint } => {
            let remote = kronik_ship::Remote::open(url, endpoint.as_deref())
                .map_err(|e| unavailable(format!("opening the audit bucket: {e}")))?;
            // Names start with the time the batch was prepared, so name
            // order is write order, after a restore too (review H-B).
            let (mut names, _) = remote
                .list("audit")
                .await
                .map_err(|e| unavailable(format!("listing the audit bucket: {}", e.code())))?;
            names.sort();
            for name in names {
                let body = remote
                    .get(&format!("audit/{name}"))
                    .await
                    .map_err(|e| unavailable(format!("reading audit/{name}: {}", e.code())))?;
                bodies.push((name, body));
            }
        }
        Sink::Webhook(_) => {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "a webhook cannot be read back",
            )
            .with_hint("Verify the store the webhook writes to with --sink file:///dir/ or --sink s3://bucket/prefix."));
        }
    }
    let mut lines = Vec::new();
    for (name, body) in bodies {
        let whole = body.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        for (i, raw) in body[..whole].split(|b| *b == b'\n').enumerate() {
            if raw.is_empty() {
                continue;
            }
            let line = serde_json::from_slice::<Line>(raw).map_err(|e| {
                ApiError::new(
                    ErrorCode::BadRequest,
                    format!("{name} line {}: not a kronik.audit/v1 line: {e}", i + 1),
                )
            })?;
            lines.push(line);
        }
    }
    Ok(lines)
}

fn render_verify(r: &Report, sink: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {sink}: {} audited items in ({}, {}], {} distinct lines{}",
        if r.complete {
            "Complete:"
        } else {
            "NOT complete:"
        },
        r.expected,
        r.from,
        r.to,
        r.lines,
        if r.superseded > 0 {
            format!(", {} superseded by a restore", r.superseded)
        } else {
            String::new()
        }
    );
    for (what, items) in [
        ("Missing", &r.missing),
        ("Extra", &r.extra),
        ("Conflicting", &r.conflicting),
    ] {
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "{what} ({}):", items.len());
        out.push_str(&table(
            &["lsn", "effect", "kind", "action", "record_hash"],
            items.iter().map(item_row).collect(),
        ));
    }
    out
}

fn item_row(i: &Item) -> Vec<String> {
    vec![
        i.lsn.to_string(),
        i.effect.map_or_else(|| "-".to_owned(), |e| e.to_string()),
        i.kind.clone(),
        i.action.clone(),
        i.record_hash.clone(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_names_what_is_missing() {
        let item = Item {
            lsn: 7,
            effect: None,
            kind: "grant".into(),
            action: "grant".into(),
            record_hash: "b3:00".into(),
        };
        let r = Report {
            complete: false,
            from: 0,
            to: 9,
            expected: 3,
            lines: 2,
            missing: vec![item],
            ..Report::default()
        };
        let text = render_verify(&r, "file://");
        assert!(text.starts_with("NOT complete: file://"), "{text}");
        assert!(text.contains("Missing (1)"), "{text}");
        assert!(text.contains("b3:00"), "{text}");
    }
}
