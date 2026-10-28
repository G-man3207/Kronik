//! `kronik privacy mode on|off`, `kronik privacy status`, `kronik privacy
//! erase` and `kronik privacy reseal` (M8): the operator's switch for
//! sealing personal data, erasure, and resealing history written in `off`
//! mode (docs/design/m8-privacy.md).

use std::fmt::Write as _;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use kronik_api::privacy::{
    ErasureRequest, ErasureResponse, PrivacyModeName, PrivacyModeRequest, PrivacyModeResponse,
    PrivacyStatus, ResealRequest, ResealResponse,
};

use super::render::{field, next, shell_quote};
use super::{Ctx, Error, Mutation, reason, units};

#[derive(Debug, Subcommand)]
pub enum PrivacyCommand {
    /// Turn privacy mode on or off. With it on, values with a subject that
    /// are written from then on are sealed with the subject's key; values
    /// written before stay as they are.
    Mode {
        /// `on` or `off`.
        #[arg(value_enum)]
        mode: Mode,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Show privacy mode, the epoch it was set in, and the keystore's counts.
    Status,
    /// Erase a subject: delete its keys, so its sealed values can't be read
    /// again, anywhere, and delete its SQL rows.
    Erase {
        /// The subject, e.g. user:123.
        subject: String,
        #[command(flatten)]
        mutation: Mutation,
    },
    /// Rewrite closed log segments: seal plain values and tombstone erased
    /// ones. Privacy mode must already be on.
    Reseal {
        #[command(flatten)]
        mutation: Mutation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    On,
    Off,
}

fn name(m: PrivacyModeName) -> &'static str {
    match m {
        PrivacyModeName::On => "on",
        PrivacyModeName::Off => "off",
    }
}

pub(super) fn privacy(ctx: &Ctx, command: PrivacyCommand) -> Result<ExitCode, Error> {
    match command {
        PrivacyCommand::Mode { mode, mutation } => set_mode(ctx, mode, &mutation),
        PrivacyCommand::Status => status(ctx),
        PrivacyCommand::Erase { subject, mutation } => erase(ctx, &subject, &mutation),
        PrivacyCommand::Reseal { mutation } => reseal(ctx, &mutation),
    }
}

fn set_mode(ctx: &Ctx, mode: Mode, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let wanted = match mode {
        Mode::On => PrivacyModeName::On,
        Mode::Off => PrivacyModeName::Off,
    };
    let body = ctx.post(
        "/v1/privacy/mode",
        &PrivacyModeRequest {
            mode: wanted,
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: PrivacyModeResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik privacy mode {} --reason {}",
        name(wanted),
        shell_quote(reason)
    );
    ctx.print(&render_mode(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn epoch(e: Option<u64>) -> String {
    e.map_or_else(|| "none yet".to_owned(), |e| e.to_string())
}

fn render_mode(r: &PrivacyModeResponse, rerun: &str) -> String {
    let mut out = String::new();
    let mode = name(r.mode);
    if !r.changed {
        let _ = writeln!(out, "Privacy mode was already {mode}; nothing was recorded");
        out.push_str(&next(&["kronik privacy status".to_owned()]));
        return out;
    }
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: privacy mode would turn {mode} (epoch {}); nothing was written",
            epoch(r.epoch)
        );
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    let _ = writeln!(
        out,
        "Privacy mode is {mode} (epoch {}, lsn {})",
        epoch(r.epoch),
        r.lsn.map_or_else(|| "-".to_owned(), |l| l.to_string())
    );
    match r.mode {
        PrivacyModeName::On => out.push_str(
            "Values with a subject written from now on are sealed with their subject's key;\n\
             values written before stay as they are.\n",
        ),
        PrivacyModeName::Off => out.push_str(
            "Values written from now on are stored in the clear; sealed values stay sealed.\n",
        ),
    }
    out.push_str(&next(&["kronik privacy status".to_owned()]));
    out
}

fn status(ctx: &Ctx) -> Result<ExitCode, Error> {
    let body = ctx.get("/v1/privacy")?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let s: PrivacyStatus = ctx.decode(&body)?;
    let mut out = String::new();
    field(
        &mut out,
        "Mode",
        &[format!("{} (epoch {})", name(s.mode), epoch(s.epoch))],
        "",
    );
    let keystore = match s.keystore {
        Some(k) => format!(
            "{} subjects, {} keys, {} erased",
            k.subjects, k.keys, k.erased
        ),
        None => "none".to_owned(),
    };
    field(&mut out, "Keystore", &[keystore], "");
    field(
        &mut out,
        "Erasures",
        &[format!(
            "{} still have a plain value in the log",
            s.pending_erasures
        )],
        "",
    );
    let r = &s.reseal;
    field(
        &mut out,
        "Reseal",
        &[format!(
            "{} of {} segments, {} values sealed, {} tombstones",
            r.segments_done, r.segments_total, r.values_sealed, r.tombstones
        )],
        "",
    );
    if r.pending_segments > 0 {
        let _ = writeln!(
            out,
            "The shipped copy still holds the old bytes until the shipper replaces them."
        );
    }
    let other = match s.mode {
        PrivacyModeName::On => "off",
        PrivacyModeName::Off => "on",
    };
    out.push_str(&next(&[format!(
        "kronik privacy mode {other} --reason \"...\""
    )]));
    ctx.print(&out);
    Ok(ExitCode::SUCCESS)
}

fn erase(ctx: &Ctx, subject: &str, mutation: &Mutation) -> Result<ExitCode, Error> {
    let reason = reason(mutation)?;
    let body = ctx.post(
        "/v1/privacy/erase",
        &ErasureRequest {
            subject: subject.to_owned(),
            reason: reason.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ErasureResponse = ctx.decode(&body)?;
    let rerun = format!(
        "kronik privacy erase {} --reason {}",
        shell_quote(subject),
        shell_quote(reason)
    );
    ctx.print(&render_erase(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn render_erase(r: &ErasureResponse, rerun: &str) -> String {
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: subject {} can be erased (epoch {}); nothing was written",
            r.subject, r.epoch
        );
        complete_after(&mut out, r.complete_after_ms);
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    let _ = writeln!(
        out,
        "Erased subject {}: its sealed values can't be read again (key version {}, epoch {}, lsn {})",
        r.subject,
        r.key_version,
        r.epoch,
        r.lsn.map_or_else(|| "-".to_owned(), |l| l.to_string())
    );
    if r.plain_values > 0 {
        let _ = writeln!(
            out,
            "Warning: {} of its values were written with privacy mode off and are still \
             plain in the log, until they are resealed.",
            r.plain_values
        );
    }
    complete_after(&mut out, r.complete_after_ms);
    out.push_str(&next(&["kronik privacy status".to_owned()]));
    out
}

fn complete_after(out: &mut String, ms: u64) {
    if ms == 0 {
        return;
    }
    let _ = writeln!(
        out,
        "Erasure is complete after {}, once reseal and snapshot replacement have run.",
        units::utc(ms)
    );
}

fn reseal(ctx: &Ctx, mutation: &Mutation) -> Result<ExitCode, Error> {
    let why = reason(mutation)?;
    let body = ctx.post(
        "/v1/privacy/reseal",
        &ResealRequest {
            reason: why.to_owned(),
            dry_run: mutation.dry_run,
        },
    )?;
    if ctx.json {
        ctx.print_raw(&body);
        return Ok(ExitCode::SUCCESS);
    }
    let r: ResealResponse = ctx.decode(&body)?;
    let rerun = format!("kronik privacy reseal --reason {}", shell_quote(why));
    ctx.print(&render_reseal(&r, &rerun));
    Ok(ExitCode::SUCCESS)
}

fn render_reseal(r: &ResealResponse, rerun: &str) -> String {
    let mut out = String::new();
    if r.dry_run {
        let _ = writeln!(
            out,
            "Dry run: reseal would rewrite {} closed segments; nothing was written",
            r.segments
        );
        out.push_str(&next(&[rerun.to_owned()]));
        return out;
    }
    if r.segments == 0 {
        let _ = writeln!(out, "No closed segment needed resealing");
    } else {
        let _ = writeln!(out, "Resealed {} closed segments", r.segments);
    }
    out.push_str(&next(&["kronik privacy status".to_owned()]));
    out
}
