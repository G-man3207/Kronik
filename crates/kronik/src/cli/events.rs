//! Operational event pages and a backpressured, incremental SSE follower.

use std::io::{self, Read as _};
use std::process::ExitCode;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::SourcePos;
use kronik_fleet::events::ResumeCursor;
use serde_json::json;

use super::{Ctx, Error, Mutation, http, reason};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSource {
    Native,
    Actor(u32),
    Metadata,
}

impl std::str::FromStr for EventSource {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "actor-native" => return Ok(Self::Native),
            "metadata" => return Ok(Self::Metadata),
            _ => {}
        }
        let bad = "source must be actor-native, metadata, or actor-N with a canonical in-range shard number";
        let number = value.strip_prefix("actor-").ok_or(bad)?;
        if !number.bytes().all(|byte| byte.is_ascii_digit())
            || (number.starts_with('0') && number != "0") {
            return Err(bad);
        }
        let shard = number.parse::<u32>().map_err(|_| bad)?;
        if shard >= kronik_proto::MAX_SHARD_COUNT { return Err(bad); }
        Ok(Self::Actor(shard))
    }
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native => out.write_str("actor-native"),
            Self::Actor(shard) => write!(out, "actor-{shard}"),
            Self::Metadata => out.write_str("metadata"),
        }
    }
}

impl EventSource {
    fn matches(self, position: SourcePos) -> bool {
        match (self, position) {
            (Self::Native, SourcePos::Actor { shard: None, .. }) => true,
            (Self::Actor(expected), SourcePos::Actor { shard: Some(actual), .. }) => expected == actual,
            (Self::Metadata, SourcePos::Metadata { .. }) => true,
            _ => false,
        }
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum EventsCommand {
    /// Read a bounded page of operational events.
    List {
        /// One actual source: actor-native, actor-N, or metadata; omission uses the API's configured default.
        #[arg(long, value_name = "SOURCE")]
        source: Option<EventSource>,
        /// Resume cursor JSON, or `-` to read its bounded JSON from stdin.
        #[arg(long)]
        cursor: Option<String>,
        /// The maximum page size (1–256) [default: 100].
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=256))]
        limit: Option<u64>,
    },
    /// Follow the live SSE stream until Ctrl-C, or until --limit actual events.
    Tail {
        /// Follow one actual source; omission keeps the API's all-source stream.
        #[arg(long, value_name = "SOURCE")]
        source: Option<EventSource>,
        /// Resume cursor JSON, or `-` to read its bounded JSON from stdin.
        #[arg(long)]
        cursor: Option<String>,
        /// Stop successfully after this many actual events (at least one).
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        limit: Option<u64>,
    },
    /// Show the published event schemas.
    Schemas,
    /// Show delivery status or replay events to a configured webhook.
    #[command(subcommand)]
    Webhooks(WebhooksCommand),
}

#[derive(Debug, clap::Subcommand)]
pub enum WebhooksCommand {
    /// Show configured webhooks' durable delivery status.
    Status,
    /// Replay to a configured webhook from an opaque cursor.
    Replay {
        name: String,
        /// Resume cursor JSON, or `-` to read its bounded JSON from stdin.
        #[arg(long)]
        cursor: String,
        #[command(flatten)]
        mutation: Mutation,
    },
}

pub(super) fn events(ctx: &Ctx, command: EventsCommand) -> Result<ExitCode, Error> {
    let body = match command {
        EventsCommand::Tail { source, cursor, limit } => return tail(ctx, source, cursor, limit),
        EventsCommand::List { source, cursor, limit } => {
            let cursor = cursor.map(|value| read_cursor(&value, &mut io::stdin().lock())).transpose()?;
            let encoded = cursor.as_ref().map(encode_cursor).transpose()?;
            ctx.request("GET", &target("/v1/events", source, limit), None, encoded.as_deref())?
        }
        EventsCommand::Schemas => ctx.get("/v1/events/schemas")?,
        EventsCommand::Webhooks(WebhooksCommand::Status) => ctx.get("/v1/events/webhooks")?,
        EventsCommand::Webhooks(WebhooksCommand::Replay { name, cursor, mutation }) => {
            let why = reason(&mutation)?;
            let cursor = read_cursor(&cursor, &mut io::stdin().lock())?;
            ctx.post(
                &format!("/v1/events/webhooks/{}/replay", http::encode(&name)),
                &json!({"cursor": cursor, "reason": why, "dry_run": mutation.dry_run}),
            )?
        }
    };
    super::fleet::render(ctx, &body)?;
    Ok(ExitCode::SUCCESS)
}

fn target(path: &str, source: Option<EventSource>, limit: Option<u64>) -> String {
    match (source, limit) {
        (Some(source), Some(limit)) => format!("{path}?source={source}&limit={limit}"),
        (Some(source), None) => format!("{path}?source={source}"),
        (None, Some(limit)) => format!("{path}?limit={limit}"),
        (None, None) => path.to_owned(),
    }
}

fn unavailable(message: &str) -> ApiError {
    ApiError::new(ErrorCode::Unavailable, message)
}

fn decode_cursor(bytes: &[u8]) -> Result<ResumeCursor, ApiError> {
    let bad = || ApiError::new(ErrorCode::BadRequest, "the event cursor is not valid bounded resume-cursor JSON");
    if bytes.len() > MAX_CURSOR { return Err(bad()); }
    let cursor: ResumeCursor = serde_json::from_slice(bytes).map_err(|_| bad())?;
    cursor.validate(&cursor.identity).map_err(|_| bad())?;
    Ok(cursor)
}

pub(super) fn read_cursor(value: &str, input: &mut impl io::Read) -> Result<ResumeCursor, ApiError> {
    if value != "-" { return decode_cursor(value.as_bytes()); }
    let mut bytes = Vec::new();
    input.take((MAX_CURSOR + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "cannot read the event cursor from stdin"))?;
    decode_cursor(&bytes)
}

fn encode_cursor(cursor: &ResumeCursor) -> Result<String, ApiError> {
    let value = serde_json::to_string(cursor)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot encode the event cursor"))?;
    if value.len() > MAX_CURSOR {
        return Err(ApiError::new(ErrorCode::BadRequest, "the event cursor exceeds its byte bound"));
    }
    Ok(value)
}

/// Reuse the published cursor schema as a checkpoint, not an oversized shell argument.
fn write_checkpoint(
    out: &mut impl io::Write,
    err: &mut impl io::Write,
    json: bool,
    cursor: Option<&ResumeCursor>,
    source: Option<EventSource>,
) -> Result<(), ApiError> {
    let Some(cursor) = cursor else { return Ok(()); };
    if json {
        serde_json::to_writer(&mut *out, cursor)
            .map_err(|_| unavailable("cannot write the event checkpoint"))?;
        out.write_all(b"\n").and_then(|()| out.flush())
            .map_err(|_| unavailable("cannot write the event checkpoint"))?;
    } else {
        err.write_all(b"Cursor checkpoint (JSON):\n")
            .map_err(|_| unavailable("cannot write the event checkpoint"))?;
        serde_json::to_writer(&mut *err, cursor)
            .map_err(|_| unavailable("cannot write the event checkpoint"))?;
        err.write_all(b"\n").map_err(|_| unavailable("cannot write the event checkpoint"))?;
    }
    err.write_all(b"Resume with kronik events tail")
        .map_err(|_| unavailable("cannot write the checkpoint hint"))?;
    if let Some(source) = source {
        write!(err, " --source {source}").map_err(|_| unavailable("cannot write the checkpoint hint"))?;
    }
    err.write_all(b" --cursor - < checkpoint.json (save the cursor JSON footer).\n")
        .and_then(|()| err.flush())
        .map_err(|_| unavailable("cannot write the checkpoint hint"))
}

fn tail(ctx: &Ctx, source: Option<EventSource>, cursor: Option<String>, limit: Option<u64>) -> Result<ExitCode, Error> {
    let endpoint = ctx.endpoint.as_ref().map_err(|error| Error::Local(error.clone()))?.clone();
    let token = ctx.token.as_ref().map_err(|error| Error::Local(error.clone()))?.clone();
    let mut checkpoint = cursor.map(|value| read_cursor(&value, &mut io::stdin().lock())).transpose()?;
    let encoded = checkpoint.as_ref().map(encode_cursor).transpose()?;
    let target = target("/v1/events/stream", source, None);
    let json = ctx.json;
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = cancelled.clone();
    let runtime = crate::restore::runtime()?;
    let result = runtime.block_on(async move {
        let mut worker = tokio::task::spawn_blocking(move || {
            let result = (|| {
                let response = match http::stream(&endpoint, &target, token.as_deref(), encoded.as_deref(), stop.clone()) {
                    Ok(response) => response,
                    Err(http::Failure::Io(error))
                        if error.kind() == io::ErrorKind::ConnectionAborted && stop.load(Ordering::Relaxed) => return Ok(()),
                    Err(failure) => return Err(Error::Local(match failure {
                        http::Failure::Connect(error) => super::connect_error(&endpoint, &error),
                        http::Failure::Tls(_) => unavailable("TLS verification failed for the event stream")
                            .with_hint(super::TLS_HINT),
                        _ => unavailable("cannot open the event stream"),
                    })),
                };
                drop(encoded);
                if !(200..300).contains(&response.status) {
                    let mut body = Vec::new();
                    match response.body.take((MAX_FRAME + 1) as u64).read_to_end(&mut body) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::ConnectionAborted && stop.load(Ordering::Relaxed) => return Ok(()),
                        Err(_) => return Err(Error::Local(unavailable("cannot read the event stream's API error"))),
                    }
                    if body.len() > MAX_FRAME {
                        return Err(Error::Local(unavailable("the event stream's API error exceeds its bound")));
                    }
                    // Do not send a proxy's HTML or arbitrary metadata to human output.
                    let error: ApiError = serde_json::from_slice(&body)
                        .map_err(|_| Error::Local(unavailable("the event stream returned no stable API error")))?;
                    return Err(Error::Local(error));
                }
                if !response.content_type.as_deref().is_some_and(|value| {
                    value.split(';').next().is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
                }) {
                    return Err(Error::Local(unavailable("the API response is not an event stream")));
                }
                follow(response.body, &mut io::stdout().lock(), json, limit, &mut checkpoint, stop.as_ref(), source)
                    .map_err(Error::Local)
            })();
            let footer = write_checkpoint(&mut io::stdout().lock(), &mut io::stderr().lock(), json, checkpoint.as_ref(), source);
            result?;
            footer.map_err(Error::Local)
        });
        tokio::select! {
            result = &mut worker => result.map_err(|_| Error::Local(unavailable("the event stream worker failed")))?,
            signal = tokio::signal::ctrl_c() => {
                cancelled.store(true, Ordering::Relaxed);
                let result = worker.await.map_err(|_| Error::Local(unavailable("the event stream worker failed")))?;
                signal.map_err(|_| Error::Local(unavailable("cannot listen for Ctrl-C")))?;
                result
            }
        }
    });
    result?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
pub(super) fn tail_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut map = serde_json::Map::new();
    map.insert("oneOf".into(), json!([
        g.subschema_for::<kronik_fleet::events::Event>().to_value(),
        g.subschema_for::<ResumeCursor>().to_value(),
    ]));
    schemars::Schema::from(map)
}

const MAX_CURSOR: usize = kronik_fleet::events::MAX_CURSOR_BYTES;
const MAX_LINE: usize = kronik_fleet::events::MAX_PAGE_BYTES + MAX_CURSOR + 4096;
const MAX_FRAME: usize = kronik_fleet::events::MAX_PAGE_BYTES + 2 * MAX_CURSOR + 8192;

#[cfg(test)]
pub(super) fn full_event_cursor() -> kronik_fleet::events::ResumeCursor {
    use kronik_fleet::events::{Identity, Position, ResumeCursor, domain};
    let identity = Identity { installation: "node-a".into(), branch: "main".into() };
    let mut cursor = ResumeCursor::new(identity);
    let sources = [
        SourcePos::Actor { shard: None, lsn: u64::MAX },
        SourcePos::Metadata { index: u64::MAX },
    ].into_iter().chain((0..kronik_proto::MAX_SHARD_COUNT)
        .map(|shard| SourcePos::Actor { shard: Some(shard), lsn: u64::MAX }));
    for source in sources {
        cursor.streams.insert(domain(source).into_owned(), Position { source, subindex: 0 });
    }
    cursor.validate(&cursor.identity).unwrap();
    cursor
}

#[derive(Default)]
struct Frame {
    id: Option<String>,
    event: String,
    data: String,
    size: usize,
}

/// Emits only complete operational envelopes. The reader is never drained ahead
/// of stdout, so a slow consumer applies backpressure to the daemon.
fn follow(
    input: impl io::Read,
    out: &mut impl io::Write,
    json: bool,
    limit: Option<u64>,
    cursor: &mut Option<ResumeCursor>,
    cancelled: &AtomicBool,
    source: Option<EventSource>,
) -> Result<(), ApiError> {
    let mut input = io::BufReader::new(input);
    let mut frame = Frame::default();
    let mut emitted = 0;
    let mut skip_lf = false;
    loop {
        let line = match sse_line(&mut input, &mut skip_lf) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted && cancelled.load(Ordering::Relaxed) => return Ok(()),
            Err(_) => return Err(unavailable("the event stream is malformed, oversized or disconnected")),
            Ok(Some(line)) => line,
            Ok(None) => return Err(unavailable("the event stream ended; resume explicitly with --cursor")
                .with_hint(if cursor.is_some() {
                    "Save the cursor JSON footer; resume with --cursor - < checkpoint.json and the same --source selection shown in the checkpoint hint."
                } else { "Use your last saved cursor with --cursor - < checkpoint.json and the same --source selection." })),
        };
        frame.size = frame.size.saturating_add(line.len() + 1);
        if frame.size > MAX_FRAME {
            return Err(unavailable("an event frame exceeds its bounded page and cursor budget"));
        }
        if line.is_empty() {
            if !frame.data.is_empty() {
                if frame.event == "error" {
                    return Err(serde_json::from_str::<ApiError>(frame.data.trim_end_matches('\n'))
                        .unwrap_or_else(|_| unavailable("the event stream reported an invalid API error")));
                }
                if frame.event == "gap" {
                    return Err(unavailable("the event cursor crosses a retained-history gap; continuity is not available"));
                }
                if frame.event == "cursor" {
                    let page: kronik_fleet::events::Page = serde_json::from_str(frame.data.trim_end_matches('\n'))
                        .map_err(|_| unavailable("the event stream contains an invalid cursor page"))?;
                    if source.is_some_and(|selected| !selected.matches(page.applied)) {
                        return Err(unavailable("the event stream returned a page outside the requested source"));
                    }
                    if page.gap.is_some() {
                        return Err(unavailable("the event cursor crosses a retained-history gap; continuity is not available"));
                    }
                    page.cursor.validate(&page.cursor.identity)
                        .map_err(|_| unavailable("the event stream contains an invalid resume cursor"))?;
                    let id = frame.id.take().ok_or_else(|| unavailable("a cursor page has no resume id"))?;
                    let next = decode_cursor(id.as_bytes())
                        .map_err(|_| unavailable("the event stream contains an invalid resume cursor"))?;
                    if next != page.cursor {
                        return Err(unavailable("the event stream cursor page and resume id disagree"));
                    }
                    *cursor = Some(next);
                } else {
                    if !matches!(frame.event.as_str(), "" | "message" | "operational") {
                        return Err(unavailable("the event stream contains an unsupported event type"));
                    }
                    let id = frame.id.take().ok_or_else(|| unavailable("an operational event has no resume cursor"))?;
                    let next = decode_cursor(id.as_bytes())
                        .map_err(|_| unavailable("the event stream contains an invalid resume cursor"))?;
                    let event: kronik_fleet::events::Event = serde_json::from_str(frame.data.trim_end_matches('\n'))
                        .map_err(|_| unavailable("the event stream contains an invalid event envelope"))?;
                    if event.schema != "kronik.event/v1" {
                        return Err(unavailable("the event stream uses an unsupported envelope schema"));
                    }
                    if source.is_some_and(|selected| !selected.matches(event.source)) {
                        return Err(unavailable("the event stream returned an event outside the requested source"));
                    }
                    if json {
                        serde_json::to_writer(&mut *out, &event)
                            .map_err(|_| unavailable("cannot write the event envelope"))?;
                        out.write_all(b"\n").map_err(|_| unavailable("cannot write the event envelope"))?;
                    } else {
                        // Only stable identity, position and closed provenance; never raw audit metadata.
                        write!(out, "{:?} ", event.id)
                            .map_err(|_| unavailable("cannot write the event envelope"))?;
                        if let Some(branch) = &event.branch {
                            write!(out, "{branch:?} ")
                                .map_err(|_| unavailable("cannot write the event envelope"))?;
                        }
                        match event.source {
                            SourcePos::Actor { shard: None, lsn } => write!(out, "actor-native:{lsn}"),
                            SourcePos::Actor { shard: Some(shard), lsn } => write!(out, "actor-{shard}:{lsn}"),
                            SourcePos::Metadata { index } => write!(out, "metadata:{index}"),
                        }.map_err(|_| unavailable("cannot write the event envelope"))?;
                        write!(out, "#{} record={}", event.subindex, event.record_kind)
                            .map_err(|_| unavailable("cannot write the event envelope"))?;
                        if let Some(adoption) = &event.data.adoption {
                            let marker = if adoption.current_projection {
                                b" adoption=current-projection (imported history)".as_slice()
                            } else {
                                b" adoption=archive (imported history)".as_slice()
                            };
                            out.write_all(marker).map_err(|_| unavailable("cannot write the event envelope"))?;
                        }
                        out.write_all(b"\n").map_err(|_| unavailable("cannot write the event envelope"))?;
                    }
                    out.flush().map_err(|_| unavailable("cannot flush the event envelope"))?;
                    *cursor = Some(next);
                    emitted += 1;
                    if limit == Some(emitted) { return Ok(()); }
                }
            }
            frame = Frame::default();
            continue;
        }
        if line.starts_with(':') { continue; }
        let (name, value) = line.split_once(':').map_or((line.as_str(), ""), |(name, value)| {
            (name, value.strip_prefix(' ').unwrap_or(value))
        });
        match name {
            "id" => {
                if value.len() > MAX_CURSOR || value.chars().any(char::is_control) {
                    return Err(unavailable("the event stream contains an invalid resume cursor"));
                }
                frame.id = Some(value.to_owned());
            }
            "event" => frame.event = value.to_owned(),
            "data" => { frame.data.push_str(value); frame.data.push('\n'); }
            _ => {}
        }
    }
}

/// SSE permits LF, CRLF and CR. Bound before extending, including comments.
fn sse_line(input: &mut impl io::BufRead, skip_lf: &mut bool) -> io::Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let bytes = input.fill_buf()?;
        if bytes.is_empty() {
            return if line.is_empty() { Ok(None) } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SSE line"))
            };
        }
        if *skip_lf {
            *skip_lf = false;
            if bytes[0] == b'\n' { input.consume(1); continue; }
        }
        let bytes = input.fill_buf()?;
        let end = bytes.iter().position(|byte| matches!(*byte, b'\r' | b'\n'));
        let count = end.unwrap_or(bytes.len());
        if count > MAX_LINE.saturating_sub(line.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized SSE line"));
        }
        line.extend_from_slice(&bytes[..count]);
        let cr = end.is_some_and(|index| bytes[index] == b'\r');
        input.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            *skip_lf = cr;
            return String::from_utf8(line).map(Some)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SSE UTF-8"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn source_options_are_canonical_bounded_and_local_to_list_and_tail() {
        let last = format!("actor-{}", kronik_proto::MAX_SHARD_COUNT - 1);
        for command in ["list", "tail"] {
            for (name, expected) in [
                ("actor-native", EventSource::Native),
                ("actor-0", EventSource::Actor(0)),
                ("metadata", EventSource::Metadata),
                (last.as_str(), EventSource::Actor(kronik_proto::MAX_SHARD_COUNT - 1)),
            ] {
                let cli = crate::Cli::try_parse_from(["kronik", "events", command, "--source", name]).unwrap();
                let crate::Command::Client(super::super::Command::Events(parsed)) = cli.command else {
                    panic!("expected events command");
                };
                let source = match parsed {
                    EventsCommand::List { source, .. } | EventsCommand::Tail { source, .. } => source,
                    _ => panic!("expected list or tail"),
                };
                assert_eq!(source, Some(expected));
                assert_eq!(expected.to_string(), name);
            }
            let cli = crate::Cli::try_parse_from(["kronik", "events", command]).unwrap();
            let crate::Command::Client(super::super::Command::Events(parsed)) = cli.command else {
                panic!("expected events command");
            };
            let source = match parsed {
                EventsCommand::List { source, .. } | EventsCommand::Tail { source, .. } => source,
                _ => panic!("expected list or tail"),
            };
            assert!(source.is_none());
            let outside = format!("actor-{}", kronik_proto::MAX_SHARD_COUNT);
            for malformed in ["", "native", "actor", "0", "actor-", "actor-00", "actor-01",
                "actor-+1", "actor--1", "actor-4294967296", "Actor-native", "metadata ",
                "actor-0&source=metadata", "metadata\r\nprivate: value", outside.as_str()] {
                // clap rejects the namespace before main can construct a context or do I/O.
                assert!(crate::Cli::try_parse_from(["kronik", "events", command, "--source", malformed]).is_err());
            }
        }
        assert!(crate::Cli::try_parse_from(["kronik", "events", "schemas", "--source", "metadata"]).is_err());
        assert!(crate::Cli::try_parse_from(["kronik", "events", "webhooks", "status", "--source", "metadata"]).is_err());
        assert!(crate::Cli::try_parse_from(["kronik", "events", "webhooks", "replay", "sink",
            "--cursor", "-", "--reason", "recover", "--source", "metadata"]).is_err());
        assert_eq!(target("/v1/events", Some(EventSource::Native), Some(2)),
            "/v1/events?source=actor-native&limit=2");
        assert_eq!(target("/v1/events/stream", Some(EventSource::Metadata), None),
            "/v1/events/stream?source=metadata");
        let domains = [
            (EventSource::Native, SourcePos::Actor { shard: None, lsn: 53 }),
            (EventSource::Actor(0), SourcePos::Actor { shard: Some(0), lsn: 53 }),
            (EventSource::Actor(1), SourcePos::Actor { shard: Some(1), lsn: 53 }),
            (EventSource::Metadata, SourcePos::Metadata { index: 53 }),
        ];
        for (selected, _) in domains {
            for (actual, position) in domains {
                assert_eq!(selected.matches(position), selected == actual);
            }
        }
    }

    #[test]
    fn selected_metadata_and_actor_zero_reach_native_http_and_framed_consumer_without_cursor_changes() {
        use std::io::Write as _;
        // Unit HTTP/framing coverage with real projections, not a member installation proof.
        for (selected, position) in [
            (EventSource::Metadata, SourcePos::Metadata { index: 53 }),
            (EventSource::Actor(0), SourcePos::Actor { shard: Some(0), lsn: 53 }),
        ] {
            let (event, _) = projected_event_at(position);
            let mut resume = full_event_cursor();
            resume.rewind(kronik_fleet::events::Position { source: position, subindex: 0 }).unwrap();
            let encoded = encode_cursor(&resume).unwrap();
            let next = kronik_fleet::events::resume_after(&event, &resume).unwrap();
            for streaming in [false, true] {
                let payload = if streaming {
                    kronik_fleet::events::sse_event(&event, &resume).unwrap().into_bytes()
                } else {
                    serde_json::to_vec(&kronik_fleet::events::Page { events: vec![event.clone()],
                        cursor: next.clone(), applied: position, gap: None, more: false }).unwrap()
                };
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("api.sock");
                let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
                let server = std::thread::spawn(move || {
                    let (socket, _) = listener.accept().unwrap();
                    socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                    socket.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                    let mut input = io::BufReader::new(socket);
                    let first = http::bounded_line(&mut input, 8192).unwrap().unwrap();
                    let mut cursor = None;
                    let mut bearer = None;
                    loop {
                        let line = http::bounded_line(&mut input, MAX_CURSOR + 1024).unwrap().unwrap();
                        if line == b"\r\n" { break; }
                        let line = String::from_utf8(line).unwrap();
                        if let Some(value) = line.strip_prefix("Last-Event-ID: ") {
                            assert!(cursor.is_none());
                            cursor = Some(value.strip_suffix("\r\n").unwrap().to_owned());
                        }
                        if let Some(value) = line.strip_prefix("Authorization: ") {
                            bearer = Some(value.strip_suffix("\r\n").unwrap().to_owned());
                        }
                    }
                    let socket = input.get_mut();
                    if streaming {
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
                        for chunk in payload.chunks(8191) {
                            write!(socket, "{:x}\r\n", chunk.len()).unwrap();
                            socket.write_all(chunk).unwrap();
                            socket.write_all(b"\r\n").unwrap();
                        }
                        // A finite consumer may close after the complete event, before the terminator.
                        if let Err(error) = socket.write_all(b"0\r\n\r\n") {
                            assert!(matches!(error.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset));
                        }
                    } else {
                        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", payload.len()).unwrap();
                        socket.write_all(&payload).unwrap();
                    }
                    (String::from_utf8(first).unwrap(), cursor.unwrap(), bearer.unwrap())
                });
                let ctx = Ctx { endpoint: Ok(http::Endpoint::Unix(path)), json: true,
                    token: Ok(Some("api-bearer".into())), url_flag: None };
                let url = if streaming {
                    target("/v1/events/stream", Some(selected), None)
                } else { target("/v1/events", Some(selected), Some(1)) };
                if streaming {
                    let response = http::stream(ctx.endpoint.as_ref().unwrap(), &url, Some("api-bearer"),
                        Some(&encoded), Arc::new(AtomicBool::new(false))).unwrap();
                    assert_eq!(response.status, 200);
                    assert_eq!(response.content_type.as_deref(), Some("text/event-stream"));
                    let mut output = Vec::new();
                    let mut checkpoint = Some(resume.clone());
                    follow(response.body, &mut output, true, Some(1), &mut checkpoint,
                        &AtomicBool::new(false), Some(selected)).unwrap();
                    assert_eq!(serde_json::from_slice::<kronik_fleet::events::Event>(&output).unwrap(), event);
                    assert_eq!(checkpoint, Some(next.clone()));
                    let mut footer = Vec::new();
                    let mut hint = Vec::new();
                    write_checkpoint(&mut footer, &mut hint, true, checkpoint.as_ref(), Some(selected)).unwrap();
                    assert_eq!(read_cursor("-", &mut footer.as_slice()).unwrap(), next);
                    assert!(String::from_utf8(hint).unwrap().contains(&format!("--source {selected} --cursor -")));
                } else {
                    let body = ctx.request("GET", &url, None, Some(&encoded))
                        .unwrap_or_else(|_| panic!("ordinary source request failed"));
                    let page: kronik_fleet::events::Page = ctx.decode(&body)
                        .unwrap_or_else(|_| panic!("ordinary source page failed"));
                    assert_eq!(page.applied, position);
                    assert_eq!(page.events, vec![event.clone()]);
                    assert_eq!(page.cursor, next);
                }
                let (request, cursor, bearer) = server.join().unwrap();
                assert_eq!(request, format!("GET {url} HTTP/1.1\r\n"));
                assert!(request.contains(&format!("?source={selected}")));
                assert!(!request.contains("cursor="));
                assert_eq!(cursor, encoded);
                assert_eq!(bearer, "Bearer api-bearer");
            }
        }
    }

    #[test]
    fn requested_source_mismatches_fail_before_output_or_checkpoint_but_omission_keeps_all_sources() {
        let (actor, start) = projected_event_at(SourcePos::Actor { shard: Some(0), lsn: 53 });
        let next = kronik_fleet::events::resume_after(&actor, &start).unwrap();
        let event_frame = kronik_fleet::events::sse_event(&actor, &start).unwrap();
        let page_frame = kronik_fleet::events::sse_cursor(&kronik_fleet::events::Page {
            events: Vec::new(), cursor: next.clone(), applied: actor.source, gap: None, more: false }).unwrap();
        for selected in [EventSource::Native, EventSource::Actor(1), EventSource::Metadata] {
            for frame in [&event_frame, &page_frame] {
                let mut checkpoint = Some(start.clone());
                let mut output = Vec::new();
                let error = follow(frame.as_bytes(), &mut output, true, Some(1), &mut checkpoint,
                    &AtomicBool::new(false), Some(selected)).unwrap_err();
                assert!(error.message.contains("outside the requested source"));
                assert!(output.is_empty());
                assert_eq!(checkpoint, Some(start.clone()));
            }
        }
        let (metadata, _) = projected_event_at(SourcePos::Metadata { index: 53 });
        let expected = kronik_fleet::events::resume_after(&metadata, &next).unwrap();
        let metadata_frame = kronik_fleet::events::sse_event(&metadata, &next).unwrap();
        let combined = format!("{event_frame}{metadata_frame}");
        let mut checkpoint = Some(start);
        let mut output = Vec::new();
        follow(combined.as_bytes(), &mut output, true, Some(2), &mut checkpoint,
            &AtomicBool::new(false), None).unwrap();
        let events: Vec<kronik_fleet::events::Event> = output.split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty()).map(|line| serde_json::from_slice(line).unwrap()).collect();
        assert_eq!(events, vec![actor, metadata]);
        assert_eq!(checkpoint, Some(expected));
        let page = kronik_fleet::events::Page { events: Vec::new(), cursor: next.clone(),
            applied: SourcePos::Actor { shard: Some(0), lsn: 53 }, gap: None, more: false };
        let mut checkpoint = None;
        let frame = kronik_fleet::events::sse_cursor(&page).unwrap();
        assert!(follow(frame.as_bytes(), &mut Vec::new(), true, Some(1), &mut checkpoint,
            &AtomicBool::new(false), Some(EventSource::Actor(0))).is_err());
        assert_eq!(checkpoint, Some(next));
    }

    #[test]
    fn full_cursor_stdin_and_published_footer_round_trip_without_argv_or_cache() {
        let full = full_event_cursor();
        let encoded = encode_cursor(&full).unwrap();
        assert!(encoded.len() > 200_000, "exercise the observed oversized argv case");
        let from_stdin = read_cursor("-", &mut encoded.as_bytes()).unwrap();
        assert_eq!(from_stdin, full);
        let small = ResumeCursor::new(kronik_fleet::events::Identity {
            installation: "node-a".into(), branch: "main".into() });
        struct NoRead;
        impl io::Read for NoRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("literal must not read stdin"); }
        }
        assert_eq!(read_cursor(&encode_cursor(&small).unwrap(), &mut NoRead).unwrap(), small);
        let mut footer = Vec::new();
        let mut hint = Vec::new();
        write_checkpoint(&mut footer, &mut hint, true, Some(&from_stdin), None).unwrap();
        assert_eq!(read_cursor("-", &mut footer.as_slice()).unwrap(), full);
        assert_eq!(serde_json::from_slice::<ResumeCursor>(&footer).unwrap(), full);
        assert!(footer.starts_with(b"{\"schema\":\"kronik.events-cursor/v1\","));
        let hint = String::from_utf8(hint).unwrap();
        assert!(hint.contains("--cursor - < checkpoint.json"));
        assert!(hint.len() < 256);
        let mut out = Vec::new();
        let mut human = Vec::new();
        write_checkpoint(&mut out, &mut human, false, Some(&full), None).unwrap();
        assert!(out.is_empty());
        let human = String::from_utf8(human).unwrap();
        assert!(human.starts_with("Cursor checkpoint (JSON):\n"));
        let checkpoint = human.lines().find(|line| line.starts_with('{')).unwrap();
        assert_eq!(serde_json::from_str::<ResumeCursor>(checkpoint).unwrap(), full);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_checkpoint(&mut out, &mut err, true, None, None).unwrap();
        assert!(out.is_empty() && err.is_empty());
        for command in ["list", "tail"] {
            assert!(crate::Cli::try_parse_from(["kronik", "events", command, "--cursor", "-"]).is_ok());
        }
        assert!(crate::Cli::try_parse_from(["kronik", "events", "webhooks", "replay", "sink",
            "--cursor", "-", "--reason", "recover"]).is_ok());
    }

    #[test]
    fn cursor_input_is_bounded_typed_and_rejected_before_any_request_without_echo() {
        let mut invalid_schema = serde_json::to_value(full_event_cursor()).unwrap();
        invalid_schema["schema"] = json!("private-invalid-schema");
        let mut invalid_domain = full_event_cursor();
        let position = invalid_domain.streams.remove("actor-native").unwrap();
        invalid_domain.streams.insert("private-domain".into(), position);
        for bytes in [
            Vec::new(), b"private-not-json".to_vec(), b"@private-path".to_vec(), vec![255],
            serde_json::to_vec(&invalid_schema).unwrap(), serde_json::to_vec(&invalid_domain).unwrap(),
            vec![b'x'; MAX_CURSOR + 100],
        ] {
            let mut input = io::Cursor::new(bytes);
            let error = read_cursor("-", &mut input).unwrap_err();
            assert_eq!(error.code, ErrorCode::BadRequest);
            assert!(!error.message.contains("private"));
            assert!(input.position() <= (MAX_CURSOR + 1) as u64);
        }
        struct BrokenRead;
        impl io::Read for BrokenRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "private input detail"))
            }
        }
        assert!(!read_cursor("-", &mut BrokenRead).unwrap_err().message.contains("private"));
        let mut oversized = ResumeCursor::new(kronik_fleet::events::Identity {
            installation: "node-a".into(), branch: "main".into() });
        oversized.identity.installation = "x".repeat(MAX_CURSOR);
        assert_eq!(encode_cursor(&oversized).unwrap_err().code, ErrorCode::BadRequest);
        let dir = tempfile::tempdir().unwrap();
        let ctx = Ctx { endpoint: Ok(http::Endpoint::Unix(dir.path().join("absent.sock"))), json: true,
            token: Ok(None), url_flag: None };
        for command in [
            EventsCommand::List { source: None, cursor: Some("private".into()), limit: None },
            EventsCommand::Tail { source: None, cursor: Some("private".into()), limit: Some(1) },
            EventsCommand::Webhooks(WebhooksCommand::Replay { name: "sink".into(), cursor: "private".into(),
                mutation: Mutation { reason: Some("recover".into()), dry_run: false } }),
        ] {
            let Err(Error::Local(error)) = events(&ctx, command) else { panic!("must reject before HTTP"); };
            assert_eq!(error.code, ErrorCode::BadRequest);
            assert!(!error.message.contains("private"));
        }
    }

    #[test]
    fn checkpoints_commit_only_after_complete_valid_frames_and_successful_output() {
        let (first, start) = projected_event();
        let acknowledged = kronik_fleet::events::resume_after(&first, &start).unwrap();
        let (second, _) = projected_event_at(SourcePos::Actor { shard: Some(7), lsn: 8 });
        let next = kronik_fleet::events::resume_after(&second, &acknowledged).unwrap();
        let first_frame = kronik_fleet::events::sse_event(&first, &start).unwrap();
        let id = encode_cursor(&next).unwrap();
        let body = serde_json::to_string(&second).unwrap();
        let mut gap_cursor = acknowledged.clone();
        gap_cursor.rewind(kronik_fleet::events::Position {
            source: SourcePos::Actor { shard: Some(7), lsn: 9 }, subindex: 0 }).unwrap();
        let gap = kronik_fleet::events::Page {
            events: Vec::new(), cursor: gap_cursor,
            applied: SourcePos::Actor { shard: Some(7), lsn: 8 },
            gap: Some(kronik_fleet::events::Gap {
                from: SourcePos::Actor { shard: Some(7), lsn: 8 },
                through: SourcePos::Actor { shard: Some(7), lsn: 8 },
            }), more: true,
        };
        for incomplete in [
            format!("id: {id}\n"),
            format!("id: {id}\nevent: operational\ndata: {body}\n"),
            format!("id: {id}\nevent: operational\ndata: private-invalid-json\n\n"),
            kronik_fleet::events::sse_cursor(&gap).unwrap(),
        ] {
            let stream = format!("{first_frame}{incomplete}");
            let mut checkpoint = None;
            let mut output = Vec::new();
            assert!(follow(stream.as_bytes(), &mut output, true, Some(2), &mut checkpoint,
                &AtomicBool::new(false), None).is_err());
            assert_eq!(checkpoint, Some(acknowledged.clone()));
            assert_eq!(serde_json::from_slice::<kronik_fleet::events::Event>(&output).unwrap(), first);
            let mut footer = Vec::new();
            write_checkpoint(&mut footer, &mut Vec::new(), true, checkpoint.as_ref(), None).unwrap();
            assert_eq!(read_cursor("-", &mut footer.as_slice()).unwrap(), acknowledged);
        }
        struct FailAfterFlush { flushes: usize, fail_write: bool }
        impl io::Write for FailAfterFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.flushes != 0 && self.fail_write {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                if self.flushes > 1 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"));
                }
                Ok(())
            }
        }
        let second_frame = kronik_fleet::events::sse_event(&second, &acknowledged).unwrap();
        for fail_write in [true, false] {
            let stream = format!("{first_frame}{second_frame}");
            let mut checkpoint = None;
            let mut output = FailAfterFlush { flushes: 0, fail_write };
            let error = follow(stream.as_bytes(), &mut output, true, Some(2), &mut checkpoint, &AtomicBool::new(false), None).unwrap_err();
            assert!(error.message.contains(if fail_write { "cannot write" } else { "cannot flush" }));
            assert_eq!(checkpoint, Some(acknowledged.clone()));
        }
        for fail_write in [true, false] {
            let mut broken_footer = FailAfterFlush { flushes: 1, fail_write };
            assert!(write_checkpoint(&mut broken_footer, &mut Vec::new(), true, Some(&acknowledged), None).is_err());
        }
    }

    #[test]
    fn cancellation_preserves_the_last_complete_checkpoint_but_disconnect_is_an_error() {
        struct AbortAfterBytes(io::Cursor<Vec<u8>>);
        impl io::Read for AbortAfterBytes {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let read = self.0.read(bytes)?;
                if read == 0 { Err(io::Error::new(io::ErrorKind::ConnectionAborted, "cancelled")) }
                else { Ok(read) }
            }
        }
        let (event, cursor) = projected_event();
        let frame = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
        let expected = kronik_fleet::events::resume_after(&event, &cursor).unwrap();
        for cancelled in [false, true] {
            let input = AbortAfterBytes(io::Cursor::new(format!("{frame}id: partial").into_bytes()));
            let mut checkpoint = None;
            let mut output = Vec::new();
            let result = follow(input, &mut output, true, None, &mut checkpoint, &AtomicBool::new(cancelled), None);
            assert_eq!(result.is_ok(), cancelled);
            assert_eq!(checkpoint, Some(expected.clone()));
            let mut footer = Vec::new();
            write_checkpoint(&mut footer, &mut Vec::new(), true, checkpoint.as_ref(), None).unwrap();
            assert_eq!(read_cursor("-", &mut footer.as_slice()).unwrap(), expected);
        }
    }

    #[test]
    fn full_cursor_and_maximum_event_page_fit_without_dropping_streams() {
        let cursor = full_event_cursor();
        let encoded_cursor = serde_json::to_string(&cursor).unwrap();
        assert_eq!(cursor.streams.len(), kronik_fleet::events::MAX_STREAMS);
        assert!(encoded_cursor.len() > 65_534);
        assert!(encoded_cursor.len() <= MAX_CURSOR);
        let (mut event, _) = projected_event_at(SourcePos::Actor { shard: Some(7), lsn: u64::MAX });
        event.data.action = "a".repeat(kronik_fleet::events::MAX_PAGE_BYTES - 4096);
        assert!(event.body().unwrap().len() <= kronik_fleet::events::MAX_PAGE_BYTES);
        let page = kronik_fleet::events::Page { events: vec![event.clone()], cursor: cursor.clone(),
            applied: event.source, gap: None, more: false };
        let cursor_frame = kronik_fleet::events::sse_cursor(&page).unwrap();
        let event_frame = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
        assert!(cursor_frame.len() > 1024 * 1024);
        assert!(cursor_frame.len() <= MAX_FRAME);
        assert!(event_frame.len() > 1024 * 1024);
        assert!(event_frame.len() <= MAX_FRAME);
        let stream = format!("{cursor_frame}{event_frame}");
        let mut output = Vec::new();
        let mut checkpoint = None;
        follow(stream.as_bytes(), &mut output, true, Some(1), &mut checkpoint, &AtomicBool::new(false), None).unwrap();
        let resumed = checkpoint.unwrap();
        let expected = kronik_fleet::events::resume_after(&event, &cursor).unwrap();
        assert_eq!(resumed, expected);
        assert_eq!(resumed.streams.len(), kronik_fleet::events::MAX_STREAMS);
        assert_eq!(resumed.streams["metadata"], cursor.streams["metadata"]);
        let rendered: kronik_fleet::events::Event = serde_json::from_slice(&output).unwrap();
        assert_eq!(rendered, event);
    }

    #[test]
    fn cursor_never_enters_target_and_limits_are_validated() {
        assert_eq!(target("/v1/events", None, Some(2)), "/v1/events?limit=2");
        assert_eq!(target("/v1/events/stream", None, None), "/v1/events/stream");
        for command in ["list", "tail"] {
            for limit in ["0", "-1", "18446744073709551616", "secret"] {
                assert!(crate::Cli::try_parse_from(["kronik", "events", command, "--limit", limit]).is_err());
            }
        }
        assert!(crate::Cli::try_parse_from(["kronik", "events", "list", "--limit", "1001"]).is_err());
    }

    #[test]
    fn bounds_lines_frames_and_cursor_without_leaking_input() {
        let cases = [
            format!("data: {}\n\n", "private".repeat(MAX_LINE)),
            format!("id: {}\n\n", "s".repeat(MAX_CURSOR + 1)),
            "id: private\0cursor\n\n".to_owned(),
            "data: private incomplete".to_owned(),
            "id: cursor\ndata: private invalid JSON\n\n".to_owned(),
            ": comment\n".repeat(MAX_FRAME / 8),
        ];
        for case in cases {
            let mut out = Vec::new();
            let error = follow(case.as_bytes(), &mut out, true, Some(1), &mut None, &AtomicBool::new(false), None).unwrap_err();
            assert!(out.is_empty());
            assert!(!error.message.contains("private"));
        }
    }

    #[test]
    fn accepts_sse_line_endings_and_rejects_invalid_utf8() {
        let mut reader = io::BufReader::new(&b"one\rtwo\r\nthree\n\n"[..]);
        let mut skip = false;
        for expected in ["one", "two", "three", ""] {
            assert_eq!(sse_line(&mut reader, &mut skip).unwrap().as_deref(), Some(expected));
        }
        assert!(sse_line(&mut reader, &mut skip).unwrap().is_none());
        assert!(sse_line(&mut io::BufReader::new(&b"\xff\n"[..]), &mut false).is_err());
    }

    #[test]
    fn cursor_heartbeats_do_not_count_and_gap_and_errors_fail_closed() {
        for stream in [
            "id: resume\nevent: cursor\ndata: {}\n\n",
            "id: resume\nevent: gap\ndata: {}\n\n",
            "event: error\ndata: private invalid error\n\n",
            "event: unknown\ndata: {}\n\n",
        ] {
            let mut out = Vec::new();
            assert!(follow(stream.as_bytes(), &mut out, true, Some(1), &mut None, &AtomicBool::new(false), None).is_err());
            assert!(out.is_empty());
        }
        let error = ApiError::new(ErrorCode::ScopeMissing, "scope denied");
        let stream = format!("event: error\ndata: {}\n\n", serde_json::to_string(&error).unwrap());
        assert_eq!(follow(stream.as_bytes(), &mut Vec::new(), true, None, &mut None, &AtomicBool::new(false), None).unwrap_err().code, ErrorCode::ScopeMissing);
    }

    #[test]
    fn webhook_replay_sends_the_actual_api_cursor_object_over_ordinary_unix_http() {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (_, cursor) = projected_event();
        let receiver = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "owned replay receiver accept deadline");
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => panic!("owned replay receiver accept failed"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut stream = io::BufReader::new(stream);
            http::bounded_line(&mut stream, 8192).unwrap().unwrap();
            let mut length = None;
            loop {
                let line = http::bounded_line(&mut stream, 8192).unwrap().unwrap();
                if line == b"\r\n" { break; }
                let line = std::str::from_utf8(&line).unwrap();
                if let Some(value) = line.strip_prefix("Content-Length: ") {
                    length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let length = length.unwrap();
            assert!(length <= 1 << 20);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let request: kronik_api::events::ReplayRequest = serde_json::from_slice(&body).unwrap();
            let body = serde_json::to_vec(&kronik_api::events::ReplayResponse {
                dry_run: request.dry_run, cursor: request.cursor }).unwrap();
            write!(stream.get_mut(), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
            stream.get_mut().write_all(&body).unwrap();
            stream.get_mut().flush().unwrap();
        });
        let ctx = Ctx { endpoint: Ok(http::Endpoint::Unix(socket)), json: true,
            token: Ok(Some("ordinary-api-fixture".into())), url_flag: None };
        let command = EventsCommand::Webhooks(WebhooksCommand::Replay {
            name: "proof:actor-native".into(), cursor: encode_cursor(&cursor).unwrap(),
            mutation: Mutation { reason: Some("replay the owned fixture".into()), dry_run: true },
        });
        assert!(events(&ctx, command).is_ok());
        receiver.join().unwrap();
    }

    fn projected_event() -> (kronik_fleet::events::Event, kronik_fleet::events::ResumeCursor) {
        projected_event_at(SourcePos::Actor { shard: Some(7), lsn: 7 })
    }

    fn projected_event_at(source: SourcePos) -> (kronik_fleet::events::Event, kronik_fleet::events::ResumeCursor) {
        use kronik_fleet::events::{Identity, ResumeCursor};
        use kronik_otel::audit::{Keys, Mapper};
        use kronik_privacy::sealer::Sealer;
        use kronik_proto::{Record, log::v1 as pb};
        let identity = Identity { installation: "node-a".into(), branch: "main".into() };
        let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
        let keyed = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
        let mapper = Mapper { keys: Keys::Omit,
            sealer: Arc::new(Sealer::plain().with_pseudonyms(keyed)), branch: "main".into() };
        let record = Record::AuditEvent(pb::AuditEvent {
            action: "proposal.create".into(), target: "p-7".into(),
            details: std::collections::BTreeMap::from([("state".into(), "ready".into())]),
            audit: Some(pb::Audit { token_id: "token:ops".into(),
                reason: "rotate PRIVATE-CREDENTIAL".into(), wall_time_ms: 123 }),
            operation: None,
            ..Default::default()
        });
        let secrets = [("token", b"PRIVATE-CREDENTIAL".as_slice())];
        let event = match source {
            SourcePos::Actor { .. } => kronik_fleet::events::project(&mapper, &identity, source, &record, &secrets),
            SourcePos::Metadata { index } => {
                let record = Record::decode(record.kind(), &record.encode()).unwrap();
                let envelope = kronik_log::MetadataAuditRecord { index, record, native_origin: None };
                kronik_fleet::events::project_metadata(&mapper, &identity, &envelope, &secrets)
            }
        }.unwrap().remove(0);
        (event, ResumeCursor::new(identity))
    }

    #[test]
    fn native_secret_adoption_metadata_fixture_labels_archive_and_current_imports() {
        use kronik_fleet::events::Identity;
        use kronik_otel::audit::{Keys, Mapper};
        use kronik_privacy::sealer::Sealer;
        use kronik_proto::{Record, log::v1 as pb};
        let identity = Identity { installation: "installation-1".into(), branch: "main".into() };
        let master = kronik_privacy::MasterKey::from_bytes([7; 32]).unwrap();
        let keyed = kronik_privacy::keystore::Pseudonyms::new(&master).unwrap();
        let mapper = Mapper { keys: Keys::Omit,
            sealer: Arc::new(Sealer::plain().with_pseudonyms(keyed)), branch: "main".into() };
        for current_projection in [false, true] {
            let bytes = kronik_core::ids::unhex(include_str!(
                "../../../kronik-proto/tests/fixtures/secret-version-wide-active-v1.hex").trim()).unwrap();
            let record = Record::decode(kronik_proto::kind::SECRET_VERSION, &bytes).unwrap();
            // Existing supported Record45 sidecar: a wire/rendering unit, not a Raft receipt.
            let envelope = kronik_log::MetadataAuditRecord { index: 53, record,
                native_origin: Some(pb::NativeAuthorityOrigin {
                    source: None,
                    adoption_audit: Some(pb::Audit { token_id: "unix:uid=0".into(),
                        reason: "native authority initialization".into(), wall_time_ms: 37 }),
                    current_projection,
                }) };
            let event = kronik_fleet::events::project_metadata(&mapper, &identity, &envelope, &[]).unwrap().remove(0);
            assert_eq!(event.source, SourcePos::Metadata { index: 53 });
            assert_eq!(event.record_kind, envelope.record.kind());
            assert_eq!(Some(event.data.record_hash.clone()),
                kronik_otel::audit::record_hash(&envelope.record, &mapper.sealer));
            assert_eq!(event.data.adoption.as_ref().unwrap().current_projection, current_projection);
            assert!(event.branch.is_none());
            let cursor = ResumeCursor::new(identity.clone());
            let stream = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
            let mut human = Vec::new();
            follow(stream.as_bytes(), &mut human, false, Some(1), &mut None, &AtomicBool::new(false), None).unwrap();
            let human = String::from_utf8(human).unwrap();
            for private in ["unix:uid=0", "native authority initialization", "adoption_audit"] {
                assert!(!human.contains(private));
            }
            let mut json = Vec::new();
            follow(stream.as_bytes(), &mut json, true, Some(1), &mut None, &AtomicBool::new(false), None).unwrap();
            let decoded: kronik_fleet::events::Event = serde_json::from_slice(&json).unwrap();
            assert_eq!(decoded, event);
            assert_eq!(decoded.data.adoption.unwrap().current_projection, current_projection);
        }
    }


    #[test]
    fn finite_tail_reads_actual_projected_event_without_reading_to_eof() {
        let (event, cursor) = projected_event();
        let encoded = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
        let stream = format!(": heartbeat\n\n{encoded}data: incomplete private trailer");
        let mut out = Vec::new();
        let mut checkpoint = None;
        follow(stream.as_bytes(), &mut out, true, Some(1), &mut checkpoint, &AtomicBool::new(false), None).unwrap();
        let expected = kronik_fleet::events::resume_after(&event, &cursor).unwrap();
        assert_eq!(checkpoint, Some(expected.clone()));
        let rendered: kronik_fleet::events::Event = serde_json::from_slice(&out).unwrap();
        assert_eq!(rendered.id, event.id);
        assert_eq!(rendered.branch.as_deref(), Some("main"));
        assert_eq!(rendered.data.action, "proposal.create");
        assert_eq!(rendered.data.kind, "audit_event");
        assert_eq!(rendered.source, event.source);
        assert!(!std::str::from_utf8(&out).unwrap().contains("PRIVATE-CREDENTIAL"));
        write_checkpoint(&mut out, &mut Vec::new(), true, checkpoint.as_ref(), None).unwrap();
        let lines: Vec<serde_json::Value> = out.split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty()).map(|line| serde_json::from_slice(line).unwrap()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["schema"], "kronik.event/v1");
        assert_eq!(lines[1]["schema"], "kronik.events-cursor/v1");
        assert_eq!(serde_json::from_value::<ResumeCursor>(lines[1].clone()).unwrap(), expected);
        let schema = tail_schema(&mut kronik_api::openapi::generator());
        assert_eq!(schema.get("oneOf").and_then(serde_json::Value::as_array).unwrap().len(), 2);
        let mut human = Vec::new();
        follow(encoded.as_bytes(), &mut human, false, Some(1), &mut None, &AtomicBool::new(false), None).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("actor-7:7"));
        assert!(!human.contains("rotate"));
    }

    #[test]
    fn human_tail_distinguishes_native_sharded_and_metadata_sources() {
        for (source, expected) in [
            (SourcePos::Actor { shard: None, lsn: 7 }, "actor-native:7"),
            (SourcePos::Actor { shard: Some(3), lsn: 7 }, "actor-3:7"),
            (SourcePos::Metadata { index: 7 }, "metadata:7"),
        ] {
            let (event, cursor) = projected_event_at(source);
            let stream = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
            let mut human = Vec::new();
            follow(stream.as_bytes(), &mut human, false, Some(1), &mut None, &AtomicBool::new(false), None).unwrap();
            let human = String::from_utf8(human).unwrap();
            assert!(human.contains(expected));
            assert!(!human.contains("adoption="));
            assert_eq!(human.contains("\"main\""), matches!(source, SourcePos::Actor { .. }));
            let mut json = Vec::new();
            follow(stream.as_bytes(), &mut json, true, Some(1), &mut None, &AtomicBool::new(false), None).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(value["source"], serde_json::to_value(source).unwrap());
            assert!(value.get("lsn").is_none());
            assert!(value.get("shard").is_none());
            match source {
                SourcePos::Actor { .. } => {
                    assert_eq!(event.branch.as_deref(), Some("main"));
                    assert_eq!(value["branch"], "main");
                }
                SourcePos::Metadata { .. } => {
                    assert!(event.branch.is_none());
                    assert!(value.get("branch").is_none());
                }
            }
        }
    }

    #[test]
    fn cursor_page_advances_resume_even_without_operational_events() {
        let (_, mut cursor) = projected_event();
        cursor.rewind(kronik_fleet::events::Position {
            source: SourcePos::Actor { shard: Some(7), lsn: 9 }, subindex: 2 }).unwrap();
        let page = kronik_fleet::events::Page { events: Vec::new(), cursor: cursor.clone(),
            applied: SourcePos::Actor { shard: Some(7), lsn: 12 }, gap: None, more: true };
        let stream = kronik_fleet::events::sse_cursor(&page).unwrap();
        let mut out = Vec::new();
        let mut checkpoint = None;
        let error = follow(stream.as_bytes(), &mut out, true, Some(1), &mut checkpoint, &AtomicBool::new(false), None).unwrap_err();
        assert!(out.is_empty());
        assert_eq!(checkpoint, Some(cursor));
        assert!(error.hint.unwrap().contains("--cursor - < checkpoint.json"));
        let mut gapped = page.clone();
        gapped.gap = Some(kronik_fleet::events::Gap {
            from: SourcePos::Actor { shard: Some(7), lsn: 1 },
            through: SourcePos::Actor { shard: Some(7), lsn: 8 } });
        let stream = format!("event: cursor\ndata: {}\n\n", serde_json::to_string(&gapped).unwrap());
        assert!(follow(stream.as_bytes(), &mut Vec::new(), true, Some(1), &mut None, &AtomicBool::new(false), None).unwrap_err().message.contains("gap"));
        let mut invalid = page.clone();
        invalid.cursor.schema = "unpublished".into();
        let stream = kronik_fleet::events::sse_cursor(&invalid).unwrap();
        assert!(follow(stream.as_bytes(), &mut Vec::new(), true, Some(1), &mut None, &AtomicBool::new(false), None).is_err());
        let mut mismatched = page.clone();
        let position = mismatched.cursor.streams.remove("actor-7").unwrap();
        mismatched.cursor.streams.insert("metadata".into(), position);
        let stream = kronik_fleet::events::sse_cursor(&mismatched).unwrap();
        assert!(follow(stream.as_bytes(), &mut Vec::new(), true, Some(1), &mut None, &AtomicBool::new(false), None).is_err());
        let wrong = ResumeCursor::new(page.cursor.identity.clone());
        let stream = format!("id: {}\nevent: cursor\ndata: {}\n\n",
            encode_cursor(&wrong).unwrap(), serde_json::to_string(&page).unwrap());
        let mut checkpoint = None;
        let error = follow(stream.as_bytes(), &mut Vec::new(), true, None, &mut checkpoint, &AtomicBool::new(false), None).unwrap_err();
        assert!(error.message.contains("disagree"));
        assert!(checkpoint.is_none());
        let stream = format!("event: cursor\ndata: {}\n\n", serde_json::to_string(&page).unwrap());
        assert!(follow(stream.as_bytes(), &mut Vec::new(), true, None, &mut checkpoint,
            &AtomicBool::new(false), None).is_err());
        assert!(checkpoint.is_none());
    }

    #[test]
    fn malformed_envelopes_missing_ids_and_output_failure_never_succeed() {
        let (event, cursor) = projected_event();
        let body = serde_json::to_string(&event).unwrap();
        let id = encode_cursor(&kronik_fleet::events::resume_after(&event, &cursor).unwrap()).unwrap();
        let mut invalid = serde_json::to_value(&event).unwrap();
        invalid["raw_metadata"] = json!({"credential": "private"});
        let mut metadata = serde_json::to_value(&event).unwrap();
        metadata["data"]["reason"] = json!("private credential");
        let mut wrong_schema = event.clone();
        wrong_schema.schema = "unpublished/v2".into();
        for stream in [
            format!("data: {body}\n\n"),
            format!("id: {id}\ndata: {}\n\n", serde_json::to_string(&invalid).unwrap()),
            format!("id: {id}\ndata: {}\n\n", serde_json::to_string(&metadata).unwrap()),
            format!("id: {id}\ndata: {}\n\n", serde_json::to_string(&wrong_schema).unwrap()),
        ] {
            let mut out = Vec::new();
            assert!(follow(stream.as_bytes(), &mut out, true, Some(1), &mut None, &AtomicBool::new(false), None).is_err());
            assert!(out.is_empty());
        }
        struct BrokenOutput;
        impl io::Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let stream = kronik_fleet::events::sse_event(&event, &cursor).unwrap();
        assert!(follow(stream.as_bytes(), &mut BrokenOutput, true, Some(1), &mut None, &AtomicBool::new(false), None).is_err());
    }
}
