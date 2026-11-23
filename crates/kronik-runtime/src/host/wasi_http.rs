//! Standard `fetch`: `wasi:http/outgoing-handler` as `http.fetch` effects
//! (ADR 0070, M22).
//!
//! `wasmtime-wasi-http` (p2 only, no network code) builds the requests. Its
//! `send_request` hook only hands each request back; `handle` queues it with
//! its `future-incoming-response`. Nothing runs until the guest waits:
//! `wasi:io/poll.poll`, `pollable.block` and the blocking stream calls first
//! *drive* the queue. For each request in `handle` order, drive takes the
//! body frames already written; once the body is complete it takes the next
//! operation ordinal, runs the effect through [`EffectGate::fetch`] (one at a
//! time, as `http-client.fetch`) and writes the response into the future's
//! table entry. The wait itself must then finish at once: nothing outside the
//! guest makes progress, so a wait that would block can never end and traps.
//! What a wait returns therefore depends only on what the guest did and on
//! the effects' results, never on timing.
//!
//! Bodies above the kind's blob threshold (M25 §7.6, ADR 0121 §6), in a turn
//! with a blob host whose component reads blobs:
//!
//! - A response the gate gives as a blob is read from the store one frame
//!   (at most 64 KiB) at a time, and only at a wait: when the body's stream
//!   finds nothing to take, the body wants a frame, and the next wait reads
//!   exactly that one. A wait that is not ready because it found such a body
//!   empty reads its frame and looks again. A non-blocking read returns only
//!   what an earlier wait read, so what it returns depends only on the
//!   guest's calls, and the host holds at most one frame of a body.
//! - A request body that passes the threshold is spooled into a blob of the
//!   turn's subject instead of host memory, and the effect sends the blob.
//!
//! [`EffectGate::fetch`]: super::EffectGate::fetch

use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full};
use kronik_core::env::BoxFuture;
use kronik_core::sync::lock;
use kronik_proto::log::v1 as pb;
use wasmtime::component::{Linker, Resource, ResourceTable};
use wasmtime::format_err;
use wasmtime_wasi::p2::DynPollable;
use wasmtime_wasi::runtime::{AbortOnDropJoinHandle, poll_noop};
use wasmtime_wasi_http::p2::bindings::http::{outgoing_handler, types as ht};
use wasmtime_wasi_http::p2::body::HyperIncomingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, HostOutgoingRequest};
use wasmtime_wasi_http::p2::{HttpError, HttpResult};
use wasmtime_wasi_http::{
    Error as HttpErr, WasiBody, WasiHttp, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
};
use wasmtime_wasi_io::bindings::wasi::io::{poll, streams};
use wasmtime_wasi_io::streams::{DynInputStream, DynOutputStream, StreamError, StreamResult};

use super::blobs::{
    BLOB_FRAME_BYTES, BlobHost, BlobHostError, MAX_BLOB_CALL_BYTES, MAX_OPEN_WRITERS, read_charge,
};
use super::{
    FetchBody, FetchHeader, FetchOutcome, FetchRequest, FetchResponseBody, LogEvent, TurnHost,
};

/// Requests a turn may have started and not yet waited for: each holds its
/// request body in host memory up to the blob threshold, or, without
/// spooling, up to `message_bytes`.
const MAX_PENDING: usize = 32;

/// The `wasi:http` version `wasmtime-wasi-http` 50 implements; the linker
/// accepts any 0.2.x import for it.
const OUTGOING_HANDLER: &str = "wasi:http/outgoing-handler@0.2.12";

/// The turn's `wasi:http` state.
pub(crate) struct State {
    ctx: WasiHttpCtx,
    hooks: Hooks,
    pending: Vec<Pending>,
    /// A request body above this many bytes is spooled into a blob: set for
    /// a turn with a blob host whose component reads blobs (M25 §7.6).
    spool_above: Option<u64>,
    /// The blob-backed response bodies, while the guest holds them.
    bodies: Vec<Weak<Mutex<BlobFrames>>>,
}

impl State {
    pub(crate) fn new() -> State {
        State {
            ctx: WasiHttpCtx::new(),
            hooks: Hooks::default(),
            pending: Vec::new(),
            spool_above: None,
            bodies: Vec::new(),
        }
    }
}

/// A request `handle` queued and drive has not run yet.
struct Pending {
    /// The table index of its `future-incoming-response`.
    rep: u32,
    parts: http::request::Parts,
    body: WasiBody,
    /// The body taken so far, while it is not above the spool threshold.
    bytes: Vec<u8>,
    /// The blob writer the body went to once it passed the threshold.
    writer: Option<u64>,
    done: bool,
}

/// What the host holds of a blob-backed response body: at most one frame.
struct BlobFrames {
    blob: pb::BlobRef,
    /// Where the next frame starts.
    next: u64,
    /// The frame a wait read, not taken by the body's stream yet.
    frame: Option<Bytes>,
    /// The stream found nothing to take: the next wait reads a frame.
    wanted: bool,
    /// The store could not give the next frame: the stream's next read
    /// fails with this.
    failed: Option<HttpErr>,
}

/// A response body above the threshold, as `wasi:http` reads it: its frames
/// come only from [`TurnHost::fill_bodies`], at the guest's waits.
struct BlobBody(Arc<Mutex<BlobFrames>>);

impl Body for BlobBody {
    type Data = Bytes;
    type Error = HttpErr;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, HttpErr>>> {
        let mut f = lock(&self.0);
        if let Some(bytes) = f.frame.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(error) = f.failed.take() {
            return Poll::Ready(Some(Err(error)));
        }
        if f.next >= f.blob.size {
            return Poll::Ready(None);
        }
        // No waker: nothing but a wait reads the next frame.
        f.wanted = true;
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        let f = lock(&self.0);
        f.frame.is_none() && f.failed.is_none() && f.next >= f.blob.size
    }

    fn size_hint(&self) -> SizeHint {
        let f = lock(&self.0);
        let held = f.frame.as_ref().map_or(0, |frame| frame.len() as u64);
        SizeHint::with_exact(f.blob.size.saturating_sub(f.next) + held)
    }
}

type SendFuture = Box<
    dyn Future<
            Output = wasmtime_wasi_http::Result<(
                http::Response<WasiBody>,
                Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send>,
            )>,
        > + Send,
>;

#[derive(Default)]
struct Hooks {
    /// The request `handle` just passed to `send_request`.
    sent: Option<http::Request<WasiBody>>,
}

impl WasiHttpHooks for Hooks {
    fn set_host_header(&mut self) -> bool {
        false
    }

    /// Never sends: the request goes back to `TurnHost::handle`, and the
    /// future, which nothing awaits once drive answers, never resolves.
    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        _options: Option<wasmtime_wasi_http::RequestOptions>,
        _fut: Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send>,
    ) -> SendFuture {
        self.sent = Some(request);
        Box::new(std::future::pending())
    }
}

impl WasiHttpView for TurnHost {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            hooks: &mut self.http.hooks,
            table: &mut self.table,
            ctx: &mut self.http.ctx,
        }
    }
}

/// A header value: text, or exactly one `{{secret:NAME}}`, which becomes the
/// secret-header template `http-client.fetch` uses (`{}` stands for the
/// value the host inserts).
fn header_value(v: &str) -> Result<FetchHeader, String> {
    const OPEN: &str = "{{secret:";
    let Some(start) = v.find(OPEN) else {
        return Ok(FetchHeader::Text(v.to_owned()));
    };
    let rest = &v[start + OPEN.len()..];
    let end = rest
        .find("}}")
        .ok_or_else(|| format!("{v:?} has an unterminated {{{{secret:"))?;
    let name = &rest[..end];
    let tail = &rest[end + 2..];
    let valid = !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b));
    if !valid {
        return Err(format!("{name:?} is not a secret name"));
    }
    if tail.contains(OPEN) || v.contains("{}") {
        return Err("a header value holds one {{secret:NAME}} and no literal {}".into());
    }
    Ok(FetchHeader::Secret {
        name: name.to_owned(),
        template: format!("{}{{}}{tail}", &v[..start]),
    })
}

/// The headers of a request, as the effect takes them.
fn request_headers(parts: &http::request::Parts) -> Result<Vec<(String, FetchHeader)>, String> {
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        let value = value
            .to_str()
            .map_err(|_| format!("header {name} is not text"))?;
        headers.push((name.as_str().to_owned(), header_value(value)?));
    }
    Ok(headers)
}

type Answer =
    wasmtime_wasi_http::Result<(http::Response<HyperIncomingBody>, AbortOnDropJoinHandle<()>)>;

/// Why a request is not sent: the guest's error code, and the warning's
/// reason.
type Refused = (HttpErr, String);

fn erased() -> Refused {
    (
        HttpErr::HttpRequestDenied,
        "the turn's subject is erased, so its body cannot be stored".into(),
    )
}

fn too_large_for_a_blob() -> Refused {
    (
        HttpErr::HttpRequestBodySize(None),
        "the request body is too large for a blob".into(),
    )
}

fn never_ready(what: &str) -> wasmtime::Error {
    format_err!(
        "wasi:http: {what} waits for something that can never be ready \
         (a response to a request whose body was not finished?)"
    )
}

impl TurnHost {
    /// Spools `wasi:http` request bodies above `threshold` bytes into blobs
    /// (M25 §7.6): for a turn with a blob host whose component reads blobs.
    /// Otherwise a body stays in memory, up to `message_bytes`.
    pub(crate) fn spool_request_bodies_above(&mut self, threshold: u64) {
        self.http.spool_above = Some(threshold);
    }

    /// `wasi:http/outgoing-handler.handle`: builds the request and queues it.
    fn handle(
        &mut self,
        request: Resource<HostOutgoingRequest>,
        options: Option<Resource<ht::RequestOptions>>,
    ) -> HttpResult<Resource<HostFutureIncomingResponse>> {
        self.deny_in_describe("wasi:http")
            .map_err(HttpError::trap)?;
        self.gate("wasi:http").map_err(HttpError::trap)?;
        if self.http.pending.len() >= MAX_PENDING {
            self.warn(format!(
                "wasi:http: more than {MAX_PENDING} requests started without waiting for one"
            ));
            return Err(ht::ErrorCode::ConnectionLimitReached.into());
        }
        let future = outgoing_handler::Host::handle(&mut self.http(), request, options)?;
        let request = self
            .http
            .hooks
            .sent
            .take()
            .ok_or_else(|| HttpError::trap(format_err!("wasi:http: handle sent no request")))?;
        // A queued index reused by this handle means the guest dropped that
        // future before it waited: its request is never sent.
        let mut dropped = Vec::new();
        self.http.pending.retain(|p| {
            let keep = p.rep != future.rep();
            if !keep {
                dropped.extend(p.writer);
            }
            keep
        });
        for writer in dropped {
            self.discard_spool(writer);
        }
        let (parts, body) = request.into_parts();
        self.http.pending.push(Pending {
            rep: future.rep(),
            parts,
            body,
            bytes: Vec::new(),
            writer: None,
            done: false,
        });
        Ok(future)
    }

    fn warn(&self, message: String) {
        // A host warning is not worth failing the turn over: drop it when the
        // guest's own output has spent the budget, instead of trapping here.
        let _ = self.logs.push(LogEvent {
            level: "warn",
            message,
            fields: Vec::new(),
        });
    }

    /// At the end of a turn: a request it started and never waited for was
    /// never sent (a `fetch` nobody awaits), which the code may not expect.
    pub(crate) fn warn_unsent(&self) {
        let n = self.http.pending.len();
        if n > 0 {
            self.warn(format!(
                "wasi:http: {n} request(s) the turn never waited for were not sent \
                 (await every fetch)"
            ));
        }
    }

    /// Runs every queued request whose body is complete, in `handle` order,
    /// and makes its response ready; then reads the next frame of every
    /// blob-backed response body that wants one.
    async fn drive(&mut self) -> wasmtime::Result<()> {
        let mut i = 0;
        while i < self.http.pending.len() {
            let refused = self.take_body(i).await?;
            if !self.http.pending[i].done && refused.is_none() {
                i += 1;
                continue;
            }
            let p = self.http.pending.remove(i);
            let future = Resource::<HostFutureIncomingResponse>::new_borrow(p.rep);
            if !matches!(
                self.table.get(&future),
                Ok(HostFutureIncomingResponse::Pending(_))
            ) {
                if let Some(writer) = p.writer {
                    self.discard_spool(writer);
                }
                continue;
            }
            let what = format!("{} {}", p.parts.method, p.parts.uri);
            let request = match refused {
                Some(refused) => {
                    if let Some(writer) = p.writer {
                        self.discard_spool(writer);
                    }
                    Err(refused)
                }
                None => self.complete_request(p, &what).await?,
            };
            let result = match request {
                Err((code, why)) => {
                    self.warn(format!("wasi:http: {what} not sent: {why}"));
                    Err(code)
                }
                Ok(req) => {
                    let gate = self.gate("wasi:http")?;
                    let ordinal = self.ordinal();
                    let outcome = gate
                        .fetch(ordinal, req)
                        .await
                        .map_err(|e| self.gate_failure(e))?;
                    self.answer(outcome)?
                }
            };
            *self.table.get_mut(&future)? = HostFutureIncomingResponse::Ready(result);
        }
        self.fill_bodies().await?;
        Ok(())
    }

    /// Takes what the guest wrote of request `i`'s body so far, waiting for
    /// nothing. `Some` when the request cannot be sent.
    async fn take_body(&mut self, i: usize) -> wasmtime::Result<Option<Refused>> {
        loop {
            let p = &mut self.http.pending[i];
            if p.done {
                return Ok(None);
            }
            let data = match poll_noop(pin!(p.body.frame())) {
                None => return Ok(None),
                Some(None) => {
                    p.done = true;
                    return Ok(None);
                }
                Some(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => data,
                    Err(_) => {
                        return Ok(Some((
                            HttpErr::HttpRequestDenied,
                            "request trailers are not supported".into(),
                        )));
                    }
                },
                Some(Some(Err(e))) => return Ok(Some((e, "the request body failed".into()))),
            };
            if let Some(refused) = self.take_data(i, data).await? {
                return Ok(Some(refused));
            }
        }
    }

    /// Adds `data` to request `i`'s body: in memory up to the spool
    /// threshold (without spooling, up to `message_bytes`), into a blob
    /// once the body passes it. (`wasi:http` reaches only `http` and
    /// `https` URLs, never a foreign actor's, whose bodies stay inline.)
    async fn take_data(&mut self, i: usize, data: Bytes) -> wasmtime::Result<Option<Refused>> {
        let writer = match self.http.pending[i].writer {
            Some(writer) => writer,
            None => {
                let spool = self.http.spool_above;
                let p = &mut self.http.pending[i];
                let held = (p.bytes.len() + data.len()) as u64;
                if !matches!(spool, Some(threshold) if held > threshold) {
                    p.bytes.extend_from_slice(&data);
                    let limit = self.limits.message_bytes;
                    if p.bytes.len() > limit {
                        return Ok(Some((
                            HttpErr::HttpRequestBodySize(Some(limit as u64)),
                            format!("the request body is over {limit} bytes"),
                        )));
                    }
                    return Ok(None);
                }
                let writer = match self.open_spool().await? {
                    Ok(writer) => writer,
                    Err(refused) => return Ok(Some(refused)),
                };
                let p = &mut self.http.pending[i];
                p.writer = Some(writer);
                let held = Bytes::from(std::mem::take(&mut p.bytes));
                if let Some(refused) = self.spool(writer, held).await? {
                    return Ok(Some(refused));
                }
                writer
            }
        };
        self.spool(writer, data).await
    }

    fn blob_reader(&self) -> wasmtime::Result<Arc<dyn BlobHost>> {
        self.blobs
            .clone()
            .ok_or_else(|| format_err!("wasi:http: a blob body in a turn without a blob host"))
    }

    /// A blob writer of the turn's subject for a request body that passed
    /// the threshold: one of the turn's open writers.
    async fn open_spool(&mut self) -> wasmtime::Result<Result<u64, Refused>> {
        let host = self.blob_reader()?;
        if self.blob_state.open.len() >= MAX_OPEN_WRITERS {
            return Ok(Err((
                HttpErr::InternalError(Some("too many open blob writers".into())),
                format!(
                    "its body passed the blob threshold, and the turn already holds \
                     {MAX_OPEN_WRITERS} open blob writers"
                ),
            )));
        }
        match host.create(self.subject.clone()).await {
            Ok(writer) => {
                self.blob_state.open.push(writer);
                Ok(Ok(writer))
            }
            Err(BlobHostError::Erased) => Ok(Err(erased())),
            Err(error) => Err(self.blob_failure(error)),
        }
    }

    /// Appends `chunk` to a request body's blob: bytes the turn created,
    /// counted against its quota and its blob budget as a guest's `write`.
    async fn spool(&mut self, writer: u64, chunk: Bytes) -> wasmtime::Result<Option<Refused>> {
        let host = self.blob_reader()?;
        for piece in chunk.chunks(MAX_BLOB_CALL_BYTES) {
            let quota = self.limits.blob_bytes;
            let created = self.blob_state.created.saturating_add(piece.len() as u64);
            if created > quota {
                return Ok(Some((
                    HttpErr::HttpRequestBodySize(Some(quota)),
                    format!(
                        "the request body passes the {quota} bytes a turn may write into blobs"
                    ),
                )));
            }
            self.charge_blob_bytes(piece.len() as u64)?;
            self.blob_state.created = created;
            match host.write(writer, piece.to_vec()).await {
                Ok(()) => {}
                Err(BlobHostError::Erased) => return Ok(Some(erased())),
                Err(BlobHostError::TooLarge) => return Ok(Some(too_large_for_a_blob())),
                Err(error) => return Err(self.blob_failure(error)),
            }
        }
        Ok(None)
    }

    /// Drops a request body's blob writer.
    fn discard_spool(&mut self, writer: u64) {
        self.blob_state.open.retain(|open| *open != writer);
        if let Some(host) = &self.blobs {
            host.discard(writer);
        }
    }

    /// The effect's request for a complete body: its headers, and its bytes
    /// or the blob they were spooled into, finished.
    async fn complete_request(
        &mut self,
        p: Pending,
        what: &str,
    ) -> wasmtime::Result<Result<FetchRequest, Refused>> {
        let headers = match request_headers(&p.parts) {
            Ok(headers) => headers,
            Err(why) => {
                if let Some(writer) = p.writer {
                    self.discard_spool(writer);
                }
                return Ok(Err((HttpErr::HttpRequestDenied, why)));
            }
        };
        let body = match p.writer {
            None => FetchBody::Inline(p.bytes),
            Some(writer) => {
                let host = self.blob_reader()?;
                self.blob_state.open.retain(|open| *open != writer);
                match host.finish(writer).await {
                    Ok(blob) => {
                        let replaced = host.replaced(writer);
                        if replaced > 0 {
                            self.warn(format!(
                                "wasi:http: {what}: {replaced} secret value(s) in the request \
                                 body were replaced by their placeholders, since a body above \
                                 the blob threshold is stored as a blob; send secrets in \
                                 {{{{secret:NAME}}}} headers"
                            ));
                        }
                        FetchBody::Blob(blob)
                    }
                    Err(BlobHostError::Erased) => return Ok(Err(erased())),
                    Err(BlobHostError::TooLarge) => return Ok(Err(too_large_for_a_blob())),
                    Err(error) => return Err(self.blob_failure(error)),
                }
            }
        };
        Ok(Ok(FetchRequest {
            method: p.parts.method.to_string(),
            url: p.parts.uri.to_string(),
            headers,
            body,
            subject: self.subject.clone(),
        }))
    }

    /// The effect's result as `wasi:http` sees it (ADR 0070 §3). A blob
    /// response joins the turn's references, as in `http-client.fetch`, and
    /// becomes a body whose frames only the guest's waits read.
    fn answer(&mut self, outcome: FetchOutcome) -> wasmtime::Result<Answer> {
        let r = match outcome {
            FetchOutcome::Ok(r) => r,
            FetchOutcome::Denied(_) => return Ok(Err(HttpErr::HttpRequestDenied)),
            FetchOutcome::Timeout => return Ok(Err(HttpErr::HttpResponseTimeout)),
            FetchOutcome::TooLarge => return Ok(Err(HttpErr::HttpResponseBodySize(None))),
            FetchOutcome::Network(m) => return Ok(Err(HttpErr::InternalError(Some(m)))),
            FetchOutcome::OutcomeUnknown => {
                return Ok(Err(HttpErr::InternalError(Some("outcome-unknown".into()))));
            }
            FetchOutcome::HostRedactionFailure => {
                return Err(wasmtime::Error::new(super::HostRedactionFailure));
            }
        };
        let body = match r.body {
            FetchResponseBody::Inline(bytes) => Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed_unsync(),
            FetchResponseBody::Blob(blob) => {
                if self.blobs.is_none() {
                    return Err(self.host_failure("a blob response in a turn without blobs".into()));
                }
                self.blob_state.admit(blob.clone());
                let frames = Arc::new(Mutex::new(BlobFrames {
                    blob,
                    next: 0,
                    frame: None,
                    wanted: false,
                    failed: None,
                }));
                self.http.bodies.push(Arc::downgrade(&frames));
                BlobBody(frames).boxed_unsync()
            }
        };
        let mut b = http::Response::builder().status(r.status);
        for (name, value) in r.headers {
            b = b.header(name, value);
        }
        let response = b
            .body(body)
            .map_err(|e| HttpErr::InternalError(Some(e.to_string())));
        // The body is in memory, or read at the guest's waits: the worker
        // task has nothing to do.
        Ok(response.map(|response| (response, wasmtime_wasi::runtime::spawn(async {}))))
    }

    /// Reads the next frame of every blob-backed response body that wants
    /// one: the only place their bytes are read. Whether it read any.
    async fn fill_bodies(&mut self) -> wasmtime::Result<bool> {
        let mut filled = false;
        let mut i = 0;
        while i < self.http.bodies.len() {
            let Some(body) = self.http.bodies[i].upgrade() else {
                self.http.bodies.remove(i);
                continue;
            };
            i += 1;
            let (blob, offset, len) = {
                let mut f = lock(&body);
                if !f.wanted || f.frame.is_some() || f.failed.is_some() || f.next >= f.blob.size {
                    continue;
                }
                f.wanted = false;
                let len = (f.blob.size - f.next).min(BLOB_FRAME_BYTES);
                (f.blob.clone(), f.next, len as u32)
            };
            let host = self.blob_reader()?;
            self.charge_blob_bytes(read_charge(blob.size, offset, len))?;
            let read = host.read(&blob, offset, len).await;
            let failure = {
                let mut f = lock(&body);
                match read {
                    Ok(bytes) if !bytes.is_empty() => {
                        f.next = offset + bytes.len() as u64;
                        f.frame = Some(Bytes::from(bytes));
                        None
                    }
                    Ok(_) => Some(BlobHostError::Host(format!(
                        "the blob {} ended at {offset} of its {} bytes",
                        blob.hash, blob.size
                    ))),
                    Err(BlobHostError::Erased) => {
                        f.next = f.blob.size;
                        f.failed = Some(HttpErr::InternalError(Some(
                            "the response body's subject is erased".into(),
                        )));
                        None
                    }
                    Err(error) => Some(error),
                }
            };
            if let Some(error) = failure {
                return Err(self.blob_failure(error));
            }
            filled = true;
        }
        Ok(filled)
    }

    /// Drives, then runs `op`, which must finish at once (module docs).
    async fn now<T>(
        &mut self,
        what: &str,
        op: impl FnOnce(&mut ResourceTable) -> BoxFuture<'_, T>,
    ) -> wasmtime::Result<T> {
        self.drive().await?;
        match poll_noop(pin!(op(&mut self.table))) {
            Some(v) => Ok(v),
            None => Err(never_ready(what)),
        }
    }

    /// [`TurnHost::now`] for a wait that may read a blob-backed response
    /// body, whose `op` changes nothing until it is ready: when it found
    /// such a body empty, the body gets its next frame and `op` runs again.
    async fn wait<T>(
        &mut self,
        what: &str,
        mut op: impl FnMut(&mut ResourceTable) -> BoxFuture<'_, T>,
    ) -> wasmtime::Result<T> {
        self.drive().await?;
        loop {
            if let Some(v) = poll_noop(pin!(op(&mut self.table))) {
                return Ok(v);
            }
            if !self.fill_bodies().await? {
                return Err(never_ready(what));
            }
        }
    }
}

/// Links `wasi:http/types`, `outgoing-handler` and Kronik's `wasi:io/poll`
/// and `wasi:io/streams`.
pub(crate) fn add_to_linker(l: &mut Linker<TurnHost>) -> wasmtime::Result<()> {
    use wasmtime::component::HasSelf;
    poll::add_to_linker::<TurnHost, HasSelf<TurnHost>>(l, |s| s)?;
    streams::add_to_linker::<TurnHost, HasSelf<TurnHost>>(l, |s| s)?;
    let options = wasmtime_wasi_http::p2::bindings::LinkOptions::default();
    ht::add_to_linker::<TurnHost, WasiHttp>(l, &options.into(), TurnHost::http)?;
    // By hand: the generated `outgoing_handler::add_to_linker` needs all of
    // `wasi:http/types` on the store type (`types::Host`'s supertraits).
    l.instance(OUTGOING_HANDLER)?.func_wrap(
        "handle",
        |mut store: wasmtime::StoreContextMut<'_, TurnHost>,
         (request, options): (
            Resource<HostOutgoingRequest>,
            Option<Resource<ht::RequestOptions>>,
        )| {
            Ok((match store.data_mut().handle(request, options) {
                Ok(future) => Ok(future),
                Err(e) => Err(e.downcast()?),
            },))
        },
    )?;
    Ok(())
}

impl poll::Host for TurnHost {
    async fn poll(&mut self, list: Vec<Resource<DynPollable>>) -> wasmtime::Result<Vec<u32>> {
        let reps: Vec<u32> = list.iter().map(Resource::rep).collect();
        self.wait("poll", |t| {
            let list = reps.iter().map(|rep| Resource::new_borrow(*rep)).collect();
            Box::pin(poll::Host::poll(t, list))
        })
        .await?
    }
}

impl poll::HostPollable for TurnHost {
    async fn block(&mut self, p: Resource<DynPollable>) -> wasmtime::Result<()> {
        let rep = p.rep();
        self.wait("block", |t| {
            Box::pin(poll::HostPollable::block(t, Resource::new_borrow(rep)))
        })
        .await?
    }
    async fn ready(&mut self, p: Resource<DynPollable>) -> wasmtime::Result<bool> {
        poll::HostPollable::ready(&mut self.table, p).await
    }
    fn drop(&mut self, p: Resource<DynPollable>) -> wasmtime::Result<()> {
        poll::HostPollable::drop(&mut self.table, p)
    }
}

impl streams::Host for TurnHost {
    fn convert_stream_error(&mut self, err: StreamError) -> wasmtime::Result<streams::StreamError> {
        streams::Host::convert_stream_error(&mut self.table, err)
    }
}

impl streams::HostInputStream for TurnHost {
    async fn drop(&mut self, s: Resource<DynInputStream>) -> wasmtime::Result<()> {
        streams::HostInputStream::drop(&mut self.table, s).await
    }
    fn read(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<Vec<u8>> {
        streams::HostInputStream::read(&mut self.table, s, len)
    }
    async fn blocking_read(
        &mut self,
        s: Resource<DynInputStream>,
        len: u64,
    ) -> StreamResult<Vec<u8>> {
        let rep = s.rep();
        self.wait("blocking-read", |t| {
            Box::pin(streams::HostInputStream::blocking_read(
                t,
                Resource::new_borrow(rep),
                len,
            ))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        streams::HostInputStream::skip(&mut self.table, s, len)
    }
    async fn blocking_skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        let rep = s.rep();
        self.wait("blocking-skip", |t| {
            Box::pin(streams::HostInputStream::blocking_skip(
                t,
                Resource::new_borrow(rep),
                len,
            ))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn subscribe(
        &mut self,
        s: Resource<DynInputStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        streams::HostInputStream::subscribe(&mut self.table, s)
    }
}

impl streams::HostOutputStream for TurnHost {
    async fn drop(&mut self, s: Resource<DynOutputStream>) -> wasmtime::Result<()> {
        streams::HostOutputStream::drop(&mut self.table, s).await
    }
    fn check_write(&mut self, s: Resource<DynOutputStream>) -> StreamResult<u64> {
        streams::HostOutputStream::check_write(&mut self.table, s)
    }
    fn write(&mut self, s: Resource<DynOutputStream>, bytes: Vec<u8>) -> StreamResult<()> {
        streams::HostOutputStream::write(&mut self.table, s, bytes)
    }
    async fn blocking_write_and_flush(
        &mut self,
        s: Resource<DynOutputStream>,
        bytes: Vec<u8>,
    ) -> StreamResult<()> {
        self.now("blocking-write-and-flush", |t| {
            Box::pin(streams::HostOutputStream::blocking_write_and_flush(
                t, s, bytes,
            ))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    async fn blocking_write_zeroes_and_flush(
        &mut self,
        s: Resource<DynOutputStream>,
        len: u64,
    ) -> StreamResult<()> {
        self.now("blocking-write-zeroes-and-flush", |t| {
            Box::pin(streams::HostOutputStream::blocking_write_zeroes_and_flush(
                t, s, len,
            ))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn write_zeroes(&mut self, s: Resource<DynOutputStream>, len: u64) -> StreamResult<()> {
        streams::HostOutputStream::write_zeroes(&mut self.table, s, len)
    }
    fn flush(&mut self, s: Resource<DynOutputStream>) -> StreamResult<()> {
        streams::HostOutputStream::flush(&mut self.table, s)
    }
    async fn blocking_flush(&mut self, s: Resource<DynOutputStream>) -> StreamResult<()> {
        self.now("blocking-flush", |t| {
            Box::pin(streams::HostOutputStream::blocking_flush(t, s))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn splice(
        &mut self,
        d: Resource<DynOutputStream>,
        s: Resource<DynInputStream>,
        len: u64,
    ) -> StreamResult<u64> {
        streams::HostOutputStream::splice(&mut self.table, d, s, len)
    }
    async fn blocking_splice(
        &mut self,
        d: Resource<DynOutputStream>,
        s: Resource<DynInputStream>,
        len: u64,
    ) -> StreamResult<u64> {
        // The source may be a blob-backed body: the wait reads it nothing
        // before the destination and the source are both ready.
        let (d, s) = (d.rep(), s.rep());
        self.wait("blocking-splice", |t| {
            Box::pin(streams::HostOutputStream::blocking_splice(
                t,
                Resource::new_borrow(d),
                Resource::new_borrow(s),
                len,
            ))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn subscribe(
        &mut self,
        s: Resource<DynOutputStream>,
    ) -> wasmtime::Result<Resource<DynPollable>> {
        streams::HostOutputStream::subscribe(&mut self.table, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_placeholder_becomes_the_secret_header_template() {
        assert_eq!(
            header_value("Bearer {{secret:api-key}}"),
            Ok(FetchHeader::Secret {
                name: "api-key".into(),
                template: "Bearer {}".into()
            })
        );
        assert_eq!(
            header_value("{{secret:k}}; v=1"),
            Ok(FetchHeader::Secret {
                name: "k".into(),
                template: "{}; v=1".into()
            })
        );
        assert_eq!(header_value("plain"), Ok(FetchHeader::Text("plain".into())));
        for bad in [
            "{{secret:a}} {{secret:b}}",
            "{} {{secret:a}}",
            "{{secret:Upper}}",
            "{{secret:}}",
            "{{secret:_a}}",
            "{{secret:open",
        ] {
            assert!(header_value(bad).is_err(), "{bad}");
        }
    }
}
