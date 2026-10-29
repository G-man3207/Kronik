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
//! [`EffectGate::fetch`]: super::EffectGate::fetch

use std::pin::pin;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use kronik_core::env::BoxFuture;
use wasmtime::component::{Linker, Resource, ResourceTable};
use wasmtime::{bail, format_err};
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

use super::{FetchHeader, FetchOutcome, FetchRequest, LogEvent, TurnHost};

/// Requests a turn may have started and not yet waited for: each holds up to
/// a request body in host memory.
const MAX_PENDING: usize = 32;

/// The `wasi:http` version `wasmtime-wasi-http` 50 implements; the linker
/// accepts any 0.2.x import for it.
const OUTGOING_HANDLER: &str = "wasi:http/outgoing-handler@0.2.12";

/// The turn's `wasi:http` state.
pub(crate) struct State {
    ctx: WasiHttpCtx,
    hooks: Hooks,
    pending: Vec<Pending>,
}

impl State {
    pub(crate) fn new() -> State {
        State {
            ctx: WasiHttpCtx::new(),
            hooks: Hooks::default(),
            pending: Vec::new(),
        }
    }
}

/// A request `handle` queued and drive has not run yet.
struct Pending {
    /// The table index of its `future-incoming-response`.
    rep: u32,
    parts: http::request::Parts,
    body: WasiBody,
    bytes: Vec<u8>,
    done: bool,
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

fn fetch_request(
    parts: &http::request::Parts,
    body: Vec<u8>,
    subject: Option<String>,
) -> Result<FetchRequest, String> {
    let mut headers = Vec::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        let value = value
            .to_str()
            .map_err(|_| format!("header {name} is not text"))?;
        headers.push((name.as_str().to_owned(), header_value(value)?));
    }
    Ok(FetchRequest {
        method: parts.method.to_string(),
        url: parts.uri.to_string(),
        headers,
        body,
        subject,
    })
}

type Answer =
    wasmtime_wasi_http::Result<(http::Response<HyperIncomingBody>, AbortOnDropJoinHandle<()>)>;

/// The effect's result as `wasi:http` sees it (ADR 0070 §3).
fn answer(outcome: FetchOutcome) -> Answer {
    match outcome {
        FetchOutcome::Ok(r) => {
            let mut b = http::Response::builder().status(r.status);
            for (name, value) in r.headers {
                b = b.header(name, value);
            }
            let body = Full::new(Bytes::from(r.body))
                .map_err(|never| match never {})
                .boxed_unsync();
            let response = b
                .body(body)
                .map_err(|e| HttpErr::InternalError(Some(e.to_string())))?;
            // The body is in memory: the worker task has nothing to do.
            Ok((response, wasmtime_wasi::runtime::spawn(async {})))
        }
        FetchOutcome::Denied(_) => Err(HttpErr::HttpRequestDenied),
        FetchOutcome::Timeout => Err(HttpErr::HttpResponseTimeout),
        FetchOutcome::TooLarge => Err(HttpErr::HttpResponseBodySize(None)),
        FetchOutcome::Network(m) => Err(HttpErr::InternalError(Some(m))),
        FetchOutcome::OutcomeUnknown => Err(HttpErr::InternalError(Some("outcome-unknown".into()))),
    }
}

impl TurnHost {
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
        self.http.pending.retain(|p| p.rep != future.rep());
        let (parts, body) = request.into_parts();
        self.http.pending.push(Pending {
            rep: future.rep(),
            parts,
            body,
            bytes: Vec::new(),
            done: false,
        });
        Ok(future)
    }

    fn warn(&self, message: String) {
        self.logs.push(LogEvent {
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
    /// and makes its response ready.
    async fn drive(&mut self) -> wasmtime::Result<()> {
        let limit = self.limits.message_bytes;
        let mut i = 0;
        while i < self.http.pending.len() {
            let p = &mut self.http.pending[i];
            let mut refused: Option<(HttpErr, String)> = None;
            while !p.done && refused.is_none() {
                match poll_noop(pin!(p.body.frame())) {
                    None => break,
                    Some(None) => p.done = true,
                    Some(Some(Ok(frame))) => match frame.into_data() {
                        Ok(data) => {
                            p.bytes.extend_from_slice(&data);
                            if p.bytes.len() > limit {
                                refused = Some((
                                    HttpErr::HttpRequestBodySize(Some(limit as u64)),
                                    format!("the request body is over {limit} bytes"),
                                ));
                            }
                        }
                        Err(_) => {
                            refused = Some((
                                HttpErr::HttpRequestDenied,
                                "request trailers are not supported".into(),
                            ));
                        }
                    },
                    Some(Some(Err(e))) => refused = Some((e, "the request body failed".into())),
                }
            }
            if !p.done && refused.is_none() {
                i += 1;
                continue;
            }
            let p = self.http.pending.remove(i);
            let future = Resource::<HostFutureIncomingResponse>::new_borrow(p.rep);
            if !matches!(
                self.table.get(&future),
                Ok(HostFutureIncomingResponse::Pending(_))
            ) {
                continue;
            }
            let request = match refused {
                Some(r) => Err(r),
                None => fetch_request(&p.parts, p.bytes, self.subject.clone())
                    .map_err(|why| (HttpErr::HttpRequestDenied, why)),
            };
            let result = match request {
                Err((code, why)) => {
                    self.warn(format!(
                        "wasi:http: {} {} not sent: {why}",
                        p.parts.method, p.parts.uri
                    ));
                    Err(code)
                }
                Ok(req) => {
                    let gate = self.gate("wasi:http")?;
                    let ordinal = self.ordinal();
                    let outcome = gate
                        .fetch(ordinal, req)
                        .await
                        .map_err(|e| self.gate_failure(e))?;
                    answer(outcome)
                }
            };
            *self.table.get_mut(&future)? = HostFutureIncomingResponse::Ready(result);
        }
        Ok(())
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
            None => bail!(
                "wasi:http: {what} waits for something that can never be ready \
                 (a response to a request whose body was not finished?)"
            ),
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
        self.now("poll", |t| Box::pin(poll::Host::poll(t, list)))
            .await?
    }
}

impl poll::HostPollable for TurnHost {
    async fn block(&mut self, p: Resource<DynPollable>) -> wasmtime::Result<()> {
        self.now("block", |t| Box::pin(poll::HostPollable::block(t, p)))
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
        self.now("blocking-read", |t| {
            Box::pin(streams::HostInputStream::blocking_read(t, s, len))
        })
        .await
        .map_err(StreamError::Trap)?
    }
    fn skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        streams::HostInputStream::skip(&mut self.table, s, len)
    }
    async fn blocking_skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        self.now("blocking-skip", |t| {
            Box::pin(streams::HostInputStream::blocking_skip(t, s, len))
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
        self.now("blocking-splice", |t| {
            Box::pin(streams::HostOutputStream::blocking_splice(t, d, s, len))
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
