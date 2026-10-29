//! Spike M22 (ADR 0070): standard `fetch` from a ComponentizeJS guest through
//! `wasi:http/outgoing-handler` as Kronik `http.fetch` effects.
//!
//! - `wasmtime-wasi-http` 50 (`p2` only, no `default-send-request`) builds the
//!   requests; its `send_request` hook only queues them (it never touches the
//!   network and its future never resolves).
//! - `handle` is wrapped: it remembers the `future-incoming-response` next to
//!   the queued request.
//! - `wasi:io/poll.poll`, `pollable.block` and the blocking stream calls are
//!   wrapped: before the real call they *drive*: for each queued request in
//!   `handle` order, take the body frames already written (no waiting); when
//!   the body is complete, take the next operation ordinal, run the effect
//!   through `EffectGate::fetch` and put
//!   the response into the future's table entry (`Ready`). Then the real call
//!   must complete at once; if it would wait, nothing can ever wake it, and
//!   the turn traps.
//! - `--naive` (the rejected alternative in ADR 0070): the effect runs inside
//!   the hook's future on a tokio task, so readiness depends on timing.
//!
//! Every effect gets a random real-time latency (0 to 4 ms). A mode is
//! deterministic when all its runs give the same transcript: the guest's
//! output, the effects the gate saw (ordinal, request) and every ready list
//! `poll` returned, plus the fuel used.

use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt as _;
use http_body_util::{BodyExt as _, Full};
use kronik_core::env::BoxFuture;
use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{
    CallOutcome, CryptoAlgorithm, CryptoOutcome, EffectGate, FetchHeader, FetchOutcome,
    FetchRequest, FetchResponse, GateError, PoolSize,
};
use wasmtime::component::{Component, HasData, HasSelf, Linker, Resource, ResourceTable};
use wasmtime::{Store, bail, format_err};
use wasmtime_wasi::p2::DynPollable;
use wasmtime_wasi::p2::bindings::clocks::{monotonic_clock, wall_clock};
use wasmtime_wasi::p2::bindings::random::random;
use wasmtime_wasi::runtime::{AbortOnDropJoinHandle, poll_noop};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::http::{outgoing_handler, types as ht};
use wasmtime_wasi_http::p2::body::HyperIncomingBody;
use wasmtime_wasi_http::p2::types::{HostFutureIncomingResponse, HostOutgoingRequest};
use wasmtime_wasi_http::p2::{HttpError, HttpResult};
use wasmtime_wasi_http::{
    Error as HttpErr, WasiBody, WasiHttp, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks,
    WasiHttpView,
};
use wasmtime_wasi_io::bindings::wasi::io::{error, poll, streams};
use wasmtime_wasi_io::streams::{DynInputStream, DynOutputStream, StreamError, StreamResult};

const SECRET_VALUE: &str = "s3cr3t-value-api";
const BODY_LIMIT: usize = 10 << 20;

// ---------------------------------------------------------------- the gate

/// Stands in for kronik-sched's gate: logs every effect, renders a secret
/// header's template (`{}` → value) for the "wire", lets a fake server echo
/// what it got, and scrubs secret values from the answer, as
/// `effects.rs` does for `http-client.fetch`.
struct Gate {
    log: Mutex<Vec<String>>,
    jitter: AtomicU64,
}

impl Gate {
    fn new(seed: u64) -> Gate {
        Gate {
            log: Mutex::new(Vec::new()),
            jitter: AtomicU64::new(seed | 1),
        }
    }

    fn latency(&self) -> Duration {
        let mut x = self.jitter.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter.store(x, Ordering::Relaxed);
        Duration::from_micros(x % 4000)
    }
}

impl EffectGate for Gate {
    fn fetch(
        &self,
        ordinal: u32,
        req: FetchRequest,
    ) -> BoxFuture<'static, Result<FetchOutcome, GateError>> {
        let shown: Vec<String> = req
            .headers
            .iter()
            .map(|(n, v)| match v {
                FetchHeader::Text(t) => format!("{n}: {t}"),
                FetchHeader::Secret { name, template } => {
                    format!("{n}: secret {name} template {template:?}")
                }
            })
            .collect();
        self.log.lock().unwrap().push(format!(
            "#{ordinal} {} {} {:?} body {:?}",
            req.method,
            req.url,
            shown,
            String::from_utf8_lossy(&req.body)
        ));
        let latency = self.latency();
        Box::pin(async move {
            tokio::time::sleep(latency).await;
            if req.url.contains("denied.example") {
                return Ok(FetchOutcome::Denied(
                    "CAPABILITY_NOT_GRANTED: http:denied.example".into(),
                ));
            }
            // The wire: secret templates rendered with the value.
            let wire: Vec<String> = req
                .headers
                .iter()
                .map(|(n, v)| match v {
                    FetchHeader::Text(t) => format!("{n}={t}"),
                    FetchHeader::Secret { template, .. } => {
                        format!("{n}={}", template.replace("{}", SECRET_VALUE))
                    }
                })
                .collect();
            // The fake server echoes the request; the gate scrubs secrets.
            let echo = format!(
                "{} {} {} bytes; {}",
                req.method,
                req.url,
                req.body.len(),
                wire.join(", ")
            )
            .replace(SECRET_VALUE, "[secret:api]");
            Ok(FetchOutcome::Ok(FetchResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: echo.into_bytes(),
            }))
        })
    }

    fn call(
        &self,
        _: u32,
        _: ActorRef,
        _: pb::Message,
        _: Option<pb::Message>,
    ) -> BoxFuture<'static, Result<CallOutcome, GateError>> {
        Box::pin(async { Err(GateError::Host("not in the spike".into())) })
    }

    fn crypto(
        &self,
        _: u32,
        _: CryptoAlgorithm,
        _: String,
        _: Vec<u8>,
    ) -> BoxFuture<'static, Result<CryptoOutcome, GateError>> {
        Box::pin(async { Err(GateError::Host("not in the spike".into())) })
    }

    fn reveal(
        &self,
        _: u32,
        _: String,
    ) -> BoxFuture<'static, Result<Result<String, String>, GateError>> {
        Box::pin(async { Err(GateError::Host("not in the spike".into())) })
    }
}

// --------------------------------------------------- request → FetchRequest

/// A header value: text, or exactly one `{{secret:NAME}}` that becomes the
/// existing secret-header template (`{}` stands for the value).
fn header_value(v: &str) -> Result<FetchHeader, String> {
    const OPEN: &str = "{{secret:";
    let Some(start) = v.find(OPEN) else {
        return Ok(FetchHeader::Text(v.to_owned()));
    };
    let rest = &v[start + OPEN.len()..];
    let end = rest.find("}}").ok_or("an unterminated {{secret:")?;
    let name = &rest[..end];
    let tail = &rest[end + 2..];
    let ok_name = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
        && name.as_bytes()[0].is_ascii_alphanumeric();
    if !ok_name {
        return Err(format!("{name:?} is not a secret name"));
    }
    if tail.contains(OPEN) || v.contains("{}") {
        return Err("one {{secret:NAME}} per header value, and no literal {}".into());
    }
    Ok(FetchHeader::Secret {
        name: name.to_owned(),
        template: format!("{}{{}}{tail}", &v[..start]),
    })
}

fn fetch_request(parts: &http::request::Parts, body: Vec<u8>) -> Result<FetchRequest, String> {
    let mut headers = Vec::new();
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
        subject: None,
    })
}

type Answer = wasmtime_wasi_http::Result<(http::Response<HyperIncomingBody>, AbortOnDropJoinHandle<()>)>;

fn answer(outcome: FetchOutcome) -> Answer {
    match outcome {
        FetchOutcome::Ok(r) => {
            let mut b = http::Response::builder().status(r.status);
            for (k, v) in r.headers {
                b = b.header(k, v);
            }
            let body = Full::new(Bytes::from(r.body))
                .map_err(|never| match never {})
                .boxed_unsync();
            let resp = b
                .body(body)
                .map_err(|e| HttpErr::InternalError(Some(e.to_string())))?;
            Ok((resp, wasmtime_wasi::runtime::spawn(async {})))
        }
        FetchOutcome::Denied(_) => Err(HttpErr::HttpRequestDenied),
        FetchOutcome::Timeout => Err(HttpErr::HttpResponseTimeout),
        FetchOutcome::TooLarge => Err(HttpErr::HttpResponseBodySize(None)),
        FetchOutcome::Network(m) => Err(HttpErr::InternalError(Some(m))),
        FetchOutcome::OutcomeUnknown => Err(HttpErr::InternalError(Some("outcome-unknown".into()))),
    }
}

// ------------------------------------------------------------- the hooks

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
    /// `--naive`: the gate and the ordinal counter for in-hook effects.
    naive: Option<(Arc<Gate>, Arc<AtomicU32>)>,
}

impl WasiHttpHooks for Hooks {
    fn set_host_header(&mut self) -> bool {
        false
    }

    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        _options: Option<wasmtime_wasi_http::RequestOptions>,
        _fut: Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send>,
    ) -> SendFuture {
        let Some((gate, ordinals)) = self.naive.clone() else {
            self.sent = Some(request);
            return Box::new(std::future::pending());
        };
        let ordinal = ordinals.fetch_add(1, Ordering::SeqCst);
        Box::new(async move {
            let (parts, body) = request.into_parts();
            let body = body.collect().await?.to_bytes().to_vec();
            let req = fetch_request(&parts, body).map_err(|_| HttpErr::HttpRequestDenied)?;
            let outcome = gate
                .fetch(ordinal, req)
                .await
                .map_err(|e| HttpErr::InternalError(Some(format!("{e:?}"))))?;
            let (resp, _io) = answer(outcome)?;
            let io: Box<dyn Future<Output = wasmtime_wasi_http::Result<()>> + Send> =
                Box::new(async { Ok(()) });
            Ok((resp.map(|b| b.boxed_unsync()), io))
        })
    }
}

// -------------------------------------------------------------- the host

struct Pending {
    /// The `future-incoming-response` handle's table index.
    rep: u32,
    parts: http::request::Parts,
    body: WasiBody,
    bytes: Vec<u8>,
    done: bool,
}

struct Host {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: Hooks,
    gate: Arc<Gate>,
    naive: bool,
    pending: Vec<Pending>,
    next_ordinal: u32,
    rng: u64,
    trace: Vec<String>,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for Host {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            hooks: &mut self.hooks,
            table: &mut self.table,
            ctx: &mut self.http,
        }
    }
}

impl Host {
    /// Runs every queued request whose body is complete, in `handle` order,
    /// through the gate, and makes its response ready.
    async fn drive(&mut self) -> wasmtime::Result<()> {
        let mut i = 0;
        while i < self.pending.len() {
            let p = &mut self.pending[i];
            let mut failed: Option<HttpErr> = None;
            while !p.done && failed.is_none() {
                match poll_noop(pin!(p.body.frame())) {
                    None => break,
                    Some(None) => p.done = true,
                    Some(Some(Ok(frame))) => {
                        if let Ok(data) = frame.into_data() {
                            p.bytes.extend_from_slice(&data);
                            if p.bytes.len() > BODY_LIMIT {
                                failed = Some(HttpErr::HttpRequestBodySize(Some(BODY_LIMIT as u64)));
                            }
                        }
                    }
                    Some(Some(Err(e))) => failed = Some(e),
                }
            }
            if !p.done && failed.is_none() {
                i += 1;
                continue;
            }
            let p = self.pending.remove(i);
            let future = Resource::<HostFutureIncomingResponse>::new_borrow(p.rep);
            // Dropped by the guest before it waited: never sent.
            if !matches!(self.table.get(&future), Ok(HostFutureIncomingResponse::Pending(_))) {
                continue;
            }
            let result = match failed {
                Some(e) => Err(e),
                None => match fetch_request(&p.parts, p.bytes) {
                    Err(_) => Err(HttpErr::HttpRequestDenied),
                    Ok(req) => {
                        // The ordinal is taken when the effect runs, so the
                        // gate sees ordinals in the order effects happen
                        // (bodies complete in another order than `handle`).
                        let ordinal = self.next_ordinal;
                        self.next_ordinal += 1;
                        let outcome = self
                            .gate
                            .fetch(ordinal, req)
                            .await
                            .map_err(|e| format_err!("gate: {e:?}"))?;
                        answer(outcome)
                    }
                },
            };
            *self.table.get_mut(&future)? = HostFutureIncomingResponse::Ready(result);
        }
        Ok(())
    }

    /// Drives, then runs `op`, which must not wait: nothing outside the
    /// guest makes progress (ADR 0070 §2).
    async fn now<T>(&mut self, what: &str, op: impl FnOnce(&mut ResourceTable) -> BoxFuture<'_, T>) -> wasmtime::Result<T> {
        if self.naive {
            return Ok(op(&mut self.table).await);
        }
        self.drive().await?;
        match op(&mut self.table).now_or_never() {
            Some(v) => Ok(v),
            None => bail!("TURN_FAILED: wasi:http wait cannot make progress ({what})"),
        }
    }
}

impl Host {
    /// `wasi:http/outgoing-handler.handle`, linked by hand: the generated
    /// `add_to_linker` would need all of `wasi:http/types` on `Host`.
    fn handle(
        &mut self,
        request: Resource<HostOutgoingRequest>,
        options: Option<Resource<ht::RequestOptions>>,
    ) -> HttpResult<Resource<HostFutureIncomingResponse>> {
        let future = outgoing_handler::Host::handle(&mut self.http(), request, options)?;
        if self.naive {
            return Ok(future);
        }
        let request = self
            .hooks
            .sent
            .take()
            .ok_or_else(|| HttpError::trap(format_err!("send_request was not called")))?;
        // An index reused by this new handle means the old one was dropped.
        self.pending.retain(|p| p.rep != future.rep());
        let (parts, body) = request.into_parts();
        self.pending.push(Pending {
            rep: future.rep(),
            parts,
            body,
            bytes: Vec::new(),
            done: false,
        });
        Ok(future)
    }

}

impl poll::Host for Host {
    async fn poll(&mut self, list: Vec<Resource<DynPollable>>) -> wasmtime::Result<Vec<u32>> {
        let n = list.len();
        let ready = self
            .now("poll", |t| Box::pin(poll::Host::poll(t, list)))
            .await??;
        self.trace.push(format!("poll {n} -> {ready:?}"));
        Ok(ready)
    }
}

impl poll::HostPollable for Host {
    async fn block(&mut self, p: Resource<DynPollable>) -> wasmtime::Result<()> {
        self.trace.push("block".into());
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

impl streams::Host for Host {
    fn convert_stream_error(
        &mut self,
        err: StreamError,
    ) -> wasmtime::Result<streams::StreamError> {
        streams::Host::convert_stream_error(&mut self.table, err)
    }
}

impl streams::HostInputStream for Host {
    async fn drop(&mut self, s: Resource<DynInputStream>) -> wasmtime::Result<()> {
        streams::HostInputStream::drop(&mut self.table, s).await
    }
    fn read(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<Vec<u8>> {
        streams::HostInputStream::read(&mut self.table, s, len)
    }
    async fn blocking_read(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<Vec<u8>> {
        self.trace.push("blocking-read".into());
        self.now("blocking-read", |t| Box::pin(streams::HostInputStream::blocking_read(t, s, len)))
            .await.map_err(StreamError::Trap)?
    }
    fn skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        streams::HostInputStream::skip(&mut self.table, s, len)
    }
    async fn blocking_skip(&mut self, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        self.now("blocking-skip", |t| Box::pin(streams::HostInputStream::blocking_skip(t, s, len)))
            .await.map_err(StreamError::Trap)?
    }
    fn subscribe(&mut self, s: Resource<DynInputStream>) -> wasmtime::Result<Resource<DynPollable>> {
        streams::HostInputStream::subscribe(&mut self.table, s)
    }
}

impl streams::HostOutputStream for Host {
    async fn drop(&mut self, s: Resource<DynOutputStream>) -> wasmtime::Result<()> {
        streams::HostOutputStream::drop(&mut self.table, s).await
    }
    fn check_write(&mut self, s: Resource<DynOutputStream>) -> StreamResult<u64> {
        streams::HostOutputStream::check_write(&mut self.table, s)
    }
    fn write(&mut self, s: Resource<DynOutputStream>, bytes: Vec<u8>) -> StreamResult<()> {
        streams::HostOutputStream::write(&mut self.table, s, bytes)
    }
    async fn blocking_write_and_flush(&mut self, s: Resource<DynOutputStream>, bytes: Vec<u8>) -> StreamResult<()> {
        self.trace.push("blocking-write-and-flush".into());
        self.now("blocking-write-and-flush", |t| {
            Box::pin(streams::HostOutputStream::blocking_write_and_flush(t, s, bytes))
        })
        .await.map_err(StreamError::Trap)?
    }
    async fn blocking_write_zeroes_and_flush(&mut self, s: Resource<DynOutputStream>, len: u64) -> StreamResult<()> {
        self.now("blocking-write-zeroes-and-flush", |t| {
            Box::pin(streams::HostOutputStream::blocking_write_zeroes_and_flush(t, s, len))
        })
        .await.map_err(StreamError::Trap)?
    }
    fn write_zeroes(&mut self, s: Resource<DynOutputStream>, len: u64) -> StreamResult<()> {
        streams::HostOutputStream::write_zeroes(&mut self.table, s, len)
    }
    fn flush(&mut self, s: Resource<DynOutputStream>) -> StreamResult<()> {
        streams::HostOutputStream::flush(&mut self.table, s)
    }
    async fn blocking_flush(&mut self, s: Resource<DynOutputStream>) -> StreamResult<()> {
        self.trace.push("blocking-flush".into());
        self.now("blocking-flush", |t| Box::pin(streams::HostOutputStream::blocking_flush(t, s)))
            .await.map_err(StreamError::Trap)?
    }
    fn splice(&mut self, d: Resource<DynOutputStream>, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        streams::HostOutputStream::splice(&mut self.table, d, s, len)
    }
    async fn blocking_splice(&mut self, d: Resource<DynOutputStream>, s: Resource<DynInputStream>, len: u64) -> StreamResult<u64> {
        self.now("blocking-splice", |t| {
            Box::pin(streams::HostOutputStream::blocking_splice(t, d, s, len))
        })
        .await.map_err(StreamError::Trap)?
    }
    fn subscribe(&mut self, s: Resource<DynOutputStream>) -> wasmtime::Result<Resource<DynPollable>> {
        streams::HostOutputStream::subscribe(&mut self.table, s)
    }
}

// ------------------------------------------- deterministic clocks, random

struct Det;
impl HasData for Det {
    type Data<'a> = &'a mut Host;
}
struct HasIo;
impl HasData for HasIo {
    type Data<'a> = &'a mut ResourceTable;
}

struct ReadyNow;
#[wasmtime_wasi::async_trait]
impl wasmtime_wasi::p2::Pollable for ReadyNow {
    async fn ready(&mut self) {}
}

impl wall_clock::Host for &mut Host {
    fn now(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        Ok(wall_clock::Datetime { seconds: 1_800_000_000, nanoseconds: 0 })
    }
    fn resolution(&mut self) -> wasmtime::Result<wall_clock::Datetime> {
        Ok(wall_clock::Datetime { seconds: 0, nanoseconds: 1_000_000 })
    }
}

impl monotonic_clock::Host for &mut Host {
    fn now(&mut self) -> wasmtime::Result<monotonic_clock::Instant> {
        Ok(1_000_000_000)
    }
    fn resolution(&mut self) -> wasmtime::Result<monotonic_clock::Duration> {
        Ok(1_000_000)
    }
    fn subscribe_instant(&mut self, _: monotonic_clock::Instant) -> wasmtime::Result<Resource<DynPollable>> {
        let r = self.table.push(ReadyNow)?;
        wasmtime_wasi::p2::subscribe(&mut self.table, r)
    }
    fn subscribe_duration(&mut self, _: monotonic_clock::Duration) -> wasmtime::Result<Resource<DynPollable>> {
        let r = self.table.push(ReadyNow)?;
        wasmtime_wasi::p2::subscribe(&mut self.table, r)
    }
}

impl random::Host for &mut Host {
    fn get_random_bytes(&mut self, len: u64) -> wasmtime::Result<Vec<u8>> {
        Ok((0..len).map(|_| (self.get_random_u64().unwrap_or(0) & 0xff) as u8).collect())
    }
    fn get_random_u64(&mut self) -> wasmtime::Result<u64> {
        self.rng = self.rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        Ok(self.rng)
    }
}

fn build_linker(engine: &wasmtime::Engine) -> wasmtime::Result<Linker<Host>> {
    use wasmtime_wasi::cli::{WasiCli, WasiCliView};
    let mut l = Linker::<Host>::new(engine);
    error::add_to_linker::<Host, HasIo>(&mut l, |h| &mut h.table)?;
    poll::add_to_linker::<Host, HasSelf<Host>>(&mut l, |h| h)?;
    streams::add_to_linker::<Host, HasSelf<Host>>(&mut l, |h| h)?;
    wall_clock::add_to_linker::<Host, Det>(&mut l, |h| h)?;
    monotonic_clock::add_to_linker::<Host, Det>(&mut l, |h| h)?;
    random::add_to_linker::<Host, Det>(&mut l, |h| h)?;
    wasmtime_wasi::p2::bindings::cli::stderr::add_to_linker::<Host, WasiCli>(&mut l, Host::cli)?;
    let options = wasmtime_wasi_http::p2::bindings::LinkOptions::default();
    ht::add_to_linker::<Host, WasiHttp>(&mut l, &options.into(), Host::http)?;
    l.instance("wasi:http/outgoing-handler@0.2.12")?.func_wrap(
        "handle",
        |mut store: wasmtime::StoreContextMut<'_, Host>,
         (request, options): (Resource<HostOutgoingRequest>, Option<Resource<ht::RequestOptions>>)| {
            Ok((match store.data_mut().handle(request, options) {
                Ok(future) => Ok(future),
                Err(e) => Err(e.downcast()?),
            },))
        },
    )?;
    Ok(l)
}

// ---------------------------------------------------------------- runs

async fn run_once(
    pre: &wasmtime::component::InstancePre<Host>,
    engine: &wasmtime::Engine,
    mode: &str,
    naive: bool,
    seed: u64,
) -> wasmtime::Result<String> {
    let gate = Arc::new(Gate::new(seed));
    let mut hooks = Hooks::default();
    if naive {
        hooks.naive = Some((gate.clone(), Arc::new(AtomicU32::new(0))));
    }
    let host = Host {
        table: ResourceTable::new(),
        wasi: WasiCtxBuilder::new().build(),
        http: WasiHttpCtx::new(),
        hooks,
        gate: gate.clone(),
        naive,
        pending: Vec::new(),
        next_ordinal: 0,
        rng: 7,
        trace: Vec::new(),
    };
    let fuel = 10_000_000_000;
    let mut store = Store::new(engine, host);
    store.set_fuel(fuel)?;
    store.fuel_async_yield_interval(Some(1_000_000))?;
    let instance = pre.instantiate_async(&mut store).await?;
    let run = instance.get_typed_func::<(String,), (String,)>(&mut store, "run")?;
    let output = match run.call_async(&mut store, (mode.to_owned(),)).await {
        Ok((out,)) => out,
        Err(e) => format!("TRAP {e:#}"),
    };
    let fuel_used = fuel - store.get_fuel()?;
    let host = store.data();
    assert!(
        !output.contains(SECRET_VALUE),
        "the secret's value reached the guest: {output}"
    );
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "output": output,
        "effects": *gate.log.lock().unwrap(),
        "waits": host.trace,
        "fuel": fuel_used,
    }))?)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> wasmtime::Result<()> {
    let wasm = std::env::args().nth(1).unwrap_or_else(|| "guest/spike.wasm".into());
    let runs: u64 = std::env::var("RUNS").ok().and_then(|r| r.parse().ok()).unwrap_or(100);
    let engine = kronik_runtime::build_engine(PoolSize { concurrency: 1 })?;
    let component = Component::from_file(&engine, &wasm)?;
    let pre = build_linker(&engine)?.instantiate_pre(&component)?;
    let mut failed = false;
    for (mode, naive) in [("two", false), ("stream", false), ("error", false), ("two", true)] {
        let mut seen: BTreeMap<String, u64> = BTreeMap::new();
        for run in 0..runs {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                ^ run;
            let t = run_once(&pre, &engine, mode, naive, seed).await?;
            *seen.entry(t).or_default() += 1;
        }
        let label = if naive { format!("{mode} --naive") } else { mode.to_owned() };
        println!("== {label}: {runs} runs, {} distinct transcript(s)", seen.len());
        for (t, n) in &seen {
            println!("-- {n}x\n{t}");
        }
        if !naive && seen.len() != 1 {
            failed = true;
        }
    }
    if failed {
        bail!("a driven mode was not deterministic");
    }
    Ok(())
}
