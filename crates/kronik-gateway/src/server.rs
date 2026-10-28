//! Binds the gateway to hyper on a TCP listener: HTTP/1.1, plain or over
//! TLS ([`crate::tls`]).
//
// The hyper server runs on tokio directly (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::tls::ACME_TLS_ALPN;
use crate::{Gateway, HttpRequest, HttpResponse, IpNet};

/// How long a client may take to send a request head, then its body.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

fn error(status: u16, code: kronik_core::error::ErrorCode, message: String) -> HttpResponse {
    let e = kronik_core::error::ApiError::new(code, message);
    HttpResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: e.to_json().to_string().into_bytes(),
    }
}

async fn to_request(
    req: hyper::Request<Incoming>,
    max_body: usize,
    peer: std::net::IpAddr,
) -> Result<HttpRequest, HttpResponse> {
    let (parts, body) = req.into_parts();
    let body =
        match tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, max_body).collect()).await {
            Ok(Ok(b)) => b.to_bytes().to_vec(),
            Ok(Err(_)) => {
                return Err(error(
                    413,
                    kronik_core::error::ErrorCode::PayloadTooLarge,
                    format!("the request body exceeds {max_body} bytes"),
                ));
            }
            Err(_) => {
                return Err(error(
                    400,
                    kronik_core::error::ErrorCode::BadRequest,
                    format!(
                        "the request body did not arrive within {} s",
                        BODY_TIMEOUT.as_secs()
                    ),
                ));
            }
        };
    Ok(HttpRequest {
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_owned(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body,
        peer: Some(peer),
    })
}

fn to_hyper(r: HttpResponse) -> hyper::Response<Full<Bytes>> {
    let mut b = hyper::Response::builder().status(r.status);
    for (n, v) in &r.headers {
        b = b.header(n, v);
    }
    b.body(Full::new(Bytes::from(r.body))).unwrap_or_else(|e| {
        let mut resp = hyper::Response::new(Full::new(Bytes::from(format!(
            "{{\"error\":{{\"code\":\"INTERNAL\",\"message\":\"invalid response from the actor: {e}\"}}}}"
        ))));
        *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
        resp
    })
}

/// Serves HTTP/1.1 on one connection.
async fn serve_connection<I>(io: I, gw: Arc<Gateway>, peer: std::net::IpAddr)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let gw = gw.clone();
        async move {
            let started = std::time::Instant::now();
            let resp = match to_request(req, gw.cfg.max_body, peer).await {
                Ok(r) => gw.handle(r).await,
                Err(resp) => resp,
            };
            let status = resp.status.to_string();
            kronik_metrics::inc("kronik_gateway_requests_total", &[("status", &status)]);
            kronik_metrics::observe(
                "kronik_gateway_request_duration_seconds",
                &[("status", &status)],
                started.elapsed(),
            );
            Ok::<_, Infallible>(to_hyper(resp))
        }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    if let Err(e) = builder.serve_connection(TokioIo::new(io), svc).await {
        tracing::debug!(error = %e, "gateway connection ended");
    }
}

/// After a failed `accept()` (EMFILE when the descriptors run out, say): a
/// warning and a pause that doubles from 10 ms to about a second, instead
/// of ending the server. `failures` counts the failures in a row.
async fn pause_after_accept_error(failures: &mut u32, error: &std::io::Error) {
    tracing::warn!(%error, listener = "gateway", "accept failed; retrying");
    let pause = Duration::from_millis(10 << (*failures).min(7));
    *failures += 1;
    tokio::time::sleep(pause).await;
}

/// How many connections over their client's share are answered 503 at
/// once, and how long each answer may take; more are closed unanswered.
const REFUSALS: usize = 64;
const REFUSAL_TIME: Duration = Duration::from_secs(2);

/// The open connections: at most `total`, and a quarter of them (at least
/// four) from one client address, so that one client cannot hold them all.
/// Trusted proxies (`gateway.trusted_proxies`) have no share of their own.
struct Slots {
    total: Arc<Semaphore>,
    per_client: usize,
    clients: std::sync::Mutex<HashMap<IpAddr, usize>>,
    refusals: Arc<Semaphore>,
}

impl Slots {
    fn new(total: usize) -> Arc<Slots> {
        Arc::new(Slots {
            total: Arc::new(Semaphore::new(total)),
            per_client: (total / 4).max(4),
            clients: std::sync::Mutex::new(HashMap::new()),
            refusals: Arc::new(Semaphore::new(REFUSALS)),
        })
    }

    /// A slot for a connection from `client`, unless it is no trusted proxy
    /// and has its share open.
    fn take(
        self: &Arc<Self>,
        client: IpAddr,
        trusted: bool,
        total: OwnedSemaphorePermit,
    ) -> Option<Slot> {
        let counted = if trusted {
            None
        } else {
            let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
            let open = clients.entry(client).or_insert(0);
            if *open >= self.per_client {
                return None;
            }
            *open += 1;
            Some(client)
        };
        Some(Slot {
            _total: total,
            slots: self.clone(),
            client: counted,
        })
    }
}

/// A connection's slot, given back when the connection ends.
struct Slot {
    _total: OwnedSemaphorePermit,
    slots: Arc<Slots>,
    /// The client whose share it counts against; none for a trusted proxy.
    client: Option<IpAddr>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let Some(client) = self.client else {
            return;
        };
        let mut clients = self.slots.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = clients.get_mut(&client) {
            *open = open.saturating_sub(1);
            if *open == 0 {
                clients.remove(&client);
            }
        }
    }
}

/// A new connection: with its slot, or over its client's share and to be
/// answered 503 (holding one of the [`REFUSALS`] permits).
enum Accepted {
    Served(TcpStream, SocketAddr, Slot),
    Refused(TcpStream, SocketAddr, OwnedSemaphorePermit),
}

async fn accept(listener: &TcpListener, slots: &Arc<Slots>, trusted: &[IpNet]) -> Accepted {
    let mut failures = 0;
    loop {
        // The semaphore is never closed, so this waits for a free slot.
        let Ok(total) = slots.total.clone().acquire_owned().await else {
            continue;
        };
        match listener.accept().await {
            Ok((stream, peer)) => {
                let proxy = trusted.iter().any(|net| net.contains(peer.ip()));
                if let Some(slot) = slots.take(peer.ip(), proxy, total) {
                    return Accepted::Served(stream, peer, slot);
                }
                match slots.refusals.clone().try_acquire_owned() {
                    Ok(permit) => return Accepted::Refused(stream, peer, permit),
                    Err(_) => {
                        tracing::debug!(%peer, "too many connections from this client; closed")
                    }
                }
            }
            Err(e) => pause_after_accept_error(&mut failures, &e).await,
        }
    }
}

/// Answers a connection over its client's share with 503 and `connection:
/// close`, so that a proxy in front can say so too. What the client sends
/// meanwhile is read, so that closing is no reset that loses the answer.
async fn refuse<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let body = kronik_core::error::ApiError::new(
        kronik_core::error::ErrorCode::Unavailable,
        "too many connections from this address; try again shortly",
    )
    .to_json()
    .to_string();
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\nretry-after: 1\r\n\r\n{body}",
        body.len()
    );
    let answer = async {
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
        let mut sink = [0u8; 1024];
        while stream.read(&mut sink).await? > 0 {}
        Ok::<_, std::io::Error>(())
    };
    if let Err(e) = tokio::time::timeout(REFUSAL_TIME, answer).await {
        tracing::debug!(error = %e, "a refused connection stayed open; closed");
    }
}

/// Serves until the task is dropped, with at most `max_connections` open.
/// Each connection is a task.
pub async fn serve(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    max_connections: usize,
) -> std::io::Result<()> {
    let slots = Slots::new(max_connections);
    loop {
        match accept(&listener, &slots, &gateway.cfg.trusted_proxies).await {
            Accepted::Served(stream, peer, slot) => {
                let gw = gateway.clone();
                tokio::spawn(async move {
                    serve_connection(stream, gw, peer.ip()).await;
                    drop(slot);
                });
            }
            Accepted::Refused(stream, _, permit) => {
                tokio::spawn(async move {
                    refuse(stream).await;
                    drop(permit);
                });
            }
        }
    }
}

/// [`serve_tls`] with a TLS configuration, else [`serve`].
pub async fn serve_with_tls(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    tls: Option<Arc<rustls::ServerConfig>>,
    max_connections: usize,
) -> std::io::Result<()> {
    match tls {
        Some(config) => serve_tls(listener, gateway, config, max_connections).await,
        None => serve(listener, gateway, max_connections).await,
    }
}

/// Like [`serve`], over TLS with `config` (from [`crate::tls::start`]). A
/// TLS-ALPN-01 validation by an ACME CA ends after the handshake.
pub async fn serve_tls(
    listener: TcpListener,
    gateway: Arc<Gateway>,
    config: Arc<rustls::ServerConfig>,
    max_connections: usize,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let slots = Slots::new(max_connections);
    loop {
        let (stream, peer, slot) = match accept(&listener, &slots, &gateway.cfg.trusted_proxies)
            .await
        {
            Accepted::Served(stream, peer, slot) => (stream, peer, slot),
            Accepted::Refused(stream, peer, permit) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(REFUSAL_TIME, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => refuse(tls).await,
                        _ => tracing::debug!(%peer, "no TLS handshake from a refused connection"),
                    }
                    drop(permit);
                });
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let gw = gateway.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(tls)) => {
                    if tls.get_ref().1.alpn_protocol() != Some(ACME_TLS_ALPN) {
                        serve_connection(tls, gw, peer.ip()).await;
                    }
                }
                Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
            drop(slot);
        });
    }
}
