//! Binds the API to hyper: on a Unix socket (mode 0660), where the
//! connection's identity is the peer's uid from `SO_PEERCRED`
//! (`unix:uid=<n>`), and optionally on TCP (M5), where every request needs a
//! bearer token. A request with `Authorization: Bearer <token>` is that
//! token's caller on either listener ([`crate::tokens`]).
//
// The hyper server runs on tokio directly (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::convert::Infallible;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use kronik_core::error::{ApiError, ErrorCode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio_rustls::rustls::ServerConfig;

use crate::{Api, ApiRequest};

/// Largest API request body (a deploy carries the component as base64).
pub const MAX_REQUEST: usize = 64 << 20;

/// Over TCP, how long a client may take to send a request head, then its
/// body. The Unix socket is local, and has no limit.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// A response body: buffered for the JSON API, possibly streamed by a
/// [`Mount`].
pub type Body = BoxBody<Bytes, Infallible>;

/// A service mounted at a path of the API listener, such as the MCP
/// endpoint at `/mcp`. It gets the connection's identity (`unix:uid=<n>` or
/// `tcp:<peer>`) and the request with its body read (at most
/// [`MAX_REQUEST`] bytes). The listener has already checked a bearer token in
/// the request's `Authorization` header, and refused requests without one
/// over TCP.
pub type Mount = Arc<
    dyn Fn(
            String,
            hyper::Request<Full<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = hyper::Response<Body>> + Send>>
        + Send
        + Sync,
>;

/// Binds the socket, replacing a stale socket file, with mode 0660.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn response(status: u16, content_type: &'static str, body: Vec<u8>) -> hyper::Response<Body> {
    let mut resp = hyper::Response::new(Full::new(Bytes::from(body)).boxed());
    *resp.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    if status == 401 {
        resp.headers_mut().insert(
            hyper::header::WWW_AUTHENTICATE,
            hyper::header::HeaderValue::from_static("Bearer"),
        );
    }
    resp
}

fn error_response(e: &ApiError) -> hyper::Response<Body> {
    response(
        e.code.http_status(),
        "application/json",
        e.to_json().to_string().into_bytes(),
    )
}

/// The token of an `Authorization: Bearer <token>` header; an error when
/// the header is there but holds no bearer token.
pub fn bearer(headers: &hyper::HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(value) = headers.get(hyper::header::AUTHORIZATION) else {
        return Ok(None);
    };
    let malformed = || {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "the Authorization header must be `Bearer <token>`",
        )
    };
    let value = value.to_str().map_err(|_| malformed())?;
    match value.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => {
            let token = token.trim();
            if token.is_empty() {
                Err(malformed())
            } else {
                Ok(Some(token.to_owned()))
            }
        }
        _ => Err(malformed()),
    }
}

/// After a failed `accept()` (EMFILE when the descriptors run out, say): a
/// warning and a pause that doubles from 10 ms to about a second, instead
/// of ending the server. `failures` counts the failures in a row.
pub async fn pause_after_accept_error(failures: &mut u32, error: &std::io::Error, listener: &str) {
    tracing::warn!(%error, listener, "accept failed; retrying");
    let pause = Duration::from_millis(10 << (*failures).min(7));
    *failures += 1;
    tokio::time::sleep(pause).await;
}

/// Serves until the task is dropped. Each connection is a task.
pub async fn serve(listener: UnixListener, api: Arc<Api>) -> std::io::Result<()> {
    serve_with(listener, api, None).await
}

/// Like [`serve`], with `mount` answering the requests to its path, or
/// below it, instead of the JSON API.
pub async fn serve_with(
    listener: UnixListener,
    api: Arc<Api>,
    mount: Option<(&'static str, Mount)>,
) -> std::io::Result<()> {
    let mut failures = 0;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                pause_after_accept_error(&mut failures, &e, "API socket").await;
                continue;
            }
        };
        failures = 0;
        let identity = match stream.peer_cred() {
            Ok(c) => format!("unix:uid={}", c.uid()),
            Err(_) => "unix:uid=unknown".into(),
        };
        tokio::spawn(serve_connection(
            stream,
            identity,
            api.clone(),
            mount.clone(),
        ));
    }
}

/// The API and `mount` on TCP, where every request needs a bearer token;
/// over TLS with `tls` (the gateway's certificate configuration). Serves
/// until the task is dropped, with at most `max_connections` at once.
pub async fn serve_tcp(
    listener: TcpListener,
    api: Arc<Api>,
    mount: Option<(&'static str, Mount)>,
    tls: Option<Arc<ServerConfig>>,
    max_connections: usize,
) -> std::io::Result<()> {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut failures = 0;
    loop {
        // The semaphore is never closed.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return Ok(());
        };
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                pause_after_accept_error(&mut failures, &e, "API over TCP").await;
                continue;
            }
        };
        failures = 0;
        let identity = format!("tcp:{peer}");
        let (api, mount) = (api.clone(), mount.clone());
        match &acceptor {
            None => {
                tokio::spawn(async move {
                    serve_connection(stream, identity, api, mount).await;
                    drop(slot);
                });
            }
            Some(acceptor) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(tls)) => serve_connection(tls, identity, api, mount).await,
                        Ok(Err(e)) => {
                            tracing::debug!(%peer, error = %e, "API TLS handshake failed")
                        }
                        Err(_) => tracing::debug!(%peer, "API TLS handshake timed out"),
                    }
                    drop(slot);
                });
            }
        }
    }
}

/// One connection: HTTP/1.1 requests to the JSON API or to `mount`.
async fn serve_connection<S>(
    stream: S,
    identity: String,
    api: Arc<Api>,
    mount: Option<(&'static str, Mount)>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tcp = identity.starts_with("tcp:");
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let api = api.clone();
        let identity = identity.clone();
        let mount = mount.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bearer = match bearer(&parts.headers) {
                Ok(bearer) => bearer,
                Err(e) => return Ok::<_, Infallible>(error_response(&e)),
            };
            if tcp && bearer.is_none() {
                let e = ApiError::new(
                    ErrorCode::Unauthenticated,
                    "the API over TCP needs a bearer token",
                )
                .with_hint(
                    "Send `Authorization: Bearer <token>`; `kronik token create` makes one.",
                );
                return Ok(error_response(&e));
            }
            let req = ApiRequest {
                method: parts.method.as_str().to_owned(),
                path: parts.uri.path().to_owned(),
                query: parts.uri.query().unwrap_or("").to_owned(),
                body: Vec::new(),
                token_id: identity,
                bearer,
            };
            // The caller first: a bad token gets no further than the
            // listener, and never makes it read a body. The mount makes its
            // own API requests as this caller.
            if let Err(e) = api.caller(&req) {
                return Ok(error_response(&e));
            }
            let read = Limited::new(body, MAX_REQUEST).collect();
            let read = if tcp {
                match tokio::time::timeout(BODY_TIMEOUT, read).await {
                    Ok(read) => read,
                    Err(_) => {
                        let e = ApiError::new(
                            ErrorCode::BadRequest,
                            format!(
                                "the request body did not arrive within {} s",
                                BODY_TIMEOUT.as_secs()
                            ),
                        );
                        return Ok(error_response(&e));
                    }
                }
            } else {
                read.await
            };
            let body = match read {
                Ok(b) => b.to_bytes(),
                Err(_) => {
                    let e = ApiError::new(
                        ErrorCode::PayloadTooLarge,
                        format!("API requests are limited to {MAX_REQUEST} bytes"),
                    );
                    return Ok(error_response(&e));
                }
            };
            if let Some((path, mount)) = &mount {
                let under = parts.uri.path().strip_prefix(path);
                if under.is_some_and(|rest| rest.is_empty() || rest.starts_with('/')) {
                    let request = hyper::Request::from_parts(parts, Full::new(body));
                    return Ok(mount(req.token_id, request).await);
                }
            }
            let r = api
                .handle(ApiRequest {
                    body: body.to_vec(),
                    ..req
                })
                .await;
            Ok(response(r.status, r.content_type, r.body))
        }
    });
    let mut builder = http1::Builder::new();
    if tcp {
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT);
    }
    if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
        tracing::debug!(error = %e, "API connection ended");
    }
}
