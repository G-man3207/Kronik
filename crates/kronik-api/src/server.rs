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
/// One maximum typed resume cursor plus bounded request headroom.
pub const MAX_HEADER_BYTES: usize = 2 * kronik_fleet::events::MAX_CURSOR_BYTES + 8192;

/// Over TCP, how long a client may take to send a request head, then its
/// body. The Unix socket is local, and has no limit.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// A response body: buffered for the JSON API, possibly streamed by a
/// [`Mount`].
pub type Body = BoxBody<Bytes, Infallible>;

/// A mounted service receives the original pre-body authority, never a bearer.
pub type Mount = Arc<
    dyn Fn(
            crate::CapturedRequest,
            hyper::Request<Full<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = hyper::Response<Body>> + Send>>
        + Send
        + Sync,
>;

/// Binds the socket, replacing a stale socket file, with mode 0660.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    prepare_socket(path)?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// [`bind`] without the runtime: the non-root daemon binds before it
/// starts one, and hands the listener to its acceptor process.
pub fn bind_std(path: &Path) -> std::io::Result<std::os::unix::net::UnixListener> {
    prepare_socket(path)?;
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// The socket's directory exists and no stale socket file is in the way.
fn prepare_socket(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

pub(crate) fn event_cursor_header(headers: &hyper::HeaderMap) -> Result<Option<&str>, ApiError> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "duplicate Last-Event-ID headers",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "invalid Last-Event-ID"))?;
    if value.len() > kronik_fleet::events::MAX_CURSOR_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "invalid Last-Event-ID",
        ));
    }
    Ok(Some(value))
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
            None,
        ));
    }
}

/// Like [`serve_with`], for connections accepted elsewhere, each with its
/// peer's host uid (`u32::MAX`: unknown): the non-root daemon's acceptor
/// process reads it in the initial user namespace, where `SO_PEERCRED` is
/// not translated. Serves until `conns` ends, then fails.
pub async fn serve_accepted(
    mut conns: tokio::sync::mpsc::Receiver<(std::os::unix::net::UnixStream, u32)>,
    api: Arc<Api>,
    mount: Option<(&'static str, Mount)>,
) -> std::io::Result<()> {
    while let Some((stream, uid)) = conns.recv().await {
        let stream = match stream
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UnixStream::from_std(stream))
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "dropping an API connection");
                continue;
            }
        };
        let identity = if uid == u32::MAX {
            "unix:uid=unknown".to_owned()
        } else {
            format!("unix:uid={uid}")
        };
        tokio::spawn(serve_connection(
            stream,
            identity,
            api.clone(),
            mount.clone(),
            None,
        ));
    }
    Err(std::io::Error::other("the API socket's acceptor stopped"))
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
                    serve_connection(stream, identity, api, mount, None).await;
                    drop(slot);
                });
            }
            Some(acceptor) => {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(tls)) => serve_connection(tls, identity, api, mount, None).await,
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

/// The outbound controller receives only this already captured ordinary credential.
/// No remote header, cookie, request field or fresh post-handoff lookup selects identity.
pub async fn serve_fleet_connection(
    stream: tokio::io::DuplexStream,
    api: Arc<Api>,
    captured: crate::CapturedRequest,
    mount: Option<(&'static str, Mount)>,
) -> Result<(), ApiError> {
    captured.authority().check()?;
    let lifetime = captured.authority().clone();
    tokio::select! {
        biased;
        () = lifetime.cancelled() => {},
        () = serve_connection(stream, "tcp:fleet".into(), api, mount, Some(captured)) => {},
    }
    Ok(())
}

/// One connection: HTTP/1.1 requests to the JSON API or to `mount`.
async fn serve_connection<S>(
    stream: S,
    identity: String,
    api: Arc<Api>,
    mount: Option<(&'static str, Mount)>,
    trusted: Option<crate::CapturedRequest>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tcp = identity.starts_with("tcp:");
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let api = api.clone();
        let identity = identity.clone();
        let mount = mount.clone();
        let trusted = trusted.clone();
        async move {
            let (mut parts, body) = req.into_parts();
            let identity_is_fleet = trusted.is_some();
            let bearer = if trusted.is_some() {
                None
            } else {
                match bearer(&parts.headers) {
                    Ok(bearer) => bearer,
                    Err(e) => return Ok::<_, Infallible>(error_response(&e)),
                }
            };
            if tcp && trusted.is_none() && bearer.is_none() {
                let e = ApiError::new(
                    ErrorCode::Unauthenticated,
                    "the API over TCP needs a bearer token",
                )
                .with_hint(
                    "Send `Authorization: Bearer <token>`; `kronik token create` makes one.",
                );
                return Ok(error_response(&e));
            }
            let mut req = ApiRequest {
                method: parts.method.as_str().to_owned(),
                path: parts.uri.path().to_owned(),
                query: parts.uri.query().unwrap_or("").to_owned(),
                body: Vec::new(),
                token_id: identity,
                bearer,
            };
            let mounted = mount.as_ref().is_some_and(|(path, _)| {
                req.path
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            });
            let captured = match if let Some(captured) = trusted {
                let authorization = if mounted {
                    captured.authority().check()
                } else {
                    api.authorize_captured_request(&req, &captured)
                };
                authorization.map(|()| captured)
            } else if mounted {
                api.capture_binding(&req)
            } else {
                api.capture(&req)
            } {
                Ok(captured) => captured,
                Err(error) => return Ok(error_response(&error)),
            };
            let authority = captured.authority().clone();
            parts.headers.remove(hyper::header::AUTHORIZATION);
            if identity_is_fleet {
                parts.headers.remove(hyper::header::COOKIE);
            }
            req.bearer = None;
            if matches!(req.path.as_str(), "/v1/events/stream" | "/v1/events/ws") {
                let incoming = hyper::Request::from_parts(parts, body);
                return Ok(crate::event_stream::serve_captured(api, req, captured, incoming).await);
            }
            if req.method == "GET" && req.path == "/v1/events" {
                let incoming = hyper::Request::from_parts(parts, body);
                return Ok(
                    crate::event_stream::serve_page_captured(api, req, captured, incoming).await,
                );
            }
            let read = async {
                let read = Limited::new(body, MAX_REQUEST).collect();
                if tcp {
                    match tokio::time::timeout(BODY_TIMEOUT, read).await {
                        Ok(read) => read.map_err(|_| {
                            ApiError::new(
                                ErrorCode::PayloadTooLarge,
                                "API request body exceeds its limit",
                            )
                        }),
                        Err(_) => Err(ApiError::new(
                            ErrorCode::BadRequest,
                            "API request body timed out",
                        )),
                    }
                } else {
                    read.await.map_err(|_| {
                        ApiError::new(
                            ErrorCode::PayloadTooLarge,
                            "API request body exceeds its limit",
                        )
                    })
                }
            };
            let read = tokio::select! {
                biased;
                () = authority.cancelled() => return Ok(error_response(&ApiError::new(ErrorCode::Unauthenticated, "Request authority revoked while reading the body"))),
                read = read => read,
            };
            let body = match read {
                Ok(body) => body.to_bytes(),
                Err(error) => return Ok(error_response(&error)),
            };
            if let Err(error) = authority.check() {
                return Ok(error_response(&error));
            }
            if mounted && let Some((_, mount)) = &mount {
                return Ok(
                    mount(captured, hyper::Request::from_parts(parts, Full::new(body))).await,
                );
            }
            let r = api
                .handle_admitted(
                    ApiRequest {
                        body: body.to_vec(),
                        ..req
                    },
                    captured,
                )
                .await;
            Ok(response(r.status, r.content_type, r.body))
        }
    });
    let mut builder = http1::Builder::new();
    builder.max_buf_size(MAX_HEADER_BYTES);
    if tcp {
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT);
    }
    if let Err(e) = builder
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await
    {
        tracing::debug!(error = %e, "API connection ended");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod event_cursor_tests {
    use super::*;
    #[test]
    fn full_cursor_header_is_bounded_and_duplicate_headers_are_rejected() {
        let mut headers = hyper::HeaderMap::new();
        let cursor = "x".repeat(kronik_fleet::events::MAX_CURSOR_BYTES);
        headers.insert(
            "last-event-id",
            hyper::header::HeaderValue::from_str(&cursor).unwrap(),
        );
        assert_eq!(
            event_cursor_header(&headers).unwrap(),
            Some(cursor.as_str())
        );
        headers.append(
            "last-event-id",
            hyper::header::HeaderValue::from_static("other"),
        );
        assert!(event_cursor_header(&headers).is_err());
        headers.clear();
        headers.insert(
            "last-event-id",
            hyper::header::HeaderValue::from_str(&(cursor + "x")).unwrap(),
        );
        assert!(event_cursor_header(&headers).is_err());
        headers.insert(
            "last-event-id",
            hyper::header::HeaderValue::from_static("bad\tcursor"),
        );
        assert!(event_cursor_header(&headers).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod acceptor_tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn transferred_uid_is_not_recomputed_and_acceptor_eof_is_fatal() {
        let data = tempfile::tempdir().unwrap();
        let env = kronik_core::env::Env::real(tokio::runtime::Handle::current());
        let node = kronik_sched::start_local(env, data.path(), Default::default())
            .await
            .unwrap();
        let api = Arc::new(Api::new(node));
        let mount: Mount = Arc::new(|captured, _| {
            Box::pin(
                async move { response(200, "text/plain", captured.caller.token_id.into_bytes()) },
            )
        });
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(serve_accepted(rx, api, Some(("/identity", mount))));
        let (client, accepted) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.send((accepted, 4242)).await.unwrap();
        client.set_nonblocking(true).unwrap();
        let mut client = tokio::net::UnixStream::from_std(client).unwrap();
        client
            .write_all(b"GET /identity HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert!(
            answer.ends_with(b"unix:uid=4242"),
            "{}",
            String::from_utf8_lossy(&answer)
        );
        drop(tx);
        let stopped = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            stopped.is_err(),
            "acceptor death cannot leave a serving daemon"
        );
    }
}
