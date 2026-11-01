//! The admin listener on `server.admin_listen` (127.0.0.1:9464 by default):
//! TLS additionally serves the embedded UI and public JSON API. Plain HTTP
//! serves only `/metrics` and `/healthz`, including storage failure status.
//
// Shell code: a hyper server on tokio (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use kronik_api::oidc::BrowserAuth;
use kronik_api::{Api, ApiRequest};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::Node;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

/// How long a client may take to send a request head.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Browser assets and API routes are mounted only on this listener over TLS.
pub async fn serve(
    listener: TcpListener,
    node: Arc<Node>,
    api: Arc<Api>,
    browser: Arc<BrowserAuth>,
    tls: Option<Arc<ServerConfig>>,
    max_connections: usize,
) -> std::io::Result<()> {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let slots = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut failures = 0;
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return Ok(());
        };
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                kronik_api::server::pause_after_accept_error(&mut failures, &error, "admin").await;
                continue;
            }
        };
        failures = 0;
        let (node, api, browser, acceptor) =
            (node.clone(), api.clone(), browser.clone(), acceptor.clone());
        tokio::spawn(async move {
            if let Some(acceptor) = acceptor {
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(stream)).await
                {
                    connection(stream, node, api, browser, true).await;
                }
            } else {
                connection(stream, node, api, browser, false).await;
            }
            drop(slot);
        });
    }
}

async fn connection<S>(
    stream: S,
    node: Arc<Node>,
    api: Arc<Api>,
    browser: Arc<BrowserAuth>,
    admin_tls: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let (node, api, browser) = (node.clone(), api.clone(), browser.clone());
        async move {
            let response = if admin_tls {
                match browser_request(request, &node, &api, &browser).await {
                    Ok(response) => response,
                    Err(error) => response(
                        error.code.http_status(),
                        "application/json",
                        error.to_json().to_string(),
                    ),
                }
            } else {
                answer(request.method(), request.uri().path(), &node)
            };
            Ok::<_, Infallible>(secure(response))
        }
    });
    let mut builder = http1::Builder::new();
    builder.max_buf_size(kronik_api::server::MAX_HEADER_BYTES);
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    if builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
        .is_err()
    {
        // Hyper errors can contain OAuth codes from malformed requests.
        tracing::debug!("admin connection ended");
    }
}

fn header<'a>(headers: &'a hyper::HeaderMap, name: &str) -> Result<Option<&'a str>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "duplicate authentication header",
        ));
    }
    value
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::new(ErrorCode::BadRequest, "invalid authentication header"))
        })
        .transpose()
}

async fn browser_request(
    request: hyper::Request<hyper::body::Incoming>,
    node: &Node,
    api: &Arc<Api>,
    browser: &BrowserAuth,
) -> Result<hyper::Response<kronik_api::server::Body>, ApiError> {
    let (parts, body) = request.into_parts();
    if let Some(origin) = browser.origin() {
        let host = origin.strip_prefix("https://").unwrap_or("");
        if header(&parts.headers, "host")? != Some(host) {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "admin request authority differs from configured OIDC redirect_uri",
            ));
        }
    }
    let path = parts.uri.path();
    if matches!(path, "/metrics" | "/healthz") {
        return Ok(answer(&parts.method, path, node));
    }
    if let Some(asset) = kronik_ui::asset(path) {
        if parts.method != hyper::Method::GET && parts.method != hyper::Method::HEAD {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "static UI assets accept GET and HEAD only",
            ));
        }
        return Ok(bytes_response(
            200,
            asset.content_type,
            if parts.method == hyper::Method::HEAD {
                Bytes::new()
            } else {
                Bytes::from_static(asset.bytes)
            },
        ));
    }
    if !path.starts_with("/v1/") {
        return Err(ApiError::new(
            ErrorCode::RouteNotFound,
            "the TLS admin listener serves /ui/, /v1/, /metrics and /healthz",
        ));
    }
    header(&parts.headers, "authorization")?;
    let cookies = header(&parts.headers, "cookie")?;
    let public_flow = matches!(path, "/v1/auth/login" | "/v1/auth/callback");
    let bearer = kronik_api::server::bearer(&parts.headers)?;
    let cookie_discovery = bearer.is_none() && path == "/v1/auth/session";
    let credential = match browser.credential(
        bearer,
        if public_flow { None } else { cookies },
        parts.method.as_str(),
        header(&parts.headers, "origin")?,
        header(&parts.headers, "x-kronik-csrf")?,
    ) {
        Ok(credential) => credential,
        Err(_) if cookie_discovery => None,
        Err(error) => return Err(error),
    };
    let mut req = ApiRequest {
        method: parts.method.as_str().into(),
        path: path.into(),
        query: parts.uri.query().unwrap_or("").into(),
        body: Vec::new(),
        token_id: "admin:browser".into(),
        bearer: credential,
    };
    if matches!(path, "/v1/events" | "/v1/events/stream" | "/v1/events/ws") {
        let incoming = hyper::Request::from_parts(parts, body);
        return Ok(kronik_api::event_stream::serve(api.clone(), req, incoming).await);
    }
    let protocol = matches!(
        path,
        "/v1/auth/session" | "/v1/auth/login" | "/v1/auth/callback" | "/v1/auth/logout"
    );
    let captured = if protocol {
        browser.capture_protocol_request(&req, api)?
    } else {
        Some(api.capture(&req)?)
    };
    let read = async {
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            Limited::new(body, kronik_api::server::MAX_REQUEST).collect(),
        )
        .await
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "admin request body timed out"))?
        .map_err(|_| {
            ApiError::new(
                ErrorCode::PayloadTooLarge,
                "admin request body exceeds the API limit",
            )
        })
    };
    let body = if let Some(captured) = &captured {
        tokio::select! {
            biased;
            () = captured.authority().cancelled() => {
                return Err(ApiError::new(ErrorCode::Unauthenticated, "Request authority revoked while reading the body"));
            }
            body = read => body?,
        }
    } else {
        read.await?
    };
    req.body = body.to_bytes().to_vec();
    if let Some(captured) = &captured {
        captured.authority().check()?;
    }
    if protocol {
        let result = browser
            .route(&req, cookies, api, captured)
            .await
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::NotImplemented,
                    "unknown authentication operation",
                )
            })??;
        let mut response = bytes_response(result.status, result.content_type, result.body);
        for (name, value) in result.headers.iter() {
            response.headers_mut().append(
                hyper::header::HeaderName::from_static(*name),
                hyper::header::HeaderValue::from_str(value).map_err(|_| {
                    ApiError::new(
                        ErrorCode::Internal,
                        "invalid authentication response header",
                    )
                })?,
            );
        }
        return Ok(response);
    }
    let captured = captured.ok_or_else(|| {
        ApiError::new(
            ErrorCode::Unauthenticated,
            "request lacks its original authority",
        )
    })?;
    req.bearer = None;
    let result = api.handle_admitted(req, captured).await;
    Ok(bytes_response(
        result.status,
        result.content_type,
        result.body.into(),
    ))
}

fn bytes_response(
    status: u16,
    content_type: &'static str,
    body: Bytes,
) -> hyper::Response<kronik_api::server::Body> {
    let mut response = hyper::Response::new(Full::new(body).boxed());
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    response
}

fn secure(
    mut response: hyper::Response<kronik_api::server::Body>,
) -> hyper::Response<kronik_api::server::Body> {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    ] {
        response.headers_mut().insert(
            hyper::header::HeaderName::from_static(name),
            hyper::header::HeaderValue::from_static(value),
        );
    }
    response
}

fn response(
    status: u16,
    content_type: &'static str,
    body: String,
) -> hyper::Response<kronik_api::server::Body> {
    let mut resp = hyper::Response::new(Full::new(Bytes::from(body)).boxed());
    *resp.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    resp
}

/// The gauges read at scrape time, set before `/metrics` answers and
/// before each OTLP metrics push.
pub fn set_scrape_gauges(node: &Node) {
    kronik_metrics::set(
        "kronik_build_info",
        &[
            ("version", kronik_runtime::KRONIK_VERSION),
            ("engine", kronik_runtime::ENGINE_VERSION),
        ],
        1.0,
    );
    kronik_metrics::set("kronik_applied_lsn", &[], node.applied_lsn() as f64);
    kronik_metrics::set(
        "kronik_key_source_up",
        &[],
        f64::from(u8::from(node.key_source().is_some())),
    );
    if let Some(free) = node.disk_free() {
        kronik_metrics::set("kronik_disk_free_bytes", &[], free as f64);
        let low = node.disk_below_reserve().is_some();
        kronik_metrics::set("kronik_disk_below_reserve", &[], f64::from(u8::from(low)));
    }
}

fn answer(
    method: &hyper::Method,
    path: &str,
    node: &Node,
) -> hyper::Response<kronik_api::server::Body> {
    if method != hyper::Method::GET {
        let e = ApiError::new(ErrorCode::BadRequest, format!("{method} {path}: only GET"));
        return response(405, "application/json", e.to_json().to_string());
    }
    match path {
        "/metrics" => {
            set_scrape_gauges(node);
            response(
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                kronik_metrics::render(),
            )
        }
        "/healthz" => match node.fatal() {
            None => {
                let mut body =
                    serde_json::json!({"status": "ok", "applied_lsn": node.applied_lsn()});
                // A field of its own: probes that compare the status keep working.
                if node.disk_below_reserve().is_some() {
                    body["low_disk"] = serde_json::Value::Bool(true);
                }
                response(200, "application/json", body.to_string())
            }
            Some(failure) => response(
                503,
                "application/json",
                ApiError::new(ErrorCode::Unavailable, failure)
                    .to_json()
                    .to_string(),
            ),
        },
        _ => {
            let e = ApiError::new(
                ErrorCode::RouteNotFound,
                format!("no {path} here: /metrics and /healthz"),
            );
            response(404, "application/json", e.to_json().to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_headers_must_be_unique_and_text() {
        let mut headers = hyper::HeaderMap::new();
        for name in ["authorization", "cookie", "origin", "x-kronik-csrf", "host"] {
            headers.insert(name, hyper::header::HeaderValue::from_static("one"));
            assert_eq!(header(&headers, name).unwrap(), Some("one"));
            headers.append(name, hyper::header::HeaderValue::from_static("two"));
            assert!(header(&headers, name).is_err());
            headers.insert(
                name,
                hyper::header::HeaderValue::from_bytes(b"\xff").unwrap(),
            );
            assert!(header(&headers, name).is_err());
            headers.remove(name);
        }
    }

    #[test]
    fn browser_responses_never_cache_or_leak_referrers() {
        let response = secure(bytes_response(200, "text/html", Bytes::new()));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(
            response.headers()["cross-origin-resource-policy"],
            "same-origin"
        );
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }
}
