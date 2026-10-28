//! The admin listener on `server.admin_listen` (127.0.0.1:9464 by default):
//! `GET /metrics` in the Prometheus text format ([`kronik_metrics`]) and
//! `GET /healthz`, 200 while the node runs and 503 after a storage failure.
//
// Shell code: a hyper server on tokio (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_sched::Node;
use tokio::net::TcpListener;

/// How long a client may take to send a request head.
const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serves until the task is dropped. Each connection is a task.
pub async fn serve(listener: TcpListener, node: Arc<Node>) -> std::io::Result<()> {
    let mut failures = 0;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                kronik_api::server::pause_after_accept_error(&mut failures, &e, "admin").await;
                continue;
            }
        };
        failures = 0;
        let node = node.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let response = answer(req.method(), req.uri().path(), &node);
                async move { Ok::<_, Infallible>(response) }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_TIMEOUT);
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                tracing::debug!(error = %e, "admin connection ended");
            }
        });
    }
}

fn response(status: u16, content_type: &'static str, body: String) -> hyper::Response<Full<Bytes>> {
    let mut resp = hyper::Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static(content_type),
    );
    resp
}

fn answer(method: &hyper::Method, path: &str, node: &Node) -> hyper::Response<Full<Bytes>> {
    if method != hyper::Method::GET {
        let e = ApiError::new(ErrorCode::BadRequest, format!("{method} {path}: only GET"));
        return response(405, "application/json", e.to_json().to_string());
    }
    match path {
        "/metrics" => {
            kronik_metrics::set(
                "kronik_build_info",
                &[
                    ("version", kronik_runtime::KRONIK_VERSION),
                    ("engine", kronik_runtime::ENGINE_VERSION),
                ],
                1.0,
            );
            kronik_metrics::set("kronik_applied_lsn", &[], node.applied_lsn() as f64);
            if let Some(free) = node.disk_free() {
                kronik_metrics::set("kronik_disk_free_bytes", &[], free as f64);
                let low = node.disk_below_reserve().is_some();
                kronik_metrics::set("kronik_disk_below_reserve", &[], f64::from(u8::from(low)));
            }
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
