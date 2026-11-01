//! HTTP/1 admission at Hyper's actual synchronous dispatch queue.
use http_body_util::BodyExt as _;
use hyper::rt::Executor as _;
use tower_service::Service as _;

use crate::authority::AuthLease;
use crate::env::{BoxFuture, HttpRequest, HttpResponse, NetError};
use super::Connector;

pub(super) fn send(connector: Result<Connector, String>, req: HttpRequest, original: AuthLease)
    -> BoxFuture<'static, Result<HttpResponse, NetError>>
{
    Box::pin(async move {
        let denied = |error: crate::error::ApiError| NetError::Connect(error.to_string());
        original.check().map_err(denied)?;
        let uri: hyper::Uri = req.url.parse()
            .map_err(|error| NetError::Connect(format!("invalid request URI: {error}")))?;
        uri.scheme_str().filter(|scheme| matches!(*scheme, "http" | "https"))
            .ok_or_else(|| NetError::Connect("request URI needs http or https".into()))?;
        let destination = uri.authority()
            .ok_or_else(|| NetError::Connect("request URI needs an authority".into()))?;
        let mut builder = hyper::Request::builder().method(req.method.as_str());
        builder = if req.method == "CONNECT" { builder.uri(destination.as_str()) }
            else { builder.uri(uri.path_and_query().map_or("/", |path| path.as_str())) };
        for (name, value) in &req.headers { builder = builder.header(name.as_str(), value.as_str()); }
        if !req.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
            builder = builder.header(hyper::header::HOST, destination.as_str());
        }
        let request = builder.body(http_body_util::Full::new(req.body))
            .map_err(|error| NetError::Connect(format!("invalid request: {error}")))?;
        let mut connector = connector.map_err(NetError::Connect)?;
        let connect = async {
            std::future::poll_fn(|cx| connector.poll_ready(cx)).await
                .map_err(|error| NetError::Connect(error.to_string()))?;
            let stream = connector.call(uri).await
                .map_err(|error| NetError::Connect(error.to_string()))?;
            let (sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(64 * 1024)
                .handshake::<_, http_body_util::Full<bytes::Bytes>>(stream).await
                .map_err(|error| NetError::Connect(error.to_string()))?;
            hyper_util::rt::TokioExecutor::new().execute(async move { let _ = connection.await; });
            Ok::<_, NetError>(sender)
        };
        let mut sender = tokio::select! {
            biased;
            () = original.cancelled() => return Err(NetError::Connect("request authority ended before connection admission".into())),
            result = connect => result?,
        };
        tokio::select! {
            biased;
            () = original.cancelled() => return Err(NetError::Connect("request authority ended while waiting for HTTP capacity".into())),
            result = sender.ready() => result.map_err(|error| NetError::Connect(error.to_string()))?,
        }
        let mut pending = Some(request);
        let mut response = None;
        original.admit(&mut || {
            let request = pending.take().ok_or_else(|| crate::error::ApiError::new(
                crate::error::ErrorCode::Internal, "HTTP request admitted twice"))?;
            response = Some(sender.try_send_request(request));
            Ok(())
        }).map_err(denied)?;
        let response = response.ok_or_else(|| NetError::Connect("authority did not enqueue the HTTP request".into()))?;
        let response = response.await.map_err(|mut error| {
            if error.take_message().is_some() { NetError::Connect(error.error().to_string()) }
            else { NetError::Io(error.error().to_string()) }
        })?;
        let status = response.status().as_u16();
        let headers = response.headers().iter().map(|(name, value)| {
            (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned())
        }).collect();
        let limit = usize::try_from(req.max_response_bytes).unwrap_or(usize::MAX);
        let body = http_body_util::Limited::new(response.into_body(), limit).collect().await
            .map_err(|error| if error.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                NetError::TooLarge
            } else { NetError::Io(error.to_string()) })?.to_bytes();
        drop(original);
        Ok(HttpResponse { status, headers, body })
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "authorized_tests.rs"]
mod tests;
