//! HTTP/1 admission at Hyper's actual synchronous dispatch queue.
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::{Body, Frame, SizeHint};
use hyper::rt::Executor as _;
use tower_service::Service as _;

use super::Connector;
use crate::authority::AuthLease;
use crate::env::{
    BodySource, BoxFuture, HttpBody, HttpRequest, HttpResponse, HttpStreamRequest,
    HttpStreamResponse, NetError,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(super) fn send(
    connector: Result<Connector, String>,
    req: HttpRequest,
    original: AuthLease,
) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
    Box::pin(async move {
        let limit = usize::try_from(req.max_response_bytes).unwrap_or(usize::MAX);
        let response = exchange(
            connector,
            &req.method,
            &req.url,
            &req.headers,
            http_body_util::Full::new(req.body),
            &original,
        )
        .await?;
        let (status, headers) = head(&response);
        let body = http_body_util::Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|error| {
                if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    NetError::TooLarge
                } else {
                    NetError::Io(error.to_string())
                }
            })?
            .to_bytes();
        drop(original);
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    })
}

/// [`send`] with a request body that may be streamed and a response body
/// given as it arrives (M25). The original authority stays owned by the
/// response body until its end, as `send` keeps it through the body's EOF.
pub(super) fn send_stream(
    connector: Result<Connector, String>,
    req: HttpStreamRequest,
    original: AuthLease,
) -> BoxFuture<'static, Result<HttpStreamResponse, NetError>> {
    Box::pin(async move {
        let body = match req.body {
            HttpBody::Bytes(bytes) => http_body_util::Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync(),
            HttpBody::Stream { len, source } => SourceBody {
                len,
                sent: 0,
                source: Some(source),
                pull: None,
            }
            .boxed_unsync(),
        };
        let response = exchange(
            connector,
            &req.method,
            &req.url,
            &req.headers,
            body,
            &original,
        )
        .await?;
        let (status, headers) = head(&response);
        Ok(HttpStreamResponse {
            status,
            headers,
            body: Box::new(IncomingSource {
                body: response.into_body(),
                limit: req.max_response_bytes,
                read: 0,
                original: Some(original),
            }),
        })
    })
}

fn head(response: &hyper::Response<hyper::body::Incoming>) -> (u16, Vec<(String, String)>) {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    (status, headers)
}

/// Connects, waits for capacity and enqueues the request under the final
/// admission of `original`; returns the response head with its body.
async fn exchange<B>(
    connector: Result<Connector, String>,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: B,
    original: &AuthLease,
) -> Result<hyper::Response<hyper::body::Incoming>, NetError>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let denied = |error: crate::error::ApiError| NetError::Connect(error.to_string());
    original.check().map_err(denied)?;
    let uri: hyper::Uri = url
        .parse()
        .map_err(|error| NetError::Connect(format!("invalid request URI: {error}")))?;
    uri.scheme_str()
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .ok_or_else(|| NetError::Connect("request URI needs http or https".into()))?;
    let destination = uri
        .authority()
        .ok_or_else(|| NetError::Connect("request URI needs an authority".into()))?;
    let mut builder = hyper::Request::builder().method(method);
    builder = if method == "CONNECT" {
        builder.uri(destination.as_str())
    } else {
        builder.uri(uri.path_and_query().map_or("/", |path| path.as_str()))
    };
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        builder = builder.header(hyper::header::HOST, destination.as_str());
    }
    let request = builder
        .body(body)
        .map_err(|error| NetError::Connect(format!("invalid request: {error}")))?;
    let mut connector = connector.map_err(NetError::Connect)?;
    let connect = async {
        std::future::poll_fn(|cx| connector.poll_ready(cx))
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        let stream = connector
            .call(uri)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(64 * 1024)
            .handshake::<_, B>(stream)
            .await
            .map_err(|error| NetError::Connect(error.to_string()))?;
        hyper_util::rt::TokioExecutor::new().execute(async move {
            let _ = connection.await;
        });
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
    original
        .admit(&mut || {
            let request = pending.take().ok_or_else(|| {
                crate::error::ApiError::new(
                    crate::error::ErrorCode::Internal,
                    "HTTP request admitted twice",
                )
            })?;
            response = Some(sender.try_send_request(request));
            Ok(())
        })
        .map_err(denied)?;
    let response = response
        .ok_or_else(|| NetError::Connect("authority did not enqueue the HTTP request".into()))?;
    response.await.map_err(|mut error| {
        if error.take_message().is_some() {
            NetError::Connect(error.error().to_string())
        } else {
            NetError::Io(error.error().to_string())
        }
    })
}

type Pull =
    Pin<Box<dyn Future<Output = (Box<dyn BodySource>, std::io::Result<Option<Bytes>>)> + Send>>;

/// A request body of exactly `len` bytes, pulled from a [`BodySource`] one
/// chunk at a time as hyper writes it.
struct SourceBody {
    len: u64,
    sent: u64,
    source: Option<Box<dyn BodySource>>,
    pull: Option<Pull>,
}

impl Body for SourceBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        if this.pull.is_none() {
            let Some(mut source) = this.source.take() else {
                return Poll::Ready(None);
            };
            this.pull = Some(Box::pin(async move {
                let next = source.next().await;
                (source, next)
            }));
        }
        let Some(pull) = this.pull.as_mut() else {
            return Poll::Ready(None);
        };
        let (source, next) = ready!(pull.as_mut().poll(cx));
        this.pull = None;
        match next {
            Ok(Some(chunk)) => {
                this.sent = this.sent.saturating_add(chunk.len() as u64);
                if this.sent > this.len {
                    return Poll::Ready(Some(Err(
                        "the request body is longer than its length".into()
                    )));
                }
                this.source = Some(source);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Ok(None) if this.sent == this.len => Poll::Ready(None),
            Ok(None) => Poll::Ready(Some(Err("the request body ended before its length".into()))),
            Err(error) => Poll::Ready(Some(Err(Box::new(error)))),
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}

/// A response body read frame by frame, at most `limit` bytes; it owns the
/// request's original authority until the body's end.
struct IncomingSource {
    body: hyper::body::Incoming,
    limit: u64,
    read: u64,
    original: Option<AuthLease>,
}

impl BodySource for IncomingSource {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>> {
        Box::pin(async move {
            loop {
                match self.body.frame().await {
                    None => {
                        self.original = None;
                        return Ok(None);
                    }
                    Some(Err(error)) => return Err(std::io::Error::other(error)),
                    Some(Ok(frame)) => {
                        // Trailers carry no body bytes.
                        if let Ok(data) = frame.into_data() {
                            self.read = self.read.saturating_add(data.len() as u64);
                            if self.read > self.limit {
                                return Err(crate::env::response_too_large());
                            }
                            return Ok(Some(data));
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "authorized_tests.rs"]
mod tests;
