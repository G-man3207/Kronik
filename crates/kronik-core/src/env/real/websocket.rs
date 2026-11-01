//! Bounded outbound WebSockets using the owning RealNet's TLS configuration.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::{Error, Message};

use crate::env::{BoxFuture, NetError, WebSocket, WebSocketRequest};

pub(super) fn connect(
    tls: Result<Arc<rustls::ClientConfig>, String>,
    req: WebSocketRequest,
) -> BoxFuture<'static, Result<Arc<dyn WebSocket>, NetError>> {
    Box::pin(async move {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

        let invalid = || NetError::Connect("invalid WebSocket request".into());
        if req.max_message_bytes == 0 {
            return Err(invalid());
        }
        let write_limit = req
            .max_message_bytes
            .checked_add(1024)
            .ok_or_else(invalid)?;
        let mut request = req.url.into_client_request().map_err(|_| invalid())?;
        let host = request
            .uri()
            .host()
            .ok_or_else(invalid)?
            .trim_matches(['[', ']'])
            .to_owned();
        let scheme = request.uri().scheme_str().ok_or_else(invalid)?;
        let port = request
            .uri()
            .port_u16()
            .unwrap_or(if scheme == "wss" { 443 } else { 80 });
        let encrypted = match scheme {
            "wss" => true,
            "ws" if host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()) =>
            {
                false
            }
            _ => return Err(invalid()),
        };
        for (name, value) in req.headers {
            let name = tokio_tungstenite::tungstenite::http::HeaderName::try_from(name)
                .map_err(|_| invalid())?;
            if matches!(name.as_str(), "host" | "connection" | "upgrade")
                || name.as_str().starts_with("sec-websocket-")
            {
                return Err(invalid());
            }
            let value = value.parse().map_err(|_| invalid())?;
            request.headers_mut().append(name, value);
        }
        let socket = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;
        let stream: Box<dyn WebSocketIo> = if encrypted {
            let name = rustls::pki_types::ServerName::try_from(host).map_err(|_| invalid())?;
            Box::new(
                tokio_rustls::TlsConnector::from(tls.map_err(NetError::Connect)?)
                    .connect(name, socket)
                    .await
                    .map_err(|e| NetError::Connect(e.to_string()))?,
            )
        } else {
            Box::new(socket)
        };
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .read_buffer_size(req.max_message_bytes.min(128 * 1024))
            .write_buffer_size(0)
            .max_write_buffer_size(write_limit)
            .max_message_size(Some(req.max_message_bytes))
            .max_frame_size(Some(req.max_message_bytes));
        let (stream, _) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                .await
                .map_err(websocket_error)?;
        let (send, recv) = stream.split();
        Ok(Arc::new(RealWebSocket {
            send: Arc::new(tokio::sync::Mutex::new(send)),
            recv: Arc::new(tokio::sync::Mutex::new(Some(recv))),
            max_message_bytes: req.max_message_bytes,
        }) as Arc<dyn WebSocket>)
    })
}

trait WebSocketIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> WebSocketIo for T {}

type WebSocketStream = tokio_tungstenite::WebSocketStream<Box<dyn WebSocketIo>>;

struct RealWebSocket {
    send: Arc<tokio::sync::Mutex<futures_util::stream::SplitSink<WebSocketStream, Message>>>,
    recv: Arc<tokio::sync::Mutex<Option<futures_util::stream::SplitStream<WebSocketStream>>>>,
    max_message_bytes: usize,
}

fn websocket_error(error: Error) -> NetError {
    match error {
        Error::Capacity(_) => NetError::TooLarge,
        error => NetError::Io(error.to_string()),
    }
}

impl WebSocket for RealWebSocket {
    fn recv(&self) -> BoxFuture<'static, Result<Option<Bytes>, NetError>> {
        let recv = self.recv.clone();
        Box::pin(async move {
            let mut recv = recv.lock().await;
            loop {
                let Some(stream) = recv.as_mut() else {
                    return Ok(None);
                };
                match stream.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes)),
                    Some(Ok(Message::Text(text))) => return Ok(Some(text.into())),
                    Some(Ok(Message::Close(_)))
                    | None
                    | Some(Err(Error::ConnectionClosed | Error::AlreadyClosed)) => {
                        *recv = None;
                        return Ok(None);
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(error)) => return Err(websocket_error(error)),
                }
            }
        })
    }

    fn send(&self, message: Bytes) -> BoxFuture<'static, Result<(), NetError>> {
        if message.len() > self.max_message_bytes {
            return Box::pin(async { Err(NetError::TooLarge) });
        }
        let send = self.send.clone();
        Box::pin(async move {
            send.lock()
                .await
                .send(Message::Binary(message))
                .await
                .map_err(websocket_error)
        })
    }

    fn close(&self) -> BoxFuture<'static, Result<(), NetError>> {
        let send = self.send.clone();
        Box::pin(async move {
            match send.lock().await.close().await {
                Ok(()) | Err(Error::ConnectionClosed | Error::AlreadyClosed) => Ok(()),
                Err(error) => Err(websocket_error(error)),
            }
        })
    }
}
