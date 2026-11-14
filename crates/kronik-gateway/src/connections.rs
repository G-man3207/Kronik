//! The gateway's side of long-lived connections (M24,
//! docs/design/m24-connections.md §5.3, §5.5 to §5.8): the WebSocket
//! transport that the node's hub writes through, and the task that drives
//! one upgraded connection.
//!
//! One task per connection reads and writes. The writer drains the hub's
//! queue in `seq` order whenever the hub wakes it. The reader admits each
//! incoming message as a frame input through the hub, which holds the read
//! back while the connection's in-flight window is full or its inbound
//! rate is spent, so TCP pushes back on a client that sends faster than
//! its owner works; writing goes on meanwhile. Pings keep an idle
//! connection alive. Whoever ends the connection, the hub gets exactly one
//! report of it ([`Hub::finished`]), with the client's close when there was
//! one.
//
// The connection task runs on tokio directly, like the hyper server
// (ADR 0004 §3).
#![allow(clippy::disallowed_methods)]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use hyper_util::rt::TokioIo;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::{Hub, Outgoing, Transport};
use tokio::sync::Notify;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

pub mod sse;

/// How long the upgrade of an accepted connection may take before it is
/// abandoned.
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// The WebSocket transport the hub writes through: it wakes the
/// connection's task, and asks it to close.
#[derive(Default)]
pub struct WsTransport {
    notify: Notify,
    host_close: Mutex<Option<(u16, String)>>,
}

impl Transport for WsTransport {
    fn wake(&self) {
        // A stored permit: a wake while the task is busy is not lost.
        self.notify.notify_one();
    }

    fn close(&self, code: u16, reason: &str) {
        *self.host_close.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((code, reason.to_owned()));
        self.notify.notify_one();
    }
}

impl WsTransport {
    fn take_host_close(&self) -> Option<(u16, String)> {
        self.host_close
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// Settings of one connection's socket (§5.3).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The largest incoming message: the smaller of `[connections]
    /// max_frame_bytes` and the owner kind's `message_bytes`.
    pub max_message: usize,
    pub outbound_queue_bytes: usize,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub close_timeout: Duration,
}

impl Limits {
    fn config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            // tungstenite allocates its 128 KiB default eagerly per
            // connection.
            .read_buffer_size(4096)
            .write_buffer_size(0)
            .max_write_buffer_size(self.outbound_queue_bytes + self.max_message + 4096)
            .max_message_size(Some(self.max_message))
            .max_frame_size(Some(self.max_message))
    }
}

fn to_message(frame: pb::Frame) -> Message {
    let data = match frame.data.and_then(|d| d.value) {
        Some(pb::sealable::Value::Plain(b)) => b,
        // The hub gets the committed record's frames before they are
        // sealed; a sealed one is never expected here.
        _ => Vec::new(),
    };
    match pb::frame::Kind::try_from(frame.kind) {
        Ok(pb::frame::Kind::Binary) => Message::Binary(Bytes::from(data)),
        // An event's data is a text frame on a WebSocket.
        _ => Message::Text(String::from_utf8_lossy(&data).into_owned().into()),
    }
}

fn close_message(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: reason.into(),
    }))
}

/// How a connection's task ended, for the hub.
enum End {
    /// The client closed (with its close frame's code and reason; 1005 for
    /// a close frame without one), or went away (`None`: 1006).
    Client(Option<(u16, String)>),
    /// Kronik sent a close frame (the actor's or the host's): the hub has
    /// its cause.
    Kronik,
}

type Admit = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Drives one upgraded WebSocket connection until it ends, then reports the
/// end to the hub. `io` is the upgraded connection.
pub async fn drive<I>(hub: Arc<Hub>, conn: String, io: I, limits: Limits)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let socket =
        WebSocketStream::from_raw_socket(TokioIo::new(io), Role::Server, Some(limits.config()))
            .await;
    let (mut sink, mut stream) = socket.split();
    let transport = Arc::new(WsTransport::default());
    if hub.attach(&conn, transport.clone()).is_err() {
        // Closed while the client upgraded (a restart, an operator).
        let _ = sink.send(close_message(1001, "")).await;
        return;
    }
    let start = tokio::time::Instant::now();
    let now = || start.elapsed();
    let mut admitting: Option<Admit> = None;
    // Set when Kronik sent its close frame: the client's close, or this
    // deadline, ends the connection.
    let mut closing: Option<Duration> = None;
    let mut last_heard = now();
    let mut ping_sent: Option<Duration> = None;
    let end = 'run: loop {
        let wait = match (closing, ping_sent) {
            (Some(deadline), _) => deadline.saturating_sub(now()),
            (None, Some(sent)) => (sent + limits.ping_timeout).saturating_sub(now()),
            (None, None) => (last_heard + limits.ping_interval).saturating_sub(now()),
        };
        tokio::select! {
            biased;
            () = transport.notify.notified(), if closing.is_none() => {
                if let Some((code, reason)) = transport.take_host_close() {
                    if sink.send(close_message(code, &reason)).await.is_err() {
                        break 'run End::Kronik;
                    }
                    closing = Some(now() + limits.close_timeout);
                    continue;
                }
                while let Some(item) = hub.next(&conn) {
                    match item {
                        Outgoing::Frame { seq, frame } => {
                            if sink.send(to_message(frame)).await.is_err() {
                                break 'run End::Client(None);
                            }
                            hub.written(&conn, seq);
                        }
                        Outgoing::Close { code, reason } => {
                            if sink.send(close_message(code, &reason)).await.is_err() {
                                break 'run End::Kronik;
                            }
                            closing = Some(now() + limits.close_timeout);
                            break;
                        }
                    }
                }
            }
            () = async {
                if let Some(admit) = admitting.as_mut() {
                    admit.await;
                }
            }, if admitting.is_some() => {
                admitting = None;
            }
            message = stream.next(), if admitting.is_none() => {
                last_heard = now();
                ping_sent = None;
                match message {
                    Some(Ok(Message::Text(text))) => {
                        let frame = pb::Frame {
                            kind: pb::frame::Kind::Text as i32,
                            data: Some(pb::Sealable {
                                subject: None,
                                value: Some(pb::sealable::Value::Plain(text.as_bytes().to_vec())),
                            }),
                            ..Default::default()
                        };
                        admitting = Some(admit(hub.clone(), conn.clone(), frame));
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        let frame = pb::Frame {
                            kind: pb::frame::Kind::Binary as i32,
                            data: Some(pb::Sealable {
                                subject: None,
                                value: Some(pb::sealable::Value::Plain(bytes.to_vec())),
                            }),
                            ..Default::default()
                        };
                        admitting = Some(admit(hub.clone(), conn.clone(), frame));
                    }
                    // tungstenite answers pings; a pong marks the peer alive.
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        // tungstenite queued the answering close: send it.
                        let _ = sink.flush().await;
                        if closing.is_some() {
                            break 'run End::Kronik;
                        }
                        let close = frame.map_or((1005, String::new()), |f| {
                            (u16::from(f.code), f.reason.as_str().to_owned())
                        });
                        break 'run End::Client(Some(close));
                    }
                    Some(Err(WsError::Capacity(_))) => {
                        hub.close_host(&conn, pb::CloseCause::TooLarge);
                        if !closing_after_error(&transport, &mut sink, &mut closing, now(), &limits).await {
                            break 'run End::Kronik;
                        }
                    }
                    Some(Err(WsError::Protocol(_) | WsError::Utf8(_) | WsError::AttackAttempt)) => {
                        hub.close_host(&conn, pb::CloseCause::Protocol);
                        if !closing_after_error(&transport, &mut sink, &mut closing, now(), &limits).await {
                            break 'run End::Kronik;
                        }
                    }
                    Some(Err(_)) | None => {
                        if closing.is_some() {
                            break 'run End::Kronik;
                        }
                        break 'run End::Client(None);
                    }
                }
            }
            () = tokio::time::sleep(wait) => {
                if closing.is_some() {
                    // The client did not answer the close in time.
                    break 'run End::Kronik;
                }
                match ping_sent {
                    Some(_) => hub.close_host(&conn, pb::CloseCause::PingTimeout),
                    None => {
                        if sink.send(Message::Ping(Bytes::new())).await.is_err() {
                            break 'run End::Client(None);
                        }
                        ping_sent = Some(now());
                    }
                }
            }
        }
    };
    drop(admitting);
    let _ = sink.close().await;
    match end {
        End::Client(close) => hub.finished(&conn, close),
        End::Kronik => hub.finished(&conn, None),
    }
}

/// The frame input of an incoming message, admitted through the hub (which
/// waits for an in-flight permit and the inbound rate).
fn admit(hub: Arc<Hub>, conn: String, frame: pb::Frame) -> Admit {
    Box::pin(async move { hub.incoming(&conn, frame).await })
}

/// After a read error the hub decided a host close: send its close frame
/// now. `false` when that is impossible (the socket is unusable).
async fn closing_after_error<S>(
    transport: &WsTransport,
    sink: &mut S,
    closing: &mut Option<Duration>,
    now: Duration,
    limits: &Limits,
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    let Some((code, reason)) = transport.take_host_close() else {
        return false;
    };
    if sink.send(close_message(code, &reason)).await.is_err() {
        return false;
    }
    *closing = Some(now + limits.close_timeout);
    true
}
