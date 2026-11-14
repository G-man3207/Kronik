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
//! connection alive.
//!
//! No write waits for ever on a client that stops reading: a frame or a
//! ping it does not take within `ping_timeout` closes the connection as a
//! slow consumer (or a ping timeout), and a close frame, the flush after
//! the client's close and the final close get `close_timeout`. Then the
//! socket is dropped. Whoever ends the connection, and however the task
//! ends, the hub gets exactly one report of it ([`Hub::finished`], through
//! a [`FinishGuard`]), with the client's close when there was one.
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
use kronik_sched::connections::{FinishGuard, Hub, Outgoing, Transport};
use tokio::sync::Notify;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

pub mod sse;

/// How long the upgrade of an accepted connection may take before it is
/// abandoned.
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most frames the writer sends per wakeup before it lets the reader,
/// the timer and the closes have their turn (review M4).
const WRITE_BATCH: usize = 64;

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

    fn host_close_pending(&self) -> bool {
        self.host_close
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
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

fn to_message(frame: &pb::Frame) -> Message {
    let data: &[u8] = match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b,
        // The hub gets the committed record's frames before they are
        // sealed; a sealed one is never expected here.
        _ => &[],
    };
    match pb::frame::Kind::try_from(frame.kind) {
        Ok(pb::frame::Kind::Binary) => Message::Binary(Bytes::copy_from_slice(data)),
        // An event's data is a text frame on a WebSocket.
        _ => Message::Text(String::from_utf8_lossy(data).into_owned().into()),
    }
}

fn close_message(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code: CloseCode::from(code),
        reason: reason.into(),
    }))
}

/// Why a write did not complete.
enum WriteError {
    /// The socket failed: the client is gone.
    Gone,
    /// The client took nothing for the write's deadline.
    Stalled,
}

/// Sends `m`, waiting at most `limit` for the client to take it.
async fn send<S>(sink: &mut S, m: Message, limit: Duration) -> Result<(), WriteError>
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    match tokio::time::timeout(limit, sink.send(m)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(WriteError::Gone),
        Err(_) => Err(WriteError::Stalled),
    }
}

type Admit = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What woke the connection's task.
enum Event {
    /// A frame's admission finished: reading goes on.
    Admitted,
    /// The client sent something, or the stream ended.
    Read(Option<Result<Message, WsError>>),
    /// The hub queued frames or decided a close.
    Write,
    /// The ping or close timer.
    Tick,
}

/// Waits for the pending admission, if there is one.
async fn admitted(admitting: &mut Option<Admit>) {
    if let Some(admit) = admitting.as_mut() {
        admit.await;
    }
}

/// Drives one upgraded WebSocket connection until it ends, then reports the
/// end to the hub. `io` is the upgraded connection.
pub async fn drive<I>(hub: Arc<Hub>, conn: String, io: I, limits: Limits)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    // Reports the end however this task ends (a dropped task included).
    let mut finish = FinishGuard::new(hub.clone(), conn.clone());
    let socket =
        WebSocketStream::from_raw_socket(TokioIo::new(io), Role::Server, Some(limits.config()))
            .await;
    let (mut sink, mut stream) = socket.split();
    let transport = Arc::new(WsTransport::default());
    if hub.attach(&conn, transport.clone()).is_err() {
        // Closed while the client upgraded (a restart, an operator).
        let _ = send(&mut sink, close_message(1001, ""), limits.close_timeout).await;
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
    // Reading and writing take turns: each wait is one of two `biased`
    // selects (ADR 0004 §3) whose order flips every round, and the writer
    // sends at most a batch per round (review M4). The close deadline is
    // checked before every wait, so a client that floods cannot outrun it.
    let mut read_first = true;
    'run: loop {
        if closing.is_some_and(|deadline| now() >= deadline) {
            // The client did not answer the close in time.
            break 'run;
        }
        let wait = match (closing, ping_sent) {
            (Some(deadline), _) => deadline.saturating_sub(now()),
            (None, Some(sent)) => (sent + limits.ping_timeout).saturating_sub(now()),
            (None, None) => (last_heard + limits.ping_interval).saturating_sub(now()),
        };
        let event = if read_first {
            tokio::select! {
                biased;
                () = admitted(&mut admitting), if admitting.is_some() => Event::Admitted,
                message = stream.next(), if admitting.is_none() => Event::Read(message),
                () = transport.notify.notified(), if closing.is_none() => Event::Write,
                () = tokio::time::sleep(wait) => Event::Tick,
            }
        } else {
            tokio::select! {
                biased;
                () = transport.notify.notified(), if closing.is_none() => Event::Write,
                () = admitted(&mut admitting), if admitting.is_some() => Event::Admitted,
                message = stream.next(), if admitting.is_none() => Event::Read(message),
                () = tokio::time::sleep(wait) => Event::Tick,
            }
        };
        read_first = !read_first;
        match event {
            Event::Admitted => admitting = None,
            Event::Read(message) => {
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
                        let _ = tokio::time::timeout(limits.close_timeout, sink.flush()).await;
                        if closing.is_none() {
                            finish.client_closed(Some(frame.map_or((1005, String::new()), |f| {
                                (u16::from(f.code), f.reason.as_str().to_owned())
                            })));
                        }
                        break 'run;
                    }
                    Some(Err(WsError::Capacity(_))) => {
                        hub.close_host(&conn, pb::CloseCause::TooLarge);
                        if !closing_after_error(&transport, &mut sink, &mut closing, now(), &limits)
                            .await
                        {
                            break 'run;
                        }
                    }
                    // Gone without a close frame: a client close (1006).
                    Some(Err(WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake))) => {
                        break 'run;
                    }
                    // Invalid UTF-8 in a text message closes with 1007,
                    // other protocol errors with 1002 (§5.5).
                    Some(Err(WsError::Utf8(_))) => {
                        hub.close_host_with(&conn, pb::CloseCause::Protocol, 1007);
                        if !closing_after_error(&transport, &mut sink, &mut closing, now(), &limits)
                            .await
                        {
                            break 'run;
                        }
                    }
                    Some(Err(WsError::Protocol(_) | WsError::AttackAttempt)) => {
                        hub.close_host(&conn, pb::CloseCause::Protocol);
                        if !closing_after_error(&transport, &mut sink, &mut closing, now(), &limits)
                            .await
                        {
                            break 'run;
                        }
                    }
                    // Gone without a close frame (1006), unless Kronik
                    // closed first.
                    Some(Err(_)) | None => break 'run,
                }
            }
            Event::Write => {
                if let Some((code, reason)) = transport.take_host_close() {
                    if send(
                        &mut sink,
                        close_message(code, &reason),
                        limits.close_timeout,
                    )
                    .await
                    .is_err()
                    {
                        break 'run;
                    }
                    closing = Some(now() + limits.close_timeout);
                    continue;
                }
                let mut batch = 0;
                while let Some(item) = hub.next(&conn) {
                    batch += 1;
                    match item {
                        Outgoing::Frame { seq, frame } => {
                            match send(&mut sink, to_message(&frame), limits.ping_timeout).await {
                                Ok(()) => hub.written(&conn, seq),
                                // A client that takes no frame for the ping
                                // timeout cannot keep up: no close frame
                                // could reach it either (review S1).
                                Err(WriteError::Stalled) => {
                                    hub.close_host(&conn, pb::CloseCause::SlowConsumer);
                                    break 'run;
                                }
                                Err(WriteError::Gone) => break 'run,
                            }
                        }
                        Outgoing::Close { code, reason } => {
                            if send(
                                &mut sink,
                                close_message(code, &reason),
                                limits.close_timeout,
                            )
                            .await
                            .is_err()
                            {
                                break 'run;
                            }
                            closing = Some(now() + limits.close_timeout);
                            break;
                        }
                    }
                    // A host close decided meanwhile (it dropped the queue),
                    // or a full batch: the rest after the other branches.
                    if transport.host_close_pending() || batch >= WRITE_BATCH {
                        transport.notify.notify_one();
                        break;
                    }
                }
            }
            Event::Tick => {
                if closing.is_some() {
                    // The client did not answer the close in time.
                    break 'run;
                }
                if admitting.is_some() {
                    // Kronik paused reading (the in-flight window, the
                    // rate): the client's pongs wait unread, so its silence
                    // proves nothing (review M3).
                    last_heard = now();
                    ping_sent = None;
                    continue;
                }
                match ping_sent {
                    Some(_) => hub.close_host(&conn, pb::CloseCause::PingTimeout),
                    None => match send(&mut sink, Message::Ping(Bytes::new()), limits.ping_timeout)
                        .await
                    {
                        Ok(()) => ping_sent = Some(now()),
                        Err(WriteError::Stalled) => {
                            hub.close_host(&conn, pb::CloseCause::PingTimeout);
                            break 'run;
                        }
                        Err(WriteError::Gone) => break 'run,
                    },
                }
            }
        }
    }
    drop(admitting);
    let _ = tokio::time::timeout(limits.close_timeout, sink.close()).await;
    // `finish` reports the end now: the hub has the actor's or the host's
    // cause if one was decided, else the client's close (1006 without one).
    drop(finish);
}

/// The frame input of an incoming message, admitted through the hub (which
/// waits for an in-flight permit and the inbound rate).
fn admit(hub: Arc<Hub>, conn: String, frame: pb::Frame) -> Admit {
    Box::pin(async move { hub.incoming(&conn, frame).await })
}

/// After a read error the hub decided a host close: send its close frame
/// now, within `close_timeout`. `false` when that is impossible (the
/// socket is unusable, or the client takes nothing).
async fn closing_after_error<S>(
    transport: &WsTransport,
    sink: &mut S,
    closing: &mut Option<Duration>,
    now: Duration,
    limits: &Limits,
) -> bool
where
    S: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    let Some((code, reason)) = transport.take_host_close() else {
        return false;
    };
    if send(sink, close_message(code, &reason), limits.close_timeout)
        .await
        .is_err()
    {
        return false;
    }
    *closing = Some(now + limits.close_timeout);
    true
}
