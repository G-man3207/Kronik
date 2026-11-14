//! SSE connections (M24, docs/design/m24-connections.md §5.4): the event
//! encoder and the driver that streams one connection's queued frames as
//! the body of its `200 text/event-stream` response.
//!
//! The driver sends encoded chunks into a channel that the response body
//! reads. A frame counts as written when hyper has taken it from the
//! channel, which the driver learns when it gets room for the next chunk.
//! The stream ends after the actor's close, or at once on a host close (a
//! graceful stop sends `retry: 5000` first, so browsers reconnect in 5 s);
//! a client that goes away drops the body, which the driver notices and
//! reports as the client's close. SSE has no incoming frames.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_proto::log::v1 as pb;
use kronik_sched::connections::{Hub, Outgoing, RESTART_CODE, Transport};
use tokio::sync::{Notify, mpsc};

/// The comment an idle stream gets every `sse_heartbeat`.
pub const HEARTBEAT: &[u8] = b": keep-alive\n\n";

/// What a graceful stop tells browsers before the stream ends: reconnect in
/// 5 s.
pub const RETRY_AFTER_RESTART: &[u8] = b"retry: 5000\n\n";

/// One SSE event of a frame: `id:` and `event:` when not empty, then one
/// `data:` line per line of the data (CRLF and CR become LF), then an empty
/// line. A text frame is an event with only data. An `event` or `id` holds
/// no line break (the runtime refuses one); any that slipped in would end
/// the field, so it becomes a space.
pub fn encode(frame: &pb::Frame) -> Vec<u8> {
    let data = match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    };
    let one_line = |s: &str| s.replace(['\r', '\n', '\0'], " ");
    let mut out = String::with_capacity(data.len() + 32);
    if frame.kind == pb::frame::Kind::Event as i32 {
        if !frame.id.is_empty() {
            out.push_str("id: ");
            out.push_str(&one_line(&frame.id));
            out.push('\n');
        }
        if !frame.event.is_empty() {
            out.push_str("event: ");
            out.push_str(&one_line(&frame.event));
            out.push('\n');
        }
    }
    let data = data.replace("\r\n", "\n").replace('\r', "\n");
    for line in data.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out.into_bytes()
}

/// The SSE transport the hub writes through.
#[derive(Default)]
pub struct SseTransport {
    notify: Notify,
    host_close: Mutex<Option<u16>>,
}

impl Transport for SseTransport {
    fn wake(&self) {
        self.notify.notify_one();
    }

    fn close(&self, code: u16, _reason: &str) {
        *self.host_close.lock().unwrap_or_else(|e| e.into_inner()) = Some(code);
        self.notify.notify_one();
    }
}

/// Streams connection `conn` into `out` until it ends, then reports the
/// end to the hub.
pub async fn drive(hub: Arc<Hub>, conn: String, out: mpsc::Sender<Vec<u8>>, heartbeat: Duration) {
    let transport = Arc::new(SseTransport::default());
    if hub.attach(&conn, transport.clone()).is_err() {
        return;
    }
    // The frame hyper may not have taken yet.
    let mut unconfirmed: Option<u64> = None;
    'run: loop {
        let host_close = transport
            .host_close
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(code) = host_close {
            if code == RESTART_CODE {
                let _ = out.send(RETRY_AFTER_RESTART.to_vec()).await;
            }
            break 'run;
        }
        match hub.next(&conn) {
            Some(Outgoing::Frame { seq, frame }) => {
                let Ok(permit) = out.reserve().await else {
                    break 'run;
                };
                if let Some(prev) = unconfirmed.take() {
                    hub.written(&conn, prev);
                }
                permit.send(encode(&frame));
                unconfirmed = Some(seq);
            }
            Some(Outgoing::Close { .. }) => {
                // The actor's close: the stream ends after its frames.
                if out.reserve().await.is_err() {
                    break 'run;
                }
                if let Some(prev) = unconfirmed.take() {
                    hub.written(&conn, prev);
                }
                break 'run;
            }
            None => {
                tokio::select! {
                    biased;
                    () = out.closed() => break 'run,
                    () = transport.notify.notified() => {}
                    () = tokio::time::sleep(heartbeat) => {
                        if out.send(HEARTBEAT.to_vec()).await.is_err() {
                            break 'run;
                        }
                        // Hyper took the chunk before the heartbeat.
                        if let Some(prev) = unconfirmed.take() {
                            hub.written(&conn, prev);
                        }
                    }
                }
            }
        }
    }
    drop(out);
    // The hub has the actor's or the host's cause; without one the client
    // left: 1006, as SSE always records a client's end (§4.8).
    hub.finished(&conn, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: pb::frame::Kind, data: &str, event: &str, id: &str) -> pb::Frame {
        pb::Frame {
            kind: kind as i32,
            data: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(data.as_bytes().to_vec())),
            }),
            event: event.into(),
            id: id.into(),
        }
    }

    #[test]
    fn events_are_encoded_line_by_line() {
        let e = encode(&frame(pb::frame::Kind::Event, "{\"a\":1}", "message", "7"));
        assert_eq!(e, b"id: 7\nevent: message\ndata: {\"a\":1}\n\n");
        let e = encode(&frame(pb::frame::Kind::Event, "a\r\nb\rc\nd", "", ""));
        assert_eq!(e, b"data: a\ndata: b\ndata: c\ndata: d\n\n");
        // A text frame is an event with only data; empty data is one line.
        let e = encode(&frame(pb::frame::Kind::Text, "hi", "ignored", "9"));
        assert_eq!(e, b"data: hi\n\n");
        let e = encode(&frame(pb::frame::Kind::Text, "", "", ""));
        assert_eq!(e, b"data: \n\n");
        // A line break in a field cannot end it early.
        let e = encode(&frame(pb::frame::Kind::Event, "x", "a\nb", "1\r2"));
        assert_eq!(e, b"id: 1 2\nevent: a b\ndata: x\n\n");
    }
}
