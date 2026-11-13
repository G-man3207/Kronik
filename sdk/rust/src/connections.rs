//! Long-lived connections (M24): WebSocket and SSE.
//!
//! A kind declares `WEBSOCKET` and `SSE` routes ([`Route::websocket`],
//! [`Route::sse`]) and implements [`Actor::connection_open`],
//! [`Actor::connection_frame`] and [`Actor::connection_close`]. Each input
//! of a connection is a turn of the actor that accepted it, and only that
//! actor may send on it or close it ([`Ctx::connections`]).
//!
//! [`Route::websocket`]: crate::Route::websocket
//! [`Route::sse`]: crate::Route::sse
//! [`Actor::connection_open`]: crate::Actor::connection_open
//! [`Actor::connection_frame`]: crate::Actor::connection_frame
//! [`Actor::connection_close`]: crate::Actor::connection_close
//! [`Ctx::connections`]: crate::Ctx::connections

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::bindings::kronik::actor::connections as host;
use crate::{Error, HttpResponse, Output};

pub use host::{
    Accept, CloseInfo, CloseInitiator, Closed, Frame, IncomingFrame, OpenReply, OpenRequest,
    Protocol, SendError, SseEvent,
};

impl Frame {
    /// A text frame; on an SSE stream, an event with only data.
    pub fn text(text: impl Into<String>) -> Frame {
        Frame::Text(text.into())
    }

    /// `value` as JSON in a text frame.
    pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<Frame, Error> {
        serde_json::to_string(value)
            .map(Frame::Text)
            .map_err(|source| Error::Json {
                what: "a frame".into(),
                topic: "connections",
                source,
            })
    }

    /// A binary frame (WebSocket only: sending one on an SSE stream traps).
    pub fn binary(bytes: impl Into<Vec<u8>>) -> Frame {
        Frame::Binary(bytes.into())
    }

    /// An SSE event with an `event` name and an `id` (both may be empty). A
    /// reconnecting EventSource sends the last id back
    /// ([`OpenRequest::last_event_id`]). On a WebSocket, a text frame with
    /// the data.
    pub fn event(
        event: impl Into<String>,
        id: impl Into<String>,
        data: impl Into<String>,
    ) -> Frame {
        Frame::Event(SseEvent {
            event: event.into(),
            id: id.into(),
            data: data.into(),
        })
    }
}

impl OpenRequest {
    /// The first header called `name`, ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.request.header(name)
    }

    /// The route parameter `name`, such as `key`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.request.param(name)
    }

    /// The first query parameter called `name`, decoded.
    pub fn query_param(&self, name: &str) -> Option<String> {
        self.request.query_param(name)
    }

    /// The `Origin` header. A browser sends it, with its cookies, on a
    /// WebSocket handshake: an actor that authenticates by cookie checks it
    /// (see `kronik explain connections`).
    pub fn origin(&self) -> Option<&str> {
        self.header("origin")
    }

    /// The last SSE event id a reconnecting EventSource saw
    /// (`Last-Event-ID`).
    pub fn last_event_id(&self) -> Option<&str> {
        self.header("last-event-id")
    }
}

impl IncomingFrame {
    /// The frame's bytes: a text frame's text as UTF-8.
    pub fn bytes(&self) -> &[u8] {
        match &self.frame {
            Frame::Text(text) => text.as_bytes(),
            Frame::Binary(bytes) => bytes,
            Frame::Event(event) => event.data.as_bytes(),
        }
    }

    /// The frame's text: a binary frame's bytes decoded as UTF-8.
    pub fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(self.bytes()).map_err(|_| Error::Utf8 {
            what: "the frame".into(),
            topic: "connections",
        })
    }

    /// The frame parsed as JSON.
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(self.bytes()).map_err(|source| Error::Json {
            what: "the frame".into(),
            topic: "connections",
            source,
        })
    }
}

impl Accept {
    /// An accept without a subprotocol, extra headers or subject.
    pub fn new() -> Accept {
        Accept {
            subprotocol: None,
            headers: Vec::new(),
            subject: None,
        }
    }

    /// Selects one of the subprotocols the client offered (WebSocket only).
    pub fn with_subprotocol(mut self, subprotocol: impl Into<String>) -> Self {
        self.subprotocol = Some(subprotocol.into());
        self
    }

    /// Adds a response header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(crate::Header {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// The subject of the connection's later inputs (its frames and its
    /// close); by default the request's.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

impl Default for Accept {
    fn default() -> Self {
        Accept::new()
    }
}

impl OpenReply {
    /// Accepts the connection.
    pub fn accept(accept: Accept) -> OpenReply {
        OpenReply::Accept(accept)
    }

    /// Refuses the connection with an HTTP response, such as
    /// `Output::status(403)`: a reply answers 200 with its body, `none` 204.
    pub fn refuse(output: Output) -> OpenReply {
        OpenReply::Refuse(match output {
            Output::Http(response) => response,
            Output::Reply(message) => HttpResponse::new(200)
                .header("content-type", message.content_type)
                .body(message.body),
            Output::None => HttpResponse::new(204),
        })
    }
}

/// The WebSocket and SSE connections this actor accepted: [`Ctx::connections`](crate::Ctx::connections).
///
/// Only the actor whose open accepted a connection may send on it or close
/// it; any other use traps with `CONNECTION_NOT_HELD`. A frame to a closed
/// connection is dropped and shows in the history.
pub struct Connections {
    _private: (),
}

impl Connections {
    pub(crate) fn new() -> Connections {
        Connections { _private: () }
    }

    /// Sends `frame` to `connection` when this turn commits, in call order;
    /// nothing if the turn fails.
    pub fn send(&self, connection: &str, frame: &Frame) {
        host::send(connection, frame);
    }

    /// [`send`](Connections::send) to each of `connections`, recorded once:
    /// the way to fan a message out.
    pub fn broadcast(&self, connections: &[String], frame: &Frame) {
        host::broadcast(connections, frame);
    }

    /// Closes `connection` when this turn commits, after the frames sent
    /// before: a WebSocket with `code` and `reason`, an SSE stream by
    /// ending it. Its close input still follows.
    pub fn close(&self, connection: &str, code: u16, reason: &str) {
        host::close(connection, code, reason);
    }

    /// Sends `frame` now, before this turn commits, for intermediate results
    /// such as the tokens of a streamed answer; use
    /// [`send`](Connections::send) for final notices. An effect with
    /// delivery class `unsafe` that needs the capability
    /// `connection:send-now`.
    ///
    /// `Ok(true)`: handed to the connection (not that the client received
    /// it). `Ok(false)`: the connection is closed or its client does not
    /// keep up. `Err(Error::SendNow(SendError::OutcomeUnknown))`: a crash
    /// made the outcome unknown, and a frame is never sent twice; returned
    /// from the turn, it fails with `EFFECT_OUTCOME_UNKNOWN`. Frames sent now
    /// go out before the turn's buffered frames.
    pub fn send_now(&self, connection: &str, frame: &Frame) -> Result<bool, Error> {
        match host::send_now(connection, frame) {
            Ok(()) => Ok(true),
            Err(SendError::Closed) => Ok(false),
            Err(e) => Err(Error::SendNow(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HttpBody, HttpRequest};

    fn request(headers: &[(&str, &str)]) -> OpenRequest {
        OpenRequest {
            connection: "c-0123".into(),
            protocol: Protocol::Websocket,
            subprotocols: vec!["chat.v1".into()],
            request: HttpRequest {
                method: "GET".into(),
                path: "/chat/lobby/ws".into(),
                query: "user=ada".into(),
                params: vec![("key".into(), "lobby".into())],
                headers: headers
                    .iter()
                    .map(|(name, value)| crate::Header {
                        name: (*name).into(),
                        value: (*value).into(),
                    })
                    .collect(),
                body: HttpBody::Inline(Vec::new()),
            },
        }
    }

    #[test]
    fn frames_and_incoming_frames() {
        assert!(matches!(Frame::text("hi"), Frame::Text(t) if t == "hi"));
        assert!(
            matches!(Frame::json(&serde_json::json!({"n": 1})).unwrap(), Frame::Text(t) if t == r#"{"n":1}"#)
        );
        assert!(matches!(Frame::binary(vec![1, 2]), Frame::Binary(b) if b == [1, 2]));
        assert!(matches!(Frame::event("message", "7", "x"),
            Frame::Event(SseEvent { event, id, data }) if event == "message" && id == "7" && data == "x"));
        let text = IncomingFrame {
            connection: "c-0123".into(),
            seq: 3,
            frame: Frame::text(r#"{"type":"say"}"#),
        };
        assert_eq!(text.text().unwrap(), r#"{"type":"say"}"#);
        let v: serde_json::Value = text.json().unwrap();
        assert_eq!(v["type"], "say");
        let binary = IncomingFrame {
            connection: "c-0123".into(),
            seq: 4,
            frame: Frame::binary(vec![0xff]),
        };
        assert_eq!(binary.bytes(), [0xff]);
        let e = binary.text().unwrap_err().to_string();
        assert!(
            e.contains("the frame is not UTF-8 (see `kronik explain connections`)"),
            "{e}"
        );
        let e = binary.json::<serde_json::Value>().unwrap_err().to_string();
        assert!(e.contains("the frame is not the expected JSON"), "{e}");
    }

    #[test]
    fn the_open_request_and_its_answers() {
        let r = request(&[("Origin", "https://chat.example"), ("Last-Event-ID", "41")]);
        assert_eq!(r.param("key"), Some("lobby"));
        assert_eq!(r.query_param("user").as_deref(), Some("ada"));
        assert_eq!(r.origin(), Some("https://chat.example"));
        assert_eq!(r.last_event_id(), Some("41"));
        assert_eq!(request(&[]).origin(), None);
        let accept = Accept::new()
            .with_subprotocol("chat.v1")
            .with_header("x-room", "lobby")
            .with_subject("user:ada");
        match OpenReply::accept(accept) {
            OpenReply::Accept(a) => {
                assert_eq!(a.subprotocol.as_deref(), Some("chat.v1"));
                assert_eq!(a.headers.len(), 1);
                assert_eq!(a.subject.as_deref(), Some("user:ada"));
            }
            OpenReply::Refuse(_) => panic!("refused"),
        }
        match OpenReply::refuse(Output::status(403)) {
            OpenReply::Refuse(r) => assert_eq!(r.status, 403),
            OpenReply::Accept(_) => panic!("accepted"),
        }
        match OpenReply::refuse(Output::None) {
            OpenReply::Refuse(r) => assert_eq!(r.status, 204),
            OpenReply::Accept(_) => panic!("accepted"),
        }
    }
}
