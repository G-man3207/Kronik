//! Long-lived connections in a test host (M24, docs/design/m24-connections.md
//! §15): the test plays the client. A connection the test opens gets a
//! [`RecordingTransport`], which takes every frame its actor sends as soon as
//! it is queued, and records the close. The test's frames and closes go
//! through the hub as a socket's would, and the host settles before it
//! answers, so by then the frames that their turns sent are recorded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use kronik_gateway::{HttpRequest, OpenAnswer};
use kronik_proto::connection as conn;
use kronik_proto::log::v1 as pb;
use kronik_sched::connections::RecordingTransport;

use crate::{Error, TestHost};

/// A connection the test opened.
struct Opened {
    transport: Arc<RecordingTransport>,
    /// How many recorded frames `frames_sent` has cleared.
    cleared: usize,
}

/// The connections a test opened, by id.
#[derive(Default)]
pub(crate) struct Connections(Mutex<HashMap<String, Opened>>);

impl Connections {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Opened>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How a test ends a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseBy {
    /// The client's close frame, with its code and reason.
    Client { code: u16, reason: String },
    /// The client goes away without a close frame: the actor's close
    /// handler gets 1006.
    Gone,
    /// The host closes it for a cause such as `restart` or `slow-consumer`.
    Host(pb::CloseCause),
}

impl CloseBy {
    /// A close as the protocol names it: the initiator `client` with a code
    /// (1006: gone without a close frame) and a reason, or `host` with a
    /// cause (`restart`, `ping-timeout`, `too-large`, `slow-consumer`,
    /// `protocol`, `operator`, `unavailable`).
    pub fn parse(
        initiator: &str,
        code: Option<u16>,
        reason: String,
        cause: Option<&str>,
    ) -> Result<CloseBy, String> {
        match initiator {
            "client" => {
                if cause.is_some() {
                    return Err("a client's close has a code, not a cause".into());
                }
                match code.unwrap_or(1000) {
                    1006 if reason.is_empty() => Ok(CloseBy::Gone),
                    1006 => {
                        Err("1006 means gone without a close frame, which has no reason".into())
                    }
                    code if sendable(code) => Ok(CloseBy::Client { code, reason }),
                    code => Err(format!(
                        "a client cannot send the close code {code}: use 1000 to 1003, 1007 to 1011 or 3000 to 4999, or 1006 for a client that goes away without a close frame"
                    )),
                }
            }
            "host" => {
                if code.is_some() || !reason.is_empty() {
                    return Err("a host's close has a cause, not a code or a reason".into());
                }
                let cause = cause.ok_or("a host's close needs a cause, such as restart")?;
                host_cause(cause).map(CloseBy::Host).ok_or_else(|| {
                    format!(
                        "unknown cause {cause:?}: use restart, ping-timeout, too-large, slow-consumer, protocol, operator or unavailable"
                    )
                })
            }
            other => Err(format!(
                "unknown initiator {other:?}: use client or host (the actor closes with connections.close)"
            )),
        }
    }
}

/// A close code that a client may send in a close frame (RFC 6455 §7.4).
fn sendable(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1011 | 3000..=4999)
}

/// A host cause the test may inject.
fn host_cause(name: &str) -> Option<pb::CloseCause> {
    use pb::CloseCause::*;
    [
        Restart,
        PingTimeout,
        TooLarge,
        SlowConsumer,
        Protocol,
        Operator,
        Unavailable,
    ]
    .into_iter()
    .find(|c| conn::cause_name(*c as i32) == name)
}

/// The handshake headers that a test need not write: a WebSocket
/// upgrade's (with a valid key), or an event stream's `accept`. A header the
/// test gives wins, so a test can also send a bad handshake.
fn with_handshake(
    protocol: &str,
    mut headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, Error> {
    let defaults: &[(&str, &str)] = match protocol {
        "websocket" => &[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-version", "13"),
            // RFC 6455's example key: any 16 bytes in base64 will do.
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
        "sse" => &[("accept", "text/event-stream")],
        other => {
            return Err(Error(format!(
                "unknown protocol {other:?}: use websocket or sse"
            )));
        }
    };
    for (name, value) in defaults {
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            headers.push(((*name).to_owned(), (*value).to_owned()));
        }
    }
    Ok(headers)
}

/// What an actor sent on a connection.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sent {
    /// The frames, with their outgoing seqs, oldest first.
    pub frames: Vec<(u64, pb::Frame)>,
    /// The close the connection got, the actor's or the host's: its code and
    /// reason.
    pub closed: Option<(u16, String)>,
}

impl TestHost {
    /// Opens a WebSocket (`websocket`) or an event stream (`sse`) at `path`,
    /// with its query, through the gateway as a client would. When the
    /// actor accepts, a recording transport takes what it sends. Answers
    /// once the open turn, and what it started, have finished.
    pub async fn open_connection(
        &self,
        path: &str,
        headers: Vec<(String, String)>,
        protocol: &str,
    ) -> Result<OpenAnswer, Error> {
        let headers = with_handshake(protocol, headers)?;
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let answer = self
            .gateway
            .open_connection(HttpRequest {
                method: "GET".into(),
                path: path.into(),
                query: query.into(),
                headers,
                body: Vec::new(),
                peer: None,
            })
            .await;
        if let Some(conn) = &answer.connection
            && let Err(e) = self.attach(conn)
        {
            self.node.hub().abandon(conn);
            return Err(e);
        }
        self.settle().await?;
        Ok(answer)
    }

    /// Records what the actor sends on `conn`, a connection it accepted.
    pub(crate) fn attach(&self, conn: &str) -> Result<(), Error> {
        let transport = RecordingTransport::attach(self.node.hub(), conn)
            .map_err(|e| Error::new("attaching the connection", e))?;
        self.connections.lock().insert(
            conn.to_owned(),
            Opened {
                transport,
                cleared: 0,
            },
        );
        Ok(())
    }

    /// The transport of `conn`, if it is still open.
    fn open_transport(&self, conn: &str) -> Result<Arc<RecordingTransport>, Error> {
        let transport = self
            .connections
            .lock()
            .get(conn)
            .map(|o| o.transport.clone())
            .ok_or_else(|| {
                Error(format!(
                    "connection {conn} was not opened in this test host"
                ))
            })?;
        let gone = self.node.hub().queued_bytes(conn).is_none();
        match transport.recording().closed {
            Some((code, reason)) => Err(Error(format!(
                "connection {conn} is closed ({code} {reason:?})"
            ))),
            None if gone => Err(Error(format!("connection {conn} is closed"))),
            None => Ok(transport),
        }
    }

    /// A frame from the client on `conn`, admitted as its socket's reader
    /// would admit it. Answers once the frame's turn and what it started
    /// have finished.
    pub async fn send_frame(&self, conn: &str, frame: pb::Frame) -> Result<(), Error> {
        self.open_transport(conn)?;
        self.node.hub().incoming(conn, frame).await;
        self.settle().await
    }

    /// Ends `conn` as `by` says. Answers once the close turn and what it
    /// started have finished.
    pub async fn close_connection(&self, conn: &str, by: CloseBy) -> Result<(), Error> {
        let transport = self.open_transport(conn)?;
        match by {
            CloseBy::Client { code, reason } => transport.client_close(Some((code, reason))),
            CloseBy::Gone => transport.client_close(None),
            CloseBy::Host(cause) => self.node.hub().close_host(conn, cause),
        }
        self.settle().await
    }

    /// What the actor sent on `conn` since the last `clear`, and its close.
    /// With `clear`, the frames returned are not returned again.
    pub fn frames_sent(&self, conn: &str, clear: bool) -> Result<Sent, Error> {
        let mut conns = self.connections.lock();
        let opened = conns.get_mut(conn).ok_or_else(|| {
            Error(format!(
                "connection {conn} was not opened in this test host"
            ))
        })?;
        let recording = opened.transport.recording();
        let frames = recording
            .frames
            .get(opened.cleared..)
            .unwrap_or_default()
            .to_vec();
        if clear {
            opened.cleared = recording.frames.len();
        }
        Ok(Sent {
            frames,
            closed: recording.closed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_parse() {
        let parse = |i: &str, code: Option<u16>, reason: &str, cause: Option<&str>| {
            CloseBy::parse(i, code, reason.to_owned(), cause)
        };
        assert_eq!(
            parse("client", None, "", None),
            Ok(CloseBy::Client {
                code: 1000,
                reason: String::new()
            })
        );
        assert_eq!(
            parse("client", Some(4001), "kicked", None),
            Ok(CloseBy::Client {
                code: 4001,
                reason: "kicked".into()
            })
        );
        assert_eq!(parse("client", Some(1006), "", None), Ok(CloseBy::Gone));
        assert_eq!(
            parse("host", None, "", Some("restart")),
            Ok(CloseBy::Host(pb::CloseCause::Restart))
        );
        assert_eq!(
            parse("host", None, "", Some("slow-consumer")),
            Ok(CloseBy::Host(pb::CloseCause::SlowConsumer))
        );
        for (i, code, reason, cause) in [
            ("client", Some(1005), "", None),
            ("client", Some(1015), "", None),
            ("client", Some(2000), "", None),
            ("client", Some(1006), "why", None),
            ("client", None, "", Some("restart")),
            ("host", None, "", None),
            ("host", Some(1012), "", Some("restart")),
            ("host", None, "", Some("client")),
            ("host", None, "", Some("abandoned")),
            ("actor", None, "", None),
        ] {
            assert!(
                parse(i, code, reason, cause).is_err(),
                "{i} {code:?} {reason:?} {cause:?}"
            );
        }
    }
}

/// The whole client's side against the room guest (tests/guests/room), with
/// connections opened through the node: what the protocol's ops do.
#[cfg(test)]
mod flow {
    use base64::Engine as _;
    use kronik_core::env::real::RealSpawner;
    use kronik_gateway::HttpRequest;

    use super::*;
    use crate::Options;

    const ROOM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/room.wasm");

    async fn host() -> TestHost {
        let spawner = Arc::new(RealSpawner(tokio::runtime::Handle::current()));
        let host = TestHost::start(spawner, Options::default()).await.unwrap();
        let wasm = base64::engine::general_purpose::STANDARD.encode(std::fs::read(ROOM).unwrap());
        let body = serde_json::json!({ "wasm_base64": wasm, "reason": "test" });
        let res = host
            .api("POST", "/v1/deployments", "", body.to_string().into_bytes())
            .await;
        assert_eq!(res.status, 200, "{}", String::from_utf8_lossy(&res.body));
        host
    }

    /// Opens a WebSocket of `room/<key>` as `user` through the gateway: its
    /// id when the room accepts.
    async fn open(host: &TestHost, key: &str, user: &str) -> Option<String> {
        let answer = host
            .open_connection(
                &format!("/room/{key}/ws?user={user}"),
                Vec::new(),
                "websocket",
            )
            .await
            .unwrap();
        if answer.connection.is_some() {
            assert_eq!(answer.response.status, 101, "{answer:?}");
        }
        answer.connection
    }

    fn text_frame(t: &str) -> pb::Frame {
        pb::Frame {
            kind: pb::frame::Kind::Text as i32,
            data: Some(pb::Sealable {
                subject: None,
                value: Some(pb::sealable::Value::Plain(t.as_bytes().to_vec())),
            }),
            ..Default::default()
        }
    }

    /// The data of each frame, as text.
    fn texts(sent: &Sent) -> Vec<String> {
        sent.frames
            .iter()
            .map(
                |(_, f)| match f.data.as_ref().and_then(|d| d.value.as_ref()) {
                    Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
                    _ => String::new(),
                },
            )
            .collect()
    }

    async fn closes(host: &TestHost) -> String {
        let res = host
            .http(HttpRequest {
                method: "GET".into(),
                path: "/room/lobby/closes".into(),
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
                peer: None,
            })
            .await;
        assert_eq!(res.status, 200);
        String::from_utf8(res.body).unwrap()
    }

    #[test]
    fn a_test_plays_the_client() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let host = host().await;
            let ada = open(&host, "lobby", "ada").await.unwrap();
            let welcome = host.frames_sent(&ada, true).unwrap();
            assert_eq!(welcome.frames.len(), 1, "{welcome:?}");
            assert!(texts(&welcome)[0].starts_with(r#"{"type":"welcome""#));
            assert_eq!(
                host.frames_sent(&ada, false).unwrap(),
                Sent::default(),
                "cleared"
            );

            // A second member: the first gets `joined`.
            let bob = open(&host, "lobby", "bob").await.unwrap();
            host.frames_sent(&bob, true).unwrap();
            assert_eq!(
                texts(&host.frames_sent(&ada, true).unwrap()),
                [r#"{"type":"joined","user":"bob"}"#]
            );

            // A frame's turn broadcasts; the host answers after it settled.
            host.send_frame(&ada, text_frame("say hi")).await.unwrap();
            for member in [&ada, &bob] {
                let sent = host.frames_sent(member, true).unwrap();
                assert_eq!(sent.frames.len(), 1, "{sent:?}");
                let (_, frame) = &sent.frames[0];
                assert_eq!(frame.kind, pb::frame::Kind::Event as i32);
                assert_eq!(frame.id, "1");
                assert!(texts(&sent)[0].contains(r#""text":"hi""#), "{sent:?}");
            }

            // The actor closes: the close is recorded, the other member gets
            // `left`, and the closed connection takes no more frames.
            host.send_frame(&bob, text_frame("bye")).await.unwrap();
            let sent = host.frames_sent(&bob, false).unwrap();
            assert_eq!(sent.closed, Some((1000, "bye".to_string())));
            assert_eq!(
                texts(&host.frames_sent(&ada, true).unwrap()),
                [r#"{"type":"left","user":"bob"}"#]
            );
            let e = host
                .send_frame(&bob, text_frame("say late"))
                .await
                .unwrap_err();
            assert!(e.to_string().contains("is closed"), "{e}");

            // The host closes for a restart; a client goes away.
            host.close_connection(&ada, CloseBy::Host(pb::CloseCause::Restart))
                .await
                .unwrap();
            assert_eq!(
                host.frames_sent(&ada, false).unwrap().closed,
                Some((1012, "restart".to_string()))
            );
            let cy = open(&host, "lobby", "cy").await.unwrap();
            host.close_connection(&cy, CloseBy::Gone).await.unwrap();
            let e = host.close_connection(&cy, CloseBy::Gone).await.unwrap_err();
            assert!(e.to_string().contains("is closed"), "{e}");

            // Each close input ran the room's close handler once.
            let closes = closes(&host).await;
            for line in [
                format!("{bob} actor 1000 bye"),
                format!("{ada} host 1012 restart"),
                format!("{cy} client 1006 "),
            ] {
                assert!(closes.lines().any(|l| l == line), "{line:?} in {closes:?}");
            }
            assert_eq!(closes.lines().count(), 3, "{closes:?}");
            let e = host
                .frames_sent("c-00000000000000000000000000000000", false)
                .unwrap_err();
            assert!(e.to_string().contains("was not opened"), "{e}");
        });
    }

    /// The same through the JSON lines that the testkits send.
    #[test]
    fn the_protocol_drives_a_connection() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let host = host().await;
            let ada = open(&host, "lobby", "ada").await.unwrap();
            let call = |line: serde_json::Value| {
                let host = &host;
                async move {
                    let out = host.handle_line(&line.to_string()).await;
                    serde_json::from_str::<serde_json::Value>(&out).unwrap()
                }
            };
            let sent = call(serde_json::json!({ "op": "frames-sent", "connection": ada, "clear": true })).await;
            assert_eq!(sent["ok"], true, "{sent}");
            assert_eq!(sent["frames"][0]["seq"], 0);
            assert_eq!(sent["frames"][0]["kind"], "text");
            assert!(sent["frames"][0]["body"].as_str().unwrap().starts_with(r#"{"type":"welcome""#));
            assert_eq!(sent["closed"], serde_json::Value::Null);

            let ok = call(serde_json::json!({ "op": "send-frame", "connection": ada, "body_base64": "YmluYXJ5IHJhdw==" })).await;
            assert_eq!(ok, serde_json::json!({ "ok": true }));
            let ok = call(serde_json::json!({ "op": "send-frame", "connection": ada, "body": "binary raw" })).await;
            assert_eq!(ok, serde_json::json!({ "ok": true }));
            let sent = call(serde_json::json!({ "op": "frames-sent", "connection": ada })).await;
            // The room reads a binary frame's bytes as a command too: both
            // `binary raw` frames echo `raw` as a binary frame.
            assert_eq!(
                sent["frames"],
                serde_json::json!([
                    { "seq": 1, "kind": "binary", "body_base64": "cmF3" },
                    { "seq": 2, "kind": "binary", "body_base64": "cmF3" },
                ])
            );

            let bad = call(serde_json::json!({ "op": "close-connection", "connection": ada, "initiator": "client", "code": 1005 })).await;
            assert_eq!(bad["ok"], false, "{bad}");
            let ok = call(serde_json::json!({ "op": "close-connection", "connection": ada, "initiator": "client", "code": 4001, "reason": "done" })).await;
            assert_eq!(ok, serde_json::json!({ "ok": true }));
            let closes = closes(&host).await;
            assert_eq!(closes.trim_end(), format!("{ada} client 4001 done"));
            let late = call(serde_json::json!({ "op": "send-frame", "connection": ada, "body": "say late" })).await;
            assert_eq!(late["ok"], false, "{late}");
        });
    }

    /// What the gateway answers: a refusal, a bad handshake, an event
    /// stream, and the protocol's `open-connection`.
    #[test]
    fn opens_go_through_the_gateway() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let host = host().await;
            let refused = host
                .open_connection("/room/lobby/ws?user=ada&deny=1", Vec::new(), "websocket")
                .await
                .unwrap();
            assert_eq!((refused.response.status, refused.connection), (403, None));
            let bad = host
                .open_connection(
                    "/room/lobby/ws?user=ada",
                    vec![("sec-websocket-version".into(), "12".into())],
                    "websocket",
                )
                .await
                .unwrap();
            assert_eq!((bad.response.status, bad.connection), (400, None));
            let e = host
                .open_connection("/room/lobby/ws", Vec::new(), "carrier-pigeon")
                .await
                .unwrap_err();
            assert!(e.to_string().contains("unknown protocol"), "{e}");

            // An event stream gets the messages after its Last-Event-ID.
            let ada = open(&host, "lobby", "ada").await.unwrap();
            for text in ["one", "two", "three"] {
                host.send_frame(&ada, text_frame(&format!("say {text}")))
                    .await
                    .unwrap();
            }
            let stream = host
                .open_connection(
                    "/room/lobby/events",
                    vec![("last-event-id".into(), "1".into())],
                    "sse",
                )
                .await
                .unwrap();
            assert_eq!(stream.response.status, 200, "{stream:?}");
            assert_eq!(stream.protocol, Some(pb::ConnectionProtocol::Sse));
            let follower = stream.connection.unwrap();
            let sent = host.frames_sent(&follower, true).unwrap();
            assert_eq!(
                sent.frames
                    .iter()
                    .map(|(_, f)| f.id.as_str())
                    .collect::<Vec<_>>(),
                ["2", "3"]
            );

            let line = serde_json::json!({ "op": "open-connection", "path": "/room/lobby/ws?user=bob", "headers": [["sec-websocket-protocol", "x, room.v1"]] });
            let out: serde_json::Value =
                serde_json::from_str(&host.handle_line(&line.to_string()).await).unwrap();
            assert_eq!(out["ok"], true, "{out}");
            assert_eq!(out["status"], 101);
            let bob = out["connection"].as_str().unwrap().to_string();
            assert!(kronik_proto::connection::valid_id(&bob), "{bob}");
            let headers = out["headers"].as_array().unwrap();
            assert!(
                headers.contains(&serde_json::json!(["sec-websocket-protocol", "room.v1"])),
                "the room selects room.v1: {headers:?}"
            );
            assert!(out["turn"].as_str().is_some(), "{out}");
            assert!(
                host.frames_sent(&bob, false).unwrap().frames.len() == 1,
                "the welcome"
            );
        });
    }
}
