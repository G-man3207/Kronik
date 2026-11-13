//! Every `Sealable` of a record, in one place (docs/design/m8-privacy.md
//! §4): the sealing points, unsealing for guests and the erasure scan walk
//! records through these functions, so a new user-data field only has to be
//! added here.

use crate::Record;
use crate::log::v1 as pb;

/// A `Sealable` visitor.
pub type Visit<'a> = &'a mut dyn FnMut(&mut pb::Sealable);

fn body(b: Option<&mut pb::Body>, f: Visit<'_>) {
    if let Some(pb::Body {
        value: Some(pb::body::Value::Inline(s)),
    }) = b
    {
        f(s);
    }
}

fn headers(hs: &mut [pb::Header], f: Visit<'_>) {
    for h in hs {
        if let Some(v) = h.value.as_mut() {
            f(v);
        }
    }
}

/// The body of a message.
pub fn message_mut(m: Option<&mut pb::Message>, f: Visit<'_>) {
    if let Some(b) = m.and_then(|m| m.body.as_mut()) {
        f(b);
    }
}

fn http_input(h: &mut pb::HttpInput, f: Visit<'_>) {
    for s in [h.sealed_path.as_mut(), h.sealed_query.as_mut()]
        .into_iter()
        .flatten()
    {
        f(s);
    }
    for p in &mut h.params {
        if let Some(v) = p.sealed_value.as_mut() {
            f(v);
        }
    }
    headers(&mut h.headers, f);
    body(h.body.as_mut(), f);
}

/// A frame's data (M24).
pub fn frame_mut(frame: Option<&mut pb::Frame>, f: Visit<'_>) {
    if let Some(d) = frame.and_then(|frame| frame.data.as_mut()) {
        f(d);
    }
}

/// HTTP path, query, parameter values, headers and body; message and timer
/// bodies of an input; a connection open's request, a frame's data and a
/// close's reason (M24).
pub fn input_mut(input: Option<&mut pb::Input>, f: Visit<'_>) {
    use pb::connection_input::Event;
    use pb::input::Kind;
    match input.and_then(|i| i.kind.as_mut()) {
        Some(Kind::Http(h)) => http_input(h, f),
        Some(Kind::Message(m)) => message_mut(m.msg.as_mut(), f),
        Some(Kind::Timer(t)) => message_mut(t.msg.as_mut(), f),
        Some(Kind::Connection(c)) => match c.event.as_mut() {
            Some(Event::Open(o)) => {
                if let Some(h) = o.request.as_mut() {
                    http_input(h, f);
                }
            }
            Some(Event::Frame(fr)) => frame_mut(fr.frame.as_mut(), f),
            Some(Event::Close(close)) => {
                if let Some(r) = close.reason.as_mut() {
                    f(r);
                }
            }
            None => {}
        },
        Some(Kind::Migrate(_)) | None => {}
    }
}

/// The reply or HTTP response of an outcome.
pub fn outcome_mut(o: Option<&mut pb::Outcome>, f: Visit<'_>) {
    use pb::outcome::Output;
    match o.and_then(|o| o.output.as_mut()) {
        Some(Output::Reply(m)) => message_mut(Some(m), f),
        Some(Output::Http(h)) => {
            headers(&mut h.headers, f);
            body(h.body.as_mut(), f);
        }
        Some(Output::Accept(a)) => headers(&mut a.headers, f),
        None => {}
    }
}

/// A turn's buffered connection operations (M24): frame data and close
/// reasons.
pub fn connection_ops_mut(ops: &mut [pb::ConnectionOp], f: Visit<'_>) {
    for op in ops {
        match op.op.as_mut() {
            Some(pb::connection_op::Op::Send(frame)) => frame_mut(Some(frame), f),
            Some(pb::connection_op::Op::Close(close)) => {
                if let Some(r) = close.reason.as_mut() {
                    f(r);
                }
            }
            None => {}
        }
    }
}

/// An effect's request and response.
pub fn effect_mut(e: &mut pb::EffectRecord, f: Visit<'_>) {
    if let Some(r) = e.request.as_mut() {
        f(r);
    }
    if let Some(r) = e.response.as_mut() {
        f(r);
    }
}

/// Every `Sealable` of a turn record.
pub fn turn_mut(t: &mut pb::TurnRecord, f: Visit<'_>) {
    input_mut(t.input.as_mut(), f);
    for e in &mut t.effects {
        effect_mut(e, f);
    }
    for w in &mut t.writes {
        if let Some(v) = w.value.as_mut() {
            f(v);
        }
    }
    for m in t.messages.iter_mut().chain(t.compensations.iter_mut()) {
        message_mut(m.msg.as_mut(), f);
    }
    for op in &mut t.timers {
        message_mut(op.msg.as_mut(), f);
    }
    for c in &mut t.sql_changes {
        if let Some(cs) = c.changeset.as_mut() {
            f(cs);
        }
    }
    outcome_mut(t.outcome.as_mut(), f);
    connection_ops_mut(&mut t.connection_ops, f);
}

/// Every `Sealable` of a record, including protected historical approval identity.
pub fn record_mut(r: &mut Record, f: Visit<'_>) {
    match r {
        Record::Approval(approval) => {
            if let Some(identity) = approval.verified_identity.as_mut() {
                f(identity);
            }
        }
        Record::TurnBegin(b) => input_mut(b.input.as_mut(), f),
        Record::EffectResult(e) => {
            if let Some(e) = e.effect.as_mut() {
                effect_mut(e, f);
            }
        }
        Record::TurnRecord(t) => turn_mut(t, f),
        // A rebased turn holds a turn record's user data (M13).
        Record::StateRebase(r) => {
            if let Some(pb::state_rebase::Part::Turn(t)) = r.part.as_mut()
                && let Some(t) = t.record.as_mut()
            {
                turn_mut(t, f);
            }
        }
        // Provenance contains public resource identities, never secret bytes.
        Record::SecretVersion(_) | Record::SecretLink(_) => {}
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(subject: &str, v: &[u8]) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: Some(subject.into()),
            value: Some(pb::sealable::Value::Plain(v.to_vec())),
        })
    }

    #[test]
    fn every_user_data_field_is_visited() {
        let msg = |v: &[u8]| pb::Message {
            body: s("m", v),
            ..Default::default()
        };
        let mut t = pb::TurnRecord {
            input: Some(pb::Input {
                kind: Some(pb::input::Kind::Http(pb::HttpInput {
                    sealed_path: s("u", b"0a"),
                    sealed_query: s("u", b"0b"),
                    params: vec![pb::Param {
                        name: "key".into(),
                        value: String::new(),
                        sealed_value: s("u", b"0c"),
                    }],
                    headers: vec![pb::Header {
                        name: "h".into(),
                        value: s("u", b"1"),
                    }],
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(s("u", b"2").unwrap_or_default())),
                    }),
                    ..Default::default()
                })),
            }),
            effects: vec![pb::EffectRecord {
                request: s("u", b"3"),
                response: s("u", b"4"),
                ..Default::default()
            }],
            writes: vec![pb::StateWrite {
                value: s("u", b"5"),
                ..Default::default()
            }],
            messages: vec![pb::OutboundMessage {
                msg: Some(msg(b"6")),
                ..Default::default()
            }],
            compensations: vec![pb::OutboundMessage {
                msg: Some(msg(b"7")),
                ..Default::default()
            }],
            timers: vec![pb::TimerOp {
                msg: Some(msg(b"8")),
                ..Default::default()
            }],
            sql_changes: vec![pb::SqlChangeset {
                changeset: s("u", b"9"),
            }],
            outcome: Some(pb::Outcome {
                output: Some(pb::outcome::Output::Reply(msg(b"10"))),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut seen = Vec::new();
        turn_mut(&mut t, &mut |v| {
            if let Some(pb::sealable::Value::Plain(b)) = &v.value {
                seen.push(String::from_utf8_lossy(b).into_owned());
            }
        });
        assert_eq!(
            seen,
            [
                "0a", "0b", "0c", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"
            ]
        );
        let mut r = Record::TurnBegin(pb::TurnBegin {
            input: t.input.clone(),
            ..Default::default()
        });
        let mut n = 0;
        record_mut(&mut r, &mut |_| n += 1);
        assert_eq!(n, 5);
    }

    fn visited(t: &mut pb::TurnRecord) -> Vec<String> {
        let mut seen = Vec::new();
        turn_mut(t, &mut |v| {
            if let Some(pb::sealable::Value::Plain(b)) = &v.value {
                seen.push(String::from_utf8_lossy(b).into_owned());
            }
        });
        seen
    }

    fn connection(event: pb::connection_input::Event) -> Option<pb::Input> {
        Some(pb::Input {
            kind: Some(pb::input::Kind::Connection(pb::ConnectionInput {
                connection: "c-0123456789abcdef0123456789abcdef".into(),
                protocol: pb::ConnectionProtocol::Websocket as i32,
                event: Some(event),
                ..Default::default()
            })),
        })
    }

    /// M24 §6.4: a connection open's request, a frame's data, a close's
    /// reason, the accept's header values and every operation's frame data
    /// and close reason.
    #[test]
    fn every_connection_field_is_visited() {
        use pb::connection_input::Event;
        let frame = |v: &[u8]| pb::Frame {
            kind: pb::frame::Kind::Text as i32,
            data: s("u", v),
            ..Default::default()
        };
        let mut open = pb::TurnRecord {
            input: connection(Event::Open(pb::ConnectionOpen {
                request: Some(pb::HttpInput {
                    sealed_path: s("u", b"path"),
                    sealed_query: s("u", b"query"),
                    params: vec![pb::Param {
                        name: "key".into(),
                        value: String::new(),
                        sealed_value: s("u", b"param"),
                    }],
                    headers: vec![pb::Header {
                        name: "h".into(),
                        value: s("u", b"header"),
                    }],
                    body: Some(pb::Body {
                        value: Some(pb::body::Value::Inline(s("u", b"body").unwrap_or_default())),
                    }),
                    ..Default::default()
                }),
                subprotocols: vec!["chat".into()],
            })),
            outcome: Some(pb::Outcome {
                output: Some(pb::outcome::Output::Accept(pb::ConnectionAccept {
                    headers: vec![pb::Header {
                        name: "x".into(),
                        value: s("u", b"accept-header"),
                    }],
                    ..Default::default()
                })),
                ..Default::default()
            }),
            connection_ops: vec![
                pb::ConnectionOp {
                    connections: vec!["c-0123456789abcdef0123456789abcdef".into()],
                    seqs: vec![0],
                    op: Some(pb::connection_op::Op::Send(frame(b"welcome"))),
                },
                pb::ConnectionOp {
                    connections: vec!["c-0123456789abcdef0123456789abcdef".into()],
                    seqs: vec![],
                    op: Some(pb::connection_op::Op::Close(pb::ConnectionCloseRequest {
                        code: 1000,
                        reason: s("u", b"bye"),
                    })),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            visited(&mut open),
            [
                "path",
                "query",
                "param",
                "header",
                "body",
                "accept-header",
                "welcome",
                "bye"
            ]
        );
        let mut incoming = pb::TurnRecord {
            input: connection(Event::Frame(pb::ConnectionFrame {
                seq: 3,
                frame: Some(frame(b"incoming")),
            })),
            ..Default::default()
        };
        assert_eq!(visited(&mut incoming), ["incoming"]);
        let mut close = pb::TurnRecord {
            input: connection(Event::Close(pb::ConnectionClose {
                cause: pb::CloseCause::Client as i32,
                code: 1000,
                reason: s("u", b"client-reason"),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_eq!(visited(&mut close), ["client-reason"]);
    }
}
