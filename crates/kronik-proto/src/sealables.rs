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

/// HTTP path, query, parameter values, headers and body; message and timer
/// bodies of an input.
pub fn input_mut(input: Option<&mut pb::Input>, f: Visit<'_>) {
    use pb::input::Kind;
    match input.and_then(|i| i.kind.as_mut()) {
        Some(Kind::Http(h)) => {
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
        Some(Kind::Message(m)) => message_mut(m.msg.as_mut(), f),
        Some(Kind::Timer(t)) => message_mut(t.msg.as_mut(), f),
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
        None => {}
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
}

/// Every `Sealable` of a record: turn begins, effect results and turn
/// records carry user data; configuration records carry none.
pub fn record_mut(r: &mut Record, f: Visit<'_>) {
    match r {
        Record::TurnBegin(b) => input_mut(b.input.as_mut(), f),
        Record::EffectResult(e) => {
            if let Some(e) = e.effect.as_mut() {
                effect_mut(e, f);
            }
        }
        Record::TurnRecord(t) => turn_mut(t, f),
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
}
