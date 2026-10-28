//! Secret scrubbing (I8): every exact occurrence of a secret value the turn
//! used or revealed becomes `[secret:<name>]` before anything is written.
//!
//! Scrubbing works on structured fields, never on encoded protobuf bytes: a
//! replacement of another length inside an encoded message breaks its
//! length prefixes. Effect payloads (`EffectRecord.request`/`response`) are
//! decoded by kind, scrubbed field by field and encoded again. Values in
//! sealed (encrypted) form are left alone: scrubbing happens before sealing.
//! Production turns and fork turns use the same functions.

use kronik_effects::http::{scrub, scrub_str};
use kronik_proto::log::v1 as pb;
use prost::Message as _;

/// Secret names and values, as the effect gate collects them.
pub type Secrets = [(String, Vec<u8>)];

/// Replaces secret values in a sealable's plain bytes (raw user bytes).
pub fn sealable(s: &mut Option<pb::Sealable>, secrets: &Secrets) {
    if let Some(pb::Sealable {
        value: Some(pb::sealable::Value::Plain(b)),
        ..
    }) = s
    {
        *b = scrub(b, secrets);
    }
}

/// Replaces secret values in a message's body.
pub fn message(m: &mut Option<pb::Message>, secrets: &Secrets) {
    if let Some(m) = m {
        sealable(&mut m.body, secrets);
    }
}

/// Everything a turn writes from guest data: state writes, messages,
/// timers, compensations and the output.
pub fn output(out: &mut kronik_runtime::TurnOutput, secrets: &Secrets) {
    if secrets.is_empty() {
        return;
    }
    for w in &mut out.writes {
        sealable(&mut w.value, secrets);
    }
    for m in &mut out.messages {
        message(&mut m.msg, secrets);
    }
    for t in &mut out.timers {
        message(&mut t.msg, secrets);
    }
    out.outcome.message = scrub_str(&out.outcome.message, secrets);
    outcome_output(&mut out.outcome.output, secrets);
}

/// A turn's output (reply or HTTP response).
pub fn outcome_output(o: &mut Option<pb::outcome::Output>, secrets: &Secrets) {
    match o {
        Some(pb::outcome::Output::Reply(m)) => sealable(&mut m.body, secrets),
        Some(pb::outcome::Output::Http(h)) => {
            for hd in &mut h.headers {
                sealable(&mut hd.value, secrets);
            }
            if let Some(pb::Body {
                value: Some(pb::body::Value::Inline(s)),
            }) = &mut h.body
            {
                let mut opt = Some(std::mem::take(s));
                sealable(&mut opt, secrets);
                if let Some(v) = opt {
                    *s = v;
                }
            }
        }
        None => {}
    }
}

/// The plain bytes of a sealable, to decode, scrub and put back.
fn with_plain(s: &mut Option<pb::Sealable>, f: impl FnOnce(&[u8]) -> Option<Vec<u8>>) {
    if let Some(pb::Sealable {
        value: Some(pb::sealable::Value::Plain(b)),
        ..
    }) = s
        && let Some(new) = f(b)
    {
        *b = new;
    }
}

/// An HTTP effect request: URL, text header values and body.
pub fn http_request(r: &mut pb::HttpEffectRequest, secrets: &Secrets) {
    r.url = scrub_str(&r.url, secrets);
    for h in &mut r.headers {
        if let Some(pb::http_effect_header::Value::Text(t)) = &mut h.value {
            *t = scrub_str(t, secrets);
        }
    }
    r.body = scrub(&r.body, secrets);
}

/// An HTTP effect response: header values and body.
pub fn http_response(r: &mut pb::HttpEffectResponse, secrets: &Secrets) {
    for h in &mut r.headers {
        h.value = scrub_str(&h.value, secrets);
    }
    r.body = scrub(&r.body, secrets);
}

/// An effect record's payloads and error, by kind. A payload that does not
/// decode is left as it is (it never held a decodable value to scrub).
pub fn effect(e: &mut pb::EffectRecord, secrets: &Secrets) {
    if secrets.is_empty() {
        return;
    }
    e.error = scrub_str(&e.error, secrets);
    match e.kind.as_str() {
        "http.fetch" | "foreign.http" => {
            with_plain(&mut e.request, |b| {
                let mut r = pb::HttpEffectRequest::decode(b).ok()?;
                http_request(&mut r, secrets);
                Some(r.encode_to_vec())
            });
            with_plain(&mut e.response, |b| {
                let mut r = pb::HttpEffectResponse::decode(b).ok()?;
                http_response(&mut r, secrets);
                Some(r.encode_to_vec())
            });
        }
        "actor.call" => {
            with_plain(&mut e.request, |b| {
                let mut r = pb::CallEffectRequest::decode(b).ok()?;
                message(&mut r.msg, secrets);
                message(&mut r.compensate, secrets);
                Some(r.encode_to_vec())
            });
            with_plain(&mut e.response, |b| {
                let mut r = pb::CallEffectResponse::decode(b).ok()?;
                message(&mut r.reply, secrets);
                Some(r.encode_to_vec())
            });
        }
        // secret.reveal and crypto.* record a secret reference and a data
        // hash, never a value; their responses are not secret values.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(b: Vec<u8>) -> Option<pb::Sealable> {
        Some(pb::Sealable {
            subject: None,
            value: Some(pb::sealable::Value::Plain(b)),
        })
    }

    fn bytes(s: &Option<pb::Sealable>) -> Vec<u8> {
        match s.as_ref().and_then(|s| s.value.as_ref()) {
            Some(pb::sealable::Value::Plain(b)) => b.clone(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn effect_payloads_stay_decodable_after_scrubbing() {
        let secrets = vec![("k1".to_owned(), b"VALUE-k1-7c2e".to_vec())];
        let msg = |t: &str| pb::Message {
            name: "m".into(),
            content_type: "text/plain".into(),
            body: plain(t.as_bytes().to_vec()),
            blobs: vec![],
        };
        let mut call = pb::EffectRecord {
            kind: "actor.call".into(),
            request: plain(
                pb::CallEffectRequest {
                    to: Some(pb::ActorRef {
                        kind: "leaky".into(),
                        key: "b".into(),
                    }),
                    msg: Some(msg("pass VALUE-k1-7c2e on")),
                    compensate: Some(msg("undo VALUE-k1-7c2e")),
                    message_id: "id".into(),
                }
                .encode_to_vec(),
            ),
            response: plain(
                pb::CallEffectResponse {
                    reply: Some(msg("got VALUE-k1-7c2e")),
                    turn_id: "main:9".into(),
                }
                .encode_to_vec(),
            ),
            ..Default::default()
        };
        effect(&mut call, &secrets);
        let req = pb::CallEffectRequest::decode(bytes(&call.request).as_slice()).unwrap();
        assert_eq!(
            bytes(&req.msg.unwrap().body),
            b"pass [secret:k1] on".to_vec()
        );
        assert_eq!(
            bytes(&req.compensate.unwrap().body),
            b"undo [secret:k1]".to_vec()
        );
        assert_eq!(req.to.unwrap().key, "b");
        let resp = pb::CallEffectResponse::decode(bytes(&call.response).as_slice()).unwrap();
        assert_eq!(
            bytes(&resp.reply.unwrap().body),
            b"got [secret:k1]".to_vec()
        );
        assert_eq!(resp.turn_id, "main:9");

        let mut fetch = pb::EffectRecord {
            kind: "http.fetch".into(),
            request: plain(
                pb::HttpEffectRequest {
                    method: "POST".into(),
                    url: "http://h/x?key=VALUE-k1-7c2e".into(),
                    headers: vec![pb::HttpEffectHeader {
                        name: "x-api-key".into(),
                        value: Some(pb::http_effect_header::Value::Text("VALUE-k1-7c2e".into())),
                    }],
                    body: b"VALUE-k1-7c2e".to_vec(),
                }
                .encode_to_vec(),
            ),
            error: "failed with VALUE-k1-7c2e".into(),
            ..Default::default()
        };
        effect(&mut fetch, &secrets);
        let req = pb::HttpEffectRequest::decode(bytes(&fetch.request).as_slice()).unwrap();
        assert_eq!(req.url, "http://h/x?key=[secret:k1]");
        assert_eq!(req.body, b"[secret:k1]".to_vec());
        assert_eq!(
            req.headers[0].value,
            Some(pb::http_effect_header::Value::Text("[secret:k1]".into()))
        );
        assert_eq!(fetch.error, "failed with [secret:k1]");
    }
}
