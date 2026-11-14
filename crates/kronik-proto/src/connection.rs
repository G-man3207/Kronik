//! Long-lived connections in the log (M24, docs/design/m24-connections.md
//! §6): connection ids and the names the API, the diff and the metrics use
//! for the protocol, the close cause and the frame kind.

use crate::log::v1 as pb;

/// The prefix of a connection id.
pub const ID_PREFIX: &str = "c-";

/// The effect kind of `connections.send-now` (§4.4).
pub const SEND_NOW_KIND: &str = "connection.send-now";

/// The domain of a `send-now` fingerprint (§6.2).
const SEND_NOW_DOMAIN: &[u8] = b"kronik.fingerprint.connection.v1";

/// A `send-now`'s plain fingerprint (§6.2): BLAKE3 over the domain string
/// and the length-prefixed connection, frame kind, data, event and id,
/// without the seq. The node keys it per subject like every fingerprint.
pub fn send_now_fingerprint(connection: &str, frame: &pb::Frame) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(SEND_NOW_DOMAIN);
    let data: &[u8] = match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.as_slice(),
        _ => &[],
    };
    let kind = frame.kind.to_le_bytes();
    for field in [
        connection.as_bytes(),
        kind.as_slice(),
        data,
        frame.event.as_bytes(),
        frame.id.as_bytes(),
    ] {
        h.update(&(field.len() as u64).to_le_bytes());
        h.update(field);
    }
    h.finalize().as_bytes().to_vec()
}

/// The plaintext of a `send-now`'s `EffectRecord.request` (§6.2): the
/// connection, the frame and its `seq` (0 unless the status is `OK`).
pub fn send_now_request(
    connection: &str,
    seq: u64,
    frame: &pb::Frame,
) -> pb::ConnectionSendRequest {
    pb::ConnectionSendRequest {
        connection: connection.to_owned(),
        seq,
        kind: frame.kind,
        data: match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
            Some(pb::sealable::Value::Plain(b)) => b.clone(),
            _ => Vec::new(),
        },
        event: frame.event.clone(),
        id: frame.id.clone(),
    }
}

/// Whether `id` is a connection id: `c-` and 32 lowercase hex characters.
pub fn valid_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX).is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The id of the connection that the open input with root id `root`
/// opens: `c-` and the root id, so it is recorded with the open and the
/// same in replay.
pub fn id_for_root(root: &str) -> String {
    format!("{ID_PREFIX}{root}")
}

/// `websocket` or `sse`, as the API and the metrics name the protocol.
pub fn protocol_name(protocol: i32) -> &'static str {
    match pb::ConnectionProtocol::try_from(protocol) {
        Ok(pb::ConnectionProtocol::Websocket) => "websocket",
        Ok(pb::ConnectionProtocol::Sse) => "sse",
        _ => "unspecified",
    }
}

/// The route method of a protocol: `WEBSOCKET` or `SSE`.
pub fn protocol_method(protocol: i32) -> &'static str {
    match pb::ConnectionProtocol::try_from(protocol) {
        Ok(pb::ConnectionProtocol::Websocket) => "WEBSOCKET",
        Ok(pb::ConnectionProtocol::Sse) => "SSE",
        _ => "UNSPECIFIED",
    }
}

/// `text`, `binary` or `event`.
pub fn frame_kind_name(kind: i32) -> &'static str {
    match pb::frame::Kind::try_from(kind) {
        Ok(pb::frame::Kind::Text) => "text",
        Ok(pb::frame::Kind::Binary) => "binary",
        Ok(pb::frame::Kind::Event) => "event",
        _ => "unspecified",
    }
}

/// Who ended a connection: `client`, `actor` or `host`.
pub fn initiator(cause: i32) -> &'static str {
    match pb::CloseCause::try_from(cause) {
        Ok(pb::CloseCause::Client) => "client",
        Ok(pb::CloseCause::Actor) => "actor",
        Ok(_) if cause != 0 => "host",
        _ => "unspecified",
    }
}

/// The cause as the API names it (`client`, `actor`, `restart`, ...); for a
/// host cause it is also the close reason the actor's close handler gets.
pub fn cause_name(cause: i32) -> &'static str {
    match pb::CloseCause::try_from(cause) {
        Ok(pb::CloseCause::Client) => "client",
        Ok(pb::CloseCause::Actor) => "actor",
        Ok(pb::CloseCause::Restart) => "restart",
        Ok(pb::CloseCause::PingTimeout) => "ping-timeout",
        Ok(pb::CloseCause::TooLarge) => "too-large",
        Ok(pb::CloseCause::SlowConsumer) => "slow-consumer",
        Ok(pb::CloseCause::Protocol) => "protocol",
        Ok(pb::CloseCause::Operator) => "operator",
        Ok(pb::CloseCause::Rebase) => "rebase",
        Ok(pb::CloseCause::Abandoned) => "abandoned",
        Ok(pb::CloseCause::Unavailable) => "unavailable",
        _ => "unspecified",
    }
}

/// The bytes of a sealed value's AEAD tag: `Sealed` is XChaCha20-Poly1305
/// (common.proto), whose ciphertext is the plaintext and a 16-byte tag.
const SEAL_TAG_BYTES: usize = 16;

/// A frame's payload size, the same whether its data is sealed or not: the
/// data's plaintext, plus the event and id of an SSE event. The runtime's
/// limits count the same bytes, before sealing.
pub fn frame_bytes(frame: &pb::Frame) -> usize {
    let data = match frame.data.as_ref().and_then(|d| d.value.as_ref()) {
        Some(pb::sealable::Value::Plain(b)) => b.len(),
        Some(pb::sealable::Value::Sealed(s)) => s.ciphertext.len().saturating_sub(SEAL_TAG_BYTES),
        None => 0,
    };
    data + frame.event.len() + frame.id.len()
}

/// The subject of a connection input (M24 §4.10), which is its turn's
/// default subject: an open's request's (the gateway tags its headers and
/// body with it), a frame's data's, a close's reason's. The gateway and the
/// node tag every later input of a connection with the connection's
/// subject, a host close an empty reason, so a re-run and a replay derive
/// the same subject from the recorded input.
pub fn input_subject(c: &pb::ConnectionInput) -> Option<String> {
    use pb::connection_input::Event;
    match &c.event {
        Some(Event::Open(o)) => {
            let h = o.request.as_ref()?;
            match h.body.as_ref().and_then(|b| b.value.as_ref()) {
                Some(pb::body::Value::Inline(s)) if s.subject.is_some() => s.subject.clone(),
                _ => h
                    .headers
                    .iter()
                    .find_map(|h| h.value.as_ref().and_then(|v| v.subject.clone())),
            }
        }
        Some(Event::Frame(f)) => f.frame.as_ref()?.data.as_ref()?.subject.clone(),
        Some(Event::Close(close)) => close.reason.as_ref()?.subject.clone(),
        None => None,
    }
}

/// The connection input of `input`, if it is one.
pub fn input(input: Option<&pb::Input>) -> Option<&pb::ConnectionInput> {
    match input?.kind.as_ref()? {
        pb::input::Kind::Connection(c) => Some(c),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids() {
        let root = "0123456789abcdef0123456789abcdef";
        assert!(valid_id(&id_for_root(root)));
        assert_eq!(id_for_root(root), format!("c-{root}"));
        for bad in [
            "",
            "c-",
            root,
            "c-0123456789ABCDEF0123456789abcdef",
            "c-0123456789abcdef0123456789abcde",
            "c-0123456789abcdef0123456789abcdef0",
            "d-0123456789abcdef0123456789abcdef",
            "c-0123456789abcdef0123456789abcdeg",
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn names() {
        assert_eq!(protocol_name(1), "websocket");
        assert_eq!(protocol_method(2), "SSE");
        assert_eq!(frame_kind_name(3), "event");
        assert_eq!(initiator(pb::CloseCause::Restart as i32), "host");
        assert_eq!(initiator(pb::CloseCause::Client as i32), "client");
        assert_eq!(initiator(0), "unspecified");
        assert_eq!(
            cause_name(pb::CloseCause::SlowConsumer as i32),
            "slow-consumer"
        );
        assert_eq!(cause_name(99), "unspecified");
    }
}
