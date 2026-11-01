#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_api::types::{BlobReference, Payload, Reply, SendRequest};
use serde_json::json;

fn reference(byte: &str, size: u64) -> BlobReference {
    BlobReference::from(&kronik_proto::log::v1::BlobRef {
        hash: format!("b3:{}", byte.repeat(32)), size,
    })
}

#[test]
fn inline_utf8_binary_and_genuine_empty_replies_keep_the_legacy_wire_shape() {
    for (bytes, expected) in [
        (b"".as_slice(), json!({"name":"reply","content_type":"application/octet-stream","text":"","base64":""})),
        ("röd".as_bytes(), json!({"name":"reply","content_type":"application/octet-stream","text":"röd","base64":"csO2ZA=="})),
        (b"\xff\x00".as_slice(), json!({"name":"reply","content_type":"application/octet-stream","base64":"/wA="})),
    ] {
        let reply = Reply::inline("reply".into(), "application/octet-stream".into(), Payload::from_bytes(bytes), Vec::new());
        assert_eq!(serde_json::to_value(&reply).unwrap(), expected);
        let decoded: Reply = serde_json::from_value(expected).unwrap();
        assert_eq!(decoded.body.to_bytes().unwrap(), bytes);
        assert!(decoded.blob.is_none());
        assert!(decoded.blobs.is_empty());
    }
    let request: SendRequest = serde_json::from_value(json!({
        "name":"message", "text":"not the selected bytes", "base64":"/wA=", "reason":"operator request"
    })).unwrap();
    assert_eq!(request.body.to_bytes().unwrap(), b"\xff\x00");
}

#[test]
fn body_blob_has_no_fabricated_inline_bytes_and_message_attachments_are_preserved() {
    let body = reference("11", 1 << 30);
    let reply = Reply::blob("http 200".into(), "application/octet-stream".into(), body.clone());
    let encoded = serde_json::to_value(&reply).unwrap();
    assert_eq!(encoded["blob"], json!({"hash":body.hash,"size":body.size}));
    assert!(encoded.get("text").is_none());
    assert!(encoded.get("base64").is_none());
    assert!(encoded.get("blobs").is_none());
    let decoded: Reply = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.blob, Some(body));
    assert_eq!(decoded.body, Payload::default());

    let attachments = vec![reference("22", 17), reference("33", 29)];
    let message = Reply::inline("message".into(), "text/plain".into(), Payload::from_bytes(b"original body"), attachments.clone());
    let decoded: Reply = serde_json::from_slice(&serde_json::to_vec(&message).unwrap()).unwrap();
    assert_eq!(decoded.body.to_bytes().unwrap(), b"original body");
    assert_eq!(decoded.blobs, attachments);
    assert!(decoded.blob.is_none());
}

#[test]
fn even_empty_inline_data_cannot_be_misrepresented_as_a_body_blob() {
    let body = reference("44", 13);
    for field in ["text", "base64"] {
        let mut invalid = json!({"name":"reply","content_type":"application/octet-stream","blob":{"hash":body.hash,"size":body.size}});
        invalid[field] = json!("");
        assert!(serde_json::from_value::<Reply>(invalid).is_err());
    }
    let mut invalid = Reply::blob("reply".into(), "application/octet-stream".into(), body);
    invalid.body = Payload::from_bytes(b"");
    assert!(serde_json::to_vec(&invalid).is_err());
}
