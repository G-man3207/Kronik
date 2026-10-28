//! Reading an [`pb::HttpInput`]'s path, query and route parameters.
//!
//! A request with a subject keeps them in sealable fields (`sealed_path`,
//! `sealed_query`, `Param.sealed_value`, I9); older records and requests
//! without a subject keep them in the plain fields. These helpers read
//! whichever is set. A value still sealed reads as `[sealed]`: callers that
//! need the plaintext unseal the input first (the host for the guest, the
//! API's redaction for callers allowed to see it).

use crate::log::v1 as pb;

/// What a still-sealed value reads as.
pub const SEALED: &str = "[sealed]";

fn text(s: &pb::Sealable) -> String {
    match &s.value {
        Some(pb::sealable::Value::Plain(b)) => String::from_utf8_lossy(b).into_owned(),
        Some(pb::sealable::Value::Sealed(_)) => SEALED.to_owned(),
        None => String::new(),
    }
}

/// A plain value tagged with `subject`.
pub fn tagged(subject: &str, value: String) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: Some(subject.to_owned()),
        value: Some(pb::sealable::Value::Plain(value.into_bytes())),
    })
}

impl pb::HttpInput {
    /// The request path.
    pub fn path_text(&self) -> String {
        self.sealed_path
            .as_ref()
            .map_or_else(|| self.path.clone(), text)
    }

    /// The query string (without `?`).
    pub fn query_text(&self) -> String {
        self.sealed_query
            .as_ref()
            .map_or_else(|| self.query.clone(), text)
    }

    /// The route parameters as (name, value), in pattern order.
    pub fn param_values(&self) -> Vec<(String, String)> {
        self.params
            .iter()
            .map(|p| {
                let value = p
                    .sealed_value
                    .as_ref()
                    .map_or_else(|| p.value.clone(), text);
                (p.name.clone(), value)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use prost::Message as _;

    /// A record written before the sealable fields existed (path, query and
    /// params plain): the committed bytes decode, and the readers return
    /// the plain fields. Fixture: `tests/fixtures/http-input-v1.hex`.
    #[test]
    fn records_from_before_sealable_fields_read_their_plain_fields() {
        let hex = include_str!("../tests/fixtures/http-input-v1.hex");
        let bytes: Vec<u8> = (0..hex.trim().len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap())
            .collect();
        let h = pb::HttpInput::decode(bytes.as_slice()).unwrap();
        assert_eq!(h.path_text(), "/counter/a/increment");
        assert_eq!(h.query_text(), "email=a%40example.com");
        assert_eq!(
            h.param_values(),
            vec![
                ("key".to_owned(), "a".to_owned()),
                ("op".to_owned(), "increment".to_owned())
            ]
        );
        assert!(h.sealed_path.is_none() && h.sealed_query.is_none());
    }

    #[test]
    fn sealable_fields_win_and_sealed_values_stay_hidden() {
        let mut h = pb::HttpInput {
            path: String::new(),
            sealed_path: tagged("user:1", "/notes/carol%40example.com".into()),
            sealed_query: tagged("user:1", "reset_token=rt-5f3a9c".into()),
            params: vec![pb::Param {
                name: "key".into(),
                value: String::new(),
                sealed_value: tagged("user:1", "carol@example.com".into()),
            }],
            ..Default::default()
        };
        assert_eq!(h.path_text(), "/notes/carol%40example.com");
        assert_eq!(h.query_text(), "reset_token=rt-5f3a9c");
        assert_eq!(h.param_values()[0].1, "carol@example.com");
        if let Some(s) = h.sealed_query.as_mut() {
            s.value = Some(pb::sealable::Value::Sealed(pb::Sealed::default()));
        }
        assert_eq!(h.query_text(), SEALED);
    }
}
