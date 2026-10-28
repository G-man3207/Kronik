//! How the API shows user data (docs/design/m8-privacy.md §5): one helper,
//! [`render_sealable`], so the JSON API, MCP (which calls the API) and the
//! CLI agree.
//!
//! - Plain values are shown as recorded: `off` protects nothing.
//! - Sealed values are unsealed for callers with `pii:read`; others see
//!   `[sealed]`.
//! - Values of an erased subject are `[erased]` for every caller; a value
//!   whose key this keystore lacks is `[unreadable:<subject>]` (only callers
//!   with `pii:read` get that far).
//! - Callers without `pii:read` never see a subject id: [`redact`] drops
//!   the subject of every value for them.

use kronik_privacy::sealer::{Opened, Sealer};
use kronik_proto::log::v1 as pb;

/// What the API shows for one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendered {
    Value(Vec<u8>),
    Sealed,
    Erased,
    Unreadable(String),
}

impl Rendered {
    /// The bytes the JSON shows: the value, or its placeholder text.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Rendered::Value(v) => v,
            Rendered::Sealed => kronik_proto::http::SEALED.as_bytes().to_vec(),
            Rendered::Erased => b"[erased]".to_vec(),
            Rendered::Unreadable(s) => format!("[unreadable:{s}]").into_bytes(),
        }
    }
}

/// One value for a caller that may (`pii`) or may not read personal data.
pub fn render_sealable(s: &pb::Sealable, sealer: &Sealer, pii: bool) -> Rendered {
    let sealed = matches!(s.value, Some(pb::sealable::Value::Sealed(_)));
    let subject = s.subject.clone().unwrap_or_default();
    match sealer.open(s) {
        Opened::Erased { .. } => Rendered::Erased,
        _ if sealed && !pii => Rendered::Sealed,
        Opened::Value(v) => Rendered::Value(v.into_owned()),
        Opened::Unreadable { .. } => Rendered::Unreadable(subject),
    }
}

/// Replaces a value with what the caller may see, as a plain value, so the
/// existing renderers show it unchanged. Without `pii` the subject goes
/// too, sealed or not.
pub fn redact(s: &mut pb::Sealable, sealer: &Sealer, pii: bool) {
    if !matches!(s.value, Some(pb::sealable::Value::Plain(_)) | None) {
        let shown = render_sealable(s, sealer, pii).into_bytes();
        s.value = Some(pb::sealable::Value::Plain(shown));
    }
    if !pii {
        s.subject = None;
    }
}

/// Whether a value is sealed for an erased subject: `history`, which
/// shows no values, marks such writes `[erased]`.
pub fn is_erased(s: &pb::Sealable, sealer: &Sealer) -> bool {
    matches!(s.value, Some(pb::sealable::Value::Sealed(_)))
        && matches!(sealer.open(s), Opened::Erased { .. })
}

/// [`redact`] for every value of a turn record.
pub fn redact_turn(t: &mut pb::TurnRecord, sealer: &Sealer, pii: bool) {
    kronik_proto::sealables::turn_mut(t, &mut |s| redact(s, sealer, pii));
}

/// [`redact`] for every value of an input.
pub fn redact_input(i: &mut pb::Input, sealer: &Sealer, pii: bool) {
    kronik_proto::sealables::input_mut(Some(i), &mut |s| redact(s, sealer, pii));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_values_show_as_recorded_and_sealed_ones_need_pii_read() {
        let sealer = Sealer::plain();
        let plain = pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Plain(b"alice".to_vec())),
        };
        assert_eq!(
            render_sealable(&plain, &sealer, false),
            Rendered::Value(b"alice".to_vec())
        );
        let sealed = pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: vec![0; 24],
                ciphertext: vec![1, 2, 3],
            })),
        };
        assert_eq!(
            render_sealable(&sealed, &sealer, false).into_bytes(),
            b"[sealed]"
        );
        // Without pii:read no subject id is left, sealed or plain.
        for v in [&sealed, &plain] {
            let mut v = v.clone();
            redact(&mut v, &sealer, false);
            assert_eq!(v.subject, None);
        }
        // A tombstone is erased for everyone.
        let tomb = pb::Sealable {
            subject: Some("user:1".into()),
            value: Some(pb::sealable::Value::Sealed(pb::Sealed {
                key_version: 1,
                nonce: Vec::new(),
                ciphertext: Vec::new(),
            })),
        };
        assert_eq!(render_sealable(&tomb, &sealer, true), Rendered::Erased);
        let mut v = sealed.clone();
        redact(&mut v, &sealer, true);
        assert_eq!(
            v.value,
            Some(pb::sealable::Value::Plain(b"[unreadable:user:1]".to_vec()))
        );
    }
}
