//! `privacy.subject_from`: the default subject of HTTP root inputs, read
//! from a request header (`header:x-user-id`) or from a claim of the bearer
//! JWT in `Authorization` (`jwt:sub`).
//!
//! Kronik v0.1 does not verify the JWT's signature, it only reads the claim.
//! Whoever can send a request can therefore choose its subject. The subject
//! tags data for privacy mode (sealing, erasure); it does not authenticate
//! anyone.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kronik_privacy::keystore::valid_subject;

/// Where a request's subject comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectFrom {
    /// A header, by lowercase name.
    Header(String),
    /// A claim of the unverified bearer JWT.
    JwtClaim(String),
}

impl SubjectFrom {
    /// `header:<name>` or `jwt:<claim>`.
    pub fn parse(spec: &str) -> Option<SubjectFrom> {
        let valid = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && b != b':');
        match spec.split_once(':')? {
            ("header", name) if valid(name) => Some(SubjectFrom::Header(name.to_ascii_lowercase())),
            ("jwt", claim) if valid(claim) => Some(SubjectFrom::JwtClaim(claim.to_owned())),
            _ => None,
        }
    }

    /// The request's subject: `None` when the header, the bearer token or
    /// the claim is absent. An error says why a present one is unusable.
    /// The header carrying the subject must appear once with one value: a
    /// proxy that appends to a client's header instead of replacing it
    /// would otherwise let the client choose the subject.
    pub fn subject(&self, headers: &[(String, String)]) -> Result<Option<String>, String> {
        let header = |name: &str| -> Result<Option<&str>, String> {
            let mut found = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name));
            let first = found.next().map(|(_, v)| v.trim());
            if found.next().is_some() {
                return Err(format!("the header {name} must appear only once"));
            }
            if first.is_some_and(|v| v.contains(',')) {
                return Err(format!("the header {name} must hold one value, not a list"));
            }
            Ok(first)
        };
        let subject = match self {
            SubjectFrom::Header(name) => match header(name)? {
                None | Some("") => return Ok(None),
                Some(v) => v.to_owned(),
            },
            SubjectFrom::JwtClaim(claim) => {
                let Some(token) = header("authorization")?.and_then(|v| {
                    v.split_once(' ')
                        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                        .map(|(_, t)| t.trim())
                }) else {
                    return Ok(None);
                };
                match jwt_claim(token, claim)? {
                    Some(v) => v,
                    None => return Ok(None),
                }
            }
        };
        if !valid_subject(&subject) {
            return Err(format!(
                "the subject {subject:?} from {} must be 1 to 256 bytes of printable ASCII without spaces",
                self.source()
            ));
        }
        Ok(Some(subject))
    }

    pub(crate) fn source(&self) -> String {
        match self {
            SubjectFrom::Header(name) => format!("header {name}"),
            SubjectFrom::JwtClaim(claim) => format!("JWT claim {claim}"),
        }
    }
}

/// The claim from the token's payload, unverified. Strings are taken as
/// they are and integers in decimal; other types are errors.
fn jwt_claim(token: &str, claim: &str) -> Result<Option<String>, String> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the bearer token is not a JWT (header.payload.signature)".into());
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "the bearer JWT's payload is not base64url".to_owned())?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| "the bearer JWT's payload is not JSON".to_owned())?;
    match json.get(claim) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(serde_json::Value::Number(n)) if n.is_u64() || n.is_i64() => Ok(Some(n.to_string())),
        Some(_) => Err(format!(
            "the bearer JWT's claim {claim:?} is neither a string nor an integer"
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn jwt(payload: &str) -> String {
        format!(
            "eyJhbGciOiJIUzI1NiJ9.{}.c2lnbmF0dXJl",
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn specs_parse() {
        assert_eq!(
            SubjectFrom::parse("header:X-User-Id"),
            Some(SubjectFrom::Header("x-user-id".into()))
        );
        assert_eq!(
            SubjectFrom::parse("jwt:sub"),
            Some(SubjectFrom::JwtClaim("sub".into()))
        );
        for bad in [
            "cookie:id",
            "header:",
            "jwt:",
            "header",
            "header:a b",
            "jwt:a:b",
        ] {
            assert_eq!(SubjectFrom::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_header_gives_the_subject() {
        let from = SubjectFrom::parse("header:x-user-id").unwrap();
        assert_eq!(
            from.subject(&headers(&[("X-User-Id", " user:123 ")]))
                .unwrap()
                .as_deref(),
            Some("user:123")
        );
        assert_eq!(from.subject(&headers(&[("other", "x")])).unwrap(), None);
        assert_eq!(from.subject(&headers(&[("x-user-id", "")])).unwrap(), None);
        let err = from
            .subject(&headers(&[("x-user-id", "two words")]))
            .unwrap_err();
        assert!(err.contains("header x-user-id"), "{err}");
    }

    #[test]
    fn the_jwt_claim_is_read_without_verification() {
        let from = SubjectFrom::parse("jwt:sub").unwrap();
        let auth = |t: String| headers(&[("Authorization", &format!("Bearer {t}"))]);
        assert_eq!(
            from.subject(&auth(jwt(r#"{"sub":"user:7","iat":1}"#)))
                .unwrap()
                .as_deref(),
            Some("user:7")
        );
        assert_eq!(
            from.subject(&auth(jwt(r#"{"sub":42}"#)))
                .unwrap()
                .as_deref(),
            Some("42")
        );
        // Padding is tolerated; the signature is never checked.
        let padded = format!(
            "{}=",
            jwt(r#"{"sub":"user:8"}"#).replace(".c2lnbmF0dXJl", "")
        );
        assert_eq!(
            from.subject(&auth(format!("{padded}.x")))
                .unwrap()
                .as_deref(),
            Some("user:8")
        );
        assert_eq!(from.subject(&auth(jwt(r#"{"iat":1}"#))).unwrap(), None);
        assert_eq!(from.subject(&headers(&[])).unwrap(), None);
        assert_eq!(
            from.subject(&headers(&[("authorization", "Basic dXNlcjpwdw==")]))
                .unwrap(),
            None
        );
        assert!(
            from.subject(&auth("opaque-token".into()))
                .unwrap_err()
                .contains("not a JWT")
        );
        assert!(
            from.subject(&auth("a.%%%.c".into()))
                .unwrap_err()
                .contains("base64url")
        );
        assert!(from.subject(&auth(jwt("[1]"))).is_ok_and(|s| s.is_none()));
        assert!(
            from.subject(&auth(jwt("not json")))
                .unwrap_err()
                .contains("not JSON")
        );
        assert!(
            from.subject(&auth(jwt(r#"{"sub":{"a":1}}"#)))
                .unwrap_err()
                .contains("neither")
        );
    }

    /// A proxy that appends instead of replacing must not let the client
    /// choose: a repeated or list-valued subject header is refused.
    #[test]
    fn a_repeated_subject_header_is_refused() {
        let from = SubjectFrom::parse("header:x-user-id").unwrap();
        let err = from
            .subject(&headers(&[
                ("x-user-id", "user:evil"),
                ("X-User-Id", "user:1"),
            ]))
            .unwrap_err();
        assert!(err.contains("only once"), "{err}");
        let err = from
            .subject(&headers(&[("x-user-id", "user:evil,user:1")]))
            .unwrap_err();
        assert!(err.contains("one value"), "{err}");
        let jwt_from = SubjectFrom::parse("jwt:sub").unwrap();
        let t = format!("Bearer {}", jwt(r#"{"sub":"user:7"}"#));
        assert!(
            jwt_from
                .subject(&headers(&[("authorization", &t), ("authorization", &t)]))
                .is_err()
        );
    }
}
