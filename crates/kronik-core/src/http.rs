//! HTTP rules the gateway, the API and the foreign-actor bridge share.

/// Headers that belong to one connection (RFC 9110 §7.6.1), plus
/// `Content-Length`, which the sender computes from the body. Neither an
/// actor's response nor a request Kronik forwards may carry them: on a
/// keep-alive connection a false length lets one message spill into the next.
pub fn hop_by_hop(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "transfer-encoding"
            | "content-length"
            | "upgrade"
            | "te"
            | "trailer"
    ) || name.starts_with("proxy-")
}

/// Whether a header carries a credential: `Authorization` in any spelling,
/// `X-Auth`, a cookie, an API or access key, a session id, a JWT, a
/// password, a token or a secret, and `Sec-WebSocket-Protocol`, where
/// browsers' WebSocket clients put bearer tokens because they cannot set
/// `Authorization` (M24). The API shows their values only to callers with
/// `pii:read`. It over-matches on purpose (`x-session-affinity`).
pub fn credential_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
        "sec-websocket-protocol",
        "x-auth",
        "cookie",
        "api-key",
        "apikey",
        "api_key",
        "access-key",
        "session",
        "jwt",
        "password",
    ]
    .iter()
    .any(|k| name.contains(k))
        || name.ends_with("token")
        || name.ends_with("secret")
}

/// Percent-encodes a path segment or a query value: everything except
/// unreserved characters (RFC 3986). The API server builds its URLs with it,
/// and so does the client the CLI uses against that server.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-decodes a path segment or a query value. `plus_is_space` says
/// whether `+` stands for a space (`application/x-www-form-urlencoded`);
/// in a path it is a literal character (RFC 3986 §3.3), so an actor key
/// `a+b` arrives as `a+b`.
pub fn percent_decode(s: &str, plus_is_space: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// After a failed `accept()` (EMFILE when the descriptors run out, say): a
/// warning and a pause that doubles from 10 ms to about a second, instead
/// of ending the server. `failures` counts the failures in a row.
// The accept loops this serves are the production boundary, like the API
// and gateway servers' own loops, which allow tokio directly.
#[allow(clippy::disallowed_methods)]
#[cfg(feature = "real")]
pub async fn pause_after_accept_error(failures: &mut u32, error: &std::io::Error, listener: &str) {
    tracing::warn!(%error, listener, "accept failed; retrying");
    let pause = std::time::Duration::from_millis(10 << (*failures).min(7));
    *failures += 1;
    tokio::time::sleep(pause).await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_encoding_round_trips() {
        for (raw, encoded) in [
            ("main:12", "main%3A12"),
            ("a b/c?d&e", "a%20b%2Fc%3Fd%26e"),
            ("ok-._~09AZ", "ok-._~09AZ"),
            ("ä", "%C3%A4"),
        ] {
            assert_eq!(super::percent_encode(raw), encoded);
            assert_eq!(super::percent_decode(encoded, false).as_deref(), Some(raw));
        }
        assert_eq!(super::percent_decode("a+b", false).as_deref(), Some("a+b"));
        assert_eq!(super::percent_decode("a+b", true).as_deref(), Some("a b"));
        assert_eq!(super::percent_decode("%2", false), None);
    }

    #[test]
    fn hop_by_hop_headers() {
        for name in [
            "Connection",
            "content-length",
            "Transfer-Encoding",
            "proxy-authorization",
        ] {
            assert!(super::hop_by_hop(name), "{name}");
        }
        for name in ["content-type", "set-cookie", "host", "x-proxy"] {
            assert!(!super::hop_by_hop(name), "{name}");
        }
    }

    #[test]
    fn credential_headers() {
        for name in [
            "Authorization",
            "proxy-authorization",
            "x-authorization",
            "cookie",
            "Set-Cookie",
            "x-api-key",
            "x-session-id",
            "cf-access-jwt-assertion",
            "x-refresh-token",
            "x-client-secret",
            "X-Auth",
            "x-access-key",
            "x-password",
            "proxy-password",
            "Sec-WebSocket-Protocol",
        ] {
            assert!(super::credential_header(name), "{name}");
        }
        for name in ["content-type", "location", "x-request-id", "etag"] {
            assert!(!super::credential_header(name), "{name}");
        }
    }
}
