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
/// password, a token or a secret. The API shows their values only to
/// callers with `pii:read`. It over-matches on purpose (`x-session-affinity`).
pub fn credential_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authorization",
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

#[cfg(test)]
mod tests {
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
        ] {
            assert!(super::credential_header(name), "{name}");
        }
        for name in ["content-type", "location", "x-request-id", "etag"] {
            assert!(!super::credential_header(name), "{name}");
        }
    }
}
