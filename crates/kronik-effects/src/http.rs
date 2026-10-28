//! HTTP effect requests: URL parsing, fingerprints and secret scrubbing.

use kronik_proto::log::v1 as pb;

/// Headers left out of the fingerprint by default.
pub const FINGERPRINT_EXCLUDED: &[&str] = &[
    "authorization",
    "cookie",
    "date",
    "idempotency-key",
    "user-agent",
    "x-request-id",
];

/// The parts of an effect URL Kronik needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    /// Lowercase.
    pub host: String,
    /// Only when it differs from the scheme's default.
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

/// Parses `http://`, `https://` and `foreign://` URLs.
pub fn parse_url(url: &str) -> Result<Target, String> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("URL {url:?} has no scheme"))?
        .to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "foreign") {
        return Err(format!("URL scheme {scheme:?} is not supported"));
    }
    let auth = uri
        .authority()
        .ok_or_else(|| format!("URL {url:?} has no host"))?;
    if auth.as_str().contains('@') {
        return Err("credentials in URLs are not allowed; use a secret header".into());
    }
    let default = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    Ok(Target {
        host: auth.host().to_ascii_lowercase(),
        port: uri.port_u16().filter(|p| Some(*p) != default),
        path: if uri.path().is_empty() {
            "/".into()
        } else {
            uri.path().to_owned()
        },
        query: uri.query().unwrap_or("").to_owned(),
        scheme,
    })
}

/// The route pattern of a URL path (docs/design/m3-fork.md §3.5): each
/// segment that is a decimal number, a UUID, 8 or more hex characters, or a
/// mix of letters and 6 or more digits becomes `{}`.
pub fn route_pattern(path: &str) -> String {
    fn variable(seg: &str) -> bool {
        if seg.is_empty() {
            return false;
        }
        let digits = seg.bytes().filter(u8::is_ascii_digit).count();
        let all_digits = digits == seg.len();
        let hex = seg.len() >= 8 && seg.bytes().all(|b| b.is_ascii_hexdigit());
        let uuid = seg.len() == 36
            && seg.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
        let mixed = digits >= 6 && seg.bytes().any(|b| b.is_ascii_alphabetic());
        all_digits || hex || uuid || mixed
    }
    path.split('/')
        .map(|s| if variable(s) { "{}" } else { s })
        .collect::<Vec<_>>()
        .join("/")
}

/// The target of an HTTP effect for approximate matching: method, host and
/// route pattern.
pub fn target_of(req: &pb::HttpEffectRequest) -> Option<(String, String, String)> {
    let t = parse_url(&req.url).ok()?;
    Some((
        req.method.to_ascii_uppercase(),
        t.host,
        route_pattern(&t.path),
    ))
}

/// The fingerprint of an HTTP effect (docs/design/m2-effects.md §3): method,
/// scheme, host, port, path, sorted query parameters, body hash and the
/// non-excluded headers; secrets contribute name and version hash only.
pub fn fingerprint(req: &pb::HttpEffectRequest) -> Result<Vec<u8>, String> {
    let t = parse_url(&req.url)?;
    let mut h = blake3::Hasher::new();
    let mut field = |b: &[u8]| {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    };
    field(b"kronik.fingerprint.http.v1");
    field(req.method.to_ascii_uppercase().as_bytes());
    field(t.scheme.as_bytes());
    field(t.host.as_bytes());
    field(&t.port.unwrap_or(0).to_le_bytes());
    field(t.path.as_bytes());
    let mut query: Vec<&str> = t.query.split('&').filter(|p| !p.is_empty()).collect();
    query.sort_by_key(|p| (p.split_once('=').map_or(*p, |(k, _)| k), *p));
    for q in query {
        field(q.as_bytes());
    }
    field(blake3::hash(&req.body).as_bytes());
    let mut headers: Vec<(String, Vec<u8>)> = req
        .headers
        .iter()
        .filter(|hd| !FINGERPRINT_EXCLUDED.contains(&hd.name.to_ascii_lowercase().as_str()))
        .map(|hd| {
            let v = match &hd.value {
                Some(pb::http_effect_header::Value::Text(t)) => t.as_bytes().to_vec(),
                Some(pb::http_effect_header::Value::Secret(s)) => {
                    let mut v = b"secret:".to_vec();
                    v.extend_from_slice(s.name.as_bytes());
                    v.push(b'@');
                    v.extend_from_slice(&s.version_hash);
                    v
                }
                None => Vec::new(),
            };
            (hd.name.to_ascii_lowercase(), v)
        })
        .collect();
    headers.sort();
    for (n, v) in headers {
        field(n.as_bytes());
        field(&v);
    }
    Ok(h.finalize().as_bytes().to_vec())
}

/// Replaces every exact occurrence of each secret value in `bytes` with
/// `[secret:<name>]`. Values shorter than 4 bytes and the JSON words
/// `true`, `false` and `null` are left alone (they would match by accident
/// and break JSON). One pass over `bytes`, whatever the number of values
/// (every stored version of every secret): equal values count once (the
/// first name wins), the longest value wins where several start, and a
/// marker already written is never matched again.
pub fn scrub(bytes: &[u8], secrets: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut seen = std::collections::HashSet::new();
    let (values, markers): (Vec<&[u8]>, Vec<String>) = secrets
        .iter()
        .filter(|(_, v)| {
            v.len() >= 4
                && v.len() <= bytes.len()
                && !matches!(v.as_slice(), b"true" | b"false" | b"null")
                && seen.insert(v.as_slice())
        })
        .map(|(n, v)| (v.as_slice(), format!("[secret:{n}]")))
        .unzip();
    if values.is_empty() {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let replaced = aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&values)
        .map_err(|e| e.to_string())
        .and_then(|ac| {
            ac.try_replace_all_with_bytes(bytes, &mut out, |m, _, dst| {
                dst.extend_from_slice(markers[m.pattern().as_usize()].as_bytes());
                true
            })
            .map_err(|e| e.to_string())
        });
    match replaced {
        Ok(()) => out,
        // Only past aho-corasick's size limits (gigabytes of values): hide
        // everything rather than leak.
        Err(e) => format!("[secret:scrub failed: {e}]").into_bytes(),
    }
}

/// `scrub` for text.
pub fn scrub_str(s: &str, secrets: &[(String, Vec<u8>)]) -> String {
    String::from_utf8_lossy(&scrub(s.as_bytes(), secrets)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(url: &str, headers: Vec<(&str, &str)>, body: &[u8]) -> pb::HttpEffectRequest {
        pb::HttpEffectRequest {
            method: "POST".into(),
            url: url.into(),
            headers: headers
                .into_iter()
                .map(|(n, v)| pb::HttpEffectHeader {
                    name: n.into(),
                    value: Some(pb::http_effect_header::Value::Text(v.into())),
                })
                .collect(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn fingerprint_normalizes_and_excludes() {
        let a = fingerprint(&req(
            "https://API.example.com:443/p?b=2&a=1",
            vec![("Date", "x"), ("X-A", "1")],
            b"{}",
        ))
        .unwrap();
        let b = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "1"), ("user-agent", "y")],
            b"{}",
        ))
        .unwrap();
        assert_eq!(a, b);
        let c = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "2")],
            b"{}",
        ))
        .unwrap();
        assert_ne!(a, c);
        let d = fingerprint(&req(
            "https://api.example.com/p?a=1&b=2",
            vec![("x-a", "1")],
            b"{ }",
        ))
        .unwrap();
        assert_ne!(a, d);
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://user:pw@x.com/").is_err());
        assert_eq!(parse_url("http://h:8080").unwrap().port, Some(8080));
        assert_eq!(parse_url("http://h:80/a").unwrap().port, None);
    }

    #[test]
    fn route_patterns() {
        assert_eq!(route_pattern("/v1/charges/123"), "/v1/charges/{}");
        assert_eq!(
            route_pattern("/u/550e8400-e29b-41d4-a716-446655440000/x"),
            "/u/{}/x"
        );
        assert_eq!(route_pattern("/obj/deadbeefcafe"), "/obj/{}");
        assert_eq!(route_pattern("/ord/ab123456"), "/ord/{}");
        assert_eq!(route_pattern("/v2/users/me"), "/v2/users/me");
        assert_eq!(route_pattern("/"), "/");
    }

    #[test]
    fn scrubbing() {
        let s = vec![("k".to_string(), b"sk_live_123".to_vec())];
        assert_eq!(
            scrub(b"x sk_live_123 y sk_live_123", &s),
            b"x [secret:k] y [secret:k]"
        );
        assert_eq!(scrub(b"nothing", &s), b"nothing");
        // Versions of one secret, a repeated value, a value inside another,
        // a value that a marker contains ("secret") and a JSON word: one
        // pass, and the JSON stays JSON.
        let s = vec![
            ("k".to_string(), b"sk_live_123".to_vec()),
            ("k".to_string(), b"sk_live_123".to_vec()),
            ("old".to_string(), b"sk_live".to_vec()),
            ("word".to_string(), b"secret".to_vec()),
            ("tiny".to_string(), b"ab".to_vec()),
            ("flag".to_string(), b"true".to_vec()),
        ];
        assert_eq!(
            scrub(b"sk_live_123 sk_live_9 secret ab", &s),
            b"[secret:k] [secret:old]_9 [secret:word] ab"
        );
        assert_eq!(
            scrub(br#"{"ok":true,"key":"sk_live_123"}"#, &s),
            br#"{"ok":true,"key":"[secret:k]"}"#
        );
    }
}
