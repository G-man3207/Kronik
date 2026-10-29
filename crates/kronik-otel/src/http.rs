//! The HTTP pieces the exporters share (m28-otel §3.6, §4.4): a POST
//! through `Env::net` with a timeout, extra headers from an environment
//! variable, `Retry-After`, and the scheme and host a status may show.

use std::time::Duration;

use bytes::Bytes;
use kronik_core::env::{Env, HttpRequest, HttpResponse, NetError};

/// A collector or webhook slower than this counts as a failed attempt.
const TIMEOUT: Duration = Duration::from_secs(30);

/// POSTs `body`. The error is a status code: `connect` (not sent), `io`
/// (maybe delivered) or `timeout`.
pub async fn post(
    env: &Env,
    url: String,
    mut headers: Vec<(String, String)>,
    content_type: &str,
    body: Vec<u8>,
) -> Result<HttpResponse, &'static str> {
    headers.push(("content-type".into(), content_type.into()));
    let req = HttpRequest {
        method: "POST".into(),
        url,
        headers,
        body: Bytes::from(body),
        max_response_bytes: 1 << 20,
    };
    match env.timeout(TIMEOUT, env.net.http(req)).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(NetError::Connect(_))) => Err("connect"),
        Ok(Err(NetError::Io(_) | NetError::TooLarge)) => Err("io"),
        Err(_) => Err("timeout"),
    }
}

/// Extra headers, `key=value,…` as `OTEL_EXPORTER_OTLP_HEADERS` writes
/// them, from the variable `var` names. Unset is none.
///
/// shortcut: values are taken as written, without the spec's percent
/// decoding; decode them if a vendor's token needs a `,` or `=`.
pub fn env_headers(var: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let Some(var) = var else {
        return Ok(Vec::new());
    };
    let Ok(text) = std::env::var(var) else {
        return Ok(Vec::new());
    };
    parse_headers(var, &text)
}

/// `text` as `key=value,…`. An error names the variable and the pair's
/// position, never its text: it is usually a credential, and the error
/// reaches the daemon's log (review M9).
fn parse_headers(var: &str, text: &str) -> Result<Vec<(String, String)>, String> {
    text.split(',')
        .filter(|p| !p.trim().is_empty())
        .enumerate()
        .map(|(i, p)| {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| format!("${var}: header {} is not key=value", i + 1))?;
            Ok((k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        })
        .collect()
}

/// `Retry-After` in seconds.
///
/// shortcut: the HTTP-date form is ignored (the backoff applies); parse it
/// if a collector sends dates.
pub fn retry_after(resp: &HttpResponse) -> Option<Duration> {
    resp.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .map(Duration::from_secs)
}

/// `scheme://host[:port]` of a URL: no user, password, path or query,
/// which can hold credentials (review M6).
pub fn scheme_host(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    format!("{scheme}://{host}")
}

/// The host of an `http://` or `https://` URL, without brackets or port.
pub fn host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    Some(match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    })
}

/// Whether `url`'s host is a loopback address or `localhost`.
pub fn is_loopback(url: &str) -> bool {
    host(url).is_some_and(|h| {
        h.eq_ignore_ascii_case("localhost")
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_show_scheme_and_host_only() {
        assert_eq!(
            scheme_host("https://user:pw@hooks.example.com:8443/t/SECRET?x=1"),
            "https://hooks.example.com:8443"
        );
        assert_eq!(scheme_host("s3://bucket/prefix"), "s3://bucket");
        assert_eq!(scheme_host("nonsense"), "");
        assert!(is_loopback("http://127.0.0.1:4318"));
        assert!(is_loopback("http://[::1]:4318/"));
        assert!(is_loopback("http://localhost"));
        assert!(!is_loopback("http://collector.internal:4318"));
        assert!(!is_loopback("http://10.0.0.1"));
    }

    #[test]
    fn retry_after_is_seconds() {
        let resp = |v: &str| HttpResponse {
            status: 429,
            headers: vec![("Retry-After".into(), v.into())],
            body: Bytes::new(),
        };
        assert_eq!(retry_after(&resp("7")), Some(Duration::from_secs(7)));
        assert_eq!(retry_after(&resp("Wed, 21 Oct 2015 07:28:00 GMT")), None);
    }

    #[test]
    fn a_malformed_header_names_its_position_not_its_text() {
        let ok = parse_headers("V", "a=1, b = 2 ,").unwrap();
        assert_eq!(ok, [("a".into(), "1".into()), ("b".into(), "2".into())]);
        let e = parse_headers("V", "x-id=1,authorization: Bearer NEEDLE").unwrap_err();
        assert_eq!(e, "$V: header 2 is not key=value");
    }
}
