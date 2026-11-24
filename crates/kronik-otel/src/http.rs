//! The HTTP pieces the exporters share (m28-otel §3.6, §4.4): a POST
//! through `Env::net` with a timeout, extra headers from an environment
//! variable, `Retry-After`, and the scheme and host a status may show.

use std::time::Duration;

use bytes::Bytes;
use kronik_core::authority::AuthLease;
use kronik_core::env::{Env, HttpRequest, HttpResponse, NetError};
use kronik_sched::Node;

/// A collector or webhook slower than this counts as a failed attempt.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The POST every exporter sends: `content-type` last of the headers, and a
/// response of at most 1 MiB.
fn post_request(
    url: String,
    mut headers: Vec<(String, String)>,
    content_type: &str,
    body: Bytes,
) -> HttpRequest {
    headers.push(("content-type".into(), content_type.into()));
    HttpRequest {
        method: "POST".into(),
        url,
        headers,
        body,
        max_response_bytes: 1 << 20,
    }
}

/// `request` through `env.net` as `original`, with `timeout` for the whole
/// exchange. The error is a status code: `connect` (not sent), `io` (maybe
/// delivered) or `timeout`.
async fn send(
    env: &Env,
    timeout: Duration,
    request: HttpRequest,
    original: AuthLease,
) -> Result<HttpResponse, &'static str> {
    let exchange = env.net.http_authorized(request, original);
    match env.timeout(timeout, exchange).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(NetError::Connect(_))) => Err("connect"),
        Ok(Err(NetError::Io(_) | NetError::TooLarge)) => Err("io"),
        Err(_) => Err("timeout"),
    }
}

/// POSTs `body`. The error is a status code: `connect` (not sent), `io`
/// (maybe delivered), `timeout`, or the actual original-admission error code.
pub async fn post(
    node: &Node,
    url: String,
    headers: Vec<(String, String)>,
    content_type: &str,
    body: Bytes,
    original: AuthLease,
) -> Result<HttpResponse, &'static str> {
    let req = post_request(url, headers, content_type, body);
    let env = node.env().clone();
    let deadline = env.clock.monotonic().saturating_add(TIMEOUT);
    let owned_env = env.clone();
    let work = node.authorized_effect(original.clone(), move || async move {
        let remaining = deadline.saturating_sub(owned_env.clock.monotonic());
        if remaining.is_zero() {
            return Ok(Err("timeout"));
        }
        Ok(send(&owned_env, remaining, req, original).await)
    });
    match env.timeout(TIMEOUT, work).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.code.as_str()),
        Err(_) => Err("timeout"),
    }
}

/// Actor-free delivery from an existing owned export job. The same original
/// admits Net's actual final enqueue; the total timeout includes response EOF.
/// Root Net returns buffered bytes, so no body adapter or second client is used.
pub async fn post_authorized(
    env: &Env,
    url: String,
    headers: Vec<(String, String)>,
    content_type: &str,
    body: Bytes,
    original: AuthLease,
) -> Result<HttpResponse, &'static str> {
    let request = post_request(url, headers, content_type, body);
    match send(env, TIMEOUT, request, original).await {
        Ok(response) if response.body.len() <= 1 << 20 => Ok(response),
        Ok(_) => Err("io"),
        Err(code) => Err(code),
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
    let Ok(parsed) = url.parse::<http::Uri>() else {
        return String::new();
    };
    let (Some(scheme), Some(authority)) = (parsed.scheme_str(), parsed.authority()) else {
        return String::new();
    };
    let host = authority.host();
    let host_port = authority.as_str().rsplit('@').next().unwrap_or_default();
    // URI authorities permit opaque ports; a credential prefix is not a displayable host.
    if host.is_empty() || (authority.port().is_none() && host_port != host) {
        return String::new();
    }
    let port = authority
        .port()
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    format!("{scheme}://{host}{port}")
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
    use kronik_core::authority::Authority;
    use kronik_core::env::{BoxFuture, Net};
    use kronik_core::error::ApiError;
    use std::sync::{Arc, Mutex};

    const URL: &str = "http://collector.test/v1/traces";

    #[test]
    fn urls_show_scheme_and_host_only() {
        assert_eq!(
            scheme_host("https://user:pw@hooks.example.com:8443/t/SECRET?x=1"),
            "https://hooks.example.com:8443"
        );
        assert_eq!(scheme_host("s3://bucket/prefix"), "s3://bucket");
        assert_eq!(scheme_host("nonsense"), "");
        assert_eq!(
            scheme_host("https://user:pw@[::1]:8443/private"),
            "https://[::1]:8443"
        );
        assert_eq!(
            scheme_host("https://USER:pw@Host:443/path"),
            "https://Host:443"
        );
        for malformed in [
            "https://u:p/ss@h/",
            "https://u:NEEDLE?secret@host/",
            "https://u:NEEDLE#secret@host/",
            "https://u:NEEDLE\\secret@host/",
            "https://u:NEEDLE%2fsecret@host:bad/",
            "https://NEEDLE:NEEDLE/path@host/",
        ] {
            assert_eq!(scheme_host(malformed), "");
        }
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

    /// A network that answers each authorized request with the queued
    /// answer (`Io("hang")`: never) and keeps the requests it had.
    #[derive(Default)]
    struct Answered {
        answer: Mutex<Option<Result<HttpResponse, NetError>>>,
        requests: Mutex<Vec<HttpRequest>>,
    }

    impl Net for Answered {
        fn http(&self, _req: HttpRequest) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            Box::pin(async { Err(NetError::Connect("unused".into())) })
        }
        fn http_authorized(
            &self,
            req: HttpRequest,
            _original: AuthLease,
        ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            self.requests.lock().unwrap().push(req);
            let answer = self.answer.lock().unwrap().take();
            Box::pin(async move {
                if matches!(&answer, Some(Err(NetError::Io(m))) if m == "hang") {
                    std::future::pending::<()>().await;
                }
                answer.unwrap_or(Err(NetError::Connect("no answer queued".into())))
            })
        }
    }

    /// Admits every effect: what a test sees is its network's answer.
    struct Open;

    impl Authority for Open {
        fn check(&self) -> Result<(), ApiError> {
            Ok(())
        }
        fn cancelled(&self) -> BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
        fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
            effect()
        }
    }

    /// A real environment whose network is the returned [`Answered`].
    fn answered() -> (Env, Arc<Answered>) {
        let mut env = Env::real(tokio::runtime::Handle::current());
        let net = Arc::new(Answered::default());
        env.net = net.clone();
        (env, net)
    }

    fn response(status: u16, body: Bytes) -> Result<HttpResponse, NetError> {
        Ok(HttpResponse {
            status,
            headers: Vec::new(),
            body,
        })
    }

    #[tokio::test]
    async fn a_post_is_content_type_last_with_a_1_mib_response_cap() {
        let (env, net) = answered();
        let post = || {
            post_authorized(
                &env,
                URL.into(),
                vec![("x-id".to_owned(), "1".to_owned())],
                "application/json",
                Bytes::from_static(b"body"),
                Arc::new(Open),
            )
        };
        *net.answer.lock().unwrap() = Some(response(204, Bytes::new()));
        assert_eq!(post().await.map(|r| r.status), Ok(204));
        let request = net.requests.lock().unwrap().remove(0);
        assert_eq!(
            (
                request.method.as_str(),
                request.url.as_str(),
                request.body.as_ref(),
                request.max_response_bytes
            ),
            ("POST", URL, &b"body"[..], 1 << 20)
        );
        assert_eq!(
            request.headers,
            [
                ("x-id".to_owned(), "1".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned())
            ]
        );
        // A network that hands back more than the cap asked for: `io`.
        *net.answer.lock().unwrap() = Some(response(204, Bytes::from(vec![b'x'; (1 << 20) + 1])));
        assert_eq!(post().await.map(|r| r.status), Err("io"));
    }

    #[tokio::test]
    async fn a_failed_post_is_connect_io_or_timeout() {
        let (env, net) = answered();
        let original: AuthLease = Arc::new(Open);
        // `connect` is the one outcome that says the request never left.
        for (answer, code) in [
            (response(200, Bytes::new()), None),
            (Err(NetError::Connect("refused".into())), Some("connect")),
            (Err(NetError::Io("reset".into())), Some("io")),
            (Err(NetError::TooLarge), Some("io")),
            (Err(NetError::Io("hang".into())), Some("timeout")),
        ] {
            *net.answer.lock().unwrap() = Some(answer);
            let request = post_request(URL.into(), Vec::new(), "text/plain", Bytes::new());
            let status = send(&env, Duration::from_millis(100), request, original.clone())
                .await
                .map(|r| r.status);
            assert_eq!(status, code.map_or(Ok(200), Err), "{code:?}");
        }
    }
}
