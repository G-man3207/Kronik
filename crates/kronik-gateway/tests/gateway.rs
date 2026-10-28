//! Gateway service-function tests on the real environment.

// Test helpers outside #[test] functions may unwrap too, and a test spawns
// a request on the test runtime.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use kronik_core::env::{BoxFuture, Env};
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::{ActorRef, TurnId};
use kronik_gateway::subject::SubjectFrom;
use kronik_gateway::{
    Gateway, GatewayConfig, HttpRequest, HttpResponse, PreviewRouter, TURN_ID_HEADER,
};
use kronik_proto::log::v1 as pb;
use kronik_sched::{Node, NodeConfig, RouteEntry, TurnResult, start_local};

const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);

async fn node(dir: &std::path::Path) -> Arc<Node> {
    let env = Env::real(tokio::runtime::Handle::current());
    let node = start_local(env, dir, NodeConfig::default()).await.unwrap();
    let audit = pb::Audit {
        token_id: "t".into(),
        reason: "test".into(),
        wall_time_ms: 0,
    };
    node.deploy(&std::fs::read(COUNTER).unwrap(), audit, false)
        .await
        .unwrap();
    node
}

fn post(path: &str, key: Option<&str>, body: &[u8]) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        path: path.into(),
        query: String::new(),
        headers: key
            .map(|k| vec![("Idempotency-Key".to_string(), k.to_string())])
            .unwrap_or_default(),
        body: body.to_vec(),
        peer: None,
    }
}

fn header<'a>(r: &'a HttpResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn code(r: &HttpResponse) -> String {
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    v["error"]["code"].as_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_outcomes_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    let gw = Gateway::new(node.clone(), GatewayConfig::default());

    let r = gw.handle(post("/counter/a/increment", None, b"")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"1");
    assert!(header(&r, TURN_ID_HEADER).unwrap().starts_with("main:"));

    let get = HttpRequest {
        method: "GET".into(),
        path: "/counter/a".into(),
        query: String::new(),
        headers: vec![],
        body: vec![],
        peer: None,
    };
    let r = gw.handle(get).await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"1".as_slice()));

    let r = gw.handle(post("/counter/a/fail", None, b"")).await;
    assert_eq!(r.status, 500);
    assert_eq!(code(&r), "TURN_FAILED");
    let turn = header(&r, TURN_ID_HEADER).unwrap();
    let body = String::from_utf8(r.body.clone()).unwrap();
    assert!(body.contains(turn), "{body}");
    // HTTP failures are not dead letters (the client got the error).
    assert!(node.store().db().dead_letters(0, 10).unwrap().is_empty());

    let r = gw.handle(post("/nothing/here", None, b"")).await;
    assert_eq!((r.status, code(&r)), (404, "ROUTE_NOT_FOUND".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_subject_from_a_header_or_jwt_tags_the_root_input() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    let recorded = |r: &HttpResponse| {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let id = header(r, TURN_ID_HEADER).unwrap();
        let lsn: u64 = id.rsplit(':').next().unwrap().parse().unwrap();
        let node = node.clone();
        async move {
            let c = node.read_record(lsn).await.unwrap().unwrap();
            let kronik_proto::Record::TurnRecord(t) = c.record else {
                panic!("not a turn: {:?}", c.record)
            };
            let Some(pb::input::Kind::Http(http)) = t.input.and_then(|i| i.kind) else {
                panic!("not an HTTP input")
            };
            http
        }
    };
    let by_header = Gateway::new(
        node.clone(),
        GatewayConfig {
            subject_from: SubjectFrom::parse("header:x-user-id"),
            ..GatewayConfig::default()
        },
    );
    let mut req = post("/counter/a/increment", None, b"hello");
    req.headers.push(("X-User-Id".into(), "user:123".into()));
    let http = recorded(&by_header.handle(req).await).await;
    let pb::body::Value::Inline(body) = http.body.unwrap().value.unwrap() else {
        panic!("not inline")
    };
    assert_eq!(body.subject.as_deref(), Some("user:123"));
    assert!(
        http.headers
            .iter()
            .all(|h| h.value.as_ref().unwrap().subject.as_deref() == Some("user:123"))
    );

    // Without the header, the input carries no subject.
    let http = recorded(
        &by_header
            .handle(post("/counter/a/increment", None, b""))
            .await,
    )
    .await;
    let pb::body::Value::Inline(body) = http.body.unwrap().value.unwrap() else {
        panic!("not inline")
    };
    assert_eq!(body.subject, None);

    // An unusable subject is the client's error.
    let mut req = post("/counter/a/increment", None, b"");
    req.headers.push(("x-user-id".into(), "two words".into()));
    let r = by_header.handle(req).await;
    assert_eq!((r.status, code(&r)), (400, "BAD_REQUEST".to_string()));

    // The JWT's claim is read, not verified.
    let by_jwt = Gateway::new(
        node.clone(),
        GatewayConfig {
            subject_from: SubjectFrom::parse("jwt:sub"),
            ..GatewayConfig::default()
        },
    );
    let mut req = post("/counter/b/increment", None, b"x");
    // {"alg":"none"}.{"sub":"user:7"}.forged
    req.headers.push((
        "Authorization".into(),
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyOjcifQ.forged".into(),
    ));
    let http = recorded(&by_jwt.handle(req).await).await;
    let pb::body::Value::Inline(body) = http.body.unwrap().value.unwrap() else {
        panic!("not inline")
    };
    assert_eq!(body.subject.as_deref(), Some("user:7"));
}

/// With `trusted_proxies`, only a trusted proxy may set the subject: a peer
/// outside them could choose any subject, so its request with a subject
/// header (or bearer claim) is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_trusted_proxies_set_the_subject_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    let subject_of = |r: HttpResponse| {
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let lsn: u64 = header(&r, TURN_ID_HEADER)
            .unwrap()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let node = node.clone();
        async move {
            let c = node.read_record(lsn).await.unwrap().unwrap();
            let kronik_proto::Record::TurnRecord(t) = c.record else {
                panic!("not a turn")
            };
            let Some(pb::input::Kind::Http(http)) = t.input.and_then(|i| i.kind) else {
                panic!("not HTTP")
            };
            let pb::body::Value::Inline(body) = http.body.unwrap().value.unwrap() else {
                panic!("not inline")
            };
            body.subject
        }
    };
    let gw = Gateway::new(
        node.clone(),
        GatewayConfig {
            subject_from: SubjectFrom::parse("header:x-user-id"),
            trusted_proxies: vec![kronik_gateway::IpNet::parse("10.0.0.0/8").unwrap()],
            ..GatewayConfig::default()
        },
    );
    let req = |peer: &str| {
        let mut r = post("/counter/a/increment", None, b"");
        r.headers.push(("x-user-id".into(), "user:1".into()));
        r.peer = Some(peer.parse().unwrap());
        r
    };
    assert_eq!(
        subject_of(gw.handle(req("10.1.2.3")).await)
            .await
            .as_deref(),
        Some("user:1")
    );
    assert_eq!(
        subject_of(gw.handle(req("::ffff:10.1.2.3")).await)
            .await
            .as_deref(),
        Some("user:1")
    );
    // From any other peer, a subject is refused, not dropped: dropped, the
    // data would be stored unsealed and could not be erased.
    let r = gw.handle(req("192.0.2.9")).await;
    assert_eq!((r.status, code(&r)), (400, "BAD_REQUEST".to_string()));
    assert!(String::from_utf8_lossy(&r.body).contains("trusted_proxies"));
    // Without a subject header, such a peer's request runs as before.
    let mut plain = post("/counter/a/increment", None, b"");
    plain.peer = Some("192.0.2.9".parse().unwrap());
    assert_eq!(subject_of(gw.handle(plain).await).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_then_retry_gives_one_turn_and_the_same_response() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    // A zero timeout loses to the timer only while the turn is still
    // queued: the gateway's wait checks the result first, so a turn that
    // already finished would answer. Keep the actor busy with a turn that
    // spins until its fuel runs out, so the request waits behind it.
    let impatient = Gateway::new(
        node.clone(),
        GatewayConfig {
            timeout: Duration::ZERO,
            ..GatewayConfig::default()
        },
    );
    let gw = Gateway::new(node.clone(), GatewayConfig::default());
    let busy = {
        let gw = Gateway::new(node.clone(), GatewayConfig::default());
        tokio::spawn(async move { gw.handle(post("/counter/a/spin", None, b"")).await })
    };
    // Wait until the spinning turn runs.
    while node
        .probe
        .turns_run
        .load(std::sync::atomic::Ordering::Relaxed)
        == 0
    {
        tokio::task::yield_now().await;
    }

    let first = impatient
        .handle(post("/counter/a/increment", Some("k1"), b"x"))
        .await;
    assert_eq!(first.status, 504);
    assert_eq!(code(&first), "GATEWAY_TIMEOUT");
    let _ = busy.await;

    let retry = gw
        .handle(post("/counter/a/increment", Some("k1"), b"x"))
        .await;
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, b"1");
    let again = gw
        .handle(post("/counter/a/increment", Some("k1"), b"x"))
        .await;
    assert_eq!(again, retry);

    let reused = gw
        .handle(post("/counter/a/increment", Some("k1"), b"y"))
        .await;
    assert_eq!(
        (reused.status, code(&reused)),
        (422, "IDEMPOTENCY_KEY_REUSED".to_string())
    );

    // Exactly one turn ran for the key (plus the spinning one).
    let actor = node.store().db().actor("counter", "a").unwrap().unwrap();
    assert_eq!(actor.turns, 2);
    // The same key on another actor is a different request.
    let other = gw
        .handle(post("/counter/b/increment", Some("k1"), b"x"))
        .await;
    assert_eq!(other.status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configured_idempotency_header_is_the_only_one_read() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    let gw = Gateway::new(
        node.clone(),
        GatewayConfig {
            idempotency_header: "X-Idem".into(),
            ..GatewayConfig::default()
        },
    );
    let mut first = post("/counter/a/increment", None, b"same");
    first.headers.push(("X-Idem".into(), "k".into()));
    let a = gw.handle(first).await;
    assert_eq!(a.status, 200, "{}", String::from_utf8_lossy(&a.body));
    let turns = node
        .store()
        .db()
        .actor("counter", "a")
        .unwrap()
        .unwrap()
        .turns;
    let mut again = post("/counter/a/increment", None, b"same");
    again.headers.push(("x-idem".into(), "k".into()));
    let b = gw.handle(again).await;
    assert_eq!(b.body, a.body);
    assert_eq!(
        node.store()
            .db()
            .actor("counter", "a")
            .unwrap()
            .unwrap()
            .turns,
        turns,
        "a repeat with the configured header created another turn"
    );
    // The default name is not the configured header, so it is ignored.
    let ignored = gw
        .handle(post("/counter/a/increment", Some("k"), b"other"))
        .await;
    assert_eq!(
        ignored.status,
        200,
        "{}",
        String::from_utf8_lossy(&ignored.body)
    );
    assert_ne!(ignored.body, a.body);
    assert!(
        node.store()
            .db()
            .actor("counter", "a")
            .unwrap()
            .unwrap()
            .turns
            > turns
    );
}

fn plain(b: &[u8]) -> Option<pb::Sealable> {
    Some(pb::Sealable {
        subject: None,
        value: Some(pb::sealable::Value::Plain(b.to_vec())),
    })
}

/// One preview, `v-1`, whose code answers every request with a cookie and
/// headers acting on the origin; it keeps the inputs it gets.
#[derive(Default)]
struct CookiePreview(std::sync::Mutex<Vec<pb::HttpInput>>);

impl PreviewRouter for CookiePreview {
    fn routes(&self, id: &str) -> BoxFuture<'_, Result<Vec<RouteEntry>, ApiError>> {
        let found = id == "v-1";
        Box::pin(async move {
            if !found {
                return Err(ApiError::new(ErrorCode::PreviewNotFound, "no preview"));
            }
            Ok(vec![RouteEntry {
                kind: "counter".into(),
                method: "POST".into(),
                pattern: "/counter/{key}/{op}".into(),
            }])
        })
    }

    fn send(
        self: Arc<Self>,
        id: String,
        _actor: ActorRef,
        http: pb::HttpInput,
        _subject: Option<String>,
    ) -> BoxFuture<'static, Result<TurnResult, ApiError>> {
        self.0.lock().unwrap().push(http);
        let h = |n: &str, v: &[u8]| pb::Header {
            name: n.into(),
            value: plain(v),
        };
        Box::pin(async move {
            Ok(TurnResult {
                turn_id: TurnId { branch: id, lsn: 1 },
                outcome: pb::Outcome {
                    kind: pb::OutcomeKind::Committed as i32,
                    output: Some(pb::outcome::Output::Http(pb::HttpResponse {
                        status: 200,
                        headers: vec![
                            h("Set-Cookie", b"session=preview"),
                            h("Strict-Transport-Security", b"max-age=0"),
                            h("Clear-Site-Data", b"\"*\""),
                            h("Location", b"https://evil.example/"),
                            h("Content-Type", b"text/html"),
                            h("ETag", b"\"1\""),
                        ],
                        body: Some(pb::Body {
                            value: plain(b"from the preview").map(pb::body::Value::Inline),
                        }),
                    })),
                    ..Default::default()
                },
            })
        })
    }
}

/// P-F1, P-F6, N1-N3: without a preview domain the prefix serves previews,
/// sandboxed, keeping only safe response headers and receiving neither
/// main's cookies nor its authorization; with one, only hosts under it do
/// (any case, port, trailing dot), and the prefix is main's path. No
/// preview input carries an idempotency key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn previews_answer_on_the_prefix_only_without_a_preview_domain() {
    let dir = tempfile::tempdir().unwrap();
    let node = node(dir.path()).await;
    let at = |path: &str, host: &str| {
        let mut r = post(path, Some("k1"), b"");
        r.headers.push(("Host".into(), host.into()));
        r.headers.push(("Cookie".into(), "main=secret".into()));
        r.headers.push(("AUTHORIZATION".into(), "Bearer t".into()));
        r.headers.push(("cookie".into(), "other=1".into()));
        r.headers
            .push(("Proxy-Authorization".into(), "Basic cA==".into()));
        r
    };
    let prefix = "/__preview/v-1/counter/a/increment";

    let seen = Arc::new(CookiePreview::default());
    let gw = Gateway::new(node.clone(), GatewayConfig::default()).with_preview(seen.clone());
    let r = gw.handle(at(prefix, "app.example")).await;
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, b"from the preview".as_slice())
    );
    for dropped in [
        "set-cookie",
        "strict-transport-security",
        "clear-site-data",
        "location",
    ] {
        assert_eq!(header(&r, dropped), None, "{dropped}");
    }
    assert_eq!(header(&r, "content-type"), Some("text/html"));
    assert_eq!(header(&r, "etag"), Some("\"1\""));
    assert!(header(&r, "kronik-turn-id").is_some());
    assert_eq!(header(&r, "content-security-policy"), Some("sandbox"));
    {
        let inputs = seen.0.lock().unwrap();
        let names: Vec<String> = inputs[0]
            .headers
            .iter()
            .map(|h| h.name.to_lowercase())
            .collect();
        assert!(names.contains(&"host".to_owned()), "{names:?}");
        assert!(!names.contains(&"cookie".to_owned()), "{names:?}");
        assert!(!names.contains(&"authorization".to_owned()), "{names:?}");
        assert!(
            !names.contains(&"proxy-authorization".to_owned()),
            "{names:?}"
        );
        assert_eq!(inputs[0].idempotency_key, "");
        assert!(inputs[0].request_hash.is_empty());
    }

    let gw = Gateway::new(
        node.clone(),
        GatewayConfig {
            preview_domain: Some("p.example".into()),
            ..GatewayConfig::default()
        },
    )
    .with_preview(seen.clone());
    let r = gw.handle(at(prefix, "app.example")).await;
    assert_eq!((r.status, code(&r).as_str()), (404, "ROUTE_NOT_FOUND"));
    let r = gw
        .handle(at("/counter/a/increment", "V-1.P.Example.:8443"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(header(&r, "set-cookie"), Some("session=preview"));
    assert_eq!(header(&r, "content-security-policy"), None);
    // Its own origin: credentials for it reach it.
    let last = seen.0.lock().unwrap().last().cloned().unwrap();
    assert!(last.headers.iter().any(|h| h.name == "Cookie"));
    assert!(last.headers.iter().any(|h| h.name == "AUTHORIZATION"));
    assert_eq!(last.idempotency_key, "");
    let r = gw
        .handle(at("/counter/a/increment", "x.v-1.p.example"))
        .await;
    assert_eq!((r.status, code(&r).as_str()), (404, "PREVIEW_NOT_FOUND"));
    // None of it reached main.
    assert!(node.store().db().actor("counter", "a").unwrap().is_none());
}
