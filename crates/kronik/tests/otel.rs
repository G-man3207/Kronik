//! M28's first acceptance in CI (docs/design/m28-otel.md §8): a real
//! `kronik serve` exports spans to an in-process OTLP/HTTP receiver, and a
//! call through three actors arrives as one connected trace. Also: an
//! incoming `traceparent` is a link on the root, not the trace (review H1);
//! children lie within their parents when both are in one request (review
//! M9); a restart resumes from the cursor; metrics are pushed.

// Test helpers outside #[test] functions may unwrap; the receiver is a
// hyper server on a runtime of its own (a test harness, ADR 0004 §3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt as _, Full};
use kronik_core::ids::hex;
use kronik_otel::otlp::collector::metrics::v1::ExportMetricsServiceRequest;
use kronik_otel::otlp::collector::trace::v1::ExportTraceServiceRequest;
use kronik_otel::otlp::common::v1::any_value::Value as AnyValue;
use kronik_otel::otlp::metrics::v1::{metric, number_data_point};
use kronik_otel::otlp::trace::v1::Span;
use prost::Message as _;
use serde_json::Value;

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---- the receiver ----

#[derive(Default)]
struct Received {
    traces: Mutex<Vec<ExportTraceServiceRequest>>,
    metrics: Mutex<Vec<ExportMetricsServiceRequest>>,
    /// Answer 503 with `Retry-After: 1` while set.
    fail: AtomicBool,
}

impl Received {
    /// Every span received, request by request.
    fn requests(&self) -> Vec<Vec<Span>> {
        self.traces
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                r.resource_spans
                    .iter()
                    .flat_map(|rs| &rs.scope_spans)
                    .flat_map(|ss| ss.spans.clone())
                    .collect()
            })
            .collect()
    }

    /// Each span once (a resent batch repeats the same ids).
    fn spans(&self) -> Vec<Span> {
        let mut seen = BTreeSet::new();
        self.requests()
            .into_iter()
            .flatten()
            .filter(|s| seen.insert((s.trace_id.clone(), s.span_id.clone())))
            .collect()
    }
}

/// A small OTLP/HTTP receiver: `POST /v1/traces` and `/v1/metrics`,
/// decoded with the vendored types.
struct Receiver {
    endpoint: String,
    got: Arc<Received>,
    _rt: tokio::runtime::Runtime,
}

fn receiver() -> Receiver {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let got = Arc::new(Received::default());
    let shared = got.clone();
    rt.spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let got = shared.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let got = got.clone();
                        async move {
                            let path = req.uri().path().to_owned();
                            let body = req.into_body().collect().await?.to_bytes();
                            let status = if got.fail.load(Ordering::SeqCst) {
                                503
                            } else if path == "/v1/traces" {
                                let r = ExportTraceServiceRequest::decode(body).unwrap();
                                got.traces.lock().unwrap().push(r);
                                200
                            } else if path == "/v1/metrics" {
                                let r = ExportMetricsServiceRequest::decode(body).unwrap();
                                got.metrics.lock().unwrap().push(r);
                                200
                            } else {
                                404
                            };
                            Ok::<_, hyper::Error>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/x-protobuf")
                                    .header("retry-after", "1")
                                    .body(Full::new(bytes::Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });
    Receiver {
        endpoint,
        got,
        _rt: rt,
    }
}

// ---- the daemon ----

fn command() -> Command {
    let mut c = Command::new(KRONIK);
    for var in [
        "KRONIK_CONFIG",
        "KRONIK_DATA_DIR",
        "KRONIK_HTTP_LISTEN",
        "KRONIK_ADMIN_LISTEN",
        "KRONIK_API_SOCKET",
        "KRONIK_API_LISTEN",
        "KRONIK_TOKEN",
        "KRONIK_MASTER_KEY_FILE",
        "KRONIK_MASTER_KEY",
        "KRONIK_OTEL_ENDPOINT",
    ] {
        c.env_remove(var);
    }
    // The tests' temporary file system may have less than the reserve.
    c.env("KRONIK_DISK_RESERVE", "0B");
    c.stdin(Stdio::null());
    c
}

/// `kronik serve` from a configuration file with `[otel]` pointing at the
/// receiver; killed when dropped.
struct Daemon {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
    gateway: String,
}

/// Writes `<dir>/kronik.toml` with `[server]` and `sections`, and runs
/// `kronik serve` on it with `envs`, logging to `<dir>/serve.log`.
fn serve(dir: &Path, socket: &Path, gateway: &str, sections: &str, envs: &[(&str, &str)]) -> Child {
    let config = dir.join("kronik.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndata_dir = {:?}\napi_socket = {socket:?}\nhttp_listen = \"{gateway}\"\n\
             admin_listen = \"127.0.0.1:{}\"\n\n{sections}",
            dir.join("data"),
            free_port(),
        ),
    )
    .unwrap();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("serve.log"))
        .unwrap();
    command()
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env("KRONIK_LOG", "warn")
        .envs(envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap()
}

impl Daemon {
    fn start(dir: &Path, endpoint: &str) -> Daemon {
        let otel = format!(
            "[otel]\nendpoint = \"{endpoint}\"\nactor_keys = \"plain\"\n\
             interval = \"100ms\"\nmetrics_interval = \"500ms\"\n"
        );
        Daemon::start_with(dir, &otel, &[])
    }

    /// `kronik serve` with `sections` after `[server]` and `envs` set.
    fn start_with(dir: &Path, sections: &str, envs: &[(&str, &str)]) -> Daemon {
        let socket = dir.join("api.sock");
        let gateway = format!("127.0.0.1:{}", free_port());
        let child = serve(dir, &socket, &gateway, sections, envs);
        let d = Daemon {
            child,
            dir: dir.to_owned(),
            socket,
            gateway,
        };
        let up = (0..600).any(|_| {
            let ok = d.cli(&["--json", "actors", "list"]).status.success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", d.log());
        d
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        command()
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut all = vec!["--json"];
        all.extend_from_slice(args);
        let out = self.cli(&all);
        assert!(out.status.success(), "{args:?}: {out:?}\n{}", self.log());
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("serve.log")).unwrap_or_default()
    }

    /// `POST /counter/a/call` with body `counter/b call`: counter/a calls
    /// counter/b, which calls counter/x. The root turn's id.
    fn three_actors(&self, headers: &[(&str, &str)]) -> String {
        let body = "counter/b call";
        let mut s = TcpStream::connect(&self.gateway).unwrap();
        let extra: String = headers
            .iter()
            .map(|(n, v)| format!("{n}: {v}\r\n"))
            .collect();
        write!(
            s,
            "POST /counter/a/call HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        s.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("reply reply "), "{response}");
        response
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.eq_ignore_ascii_case("kronik-turn-id")
                    .then(|| v.trim().to_owned())
            })
            .unwrap()
    }

    /// The causal root of a turn, from `GET /v1/turns/{id}`.
    fn causal_root(&self, turn: &str) -> String {
        let mut stream = std::os::unix::net::UnixStream::connect(&self.socket).unwrap();
        write!(
            stream,
            "GET /v1/turns/{turn} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (_, body) = response.split_once("\r\n\r\n").unwrap();
        let v: Value = serde_json::from_str(body).unwrap();
        v["causal_key"]["root"].as_str().unwrap().to_owned()
    }

    fn traces_status(&self) -> Value {
        let v = self.json(&["export", "status"]);
        v["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "traces")
            .unwrap()
            .clone()
    }

    /// Waits until the trace cursor reaches the applied LSN.
    fn wait_exported(&self) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let s = self.traces_status();
            if s["cursor"] == s["applied_lsn"] {
                return s;
            }
            assert!(
                Instant::now() < deadline,
                "not exported: {s}\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- checks ----

fn attr<'a>(s: &'a Span, key: &str) -> Option<&'a str> {
    s.attributes
        .iter()
        .find(|a| a.key == key)
        .and_then(|a| a.value.as_ref()?.value.as_ref())
        .and_then(|v| match v {
            AnyValue::StringValue(s) => Some(s.as_str()),
            _ => None,
        })
}

fn link_of(s: &Span) -> Option<(String, String, String)> {
    let l = s.links.first()?;
    let name = l
        .attributes
        .iter()
        .find(|a| a.key == "kronik.link")
        .and_then(|a| match a.value.as_ref()?.value.as_ref()? {
            AnyValue::StringValue(v) => Some(v.clone()),
            _ => None,
        })?;
    Some((hex(&l.trace_id), hex(&l.span_id), name))
}

/// Polls until the root span of `turn` arrived; then its trace.
fn trace_of(got: &Received, d: &Daemon, turn: &str) -> Vec<Span> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let spans = got.spans();
        if let Some(root) = spans
            .iter()
            .find(|s| attr(s, "kronik.turn_id") == Some(turn))
        {
            let trace = root.trace_id.clone();
            return spans.into_iter().filter(|s| s.trace_id == trace).collect();
        }
        assert!(
            Instant::now() < deadline,
            "no span of {turn} arrived\n{}",
            d.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One trace: the causal root as trace id, three turn spans (a, b, x),
/// two `actor.call` spans, one root, every other span's parent in the
/// trace, and each callee linked (`call`) to its caller's effect span.
fn check_three_actors(d: &Daemon, trace: &[Span], turn: &str, traceparent: Option<&str>) {
    let root_id = d.causal_root(turn);
    assert!(
        trace.iter().all(|s| hex(&s.trace_id) == root_id),
        "{trace:#?}"
    );
    let turns: BTreeSet<String> = trace
        .iter()
        .filter(|s| attr(s, "kronik.turn_id").is_some())
        .map(|s| {
            format!(
                "{}/{}",
                attr(s, "kronik.actor.kind").unwrap(),
                attr(s, "kronik.actor.key").unwrap()
            )
        })
        .collect();
    assert_eq!(
        turns,
        ["counter/a", "counter/b", "counter/x"]
            .map(String::from)
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(trace.len(), 5, "{trace:#?}");
    assert_eq!(trace.iter().filter(|s| s.name == "actor.call").count(), 2);
    let ids: BTreeSet<&[u8]> = trace.iter().map(|s| s.span_id.as_slice()).collect();
    let roots: Vec<&Span> = trace
        .iter()
        .filter(|s| s.parent_span_id.is_empty())
        .collect();
    assert_eq!(roots.len(), 1, "{trace:#?}");
    assert_eq!(attr(roots[0], "kronik.turn_id"), Some(turn));
    for s in trace.iter().filter(|s| !s.parent_span_id.is_empty()) {
        assert!(
            ids.contains(s.parent_span_id.as_slice()),
            "{} has no parent in the trace",
            s.name
        );
    }
    for callee in trace
        .iter()
        .filter(|s| attr(s, "kronik.message.source") == Some("call"))
    {
        let parent = trace
            .iter()
            .find(|p| p.span_id == callee.parent_span_id)
            .unwrap();
        assert_eq!(parent.name, "actor.call");
        assert_eq!(
            link_of(callee),
            Some((hex(&parent.trace_id), hex(&parent.span_id), "call".into()))
        );
    }
    // An incoming traceparent is a link on the root, with its two ids
    // (review H1); the trace stays the causal root's.
    let expected = traceparent.map(|tp| {
        let parts: Vec<&str> = tp.split('-').collect();
        (
            parts[1].to_owned(),
            parts[2].to_owned(),
            "traceparent".into(),
        )
    });
    assert_eq!(link_of(roots[0]), expected);
}

/// Within each request, every span lies within its parent (review M9).
fn check_children_inside_parents(requests: &[Vec<Span>]) {
    for spans in requests {
        let by_id: BTreeMap<(&[u8], &[u8]), &Span> = spans
            .iter()
            .map(|s| ((s.trace_id.as_slice(), s.span_id.as_slice()), s))
            .collect();
        for s in spans {
            if let Some(p) = by_id.get(&(s.trace_id.as_slice(), s.parent_span_id.as_slice())) {
                assert!(
                    p.start_time_unix_nano <= s.start_time_unix_nano
                        && s.end_time_unix_nano <= p.end_time_unix_nano,
                    "{} [{}, {}] outside {} [{}, {}]",
                    s.name,
                    s.start_time_unix_nano,
                    s.end_time_unix_nano,
                    p.name,
                    p.start_time_unix_nano,
                    p.end_time_unix_nano
                );
            }
        }
    }
}

#[test]
fn a_call_through_three_actors_reaches_an_otlp_receiver_as_one_trace() {
    let dir = tempfile::tempdir().unwrap();
    let r = receiver();
    let d = Daemon::start(dir.path(), &r.endpoint);
    d.json(&["deploy", COUNTER, "--reason", "otel test"]);

    let plain = d.three_actors(&[]);
    let traced = d.three_actors(&[("traceparent", TRACEPARENT)]);
    let first = trace_of(&r.got, &d, &plain);
    check_three_actors(&d, &first, &plain, None);
    let second = trace_of(&r.got, &d, &traced);
    check_three_actors(&d, &second, &traced, Some(TRACEPARENT));
    assert_ne!(first[0].trace_id, second[0].trace_id);
    check_children_inside_parents(&r.got.requests());

    // A metrics push with a known counter: the turns just run.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let turns = r.got.metrics.lock().unwrap().iter().any(|m| {
            m.resource_metrics
                .iter()
                .flat_map(|rm| &rm.scope_metrics)
                .flat_map(|sm| &sm.metrics)
                .filter(|m| m.name == "kronik_turns_total")
                .any(|m| match &m.data {
                    Some(metric::Data::Sum(sum)) => {
                        sum.is_monotonic
                            && sum.data_points.iter().any(|p| {
                                matches!(p.value, Some(number_data_point::Value::AsInt(n)) if n >= 6)
                            })
                    }
                    _ => false,
                })
        });
        if turns {
            break;
        }
        assert!(Instant::now() < deadline, "no metrics push\n{}", d.log());
        std::thread::sleep(Duration::from_millis(100));
    }

    // A restart resumes from the cursor: what was delivered is not sent
    // again, and a turn the receiver refused before the restart arrives
    // after it.
    let before = d.wait_exported();
    assert!(before["last_success_wall_ms"].is_u64(), "{before}");
    assert_eq!(before["sink"], r.endpoint.as_str());
    r.got.fail.store(true, Ordering::SeqCst);
    let refused = d.three_actors(&[]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while d.traces_status()["last_error"] != "http_503" {
        assert!(Instant::now() < deadline, "no 503 seen\n{}", d.log());
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(d);
    let saved: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("data/export.json")).unwrap())
            .unwrap();
    // Records without spans (the refused call's `TurnBegin`s) may still
    // move the cursor; the refused turn's own record must not.
    let saved_lsn = saved["traces"]["lsn"].as_u64().unwrap();
    let refused_lsn: u64 = refused.rsplit(':').next().unwrap().parse().unwrap();
    assert!(
        before["cursor"].as_u64().unwrap() <= saved_lsn && saved_lsn < refused_lsn,
        "{saved} {refused}"
    );
    r.got.fail.store(false, Ordering::SeqCst);
    let d = Daemon::start(dir.path(), &r.endpoint);
    let third = trace_of(&r.got, &d, &refused);
    check_three_actors(&d, &third, &refused, None);
    d.wait_exported();
    let roots_sent = |turn: &str| {
        r.got
            .requests()
            .iter()
            .flatten()
            .filter(|s| attr(s, "kronik.turn_id") == Some(turn))
            .count()
    };
    assert_eq!(roots_sent(&plain), 1);
    assert_eq!(roots_sent(&traced), 1);
}

const NEEDLE: &str = "NEEDLE-7f3a";

/// Runs `kronik serve` that must fail at start: its log.
fn serve_fails(dir: &Path, sections: &str, envs: &[(&str, &str)]) -> String {
    let gateway = format!("127.0.0.1:{}", free_port());
    let mut child = serve(dir, &dir.join("api.sock"), &gateway, sections, envs);
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("kronik serve did not fail");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::read_to_string(dir.join("serve.log")).unwrap()
}

/// An S3-compatible endpoint that refuses everything with 403 and an
/// error body echoing `NEEDLE`, as a provider may echo a credential.
fn refusing_s3() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut head = Vec::new();
            let mut byte = [0; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |v| v.trim().parse().unwrap_or(0));
            let mut body = vec![0; len];
            let _ = s.read_exact(&mut body);
            let reply =
                format!("<Error><Code>AccessDenied</Code><Message>key {NEEDLE}</Message></Error>");
            let _ = write!(
                s,
                "HTTP/1.1 403 Forbidden\r\ncontent-type: application/xml\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            );
        }
    });
    endpoint
}

/// Review M9: what the daemon logs never holds credential text: not a
/// malformed `headers_env` pair, not a rejected endpoint's userinfo, path
/// or query, not an S3 store's error body. The log names the variable,
/// the scheme and host, and a classified code instead.
#[test]
fn credentials_never_reach_the_daemons_log() {
    let dir = tempfile::tempdir().unwrap();
    let sub = |name: &str| {
        let d = dir.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    };

    let log = serve_fails(
        &sub("headers"),
        "[otel]\nendpoint = \"http://127.0.0.1:4318\"\nheaders_env = \"KRONIK_TEST_HEADERS\"\n",
        &[(
            "KRONIK_TEST_HEADERS",
            &format!("x-team=a,authorization: Bearer {NEEDLE}"),
        )],
    );
    assert!(log.contains("$KRONIK_TEST_HEADERS: header 2"), "{log}");
    assert!(!log.contains(NEEDLE), "{log}");

    let log = serve_fails(
        &sub("endpoint"),
        &format!(
            "[otel]\nendpoint = \"http://user:{NEEDLE}@collector.example:4318/{NEEDLE}?t={NEEDLE}\"\n\
             headers_env = \"KRONIK_TEST_HEADERS\"\n"
        ),
        &[],
    );
    assert!(log.contains("http://collector.example:4318"), "{log}");
    assert!(!log.contains(NEEDLE), "{log}");

    let s3 = refusing_s3();
    let d = Daemon::start_with(
        &sub("s3"),
        &format!(
            "[audit]\nsink = \"s3://bucket/prefix\"\nendpoint = \"{s3}\"\ninterval = \"100ms\"\nmax_hold = \"30d\"\n"
        ),
        &[
            ("AWS_ACCESS_KEY_ID", "AKIDTEST"),
            ("AWS_SECRET_ACCESS_KEY", NEEDLE),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let v = d.json(&["export", "status"]);
        let audit = v["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "audit")
            .unwrap()
            .clone();
        if audit["last_error"] == "s3_forbidden" {
            break;
        }
        assert!(Instant::now() < deadline, "{audit}\n{}", d.log());
        std::thread::sleep(Duration::from_millis(100));
    }
    let log = d.log();
    assert!(log.contains("s3_forbidden"), "{log}");
    assert!(!log.contains(NEEDLE), "{log}");
}
