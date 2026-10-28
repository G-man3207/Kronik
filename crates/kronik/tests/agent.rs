//! The M5 agent test (brief: test strategy, "Agent test"): a scripted MCP
//! client with an agent's token runs the golden path against a real
//! `kronik serve`, calling only the tools that AGENT_GUIDE.md names: it reads
//! the history, proposes a change, reads the diff and asks for approval. A
//! human's token then approves and promotes.
//!
//! The change alters a payment call. Hundreds of exact effects to another
//! target keep the total confidence above 0.99, and the policy still asks
//! for approval because one payments.internal call is approximate
//! (`payments-must-be-exact`, grounding per target). Promote is refused
//! until the approval.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::free_port;
use rmcp::model::{CallToolRequestParams, ReadResourceRequestParams, ResourceContents};
use rmcp::service::{RoleClient, RunningService, ServiceExt as _};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const GUESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/guests/");
const ENDPOINT: &str = "http://localhost/mcp";
/// Webhooks relayed to a local target: their effects replay exactly.
const WEBHOOKS: usize = 200;

fn guest(name: &str) -> PathBuf {
    PathBuf::from(format!("{GUESTS}{name}.wasm"))
}

/// A local HTTP target that answers 200 to everything.
// A test harness thread, not daemon code (ADR 0004).
#[allow(clippy::disallowed_methods)]
fn relay_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    addr
}

/// `kronik serve` with its socket in a temporary directory; killed when
/// dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    gateway: String,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let gateway = format!("127.0.0.1:{}", free_port());
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = Command::new(KRONIK)
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .args(["--http-listen", &gateway])
            .args(["--admin-listen", &format!("127.0.0.1:{}", free_port())])
            .arg("--api-socket")
            .arg(&socket)
            .env_remove("KRONIK_CONFIG")
            .env("KRONIK_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon {
            child,
            socket,
            gateway,
            dir,
        };
        let up = (0..600).any(|_| {
            let ok = d
                .cli(None, &["--json", "actors", "list"], None)
                .status
                .success();
            if !ok {
                std::thread::sleep(Duration::from_millis(100));
            }
            ok
        });
        assert!(up, "kronik serve did not start:\n{}", d.log());
        d
    }

    /// `kronik --socket <socket> <args>`, as `token` when given.
    fn cli(&self, token: Option<&str>, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut c = Command::new(KRONIK);
        c.arg("--socket")
            .arg(&self.socket)
            .args(args)
            .env_remove("KRONIK_API_SOCKET")
            .env_remove("KRONIK_TOKEN")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(token) = token {
            c.env("KRONIK_TOKEN", token);
        }
        c.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = c.spawn().unwrap();
        if let Some(input) = stdin {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        child.wait_with_output().unwrap()
    }

    /// An operator command on the socket, without a token; it must succeed.
    fn operator(&self, args: &[&str]) {
        let out = self.cli(None, args, None);
        assert!(out.status.success(), "{args:?}: {}", text(&out));
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("serve.log")).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// `POST path` with `body` to the gateway: the status.
fn post(gateway: &str, path: &str, body: &str) -> u16 {
    let mut s = TcpStream::connect(gateway).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    s.read_to_string(&mut response).unwrap();
    response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// `GET path` on the API socket, without a token.
fn api_get(socket: &Path, path: &str) -> Value {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {response}"))
}

/// The tools AGENT_GUIDE.md names in its table, `| \`a\`, \`b\` | scope | … |`.
fn guide_tools(guide: &str) -> BTreeSet<String> {
    let table = guide.split("## Tools").nth(1).unwrap();
    let table = table.split("\n## ").next().unwrap();
    table
        .lines()
        .filter(|l| l.starts_with("| `"))
        .flat_map(|l| l.split('|').nth(1).unwrap().split(','))
        .map(|name| name.trim().trim_matches('`').to_owned())
        .collect()
}

/// An MCP client as an agent: every tool it calls must be one the guide
/// names.
struct Agent {
    client: RunningService<RoleClient, ()>,
    allowed: BTreeSet<String>,
    called: BTreeSet<String>,
}

impl Agent {
    async fn connect(socket: &Path, token: &str) -> Agent {
        let client = UnixSocketHttpClient::new(&socket.to_string_lossy(), ENDPOINT);
        let config = StreamableHttpClientTransportConfig::with_uri(ENDPOINT).auth_header(token);
        let transport = StreamableHttpClientTransport::with_client(client, config);
        let client = ().serve(transport).await.unwrap();
        Agent {
            client,
            allowed: BTreeSet::new(),
            called: BTreeSet::new(),
        }
    }

    async fn resource(&self, uri: &str) -> String {
        let result = self
            .client
            .read_resource(ReadResourceRequestParams::new(uri.to_owned()))
            .await
            .unwrap();
        match &result.contents[0] {
            ResourceContents::TextResourceContents { text, .. } => text.clone(),
            other => panic!("{uri}: {other:?}"),
        }
    }

    /// Calls a tool the guide names; `Ok` with its structured result, `Err`
    /// with the error JSON.
    async fn call(&mut self, name: &str, arguments: Value) -> Result<Value, Value> {
        assert!(
            self.allowed.contains(name),
            "{name} is not a tool AGENT_GUIDE.md names: {:?}",
            self.allowed
        );
        self.called.insert(name.to_owned());
        let Value::Object(arguments) = arguments else {
            panic!("arguments must be an object");
        };
        let result = self
            .client
            .call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let value = result.structured_content.clone().unwrap_or(Value::Null);
        if result.is_error == Some(true) {
            Err(value)
        } else {
            Ok(value)
        }
    }
}

#[test]
fn an_agent_runs_the_golden_path_with_only_the_guide() {
    let d = Daemon::start();
    let target = relay_target();

    // The operator: two kinds, their grants, a signing secret, and tokens
    // for an agent and for a human.
    d.operator(&[
        "deploy",
        guest("webhook-relay").to_str().unwrap(),
        "--reason",
        "setup",
    ]);
    d.operator(&[
        "deploy",
        guest("counter").to_str().unwrap(),
        "--reason",
        "setup",
    ]);
    let secret = d.cli(
        None,
        &["secret", "set", "relay-signing-key", "--reason", "setup"],
        Some(b"agent-test-signing-key"),
    );
    assert!(secret.status.success(), "{}", text(&secret));
    for (kind, cap) in [
        ("webhook-relay", "http:127.0.0.1"),
        ("webhook-relay", "secret:relay-signing-key"),
        ("counter", "http:payments.internal"),
    ] {
        d.operator(&["grant", kind, cap, "--reason", "setup"]);
    }
    let configure = format!("{{\"target\":\"http://{target}/relay\"}}");
    d.operator(&[
        "send",
        "webhook-relay/shop",
        "configure",
        "--text",
        &configure,
        "--content-type",
        "application/json",
        "--reason",
        "setup",
    ]);
    let token = |name: &str, scopes: &str| {
        let out = d.cli(
            None,
            &[
                "--json",
                "token",
                "create",
                "--name",
                name,
                "--scopes",
                scopes,
                "--reason",
                "agent test",
            ],
            None,
        );
        assert!(out.status.success(), "{}", text(&out));
        let created: Value = serde_json::from_slice(&out.stdout).unwrap();
        created["secret"].as_str().unwrap().to_owned()
    };
    let agent_token = token("agent-1", "read,fork,propose");
    let human_token = token("alice", "read,approve,promote");

    // Production traffic: webhooks relayed to the local target, and one
    // payment call, which fails (payments.internal does not resolve here)
    // and is recorded all the same.
    for i in 0..WEBHOOKS {
        let status = post(&d.gateway, "/hooks/shop", &format!("{{\"order\":{i}}}"));
        assert_eq!(status, 200, "webhook {i}:\n{}", d.log());
    }
    d.operator(&[
        "send",
        "counter/pay",
        "fetch-ok",
        "--text",
        "POST http://payments.internal/v1/charges\n\namount=10",
        "--reason",
        "a payment",
    ]);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let proposal = runtime.block_on(async {
        let mut agent = Agent::connect(&d.socket, &agent_token).await;
        // The agent starts from the guide, and uses only the tools it names.
        let guide = agent.resource("kronik://agent-guide").await;
        agent.allowed = guide_tools(&guide);
        assert!(agent.allowed.len() >= 13, "{:?}", agent.allowed);

        // 1-2. What runs, and what it did.
        let actors = agent.call("list_actors", json!({})).await.unwrap();
        let names: Vec<String> = actors["actors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                format!(
                    "{}/{}",
                    a["kind"].as_str().unwrap(),
                    a["key"].as_str().unwrap()
                )
            })
            .collect();
        assert!(names.contains(&"counter/pay".to_owned()), "{names:?}");
        let history = agent
            .call("query_history", json!({"actor": "counter/pay", "limit": 5}))
            .await
            .unwrap();
        let turn = &history["turns"][0];
        let target = turn["effects"][0]["target"].as_str().unwrap_or_default();
        assert!(target.contains("payments.internal"), "{turn}");
        let traced = agent
            .call("trace_turn", json!({"turn_id": turn["turn_id"]}))
            .await
            .unwrap();
        assert_eq!(traced["actor"], "counter/pay", "{traced}");

        // 3-4. The change: a payment request with a new body.
        let wasm = STANDARD.encode(std::fs::read(guest("counter-body-v2")).unwrap());
        let proposed = agent
            .call(
                "propose_change",
                json!({"wasm_base64": wasm, "reason": "payments carry the v2 body"}),
            )
            .await
            .unwrap();
        let p = &proposed["proposal"];
        let id = p["id"].as_str().unwrap().to_owned();
        assert_eq!(p["status"], "evaluated", "{proposed}");
        assert_eq!(p["policy"]["outcome"], "require_approval", "{proposed}");
        let fired: Vec<&str> = p["policy"]["fired"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(fired, ["payments-must-be-exact"], "{proposed}");
        let confidence = p["summary"]["confidence"].as_f64().unwrap();
        assert!(
            confidence > 0.99,
            "total confidence {confidence}: {proposed}"
        );

        // 5. The whole diff: the payment target alone is approximate.
        let diff = agent
            .call("get_diff", json!({"proposal": id}))
            .await
            .unwrap();
        assert!(
            diff["summary"]["confidence"].as_f64().unwrap() > 0.99,
            "{diff}"
        );
        let payments = diff["grounding"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["host"] == "payments.internal")
            .unwrap_or_else(|| panic!("no payments grounding: {diff}"));
        let inexact =
            payments["approximate"].as_u64().unwrap() + payments["synthetic"].as_u64().unwrap();
        assert!(inexact > 0, "{payments}");
        assert_eq!(diff["errors"]["introduced"], 0, "{diff}");

        // 6. Promote is a human's, so the agent asks for an approval.
        let refused = agent
            .call("promote", json!({"proposal": id, "reason": "ship it"}))
            .await
            .unwrap_err();
        assert_eq!(refused["error"]["code"], "SCOPE_MISSING", "{refused}");
        let asked = agent
            .call(
                "request_approval",
                json!({
                    "proposal": id,
                    "reason": "only the payment body changes; 200 webhooks replay exactly"
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            asked["request"]["command"],
            format!("kronik approve {id} --reason '...'"),
            "{asked}"
        );
        assert_eq!(
            agent.called,
            [
                "get_diff",
                "list_actors",
                "promote",
                "propose_change",
                "query_history",
                "request_approval",
                "trace_turn"
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
        );
        agent.client.cancel().await.unwrap();
        id
    });

    // The human: the policy blocks promote until the approval.
    let human = |args: &[&str]| d.cli(Some(&human_token), args, None);
    let blocked = human(&["promote", &proposal, "--reason", "ship it"]);
    assert_eq!(blocked.status.code(), Some(1), "{}", text(&blocked));
    assert!(
        text(&blocked).contains("APPROVAL_REQUIRED"),
        "{}",
        text(&blocked)
    );
    let approved = human(&["approve", &proposal, "--reason", "checked the payment diff"]);
    assert!(approved.status.success(), "{}", text(&approved));
    let promoted = human(&["promote", &proposal, "--reason", "ship it"]);
    assert!(promoted.status.success(), "{}", text(&promoted));

    // Everyone's part is recorded with their token.
    let shown = api_get(&d.socket, &format!("/v1/proposals/{proposal}"));
    assert_eq!(shown["status"], "promoted", "{shown}");
    let request = &shown["approval_requests"][0];
    assert_eq!(request["token_id"], "token:agent-1", "{shown}");
    assert_eq!(request["pending"], false, "{shown}");
    let deployments = api_get(&d.socket, "/v1/deployments");
    let last = deployments["deployments"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(last["cause"], "promote", "{deployments}");
    assert_eq!(last["token_id"], "token:alice", "{deployments}");
}
