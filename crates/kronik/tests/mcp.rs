//! MCP against a real `kronik serve`: a client over Streamable HTTP at
//! `/mcp` on the API socket, and `kronik mcp`, the stdio bridge, driven with
//! raw JSON-RPC as an agent's host would.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rmcp::model::{CallToolRequestParams, ReadResourceRequestParams, ResourceContents};
use rmcp::service::{RoleClient, RunningService, ServiceExt as _};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use serde_json::{Value, json};

const KRONIK: &str = env!("CARGO_BIN_EXE_kronik");
const COUNTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter.wasm"
);
const COUNTER_STEP2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/guests/counter-step2.wasm"
);
const ENDPOINT: &str = "http://localhost/mcp";

/// `kronik serve` on a free port with its socket in a temporary directory,
/// with the counter deployed and `counter/a` incremented once; killed when
/// dropped.
struct Daemon {
    child: Child,
    socket: PathBuf,
    dir: tempfile::TempDir,
}

impl Daemon {
    fn start() -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let log = std::fs::File::create(dir.path().join("serve.log")).unwrap();
        let child = Command::new(KRONIK)
            .arg("serve")
            .env("KRONIK_DISK_RESERVE", "0B")
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            // The tests never call the gateway: port 0, which nothing can take first.
            .args(["--http-listen", "127.0.0.1:0", "--api-socket"])
            .arg(&socket)
            .env("KRONIK_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let d = Daemon { child, socket, dir };
        let started = (0..600).any(|_| {
            let up = d.cli(&["--json", "actors", "list"]).status.success();
            if !up {
                std::thread::sleep(Duration::from_millis(100));
            }
            up
        });
        assert!(started, "kronik serve did not start:\n{}", d.log());
        assert!(
            d.cli(&["deploy", COUNTER, "--reason", "mcp test"])
                .status
                .success()
        );
        let sent = d.cli(&["send", "counter/a", "increment", "--reason", "mcp test"]);
        assert!(sent.status.success(), "{sent:?}");
        d
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        Command::new(KRONIK)
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .env_remove("KRONIK_API_SOCKET")
            .env_remove("KRONIK_TOKEN")
            .stdin(Stdio::null())
            .output()
            .unwrap()
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

/// `GET path` on the JSON API, bypassing MCP.
fn api_get(socket: &Path, path: &str) -> Value {
    use std::io::Read as _;
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

async fn connect(socket: &Path) -> RunningService<RoleClient, ()> {
    connect_as(socket, None).await.unwrap()
}

/// An MCP client on the socket, sending `token` as a bearer token.
async fn connect_as(
    socket: &Path,
    token: Option<&str>,
) -> Result<RunningService<RoleClient, ()>, String> {
    let client = UnixSocketHttpClient::new(&socket.to_string_lossy(), ENDPOINT);
    let mut config = StreamableHttpClientTransportConfig::with_uri(ENDPOINT);
    if let Some(token) = token {
        config = config.auth_header(token);
    }
    let transport = StreamableHttpClientTransport::with_client(client, config);
    ().serve(transport).await.map_err(|e| e.to_string())
}

/// Calls a tool; `Ok` with its structured result, `Err` with it when the
/// result is an error.
async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &'static str,
    arguments: Value,
) -> Result<Value, Value> {
    let Value::Object(arguments) = arguments else {
        panic!("arguments must be an object");
    };
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(arguments))
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    let value = result.structured_content.clone().unwrap_or(Value::Null);
    if result.is_error == Some(true) {
        Err(value)
    } else {
        Ok(value)
    }
}

const TOOLS: [&str; 13] = [
    "create_fork",
    "explain",
    "get_diff",
    "inspect_actor",
    "list_actors",
    "list_dead_letters",
    "promote",
    "propose_change",
    "query_history",
    "request_approval",
    "rollback",
    "send_to_fork",
    "trace_turn",
];

#[test]
fn tools_and_resources_over_streamable_http() {
    let daemon = Daemon::start();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(over_streamable_http(&daemon));
}

async fn over_streamable_http(daemon: &Daemon) {
    let client = connect(&daemon.socket).await;

    let info = client.peer_info().unwrap();
    assert_eq!(info.server_info.as_ref().unwrap().name, "kronik");
    assert!(info.capabilities.tools.is_some());
    assert!(info.capabilities.resources.is_some());
    let instructions = info.instructions.as_deref().unwrap();
    assert!(instructions.contains("propose_change"), "{instructions}");
    assert!(
        instructions.contains("kronik://agent-guide"),
        "{instructions}"
    );

    // Every tool has input and output schemas and names its scope; every
    // mutation requires a reason, and every mutation but a message into a
    // fork accepts dry_run.
    let tools = client.list_all_tools().await.unwrap();
    let names: BTreeSet<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, BTreeSet::from(TOOLS));
    for tool in &tools {
        let scope = tool.meta.as_ref().unwrap().0["kronik/scope"]
            .as_str()
            .unwrap();
        assert!(
            ["read", "fork", "propose", "promote"].contains(&scope),
            "{}",
            tool.name
        );
        assert!(tool.output_schema.is_some(), "{}", tool.name);
        let read_only = tool.annotations.as_ref().unwrap().read_only_hint == Some(true);
        assert_eq!(read_only, scope == "read", "{}", tool.name);
        let required = tool.input_schema["required"].as_array().unwrap();
        let properties = tool.input_schema["properties"].as_object().unwrap();
        assert_eq!(
            required.contains(&json!("reason")),
            !read_only,
            "{}",
            tool.name
        );
        assert_eq!(
            properties.contains_key("dry_run"),
            !read_only && tool.name != "send_to_fork",
            "{}",
            tool.name
        );
    }

    // The read tools answer as the API does.
    let actors = call(&client, "list_actors", json!({"kind": "counter"}))
        .await
        .unwrap();
    assert_eq!(actors["actors"][0]["kind"], "counter");
    assert_eq!(actors["actors"][0]["key"], "a");
    let actor = call(&client, "inspect_actor", json!({"actor": "counter/a"}))
        .await
        .unwrap();
    assert_eq!(actor["actor"]["key"], "a");
    assert!(actor["state"].is_array());
    let history = call(
        &client,
        "query_history",
        json!({"actor": "counter/a", "limit": 5}),
    )
    .await
    .unwrap();
    assert_eq!(
        history["turns"][0]["outcome"]["kind"], "committed",
        "{history}"
    );
    let dead = call(&client, "list_dead_letters", json!({})).await.unwrap();
    assert_eq!(dead["dead_letters"], json!([]));
    let turn_id = history["turns"][0]["turn_id"].as_str().unwrap();
    let trace = call(&client, "trace_turn", json!({"turn_id": turn_id}))
        .await
        .unwrap();
    assert_eq!(trace["turn"]["turn_id"], turn_id, "{trace}");
    assert_eq!(trace["actor"], "counter/a", "{trace}");
    assert!(trace["descendants"].is_array(), "{trace}");
    let no_turn = call(&client, "trace_turn", json!({"turn_id": "main:999999"}))
        .await
        .unwrap_err();
    assert_eq!(no_turn["error"]["code"], "TURN_NOT_FOUND", "{no_turn}");

    // explain is `kronik explain`.
    let fork = call(&client, "explain", json!({"topic": "fork"}))
        .await
        .unwrap();
    assert_eq!(fork["kind"], "concept");
    assert!(fork["text"].as_str().unwrap().len() > 20);
    let code = call(&client, "explain", json!({"topic": "POLICY_DENIED"}))
        .await
        .unwrap();
    assert_eq!(code["kind"], "error_code");
    let guide = call(&client, "explain", json!({"topic": "agent"}))
        .await
        .unwrap();
    assert_eq!(guide["kind"], "guide");
    assert!(
        guide["text"]
            .as_str()
            .unwrap()
            .starts_with("# Kronik for agents")
    );
    let all = call(&client, "explain", json!({})).await.unwrap();
    assert!(all["topics"].as_array().unwrap().len() > 40);

    // Errors carry the API's stable code and hint.
    let missing = call(&client, "inspect_actor", json!({"actor": "nosuch/x"}))
        .await
        .unwrap_err();
    assert_eq!(missing["error"]["code"], "ACTOR_NOT_FOUND", "{missing}");
    assert!(missing["error"]["hint"].is_string(), "{missing}");
    assert_eq!(missing["error"]["docs"], "kronik explain ACTOR_NOT_FOUND");
    let topic = call(&client, "explain", json!({"topic": "no-such-topic"}))
        .await
        .unwrap_err();
    assert_eq!(topic["error"]["code"], "BAD_REQUEST");
    assert!(
        topic["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("kronik explain --list")
    );
    let unknown = call(&client, "get_diff", json!({"fork": "f-000000000000"}))
        .await
        .unwrap_err();
    assert_eq!(unknown["error"]["code"], "FORK_NOT_FOUND", "{unknown}");
    assert!(unknown["error"]["hint"].is_string(), "{unknown}");
    let unknown = call(&client, "get_diff", json!({"proposal": "p-000000000000"}))
        .await
        .unwrap_err();
    let code = unknown["error"]["code"].as_str().unwrap();
    assert!(code.ends_with("_NOT_FOUND"), "{unknown}");
    let malformed = call(&client, "query_history", json!({"actor": "counter"}))
        .await
        .unwrap_err();
    assert_eq!(malformed["error"]["code"], "BAD_REQUEST");

    // A mutation needs a reason (I12), and a dry run writes nothing.
    let no_reason = call(&client, "create_fork", json!({"at": "now"}))
        .await
        .unwrap_err();
    assert_eq!(no_reason["error"]["code"], "REASON_REQUIRED", "{no_reason}");
    let plan = call(
        &client,
        "create_fork",
        json!({"at": "now", "reason": "mcp test", "dry_run": true}),
    )
    .await
    .unwrap();
    assert_eq!(plan["dry_run"], true, "{plan}");
    let forks = api_get(&daemon.socket, "/v1/forks");
    assert_eq!(
        forks["forks"],
        json!([]),
        "a dry run created a fork: {forks}"
    );
    let rollback = call(
        &client,
        "rollback",
        json!({"deployment": 999, "reason": "mcp test"}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        rollback["error"]["code"], "DEPLOYMENT_NOT_FOUND",
        "{rollback}"
    );

    // A message into a fork runs there, and main is untouched.
    call(
        &client,
        "create_fork",
        json!({"at": "now", "name": "mcp-fork", "reason": "mcp test"}),
    )
    .await
    .unwrap();
    let sent = call(
        &client,
        "send_to_fork",
        json!({"fork": "mcp-fork", "actor": "counter/a", "name": "increment", "reason": "mcp test"}),
    )
    .await
    .unwrap();
    assert_eq!(sent["outcome"]["kind"], "committed", "{sent}");
    assert!(
        sent["turn_id"].as_str().unwrap().starts_with("mcp-fork:"),
        "{sent}"
    );
    assert_eq!(sent["reply"]["text"], "2", "{sent}");
    let main = api_get(&daemon.socket, "/v1/actors/counter/a/history?limit=10");
    assert_eq!(main["turns"].as_array().unwrap().len(), 1, "{main}");
    let no_fork = call(
        &client,
        "send_to_fork",
        json!({"fork": "nope", "actor": "counter/a", "name": "increment", "reason": "mcp test"}),
    )
    .await
    .unwrap_err();
    assert_eq!(no_fork["error"]["code"], "FORK_NOT_FOUND", "{no_fork}");

    // An approval request is recorded with the command for a human.
    let step2 = std::fs::read(COUNTER_STEP2).unwrap();
    let proposed = call(
        &client,
        "propose_change",
        json!({"wasm_base64": STANDARD.encode(step2), "reason": "mcp test"}),
    )
    .await
    .unwrap();
    let id = proposed["proposal"]["id"].as_str().unwrap().to_owned();
    // The agent's evidence: a human reads it in full in `kronik proposals show`.
    let evidence = "step 2 doubles the increment: every replayed response is n+2 \
                    instead of n+1,\nand no effect, error or other actor changed";
    let asked = call(
        &client,
        "request_approval",
        json!({"proposal": id, "reason": evidence}),
    )
    .await
    .unwrap();
    assert_eq!(
        asked["request"]["command"],
        format!("kronik approve {id} --reason '...'"),
        "{asked}"
    );
    let shown = api_get(&daemon.socket, &format!("/v1/proposals/{id}"));
    let request = &shown["approval_requests"][0];
    assert_eq!(request["reason"], evidence, "{shown}");
    assert_eq!(request["pending"], true, "{shown}");
    let out = daemon.cli(&["proposals", "show", &id]);
    let human = String::from_utf8_lossy(&out.stdout);
    assert!(human.contains(" (pending):\n"), "{human}");
    for line in evidence.lines() {
        assert!(
            human.contains(&format!("\n  {line}\n")),
            "{line:?}: {human}"
        );
    }

    // Resources: the agent guide, concepts, the error catalog, the WIT and
    // the configuration.
    let resources = client.list_all_resources().await.unwrap();
    let uris: BTreeSet<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert_eq!(
        uris,
        BTreeSet::from([
            "kronik://agent-guide",
            "kronik://concepts",
            "kronik://config",
            "kronik://errors",
            "kronik://wit/kronik-actor.wit"
        ])
    );
    let read = |uri: &'static str| {
        let client = &client;
        async move {
            let result = client
                .read_resource(ReadResourceRequestParams::new(uri))
                .await
                .unwrap();
            match &result.contents[0] {
                ResourceContents::TextResourceContents { text, .. } => text.clone(),
                other => panic!("{uri}: {other:?}"),
            }
        }
    };
    let concepts: Value = serde_json::from_str(&read("kronik://concepts").await).unwrap();
    assert!(
        concepts
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "fork")
    );
    let errors: Value = serde_json::from_str(&read("kronik://errors").await).unwrap();
    let error_entry = errors
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "ACTOR_NOT_FOUND")
        .cloned()
        .unwrap();
    assert_eq!(error_entry["http_status"], 404);
    assert!(
        read("kronik://wit/kronik-actor.wit")
            .await
            .starts_with("package kronik:actor@")
    );
    let guide = read("kronik://agent-guide").await;
    assert!(guide.starts_with("# Kronik for agents"), "{guide}");
    for tool in TOOLS {
        assert!(
            guide.contains(&format!("`{tool}`")),
            "the guide misses {tool}"
        );
    }
    let config: Value = serde_json::from_str(&read("kronik://config").await).unwrap();
    assert_eq!(
        config["deployments"][0]["kinds"][0]["kind"], "counter",
        "{config}"
    );
    assert!(config["grants"].is_array(), "{config}");
    assert!(config["limits"].is_array(), "{config}");
    assert!(
        config["policy"]["rules_toml"]
            .as_str()
            .unwrap()
            .contains("no-new-errors")
    );

    client.cancel().await.unwrap();
}

/// `kronik mcp` with pipes: newline-delimited JSON-RPC, as an agent's host
/// speaks it to a subprocess.
struct Bridge {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Bridge {
    fn start(socket: &Path) -> Bridge {
        Bridge::start_with_token(socket, None)
    }

    /// `kronik mcp` with `$KRONIK_TOKEN` set to `token`.
    fn start_with_token(socket: &Path, token: Option<&str>) -> Bridge {
        let mut command = Command::new(KRONIK);
        command
            .arg("--socket")
            .arg(socket)
            .arg("mcp")
            .env_remove("KRONIK_API_SOCKET")
            .env_remove("KRONIK_TOKEN");
        if let Some(token) = token {
            command.env("KRONIK_TOKEN", token);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Bridge {
            child,
            stdin,
            stdout,
        }
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// Sends a request and returns its response, skipping notifications.
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "the bridge closed stdout"
            );
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// [`Bridge::request`] that fails instead of hanging when the bridge
    /// does not answer within `limit`.
    // A test harness thread, not daemon code (ADR 0004).
    #[allow(clippy::disallowed_methods)]
    fn request_within(&mut self, id: u64, method: &str, params: Value, limit: Duration) -> Value {
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let pid = self.child.id().to_string();
        let watchdog = std::thread::spawn(move || {
            if wait.recv_timeout(limit).is_err() {
                // Killing the bridge ends the read with "the bridge closed stdout".
                let _ = Command::new("kill").arg(&pid).status();
            }
        });
        let answer = self.request(id, method, params);
        let _ = done.send(());
        watchdog.join().unwrap();
        answer
    }
}

#[test]
fn the_stdio_bridge_forwards_to_the_daemon() {
    let daemon = Daemon::start();
    let mut bridge = Bridge::start(&daemon.socket);

    let init = bridge.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "kronik-test", "version": "0"}
        }),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "kronik", "{init}");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "{init}"
    );
    bridge.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    let tools = bridge.request(2, "tools/list", json!({}));
    let names: BTreeSet<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, BTreeSet::from(TOOLS), "{tools}");

    let explained = bridge.request(
        3,
        "tools/call",
        json!({"name": "explain", "arguments": {"topic": "APPROVAL_REQUIRED"}}),
    );
    assert_eq!(
        explained["result"]["structuredContent"]["name"],
        "APPROVAL_REQUIRED"
    );

    let actors = bridge.request(
        4,
        "tools/call",
        json!({"name": "list_actors", "arguments": {}}),
    );
    assert_eq!(
        actors["result"]["structuredContent"]["actors"][0]["key"], "a",
        "{actors}"
    );

    let missing = bridge.request(
        5,
        "tools/call",
        json!({"name": "query_history", "arguments": {"actor": "nosuch/x"}}),
    );
    assert_eq!(missing["result"]["isError"], true, "{missing}");
    let error = &missing["result"]["structuredContent"]["error"];
    assert_eq!(error["code"], "ACTOR_NOT_FOUND", "{missing}");
    assert!(error["hint"].is_string(), "{missing}");

    let wit = bridge.request(
        6,
        "resources/read",
        json!({"uri": "kronik://wit/kronik-actor.wit"}),
    );
    let text = wit["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("package kronik:actor@"), "{wit}");

    let unknown = bridge.request(
        7,
        "tools/call",
        json!({"name": "no_such_tool", "arguments": {}}),
    );
    assert!(unknown["error"]["code"].is_i64(), "{unknown}");

    // Closing stdin ends the session.
    drop(bridge.stdin.take());
    let status = bridge.child.wait().unwrap();
    assert!(status.success(), "{status:?}");
}

/// Stdio reads a request as long as the daemon accepts, and answers one
/// that is longer instead of dropping it in silence.
#[test]
fn the_stdio_bridge_answers_large_requests() {
    let daemon = Daemon::start();
    let mut bridge = Bridge::start(&daemon.socket);
    let limit = Duration::from_secs(120);
    bridge.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "kronik-test", "version": "0"}
        }),
    );
    bridge.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    // About 17.5 MB of base64, as a TypeScript component has: over rmcp's
    // 16 MiB default for stdio. The bytes are no component.
    let wasm = STANDARD.encode(vec![0u8; 13 << 20]);
    let proposed = bridge.request_within(
        2,
        "tools/call",
        json!({"name": "propose_change", "arguments": {"wasm_base64": wasm, "reason": "large"}}),
        limit,
    );
    assert_eq!(proposed["result"]["isError"], true, "{proposed}");
    assert_eq!(
        proposed["result"]["structuredContent"]["error"]["code"], "BAD_REQUEST",
        "{proposed}"
    );

    // Over the API's limit: an error that names the request.
    let huge = "A".repeat(kronik_api::server::MAX_REQUEST);
    let refused = bridge.request_within(
        3,
        "tools/call",
        json!({"name": "propose_change", "arguments": {"wasm_base64": huge, "reason": "too large"}}),
        limit,
    );
    assert_eq!(refused["error"]["code"], -32600, "{refused}");
    let message = refused["error"]["message"].as_str().unwrap();
    assert!(message.starts_with("PAYLOAD_TOO_LARGE: "), "{refused}");

    // The session goes on.
    let tools = bridge.request_within(4, "tools/list", json!({}), limit);
    assert!(tools["result"]["tools"].is_array(), "{tools}");
}

/// `kronik --json token create`: the token.
fn token(daemon: &Daemon, name: &str, scopes: &str) -> String {
    let out = daemon.cli(&[
        "--json", "token", "create", "--name", name, "--scopes", scopes, "--reason", "mcp test",
    ]);
    assert!(out.status.success(), "{out:?}");
    let created: Value = serde_json::from_slice(&out.stdout).unwrap();
    created["secret"].as_str().unwrap().to_owned()
}

#[test]
fn tools_and_resources_take_the_tokens_scopes() {
    let daemon = Daemon::start();
    let agent = token(&daemon, "agent-1", "read,fork,propose");
    let approver = token(&daemon, "approver", "approve");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // An agent reads and forks, always without personal data, and
        // cannot promote.
        let client = connect_as(&daemon.socket, Some(&agent)).await.unwrap();
        let actors = call(&client, "list_actors", json!({})).await.unwrap();
        assert_eq!(actors["actors"][0]["key"], "a", "{actors}");
        let fork = call(
            &client,
            "create_fork",
            json!({"at": "now", "name": "agent-fork", "reason": "mcp test"}),
        )
        .await
        .unwrap();
        assert_eq!(fork["fork"]["no_pii"], true, "{fork}");
        let promote = call(
            &client,
            "promote",
            json!({"proposal": "p-000000000000", "reason": "mcp test"}),
        )
        .await
        .unwrap_err();
        assert_eq!(promote["error"]["code"], "SCOPE_MISSING", "{promote}");
        assert!(
            promote["error"]["message"]
                .as_str()
                .unwrap()
                .contains("token:agent-1 lacks scope promote"),
            "{promote}"
        );
        call(&client, "explain", json!({"topic": "agent"}))
            .await
            .unwrap();
        client.cancel().await.unwrap();

        // Without `read`, neither explain nor the resources answer.
        let client = connect_as(&daemon.socket, Some(&approver)).await.unwrap();
        let explain = call(&client, "explain", json!({"topic": "fork"}))
            .await
            .unwrap_err();
        assert_eq!(explain["error"]["code"], "SCOPE_MISSING", "{explain}");
        let read = client
            .read_resource(ReadResourceRequestParams::new("kronik://agent-guide"))
            .await
            .unwrap_err()
            .to_string();
        assert!(read.contains("lacks scope read"), "{read}");
        let actors = call(&client, "list_actors", json!({})).await.unwrap_err();
        assert_eq!(actors["error"]["code"], "SCOPE_MISSING", "{actors}");
        client.cancel().await.unwrap();

        // An unknown token gets no session at all.
        let refused = connect_as(&daemon.socket, Some("kronik_nope")).await;
        assert!(refused.is_err());
    });
    // The stdio bridge sends $KRONIK_TOKEN.
    let mut bridge = Bridge::start_with_token(&daemon.socket, Some(&agent));
    bridge.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "kronik-test", "version": "0"}
        }),
    );
    bridge.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let promote = bridge.request(
        2,
        "tools/call",
        json!({"name": "promote", "arguments": {"proposal": "p-000000000000", "reason": "x"}}),
    );
    assert_eq!(
        promote["result"]["structuredContent"]["error"]["code"], "SCOPE_MISSING",
        "{promote}"
    );
    drop(bridge.stdin.take());
    assert!(bridge.child.wait().unwrap().success());
}

#[test]
fn the_stdio_bridge_without_a_daemon_says_how_to_start_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(KRONIK)
        .arg("--socket")
        .arg(dir.path().join("none.sock"))
        .arg("mcp")
        .env_remove("KRONIK_API_SOCKET")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("UNAVAILABLE"), "{stderr}");
    assert!(stderr.contains("kronik serve"), "{stderr}");
}

/// H2: `kronik mcp --token` acts as that token, not as the socket's caller
/// with every scope; `--url` is refused with the way to a remote `/mcp`.
#[test]
fn the_stdio_bridge_takes_the_token_flag_and_refuses_a_url() {
    let daemon = Daemon::start();
    let reader = token(&daemon, "reader", "read");
    let mut child = Command::new(KRONIK)
        .arg("--socket")
        .arg(&daemon.socket)
        .args(["mcp", "--token", &reader])
        .env_remove("KRONIK_API_SOCKET")
        .env_remove("KRONIK_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut bridge = Bridge {
        stdin: child.stdin.take(),
        stdout: BufReader::new(child.stdout.take().unwrap()),
        child,
    };
    bridge.request(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "kronik-test", "version": "0"}
        }),
    );
    bridge.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    let fork = bridge.request(
        2,
        "tools/call",
        json!({"name": "create_fork", "arguments": {"at": "now", "name": "f", "reason": "x", "dry_run": true}}),
    );
    assert_eq!(
        fork["result"]["structuredContent"]["error"]["code"], "SCOPE_MISSING",
        "{fork}"
    );
    drop(bridge.stdin.take());
    assert!(bridge.child.wait().unwrap().success());

    let out = Command::new(KRONIK)
        .args(["mcp", "--url", "https://x:1"])
        .env_remove("KRONIK_API_SOCKET")
        .env_remove("KRONIK_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("BAD_REQUEST"), "{stderr}");
    assert!(
        stderr.contains("/mcp") && stderr.contains("Authorization: Bearer"),
        "{stderr}"
    );

    // N3: $KRONIK_URL is refused the same way, not silently ignored.
    let out = Command::new(KRONIK)
        .arg("mcp")
        .env("KRONIK_URL", "https://x:1")
        .env_remove("KRONIK_API_SOCKET")
        .env_remove("KRONIK_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("BAD_REQUEST") && stderr.contains("$KRONIK_URL") && stderr.contains("/mcp"),
        "{stderr}"
    );

    // N2: a blank --token is refused, not taken as no token (every scope).
    let out = Command::new(KRONIK)
        .arg("--socket")
        .arg(&daemon.socket)
        .args(["mcp", "--token", " "])
        .env_remove("KRONIK_API_SOCKET")
        .env_remove("KRONIK_TOKEN")
        .env_remove("KRONIK_URL")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--token is empty"), "{stderr}");
}
