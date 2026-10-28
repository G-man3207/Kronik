//! `kronik mcp`: MCP over stdio, for agents that launch a subprocess. It
//! connects to the daemon's MCP endpoint (`/mcp` on the API socket) and
//! forwards every request there, so stdio and Streamable HTTP serve the same
//! tools and resources, answered by the same code (ADR 0008). With
//! `$KRONIK_TOKEN` set, the agent acts as that token, with its scopes.
//!
//! Stdio reads requests as long as the daemon accepts ([`MAX_REQUEST`]):
//! rmcp's own stdio transport stops at 16 MiB and drops a longer line
//! without an answer, below a TypeScript component in base64 (17.5 MB). A
//! request over the limit gets a `PAYLOAD_TOO_LARGE` error with its id.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientJsonRpcMessage, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams,
    ReadResourceResponse, RequestId, ServerConfig, ServerJsonRpcMessage,
};
use rmcp::service::{Peer, RequestContext, RunningService, ServiceError};
use rmcp::transport::Transport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, UnixSocketHttpClient};
use rmcp::{ErrorData, RoleClient, RoleServer, ServerHandler, ServiceExt};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, Stdin, Stdout};
use tokio::sync::Mutex;

/// The longest request read from stdin: the most the daemon's API and MCP
/// endpoint accept.
const MAX_REQUEST: usize = kronik_api::server::MAX_REQUEST;

/// The URI the daemon's MCP endpoint is reached at over the socket; the
/// host only fills the `Host` header.
const ENDPOINT: &str = "http://localhost/mcp";

/// Arguments of `kronik mcp`.
#[derive(Debug, clap::Args)]
pub struct McpArgs {}

/// Serves MCP on stdin and stdout until the client closes stdin.
pub fn run(_args: McpArgs, socket_path: Option<PathBuf>) -> ExitCode {
    let socket = match crate::config::client_api_socket(socket_path) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("error: BAD_REQUEST: {e}");
            return ExitCode::FAILURE;
        }
    };
    let token = match crate::cli::client_token() {
        Ok(token) => token,
        Err(e) => {
            eprintln!("error: {}: {}", e.code, e.message);
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: INTERNAL: starting the async runtime failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(bridge(&socket, token)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn bridge(socket: &std::path::Path, token: Option<String>) -> Result<(), String> {
    let client = UnixSocketHttpClient::new(&socket.to_string_lossy(), ENDPOINT);
    let hint = if token.is_some() {
        "hint: check that `kronik serve` runs with that API socket, and that $KRONIK_TOKEN \
         is a live token (`kronik token list`)"
    } else {
        "hint: start the daemon with `kronik serve`, or pass its API socket with --socket"
    };
    let mut config = StreamableHttpClientTransportConfig::with_uri(ENDPOINT);
    if let Some(token) = token {
        config = config.auth_header(token);
    }
    let transport = StreamableHttpClientTransport::with_client(client, config);
    let daemon: RunningService<RoleClient, ()> = ().serve(transport).await.map_err(|e| {
        format!(
            "error: UNAVAILABLE: cannot reach the Kronik daemon's MCP endpoint on {}: {e}\n{hint}",
            socket.display()
        )
    })?;
    let Some(info) = daemon.peer_info() else {
        return Err("error: INTERNAL: the daemon's MCP endpoint did not describe itself".into());
    };
    let mut config = ServerConfig::new(info.capabilities.clone())
        .with_instructions(info.instructions.clone().unwrap_or_default());
    if let Some(server_info) = &info.server_info {
        config = config.with_server_info(server_info.clone());
    }
    let proxy = Proxy {
        daemon: daemon.peer().clone(),
        info: config,
    };
    let stdio = proxy
        .serve(Stdio::new())
        .await
        .map_err(|e| format!("error: INTERNAL: serving MCP on stdio failed: {e}"))?;
    stdio
        .waiting()
        .await
        .map_err(|e| format!("error: INTERNAL: the stdio session failed: {e}"))?;
    Ok(())
}

/// Answers stdio requests with the daemon's answers.
struct Proxy {
    daemon: Peer<RoleClient>,
    info: ServerConfig,
}

/// The daemon's protocol error as is; anything else means it is unreachable.
fn forwarded(error: ServiceError) -> ErrorData {
    match error {
        ServiceError::McpError(error) => error,
        other => ErrorData::internal_error(
            format!("UNAVAILABLE: the Kronik daemon's MCP endpoint failed: {other}"),
            None,
        ),
    }
}

impl ServerHandler for Proxy {
    fn get_info(&self) -> ServerConfig {
        self.info.clone()
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.daemon.list_tools(request).await.map_err(forwarded)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.daemon
            .call_tool(request)
            .await
            .map(CallToolResponse::from)
            .map_err(forwarded)
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        self.daemon.list_resources(request).await.map_err(forwarded)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        self.daemon
            .list_resource_templates(request)
            .await
            .map_err(forwarded)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.daemon
            .read_resource(request)
            .await
            .map(ReadResourceResponse::from)
            .map_err(forwarded)
    }
}

/// MCP on stdin and stdout, one JSON-RPC message per line as in rmcp's
/// stdio transport, but with lines up to [`MAX_REQUEST`] bytes, and an
/// answer to a longer one instead of silence.
struct Stdio {
    stdin: BufReader<Stdin>,
    /// The line being read, with its newline once complete.
    line: Vec<u8>,
    /// While the rest of a line over [`MAX_REQUEST`] is skipped: its id.
    skipping: Option<IdScan>,
    /// An answer not sent yet. rmcp drops `receive` whenever it has
    /// something else to do and calls it again, so it waits here.
    unsent: Option<ServerJsonRpcMessage>,
    stdout: Arc<Mutex<Stdout>>,
}

enum Read {
    Line,
    TooLong(Option<RequestId>),
    End,
}

impl Stdio {
    fn new() -> Stdio {
        Stdio {
            stdin: BufReader::new(tokio::io::stdin()),
            line: Vec::new(),
            skipping: None,
            unsent: None,
            stdout: Arc::new(Mutex::new(tokio::io::stdout())),
        }
    }

    /// Reads up to the next newline. Nothing is lost when the future is
    /// dropped: what was read is in `line` or `skipping`.
    async fn read_line(&mut self) -> std::io::Result<Read> {
        loop {
            let available = self.stdin.fill_buf().await?;
            if available.is_empty() {
                return Ok(Read::End);
            }
            let newline = available.iter().position(|&b| b == b'\n');
            let take = newline.map_or(available.len(), |i| i + 1);
            let chunk = &available[..take];
            if let Some(scan) = &mut self.skipping {
                scan.feed(chunk);
            } else if self.line.len() + take > MAX_REQUEST + 1 {
                let mut scan = IdScan::default();
                scan.feed(&self.line);
                scan.feed(chunk);
                self.line.clear();
                self.skipping = Some(scan);
            } else {
                self.line.extend_from_slice(chunk);
            }
            self.stdin.consume(take);
            if newline.is_some() {
                return Ok(match self.skipping.take() {
                    Some(scan) => Read::TooLong(scan.id()),
                    None => Read::Line,
                });
            }
        }
    }
}

async fn write_line(stdout: &Mutex<Stdout>, message: &ServerJsonRpcMessage) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    let mut stdout = stdout.lock().await;
    stdout.write_all(&line).await?;
    stdout.flush().await
}

/// A line as rmcp's stdio transport reads it: `None` to skip it (empty,
/// or not JSON, which has no id to answer), an answer for JSON that is not
/// a JSON-RPC message.
fn parse(line: &[u8]) -> Option<Result<ClientJsonRpcMessage, ServerJsonRpcMessage>> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = line.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(line);
    if line.is_empty() {
        return None;
    }
    match serde_json::from_slice(line) {
        Ok(message) => Some(Ok(message)),
        Err(e) if e.is_syntax() || e.is_eof() => None,
        Err(_) => Some(Err(ServerJsonRpcMessage::error(
            ErrorData::invalid_request("Invalid request", None),
            None,
        ))),
    }
}

impl Transport<RoleServer> for Stdio {
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: ServerJsonRpcMessage,
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'static {
        let stdout = self.stdout.clone();
        async move { write_line(&stdout, &item).await }
    }

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            if let Some(answer) = &self.unsent {
                write_line(&self.stdout, answer).await.ok()?;
                self.unsent = None;
            }
            match self.read_line().await {
                Ok(Read::Line) => {}
                Ok(Read::TooLong(id)) => {
                    self.unsent = Some(ServerJsonRpcMessage::error(
                        ErrorData::invalid_request(
                            format!(
                                "PAYLOAD_TOO_LARGE: MCP requests are limited to {MAX_REQUEST} \
                                 bytes, as the API's are"
                            ),
                            None,
                        ),
                        id,
                    ));
                    continue;
                }
                Ok(Read::End) | Err(_) => return None,
            }
            let parsed = parse(&self.line);
            self.line.clear();
            match parsed {
                Some(Ok(message)) => return Some(message),
                Some(Err(answer)) => self.unsent = Some(answer),
                None => {}
            }
        }
    }

    async fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The top-level `"id"` of a JSON object, read a byte at a time, so that a
/// line too long to keep can still be answered with its request id.
#[derive(Default)]
struct IdScan {
    depth: usize,
    in_string: bool,
    escaped: bool,
    at: At,
    /// The key being read (its first bytes), or the `"id"` value.
    text: Vec<u8>,
    id: Option<Vec<u8>>,
}

/// Where [`IdScan`] is in the top-level object.
#[derive(Clone, Copy, Default, PartialEq)]
enum At {
    #[default]
    Key,
    InKey,
    Colon {
        id: bool,
    },
    Value {
        id: bool,
    },
}

impl IdScan {
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.id.is_some() {
                return;
            }
            self.step(b);
        }
    }

    fn step(&mut self, b: u8) {
        let capture = self.at == (At::Value { id: true });
        if self.in_string {
            let end = !self.escaped && b == b'"';
            self.escaped = !self.escaped && b == b'\\';
            if end {
                self.in_string = false;
            }
            if self.at == At::InKey {
                if end {
                    self.at = At::Colon {
                        id: self.text == b"id",
                    };
                    self.text.clear();
                } else if self.text.len() < 3 {
                    self.text.push(b);
                }
            } else if capture {
                self.text.push(b);
            }
        } else {
            match b {
                b'"' => {
                    self.in_string = true;
                    if self.depth == 1 && self.at == At::Key {
                        self.at = At::InKey;
                    } else if capture {
                        self.text.push(b);
                    }
                }
                b':' if self.depth == 1 => {
                    if let At::Colon { id } = self.at {
                        self.at = At::Value { id };
                    }
                }
                b',' | b'}' if self.depth == 1 => {
                    if capture {
                        self.id = Some(std::mem::take(&mut self.text));
                    }
                    self.at = At::Key;
                    if b == b'}' {
                        self.depth = 0;
                    }
                }
                b'{' | b'[' => {
                    self.depth += 1;
                    if capture {
                        self.text.push(b);
                    }
                }
                b'}' | b']' => {
                    self.depth = self.depth.saturating_sub(1);
                    if capture {
                        self.text.push(b);
                    }
                }
                _ if capture => self.text.push(b),
                _ => {}
            }
        }
        // An id is a number or a short string; anything longer is not kept.
        if capture && self.text.len() > 256 {
            self.at = At::Value { id: false };
            self.text.clear();
        }
    }

    fn id(&self) -> Option<RequestId> {
        serde_json::from_slice(self.id.as_deref()?.trim_ascii()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_of(chunks: &[&str]) -> Option<RequestId> {
        let mut scan = IdScan::default();
        for c in chunks {
            scan.feed(c.as_bytes());
        }
        scan.id()
    }

    #[test]
    fn finds_the_top_level_id_wherever_it_is() {
        let first = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"arguments":{"id":"inner"}}}"#;
        assert_eq!(id_of(&[first]), Some(RequestId::Number(7)));
        let last = r#"{"method":"m","params":{"id":1,"s":"a\"b},{\"id\":2"}, "id" : "req-2" }"#;
        assert_eq!(id_of(&[last]), Some(RequestId::String("req-2".into())));
        // Fed in pieces, as a long line arrives.
        let pieces: Vec<String> = last.chars().map(String::from).collect();
        let pieces: Vec<&str> = pieces.iter().map(String::as_str).collect();
        assert_eq!(id_of(&pieces), Some(RequestId::String("req-2".into())));
        assert_eq!(
            id_of(&[r#"{"jsonrpc":"2.0","method":"notifications/x"}"#]),
            None
        );
        assert_eq!(id_of(&[r#"{"id":null,"method":"m"}"#]), None);
        assert_eq!(id_of(&[r#"{"idx":3,"id":4}"#]), Some(RequestId::Number(4)));
    }
}
